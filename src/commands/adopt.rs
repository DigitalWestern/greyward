//! `ward update --adopt [<ecosystem>] [--accept-changes]`: give a lock no
//! resolver wrote (a hand-hashed `requirements.txt`) the provenance `ward
//! attest` and `--strict` require, by having the ecosystem's resolver
//! compile it.
//!
//! Hashes alone prove which bytes to install, not how the dependency set
//! was chosen, so attest never signs them. Adoption is the explicit step
//! that turns them into resolver output: each ecosystem's `Adopter` keeps
//! the original as the resolver's source and compiles the lock through the
//! edit door, which publishes source, lock and signed record together. What
//! stays here is ecosystem-neutral: choosing the ecosystems (before the
//! store is opened), printing the original pins against the compiled ones
//! for review, refusing a withheld compile, and the sync after. It is a
//! mode of `update`, the verb that rewrites locks, so `attest` keeps its
//! promise of never changing one.

use crate::cli::Command;
use crate::commands::shared::project_dir;
use crate::commands::sync;
use crate::kernel::context::Context;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::resolve::{transaction, DoorKind, ResolutionDoor};
use crate::kernel::ui;
use crate::tailors::adopt::pin_diff;
use crate::tailors::{self, Adopted, Adopter, Adoption, LockAdoption, Tailor};
use std::io;
use std::path::{Path, PathBuf};

/// What `ward update --adopt` was asked.
#[derive(Debug, Clone, Copy)]
struct Request<'a> {
    /// A tailor id, or `None` for every adoptable ecosystem found here.
    ecosystem: Option<&'a str>,
    no_sync: bool,
    /// `--accept-changes`: publish a compile that moves a pinned version or
    /// loses an original hash.
    accept_changes: bool,
}

/// Run `ward update --adopt` as parsed: choose the ecosystems, then check
/// the host, load the signing key and open the store, adopt, print the
/// diff on stdout, then the ordinary sync unless `--no-sync`. A refused
/// selection returns before the key is loaded or the store is opened.
pub fn run(command: Command) -> io::Result<i32> {
    let Command::Adopt {
        ecosystem,
        no_sync,
        accept_changes,
    } = command
    else {
        unreachable!("dispatch hands adopt only its own command");
    };
    let request = Request {
        ecosystem: ecosystem.as_deref(),
        no_sync,
        accept_changes,
    };
    let cwd = project_dir();
    // Load the policy chain before any toolchain object is read, as an
    // edit does.
    let _policy = policy::init(&cwd)?;
    let (project, targets) = targets(&cwd, request.ecosystem)?;
    let platform = Platform::host()?;
    let _signing = crate::comforter::init_signing()?;
    let ctx = Context::open(platform)?;
    // Undo an interrupted publication first.
    if transaction::has_pending_journal(&project) {
        transaction::recover_project(&ctx.store, &ctx.activity, &project)?;
    }
    if project != cwd {
        ui::note(&format!("project: {}", project.display()));
    }
    let mut attribution = policy::Attribution::open("dependency-edit")?;
    let adopted = adopt(&ctx, &project, &targets, request, &mut attribution);
    // The edit owns its exceptions; the sync opens a fresh scope.
    attribution.discard();
    let Some(sync_root) = adopted? else {
        return Ok(0);
    };
    if request.no_sync {
        ui::note("--no-sync: review the change, then run 'ward'");
        return Ok(0);
    }
    sync::run_in(&ctx, &sync_root, false, false).map(|_| 0)
}

/// One ecosystem to adopt in, with its adopter.
struct Target {
    tailor: &'static dyn Tailor,
    adopter: &'static dyn Adopter,
}

/// The nearest project from `cwd` upward and the ecosystems to adopt in:
/// the named one, or every adoptable ecosystem found there. A named
/// ecosystem that is not here, or has no adopter, is refused; unnamed, the
/// ones without an adopter are skipped, and a project with none is
/// refused. This reads no store.
fn targets(cwd: &Path, named: Option<&str>) -> io::Result<(PathBuf, Vec<Target>)> {
    let location = crate::commands::shared::nearest_manifest(cwd)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no project from {} upward (looked for {})",
                cwd.display(),
                crate::commands::shared::input_files()
            ),
        )
    })?;
    let present: Vec<&'static dyn Tailor> = location
        .detected
        .iter()
        .filter_map(|id| tailors::by_id(id))
        .collect();
    let targets = select(&location.root, &present, named)?;
    Ok((location.root, targets))
}

fn select(
    root: &Path,
    present: &[&'static dyn Tailor],
    named: Option<&str>,
) -> io::Result<Vec<Target>> {
    let adoptable =
        |tailor: &'static dyn Tailor| tailor.adopter().map(|adopter| Target { tailor, adopter });
    let Some(id) = named else {
        let targets: Vec<Target> = present.iter().copied().filter_map(adoptable).collect();
        if targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "nothing to adopt in {}: no ecosystem found here has locks that ward \
                     adopts; a lock its own resolver wrote needs none (`ward attest` signs a \
                     resolution record for it)",
                    root.display()
                ),
            ));
        }
        return Ok(targets);
    };
    let Some(tailor) = present.iter().copied().find(|tailor| tailor.id() == id) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no {id} project in {}", root.display()),
        ));
    };
    adoptable(tailor).map(|target| vec![target]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "ward update --adopt does not support {id}: its locks are written by its own \
                 resolver, so there is nothing to adopt; `ward attest {id}` signs a resolution \
                 record for one"
            ),
        )
    })
}

/// Run each ecosystem's adoption through one edit door. `Some(sync root)`
/// when anything was adopted. Every compile's diff is printed, a withheld
/// one's too; a withheld compile fails the command after the rest ran.
fn adopt(
    ctx: &Context,
    project: &Path,
    targets: &[Target],
    request: Request<'_>,
    attribution: &mut policy::Attribution,
) -> io::Result<Option<PathBuf>> {
    ctx.store.require_activity(&ctx.activity, "lock adoption")?;
    let host = crate::commands::shared::CommandHost {
        platform: ctx.platform,
    };
    let mut door = ResolutionDoor::open(
        &ctx.store,
        &ctx.activity,
        ctx.platform,
        DoorKind::Edit,
        attribution,
    )?;
    let mut sync_root = None;
    let mut withheld = Vec::new();
    for target in targets {
        let id = target.tailor.id();
        let adoption = LockAdoption {
            project,
            host: &host,
            accept_changes: request.accept_changes,
        };
        match target.adopter.adopt_lock(ctx, &adoption, &mut door)? {
            Adoption::Nothing(why) => ui::note(&format!("{id}: nothing to adopt: {why}")),
            Adoption::Adopted(adopted) => {
                ui::note(&format!(
                    "{id}: {}: adopted; the resolver compiled {} and its resolution record is \
                     written",
                    adopted.files.join(", "),
                    adopted.lock
                ));
                print!("{}", report(id, &adopted));
                sync_root = Some(adopted.sync_root);
            }
            Adoption::Withheld { review, changes } => {
                print!("{}", report(id, &review));
                withheld.push(format!(
                    "{id}: the compiled {} changes what the original pins ({}), so nothing \
                     was written",
                    review.lock,
                    changes.join("; ")
                ));
            }
        }
    }
    if !withheld.is_empty() {
        let again = match request.ecosystem {
            Some(id) => format!("ward update --adopt {id} --accept-changes"),
            None => "ward update --adopt --accept-changes".to_string(),
        };
        return Err(io::Error::other(format!(
            "{}; review the diff above, then run `{again}` to accept it",
            withheld.join("; ")
        )));
    }
    Ok(sync_root)
}

/// The review text for one adoption: a heading, then the pin diff.
fn report(ecosystem: &str, adopted: &Adopted) -> String {
    let mut out = format!(
        "{ecosystem}: {}, original pins against the compiled lock:\n",
        adopted.lock
    );
    for line in pin_diff(&adopted.before, &adopted.after) {
        out.push_str("  ");
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailors::adopt::Pins;

    #[test]
    fn the_report_heads_the_diff_with_the_lock() {
        let adopted = Adopted {
            files: vec!["requirements.in".into(), "requirements.txt".into()],
            sync_root: PathBuf::from("/p"),
            lock: "requirements.txt".into(),
            before: Pins::new(),
            after: Pins::new(),
        };
        assert_eq!(
            report("python", &adopted),
            "python: requirements.txt, original pins against the compiled lock:\n"
        );
    }

    /// Selection reads only the tailors: a named ecosystem without an
    /// adopter is refused by name, unnamed ones without one are skipped,
    /// and a project with no adoptable ecosystem is refused, all before the
    /// store is opened.
    #[test]
    fn unsupported_ecosystems_are_refused_named_and_skipped_unnamed() {
        let python = tailors::by_id("python").unwrap();
        let node = tailors::by_id("node").unwrap();
        assert!(node.adopter().is_none());
        let root = Path::new("/p");
        let error = select(root, &[python, node], Some("node")).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            error
                .to_string()
                .contains("ward update --adopt does not support node"),
            "{error}"
        );
        let error = select(root, &[node], Some("python")).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let chosen = select(root, &[node, python], None).unwrap();
        assert_eq!(
            chosen
                .iter()
                .map(|target| target.tailor.id())
                .collect::<Vec<_>>(),
            ["python"]
        );
        let error = select(root, &[node], None).err().unwrap();
        assert!(
            error.to_string().starts_with("nothing to adopt in /p"),
            "{error}"
        );
    }
}
