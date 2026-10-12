//! `ward update --adopt [<ecosystem>]`: give a lock no resolver wrote (a
//! hand-hashed `requirements.txt`) the provenance `ward attest` and
//! `--strict` require, by having the ecosystem's resolver compile it.
//!
//! Hashes alone prove which bytes to install, not how the dependency set
//! was chosen, so attest never signs them. Adoption is the explicit step
//! that turns them into resolver output: each tailor's `adopt_lock` keeps
//! the original as the resolver's source and compiles the lock through the
//! edit door, which publishes it with its signed resolution record. What
//! stays here is ecosystem-neutral: choosing the tailors, printing the
//! original pins against the compiled ones for review, and the sync after.
//! It is a mode of `update`, the verb that rewrites locks, so `attest`
//! keeps its promise of never changing one.

use crate::commands::shared::project_dir;
use crate::commands::sync;
use crate::kernel::context::Context;
use crate::kernel::policy;
use crate::kernel::resolve::{transaction, DoorKind, ResolutionDoor};
use crate::kernel::store::Store;
use crate::kernel::ui;
use crate::tailors::{self, Adopted, Adoption, LockAdoption, Pins, Tailor};
use std::io;
use std::path::{Path, PathBuf};

/// Entry point for `dispatch`: adopt, print the diff on stdout, then the
/// ordinary sync unless `no_sync`.
pub fn run(ctx: &Context, ecosystem: Option<&str>, no_sync: bool) -> io::Result<()> {
    let cwd = project_dir();
    // Load the policy chain before any toolchain object is read, as an
    // edit does, and undo an interrupted publication first.
    let _policy = policy::init(&cwd)?;
    if transaction::has_pending_journal(&cwd) {
        transaction::recover_project(&ctx.store, &ctx.activity, &cwd)?;
    }
    let (project, targets) = targets(&cwd, ecosystem)?;
    if project != cwd {
        ui::note(&format!("project: {}", project.display()));
    }
    let mut attribution = policy::Attribution::open("dependency-edit")?;
    let adopted = adopt(ctx, &project, &targets, &mut attribution)?;
    let Some(sync_root) = adopted else {
        attribution.discard();
        return Ok(());
    };
    if no_sync {
        ui::note("--no-sync: review the change, then run 'ward'");
        attribution.discard();
        return Ok(());
    }
    // The edit owns its exceptions; the sync opens a fresh scope.
    attribution.discard();
    sync::run_in(ctx, &sync_root, false, false)
}

/// The nearest project from `cwd` upward and the tailors to adopt in: the
/// named one, or every ecosystem found there.
fn targets(cwd: &Path, named: Option<&str>) -> io::Result<(PathBuf, Vec<&'static dyn Tailor>)> {
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
    let targets = match named {
        None => present,
        Some(id) => match present.into_iter().find(|tailor| tailor.id() == id) {
            Some(tailor) => vec![tailor],
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no {id} project in {}", location.root.display()),
                ))
            }
        },
    };
    Ok((location.root, targets))
}

/// Run each tailor's adoption through one edit door. `Some(sync root)`
/// when anything was adopted.
fn adopt(
    ctx: &Context,
    project: &Path,
    targets: &[&'static dyn Tailor],
    attribution: &mut policy::Attribution,
) -> io::Result<Option<PathBuf>> {
    let store = Store::open()?;
    store.require_activity(&ctx.activity, "lock adoption")?;
    let host = crate::commands::shared::CommandHost {
        platform: ctx.platform,
    };
    let mut door = ResolutionDoor::open(
        &store,
        &ctx.activity,
        ctx.platform,
        DoorKind::Edit,
        attribution,
    )?;
    let mut sync_root = None;
    for tailor in targets {
        let adoption = LockAdoption {
            project,
            host: &host,
        };
        match tailor.adopt_lock(ctx, &adoption, &mut door)? {
            Adoption::Nothing(why) => {
                ui::note(&format!("{}: nothing to adopt: {why}", tailor.id()))
            }
            Adoption::Adopted(adopted) => {
                ui::note(&format!(
                    "{}: {}: adopted; the resolver compiled {} and its resolution record is \
                     written",
                    tailor.id(),
                    adopted.files.join(", "),
                    adopted.lock
                ));
                print!("{}", report(tailor.id(), &adopted));
                sync_root = Some(adopted.sync_root);
            }
        }
    }
    Ok(sync_root)
}

/// The review text for one adoption: a heading, then a line per package
/// (`=` kept, `~` version changed, `+` added by the resolver, `-` not in
/// the compiled lock), and a `!` line for every original hash the compiled
/// lock no longer accepts.
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

fn pin_diff(before: &Pins, after: &Pins) -> Vec<String> {
    let mut lines = Vec::new();
    for (name, old) in before {
        let Some(new) = after.get(name) else {
            lines.push(format!(
                "- {name} {} (not in the compiled lock)",
                old.version
            ));
            continue;
        };
        if old.version == new.version {
            let kept = old.hashes.intersection(&new.hashes).count();
            let added = new.hashes.difference(&old.hashes).count();
            lines.push(format!(
                "= {name} {} (hashes: {kept} of {} kept, {added} added)",
                new.version,
                old.hashes.len()
            ));
        } else {
            lines.push(format!("~ {name} {} -> {}", old.version, new.version));
        }
        for hash in old.hashes.difference(&new.hashes) {
            lines.push(format!(
                "! {name}: the original hash {hash} is not in the compiled lock"
            ));
        }
    }
    for (name, new) in after {
        if !before.contains_key(name) {
            lines.push(format!("+ {name} {} (added by the resolver)", new.version));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailors::Pin;

    fn pin(version: &str, hashes: &[&str]) -> Pin {
        Pin {
            version: version.to_string(),
            hashes: hashes.iter().map(|hash| hash.to_string()).collect(),
        }
    }

    #[test]
    fn the_diff_names_every_kept_changed_added_and_dropped_pin() {
        let before: Pins = [
            ("six".to_string(), pin("1.16.0", &["sha256:a"])),
            ("idna".to_string(), pin("3.9", &["sha256:i"])),
            ("gone".to_string(), pin("1.0", &[])),
            ("swapped".to_string(), pin("2.0", &["sha256:old"])),
        ]
        .into_iter()
        .collect();
        let after: Pins = [
            ("six".to_string(), pin("1.16.0", &["sha256:a", "sha256:b"])),
            ("idna".to_string(), pin("3.10", &["sha256:j"])),
            ("swapped".to_string(), pin("2.0", &["sha256:new"])),
            ("new".to_string(), pin("0.1", &[])),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            pin_diff(&before, &after),
            [
                "- gone 1.0 (not in the compiled lock)",
                "~ idna 3.9 -> 3.10",
                "! idna: the original hash sha256:i is not in the compiled lock",
                "= six 1.16.0 (hashes: 1 of 1 kept, 1 added)",
                "= swapped 2.0 (hashes: 0 of 1 kept, 1 added)",
                "! swapped: the original hash sha256:old is not in the compiled lock",
                "+ new 0.1 (added by the resolver)",
            ]
        );
        let adopted = Adopted {
            files: vec!["requirements.in".into(), "requirements.txt".into()],
            sync_root: PathBuf::from("/p"),
            lock: "requirements.txt".into(),
            before: before.clone(),
            after: before,
        };
        let text = report("python", &adopted);
        assert!(text
            .starts_with("python: requirements.txt, original pins against the compiled lock:\n  "));
    }
}
