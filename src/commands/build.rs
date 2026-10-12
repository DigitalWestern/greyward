//! `ward build [ecosystem] [args...]`: a sandboxed build for the one
//! build-capable ecosystem present, or the named one, through the tailor
//! registry.

use crate::comforter::toolchain::{self as project_toolchain, Mode};
use crate::commands::shared::ecosystem_inputs;
use crate::kernel::context::Context;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy;
use crate::tailors::{self, Tailor};
use std::io;

/// `ward build` with nothing to build here: every ecosystem it builds, by
/// the file that marks its project, read from the tailors so a new one is
/// never left out.
fn no_build_project() -> io::Error {
    let kinds: Vec<String> = tailors::registry()
        .iter()
        .filter(|tailor| tailor.builds())
        .map(|tailor| {
            let marker = tailor.input_files().split(", ").next().unwrap_or_default();
            format!("{marker} ({})", tailor.id())
        })
        .collect();
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "ward build requires a project with one of: {}",
            kinds.join(", ")
        ),
    )
}

/// Explicit ecosystem, or inferred when exactly one build-capable ecosystem
/// is present.
pub fn run(
    ctx: &Context,
    ecosystem: Option<String>,
    args: &[String],
    frozen: bool,
) -> io::Result<()> {
    let cwd = ctx.project_dir();
    let explicit = ecosystem
        .as_deref()
        .and_then(tailors::by_id)
        .filter(|tailor| tailor.builds());
    let (tailor, rest): (&dyn Tailor, &[String]) = match explicit {
        Some(tailor) => (tailor, args),
        None => {
            let mut present = Vec::new();
            for tailor in tailors::registry() {
                if tailor.builds() && tailor.build_present(&cwd)? {
                    present.push(*tailor);
                }
            }
            match present.as_slice() {
                [one] => (*one, args),
                [] => return Err(no_build_project()),
                many => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "multiple build-capable ecosystems found ({}); specify one: \
                             `ward build <ecosystem> ...`",
                            many.iter()
                                .map(|tailor| tailor.id())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ))
                }
            }
        }
    };
    // A build against inputs the lock no longer describes is the bug the
    // sync-on-the-way-in exists to prevent, so when the ecosystem being
    // built is stale or never synced the project is synced first, as `run`
    // does: that sync may write a lock, like `cargo build` updating
    // Cargo.lock. CI that must not write one runs `ward --frozen build`,
    // whose implicit sync runs frozen (or `ward --frozen` first, and this
    // check then finds nothing to do). Only the built ecosystem's
    // row decides, and only it is host preflighted, prepared and realized;
    // the input check and the toolchain lock still cover the whole project,
    // so an unrelated ecosystem blocks the build only when its version
    // request is malformed or its lock section is stale, not when this host
    // cannot run it or its install fails (see
    // `sync::ensure_current_for`).
    crate::commands::sync::ensure_current_for(ctx, &cwd, Some(tailor.id()), frozen)?;
    let root = tailor.build_root(&cwd)?;
    let _policy = policy::init(&root)?;
    // The build itself honors the lock the sync above left and never
    // writes one.
    let held = ProjectRoot::open(&root)?;
    let toolchain = project_toolchain::resolve(
        &held,
        ctx.platform,
        ecosystem_inputs(&[tailor])?,
        Mode::ReadOnly,
        false,
    )?;
    let selected = toolchain.get(tailor.lock_ecosystem())?;
    let mut attribution = policy::Attribution::open(tailor.id())?;
    // The compiler's errors are the user's, even under `--quiet`.
    crate::kernel::ui::with_users_stderr(|| {
        tailor.build(ctx, &root, &cwd, rest, selected, &mut attribution)
    })?;
    attribution.finish(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every ecosystem `ward build` builds is named by its project file,
    /// .NET's `*.csproj` among them.
    #[test]
    fn nothing_to_build_names_every_building_ecosystem() {
        let message = no_build_project().to_string();
        for marker in ["Cargo.toml", "go.mod", "mix.exs", "*.csproj"] {
            assert!(message.contains(marker), "{message}");
        }
    }
}
