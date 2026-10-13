//! Checks a producer leaves for the closure writer to run right before
//! anything of a sync is published: a fact the producer established while
//! it built (a workspace link it planted leads into the project, say) that
//! a writer in the project could have undone since. Each check is
//! registered under the project it was made for and a name of the
//! producer's own; registering the same pair again replaces it, so the
//! check in force is always the latest build's.

use crate::kernel::fsroot::ProjectRoot;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A check run before publication; an error refuses the publication.
pub type PublicationCheck = dyn Fn() -> io::Result<()> + Send + Sync;

type Registered = (PathBuf, &'static str, Arc<PublicationCheck>);

static CHECKS: Mutex<Vec<Registered>> = Mutex::new(Vec::new());

/// Register `check` for the project at `project` under `name`, replacing
/// the one registered there under that name before.
pub fn register_publication_check(
    project: &Path,
    name: &'static str,
    check: Arc<PublicationCheck>,
) {
    let mut checks = CHECKS.lock().unwrap_or_else(|p| p.into_inner());
    checks.retain(|(at, named, _)| !(at == project && *named == name));
    checks.push((project.to_path_buf(), name, check));
}

/// Withdraw the check registered for the project at `project` under
/// `name`, if any: a producer starting a new build for the project, whose
/// earlier build's facts no longer apply.
pub fn withdraw_publication_check(project: &Path, name: &'static str) {
    let mut checks = CHECKS.lock().unwrap_or_else(|p| p.into_inner());
    checks.retain(|(at, named, _)| !(at == project && *named == name));
}

/// Run every check registered for `project`, for a project inside it, or
/// for one it lies inside (a workspace member's closure covers the links
/// planted for its root). Called by the closure writer after the toolchain
/// recheck. The checks run outside the registry's lock.
pub(crate) fn run_publication_checks(project: &ProjectRoot) -> io::Result<()> {
    let path = project.path();
    let due: Vec<Arc<PublicationCheck>> = CHECKS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .filter(|(at, _, _)| path.starts_with(at) || at.starts_with(path))
        .map(|(_, _, check)| check.clone())
        .collect();
    for check in due {
        check()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// A check runs for its own project and the ones nested with it, not
    /// for an unrelated one, and a second registration replaces the first.
    #[test]
    fn a_registered_check_runs_for_its_project_and_is_replaced() {
        let scratch = TempDir::named("publication-checks");
        for dir in ["project/member", "other"] {
            std::fs::create_dir_all(scratch.0.join(dir)).unwrap();
        }
        let project = scratch.0.join("project");
        let refuse: Arc<PublicationCheck> = Arc::new(|| Err(io::Error::other("refused")));
        register_publication_check(&project, "test", refuse);
        for dir in ["project", "project/member"] {
            let root = ProjectRoot::open(&scratch.0.join(dir)).unwrap();
            assert!(run_publication_checks(&root).is_err(), "{dir}");
        }
        run_publication_checks(&ProjectRoot::open(&scratch.0.join("other")).unwrap()).unwrap();
        register_publication_check(&project, "test", Arc::new(|| Ok(())));
        run_publication_checks(&ProjectRoot::open(&project).unwrap()).unwrap();
        register_publication_check(&project, "test", refuse_again());
        withdraw_publication_check(&project, "test");
        run_publication_checks(&ProjectRoot::open(&project).unwrap()).unwrap();
    }

    fn refuse_again() -> Arc<PublicationCheck> {
        Arc::new(|| Err(io::Error::other("refused")))
    }
}
