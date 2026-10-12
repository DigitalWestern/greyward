//! Staged files and a publication review for a project's next resolution
//! (kernel layer).
//!
//! Some commands must hand a resolution tool a file the project does not
//! have yet, and publish that file only together with what the tool
//! writes: `ward update --adopt` keeps a hand-written lock as the
//! resolver's source, a file that must appear exactly when the compiled
//! lock and its record do, and never otherwise. Writing it into the
//! project first would leave it behind on a failed run or a killed
//! process, and a later cleanup by name could remove a file somebody else
//! put there.
//!
//! So such a file is *staged* instead: registered here against the held
//! project directory (by its device and inode, so a directory swapped in
//! at the same path does not match), never written to the project. While
//! the [`Staged`] guard lives:
//!
//! - the door's snapshot (`Snapshot::build`) writes each staged file into
//!   the stage beside the project's own files, with its mode, and leaves it
//!   out of the baseline, so the tool reads it and the diff reports it as a
//!   new file;
//! - the resolution transaction (`Transaction::hold`) requires each staged
//!   file to be a declared output that is absent from the project, and its
//!   publication requires the tool to have left it byte for byte as staged.
//!   It is then created with `RENAME_NOREPLACE` in the same journaled
//!   publication as the lock and the receipt, with the staged mode, so an
//!   interrupted publication is undone to the original absence like any
//!   other created target;
//! - the optional [`Review`] sees every output the publication would write,
//!   with the pre-run digests, before the first project write, and an error
//!   from it publishes nothing.
//!
//! A failed or interrupted run therefore leaves no staged file anywhere in
//! the project, and nothing ever deletes one by name.

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::snapshot;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// One file a resolution reads and publishes without the project having it
/// first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFile {
    /// Relative to the lock root: a plain path that the door declares as an
    /// output.
    pub relative: PathBuf,
    pub bytes: Vec<u8>,
    /// The permission bits the published file gets (0o777 mask).
    pub mode: u32,
}

/// One held output as the publication would leave it, for a [`Review`].
#[derive(Debug)]
pub struct Candidate<'a> {
    /// Relative to the lock root.
    pub relative: &'a Path,
    /// The sha256 the file had when the transaction held it, `None` when it
    /// was absent.
    pub before: Option<[u8; 32]>,
    /// The bytes the publication writes, `None` when it leaves the file as
    /// it was.
    pub after: Option<&'a [u8]>,
}

/// A check every publication in the staged project must pass before its
/// first project write. An error publishes nothing and is the run's error.
pub type Review = Box<dyn Fn(&[Candidate<'_>]) -> io::Result<()> + Send + Sync>;

/// What one command stages for a project's resolutions.
#[derive(Default)]
pub struct Staging {
    pub files: Vec<StagedFile>,
    pub review: Option<Review>,
}

struct Row {
    id: u64,
    device: u64,
    inode: u64,
    staging: Arc<Staging>,
}

static STAGED: Mutex<Vec<Row>> = Mutex::new(Vec::new());

fn table() -> MutexGuard<'static, Vec<Row>> {
    STAGED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Registers a [`Staging`] for one held project directory; dropping it
/// withdraws the staging. Nothing is ever written to the project for it.
#[derive(Debug)]
pub struct Staged(u64);

impl Drop for Staged {
    fn drop(&mut self) {
        table().retain(|row| row.id != self.0);
    }
}

fn identity(dirfd: RawFd) -> io::Result<(u64, u64)> {
    let stat = crate::kernel::store::fd_stat(dirfd)?;
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

/// Stage `staging` for the resolutions run in `root` while the guard lives.
/// One staging per project directory at a time; each file is a plain path
/// below the root, outside ward's own state, named once.
pub fn stage(root: &ProjectRoot, staging: Staging) -> io::Result<Staged> {
    for (index, file) in staging.files.iter().enumerate() {
        snapshot::check_relative(&file.relative)?;
        if file.relative.starts_with(".greyward") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is ward's own state, never a staged file",
                    file.relative.display()
                ),
            ));
        }
        if staging.files[..index]
            .iter()
            .any(|other| other.relative == file.relative)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is staged twice", file.relative.display()),
            ));
        }
    }
    let (device, inode) = identity(root.as_raw_fd())?;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut rows = table();
    if rows
        .iter()
        .any(|row| row.device == device && row.inode == inode)
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!(
                "{} already has files staged for a resolution in this process",
                root.path().display()
            ),
        ));
    }
    rows.push(Row {
        id,
        device,
        inode,
        staging: Arc::new(staging),
    });
    Ok(Staged(id))
}

/// The staging registered for the directory `dirfd` holds, if any.
fn staging_at(dirfd: RawFd) -> io::Result<Option<Arc<Staging>>> {
    let (device, inode) = identity(dirfd)?;
    Ok(table()
        .iter()
        .find(|row| row.device == device && row.inode == inode)
        .map(|row| row.staging.clone()))
}

/// The files staged for the directory `dirfd` holds (none when nothing is
/// staged there).
pub(crate) fn files_at(dirfd: RawFd) -> io::Result<Vec<StagedFile>> {
    Ok(staging_at(dirfd)?.map_or_else(Vec::new, |staging| staging.files.clone()))
}

/// Run the review staged for the directory `dirfd` holds, if any, over
/// `candidates`. The table is not locked while it runs.
pub(crate) fn review_at(dirfd: RawFd, candidates: &[Candidate<'_>]) -> io::Result<()> {
    match staging_at(dirfd)? {
        Some(staging) => match &staging.review {
            Some(review) => review(candidates),
            None => Ok(()),
        },
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn file(relative: &str) -> StagedFile {
        StagedFile {
            relative: PathBuf::from(relative),
            bytes: b"x\n".to_vec(),
            mode: 0o600,
        }
    }

    #[test]
    fn a_staging_lives_with_its_guard_and_matches_the_directory_not_the_name() {
        let temp = TempDir::named("staging-guard");
        let project = temp.0.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        let guard = stage(
            &root,
            Staging {
                files: vec![file("requirements.in")],
                review: None,
            },
        )
        .unwrap();
        assert_eq!(
            files_at(root.as_raw_fd()).unwrap(),
            vec![file("requirements.in")]
        );
        let again = stage(&root, Staging::default()).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::WouldBlock);
        // Another directory moved to the same name is not the staged one.
        std::fs::rename(&project, temp.0.join("moved")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let other = ProjectRoot::open(&project).unwrap();
        assert!(files_at(other.as_raw_fd()).unwrap().is_empty());
        drop(guard);
        assert!(files_at(root.as_raw_fd()).unwrap().is_empty());
    }

    #[test]
    fn staged_names_are_plain_once_and_never_wards_own() {
        let temp = TempDir::named("staging-names");
        let root = ProjectRoot::open(&temp.0).unwrap();
        for files in [
            vec![file("../escape")],
            vec![file("/abs")],
            vec![file(".greyward/resolution/python.json")],
            vec![file("a"), file("a")],
        ] {
            let error = stage(
                &root,
                Staging {
                    files,
                    review: None,
                },
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
        }
        assert!(files_at(root.as_raw_fd()).unwrap().is_empty());
    }

    #[test]
    fn the_review_runs_only_where_it_was_staged() {
        let temp = TempDir::named("staging-review");
        let root = ProjectRoot::open(&temp.0).unwrap();
        let candidates = [Candidate {
            relative: Path::new("requirements.txt"),
            before: None,
            after: Some(b"new"),
        }];
        review_at(root.as_raw_fd(), &candidates).unwrap();
        let _guard = stage(
            &root,
            Staging {
                files: Vec::new(),
                review: Some(Box::new(|candidates| {
                    Err(io::Error::other(format!("refused {}", candidates.len())))
                })),
            },
        )
        .unwrap();
        let error = review_at(root.as_raw_fd(), &candidates).unwrap_err();
        assert_eq!(error.to_string(), "refused 1");
    }
}
