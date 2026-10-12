//! What every store-backed command needs: the validated host platform, an
//! opened store, and the shared activity lease that keeps GC from racing
//! the command. Kernel layer, so that a tailor can take a `&Context` without
//! naming the command layer.

use crate::kernel::activity::{ActivityMode, StoreActivity};
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use std::io;
use std::path::PathBuf;

pub struct Context {
    pub platform: Platform,
    pub store: Store,
    project_dir: Option<PathBuf>,
    /// Keeps the operation protected from its first store read through its
    /// final child/projection use, which is what prevents GC from racing a
    /// CLI job. Every store helper borrows this lease as a `&StoreActivity`
    /// parameter; only the lease-free root-registry calls
    /// (`register_root_record` and friends) take their own.
    pub activity: StoreActivity,
}

impl Context {
    /// Open the store and take the shared lease.
    pub fn open(platform: Platform) -> io::Result<Self> {
        Self::open_with_project_dir(platform, None)
    }

    /// Open a context whose project directory is independent of the process
    /// cwd. Production dispatch uses `open`, which reads the cwd.
    pub fn open_in(platform: Platform, project_dir: &std::path::Path) -> io::Result<Self> {
        Self::open_with_project_dir(platform, Some(project_dir.to_path_buf()))
    }

    // Reviewed site (tests/architecture.rs): operation boundary: the shared lease every command borrows via `Context`.
    #[allow(clippy::disallowed_methods)]
    fn open_with_project_dir(platform: Platform, project_dir: Option<PathBuf>) -> io::Result<Self> {
        let store = Store::open()?;
        let activity = store.activity(ActivityMode::Shared)?;
        Ok(Self {
            platform,
            store,
            project_dir,
            activity,
        })
    }

    /// The directory `open_in` pinned, or the current directory.
    pub fn project_dir(&self) -> io::Result<PathBuf> {
        match &self.project_dir {
            Some(dir) => Ok(dir.clone()),
            None => project_dir(),
        }
    }
}

/// The project directory: the current directory, as every command reads it.
/// A shell can sit in a directory something else removed; that is an error
/// the user can act on, not a panic.
pub fn project_dir() -> io::Result<PathBuf> {
    std::env::current_dir().map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => io::Error::new(
            io::ErrorKind::NotFound,
            "the current directory no longer exists: cd to one that does, or name it with -C",
        ),
        kind => io::Error::new(kind, format!("cannot read the current directory: {error}")),
    })
}

#[cfg(test)]
mod tests {
    /// A removed working directory is an error that says so. The process
    /// cwd is shared by every test thread, so the removal runs in a child.
    #[test]
    fn a_removed_current_directory_is_an_error() {
        let Ok(test) = std::env::current_exe() else {
            return;
        };
        if std::env::var_os("WARD_REMOVED_CWD_CHILD").is_some() {
            let dir = std::env::temp_dir().join(format!("ward-gone-{}", std::process::id()));
            std::fs::create_dir(&dir).unwrap();
            std::env::set_current_dir(&dir).unwrap();
            std::fs::remove_dir(&dir).unwrap();
            let error = super::project_dir().unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            assert!(error.to_string().contains("no longer exists"), "{error}");
            return;
        }
        let status = std::process::Command::new(test)
            .args([
                "--exact",
                "kernel::context::tests::a_removed_current_directory_is_an_error",
            ])
            .env("WARD_REMOVED_CWD_CHILD", "1")
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }
}
