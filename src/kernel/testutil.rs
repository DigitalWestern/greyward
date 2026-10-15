//! Test-only helpers shared across layers (kernel layer, `cfg(test)`).

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) mod upstream;

/// Create fixture archives from the declared tree, without host metadata.
pub(crate) fn tar_create() -> Command {
    let mut command = Command::new("/usr/bin/tar");
    command.env_remove("TAR_OPTIONS");
    #[cfg(target_os = "macos")]
    {
        // bsdtar otherwise adds AppleDouble members and binary provenance
        // xattrs inherited from the process that created the fixture.
        command.env("COPYFILE_DISABLE", "1").arg("--no-xattrs");
    }
    command
}

/// A `file://` URL whose bytes arrive only after `delay`: a FIFO at `path`
/// that a thread fills then closes. A download from it is slow by
/// construction, so a test can order another download against it without
/// relying on timing. Join the handle once the read is done.
pub(crate) fn slow_file_url(
    path: &std::path::Path,
    bytes: Vec<u8>,
    delay: std::time::Duration,
) -> (String, std::thread::JoinHandle<()>) {
    use std::os::unix::ffi::OsStrExt as _;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `name` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let fifo = path.to_path_buf();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(delay);
        use std::io::Write as _;
        // Blocks until the download opens the FIFO for reading.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    });
    (format!("file://{}", path.display()), writer)
}

/// `dir` at mode 0111 (search, no read) until dropped, for a test that a
/// walk reaches names in a directory it cannot list. When this user lists
/// it anyway (root, or `CAP_DAC_READ_SEARCH`) the test would prove nothing:
/// the error is the line the test prints as it skips.
pub(crate) struct SearchOnly(PathBuf);

impl SearchOnly {
    pub(crate) fn new(dir: &std::path::Path) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o111)).unwrap();
        let held = Self(dir.to_path_buf());
        if std::fs::read_dir(dir).is_ok() {
            return Err(format!(
                "skipped: {} is still listable at mode 0111 (root or CAP_DAC_READ_SEARCH)",
                dir.display()
            ));
        }
        Ok(held)
    }
}

impl Drop for SearchOnly {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// A Unix socket listening at `path`, however long `path` is. A socket
/// address holds about 108 bytes, which a long `TMPDIR` exceeds. On Linux
/// the socket is bound through the parent directory's `/proc/self/fd`
/// alias, so it is made where it lives, on that filesystem, with no
/// process-wide `chdir`. Elsewhere a long path is bound under `/tmp` and
/// renamed in, which needs `TMPDIR` on the same filesystem as `/tmp`.
pub(crate) fn bind_socket(path: &std::path::Path) -> std::os::unix::net::UnixListener {
    use std::os::unix::net::UnixListener;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        let parent = path.parent().expect("a socket path has a parent");
        let name = path.file_name().expect("a socket path names a file");
        let directory = std::fs::File::open(parent).unwrap();
        let alias = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
        UnixListener::bind(alias).unwrap()
    }
    #[cfg(not(target_os = "linux"))]
    {
        if path.as_os_str().len() < 100 {
            return UnixListener::bind(path).unwrap();
        }
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let short = PathBuf::from(format!(
            "/tmp/greyward-sock-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&short);
        let listener = UnixListener::bind(&short).unwrap();
        std::fs::rename(&short, path).unwrap();
        listener
    }
}

/// A private (0700) directory for a test's Unix sockets, on a path short
/// enough to bind them by name, removed on drop. A socket address holds
/// about 108 bytes, which a long `TMPDIR` exceeds, so the directory is
/// placed like the resolution door's session directory: under
/// `$XDG_RUNTIME_DIR`, else the temp dir, else `/tmp`, whichever is first
/// to fit. Use it for a socket a test binds through an API that takes a
/// path (`Session::listen_unix`, `ProxySocket::hold`), and keep the store
/// itself in a `TempDir` under the caller's `TMPDIR`.
pub(crate) struct SocketDir(PathBuf);

/// The longest socket name `SocketDir::socket` accepts.
const SOCKET_NAME_MAX: usize = 16;

impl SocketDir {
    pub(crate) fn new() -> Self {
        let mut bases = Vec::new();
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            if runtime.is_absolute() && runtime.is_dir() {
                bases.push(runtime);
            }
        }
        bases.push(std::env::temp_dir());
        bases.push(PathBuf::from("/tmp"));
        Self::under(bases)
    }

    /// A socket directory in the first of `bases` whose path leaves room
    /// for the longest socket name.
    fn under(bases: impl IntoIterator<Item = PathBuf>) -> Self {
        let name = format!(
            "greyward-sock-{}",
            hex::encode(crate::kernel::fsroot::urandom_bytes(8).unwrap())
        );
        for base in bases {
            let dir = base.join(&name);
            // The directory, a separator, and the longest name, under the
            // 107 bytes `sun_path` holds before its NUL.
            if dir.as_os_str().len() + 1 + SOCKET_NAME_MAX > 107 {
                continue;
            }
            // `create`, not `create_dir_all`: the name is fresh, so an
            // existing entry is not ours, and drop must not remove it.
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
            return Self(dir);
        }
        panic!("no directory for a test socket has a path short enough; set XDG_RUNTIME_DIR");
    }

    /// The path of the socket `name` in this directory.
    pub(crate) fn socket(&self, name: &str) -> PathBuf {
        assert!(
            name.len() <= SOCKET_NAME_MAX && !name.contains('/'),
            "socket name {name:?}"
        );
        self.0.join(name)
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A scratch directory named `greyward-<label>-<pid>-<nanos>-<seq>`, gone on
/// drop even when a store inside it has made its objects read-only: a plain
/// `remove_dir_all` fails on those and leaves the tree behind, and enough
/// leftovers fill the per-user /tmp quota.
pub struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub fn new() -> Self {
        Self::named("test")
    }

    /// A scratch directory whose name says which test made it, for the
    /// leftover a killed run leaves.
    ///
    /// The clock alone is not unique: macOS's ticks in microseconds, so two
    /// tests with one label could share a directory without the sequence.
    pub fn named(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        Self::create(std::env::temp_dir().join(format!(
            "greyward-{label}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        )))
    }

    /// A scratch directory at `greyward-<name>` with no per-call suffix, for a
    /// fixture whose path enters the result under test and so must be the
    /// same on every call. Callers serialize their use of one name.
    pub fn fixed(name: &str) -> Self {
        Self::create(std::env::temp_dir().join(format!("greyward-{name}")))
    }

    fn create(path: PathBuf) -> Self {
        std::fs::create_dir_all(&path).unwrap();
        // The store records object paths under its canonicalized root and
        // compares them exactly; on macOS the temp dir sits under /var, a
        // symlink to /private/var.
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = crate::kernel::store::remove_tree(&self.0);
    }
}

/// An executable script at `relative` under `root` that exits 0: a store
/// program a test can point a command at, which the host-local tripwire
/// resolves like the real one.
pub(crate) fn store_program(root: &std::path::Path, relative: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Every command `build` makes with one of its own environment edits
/// undone, named by the variable: a variable it sets removed, one it
/// removes set. A host-local form must refuse each.
pub(crate) fn loosened(build: impl Fn() -> Command) -> Vec<(String, Command)> {
    let edits: Vec<(std::ffi::OsString, bool)> = build()
        .get_envs()
        .map(|(key, value)| (key.to_os_string(), value.is_some()))
        .collect();
    edits
        .into_iter()
        .map(|(key, set)| {
            let mut command = build();
            if set {
                command.env_remove(&key);
            } else {
                command.env(&key, "loosened");
            }
            (key.to_string_lossy().into_owned(), command)
        })
        .chain(std::iter::once({
            // A variable no form admits: a caller adding one (a loader
            // preload, a tool setting outside the checked families) must be
            // refused as surely as one loosening a forced value.
            let mut command = build();
            command.env("LD_PRELOAD", "/tmp/loosened.so");
            ("+LD_PRELOAD".to_string(), command)
        }))
        .collect()
}

/// A lease on an empty scratch store, for a test whose code under test takes
/// the caller's activity token but must return before touching any store.
/// The directory is removed when the `TempDir` drops.
pub(crate) fn detached_lease() -> (TempDir, crate::kernel::activity::StoreActivity) {
    let temp = TempDir::new();
    let activity = crate::kernel::activity::StoreActivity::acquire(
        &temp.0,
        crate::kernel::activity::ActivityMode::Shared,
    )
    .unwrap();
    (temp, activity)
}

/// The scope a test's resolution doors record into, for a test that calls a
/// planner or realizer directly. It holds the attribution test lock, the
/// last one in the whole-crate order (see `policy::attribution_test_lock`),
/// and its frame is discarded when it drops.
pub(crate) struct DoorScope {
    attribution: crate::kernel::policy::Attribution,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl DoorScope {
    pub(crate) fn new() -> Self {
        let guard = crate::kernel::policy::attribution_test_lock();
        Self {
            attribution: crate::kernel::policy::Attribution::open("test").unwrap(),
            _guard: guard,
        }
    }

    pub(crate) fn door<'a>(
        &'a mut self,
        store: &'a crate::kernel::store::Store,
        activity: &'a crate::kernel::activity::StoreActivity,
        platform: crate::kernel::platform::Platform,
        kind: crate::kernel::resolve::DoorKind,
    ) -> crate::kernel::resolve::ResolutionDoor<'a> {
        crate::kernel::resolve::ResolutionDoor::open(
            store,
            activity,
            platform,
            kind,
            &mut self.attribution,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod socket_tests {
    use super::*;

    /// A socket path longer than a socket address holds is bound where it
    /// is: the entry at that path is a socket.
    #[test]
    fn bind_socket_takes_a_path_past_the_address_limit() {
        use std::os::unix::fs::FileTypeExt as _;
        let temp = TempDir::named("bind-socket");
        let deep = temp.0.join("d".repeat(60)).join("e".repeat(60));
        std::fs::create_dir_all(&deep).unwrap();
        let path = deep.join("listener.sock");
        assert!(path.as_os_str().len() > 108, "{}", path.display());
        let _listener = bind_socket(&path);
        let stat = std::fs::symlink_metadata(&path).unwrap();
        assert!(stat.file_type().is_socket());
    }

    /// A socket directory is private, its socket paths bind by name even
    /// under a long `TMPDIR`, and dropping it removes it and nothing else.
    #[test]
    fn socket_dir_is_short_private_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt as _;
        let sockets = SocketDir::new();
        let dir = sockets.0.clone();
        let parent = dir.parent().unwrap().to_path_buf();
        let sibling = TempDir::named("socket-dir-sibling");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let path = sockets.socket("sixteen-bytes.ok");
        assert!(path.as_os_str().len() <= 107, "{}", path.display());
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(sockets);
        assert!(!dir.exists(), "the socket directory is removed");
        assert!(parent.is_dir(), "its parent stays");
        assert!(sibling.0.is_dir(), "other scratch directories stay");
    }

    /// A base too long for a socket path is passed over for the next one,
    /// and nothing is created in it: the case a long `TMPDIR` hits.
    #[test]
    fn socket_dir_skips_a_base_too_long_for_a_socket() {
        let long = TempDir::named("socket-dir-long");
        let deep = long.0.join("d".repeat(60)).join("e".repeat(60));
        std::fs::create_dir_all(&deep).unwrap();
        let short = PathBuf::from("/tmp");
        let sockets = SocketDir::under([deep.clone(), short.clone()]);
        assert_eq!(sockets.0.parent(), Some(short.as_path()));
        assert_eq!(std::fs::read_dir(&deep).unwrap().count(), 0);
        let path = sockets.socket("sixteen-bytes.ok");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    }
}
