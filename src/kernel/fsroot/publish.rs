//! Streamed atomic publication through a held project directory.

use super::{
    fsync_held, read_dir_names_at, refusal, split_relative, ProjectRoot, DIRECTORY_FLAGS,
    TEMP_ATTEMPTS,
};
use crate::kernel::store::{
    fd_stat, fsync_directory, open_file_at, rename_at, same_inode, stat_at, unlink_if_same,
};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

impl ProjectRoot {
    /// Recheck an unchanged file at the publication boundary and make its
    /// contents and name durable. The reader and directory sync use the
    /// same held parent. A missing or changed file is a comparison miss,
    /// while a symlink or special file is refused as it is by the writer.
    pub(crate) fn sync_file_if_matches(
        &self,
        relative: &Path,
        expected: &[u8],
    ) -> io::Result<bool> {
        use std::io::Read as _;

        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "compare", &mut display)? else {
            return Ok(false);
        };
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        let mut file = match open_file_at(
            parent_fd,
            name.as_bytes(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(refusal(format!(
                    "{} is a symlink; refusing to compare through it",
                    display.display()
                )));
            }
            Err(error) => return Err(error),
        };
        let opened = fd_stat(file.as_raw_fd())?;
        if opened.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(refusal(format!(
                "{} is not a regular file; refusing to compare it",
                display.display()
            )));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes != expected {
            return Ok(false);
        }
        file.sync_all()?;
        let current = match stat_at(parent_fd, name.as_bytes()) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if !same_inode(&opened, &current) {
            return Ok(false);
        }
        fsync_held(parent_fd)?;
        remove_stale_temps(parent_fd);
        Ok(true)
    }

    /// `replace_link` lets the rename replace a symlink at the destination
    /// (the link itself, never what it names), as `rename_in` does. The
    /// contents are streamed from `source` into the temporary, so a large
    /// file is never held in memory whole.
    pub(super) fn publish_mode(
        &self,
        relative: &Path,
        source: &mut dyn io::Read,
        mode: Option<libc::mode_t>,
        replace_link: bool,
        temp_name: &mut dyn FnMut(&[u8], usize) -> io::Result<Vec<u8>>,
    ) -> io::Result<()> {
        let (parents, name) = split_relative(relative)?;
        let mut display = self.path.clone();
        let held = self.open_creating(&parents, &mut display)?;
        display.push(name);
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        match stat_at(parent_fd, name.as_bytes()) {
            Ok(stat) => match stat.st_mode & libc::S_IFMT {
                libc::S_IFLNK if replace_link => {}
                libc::S_IFLNK => {
                    return Err(refusal(format!(
                        "{} is a symlink; refusing to replace it",
                        display.display()
                    )))
                }
                libc::S_IFDIR => {
                    return Err(refusal(format!(
                        "{} is a directory; refusing to replace it",
                        display.display()
                    )))
                }
                libc::S_IFREG => {}
                _ => {
                    return Err(refusal(format!(
                        "{} is not a regular file; refusing to replace it",
                        display.display()
                    )))
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let (temp, mut file) = {
            let mut last = Vec::new();
            let mut opened = None;
            let mut spare = None;
            for attempt in 0..TEMP_ATTEMPTS {
                let candidate = temp_name(name.as_bytes(), attempt)?;
                match create_locked(parent_fd, &candidate, 0o644, &mut spare) {
                    Ok(file) => {
                        opened = Some((candidate, file));
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        last = candidate;
                    }
                    Err(error) => {
                        return Err(io::Error::new(
                            error.kind(),
                            format!("create temporary for {}: {error}", display.display()),
                        ))
                    }
                }
            }
            match opened {
                Some(opened) => opened,
                None => {
                    return Err(refusal(format!(
                        "every temporary name for {} is occupied (last tried {:?}); \
                         remove stale .greyward-tmp entries and retry",
                        display.display(),
                        OsStr::from_bytes(&last)
                    )))
                }
            }
        };
        let created = fd_stat(file.as_raw_fd())?;
        let mut renamed = false;
        // `file` stays open through the identity checks below so the inode
        // it names cannot be recycled under them.
        let result = (|| {
            if let Some(mode) = mode {
                // SAFETY: the descriptor is owned by `file` for this call.
                if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            io::copy(source, &mut file)?;
            file.sync_all()?;
            let current = stat_at(parent_fd, &temp)?;
            if !same_inode(&current, &created) {
                return Err(refusal(format!(
                    "temporary for {} was replaced while it was being written",
                    display.display()
                )));
            }
            rename_at(parent_fd, &temp, name.as_bytes()).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("publish {}: {error}", display.display()),
                )
            })?;
            renamed = true;
            fsync_directory(parent_fd)
        })();
        if result.is_err() && !renamed {
            let _ = unlink_if_same(parent_fd, &temp, &created, 0);
        }
        if result.is_ok() {
            remove_stale_temps(parent_fd);
        }
        drop(file);
        result
    }
}

/// The start of every name `random_temp_name` makes.
pub(super) const TEMP_PREFIX: &str = ".greyward-tmp.lk-";

/// The suffix of the file whose lock stands for a temporary link's owner.
const OWNER_SUFFIX: &[u8] = b".lock";

/// How old a temporary of ours must be before a publication in the same
/// directory may remove it. Its lock decides; the age only covers the moment
/// between a temporary's creation and its lock.
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Whether `name` is exactly a name `random_temp_name` makes.
fn is_own_temp_name(name: &[u8]) -> bool {
    name.strip_prefix(TEMP_PREFIX.as_bytes())
        .is_some_and(|hex| hex.len() == 32 && hex.iter().all(|byte| byte.is_ascii_hexdigit()))
}

fn owner_name(temp: &[u8]) -> Vec<u8> {
    [temp, OWNER_SUFFIX].concat()
}

/// Lock `file` for its writer. A lock that cannot be taken (`ENOLCK`, a
/// filesystem without `flock`) fails the publication: an unlocked
/// temporary is one a cleanup could take for a dead writer's.
fn lock_for_writer(file: &fs::File) -> io::Result<()> {
    if let Some(errno) = lock_failpoint() {
        return Err(io::Error::from_raw_os_error(errno));
    }
    file.try_lock().map_err(|error| {
        let error = io::Error::from(error);
        io::Error::new(error.kind(), format!("lock temporary: {error}"))
    })
}

/// Create `name` in `dirfd` as a new, empty file, locked for its writer
/// before the name exists, so no cleanup can ever see it unlocked. On Linux
/// the file is made unnamed (`O_TMPFILE`), locked, then linked to `name`; a
/// name already taken gives `AlreadyExists` and leaves the unnamed file in
/// `spare` for the caller's next name.
fn create_locked(
    dirfd: RawFd,
    name: &[u8],
    mode: libc::mode_t,
    spare: &mut Option<fs::File>,
) -> io::Result<fs::File> {
    #[cfg(target_os = "linux")]
    {
        let unnamed = match spare.take() {
            Some(file) => Some(file),
            None => unnamed_locked(dirfd, mode)?,
        };
        if let Some(file) = unnamed {
            match link_unnamed(&file, dirfd, name) {
                Ok(true) => return Ok(file),
                Ok(false) => {}
                Err(error) => {
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        *spare = Some(file);
                    }
                    return Err(error);
                }
            }
        }
    }
    let _ = spare;
    // No unnamed file here: create the name, then lock it. A shared lock
    // on the directory covers the moment between the two: a cleanup sweeps
    // only under the directory's exclusive lock, so it never sees this
    // temporary before its own lock is held, however long the writer is
    // paused in between.
    let directory = open_file_at(dirfd, b".", DIRECTORY_FLAGS, 0)?;
    directory.lock_shared().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("lock the temporary's directory: {error}"),
        )
    })?;
    let file = open_file_at(
        dirfd,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        mode,
    )?;
    if let Err(error) = lock_for_writer(&file) {
        if let Ok(created) = fd_stat(file.as_raw_fd()) {
            let _ = unlink_if_same(dirfd, name, &created, 0);
        }
        return Err(error);
    }
    Ok(file)
}

/// An unnamed, locked file in `dirfd`, or `None` where the filesystem
/// refuses `O_TMPFILE` (or a test asks for the named route).
#[cfg(target_os = "linux")]
fn unnamed_locked(dirfd: RawFd, mode: libc::mode_t) -> io::Result<Option<fs::File>> {
    if unnamed_failpoint() {
        return Ok(None);
    }
    // No `O_EXCL`: that would forbid the link.
    let file = match open_file_at(
        dirfd,
        b".",
        libc::O_TMPFILE | libc::O_WRONLY | libc::O_CLOEXEC,
        mode,
    ) {
        Ok(file) => file,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP | libc::EISDIR | libc::EINVAL)
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    lock_for_writer(&file)?;
    Ok(Some(file))
}

/// Give the unnamed `file` the name `name` in `dirfd`. `false` when there
/// is no `/proc` to link it through, so the caller takes the named route.
#[cfg(target_os = "linux")]
fn link_unnamed(file: &fs::File, dirfd: RawFd, name: &[u8]) -> io::Result<bool> {
    // `AT_EMPTY_PATH` would need a capability on older kernels; the
    // descriptor's `/proc` entry links the same inode without one.
    let from = std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .expect("a descriptor path holds no NUL");
    let to = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "temporary name contains NUL"))?;
    // SAFETY: both strings are NUL-terminated and outlive the call, and
    // dirfd is borrowed for it.
    let linked = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            from.as_ptr(),
            dirfd,
            to.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if linked == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) && stat_at(dirfd, b".").is_ok() {
        return Ok(false);
    }
    Err(error)
}

#[cfg(test)]
thread_local! {
    /// Set by a test to make every writer lock fail with this errno.
    static LOCK_FAILPOINT: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    /// Set by a test to make `create_locked` take the named route.
    static UNNAMED_FAILPOINT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn lock_failpoint() -> Option<i32> {
    LOCK_FAILPOINT.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn lock_failpoint() -> Option<i32> {
    None
}

#[cfg(all(test, target_os = "linux"))]
fn unnamed_failpoint() -> bool {
    UNNAMED_FAILPOINT.with(std::cell::Cell::get)
}

#[cfg(all(not(test), target_os = "linux"))]
fn unnamed_failpoint() -> bool {
    false
}

/// The target bytes of the symlink `name` in the directory `dirfd`, read
/// without following it. `None` when the name is absent or is not a
/// symlink.
pub(super) fn link_target_at(dirfd: RawFd, name: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    let mut buffer = vec![0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: dirfd is open, name is NUL-terminated, and the buffer is
    // writable for its whole length.
    let length = unsafe {
        libc::readlinkat(
            dirfd,
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) | Some(libc::EINVAL) => Ok(None),
            _ => Err(error),
        };
    }
    buffer.truncate(length as usize);
    Ok(Some(buffer))
}

/// The owner of a temporary link: `<temp>.lock`, created exclusively and
/// locked before its name exists (`create_locked`), and before the link
/// exists, held until the link is renamed or removed. A link cannot carry
/// a lock itself.
pub(super) fn hold_link_temp(dirfd: RawFd, temp: &[u8]) -> io::Result<fs::File> {
    create_locked(dirfd, &owner_name(temp), 0o600, &mut None)
}

/// Remove the owner file `hold_link_temp` made, then let its lock go.
pub(super) fn release_link_temp(dirfd: RawFd, temp: &[u8], owner: fs::File) {
    if let Ok(created) = fd_stat(owner.as_raw_fd()) {
        let _ = unlink_if_same(dirfd, &owner_name(temp), &created, 0);
    }
    drop(owner);
}

/// The entry `name` in `dirfd`, opened without following it, while it is
/// still `stat` and its writer's lock can be taken: proof the ward that
/// made it has exited, since a live writer holds the lock from creation to
/// rename. The returned descriptor keeps the lock until the entry is gone.
fn dead_writer(dirfd: RawFd, name: &[u8], stat: &libc::stat) -> Option<fs::File> {
    let file = open_file_at(
        dirfd,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )
    .ok()?;
    if !same_inode(&fd_stat(file.as_raw_fd()).ok()?, stat)
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return None;
    }
    // Shared: it still conflicts with the writer's exclusive lock, and NFS
    // grants it on this read-only descriptor where it refuses an exclusive
    // one. Another publication's probe holding it too is no writer.
    file.try_lock_shared().ok()?;
    Some(file)
}

/// Remove the temporaries of ours a killed ward left in the held directory
/// `dirfd` (#678). Left alone, they pile up in the project beside `.venv`
/// and the closures, where they can be committed. Only names of exactly
/// the `random_temp_name` shape are touched, older than `STALE_TEMP_AGE`,
/// each through the held descriptor and only while it is still the entry
/// that was judged, and only when its writer is provably gone: a file
/// whose own lock can be taken, a link whose `<name>.lock` owner's lock can
/// be taken (and an owner file whose link is gone, the same way). A paused
/// writer still holds its lock and keeps its temporary. Best effort: a
/// publication never fails because a leftover could not be removed.
pub(super) fn remove_stale_temps(dirfd: RawFd) {
    // A fresh descriptor of the same directory to list: a listing reads
    // from the descriptor's offset, which an earlier listing of `dirfd`
    // left at the end, and `dirfd` may be an `O_PATH` one.
    let Ok(listed) = open_file_at(dirfd, b".", DIRECTORY_FLAGS, 0) else {
        return;
    };
    // Exclusive and never waited for: a writer creating a temporary without
    // an unnamed file holds the directory shared until its temporary is
    // locked (`create_locked`), so the sweep waits for the next publication.
    if listed.try_lock().is_err() {
        return;
    }
    let Ok(names) = read_dir_names_at(listed.as_raw_fd()) else {
        return;
    };
    let cutoff = std::time::SystemTime::now()
        .checked_sub(STALE_TEMP_AGE)
        .and_then(|cutoff| cutoff.duration_since(std::time::UNIX_EPOCH).ok());
    let Some(cutoff) = cutoff else {
        return;
    };
    let stale = |name: &[u8]| {
        stat_at(dirfd, name)
            .ok()
            .filter(|stat| u64::try_from(stat.st_mtime).is_ok_and(|t| t < cutoff.as_secs()))
    };
    for name in names {
        let name = name.as_bytes();
        let temp = name.strip_suffix(OWNER_SUFFIX).unwrap_or(name);
        if !is_own_temp_name(temp) {
            continue;
        }
        let Some(stat) = stale(name) else {
            continue;
        };
        if temp.len() != name.len() {
            // An owner file. Its link, if any, is judged by its own name.
            if stat_at(dirfd, temp).is_err() {
                if let Some(_lock) = dead_writer(dirfd, name, &stat) {
                    let _ = unlink_if_same(dirfd, name, &stat, 0);
                }
            }
            continue;
        }
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFREG => {
                if let Some(_lock) = dead_writer(dirfd, name, &stat) {
                    let _ = unlink_if_same(dirfd, name, &stat, 0);
                }
            }
            libc::S_IFLNK => {
                let owner = owner_name(name);
                let Ok(owner_stat) = stat_at(dirfd, &owner) else {
                    continue;
                };
                if let Some(_lock) = dead_writer(dirfd, &owner, &owner_stat) {
                    let _ = unlink_if_same(dirfd, name, &stat, 0);
                    let _ = unlink_if_same(dirfd, &owner, &owner_stat, 0);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::path::PathBuf;

    fn project(temp: &TempDir) -> PathBuf {
        let dir = temp.0.join("proj");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// A writer lock that cannot be taken fails the publication, on the
    /// unnamed route and the named one alike (Sol round 2): the destination
    /// keeps its old contents and no temporary or owner file is left.
    #[test]
    fn a_refused_writer_lock_fails_the_publication() {
        for named in [false, true] {
            let temp = TempDir::new();
            let dir = project(&temp);
            fs::write(dir.join("published"), b"old").unwrap();
            let root = ProjectRoot::open(&dir).unwrap();
            UNNAMED_FAILPOINT.with(|cell| cell.set(named));
            LOCK_FAILPOINT.with(|cell| cell.set(Some(libc::ENOLCK)));
            let file = root.write_file(Path::new("published"), b"new");
            let link = root.replace_symlink(Path::new(".venv"), Path::new("/store/env"), "venv");
            LOCK_FAILPOINT.with(|cell| cell.set(None));
            UNNAMED_FAILPOINT.with(|cell| cell.set(false));
            for result in [file, link] {
                let error = result.unwrap_err();
                assert_eq!(error.raw_os_error(), None, "{error}");
                assert!(
                    error
                        .to_string()
                        .contains(&io::Error::from_raw_os_error(libc::ENOLCK).to_string()),
                    "named {named}: {error}"
                );
            }
            assert_eq!(fs::read(dir.join("published")).unwrap(), b"old");
            assert_eq!(names(&dir), ["published"], "named {named}");
        }
    }

    /// On Linux a temporary is locked while it is still unnamed, so no
    /// cleanup can see it before its lock: an `O_TMPFILE` file has no
    /// link, already conflicts with a probe's shared lock, and is the
    /// inode its name resolves to once linked. A name already taken keeps
    /// the unnamed file for the next name and leaves the occupant alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_temporary_is_locked_before_it_has_a_name() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let held = fs::File::open(&dir).unwrap();
        let Some(unnamed) = unnamed_locked(held.as_raw_fd(), 0o644).unwrap() else {
            eprintln!("skipped: this filesystem refuses O_TMPFILE");
            return;
        };
        assert_eq!(fd_stat(unnamed.as_raw_fd()).unwrap().st_nlink, 0);
        let probe = fs::File::open(format!("/proc/self/fd/{}", unnamed.as_raw_fd())).unwrap();
        assert!(matches!(
            probe.try_lock_shared(),
            Err(fs::TryLockError::WouldBlock)
        ));
        let created = fd_stat(unnamed.as_raw_fd()).unwrap();

        fs::write(dir.join("taken"), b"theirs").unwrap();
        let mut spare = Some(unnamed);
        let error = create_locked(held.as_raw_fd(), b"taken", 0o644, &mut spare).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(dir.join("taken")).unwrap(), b"theirs");
        assert!(spare.is_some(), "the unnamed file was dropped");

        let file = create_locked(held.as_raw_fd(), b"free", 0o644, &mut spare).unwrap();
        assert!(spare.is_none());
        let linked = stat_at(held.as_raw_fd(), b"free").unwrap();
        assert!(same_inode(&linked, &created));
        assert!(same_inode(&fd_stat(file.as_raw_fd()).unwrap(), &created));
        assert_eq!(names(&dir), ["free", "taken"]);
        let probe = fs::File::open(dir.join("free")).unwrap();
        assert!(matches!(
            probe.try_lock_shared(),
            Err(fs::TryLockError::WouldBlock)
        ));
        drop(file);
        probe.try_lock_shared().unwrap();
    }

    /// The named route, for a filesystem that refuses `O_TMPFILE`, still
    /// hands back a locked file under the name, and still refuses a taken
    /// one.
    #[test]
    fn the_named_route_creates_a_locked_file() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let held = fs::File::open(&dir).unwrap();
        UNNAMED_FAILPOINT.with(|cell| cell.set(true));
        let made = create_locked(held.as_raw_fd(), b"named", 0o644, &mut None);
        fs::write(dir.join("taken"), b"theirs").unwrap();
        let taken = create_locked(held.as_raw_fd(), b"taken", 0o644, &mut None);
        UNNAMED_FAILPOINT.with(|cell| cell.set(false));
        let file = made.unwrap();
        assert_eq!(taken.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(dir.join("taken")).unwrap(), b"theirs");
        let probe = fs::File::open(dir.join("named")).unwrap();
        assert!(matches!(
            probe.try_lock_shared(),
            Err(fs::TryLockError::WouldBlock)
        ));
        drop(file);
    }
}
