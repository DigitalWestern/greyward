//! Streamed atomic publication through a held project directory.

use super::{
    read_dir_names_at, refusal, split_relative, ProjectRoot, DIRECTORY_FLAGS, TEMP_ATTEMPTS,
};
use crate::kernel::store::{
    fd_stat, fsync_directory, open_file_at, rename_at, same_inode, stat_at, unlink_if_same,
};
use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

impl ProjectRoot {
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
            for attempt in 0..TEMP_ATTEMPTS {
                let candidate = temp_name(name.as_bytes(), attempt)?;
                match open_file_at(
                    parent_fd,
                    &candidate,
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o644,
                ) {
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

/// How old a temporary of ours must be before a publication in the same
/// directory removes it: far past any write, so one another ward is
/// publishing right now is never taken.
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Whether `name` is exactly a name `random_temp_name` makes.
fn is_own_temp_name(name: &[u8]) -> bool {
    name.strip_prefix(b".greyward-tmp.")
        .is_some_and(|hex| hex.len() == 32 && hex.iter().all(|byte| byte.is_ascii_hexdigit()))
}

/// Remove the temporaries of ours a killed ward left in the held directory
/// `dirfd` (#678): a file or link named exactly as `random_temp_name` names
/// one, older than `STALE_TEMP_AGE`. Left alone, they pile up in the project
/// beside `.venv` and the closures, where they can be committed. Only names
/// of that exact shape are touched, each through the held descriptor and
/// only while it is still the entry that was judged. Best effort: a
/// publication never fails because a leftover could not be removed.
pub(super) fn remove_stale_temps(dirfd: RawFd) {
    // A fresh descriptor of the same directory to list: a listing reads
    // from the descriptor's offset, which an earlier listing of `dirfd`
    // left at the end, and `dirfd` may be an `O_PATH` one.
    let Ok(listed) = open_file_at(dirfd, b".", DIRECTORY_FLAGS, 0) else {
        return;
    };
    let Ok(names) = read_dir_names_at(listed.as_raw_fd()) else {
        return;
    };
    let cutoff = std::time::SystemTime::now()
        .checked_sub(STALE_TEMP_AGE)
        .and_then(|cutoff| cutoff.duration_since(std::time::UNIX_EPOCH).ok());
    let Some(cutoff) = cutoff else {
        return;
    };
    for name in names {
        let name = name.as_bytes();
        if !is_own_temp_name(name) {
            continue;
        }
        let Ok(stat) = stat_at(dirfd, name) else {
            continue;
        };
        let kind = stat.st_mode & libc::S_IFMT;
        let stale = u64::try_from(stat.st_mtime).is_ok_and(|mtime| mtime < cutoff.as_secs());
        if stale && (kind == libc::S_IFREG || kind == libc::S_IFLNK) {
            let _ = unlink_if_same(dirfd, name, &stat, 0);
        }
    }
}
