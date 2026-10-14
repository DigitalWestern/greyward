//! Where a planted workspace link lives, held by descriptor, so the link's
//! `..` steps can be shown to climb through the very directories they
//! climbed through when it was planted (#692, Sol round 7).
//!
//! A link in the store's forest reaches the project with a relative text:
//! `..` up from the link's own directory to the deepest directory that
//! directory shares with the project's path (the anchor), then down the
//! project's path. The kernel resolves each `..` from where the link's
//! directory really is, not from the path ward planted it at, so a forest
//! moved and replaced with a symlink to its new place would carry the same
//! text somewhere else. [`LinkSite`] holds the anchor and the link's
//! directory, opened from the anchor with no symlink on the way, and
//! [`LinkSite::in_place`] proves both are still where their paths say.

use super::*;
use crate::kernel::store::fd_identity;
use std::ffi::OsString;

/// A planted link's directory, and the anchor its `..` steps climb to.
pub(crate) struct LinkSite {
    anchor_path: PathBuf,
    anchor: fs::File,
    below: Vec<OsString>,
    dir: fs::File,
    name: OsString,
}

impl LinkSite {
    /// Hold the directory of `link`, a link that will reach into the
    /// project at `project`. The directory must already exist, and every
    /// component of it below the anchor must be a real directory.
    pub(crate) fn hold(link: &Path, project: &Path) -> io::Result<LinkSite> {
        let invalid = |why: &str| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("link {}: {why}", link.display()),
            )
        };
        let parent = link.parent().ok_or_else(|| invalid("has no directory"))?;
        let name = link
            .file_name()
            .ok_or_else(|| invalid("has no name"))?
            .to_os_string();
        let from: Vec<_> = parent.components().collect();
        let to: Vec<_> = project.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        if common == 0 {
            return Err(invalid("shares no directory with the project's path"));
        }
        let anchor_path: PathBuf = from[..common].iter().collect();
        let mut below = Vec::new();
        for component in &from[common..] {
            match component {
                std::path::Component::Normal(name) => below.push(name.to_os_string()),
                _ => return Err(invalid("is not a plain path below its anchor")),
            }
        }
        let anchor = open_anchor(&anchor_path)?;
        let dir = walk_down(&anchor, &below)?;
        Ok(LinkSite {
            anchor_path,
            anchor,
            below,
            dir,
            name,
        })
    }

    /// Create the link in the held directory with `text`.
    pub(crate) fn plant(&self, text: &Path) -> io::Result<()> {
        let text = cstring(text.as_os_str())?;
        let name = cstring(&self.name)?;
        // SAFETY: a live directory fd and two NUL-terminated strings.
        if unsafe { libc::symlinkat(text.as_ptr(), self.dir.as_raw_fd(), name.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The link's text, read in the held directory; `None` when there is
    /// no link of that name, and an error when the name is something else.
    pub(crate) fn read(&self) -> io::Result<Option<PathBuf>> {
        let name = cstring(&self.name)?;
        let mut buffer = vec![0u8; libc::PATH_MAX as usize + 1];
        // SAFETY: a live directory fd, a NUL-terminated name and a buffer
        // of the length passed.
        let length = unsafe {
            libc::readlinkat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            return match error.kind() {
                io::ErrorKind::NotFound => Ok(None),
                _ => Err(error),
            };
        }
        buffer.truncate(length as usize);
        Ok(Some(PathBuf::from(OsString::from_vec(buffer))))
    }

    /// Remove the link from the held directory.
    pub(crate) fn remove(&self) -> io::Result<()> {
        let name = cstring(&self.name)?;
        // SAFETY: a live directory fd and a NUL-terminated name.
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Whether the anchor's path still names the held anchor and, walked
    /// down from it again with no symlink followed, the link's path still
    /// names the held directory. Then the link's `..` steps climb through
    /// the directories they climbed through when it was planted.
    pub(crate) fn in_place(&self) -> io::Result<bool> {
        let anchor = match open_anchor(&self.anchor_path) {
            Ok(anchor) => anchor,
            Err(error) if moved(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        if fd_identity(&anchor)? != fd_identity(&self.anchor)? {
            return Ok(false);
        }
        match walk_down(&anchor, &self.below) {
            Ok(dir) => Ok(fd_identity(&dir)? == fd_identity(&self.dir)?),
            Err(error) if moved(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// An error that says a directory on the way is gone or is no directory
/// now (a symlink put in its place).
fn moved(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        || matches!(
            error.raw_os_error(),
            Some(libc::ENOTDIR | libc::ELOOP | libc::EMLINK)
        )
}

fn cstring(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// The anchor, opened by its path: the path above it is the user's, and
/// may go through symlinks (a home directory that is one).
fn open_anchor(path: &Path) -> io::Result<fs::File> {
    open_dir_at(libc::AT_FDCWD, path.as_os_str(), 0)
}

/// `names` opened one at a time below `from`, none of them followed if it
/// is a symlink.
fn walk_down(from: &fs::File, names: &[OsString]) -> io::Result<fs::File> {
    let mut dir = from.try_clone()?;
    for name in names {
        dir = open_dir_at(dir.as_raw_fd(), name, libc::O_NOFOLLOW)?;
    }
    Ok(dir)
}

fn open_dir_at(dirfd: RawFd, name: &OsStr, extra: libc::c_int) -> io::Result<fs::File> {
    let name = cstring(name)?;
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | extra;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | extra;
    // SAFETY: a live directory fd (or AT_FDCWD) and a NUL-terminated name;
    // a returned fd is owned by the File.
    let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this descriptor to us.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link site is in place until its directory, or one between it and
    /// the anchor, is moved and replaced with a symlink to its new place:
    /// the link's text would then climb from somewhere else.
    #[test]
    fn a_link_site_moved_and_replaced_with_a_symlink_is_not_in_place() {
        let scratch = crate::kernel::testutil::TempDir::named("link-site");
        let project = scratch.0.join("project");
        let forest = scratch.0.join("store/forests/id");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(forest.join("node_modules")).unwrap();
        let site = LinkSite::hold(&forest.join("node_modules/lib"), &project).unwrap();
        site.plant(Path::new("../../../../project")).unwrap();
        assert_eq!(
            site.read().unwrap(),
            Some(PathBuf::from("../../../../project"))
        );
        assert!(site.in_place().unwrap());
        fs::create_dir_all(scratch.0.join("elsewhere/deeper")).unwrap();
        let moved = scratch.0.join("elsewhere/deeper/id");
        fs::rename(&forest, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &forest).unwrap();
        assert!(!site.in_place().unwrap());
        fs::remove_file(&forest).unwrap();
        assert!(!site.in_place().unwrap());
        fs::rename(&moved, &forest).unwrap();
        assert!(site.in_place().unwrap());
        site.remove().unwrap();
        assert_eq!(site.read().unwrap(), None);
    }
}
