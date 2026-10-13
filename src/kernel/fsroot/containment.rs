//! Whether a project input stays inside the held project once its
//! symlinks are followed: the containment check a lockfile's link and
//! workspace paths pass before anything is placed there.

use super::*;

/// Where a project-relative name leads, symlinks followed
/// ([`ProjectRoot::input_containment`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Containment {
    /// Inside the project, or not there yet below a directory that is.
    Inside,
    /// A symlink on the way carries it outside the project.
    Outside,
    /// It passes through a symlink whose target does not exist.
    Dangling,
}

impl ProjectRoot {
    /// Where the project input `relative` (plain components only, or `.`
    /// for the root itself) leads, symlinks followed from the held
    /// descriptor. A name that does not exist yet is judged by its deepest
    /// existing ancestor: the rest is plain names, so whatever is created
    /// there stays beneath it. A dangling symlink on the way could lead
    /// anywhere once its target appears: `Containment::Dangling`.
    pub(crate) fn input_containment(&self, relative: &Path) -> io::Result<Containment> {
        #[cfg(target_os = "linux")]
        const FOLLOWING: libc::c_int = libc::O_PATH | libc::O_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        const FOLLOWING: libc::c_int = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("project-relative path {relative:?} is not a plain path"),
            )
        };
        if relative.as_os_str().is_empty() {
            return Err(invalid());
        }
        let mut names = Vec::new();
        for component in relative.components() {
            match component {
                std::path::Component::Normal(name) => names.push(name),
                std::path::Component::CurDir if names.is_empty() => {}
                _ => return Err(invalid()),
            }
        }
        let root = fd_stat(self.dir.as_raw_fd())?;
        while !names.is_empty() {
            let name = names
                .iter()
                .map(|name| name.as_bytes())
                .collect::<Vec<_>>()
                .join(&b'/');
            match open_file_at(self.dir.as_raw_fd(), &name, FOLLOWING, 0) {
                Ok(file) => {
                    let inside = same_inode(&fd_stat(file.as_raw_fd())?, &root)
                        || self.contains_open_file(&file)?;
                    return Ok(if inside {
                        Containment::Inside
                    } else {
                        Containment::Outside
                    });
                }
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        || error.raw_os_error() == Some(libc::ENOTDIR) =>
                {
                    if stat_at(self.dir.as_raw_fd(), &name)
                        .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFLNK)
                    {
                        return Ok(Containment::Dangling);
                    }
                    names.pop();
                }
                // The OS error as it is (a symlink loop): the caller names
                // the input it asked about.
                Err(error) => return Err(error),
            }
        }
        Ok(Containment::Inside)
    }
}
