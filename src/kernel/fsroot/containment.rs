//! Whether a project input stays inside the held project once its
//! symlinks are followed: the containment check a lockfile's link and
//! workspace paths pass before anything is placed there, and the
//! symlink-free path a link is planted to.

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

/// Where a planted link leads ([`ProjectRoot::link_leads_to`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkEnd {
    /// To its target, inside the project: the directory's device and
    /// inode, so a later check can tell it is still the same one.
    Target((u64, u64)),
    /// Somewhere else, or to its target once that has left the project.
    Elsewhere,
    /// To nothing: the link or its target is gone.
    Gone,
}

/// How a name is opened to judge where it leads: symlinks followed, no
/// read access needed.
#[cfg(target_os = "linux")]
const FOLLOWING: libc::c_int = libc::O_PATH | libc::O_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const FOLLOWING: libc::c_int = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;

/// The walk's end: the deepest existing ancestor, opened with symlinks
/// followed, and the plain names below it that do not exist yet.
enum Deepest {
    Opened(fs::File, Vec<std::ffi::OsString>),
    /// No ancestor below the root exists: all of it is plain names.
    Root(Vec<std::ffi::OsString>),
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
        Ok(match self.deepest_existing(relative)? {
            Deepest::Opened(file, _) if self.holds_inside(&file)? => Containment::Inside,
            Deepest::Opened(..) => Containment::Outside,
            Deepest::Root(_) => Containment::Inside,
            Deepest::Dangling => Containment::Dangling,
        })
    }

    /// The project-relative path the input `relative` really names, read
    /// from the descriptor the containment walk opened: every symlink in
    /// its existing part resolved, so a link planted to it never passes
    /// through one a writer can repoint afterwards. `.` is the root. A name
    /// that leads outside the project or through a dangling symlink is an
    /// error, as for [`ProjectRoot::input_containment`].
    pub(crate) fn contained_input_path(&self, relative: &Path) -> io::Result<PathBuf> {
        let refused = |why: &str| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} {why}", relative.display()),
            )
        };
        let (mut resolved, rest) = match self.deepest_existing(relative)? {
            Deepest::Dangling => {
                return Err(refused(
                    "passes through a dangling symlink; ward cannot tell whether it stays in the project",
                ))
            }
            Deepest::Root(rest) => (PathBuf::new(), rest),
            Deepest::Opened(file, rest) => {
                if !self.holds_inside(&file)? {
                    return Err(refused("is outside the project"));
                }
                let root = descriptor_path(self.dir.as_raw_fd())?;
                let opened = descriptor_path(file.as_raw_fd())?;
                let inside = opened.strip_prefix(&root).map_err(|_| {
                    refused("resolves to a path the kernel does not name under the project")
                })?;
                (inside.to_path_buf(), rest)
            }
        };
        resolved.extend(rest);
        if resolved.as_os_str().is_empty() {
            resolved.push(".");
        }
        Ok(resolved)
    }

    /// Where the planted symlink `link` leads now, judged by one kernel
    /// resolution from the held descriptor. `text` is what ward planted the
    /// link with and `target` the project input it names; the caller
    /// compares a `LinkEnd::Target` identity with the one recorded when the
    /// link was planted.
    ///
    /// The link lives in the store's forest, outside the project, so it
    /// cannot itself be opened beneath the held descriptor: its text climbs
    /// to the project by the project's path and then names `target` inside
    /// it. Each of those parts is fixed here instead of being opened twice:
    ///
    /// 1. The link still holds `text`, the text ward planted.
    /// 2. The project's path still names the held directory
    ///    ([`ProjectRoot::check_still_named`]), so the climb ends there.
    /// 3. `target` is opened once from the descriptor with `openat2`
    ///    (`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`): the kernel follows
    ///    every symlink on the way as it is at that instant and refuses,
    ///    atomically, one that leads out of the project (`EXDEV`, `ELOOP`).
    ///    The descriptor's device and inode are the answer.
    ///
    /// There is no second open and no walk of the directory's ancestry, so
    /// nothing can be moved between two looks. A kernel with no `openat2`
    /// (and macOS) opens `target` by the descriptor walk of
    /// [`ProjectRoot::input_containment`] instead.
    pub(crate) fn link_leads_to(
        &self,
        link: &Path,
        text: &Path,
        target: &Path,
    ) -> io::Result<LinkEnd> {
        match fs::read_link(link) {
            Ok(now) if now == text => {}
            Ok(_) => return Ok(LinkEnd::Elsewhere),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(LinkEnd::Gone),
            Err(error) => return Err(error),
        }
        self.check_still_named()?;
        let opened = match open_beneath_following(self.dir.as_raw_fd(), target) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(LinkEnd::Gone),
            Err(error) if matches!(error.raw_os_error(), Some(libc::EXDEV | libc::ELOOP)) => {
                return Ok(LinkEnd::Elsewhere)
            }
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => {
                return self.target_without_openat2(target)
            }
            Err(error) => return Err(error),
        };
        Ok(LinkEnd::Target(fd_identity(&opened)?))
    }

    /// `target` opened by the descriptor walk, for a kernel with no
    /// `openat2`: inside the project once its symlinks are followed, and
    /// all of it there.
    fn target_without_openat2(&self, target: &Path) -> io::Result<LinkEnd> {
        Ok(match self.deepest_existing(target)? {
            Deepest::Opened(file, rest) if rest.is_empty() => {
                if self.holds_inside(&file)? {
                    LinkEnd::Target(fd_identity(&file)?)
                } else {
                    LinkEnd::Elsewhere
                }
            }
            Deepest::Opened(..) | Deepest::Root(_) | Deepest::Dangling => LinkEnd::Gone,
        })
    }

    fn holds_inside(&self, file: &fs::File) -> io::Result<bool> {
        let root = fd_stat(self.dir.as_raw_fd())?;
        Ok(same_inode(&fd_stat(file.as_raw_fd())?, &root) || self.contains_open_file(file)?)
    }

    fn deepest_existing(&self, relative: &Path) -> io::Result<Deepest> {
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
                std::path::Component::Normal(name) => names.push(name.to_os_string()),
                std::path::Component::CurDir if names.is_empty() => {}
                _ => return Err(invalid()),
            }
        }
        let mut rest = Vec::new();
        while !names.is_empty() {
            let name = names
                .iter()
                .map(|name| name.as_bytes())
                .collect::<Vec<_>>()
                .join(&b'/');
            match open_file_at(self.dir.as_raw_fd(), &name, FOLLOWING, 0) {
                Ok(file) => {
                    rest.reverse();
                    return Ok(Deepest::Opened(file, rest));
                }
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        || error.raw_os_error() == Some(libc::ENOTDIR) =>
                {
                    if stat_at(self.dir.as_raw_fd(), &name)
                        .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFLNK)
                    {
                        return Ok(Deepest::Dangling);
                    }
                    rest.extend(names.pop());
                }
                // The OS error as it is (a symlink loop): the caller names
                // the input it asked about.
                Err(error) => return Err(error),
            }
        }
        rest.reverse();
        Ok(Deepest::Root(rest))
    }
}

/// `target` below `dirfd`, every symlink followed but none out of `dirfd`
/// and no magic link (`openat2` with `RESOLVE_BENEATH |
/// RESOLVE_NO_MAGICLINKS`).
#[cfg(target_os = "linux")]
fn open_beneath_following(dirfd: RawFd, target: &Path) -> io::Result<fs::File> {
    let path = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: open_how is plain data; zeroed is its documented default.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: openat2 with a live directory fd, a NUL-terminated path and a
    // correctly sized open_how; a returned fd is owned by the File.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this descriptor to us.
    Ok(unsafe { fs::File::from_raw_fd(fd as RawFd) })
}

#[cfg(not(target_os = "linux"))]
fn open_beneath_following(_dirfd: RawFd, _target: &Path) -> io::Result<fs::File> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A planted link is judged by one beneath-open of its target from the
    /// held descriptor: a directory on the way swapped for a symlink out of
    /// the project is `Elsewhere`, a link whose text was changed is
    /// `Elsewhere`, and a target that is gone is `Gone` (#692).
    #[test]
    fn a_link_must_reach_its_target_through_the_held_project() {
        let scratch = crate::kernel::testutil::TempDir::named("link-leads-to");
        let project = scratch.0.join("project");
        fs::create_dir_all(project.join("src/lib")).unwrap();
        fs::create_dir_all(scratch.0.join("outside/lib")).unwrap();
        let link = scratch.0.join("forest-link");
        let text = project.join("src/lib");
        std::os::unix::fs::symlink(&text, &link).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        let target = Path::new("src/lib");
        let planted = fd_identity(&fs::File::open(project.join("src/lib")).unwrap()).unwrap();
        assert_eq!(
            root.link_leads_to(&link, &text, target).unwrap(),
            LinkEnd::Target(planted)
        );
        assert_eq!(
            root.link_leads_to(&link, Path::new("other"), target)
                .unwrap(),
            LinkEnd::Elsewhere
        );
        fs::rename(project.join("src"), project.join("src.saved")).unwrap();
        std::os::unix::fs::symlink(scratch.0.join("outside"), project.join("src")).unwrap();
        assert_eq!(
            root.link_leads_to(&link, &text, target).unwrap(),
            LinkEnd::Elsewhere
        );
        fs::remove_file(project.join("src")).unwrap();
        assert_eq!(
            root.link_leads_to(&link, &text, target).unwrap(),
            LinkEnd::Gone
        );
        fs::remove_file(&link).unwrap();
        assert_eq!(
            root.link_leads_to(&link, &text, target).unwrap(),
            LinkEnd::Gone
        );
    }

    /// Sol's move-out, move-back: the target's directory moved out of the
    /// project with a symlink to its new place left behind, then moved back
    /// in under another name with a fresh directory recreated outside. The
    /// planted link reaches the outside directory throughout, and the one
    /// beneath-open refuses it at every step; the original directory, back
    /// inside, is never mistaken for the link's end (#692, Sol round 6).
    #[test]
    fn a_link_whose_target_was_moved_out_and_back_is_refused() {
        let scratch = crate::kernel::testutil::TempDir::named("link-moved-out");
        let project = scratch.0.join("project");
        fs::create_dir_all(project.join("src/lib")).unwrap();
        fs::create_dir_all(scratch.0.join("outside")).unwrap();
        let link = scratch.0.join("forest-link");
        let text = project.join("src/lib");
        std::os::unix::fs::symlink(&text, &link).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        let target = Path::new("src/lib");
        let LinkEnd::Target(planted) = root.link_leads_to(&link, &text, target).unwrap() else {
            panic!("the planted link does not reach its target");
        };
        let moved = scratch.0.join("outside/src");
        fs::rename(project.join("src"), &moved).unwrap();
        std::os::unix::fs::symlink(&moved, project.join("src")).unwrap();
        assert_eq!(
            root.link_leads_to(&link, &text, target).unwrap(),
            LinkEnd::Elsewhere
        );
        fs::rename(&moved, project.join("kept")).unwrap();
        fs::create_dir_all(moved.join("lib")).unwrap();
        assert_eq!(
            fd_identity(&fs::File::open(project.join("kept/lib")).unwrap()).unwrap(),
            planted,
            "the original directory is back inside"
        );
        assert_eq!(
            root.link_leads_to(&link, &text, target).unwrap(),
            LinkEnd::Elsewhere
        );
    }

    /// The path a link is planted to is the one the held descriptor
    /// reached, symlinks resolved, so repointing one later cannot redirect
    /// the link (#692).
    #[test]
    fn a_contained_input_path_has_its_symlinks_resolved() {
        let scratch = crate::kernel::testutil::TempDir::named("contained-path");
        let project = scratch.0.join("project");
        fs::create_dir_all(project.join("src/lib")).unwrap();
        fs::create_dir_all(scratch.0.join("outside")).unwrap();
        std::os::unix::fs::symlink("src", project.join("vendor")).unwrap();
        std::os::unix::fs::symlink("../outside", project.join("away")).unwrap();
        std::os::unix::fs::symlink("missing", project.join("dangling")).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        let at = |name: &str| root.contained_input_path(Path::new(name));
        assert_eq!(at("vendor/lib").unwrap(), Path::new("src/lib"));
        assert_eq!(
            at("vendor/lib/not/yet").unwrap(),
            Path::new("src/lib/not/yet")
        );
        assert_eq!(at("new/dir").unwrap(), Path::new("new/dir"));
        assert_eq!(at("src").unwrap(), Path::new("src"));
        assert_eq!(at(".").unwrap(), Path::new("."));
        assert_eq!(
            at("vendor/..").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(at("away/x")
            .unwrap_err()
            .to_string()
            .contains("outside the project"));
        assert!(at("dangling/x")
            .unwrap_err()
            .to_string()
            .contains("dangling"));
    }
}
