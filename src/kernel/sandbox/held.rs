//! Declared sandbox roots an open project root holds (#497), and handing
//! descriptors to bubblewrap.

use super::Sandbox;
use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The declared roots (and the working directory) an open project root
/// holds, each resolved once through its held descriptor (#497). The socket
/// scan walks that descriptor and bubblewrap binds it, so a project renamed
/// or swapped (and even swapped back) since ward opened it is not what the
/// build sees. A root no open project root holds keeps its pathname.
#[derive(Default)]
pub(super) struct HeldRoots {
    roots: Vec<HeldRoot>,
}

pub(super) struct HeldRoot {
    /// The path the caller declared.
    requested: PathBuf,
    /// Where the sandbox shows it: the canonical path it was opened at.
    pub(super) dest: PathBuf,
    dir: fs::File,
    /// Whether bubblewrap binds it (not for a working directory that is no
    /// declared root).
    bound: bool,
    /// The descriptor number bubblewrap receives it at, once pinned.
    target: Option<RawFd>,
    /// The copy of `dir` open at `target`, until the child has run.
    _pinned: Option<std::os::fd::OwnedFd>,
}

/// The lowest number a held root is passed at, and the highest the system
/// shell closes: dash reads one digit (`exec 12<&-` is "exec: 12: not
/// found"), so a number past it is closed by bash.
const HELD_FD_FIRST: RawFd = 3;
const HELD_FD_LAST: RawFd = 9;
/// The lowest number the `--args` descriptor may have, so it never takes a
/// number the system shell could close a held root at.
#[cfg(target_os = "linux")]
const ARGS_FD_FLOOR: RawFd = HELD_FD_LAST + 1;
/// The shell that closes held descriptors above `HELD_FD_LAST`.
const BASH: &str = "/bin/bash";

impl HeldRoots {
    pub(super) fn resolve(sandbox: &Sandbox<'_>, cwd: &Path) -> io::Result<Self> {
        let mut held = Self::default();
        for path in sandbox.read.iter().chain(&sandbox.write) {
            if held.find(path).is_some() {
                continue;
            }
            let Some((dir, dest)) = crate::kernel::fsroot::held_root_for(path)? else {
                continue;
            };
            held.roots.push(HeldRoot {
                requested: path.to_path_buf(),
                dest,
                dir,
                bound: true,
                target: None,
                _pinned: None,
            });
        }
        if held.find(cwd).is_none() {
            if let Some((dir, dest)) = crate::kernel::fsroot::held_root_for(cwd)? {
                held.roots.push(HeldRoot {
                    requested: cwd.to_path_buf(),
                    dest,
                    dir,
                    bound: false,
                    target: None,
                    _pinned: None,
                });
            }
        }
        Ok(held)
    }

    pub(super) fn find(&self, path: &Path) -> Option<&HeldRoot> {
        self.roots.iter().find(|root| root.requested == path)
    }

    /// Each declared root as (bind source, place in the sandbox), the
    /// writable ones with scratch added: a held one is bound from its
    /// descriptor at the path it was opened at.
    pub(super) fn place(
        &self,
        read: &[&Path],
        write: &[&Path],
        scratch: &Path,
    ) -> io::Result<(Vec<(PathBuf, PathBuf)>, Vec<(PathBuf, PathBuf)>)> {
        let read = read
            .iter()
            .map(|path| self.place_one(path))
            .collect::<io::Result<_>>()?;
        let mut write: Vec<(PathBuf, PathBuf)> = write
            .iter()
            .map(|path| self.place_one(path))
            .collect::<io::Result<_>>()?;
        let scratch = fs::canonicalize(scratch)?;
        if !write.iter().any(|(_, path)| path == &scratch) {
            write.push((scratch.clone(), scratch));
        }
        Ok((read, write))
    }

    /// One declared root as (bind source, place in the sandbox).
    pub(super) fn place_one(&self, path: &Path) -> io::Result<(PathBuf, PathBuf)> {
        match self.find(path) {
            Some(found) => Ok((found.source()?, found.dest.clone())),
            None => fs::canonicalize(path).map(|path| (path.clone(), path)),
        }
    }

    /// Where the sandbox shows `path`, declared root or not: the working
    /// directory is only entered, never bound by itself, so a held one
    /// that is no declared root (a subdirectory of the bound project) has
    /// a place here and no bind source.
    pub(super) fn dest(&self, path: &Path) -> io::Result<PathBuf> {
        match self.find(path) {
            Some(found) => Ok(found.dest.clone()),
            None => fs::canonicalize(path),
        }
    }

    /// Give each bound root the number it is passed at, just before the
    /// spawn: a fresh close-on-exec copy of its descriptor at the lowest free
    /// number from 3, kept open here until the child has run. Every copy is
    /// open at once, so no two roots share a number, and std cannot take one
    /// for the spawn's own pipes (its error channel among them); in the
    /// child only close-on-exec is cleared.
    pub(super) fn pin(&mut self) -> io::Result<()> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        for root in self.roots.iter_mut().filter(|root| root.bound) {
            // SAFETY: F_DUPFD_CLOEXEC only reads `dir`, open here.
            let copy =
                unsafe { libc::fcntl(root.dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, HELD_FD_FIRST) };
            if copy < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `copy` was just duplicated and nothing else owns it.
            let copy = unsafe { std::os::fd::OwnedFd::from_raw_fd(copy) };
            root.target = Some(copy.as_raw_fd());
            root._pinned = Some(copy);
        }
        let numbers = self.numbers();
        debug_assert!(
            numbers
                .iter()
                .enumerate()
                .all(|(at, number)| !numbers[..at].contains(number)),
            "held roots share a descriptor number: {numbers:?}"
        );
        Ok(())
    }

    /// Held roots bubblewrap binds, from open directories, for a test that
    /// places their descriptors itself.
    #[cfg(test)]
    pub(super) fn bound_for_test(dirs: Vec<(fs::File, PathBuf)>) -> Self {
        let roots = dirs
            .into_iter()
            .map(|(dir, dest)| HeldRoot {
                requested: dest.clone(),
                dest,
                dir,
                bound: true,
                target: None,
                _pinned: None,
            })
            .collect();
        Self { roots }
    }

    /// The number every bound root is passed at, once pinned.
    pub(super) fn numbers(&self) -> Vec<RawFd> {
        self.roots.iter().filter_map(|root| root.target).collect()
    }

    /// The shell script that closes every passed descriptor and runs its
    /// arguments, or `None` when nothing is passed.
    /// The shell that runs `close_script`: the system shell when every
    /// number is a single digit, since dash reads no other (`exec 12<&-` is
    /// "exec: 12: not found"), and bash, which takes any number, otherwise.
    pub(super) fn close_shell(&self) -> io::Result<&'static str> {
        if self.numbers().iter().all(|number| *number <= HELD_FD_LAST) {
            return Ok("/bin/sh");
        }
        if Path::new(BASH).is_file() {
            return Ok(BASH);
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "descriptors {HELD_FD_FIRST} to {HELD_FD_LAST} are all in use, and the system \
                 shell closes no other, so passing a held root to the sandbox needs {BASH}"
            ),
        ))
    }

    pub(super) fn close_script(&self) -> Option<String> {
        let closes: Vec<String> = self
            .roots
            .iter()
            .filter_map(|root| Some(format!("{}<&-", root.target?)))
            .collect();
        (!closes.is_empty()).then(|| format!("exec {}; exec \"$@\"", closes.join(" ")))
    }
}

impl HeldRoot {
    /// The bind source bubblewrap opens: its own copy of the descriptor.
    /// A working directory that is no declared root has none.
    fn source(&self) -> io::Result<PathBuf> {
        match self.target {
            Some(target) => Ok(PathBuf::from(format!("/proc/self/fd/{target}"))),
            None => Err(io::Error::other(format!(
                "{} is the working directory, not a declared sandbox root",
                self.requested.display()
            ))),
        }
    }

    /// This process's view of the held directory, for the socket scan.
    /// The trailing `.` makes the scan start in the directory rather than
    /// at the descriptor's symlink.
    pub(super) fn alias(&self) -> PathBuf {
        use std::os::fd::AsRawFd as _;
        PathBuf::from(format!("/proc/self/fd/{}/.", self.dir.as_raw_fd()))
    }
}

/// Hand each `(source, target)` descriptor to the command at `target`.
/// This runs after `bwrap_command` marked every inherited descriptor
/// close-on-exec, so the targets are the only ones that survive. Each
/// source is first copied above every target, so a source numbered like
/// another target is not overwritten before it is moved.
pub(crate) fn pass_fds(command: &mut Command, fds: Vec<(RawFd, RawFd)>) {
    if fds.is_empty() {
        return;
    }
    let floor = fds.iter().map(|(_, target)| *target).max().unwrap_or(2) + 1;
    // Allocated before fork: the closure runs between fork and exec.
    let mut high = vec![0; fds.len()];
    use std::os::unix::process::CommandExt as _;
    // SAFETY: the closure calls only fcntl/dup2/close, which are
    // async-signal-safe, on vectors allocated before fork.
    unsafe {
        command.pre_exec(move || {
            for (slot, (source, _)) in high.iter_mut().zip(&fds) {
                *slot = libc::fcntl(*source, libc::F_DUPFD_CLOEXEC, floor);
                if *slot < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for (copy, (_, target)) in high.iter().zip(&fds) {
                // dup2 leaves the new descriptor without close-on-exec.
                if libc::dup2(*copy, *target) < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(*copy);
            }
            Ok(())
        });
    }
}

#[cfg(test)]
thread_local! {
    /// Called by `Sandbox::bwrap` on this thread once the roots are
    /// resolved, for the engine it runs in place of the preflight's: a test
    /// of an engine gone after the preflight, which may change this
    /// process's descriptors first.
    pub(super) static ENGINE_OVERRIDE: std::cell::RefCell<Option<Box<dyn FnMut() -> PathBuf>>> =
        std::cell::RefCell::new(None);
}

/// Refuse a command line holding a NUL byte: in the `--args` data it
/// would end an argument early and make the rest options of bubblewrap's
/// own. Refuse too a variable name `/usr/bin/env` would read differently
/// (empty, or holding `=`). The refusal is `InvalidInput` and unmarked, the
/// build's own failure, as the kernel's refusal of a NUL on argv is.
pub(super) fn refuse_unpassable(
    args: &[std::ffi::OsString],
    envs: &[(String, String)],
) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let refuse = |what: String| Err(io::Error::new(io::ErrorKind::InvalidInput, what));
    if let Some(at) = args.iter().position(|arg| arg.as_bytes().contains(&0)) {
        return refuse(format!("sandbox argument {at} holds a NUL byte"));
    }
    match envs
        .iter()
        .find(|(key, _)| key.is_empty() || key.contains('='))
    {
        Some((key, _)) => refuse(format!("{key:?} is no environment variable name")),
        None => Ok(()),
    }
}

/// Whether bubblewrap failed its exec of `program`, the command it was
/// given after `--`, with E2BIG: `die_with_error` exits 1 after printing
/// `bwrap: execvp PROGRAM: Argument list too long`, the last line of its
/// stderr. That is the build's own failure, as an E2BIG at the spawn is:
/// every argument ward generates is in the `--args` data and bubblewrap's
/// own environment is only PWD, so the command and its environment are
/// what is too long. A build that prints the same line and exits 1 reports
/// its own failure either way.
pub(super) fn exec_too_long(
    status: &std::process::ExitStatus,
    stderr: &[u8],
    program: &std::ffi::OsStr,
) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let expected = [
        &b"bwrap: execvp "[..],
        program.as_bytes(),
        b": Argument list too long",
    ]
    .concat();
    let stderr = stderr.strip_suffix(b"\n").unwrap_or(stderr);
    status.code() == Some(1) && stderr.rsplit(|byte| *byte == b'\n').next() == Some(&expected[..])
}

/// `args`, each ended by a NUL as bubblewrap's `--args` reads them, in a
/// memory file at a number at or above `ARGS_FD_FLOOR`, kept open until
/// the child has run.
#[cfg(target_os = "linux")]
pub(super) fn args_file(args: &[std::ffi::OsString]) -> io::Result<fs::File> {
    use std::io::{Seek as _, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    // SAFETY: memfd_create reads only the NUL-terminated name.
    let fd = unsafe { libc::memfd_create(c"greyward-bwrap-args".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just created and nothing else owns it.
    let low = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: F_DUPFD_CLOEXEC only reads `low`, which stays open here.
    let fd = unsafe { libc::fcntl(low.as_raw_fd(), libc::F_DUPFD_CLOEXEC, ARGS_FD_FLOOR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    drop(low);
    // SAFETY: `fd` was just duplicated and nothing else owns it.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let mut data = Vec::new();
    for arg in args {
        data.extend_from_slice(arg.as_bytes());
        data.push(0);
    }
    file.write_all(&data)?;
    file.rewind()?;
    Ok(file)
}

/// Hand `file` to the command at the number it has here, its descriptor's
/// close-on-exec cleared after `bwrap_command` set it on everything. No
/// descriptor is moved onto another number for it: one numbered in advance
/// could cover std's spawn-error channel, and then a spawn that failed
/// would report none. Returns the number.
pub(super) fn pass_in_place(command: &mut Command, file: &fs::File) -> RawFd {
    use std::os::fd::AsRawFd as _;
    let fd = file.as_raw_fd();
    keep_in_place(command, vec![fd]);
    fd
}

/// Clear close-on-exec on each of `fds` in the child, after
/// `bwrap_command` set it on everything: each reaches the command at the
/// number it has here, which this process keeps open until the spawn.
pub(super) fn keep_in_place(command: &mut Command, fds: Vec<RawFd>) {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: the closure calls only fcntl, async-signal-safe, on a vector
    // allocated before fork.
    unsafe {
        command.pre_exec(move || {
            for fd in &fds {
                if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn args_file(_: &[std::ffi::OsString]) -> io::Result<fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bubblewrap runs only on Linux",
    ))
}
