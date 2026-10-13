//! What of the host a sandboxed command sees (`HostView`), and the pieces
//! of the whole-host view: the root it binds and the keys it covers.

use super::{push_arg, push_bind, system_root_args};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// How much of the host's system directories a sandboxed build can see.
/// The host C toolchain is an unpinned build input either way (see
/// docs/human/LIMITATIONS.md); this decides what else of the host rides
/// along with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostView {
    /// The whole host `/usr` (and `/bin`, `/lib`, ...), read-only: every
    /// header, library and pkg-config file this machine has installed is
    /// visible to the build.
    Full,
    /// The host's runtime files plus the C runtime's own development files:
    /// glibc, libxcrypt and kernel headers, their link-time libraries and
    /// start files, and the compiler's own directories. Every other host
    /// header, linker-visible library, static archive, libtool archive,
    /// pkg-config file and CMake package directory is absent, so a build
    /// cannot link something one host happens to have installed and
    /// another does not. Programs keep every shared library they load at
    /// run time.
    RuntimeOnly,
    /// The whole host filesystem, read-only, `/tmp` included, so a tool
    /// sees every path an unconfined run of it would. Only for a tool from
    /// the store that reads the project as data and runs none of its code
    /// (npm's workspace member reader): no host socket scan can cover `/`,
    /// so the trust is in the tool, and ward's signing keys are hidden.
    /// Network, writes outside the declared roots, and the environment
    /// stay confined as in every view.
    WholeHost,
}

/// The host root bubblewrap starts from: the whole of `/`, read-only, for
/// `HostView::WholeHost`, and the system directories otherwise.
pub(super) fn push_host_root(args: &mut Vec<OsString>, whole_host: bool) -> io::Result<()> {
    if whole_host {
        push_bind(args, "--ro-bind", "/", "/");
    } else {
        args.extend(system_root_args(Path::new("/"))?);
    }
    Ok(())
}

/// Cover each of ward's signing keys with `/dev/null` in the whole-host
/// view, after every other bind.
pub(super) fn push_hidden_keys(args: &mut Vec<OsString>, whole_host: bool) {
    if !whole_host {
        return;
    }
    for key in hidden_keys() {
        push_arg(args, "--ro-bind");
        push_arg(args, "/dev/null");
        args.push(key.into_os_string());
    }
}

/// The Seatbelt rules the whole-host view adds: every read, less the keys.
pub(super) fn push_whole_host_profile(profile: &mut String, view: HostView) {
    if view != HostView::WholeHost {
        return;
    }
    profile.push_str("(allow file-read*)\n");
    for key in hidden_keys() {
        profile.push_str(&format!(
            "(deny file-read* (literal {:?}))\n",
            key.display().to_string()
        ));
    }
}

/// Ward's signing keys as they really are on disk, for `HostView::WholeHost`
/// to cover: each existing one, by its symlink-free path.
fn hidden_keys() -> Vec<PathBuf> {
    existing_keys(&crate::kernel::resolve::confine::signing_key_paths())
}

pub(super) fn existing_keys(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut keys: Vec<PathBuf> = paths
        .iter()
        .filter_map(|key| fs::canonicalize(key).ok())
        .filter(|key| key.is_file())
        .collect();
    keys.sort();
    keys.dedup();
    keys
}
