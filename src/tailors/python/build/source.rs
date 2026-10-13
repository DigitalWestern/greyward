//! What pip builds from: the tree ward unpacked from an sdist, never the
//! archive itself (#675).

use crate::kernel::activity::StoreActivity;
use crate::tailors::python::build_requires::{self, ArchiveInfo};
use std::io;
use std::path::{Path, PathBuf};

/// An sdist on its way to the build: unpacked under `work` already, or
/// still the verified archive, held until it is.
pub(super) enum SdistSource {
    Unpacked(PathBuf),
    Held(crate::kernel::fetch::CacheLease),
}

impl SdistSource {
    /// The unpacked tree pip builds from. pip is never handed the archive:
    /// its zip and tar readers are not ward's, and a member they read
    /// differently (a ZIP64 size override, a Unicode path field) would
    /// build bytes ward never inspected or budgeted (#675). The archive's
    /// lease is released here, before toolchain realization can fetch more
    /// cache entries.
    pub(super) fn unpacked(
        self,
        activity: &StoreActivity,
        info: &ArchiveInfo,
        work: &Path,
    ) -> io::Result<PathBuf> {
        match self {
            SdistSource::Unpacked(source) => Ok(source),
            SdistSource::Held(sdist) => {
                build_requires::extract_sdist_for(activity, &sdist, &work.join("source"), info)
            }
        }
    }
}

/// `pip wheel` on `input`, which must be the tree ward unpacked: pip
/// handed the archive would read it with its own zip or tar reader, which
/// can disagree with ward's about a member's size or name (#675).
pub(super) fn pip_wheel_argv(
    py: &Path,
    log: &Path,
    outdir: &Path,
    input: &Path,
) -> io::Result<Vec<String>> {
    if !input.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "pip builds from the tree ward unpacked, not {}",
                input.display()
            ),
        ));
    }
    let text = |path: &Path| path.to_string_lossy().into_owned();
    let mut argv = vec![
        text(py),
        "-m".into(),
        "pip".into(),
        "--log".into(),
        text(log),
    ];
    for arg in [
        "wheel",
        "--no-deps",
        "--no-build-isolation",
        "--no-index",
        "-w",
    ] {
        argv.push(arg.into());
    }
    argv.extend([text(outdir), text(input)]);
    Ok(argv)
}
