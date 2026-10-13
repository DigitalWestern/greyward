//! Python's archive reads and extraction: every call this tailor makes
//! into `kernel::archive` (tar and zip alike), and the wheel installer in
//! `wheel`. heavy.yml's `gate` watches each tailor's `unpack.rs` and
//! `unpack/`, so a change here runs the heavy suite against real archives
//! (#325, #557). `tests/architecture.rs` keeps the calls here.

pub(super) mod wheel;

use crate::kernel::activity::StoreActivity;
use crate::kernel::archive::{self, Compression, Entry, ZipReader};
use std::io;
use std::path::{Path, PathBuf};

/// A zip sdist, listed under the kernel's zip rules with the byte budget
/// a `.tar.gz` sdist gets.
fn open_zip_sdist(path: &Path) -> io::Result<ZipReader> {
    ZipReader::open(path, archive::MAX_ARCHIVE_BYTES)
}

/// Every member name of a zip sdist, in archive order.
pub(super) fn zip_sdist_names(path: &Path) -> io::Result<Vec<String>> {
    Ok(open_zip_sdist(path)?
        .members()
        .iter()
        .map(|member| member.name.clone())
        .collect())
}

/// One member of a zip sdist, by its exact stored name, at most `cap`
/// bytes.
pub(super) fn read_zip_sdist_member(path: &Path, member: &str, cap: u64) -> io::Result<Vec<u8>> {
    open_zip_sdist(path)?.read(member, cap)
}

/// Write a zip sdist's members into `destination`. `place` maps a member
/// name to its path under `destination`, or `None` to skip it, and
/// refuses a name it does not accept. Files keep their execute bit, as a
/// `.tar.gz` sdist's do.
pub(super) fn extract_zip_sdist(
    path: &Path,
    destination: &Path,
    place: impl Fn(&str) -> io::Result<Option<String>>,
) -> io::Result<()> {
    open_zip_sdist(path)?.extract(destination, |member| {
        Ok(place(&member.name)?.map(PathBuf::from))
    })
}

/// Every member of a `.tar.gz` sdist, validated by the header reader.
pub(super) fn list_sdist(path: &Path, activity: Option<&StoreActivity>) -> io::Result<Vec<Entry>> {
    match activity {
        Some(activity) => archive::list_with_activity(activity, path, Compression::Gzip),
        None => archive::list(path, Compression::Gzip),
    }
}

/// Extract a `.tar.gz` sdist that `list_sdist` listed as `listed` into
/// `destination`, past its one top-level directory.
pub(super) fn extract_sdist(
    path: &Path,
    destination: &Path,
    activity: Option<&StoreActivity>,
    listed: &[Entry],
) -> io::Result<()> {
    match activity {
        Some(activity) => archive::extract_validated_with_activity(
            activity,
            path,
            destination,
            1,
            Compression::Gzip,
            listed,
        ),
        None => archive::extract_validated(path, destination, 1, Compression::Gzip, listed),
    }
}

/// One member of a `.tar.gz` sdist, at most `cap` bytes, read in process.
pub(super) fn read_sdist_member(path: &Path, member: &str, cap: u64) -> io::Result<Vec<u8>> {
    archive::read_member(path, Compression::Gzip, member, cap)
}
