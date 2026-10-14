//! .NET's archive reads and extraction: every call this tailor makes
//! into `kernel::archive`. heavy.yml's `gate` watches
//! `src/tailors/*/unpack.rs`, so a change here runs the heavy suite against
//! real archives (#325). `tests/architecture.rs` keeps the calls here.

use super::*;
use crate::kernel::archive::{Compression, ExtractOptions};

/// A gzip `body` inflated, or `None` when it is not gzip or inflates past
/// `cap` bytes (a registration leaf's `published` lookup).
pub(super) fn gunzip_capped(body: &[u8], cap: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(body)
        .take(cap + 1)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() as u64 <= cap).then_some(out)
}

#[cfg(test)]
pub(super) fn extract_sdk_archive(tarball: &Path, staged: &Path) -> io::Result<()> {
    // No activity lease: the extraction is test-only and writes scratch
    // directories outside any store.
    crate::kernel::archive::extract_with_options(
        tarball,
        staged,
        &ExtractOptions::platform_build(0),
        Compression::Gzip,
    )
    .map(|_| ())
    .map_err(|e| io::Error::new(e.kind(), format!("extract dotnet SDK archive: {e}")))?;
    if !staged.join("dotnet").is_file() {
        return Err(err("dotnet SDK extraction failed or has unexpected layout"));
    }
    Ok(())
}

pub(super) fn extract_sdk_archive_for(
    activity: &StoreActivity,
    tarball: &Path,
    staged: &Path,
) -> io::Result<()> {
    crate::kernel::archive::extract_with_activity_and_options(
        activity,
        tarball,
        staged,
        &ExtractOptions::platform_build(0),
        Compression::Gzip,
    )
    .map(|_| ())
    .map_err(|e| io::Error::new(e.kind(), format!("extract dotnet SDK archive: {e}")))?;
    if !staged.join("dotnet").is_file() {
        return Err(err("dotnet SDK extraction failed or has unexpected layout"));
    }
    Ok(())
}
