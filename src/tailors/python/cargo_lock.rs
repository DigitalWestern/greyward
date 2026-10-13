//! The `Cargo.lock` of a Python sdist with Rust in it: where cargo leaves
//! it, the cache key of one ward generated, and putting a cached one back
//! once it passes the lock check.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn cargo_lock_for(source: &Path, manifest: &Path) -> Option<PathBuf> {
    [
        manifest.parent().map(|parent| parent.join("Cargo.lock")),
        Some(source.join("Cargo.lock")),
    ]
    .into_iter()
    .flatten()
    .find(|path| path.is_file())
}

pub(super) fn cargo_lock_cache_key(sdist_sha256: &str, rust_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(
        format!("{sdist_sha256}\0{rust_id}").as_bytes(),
    ))
}

/// Put a cached generated `Cargo.lock` back beside the sdist's manifest.
/// The door checked it when it generated it; the cached copy is held to the
/// same rule, and its transports recorded under the policy, before it is
/// written or reused (`cargo_door::refuse_lock_sources`).
pub(super) fn reuse_cached_cargo_lock(
    text: &str,
    source: &Path,
    manifest_rel: &Path,
) -> io::Result<()> {
    for exception in crate::kernel::provider::cargo_door::refuse_lock_sources(text.as_bytes())? {
        crate::kernel::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
    }
    let lock_path = generated_cargo_lock_path(source, manifest_rel);
    if fs::symlink_metadata(&lock_path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cached Cargo.lock would overwrite an extracted symlink: {}",
                lock_path.display()
            ),
        ));
    }
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&lock_path, text)
}

pub(super) fn generated_cargo_lock_path(source: &Path, manifest: &Path) -> PathBuf {
    source
        .join(manifest.parent().unwrap_or_else(|| Path::new("")))
        .join("Cargo.lock")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cached generated lock is checked before it is reused, as the door
    /// checked it when cargo made it: a file registry is refused and the
    /// lock is not written; a git dependency read from a path records its
    /// transport.
    #[test]
    fn a_cached_cargo_lock_is_checked_before_reuse() {
        let _serial = crate::kernel::policy::attribution_test_lock();
        let temp = crate::kernel::testutil::TempDir::named("python-cached-cargo-lock");
        let manifest = Path::new("native/Cargo.toml");
        let bad = "version = 4\n[[package]]\nname = \"bad\"\nversion = \"1.0.0\"\n\
                   source = \"registry+file:///src/index\"\n";
        let error = reuse_cached_cargo_lock(bad, &temp.0, manifest).unwrap_err();
        assert_eq!(
            crate::kernel::error::class_of(&error),
            Some(crate::kernel::error::Class::Refused),
            "{error}"
        );
        assert!(!temp.0.join("native/Cargo.lock").exists());

        let git = "version = 4\n[[package]]\nname = \"g\"\nversion = \"1.0.0\"\n\
                   source = \"git+file:///srv/g#0123456789abcdef0123456789abcdef01234567\"\n";
        let attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        reuse_cached_cargo_lock(git, &temp.0, manifest).unwrap();
        let recorded = attribution.recorded();
        attribution.discard();
        assert_eq!(
            fs::read_to_string(temp.0.join("native/Cargo.lock")).unwrap(),
            git
        );
        assert!(
            recorded.iter().any(|exception| {
                exception.kind == crate::kernel::policy::HOST_GIT_TRANSPORT
                    && exception.subject == "file:///srv/g"
            }),
            "{recorded:?}"
        );
    }
}
