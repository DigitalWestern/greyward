//! The `Cargo.lock` of a Python sdist with Rust in it: where cargo may put
//! it, which one cargo wrote, and the cache of one ward generated (its text
//! and where in the sdist it goes), put back once it passes the lock check.
//!
//! Cargo writes the lock beside the manifest of the workspace root: the
//! selected manifest's own directory, or one above it (`rust/Cargo.toml`
//! for `rust/native/Cargo.toml`). Ward does not work out which: it lets
//! cargo write any of them ([`lock_candidates`]) and takes the one it
//! wrote ([`written_cargo_lock`]), and a cached lock goes back to that
//! same place.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Every place, relative to the source root, cargo may write the lock for
/// the manifest `manifest_rel`: beside it, and beside each directory above
/// it up to the source root. Nearest first.
pub(crate) fn lock_candidates(manifest_rel: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut dir = manifest_rel.parent();
    while let Some(at) = dir.filter(|at| !at.as_os_str().is_empty()) {
        found.push(at.join("Cargo.lock"));
        dir = at.parent();
    }
    found.push(PathBuf::from("Cargo.lock"));
    found
}

/// The `Cargo.lock` the sdist ships for `manifest_rel`, relative to
/// `source`: the nearest of [`lock_candidates`] that is a file.
pub(super) fn cargo_lock_for(source: &Path, manifest_rel: &Path) -> Option<PathBuf> {
    lock_candidates(manifest_rel)
        .into_iter()
        .find(|lock| source.join(lock).is_file())
}

/// The lock cargo wrote for `manifest_rel` in a source that held none of
/// the [`lock_candidates`] before it ran: the one of them that is a file
/// now. Cargo writes exactly one; none, or more than one, is an error.
pub(crate) fn written_cargo_lock(source: &Path, manifest_rel: &Path) -> io::Result<PathBuf> {
    let written: Vec<PathBuf> = lock_candidates(manifest_rel)
        .into_iter()
        .filter(|lock| source.join(lock).is_file())
        .collect();
    match written.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "store cargo generated no Cargo.lock for {} in it or a directory above it",
                manifest_rel.display()
            ),
        )),
        many => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "store cargo left more than one Cargo.lock for {}: {}",
                manifest_rel.display(),
                many.iter()
                    .map(|lock| lock.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

pub(super) fn cargo_lock_cache_key(sdist_sha256: &str, rust_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(
        format!("{sdist_sha256}\0{rust_id}").as_bytes(),
    ))
}

/// A generated lock ward cached: its text, and where in the sdist cargo
/// wrote it (relative to the source root).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CachedLock {
    pub(super) text: String,
    pub(super) at: PathBuf,
}

/// The cached lock at `text_path`, with where it goes at `at_path`; `None`
/// (a cache miss: cargo generates it again) when either is missing or the
/// place is not one cargo may write for `manifest_rel`
/// ([`lock_candidates`]), as in a cache written before ward kept the place.
pub(super) fn read_cached_lock(
    text_path: &Path,
    at_path: &Path,
    manifest_rel: &Path,
) -> Option<CachedLock> {
    let at = PathBuf::from(fs::read_to_string(at_path).ok()?.trim_end_matches('\n'));
    if !lock_candidates(manifest_rel).contains(&at) {
        return None;
    }
    let text = fs::read_to_string(text_path).ok()?;
    Some(CachedLock { text, at })
}

/// Cache `lock`: where it goes first, then its text, so an interrupted
/// write leaves a miss rather than a lock with no place.
pub(super) fn write_cached_lock(
    text_path: &Path,
    at_path: &Path,
    lock: &CachedLock,
) -> io::Result<()> {
    for path in [at_path, text_path] {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(at_path, format!("{}\n", lock.at.display()))?;
    fs::write(text_path, &lock.text)
}

/// Put a cached generated `Cargo.lock` back where cargo wrote it, `at`
/// (relative to `source`). The door checked it when it generated it; the
/// cached copy is held to the same rule, and its transports recorded under
/// the policy (a deny refuses here), before it is written or reused
/// (`cargo_door::refuse_lock_sources`).
pub(super) fn reuse_cached_cargo_lock(text: &str, source: &Path, at: &Path) -> io::Result<()> {
    for exception in crate::kernel::provider::cargo_door::refuse_lock_sources(text.as_bytes())? {
        crate::kernel::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
    }
    let lock_path = source.join(at);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    #[test]
    fn cargo_may_write_the_lock_beside_the_manifest_or_any_directory_above() {
        assert_eq!(
            lock_candidates(Path::new("Cargo.toml")),
            ["Cargo.lock"].map(PathBuf::from)
        );
        assert_eq!(
            lock_candidates(Path::new("native/Cargo.toml")),
            ["native/Cargo.lock", "Cargo.lock"].map(PathBuf::from)
        );
        assert_eq!(
            lock_candidates(Path::new("rust/native/Cargo.toml")),
            ["rust/native/Cargo.lock", "rust/Cargo.lock", "Cargo.lock"].map(PathBuf::from)
        );
    }

    /// The two layouts cargo puts the lock above the selected manifest
    /// for: a root workspace with a `native/` member, and
    /// `rust/native/Cargo.toml` in a workspace at `rust/`. The lock found
    /// is where cargo wrote it; a cached lock goes back to that place, not
    /// beside the member, and a cache with no place (or one cargo could
    /// not have written) is a miss.
    #[test]
    fn a_workspace_lock_is_found_cached_and_restored_where_cargo_wrote_it() {
        let _serial = crate::kernel::policy::attribution_test_lock();
        let temp = TempDir::named("python-workspace-cargo-lock");
        let lock = "version = 4\n[[package]]\nname = \"native\"\nversion = \"0.1.0\"\n";
        for (name, manifest, written) in [
            ("root-workspace", "native/Cargo.toml", "Cargo.lock"),
            (
                "rust-workspace",
                "rust/native/Cargo.toml",
                "rust/Cargo.lock",
            ),
        ] {
            let manifest = Path::new(manifest);
            let source = temp.0.join(name).join("source");
            fs::create_dir_all(source.join(manifest.parent().unwrap())).unwrap();
            assert!(written_cargo_lock(&source, manifest).is_err(), "{name}");
            // What cargo generate-lockfile leaves.
            fs::write(source.join(written), lock).unwrap();
            let at = written_cargo_lock(&source, manifest).unwrap();
            assert_eq!(at, Path::new(written), "{name}");

            let cache = temp.0.join(name).join("cache");
            let (text_path, at_path) = (cache.join("lock"), cache.join("at"));
            assert_eq!(read_cached_lock(&text_path, &at_path, manifest), None);
            let cached = CachedLock {
                text: lock.to_string(),
                at: at.clone(),
            };
            write_cached_lock(&text_path, &at_path, &cached).unwrap();
            let read = read_cached_lock(&text_path, &at_path, manifest).unwrap();
            assert_eq!(read, cached, "{name}");

            // A fresh unpack of the sdist, warm: the lock goes back where
            // cargo wrote it, and cargo_lock_for finds it there.
            let fresh = temp.0.join(name).join("fresh");
            fs::create_dir_all(fresh.join(manifest.parent().unwrap())).unwrap();
            let attribution = crate::kernel::policy::Attribution::open("python").unwrap();
            reuse_cached_cargo_lock(&read.text, &fresh, &read.at).unwrap();
            attribution.discard();
            assert_eq!(fs::read_to_string(fresh.join(written)).unwrap(), lock);
            assert!(
                !fresh.join(manifest.with_file_name("Cargo.lock")).exists(),
                "{name}: restored beside the member"
            );
            assert_eq!(
                cargo_lock_for(&fresh, manifest).unwrap(),
                Path::new(written)
            );

            // A place cargo could not have written for this manifest.
            fs::write(&at_path, "elsewhere/Cargo.lock\n").unwrap();
            assert_eq!(read_cached_lock(&text_path, &at_path, manifest), None);
            fs::remove_file(&at_path).unwrap();
            assert_eq!(read_cached_lock(&text_path, &at_path, manifest), None);
        }
    }

    /// A cached generated lock is checked before it is reused, as the door
    /// checked it when cargo made it: a file registry is refused and the
    /// lock is not written; a git dependency read from a path or over the
    /// git protocol records its transport, and a policy denying
    /// `host-git-transport` refuses the reuse.
    #[test]
    fn a_cached_cargo_lock_is_checked_before_reuse() {
        let _serial = crate::kernel::policy::attribution_test_lock();
        let temp = TempDir::named("python-cached-cargo-lock");
        let at = Path::new("native/Cargo.lock");
        let bad = "version = 4\n[[package]]\nname = \"bad\"\nversion = \"1.0.0\"\n\
                   source = \"registry+file:///src/index\"\n";
        let error = reuse_cached_cargo_lock(bad, &temp.0, at).unwrap_err();
        assert_eq!(
            crate::kernel::error::class_of(&error),
            Some(crate::kernel::error::Class::Refused),
            "{error}"
        );
        assert!(!temp.0.join(at).exists());

        let commit = "0123456789abcdef0123456789abcdef01234567";
        for (url, subject) in [
            ("file:///srv/g", "file:///srv/g"),
            ("git://g.test/g", "git://g.test/g"),
        ] {
            let git = format!(
                "version = 4\n[[package]]\nname = \"g\"\nversion = \"1.0.0\"\n\
                 source = \"git+{url}#{commit}\"\n"
            );
            let attribution = crate::kernel::policy::Attribution::open("python").unwrap();
            reuse_cached_cargo_lock(&git, &temp.0, at).unwrap();
            let recorded = attribution.recorded();
            attribution.discard();
            assert_eq!(fs::read_to_string(temp.0.join(at)).unwrap(), git);
            assert!(
                recorded.iter().any(|exception| {
                    exception.kind == crate::kernel::policy::HOST_GIT_TRANSPORT
                        && exception.subject == subject
                }),
                "{url}: {recorded:?}"
            );
            fs::remove_file(temp.0.join(at)).unwrap();

            let _deny =
                crate::kernel::policy::PolicyScope::install(crate::kernel::policy::Policy {
                    deny: [crate::kernel::policy::HOST_GIT_TRANSPORT.to_string()]
                        .into_iter()
                        .collect(),
                    ..crate::kernel::policy::Policy::default()
                });
            let attribution = crate::kernel::policy::Attribution::open("python").unwrap();
            let error = reuse_cached_cargo_lock(&git, &temp.0, at).unwrap_err();
            attribution.discard();
            assert_eq!(
                crate::kernel::error::class_of(&error),
                Some(crate::kernel::error::Class::Refused),
                "{url}: {error}"
            );
            assert!(error.to_string().contains("host-git-transport"), "{error}");
            assert!(!temp.0.join(at).exists(), "{url}: written though denied");
        }
    }
}
