//! The `Cargo.lock` of a Python sdist with Rust in it: which workspace the
//! sdist's manifest belongs to, where its lock is, and the cache of one ward
//! generated (its text, where in the sdist it goes, and the transport
//! exceptions it was made with), put back once it passes the lock check.
//!
//! Cargo writes and reads the lock beside the manifest of the workspace
//! root, which cargo alone decides (a manifest with its own `[workspace]`
//! is its own root, whatever lock lies above it). Ward asks it:
//! `cargo locate-project --workspace` on the selected manifest, confined and
//! offline ([`workspace_root`]), and uses exactly `<root>/Cargo.lock`.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::kernel::policy::Exception;
use crate::kernel::provider::cargo_door;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};

/// The arguments of the confined `cargo locate-project` run that names the
/// workspace root of `manifest_arg` (relative to the sdist).
fn locate_args(manifest_arg: &str) -> [&str; 7] {
    [
        "locate-project",
        "--workspace",
        "--message-format",
        "plain",
        "--offline",
        "--manifest-path",
        manifest_arg,
    ]
}

/// The workspace root, relative to `source`, from what `cargo
/// locate-project --workspace --message-format plain` printed: the root
/// manifest's path inside the stage, which is bound at the source's real
/// path. Refused when it is not a `Cargo.toml` inside the sdist tree, or
/// when the selected manifest `manifest_rel` is not under it.
fn workspace_root(source: &Path, manifest_rel: &Path, printed: &str) -> io::Result<PathBuf> {
    let refuse = |why: String| crate::kernel::error::refused(io::ErrorKind::PermissionDenied, why);
    let manifest = Path::new(printed.trim_end_matches(['\n', '\r']));
    let real = fs::canonicalize(source).unwrap_or_else(|_| source.to_path_buf());
    let inside = [real.as_path(), source]
        .into_iter()
        .find_map(|root| manifest.strip_prefix(root).ok())
        .filter(|rel| rel.file_name() == Some("Cargo.toml".as_ref()))
        .filter(|rel| {
            rel.components()
                .all(|part| matches!(part, Component::Normal(_)))
        })
        .ok_or_else(|| {
            refuse(format!(
                "cargo places the workspace of the sdist's {} at {}, outside the sdist: ward \
                 builds an sdist only from its own files",
                manifest_rel.display(),
                manifest.display()
            ))
        })?;
    let root = inside
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();
    if !manifest_rel.starts_with(&root) {
        return Err(refuse(format!(
            "cargo places the workspace of the sdist's {} at {}, which does not hold it",
            manifest_rel.display(),
            inside.display()
        )));
    }
    Ok(root)
}

/// The workspace root cached at `path` for the sdist; `None` (ask cargo
/// again) when there is none, or it is not a directory of `source` holding
/// a `Cargo.toml` above `manifest_rel`.
pub(super) fn read_cached_root(path: &Path, source: &Path, manifest_rel: &Path) -> Option<PathBuf> {
    let root = PathBuf::from(fs::read_to_string(path).ok()?.trim_end_matches('\n'));
    let normal = root
        .components()
        .all(|part| matches!(part, Component::Normal(_)));
    (normal && manifest_rel.starts_with(&root) && source.join(&root).join("Cargo.toml").is_file())
        .then_some(root)
}

/// Cache the workspace root `root` cargo named for the sdist at `path`.
pub(super) fn write_cached_root(path: &Path, root: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", root.display()))
}

pub(super) fn cargo_lock_cache_key(sdist_sha256: &str, rust_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(
        format!("{sdist_sha256}\0{rust_id}").as_bytes(),
    ))
}

/// The transport exceptions of the sdist's lock `text` and its cargo
/// configuration ([`cargo_door::transport_exceptions`], the one set every
/// cargo path takes), refusing a lock from a source ward does not resolve
/// from ([`cargo_door::refuse_lock_sources`]).
pub(super) fn lock_exceptions(text: &str, source: &Path) -> io::Result<Vec<Exception>> {
    let sources = cargo_door::refuse_lock_sources(text.as_bytes())?;
    let files = cargo_door::config_files(source, &cargo_door::Bound::new(source)?)?;
    Ok(cargo_door::transport_exceptions(
        sources.iter().map(String::as_str),
        &files,
    ))
}

/// A generated lock ward cached, one entry under one key: its text, where
/// in the sdist cargo wrote it (relative to the source root), and the
/// transport exceptions it was generated with (the configuration's and the
/// lock's), so a reuse carries what the cold run recorded.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct CachedLock {
    pub(super) text: String,
    pub(super) at: PathBuf,
    pub(super) exceptions: Vec<Exception>,
}

/// The cached lock at `path` for the lock `at`; `None` (a cache miss: cargo
/// generates it again) when there is none, it does not parse, or it was
/// cached for another place.
pub(super) fn read_cached_lock(path: &Path, at: &Path) -> Option<CachedLock> {
    let cached: CachedLock = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    (cached.at == at).then_some(cached)
}

/// Cache `lock` at `path`, one file written whole.
pub(super) fn write_cached_lock(path: &Path, lock: &CachedLock) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(lock).map_err(io::Error::other)?;
    let partial = path.with_extension("partial");
    fs::write(&partial, bytes)?;
    fs::rename(partial, path)
}

/// Put a cached generated `Cargo.lock` back where cargo wrote it. Its
/// exceptions are the ones cached with it joined with a fresh pass over the
/// lock and this source's configuration ([`lock_exceptions`]), recorded
/// under the policy (a deny refuses here) before the lock is written: the
/// signed record carries what the cold run recorded, an evicted wheel or
/// environment notwithstanding.
pub(super) fn reuse_cached_cargo_lock(cached: &CachedLock, source: &Path) -> io::Result<()> {
    let mut exceptions = cached.exceptions.clone();
    for exception in lock_exceptions(&cached.text, source)? {
        if !exceptions.contains(&exception) {
            exceptions.push(exception);
        }
    }
    cargo_door::record_exceptions(&exceptions)?;
    let lock_path = source.join(&cached.at);
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
    fs::write(&lock_path, &cached.text)
}

/// The workspace root of the sdist's manifest `manifest_rel`, relative to
/// `source`, as cargo itself names it: `cargo locate-project --workspace`,
/// confined through `door` and offline, on the unpacked source
/// ([`workspace_root`] refuses a root outside the sdist).
pub(super) fn locate_workspace_root(
    door: &mut ResolutionDoor<'_>,
    rust_obj: &Path,
    manifest_rel: &Path,
    source: &Path,
) -> io::Result<PathBuf> {
    use crate::kernel::provider::cargo_door::{run_cargo, CargoPublish, CargoRun};
    let manifest_arg = manifest_rel.to_string_lossy().into_owned();
    let args = locate_args(&manifest_arg);
    let report = run_cargo(
        door,
        CargoRun {
            rust_obj,
            lock_root: source,
            args: &args,
            publish: CargoPublish::Detached {
                outputs: Vec::new(),
            },
        },
    )
    .map_err(|e| crate::kernel::error::context(e, "locate the sdist's Cargo workspace"))?;
    if let Some(objects) = report.ledger.clone() {
        door.keep_ledger(objects);
    }
    if !report.status.success() {
        return Err(io::Error::other(format!(
            "store cargo locate-project failed for the sdist: {}",
            crate::kernel::resolve::confine::scrub_signing_key(
                String::from_utf8_lossy(&report.stderr).trim()
            )
        )));
    }
    workspace_root(
        source,
        manifest_rel,
        &String::from_utf8_lossy(&report.stdout),
    )
}

/// `cargo generate-lockfile` for an sdist that ships no `Cargo.lock`,
/// confined through the door with the unpacked source as its greyward-owned
/// lock root (Detached): the lock is written back there, and the run's
/// ledger is kept on `door` for the sync that opened it to root under its
/// project. `manifest_rel` is the sdist's `Cargo.toml` and `root` its
/// workspace root ([`locate_workspace_root`]), both relative to `source`;
/// the one output is `<root>/Cargo.lock`, and cargo must write it.
pub(super) fn generate_cargo_lock(
    door: &mut ResolutionDoor<'_>,
    rust_obj: &Path,
    manifest_rel: &Path,
    root: &Path,
    source: &Path,
) -> io::Result<()> {
    use crate::kernel::provider::cargo_door::{run_cargo, CargoPublish, CargoRun};
    // A workspace member through a symlinked directory would be missing
    // from the confined run (the stage copies the link): refused.
    crate::kernel::provider::cargo_door::refuse_unlisted_members(
        &crate::kernel::fsroot::ProjectRoot::open(&source.join(root))?,
    )?;
    let manifest_arg = manifest_rel.to_string_lossy().into_owned();
    let args = [
        "generate-lockfile",
        "--manifest-path",
        manifest_arg.as_str(),
    ];
    let lock = root.join("Cargo.lock");
    // The sdist ships no Cargo.lock: this is its missing-lock door, whatever
    // the planning door it runs under.
    let mut missing_lock = door.reopen(DoorKind::MissingLock);
    let report = run_cargo(
        &mut missing_lock,
        CargoRun {
            rust_obj,
            lock_root: source,
            args: &args,
            publish: CargoPublish::Detached {
                outputs: vec![lock.clone()],
            },
        },
    )
    .map_err(|e| crate::kernel::error::context(e, "generate the sdist's Cargo.lock"))?;
    if let Some(objects) = report.ledger.clone() {
        missing_lock.keep_ledger(objects);
    }
    if !report.status.success() {
        return Err(io::Error::other(format!(
            "store cargo generate-lockfile failed for the sdist: {}",
            crate::kernel::resolve::confine::scrub_signing_key(
                String::from_utf8_lossy(&report.stderr).trim()
            )
        )));
    }
    if !source.join(&lock).is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "store cargo generated no {} for the sdist's {}",
                lock.display(),
                manifest_rel.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::{self, Attribution, Policy, PolicyScope, HOST_GIT_TRANSPORT};
    use crate::kernel::testutil::TempDir;

    /// The root cargo printed maps back to the sdist: the source root, a
    /// directory above the manifest, or the manifest's own. A root outside
    /// the sdist, or one that does not hold the manifest, is refused.
    #[test]
    fn the_workspace_root_is_the_one_cargo_names_inside_the_sdist() {
        let temp = TempDir::named("python-workspace-root");
        let source = temp.0.join("source");
        fs::create_dir_all(source.join("rust/native")).unwrap();
        let real = fs::canonicalize(&source).unwrap();
        let printed = |rel: &str| format!("{}\n", real.join(rel).display());
        let manifest = Path::new("rust/native/Cargo.toml");
        for (rel, root) in [
            ("Cargo.toml", ""),
            ("rust/Cargo.toml", "rust"),
            ("rust/native/Cargo.toml", "rust/native"),
        ] {
            assert_eq!(
                workspace_root(&source, manifest, &printed(rel)).unwrap(),
                Path::new(root)
            );
        }
        for outside in [
            temp.0.join("Cargo.toml").display().to_string(),
            "/elsewhere/Cargo.toml".to_string(),
            printed("other/Cargo.toml"),
            printed("rust/native/Cargo.lock"),
        ] {
            let error = workspace_root(&source, manifest, &outside).unwrap_err();
            assert_eq!(
                crate::kernel::error::class_of(&error),
                Some(crate::kernel::error::Class::Refused),
                "{outside}: {error}"
            );
        }
    }

    /// A cached root is used only while it still names a workspace manifest
    /// above the selected one in this source.
    #[test]
    fn a_cached_workspace_root_is_checked_against_the_source() {
        let temp = TempDir::named("python-cached-root");
        let source = temp.0.join("source");
        fs::create_dir_all(source.join("rust/native")).unwrap();
        fs::write(source.join("rust/Cargo.toml"), "[workspace]\n").unwrap();
        let manifest = Path::new("rust/native/Cargo.toml");
        let cache = temp.0.join("cache/root");
        assert_eq!(read_cached_root(&cache, &source, manifest), None);
        write_cached_root(&cache, Path::new("rust")).unwrap();
        assert_eq!(
            read_cached_root(&cache, &source, manifest),
            Some(PathBuf::from("rust"))
        );
        for bad in ["../rust", "/rust", "other", "rust/native"] {
            fs::write(&cache, format!("{bad}\n")).unwrap();
            assert_eq!(read_cached_root(&cache, &source, manifest), None, "{bad}");
        }
    }

    fn deny_transports() -> PolicyScope {
        PolicyScope::install(Policy {
            deny: [HOST_GIT_TRANSPORT.to_string()].into_iter().collect(),
            ..Policy::default()
        })
    }

    /// An sdist whose cargo configuration names an unused ssh registry:
    /// the cold run's exceptions are cached with the lock, so after the
    /// wheel and environment are evicted a rebuild from the cached lock
    /// records the transport into the closure, and a policy denying
    /// `host-git-transport` refuses it, before the lock is written back,
    /// even when the configuration is gone from the source it is put into.
    #[test]
    fn a_cached_sdist_lock_carries_the_transports_it_was_generated_with() {
        let _serial = policy::attribution_test_lock();
        let temp = TempDir::named("python-cached-lock-transports");
        let lock = "version = 4\n[[package]]\nname = \"native\"\nversion = \"0.1.0\"\n";
        let config = "[registries.internal]\nindex = \"ssh://git@git.internal.test/index\"\n";
        let cold = temp.0.join("cold");
        fs::create_dir_all(cold.join(".cargo")).unwrap();
        fs::write(cold.join(".cargo/config.toml"), config).unwrap();
        let exceptions = lock_exceptions(lock, &cold).unwrap();
        assert_eq!(
            exceptions
                .iter()
                .map(|e| (e.kind.as_str(), e.subject.as_str()))
                .collect::<Vec<_>>(),
            [(HOST_GIT_TRANSPORT, "ssh://git@git.internal.test/index")]
        );
        let entry = temp.0.join("cache/entry");
        let at = PathBuf::from("Cargo.lock");
        let cached = CachedLock {
            text: lock.to_string(),
            at: at.clone(),
            exceptions,
        };
        write_cached_lock(&entry, &cached).unwrap();
        assert_eq!(read_cached_lock(&entry, Path::new("rust/Cargo.lock")), None);
        let read = read_cached_lock(&entry, &at).unwrap();
        assert_eq!(read, cached);

        // The rebuild: a fresh unpack with the same configuration, and one
        // without it. Both record the cached transport.
        for (name, with_config) in [("same", true), ("bare", false)] {
            let fresh = temp.0.join(name);
            fs::create_dir_all(fresh.join(".cargo")).unwrap();
            if with_config {
                fs::write(fresh.join(".cargo/config.toml"), config).unwrap();
            }
            let attribution = Attribution::open("python").unwrap();
            reuse_cached_cargo_lock(&read, &fresh).unwrap();
            let recorded = attribution.recorded();
            attribution.discard();
            assert!(
                recorded.iter().any(|e| e.kind == HOST_GIT_TRANSPORT
                    && e.subject == "ssh://git@git.internal.test/index"),
                "{name}: {recorded:?}"
            );
            fs::remove_file(fresh.join(&at)).unwrap();

            let _deny = deny_transports();
            let attribution = Attribution::open("python").unwrap();
            let error = reuse_cached_cargo_lock(&read, &fresh).unwrap_err();
            attribution.discard();
            assert_eq!(
                crate::kernel::error::class_of(&error),
                Some(crate::kernel::error::Class::Refused),
                "{name}: {error}"
            );
            assert!(!fresh.join(&at).exists(), "{name}: written though denied");
        }
    }

    /// A cached generated lock is checked before it is reused, as the door
    /// checked it when cargo made it: a file registry is refused and the
    /// lock is not written; a git dependency read from a path or over the
    /// git protocol records its transport, and a policy denying
    /// `host-git-transport` refuses the reuse.
    #[test]
    fn a_cached_cargo_lock_is_checked_before_reuse() {
        let _serial = policy::attribution_test_lock();
        let temp = TempDir::named("python-cached-cargo-lock");
        let at = PathBuf::from("native/Cargo.lock");
        let cached = |text: String| CachedLock {
            text,
            at: at.clone(),
            exceptions: Vec::new(),
        };
        let bad = "version = 4\n[[package]]\nname = \"bad\"\nversion = \"1.0.0\"\n\
                   source = \"registry+file:///src/index\"\n";
        let error = reuse_cached_cargo_lock(&cached(bad.to_string()), &temp.0).unwrap_err();
        assert_eq!(
            crate::kernel::error::class_of(&error),
            Some(crate::kernel::error::Class::Refused),
            "{error}"
        );
        assert!(!temp.0.join(&at).exists());

        let commit = "0123456789abcdef0123456789abcdef01234567";
        for url in ["file:///srv/g", "git://g.test/g"] {
            let git = cached(format!(
                "version = 4\n[[package]]\nname = \"g\"\nversion = \"1.0.0\"\n\
                 source = \"git+{url}#{commit}\"\n"
            ));
            let attribution = Attribution::open("python").unwrap();
            reuse_cached_cargo_lock(&git, &temp.0).unwrap();
            let recorded = attribution.recorded();
            attribution.discard();
            assert_eq!(fs::read_to_string(temp.0.join(&at)).unwrap(), git.text);
            assert!(
                recorded
                    .iter()
                    .any(|e| e.kind == HOST_GIT_TRANSPORT && e.subject == url),
                "{url}: {recorded:?}"
            );
            fs::remove_file(temp.0.join(&at)).unwrap();

            let _deny = deny_transports();
            let attribution = Attribution::open("python").unwrap();
            let error = reuse_cached_cargo_lock(&git, &temp.0).unwrap_err();
            attribution.discard();
            assert_eq!(
                crate::kernel::error::class_of(&error),
                Some(crate::kernel::error::Class::Refused),
                "{url}: {error}"
            );
            assert!(error.to_string().contains("host-git-transport"), "{error}");
            assert!(!temp.0.join(&at).exists(), "{url}: written though denied");
        }
    }
}
