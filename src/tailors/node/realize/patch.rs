//! pnpm patches: re-verified against the lock's hash, snapshotted into a
//! private stage directory, and applied with `/usr/bin/patch`.

use super::*;

/// A pnpm patch, re-verified against the hash the lock attested before it is
/// applied: the file on disk can have changed since lock verification. A
/// normalized match also rechecks the raw-byte identity binding.
pub(super) fn read_verified_patch(package_path: &str, patch: &NpmPatch) -> io::Result<Vec<u8>> {
    let patch_path = Path::new(&patch.path);
    let patch_bytes = fs::read(patch_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("{}: read verified patch {}: {e}", package_path, patch.path),
        )
    })?;
    // Same acceptance set as the lock-time check, from the same function, so a
    // pnpm 9 base32 hash cannot pass one gate and fail the other.
    let matched =
        super::lock_import::check_patch_hash(&patch.hash, &patch_bytes).map_err(|actual| {
            err(format!(
                "{}: patch {} changed after lock verification (expected {}, got {})",
                package_path, patch.path, patch.hash, actual
            ))
        })?;
    match patch.content_sha256.as_deref() {
        // The lock matched the raw bytes, so the identity carries no separate
        // raw digest: the declared hash is the only binding, and it only binds
        // raw bytes when the match is raw. A file rewritten so that it matches
        // only after lossy UTF-8 normalization (a U+FFFD sequence replaced by
        // the invalid byte it stands for) would otherwise reach `patch` with
        // different bytes under an unchanged object id.
        None => {
            if matched != super::lock_import::PatchMatch::Raw {
                return Err(err(format!(
                    "{}: patch {} changed after lock verification (the lock hash matched the \
                     raw bytes at lock time but only their normalized form now)",
                    package_path, patch.path
                )));
            }
        }
        Some(expected) => {
            let actual = hex::encode(sha2::Sha256::digest(&patch_bytes));
            if actual != expected {
                return Err(err(format!(
                    "{}: patch {} changed after lock verification (expected sha256 {}, got {})",
                    package_path, patch.path, expected, actual
                )));
            }
        }
    }
    Ok(patch_bytes)
}

pub(super) struct PatchSnapshot {
    pub(super) root: PathBuf,
    path: PathBuf,
    source: PathBuf,
}

impl PatchSnapshot {
    fn open(&self) -> io::Result<fs::File> {
        fs::File::open(&self.path)
    }
}

impl Drop for PatchSnapshot {
    fn drop(&mut self) {
        let _ = crate::kernel::store::remove_tree(&self.root);
    }
}

/// Write the verified bytes to a fresh private stage directory under
/// `store/tmp`. If a process is killed before the guard runs, the leftover
/// `stage-*` directory is enumerated by `kernel::gc::read::read_stages` and
/// reclaimed by the stale-stage plan; ordinary success and error paths remove
/// the whole directory through `PatchSnapshot::drop`.
pub(super) fn snapshot_verified_patch(
    store: &Store,
    activity: &StoreActivity,
    package_path: &str,
    patch: &NpmPatch,
) -> io::Result<PatchSnapshot> {
    let patch_bytes = read_verified_patch(package_path, patch)?;
    let root = store.stage_with_activity(activity)?;
    let path = root.join("patch");
    let snapshot = PatchSnapshot {
        root,
        path,
        source: PathBuf::from(&patch.path),
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&snapshot.path)?;
    file.write_all(&patch_bytes)?;
    drop(file);
    Ok(snapshot)
}

pub(super) fn apply_verified_patch(
    activity: &StoreActivity,
    package_path: &str,
    snapshot: &PatchSnapshot,
    dest: &Path,
) -> io::Result<()> {
    let snapshot_file = snapshot.open().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "{}: open patch snapshot for {}: {e}",
                package_path,
                snapshot.source.display()
            ),
        )
    })?;
    let mut command = Command::new("/usr/bin/patch");
    command
        .args(["-p1", "--batch", "--forward"])
        .current_dir(dest)
        .stdin(snapshot_file);
    let status = crate::kernel::supervise::local_status(&mut command, activity).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "{}: spawn /usr/bin/patch for {}: {e}",
                package_path,
                snapshot.source.display()
            ),
        )
    })?;
    if !status.success() {
        return Err(err(format!(
            "{}: applying patch {} failed",
            package_path,
            snapshot.source.display()
        )));
    }
    normalize_modes(dest).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("{}: normalize patched modes: {e}", package_path),
        )
    })
}
