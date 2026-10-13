//! Which archive each registry package was installed from.
//!
//! A package's integrity may list several digests, and its tarball's bytes
//! matched one of them when the realization fetched and verified it. That
//! digest is recorded per package, in the environment object itself, so a
//! warm sync names the same one the cold sync verified. The environment's
//! cache set cannot say it: it also holds every declared artifact a
//! lifecycle script was given, and one of those can be another candidate of
//! a package's integrity.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::kernel::digest::{sri_candidates, Digest};

/// Where in the environment object the record lives. Outside
/// `node_modules`, so no projection links it into a project.
pub(super) const ARCHIVES_FILE: &str = ".greyward/archives.json";
const ARCHIVES_SCHEMA: &str = "node-archives/1";

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Write `matched` (lockfile path to the integrity candidate its tarball
/// matched) into the staged environment `staged`.
pub(super) fn write_matched_archives(
    staged: &Path,
    matched: &BTreeMap<String, Digest>,
) -> io::Result<()> {
    let packages: serde_json::Map<String, serde_json::Value> = matched
        .iter()
        .map(|(path, digest)| {
            (
                path.clone(),
                serde_json::json!({"algo": digest.algo(), "hex": digest.hex()}),
            )
        })
        .collect();
    let path = staged.join(ARCHIVES_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::json!({"schema": ARCHIVES_SCHEMA, "packages": packages});
    fs::write(&path, serde_json::to_vec_pretty(&body)?)
}

/// The record [`write_matched_archives`] left in `env_obj`, `None` for an
/// environment without one.
pub(super) fn read_matched_archives(
    env_obj: &Path,
) -> io::Result<Option<BTreeMap<String, Digest>>> {
    let path = env_obj.join(ARCHIVES_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| invalid(format!("{}: {e}", path.display())))?;
    if body["schema"] != ARCHIVES_SCHEMA {
        return Err(invalid(format!(
            "{}: unknown schema {}",
            path.display(),
            body["schema"]
        )));
    }
    let packages = body["packages"]
        .as_object()
        .ok_or_else(|| invalid(format!("{}: no packages", path.display())))?;
    let mut matched = BTreeMap::new();
    for (package, digest) in packages {
        let algo = digest["algo"].as_str().unwrap_or_default();
        let hex = digest["hex"].as_str().unwrap_or_default();
        let digest = Digest::from_parts(algo, hex)
            .map_err(|e| invalid(format!("{}: {package}: {e}", path.display())))?;
        matched.insert(package.clone(), digest);
    }
    Ok(Some(matched))
}

/// Give each package row of `body` the digest its bytes matched, as
/// `env_obj` recorded it when the package's tarball was verified. A row
/// the record does not name (a git or local package) gets none, and so
/// does every row of an environment without the record.
pub(super) fn record_matched_digests(
    body: &mut serde_json::Value,
    env_obj: &Path,
) -> io::Result<()> {
    let Some(matched) = read_matched_archives(env_obj)? else {
        return Ok(());
    };
    for row in body["packages"].as_array_mut().into_iter().flatten() {
        let path = row["path"].as_str().unwrap_or_default();
        let Some(digest) = matched.get(path) else {
            continue;
        };
        let integrity = row["integrity"].as_str().unwrap_or_default();
        if !sri_candidates(integrity)
            .map(|candidates| candidates.contains(digest))
            .unwrap_or(false)
        {
            return Err(invalid(format!(
                "{path}: the environment's archive {}:{} is not one of the integrity's digests",
                digest.algo(),
                digest.hex()
            )));
        }
        row["matched_digest"] = serde_json::json!({"algo": digest.algo(), "hex": digest.hex()});
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    const FIRST: &str = "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ==";
    const SECOND: &str = "sha512-AAAAktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ==";

    fn rows(integrity: &str) -> serde_json::Value {
        serde_json::json!({"packages": [
            {"path": "node_modules/a", "integrity": integrity},
            {"path": "node_modules/git", "integrity": "git:0123"},
        ]})
    }

    /// A row names the candidate its own tarball matched, as the record
    /// says, even when the environment also holds bytes (a lifecycle
    /// artifact) for another candidate of the same integrity that sorts
    /// first.
    #[test]
    fn a_row_names_the_digest_its_own_tarball_matched() {
        let temp = TempDir::named("node-archives");
        let integrity = format!("{FIRST} {SECOND}");
        let tarball = Digest::from_sri(FIRST).unwrap();
        let artifact = Digest::from_sri(SECOND).unwrap();
        assert!(artifact < tarball, "the artifact must sort first");
        write_matched_archives(
            &temp.0,
            &[("node_modules/a".to_string(), tarball.clone())].into(),
        )
        .unwrap();

        let mut body = rows(&integrity);
        record_matched_digests(&mut body, &temp.0).unwrap();
        assert_eq!(
            body["packages"][0]["matched_digest"],
            serde_json::json!({"algo": "sha512", "hex": tarball.hex()})
        );
        assert!(body["packages"][1].get("matched_digest").is_none());

        // A record naming a digest the row's integrity does not list is
        // refused, not exported.
        let mut body = rows(SECOND);
        let error = record_matched_digests(&mut body, &temp.0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// An environment without the record names no digest for any row, so
    /// the SBOM says the match is unrecorded.
    #[test]
    fn an_environment_without_the_record_names_no_digest() {
        let temp = TempDir::named("node-archives-none");
        let mut body = rows(FIRST);
        record_matched_digests(&mut body, &temp.0).unwrap();
        assert!(body["packages"][0].get("matched_digest").is_none());
        fs::create_dir_all(temp.0.join(".greyward")).unwrap();
        fs::write(
            temp.0.join(ARCHIVES_FILE),
            r#"{"schema":"node-archives/9"}"#,
        )
        .unwrap();
        assert_eq!(
            record_matched_digests(&mut body, &temp.0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
