//! `ward sbom` — CycloneDX 1.5 JSON from the closure envelopes.
//!
//! Pure format translation: reads every .greyward/closures/<eco>.json the
//! project has and emits one SBOM document. No network, no new inputs —
//! the closures already carry names, versions, and pinned hashes.

use crate::commands::shared::project_dir;
use crate::kernel::cyclonedx::err;
use crate::kernel::ui;
use crate::tailors;
use serde_json::{json, Value};
use std::io;
use std::path::Path;

/// urn:uuid v4 from the shared operating-system randomness helper.
fn serial_number() -> io::Result<String> {
    let bytes = crate::kernel::fsroot::urandom_bytes(16)?;
    let mut bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| io::Error::other("system randomness returned the wrong length"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "urn:uuid:{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        h[8],
        h[9],
        h[10],
        h[11],
        h[12],
        h[13],
        h[14],
        h[15]
    ))
}

fn eco_components(eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
    match tailors::for_closure(eco) {
        Some(tailor) => tailor.sbom_components(eco, body, out),
        None => Err(err(format!("unknown closure ecosystem '{eco}'"))),
    }
}

/// Build the CycloneDX document for every closure in the project. The
/// closures are read as committed, whichever platform projected them: the
/// SBOM describes what the record says, so a Linux runner can describe a
/// closure synced on a Mac. Nothing here opens the store.
pub fn generate(project_dir: &Path) -> io::Result<Value> {
    let mut closures = crate::commands::inspect::closures(project_dir)?;
    closures.sort_by(|a, b| a.ecosystem.cmp(&b.ecosystem));
    if closures.is_empty() {
        return Err(err("no closures found; run `ward` first"));
    }
    let mut components = Vec::new();
    let mut exception_properties = Vec::new();
    for closure in &closures {
        let eco = &closure.ecosystem;
        let stem = closure.path.file_stem().and_then(|stem| stem.to_str());
        if closure.envelope["schema"] != "closure/1"
            || closure.envelope["ecosystem"].as_str() != stem
        {
            return Err(err(format!(
                "{}: unknown closure schema/ecosystem; re-run `ward`",
                closure.path.display()
            )));
        }
        let body = &closure.body;
        // Every exception the record carries, as `ward status` and `ward
        // audit` read them: the closure's own list and the joined resolution
        // record's, each kind under the name this binary prints.
        for exception in crate::comforter::records::exceptions(closure)?.exceptions {
            exception_properties.push(json!({
                "name": format!("greyward:exception:{}", exception.kind),
                "value": format!("{}: {}", exception.subject, exception.detail),
            }));
        }
        // What the user chose not to install, kept apart from the
        // exceptions so a reader never counts it as one (#71).
        for group in crate::comforter::records::optional_groups_skipped(closure)? {
            exception_properties.push(json!({
                "name": "greyward:optional-group-skipped",
                "value": format!("{eco}: {}: {}", group.group, group.detail),
            }));
        }
        eco_components(eco, body, &mut components)?;
    }
    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number()?,
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": "greyward",
                "name": "greyward",
                "version": env!("CARGO_PKG_VERSION"),
            }],
            "properties": exception_properties,
        },
        "components": components,
    }))
}

pub fn run(output: Option<&Path>) -> io::Result<()> {
    let doc = generate(&project_dir()?)?;
    let text = serde_json::to_string_pretty(&doc)?;
    match output {
        Some(path) => {
            std::fs::write(path, text + "\n")?;
            ui::note(&format!("SBOM written to {}", path.display()));
        }
        None => println!("{text}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    #[test]
    fn sbom_from_synthetic_closures() {
        let scratch = TempDir::named("sbom-test");
        let dir = scratch.0.clone();
        fs::create_dir_all(dir.join(".greyward/closures")).unwrap();
        let write = |eco: &str, body: Value| {
            let envelope = json!({
                "schema": "closure/1",
                "ecosystem": eco,
                "projected_at": 0,
                "body": body,
            });
            fs::write(
                dir.join(format!(".greyward/closures/{eco}.json")),
                serde_json::to_vec(&envelope).unwrap(),
            )
            .unwrap();
        };
        write(
            "python",
            json!({
                "env_object": "/store/objects/abc123",
                "plan": {
                    "python_version": "3.13.1",
                    "packages": [
                        {"name": "Flask_Login", "version": "0.6.3", "sha256": "aa".repeat(32),
                         "url": "https://files.pythonhosted.org/packages/f/flask_login.whl"},
                        {"name": "internal", "version": "1.0", "sha256": "bb".repeat(32),
                         "url": "https://user:token@pypi.corp.example:8443/files/internal-1.0.whl"},
                        {"name": "fromgit", "version": "0.1", "sha256": "cc".repeat(32),
                         "url": "", "git": {"url": "https://github.com/o/fromgit",
                                            "commit": "ab".repeat(20), "subdirectory": null}},
                    ],
                },
                "exceptions": [{
                    "kind": "requirement-skipped",
                    "subject": ".",
                    "detail": "project-local requirement",
                }, {
                    "kind": "unattested_index",
                    "subject": "pypi.corp.example",
                    "detail": "private index",
                }],
                "resolution": {
                    "exceptions": [{
                        "kind": "unconfined-resolution",
                        "subject": "uv",
                        "detail": "network not fenced",
                    }],
                },
                "optional_groups_skipped": [{
                    "group": "docs",
                    "detail": "extra, not requested",
                    "requirements": ["sphinx"],
                }],
            }),
        );
        write(
            "node",
            json!({
                "env_object": "/store/objects/def456",
                "node_version": "24.20.0",
                "packages": [
                    {"path": "node_modules/@types/node", "version": "22.0.0",
                     "integrity": "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ=="},
                    {"path": "node_modules/a/node_modules/b", "version": "1.0.0",
                    "integrity": "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ=="},
                ],
                "exceptions": [{
                    "kind": "install-script-failed",
                    "subject": "node_modules/a",
                    "detail": "postinstall: network-denied",
                }],
            }),
        );
        // The record an older `ward fmt` left: not a closure any more, so it
        // is skipped rather than failing the whole document.
        write(
            "rustfmt",
            json!({
                "rust_object": {"path": "/store/objects/rust789", "id": "rust789"},
                "rustfmt_object": {"path": "/store/objects/fmt012", "id": "fmt012"},
                "rust_version": "1.96.1",
                "workspace_root": "/w",
            }),
        );
        let doc = generate(&dir).unwrap();
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert!(doc["serialNumber"]
            .as_str()
            .unwrap()
            .starts_with("urn:uuid:"));
        let comps = doc["components"].as_array().unwrap();
        // 3 pypi + 2 npm + 2 dependency environments
        assert_eq!(comps.len(), 7);
        let purls: Vec<&str> = comps.iter().filter_map(|c| c["purl"].as_str()).collect();
        assert!(purls.contains(&"pkg:pypi/flask-login@0.6.3"));
        // Another index is named by its origin, without the credentials
        // the file URL carried; a git package by its repository and commit.
        assert!(
            purls.contains(
                &"pkg:pypi/internal@1.0?repository_url=https%3A%2F%2Fpypi.corp.example%3A8443"
            ),
            "{purls:?}"
        );
        let vcs = format!(
            "pkg:pypi/fromgit@0.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Ffromgit%40{}",
            "ab".repeat(20)
        );
        assert!(purls.contains(&vcs.as_str()), "{purls:?}");
        assert!(purls.contains(&"pkg:npm/%40types/node@22.0.0"));
        assert!(purls.contains(&"pkg:npm/b@1.0.0"));
        let ids: Vec<&str> = comps
            .iter()
            .filter(|c| c["type"] == "application")
            .flat_map(|c| c["properties"].as_array().unwrap())
            .filter(|p| p["name"] == "greyward:store-id")
            .filter_map(|p| p["value"].as_str())
            .collect();
        // Closures are processed in name order: node, then python.
        assert_eq!(ids, ["def456", "abc123"]);
        let env_names: Vec<&str> = comps
            .iter()
            .filter(|c| c["type"] == "application")
            .filter_map(|c| c["name"].as_str())
            .collect();
        assert_eq!(env_names, ["node-env", "python-env"]);
        let properties = doc["metadata"]["properties"].as_array().unwrap();
        assert!(properties.iter().any(|p| {
            p["name"] == "greyward:exception:requirement-skipped"
                && p["value"] == ".: project-local requirement"
        }));
        assert!(properties.iter().any(|p| {
            p["name"] == "greyward:exception:install-script-failed"
                && p["value"] == "node_modules/a: postinstall: network-denied"
        }));
        // A legacy spelling is printed as the kind it is, and the joined
        // resolution record's exceptions are the closure's too.
        assert!(properties.iter().any(|p| {
            p["name"] == "greyward:exception:unattested-index"
                && p["value"] == "pypi.corp.example: private index"
        }));
        assert!(properties.iter().any(|p| {
            p["name"] == "greyward:exception:unconfined-resolution"
                && p["value"] == "uv: network not fenced"
        }));
        assert!(properties.iter().any(|p| {
            p["name"] == "greyward:optional-group-skipped"
                && p["value"] == "python: docs: extra, not requested"
        }));
    }

    #[test]
    fn sbom_requires_package_fields() {
        let body = json!({
            "plan": {
                "packages": [{"name": "Flask", "version": "3.0.0"}],
            },
        });
        let mut components = Vec::new();
        let error = eco_components("python", &body, &mut components)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("python closure: package missing 'sha256'"),
            "{error}"
        );
    }

    #[test]
    fn no_closures_is_a_loud_error() {
        let dir = TempDir::named("sbom-empty");
        let error = generate(&dir.0).unwrap_err();
        assert!(error.to_string().contains("no closures found"), "{error}");
    }
}
