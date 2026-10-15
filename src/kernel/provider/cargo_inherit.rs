//! Cargo workspace inheritance for git crates (kernel provider layer).
//!
//! A crate inside a multi-crate git repository usually takes some of its
//! manifest from the repository's root `Cargo.toml`: `version.workspace =
//! true`, `serde = { workspace = true }`, `[lints] workspace = true`. Once
//! the crate is copied alone into a vendor directory there is no workspace
//! around it, so those references must be filled in first. This module does
//! what `cargo package` does: it reads the workspace root inside the same
//! checkout and writes a manifest with every inherited value spelled out.

use std::io;
use std::path::{Component, Path, PathBuf};

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// The dependency tables cargo reads, in both spellings it accepts.
const DEPENDENCY_TABLES: [&str; 5] = [
    "dependencies",
    "dev-dependencies",
    "dev_dependencies",
    "build-dependencies",
    "build_dependencies",
];

/// `[package]` keys whose inherited value is a path relative to the
/// workspace root, so it must be re-expressed relative to the crate.
const PATH_KEYS: [&str; 2] = ["readme", "license-file"];

/// Read and parse one manifest.
pub(crate) fn read_manifest(path: &Path) -> io::Result<toml::Table> {
    let text = std::fs::read_to_string(path)?;
    toml::from_str(&text).map_err(|e| err(format!("parse {}: {e}", path.display())))
}

fn inherits(value: &toml::Value) -> bool {
    value
        .as_table()
        .and_then(|table| table.get("workspace"))
        .and_then(toml::Value::as_bool)
        == Some(true)
}

/// Every place in `manifest` that inherits from the workspace, by the name
/// a message shows (`package.version`, `dependencies.serde`, `lints`).
fn inherited_fields(manifest: &toml::Table) -> Vec<String> {
    let mut fields = Vec::new();
    if let Some(package) = manifest.get("package").and_then(toml::Value::as_table) {
        for (key, value) in package {
            if inherits(value) {
                fields.push(format!("package.{key}"));
            }
        }
    }
    if manifest.get("lints").is_some_and(inherits) {
        fields.push(String::from("lints"));
    }
    let mut dependency_tables = Vec::new();
    for table in DEPENDENCY_TABLES {
        if let Some(deps) = manifest.get(table).and_then(toml::Value::as_table) {
            dependency_tables.push((table.to_string(), deps));
        }
    }
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for (cfg, target) in targets {
            for table in DEPENDENCY_TABLES {
                if let Some(deps) = target.get(table).and_then(toml::Value::as_table) {
                    dependency_tables.push((format!("target.{cfg}.{table}"), deps));
                }
            }
        }
    }
    for (prefix, deps) in dependency_tables {
        for (name, value) in deps {
            if inherits(value) {
                fields.push(format!("{prefix}.{name}"));
            }
        }
    }
    fields
}

/// Fold `.` and `..` out of an absolute path without touching the disk.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// `to` written relative to the directory `from` (both absolute, lexical),
/// with `/` separators as a manifest spells it.
fn relative(from: &Path, to: &Path) -> String {
    let from: Vec<_> = from.components().collect();
    let to: Vec<_> = to.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<String> = vec![String::from(".."); from.len() - common];
    parts.extend(
        to[common..]
            .iter()
            .map(|part| part.as_os_str().to_string_lossy().into_owned()),
    );
    if parts.is_empty() {
        String::from(".")
    } else {
        parts.join("/")
    }
}

/// A path value written relative to `workspace_root`, re-expressed relative
/// to `crate_dir`.
fn rebase(value: &str, workspace_root: &Path, crate_dir: &Path) -> String {
    relative(crate_dir, &lexical(&workspace_root.join(value)))
}

/// Whether the workspace rooted at `root` leaves `crate_dir` out, by cargo's
/// rule (`WorkspaceRootConfig::is_excluded`): the crate's manifest lies
/// under an `exclude` entry and under no `members` entry, both compared as
/// written (a `members` glob is not expanded for this test).
fn excludes(root: &Path, workspace: &toml::Table, crate_dir: &Path) -> bool {
    let manifest = crate_dir.join("Cargo.toml");
    let under = |key: &str| {
        workspace
            .get("workspace")
            .and_then(|table| table.get(key))
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .any(|entry| manifest.starts_with(lexical(&root.join(entry))))
    };
    under("exclude") && !under("members")
}

/// The workspace root manifest for the crate in `crate_dir`, inside the git
/// checkout `checkout` (both canonical): `package.workspace` when the crate
/// names its root, otherwise the nearest `Cargo.toml` with a `[workspace]`
/// table, starting at the crate itself, that does not exclude the crate:
/// cargo's `find_root`. As there, a root that excludes the crate is passed
/// over for one further up, and a root whose `members` do not list the
/// crate still serves it: cargo reads a git dependency's manifest this way
/// and checks membership only for a workspace it builds. `None` when no
/// workspace inside the checkout takes the crate.
pub(crate) fn workspace_root(
    crate_dir: &Path,
    checkout: &Path,
    manifest: &toml::Table,
) -> io::Result<Option<(PathBuf, toml::Table)>> {
    let explicit = manifest
        .get("package")
        .and_then(|package| package.get("workspace"))
        .and_then(toml::Value::as_str);
    if let Some(path) = explicit {
        let root = lexical(&crate_dir.join(path));
        if !root.starts_with(checkout) {
            return Err(err(format!(
                "package.workspace = {path:?} in {} leaves the git checkout",
                crate_dir.display()
            )));
        }
        let root_manifest = read_manifest(&root.join("Cargo.toml"))?;
        if !root_manifest.contains_key("workspace") {
            return Err(err(format!(
                "package.workspace = {path:?} in {} names a manifest with no [workspace]",
                crate_dir.display()
            )));
        }
        return Ok(Some((root, root_manifest)));
    }
    let mut dir = crate_dir.to_path_buf();
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            let parsed = if dir == crate_dir {
                manifest.clone()
            } else {
                read_manifest(&candidate)?
            };
            if parsed.contains_key("workspace")
                && (dir == crate_dir || !excludes(&dir, &parsed, crate_dir))
            {
                return Ok(Some((dir, parsed)));
            }
        }
        if dir == checkout || !dir.pop() || !dir.starts_with(checkout) {
            return Ok(None);
        }
    }
}

/// The value the workspace defines at `workspace.<section>.<key>`, or a
/// message naming what the crate asked for and the workspace lacks.
fn workspace_value<'a>(
    workspace: &'a toml::Table,
    section: Option<&str>,
    key: &str,
    field: &str,
    root: &Path,
) -> io::Result<&'a toml::Value> {
    let table = workspace.get("workspace").and_then(toml::Value::as_table);
    let table = match section {
        Some(section) => table
            .and_then(|table| table.get(section))
            .and_then(toml::Value::as_table),
        None => table,
    };
    table.and_then(|table| table.get(key)).ok_or_else(|| {
        let at = section.map_or_else(|| key.to_string(), |s| format!("{s}.{key}"));
        err(format!(
            "{field} inherits from the workspace, but {} defines no workspace.{at}",
            root.join("Cargo.toml").display()
        ))
    })
}

/// The crate's own package version: written out, inherited from the
/// workspace, or cargo's `0.0.0` when the manifest leaves it out.
pub(crate) fn package_version(
    crate_dir: &Path,
    checkout: &Path,
    manifest: &toml::Table,
) -> io::Result<Option<String>> {
    let Some(package) = manifest.get("package").and_then(toml::Value::as_table) else {
        return Ok(None);
    };
    match package.get("version") {
        None => Ok(Some(String::from("0.0.0"))),
        Some(toml::Value::String(version)) => Ok(Some(version.clone())),
        Some(value) if inherits(value) => {
            let Some((root, workspace)) = workspace_root(crate_dir, checkout, manifest)? else {
                return Err(err(format!(
                    "package.version in {} inherits from a workspace, and none encloses it in the git checkout",
                    crate_dir.display()
                )));
            };
            let version = workspace_value(
                &workspace,
                Some("package"),
                "version",
                "package.version",
                &root,
            )?;
            Ok(version.as_str().map(str::to_string))
        }
        Some(_) => Ok(None),
    }
}

/// One inherited dependency, merged the way cargo merges it: the
/// workspace's entry (a bare version string becomes `{ version }`, a `path`
/// is rebased onto the crate), the member's `features` added to the
/// workspace's, the member's `optional` and `public` taken as written, and
/// the member's `default-features = true` overriding a workspace `false`
/// (a member `false` against a workspace default changes nothing: cargo
/// warns before edition 2024 and refuses it from 2024 on, as this does when
/// `edition_2024` is set). Every other key on the member entry (`version`,
/// `path`, `git`, `package`, ...) is ignored, as cargo ignores it.
fn merge_dependency(
    base: &toml::Value,
    member: &toml::Table,
    workspace_root: &Path,
    crate_dir: &Path,
    field: &str,
    edition_2024: bool,
) -> io::Result<toml::Value> {
    let mut merged = match base {
        toml::Value::String(version) => {
            let mut table = toml::Table::new();
            table.insert("version".into(), toml::Value::String(version.clone()));
            table
        }
        toml::Value::Table(table) => table.clone(),
        _ => {
            return Err(err(format!(
                "{field}: the workspace dependency is neither a version nor a table"
            )))
        }
    };
    if let Some(path) = merged.get("path").and_then(toml::Value::as_str) {
        let rebased = rebase(path, workspace_root, crate_dir);
        merged.insert("path".into(), toml::Value::String(rebased));
    }
    if let Some(member_features) = member.get("features").and_then(toml::Value::as_array) {
        let mut features = merged
            .get("features")
            .and_then(toml::Value::as_array)
            .cloned()
            .unwrap_or_default();
        for feature in member_features {
            if !features.contains(feature) {
                features.push(feature.clone());
            }
        }
        merged.insert("features".into(), toml::Value::Array(features));
    }
    let default_features = |table: &toml::Table| {
        table
            .get("default-features")
            .or_else(|| table.get("default_features"))
            .and_then(toml::Value::as_bool)
    };
    match (default_features(member), default_features(&merged)) {
        (Some(true), Some(false)) => {
            merged.remove("default_features");
            merged.insert("default-features".into(), toml::Value::Boolean(true));
        }
        (Some(false), Some(true) | None) if edition_2024 => {
            return Err(err(format!(
                "{field}: default-features = false has no effect, because the workspace \
                 dependency keeps default features on; cargo refuses this from edition 2024"
            )));
        }
        _ => {}
    }
    for key in ["optional", "public"] {
        match member.get(key) {
            Some(value) => {
                merged.insert(key.into(), value.clone());
            }
            None => {
                merged.remove(key);
            }
        }
    }
    Ok(toml::Value::Table(merged))
}

fn normalize_dependencies(
    deps: &mut toml::Table,
    prefix: &str,
    workspace: &toml::Table,
    workspace_root: &Path,
    crate_dir: &Path,
    edition_2024: bool,
) -> io::Result<()> {
    for (name, value) in deps.iter_mut() {
        if !inherits(value) {
            continue;
        }
        let field = format!("{prefix}.{name}");
        let base = workspace_value(
            workspace,
            Some("dependencies"),
            name,
            &field,
            workspace_root,
        )?;
        let member = value.as_table().cloned().unwrap_or_default();
        *value = merge_dependency(
            base,
            &member,
            workspace_root,
            crate_dir,
            &field,
            edition_2024,
        )?;
    }
    Ok(())
}

/// The crate's manifest with every workspace reference filled in, or `None`
/// when it inherits nothing (and is copied unchanged). `crate_dir` and
/// `checkout` are canonical; the workspace root must lie inside the checkout.
pub(crate) fn normalize(
    crate_dir: &Path,
    checkout: &Path,
    manifest: &toml::Table,
) -> io::Result<Option<toml::Table>> {
    let fields = inherited_fields(manifest);
    if fields.is_empty() {
        return Ok(None);
    }
    let Some((root, workspace)) = workspace_root(crate_dir, checkout, manifest)? else {
        return Err(err(format!(
            "{} inherits {} from a workspace, and none encloses it in the git checkout",
            crate_dir.display(),
            fields.join(", ")
        )));
    };
    let mut out = manifest.clone();
    if let Some(package) = out.get_mut("package").and_then(toml::Value::as_table_mut) {
        package.remove("workspace");
        for (key, value) in package.iter_mut() {
            if !inherits(value) {
                continue;
            }
            let field = format!("package.{key}");
            let mut inherited =
                workspace_value(&workspace, Some("package"), key, &field, &root)?.clone();
            if PATH_KEYS.contains(&key.as_str()) {
                if let Some(path) = inherited.as_str() {
                    inherited = toml::Value::String(rebase(path, &root, crate_dir));
                }
            }
            *value = inherited;
        }
    }
    if let Some(lints) = out.get("lints").filter(|lints| inherits(lints)) {
        // Cargo takes the workspace's lints whole: a member table that
        // inherits and also sets its own is an error there.
        let own: Vec<&String> = lints
            .as_table()
            .into_iter()
            .flat_map(|table| table.keys())
            .filter(|key| key.as_str() != "workspace")
            .collect();
        if !own.is_empty() {
            return Err(err(format!(
                "{}: [lints] inherits from the workspace and also sets {}; cargo refuses that",
                crate_dir.display(),
                own.iter()
                    .map(|key| format!("lints.{key}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let lints = workspace_value(&workspace, None, "lints", "lints", &root)?.clone();
        out.insert("lints".into(), lints);
    }
    // The package's effective edition, inherited or not (cargo's default
    // is 2015): some dependency rules tighten from 2024 on.
    let edition_2024 = out
        .get("package")
        .and_then(|package| package.get("edition"))
        .and_then(toml::Value::as_str)
        .and_then(|edition| edition.parse::<u32>().ok())
        .is_some_and(|edition| edition >= 2024);
    for table in DEPENDENCY_TABLES {
        if let Some(deps) = out.get_mut(table).and_then(toml::Value::as_table_mut) {
            normalize_dependencies(deps, table, &workspace, &root, crate_dir, edition_2024)?;
        }
    }
    if let Some(targets) = out.get_mut("target").and_then(toml::Value::as_table_mut) {
        for (cfg, target) in targets.iter_mut() {
            for table in DEPENDENCY_TABLES {
                if let Some(deps) = target.get_mut(table).and_then(toml::Value::as_table_mut) {
                    let prefix = format!("target.{cfg}.{table}");
                    normalize_dependencies(
                        deps,
                        &prefix,
                        &workspace,
                        &root,
                        crate_dir,
                        edition_2024,
                    )?;
                }
            }
        }
    }
    let left = inherited_fields(&out);
    if !left.is_empty() {
        return Err(err(format!(
            "{} still inherits {} after normalization",
            crate_dir.display(),
            left.join(", ")
        )));
    }
    Ok(Some(out))
}

/// A `readme` or `license-file` that lies outside the crate (usually one
/// inherited from the workspace root) is copied into the crate's top
/// directory and named there, as `cargo package` does, so the vendored
/// manifest names a file it carries. When the crate already has an entry of
/// that name the path is left pointing outside, where cargo never reads it
/// for a dependency.
fn bring_in_package_files(
    manifest: &mut toml::Table,
    source_dir: &Path,
    checkout: &Path,
    dest: &Path,
) -> io::Result<()> {
    let Some(package) = manifest
        .get_mut("package")
        .and_then(toml::Value::as_table_mut)
    else {
        return Ok(());
    };
    for key in PATH_KEYS {
        let Some(path) = package.get(key).and_then(toml::Value::as_str) else {
            continue;
        };
        let file = lexical(&source_dir.join(path));
        if file.starts_with(source_dir) || !file.starts_with(checkout) || !file.is_file() {
            continue;
        }
        let Some(name) = file.file_name() else {
            continue;
        };
        let local = dest.join(name);
        if std::fs::symlink_metadata(&local).is_ok() {
            continue;
        }
        std::fs::copy(&file, &local)?;
        crate::kernel::store::restore_write_bits(&local)?;
        package.insert(
            key.to_string(),
            toml::Value::String(name.to_string_lossy().into_owned()),
        );
    }
    Ok(())
}

/// Write the normalized manifest into the copied crate `dest`, keeping the
/// original beside it as `Cargo.toml.orig` the way `cargo package` does.
/// Returns whether anything was rewritten.
pub(crate) fn write_normalized(
    source_dir: &Path,
    checkout: &Path,
    dest: &Path,
) -> io::Result<bool> {
    let manifest_path = source_dir.join("Cargo.toml");
    let manifest = read_manifest(&manifest_path)?;
    let Some(mut normalized) = normalize(source_dir, checkout, &manifest)? else {
        return Ok(false);
    };
    bring_in_package_files(&mut normalized, source_dir, checkout, dest)?;
    let text = toml::to_string(&normalized)
        .map_err(|e| err(format!("serialize normalized Cargo.toml: {e}")))?;
    let original = std::fs::read(&manifest_path)?;
    let target = dest.join("Cargo.toml");
    // The copy may hold a link here (a materialized one is a plain file);
    // replace the entry rather than write through it.
    std::fs::remove_file(&target)?;
    std::fs::write(&target, text)?;
    let orig = dest.join("Cargo.toml.orig");
    if std::fs::symlink_metadata(&orig).is_ok() {
        std::fs::remove_file(&orig)?;
    }
    std::fs::write(orig, original)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn table(text: &str) -> toml::Table {
        toml::from_str(text).unwrap()
    }

    fn workspace(scratch: &TempDir) -> PathBuf {
        let root = scratch.0.canonicalize().unwrap();
        std::fs::create_dir_all(root.join("crates/member")).unwrap();
        std::fs::create_dir_all(root.join("crates/sibling")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            r#"
[workspace]
members = ["crates/*"]
[workspace.package]
version = "1.2.3"
edition = "2021"
license-file = "LICENSE"
readme = "README.md"
[workspace.dependencies]
serde = { version = "1", features = ["derive"], default-features = false }
itoa = "1.0"
sibling = { path = "crates/sibling", version = "1.2.3" }
[workspace.lints.rust]
unsafe_code = "forbid"
"#,
        )
        .unwrap();
        root
    }

    #[test]
    fn inherited_package_fields_dependencies_and_lints_are_written_out() {
        let scratch = TempDir::named("cargo-inherit");
        let root = workspace(&scratch);
        let member = root.join("crates/member");
        let manifest = table(
            r#"
[package]
name = "member"
version.workspace = true
edition = { workspace = true }
license-file.workspace = true
readme.workspace = true
[dependencies]
serde = { workspace = true, features = ["rc"], optional = true }
sibling.workspace = true
[target.'cfg(unix)'.dev-dependencies]
itoa = { workspace = true }
[lints]
workspace = true
"#,
        );
        assert_eq!(
            package_version(&member, &root, &manifest)
                .unwrap()
                .as_deref(),
            Some("1.2.3")
        );
        let out = normalize(&member, &root, &manifest).unwrap().unwrap();
        let expected = table(
            r#"
[package]
name = "member"
version = "1.2.3"
edition = "2021"
license-file = "../../LICENSE"
readme = "../../README.md"
[dependencies]
serde = { version = "1", features = ["derive", "rc"], default-features = false, optional = true }
sibling = { path = "../sibling", version = "1.2.3" }
[target.'cfg(unix)'.dev-dependencies]
itoa = { version = "1.0" }
[lints.rust]
unsafe_code = "forbid"
"#,
        );
        assert_eq!(out, expected);
    }

    /// Cargo's merge, checked against `cargo vendor` 1.98: a member's
    /// `default-features = true` beats a workspace `false`, a member `false`
    /// against the workspace default changes nothing, `optional` and
    /// `public` come from the member, and every other member key
    /// (`version`, `path`, `package`, `git`, `rev`) is ignored.
    #[test]
    fn dependency_merge_follows_cargo() {
        let scratch = TempDir::named("cargo-inherit-merge");
        let root = scratch.0.canonicalize().unwrap();
        std::fs::create_dir_all(root.join("m")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            r#"
[workspace]
[workspace.dependencies]
off = { path = "off", default_features = false, features = ["x"] }
on = { path = "on" }
plain = "1.0"
"#,
        )
        .unwrap();
        let member = root.join("m");
        let manifest = table(
            r#"
[package]
name = "m"
version = "1.0.0"
[dependencies]
off = { workspace = true, default-features = true, features = ["y", "x"], optional = true, version = "9.9", package = "zzz" }
on = { workspace = true, default-features = false, path = "elsewhere", git = "https://example.invalid/r", rev = "abc" }
plain = { workspace = true, default_features = false, public = true, version = "2" }
"#,
        );
        let out = normalize(&member, &root, &manifest).unwrap().unwrap();
        let expected = table(
            r#"
off = { path = "../off", default-features = true, features = ["x", "y"], optional = true }
on = { path = "../on" }
plain = { version = "1.0", public = true }
"#,
        );
        assert_eq!(out["dependencies"].as_table().unwrap(), &expected);

        // Both explicit and agreeing: nothing to override.
        let agree = table(
            "[package]\nname = \"m\"\nversion = \"1.0.0\"\n[dependencies]\noff = { workspace = true, default-features = false }\n",
        );
        let out = normalize(&member, &root, &agree).unwrap().unwrap();
        assert_eq!(
            out["dependencies"]["off"].get("default_features"),
            Some(&toml::Value::Boolean(false))
        );
        assert_eq!(out["dependencies"]["off"].get("default-features"), None);
    }

    /// A member's `default-features = false` over a workspace dependency
    /// that keeps defaults on is ignored up to edition 2021 and refused from
    /// edition 2024, inherited edition included, as cargo does.
    #[test]
    fn an_ignored_default_features_false_is_refused_from_edition_2024() {
        let scratch = TempDir::named("cargo-inherit-edition");
        let root = scratch.0.canonicalize().unwrap();
        std::fs::create_dir_all(root.join("m")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\n[workspace.package]\nedition = \"2024\"\n\
             [workspace.dependencies]\non = \"1\"\nset = { version = \"1\", default-features = true }\noff = { version = \"1\", default-features = false }\n",
        )
        .unwrap();
        let member = root.join("m");
        let manifest = |edition: &str, dep: &str| {
            table(&format!(
                "[package]\nname = \"m\"\nversion = \"1.0.0\"\n{edition}\n[dependencies]\n{dep} = {{ workspace = true, default-features = false }}\n"
            ))
        };
        for dep in ["on", "set"] {
            let out = normalize(&member, &root, &manifest("edition = \"2021\"", dep))
                .unwrap()
                .unwrap();
            assert_eq!(out["dependencies"][dep].get("default-features"), {
                if dep == "set" {
                    Some(&toml::Value::Boolean(true))
                } else {
                    None
                }
            });
            for edition in ["edition = \"2024\"", "edition.workspace = true"] {
                let error = normalize(&member, &root, &manifest(edition, dep))
                    .unwrap_err()
                    .to_string();
                assert!(
                    error.contains(&format!("dependencies.{dep}: default-features = false")),
                    "{error}"
                );
                assert!(error.contains("edition 2024"), "{error}");
            }
        }
        // Agreeing with a workspace `false` is fine in any edition.
        let out = normalize(&member, &root, &manifest("edition = \"2024\"", "off"))
            .unwrap()
            .unwrap();
        assert_eq!(
            out["dependencies"]["off"].get("default-features"),
            Some(&toml::Value::Boolean(false))
        );
    }

    /// A workspace whose `exclude` covers the crate, and whose `members` do
    /// not name it, is passed over for one further up (none here, so the
    /// inheritance is refused); one that lists it as a member despite the
    /// `exclude` serves it; a root that simply does not list it serves it
    /// too, as cargo reads a git dependency.
    #[test]
    fn excluded_crates_do_not_inherit_from_that_root() {
        let scratch = TempDir::named("cargo-inherit-exclude");
        let root = scratch.0.canonicalize().unwrap();
        for dir in ["ex", "nm"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let write_root = |members: &str| {
            std::fs::write(
                root.join("Cargo.toml"),
                format!(
                    "[workspace]\nmembers = [{members}]\nexclude = [\"ex\"]\n[workspace.package]\nversion = \"0.5.0\"\n"
                ),
            )
            .unwrap();
        };
        let manifest = table("[package]\nname = \"c\"\nversion.workspace = true\n");
        write_root("\"a\"");
        let error = package_version(&root.join("ex"), &root, &manifest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("none encloses it"), "{error}");
        assert_eq!(
            package_version(&root.join("nm"), &root, &manifest)
                .unwrap()
                .as_deref(),
            Some("0.5.0")
        );
        write_root("\"a\", \"ex\"");
        assert_eq!(
            package_version(&root.join("ex"), &root, &manifest)
                .unwrap()
                .as_deref(),
            Some("0.5.0")
        );

        // An outer workspace takes over from an inner one that excludes it.
        std::fs::create_dir_all(root.join("inner/ex")).unwrap();
        std::fs::write(
            root.join("inner/Cargo.toml"),
            "[workspace]\nexclude = [\"ex\"]\n[workspace.package]\nversion = \"9.9.9\"\n",
        )
        .unwrap();
        assert_eq!(
            package_version(&root.join("inner/ex"), &root, &manifest)
                .unwrap()
                .as_deref(),
            Some("0.5.0")
        );
    }

    #[test]
    fn inherited_lints_with_own_overrides_are_refused() {
        let scratch = TempDir::named("cargo-inherit-lints");
        let root = workspace(&scratch);
        let manifest = table(
            "[package]\nname = \"m\"\nversion = \"1.0.0\"\n[lints]\nworkspace = true\n[lints.clippy]\nall = \"warn\"\n",
        );
        let error = normalize(&root.join("crates/member"), &root, &manifest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("also sets lints.clippy"), "{error}");
    }

    #[test]
    fn a_crate_inheriting_nothing_is_left_alone() {
        let scratch = TempDir::named("cargo-inherit-none");
        let root = workspace(&scratch);
        let manifest = table("[package]\nname = \"plain\"\nversion = \"0.1.0\"\n");
        assert_eq!(
            normalize(&root.join("crates/member"), &root, &manifest).unwrap(),
            None
        );
        // A missing version is cargo's 0.0.0.
        let bare = table("[package]\nname = \"bare\"\n");
        assert_eq!(
            package_version(&root, &root, &bare).unwrap().as_deref(),
            Some("0.0.0")
        );
    }

    #[test]
    fn a_field_the_workspace_lacks_is_named() {
        let scratch = TempDir::named("cargo-inherit-missing");
        let root = workspace(&scratch);
        let manifest = table(
            "[package]\nname = \"m\"\nversion = \"1.0.0\"\n[dependencies]\nrand = { workspace = true }\n",
        );
        let error = normalize(&root.join("crates/member"), &root, &manifest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("dependencies.rand inherits"), "{error}");
        assert!(error.contains("workspace.dependencies.rand"), "{error}");
    }

    #[test]
    fn inheritance_without_an_enclosing_workspace_is_refused() {
        let scratch = TempDir::named("cargo-inherit-orphan");
        let root = scratch.0.canonicalize().unwrap();
        let manifest = table("[package]\nname = \"m\"\nversion.workspace = true\n");
        let error = normalize(&root, &root, &manifest).unwrap_err().to_string();
        assert!(error.contains("none encloses it"), "{error}");
    }

    #[test]
    fn an_explicit_workspace_path_is_followed_and_bounded() {
        let scratch = TempDir::named("cargo-inherit-explicit");
        let root = workspace(&scratch);
        let member = root.join("crates/member");
        let manifest =
            table("[package]\nname = \"m\"\nworkspace = \"../..\"\nversion.workspace = true\n");
        let out = normalize(&member, &root, &manifest).unwrap().unwrap();
        assert_eq!(out["package"].get("workspace"), None);
        assert_eq!(out["package"]["version"].as_str(), Some("1.2.3"));
        let escaping =
            table("[package]\nname = \"m\"\nworkspace = \"../../..\"\nversion.workspace = true\n");
        let error = normalize(&member, &root, &escaping)
            .unwrap_err()
            .to_string();
        assert!(error.contains("leaves the git checkout"), "{error}");
    }
}
