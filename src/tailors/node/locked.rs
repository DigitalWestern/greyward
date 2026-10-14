//! The registry packages a Node lock names, for the door's `young-package`
//! check (`kernel::resolve::age`): every package `package-lock.json` or
//! `pnpm-lock.yaml` resolves from the npm registry, at its locked version.
//! Git, tarball-URL, `file:` and workspace packages are not the registry's
//! and are left out.

use super::lock_import::pnpm_registry_packages;
use super::registry::REGISTRY_HOST;
use crate::kernel::fetch::registry::{source_for, Served};
use crate::kernel::registries::config::Ecosystem;
use crate::kernel::registries::effective::Sources;
use crate::kernel::resolve::age::LockedPackage;
use crate::kernel::resolve::door::{LockedList, Staged};
use std::io;
use std::path::Path;
use url::Url;

/// Which lock the run leaves.
#[derive(Debug, Clone, Copy)]
pub(crate) enum NodeLock {
    Npm,
    Pnpm,
}

/// The [`LockedList`] of a run whose lock is `lock`, at the lock root.
/// `sources` are the run's node sources: a tarball one of its configured
/// registries serves is that registry's package.
pub(crate) fn locked_list<'a>(lock: NodeLock, sources: Sources) -> LockedList<'a> {
    Box::new(move |staged: &Staged<'_>| {
        let configured = |url: &str| {
            matches!(
                source_for(&sources, Ecosystem::Node, url),
                Ok(Served::Registry(_))
            )
        };
        let file = match lock {
            NodeLock::Npm => "package-lock.json",
            NodeLock::Pnpm => "pnpm-lock.yaml",
        };
        let text = String::from_utf8_lossy(&staged.read_lock(Path::new(file))?).into_owned();
        match lock {
            NodeLock::Npm => npm_registry_packages(&text, &configured),
            NodeLock::Pnpm => Ok(pnpm_registry_packages(&text, &configured)?
                .into_iter()
                .map(|(name, version)| LockedPackage::new(name, version))
                .collect()),
        }
    })
}

/// Every `packages` entry of a `package-lock.json` (v2 and v3) whose
/// `resolved` is a tarball on the public registry, named and versioned by
/// that tarball, so an alias (`"x": "npm:y@1"`) reads as the package it
/// really is.
///
/// Every entry is accounted for. The root, a workspace member, a link, a
/// bundled dependency, and a git, `file:` or off-registry tarball are
/// known and left out. Anything else (a lock without `packages`, an
/// installed package with no `resolved`, a `resolved` that is no URL, a
/// registry URL that is not a tarball) is `InvalidData`: a package this
/// reader skipped would never be judged.
pub(crate) fn npm_registry_packages(
    text: &str,
    configured: &dyn Fn(&str) -> bool,
) -> io::Result<Vec<LockedPackage>> {
    let lock: serde_json::Value = serde_json::from_str(text).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package-lock.json does not parse: {error}"),
        )
    })?;
    let unread = |why: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package-lock.json: {why}"),
        )
    };
    let Some(packages) = lock.get("packages").and_then(|p| p.as_object()) else {
        return Err(unread(
            "no packages object (ward reads lockfileVersion 2 and 3)".into(),
        ));
    };
    let mut found = Vec::new();
    for (path, entry) in packages {
        let flag = |name: &str| entry.get(name).and_then(|v| v.as_bool()) == Some(true);
        // The root, a workspace member's folder, a link to one, and a
        // dependency bundled inside its parent's tarball.
        if path.is_empty() || !path.contains("node_modules/") || flag("link") || flag("inBundle") {
            continue;
        }
        let Some(resolved) = entry.get("resolved").and_then(|v| v.as_str()) else {
            return Err(unread(format!("{path} has no resolved")));
        };
        if ["git+", "git:", "github:", "file:"]
            .iter()
            .any(|scheme| resolved.starts_with(scheme))
        {
            continue;
        }
        let url = Url::parse(resolved)
            .map_err(|_| unread(format!("{path} resolves to {resolved:?}, which is no URL")))?;
        if url.host_str() != Some(REGISTRY_HOST) {
            // A configured registry lays its tarballs out its own way
            // (Nexus under its repository path, GitHub Packages under
            // `/download/`): the entry names the package.
            if configured(resolved) {
                found.push(entry_identity(path, entry).ok_or_else(|| {
                    unread(format!(
                        "{path} resolves to {resolved}, and names no version"
                    ))
                })?);
            }
            continue;
        }
        let package = tarball_identity(&url).ok_or_else(|| {
            unread(format!(
                "{path} resolves to {resolved}, which is not a registry tarball"
            ))
        })?;
        found.push(package);
    }
    Ok(found)
}

/// The URL a package's tarball was fetched from, when that is not the
/// public registry: a tarball-URL dependency. `None` for a registry, git
/// or `file:` package.
pub(crate) fn off_registry_tarball(package: &super::NpmPackage) -> Option<&str> {
    if package.git.is_some()
        || package.url.is_empty()
        || super::local_package::source_dir(package).is_some()
    {
        return None;
    }
    let host = Url::parse(&package.url)
        .ok()?
        .host_str()
        .map(str::to_string);
    (host.as_deref() != Some(REGISTRY_HOST)).then_some(package.url.as_str())
}

/// `(name, version)` of a `package-lock.json` entry at `path`: its `name`
/// (an alias's real name) or the folder under the last `node_modules/`,
/// and its `version`.
fn entry_identity(path: &str, entry: &serde_json::Value) -> Option<LockedPackage> {
    let name = match entry.get("name").and_then(|v| v.as_str()) {
        Some(name) => name,
        None => path.rsplit_once("node_modules/")?.1,
    };
    let version = entry.get("version").and_then(|v| v.as_str())?;
    (!name.is_empty() && !version.is_empty()).then(|| LockedPackage::new(name, version))
}

/// `(name, version)` of a registry tarball URL:
/// `/<name>/-/<name>-<version>.tgz` or `/@<scope>/<name>/-/<name>-<version>.tgz`.
fn tarball_identity(url: &Url) -> Option<LockedPackage> {
    let parts: Vec<&str> = url.path().trim_start_matches('/').split('/').collect();
    let (name, base, file) = match parts.as_slice() {
        [name, "-", file] => (name.to_string(), *name, *file),
        [scope, name, "-", file] if scope.starts_with('@') => {
            (format!("{scope}/{name}"), *name, *file)
        }
        _ => return None,
    };
    let version = file
        .strip_prefix(base)?
        .strip_prefix('-')?
        .strip_suffix(".tgz")?;
    if version.is_empty() {
        return None;
    }
    Some(LockedPackage::new(name, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_locks_list_registry_tarballs_by_their_real_names() {
        let lock = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"name": "demo", "dependencies": {"is-odd": "^3.0.1"}},
            "node_modules/is-odd": {"version": "3.0.1",
              "resolved": "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"},
            "node_modules/is-odd/node_modules/is-number": {"version": "6.0.0",
              "resolved": "https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz"},
            "node_modules/alias": {"name": "@types/node", "version": "20.1.0",
              "resolved": "https://registry.npmjs.org/@types/node/-/node-20.1.0.tgz"},
            "node_modules/from-git": {"version": "1.0.0",
              "resolved": "git+ssh://git@github.com/a/b.git#abc"},
            "node_modules/elsewhere": {"version": "1.0.0",
              "resolved": "https://example.com/elsewhere-1.0.0.tgz"},
            "packages/member": {"version": "0.1.0"},
            "node_modules/member": {"resolved": "packages/member", "link": true}
          }
        }"#;
        let mut found = npm_registry_packages(lock, &|_| false).unwrap();
        found.sort();
        assert_eq!(
            found,
            [
                LockedPackage::new("@types/node", "20.1.0"),
                LockedPackage::new("is-number", "6.0.0"),
                LockedPackage::new("is-odd", "3.0.1"),
            ]
        );
        // A configured registry's tarball, laid out its own way, is named
        // by the entry; an alias by its `name`. One with no version is
        // unread.
        let private = r#"{
          "lockfileVersion": 3,
          "packages": {
            "node_modules/is-odd": {"version": "3.0.1",
              "resolved": "https://nexus.test/repository/npm/is-odd/-/is-odd-3.0.1.tgz"},
            "node_modules/w": {"name": "@corp/widget", "version": "1.0.0",
              "resolved": "https://npm.pkg.github.com/download/@corp/widget/1.0.0/abc"},
            "node_modules/elsewhere": {"version": "1.0.0",
              "resolved": "https://example.com/elsewhere-1.0.0.tgz"}
          }
        }"#;
        let configured = |url: &str| !url.starts_with("https://example.com/");
        let mut found = npm_registry_packages(private, &configured).unwrap();
        found.sort();
        assert_eq!(
            found,
            [
                LockedPackage::new("@corp/widget", "1.0.0"),
                LockedPackage::new("is-odd", "3.0.1"),
            ]
        );
        let unversioned =
            r#"{"packages": {"node_modules/x": {"resolved": "https://nexus.test/x.tgz"}}}"#;
        let error = npm_registry_packages(unversioned, &configured).unwrap_err();
        assert!(error.to_string().contains("names no version"), "{error}");
        for unread in [
            "{}",
            "not json",
            r#"{"packages": {"node_modules/x": {"version": "1.0.0"}}}"#,
            r#"{"packages": {"node_modules/x": {"resolved": "not a url"}}}"#,
            r#"{"packages": {"node_modules/x": {"resolved": "https://registry.npmjs.org/x"}}}"#,
        ] {
            let error = npm_registry_packages(unread, &|_| false).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{unread}");
        }
        let bundled = r#"{"packages": {"": {}, "node_modules/a/node_modules/b":
            {"version": "1.0.0", "inBundle": true}}}"#;
        assert!(npm_registry_packages(bundled, &|_| false)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn pnpm_locks_list_registry_resolutions_without_peer_context() {
        let lock = "lockfileVersion: '9.0'\n\
            \n\
            importers:\n\
            \n\
            \x20 .:\n\
            \x20   dependencies:\n\
            \x20     is-odd:\n\
            \x20       specifier: ^3.0.1\n\
            \x20       version: 3.0.1\n\
            \n\
            packages:\n\
            \n\
            \x20 '@scope/peer@2.0.0':\n\
            \x20   resolution: {integrity: sha512-AAAA}\n\
            \n\
            \x20 is-number@6.0.0:\n\
            \x20   resolution: {integrity: sha512-BBBB}\n\
            \x20   engines: {node: '>=0.10.0'}\n\
            \n\
            \x20 is-odd@3.0.1:\n\
            \x20   resolution: {integrity: sha512-CCCC}\n\
            \n\
            \x20 from-url@1.0.0:\n\
            \x20   resolution: {integrity: sha512-DDDD, tarball: https://example.com/x.tgz}\n\
            \n\
            \x20 from-git@https://codeload.github.com/a/b/tar.gz/abc:\n\
            \x20   resolution: {tarball: https://codeload.github.com/a/b/tar.gz/abc}\n\
            \n\
            snapshots:\n\
            \n\
            \x20 is-odd@3.0.1:\n\
            \x20   dependencies:\n\
            \x20     is-number: 6.0.0\n";
        let found = pnpm_registry_packages(lock, &|_| false).unwrap();
        assert_eq!(
            found,
            [
                ("@scope/peer".to_string(), "2.0.0".to_string()),
                ("is-number".to_string(), "6.0.0".to_string()),
                ("is-odd".to_string(), "3.0.1".to_string()),
            ]
        );
        // A tarball on a configured registry is that registry's.
        let found =
            pnpm_registry_packages(lock, &|url| url == "https://example.com/x.tgz").unwrap();
        assert!(
            found.contains(&("from-url".to_string(), "1.0.0".to_string())),
            "{found:?}"
        );
        // A lock without packages locks nothing.
        let empty = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n";
        assert!(pnpm_registry_packages(empty, &|_| false)
            .unwrap()
            .is_empty());
        assert!(pnpm_registry_packages("packages: {}\n", &|_| false)
            .unwrap()
            .is_empty());
        // A registry tarball URL is still the registry's.
        let tarball = "packages:\n\
            \x20 is-odd@3.0.1:\n\
            \x20   resolution: {integrity: sha512-CCCC, \
            tarball: https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz}\n";
        assert_eq!(
            pnpm_registry_packages(tarball, &|_| false).unwrap(),
            [("is-odd".to_string(), "3.0.1".to_string())]
        );
        for unread in [
            "packages:\n  is-odd@3.0.1:\n    engines: {node: '>=0.10.0'}\n",
            "packages:\n  is-odd@3.0.1:\n    resolution: {tarball: 'not a url'}\n",
            "packages:\n  is-odd@latest:\n    resolution: {integrity: sha512-CCCC}\n",
            "packages:\n  is-odd@3.0.1:\n    resolution: {}\n",
            "packages:\n",
            "packages: is-odd@3.0.1\n",
            "packages:\n  - is-odd@3.0.1\n",
        ] {
            let error = pnpm_registry_packages(unread, &|_| false).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{unread}");
        }
    }

    #[test]
    fn only_a_tarball_off_the_registry_is_named_as_such() {
        let package = |url: &str| super::super::NpmPackage {
            path: "node_modules/x".into(),
            name: "x".into(),
            version: "1.0.0".into(),
            url: url.into(),
            integrity: String::new(),
            bin: Vec::new(),
            patch: None,
            git: None,
            foreign_platform: false,
            needs_workspace: false,
        };
        let elsewhere = package("https://example.com/x-1.0.0.tgz");
        assert_eq!(
            off_registry_tarball(&elsewhere),
            Some("https://example.com/x-1.0.0.tgz")
        );
        for url in [
            "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
            "file:vendor/x",
            "",
        ] {
            assert_eq!(off_registry_tarball(&package(url)), None, "{url}");
        }
        let mut git = package("https://example.com/x.git");
        git.git = Some(crate::kernel::gitsrc::GitSource {
            url: "https://example.com/x.git".into(),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
            subdirectory: None,
        });
        assert_eq!(off_registry_tarball(&git), None);
    }
}
