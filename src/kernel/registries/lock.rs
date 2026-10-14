//! The registry check a sync runs on every package a lock names, before
//! anything is fetched: which listed registry serves its file, and whether
//! that is the registry the lock says it came from.
//!
//! In a default ecosystem nothing changes: the lock's own sources keep
//! today's `unattested-index` recording. In an enforced ecosystem a file
//! no listed registry covers, a lock that names an index the list does not
//! hold, or a file served by a registry other than the one the lock names
//! is an error naming the package, the registry and the list.

use super::config::{Ecosystem, Registry};
use super::effective::Sources;
use crate::kernel::error;
use crate::kernel::fetch::registry::{source_for, Served};
use crate::kernel::fetch::shown_url;
use std::io;

/// Who serves a locked package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// The ecosystem is not enforced: the caller records what it always
    /// has.
    Default,
    /// The public registry, listed.
    Public,
    /// A listed configured registry: approved, no exception.
    Listed(&'a Registry),
}

/// What a lock says about one package.
pub struct Entry<'e> {
    /// The package's name, as the lock spells it (`@scope/name` for npm).
    pub name: &'e str,
    /// The index the lock says the package came from (uv.lock's
    /// `source.registry`); `None` when the lock names none, or names the
    /// public one.
    pub index: Option<&'e str>,
    /// The file the sync would fetch.
    pub file: &'e str,
}

/// Check `entry` against the effective list of `ecosystem`.
pub fn check<'a>(
    sources: &'a Sources,
    ecosystem: Ecosystem,
    entry: &Entry<'_>,
) -> io::Result<Verdict<'a>> {
    let list = sources.ecosystem(ecosystem);
    if !list.enforced {
        return Ok(Verdict::Default);
    }
    let refused = |what: String| {
        error::refused(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} package {}: {what}; {} allows [{}] ({})\nfix: run `ward update {}` so the lock names a listed registry, or have the machine policy list the one it names",
                ecosystem.as_str(),
                entry.name,
                ecosystem.as_str(),
                list.names(),
                list.provenance(),
                entry.name
            ),
        )
    };
    let served = source_for(sources, ecosystem, entry.file).map_err(|_| {
        refused(format!(
            "{} is not under any listed registry",
            shown_url(entry.file)
        ))
    })?;
    let named = match entry.index {
        None => None,
        Some(index) => Some(
            list.registries()
                .find(|registry| same_url(&registry.url, index))
                .ok_or_else(|| {
                    refused(format!(
                        "the lock names index {}, which is not a listed registry",
                        shown_url(index)
                    ))
                })?,
        ),
    };
    let scoped = scope_of(entry.name).and_then(|scope| {
        list.registries()
            .find(|registry| registry.scopes.iter().any(|s| s == scope))
    });
    let expected = named.or(scoped);
    match (served, expected) {
        (Served::Registry(registry), Some(expected)) if registry.name != expected.name => {
            Err(refused(format!(
                "{} is served by registry {}, but the package belongs to registry {}",
                shown_url(entry.file),
                registry.name,
                expected.name
            )))
        }
        (Served::Public, Some(expected)) => Err(refused(format!(
            "{} is on the public registry, but the package belongs to registry {}",
            shown_url(entry.file),
            expected.name
        ))),
        (Served::Registry(registry), _) => Ok(Verdict::Listed(registry)),
        (Served::Public, None) => Ok(Verdict::Public),
    }
}

/// Whether `url` names a registry the effective list of `ecosystem` holds:
/// a project's index setting that points there is approved, and is no
/// exception.
pub fn listed_index(sources: &Sources, ecosystem: Ecosystem, url: &str) -> bool {
    sources
        .ecosystem(ecosystem)
        .registries()
        .any(|registry| same_url(&registry.url, url))
}

/// `@scope` of an npm `@scope/name`.
fn scope_of(name: &str) -> Option<&str> {
    name.starts_with('@')
        .then(|| name.split_once('/').map(|(scope, _)| scope))
        .flatten()
}

/// Whether two index URLs name the same index: parsed, the host
/// lowercased, the default port dropped, the decoded path segments equal,
/// one trailing slash ignored.
pub fn same_url(a: &str, b: &str) -> bool {
    fn key(raw: &str) -> Option<(String, String, u16, Vec<String>)> {
        let url = url::Url::parse(raw).ok()?;
        let mut segments: Vec<String> = url.path_segments()?.map(decode).collect();
        if segments.last().is_some_and(String::is_empty) {
            segments.pop();
        }
        Some((
            url.scheme().to_string(),
            url.host_str()?.to_ascii_lowercase(),
            url.port_or_known_default()?,
            segments,
        ))
    }
    matches!((key(a), key(b)), (Some(a), Some(b)) if a == b)
}

/// `%XX` escapes decoded; a malformed one is kept as spelled.
fn decode(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::{self, Policy, SourceOrigin};
    use std::path::Path;

    fn with_sources(node: &str) -> Policy {
        let text = format!(
            r#"
[[registry]]
name = "corp"
ecosystem = "node"
url = "https://nexus.corp.example/repository/npm/"

[[registry]]
name = "gh"
ecosystem = "node"
url = "https://npm.pkg.github.com/"
scopes = ["@corp"]
files = ["https://pkg-blobs.example/"]

[sources]
node = {node}
"#
        );
        let path = Path::new("/machine/policy.toml");
        let parsed = policy::parse_file(path, &text).unwrap();
        let mut merged = Policy::default();
        policy::merge_file(&mut merged, &parsed, SourceOrigin::Machine, path).unwrap();
        merged
    }

    fn verdict(policy: &Policy, name: &str, index: Option<&str>, file: &str) -> io::Result<String> {
        check(
            &policy.registries,
            Ecosystem::Node,
            &Entry { name, index, file },
        )
        .map(|verdict| match verdict {
            Verdict::Default => "default".into(),
            Verdict::Public => "public".into(),
            Verdict::Listed(registry) => registry.name.clone(),
        })
    }

    #[test]
    fn a_default_ecosystem_is_left_alone() {
        assert_eq!(
            verdict(
                &Policy::default(),
                "x",
                None,
                "https://anywhere.example/x.tgz"
            )
            .unwrap(),
            "default"
        );
    }

    #[test]
    fn a_scoped_package_must_come_from_its_scope_registry() {
        let policy = with_sources(r#"["gh", "corp", "public"]"#);
        assert_eq!(
            verdict(
                &policy,
                "@corp/widget",
                None,
                "https://npm.pkg.github.com/download/@corp/widget/1.0.0/abc"
            )
            .unwrap(),
            "gh"
        );
        assert_eq!(
            verdict(
                &policy,
                "@corp/widget",
                None,
                "https://pkg-blobs.example/abc"
            )
            .unwrap(),
            "gh"
        );
        for file in [
            "https://nexus.corp.example/repository/npm/@corp/widget/-/widget-1.0.0.tgz",
            "https://registry.npmjs.org/@corp/widget/-/widget-1.0.0.tgz",
        ] {
            let error = verdict(&policy, "@corp/widget", None, file)
                .unwrap_err()
                .to_string();
            assert!(error.contains("belongs to registry gh"), "{error}");
            assert!(error.contains("fix:"), "{error}");
        }
        assert_eq!(
            verdict(
                &policy,
                "left-pad",
                None,
                "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            )
            .unwrap(),
            "public"
        );
    }

    #[test]
    fn an_unlisted_file_or_index_is_refused() {
        let policy = with_sources(r#"["corp"]"#);
        let error = verdict(
            &policy,
            "left-pad",
            None,
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not under any listed registry"), "{error}");
        let error = verdict(
            &policy,
            "left-pad",
            Some("https://other.example/npm/"),
            "https://nexus.corp.example/repository/npm/left-pad/-/left-pad-1.3.0.tgz",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a listed registry"), "{error}");
        assert_eq!(
            verdict(
                &policy,
                "left-pad",
                Some("https://NEXUS.corp.example:443/repository/npm"),
                "https://nexus.corp.example/repository/npm/left-pad/-/left-pad-1.3.0.tgz",
            )
            .unwrap(),
            "corp"
        );
    }

    #[test]
    fn index_urls_compare_normalized() {
        assert!(same_url(
            "https://Nexus.example:443/repo/pypi/simple/",
            "https://nexus.example/repo/pypi/simple"
        ));
        assert!(same_url(
            "https://nexus.example/repo/py%70i/simple/",
            "https://nexus.example/repo/pypi/simple/"
        ));
        assert!(!same_url(
            "https://nexus.example/repo/pypi/simple/",
            "https://nexus.example/repo/pypi/simple//"
        ));
        assert!(!same_url(
            "https://nexus.example:8443/repo/",
            "https://nexus.example/repo/"
        ));
        assert!(!same_url(
            "http://nexus.example/repo/",
            "https://nexus.example/repo/"
        ));
    }
}
