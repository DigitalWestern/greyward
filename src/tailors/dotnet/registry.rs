//! The NuGet v3 protocol, as ward's resolution proxy serves it to restore.
//!
//! NuGet reaches api.nuget.org through a mirror, not interception: a
//! greyward-written `nuget.config` names one source, the session's route, and
//! packages.lock.json records no source URL, so a mirror leaves the lock as
//! it would be. Restore asks the mirror for these paths, each mapped to the
//! same path on `https://api.nuget.org`:
//!
//! - `/v3/index.json`: the service index (Index), rewritten (below).
//! - `/v3-flatcontainer/<id>/index.json`: one package's versions
//!   (Metadata).
//! - `/v3-flatcontainer/<id>/<version>/<id>.<version>.nupkg`: a package
//!   (Artifact).
//! - `/v3/vulnerabilities/index.json` and the files it names under
//!   `/v3-vulnerabilities/`: NuGetAudit's data (Metadata), the index
//!   rewritten.
//!
//! Anything else is refused: a query string, registration pages (restore
//! reads none), and any id or version outside the flat container's
//! lower-case grammar. The service index and the vulnerability index carry
//! absolute URLs, so the route rewrites each `https://api.nuget.org/` to
//! the route's base. The service index keeps only api.nuget.org's
//! resources and drops `RepositorySignatures/*`: NuGet requires that
//! resource over https and fails with NU1301 otherwise. The lock's
//! `contentHash` is a semantic hash NuGet itself verifies, so the route
//! claims nothing.

use crate::kernel::resolve::age::parse_rfc3339;
use crate::kernel::resolve::routes::{
    Claim, Endpoint, Lookup, ProxyAddress, RegistryProtocol, RequestClass, Route, Upstream,
};
use std::io;
use url::Url;

/// The route id in mirror URLs: `http://<relay>/<token>/nuget/...`.
pub const ROUTE_ID: &str = "nuget";
/// The NuGet v3 host.
pub const HOST: &str = "api.nuget.org";
/// What every absolute URL the route rewrites starts with.
const UPSTREAM_BASE: &str = "https://api.nuget.org/";

/// The longest id, version or path part the grammar accepts.
const MAX_WORD: usize = 256;

/// The NuGet v3 feed on api.nuget.org.
pub struct NuGet;

pub static NUGET: NuGet = NuGet;

impl RegistryProtocol for NuGet {
    fn route_id(&self) -> &'static str {
        ROUTE_ID
    }

    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        if path.contains('?') {
            return Err(refused(path, "a NuGet request carries no query"));
        }
        check_path(path).map_err(|why| refused(path, &why))?;
        let endpoint = endpoints
            .iter()
            .find(|endpoint| endpoint.host() == HOST)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the NuGet route has no {HOST} endpoint"),
                )
            })?;
        Ok(Upstream::Fetch(endpoint.url(path)?))
    }

    fn classify(&self, url: &Url) -> RequestClass {
        let path = url.path();
        if path == "/v3/index.json" {
            RequestClass::Index
        } else if path.ends_with(".nupkg") {
            RequestClass::Artifact
        } else {
            RequestClass::Metadata
        }
    }

    fn claims(&self, _url: &Url, _body: &[u8]) -> Vec<(Url, Claim)> {
        Vec::new()
    }

    /// A registration leaf (`/v3/registration5-gz-semver2/<id>/<version>.json`,
    /// gzip on the wire): its `published`. NuGet writes 1900-01-01 for an
    /// unlisted version, which says nothing about when it was published.
    fn published(&self, url: &Url, body: &[u8]) -> Vec<(String, String, i64)> {
        let Some((id, version)) = leaf_path(url) else {
            return Vec::new();
        };
        let Some(json) = inflated(body) else {
            return Vec::new();
        };
        serde_json::from_slice::<serde_json::Value>(&json)
            .ok()
            .and_then(|leaf| leaf.get("published")?.as_str().map(str::to_string))
            .filter(|at| !at.starts_with("1900-"))
            .and_then(|at| parse_rfc3339(&at))
            .map(|at| (id.to_string(), version.to_string(), at))
            .into_iter()
            .collect()
    }

    /// The registration leaf of the lower-cased id and version. Restore
    /// itself reads no registration page, so only a lookup reaches one.
    fn lookup(&self, endpoints: &[Endpoint], name: &str, version: &str) -> Option<Lookup> {
        let (id, version) = self.package_key(name, version);
        check_word(&id).ok()?;
        check_word(&version).ok()?;
        let endpoint = endpoints.iter().find(|endpoint| endpoint.host() == HOST)?;
        Some(Lookup {
            url: endpoint
                .url(&format!("{REGISTRATION}{id}/{version}.json"))
                .ok()?,
            accept: "application/json",
        })
    }

    /// Lower-cased ids and NuGet's normalized versions, the spelling its
    /// URLs carry: `1.00` is `1.0.0`, `1.0.0.0` is `1.0.0`, and build
    /// metadata (`+sha.abc`) is dropped.
    fn package_key(&self, name: &str, version: &str) -> (String, String) {
        (name.to_ascii_lowercase(), normalized_version(version))
    }

    fn rewrite(&self, url: &Url, body: Vec<u8>, base: &ProxyAddress) -> io::Result<Vec<u8>> {
        let route_base = base.route_base(ROUTE_ID);
        match url.path() {
            "/v3/index.json" => rewrite_service_index(&body, &route_base),
            "/v3/vulnerabilities/index.json" => rewrite_ids(&body, &route_base),
            _ => Ok(body),
        }
    }
}

/// A NuGet version in its normalized form, lower-cased: build metadata
/// dropped, each release number without leading zeros, at least three of
/// them, and a fourth only when it is not zero. A release part that is not
/// a number leaves the version as written (lower-cased, without metadata).
fn normalized_version(version: &str) -> String {
    let version = version.trim().to_ascii_lowercase();
    let version = version.split('+').next().unwrap_or_default();
    let (release, pre) = match version.split_once('-') {
        Some((release, pre)) => (release, Some(pre)),
        None => (version, None),
    };
    let Ok(mut parts) = release
        .split('.')
        .map(|part| part.parse::<u64>())
        .collect::<Result<Vec<u64>, _>>()
    else {
        return version.to_string();
    };
    if parts.is_empty() || parts.len() > 4 {
        return version.to_string();
    }
    parts.resize(parts.len().max(3), 0);
    if parts.len() == 4 && parts[3] == 0 {
        parts.pop();
    }
    let release = parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".");
    match pre {
        Some(pre) => format!("{release}-{pre}"),
        None => release,
    }
}

/// The registration hive whose leaves carry `published`.
const REGISTRATION: &str = "/v3/registration5-gz-semver2/";
/// The most a registration leaf may inflate to.
const MAX_LEAF: u64 = 1 << 20;

/// The id and version of a registration leaf URL on api.nuget.org.
fn leaf_path(url: &Url) -> Option<(&str, &str)> {
    if url.host_str() != Some(HOST) {
        return None;
    }
    let rest = url.path().strip_prefix(REGISTRATION)?;
    let (id, file) = rest.split_once('/')?;
    let version = file.strip_suffix(".json")?;
    (check_word(id).is_ok() && check_word(version).is_ok() && version != "index")
        .then_some((id, version))
}

/// `body`, inflated when it is gzip (the hive is stored compressed), at
/// most [`MAX_LEAF`] bytes.
fn inflated(body: &[u8]) -> Option<Vec<u8>> {
    if !body.starts_with(&[0x1f, 0x8b]) {
        return Some(body.to_vec());
    }
    super::unpack::gunzip_capped(body, MAX_LEAF)
}

/// Whether `path` is one the route serves.
fn check_path(path: &str) -> Result<(), String> {
    if path == "/v3/index.json" || path == "/v3/vulnerabilities/index.json" {
        return Ok(());
    }
    if let Some(rest) = path.strip_prefix("/v3-flatcontainer/") {
        let parts: Vec<&str> = rest.split('/').collect();
        return match parts.as_slice() {
            [id, "index.json"] => check_word(id),
            [id, version, file] => {
                check_word(id)?;
                check_word(version)?;
                if *file == format!("{id}.{version}.nupkg") {
                    Ok(())
                } else {
                    Err(format!("{file:?} is not {id}.{version}.nupkg"))
                }
            }
            _ => Err("not a flat-container index or package".into()),
        };
    }
    if let Some(rest) = path.strip_prefix("/v3-vulnerabilities/") {
        let parts: Vec<&str> = rest.split('/').collect();
        return match parts.as_slice() {
            [stamp, "vulnerability.base.json"] => check_stamp(stamp),
            [base, stamp, "vulnerability.update.json"] => {
                check_stamp(base)?;
                check_stamp(stamp)
            }
            _ => Err("not a vulnerability file".into()),
        };
    }
    Err("only the service index, the flat container and NuGetAudit's files are served".into())
}

/// A flat-container id or version: lower-case letters, digits, `.`, `-`,
/// `_` and `+`, no leading dot.
fn check_word(word: &str) -> Result<(), String> {
    if word.is_empty()
        || word.len() > MAX_WORD
        || word.starts_with('.')
        || word.contains("..")
        || !word.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_' | b'+')
        })
    {
        return Err(format!("{word:?} is not a flat-container id or version"));
    }
    Ok(())
}

/// A vulnerability data stamp: digits and dots (`2026.09.23.05.36.38`).
fn check_stamp(stamp: &str) -> Result<(), String> {
    if stamp.is_empty()
        || stamp.len() > MAX_WORD
        || !stamp.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return Err(format!("{stamp:?} is not a vulnerability data stamp"));
    }
    Ok(())
}

/// `url` on api.nuget.org, moved to the route.
fn on_route(url: &str, route_base: &str) -> Option<String> {
    url.strip_prefix(UPSTREAM_BASE)
        .map(|rest| format!("{route_base}{rest}"))
}

/// The service index with only api.nuget.org's resources, each moved to the
/// route, and no `RepositorySignatures/*`.
fn rewrite_service_index(body: &[u8], route_base: &str) -> io::Result<Vec<u8>> {
    let mut index: serde_json::Value = serde_json::from_slice(body).map_err(invalid)?;
    let resources = index
        .get_mut("resources")
        .and_then(|value| value.as_array_mut())
        .ok_or_else(|| invalid("the service index has no resources list"))?;
    let kept = std::mem::take(resources)
        .into_iter()
        .filter_map(|mut resource| {
            let kind = resource["@type"].as_str().unwrap_or_default();
            if kind.starts_with("RepositorySignatures/") {
                return None;
            }
            let moved = on_route(resource["@id"].as_str()?, route_base)?;
            resource["@id"] = moved.into();
            Some(resource)
        })
        .collect();
    *resources = kept;
    serde_json::to_vec(&index).map_err(invalid)
}

/// A list of `{"@id": ...}` objects with each api.nuget.org id moved to the
/// route and every other one dropped.
fn rewrite_ids(body: &[u8], route_base: &str) -> io::Result<Vec<u8>> {
    let entries: Vec<serde_json::Value> = serde_json::from_slice(body).map_err(invalid)?;
    let kept: Vec<serde_json::Value> = entries
        .into_iter()
        .filter_map(|mut entry| {
            let moved = on_route(entry["@id"].as_str()?, route_base)?;
            entry["@id"] = moved.into();
            Some(entry)
        })
        .collect();
    serde_json::to_vec(&kept).map_err(invalid)
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn refused(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("NuGet path {path:?} refused: {why}"),
    )
}

/// The `nuget.config` that points restore at a session: no other source,
/// the route's service index over plain http on the relay.
pub fn nuget_config(address: &ProxyAddress) -> String {
    let source = format!("{}v3/index.json", address.route_base(ROUTE_ID));
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
         <clear />\n    <add key=\"nuget.org\" value=\"{source}\" protocolVersion=\"3\" \
         allowInsecureConnections=\"true\" />\n  </packageSources>\n</configuration>\n"
    )
}

/// The proxy (with the session token) for any other https source, which
/// the door refuses visibly. No `http_proxy`: the mirror is plain http on
/// the relay, and the proxy refuses an absolute-form request.
pub fn proxy_env(address: &ProxyAddress) -> Vec<(String, String)> {
    let mirror_host = Url::parse(&address.route_base(ROUTE_ID))
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default();
    vec![
        ("HTTPS_PROXY".to_string(), address.proxy_url()),
        ("NO_PROXY".to_string(), mirror_host),
        (
            "NUGET_CERT_REVOCATION_MODE".to_string(),
            "offline".to_string(),
        ),
    ]
}

/// The NuGet route: api.nuget.org alone.
pub fn route() -> io::Result<Route> {
    Route::new(&NUGET, vec![Endpoint::https(HOST)?])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(path: &str) -> io::Result<String> {
        let endpoints = vec![Endpoint::https(HOST).unwrap()];
        match NUGET.upstream(&endpoints, path)? {
            Upstream::Fetch(url) => Ok(url.to_string()),
            _ => panic!("not a fetch"),
        }
    }

    #[test]
    fn restore_paths_map_to_api_nuget_org() {
        for path in [
            "/v3/index.json",
            "/v3-flatcontainer/humanizer.core/index.json",
            "/v3-flatcontainer/humanizer.core/2.14.1/humanizer.core.2.14.1.nupkg",
            "/v3/vulnerabilities/index.json",
            "/v3-vulnerabilities/2026.09.23.05.36.38/vulnerability.base.json",
            "/v3-vulnerabilities/2026.09.23.05.36.38/2026.09.23.23.36.42/vulnerability.update.json",
        ] {
            assert_eq!(
                upstream(path).unwrap(),
                format!("https://api.nuget.org{path}")
            );
        }
    }

    #[test]
    fn versions_compare_in_nuget_normal_form() {
        let key = |version: &str| NUGET.package_key("Humanizer.Core", version);
        for (spelled, normal) in [
            ("2.14.1", "2.14.1"),
            ("1.0", "1.0.0"),
            ("1", "1.0.0"),
            ("01.002.03", "1.2.3"),
            ("1.0.0.0", "1.0.0"),
            ("1.0.0.4", "1.0.0.4"),
            ("1.0.0-Beta.1", "1.0.0-beta.1"),
            ("1.0-rc+sha.abc", "1.0.0-rc"),
            ("2.14.1+build.7", "2.14.1"),
            ("1.x", "1.x"),
        ] {
            assert_eq!(
                key(spelled),
                ("humanizer.core".to_string(), normal.to_string()),
                "{spelled}"
            );
        }
        let lookup = NUGET
            .lookup(
                &[Endpoint::https(HOST).unwrap()],
                "Humanizer.Core",
                "2.14.1.0",
            )
            .unwrap();
        assert_eq!(
            lookup.url.path(),
            "/v3/registration5-gz-semver2/humanizer.core/2.14.1.json"
        );
    }

    #[test]
    fn everything_else_is_refused() {
        for path in [
            "/v3/index.json?x=1",
            "/v3/registration5-semver1/humanizer.core/index.json",
            "/v3-flatcontainer/Humanizer.Core/index.json",
            "/v3-flatcontainer/humanizer.core/2.14.1/other.2.14.1.nupkg",
            "/v3-flatcontainer/../index.json",
            "/v3-flatcontainer/humanizer.core/2.14.1/humanizer.core.2.14.1.nuspec",
            "/v3-vulnerabilities/x/vulnerability.base.json",
            "/v3/catalog0/index.json",
            "/",
        ] {
            assert!(upstream(path).is_err(), "{path} was served");
        }
    }

    #[test]
    fn the_service_index_keeps_only_its_own_host_moved_to_the_route() {
        let body = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/proxy/registry/dotnet/api.nuget.org/v3/index.json.body"),
        )
        .unwrap();
        let base = "http://127.0.0.1:9/token/nuget/";
        let out: serde_json::Value =
            serde_json::from_slice(&rewrite_service_index(&body, base).unwrap()).unwrap();
        let resources = out["resources"].as_array().unwrap();
        assert!(!resources.is_empty());
        for resource in resources {
            let id = resource["@id"].as_str().unwrap();
            assert!(id.starts_with(base), "{id}");
            let kind = resource["@type"].as_str().unwrap();
            assert!(!kind.starts_with("RepositorySignatures/"), "{kind}");
        }
        assert!(resources
            .iter()
            .any(|r| r["@type"] == "PackageBaseAddress/3.0.0"
                && r["@id"] == format!("{base}v3-flatcontainer/")));
    }

    #[test]
    fn the_vulnerability_index_moves_to_the_route() {
        let body = br#"[{"@name":"base","@id":"https://api.nuget.org/v3-vulnerabilities/1/vulnerability.base.json"},{"@id":"https://elsewhere.test/x"}]"#;
        let out: serde_json::Value =
            serde_json::from_slice(&rewrite_ids(body, "http://r/t/nuget/").unwrap()).unwrap();
        assert_eq!(
            out,
            serde_json::json!([{"@name": "base", "@id": "http://r/t/nuget/v3-vulnerabilities/1/vulnerability.base.json"}])
        );
    }
}
