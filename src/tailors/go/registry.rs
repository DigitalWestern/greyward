//! Go's module proxy protocol, as ward's resolution proxy serves it.
//!
//! The store go is pointed at the proxy with
//! `GOPROXY=http://<relay>/<token>/go/` (no `direct`) and
//! `GOSUMDB=sum.golang.org`. It then asks for these paths, each mapped
//! here to its upstream:
//!
//! - `/<module>/@v/list`, `/<module>/@v/<version>.info`, `.mod`, `.zip`, and
//!   `/<module>/@latest` go to `https://proxy.golang.org` unchanged. The
//!   import-path prefixes `go get` probes (`/github.com/@v/list`) are the
//!   same grammar, and proxy.golang.org's 404 for them is passed through.
//!   go sends the `!` of an escaped uppercase letter (`!azure`) as `%21`;
//!   the path is percent-decoded once before the grammar sees it, and goes
//!   upstream decoded. proxy.golang.org redirects most `.zip` downloads to
//!   `https://storage.googleapis.com`, and that one hop is followed
//!   ([`GoProxy::follows_redirect`]).
//! - `/sumdb/sum.golang.org/supported` is answered by the proxy itself with
//!   200. Both upstream hosts answer it 404, which would send go straight
//!   to sum.golang.org outside the proxy.
//! - `/sumdb/sum.golang.org/<rest>` (`latest`, `lookup/...`, `tile/...`) goes
//!   to `https://sum.golang.org/<rest>` byte-for-byte. go verifies the
//!   signed tree note itself, so the proxy claims nothing about it. ward
//!   verifies each tree head too, for `young-package`, which judges a Go
//!   version by its record number in the database's log ([`super::sumdb`]):
//!   a head that does not verify is refused.
//!
//! Anything else is refused: another checksum database, a query string, a
//! module or version outside go's escaped spelling, and the
//! `golang.org/toolchain` module (the forced `GOTOOLCHAIN=local` means go
//! never asks for it; a request for it is a broken setting, not a lookup).
//! go checks every module it fetches against go.sum and the checksum
//! database, so the protocol publishes no claims.

use crate::kernel::resolve::routes::{
    Claim, Endpoint, LocalAnswer, Lookup, ProxyAddress, RegistryProtocol, RequestClass, Upstream,
};
use crate::kernel::resolve::tlog::{Head, Log};
use std::io;
use url::Url;

/// The route id in mirror URLs: `http://<relay>/<token>/go/...`.
pub const ROUTE_ID: &str = "go";
/// The module proxy and the checksum database go is pointed at.
pub const PROXY_HOST: &str = "proxy.golang.org";
pub const SUMDB_HOST: &str = "sum.golang.org";
/// Where proxy.golang.org redirects module zips; reached only by that
/// redirect ([`GoProxy::follows_redirect`]), never as an endpoint.
pub const STORAGE_HOST: &str = "storage.googleapis.com";
/// The only checksum database the route serves; `GOSUMDB` names it.
pub const SUMDB_NAME: &str = "sum.golang.org";

/// The longest module path or version the grammar accepts.
const MAX_WORD: usize = 512;

/// Go's module proxy protocol.
pub struct GoProxy;

pub static GO_PROXY: GoProxy = GoProxy;

impl RegistryProtocol for GoProxy {
    fn route_id(&self) -> &'static str {
        ROUTE_ID
    }

    fn upstream(&self, endpoints: &[Endpoint], raw: &str) -> io::Result<Upstream> {
        if raw.contains('?') {
            return Err(refused(raw, "a Go proxy request carries no query"));
        }
        // go's HTTP client sends the `!` of the escaped spelling as `%21`.
        // Every escape in the path (not only `%21`) is decoded once, then
        // held to go's own grammar, which has no `%`: a double encoding
        // (`%2521`) decodes to `%21` and is refused, and an encoded
        // uppercase letter (`%41`) decodes to one the grammar refuses. An
        // escape of an allowed byte (`%73umdb`) is the same request as the
        // byte itself. Upstream gets the decoded spelling, the one go.sum
        // and the checksum database use.
        //
        // `Route::resolve` has already refused an encoded `/`, `\` or NUL;
        // they are refused here too, so this protocol is safe called
        // directly: a decoded `/` would otherwise be a segment boundary.
        let lower = raw.to_ascii_lowercase();
        if ["%2f", "%5c", "%00"].iter().any(|bad| lower.contains(bad)) {
            return Err(refused(raw, "a percent-encoded /, \\, or NUL"));
        }
        let decoded = crate::kernel::gitsrc::percent_decode(raw);
        let path = decoded.as_str();
        let refuse = |why: &str| refused(raw, why);
        let sumdb_prefix = format!("/sumdb/{SUMDB_NAME}/");
        if let Some(rest) = path.strip_prefix(&sumdb_prefix) {
            let sumdb = endpoint(endpoints, SUMDB_HOST)?;
            if rest == "supported" {
                return Ok(Upstream::Local(LocalAnswer {
                    url: sumdb.url("/supported")?,
                    status: 200,
                    content_type: "text/plain; charset=utf-8".into(),
                    body: Vec::new(),
                }));
            }
            check_sumdb_path(rest).map_err(|why| refuse(&why))?;
            return Ok(Upstream::Fetch(sumdb.url(&format!("/{rest}"))?));
        }
        if path.starts_with("/sumdb/") {
            return Err(refuse(&format!(
                "the only checksum database is {SUMDB_NAME}"
            )));
        }
        check_module_path(path).map_err(|why| refuse(&why))?;
        Ok(Upstream::Fetch(endpoint(endpoints, PROXY_HOST)?.url(path)?))
    }

    /// proxy.golang.org hands most module zips to Google Cloud Storage
    /// (`https://storage.googleapis.com/proxy-golang-org-prod/...`, a signed
    /// URL). That one hop is followed for a zip request only: go checks
    /// every zip against go.sum and the checksum database, so the storage
    /// host is trusted with nothing. Both the request go made (`requested`)
    /// and the hop's source must be zips on proxy.golang.org: a `list`,
    /// `@latest`, `.info` or `.mod` request steers version selection or is
    /// checked less, and receives no storage-handoff exception, even when
    /// it redirects through a zip URL first. Only the host is pinned, not
    /// the bucket, which Google may rename; a hop anywhere else, or from
    /// sum.golang.org, is refused.
    fn follows_redirect(&self, requested: &Url, from: &Url, to: &Url) -> bool {
        let zip = |url: &Url| url.host_str() == Some(PROXY_HOST) && url.path().ends_with(".zip");
        zip(requested)
            && zip(from)
            && to.scheme() == "https"
            && to.host_str() == Some(STORAGE_HOST)
            && to.port_or_known_default() == Some(443)
            && to.username().is_empty()
            && to.password().is_none()
    }

    fn classify(&self, url: &Url) -> RequestClass {
        let path = url.path();
        if url.host_str() == Some(SUMDB_HOST) {
            RequestClass::Sumdb
        } else if path.ends_with("/@v/list") {
            RequestClass::Index
        } else if path.ends_with(".zip") {
            RequestClass::Artifact
        } else {
            RequestClass::Metadata
        }
    }

    fn claims(&self, _url: &Url, _body: &[u8]) -> Vec<(Url, Claim)> {
        Vec::new()
    }

    /// A checksum-database lookup answer: the version's record number in
    /// the log, keyed by the escaped module path and version the lookup
    /// URL names (as [`Self::package_key`] spells a go.sum entry). Only an
    /// answer whose tree head verifies, whose record is in that tree, and
    /// whose record is exactly that version's go.sum lines gives one
    /// ([`super::sumdb::verify_lookup`]); any other answer is refused
    /// before it gets here, by [`Self::tree_size`]. The module proxy's
    /// `.info` time is never read: it is the commit's time, which the
    /// module's author sets.
    fn published(&self, url: &Url, body: &[u8]) -> Vec<(String, String, i64)> {
        let Some((module, version)) = lookup_target(url) else {
            return Vec::new();
        };
        let Ok((answer, _)) = super::sumdb::verify_lookup(body, &module, &version) else {
            return Vec::new();
        };
        match i64::try_from(answer.record) {
            Ok(record) => vec![(module, version, record)],
            Err(_) => Vec::new(),
        }
    }

    /// The checksum database's lookup for the version, through the route's
    /// sum.golang.org endpoint.
    fn lookup(&self, endpoints: &[Endpoint], name: &str, version: &str) -> Option<Lookup> {
        let (module, version) = self.package_key(name, version);
        let rest = format!("lookup/{module}@{version}");
        check_sumdb_path(&rest).ok()?;
        Some(Lookup {
            url: endpoint(endpoints, SUMDB_HOST)
                .ok()?
                .url(&format!("/{rest}"))
                .ok()?,
            accept: "*/*",
        })
    }

    /// The proxy's escaped spelling (`!azure`), which the URLs carry.
    fn package_key(&self, name: &str, version: &str) -> (String, String) {
        let escape = |word: &str| {
            crate::tailors::go::escape_go_path(word).unwrap_or_else(|_| word.to_string())
        };
        (escape(name), escape(version))
    }

    /// Go's ages are judged by record numbers in the checksum database.
    fn log(&self) -> Option<Log> {
        Some(super::sumdb::log())
    }

    /// A `latest` answer is a signed tree head; a lookup answer ends with
    /// one, and must also be the record of the version the URL asks for.
    /// Tiles carry none.
    fn tree_size(&self, url: &Url, body: &[u8]) -> Option<Result<Head, String>> {
        if url.host_str() != Some(SUMDB_HOST) {
            return None;
        }
        if url.path() == "/latest" {
            return Some(super::sumdb::verify_tree(body));
        }
        let (module, version) = lookup_target(url)?;
        Some(super::sumdb::verify_lookup(body, &module, &version).map(|(_, head)| head))
    }
}

/// The escaped module path and version a checksum-database lookup URL
/// names.
fn lookup_target(url: &Url) -> Option<(String, String)> {
    if url.host_str() != Some(SUMDB_HOST) {
        return None;
    }
    let (module, version) = url.path().strip_prefix("/lookup/")?.rsplit_once('@')?;
    Some((module.to_string(), version.to_string()))
}

/// The route endpoint on `host`, which a Go route always has.
fn endpoint<'a>(endpoints: &'a [Endpoint], host: &str) -> io::Result<&'a Endpoint> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.host() == host)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the Go route has no {host} endpoint"),
            )
        })
}

fn refused(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("Go proxy path {path:?} refused: {why}"),
    )
}

/// `<module>/@v/list`, `<module>/@v/<version>.(info|mod|zip)`, or
/// `<module>/@latest`, with a leading `/`.
fn check_module_path(path: &str) -> Result<(), String> {
    let path = path
        .strip_prefix('/')
        .ok_or("not an absolute path".to_string())?;
    let (module, tail) = if let Some(module) = path.strip_suffix("/@latest") {
        (module, None)
    } else {
        let (module, rest) = path
            .split_once("/@v/")
            .ok_or("not a module proxy request (no /@v/ or /@latest)".to_string())?;
        (module, Some(rest))
    };
    check_module(module)?;
    match tail {
        None | Some("list") => Ok(()),
        Some(file) => {
            let version = [".info", ".mod", ".zip"]
                .iter()
                .find_map(|suffix| file.strip_suffix(suffix))
                .ok_or(format!("{file:?} is not list, .info, .mod or .zip"))?;
            check_version(version)
        }
    }
}

/// A module path in go's escaped spelling (`module.EscapePath`): lowercase
/// letters, digits, `.`, `-`, `_`, `~`, and `!` before a lowercase letter
/// for each uppercase one, in `/`-separated elements that neither start nor
/// end with a dot.
fn check_module(module: &str) -> Result<(), String> {
    if module.is_empty() || module.len() > MAX_WORD {
        return Err("an empty or overlong module path".into());
    }
    for element in module.split('/') {
        if element.is_empty() || element.starts_with('.') || element.ends_with('.') {
            return Err(format!("module path element {element:?} is not allowed"));
        }
        check_escaped(element, |b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_' | b'~')
        })?;
    }
    if module == "golang.org/toolchain" || module.starts_with("golang.org/toolchain/") {
        return Err(
            "a Go toolchain download; ward forces GOTOOLCHAIN=local and provides go itself".into(),
        );
    }
    Ok(())
}

/// A version in go's escaped spelling: `v`, then lowercase letters,
/// digits, `.`, `-`, `+`, and `!`-escapes.
fn check_version(version: &str) -> Result<(), String> {
    if !version.starts_with('v') || version.len() > MAX_WORD {
        return Err(format!("{version:?} is not a module version"));
    }
    check_escaped(version, |b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+')
    })
}

/// Every byte is `plain`, or `!` followed by a lowercase letter.
fn check_escaped(word: &str, plain: impl Fn(u8) -> bool) -> Result<(), String> {
    let bytes = word.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'!' {
            match bytes.get(index + 1) {
                Some(next) if next.is_ascii_lowercase() => index += 2,
                _ => return Err(format!("{word:?} has a bad ! escape")),
            }
            continue;
        }
        if !plain(byte) {
            return Err(format!("{word:?} has a byte outside go's escaped spelling"));
        }
        index += 1;
    }
    Ok(())
}

/// What go asks a checksum database for: `latest`,
/// `lookup/<module>@<version>`, or a tile
/// `tile/<height>/<level|data>/<x000/>...<000>[.p/<width>]`.
fn check_sumdb_path(rest: &str) -> Result<(), String> {
    if rest == "latest" {
        return Ok(());
    }
    if let Some(lookup) = rest.strip_prefix("lookup/") {
        let (module, version) = lookup
            .rsplit_once('@')
            .ok_or("a lookup names module@version".to_string())?;
        check_module(module)?;
        return check_version(version);
    }
    let tile = rest
        .strip_prefix("tile/")
        .ok_or(format!("{rest:?} is not latest, a lookup, or a tile"))?;
    check_tile(tile)
}

fn check_tile(tile: &str) -> Result<(), String> {
    let bad = || format!("tile/{tile} is not a checksum database tile");
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let tile = match tile.split_once(".p/") {
        Some((tile, width)) if digits(width) => tile,
        Some(_) => return Err(bad()),
        None => tile,
    };
    let parts: Vec<&str> = tile.split('/').collect();
    let [height, level, index @ ..] = parts.as_slice() else {
        return Err(bad());
    };
    if !digits(height) || !(digits(level) || *level == "data") {
        return Err(bad());
    }
    let Some((last, prefix)) = index.split_last() else {
        return Err(bad());
    };
    let three = |part: &str| part.len() == 3 && digits(part);
    let prefix_ok = prefix
        .iter()
        .all(|part| part.strip_prefix('x').is_some_and(three));
    if !prefix_ok || !three(last) {
        return Err(bad());
    }
    Ok(())
}

/// The environment that points the store go at a proxy session: the
/// session's Go mirror, the one checksum database, no VCS.
pub fn proxy_env(address: &ProxyAddress) -> Vec<(String, String)> {
    let base = address.route_base(ROUTE_ID);
    vec![
        (
            "GOPROXY".to_string(),
            base.trim_end_matches('/').to_string(),
        ),
        ("GOSUMDB".to_string(), SUMDB_NAME.to_string()),
        ("GOVCS".to_string(), "*:off".to_string()),
    ]
}

/// The Go route: the module proxy and the checksum database.
pub fn route() -> io::Result<crate::kernel::resolve::routes::Route> {
    crate::kernel::resolve::routes::Route::new(
        &GO_PROXY,
        vec![Endpoint::https(PROXY_HOST)?, Endpoint::https(SUMDB_HOST)?],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> Vec<Endpoint> {
        vec![
            Endpoint::https(PROXY_HOST).unwrap(),
            Endpoint::https(SUMDB_HOST).unwrap(),
        ]
    }

    fn fetch(path: &str) -> String {
        match GO_PROXY.upstream(&endpoints(), path).unwrap() {
            Upstream::Fetch(url) => url.to_string(),
            other => panic!("{path}: {other:?}"),
        }
    }

    fn refusal(path: &str) -> String {
        GO_PROXY
            .upstream(&endpoints(), path)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn record_numbers_come_from_verified_lookups_in_escaped_spelling() {
        let body = include_bytes!(
            "../../../tests/fixtures/proxy/registry/go/sum.golang.org/lookup/github.com/google/uuid@v1.6.0.body"
        );
        let url = |host: &str, path: &str| Url::parse(&format!("https://{host}{path}")).unwrap();
        let lookup = url(SUMDB_HOST, "/lookup/github.com/google/uuid@v1.6.0");
        assert_eq!(
            GO_PROXY.published(&lookup, body),
            vec![(
                "github.com/google/uuid".to_string(),
                "v1.6.0".to_string(),
                22_152_757,
            )]
        );
        let size =
            |answer: Option<Result<Head, String>>| answer.map(|head| head.map(|head| head.size));
        assert_eq!(
            size(GO_PROXY.tree_size(&lookup, body)),
            Some(Ok(64_828_441))
        );
        // The answer must name the version the URL asked for, and is
        // refused outright when it does not.
        let other = url(SUMDB_HOST, "/lookup/github.com/google/uuid@v1.5.0");
        assert!(GO_PROXY.published(&other, body).is_empty());
        assert!(matches!(GO_PROXY.tree_size(&other, body), Some(Err(_))));
        // A forged head gives no record, and its tree size is refused.
        let forged = String::from_utf8_lossy(body).replace("64828441", "94828441");
        assert!(GO_PROXY.published(&lookup, forged.as_bytes()).is_empty());
        assert!(matches!(
            GO_PROXY.tree_size(&lookup, forged.as_bytes()),
            Some(Err(_))
        ));
        // `latest` is a bare head; tiles and the module proxy carry none,
        // and an `.info` time (the commit's, author-set) is never read.
        let head = &body[body.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2..];
        assert_eq!(
            size(GO_PROXY.tree_size(&url(SUMDB_HOST, "/latest"), head)),
            Some(Ok(64_828_441))
        );
        assert_eq!(
            GO_PROXY.tree_size(&url(SUMDB_HOST, "/tile/8/0/x086/534"), head),
            None
        );
        let info = url(PROXY_HOST, "/github.com/google/uuid/@v/v1.6.0.info");
        let info_body = br#"{"Version":"v1.6.0","Time":"2024-01-23T18:54:04Z"}"#;
        assert!(GO_PROXY.published(&info, info_body).is_empty());
        assert_eq!(GO_PROXY.tree_size(&info, info_body), None);
        assert_eq!(GO_PROXY.log().unwrap().name, "sum.golang.org");
        assert_eq!(
            GO_PROXY.package_key("github.com/Azure/sdk", "v1.2.0"),
            ("github.com/!azure/sdk".to_string(), "v1.2.0".to_string())
        );
        // Tagged and pseudo-versions alike are looked up in the log.
        for version in ["v1.2.0", "v0.0.0-20240123185404-0123456789ab"] {
            let lookup = GO_PROXY
                .lookup(&endpoints(), "github.com/Azure/sdk", version)
                .unwrap();
            assert_eq!(
                lookup.url.as_str(),
                format!("https://sum.golang.org/lookup/github.com/!azure/sdk@{version}")
            );
        }
        let sum = "github.com/google/uuid v1.6.0 h1:abc=\n\
                   github.com/google/uuid v1.6.0/go.mod h1:def=\n\
                   golang.org/x/sync v0.9.0/go.mod h1:ghi=\n";
        assert_eq!(
            crate::tailors::go::tool::go_sum_modules(sum).unwrap(),
            [crate::kernel::resolve::age::LockedPackage::new(
                "github.com/google/uuid",
                "v1.6.0"
            )]
        );
        let error = crate::tailors::go::tool::go_sum_modules(
            "github.com/google/uuid v1.6.0 h1:abc=\ngithub.com/evil/pkg v1.0.0\n",
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("line 2"), "{error}");
    }

    #[test]
    fn module_proxy_paths_map_to_proxy_golang_org_unchanged() {
        for path in [
            "/github.com/google/uuid/@v/list",
            "/github.com/google/uuid/@v/v1.6.0.info",
            "/github.com/google/uuid/@v/v1.6.0.mod",
            "/github.com/google/uuid/@v/v1.6.0.zip",
            "/github.com/google/uuid/@latest",
            "/github.com/!burnt!sushi/toml/@v/v1.4.0.info",
            "/github.com/@v/list",
            "/golang.org/x/@v/v0.10.0.info",
            "/gopkg.in/yaml.v3/@v/v3.0.1+incompatible.mod",
        ] {
            assert_eq!(fetch(path), format!("https://proxy.golang.org{path}"));
        }
    }

    /// go's HTTP client sends the `!` escape as `%21`: decoded once, it is
    /// go's escaped spelling and goes upstream with a literal `!`, the
    /// spelling go.sum, the checksum database, and `package_key` use.
    #[test]
    fn percent_encoded_bang_escapes_are_decoded_once() {
        for (raw, upstream) in [
            (
                "/github.com/%21google%21cloud%21platform/opentelemetry-operations-go/@v/list",
                "https://proxy.golang.org/github.com/!google!cloud!platform/opentelemetry-operations-go/@v/list",
            ),
            (
                "/github.com/%21johannes%21kaufmann/html-to-markdown/@v/v1.6.0.zip",
                "https://proxy.golang.org/github.com/!johannes!kaufmann/html-to-markdown/@v/v1.6.0.zip",
            ),
            (
                "/github.com/%21burnt%21sushi/toml/@v/v1.4.0-%21r%21c.mod",
                "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0-!r!c.mod",
            ),
            (
                "/sumdb/sum.golang.org/lookup/github.com/%21azure/azure-sdk-for-go@v68.0.0+incompatible",
                "https://sum.golang.org/lookup/github.com/!azure/azure-sdk-for-go@v68.0.0+incompatible",
            ),
        ] {
            assert_eq!(fetch(raw), upstream, "{raw}");
        }
        // The decoded lookup URL names the same module the lock's spelling
        // escapes to, so its record number keys the version.
        let lookup = Url::parse(&fetch(
            "/sumdb/sum.golang.org/lookup/github.com/%21azure/azure-sdk-for-go@v68.0.0+incompatible",
        ))
        .unwrap();
        assert_eq!(
            lookup_target(&lookup),
            Some(GO_PROXY.package_key("github.com/Azure/azure-sdk-for-go", "v68.0.0+incompatible"))
        );
        // One decoding only, and nothing outside the grammar survives it.
        for (raw, needle) in [
            ("/github.com/%2521google/x/@v/list", "escaped spelling"),
            ("/github.com/%47oogle/x/@v/list", "escaped spelling"),
            ("/github.com/x/@v/v1.0.0-%21r%43.mod", "escaped spelling"),
            ("/github.com/%21/x/@v/list", "bad ! escape"),
            ("/github.com/a%20b/@v/list", "escaped spelling"),
            ("/github.com/x/@v/list%3fgo-get=1", "not list"),
            ("/github.com/x/@v/v1.0.0%ff.zip", "escaped spelling"),
            ("/%73umdb/sum.example.org/latest", "only checksum database"),
        ] {
            let error = refusal(raw);
            assert!(error.contains(needle), "{raw}: {error}");
            assert!(error.contains(raw), "names the path as sent: {error}");
        }
    }

    /// Through the route, as the proxy calls it: the kernel grammar runs
    /// first, then go's; an escaped module resolves to its decoded URL.
    #[test]
    fn the_go_route_resolves_escaped_paths_under_the_kernel_grammar() {
        let route = route().unwrap();
        match route
            .resolve("/github.com/%21azure/azure-sdk-for-go/@v/v68.0.0+incompatible.zip")
            .unwrap()
        {
            Upstream::Fetch(url) => assert_eq!(
                url.as_str(),
                "https://proxy.golang.org/github.com/!azure/azure-sdk-for-go/@v/v68.0.0+incompatible.zip"
            ),
            other => panic!("{other:?}"),
        }
        for (path, needle) in [
            ("/github.com%2fx/y/@v/list", "percent-encoded"),
            ("/github.com/x%5cy/@v/list", "percent-encoded"),
            ("/github.com/x%00/@v/list", "percent-encoded"),
            ("/github.com/%2e%2e/x/@v/list", ". or .."),
            ("/github.com/%2/x/@v/list", "malformed percent-escape"),
            ("/github.com/%zz/x/@v/list", "malformed percent-escape"),
        ] {
            let error = route.resolve(path).unwrap_err();
            assert!(error.contains(needle), "{path}: {error}");
        }
        // The protocol alone refuses the encoded separators too.
        for path in [
            "/github.com%2Fx/y/@v/list",
            "/github.com/x%5Cy/@v/list",
            "/x%00/@v/list",
        ] {
            assert!(refusal(path).contains("percent-encoded"), "{path}");
        }
    }

    /// proxy.golang.org's handoff of a module zip to Cloud Storage is the
    /// one redirect the Go route follows off its own hosts.
    #[test]
    fn only_the_module_proxy_hands_off_to_cloud_storage() {
        let url = |text: &str| Url::parse(text).unwrap();
        let zip = url("https://proxy.golang.org/github.com/klauspost/compress/@v/v1.17.6.zip");
        let storage = url(
            "https://storage.googleapis.com/proxy-golang-org-prod/0900f5b99fe62352-github.com:klauspost:compress-v1.17.6.zip?Expires=1&GoogleAccessId=a&Signature=s",
        );
        assert!(GO_PROXY.follows_redirect(&zip, &zip, &storage));
        // Only a zip request is handed off: a list, @latest, .info or .mod
        // request is not, from its own URL or through a zip URL it redirects to.
        for from in [
            "https://proxy.golang.org/github.com/klauspost/compress/@v/list",
            "https://proxy.golang.org/github.com/klauspost/compress/@latest",
            "https://proxy.golang.org/github.com/klauspost/compress/@v/v1.17.6.info",
            "https://proxy.golang.org/github.com/klauspost/compress/@v/v1.17.6.mod",
        ] {
            assert!(
                !GO_PROXY.follows_redirect(&url(from), &url(from), &storage),
                "{from}"
            );
            assert!(
                !GO_PROXY.follows_redirect(&url(from), &zip, &storage),
                "{from}"
            );
            assert!(
                !GO_PROXY.follows_redirect(&zip, &url(from), &storage),
                "{from}"
            );
        }
        let lookup = url("https://sum.golang.org/lookup/github.com/google/uuid@v1.6.0");
        assert!(!GO_PROXY.follows_redirect(&lookup, &lookup, &storage));
        assert!(!GO_PROXY.follows_redirect(&lookup, &zip, &storage));
        for to in [
            "https://storage.googleapis.com.evil.example/x.zip",
            "https://evil.example/x.zip",
            "https://googleapis.com/x.zip",
            "http://storage.googleapis.com/x.zip",
            "https://storage.googleapis.com:8443/x.zip",
            "https://user:pass@storage.googleapis.com/x.zip",
            "https://sum.golang.org/latest",
        ] {
            assert!(!GO_PROXY.follows_redirect(&zip, &zip, &url(to)), "{to}");
        }
        // From the storage host onward: nothing (the kernel never asks,
        // and the protocol says no anyway).
        assert!(!GO_PROXY.follows_redirect(&zip, &storage, &storage));
    }

    #[test]
    fn sumdb_paths_forward_to_sum_golang_org_and_supported_is_local() {
        for rest in [
            "latest",
            "lookup/github.com/google/uuid@v1.6.0",
            "tile/8/0/x086/534",
            "tile/8/1/989.p/52",
            "tile/8/0/x253/236.p/25",
            "tile/8/data/x001/234",
        ] {
            assert_eq!(
                fetch(&format!("/sumdb/sum.golang.org/{rest}")),
                format!("https://sum.golang.org/{rest}")
            );
        }
        match GO_PROXY
            .upstream(&endpoints(), "/sumdb/sum.golang.org/supported")
            .unwrap()
        {
            Upstream::Local(answer) => {
                assert_eq!(answer.status, 200);
                assert_eq!(answer.url.as_str(), "https://sum.golang.org/supported");
                assert!(answer.body.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn go_grammar_refuses_everything_else() {
        for (path, needle) in [
            ("/sumdb/sum.example.org/latest", "only checksum database"),
            (
                "/sumdb/sum.golang.org/tile/8/0/86/534",
                "not a checksum database tile",
            ),
            (
                "/sumdb/sum.golang.org/tile/8/0/x086/53",
                "not a checksum database tile",
            ),
            (
                "/sumdb/sum.golang.org/lookup/github.com/x",
                "module@version",
            ),
            (
                "/sumdb/sum.golang.org/other",
                "not latest, a lookup, or a tile",
            ),
            ("/github.com/google/uuid/@v/list?go-get=1", "no query"),
            ("/github.com/Google/uuid/@v/list", "escaped spelling"),
            (
                "/github.com/google/uuid/@v/1.6.0.info",
                "not a module version",
            ),
            ("/github.com/google/uuid/@v/v1.6.0.tar", "not list"),
            ("/github.com/google/uuid", "no /@v/"),
            ("/.hidden/mod/@v/list", "is not allowed"),
            ("/github.com/a!/b/@v/list", "bad ! escape"),
            (
                "/golang.org/toolchain/@v/v0.0.1-go1.99.0.linux-amd64.zip",
                "toolchain",
            ),
        ] {
            let error = refusal(path);
            assert!(error.contains(needle), "{path}: {error}");
        }
    }

    #[test]
    fn requests_are_classified_by_what_they_fetch() {
        let class = |url: &str| GO_PROXY.classify(&Url::parse(url).unwrap());
        assert_eq!(
            class("https://proxy.golang.org/github.com/google/uuid/@v/list"),
            RequestClass::Index
        );
        assert_eq!(
            class("https://proxy.golang.org/github.com/google/uuid/@v/v1.6.0.zip"),
            RequestClass::Artifact
        );
        assert_eq!(
            class("https://proxy.golang.org/github.com/google/uuid/@v/v1.6.0.mod"),
            RequestClass::Metadata
        );
        assert_eq!(
            class("https://proxy.golang.org/github.com/google/uuid/@latest"),
            RequestClass::Metadata
        );
        assert_eq!(
            class("https://sum.golang.org/tile/8/1/338"),
            RequestClass::Sumdb
        );
        assert!(GO_PROXY
            .claims(
                &Url::parse("https://proxy.golang.org/x/@v/v1.0.0.mod").unwrap(),
                b"module x"
            )
            .is_empty());
    }

    /// The real Go route through the proxy, on port 443 with every address
    /// landing on the fixture: an `%21`-escaped zip is fetched decoded and
    /// handed off to Cloud Storage, through the mirror and through a
    /// tunnel to proxy.golang.org alike. Under a policy that denies
    /// `unattested-index`, the handoff records no such fact; a `.mod` is
    /// not handed off; a refused `%21` request keeps its path in the
    /// portable ledger.
    #[test]
    fn an_escaped_zip_is_handed_off_to_cloud_storage_on_both_doors() {
        use crate::kernel::policy::{self, Policy};
        use crate::kernel::resolve::session::{Intercept, Mode};
        use crate::kernel::resolve::testing::{
            get, open_tunnel, tunnel_request, Harness, Reach, TEST_ORIGIN_PUBLIC,
        };
        use crate::kernel::testutil::upstream::{Behavior, Reply};

        let harness = Harness::serving(
            "go-storage-handoff",
            Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]),
            &[PROXY_HOST, SUMDB_HOST, STORAGE_HOST],
            "go",
        );
        let zip = "/github.com/!azure/demo/@v/v1.0.0.zip";
        let signed = "/proxy-golang-org-prod/0a-github.com:!azure:demo-v1.0.0.zip\
                      ?Expires=1&GoogleAccessId=signer%40example&Signature=SECRETSIGNATURE";
        let to_storage = |target: &str| {
            Behavior::Reply(
                Reply::new(302, b"").header("Location", &format!("https://{STORAGE_HOST}{target}")),
            )
        };
        harness.upstream.set(zip, to_storage(signed));
        harness
            .upstream
            .set(signed, Behavior::Reply(Reply::new(200, b"zip bytes")));
        let module = "/github.com/!azure/demo/@v/v1.0.0.mod";
        harness.upstream.set(module, to_storage("/bucket/demo.mod"));
        let policy = Policy {
            deny: [policy::UNATTESTED_INDEX.to_string()].into(),
            ..Policy::default()
        };
        let mut config = harness.config(policy, Mode::Online);
        config.routes = vec![route().unwrap()];
        config.permitted = crate::kernel::resolve::routes::Permitted::compiled();
        config.intercept = Intercept::Tls;
        let (session, address) = harness.open(config);

        let mirrored = get(
            &address,
            &format!(
                "/{}/go/github.com/%21azure/demo/@v/v1.0.0.zip",
                address.token()
            ),
            "",
        );
        assert_eq!(mirrored.status, 200, "{}", mirrored.text());
        assert_eq!(mirrored.body, b"zip bytes");

        let authority = format!("{PROXY_HOST}:443");
        let roots = harness.proxy.authority().roots();
        let mut tunnel = open_tunnel(&address, &authority, PROXY_HOST, roots, &[]).unwrap();
        let request = |method: &str, path: &str| {
            format!("{method} {path} HTTP/1.1\r\nHost: {PROXY_HOST}\r\n")
        };
        let tunneled = tunnel_request(
            &mut tunnel,
            &request("GET", "/github.com/%21azure/demo/@v/v1.0.0.zip"),
            b"",
        );
        assert_eq!(tunneled.status, 200, "{}", tunneled.text());
        assert_eq!(tunneled.body, b"zip bytes");
        let not_zip = tunnel_request(
            &mut tunnel,
            &request("GET", "/github.com/%21azure/demo/@v/v1.0.0.mod"),
            b"",
        );
        assert_eq!(not_zip.status, 403, "{}", not_zip.text());
        assert!(
            not_zip.text().contains("is not a permitted endpoint"),
            "{}",
            not_zip.text()
        );
        let pushed = tunnel_request(
            &mut tunnel,
            &request("DELETE", "/github.com/%21azure/demo/@v/v1.0.0.zip"),
            b"",
        );
        assert_eq!(pushed.status, 405, "{}", pushed.text());
        drop(tunnel);

        let report = session.finish();
        assert_eq!(harness.upstream.hits(signed), 2);
        assert_eq!(harness.upstream.hits("/bucket/demo.mod"), 0);
        assert!(
            !report
                .facts
                .exceptions
                .iter()
                .any(|fact| fact.kind == policy::UNATTESTED_INDEX),
            "{:?}",
            report.facts
        );
        assert!(report.facts.refusals.is_empty(), "{:?}", report.facts);
        let entries: Vec<_> = report.ledger.entries().cloned().collect();
        let fetched = format!("https://{PROXY_HOST}{zip}");
        assert!(
            entries
                .iter()
                .any(|entry| entry.url == fetched && entry.status == 200),
            "{entries:?}"
        );
        // The refused DELETE was never resolved, but its path is one the
        // route maps to the decoded URL: it is kept whole, as sent.
        let refused = format!("https://{PROXY_HOST}/github.com/%21azure/demo/@v/v1.0.0.zip");
        assert!(
            entries
                .iter()
                .any(|entry| entry.url == refused && entry.method == "DELETE"),
            "{entries:?}"
        );
        let text = format!("{entries:?} {:?}", report.diagnostics);
        assert!(!text.contains("SECRETSIGNATURE"), "{text}");
    }

    /// A list, `@latest`, `.info` or `.mod` request that redirects to a
    /// zip URL on proxy.golang.org, which then hands off to Cloud Storage,
    /// does not pick up the zip's exception: the handoff is judged on the
    /// request go made, and is refused through the mirror and a tunnel.
    #[test]
    fn a_document_cannot_reach_cloud_storage_through_a_zip_url() {
        use crate::kernel::policy::{self, Policy};
        use crate::kernel::resolve::session::{Intercept, Mode};
        use crate::kernel::resolve::testing::{
            get, open_tunnel, tunnel_request, Harness, Reach, TEST_ORIGIN_PUBLIC,
        };
        use crate::kernel::testutil::upstream::{Behavior, Reply};

        let harness = Harness::serving(
            "go-storage-chain",
            Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]),
            &[PROXY_HOST, SUMDB_HOST, STORAGE_HOST],
            "go",
        );
        let location =
            |target: String| Behavior::Reply(Reply::new(302, b"").header("Location", &target));
        let documents = [
            "/github.com/chain/demo/@v/list",
            "/github.com/chain/demo/@latest",
            "/github.com/chain/demo/@v/v1.0.0.info",
            "/github.com/chain/demo/@v/v1.0.0.mod",
        ];
        for (index, document) in documents.iter().enumerate() {
            let zip = format!("/github.com/chain/demo/@v/v9.0.{index}.zip");
            harness
                .upstream
                .set(document, location(format!("https://{PROXY_HOST}{zip}")));
            harness.upstream.set(
                &zip,
                location(format!("https://{STORAGE_HOST}/bucket/chain-{index}")),
            );
            harness.upstream.set(
                &format!("/bucket/chain-{index}"),
                Behavior::Reply(Reply::new(200, b"steered")),
            );
        }
        let policy = Policy {
            deny: [policy::UNATTESTED_INDEX.to_string()].into(),
            ..Policy::default()
        };
        let mut config = harness.config(policy, Mode::Online);
        config.routes = vec![route().unwrap()];
        config.permitted = crate::kernel::resolve::routes::Permitted::compiled();
        config.intercept = Intercept::Tls;
        let (session, address) = harness.open(config);

        let authority = format!("{PROXY_HOST}:443");
        let roots = harness.proxy.authority().roots();
        let mut tunnel = open_tunnel(&address, &authority, PROXY_HOST, roots, &[]).unwrap();
        for document in documents {
            let mirrored = get(&address, &format!("/{}/go{document}", address.token()), "");
            let tunneled = tunnel_request(
                &mut tunnel,
                &format!("GET {document} HTTP/1.1\r\nHost: {PROXY_HOST}\r\n"),
                b"",
            );
            for (door, answer) in [("mirror", &mirrored), ("tunnel", &tunneled)] {
                assert_eq!(answer.status, 403, "{door} {document}: {}", answer.text());
                assert!(
                    answer.text().contains("is not a permitted endpoint"),
                    "{door} {document}: {}",
                    answer.text()
                );
            }
        }
        drop(tunnel);
        session.finish();
        for index in 0..documents.len() {
            assert_eq!(harness.upstream.hits(&format!("/bucket/chain-{index}")), 0);
        }
    }

    #[test]
    fn the_route_reaches_only_the_two_go_hosts() {
        let route = route().unwrap();
        let hosts: Vec<&str> = route.endpoints.iter().map(Endpoint::host).collect();
        assert_eq!(hosts, vec![PROXY_HOST, SUMDB_HOST]);
        assert!(route.resolve("/github.com/google/uuid/@v/list").is_ok());
        assert!(route.resolve("/github.com/google/../uuid/@v/list").is_err());
    }

    /// `go mod tidy` then `go get golang.org/x/sync@v0.10.0`, the census's
    /// order, confined and answered by the recorded Go registry: the
    /// checksum database is reached only through the mirror, and its
    /// `supported` probe is answered locally.
    ///
    /// Ignored: it realizes the store Go toolchain, which is fetched over
    /// the network. The resolution itself is offline.
    #[test]
    #[ignore = "realizes the store Go toolchain over the network"]
    fn go_get_through_mirror_uses_proxied_sumdb() {
        use crate::kernel::platform::Platform;
        use crate::kernel::policy::{self, Attribution};
        use crate::kernel::resolve::door::RELAY_FOR_TEST;
        use crate::kernel::resolve::ledger;
        use crate::kernel::resolve::routes::{Permitted, Route};
        use crate::kernel::resolve::testing::{relay, Harness, Reach};
        use crate::kernel::resolve::DoorKind;
        use crate::kernel::resolve::ResolutionDoor;
        use crate::tailors::go::tool::{go_confined, go_spec, GoPublish, GoRun};
        use std::fs;

        let Some(relay) = relay("go_get_through_mirror_uses_proxied_sumdb") else {
            return;
        };
        let harness = Harness::serving(
            "go-mirror",
            Reach::loopback(),
            &[PROXY_HOST, SUMDB_HOST],
            "go",
        );
        let port = harness.upstream.port();
        let store = &harness.store;
        let activity = &harness.activity;
        // A checkpoint old enough to judge by, as a store that resolved Go
        // a month ago holds: both recorded versions sit below it.
        let month_ago =
            crate::kernel::resolve::age::unix_seconds(std::time::SystemTime::now()) - 30 * 86_400;
        // The recorded lookup's head, root and all, so no head go fetches
        // of that size can disagree with it.
        let fixture = include_bytes!(
            "../../../tests/fixtures/proxy/registry/go/sum.golang.org/lookup/github.com/google/uuid@v1.6.0.body"
        );
        let (_, head) =
            crate::tailors::go::sumdb::verify_lookup(fixture, "github.com/google/uuid", "v1.6.0")
                .unwrap();
        crate::kernel::resolve::tlog::record(store, &GO_PROXY.log().unwrap(), head, month_ago)
            .unwrap();
        let go_obj = super::super::ensure_go(store, activity, "1.27.0").unwrap();
        let modcache = super::super::gate_cache(store).unwrap();
        let temp = crate::kernel::testutil::TempDir::named("go-mirror-project");
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("go.mod"), "module spike\n\ngo 1.23\n").unwrap();
        fs::write(
            project.join("main.go"),
            "package main\n\nimport \"github.com/google/uuid\"\n\nfunc main() { _ = uuid.New() }\n",
        )
        .unwrap();
        let project = project.canonicalize().unwrap();

        let _serial = policy::attribution_test_lock();
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        let run = |kind: DoorKind, args: &[&str]| {
            let mut attribution = Attribution::open("go").unwrap();
            let mut door = ResolutionDoor::open(
                store,
                activity,
                Platform::host().unwrap(),
                kind,
                &mut attribution,
            )
            .unwrap();
            let go = GoRun {
                go_obj: &go_obj,
                lock_root: &project,
                modcache: &modcache,
                args,
                publish: GoPublish::Project { receipt: None },
            };
            let mut confined = go_confined(&go, GoPublish::Project { receipt: None }).unwrap();
            confined.routes = vec![Route::new(
                &GO_PROXY,
                vec![
                    Endpoint::for_test(PROXY_HOST, port),
                    Endpoint::for_test(SUMDB_HOST, port),
                ],
            )
            .unwrap()];
            confined.proxy = Some(&harness.proxy);
            confined.permitted = Permitted::compiled()
                .with_origin(PROXY_HOST, port)
                .with_origin(SUMDB_HOST, port);
            let spec = go_spec(&go_obj, &project, &modcache, false, args);
            let report = door.run_confined(spec, confined).unwrap();
            assert!(
                report.status.success(),
                "go {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&report.stderr)
            );
            let recorded = attribution.recorded();
            attribution.discard();
            (report, recorded)
        };

        let (tidy, _) = run(DoorKind::MissingLock, &["mod", "tidy"]);
        let gosum = fs::read_to_string(project.join("go.sum")).unwrap();
        assert!(
            gosum.contains("github.com/google/uuid v1.6.0 h1:"),
            "{gosum}"
        );
        let (get, recorded) = run(DoorKind::Edit, &["get", "golang.org/x/sync@v0.10.0"]);
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        assert!(recorded.is_empty(), "{recorded:?}");
        // Every tree head go fetched through the mirror verified and is a
        // checkpoint now, beside the seed and the one written above.
        let kept = crate::kernel::resolve::tlog::load(store, &GO_PROXY.log().unwrap()).unwrap();
        assert!(kept.len() > 2, "{kept:?}");
        let gomod = fs::read_to_string(project.join("go.mod")).unwrap();
        assert!(gomod.contains("golang.org/x/sync v0.10.0"), "{gomod}");
        let gosum = fs::read_to_string(project.join("go.sum")).unwrap();
        assert!(gosum.contains("golang.org/x/sync v0.10.0 h1:"), "{gosum}");

        let sum = format!("https://{SUMDB_HOST}:{port}");
        for (report, lookup) in [
            (&tidy, "github.com/google/uuid@v1.6.0"),
            (&get, "golang.org/x/sync@v0.10.0"),
        ] {
            let objects = report.ledger.as_ref().unwrap();
            let portable = ledger::PortableLedger::parse(
                &ledger::read_portable(store, &objects.ledger).unwrap(),
            )
            .unwrap();
            let entries: Vec<_> = portable.entries().collect();
            assert!(
                entries
                    .iter()
                    .any(|entry| entry.url == format!("{sum}/lookup/{lookup}")
                        && entry.class == "sumdb"
                        && entry.status == 200),
                "{entries:?}"
            );
            assert!(
                entries.iter().all(|entry| entry.class != "refused"),
                "{entries:?}"
            );
            assert!(
                entries.iter().all(|entry| entry.url.starts_with(&sum)
                    || entry
                        .url
                        .starts_with(&format!("https://{PROXY_HOST}:{port}/"))),
                "every request went to the two Go hosts: {entries:?}"
            );
        }
    }
}
