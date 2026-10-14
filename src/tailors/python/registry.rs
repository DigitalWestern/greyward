//! The PyPI protocol (python tailor), as ward's resolution proxy serves it to
//! uv.
//!
//! uv reaches PyPI through TLS interception, not a mirror: `uv.lock` and
//! `requirements.lock.txt` record PyPI's own file URLs, so the proxy
//! terminates uv's tunnels to `pypi.org` and `files.pythonhosted.org` and
//! serves what it asks for there through this route:
//!
//! - `pypi.org/simple/<name>/`: the project page (PEP 691 JSON, which uv
//!   asks for, or PEP 503 HTML). Each file it lists names its URL and its
//!   hashes (`hashes` in JSON, a `#sha256=` fragment in HTML), and the
//!   hash of its core metadata when PyPI serves that separately
//!   (`core-metadata`, PEP 714, or the older `data-dist-info-metadata`).
//!   Those are the route's claims.
//! - `files.pythonhosted.org/packages/...`: a wheel or sdist, verified
//!   against its page's claim, and a wheel's `<file>.metadata` (PEP 658),
//!   which is how uv resolves without downloading wheels.
//!
//! Anything else on either host is refused. An extra index a project
//! names (`[[tool.uv.index]]`), a direct-URL requirement, and a git
//! dependency are not this route's: they reach the proxy as unattested
//! hosts or git fetches (see `kernel::resolve::intercept`).

use super::pypi::normalize_name;
use crate::kernel::fetch::Digest;
use crate::kernel::pep440::Version;
use crate::kernel::registries::config::Registry;
use crate::kernel::registries::covers;
use crate::kernel::resolve::age::parse_rfc3339;
use crate::kernel::resolve::routes::{
    file_key, Claim, Endpoint, Lookup, RegistryProtocol, RequestClass, Route, Upstream,
};
use std::io;
use url::Url;

/// The route id the ledger and the diagnostics name.
pub const ROUTE_ID: &str = "pypi";
/// The index host.
pub const INDEX_HOST: &str = "pypi.org";
/// The file host.
pub const FILES_HOST: &str = "files.pythonhosted.org";
/// The index as uv is told it: the default index forced on every uv run.
pub const INDEX_URL: &str = "https://pypi.org/simple";

/// The longest project name this grammar accepts.
const MAX_NAME: usize = 256;
/// The longest path segment under `/packages/`.
const MAX_SEGMENT: usize = 512;
/// The most segments a file path has under `/packages/` (PyPI's hashed
/// layout uses four, the legacy `<pyver>/<letter>/<name>/<file>` four too).
const MAX_FILE_DEPTH: usize = 6;
/// The suffix of a wheel's separately served core metadata (PEP 658).
const METADATA_SUFFIX: &str = ".metadata";
/// The distribution file types PyPI serves.
const DIST_SUFFIXES: [&str; 6] = [".whl", ".tar.gz", ".zip", ".tar.bz2", ".tgz", ".egg"];

/// The PyPI protocol.
pub struct PypiRegistry;

pub static PYPI_REGISTRY: PypiRegistry = PypiRegistry;

impl RegistryProtocol for PypiRegistry {
    fn route_id(&self) -> &'static str {
        ROUTE_ID
    }

    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        if path.contains('?') {
            return Err(refused(path, "a PyPI request carries no query"));
        }
        let host = match check_path(path) {
            Ok(host) => host,
            Err(why) => return Err(refused(path, &why)),
        };
        Ok(Upstream::Fetch(endpoint(endpoints, host)?.url(path)?))
    }

    fn classify(&self, url: &Url) -> RequestClass {
        if url.host_str() == Some(FILES_HOST) {
            // Wheel metadata is immutable, claimed content too. Routing it
            // as revalidatable metadata would bypass digest verification.
            RequestClass::Artifact
        } else {
            RequestClass::Index
        }
    }

    /// Each file a project page lists, on the file host, claimed by its
    /// strongest hash, and its core metadata by the hash the page gives
    /// for it.
    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)> {
        if url.host_str() != Some(INDEX_HOST) || !url.path().starts_with("/simple/") {
            return Vec::new();
        }
        page_claims(url, body, |target| {
            target.host_str() == Some(FILES_HOST) && check_file_path(target.path()).is_ok()
        })
    }

    /// PyPI publishes a digest for every file it serves.
    fn expects_claim(&self, url: &Url) -> bool {
        url.host_str() == Some(FILES_HOST)
    }

    /// A JSON project page's `upload-time` per file, each file's version
    /// read from its name: under the version (whose earliest file is when
    /// it was published) and under the file's own key ([`file_key`]), since
    /// a file can be added to a version long after its first. An HTML page
    /// carries no upload times.
    fn published(&self, url: &Url, body: &[u8]) -> Vec<(String, String, i64)> {
        if url.host_str() != Some(INDEX_HOST) || !url.path().starts_with("/simple/") {
            return Vec::new();
        }
        page_times(body)
    }

    /// The project's JSON page (PEP 691), which lists each file's upload
    /// time.
    fn lookup(&self, endpoints: &[Endpoint], name: &str, _version: &str) -> Option<Lookup> {
        let name = normalize_name(name);
        check_name(&name).ok()?;
        let url = endpoint(endpoints, INDEX_HOST)
            .ok()?
            .url(&format!("/simple/{name}/"))
            .ok()?;
        Some(Lookup {
            url,
            accept: "application/vnd.pypi.simple.v1+json",
        })
    }

    /// PEP 503 names and PEP 440 normalized versions (`1.0-1` is
    /// `1.0.post1`); a [`file_key`]'s file name compared without letter
    /// case.
    fn package_key(&self, name: &str, version: &str) -> (String, String) {
        package_key(name, version)
    }
}

/// PyPI's [`RegistryProtocol::package_key`], shared with configured
/// indexes.
fn package_key(name: &str, version: &str) -> (String, String) {
    let version = match version.split_once(' ') {
        // A lock takes the file name from its URL, percent-encoded
        // (`%2B` for a local version's `+`); the index names it plain.
        Some((version, file)) => file_key(
            &version_key(version),
            &crate::kernel::gitsrc::percent_decode(file).to_ascii_lowercase(),
        ),
        None => version_key(version),
    };
    (normalize_name(name), version)
}

/// The upload times a JSON project page (PEP 691) lists: each file's under
/// the file's own key ([`file_key`]) and under its version, read from the
/// file's name. An HTML page carries none.
fn page_times(body: &[u8]) -> Vec<(String, String, i64)> {
    let Ok(page) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(name) = page.get("name").and_then(|name| name.as_str()) else {
        return Vec::new();
    };
    page.get("files")
        .and_then(|files| files.as_array())
        .into_iter()
        .flatten()
        .filter_map(|file| {
            let filename = file.get("filename")?.as_str()?;
            let at = parse_rfc3339(file.get("upload-time")?.as_str()?)?;
            let version = file_version(name, filename)?;
            Some([
                (name.to_string(), file_key(&version, filename), at),
                (name.to_string(), version, at),
            ])
        })
        .flatten()
        .collect()
}

/// A version's PEP 440 normal form, compared as PEP 440 compares it: the
/// release's trailing zeros dropped (`1.0` is `1.0.0`), here only, so the
/// shared canonical form stays as written. A wheel file name may spell an
/// epoch's `!` as `_` (`1_2.0` is `1!2.0`); a version that does not parse
/// either way is compared as written, without letter case.
fn version_key(version: &str) -> String {
    let canonical = |text: &str| {
        Version::parse(text)
            .ok()
            .map(|parsed| trim_release(&parsed.canonical()))
    };
    canonical(version)
        .or_else(|| {
            let (epoch, rest) = version.split_once('_')?;
            if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            canonical(&format!("{epoch}!{rest}"))
        })
        .unwrap_or_else(|| version.to_ascii_lowercase())
}

/// `canonical` with its release's trailing `.0` segments dropped (one
/// segment always stays): `1!2.0.0rc1` is `1!2rc1`.
fn trim_release(canonical: &str) -> String {
    let (epoch, rest) = match canonical.split_once('!') {
        Some((epoch, rest)) => (Some(epoch), rest),
        None => (None, canonical),
    };
    // The release is the leading digits and dots, less the dot that
    // starts a `.post` or `.dev` segment.
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    let end = rest[..end].trim_end_matches('.').len();
    let (mut release, tail) = rest.split_at(end);
    while let Some(head) = release.strip_suffix(".0") {
        release = head;
    }
    match epoch {
        Some(epoch) => format!("{epoch}!{release}{tail}"),
        None => format!("{release}{tail}"),
    }
}

/// The version in a distribution's file name for project `project`: a
/// wheel's second field, or what follows the project's name in an sdist
/// (whose name part may itself hold `-`). `None` for an egg or a name that
/// does not belong to `project`.
fn file_version(project: &str, filename: &str) -> Option<String> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let mut fields = stem.split('-');
        let (dist, version) = (fields.next()?, fields.next()?);
        return (normalize_name(dist) == normalize_name(project) && !version.is_empty())
            .then(|| version.to_string());
    }
    let stem = [".tar.gz", ".zip", ".tar.bz2", ".tgz"]
        .iter()
        .find_map(|suffix| filename.strip_suffix(suffix))?;
    let project = normalize_name(project);
    stem.match_indices('-').find_map(|(at, _)| {
        let version = &stem[at + 1..];
        (normalize_name(&stem[..at]) == project
            && version.starts_with(|c: char| c.is_ascii_digit()))
        .then(|| version.to_string())
    })
}

/// One file a project page lists: its link as written, and the hashes the
/// page gives for it and for its core metadata (`(algorithm, hex)`).
struct ListedFile {
    href: String,
    hashes: Vec<(String, String)>,
    metadata: Vec<(String, String)>,
}

/// The files of a PEP 691 JSON page.
fn json_files(page: &serde_json::Value) -> Vec<ListedFile> {
    let pairs = |value: Option<&serde_json::Value>| -> Vec<(String, String)> {
        value
            .and_then(|value| value.as_object())
            .into_iter()
            .flatten()
            .filter_map(|(algo, hex)| Some((algo.to_ascii_lowercase(), hex.as_str()?.to_string())))
            .collect()
    };
    page.get("files")
        .and_then(|files| files.as_array())
        .into_iter()
        .flatten()
        .filter_map(|file| {
            let href = file.get("url")?.as_str()?.to_string();
            // PEP 714 renamed the key; a page may carry either, and a bare
            // `true` names no hash.
            let metadata = file
                .get("core-metadata")
                .filter(|value| value.is_object())
                .or_else(|| file.get("data-dist-info-metadata"));
            Some(ListedFile {
                href,
                hashes: pairs(file.get("hashes")),
                metadata: pairs(metadata),
            })
        })
        .collect()
}

/// The files of a PEP 503 HTML page: each anchor's `href` (its `#<algo>=<hex>`
/// fragment is the file's hash) and its `data-core-metadata` (or
/// `data-dist-info-metadata`) `<algo>=<hex>`.
fn html_files(text: &str) -> Vec<ListedFile> {
    let mut files = Vec::new();
    let mut rest = text;
    while let Some(start) = find_ascii_ci(rest, "<a ") {
        let tag_rest = &rest[start..];
        let end = tag_rest.find('>').unwrap_or(tag_rest.len());
        let tag = &tag_rest[..end];
        rest = &tag_rest[end..];
        let Some(href) = attribute(tag, "href") else {
            continue;
        };
        let href = unescape(&href);
        let hashes = href
            .split_once('#')
            .and_then(|(_, fragment)| hash_pair(fragment))
            .into_iter()
            .collect();
        let metadata = attribute(tag, "data-core-metadata")
            .or_else(|| attribute(tag, "data-dist-info-metadata"))
            .and_then(|value| hash_pair(&unescape(&value)))
            .into_iter()
            .collect();
        files.push(ListedFile {
            href,
            hashes,
            metadata,
        });
    }
    files
}

fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// The value of `name="..."` (or single-quoted) in an HTML tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let mut search = tag;
    loop {
        let at = find_ascii_ci(search, name)?;
        let before = search[..at].chars().last();
        let after = &search[at + name.len()..];
        search = after;
        if !before.is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(value) = after.trim_start().strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let quote = value.chars().next()?;
        if quote != '"' && quote != '\'' {
            continue;
        }
        let inner = &value[1..];
        let close = inner.find(quote)?;
        return Some(inner[..close].to_string());
    }
}

/// The few entities a PyPI page writes inside attributes.
fn unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

/// `<algo>=<hex>`.
fn hash_pair(text: &str) -> Option<(String, String)> {
    let (algo, hex) = text.split_once('=')?;
    Some((algo.to_ascii_lowercase(), hex.to_string()))
}

/// The claim of the strongest algorithm ward reads among `hashes`: sha512,
/// then sha256, then sha1 (weak). An md5 alone claims nothing, so its
/// artifact is unclaimed and `weak-integrity`.
fn strongest(hashes: &[(String, String)]) -> Option<Claim> {
    for algo in ["sha512", "sha256", "sha1"] {
        if let Some((_, hex)) = hashes.iter().find(|(name, _)| name == algo) {
            if let Ok(digest) = Digest::from_parts(algo, &hex.to_ascii_lowercase()) {
                return Some(Claim::one(digest));
            }
        }
    }
    None
}

/// The route endpoint on `host`, which a PyPI route always has.
fn endpoint<'a>(endpoints: &'a [Endpoint], host: &str) -> io::Result<&'a Endpoint> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.host() == host)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the PyPI route has no {host} endpoint"),
            )
        })
}

fn refused(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("PyPI path {path:?} refused: {why}"),
    )
}

/// Which host serves `path`, else why it is not a PyPI path.
fn check_path(path: &str) -> Result<&'static str, String> {
    if let Some(rest) = path.strip_prefix("/simple/") {
        let name = rest.strip_suffix('/').unwrap_or(rest);
        if name.is_empty() {
            return Ok(INDEX_HOST);
        }
        check_name(name)?;
        return Ok(INDEX_HOST);
    }
    if path.starts_with("/packages/") {
        check_file_path(path)?;
        return Ok(FILES_HOST);
    }
    Err("not a project page (/simple/<name>/) or a file (/packages/...)".into())
}

/// A project name as a page path spells it: letters, digits, `.`, `_`,
/// `-`, not starting with `.`.
fn check_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(format!("{name:?} is not a project name"))
    }
}

/// `/packages/<dir>/.../<file>`: plain segments, the last a distribution
/// file or its `.metadata`.
fn check_file_path(path: &str) -> Result<(), String> {
    let rest = path
        .strip_prefix("/packages/")
        .ok_or("a file is under /packages/")?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() < 2 || parts.len() > MAX_FILE_DEPTH {
        return Err("a file is /packages/<directories>/<file>".into());
    }
    for part in &parts {
        let valid = !part.is_empty()
            && part.len() <= MAX_SEGMENT
            && !part.starts_with('.')
            && part.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'!')
            });
        if !valid {
            return Err(format!("{part:?} is not a file path segment"));
        }
    }
    let file = parts[parts.len() - 1];
    let file = file.strip_suffix(METADATA_SUFFIX).unwrap_or(file);
    if !DIST_SUFFIXES.iter().any(|suffix| file.ends_with(suffix)) {
        return Err(format!("{file:?} is not a distribution file"));
    }
    Ok(())
}

/// A configured Python registry's simple API (PEP 503 and 691), as a
/// route of its own. Its grammar
/// decides metadata only: `<url><project>/` is a project page, read for
/// claims exactly as PyPI's is. Every other URL the route owns is a file,
/// wherever the registry put it (Nexus links `../../packages/...`,
/// CodeArtifact pre-signed URLs), and is fetched only when this registry's
/// own pages claimed it with a digest.
pub struct ConfiguredSimple {
    id: String,
    base: String,
}

impl ConfiguredSimple {
    pub fn new(registry: &Registry) -> ConfiguredSimple {
        ConfiguredSimple {
            id: format!("{ROUTE_ID}-{}", registry.name),
            base: registry.url.clone(),
        }
    }

    /// Whether `url` is a project page (or the index root) of this registry.
    fn is_page(&self, url: &Url) -> bool {
        if url.query().is_some() || !covers::covers(&self.base, url.as_str()) {
            return false;
        }
        let base_path = Url::parse(&self.base).map(|base| base.path().to_string());
        let Ok(base_path) = base_path else {
            return false;
        };
        let Some(rest) = url.path().strip_prefix(&base_path) else {
            return false;
        };
        let name = rest.strip_suffix('/').unwrap_or(rest);
        name.is_empty() || check_name(name).is_ok()
    }
}

impl RegistryProtocol for ConfiguredSimple {
    fn route_id(&self) -> &str {
        &self.id
    }

    /// Reached only through interception, never as a mirror path.
    fn upstream(&self, _endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        Err(refused(
            path,
            "a configured registry is not served as a mirror",
        ))
    }

    fn classify(&self, url: &Url) -> RequestClass {
        if self.is_page(url) {
            RequestClass::Index
        } else {
            RequestClass::Artifact
        }
    }

    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)> {
        if !self.is_page(url) {
            return Vec::new();
        }
        page_claims(url, body, |_| true)
    }

    fn expects_claim(&self, _url: &Url) -> bool {
        true
    }

    /// A JSON project page's upload times, as on PyPI.
    fn published(&self, url: &Url, body: &[u8]) -> Vec<(String, String, i64)> {
        if !self.is_page(url) {
            return Vec::new();
        }
        page_times(body)
    }

    /// The project's JSON page under this registry's `url`.
    fn lookup(&self, _endpoints: &[Endpoint], name: &str, _version: &str) -> Option<Lookup> {
        let name = normalize_name(name);
        check_name(&name).ok()?;
        let url = Url::parse(&self.base)
            .ok()?
            .join(&format!("{name}/"))
            .ok()?;
        self.is_page(&url).then_some(Lookup {
            url,
            accept: "application/vnd.pypi.simple.v1+json",
        })
    }

    fn package_key(&self, name: &str, version: &str) -> (String, String) {
        package_key(name, version)
    }
}

/// Every file a project page at `url` lists that `keep` accepts, claimed
/// by its strongest hash, and its core metadata by the hash the page gives
/// for it. Relative links resolve against the page's URL.
fn page_claims(url: &Url, body: &[u8], keep: impl Fn(&Url) -> bool) -> Vec<(Url, Claim)> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    let files = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(page) => json_files(&page),
        Err(_) => html_files(text),
    };
    let mut claims = Vec::new();
    for file in files {
        let Ok(mut target) = url.join(&file.href) else {
            continue;
        };
        target.set_fragment(None);
        if !keep(&target) {
            continue;
        }
        if let Some(claim) = strongest(&file.hashes) {
            claims.push((target.clone(), claim));
        }
        if let Some(claim) = strongest(&file.metadata) {
            let mut metadata = target.clone();
            metadata.set_path(&format!("{}{METADATA_SUFFIX}", target.path()));
            claims.push((metadata, claim));
        }
    }
    claims
}

/// The files a simple API project page lists, as `(filename, url,
/// sha256)`, each link resolved against `page` (the URL that served it).
/// PEP 691 JSON or the PEP 503 HTML page, as the proxy reads them. A file
/// with no sha256 can never match a pin and is dropped.
pub(crate) fn simple_page_files(page: &Url, body: &[u8]) -> Vec<(String, String, String)> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    let files = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(json) => json_files(&json),
        Err(_) => html_files(text),
    };
    files
        .into_iter()
        .filter_map(|file| {
            let mut target = page.join(&file.href).ok()?;
            target.set_fragment(None);
            let filename = target.path_segments()?.next_back()?.to_string();
            let (_, sha256) = file.hashes.iter().find(|(algo, _)| algo == "sha256")?;
            Some((filename, target.to_string(), sha256.to_ascii_lowercase()))
        })
        .collect()
}

/// The PyPI route: the index and the file host.
pub fn route() -> io::Result<Route> {
    Route::new(
        &PYPI_REGISTRY,
        vec![Endpoint::https(INDEX_HOST)?, Endpoint::https(FILES_HOST)?],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple page's files resolve against the page that served them,
    /// in either format; a file with no sha256 is dropped.
    #[test]
    fn simple_page_files_resolve_links_in_both_formats() {
        let page = Url::parse("https://nexus.example/repo/pypi/simple/demo/").unwrap();
        let html = b"<a href=\"../../packages/demo-1.0.tar.gz#sha256=AB\">demo-1.0.tar.gz</a>\n\
                     <a href=\"https://cdn.example/demo-1.0-py3-none-any.whl#md5=00\">w</a>";
        assert_eq!(
            simple_page_files(&page, html),
            [(
                "demo-1.0.tar.gz".to_string(),
                "https://nexus.example/repo/pypi/packages/demo-1.0.tar.gz".to_string(),
                "ab".to_string()
            )]
        );
        let json = br#"{"files": [{"filename": "demo-1.0-py3-none-any.whl",
            "url": "/repo/pypi/packages/demo-1.0-py3-none-any.whl",
            "hashes": {"sha256": "cd"}}]}"#;
        assert_eq!(
            simple_page_files(&page, json),
            [(
                "demo-1.0-py3-none-any.whl".to_string(),
                "https://nexus.example/repo/pypi/packages/demo-1.0-py3-none-any.whl".to_string(),
                "cd".to_string()
            )]
        );
    }

    fn endpoints() -> Vec<Endpoint> {
        vec![
            Endpoint::https(INDEX_HOST).unwrap(),
            Endpoint::https(FILES_HOST).unwrap(),
        ]
    }

    fn fetch(path: &str) -> String {
        match PYPI_REGISTRY.upstream(&endpoints(), path).unwrap() {
            Upstream::Fetch(url) => url.to_string(),
            other => panic!("{path}: {other:?}"),
        }
    }

    const WHEEL: &str = "/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl";

    /// A JSON page's files carry `upload-time`; each version is read from
    /// its file name, a wheel's or an sdist's whose name holds `-`.
    #[test]
    fn publish_times_come_from_json_pages_and_file_names() {
        let body = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/proxy/registry/python/pypi.org/simple/six/_index.body"),
        )
        .unwrap();
        let url = Url::parse("https://pypi.org/simple/six/").unwrap();
        let times = PYPI_REGISTRY.published(&url, &body);
        assert!(times.contains(&("six".into(), "1.16.0".into(), 1_620_224_297)));
        assert!(times.contains(&("six".into(), "1.16.0".into(), 1_620_224_298)));
        assert!(times.contains(&("six".into(), "1.17.0".into(), 1_733_333_726)));
        let file =
            Url::parse("https://files.pythonhosted.org/packages/x/six-1.17.0.tar.gz").unwrap();
        assert!(PYPI_REGISTRY.published(&file, &body).is_empty());
        let html = b"<a href=\"https://files.pythonhosted.org/packages/a/six-1.0.tar.gz\">x</a>";
        assert!(PYPI_REGISTRY.published(&url, html).is_empty());
        assert_eq!(
            file_version("python-dateutil", "python-dateutil-2.8.2.tar.gz").as_deref(),
            Some("2.8.2")
        );
        assert_eq!(
            file_version(
                "Python_Dateutil",
                "python_dateutil-2.9.0.post0-py2.py3-none-any.whl"
            )
            .as_deref(),
            Some("2.9.0.post0")
        );
        assert_eq!(file_version("six", "other-1.0.tar.gz"), None);
        assert_eq!(file_version("six", "six-1.0-py2.7.egg"), None);
        let lookup = PYPI_REGISTRY
            .lookup(&endpoints(), "Python_Dateutil", "2.9.0")
            .unwrap();
        assert_eq!(
            lookup.url.as_str(),
            "https://pypi.org/simple/python-dateutil/"
        );
        assert_eq!(lookup.accept, "application/vnd.pypi.simple.v1+json");
        assert_eq!(
            PYPI_REGISTRY.package_key("Python_Dateutil", "2.9.0.POST0"),
            ("python-dateutil".to_string(), "2.9.post0".to_string())
        );
    }

    /// A lock and a page that spell one version differently meet at its
    /// PEP 440 normal form, epochs included, and so do their files.
    #[test]
    fn versions_and_files_compare_in_pep_440_normal_form() {
        let key = |version: &str| PYPI_REGISTRY.package_key("Demo", version).1;
        assert_eq!(key("1.0-1"), key("1.0.post1"));
        assert_eq!(key("1.0.POST1"), "1.post1");
        assert_eq!(key("1.0RC1"), "1rc1");
        assert_eq!(key("v2.0"), "2");
        assert_eq!(key("1!2.0"), "1!2");
        // A wheel name writes the epoch's `!` as `_`.
        assert_eq!(key("1_2.0"), "1!2");
        assert_ne!(key("1!2.0"), key("2.0"));
        assert_eq!(key("not a version"), "not a version");
        // PEP 440 pads releases with zeros: 1.0 is 1.0.0 is 1.
        assert_eq!(key("1.0"), key("1.0.0"));
        assert_eq!(key("1.0.0"), "1");
        assert_eq!(key("1!2.0.0rc1.post2+local.0"), "1!2rc1.post2+local.0");
        assert_eq!(key("0.0"), "0");
        assert_ne!(key("1.10"), key("1.1"));
        assert_eq!(key("1.10.0"), "1.10");
        assert_eq!(key("2.0.1"), "2.0.1");
        assert_eq!(key("2.0.0.dev3"), "2.dev3");
        assert_eq!(
            key(&file_key("1.0-1", "Demo-1.0-1-py3-none-any.whl")),
            key(&file_key("1.0.post1", "demo-1.0-1-py3-none-any.whl"))
        );
        assert_eq!(
            key(&file_key("1.0+cpu", "demo-1.0%2Bcpu-py3-none-any.whl")),
            key(&file_key("1.0+cpu", "demo-1.0+cpu-py3-none-any.whl"))
        );
        let page = br#"{"name": "demo", "files": [
            {"filename": "demo-1_2.0-py3-none-any.whl", "upload-time": "2024-02-12T23:43:59Z"}
        ]}"#;
        let url = Url::parse("https://pypi.org/simple/demo/").unwrap();
        let keys: Vec<(String, String)> = PYPI_REGISTRY
            .published(&url, page)
            .into_iter()
            .map(|(name, version, _)| PYPI_REGISTRY.package_key(&name, &version))
            .collect();
        assert_eq!(
            keys,
            [
                (
                    "demo".to_string(),
                    file_key("1!2", "demo-1_2.0-py3-none-any.whl")
                ),
                ("demo".to_string(), "1!2".to_string()),
            ]
        );
    }

    #[test]
    fn pages_and_files_map_onto_their_hosts() {
        for path in [
            "/simple/",
            "/simple/six/",
            "/simple/Zope.Interface",
            "/simple/a_b-c/",
        ] {
            assert_eq!(fetch(path), format!("https://{INDEX_HOST}{path}"));
        }
        for path in [
            WHEEL.to_string(),
            format!("{WHEEL}.metadata"),
            "/packages/source/s/six/six-1.16.0.tar.gz".to_string(),
            "/packages/ab/cd/ef/torch-2.1.0+cpu-cp312-cp312-linux_x86_64.whl".to_string(),
        ] {
            assert_eq!(fetch(&path), format!("https://{FILES_HOST}{path}"));
        }
        let page = Url::parse("https://pypi.org/simple/six/").unwrap();
        let wheel = Url::parse(&format!("https://{FILES_HOST}{WHEEL}")).unwrap();
        let metadata = Url::parse(&format!("https://{FILES_HOST}{WHEEL}.metadata")).unwrap();
        assert_eq!(PYPI_REGISTRY.classify(&page), RequestClass::Index);
        assert_eq!(PYPI_REGISTRY.classify(&wheel), RequestClass::Artifact);
        assert_eq!(PYPI_REGISTRY.classify(&metadata), RequestClass::Artifact);
        assert!(PYPI_REGISTRY.expects_claim(&wheel));
        assert!(PYPI_REGISTRY.expects_claim(&metadata));
        assert!(!PYPI_REGISTRY.expects_claim(&page));
    }

    #[test]
    fn the_pypi_grammar_refuses_everything_else() {
        for (path, needle) in [
            ("/simple/six/?format=json", "no query"),
            ("/pypi/six/json", "not a project page"),
            ("/simple/.hidden/", "not a project name"),
            ("/simple/a b/", "not a project name"),
            ("/simple/six/extra/", "not a project name"),
            ("/packages/six.whl", "/packages/<directories>/<file>"),
            ("/packages/aa/bb/six-1.0.txt", "not a distribution file"),
            ("/packages/aa/.git/six-1.0.whl", "not a file path segment"),
            (
                "/packages/a/b/c/d/e/f/six-1.0.whl",
                "/packages/<directories>/<file>",
            ),
            ("/", "not a project page"),
        ] {
            let error = PYPI_REGISTRY
                .upstream(&endpoints(), path)
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "{path}: {error}");
        }
    }

    /// The recorded `six` page claims the recorded wheel's sha256 and its
    /// core metadata's.
    #[test]
    fn a_json_page_claims_its_files_and_their_metadata() {
        use sha2::{Digest as _, Sha256};
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proxy/registry/python");
        let body = std::fs::read(fixtures.join("pypi.org/simple/six/_index.body")).unwrap();
        let page = Url::parse("https://pypi.org/simple/six/").unwrap();
        let claims = PYPI_REGISTRY.claims(&page, &body);
        let metadata_bytes = std::fs::read(
            fixtures.join(format!("{FILES_HOST}{WHEEL}.metadata.body").trim_start_matches('/')),
        )
        .unwrap();
        let metadata = Url::parse(&format!("https://{FILES_HOST}{WHEEL}.metadata")).unwrap();
        let (_, claim) = claims
            .iter()
            .find(|(url, _)| *url == metadata)
            .expect("the metadata is claimed");
        assert_eq!(claim.algo(), "sha256");
        assert_eq!(
            claim.digests()[0].hex(),
            hex::encode(Sha256::digest(&metadata_bytes))
        );
        let wheel = Url::parse(&format!("https://{FILES_HOST}{WHEEL}")).unwrap();
        assert!(claims.iter().any(|(url, _)| *url == wheel));
        assert!(claims.len() > 20, "every file is claimed");
        // Nothing but a project page on the index host claims anything.
        assert!(PYPI_REGISTRY.claims(&wheel, &body).is_empty());
        assert!(PYPI_REGISTRY
            .claims(
                &Url::parse("https://pypi.org/pypi/six/json").unwrap(),
                &body
            )
            .is_empty());
    }

    #[test]
    fn mismatched_wheel_metadata_hard_fails_and_never_poison_caches() {
        use crate::kernel::policy::Policy;
        use crate::kernel::resolve::session::Mode;
        use crate::kernel::resolve::testing::{
            get, stored_rows, Harness, Reach, TEST_ORIGIN_PUBLIC,
        };
        use crate::kernel::testutil::upstream::{Behavior, Reply};
        use sha2::{Digest as _, Sha256};
        let rows = stored_rows("python", "pypi-metadata-mismatch");
        let harness = Harness::serving(
            "pypi-metadata-mismatch",
            Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]),
            &[INDEX_HOST, FILES_HOST],
            &rows.0.to_string_lossy(),
        );
        let path = format!("{WHEEL}.metadata");
        let poisoned = b"Name: six\nVersion: 1.16.0\nRequires-Dist: injected\n";
        harness
            .upstream
            .set(&path, Behavior::Reply(Reply::new(200, poisoned)));
        let mut config = harness.config(Policy::default(), Mode::Online);
        config.routes = vec![route().unwrap()];
        let (session, address) = harness.open(config);
        let fetch = |path: &str| {
            get(
                &address,
                &format!(
                    "{}{}",
                    url::Url::parse(&address.route_base(ROUTE_ID))
                        .unwrap()
                        .path(),
                    path.trim_start_matches('/')
                ),
                "",
            )
        };
        assert_eq!(fetch("/simple/six/").status, 200);
        assert_eq!(fetch(&path).status, 502);
        let report = session.finish();
        assert!(!report.facts.hard_failures.is_empty());
        let poisoned_hash = hex::encode(Sha256::digest(poisoned));
        assert!(!harness
            .store
            .root
            .join("cache/sha256")
            .join(poisoned_hash)
            .exists());
        assert!(report
            .ledger
            .entries()
            .any(|entry| entry.status == 502 && !entry.verified));

        // A later session must fetch and verify the restored sidecar,
        // rather than serving a poisoned metadata-cache copy.
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proxy/registry/python");
        let good = std::fs::read(fixtures.join(format!("{FILES_HOST}{path}.body"))).unwrap();
        harness
            .upstream
            .set(&path, Behavior::Reply(Reply::new(200, &good)));
        let mut config = harness.config(Policy::default(), Mode::Online);
        config.routes = vec![route().unwrap()];
        let (session, address) = harness.open(config);
        let fetch = |path: &str| {
            get(
                &address,
                &format!(
                    "{}{}",
                    url::Url::parse(&address.route_base(ROUTE_ID))
                        .unwrap()
                        .path(),
                    path.trim_start_matches('/')
                ),
                "",
            )
        };
        assert_eq!(fetch("/simple/six/").status, 200);
        let response = fetch(&path);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, good);
        assert!(session
            .finish()
            .ledger
            .entries()
            .any(|entry| entry.verified));
    }

    #[test]
    fn an_html_page_claims_by_fragment_and_metadata_attribute() {
        let sha = "a".repeat(64);
        let meta = "b".repeat(64);
        let html = format!(
            "<!DOCTYPE html><html><body>\n\
             <a href=\"https://files.pythonhosted.org/packages/aa/bb/x-1.0-py3-none-any.whl#sha256={sha}\" \
             data-requires-python=\"&gt;=3.8\" data-core-metadata=\"sha256={meta}\">x-1.0-py3-none-any.whl</a><br/>\n\
             <A HREF='../../packages/cc/dd/x-1.0.tar.gz#md5=0123456789abcdef0123456789abcdef'>x-1.0.tar.gz</A>\n\
             <a href=\"https://elsewhere.test/packages/aa/bb/x-2.0.whl#sha256={sha}\">x-2.0.whl</a>\n\
             </body></html>"
        );
        let page = Url::parse("https://pypi.org/simple/x/").unwrap();
        let claims = PYPI_REGISTRY.claims(&page, html.as_bytes());
        let urls: Vec<String> = claims.iter().map(|(url, _)| url.to_string()).collect();
        assert_eq!(
            urls,
            [
                "https://files.pythonhosted.org/packages/aa/bb/x-1.0-py3-none-any.whl",
                "https://files.pythonhosted.org/packages/aa/bb/x-1.0-py3-none-any.whl.metadata",
            ],
            "the md5-only sdist is unclaimed (weak), the other host is not this route's"
        );
        assert_eq!(claims[0].1.digests()[0].hex(), sha);
        assert_eq!(claims[1].1.digests()[0].hex(), meta);
    }

    #[test]
    fn the_strongest_hash_wins_and_md5_claims_nothing() {
        let pairs = |list: &[(&str, &str)]| -> Vec<(String, String)> {
            list.iter()
                .map(|(a, h)| (a.to_string(), h.to_string()))
                .collect()
        };
        let sha256 = "c".repeat(64);
        let sha512 = "d".repeat(128);
        let claim = strongest(&pairs(&[("sha256", &sha256), ("sha512", &sha512)])).unwrap();
        assert_eq!(claim.algo(), "sha512");
        let claim = strongest(&pairs(&[("md5", "0"), ("sha256", &sha256.to_uppercase())])).unwrap();
        assert_eq!(claim.algo(), "sha256");
        assert!(strongest(&pairs(&[("md5", &"e".repeat(32))])).is_none());
        assert!(strongest(&pairs(&[("sha1", &"f".repeat(40))]))
            .unwrap()
            .is_weak());
    }

    /// A configured registry through interception, against an
    /// authenticated fixture.
    mod configured {
        use super::*;
        use crate::kernel::policy::{self, Policy, SourceOrigin};
        use crate::kernel::registries::config::Ecosystem;
        use crate::kernel::registries::route as registry_route;
        use crate::kernel::resolve::routes::Permitted;
        use crate::kernel::resolve::session::{Intercept, Mode, SessionReport};
        use crate::kernel::resolve::testing::{open_tunnel, tunnel_request, Harness, TlsTunnel};
        use crate::kernel::testutil::upstream::{Behavior, Reply};
        use sha2::{Digest as _, Sha256};
        use std::path::Path;
        use std::sync::Arc;

        const CORP_TOKEN: &str = "corp-token-0123456789abcdef";
        const TEAM_TOKEN: &str = "team-token-fedcba9876543210";

        fn sha(body: &[u8]) -> String {
            hex::encode(Sha256::digest(body))
        }

        fn token_file(dir: &Path, name: &str, value: &str) -> String {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.join(name);
            std::fs::write(&path, value).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path.display().to_string()
        }

        /// The machine policy: `corp` (root `/repo/pypi/`, files on
        /// other.test) and `team`, whose root nests inside corp's.
        fn machine(port: u16, corp_file: &str, team_file: &str) -> Policy {
            let text = format!(
                r#"
[credentials.corp]
file = "{corp_file}"

[credentials.team]
file = "{team_file}"

[[registry]]
name = "corp"
ecosystem = "python"
url = "https://registry.test:{port}/repo/pypi/simple/"
root = "https://registry.test:{port}/repo/pypi/"
credential = "corp"
files = ["https://other.test:{port}/"]

[[registry]]
name = "team"
ecosystem = "python"
url = "https://registry.test:{port}/repo/pypi/team/simple/"
root = "https://registry.test:{port}/repo/pypi/team/"
credential = "team"

[sources]
python = ["corp", "team"]
"#
            );
            let path = Path::new("/machine/policy.toml");
            let parsed = policy::parse_file(path, &text).unwrap();
            let mut merged = Policy::default();
            policy::merge_file(&mut merged, &parsed, SourceOrigin::Machine, path).unwrap();
            merged
        }

        fn session(
            harness: &Harness,
            policy: Policy,
        ) -> (
            crate::kernel::resolve::proxy::Session,
            crate::kernel::resolve::routes::ProxyAddress,
        ) {
            let sources = policy.registries.ecosystem(Ecosystem::Python);
            let mut routes = Vec::new();
            let mut permitted = Permitted::compiled();
            for registry in sources.registries() {
                routes.push(
                    registry_route::route(
                        Arc::new(ConfiguredSimple::new(registry)),
                        registry,
                        &policy.registries,
                    )
                    .unwrap(),
                );
                permitted = registry_route::permit(permitted, registry);
            }
            let mut config = harness.config(policy.clone(), Mode::Online);
            config.ecosystem = "python".into();
            config.intercept = Intercept::Tls;
            config.routes = routes;
            config.permitted = permitted;
            harness.open(config)
        }

        fn tunnel(
            harness: &Harness,
            address: &crate::kernel::resolve::routes::ProxyAddress,
            host: &str,
        ) -> (TlsTunnel, String) {
            let authority = format!("{host}:{}", harness.upstream.port());
            let roots = harness.proxy.authority().roots();
            (
                open_tunnel(address, &authority, host, roots, &[]).unwrap(),
                authority,
            )
        }

        fn get(tunnel: &mut TlsTunnel, authority: &str, path: &str) -> (u16, Vec<u8>) {
            let head = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\n");
            let response = tunnel_request(tunnel, &head, b"");
            (response.status, response.body)
        }

        fn bearer(token: &str) -> String {
            format!("Bearer {token}")
        }

        fn leaks(report: &SessionReport, token: &str) -> bool {
            format!("{:?}", report.ledger).contains(token)
                || format!("{:?}", report.facts).contains(token)
                || format!("{:?}", report.diagnostics).contains(token)
        }

        #[test]
        fn a_configured_registry_is_served_by_claim_with_its_credential_under_its_root_only() {
            let harness = Harness::new("configured-python");
            let port = harness.upstream.port();
            let temp = crate::kernel::testutil::TempDir::new();
            let corp_file = token_file(&temp.0, "corp", CORP_TOKEN);
            let team_file = token_file(&temp.0, "team", TEAM_TOKEN);
            let sdist = b"demo sdist bytes";
            let wheel = b"demo wheel bytes";
            let moved = b"redirected sdist bytes";
            let page = format!(
                "<html><body>\n\
                 <a href=\"../../packages/demo-1.0.tar.gz#sha256={}\">demo-1.0.tar.gz</a>\n\
                 <a href=\"https://other.test:{port}/blob/demo-1.0-py3-none-any.whl#sha256={}\">w</a>\n\
                 <a href=\"/repo/pypi/team/packages/stolen.tar.gz#sha256={}\">s</a>\n\
                 <a href=\"../../packages/moved.tar.gz#sha256={}\">m</a>\n\
                 <a href=\"../../packages/escape.tar.gz#sha256={}\">e</a>\n\
                 <a href=\"../../packages/nodigest.tar.gz\">n</a>\n\
                 </body></html>",
                sha(sdist),
                sha(wheel),
                sha(sdist),
                sha(moved),
                sha(b"escape bytes"),
            );
            let corp = |body: &[u8]| Behavior::Authorized {
                value: bearer(CORP_TOKEN),
                reply: Reply::new(200, body),
            };
            let up = &harness.upstream;
            up.set("/repo/pypi/simple/demo/", corp(page.as_bytes()));
            up.set("/repo/pypi/packages/demo-1.0.tar.gz", corp(sdist));
            up.set("/repo/pypi/packages/nodigest.tar.gz", corp(sdist));
            up.set(
                "/blob/demo-1.0-py3-none-any.whl",
                Behavior::Reply(Reply::new(200, wheel)),
            );
            up.set(
                "/repo/pypi/packages/moved.tar.gz",
                Behavior::Authorized {
                    value: bearer(CORP_TOKEN),
                    reply: Reply::new(302, b"").header(
                        "Location",
                        &format!("https://other.test:{port}/blob/moved.tar.gz"),
                    ),
                },
            );
            up.set(
                "/blob/moved.tar.gz",
                Behavior::Reply(Reply::new(200, moved)),
            );
            up.set(
                "/repo/pypi/packages/escape.tar.gz",
                Behavior::Authorized {
                    value: bearer(CORP_TOKEN),
                    reply: Reply::new(302, b"")
                        .header("Location", &format!("https://third.test:{port}/x.tar.gz")),
                },
            );
            up.set(
                "/repo/pypi/team/packages/stolen.tar.gz",
                Behavior::Reply(Reply::new(200, sdist)),
            );
            up.set(
                "/repo/pypi/team/simple/demo/",
                Behavior::Authorized {
                    value: bearer(TEAM_TOKEN),
                    reply: Reply::new(200, b"<html></html>"),
                },
            );
            up.set("/repo/other/x", Behavior::Reply(Reply::new(200, b"x")));
            up.set("/x", Behavior::Reply(Reply::new(200, b"x")));

            let (session, address) = session(&harness, machine(port, &corp_file, &team_file));
            let (mut index, authority) = tunnel(&harness, &address, "registry.test");
            assert_eq!(
                get(&mut index, &authority, "/repo/pypi/simple/demo/").0,
                200
            );
            assert_eq!(
                get(
                    &mut index,
                    &authority,
                    "/repo/pypi/packages/demo-1.0.tar.gz"
                ),
                (200, sdist.to_vec())
            );
            // A claimed file whose 302 leads to the registry's files origin:
            // served, and the credential stays behind.
            assert_eq!(
                get(&mut index, &authority, "/repo/pypi/packages/moved.tar.gz"),
                (200, moved.to_vec())
            );
            // A redirect anywhere else is refused.
            assert_eq!(
                get(&mut index, &authority, "/repo/pypi/packages/escape.tar.gz").0,
                403
            );
            // Nothing the registry's pages did not claim is fetched.
            assert_eq!(
                get(
                    &mut index,
                    &authority,
                    "/repo/pypi/packages/unlisted.tar.gz"
                )
                .0,
                403
            );
            assert_eq!(
                get(
                    &mut index,
                    &authority,
                    "/repo/pypi/packages/nodigest.tar.gz"
                )
                .0,
                403
            );
            // A URL under team's (longer) root is team's: corp's claim for it
            // does not count, and corp's credential is never sent there.
            assert_eq!(
                get(
                    &mut index,
                    &authority,
                    "/repo/pypi/team/packages/stolen.tar.gz"
                )
                .0,
                403
            );
            // Team's own pages get team's credential.
            assert_eq!(
                get(&mut index, &authority, "/repo/pypi/team/simple/demo/").0,
                200
            );
            // Another path on the same host is no registry's: refused hard.
            assert_eq!(get(&mut index, &authority, "/repo/other/x").0, 403);
            drop(index);
            let (mut files, files_authority) = tunnel(&harness, &address, "other.test");
            assert_eq!(
                get(
                    &mut files,
                    &files_authority,
                    "/blob/demo-1.0-py3-none-any.whl"
                ),
                (200, wheel.to_vec())
            );
            drop(files);
            let (mut third, third_authority) = tunnel(&harness, &address, "third.test");
            assert_eq!(get(&mut third, &third_authority, "/x").0, 403);
            drop(third);
            let report = session.finish();

            for unfetched in [
                "/repo/pypi/packages/unlisted.tar.gz",
                "/repo/pypi/packages/nodigest.tar.gz",
                "/repo/pypi/team/packages/stolen.tar.gz",
                "/repo/other/x",
                "/x",
            ] {
                assert_eq!(up.hits(unfetched), 0, "{unfetched} reached upstream");
            }
            for seen in up.seen() {
                let auth = seen.headers.get("authorization");
                let expected = match seen.target.as_str() {
                    t if t.starts_with("/repo/pypi/team/") => Some(bearer(TEAM_TOKEN)),
                    t if t.starts_with("/repo/pypi/") => Some(bearer(CORP_TOKEN)),
                    _ => None,
                };
                assert_eq!(auth, expected.as_deref(), "{} {:?}", seen.target, seen.sni);
            }
            // The two unlisted hosts or paths fail the door; nothing else does.
            assert_eq!(report.facts.hard_failures.len(), 2, "{:?}", report.facts);
            assert!(report
                .facts
                .hard_failures
                .iter()
                .all(|failure| failure.contains("fix:") && failure.contains("[corp, team]")));
            assert!(report.facts.exceptions.is_empty(), "{:?}", report.facts);
            assert!(!leaks(&report, CORP_TOKEN) && !leaks(&report, TEAM_TOKEN));
        }

        #[test]
        fn an_unreadable_credential_is_a_hard_failure_and_sends_nothing() {
            let harness = Harness::new("configured-python-nocred");
            let port = harness.upstream.port();
            let temp = crate::kernel::testutil::TempDir::new();
            let missing = temp.0.join("missing-token").display().to_string();
            harness.upstream.set(
                "/repo/pypi/simple/demo/",
                Behavior::Reply(Reply::new(200, b"<html></html>")),
            );
            let (session, address) = session(&harness, machine(port, &missing, &missing));
            let (mut index, authority) = tunnel(&harness, &address, "registry.test");
            assert_eq!(
                get(&mut index, &authority, "/repo/pypi/simple/demo/").0,
                502
            );
            drop(index);
            let report = session.finish();
            assert_eq!(harness.upstream.hits("/repo/pypi/simple/demo/"), 0);
            assert_eq!(report.facts.hard_failures.len(), 1, "{:?}", report.facts);
            assert!(
                report.facts.hard_failures[0].contains("credential corp"),
                "{:?}",
                report.facts
            );
        }

        #[test]
        fn the_page_grammar_is_relative_to_the_registry_url() {
            let registry = machine(8443, "/t", "/t");
            let corp = registry.registries.registry("corp").unwrap();
            let protocol = ConfiguredSimple::new(corp);
            let base = "https://registry.test:8443/repo/pypi/simple/";
            for (path, class) in [
                ("demo/", RequestClass::Index),
                ("Demo.Name_x/", RequestClass::Index),
                ("", RequestClass::Index),
                ("demo/demo-1.0.tar.gz", RequestClass::Artifact),
                ("../packages/demo-1.0.tar.gz", RequestClass::Artifact),
            ] {
                let url = Url::parse(&format!("{base}{path}")).unwrap();
                assert_eq!(protocol.classify(&url), class, "{path}");
            }
            assert_eq!(protocol.route_id(), "pypi-corp");
        }

        /// A configured index's JSON pages give upload times as PyPI's do,
        /// and its publish-time lookup is the project page under its URL.
        #[test]
        fn a_configured_index_reads_upload_times_under_its_url() {
            let registry = machine(8443, "/t", "/t");
            let protocol = ConfiguredSimple::new(registry.registries.registry("corp").unwrap());
            let page = br#"{"name": "demo", "files": [
                {"filename": "demo-1.0-py3-none-any.whl", "url": "../../packages/demo-1.0-py3-none-any.whl",
                 "hashes": {}, "upload-time": "2020-01-02T03:04:05.000000Z"}]}"#;
            let at = parse_rfc3339("2020-01-02T03:04:05Z").unwrap();
            let url = |raw: &str| Url::parse(raw).unwrap();
            assert_eq!(
                protocol.published(
                    &url("https://registry.test:8443/repo/pypi/simple/demo/"),
                    page
                ),
                [
                    (
                        "demo".into(),
                        file_key("1.0", "demo-1.0-py3-none-any.whl"),
                        at
                    ),
                    ("demo".into(), "1.0".into(), at),
                ]
            );
            // A body outside the registry's pages times nothing.
            assert!(protocol
                .published(
                    &url("https://registry.test:8443/repo/pypi/team/simple/demo/"),
                    page
                )
                .is_empty());
            let lookup = protocol.lookup(&[], "Demo_Name", "1.0").unwrap();
            assert_eq!(
                lookup.url.as_str(),
                "https://registry.test:8443/repo/pypi/simple/demo-name/"
            );
            assert_eq!(lookup.accept, "application/vnd.pypi.simple.v1+json");
            assert_eq!(
                protocol.package_key("Demo_Name", "1.0.0"),
                PYPI_REGISTRY.package_key("Demo_Name", "1.0.0")
            );
        }
    }
}
