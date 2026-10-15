//! Where the proxy may forward, and how a registry-mirror path maps to an
//! upstream URL.
//!
//! The kernel never names an ecosystem. Each ecosystem's registry protocol
//! implements [`RegistryProtocol`] in its tailor folder; a door hands the
//! proxy [`Route`]s pairing a protocol with the [`Endpoint`]s it may reach.
//! The kernel checks everything the protocol returns: the upstream origin
//! must be one of the route's endpoints, every endpoint must be in the
//! permitted set, and the request path must parse in the route grammar
//! before the protocol ever sees it.

use super::clients::ClientSpec;
use crate::kernel::fetch::Digest;
use crate::kernel::registries::covers;
use crate::kernel::registries::credential::{Credential, Secret};
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use url::Url;

/// The upstream hosts the proxy may reach: the public registries ward
/// already fetches from, plus the GitHub hosts resolvers use for git
/// dependencies. A registry that lives elsewhere is refused until it is
/// configured as a permitted endpoint in machine policy.
pub const PERMITTED_HOSTS: &[&str] = &[
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "index.crates.io",
    "static.crates.io",
    "crates.io",
    "proxy.golang.org",
    "sum.golang.org",
    "rubygems.org",
    "index.rubygems.org",
    "repo.hex.pm",
    // Hex's HTTP API: ward reads a release's publish time there, since
    // the signed registry Hex resolves from carries none.
    "hex.pm",
    "api.nuget.org",
    "api.github.com",
    "raw.githubusercontent.com",
];

/// What kind of thing a request fetches. Metadata-like classes (index,
/// metadata, sumdb) are cached, revalidated, and may be served last-good;
/// an artifact is served only as verified bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestClass {
    /// A listing of what exists (Go's `@v/list`, a compact index).
    Index,
    /// A document describing packages (a packument, a `.mod`, a service
    /// index). Its digests feed claims.
    Metadata,
    /// Package bytes: a tarball, a wheel, a module zip.
    Artifact,
    /// A checksum-database answer the tool verifies itself.
    Sumdb,
    /// A git smart-HTTP exchange (or GitHub's commit lookup) inside an
    /// intercepted tunnel: streamed, never cached; the tool checks the
    /// objects it receives against the commit it locks.
    Git,
}

impl RequestClass {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestClass::Index => "index",
            RequestClass::Metadata => "metadata",
            RequestClass::Artifact => "artifact",
            RequestClass::Sumdb => "sumdb",
            RequestClass::Git => "git",
        }
    }

    /// Cached in the metadata cache and eligible for last-good.
    pub fn is_metadata(self) -> bool {
        !matches!(self, RequestClass::Artifact | RequestClass::Git)
    }
}

/// The digests a registry published for an artifact URL, read from
/// metadata the proxy served. The bytes of that URL must hash to one of
/// them. Usually one: an npm `integrity` list may name several of its
/// strongest algorithm, and any of them admits the bytes. Never empty,
/// all of one algorithm, sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim(Vec<Digest>);

impl Claim {
    /// A claim of exactly one digest.
    pub fn one(digest: Digest) -> Claim {
        Claim(vec![digest])
    }

    /// A claim allowing any of `digests`, or `None` when they are empty or
    /// mix algorithms.
    pub fn any(mut digests: Vec<Digest>) -> Option<Claim> {
        let first = digests.first()?.algo();
        if digests.iter().any(|digest| digest.algo() != first) {
            return None;
        }
        digests.sort();
        digests.dedup();
        Some(Claim(digests))
    }

    /// Every digest the bytes may match.
    pub fn digests(&self) -> &[Digest] {
        &self.0
    }

    /// The claim's algorithm.
    pub fn algo(&self) -> &'static str {
        self.0[0].algo()
    }

    /// `sha512:<hex>` (several joined by `|`): how the ledger writes a claim.
    pub fn describe(&self) -> String {
        crate::kernel::digest::describe_candidates(&self.0)
    }

    /// A SHA-1 claim pins nothing collision-resistant: `weak-integrity`.
    pub fn is_weak(&self) -> bool {
        self.algo() == "sha1"
    }
}

/// Hosts (with port) the proxy may reach, for route endpoints and every
/// redirect hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permitted {
    origins: BTreeSet<(String, u16)>,
}

impl Permitted {
    /// The compiled-in set, all on 443.
    pub fn compiled() -> Self {
        Self {
            origins: PERMITTED_HOSTS
                .iter()
                .map(|host| (host.to_string(), 443))
                .collect(),
        }
    }

    /// Whether `url` is an https URL on a permitted host and port, with no
    /// userinfo.
    pub fn allows(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && match (url.host_str(), url.port_or_known_default()) {
                (Some(host), Some(port)) => self.origins.contains(&(host.to_string(), port)),
                _ => false,
            }
    }

    /// Exactly one origin: where an intercepted request to a host outside
    /// every route (a git host, an unattested registry) may be redirected,
    /// which is nowhere but itself.
    pub(crate) fn only(host: &str, port: u16) -> Self {
        Self {
            origins: BTreeSet::from([(host.to_string(), port)]),
        }
    }

    /// The set with one more origin: a configured registry's (from
    /// machine policy), or in tests a fixture host on its ephemeral port.
    pub fn with_origin(mut self, host: &str, port: u16) -> Self {
        self.origins.insert((host.to_string(), port));
        self
    }
}

/// One upstream origin a route may reach, and the credential ward attaches
/// to requests for that origin. A credential never follows a redirect to
/// another origin, and the tool never sees it.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
    authorization: Option<Authorization>,
    /// A configured registry's endpoint: its client settings.
    client: Option<ClientSpec>,
}

/// The credential an endpoint attaches.
#[derive(Clone, PartialEq, Eq)]
enum Authorization {
    /// Tests only: a fixed value for the whole origin.
    #[cfg(test)]
    Fixed(String),
    /// A configured registry's credential, read on first use and sent only
    /// to URLs under `root` (`covers`).
    Registry {
        root: String,
        credential: Arc<Credential>,
    },
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("authorization", &self.authorization.as_ref().map(|_| "…"))
            .field("client", &self.client)
            .finish()
    }
}

impl Endpoint {
    /// `https://<host>/`, which must be a compiled-in permitted host.
    pub fn https(host: &str) -> io::Result<Endpoint> {
        let host = host.to_ascii_lowercase();
        if !PERMITTED_HOSTS.contains(&host.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{host} is not a permitted resolution endpoint"),
            ));
        }
        Ok(Endpoint {
            host,
            port: 443,
            authorization: None,
            client: None,
        })
    }

    /// A configured registry's origin (its `url` origin, or one of its
    /// `files` origins), outside the compiled set: the permitted set of a
    /// session that routes it must name it. `root` and `credential`, when
    /// given, attach the credential to URLs under the root only.
    pub fn configured(
        origin: &str,
        credential: Option<(String, Arc<Credential>)>,
        client: ClientSpec,
    ) -> io::Result<Endpoint> {
        let url = Url::parse(origin).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{origin}: {error}"))
        })?;
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{origin} has no host"),
            ));
        };
        if url.scheme() != "https" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{origin} is not https"),
            ));
        }
        Ok(Endpoint {
            host: host.to_ascii_lowercase(),
            port,
            authorization: credential
                .map(|(root, credential)| Authorization::Registry { root, credential }),
            client: Some(client),
        })
    }

    /// The host an intercepted tunnel was opened to, when no route serves
    /// it: a git host (any public https host may serve git) or an
    /// unattested registry. It carries no credential, and it never enters a
    /// session's routes, so the permitted set is not asked.
    pub(crate) fn intercepted(host: &str, port: u16) -> Endpoint {
        Endpoint {
            host: host.to_ascii_lowercase(),
            port,
            authorization: None,
            client: None,
        }
    }

    /// Tests only: a fixture host on any port, outside the compiled set. A
    /// session still refuses it unless its permitted set names it.
    #[cfg(test)]
    pub(crate) fn for_test(host: &str, port: u16) -> Endpoint {
        Endpoint {
            host: host.to_string(),
            port,
            authorization: None,
            client: None,
        }
    }

    #[cfg(test)]
    /// Attach an `Authorization` value to requests for this origin only.
    /// The value must be a valid header value (visible ASCII, space, and
    /// tab): the error names neither the value nor the bad byte, and a
    /// value never reaches a client that would echo it back.
    pub fn with_authorization(mut self, value: &str) -> io::Result<Endpoint> {
        if value.trim().is_empty() || !super::http::is_field_value(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the credential for {} is not a valid header value",
                    self.origin()
                ),
            ));
        }
        self.authorization = Some(Authorization::Fixed(value.to_string()));
        Ok(self)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// `https://host[:port]`.
    pub fn origin(&self) -> String {
        // An IPv6 literal (only an intercepted tunnel's host can be one)
        // takes brackets in a URL.
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{}", self.port)
        }
    }

    /// The URL of `path` (starting with `/`, query allowed) on this origin.
    pub fn url(&self, path: &str) -> io::Result<Url> {
        Url::parse(&format!("{}{path}", self.origin())).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}{path}: {error}", self.origin()),
            )
        })
    }

    /// Whether `url` is on this endpoint's origin.
    pub fn serves(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.host_str() == Some(self.host.as_str())
            && url.port_or_known_default() == Some(self.port)
    }

    /// The `Authorization` value for a request to `raw` (the URL as it
    /// will be sent), read on first use: `None` when this endpoint sends no
    /// credential there, an error when the credential cannot be read.
    pub(crate) fn authorization(&self, raw: &str) -> Result<Option<Secret>, String> {
        match &self.authorization {
            None => Ok(None),
            #[cfg(test)]
            Some(Authorization::Fixed(value)) => Ok(Some(Secret::fixed(value))),
            Some(Authorization::Registry { root, credential }) => {
                if !covers::covers(root, raw) {
                    return Ok(None);
                }
                credential.authorization().map(Some)
            }
        }
    }

    /// The identity of this endpoint's credential for cache keys: never the
    /// value, and never a read of it.
    fn credential_reference(&self) -> Option<String> {
        match self.authorization.as_ref()? {
            #[cfg(test)]
            Authorization::Fixed(value) => Some(format!("fixed|{value}")),
            Authorization::Registry { root, credential } => {
                Some(format!("{root}|{}", credential.reference()))
            }
        }
    }

    /// The client settings of a configured registry's endpoint; `None`
    /// takes the public client.
    pub(crate) fn client(&self) -> Option<&ClientSpec> {
        self.client.as_ref()
    }

    pub(crate) fn permitted_by(&self, permitted: &Permitted) -> bool {
        permitted.origins.contains(&(self.host.clone(), self.port))
    }
}

/// Where the tool reaches this session's proxy, as the tool sees it. Inside
/// a sandbox that is the relay's fixed address, not the host listener's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAddress {
    pub address: SocketAddr,
    token: String,
}

impl ProxyAddress {
    pub(crate) fn new(address: SocketAddr, token: &str) -> Self {
        Self {
            address,
            token: token.to_string(),
        }
    }

    /// The forward-proxy URL with the session token as credentials:
    /// `http://ward:<token>@<address>`.
    pub fn proxy_url(&self) -> String {
        format!("http://ward:{}@{}", self.token, self.address)
    }

    /// The registry-mirror base of one route:
    /// `http://<address>/<token>/<route>/`.
    pub fn route_base(&self, route_id: &str) -> String {
        format!("http://{}/{}/{route_id}/", self.address, self.token)
    }

    #[cfg(test)]
    /// The session token, for the output checks that make sure it never
    /// reaches a published file.
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// What a mirror path maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// Fetch this URL, which must be on one of the route's endpoints.
    Fetch(Url),
    /// Answer from the proxy itself, without contacting upstream. The URL
    /// is what the ledger records the answer as, and is held to the same
    /// origin rule as a fetch.
    Local(LocalAnswer),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAnswer {
    pub url: Url,
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// One registry's protocol, implemented in its tailor folder. Every method
/// is pure: no I/O, no network.
pub trait RegistryProtocol: Send + Sync {
    /// The route segment in mirror URLs (`/<token>/<route_id>/...`):
    /// lowercase letters, digits, and `-`.
    fn route_id(&self) -> &str;

    /// Map a mirror path (starting with `/`, query included) to where it
    /// is served from. `endpoints` are the route's; the answer's origin must
    /// be one of them. The kernel has already refused `..`, encoded `/`,
    /// and absolute URLs in `path`; a protocol refuses whatever else its
    /// grammar does not allow, with an `InvalidInput` error.
    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream>;

    /// What `url` fetches.
    fn classify(&self, url: &Url) -> RequestClass;

    /// The artifact digests the metadata `body`, fetched from `url`,
    /// promises.
    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)>;

    /// Whether this protocol publishes a claim for every artifact like
    /// `url`, so an unclaimed one is `weak-integrity`.
    fn expects_claim(&self, _url: &Url) -> bool {
        false
    }

    /// The largest request body this route reads, checked only after the
    /// token, route, and method were admitted from the head. Registry
    /// reads send none; a route that needs one (git `upload-pack`) raises
    /// it deliberately.
    fn request_body_cap(&self) -> u64 {
        0
    }

    /// Query keys that identify content, kept by redaction; every other
    /// query value is recorded as `REDACTED`.
    fn content_query_keys(&self) -> &'static [&'static str] {
        &[]
    }

    /// Rewrite a metadata body before it is served (absolute URLs that
    /// must point back at the proxy). The ledger always records the
    /// upstream bytes, never the rewritten ones.
    fn rewrite(&self, _url: &Url, body: Vec<u8>, _base: &ProxyAddress) -> io::Result<Vec<u8>> {
        Ok(body)
    }

    /// Whether a percent-encoded `/` (`%2f`) may appear inside a path
    /// segment of this protocol. npm spells a scoped package's packument
    /// `/@scope%2fname`, so its route says yes. The kernel still refuses
    /// `.` and `..` on either side of the encoded slash, an encoded `\` or
    /// NUL, and every double encoding; the protocol's own grammar decides
    /// where the encoded slash may stand.
    fn encoded_slash(&self) -> bool {
        false
    }

    /// Whether a redirect from `from` (a URL on one of the route's
    /// endpoints) to `to`, an origin the session's permitted set does not
    /// name, is followed anyway: a registry that hands its downloads to a
    /// storage host of its own (proxy.golang.org's module zips on
    /// storage.googleapis.com). Say yes only for requests whose bytes the
    /// tool checks against digests it got elsewhere (Go: zips only), so
    /// the storage host is trusted with nothing. The kernel asks only for a
    /// hop straight off a route endpoint, refuses any redirect after the
    /// handoff, and still requires https without userinfo, the validating
    /// resolver, and no credential across origins. The tool's allowlisted
    /// headers, and a request body across a 307 or 308, do follow the hop.
    fn follows_redirect(&self, _from: &Url, _to: &Url) -> bool {
        false
    }

    /// When each package version the metadata `body`, fetched from `url`,
    /// describes was published: `(name, version, unix seconds)`, as the
    /// registry spells them ([`Self::package_key`] compares them). A body
    /// that names no times gives none. Feeds `young-package`.
    fn published(&self, _url: &Url, _body: &[u8]) -> Vec<(String, String, i64)> {
        Vec::new()
    }

    /// Where ward itself reads the publish time of `name` at `version`
    /// when the tool's own traffic did not carry it: a URL on one of
    /// `endpoints` whose body [`Self::published`] reads, and the `Accept`
    /// to send. `None`: this protocol has no such document.
    fn lookup(&self, _endpoints: &[Endpoint], _name: &str, _version: &str) -> Option<Lookup> {
        None
    }

    /// The form under which two spellings of one package version compare
    /// equal (PyPI's normalized names, NuGet's lowercase ids and
    /// versions). The lock's spelling and the metadata's meet here.
    fn package_key(&self, name: &str, version: &str) -> (String, String) {
        (name.to_string(), version.to_string())
    }

    /// The append-only log this protocol's ages are judged by, when its
    /// registry records no upload time ward can trust (Go's checksum
    /// database). The values [`Self::published`] returns are then record
    /// numbers in that log, not times, and a version passes when its
    /// record is below a checkpoint old enough ([`super::tlog`]).
    fn log(&self) -> Option<super::tlog::Log> {
        None
    }

    /// The tree the signed head in `body`, fetched from `url`, names,
    /// once its signature verifies against the log's key. `None`: the body
    /// carries no head. An error (a bad signature, a malformed head) refuses
    /// the body. Each verified head is a checkpoint.
    fn tree_size(&self, _url: &Url, _body: &[u8]) -> Option<Result<super::tlog::Head, String>> {
        None
    }
}

/// The publish-time key of one file of a version (`young-package` reads
/// a version's files when the lock names them): the version and the file
/// name, joined by a space, which no version spelling holds.
pub fn file_key(version: &str, file: &str) -> String {
    format!("{version} {file}")
}

/// A publish-time document ward fetches itself ([`RegistryProtocol::lookup`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub url: Url,
    /// The `Accept` header the document is asked for with.
    pub accept: &'static str,
}

/// A mirror route: a protocol and the endpoints it may reach.
#[derive(Clone)]
pub struct Route {
    pub protocol: Arc<dyn RegistryProtocol>,
    pub endpoints: Vec<Endpoint>,
    /// A configured registry's route: the URLs it owns.
    scope: Option<RouteScope>,
}

/// The URLs a configured registry's route owns: those under its root, and
/// those on its own `files` origins. Every check that asks which registry
/// a URL belongs to asks [`covers`] against these, on the raw spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteScope {
    /// The registry's name, for error text.
    pub registry: String,
    /// The registry's `url`, normalized.
    pub url: String,
    pub root: String,
    /// `https://host[:port]/` download-only origins.
    pub files: Vec<String>,
}

impl RouteScope {
    /// Whether `raw` is under the root.
    pub fn under_root(&self, raw: &str) -> bool {
        covers::covers(&self.root, raw)
    }

    /// Whether `raw` is on one of the `files` origins.
    pub fn on_files(&self, raw: &str) -> bool {
        self.files.iter().any(|files| covers::covers(files, raw))
    }

    /// Whether the route owns `raw`: under its root or on its `files`.
    pub fn owns(&self, raw: &str) -> bool {
        self.under_root(raw) || self.on_files(raw)
    }
}

/// The route that serves `raw` (a URL as the tool or a redirect spelled
/// it): the configured route with the longest root that covers it, else a
/// configured route whose `files` origin covers it, else a public route on
/// its origin. A URL on a configured registry's host but outside every root
/// is no configured route's.
pub fn route_for<'a>(routes: &'a [Route], raw: &str) -> Option<&'a Route> {
    let configured = routes
        .iter()
        .filter_map(|route| {
            let scope = route.scope.as_ref()?;
            scope
                .under_root(raw)
                .then(|| (covers::root_len(&scope.root), route))
        })
        // The longest root wins; on a tie the earlier route does, as in
        // ward's own fetches.
        .fold(None::<(usize, &Route)>, |best, (len, route)| match best {
            Some((best_len, _)) if best_len >= len => best,
            _ => Some((len, route)),
        })
        .map(|(_, route)| route);
    if configured.is_some() {
        return configured;
    }
    if let Some(route) = routes.iter().find(|route| {
        route
            .scope
            .as_ref()
            .is_some_and(|scope| scope.on_files(raw))
    }) {
        return Some(route);
    }
    let url = Url::parse(raw).ok()?;
    routes.iter().find(|route| {
        route.scope.is_none() && route.endpoints.iter().any(|endpoint| endpoint.serves(&url))
    })
}

/// A compiled-in protocol, shared as an instance.
struct Fixed(&'static dyn RegistryProtocol);

impl RegistryProtocol for Fixed {
    fn route_id(&self) -> &str {
        self.0.route_id()
    }
    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        self.0.upstream(endpoints, path)
    }
    fn classify(&self, url: &Url) -> RequestClass {
        self.0.classify(url)
    }
    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)> {
        self.0.claims(url, body)
    }
    fn expects_claim(&self, url: &Url) -> bool {
        self.0.expects_claim(url)
    }
    fn request_body_cap(&self) -> u64 {
        self.0.request_body_cap()
    }
    fn content_query_keys(&self) -> &'static [&'static str] {
        self.0.content_query_keys()
    }
    fn rewrite(&self, url: &Url, body: Vec<u8>, base: &ProxyAddress) -> io::Result<Vec<u8>> {
        self.0.rewrite(url, body, base)
    }
    fn encoded_slash(&self) -> bool {
        self.0.encoded_slash()
    }
    fn follows_redirect(&self, from: &Url, to: &Url) -> bool {
        self.0.follows_redirect(from, to)
    }
    fn published(&self, url: &Url, body: &[u8]) -> Vec<(String, String, i64)> {
        self.0.published(url, body)
    }
    fn lookup(&self, endpoints: &[Endpoint], name: &str, version: &str) -> Option<Lookup> {
        self.0.lookup(endpoints, name, version)
    }
    fn package_key(&self, name: &str, version: &str) -> (String, String) {
        self.0.package_key(name, version)
    }
    fn log(&self) -> Option<super::tlog::Log> {
        self.0.log()
    }
    fn tree_size(&self, url: &Url, body: &[u8]) -> Option<Result<super::tlog::Head, String>> {
        self.0.tree_size(url, body)
    }
}

impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Route")
            .field("route_id", &self.protocol.route_id())
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

impl Route {
    /// A route of a compiled-in protocol.
    pub fn new(
        protocol: &'static dyn RegistryProtocol,
        endpoints: Vec<Endpoint>,
    ) -> io::Result<Route> {
        Route::instance(Arc::new(Fixed(protocol)), endpoints)
    }

    /// A route of a protocol instance (a configured registry's).
    pub fn instance(
        protocol: Arc<dyn RegistryProtocol>,
        endpoints: Vec<Endpoint>,
    ) -> io::Result<Route> {
        let id = protocol.route_id();
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("route id {id:?} must be lowercase letters, digits, and -"),
            ));
        }
        if endpoints.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("route {id} has no endpoint"),
            ));
        }
        Ok(Route {
            protocol,
            endpoints,
            scope: None,
        })
    }

    /// A configured registry's route: `endpoints` must include the root's
    /// origin and every `files` origin, and nothing else.
    pub fn configured(
        protocol: Arc<dyn RegistryProtocol>,
        scope: RouteScope,
        endpoints: Vec<Endpoint>,
    ) -> io::Result<Route> {
        let mut route = Route::instance(protocol, endpoints)?;
        let origins: BTreeSet<String> = route.endpoints.iter().map(Endpoint::origin).collect();
        let mut wanted = BTreeSet::from([origin_of(&scope.root)]);
        wanted.extend(scope.files.iter().map(|files| origin_of(files)));
        if origins != wanted {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "route {} for registry {} has endpoints {origins:?}, not its root and files origins {wanted:?}",
                    route.protocol.route_id(),
                    scope.registry
                ),
            ));
        }
        route.scope = Some(scope);
        Ok(route)
    }

    /// The configured registry this route serves, if any.
    pub fn scope(&self) -> Option<&RouteScope> {
        self.scope.as_ref()
    }

    /// The scope claims are learned and looked up in: a configured route's
    /// claims are its own, so one registry's metadata never admits a URL
    /// for another; the public routes share one scope, as before.
    pub(crate) fn claim_scope(&self) -> &str {
        match &self.scope {
            Some(_) => self.protocol.route_id(),
            None => "",
        }
    }

    /// Where `path` goes, after the kernel's grammar check and the origin
    /// check on the protocol's answer.
    pub fn resolve(&self, path: &str) -> Result<Upstream, String> {
        check_route_path_with(path, self.protocol.encoded_slash())?;
        let upstream = self
            .protocol
            .upstream(&self.endpoints, path)
            .map_err(|error| scrub_echo(&error.to_string(), path, &*self.protocol))?;
        let url = match &upstream {
            Upstream::Fetch(url) => url,
            Upstream::Local(answer) => &answer.url,
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(format!(
                "route {} produced a URL with userinfo",
                self.protocol.route_id()
            ));
        }
        if !self.endpoints.iter().any(|endpoint| endpoint.serves(url)) {
            return Err(format!(
                "route {} mapped the path to {}, which is not one of its endpoints",
                self.protocol.route_id(),
                url.origin().ascii_serialization()
            ));
        }
        Ok(upstream)
    }

    /// The identity of this route's endpoint credentials: empty when no
    /// endpoint carries one, otherwise a sha256 over every (origin,
    /// credential) pair. Caches keyed by URL include it, so a response
    /// fetched with a credential is only ever served under the same
    /// credentials. The value itself never leaves this hash.
    pub(crate) fn credential_identity(&self) -> String {
        use sha2::{Digest as _, Sha256};
        let mut pairs: Vec<(String, String)> = self
            .endpoints
            .iter()
            .filter_map(|endpoint| {
                let credential = endpoint.credential_reference();
                let client = endpoint.client().map(|client| {
                    // The trust roots by content, so a replaced file is a
                    // different configuration; an unreadable one fails the
                    // request itself, so its path stands in here.
                    let ca = client.ca.as_ref().map(|path| {
                        super::clients::ca_file(path)
                            .map(|ca| hex::encode(ca.digest))
                            .unwrap_or_else(|_| path.display().to_string())
                    });
                    format!("{}|{}", client.network.as_str(), ca.unwrap_or_default())
                });
                if credential.is_none() && client.is_none() {
                    return None;
                }
                let identity = format!(
                    "{}|{}",
                    credential.unwrap_or_default(),
                    client.unwrap_or_default()
                );
                Some((endpoint.origin(), identity))
            })
            .collect();
        if pairs.is_empty() {
            return String::new();
        }
        pairs.sort();
        let mut hasher = Sha256::new();
        for (origin, credential) in pairs {
            hasher.update(origin.as_bytes());
            hasher.update([0u8]);
            hasher.update(credential.as_bytes());
            hasher.update([0u8]);
        }
        hex::encode(hasher.finalize())
    }

    /// The endpoint serving `url`, for its credential.
    pub(crate) fn endpoint_for(&self, url: &Url) -> Option<&Endpoint> {
        self.endpoints.iter().find(|endpoint| endpoint.serves(url))
    }
}

/// `https://host[:port]` of a normalized URL, as [`Endpoint::origin`]
/// spells it.
fn origin_of(url: &str) -> String {
    crate::kernel::registries::config::origin_of(url).to_string()
}

/// A protocol's error text with any echo of the raw mirror path (or its
/// query) replaced by the redacted form, since the query may hold a secret.
fn scrub_echo(text: &str, path: &str, protocol: &dyn RegistryProtocol) -> String {
    let keys = protocol.content_query_keys();
    let mut text = text.replace(path, &super::redact::url(path, keys));
    if let Some((_, query)) = path.split_once('?') {
        let redacted = super::redact::url(&format!("?{query}"), keys);
        text = text.replace(query, &redacted[1..]);
    }
    super::redact::text(&text)
}

/// The grammar every mirror path must satisfy before a protocol sees it:
/// an absolute path, no empty, `.`, or `..` segment (percent-encoded or
/// not), no percent-encoded `/`, `\`, or NUL, no backslash, and no URL
/// inside it. The query is not restricted beyond well-formed escapes.
///
/// `encoded_slash` is set for a protocol that accepts a percent-encoded `/`
/// inside a segment ([`RegistryProtocol::encoded_slash`]): the encoded
/// slash then counts as a segment boundary for the `.`, `..`, and empty
/// segment rules, so `/@s%2f..` is refused like `/@s/..`.
pub fn check_route_path_with(path_and_query: &str, encoded_slash: bool) -> Result<(), String> {
    // The path is not echoed (its query may hold a secret); the caller
    // names the request with its redacted URL.
    let refuse = |why: &str| Err(format!("mirror path refused: {why}"));
    // A fragment never belongs in a request target; a `#` here is either
    // a confused client or an attempt to make two parsers disagree.
    if path_and_query.contains('#') {
        return refuse("a # (fragments are not sent to a server)");
    }
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    };
    if !path.starts_with('/') {
        return refuse("not an absolute path");
    }
    if path.contains('\\') {
        return refuse("a backslash");
    }
    if path.contains("://") {
        return refuse("an absolute URL inside the route");
    }
    for part in [Some(path), query].into_iter().flatten() {
        if !escapes_well_formed(part) {
            return refuse("a malformed percent-escape");
        }
    }
    let lower = path.to_ascii_lowercase();
    for encoded in ["%2f", "%5c", "%00"] {
        if lower.contains(encoded) && !(encoded == "%2f" && encoded_slash) {
            return refuse("a percent-encoded /, \\, or NUL");
        }
    }
    // `%25` is an encoded `%`. Followed by the escape of `.`, `/`, `\`,
    // NUL, or `%`, it decodes in two passes to a character the checks
    // above refuse, so a server that decodes twice would see it.
    for encoded in ["%252e", "%252f", "%255c", "%2500", "%2525"] {
        if lower.contains(encoded) {
            return refuse("a double percent-encoding");
        }
    }
    // With the encoded slash allowed, it bounds segments like a real one,
    // so an encoded `..` cannot hide behind it.
    let segmented = if encoded_slash {
        lower.replace("%2f", "/")
    } else {
        lower.clone()
    };
    let segments: Vec<&str> = segmented[1..].split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        if segment.is_empty() && !last {
            return refuse("an empty segment");
        }
        let decoded = segment.replace("%2e", ".");
        if decoded == "." || decoded == ".." {
            return refuse("a . or .. segment");
        }
    }
    Ok(())
}

/// Whether `requested` (a URL as the tool spelled it) and `mapped` (what a
/// route resolved its path to) name one resource: the same scheme, host
/// and port, no userinfo on either, the same path segments once each
/// segment is percent-decoded once, and the same query as sent. A route
/// may send a decoded spelling upstream (Go's `%21azure` goes as
/// `!azure`), so a byte-for-byte comparison would tell them apart. The
/// path is split before decoding, so an encoded `/` stays inside its
/// segment and never matches a real boundary. The fragment is ignored: it
/// is never sent.
pub fn same_resource(requested: &Url, mapped: &Url) -> bool {
    let plain = |url: &Url| url.username().is_empty() && url.password().is_none();
    requested.scheme() == mapped.scheme()
        && requested.host_str() == mapped.host_str()
        && requested.port_or_known_default() == mapped.port_or_known_default()
        && plain(requested)
        && plain(mapped)
        && requested.query() == mapped.query()
        && requested.path().split('/').count() == mapped.path().split('/').count()
        && requested
            .path()
            .split('/')
            .zip(mapped.path().split('/'))
            .all(|(left, right)| decode_once(left) == decode_once(right))
}

/// `%XX` escapes decoded once, to bytes; a malformed escape is kept as it
/// was.
fn decode_once(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |at: usize| bytes.get(at).and_then(|b| (*b as char).to_digit(16));
        if bytes[i] == b'%' {
            if let (Some(high), Some(low)) = (hex(i + 1), hex(i + 2)) {
                out.push((high * 16 + low) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn escapes_well_formed(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if !(bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

#[cfg(test)]
pub(crate) mod testing {
    //! A registry protocol for kernel tests, over the fixture registry in
    //! `tests/fixtures/proxy/registry/kernel/`. Mirror paths map one to one
    //! onto the first endpoint; `/meta/...` is metadata whose JSON body
    //! lists artifact claims, `/art/...` is an artifact, `/index/...` an
    //! index, `/sumdb/...` sumdb, and `/local/supported` is answered by the
    //! proxy itself.

    use super::*;

    pub struct TestProtocol;

    pub static TEST_PROTOCOL: TestProtocol = TestProtocol;

    impl RegistryProtocol for TestProtocol {
        fn route_id(&self) -> &'static str {
            "fixture"
        }

        fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
            if path.starts_with("/forbidden/") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the fixture grammar forbids /forbidden/",
                ));
            }
            if path == "/local/supported" {
                return Ok(Upstream::Local(LocalAnswer {
                    url: endpoints[0].url("/supported")?,
                    status: 200,
                    content_type: "text/plain".into(),
                    body: Vec::new(),
                }));
            }
            if let Some(rest) = path.strip_prefix("/elsewhere") {
                // A protocol bug the kernel must catch: an origin that is
                // not one of the route's endpoints.
                let url = Url::parse(&format!("https://not-an-endpoint.test{rest}")).unwrap();
                return Ok(Upstream::Fetch(url));
            }
            if let Some(rest) = path.strip_prefix("/second") {
                return Ok(Upstream::Fetch(endpoints[1].url(rest)?));
            }
            Ok(Upstream::Fetch(endpoints[0].url(path)?))
        }

        fn classify(&self, url: &Url) -> RequestClass {
            let path = url.path();
            if path.starts_with("/art/") {
                RequestClass::Artifact
            } else if path.starts_with("/index/") {
                RequestClass::Index
            } else if path.starts_with("/sumdb/") {
                RequestClass::Sumdb
            } else {
                RequestClass::Metadata
            }
        }

        /// A metadata body `{"claims": {"<url>": "<algo>:<hex>"}}`, each
        /// URL relative to the metadata's own (the fixture's port changes
        /// every run).
        fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)> {
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
                return Vec::new();
            };
            let Some(claims) = value.get("claims").and_then(|c| c.as_object()) else {
                return Vec::new();
            };
            claims
                .iter()
                .filter_map(|(target, digests)| {
                    // `algo:hex`, several joined by `|` as an SRI list
                    // allows (any one admits the bytes).
                    let digests = digests
                        .as_str()?
                        .split('|')
                        .map(|digest| {
                            let (algo, hex) = digest.split_once(':')?;
                            Digest::from_parts(algo, hex).ok()
                        })
                        .collect::<Option<Vec<_>>>()?;
                    Some((url.join(target).ok()?, Claim::any(digests)?))
                })
                .collect()
        }

        fn expects_claim(&self, url: &Url) -> bool {
            url.path().starts_with("/art/claimed-")
        }

        /// A metadata body's `{"published": {"<name>@<version>": "<time>"}}`.
        fn published(&self, _url: &Url, body: &[u8]) -> Vec<(String, String, i64)> {
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
                return Vec::new();
            };
            let Some(times) = value.get("published").and_then(|t| t.as_object()) else {
                return Vec::new();
            };
            times
                .iter()
                .filter_map(|(package, at)| {
                    let (name, version) = package.split_once('@')?;
                    let at = crate::kernel::resolve::age::parse_rfc3339(at.as_str()?)?;
                    Some((name.to_string(), version.to_string(), at))
                })
                .collect()
        }

        /// `/meta/<name>.json` on the first endpoint.
        fn lookup(&self, endpoints: &[Endpoint], name: &str, _version: &str) -> Option<Lookup> {
            Some(Lookup {
                url: endpoints[0].url(&format!("/meta/{name}.json")).ok()?,
                accept: "application/json",
            })
        }

        fn content_query_keys(&self) -> &'static [&'static str] {
            &["format"]
        }

        fn rewrite(&self, url: &Url, body: Vec<u8>, base: &ProxyAddress) -> io::Result<Vec<u8>> {
            if url.path() != "/meta/rewritten.json" {
                return Ok(body);
            }
            let text =
                String::from_utf8_lossy(&body).replace("{BASE}", &base.route_base("fixture"));
            Ok(text.into_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::TEST_PROTOCOL;
    use super::*;

    /// The wrapper of compiled-in protocols names every method the trait
    /// has: a method added to the trait with a default body, and not
    /// forwarded, would leave every compiled-in route on the default.
    #[test]
    fn the_compiled_in_wrapper_names_every_trait_method() {
        let source = include_str!("routes.rs");
        let methods = |header: &str| -> BTreeSet<String> {
            let start = source.find(header).expect(header) + header.len();
            let body = &source[start..start + source[start..].find("\n}\n").unwrap()];
            body.lines()
                .filter_map(|line| line.strip_prefix("    fn "))
                .map(|rest| rest.split(['(', '<']).next().unwrap().to_string())
                .collect()
        };
        let trait_methods = methods("pub trait RegistryProtocol: Send + Sync {");
        assert!(trait_methods.contains("tree_size"), "{trait_methods:?}");
        assert_eq!(methods("impl RegistryProtocol for Fixed {"), trait_methods);
    }

    /// A compiled-in protocol answers through its route exactly as it
    /// answers itself: every method the trait has is passed through, so a
    /// method added later and not forwarded fails here, not silently.
    #[test]
    fn a_compiled_in_route_forwards_every_protocol_method() {
        struct Sentinel;
        impl RegistryProtocol for Sentinel {
            fn route_id(&self) -> &str {
                "sentinel"
            }
            fn upstream(&self, endpoints: &[Endpoint], _path: &str) -> io::Result<Upstream> {
                Ok(Upstream::Fetch(endpoints[0].url("/upstream")?))
            }
            fn classify(&self, _url: &Url) -> RequestClass {
                RequestClass::Sumdb
            }
            fn claims(&self, url: &Url, _body: &[u8]) -> Vec<(Url, Claim)> {
                vec![(
                    url.clone(),
                    Claim::one(Digest::sha256(&"7".repeat(64)).unwrap()),
                )]
            }
            fn expects_claim(&self, _url: &Url) -> bool {
                true
            }
            fn request_body_cap(&self) -> u64 {
                77
            }
            fn content_query_keys(&self) -> &'static [&'static str] {
                &["sentinel"]
            }
            fn rewrite(
                &self,
                _url: &Url,
                _body: Vec<u8>,
                _base: &ProxyAddress,
            ) -> io::Result<Vec<u8>> {
                Ok(b"rewritten".to_vec())
            }
            fn encoded_slash(&self) -> bool {
                true
            }
            fn follows_redirect(&self, _from: &Url, to: &Url) -> bool {
                to.path() == "/sentinel"
            }
            fn published(&self, _url: &Url, _body: &[u8]) -> Vec<(String, String, i64)> {
                vec![("n".into(), "1".into(), 7)]
            }
            fn lookup(
                &self,
                endpoints: &[Endpoint],
                _name: &str,
                _version: &str,
            ) -> Option<Lookup> {
                Some(Lookup {
                    url: endpoints[0].url("/lookup").ok()?,
                    accept: "sentinel",
                })
            }
            fn package_key(&self, name: &str, version: &str) -> (String, String) {
                (format!("key-{name}"), format!("key-{version}"))
            }
            fn log(&self) -> Option<super::super::tlog::Log> {
                Some(crate::tailors::go::sumdb::log())
            }
            fn tree_size(
                &self,
                _url: &Url,
                _body: &[u8],
            ) -> Option<Result<super::super::tlog::Head, String>> {
                Some(Err("sentinel".into()))
            }
        }
        static SENTINEL: Sentinel = Sentinel;
        let endpoints = vec![Endpoint::https("pypi.org").unwrap()];
        let route = Route::new(&SENTINEL, endpoints.clone()).unwrap();
        let wrapped = &route.protocol;
        let url = Url::parse("https://pypi.org/x").unwrap();
        let base = ProxyAddress::new(std::net::SocketAddr::from(([127, 0, 0, 1], 1)), "t");
        assert_eq!(wrapped.route_id(), "sentinel");
        assert_eq!(
            wrapped.upstream(&endpoints, "/x").unwrap(),
            SENTINEL.upstream(&endpoints, "/x").unwrap()
        );
        assert_eq!(wrapped.classify(&url), RequestClass::Sumdb);
        assert_eq!(wrapped.claims(&url, b""), SENTINEL.claims(&url, b""));
        assert!(wrapped.expects_claim(&url));
        assert_eq!(wrapped.request_body_cap(), 77);
        assert_eq!(wrapped.content_query_keys(), ["sentinel"]);
        assert_eq!(
            wrapped.rewrite(&url, Vec::new(), &base).unwrap(),
            b"rewritten"
        );
        assert!(wrapped.encoded_slash());
        let sentinel = Url::parse("https://pypi.org/sentinel").unwrap();
        assert!(wrapped.follows_redirect(&url, &sentinel));
        assert!(!wrapped.follows_redirect(&sentinel, &url));
        assert_eq!(wrapped.published(&url, b""), SENTINEL.published(&url, b""));
        assert_eq!(
            wrapped.lookup(&endpoints, "n", "1"),
            SENTINEL.lookup(&endpoints, "n", "1")
        );
        assert_eq!(
            wrapped.package_key("n", "1"),
            ("key-n".into(), "key-1".into())
        );
        assert_eq!(wrapped.log().map(|log| log.name), Some("sum.golang.org"));
        assert_eq!(
            wrapped.tree_size(&url, b"").unwrap().unwrap_err(),
            "sentinel"
        );
    }

    /// A requested URL and a route's mapping name one resource when only
    /// their percent-escapes differ, segment by segment.
    #[test]
    fn same_resource_compares_segments_after_one_decoding() {
        let url = |text: &str| Url::parse(text).unwrap();
        let mapped = url("https://proxy.golang.org/github.com/!azure/x/@v/list");
        for same in [
            "https://proxy.golang.org/github.com/%21azure/x/@v/list",
            "https://proxy.golang.org:443/github.com/!azure/x/@v/list",
            "https://proxy.golang.org/github.com/!azure/x/%40v/list#ignored",
        ] {
            assert!(same_resource(&url(same), &mapped), "{same}");
        }
        for other in [
            "http://proxy.golang.org/github.com/!azure/x/@v/list",
            "https://sum.golang.org/github.com/!azure/x/@v/list",
            "https://proxy.golang.org:8443/github.com/!azure/x/@v/list",
            "https://u@proxy.golang.org/github.com/!azure/x/@v/list",
            "https://proxy.golang.org/github.com/%2521azure/x/@v/list",
            "https://proxy.golang.org/github.com/!azure/x/@v/list?go-get=1",
            "https://proxy.golang.org/github.com/!azure/x/@v/list/",
            "https://proxy.golang.org/github.com%2f!azure/x/@v/list",
        ] {
            assert!(!same_resource(&url(other), &mapped), "{other}");
        }
        // An encoded slash stays inside its segment on both sides.
        let scoped = url("https://registry.npmjs.org/@s%2fn");
        assert!(same_resource(
            &url("https://registry.npmjs.org/@s%2Fn"),
            &scoped
        ));
        assert!(!same_resource(
            &url("https://registry.npmjs.org/@s/n"),
            &scoped
        ));
    }

    #[test]
    fn route_paths_follow_the_grammar() {
        for good in [
            "/",
            "/github.com/google/uuid/@v/list",
            "/a/b.json?format=json&x=%2F",
            "/a%20b/c",
            "/dir/",
            "/a%25b",
            "/a%2541",
        ] {
            assert_eq!(check_route_path_with(good, false), Ok(()), "{good}");
        }
        for (bad, why) in [
            ("a/b", "absolute path"),
            ("/a/../b", ". or .."),
            ("/a/%2e%2E/b", ". or .."),
            ("/a/./b", ". or .."),
            ("/..", ". or .."),
            ("/a%2Fb", "percent-encoded"),
            ("/a%5cb", "percent-encoded"),
            ("/a%00", "percent-encoded"),
            ("/a\\b", "backslash"),
            ("/http://evil.test/x", "absolute URL"),
            ("//evil.test/x", "empty segment"),
            ("/a//b", "empty segment"),
            ("/a%zz", "malformed"),
            ("/a%2", "malformed"),
            ("/a#b", "a #"),
            ("/a?x=1#frag", "a #"),
            ("/a/%252e%252e/b", "double"),
            ("/a%252Fb", "double"),
            ("/a%255cb", "double"),
            ("/a%2500", "double"),
            ("/a%2525", "double"),
        ] {
            let error = check_route_path_with(bad, false).unwrap_err();
            assert!(error.contains(why), "{bad}: {error}");
        }
    }

    /// A protocol that takes an encoded slash (npm's `/@scope%2fname`)
    /// gets it in either case, and nothing else changes: the encoded slash
    /// bounds a segment, so `..` or an empty segment behind it is still
    /// refused, and `\`, NUL, and every double encoding stay refused.
    #[test]
    fn an_encoded_slash_is_a_segment_boundary_when_a_protocol_allows_it() {
        for good in ["/@types%2fnode", "/@Types%2Fnode", "/@s%2fn/-/n-1.0.0.tgz"] {
            assert_eq!(check_route_path_with(good, true), Ok(()), "{good}");
            assert!(check_route_path_with(good, false).is_err(), "{good}");
        }
        for (bad, why) in [
            ("/@s%2f..", ". or .."),
            ("/@s%2f%2e%2e/x", ". or .."),
            ("/@s%2f.%2fx", ". or .."),
            ("/@s%2f%2fx", "empty segment"),
            ("/a%5cb", "percent-encoded"),
            ("/a%00", "percent-encoded"),
            ("/a%252Fb", "double"),
        ] {
            let error = check_route_path_with(bad, true).unwrap_err();
            assert!(error.contains(why), "{bad}: {error}");
        }
    }

    #[test]
    fn endpoint_credentials_must_be_valid_header_values() {
        for bad in [
            "",
            "   ",
            "Bearer s3cret\r\nX: y",
            "Bearer s3cr\u{e9}t",
            "Bearer s3cret\0",
        ] {
            let error = Endpoint::https("pypi.org")
                .unwrap()
                .with_authorization(bad)
                .unwrap_err();
            assert!(!error.to_string().contains("s3cr"), "{error}");
        }
        let good = Endpoint::https("pypi.org")
            .unwrap()
            .with_authorization("Basic dG9nOnRvZw==\t")
            .unwrap();
        assert!(format!("{good:?}").contains("…") && !format!("{good:?}").contains("dG9n"));
    }

    #[test]
    fn endpoints_come_only_from_the_permitted_set() {
        assert_eq!(
            Endpoint::https("proxy.golang.org").unwrap().origin(),
            "https://proxy.golang.org"
        );
        let error = Endpoint::https("evil.example").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let permitted = Permitted::compiled();
        for (url, allowed) in [
            ("https://proxy.golang.org/x", true),
            ("https://PROXY.golang.org/x", true),
            ("http://proxy.golang.org/x", false),
            ("https://proxy.golang.org:8443/x", false),
            ("https://user:pw@proxy.golang.org/x", false),
            ("https://builds.hex.pm/x", false),
            ("https://127.0.0.1/x", false),
        ] {
            assert_eq!(
                permitted.allows(&Url::parse(url).unwrap()),
                allowed,
                "{url}"
            );
        }
    }

    #[test]
    fn a_route_answer_must_stay_on_its_endpoints() {
        let route = Route::new(
            &TEST_PROTOCOL,
            vec![
                Endpoint::for_test("fixture.test", 8443),
                Endpoint::for_test("other.test", 8443),
            ],
        )
        .unwrap();
        assert_eq!(
            route.resolve("/meta/a.json").unwrap(),
            Upstream::Fetch(Url::parse("https://fixture.test:8443/meta/a.json").unwrap())
        );
        assert!(matches!(
            route.resolve("/second/x").unwrap(),
            Upstream::Fetch(url) if url.host_str() == Some("other.test")
        ));
        let error = route.resolve("/elsewhere/x").unwrap_err();
        assert!(error.contains("not one of its endpoints"), "{error}");
        let error = route.resolve("/forbidden/x").unwrap_err();
        assert!(error.contains("forbids"), "{error}");
        let error = route.resolve("/a/../b").unwrap_err();
        assert!(error.contains(". or .."), "{error}");
    }
}
