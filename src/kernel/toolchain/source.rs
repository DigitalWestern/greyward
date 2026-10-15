//! Source policy (kernel layer): which publishers may serve toolchain
//! artifacts, from which endpoints, with which credential *reference*.
//!
//! The shipped defaults are configuration, not a compiled allow-list baked
//! into lock validity: a lock stays valid when policy tightens, and
//! retrieval refuses instead. Every toolchain artifact download
//! (`kernel::fetch::download_toolchain_artifact_held`) checks the row's URL
//! against the effective policy under the row's own `provider` before it
//! looks in the cache, and checks every redirect `Location` again before
//! requesting it, so a redirect off the publisher's endpoints refuses.
//! Package-registry downloads (npm, PyPI, crates, gems) are not toolchain
//! rows and do not pass through here.
//!
//! An endpoint may name a credential *reference*, and a redirect is matched
//! to the target endpoint, so it would get that endpoint's credential or
//! none, never the original endpoint's. No shipped endpoint names one, and
//! retrieval sends none (the credential policy is decided in #72; sending
//! is not built yet, #404). No secret is
//! ever stored here or in a catalog row: a [`CredentialRef`] names where an
//! operator keeps one.

use super::invalid;
use std::io;
use std::sync::OnceLock;

/// A named reference to a credential held outside ward (an environment
/// variable or keychain entry an operator configures). Never the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRef {
    pub name: String,
}

/// One authorized URL prefix: an `https://` origin plus an optional path
/// prefix, so a policy can admit `https://github.com/astral-sh/uv/` without
/// admitting every repository on that host.
///
/// A `redirect_only` endpoint is reached only by a redirect from one of the
/// same publisher's other endpoints, never named as the first hop: GitHub's
/// asset CDN serves every repository's release files under URLs that do not
/// say which repository they belong to, so a lock or catalog row naming one
/// directly could not be reviewed for its publisher (#699).
///
/// An `anonymous_token` endpoint is a registry that answers an anonymous
/// pull only with a fixed, public `Authorization` value (GitHub's container
/// registry takes `Bearer QQ==`, the value Homebrew itself sends). It is
/// the same for everyone and grants nothing, so it is not a credential: it
/// is compiled in, sent on requests to that endpoint only, and never on a
/// redirect to another endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub base: String,
    pub credential: Option<CredentialRef>,
    pub redirect_only: bool,
    pub anonymous_token: Option<&'static str>,
}

/// The `Authorization` value GitHub's container registry takes for an
/// anonymous pull of a public image.
pub const GHCR_ANONYMOUS: &str = "Bearer QQ==";

impl Endpoint {
    /// An anonymous endpoint. `base` must be `https://host[:port]/...`.
    pub fn new(base: &str) -> io::Result<Endpoint> {
        Endpoint::validate_base(base)?;
        Ok(Endpoint {
            base: base.into(),
            credential: None,
            redirect_only: false,
            anonymous_token: None,
        })
    }

    /// An anonymous endpoint that is sent the public `token` (see
    /// [`Endpoint`]).
    pub fn with_anonymous_token(base: &str, token: &'static str) -> io::Result<Endpoint> {
        Ok(Endpoint {
            anonymous_token: Some(token),
            ..Endpoint::new(base)?
        })
    }

    /// An anonymous endpoint only a redirect may reach (see [`Endpoint`]).
    pub fn redirect_target(base: &str) -> io::Result<Endpoint> {
        Ok(Endpoint {
            redirect_only: true,
            ..Endpoint::new(base)?
        })
    }

    #[cfg(test)]
    /// An endpoint that sends the referenced credential, and only there.
    pub fn with_credential(base: &str, credential: &str) -> io::Result<Endpoint> {
        let mut endpoint = Endpoint::new(base)?;
        if credential.is_empty() {
            return Err(invalid("credential reference is empty"));
        }
        endpoint.credential = Some(CredentialRef {
            name: credential.into(),
        });
        Ok(endpoint)
    }

    fn validate_base(base: &str) -> io::Result<()> {
        let rest = base
            .strip_prefix("https://")
            .ok_or_else(|| invalid(format!("endpoint {base:?} is not https://")))?;
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() || host.contains('@') || host.contains('?') || host.contains('#') {
            return Err(invalid(format!("endpoint {base:?} has no plain host")));
        }
        Ok(())
    }

    /// Does `url` fall under this endpoint? The origin must match exactly
    /// (no suffix matching) and the path must extend the base's path at a
    /// segment boundary. A path that a server or client could normalize to
    /// somewhere else (`.`/`..` segments, backslashes, or a percent-escape
    /// that decodes to `/`, `\`, `.` or `%`) is never covered, so a prefix
    /// cannot be escaped by spelling. Inert escapes such as the `%2B` in a
    /// python-build-standalone file name are fine; overlong UTF-8 spellings
    /// are not decoded here, since every shipped endpoint rejects them.
    pub fn covers(&self, url: &str) -> bool {
        let Some(rest) = url.strip_prefix("https://") else {
            return false;
        };
        let base_rest = &self.base["https://".len()..];
        let (base_host, base_path) = split_host(base_rest);
        let (host, path) = split_host(rest);
        if host != base_host {
            return false;
        }
        let path = path.split(['?', '#']).next().unwrap_or("");
        if path.contains('\\')
            || !escapes_are_inert(path)
            || path
                .split('/')
                .any(|segment| segment == "." || segment == "..")
        {
            return false;
        }
        let base_path = base_path.trim_end_matches('/');
        if base_path.is_empty() {
            return true;
        }
        path == base_path || path.starts_with(&format!("{base_path}/"))
    }
}

/// Every `%XX` in `path` is well formed and decodes to a byte that cannot
/// change which directory the path names once a server decodes it.
fn escapes_are_inert(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let Some(hex) = bytes.get(i + 1..i + 3) else {
                return false;
            };
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            let Ok(decoded) = u8::from_str_radix(std::str::from_utf8(hex).expect("hex digits"), 16)
            else {
                return false;
            };
            if matches!(decoded, b'/' | b'\\' | b'.' | b'%') {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

fn split_host(rest: &str) -> (&str, &str) {
    match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    }
}

/// A publisher: the `provider` a catalog row names, and the endpoints that
/// may serve its artifacts (including the CDN origins its downloads redirect
/// to).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publisher {
    pub id: String,
    pub endpoints: Vec<Endpoint>,
}

/// The effective source policy: the shipped defaults, plus whatever an
/// operator adds through [`SourcePolicy::allow`]. Later layers load and
/// protect it; this is the typed interface they fill.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourcePolicy {
    publishers: Vec<Publisher>,
}

#[cfg(test)]
thread_local! {
    static TEST_POLICY: std::cell::Cell<Option<&'static SourcePolicy>> =
        const { std::cell::Cell::new(None) };
}

/// What an authorized fetch may do: contact `endpoint` on behalf of
/// `publisher`. The endpoint's credential reference, if it has one, is the
/// only credential that hop could carry; retrieval sends none today (#72).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorized<'a> {
    pub publisher: &'a str,
    pub endpoint: &'a Endpoint,
}

impl SourcePolicy {
    /// No publisher at all: every fetch refuses until one is allowed.
    pub fn empty() -> SourcePolicy {
        SourcePolicy::default()
    }

    /// The upstream endpoints the shipped catalog rows are served from.
    /// Defaults an operator may replace; not a validity rule for locks.
    pub fn shipped() -> SourcePolicy {
        let mut policy = SourcePolicy::empty();
        // A GitHub release download redirects to the asset CDN. The CDN is
        // the same publisher's endpoint only as that redirect's target: a
        // row or lock must name the repository's own release URL.
        let github_publisher = |policy: &mut SourcePolicy, id: &str, repo: &str| {
            let release = format!("https://github.com/{repo}/releases/download/");
            policy
                .allow(id, Endpoint::new(&release).expect("shipped endpoint"))
                .expect("shipped publisher");
            for cdn in [
                "https://objects.githubusercontent.com/",
                "https://release-assets.githubusercontent.com/",
            ] {
                policy
                    .allow(
                        id,
                        Endpoint::redirect_target(cdn).expect("shipped endpoint"),
                    )
                    .expect("shipped publisher");
            }
        };
        github_publisher(
            &mut policy,
            "python-build-standalone",
            "astral-sh/python-build-standalone",
        );
        github_publisher(&mut policy, "uv", "astral-sh/uv");
        github_publisher(
            &mut policy,
            "homebrew-portable-ruby",
            "Homebrew/homebrew-portable-ruby",
        );
        // Homebrew's portable-ruby builds since 3.4.6, on GitHub's
        // container registry: a blob URL names the bottle by its sha256,
        // and a pull redirects to the registry's blob CDN.
        policy
            .allow(
                "ghcr-homebrew-portable-ruby",
                Endpoint::with_anonymous_token(
                    "https://ghcr.io/v2/homebrew/core/portable-ruby/blobs/",
                    GHCR_ANONYMOUS,
                )
                .expect("shipped endpoint"),
            )
            .expect("shipped publisher");
        policy
            .allow(
                "ghcr-homebrew-portable-ruby",
                Endpoint::redirect_target("https://pkg-containers.githubusercontent.com/")
                    .expect("shipped endpoint"),
            )
            .expect("shipped publisher");
        github_publisher(&mut policy, "erlef-otp-builds", "erlef/otp_builds");
        github_publisher(
            &mut policy,
            "greyward-toolchains",
            "DigitalWestern/greyward-toolchains",
        );
        github_publisher(&mut policy, "elixir-lang", "elixir-lang/elixir");
        for (id, base) in [
            ("nodejs.org", "https://nodejs.org/dist/"),
            ("static.rust-lang.org", "https://static.rust-lang.org/dist/"),
            ("go.dev", "https://go.dev/dl/"),
            ("go.dev", "https://dl.google.com/go/"),
            ("builds.hex.pm", "https://builds.hex.pm/"),
            (
                "builds.dotnet.microsoft.com",
                "https://builds.dotnet.microsoft.com/dotnet/",
            ),
            // The native-library closure Python wheels link against
            // (`kernel::provider::nativelibs`).
            ("conda-forge", "https://conda.anaconda.org/conda-forge/"),
        ] {
            policy
                .allow(id, Endpoint::new(base).expect("shipped endpoint"))
                .expect("shipped publisher");
        }
        policy
    }

    /// The policy every toolchain download is checked against: the shipped
    /// defaults, built once per process. Nothing configures it yet.
    pub fn effective() -> &'static SourcePolicy {
        #[cfg(test)]
        if let Some(policy) = TEST_POLICY.with(std::cell::Cell::get) {
            return policy;
        }
        static EFFECTIVE: OnceLock<SourcePolicy> = OnceLock::new();
        EFFECTIVE.get_or_init(SourcePolicy::shipped)
    }

    /// Run `body` with `policy` as this thread's effective policy, for unit
    /// tests whose rows point at a local address the shipped policy refuses.
    /// The shipped policy itself is never loosened.
    #[cfg(test)]
    pub(crate) fn with_test_policy<R>(policy: SourcePolicy, body: impl FnOnce() -> R) -> R {
        struct Restore(Option<&'static SourcePolicy>);
        impl Drop for Restore {
            fn drop(&mut self) {
                TEST_POLICY.with(|cell| cell.set(self.0));
            }
        }
        let leaked: &'static SourcePolicy = Box::leak(Box::new(policy));
        let _restore = Restore(TEST_POLICY.with(|cell| cell.replace(Some(leaked))));
        body()
    }

    #[cfg(test)]
    pub fn publishers(&self) -> &[Publisher] {
        &self.publishers
    }

    pub fn publisher(&self, id: &str) -> Option<&Publisher> {
        self.publishers.iter().find(|p| p.id == id)
    }

    /// Admit `endpoint` for `publisher`, creating the publisher if new. This
    /// is an explicit configuration change, never a side effect of a lock.
    pub fn allow(&mut self, publisher: &str, endpoint: Endpoint) -> io::Result<()> {
        if publisher.is_empty() {
            return Err(invalid("publisher id is empty"));
        }
        match self.publishers.iter_mut().find(|p| p.id == publisher) {
            Some(existing) => {
                if !existing.endpoints.contains(&endpoint) {
                    existing.endpoints.push(endpoint);
                }
            }
            None => self.publishers.push(Publisher {
                id: publisher.into(),
                endpoints: vec![endpoint],
            }),
        }
        Ok(())
    }

    /// May `url` be fetched on behalf of `publisher` as the first hop: the
    /// URL a catalog row or lock names? Only `https://` URLs under one of
    /// that publisher's endpoints that is not redirect-only; `file://`,
    /// `http://` and any other publisher's endpoint refuse before any
    /// network activity. Every redirect `Location` after it goes through
    /// [`SourcePolicy::authorize_redirect`].
    pub fn authorize<'a>(&'a self, publisher: &str, url: &str) -> io::Result<Authorized<'a>> {
        self.authorize_hop(publisher, url, false)
    }

    /// May a redirect from one of `publisher`'s endpoints lead to `url`? The
    /// same rule as [`SourcePolicy::authorize`], with the publisher's
    /// redirect-only endpoints (GitHub's asset CDN) admitted too.
    pub fn authorize_redirect<'a>(
        &'a self,
        publisher: &str,
        url: &str,
    ) -> io::Result<Authorized<'a>> {
        self.authorize_hop(publisher, url, true)
    }

    /// The public anonymous-pull token a request to `url` for `publisher`
    /// carries: that of the publisher's first-hop endpoint covering `url`,
    /// if it names one. A redirect-only endpoint never does.
    pub fn anonymous_token(&self, publisher: &str, url: &str) -> Option<&'static str> {
        self.publisher(publisher)?
            .endpoints
            .iter()
            .filter(|endpoint| !endpoint.redirect_only && endpoint.covers(url))
            .find_map(|endpoint| endpoint.anonymous_token)
    }

    fn authorize_hop<'a>(
        &'a self,
        publisher: &str,
        url: &str,
        redirected: bool,
    ) -> io::Result<Authorized<'a>> {
        let refuse = |why: &str| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "source policy refuses {} for {publisher}: {why}",
                    crate::kernel::fetch::shown_url(url)
                ),
            )
        };
        if !url.starts_with("https://") {
            return Err(refuse(
                "only https:// endpoints may serve toolchain artifacts",
            ));
        }
        let Some(found) = self.publisher(publisher) else {
            return Err(refuse("no such publisher in the effective policy"));
        };
        let covering = || {
            found
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.covers(url))
        };
        if let Some(endpoint) = covering().find(|endpoint| redirected || !endpoint.redirect_only) {
            return Ok(Authorized {
                publisher: &found.id,
                endpoint,
            });
        }
        if covering().next().is_some() {
            return Err(refuse(
                "that endpoint is only a redirect target for this publisher (its URLs do not \
                 name the repository they belong to); name the publisher's own release URL",
            ));
        }
        Err(refuse(
            "not under any endpoint authorized for this publisher",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_token_goes_to_the_registry_endpoint_only() {
        let policy = SourcePolicy::shipped();
        let publisher = "ghcr-homebrew-portable-ruby";
        let blob = "https://ghcr.io/v2/homebrew/core/portable-ruby/blobs/sha256:ab";
        policy.authorize(publisher, blob).unwrap();
        assert_eq!(
            policy.anonymous_token(publisher, blob),
            Some(GHCR_ANONYMOUS)
        );
        // The CDN a pull redirects to is reached only by that redirect, and
        // gets no token.
        let cdn = "https://pkg-containers.githubusercontent.com/ghcr1/blobs/sha256:ab";
        policy.authorize(publisher, cdn).unwrap_err();
        policy.authorize_redirect(publisher, cdn).unwrap();
        assert_eq!(policy.anonymous_token(publisher, cdn), None);
        // Another image on the registry is not this publisher's, and no
        // other publisher's endpoint sends a token.
        let other = "https://ghcr.io/v2/someone/else/blobs/sha256:ab";
        policy.authorize(publisher, other).unwrap_err();
        assert_eq!(policy.anonymous_token(publisher, other), None);
        assert_eq!(
            policy.anonymous_token(
                "homebrew-portable-ruby",
                "https://github.com/Homebrew/homebrew-portable-ruby/releases/download/3.4.6/x"
            ),
            None
        );
    }

    #[test]
    fn endpoints_match_origin_exactly_and_paths_at_segment_boundaries() {
        let endpoint = Endpoint::new("https://github.com/astral-sh/uv/releases/download/").unwrap();
        assert!(
            endpoint.covers("https://github.com/astral-sh/uv/releases/download/0.12.7/uv.tar.gz")
        );
        assert!(endpoint.covers("https://github.com/astral-sh/uv/releases/download?x=1"));
        assert!(!endpoint.covers("https://github.com/astral-sh/uv/releases/downloads/x"));
        assert!(!endpoint.covers("https://github.com/astral-sh/other/releases/download/x"));
        assert!(
            !endpoint.covers("https://github.com.evil.example/astral-sh/uv/releases/download/x")
        );
        assert!(
            !endpoint.covers("https://evil.example/github.com/astral-sh/uv/releases/download/x")
        );
        assert!(!endpoint.covers("http://github.com/astral-sh/uv/releases/download/x"));
        // Spellings a server would normalize out of the prefix.
        for escape in [
            "https://github.com/astral-sh/uv/releases/download/../../../other/x/releases/download/y",
            "https://github.com/astral-sh/uv/releases/download/./x",
            "https://github.com/astral-sh/uv/releases/download/%2e%2e/x",
            "https://github.com/astral-sh/uv/releases/download/..\\x",
            "https://github.com/astral-sh/uv/releases/download/a%2fb",
            "https://github.com/astral-sh/uv/releases/download/a%5Cb",
            "https://github.com/astral-sh/uv/releases/download/a%2",
            "https://github.com/astral-sh/uv/releases/download/a%zz",
            "https://github.com/astral-sh/uv/releases/download/a%25",
            "https://github.com/astral-sh/uv/releases/download/a%+5",
        ] {
            assert!(!endpoint.covers(escape), "{escape}");
        }
        // An escape that decodes to an ordinary character is inert.
        assert!(endpoint.covers(
            "https://github.com/astral-sh/uv/releases/download/cpython-3.12.14%2B20260825.tar.gz"
        ));
        let origin = Endpoint::new("https://nodejs.org").unwrap();
        assert!(origin.covers("https://nodejs.org/dist/v24.20.0/node.tar.gz"));
        assert!(!origin.covers("https://nodejs.org:8443/dist/x"));
        for bad in [
            "http://x/",
            "file:///tmp/x",
            "https://",
            "https://user@host/",
            "ftp://x",
        ] {
            assert!(Endpoint::new(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn authorize_refuses_non_https_unknown_publishers_and_foreign_endpoints() {
        let policy = SourcePolicy::shipped();
        let ok = policy
            .authorize(
                "nodejs.org",
                "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.gz",
            )
            .unwrap();
        assert_eq!(ok.publisher, "nodejs.org");
        assert!(ok.endpoint.credential.is_none());
        for (publisher, url, why) in [
            ("nodejs.org", "file:///tmp/node.tar.gz", "only https://"),
            (
                "nodejs.org",
                "http://nodejs.org/dist/x.tar.gz",
                "only https://",
            ),
            (
                "nodejs.org",
                "https://static.rust-lang.org/dist/x",
                "not under any endpoint",
            ),
            ("nobody", "https://nodejs.org/dist/x", "no such publisher"),
            (
                "uv",
                "https://github.com/astral-sh/python-build-standalone/releases/download/x",
                "not under any endpoint",
            ),
        ] {
            let error = policy.authorize(publisher, url).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains(why), "{url}: {error}");
        }
        assert!(SourcePolicy::empty()
            .authorize("nodejs.org", "https://nodejs.org/dist/x")
            .is_err());
    }

    #[test]
    fn redirects_get_the_target_endpoints_credential_or_none() {
        let mut policy = SourcePolicy::empty();
        policy
            .allow(
                "corp",
                Endpoint::with_credential("https://artifacts.corp.example/", "CORP_TOKEN").unwrap(),
            )
            .unwrap();
        policy
            .allow("corp", Endpoint::new("https://cdn.corp.example/").unwrap())
            .unwrap();
        let first = policy
            .authorize("corp", "https://artifacts.corp.example/node.tar.gz")
            .unwrap();
        assert_eq!(
            first.endpoint.credential.as_ref().unwrap().name,
            "CORP_TOKEN"
        );
        // A redirect is re-authorized under the same publisher: the CDN
        // endpoint carries no credential, so none is sent there.
        let redirected = policy
            .authorize("corp", "https://cdn.corp.example/blob/1")
            .unwrap();
        assert!(redirected.endpoint.credential.is_none());
        // A redirect off-policy refuses even though the first hop passed.
        assert!(policy
            .authorize("corp", "https://elsewhere.example/blob/1")
            .is_err());
        // Adding an endpoint is explicit and idempotent.
        policy
            .allow("corp", Endpoint::new("https://cdn.corp.example/").unwrap())
            .unwrap();
        assert_eq!(policy.publisher("corp").unwrap().endpoints.len(), 2);
        assert!(policy
            .allow("", Endpoint::new("https://x.example/").unwrap())
            .is_err());
        assert!(Endpoint::with_credential("https://x.example/", "").is_err());
    }

    /// Issue #699. GitHub release downloads redirect to the asset CDN; the
    /// shipped publisher admits that hop under the same publisher, but only
    /// as a redirect. A row or lock naming a CDN URL directly is refused:
    /// the URL does not say which repository the asset belongs to.
    #[test]
    fn shipped_github_publishers_admit_the_asset_cdn_only_as_a_redirect() {
        let policy = SourcePolicy::shipped();
        for cdn in [
            "https://objects.githubusercontent.com/github-production-release-asset/1",
            "https://release-assets.githubusercontent.com/github-production-release-asset/2",
        ] {
            let hop = policy.authorize_redirect("uv", cdn).unwrap();
            assert_eq!(hop.publisher, "uv");
            let first = policy.authorize("uv", cdn).unwrap_err();
            assert_eq!(first.kind(), io::ErrorKind::PermissionDenied);
            assert!(
                first.to_string().contains("only a redirect target"),
                "{first}"
            );
        }
        // The repository's own release URL is a first hop, and a redirect.
        let release = "https://github.com/astral-sh/uv/releases/download/0.1.0/uv.tar.gz";
        assert_eq!(policy.authorize("uv", release).unwrap().publisher, "uv");
        assert_eq!(
            policy.authorize_redirect("uv", release).unwrap().publisher,
            "uv"
        );
        // A publisher with no redirect-only endpoint answers the same both
        // ways, and the CDN is not one of its endpoints.
        let node = "https://nodejs.org/dist/v1/node.tar.gz";
        assert!(policy.authorize("nodejs.org", node).is_ok());
        assert!(policy.authorize_redirect("nodejs.org", node).is_ok());
        assert!(policy
            .authorize_redirect(
                "nodejs.org",
                "https://objects.githubusercontent.com/github-production-release-asset/1"
            )
            .is_err());
    }
}
