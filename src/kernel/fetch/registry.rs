//! Ward's own registry downloads: the wheels, sdists and tarballs a sync
//! fetches by the URL a lock names.
//!
//! The ecosystem's effective `[sources]` list decides who serves a URL:
//! the listed registry whose root covers it (longest root wins), else one
//! whose `files` origin covers it. That registry's request carries its
//! credential while the URL is under its root, goes through the client its
//! `ca` and `network` select, and follows redirects here, each hop bound
//! to the same registry's root and `files` origins. In an enforced
//! ecosystem a URL no listed registry covers is refused before any request
//! (a public URL passes when `public` is listed); in a default ecosystem
//! it takes the public path unchanged.

use super::{follow_redirects, open_url, shown_url, Hop, StatusFailure};
use crate::kernel::error;
use crate::kernel::fetch::pinned::{PinnedError, PinnedRequest};
use crate::kernel::registries::config::{Ecosystem, Registry};
use crate::kernel::registries::covers::{covers, root_len};
use crate::kernel::registries::credential::Credential;
use crate::kernel::registries::effective::Sources;
use crate::kernel::resolve::clients::{self, ClientSpec, Clients};
use std::io::{self, Read};

/// Who serves a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served<'a> {
    /// Today's path: the public registry, no credential.
    Public,
    Registry(&'a Registry),
}

/// Which source of `ecosystem` serves `url`, or the refusal with a `fix:`
/// line.
pub fn source_for<'a>(
    sources: &'a Sources,
    ecosystem: Ecosystem,
    url: &str,
) -> io::Result<Served<'a>> {
    let refused = |message: String| error::refused(io::ErrorKind::PermissionDenied, message);
    if has_userinfo(url) {
        return Err(refused(format!(
            "{}: a package URL may not carry credentials\nfix: remove the user and password from the URL; a private registry's credential goes in the machine policy's [credentials]",
            shown_url(url)
        )));
    }
    let list = sources.ecosystem(ecosystem);
    // The longest root wins; on a tie the earlier entry does, as it does
    // where a lock names an index.
    let by_root = list
        .registries()
        .filter(|registry| covers(&registry.root, url))
        .fold(None::<&Registry>, |best, registry| match best {
            Some(best) if root_len(&best.root) >= root_len(&registry.root) => Some(best),
            _ => Some(registry),
        });
    if let Some(registry) = by_root {
        return Ok(Served::Registry(registry));
    }
    if let Some(registry) = list
        .registries()
        .find(|registry| registry.files.iter().any(|files| covers(files, url)))
    {
        return Ok(Served::Registry(registry));
    }
    if !list.enforced || (list.includes_public() && is_public(ecosystem, url)) {
        return Ok(Served::Public);
    }
    Err(refused(format!(
        "{} is not served by any registry allowed for {}: [{}] ({})\nfix: lock the package from a listed registry (run `ward update` for it), or have the machine policy list the registry that serves it",
        shown_url(url),
        ecosystem.as_str(),
        list.names(),
        list.provenance()
    )))
}

/// Open `url` for `ecosystem` through whoever serves it.
pub(crate) fn open(
    sources: &Sources,
    ecosystem: Ecosystem,
    url: &str,
) -> io::Result<(Box<dyn Read>, Option<u64>)> {
    open_through(clients::process, sources, ecosystem, url)
}

/// [`open`] with the clients a configured registry's request goes through.
fn open_through<'c>(
    clients: impl FnOnce() -> io::Result<&'c Clients>,
    sources: &Sources,
    ecosystem: Ecosystem,
    url: &str,
) -> io::Result<(Box<dyn Read>, Option<u64>)> {
    match source_for(sources, ecosystem, url)? {
        Served::Public => open_url(url, "download", None),
        Served::Registry(registry) => open_configured(clients()?, sources, registry, url, None)
            .map(|opened| (opened.reader, opened.declared)),
    }
}

/// A page a configured registry serves (a simple API project page): its
/// body, at most `max` bytes, and the URL it was finally served from,
/// which relative links resolve against. `None` when the registry answers
/// 404.
pub(crate) fn fetch_page(
    sources: &Sources,
    registry: &Registry,
    url: &str,
    accept: &str,
    max: u64,
) -> io::Result<Option<(Vec<u8>, String)>> {
    fetch_page_through(clients::process()?, sources, registry, url, accept, max)
}

fn fetch_page_through(
    clients: &Clients,
    sources: &Sources,
    registry: &Registry,
    url: &str,
    accept: &str,
    max: u64,
) -> io::Result<Option<(Vec<u8>, String)>> {
    let opened = match open_configured(clients, sources, registry, url, Some(accept)) {
        Ok(opened) => opened,
        Err(error) if super::http_status(&error) == Some(404) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut body = Vec::new();
    opened
        .reader
        .take(max + 1)
        .read_to_end(&mut body)
        .map_err(|error| super::read_failure(&opened.url, error))?;
    if body.len() as u64 > max {
        return Err(io::Error::other(format!(
            "{}: larger than {max} bytes; refusing",
            shown_url(&opened.url)
        )));
    }
    Ok(Some((body, opened.url)))
}

/// One configured registry's answer: the body, its declared length, and
/// the URL that served it after redirects.
struct Opened {
    reader: Box<dyn Read>,
    declared: Option<u64>,
    url: String,
}

/// The public registry's hosts for `ecosystem`, as the proxy's public
/// routes name them.
pub fn is_public(ecosystem: Ecosystem, url: &str) -> bool {
    let hosts: &[&str] = match ecosystem {
        Ecosystem::Python => &["pypi.org", "files.pythonhosted.org"],
        Ecosystem::Node => &["registry.npmjs.org"],
        Ecosystem::Go => &["proxy.golang.org", "sum.golang.org"],
        Ecosystem::Cargo => &["index.crates.io", "static.crates.io", "crates.io"],
        Ecosystem::Ruby => &["rubygems.org", "index.rubygems.org"],
        Ecosystem::Dotnet => &["api.nuget.org"],
        Ecosystem::Elixir => &["repo.hex.pm"],
    };
    hosts
        .iter()
        .any(|host| covers(&format!("https://{host}/"), url))
}

fn has_userinfo(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    rest[..end].contains('@')
}

/// One configured registry's download: its credential under its root, its
/// client, redirects bound to its root and `files` origins.
fn open_configured(
    clients: &Clients,
    sources: &Sources,
    registry: &Registry,
    url: &str,
    accept: Option<&str>,
) -> io::Result<Opened> {
    let credential = match &registry.credential {
        None => None,
        Some(name) => {
            let spec = sources.credential(name).ok_or_else(|| {
                io::Error::other(format!(
                    "registry {} names credential {name}, which the machine policy does not declare",
                    registry.name
                ))
            })?;
            Some(Credential::new(registry, name, spec))
        }
    };
    let client = clients
        .for_spec(&ClientSpec {
            ca: registry.ca.clone(),
            network: registry.network,
        })
        .map_err(io::Error::other)?;
    let owns = |hop: &str| {
        covers(&registry.root, hop) || registry.files.iter().any(|files| covers(files, hop))
    };
    let authorize = |hop: &str| {
        if owns(hop) {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "download {}: {} is outside registry {}'s root and files origins; refusing",
                shown_url(url),
                shown_url(hop),
                registry.name
            ),
        ))
    };
    follow_redirects(url, authorize, |hop| {
        let mut headers = vec![("User-Agent".to_string(), super::USER_AGENT.to_string())];
        if let Some(accept) = accept {
            headers.push(("Accept".to_string(), accept.to_string()));
        }
        if let Some(credential) = &credential {
            if covers(&registry.root, hop) {
                let secret = credential.authorization().map_err(io::Error::other)?;
                headers.push(("Authorization".to_string(), secret.expose().to_string()));
            }
        }
        let response = client
            .send(&PinnedRequest {
                method: "GET",
                url: hop,
                headers: &headers,
                body: None,
            })
            .map_err(|failure| transport_failure(hop, failure))?;
        let status = response.status;
        if (300..400).contains(&status) {
            let location = response.header("Location").ok_or_else(|| {
                io::Error::other(format!(
                    "download {}: redirect {status} names no Location",
                    shown_url(hop)
                ))
            })?;
            return Ok(Hop::Redirect(location.to_string()));
        }
        if !(200..300).contains(&status) {
            return Err(io::Error::other(StatusFailure {
                code: status,
                message: format!(
                    "download {}: registry {} answered {status}",
                    shown_url(hop),
                    registry.name
                ),
            }));
        }
        let declared = response
            .header("Content-Length")
            .and_then(|value| value.trim().parse::<u64>().ok());
        Ok(Hop::Body(Opened {
            reader: response.body,
            declared,
            url: hop.to_string(),
        }))
    })
}

/// A failure to get any response: a refused address is permanent, every
/// other transport failure may pass on a retry.
fn transport_failure(url: &str, failure: PinnedError) -> io::Error {
    let message = format!("download {}: {failure}", shown_url(url));
    match failure {
        PinnedError::Refused(_) => io::Error::new(io::ErrorKind::PermissionDenied, message),
        PinnedError::Transport(_) => {
            error::new(error::Class::Network, io::ErrorKind::Other, message)
        }
        PinnedError::Invalid(_) => io::Error::other(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::{self, Policy, SourceOrigin};
    use std::path::Path;

    fn with_sources(python: &str) -> Policy {
        let text = format!(
            r#"
[[registry]]
name = "corp"
ecosystem = "python"
url = "https://nexus.corp.example/repository/pypi/simple/"
root = "https://nexus.corp.example/repository/pypi/"
files = ["https://cdn.corp.example/"]

[[registry]]
name = "team"
ecosystem = "python"
url = "https://nexus.corp.example/repository/pypi/team/simple/"
root = "https://nexus.corp.example/repository/pypi/team/"

[sources]
python = {python}
"#
        );
        let path = Path::new("/machine/policy.toml");
        let other = policy::parse_file(path, &text).unwrap();
        let mut merged = Policy::default();
        policy::merge_file(&mut merged, &other, SourceOrigin::Machine, path).unwrap();
        merged
    }

    fn served<'a>(policy: &'a Policy, url: &str) -> io::Result<Served<'a>> {
        source_for(&policy.registries, Ecosystem::Python, url)
    }

    fn name(served: Served<'_>) -> &str {
        match served {
            Served::Public => "public",
            Served::Registry(registry) => &registry.name,
        }
    }

    #[test]
    fn the_longest_root_then_a_files_origin_serves_a_url() {
        let policy = with_sources(r#"["corp", "team"]"#);
        let at = |url: &str| name(served(&policy, url).unwrap()).to_string();
        assert_eq!(
            at("https://nexus.corp.example/repository/pypi/packages/a.whl"),
            "corp"
        );
        assert_eq!(
            at("https://nexus.corp.example/repository/pypi/team/packages/a.whl"),
            "team"
        );
        assert_eq!(at("https://cdn.corp.example/blobs/a.whl"), "corp");
    }

    #[test]
    fn an_enforced_list_refuses_what_it_does_not_cover() {
        let policy = with_sources(r#"["corp"]"#);
        for url in [
            "https://files.pythonhosted.org/packages/a.whl",
            "https://nexus.corp.example/repository/other/a.whl",
            "https://nexus.corp.example/repository/pypi/../other/a.whl",
        ] {
            let error = served(&policy, url).unwrap_err().to_string();
            assert!(error.contains("not served by any registry"), "{error}");
            assert!(error.contains("fix:"), "{error}");
        }
        let with_public = with_sources(r#"["corp", "public"]"#);
        assert_eq!(
            served(
                &with_public,
                "https://files.pythonhosted.org/packages/a.whl"
            )
            .unwrap(),
            Served::Public
        );
        assert!(served(&with_public, "https://elsewhere.example/a.whl").is_err());
    }

    #[test]
    fn a_default_ecosystem_takes_the_public_path_and_userinfo_is_refused() {
        let policy = Policy::default();
        assert_eq!(
            served(&policy, "https://elsewhere.example/a.whl").unwrap(),
            Served::Public
        );
        let error = served(&policy, "https://u:p@files.pythonhosted.org/a.whl")
            .unwrap_err()
            .to_string();
        assert!(error.contains("may not carry credentials"), "{error}");
        assert!(!error.contains("u:p"), "{error}");
    }

    mod fixture {
        use super::super::*;
        use crate::kernel::policy::{self, Policy, SourceOrigin};
        use crate::kernel::resolve::clients::ClientBase;
        use crate::kernel::resolve::testing::Answers;
        use crate::kernel::testutil::upstream::{Behavior, FixtureCa, FixtureUpstream, Reply};
        use std::path::Path;
        use std::sync::Arc;
        use std::time::Duration;

        const TOKEN: &str = "fetch-token-0123456789abcdef";

        struct Fixture {
            upstream: FixtureUpstream,
            clients: Clients,
            policy: Policy,
            _temp: crate::kernel::testutil::TempDir,
        }

        /// A registry whose root needs the token, with a `files` origin on
        /// cdn.test, all served by one local fixture.
        fn fixture() -> Fixture {
            use std::os::unix::fs::PermissionsExt;
            let ca = FixtureCa::new();
            let upstream = FixtureUpstream::start(&ca, &["registry.test", "cdn.test", "evil.test"]);
            let port = upstream.port();
            let temp = crate::kernel::testutil::TempDir::new();
            let token = temp.0.join("token");
            std::fs::write(&token, TOKEN).unwrap();
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
            let text = format!(
                r#"
[credentials.corp]
file = "{}"

[[registry]]
name = "corp"
ecosystem = "python"
url = "https://registry.test:{port}/repo/pypi/simple/"
root = "https://registry.test:{port}/repo/pypi/"
credential = "corp"
files = ["https://cdn.test:{port}/"]

[sources]
python = ["corp"]
"#,
                token.display()
            );
            let path = Path::new("/machine/policy.toml");
            let parsed = policy::parse_file(path, &text).unwrap();
            let mut merged = Policy::default();
            policy::merge_file(&mut merged, &parsed, SourceOrigin::Machine, path).unwrap();
            let clients = Clients::new(ClientBase {
                roots: ca.roots(),
                lookup: Arc::new(Answers::new(|_, _| vec!["127.0.0.1".parse().unwrap()])),
                connect_timeout: Duration::from_secs(2),
                io_timeout: Duration::from_secs(2),
                allow_loopback: true,
                connect_to: None,
            })
            .unwrap();
            Fixture {
                upstream,
                clients,
                policy: merged,
                _temp: temp,
            }
        }

        impl Fixture {
            fn url(&self, host: &str, path: &str) -> String {
                format!("https://{host}:{}{path}", self.upstream.port())
            }

            fn get(&self, url: &str) -> io::Result<Vec<u8>> {
                let (mut reader, _) = open_through(
                    || Ok(&self.clients),
                    &self.policy.registries,
                    Ecosystem::Python,
                    url,
                )?;
                let mut body = Vec::new();
                reader.read_to_end(&mut body)?;
                Ok(body)
            }

            fn authorization_at(&self, target: &str) -> Vec<Option<String>> {
                self.upstream
                    .seen()
                    .iter()
                    .filter(|seen| seen.target == target)
                    .map(|seen| seen.headers.get("authorization").map(str::to_string))
                    .collect()
            }
        }

        #[test]
        fn the_credential_goes_under_the_root_only_and_redirects_stay_in_the_registry() {
            let fx = fixture();
            let up = &fx.upstream;
            up.set(
                "/repo/pypi/packages/a.whl",
                Behavior::Authorized {
                    value: format!("Bearer {TOKEN}"),
                    reply: Reply::new(200, b"wheel bytes"),
                },
            );
            assert_eq!(
                fx.get(&fx.url("registry.test", "/repo/pypi/packages/a.whl"))
                    .unwrap(),
                b"wheel bytes"
            );

            // A redirect to the files origin is followed without the
            // credential.
            up.set(
                "/repo/pypi/packages/b.whl",
                Behavior::Authorized {
                    value: format!("Bearer {TOKEN}"),
                    reply: Reply::new(302, b"")
                        .header("Location", &fx.url("cdn.test", "/blobs/b.whl?sig=1")),
                },
            );
            up.set(
                "/blobs/b.whl?sig=1",
                Behavior::Reply(Reply::new(200, b"cdn bytes")),
            );
            assert_eq!(
                fx.get(&fx.url("registry.test", "/repo/pypi/packages/b.whl"))
                    .unwrap(),
                b"cdn bytes"
            );
            assert_eq!(fx.authorization_at("/blobs/b.whl?sig=1"), [None]);

            // A redirect off the registry is refused before any request,
            // and so is one into another repository on the same host.
            for target in [
                fx.url("evil.test", "/c.whl"),
                fx.url("registry.test", "/repo/other/c.whl"),
            ] {
                up.set(
                    "/repo/pypi/packages/c.whl",
                    Behavior::Reply(Reply::new(302, b"").header("Location", &target)),
                );
                let error = fx
                    .get(&fx.url("registry.test", "/repo/pypi/packages/c.whl"))
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("outside registry corp"), "{error}");
                assert!(!error.contains(TOKEN), "{error}");
            }
            assert!(fx.authorization_at("/c.whl").is_empty());
            assert!(fx.authorization_at("/repo/other/c.whl").is_empty());

            // A wrong answer keeps its status and never shows the token.
            up.set(
                "/repo/pypi/packages/d.whl",
                Behavior::Reply(Reply::new(404, b"")),
            );
            let error = fx
                .get(&fx.url("registry.test", "/repo/pypi/packages/d.whl"))
                .unwrap_err();
            assert_eq!(super::super::super::http_status(&error), Some(404));
            assert!(!error.to_string().contains(TOKEN));
        }

        /// A simple page is read with the credential and the Accept asked
        /// for, and comes back with the URL that served it; a 404 is no
        /// page.
        #[test]
        fn a_page_comes_back_with_the_url_that_served_it() {
            let fx = fixture();
            let registry = fx.policy.registries.registry("corp").unwrap();
            fx.upstream.set(
                "/repo/pypi/simple/demo/",
                Behavior::Authorized {
                    value: format!("Bearer {TOKEN}"),
                    reply: Reply::new(
                        200,
                        b"<a href=\"../../packages/demo-1.0.tar.gz#sha256=00\">x</a>",
                    ),
                },
            );
            let url = fx.url("registry.test", "/repo/pypi/simple/demo/");
            let (body, served) = fetch_page_through(
                &fx.clients,
                &fx.policy.registries,
                registry,
                &url,
                "application/vnd.pypi.simple.v1+json",
                1 << 20,
            )
            .unwrap()
            .unwrap();
            assert!(body.starts_with(b"<a href"));
            assert_eq!(served, url);
            let seen = fx.upstream.seen();
            let request = seen
                .iter()
                .find(|seen| seen.target == "/repo/pypi/simple/demo/")
                .unwrap();
            assert_eq!(
                request.headers.get("accept"),
                Some("application/vnd.pypi.simple.v1+json")
            );
            let missing = fx.url("registry.test", "/repo/pypi/simple/nope/");
            fx.upstream.set(
                "/repo/pypi/simple/nope/",
                Behavior::Reply(Reply::new(404, b"")),
            );
            assert!(fetch_page_through(
                &fx.clients,
                &fx.policy.registries,
                registry,
                &missing,
                "text/html",
                1 << 20
            )
            .unwrap()
            .is_none());
        }
    }
}
