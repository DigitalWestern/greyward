//! The policy-file grammar of private registries: `[credentials.<name>]`,
//! `[[registry]]` and `[sources]` (docs/agent/DESIGNS.md §4 "Private
//! registries"). Parsing and validation here are pure: no file, variable or
//! network is touched. Secrets are read later, lazily, by
//! [`super::credential`]; a [`CredentialSpec`] only says where one lives.

use super::covers;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// The name `[sources]` uses for an ecosystem's shipped public registry.
pub const PUBLIC: &str = "public";

/// An ecosystem as `[[registry]] ecosystem` and `[sources]` spell it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    Python,
    Node,
    Go,
    Cargo,
    Ruby,
    Dotnet,
    Elixir,
}

impl Ecosystem {
    pub const ALL: [Ecosystem; 7] = [
        Ecosystem::Python,
        Ecosystem::Node,
        Ecosystem::Go,
        Ecosystem::Cargo,
        Ecosystem::Ruby,
        Ecosystem::Dotnet,
        Ecosystem::Elixir,
    ];

    pub fn parse(text: &str) -> Option<Ecosystem> {
        Ecosystem::ALL.into_iter().find(|eco| eco.as_str() == text)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Python => "python",
            Ecosystem::Node => "node",
            Ecosystem::Go => "go",
            Ecosystem::Cargo => "cargo",
            Ecosystem::Ruby => "ruby",
            Ecosystem::Dotnet => "dotnet",
            Ecosystem::Elixir => "elixir",
        }
    }

    /// Whether this ward wires private registries for the ecosystem. Any
    /// other ecosystem is refused at load, so none is ever enforced on paper
    /// while its doors still use the public registry.
    pub fn wired(self) -> bool {
        matches!(self, Ecosystem::Python | Ecosystem::Node)
    }

    /// The shipped public registry's `url`, normalized like a configured one.
    pub fn public_url(self) -> &'static str {
        match self {
            Ecosystem::Python => "https://pypi.org/simple/",
            Ecosystem::Node => "https://registry.npmjs.org/",
            Ecosystem::Go => "https://proxy.golang.org/",
            Ecosystem::Cargo => "https://index.crates.io/",
            Ecosystem::Ruby => "https://rubygems.org/",
            Ecosystem::Dotnet => "https://api.nuget.org/v3/index.json",
            Ecosystem::Elixir => "https://repo.hex.pm/",
        }
    }
}

/// `[credentials.<name>]`: where a secret lives, never the secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub netrc: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<Scheme>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Bearer,
    Basic,
    Raw,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Bearer => "bearer",
            Scheme::Basic => "basic",
            Scheme::Raw => "raw",
        }
    }
}

impl CredentialSpec {
    /// The scheme in force: `basic` for netrc, else `bearer` when unset.
    pub fn scheme(&self) -> Scheme {
        self.scheme.unwrap_or(if self.netrc {
            Scheme::Basic
        } else {
            Scheme::Bearer
        })
    }

    /// Where the secret lives, spelled for errors and cache keys:
    /// `env:NAME`, `file:/path` or `netrc`.
    pub fn source(&self) -> String {
        if let Some(name) = &self.env {
            format!("env:{name}")
        } else if let Some(path) = &self.file {
            format!("file:{}", path.display())
        } else {
            "netrc".into()
        }
    }

    fn validate(&self, name: &str) -> Result<(), String> {
        let sources = usize::from(self.env.is_some())
            + usize::from(self.file.is_some())
            + usize::from(self.netrc);
        if sources != 1 {
            return Err(format!(
                "[credentials.{name}] must set exactly one of env, file or netrc"
            ));
        }
        if let Some(var) = &self.env {
            if var.is_empty() || var.contains('=') || var.contains('\0') {
                return Err(format!(
                    "[credentials.{name}] env {var:?} is not a variable name"
                ));
            }
        }
        if let Some(path) = &self.file {
            if !path.is_absolute() {
                return Err(format!(
                    "[credentials.{name}] file {} must be an absolute path",
                    path.display()
                ));
            }
        }
        match (self.scheme(), self.netrc, &self.username) {
            (Scheme::Basic, false, None) => Err(format!(
                "[credentials.{name}] scheme \"basic\" with env or file needs a username"
            )),
            (Scheme::Basic, true, Some(_)) => Err(format!(
                "[credentials.{name}] netrc gives the username; remove username"
            )),
            (Scheme::Bearer | Scheme::Raw, true, _) => Err(format!(
                "[credentials.{name}] netrc gives a basic credential; set scheme = \"basic\" or leave it out"
            )),
            (Scheme::Bearer | Scheme::Raw, false, Some(_)) => Err(format!(
                "[credentials.{name}] username is used only with scheme = \"basic\""
            )),
            (_, _, Some(user)) if user.contains(':') || user.is_empty() => Err(format!(
                "[credentials.{name}] username must be non-empty and hold no ':'"
            )),
            _ => Ok(()),
        }
    }
}

/// `network`: which addresses a registry's hosts may resolve to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    #[default]
    Public,
    Private,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::Public => "public",
            NetworkMode::Private => "private",
        }
    }
}

/// One `[[registry]]` entry, as written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySpec {
    pub name: String,
    pub ecosystem: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_of: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nosumdb: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sumdb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex_public_key: Option<PathBuf>,
}

/// A `[[registry]]` entry after validation: the URL forms normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registry {
    pub name: String,
    pub ecosystem: Ecosystem,
    /// `https://host[:port]/path/`, host lowercased, default port dropped.
    /// Cargo's `sparse+` prefix is not part of it.
    pub url: String,
    /// The path prefix every URL of this registry on its origin lives under,
    /// and the only one its credential is sent to. Defaults to `url` (for
    /// .NET, the directory of the service index).
    pub root: String,
    /// Download-only origins, `https://host[:port]/`.
    pub files: Vec<String>,
    pub credential: Option<String>,
    pub network: NetworkMode,
    pub ca: Option<PathBuf>,
    pub scopes: Vec<String>,
    pub mirror_of_public: bool,
}

impl Registry {
    /// `https://host[:port]` of `url`.
    pub fn origin(&self) -> &str {
        origin_of(&self.url)
    }
}

/// The origin part of an already-normalized URL.
pub(crate) fn origin_of(url: &str) -> &str {
    let rest = &url["https://".len()..];
    let end = rest.find('/').unwrap_or(rest.len());
    &url[.."https://".len() + end]
}

/// Validate and normalize every `[[registry]]` of one file. Cross-checks
/// against `[credentials]` are made by the caller that knows the machine
/// scope's credentials.
pub fn validate_registries(
    specs: &[RegistrySpec],
    credentials: &BTreeMap<String, CredentialSpec>,
) -> Result<Vec<Registry>, String> {
    for (name, spec) in credentials {
        check_name(name, "[credentials]")?;
        spec.validate(name)?;
    }
    let mut out: Vec<Registry> = Vec::new();
    let mut names = BTreeSet::new();
    let mut scopes = BTreeSet::new();
    let mut files_owner: BTreeMap<String, String> = BTreeMap::new();
    for spec in specs {
        let registry = validate_one(spec)?;
        if !names.insert(registry.name.clone()) {
            return Err(format!("[[registry]] {} is declared twice", registry.name));
        }
        if let Some(credential) = &registry.credential {
            if !credentials.contains_key(credential) {
                return Err(format!(
                    "[[registry]] {} names credential {credential:?}, which no [credentials.{credential}] table declares",
                    registry.name
                ));
            }
        }
        for scope in &registry.scopes {
            if !scopes.insert(scope.clone()) {
                return Err(format!(
                    "[[registry]] {}: scope {scope} is listed by two registries",
                    registry.name
                ));
            }
        }
        for files in &registry.files {
            if let Some(owner) = files_owner.insert(files.clone(), registry.name.clone()) {
                return Err(format!(
                    "[[registry]] {}: files origin {files} is already listed by {owner}; a download origin belongs to one registry",
                    registry.name
                ));
            }
        }
        out.push(registry);
    }
    for registry in &out {
        for files in &registry.files {
            if let Some(other) = out
                .iter()
                .find(|other| other.origin() == files.trim_end_matches('/'))
            {
                return Err(format!(
                    "[[registry]] {}: files origin {files} is the url origin of {}; a files origin must be a host no registry is served from",
                    registry.name, other.name
                ));
            }
        }
    }
    for (i, a) in out.iter().enumerate() {
        for b in &out[i + 1..] {
            if a.root == b.root
                && (a.credential != b.credential || a.network != b.network || a.ca != b.ca)
            {
                return Err(format!(
                    "[[registry]] {} and {} have the same root {} but different credential, network or ca; give them one setting or different roots",
                    a.name, b.name, a.root
                ));
            }
        }
    }
    Ok(out)
}

fn check_name(name: &str, table: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "{table} name {name:?} must be lowercase letters, digits and -"
        ));
    }
    Ok(())
}

fn validate_one(spec: &RegistrySpec) -> Result<Registry, String> {
    let name = &spec.name;
    check_name(name, "[[registry]]")?;
    if name == PUBLIC {
        return Err(format!(
            "[[registry]] name {PUBLIC:?} is reserved for the shipped public registry"
        ));
    }
    let ecosystem = Ecosystem::parse(&spec.ecosystem).ok_or_else(|| {
        format!(
            "[[registry]] {name}: unknown ecosystem {:?}; one of {}",
            spec.ecosystem,
            Ecosystem::ALL.map(Ecosystem::as_str).join(", ")
        )
    })?;
    let fail = |what: String| format!("[[registry]] {name}: {what}");
    let url = match ecosystem {
        Ecosystem::Cargo => {
            let Some(rest) = spec.url.strip_prefix("sparse+") else {
                return Err(fail(format!(
                    "url {:?} must be a sparse index, sparse+https://...; git indexes are not supported",
                    spec.url
                )));
            };
            normalize(rest, true).map_err(|e| fail(format!("url: {e}")))?
        }
        Ecosystem::Dotnet => {
            let url = normalize(&spec.url, false).map_err(|e| fail(format!("url: {e}")))?;
            if !url.ends_with(".json") {
                return Err(fail(format!(
                    "url {:?} must be the NuGet v3 service index (…/index.json)",
                    spec.url
                )));
            }
            url
        }
        _ => normalize(&spec.url, true).map_err(|e| fail(format!("url: {e}")))?,
    };
    let default_root = match ecosystem {
        Ecosystem::Dotnet => {
            url[..url.rfind('/').expect("normalized url has a path") + 1].to_string()
        }
        _ => url.clone(),
    };
    let root = match &spec.root {
        None => default_root,
        Some(root) => {
            let root = normalize(root, true).map_err(|e| fail(format!("root: {e}")))?;
            if origin_of(&root) != origin_of(&url) || !url.starts_with(&root) {
                return Err(fail(format!(
                    "root {root} must be on the url's origin and a path prefix of url {url}"
                )));
            }
            root
        }
    };
    let mut files = Vec::new();
    for entry in &spec.files {
        let normalized = normalize(entry, true).map_err(|e| fail(format!("files: {e}")))?;
        if normalized.trim_end_matches('/') != origin_of(&normalized) {
            return Err(fail(format!(
                "files entry {entry:?} must be an origin only, https://host[:port]/"
            )));
        }
        files.push(normalized);
    }
    if !spec.scopes.is_empty() && ecosystem != Ecosystem::Node {
        return Err(fail("scopes is used only by node registries".into()));
    }
    for scope in &spec.scopes {
        let valid = scope.strip_prefix('@').is_some_and(|rest| {
            !rest.is_empty()
                && rest.bytes().all(|b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || matches!(b, b'-' | b'.' | b'_' | b'~')
                })
        });
        if !valid {
            return Err(fail(format!("scope {scope:?} must be @name, lowercase")));
        }
    }
    let mirror_of_public = match spec.mirror_of.as_deref() {
        None => false,
        Some(PUBLIC)
            if matches!(
                ecosystem,
                Ecosystem::Cargo | Ecosystem::Ruby | Ecosystem::Elixir
            ) =>
        {
            true
        }
        Some(PUBLIC) => {
            return Err(fail(
                "mirror_of is used only by cargo, ruby and elixir registries".into(),
            ))
        }
        Some(other) => {
            return Err(fail(format!(
                "mirror_of {other:?}: the only value is \"public\""
            )))
        }
    };
    if (!spec.nosumdb.is_empty() || spec.sumdb.is_some()) && ecosystem != Ecosystem::Go {
        return Err(fail(
            "nosumdb and sumdb are used only by go registries".into(),
        ));
    }
    if let Some(sumdb) = &spec.sumdb {
        if sumdb != "direct" && sumdb != "registry" {
            return Err(fail(format!(
                "sumdb {sumdb:?}: one of \"direct\", \"registry\""
            )));
        }
    }
    if spec.hex_public_key.is_some() && ecosystem != Ecosystem::Elixir {
        return Err(fail(
            "hex_public_key is used only by elixir registries".into(),
        ));
    }
    for path in [&spec.ca, &spec.hex_public_key].into_iter().flatten() {
        if !path.is_absolute() {
            return Err(fail(format!("{} must be an absolute path", path.display())));
        }
    }
    Ok(Registry {
        name: name.clone(),
        ecosystem,
        url,
        root,
        files,
        credential: spec.credential.clone(),
        network: spec.network.unwrap_or_default(),
        ca: spec.ca.clone(),
        scopes: spec.scopes.clone(),
        mirror_of_public,
    })
}

/// `https://host[:port]/path`, refused with userinfo, query or fragment,
/// with a path that is not clean (see [`covers`]), or one the URL parser
/// would rewrite. The host is lowercased and `:443` dropped; with
/// `directory`, a missing trailing `/` is added.
pub fn normalize(raw: &str, directory: bool) -> Result<String, String> {
    if !raw.starts_with("https://") {
        return Err(format!("{raw:?} must be an https:// URL"));
    }
    if raw.contains(['?', '#']) {
        return Err(format!("{raw:?} must not carry a query or fragment"));
    }
    let parsed = url::Url::parse(raw).map_err(|e| format!("{raw:?}: {e}"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "{raw:?} must not carry a user or password; put the secret in [credentials]"
        ));
    }
    let Some(host) = parsed.host_str() else {
        return Err(format!("{raw:?} has no host"));
    };
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let raw_path = {
        let rest = &raw["https://".len()..];
        rest.find('/').map_or("/", |i| &rest[i..])
    };
    if !covers::path_is_clean(raw_path) || parsed.path() != raw_path {
        return Err(format!(
            "{raw:?} has a path with dot segments, empty segments, backslashes or escapes"
        ));
    }
    let mut path = parsed.path().to_string();
    if directory && !path.ends_with('/') {
        path.push('/');
    }
    Ok(format!("https://{authority}{path}"))
}

/// Validate one file's `[sources]` table: known ecosystems, non-empty
/// unique names.
pub fn validate_sources(sources: &BTreeMap<String, Vec<String>>) -> Result<(), String> {
    for (eco, names) in sources {
        if Ecosystem::parse(eco).is_none() {
            return Err(format!(
                "[sources] {eco}: unknown ecosystem; one of {}",
                Ecosystem::ALL.map(Ecosystem::as_str).join(", ")
            ));
        }
        let mut seen = BTreeSet::new();
        for name in names {
            if !seen.insert(name) {
                return Err(format!("[sources] {eco} names {name} twice"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, ecosystem: &str, url: &str) -> RegistrySpec {
        RegistrySpec {
            name: name.into(),
            ecosystem: ecosystem.into(),
            url: url.into(),
            credential: None,
            root: None,
            files: vec![],
            network: None,
            ca: None,
            scopes: vec![],
            mirror_of: None,
            nosumdb: vec![],
            sumdb: None,
            hex_public_key: None,
        }
    }

    fn one(spec: RegistrySpec) -> Result<Registry, String> {
        validate_registries(&[spec], &BTreeMap::new()).map(|mut v| v.remove(0))
    }

    #[test]
    fn urls_are_normalized_per_ecosystem() {
        let r = one(spec(
            "corp",
            "python",
            "https://Nexus.Corp.example:443/repository/pypi/simple",
        ))
        .unwrap();
        assert_eq!(r.url, "https://nexus.corp.example/repository/pypi/simple/");
        assert_eq!(r.root, r.url);
        assert_eq!(r.origin(), "https://nexus.corp.example");
        let r = one(spec(
            "crates",
            "cargo",
            "sparse+https://a.example/api/cargo/c/index/",
        ))
        .unwrap();
        assert_eq!(r.url, "https://a.example/api/cargo/c/index/");
        assert!(one(spec("crates", "cargo", "https://a.example/index/")).is_err());
        let r = one(spec(
            "feed",
            "dotnet",
            "https://a.example/api/nuget/v3/feed/index.json",
        ))
        .unwrap();
        assert_eq!(r.url, "https://a.example/api/nuget/v3/feed/index.json");
        assert_eq!(r.root, "https://a.example/api/nuget/v3/feed/");
        assert!(one(spec(
            "feed",
            "dotnet",
            "https://a.example/api/nuget/v3/feed/"
        ))
        .is_err());
    }

    #[test]
    fn bad_urls_are_refused() {
        for url in [
            "http://a.example/simple/",
            "https://user:pw@a.example/simple/",
            "https://a.example/simple/?token=x",
            "https://a.example/simple/#x",
            "https://a.example/a/../simple/",
            "https://a.example/a/%2e%2e/simple/",
            "https://a.example/a//simple/",
        ] {
            assert!(one(spec("corp", "python", url)).is_err(), "{url}");
        }
    }

    #[test]
    fn root_must_prefix_url_on_its_origin() {
        let mut s = spec(
            "corp",
            "python",
            "https://n.example/repository/pypi/simple/",
        );
        s.root = Some("https://n.example/repository/pypi".into());
        assert_eq!(
            one(s.clone()).unwrap().root,
            "https://n.example/repository/pypi/"
        );
        s.root = Some("https://n.example/repository/other/".into());
        assert!(one(s.clone()).is_err());
        s.root = Some("https://m.example/repository/pypi/".into());
        assert!(one(s).is_err());
    }

    #[test]
    fn field_per_ecosystem_rules() {
        let mut s = spec("corp", "python", "https://n.example/simple/");
        s.scopes = vec!["@corp".into()];
        assert!(one(s).is_err());
        let mut s = spec("corp", "node", "https://n.example/npm/");
        s.scopes = vec!["corp".into()];
        assert!(one(s).is_err());
        let mut s = spec("corp", "node", "https://n.example/npm/");
        s.mirror_of = Some("public".into());
        assert!(one(s).is_err());
        let mut s = spec("corp", "ruby", "https://n.example/gems/");
        s.mirror_of = Some("public".into());
        assert!(one(s).unwrap().mirror_of_public);
        let mut s = spec("corp", "python", "https://n.example/simple/");
        s.nosumdb = vec!["corp.example/*".into()];
        assert!(one(s).is_err());
        let mut s = spec("corp", "python", "https://n.example/simple/");
        s.hex_public_key = Some("/k.pem".into());
        assert!(one(s).is_err());
        assert!(one(spec("public", "python", "https://n.example/simple/")).is_err());
        assert!(one(spec("Corp", "python", "https://n.example/simple/")).is_err());
        assert!(one(spec("corp", "java", "https://n.example/simple/")).is_err());
    }

    #[test]
    fn files_origins_belong_to_one_registry_and_never_to_a_url_origin() {
        let mut a = spec("a", "node", "https://a.example/npm/");
        a.files = vec!["https://cdn.example".into()];
        let mut b = spec("b", "node", "https://b.example/npm/");
        b.files = vec!["https://cdn.example/".into()];
        assert!(validate_registries(&[a.clone(), b.clone()], &BTreeMap::new()).is_err());
        b.files = vec!["https://a.example/".into()];
        assert!(validate_registries(&[a.clone(), b.clone()], &BTreeMap::new()).is_err());
        b.files = vec!["https://cdn.example/path/".into()];
        assert!(validate_registries(&[a, b], &BTreeMap::new()).is_err());
    }

    #[test]
    fn equal_roots_must_agree() {
        let credentials = BTreeMap::from([(
            "corp".to_string(),
            CredentialSpec {
                env: Some("T".into()),
                ..Default::default()
            },
        )]);
        let a = spec("a", "python", "https://n.example/simple/");
        let mut b = spec("b", "node", "https://n.example/simple/");
        assert!(validate_registries(&[a.clone(), b.clone()], &credentials).is_ok());
        b.credential = Some("corp".into());
        assert!(validate_registries(&[a, b.clone()], &credentials).is_err());
        b.credential = Some("missing".into());
        assert!(validate_registries(&[b], &credentials).is_err());
    }

    #[test]
    fn credential_specs_are_checked() {
        let check = |spec: CredentialSpec| {
            validate_registries(&[], &BTreeMap::from([("c".to_string(), spec)]))
        };
        assert!(check(CredentialSpec::default()).is_err());
        assert!(check(CredentialSpec {
            env: Some("A".into()),
            netrc: true,
            ..Default::default()
        })
        .is_err());
        assert!(check(CredentialSpec {
            env: Some("A".into()),
            scheme: Some(Scheme::Basic),
            ..Default::default()
        })
        .is_err());
        assert!(check(CredentialSpec {
            env: Some("A".into()),
            scheme: Some(Scheme::Basic),
            username: Some("ci".into()),
            ..Default::default()
        })
        .is_ok());
        assert!(check(CredentialSpec {
            netrc: true,
            scheme: Some(Scheme::Bearer),
            ..Default::default()
        })
        .is_err());
        assert!(check(CredentialSpec {
            file: Some("relative".into()),
            ..Default::default()
        })
        .is_err());
        assert!(check(CredentialSpec {
            env: Some("A".into()),
            username: Some("ci".into()),
            ..Default::default()
        })
        .is_err());
    }
}
