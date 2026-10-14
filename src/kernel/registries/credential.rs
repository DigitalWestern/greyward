//! Registry credentials, read lazily. A [`Credential`] is a reference: which registry, which
//! `[credentials]` entry, which host. Its secret is read the first time a
//! request inside the registry's root is sent upstream, once per process;
//! the result, a failure included, is kept for every later request. The
//! secret lives in [`Secret`], whose `Debug` prints `…`, and never enters
//! `Policy`, a lock, a closure, a log or an error.

use super::config::{CredentialSpec, Registry, Scheme};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// A secret value: a token, a password, or a whole `Authorization` value.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Tests only: a value given directly.
    #[cfg(test)]
    pub(crate) fn fixed(value: &str) -> Secret {
        Secret(value.to_string())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("…")
    }
}

/// What a credential source gave: a secret, and for netrc its login.
#[derive(Clone, PartialEq, Eq)]
struct Material {
    username: Option<String>,
    secret: Secret,
}

/// One registry's credential, unresolved.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    /// The registry it authenticates, for error text and the URL check.
    registry: String,
    registry_urls: Vec<String>,
    host: String,
    name: String,
    spec: CredentialSpec,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("registry", &self.registry)
            .field("name", &self.name)
            .field("source", &self.spec.source())
            .finish()
    }
}

impl Credential {
    pub fn new(registry: &Registry, name: &str, spec: &CredentialSpec) -> Credential {
        let host = url::Url::parse(&registry.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .unwrap_or_default();
        let mut registry_urls = vec![registry.url.clone(), registry.root.clone()];
        registry_urls.extend(registry.files.iter().cloned());
        Credential {
            registry: registry.name.clone(),
            registry_urls,
            host,
            name: name.to_string(),
            spec: spec.clone(),
        }
    }

    /// The whole reference, spelled for the metadata cache key: no secret,
    /// and no read of one. `netrc` names the file it would read and the
    /// host it would look up.
    pub fn reference(&self) -> String {
        let source = if self.spec.netrc {
            let path = netrc_path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|error| format!("<{error}>"));
            format!("netrc:{path}:{}", self.host)
        } else {
            self.spec.source()
        };
        format!(
            "{}|{source}|{}|{}",
            self.name,
            self.spec.scheme().as_str(),
            self.spec.username.as_deref().unwrap_or("")
        )
    }

    /// The `Authorization` value, read on first use and kept for the life
    /// of the process. An error names the registry, the credential and its
    /// source, never the value, and ends with a `fix:` line.
    pub fn authorization(&self) -> Result<Secret, String> {
        let material = resolved(&self.reference(), || self.read())?;
        let header = match self.spec.scheme() {
            Scheme::Bearer => format!("Bearer {}", material.secret.expose()),
            Scheme::Raw => material.secret.expose().to_string(),
            Scheme::Basic => {
                let user = self
                    .spec
                    .username
                    .as_deref()
                    .or(material.username.as_deref())
                    .unwrap_or("");
                format!(
                    "Basic {}",
                    crate::kernel::base64::encode(
                        format!("{user}:{}", material.secret.expose()).as_bytes()
                    )
                )
            }
        };
        if !crate::kernel::resolve::http::is_field_value(&header) {
            return Err(self.fail(
                "its value holds a character a header cannot carry (a newline or a control character)",
                "store the token alone, with no line breaks",
            ));
        }
        if self
            .registry_urls
            .iter()
            .any(|url| url.contains(material.secret.expose()))
        {
            return Err(self.fail(
                "its secret also appears in the registry's url, root or files; a token in a URL is written into locks and receipts",
                "use the registry URL without the token in [[registry]] url, and keep the token only in the credential",
            ));
        }
        Ok(Secret(header))
    }

    fn fail(&self, what: &str, fix: &str) -> String {
        format!(
            "registry {}: credential {} ({}): {what}\nfix: {fix}",
            self.registry,
            self.name,
            self.spec.source()
        )
    }

    fn read(&self) -> Result<Material, String> {
        if let Some(var) = &self.spec.env {
            let value = std::env::var(var).map_err(|error| match error {
                std::env::VarError::NotPresent => self.fail(
                    "the variable is not set",
                    &format!("set {var} to the registry token before running ward"),
                ),
                std::env::VarError::NotUnicode(_) => self.fail(
                    "the variable is not valid UTF-8",
                    &format!("set {var} to the registry token"),
                ),
            })?;
            if value.is_empty() {
                return Err(self.fail(
                    "the variable is empty",
                    &format!("set {var} to the registry token"),
                ));
            }
            return Ok(Material {
                username: None,
                secret: Secret(value),
            });
        }
        if let Some(path) = &self.spec.file {
            let text = read_private(path).map_err(|error| {
                self.fail(
                    &error,
                    "write the token to the file, mode 0600, owned by you",
                )
            })?;
            let value = text.strip_suffix('\n').unwrap_or(&text);
            let value = value.strip_suffix('\r').unwrap_or(value);
            if value.is_empty() {
                return Err(self.fail("the file is empty", "write the token to the file"));
            }
            return Ok(Material {
                username: None,
                secret: Secret(value.to_string()),
            });
        }
        let path = netrc_path().map_err(|error| {
            self.fail(
                &error,
                "set NETRC to the netrc file, or HOME to your home directory",
            )
        })?;
        let text = read_private(&path).map_err(|error| {
            self.fail(
                &format!("{}: {error}", path.display()),
                "create the netrc file, mode 0600, owned by you",
            )
        })?;
        match netrc_entry(&text, &self.host) {
            Some((login, password)) if !password.is_empty() => Ok(Material {
                username: Some(login),
                secret: Secret(password),
            }),
            _ => Err(self.fail(
                &format!(
                    "{} has no machine {} entry with a login and a password (a default entry is not used)",
                    path.display(),
                    self.host
                ),
                &format!(
                    "add 'machine {} login <user> password <token>' to {}",
                    self.host,
                    path.display()
                ),
            )),
        }
    }
}

type Cell = Arc<OnceLock<Result<Material, String>>>;

/// One resolution per reference per process, failures included.
fn resolved(
    reference: &str,
    read: impl FnOnce() -> Result<Material, String>,
) -> Result<Material, String> {
    static CELLS: OnceLock<Mutex<HashMap<String, Cell>>> = OnceLock::new();
    let cell = CELLS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .entry(reference.to_string())
        .or_default()
        .clone();
    cell.get_or_init(read).clone()
}

/// `$NETRC`, else `~/.netrc` through the shared home resolver.
fn netrc_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("NETRC") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(format!("NETRC {} is not an absolute path", path.display()));
        }
        return Ok(path);
    }
    crate::kernel::home::home()
        .map(|home| home.join(".netrc"))
        .map_err(|error| error.to_string())
}

/// Read a secret-holding file: a regular file opened without following a
/// symlink, owned by the current user, with no group or other bits.
fn read_private(path: &Path) -> Result<String, String> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) => "it is a symlink; point the policy at the file itself".into(),
            _ => format!("cannot open it: {error}"),
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot stat it: {error}"))?;
    if !metadata.is_file() {
        return Err("it is not a regular file".into());
    }
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    if metadata.uid() != uid {
        return Err(format!(
            "it is owned by uid {}, not by you (uid {uid})",
            metadata.uid()
        ));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "its mode is {mode:04o}; group and others must have no access (chmod 600)"
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| format!("cannot read it: {error}"))?;
    Ok(text)
}

/// The login and password of `machine <host>` in a netrc text. The
/// `default` entry is never used: a credential is sent only to a host the
/// file names. `macdef` bodies are skipped.
fn netrc_entry(text: &str, host: &str) -> Option<(String, String)> {
    let mut tokens = Tokens::new(text);
    let mut current: Option<bool> = None;
    let mut login = None;
    let mut password = None;
    while let Some(token) = tokens.next() {
        match token.as_str() {
            "machine" | "default" => {
                if current == Some(true) {
                    break;
                }
                current = Some(
                    token == "machine"
                        && tokens
                            .next()
                            .is_some_and(|name| name.eq_ignore_ascii_case(host)),
                );
                login = None;
                password = None;
            }
            "login" => login = tokens.next(),
            "password" => password = tokens.next(),
            "account" => {
                tokens.next();
            }
            "macdef" => {
                tokens.next();
                tokens.skip_macro();
            }
            _ => {}
        }
    }
    match (current, login, password) {
        (Some(true), Some(login), Some(password)) => Some((login, password)),
        _ => None,
    }
}

struct Tokens<'a> {
    rest: &'a str,
}

impl<'a> Tokens<'a> {
    fn new(text: &'a str) -> Self {
        Tokens { rest: text }
    }

    fn next(&mut self) -> Option<String> {
        self.rest = self.rest.trim_start();
        if self.rest.is_empty() {
            return None;
        }
        if let Some(quoted) = self.rest.strip_prefix('"') {
            let mut out = String::new();
            let mut chars = quoted.char_indices();
            while let Some((i, c)) = chars.next() {
                match c {
                    '"' => {
                        self.rest = &quoted[i + 1..];
                        return Some(out);
                    }
                    '\\' => {
                        if let Some((_, escaped)) = chars.next() {
                            out.push(escaped);
                        }
                    }
                    c => out.push(c),
                }
            }
            self.rest = "";
            return Some(out);
        }
        let end = self
            .rest
            .find(char::is_whitespace)
            .unwrap_or(self.rest.len());
        let token = self.rest[..end].to_string();
        self.rest = &self.rest[end..];
        Some(token)
    }

    /// A macro body runs to the next blank line.
    fn skip_macro(&mut self) {
        match self.rest.find("\n\n") {
            Some(end) => self.rest = &self.rest[end + 2..],
            None => self.rest = "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::registries::config::{validate_registries, RegistrySpec};
    use std::collections::BTreeMap;

    fn registry(url: &str) -> Registry {
        let spec = RegistrySpec {
            name: "corp".into(),
            ecosystem: "python".into(),
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
        };
        validate_registries(&[spec], &BTreeMap::new())
            .unwrap()
            .remove(0)
    }

    fn file_credential(dir: &Path, body: &str, mode: u32) -> CredentialSpec {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(format!("token-{mode:o}-{}", body.len()));
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        CredentialSpec {
            file: Some(path),
            ..Default::default()
        }
    }

    #[test]
    fn a_secret_never_prints() {
        let secret = Secret("s3cr3t".into());
        assert_eq!(format!("{secret:?}"), "…");
        let registry = registry("https://n.example/simple/");
        let credential = Credential::new(
            &registry,
            "corp",
            &CredentialSpec {
                env: Some("GREYWARD_TEST_NEVER_SET_TOKEN".into()),
                ..Default::default()
            },
        );
        assert!(!format!("{credential:?}").contains("s3cr3t"));
    }

    #[test]
    fn a_file_gives_a_bearer_header_and_bad_files_are_refused() {
        let temp = crate::kernel::testutil::TempDir::new();
        let registry = registry("https://n.example/simple/");
        let good = Credential::new(
            &registry,
            "corp",
            &file_credential(&temp.0, "tok-file\n", 0o600),
        );
        assert_eq!(good.authorization().unwrap().expose(), "Bearer tok-file");
        let open = Credential::new(
            &registry,
            "corp",
            &file_credential(&temp.0, "tok-open\n", 0o644),
        );
        let error = open.authorization().unwrap_err();
        assert!(error.contains("0644"), "{error}");
        assert!(!error.contains("tok-open"), "{error}");
        assert!(error.contains("fix:"), "{error}");
        let link = temp.0.join("link");
        std::os::unix::fs::symlink(temp.0.join("token-600-9"), &link).unwrap();
        let linked = Credential::new(
            &registry,
            "corp",
            &CredentialSpec {
                file: Some(link),
                ..Default::default()
            },
        );
        assert!(linked.authorization().unwrap_err().contains("symlink"));
        let multi = Credential::new(
            &registry,
            "corp",
            &file_credential(&temp.0, "a\nb\n", 0o600),
        );
        let error = multi.authorization().unwrap_err();
        assert!(error.contains("header cannot carry"), "{error}");
    }

    #[test]
    fn basic_and_raw_schemes() {
        let temp = crate::kernel::testutil::TempDir::new();
        let registry = registry("https://n.example/simple/");
        let mut spec = file_credential(&temp.0, "pw-basic", 0o600);
        spec.scheme = Some(Scheme::Basic);
        spec.username = Some("ci".into());
        let header = Credential::new(&registry, "corp", &spec)
            .authorization()
            .unwrap();
        assert_eq!(
            header.expose(),
            format!("Basic {}", crate::kernel::base64::encode(b"ci:pw-basic"))
        );
        let mut spec = file_credential(&temp.0, "raw-token-x", 0o600);
        spec.scheme = Some(Scheme::Raw);
        let header = Credential::new(&registry, "corp", &spec)
            .authorization()
            .unwrap();
        assert_eq!(header.expose(), "raw-token-x");
    }

    #[test]
    fn a_token_in_the_registry_url_is_refused() {
        let temp = crate::kernel::testutil::TempDir::new();
        let registry = registry("https://n.example/tok-in-url/simple/");
        let credential = Credential::new(
            &registry,
            "corp",
            &file_credential(&temp.0, "tok-in-url", 0o600),
        );
        let error = credential.authorization().unwrap_err();
        assert!(error.contains("also appears"), "{error}");
        assert!(!error.contains("tok-in-url"), "{error}");
    }

    #[test]
    fn a_missing_variable_fails_without_reading_anything_else() {
        let registry = registry("https://n.example/simple/");
        let credential = Credential::new(
            &registry,
            "corp",
            &CredentialSpec {
                env: Some("GREYWARD_TEST_NEVER_SET_TOKEN_2".into()),
                ..Default::default()
            },
        );
        let error = credential.authorization().unwrap_err();
        assert!(error.contains("not set"), "{error}");
        assert!(
            error.contains("fix: set GREYWARD_TEST_NEVER_SET_TOKEN_2"),
            "{error}"
        );
        assert!(credential
            .reference()
            .contains("env:GREYWARD_TEST_NEVER_SET_TOKEN_2"));
    }

    #[test]
    fn netrc_entries() {
        let text = "default login d password dpw\nmachine other.example login o password opw\n\
                    macdef init\ncd /\n\nmachine N.example\n  login \"ci bot\"\n  password \"p\\\"w\"\n";
        assert_eq!(
            netrc_entry(text, "n.example"),
            Some(("ci bot".into(), "p\"w".into()))
        );
        assert_eq!(netrc_entry(text, "missing.example"), None);
        assert_eq!(
            netrc_entry("default login d password dpw\n", "n.example"),
            None
        );
        assert_eq!(
            netrc_entry("machine n.example login a\n", "n.example"),
            None
        );
    }

    #[test]
    fn the_reference_differs_by_scheme_and_username() {
        let registry = registry("https://n.example/simple/");
        let mut spec = CredentialSpec {
            env: Some("T".into()),
            ..Default::default()
        };
        let a = Credential::new(&registry, "corp", &spec).reference();
        spec.scheme = Some(Scheme::Raw);
        let b = Credential::new(&registry, "corp", &spec).reference();
        spec.scheme = Some(Scheme::Basic);
        spec.username = Some("x".into());
        let c = Credential::new(&registry, "corp", &spec).reference();
        spec.username = Some("y".into());
        let d = Credential::new(&registry, "corp", &spec).reference();
        let all = [a, b, c, d];
        for (i, x) in all.iter().enumerate() {
            for y in &all[i + 1..] {
                assert_ne!(x, y);
            }
        }
    }
}
