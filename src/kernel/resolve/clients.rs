//! The upstream clients of one process: the public one, and one per (extra
//! trust roots, network mode) a configured registry asks for
//!.
//!
//! Each client is immutable once built, and the key fully determines it, so
//! sessions under different machine policies share entries safely and no
//! allowance is ever global. Only a configured registry's endpoints select a
//! private-mode or extra-root client; public routes, git fetches and
//! unattested hosts always use [`Clients::public`].

use super::ssrf::{Lookup, ValidatingResolver};
use crate::kernel::fetch::pinned::{self, PinnedClient, PinnedConfig};
use crate::kernel::registries::config::NetworkMode;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// What a configured registry's endpoint asks of its client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ClientSpec {
    /// A PEM file of extra trust roots for this registry only.
    pub ca: Option<PathBuf>,
    pub network: NetworkMode,
}

/// How every client of a process is built.
pub struct ClientBase {
    pub roots: rustls::RootCertStore,
    pub lookup: Arc<dyn Lookup>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    #[cfg(test)]
    pub(crate) allow_loopback: bool,
    #[cfg(test)]
    pub(crate) connect_to:
        Option<Arc<dyn Fn(std::net::SocketAddr) -> std::net::SocketAddr + Send + Sync>>,
}

type Key = (Option<[u8; 32]>, NetworkMode);

pub struct Clients {
    base: ClientBase,
    public: Arc<PinnedClient>,
    built: Mutex<HashMap<Key, Arc<PinnedClient>>>,
}

impl Clients {
    pub fn new(base: ClientBase) -> io::Result<Clients> {
        let public = Arc::new(build(&base, None, NetworkMode::Public)?);
        Ok(Clients {
            base,
            public,
            built: Mutex::new(HashMap::new()),
        })
    }

    /// The client of every public route, git fetch and unattested host.
    pub fn public(&self) -> &Arc<PinnedClient> {
        &self.public
    }

    /// The client a configured registry's endpoint uses. The `ca` file is
    /// read once per process; an unreadable or certificate-less file is an
    /// error naming it.
    pub fn for_spec(&self, spec: &ClientSpec) -> Result<Arc<PinnedClient>, String> {
        let ca = match &spec.ca {
            None => None,
            Some(path) => Some(ca_file(path)?),
        };
        if ca.is_none() && spec.network == NetworkMode::Public {
            return Ok(self.public.clone());
        }
        let key = (ca.as_ref().map(|ca| ca.digest), spec.network);
        let mut built = self.built.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(client) = built.get(&key) {
            return Ok(client.clone());
        }
        let client = Arc::new(
            build(&self.base, ca.as_deref(), spec.network)
                .map_err(|error| format!("upstream client: {error}"))?,
        );
        built.insert(key, client.clone());
        Ok(client)
    }
}

fn build(base: &ClientBase, ca: Option<&CaFile>, network: NetworkMode) -> io::Result<PinnedClient> {
    let mut roots = base.roots.clone();
    if let Some(ca) = ca {
        for certificate in &ca.certificates {
            roots
                .add(certificate.clone())
                .map_err(|error| io::Error::other(format!("{}: {error}", ca.path.display())))?;
        }
    }
    #[allow(unused_mut)]
    let mut resolver = ValidatingResolver::new(base.lookup.clone());
    resolver.private = network == NetworkMode::Private;
    #[cfg(test)]
    {
        resolver.allow_loopback = base.allow_loopback;
        resolver.connect_to = base.connect_to.clone();
    }
    PinnedClient::new(PinnedConfig {
        roots,
        resolver: Arc::new(resolver),
        connect_timeout: base.connect_timeout,
        io_timeout: base.io_timeout,
    })
}

/// A `ca` file's certificates and the digest of its bytes.
pub struct CaFile {
    path: PathBuf,
    pub digest: [u8; 32],
    certificates: Vec<CertificateDer<'static>>,
}

/// Read a `ca` file once per process; the answer, a failure included, is
/// kept.
pub fn ca_file(path: &Path) -> Result<Arc<CaFile>, String> {
    type Cell = Arc<OnceLock<Result<Arc<CaFile>, String>>>;
    static FILES: OnceLock<Mutex<HashMap<PathBuf, Cell>>> = OnceLock::new();
    let cell = FILES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .entry(path.to_path_buf())
        .or_default()
        .clone();
    cell.get_or_init(|| read_ca(path).map(Arc::new)).clone()
}

fn read_ca(path: &Path) -> Result<CaFile, String> {
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "ca {}: cannot read it: {error}\nfix: point [[registry]] ca at a readable PEM file of the registry's root certificate",
            path.display()
        )
    })?;
    let certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<_, _>>()
        .map_err(|error| format!("ca {}: not valid PEM: {error}", path.display()))?;
    if certificates.is_empty() {
        return Err(format!(
            "ca {}: holds no certificate\nfix: point [[registry]] ca at a PEM file with at least one CERTIFICATE block",
            path.display()
        ));
    }
    Ok(CaFile {
        path: path.to_path_buf(),
        digest: Sha256::digest(&bytes).into(),
        certificates,
    })
}

impl ClientBase {
    /// Production: webpki roots and the system resolver.
    pub fn system(connect_timeout: Duration, io_timeout: Duration) -> ClientBase {
        ClientBase {
            roots: pinned::webpki_roots(),
            lookup: Arc::new(super::ssrf::SystemLookup),
            connect_timeout,
            io_timeout,
            #[cfg(test)]
            allow_loopback: false,
            #[cfg(test)]
            connect_to: None,
        }
    }
}

/// The process's clients for ward's own registry fetches, built on first
/// use with production settings.
pub fn process() -> io::Result<&'static Clients> {
    static CLIENTS: OnceLock<Clients> = OnceLock::new();
    static START: Mutex<()> = Mutex::new(());
    if let Some(clients) = CLIENTS.get() {
        return Ok(clients);
    }
    let _starting = START.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(clients) = CLIENTS.get() {
        return Ok(clients);
    }
    let built = Clients::new(ClientBase::system(
        Duration::from_secs(15),
        Duration::from_secs(60),
    ))?;
    Ok(CLIENTS.get_or_init(|| built))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ClientBase {
        ClientBase::system(Duration::from_secs(1), Duration::from_secs(1))
    }

    #[test]
    fn clients_are_shared_by_key_and_public_needs_nothing() {
        let clients = Clients::new(base()).unwrap();
        let public = clients.for_spec(&ClientSpec::default()).unwrap();
        assert!(Arc::ptr_eq(&public, clients.public()));
        let private = ClientSpec {
            ca: None,
            network: NetworkMode::Private,
        };
        let a = clients.for_spec(&private).unwrap();
        let b = clients.for_spec(&private).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, clients.public()));
    }

    #[test]
    fn a_ca_file_must_hold_a_certificate() {
        let temp = crate::kernel::testutil::TempDir::new();
        let clients = Clients::new(base()).unwrap();
        let missing = ClientSpec {
            ca: Some(temp.0.join("missing.pem")),
            network: NetworkMode::Public,
        };
        let Err(error) = clients.for_spec(&missing) else {
            panic!("a missing ca file was accepted");
        };
        assert!(error.contains("cannot read"), "{error}");
        let empty = temp.0.join("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        let Err(error) = clients.for_spec(&ClientSpec {
            ca: Some(empty),
            network: NetworkMode::Public,
        }) else {
            panic!("a certificate-less ca file was accepted");
        };
        assert!(error.contains("no certificate"), "{error}");
        let ca = rcgen::generate_simple_self_signed(vec!["corp.test".into()]).unwrap();
        let good = temp.0.join("good.pem");
        std::fs::write(&good, ca.cert.pem()).unwrap();
        let spec = ClientSpec {
            ca: Some(good),
            network: NetworkMode::Public,
        };
        let a = clients.for_spec(&spec).unwrap();
        assert!(!Arc::ptr_eq(&a, clients.public()));
        assert!(Arc::ptr_eq(&a, &clients.for_spec(&spec).unwrap()));
    }
}
