//! The validating resolver: every upstream connection the proxy opens is to
//! an address it looked up once and checked against the IANA
//! special-purpose table ([`super::iana`]).
//!
//! Sandboxed code chooses the paths the proxy fetches, so without this the
//! proxy is a pivot to whatever the host can reach: cloud metadata at
//! `169.254.169.254`, a database on `10.x`, a service on loopback. The
//! lookup happens here, once per connection; every returned address must be
//! globally routable or the whole connection is refused (one private answer
//! among public ones is how a rebinding attack starts); and the HTTP client
//! connects only to the list returned here, never looking the name up
//! again.

use super::iana;
use crate::kernel::fetch::pinned::{PinnedResolve, ResolveRefusal};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

/// A name lookup. Production asks the system resolver; tests answer from a
/// table (and count the calls).
pub trait Lookup: Send + Sync {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>>;
}

/// The system resolver (`getaddrinfo`).
pub struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>> {
        Ok((host, port)
            .to_socket_addrs()?
            .map(|address| address.ip())
            .collect())
    }
}

/// The ranges a `network = "private"` registry may resolve to (machine
/// policy only): RFC 1918, shared address space, unique local, loopback.
const PRIVATE: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "fc00::/7",
    "::1/128",
];

/// Cloud metadata services inside the private ranges: refused under every
/// setting.
const METADATA: &[&str] = &["100.100.100.200/32", "fd00:ec2::254/128"];

/// Whether `address` is one a private-mode registry may use: inside
/// [`PRIVATE`] and not a metadata address. Everything else private
/// (link-local, the embedding forms, multicast) stays refused.
fn private_allowed(address: IpAddr) -> bool {
    let inside = |blocks: &[&str]| {
        blocks
            .iter()
            .filter_map(|block| iana::Block::parse(block))
            .any(|block| block.contains(address))
    };
    inside(PRIVATE) && !inside(METADATA)
}

/// Looks up once, validates every address, returns exactly that list.
pub struct ValidatingResolver {
    lookup: Arc<dyn Lookup>,
    /// A `network = "private"` registry's resolver: an answer may be all
    /// globally routable or all inside the private ranges, never a mix.
    pub(crate) private: bool,
    /// Tests only: accept loopback answers, so the fixture upstream on
    /// `127.0.0.1` is reachable. Every other refused range stays refused,
    /// and the SSRF tests build their resolver with this off.
    #[cfg(test)]
    pub(crate) allow_loopback: bool,
    /// Tests only: where a validated address actually connects. The rebinding
    /// test validates a public answer and lands it on a local listener.
    #[cfg(test)]
    pub(crate) connect_to: Option<Arc<dyn Fn(SocketAddr) -> SocketAddr + Send + Sync>>,
}

impl ValidatingResolver {
    pub fn new(lookup: Arc<dyn Lookup>) -> Self {
        Self {
            lookup,
            private: false,
            #[cfg(test)]
            allow_loopback: false,
            #[cfg(test)]
            connect_to: None,
        }
    }

    /// Why `address` may not be connected to, if it may not.
    fn refusal(&self, address: IpAddr) -> Option<String> {
        #[cfg(test)]
        // `is_loopback` is `127.0.0.0/8` and `::1` only: an IPv4-mapped
        // `::ffff:127.0.0.1` is not loopback here and stays refused.
        if self.allow_loopback && address.is_loopback() {
            return None;
        }
        iana::refusal(address)
    }
}

impl PinnedResolve for ValidatingResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let addresses = self.lookup.lookup(host, port)?;
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{host} resolved to no address"),
            ));
        }
        let all_private = self.private && addresses.iter().all(|a| private_allowed(*a));
        if !all_private {
            for address in &addresses {
                if let Some(reason) = self.refusal(*address) {
                    let rule = if self.private {
                        "a private registry's answer must be all globally routable or all inside \
                         10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7 or loopback, and never a \
                         metadata address"
                    } else {
                        "the proxy connects only to globally routable addresses"
                    };
                    return Err(
                        ResolveRefusal(format!("{host} resolves to {reason}; {rule}")).into_io(),
                    );
                }
            }
        }
        let validated: Vec<SocketAddr> = addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect();
        #[cfg(test)]
        if let Some(connect_to) = &self.connect_to {
            return Ok(validated.into_iter().map(|a| connect_to(a)).collect());
        }
        Ok(validated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers from a fixed table.
    struct Table(Vec<IpAddr>, Mutex<usize>);

    impl Lookup for Table {
        fn lookup(&self, _host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
            *self.1.lock().unwrap() += 1;
            Ok(self.0.clone())
        }
    }

    fn resolver(answers: &[&str]) -> ValidatingResolver {
        ValidatingResolver::new(Arc::new(Table(
            answers.iter().map(|a| a.parse().unwrap()).collect(),
            Mutex::new(0),
        )))
    }

    fn refused(error: io::Error) -> String {
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ResolveRefusal>())
            .map(|refusal| refusal.0.clone())
            .unwrap_or_else(|| panic!("not a refusal: {error}"))
    }

    #[test]
    fn every_answer_must_be_global() {
        let ok = resolver(&["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]);
        assert_eq!(ok.resolve("registry.test", 443).unwrap().len(), 2);
        for private in ["10.0.0.1", "169.254.169.254", "::ffff:10.0.0.1", "fd00::1"] {
            let mixed = resolver(&["93.184.216.34", private]);
            let why = refused(mixed.resolve("registry.test", 443).unwrap_err());
            assert!(why.contains("registry.test"), "{why}");
        }
    }

    #[test]
    fn private_mode_takes_all_private_or_all_public_answers() {
        let private = |answers: &[&str]| {
            let mut resolver = resolver(answers);
            resolver.private = true;
            resolver.resolve("nexus.corp.test", 443)
        };
        for ok in [
            &["10.1.2.3"][..],
            &["172.16.0.9", "192.168.1.1"],
            &["100.64.0.1"],
            &["127.0.0.1"],
            &["::1"],
            &["fd12::1"],
            &["93.184.216.34"],
        ] {
            assert!(private(ok).is_ok(), "{ok:?}");
        }
        for refused_answer in [
            &["10.0.0.1", "93.184.216.34"][..],
            &["169.254.169.254"],
            &["fe80::1"],
            &["::ffff:10.0.0.1"],
            &["64:ff9b::a00:1"],
            &["2002:a00:1::1"],
            &["100.100.100.200"],
            &["fd00:ec2::254"],
            &["224.0.0.1"],
            &["0.0.0.0"],
        ] {
            refused(private(refused_answer).unwrap_err());
        }
        // The default mode is unchanged.
        refused(
            resolver(&["10.1.2.3"])
                .resolve("nexus.corp.test", 443)
                .unwrap_err(),
        );
    }

    #[test]
    fn the_loopback_exception_is_loopback_only() {
        let mut local = resolver(&["127.0.0.1"]);
        refused(local.resolve("fixture.test", 443).unwrap_err());
        local.allow_loopback = true;
        assert!(local.resolve("fixture.test", 443).is_ok());
        let mut mapped = resolver(&["::ffff:127.0.0.1"]);
        mapped.allow_loopback = true;
        refused(mapped.resolve("fixture.test", 443).unwrap_err());
        let mut private = resolver(&["10.0.0.1"]);
        private.allow_loopback = true;
        refused(private.resolve("fixture.test", 443).unwrap_err());
    }
}
