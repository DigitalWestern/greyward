//! A configured registry as a resolution-proxy route: its root's origin
//! carrying the lazy credential, its `files` origins carrying none, both on
//! the client its `ca` and `network` select. The protocol instance is the tailor's.

use super::config::Registry;
use super::credential::Credential;
use super::effective::Sources;
use crate::kernel::resolve::clients::ClientSpec;
use crate::kernel::resolve::routes::{Endpoint, Permitted, RegistryProtocol, Route, RouteScope};
use std::io;
use std::sync::Arc;

/// The route serving `registry` through `protocol`.
pub fn route(
    protocol: Arc<dyn RegistryProtocol>,
    registry: &Registry,
    sources: &Sources,
) -> io::Result<Route> {
    let client = ClientSpec {
        ca: registry.ca.clone(),
        network: registry.network,
    };
    let credential = match &registry.credential {
        None => None,
        Some(name) => {
            let spec = sources.credential(name).ok_or_else(|| {
                io::Error::other(format!(
                    "registry {} names credential {name}, which the machine policy does not declare",
                    registry.name
                ))
            })?;
            Some((
                registry.root.clone(),
                Arc::new(Credential::new(registry, name, spec)),
            ))
        }
    };
    let mut endpoints = vec![Endpoint::configured(
        registry.origin(),
        credential,
        client.clone(),
    )?];
    for files in &registry.files {
        endpoints.push(Endpoint::configured(files, None, client.clone())?);
    }
    Route::configured(
        protocol,
        RouteScope {
            registry: registry.name.clone(),
            url: registry.url.clone(),
            root: registry.root.clone(),
            files: registry.files.clone(),
        },
        endpoints,
    )
}

/// `permitted` with `registry`'s origins added.
pub fn permit(mut permitted: Permitted, registry: &Registry) -> Permitted {
    for origin in
        std::iter::once(registry.origin()).chain(registry.files.iter().map(String::as_str))
    {
        if let Ok(url) = url::Url::parse(origin) {
            if let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) {
                permitted = permitted.with_origin(host, port);
            }
        }
    }
    permitted
}
