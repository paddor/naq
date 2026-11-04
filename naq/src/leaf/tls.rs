//! TLS to hubs: the client side of the handshake, after the hub's `INFO`
//! or before it, as `nats-server` leafs do it.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::HubUrl;
use crate::{Error, Remote, RemoteTls};

/// How one remote starts TLS with its hub.
pub(crate) struct Connector {
    /// From the remote's `tls`; `None` without one.
    config: Option<Arc<ClientConfig>>,
    timeout: Duration,
    first: bool,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("configured", &self.config.is_some())
            .field("timeout", &self.timeout)
            .field("first", &self.first)
            .finish()
    }
}

impl Connector {
    /// Reads the files `r`'s `tls` names.
    ///
    /// # Errors
    ///
    /// A file that cannot be read, or a certificate without its key.
    pub(crate) fn new(r: &Remote) -> Result<Connector, Error> {
        let Some(t) = &r.tls else {
            return Ok(Connector {
                config: None,
                timeout: RemoteTls::default().timeout,
                first: false,
            });
        };
        Ok(Connector {
            config: Some(Arc::new(config(t)?)),
            timeout: t.timeout,
            first: t.handshake_first,
        })
    }

    /// The handshake comes before the hub's `INFO`.
    pub(super) const fn first(&self) -> bool {
        self.first
    }

    /// Whether the link starts TLS after the hub's `INFO`: the remote has
    /// `tls`, or the hub asks for it.
    pub(super) const fn after_info(&self, hub_asks: bool) -> bool {
        self.config.is_some() || hub_asks
    }

    /// The handshake over `tcp` with the hub at `url`, one of `urls`,
    /// within the remote's timeout.
    pub(super) async fn connect(
        &self,
        tcp: TcpStream,
        url: &HubUrl,
        urls: &[HubUrl],
    ) -> Option<TlsStream<TcpStream>> {
        let config = self.config.clone().or_else(system)?;
        let name = name(url, urls)?;
        let connect = TlsConnector::from(config).connect(name, tcp);
        tokio::time::timeout(self.timeout, connect).await.ok()?.ok()
    }
}

/// The client config `t` asks for.
fn config(t: &RemoteTls) -> Result<ClientConfig, Error> {
    let bad = |what: &dyn std::fmt::Display, e: &dyn std::fmt::Display| {
        Error::Tls(format!("leafnode remote tls: {what}: {e}"))
    };
    let roots = match &t.ca_file {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in CertificateDer::pem_file_iter(ca).map_err(|e| bad(&ca.display(), &e))? {
                let c = c.map_err(|e| bad(&ca.display(), &e))?;
                roots.add(c).map_err(|e| bad(&ca.display(), &e))?;
            }
            Arc::new(roots)
        }
        None => system_roots(),
    };
    let builder = builder()
        .map_err(|e| bad(&"protocols", &e))?
        .with_root_certificates(roots);
    match (&t.cert_file, &t.key_file) {
        (Some(cert), Some(key)) => {
            let certs = CertificateDer::pem_file_iter(cert)
                .and_then(Iterator::collect)
                .map_err(|e| bad(&cert.display(), &e))?;
            let key = PrivateKeyDer::from_pem_file(key).map_err(|e| bad(&key.display(), &e))?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| bad(&"certificate and key", &e))
        }
        (None, None) => Ok(builder.with_no_client_auth()),
        _ => Err(Error::Tls(
            "leafnode remote tls: cert_file and key_file go together".into(),
        )),
    }
}

/// A client config builder of TLS 1.2 and 1.3.
fn builder() -> Result<rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()
}

/// The certificate authorities of the system, loaded once.
fn system_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            // Unreadable ones are left out, as Go leaves them out.
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            Arc::new(roots)
        })
        .clone()
}

/// The config for a hub that asks for TLS of a remote without `tls`.
fn system() -> Option<Arc<ClientConfig>> {
    static SYSTEM: OnceLock<Option<Arc<ClientConfig>>> = OnceLock::new();
    SYSTEM
        .get_or_init(|| {
            let b = builder().ok()?.with_root_certificates(system_roots());
            Some(Arc::new(b.with_no_client_auth()))
        })
        .clone()
}

/// The name the hub's certificate must have: the host of `url`, or for an
/// IP, the first host name among `urls`, as `nats-server` picks it.
fn name(url: &HubUrl, urls: &[HubUrl]) -> Option<ServerName<'static>> {
    let host = if url.host.parse::<IpAddr>().is_ok() {
        urls.iter()
            .map(|u| u.host.as_str())
            .find(|h| h.parse::<IpAddr>().is_err())
            .unwrap_or(&url.host)
    } else {
        &url.host
    };
    ServerName::try_from(host.to_owned()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(host: &str) -> HubUrl {
        HubUrl::parse(&format!("{host}:7422")).unwrap()
    }

    #[test]
    fn an_ip_hub_is_checked_by_a_host_name_of_the_remote() {
        let (ip, host) = (url("10.0.0.1"), url("hub.example"));
        let name = |u, all: &[HubUrl]| name(u, all).map(|n| n.to_str().into_owned());
        assert_eq!(name(&host, &[]), Some("hub.example".into()));
        assert_eq!(
            name(&ip, &[ip.clone(), host.clone()]),
            Some("hub.example".into())
        );
        assert_eq!(
            name(&ip, std::slice::from_ref(&ip)),
            Some("10.0.0.1".into())
        );
    }

    #[test]
    fn a_certificate_needs_its_key() {
        let r = Remote {
            tls: Some(RemoteTls {
                cert_file: Some("c.pem".into()),
                ..RemoteTls::default()
            }),
            ..Remote::default()
        };
        let e = Connector::new(&r).unwrap_err();
        assert!(e.to_string().contains("go together"), "{e}");
        let missing = Remote {
            tls: Some(RemoteTls {
                ca_file: Some("/nonexistent/ca.pem".into()),
                ..RemoteTls::default()
            }),
            ..Remote::default()
        };
        assert!(Connector::new(&missing).is_err());
        let plain = Connector::new(&Remote::default()).unwrap();
        assert!(!plain.first() && !plain.after_info(false) && plain.after_info(true));
        assert!(format!("{plain:?}").contains("configured: false"));
    }
}
