//! TLS for clients, as `nats-server` does it: `INFO` in the clear, then the
//! handshake the client starts; or, with `handshake_first`, the handshake
//! right away and `INFO` over it.

pub(crate) mod cert;
pub(crate) mod dn;

use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use zzq_tokio::transport::Stream;

use crate::conn::Hello;
use crate::lane::Lane;
use crate::{Error, Tls};

/// What the server needs for TLS clients.
pub(crate) struct Acceptor {
    inner: TlsAcceptor,
    first: bool,
    /// With `first`: how long a client has to start TLS before it gets
    /// `INFO` in the clear.
    fallback: Option<Duration>,
    timeout: Duration,
    /// Clients present certificates.
    pub(crate) verify: bool,
    /// Their certificates name their users.
    map: bool,
}

impl std::fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acceptor")
            .field("first", &self.first)
            .field("timeout", &self.timeout)
            .field("verify", &self.verify)
            .field("map", &self.map)
            .finish_non_exhaustive()
    }
}

impl Acceptor {
    /// Reads the certificates and key `o` names.
    pub(crate) fn new(o: &Tls) -> Result<Acceptor, Error> {
        let bad = |what: &str, e: &dyn std::fmt::Display| Error::Tls(format!("{what}: {e}"));
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&o.cert_file)
            .and_then(Iterator::collect)
            .map_err(|e| bad(&o.cert_file.display().to_string(), &e))?;
        let key = PrivateKeyDer::from_pem_file(&o.key_file)
            .map_err(|e| bad(&o.key_file.display().to_string(), &e))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| bad("protocols", &e))?;
        let builder = match (&o.ca_file, o.verify) {
            (Some(ca), true) => {
                let mut roots = rustls::RootCertStore::empty();
                for c in CertificateDer::pem_file_iter(ca)
                    .map_err(|e| bad(&ca.display().to_string(), &e))?
                {
                    let c = c.map_err(|e| bad(&ca.display().to_string(), &e))?;
                    roots
                        .add(c)
                        .map_err(|e| bad(&ca.display().to_string(), &e))?;
                }
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                        .build()
                        .map_err(|e| bad("client verifier", &e))?;
                builder.with_client_cert_verifier(verifier)
            }
            (None, true) => return Err(Error::Tls("verify needs a ca_file".into())),
            (_, false) => builder.with_no_client_auth(),
        };
        let config = builder
            .with_single_cert(certs, key)
            .map_err(|e| bad("certificate and key", &e))?;
        Ok(Acceptor {
            inner: TlsAcceptor::from(Arc::new(config)),
            first: o.handshake_first,
            fallback: o.fallback,
            timeout: o.timeout,
            verify: o.verify,
            map: o.map,
        })
    }
}

impl Acceptor {
    /// The server side of a handshake over `tcp`, without a time limit.
    pub(crate) async fn accept(
        &self,
        tcp: tokio::net::TcpStream,
    ) -> Option<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        self.inner.accept(tcp).await.ok()
    }

    /// What the certificate of the client of `tls` names, where clients
    /// log in as the users their certificates name.
    pub(crate) fn names(
        &self,
        tls: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) -> Option<Box<cert::Names>> {
        if !self.map {
            return None;
        }
        let first = tls.get_ref().1.peer_certificates().and_then(<[_]>::first);
        Some(Box::new(
            first.map(|c| cert::Names::of(c)).unwrap_or_default(),
        ))
    }
}

/// Runs a TLS client:  `info` goes out in the clear before the handshake, or
/// over TLS after it, as the server is set up.
pub(crate) async fn serve(lane: Rc<Lane>, mut hello: Hello, info: Vec<u8>, stream: Stream) {
    let Some(acc) = lane.shared.tls.as_ref() else {
        return;
    };
    let Some((tls, sent)) = handshake(acc, &info, stream).await else {
        lane.shared.client_gone();
        return;
    };
    if !sent {
        hello.client.out.borrow_mut().extend_from_slice(&info);
    }
    hello.via.cert = acc.names(&tls);
    let (r, w) = tokio::io::split(tls);
    crate::conn::serve(lane, hello, r, w).await;
}

/// `INFO` and the handshake, in the order the server is set up for, or
/// the client asks for. Tells whether `INFO` went out in the clear.
async fn handshake(
    acc: &Acceptor,
    info: &[u8],
    stream: Stream,
) -> Option<(tokio_rustls::server::TlsStream<tokio::net::TcpStream>, bool)> {
    let Stream::Tcp(s) = stream else {
        return None;
    };
    s.set_nonblocking(true).ok()?;
    let mut tcp = tokio::net::TcpStream::from_std(s).ok()?;
    tcp.set_nodelay(true).ok()?;
    let clear = match (acc.first, acc.fallback) {
        (false, _) => true,
        (true, None) => false,
        // Nothing from the client in time: it waits for INFO.
        (true, Some(wait)) => tokio::time::timeout(wait, tcp.peek(&mut [0u8; 1]))
            .await
            .is_err(),
    };
    if clear {
        tcp.write_all(info).await.ok()?;
    }
    let tls = tokio::time::timeout(acc.timeout, acc.inner.accept(tcp))
        .await
        .ok()?
        .ok()?;
    Some((tls, clear))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_acceptor_reads_its_files_and_shows_its_settings() {
        let dir = std::env::temp_dir().join(format!("naq-tls-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.join("c.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("k.pem"), key.serialize_pem()).unwrap();
        let o = Tls {
            cert_file: dir.join("c.pem"),
            key_file: dir.join("k.pem"),
            ca_file: Some(dir.join("c.pem")),
            verify: true,
            map: false,
            timeout: Duration::from_secs(1),
            handshake_first: true,
            fallback: None,
        };
        let a = Acceptor::new(&o).unwrap();
        let shown = format!("{a:?}");
        assert!(
            shown.contains("first: true") && shown.contains("verify: true"),
            "{shown}"
        );
        let mismatched = Tls {
            key_file: dir.join("other.pem"),
            ..o.clone()
        };
        std::fs::write(
            dir.join("other.pem"),
            rcgen::KeyPair::generate().unwrap().serialize_pem(),
        )
        .unwrap();
        assert!(matches!(Acceptor::new(&mismatched), Err(Error::Tls(_))));
        let missing_ca = Tls {
            ca_file: Some(dir.join("none.pem")),
            ..o
        };
        assert!(matches!(Acceptor::new(&missing_ca), Err(Error::Tls(_))));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
