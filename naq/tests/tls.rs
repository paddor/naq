//! TLS clients, with certificates made for the test.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use naq::{Error, Options, Server, Tls};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// A CA, a server certificate for 127.0.0.1 and a client certificate, in
/// PEM files of a directory of the test's own.
struct Pki {
    dir: PathBuf,
}

impl Pki {
    fn new(name: &str) -> Pki {
        let dir = std::env::temp_dir().join(format!("naq-tls-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca, &ca_key);
        std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
        for (who, names) in [
            ("server", vec!["127.0.0.1".to_owned()]),
            ("client", vec!["client".to_owned()]),
        ] {
            let key = KeyPair::generate().unwrap();
            let cert = CertificateParams::new(names)
                .unwrap()
                .signed_by(&key, &issuer)
                .unwrap();
            std::fs::write(dir.join(format!("{who}.pem")), cert.pem()).unwrap();
            std::fs::write(dir.join(format!("{who}-key.pem")), key.serialize_pem()).unwrap();
        }
        Pki { dir }
    }

    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    fn tls(&self, verify: bool, first: bool) -> Tls {
        Tls {
            cert_file: self.path("server.pem"),
            key_file: self.path("server-key.pem"),
            ca_file: verify.then(|| self.path("ca.pem")),
            verify,
            timeout: Duration::from_secs(2),
            handshake_first: first,
        }
    }

    /// A client side that trusts the CA, with the client certificate if
    /// `cert`.
    fn client(&self, cert: bool) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(self.path("ca.pem")).unwrap())
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let b = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        let cfg = if cert {
            let chain = vec![CertificateDer::from_pem_file(self.path("client.pem")).unwrap()];
            let key = PrivateKeyDer::from_pem_file(self.path("client-key.pem")).unwrap();
            b.with_client_auth_cert(chain, key).unwrap()
        } else {
            b.with_no_client_auth()
        };
        Arc::new(cfg)
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn server(tls: Tls) -> Server {
    Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        tls: Some(tls),
        ..Options::default()
    })
    .unwrap()
}

/// Reads from `r` until `end`, and returns all that came.
fn until(r: &mut impl Read, end: &str) -> String {
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(end.as_bytes()) {
        if r.read(&mut b).unwrap() == 0 {
            break;
        }
        got.push(b[0]);
    }
    String::from_utf8(got).unwrap()
}

fn tcp(s: &Server) -> TcpStream {
    let t = TcpStream::connect(s.addr()).unwrap();
    t.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    t
}

fn wrap(cfg: Arc<ClientConfig>, t: TcpStream) -> StreamOwned<ClientConnection, TcpStream> {
    let name = ServerName::try_from("127.0.0.1").unwrap();
    StreamOwned::new(ClientConnection::new(cfg, name).unwrap(), t)
}

#[test]
fn info_comes_in_the_clear_then_the_client_starts_tls() {
    let pki = Pki::new("info");
    let s = server(pki.tls(false, false));
    let mut t = tcp(&s);
    let info = until(&mut t, "\r\n");
    assert!(info.contains(r#""tls_required":true"#), "{info}");
    let mut tls = wrap(pki.client(false), t);
    tls.write_all(b"CONNECT {\"verbose\":false}\r\nSUB a 1\r\nPUB a 2\r\nhi\r\nPING\r\n")
        .unwrap();
    assert_eq!(until(&mut tls, "PONG\r\n"), "MSG a 1 2\r\nhi\r\nPONG\r\n");
}

#[test]
fn the_handshake_may_come_first() {
    let pki = Pki::new("first");
    let s = server(pki.tls(false, true));
    let mut tls = wrap(pki.client(false), tcp(&s));
    tls.write_all(b"CONNECT {\"verbose\":false}\r\nPING\r\n")
        .unwrap();
    let got = until(&mut tls, "PONG\r\n");
    assert!(got.starts_with("INFO "), "{got}");
    assert!(got.ends_with("PONG\r\n"), "{got}");
}

#[test]
fn verify_wants_a_client_certificate_from_the_ca() {
    let pki = Pki::new("verify");
    let s = server(pki.tls(true, false));
    let mut t = tcp(&s);
    let info = until(&mut t, "\r\n");
    assert!(info.contains(r#""tls_verify":true"#), "{info}");
    let mut tls = wrap(pki.client(true), t);
    tls.write_all(b"CONNECT {\"verbose\":false}\r\nPING\r\n")
        .unwrap();
    assert_eq!(until(&mut tls, "PONG\r\n"), "PONG\r\n");
    let mut t = tcp(&s);
    until(&mut t, "\r\n");
    let mut tls = wrap(pki.client(false), t);
    let sent = tls.write_all(b"PING\r\n");
    let mut rest = Vec::new();
    assert!(sent.is_err() || tls.read_to_end(&mut rest).is_err() || rest.is_empty());
}

#[test]
fn a_client_that_skips_tls_is_closed() {
    let pki = Pki::new("plain");
    let s = server(pki.tls(false, false));
    let mut t = tcp(&s);
    until(&mut t, "\r\n");
    t.write_all(b"CONNECT {}\r\nPING\r\n").unwrap();
    let mut rest = Vec::new();
    let _ = t.read_to_end(&mut rest);
    assert!(!String::from_utf8_lossy(&rest).contains("PONG"));
}

#[test]
fn files_that_are_no_certificates_are_an_error() {
    let pki = Pki::new("bad");
    std::fs::write(pki.path("junk.pem"), "not pem").unwrap();
    for tls in [
        Tls {
            cert_file: pki.path("junk.pem"),
            ..pki.tls(false, false)
        },
        Tls {
            key_file: pki.path("missing.pem"),
            ..pki.tls(false, false)
        },
        Tls {
            ca_file: None,
            ..pki.tls(true, false)
        },
        Tls {
            ca_file: Some(pki.path("junk.pem")),
            ..pki.tls(true, false)
        },
    ] {
        let e = Server::start(&Options {
            host: "127.0.0.1".into(),
            port: 0,
            lanes: 1,
            tls: Some(tls),
            ..Options::default()
        });
        assert!(matches!(e, Err(Error::Tls(_))), "{e:?}");
    }
}

#[test]
fn the_config_file_names_the_files() {
    let o: Options = "tls {\n  cert_file: a.pem\n  key_file: b.pem\n  ca_file: c.pem\n  verify: true\n  timeout: 0.5\n  handshake_first: true\n}\n"
        .parse()
        .unwrap();
    let t = o.tls.unwrap();
    assert_eq!(t.cert_file, PathBuf::from("a.pem"));
    assert_eq!(t.ca_file, Some(PathBuf::from("c.pem")));
    assert!(t.verify && t.handshake_first);
    assert_eq!(t.timeout, Duration::from_millis(500));
    for bad in [
        "tls { key_file: b }\n",
        "tls { cert_file: a }\n",
        "tls { cert_file: a, key_file: b, verify: 1 }\n",
        "tls { bogus: 1 }\n",
        "tls: 1\n",
    ] {
        assert!(bad.parse::<Options>().is_err(), "{bad}");
    }
}
