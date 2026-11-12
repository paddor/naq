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
            fallback: None,
            map: false,
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
    assert!(t.verify && t.handshake_first && !t.map);
    assert_eq!(t.timeout, Duration::from_millis(500));
    assert_eq!(
        o.auth_timeout,
        Duration::from_millis(1500),
        "with TLS, clients have a second more to log in"
    );
    let timed: Options = "tls { cert_file: a, key_file: b }\nauthorization { timeout: 4 }\n"
        .parse()
        .unwrap();
    assert_eq!(timed.auth_timeout, Duration::from_secs(4));
    let mapped: Options = "tls { cert_file: a, key_file: b, ca_file: c, verify_and_map: true }\n"
        .parse()
        .unwrap();
    let t = mapped.tls.unwrap();
    assert!(t.verify && t.map, "mapping verifies");
    for bad in [
        "tls { key_file: b }\n",
        "tls { cert_file: a }\n",
        "tls { cert_file: a, key_file: b, verify: 1 }\n",
        "tls { cert_file: a, key_file: b, verify_and_map: 1 }\n",
        "tls { bogus: 1 }\n",
        "tls: 1\n",
    ] {
        assert!(bad.parse::<Options>().is_err(), "{bad}");
    }
}

#[test]
fn auto_mode_takes_tls_first_or_falls_back_to_info_first() {
    let pki = Pki::new("auto");
    let s = server(Tls {
        fallback: Some(Duration::from_millis(100)),
        ..pki.tls(false, true)
    });
    let mut tls = wrap(pki.client(false), tcp(&s));
    tls.write_all(b"CONNECT {\"verbose\":false}\r\nPING\r\n")
        .unwrap();
    assert!(until(&mut tls, "PONG\r\n").starts_with("INFO "));
    let mut t = tcp(&s);
    let info = until(&mut t, "\r\n");
    assert!(info.starts_with("INFO "), "{info}");
    let mut tls = wrap(pki.client(false), t);
    tls.write_all(b"CONNECT {\"verbose\":false}\r\nPING\r\n")
        .unwrap();
    assert_eq!(until(&mut tls, "PONG\r\n"), "PONG\r\n");
    let o: Options = "tls { cert_file: a, key_file: b, handshake_first: \"300ms\" }\n"
        .parse()
        .unwrap();
    let t = o.tls.unwrap();
    assert!(t.handshake_first);
    assert_eq!(t.fallback, Some(Duration::from_millis(300)));
}

#[test]
fn monitoring_over_https_asks_no_client_certificate() {
    let pki = Pki::new("https");
    let s = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        tls: Some(pki.tls(true, false)),
        https_port: Some(0),
        ..Options::default()
    })
    .unwrap();
    let at = s.monitor_addr().unwrap();
    let t = TcpStream::connect(at).unwrap();
    t.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut tls = wrap(pki.client(false), t);
    tls.write_all(b"GET /varz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut got = String::new();
    let _ = tls.read_to_string(&mut got);
    assert!(got.starts_with("HTTP/1.1 200 OK\r\n"), "{got}");
    let port = format!("\"https_port\": {}", at.port());
    assert!(
        got.contains(&port) && got.contains("\"http_port\": 0"),
        "{got}"
    );
    // Plain HTTP gets Go's answer.
    let mut plain = TcpStream::connect(at).unwrap();
    plain
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    plain
        .write_all(b"GET /varz HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut got = String::new();
    let _ = plain.read_to_string(&mut got);
    assert_eq!(
        got,
        "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"
    );
    // Neither HTTP nor TLS: closed.
    let mut junk = TcpStream::connect(at).unwrap();
    junk.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    junk.write_all(b"\x17\x03\x03\x00\x01x").unwrap();
    let mut got = Vec::new();
    let _ = junk.read_to_end(&mut got);
    assert!(!got.starts_with(b"HTTP"), "{got:?}");
}

#[test]
fn https_needs_tls_and_no_http_port() {
    let pki = Pki::new("https-bad");
    let err = Server::start(&Options {
        https_port: Some(0),
        ..Options::default()
    })
    .unwrap_err();
    assert!(
        matches!(err, Error::Options(ref e) if e == "TLS cert and key required for HTTPS"),
        "{err}"
    );
    let err = Server::start(&Options {
        tls: Some(pki.tls(false, false)),
        http_port: Some(0),
        https_port: Some(0),
        ..Options::default()
    })
    .unwrap_err();
    assert!(
        matches!(err, Error::Options(ref e) if e.starts_with("can't specify both HTTP")),
        "{err}"
    );
}

/// The JSON of `GET path` on plain monitoring at `at`.
fn monitor(at: std::net::SocketAddr, path: &str) -> serde_json::Value {
    let mut c = TcpStream::connect(at).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .unwrap();
    let mut text = String::new();
    c.read_to_string(&mut text).unwrap();
    serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap()
}

#[test]
fn connz_shows_the_tls_of_a_client_and_its_certificate_with_auth() {
    use sha2::Digest as _;
    let pki = Pki::new("connz");
    let server = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        http_port: Some(0),
        tls: Some(pki.tls(true, false)),
        ..Options::default()
    })
    .unwrap();
    let mut plain = tcp(&server);
    until(&mut plain, "\r\n");
    let mut tls = wrap(pki.client(true), plain);
    tls.write_all(b"CONNECT {\"verbose\":false}\r\nPING\r\n")
        .unwrap();
    until(&mut tls, "PONG\r\n");
    let m = server.monitor_addr().unwrap();
    let z = monitor(m, "/connz");
    let c = &z["connections"][0];
    assert_eq!(c["tls_version"], "1.3", "{z}");
    assert_eq!(c["tls_cipher_suite"], "TLS_AES_256_GCM_SHA384", "{z}");
    assert!(
        c.get("tls_peer_certs").is_none() && c.get("tls_first").is_none(),
        "{z}"
    );
    let z = monitor(m, "/connz?auth=1");
    let certs = &z["connections"][0]["tls_peer_certs"];
    let der = CertificateDer::from_pem_file(pki.path("client.pem")).unwrap();
    let sum = sha2::Sha256::digest(der.as_ref());
    let hex = sum.iter().fold(String::new(), |mut h, b| {
        use std::fmt::Write as _;
        let _ = write!(h, "{b:02x}");
        h
    });
    assert_eq!(certs[0]["cert_sha256"], hex.as_str(), "{z}");
    assert_eq!(certs[0]["subject"], "CN=rcgen self signed cert", "{z}");
    assert_eq!(certs[0]["spki_sha256"].as_str().unwrap().len(), 64, "{z}");
    // A closed client keeps its TLS, not its certificates.
    drop(tls);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let z = loop {
        let z = monitor(m, "/connz?state=closed&auth=1");
        if z["num_connections"] == 1 {
            break z;
        }
        assert!(std::time::Instant::now() < deadline, "{z}");
        std::thread::sleep(Duration::from_millis(10));
    };
    let c = &z["connections"][0];
    assert_eq!(c["tls_version"], "1.3", "{z}");
    assert!(c.get("tls_peer_certs").is_none(), "{z}");
}

/// Whether a client of `cfg` completes a handshake with `at` and reads.
fn handshakes(cfg: Arc<ClientConfig>, at: std::net::SocketAddr, ask: &[u8]) -> bool {
    let t = TcpStream::connect(at).unwrap();
    t.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut tls = wrap(cfg, t);
    if tls.write_all(ask).is_err() {
        return false;
    }
    let mut b = [0u8; 1];
    matches!(tls.read(&mut b), Ok(1))
}

#[test]
fn a_reload_serves_new_certificate_files_to_new_clients_and_monitoring() {
    let (old, new) = (Pki::new("rotate-old"), Pki::new("rotate-new"));
    let opts = Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        tls: Some(old.tls(false, true)),
        https_port: Some(0),
        ..Options::default()
    };
    let s = Server::start(&opts).unwrap();
    s.reload_with(move || Ok(opts.clone()));
    let get = b"GET /varz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (nats, https) = (s.addr(), s.monitor_addr().unwrap());
    assert!(handshakes(old.client(false), nats, b"PING\r\n"));
    assert!(handshakes(old.client(false), https, get));
    for f in ["server.pem", "server-key.pem"] {
        std::fs::copy(new.path(f), old.path(f)).unwrap();
    }
    s.reload().unwrap();
    for (at, ask) in [(nats, &b"PING\r\n"[..]), (https, &get[..])] {
        assert!(!handshakes(old.client(false), at, ask), "{at}: the old CA");
        assert!(handshakes(new.client(false), at, ask), "{at}: the new CA");
    }
}
