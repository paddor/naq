//! WebSocket clients, where naq goes beyond what the wire scripts can
//! compare with `nats-server`: close frames on errors, `wss://`, time
//! limits.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use naq::{Error, Options, Server, Tls, Websocket};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

fn server(ws: Websocket) -> Server {
    Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        websocket: Some(Websocket {
            host: "127.0.0.1".into(),
            ..ws
        }),
        ..Options::default()
    })
    .unwrap()
}

fn plain() -> Websocket {
    Websocket {
        no_tls: true,
        ..Websocket::default()
    }
}

fn tcp(s: &Server) -> TcpStream {
    let t = TcpStream::connect(s.websocket_addr().unwrap()).unwrap();
    t.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    t
}

/// Sends the upgrade and reads the response head.
fn upgrade<S: Read + Write>(s: &mut S) -> String {
    s.write_all(UPGRADE.as_bytes()).unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).unwrap(), 1, "closed in the upgrade");
        head.push(b[0]);
    }
    String::from_utf8(head).unwrap()
}

/// A masked client frame.
fn frame(op: u8, payload: &[u8]) -> Vec<u8> {
    let key = [9, 8, 7, 6];
    assert!(payload.len() < 126);
    let mut f = vec![0x80 | op, 0x80 | payload.len() as u8];
    f.extend_from_slice(&key);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
    f
}

/// The next frame: opcode and payload. `None` at the end.
fn next<S: Read>(s: &mut S) -> Option<(u8, Vec<u8>)> {
    let mut h = [0u8; 2];
    s.read_exact(&mut h).ok()?;
    let len = match h[1] & 0x7f {
        126 => {
            let mut l = [0u8; 2];
            s.read_exact(&mut l).unwrap();
            usize::from(u16::from_be_bytes(l))
        }
        127 => {
            let mut l = [0u8; 8];
            s.read_exact(&mut l).unwrap();
            u64::from_be_bytes(l) as usize
        }
        n => usize::from(n),
    };
    let mut payload = vec![0; len];
    s.read_exact(&mut payload).unwrap();
    Some((h[0] & 0x0f, payload))
}

/// The NATS bytes of data frames up to the first control frame, and that
/// frame.
fn until_control<S: Read>(s: &mut S) -> (String, Option<(u8, Vec<u8>)>) {
    let mut data = Vec::new();
    loop {
        match next(s) {
            Some((0x2, p)) => data.extend(p),
            other => return (String::from_utf8(data).unwrap(), other),
        }
    }
}

/// A close frame with `status` and `text`, as [`next`] returns it.
fn close(status: u16, text: &str) -> (u8, Vec<u8>) {
    let mut p = status.to_be_bytes().to_vec();
    p.extend_from_slice(text.as_bytes());
    (0x8, p)
}

#[test]
fn broken_frames_get_a_close_frame_with_the_reason() {
    let s = server(plain());
    let cases: [(&[u8], &str); 4] = [
        (b"\x82\x06PING\r\n", "mask bit missing"),
        (b"\x83\x80\0\0\0\0", "unknown opcode 3"),
        (b"\x80\x80\0\0\0\0", "invalid continuation frame"),
        (
            b"\x02\x80\0\0\0\0\x82\x80\0\0\0\0",
            "new message started before final frame for previous message was received",
        ),
    ];
    for (bad, reason) in cases {
        let mut t = tcp(&s);
        upgrade(&mut t);
        t.write_all(&frame(0x2, b"CONNECT {\"verbose\":false}\r\nPING\r\n"))
            .unwrap();
        t.write_all(bad).unwrap();
        let (data, end) = until_control(&mut t);
        assert!(
            data.starts_with("INFO ") && data.ends_with("PONG\r\n"),
            "{data}"
        );
        assert_eq!(end, Some(close(1002, reason)));
        assert_eq!(next(&mut t), None);
    }
}

#[test]
fn protocol_errors_get_their_err_then_a_close_frame() {
    let s = server(plain());
    let mut t = tcp(&s);
    upgrade(&mut t);
    t.write_all(&frame(0x2, b"CONNECT {\"verbose\":false}\r\nFOO\r\n"))
        .unwrap();
    let (data, end) = until_control(&mut t);
    assert!(
        data.ends_with("-ERR 'Unknown Protocol Operation'\r\n"),
        "{data}"
    );
    assert_eq!(end, Some(close(1002, "Parse Error")));
}

#[test]
fn an_upgrade_that_does_not_come_in_time_is_closed() {
    let s = server(Websocket {
        handshake_timeout: Duration::from_millis(100),
        ..plain()
    });
    let mut t = tcp(&s);
    let start = Instant::now();
    let mut b = [0u8; 1];
    assert!(matches!(t.read(&mut b), Ok(0) | Err(_)));
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn websocket_clients_get_pings_at_their_own_interval() {
    let s = server(Websocket {
        ping_interval: Some(Duration::from_millis(100)),
        // No limit on the upgrade.
        handshake_timeout: Duration::ZERO,
        ..plain()
    });
    let mut t = tcp(&s);
    upgrade(&mut t);
    t.write_all(&frame(0x2, b"CONNECT {\"verbose\":false}\r\n"))
        .unwrap();
    let mut got = String::new();
    while !got.ends_with("PING\r\n") {
        let (op, p) = next(&mut t).unwrap();
        assert_eq!(op, 0x2);
        got += std::str::from_utf8(&p).unwrap();
    }
}

#[test]
fn websocket_options_that_cannot_run_are_refused() {
    let e = Server::start(&Options {
        port: 0,
        websocket: Some(Websocket::default()),
        ..Options::default()
    })
    .unwrap_err();
    assert!(matches!(e, Error::Options(_)), "{e}");
    let s = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        ..Options::default()
    })
    .unwrap();
    assert_eq!(s.websocket_addr(), None);
}

#[test]
fn wss_runs_tls_before_the_upgrade() {
    let dir = std::env::temp_dir().join(format!("naq-wss-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
    let s = server(Websocket {
        tls: Some(Tls {
            cert_file: dir.join("cert.pem"),
            key_file: dir.join("key.pem"),
            ca_file: None,
            verify: false,
            timeout: Duration::from_secs(2),
            handshake_first: false,
            fallback: None,
        }),
        ..Websocket::default()
    });
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(dir.join("cert.pem")).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from("localhost").unwrap();
    let conn = ClientConnection::new(Arc::new(cfg), name).unwrap();
    let mut tls = StreamOwned::new(conn, tcp(&s));
    assert!(upgrade(&mut tls).starts_with("HTTP/1.1 101 "));
    tls.write_all(&frame(
        0x2,
        b"CONNECT {\"verbose\":false}\r\nSUB a 1\r\nPUB a 2\r\nhi\r\nPING\r\n",
    ))
    .unwrap();
    let mut got = String::new();
    while !got.ends_with("PONG\r\n") {
        let (_, p) = next(&mut tls).unwrap();
        got += std::str::from_utf8(&p).unwrap();
    }
    assert!(got.contains(r#""tls_required":true"#), "{got}");
    assert!(got.contains(r#""tls_available":true"#), "{got}");
    assert!(got.ends_with("MSG a 1 2\r\nhi\r\nPONG\r\n"), "{got}");
    std::fs::remove_dir_all(&dir).unwrap();
}
