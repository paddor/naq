//! naq as a leaf node: links to a scripted hub, and to `nats-server` when
//! `NAQ_GO` names one.

#![expect(clippy::unwrap_used, clippy::panic, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use naq::{Options, Remote, Server};

/// Longest wait for anything a test expects.
const WAIT: Duration = Duration::from_secs(5);

/// A naq leaf that dials `url`, quickly again after a link ends.
fn leaf(url: &str) -> Server {
    Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        server_name: "naq-leaf".into(),
        leaf_reconnect: Duration::from_millis(50),
        remotes: vec![Remote {
            urls: vec![url.into()],
            ..Remote::default()
        }],
        ..Options::default()
    })
    .unwrap()
}

/// A hub played by the test: it accepts a link and speaks for itself.
struct Hub {
    listener: TcpListener,
}

impl Hub {
    fn new() -> Hub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Hub { listener }
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    /// The next link, within [`WAIT`].
    fn accept(&self) -> Peer {
        self.accept_within(WAIT)
            .unwrap_or_else(|| panic!("no link within {WAIT:?}"))
    }

    /// The next link, if one comes within `wait`.
    fn accept_within(&self, wait: Duration) -> Option<Peer> {
        let deadline = Instant::now() + wait;
        loop {
            match self.listener.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    s.set_read_timeout(Some(WAIT)).unwrap();
                    return Some(Peer {
                        r: BufReader::new(s.try_clone().unwrap()),
                        w: s,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        }
    }
}

/// The hub's end of a link.
struct Peer {
    r: BufReader<TcpStream>,
    w: TcpStream,
}

impl Peer {
    fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
    }

    /// The next line the leaf sends, without its CRLF.
    fn line(&mut self) -> String {
        let mut l = String::new();
        self.r.read_line(&mut l).unwrap();
        l.trim_end_matches(['\r', '\n']).to_owned()
    }

    /// Whether the leaf closed the link.
    fn closed(&mut self) -> bool {
        let mut l = String::new();
        matches!(self.r.read_line(&mut l), Ok(0))
    }
}

const INFO: &str = "INFO {\"server_id\":\"HUB\",\"client_id\":5,\"headers\":true,\"info_on_connect\":true,\"compression\":\"s2_auto\",\"nonce\":\"n\"} \r\n";

#[test]
fn a_leaf_connects_as_nats_server_does_and_answers_pings() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("nats-leaf://al:secret@127.0.0.1:{}", hub.port()));
    let mut p = hub.accept();
    p.send(INFO);
    let connect = p.line();
    let json: serde_json::Value =
        serde_json::from_str(connect.strip_prefix("CONNECT ").unwrap()).unwrap();
    assert_eq!(json["name"], "naq-leaf");
    assert_eq!(json["headers"], true);
    assert_eq!(json["remote_account"], "$G");
    assert_eq!(
        (json["user"].as_str(), json["pass"].as_str()),
        (Some("al"), Some("secret"))
    );
    for absent in ["compress_mode", "lang", "account", "protocol", "auth_token"] {
        assert!(json.get(absent).is_none(), "{absent} in {connect}");
    }
    p.send("INFO {\"connect_info\":true,\"remote_account\":\"$G\"}\r\nPING\r\n");
    assert_eq!(p.line(), "PONG");
}

#[test]
fn a_user_without_a_password_is_a_token() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("nats://t0k@127.0.0.1:{}", hub.port()));
    let mut p = hub.accept();
    p.send(INFO);
    let json: serde_json::Value =
        serde_json::from_str(p.line().strip_prefix("CONNECT ").unwrap()).unwrap();
    assert_eq!(
        (json["user"].as_str(), json["auth_token"].as_str()),
        (Some("t0k"), Some("t0k"))
    );
}

#[test]
fn a_link_that_ends_is_dialed_again() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = hub.accept();
    p.send(INFO);
    p.line();
    p.send("INFO {\"connect_info\":true}\r\n");
    drop(p);
    let mut again = hub.accept();
    again.send(INFO);
    assert!(again.line().starts_with("CONNECT "));
}

#[test]
fn a_client_port_is_left_and_dialed_again() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = hub.accept();
    // What a client port says: no client ID for a leaf, no leaf URLs.
    p.send("INFO {\"server_id\":\"HUB\",\"client_id\":0} \r\n");
    assert!(p.closed());
    let mut p = hub.accept();
    // A cluster name a leaf may not take.
    p.send("INFO {\"server_id\":\"HUB\",\"client_id\":5,\"info_on_connect\":true,\"cluster\":\"a b\"}\r\n");
    assert_eq!(p.line(), "-ERR 'cluster name cannot contain spaces'");
    assert!(p.closed());
    let mut p = hub.accept();
    // No answer to the CONNECT.
    p.send(INFO);
    p.line();
    let started = Instant::now();
    assert!(p.closed());
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_hub_that_stops_answering_pings_is_left() {
    let hub = Hub::new();
    let _leaf = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        ping_interval: Duration::from_millis(100),
        remotes: vec![Remote {
            urls: vec![format!("127.0.0.1:{}", hub.port())],
            ..Remote::default()
        }],
        ..Options::default()
    })
    .unwrap();
    let mut p = hub.accept();
    p.send(INFO);
    p.line();
    p.send("INFO {\"connect_info\":true}\r\n");
    assert_eq!(p.line(), "PING");
    p.send("PONG\r\n");
    assert_eq!(p.line(), "PING");
    assert_eq!(p.line(), "PING");
    assert_eq!(p.line(), "-ERR 'Stale Connection'");
    assert!(p.closed());
}

/// A link up to its `connect_info`, from the hub's end.
fn linked(hub: &Hub) -> Peer {
    let mut p = hub.accept();
    p.send(INFO);
    p.line();
    p.send("INFO {\"connect_info\":true}\r\n");
    p
}

/// Whether the leaf dials again within half a second, as it does after a
/// plain end with the 50 ms interval of [`leaf`].
fn dials_soon(hub: &Hub) -> bool {
    hub.accept_within(Duration::from_millis(500)).is_some()
}

#[test]
fn errors_that_say_wait_hold_the_next_dial() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = linked(&hub);
    p.send("-ERR 'Authorization Violation'\r\nPING\r\n");
    // Not an error to leave on: the link goes on.
    assert_eq!(p.line(), "PONG");
    p.send("-ERR 'Loop detected for leafnode account=\"$G\". Delaying attempt to reconnect for 30s'\r\n");
    assert!(p.closed());
    assert!(!dials_soon(&hub), "dialed again at once after a loop");

    let hub = Hub::new();
    let _leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = hub.accept();
    p.send(INFO);
    p.line();
    p.send("-ERR 'remote leafnode has same cluster name'\r\n");
    drop(p);
    assert!(
        !dials_soon(&hub),
        "dialed again at once after a cluster clash"
    );
}

#[test]
fn a_ping_before_the_connect_info_is_answered() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = hub.accept();
    p.send(INFO);
    p.line();
    p.send("+OK\r\nPING\r\n");
    assert_eq!(p.line(), "PONG");
    p.send("INFO {\"connect_info\":true}\r\n");
    // A message in two reads, then a PING behind it.
    let big = "x".repeat(70_000);
    p.send(&format!("LMSG s {}\r\n{}", big.len(), &big[..10]));
    std::thread::sleep(Duration::from_millis(20));
    p.send(&format!("{}\r\nPING\r\n", &big[10..]));
    assert_eq!(p.line(), "PONG");
}

#[test]
fn hubs_that_break_the_handshake_or_the_link_are_left() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let scripts: [&[&str]; 6] = [
        // TLS to hubs is not there yet.
        &["INFO {\"client_id\":5,\"info_on_connect\":true,\"tls_required\":true}\r\n"],
        // An answer that is not the connect_info.
        &[INFO, "INFO {\"server_id\":\"HUB\"}\r\n"],
        &[INFO, "BOGUS\r\n"],
        &["INFO {not json}\r\n"],
        &[INFO, "INFO {\"connect_info\":true}\r\n", "CONNECT {}\r\n"],
        &[INFO, "INFO {\"connect_info\":true}\r\n", "LS+ a b\r\n"],
    ];
    for script in scripts {
        let mut p = hub.accept();
        for step in script {
            p.send(step);
        }
        let mut l = String::new();
        // The CONNECT may come first; then the end.
        while p.r.read_line(&mut l).unwrap_or(0) > 0 {
            l.clear();
        }
    }
    // A hub that goes away in the handshake.
    let mut p = hub.accept();
    p.send(INFO);
    p.line();
    drop(p);
    assert!(dials_soon(&hub));
}

#[test]
fn hub_urls_are_tried_in_turn() {
    let hub = Hub::new();
    let dead = free_port();
    for no_randomize in [true, false] {
        let _leaf = Server::start(&Options {
            host: "127.0.0.1".into(),
            port: 0,
            leaf_reconnect: Duration::from_millis(20),
            remotes: vec![Remote {
                urls: vec![
                    format!("127.0.0.1:{dead}"),
                    format!("127.0.0.1:{}", hub.port()),
                ],
                no_randomize,
                ..Remote::default()
            }],
            ..Options::default()
        })
        .unwrap();
        let mut p = hub.accept();
        p.send(INFO);
        assert!(p.line().starts_with("CONNECT "));
    }
}

/// `nats-server` from `NAQ_GO`, with `conf`; `None` without `NAQ_GO`.
fn go(conf: &str) -> Option<GoServer> {
    let bin = PathBuf::from(std::env::var_os("NAQ_GO")?);
    let dir = std::env::temp_dir().join(format!("naq-leaf-{}-{}", std::process::id(), fastrand()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.conf");
    std::fs::write(&path, conf).unwrap();
    let child = Command::new(bin)
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Some(GoServer { child, dir })
}

/// A number that differs between calls.
fn fastrand() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

struct GoServer {
    child: Child,
    dir: PathBuf,
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A free port.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `GET path` on the hub's monitoring port, once it answers.
fn get(port: u16, path: &str) -> serde_json::Value {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
            let mut body = String::new();
            std::io::Read::read_to_string(&mut s, &mut body).unwrap();
            if let Some((_, json)) = body.split_once("\r\n\r\n") {
                return serde_json::from_str(json).unwrap();
            }
        }
        assert!(Instant::now() < deadline, "no answer on {port}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Waits until `f` holds of the hub's `/leafz`, and returns it.
fn leafz_until(http: u16, f: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let z = get(http, "/leafz");
        if f(&z) {
            return z;
        }
        assert!(Instant::now() < deadline, "/leafz: {z}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_go_hub_takes_the_link_uncompressed_and_sees_it_come_back() {
    let (leafport, http) = (free_port(), free_port());
    let conf = format!("port: -1\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\n");
    let Some(hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let _leaf = leaf(&format!("nats-leaf://127.0.0.1:{leafport}"));
    let z = leafz_until(http, |z| z["leafnodes"] == 1);
    let link = &z["leafs"][0];
    assert_eq!(link["name"], "naq-leaf");
    assert_eq!(link["account"], "$G");
    assert_eq!(link["compression"], "not supported");
    drop(hub);
    let _hub = go(&conf).unwrap();
    leafz_until(http, |z| z["leafnodes"] == 1);
}
