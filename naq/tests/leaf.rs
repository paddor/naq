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
    p.send("INFO {\"connect_info\":true,\"remote_account\":\"$G\"}\r\n");
    lines_until(&mut p, "LS+ $LDS.");
    p.send("PING\r\n");
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
    lines_until(&mut p, "LS+ $LDS.");
    assert_eq!(p.line(), "PING");
    p.send("PONG\r\n");
    assert_eq!(p.line(), "PING");
    assert_eq!(p.line(), "PING");
    assert_eq!(p.line(), "-ERR 'Stale Connection'");
    assert!(p.closed());
}

/// A link up to its `connect_info`, from the hub's end, and the interest
/// the leaf tells of first.
fn linked_with(hub: &Hub) -> (Peer, Vec<String>) {
    let mut p = hub.accept();
    p.send(INFO);
    p.line();
    p.send("INFO {\"connect_info\":true}\r\n");
    let first = lines_until(&mut p, "LS+ $LDS.");
    (p, first)
}

/// A link up to its `connect_info` and the interest that follows.
fn linked(hub: &Hub) -> Peer {
    linked_with(hub).0
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
    lines_until(&mut p, "LS+ $LDS.");
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

/// A client of `server`, subscribed as `subs` say, once the server
/// answered its `PING`.
fn client(server: &Server, subs: &str) -> Peer {
    let s = TcpStream::connect(server.addr()).unwrap();
    s.set_read_timeout(Some(WAIT)).unwrap();
    let mut c = Peer {
        r: BufReader::new(s.try_clone().unwrap()),
        w: s,
    };
    c.line();
    c.send(&format!("CONNECT {{\"verbose\":false}}\r\n{subs}PING\r\n"));
    assert_eq!(c.line(), "PONG");
    c
}

/// The lines the leaf sends until one starts with `last`, that one too.
fn lines_until(p: &mut Peer, last: &str) -> Vec<String> {
    let mut got = Vec::new();
    loop {
        let l = p.line();
        let done = l.starts_with(last);
        got.push(l);
        if done {
            return got;
        }
    }
}

#[test]
fn the_hub_hears_of_local_interest_as_it_comes_and_goes() {
    let hub = Hub::new();
    let leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let _before = client(&leaf, "SUB a.b 1\r\nSUB w.* q 2\r\n");
    let (mut p, mut first) = linked_with(&hub);
    let lds = first.pop().unwrap();
    first.sort();
    assert_eq!(first, ["LS+ a.b", "LS+ w.* q 1"]);
    assert_eq!(lds.len(), "LS+ $LDS.".len() + 22, "{lds}");
    let mut after = client(&leaf, "SUB a.b 1\r\nSUB c 2\r\nSUB w.* q 3\r\n");
    let mut more = vec![p.line(), p.line()];
    more.sort();
    assert_eq!(more, ["LS+ c", "LS+ w.* q 2"]);
    after.send("UNSUB 2\r\nUNSUB 3\r\nPING\r\n");
    assert_eq!(after.line(), "PONG");
    let mut gone = vec![p.line(), p.line()];
    gone.sort();
    assert_eq!(gone, ["LS+ w.* q 1", "LS- c"]);
    drop(after);
    // Its plain sub went with it, the one before stays.
    p.send("PING\r\n");
    assert_eq!(p.line(), "PONG");
}

#[test]
fn its_own_loop_subject_coming_back_ends_the_link() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let (mut p, mut first) = linked_with(&hub);
    let lds = first.pop().unwrap();
    p.send(&format!("{lds}\r\n"));
    let err = p.line();
    assert!(
        err.starts_with("-ERR 'Loop detected for leafnode account=\"$G\"."),
        "{err}"
    );
    assert!(p.closed());
    assert!(!dials_soon(&hub));
}

#[test]
fn a_go_hub_learns_the_interest_of_naq_clients() {
    let (leafport, http) = (free_port(), free_port());
    let conf = format!("port: -1\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\n");
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let leaf = leaf(&format!("nats-leaf://127.0.0.1:{leafport}"));
    let _c = client(&leaf, "SUB orders.* 1\r\nSUB jobs q 2\r\n");
    let z = leafz_until(http, |z| z["leafs"][0]["subscriptions"] == 3);
    let mut subs: Vec<String> = z["leafs"][0]["subscriptions_list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .filter(|s| !s.starts_with("$LDS."))
        .collect();
    subs.sort();
    // `nats-server` lists queue subscriptions by subject.
    assert_eq!(subs, ["jobs", "orders.*"]);
}

/// Waits until a client of `leaf` publishing to `subject` reaches the hub
/// at `p`: hub interest reaches the lanes in its own time.
fn wait_for_interest(leaf: &Server, p: &mut Peer, subject: &str) {
    let mut c = client(leaf, "");
    let deadline = Instant::now() + WAIT;
    p.w.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    loop {
        c.send(&format!("PUB {subject} 4\r\nwait\r\n"));
        let mut l = String::new();
        if p.r.read_line(&mut l).is_ok() && l.starts_with("LMSG") {
            p.line();
            break;
        }
        assert!(Instant::now() < deadline, "no interest in {subject}");
    }
    p.w.set_read_timeout(Some(WAIT)).unwrap();
}

#[test]
fn messages_reach_the_hub_once_with_the_queue_groups_picked_for_it() {
    let hub = Hub::new();
    let leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = linked(&hub);
    p.send("LS+ s\r\nLS+ q.s q 3\r\nLS+ c\r\nLS+ c g 1\r\n");
    wait_for_interest(&leaf, &mut p, "s");
    // Two publishers, so one is on the link's lane and one is not.
    let mut a = client(&leaf, "");
    let mut b = client(&leaf, "");
    for c in [&mut a, &mut b] {
        c.send("PUB s 2\r\nhi\r\n");
        assert_eq!((p.line(), p.line()), ("LMSG s 2".into(), "hi".into()));
        // No naq member: the hub's gets it.
        c.send("PUB q.s 2\r\nhi\r\n");
        assert_eq!((p.line(), p.line()), ("LMSG q.s | q 2".into(), "hi".into()));
        // Plain interest and a group of the hub: one message.
        c.send("PUB c r 2\r\nhi\r\n");
        assert_eq!((p.line(), p.line()), ("LMSG c + r g 2".into(), "hi".into()));
    }
    // A naq member comes first; the hub gets the plain message only.
    let mut m = client(&leaf, "SUB q.s q 1\r\nSUB c g 2\r\n");
    let mut told = lines(&mut p, 2);
    told.sort();
    assert_eq!(told, ["LS+ c g 1", "LS+ q.s q 1"]);
    a.send("PUB q.s 2\r\nhi\r\nPUB c 2\r\nhi\r\nPUB s 2\r\nhi\r\n");
    assert_eq!((m.line(), m.line()), ("MSG q.s 1 2".into(), "hi".into()));
    assert_eq!((m.line(), m.line()), ("MSG c 2 2".into(), "hi".into()));
    assert_eq!((p.line(), p.line()), ("LMSG c 2".into(), "hi".into()));
    assert_eq!((p.line(), p.line()), ("LMSG s 2".into(), "hi".into()));
}

#[test]
fn headers_cross_the_link_where_the_hub_takes_them() {
    let hub = Hub::new();
    let leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = linked(&hub);
    p.send("LS+ h\r\n");
    wait_for_interest(&leaf, &mut p, "h");
    let mut c = client(&leaf, "");
    c.send("CONNECT {\"headers\":true}\r\nHPUB h 12 14\r\nNATS/1.0\r\n\r\nhi\r\n");
    assert_eq!(lines(&mut p, 4), ["HMSG h 12 14", "NATS/1.0", "", "hi"]);
}

#[test]
fn interest_the_hub_drops_or_had_on_an_old_link_gets_nothing() {
    let hub = Hub::new();
    let leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = linked(&hub);
    p.send("LS+ x\r\nLS+ y\r\n");
    wait_for_interest(&leaf, &mut p, "x");
    p.send("LS- y\r\nLS- nothing\r\n");
    let mut c = client(&leaf, "");
    // Each lane hears of the LS- in its own time: until then y comes too.
    // A message on x after it shows when y goes nowhere.
    let deadline = Instant::now() + WAIT;
    loop {
        c.send("PUB y 2\r\nhi\r\nPUB x 2\r\nhi\r\n");
        let first = lines(&mut p, 2);
        if first == ["LMSG x 2", "hi"] {
            break;
        }
        assert_eq!(first, ["LMSG y 2", "hi"]);
        assert_eq!(lines(&mut p, 2), ["LMSG x 2", "hi"]);
        assert!(Instant::now() < deadline, "y still goes to the hub");
    }
    drop(p);
    let mut again = linked(&hub);
    c.send("PUB x 2\r\nhi\r\n");
    again.send("LS+ z\r\n");
    wait_for_interest(&leaf, &mut again, "z");
}

/// The next `n` lines from `p`.
fn lines(p: &mut Peer, n: usize) -> Vec<String> {
    (0..n).map(|_| p.line()).collect()
}

#[test]
fn a_go_hub_gets_what_naq_clients_publish() {
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let conf = format!("port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\n");
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let mut sub = go_client(port, "SUB orders.* 1\r\nSUB jobs q 2\r\n");
    let leaf = leaf(&format!("nats-leaf://127.0.0.1:{leafport}"));
    leafz_until(http, |z| z["leafnodes"] == 1);
    let mut c = client(&leaf, "");
    // Until the hub's interest reaches the leaf.
    let deadline = Instant::now() + WAIT;
    sub.w
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    loop {
        c.send("PUB orders.1 2\r\nhi\r\n");
        let mut l = String::new();
        if sub.r.read_line(&mut l).is_ok() && l.starts_with("MSG orders.1 1 2") {
            sub.line();
            break;
        }
        assert!(Instant::now() < deadline, "nothing came");
    }
    sub.w.set_read_timeout(Some(WAIT)).unwrap();
    c.send("PUB jobs 3\r\njob\r\n");
    assert_eq!(lines(&mut sub, 2), ["MSG jobs 2 3", "job"]);
}

/// A client of the Go server on `port`, subscribed as `subs` say.
fn go_client(port: u16, subs: &str) -> Peer {
    let deadline = Instant::now() + WAIT;
    let s = loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            break s;
        }
        assert!(Instant::now() < deadline, "no Go server on {port}");
        std::thread::sleep(Duration::from_millis(20));
    };
    s.set_read_timeout(Some(WAIT)).unwrap();
    let mut c = Peer {
        r: BufReader::new(s.try_clone().unwrap()),
        w: s,
    };
    c.line();
    c.send(&format!("CONNECT {{\"verbose\":false}}\r\n{subs}PING\r\n"));
    assert_eq!(c.line(), "PONG");
    c
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
        let z = get(http, "/leafz?subs=1");
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

/// Waits until the leaf told the hub at `p` each of `lines`, in any
/// order: the link's lane has that interest then.
fn told(p: &mut Peer, lines: &[&str]) {
    let mut left = lines.to_vec();
    while !left.is_empty() {
        let l = p.line();
        left.retain(|x| *x != l);
    }
}

/// The messages `c` got, as `MSG` line and payload, until one on `done`.
fn got_until_done(c: &mut Peer) -> Vec<(String, String)> {
    let mut got = Vec::new();
    loop {
        let m = (c.line(), c.line());
        if m.0.starts_with("MSG done ") {
            return got;
        }
        got.push(m);
    }
}

#[test]
fn messages_of_the_hub_reach_every_plain_subscriber_and_the_groups_it_lists() {
    let hub = Hub::new();
    let leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = linked(&hub);
    // Two of each, so one is on the link's lane and one is not. The queue
    // subscription comes last: once the hub hears of both, the link's lane
    // has all.
    let subs = "SUB m 1\r\nSUB m.> 3\r\nSUB done 9\r\nSUB m q 2\r\n";
    let mut a = client(&leaf, subs);
    let mut b = client(&leaf, subs);
    told(&mut p, &["LS+ m q 2"]);
    p.send("LMSG m 2\r\nhi\r\nLMSG m | q 2\r\nqq\r\nLMSG m + r other q 2\r\nrr\r\n");
    p.send("LMSG m | other 2\r\nno\r\nLMSG m.x.y r 2\r\nxy\r\nLMSG done 0\r\n\r\n");
    let pair = |m: &str, p: &str| (m.to_owned(), p.to_owned());
    let plain = [
        pair("MSG m 1 2", "hi"),
        pair("MSG m 1 2", "qq"),
        pair("MSG m 1 r 2", "rr"),
        pair("MSG m 1 2", "no"),
        pair("MSG m.x.y 3 r 2", "xy"),
    ];
    let mut picked = Vec::new();
    for c in [&mut a, &mut b] {
        let (q, rest): (Vec<_>, Vec<_>) = got_until_done(c)
            .into_iter()
            .partition(|(m, _)| m.starts_with("MSG m 2 "));
        assert_eq!(rest, plain);
        picked.extend(q);
    }
    picked.sort();
    // One member of q each, where the hub listed it.
    assert_eq!(picked, [pair("MSG m 2 2", "qq"), pair("MSG m 2 r 2", "rr")]);
}

#[test]
fn a_message_of_the_hub_never_goes_back_to_it() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = linked(&hub);
    // Its own interest is on the link's lane at once.
    p.send("LS+ m\r\nLS+ m q 1\r\nLMSG m 2\r\nhi\r\nLMSG m | q 2\r\nhi\r\nPING\r\n");
    assert_eq!(p.line(), "PONG");
}

#[test]
fn messages_of_the_hub_on_denied_subjects_are_dropped() {
    let hub = Hub::new();
    let leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = linked(&hub);
    let mut c = client(&leaf, "SUB > 1\r\n");
    told(&mut p, &["LS+ >"]);
    p.send("LMSG $KV.b.k 2\r\nno\r\nLMSG $JS.API.INFO 2\r\nno\r\nLMSG $JS.ACK.x 2\r\nok\r\n");
    assert_eq!(lines(&mut c, 2), ["MSG $JS.ACK.x 1 2", "ok"]);
}

#[test]
fn headers_of_the_hub_reach_the_clients_that_take_them() {
    let hub = Hub::new();
    let leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = linked(&hub);
    let mut h = client(&leaf, "CONNECT {\"headers\":true}\r\nSUB h 1\r\n");
    let mut n = client(&leaf, "SUB * 1\r\n");
    told(&mut p, &["LS+ h", "LS+ *"]);
    p.send("HMSG h 12 14\r\nNATS/1.0\r\n\r\nhi\r\n");
    assert_eq!(lines(&mut h, 4), ["HMSG h 1 12 14", "NATS/1.0", "", "hi"]);
    assert_eq!(lines(&mut n, 2), ["MSG h 1 2", "hi"]);
}

#[test]
fn a_message_of_one_hub_reaches_another() {
    let (one, two) = (Hub::new(), Hub::new());
    let remote = |h: &Hub| Remote {
        urls: vec![format!("127.0.0.1:{}", h.port())],
        ..Remote::default()
    };
    let _leaf = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        server_name: "naq-leaf".into(),
        remotes: vec![remote(&one), remote(&two)],
        ..Options::default()
    })
    .unwrap();
    let (mut p1, mut p2) = (linked(&one), linked(&two));
    p2.send("LS+ m\r\nLS+ m q 1\r\n");
    // Until the interest of hub two reaches the lane of link one.
    let deadline = Instant::now() + WAIT;
    p2.w.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    loop {
        p1.send("LMSG m 4\r\nwait\r\n");
        let mut l = String::new();
        if p2.r.read_line(&mut l).is_ok() && l.starts_with("LMSG m 4") {
            p2.line();
            break;
        }
        assert!(Instant::now() < deadline, "nothing came");
    }
    p2.w.set_read_timeout(Some(WAIT)).unwrap();
    // No client member: the group of hub two is the last resort.
    p1.send("LMSG m | q 2\r\nhi\r\n");
    loop {
        let m = lines(&mut p2, 2);
        if m != ["LMSG m 4", "wait"] {
            assert_eq!(m, ["LMSG m | q 2", "hi"]);
            break;
        }
    }
}

#[test]
fn naq_clients_get_what_go_hub_clients_publish() {
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let conf = format!("port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\n");
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let leaf = leaf(&format!("nats-leaf://127.0.0.1:{leafport}"));
    let mut sub = client(&leaf, "SUB orders.* 1\r\nSUB jobs q 2\r\n");
    leafz_until(http, |z| z["leafs"][0]["subscriptions"] == 3);
    let mut c = go_client(port, "");
    // No member at the hub: the one of the leaf gets the job.
    c.send("PUB orders.1 2\r\nhi\r\nPUB jobs 3\r\njob\r\n");
    assert_eq!(
        lines(&mut sub, 4),
        ["MSG orders.1 1 2", "hi", "MSG jobs 2 3", "job"]
    );
}
