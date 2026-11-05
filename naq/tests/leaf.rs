//! naq as a leaf node: links to a scripted hub, and to `nats-server` when
//! `NAQ_GO` names one.

#![expect(clippy::unwrap_used, clippy::panic, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use naq::{Options, Remote, RemoteTls, Server};

/// Longest wait for anything a test expects.
const WAIT: Duration = Duration::from_secs(5);

/// A naq leaf that dials `url`, quickly again after a link ends.
fn leaf(url: &str) -> Server {
    leaf_with(Remote {
        urls: vec![url.into()],
        ..Remote::default()
    })
}

/// A naq leaf of `remote`, which it dials quickly again after a link ends.
fn leaf_with(remote: Remote) -> Server {
    leaf_named("naq-leaf", remote)
}

/// [`leaf_with`], with server name `name`.
fn leaf_named(name: &str, remote: Remote) -> Server {
    Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        server_name: name.into(),
        leaf_reconnect: Duration::from_millis(50),
        remotes: vec![remote],
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

/// A user NKey seed.
const SEED: &str = "SUABXPISJ672XCVCU7XD7CVTTXYTBXTGZ4LX3WZCSLCPKHDPCXCLZVMVPI";

/// The `CONNECT` of a leaf of `remote` that dials `hub`, as JSON.
fn connect_of(hub: &Hub, mut remote: Remote) -> serde_json::Value {
    remote.urls = vec![format!("127.0.0.1:{}", hub.port())];
    let _leaf = leaf_with(remote);
    let mut p = hub.accept();
    p.send(INFO);
    serde_json::from_str(p.line().strip_prefix("CONNECT ").unwrap()).unwrap()
}

/// Whether `sig` of `json` is the hub's nonce `n`, signed with [`SEED`].
fn signed(json: &serde_json::Value) -> bool {
    let sig = data_encoding::BASE64URL_NOPAD
        .decode(json["sig"].as_str().unwrap().as_bytes())
        .unwrap();
    let key = nkeys::KeyPair::from_seed(SEED).unwrap();
    key.verify(b"n", &sig).is_ok()
}

#[test]
fn a_seed_signs_the_nonce_of_the_hub() {
    let json = connect_of(
        &Hub::new(),
        Remote {
            nkey: Some(SEED.into()),
            ..Remote::default()
        },
    );
    let key = nkeys::KeyPair::from_seed(SEED).unwrap().public_key();
    assert_eq!(json["nkey"].as_str(), Some(key.as_str()));
    assert!(signed(&json), "{json}");
    assert!(json.get("jwt").is_none(), "{json}");
}

#[test]
fn a_credentials_file_gives_its_jwt_and_signs_the_nonce() {
    let dir = std::env::temp_dir().join(format!("naq-leaf-creds-{}", fastrand()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("user.creds");
    std::fs::write(
        &path,
        format!(
            "-----BEGIN NATS USER JWT-----\nthe.user.jwt\n------END NATS USER JWT------\n\n\
             -----BEGIN USER NKEY SEED-----\n{SEED}\n------END USER NKEY SEED------\n"
        ),
    )
    .unwrap();
    let json = connect_of(
        &Hub::new(),
        Remote {
            credentials: Some(path),
            ..Remote::default()
        },
    );
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(json["jwt"], "the.user.jwt");
    assert!(signed(&json), "{json}");
    assert!(json.get("nkey").is_none(), "{json}");
}

#[test]
fn a_go_hub_takes_a_leaf_that_signs_with_the_nkey_it_knows() {
    let (leafport, http) = (free_port(), free_port());
    let key = nkeys::KeyPair::from_seed(SEED).unwrap().public_key();
    let conf = format!(
        "port: -1\nhttp_port: {http}\nleafnodes {{ port: {leafport}, authorization {{ nkey: {key} }} }}\n"
    );
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let url = format!("nats-leaf://127.0.0.1:{leafport}");
    let _right = leaf_with(Remote {
        urls: vec![url.clone()],
        nkey: Some(SEED.into()),
        ..Remote::default()
    });
    leafz_until(http, |z| z["leafnodes"] == 1);
    // Named apart, so the hub would take it beside the first.
    let _wrong = leaf_named(
        "naq-wrong",
        Remote {
            urls: vec![url],
            nkey: Some(nkeys::KeyPair::new_user().seed().unwrap()),
            ..Remote::default()
        },
    );
    // It dials again every 50 ms or so, and is refused each time.
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        assert_eq!(get(http, "/leafz")["leafnodes"], 1);
        std::thread::sleep(Duration::from_millis(20));
    }
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
        // A hub that asks for TLS and never answers the handshake.
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
    let log = std::fs::File::create(dir.join("hub.log")).unwrap();
    let child = Command::new(bin)
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(log)
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
        // A failing test shows what the hub said.
        if std::thread::panicking()
            && let Ok(log) = std::fs::read_to_string(self.dir.join("hub.log"))
        {
            eprintln!("hub log:\n{log}");
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A free port, each once per run, below the kernel's ephemeral ports
/// (32768 on): a server that binds port 0 cannot take it first.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    // Test binaries of other runs start elsewhere.
    let base = 20_000 + (std::process::id() % 400) as u16 * 30;
    loop {
        // Relaxed: only uniqueness matters.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = 20_000 + (base - 20_000 + n) % 12_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
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
    until(http, "/leafz?subs=1", f)
}

/// Waits until `f` holds of `path` on the hub's monitoring port, and
/// returns it.
fn until(http: u16, path: &str, f: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let z = get(http, path);
        if f(&z) {
            return z;
        }
        assert!(Instant::now() < deadline, "{path}: {z}");
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

/// A CA, and certificates it signed for a hub at 127.0.0.1 and for a
/// leaf, in PEM files of a directory of the test's own.
struct Pki {
    dir: PathBuf,
}

impl Pki {
    fn new() -> Pki {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        let dir = std::env::temp_dir().join(format!("naq-leaf-tls-{}", fastrand()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        std::fs::write(dir.join("ca.pem"), ca.self_signed(&ca_key).unwrap().pem()).unwrap();
        let issuer = Issuer::from_params(&ca, &ca_key);
        for (who, name) in [("hub", "127.0.0.1"), ("leaf", "leaf")] {
            let key = KeyPair::generate().unwrap();
            let cert = CertificateParams::new(vec![name.to_owned()])
                .unwrap()
                .signed_by(&key, &issuer)
                .unwrap();
            std::fs::write(dir.join(format!("{who}.pem")), cert.pem()).unwrap();
            std::fs::write(dir.join(format!("{who}-key.pem")), key.serialize_pem()).unwrap();
        }
        Pki { dir }
    }

    fn path(&self, file: &str) -> String {
        self.dir.join(file).display().to_string()
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn a_hub_that_asks_for_tls_gets_a_handshake_after_its_info() {
    let hub = Hub::new();
    let _leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = hub.accept();
    p.send(&INFO.replace("\"headers\"", "\"tls_required\":true,\"headers\""));
    let mut hello = [0u8; 1];
    std::io::Read::read_exact(&mut p.r, &mut hello).unwrap();
    assert_eq!(hello[0], 0x16, "a TLS handshake record");
}

#[test]
fn a_go_hub_that_asks_for_tls_gets_it_after_its_info() {
    let pki = Pki::new();
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let conf = format!(
        "port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport}, tls {{ cert_file: \"{}\", key_file: \"{}\" }} }}\n",
        pki.path("hub.pem"),
        pki.path("hub-key.pem"),
    );
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let mut sub = go_client(port, "SUB s 1\r\n");
    let leaf = leaf_with(Remote {
        urls: vec![format!("nats-leaf://127.0.0.1:{leafport}")],
        tls: Some(RemoteTls {
            ca_file: Some(pki.path("ca.pem").into()),
            ..RemoteTls::default()
        }),
        ..Remote::default()
    });
    let z = leafz_until(http, |z| z["leafnodes"] == 1);
    assert_eq!(z["leafs"][0]["name"], "naq-leaf", "{z}");
    published_to_go(&leaf, &mut sub);
}

#[test]
fn a_go_hub_takes_tls_first_and_checks_the_certificate_of_the_leaf() {
    let pki = Pki::new();
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let conf = format!(
        "port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport}, tls {{ cert_file: \"{}\", key_file: \"{}\", ca_file: \"{}\", verify: true, handshake_first: true }} }}\n",
        pki.path("hub.pem"),
        pki.path("hub-key.pem"),
        pki.path("ca.pem"),
    );
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let mut sub = go_client(port, "SUB s 1\r\n");
    let leaf = leaf_with(Remote {
        urls: vec![format!("nats-leaf://127.0.0.1:{leafport}")],
        tls: Some(RemoteTls {
            ca_file: Some(pki.path("ca.pem").into()),
            cert_file: Some(pki.path("leaf.pem").into()),
            key_file: Some(pki.path("leaf-key.pem").into()),
            handshake_first: true,
            ..RemoteTls::default()
        }),
        ..Remote::default()
    });
    leafz_until(http, |z| z["leafnodes"] == 1);
    published_to_go(&leaf, &mut sub);
}

/// Waits until a client of `leaf` publishing to `s` reaches `sub`, a Go
/// client with `SUB s 1`: the hub's interest reaches the leaf in its own
/// time.
fn published_to_go(leaf: &Server, sub: &mut Peer) {
    let mut c = client(leaf, "");
    let deadline = Instant::now() + WAIT;
    sub.w
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    loop {
        c.send("PUB s 2\r\nhi\r\n");
        let mut l = String::new();
        if sub.r.read_line(&mut l).is_ok() && l.starts_with("MSG s 1 2") {
            sub.line();
            break;
        }
        assert!(Instant::now() < deadline, "nothing came");
    }
    sub.w.set_read_timeout(Some(WAIT)).unwrap();
}

#[test]
fn a_go_hub_takes_the_link_over_websocket() {
    let (port, wsport, leafport, http) = (free_port(), free_port(), free_port(), free_port());
    // The hub takes WebSocket leafs only with a leaf node port too.
    let conf = format!(
        "port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\nwebsocket {{ port: {wsport}, no_tls: true }}\n"
    );
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let mut sub = go_client(port, "SUB s 1\r\n");
    let leaf = leaf(&format!("ws://127.0.0.1:{wsport}/some/path"));
    leafz_until(http, |z| z["leafnodes"] == 1);
    published_to_go(&leaf, &mut sub);
    // And the other way, over the hub's frames.
    let mut mine = client(&leaf, "SUB back 1\r\n");
    leafz_until(http, |z| {
        z["leafs"][0]["subscriptions_list"]
            .as_array()
            .is_some_and(|l| l.iter().any(|s| s == "back"))
    });
    let mut go = go_client(port, "");
    go.send(&format!(
        "PUB back {}\r\n{}\r\n",
        70_000,
        "x".repeat(70_000)
    ));
    assert_eq!(mine.line(), "MSG back 1 70000");
    assert_eq!(mine.line().len(), 70_000);
}

#[test]
fn a_go_hub_takes_the_link_over_websocket_with_tls() {
    let pki = Pki::new();
    let (port, wsport, leafport, http) = (free_port(), free_port(), free_port(), free_port());
    let conf = format!(
        "port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\nwebsocket {{ port: {wsport}, tls {{ cert_file: \"{}\", key_file: \"{}\" }} }}\n",
        pki.path("hub.pem"),
        pki.path("hub-key.pem"),
    );
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let mut sub = go_client(port, "SUB s 1\r\n");
    let leaf = leaf_with(Remote {
        urls: vec![format!("wss://127.0.0.1:{wsport}")],
        tls: Some(RemoteTls {
            ca_file: Some(pki.path("ca.pem").into()),
            ..RemoteTls::default()
        }),
        ..Remote::default()
    });
    leafz_until(http, |z| z["leafnodes"] == 1);
    published_to_go(&leaf, &mut sub);
}

#[test]
fn a_hub_named_in_an_info_is_dialed_next_with_the_credentials_configured() {
    let (one, two) = (Hub::new(), Hub::new());
    let _leaf = leaf(&format!("nats://u:p@127.0.0.1:{}", one.port()));
    let mut p = linked(&one);
    p.send(&format!(
        "INFO {{\"leafnode_urls\":[\"127.0.0.1:{}\"]}}\r\n",
        two.port()
    ));
    p.send("PING\r\n");
    assert_eq!(p.line(), "PONG");
    drop(p);
    let mut q = two.accept();
    q.send(INFO);
    let json: serde_json::Value =
        serde_json::from_str(q.line().strip_prefix("CONNECT ").unwrap()).unwrap();
    assert_eq!(
        (json["user"].as_str(), json["pass"].as_str()),
        (Some("u"), Some("p"))
    );
}

/// The ports of one node of a Go hub cluster.
#[derive(Debug, Clone, Copy)]
struct Node {
    client: u16,
    route: u16,
    leaf: u16,
    http: u16,
}

/// A Go hub cluster of two nodes, `None` without `NAQ_GO`, once the
/// route between them is up.
fn go_cluster() -> Option<(Vec<GoServer>, [Node; 2])> {
    let node = || Node {
        client: free_port(),
        route: free_port(),
        leaf: free_port(),
        http: free_port(),
    };
    let nodes = [node(), node()];
    // Only node b dials the route: routes dialed both ways race, and the
    // hub tells its leafs of the cluster without node b for a moment.
    let conf = |me: usize| {
        let n = nodes[me];
        let routes = if me == 1 {
            format!("routes: [\"nats-route://127.0.0.1:{}\"]", nodes[0].route)
        } else {
            String::new()
        };
        format!(
            "port: {}\nhttp_port: {}\ncluster {{ name: c, listen: \"127.0.0.1:{}\", {routes} }}\nleafnodes {{ listen: \"127.0.0.1:{}\" }}\n",
            n.client, n.http, n.route, n.leaf
        )
    };
    let servers = vec![go(&conf(0))?, go(&conf(1)).unwrap()];
    // A route pool: several routes to the one peer. Once it is up, node a
    // tells of node b in its first INFO.
    until(nodes[0].http, "/routez", |z| {
        z["num_routes"].as_u64() > Some(0)
    });
    Some((servers, nodes))
}

#[test]
fn a_leaf_fails_over_to_another_node_of_a_go_hub_cluster() {
    let Some((mut servers, [a, b])) = go_cluster() else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let _leaf = leaf(&format!("nats-leaf://127.0.0.1:{}", a.leaf));
    leafz_until(a.http, |z| z["leafnodes"] == 1);
    drop(servers.remove(0));
    leafz_until(b.http, |z| z["leafnodes"] == 1);
}

#[test]
fn messages_cross_a_go_hub_cluster_both_ways() {
    let Some((_servers, [a, b])) = go_cluster() else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    // Clients of node b, the leaf on node a.
    let mut sub = go_client(b.client, "SUB s 1\r\n");
    let leaf = leaf(&format!("nats-leaf://127.0.0.1:{}", a.leaf));
    leafz_until(a.http, |z| z["leafnodes"] == 1);
    published_to_go(&leaf, &mut sub);
    let mut mine = client(&leaf, "SUB back 1\r\nSUB jobs q 2\r\n");
    // Node b hears of the leaf's interest through node a.
    let mut go = go_client(b.client, "");
    let deadline = Instant::now() + WAIT;
    mine.w
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    loop {
        go.send("PUB back 4\r\nwait\r\n");
        let mut l = String::new();
        if mine.r.read_line(&mut l).is_ok() && l.starts_with("MSG back 1 4") {
            mine.line();
            break;
        }
        assert!(Instant::now() < deadline, "nothing came back");
    }
    mine.w.set_read_timeout(Some(WAIT)).unwrap();
    // No member in the cluster: the leaf's queue member gets the job.
    go.send("PUB jobs 3\r\njob\r\n");
    lines_until(&mut mine, "MSG jobs 2 3");
    assert_eq!(mine.line(), "job");
}

/// Two naq servers of cluster `s`, server `i` linked to the hub at
/// `hubs[i]`.
fn naq_cluster(hubs: [u16; 2]) -> Vec<Server> {
    let ports = [free_port(), free_port()];
    (0..2)
        .map(|i| {
            Server::start(&Options {
                host: "127.0.0.1".into(),
                port: 0,
                lanes: 2,
                http_port: Some(0),
                server_name: format!("s{i}"),
                cluster: Some(naq::Cluster {
                    name: "s".into(),
                    host: "127.0.0.1".into(),
                    port: ports[i],
                    routes: vec![format!("127.0.0.1:{}", ports[1 - i])],
                }),
                leaf_reconnect: Duration::from_millis(50),
                remotes: vec![Remote {
                    urls: vec![format!("nats-leaf://127.0.0.1:{}", hubs[i])],
                    ..Remote::default()
                }],
                ..Options::default()
            })
            .unwrap()
        })
        .collect()
}

/// The subjects the hub of `s`'s only link has interest in.
fn hub_subjects(s: &Server) -> Vec<serde_json::Value> {
    let z = get(s.monitor_addr().unwrap().port(), "/leafz?subs=1");
    z["leafs"][0]["subscriptions_list"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[test]
fn a_go_hub_cluster_keeps_the_interest_of_a_naq_cluster_from_itself() {
    let Some((_servers, [a, b])) = go_cluster() else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let naq = naq_cluster([a.leaf, b.leaf]);
    leafz_until(a.http, |z| z["leafnodes"] == 1);
    leafz_until(b.http, |z| z["leafnodes"] == 1);
    let _sub = client(&naq[0], "SUB foo 1\r\n");
    leafz_until(a.http, |z| {
        z["leafs"][0]["subscriptions_list"]
            .as_array()
            .is_some_and(|l| l.contains(&"foo".into()))
    });
    // After foo on the same route: node b tells the link of server 1 of
    // foo first, if it does.
    let _go = go_client(a.client, "SUB bar 1\r\n");
    let deadline = Instant::now() + WAIT;
    while !hub_subjects(&naq[1]).contains(&"bar".into()) {
        assert!(
            Instant::now() < deadline,
            "no bar: {:?}",
            hub_subjects(&naq[1])
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // Server 1 sends foo to server 0 itself, not through the hubs too.
    assert!(!hub_subjects(&naq[1]).contains(&"foo".into()));
}

#[test]
fn the_hub_hears_of_the_denies_and_the_isolation_asked_for() {
    let json = connect_of(
        &Hub::new(),
        Remote {
            deny_imports: vec!["secret.>".into()],
            request_isolation: true,
            ..Remote::default()
        },
    );
    assert_eq!(json["deny_pub"], serde_json::json!(["secret.>"]));
    assert_eq!(json["isolate"], true);
    let plain = connect_of(&Hub::new(), Remote::default());
    assert!(plain.get("deny_pub").is_none() && plain.get("isolate").is_none());
}

#[test]
fn the_imports_and_exports_of_the_hub_and_the_remote_hold() {
    let hub = Hub::new();
    let naq = leaf_with(Remote {
        urls: vec![format!("127.0.0.1:{}", hub.port())],
        deny_imports: vec!["in.no".into()],
        deny_exports: vec!["out.no".into()],
        ..Remote::default()
    });
    let mut p = hub.accept();
    p.send(INFO);
    p.line();
    p.send(
        "INFO {\"connect_info\":true,\"import\":{\"allow\":[\"in.>\",\"done\"]},\"export\":{\"allow\":[\"out.>\"]}}\r\n",
    );
    lines_until(&mut p, "LS+ $LDS.");
    // Interest outside the imports is not told.
    let mut c = client(
        &naq,
        "SUB other 1\r\nSUB in.no 2\r\nSUB _R_.x 3\r\nSUB in.a 4\r\nSUB done 9\r\n",
    );
    told(&mut p, &["LS+ in.a", "LS+ done"]);
    // Literal interest outside the exports is left out; wildcards count.
    p.send("LS+ bad\r\nLS+ out.no\r\nLS+ out.ok\r\nLS+ >\r\n");
    wait_for_interest(&naq, &mut p, "out.ok");
    c.send("PUB bad 2\r\nno\r\nPUB out.no 2\r\nno\r\nPUB out.ok 2\r\nok\r\n");
    assert_eq!(lines(&mut p, 2), ["LMSG out.ok 2", "ok"]);
    // Messages outside the imports stay out, but service replies.
    p.send(
        "LMSG other 2\r\nno\r\nLMSG in.no 2\r\nno\r\nLMSG _R_.x 2\r\nok\r\nLMSG in.a 2\r\nok\r\n",
    );
    p.send("LMSG done 0\r\n\r\n");
    let got: Vec<_> = got_until_done(&mut c).into_iter().map(|(m, _)| m).collect();
    assert_eq!(got, ["MSG _R_.x 3 2", "MSG in.a 4 2"]);
}

#[test]
fn a_go_hub_keeps_the_link_of_a_leaf_that_keeps_to_its_permissions() {
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let conf = format!(
        "port: {port}\nhttp_port: {http}\nauthorization {{ users: [{{ user: l, password: p, permissions: {{ publish: s, subscribe: in }} }}, {{ user: c, password: c }}] }}\nno_auth_user: c\nleafnodes {{ port: {leafport} }}\n"
    );
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let mut sub = go_client(port, "SUB > 1\r\n");
    let leaf = leaf(&format!("nats-leaf://l:p@127.0.0.1:{leafport}"));
    leafz_until(http, |z| z["leafnodes"] == 1);
    published_to_go(&leaf, &mut sub);
    // The hub would end the link for this one: it is not sent.
    let mut c = client(&leaf, "");
    c.send("PUB t 2\r\nno\r\nPUB s 2\r\nok\r\n");
    let got = lines_until(&mut sub, "ok");
    assert!(!got.iter().any(|l| l.starts_with("MSG t ")), "{got:?}");
    assert_eq!(get(http, "/leafz")["leafnodes"], 1);
}

#[test]
fn a_request_crosses_a_go_hub_and_its_reply_comes_back() {
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let conf = format!("port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\n");
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    // Its interest in s comes with the one in svc.
    let mut svc = go_client(port, "SUB s 1\r\nSUB svc 2\r\n");
    let leaf = leaf(&format!("nats-leaf://127.0.0.1:{leafport}"));
    leafz_until(http, |z| z["leafnodes"] == 1);
    published_to_go(&leaf, &mut svc);
    let mut c = client(
        &leaf,
        "CONNECT {\"headers\":true,\"no_responders\":true}\r\nSUB _INBOX.r 7\r\n",
    );
    leafz_until(http, |z| {
        z["leafs"][0]["subscriptions_list"]
            .as_array()
            .is_some_and(|l| l.iter().any(|s| s == "_INBOX.r"))
    });
    c.send("PUB svc _INBOX.r 3\r\nask\r\n");
    lines_until(&mut svc, "MSG svc 2 _INBOX.r 3");
    assert_eq!(svc.line(), "ask");
    svc.send("PUB _INBOX.r 6\r\nanswer\r\n");
    assert_eq!(lines(&mut c, 2), ["MSG _INBOX.r 7 6", "answer"]);
}

/// A naq leaf of one lane that dials each of `urls`, so what it tells
/// one hub keeps the order of what it learns.
fn leaf_of_one_lane(urls: &[String]) -> Server {
    Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        http_port: Some(0),
        server_name: "naq-leaf".into(),
        remotes: urls
            .iter()
            .map(|u| Remote {
                urls: vec![u.clone()],
                ..Remote::default()
            })
            .collect(),
        ..Options::default()
    })
    .unwrap()
}

#[test]
fn only_the_loop_detection_of_one_hub_is_told_to_another() {
    let (one, two) = (Hub::new(), Hub::new());
    let url = |h: &Hub| format!("127.0.0.1:{}", h.port());
    let _leaf = leaf_of_one_lane(&[url(&one), url(&two)]);
    let (mut p1, mut p2) = (linked(&one), linked(&two));
    p2.send("LS+ m\r\nLS+ m q 2\r\nLS+ $LDS.two\r\n");
    // Interest at a hub stays with it, as in `nats-server`.
    assert_eq!(lines_until(&mut p1, "LS+ $LDS.two"), ["LS+ $LDS.two"]);
    p2.send("LS- $LDS.two\r\nPING\r\n");
    assert_eq!(p2.line(), "PONG", "not told back to its own hub");
    assert_eq!(p1.line(), "LS- $LDS.two");
}

#[test]
fn a_naq_leaf_does_not_bridge_two_go_hubs() {
    let hubs: Vec<[u16; 3]> = (0..2)
        .map(|_| [free_port(), free_port(), free_port()])
        .collect();
    let conf = |[port, leafport, http]: [u16; 3]| {
        format!("port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\n")
    };
    let Some(_a) = go(&conf(hubs[0])) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let _b = go(&conf(hubs[1])).unwrap();
    let _sub = go_client(hubs[0][0], "SUB x 1\r\n");
    let url = |h: [u16; 3]| format!("nats-leaf://127.0.0.1:{}", h[1]);
    let leaf = leaf_of_one_lane(&[url(hubs[0]), url(hubs[1])]);
    let mine = leaf.monitor_addr().unwrap().port();
    until(mine, "/leafz?subs=1", |z| {
        z["leafs"].as_array().is_some_and(|l| {
            l.iter().any(|l| {
                l["subscriptions_list"]
                    .as_array()
                    .is_some_and(|s| s.iter().any(|s| s == "x"))
            })
        })
    });
    // Told to hub b after anything hub a told before.
    let _marker = client(&leaf, "SUB z 1\r\n");
    let b = until(hubs[1][2], "/leafz?subs=1", |z| {
        z["leafs"][0]["subscriptions_list"]
            .as_array()
            .is_some_and(|l| l.iter().any(|s| s == "z"))
    });
    let subs = b["leafs"][0]["subscriptions_list"].as_array().unwrap();
    assert!(!subs.iter().any(|s| s == "x"), "{subs:?}");
    // The loop detection subjects of naq and of hub a.
    let lds = subs
        .iter()
        .filter(|s| s.as_str().unwrap().starts_with("$LDS."))
        .count();
    assert_eq!(lds, 2, "{subs:?}");
}

#[test]
fn leafz_shows_the_links_and_the_interest_of_their_hubs() {
    let hub = Hub::new();
    let naq = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        http_port: Some(0),
        remotes: vec![Remote {
            urls: vec![format!("127.0.0.1:{}", hub.port())],
            ..Remote::default()
        }],
        ..Options::default()
    })
    .unwrap();
    let http = naq.monitor_addr().unwrap().port();
    let mut p = hub.accept();
    p.send(&INFO.replace("\"client_id\"", "\"server_name\":\"hub1\",\"client_id\""));
    p.line();
    p.send("INFO {\"connect_info\":true}\r\n");
    lines_until(&mut p, "LS+ $LDS.");
    p.send("LS+ b q 2\r\nLS+ a\r\nPING\r\n");
    assert_eq!(p.line(), "PONG");
    let z = get(http, "/leafz");
    assert_eq!(z["leafnodes"], 1, "{z}");
    let l = &z["leafs"][0];
    assert_eq!(
        (&l["name"], &l["account"], &l["ip"]),
        (&"hub1".into(), &"$G".into(), &"127.0.0.1".into())
    );
    assert_eq!(
        (&l["port"], &l["subscriptions"], &l["is_spoke"]),
        (&hub.port().into(), &2.into(), &true.into())
    );
    assert!(l.get("subscriptions_list").is_none(), "{l}");
    let z = get(http, "/leafz?subs=1");
    assert_eq!(
        z["leafs"][0]["subscriptions_list"],
        serde_json::json!(["a", "b"])
    );
}

/// The next line `c` gets but `PING`s, which it answers.
fn not_ping(c: &mut Peer) -> String {
    loop {
        let l = c.line();
        if l != "PING" {
            return l;
        }
        c.send("PONG\r\n");
    }
}

/// The answer to request `body` on `subject`, from a client subscribed
/// to `_INBOX.js` as SID 1.
fn ask(c: &mut Peer, subject: &str, body: &str) -> serde_json::Value {
    c.send(&format!(
        "PUB {subject} _INBOX.js {}\r\n{body}\r\n",
        body.len()
    ));
    let head = not_ping(c);
    assert!(head.starts_with("MSG _INBOX.js 1 "), "{head}");
    serde_json::from_str(&c.line()).unwrap()
}

/// A client of `leaf`, subscribed to `_INBOX.js` as SID 1, once the
/// JetStream of the hub with monitoring port `http` answers it through
/// domain `hub`.
fn js_client(leaf: &Server, http: u16) -> Peer {
    let mut c = client(leaf, "SUB _INBOX.js 1\r\n");
    leafz_until(http, |z| {
        z["leafs"][0]["subscriptions_list"]
            .as_array()
            .is_some_and(|l| l.iter().any(|s| s == "_INBOX.js"))
    });
    // The hub's interest in its domain's API reaches the leaf in its time.
    let deadline = Instant::now() + WAIT;
    c.w.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    loop {
        c.send("PUB $JS.hub.API.INFO _INBOX.js 0\r\n\r\n");
        let mut l = String::new();
        if c.r.read_line(&mut l).is_ok() && l.starts_with("MSG _INBOX.js 1 ") {
            let info: serde_json::Value = serde_json::from_str(&c.line()).unwrap();
            assert_eq!(
                info["type"],
                "io.nats.jetstream.api.v1.account_info_response"
            );
            assert_eq!(info["domain"], "hub");
            break;
        }
        assert!(Instant::now() < deadline, "no JetStream answer");
    }
    c.w.set_read_timeout(Some(WAIT)).unwrap();
    c
}

#[test]
fn naq_clients_use_the_jetstream_of_a_go_hub_through_its_domain() {
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("naq-leaf-js-{}", fastrand()));
    let conf = format!(
        "port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\njetstream {{ store_dir: \"{}\", domain: hub }}\n",
        dir.display()
    );
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let leaf = leaf(&format!("nats-leaf://127.0.0.1:{leafport}"));
    let mut c = js_client(&leaf, http);
    let stream = r#"{"name":"S","subjects":["orders.>"]}"#;
    let made = ask(&mut c, "$JS.hub.API.STREAM.CREATE.S", stream);
    assert_eq!(made["config"]["name"], "S", "{made}");
    // The stream's interest reaches the leaf too: published until stored.
    let deadline = Instant::now() + WAIT;
    while ask(&mut c, "$JS.hub.API.STREAM.INFO.S", "")["state"]["messages"] == 0 {
        c.send("PUB orders.1 2\r\nhi\r\n");
        assert!(Instant::now() < deadline, "nothing stored");
    }
    // A pull consumer: the message comes over the link, the ack goes back.
    let consumer = r#"{"stream_name":"S","config":{"durable_name":"C","ack_policy":"explicit"}}"#;
    assert_eq!(
        ask(&mut c, "$JS.hub.API.CONSUMER.CREATE.S.C", consumer)["name"],
        "C"
    );
    c.send("PUB $JS.hub.API.CONSUMER.MSG.NEXT.S.C _INBOX.js 1\r\n1\r\n");
    // As a client of the hub gets it: the stream's subject, and an ack
    // reply without the `@` and subject the hub sent.
    let head = not_ping(&mut c);
    let ack = head
        .strip_prefix("MSG orders.1 1 ")
        .and_then(|r| r.split(' ').next());
    assert!(ack.is_some_and(|a| a.starts_with("$JS.ACK.S.C.")), "{head}");
    assert_eq!(c.line(), "hi");
    c.send(&format!("PUB {} 0\r\n\r\n", ack.unwrap()));
    let deadline = Instant::now() + WAIT;
    loop {
        let info = ask(&mut c, "$JS.hub.API.CONSUMER.INFO.S.C", "");
        if info["num_ack_pending"] == 0 && info["ack_floor"]["consumer_seq"] == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "not acked: {info}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clients_on_any_lane_get_jetstream_messages_of_the_hub_as_go_leafs_hand_them_on() {
    let hub = Hub::new();
    let leaf = leaf(&format!("127.0.0.1:{}", hub.port()));
    let mut p = linked(&hub);
    // One on the link's lane, one not.
    let subs = "SUB _INBOX.x 1\r\nSUB _INBOX.x q 2\r\n";
    let (mut a, mut b) = (client(&leaf, subs), client(&leaf, subs));
    told(&mut p, &["LS+ _INBOX.x q 2"]);
    p.send("LMSG _INBOX.x + $JS.ACK.S.C.1.2.3.4.0@orders.1 q 2\r\nhi\r\n");
    for c in [&mut a, &mut b] {
        assert_eq!(
            lines(c, 2),
            ["MSG orders.1 1 $JS.ACK.S.C.1.2.3.4.0 2", "hi"]
        );
    }
    let picked = [a, b].map(|mut c| {
        c.w.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut l = String::new();
        let got = c.r.read_line(&mut l).is_ok() && !l.is_empty();
        assert!(
            !got || l == "MSG orders.1 2 $JS.ACK.S.C.1.2.3.4.0 2\r\n",
            "{l}"
        );
        got
    });
    assert_eq!(picked.iter().filter(|&&g| g).count(), 1, "one member of q");
}

/// A TCP proxy to `to` that can cut every connection through it.
struct Proxy {
    port: u16,
    cut: std::sync::Arc<std::sync::atomic::AtomicBool>,
    conns: std::sync::Arc<std::sync::Mutex<Vec<TcpStream>>>,
}

impl Proxy {
    fn new(to: u16) -> Proxy {
        use std::sync::atomic::Ordering;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cut = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let conns = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (c, k) = (cut.clone(), conns.clone());
        std::thread::spawn(move || {
            for down in listener.incoming() {
                let Ok(down) = down else { return };
                let Ok(up) = TcpStream::connect(("127.0.0.1", to)) else {
                    continue;
                };
                // Relaxed: a flag the test sets before it cuts.
                if c.load(Ordering::Relaxed) {
                    return;
                }
                let mut k = k.lock().unwrap();
                for (mut from, mut to) in [
                    (down.try_clone().unwrap(), up.try_clone().unwrap()),
                    (up.try_clone().unwrap(), down.try_clone().unwrap()),
                ] {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut from, &mut to);
                        let _ = to.shutdown(std::net::Shutdown::Both);
                    });
                }
                k.extend([down, up]);
            }
        });
        Proxy { port, cut, conns }
    }

    /// Cuts every connection through the proxy so far.
    fn cut_all(&self) {
        for c in self.conns.lock().unwrap().drain(..) {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // Relaxed: see `Proxy::new`.
        self.cut.store(true, std::sync::atomic::Ordering::Relaxed);
        self.cut_all();
    }
}

#[test]
fn a_link_cut_on_the_way_comes_back_with_its_interest() {
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let conf = format!("port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\n");
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let proxy = Proxy::new(leafport);
    let mut sub = go_client(port, "SUB s 1\r\n");
    let leaf = leaf(&format!("nats-leaf://127.0.0.1:{}", proxy.port));
    let mut mine = client(&leaf, "SUB back 1\r\n");
    leafz_until(http, |z| z["leafnodes"] == 1);
    published_to_go(&leaf, &mut sub);
    let first = get(http, "/leafz")["leafs"][0]["id"].clone();
    proxy.cut_all();
    // A new link, with the interest of both sides told again.
    leafz_until(http, |z| {
        z["leafnodes"] == 1 && z["leafs"][0]["id"] != first
    });
    published_to_go(&leaf, &mut sub);
    leafz_until(http, |z| {
        z["leafs"][0]["subscriptions_list"]
            .as_array()
            .is_some_and(|l| l.iter().any(|s| s == "back"))
    });
    let mut go = go_client(port, "");
    go.send("PUB back 2\r\nhi\r\n");
    assert_eq!(lines(&mut mine, 2), ["MSG back 1 2", "hi"]);
}

#[test]
fn a_client_of_the_leaf_that_reads_nothing_does_not_hold_up_the_link() {
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let conf = format!("port: {port}\nhttp_port: {http}\nleafnodes {{ port: {leafport} }}\n");
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let leaf = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        max_pending: 1 << 20,
        remotes: vec![Remote {
            urls: vec![format!("nats-leaf://127.0.0.1:{leafport}")],
            ..Remote::default()
        }],
        ..Options::default()
    })
    .unwrap();
    // It reads its PONG, then nothing.
    let _slow = client(&leaf, "SUB flood 1\r\n");
    let mut quick = client(&leaf, "SUB ok 1\r\n");
    leafz_until(http, |z| {
        z["leafs"][0]["subscriptions_list"]
            .as_array()
            .is_some_and(|l| l.iter().any(|s| s == "ok") && l.iter().any(|s| s == "flood"))
    });
    let mut go = go_client(port, "");
    let big = "x".repeat(32 << 10);
    let flood = format!("PUB flood {}\r\n{big}\r\n", big.len()).repeat(256);
    // 8 MiB for a client that takes 1 MiB, then one for the quick one.
    go.send(&flood);
    go.send("PUB ok 2\r\nhi\r\n");
    assert_eq!(lines(&mut quick, 2), ["MSG ok 1 2", "hi"]);
    assert_eq!(get(http, "/leafz")["leafnodes"], 1, "the link held");
}

/// A naq leaf whose account I imports from E, linked as `account` to
/// `hub`: I takes E's streams under `pre` and its service `svc.>`.
fn importing_leaf(hub: &Hub, account: &str) -> Server {
    let opts: Options = "accounts {\n\
        E { users: [{user: e, password: p}], exports: [{stream: \"s.>\"}, {service: \"svc.>\"}] }\n\
        I { users: [{user: i, password: p}], imports: [\n\
            {stream: {account: E, subject: \"s.>\"}, prefix: pre},\n\
            {service: {account: E, subject: \"svc.>\"}}] }\n}\n"
        .parse()
        .unwrap();
    Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        leaf_reconnect: Duration::from_millis(50),
        remotes: vec![Remote {
            urls: vec![format!("127.0.0.1:{}", hub.port())],
            account: Some(account.into()),
            ..Remote::default()
        }],
        ..opts
    })
    .unwrap()
}

/// A client of `server` that logs in as `user`.
fn login(server: &Server, user: &str) -> Peer {
    let s = TcpStream::connect(server.addr()).unwrap();
    s.set_read_timeout(Some(WAIT)).unwrap();
    let mut c = Peer {
        r: BufReader::new(s.try_clone().unwrap()),
        w: s,
    };
    c.line();
    c.send(&format!(
        "CONNECT {{\"verbose\":false,\"headers\":true,\"user\":\"{user}\",\"pass\":\"p\"}}\r\nPING\r\n"
    ));
    assert_eq!(c.line(), "PONG");
    c
}

#[test]
fn a_hub_linked_to_an_importer_hears_of_its_service_and_gets_its_streams() {
    let hub = Hub::new();
    let leaf = importing_leaf(&hub, "I");
    let (mut p, first) = linked_with(&hub);
    assert!(first.iter().any(|l| l == "LS+ svc.>"), "{first:?}");
    // The hub's interest in an imported subject reaches the exporter.
    p.send("LS+ pre.s.x\r\nPING\r\n");
    assert_eq!(p.line(), "PONG");
    let mut e = login(&leaf, "e");
    let deadline = Instant::now() + WAIT;
    p.w.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    loop {
        e.send("PUB s.x 2\r\nhi\r\n");
        let mut l = String::new();
        if p.r.read_line(&mut l).is_ok() {
            assert_eq!(l, "LMSG pre.s.x 2\r\n");
            break;
        }
        assert!(Instant::now() < deadline, "nothing came");
    }
    p.w.set_read_timeout(Some(WAIT)).unwrap();
    assert_eq!(p.line(), "hi");
    // Gone with the hub's interest: once `pre.s.y`, which the hub took up
    // after, comes through, `pre.s.x` no longer does.
    p.send("LS- pre.s.x\r\nLS+ pre.s.y\r\n");
    let deadline = Instant::now() + WAIT;
    loop {
        e.send("PUB s.x 1\r\nx\r\nPUB s.y 1\r\ny\r\n");
        let l = p.line();
        p.line();
        if l == "LMSG pre.s.y 1" {
            break;
        }
        assert!(Instant::now() < deadline, "no pre.s.y");
    }
    e.send("PUB s.x 1\r\nx\r\nPUB s.y 1\r\ny\r\nPING\r\n");
    assert_eq!(e.line(), "PONG");
    let mut rest = Vec::new();
    p.w.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut l = String::new();
    while p.r.read_line(&mut l).is_ok_and(|n| n > 0) {
        rest.push(l.trim_end().to_owned());
        l.clear();
    }
    assert!(!rest.iter().any(|l| l == "LMSG pre.s.x 1"), "{rest:?}");
    assert!(rest.iter().any(|l| l == "LMSG pre.s.y 1"), "{rest:?}");
}

#[test]
fn a_request_from_the_hub_goes_through_the_import_and_back() {
    let hub = Hub::new();
    let leaf = importing_leaf(&hub, "I");
    let mut p = linked(&hub);
    let mut svc = login(&leaf, "e");
    svc.send("SUB svc.> 1\r\nPING\r\n");
    assert_eq!(svc.line(), "PONG");
    p.send("LS+ inbox\r\nLMSG svc.q inbox 1\r\nq\r\n");
    let head = svc.line();
    let parts: Vec<&str> = head.split(' ').collect();
    assert_eq!(
        (parts[0], parts[1], parts[2]),
        ("HMSG", "svc.q", "1"),
        "{head}"
    );
    assert!(parts[3].starts_with("_R_."), "{head}");
    assert_eq!(svc.line(), "NATS/1.0");
    assert_eq!(svc.line(), r#"Nats-Request-Info: {"acc":"I"}"#);
    assert_eq!(svc.line(), "");
    assert_eq!(svc.line(), "q");
    svc.send(&format!("PUB {} 2\r\nok\r\n", parts[3]));
    assert_eq!(p.line(), "LMSG inbox 2");
    assert_eq!(p.line(), "ok");
}

#[test]
fn a_hub_linked_to_an_exporter_hears_of_the_replies_of_its_requests() {
    let hub = Hub::new();
    let _leaf = importing_leaf(&hub, "E");
    let (_p, first) = linked_with(&hub);
    let replies: Vec<&String> = first.iter().filter(|l| l.starts_with("LS+ _R_.")).collect();
    assert_eq!(replies.len(), 1, "{first:?}");
    assert!(replies[0].ends_with(".>") && replies[0].len() == "LS+ _R_.abcdef.>".len());
}

/// A client of the Go server on `port` that logs in as `user`, password
/// `p`, subscribed as `subs` say.
fn go_login(port: u16, user: &str, subs: &str) -> Peer {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(WAIT)).unwrap();
    let mut c = Peer {
        r: BufReader::new(s.try_clone().unwrap()),
        w: s,
    };
    c.line();
    c.send(&format!(
        "CONNECT {{\"verbose\":false,\"user\":\"{user}\",\"pass\":\"p\"}}\r\n{subs}PING\r\n"
    ));
    assert_eq!(c.line(), "PONG");
    c
}

/// Publishes `subject` from `p` until `c` gets it, then `done`, and the
/// payloads `c` got until that one.
fn heard_until_done(p: &mut Peer, c: &mut Peer, subject: &str) -> Vec<String> {
    let deadline = Instant::now() + WAIT;
    c.w.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    loop {
        p.send(&format!("PUB {subject} 4\r\nwait\r\n"));
        let mut l = String::new();
        if c.r.read_line(&mut l).is_ok() && l.starts_with(&format!("MSG {subject} ")) {
            c.line();
            break;
        }
        assert!(Instant::now() < deadline, "nothing on {subject}");
    }
    c.w.set_read_timeout(Some(WAIT)).unwrap();
    p.send(&format!("PUB {subject} 4\r\ndone\r\n"));
    let mut got = Vec::new();
    while got.last().is_none_or(|l| l != "done") {
        let head = c.line();
        assert!(head.starts_with(&format!("MSG {subject} ")), "{head}");
        got.push(c.line());
    }
    got
}

#[test]
fn a_leaf_bound_to_an_account_of_a_go_hub_shares_no_other() {
    let (port, leafport, http) = (free_port(), free_port(), free_port());
    let conf = format!(
        "port: {port}\nhttp_port: {http}\naccounts {{\n  H {{ users: [{{user: h, password: p}}] }}\n  G {{ users: [{{user: g, password: p}}] }}\n}}\n\
         leafnodes {{ port: {leafport}, authorization {{ users: [{{user: l, password: p, account: H}}] }} }}\n"
    );
    let Some(_hub) = go(&conf) else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    let opts: Options = "accounts {\n  L { users: [{user: l, password: p}] }\n  M { users: [{user: m, password: p}] }\n}\n"
        .parse()
        .unwrap();
    let leaf = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        leaf_reconnect: Duration::from_millis(50),
        remotes: vec![Remote {
            urls: vec![format!("nats-leaf://l:p@127.0.0.1:{leafport}")],
            account: Some("L".into()),
            ..Remote::default()
        }],
        ..opts
    })
    .unwrap();
    leafz_until(http, |z| {
        z["leafnodes"] == 1 && z["leafs"][0]["account"] == "H"
    });
    let (mut h, mut l) = (go_login(port, "h", "SUB x 1\r\n"), login(&leaf, "l"));
    let (mut g, mut m) = (go_login(port, "g", "SUB x 1\r\n"), login(&leaf, "m"));
    m.send("PUB x 2\r\nno\r\nPING\r\n");
    assert_eq!(m.line(), "PONG");
    let got = heard_until_done(&mut l, &mut h, "x");
    assert!(
        !got.contains(&"no".into()),
        "another account of the leaf: {got:?}"
    );
    g.send("PING\r\n");
    assert_eq!(g.line(), "PONG", "another account of the hub");
    l.send("SUB y 1\r\nPING\r\n");
    assert_eq!(l.line(), "PONG");
    m.send("SUB y 1\r\nPING\r\n");
    assert_eq!(m.line(), "PONG");
    g.send("PUB y 2\r\nno\r\nPING\r\n");
    assert_eq!(g.line(), "PONG");
    let got = heard_until_done(&mut h, &mut l, "y");
    assert!(
        !got.contains(&"no".into()),
        "another account of the hub: {got:?}"
    );
    m.send("PING\r\n");
    assert_eq!(m.line(), "PONG", "another account of the leaf");
}
