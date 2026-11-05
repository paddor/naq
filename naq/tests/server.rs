//! A server and clients over TCP.

#![expect(clippy::unwrap_used, clippy::panic, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use naq::{Options, Server};

const WAIT: Duration = Duration::from_secs(5);

/// A server on one lane.
fn server() -> Server {
    server_with(Options {
        lanes: 1,
        ..Options::default()
    })
}

fn server_with(opts: Options) -> Server {
    Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        ..opts
    })
    .unwrap()
}

/// A client that reads lines, with a timeout on every read.
struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
}

impl Client {
    /// Connects and reads the `INFO`.
    fn raw(server: &Server) -> (Client, String) {
        let w = TcpStream::connect(server.addr()).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let mut c = Client {
            r: BufReader::new(w.try_clone().unwrap()),
            w,
        };
        let info = c.line();
        (c, info)
    }

    /// Connects with `CONNECT` options, after a round trip.
    fn new(server: &Server, connect: &str) -> Client {
        let (mut c, _) = Client::raw(server);
        c.send(&format!("CONNECT {connect}\r\nPING\r\n"));
        c.expect("PONG");
        c
    }

    fn quiet(server: &Server) -> Client {
        Client::new(server, r#"{"verbose":false}"#)
    }

    fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
    }

    /// The next line, answering the server's `PING`s on the way, as a
    /// client library does.
    fn line(&mut self) -> String {
        loop {
            let l = self.raw_line();
            if l != "PING" {
                return l;
            }
            self.send("PONG\r\n");
        }
    }

    fn raw_line(&mut self) -> String {
        let mut l = String::new();
        let n = self.r.read_line(&mut l).unwrap();
        assert!(n > 0, "closed");
        l.trim_end_matches("\r\n").to_owned()
    }

    fn expect(&mut self, want: &str) {
        assert_eq!(self.line(), want);
    }

    /// Round trip: everything sent before has been handled.
    fn flush(&mut self) {
        self.send("PING\r\n");
        self.expect("PONG");
    }

    /// Reads until the server closes, returning what came.
    fn rest(&mut self) -> String {
        let mut s = String::new();
        match self.r.read_to_string(&mut s) {
            Ok(_) => s,
            Err(e) if e.kind() == ErrorKind::ConnectionReset => s,
            Err(e) => panic!("not closed: {e}"),
        }
    }
}

#[test]
fn info_comes_first() {
    let s = server();
    let (_, info) = Client::raw(&s);
    let json: serde_json::Value =
        serde_json::from_str(info.strip_prefix("INFO ").unwrap()).unwrap();
    assert_eq!(json["proto"], 1);
    assert_eq!(json["port"], s.addr().port());
    assert_eq!(json["max_payload"], 1 << 20);
    assert_eq!(json["headers"], true);
    let id = json["server_id"].as_str().unwrap();
    assert!(id.starts_with('N') && id.len() == 56, "a server NKey: {id}");
    assert!(json["xkey"].as_str().unwrap().starts_with('X'));
    assert!(json["client_id"].as_u64().unwrap() > 0);
    assert!(json["version"].is_string());
}

#[test]
fn clients_are_verbose_until_connect_says_otherwise() {
    let s = server();
    let (mut c, _) = Client::raw(&s);
    c.send("SUB a 1\r\nPING\r\n");
    c.expect("+OK");
    c.expect("PONG");
    c.send("CONNECT {\"verbose\":false}\r\nSUB b 2\r\nPING\r\n");
    c.expect("PONG");
}

#[test]
fn a_publish_reaches_subscribers_with_their_sids() {
    let s = server();
    let mut sub = Client::quiet(&s);
    let mut other = Client::quiet(&s);
    sub.send("SUB a.b 7\r\nSUB a.b x\r\n");
    other.send("SUB a.c 1\r\n");
    sub.flush();
    other.flush();
    let mut p = Client::quiet(&s);
    p.send("PUB a.b 2\r\nhi\r\nPUB a.b reply.to 0\r\n\r\n");
    p.flush();
    let got: Vec<String> = (0..6).map(|_| sub.line()).collect();
    assert_eq!(
        got,
        [
            "MSG a.b 7 2",
            "hi",
            "MSG a.b x 2",
            "hi",
            "MSG a.b 7 reply.to 0",
            "",
        ]
    );
    other.flush();
}

#[test]
fn headers_go_only_to_clients_that_take_them() {
    let s = server();
    let mut hdr = Client::new(&s, r#"{"verbose":false,"headers":true}"#);
    let mut plain = Client::quiet(&s);
    hdr.send("SUB h 1\r\n");
    plain.send("SUB h 2\r\n");
    hdr.flush();
    plain.flush();
    let mut p = Client::new(&s, r#"{"verbose":false,"headers":true}"#);
    p.send("HPUB h 12 14\r\nNATS/1.0\r\n\r\nhi\r\n");
    p.flush();
    assert_eq!(hdr.line(), "HMSG h 1 12 14");
    assert_eq!(hdr.line(), "NATS/1.0");
    assert_eq!(hdr.line(), "");
    assert_eq!(hdr.line(), "hi");
    assert_eq!(plain.line(), "MSG h 2 2");
    assert_eq!(plain.line(), "hi");
}

#[test]
fn echo_off_keeps_a_clients_messages_from_itself() {
    let s = server();
    let mut quiet = Client::new(&s, r#"{"verbose":false,"echo":false}"#);
    quiet.send("SUB e 1\r\nPUB e 1\r\nx\r\n");
    quiet.flush();
    let mut loud = Client::quiet(&s);
    loud.send("SUB e 1\r\nPUB e 1\r\ny\r\nPING\r\n");
    loud.expect("MSG e 1 1");
    loud.expect("y");
    loud.expect("PONG");
    assert_eq!(quiet.line(), "MSG e 1 1");
    assert_eq!(quiet.line(), "y");
}

#[test]
fn unsubscribing_and_disconnecting_end_interest() {
    let s = server();
    let mut sub = Client::quiet(&s);
    sub.send("SUB u 1\r\nSUB u 1\r\nSUB u 2\r\nUNSUB 2\r\nUNSUB 9\r\n");
    sub.flush();
    let mut gone = Client::quiet(&s);
    gone.send("SUB u 3\r\n");
    gone.flush();
    drop(gone);
    let mut p = Client::quiet(&s);
    // The closed client's interest goes once the server saw it close.
    for _ in 0..100 {
        p.send("PUB u 1\r\nz\r\n");
        p.flush();
        assert_eq!(sub.line(), "MSG u 1 1");
        assert_eq!(sub.line(), "z");
    }
    sub.flush();
}

#[test]
fn protocol_errors_close_the_connection() {
    let s = server_with(Options {
        max_payload: 8,
        ..Options::default()
    });
    let cases = [
        ("FOO\r\n", "-ERR 'Unknown Protocol Operation'\r\n"),
        ("PUB a 1\r\nxy\r\n", "-ERR 'Unknown Protocol Operation'\r\n"),
        ("PUB a 9\r\n", "-ERR 'Maximum Payload Violation'\r\n"),
        ("PUB a b c 1\r\n", ""),
        ("CONNECT {\r\n", ""),
    ];
    for (send, want) in cases {
        let (mut c, _) = Client::raw(&s);
        c.send(&format!("CONNECT {{\"verbose\":false}}\r\n{send}"));
        assert_eq!(c.rest(), want, "after {send:?}");
    }
    let mut long = String::from("SUB ");
    long.push_str(&"a".repeat(5000));
    let (mut c, _) = Client::raw(&s);
    c.send(&long);
    assert_eq!(c.rest(), "-ERR 'maximum control line exceeded'\r\n");
}

#[test]
fn a_subscriber_that_does_not_read_is_closed_and_its_publisher_goes_on() {
    let s = server_with(Options {
        max_pending: 64 << 10,
        ..Options::default()
    });
    let mut slow = Client::quiet(&s);
    slow.send("SUB s 1\r\n");
    slow.flush();
    let mut p = Client::quiet(&s);
    let payload = "x".repeat(1000);
    for _ in 0..4096 {
        p.send(&format!("PUB s 1000\r\n{payload}\r\n"));
    }
    p.flush();
    // The kernel holds some of the backlog; the server closes the rest.
    let rest = slow.rest();
    assert!(rest.len() < 4096 * 1000, "{} bytes", rest.len());
}

#[test]
fn a_dropped_server_closes_its_clients() {
    let s = server();
    let mut c = Client::quiet(&s);
    drop(s);
    assert_eq!(c.rest(), "");
}

/// A server with `n` lanes. Clients go to the lanes in turn, in the order
/// they connect.
fn lanes(n: usize) -> Server {
    server_with(Options {
        lanes: n,
        ..Options::default()
    })
}

#[test]
fn publishes_reach_subscribers_on_every_lane_in_order() {
    let s = lanes(3);
    let mut a = Client::quiet(&s);
    let mut b = Client::quiet(&s);
    let mut p = Client::quiet(&s);
    a.send("SUB t 1\r\nPING\r\n");
    a.expect("PONG");
    b.send("SUB t 2\r\nPING\r\n");
    b.expect("PONG");
    for i in 0..200 {
        p.send(&format!("PUB t {}\r\n{i}\r\n", i.to_string().len()));
    }
    p.flush();
    for (c, sid) in [(&mut a, 1), (&mut b, 2)] {
        for i in 0..200 {
            assert_eq!(c.line(), format!("MSG t {sid} {}", i.to_string().len()));
            assert_eq!(c.line(), i.to_string());
        }
    }
}

#[test]
fn the_pong_after_a_sub_means_every_lane_routes_to_it() {
    let s = lanes(2);
    let mut p = Client::quiet(&s);
    let mut sub = Client::quiet(&s);
    for i in 0..50 {
        sub.send(&format!("SUB f{i} {i}\r\nPING\r\n"));
        sub.expect("PONG");
        p.send(&format!("PUB f{i} 1\r\nx\r\n"));
        assert_eq!(
            sub.line(),
            format!("MSG f{i} {i} 1"),
            "lost after the fence"
        );
        assert_eq!(sub.line(), "x");
    }
}

#[test]
fn interest_from_other_lanes_ends_with_unsub_and_disconnect() {
    let s = lanes(2);
    let mut p = Client::quiet(&s);
    let mut sub = Client::quiet(&s);
    let mut gone = Client::quiet(&s);
    sub.send("SUB g 1\r\nSUB h 2\r\nPING\r\n");
    sub.expect("PONG");
    gone.send("SUB g 3\r\nPING\r\n");
    gone.expect("PONG");
    drop(gone);
    sub.send("UNSUB 1\r\nPING\r\n");
    sub.expect("PONG");
    p.send("PUB g 1\r\nx\r\nPUB h 1\r\ny\r\n");
    p.flush();
    assert_eq!(sub.line(), "MSG h 2 1");
    assert_eq!(sub.line(), "y");
}

#[test]
fn a_slow_subscriber_on_another_lane_is_closed_and_its_publisher_goes_on() {
    let s = server_with(Options {
        lanes: 2,
        max_pending: 64 << 10,
        ..Options::default()
    });
    let mut p = Client::quiet(&s);
    let mut slow = Client::quiet(&s);
    slow.send("SUB s 1\r\n");
    slow.flush();
    let payload = "x".repeat(1000);
    for _ in 0..4096 {
        p.send(&format!("PUB s 1000\r\n{payload}\r\n"));
    }
    p.flush();
    let rest = slow.rest();
    assert!(rest.len() < 4096 * 1000, "{} bytes", rest.len());
}

#[test]
fn replies_and_headers_cross_lanes() {
    let s = lanes(2);
    let mut p = Client::new(&s, r#"{"verbose":false,"headers":true}"#);
    let mut sub = Client::new(&s, r#"{"verbose":false,"headers":true}"#);
    sub.send("SUB r 1\r\nPING\r\n");
    sub.expect("PONG");
    p.send("PUB r inbox.1 2\r\nhi\r\nHPUB r inbox.2 12 13\r\nNATS/1.0\r\n\r\nx\r\n");
    p.flush();
    sub.expect("MSG r 1 inbox.1 2");
    sub.expect("hi");
    sub.expect("HMSG r 1 inbox.2 12 13");
    sub.expect("NATS/1.0");
    sub.expect("");
    sub.expect("x");
}

/// Reads `c`'s messages until the one on subject `done`, and counts those
/// on other subjects.
fn count_until_done(c: &mut Client) -> usize {
    let mut n = 0;
    loop {
        let line = c.line();
        c.line();
        if line.starts_with("MSG done ") {
            return n;
        }
        n += 1;
    }
}

#[test]
fn wildcard_and_queue_interest_crosses_lanes() {
    let s = lanes(3);
    let mut p = Client::quiet(&s);
    let mut sub = Client::quiet(&s);
    sub.send("SUB w.* 1\r\nSUB w.> q 2\r\nSUB > 3\r\nPING\r\n");
    sub.expect("PONG");
    p.send("PUB w.a 1\r\nx\r\nPUB w.a.b 1\r\ny\r\nPUB v 1\r\nz\r\n");
    p.flush();
    let lines: Vec<String> = (0..12).map(|_| sub.line()).collect();
    let mut msgs: Vec<_> = lines.chunks(2).map(|m| m.join(" ")).collect();
    // Order holds per subscription only.
    msgs.sort();
    assert_eq!(
        msgs,
        [
            "MSG v 3 1 z",
            "MSG w.a 1 1 x",
            "MSG w.a 2 1 x",
            "MSG w.a 3 1 x",
            "MSG w.a.b 2 1 y",
            "MSG w.a.b 3 1 y",
        ],
    );
}

#[test]
fn a_queue_group_spreads_over_its_members_on_every_lane() {
    let s = lanes(3);
    let mut members: Vec<Client> = (0..3).map(|_| Client::quiet(&s)).collect();
    for m in &mut members {
        m.send("SUB work q 1\r\nSUB done 2\r\nPING\r\n");
        m.expect("PONG");
    }
    let mut p = Client::quiet(&s);
    let n = 3000;
    for _ in 0..n {
        p.send("PUB work 1\r\nx\r\n");
    }
    p.send("PUB done 0\r\n\r\n");
    p.flush();
    let counts: Vec<usize> = members.iter_mut().map(count_until_done).collect();
    assert_eq!(counts.iter().sum::<usize>(), n, "each message once");
    for c in &counts {
        assert!((800..1200).contains(c), "{counts:?}");
    }
}

#[test]
fn a_queue_group_passes_over_the_publisher_on_its_lane_without_echo() {
    let s = lanes(2);
    let mut p = Client::new(&s, r#"{"verbose":false,"echo":false}"#);
    let mut other = Client::quiet(&s);
    p.send("SUB work q 1\r\nPING\r\n");
    p.expect("PONG");
    other.send("SUB work q 1\r\nSUB done 2\r\nPING\r\n");
    other.expect("PONG");
    for _ in 0..200 {
        p.send("PUB work 1\r\nx\r\n");
    }
    p.send("PUB done 0\r\n\r\n");
    p.flush();
    assert_eq!(count_until_done(&mut other), 200);
}

#[test]
fn a_maximum_ends_a_subscription_on_another_lane() {
    let s = lanes(2);
    let mut p = Client::quiet(&s);
    let mut sub = Client::quiet(&s);
    sub.send("SUB m 1\r\nUNSUB 1 3\r\nSUB done 2\r\nPING\r\n");
    sub.expect("PONG");
    for _ in 0..5 {
        p.send("PUB m 1\r\nx\r\n");
    }
    p.send("PUB done 0\r\n\r\n");
    p.flush();
    assert_eq!(count_until_done(&mut sub), 3);
}

#[test]
fn a_responder_on_another_lane_is_a_responder() {
    let s = lanes(2);
    let mut req = Client::new(
        &s,
        r#"{"verbose":false,"headers":true,"no_responders":true}"#,
    );
    let mut svc = Client::quiet(&s);
    req.send("SUB _INBOX.r 1\r\nPING\r\n");
    req.expect("PONG");
    req.send("PUB svc _INBOX.r 1\r\nx\r\n");
    req.expect("HMSG _INBOX.r 1 35 35");
    req.expect("NATS/1.0 503");
    req.expect("Nats-Subject: svc");
    req.expect("");
    req.expect("");
    svc.send("SUB svc 1\r\nPING\r\n");
    svc.expect("PONG");
    req.send("PUB svc _INBOX.r 1\r\ny\r\n");
    svc.expect("MSG svc 1 _INBOX.r 1");
    svc.expect("y");
    svc.send("PUB _INBOX.r 2\r\nok\r\n");
    req.expect("MSG _INBOX.r 1 2");
    req.expect("ok");
}

fn pinging(interval_ms: u64) -> Server {
    server_with(Options {
        ping_interval: Duration::from_millis(interval_ms),
        ..Options::default()
    })
}

#[test]
fn a_client_that_stops_answering_pings_is_closed_as_stale() {
    let s = pinging(50);
    let mut c = Client::quiet(&s);
    assert_eq!(c.raw_line(), "PING");
    assert_eq!(c.raw_line(), "PING");
    assert_eq!(c.raw_line(), "-ERR 'Stale Connection'");
    assert_eq!(c.rest(), "");
}

#[test]
fn a_client_that_answers_pings_stays() {
    let s = pinging(50);
    let mut c = Client::quiet(&s);
    for _ in 0..4 {
        assert_eq!(c.raw_line(), "PING");
        c.send("PONG\r\n");
    }
    c.flush();
}

#[test]
fn a_subscriber_whose_writes_stall_past_the_deadline_is_closed() {
    let s = server_with(Options {
        write_deadline: Duration::from_millis(100),
        ..Options::default()
    });
    let mut slow = Client::quiet(&s);
    slow.send("SUB s 1\r\n");
    slow.flush();
    let mut p = Client::quiet(&s);
    let payload = "x".repeat(64 << 10);
    for _ in 0..256 {
        p.send(&format!("PUB s {}\r\n{payload}\r\n", payload.len()));
    }
    p.flush();
    // The subscriber reads nothing for a while: the server's write to it
    // stays stuck past the deadline.
    std::thread::sleep(Duration::from_millis(500));
    let rest = slow.rest();
    assert!(rest.len() < 256 * (64 << 10), "{} bytes", rest.len());
    p.flush();
}

fn with_users(lanes: usize) -> Server {
    server_with(Options {
        lanes,
        accounts: vec!["A".into(), "B".into()],
        users: ["a1", "a2", "b1"]
            .iter()
            .map(|u| naq::User {
                login: naq::Login::Password {
                    user: (*u).into(),
                    password: "p".into(),
                },
                account: Some(if u.starts_with('a') { "A" } else { "B" }.into()),
                permissions: None,
                connection_types: Vec::new(),
            })
            .collect(),
        auth_timeout: Duration::from_millis(100),
        ..Options::default()
    })
}

#[test]
fn a_client_that_does_not_authenticate_in_time_is_closed() {
    let s = with_users(1);
    let (mut c, info) = Client::raw(&s);
    assert!(info.contains(r#""auth_required":true"#), "{info}");
    assert_eq!(c.raw_line(), "-ERR 'Authentication Timeout'");
    assert_eq!(c.rest(), "");
}

#[test]
fn accounts_keep_their_subjects_apart_across_lanes() {
    let s = with_users(3);
    let login = |u: &str| format!(r#"{{"verbose":false,"user":"{u}","pass":"p"}}"#);
    let mut a1 = Client::new(&s, &login("a1"));
    let mut b1 = Client::new(&s, &login("b1"));
    let mut a2 = Client::new(&s, &login("a2"));
    for c in [&mut a1, &mut b1] {
        c.send("SUB t 1\r\nSUB done 2\r\nPING\r\n");
        c.expect("PONG");
    }
    a2.send("PUB t 1\r\na\r\nPUB done 0\r\n\r\n");
    a2.flush();
    assert_eq!(count_until_done(&mut a1), 1);
    // b1 sees its own message first: nothing came over from account A.
    b1.send("PUB t 1\r\nb\r\n");
    b1.expect("MSG t 1 1");
    b1.expect("b");
}

#[test]
fn an_nkey_user_logs_in_by_signing_the_nonce() {
    let key = nkeys::KeyPair::new_user();
    let s = server_with(Options {
        lanes: 1,
        users: vec![naq::User {
            login: naq::Login::Nkey(key.public_key()),
            account: None,
            permissions: None,
            connection_types: Vec::new(),
        }],
        ..Options::default()
    });
    let (mut c, info) = Client::raw(&s);
    let json: serde_json::Value =
        serde_json::from_str(info.strip_prefix("INFO ").unwrap()).unwrap();
    let nonce = json["nonce"].as_str().unwrap();
    let sig = data_encoding::BASE64URL_NOPAD.encode(&key.sign(nonce.as_bytes()).unwrap());
    let connect = format!(
        r#"{{"verbose":false,"nkey":"{}","sig":"{sig}"}}"#,
        key.public_key()
    );
    c.send(&format!("CONNECT {connect}\r\nPING\r\n"));
    c.expect("PONG");
}

#[test]
fn a_host_name_binds_where_it_resolves() {
    let s = Server::start(&Options {
        host: "localhost".into(),
        port: 0,
        lanes: 1,
        ..Options::default()
    })
    .unwrap();
    assert_eq!(
        s.addr().ip().to_string(),
        "127.0.0.1",
        "IPv4 first, as Go listens"
    );
    TcpStream::connect(s.addr()).unwrap();
}

#[test]
fn the_wildcard_host_takes_ipv6_clients_too() {
    // As Go binds `0.0.0.0`: `localhost` may resolve to `::1` alone.
    let s = Server::start(&Options {
        port: 0,
        lanes: 1,
        ..Options::default()
    })
    .unwrap();
    assert!(s.addr().is_ipv4() && s.addr().ip().is_unspecified());
    for (ip, shown) in [("::1", "::1"), ("127.0.0.1", "127.0.0.1")] {
        let c = TcpStream::connect((ip, s.addr().port())).unwrap();
        c.set_read_timeout(Some(WAIT)).unwrap();
        let mut line = String::new();
        BufReader::new(c).read_line(&mut line).unwrap();
        // An IPv4 client shows as such, not as an IPv6 mapped address.
        let want = format!("\"client_ip\":\"{shown}\"");
        assert!(line.starts_with("INFO ") && line.contains(&want), "{line}");
    }
}

/// A server on `lanes` lanes, with users `e` in account E and `i` in I,
/// and I importing the streams E exports, its subjects under `pre`.
fn importing(lanes: usize) -> Server {
    let opts: Options = "accounts {\n\
        E { users: [{user: e, password: p}], exports: [{stream: \"s.>\"}, {stream: done}] }\n\
        I { users: [{user: i, password: p}], imports: [\n\
            {stream: {account: E, subject: \"s.>\"}, prefix: pre},\n\
            {stream: {account: E, subject: done}}] }\n}\n"
        .parse()
        .unwrap();
    server_with(Options { lanes, ..opts })
}

fn login(s: &Server, user: &str) -> Client {
    Client::new(
        s,
        &format!(r#"{{"verbose":false,"user":"{user}","pass":"p"}}"#),
    )
}

#[test]
fn a_stream_import_reaches_its_importer_on_every_lane() {
    let s = importing(3);
    let mut subs: Vec<Client> = (0..3).map(|_| login(&s, "i")).collect();
    for c in &mut subs {
        c.send("SUB pre.s.* 1\r\nSUB done 2\r\nPING\r\n");
        c.expect("PONG");
    }
    let mut p = login(&s, "e");
    p.send("PUB s.a 1\r\nx\r\nPUB done 0\r\n\r\n");
    p.flush();
    for c in &mut subs {
        c.expect("MSG pre.s.a 1 1");
        c.expect("x");
        c.expect("MSG done 2 0");
        c.expect("");
    }
    // Gone with its subscription, on every lane.
    for c in &mut subs {
        c.send("UNSUB 1\r\nPING\r\n");
        c.expect("PONG");
    }
    p.send("PUB s.b 1\r\ny\r\nPUB done 0\r\n\r\n");
    p.flush();
    for c in &mut subs {
        c.expect("MSG done 2 0");
        c.expect("");
    }
}

#[test]
fn an_importer_and_its_exporter_share_a_queue_group_of_one_name() {
    let s = importing(3);
    let mut importer = login(&s, "i");
    importer.send("SUB pre.s.q q 1\r\nSUB done 2\r\nPING\r\n");
    importer.expect("PONG");
    let mut exporter = login(&s, "e");
    exporter.send("SUB s.q q 1\r\nSUB done 2\r\nPING\r\n");
    exporter.expect("PONG");
    let mut publisher = login(&s, "e");
    let n = 2000;
    for _ in 0..n {
        publisher.send("PUB s.q 1\r\nx\r\n");
    }
    publisher.send("PUB done 0\r\n\r\n");
    publisher.flush();
    let counts = [
        count_until_done(&mut importer),
        count_until_done(&mut exporter),
    ];
    assert_eq!(counts.iter().sum::<usize>(), n, "each message once");
    for c in counts {
        assert!((700..1300).contains(&c), "{counts:?}");
    }
}
