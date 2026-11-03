//! A server and clients over TCP.

#![expect(clippy::unwrap_used, clippy::panic, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use naq::{Error, Options, Server};

const WAIT: Duration = Duration::from_secs(5);

fn server() -> Server {
    server_with(Options::default())
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

    fn line(&mut self) -> String {
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
    assert_eq!(json["server_id"].as_str().unwrap().len(), 22);
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
fn what_the_skeleton_cannot_do_is_refused() {
    let s = server();
    let mut c = Client::quiet(&s);
    c.send("SUB a.* 1\r\nSUB a.> 2\r\nSUB q g 3\r\nSUB m 4\r\nUNSUB 4 5\r\nPING\r\n");
    c.expect("-ERR 'Wildcards Not Supported'");
    c.expect("-ERR 'Wildcards Not Supported'");
    c.expect("-ERR 'Queue Groups Not Supported'");
    c.expect("-ERR 'UNSUB Maximum Not Supported'");
    c.expect("PONG");
    let more = Server::start(&Options {
        lanes: 2,
        ..Options::default()
    });
    assert!(matches!(more, Err(Error::Unsupported(_))), "{more:?}");
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
    assert_eq!(c.rest(), "-ERR 'Maximum Control Line Exceeded'\r\n");
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
