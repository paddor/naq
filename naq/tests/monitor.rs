//! Monitoring over HTTP.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use naq::{Options, Server};

/// The status line and JSON body of `GET path`.
fn get(at: SocketAddr, path: &str) -> (String, serde_json::Value) {
    let mut c = TcpStream::connect(at).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .unwrap();
    let mut text = String::new();
    c.read_to_string(&mut text).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.lines().next().unwrap().to_owned();
    (status, serde_json::from_str(body).unwrap_or_default())
}

/// A client that subscribed to its name and sent `n` messages to itself,
/// after a round trip.
fn busy(s: &Server, name: &str, n: usize) -> BufReader<TcpStream> {
    let mut c = TcpStream::connect(s.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = format!(
        "CONNECT {{\"verbose\":false,\"name\":\"{name}\",\"lang\":\"rust\",\"version\":\"9\"}}\r\nSUB {name} 1\r\n"
    );
    for _ in 0..n {
        let _ = write!(out, "PUB {name} 2\r\nhi\r\n");
    }
    out += "PING\r\n";
    c.write_all(out.as_bytes()).unwrap();
    let mut r = BufReader::new(c);
    let mut line = String::new();
    loop {
        line.clear();
        r.read_line(&mut line).unwrap();
        if line == "PONG\r\n" {
            return r;
        }
    }
}

#[test]
fn health_vars_and_connections_come_as_nats_server_writes_them() {
    let s = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        http_port: Some(0),
        ..Options::default()
    })
    .unwrap();
    let m = s.monitor_addr().unwrap();
    let (status, health) = get(m, "/healthz");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert_eq!(health["status"], "ok");
    let _a = busy(&s, "a", 3);
    let _b = busy(&s, "b", 2);
    let (_, varz) = get(m, "/varz");
    assert_eq!(varz["connections"], 2);
    assert_eq!(varz["total_connections"], 2);
    assert_eq!(varz["in_msgs"], 5);
    assert_eq!(varz["in_bytes"], 10);
    assert_eq!(varz["out_msgs"], 5);
    assert_eq!(varz["max_payload"], 1 << 20);
    assert!(varz["start"].as_str().unwrap().ends_with('Z'));
    let (_, conn_list) = get(m, "/connz?limit=10");
    assert_eq!(conn_list["num_connections"], 2);
    let conns = conn_list["connections"].as_array().unwrap();
    let names: Vec<_> = conns.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["a", "b"]);
    assert_eq!(conns[0]["in_msgs"], 3);
    assert_eq!(conns[0]["out_msgs"], 3);
    assert_eq!(conns[0]["subscriptions"], 1);
    assert_eq!(conns[0]["lang"], "rust");
    assert_eq!(conns[0]["account"], "$G");
    let (status, _) = get(m, "/nothing");
    assert_eq!(status, "HTTP/1.1 404 Not Found");
}

#[test]
fn one_connection_takes_requests_in_turn() {
    let s = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        http_port: Some(0),
        ..Options::default()
    })
    .unwrap();
    let mut c = TcpStream::connect(s.monitor_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\nGET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut r = BufReader::new(c);
    let mut statuses = Vec::new();
    let mut line = String::new();
    while statuses.len() < 2 {
        line.clear();
        assert!(r.read_line(&mut line).unwrap() > 0, "closed");
        // A body without a newline runs into the next status line.
        if let Some(at) = line.find("HTTP/1.1 ") {
            statuses.push(line[at..].trim_end().to_owned());
        }
    }
    assert_eq!(statuses, ["HTTP/1.1 200 OK", "HTTP/1.1 404 Not Found"]);
    // A head past 1 MiB is refused, and the connection closed.
    let mut c = TcpStream::connect(s.monitor_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut big = b"GET /varz HTTP/1.1\r\nX: ".to_vec();
    big.resize((1 << 20) + 8192, b'x');
    let _ = c.write_all(&big);
    let mut text = String::new();
    let _ = c.read_to_string(&mut text);
    assert!(text.starts_with("HTTP/1.1 431 "), "{text}");
}

#[test]
fn no_port_no_monitoring() {
    let s = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        ..Options::default()
    })
    .unwrap();
    assert!(s.monitor_addr().is_none());
}

/// The status line, headers and body of `GET path`, as text.
fn get_text(at: SocketAddr, path: &str) -> (String, String) {
    let mut c = TcpStream::connect(at).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .unwrap();
    let mut text = String::new();
    c.read_to_string(&mut text).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (head.to_owned(), body.to_owned())
}

#[test]
fn the_index_links_to_the_endpoints_under_the_base_path() {
    let s = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        http_port: Some(0),
        http_base_path: "/mon/".into(),
        ..Options::default()
    })
    .unwrap();
    let m = s.monitor_addr().unwrap();
    let (head, page) = get_text(m, "/mon");
    assert!(
        head.contains("Content-Type: text/html; charset=utf-8"),
        "{head}"
    );
    assert!(page.contains("<a href=\"/mon/varz\">varz</a>"), "{page}");
    assert!(page.contains("<a href=\"/mon/debug/vars\">"), "{page}");
    let (_, varz) = get(m, "/mon/varz");
    assert_eq!(varz["http_req_stats"]["/"], 1);
    // The command line, as Go's expvar writes it.
    let (head, expvar) = get_text(m, "/mon/debug/vars");
    assert!(
        head.contains("Content-Type: application/json; charset=utf-8"),
        "{head}"
    );
    assert!(!head.contains("Access-Control"), "{head}");
    assert!(
        expvar.starts_with("{\n\"cmdline\": [\"") && expvar.ends_with("\"]\n}\n"),
        "{expvar}"
    );
    let (head, _) = get_text(m, "/mon/stacksz");
    assert!(head.starts_with("HTTP/1.1 404 "), "{head}");
}

#[test]
fn a_publisher_that_outruns_its_subscriber_is_stalled_and_counted() {
    let s = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        http_port: Some(0),
        max_pending: 256 << 10,
        ..Options::default()
    })
    .unwrap();
    // A subscriber that never reads.
    let mut sub = TcpStream::connect(s.addr()).unwrap();
    sub.write_all(b"CONNECT {\"verbose\":false}\r\nSUB big 1\r\nPING\r\n")
        .unwrap();
    let mut publisher = busy(&s, "p", 0);
    let payload = "x".repeat(32 << 10);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let (_, varz) = get(s.monitor_addr().unwrap(), "/varz");
        if varz["slow_consumer_stats"]["clients"] == 1 {
            assert!(varz["stalled_clients"].as_u64().unwrap() > 0, "{varz}");
            assert_eq!(varz["slow_consumers"], 1);
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{varz}");
        let mut batch = String::new();
        for _ in 0..64 {
            let _ = write!(batch, "PUB big {}\r\n{payload}\r\n", payload.len());
        }
        publisher.get_mut().write_all(batch.as_bytes()).unwrap();
    }
}
