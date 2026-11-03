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
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .unwrap();
    let mut text = String::new();
    c.read_to_string(&mut text).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.lines().next().unwrap().to_owned();
    (status, serde_json::from_str(body).unwrap())
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
fn a_bad_request_is_closed() {
    let s = Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        http_port: Some(0),
        ..Options::default()
    })
    .unwrap();
    let m = s.monitor_addr().unwrap();
    for bad in ["POST /varz HTTP/1.1\r\n\r\n", "GET\r\n\r\n"] {
        let mut c = TcpStream::connect(m).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(bad.as_bytes()).unwrap();
        let mut text = String::new();
        let _ = c.read_to_string(&mut text);
        assert_eq!(text, "", "{bad:?}");
    }
    let mut c = TcpStream::connect(m).unwrap();
    c.write_all(&[b'x'; 9000]).unwrap();
    let mut text = String::new();
    let _ = c.read_to_string(&mut text);
    assert_eq!(text, "");
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
