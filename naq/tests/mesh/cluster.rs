//! Clusters of naq servers for tests: started on free ports, through
//! proxies if need be, and the oracle of a quiet one.
//!
//! Each test crate uses a part of it.
#![allow(dead_code, reason = "each test crate uses a part")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use naq::{Cluster, Options, Server};

use super::proxy::Proxy;

/// Longest wait for anything a test expects.
pub(crate) const WAIT: Duration = Duration::from_secs(5);

/// A free port, each once per run, below the kernel's ephemeral ports.
pub(crate) fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 32_000 - (std::process::id() % 400) as u16 * 30;
    loop {
        // Relaxed: only uniqueness matters.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = base - n % 2_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// Server `n{i}` of cluster `c`, two lanes, on cluster port `port` with
/// routes to `routes`.
pub(crate) fn node(i: usize, port: u16, routes: &[u16]) -> Server {
    Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        http_port: Some(0),
        server_name: format!("n{i}"),
        cluster: Some(Cluster {
            name: "c".into(),
            host: "127.0.0.1".into(),
            port,
            routes: routes
                .iter()
                .map(|p| format!("nats-route://127.0.0.1:{p}"))
                .collect(),
        }),
        ..Options::default()
    })
    .unwrap()
}

/// Interest one server tells the others of: subject, queue group and its
/// members there, 1 for plain interest.
pub(crate) type Told = (String, Option<String>, u64);

/// `entries`, sorted, as [`heard`] gives them.
pub(crate) fn told(entries: &[(&str, Option<&str>, u64)]) -> Vec<Told> {
    let mut all: Vec<Told> = entries
        .iter()
        .map(|&(s, q, w)| (s.to_owned(), q.map(str::to_owned), w))
        .collect();
    all.sort();
    all
}

/// What `s` heard of the interest of server `name`, sorted; `None`
/// while its route is down.
pub(crate) fn heard(s: &Server, name: &str) -> Option<Vec<Told>> {
    let z = get(s, "/routez?subs=detail");
    let r = z["routes"]
        .as_array()?
        .iter()
        .find(|r| r["remote_name"] == name)?;
    let mut all: Vec<Told> = r["subscriptions_list_detail"]
        .as_array()
        .map(|subs| {
            subs.iter()
                .map(|d| {
                    (
                        d["subject"].as_str().unwrap().to_owned(),
                        d["qgroup"].as_str().map(str::to_owned),
                        d["queue_weight"].as_u64().unwrap_or(1),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    all.sort();
    Some(all)
}

/// The oracle of a quiet cluster. Waits until each server `n{i}` that is
/// up, `Some` in `servers`, heard of each other one `n{j}` what `want[j]`
/// says of its clients, if `apart(i, j)` does not keep them apart, and
/// has no route to it otherwise.
pub(crate) fn quiet(
    servers: &[Option<&Server>],
    apart: impl Fn(usize, usize) -> bool,
    want: &[Vec<Told>],
) {
    let deadline = Instant::now() + WAIT;
    loop {
        let mut wrong = None;
        for (i, s) in servers.iter().enumerate() {
            let Some(s) = s else { continue };
            for (j, other) in servers.iter().enumerate().filter(|&(j, _)| j != i) {
                let got = heard(s, &format!("n{j}"));
                let expect = other.filter(|_| !apart(i, j)).map(|_| want[j].clone());
                if got != expect {
                    wrong = Some(format!("n{i} heard of n{j}: {got:?}, not {expect:?}"));
                }
            }
        }
        let Some(wrong) = wrong else { return };
        assert!(Instant::now() < deadline, "{wrong}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `GET path` on `s`'s monitoring port.
pub(crate) fn get(s: &Server, path: &str) -> serde_json::Value {
    let mut c = TcpStream::connect(s.monitor_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(WAIT)).unwrap();
    write!(c, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
    let mut body = String::new();
    c.read_to_string(&mut body).unwrap();
    serde_json::from_str(body.split_once("\r\n\r\n").unwrap().1).unwrap()
}

/// Three servers whose routes go through proxies, by server and route.
pub(crate) fn proxied() -> (Vec<Server>, Vec<Vec<Option<Proxy>>>) {
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let proxies: Vec<Vec<Option<Proxy>>> = (0..3)
        .map(|i| {
            (0..3)
                .map(|j| (i != j).then(|| Proxy::to("127.0.0.1", ports[j])))
                .collect()
        })
        .collect();
    let servers = (0..3)
        .map(|i| {
            let routes: Vec<u16> = proxies[i].iter().flatten().map(|p| p.port).collect();
            node(i, ports[i], &routes)
        })
        .collect();
    (servers, proxies)
}
