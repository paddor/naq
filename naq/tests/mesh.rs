//! naq servers of one cluster, meshed over OMQ.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use naq::{Cluster, Options, Server};

/// Longest wait for anything a test expects.
const WAIT: Duration = Duration::from_secs(5);

/// A free port, each once per run, below the kernel's ephemeral ports.
fn free_port() -> u16 {
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

/// `n` servers of cluster `c`, each with routes to all the others.
fn cluster(n: usize) -> Vec<Server> {
    let ports: Vec<u16> = (0..n).map(|_| free_port()).collect();
    (0..n)
        .map(|i| {
            Server::start(&Options {
                host: "127.0.0.1".into(),
                port: 0,
                lanes: 2,
                http_port: Some(0),
                server_name: format!("n{i}"),
                cluster: Some(Cluster {
                    name: "c".into(),
                    host: "127.0.0.1".into(),
                    port: ports[i],
                    routes: (0..n)
                        .filter(|&j| j != i)
                        .map(|j| format!("nats-route://127.0.0.1:{}", ports[j]))
                        .collect(),
                }),
                ..Options::default()
            })
            .unwrap()
        })
        .collect()
}

/// `GET path` on `s`'s monitoring port.
fn get(s: &Server, path: &str) -> serde_json::Value {
    let mut c = TcpStream::connect(s.monitor_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(WAIT)).unwrap();
    write!(c, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
    let mut body = String::new();
    c.read_to_string(&mut body).unwrap();
    serde_json::from_str(body.split_once("\r\n\r\n").unwrap().1).unwrap()
}

/// Waits until `f` holds of `path` on `s`, and returns it.
fn until(s: &Server, path: &str, f: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let z = get(s, path);
        if f(&z) {
            return z;
        }
        assert!(Instant::now() < deadline, "{path}: {z}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn servers_of_a_cluster_meet_each_other() {
    let servers = cluster(3);
    for (i, s) in servers.iter().enumerate() {
        assert!(s.cluster_addr().is_some());
        let z = until(s, "/routez", |z| z["num_routes"] == 2);
        let mut names: Vec<_> = z["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["remote_name"].as_str().unwrap().to_owned())
            .collect();
        names.sort();
        let mut want: Vec<_> = (0..3)
            .filter(|&j| j != i)
            .map(|j| format!("n{j}"))
            .collect();
        want.sort();
        assert_eq!(names, want);
    }
}

#[test]
fn a_server_of_another_cluster_is_not_met() {
    let (x, y, z) = (free_port(), free_port(), free_port());
    let start = |me: u16, others: &[u16], name: &str| {
        Server::start(&Options {
            host: "127.0.0.1".into(),
            port: 0,
            http_port: Some(0),
            cluster: Some(Cluster {
                name: name.into(),
                host: "127.0.0.1".into(),
                port: me,
                routes: others.iter().map(|p| format!("127.0.0.1:{p}")).collect(),
            }),
            ..Options::default()
        })
        .unwrap()
    };
    let one = start(x, &[y, z], "one");
    let two = start(y, &[x], "two");
    let _same = start(z, &[x], "one");
    // It meets the server of its own cluster, not the other.
    let routes = until(&one, "/routez", |z| z["num_routes"].as_u64() > Some(0));
    assert_eq!(routes["num_routes"], 1, "{routes}");
    assert_eq!(routes["routes"][0]["port"], z);
    assert_eq!(get(&two, "/routez")["num_routes"], 0);
}

#[test]
fn a_cluster_that_cannot_listen_or_route_stops_the_start() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let start = |port: u16, routes: Vec<String>| {
        Server::start(&Options {
            host: "127.0.0.1".into(),
            port: 0,
            cluster: Some(Cluster {
                name: "c".into(),
                host: "127.0.0.1".into(),
                port,
                routes,
            }),
            ..Options::default()
        })
    };
    let e = start(port, Vec::new()).unwrap_err();
    assert!(matches!(e, naq::Error::Listen { .. }), "{e}");
    let e = start(0, vec!["ws://h".into()]).unwrap_err();
    assert!(e.to_string().contains("scheme not supported"), "{e}");
    let free = start(0, Vec::new()).unwrap();
    assert_ne!(free.cluster_addr().unwrap().port(), 0);
}

#[test]
fn a_server_that_stops_leaves_the_routes_of_the_others() {
    let mut servers = cluster(3);
    until(&servers[0], "/routez", |z| z["num_routes"] == 2);
    drop(servers.remove(2));
    let z = until(&servers[0], "/routez", |z| z["num_routes"] == 1);
    assert_eq!(z["routes"][0]["remote_name"], "n1");
}
