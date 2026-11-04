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
    let many = (0..65).map(|i| format!("h{i}:1")).collect();
    let e = start(0, many).unwrap_err();
    assert!(e.to_string().contains("more than 64 routes"), "{e}");
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

/// A client of `s` that sent `ops` and got its `PONG`.
fn client(s: &Server, ops: &str) -> std::io::BufReader<TcpStream> {
    use std::io::BufRead;
    let mut c = TcpStream::connect(s.addr()).unwrap();
    c.set_read_timeout(Some(WAIT)).unwrap();
    write!(c, "CONNECT {{\"verbose\":false}}\r\n{ops}PING\r\n").unwrap();
    let mut r = std::io::BufReader::new(c);
    let mut l = String::new();
    while l != "PONG\r\n" {
        l.clear();
        r.read_line(&mut l).unwrap();
    }
    r
}

/// The subscriptions route `rid` shows on `s`, once it is up.
fn route_subs(z: &serde_json::Value, name: &str) -> Option<u64> {
    z["routes"]
        .as_array()?
        .iter()
        .find(|r| r["remote_name"] == name)?["subscriptions"]
        .as_u64()
}

#[test]
fn the_others_hear_of_the_interest_of_a_servers_clients() {
    let servers = cluster(3);
    for s in &servers {
        until(s, "/routez", |z| z["num_routes"] == 2);
    }
    let mut c = client(&servers[1], "SUB a 1\r\nSUB a 2\r\nSUB w.* q 3\r\n");
    for s in [&servers[0], &servers[2]] {
        until(s, "/routez", |z| route_subs(z, "n1") == Some(2));
    }
    c.get_mut()
        .write_all(b"UNSUB 1\r\nUNSUB 3\r\nPING\r\n")
        .unwrap();
    // One subscription to a stays: the others hear of no change for it.
    until(&servers[0], "/routez", |z| route_subs(z, "n1") == Some(1));
    drop(c);
    until(&servers[2], "/routez", |z| route_subs(z, "n1") == Some(0));
}

#[test]
fn a_server_that_starts_late_hears_of_what_was_there() {
    let ports: Vec<u16> = (0..2).map(|_| free_port()).collect();
    let start = |i: usize| {
        Server::start(&Options {
            host: "127.0.0.1".into(),
            port: 0,
            http_port: Some(0),
            server_name: format!("n{i}"),
            cluster: Some(Cluster {
                name: "c".into(),
                host: "127.0.0.1".into(),
                port: ports[i],
                routes: vec![format!("127.0.0.1:{}", ports[1 - i])],
            }),
            ..Options::default()
        })
        .unwrap()
    };
    let first = start(0);
    let _c = client(&first, "SUB a 1\r\nSUB b q 2\r\n");
    let late = start(1);
    until(&late, "/routez", |z| route_subs(z, "n0") == Some(2));
}

type Client = std::io::BufReader<TcpStream>;

/// The next line `c` gets, without its CRLF.
fn line(c: &mut Client) -> String {
    use std::io::BufRead;
    let mut l = String::new();
    c.read_line(&mut l).unwrap();
    l.trim_end_matches(['\r', '\n']).to_owned()
}

fn send(c: &mut Client, s: &str) {
    c.get_mut().write_all(s.as_bytes()).unwrap();
}

/// Publishes `subject` from `p` until `c` gets it: interest reaches every
/// lane of the other server in its own time. `c` gets one copy after.
fn until_heard(p: &mut Client, c: &mut Client, subject: &str) {
    use std::io::BufRead;
    let deadline = Instant::now() + WAIT;
    c.get_mut()
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    loop {
        send(p, &format!("PUB {subject} 4\r\nwait\r\n"));
        let mut l = String::new();
        if c.read_line(&mut l).is_ok() && l.starts_with(&format!("MSG {subject} ")) {
            line(c);
            break;
        }
        assert!(Instant::now() < deadline, "nothing on {subject}");
    }
    c.get_mut().set_read_timeout(Some(WAIT)).unwrap();
    // Copies still on their way come before this one: the same way.
    send(p, &format!("PUB {subject} 4\r\nsync\r\n"));
    while line(c) != "sync" {}
}

/// A cluster of 3, met.
fn met_cluster() -> Vec<Server> {
    let servers = cluster(3);
    for s in &servers {
        until(s, "/routez", |z| z["num_routes"] == 2);
    }
    servers
}

#[test]
fn a_message_reaches_the_subscribers_at_every_other_server_once() {
    let servers = met_cluster();
    let mut p = client(&servers[0], "");
    // Each with a subject of its own to wait on.
    let mut one = client(&servers[1], "SUB a.* 1\r\nSUB a.> 2\r\nSUB s1 9\r\n");
    let mut two = client(&servers[2], "SUB a.b 1\r\nSUB s2 9\r\n");
    until_heard(&mut p, &mut one, "s1");
    until_heard(&mut p, &mut two, "s2");
    send(
        &mut p,
        "PUB a.b r 2\r\nhi\r\nPUB s1 0\r\n\r\nPUB s2 0\r\n\r\n",
    );
    // Both filters of server 1 match: one message there, for both.
    let mut got: Vec<String> = (0..4).map(|_| line(&mut one)).collect();
    assert_eq!(line(&mut one), "MSG s1 9 0");
    got.sort();
    assert_eq!(got, ["MSG a.b 1 r 2", "MSG a.b 2 r 2", "hi", "hi"]);
    assert_eq!(
        [line(&mut two), line(&mut two), line(&mut two)],
        ["MSG a.b 1 r 2", "hi", "MSG s2 9 0"],
        "once, though server 1 got it too"
    );
}

#[test]
fn a_queue_group_across_servers_gets_each_message_once() {
    let servers = met_cluster();
    let mut p = client(&servers[0], "");
    let mut one = client(&servers[1], "SUB q.x workers 1\r\nSUB s1 9\r\n");
    let mut two = client(&servers[2], "SUB q.x workers 1\r\nSUB s2 9\r\n");
    until_heard(&mut p, &mut one, "s1");
    until_heard(&mut p, &mut two, "s2");
    // Queue interest reaches the lanes with the plain one, in order.
    let n = 200;
    let mut out = String::new();
    for _ in 0..n {
        out.push_str("PUB q.x 1\r\nj\r\n");
    }
    out.push_str("PUB s1 0\r\n\r\nPUB s2 0\r\n\r\n");
    send(&mut p, &out);
    let count = |c: &mut Client| {
        let mut jobs = 0;
        loop {
            let l = line(c);
            if l.starts_with("MSG s") {
                line(c);
                return jobs;
            }
            if l.starts_with("MSG q.x 1") {
                jobs += 1;
            }
        }
    };
    let (a, b) = (count(&mut one), count(&mut two));
    assert_eq!(a + b, n, "{a} + {b}");
    assert!(a > 0 && b > 0, "{a} and {b}");
}

#[test]
fn a_request_across_servers_gets_its_reply() {
    let servers = met_cluster();
    let mut svc = client(&servers[2], "SUB svc 1\r\n");
    let mut asker = client(&servers[0], "SUB _INBOX.me 7\r\n");
    until_heard(&mut asker, &mut svc, "svc");
    // And the asker's interest reaches server 2.
    until_heard(&mut svc, &mut asker, "_INBOX.me");
    send(&mut asker, "PUB svc _INBOX.me 3\r\nask\r\n");
    assert_eq!(
        [line(&mut svc), line(&mut svc)],
        ["MSG svc 1 _INBOX.me 3", "ask"]
    );
    send(&mut svc, "PUB _INBOX.me 6\r\nanswer\r\n");
    assert_eq!(
        [line(&mut asker), line(&mut asker)],
        ["MSG _INBOX.me 7 6", "answer"]
    );
}

#[test]
fn a_message_of_a_hub_stays_with_the_server_linked_to_it() {
    use std::io::BufRead;
    let hub = TcpListener::bind("127.0.0.1:0").unwrap();
    let ports: Vec<u16> = (0..2).map(|_| free_port()).collect();
    // One lane each: what server 0 sends server 1 keeps its order.
    let start = |i: usize| {
        Server::start(&Options {
            host: "127.0.0.1".into(),
            port: 0,
            lanes: 1,
            http_port: Some(0),
            server_name: format!("n{i}"),
            cluster: Some(Cluster {
                name: "c".into(),
                host: "127.0.0.1".into(),
                port: ports[i],
                routes: vec![format!("127.0.0.1:{}", ports[1 - i])],
            }),
            remotes: if i == 0 {
                vec![naq::Remote {
                    urls: vec![format!("127.0.0.1:{}", hub.local_addr().unwrap().port())],
                    ..naq::Remote::default()
                }]
            } else {
                Vec::new()
            },
            ..Options::default()
        })
        .unwrap()
    };
    let (linked, other) = (start(0), start(1));
    let (link, _) = hub.accept().unwrap();
    link.set_read_timeout(Some(WAIT)).unwrap();
    let mut r = std::io::BufReader::new(link.try_clone().unwrap());
    let mut w = link;
    w.write_all(b"INFO {\"server_id\":\"HUB\",\"client_id\":5,\"info_on_connect\":true}\r\n")
        .unwrap();
    let mut l = String::new();
    r.read_line(&mut l).unwrap();
    w.write_all(b"INFO {\"connect_info\":true}\r\n").unwrap();
    let mut far = client(&other, "SUB x 1\r\n");
    let mut p = client(&linked, "");
    until_heard(&mut p, &mut far, "x");
    // On the one lane, in place once it has its PONG.
    let mut near = client(&linked, "SUB x 1\r\n");
    // Its own client takes the hub's message; the other server does not.
    w.write_all(b"LMSG x 3\r\nhub\r\n").unwrap();
    assert_eq!([line(&mut near), line(&mut near)], ["MSG x 1 3", "hub"]);
    send(&mut near, "PUB x 5\r\nafter\r\n");
    assert_eq!([line(&mut far), line(&mut far)], ["MSG x 1 5", "after"]);
}

#[test]
fn clients_hear_where_the_clients_of_the_others_connect() {
    use std::io::BufRead;
    let servers = met_cluster();
    let c = TcpStream::connect(servers[0].addr()).unwrap();
    c.set_read_timeout(Some(WAIT)).unwrap();
    let mut l = String::new();
    std::io::BufReader::new(c).read_line(&mut l).unwrap();
    let info: serde_json::Value = serde_json::from_str(l.strip_prefix("INFO ").unwrap()).unwrap();
    let urls: Vec<String> = info["connect_urls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(urls[0], servers[0].addr().to_string(), "its own first");
    let mut others = urls[1..].to_vec();
    others.sort();
    let mut want: Vec<String> = servers[1..].iter().map(|s| s.addr().to_string()).collect();
    want.sort();
    assert_eq!(others, want);
}
