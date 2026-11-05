//! naq servers of one cluster, meshed over OMQ.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use naq::{Cluster, Options, Server};

mod proxy;

use proxy::{BLACKHOLE, CUT, OPEN, Proxy, STALLED, STALLING};

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

/// Server `n{i}` of cluster `c`, two lanes, on cluster port `port` with
/// routes to `routes`.
fn node(i: usize, port: u16, routes: &[u16]) -> Server {
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

/// Server `i` of a cluster on `ports`, with routes to all the others.
fn member(i: usize, ports: &[u16]) -> Server {
    let others: Vec<u16> = (0..ports.len())
        .filter(|&j| j != i)
        .map(|j| ports[j])
        .collect();
    node(i, ports[i], &others)
}

/// `n` servers of cluster `c`, each with routes to all the others.
fn cluster(n: usize) -> Vec<Server> {
    let ports: Vec<u16> = (0..n).map(|_| free_port()).collect();
    (0..n).map(|i| member(i, &ports)).collect()
}

/// Interest one server tells the others of: subject, queue group and its
/// members there, 1 for plain interest.
type Told = (String, Option<String>, u64);

/// `entries`, sorted, as [`heard`] gives them.
fn told(entries: &[(&str, Option<&str>, u64)]) -> Vec<Told> {
    let mut all: Vec<Told> = entries
        .iter()
        .map(|&(s, q, w)| (s.to_owned(), q.map(str::to_owned), w))
        .collect();
    all.sort();
    all
}

/// What `s` heard of the interest of server `name`, sorted; `None`
/// while its route is down.
fn heard(s: &Server, name: &str) -> Option<Vec<Told>> {
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
fn quiet(servers: &[Option<&Server>], apart: impl Fn(usize, usize) -> bool, want: &[Vec<Told>]) {
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

/// Never apart.
const fn together(_: usize, _: usize) -> bool {
    false
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
    let servers = met_cluster();
    let up: Vec<Option<&Server>> = servers.iter().map(Some).collect();
    let none = Vec::new();
    let mut c = client(&servers[1], "SUB a 1\r\nSUB a 2\r\nSUB w.* q 3\r\n");
    let d = client(&servers[1], "SUB w.* q 1\r\n");
    let n1 = told(&[("a", None, 1), ("w.*", Some("q"), 2)]);
    quiet(&up, together, &[none.clone(), n1, none.clone()]);
    let z = get(&servers[0], "/routez?subs=1");
    let mut subjects = z["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["remote_name"] == "n1")
        .unwrap()["subscriptions_list"]
        .clone();
    subjects
        .as_array_mut()
        .unwrap()
        .sort_by_key(ToString::to_string);
    assert_eq!(subjects, serde_json::json!(["a", "w.*"]));
    assert!(
        get(&servers[0], "/routez")
            .to_string()
            .find("subscriptions_list")
            .is_none()
    );
    send(&mut c, "UNSUB 1\r\nUNSUB 3\r\nPING\r\n");
    // One subscription to a stays: the others hear of no change for it.
    let n1 = told(&[("a", None, 1), ("w.*", Some("q"), 1)]);
    quiet(&up, together, &[none.clone(), n1, none.clone()]);
    drop((c, d));
    quiet(&up, together, &[none.clone(), none.clone(), none]);
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
fn a_message_of_another_server_is_not_sent_to_a_hub() {
    use std::io::BufRead;
    let hub = TcpListener::bind("127.0.0.1:0").unwrap();
    let ports: Vec<u16> = (0..2).map(|_| free_port()).collect();
    // Clients and links take lanes in turn: the remote and the first
    // client are on lane 0.
    let start = |i: usize| {
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
    w.write_all(b"INFO {\"connect_info\":true}\r\nLS+ x\r\n")
        .unwrap();
    until(&linked, "/leafz?subs=1", |z| {
        z["leafs"][0]["subscriptions_list"] == serde_json::json!(["x"])
    });
    let mut near = client(&linked, "SUB x 1\r\n");
    // Their messages come in on their lanes of the linked server: lane 0
    // has the link, lane 1 hands them on to lane 0.
    let mut on0 = client(&other, "");
    let mut on1 = client(&other, "");
    // The hub has a link of its own to every server that should send it
    // a message, as in `nats-server`.
    until_heard(&mut on0, &mut near, "x");
    until_heard(&mut on1, &mut near, "x");
    send(&mut near, "PUB x 4\r\nnear\r\n");
    let lmsg = loop {
        let l = line(&mut r);
        if l.starts_with("LMSG") {
            break l;
        }
    };
    assert_eq!([lmsg, line(&mut r)], ["LMSG x 4", "near"]);
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

#[test]
fn a_server_that_starts_again_is_heard_anew() {
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let (zero, two) = (member(0, &ports), member(2, &ports));
    let one = member(1, &ports);
    let none = Vec::new();
    let _old = client(&one, "SUB old 1\r\nSUB q.* g 2\r\n");
    let n1 = told(&[("old", None, 1), ("q.*", Some("g"), 1)]);
    quiet(
        &[Some(&zero), Some(&one), Some(&two)],
        together,
        &[none.clone(), n1, none.clone()],
    );
    drop(one);
    quiet(
        &[Some(&zero), None, Some(&two)],
        together,
        &[none.clone(), none.clone(), none.clone()],
    );
    // On its cluster port again, with data links of a new start.
    let one = member(1, &ports);
    let mut new = client(&one, "SUB new 1\r\n");
    let n1 = told(&[("new", None, 1)]);
    quiet(
        &[Some(&zero), Some(&one), Some(&two)],
        together,
        &[none.clone(), n1, none],
    );
    let mut p = client(&zero, "");
    until_heard(&mut p, &mut new, "new");
}

/// Three servers whose routes go through proxies, by server and route.
fn proxied() -> (Vec<Server>, Vec<Vec<Option<Proxy>>>) {
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

/// Sets every proxy between server 2 and the others to `state`.
fn isolate_two(proxies: &[Vec<Option<Proxy>>], state: u8) {
    for (i, j) in [(0, 2), (2, 0), (1, 2), (2, 1)] {
        let p = proxies[i][j].as_ref().unwrap();
        if state == CUT {
            p.cut();
        } else {
            p.set(state);
        }
    }
}

/// Server 2 is apart from the others.
const fn two_apart(i: usize, j: usize) -> bool {
    (i == 2) != (j == 2)
}

/// Server 2's interest changes while it is apart; once back, each side
/// hears the other as it is now, and messages cross again.
fn partition_heals(state: u8) {
    let (servers, proxies) = proxied();
    let up: Vec<Option<&Server>> = servers.iter().map(Some).collect();
    let none = Vec::new();
    let mut before = client(&servers[2], "SUB before 1\r\nSUB g g 2\r\n");
    let n2 = told(&[("before", None, 1), ("g", Some("g"), 1)]);
    quiet(&up, together, &[none.clone(), none.clone(), n2]);
    isolate_two(&proxies, state);
    quiet(&up, two_apart, &[none.clone(), none.clone(), none.clone()]);
    send(&mut before, "UNSUB 1\r\nSUB during 3\r\n");
    let mut zero = client(&servers[0], "SUB zero 1\r\n");
    let (n0, n2) = (
        told(&[("zero", None, 1)]),
        told(&[("during", None, 1), ("g", Some("g"), 1)]),
    );
    // Long enough for the routes to be dialed again, into the partition.
    std::thread::sleep(Duration::from_millis(500));
    isolate_two(&proxies, OPEN);
    quiet(&up, together, &[n0, none, n2]);
    until_heard(&mut zero, &mut before, "during");
    until_heard(&mut before, &mut zero, "zero");
}

#[test]
fn a_cut_from_the_cluster_heals() {
    partition_heals(CUT);
}

#[test]
fn a_silent_partition_heals() {
    partition_heals(BLACKHOLE);
}

#[test]
fn a_publisher_goes_on_when_a_server_with_interest_dies_unseen() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (mut servers, proxies) = proxied();
    let mut sub = client(&servers[2], "SUB x 1\r\n");
    let mut p = client(&servers[0], "");
    until_heard(&mut p, &mut sub, "x");
    // Its data links close; its routes, silent, stay up for a while.
    isolate_two(&proxies, BLACKHOLE);
    drop((sub, servers.pop()));
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let mut w = p.get_ref().try_clone().unwrap();
    let writer = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            // Relaxed: a test switch.
            while !stop.load(Ordering::Relaxed) {
                w.write_all(b"PUB x 1\r\na\r\n").unwrap();
            }
            w.write_all(b"PING\r\n").unwrap();
        })
    };
    let up = [Some(&servers[0]), Some(&servers[1]), None];
    quiet(&up, together, &[Vec::new(), Vec::new(), Vec::new()]);
    stop.store(true, Ordering::Relaxed);
    // Past the server's own `PING`s.
    while line(&mut p) != "PONG" {}
    writer.join().unwrap();
}

#[test]
fn a_server_hears_of_much_interest_whole() {
    const N: usize = 20_000;
    let ports: Vec<u16> = (0..2).map(|_| free_port()).collect();
    let first = member(0, &ports);
    let subs = |from: usize| -> String {
        use std::fmt::Write as _;
        (from..from + N).fold(String::new(), |mut all, i| {
            write!(all, "SUB s.{i} {i}\r\n").unwrap();
            all
        })
    };
    let mut c = client(&first, &subs(0));
    // All of it in its snapshot, then as many again in deltas.
    let late = member(1, &ports);
    until(&late, "/routez", |z| route_subs(z, "n0") == Some(N as u64));
    send(&mut c, &subs(N));
    until(&late, "/routez", |z| {
        route_subs(z, "n0") == Some(2 * N as u64)
    });
}

#[test]
fn a_server_that_falls_behind_holds_up_no_other() {
    use std::fmt::Write as _;
    // Long subjects: fewer deltas fill the route.
    const N: usize = 30_000;
    let (servers, proxies) = proxied();
    let up: Vec<Option<&Server>> = servers.iter().map(Some).collect();
    quiet(&up, together, &[Vec::new(), Vec::new(), Vec::new()]);
    // What server 1 tells server 2 backs up.
    proxies[2][1].as_ref().unwrap().set(STALLED);
    let pad = "x".repeat(200);
    let subs = (0..N).fold(String::new(), |mut all, i| {
        write!(all, "SUB s.{i}.{pad} {i}\r\n").unwrap();
        all
    });
    let _c = client(&servers[1], &subs);
    until(&servers[0], "/routez", |z| {
        route_subs(z, "n1") == Some(N as u64)
    });
    // And it catches up once it reads again.
    proxies[2][1].as_ref().unwrap().set(OPEN);
    until(&servers[2], "/routez", |z| {
        route_subs(z, "n1") == Some(N as u64)
    });
}

/// Remote port, state and unsent bytes of each TCP socket on local
/// `port`, as the kernel tells them.
#[cfg(target_os = "linux")]
fn sockets(port: u16) -> Vec<(u16, u8, u32)> {
    let port_of = |a: &str| u16::from_str_radix(a.rsplit(':').next().unwrap(), 16).unwrap();
    std::fs::read_to_string("/proc/net/tcp")
        .unwrap()
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (port_of(f[1]) == port).then(|| {
                let unsent = f[4].split(':').next().unwrap();
                (
                    port_of(f[2]),
                    u8::from_str_radix(f[3], 16).unwrap(),
                    u32::from_str_radix(unsent, 16).unwrap(),
                )
            })
        })
        .collect()
}

/// What server 1 tells a server that stops reading and sending backs up;
/// server 1 still lets the link go.
#[cfg(target_os = "linux")]
#[test]
fn a_server_that_stops_reading_is_let_go() {
    use std::fmt::Write as _;
    const ESTABLISHED: u8 = 1;
    // More than the kernel buffers on both ends hold.
    const N: usize = 50_000;
    let (servers, proxies) = proxied();
    let up: Vec<Option<&Server>> = servers.iter().map(Some).collect();
    quiet(&up, together, &[Vec::new(), Vec::new(), Vec::new()]);
    // Server 2 reads nothing more from server 1, and sends it nothing. Its
    // last heartbeat told how long it may stay silent, and more input came
    // after it, so only that heartbeat can find it gone.
    let proxy = proxies[2][1].as_ref().unwrap();
    proxy.set(STALLING);
    let deadline = Instant::now() + WAIT;
    while proxy.state() != STALLED {
        assert!(Instant::now() < deadline, "no heartbeat");
        std::thread::sleep(Duration::from_millis(20));
    }
    let pad = "x".repeat(200);
    let subs = (0..N).fold(String::new(), |mut all, i| {
        write!(all, "SUB s.{i}.{pad} {i}\r\n").unwrap();
        all
    });
    let _c = client(&servers[1], &subs);
    let port = servers[1].cluster_addr().unwrap().port();
    let deadline = Instant::now() + 4 * WAIT;
    let stuck = loop {
        let now = sockets(port);
        if let Some(&(to, ..)) = now
            .iter()
            .find(|&&(_, state, unsent)| state == ESTABLISHED && unsent >= 1 << 20)
        {
            break to;
        }
        assert!(Instant::now() < deadline, "nothing backs up: {now:?}");
        std::thread::sleep(Duration::from_millis(20));
    };
    let deadline = Instant::now() + 4 * WAIT;
    loop {
        let now = sockets(port);
        if !now
            .iter()
            .any(|&(to, state, _)| to == stuck && state == ESTABLISHED)
        {
            break;
        }
        assert!(Instant::now() < deadline, "still up: {now:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_server_that_asks_again_gets_a_snapshot_again() {
    use bytes::Bytes;
    use naq_proto::peer::{self, Control, Hello, Role};
    use omq_tokio::{Message, Socket};
    // The subjects of the next snapshot `d` gets, past beats.
    async fn snapshot(d: &Socket) -> Vec<String> {
        let mut subjects = Vec::new();
        loop {
            let msg = tokio::time::timeout(WAIT, d.recv()).await.unwrap().unwrap();
            match peer::decode(&msg.into_bytes().unwrap()).unwrap() {
                Control::Entry(i) => subjects.push(String::from_utf8_lossy(i.subject).into_owned()),
                Control::SnapshotEnd { .. } => return subjects,
                _ => {}
            }
        }
    }
    let encode = |c: Control<'_>| {
        let mut out = Vec::new();
        c.encode(&mut out);
        Message::single(Bytes::from(out))
    };
    let ports = [free_port(), free_port()];
    let s = member(0, &ports);
    let _c = client(&s, "SUB a 1\r\n");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let d = omq_tokio::Context::current().socket(
            omq_tokio::SocketType::Dealer,
            omq_tokio::Options {
                identity: Bytes::from_static(b"FAKE"),
                ..omq_tokio::Options::default()
            },
        );
        d.connect(format!("tcp://{}", s.cluster_addr().unwrap()))
            .await
            .unwrap();
        let hello = Control::Hello(Hello {
            role: Role::Route,
            account: b"",
            epoch: 1,
            server_id: b"FAKE",
            name: b"fake",
            cluster: b"c",
            data: b"",
            client_urls: b"",
            leaf_urls: b"",
            nonce: b"",
        });
        d.send(encode(hello)).await.unwrap();
        assert_eq!(snapshot(&d).await, ["a"]);
        d.send(encode(Control::Resync)).await.unwrap();
        assert_eq!(snapshot(&d).await, ["a"]);
    });
}
