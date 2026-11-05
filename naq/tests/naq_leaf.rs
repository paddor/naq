//! naq leaf nodes of naq hubs, over OMQ.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use naq::{Cluster, Leafnodes, Options, Remote, Server};

mod proxy;

use proxy::{OPEN, Proxy};

/// Longest wait for anything a test expects.
const WAIT: Duration = Duration::from_secs(5);

/// A free port, each once per run, below the kernel's ephemeral ports.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 26_000 - (std::process::id() % 200) as u16 * 25;
    loop {
        // Relaxed: only uniqueness matters.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = base - n % 2_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// Options of server `name` with two lanes and monitoring.
fn base(name: &str) -> Options {
    Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        http_port: Some(0),
        server_name: name.into(),
        leaf_reconnect: Duration::from_millis(50),
        ..Options::default()
    }
}

/// A hub named `name` that takes naq leafs on a free port.
fn hub(name: &str) -> Server {
    Server::start(&Options {
        leafnodes: Some(Leafnodes {
            host: "127.0.0.1".into(),
            port: 0,
            account: None,
        }),
        ..base(name)
    })
    .unwrap()
}

/// A naq leaf named `name` of the naq hub at `port`.
fn leaf(name: &str, port: u16) -> Server {
    Server::start(&Options {
        remotes: vec![naq_remote(port)],
        ..base(name)
    })
    .unwrap()
}

fn naq_remote(port: u16) -> Remote {
    Remote {
        urls: vec![format!("naq://127.0.0.1:{port}")],
        ..Remote::default()
    }
}

/// `GET path` on `s`'s monitoring port.
fn get(s: &Server, path: &str) -> serde_json::Value {
    let mut c = TcpStream::connect(s.monitor_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(WAIT)).unwrap();
    write!(c, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
    let mut body = String::new();
    std::io::Read::read_to_string(&mut c, &mut body).unwrap();
    serde_json::from_str(body.split_once("\r\n\r\n").unwrap().1).unwrap()
}

/// Waits until `f` holds of `s`'s `/leafz?subs=1`, and returns it.
fn leafz(s: &Server, f: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let z = get(s, "/leafz?subs=1");
        if f(&z) {
            return z;
        }
        assert!(Instant::now() < deadline, "/leafz: {z}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The subjects `s`'s only link hears of.
fn subjects(z: &serde_json::Value) -> Vec<String> {
    z["leafs"][0]["subscriptions_list"]
        .as_array()
        .map(|l| l.iter().map(|s| s.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

/// Waits until `s`'s only link hears of `subject`.
fn hears(s: &Server, subject: &str) {
    leafz(s, |z| subjects(z).iter().any(|x| x == subject));
}

type Client = BufReader<TcpStream>;

/// A client of `s` that sent `ops` and got its `PONG`.
fn client(s: &Server, ops: &str) -> Client {
    client_with(s, "{\"verbose\":false}", ops)
}

/// A client of `s` that connected with `connect`, sent `ops` and got its
/// `PONG`.
fn client_with(s: &Server, connect: &str, ops: &str) -> Client {
    let mut c = TcpStream::connect(s.addr()).unwrap();
    c.set_read_timeout(Some(WAIT)).unwrap();
    write!(c, "CONNECT {connect}\r\n{ops}PING\r\n").unwrap();
    let mut r = BufReader::new(c);
    let mut l = String::new();
    while l != "PONG\r\n" {
        l.clear();
        r.read_line(&mut l).unwrap();
    }
    r
}

/// The next line `c` gets, without its CRLF, but the server's pings.
fn line(c: &mut Client) -> String {
    loop {
        let mut l = String::new();
        c.read_line(&mut l).unwrap();
        if l != "PING\r\n" {
            return l.trim_end_matches(['\r', '\n']).to_owned();
        }
    }
}

fn send(c: &mut Client, s: &str) {
    c.get_mut().write_all(s.as_bytes()).unwrap();
}

/// Publishes `subject` from `p` until `c` gets it, then a last one that
/// `c` gets once, after those still on their way.
fn until_heard(p: &mut Client, c: &mut Client, subject: &str) {
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
    send(p, &format!("PUB {subject} 4\r\nsync\r\n"));
    while line(c) != "sync" {}
}

/// A hub and its leaf, linked.
fn linked() -> (Server, Server) {
    let h = hub("hub");
    let l = leaf("leaf", h.leafnode_addr().unwrap().port());
    leafz(&h, |z| z["leafnodes"] == 1);
    leafz(&l, |z| z["leafnodes"] == 1);
    (h, l)
}

#[test]
fn a_naq_leaf_links_to_its_naq_hub() {
    let (h, l) = linked();
    let at_hub = &get(&h, "/leafz")["leafs"][0];
    assert_eq!(
        (&at_hub["name"], &at_hub["is_spoke"], &at_hub["account"]),
        (&"leaf".into(), &false.into(), &"$G".into())
    );
    let at_leaf = &get(&l, "/leafz")["leafs"][0];
    assert_eq!(
        (&at_leaf["name"], &at_leaf["is_spoke"], &at_leaf["port"]),
        (
            &"hub".into(),
            &true.into(),
            &h.leafnode_addr().unwrap().port().into()
        )
    );
}

#[test]
fn interest_and_messages_cross_both_ways() {
    let (h, l) = linked();
    let mut at_hub = client(&h, "SUB a 1\r\n");
    let mut at_leaf = client(&l, "SUB b 1\r\n");
    hears(&l, "a");
    hears(&h, "b");
    let mut p = client(&l, "");
    until_heard(&mut p, &mut at_hub, "a");
    let mut q = client(&h, "");
    until_heard(&mut q, &mut at_leaf, "b");
    // Headers cross too, for a client that takes them.
    let mut with = client_with(&l, "{\"verbose\":false,\"headers\":true}", "SUB b 2\r\n");
    let mut q = client_with(&h, "{\"verbose\":false,\"headers\":true}", "");
    until_heard(&mut q, &mut with, "b");
    send(&mut q, "HPUB b 18 20\r\nNATS/1.0\r\nA: b\r\n\r\nhi\r\n");
    assert_eq!(line(&mut with), "HMSG b 2 18 20");
    assert_eq!(
        [line(&mut with), line(&mut with), line(&mut with)],
        ["NATS/1.0", "A: b", ""]
    );
    assert_eq!(line(&mut with), "hi");
    send(&mut at_hub, "UNSUB 1\r\nPING\r\n");
    leafz(&l, |z| subjects(z).is_empty());
}

#[test]
fn a_queue_group_takes_a_member_across_the_link_only_without_one_here() {
    let (h, l) = linked();
    let mut far = client(&h, "SUB j q 1\r\nSUB mark 2\r\n");
    let mut near = client(&l, "SUB j q 1\r\n");
    hears(&l, "j");
    hears(&l, "mark");
    let mut p = client(&l, "");
    for _ in 0..20 {
        send(&mut p, "PUB j 1\r\nx\r\n");
    }
    for _ in 0..20 {
        assert_eq!([line(&mut near), line(&mut near)], ["MSG j 1 1", "x"]);
    }
    send(&mut p, "PUB mark 1\r\nm\r\n");
    assert_eq!(
        [line(&mut far), line(&mut far)],
        ["MSG mark 2 1", "m"],
        "the hub's member got none"
    );
    drop(near);
    let deadline = Instant::now() + WAIT;
    far.get_mut()
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    loop {
        send(&mut p, "PUB j 4\r\nlast\r\n");
        let mut l = String::new();
        if far.read_line(&mut l).is_ok() && l.starts_with("MSG j 1 4") {
            break;
        }
        assert!(Instant::now() < deadline, "the hub's member got nothing");
    }
}

#[test]
fn a_leaf_gone_takes_its_interest_and_comes_back() {
    let h = hub("hub");
    let port = h.leafnode_addr().unwrap().port();
    let l = leaf("leaf", port);
    let _c = client(&l, "SUB gone 1\r\n");
    hears(&h, "gone");
    drop(l);
    leafz(&h, |z| z["leafnodes"] == 0);
    let l = leaf("again", port);
    let _c = client(&l, "SUB back 1\r\n");
    let z = leafz(&h, |z| subjects(z) == ["back"]);
    assert_eq!(z["leafs"][0]["name"], "again");
}

#[test]
fn a_leaf_links_again_to_a_hub_that_starts_again() {
    let port = free_port();
    let at = |name: &str| {
        Server::start(&Options {
            leafnodes: Some(Leafnodes {
                host: "127.0.0.1".into(),
                port,
                account: None,
            }),
            ..base(name)
        })
        .unwrap()
    };
    let h = at("first");
    let l = leaf("leaf", port);
    let mut near = client(&l, "SUB s 1\r\n");
    hears(&h, "s");
    drop(h);
    leafz(&l, |z| z["leafnodes"] == 0);
    let h = at("second");
    hears(&h, "s");
    let mut p = client(&h, "");
    until_heard(&mut p, &mut near, "s");
}

#[test]
fn a_leaf_binds_the_account_the_hub_gives() {
    let hub = Server::start(&Options {
        accounts: vec!["H".into()],
        leafnodes: Some(Leafnodes {
            host: "127.0.0.1".into(),
            port: 0,
            account: Some("H".into()),
        }),
        users: vec![naq::User {
            login: naq::Login::Password {
                user: "u".into(),
                password: "p".into(),
            },
            account: Some("H".into()),
            permissions: None,
        }],
        ..base("hub")
    })
    .unwrap();
    let spoke = Server::start(&Options {
        accounts: vec!["L".into()],
        remotes: vec![Remote {
            account: Some("L".into()),
            ..naq_remote(hub.leafnode_addr().unwrap().port())
        }],
        users: vec![naq::User {
            login: naq::Login::Password {
                user: "v".into(),
                password: "p".into(),
            },
            account: Some("L".into()),
            permissions: None,
        }],
        ..base("leaf")
    })
    .unwrap();
    let z = leafz(&hub, |z| z["leafnodes"] == 1);
    assert_eq!(z["leafs"][0]["account"], "H");
    let z = leafz(&spoke, |z| z["leafnodes"] == 1);
    assert_eq!(z["leafs"][0]["account"], "L");
    let user = |server: &Server, name: &str, ops: &str| {
        let mut c = TcpStream::connect(server.addr()).unwrap();
        c.set_read_timeout(Some(WAIT)).unwrap();
        write!(
            c,
            "CONNECT {{\"verbose\":false,\"user\":\"{name}\",\"pass\":\"p\"}}\r\n{ops}PING\r\n"
        )
        .unwrap();
        let mut r = BufReader::new(c);
        while line(&mut r) != "PONG" {}
        r
    };
    let mut at_hub = user(&hub, "u", "SUB x 1\r\n");
    hears(&spoke, "x");
    let mut p = user(&spoke, "v", "");
    until_heard(&mut p, &mut at_hub, "x");
}

/// Two servers of cluster `name`, each with `more` options, on fresh
/// ports, each with a route to the other.
fn pair(name: &str, more: impl Fn(usize) -> Options) -> Vec<Server> {
    let ports = [free_port(), free_port()];
    (0..2)
        .map(|i| {
            Server::start(&Options {
                cluster: Some(Cluster {
                    name: name.into(),
                    host: "127.0.0.1".into(),
                    port: ports[i],
                    routes: vec![format!("127.0.0.1:{}", ports[1 - i])],
                }),
                ..more(i)
            })
            .unwrap()
        })
        .collect()
}

#[test]
fn a_hub_cluster_keeps_the_interest_and_messages_of_a_leaf_cluster_from_itself() {
    // One lane each: what a hub sends a spoke keeps its order.
    let hubs = pair("h", |i| Options {
        leafnodes: Some(Leafnodes {
            host: "127.0.0.1".into(),
            port: 0,
            account: None,
        }),
        lanes: 1,
        ..base(&format!("h{i}"))
    });
    let ports: Vec<u16> = hubs
        .iter()
        .map(|h| h.leafnode_addr().unwrap().port())
        .collect();
    let spokes = pair("s", |i| Options {
        remotes: vec![naq_remote(ports[i])],
        ..base(&format!("s{i}"))
    });
    for s in &spokes {
        leafz(s, |z| z["leafnodes"] == 1);
    }
    let mut sub = client(&spokes[0], "SUB foo 1\r\nSUB bar 2\r\n");
    hears(&hubs[0], "foo");
    // After foo, from the same server: hub 1 tells spoke 1 of foo first,
    // if it does.
    let mut at_hub = client(&hubs[0], "SUB bar 1\r\n");
    hears(&spokes[1], "bar");
    let told = subjects(&get(&spokes[1], "/leafz?subs=1"));
    assert!(!told.contains(&"foo".to_owned()), "{told:?}");
    // Spoke 1 sends bar to spoke 0 itself, and through the hubs to the
    // client of hub 0, which does not hand it to spoke 0.
    let mut p = client(&spokes[1], "");
    until_heard(&mut p, &mut sub, "bar");
    until_heard(&mut p, &mut at_hub, "bar");
    send(&mut p, "PUB bar 3\r\none\r\n");
    while line(&mut at_hub) != "one" {}
    // Hub 0 got it: a copy it would hand spoke 0 comes before this.
    send(&mut at_hub, "PUB bar 4\r\nmark\r\n");
    let mut got = Vec::new();
    while !(got.contains(&"one".to_owned()) && got.contains(&"mark".to_owned())) {
        let l = line(&mut sub);
        if l == "one" || l == "mark" {
            got.push(l);
        }
    }
    got.sort();
    assert_eq!(got, ["mark", "one"], "each once");
}

#[test]
fn a_hub_cluster_carries_a_leaf_s_messages_to_its_other_servers_and_leafs() {
    let hubs = pair("h", |i| Options {
        leafnodes: Some(Leafnodes {
            host: "127.0.0.1".into(),
            port: 0,
            account: None,
        }),
        ..base(&format!("h{i}"))
    });
    let a = leaf("a", hubs[0].leafnode_addr().unwrap().port());
    let b = leaf("b", hubs[1].leafnode_addr().unwrap().port());
    let mut at_b = client(&b, "SUB t 1\r\n");
    let mut at_h0 = client(&hubs[0], "SUB t 1\r\n");
    hears(&a, "t");
    let mut p = client(&a, "");
    until_heard(&mut p, &mut at_b, "t");
    until_heard(&mut p, &mut at_h0, "t");
    let mut q = client(&b, "");
    until_heard(&mut q, &mut at_h0, "t");
}

/// The established TCP connections to `host` but to its `port`, by the
/// kernel: of the channels of a naq leaf to the lanes of a hub there.
#[cfg(target_os = "linux")]
fn channels_to(host: [u8; 4], port: u16) -> usize {
    const ESTABLISHED: &str = "01";
    // Little-endian, as the kernel prints it.
    let addr = format!("{:08X}", u32::from_le_bytes(host));
    std::fs::read_to_string("/proc/net/tcp")
        .unwrap()
        .lines()
        .skip(1)
        .filter(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (at, p) = f[2].split_once(':').unwrap();
            at == addr && u16::from_str_radix(p, 16).unwrap() != port && f[3] == ESTABLISHED
        })
        .count()
}

#[cfg(target_os = "linux")]
#[test]
fn a_leaf_closes_every_channel_of_a_hub_link_gone() {
    // A loopback address of its own: no other test dials it.
    const HOST: [u8; 4] = [127, 0, 0, 37];
    let host = std::net::Ipv4Addr::from(HOST).to_string();
    let h = Server::start(&Options {
        lanes: 4,
        leafnodes: Some(Leafnodes {
            host: host.clone(),
            port: 0,
            account: None,
        }),
        ..base("hub")
    })
    .unwrap();
    let port = h.leafnode_addr().unwrap().port();
    let proxy = Proxy::to(&host, port);
    // One lane: four channels, three of them only to take the hub's data.
    let l = Server::start(&Options {
        lanes: 1,
        remotes: vec![naq_remote(proxy.port)],
        ..base("leaf")
    })
    .unwrap();
    let channels = |n| {
        let deadline = Instant::now() + WAIT;
        while channels_to(HOST, port) != n {
            assert!(
                Instant::now() < deadline,
                "{} channels",
                channels_to(HOST, port)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    leafz(&h, |z| z["leafnodes"] == 1);
    channels(4);
    proxy.cut();
    leafz(&l, |z| z["leafnodes"] == 0);
    channels(0);
    proxy.set(OPEN);
    leafz(&l, |z| z["leafnodes"] == 1);
    channels(4);
    // The new channels carry what each lane of the hub sends: its clients
    // go to its lanes in turn.
    let mut sub = client(&l, "SUB s 1\r\n");
    hears(&h, "s");
    for _ in 0..4 {
        let mut p = client(&h, "");
        until_heard(&mut p, &mut sub, "s");
    }
}
