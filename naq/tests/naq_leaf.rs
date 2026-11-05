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
            ..Leafnodes::default()
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

/// The subjects `s`'s only link hears of, but loop detection ones.
fn subjects(z: &serde_json::Value) -> Vec<String> {
    z["leafs"][0]["subscriptions_list"]
        .as_array()
        .map(|l| {
            l.iter()
                .map(|s| s.as_str().unwrap().to_owned())
                .filter(|s| !s.starts_with("$LDS."))
                .collect()
        })
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
        assert_ne!(r.read_line(&mut l).unwrap(), 0, "closed");
    }
    r
}

/// The next line `c` gets, without its CRLF, but the server's pings. It
/// must not be closed.
fn line(c: &mut Client) -> String {
    loop {
        let mut l = String::new();
        assert_ne!(c.read_line(&mut l).unwrap(), 0, "closed");
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
fn each_side_of_a_link_tells_the_other_of_its_loop_detection_subject() {
    let (h, l) = linked();
    for s in [&h, &l] {
        leafz(s, |z| {
            let all = z["leafs"][0]["subscriptions_list"].as_array().unwrap();
            all.iter().any(|x| x.as_str().unwrap().starts_with("$LDS."))
        });
    }
}

#[test]
fn links_that_loop_are_let_go_and_wait() {
    let ports = [free_port(), free_port()];
    let proxy = Proxy::to("127.0.0.1", ports[0]);
    proxy.cut();
    let at = |i: usize, name: &str, hub: u16| {
        Server::start(&Options {
            leafnodes: Some(Leafnodes {
                host: "127.0.0.1".into(),
                port: ports[i],
                account: None,
                ..Leafnodes::default()
            }),
            remotes: vec![naq_remote(hub)],
            ..base(name)
        })
        .unwrap()
    };
    // A leaf of B; B a leaf of A, once the proxy lets it through.
    let a = at(0, "a", ports[1]);
    let b = at(1, "b", proxy.port);
    leafz(&a, |z| z["leafnodes"] == 1);
    leafz(&b, |z| z["leafnodes"] == 1);
    proxy.set(OPEN);
    let quiet = |s: &Server| {
        let deadline = Instant::now() + WAIT;
        let mut since = Instant::now();
        while since.elapsed() < Duration::from_secs(1) {
            if get(s, "/leafz")["leafnodes"] != 0 {
                since = Instant::now();
            }
            assert!(Instant::now() < deadline, "/leafz: {}", get(s, "/leafz"));
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    quiet(&a);
    quiet(&b);
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
                ..Leafnodes::default()
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
            ..Leafnodes::default()
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
        // Without users of its own for leafs, the hub's clients' stand in.
        remotes: vec![Remote {
            urls: vec![format!(
                "naq://u:p@127.0.0.1:{}",
                hub.leafnode_addr().unwrap().port()
            )],
            account: Some("L".into()),
            ..Remote::default()
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
            ..Leafnodes::default()
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
            ..Leafnodes::default()
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
            ..Leafnodes::default()
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

/// Waits until `f` holds of `s`'s `/leafz?subs=1`, for up to `wait`.
fn leafz_within(s: &Server, wait: Duration, f: impl Fn(&serde_json::Value) -> bool) {
    let deadline = Instant::now() + wait;
    while !f(&get(s, "/leafz?subs=1")) {
        assert!(Instant::now() < deadline, "/leafz: {}", get(s, "/leafz"));
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_leaf_dials_the_next_url_of_its_remote_where_one_fails() {
    let h = hub("hub");
    // Refuses the connection.
    let refused = free_port();
    // Takes it, and says nothing.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let l = Server::start(&Options {
        remotes: vec![Remote {
            urls: vec![
                format!("naq://127.0.0.1:{refused}"),
                format!("naq://127.0.0.1:{}", silent.local_addr().unwrap().port()),
                format!("naq://127.0.0.1:{}", h.leafnode_addr().unwrap().port()),
            ],
            no_randomize: true,
            ..Remote::default()
        }],
        ..base("leaf")
    })
    .unwrap();
    // Past the wait for the silent one's `Hello`.
    leafz_within(&h, 3 * WAIT, |z| z["leafnodes"] == 1);
    leafz(&l, |z| z["leafnodes"] == 1);
    // Shuffled, the URLs still all get their turn.
    let shuffled = Server::start(&Options {
        remotes: vec![Remote {
            urls: vec![
                format!("naq://127.0.0.1:{refused}"),
                format!("naq://127.0.0.1:{}", h.leafnode_addr().unwrap().port()),
            ],
            ..Remote::default()
        }],
        ..base("shuffled")
    })
    .unwrap();
    leafz(&shuffled, |z| z["leafnodes"] == 1);
}

#[test]
fn a_leaf_dials_the_servers_its_hub_s_cluster_told_of_once_its_hub_is_gone() {
    let mut hubs = pair("h", |i| Options {
        leafnodes: Some(Leafnodes {
            host: "127.0.0.1".into(),
            port: 0,
            account: None,
            ..Leafnodes::default()
        }),
        ..base(&format!("h{i}"))
    });
    let deadline = Instant::now() + WAIT;
    while hubs.iter().any(|h| get(h, "/routez")["num_routes"] != 1) {
        assert!(Instant::now() < deadline, "routes down");
        std::thread::sleep(Duration::from_millis(20));
    }
    // Only the first hub is configured.
    let l = leaf("leaf", hubs[0].leafnode_addr().unwrap().port());
    let mut sub = client(&l, "SUB s 1\r\n");
    hears(&hubs[0], "s");
    let other = hubs.pop().unwrap();
    drop(hubs);
    leafz_within(&other, 3 * WAIT, |z| z["leafnodes"] == 1);
    hears(&other, "s");
    let mut p = client(&other, "");
    until_heard(&mut p, &mut sub, "s");
}

/// A hub that takes naq leafs, which log in as `users`, beside the accounts
/// `A` and `B`, with `more`.
fn hub_with(users: Vec<naq::User>, more: Options) -> Server {
    Server::start(&Options {
        accounts: vec!["A".into(), "B".into()],
        leafnodes: Some(Leafnodes {
            host: "127.0.0.1".into(),
            port: 0,
            users,
            ..Leafnodes::default()
        }),
        ..more
    })
    .unwrap()
}

/// User `name` of `password`, into `account` or `$G`.
fn user(name: &str, password: &str, account: Option<&str>) -> naq::User {
    naq::User {
        login: naq::Login::Password {
            user: name.into(),
            password: password.into(),
        },
        account: account.map(Into::into),
        permissions: None,
    }
}

/// A leaf named `name` of `remote`.
fn leaf_of(name: &str, remote: Remote) -> Server {
    Server::start(&Options {
        remotes: vec![remote],
        ..base(name)
    })
    .unwrap()
}

/// A remote of the hub at `port` that logs in as `user` with `pass`, or
/// with the token `user` without one.
fn with_login(port: u16, user: &str, pass: Option<&str>) -> Remote {
    let login = pass.map_or(user.to_owned(), |p| format!("{user}:{p}"));
    Remote {
        urls: vec![format!("naq://{login}@127.0.0.1:{port}")],
        ..Remote::default()
    }
}

/// Asserts that `s` has `n` leaf links for a while.
fn stays_linked(s: &Server, n: u64) {
    let until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < until {
        assert_eq!(get(s, "/leafz")["leafnodes"], n, "{}", get(s, "/leafz"));
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn naq_leafs_log_in_as_the_users_of_the_leafnodes_block() {
    let key = nkeys::KeyPair::new_user();
    let hub = hub_with(
        vec![
            user("one", "pw", Some("A")),
            user("hashed", &bcrypt::hash("pw", 4).unwrap(), None),
            naq::User {
                login: naq::Login::Nkey(key.public_key()),
                account: Some("B".into()),
                permissions: None,
            },
        ],
        base("hub"),
    );
    let port = hub.leafnode_addr().unwrap().port();
    let _one = leaf_of("one", with_login(port, "one", Some("pw")));
    leafz(&hub, |z| {
        z["leafnodes"] == 1 && z["leafs"][0]["account"] == "A"
    });
    let _hashed = leaf_of("hashed", with_login(port, "hashed", Some("pw")));
    leafz(&hub, |z| z["leafnodes"] == 2);
    let _keyed = leaf_of(
        "keyed",
        Remote {
            nkey: Some(key.seed().unwrap()),
            ..naq_remote(port)
        },
    );
    let z = leafz(&hub, |z| z["leafnodes"] == 3);
    let mut accounts: Vec<&str> = (0..3)
        .map(|i| z["leafs"][i]["account"].as_str().unwrap())
        .collect();
    accounts.sort_unstable();
    assert_eq!(accounts, ["$G", "A", "B"]);
    for (name, remote) in [
        ("wrong", with_login(port, "one", Some("nope"))),
        ("nobody", naq_remote(port)),
        (
            "unknown key",
            Remote {
                nkey: Some(nkeys::KeyPair::new_user().seed().unwrap()),
                ..naq_remote(port)
            },
        ),
    ] {
        let refused = leaf_of(name, remote);
        stays_linked(&hub, 3);
        stays_linked(&refused, 0);
    }
}

#[test]
fn naq_leafs_log_in_as_clients_without_users_of_their_own() {
    let hub = hub_with(
        Vec::new(),
        Options {
            token: Some("s3cret".into()),
            ..base("hub")
        },
    );
    let port = hub.leafnode_addr().unwrap().port();
    let _with = leaf_of("with", with_login(port, "s3cret", None));
    leafz(&hub, |z| z["leafnodes"] == 1);
    let without = leaf_of("without", naq_remote(port));
    stays_linked(&without, 0);
}

/// A naq leaf of a hub, driven message by message over OMQ.
struct RawLeaf(omq_tokio::blocking::Socket);

impl RawLeaf {
    /// A leaf of routing identity `id`, on `ctx`, of the hub `hub`, that
    /// said `Hello`.
    fn new(ctx: &omq_tokio::Context, hub: &Server, id: &str) -> RawLeaf {
        let leaf = RawLeaf::dial(ctx, hub, id);
        leaf.hello();
        leaf
    }

    /// A leaf of routing identity `id`, on `ctx`, of the hub `hub`.
    fn dial(ctx: &omq_tokio::Context, hub: &Server, id: &str) -> RawLeaf {
        let s = ctx.blocking_socket(
            omq_tokio::SocketType::Dealer,
            omq_tokio::Options {
                identity: id.as_bytes().to_vec().into(),
                ..omq_tokio::Options::default()
            },
        );
        let at = hub.leafnode_addr().unwrap();
        s.connect(format!("tcp://{at}").as_str()).unwrap();
        RawLeaf(s)
    }

    /// Says `Hello`.
    fn hello(&self) {
        use naq_proto::peer::{Control, Hello, Role};
        self.send(Control::Hello(Hello {
            role: Role::Leaf,
            account: b"$G",
            epoch: 1,
            server_id: b"RAW",
            name: b"raw",
            cluster: b"",
            data: b"",
            client_urls: b"",
            leaf_urls: b"",
            nonce: b"",
        }));
    }

    fn send(&self, c: naq_proto::peer::Control<'_>) {
        let mut out = Vec::new();
        c.encode(&mut out);
        self.0.send(omq_tokio::Message::single(out)).unwrap();
    }

    /// The next message of the hub.
    fn next(&self) -> Vec<u8> {
        self.0
            .recv_timeout(WAIT)
            .unwrap()
            .into_bytes()
            .unwrap()
            .to_vec()
    }
}

#[test]
fn a_naq_leaf_that_does_not_log_in_is_told_why() {
    use naq_proto::peer::{self, Connect, Control, Role};
    let hub = hub_with(vec![user("u", "p", None)], base("hub"));
    let ctx = omq_tokio::Context::new();
    let wrong = RawLeaf::new(&ctx, &hub, "RAW/0/1");
    let got = wrong.next();
    let Ok(Control::Hello(h)) = peer::decode(&got) else {
        panic!("{got:?}")
    };
    assert_eq!((h.role, h.nonce.len()), (Role::Hub, 15), "a nonce to sign");
    wrong.send(Control::Connect(Connect {
        user: b"u",
        pass: b"x",
        ..Connect::default()
    }));
    let got = wrong.next();
    assert_eq!(
        peer::decode(&got),
        Ok(Control::Error(b"Authorization Violation"))
    );
    // A `Connect` before the hub's `Hello` counts for nothing.
    let late = RawLeaf::dial(&ctx, &hub, "RAW/0/2");
    late.send(Control::Connect(Connect::default()));
    late.hello();
    assert!(matches!(peer::decode(&late.next()), Ok(Control::Hello(_))));
    let got = late.next();
    assert_eq!(
        peer::decode(&got),
        Ok(Control::Error(b"Authentication Timeout"))
    );
}

#[test]
fn users_of_naq_leafs_that_cannot_work_are_refused() {
    let with = |u: naq::User| {
        Server::start(&Options {
            leafnodes: Some(Leafnodes {
                users: vec![u],
                ..Leafnodes::default()
            }),
            ..base("hub")
        })
        .err()
        .map(|e| e.to_string())
    };
    let limited = naq::User {
        permissions: Some(naq::Permissions::default()),
        ..user("u", "p", None)
    };
    let e = with(limited).unwrap();
    assert!(e.contains("users of leafs have no permissions"), "{e}");
    let e = with(naq::User {
        login: naq::Login::Nkey("Ux".into()),
        ..user("u", "p", None)
    })
    .unwrap();
    assert!(e.contains("is not a public user NKey"), "{e}");
}

/// Reads `c` until `last`; none of the lines before is `never`.
fn until_line(c: &mut Client, last: &str, never: &str) {
    loop {
        let l = line(c);
        assert_ne!(l, never, "got what should stay away");
        if l == last {
            return;
        }
    }
}

#[test]
fn the_deny_rules_of_a_naq_leaf_hold_both_ways() {
    let h = hub("hub");
    let l = leaf_of(
        "leaf",
        Remote {
            deny_exports: vec!["secret.>".into()],
            deny_imports: vec!["private".into()],
            ..naq_remote(h.leafnode_addr().unwrap().port())
        },
    );
    leafz(&h, |z| z["leafnodes"] == 1);
    // Out: the hub's literal interest in what the leaf may not send does
    // not count, and its wildcard interest gets none of it.
    let mut at_hub = client(&h, "SUB secret.x 1\r\nSUB secret.* 2\r\nSUB open 3\r\n");
    hears(&l, "open");
    hears(&l, "secret.*");
    let told = subjects(&get(&l, "/leafz?subs=1"));
    assert!(!told.contains(&"secret.x".to_owned()), "{told:?}");
    let mut p = client(&l, "");
    until_heard(&mut p, &mut at_hub, "open");
    send(&mut p, "PUB secret.x 2\r\nno\r\nPUB open 4\r\nmark\r\n");
    until_line(&mut at_hub, "mark", "no");
    // In: the hub hears of no interest in what the leaf takes nothing on,
    // and sends none of it to its wildcard interest.
    let mut at_leaf = client(&l, "SUB private 1\r\nSUB > 2\r\n");
    hears(&h, ">");
    let told = subjects(&get(&h, "/leafz?subs=1"));
    assert!(!told.contains(&"private".to_owned()), "{told:?}");
    let mut q = client(&h, "");
    until_heard(&mut q, &mut at_leaf, "open");
    send(&mut q, "PUB private 2\r\nno\r\nPUB open 4\r\nmark\r\n");
    until_line(&mut at_leaf, "mark", "no");
}

#[test]
fn the_permissions_of_a_leaf_s_user_hold_on_its_naq_link() {
    let limited = naq::User {
        permissions: Some(naq::Permissions {
            publish: naq::Rules {
                allow: Some(vec!["up.>".into()]),
                deny: vec!["up.secret".into()],
            },
            subscribe: naq::Rules {
                allow: Some(vec!["down.>".into()]),
                deny: Vec::new(),
            },
            responses: None,
        }),
        ..user("u", "p", None)
    };
    let h = hub_with(
        Vec::new(),
        Options {
            users: vec![limited, user("admin", "p", None)],
            ..base("hub")
        },
    );
    let admin = "{\"verbose\":false,\"user\":\"admin\",\"pass\":\"p\"}";
    let l = leaf_of(
        "leaf",
        with_login(h.leafnode_addr().unwrap().port(), "u", Some("p")),
    );
    leafz(&h, |z| z["leafnodes"] == 1);
    // The leaf hears of interest only where its user may publish, and
    // sends only there.
    let mut at_hub = client_with(&h, admin, "SUB up.a 1\r\nSUB down.b 2\r\n");
    hears(&l, "up.a");
    assert_eq!(subjects(&get(&l, "/leafz?subs=1")), ["up.a"]);
    let mut p = client(&l, "");
    until_heard(&mut p, &mut at_hub, "up.a");
    // The leaf sends to the hub's wildcard interest what its user may not
    // publish: the hub drops it.
    let mut wide = client_with(&h, admin, "SUB up.* 1\r\n");
    hears(&l, "up.*");
    until_heard(&mut p, &mut wide, "up.a");
    send(&mut p, "PUB up.secret 2\r\nno\r\nPUB up.a 4\r\nmark\r\n");
    until_line(&mut wide, "mark", "no");
    // The hub takes the leaf's interest only where its user may
    // subscribe, and sends only there.
    let mut at_leaf = client(&l, "SUB down.c 1\r\nSUB side.d 2\r\nSUB *.e 3\r\n");
    hears(&h, "*.e");
    let mut told = subjects(&get(&h, "/leafz?subs=1"));
    told.sort();
    assert_eq!(told, ["*.e", "down.c"]);
    let mut q = client_with(&h, admin, "");
    until_heard(&mut q, &mut at_leaf, "down.c");
    send(&mut q, "PUB side.e 2\r\nno\r\nPUB down.e 4\r\nmark\r\n");
    until_line(&mut at_leaf, "mark", "no");
}

#[test]
fn an_isolated_naq_leaf_hears_of_no_interest_of_other_leafs() {
    let hubs = pair("h", |i| Options {
        leafnodes: Some(Leafnodes {
            host: "127.0.0.1".into(),
            port: 0,
            ..Leafnodes::default()
        }),
        ..base(&format!("h{i}"))
    });
    let port = |i: usize| hubs[i].leafnode_addr().unwrap().port();
    let alone = leaf_of(
        "alone",
        Remote {
            request_isolation: true,
            ..naq_remote(port(0))
        },
    );
    let near = leaf("near", port(0));
    let far = leaf("far", port(1));
    let z = leafz(&hubs[0], |z| z["leafnodes"] == 2);
    let isolated: Vec<_> = (0..2).map(|i| &z["leafs"][i]["is_isolated"]).collect();
    assert!(isolated.contains(&&serde_json::Value::Bool(true)), "{z}");
    let z = leafz(&alone, |z| z["leafnodes"] == 1);
    assert_eq!(z["leafs"][0]["is_isolated"], true);
    let _subs = [
        client(&near, "SUB near 1\r\n"),
        client(&far, "SUB far 1\r\n"),
        client(&hubs[1], "SUB route 1\r\n"),
        client(&hubs[0], "SUB here 1\r\n"),
    ];
    hears(&alone, "here");
    hears(&alone, "route");
    hears(&far, "near");
    let mut told = subjects(&get(&alone, "/leafz?subs=1"));
    told.sort();
    assert_eq!(told, ["here", "route"]);
}

#[test]
fn leafz_counts_the_messages_of_naq_links() {
    let (h, l) = linked();
    let mut at_hub = client(&h, "SUB up 1\r\n");
    let mut at_leaf = client(&l, "SUB down 1\r\n");
    let mut up = client(&l, "");
    let mut down = client(&h, "");
    until_heard(&mut up, &mut at_hub, "up");
    until_heard(&mut down, &mut at_leaf, "down");
    let counts = |s: &Server| {
        let leafz = get(s, "/leafz");
        let n = |k: &str| leafz["leafs"][0][k].as_u64().unwrap();
        [n("in_msgs"), n("in_bytes"), n("out_msgs"), n("out_bytes")]
    };
    let (hub0, leaf0) = (counts(&h), counts(&l));
    for _ in 0..10 {
        send(&mut up, "PUB up 5\r\nhello\r\n");
    }
    for _ in 0..3 {
        send(&mut down, "PUB down 2\r\nhi\r\n");
    }
    for _ in 0..10 {
        assert_eq!(line(&mut at_hub), "MSG up 1 5");
        line(&mut at_hub);
    }
    for _ in 0..3 {
        assert_eq!(line(&mut at_leaf), "MSG down 1 2");
        line(&mut at_leaf);
    }
    let delta = |now: [u64; 4], was: [u64; 4]| [0, 1, 2, 3].map(|i| now[i] - was[i]);
    assert_eq!(delta(counts(&h), hub0), [10, 50, 3, 6], "in, then out");
    assert_eq!(delta(counts(&l), leaf0), [3, 6, 10, 50]);
}

#[test]
fn a_queue_group_takes_a_member_a_route_has_for_a_leaf_only_without_another() {
    let hubs = pair("h", |i| Options {
        leafnodes: Some(Leafnodes {
            host: "127.0.0.1".into(),
            port: 0,
            ..Leafnodes::default()
        }),
        ..base(&format!("h{i}"))
    });
    let deadline = Instant::now() + WAIT;
    while hubs.iter().any(|h| get(h, "/routez")["num_routes"] != 1) {
        assert!(Instant::now() < deadline, "routes down");
        std::thread::sleep(Duration::from_millis(20));
    }
    let l = leaf("leaf", hubs[1].leafnode_addr().unwrap().port());
    let mut far = client(&l, "SUB j q 1\r\nSUB mark 2\r\n");
    hears(&hubs[1], "j");
    let mut near = client(&hubs[0], "SUB j q 1\r\n");
    // Hub 0 hears of the leaf's interest from hub 1.
    let detail = || get(&hubs[0], "/routez?subs=detail").to_string();
    let deadline = Instant::now() + WAIT;
    while !(detail().contains("\"qgroup\":\"q\"") && detail().contains("\"subject\":\"mark\"")) {
        assert!(Instant::now() < deadline, "{}", detail());
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut p = client(&hubs[0], "");
    for _ in 0..50 {
        send(&mut p, "PUB j 1\r\nx\r\n");
    }
    for _ in 0..50 {
        assert_eq!(line(&mut near), "MSG j 1 1");
        line(&mut near);
    }
    // None went to the leaf.
    send(&mut p, "PUB mark 1\r\nm\r\n");
    assert_eq!(line(&mut far), "MSG mark 2 1");
    send(&mut near, "UNSUB 1\r\nPING\r\n");
    while line(&mut near) != "PONG" {}
    until_heard(&mut p, &mut far, "j");
}
