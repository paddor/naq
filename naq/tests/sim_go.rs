//! A seeded random simulation of naq leafs of a `nats-server` hub, when
//! `NAQ_GO` names one, each link through a proxy. A link is cut and comes
//! back; a leaf or the hub starts again. Once quiet, the hub heard of each
//! leaf linked to it the interest of its clients, and each such leaf of
//! the interest of the hub's clients and other leafs. See `sim/world.rs`.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use naq::{Options, Remote, Server};

#[path = "mesh/cluster.rs"]
mod cluster;
mod proxy;
#[path = "sim/world.rs"]
mod world;

use cluster::{WAIT, free_port, get};
use proxy::{OPEN, Proxy};
use world::{Links, Peer, Rng, Sim, World, links, subjects};

/// Leaf `k` is server `1 + k`; the hub is server 0.
const LEAFS: usize = 3;
/// The services each account of the hub imports of its system account:
/// it tells its leafs of them.
const IMPORTED: &[&str] = &[
    "$SYS.REQ.ACCOUNT.PING.CONNZ",
    "$SYS.REQ.ACCOUNT.PING.STATZ",
    "$SYS.REQ.SERVER.PING.CONNZ",
    "$SYS.REQ.USER.INFO",
];

/// `nats-server`, killed when dropped. A failing test shows its log.
struct Go {
    child: Child,
    dir: PathBuf,
}

impl Drop for Go {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking()
            && let Ok(log) = std::fs::read_to_string(self.dir.join("hub.log"))
        {
            eprintln!("hub log:\n{log}");
        }
    }
}

/// `GET path` on port `http` of 127.0.0.1, once it answers.
fn go_get(http: u16, path: &str) -> serde_json::Value {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", http)) {
            s.set_read_timeout(Some(WAIT)).unwrap();
            write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
            let mut body = String::new();
            s.read_to_string(&mut body).unwrap();
            if let Some((_, json)) = body.split_once("\r\n\r\n") {
                return serde_json::from_str(json).unwrap();
            }
        }
        assert!(Instant::now() < deadline, "no answer on {http}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The hub, its leafs, and the links cut.
struct GoHub {
    bin: PathBuf,
    dir: PathBuf,
    /// Its client, monitoring and leaf node ports.
    ports: [u16; 3],
    hub: Option<Go>,
    leafs: Vec<Option<Server>>,
    /// Leaf `k`'s link to the hub.
    proxies: Vec<Proxy>,
    cut: [bool; LEAFS],
}

impl GoHub {
    fn new(bin: PathBuf, seed: u64) -> GoHub {
        let ports = [free_port(), free_port(), free_port()];
        let dir = std::env::temp_dir().join(format!("naq-sim-go-{}-{seed}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut w = GoHub {
            bin,
            dir,
            ports,
            hub: None,
            leafs: (0..LEAFS).map(|_| None).collect(),
            proxies: (0..LEAFS)
                .map(|_| Proxy::to("127.0.0.1", ports[2]))
                .collect(),
            cut: [false; LEAFS],
        };
        w.start_hub();
        for k in 0..LEAFS {
            w.start_leaf(k);
        }
        w
    }

    /// Starts the hub, and waits until it takes clients. It tells leafs
    /// of no URLs: they dial theirs, through their proxy.
    fn start_hub(&mut self) {
        let [port, http, leaf] = self.ports;
        let conf = format!(
            "server_name: g\nlisten: 127.0.0.1:{port}\nhttp: 127.0.0.1:{http}\n\
             leafnodes {{ listen: 127.0.0.1:{leaf}, no_advertise: true }}\n"
        );
        let path = self.dir.join("hub.conf");
        std::fs::write(&path, conf).unwrap();
        let log = std::fs::File::create(self.dir.join("hub.log")).unwrap();
        let child = Command::new(&self.bin)
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        self.hub = Some(Go {
            child,
            dir: self.dir.clone(),
        });
        let deadline = Instant::now() + WAIT;
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "no hub on {port}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn start_leaf(&mut self, k: usize) {
        let o = Options {
            host: "127.0.0.1".into(),
            port: 0,
            lanes: 2,
            http_port: Some(0),
            server_name: format!("l{k}"),
            leaf_reconnect: Duration::from_millis(50),
            remotes: vec![Remote {
                urls: vec![format!("nats-leaf://127.0.0.1:{}", self.proxies[k].port)],
                ..Remote::default()
            }],
            ..Options::default()
        };
        self.leafs[k] = Some(Server::start(&o).unwrap());
    }

    /// Whether leaf `k` links to the hub, once quiet.
    fn linked(&self, k: usize) -> bool {
        self.hub.is_some() && self.leafs[k].is_some() && !self.cut[k]
    }

    /// The part of the world server `s` is in.
    fn part(&self, s: usize) -> usize {
        if s == 0 || self.linked(s - 1) { 0 } else { s }
    }

    /// What is not as quiet would have it, if anything.
    fn wrong(&self, clients: &[Peer]) -> Option<String> {
        for (k, l) in self.leafs.iter().enumerate() {
            let Some(l) = l else { continue };
            let mut got = links(&get(l, "/leafz?subs=1"));
            for (_, subs) in &mut got {
                subs.retain(|s| !IMPORTED.contains(&s.as_str()));
            }
            let s = 1 + k;
            let others = clients
                .iter()
                .filter(|c| c.server != s && self.reach(s, c.server));
            let want: Links = if self.linked(k) {
                vec![("g".into(), subjects(others))]
            } else {
                Vec::new()
            };
            if got != want {
                return Some(format!("l{k} heard {got:?}, not {want:?}"));
            }
        }
        self.hub.as_ref()?;
        let got = links(&go_get(self.ports[1], "/leafz?subs=1"));
        let want: Links = (0..LEAFS)
            .filter(|&k| self.linked(k))
            .map(|k| {
                let mine = clients.iter().filter(|c| c.server == 1 + k);
                (format!("l{k}"), subjects(mine))
            })
            .collect();
        (got != want).then(|| format!("the hub heard of its leafs {got:?}, not {want:?}"))
    }
}

impl World for GoHub {
    fn addrs(&self) -> Vec<Option<SocketAddr>> {
        let hub = self
            .hub
            .as_ref()
            .map(|_| SocketAddr::from(([127, 0, 0, 1], self.ports[0])));
        std::iter::once(hub)
            .chain(self.leafs.iter().map(|l| l.as_ref().map(Server::addr)))
            .collect()
    }

    fn quiet(&mut self, clients: &[Peer]) {
        let deadline = Instant::now() + WAIT;
        loop {
            let Some(wrong) = self.wrong(clients) else {
                return;
            };
            assert!(Instant::now() < deadline, "{wrong}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn reach(&self, i: usize, j: usize) -> bool {
        self.part(i) == self.part(j)
    }

    /// A link is cut or back, or a leaf or the hub stops or starts again.
    fn change(&mut self, rng: &mut Rng) -> (String, Option<usize>) {
        let n = rng.below(10);
        if n < 4 {
            let k = rng.below(LEAFS);
            self.cut[k] = !self.cut[k];
            if self.cut[k] {
                self.proxies[k].cut();
                return (format!("link of l{k} cut"), None);
            }
            self.proxies[k].set(OPEN);
            return (format!("link of l{k} back"), None);
        }
        if n < 8 {
            let k = rng.below(LEAFS);
            if self.leafs[k].take().is_some() {
                return (format!("l{k} stops"), Some(1 + k));
            }
            self.start_leaf(k);
            return (format!("l{k} starts again"), None);
        }
        if self.hub.take().is_some() {
            return ("the hub stops".into(), Some(0));
        }
        self.start_hub();
        ("the hub starts again".into(), None)
    }

    fn heal(&mut self) {
        for k in 0..LEAFS {
            if std::mem::take(&mut self.cut[k]) {
                self.proxies[k].set(OPEN);
            }
            if self.leafs[k].is_none() {
                self.start_leaf(k);
            }
        }
        if self.hub.is_none() {
            self.start_hub();
        }
    }
}

impl Drop for GoHub {
    fn drop(&mut self) {
        self.hub = None;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Runs seed `seed` against `nats-server` from `NAQ_GO`, if set.
fn run(seed: u64) {
    let Some(bin) = std::env::var_os("NAQ_GO") else {
        eprintln!("skipped: NAQ_GO is not set");
        return;
    };
    Sim::new(seed, GoHub::new(bin.into(), seed)).run();
}

#[test]
fn leafs_of_a_go_hub_hold_their_interest_and_deliveries_through_random_steps() {
    run(1);
}

#[test]
fn leafs_of_a_go_hub_hold_through_other_random_steps() {
    run(2);
}

#[test]
fn leafs_of_a_go_hub_hold_through_yet_other_random_steps() {
    run(3);
}
