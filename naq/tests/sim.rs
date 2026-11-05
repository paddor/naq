//! A seeded random simulation of a cluster of three whose routes go
//! through proxies. Clients come and go and subscribe and unsubscribe,
//! in queue groups too; a server is cut off, loudly or silently, and
//! comes back; a server starts again. Once quiet, each server heard of
//! each other one the interest its clients hold, and a message reaches
//! each subscription once and each queue group once, among the servers
//! that reach each other.
//!
//! `NAQ_SIM_SEED` runs a seed of choice, `NAQ_SIM_STEPS` sets the steps.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use naq::Server;

#[path = "mesh/cluster.rs"]
mod cluster;
mod proxy;

use cluster::{Told, WAIT, node, proxied, quiet};
use proxy::{BLACKHOLE, CUT, OPEN, Proxy};

/// xorshift64*, so a failure replays from its seed.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    const fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    const fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// What clients subscribe to. None matches a fence subject, `fence.N`.
const FILTERS: &[&str] = &[
    "a", "b", "a.b", "a.c", "x.y.z", "*", "a.*", "*.b", "a.>", "x.*.z", "x.>",
];
/// What a publisher sends to.
const SUBJECTS: &[&str] = &["a", "b", "c", "a.b", "a.c", "c.b", "x.y.z", "x.q"];
/// Mostly plain subscriptions.
const QUEUES: &[Option<&str>] = &[None, None, None, Some("q"), Some("r")];

/// Whether `filter` matches `subject`.
fn matches(filter: &str, subject: &str) -> bool {
    let (mut f, mut s) = (filter.split('.'), subject.split('.'));
    loop {
        match (f.next(), s.next()) {
            (Some(">"), Some(_)) | (None, None) => return true,
            (Some(a), Some(b)) if a == "*" || a == b => {}
            _ => return false,
        }
    }
}

/// A subscription: its SID, filter and queue group.
type Sub = (u32, String, Option<&'static str>);

/// A client of server `server`, read line by line.
struct Peer {
    server: usize,
    r: BufReader<TcpStream>,
    /// What a read cut short holds.
    pending: String,
    subs: Vec<Sub>,
    next_sid: u32,
}

impl Peer {
    fn new(server: usize, s: &Server) -> Peer {
        let w = TcpStream::connect(s.addr()).unwrap();
        let mut p = Peer {
            server,
            r: BufReader::new(w),
            pending: String::new(),
            subs: Vec::new(),
            next_sid: 1,
        };
        p.send("CONNECT {\"verbose\":false}\r\n");
        p.synced();
        p
    }

    fn send(&mut self, s: &str) {
        self.r.get_mut().write_all(s.as_bytes()).unwrap();
    }

    /// The next line within `wait`, past `PING`s, which get their `PONG`,
    /// and `INFO`s, which tell of the cluster.
    fn next_line(&mut self, wait: Duration) -> Option<String> {
        self.r.get_ref().set_read_timeout(Some(wait)).unwrap();
        loop {
            match self.r.read_line(&mut self.pending) {
                Ok(0) => {
                    assert!(self.pending.is_empty(), "closed: {:?}", self.pending);
                    unreachable!("closed by server {}", self.server);
                }
                Ok(_) if self.pending.ends_with('\n') => {
                    let l = std::mem::take(&mut self.pending);
                    let l = l.trim_end_matches(['\r', '\n']);
                    if l == "PING" {
                        self.send("PONG\r\n");
                    } else if !l.starts_with("INFO ") {
                        return Some(l.to_owned());
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    let kind = e.kind();
                    assert!(
                        matches!(
                            kind,
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ),
                        "{e}"
                    );
                    return None;
                }
            }
        }
    }

    fn line(&mut self) -> String {
        let Some(l) = self.next_line(WAIT) else {
            unreachable!("no line in time from server {}", self.server)
        };
        l
    }

    /// The next message: its subject, SID and payload.
    fn msg(&mut self, wait: Duration) -> Option<(String, u32, String)> {
        let head = self.next_line(wait)?;
        let words: Vec<&str> = head.split(' ').collect();
        assert!(
            words.len() == 4 && words[0] == "MSG",
            "not a message: {head}"
        );
        let payload = self.line();
        Some((words[1].to_owned(), words[2].parse().unwrap(), payload))
    }

    /// Waits until the server took what it was sent; messages that came
    /// meanwhile are given back.
    fn synced(&mut self) -> Vec<(String, u32, String)> {
        self.send("PING\r\n");
        let mut got = Vec::new();
        loop {
            let l = self.line();
            if l == "PONG" {
                return got;
            }
            let words: Vec<&str> = l.split(' ').collect();
            assert!(
                words.len() == 4 && words[0] == "MSG",
                "server {}: {l}",
                self.server
            );
            got.push((words[1].to_owned(), words[2].parse().unwrap(), self.line()));
        }
    }

    fn subscribe(&mut self, filter: &str, queue: Option<&'static str>) -> u32 {
        let sid = self.next_sid;
        self.next_sid += 1;
        let q = queue.map_or(String::new(), |q| format!(" {q}"));
        self.send(&format!("SUB {filter}{q} {sid}\r\n"));
        self.subs.push((sid, filter.to_owned(), queue));
        sid
    }

    fn unsubscribe(&mut self, sid: u32) {
        self.send(&format!("UNSUB {sid}\r\n"));
        self.subs.retain(|s| s.0 != sid);
    }
}

/// The cluster, its clients, and what was done to them.
struct Sim {
    seed: u64,
    rng: Rng,
    ports: Vec<u16>,
    proxies: Vec<Vec<Option<Proxy>>>,
    servers: Vec<Option<Server>>,
    clients: Vec<Peer>,
    /// The server cut off from the others, and how.
    apart: Option<(usize, u8)>,
    /// Checks so far: each has a fence subject of its own.
    checks: u32,
}

impl Sim {
    fn new(seed: u64) -> Sim {
        let (servers, proxies) = proxied();
        let ports = servers
            .iter()
            .map(|s| s.cluster_addr().unwrap().port())
            .collect();
        Sim {
            seed,
            // Never 0: xorshift would stay there.
            rng: Rng(seed | 1 << 63),
            ports,
            proxies,
            servers: servers.into_iter().map(Some).collect(),
            clients: Vec::new(),
            apart: None,
            checks: 0,
        }
    }

    fn note(&self, what: &str) {
        eprintln!("seed {}: {what}", self.seed);
    }

    fn up(&self) -> Vec<usize> {
        (0..self.servers.len())
            .filter(|&i| self.servers[i].is_some())
            .collect()
    }

    /// Whether the partition keeps servers `i` and `j` apart.
    fn kept_apart(&self, i: usize, j: usize) -> bool {
        self.apart.is_some_and(|(k, _)| (i == k) != (j == k))
    }

    /// What server `i`'s clients ask for, as the others hear of it.
    fn told(&self, i: usize) -> Vec<Told> {
        let mut plain = std::collections::BTreeSet::new();
        let mut groups = std::collections::BTreeMap::new();
        for (_, f, q) in self
            .clients
            .iter()
            .filter(|c| c.server == i)
            .flat_map(|c| &c.subs)
        {
            match q {
                None => drop(plain.insert(f.clone())),
                Some(q) => *groups.entry((f.clone(), *q)).or_insert(0) += 1,
            }
        }
        let mut all: Vec<Told> = plain.into_iter().map(|f| (f, None, 1)).collect();
        all.extend(
            groups
                .into_iter()
                .map(|((f, q), n)| (f, Some(q.to_owned()), n)),
        );
        all.sort();
        all
    }

    /// The oracle once quiet: each server heard of each other one what its
    /// clients hold, unless kept apart.
    fn quiet(&self) {
        let up: Vec<Option<&Server>> = self.servers.iter().map(Option::as_ref).collect();
        let want: Vec<Vec<Told>> = (0..self.servers.len()).map(|i| self.told(i)).collect();
        quiet(&up, |i, j| self.kept_apart(i, j), &want);
    }
}

/// The steps a simulation takes.
impl Sim {
    fn connect(&mut self, server: usize) -> usize {
        let s = self.servers[server].as_ref().unwrap();
        self.clients.push(Peer::new(server, s));
        self.clients.len() - 1
    }

    /// A client, new or not, subscribes.
    fn subscribe(&mut self) {
        let up = self.up();
        let Some(&server) = (!up.is_empty()).then(|| self.rng.pick(&up)) else {
            return;
        };
        let mine: Vec<usize> = (0..self.clients.len())
            .filter(|&c| self.clients[c].server == server)
            .collect();
        let c = if mine.is_empty() || self.rng.below(4) == 0 {
            self.connect(server)
        } else {
            *self.rng.pick(&mine)
        };
        let (filter, queue) = (*self.rng.pick(FILTERS), *self.rng.pick(QUEUES));
        self.note(&format!("client {c} at {server}: SUB {filter} {queue:?}"));
        self.clients[c].subscribe(filter, queue);
        let got = self.clients[c].synced();
        assert!(got.is_empty(), "seed {}: {got:?}", self.seed);
    }

    fn unsubscribe(&mut self) {
        let with: Vec<usize> = (0..self.clients.len())
            .filter(|&c| !self.clients[c].subs.is_empty())
            .collect();
        let Some(&c) = (!with.is_empty()).then(|| self.rng.pick(&with)) else {
            return;
        };
        let at = self.rng.below(self.clients[c].subs.len());
        let sid = self.clients[c].subs[at].0;
        self.note(&format!("client {c}: UNSUB {sid}"));
        self.clients[c].unsubscribe(sid);
        let got = self.clients[c].synced();
        assert!(got.is_empty(), "seed {}: {got:?}", self.seed);
    }

    fn disconnect(&mut self) {
        if !self.clients.is_empty() {
            let c = self.rng.below(self.clients.len());
            self.note(&format!("client {c} goes"));
            self.clients.remove(c);
        }
    }

    /// Sets every proxy between server `k` and the others to `state`.
    fn isolate(&self, k: usize, state: u8) {
        for j in (0..self.servers.len()).filter(|&j| j != k) {
            for p in [&self.proxies[k][j], &self.proxies[j][k]] {
                let p = p.as_ref().unwrap();
                if state == CUT {
                    p.cut();
                } else {
                    p.set(state);
                }
            }
        }
    }

    fn partition_or_heal(&mut self) {
        if let Some((k, _)) = self.apart.take() {
            self.note(&format!("server {k} back"));
            self.isolate(k, OPEN);
        } else {
            let k = self.rng.below(self.servers.len());
            let state = *self.rng.pick(&[CUT, BLACKHOLE]);
            self.note(&format!("server {k} cut off, state {state}"));
            self.isolate(k, state);
            self.apart = Some((k, state));
        }
    }

    /// A server stops, or one that stopped starts again.
    fn restart(&mut self) {
        let k = self.rng.below(self.servers.len());
        if self.servers[k].take().is_some() {
            self.note(&format!("server {k} stops"));
            self.clients.retain(|c| c.server != k);
        } else {
            self.note(&format!("server {k} starts again"));
            let routes: Vec<u16> = self.proxies[k].iter().flatten().map(|p| p.port).collect();
            self.servers[k] = Some(node(k, self.ports[k], &routes));
        }
    }
}

/// Messages, and the oracle of what reaches whom.
impl Sim {
    /// Once quiet, a client publishes; each client the publisher's server
    /// reaches gets what its subscriptions match, once each, and each
    /// queue group gets one pick.
    fn check(&mut self) {
        let up = self.up();
        if up.is_empty() {
            return;
        }
        let server = *self.rng.pick(&up);
        let publisher = self.connect(server);
        let readers: Vec<usize> = (0..self.clients.len())
            .filter(|&c| !self.kept_apart(server, self.clients[c].server))
            .collect();
        self.checks += 1;
        let fence = format!("fence.{}", self.checks);
        let sids: Vec<u32> = readers
            .iter()
            .map(|&c| {
                let sid = self.clients[c].subscribe(&fence, None);
                assert!(self.clients[c].synced().is_empty(), "seed {}", self.seed);
                sid
            })
            .collect();
        self.quiet();
        self.warm(publisher, &fence, &readers);
        let subjects: Vec<&str> = (0..4).map(|_| *self.rng.pick(SUBJECTS)).collect();
        self.note(&format!("server {server} publishes to {subjects:?}"));
        let p = &mut self.clients[publisher];
        for (n, s) in subjects.iter().enumerate() {
            p.send(&format!("PUB {s} 1\r\n{n}\r\n"));
        }
        p.send(&format!("PUB {fence} 3\r\nend\r\n"));
        let got = self.collect(&fence, &readers, &sids);
        self.expect(&subjects, &readers, &got);
        for (&c, &sid) in readers.iter().zip(&sids) {
            self.clients[c].unsubscribe(sid);
            assert!(self.clients[c].synced().is_empty(), "seed {}", self.seed);
        }
    }

    /// Publishes to `fence` from `publisher` until each of `readers` got
    /// it: the publisher's lane heard of all their interest by then.
    fn warm(&mut self, publisher: usize, fence: &str, readers: &[usize]) {
        let mut waiting: Vec<usize> = readers.to_vec();
        let deadline = Instant::now() + WAIT;
        while !waiting.is_empty() {
            assert!(
                Instant::now() < deadline,
                "seed {}: no fence at {waiting:?}",
                self.seed
            );
            self.clients[publisher].send(&format!("PUB {fence} 1\r\nw\r\n"));
            let clients = &mut self.clients;
            waiting.retain(|&c| {
                let got = clients[c].msg(Duration::from_millis(50));
                got.is_none_or(|(s, _, _)| s != fence)
            });
        }
    }

    /// What `readers` got, by reader, until their fence's `end`, and up to
    /// a `PONG` after it.
    fn collect(
        &mut self,
        fence: &str,
        readers: &[usize],
        sids: &[u32],
    ) -> Vec<Vec<(String, u32, String)>> {
        let mut all = Vec::new();
        for (&c, &sid) in readers.iter().zip(sids) {
            let mut got = Vec::new();
            loop {
                let m = self.clients[c].msg(WAIT);
                let (subject, at, payload) =
                    m.unwrap_or_else(|| unreachable!("seed {}: no end at {c}", self.seed));
                if subject == fence {
                    if payload == "end" && at == sid {
                        break;
                    }
                    continue;
                }
                got.push((subject, at, payload));
            }
            got.extend(self.clients[c].synced());
            all.push(got);
        }
        all
    }

    /// Checks that `got`, by reader, is what the subscriptions of
    /// `readers` match of `subjects`.
    fn expect(&self, subjects: &[&str], readers: &[usize], got: &[Vec<(String, u32, String)>]) {
        for (n, s) in subjects.iter().enumerate() {
            let payload = n.to_string();
            let mut groups = std::collections::BTreeMap::new();
            for (k, &c) in readers.iter().enumerate() {
                let had = |sid: u32| {
                    got[k]
                        .iter()
                        .filter(|m| m.1 == sid && m.2 == payload)
                        .count()
                };
                for (sid, _, q) in self.clients[c]
                    .subs
                    .iter()
                    .filter(|(_, f, _)| matches(f, s))
                {
                    match q {
                        None => assert_eq!(
                            had(*sid),
                            1,
                            "seed {}: {s} at client {c} sid {sid}",
                            self.seed
                        ),
                        Some(q) => *groups.entry(*q).or_insert(0) += had(*sid),
                    }
                }
            }
            for (q, n) in groups {
                assert_eq!(n, 1, "seed {}: {s} to queue {q}", self.seed);
            }
            let stray: Vec<_> = got
                .iter()
                .zip(readers)
                .flat_map(|(g, &c)| g.iter().filter(|m| m.2 == payload).map(move |m| (c, m)))
                .filter(|(c, m)| {
                    !self.clients[*c]
                        .subs
                        .iter()
                        .any(|(sid, f, _)| *sid == m.1 && matches(f, s))
                })
                .collect();
            assert!(
                stray.is_empty(),
                "seed {}: {s} where nothing matched: {stray:?}",
                self.seed
            );
        }
    }
}

/// Runs `steps` steps of seed `seed`, checking now and then, then heals
/// and checks once more.
fn run(seed: u64) {
    let seed = std::env::var("NAQ_SIM_SEED").map_or(seed, |s| s.parse().unwrap());
    let steps: usize = std::env::var("NAQ_SIM_STEPS").map_or(30, |s| s.parse().unwrap());
    let mut sim = Sim::new(seed);
    sim.quiet();
    for _ in 0..steps {
        match sim.rng.below(100) {
            0..40 => sim.subscribe(),
            40..55 => sim.unsubscribe(),
            55..62 => sim.disconnect(),
            62..74 => sim.partition_or_heal(),
            74..80 => sim.restart(),
            _ => sim.check(),
        }
    }
    if let Some((k, _)) = sim.apart.take() {
        sim.isolate(k, OPEN);
    }
    for k in 0..sim.servers.len() {
        if sim.servers[k].is_none() {
            let routes: Vec<u16> = sim.proxies[k].iter().flatten().map(|p| p.port).collect();
            sim.servers[k] = Some(node(k, sim.ports[k], &routes));
        }
    }
    sim.note("all back");
    sim.check();
}

#[test]
fn a_cluster_holds_its_interest_and_deliveries_through_random_steps() {
    run(1);
}

#[test]
fn a_cluster_holds_through_other_random_steps() {
    run(2);
}

#[test]
fn a_cluster_holds_through_yet_other_random_steps() {
    run(3);
}
