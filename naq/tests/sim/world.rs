//! The core of a seeded random simulation. Clients come and go and
//! subscribe and unsubscribe, in queue groups too, on the servers of a
//! [`World`], which changes at random too. Once quiet, a message reaches
//! each subscription once and each queue group once, among the servers
//! the publisher's reaches, with its reply and headers.
//!
//! `NAQ_SIM_SEED` runs a seed of choice, `NAQ_SIM_STEPS` sets the steps.

#![allow(dead_code, reason = "each simulation uses a part")]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use super::cluster::{Told, WAIT};

/// xorshift64*, so a failure replays from its seed.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) const fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) const fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub(crate) const fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
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

/// A message a client got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Msg {
    subject: String,
    sid: u32,
    reply: Option<String>,
    headers: Option<String>,
    payload: String,
}

/// A client of server `server`, read line by line.
pub(crate) struct Peer {
    pub(crate) server: usize,
    r: BufReader<TcpStream>,
    /// What a read cut short holds.
    pending: String,
    /// It takes headers; else it gets messages without theirs.
    headers: bool,
    subs: Vec<Sub>,
    next_sid: u32,
}

impl Peer {
    fn new(server: usize, at: SocketAddr, headers: bool) -> Peer {
        let w = TcpStream::connect(at).unwrap();
        let mut p = Peer {
            server,
            r: BufReader::new(w),
            pending: String::new(),
            headers,
            subs: Vec::new(),
            next_sid: 1,
        };
        p.send(&format!(
            "CONNECT {{\"verbose\":false,\"headers\":{headers}}}\r\n"
        ));
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

    /// The next message within `wait`.
    fn msg(&mut self, wait: Duration) -> Option<Msg> {
        let head = self.next_line(wait)?;
        Some(self.body(&head))
    }

    /// The message of `MSG` or `HMSG` line `head`, its body read.
    fn body(&mut self, head: &str) -> Msg {
        let w: Vec<&str> = head.split(' ').collect();
        let fixed = match w[0] {
            "MSG" => 4,
            "HMSG" => 5,
            _ => unreachable!("server {}: not a message: {head}", self.server),
        };
        assert!(
            w.len() == fixed || w.len() == fixed + 1,
            "server {}: {head}",
            self.server
        );
        let total: usize = w[w.len() - 1].parse().unwrap();
        let split: usize = if fixed == 5 {
            w[w.len() - 2].parse().unwrap()
        } else {
            0
        };
        let mut body = vec![0; total + 2];
        self.r.get_ref().set_read_timeout(Some(WAIT)).unwrap();
        self.r.read_exact(&mut body).unwrap();
        assert!(body.ends_with(b"\r\n"), "server {}: {head}", self.server);
        body.truncate(total);
        let body = String::from_utf8(body).unwrap();
        let (headers, payload) = body.split_at(split);
        Msg {
            subject: w[1].to_owned(),
            sid: w[2].parse().unwrap(),
            reply: (w.len() > fixed).then(|| w[3].to_owned()),
            headers: (fixed == 5).then(|| headers.to_owned()),
            payload: payload.to_owned(),
        }
    }

    /// Waits until the server took what it was sent; messages that came
    /// meanwhile are given back.
    fn synced(&mut self) -> Vec<Msg> {
        self.send("PING\r\n");
        let mut got = Vec::new();
        loop {
            let l = self.line();
            if l == "PONG" {
                return got;
            }
            got.push(self.body(&l));
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

/// What `clients` ask for, as a server hears of it: each filter once, and
/// each queue group of a filter with its members.
pub(crate) fn told<'a>(clients: impl Iterator<Item = &'a Peer>) -> Vec<Told> {
    let mut plain = BTreeSet::new();
    let mut groups = BTreeMap::new();
    for (_, f, q) in clients.flat_map(|c| &c.subs) {
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

/// The filters `clients` ask for, as a leaf node link hears of them: each
/// once, and once more for each queue group of it.
pub(crate) fn subjects<'a>(clients: impl Iterator<Item = &'a Peer>) -> Vec<String> {
    let mut all: Vec<String> = told(clients).into_iter().map(|t| t.0).collect();
    all.sort();
    all
}

/// The leaf node links of a server: each one's name, and the subjects it
/// heard of, sorted.
pub(crate) type Links = Vec<(String, Vec<String>)>;

/// The links `/leafz?subs=1` answer `z` tells of, but loop detection
/// subjects.
pub(crate) fn links(z: &serde_json::Value) -> Links {
    let mut all: Links = z["leafs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            let mut subs: Vec<String> = l["subscriptions_list"]
                .as_array()
                .map(|s| {
                    s.iter()
                        .map(|s| s.as_str().unwrap().to_owned())
                        .filter(|s| !s.starts_with("$LDS."))
                        .collect()
                })
                .unwrap_or_default();
            subs.sort();
            (l["name"].as_str().unwrap().to_owned(), subs)
        })
        .collect();
    all.sort();
    all
}

/// The servers of a simulation and their links, which change.
pub(crate) trait World {
    /// Where the clients of each server connect, by index; `None` for
    /// one that stopped.
    fn addrs(&self) -> Vec<Option<SocketAddr>>;

    /// Waits until each server heard of the interest of `clients` that
    /// it should, and of no other.
    fn quiet(&mut self, clients: &[Peer]);

    /// Whether, once quiet, server `i`'s messages reach server `j`'s
    /// clients.
    fn reach(&self, i: usize, j: usize) -> bool;

    /// Changes at random: what it did, and the server that stopped, if
    /// one.
    fn change(&mut self, rng: &mut Rng) -> (String, Option<usize>);

    /// Ends what keeps servers apart, and starts those that stopped.
    fn heal(&mut self);
}

/// A message a check sends: its payload is its number.
struct Sent {
    subject: &'static str,
    reply: Option<String>,
    headers: Option<String>,
}

impl Sent {
    /// Message `n` at random, with a reply subject or headers or both;
    /// headers only from a client that takes them.
    fn new(rng: &mut Rng, n: usize, headers: bool) -> Sent {
        let kind = rng.below(4);
        let subject = *rng.pick(SUBJECTS);
        Sent {
            subject,
            reply: (kind & 1 != 0).then(|| format!("re.{n}")),
            headers: (headers && kind & 2 != 0).then(|| format!("NATS/1.0\r\nSim: {n}\r\n\r\n")),
        }
    }

    /// It as message `n` on the wire.
    fn wire(&self, n: usize) -> String {
        let (s, payload) = (self.subject, n.to_string());
        let reply = self
            .reply
            .as_ref()
            .map_or(String::new(), |r| format!(" {r}"));
        match &self.headers {
            None => format!("PUB {s}{reply} {}\r\n{payload}\r\n", payload.len()),
            Some(h) => format!(
                "HPUB {s}{reply} {} {}\r\n{h}{payload}\r\n",
                h.len(),
                h.len() + payload.len()
            ),
        }
    }

    /// It as message `n` arrives on subscription `sid` of a client that
    /// takes headers or not.
    fn got(&self, n: usize, sid: u32, headers: bool) -> Msg {
        Msg {
            subject: self.subject.to_owned(),
            sid,
            reply: self.reply.clone(),
            headers: self.headers.clone().filter(|_| headers),
            payload: n.to_string(),
        }
    }
}

/// A simulation in a world, its clients, and what was done to them.
pub(crate) struct Sim<W> {
    seed: u64,
    rng: Rng,
    w: W,
    clients: Vec<Peer>,
    /// Checks so far: each has a fence subject of its own.
    checks: u32,
}

impl<W: World> Sim<W> {
    /// A simulation of `seed`, or of `NAQ_SIM_SEED`, in `w`.
    pub(crate) fn new(seed: u64, w: W) -> Sim<W> {
        let seed = std::env::var("NAQ_SIM_SEED").map_or(seed, |s| s.parse().unwrap());
        Sim {
            seed,
            // Never 0: xorshift would stay there.
            rng: Rng(seed | 1 << 63),
            w,
            clients: Vec::new(),
            checks: 0,
        }
    }

    fn note(&self, what: &str) {
        eprintln!("seed {}: {what}", self.seed);
    }

    fn up(&self) -> Vec<usize> {
        let addrs = self.w.addrs();
        (0..addrs.len()).filter(|&i| addrs[i].is_some()).collect()
    }

    /// Runs `NAQ_SIM_STEPS` steps, 30 by default, checking now and then,
    /// then heals and checks once more.
    pub(crate) fn run(mut self) {
        let steps: usize = std::env::var("NAQ_SIM_STEPS").map_or(30, |s| s.parse().unwrap());
        self.w.quiet(&self.clients);
        for _ in 0..steps {
            match self.rng.below(100) {
                0..40 => self.subscribe(),
                40..55 => self.unsubscribe(),
                55..62 => self.disconnect(),
                62..80 => self.change(),
                _ => self.check(),
            }
        }
        self.w.heal();
        self.note("all back");
        self.check();
    }
}

/// The steps a simulation takes.
impl<W: World> Sim<W> {
    fn connect(&mut self, server: usize) -> usize {
        let at = self.w.addrs()[server].unwrap();
        // Mostly clients that take headers.
        let headers = self.rng.below(4) != 0;
        self.clients.push(Peer::new(server, at, headers));
        self.clients.len() - 1
    }

    /// A client of `server`, new or not.
    fn client_of(&mut self, server: usize) -> usize {
        let mine: Vec<usize> = (0..self.clients.len())
            .filter(|&c| self.clients[c].server == server)
            .collect();
        if mine.is_empty() || self.rng.below(4) == 0 {
            self.connect(server)
        } else {
            *self.rng.pick(&mine)
        }
    }

    /// A client subscribes.
    fn subscribe(&mut self) {
        let up = self.up();
        let Some(&server) = (!up.is_empty()).then(|| self.rng.pick(&up)) else {
            return;
        };
        let c = self.client_of(server);
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

    /// The world changes: the clients of a server that stops go with it.
    fn change(&mut self) {
        let (what, stopped) = self.w.change(&mut self.rng);
        self.note(&what);
        if let Some(k) = stopped {
            self.clients.retain(|c| c.server != k);
        }
    }
}

/// Messages, and the oracle of what reaches whom.
impl<W: World> Sim<W> {
    /// Once quiet, a client publishes; each client the publisher's server
    /// reaches gets what its subscriptions match, once each, and each
    /// queue group gets one pick.
    fn check(&mut self) {
        let up = self.up();
        if up.is_empty() {
            return;
        }
        let server = *self.rng.pick(&up);
        let publisher = self.client_of(server);
        self.w.quiet(&self.clients);
        let readers: Vec<usize> = (0..self.clients.len())
            .filter(|&c| self.w.reach(server, self.clients[c].server))
            .collect();
        self.checks += 1;
        let fence = format!("fence.{}", self.checks);
        let sids = self.fences(&fence, &readers);
        self.w.quiet(&self.clients);
        self.warm(publisher, &fence, &readers);
        let headers = self.clients[publisher].headers;
        let sent: Vec<Sent> = (0..4)
            .map(|n| Sent::new(&mut self.rng, n, headers))
            .collect();
        let subjects: Vec<&str> = sent.iter().map(|s| s.subject).collect();
        self.note(&format!("client {publisher} publishes to {subjects:?}"));
        let p = &mut self.clients[publisher];
        for (n, s) in sent.iter().enumerate() {
            p.send(&s.wire(n));
        }
        p.send(&format!("PUB {fence} 3\r\nend\r\n"));
        let got = self.collect(&fence, &readers, &sids);
        for (n, s) in sent.iter().enumerate() {
            self.expect(n, s, &readers, &got);
        }
        for (&c, &sid) in readers.iter().zip(&sids) {
            self.clients[c].unsubscribe(sid);
            assert!(self.clients[c].synced().is_empty(), "seed {}", self.seed);
        }
    }

    /// Subscribes each of `readers` to `fence`: their SIDs.
    fn fences(&mut self, fence: &str, readers: &[usize]) -> Vec<u32> {
        readers
            .iter()
            .map(|&c| {
                let sid = self.clients[c].subscribe(fence, None);
                assert!(self.clients[c].synced().is_empty(), "seed {}", self.seed);
                sid
            })
            .collect()
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
                got.is_none_or(|m| m.subject != fence)
            });
        }
    }

    /// What `readers` got, by reader, until their fence's `end`, and up to
    /// a `PONG` after it.
    fn collect(&mut self, fence: &str, readers: &[usize], sids: &[u32]) -> Vec<Vec<Msg>> {
        let mut all = Vec::new();
        for (&c, &sid) in readers.iter().zip(sids) {
            let mut got = Vec::new();
            loop {
                let m = self.clients[c].msg(WAIT);
                let m = m.unwrap_or_else(|| unreachable!("seed {}: no end at {c}", self.seed));
                if m.subject == fence {
                    if m.payload == "end" && m.sid == sid {
                        break;
                    }
                    continue;
                }
                got.push(m);
            }
            got.extend(self.clients[c].synced());
            all.push(got);
        }
        all
    }

    /// Checks that `got`, by reader, holds message `n`, `s`, as the
    /// subscriptions of `readers` match it: each plain one once, each
    /// queue group once, and nothing else.
    fn expect(&self, n: usize, s: &Sent, readers: &[usize], got: &[Vec<Msg>]) {
        let payload = n.to_string();
        let mut groups = BTreeMap::new();
        for (k, &c) in readers.iter().enumerate() {
            let peer = &self.clients[c];
            for m in got[k].iter().filter(|m| m.payload == payload) {
                let sub = peer.subs.iter().find(|x| x.0 == m.sid);
                assert!(
                    sub.is_some_and(|x| matches(&x.1, s.subject)),
                    "seed {}: {} where nothing matched: client {c} {m:?}",
                    self.seed,
                    s.subject
                );
                assert_eq!(*m, s.got(n, m.sid, peer.headers), "seed {}", self.seed);
            }
            for (sid, _, q) in peer.subs.iter().filter(|x| matches(&x.1, s.subject)) {
                let had = got[k]
                    .iter()
                    .filter(|m| m.sid == *sid && m.payload == payload)
                    .count();
                match q {
                    None => assert_eq!(
                        had, 1,
                        "seed {}: {} at client {c} sid {sid}",
                        self.seed, s.subject
                    ),
                    Some(q) => *groups.entry(*q).or_insert(0) += had,
                }
            }
        }
        for (q, n) in groups {
            assert_eq!(n, 1, "seed {}: {} to queue {q}", self.seed, s.subject);
        }
    }
}
