//! What the server says on `$SYS` of its own accord: its events, its
//! `STATSZ` heartbeat, the connections of its accounts and its last word. One task on lane 0 sends it all
//! and numbers each message as it leaves, as `nats-server`'s send loop
//! does, so that every other server gets them in order.

use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use naq_proto::client::Pub;
use tokio::time::Instant;

use rustc_hash::FxHashMap;

use super::conns::{Beats, CONNS};
use super::reply::ServerInfo;
use crate::lane::{Lane, Outs};
use crate::mailbox::{self, Mailbox, Receiver};
use crate::monitor::json;
use crate::server::Shared;

/// Events that wait for the sender, at most: more are dropped.
const MOST: usize = 1 << 14;

/// How long the last word may take to leave.
const LAST: Duration = Duration::from_secs(1);

/// The first heartbeat comes this soon after the start.
const FIRST_BEAT: Duration = Duration::from_millis(250);

/// The heartbeats slow down to one every so often.
const BEAT: Duration = Duration::from_secs(10);

/// Broadcasts of `STATSZ` come this far apart at least.
const LIMIT: Duration = Duration::from_secs(1);

/// Something for the sender to send.
#[derive(Debug)]
pub(crate) enum Event {
    /// A message, numbered as it leaves.
    Note(Note),
    /// `STATSZ` on the server's own subject, as a new server makes
    /// `nats-server` send it: past the rate limit if `forced`.
    Statsz { forced: bool },
    /// The connections of this account changed: `CONNS` goes out.
    Conns(u32),
    /// A `CONNS` request about account `account`, answered to `reply` if
    /// the account has clients here.
    Answer { account: String, reply: Vec<u8> },
    /// The server's last word, `SHUTDOWN`: `done` hears once it left.
    Last(SyncSender<()>),
}

/// A message whose payload holds the block of the server that sends it,
/// between `head` and `tail`.
#[derive(Debug)]
pub(crate) struct Note {
    /// The account it goes into.
    pub(crate) account: u32,
    pub(crate) to: Vec<u8>,
    pub(crate) head: Vec<u8>,
    pub(crate) tail: Vec<u8>,
}

impl Note {
    /// An answer to `to` in the system account `sys`, as Go writes its
    /// `ServerAPIResponse`: the server, then the JSON `error`.
    pub(crate) fn error(sys: u32, to: Vec<u8>, error: &impl serde::Serialize) -> Note {
        let mut tail = b",\"error\":".to_vec();
        tail.extend(json::compact(error));
        tail.push(b'}');
        Note {
            account: sys,
            to,
            head: b"{\"server\":".to_vec(),
            tail,
        }
    }
}

/// The way to the sender.
#[derive(Debug)]
pub(crate) struct Outbox {
    tx: Mailbox<Event>,
    /// The sender's end, until it takes it.
    rx: Mutex<Option<Receiver<Event>>>,
}

impl Outbox {
    pub(crate) fn new() -> Outbox {
        let (tx, rx) = mailbox::mailbox(MOST);
        Outbox {
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    /// Hands the sender `e`: dropped if too many wait, or once the server
    /// said its last word.
    pub(crate) fn post(&self, e: Event) {
        let _ = self.tx.offer(e);
    }
}

/// Starts the sender on `lane`, if it is lane 0 of a server with a system
/// account.
pub(super) fn start(lane: &Lane) {
    let shared = &lane.shared;
    if lane.id != 0 || shared.system.is_none() {
        return;
    }
    let rx = shared
        .sys
        .outbox
        .rx
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(rx) = rx {
        tokio::task::spawn_local(run(Arc::downgrade(shared), rx));
    }
}

/// Sends the server's last word, `SHUTDOWN`, and waits until it left, a
/// second at most. The server sends nothing on `$SYS` after it.
pub(crate) fn last_word(shared: &Shared) {
    if shared.system.is_none() {
        return;
    }
    let (done, left) = std::sync::mpsc::sync_channel(1);
    // Past the limit: it must go.
    shared.sys.outbox.tx.push(Event::Last(done));
    // A sender gone drops `done`: nothing to wait for.
    let _ = left.recv_timeout(LAST);
}

/// Sends what comes to `rx` and what the timers call for, while the
/// server runs and until its last word.
async fn run(weak: Weak<Shared>, rx: Receiver<Event>) {
    let mut clock = Clock::new(Instant::now());
    let mut events = Vec::new();
    // The accounts whose connections it asked the others for.
    let mut tracked = 0;
    loop {
        // Holds the server only while it sends.
        {
            let Some(shared) = weak.upgrade() else {
                return;
            };
            let Some(lane) = crate::lane::get(shared.id, 0) else {
                return;
            };
            let mut s = Sender::new(&lane);
            tracked = s.track(tracked);
            // A change that another in the batch follows goes out as that one.
            let mut last = FxHashMap::default();
            for (i, e) in events.iter().enumerate() {
                if let Event::Conns(a) = e {
                    last.insert(*a, i);
                }
            }
            for (i, e) in events.drain(..).enumerate() {
                match e {
                    Event::Note(n) => s.note(&n),
                    Event::Statsz { forced } => {
                        if forced {
                            clock.beat.last = None;
                        }
                        if !clock.beat.limited(Instant::now()) {
                            s.statsz().await;
                        }
                    }
                    Event::Conns(a) if last.get(&a) == Some(&i) => {
                        s.conns(a, None, &mut clock.conns).await;
                    }
                    Event::Conns(_) => {}
                    Event::Answer { account, reply } => {
                        if let Some(a) = shared.accounts.id(&account) {
                            s.conns(a, Some(&reply), &mut clock.conns).await;
                        }
                    }
                    Event::Last(done) => {
                        s.farewell();
                        s.ship().await;
                        let _ = done.send(());
                        return;
                    }
                }
            }
            clock.tick(&mut s, Instant::now()).await;
            s.ship().await;
        }
        // Cancel-safe: `recv_all` takes the events only as it returns, and
        // a sleep loses nothing.
        tokio::select! {
            open = rx.recv_all(&mut events) => if !open {
                return;
            },
            () = tokio::time::sleep_until(clock.due()) => {}
        }
    }
}

/// The timers of the sender.

#[derive(Debug)]
struct Clock {
    beat: Beat,
    /// When the servers are next checked for those gone quiet.
    sweep: Instant,
    /// The heartbeats of the accounts with connections.
    conns: Beats,
}

impl Clock {
    fn new(now: Instant) -> Clock {
        Clock {
            beat: Beat::new(now),
            sweep: now + super::remote::SWEEP,
            conns: Beats::default(),
        }
    }

    /// When the next timer is due.
    fn due(&self) -> Instant {
        let due = self.beat.next.min(self.sweep);
        self.conns.next().map_or(due, |c| c.min(due))
    }

    /// Does what the timers due at `now` call for, with `s`.
    async fn tick(&mut self, s: &mut Sender<'_>, now: Instant) {
        if now >= self.beat.next {
            self.beat.fired(now);
            if !self.beat.limited(now) {
                s.statsz().await;
            }
        }
        if now >= self.sweep {
            super::remote::sweep(&s.lane.shared, now);
            self.sweep = now + super::remote::SWEEP;
        }
        for a in self.conns.due(now) {
            s.conns(a, None, &mut self.conns).await;
        }
    }
}

/// The `STATSZ` heartbeat, as `nats-server` times it: the first soon after
/// the start, then twice as late each time up to [`BEAT`], and no two
/// broadcasts closer than [`LIMIT`].
#[derive(Debug)]
struct Beat {
    /// The time between heartbeats now.
    every: Duration,
    next: Instant,
    /// The last broadcast.
    last: Option<Instant>,
}

impl Beat {
    fn new(now: Instant) -> Beat {
        Beat {
            every: FIRST_BEAT,
            next: now + FIRST_BEAT,
            last: None,
        }
    }

    /// The heartbeat fired at `now`.
    fn fired(&mut self, now: Instant) {
        self.every = (self.every * 2).min(BEAT);
        self.next = now + self.every;
    }

    /// Whether the rate limit drops a broadcast at `now`; if it does, the
    /// next heartbeat comes as the limit ends.
    fn limited(&mut self, now: Instant) -> bool {
        let gap = LIMIT.min(self.every);
        match self.last {
            Some(last) if now.saturating_duration_since(last) < gap => {
                self.next = last + gap;
                true
            }
            _ => {
                self.last = Some(now);
                false
            }
        }
    }
}

/// Messages sent from lane 0, held until shipped.
struct Sender<'l> {
    lane: &'l Lane,
    out: Outs,
}

impl<'l> Sender<'l> {
    fn new(lane: &'l Lane) -> Sender<'l> {
        Sender {
            lane,
            out: Outs::new(lane),
        }
    }

    /// Sends `payload` to `to` in `account`, as `nats-server` sends its
    /// own messages: with an empty reply, not to the server's own
    /// services.
    fn send(&mut self, account: u32, to: &[u8], payload: &[u8]) {
        let m = Pub {
            subject: to,
            reply: Some(b""),
            headers: None,
            payload,
        };
        crate::lane::inject(self.lane, &mut self.out, account, &m);
    }

    /// Asks the other servers for the connections of each account added
    /// since the first `from`: they answer to this server's inbox. The
    /// accounts asked for so far.
    fn track(&mut self, from: u32) -> u32 {
        let shared = self.lane.shared.clone();
        let (Some(sys), n) = (shared.system, shared.accounts.len()) else {
            return from;
        };
        let reply = format!("$SYS._INBOX_.{}", shared.server_id);
        for id in from..n {
            let name = shared.accounts.name(id);
            let to = format!("$SYS.REQ.ACCOUNT.{name}.CONNS");
            let mut payload = b"{\"server\":".to_vec();
            payload.extend(json::compact(&ServerInfo::of(&shared)));
            payload.extend_from_slice(b",\"acc\":");
            payload.extend(json::compact(&name));
            payload.push(b'}');
            let m = Pub {
                subject: to.as_bytes(),
                reply: Some(reply.as_bytes()),
                headers: None,
                payload: &payload,
            };
            crate::lane::inject(self.lane, &mut self.out, sys, &m);
        }
        n
    }

    /// Sends `CONNS` of account `id`: to `reply`, through the imports it
    /// meets, if it has clients here; else on both of its subjects. Its
    /// heartbeat in `beats` starts again.
    async fn conns(&mut self, id: u32, reply: Option<&[u8]>, beats: &mut Beats) {
        let shared = self.lane.shared.clone();
        let Some(sys) = shared.system else {
            return;
        };
        let Some(c) = crate::monitor::conns(&shared, id).await else {
            return;
        };
        if reply.is_some() && c.clients == 0 {
            return;
        }
        beats.sent(id, c.total, Instant::now());
        let head = super::events::head(CONNS, std::time::SystemTime::now());
        let tail = [&b","[..], &c.fields, b"}"].concat();
        let numbered = |shared: &Shared| {
            let info = json::compact(&ServerInfo::of(shared));
            [&head[..], &info, &tail].concat()
        };
        if let Some(reply) = reply {
            let m = Pub {
                subject: reply,
                reply: Some(b""),
                headers: None,
                payload: &numbered(&shared),
            };
            crate::lane::inject_through(self.lane, &mut self.out, sys, &m);
            return;
        }
        let name = shared.accounts.name(id);
        let old = format!("$SYS.SERVER.ACCOUNT.{name}.CONNS");
        let new = format!("$SYS.ACCOUNT.{name}.SERVER.CONNS");
        for to in [old, new] {
            self.send(sys, to.as_bytes(), &numbered(&shared));
        }
    }

    /// Sends `n`, numbered now.
    fn note(&mut self, n: &Note) {
        let info = json::compact(&ServerInfo::of(&self.lane.shared));
        let payload = [&n.head[..], &info, &n.tail].concat();
        self.send(n.account, &n.to, &payload);
    }

    /// Broadcasts `STATSZ` on the server's own subject, if anyone may hear
    /// it.
    async fn statsz(&mut self) {
        let shared = self.lane.shared.clone();
        let Some(sys) = shared.system else {
            return;
        };
        let to = format!("$SYS.SERVER.{}.STATSZ", shared.server_id);
        if !heard(self.lane, sys, to.as_bytes()) {
            return;
        }
        let payload = super::server::broadcast(&shared).await;
        self.send(sys, to.as_bytes(), &payload);
    }

    /// Sends `SHUTDOWN`: the block of the server alone. Its answers stop.
    fn farewell(&mut self) {
        let shared = self.lane.shared.clone();
        let Some(sys) = shared.system else {
            return;
        };
        // Relaxed: answers that see it late are sent still, as in Go.
        shared.sys.quiet.store(true, Ordering::Relaxed);
        let to = format!("$SYS.SERVER.{}.SHUTDOWN", shared.server_id);
        let payload = json::compact(&ServerInfo::of(&shared));
        self.send(sys, to.as_bytes(), &payload);
    }

    /// Ships what it sent, in order.
    async fn ship(&mut self) {
        self.lane.flush();
        self.lane.ship_imported(&mut self.out).await;
    }
}

/// Whether a broadcast on `to` in account `sys` may reach anyone, as
/// `nats-server` decides: always with a cluster, naq leafs or a link that
/// binds the system account; else when something subscribes to it.
fn heard(lane: &Lane, sys: u32, to: &[u8]) -> bool {
    let shared = &lane.shared;
    let o = &shared.opts;
    let name = shared.accounts.name(sys);
    let linked = o.remotes.iter().any(|r| r.account.as_deref() == Some(name));
    o.cluster.is_some() || o.leafnodes.is_some() || linked || lane.index(sys).borrow().wanted(to)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// The times of the broadcasts the heartbeat makes up to `until`.
    fn beats(until: Duration) -> Vec<Duration> {
        let t0 = Instant::now();
        let mut b = Beat::new(t0);
        let mut sent = Vec::new();
        while b.next <= t0 + until {
            let now = b.next;
            b.fired(now);
            if !b.limited(now) {
                sent.push(now - t0);
            }
        }
        sent
    }

    #[test]
    fn heartbeats_come_as_nats_server_sends_them() {
        let s = |n: u64| Duration::from_millis(n);
        assert_eq!(
            beats(Duration::from_secs(36)),
            [
                s(250),
                s(1250),
                s(3250),
                s(7250),
                s(15250),
                s(25250),
                s(35250)
            ]
        );
    }

    #[test]
    fn a_broadcast_too_soon_is_dropped_and_pulls_the_heartbeat_in() {
        let t0 = Instant::now();
        let mut b = Beat::new(t0);
        b.every = BEAT;
        assert!(!b.limited(t0));
        b.next = t0 + BEAT;
        assert!(b.limited(t0 + 500 * MS), "too soon");
        assert_eq!(b.next, t0 + LIMIT, "the next comes as the limit ends");
        assert!(!b.limited(t0 + LIMIT));
        b.last = None;
        assert!(!b.limited(t0 + LIMIT + MS), "forced past the limit");
    }

    #[test]
    fn errors_are_written_around_the_server() {
        let n = Note::error(3, b"x".to_vec(), &serde_json::json!({"code": 400}));
        assert_eq!(n.head, b"{\"server\":");
        assert_eq!(n.tail, b",\"error\":{\"code\":400}}");
    }
}
