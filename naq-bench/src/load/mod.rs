//! Sustained publish/subscribe load over raw NATS wire.
//!
//! Publishers stamp each payload with their ID and a sequence number.
//! Subscribers count and check the order. A shared window bounds the
//! messages in flight, so every message is delivered at the rate the
//! server sustains (PUSH/PULL-like), without slow consumer drops.
//!
//! Before the run, each publisher sends probes until they reach the
//! subscribers: then its server, and its lane there, knows their
//! interest, even across a cluster.

mod publisher;
mod subscriber;

use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::conn::HANDSHAKE_TIMEOUT;
use crate::cpu;
use crate::wire::MAX_PAYLOAD;

/// One load run.
#[derive(Debug, Clone)]
pub struct Config {
    /// Server of the publishers, and of the subscribers unless
    /// `sub_addrs` names others.
    pub addr: SocketAddr,
    /// Servers of the subscribers, in turn. Empty: `addr`.
    pub sub_addrs: Vec<SocketAddr>,
    /// Publisher connections. Zero measures subscribers alone, against a
    /// source.
    pub pubs: usize,
    /// Subscriber connections. Zero publishes without a window.
    pub subs: usize,
    /// Queue group the subscribers join, if any.
    pub queue: Option<String>,
    /// Subject for all messages.
    pub subject: String,
    /// Payload bytes per message.
    pub payload: usize,
    /// Wire bytes in flight across all publishers.
    pub window: usize,
    /// Wire bytes per publisher write.
    pub batch: usize,
    /// Time before measuring.
    pub warmup: Duration,
    /// Measured time.
    pub duration: Duration,
    /// Time allowed for delivering the rest after publishing stops.
    pub drain: Duration,
    /// Server processes, for their CPU time, summed.
    pub server_pids: Vec<u32>,
}

impl Config {
    /// The server subscriber `idx` connects to.
    fn sub_addr(&self, idx: usize) -> SocketAddr {
        match self.sub_addrs.len() {
            0 => self.addr,
            n => self.sub_addrs[idx % n],
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            addr: SocketAddr::from(([127, 0, 0, 1], 4222)),
            sub_addrs: Vec::new(),
            pubs: 1,
            subs: 1,
            queue: None,
            subject: "bench".into(),
            payload: 16,
            window: 1 << 20,
            batch: 64 << 10,
            warmup: Duration::from_secs(2),
            duration: Duration::from_secs(10),
            drain: Duration::from_secs(10),
            server_pids: Vec::new(),
        }
    }
}

/// What a run measured.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// `version` from the server's `INFO`.
    pub server_version: Option<String>,
    /// Publisher connections.
    pub pubs: usize,
    /// Subscriber connections.
    pub subs: usize,
    /// Queue group, if any.
    pub queue: Option<String>,
    /// Payload bytes per message.
    pub payload: usize,
    /// Subject.
    pub subject: String,
    /// Window, in wire bytes.
    pub window: usize,
    /// Batch, in wire bytes.
    pub batch: usize,
    /// Measured seconds.
    pub elapsed_s: f64,
    /// Messages published per second.
    pub pub_msgs_s: f64,
    /// Messages delivered per second, summed over subscribers.
    pub sub_msgs_s: f64,
    /// Payload megabytes (10^6) delivered per second.
    pub sub_mb_s: f64,
    /// Messages published in the whole run.
    pub published: u64,
    /// Messages delivered in the whole run, summed over subscribers.
    pub delivered: u64,
    /// Deliveries missing after the drain.
    pub lost: u64,
    /// Deliveries at or below a sequence already seen.
    pub out_of_order: u64,
    /// Deliveries with a wrong size or an unknown publisher.
    pub corrupt: u64,
    /// Server CPU in percent of one core, while measuring, summed over
    /// the servers.
    pub server_cpu_pct: Option<f64>,
    /// Load generator CPU in percent of one core, while measuring.
    pub load_cpu_pct: Option<f64>,
}

impl Report {
    /// Whether every message arrived once, in order, intact.
    pub const fn is_clean(&self) -> bool {
        self.lost == 0 && self.out_of_order == 0 && self.corrupt == 0
    }
}

/// Why a run failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The configuration cannot run.
    #[error("bad config: {0}")]
    Config(&'static str),
    /// A connection failed.
    #[error("{0}")]
    Failed(String),
}

/// Longest wait for the subscribers' interest to reach the publishers'
/// servers: a cluster may still be linking.
const INTEREST_LIMIT: Duration = Duration::from_secs(10);

/// Between probes of a publisher.
const PROBE_EVERY: Duration = Duration::from_millis(5);

/// A counter on its own cache line.
#[derive(Debug, Default)]
#[repr(align(128))]
struct Counter(AtomicU64);

/// State the run threads share.
#[derive(Debug)]
struct Shared {
    /// Messages committed by all publishers.
    sent: Counter,
    /// Messages received, per subscriber.
    received: Box<[Counter]>,
    /// Whether a probe of publisher `p` reached subscriber `s`, at
    /// `s * pubs + p`.
    probed: Box<[AtomicBool]>,
    pubs: usize,
    queue: bool,
    go: AtomicBool,
    stop: AtomicBool,
    pubs_done: AtomicUsize,
    failed: AtomicBool,
    error: Mutex<Option<String>>,
    /// Streams to shut down at the end; `None` once closing.
    streams: Mutex<Option<Vec<TcpStream>>>,
}

// The counters and flags are statistics and stop signals: no other memory
// is published through them, so `Relaxed` is enough. Thread joins order
// the final reads.
impl Shared {
    fn new(pubs: usize, subs: usize, queue: bool) -> Shared {
        Shared {
            sent: Counter::default(),
            received: (0..subs).map(|_| Counter::default()).collect(),
            probed: (0..subs * pubs).map(|_| AtomicBool::new(false)).collect(),
            pubs,
            queue,
            go: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            pubs_done: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            error: Mutex::new(None),
            streams: Mutex::new(Some(Vec::new())),
        }
    }

    /// Messages every publisher may count as delivered: all subscribers
    /// have them, or for a queue group, one member has each.
    fn acked(&self) -> u64 {
        let counts = self.received.iter().map(|c| c.0.load(Relaxed));
        if self.queue {
            counts.sum()
        } else {
            counts.min().unwrap_or(0)
        }
    }

    /// Which publishers' probes reached subscriber `sub`.
    fn probed(&self, sub: usize) -> &[AtomicBool] {
        &self.probed[sub * self.pubs..(sub + 1) * self.pubs]
    }

    /// Whether the probes of every publisher reached every subscriber, or
    /// for a queue group, one member.
    fn heard(&self) -> bool {
        (0..self.pubs).all(|p| {
            let mut got = self
                .probed
                .iter()
                .skip(p)
                .step_by(self.pubs)
                .map(|b| b.load(Relaxed));
            if self.queue {
                got.any(|b| b)
            } else {
                got.all(|b| b)
            }
        })
    }

    fn delivered(&self) -> u64 {
        self.received.iter().map(|c| c.0.load(Relaxed)).sum()
    }

    fn halted(&self) -> bool {
        self.stop.load(Relaxed) || self.failed.load(Relaxed)
    }

    fn closing(&self) -> bool {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
    }

    /// Records the first error and stops the run.
    fn fail(&self, msg: String) {
        let mut e = self.error.lock().unwrap_or_else(PoisonError::into_inner);
        e.get_or_insert(msg);
        self.failed.store(true, Relaxed);
    }

    /// Keeps a stream for [`Shared::close`]; shuts it down at once if
    /// closing already started.
    fn register(&self, stream: &TcpStream) {
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        match (streams.as_mut(), stream.try_clone()) {
            (Some(list), Ok(s)) => list.push(s),
            _ => {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }

    /// Shuts down every stream, so blocked reads and writes return.
    fn close(&self) {
        let streams = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        for s in streams.into_iter().flatten() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    fn error(&self) -> String {
        let e = self.error.lock().unwrap_or_else(PoisonError::into_inner);
        e.clone().unwrap_or_else(|| "failed".into())
    }
}

/// What a connection thread reports once it is set up.
type Ready = Result<Option<String>, String>;

/// Counters at one instant.
#[derive(Debug, Clone, Copy)]
struct Sample {
    at: Instant,
    sent: u64,
    delivered: u64,
    server: Option<Duration>,
    own: Option<Duration>,
}

impl Sample {
    fn take(shared: &Shared, server_pids: &[u32]) -> Sample {
        Sample {
            at: Instant::now(),
            sent: shared.sent.0.load(Relaxed),
            delivered: shared.delivered(),
            server: servers_time(server_pids),
            own: cpu::own_time(),
        }
    }
}

/// The CPU time of all `pids`; `None` without one, or if one is gone.
fn servers_time(pids: &[u32]) -> Option<Duration> {
    if pids.is_empty() {
        return None;
    }
    pids.iter().map(|&p| cpu::process_time(p)).sum()
}

/// Runs the load and reports it.
///
/// # Errors
///
/// [`LoadError::Config`] for a configuration that cannot run,
/// [`LoadError::Failed`] if a connection fails.
pub fn run(cfg: &Config) -> Result<Report, LoadError> {
    check(cfg)?;
    let cfg = Arc::new(cfg.clone());
    let shared = Arc::new(Shared::new(cfg.pubs, cfg.subs, cfg.queue.is_some()));
    let (tx, rx) = mpsc::channel();
    let mut subs = Vec::with_capacity(cfg.subs);
    let mut pubs = Vec::with_capacity(cfg.pubs);
    let result = (|| {
        for i in 0..cfg.subs {
            subs.push(spawn_sub(&cfg, i, &shared, &tx));
        }
        let mut version = wait_ready(&rx, cfg.subs)?;
        for i in 0..cfg.pubs {
            pubs.push(spawn_pub(&cfg, i, &shared, &tx));
        }
        version = wait_ready(&rx, cfg.pubs)?.or(version);
        wait_heard(&shared)?;
        shared.go.store(true, Relaxed);
        for p in &pubs {
            p.thread().unpark();
        }
        measure(&cfg, &shared, version)
    })();
    shared.stop.store(true, Relaxed);
    shared.close();
    for p in &pubs {
        p.thread().unpark();
    }
    for p in pubs {
        let _ = p.join();
    }
    let mut out_of_order = 0;
    let mut corrupt = 0;
    for s in subs {
        let st = s.join().unwrap_or_default();
        out_of_order += st.out_of_order;
        corrupt += st.corrupt;
    }
    let mut report = result?;
    report.out_of_order = out_of_order;
    report.corrupt = corrupt;
    Ok(report)
}

fn check(cfg: &Config) -> Result<(), LoadError> {
    if cfg.pubs + cfg.subs == 0 {
        return Err(LoadError::Config("no publishers and no subscribers"));
    }
    if cfg.queue.is_some() && cfg.subs == 0 {
        return Err(LoadError::Config("a queue group needs subscribers"));
    }
    if cfg.payload > MAX_PAYLOAD {
        return Err(LoadError::Config("payload too large"));
    }
    if cfg.batch == 0 || cfg.window < cfg.batch {
        return Err(LoadError::Config(
            "batch must be positive and fit the window",
        ));
    }
    if cfg.subject.is_empty() || cfg.subject.contains(char::is_whitespace) {
        return Err(LoadError::Config("subject must be one non-empty token"));
    }
    Ok(())
}

fn spawn_sub(
    cfg: &Arc<Config>,
    idx: usize,
    shared: &Arc<Shared>,
    tx: &Sender<Ready>,
) -> JoinHandle<subscriber::Stats> {
    let (cfg, shared, tx) = (cfg.clone(), shared.clone(), tx.clone());
    thread::spawn(move || subscriber::run(&cfg, idx, &shared, &tx))
}

fn spawn_pub(
    cfg: &Arc<Config>,
    idx: usize,
    shared: &Arc<Shared>,
    tx: &Sender<Ready>,
) -> JoinHandle<()> {
    let (cfg, shared, tx) = (cfg.clone(), shared.clone(), tx.clone());
    thread::spawn(move || publisher::run(&cfg, idx as u32, &shared, &tx))
}

/// Waits for `n` threads to be set up. Returns the server version.
fn wait_ready(rx: &Receiver<Ready>, n: usize) -> Result<Option<String>, LoadError> {
    let mut version = None;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT * 2;
    for _ in 0..n {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Ok(v)) => version = version.or(v),
            Ok(Err(e)) => return Err(LoadError::Failed(e)),
            Err(_) => return Err(LoadError::Failed("setup timed out".into())),
        }
    }
    Ok(version)
}

/// Waits until the publishers' probes reach the subscribers.
fn wait_heard(shared: &Shared) -> Result<(), LoadError> {
    if wait_until(shared, Instant::now() + INTEREST_LIMIT, || shared.heard())? {
        Ok(())
    } else {
        Err(LoadError::Failed(
            "the subscribers' interest did not reach the publishers".into(),
        ))
    }
}

/// Warms up, measures, stops the publishers and drains.
fn measure(
    cfg: &Config,
    shared: &Shared,
    server_version: Option<String>,
) -> Result<Report, LoadError> {
    pause(shared, cfg.warmup)?;
    let a = Sample::take(shared, &cfg.server_pids);
    pause(shared, cfg.duration)?;
    let b = Sample::take(shared, &cfg.server_pids);
    shared.stop.store(true, Relaxed);
    let deadline = Instant::now() + cfg.drain;
    let pubs_done = || shared.pubs_done.load(Relaxed) == cfg.pubs;
    if !wait_until(shared, deadline, pubs_done)? {
        return Err(LoadError::Failed("publishers did not stop".into()));
    }
    let published = shared.sent.0.load(Relaxed);
    let expected = match cfg.subs {
        0 => 0,
        _ if cfg.queue.is_some() => published,
        n => published * n as u64,
    };
    wait_until(shared, deadline, || shared.delivered() >= expected)?;
    let delivered = shared.delivered();
    let wall = b.at - a.at;
    let secs = wall.as_secs_f64();
    let sub_msgs_s = (b.delivered - a.delivered) as f64 / secs;
    let pct =
        |x: Option<Duration>, y: Option<Duration>| Some(cpu::percent(y?.checked_sub(x?)?, wall));
    Ok(Report {
        server_version,
        pubs: cfg.pubs,
        subs: cfg.subs,
        queue: cfg.queue.clone(),
        payload: cfg.payload,
        subject: cfg.subject.clone(),
        window: cfg.window,
        batch: cfg.batch,
        elapsed_s: secs,
        pub_msgs_s: (b.sent - a.sent) as f64 / secs,
        sub_msgs_s,
        sub_mb_s: sub_msgs_s * cfg.payload as f64 / 1e6,
        published,
        delivered,
        lost: expected.saturating_sub(delivered),
        out_of_order: 0,
        corrupt: 0,
        server_cpu_pct: pct(a.server, b.server),
        load_cpu_pct: pct(a.own, b.own),
    })
}

/// Sleeps, but fails early if a connection fails.
fn pause(shared: &Shared, d: Duration) -> Result<(), LoadError> {
    wait_until(shared, Instant::now() + d, || false).map(|_| ())
}

/// Polls `done` until it holds or `deadline` passes. Fails if a connection
/// fails.
fn wait_until(
    shared: &Shared,
    deadline: Instant,
    done: impl Fn() -> bool,
) -> Result<bool, LoadError> {
    loop {
        if shared.failed.load(Relaxed) {
            return Err(LoadError::Failed(shared.error()));
        }
        if done() {
            return Ok(true);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        thread::sleep((deadline - now).min(Duration::from_millis(1)));
    }
}

/// Spin, then yield, then sleep.
fn backoff(spins: &mut u32) {
    *spins = spins.saturating_add(1);
    if *spins < 64 {
        std::hint::spin_loop();
    } else if *spins < 128 {
        thread::yield_now();
    } else {
        thread::sleep(Duration::from_micros(20));
    }
}
