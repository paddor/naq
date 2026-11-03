//! A fake NATS server that measures the load generator alone.
//!
//! [`Mode::Relay`] counts `PUB`s and relays them to exact-subject
//! subscribers, one queue member per group in turn. With no subscribers it
//! is a pure sink. [`Mode::Source`] sends every subscriber an endless
//! stream of stamped `MSG`s.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

use crate::conn::{ConnError, FrameReader, lossy};
use crate::wire::{self, Op};

/// `INFO` the sink sends.
const INFO: &[u8] = b"INFO {\"server_id\":\"naq-sink\",\"server_name\":\"naq-sink\",\"version\":\"0.0.0-sink\",\"proto\":1,\"headers\":true,\"max_payload\":8388608}\r\n";

/// Bytes per source write.
const SOURCE_BATCH: usize = 64 << 10;

/// What the sink does with clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Count `PUB`s, relay them to subscribers.
    Relay,
    /// Stream `MSG`s with payloads of this size to every subscriber.
    Source(usize),
}

/// A subscriber the relay writes to.
#[derive(Debug)]
struct Target {
    subject: Vec<u8>,
    sid: Vec<u8>,
    queue: Option<Vec<u8>>,
    out: Arc<Mutex<TcpStream>>,
}

#[derive(Debug, Default)]
struct State {
    published: AtomicU64,
    targets: Mutex<Vec<Arc<Target>>>,
    stop: AtomicBool,
}

/// A running sink. Dropping it stops accepting connections.
#[derive(Debug)]
pub struct Sink {
    addr: SocketAddr,
    state: Arc<State>,
}

impl Sink {
    /// Binds `addr` and serves clients on threads.
    ///
    /// # Errors
    ///
    /// The bind error.
    pub fn spawn(addr: SocketAddr, mode: Mode) -> io::Result<Sink> {
        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;
        let state = Arc::new(State::default());
        let st = state.clone();
        thread::spawn(move || accept(&listener, mode, &st));
        Ok(Sink { addr, state })
    }

    /// The bound address.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `PUB`s received so far.
    pub fn published(&self) -> u64 {
        self.state.published.load(Relaxed)
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.state.stop.store(true, Relaxed);
        // Wake the accept loop so it sees `stop`.
        let _ = TcpStream::connect(self.addr);
    }
}

fn accept(listener: &TcpListener, mode: Mode, state: &Arc<State>) {
    for conn in listener.incoming() {
        if state.stop.load(Relaxed) {
            return;
        }
        let Ok(stream) = conn else { continue };
        let st = state.clone();
        thread::spawn(move || {
            let _ = serve(stream, mode, &st);
        });
    }
}

/// Serves one client until it disconnects or misbehaves.
fn serve(stream: TcpStream, mode: Mode, state: &State) -> Result<(), ConnError> {
    stream.set_nodelay(true)?;
    let out = Arc::new(Mutex::new(stream.try_clone()?));
    write(&out, INFO)?;
    let mut r = FrameReader::new(stream);
    let mut relay = Relay::default();
    let mut source: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        let mut pongs = 0;
        while let Some(f) = r.take_frame()? {
            match f.op {
                Op::Pub | Op::Hpub => {
                    state.published.fetch_add(1, Relaxed);
                    relay.route(state, f.args, f.payload);
                }
                Op::Ping => pongs += 1,
                Op::Sub => {
                    let t = target(f.args, &out)?;
                    if mode == Mode::Relay {
                        lock(&state.targets).push(Arc::new(t));
                    } else {
                        source = Some((t.subject, t.sid));
                    }
                }
                Op::Connect | Op::Pong | Op::Unsub => {}
                op => {
                    let _ = write(&out, b"-ERR 'Unknown Protocol Operation'\r\n");
                    return Err(ConnError::Unexpected(format!("{op:?}")));
                }
            }
        }
        relay.flush(state);
        for _ in 0..pongs {
            write(&out, b"PONG\r\n")?;
        }
        // The client's PING after SUB starts the stream.
        if let (Mode::Source(size), Some((subject, sid))) = (mode, &source)
            && pongs > 0
        {
            return stream_msgs(&out, subject, sid, size);
        }
        if !r.fill()? {
            return Ok(());
        }
    }
}

/// Parses `SUB <subject> [queue] <sid>`.
fn target(args: &[u8], out: &Arc<Mutex<TcpStream>>) -> Result<Target, ConnError> {
    let t: Vec<&[u8]> = wire::tokens(args).collect();
    let (subject, queue, sid) = match t[..] {
        [s, sid] => (s, None, sid),
        [s, q, sid] => (s, Some(q.to_vec()), sid),
        _ => return Err(ConnError::Unexpected(format!("SUB {}", lossy(args)))),
    };
    Ok(Target {
        subject: subject.to_vec(),
        sid: sid.to_vec(),
        queue,
        out: out.clone(),
    })
}

/// Writes stamped `MSG`s until the client goes away.
fn stream_msgs(
    out: &Mutex<TcpStream>,
    subject: &[u8],
    sid: &[u8],
    size: usize,
) -> Result<(), ConnError> {
    let mut template = Vec::new();
    wire::write_msg(&mut template, subject, sid, &wire::filler(size));
    let stamp_at = template.len() - size - 2;
    let per_batch = (SOURCE_BATCH / template.len()).max(1);
    let mut batch = template.repeat(per_batch);
    let mut seq = 0u64;
    let mut w = lock(out).try_clone()?;
    loop {
        for chunk in batch.chunks_exact_mut(template.len()) {
            seq += 1;
            wire::stamp(&mut chunk[stamp_at..], 0, seq);
        }
        w.write_all(&batch)?;
    }
}

/// Per-connection relay buffers, written once per read.
#[derive(Debug, Default)]
struct Relay {
    /// Targets and their `MSG`s, loaded at the first `PUB` of a read.
    pending: Vec<(Arc<Target>, Vec<u8>)>,
    loaded: bool,
    /// Queue groups: key, subject, member indexes into `pending`.
    groups: Vec<(Vec<u8>, Vec<u8>, Vec<usize>)>,
    /// Next member per group key, kept across reads.
    turns: HashMap<Vec<u8>, usize>,
}

impl Relay {
    fn load(&mut self, state: &State) {
        self.pending = lock(&state.targets)
            .iter()
            .map(|t| (t.clone(), Vec::new()))
            .collect();
        self.groups.clear();
        for (i, (t, _)) in self.pending.iter().enumerate() {
            let Some(q) = &t.queue else { continue };
            let key = [&t.subject[..], b" ", q].concat();
            if let Some(g) = self.groups.iter_mut().find(|g| g.0 == key) {
                g.2.push(i);
            } else {
                self.turns.entry(key.clone()).or_default();
                self.groups.push((key, t.subject.clone(), vec![i]));
            }
        }
        self.loaded = true;
    }

    fn route(&mut self, state: &State, args: &[u8], payload: &[u8]) {
        let Some(subject) = wire::tokens(args).next() else {
            return;
        };
        if !self.loaded {
            self.load(state);
        }
        for (t, buf) in &mut self.pending {
            if t.queue.is_none() && t.subject == subject {
                wire::write_msg(buf, subject, &t.sid, payload);
            }
        }
        for (key, group_subject, members) in &self.groups {
            if group_subject != subject {
                continue;
            }
            let Some(turn) = self.turns.get_mut(key) else {
                continue;
            };
            let (t, buf) = &mut self.pending[members[*turn % members.len()]];
            *turn += 1;
            wire::write_msg(buf, subject, &t.sid, payload);
        }
    }

    /// Writes the buffered `MSG`s. Drops targets that fail.
    fn flush(&mut self, state: &State) {
        for (t, buf) in self.pending.drain(..) {
            if !buf.is_empty() && write(&t.out, &buf).is_err() {
                lock(&state.targets).retain(|x| !Arc::ptr_eq(x, &t));
            }
        }
        self.loaded = false;
    }
}

fn write(out: &Mutex<TcpStream>, bytes: &[u8]) -> io::Result<()> {
    lock(out).write_all(bytes)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
