//! A TCP proxy for tests, to cut, blackhole or stall a link.
//!
//! Each test crate uses a part of it.
#![allow(dead_code, reason = "each test crate uses a part")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// A TCP proxy to a port, to cut or blackhole what goes through it.
pub(crate) struct Proxy {
    pub(crate) port: u16,
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
    conns: std::sync::Arc<std::sync::Mutex<Vec<TcpStream>>>,
}

/// [`Proxy`] states.
pub(crate) const OPEN: u8 = 0;
pub(crate) const CUT: u8 = 1;
pub(crate) const BLACKHOLE: u8 = 2;
pub(crate) const STOPPED: u8 = 3;
/// Reads nothing: what is sent backs up.
pub(crate) const STALLED: u8 = 4;
/// Open until the dialing side sends more after a heartbeat, then
/// [`STALLED`].
pub(crate) const STALLING: u8 = 5;

impl Proxy {
    /// A proxy on a free port of 127.0.0.1 to `port` of `host`.
    pub(crate) fn to(host: &str, port: u16) -> Proxy {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = Proxy {
            port: l.local_addr().unwrap().port(),
            state: std::sync::Arc::default(),
            conns: std::sync::Arc::default(),
        };
        let (state, conns) = (p.state.clone(), p.conns.clone());
        let host = host.to_owned();
        std::thread::spawn(move || {
            for c in l.incoming() {
                // Relaxed: a test switch, nothing else hangs on it.
                let now = state.load(Ordering::Relaxed);
                let Ok(c) = c else { return };
                if now == STOPPED {
                    return;
                }
                if now == CUT {
                    continue;
                }
                let Ok(up) = TcpStream::connect((host.as_str(), port)) else {
                    continue;
                };
                conns
                    .lock()
                    .unwrap()
                    .extend([c.try_clone().unwrap(), up.try_clone().unwrap()]);
                for (from, to, dialer) in [
                    (c.try_clone().unwrap(), up.try_clone().unwrap(), true),
                    (up, c, false),
                ] {
                    let state = state.clone();
                    std::thread::spawn(move || forward(from, to, &state, dialer));
                }
            }
        });
        p
    }

    /// Closes what goes through it, and what comes, until set [`OPEN`].
    pub(crate) fn cut(&self) {
        self.set(CUT);
        self.close();
    }

    /// Its state.
    pub(crate) fn state(&self) -> u8 {
        // Relaxed: a test switch, nothing else hangs on it.
        self.state.load(Ordering::Relaxed)
    }

    fn close(&self) {
        for c in self.conns.lock().unwrap().drain(..) {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Sets its state.
    pub(crate) fn set(&self, state: u8) {
        self.state.store(state, Ordering::Relaxed);
    }
}

/// Copies `from` to `to` as `state` says. Only the `dialer` side, from the
/// server that connects, turns [`STALLING`] into [`STALLED`].
fn forward(
    mut from: TcpStream,
    mut to: TcpStream,
    state: &std::sync::atomic::AtomicU8,
    dialer: bool,
) {
    // Whether this link carried a heartbeat yet.
    let mut pinged = false;
    let mut buf = [0; 16 << 10];
    loop {
        // Relaxed: a test switch, nothing else hangs on it.
        while state.load(Ordering::Relaxed) == STALLED {
            std::thread::sleep(Duration::from_millis(5));
        }
        let Ok(n @ 1..) = from.read(&mut buf) else {
            break;
        };
        let now = state.load(Ordering::Relaxed);
        // Stalling, it passes what comes up to the end of the first frame
        // after a heartbeat, and drops the rest.
        let stall = if dialer {
            past_heartbeat(&buf[..n], &mut pinged).filter(|_| now == STALLING)
        } else {
            None
        };
        let len = stall.unwrap_or(n);
        if matches!(now, OPEN | STALLING) && to.write_all(&buf[..len]).is_err() {
            break;
        }
        if stall.is_some() {
            state.store(STALLED, Ordering::Relaxed);
        }
    }
    // A blackhole tells of no end either.
    if state.load(Ordering::Relaxed) != BLACKHOLE {
        let _ = to.shutdown(std::net::Shutdown::Both);
    }
}

/// Where the first ZMTP frame of `chunk` that is no heartbeat, after one,
/// ends, if one does; `pinged` notes a heartbeat. Frames are taken to start
/// the chunk, as they do on a quiet link; past what it can read, the rest
/// of the chunk counts as one frame.
fn past_heartbeat(chunk: &[u8], pinged: &mut bool) -> Option<usize> {
    let mut at = 0;
    while at < chunk.len() {
        let flags = chunk[at];
        // The flags, then the size: 8 bytes in a long frame, else 1.
        let (head, size) = if flags & 0x02 == 0 {
            (2, chunk.get(at + 1).map(|&s| usize::from(s)))
        } else {
            let long = chunk
                .get(at + 1..at + 9)
                .and_then(|s| <[u8; 8]>::try_from(s).ok());
            (
                9,
                long.map(|s| usize::try_from(u64::from_be_bytes(s)).unwrap_or(usize::MAX)),
            )
        };
        let end = size.map_or(chunk.len(), |s| {
            (at + head).saturating_add(s).min(chunk.len())
        });
        // A command, its name length first.
        let body = chunk.get(at + head..).unwrap_or_default();
        let ping = flags & 0x04 != 0 && body.starts_with(b"\x04PING");
        if *pinged && !ping {
            return Some(end);
        }
        *pinged |= ping;
        at = end;
    }
    None
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.set(STOPPED);
        self.close();
        // Wakes its accept.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}
