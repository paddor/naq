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
        if matches!(now, OPEN | STALLING) && to.write_all(&buf[..n]).is_err() {
            break;
        }
        if dialer {
            // ZMTP command names come length first.
            let ping = buf[..n].windows(5).any(|w| w == b"\x04PING");
            if now == STALLING && pinged && !ping {
                state.store(STALLED, Ordering::Relaxed);
            }
            pinged |= ping;
        }
    }
    // A blackhole tells of no end either.
    if state.load(Ordering::Relaxed) != BLACKHOLE {
        let _ = to.shutdown(std::net::Shutdown::Both);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.set(STOPPED);
        self.close();
        // Wakes its accept.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}
