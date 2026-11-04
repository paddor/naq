//! A subscriber connection: counts deliveries and checks their order.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::Sender;

use super::{Config, Ready, Shared};
use crate::conn::{self, ConnError, FrameReader, lossy};
use crate::wire::{self, Op};

/// Order and integrity findings of one subscriber.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Stats {
    pub(super) out_of_order: u64,
    pub(super) corrupt: u64,
}

/// Per-publisher sequence check.
#[derive(Debug)]
struct Order {
    payload: usize,
    last: Vec<u64>,
    stats: Stats,
}

impl Order {
    fn new(cfg: &Config) -> Order {
        Order {
            payload: cfg.payload,
            last: vec![0; cfg.pubs.max(1)],
            stats: Stats::default(),
        }
    }

    /// Checks one payload. Returns whether it counts as delivered: a
    /// probe does not, and is noted in `probed`. Gaps are not counted
    /// here: a queue member sees gaps by design, and missing messages
    /// show up in the final count.
    fn check(&mut self, payload: &[u8], probed: &[AtomicBool]) -> bool {
        if payload.len() != self.payload {
            return self.odd(payload, probed);
        }
        let Some((publisher, seq)) = wire::read_stamp(payload) else {
            return true;
        };
        match self.last.get_mut(publisher as usize) {
            Some(last) if seq > *last => *last = seq,
            Some(_) => self.stats.out_of_order += 1,
            None => self.stats.corrupt += 1,
        }
        true
    }

    /// A payload not of the load's size: a probe, else corrupt.
    #[cold]
    #[inline(never)]
    fn odd(&mut self, payload: &[u8], probed: &[AtomicBool]) -> bool {
        if payload.len() == self.payload + wire::STAMP_LEN
            && let Some((publisher, _)) = wire::read_stamp(payload)
            && let Some(heard) = probed.get(publisher as usize)
        {
            heard.store(true, Relaxed);
            return false;
        }
        self.stats.corrupt += 1;
        true
    }
}

/// Connects, subscribes, then counts until the run shuts the stream down.
pub(super) fn run(cfg: &Config, idx: usize, shared: &Shared, ready: &Sender<Ready>) -> Stats {
    let setup = || -> Result<_, ConnError> {
        let (mut r, info) = conn::handshake(cfg.sub_addr(idx), "naq-load-sub")?;
        let sid = idx + 1;
        let sub = match &cfg.queue {
            Some(q) => format!("SUB {} {q} {sid}\r\nPING\r\n", cfg.subject),
            None => format!("SUB {} {sid}\r\nPING\r\n", cfg.subject),
        };
        r.stream().write_all(sub.as_bytes())?;
        conn::expect_pong(&mut r)?;
        r.stream().set_read_timeout(None)?;
        Ok((r, info))
    };
    let (mut r, info) = match setup() {
        Ok(x) => x,
        Err(e) => {
            let _ = ready.send(Err(format!("subscriber {idx}: {e}")));
            return Stats::default();
        }
    };
    shared.register(r.stream());
    let _ = ready.send(Ok(info.version));
    let mut order = Order::new(cfg);
    let probed = shared.probed(idx);
    if let Err(e) = receive(&mut r, &mut order, &shared.received[idx].0, probed)
        && !shared.closing()
    {
        shared.fail(format!("subscriber {idx}: {e}"));
    }
    order.stats
}

/// Reads and counts deliveries. Publishes the count after each read.
fn receive(
    r: &mut FrameReader,
    order: &mut Order,
    count: &AtomicU64,
    probed: &[AtomicBool],
) -> Result<(), ConnError> {
    let mut n = 0u64;
    loop {
        let mut pings = 0;
        while let Some(f) = r.take_frame()? {
            match f.op {
                Op::Msg | Op::Hmsg => n += u64::from(order.check(f.payload, probed)),
                Op::Ping => pings += 1,
                Op::Info | Op::Ok | Op::Pong => {}
                Op::Err => return Err(ConnError::Server(lossy(f.args))),
                op => return Err(ConnError::Unexpected(format!("{op:?}"))),
            }
        }
        count.store(n, Relaxed);
        for _ in 0..pings {
            r.stream().write_all(b"PONG\r\n")?;
        }
        if !r.fill()? {
            return Err(ConnError::Closed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_order_size_and_publisher() {
        let cfg = Config {
            pubs: 2,
            payload: 16,
            ..Config::default()
        };
        let mut o = Order::new(&cfg);
        let probed = [AtomicBool::new(false), AtomicBool::new(false)];
        let msg = |len: usize, p: u32, s: u64| {
            let mut m = wire::filler(len);
            wire::stamp(&mut m, p, s);
            m
        };
        let counted: Vec<bool> = [
            msg(16, 0, 1),
            msg(16, 1, 1),
            msg(16, 0, 3),
            msg(16, 0, 2),
            msg(16, 0, 3),
            msg(16, 2, 1),
            wire::filler(15),
        ]
        .iter()
        .map(|m| o.check(m, &probed))
        .collect();
        assert!(counted.iter().all(|c| *c));
        assert_eq!((o.stats.out_of_order, o.stats.corrupt), (2, 2));
        let tiny = Config {
            payload: 4,
            ..Config::default()
        };
        let mut o = Order::new(&tiny);
        assert!(o.check(b"xxxx", &probed));
        assert_eq!((o.stats.out_of_order, o.stats.corrupt), (0, 0));
    }

    #[test]
    fn probes_are_noted_and_not_counted() {
        let cfg = Config {
            pubs: 2,
            payload: 4,
            ..Config::default()
        };
        let mut o = Order::new(&cfg);
        let probed = [AtomicBool::new(false), AtomicBool::new(false)];
        let probe = |p: u32| {
            let mut m = wire::filler(4 + wire::STAMP_LEN);
            wire::stamp(&mut m, p, 0);
            m
        };
        assert!(!o.check(&probe(1), &probed));
        assert!(!probed[0].load(Relaxed) && probed[1].load(Relaxed));
        assert!(o.check(&probe(2), &probed), "an unknown publisher");
        assert_eq!((o.stats.out_of_order, o.stats.corrupt), (0, 1));
    }
}
