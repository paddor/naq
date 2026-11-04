//! A publisher connection: batched `PUB` writes within the shared window.

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::mpsc::Sender;
use std::thread;

use super::{Config, PROBE_EVERY, Ready, Shared, backoff};
use crate::conn::{self, ConnError, FrameReader, lossy};
use crate::wire::{self, Op};

/// Connects, probes until `go`, then publishes until `stop`.
pub(super) fn run(cfg: &Config, id: u32, shared: &Arc<Shared>, ready: &Sender<Ready>) {
    let setup = || -> Result<_, ConnError> {
        let (mut r, info) = conn::handshake(cfg.addr, "naq-load-pub")?;
        r.stream().set_read_timeout(None)?;
        let w = r.stream().try_clone()?;
        Ok((r, w, info))
    };
    let (r, mut w, info) = match setup() {
        Ok(x) => x,
        Err(e) => {
            let _ = ready.send(Err(format!("publisher {id}: {e}")));
            return;
        }
    };
    shared.register(&w);
    let owed = Arc::new(AtomicU32::new(0));
    let watcher = {
        let (shared, owed) = (shared.clone(), owed.clone());
        thread::spawn(move || watch(r, &owed, &shared))
    };
    let _ = ready.send(Ok(info.version));
    if let Err(e) =
        probe(cfg, id, shared, &mut w).and_then(|()| publish(cfg, id, shared, &owed, &mut w))
        && !shared.closing()
    {
        shared.fail(format!("publisher {id}: {e}"));
    }
    shared.pubs_done.fetch_add(1, Relaxed);
    // The watcher reads until the run shuts the stream down.
    let _ = watcher.join();
}

/// Until `go`, publishes a probe every [`PROBE_EVERY`]: a payload one
/// stamp longer than the load's, stamped with `id`. Subscribers note it
/// and do not count it. Without subscribers, only waits.
fn probe(cfg: &Config, id: u32, shared: &Shared, w: &mut TcpStream) -> std::io::Result<()> {
    let frame = (cfg.subs > 0).then(|| {
        let mut payload = wire::filler(cfg.payload + wire::STAMP_LEN);
        wire::stamp(&mut payload, id, 0);
        let mut f = Vec::new();
        wire::write_pub(&mut f, cfg.subject.as_bytes(), &payload);
        f
    });
    while !shared.go.load(Relaxed) && !shared.halted() {
        if let Some(f) = &frame {
            w.write_all(f)?;
        }
        thread::park_timeout(PROBE_EVERY);
    }
    Ok(())
}

/// Writes batches of stamped `PUB` frames while the window has room.
fn publish(
    cfg: &Config,
    id: u32,
    shared: &Shared,
    owed: &AtomicU32,
    w: &mut TcpStream,
) -> std::io::Result<()> {
    let mut template = Vec::new();
    wire::write_pub(
        &mut template,
        cfg.subject.as_bytes(),
        &wire::filler(cfg.payload),
    );
    let frame = template.len();
    let stamp_at = frame - cfg.payload - 2;
    let per_batch = (cfg.batch / frame).max(1) as u64;
    let window = if cfg.subs == 0 {
        u64::MAX
    } else {
        ((cfg.window / frame) as u64).max(per_batch)
    };
    let mut out = Vec::with_capacity(per_batch as usize * frame + 64);
    let mut seq = 0u64;
    loop {
        let n = credit(shared, window, per_batch);
        if n == 0 {
            return Ok(());
        }
        out.clear();
        for _ in 0..owed.swap(0, Relaxed) {
            out.extend_from_slice(b"PONG\r\n");
        }
        for _ in 0..n {
            seq += 1;
            let at = out.len() + stamp_at;
            out.extend_from_slice(&template);
            wire::stamp(&mut out[at..], id, seq);
        }
        shared.sent.0.fetch_add(n, Relaxed);
        w.write_all(&out)?;
    }
}

/// Waits until the window has room for at least half a batch. Returns how
/// many messages to send, 0 once the run stops.
fn credit(shared: &Shared, window: u64, per_batch: u64) -> u64 {
    let want = per_batch.min(window);
    let low = (want / 2).max(1);
    let mut spins = 0;
    loop {
        if shared.halted() {
            return 0;
        }
        let in_flight = shared.sent.0.load(Relaxed).saturating_sub(shared.acked());
        let free = window.saturating_sub(in_flight);
        if free >= low {
            return free.min(want);
        }
        backoff(&mut spins);
    }
}

/// Reads what the server sends a publisher. `PING`s are answered by the
/// writer through `owed`, so that frames never interleave.
fn watch(mut r: FrameReader, owed: &AtomicU32, shared: &Shared) {
    let err = loop {
        match r.take_frame() {
            Ok(Some(f)) => match f.op {
                Op::Ping => {
                    owed.fetch_add(1, Relaxed);
                }
                Op::Info | Op::Ok | Op::Pong => {}
                Op::Err => break format!("server error: {}", lossy(f.args)),
                op => break format!("unexpected {op:?}"),
            },
            Ok(None) => match r.fill() {
                Ok(true) => {}
                Ok(false) => break "connection closed by peer".into(),
                Err(e) => break e.to_string(),
            },
            Err(e) => break e.to_string(),
        }
    };
    if !shared.closing() {
        shared.fail(format!("publisher: {err}"));
    }
}
