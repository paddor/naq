//! The OMQ hop between servers: a lane batches publishes into OMQ messages,
//! a lane of another context takes them apart again, as peers would.
//!
//! The sockets run either on OMQ's own IO thread, which the lanes reach
//! through its socket handles, or on the lanes' runtimes themselves.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use naq_proto::client::{self, Limits, Parsed};
use omq_tokio::{ContextConfig, Endpoint, Message, Options, Socket, SocketType};
use serde::Serialize;
use tokio::sync::oneshot;

/// Messages the sender may have queued in OMQ before it waits.
const HWM: u32 = 64;

/// Where the OMQ sockets run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// On the lanes' runtimes.
    Lane,
    /// On an OMQ IO thread per side.
    Omq,
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "lane" => Ok(Mode::Lane),
            "omq" => Ok(Mode::Omq),
            _ => Err(format!("unknown mode {s:?}")),
        }
    }
}

/// A hop run.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where the sockets run.
    pub mode: Mode,
    /// Payload of each publish.
    pub payload: usize,
    /// Bytes of publishes per OMQ message.
    pub batch: usize,
    /// Before measuring.
    pub warmup: Duration,
    /// Measured.
    pub duration: Duration,
    /// Round trips of one publish, for the latency.
    pub pings: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Lane,
            payload: 16,
            batch: 64 << 10,
            warmup: Duration::from_secs(2),
            duration: Duration::from_secs(10),
            pings: 10_000,
        }
    }
}

/// Rates and latency of a run.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Where the sockets ran.
    pub mode: Mode,
    /// Payload of each publish.
    pub payload: usize,
    /// Bytes of publishes per OMQ message.
    pub batch: usize,
    /// Publishes received per second.
    pub msgs_s: f64,
    /// Publish bytes received per second, in MB.
    pub mb_s: f64,
    /// Round trip of one publish in its own message: median and 99th
    /// percentile, in microseconds.
    pub rtt_p50_us: f64,
    /// See `rtt_p50_us`.
    pub rtt_p99_us: f64,
}

/// Runs the hop: throughput, then latency.
///
/// # Errors
///
/// A message if a lane or socket cannot start or a run fails.
pub fn run(cfg: &Config) -> Result<Report, String> {
    let frame = publish(cfg.payload);
    let n = (cfg.batch / frame.len()).max(1);
    let batch = Bytes::from(frame.repeat(n));
    let (msgs_s, mb_s) = throughput(cfg, batch, frame.len())?;
    let (rtt_p50_us, rtt_p99_us) = latency(cfg, Bytes::from(frame))?;
    Ok(Report {
        mode: cfg.mode,
        payload: cfg.payload,
        batch: cfg.batch,
        msgs_s,
        mb_s,
        rtt_p50_us,
        rtt_p99_us,
    })
}

/// One `PUB` frame.
fn publish(payload: usize) -> Vec<u8> {
    let mut f = format!("PUB bench {payload}\r\n").into_bytes();
    f.extend(std::iter::repeat_n(b'x', payload));
    f.extend_from_slice(b"\r\n");
    f
}

/// Two lanes in contexts of their own, and OMQ contexts when the sockets
/// get a thread.
struct Sides {
    send: zzq_tokio::Context,
    recv: zzq_tokio::Context,
    omq: Option<(omq_tokio::Context, omq_tokio::Context)>,
}

impl Sides {
    fn new(mode: Mode) -> Result<Sides, String> {
        let lane = |name: &str| {
            zzq_tokio::Context::with_config(&zzq_tokio::Config {
                io_threads: 1,
                name: name.into(),
                ..zzq_tokio::Config::default()
            })
            .map_err(|e| format!("lane: {e}"))
        };
        let omq = (mode == Mode::Omq).then(|| {
            let c = || omq_tokio::Context::with_config(ContextConfig { io_threads: 1 });
            (c(), c())
        });
        Ok(Sides {
            send: lane("hop-send")?,
            recv: lane("hop-recv")?,
            omq,
        })
    }

    /// A socket for one side, made on that side's lane.
    fn socket(omq: Option<&omq_tokio::Context>, kind: SocketType) -> Socket {
        let opts = Options {
            send_hwm: HWM,
            recv_hwm: HWM,
            ..Options::default()
        };
        match omq {
            Some(c) => c.socket(kind, opts),
            None => omq_tokio::Context::current().socket(kind, opts),
        }
    }
}

/// A free local TCP endpoint.
fn endpoint() -> Result<Endpoint, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    format!("tcp://127.0.0.1:{port}")
        .parse()
        .map_err(|e| format!("{e}"))
}

/// Publishes received per second, and their megabytes per second.
fn throughput(cfg: &Config, batch: Bytes, frame: usize) -> Result<(f64, f64), String> {
    let sides = Sides::new(cfg.mode)?;
    let at = endpoint()?;
    let got = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (bound, ready) = oneshot::channel();
    {
        let (omq, at, got, stop) = (
            sides.omq.as_ref().map(|o| o.1.clone()),
            at.clone(),
            got.clone(),
            stop.clone(),
        );
        sides
            .recv
            .lane(0)
            .spawn(move || async move {
                let s = Sides::socket(omq.as_ref(), SocketType::Pull);
                let ok = s.bind(at).await.map_err(|e| e.to_string());
                let failed = ok.is_err();
                let _ = bound.send(ok);
                if !failed {
                    count(&s, &got, &stop).await;
                }
            })
            .map_err(|e| e.to_string())?;
    }
    block(ready)??;
    {
        let (omq, stop) = (sides.omq.as_ref().map(|o| o.0.clone()), stop.clone());
        sides
            .send
            .lane(0)
            .spawn(move || async move {
                let s = Sides::socket(omq.as_ref(), SocketType::Push);
                if s.connect(at).await.is_ok() {
                    while !stop.load(Ordering::Relaxed) {
                        if s.send(Message::single(batch.clone())).await.is_err() {
                            return;
                        }
                    }
                }
            })
            .map_err(|e| e.to_string())?;
    }
    std::thread::sleep(cfg.warmup);
    let (t0, n0) = (Instant::now(), got.load(Ordering::Relaxed));
    std::thread::sleep(cfg.duration);
    let (t1, n1) = (Instant::now(), got.load(Ordering::Relaxed));
    stop.store(true, Ordering::Relaxed);
    let rate = (n1 - n0) as f64 / (t1 - t0).as_secs_f64();
    if rate == 0.0 {
        return Err("nothing arrived".into());
    }
    Ok((rate, rate * frame as f64 / 1e6))
}

/// Counts the publishes in each message `s` receives, parsing them as a
/// receiving lane would.
async fn count(s: &Socket, got: &AtomicU64, stop: &AtomicBool) {
    let limits = Limits::default();
    while !stop.load(Ordering::Relaxed) {
        let Ok(m) = s.recv().await else {
            return;
        };
        for part in &m {
            let mut at = 0;
            let mut n = 0;
            while let Ok(Parsed::Op(_, used)) = client::parse(&part[at..], &limits) {
                at += used;
                n += 1;
            }
            // Relaxed: a counter the measuring thread samples.
            got.fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// Median and 99th percentile round trip of `frame` in its own message,
/// echoed by the other lane, in microseconds.
fn latency(cfg: &Config, frame: Bytes) -> Result<(f64, f64), String> {
    let sides = Sides::new(cfg.mode)?;
    let at = endpoint()?;
    let (bound, ready) = oneshot::channel();
    {
        let (omq, at) = (sides.omq.as_ref().map(|o| o.1.clone()), at.clone());
        sides
            .recv
            .lane(0)
            .spawn(move || async move {
                let s = Sides::socket(omq.as_ref(), SocketType::Pair);
                let ok = s.bind(at).await.map_err(|e| e.to_string());
                let failed = ok.is_err();
                let _ = bound.send(ok);
                if failed {
                    return;
                }
                while let Ok(m) = s.recv().await {
                    if s.send(m).await.is_err() {
                        return;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
    }
    block(ready)??;
    let (done, rtts) = oneshot::channel();
    let (omq, pings) = (sides.omq.as_ref().map(|o| o.0.clone()), cfg.pings.max(1));
    sides
        .send
        .lane(0)
        .spawn(move || async move {
            let s = Sides::socket(omq.as_ref(), SocketType::Pair);
            let _ = done.send(pingpong(&s, at, frame, pings).await);
        })
        .map_err(|e| e.to_string())?;
    let mut rtts = block(rtts)??;
    rtts.sort_unstable();
    let pick = |q: f64| rtts[((rtts.len() - 1) as f64 * q) as usize].as_secs_f64() * 1e6;
    Ok((pick(0.5), pick(0.99)))
}

/// Round trips of `frame` over `s`, after a tenth as many to warm up.
async fn pingpong(
    s: &Socket,
    at: Endpoint,
    frame: Bytes,
    pings: usize,
) -> Result<Vec<Duration>, String> {
    s.connect(at).await.map_err(|e| e.to_string())?;
    let mut rtts = Vec::with_capacity(pings);
    for i in 0..pings + pings / 10 {
        let t = Instant::now();
        s.send(Message::single(frame.clone()))
            .await
            .map_err(|e| e.to_string())?;
        s.recv().await.map_err(|e| e.to_string())?;
        if i >= pings / 10 {
            rtts.push(t.elapsed());
        }
    }
    Ok(rtts)
}

/// Waits on the caller's thread for what a lane sends back.
fn block<T>(rx: oneshot::Receiver<T>) -> Result<T, String> {
    rx.blocking_recv().map_err(|_| "a lane stopped".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_cross_with_the_sockets_on_either_side() {
        for mode in [Mode::Lane, Mode::Omq] {
            let r = run(&Config {
                mode,
                payload: 64,
                batch: 4 << 10,
                warmup: Duration::from_millis(50),
                duration: Duration::from_millis(100),
                pings: 50,
            })
            .unwrap();
            assert!(r.msgs_s > 0.0 && r.mb_s > 0.0, "{r:?}");
            assert!(r.rtt_p50_us > 0.0 && r.rtt_p99_us >= r.rtt_p50_us, "{r:?}");
        }
    }

    #[test]
    fn modes_parse_from_their_names() {
        for m in [Mode::Lane, Mode::Omq] {
            let name = serde_json::to_value(m).unwrap();
            assert_eq!(name.as_str().unwrap().parse::<Mode>(), Ok(m));
        }
        assert!("x".parse::<Mode>().is_err());
    }
}
