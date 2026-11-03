//! Codec cost on one core: parsing `PUB`, encoding `MSG`, and both, as a
//! server does for each message it relays.

use std::hint::black_box;
use std::time::{Duration, Instant};

use naq_proto::client::{self, ClientOp, Limits, Parsed};
use naq_proto::encode::Msg;
use serde::Serialize;

/// Input and output buffers hold about this many bytes.
const BUF: usize = 1 << 20;

/// SID of the encoded deliveries.
const SID: &[u8] = b"1";

/// What a run measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kernel {
    /// Parse `PUB` frames from a buffer.
    Parse,
    /// Encode `MSG` frames into a buffer.
    Encode,
    /// Parse a `PUB`, encode its `MSG`.
    Relay,
}

impl Kernel {
    /// Every kernel.
    pub const ALL: [Kernel; 3] = [Kernel::Parse, Kernel::Encode, Kernel::Relay];
}

impl std::str::FromStr for Kernel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "parse" => Ok(Kernel::Parse),
            "encode" => Ok(Kernel::Encode),
            "relay" => Ok(Kernel::Relay),
            _ => Err(format!("unknown kernel {s:?}")),
        }
    }
}

/// A codec run.
#[derive(Debug, Clone)]
pub struct Config {
    /// Subject of every message.
    pub subject: String,
    /// Payload size.
    pub payload: usize,
    /// How long to run.
    pub duration: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            subject: "bench".into(),
            payload: 16,
            duration: Duration::from_secs(3),
        }
    }
}

/// Rates of a run.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// What ran.
    pub kernel: Kernel,
    /// Payload size.
    pub payload: usize,
    /// Messages handled.
    pub msgs: u64,
    /// Seconds measured.
    pub elapsed_s: f64,
    /// Messages per second.
    pub msgs_s: f64,
    /// Nanoseconds per message.
    pub ns_msg: f64,
    /// `PUB` bytes parsed per second, in MB.
    pub in_mb_s: f64,
    /// `MSG` bytes encoded per second, in MB.
    pub out_mb_s: f64,
}

/// Runs `kernel` for the configured duration.
///
/// # Errors
///
/// If the codec rejects the frames, as for a subject over the control
/// line limit.
pub fn run(kernel: Kernel, cfg: &Config) -> Result<Report, String> {
    let (input, frames) = frames(cfg);
    let out_len = Msg {
        subject: cfg.subject.as_bytes(),
        sid: SID,
        reply: None,
        headers: None,
        payload: &input[..0],
    }
    .encoded_len()
        + cfg.payload;
    let in_len = input.len() / frames;
    let mut out = Vec::with_capacity(BUF + out_len);
    let start = Instant::now();
    let deadline = start + cfg.duration;
    let mut msgs = 0u64;
    let payload = vec![0u8; cfg.payload];
    loop {
        match kernel {
            Kernel::Parse => parse_all(&input, |op| {
                black_box(op);
            })?,
            Kernel::Encode => {
                for _ in 0..frames {
                    encode(&mut out, black_box(cfg.subject.as_bytes()), &payload);
                }
            }
            Kernel::Relay => parse_all(&input, |p| {
                encode(&mut out, p.subject, p.payload);
            })?,
        }
        msgs += frames as u64;
        if Instant::now() >= deadline {
            break;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let rate = msgs as f64 / elapsed;
    let (in_mb_s, out_mb_s) = match kernel {
        Kernel::Parse => (rate * in_len as f64 / 1e6, 0.0),
        Kernel::Encode => (0.0, rate * out_len as f64 / 1e6),
        Kernel::Relay => (rate * in_len as f64 / 1e6, rate * out_len as f64 / 1e6),
    };
    Ok(Report {
        kernel,
        payload: cfg.payload,
        msgs,
        elapsed_s: elapsed,
        msgs_s: rate,
        ns_msg: 1e9 / rate,
        in_mb_s,
        out_mb_s,
    })
}

/// About [`BUF`] bytes of whole `PUB` frames, and how many.
fn frames(cfg: &Config) -> (Vec<u8>, usize) {
    let mut frame = format!("PUB {} {}\r\n", cfg.subject, cfg.payload).into_bytes();
    frame.extend(std::iter::repeat_n(b'x', cfg.payload));
    frame.extend_from_slice(b"\r\n");
    let n = (BUF / frame.len()).max(1);
    (frame.repeat(n), n)
}

/// Parses every frame of `input`, handing each publish to `f`.
#[inline]
fn parse_all<'a>(input: &'a [u8], mut f: impl FnMut(client::Pub<'a>)) -> Result<(), String> {
    let limits = Limits {
        max_payload: usize::MAX,
        ..Limits::default()
    };
    let mut at = 0;
    while at < input.len() {
        match client::parse(&input[at..], &limits) {
            Ok(Parsed::Op(ClientOp::Pub(p), used)) => {
                f(p);
                at += used;
            }
            other => return Err(format!("codec rejected its own frames: {other:?}")),
        }
    }
    Ok(())
}

/// Encodes one `MSG`, emptying `out` once it holds [`BUF`] bytes.
#[inline]
fn encode(out: &mut Vec<u8>, subject: &[u8], payload: &[u8]) {
    Msg {
        subject,
        sid: SID,
        reply: None,
        headers: None,
        payload,
    }
    .encode(out);
    if out.len() >= BUF {
        black_box(&out[..]);
        out.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kernel_counts_messages_and_bytes() {
        let cfg = Config {
            duration: Duration::from_millis(20),
            payload: 1024,
            ..Config::default()
        };
        for k in Kernel::ALL {
            let r = run(k, &cfg).unwrap();
            assert!(r.msgs > 0 && r.msgs_s > 0.0 && r.ns_msg > 0.0, "{r:?}");
            assert_eq!(r.in_mb_s > 0.0, k != Kernel::Encode, "{r:?}");
            assert_eq!(r.out_mb_s > 0.0, k != Kernel::Parse, "{r:?}");
        }
    }

    #[test]
    fn a_rejected_frame_is_an_error() {
        let cfg = Config {
            subject: "s".repeat(5000),
            ..Config::default()
        };
        assert!(
            run(Kernel::Relay, &cfg)
                .unwrap_err()
                .contains("ControlLine")
        );
    }

    #[test]
    fn frames_fill_the_buffer_with_whole_publishes() {
        let (input, n) = frames(&Config::default());
        let frame = b"PUB bench 16\r\nxxxxxxxxxxxxxxxx\r\n";
        assert_eq!(input.len(), n * frame.len());
        assert!(input.len() <= BUF && input.len() + frame.len() > BUF);
        let mut count = 0;
        parse_all(&input, |_| count += 1).unwrap();
        assert_eq!(count, n);
    }

    #[test]
    fn kernels_parse_from_their_names() {
        for k in Kernel::ALL {
            let name = serde_json::to_value(k).unwrap();
            assert_eq!(name.as_str().unwrap().parse::<Kernel>(), Ok(k));
        }
        assert!("nope".parse::<Kernel>().is_err());
    }
}
