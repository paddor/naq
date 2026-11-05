//! Service latency samples, as `nats-server` sends them for exports with
//! `latency`: which requests get one, and what it says.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime};

use naq_proto::client::Pub;
use serde::Serialize;

use super::info::ClientInfo;
use crate::lane::{Lane, Outs};
use crate::{Latency, Sampling};

/// Headers that asked for a sample, by their canonical names.
pub(crate) type Header = BTreeMap<String, Vec<String>>;

/// What a sampled request keeps until its sample goes out.
#[derive(Debug, Clone)]
pub(crate) struct Track {
    /// The requester, as its import shares it.
    pub(crate) requestor: ClientInfo,
    /// When the request came.
    pub(crate) start: SystemTime,
    pub(crate) at: Instant,
    /// The headers that asked for the sample, if they did.
    pub(crate) header: Option<Header>,
    /// Where the sample goes: the exporting account, and the subject there.
    pub(crate) account: u32,
    pub(crate) subject: Box<[u8]>,
}

/// Why a request gets a sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Why {
    /// Its export samples this share of requests.
    Share,
    /// These trace headers of it asked for one.
    Traced(Header),
}

impl Why {
    /// The headers that asked for the sample, if they did.
    pub(crate) fn header(self) -> Option<Header> {
        match self {
            Why::Share => None,
            Why::Traced(h) => Some(h),
        }
    }
}

/// Why a request with headers `headers` gets a sample, as `l` says, if it
/// does. `random` gives a number below the one it is given.
pub(crate) fn sampled(
    l: &Latency,
    headers: Option<&[u8]>,
    random: impl FnOnce(u64) -> u64,
) -> Option<Why> {
    match l.sampling {
        Sampling::Percent(n) if n >= 100 => return Some(Why::Share),
        // As `nats-server` draws it: `n` percent and one more.
        Sampling::Percent(n) if random(100) <= u64::from(n) => return Some(Why::Share),
        _ => {}
    }
    traced(&parse(headers?)).map(Why::Traced)
}

/// The headers of a header block, by canonical name, as `nats-server`
/// reads them.
fn parse(block: &[u8]) -> Header {
    let mut h = Header::new();
    let text = String::from_utf8_lossy(block);
    for line in text.split("\r\n").skip(1).take_while(|l| !l.is_empty()) {
        if let Some((k, v)) = line.split_once(':') {
            h.entry(canonical(k.trim()))
                .or_default()
                .push(v.trim().to_owned());
        }
    }
    h
}

/// `key` as a MIME header name: each word capitalized, the rest lower.
fn canonical(key: &str) -> String {
    let mut up = true;
    key.chars()
        .map(|c| {
            let c = if up {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            up = c == '-';
            c
        })
        .collect()
}

/// Whether trace headers `h` ask for a sample, as `nats-server` reads
/// Jaeger, B3 and W3C trace context: the first one there decides.
fn traced(h: &Header) -> Option<Header> {
    let first = |k: &str| h.get(k).and_then(|v| v.first()).map(String::as_str);
    let keep = |keys: &[&str]| {
        let kept: Header = keys
            .iter()
            .filter_map(|k| Some(((*k).to_owned(), h.get(*k)?.clone())))
            .collect();
        Some(kept)
    };
    if let Some(id) = first("Uber-Trace-Id") {
        let flags = id
            .split(':')
            .nth(3)
            .filter(|_| id.split(':').count() == 4)?;
        let bits = u8::from_str_radix(flags, 16)
            .ok()
            .filter(|_| flags.len() <= 2)?;
        if bits & 1 == 0 {
            return None;
        }
        let mut kept: Header = h
            .iter()
            .filter(|(k, _)| k.starts_with("Uberctx-"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        kept.insert("Uber-Trace-Id".into(), h["Uber-Trace-Id"].clone());
        return Some(kept);
    }
    let b3 = [
        "X-B3-Sampled",
        "X-B3-Traceid",
        "X-B3-Parentspanid",
        "X-B3-Spanid",
    ];
    match first("X-B3-Sampled") {
        Some("1") => return keep(&b3),
        Some("0") => return None,
        _ if h.contains_key("X-B3-Traceid") => return keep(&b3),
        _ => {}
    }
    if let Some(v) = first("B3") {
        let tokens: Vec<&str> = v.split('-').collect();
        if tokens.get(2) == Some(&"0") || tokens == ["0"] {
            return None;
        }
        return keep(&["B3"]);
    }
    let ctx = first("Traceparent")?;
    let tokens: Vec<&str> = ctx.split('-').collect();
    let flags = tokens
        .get(3)
        .filter(|f| tokens.len() == 4 && f.len() == 2)?;
    let bits = i8::from_str_radix(flags, 16).ok()?;
    (bits & 1 == 1)
        .then(|| keep(&["Traceparent", "Tracestate"]))
        .flatten()
}

/// A latency sample, as `nats-server` writes it.
#[derive(Debug, Serialize)]
struct Sample<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    id: String,
    timestamp: String,
    status: u16,
    #[serde(rename = "description", skip_serializing_if = "str::is_empty")]
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    requestor: Option<&'a ClientInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    responder: Option<&'a ClientInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<&'a Header>,
    start: String,
    /// In nanoseconds, as all three.
    service: u64,
    system: u64,
    total: u64,
}

/// What a sample says of how a request went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Its first response reached the requester (200).
    Answered,
    /// It had no reply (400).
    BadRequest,
    /// Nothing in the exporting account got it (503).
    Unavailable,
    /// No response came within the threshold (504).
    Timeout,
}

/// The sample of the request `t` tracks, which came to `outcome`; for an
/// answer, from `responder` if a client answered.
pub(crate) fn sample(
    lane: &Lane,
    t: &Track,
    outcome: Outcome,
    responder: Option<&ClientInfo>,
) -> Vec<u8> {
    let now = Instant::now();
    let req_rtt = Duration::from_nanos(t.requestor.rtt);
    let (status, error) = match outcome {
        Outcome::Answered => (200, ""),
        Outcome::BadRequest => (400, "Bad Request"),
        Outcome::Unavailable => (503, "Service Unavailable"),
        Outcome::Timeout => (504, "Service Timeout"),
    };
    let (mut service, mut system, mut total) = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    if outcome == Outcome::Answered {
        let elapsed = now.saturating_duration_since(t.at);
        let resp_rtt = Duration::from_nanos(responder.map_or(0, |r| r.rtt));
        service = elapsed.saturating_sub(resp_rtt);
        total = req_rtt + elapsed;
        if !resp_rtt.is_zero() {
            system = now.elapsed();
            total += system;
        }
    }
    let s = Sample {
        kind: "io.nats.server.metric.v1.service_latency",
        id: event_id(lane),
        timestamp: rfc3339_nano(SystemTime::now()),
        status,
        error,
        requestor: Some(&t.requestor),
        responder,
        header: t.header.as_ref(),
        start: rfc3339_nano(t.start.checked_sub(req_rtt).unwrap_or(t.start)),
        service: nanos(service),
        system: nanos(system),
        total: nanos(total),
    };
    serde_json::to_vec(&s).unwrap_or_default()
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// An event ID as `nats-server` makes them: 22 letters or digits.
fn event_id(lane: &Lane) -> String {
    (0..22)
        .map(|_| char::from(super::service::base62(lane.below(62))))
        .collect()
}

/// `t` in RFC 3339 with nanoseconds, UTC, trailing zeros cut, as Go
/// writes a time.
pub(crate) fn rfc3339_nano(t: SystemTime) -> String {
    let full = crate::monitor::rfc3339(t);
    let (whole, fraction) = full
        .trim_end_matches('Z')
        .split_once('.')
        .unwrap_or((&full, ""));
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{whole}Z")
    } else {
        format!("{whole}.{fraction}Z")
    }
}

/// Publishes `payload` on `subject` in `account` from the server itself,
/// with an empty reply, as `nats-server` sends a sample: routed on `lane`,
/// what goes on held in `out`.
pub(crate) fn publish(lane: &Lane, out: &mut Outs, account: u32, subject: &[u8], payload: &[u8]) {
    let p = Pub {
        subject,
        // Empty, not absent: the `MSG` line has two blanks before the size.
        reply: Some(b""),
        headers: None,
        payload,
    };
    crate::lane::inject(lane, out, account, &p);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(text: &str) -> Option<Header> {
        let l = Latency {
            sampling: Sampling::Headers,
            subject: "lat".into(),
        };
        sampled(
            &l,
            Some(format!("NATS/1.0\r\n{text}\r\n\r\n").as_bytes()),
            |_| 0,
        )
        .and_then(Why::header)
    }

    #[test]
    fn trace_headers_ask_for_samples_as_nats_server_reads_them() {
        let got = header("traceparent: 00-4bf9-00f0-01\r\ntracestate: a=b").unwrap();
        assert_eq!(got["Traceparent"], ["00-4bf9-00f0-01"]);
        assert_eq!(got["Tracestate"], ["a=b"]);
        assert_eq!(header("Traceparent: 00-4bf9-00f0-00"), None);
        assert!(
            header("Uber-Trace-Id: 479:5ad:479:1\r\nUberctx-Who: me")
                .unwrap()
                .contains_key("Uberctx-Who")
        );
        assert_eq!(header("Uber-Trace-Id: 479:5ad:479:2"), None);
        assert!(header("X-B3-Sampled: 1").is_some());
        assert_eq!(header("X-B3-Sampled: 0\r\nX-B3-TraceId: 1"), None);
        let b3 = header("X-B3-TraceId: 80f1\r\nx-b3-spanid: 7").unwrap();
        assert_eq!(
            b3.keys().collect::<Vec<_>>(),
            ["X-B3-Spanid", "X-B3-Traceid"]
        );
        assert!(header("B3: 80f1-e457-1-05e3").is_some());
        assert_eq!(header("B3: 80f1-e457-0"), None);
        assert_eq!(header("B3: 0"), None);
        assert_eq!(header("X-Other: 1"), None);
    }

    #[test]
    fn a_percent_samples_one_more_than_it_says() {
        let l = |n| Latency {
            sampling: Sampling::Percent(n),
            subject: "lat".into(),
        };
        assert_eq!(sampled(&l(100), None, |_| 99), Some(Why::Share));
        assert_eq!(sampled(&l(10), None, |_| 10), Some(Why::Share));
        assert_eq!(sampled(&l(10), None, |_| 11), None);
    }

    #[test]
    fn times_are_written_as_go_writes_them() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_millis(1500);
        assert_eq!(rfc3339_nano(t), "1970-01-01T00:00:01.5Z");
        assert_eq!(rfc3339_nano(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(canonical("x-b3-sampled"), "X-B3-Sampled");
    }
}
