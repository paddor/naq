//! Command-line parsing and result records for the binaries.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::load::{Config, Report};
use crate::sink::Mode;

/// Usage of `naq_load`.
pub const LOAD_USAGE: &str = "\
usage: naq_load [options]
  --addr HOST:PORT     server (127.0.0.1:4222)
  --pubs N             publisher connections (1)
  --subs N             subscriber connections (1)
  --queue NAME         subscribers join this queue group
  --subject S          subject (bench)
  --payload BYTES      payload size (16)
  --window BYTES       wire bytes in flight (1m)
  --batch BYTES        wire bytes per publisher write (64k)
  --warmup SECS        before measuring (2)
  --duration SECS      measured (10)
  --drain SECS         to deliver the rest after publishing (10)
  --server-pid PID     server process, for its CPU time
  --server NAME        label for the record
  --workload NAME      label for the record
  --tag KEY=VALUE      extra label, repeatable
  --record FILE        append the JSON line if the run is clean
BYTES take k and m suffixes (KiB, MiB).";

/// Usage of `naq_sink`.
pub const SINK_USAGE: &str = "\
usage: naq_sink [--addr HOST:PORT] [--source BYTES]
  Relays PUB to SUB on the same subject; a sink without subscribers.
  --source streams MSGs of that payload size to every subscriber.";

/// Parsed `naq_load` arguments.
#[derive(Debug, Clone, Default)]
pub struct LoadArgs {
    /// The run.
    pub cfg: Config,
    /// Server label.
    pub server: Option<String>,
    /// Workload label.
    pub workload: Option<String>,
    /// Extra labels.
    pub tags: BTreeMap<String, String>,
    /// File to append the record to.
    pub record: Option<PathBuf>,
}

/// Parses `naq_load` arguments.
///
/// # Errors
///
/// A message naming the bad argument.
pub fn load_args(args: &[String]) -> Result<LoadArgs, String> {
    let mut a = LoadArgs::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        let c = &mut a.cfg;
        match flag.as_str() {
            "--addr" => c.addr = parse(flag, val()?)?,
            "--pubs" => c.pubs = parse(flag, val()?)?,
            "--subs" => c.subs = parse(flag, val()?)?,
            "--queue" => c.queue = Some(val()?.clone()),
            "--subject" => c.subject.clone_from(val()?),
            "--payload" => c.payload = size(flag, val()?)?,
            "--window" => c.window = size(flag, val()?)?,
            "--batch" => c.batch = size(flag, val()?)?,
            "--warmup" => c.warmup = secs(flag, val()?)?,
            "--duration" => c.duration = secs(flag, val()?)?,
            "--drain" => c.drain = secs(flag, val()?)?,
            "--server-pid" => c.server_pid = Some(parse(flag, val()?)?),
            "--server" => a.server = Some(val()?.clone()),
            "--workload" => a.workload = Some(val()?.clone()),
            "--tag" => {
                let v = val()?;
                let (k, v) = v
                    .split_once('=')
                    .ok_or_else(|| format!("--tag wants KEY=VALUE, got {v:?}"))?;
                a.tags.insert(k.into(), v.into());
            }
            "--record" => a.record = Some(val()?.into()),
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    Ok(a)
}

/// Parses `naq_sink` arguments.
///
/// # Errors
///
/// A message naming the bad argument.
pub fn sink_args(args: &[String]) -> Result<(SocketAddr, Mode), String> {
    let mut addr = SocketAddr::from(([127, 0, 0, 1], 4222));
    let mut mode = Mode::Relay;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--addr" => addr = parse(flag, val)?,
            "--source" => mode = Mode::Source(size(flag, val)?),
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    Ok((addr, mode))
}

fn parse<T: std::str::FromStr>(flag: &str, v: &str) -> Result<T, String> {
    v.parse().map_err(|_| format!("bad value {v:?} for {flag}"))
}

/// Bytes, with optional `k` or `m` suffix.
fn size(flag: &str, v: &str) -> Result<usize, String> {
    let (num, mul) = match v.as_bytes().last() {
        Some(b'k' | b'K') => (&v[..v.len() - 1], 1 << 10),
        Some(b'm' | b'M') => (&v[..v.len() - 1], 1 << 20),
        _ => (v, 1),
    };
    parse::<usize>(flag, num)?
        .checked_mul(mul)
        .ok_or_else(|| format!("{flag} too large"))
}

/// Seconds, fractions allowed.
fn secs(flag: &str, v: &str) -> Result<Duration, String> {
    let s: f64 = parse(flag, v)?;
    Duration::try_from_secs_f64(s).map_err(|_| format!("bad value {v:?} for {flag}"))
}

/// The JSON record of a run: labels, host and time, then the report.
pub fn record(args: &LoadArgs, report: &Report) -> Value {
    let mut m = Map::new();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    m.insert("ts".into(), ts.into());
    m.insert("host".into(), hostname().into());
    m.insert("server".into(), args.server.clone().into());
    m.insert("workload".into(), args.workload.clone().into());
    let tags: Map<String, Value> = args
        .tags
        .iter()
        .map(|(k, v)| (k.clone(), v.clone().into()))
        .collect();
    m.insert("tags".into(), tags.into());
    if let Ok(Value::Object(r)) = serde_json::to_value(report) {
        m.extend(r);
    }
    Value::Object(m)
}

/// One line for people: rates and CPU.
pub fn summary(report: &Report) -> String {
    let cpu = |c: Option<f64>| c.map_or_else(|| "-".into(), |c| format!("{c:.0}%"));
    format!(
        "pub {:.3}M msgs/s, sub {:.3}M msgs/s ({:.1} MB/s), server cpu {}, load cpu {}, lost {}, out of order {}, corrupt {}",
        report.pub_msgs_s / 1e6,
        report.sub_msgs_s / 1e6,
        report.sub_mb_s,
        cpu(report.server_cpu_pct),
        cpu(report.load_cpu_pct),
        report.lost,
        report.out_of_order,
        report.corrupt,
    )
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses_load_args() {
        let a = load_args(&strings(
            "--addr 127.0.0.1:5000 --pubs 2 --subs 4 --queue q --subject a.b --payload 1k \
             --window 8m --batch 32K --warmup 0.5 --duration 3 --drain 1 --server-pid 7 \
             --server nats --workload fanout --tag rep=1 --tag cpus=0-3 --record /tmp/x.jsonl",
        ))
        .unwrap();
        let c = &a.cfg;
        assert_eq!(c.addr, "127.0.0.1:5000".parse().unwrap());
        assert_eq!((c.pubs, c.subs, c.queue.as_deref()), (2, 4, Some("q")));
        assert_eq!((c.subject.as_str(), c.payload), ("a.b", 1024));
        assert_eq!((c.window, c.batch), (8 << 20, 32 << 10));
        assert_eq!(c.warmup, Duration::from_millis(500));
        assert_eq!(
            (c.duration, c.drain),
            (Duration::from_secs(3), Duration::from_secs(1))
        );
        assert_eq!(c.server_pid, Some(7));
        assert_eq!(
            (a.server.as_deref(), a.workload.as_deref()),
            (Some("nats"), Some("fanout"))
        );
        assert_eq!(a.tags.len(), 2);
        assert_eq!(a.record, Some("/tmp/x.jsonl".into()));
    }

    #[test]
    fn rejects_bad_load_args() {
        for bad in [
            "--pubs",
            "--pubs x",
            "--nope 1",
            "--tag novalue",
            "--payload 99999999999999999999k",
            "--warmup -1",
        ] {
            assert!(load_args(&strings(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_sink_args() {
        let (addr, mode) = sink_args(&strings("--addr 127.0.0.1:1 --source 64")).unwrap();
        assert_eq!((addr.port(), mode), (1, Mode::Source(64)));
        assert_eq!(sink_args(&[]).unwrap().1, Mode::Relay);
        assert!(sink_args(&strings("--addr")).is_err());
        assert!(sink_args(&strings("--x 1")).is_err());
    }

    #[test]
    fn records_labels_and_report() {
        let a = load_args(&strings("--server s --workload w --tag k=v")).unwrap();
        let r = Report {
            server_version: Some("1".into()),
            pubs: 1,
            subs: 1,
            queue: None,
            payload: 16,
            subject: "bench".into(),
            window: 1,
            batch: 1,
            elapsed_s: 1.0,
            pub_msgs_s: 2e6,
            sub_msgs_s: 1e6,
            sub_mb_s: 16.0,
            published: 3,
            delivered: 3,
            lost: 0,
            out_of_order: 0,
            corrupt: 0,
            server_cpu_pct: Some(150.0),
            load_cpu_pct: None,
        };
        let v = record(&a, &r);
        assert_eq!(v["server"], "s");
        assert_eq!(v["tags"]["k"], "v");
        assert_eq!(v["sub_msgs_s"], 1e6);
        assert!(v["ts"].as_u64().unwrap() > 0);
        let s = summary(&r);
        assert!(
            s.starts_with(
                "pub 2.000M msgs/s, sub 1.000M msgs/s (16.0 MB/s), server cpu 150%, load cpu -"
            ),
            "{s}"
        );
    }
}
