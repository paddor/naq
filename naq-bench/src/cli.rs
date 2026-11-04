//! Command-line parsing and result records for the binaries.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::load::{Config, Report};
use crate::sink::Mode;
use crate::suite::{self, Host, Output, Plan, Server, Timing};
use crate::{codec, hop, index};

/// Usage of `naq_load`.
pub const LOAD_USAGE: &str = "\
usage: naq_load [options]
  --addr HOST:PORT     server (127.0.0.1:4222)
  --sub-addr HOST:PORT server of the subscribers, in turn; repeatable
                       (--addr)
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
  --server-pid PID     server process, for its CPU time; repeatable
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

/// Usage of `naq_codec`.
pub const CODEC_USAGE: &str = "\
usage: naq_codec [options]
  --kernel K           parse, encode or relay; repeatable (all)
  --payload BYTES      payload size (16)
  --subject S          subject (bench)
  --duration SECS      per kernel (3)
  --tag KEY=VALUE      extra label, repeatable
  --record FILE        append the JSON lines
BYTES take k and m suffixes (KiB, MiB).";

/// Parsed `naq_codec` arguments.
#[derive(Debug, Clone, Default)]
pub struct CodecArgs {
    /// The runs.
    pub cfg: codec::Config,
    /// Kernels to run, in order. Empty runs all.
    pub kernels: Vec<codec::Kernel>,
    /// Extra labels.
    pub tags: BTreeMap<String, String>,
    /// File to append the records to.
    pub record: Option<PathBuf>,
}

/// Parses `naq_codec` arguments.
///
/// # Errors
///
/// A message naming the bad argument.
pub fn codec_args(args: &[String]) -> Result<CodecArgs, String> {
    let mut a = CodecArgs::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--kernel" => a.kernels.push(val.parse()?),
            "--payload" => a.cfg.payload = size(flag, val)?,
            "--subject" => a.cfg.subject.clone_from(val),
            "--duration" => a.cfg.duration = secs(flag, val)?,
            "--tag" => tag(&mut a.tags, val)?,
            "--record" => a.record = Some(val.into()),
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    if a.kernels.is_empty() {
        a.kernels = codec::Kernel::ALL.to_vec();
    }
    Ok(a)
}

/// The JSON record of a codec run.
pub fn codec_record(args: &CodecArgs, report: &codec::Report) -> Value {
    let mut m = Map::new();
    stamp(&mut m, &args.tags);
    m.insert("bench".into(), "codec".into());
    m.insert("subject".into(), args.cfg.subject.clone().into());
    if let Ok(Value::Object(r)) = serde_json::to_value(report) {
        m.extend(r);
    }
    Value::Object(m)
}

/// Usage of `naq_hop`.
pub const HOP_USAGE: &str = "\
usage: naq_hop [options]
  --mode M             lane: OMQ sockets on the lanes; omq: on OMQ's threads (lane)
  --payload BYTES      payload size (16)
  --batch BYTES        publishes per OMQ message, in bytes (64k)
  --warmup SECS        before measuring (2)
  --duration SECS      measured (10)
  --pings N            round trips for the latency (10000)
  --tag KEY=VALUE      extra label, repeatable
  --record FILE        append the JSON line
BYTES take k and m suffixes (KiB, MiB).";

/// Parsed `naq_hop` arguments.
#[derive(Debug, Clone, Default)]
pub struct HopArgs {
    /// The run.
    pub cfg: hop::Config,
    /// Extra labels.
    pub tags: BTreeMap<String, String>,
    /// File to append the record to.
    pub record: Option<PathBuf>,
}

/// Parses `naq_hop` arguments.
///
/// # Errors
///
/// A message naming the bad argument.
pub fn hop_args(args: &[String]) -> Result<HopArgs, String> {
    let mut a = HopArgs::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let c = &mut a.cfg;
        match flag.as_str() {
            "--mode" => c.mode = val.parse()?,
            "--payload" => c.payload = size(flag, val)?,
            "--batch" => c.batch = size(flag, val)?,
            "--warmup" => c.warmup = secs(flag, val)?,
            "--duration" => c.duration = secs(flag, val)?,
            "--pings" => c.pings = parse(flag, val)?,
            "--tag" => tag(&mut a.tags, val)?,
            "--record" => a.record = Some(val.into()),
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    Ok(a)
}

/// The JSON record of a hop run.
pub fn hop_record(args: &HopArgs, report: &hop::Report) -> Value {
    let mut m = Map::new();
    stamp(&mut m, &args.tags);
    m.insert("bench".into(), "hop".into());
    if let Ok(Value::Object(r)) = serde_json::to_value(report) {
        m.extend(r);
    }
    Value::Object(m)
}

/// Usage of `naq_index`.
pub const INDEX_USAGE: &str = "\
usage: naq_index [options]
  --subjects N         distinct subjects, repeatable (1, 1000, 100000)
  --duration SECS      per kind and size (2)
  --tag KEY=VALUE      extra label, repeatable
  --record FILE        append the JSON lines";

/// Parsed `naq_index` arguments.
#[derive(Debug, Clone)]
pub struct IndexArgs {
    /// Index sizes to measure.
    pub subjects: Vec<usize>,
    /// Per kind and size.
    pub duration: Duration,
    /// Extra labels.
    pub tags: BTreeMap<String, String>,
    /// File to append the records to.
    pub record: Option<PathBuf>,
}

/// Parses `naq_index` arguments.
///
/// # Errors
///
/// A message naming the bad argument.
pub fn index_args(args: &[String]) -> Result<IndexArgs, String> {
    let mut a = IndexArgs {
        subjects: Vec::new(),
        duration: Duration::from_secs(2),
        tags: BTreeMap::new(),
        record: None,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--subjects" => a.subjects.push(parse(flag, val)?),
            "--duration" => a.duration = secs(flag, val)?,
            "--tag" => tag(&mut a.tags, val)?,
            "--record" => a.record = Some(val.into()),
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    if a.subjects.is_empty() {
        a.subjects = vec![1, 1000, 100_000];
    }
    Ok(a)
}

/// The JSON record of an index run.
pub fn index_record(args: &IndexArgs, report: &index::Report) -> Value {
    let mut m = Map::new();
    stamp(&mut m, &args.tags);
    m.insert("bench".into(), "index".into());
    if let Ok(Value::Object(r)) = serde_json::to_value(report) {
        m.extend(r);
    }
    Value::Object(m)
}

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
            "--sub-addr" => c.sub_addrs.push(parse(flag, val()?)?),
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
            "--server-pid" => c.server_pids.push(parse(flag, val()?)?),
            "--server" => a.server = Some(val()?.clone()),
            "--workload" => a.workload = Some(val()?.clone()),
            "--tag" => tag(&mut a.tags, val()?)?,
            "--record" => a.record = Some(val()?.into()),
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    Ok(a)
}

/// Usage of `naq_suite`.
pub const SUITE_USAGE: &str = "\
usage: naq_suite [options]
  The same load against nats-server and naq, fresh servers per run: one,
  or a cluster of three for the cluster workloads. The gate fails when
  naq's rate over nats-server's falls below a floor.
  --gate               only the gated cells
  --workload NAME      only this workload, repeatable: one-to-one,
                       fan-out-4, queue-4, pub-only, cluster-one-to-one,
                       cluster-fan-out-3, cluster-queue-3 (all)
  --nats-server PATH   the rival ($NAQ_GO, else nats-server on PATH)
  --naq PATH           naq (next to naq_suite)
  --load PATH          naq_load (next to naq_suite)
  --lanes N            naq lanes (naq's default: one per core)
  --reps N             runs per server and cell (3)
  --warmup SECS        before measuring (2)
  --duration SECS      measured (10)
  --port PORT          client port of the servers (4222), the next ones
                       for the other servers of a cluster
  --cluster-port PORT  cluster port of the first server of a cluster
                       (6222), the next ones for the others
  --server-cpus LIST   taskset CPUs for the servers (0-3); empty: unpinned
  --load-cpus LIST     taskset CPUs for naq_load (4-5); empty: unpinned
  --busy-ok            skip the idle check, for smoke runs
  --logs DIR           server logs (naq-suite in the temp dir)
  --record FILE        append each run's JSON line
  --tag KEY=VALUE      extra label, repeatable";

/// The suite's defaults: binaries in `bins`, the rival at `go` or on the
/// `PATH`.
fn suite_plan(bins: &Path, go: Option<PathBuf>) -> Plan {
    let server = |name: &str, program: PathBuf| Server {
        name: name.into(),
        program,
        args: Vec::new(),
    };
    Plan {
        rival: server("nats-server", go.unwrap_or_else(|| "nats-server".into())),
        naq: server("naq", bins.join("naq")),
        load: bins.join("naq_load"),
        cells: Vec::new(),
        timing: Timing {
            reps: 3,
            warmup: Duration::from_secs(2),
            duration: Duration::from_secs(10),
        },
        host: Host {
            port: 4222,
            cluster_port: 6222,
            server_cpus: "0-3".into(),
            load_cpus: "4-5".into(),
            idle_check: true,
        },
        out: Output {
            logs: std::env::temp_dir().join("naq-suite"),
            record: None,
            tags: BTreeMap::new(),
        },
    }
}

/// Parses `naq_suite` arguments. Binaries default to `bins`, the rival to
/// `go`.
///
/// # Errors
///
/// A message naming the bad argument.
pub fn suite_args(args: &[String], bins: &Path, go: Option<PathBuf>) -> Result<Plan, String> {
    let mut p = suite_plan(bins, go);
    let (mut names, mut gated) = (Vec::new(), false);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--gate" => gated = true,
            "--busy-ok" => p.host.idle_check = false,
            "--workload" => names.push(val()?.clone()),
            "--nats-server" => p.rival.program = val()?.into(),
            "--naq" => p.naq.program = val()?.into(),
            "--load" => p.load = val()?.into(),
            "--lanes" => {
                let n: usize = parse(flag, val()?)?;
                p.naq.args = vec!["--lanes".into(), n.to_string()];
            }
            "--reps" => p.timing.reps = parse(flag, val()?)?,
            "--warmup" => p.timing.warmup = secs(flag, val()?)?,
            "--duration" => p.timing.duration = secs(flag, val()?)?,
            "--port" => p.host.port = parse(flag, val()?)?,
            "--cluster-port" => p.host.cluster_port = parse(flag, val()?)?,
            "--server-cpus" => p.host.server_cpus.clone_from(val()?),
            "--load-cpus" => p.host.load_cpus.clone_from(val()?),
            "--logs" => p.out.logs = val()?.into(),
            "--record" => p.out.record = Some(val()?.into()),
            "--tag" => tag(&mut p.out.tags, val()?)?,
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    if p.timing.reps == 0 || p.host.port == 0 || p.host.cluster_port == 0 {
        return Err("--reps, --port and --cluster-port must not be 0".into());
    }
    p.cells = suite::cells(&names, gated)?;
    Ok(p)
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

/// Adds a `KEY=VALUE` label.
fn tag(tags: &mut BTreeMap<String, String>, v: &str) -> Result<(), String> {
    let (k, v) = v
        .split_once('=')
        .ok_or_else(|| format!("--tag wants KEY=VALUE, got {v:?}"))?;
    tags.insert(k.into(), v.into());
    Ok(())
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
    stamp(&mut m, &args.tags);
    m.insert("server".into(), args.server.clone().into());
    m.insert("workload".into(), args.workload.clone().into());
    if let Ok(Value::Object(r)) = serde_json::to_value(report) {
        m.extend(r);
    }
    Value::Object(m)
}

/// Time, host and labels of a record.
fn stamp(m: &mut Map<String, Value>, tags: &BTreeMap<String, String>) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    m.insert("ts".into(), ts.into());
    m.insert("host".into(), hostname().into());
    let tags: Map<String, Value> = tags
        .iter()
        .map(|(k, v)| (k.clone(), v.clone().into()))
        .collect();
    m.insert("tags".into(), tags.into());
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
             --sub-addr 127.0.0.1:5001 --server-pid 8 --sub-addr 127.0.0.1:5002 \
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
        assert_eq!(c.server_pids, [7, 8]);
        assert_eq!(
            c.sub_addrs,
            [
                "127.0.0.1:5001".parse().unwrap(),
                "127.0.0.1:5002".parse().unwrap()
            ]
        );
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
    fn parses_codec_args() {
        let a = codec_args(&strings(
            "--kernel relay --kernel parse --payload 1k --subject a.b --duration 0.5 \
             --tag rep=2 --record /tmp/c.jsonl",
        ))
        .unwrap();
        assert_eq!(a.kernels, [codec::Kernel::Relay, codec::Kernel::Parse]);
        assert_eq!((a.cfg.payload, a.cfg.subject.as_str()), (1024, "a.b"));
        assert_eq!(a.cfg.duration, Duration::from_millis(500));
        assert_eq!(a.record, Some("/tmp/c.jsonl".into()));
        assert_eq!(codec_args(&[]).unwrap().kernels, codec::Kernel::ALL);
        for bad in ["--kernel x", "--payload", "--tag x", "--nope 1"] {
            assert!(codec_args(&strings(bad)).is_err(), "{bad}");
        }
        let r = codec::run(
            codec::Kernel::Parse,
            &codec::Config {
                duration: Duration::from_millis(5),
                ..a.cfg.clone()
            },
        )
        .unwrap();
        let v = codec_record(&a, &r);
        assert_eq!(
            (v["bench"].as_str(), v["kernel"].as_str()),
            (Some("codec"), Some("parse"))
        );
        assert_eq!(
            (v["subject"].as_str(), v["tags"]["rep"].as_str()),
            (Some("a.b"), Some("2"))
        );
    }

    #[test]
    fn parses_hop_args() {
        let a = hop_args(&strings(
            "--mode omq --payload 1k --batch 256k --warmup 0 --duration 1 --pings 10 \
         --tag rep=1 --record /tmp/h.jsonl",
        ))
        .unwrap();
        let c = &a.cfg;
        assert_eq!(
            (c.mode, c.payload, c.batch, c.pings),
            (hop::Mode::Omq, 1024, 256 << 10, 10)
        );
        assert_eq!(
            (c.warmup, c.duration),
            (Duration::ZERO, Duration::from_secs(1))
        );
        assert_eq!(a.record, Some("/tmp/h.jsonl".into()));
        for bad in ["--mode x", "--pings", "--pings x", "--nope 1", "--tag x"] {
            assert!(hop_args(&strings(bad)).is_err(), "{bad}");
        }
        let r = hop::Report {
            mode: hop::Mode::Lane,
            payload: 16,
            batch: 1,
            msgs_s: 1.0,
            mb_s: 1.0,
            rtt_p50_us: 1.0,
            rtt_p99_us: 2.0,
        };
        let v = hop_record(&a, &r);
        assert_eq!(
            (v["bench"].as_str(), v["mode"].as_str()),
            (Some("hop"), Some("lane"))
        );
        assert_eq!(v["tags"]["rep"].as_str(), Some("1"));
    }

    #[test]
    fn parses_index_args() {
        let a = index_args(&strings(
            "--subjects 5 --subjects 7 --duration 0.01 --tag k=v",
        ))
        .unwrap();
        assert_eq!(a.subjects, [5, 7]);
        assert_eq!(index_args(&[]).unwrap().subjects, [1, 1000, 100_000]);
        for bad in ["--subjects x", "--duration", "--nope 1"] {
            assert!(index_args(&strings(bad)).is_err(), "{bad}");
        }
        let r = index::run(index::Kind::Hash, 3, a.duration);
        let v = index_record(&a, &r);
        assert_eq!(
            (v["bench"].as_str(), v["kind"].as_str()),
            (Some("index"), Some("hash"))
        );
    }

    #[test]
    fn parses_suite_args() {
        let bins = Path::new("/b");
        let p = suite_args(&[], bins, None).unwrap();
        assert_eq!(p.rival.program, Path::new("nats-server"));
        assert_eq!(
            (p.naq.program.as_path(), p.load.as_path()),
            (Path::new("/b/naq"), Path::new("/b/naq_load"))
        );
        assert_eq!((p.cells.len(), p.timing.reps, p.host.port), (15, 3, 4222));
        assert_eq!(p.host.cluster_port, 6222);
        assert!(p.host.idle_check && p.naq.args.is_empty());
        let p = suite_args(
            &strings(
                "--gate --busy-ok --workload one-to-one --nats-server /g --naq /n --load /l \
                 --lanes 2 --reps 5 --warmup 0.5 --duration 3 --port 5000 --server-cpus 0-1 \
                 --load-cpus 2 --logs /logs --record /r.jsonl --tag k=v --cluster-port 7000",
            ),
            bins,
            Some("/go".into()),
        )
        .unwrap();
        assert_eq!(p.rival.program, Path::new("/g"));
        assert_eq!(
            (p.naq.program.as_path(), p.load.as_path()),
            (Path::new("/n"), Path::new("/l"))
        );
        assert_eq!(p.naq.args, ["--lanes", "2"]);
        assert_eq!((p.cells.len(), p.timing.reps), (3, 5));
        assert_eq!(
            (p.timing.warmup, p.timing.duration),
            (Duration::from_millis(500), Duration::from_secs(3))
        );
        assert_eq!(
            (
                p.host.port,
                p.host.server_cpus.as_str(),
                p.host.load_cpus.as_str()
            ),
            (5000, "0-1", "2")
        );
        assert_eq!(p.host.cluster_port, 7000);
        assert!(!p.host.idle_check);
        assert_eq!(p.out.logs, Path::new("/logs"));
        assert_eq!(p.out.record, Some("/r.jsonl".into()));
        assert_eq!(p.out.tags["k"], "v");
        let go = suite_args(&[], bins, Some("/go".into())).unwrap();
        assert_eq!(go.rival.program, Path::new("/go"));
        for bad in [
            "--reps 0",
            "--port 0",
            "--cluster-port 0",
            "--port 70000",
            "--lanes x",
            "--workload nope",
            "--gate --workload pub-only",
            "--record",
            "--nope",
        ] {
            assert!(suite_args(&strings(bad), bins, None).is_err(), "{bad}");
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
