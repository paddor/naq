//! The benchmark binaries as processes.

#![expect(clippy::unwrap_used, clippy::panic, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};

const LOAD: &str = env!("CARGO_BIN_EXE_naq_load");
const SINK: &str = env!("CARGO_BIN_EXE_naq_sink");
const CODEC: &str = env!("CARGO_BIN_EXE_naq_codec");
const HOP: &str = env!("CARGO_BIN_EXE_naq_hop");
const INDEX: &str = env!("CARGO_BIN_EXE_naq_index");

/// A sink process, killed on drop.
struct SinkProc(Child, String);

impl SinkProc {
    fn start(extra: &[&str]) -> SinkProc {
        let mut child = Command::new(SINK)
            .args(["--addr", "127.0.0.1:0"])
            .args(extra)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stderr.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let addr = line
            .split("connections on ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or_else(|| panic!("no address in {line:?}"))
            .to_owned();
        SinkProc(child, addr)
    }
}

impl Drop for SinkProc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn load(args: &[&str]) -> std::process::Output {
    Command::new(LOAD).args(args).output().unwrap()
}

#[test]
fn load_records_a_clean_run_against_the_sink() {
    let sink = SinkProc::start(&[]);
    let dir = std::env::temp_dir().join(format!("naq-bins-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let record = dir.join("runs.jsonl");
    let quick = [
        "--warmup",
        "0.05",
        "--duration",
        "0.2",
        "--window",
        "256k",
        "--batch",
        "16k",
    ];
    let pid = sink.0.id().to_string();
    let mut args = vec!["--addr", &sink.1, "--server", "sink", "--server-pid", &pid];
    args.extend(quick);
    args.extend(["--tag", "rep=1", "--record", record.to_str().unwrap()]);
    let out = load(&args);
    assert!(out.status.success(), "{out:?}");
    let line: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(line["server"], "sink");
    assert_eq!(line["tags"]["rep"], "1");
    assert!(line["server_cpu_pct"].as_f64().is_some());
    let saved = std::fs::read_to_string(&record).unwrap();
    assert_eq!(saved.lines().count(), 1);
    assert!(String::from_utf8_lossy(&out.stderr).contains("msgs/s"));

    // A record path that cannot be written fails the run.
    let mut args = vec!["--addr", &sink.1, "--record", "/nonexistent/dir/x.jsonl"];
    args.extend(quick);
    assert_eq!(load(&args).status.code(), Some(1));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn source_feeds_a_subscribe_only_load() {
    let sink = SinkProc::start(&["--source", "64"]);
    let out = load(&[
        "--addr",
        &sink.1,
        "--pubs",
        "0",
        "--payload",
        "64",
        "--warmup",
        "0.05",
        "--duration",
        "0.2",
    ]);
    assert!(out.status.success(), "{out:?}");
}

#[test]
fn bins_print_usage_and_reject_bad_arguments() {
    for bin in [LOAD, SINK, CODEC, HOP, INDEX] {
        let help = Command::new(bin).arg("--help").output().unwrap();
        assert!(help.status.success());
        assert!(String::from_utf8_lossy(&help.stdout).starts_with("usage:"));
        let bad = Command::new(bin).arg("--bogus").output().unwrap();
        assert_eq!(bad.status.code(), Some(2));
    }
}

#[test]
fn load_fails_without_a_server_and_sink_without_its_port() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap().to_string();
    let sink = Command::new(SINK).args(["--addr", &addr]).output().unwrap();
    assert_eq!(sink.status.code(), Some(1));
    drop(taken);
    let out = load(&["--addr", &addr, "--duration", "0.1"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("subscriber 0:"));
}

#[test]
fn load_does_not_record_a_run_with_corrupt_deliveries() {
    use std::io::{Read, Write};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.write_all(b"INFO {}\r\n").unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        let mut line = String::new();
        // CONNECT, PING, SUB, PING.
        for _ in 0..4 {
            line.clear();
            r.read_line(&mut line).unwrap();
            if line.starts_with("PING") {
                s.write_all(b"PONG\r\n").unwrap();
            }
        }
        s.write_all(b"MSG bench 1 3\r\nabc\r\n").unwrap();
        let _ = r.read_to_end(&mut Vec::new());
    });
    let out = load(&[
        "--addr",
        &addr,
        "--pubs",
        "0",
        "--warmup",
        "0",
        "--duration",
        "0.1",
    ]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("not clean"));
}

#[test]
fn codec_records_each_kernel_and_fails_on_rejected_frames() {
    let dir = std::env::temp_dir().join(format!("naq-codec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let record = dir.join("codec.jsonl");
    let out = Command::new(CODEC)
        .args([
            "--duration",
            "0.02",
            "--kernel",
            "parse",
            "--kernel",
            "relay",
        ])
        .args(["--payload", "64", "--record"])
        .arg(&record)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let lines = std::fs::read_to_string(&record).unwrap();
    let kernels: Vec<String> = lines
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["kernel"].to_string())
        .collect();
    assert_eq!(kernels, ["\"parse\"", "\"relay\""]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 2);

    let long = "s".repeat(5000);
    let out = Command::new(CODEC)
        .args(["--duration", "0.01", "--subject", &long])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");

    let out = Command::new(CODEC)
        .args([
            "--duration",
            "0.01",
            "--kernel",
            "encode",
            "--record",
            "/nonexistent/x",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hop_and_index_record_their_runs() {
    let dir = std::env::temp_dir().join(format!("naq-hop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let record = dir.join("runs.jsonl");
    let out = Command::new(HOP)
        .args([
            "--batch",
            "4k",
            "--warmup",
            "0.05",
            "--duration",
            "0.1",
            "--pings",
            "20",
        ])
        .arg("--record")
        .arg(&record)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let out = Command::new(INDEX)
        .args(["--subjects", "3", "--duration", "0.01", "--record"])
        .arg(&record)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let benches: Vec<String> = std::fs::read_to_string(&record)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["bench"].to_string())
        .collect();
    assert_eq!(benches, ["\"hop\"", "\"index\"", "\"index\"", "\"index\""]);
    for bin in [HOP, INDEX] {
        let out = Command::new(bin)
            .args(["--duration", "0.01", "--record", "/nonexistent/x"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{out:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
