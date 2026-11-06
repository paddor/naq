//! The `naq` binary.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const NAQ: &str = env!("CARGO_BIN_EXE_naq");

/// The server process, killed on drop.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reads log lines from `r` up to the one that says where clients connect:
/// the address, and the lines before.
fn listening(r: &mut impl BufRead) -> (String, Vec<String>) {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        assert!(
            r.read_line(&mut line).unwrap() > 0,
            "no address in {lines:?}"
        );
        if let Some((_, addr)) = line.split_once("Listening for client connections on ") {
            return (addr.trim().to_owned(), lines);
        }
        lines.push(line);
    }
}

#[test]
fn logs_its_address_and_serves_clients() {
    let mut child = Command::new(NAQ)
        .args([
            "-a",
            "127.0.0.1",
            "--port",
            "0",
            "--lanes",
            "1",
            "--name",
            "t",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (addr, _) = listening(&mut BufReader::new(child.stderr.take().unwrap()));
    let _proc = Proc(child);
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"PING\r\n").unwrap();
    let mut r = BufReader::new(c);
    let mut info = String::new();
    r.read_line(&mut info).unwrap();
    assert!(info.contains(r#""server_name":"t""#), "{info}");
    let mut pong = String::new();
    r.read_line(&mut pong).unwrap();
    assert_eq!(pong, "PONG\r\n");
}

#[test]
fn prints_usage_and_rejects_bad_arguments() {
    let help = Command::new(NAQ).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).starts_with("usage:"));
    for bad in [
        &["--bogus", "1"][..],
        &["-p"],
        &["-p", "x"],
        &["--lanes", "-1"],
    ] {
        let out = Command::new(NAQ).args(bad).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
    }
}

#[test]
fn fails_when_it_cannot_start() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port().to_string();
    for args in [
        &["-a", "127.0.0.1", "-p", &port][..],
        &["-a", "no.such.host.invalid", "-p", "0"],
    ] {
        let mut child = Command::new(NAQ)
            .args(args)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut err = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(1), "{err}");
        assert!(err.starts_with("naq: "), "{err}");
    }
}

#[test]
fn takes_a_configuration_file_that_flags_override() {
    let dir = std::env::temp_dir().join(format!("naq-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("server.conf");
    std::fs::write(&conf, "server_name: fromfile\nport: 1\n").unwrap();
    let mut child = Command::new(NAQ)
        .args(["-c".as_ref(), conf.as_os_str()])
        .args(["-a", "127.0.0.1", "-p", "0", "--lanes", "1"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (addr, _) = listening(&mut BufReader::new(child.stderr.take().unwrap()));
    let _proc = Proc(child);
    let mut r = BufReader::new(TcpStream::connect(addr).unwrap());
    let mut info = String::new();
    r.read_line(&mut info).unwrap();
    assert!(info.contains(r#""server_name":"fromfile""#), "{info}");
    std::fs::write(&conf, "bogus: 1\n").unwrap();
    let out = Command::new(NAQ)
        .args(["-c".as_ref(), conf.as_os_str()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("bogus: not supported"));
    let out = Command::new(NAQ).arg("-c").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn takes_the_flags_nats_server_harnesses_pass() {
    let dir = std::env::temp_dir().join(format!("naq-bin-files-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (log, pid) = (dir.join("naq.log"), dir.join("naq.pid"));
    let child = Command::new(NAQ)
        .args([
            "-a",
            "127.0.0.1",
            "-p",
            "-1",
            "--lanes",
            "1",
            "--store_dir",
            "/nowhere",
        ])
        .args([
            "-l".as_ref(),
            log.as_os_str(),
            "-P".as_ref(),
            pid.as_os_str(),
        ])
        .spawn()
        .unwrap();
    let proc = Proc(child);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let text = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.contains("Server is ready\n") {
            break text;
        }
        assert!(std::time::Instant::now() < deadline, "no log line");
        std::thread::sleep(Duration::from_millis(10));
    };
    let (addr, _) = listening(&mut text.as_bytes());
    assert_ne!(addr, "127.0.0.1:0");
    TcpStream::connect(addr).unwrap();
    assert_eq!(
        std::fs::read_to_string(&pid).unwrap(),
        proc.0.id().to_string()
    );
    drop(proc);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn log_flags_set_the_level_and_the_time() {
    let mut child = Command::new(NAQ)
        .args([
            "-a",
            "127.0.0.1",
            "-p",
            "0",
            "--lanes",
            "1",
            "-DV",
            "-T=false",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut r = BufReader::new(child.stderr.take().unwrap());
    let (addr, before) = listening(&mut r);
    let proc = Proc(child);
    let pid = proc.0.id();
    assert_eq!(before[0], format!("[{pid}] [INF] Starting naq\n"));
    let mut c = TcpStream::connect(&addr).unwrap();
    c.write_all(b"CONNECT {}\r\nPING\r\n").unwrap();
    let mut seen = Vec::new();
    while !seen.iter().any(|l: &String| l.contains("->> [PONG]")) {
        let mut line = String::new();
        assert!(r.read_line(&mut line).unwrap() > 0, "{seen:#?}");
        seen.push(line);
    }
    assert!(
        seen.iter().any(|l| l.contains("[DBG] 127.0.0.1:")),
        "{seen:#?}"
    );
    assert!(
        seen.iter().any(|l| l.contains("[TRC] 127.0.0.1:")),
        "{seen:#?}"
    );
    let out = Command::new(NAQ).args(["-D=maybe"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn takes_the_other_log_flags_of_nats_server() {
    let syslog = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    syslog
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let url = format!("udp://{}", syslog.local_addr().unwrap());
    let child = Command::new(NAQ)
        .args(["-a", "127.0.0.1", "-p", "0", "--lanes", "1", "-r", &url])
        .args(["-s=false", "--logtime_utc", "--log_size_limit=100000"])
        .args(["--max_traced_msg_len", "8", "-V=false"])
        .spawn()
        .unwrap();
    let _running = Proc(child);
    let mut buf = [0; 512];
    let ready = loop {
        let n = syslog.recv(&mut buf).unwrap();
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        if line.contains("Server is ready") {
            break line;
        }
    };
    assert!(ready.starts_with("<5>"), "{ready}");
}
