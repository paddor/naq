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
    assert_eq!(out.status.code(), Some(1));
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

/// Sends signal `sig` to process `pid` with `kill`.
fn kill(sig: &str, pid: u32) {
    let ok = Command::new("kill")
        .args(["-s", sig, &pid.to_string()])
        .status()
        .unwrap()
        .success();
    assert!(ok, "kill -s {sig} {pid}");
}

/// Reads lines from `r` until one contains `text`; returns them.
fn until(r: &mut impl BufRead, text: &str) -> Vec<String> {
    let mut seen = Vec::new();
    loop {
        let mut line = String::new();
        assert!(
            r.read_line(&mut line).unwrap() > 0,
            "no {text:?} in {seen:#?}"
        );
        let found = line.contains(text);
        seen.push(line);
        if found {
            return seen;
        }
    }
}

#[test]
fn term_shuts_the_server_down_and_usr1_reopens_its_log() {
    let dir = std::env::temp_dir().join(format!("naq-bin-sig-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("naq.log");
    let mut child = Command::new(NAQ)
        .args(["-a", "127.0.0.1", "-p", "0", "--lanes", "1", "-D"])
        .args(["-l".as_ref(), log.as_os_str()])
        .spawn()
        .unwrap();
    let pid = child.id();
    let wait = |text: &str| {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let t = std::fs::read_to_string(&log).unwrap_or_default();
            if t.contains(text) {
                return t;
            }
            assert!(std::time::Instant::now() < deadline, "no {text:?} in {t}");
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let text = wait("Server is ready");
    let (addr, _) = listening(&mut text.as_bytes());
    std::fs::rename(&log, dir.join("old.log")).unwrap();
    kill("USR1", pid);
    wait("File log re-opened");
    let mut c = TcpStream::connect(&addr).unwrap();
    c.write_all(b"CONNECT {}\r\nPING\r\n").unwrap();
    wait("Client connection created");
    kill("TERM", pid);
    assert_eq!(child.wait().unwrap().code(), Some(0));
    let text = std::fs::read_to_string(&log).unwrap();
    for line in [
        "[INF] Trapped \"terminated\" signal",
        "[INF] Initiating Shutdown...",
        "Client connection closed: Server Shutdown",
        "[INF] Server Exiting..",
    ] {
        assert!(text.contains(line), "no {line:?} in {text}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn signal_sends_its_command_to_the_server_its_pid_file_names() {
    let dir = std::env::temp_dir().join(format!("naq-bin-sl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pid_file = dir.join("naq.pid");
    let mut child = Proc(
        Command::new(NAQ)
            .args(["-a", "127.0.0.1", "-p", "0", "--lanes", "1"])
            .args(["-P".as_ref(), pid_file.as_os_str()])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut r = BufReader::new(child.0.stderr.take().unwrap());
    until(&mut r, "Server is ready");
    let reopen = format!("reopen={}", pid_file.display());
    let out = Command::new(NAQ)
        .args(["--signal", &reopen])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    until(&mut r, "File log re-open ignored, not a file logger");
    let quit = format!("quit={}", child.0.id());
    let out = Command::new(NAQ).args(["-sl", &quit]).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    until(&mut r, "Trapped \"interrupt\" signal");
    assert_eq!(child.0.wait().unwrap().code(), Some(0));
    for (spec, err) in [
        ("bogus=1", "naq: unknown signal \"bogus\""),
        ("stop=x", "naq: invalid pid: x"),
        ("stop=1=2", "naq: invalid signal parameters"),
    ] {
        let out = Command::new(NAQ).args(["--signal", spec]).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{spec}");
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(text.starts_with(err), "{spec}: {text}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn version_help_and_checks_answer_without_a_server() {
    let out = Command::new(NAQ).arg("-v").output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("naq: v{}\n", env!("CARGO_PKG_VERSION"))
    );
    for args in [&["version"][..], &["--version"], &["help"], &["--help_tls"]] {
        assert!(
            Command::new(NAQ)
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let dir = std::env::temp_dir().join(format!("naq-bin-t-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("good.conf");
    std::fs::write(&conf, "port: 4333\n").unwrap();
    let out = Command::new(NAQ)
        .args(["-t", "-c"])
        .arg(&conf)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("good.conf is valid (sha256:"), "{text}");
    std::fs::write(&conf, "bogus: 1\n").unwrap();
    let out = Command::new(NAQ)
        .args(["-t", "-c"])
        .arg(&conf)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let out = Command::new(NAQ).arg("-t").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    for (args, code) in [
        (&["extra"][..], 2),
        (&["-js"], 2),
        (&["--tls"], 1),
        (&["--tlscert", "c.pem"], 1),
        (&["--routes", "nats://h:1"], 1),
    ] {
        let out = Command::new(NAQ).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(code), "{args:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn auth_and_cluster_flags_set_what_they_name() {
    let mut child = Command::new(NAQ)
        .args(["-a", "127.0.0.1", "-p", "0", "--lanes", "1"])
        .args([
            "--user",
            "u",
            "--pass",
            "p",
            "--cluster",
            "nats://127.0.0.1:-1",
        ])
        .args(["--cluster_name", "c", "--routes", ""])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut r = BufReader::new(child.stderr.take().unwrap());
    let (addr, before) = listening(&mut r);
    let proc = Proc(child);
    assert!(
        before.iter().any(|l| l.contains("Plaintext passwords")),
        "{before:#?}"
    );
    until(&mut r, "Cluster name is c");
    let mut c = TcpStream::connect(&addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"CONNECT {\"user\":\"u\",\"pass\":\"x\"}\r\nPING\r\n")
        .unwrap();
    let mut got = String::new();
    let _ = c.read_to_string(&mut got);
    assert!(got.contains("-ERR 'Authorization Violation'"), "{got}");
    drop(proc);
}

#[test]
fn a_signal_sent_once_the_pid_file_is_there_is_caught() {
    let dir = std::env::temp_dir().join(format!("naq-bin-early-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for round in 0..20 {
        let pid_file = dir.join(format!("naq-{round}.pid"));
        let mut child = Proc(
            Command::new(NAQ)
                .args(["-a", "127.0.0.1", "-p", "0", "--lanes", "1"])
                .args(["-P".as_ref(), pid_file.as_os_str()])
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        // At once, not by a `kill` that takes a while to start.
        while !pid_file.exists() {
            std::hint::spin_loop();
        }
        let pid = nix::unistd::Pid::from_raw(child.0.id().cast_signed());
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGUSR1).unwrap();
        let mut r = BufReader::new(child.0.stderr.take().unwrap());
        until(&mut r, "Trapped \"user defined signal 1\" signal");
        kill("INT", child.0.id());
        assert_eq!(child.0.wait().unwrap().code(), Some(0), "round {round}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn usr2_puts_the_server_in_lame_duck_mode_which_only_int_cuts_short() {
    let dir = std::env::temp_dir().join(format!("naq-bin-ldm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("naq.conf");
    std::fs::write(
        &conf,
        "lame_duck_duration: 2m\nlame_duck_grace_period: 1m\n",
    )
    .unwrap();
    let mut child = Proc(
        Command::new(NAQ)
            .args(["-a", "127.0.0.1", "-p", "0", "--lanes", "1"])
            .args(["-c".as_ref(), conf.as_os_str()])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    let mut r = BufReader::new(child.0.stderr.take().unwrap());
    let (addr, _) = listening(&mut r);
    until(&mut r, "Server is ready");
    let mut c = TcpStream::connect(&addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"CONNECT {\"protocol\":1}\r\nPING\r\n")
        .unwrap();
    let mut c = BufReader::new(c);
    let mut line = String::new();
    while line != "PONG\r\n" {
        line.clear();
        c.read_line(&mut line).unwrap();
    }
    kill("USR2", pid);
    until(
        &mut r,
        "Entering lame duck mode, stop accepting new clients",
    );
    loop {
        line.clear();
        c.read_line(&mut line).unwrap();
        if line.contains("\"ldm\":true") {
            break;
        }
    }
    // In lame duck mode, TERM and USR2 do nothing; INT stops it at once.
    kill("TERM", pid);
    until(&mut r, "Trapped \"terminated\" signal");
    kill("USR2", pid);
    let since = until(&mut r, "Trapped \"user defined signal 2\" signal");
    assert!(
        !since.iter().any(|l| l.contains("Initiating Shutdown...")),
        "{since:#?}"
    );
    kill("INT", pid);
    let rest = until(&mut r, "Server Exiting..");
    assert!(
        rest.iter().any(|l| l.contains("Initiating Shutdown...")),
        "{rest:#?}"
    );
    assert_eq!(child.0.wait().unwrap().code(), Some(0));
    std::fs::remove_dir_all(&dir).unwrap();
}
