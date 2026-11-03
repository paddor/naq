//! The `naq` binary.

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
    let mut line = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let _proc = Proc(child);
    let addr = line
        .strip_prefix("[naq] Listening for client connections on ")
        .unwrap_or_else(|| panic!("{line:?}"))
        .trim();
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
        &["-a", "127.0.0.1", "-p", "0", "--lanes", "2"],
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
