//! Stopping a server, and the files it writes of itself.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use naq::{LogTo, Logging, Options, Server};

/// A directory of its own for test `name`.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("naq-stop-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Options of a server on a free port, logging debug lines to `log`.
fn opts(log: &Path) -> Options {
    Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        log: Logging {
            to: Some(LogTo::File(log.to_path_buf())),
            debug: true,
            time: false,
            ..Logging::default()
        },
        ..Options::default()
    }
}

/// A client of `s` that subscribed to `foo` and saw its `PONG`.
fn subscriber(s: &Server) -> BufReader<TcpStream> {
    let mut c = TcpStream::connect(s.addr()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"CONNECT {}\r\nSUB foo 1\r\nPING\r\n").unwrap();
    let mut r = BufReader::new(c);
    let mut line = String::new();
    while line != "PONG\r\n" {
        line.clear();
        r.read_line(&mut line).unwrap();
    }
    r
}

#[test]
fn a_shutdown_closes_clients_after_what_they_were_sent() {
    let d = dir("clients");
    let log = d.join("s.log");
    let s = Server::start(&opts(&log)).unwrap();
    let addr = s.addr();
    let mut sub = subscriber(&s);
    let mut publisher = TcpStream::connect(addr).unwrap();
    publisher
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    publisher
        .write_all(b"CONNECT {}\r\nPUB foo 2\r\nhi\r\nPING\r\n")
        .unwrap();
    // The PONG says the server read the publish.
    let mut publisher = BufReader::new(publisher);
    let mut line = String::new();
    while line != "PONG\r\n" {
        line.clear();
        assert!(publisher.read_line(&mut line).unwrap() > 0, "closed");
    }
    s.shutdown();
    let mut rest = String::new();
    sub.read_to_string(&mut rest).unwrap();
    assert!(rest.ends_with("MSG foo 1 2\r\nhi\r\n"), "{rest:?}");
    assert!(TcpStream::connect(addr).is_err(), "still takes clients");
    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let at = |t: &str| {
        lines
            .iter()
            .position(|l| l.contains(t))
            .unwrap_or(usize::MAX)
    };
    let closed = "Client connection closed: Server Shutdown";
    assert!(at("[INF] Initiating Shutdown...") < at(closed), "{text}");
    assert!(at(closed) < at("[INF] Server Exiting.."), "{text}");
    assert_eq!(
        lines.iter().filter(|l| l.contains(closed)).count(),
        2,
        "{text}"
    );
}

#[test]
fn a_server_writes_its_pid_and_ports_files_and_removes_the_ports_one() {
    let d = dir("files");
    let pid = d.join("naq.pid");
    let s = Server::start(&Options {
        pid_file: Some(pid.clone()),
        ports_file_dir: Some(d.clone()),
        http_port: Some(0),
        ..opts(&d.join("s.log"))
    })
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(&pid).unwrap(),
        std::process::id().to_string()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&pid).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let ports: Vec<PathBuf> = std::fs::read_dir(&d)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "ports"))
        .collect();
    assert_eq!(ports.len(), 1);
    let name = ports[0].file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.ends_with(&format!("_{}.ports", std::process::id())),
        "{name}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ports[0]).unwrap()).unwrap();
    assert_eq!(
        json["nats"],
        serde_json::json!([format!("nats://127.0.0.1:{}", s.addr().port())])
    );
    let monitor = s.monitor_addr().unwrap().port();
    assert_eq!(
        json["monitoring"],
        serde_json::json!([format!("http://127.0.0.1:{monitor}")])
    );
    s.shutdown();
    assert!(!ports[0].exists(), "the ports file stays");
    // As nats-server, it leaves its pid file.
    assert!(pid.exists());
}

#[test]
fn a_server_that_cannot_write_its_pid_file_does_not_start() {
    let d = dir("nopid");
    let e = Server::start(&Options {
        pid_file: Some(d.join("none").join("naq.pid")),
        ..opts(&d.join("s.log"))
    })
    .unwrap_err();
    assert!(matches!(e, naq::Error::Write { .. }), "{e}");
}

#[test]
fn pid_and_ports_keys_come_from_the_file() {
    let o: Options = "pid_file: \"/run/naq.pid\"\nports_file_dir: \"/run\"\n"
        .parse()
        .unwrap();
    assert_eq!(o.pid_file, Some("/run/naq.pid".into()));
    assert_eq!(o.ports_file_dir, Some("/run".into()));
    let o: Options = "pidfile: \"/run/naq.pid\"\n".parse().unwrap();
    assert_eq!(o.pid_file, Some("/run/naq.pid".into()));
}
