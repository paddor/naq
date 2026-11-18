//! What the integration tests share: ports and directories of their own,
//! servers on the loopback, `nats-server` to check against, a raw client,
//! logs and monitoring.
//!
//! Each test crate uses a part of it.
#![allow(dead_code, reason = "each test crate uses a part")]

use std::fmt::Debug;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use naq::{Cluster, Options, Server};

/// Longest wait for anything these helpers expect.
pub(crate) const WAIT: Duration = Duration::from_secs(10);

/// A free port, each once per run, below the kernel's ephemeral ports
/// (32768 on): a server that binds port 0 cannot take it first.
pub(crate) fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    // Test binaries of other runs start elsewhere.
    let base = 32_000 - (std::process::id() % 400) as u16 * 30;
    loop {
        // Relaxed: only uniqueness matters.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = base - n % 2_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A new, empty directory of its own for test `name` of the tests
/// `prefix`.
pub(crate) fn dir(prefix: &str, name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("naq-{prefix}-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `o` on a free port of the loopback, with `lanes` lanes.
pub(crate) fn local(o: Options, lanes: usize) -> Options {
    Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes,
        ..o
    }
}

/// The ports of `ports` but the `i`th: where server `i` of a cluster on
/// them has its routes to.
pub(crate) fn others(ports: &[u16], i: usize) -> Vec<u16> {
    let mut rest = ports.to_vec();
    rest.remove(i);
    rest
}

/// Cluster `c` for a server on cluster port `port` with routes to
/// `routes`.
pub(crate) fn cluster(port: u16, routes: &[u16]) -> Cluster {
    Cluster {
        name: "c".into(),
        host: "127.0.0.1".into(),
        port,
        routes: routes
            .iter()
            .map(|p| format!("nats-route://127.0.0.1:{p}"))
            .collect(),
    }
}

/// The configuration of server `n{i}` of cluster `c` on `ports`, with
/// routes to the others.
pub(crate) fn member_conf(i: usize, ports: &[u16]) -> String {
    let routes: Vec<String> = others(ports, i)
        .iter()
        .map(|p| format!("\"nats-route://127.0.0.1:{p}\""))
        .collect();
    format!(
        "server_name: n{i}\n\
         cluster {{ name: c, listen: \"127.0.0.1:{}\", routes: [{}] }}\n",
        ports[i],
        routes.join(", ")
    )
}

/// The lines of the log at `path`, once `ready` holds for them.
pub(crate) fn lines_once(path: &Path, ready: impl Fn(&[String]) -> bool) -> Vec<String> {
    let deadline = Instant::now() + WAIT;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if ready(&lines) {
            return lines;
        }
        assert!(Instant::now() < deadline, "log not ready: {lines:#?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Sends signal `sig` to process `pid` with `kill`: whether it went.
pub(crate) fn signal(sig: &str, pid: u32) -> bool {
    Command::new("kill")
        .args(["-s", sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success())
}

/// Sends signal `sig` to process `pid`, which must be there.
pub(crate) fn kill(sig: &str, pid: u32) {
    assert!(signal(sig, pid), "kill -s {sig} {pid}");
}

/// Waits until `at` takes connections.
pub(crate) fn accepts(at: SocketAddr) {
    let deadline = Instant::now() + WAIT;
    while TcpStream::connect(at).is_err() {
        assert!(Instant::now() < deadline, "nothing listens on {at}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Waits until `at` refuses connections.
pub(crate) fn refuses(at: SocketAddr) {
    let deadline = Instant::now() + WAIT;
    while TcpStream::connect(at).is_ok() {
        assert!(Instant::now() < deadline, "{at} still takes clients");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The head and the body of the answer to `GET path` at `at`.
pub(crate) fn fetch(at: SocketAddr, path: &str) -> (String, String) {
    let mut c = TcpStream::connect(at).unwrap();
    c.set_read_timeout(Some(WAIT)).unwrap();
    write!(
        c,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut text = String::new();
    c.read_to_string(&mut text).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (head.to_owned(), body.to_owned())
}

/// The JSON body of the answer to `GET path` at `at`.
pub(crate) fn get(at: SocketAddr, path: &str) -> serde_json::Value {
    serde_json::from_str(&fetch(at, path).1).unwrap()
}

/// A raw client.
pub(crate) struct Client {
    pub(crate) w: TcpStream,
    pub(crate) r: BufReader<TcpStream>,
    /// Its first `INFO`.
    pub(crate) info: serde_json::Value,
}

impl Client {
    /// Connects to `port` on the loopback, and reads its `INFO`.
    pub(crate) fn dial(port: u16) -> Client {
        let w = TcpStream::connect(("127.0.0.1", port)).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let mut r = BufReader::new(w.try_clone().unwrap());
        let mut first = String::new();
        r.read_line(&mut first).unwrap();
        let info = serde_json::from_str(first.strip_prefix("INFO ").unwrap().trim_end()).unwrap();
        Client { w, r, info }
    }

    /// Connects to `port`, and sends `connect` with a `PING`.
    pub(crate) fn open(port: u16, connect: &str) -> Client {
        let mut c = Client::dial(port);
        c.send(&format!("CONNECT {connect}\r\nPING\r\n"));
        c
    }

    /// Connects to `port` with `connect`, and reads up to its `PONG`.
    pub(crate) fn new(port: u16, connect: &str) -> Client {
        let mut c = Client::open(port, connect);
        c.pong();
        c
    }

    pub(crate) fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
    }

    /// The next line; empty once the connection closed.
    pub(crate) fn line(&mut self) -> String {
        let mut line = String::new();
        self.r.read_line(&mut line).unwrap();
        line
    }

    /// Reads up to the next `PONG`, which must come.
    pub(crate) fn pong(&mut self) {
        loop {
            let line = self.line();
            assert!(!line.is_empty(), "closed");
            if line == "PONG\r\n" {
                return;
            }
        }
    }

    /// What it gets until the server closes the connection.
    pub(crate) fn rest(mut self) -> String {
        let mut rest = String::new();
        let _ = self.r.read_to_string(&mut rest);
        rest
    }
}

/// The `nats-server` to check against, if `NAQ_GO` names one.
pub(crate) fn go_bin() -> Option<PathBuf> {
    std::env::var_os("NAQ_GO").map(PathBuf::from)
}

/// A `nats-server` process, killed when it drops.
pub(crate) struct Go {
    pub(crate) child: Child,
    /// Its directory, if it goes with it.
    own: Option<PathBuf>,
}

impl Go {
    /// Runs `bin` with the configuration file `conf`, saying nothing.
    pub(crate) fn run(bin: &Path, conf: &Path) -> Go {
        let child = Command::new(bin)
            .arg("-c")
            .arg(conf)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Go { child, own: None }
    }

    /// Runs `bin` with `conf`, written to `go.conf` in `dir`, for clients
    /// on `port`, and waits until it takes them.
    pub(crate) fn listening(bin: &Path, dir: &Path, port: u16, conf: &str) -> Go {
        let path = dir.join("go.conf");
        std::fs::write(&path, format!("listen: 127.0.0.1:{port}\n{conf}")).unwrap();
        let go = Go::run(bin, &path);
        accepts(SocketAddr::from(([127, 0, 0, 1], port)));
        go
    }

    /// As it is, removing `dir` when it drops.
    pub(crate) fn owning(mut self, dir: PathBuf) -> Go {
        self.own = Some(dir);
        self
    }
}

impl Drop for Go {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(dir) = &self.own {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// A server running a configuration: naq, or `nats-server` and the port
/// of its clients.
pub(crate) enum Target {
    Naq(Server),
    Go(Go, u16),
}

impl Target {
    pub(crate) fn addr(&self) -> SocketAddr {
        match self {
            Target::Naq(s) => s.addr(),
            Target::Go(_, port) => SocketAddr::from(([127, 0, 0, 1], *port)),
        }
    }
}

/// naq running `conf` on a free port, with `lanes` lanes.
pub(crate) fn naq(conf: &str, lanes: usize) -> Server {
    Server::start(&local(conf.parse().unwrap(), lanes)).unwrap()
}

/// naq, then `nats-server` if `NAQ_GO` names one, each running `conf`;
/// `nats-server` in a directory of the tests `prefix`.
pub(crate) fn targets(prefix: &str, conf: &str) -> Vec<(&'static str, Target)> {
    let mut all = vec![("naq", Target::Naq(naq(conf, 2)))];
    if let Some(bin) = go_bin() {
        let port = free_port();
        let d = dir(prefix, &port.to_string());
        let go = Go::listening(&bin, &d, port, conf).owning(d);
        all.push(("go", Target::Go(go, port)));
    }
    all
}

/// Fails unless naq and `nats-server` did the same.
pub(crate) fn same<T: PartialEq + Debug>(naq: &T, go: &T) {
    assert_eq!(naq, go, "naq, then nats-server");
}

/// Runs `script` for naq, with 0 and `None`, then for `nats-server` if
/// `NAQ_GO` names one, with 1 and its path, and has `check` compare what
/// both gave. Returns naq's.
pub(crate) fn both_with<T>(
    mut script: impl FnMut(usize, Option<&Path>) -> T,
    check: impl Fn(&T, &T),
) -> T {
    let naq = script(0, None);
    if let Some(bin) = go_bin() {
        check(&naq, &script(1, Some(&bin)));
    }
    naq
}

/// [`both_with`], where both must give the same.
pub(crate) fn both<T: PartialEq + Debug>(script: impl FnMut(usize, Option<&Path>) -> T) -> T {
    both_with(script, same)
}
