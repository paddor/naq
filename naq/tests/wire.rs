//! Wire scripts in `tests/wire/`, replayed against naq. Each script holds
//! what clients send and, after it, what `nats-server` v2.15.2 replied to
//! the same script; naq must reply the same.
//!
//! A script line is one of:
//!
//! - `a> text`: client `a` sends `text` and CRLF. `a~ text` sends it without
//!   the CRLF. Escapes: `\r`, `\n`, `\t`, `\\`, `\xNN`.
//! - `a< text`: what client `a` got, one server operation per line, a
//!   message's payload on a line of its own. `INFO` keeps only the fields
//!   that do not change between runs. `(closed)` is the server closing.
//! - `#` comments and blank lines, kept as they are.
//!
//! Replies are collected when the script moves from one client to another
//! and at its end: the client that sent last, then every other client in
//! order, each with a `PING` the transcript leaves out.
//!
//! `NAQ_GO=<path to nats-server>` also replays every script against Go.
//! With `NAQ_BLESS=1`, Go's replies are written into the scripts.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use naq_proto::client::{self, ClientOp, Limits, Parsed};

/// Longest wait for the replies to one sync.
const WAIT: Duration = Duration::from_secs(2);

/// `INFO` fields a transcript keeps.
const INFO_KEYS: &[&str] = &[
    "auth_required",
    "client_ip",
    "connect_info",
    "headers",
    "max_payload",
    "nonce",
    "proto",
    "remote_account",
    "tls_available",
    "tls_required",
    "tls_verify",
];

#[test]
fn naq_replies_as_nats_server_does() {
    let go = std::env::var_os("NAQ_GO").map(PathBuf::from);
    let bless = std::env::var_os("NAQ_BLESS").is_some();
    assert!(go.is_some() || !bless, "NAQ_BLESS needs NAQ_GO");
    let mut failed = String::new();
    for path in scripts() {
        let text = std::fs::read_to_string(&path).unwrap();
        let mut want = text.clone();
        if let Some(go) = &go {
            let server = GoServer::start(go);
            let got = replay(&text, server.addr);
            if bless {
                std::fs::write(&path, &got).unwrap();
                want = got;
            } else if got != text {
                failed += &mismatch(&path, "nats-server", &text, &got);
            }
        }
        let server = naq::Server::start(&naq::Options {
            host: "127.0.0.1".into(),
            port: 0,
            lanes: 1,
            ..naq::Options::default()
        })
        .unwrap();
        let got = replay(&want, server.addr());
        if got != want {
            failed += &mismatch(&path, "naq", &want, &got);
        }
    }
    assert!(failed.is_empty(), "{failed}");
}

fn scripts() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wire");
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no scripts");
    paths
}

/// Where `got` first differs from `want`.
fn mismatch(path: &Path, who: &str, want: &str, got: &str) -> String {
    let (w, g): (Vec<_>, Vec<_>) = (want.lines().collect(), got.lines().collect());
    let at = w.iter().zip(&g).take_while(|(a, b)| a == b).count();
    let window = |l: &[&str]| l[at.saturating_sub(3)..(at + 4).min(l.len())].join("\n");
    format!(
        "\n{} line {}: {who} differs\n--- want\n{}\n--- got\n{}\n",
        path.display(),
        at + 1,
        window(&w),
        window(&g),
    )
}

/// Replays `script` against the server at `addr` and returns the script
/// with the replies it got in place of those it had.
fn replay(script: &str, addr: SocketAddr) -> String {
    let mut run = Run {
        addr,
        clients: Vec::new(),
        last: None,
        out: String::new(),
    };
    // Comments and blank lines since the last step: replies go before them.
    let mut kept = String::new();
    for line in script.lines() {
        let Some((name, kind, text)) = step(line) else {
            kept += line;
            kept.push('\n');
            continue;
        };
        if kind == '<' {
            continue;
        }
        let known = run.clients.iter().position(|c| c.name == name);
        if run.last.is_some() && run.last != known {
            run.sync_all();
        }
        run.out += &std::mem::take(&mut kept);
        let at = known.unwrap_or_else(|| run.connect(name));
        run.last = Some(at);
        run.out += line;
        run.out.push('\n');
        let mut bytes = unescape(text);
        if kind == '>' {
            bytes.extend_from_slice(b"\r\n");
        }
        run.clients[at].send(&bytes);
    }
    run.sync_all();
    run.out + &kept
}

/// The client, kind and text of a step line: `a> text`, `a~ text` or
/// `a< text`.
fn step(line: &str) -> Option<(&str, char, &str)> {
    let at = line.find(['>', '~', '<'])?;
    let name = &line[..at];
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let kind = line[at..].chars().next()?;
    let rest = &line[at + 1..];
    Some((name, kind, rest.strip_prefix(' ').unwrap_or(rest)))
}

struct Run {
    addr: SocketAddr,
    clients: Vec<Client>,
    /// The client that sent last.
    last: Option<usize>,
    out: String,
}

impl Run {
    /// Connects client `name`.
    fn connect(&mut self, name: &str) -> usize {
        self.clients.push(Client::connect(name, self.addr));
        self.clients.len() - 1
    }

    /// Collects every client's replies, the last sender's first.
    fn sync_all(&mut self) {
        let first = self.last.unwrap_or(0);
        let order = std::iter::once(first).chain((0..self.clients.len()).filter(|&i| i != first));
        for i in order.collect::<Vec<_>>() {
            let c = &mut self.clients[i];
            for line in c.sync() {
                let _ = writeln!(self.out, "{}< {line}", c.name);
            }
        }
    }
}

/// One client connection of a script.
struct Client {
    name: String,
    stream: TcpStream,
    /// Everything sent, to count the `PING`s in it.
    sent: Vec<u8>,
    /// How far `sent` has been parsed; `None` after a parse error.
    parsed: Option<usize>,
    /// For each `PING` not answered yet: whether the script sent it.
    pings: std::collections::VecDeque<bool>,
    /// Received, not yet turned into lines.
    buf: Vec<u8>,
    closed: bool,
}

impl Client {
    fn connect(name: &str, addr: SocketAddr) -> Client {
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).unwrap();
        Client {
            name: name.into(),
            stream,
            sent: Vec::new(),
            parsed: Some(0),
            pings: std::collections::VecDeque::new(),
            buf: Vec::new(),
            closed: false,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        if self.closed {
            return;
        }
        // A server that closed may reset the connection: the replies show it.
        let _ = self.stream.write_all(bytes);
        self.sent.extend_from_slice(bytes);
        self.count_pings();
    }

    /// Notes the script's `PING`s among the operations sent so far.
    fn count_pings(&mut self) {
        let limits = Limits {
            max_control_line: 1 << 20,
            max_payload: 1 << 30,
        };
        while let Some(at) = self.parsed {
            match client::parse(&self.sent[at..], &limits) {
                Ok(Parsed::Op(op, used)) => {
                    if op == ClientOp::Ping {
                        self.pings.push_back(true);
                    }
                    self.parsed = Some(at + used);
                }
                Ok(Parsed::Partial(_)) => return,
                Err(_) => self.parsed = None,
            }
        }
    }

    /// Reads replies until the server answered every `PING` or closed. Sends
    /// a `PING` of its own first, unless what was sent cannot parse: then
    /// the server closes.
    fn sync(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.closed {
            return lines;
        }
        if self.parsed.is_some() {
            let _ = self.stream.write_all(b"PING\r\n");
            self.pings.push_back(false);
        }
        let deadline = Instant::now() + WAIT;
        loop {
            self.take_lines(&mut lines);
            if self.pings.is_empty() && self.parsed.is_some() {
                return lines;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                lines.push("(timeout)".into());
                return lines;
            };
            self.stream.set_read_timeout(Some(left)).unwrap();
            let mut chunk = [0; 16 << 10];
            match self.stream.read(&mut chunk) {
                Ok(0) => {}
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    continue;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue;
                }
                Err(_) => {}
            }
            self.take_lines(&mut lines);
            lines.push("(closed)".into());
            self.closed = true;
            return lines;
        }
    }

    /// Turns the complete server operations received into lines, leaving
    /// out the `PONG`s to the client's own `PING`s.
    fn take_lines(&mut self, lines: &mut Vec<String>) {
        while let Some((op, used)) = server_op(&self.buf) {
            match op {
                Op::Pong => {
                    if self.pings.pop_front() != Some(false) {
                        lines.push("PONG".into());
                    }
                }
                Op::Info(json) => lines.push(info(&json)),
                Op::Line(l) => lines.push(l),
                Op::Msg(l, payload) => {
                    lines.push(l);
                    lines.push(payload);
                }
            }
            self.buf.drain(..used);
        }
    }
}

enum Op {
    Pong,
    Info(Vec<u8>),
    Line(String),
    /// A message's control line and its payload.
    Msg(String, String),
}

/// The first complete server operation in `buf`, and its length.
fn server_op(buf: &[u8]) -> Option<(Op, usize)> {
    let end = buf.windows(2).position(|w| w == b"\r\n")?;
    let line = &buf[..end];
    if line == b"PONG" {
        return Some((Op::Pong, end + 2));
    }
    if let Some(json) = line.strip_prefix(b"INFO ") {
        return Some((Op::Info(json.to_vec()), end + 2));
    }
    if !(line.starts_with(b"MSG ") || line.starts_with(b"HMSG ")) {
        return Some((Op::Line(escape(line)), end + 2));
    }
    let size: usize = std::str::from_utf8(line.rsplit(|&b| b == b' ').next()?)
        .ok()?
        .parse()
        .ok()?;
    let body = buf.get(end + 2..end + 2 + size)?;
    buf.get(end + 2 + size..end + 4 + size)?;
    Some((Op::Msg(escape(line), escape(body)), end + 4 + size))
}

/// `INFO` with only the fields in [`INFO_KEYS`], a nonce as `*`.
fn info(json: &[u8]) -> String {
    let all: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(json).unwrap();
    let kept: serde_json::Map<_, _> = all
        .into_iter()
        .filter(|(k, _)| INFO_KEYS.contains(&k.as_str()))
        .map(|(k, v)| {
            let v = if k == "nonce" { "*".into() } else { v };
            (k, v)
        })
        .collect();
    format!("INFO {}", serde_json::Value::Object(kept))
}

fn escape(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        match b {
            b'\r' => s += "\\r",
            b'\n' => s += "\\n",
            b'\t' => s += "\\t",
            b'\\' => s += "\\\\",
            0x20..=0x7e => s.push(char::from(b)),
            _ => {
                let _ = write!(s, "\\x{b:02x}");
            }
        }
    }
    s
}

fn unescape(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match bytes.next() {
            Some(b'r') => out.push(b'\r'),
            Some(b'n') => out.push(b'\n'),
            Some(b't') => out.push(b'\t'),
            Some(b'x') => {
                let hex: String = bytes.by_ref().take(2).map(char::from).collect();
                out.push(u8::from_str_radix(&hex, 16).unwrap());
            }
            Some(other) => out.push(other),
            None => out.push(b'\\'),
        }
    }
    out
}

/// A `nats-server` child process, stopped on drop.
struct GoServer {
    child: Child,
    addr: SocketAddr,
}

impl GoServer {
    fn start(bin: &Path) -> GoServer {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = Command::new(bin)
            .args(["-a", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(addr).is_err() {
            assert!(Instant::now() < deadline, "nats-server did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        GoServer { child, addr }
    }
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_round_trip() {
        let raw = b"a\r\n\t\\\x00\xff z";
        assert_eq!(unescape(&escape(raw)), raw);
    }

    #[test]
    fn server_ops_wait_for_whole_messages() {
        assert!(server_op(b"MSG a 1 5\r\nhel").is_none());
        let (op, used) = server_op(b"MSG a 1 5\r\nhello\r\nPONG\r\n").unwrap();
        assert!(matches!(op, Op::Msg(l, p) if l == "MSG a 1 5" && p == "hello"));
        assert_eq!(used, 18);
    }
}
