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
//! - `a! text`: client `a` sends `text` as it is, with the same escapes,
//!   outside WebSocket frames: an upgrade request or frames by hand. A
//!   client whose last step is `!` gets no `PING` of the harness: its
//!   replies are what comes until the server closes, or `(timeout)`.
//! - `#` comments and blank lines, kept as they are. `#! text` is also a
//!   line of the configuration file both servers run with; `$WS_PORT` in it
//!   is a free port.
//!
//! A client whose name starts with `ws` connects to the WebSocket port. If
//! its first step is `!`, that sends the upgrade request and the response
//! is part of the transcript, headers sorted and `Date` left out;
//! otherwise it upgrades quietly. Its `>` and `~` steps go out as a masked
//! frame each, and the frames it gets become what they carry: NATS
//! operations, or `(ping ...)`, `(pong ...)` and `(close status text)`.
//!
//! A client's lines go out in one write when the script moves to another
//! client, and at its end, so the server reads them together whatever the
//! timing. Replies are collected then too: the client that sent last, then
//! every other client in order, each with a `PING` the transcript leaves out. NATS orders the
//! messages of each subscription, not those of different ones: in each
//! client's replies, messages are sorted by SID, each SID's kept in order.
//!
//! `NAQ_GO=<path to nats-server>` also replays every script against Go.
//! With `NAQ_BLESS=1`, Go's replies are written into the scripts. A
//! transcript that differs is written to `CARGO_TARGET_TMPDIR/wire/`.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

#[path = "wire/ws.rs"]
mod ws;

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
        let ws_port = free_port();
        let conf = config(&text).replace("$WS_PORT", &ws_port.to_string());
        let ws_addr = SocketAddr::from(([127, 0, 0, 1], ws_port));
        let mut want = text.clone();
        if let Some(go) = &go {
            let server = GoServer::start(go, &path, &conf);
            let got = replay(&text, server.addr, ws_addr);
            if bless {
                std::fs::write(&path, &got).unwrap();
                want = got;
            } else if got != text {
                failed += &mismatch(&path, "nats-server", &text, &got);
            }
        }
        // naq picks its own WebSocket port: a free port found earlier may be
        // taken by the time it binds.
        let conf = config(&text).replace("$WS_PORT", "-1");
        let opts: naq::Options = conf.parse().unwrap();
        let server = naq::Server::start(&naq::Options {
            host: "127.0.0.1".into(),
            port: 0,
            lanes: 1,
            ..opts
        })
        .unwrap();
        let ws_addr = server.websocket_addr().unwrap_or(ws_addr);
        let got = replay(&want, server.addr(), ws_addr);
        if got != want {
            failed += &mismatch(&path, "naq", &want, &got);
        }
    }
    assert!(failed.is_empty(), "{failed}");
}

/// The configuration in the `#!` lines of `script`.
fn config(script: &str) -> String {
    script
        .lines()
        .filter_map(|l| l.strip_prefix("#!"))
        .map(|l| l.strip_prefix(' ').unwrap_or(l).to_owned() + "\n")
        .collect()
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

/// Where `got` first differs from `want`; writes all of `got` out.
fn mismatch(path: &Path, who: &str, want: &str, got: &str) -> String {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("wire");
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join(format!("{}.{who}", path.file_name().unwrap().display()));
    std::fs::write(&out, got).unwrap();
    let (w, g): (Vec<_>, Vec<_>) = (want.lines().collect(), got.lines().collect());
    let at = w.iter().zip(&g).take_while(|(a, b)| a == b).count();
    let window = |l: &[&str]| l[at.saturating_sub(3)..(at + 4).min(l.len())].join("\n");
    format!(
        "\n{} line {}: {who} differs, all in {}\n--- want\n{}\n--- got\n{}\n",
        path.display(),
        at + 1,
        out.display(),
        window(&w),
        window(&g),
    )
}

/// A port free a moment ago.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Replays `script` against the server at `addr`, with WebSocket clients
/// at `ws_addr`, and returns the script with the replies it got in place of
/// those it had.
fn replay(script: &str, addr: SocketAddr, ws_addr: SocketAddr) -> String {
    let mut run = Run {
        addr,
        ws_addr,
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
        let at = known.unwrap_or_else(|| run.connect(name, kind == '!'));
        run.last = Some(at);
        run.out += line;
        run.out.push('\n');
        let mut bytes = unescape(text);
        if kind == '>' {
            bytes.extend_from_slice(b"\r\n");
        }
        run.clients[at].send(&bytes, kind == '!');
    }
    run.sync_all();
    run.out + &kept
}

/// The client, kind and text of a step line: `a> text`, `a~ text`,
/// `a! text` or `a< text`.
fn step(line: &str) -> Option<(&str, char, &str)> {
    let at = line.find(['>', '~', '!', '<'])?;
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
    ws_addr: SocketAddr,
    clients: Vec<Client>,
    /// The client that sent last.
    last: Option<usize>,
    out: String,
}

impl Run {
    /// Connects client `name`; a WebSocket client upgrades by hand if
    /// `by_hand`.
    fn connect(&mut self, name: &str, by_hand: bool) -> usize {
        let c = if name.starts_with("ws") {
            Client::websocket(name, self.ws_addr, by_hand)
        } else {
            Client::connect(name, self.addr)
        };
        self.clients.push(c);
        self.clients.len() - 1
    }

    /// Collects every client's replies, the last sender's first.
    fn sync_all(&mut self) {
        let first = self.last.unwrap_or(0);
        let order = std::iter::once(first).chain((0..self.clients.len()).filter(|&i| i != first));
        for i in order.collect::<Vec<_>>() {
            let c = &mut self.clients[i];
            for line in by_sid(c.sync()).iter().flatten() {
                let _ = writeln!(self.out, "{}< {line}", c.name);
            }
        }
    }
}

/// `replies` with the messages among them sorted by SID, stably. A message
/// is its control line and its payload.
fn by_sid(replies: Vec<Vec<String>>) -> Vec<Vec<String>> {
    let is_msg = |r: &Vec<String>| r.len() == 2;
    let sid = |r: &Vec<String>| r[0].split(' ').nth(2).unwrap_or_default().to_owned();
    let mut msgs: Vec<_> = replies.iter().filter(|r| is_msg(r)).cloned().collect();
    msgs.sort_by_key(sid);
    let mut msgs = msgs.into_iter();
    replies
        .into_iter()
        .map(|r| if is_msg(&r) { msgs.next().unwrap() } else { r })
        .collect()
}

/// One client connection of a script.
struct Client {
    name: String,
    stream: TcpStream,
    /// Everything sent, to count the `PING`s in it.
    sent: Vec<u8>,
    /// Not written yet.
    pending: Vec<u8>,
    /// How far `sent` has been parsed; `None` after a parse error.
    parsed: Option<usize>,
    /// For each `PING` not answered yet: whether the script sent it.
    pings: std::collections::VecDeque<bool>,
    /// Received, not yet turned into lines.
    buf: Vec<u8>,
    closed: bool,
    /// For a WebSocket client.
    ws: Option<ws::Ws>,
    /// Sends that wait for an upgrade by hand to finish, and whether
    /// they are raw.
    held: Vec<(Vec<u8>, bool)>,
    /// The last send was raw: no `PING` to sync on.
    raw_last: bool,
}

impl Client {
    fn connect(name: &str, addr: SocketAddr) -> Client {
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).unwrap();
        Client {
            name: name.into(),
            stream,
            sent: Vec::new(),
            pending: Vec::new(),
            parsed: Some(0),
            pings: std::collections::VecDeque::new(),
            buf: Vec::new(),
            closed: false,
            ws: None,
            held: Vec::new(),
            raw_last: false,
        }
    }

    /// A WebSocket client, upgraded unless it does it `by_hand`.
    fn websocket(name: &str, addr: SocketAddr, by_hand: bool) -> Client {
        let mut c = Client::connect(name, addr);
        c.ws = Some(if by_hand {
            ws::Ws::default()
        } else {
            ws::Ws::upgrade(&mut c.stream)
        });
        c
    }

    /// Queues `bytes`: in a frame for a WebSocket client, unless `raw`.
    /// Before an upgrade by hand is done, only its request goes out.
    fn send(&mut self, bytes: &[u8], raw: bool) {
        self.raw_last = raw;
        if !raw {
            self.sent.extend_from_slice(bytes);
            self.count_pings();
        }
        match &self.ws {
            Some(w) if !w.up && (!raw || !self.pending.is_empty()) => {
                self.held.push((bytes.to_vec(), raw));
            }
            Some(w) if !raw => self.pending.extend(w.frame(bytes)),
            _ => self.pending.extend_from_slice(bytes),
        }
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

    /// Writes what is pending and reads replies until the server answered
    /// every `PING` or closed. Adds a `PING` of its own, unless what was
    /// sent cannot parse: then the server closes.
    fn sync(&mut self) -> Vec<Vec<String>> {
        let mut lines = Vec::new();
        if self.closed {
            return lines;
        }
        if self.ws.as_ref().is_some_and(|w| !w.up) && !self.upgrade_by_hand(&mut lines) {
            return lines;
        }
        let quiet = std::mem::take(&mut self.raw_last);
        if self.parsed.is_some() && !quiet {
            self.send(b"PING\r\n", false);
            self.pings.pop_back();
            self.pings.push_back(false);
        }
        // A server that closed may reset the connection: the replies show it.
        let _ = self.stream.write_all(&std::mem::take(&mut self.pending));
        let deadline = Instant::now() + WAIT;
        loop {
            self.take_lines(&mut lines);
            if self.pings.is_empty() && self.parsed.is_some() && !quiet {
                return lines;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                lines.push(vec!["(timeout)".into()]);
                return lines;
            };
            self.stream.set_read_timeout(Some(left)).unwrap();
            let mut chunk = [0; 16 << 10];
            match self.stream.read(&mut chunk) {
                Ok(0) => {}
                Ok(n) => {
                    self.feed(&chunk[..n], &mut lines);
                    continue;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue;
                }
                Err(_) => {}
            }
            self.take_lines(&mut lines);
            lines.push(vec!["(closed)".into()]);
            self.closed = true;
            return lines;
        }
    }

    /// Writes the upgrade request the script queued and reads the
    /// response into `lines`. False unless it upgraded.
    fn upgrade_by_hand(&mut self, lines: &mut Vec<Vec<String>>) -> bool {
        let _ = self.stream.write_all(&std::mem::take(&mut self.pending));
        let deadline = Instant::now() + WAIT;
        let ws = self.ws.as_mut().unwrap();
        loop {
            if let Some((http, up)) = ws.http() {
                lines.extend(http.into_iter().map(|l| vec![l]));
                // Refused: the rest is up to the server, as HTTP has it.
                self.closed = !up;
                for (bytes, raw) in std::mem::take(&mut self.held) {
                    let framed = if raw { bytes } else { ws.frame(&bytes) };
                    self.pending.extend(framed);
                }
                return up;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            self.stream
                .set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .unwrap();
            let mut chunk = [0; 16 << 10];
            match self.stream.read(&mut chunk) {
                Ok(n) if n > 0 => ws.feed(&chunk[..n]),
                _ => {
                    lines.push(vec!["(closed)".into()]);
                    self.closed = true;
                    return false;
                }
            }
        }
    }

    /// Takes in bytes received: NATS bytes, or for a WebSocket client,
    /// frames.
    fn feed(&mut self, bytes: &[u8], lines: &mut Vec<Vec<String>>) {
        let Some(w) = self.ws.as_mut() else {
            self.buf.extend_from_slice(bytes);
            return;
        };
        w.feed(bytes);
        for got in w.take() {
            match got {
                ws::Got::Data(d) => self.buf.extend_from_slice(&d),
                ws::Got::Line(l) => {
                    self.take_lines(lines);
                    lines.push(vec![l]);
                }
            }
        }
    }

    /// Turns the complete server operations received into lines, one or
    /// two per operation, leaving out the `PONG`s to the client's own
    /// `PING`s.
    fn take_lines(&mut self, lines: &mut Vec<Vec<String>>) {
        while let Some((op, used)) = server_op(&self.buf) {
            match op {
                Op::Pong => {
                    if self.pings.pop_front() != Some(false) {
                        lines.push(vec!["PONG".into()]);
                    }
                }
                Op::Info(json) => lines.push(vec![info(&json)]),
                Op::Line(l) => lines.push(vec![l]),
                Op::Msg(l, payload) => lines.push(vec![l, payload]),
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
    /// Starts `bin` with configuration `conf` for `script`.
    fn start(bin: &Path, script: &Path, conf: &str) -> GoServer {
        let port = free_port();
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("wire");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(format!("{}.conf", script.file_name().unwrap().display()));
        std::fs::write(&file, conf).unwrap();
        let child = Command::new(bin)
            .args(["-c".as_ref(), file.as_os_str()])
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
