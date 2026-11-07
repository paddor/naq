//! Monitoring scripts in `tests/endpoints/`, replayed against naq. Each
//! script holds what clients send and the requests to the monitoring port
//! and, after each request, what `nats-server` v2.15.2 answered to the
//! same script; naq must answer the same.
//!
//! A script line is one of:
//!
//! - `a> text`: client `a` sends `text`, with `\r`, `\n` and `\\` escapes,
//!   and CRLF; `a>` sends an empty line. It connects on first use.
//!   Before the next request, every client's lines go out with a `PING`,
//!   and its replies are read up to the `PONG` and dropped.
//! - `a< n`: client `a` sends what it has with a `PING` and waits until it
//!   got `n` messages, or for a moment if `n` is 0, and every message it
//!   got shows: its control line without the sizes, its headers, and its
//!   payload, as an answer body is shown, decoded if compressed.
//!   `$SERVER_ID` in a client's line, and in what it got, is the ID of
//!   the server, `$CID_a`
//!   that of client `a`; a size `$LEN` at the end of a `PUB` is that of
//!   the client's next line.
//! - `a.`: client `a` sends what it has, then closes its connection, and
//!   the harness waits until `/connz?state=closed` lists it. Before the
//!   next request,
//!   the harness waits until `/connz?state=closed` lists every client that
//!   closed or was closed; those requests are not in the transcript.
//! - `GET /path?query`: a request to the monitoring port, any method;
//!   `HEAD /path` too. `$CID_a` in it is the ID of client `a`, as its
//!   `INFO` gave it. `RAW text` sends `text` as it is, with `\r`, `\n`
//!   and `\\` escapes, and records all that comes back.
//! - `< text`: a line of the answer. The status line, then the headers
//!   that do not change between runs, sorted, a blank line and the body.
//!   In an indented JSON body, the values of keys that change between
//!   runs or servers are `~`, and the keys naq leaves out are gone. Lists
//!   in an order Go leaves open are sorted.
//! - `#` comments and blank lines, kept as they are. `#! text` is also a
//!   line of the configuration file both servers run with; `$CERTS` in it
//!   is a directory with a CA (`ca.pem`) and a certificate for 127.0.0.1
//!   (`server.pem`, `server-key.pem`). `#~ key` masks one more key for
//!   the script, `#- key` drops one, `#= key` sorts its list.
//!
//! `NAQ_GO=<path to nats-server>` also replays every script against Go.
//! With `NAQ_BLESS=1`, Go's answers are written into the scripts, and
//! naq is not replayed. A
//! transcript that differs is written to `CARGO_TARGET_TMPDIR/endpoints/`.
//! `NAQ_ENDPOINTS=<text>` replays only the scripts whose names hold it.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);

/// Keys whose values change between runs or servers, wherever they are.
const MASKED: &[&str] = &[
    "server_id",
    "now",
    "start",
    "uptime",
    "idle",
    "rtt",
    "last_activity",
    // Go counts what it has yet to write when it is asked, a PONG too.
    "pending_bytes",
    "stop",
    "update_time",
    "mem",
    "cpu",
    "cores",
    "gomaxprocs",
    "config_load_time",
    "config_digest",
    "remote_id",
    "tls_cert_not_after",
    "port",
    "http_port",
    "https_port",
    "cluster_port",
    "cid",
];

/// Keys masked at the top level only: elsewhere they hold what clients
/// sent, or what the script made.
const TOP_MASKED: &[&str] = &["version", "go", "subscriptions"];

/// Keys naq leaves out, wherever they are: Go facts naq has no part of.
const DROPPED: &[&str] = &["git_commit", "feature_flags", "pool_size"];

/// Keys of lists in an order Go leaves open: they are sorted.
const UNORDERED: &[&str] = &["subscriptions_list", "subscriptions_list_detail"];

/// Headers a transcript keeps.
const HEADERS: &[&str] = &[
    "access-control-allow-origin",
    "connection",
    "content-type",
    "location",
    "x-content-type-options",
];

#[test]
fn naq_answers_as_nats_server_does() {
    let go = std::env::var_os("NAQ_GO").map(PathBuf::from);
    let bless = std::env::var_os("NAQ_BLESS").is_some();
    assert!(go.is_some() || !bless, "NAQ_BLESS needs NAQ_GO");
    let mut failed = String::new();
    let certs = certs();
    for path in scripts() {
        let text = std::fs::read_to_string(&path).unwrap();
        let mut script = Script::parse(&text);
        script.conf = script.conf.replace("$CERTS", &certs.display().to_string());
        let want = text.clone();
        if let Some(go) = &go {
            let server = GoServer::start(go, &path, &script);
            let got = script.replay(server.client, server.monitor);
            if bless {
                std::fs::write(&path, &got).unwrap();
                continue;
            } else if got != text {
                failed += &mismatch(&path, "nats-server", &text, &got);
            }
        }
        let opts: naq::Options = script.conf.parse().unwrap();
        let secure = opts.https_port.is_some();
        let server = naq::Server::start(&naq::Options {
            host: "127.0.0.1".into(),
            port: 0,
            lanes: 2,
            http_port: (!secure).then_some(0),
            https_port: secure.then_some(0),
            ..opts
        })
        .unwrap();
        let got = script.replay(server.addr(), server.monitor_addr().unwrap());
        if got != want {
            failed += &mismatch(&path, "naq", &want, &got);
        }
    }
    assert!(failed.is_empty(), "{failed}");
}

fn scripts() -> Vec<PathBuf> {
    let only = std::env::var("NAQ_ENDPOINTS").ok();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/endpoints");
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .filter(|p| {
            only.as_ref()
                .is_none_or(|o| p.to_string_lossy().contains(o.as_str()))
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no scripts");
    paths
}

/// A directory with a CA and a certificate it signed for 127.0.0.1.
fn certs() -> PathBuf {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("endpoints/certs");
    std::fs::create_dir_all(&dir).unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .unwrap()
        .signed_by(&key, &Issuer::from_params(&ca, &ca_key))
        .unwrap();
    std::fs::write(dir.join("server.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("server-key.pem"), key.serialize_pem()).unwrap();
    dir
}

/// Where `got` first differs from `want`; writes all of `got` out.
fn mismatch(path: &Path, who: &str, want: &str, got: &str) -> String {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("endpoints");
    std::fs::create_dir_all(&dir).unwrap();
    let name = path.file_name().unwrap().display().to_string();
    let out = dir.join(format!("{name}.{who}"));
    std::fs::write(&out, got).unwrap();
    let line = want
        .lines()
        .zip(got.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| want.lines().count().min(got.lines().count()));
    let at = |t: &str| t.lines().nth(line).unwrap_or("(end)").to_owned();
    format!(
        "\n{name} on {who}, line {}:\n  want: {}\n  got:  {}\n  all of it: {}\n",
        line + 1,
        at(want),
        at(got),
        out.display()
    )
}

/// A script, read.
struct Script {
    /// The lines that are not answers, in order.
    steps: Vec<String>,
    conf: String,
    masked: Vec<String>,
    dropped: Vec<String>,
    unordered: Vec<String>,
}

impl Script {
    fn parse(text: &str) -> Script {
        let mut s = Script {
            steps: Vec::new(),
            conf: String::new(),
            masked: MASKED.iter().map(|&k| k.to_owned()).collect(),
            dropped: DROPPED.iter().map(|&k| k.to_owned()).collect(),
            unordered: UNORDERED.iter().map(|&k| k.to_owned()).collect(),
        };
        for line in text.lines() {
            if let Some(c) = line.strip_prefix("#!") {
                s.conf += c.strip_prefix(' ').unwrap_or(c);
                s.conf.push('\n');
            } else if let Some(k) = line.strip_prefix("#~ ") {
                s.masked.push(k.to_owned());
            } else if let Some(k) = line.strip_prefix("#- ") {
                s.dropped.push(k.to_owned());
            } else if let Some(k) = line.strip_prefix("#= ") {
                s.unordered.push(k.to_owned());
            }
            if !line.starts_with('<') {
                s.steps.push(line.to_owned());
            }
        }
        s
    }

    /// The transcript of the script against the server with clients at
    /// `client` and monitoring at `monitor`.
    fn replay(&self, client: SocketAddr, monitor: SocketAddr) -> String {
        let mut clients: BTreeMap<String, Client> = BTreeMap::new();
        let mut out = String::new();
        for step in &self.steps {
            out += step;
            out.push('\n');
            if self.client_step(step, &mut clients, (client, monitor), &mut out) {
                continue;
            }
            let request = match step.split_once(' ') {
                Some(("RAW", raw)) => unescape(raw),
                Some((method, target)) if method.bytes().all(|b| b.is_ascii_uppercase()) => {
                    let target = cids(target, &clients);
                    format!("{method} {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                }
                _ => continue,
            };
            for c in clients.values_mut() {
                c.sync();
                if c.gone && !c.listed {
                    until_closed(monitor, c.cid);
                    c.listed = true;
                }
            }
            let answer = self.request(monitor, &request, step.split_once(' ').map(|(m, _)| m));
            for line in answer.lines() {
                out += "< ";
                out += line;
                out = out.trim_end().to_owned();
                out.push('\n');
            }
        }
        out
    }

    /// Acts on `step` if it is a client's, with clients at `at.0` and
    /// monitoring at `at.1`, and adds what it shows to `out`. Whether it
    /// was.
    fn client_step(
        &self,
        step: &str,
        clients: &mut BTreeMap<String, Client>,
        at: (SocketAddr, SocketAddr),
        out: &mut String,
    ) -> bool {
        // `a>` alone sends an empty line.
        let line = step
            .strip_suffix(">")
            .map_or(step.split_once("> "), |n| Some((n, "")));
        if let Some((name, sent)) = line
            && !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            clients
                .entry(name.to_owned())
                .or_insert_with(|| Client::new(at.0));
            let text = cids(sent, clients);
            let c = clients.get_mut(name).unwrap();
            let text = unescape(&text.replace("$SERVER_ID", &c.server_id));
            if let Some(head) = c.sized.take() {
                let _ = write!(c.pending, "{head} {}\r\n", text.len());
            } else if let Some(head) = text.strip_suffix(" $LEN") {
                c.sized = Some(head.to_owned());
                return true;
            }
            c.pending += &text;
            c.pending += "\r\n";
            return true;
        }
        if let Some((name, n)) = step.split_once("< ")
            && let Some(c) = clients.get_mut(name)
            && let Ok(n) = n.parse()
        {
            let id = c.server_id.clone();
            for g in c.take(n) {
                *out += &self.shown(&g).replace(&id, "$SERVER_ID");
            }
            return true;
        }
        if let Some(name) = step.strip_suffix('.')
            && let Some(c) = clients.get_mut(name)
        {
            c.sync();
            c.close();
            until_closed(at.1, c.cid);
            c.listed = true;
            return true;
        }
        false
    }

    /// What monitoring at `at` answers to `request` with `method`, for a
    /// transcript.
    fn request(&self, at: SocketAddr, request: &str, method: Option<&str>) -> String {
        let (raw, head) = (method == Some("RAW"), method == Some("HEAD"));
        let mut c = TcpStream::connect(at).unwrap();
        // A raw request may leave the connection open: what came in a
        // moment is the answer.
        c.set_read_timeout(Some(if raw {
            Duration::from_millis(500)
        } else {
            WAIT
        }))
        .unwrap();
        c.write_all(request.as_bytes()).unwrap();
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        let got = String::from_utf8_lossy(&got).into_owned();
        if raw {
            return got
                .split_inclusive("\r\n")
                .filter(|l| !l.starts_with("Date: "))
                .collect::<String>()
                .replace("\r\n", "\\r\\n\n");
        }
        let (head_text, body) = got.split_once("\r\n\r\n").unwrap_or((&got, ""));
        let mut lines = head_text.split("\r\n");
        let status = lines.next().unwrap_or("").to_owned();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut chunked = false;
        for l in lines {
            let (k, v) = l.split_once(": ").unwrap();
            let k = k.to_ascii_lowercase();
            chunked |= k == "transfer-encoding" && v == "chunked";
            if HEADERS.contains(&k.as_str()) {
                headers.push((k, v.to_owned()));
            }
        }
        headers.sort();
        let body = if chunked {
            dechunk(body)
        } else {
            body.to_owned()
        };
        let mut out = status + "\n";
        for (k, v) in headers {
            let _ = writeln!(out, "{k}: {v}");
        }
        out.push('\n');
        if !head {
            out += &self.mask(&body);
        }
        out
    }

    /// Message `g`, for a transcript.
    fn shown(&self, g: &Got) -> String {
        let mut out = format!("< {}\n", g.line.trim_end());
        let headers = String::from_utf8_lossy(&g.headers);
        for h in headers.split("\r\n").filter(|h| !h.is_empty()) {
            let _ = writeln!(out, "< {h}");
        }
        let body = String::from_utf8_lossy(&decoded(&g.headers, &g.payload)).into_owned();
        let body = if body.starts_with('{') {
            self.mask(&indent(&body))
        } else {
            body
        };
        for line in body.lines() {
            let _ = writeln!(out, "< {}", line.trim_end());
        }
        out
    }

    /// `body` with the values of masked keys `~` and dropped keys gone, if
    /// it is indented JSON.
    fn mask(&self, body: &str) -> String {
        if !body.starts_with("{\n") {
            return body.to_owned();
        }
        self.sorted(&self.masked_lines(body))
    }

    /// `body` with the lists of [`Script::unordered`] keys sorted.
    fn sorted(&self, body: &str) -> String {
        let lines: Vec<&str> = body.lines().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            out += line;
            out.push('\n');
            i += 1;
            let t = line.trim_start();
            let open = self.unordered.iter().any(|k| t == format!("\"{k}\": ["));
            if !open {
                continue;
            }
            let indent = line.len() - t.len();
            let close = format!("{}]", " ".repeat(indent));
            let inner = " ".repeat(indent + 2);
            let mut items: Vec<String> = Vec::new();
            while i < lines.len() && !lines[i].starts_with(&close) {
                let l = lines[i].trim_end_matches(',');
                if lines[i].starts_with(&inner)
                    && !lines[i][inner.len()..].starts_with(' ')
                    && !l.trim_start().starts_with('}')
                {
                    items.push(String::new());
                }
                if let Some(item) = items.last_mut() {
                    *item += lines[i];
                    item.push('\n');
                }
                i += 1;
            }
            // Lists in an item are sorted first.
            let mut items: Vec<String> = items
                .iter()
                .map(|t| {
                    let t = self.sorted(t);
                    t.trim_end_matches('\n').trim_end_matches(',').to_owned()
                })
                .collect();
            items.sort();
            let n = items.len();
            for (j, item) in items.into_iter().enumerate() {
                out += &item;
                out += if j + 1 < n { ",\n" } else { "\n" };
            }
        }
        out
    }

    /// `body` with the values of masked keys `~` and dropped keys gone.
    fn masked_lines(&self, body: &str) -> String {
        let mut out = String::new();
        let mut skip_until: Option<String> = None;
        for line in body.lines() {
            if let Some(end) = &skip_until {
                if line.starts_with(end.as_str()) {
                    skip_until = None;
                    if !line.ends_with(',') {
                        last_dropped(&mut out);
                    }
                }
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            let Some((key, value)) = line
                .trim_start()
                .strip_prefix('"')
                .and_then(|l| l.split_once("\": "))
            else {
                out += line;
                out.push('\n');
                continue;
            };
            if self.dropped.iter().any(|k| k == key) {
                if value.ends_with('{') || value.ends_with('[') {
                    let close = if value.ends_with('{') { '}' } else { ']' };
                    skip_until = Some(format!("{}{close}", " ".repeat(indent)));
                } else if !value.ends_with(',') {
                    last_dropped(&mut out);
                }
                continue;
            }
            // Without a name, Go is named by its ID, naq `naq`.
            let unnamed = key == "server_name"
                && (value.starts_with("\"N") && value.len() > 50 || value.starts_with("\"naq\""));
            let top = indent == 2 && (TOP_MASKED.contains(&key) || unnamed);
            if (top || self.masked.iter().any(|k| k == key))
                && !value.ends_with('{')
                && !value.ends_with('[')
            {
                let comma = if value.ends_with(',') { "," } else { "" };
                let _ = writeln!(out, "{}\"{key}\": ~{comma}", " ".repeat(indent));
                continue;
            }
            out += line;
            out.push('\n');
        }
        out
    }
}

/// Drops the comma at the end of `out`: the entry after it was the last
/// of its object, and is gone.
fn last_dropped(out: &mut String) {
    if out.ends_with(",\n") {
        out.truncate(out.len() - 2);
        out.push('\n');
    }
}

/// The body of a chunked answer.
fn dechunk(mut body: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = body.split_once("\r\n") {
        let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        out += &rest[..n];
        body = rest[n..].strip_prefix("\r\n").unwrap_or(&rest[n..]);
    }
    out
}

/// `s` with `\r`, `\n` and `\\` escapes decoded.
fn unescape(s: &str) -> String {
    s.replace("\\r", "\r")
        .replace("\\n", "\n")
        .replace("\\\\", "\\")
}

/// A client of the script.
struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
    pending: String,
    /// Its ID, from its `INFO`.
    cid: u64,
    /// The server's ID, from its `INFO`.
    server_id: String,
    /// The messages it got that no step showed yet.
    got: Vec<Got>,
    /// A `PUB` waiting for the size of its payload, the next line.
    sized: Option<String>,
    /// Its connection closed.
    gone: bool,
    /// Closed connections list it.
    listed: bool,
}

impl Client {
    fn new(at: SocketAddr) -> Client {
        let w = TcpStream::connect(at).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let mut r = BufReader::new(w.try_clone().unwrap());
        let mut info = String::new();
        r.read_line(&mut info).unwrap();
        let cid = info
            .split_once("\"client_id\":")
            .and_then(|(_, rest)| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .unwrap();
        let server_id = info
            .split_once("\"server_id\":\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(id, _)| id.to_owned())
            .unwrap();
        Client {
            w,
            r,
            pending: String::new(),
            cid,
            server_id,
            got: Vec::new(),
            sized: None,
            gone: false,
            listed: false,
        }
    }

    fn close(&mut self) {
        let _ = self.w.shutdown(std::net::Shutdown::Both);
        self.gone = true;
    }

    /// Sends what is pending with a `PING`, and reads up to the `PONG`,
    /// keeping the messages.
    fn sync(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let sent = std::mem::take(&mut self.pending) + "PING\r\n";
        if self.gone || self.w.write_all(sent.as_bytes()).is_err() {
            self.gone = true;
            return;
        }
        loop {
            match self.frame() {
                Frame::Pong => return,
                Frame::Msg(g) => self.got.push(g),
                Frame::Other => {}
                // Closed by the server, or reset.
                Frame::Quiet | Frame::Gone => {
                    self.gone = true;
                    return;
                }
            }
        }
    }

    /// Reads the next frame.
    fn frame(&mut self) -> Frame {
        let mut line = String::new();
        match self.r.read_line(&mut line) {
            Ok(0) => return Frame::Gone,
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Frame::Quiet;
            }
            Err(_) => return Frame::Gone,
        }
        let line = line.trim_end_matches("\r\n");
        if line == "PONG" {
            return Frame::Pong;
        }
        let mut words: Vec<&str> = line.split(' ').collect();
        let size = |w: Option<&str>| w.unwrap().parse::<usize>().unwrap();
        let (head, total) = match words.first() {
            Some(&"MSG") => (0, size(words.pop())),
            Some(&"HMSG") => {
                let total = size(words.pop());
                (size(words.pop()), total)
            }
            _ => return Frame::Other,
        };
        let mut buf = vec![0; total + 2];
        self.r.read_exact(&mut buf).unwrap();
        buf.truncate(total);
        let payload = buf.split_off(head);
        Frame::Msg(Got {
            line: words.join(" "),
            headers: buf,
            payload,
        })
    }

    /// Waits until it got `n` messages, or for a moment for none if `n` is
    /// 0, and hands over all it got.
    fn take(&mut self, n: usize) -> Vec<Got> {
        self.sync();
        let deadline = Instant::now() + WAIT;
        loop {
            let wait = if n == 0 {
                Duration::from_millis(300)
            } else {
                deadline.saturating_duration_since(Instant::now())
            };
            if (n > 0 && self.got.len() >= n) || wait.is_zero() {
                break;
            }
            self.w.set_read_timeout(Some(wait)).unwrap();
            match self.frame() {
                Frame::Msg(g) => self.got.push(g),
                Frame::Quiet | Frame::Gone => break,
                Frame::Pong | Frame::Other => {}
            }
        }
        self.w.set_read_timeout(Some(WAIT)).unwrap();
        std::mem::take(&mut self.got)
    }
}

/// A message a client got.
struct Got {
    /// Its control line, without its sizes.
    line: String,
    headers: Vec<u8>,
    payload: Vec<u8>,
}

/// What a client read.
enum Frame {
    Pong,
    Msg(Got),
    Other,
    /// Nothing came in time.
    Quiet,
    Gone,
}

/// `body` decoded as its `Content-Encoding` in `headers` says.
fn decoded(headers: &[u8], body: &[u8]) -> Vec<u8> {
    let h = String::from_utf8_lossy(headers);
    if h.contains("Content-Encoding: gzip") {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(body)
            .read_to_end(&mut out)
            .unwrap();
        out
    } else if h.contains("Content-Encoding: snappy") {
        unsnappy(body)
    } else {
        body.to_vec()
    }
}

/// `target` with `$CID_a` for the ID of each client `a`.
fn cids(target: &str, clients: &BTreeMap<String, Client>) -> String {
    let mut t = target.to_owned();
    // Longest names first, so that `$CID_ab` is not taken for `$CID_a`.
    let mut names: Vec<&String> = clients.keys().collect();
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    for n in names {
        t = t.replace(&format!("$CID_{n}"), &clients[n].cid.to_string());
    }
    t
}

/// Waits until the monitoring port at `at` lists client `cid` among the
/// closed connections.
fn until_closed(at: SocketAddr, cid: u64) {
    let deadline = Instant::now() + WAIT;
    loop {
        let mut c = TcpStream::connect(at).unwrap();
        c.set_read_timeout(Some(WAIT)).unwrap();
        let req = format!(
            "GET /connz?state=closed&cid={cid} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        );
        c.write_all(req.as_bytes()).unwrap();
        let mut got = String::new();
        let _ = c.read_to_string(&mut got);
        if got.contains("\"num_connections\": 1") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "client {cid} not listed as closed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `nats-server` running a script's configuration.
struct GoServer {
    child: Child,
    client: SocketAddr,
    monitor: SocketAddr,
}

impl GoServer {
    fn start(bin: &Path, script: &Path, s: &Script) -> GoServer {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("endpoints");
        std::fs::create_dir_all(&dir).unwrap();
        let name = script.file_name().unwrap().display().to_string();
        let conf = dir.join(format!("{name}.conf"));
        std::fs::write(&conf, &s.conf).unwrap();
        let log = dir.join(format!("{name}.log"));
        let _ = std::fs::remove_file(&log);
        let (port, http) = (free_port(), free_port());
        let flag = if s.conf.contains("https") {
            "-ms"
        } else {
            "-m"
        };
        let child = Command::new(bin)
            .args([
                "-c".as_ref(),
                conf.as_os_str(),
                "-l".as_ref(),
                log.as_os_str(),
            ])
            .args([
                "-a",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                flag,
                &http.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Not by a connection: that would count as one.
        let deadline = Instant::now() + WAIT;
        while !std::fs::read_to_string(&log).is_ok_and(|l| l.contains("Server is ready")) {
            assert!(Instant::now() < deadline, "nats-server did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        GoServer {
            child,
            client: SocketAddr::from(([127, 0, 0, 1], port)),
            monitor: SocketAddr::from(([127, 0, 0, 1], http)),
        }
    }
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Compact JSON `json` indented as Go's `json.MarshalIndent` with two
/// spaces indents it: empty objects and lists stay `{}` and `[]`.
fn indent(json: &str) -> String {
    let b = json.as_bytes();
    let mut out = String::with_capacity(json.len() * 2);
    let mut depth = 0usize;
    let mut i = 0;
    let newline = |out: &mut String, depth: usize| {
        out.push('\n');
        out.push_str(&"  ".repeat(depth));
    };
    while i < b.len() {
        let c = b[i];
        match c {
            b'"' => {
                let start = i;
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                out.push_str(&json[start..=i.min(b.len() - 1)]);
            }
            b'{' | b'[' => {
                let close = if c == b'{' { b'}' } else { b']' };
                if b.get(i + 1) == Some(&close) {
                    out.push(c as char);
                    out.push(close as char);
                    i += 1;
                } else {
                    out.push(c as char);
                    depth += 1;
                    newline(&mut out, depth);
                }
            }
            b'}' | b']' => {
                depth -= 1;
                newline(&mut out, depth);
                out.push(c as char);
            }
            b',' => {
                out.push(',');
                newline(&mut out, depth);
            }
            b':' => out.push_str(": "),
            _ => out.push(c as char),
        }
        i += 1;
    }
    out.push('\n');
    out
}

/// The data of the snappy framing format stream `b`.
fn unsnappy(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let kind = b[0];
        let len = usize::from(b[1]) | usize::from(b[2]) << 8 | usize::from(b[3]) << 16;
        let chunk = &b[4..4 + len];
        match kind {
            0x00 => out.extend(unsnappy_block(&chunk[4..])),
            0x01 => out.extend_from_slice(&chunk[4..]),
            _ => {}
        }
        b = &b[4 + len..];
    }
    out
}

/// A snappy block decoded.
fn unsnappy_block(b: &[u8]) -> Vec<u8> {
    let mut i = 0;
    let mut n = 0usize;
    let mut shift = 0;
    loop {
        let c = b[i];
        i += 1;
        n |= usize::from(c & 0x7f) << shift;
        shift += 7;
        if c < 0x80 {
            break;
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let le = |s: &[u8]| s.iter().rev().fold(0usize, |a, &x| a << 8 | usize::from(x));
    while i < b.len() {
        let tag = b[i];
        i += 1;
        let (len, offset) = match tag & 3 {
            0 => {
                let mut len = usize::from(tag >> 2);
                if len >= 60 {
                    let extra = len - 59;
                    len = le(&b[i..i + extra]);
                    i += extra;
                }
                out.extend_from_slice(&b[i..=i + len]);
                i += len + 1;
                continue;
            }
            1 => {
                let off = usize::from(tag >> 5) << 8 | usize::from(b[i]);
                i += 1;
                (usize::from(tag >> 2 & 7) + 4, off)
            }
            2 => {
                let off = le(&b[i..i + 2]);
                i += 2;
                (usize::from(tag >> 2) + 1, off)
            }
            _ => {
                let off = le(&b[i..i + 4]);
                i += 4;
                (usize::from(tag >> 2) + 1, off)
            }
        };
        let from = out.len() - offset;
        for k in 0..len {
            out.push(out[from + k]);
        }
    }
    out
}
