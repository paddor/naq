//! Monitoring scripts in `tests/endpoints/`, replayed against naq. Each
//! script holds what clients send and the requests to the monitoring port
//! and, after each request, what `nats-server` v2.15.2 answered to the
//! same script; naq must answer the same.
//!
//! A script line is one of:
//!
//! - `a> text`: client `a` sends `text`, with `\r`, `\n` and `\\` escapes,
//!   and CRLF. It connects on first use.
//!   Before the next request, every client's lines go out with a `PING`,
//!   and its replies are read up to the `PONG` and dropped.
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
use std::io::{BufRead, BufReader, Read, Write};
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
            if let Some((name, sent)) = step.split_once("> ")
                && !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                let c = clients
                    .entry(name.to_owned())
                    .or_insert_with(|| Client::new(client));
                c.pending += &unescape(sent);
                c.pending += "\r\n";
                continue;
            }
            if let Some(name) = step.strip_suffix('.')
                && let Some(c) = clients.get_mut(name)
            {
                c.sync();
                c.close();
                until_closed(monitor, c.cid);
                c.listed = true;
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
            let mut items: Vec<String> = items
                .iter()
                .map(|t| t.trim_end_matches('\n').trim_end_matches(',').to_owned())
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
        Client {
            w,
            r,
            pending: String::new(),
            cid,
            gone: false,
            listed: false,
        }
    }

    fn close(&mut self) {
        let _ = self.w.shutdown(std::net::Shutdown::Both);
        self.gone = true;
    }

    /// Sends what is pending with a `PING`, and reads up to the `PONG`.
    fn sync(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let sent = std::mem::take(&mut self.pending) + "PING\r\n";
        if self.gone || self.w.write_all(sent.as_bytes()).is_err() {
            self.gone = true;
            return;
        }
        let mut line = String::new();
        loop {
            line.clear();
            // Closed by the server, or reset.
            if self.r.read_line(&mut line).unwrap_or(0) == 0 {
                self.gone = true;
                return;
            }
            if line == "PONG\r\n" {
                return;
            }
        }
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
