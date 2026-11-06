//! HTTP/1.1 for monitoring, as Go's `net/http` serves it: keep-alive and
//! pipelining, any method, `HEAD` without a body, and Go's answers to
//! requests it cannot read.

use std::fmt::Write as _;
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Most bytes of a request head, as Go's `MaxHeaderBytes` of 1 MiB plus
/// its slack.
const MAX_HEAD: usize = (1 << 20) + 4096;

/// Most bytes of a request body read and dropped to keep the connection.
const MAX_BODY: usize = 256 << 10;

/// How long a request head may take once it starts (Go's
/// `ReadHeaderTimeout`).
const HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a connection may wait for its next request.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// A request, as the handlers see it.
#[derive(Debug)]
pub(crate) struct Request {
    method: Method,
    /// Its path, decoded.
    pub(crate) path: String,
    /// Its query, as sent.
    pub(crate) query: String,
    /// HTTP/1.0 rather than 1.1.
    old: bool,
    /// The connection closes after it.
    close: bool,
    /// Bytes of body that follow it; `None` for a chunked one.
    body: Option<usize>,
}

/// What the method of a request asks of its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    /// The headers only.
    Head,
    Other,
}

/// An answer to a request.
#[derive(Debug)]
pub(crate) struct Response {
    pub(crate) status: u16,
    /// Headers besides `Date`, `Content-Length` and `Connection`.
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) body: Vec<u8>,
}

impl Response {
    /// JSON, as the monitoring endpoints answer.
    pub(crate) fn json(status: u16, body: Vec<u8>) -> Response {
        Response {
            status,
            headers: vec![
                ("Access-Control-Allow-Origin", "*".into()),
                ("Content-Type", "application/json".into()),
            ],
            body,
        }
    }

    /// Plain text, as Go sniffs it.
    pub(crate) fn text(status: u16, body: impl Into<Vec<u8>>) -> Response {
        Response {
            status,
            headers: vec![("Content-Type", "text/plain; charset=utf-8".into())],
            body: body.into(),
        }
    }

    /// HTML, as Go sniffs it.
    pub(crate) fn html(body: impl Into<Vec<u8>>) -> Response {
        Response {
            status: 200,
            headers: vec![("Content-Type", "text/html; charset=utf-8".into())],
            body: body.into(),
        }
    }

    /// Go's `http.NotFound`.
    pub(crate) fn not_found() -> Response {
        let mut r = Response::text(404, "404 page not found\n");
        r.headers.push(("X-Content-Type-Options", "nosniff".into()));
        r
    }

    /// Go's redirect of a path that is not clean to `to`, with `query`.
    fn redirect(to: &str, query: &str, get: bool) -> Response {
        let mut url = escape_path(to);
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        let mut r = Response {
            status: 307,
            headers: Vec::new(),
            body: Vec::new(),
        };
        if get {
            r.headers
                .push(("Content-Type", "text/html; charset=utf-8".into()));
            r.body = format!(
                "<a href=\"{}\">Temporary Redirect</a>.\n\n",
                html_escape(&url)
            )
            .into();
        }
        r.headers.push(("Location", url));
        r
    }
}

/// What the handlers do with a request.
pub(crate) trait Handler {
    /// The answer to `req`, whose path is clean.
    fn answer(&self, req: &Request) -> impl Future<Output = Response>;
}

/// Serves requests on `io` until the peer closes it, one is refused, or
/// it idles too long.
pub(crate) async fn serve<S, H>(mut io: S, handler: &H)
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let mut buf = Vec::with_capacity(1024);
    loop {
        let head = match read_head(&mut io, &mut buf).await {
            Ok(Some(n)) => n,
            Ok(None) => return,
            Err(refusal) => {
                let _ = io.write_all(refusal.as_bytes()).await;
                let _ = io.shutdown().await;
                return;
            }
        };
        let req = match parse(&buf[..head]) {
            Ok(r) => r,
            Err(refusal) => {
                let _ = io.write_all(refusal.as_bytes()).await;
                let _ = io.shutdown().await;
                return;
            }
        };
        buf.drain(..head);
        // A body too long to drop, or chunked, ends the connection.
        let keep = match req.body {
            Some(n) if n <= MAX_BODY => skip(&mut io, &mut buf, n).await,
            _ => false,
        };
        let close = req.close || !keep;
        let resp = match clean(&req.path) {
            Some(to) => Response::redirect(&to, &req.query, req.method != Method::Other),
            None => handler.answer(&req).await,
        };
        let out = encode(&req, &resp, close, SystemTime::now());
        if io.write_all(&out).await.is_err() || close {
            let _ = io.shutdown().await;
            return;
        }
    }
}

/// Reads until `buf` holds a whole request head; returns its length, or
/// `None` once the peer is gone or idle. A refusal is what to send.
async fn read_head<S: AsyncRead + Unpin>(
    io: &mut S,
    buf: &mut Vec<u8>,
) -> Result<Option<usize>, &'static str> {
    let mut started = None;
    loop {
        if let Some(end) = head_end(buf) {
            return Ok(Some(end));
        }
        if buf.len() > MAX_HEAD {
            return Err(TOO_LARGE);
        }
        let wait = match started {
            None if buf.is_empty() => IDLE_TIMEOUT,
            None => {
                started = Some(tokio::time::Instant::now());
                HEAD_TIMEOUT
            }
            Some(t) => HEAD_TIMEOUT.saturating_sub(t.elapsed()),
        };
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(wait, io.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                buf.extend_from_slice(&chunk[..n]);
                if started.is_none() {
                    started = Some(tokio::time::Instant::now());
                }
            }
            _ => return Ok(None),
        }
    }
}

/// Where the head in `buf` ends, after its blank line.
fn head_end(buf: &[u8]) -> Option<usize> {
    // Go takes bare LFs too.
    let mut i = 0;
    while let Some(at) = memchr::memchr(b'\n', &buf[i..]) {
        let end = i + at + 1;
        match &buf[end..] {
            [b'\n', ..] => return Some(end + 1),
            [b'\r', b'\n', ..] => return Some(end + 2),
            _ => i = end,
        }
    }
    None
}

/// Reads and drops `n` bytes of body after what `buf` holds; false if the
/// peer went away first.
async fn skip<S: AsyncRead + Unpin>(io: &mut S, buf: &mut Vec<u8>, mut n: usize) -> bool {
    let have = n.min(buf.len());
    buf.drain(..have);
    n -= have;
    let mut chunk = [0u8; 4096];
    while n > 0 {
        let want = n.min(chunk.len());
        match tokio::time::timeout(HEAD_TIMEOUT, io.read(&mut chunk[..want])).await {
            Ok(Ok(got)) if got > 0 => n -= got,
            _ => return false,
        }
    }
    true
}

const BAD: &str = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request";
const NO_HOST: &str = "HTTP/1.1 400 Bad Request: missing required Host header\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: missing required Host header";
const TOO_LARGE: &str = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large";
const VERSION: &str = "HTTP/1.1 505 HTTP Version Not Supported: unsupported protocol version\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n505 HTTP Version Not Supported: unsupported protocol version";

/// The request in `head`, or Go's refusal of it.
fn parse(head: &[u8]) -> Result<Request, &'static str> {
    let text = std::str::from_utf8(head).map_err(|_| BAD)?;
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let first = lines.next().ok_or(BAD)?;
    let (method, rest) = first.split_once(' ').ok_or(BAD)?;
    let (target, proto) = rest.split_once(' ').ok_or(BAD)?;
    if method.is_empty() || !method.bytes().all(is_token) {
        return Err(BAD);
    }
    let old = match proto {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        p if p.starts_with("HTTP/") && p.len() == 8 && p.as_bytes()[6] == b'.' => {
            return Err(VERSION);
        }
        _ => return Err(BAD),
    };
    let (mut close, mut keep_alive, mut host) = (old, false, 0);
    let mut body = Some(0);
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(BAD)?;
        if name.is_empty() || !name.bytes().all(is_token) {
            return Err(BAD);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") {
            host += 1;
        } else if name.eq_ignore_ascii_case("connection") {
            for token in value.split(',').map(str::trim) {
                close |= token.eq_ignore_ascii_case("close");
                keep_alive |= token.eq_ignore_ascii_case("keep-alive");
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            body = Some(value.parse().map_err(|_| BAD)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            body = None;
        }
    }
    if host > 1 || (host == 0 && !old) {
        return Err(if host > 1 { BAD } else { NO_HOST });
    }
    if old && keep_alive {
        close = false;
    }
    let (path, query) = split_target(target).ok_or(BAD)?;
    Ok(Request {
        method: match method {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            _ => Method::Other,
        },
        path,
        query: query.to_owned(),
        old,
        close,
        body,
    })
}

/// The decoded path and the raw query of a request target: an absolute
/// path, or an absolute URL.
fn split_target(target: &str) -> Option<(String, &str)> {
    let target = match target.split_once("://") {
        Some((scheme, rest)) if !scheme.is_empty() && !scheme.contains('/') => {
            let at = rest.find(['/', '?']).unwrap_or(rest.len());
            &rest[at..]
        }
        _ => target,
    };
    let (raw, query) = target.split_once('?').unwrap_or((target, ""));
    let raw = raw.split_once('#').map_or(raw, |(p, _)| p);
    let path = if raw.is_empty() { "/" } else { raw };
    if !path.starts_with('/') {
        return None;
    }
    Some((super::query::percent(path, false)?, query))
}

/// A byte of an HTTP token.
const fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// The clean form of `path` if it is not clean, as Go's `ServeMux`
/// cleans it: [`path_clean`], with a trailing `/` kept.
fn clean(path: &str) -> Option<String> {
    let mut c = path_clean(path);
    if path.ends_with('/') && c != "/" {
        c.push('/');
    }
    (c != path).then_some(c)
}

/// Rooted `path` as Go's `path.Clean` makes it: no `.` or `..` parts, no
/// doubled or trailing `/`.
pub(crate) fn path_clean(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for p in path.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

/// `path` with what a URL path cannot hold escaped, as Go's
/// `url.URL.EscapedPath` does.
fn escape_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~$&+,/:;=@!'()*".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `s` with `<`, `>`, `&`, `'` and `"` escaped, as Go's `htmlEscape`.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// The bytes of `resp` to `req`, sent at `now`, closing the connection
/// after if `close`.
fn encode(req: &Request, resp: &Response, close: bool, now: SystemTime) -> Vec<u8> {
    let version = if req.old { "HTTP/1.0" } else { "HTTP/1.1" };
    let mut out = format!("{version} {} {}\r\n", resp.status, reason(resp.status));
    for (k, v) in &resp.headers {
        let _ = write!(out, "{k}: {v}\r\n");
    }
    let _ = write!(
        out,
        "Date: {}\r\nContent-Length: {}\r\n",
        crate::times::http_date(now),
        resp.body.len()
    );
    if close && !req.old {
        out.push_str("Connection: close\r\n");
    } else if !close && req.old {
        out.push_str("Connection: keep-alive\r\n");
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    if req.method != Method::Head {
        out.extend_from_slice(&resp.body);
    }
    out
}

/// The reason phrase of `status`.
const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// Reads `data` as a request to the monitoring port, as [`serve`] reads
/// one: its head, path and query, and the answers it may get.
///
/// # Panics
///
/// When a path cleaned for a redirect is not clean.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz(data: &[u8]) {
    let Some(end) = head_end(data) else {
        return;
    };
    let Ok(req) = parse(&data[..end]) else {
        return;
    };
    if let Some(to) = clean(&req.path) {
        assert_eq!(clean(&to), None, "{to:?} is not clean");
        let _ = encode(
            &req,
            &Response::redirect(&to, &req.query, true),
            req.close,
            SystemTime::UNIX_EPOCH,
        );
    }
    let q = super::query::Query::parse(&req.query);
    for key in ["subs", "limit", "cid", "state", "acc"] {
        let _ = (q.bool(key), q.int(key), q.uint(key));
    }
    let _ = q.subs();
    let _ = encode(
        &req,
        &Response::not_found(),
        req.close,
        SystemTime::UNIX_EPOCH,
    );
}

#[cfg(test)]
mod tests;
