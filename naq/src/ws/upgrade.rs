//! The HTTP upgrade to WebSocket [RFC 6455 4.2], checked and answered as
//! `nats-server` checks and answers it.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64;

use crate::Websocket;
use crate::auth::Creds;

/// Largest upgrade request, as `nats-server` reads it.
pub(super) const MAX_REQUEST: usize = 64 << 10;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// What a client asked for in an upgrade the server takes.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Upgrade {
    /// Of `Sec-WebSocket-Accept`.
    pub(super) accept: String,
    /// Messages may be compressed.
    pub(super) compress: bool,
    /// The client does not mask its frames (`Nats-No-Masking`).
    pub(super) no_masking: bool,
    /// Who connects, as its `User-Agent` tells.
    pub(super) agent: Agent,
    /// From the cookies the listener names.
    pub(super) cookies: Creds,
    /// For a leaf node: upgraded, then closed, as this server takes none.
    pub(super) leaf: bool,
}

/// Who connects, as far as framing cares.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum Agent {
    #[default]
    Other,
    /// A browser: messages go out in small frames.
    Browser,
    /// Safari, which takes a compressed message in one frame only.
    Safari,
}

/// Why an upgrade is refused: an HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    BadRequest,
    Forbidden,
    NotFound,
    MethodNotAllowed,
}

impl Refusal {
    const fn status(self) -> (u16, &'static str) {
        match self {
            Refusal::BadRequest => (400, "Bad Request"),
            Refusal::Forbidden => (403, "Forbidden"),
            Refusal::NotFound => (404, "Not Found"),
            Refusal::MethodNotAllowed => (405, "Method Not Allowed"),
        }
    }

    /// The response, as Go's `http.Error` writes it: with
    /// `Connection: close` if the request asked to `close`.
    pub(super) fn response(self, now: SystemTime, close: bool) -> String {
        let (code, text) = self.status();
        let connection = if close { "Connection: close\r\n" } else { "" };
        format!(
            "HTTP/1.1 {code} {text}\r\nContent-Type: text/plain; charset=utf-8\r\nSec-Websocket-Version: 13\r\nX-Content-Type-Options: nosniff\r\n{connection}Date: {}\r\nContent-Length: {}\r\n\r\n{text}\n",
            http_date(now),
            text.len() + 1
        )
    }
}

/// An upgrade request's head.
struct Request<'a> {
    method: &'a str,
    path: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

impl<'a> Request<'a> {
    fn parse(head: &'a str) -> Option<Request<'a>> {
        let mut lines = head.split("\r\n");
        let mut first = lines.next()?.split(' ');
        let (method, target, version) = (first.next()?, first.next()?, first.next()?);
        if !version.starts_with("HTTP/1.") || first.next().is_some() {
            return None;
        }
        let path = target.split('?').next().unwrap_or_default();
        let mut headers = Vec::new();
        for line in lines.take_while(|l| !l.is_empty()) {
            let (k, v) = line.split_once(':')?;
            headers.push((k.trim(), v.trim()));
        }
        Some(Request {
            method,
            path,
            headers,
        })
    }

    /// Every value of header `name`.
    fn all(&self, name: &str) -> impl Iterator<Item = &'a str> {
        let name = name.to_owned();
        self.headers
            .clone()
            .into_iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(&name))
            .map(|(_, v)| v)
    }

    /// The first value of header `name`.
    fn get(&self, name: &str) -> Option<&'a str> {
        self.all(name).next()
    }

    /// Whether a value of header `name` lists `token`.
    fn lists(&self, name: &str, token: &str) -> bool {
        self.all(name)
            .flat_map(|v| v.split(','))
            .any(|t| t.trim_matches([' ', '\t']).eq_ignore_ascii_case(token))
    }
}

/// Whether `line`, up to its newline, can start a request:
/// `METHOD target HTTP/1.x`.
pub(super) fn request_line(line: &[u8]) -> bool {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.split(|&b| b == b' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    !method.is_empty()
        && method.iter().all(u8::is_ascii_alphabetic)
        && !target.is_empty()
        && version.starts_with(b"HTTP/1.")
        && parts.next().is_none()
}

/// Whether the request in `head` asks to close the connection.
pub(super) fn asks_close(head: &str) -> bool {
    Request::parse(head).is_some_and(|r| r.lists("connection", "close"))
}

/// Checks the upgrade request in `head` for listener `o`, reached over
/// TLS if `tls`.
pub(super) fn check(head: &str, o: &Websocket, tls: bool) -> Result<Upgrade, Refusal> {
    let r = Request::parse(head).ok_or(Refusal::BadRequest)?;
    let leaf = r.path.ends_with("/leafnode");
    if !leaf && r.path.ends_with("/mqtt") {
        return Err(Refusal::NotFound);
    }
    if r.method != "GET" {
        return Err(Refusal::MethodNotAllowed);
    }
    let host = r.get("host").unwrap_or_default();
    if host.is_empty() || !r.lists("upgrade", "websocket") || !r.lists("connection", "upgrade") {
        return Err(Refusal::BadRequest);
    }
    let key = r.get("sec-websocket-key").unwrap_or_default();
    if BASE64.decode(key.as_bytes()).map(|k| k.len()) != Ok(16)
        || !r.lists("sec-websocket-version", "13")
    {
        return Err(Refusal::BadRequest);
    }
    if !origin_ok(&r, o, host, tls) {
        return Err(Refusal::Forbidden);
    }
    let ua = r.get("user-agent").unwrap_or_default();
    let agent = match ua.starts_with("Mozilla/") {
        false => Agent::Other,
        true if ua.contains("Version/") && ua.contains("Safari/") => Agent::Safari,
        true => Agent::Browser,
    };
    let compress = o.compression && wants_deflate(&r);
    Ok(Upgrade {
        accept: accept_key(key),
        compress,
        no_masking: r.get("nats-no-masking") == Some("true"),
        agent,
        cookies: cookies(&r, o),
        leaf,
    })
}

/// Whether the client offers `permessage-deflate`.
fn wants_deflate(r: &Request<'_>) -> bool {
    r.all("sec-websocket-extensions")
        .flat_map(|v| v.split([',', ';']))
        .any(|p| {
            p.trim_matches([' ', '\t'])
                .eq_ignore_ascii_case("permessage-deflate")
        })
}

/// The credentials in the cookies `opts` names.
fn cookies(req: &Request<'_>, opts: &Websocket) -> Creds {
    let mut creds = Creds::default();
    let names = &opts.cookies;
    if names.user.is_none() && names.pass.is_none() && names.token.is_none() {
        return creds;
    }
    for pair in req.all("cookie").flat_map(|v| v.split(';')) {
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        let is = |n: &Option<String>| n.as_deref() == Some(name);
        if is(&names.user) {
            creds.user = Some(value.to_owned());
        } else if is(&names.pass) {
            creds.pass = Some(value.to_owned());
        } else if is(&names.token) {
            creds.token = Some(value.to_owned());
        }
    }
    creds
}

/// Whether the request's origin may connect, as `nats-server` checks it:
/// any may with no checks set up or no `Origin` given.
fn origin_ok(r: &Request<'_>, o: &Websocket, host: &str, tls: bool) -> bool {
    if !o.same_origin && o.allowed_origins.is_empty() {
        return true;
    }
    let origin = r
        .get("origin")
        .filter(|v| !v.is_empty())
        .or_else(|| r.get("sec-websocket-origin"))
        .unwrap_or_default();
    if origin.is_empty() {
        return true;
    }
    let Some(from) = Origin::parse(origin) else {
        return false;
    };
    if o.same_origin {
        let scheme = if tls { "https" } else { "http" };
        let here = host_port(host, tls);
        if !from.scheme.eq_ignore_ascii_case(scheme)
            || here != (from.host.clone(), from.port.clone())
        {
            return false;
        }
    }
    if !o.allowed_origins.is_empty() {
        let allowed = o
            .allowed_origins
            .iter()
            .filter_map(|a| Origin::parse(a))
            .any(|a| a.host == from.host && a.scheme == from.scheme && a.port == from.port);
        if !allowed {
            return false;
        }
    }
    true
}

/// An origin: scheme, host in lowercase, port.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Origin {
    scheme: String,
    host: String,
    port: String,
}

impl Origin {
    /// `scheme://host[:port][/...]`.
    pub(super) fn parse(url: &str) -> Option<Origin> {
        let (scheme, rest) = url.split_once("://")?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let authority = authority.rsplit('@').next().unwrap_or_default();
        if scheme.is_empty() || authority.is_empty() {
            return None;
        }
        let (host, port) = host_port(authority, scheme == "https");
        Some(Origin {
            scheme: scheme.to_owned(),
            host,
            port,
        })
    }

    /// Whether it may be an allowed origin: an `http` or `https` URL.
    pub(super) fn is_web(&self) -> bool {
        self.scheme == "http" || self.scheme == "https"
    }
}

/// The host, lowercased, and port of `hostport`; without a port, the
/// scheme's.
fn host_port(hostport: &str, tls: bool) -> (String, String) {
    let split = match hostport.strip_prefix('[') {
        Some(v6) => v6.split_once("]:"),
        None => hostport.rsplit_once(':').filter(|(h, _)| !h.contains(':')),
    };
    if let Some((h, p)) = split {
        return (h.to_ascii_lowercase(), p.to_owned());
    }
    let port = if tls { "443" } else { "80" };
    (hostport.to_ascii_lowercase(), port.to_owned())
}

/// The `101` response to `u`, with the listener's own `headers`.
pub(super) fn response(u: &Upgrade, headers: &[(String, String)]) -> String {
    let mut out = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        u.accept
    );
    if u.compress {
        out += "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n";
    }
    if u.no_masking {
        out += "Nats-No-Masking: true\r\n";
    }
    for (k, v) in headers {
        let _ = write!(out, "{k}: {v}\r\n");
    }
    out + "\r\n"
}

/// `Sec-WebSocket-Accept` for `key`.
pub(super) fn accept_key(key: &str) -> String {
    let digest = sha1_smol::Sha1::from(format!("{key}{GUID}")).digest();
    BASE64.encode(&digest.bytes())
}

/// `t` as HTTP writes dates: `Tue, 03 Nov 2026 20:47:19 GMT`.
fn http_date(t: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = crate::monitor::civil(days.cast_signed());
    format!(
        "{}, {d:02} {} {y} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[m as usize - 1],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::Cookies;

    fn ws() -> Websocket {
        Websocket {
            no_tls: true,
            ..Websocket::default()
        }
    }

    fn request(extra: &str) -> String {
        format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
        )
    }

    #[test]
    fn a_good_request_gets_the_accept_key_of_the_rfc() {
        let u = check(&request(""), &ws(), false).unwrap();
        assert_eq!(u.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert!(!u.compress && !u.leaf);
        assert_eq!(u.agent, Agent::Other);
        let r = response(&u, &[("X-A".into(), "b".into())]);
        assert_eq!(
            r,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-A: b\r\n\r\n"
        );
    }

    #[test]
    fn bad_requests_are_refused_as_nats_server_refuses_them() {
        let good = request("");
        let cases = [
            (good.replace("GET", "POST"), Refusal::MethodNotAllowed),
            (good.replace("GET /", "GET /mqtt"), Refusal::NotFound),
            (
                good.replace("Host: 127.0.0.1:8080", "Host:"),
                Refusal::BadRequest,
            ),
            (
                good.replace("Upgrade: websocket", "Upgrade: h2c"),
                Refusal::BadRequest,
            ),
            (
                good.replace("keep-alive, Upgrade", "close"),
                Refusal::BadRequest,
            ),
            (
                good.replace("dGhlIHNhbXBsZSBub25jZQ==", "abc"),
                Refusal::BadRequest,
            ),
            (
                good.replace("Version: 13", "Version: 8"),
                Refusal::BadRequest,
            ),
            ("nonsense\r\n\r\n".into(), Refusal::BadRequest),
            (good.replace("HTTP/1.1", "HTTP/2"), Refusal::BadRequest),
        ];
        for (req, want) in cases {
            assert_eq!(check(&req, &ws(), false), Err(want), "{req}");
        }
        let leaf = check(&good.replace("GET /", "GET /x/leafnode"), &ws(), false).unwrap();
        assert!(leaf.leaf);
    }

    #[test]
    fn options_come_from_the_headers() {
        let o = Websocket {
            compression: true,
            cookies: Cookies {
                user: Some("u".into()),
                pass: Some("p".into()),
                token: Some("t".into()),
            },
            ..ws()
        };
        let u = check(
            &request(
                "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nNats-No-Masking: true\r\nUser-Agent: Mozilla/5.0 Version/17 Safari/605\r\nCookie: u=al; p=\"pw\"\r\nCookie: t=tok; other=1\r\n",
            ),
            &o,
            false,
        )
        .unwrap();
        assert!(u.compress && u.no_masking);
        assert_eq!(u.agent, Agent::Safari);
        assert_eq!(u.cookies.user.as_deref(), Some("al"));
        assert_eq!(u.cookies.pass.as_deref(), Some("pw"));
        assert_eq!(u.cookies.token.as_deref(), Some("tok"));
        let r = response(&u, &[]);
        assert!(r.contains("permessage-deflate; server_no_context_takeover"));
        assert!(r.contains("Nats-No-Masking: true\r\n"));
        let plain = check(&request(""), &ws(), false).unwrap();
        assert_eq!(plain.cookies, Creds::default());
    }

    #[test]
    fn origins_are_checked_when_asked() {
        let same = Websocket {
            same_origin: true,
            ..ws()
        };
        let listed = Websocket {
            allowed_origins: vec!["https://app.example".into(), "http://b:81".into()],
            ..ws()
        };
        let origin = |o: &str| request(&format!("Origin: {o}\r\n"));
        assert!(check(&request(""), &same, false).is_ok(), "no origin");
        assert!(check(&origin("http://127.0.0.1:8080"), &same, false).is_ok());
        assert!(check(&origin("https://127.0.0.1:8080"), &same, true).is_ok());
        for bad in ["http://127.0.0.1:8081", "http://other:8080", "nonsense"] {
            assert_eq!(
                check(&origin(bad), &same, false),
                Err(Refusal::Forbidden),
                "{bad}"
            );
        }
        assert!(check(&origin("https://APP.example"), &listed, false).is_ok());
        assert!(check(&origin("https://app.example:443/x"), &listed, false).is_ok());
        assert!(check(&origin("http://b:81"), &listed, false).is_ok());
        for bad in ["http://app.example", "http://b", "https://c"] {
            assert_eq!(
                check(&origin(bad), &listed, false),
                Err(Refusal::Forbidden),
                "{bad}"
            );
        }
        assert_eq!(
            host_port("[::1]:9", false),
            ("::1".to_owned(), "9".to_owned())
        );
        assert_eq!(host_port("::1", true), ("::1".to_owned(), "443".to_owned()));
        assert!(Origin::parse("ftp://x").is_some_and(|o| !o.is_web()));
    }

    #[test]
    fn refusals_are_written_as_go_writes_them() {
        let t = UNIX_EPOCH + Duration::from_secs(1_793_738_839);
        assert_eq!(
            Refusal::MethodNotAllowed.response(t, false),
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain; charset=utf-8\r\nSec-Websocket-Version: 13\r\nX-Content-Type-Options: nosniff\r\nDate: Tue, 03 Nov 2026 20:47:19 GMT\r\nContent-Length: 19\r\n\r\nMethod Not Allowed\n"
        );
        let forbidden = Refusal::Forbidden.response(t, false);
        assert!(forbidden.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(
            Refusal::NotFound
                .response(t, false)
                .ends_with("\r\n\r\nNot Found\n")
        );
        let bad = Refusal::BadRequest.response(t, true);
        assert!(bad.contains("Content-Length: 12\r\n"));
        assert!(bad.contains("\r\nConnection: close\r\n"));
        assert!(asks_close("GET / HTTP/1.1\r\nConnection: Close\r\n\r\n"));
        assert!(!asks_close("GET / HTTP/1.1\r\nConnection: Upgrade\r\n\r\n"));
        assert!(request_line(b"GET /x HTTP/1.1\r"));
        assert!(!request_line(b"\x16\x03\x01"));
        assert!(!request_line(b"GET /x"));
        assert!(!request_line(b"GET /x HTTP/1.1 more"));
    }
}
