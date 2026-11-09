//! WebSocket clients, as `nats-server` serves them: a port of their own,
//! TLS if set up, the HTTP upgrade, then the client protocol over binary
//! frames.

pub(crate) mod client;
mod deflate;
mod frame;
mod stream;
mod upgrade;

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::SystemTime;

use naq_proto::client::ParseError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use zzq_tokio::transport::Stream;

use crate::conn::{self, Close};
use crate::lane::{self, Lane};
use crate::server::Shared;
use crate::{Websocket, tls};

/// The WebSocket port, as the server runs it.
#[derive(Debug)]
pub(crate) struct Door {
    pub(crate) opts: Websocket,
    pub(crate) tls: Option<tls::Acceptor>,
    /// Where it listens, as bound.
    pub(crate) addr: SocketAddr,
}

/// Why WebSocket options `o` cannot run, in the words of `nats-server`.
pub(crate) fn validate(o: &Websocket) -> Result<(), String> {
    if o.tls.is_none() && !o.no_tls {
        return Err("websocket requires TLS configuration".into());
    }
    for a in &o.allowed_origins {
        if !upgrade::Origin::parse(a).is_some_and(|u| u.is_web()) {
            return Err(format!(
                "unable to parse allowed origin {a:?}: allowed origins must be absolute URLs with http or https scheme"
            ));
        }
    }
    for (k, v) in &o.headers {
        let lower = k.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host" | "content-length" | "connection" | "upgrade" | "nats-no-masking"
        ) {
            return Err(format!("websocket: invalid header {k:?} not allowed"));
        }
        if lower.starts_with("sec-websocket-") {
            return Err(format!(
                "websocket: invalid header {k:?}, \"Sec-WebSocket-\" prefix not allowed"
            ));
        }
        if [k, v].iter().any(|s| s.contains(['\r', '\n'])) || k.contains(':') {
            return Err(format!("websocket: invalid header {k:?}"));
        }
    }
    Ok(())
}

/// Runs a WebSocket client that reached lane `index`.
pub(crate) async fn run(shared: Arc<Shared>, index: usize, stream: Stream) {
    let Some(lane) = lane::get(shared.id, index) else {
        return;
    };
    let Some(door) = shared.ws.as_ref() else {
        return;
    };
    let Stream::Tcp(s) = stream else {
        return;
    };
    let peer = s
        .peer_addr()
        .map(|a| (a.ip().to_canonical().to_string(), a.port()))
        .unwrap_or_default();
    let Ok(tcp) = s
        .set_nonblocking(true)
        .and_then(|()| tokio::net::TcpStream::from_std(s))
    else {
        return;
    };
    let _ = tcp.set_nodelay(true);
    let limit = door.opts.handshake_timeout;
    let deadline = (!limit.is_zero()).then(|| Instant::now() + limit);
    let mut arrival = Arrival {
        peer,
        tls: false,
        cert: None,
        facts: None,
        deadline,
    };
    match &door.tls {
        None => {
            let (r, w) = tcp.into_split();
            open(lane, r, w, arrival).await;
        }
        Some(acc) => {
            let Some(Some(tls)) = within(deadline, acc.accept(tcp)).await else {
                return;
            };
            arrival.cert = acc.names(&tls);
            arrival.facts = Some(Box::new(crate::tls::Facts::of(&tls, true)));
            let (r, w) = tokio::io::split(tls);
            arrival.tls = true;
            open(lane, r, w, arrival).await;
        }
    }
}

/// `f`, given until `deadline` if there is one. `None` if it ran out.
async fn within<F: Future>(deadline: Option<Instant>, f: F) -> Option<F::Output> {
    match deadline {
        Some(d) => tokio::time::timeout_at(d, f).await.ok(),
        None => Some(f.await),
    }
}

/// How a connection came.
struct Arrival {
    /// IP address and port.
    peer: (String, u16),
    /// Over TLS.
    tls: bool,
    /// What its certificate names, where certificates name users.
    cert: Option<Box<crate::tls::cert::Names>>,
    /// Its TLS, for monitoring.
    facts: Option<Box<crate::tls::Facts>>,
    /// When its upgrade must be done by, if ever.
    deadline: Option<Instant>,
}

/// Upgrades the connection over `r` and `w` and serves the client.
async fn open<R, W>(lane: Rc<Lane>, mut r: R, mut w: W, arrival: Arrival)
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
{
    let shared = lane.shared.clone();
    let Some(door) = shared.ws.as_ref() else {
        return;
    };
    let Some(Some((head, early))) = within(arrival.deadline, read_head(&mut r)).await else {
        return;
    };
    let u = match upgrade::check(&head, &door.opts, arrival.tls) {
        Ok(u) if !early => u,
        // Data before the upgrade: the client did not wait for it, and
        // `nats-server` drops it.
        Ok(_) => return,
        Err(refusal) => {
            let close = upgrade::asks_close(&head);
            let _ = w
                .write_all(refusal.response(SystemTime::now(), close).as_bytes())
                .await;
            let _ = w.shutdown().await;
            return;
        }
    };
    let response = upgrade::response(&u, &door.opts.headers);
    let sent = w.write_all(response.as_bytes()).await.is_ok() && w.flush().await.is_ok();
    if !sent || u.leaf {
        let _ = w.shutdown().await;
        return;
    }
    let (ip, port) = arrival.peer;
    let (mut hello, info) = conn::greet(&lane, ip, port, true);
    hello.client.out.borrow_mut().extend_from_slice(&info);
    let link = stream::Link::new(hello.client.clone());
    let reader = stream::Reader::new(r, link.clone(), &u, shared.opts().max_payload);
    let writer = stream::Writer::new(w, link, &u);
    hello.via.cookies = Some(Box::new(u.cookies));
    hello.via.cert = arrival.cert;
    hello.client.meta.borrow_mut().tls = arrival.facts;
    conn::serve(lane, hello, reader, writer).await;
}

/// The head of the upgrade request, and whether more came after it. A
/// first line that is no request line is all there is: it gets refused
/// without waiting for more, as Go refuses it.
async fn read_head<R: AsyncRead + Unpin>(r: &mut R) -> Option<(String, bool)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let from = buf.len().saturating_sub(3);
        let n = r.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = memchr::memmem::find(&buf[from..], b"\r\n\r\n") {
            let end = from + at + 4;
            let early = buf.len() > end;
            buf.truncate(end);
            return String::from_utf8(buf).ok().map(|h| (h, early));
        }
        if let Some(nl) = memchr::memchr(b'\n', &buf)
            && !upgrade::request_line(&buf[..nl])
        {
            return Some((String::from_utf8_lossy(&buf[..nl]).into_owned(), false));
        }
        if buf.len() >= upgrade::MAX_REQUEST {
            return None;
        }
    }
}

/// The status and text of the close frame for a connection the server
/// ends for `why`, as `nats-server` maps its reasons.
pub(super) fn closing(why: Option<Close>) -> (u16, &'static str) {
    let Some(why) = why else {
        return (frame::GOING_AWAY, "Server Shutdown");
    };
    let status = match why {
        Close::Lost => frame::NORMAL,
        Close::Parse(ParseError::MaxPayload(_)) => frame::TOO_BIG,
        Close::Parse(ParseError::ControlLine)
        | Close::SlowPending
        | Close::SlowWrite(_)
        | Close::Auth
        | Close::Unsigned
        | Close::AuthTimeout
        | Close::AccountConns
        | Close::UserExpired
        | Close::AccountExpired
        | Close::MaxSubs
        | Close::Revoked => frame::POLICY,
        Close::Parse(_) | Close::Connect | Close::NoHeaders => frame::PROTOCOL_ERROR,
        Close::Refused(text) if text == conn::BAD_PROTOCOL => frame::PROTOCOL_ERROR,
        Close::Stale | Close::WriteError | Close::Shutdown => frame::GOING_AWAY,
        Close::Refused(_) | Close::Kicked => frame::INTERNAL,
    };
    (status, why.reason())
}

/// Reads an upgrade request and the frames after it from `data`, as a lane
/// would from a socket, in pieces of a size the input picks. For the fuzz
/// targets.
///
/// # Panics
///
/// When the reader keeps more than it read, or a message does not come
/// back from deflating and inflating it.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz(data: &[u8]) {
    let (head, frames) = match memchr::memmem::find(data, b"\r\n\r\n") {
        Some(at) => data.split_at(at + 4),
        None => (data, &[][..]),
    };
    if let Some(nl) = memchr::memchr(b'\n', head) {
        let _ = upgrade::request_line(&head[..nl]);
    }
    let opts = Websocket {
        no_tls: true,
        compression: true,
        same_origin: true,
        allowed_origins: vec!["http://a.example".into()],
        cookies: crate::Cookies {
            user: Some("u".into()),
            pass: Some("p".into()),
            token: Some("t".into()),
        },
        ..Websocket::default()
    };
    let text = String::from_utf8_lossy(head);
    let _ = upgrade::asks_close(&text);
    let u = upgrade::check(&text, &opts, false).unwrap_or_else(|_| upgrade::Upgrade {
        compress: true,
        ..upgrade::Upgrade::default()
    });
    let _ = upgrade::response(&u, &[("X-A".into(), "b".into())]);
    let link = stream::Link::new(Rc::new(conn::Client::new(1)));
    let mut reader = stream::Reader::new((), link, &u, 4096);
    let step = usize::from(frames.first().copied().unwrap_or(1)).max(1);
    for piece in frames.chunks(step) {
        let mut raw = piece.to_vec();
        let kept = reader.take(&mut raw);
        assert!(kept <= piece.len(), "kept {kept} of {}", piece.len());
    }
    // The same bytes as a hub's answer and frames, to a leaf.
    let _ = client::accepts(&text, "dGhlIHNhbXBsZSBub25jZQ==");
    let link = stream::Link::new(Rc::new(conn::Client::new(2)));
    let mut leaf = stream::Reader::client((), link, 4096);
    for piece in frames.chunks(step) {
        let mut raw = piece.to_vec();
        assert!(leaf.take(&mut raw) <= piece.len());
    }
    let mut packed = Vec::new();
    deflate::Deflate::new().message(frames, &mut packed);
    let mut inflate = deflate::Inflate::new();
    let mut back = Vec::new();
    let limit = frames.len() * 2 + 64;
    assert!(inflate.push(&packed, limit).is_ok() && inflate.finish(&mut back, limit).is_ok());
    assert_eq!(back, frames);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_checked_as_nats_server_checks_them() {
        let ok = Websocket {
            no_tls: true,
            allowed_origins: vec!["https://a.example:8443".into()],
            headers: vec![("X-Frame-Options".into(), "DENY".into())],
            ..Websocket::default()
        };
        assert_eq!(validate(&ok), Ok(()));
        let no_tls = Websocket {
            no_tls: false,
            ..ok.clone()
        };
        assert_eq!(
            validate(&no_tls).unwrap_err(),
            "websocket requires TLS configuration"
        );
        for origin in ["ftp://a", "a.example", "http://"] {
            let o = Websocket {
                allowed_origins: vec![origin.into()],
                ..ok.clone()
            };
            assert!(validate(&o).is_err(), "{origin}");
        }
        for name in ["Upgrade", "Sec-WebSocket-Accept", "X:Y", "Bad\r\nName"] {
            let o = Websocket {
                headers: vec![(name.into(), "v".into())],
                ..ok.clone()
            };
            assert!(validate(&o).is_err(), "{name}");
        }
    }

    #[test]
    fn closes_get_the_status_nats_server_gives() {
        let cases = [
            (Some(Close::Lost), 1000),
            (Some(Close::Kicked), 1011),
            (Some(Close::SlowPending), 1008),
            (Some(Close::SlowWrite(1)), 1008),
            (Some(Close::WriteError), 1001),
            (Some(Close::Parse(ParseError::MaxPayload(0))), 1009),
            (Some(Close::Parse(ParseError::ControlLine)), 1008),
            (Some(Close::Connect), 1002),
            (Some(Close::NoHeaders), 1002),
            (Some(Close::Refused(conn::BAD_PROTOCOL)), 1002),
            (Some(Close::Refused("other")), 1011),
            (Some(Close::Stale), 1001),
            (Some(Close::Auth), 1008),
            (Some(Close::AuthTimeout), 1008),
            (None, 1001),
        ];
        for (why, status) in cases {
            assert_eq!(closing(why).0, status, "{why:?}");
        }
    }

    #[tokio::test]
    async fn the_head_ends_at_the_blank_line() {
        let req = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let (head, early) = read_head(&mut &req[..]).await.unwrap();
        assert_eq!(head.as_bytes(), req);
        assert!(!early);
        let more = [&req[..], b"PING\r\n"].concat();
        assert!(read_head(&mut &more[..]).await.unwrap().1);
        assert!(read_head(&mut &b"GET / HTTP/1.1\r\n"[..]).await.is_none());
        let (junk, _) = read_head(&mut &b"\x16\x03\x01\n\x02 rest"[..])
            .await
            .unwrap();
        assert!(upgrade::check(&junk, &Websocket::default(), false).is_err());
        let huge = vec![b'a'; upgrade::MAX_REQUEST + 1];
        assert!(read_head(&mut &huge[..]).await.is_none());
    }
}
