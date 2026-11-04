//! The client side of a WebSocket, for leaf node links to hubs: the
//! upgrade request, then NATS bytes over masked frames.

use std::io::Cursor;
use std::rc::Rc;

use data_encoding::BASE64;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::stream::{Link, Reader, Writer};
use super::upgrade::{MAX_REQUEST, accept_key};
use crate::conn::Client;

/// Asks the server at `host:port` over `io` to take it as a leaf node link
/// at `path`, as `nats-server` asks, and checks its answer. Returns what
/// came after the answer: frames already.
pub(crate) async fn upgrade<S>(io: &mut S, host: &str, port: u16, path: &str) -> Option<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).ok()?;
    let key = BASE64.encode(&raw);
    io.write_all(request(host, port, path, &key).as_bytes())
        .await
        .ok()?;
    let (head, rest) = response(io).await?;
    accepts(&head, &key).then_some(rest)
}

/// The NATS byte stream over the frames of `io`, `pre` read of them
/// already; `client` is the link whose writer answers pings.
pub(crate) fn stream<S>(
    io: S,
    pre: Vec<u8>,
    client: Rc<Client>,
    max_payload: usize,
) -> impl AsyncRead + AsyncWrite + Unpin + 'static
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let (r, w) = tokio::io::split(io);
    let link = Link::new(client);
    let reader = Reader::client(Cursor::new(pre).chain(r), link.clone(), max_payload);
    tokio::io::join(reader, Writer::client(w, link))
}

/// The upgrade request for `path`, with `/leafnode` after it.
fn request(host: &str, port: u16, path: &str, key: &str) -> String {
    let path = path.trim_matches('/');
    let path = if path.is_empty() {
        "/leafnode".to_owned()
    } else {
        format!("/{path}/leafnode")
    };
    let host = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
}

/// The head of the server's answer, and what came after it.
async fn response<R: AsyncRead + Unpin>(r: &mut R) -> Option<(String, Vec<u8>)> {
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
            let rest = buf.split_off(from + at + 4);
            return String::from_utf8(buf).ok().map(|h| (h, rest));
        }
        if buf.len() >= MAX_REQUEST {
            return None;
        }
    }
}

/// Whether `head` takes the upgrade asked for with `key`, as `nats-server`
/// checks it.
pub(super) fn accepts(head: &str, key: &str) -> bool {
    let mut lines = head.split("\r\n");
    let status = lines.next().and_then(|l| l.split(' ').nth(1));
    let header = |name: &str| {
        head.split("\r\n").skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    };
    status == Some("101")
        && header("Upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && header("Connection").is_some_and(|v| v.eq_ignore_ascii_case("upgrade"))
        && header("Sec-WebSocket-Accept") == Some(accept_key(key).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_asks_for_the_leafnode_path() {
        let r = request("hub", 443, "", "k");
        assert!(
            r.starts_with("GET /leafnode HTTP/1.1\r\nHost: hub:443\r\n"),
            "{r}"
        );
        assert!(r.ends_with("Sec-WebSocket-Key: k\r\nSec-WebSocket-Version: 13\r\n\r\n"));
        assert!(request("hub", 1, "/a/b/", "k").starts_with("GET /a/b/leafnode "));
        assert!(request("::1", 1, "/", "k").contains("Host: [::1]:1\r\n"));
    }

    #[test]
    fn only_an_answer_with_the_right_key_upgrades() {
        let ok = |accept: &str| {
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
        };
        // The example of RFC 6455 1.3.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert!(accepts(&ok("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), key));
        assert!(!accepts(&ok("bogus"), key));
        assert!(!accepts(
            &ok("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=").replace("101", "200"),
            key
        ));
        assert!(!accepts("HTTP/1.1 101 OK\r\n\r\n", key));
    }

    #[tokio::test]
    async fn bytes_after_the_answer_are_kept_for_the_stream() {
        let mut input: &[u8] = b"HTTP/1.1 101 x\r\nA: b\r\n\r\n\x82\x02hi";
        let (head, rest) = response(&mut input).await.unwrap();
        assert_eq!(head, "HTTP/1.1 101 x\r\nA: b\r\n\r\n");
        assert_eq!(rest, b"\x82\x02hi");
        let mut short: &[u8] = b"HTTP/1.1 101";
        assert!(response(&mut short).await.is_none());
    }
}
