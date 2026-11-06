use std::cell::RefCell;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// Answers with the path and query it got, and notes them.
#[derive(Default)]
struct Echo(RefCell<Vec<String>>);

impl Handler for Echo {
    fn answer(&self, req: &Request) -> impl Future<Output = Response> {
        let seen = format!("{}?{}", req.path, req.query);
        self.0.borrow_mut().push(seen.clone());
        std::future::ready(Response::text(200, seen))
    }
}

/// What the server writes back to `sent`, `Date` lines left out, once
/// it closes or idles.
fn exchange(sent: &[u8]) -> (String, Vec<String>) {
    exchange_in(&[sent])
}

/// As [`exchange`], with `pieces` sent a second apart.
fn exchange_in(pieces: &[&[u8]]) -> (String, Vec<String>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    rt.block_on(async {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let echo = Echo::default();
        let serving = serve(server, &echo);
        let talking = async {
            for p in pieces {
                client.write_all(p).await.unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            let mut got = Vec::new();
            let _ = client.read_to_end(&mut got).await;
            got
        };
        let ((), got) = tokio::join!(serving, talking);
        let text = String::from_utf8(got).unwrap();
        let text: String = text
            .split_inclusive("\r\n")
            .filter(|l| !l.starts_with("Date: "))
            .collect();
        (text, echo.0.into_inner())
    })
}

#[test]
fn requests_on_one_connection_are_answered_in_turn() {
    let (got, seen) = exchange(
        b"GET /a?x=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc\
          POST /b HTTP/1.1\nHost: h\n\nHEAD /c HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(seen, ["/a?x=1", "/b?", "/c?"]);
    assert_eq!(
        got,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 6\r\n\r\n/a?x=1\
         HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 3\r\n\r\n/b?\
         HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 3\r\nConnection: close\r\n\r\n"
    );
}

#[test]
fn http_1_0_closes_unless_kept_alive() {
    let (got, _) = exchange(b"GET /a HTTP/1.0\r\n\r\nGET /b HTTP/1.0\r\n\r\n");
    assert_eq!(got.matches("HTTP/1.0 200 OK").count(), 1);
    let (got, seen) =
        exchange(b"GET /a HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\nGET /b HTTP/1.0\r\n\r\n");
    assert_eq!(seen, ["/a?", "/b?"]);
    assert!(got.contains("Connection: keep-alive\r\n"), "{got}");
}

#[test]
fn paths_are_decoded_and_unclean_ones_redirected() {
    let (got, seen) = exchange(b"GET /health%7A HTTP/1.1\r\nHost: h\r\n\r\nGET http://h:1/x?y HTTP/1.1\r\nHost: h\r\n\r\nGET //a/./b/../c?q=1 HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert_eq!(seen, ["/healthz?", "/x?y"]);
    assert!(
        got.ends_with(
            "HTTP/1.1 307 Temporary Redirect\r\nContent-Type: text/html; charset=utf-8\r\nLocation: /a/c?q=1\r\nContent-Length: 44\r\nConnection: close\r\n\r\n<a href=\"/a/c?q=1\">Temporary Redirect</a>.\n\n"
        ),
        "{got}"
    );
    let (got, _) = exchange(b"DELETE /a/. HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert_eq!(
        got,
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: /a\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(clean("/a/"), None);
    assert_eq!(clean("/a/../.."), Some("/".into()));
    assert_eq!(escape_path("/a b\u{e9}"), "/a%20b%C3%A9");
    assert_eq!(html_escape("<'&\">"), "&lt;&#39;&amp;&#34;&gt;");
}

#[test]
fn bad_requests_get_go_answers_and_a_close() {
    for (sent, want) in [
        (&b"GET\r\n\r\n"[..], BAD),
        (b"GET /a\r\n\r\n", BAD),
        (b"GET a HTTP/1.1\r\nHost: h\r\n\r\n", BAD),
        (b"G(T /a HTTP/1.1\r\nHost: h\r\n\r\n", BAD),
        (b"GET /a HTTP/1.1\r\n\r\n", NO_HOST),
        (b"GET /a HTTP/1.1\r\nHost: h\r\nHost: i\r\n\r\n", BAD),
        (b"GET /a HTTP/1.1\r\nHost: h\r\nnocolon\r\n\r\n", BAD),
        (b"GET /a HTTP/1.1\r\nHost: h\r\nBad Name: x\r\n\r\n", BAD),
        (
            b"GET /a HTTP/1.1\r\nHost: h\r\nContent-Length: x\r\n\r\n",
            BAD,
        ),
        (b"GET /a HTTP/2.0\r\nHost: h\r\n\r\n", VERSION),
        (b"GET /a FTP/1.1\r\nHost: h\r\n\r\n", BAD),
        (b"GET /%zz HTTP/1.1\r\nHost: h\r\n\r\n", BAD),
        (b"GET /a HTTP/1.1\r\nHost: \xff\r\n\r\n", BAD),
    ] {
        let (got, seen) = exchange(sent);
        assert_eq!(got, want, "{sent:?}");
        assert_eq!(seen, [] as [String; 0]);
    }
    let mut huge = b"GET /a HTTP/1.1\r\nHost: h\r\nX: ".to_vec();
    huge.resize(MAX_HEAD + 10, b'x');
    assert_eq!(exchange(&huge).0, TOO_LARGE);
}

#[test]
fn a_body_it_cannot_drop_ends_the_connection() {
    let (got, seen) = exchange(
        b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n",
    );
    assert_eq!(seen, ["/a?"]);
    assert!(got.contains("Connection: close"), "{got}");
    let (_, seen) = exchange(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 999999\r\n\r\n");
    assert_eq!(seen, ["/a?"]);
    // The peer stops before the body it announced ends.
    let (got, _) = exchange(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nab");
    assert!(got.ends_with("Connection: close\r\n\r\n/a?"), "{got}");
}

#[test]
fn a_connection_that_idles_or_stalls_is_closed() {
    assert_eq!(exchange(b"").0, "");
    assert_eq!(exchange(b"GET /a HTTP/1.1\r\n").0, "");
}

#[test]
fn reasons_cover_the_statuses_it_sends() {
    for s in [200, 307, 400, 404, 500, 503] {
        assert_ne!(reason(s), "");
    }
    assert_eq!(reason(299), "");
}

#[test]
fn heads_and_bodies_may_come_in_pieces() {
    let (got, seen) = exchange_in(&[
        b"POST /a HTTP/1.1\r\nHost: h\r\nContent-",
        b"Length: 4\r\n\r\nab",
        b"cdGET /b HTTP/1.1\r\nHo",
        b"st: h\r\n\r\nGET /c HT",
        b"TP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    ]);
    assert_eq!(seen, ["/a?", "/b?", "/c?"]);
    assert!(got.ends_with("Connection: close\r\n\r\n/c?"), "{got}");
}
