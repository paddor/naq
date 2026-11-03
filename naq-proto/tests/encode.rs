//! Encoding what a server sends.

use bytes::BytesMut;
use naq_proto::encode::{self, Msg};

fn encoded(m: &Msg<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    m.encode(&mut out);
    assert_eq!(out.len(), m.encoded_len(), "{m:?}");
    out
}

#[test]
fn msg_and_hmsg_carry_sid_reply_and_sizes() {
    let base = Msg {
        subject: b"a.b",
        sid: b"42",
        reply: None,
        headers: None,
        payload: b"hello",
    };
    assert_eq!(encoded(&base), b"MSG a.b 42 5\r\nhello\r\n");
    let reply = Msg {
        reply: Some(b"_INBOX.x"),
        ..base
    };
    assert_eq!(encoded(&reply), b"MSG a.b 42 _INBOX.x 5\r\nhello\r\n");
    let hdr = Msg {
        headers: Some(b"NATS/1.0\r\n\r\n"),
        ..base
    };
    assert_eq!(
        encoded(&hdr),
        b"HMSG a.b 42 12 17\r\nNATS/1.0\r\n\r\nhello\r\n"
    );
    let both = Msg {
        reply: Some(b"r"),
        headers: Some(b"NATS/1.0\r\n\r\n"),
        payload: b"",
        ..base
    };
    assert_eq!(
        encoded(&both),
        b"HMSG a.b 42 r 12 12\r\nNATS/1.0\r\n\r\n\r\n"
    );
}

#[test]
fn lengths_count_every_digit() {
    let payload = vec![b'x'; 1_000_000];
    for n in [0, 9, 10, 99, 100, 1024, 1_000_000] {
        let m = Msg {
            subject: b"s",
            sid: b"1",
            reply: None,
            headers: Some(b"NATS/1.0\r\n\r\n"),
            payload: &payload[..n],
        };
        encoded(&m);
        encoded(&Msg { headers: None, ..m });
    }
}

#[test]
fn any_buf_mut_takes_the_output() {
    let m = Msg {
        subject: b"s",
        sid: b"1",
        reply: None,
        headers: None,
        payload: b"x",
    };
    let mut out = BytesMut::new();
    m.encode(&mut out);
    let mut fixed = [0u8; 16];
    let mut slice = &mut fixed[..];
    m.encode(&mut slice);
    assert_eq!(&out[..], &fixed[..m.encoded_len()]);
}

#[test]
fn control_lines_are_fixed_or_framed() {
    assert_eq!(encode::PING, b"PING\r\n");
    assert_eq!(encode::PONG, b"PONG\r\n");
    assert_eq!(encode::OK, b"+OK\r\n");
    let mut out = Vec::new();
    encode::info(&mut out, br#"{"max_payload":1048576}"#);
    encode::err(&mut out, "Unknown Protocol Operation");
    assert_eq!(
        out,
        b"INFO {\"max_payload\":1048576}\r\n-ERR 'Unknown Protocol Operation'\r\n"
    );
}
