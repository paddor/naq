//! Parsing and encoding the leaf node wire.

#![expect(clippy::panic, reason = "tests fail loudly")]

use naq_proto::client::Limits;
use naq_proto::leaf::{self, Interest, LeafOp, Msg, ParseError, Parsed, Verb};

fn one(buf: &[u8]) -> (LeafOp<'_>, usize) {
    match leaf::parse(buf, &Limits::default()) {
        Ok(Parsed::Op(op, used)) => (op, used),
        other => panic!("{other:?} for {:?}", String::from_utf8_lossy(buf)),
    }
}

fn err(buf: &[u8]) -> ParseError {
    match leaf::parse(buf, &Limits::default()) {
        Err(e) => e,
        other => panic!("{other:?} for {:?}", String::from_utf8_lossy(buf)),
    }
}

const fn msg<'a>(subject: &'a [u8], reply: Option<&'a [u8]>, queues: &'a [u8]) -> Msg<'a> {
    Msg {
        subject,
        reply,
        queues,
        headers: None,
        payload: b"hi",
    }
}

#[test]
fn every_op_parses_and_reports_the_bytes_it_took() {
    let info = b"INFO {\"server_id\":\"x\"} \r\n";
    assert_eq!(
        one(info),
        (LeafOp::Info(b"{\"server_id\":\"x\"}"), info.len())
    );
    assert_eq!(one(b"CONNECT {}\r\n"), (LeafOp::Connect(b"{}"), 12));
    let plain = Interest {
        subject: b"a.b",
        queue: None,
        weight: 1,
    };
    assert_eq!(one(b"LS+ a.b\r\n"), (LeafOp::Sub(plain), 9));
    let queue = Interest {
        subject: b"a.*",
        queue: Some(b"q"),
        weight: 7,
    };
    assert_eq!(one(b"ls+ a.* q 7\r\n"), (LeafOp::Sub(queue), 13));
    let gone = Interest {
        subject: b"a.*",
        queue: Some(b"q"),
        weight: 0,
    };
    assert_eq!(one(b"LS- a.* q\r\n"), (LeafOp::Unsub(gone), 11));
    assert_eq!(one(b"PING\r\n"), (LeafOp::Ping, 6));
    assert_eq!(one(b"pong\n"), (LeafOp::Pong, 5));
    assert_eq!(one(b"+OK\r\n"), (LeafOp::Ok, 5));
    let e = b"-ERR 'Loop detected'\r\n";
    assert_eq!(one(e), (LeafOp::Err(b"Loop detected"), e.len()));
}

#[test]
fn a_weight_that_is_no_size_counts_as_one() {
    for w in ["0", "x", "1234567890"] {
        let line = format!("LS+ s q {w}\r\n");
        let (LeafOp::Sub(i), _) = one(line.as_bytes()) else {
            panic!("{line}")
        };
        assert_eq!(i.weight, 1, "{line}");
    }
}

#[test]
fn messages_carry_a_reply_and_queue_groups_as_markers_say() {
    let cases: [(&[u8], Msg<'_>); 6] = [
        (b"LMSG s 2\r\nhi\r\n", msg(b"s", None, b"")),
        (b"LMSG s r 2\r\nhi\r\n", msg(b"s", Some(b"r"), b"")),
        (b"LMSG s | 2\r\nhi\r\n", msg(b"s", Some(b"|"), b"")),
        (b"LMSG s | q1 q2 2\r\nhi\r\n", msg(b"s", None, b"q1 q2")),
        (
            b"LMSG s + r q1  q2 2\r\nhi\r\n",
            msg(b"s", Some(b"r"), b"q1  q2"),
        ),
        (b"LMSG s + r 2\r\nhi\r\n", msg(b"s", Some(b"r"), b"")),
    ];
    for (buf, want) in cases {
        assert_eq!(one(buf), (LeafOp::Msg(want), buf.len()));
    }
    let (LeafOp::Msg(m), _) = one(b"LMSG s + r q1 \t q2 2\r\nhi\r\n") else {
        panic!()
    };
    assert_eq!(m.queue_names().collect::<Vec<_>>(), [&b"q1"[..], b"q2"]);
}

#[test]
fn hmsg_has_a_header_size_before_the_total() {
    let buf = b"HMSG s | q 12 14\r\nNATS/1.0\r\n\r\nhi\r\n";
    let want = Msg {
        headers: Some(b"NATS/1.0\r\n\r\n"),
        ..msg(b"s", None, b"q")
    };
    assert_eq!(one(buf), (LeafOp::Msg(want), buf.len()));
    let buf = b"HMSG s r 12 14\r\nNATS/1.0\r\n\r\nhi\r\n";
    let (LeafOp::Msg(m), _) = one(buf) else {
        panic!()
    };
    assert_eq!((m.reply, m.queues), (Some(&b"r"[..]), &b""[..]));
}

#[test]
fn wrong_arguments_are_errors() {
    for (buf, e) in [
        (&b"LS+ s q\r\n"[..], ParseError::Args(Verb::Sub)),
        (b"LS+ s q 1 x\r\n", ParseError::Args(Verb::Sub)),
        (b"LS+ \n", ParseError::Args(Verb::Sub)),
        (b"LS- s q x\r\n", ParseError::Args(Verb::Unsub)),
        (b"LS- \n", ParseError::Args(Verb::Unsub)),
        (b"LMSG 5\r\n", ParseError::Args(Verb::Lmsg)),
        (b"LMSG s x q 2\r\nhi\r\n", ParseError::Args(Verb::Lmsg)),
        (b"HMSG s 2\r\n", ParseError::Args(Verb::Hmsg)),
        (b"LMSG s x\r\n", ParseError::Size(Verb::Lmsg)),
        (b"HMSG s x 2\r\n", ParseError::HeaderSize),
        (b"HMSG s 3 2\r\n", ParseError::HeaderSize),
        (b"LMSG s 2\r\nhiX\r\n", ParseError::MissingCrlf),
        (b"MSG s 2\r\n", ParseError::UnknownOp),
        (b"LS+s\r\n", ParseError::UnknownOp),
    ] {
        assert_eq!(err(buf), e, "{:?}", String::from_utf8_lossy(buf));
    }
}

#[test]
fn limits_bound_lines_and_payloads() {
    let limits = Limits {
        max_control_line: 8,
        max_payload: 4,
    };
    assert_eq!(
        leaf::parse(b"LMSG s 5\r\n", &limits),
        Err(ParseError::MaxPayload(5))
    );
    let mut long = b"LS+ ".to_vec();
    long.resize(8 + 64 + 1, b'a');
    assert_eq!(leaf::parse(&long, &limits), Err(ParseError::ControlLine));
}

#[test]
fn every_prefix_is_partial_until_the_operation_is_complete() {
    let ops: [&[u8]; 6] = [
        b"INFO {} \r\n",
        b"LS+ s q 2\r\n",
        b"LS- s\r\n",
        b"LMSG s + r q 2\r\nhi\r\n",
        b"HMSG s 12 14\r\nNATS/1.0\r\n\r\nhi\r\n",
        b"-ERR 'x'\r\n",
    ];
    for op in ops {
        for cut in 0..op.len() {
            match leaf::parse(&op[..cut], &Limits::default()) {
                Ok(Parsed::Partial(need)) => {
                    assert!(need.is_none_or(|n| n == op.len()), "{cut}: {need:?}");
                }
                other => panic!("{:?} at {cut}: {other:?}", String::from_utf8_lossy(op)),
            }
        }
        assert!(matches!(
            leaf::parse(op, &Limits::default()),
            Ok(Parsed::Op(..))
        ));
    }
}

#[test]
fn what_a_leaf_encodes_parses_back() {
    let mut out = Vec::new();
    leaf::sub(&mut out, b"a.>", None);
    leaf::sub(&mut out, b"a.b", Some((b"q", 3)));
    leaf::sub(&mut out, b"a.b", Some((b"q", 0)));
    leaf::unsub(&mut out, b"a.b", Some(b"q"));
    leaf::unsub(&mut out, b"a.>", None);
    leaf::connect(&mut out, b"{\"name\":\"n\"}");
    assert_eq!(
        out,
        b"LS+ a.>\r\nLS+ a.b q 3\r\nLS+ a.b q 1\r\nLS- a.b q\r\nLS- a.>\r\nCONNECT {\"name\":\"n\"}\r\n"
    );
    let headers: &[u8] = b"NATS/1.0\r\nA: b\r\n\r\n";
    for reply in [None, Some(&b"_INBOX.x"[..])] {
        for queues in [&b""[..], b"q", b"q1 q2"] {
            for h in [None, Some(headers)] {
                let m = Msg {
                    headers: h,
                    ..msg(b"s.t", reply, queues)
                };
                let mut out = Vec::new();
                m.encode(&mut out);
                assert_eq!(one(&out), (LeafOp::Msg(m), out.len()), "{m:?}");
            }
        }
    }
}

#[test]
fn errors_name_what_went_wrong() {
    assert_eq!(
        ParseError::Args(Verb::Lmsg).to_string(),
        "LMSG: wrong number of arguments"
    );
    assert_eq!(
        ParseError::Size(Verb::Hmsg).to_string(),
        "HMSG: bad or missing size"
    );
    assert_eq!(
        ParseError::MaxPayload(9).to_string(),
        "maximum payload exceeded: 9 bytes"
    );
}
