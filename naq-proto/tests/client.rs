//! Parsing what clients send.

#![expect(clippy::panic, reason = "tests fail loudly")]

use naq_proto::client::{ClientOp, Limits, ParseError, Parsed, Pub, Sub, Unsub, Verb, parse};

fn one(buf: &[u8]) -> (ClientOp<'_>, usize) {
    match parse(buf, &Limits::default()) {
        Ok(Parsed::Op(op, used)) => (op, used),
        other => panic!("{other:?} for {:?}", String::from_utf8_lossy(buf)),
    }
}

fn err(buf: &[u8]) -> ParseError {
    match parse(buf, &Limits::default()) {
        Err(e) => e,
        other => panic!("{other:?} for {:?}", String::from_utf8_lossy(buf)),
    }
}

const fn publish<'a>(
    subject: &'a [u8],
    reply: Option<&'a [u8]>,
    headers: Option<&'a [u8]>,
    payload: &'a [u8],
) -> ClientOp<'a> {
    ClientOp::Pub(Pub {
        subject,
        reply,
        headers,
        payload,
    })
}

#[test]
fn every_verb_parses_and_reports_the_bytes_it_took() {
    let cases: &[(&[u8], ClientOp<'_>)] = &[
        (
            br#"CONNECT {"verbose":false}"#,
            ClientOp::Connect(br#"{"verbose":false}"#),
        ),
        (b"PUB a.b 3\r\nabc", publish(b"a.b", None, None, b"abc")),
        (b"PUB a r 0\r\n", publish(b"a", Some(b"r"), None, b"")),
        (
            b"HPUB a 12 14\r\nNATS/1.0\r\n\r\nhi",
            publish(b"a", None, Some(b"NATS/1.0\r\n\r\n"), b"hi"),
        ),
        (
            b"HPUB a r 12 12\r\nNATS/1.0\r\n\r\n",
            publish(b"a", Some(b"r"), Some(b"NATS/1.0\r\n\r\n"), b""),
        ),
        (
            b"SUB a.* 1",
            ClientOp::Sub(Sub {
                subject: b"a.*",
                queue: None,
                sid: b"1",
            }),
        ),
        (
            b"SUB a.> q sid-x",
            ClientOp::Sub(Sub {
                subject: b"a.>",
                queue: Some(b"q"),
                sid: b"sid-x",
            }),
        ),
        (
            b"UNSUB 1",
            ClientOp::Unsub(Unsub {
                sid: b"1",
                max: None,
            }),
        ),
        (
            b"UNSUB 1 10",
            ClientOp::Unsub(Unsub {
                sid: b"1",
                max: Some(10),
            }),
        ),
        (b"PING", ClientOp::Ping),
        (b"PONG", ClientOp::Pong),
    ];
    for (body, want) in cases {
        let mut buf = body.to_vec();
        buf.extend_from_slice(b"\r\n");
        let len = buf.len();
        buf.extend_from_slice(b"PING\r\n");
        assert_eq!(one(&buf), (*want, len));
    }
}

#[test]
fn verbs_take_any_case_and_lines_may_end_in_lf_alone() {
    assert_eq!(
        one(b"pub a 1\nx\r\n"),
        (publish(b"a", None, None, b"x"), 11)
    );
    assert_eq!(one(b"PiNg\n").0, ClientOp::Ping);
    assert_eq!(one(b"pong\r\n").0, ClientOp::Pong);
    assert_eq!(one(b"sUb a 1\n").0, one(b"SUB a 1\r\n").0);
    assert_eq!(one(b"cOnNeCt {}\n").0, ClientOp::Connect(b"{}"));
}

#[test]
fn blanks_separate_arguments_and_ping_ignores_its_line() {
    assert_eq!(
        one(b"PUB\t a \t r  2 \r\nhi\r\n").0,
        publish(b"a", Some(b"r"), None, b"hi")
    );
    assert_eq!(one(b"PING whatever\r\n"), (ClientOp::Ping, 15));
    assert_eq!(
        one(b"CONNECT  \t{\"a\": 1}\r\n").0,
        ClientOp::Connect(b"{\"a\": 1}")
    );
}

#[test]
fn payloads_are_counted_not_scanned() {
    let (op, used) = one(b"PUB a 6\r\n\r\nPUB \r\n\r\n");
    assert_eq!(op, publish(b"a", None, None, b"\r\nPUB "));
    assert_eq!(used, 17);
    let bin = [0u8, 255, b'\n', 0];
    let mut buf = b"PUB a 4\r\n".to_vec();
    buf.extend_from_slice(&bin);
    buf.extend_from_slice(b"\r\n");
    assert_eq!(one(&buf).0, publish(b"a", None, None, &bin));
}

#[test]
fn every_prefix_is_partial_until_the_operation_is_complete() {
    let ops: &[&[u8]] = &[
        b"PUB subject.x _INBOX.y 5\r\nhello\r\n",
        b"HPUB s 12 13\r\nNATS/1.0\r\n\r\nx\r\n",
        b"SUB s q 9\r\n",
        b"UNSUB 9 3\r\n",
        b"CONNECT {}\r\n",
        b"PING\r\n",
        b"PONG\n",
    ];
    for op in ops {
        let control = op.iter().position(|&b| b == b'\n').unwrap() + 1;
        for cut in 0..op.len() {
            let got = parse(&op[..cut], &Limits::default()).unwrap();
            let is_msg = op.starts_with(b"PUB") || op.starts_with(b"HPUB");
            let want = if is_msg && cut >= control {
                Parsed::Partial(Some(op.len()))
            } else {
                Parsed::Partial(None)
            };
            assert_eq!(got, want, "{:?} cut at {cut}", String::from_utf8_lossy(op));
        }
        assert_eq!(one(op).1, op.len());
    }
}

#[test]
fn a_stream_parses_operation_by_operation() {
    let stream = b"CONNECT {}\r\nSUB a 1\r\nPUB a 2\r\nhi\r\nUNSUB 1\r\nPING\r\n";
    let mut at = 0;
    let mut verbs = Vec::new();
    while at < stream.len() {
        let (op, used) = one(&stream[at..]);
        verbs.push(op);
        at += used;
    }
    assert_eq!(at, stream.len());
    assert_eq!(verbs.len(), 5);
    assert_eq!(verbs[4], ClientOp::Ping);
}

#[test]
fn unknown_verbs_fail_at_the_first_wrong_byte() {
    assert_eq!(err(b"X"), ParseError::UnknownOp);
    assert_eq!(err(b"PX"), ParseError::UnknownOp);
    assert_eq!(err(b"PUX"), ParseError::UnknownOp);
    assert_eq!(err(b"PUBX"), ParseError::UnknownOp);
    assert_eq!(err(b"PUB\r\n"), ParseError::UnknownOp);
    assert_eq!(err(b"MSG a 1 0\r\n\r\n"), ParseError::UnknownOp);
    assert_eq!(err(b"+OK\r\n"), ParseError::UnknownOp);
    assert_eq!(err(b"\r\n"), ParseError::UnknownOp);
}

#[test]
fn wrong_arguments_are_errors() {
    assert_eq!(err(b"PUB a\r\n"), ParseError::Args(Verb::Pub));
    assert_eq!(err(b"PUB a b c 1\r\n"), ParseError::Args(Verb::Pub));
    assert_eq!(err(b"PUB a x\r\n"), ParseError::Size(Verb::Pub));
    assert_eq!(err(b"PUB a -1\r\n"), ParseError::Size(Verb::Pub));
    assert_eq!(err(b"PUB a 1000000000\r\n"), ParseError::Size(Verb::Pub));
    assert_eq!(err(b"HPUB a 1\r\n"), ParseError::Args(Verb::Hpub));
    assert_eq!(err(b"HPUB a r 1 2 3\r\n"), ParseError::Args(Verb::Hpub));
    assert_eq!(err(b"HPUB a x 2\r\n"), ParseError::HeaderSize);
    assert_eq!(err(b"HPUB a 3 2\r\n"), ParseError::HeaderSize);
    assert_eq!(err(b"HPUB a 2 x\r\n"), ParseError::Size(Verb::Hpub));
    assert_eq!(err(b"SUB a\r\n"), ParseError::Args(Verb::Sub));
    assert_eq!(err(b"SUB a q 1 2\r\n"), ParseError::Args(Verb::Sub));
    assert_eq!(err(b"UNSUB \r\n"), ParseError::Args(Verb::Unsub));
    assert_eq!(err(b"UNSUB 1 2 3\r\n"), ParseError::Args(Verb::Unsub));
}

#[test]
fn a_bad_unsub_max_ends_the_subscription_at_once() {
    let ClientOp::Unsub(u) = one(b"UNSUB 1 x\r\n").0 else {
        panic!("not an UNSUB")
    };
    assert_eq!(u.max, None);
}

#[test]
fn a_message_must_end_in_crlf() {
    assert_eq!(err(b"PUB a 1\r\nxyz"), ParseError::MissingCrlf);
    assert_eq!(err(b"PUB a 1\r\nx\n\r"), ParseError::MissingCrlf);
}

#[test]
fn limits_bound_lines_and_payloads() {
    let limits = Limits {
        max_control_line: 16,
        max_payload: 8,
    };
    assert_eq!(
        parse(b"PUB a 9\r\n", &limits),
        Err(ParseError::MaxPayload(9))
    );
    assert_eq!(
        parse(b"HPUB a 2 9\r\n", &limits),
        Err(ParseError::MaxPayload(9))
    );
    assert!(matches!(
        parse(b"PUB a 8\r\n12345678\r\n", &limits),
        Ok(Parsed::Op(..))
    ));
    let long = b"SUB aaaaaaaaaaaaaaa 1\r\n";
    assert_eq!(parse(long, &limits), Err(ParseError::ControlLine));
    let ok = b"SUB aaaaaaaaaaaa 1\r\n";
    assert!(matches!(parse(ok, &limits), Ok(Parsed::Op(..))));

    // No line end: partial until the line could no longer fit.
    let mut endless = b"SUB ".to_vec();
    endless.resize(16 + 63, b'a');
    assert_eq!(parse(&endless, &limits), Ok(Parsed::Partial(None)));
    endless.push(b'a');
    assert_eq!(parse(&endless, &limits), Err(ParseError::ControlLine));
    let mut pings = b"PING".to_vec();
    pings.resize(200, b' ');
    assert_eq!(parse(&pings, &limits), Err(ParseError::ControlLine));
}

#[test]
fn errors_name_what_went_wrong() {
    assert_eq!(
        ParseError::UnknownOp.to_string(),
        "unknown protocol operation"
    );
    assert_eq!(
        ParseError::Args(Verb::Unsub).to_string(),
        "UNSUB: wrong number of arguments"
    );
    assert_eq!(
        ParseError::Size(Verb::Hpub).to_string(),
        "HPUB: bad or missing size"
    );
    assert_eq!(
        ParseError::MaxPayload(9).to_string(),
        "maximum payload exceeded: 9 bytes"
    );
    for e in [
        ParseError::ControlLine,
        ParseError::HeaderSize,
        ParseError::MissingCrlf,
    ] {
        assert_ne!(e.to_string(), "");
    }
}
