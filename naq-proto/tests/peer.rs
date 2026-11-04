//! The peer wire: every message decodes to what was encoded, and broken
//! input is an error, never a panic.

use naq_proto::peer::{self, Batch, Control, Error, Hello, Interest, Record, Role};

fn controls() -> Vec<Control<'static>> {
    let i = Interest {
        account: b"$G",
        subject: b"orders.*",
        queue: Some(b"workers"),
        weight: 3,
        origin: None,
    };
    let hello = Hello {
        role: Role::Route,
        account: b"",
        epoch: 7,
        server_id: b"NABC",
        name: b"a",
        cluster: b"c",
        data: b"tcp://127.0.0.1:1 tcp://127.0.0.1:2",
        client_urls: b"127.0.0.1:4222",
    };
    vec![
        Control::Hello(hello),
        Control::Hello(Hello {
            role: Role::Leaf,
            account: b"A",
            ..hello
        }),
        Control::Hello(Hello {
            role: Role::Hub,
            ..hello
        }),
        Control::SnapshotStart { epoch: 7, seq: 41 },
        Control::Entry(i),
        Control::Entry(Interest {
            queue: None,
            weight: 1,
            ..i
        }),
        Control::Entry(Interest {
            origin: Some(b"spokes"),
            ..i
        }),
        Control::Entry(Interest {
            queue: None,
            origin: Some(b""),
            ..i
        }),
        Control::SnapshotEnd { epoch: 7 },
        Control::Delta {
            epoch: 7,
            seq: 42,
            interest: Interest { weight: 0, ..i },
        },
        Control::Beat { epoch: 7, seq: 42 },
        Control::Resync,
    ]
}

#[test]
fn control_messages_decode_to_what_was_encoded() {
    for c in controls() {
        let mut out = Vec::new();
        c.encode(&mut out);
        assert_eq!(peer::decode(&out), Ok(c));
    }
}

#[test]
fn broken_control_messages_are_errors() {
    for c in controls() {
        let mut out = Vec::new();
        c.encode(&mut out);
        for cut in 0..out.len() {
            assert_eq!(
                peer::decode(&out[..cut]),
                Err(Error::Short),
                "{c:?} at {cut}"
            );
        }
        out.push(0);
        assert_eq!(peer::decode(&out), Err(Error::Long), "{c:?}");
    }
    assert_eq!(peer::decode(&[99]), Err(Error::Kind(99)));
    let mut tag = Vec::new();
    Control::Entry(Interest {
        account: b"a",
        subject: b"s",
        queue: None,
        weight: 1,
        origin: None,
    })
    .encode(&mut tag);
    *tag.last_mut().unwrap() = 4;
    assert_eq!(peer::decode(&tag), Err(Error::Flags(4)));
    assert_eq!(peer::decode(&[1, 2]), Err(Error::Version(2)));
    assert_eq!(peer::decode(&[1, 1, 3]), Err(Error::Flags(3)));
}

#[test]
fn the_words_of_a_hello_list_split_at_blanks() {
    let got: Vec<&[u8]> = peer::words(b" a  b ").collect();
    assert_eq!(got, [&b"a"[..], b"b"]);
    assert_eq!(peer::words(b"").count(), 0);
}

const fn records() -> [Record<'static>; 3] {
    [
        Record {
            subject: b"a",
            reply: None,
            headers: None,
            payload: b"",
            queue: None,
        },
        Record {
            subject: b"b.c",
            reply: Some(b"_INBOX.1"),
            headers: Some(b"NATS/1.0\r\nA: b\r\n\r\n"),
            payload: b"hello",
            queue: Some(b"q"),
        },
        Record {
            subject: b"d",
            reply: None,
            headers: None,
            payload: &[0; 300],
            queue: None,
        },
    ]
}

#[test]
fn a_batch_gives_its_publishes_back_in_order() {
    for origin in [None, Some(&b"spokes"[..]), Some(b"")] {
        let mut out = Vec::new();
        peer::batch(&mut out, origin, b"acct");
        for r in records() {
            r.encode(&mut out);
        }
        let b = Batch::parse(&out).unwrap();
        assert_eq!((b.origin, b.account), (origin, &b"acct"[..]));
        let got: Vec<_> = b.records().map(Result::unwrap).collect();
        assert_eq!(got, records());
    }
    let mut empty = Vec::new();
    peer::batch(&mut empty, None, b"");
    assert_eq!(Batch::parse(&empty).unwrap().records().count(), 0);
}

#[test]
fn a_broken_batch_ends_in_an_error() {
    let mut out = Vec::new();
    peer::batch(&mut out, Some(b"o"), b"acct");
    let head = out.len();
    for r in records() {
        r.encode(&mut out);
    }
    for cut in head + 1..out.len() {
        let b = Batch::parse(&out[..cut]).unwrap();
        let last = b.records().last().unwrap();
        // Cut at a record's end, it is whole; else the cut one is an error.
        assert!(last.is_ok() || last == Err(Error::Short), "{cut}");
    }
    for cut in 0..head {
        assert_eq!(Batch::parse(&out[..cut]), Err(Error::Short), "{cut}");
    }
    assert_eq!(Batch::parse(&[1]), Err(Error::Kind(1)));
    assert_eq!(Batch::parse(&[16, 1]), Err(Error::Flags(1)));
    let mut broken = out[..head].to_vec();
    broken.extend_from_slice(&[0, 9, 0]);
    let all: Vec<_> = Batch::parse(&broken).unwrap().records().collect();
    assert_eq!(all, [Err(Error::Short)], "nothing after a broken record");
    let mut flags = out[..head].to_vec();
    flags.push(8);
    let all: Vec<_> = Batch::parse(&flags).unwrap().records().collect();
    assert_eq!(all, [Err(Error::Flags(8))]);
}
