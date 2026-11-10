//! Fuzz target bodies and their seeds. The bodies have no AFL dependency,
//! so `tests/targets.rs` replays the seeds through them.

pub mod seeds;

use naq_proto::client::{self, ClientOp, Limits, Parsed};
use naq_proto::encode::Msg;
use naq_proto::leaf::{self, LeafOp};
use naq_proto::peer;

/// A fuzz target body.
pub type Target = fn(&[u8]);

/// Every target, by name.
pub const TARGETS: [(&str, Target); 10] = [
    ("certs", certs),
    ("client_wire", client_wire),
    ("config", config),
    ("jwts", jwts),
    ("leaf_wire", leaf_wire),
    ("monitor_http", monitor_http),
    ("peer_frames", peer_frames),
    ("subjects", subjects),
    ("sys_body", sys_body),
    ("websocket", websocket),
];

/// Parses client operations until the input ends or breaks. An operation
/// takes at least one byte and no more than there are; a publish encodes
/// as a message of the length `encoded_len` gives. Each parses as it does
/// with a tab after its verb, which the parser reads the general way where
/// a space may take a faster one.
///
/// # Panics
///
/// When the parser breaks those rules.
pub fn client_wire(data: &[u8]) {
    let limits = Limits {
        max_control_line: 256,
        max_payload: 4096,
    };
    let mut at = 0;
    while at < data.len() {
        let rest = &data[at..];
        let parsed = client::parse(rest, &limits);
        if rest.get(3) == Some(&b' ') {
            let mut tabbed = rest.to_vec();
            tabbed[3] = b'\t';
            assert_eq!(
                parsed,
                client::parse(&tabbed, &limits),
                "a tab parses otherwise"
            );
        }
        match parsed {
            Ok(Parsed::Op(op, used)) => {
                assert!(used > 0 && used <= data.len() - at, "took {used}");
                if let ClientOp::Pub(p) = op {
                    assert!(p.payload.len() <= limits.max_payload);
                    let m = Msg {
                        subject: p.subject,
                        sid: b"1",
                        reply: p.reply,
                        headers: p.headers,
                        payload: p.payload,
                    };
                    let mut out = Vec::new();
                    m.encode(&mut out);
                    assert_eq!(out.len(), m.encoded_len());
                }
                at += used;
            }
            Ok(Parsed::Partial(need)) => {
                if let Some(n) = need {
                    assert!(n > data.len() - at, "needs {n}, has {}", data.len() - at);
                }
                return;
            }
            Err(_) => return,
        }
    }
}

/// Parses leaf link operations until the input ends or breaks. An
/// operation takes at least one byte and no more than there are; a message
/// and an interest encode back to what parses as the same.
///
/// # Panics
///
/// When the parser or the encoders break those rules.
pub fn leaf_wire(data: &[u8]) {
    let limits = Limits {
        max_control_line: 256,
        max_payload: 4096,
    };
    let mut at = 0;
    while at < data.len() {
        match leaf::parse(&data[at..], &limits) {
            Ok(leaf::Parsed::Op(op, used)) => {
                assert!(used > 0 && used <= data.len() - at, "took {used}");
                let mut out = Vec::new();
                match op {
                    LeafOp::Msg(m) => {
                        assert!(m.payload.len() <= limits.max_payload);
                        m.encode(&mut out);
                    }
                    LeafOp::Sub(i) => {
                        leaf::sub(&mut out, i.subject, i.queue.map(|q| (q, i.weight)));
                    }
                    _ => {}
                }
                if !out.is_empty() {
                    let again = leaf::parse(&out, &limits);
                    assert_eq!(again, Ok(leaf::Parsed::Op(op, out.len())), "re-encoded");
                }
                at += used;
            }
            Ok(leaf::Parsed::Partial(need)) => {
                if let Some(n) = need {
                    assert!(n > data.len() - at, "needs {n}, has {}", data.len() - at);
                }
                return;
            }
            Err(_) => return,
        }
    }
}

/// Reads a configuration. Includes are left out: they would read files.
pub fn config(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if text.contains("include") {
        return;
    }
    let _ = text.parse::<naq::Options>();
}

/// Decodes a JWT as operator, account, user and activation claims.
pub fn jwts(data: &[u8]) {
    naq::fuzzing::jwt(data);
}

/// A client certificate, read for the user it names, and the input as a
/// DN user name.
pub fn certs(data: &[u8]) {
    naq::fuzzing::cert(data);
}

/// A subject and filters, one per line: the index finds what matching by
/// hand finds.
///
/// # Panics
///
/// When they disagree.
pub fn subjects(data: &[u8]) {
    naq::fuzzing::index(data);
}

/// A WebSocket upgrade request and the frames after it, read as a lane
/// reads them.
///
/// # Panics
///
/// When the reader keeps more than it read, or compression does not round
/// trip.
pub fn websocket(data: &[u8]) {
    naq::fuzzing::websocket(data);
}

/// Reads a request to the monitoring port: its head, path and query, as
/// the server reads them. A path cleaned for a redirect is clean.
///
/// # Panics
///
/// When it is not.
pub fn monitor_http(data: &[u8]) {
    naq::fuzzing::monitor(data);
}

/// Reads the input as the body of each request on `$SYS`. Go's check of
/// JSON agrees with `serde_json`.
///
/// # Panics
///
/// When they disagree.
pub fn sys_body(data: &[u8]) {
    naq::fuzzing::sys_body(data);
}

/// Decodes the input as a peer control message and as a batch. What
/// decodes encodes back to the same bytes.
///
/// # Panics
///
/// When the codec breaks that rule.
pub fn peer_frames(data: &[u8]) {
    if let Ok(c) = peer::decode(data) {
        let mut out = Vec::new();
        c.encode(&mut out);
        assert_eq!(out, data, "control re-encoded");
    }
    if let Ok(b) = peer::Batch::parse(data) {
        let mut out = Vec::new();
        peer::batch(&mut out, b.origin, b.account);
        peer::stamp(&mut out, b.epoch, b.seq);
        for r in b.records() {
            let Ok(r) = r else { return };
            r.encode(&mut out);
        }
        assert_eq!(out, data, "batch re-encoded");
    }
}
