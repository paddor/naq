//! Fuzz target bodies and their seeds. The bodies have no AFL dependency,
//! so `tests/targets.rs` replays the seeds through them.

pub mod seeds;

use naq_proto::client::{self, ClientOp, Limits, Parsed};
use naq_proto::encode::Msg;

/// A fuzz target body.
pub type Target = fn(&[u8]);

/// Every target, by name.
pub const TARGETS: [(&str, Target); 3] = [
    ("client_wire", client_wire),
    ("config", config),
    ("subjects", subjects),
];

/// Parses client operations until the input ends or breaks. An operation
/// takes at least one byte and no more than there are; a publish encodes
/// as a message of the length `encoded_len` gives.
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
        match client::parse(&data[at..], &limits) {
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

/// A subject and filters, one per line: the index finds what matching by
/// hand finds.
///
/// # Panics
///
/// When they disagree.
pub fn subjects(data: &[u8]) {
    naq::fuzzing::index(data);
}
