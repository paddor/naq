//! Protocol traces of a client, as `nats-server` writes them with `trace`:
//! `<<- [PUB foo 5]` for what it sent, `->> [MSG foo 1 5]` for what it got.

use naq_proto::client::{ClientOp, Pub};

use super::{Client, Conn};
use crate::log::{Log, quote};
use crate::server::Shared;

impl Conn {
    /// Traces `op`, which the client sent.
    #[cold]
    #[inline(never)]
    pub(super) fn trace_in(&self, op: &ClientOp<'_>) {
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let line = match op {
            // Its payload is traced once it is checked.
            ClientOp::Pub(p) => format!("<<- [{}]", pub_args(p)),
            ClientOp::Sub(s) => {
                let queue = s.queue.map(|q| format!("{} ", text(q))).unwrap_or_default();
                format!("<<- [SUB {} {queue}{}]", text(s.subject), text(s.sid))
            }
            ClientOp::Unsub(u) => match u.max {
                Some(max) => format!("<<- [UNSUB {} {max}]", text(u.sid)),
                None => format!("<<- [UNSUB {}]", text(u.sid)),
            },
            ClientOp::Ping => "<<- [PING]".into(),
            ClientOp::Pong => "<<- [PONG]".into(),
            ClientOp::Connect(json) => format!("<<- [CONNECT {}]", text(&redact(json))),
            _ => return,
        };
        self.trace(&line);
    }

    /// Traces the payload of `p`, which the client sent.
    #[cold]
    #[inline(never)]
    pub(super) fn trace_payload_in(&self, p: &Pub<'_>) {
        trace_payload(&self.lane.shared.log, &self.label(), "<<-", p);
    }

    /// Traces `op`, which the server sends the client, with `arg`.
    #[cold]
    pub(super) fn trace_out(&self, op: &str, arg: Option<&str>) {
        match arg {
            Some(a) => self.trace(&format!("->> [{op} {a}]")),
            None => self.trace(&format!("->> [{op}]")),
        }
    }

    fn trace(&self, line: &str) {
        self.lane
            .shared
            .log
            .trace(format_args!("{} - {line}", self.label()));
    }
}

impl Client {
    /// Traces the delivery of `m` to it, on `sid`.
    #[cold]
    #[inline(never)]
    pub(crate) fn trace_delivery(&self, shared: &Shared, m: &Pub<'_>, sid: &[u8]) {
        let headers = m.headers.filter(|_| self.headers.get());
        let m = Pub { headers, ..*m };
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let (subject, sid) = (text(m.subject), text(sid));
        let reply = m.reply.map(|r| format!(" {}", text(r))).unwrap_or_default();
        let args = match headers {
            Some(h) => format!(
                "HMSG {subject} {sid}{reply} {} {}",
                h.len(),
                h.len() + m.payload.len()
            ),
            None => format!("MSG {subject} {sid}{reply} {}", m.payload.len()),
        };
        let prefix = self.label(shared, true);
        shared.log.trace(format_args!("{prefix} - ->> [{args}]"));
        trace_payload(&shared.log, &prefix, "->>", &m);
    }

    /// Traces the end of subscription `sid`.
    #[cold]
    pub(crate) fn trace_delsub(&self, shared: &Shared, sid: &[u8]) {
        let prefix = self.label(shared, true);
        shared.log.trace(format_args!(
            "{prefix} - <-> [DELSUB {}]",
            String::from_utf8_lossy(sid)
        ));
    }
}

/// The arguments of `PUB` or `HPUB` `p`, with its verb.
fn pub_args(p: &Pub<'_>) -> String {
    let subject = String::from_utf8_lossy(p.subject);
    let reply = p
        .reply
        .map(|r| format!(" {}", String::from_utf8_lossy(r)))
        .unwrap_or_default();
    match p.headers {
        Some(h) => format!(
            "HPUB {subject}{reply} {} {}",
            h.len(),
            h.len() + p.payload.len()
        ),
        None => format!("PUB {subject}{reply} {}", p.payload.len()),
    }
}

/// Traces the payload of `p`, as `nats-server` does: its headers and
/// payload, or with `trace_headers` its headers alone; cut at
/// `max_traced`; nothing if empty.
fn trace_payload(log: &Log, prefix: &str, dir: &str, p: &Pub<'_>) {
    let mut msg = Vec::new();
    if log.trace_headers {
        // As `nats-server` cuts them: without the line ends that end them.
        let Some(h) = p.headers else {
            return;
        };
        msg.extend_from_slice(&h[..h.len().saturating_sub(4)]);
    } else {
        msg.extend_from_slice(p.headers.unwrap_or_default());
        msg.extend_from_slice(p.payload);
    }
    if msg.is_empty() {
        return;
    }
    let max = log.max_traced;
    if max > 0 && msg.len() > max {
        let q = quote(&msg[..max]);
        log.trace(format_args!(
            "{prefix} - {dir} MSG_PAYLOAD: [\"{}...\"]",
            &q[1..q.len() - 1]
        ));
    } else {
        log.trace(format_args!(
            "{prefix} - {dir} MSG_PAYLOAD: [{}]",
            quote(&msg)
        ));
    }
}

/// `json` with the values of secrets replaced, as `nats-server` traces a
/// `CONNECT`: of keys that start with `auth_token` or `pass`, and of
/// `sig`, `proxy_sig` and `nkey`.
fn redact(json: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(json.len());
    let mut i = 0;
    while i < json.len() {
        if json[i] != b'"' {
            out.push(json[i]);
            i += 1;
            continue;
        }
        let end = string_end(json, i);
        out.extend_from_slice(&json[i..end]);
        let key = &json[i + 1..end.saturating_sub(1).max(i + 1)];
        i = end;
        let secret = key.starts_with(b"auth_token")
            || key.starts_with(b"pass")
            || [&b"sig"[..], b"proxy_sig", b"nkey"].contains(&key);
        let mut j = i;
        while j < json.len() && json[j].is_ascii_whitespace() {
            j += 1;
        }
        if !secret || json.get(j) != Some(&b':') {
            continue;
        }
        j += 1;
        while j < json.len() && json[j].is_ascii_whitespace() {
            j += 1;
        }
        if json.get(j) == Some(&b'"') {
            out.extend_from_slice(&json[i..=j]);
            out.extend_from_slice(b"[REDACTED]\"");
            i = string_end(json, j);
        }
    }
    out
}

/// Where the JSON string that starts at `at` ends, past its quote.
const fn string_end(json: &[u8], at: usize) -> usize {
    let mut i = at + 1;
    while i < json.len() {
        match json[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    json.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connects_are_traced_without_their_secrets() {
        let json =
            br#"{"user":"a","pass":"s3\"x","auth_token":"t","sig":"g","nkey":"U1","name":"n"}"#;
        assert_eq!(
            String::from_utf8(redact(json)).unwrap(),
            r#"{"user":"a","pass":"[REDACTED]","auth_token":"[REDACTED]","sig":"[REDACTED]","nkey":"[REDACTED]","name":"n"}"#
        );
        assert_eq!(redact(br#"{"pass": "x"}"#), br#"{"pass": "[REDACTED]"}"#);
        assert_eq!(
            redact(br#"{"pass":1,"name":"pass"}"#),
            br#"{"pass":1,"name":"pass"}"#
        );
        for bad in [&b"\"pass\":\"open"[..], b"\"", b"\"\\", b"{\"sig\":"] {
            redact(bad);
        }
    }

    #[test]
    fn publishes_are_traced_with_their_sizes() {
        let p = Pub {
            subject: b"foo",
            reply: Some(b"r"),
            headers: None,
            payload: b"hello",
        };
        assert_eq!(pub_args(&p), "PUB foo r 5");
        let p = Pub {
            headers: Some(b"NATS/1.0\r\n\r\n"),
            reply: None,
            ..p
        };
        assert_eq!(pub_args(&p), "HPUB foo 12 17");
    }
}
