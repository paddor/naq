//! What a NATS server sends to a client.
//!
//! Encoders append to any [`BufMut`]. [`Msg::encoded_len`] gives the exact
//! length first, for buffers that must not grow.

use bytes::BufMut;

use crate::num::{Digits, decimal, decimal_len};

/// `PING`.
pub const PING: &[u8] = b"PING\r\n";
/// `PONG`.
pub const PONG: &[u8] = b"PONG\r\n";
/// `+OK`, the reply to every operation in verbose mode.
pub const OK: &[u8] = b"+OK\r\n";

/// Appends `INFO {json}`.
pub fn info(out: &mut impl BufMut, json: &[u8]) {
    out.put_slice(b"INFO ");
    out.put_slice(json);
    out.put_slice(b"\r\n");
}

/// Appends `-ERR 'text'`.
pub fn err(out: &mut impl BufMut, text: &str) {
    out.put_slice(b"-ERR '");
    out.put_slice(text.as_bytes());
    out.put_slice(b"'\r\n");
}

/// A message for one subscription: `MSG`, or `HMSG` with headers.
///
/// # Examples
///
/// ```
/// use naq_proto::encode::Msg;
///
/// let m = Msg {
///     subject: b"greet",
///     sid: b"7",
///     reply: Some(b"_INBOX.1"),
///     headers: None,
///     payload: b"hi",
/// };
/// let mut out = Vec::new();
/// m.encode(&mut out);
/// assert_eq!(out, b"MSG greet 7 _INBOX.1 2\r\nhi\r\n");
/// assert_eq!(out.len(), m.encoded_len());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msg<'a> {
    /// Subject the message was published to.
    pub subject: &'a [u8],
    /// Subscription ID the client chose.
    pub sid: &'a [u8],
    /// Reply subject.
    pub reply: Option<&'a [u8]>,
    /// Header block; makes it an `HMSG`.
    pub headers: Option<&'a [u8]>,
    /// Payload, without CRLF.
    pub payload: &'a [u8],
}

impl Msg<'_> {
    /// Encoded length in bytes.
    pub const fn encoded_len(&self) -> usize {
        // "MSG " or "HMSG ", the blanks after subject and sid, the two CRLFs.
        let mut len = 4 + self.subject.len() + 1 + self.sid.len() + 1 + 2 + 2;
        if let Some(r) = self.reply {
            len += r.len() + 1;
        }
        let total = match self.headers {
            Some(h) => {
                len += 1 + decimal_len(h.len()) + 1 + h.len();
                h.len() + self.payload.len()
            }
            None => self.payload.len(),
        };
        len + decimal_len(total) + self.payload.len()
    }

    /// Appends the encoded message.
    #[inline]
    pub fn encode(&self, out: &mut impl BufMut) {
        let mut digits = Digits::default();
        out.put_slice(if self.headers.is_some() {
            b"HMSG "
        } else {
            b"MSG "
        });
        out.put_slice(self.subject);
        out.put_u8(b' ');
        out.put_slice(self.sid);
        out.put_u8(b' ');
        if let Some(r) = self.reply {
            out.put_slice(r);
            out.put_u8(b' ');
        }
        if let Some(h) = self.headers {
            out.put_slice(decimal(h.len(), &mut digits));
            out.put_u8(b' ');
            out.put_slice(decimal(h.len() + self.payload.len(), &mut digits));
            out.put_slice(b"\r\n");
            out.put_slice(h);
        } else {
            out.put_slice(decimal(self.payload.len(), &mut digits));
            out.put_slice(b"\r\n");
        }
        out.put_slice(self.payload);
        out.put_slice(b"\r\n");
    }
}
