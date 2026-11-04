//! The leaf node wire: what a leaf and its hub send each other on a link.
//!
//! [`parse`] takes a link's unread bytes and returns the first operation,
//! as slices of the input, as [`client::parse`](crate::client::parse) does
//! for clients. The encoders write what a leaf sends. Leaf operations carry
//! no account: a link binds one.
//!
//! Verbs are case-insensitive, arguments split at runs of blanks, and
//! lines end in `\n` with an optional `\r` before it, as in `nats-server`.

use core::fmt;

use bytes::BufMut;

use crate::client::{Limits, is_blank, line};
use crate::num::{Digits, decimal, parse_size};

/// An operation on a leaf node link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeafOp<'a> {
    /// `INFO {json}`, with the JSON not parsed yet.
    Info(&'a [u8]),
    /// `CONNECT {json}`, with the JSON not parsed yet.
    Connect(&'a [u8]),
    /// `LS+`: interest in a subject, or in a queue group on it.
    Sub(Interest<'a>),
    /// `LS-`: the end of that interest. Its weight is 0.
    Unsub(Interest<'a>),
    /// `LMSG`, or `HMSG` with headers.
    Msg(Msg<'a>),
    /// `PING`.
    Ping,
    /// `PONG`.
    Pong,
    /// `+OK`.
    Ok,
    /// `-ERR 'text'`: the text, without its quotes.
    Err(&'a [u8]),
}

/// Interest in `subject` across a link (`LS+`, `LS-`): of plain
/// subscriptions, or of queue group `queue` with `weight` members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interest<'a> {
    /// Subject filter, not checked.
    pub subject: &'a [u8],
    /// Queue group name.
    pub queue: Option<&'a [u8]>,
    /// Members of the queue group, at least 1; 1 for plain interest.
    pub weight: u32,
}

/// A message across a link: `LMSG`, or `HMSG` with headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msg<'a> {
    /// Subject, not checked.
    pub subject: &'a [u8],
    /// Reply subject.
    pub reply: Option<&'a [u8]>,
    /// Names of the queue groups one member each of gets it, separated by
    /// blanks; empty for none. Without them, only plain subscriptions do.
    pub queues: &'a [u8],
    /// The header block, from `NATS/1.0` to its empty line, not checked.
    pub headers: Option<&'a [u8]>,
    /// The payload, without its CRLF.
    pub payload: &'a [u8],
}

impl<'a> Msg<'a> {
    /// The queue group names in [`Msg::queues`].
    pub fn queue_names(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        let queues = self.queues;
        tokens(queues).map(move |(s, e)| &queues[s..e])
    }

    /// Appends the encoded message.
    ///
    /// # Examples
    ///
    /// ```
    /// use naq_proto::leaf::Msg;
    ///
    /// let m = Msg {
    ///     subject: b"orders",
    ///     reply: Some(b"_INBOX.1"),
    ///     queues: b"workers",
    ///     headers: None,
    ///     payload: b"hi",
    /// };
    /// let mut out = Vec::new();
    /// m.encode(&mut out);
    /// assert_eq!(out, b"LMSG orders + _INBOX.1 workers 2\r\nhi\r\n");
    /// ```
    pub fn encode(&self, out: &mut impl BufMut) {
        let mut digits = Digits::default();
        out.put_slice(if self.headers.is_some() {
            b"HMSG "
        } else {
            b"LMSG "
        });
        out.put_slice(self.subject);
        out.put_u8(b' ');
        match (self.reply, self.queues.is_empty()) {
            (Some(r), true) => {
                out.put_slice(r);
                out.put_u8(b' ');
            }
            (Some(r), false) => {
                out.put_slice(b"+ ");
                out.put_slice(r);
                out.put_u8(b' ');
            }
            (None, false) => out.put_slice(b"| "),
            (None, true) => {}
        }
        if !self.queues.is_empty() {
            out.put_slice(self.queues);
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

/// Appends `LS+` for `subject`, or for queue group `queue` on it with its
/// member count. A weight of 0 goes out as 1.
pub fn sub(out: &mut impl BufMut, subject: &[u8], queue: Option<(&[u8], u32)>) {
    out.put_slice(b"LS+ ");
    out.put_slice(subject);
    if let Some((q, weight)) = queue {
        let mut digits = Digits::default();
        out.put_u8(b' ');
        out.put_slice(q);
        out.put_u8(b' ');
        out.put_slice(decimal(weight.max(1) as usize, &mut digits));
    }
    out.put_slice(b"\r\n");
}

/// Appends `LS-` for `subject`, or for queue group `queue` on it.
pub fn unsub(out: &mut impl BufMut, subject: &[u8], queue: Option<&[u8]>) {
    out.put_slice(b"LS- ");
    out.put_slice(subject);
    if let Some(q) = queue {
        out.put_u8(b' ');
        out.put_slice(q);
    }
    out.put_slice(b"\r\n");
}

/// Appends `CONNECT {json}`.
pub fn connect(out: &mut impl BufMut, json: &[u8]) {
    out.put_slice(b"CONNECT ");
    out.put_slice(json);
    out.put_slice(b"\r\n");
}

/// Verb of a leaf link operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verb {
    /// `INFO`.
    Info,
    /// `CONNECT`.
    Connect,
    /// `LS+`.
    Sub,
    /// `LS-`.
    Unsub,
    /// `LMSG`.
    Lmsg,
    /// `HMSG`.
    Hmsg,
    /// `PING`.
    Ping,
    /// `PONG`.
    Pong,
    /// `+OK`.
    Ok,
    /// `-ERR`.
    Err,
}

/// The verbs in lower case, as they start a line.
const VERBS: [(&[u8], Verb); 10] = [
    (b"info", Verb::Info),
    (b"connect", Verb::Connect),
    (b"ls+", Verb::Sub),
    (b"ls-", Verb::Unsub),
    (b"lmsg", Verb::Lmsg),
    (b"hmsg", Verb::Hmsg),
    (b"ping", Verb::Ping),
    (b"pong", Verb::Pong),
    (b"+ok", Verb::Ok),
    (b"-err", Verb::Err),
];

impl Verb {
    /// Name on the wire, in lower case.
    fn name(self) -> &'static [u8] {
        VERBS
            .iter()
            .find(|(_, v)| *v == self)
            .map_or(b"", |(n, _)| n)
    }

    /// Arguments follow the name after a blank. `PING`, `PONG` and `+OK`
    /// ignore the rest of their line.
    const fn has_args(self) -> bool {
        !matches!(self, Verb::Ping | Verb::Pong | Verb::Ok)
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.name() {
            fmt::Write::write_char(f, char::from(b.to_ascii_uppercase()))?;
        }
        Ok(())
    }
}

/// Result of a [`parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed<'a> {
    /// An operation and the number of bytes it took.
    Op(LeafOp<'a>, usize),
    /// More bytes are needed. Once the control line of a message is in,
    /// this holds the length of the whole operation.
    Partial(Option<usize>),
}

/// A peer sent something the leaf protocol does not allow. The link
/// cannot continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Not a leaf link operation.
    #[error("unknown protocol operation")]
    UnknownOp,
    /// No line end within the control line limit, or arguments over it.
    #[error("maximum control line exceeded")]
    ControlLine,
    /// Too few or too many arguments, or a queue list without its marker.
    #[error("{0}: wrong number of arguments")]
    Args(Verb),
    /// A size is missing or not 1 to 9 digits.
    #[error("{0}: bad or missing size")]
    Size(Verb),
    /// The header size of an `HMSG` is larger than its total size.
    #[error("HMSG: bad header size")]
    HeaderSize,
    /// The message is larger than [`Limits::max_payload`].
    #[error("maximum payload exceeded: {0} bytes")]
    MaxPayload(usize),
    /// The message is not followed by CRLF.
    #[error("message not followed by CRLF")]
    MissingCrlf,
}

/// Parses the first operation in `buf`, from either side of a link.
/// `nats-server` allows leaf links 16 times its `max_control_line`; the
/// caller sets `limits` so.
///
/// # Errors
///
/// A [`ParseError`] for input the leaf protocol does not allow.
///
/// # Examples
///
/// ```
/// use naq_proto::client::Limits;
/// use naq_proto::leaf::{self, LeafOp, Parsed};
///
/// let buf = b"LMSG orders | workers 2\r\nhi\r\n";
/// let Parsed::Op(LeafOp::Msg(m), used) = leaf::parse(buf, &Limits::default())? else {
///     unreachable!()
/// };
/// assert_eq!((m.subject, m.payload, used), (&b"orders"[..], &b"hi"[..], buf.len()));
/// assert_eq!(m.queue_names().collect::<Vec<_>>(), [&b"workers"[..]]);
/// # Ok::<(), leaf::ParseError>(())
/// ```
pub fn parse<'a>(buf: &'a [u8], limits: &Limits) -> Result<Parsed<'a>, ParseError> {
    let Some(verb) = verb(buf)? else {
        return Ok(Parsed::Partial(None));
    };
    let name = verb.name().len();
    if verb.has_args() {
        match buf.get(name) {
            None => return Ok(Parsed::Partial(None)),
            Some(&b) if is_blank(b) => {}
            Some(_) => return Err(ParseError::UnknownOp),
        }
    }
    let Some((arg, next)) = line(buf, name, limits).map_err(|_| ParseError::ControlLine)? else {
        return Ok(Parsed::Partial(None));
    };
    let op = match verb {
        Verb::Lmsg | Verb::Hmsg => return message(buf, arg, next, verb, limits),
        Verb::Info => LeafOp::Info(trim_end(arg)),
        Verb::Connect => LeafOp::Connect(trim_end(arg)),
        Verb::Sub => LeafOp::Sub(sub_args(arg)?),
        Verb::Unsub => LeafOp::Unsub(unsub_args(arg)?),
        Verb::Ping => LeafOp::Ping,
        Verb::Pong => LeafOp::Pong,
        Verb::Ok => LeafOp::Ok,
        Verb::Err => LeafOp::Err(unquoted(trim_end(arg))),
    };
    Ok(Parsed::Op(op, next))
}

/// The verb `buf` starts with. `None` while the bytes so far could still
/// become one.
fn verb(buf: &[u8]) -> Result<Option<Verb>, ParseError> {
    if buf.is_empty() {
        return Ok(None);
    }
    let mut could = false;
    for (name, verb) in VERBS {
        let have = buf.len().min(name.len());
        // Lower case for letters; `+` and `-` stay as they are.
        if buf[..have].iter().zip(name).all(|(b, n)| b | 0x20 == *n) {
            if have == name.len() {
                return Ok(Some(verb));
            }
            could = true;
        }
    }
    if could {
        Ok(None)
    } else {
        Err(ParseError::UnknownOp)
    }
}

/// `LS+ subject [queue weight]`. A weight that is not a size, or 0,
/// counts as 1, as in `nats-server`.
fn sub_args(arg: &[u8]) -> Result<Interest<'_>, ParseError> {
    let mut t = tokens(arg).map(|(s, e)| &arg[s..e]);
    let (subject, queue, weight) = match (t.next(), t.next(), t.next(), t.next()) {
        (Some(subject), None, None, None) => (subject, None, 1),
        (Some(subject), Some(queue), Some(w), None) => {
            let w = parse_size(w).filter(|&w| w > 0).unwrap_or(1);
            (subject, Some(queue), w as u32)
        }
        _ => return Err(ParseError::Args(Verb::Sub)),
    };
    Ok(Interest {
        subject,
        queue,
        weight,
    })
}

/// `LS- subject [queue]`.
fn unsub_args(arg: &[u8]) -> Result<Interest<'_>, ParseError> {
    let mut t = tokens(arg).map(|(s, e)| &arg[s..e]);
    let (Some(subject), queue, None) = (t.next(), t.next(), t.next()) else {
        return Err(ParseError::Args(Verb::Unsub));
    };
    Ok(Interest {
        subject,
        queue,
        weight: 0,
    })
}

/// An `LMSG` or `HMSG` whose control line ends at `next`:
/// `subject [reply | + reply queues.. | | queues..] [hsize] size`.
fn message<'a>(
    buf: &'a [u8],
    arg: &'a [u8],
    next: usize,
    verb: Verb,
    limits: &Limits,
) -> Result<Parsed<'a>, ParseError> {
    let sizes = if verb == Verb::Hmsg { 2 } else { 1 };
    let n = tokens(arg).count();
    let at = |i: usize| tokens(arg).nth(i).unwrap_or_default();
    let part = |i: usize| {
        let (s, e) = at(i);
        &arg[s..e]
    };
    if n < 1 + sizes {
        return Err(ParseError::Args(verb));
    }
    // Between the subject and the sizes: nothing, a reply, or a marker
    // and what it introduces.
    let middle = n - 1 - sizes;
    let (reply, queues) = match middle {
        0 => (None, &arg[..0]),
        1 => (Some(part(1)), &arg[..0]),
        _ => {
            let first = if part(1) == b"+" { 3 } else { 2 };
            if part(1) != b"+" && part(1) != b"|" {
                return Err(ParseError::Args(verb));
            }
            let reply = (first == 3).then(|| part(2));
            let last = n - sizes - 1;
            let queues = if first <= last {
                &arg[at(first).0..at(last).1]
            } else {
                &arg[..0]
            };
            (reply, queues)
        }
    };
    let size = parse_size(part(n - 1)).ok_or(ParseError::Size(verb))?;
    let hsize = match sizes {
        2 => Some(parse_size(part(n - 2)).ok_or(ParseError::HeaderSize)?),
        _ => None,
    };
    if hsize.is_some_and(|h| h > size) {
        return Err(ParseError::HeaderSize);
    }
    if size > limits.max_payload {
        return Err(ParseError::MaxPayload(size));
    }
    // No overflow: `size` has at most 9 digits, `next` is a short line.
    let end = next + size + 2;
    let Some(frame) = buf.get(..end) else {
        return Ok(Parsed::Partial(Some(end)));
    };
    if !frame.ends_with(b"\r\n") {
        return Err(ParseError::MissingCrlf);
    }
    let body = &frame[next..end - 2];
    let (headers, payload) = match hsize {
        Some(h) => (Some(&body[..h]), &body[h..]),
        None => (None, body),
    };
    let m = Msg {
        subject: part(0),
        reply,
        queues,
        headers,
        payload,
    };
    Ok(Parsed::Op(LeafOp::Msg(m), end))
}

/// Start and end of each run of non-blank bytes in `s`.
fn tokens(s: &[u8]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut at = 0;
    core::iter::from_fn(move || {
        let start = at + s.get(at..)?.iter().position(|&b| !is_blank(b))?;
        let end = start
            + s[start..]
                .iter()
                .position(|&b| is_blank(b))
                .unwrap_or(s.len() - start);
        at = end;
        Some((start, end))
    })
}

/// `s` without the blanks it ends in.
fn trim_end(s: &[u8]) -> &[u8] {
    let end = s.iter().rposition(|&b| !is_blank(b)).map_or(0, |i| i + 1);
    &s[..end]
}

/// `s` without the single quotes around it, if it has both.
const fn unquoted(s: &[u8]) -> &[u8] {
    match s {
        [b'\'', inner @ .., b'\''] => inner,
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_the_runs_between_blanks() {
        let t: [(usize, usize); 3] = [(1, 2), (4, 6), (7, 8)];
        assert!(tokens(b" a \tbb c").eq(t));
        assert_eq!(tokens(b"").count(), 0);
        assert_eq!(tokens(b"  \t").count(), 0);
    }

    #[test]
    fn verbs_are_known_from_their_first_bytes() {
        assert_eq!(verb(b""), Ok(None));
        assert_eq!(verb(b"L"), Ok(None));
        assert_eq!(verb(b"lS"), Ok(None));
        assert_eq!(verb(b"Ls+"), Ok(Some(Verb::Sub)));
        assert_eq!(verb(b"LMSG"), Ok(Some(Verb::Lmsg)));
        assert_eq!(verb(b"-er"), Ok(None));
        assert_eq!(verb(b"+OK"), Ok(Some(Verb::Ok)));
        assert_eq!(verb(b"MSG"), Err(ParseError::UnknownOp));
        assert_eq!(verb(b"LX"), Err(ParseError::UnknownOp));
    }

    #[test]
    fn quotes_and_trailing_blanks_go() {
        assert_eq!(unquoted(b"'x y'"), b"x y");
        assert_eq!(unquoted(b"'"), b"'");
        assert_eq!(trim_end(b"{} \t"), b"{}");
        assert_eq!(trim_end(b"  "), b"");
    }

    #[test]
    fn verbs_display_in_upper_case() {
        let mut s = [0u8; 8];
        let mut w = Buf(&mut s, 0);
        fmt::write(&mut w, format_args!("{}", Verb::Sub)).unwrap();
        let n = w.1;
        assert_eq!(&s[..n], b"LS+");
    }

    /// A `fmt::Write` into a fixed buffer, as tests here have no `alloc`.
    struct Buf<'a>(&'a mut [u8], usize);

    impl fmt::Write for Buf<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.1 + s.len();
            self.0
                .get_mut(self.1..end)
                .ok_or(fmt::Error)?
                .copy_from_slice(s.as_bytes());
            self.1 = end;
            Ok(())
        }
    }
}
