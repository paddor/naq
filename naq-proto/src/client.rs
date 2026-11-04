//! What a NATS client sends: `CONNECT`, `PUB`, `HPUB`, `SUB`, `UNSUB`,
//! `PING` and `PONG`.
//!
//! [`parse`] takes a connection's unread bytes and returns the first
//! operation with the number of bytes it took, or that more bytes are
//! needed. Operations borrow from the input: subjects and payloads are
//! slices of it.
//!
//! Arguments are split as `nats-server` splits them: verbs in any case,
//! blanks (space, tab) between arguments, lines that end in `\n` with an
//! optional `\r` before it.

use core::fmt;

use crate::num::parse_size;

/// Control line bytes allowed beyond [`Limits::max_control_line`]: the verb,
/// the blanks after it and the line end.
pub(crate) const LINE_SLACK: usize = 64;

/// Limits a parse enforces. The defaults are those of `nats-server`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longest arguments of a control line, in bytes (`max_control_line`).
    pub max_control_line: usize,
    /// Largest message, headers included, in bytes (`max_payload`).
    pub max_payload: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_control_line: 4096,
            max_payload: 1 << 20,
        }
    }
}

/// An operation from a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientOp<'a> {
    /// `CONNECT {json}`, with the JSON not parsed yet.
    Connect(&'a [u8]),
    /// `PUB` or `HPUB`.
    Pub(Pub<'a>),
    /// `SUB`.
    Sub(Sub<'a>),
    /// `UNSUB`.
    Unsub(Unsub<'a>),
    /// `PING`.
    Ping,
    /// `PONG`.
    Pong,
}

/// `PUB subject [reply] size` or `HPUB subject [reply] hsize size`, and the
/// message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pub<'a> {
    /// Subject, not checked.
    pub subject: &'a [u8],
    /// Reply subject.
    pub reply: Option<&'a [u8]>,
    /// The header block of an `HPUB`, from `NATS/1.0` to its empty line,
    /// not checked.
    pub headers: Option<&'a [u8]>,
    /// The payload, without its CRLF.
    pub payload: &'a [u8],
}

/// `SUB subject [queue] sid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sub<'a> {
    /// Subject filter, not checked.
    pub subject: &'a [u8],
    /// Queue group name.
    pub queue: Option<&'a [u8]>,
    /// Subscription ID, any token the client chose.
    pub sid: &'a [u8],
}

/// `UNSUB sid [max]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsub<'a> {
    /// Subscription ID.
    pub sid: &'a [u8],
    /// Messages the subscription may get in total before it ends. `None`
    /// when absent or not a size; `nats-server` then ends it at once, as
    /// for `Some(0)`.
    pub max: Option<usize>,
}

/// Verb of a client operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verb {
    /// `CONNECT`.
    Connect,
    /// `PUB`.
    Pub,
    /// `HPUB`.
    Hpub,
    /// `SUB`.
    Sub,
    /// `UNSUB`.
    Unsub,
    /// `PING`.
    Ping,
    /// `PONG`.
    Pong,
}

impl Verb {
    /// Name on the wire, in lower case.
    const fn name(self) -> &'static [u8] {
        match self {
            Verb::Connect => b"connect",
            Verb::Pub => b"pub",
            Verb::Hpub => b"hpub",
            Verb::Sub => b"sub",
            Verb::Unsub => b"unsub",
            Verb::Ping => b"ping",
            Verb::Pong => b"pong",
        }
    }

    /// Arguments follow the name after a blank. `PING` and `PONG` ignore
    /// the rest of their line.
    const fn has_args(self) -> bool {
        !matches!(self, Verb::Ping | Verb::Pong)
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verb::Connect => "CONNECT",
            Verb::Pub => "PUB",
            Verb::Hpub => "HPUB",
            Verb::Sub => "SUB",
            Verb::Unsub => "UNSUB",
            Verb::Ping => "PING",
            Verb::Pong => "PONG",
        })
    }
}

/// Result of a [`parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed<'a> {
    /// An operation and the number of bytes it took.
    Op(ClientOp<'a>, usize),
    /// More bytes are needed. Once the control line of a message is in,
    /// this holds the length of the whole operation.
    Partial(Option<usize>),
}

/// A client sent something the protocol does not allow. The connection
/// cannot continue: the parser cannot tell where the next operation starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Not a client operation.
    #[error("unknown protocol operation")]
    UnknownOp,
    /// No line end within the control line limit, or arguments over it.
    #[error("maximum control line exceeded")]
    ControlLine,
    /// Too few or too many arguments.
    #[error("{0}: wrong number of arguments")]
    Args(Verb),
    /// The message size is missing or not 1 to 9 digits.
    #[error("{0}: bad or missing size")]
    Size(Verb),
    /// The header size of an `HPUB` is not 1 to 9 digits, or larger than
    /// its total size.
    #[error("HPUB: bad header size")]
    HeaderSize,
    /// The message is larger than [`Limits::max_payload`].
    #[error("maximum payload exceeded: {0} bytes")]
    MaxPayload(usize),
    /// The message is not followed by CRLF.
    #[error("message not followed by CRLF")]
    MissingCrlf,
}

/// Parses the first operation in `buf`.
///
/// # Errors
///
/// A [`ParseError`] for input the protocol does not allow. It is found as
/// early as `nats-server` finds it: a wrong verb at its first byte, a long
/// line once it exceeds the limit.
///
/// # Examples
///
/// ```
/// use naq_proto::client::{self, ClientOp, Limits, Parsed};
///
/// let limits = Limits::default();
/// let buf = b"PUB greet 5\r\nhello\r\nPI";
/// let Parsed::Op(ClientOp::Pub(p), used) = client::parse(buf, &limits)? else {
///     unreachable!()
/// };
/// assert_eq!((p.subject, p.payload), (&b"greet"[..], &b"hello"[..]));
/// assert_eq!(client::parse(&buf[used..], &limits)?, Parsed::Partial(None));
/// # Ok::<(), client::ParseError>(())
/// ```
#[inline]
pub fn parse<'a>(buf: &'a [u8], limits: &Limits) -> Result<Parsed<'a>, ParseError> {
    match plain_pub(buf, limits) {
        Some((p, used)) => Ok(Parsed::Op(ClientOp::Pub(p), used)),
        None => parse_any(buf, limits),
    }
}

/// [`parse`] for any input.
#[inline(never)]
fn parse_any<'a>(buf: &'a [u8], limits: &Limits) -> Result<Parsed<'a>, ParseError> {
    let Some(verb) = verb(buf)? else {
        return Ok(Parsed::Partial(None));
    };
    let name = verb.name().len();
    if verb.has_args() {
        match buf.get(name) {
            None => return Ok(Parsed::Partial(None)),
            Some(b' ' | b'\t') => {}
            Some(_) => return Err(ParseError::UnknownOp),
        }
    }
    let Some((arg, next)) = line(buf, name, limits)? else {
        return Ok(Parsed::Partial(None));
    };
    let op = match verb {
        Verb::Pub | Verb::Hpub => return message(buf, arg, next, verb, limits),
        Verb::Connect => ClientOp::Connect(arg),
        Verb::Sub => ClientOp::Sub(sub(arg)?),
        Verb::Unsub => ClientOp::Unsub(unsub(arg)?),
        Verb::Ping => ClientOp::Ping,
        Verb::Pong => ClientOp::Pong,
    };
    Ok(Parsed::Op(op, next))
}

/// The usual publish, `PUB subject [reply] size\r\n` with one space before
/// each argument, and its whole message, read in one pass. `None` for any
/// other input, which [`parse_any`] reads; for this input it gives the
/// same result.
#[inline]
fn plain_pub<'a>(buf: &'a [u8], limits: &Limits) -> Option<(Pub<'a>, usize)> {
    let verb = u32::from_le_bytes(buf.get(..4)?.try_into().ok()?);
    // Lower case for the letters; the space must be one already.
    if verb | 0x0020_2020 != u32::from_le_bytes(*b"pub ") {
        return None;
    }
    let cap = buf
        .len()
        .min(limits.max_control_line.saturating_add(LINE_SLACK));
    let line = &buf[..cap];
    let a = word(line, 4)?;
    if line[a] != b' ' {
        return None;
    }
    let b = word(line, a + 1)?;
    let (reply, size, cr) = match line[b] {
        b'\r' => (None, &line[a + 1..b], b),
        b' ' => {
            let c = word(line, b + 1)?;
            if line[c] != b'\r' {
                return None;
            }
            (Some(&line[a + 1..b]), &line[b + 1..c], c)
        }
        _ => return None,
    };
    if line.get(cr + 1) != Some(&b'\n') || cr - 4 > limits.max_control_line {
        return None;
    }
    let size = parse_size(size).filter(|&s| s <= limits.max_payload)?;
    let body = cr + 2;
    // No overflow: `size` has at most 9 digits, `body` is a short line.
    let end = body + size + 2;
    let frame = buf.get(..end)?;
    if !frame.ends_with(b"\r\n") {
        return None;
    }
    let p = Pub {
        subject: &line[4..a],
        reply,
        headers: None,
        payload: &frame[body..end - 2],
    };
    Some((p, end))
}

/// Where the part of `line` that starts at `from` ends: at its first byte
/// up to a space, blanks and line ends among them. `None` if the part is
/// empty or `line` ends first.
#[inline]
fn word(line: &[u8], from: usize) -> Option<usize> {
    const ONES: u64 = u64::from_le_bytes([1; 8]);
    let mut at = from;
    while let Some(w) = line.get(at..at + 8) {
        let w = u64::from_le_bytes(w.try_into().ok()?);
        // The high bit of bytes below 0x21. A borrow can mark bytes above
        // the first such byte, never below it.
        let low = w.wrapping_sub(ONES * 0x21) & !w & (ONES << 7);
        if low != 0 {
            at += low.trailing_zeros() as usize / 8;
            return (at > from).then_some(at);
        }
        at += 8;
    }
    let end = at + line.get(at..)?.iter().position(|&b| b <= b' ')?;
    (end > from).then_some(end)
}

/// The verb `buf` starts with. `None` while the bytes so far could still
/// become one.
#[inline]
fn verb(buf: &[u8]) -> Result<Option<Verb>, ParseError> {
    // Lower case for letters; the names have letters only.
    let lower = |at: usize| buf.get(at).map(|b| b | 0x20);
    let Some(first) = lower(0) else {
        return Ok(None);
    };
    let verb = match first {
        b'p' => match lower(1) {
            None => return Ok(None),
            Some(b'u') => Verb::Pub,
            Some(b'i') => Verb::Ping,
            Some(b'o') => Verb::Pong,
            Some(_) => return Err(ParseError::UnknownOp),
        },
        b'h' => Verb::Hpub,
        b's' => Verb::Sub,
        b'u' => Verb::Unsub,
        b'c' => Verb::Connect,
        _ => return Err(ParseError::UnknownOp),
    };
    let name = verb.name();
    let have = buf.len().min(name.len());
    if buf[..have].iter().zip(name).any(|(b, n)| b | 0x20 != *n) {
        return Err(ParseError::UnknownOp);
    }
    Ok((have == name.len()).then_some(verb))
}

/// The arguments on the control line of `buf` after the verb, which ends
/// at `from`, and the offset after the line's `\n`. `None` while the line
/// end has not arrived.
///
/// As in `nats-server`, blanks before the arguments are skipped, and a `\r`
/// anywhere after their first byte drops the last byte before the `\n`.
#[inline]
pub(crate) fn line<'a>(
    buf: &'a [u8],
    from: usize,
    limits: &Limits,
) -> Result<Option<(&'a [u8], usize)>, ParseError> {
    let cap = limits.max_control_line.saturating_add(LINE_SLACK);
    let window = buf.get(from..buf.len().min(cap)).unwrap_or_default();
    let Some(nl) = memchr::memchr(b'\n', window) else {
        return if buf.len() >= cap {
            Err(ParseError::ControlLine)
        } else {
            Ok(None)
        };
    };
    let line = &window[..nl];
    let start = line
        .iter()
        .position(|&b| !is_blank(b))
        .unwrap_or(line.len());
    let mut arg = &line[start..];
    if let [_, rest @ ..] = arg
        && (rest.last() == Some(&b'\r') || rest.contains(&b'\r'))
    {
        arg = &arg[..arg.len() - 1];
    }
    if arg.len() > limits.max_control_line {
        return Err(ParseError::ControlLine);
    }
    Ok(Some((arg, from + nl + 1)))
}

/// A `PUB` or `HPUB` whose control line ends at `next`.
#[inline]
fn message<'a>(
    buf: &'a [u8],
    arg: &'a [u8],
    next: usize,
    verb: Verb,
    limits: &Limits,
) -> Result<Parsed<'a>, ParseError> {
    let (a, n) = split::<4>(arg, is_blank).ok_or(ParseError::Args(verb))?;
    let (subject, reply, hsize, size) = match (verb, n) {
        (Verb::Pub, 2) => (a[0], None, None, a[1]),
        (Verb::Pub, 3) => (a[0], Some(a[1]), None, a[2]),
        (Verb::Hpub, 3) => (a[0], None, Some(a[1]), a[2]),
        (Verb::Hpub, 4) => (a[0], Some(a[1]), Some(a[2]), a[3]),
        _ => return Err(ParseError::Args(verb)),
    };
    let hsize = match hsize {
        Some(h) => Some(parse_size(h).ok_or(ParseError::HeaderSize)?),
        None => None,
    };
    let size = parse_size(size).ok_or(ParseError::Size(verb))?;
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
    let p = Pub {
        subject,
        reply,
        headers,
        payload,
    };
    Ok(Parsed::Op(ClientOp::Pub(p), end))
}

fn sub(arg: &[u8]) -> Result<Sub<'_>, ParseError> {
    match split::<3>(arg, is_space) {
        Some((a, 2)) => Ok(Sub {
            subject: a[0],
            queue: None,
            sid: a[1],
        }),
        Some((a, 3)) => Ok(Sub {
            subject: a[0],
            queue: Some(a[1]),
            sid: a[2],
        }),
        _ => Err(ParseError::Args(Verb::Sub)),
    }
}

fn unsub(arg: &[u8]) -> Result<Unsub<'_>, ParseError> {
    match split::<2>(arg, is_space) {
        Some((a, 1)) => Ok(Unsub {
            sid: a[0],
            max: None,
        }),
        Some((a, 2)) => Ok(Unsub {
            sid: a[0],
            max: parse_size(a[1]),
        }),
        _ => Err(ParseError::Args(Verb::Unsub)),
    }
}

/// Splits `arg` at runs of separator bytes into at most `N` parts, and
/// counts them. `None` for more than `N`.
#[inline]
fn split<const N: usize>(arg: &[u8], sep: impl Fn(u8) -> bool) -> Option<([&[u8]; N], usize)> {
    let mut parts: [&[u8]; N] = [&[]; N];
    let mut n = 0;
    let mut start = None;
    for (i, &b) in arg.iter().enumerate() {
        if sep(b) {
            if let Some(s) = start.take() {
                *parts.get_mut(n)? = &arg[s..i];
                n += 1;
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        *parts.get_mut(n)? = &arg[s..];
        n += 1;
    }
    Some((parts, n))
}

/// Separates `PUB` and `HPUB` arguments.
#[inline]
pub(crate) const fn is_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

/// Separates `SUB` and `UNSUB` arguments.
#[inline]
const fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_counts_parts_between_runs_of_separators() {
        let (a, n) = split::<3>(b"  a \t bb c ", is_blank).unwrap();
        assert_eq!((n, a), (3, [&b"a"[..], b"bb", b"c"]));
        assert!(split::<2>(b"a b c", is_blank).is_none());
        assert_eq!(split::<2>(b"", is_blank).unwrap().1, 0);
        assert_eq!(split::<2>(b"a\rb", is_blank).unwrap().1, 1);
        assert_eq!(split::<2>(b"a\rb", is_space).unwrap().1, 2);
    }

    #[test]
    fn a_cr_after_the_first_argument_byte_drops_the_last_byte() {
        let limits = Limits::default();
        let at = |buf: &'static [u8]| line(buf, 3, &limits).unwrap().unwrap();
        assert_eq!(at(b"PUB a 1\r\n"), (&b"a 1"[..], 9));
        assert_eq!(at(b"PUB a 1\n"), (&b"a 1"[..], 8));
        assert_eq!(at(b"PUB a\rb 12\n"), (&b"a\rb 1"[..], 11));
        assert_eq!(at(b"PUB \r\n"), (&b"\r"[..], 6));
        assert_eq!(at(b"PUB  \t \n"), (&b""[..], 8));
    }

    #[test]
    fn verbs_are_known_from_their_first_bytes() {
        assert_eq!(verb(b""), Ok(None));
        assert_eq!(verb(b"P"), Ok(None));
        assert_eq!(verb(b"pU"), Ok(None));
        assert_eq!(verb(b"PuB"), Ok(Some(Verb::Pub)));
        assert_eq!(verb(b"Unsub"), Ok(Some(Verb::Unsub)));
        assert_eq!(verb(b"PX"), Err(ParseError::UnknownOp));
        assert_eq!(verb(b"SUX"), Err(ParseError::UnknownOp));
        assert_eq!(verb(b"MSG"), Err(ParseError::UnknownOp));
    }

    #[test]
    fn verbs_display_in_upper_case() {
        let all = [
            Verb::Connect,
            Verb::Pub,
            Verb::Hpub,
            Verb::Sub,
            Verb::Unsub,
            Verb::Ping,
            Verb::Pong,
        ];
        for v in all {
            let mut s = [0u8; 8];
            let mut w = Buf(&mut s, 0);
            fmt::write(&mut w, format_args!("{v}")).unwrap();
            let n = w.1;
            assert!(s[..n].eq_ignore_ascii_case(v.name()));
            assert!(s[..n].iter().all(u8::is_ascii_uppercase));
        }
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
