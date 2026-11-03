//! Just enough NATS client wire for the load generator and the sink.
//!
//! Frames are split from a byte buffer without copying. The payload of
//! `PUB`, `HPUB`, `MSG` and `HMSG` is sliced; its size is the last argument.

use std::fmt;

/// Longest control line accepted, CRLF excluded.
pub const MAX_CONTROL_LINE: usize = 4096;

/// Largest payload accepted. Bounds what a peer can make us buffer.
pub const MAX_PAYLOAD: usize = 8 << 20;

/// Bytes at the start of a payload that carry the publisher and sequence.
pub const STAMP_LEN: usize = 12;

/// A protocol operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `INFO`
    Info,
    /// `CONNECT`
    Connect,
    /// `PUB`
    Pub,
    /// `HPUB`
    Hpub,
    /// `SUB`
    Sub,
    /// `UNSUB`
    Unsub,
    /// `MSG`
    Msg,
    /// `HMSG`
    Hmsg,
    /// `PING`
    Ping,
    /// `PONG`
    Pong,
    /// `+OK`
    Ok,
    /// `-ERR`
    Err,
}

impl Op {
    /// Parses an operation name, ignoring ASCII case.
    pub fn parse(name: &[u8]) -> Option<Op> {
        const OPS: [(&[u8], Op); 12] = [
            (b"MSG", Op::Msg),
            (b"PUB", Op::Pub),
            (b"PING", Op::Ping),
            (b"PONG", Op::Pong),
            (b"HMSG", Op::Hmsg),
            (b"HPUB", Op::Hpub),
            (b"SUB", Op::Sub),
            (b"UNSUB", Op::Unsub),
            (b"INFO", Op::Info),
            (b"CONNECT", Op::Connect),
            (b"+OK", Op::Ok),
            (b"-ERR", Op::Err),
        ];
        OPS.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|&(_, op)| op)
    }

    /// Whether a payload follows the control line.
    pub const fn has_payload(self) -> bool {
        matches!(self, Op::Pub | Op::Hpub | Op::Msg | Op::Hmsg)
    }
}

/// One frame: an operation, its arguments and its payload, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The operation.
    pub op: Op,
    /// Arguments after the operation name, trimmed.
    pub args: &'a [u8],
    /// The payload, empty for operations without one.
    pub payload: &'a [u8],
}

/// A protocol error from the peer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    /// Control line longer than [`MAX_CONTROL_LINE`].
    #[error("control line too long")]
    LineTooLong,
    /// Unknown operation.
    #[error("unknown operation {0:?}")]
    UnknownOp(Snippet),
    /// Payload size missing, malformed or above [`MAX_PAYLOAD`].
    #[error("bad payload size")]
    BadSize,
    /// The payload is not followed by CRLF.
    #[error("payload not followed by CRLF")]
    MissingCrlf,
}

/// The start of a peer's line, for error messages.
#[derive(Clone, PartialEq, Eq)]
pub struct Snippet(String);

impl Snippet {
    fn new(bytes: &[u8]) -> Snippet {
        Snippet(String::from_utf8_lossy(&bytes[..bytes.len().min(32)]).into_owned())
    }
}

impl fmt::Debug for Snippet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/// Splits the next frame off `buf`.
///
/// Returns the frame and the bytes it used, or `None` if `buf` holds only
/// part of it.
///
/// # Errors
///
/// A [`WireError`] if the frame is malformed.
pub fn next_frame(buf: &[u8]) -> Result<Option<(Frame<'_>, usize)>, WireError> {
    let Some(nl) = buf
        .iter()
        .take(MAX_CONTROL_LINE + 2)
        .position(|&b| b == b'\n')
    else {
        return if buf.len() > MAX_CONTROL_LINE + 1 {
            Err(WireError::LineTooLong)
        } else {
            Ok(None)
        };
    };
    let line = buf[..nl].strip_suffix(b"\r").unwrap_or(&buf[..nl]);
    if line.len() > MAX_CONTROL_LINE {
        return Err(WireError::LineTooLong);
    }
    let name_len = line
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(line.len());
    let op =
        Op::parse(&line[..name_len]).ok_or_else(|| WireError::UnknownOp(Snippet::new(line)))?;
    let args = line[name_len..].trim_ascii();
    let head = nl + 1;
    if !op.has_payload() {
        return Ok(Some((
            Frame {
                op,
                args,
                payload: &[],
            },
            head,
        )));
    }
    let size = last_size(args)?;
    let end = head + size + 2;
    if buf.len() < end {
        return Ok(None);
    }
    if &buf[head + size..end] != b"\r\n" {
        return Err(WireError::MissingCrlf);
    }
    let payload = &buf[head..head + size];
    Ok(Some((Frame { op, args, payload }, end)))
}

/// The last argument as a payload size.
fn last_size(args: &[u8]) -> Result<usize, WireError> {
    let tok = args
        .rsplit(u8::is_ascii_whitespace)
        .next()
        .filter(|t| !t.is_empty() && t.len() <= 8)
        .ok_or(WireError::BadSize)?;
    let mut n = 0usize;
    for &b in tok {
        if !b.is_ascii_digit() {
            return Err(WireError::BadSize);
        }
        n = n * 10 + usize::from(b - b'0');
    }
    if n > MAX_PAYLOAD {
        return Err(WireError::BadSize);
    }
    Ok(n)
}

/// The whitespace-separated arguments of a frame.
pub fn tokens(args: &[u8]) -> impl Iterator<Item = &[u8]> {
    args.split(u8::is_ascii_whitespace)
        .filter(|t| !t.is_empty())
}

/// Appends a `PUB` frame.
pub fn write_pub(out: &mut Vec<u8>, subject: &[u8], payload: &[u8]) {
    out.extend_from_slice(b"PUB ");
    out.extend_from_slice(subject);
    out.push(b' ');
    write_decimal(out, payload.len());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
}

/// Appends a `MSG` frame.
pub fn write_msg(out: &mut Vec<u8>, subject: &[u8], sid: &[u8], payload: &[u8]) {
    out.extend_from_slice(b"MSG ");
    out.extend_from_slice(subject);
    out.push(b' ');
    out.extend_from_slice(sid);
    out.push(b' ');
    write_decimal(out, payload.len());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
}

fn write_decimal(out: &mut Vec<u8>, mut n: usize) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

/// Writes the publisher and sequence into the start of a payload.
/// Payloads shorter than [`STAMP_LEN`] are left alone.
pub fn stamp(payload: &mut [u8], publisher: u32, seq: u64) {
    if let Some(s) = payload.get_mut(..STAMP_LEN) {
        s[..4].copy_from_slice(&publisher.to_le_bytes());
        s[4..].copy_from_slice(&seq.to_le_bytes());
    }
}

/// Reads the publisher and sequence that [`stamp`] wrote.
pub fn read_stamp(payload: &[u8]) -> Option<(u32, u64)> {
    let s = payload.get(..STAMP_LEN)?;
    let publisher = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&s[4..]);
    Some((publisher, u64::from_le_bytes(seq)))
}

/// A payload of `len` bytes: zeros for the stamp, then `x`.
pub fn filler(len: usize) -> Vec<u8> {
    let mut p = vec![b'x'; len];
    stamp(&mut p, 0, 0);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_frames(mut buf: &[u8]) -> Vec<Frame<'_>> {
        let mut out = Vec::new();
        while let Some((f, n)) = next_frame(buf).unwrap() {
            out.push(f);
            buf = &buf[n..];
        }
        assert!(buf.is_empty(), "left over: {buf:?}");
        out
    }

    #[test]
    fn splits_server_frames() {
        let wire = b"INFO {\"a\":1}\r\nMSG foo 1 3\r\nabc\r\nHMSG foo 2 r 2 5\r\nhiabc\r\nPING\r\n+OK\r\n-ERR 'x'\r\n";
        let f = all_frames(wire);
        let ops: Vec<Op> = f.iter().map(|f| f.op).collect();
        assert_eq!(
            ops,
            [Op::Info, Op::Msg, Op::Hmsg, Op::Ping, Op::Ok, Op::Err]
        );
        assert_eq!(f[1].args, b"foo 1 3");
        assert_eq!(f[1].payload, b"abc");
        assert_eq!(f[2].payload, b"hiabc");
        assert_eq!(f[5].args, b"'x'");
    }

    #[test]
    fn splits_client_frames_in_any_case() {
        let wire = b"connect {}\r\nsub foo q 1\r\npub foo 0\r\n\r\nUnsub 1\nPONG\r\n";
        let f = all_frames(wire);
        let ops: Vec<Op> = f.iter().map(|f| f.op).collect();
        assert_eq!(ops, [Op::Connect, Op::Sub, Op::Pub, Op::Unsub, Op::Pong]);
        assert_eq!(f[2].payload, b"");
        assert_eq!(
            tokens(f[1].args).collect::<Vec<_>>(),
            [&b"foo"[..], b"q", b"1"]
        );
    }

    #[test]
    fn waits_for_partial_frames_at_every_split() {
        let wire = b"MSG foo 1 5\r\nhello\r\nPING\r\n";
        for cut in 0..wire.len() {
            let part = &wire[..cut];
            match next_frame(part).unwrap() {
                None => assert!(cut < 20, "cut {cut}"),
                Some((f, n)) => {
                    assert_eq!((f.op, n), (Op::Msg, 20));
                    assert_eq!(f.payload, b"hello");
                }
            }
        }
    }

    #[test]
    fn rejects_malformed_frames() {
        assert!(matches!(
            next_frame(b"NOPE x\r\n"),
            Err(WireError::UnknownOp(_))
        ));
        assert_eq!(next_frame(b"PUB foo\r\n"), Err(WireError::BadSize));
        assert_eq!(next_frame(b"PUB foo x1\r\n"), Err(WireError::BadSize));
        assert_eq!(
            next_frame(b"PUB foo 999999999\r\n"),
            Err(WireError::BadSize)
        );
        assert_eq!(
            next_frame(b"PUB foo 2\r\nabXY"),
            Err(WireError::MissingCrlf)
        );
        let long = vec![b'A'; MAX_CONTROL_LINE + 2];
        assert_eq!(next_frame(&long), Err(WireError::LineTooLong));
        let mut long_line = vec![b'A'; MAX_CONTROL_LINE + 1];
        long_line.extend_from_slice(b"\n");
        assert_eq!(next_frame(&long_line), Err(WireError::LineTooLong));
        assert_eq!(next_frame(&long[..MAX_CONTROL_LINE]), Ok(None));
    }

    #[test]
    fn writes_frames_that_parse_back() {
        let mut out = Vec::new();
        write_pub(&mut out, b"a.b", b"0123456789ab");
        write_msg(&mut out, b"a.b", b"7", b"");
        assert_eq!(&out[..16], b"PUB a.b 12\r\n0123");
        let f = all_frames(&out);
        assert_eq!(f[0].payload, b"0123456789ab");
        assert_eq!((f[1].op, f[1].args), (Op::Msg, &b"a.b 7 0"[..]));
    }

    #[test]
    fn stamps_round_trip() {
        let mut p = filler(16);
        assert_eq!(read_stamp(&p), Some((0, 0)));
        stamp(&mut p, 3, u64::MAX - 1);
        assert_eq!(read_stamp(&p), Some((3, u64::MAX - 1)));
        assert_eq!(&p[STAMP_LEN..], b"xxxx");
        let mut short = filler(5);
        stamp(&mut short, 1, 1);
        assert_eq!(short, b"xxxxx");
        assert_eq!(read_stamp(&short), None);
    }

    #[test]
    fn writes_decimals() {
        for n in [0, 9, 10, 1024, usize::MAX] {
            let mut out = Vec::new();
            write_decimal(&mut out, n);
            assert_eq!(out, n.to_string().as_bytes());
        }
    }
}
