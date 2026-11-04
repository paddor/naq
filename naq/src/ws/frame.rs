//! WebSocket frames [RFC 6455 5]: a decoder that unmasks payloads in place,
//! and the frames the server writes. Checks and their words are those of
//! `nats-server`.

pub(super) const OP_CONTINUATION: u8 = 0x0;
pub(super) const OP_TEXT: u8 = 0x1;
pub(super) const OP_BINARY: u8 = 0x2;
pub(super) const OP_CLOSE: u8 = 0x8;
pub(super) const OP_PING: u8 = 0x9;
pub(super) const OP_PONG: u8 = 0xa;

const FIN: u8 = 0x80;
const RSV1: u8 = 0x40;
const RSV2_3: u8 = 0x30;
const MASKED: u8 = 0x80;

/// Largest control frame payload.
pub(super) const MAX_CONTROL: usize = 125;

/// Close status codes [RFC 6455 7.4.1].
pub(super) const NORMAL: u16 = 1000;
pub(super) const GOING_AWAY: u16 = 1001;
pub(super) const PROTOCOL_ERROR: u16 = 1002;
pub(super) const NO_STATUS: u16 = 1005;
pub(super) const INVALID_DATA: u16 = 1007;
pub(super) const POLICY: u16 = 1008;
pub(super) const TOO_BIG: u16 = 1009;
pub(super) const INTERNAL: u16 = 1011;

/// A piece of input, as [`Decoder::next`] finds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Piece {
    /// Header bytes, or part of a control frame.
    Header,
    /// The last `len` bytes taken: payload of a data frame, unmasked.
    Data {
        len: usize,
        /// Of a compressed message.
        compressed: bool,
        /// Ends its message.
        last: bool,
    },
    /// A whole control frame; [`Decoder::control`] holds its payload.
    Control(u8),
}

/// A frame that breaks the protocol: the text of the close frame it gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Broken(pub(super) String);

/// Reads frames from a client.
#[derive(Debug)]
pub(super) struct Decoder {
    /// Header bytes of the frame that starts, as far as they came.
    head: [u8; 14],
    have: usize,
    /// Payload left of the current frame; `None` between frames.
    left: Option<u64>,
    /// Opcode of the current frame.
    op: u8,
    mask: Option<[u8; 4]>,
    /// Payload bytes of the current frame unmasked so far, mod 4.
    turn: usize,
    /// The current frame ends its message.
    fin: bool,
    msg: Message,
    control: [u8; MAX_CONTROL],
    control_len: usize,
    agreed: Agreed,
}

/// The data message being read.
#[derive(Debug, Clone, Copy, Default)]
struct Message {
    /// It started and did not end yet.
    open: bool,
    /// It is compressed.
    compressed: bool,
}

/// What the upgrade agreed on.
#[derive(Debug, Clone, Copy)]
struct Agreed {
    /// Frames are masked, as clients mask them.
    mask: bool,
    /// Messages may be compressed.
    compress: bool,
}

impl Decoder {
    pub(super) const fn new(must_mask: bool, may_compress: bool) -> Decoder {
        Decoder {
            head: [0; 14],
            have: 0,
            left: None,
            op: 0,
            mask: None,
            turn: 0,
            fin: false,
            msg: Message {
                open: false,
                compressed: false,
            },
            control: [0; MAX_CONTROL],
            control_len: 0,
            agreed: Agreed {
                mask: must_mask,
                compress: may_compress,
            },
        }
    }

    /// The payload of the control frame [`Decoder::next`] just returned.
    pub(super) fn control(&self) -> &[u8] {
        &self.control[..self.control_len]
    }

    /// Takes the next piece from the start of `input`, which is not empty,
    /// and unmasks payload in place. Returns the piece and the bytes it
    /// took.
    pub(super) fn next(&mut self, input: &mut [u8]) -> Result<(Piece, usize), Broken> {
        let Some(left) = self.left else {
            return self.header(input);
        };
        let n = usize::try_from(left).map_or(input.len(), |l| l.min(input.len()));
        let body = &mut input[..n];
        self.unmask(body);
        let left = left - n as u64;
        self.left = Some(left);
        if self.op & 0x08 != 0 {
            self.control[self.control_len..self.control_len + n].copy_from_slice(body);
            self.control_len += n;
            if left > 0 {
                return Ok((Piece::Header, n));
            }
            self.left = None;
            return Ok((Piece::Control(self.op), n));
        }
        Ok((self.data(n, left), n))
    }

    /// The piece for `len` payload bytes of a data frame with `left` to go.
    const fn data(&mut self, len: usize, left: u64) -> Piece {
        let last = self.fin && left == 0;
        if left == 0 {
            self.left = None;
        }
        if last {
            self.msg.open = false;
        }
        Piece::Data {
            len,
            compressed: self.msg.compressed,
            last,
        }
    }

    /// Takes header bytes; once the header is whole, starts the frame.
    fn header(&mut self, input: &[u8]) -> Result<(Piece, usize), Broken> {
        let need = self.head_len()?;
        let take = (need - self.have).min(input.len());
        self.head[self.have..self.have + take].copy_from_slice(&input[..take]);
        self.have += take;
        // The length is known only once the first two bytes are.
        let need = self.head_len()?;
        if self.have < need {
            return Ok((Piece::Header, take));
        }
        let (more, piece) = self.start()?;
        if more {
            return Ok((Piece::Header, take));
        }
        Ok((piece, take))
    }

    /// How long the header is, as far as its bytes tell. Checks the
    /// first two bytes once they are there.
    fn head_len(&self) -> Result<usize, Broken> {
        if self.have < 2 {
            return Ok(2);
        }
        let (b0, b1) = (self.head[0], self.head[1]);
        self.check(b0, b1)?;
        let len = match b1 & 0x7f {
            126 => 4,
            127 => 10,
            _ => 2,
        };
        Ok(len + if b1 & MASKED != 0 { 4 } else { 0 })
    }

    /// Checks the first two header bytes, as `nats-server` does.
    fn check(&self, b0: u8, b1: u8) -> Result<(), Broken> {
        let broken = |s: &str| Err(Broken(s.to_owned()));
        let op = b0 & 0x0f;
        if b0 & RSV2_3 != 0 {
            return broken("RSV2 and RSV3 must be clear");
        }
        let compressed = b0 & RSV1 != 0;
        if compressed && !self.agreed.compress {
            return broken("compressed frame received without negotiated permessage-deflate");
        }
        if self.agreed.mask && b1 & MASKED == 0 {
            return broken("mask bit missing");
        }
        match op {
            OP_PING | OP_PONG | OP_CLOSE => {
                if usize::from(b1 & 0x7f) > MAX_CONTROL {
                    return broken("control frame length bigger than maximum allowed of 125 bytes");
                }
                if b0 & FIN == 0 {
                    return broken("control frame does not have final bit set");
                }
                if compressed {
                    return broken("control frame must not be compressed");
                }
            }
            OP_TEXT | OP_BINARY if self.msg.open => {
                return broken(
                    "new message started before final frame for previous message was received",
                );
            }
            OP_CONTINUATION if !self.msg.open || compressed => {
                return broken("invalid continuation frame");
            }
            OP_TEXT | OP_BINARY | OP_CONTINUATION => {}
            _ => return Err(Broken(format!("unknown opcode {op}"))),
        }
        Ok(())
    }

    /// Starts the frame whose header is whole. Returns whether payload
    /// follows, and the piece if none does.
    fn start(&mut self) -> Result<(bool, Piece), Broken> {
        let (b0, b1) = (self.head[0], self.head[1]);
        let (len, at) = match b1 & 0x7f {
            126 => (
                u64::from(u16::from_be_bytes([self.head[2], self.head[3]])),
                4,
            ),
            127 => {
                let mut l = [0; 8];
                l.copy_from_slice(&self.head[2..10]);
                let len = u64::from_be_bytes(l);
                if len >> 63 != 0 {
                    return Err(Broken("invalid 64-bit payload length".into()));
                }
                (len, 10)
            }
            n => (u64::from(n), 2),
        };
        self.mask = (b1 & MASKED != 0).then(|| {
            let mut m = [0; 4];
            m.copy_from_slice(&self.head[at..at + 4]);
            m
        });
        self.have = 0;
        self.turn = 0;
        self.op = b0 & 0x0f;
        self.fin = b0 & FIN != 0;
        self.left = Some(len);
        if self.op & 0x08 != 0 {
            self.control_len = 0;
            if len == 0 {
                self.left = None;
                return Ok((false, Piece::Control(self.op)));
            }
            return Ok((true, Piece::Header));
        }
        if self.op != OP_CONTINUATION {
            self.msg.compressed = b0 & RSV1 != 0;
        }
        self.msg.open = !self.fin;
        if len == 0 {
            return Ok((false, self.data(0, 0)));
        }
        Ok((true, Piece::Header))
    }

    /// Unmasks `body`, the next payload bytes of the current frame.
    fn unmask(&mut self, body: &mut [u8]) {
        let Some(m) = self.mask else {
            return;
        };
        let turn = self.turn;
        let key = [
            m[turn & 3],
            m[(turn + 1) & 3],
            m[(turn + 2) & 3],
            m[(turn + 3) & 3],
        ];
        let wide = u64::from_ne_bytes([
            key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3],
        ]);
        let (words, rest) = body.as_chunks_mut::<8>();
        for w in words {
            *w = (u64::from_ne_bytes(*w) ^ wide).to_ne_bytes();
        }
        for (i, b) in rest.iter_mut().enumerate() {
            *b ^= key[i & 3];
        }
        self.turn = (turn + body.len()) & 3;
    }
}

/// Appends the header of a server frame: unmasked.
pub(super) fn header(out: &mut Vec<u8>, op: u8, fin: bool, compressed: bool, len: usize) {
    let mut b0 = op;
    if fin {
        b0 |= FIN;
    }
    if compressed {
        b0 |= RSV1;
    }
    out.push(b0);
    if len < 126 {
        out.push(len as u8);
    } else if let Ok(short) = u16::try_from(len) {
        out.push(126);
        out.extend_from_slice(&short.to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
}

/// Appends a whole frame of a client: masked with `key`, as clients must
/// mask what they send [RFC 6455 5.3].
pub(super) fn masked(out: &mut Vec<u8>, op: u8, payload: &[u8], key: [u8; 4]) {
    let at = out.len();
    header(out, op, true, false, payload.len());
    out[at + 1] |= MASKED;
    out.extend_from_slice(&key);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
}

/// Appends a whole control frame.
pub(super) fn control(out: &mut Vec<u8>, op: u8, payload: &[u8]) {
    header(out, op, true, false, payload.len());
    out.extend_from_slice(payload);
}

/// The payload of a close frame: `status`, then `text`, cut to fit with
/// `...` as `nats-server` cuts it.
pub(super) fn close_payload(status: u16, text: &str) -> Vec<u8> {
    let mut p = status.to_be_bytes().to_vec();
    if text.len() > MAX_CONTROL - 2 {
        p.extend_from_slice(&text.as_bytes()[..MAX_CONTROL - 5]);
        p.extend_from_slice(b"...");
    } else {
        p.extend_from_slice(text.as_bytes());
    }
    p
}

/// What a server answers to a client's close frame with `payload`: the
/// same status and text, or nothing if it gave no status. A payload that
/// breaks the rules gets an error.
pub(super) fn close_reply(payload: &[u8]) -> Result<Vec<u8>, Broken> {
    match payload {
        [] => Ok(Vec::new()),
        [_] => Err(Broken("close frame payload cannot be 1 byte".into())),
        [a, b, text @ ..] => {
            let status = u16::from_be_bytes([*a, *b]);
            if !valid_status(status) {
                return Err(Broken(format!("invalid close status code {status}")));
            }
            if std::str::from_utf8(text).is_err() {
                return Ok(close_payload(
                    INVALID_DATA,
                    "invalid utf8 body in close frame",
                ));
            }
            Ok(payload.to_vec())
        }
    }
}

/// Whether a client may send `code` in a close frame.
const fn valid_status(code: u16) -> bool {
    match code {
        NO_STATUS | 1004 | 1006 | 1015 => false,
        _ => code >= 1000 && code < 5000 && !(code >= 1016 && code <= 2999),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client frame: masked with `key`.
    fn masked(b0: u8, payload: &[u8], key: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::new();
        header(
            &mut f,
            b0 & 0x0f,
            b0 & FIN != 0,
            b0 & RSV1 != 0,
            payload.len(),
        );
        f[1] |= MASKED;
        f.extend_from_slice(&key);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
        f
    }

    /// Decodes `input` fed in pieces of `step` bytes: the payload, in
    /// order, and the pieces other than headers.
    fn decode(d: &mut Decoder, input: &[u8], step: usize) -> Result<(Vec<u8>, Vec<Piece>), Broken> {
        let (mut data, mut pieces) = (Vec::new(), Vec::new());
        for chunk in input.chunks(step) {
            let mut chunk = chunk.to_vec();
            let mut at = 0;
            while at < chunk.len() {
                let (p, used) = d.next(&mut chunk[at..])?;
                if let Piece::Data { len, .. } = p {
                    data.extend_from_slice(&chunk[at + used - len..at + used]);
                }
                if p != Piece::Header {
                    pieces.push(p);
                }
                at += used;
            }
        }
        Ok((data, pieces))
    }

    #[test]
    fn payloads_come_unmasked_whatever_the_reads() {
        let text: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let mut input = masked(FIN | OP_BINARY, &text[..10], [1, 2, 3, 4]);
        input.extend(masked(OP_TEXT, &text[10..300], [9, 8, 7, 6]));
        input.extend(masked(FIN | OP_CONTINUATION, &text[300..], [5, 5, 0, 1]));
        for step in [1, 3, 7, 64, 1 << 20] {
            let mut d = Decoder::new(true, false);
            let (data, pieces) = decode(&mut d, &input, step).unwrap();
            assert_eq!(data, text, "step {step}");
            let last = pieces
                .iter()
                .filter(|p| matches!(p, Piece::Data { last: true, .. }));
            assert_eq!(last.count(), 2, "step {step}");
        }
    }

    #[test]
    fn control_frames_come_whole_between_fragments() {
        let mut input = masked(OP_BINARY, b"ab", [1, 1, 1, 1]);
        input.extend(masked(FIN | OP_PING, b"hey", [2, 2, 2, 2]));
        input.extend(masked(FIN | OP_CONTINUATION, b"", [3, 3, 3, 3]));
        input.extend(masked(FIN | OP_CLOSE, b"", [3, 3, 3, 3]));
        let mut d = Decoder::new(true, false);
        let mut seen = Vec::new();
        let mut at = 0;
        while at < input.len() {
            let (p, used) = d.next(&mut input[at..]).unwrap();
            if let Piece::Control(op) = p {
                seen.push((op, d.control().to_vec()));
            }
            at += used;
        }
        assert_eq!(
            seen,
            vec![(OP_PING, b"hey".to_vec()), (OP_CLOSE, Vec::new())]
        );
    }

    #[test]
    fn broken_frames_get_the_words_of_nats_server() {
        let cases: [(Vec<u8>, &str); 8] = [
            (vec![0x82, 0x00], "mask bit missing"),
            (vec![0xb2, 0x80], "RSV2 and RSV3 must be clear"),
            (
                vec![0xc2, 0x80],
                "compressed frame received without negotiated permessage-deflate",
            ),
            (
                vec![0x09, 0x80],
                "control frame does not have final bit set",
            ),
            (
                vec![0x89, 0xfe],
                "control frame length bigger than maximum allowed of 125 bytes",
            ),
            (vec![0x80, 0x80], "invalid continuation frame"),
            (vec![0x83, 0x80], "unknown opcode 3"),
            (
                [vec![0x82, 0xff], vec![0x80; 8]].concat(),
                "invalid 64-bit payload length",
            ),
        ];
        for (mut frame, words) in cases {
            frame.extend_from_slice(&[0; 4]);
            let mut d = Decoder::new(true, false);
            let e = decode(&mut d, &frame, 1).unwrap_err();
            assert_eq!(e.0, words);
        }
        let mut d = Decoder::new(true, false);
        let mut input = masked(OP_BINARY, b"a", [0; 4]);
        input.extend(masked(FIN | OP_BINARY, b"b", [0; 4]));
        let e = decode(&mut d, &input, 64).unwrap_err();
        assert!(e.0.starts_with("new message started"), "{e:?}");
    }

    #[test]
    fn unmasked_frames_pass_when_masking_is_off() {
        let mut d = Decoder::new(false, true);
        let mut input = Vec::new();
        header(&mut input, OP_BINARY, true, true, 3);
        input.extend_from_slice(b"xyz");
        let (data, pieces) = decode(&mut d, &input, 2).unwrap();
        assert_eq!(data, b"xyz");
        assert!(pieces.iter().all(|p| matches!(
            p,
            Piece::Data {
                compressed: true,
                ..
            }
        )));
    }

    #[test]
    fn headers_grow_with_the_payload() {
        for (len, head) in [(0, 2), (125, 2), (126, 4), (65_535, 4), (65_536, 10)] {
            let mut out = Vec::new();
            header(&mut out, OP_BINARY, true, false, len);
            assert_eq!(out.len(), head, "{len}");
            assert_eq!(out[0], 0x82);
        }
    }

    #[test]
    fn close_frames_answer_as_nats_server_answers() {
        assert_eq!(close_reply(b"").unwrap(), b"");
        assert_eq!(
            close_reply(&[0x03, 0xe8, b'o', b'k']).unwrap(),
            b"\x03\xe8ok"
        );
        assert!(close_reply(&[3]).is_err());
        assert_eq!(
            close_reply(&[0x03, 0xed]).unwrap_err().0,
            "invalid close status code 1005"
        );
        assert!(close_reply(&[0x0b, 0xb8]).is_ok(), "3000 is for apps");
        assert!(close_reply(&[0x03, 0xf8]).is_err(), "1016 is reserved");
        let bad = close_reply(&[0x03, 0xe8, 0xff]).unwrap();
        assert_eq!(&bad[..2], &INVALID_DATA.to_be_bytes());
        let long = close_payload(NORMAL, &"x".repeat(200));
        assert_eq!(long.len(), MAX_CONTROL);
        assert!(long.ends_with(b"..."));
    }
}
