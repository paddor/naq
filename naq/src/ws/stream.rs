//! Byte streams over WebSocket frames, for a connection's read loop and
//! writer. The reader takes frames apart in the caller's buffer; the
//! writer frames what it is given and answers the reader's control frames.

use std::cell::RefCell;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::deflate::{Deflate, Inflate};
use super::frame::{self, Broken, Decoder, Piece};
use super::upgrade::{Agent, Upgrade};
use crate::conn::Client;

/// Most payload the writer frames from one write.
const FRAME_MAX: usize = 256 << 10;
/// Frames to browsers stay this small, as `nats-server` keeps them.
const BROWSER_FRAME: usize = 4096;
/// Writes this small or smaller go out uncompressed, as in `nats-server`.
const COMPRESS_MIN: usize = 64;
/// A compressed message may hold this many times `max_payload`
/// compressed, up to [`COMPRESSED_CAP`], as in `nats-server`.
const COMPRESSED_FACTOR: usize = 8;
const COMPRESSED_CAP: usize = 64 << 20;

/// What the reader leaves the writer: control frames to send.
#[derive(Debug)]
pub(super) struct Link {
    client: Rc<Client>,
    /// The pong for the latest ping not answered yet [RFC 6455 5.5.3].
    pong: RefCell<Option<Vec<u8>>>,
    /// The payload of the close frame to end with, once chosen.
    close: RefCell<Option<Vec<u8>>>,
}

impl Link {
    pub(super) fn new(client: Rc<Client>) -> Rc<Link> {
        Rc::new(Link {
            client,
            pong: RefCell::default(),
            close: RefCell::default(),
        })
    }

    /// Sets the close frame, unless one is set.
    fn close_with(&self, payload: Vec<u8>) {
        self.close.borrow_mut().get_or_insert(payload);
    }
}

/// How a reader's stream ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The client sent a close frame.
    Closed,
    /// It broke the protocol; the close frame says how.
    Broken,
}

/// NATS bytes from a client's frames.
#[derive(Debug)]
pub(super) struct Reader<R> {
    inner: R,
    link: Rc<Link>,
    dec: Decoder,
    inflate: Option<Inflate>,
    /// Inflated bytes not handed out yet, then payload that came after
    /// them in the same read.
    ready: Vec<u8>,
    ready_at: usize,
    end: Option<End>,
    max_payload: usize,
}

impl<R> Reader<R> {
    pub(super) fn new(inner: R, link: Rc<Link>, u: &Upgrade, max_payload: usize) -> Reader<R> {
        Reader {
            inner,
            link,
            dec: Decoder::new(!u.no_masking, u.compress),
            inflate: u.compress.then(Inflate::new),
            ready: Vec::new(),
            ready_at: 0,
            end: None,
            max_payload,
        }
    }

    /// The reader of a client: frames from the server come unmasked and
    /// uncompressed.
    pub(super) const fn client(inner: R, link: Rc<Link>, max_payload: usize) -> Reader<R> {
        Reader {
            inner,
            link,
            dec: Decoder::new(false, false),
            inflate: None,
            ready: Vec::new(),
            ready_at: 0,
            end: None,
            max_payload,
        }
    }

    /// Takes the frames in `raw` apart: moves plain payload to its start
    /// and returns its length; inflated payload, and what follows it, goes
    /// to `ready`.
    pub(super) fn take(&mut self, raw: &mut [u8]) -> usize {
        let (mut at, mut kept) = (0, 0);
        while at < raw.len() && self.end.is_none() {
            let (piece, used) = match self.dec.next(&mut raw[at..]) {
                Ok(p) => p,
                Err(Broken(why)) => {
                    self.broken(frame::PROTOCOL_ERROR, &why);
                    break;
                }
            };
            match piece {
                Piece::Header => {}
                Piece::Data {
                    len,
                    compressed,
                    last,
                } => {
                    let span = at + used - len..at + used;
                    if compressed {
                        self.inflated(&raw[span], last);
                    } else if self.ready.is_empty() {
                        raw.copy_within(span, kept);
                        kept += len;
                    } else {
                        self.ready.extend_from_slice(&raw[span]);
                    }
                }
                Piece::Control(op) => self.control(op),
            }
            at += used;
        }
        kept
    }

    /// Payload of a compressed message; inflated once it is `last`.
    fn inflated(&mut self, part: &[u8], last: bool) {
        // Present: the decoder takes compressed frames only if agreed on.
        let Some(inflate) = self.inflate.as_mut() else {
            return;
        };
        let limit = (self.max_payload * COMPRESSED_FACTOR).min(COMPRESSED_CAP);
        let mut done = inflate.push(part, limit);
        if done.is_ok() && last {
            done = inflate.finish(&mut self.ready, self.max_payload);
        }
        if done.is_err() {
            // As `nats-server` closes a client it cannot read.
            self.broken(frame::GOING_AWAY, "Read Error");
        }
    }

    fn control(&mut self, op: u8) {
        let payload = self.dec.control();
        match op {
            frame::OP_PING => {
                *self.link.pong.borrow_mut() = Some(payload.to_vec());
                self.link.client.wake_writer();
            }
            frame::OP_CLOSE => match frame::close_reply(payload) {
                Ok(reply) => {
                    self.link.close_with(reply);
                    self.end = Some(End::Closed);
                }
                Err(Broken(why)) => self.broken(frame::PROTOCOL_ERROR, &why),
            },
            _ => {}
        }
    }

    fn broken(&mut self, status: u16, why: &str) {
        self.link.close_with(frame::close_payload(status, why));
        self.end = Some(End::Broken);
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Reader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.ready_at < this.ready.len() {
                let n = (this.ready.len() - this.ready_at).min(out.remaining());
                out.put_slice(&this.ready[this.ready_at..this.ready_at + n]);
                this.ready_at += n;
                if this.ready_at == this.ready.len() {
                    this.ready.clear();
                    this.ready_at = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match this.end {
                Some(End::Closed) => return Poll::Ready(Ok(())),
                Some(End::Broken) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidData)));
                }
                None => {}
            }
            let start = out.filled().len();
            ready!(Pin::new(&mut this.inner).poll_read(cx, out))?;
            let end = out.filled().len();
            if end == start {
                return Poll::Ready(Ok(()));
            }
            let kept = this.take(&mut out.filled_mut()[start..end]);
            out.set_filled(start + kept);
            if kept > 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

/// Frames for a client from the bytes written.
#[derive(Debug)]
pub(super) struct Writer<W> {
    inner: W,
    link: Rc<Link>,
    /// Frames not written yet, from `at` on.
    staged: Vec<u8>,
    at: usize,
    deflate: Option<Deflate>,
    /// Compressed bytes of the message being framed.
    packed: Vec<u8>,
    /// Most payload per frame.
    frame_max: usize,
    /// A compressed message goes in one frame, whatever its size.
    whole: bool,
    /// The close frame is staged: nothing may follow it.
    closed: bool,
    /// Frames are masked, as a client masks them.
    mask: bool,
}

impl<W> Writer<W> {
    pub(super) fn new(inner: W, link: Rc<Link>, u: &Upgrade) -> Writer<W> {
        Writer {
            inner,
            link,
            staged: Vec::new(),
            at: 0,
            deflate: u.compress.then(Deflate::new),
            packed: Vec::new(),
            frame_max: if u.agent == Agent::Other {
                FRAME_MAX
            } else {
                BROWSER_FRAME
            },
            whole: u.agent == Agent::Safari,
            closed: false,
            mask: false,
        }
    }

    /// The writer of a client: masked frames, uncompressed.
    pub(super) const fn client(inner: W, link: Rc<Link>) -> Writer<W> {
        Writer {
            inner,
            link,
            staged: Vec::new(),
            at: 0,
            deflate: None,
            packed: Vec::new(),
            frame_max: FRAME_MAX,
            whole: false,
            closed: false,
            mask: true,
        }
    }

    /// Stages a whole frame of `payload`, masked if a client sends it.
    fn whole_frame(&mut self, op: u8, payload: &[u8]) {
        if self.mask {
            let mut key = [0u8; 4];
            // A zero key on failure still frames right.
            let _ = getrandom::getrandom(&mut key);
            frame::masked(&mut self.staged, op, payload, key);
        } else {
            frame::control(&mut self.staged, op, payload);
        }
    }

    /// Stages the pong the reader asked for, if any.
    fn pong(&mut self) {
        let pong = self.link.pong.borrow_mut().take();
        if let Some(p) = pong
            && !self.closed
        {
            self.whole_frame(frame::OP_PONG, &p);
        }
    }

    /// Stages `msg` as one message: one frame, or several of at most
    /// `frame_max` bytes.
    fn stage(&mut self, msg: &[u8]) {
        let Some(d) = self.deflate.as_mut().filter(|_| msg.len() > COMPRESS_MIN) else {
            for part in msg.chunks(self.frame_max) {
                self.whole_frame(frame::OP_BINARY, part);
            }
            return;
        };
        self.packed.clear();
        d.message(msg, &mut self.packed);
        let max = if self.whole {
            self.packed.len().max(1)
        } else {
            self.frame_max
        };
        let parts = self.packed.chunks(max);
        let n = parts.len();
        for (i, part) in parts.enumerate() {
            let op = if i == 0 {
                frame::OP_BINARY
            } else {
                frame::OP_CONTINUATION
            };
            frame::header(&mut self.staged, op, i + 1 == n, i == 0, part.len());
            self.staged.extend_from_slice(part);
        }
    }

    /// The close frame for a connection the server ends.
    fn farewell(&self) -> Vec<u8> {
        let (status, text) = super::closing(self.link.client.ended());
        frame::close_payload(status, text)
    }
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    /// Writes what is staged.
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.at < self.staged.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.staged[self.at..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.at += n;
        }
        self.staged.clear();
        self.at = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Writer<W> {
    /// Stages a frame of what fits and takes it; it goes out on the next
    /// write or flush.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if this.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        this.pong();
        let take = buf.len().min(FRAME_MAX);
        this.stage(&buf[..take]);
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.pong();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    /// Ends with a close frame: the reader's answer to the client's, or
    /// the server's own.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.pong();
        if !this.closed {
            this.closed = true;
            let chosen = this.link.close.borrow_mut().take();
            let payload = chosen.unwrap_or_else(|| this.farewell());
            this.whole_frame(frame::OP_CLOSE, &payload);
        }
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    fn upgrade(compress: bool, browser: bool) -> Upgrade {
        with_agent(
            compress,
            if browser {
                Agent::Browser
            } else {
                Agent::Other
            },
        )
    }

    fn with_agent(compress: bool, agent: Agent) -> Upgrade {
        Upgrade {
            compress,
            agent,
            ..Upgrade::default()
        }
    }

    /// A client frame, masked with a fixed key.
    fn masked(op: u8, fin: bool, compressed: bool, payload: &[u8]) -> Vec<u8> {
        let key = [7, 1, 9, 3];
        let mut f = Vec::new();
        frame::header(&mut f, op, fin, compressed, payload.len());
        f[1] |= 0x80;
        f.extend_from_slice(&key);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
        f
    }

    /// A reader over an in-memory socket, and the client's end of it.
    fn reader(u: &Upgrade) -> (DuplexStream, Reader<DuplexStream>, Rc<Link>) {
        let (client, socket) = tokio::io::duplex(1 << 20);
        let link = Link::new(Rc::new(Client::new(1)));
        (client, Reader::new(socket, link.clone(), u, 1 << 20), link)
    }

    /// Server frames from `b`: opcode, FIN, RSV1 and payload.
    fn frames(mut b: &[u8]) -> Vec<(u8, bool, bool, Vec<u8>)> {
        let mut out = Vec::new();
        while !b.is_empty() {
            let (len, at) = match b[1] & 0x7f {
                126 => (usize::from(u16::from_be_bytes([b[2], b[3]])), 4),
                127 => (
                    u64::from_be_bytes(b[2..10].try_into().unwrap()) as usize,
                    10,
                ),
                n => (usize::from(n), 2),
            };
            let flags = (b[0] & 0x0f, b[0] & 0x80 != 0, b[0] & 0x40 != 0);
            out.push((flags.0, flags.1, flags.2, b[at..at + len].to_vec()));
            b = &b[at + len..];
        }
        out
    }

    #[tokio::test]
    async fn frames_and_fragments_read_as_one_byte_stream() {
        let (mut client, mut r, _link) = reader(&upgrade(false, false));
        let mut input = masked(frame::OP_BINARY, false, false, b"PUB a 2\r\n");
        input.extend(masked(frame::OP_PING, true, false, b"p"));
        input.extend(masked(frame::OP_CONTINUATION, true, false, b"hi\r\n"));
        input.extend(masked(frame::OP_TEXT, true, false, b"PING\r\n"));
        client.write_all(&input).await.unwrap();
        let mut got = vec![0; 19];
        r.read_exact(&mut got).await.unwrap();
        assert_eq!(got, b"PUB a 2\r\nhi\r\nPING\r\n");
    }

    #[tokio::test]
    async fn a_ping_is_answered_and_a_close_echoed_after_the_data() {
        let client_end = Rc::new(Client::new(1));
        let link = Link::new(client_end);
        let (mut peer, socket) = tokio::io::duplex(1 << 20);
        let (r, w) = tokio::io::split(socket);
        let u = upgrade(false, false);
        let mut reader = Reader::new(r, link.clone(), &u, 1 << 20);
        let mut writer = Writer::new(w, link, &u);
        let mut input = masked(frame::OP_PING, true, false, b"hey");
        input.extend(masked(frame::OP_BINARY, true, false, b"PING\r\n"));
        input.extend(masked(frame::OP_CLOSE, true, false, b"\x03\xe8bye"));
        input.extend(masked(frame::OP_BINARY, true, false, b"ignored"));
        peer.write_all(&input).await.unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"PING\r\n");
        writer.write_all(b"PONG\r\n").await.unwrap();
        writer.shutdown().await.unwrap();
        drop(writer);
        drop(reader);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        assert_eq!(
            frames(&out),
            vec![
                (frame::OP_PONG, true, false, b"hey".to_vec()),
                (frame::OP_BINARY, true, false, b"PONG\r\n".to_vec()),
                (frame::OP_CLOSE, true, false, b"\x03\xe8bye".to_vec()),
            ]
        );
    }

    #[tokio::test]
    async fn a_broken_frame_ends_the_stream_after_the_data_before_it() {
        let (mut client, mut r, link) = reader(&upgrade(false, false));
        let mut input = masked(frame::OP_BINARY, true, false, b"PING\r\n");
        input.extend_from_slice(&[0x82, 0x01, b'x']);
        client.write_all(&input).await.unwrap();
        let mut got = vec![0; 6];
        r.read_exact(&mut got).await.unwrap();
        assert_eq!(got, b"PING\r\n");
        let e = r.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let close = link.close.borrow().clone().unwrap();
        assert_eq!(
            close,
            frame::close_payload(frame::PROTOCOL_ERROR, "mask bit missing")
        );
    }

    #[tokio::test]
    async fn bad_compressed_data_and_bad_closes_end_the_stream() {
        let cases: [(Vec<u8>, u16, &str); 2] = [
            (
                masked(frame::OP_BINARY, true, true, b"\xff\xff\xff junk"),
                frame::GOING_AWAY,
                "Read Error",
            ),
            (
                masked(frame::OP_CLOSE, true, false, b"\x03"),
                frame::PROTOCOL_ERROR,
                "close frame payload cannot be 1 byte",
            ),
        ];
        for (input, status, why) in cases {
            let (mut client, mut r, link) = reader(&upgrade(true, false));
            client.write_all(&input).await.unwrap();
            let e = r.read(&mut [0; 16]).await.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            let close = link.close.borrow().clone().unwrap();
            assert_eq!(close, frame::close_payload(status, why));
        }
    }

    #[tokio::test]
    async fn nothing_goes_out_after_the_close_frame() {
        let link = Link::new(Rc::new(Client::new(1)));
        let (_peer, socket) = tokio::io::duplex(1 << 10);
        let mut w = Writer::new(socket, link, &upgrade(false, false));
        w.shutdown().await.unwrap();
        let e = w.write_all(b"late").await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn compressed_messages_come_inflated_in_order() {
        let (mut client, mut r, _link) = reader(&upgrade(true, false));
        let text = b"PUB a 3\r\nabc\r\n".repeat(50);
        let mut packed = Vec::new();
        Deflate::new().message(&text, &mut packed);
        let (first, rest) = packed.split_at(packed.len() / 2);
        let mut input = masked(frame::OP_BINARY, false, true, first);
        input.extend(masked(frame::OP_CONTINUATION, true, false, rest));
        input.extend(masked(frame::OP_BINARY, true, false, b"PING\r\n"));
        client.write_all(&input).await.unwrap();
        let mut got = vec![0; text.len() + 6];
        r.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..text.len()], &text[..]);
        assert_eq!(&got[text.len()..], b"PING\r\n");
    }

    #[tokio::test]
    async fn writes_become_frames_sized_for_the_client() {
        use Agent::{Browser, Other, Safari};
        let cases = [
            (false, Other),
            (false, Browser),
            (true, Other),
            (true, Browser),
            (true, Safari),
        ];
        for (compress, agent) in cases {
            let browser = agent == Browser;
            let link = Link::new(Rc::new(Client::new(1)));
            let (mut peer, socket) = tokio::io::duplex(1 << 20);
            let mut w = Writer::new(socket, link, &with_agent(compress, agent));
            // Bytes that do not compress well: several frames for a browser.
            let mut x = 1u32;
            let text: Vec<u8> = (0..10_000)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (x >> 24) as u8
                })
                .collect();
            w.write_all(&text).await.unwrap();
            w.write_all(b"tiny").await.unwrap();
            w.shutdown().await.unwrap();
            drop(w);
            let mut out = Vec::new();
            peer.read_to_end(&mut out).await.unwrap();
            let fs = frames(&out);
            let (data, close) = fs.split_at(fs.len() - 1);
            assert_eq!(close[0].0, frame::OP_CLOSE);
            let (mut got, mut packed, mut inside) = (Vec::new(), Vec::new(), false);
            for (_, fin, rsv1, payload) in data {
                assert!(payload.len() <= if browser { BROWSER_FRAME } else { FRAME_MAX });
                inside |= *rsv1;
                if !inside {
                    got.extend_from_slice(payload);
                    continue;
                }
                packed.extend_from_slice(payload);
                if *fin {
                    let mut i = Inflate::new();
                    i.push(&packed, 1 << 20).unwrap();
                    i.finish(&mut got, 1 << 20).unwrap();
                    (packed, inside) = (Vec::new(), false);
                }
            }
            let mut want = text.clone();
            want.extend_from_slice(b"tiny");
            assert_eq!(got, want, "compress {compress} {agent:?}");
            if compress && agent == Safari {
                assert!(data[0].3.len() > BROWSER_FRAME, "Safari: one frame");
            }
            if compress && browser {
                assert!(data[1].0 == frame::OP_CONTINUATION, "split");
            }
        }
    }
}
