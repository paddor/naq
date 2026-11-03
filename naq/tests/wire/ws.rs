//! The WebSocket side of a script client: the upgrade, frames out, and
//! frames in turned back into the bytes and events they carry.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// The key of every upgrade; the server's answer to it is fixed.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
/// The mask of every frame the client sends.
const MASK: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

/// An upgrade request for `host`.
pub(super) fn request(host: &str) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .into_bytes()
}

/// A binary frame of `payload`, masked unless the server agreed to
/// frames without.
fn frame(payload: &[u8], masked: bool) -> Vec<u8> {
    let bit = if masked { 0x80 } else { 0 };
    let mut f = vec![0x82];
    match payload.len() {
        n if n < 126 => f.push(bit | n as u8),
        n if n <= 0xffff => {
            f.push(bit | 0x7e);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(bit | 0x7f);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    if !masked {
        f.extend_from_slice(payload);
        return f;
    }
    f.extend_from_slice(&MASK);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ MASK[i & 3]));
    f
}

/// What frames carried.
pub(super) enum Got {
    /// NATS bytes.
    Data(Vec<u8>),
    /// A control frame, as a transcript line.
    Line(String),
}

/// A client's WebSocket state.
#[derive(Default)]
pub(super) struct Ws {
    /// The upgrade is done: what comes is frames.
    pub(super) up: bool,
    /// Compression was agreed on.
    compress: bool,
    /// Frames without a mask were agreed on (`Nats-No-Masking`).
    unmasked: bool,
    /// Received, not yet taken apart.
    raw: Vec<u8>,
    /// The compressed message being received.
    packed: Option<Vec<u8>>,
}

impl Ws {
    /// Upgrades `stream` with a plain request and checks the answer.
    pub(super) fn upgrade(stream: &mut TcpStream) -> Ws {
        let addr = stream.peer_addr().unwrap();
        stream.write_all(&request(&addr.to_string())).unwrap();
        let mut ws = Ws::default();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some((lines, up)) = ws.http() {
                assert!(up, "upgrade refused: {lines:?}");
                return ws;
            }
            assert!(Instant::now() < deadline, "no upgrade response");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "closed during the upgrade");
            ws.raw.extend_from_slice(&chunk[..n]);
        }
    }

    /// A frame of `payload`, as agreed on.
    pub(super) fn frame(&self, payload: &[u8]) -> Vec<u8> {
        frame(payload, !self.unmasked)
    }

    pub(super) fn feed(&mut self, bytes: &[u8]) {
        self.raw.extend_from_slice(bytes);
    }

    /// The HTTP response, once it is all in: its lines, and whether it
    /// upgraded. Header lines are sorted; `Date` is left out.
    pub(super) fn http(&mut self) -> Option<(Vec<String>, bool)> {
        let end = self.raw.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = String::from_utf8(self.raw[..end].to_vec()).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap_or_default().to_owned();
        let mut headers: Vec<String> = lines
            .filter(|l| !l.to_ascii_lowercase().starts_with("date:"))
            .map(str::to_owned)
            .collect();
        headers.sort();
        let up = status.starts_with("HTTP/1.1 101 ");
        let length: usize = headers
            .iter()
            .find_map(|h| h.strip_prefix("Content-Length: "))
            .map_or(0, |n| n.parse().unwrap());
        let body = self.raw.get(end + 4..end + 4 + length)?.to_vec();
        self.raw.drain(..end + 4 + length);
        self.compress = headers
            .iter()
            .any(|h| h.starts_with("Sec-WebSocket-Extensions: permessage-deflate"));
        self.unmasked = headers.iter().any(|h| h == "Nats-No-Masking: true");
        self.up = up;
        let mut out = vec![status];
        out.extend(headers);
        if !body.is_empty() {
            out.push(super::escape(&body));
        }
        Some((out, up))
    }

    /// Takes the whole frames received apart.
    pub(super) fn take(&mut self) -> Vec<Got> {
        let mut got = Vec::new();
        while let Some((b0, payload, used)) = whole_frame(&self.raw) {
            self.raw.drain(..used);
            match b0 & 0x0f {
                0x8 => got.push(Got::Line(close_line(&payload))),
                0x9 => got.push(Got::Line(format!("(ping {})", super::escape(&payload)))),
                0xa => got.push(Got::Line(format!("(pong {})", super::escape(&payload)))),
                _ => {
                    if let Some(data) = self.data(b0, payload) {
                        got.push(Got::Data(data));
                    }
                }
            }
        }
        got
    }

    /// The bytes of a data frame, inflated once a compressed message is
    /// whole.
    fn data(&mut self, b0: u8, payload: Vec<u8>) -> Option<Vec<u8>> {
        let fin = b0 & 0x80 != 0;
        if b0 & 0x40 != 0 {
            assert!(self.compress, "compressed without agreeing to");
            self.packed = Some(Vec::new());
        }
        let Some(packed) = self.packed.as_mut() else {
            return Some(payload);
        };
        packed.extend_from_slice(&payload);
        if !fin {
            return None;
        }
        // The tail frames leave out, then an empty last block, as Go ends
        // the stream to read it.
        packed.extend_from_slice(&[0, 0, 0xff, 0xff, 1, 0, 0, 0xff, 0xff]);
        let mut out = Vec::new();
        flate2::read::DeflateDecoder::new(&packed[..])
            .read_to_end(&mut out)
            .unwrap();
        self.packed = None;
        Some(out)
    }
}

/// The first whole frame of `raw`: its first byte, its payload and its
/// length.
fn whole_frame(raw: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    let (b0, b1) = (*raw.first()?, *raw.get(1)?);
    assert_eq!(b1 & 0x80, 0, "the server masked a frame");
    let (len, at) = match b1 & 0x7f {
        126 => (
            usize::from(u16::from_be_bytes(raw.get(2..4)?.try_into().unwrap())),
            4,
        ),
        127 => (
            u64::from_be_bytes(raw.get(2..10)?.try_into().unwrap()) as usize,
            10,
        ),
        n => (usize::from(n), 2),
    };
    let payload = raw.get(at..at + len)?.to_vec();
    Some((b0, payload, at + len))
}

/// A close frame as a transcript line: `(close 1002 text)`.
fn close_line(payload: &[u8]) -> String {
    match payload {
        [a, b, text @ ..] => format!(
            "(close {} {})",
            u16::from_be_bytes([*a, *b]),
            super::escape(text)
        ),
        [] => "(close)".into(),
        _ => format!("(close {})", super::escape(payload)),
    }
}
