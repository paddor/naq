//! Answers compressed as a request's `Accept-Encoding` asks, as
//! `nats-server` compresses them: gzip, or the snappy framing format.

use std::io::Write as _;

/// The snappy framing format's stream identifier.
const STREAM: &[u8] = b"\xff\x06\x00\x00sNaPpY";

/// The most data one snappy chunk holds.
const CHUNK: usize = 65_536;

/// How an answer is compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// Not at all, and nothing said.
    Plain,
    Gzip,
    Snappy,
    /// Not at all, for an encoding the server does not know.
    Identity,
}

impl Encoding {
    /// What request headers `headers` ask for, as `nats-server` reads
    /// `Accept-Encoding`: `snappy` or `s2` anywhere first, then `gzip`.
    pub(crate) fn of(headers: &[u8]) -> Encoding {
        let Some(v) = crate::imports::info::header(headers, b"Accept-Encoding") else {
            return Encoding::Plain;
        };
        let v = v.to_ascii_lowercase();
        let has = |w: &[u8]| v.windows(w.len()).any(|x| x == w);
        if v.is_empty() {
            Encoding::Plain
        } else if has(b"snappy") || has(b"s2") {
            Encoding::Snappy
        } else if has(b"gzip") {
            Encoding::Gzip
        } else {
            Encoding::Identity
        }
    }

    /// The `Content-Encoding` it says.
    pub(crate) const fn header(self) -> Option<&'static str> {
        match self {
            Encoding::Plain => None,
            Encoding::Gzip => Some("gzip"),
            Encoding::Snappy => Some("snappy"),
            Encoding::Identity => Some("identity"),
        }
    }

    /// `body` encoded.
    pub(crate) fn apply(self, body: Vec<u8>) -> Vec<u8> {
        match self {
            Encoding::Plain | Encoding::Identity => body,
            Encoding::Gzip => gzip(&body),
            Encoding::Snappy => snappy(&body),
        }
    }
}

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    // Writes into a Vec do not fail.
    let _ = z.write_all(body);
    z.finish().unwrap_or_default()
}

/// `body` in the snappy framing format, in chunks kept uncompressed: any
/// reader of the format takes them.
fn snappy(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(STREAM.len() + body.len() + body.len() / CHUNK * 8 + 8);
    out.extend_from_slice(STREAM);
    for data in body.chunks(CHUNK) {
        // A chunk is at most 65540 bytes long: its length fits in 3.
        let len = (data.len() + 4) as u32;
        out.push(0x01);
        out.extend_from_slice(&len.to_le_bytes()[..3]);
        out.extend_from_slice(&masked(crc32c(data)).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// A CRC as the snappy framing format masks it.
const fn masked(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

/// The CRC-32C of `data`.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let low = crc & 1;
            crc = (crc >> 1) ^ (0x82f6_3b78 & low.wrapping_neg());
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_encoding_picks_as_nats_server_does() {
        let of = |h: &str| Encoding::of(format!("NATS/1.0\r\n{h}\r\n\r\n").as_bytes());
        assert_eq!(of("Accept-Encoding: gzip, snappy"), Encoding::Snappy);
        assert_eq!(of("Accept-Encoding: S2"), Encoding::Snappy);
        assert_eq!(of("Accept-Encoding: GZIP"), Encoding::Gzip);
        assert_eq!(of("Accept-Encoding: br"), Encoding::Identity);
        assert_eq!(of("X: y"), Encoding::Plain);
        assert_eq!(of("Accept-Encoding:"), Encoding::Plain);
        assert_eq!(Encoding::Identity.header(), Some("identity"));
    }

    #[test]
    fn crc32c_is_castagnoli() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn snappy_frames_hold_the_body_in_chunks() {
        let body = vec![b'x'; CHUNK + 1];
        let out = Encoding::Snappy.apply(body);
        assert!(out.starts_with(STREAM));
        let first = &out[STREAM.len()..];
        assert_eq!(first[..4], [0x01, 0x04, 0x00, 0x01]);
        let second = &first[8 + CHUNK..];
        assert_eq!(second[..4], [0x01, 0x05, 0x00, 0x00]);
        assert_eq!(second[8..], [b'x']);
    }

    #[test]
    fn gzip_reads_back() {
        let z = Encoding::Gzip.apply(b"hello".to_vec());
        let mut back = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&z[..]), &mut back)
            .unwrap();
        assert_eq!(back, "hello");
    }
}
