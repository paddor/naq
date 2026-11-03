//! `permessage-deflate` [RFC 7692], with no context taken over either way,
//! as `nats-server` agrees to it: every message stands alone.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};

/// What a sync flush ends with. Frames leave it out [RFC 7692 7.2.1].
const TAIL: [u8; 4] = [0, 0, 0xff, 0xff];

/// Why a compressed message cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Bad {
    /// Larger than allowed, compressed or not.
    TooBig,
    /// Not deflate data.
    Corrupt,
}

/// Inflates a client's compressed messages.
pub(super) struct Inflate {
    d: Decompress,
    /// The payload of the message so far.
    input: Vec<u8>,
}

impl std::fmt::Debug for Inflate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inflate")
            .field("input", &self.input.len())
            .finish_non_exhaustive()
    }
}

impl Inflate {
    pub(super) fn new() -> Inflate {
        Inflate {
            d: Decompress::new(false),
            input: Vec::new(),
        }
    }

    /// Takes payload of the current message, which may be at most `limit`
    /// bytes compressed.
    pub(super) fn push(&mut self, part: &[u8], limit: usize) -> Result<(), Bad> {
        if self.input.len() + part.len() + TAIL.len() > limit {
            return Err(Bad::TooBig);
        }
        self.input.extend_from_slice(part);
        Ok(())
    }

    /// Inflates the current message onto `out`: at most `limit` bytes.
    pub(super) fn finish(&mut self, out: &mut Vec<u8>, limit: usize) -> Result<(), Bad> {
        self.input.extend_from_slice(&TAIL);
        let start = out.len();
        let result = self.inflate(out, start + limit);
        self.input.clear();
        self.d.reset(false);
        result
    }

    fn inflate(&mut self, out: &mut Vec<u8>, max: usize) -> Result<(), Bad> {
        let total = self.d.total_in();
        loop {
            let at = (self.d.total_in() - total) as usize;
            out.reserve((self.input.len() * 4).clamp(4 << 10, 256 << 10));
            let before = self.d.total_out();
            self.d
                .decompress_vec(&self.input[at..], out, FlushDecompress::Sync)
                .map_err(|_| Bad::Corrupt)?;
            if out.len() > max {
                return Err(Bad::TooBig);
            }
            let done = (self.d.total_in() - total) as usize == self.input.len();
            // Room left over: the decompressor wrote all it had.
            if out.len() < out.capacity() && (done || self.d.total_out() == before) {
                return Ok(());
            }
        }
    }
}

/// Deflates messages for a client.
pub(super) struct Deflate {
    c: Compress,
}

impl std::fmt::Debug for Deflate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deflate").finish_non_exhaustive()
    }
}

impl Deflate {
    pub(super) fn new() -> Deflate {
        Deflate {
            // Fast, as `nats-server` compresses.
            c: Compress::new(Compression::fast(), false),
        }
    }

    /// Appends `msg`, deflated as a message of its own, to `out`.
    pub(super) fn message(&mut self, msg: &[u8], out: &mut Vec<u8>) {
        let total = self.c.total_in();
        loop {
            let at = (self.c.total_in() - total) as usize;
            out.reserve((msg.len() - at) / 2 + 64);
            // Cannot fail: a sync flush of plain bytes into room.
            let _ = self.c.compress_vec(&msg[at..], out, FlushCompress::Sync);
            let done = (self.c.total_in() - total) as usize == msg.len();
            if done && out.len() < out.capacity() {
                break;
            }
        }
        if out.ends_with(&TAIL) {
            out.truncate(out.len() - TAIL.len());
        }
        self.c.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_one_by_one() {
        let (mut d, mut i) = (Deflate::new(), Inflate::new());
        for msg in [
            b"MSG a 1 2\r\nhi\r\n".repeat(1000),
            Vec::new(),
            b"x".to_vec(),
        ] {
            let mut packed = Vec::new();
            d.message(&msg, &mut packed);
            assert!(!packed.ends_with(&TAIL));
            for part in packed.chunks(7) {
                i.push(part, 1 << 20).unwrap();
            }
            let mut out = b"before".to_vec();
            i.finish(&mut out, 1 << 20).unwrap();
            assert_eq!(&out[6..], msg);
        }
    }

    #[test]
    fn limits_hold_both_ways() {
        let (mut d, mut i) = (Deflate::new(), Inflate::new());
        let mut packed = Vec::new();
        d.message(&vec![b'a'; 100_000], &mut packed);
        assert_eq!(i.push(&packed, packed.len()), Err(Bad::TooBig));
        i.input.clear();
        i.push(&packed, 1 << 20).unwrap();
        assert_eq!(i.finish(&mut Vec::new(), 1000), Err(Bad::TooBig));
        i.push(b"\xff\xff\xff junk", 1 << 20).unwrap();
        assert_eq!(i.finish(&mut Vec::new(), 1000), Err(Bad::Corrupt));
        i.push(&packed, 1 << 20).unwrap();
        let mut out = Vec::new();
        i.finish(&mut out, 1 << 20).unwrap();
        assert_eq!(out.len(), 100_000, "a failure leaves no state behind");
        assert!(format!("{i:?} {d:?}").starts_with("Inflate { input: 0"));
    }
}
