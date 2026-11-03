//! Entry points for the fuzz targets in `fuzz/afl`. Not API.

use naq_proto::subject;

use crate::index::{Found, Index};

/// Reads a subject and filters, one per line, and checks that the index
/// finds the filters that match the subject, no more and no fewer, before
/// and after half of them go.
///
/// # Panics
///
/// When the index and [`subject::matches`] disagree.
pub fn index(data: &[u8]) {
    let mut lines = data.split(|&b| b == b'\n');
    let Some(subj) = lines.next() else {
        return;
    };
    let filters: Vec<&[u8]> = lines
        .filter(|f| subject::is_valid_filter(f))
        .take(64)
        .collect();
    let mut idx = Index::default();
    for (lane, f) in filters.iter().enumerate() {
        idx.remote(f, None, lane, true);
    }
    check(&idx, subj, &filters, |_| true);
    for (lane, f) in filters.iter().enumerate().filter(|(l, _)| l % 2 == 0) {
        idx.remote(f, None, lane, false);
    }
    check(&idx, subj, &filters, |lane| lane % 2 == 1);
}

/// Reads a WebSocket upgrade request and the frames after it.
///
/// # Panics
///
/// When the reader keeps more than it read, or compression does not round
/// trip.
pub fn websocket(data: &[u8]) {
    crate::ws::fuzz(data);
}

fn check(idx: &Index, subj: &[u8], filters: &[&[u8]], kept: impl Fn(usize) -> bool) {
    let mut want: Vec<usize> = filters
        .iter()
        .enumerate()
        .filter(|&(lane, f)| kept(lane) && subject::matches(f, subj))
        .map(|(lane, _)| lane)
        .collect();
    let groups: Vec<_> = match idx.matches(subj) {
        None => Vec::new(),
        Some(Found::One(i)) => vec![i],
        Some(Found::Many(all)) => all.iter().collect(),
    };
    let mut got: Vec<usize> = groups
        .iter()
        .flat_map(|i| i.plain.lanes.iter().map(|&(lane, _)| lane))
        .collect();
    // The same filter twice holds both lanes.
    want.sort_unstable();
    want.dedup();
    got.sort_unstable();
    got.dedup();
    assert_eq!(got, want, "subject {:?}", String::from_utf8_lossy(subj));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_agrees_with_matching_by_hand() {
        index(b"a.b.c\na.b.c\na.*.c\na.>\n>\nb.*\n*.*.*\na.b\n\na..b\n");
        index(b"");
        index(b"x\n*\n>\nx\n");
    }

    #[test]
    fn websocket_input_is_read_without_panics() {
        websocket(b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n\x02\x82\x80\0\0\0\0\x89\x80\0\0\0\0");
        websocket(b"\x16\x03\x01\n");
        websocket(b"");
    }
}
