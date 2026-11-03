//! Decimal numbers on the wire.

/// Most digits a size may have, as in `nats-server` (999,999,999).
const MAX_SIZE_DIGITS: usize = 9;

/// Room for any `usize` in decimal.
pub(crate) type Digits = [u8; 20];

/// A size argument: 1 to 9 ASCII digits, nothing else.
#[inline]
pub(crate) fn parse_size(d: &[u8]) -> Option<usize> {
    if d.is_empty() || d.len() > MAX_SIZE_DIGITS {
        return None;
    }
    let mut n = 0;
    for &b in d {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + usize::from(b - b'0');
    }
    Some(n)
}

/// `n` in decimal, at the end of `buf`.
#[inline]
pub(crate) fn decimal(mut n: usize, buf: &mut Digits) -> &[u8] {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &buf[at..];
        }
    }
}

/// Length of `n` in decimal.
#[inline]
pub(crate) const fn decimal_len(mut n: usize) -> usize {
    let mut len = 1;
    while n >= 10 {
        n /= 10;
        len += 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_one_to_nine_digits() {
        assert_eq!(parse_size(b"0"), Some(0));
        assert_eq!(parse_size(b"1024"), Some(1024));
        assert_eq!(parse_size(b"999999999"), Some(999_999_999));
        assert_eq!(parse_size(b"1000000000"), None);
        assert_eq!(parse_size(b""), None);
        assert_eq!(parse_size(b"-1"), None);
        assert_eq!(parse_size(b"1k"), None);
    }

    #[test]
    fn decimals_round_trip() {
        let mut buf = Digits::default();
        for n in [0, 7, 10, 99, 1024, 999_999_999, usize::MAX] {
            let s = decimal(n, &mut buf);
            assert_eq!(s.len(), decimal_len(n));
            let back = core::str::from_utf8(s).unwrap().parse::<usize>().unwrap();
            assert_eq!(back, n);
        }
    }
}
