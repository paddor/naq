//! Subject rules, as `nats-server` has them.
//!
//! A subject is tokens split at `.`. In a filter, the token `*` matches any
//! one token and a last token `>` matches one or more. Wildcards are whole
//! tokens: `a*` is a literal token.

/// Separates tokens.
pub const SEP: u8 = b'.';

/// The tokens of `s`.
fn tokens(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    s.split(|&b| b == SEP)
}

/// Whether `filter` can be subscribed to: no empty token, and `>` only as
/// the last.
///
/// # Examples
///
/// ```
/// use naq_proto::subject::is_valid_filter;
///
/// assert!(is_valid_filter(b"orders.*.created"));
/// assert!(is_valid_filter(b"orders.>"));
/// assert!(!is_valid_filter(b"orders.>.created"));
/// assert!(!is_valid_filter(b"orders..created"));
/// ```
pub fn is_valid_filter(filter: &[u8]) -> bool {
    let mut after_tail = false;
    for t in tokens(filter) {
        if t.is_empty() || after_tail {
            return false;
        }
        after_tail = t == b">";
    }
    true
}

/// Whether `subject` has no wildcard token. Checks nothing else.
pub fn is_literal(subject: &[u8]) -> bool {
    !tokens(subject).any(is_wildcard)
}

/// Whether `subject` can be published to in pedantic mode: no empty token
/// and no wildcard.
pub fn is_valid_literal(subject: &[u8]) -> bool {
    tokens(subject).all(|t| !t.is_empty() && !is_wildcard(t))
}

/// Whether the tokens of `subject` are all there: none empty. A subject
/// with an empty token matches no filter.
pub fn has_all_tokens(subject: &[u8]) -> bool {
    !(subject.is_empty()
        || subject.first() == Some(&SEP)
        || subject.last() == Some(&SEP)
        || subject.windows(2).any(|w| w == [SEP, SEP]))
}

/// Whether `filter` matches `subject`. Wildcards in `subject` are taken
/// as literal tokens, as a publish takes them.
///
/// # Examples
///
/// ```
/// use naq_proto::subject::matches;
///
/// assert!(matches(b"orders.*", b"orders.1"));
/// assert!(matches(b"orders.>", b"orders.1.created"));
/// assert!(!matches(b"orders.>", b"orders"));
/// assert!(!matches(b"orders.*", b"orders.1.created"));
/// ```
pub fn matches(filter: &[u8], subject: &[u8]) -> bool {
    if !has_all_tokens(subject) {
        return false;
    }
    let mut want = tokens(filter);
    let mut have = tokens(subject);
    loop {
        match (want.next(), have.next()) {
            (Some(b">"), Some(_)) | (None, None) => return true,
            (Some(w), Some(h)) if w == b"*" || w == h => {}
            _ => return false,
        }
    }
}

fn is_wildcard(t: &[u8]) -> bool {
    t == b"*" || t == b">"
}
