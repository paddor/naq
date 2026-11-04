//! Filters with wildcards, by token.

use rustc_hash::FxHashMap;

use super::{Few, Interest};

/// The filters below one token path.
#[derive(Debug, Default)]
pub(super) struct Node {
    /// Filters that end at this node.
    here: Option<Box<Interest>>,
    /// The filter of this node's path and `>`.
    tail: Option<Box<Interest>>,
    /// `*` as the next token.
    any: Option<Box<Node>>,
    /// Literal next tokens.
    next: FxHashMap<Box<[u8]>, Node>,
}

/// The first token of `s` and what follows its separator, if anything.
#[inline]
fn split(s: &[u8]) -> (&[u8], Option<&[u8]>) {
    match memchr::memchr(naq_proto::subject::SEP, s) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

impl Node {
    pub(super) fn is_empty(&self) -> bool {
        self.here.is_none() && self.tail.is_none() && self.any.is_none() && self.next.is_empty()
    }

    /// The interest of `filter`, made if new. `filter` is valid.
    pub(super) fn interest(&mut self, filter: &[u8]) -> &mut Interest {
        let (token, rest) = split(filter);
        if token == b">" {
            return self.tail.get_or_insert_default();
        }
        let child = if token == b"*" {
            self.any.get_or_insert_default()
        } else {
            self.next.entry(token.into()).or_default()
        };
        match rest {
            Some(rest) => child.interest(rest),
            None => child.here.get_or_insert_default(),
        }
    }

    /// The interest of `filter`, if there is any.
    pub(super) fn get(&self, filter: &[u8]) -> Option<&Interest> {
        let (token, rest) = split(filter);
        if token == b">" {
            return self.tail.as_deref();
        }
        let child = if token == b"*" {
            self.any.as_deref()
        } else {
            self.next.get(token)
        }?;
        match rest {
            Some(rest) => child.get(rest),
            None => child.here.as_deref(),
        }
    }

    /// Applies `f` to the interest of `filter`, if there is any, and
    /// forgets what is left empty.
    pub(super) fn change(&mut self, filter: &[u8], f: impl FnOnce(&mut Interest)) {
        let (token, rest) = split(filter);
        if token == b">" {
            return apply(&mut self.tail, f);
        }
        if token == b"*" {
            if let Some(child) = &mut self.any {
                child.change_below(rest, f);
                if child.is_empty() {
                    self.any = None;
                }
            }
            return;
        }
        if let Some(child) = self.next.get_mut(token) {
            child.change_below(rest, f);
            if child.is_empty() {
                self.next.remove(token);
            }
        }
    }

    fn change_below(&mut self, rest: Option<&[u8]>, f: impl FnOnce(&mut Interest)) {
        match rest {
            Some(rest) => self.change(rest, f),
            None => apply(&mut self.here, f),
        }
    }

    /// Calls `f` with every filter below this node and its interest.
    /// `path` holds the tokens to here, each followed by a separator.
    pub(super) fn each(&self, path: &mut Vec<u8>, f: &mut impl FnMut(&[u8], &Interest)) {
        let at = path.len();
        if let Some(h) = &self.here {
            f(&path[..at.saturating_sub(1)], h);
        }
        if let Some(t) = &self.tail {
            path.push(b'>');
            f(path, t);
            path.truncate(at);
        }
        let any = self.any.as_deref().map(|c| (&b"*"[..], c));
        for (token, child) in any
            .into_iter()
            .chain(self.next.iter().map(|(t, c)| (&**t, c)))
        {
            path.extend_from_slice(token);
            path.push(naq_proto::subject::SEP);
            child.each(path, f);
            path.truncate(at);
        }
    }

    /// Adds the interest of every filter below this node that matches
    /// `subject`, which has all its tokens.
    pub(super) fn matches<'a>(&'a self, subject: &[u8], found: &mut Few<'a, Interest>) {
        if let Some(t) = &self.tail {
            found.push(t);
        }
        let (token, rest) = split(subject);
        for child in [self.next.get(token), self.any.as_deref()]
            .into_iter()
            .flatten()
        {
            match rest {
                Some(rest) => child.matches(rest, found),
                None => {
                    if let Some(h) = &child.here {
                        found.push(h);
                    }
                }
            }
        }
    }
}

fn apply(slot: &mut Option<Box<Interest>>, f: impl FnOnce(&mut Interest)) {
    if let Some(i) = slot {
        f(i);
        if i.is_empty() {
            *slot = None;
        }
    }
}
