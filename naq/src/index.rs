//! Interest index of a lane: which subscriptions and which other lanes a
//! subject reaches. Every lane holds the interest of the whole server.
//!
//! Literal subjects only, in a hash map. Wildcards and queue groups need
//! the subject trie.

use std::rc::Rc;

use rustc_hash::FxHashMap;

use crate::conn::Client;

/// One subscription on this lane.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) client: Rc<Client>,
    /// Subscription ID the client chose.
    pub(crate) sid: Box<[u8]>,
}

/// Interest in one subject.
#[derive(Debug, Default)]
pub(crate) struct Interest {
    /// Subscriptions on this lane.
    pub(crate) local: Vec<Entry>,
    /// Other lanes with subscriptions, and how many each has.
    pub(crate) lanes: Vec<(usize, u32)>,
}

impl Interest {
    const fn is_empty(&self) -> bool {
        self.local.is_empty() && self.lanes.is_empty()
    }
}

/// Interest by subject.
#[derive(Debug, Default)]
pub(crate) struct Index {
    subjects: FxHashMap<Box<[u8]>, Interest>,
}

impl Index {
    /// Adds a subscription on this lane.
    pub(crate) fn insert(&mut self, subject: &[u8], entry: Entry) {
        self.interest(subject).local.push(entry);
    }

    /// Removes subscription `sid` of client `id`.
    pub(crate) fn remove(&mut self, subject: &[u8], id: u64, sid: &[u8]) {
        self.change(subject, |i| {
            i.local.retain(|e| e.client.id != id || *e.sid != *sid);
        });
    }

    /// Counts a subscription that lane `lane` gained, or lost.
    pub(crate) fn remote(&mut self, subject: &[u8], lane: usize, add: bool) {
        if add {
            let lanes = &mut self.interest(subject).lanes;
            match lanes.iter_mut().find(|(l, _)| *l == lane) {
                Some((_, n)) => *n += 1,
                None => lanes.push((lane, 1)),
            }
            return;
        }
        self.change(subject, |i| {
            if let Some(at) = i.lanes.iter().position(|(l, _)| *l == lane) {
                i.lanes[at].1 -= 1;
                if i.lanes[at].1 == 0 {
                    i.lanes.swap_remove(at);
                }
            }
        });
    }

    /// The interest in `subject`, if any.
    #[inline]
    pub(crate) fn matches(&self, subject: &[u8]) -> Option<&Interest> {
        self.subjects.get(subject)
    }

    fn interest(&mut self, subject: &[u8]) -> &mut Interest {
        self.subjects.entry(subject.into()).or_default()
    }

    /// Applies `f` to the interest in `subject` and forgets the subject
    /// once nothing is left.
    fn change(&mut self, subject: &[u8], f: impl FnOnce(&mut Interest)) {
        if let Some(i) = self.subjects.get_mut(subject) {
            f(i);
            if i.is_empty() {
                self.subjects.remove(subject);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_lanes_are_counted_until_their_last_subscription_goes() {
        let mut idx = Index::default();
        idx.remote(b"a", 1, true);
        idx.remote(b"a", 1, true);
        idx.remote(b"a", 2, true);
        assert_eq!(idx.matches(b"a").unwrap().lanes, [(1, 2), (2, 1)]);
        idx.remote(b"a", 1, false);
        idx.remote(b"a", 2, false);
        assert_eq!(idx.matches(b"a").unwrap().lanes, [(1, 1)]);
        idx.remote(b"a", 3, false);
        idx.remote(b"b", 1, false);
        idx.remote(b"a", 1, false);
        assert!(idx.matches(b"a").is_none(), "forgotten");
    }
}
