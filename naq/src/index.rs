//! Interest index of a lane: which subscriptions a subject reaches.
//!
//! Literal subjects only, in a hash map. Wildcards and queue groups need
//! the subject trie.

use std::rc::Rc;

use rustc_hash::FxHashMap;

use crate::conn::Client;

/// One subscription.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) client: Rc<Client>,
    /// Subscription ID the client chose.
    pub(crate) sid: Box<[u8]>,
}

/// Subscriptions by subject.
#[derive(Debug, Default)]
pub(crate) struct Index {
    subjects: FxHashMap<Box<[u8]>, Vec<Entry>>,
}

impl Index {
    /// Adds a subscription to `subject`.
    pub(crate) fn insert(&mut self, subject: &[u8], entry: Entry) {
        if let Some(v) = self.subjects.get_mut(subject) {
            v.push(entry);
        } else {
            self.subjects.insert(subject.into(), vec![entry]);
        }
    }

    /// Removes subscription `sid` of client `id` from `subject`.
    pub(crate) fn remove(&mut self, subject: &[u8], id: u64, sid: &[u8]) {
        let Some(v) = self.subjects.get_mut(subject) else {
            return;
        };
        v.retain(|e| e.client.id != id || *e.sid != *sid);
        if v.is_empty() {
            self.subjects.remove(subject);
        }
    }

    /// The subscriptions `subject` reaches.
    #[inline]
    pub(crate) fn matches(&self, subject: &[u8]) -> &[Entry] {
        self.subjects.get(subject).map_or(&[], Vec::as_slice)
    }
}
