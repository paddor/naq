//! Interest across the mesh: what this server tells the others of its
//! clients' interest, and what each of the others told it.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use bytes::Bytes;
use naq_proto::peer::{Control, Interest};
use rustc_hash::FxHashMap;
use tokio::sync::Notify;

use crate::index::Index;

/// Deltas waiting for the others, at most. Past it, a delta is dropped:
/// the others see the gap and ask for a snapshot.
const OUTBOX: usize = 1 << 16;

/// Interest by account, filter and queue group.
type Key<A> = (A, Box<[u8]>, Option<Box<[u8]>>);

/// What this server told the others, by account ID, and the deltas not
/// sent yet. Lane 0 keeps it.
#[derive(Debug)]
pub(crate) struct Told {
    epoch: u64,
    /// Account names, by ID.
    accounts: Box<[String]>,
    /// The last delta made.
    seq: Cell<u64>,
    weights: RefCell<FxHashMap<Key<u32>, u32>>,
    outbox: RefCell<VecDeque<Bytes>>,
    /// Woken when the outbox gets a delta.
    pub(super) wake: Notify,
}

impl Told {
    pub(super) fn new(epoch: u64, accounts: Box<[String]>) -> Told {
        Told {
            epoch,
            accounts,
            seq: Cell::new(0),
            weights: RefCell::default(),
            outbox: RefCell::default(),
            wake: Notify::new(),
        }
    }

    /// Notes the client interest in `filter` of account `account`, in
    /// `queue` if given, as `index` has it now, and makes
    /// a delta if the others were told otherwise. Plain interest is there
    /// or not; a queue group tells its member count.
    pub(crate) fn update(&self, index: &Index, account: u32, filter: &[u8], queue: Option<&[u8]>) {
        let n = index.clients(filter, queue);
        let n = if queue.is_none() { u32::from(n > 0) } else { n };
        let key = (account, Box::from(filter), queue.map(Box::from));
        let mut weights = self.weights.borrow_mut();
        if weights.get(&key).copied().unwrap_or(0) == n {
            return;
        }
        if n == 0 {
            weights.remove(&key);
        } else {
            weights.insert(key, n);
        }
        let seq = self.seq.get() + 1;
        self.seq.set(seq);
        let mut out = Vec::new();
        Control::Delta {
            epoch: self.epoch,
            seq,
            interest: Interest {
                account: name(&self.accounts, account),
                subject: filter,
                queue,
                weight: n,
            },
        }
        .encode(&mut out);
        let mut outbox = self.outbox.borrow_mut();
        if outbox.len() < OUTBOX {
            outbox.push_back(out.into());
        }
        drop(outbox);
        self.wake.notify_one();
    }

    /// A snapshot of all of it, as of the last delta: its messages, in
    /// order.
    pub(super) fn snapshot(&self) -> Vec<Bytes> {
        let weights = self.weights.borrow();
        let mut all = Vec::with_capacity(weights.len() + 2);
        let mut one = |c: Control<'_>| {
            let mut out = Vec::new();
            c.encode(&mut out);
            all.push(Bytes::from(out));
        };
        one(Control::SnapshotStart {
            epoch: self.epoch,
            seq: self.seq.get(),
        });
        for ((account, subject, queue), &weight) in weights.iter() {
            one(Control::Entry(Interest {
                account: name(&self.accounts, *account),
                subject,
                queue: queue.as_deref(),
                weight,
            }));
        }
        one(Control::SnapshotEnd { epoch: self.epoch });
        all
    }

    /// A beat: how far the deltas got.
    pub(super) fn beat(&self) -> Bytes {
        let mut out = Vec::new();
        Control::Beat {
            epoch: self.epoch,
            seq: self.seq.get(),
        }
        .encode(&mut out);
        out.into()
    }

    /// The deltas to send, oldest first.
    pub(super) fn take(&self) -> VecDeque<Bytes> {
        std::mem::take(&mut *self.outbox.borrow_mut())
    }
}

/// The name of account `id` among `accounts`.
fn name(accounts: &[String], id: u32) -> &[u8] {
    accounts
        .get(id as usize)
        .map_or(&b"$G"[..], |a| a.as_bytes())
}

/// A snapshot's entries, or a view of interest, by account name.
type Entries = FxHashMap<Key<Box<[u8]>>, u32>;

/// What one other server told this one, by account name, as applied.
#[derive(Debug, Clone, Default)]
pub(crate) struct Heard {
    epoch: u64,
    /// The last delta applied; `None` until a snapshot is in.
    seq: Option<u64>,
    /// A snapshot coming in: the delta it is as of, and its entries so far.
    coming: Option<(u64, Entries)>,
    /// The other server's interest, as applied.
    view: Entries,
}

/// A change of a server's interest: account name, filter, queue group and
/// the members now, 0 for none.
pub(crate) type Change<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>, u32);

impl Heard {
    /// Takes control message `c` of the other server, and calls `apply`
    /// with each change of its interest. Returns whether this lost track of
    /// it and must ask for a snapshot.
    pub(super) fn take(&mut self, c: &Control<'_>, apply: &mut impl FnMut(Change<'_>)) -> bool {
        match *c {
            Control::Hello(h) => {
                if h.epoch != self.epoch {
                    // It started again: its snapshot comes next.
                    self.epoch = h.epoch;
                    self.seq = None;
                }
                false
            }
            Control::SnapshotStart { epoch, seq } if epoch == self.epoch => {
                self.coming = Some((seq, Entries::default()));
                false
            }
            Control::Entry(i) => {
                if let Some((_, entries)) = &mut self.coming {
                    entries.insert(key(&i), i.weight);
                }
                false
            }
            Control::SnapshotEnd { epoch } if epoch == self.epoch => {
                if let Some((seq, entries)) = self.coming.take() {
                    self.replace(entries, apply);
                    self.seq = Some(seq);
                }
                false
            }
            Control::Delta {
                epoch,
                seq,
                interest,
            } if epoch == self.epoch => match self.seq {
                // In the snapshot already, or none is in yet.
                None => false,
                Some(last) if seq <= last => false,
                Some(last) if seq == last + 1 => {
                    self.seq = Some(seq);
                    self.set(key(&interest), interest.weight, apply);
                    false
                }
                Some(_) => self.lost(),
            },
            Control::Beat { epoch, seq } if epoch == self.epoch => match self.seq {
                Some(last) if seq > last => self.lost(),
                // Still no snapshot: the ask, or the end of a snapshot, may
                // have been lost. A snapshot is sent whole, with no beat
                // in it.
                None => {
                    self.coming = None;
                    true
                }
                Some(_) => false,
            },
            _ => false,
        }
    }

    const fn lost(&mut self) -> bool {
        self.seq = None;
        true
    }

    /// Forgets all of it, as the other server is gone.
    pub(super) fn forget(&mut self, apply: &mut impl FnMut(Change<'_>)) {
        self.replace(Entries::default(), apply);
        self.seq = None;
        self.coming = None;
    }

    /// Entries of the other server's interest, as applied.
    pub(crate) fn len(&self) -> usize {
        self.view.len()
    }

    /// The other server's interest, as applied, in no order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = Change<'_>> {
        self.view
            .iter()
            .map(|(k, &w)| (&*k.0, &*k.1, k.2.as_deref(), w))
    }

    /// Makes `entries` the view, applying what differs.
    fn replace(&mut self, entries: Entries, apply: &mut impl FnMut(Change<'_>)) {
        for k in self.view.keys().filter(|k| !entries.contains_key(*k)) {
            apply((&k.0, &k.1, k.2.as_deref(), 0));
        }
        for (k, &w) in entries
            .iter()
            .filter(|(k, w)| self.view.get(*k) != Some(*w))
        {
            apply((&k.0, &k.1, k.2.as_deref(), w));
        }
        self.view = entries;
    }

    fn set(&mut self, k: Key<Box<[u8]>>, weight: u32, apply: &mut impl FnMut(Change<'_>)) {
        apply((&k.0, &k.1, k.2.as_deref(), weight));
        if weight == 0 {
            self.view.remove(&k);
        } else {
            self.view.insert(k, weight);
        }
    }
}

fn key(i: &Interest<'_>) -> Key<Box<[u8]>> {
    (i.account.into(), i.subject.into(), i.queue.map(Into::into))
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use naq_proto::peer::{self, Hello};

    use super::*;
    use crate::conn::Client;
    use crate::index::Entry;

    fn hello(epoch: u64) -> Control<'static> {
        Control::Hello(Hello {
            epoch,
            server_id: b"N",
            name: b"n",
            cluster: b"c",
            data: b"",
            client_urls: b"",
        })
    }

    fn interest(subject: &'static [u8], weight: u32) -> Interest<'static> {
        Interest {
            account: b"$G",
            subject,
            queue: None,
            weight,
        }
    }

    /// Feeds `msgs` to `h`; the changes, and whether it asked for a resync
    /// after each.
    fn feed(h: &mut Heard, msgs: &[Control<'_>]) -> (Vec<(String, u32)>, Vec<bool>) {
        let mut changes = Vec::new();
        let mut asks = Vec::new();
        for m in msgs {
            let mut apply = |(_, s, _, w): Change<'_>| {
                changes.push((String::from_utf8_lossy(s).into_owned(), w));
            };
            asks.push(h.take(m, &mut apply));
        }
        (changes, asks)
    }

    #[test]
    fn a_snapshot_then_deltas_in_order_are_applied() {
        let mut h = Heard::default();
        let (changes, asks) = feed(
            &mut h,
            &[
                hello(7),
                Control::Delta {
                    epoch: 7,
                    seq: 1,
                    interest: interest(b"early", 1),
                },
                Control::SnapshotStart { epoch: 7, seq: 2 },
                Control::Entry(interest(b"a", 1)),
                Control::Entry(interest(b"b", 1)),
                Control::SnapshotEnd { epoch: 7 },
                Control::Delta {
                    epoch: 7,
                    seq: 2,
                    interest: interest(b"a", 0),
                },
                Control::Delta {
                    epoch: 7,
                    seq: 3,
                    interest: interest(b"a", 0),
                },
                Control::Delta {
                    epoch: 6,
                    seq: 4,
                    interest: interest(b"x", 1),
                },
                Control::Beat { epoch: 7, seq: 3 },
            ],
        );
        let mut changes = changes;
        changes[..2].sort();
        assert_eq!(
            changes,
            [("a".into(), 1), ("b".into(), 1), ("a".into(), 0)],
            "before the snapshot, in it already, or of another epoch: skipped"
        );
        assert!(asks.iter().all(|a| !a), "{asks:?}");
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn a_gap_or_a_beat_ahead_asks_for_a_snapshot() {
        let start = [
            hello(1),
            Control::SnapshotStart { epoch: 1, seq: 0 },
            Control::SnapshotEnd { epoch: 1 },
        ];
        let mut h = Heard::default();
        feed(&mut h, &start);
        let skip = Control::Delta {
            epoch: 1,
            seq: 2,
            interest: interest(b"a", 1),
        };
        assert_eq!(feed(&mut h, &[skip]).1, [true]);
        // Until the snapshot is in, deltas wait; a beat asks again.
        let next = Control::Delta {
            epoch: 1,
            seq: 3,
            interest: interest(b"a", 1),
        };
        let beat = Control::Beat { epoch: 1, seq: 3 };
        assert_eq!(feed(&mut h, &[next, beat]).1, [false, true]);
        let mut h = Heard::default();
        feed(&mut h, &start);
        assert_eq!(
            feed(&mut h, &[Control::Beat { epoch: 1, seq: 1 }]).1,
            [true]
        );
    }

    #[test]
    fn a_beat_in_a_snapshot_asks_for_it_again() {
        let mut h = Heard::default();
        let cut = [
            hello(1),
            Control::SnapshotStart { epoch: 1, seq: 0 },
            Control::Entry(interest(b"a", 1)),
            Control::Beat { epoch: 1, seq: 0 },
            Control::SnapshotEnd { epoch: 1 },
        ];
        let (changes, asks) = feed(&mut h, &cut);
        assert_eq!(asks, [false, false, false, true, false]);
        // What came of it is dropped, and its end does not apply it.
        assert_eq!(changes, Vec::<(String, u32)>::new());
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn a_new_snapshot_or_start_replaces_what_was_there() {
        let mut h = Heard::default();
        feed(
            &mut h,
            &[
                hello(1),
                Control::SnapshotStart { epoch: 1, seq: 0 },
                Control::Entry(interest(b"a", 1)),
                Control::Entry(interest(b"b", 1)),
                Control::SnapshotEnd { epoch: 1 },
            ],
        );
        let (changes, _) = feed(
            &mut h,
            &[
                hello(2),
                Control::SnapshotStart { epoch: 2, seq: 5 },
                Control::Entry(interest(b"b", 1)),
                Control::Entry(interest(b"c", 1)),
                Control::SnapshotEnd { epoch: 2 },
            ],
        );
        let mut changes = changes;
        changes.sort();
        assert_eq!(changes, [("a".into(), 0), ("c".into(), 1)], "b stays");
        let mut gone = Vec::new();
        h.forget(&mut |(_, s, _, w): Change<'_>| gone.push((s.to_vec(), w)));
        gone.sort();
        assert_eq!(gone, [(b"b".to_vec(), 0), (b"c".to_vec(), 0)]);
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn the_others_are_told_of_plain_interest_once_and_of_queue_counts() {
        let told = Told::new(9, vec!["$G".to_owned()].into());
        let mut idx = Index::default();
        let c = Rc::new(Client::new(1));
        idx.insert(b"a", None, Entry::new(c.clone(), b"1"));
        told.update(&idx, 0, b"a", None);
        idx.insert(b"a", None, Entry::new(c.clone(), b"2"));
        told.update(&idx, 0, b"a", None);
        idx.insert(b"a", Some(b"q"), Entry::new(c.clone(), b"3"));
        told.update(&idx, 0, b"a", Some(b"q"));
        idx.insert(b"a", Some(b"q"), Entry::new(c, b"4"));
        told.update(&idx, 0, b"a", Some(b"q"));
        let deltas: Vec<_> = told.take().into_iter().collect();
        let weights: Vec<u32> = deltas
            .iter()
            .map(|d| match peer::decode(d) {
                Ok(Control::Delta { interest, .. }) => interest.weight,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(weights, [1, 1, 2], "plain once, the queue at 1 then 2");
        let snap = told.snapshot();
        assert_eq!(snap.len(), 4, "start, two entries, end");
        assert_eq!(
            peer::decode(&told.beat()),
            Ok(Control::Beat { epoch: 9, seq: 3 })
        );
    }
}
