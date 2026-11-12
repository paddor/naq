//! Interest across the mesh: what each of the others told this server.

use naq_proto::peer::{Control, Interest};
use rustc_hash::FxHashMap;

use crate::index::Members;

/// Interest by account, filter and queue group.
type Key = (Box<[u8]>, Box<[u8]>, Option<Box<[u8]>>);

/// Interest by account, filter, queue group and origin: `None` for the
/// other server's clients, a leaf cluster for its leafs of it.
type Keyed = (Key, Option<Box<[u8]>>);

/// A snapshot's entries, or a view of interest, by account name.
type Entries = FxHashMap<Keyed, u32>;

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
    /// The view summed over origins: what the lanes have.
    sums: FxHashMap<Key, Members>,
}

/// A change of a server's interest: account name, filter, queue group, the
/// members now, 0 for none, and how many of them it has for its leafs.
pub(crate) type Change<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>, u32, u32);

impl Heard {
    /// The interest of a server of start `epoch`, none heard yet.
    pub(super) fn of(epoch: u64) -> Heard {
        Heard {
            epoch,
            ..Heard::default()
        }
    }

    /// Its start and the last delta applied, once its snapshot is in.
    pub(super) fn taken(&self) -> Option<(u64, u64)> {
        self.seq.map(|s| (self.epoch, s))
    }

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
        self.sums.len()
    }

    /// The other server's interest, as applied, in no order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = Change<'_>> {
        self.sums
            .iter()
            .map(|(k, m)| (&*k.0, &*k.1, k.2.as_deref(), m.all, m.of_leafs))
    }

    /// The members the other server told of in `subject` of `account`, in
    /// `queue` if given, for its leafs of cluster `origin`, or for its
    /// clients without one.
    pub(crate) fn of_origin(
        &self,
        account: &[u8],
        subject: &[u8],
        queue: Option<&[u8]>,
        origin: Option<&[u8]>,
    ) -> u32 {
        let k = (
            (account.into(), subject.into(), queue.map(Into::into)),
            origin.map(Into::into),
        );
        self.view.get(&k).copied().unwrap_or(0)
    }

    /// Makes `entries` the view, applying what differs of the sums.
    fn replace(&mut self, entries: Entries, apply: &mut impl FnMut(Change<'_>)) {
        let mut sums: FxHashMap<Key, Members> = FxHashMap::default();
        for ((k, origin), &w) in &entries {
            let sum = sums.entry(k.clone()).or_default();
            *sum = added(*sum, origin.is_some(), w);
        }
        for k in self.sums.keys().filter(|k| !sums.contains_key(*k)) {
            apply((&k.0, &k.1, k.2.as_deref(), 0, 0));
        }
        for (k, m) in sums.iter().filter(|(k, m)| self.sums.get(*k) != Some(*m)) {
            apply((&k.0, &k.1, k.2.as_deref(), m.all, m.of_leafs));
        }
        self.view = entries;
        self.sums = sums;
    }

    /// Sets the members of `k` to `weight`, and applies their new sum.
    fn set(&mut self, k: Keyed, weight: u32, apply: &mut impl FnMut(Change<'_>)) {
        let was = if weight == 0 {
            self.view.remove(&k)
        } else {
            self.view.insert(k.clone(), weight)
        };
        let was = was.unwrap_or(0);
        if was == weight {
            return;
        }
        let (k, origin) = k;
        let sum = self.sums.get(&k).copied().unwrap_or_default();
        let sum = added(
            removed(sum, origin.is_some(), was),
            origin.is_some(),
            weight,
        );
        apply((&k.0, &k.1, k.2.as_deref(), sum.all, sum.of_leafs));
        if sum.all == 0 {
            self.sums.remove(&k);
        } else {
            self.sums.insert(k, sum);
        }
    }
}

/// `m` with `w` members more, of leafs if `of_leafs`.
const fn added(m: Members, of_leafs: bool, w: u32) -> Members {
    Members {
        all: m.all.saturating_add(w),
        of_leafs: if of_leafs {
            m.of_leafs.saturating_add(w)
        } else {
            m.of_leafs
        },
    }
}

/// `m` with `w` members fewer, of leafs if `of_leafs`.
const fn removed(m: Members, of_leafs: bool, w: u32) -> Members {
    Members {
        all: m.all.saturating_sub(w),
        of_leafs: if of_leafs {
            m.of_leafs.saturating_sub(w)
        } else {
            m.of_leafs
        },
    }
}

fn key(i: &Interest<'_>) -> Keyed {
    (
        (i.account.into(), i.subject.into(), i.queue.map(Into::into)),
        i.origin.map(Into::into),
    )
}

#[cfg(test)]
mod tests {
    use naq_proto::peer::{Hello, Role};

    use super::*;

    fn hello(epoch: u64) -> Control<'static> {
        Control::Hello(Hello {
            role: Role::Route,
            account: b"",
            epoch,
            server_id: b"N",
            name: b"n",
            cluster: b"c",
            data: b"",
            client_urls: b"",
            leaf_urls: b"",
            nonce: b"",
        })
    }

    fn interest(subject: &'static [u8], weight: u32) -> Interest<'static> {
        Interest {
            account: b"$G",
            subject,
            queue: None,
            weight,
            origin: None,
        }
    }

    /// Feeds `msgs` to `h`; the changes, and whether it asked for a resync
    /// after each.
    fn feed(h: &mut Heard, msgs: &[Control<'_>]) -> (Vec<(String, u32)>, Vec<bool>) {
        let mut changes = Vec::new();
        let mut asks = Vec::new();
        for m in msgs {
            let mut apply = |(_, s, _, w, _): Change<'_>| {
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
        h.forget(&mut |(_, s, _, w, _): Change<'_>| gone.push((s.to_vec(), w)));
        gone.sort();
        assert_eq!(gone, [(b"b".to_vec(), 0), (b"c".to_vec(), 0)]);
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn interest_of_each_origin_adds_up() {
        let mut h = Heard::default();
        let of = |origin: Option<&'static [u8]>, weight| Interest {
            queue: Some(b"q"),
            origin,
            ..interest(b"a", weight)
        };
        let (changes, _) = feed(
            &mut h,
            &[
                hello(1),
                Control::SnapshotStart { epoch: 1, seq: 0 },
                Control::Entry(of(None, 2)),
                Control::Entry(of(Some(b"x"), 3)),
                Control::SnapshotEnd { epoch: 1 },
                Control::Delta {
                    epoch: 1,
                    seq: 1,
                    interest: of(Some(b"y"), 1),
                },
                Control::Delta {
                    epoch: 1,
                    seq: 2,
                    interest: of(None, 0),
                },
                Control::Delta {
                    epoch: 1,
                    seq: 3,
                    interest: of(Some(b"y"), 1),
                },
            ],
        );
        assert_eq!(changes, [("a".into(), 5), ("a".into(), 6), ("a".into(), 4)]);
        assert_eq!(h.of_origin(b"$G", b"a", Some(b"q"), Some(b"x")), 3);
        assert_eq!(h.of_origin(b"$G", b"a", Some(b"q"), Some(b"z")), 0);
        assert_eq!(h.len(), 1, "one entry, summed");
        let parts: Vec<(u32, u32)> = h.entries().map(|e| (e.3, e.4)).collect();
        assert_eq!(parts, [(4, 4)], "all of them of leafs now");
        let mut gone = Vec::new();
        h.forget(&mut |(_, _, _, w, _): Change<'_>| gone.push(w));
        assert_eq!(gone, [0]);
    }
}
