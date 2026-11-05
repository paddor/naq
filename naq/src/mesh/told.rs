//! What this server tells others of its interest: a numbered stream of
//! deltas, and snapshots of all of it.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use bytes::Bytes;
use naq_proto::peer::{Control, Interest};
use rustc_hash::FxHashMap;
use tokio::sync::Notify;

/// Deltas waiting to be sent, at most. Past it, a delta is dropped: the
/// receivers see the gap and ask for a snapshot.
const OUTBOX: usize = 1 << 16;

/// Interest by account ID, filter and queue group.
type Key = (u32, Box<[u8]>, Option<Box<[u8]>>);

/// The members of some interest, by origin: `None` for clients, a leaf
/// cluster for the leafs of it. Sorted by origin, none of 0.
pub(crate) type ByOrigin = Vec<(Option<Rc<[u8]>>, u32)>;

/// What this server told, by account ID, and the deltas not sent yet.
#[derive(Debug)]
pub(crate) struct Told {
    epoch: u64,
    /// Account names, by ID.
    accounts: Box<[String]>,
    /// The last delta made.
    seq: Cell<u64>,
    weights: RefCell<FxHashMap<Key, ByOrigin>>,
    outbox: RefCell<VecDeque<Bytes>>,
    /// Plain interest always told, if any: by account ID and filter.
    pinned: RefCell<Option<(u32, Box<[u8]>)>>,
    /// Woken when the outbox gets a delta; shared with other tellers.
    pub(super) wake: Rc<Notify>,
}

impl Told {
    /// A teller of start `epoch`, of accounts `accounts`, that wakes
    /// `wake` when it has deltas.
    pub(super) fn new(epoch: u64, accounts: Box<[String]>, wake: Rc<Notify>) -> Told {
        Told {
            epoch,
            accounts,
            seq: Cell::new(0),
            weights: RefCell::default(),
            outbox: RefCell::default(),
            pinned: RefCell::default(),
            wake,
        }
    }

    /// Tells of the interest in `filter` of account `account`, in `queue`
    /// if given, as `now` has it: a delta for each origin told otherwise.
    pub(crate) fn set(&self, account: u32, filter: &[u8], queue: Option<&[u8]>, now: ByOrigin) {
        let pinned = queue.is_none()
            && self
                .pinned
                .borrow()
                .as_ref()
                .is_some_and(|(a, f)| *a == account && **f == *filter);
        let now = if pinned && now.is_empty() {
            vec![(None, 1)]
        } else {
            now
        };
        let key = (account, Box::from(filter), queue.map(Box::from));
        let mut weights = self.weights.borrow_mut();
        let was = weights.get(&key).map_or(&[][..], Vec::as_slice);
        let weight = |all: &[(Option<Rc<[u8]>>, u32)], o: &Option<Rc<[u8]>>| {
            all.iter().find(|(x, _)| x == o).map_or(0, |&(_, w)| w)
        };
        let at = |origin, weight| Interest {
            account: name(&self.accounts, account),
            subject: filter,
            queue,
            weight,
            origin,
        };
        let mut changed = false;
        for (o, w) in &now {
            if weight(was, o) != *w {
                self.delta(at(o.as_deref(), *w));
                changed = true;
            }
        }
        for (o, _) in was.iter().filter(|(o, _)| weight(&now, o) == 0) {
            self.delta(at(o.as_deref(), 0));
            changed = true;
        }
        if !changed {
            return;
        }
        if now.is_empty() {
            weights.remove(&key);
        } else {
            weights.insert(key, now);
        }
        drop(weights);
        self.wake.notify_one();
    }

    /// Tells of plain interest in `filter` of account `account` from now
    /// on, whatever else is told of it: the loop detection subject of a
    /// leaf node link.
    pub(super) fn pin(&self, account: u32, filter: &[u8]) {
        *self.pinned.borrow_mut() = Some((account, filter.into()));
        self.set(account, filter, None, ByOrigin::new());
    }

    /// Makes the next delta: `interest` now.
    fn delta(&self, interest: Interest<'_>) {
        let seq = self.seq.get() + 1;
        self.seq.set(seq);
        let mut out = Vec::new();
        Control::Delta {
            epoch: self.epoch,
            seq,
            interest,
        }
        .encode(&mut out);
        let mut outbox = self.outbox.borrow_mut();
        if outbox.len() < OUTBOX {
            outbox.push_back(out.into());
        }
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
        for ((account, subject, queue), by_origin) in weights.iter() {
            for (origin, weight) in by_origin {
                one(Control::Entry(Interest {
                    account: name(&self.accounts, *account),
                    subject,
                    queue: queue.as_deref(),
                    weight: *weight,
                    origin: origin.as_deref(),
                }));
            }
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

#[cfg(test)]
mod tests {
    use naq_proto::peer;

    use super::*;

    /// The weight and origin of each delta of `told`.
    fn deltas(told: &Told) -> Vec<(u32, Option<String>)> {
        told.take()
            .iter()
            .map(|d| match peer::decode(d) {
                Ok(Control::Delta { interest, .. }) => (
                    interest.weight,
                    interest
                        .origin
                        .map(|o| String::from_utf8_lossy(o).into_owned()),
                ),
                other => panic!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn a_delta_goes_out_for_each_origin_that_changed() {
        let told = Told::new(9, vec!["$G".to_owned()].into(), Rc::default());
        let x: Rc<[u8]> = Rc::from(&b"x"[..]);
        told.set(0, b"a", None, vec![(None, 1)]);
        told.set(0, b"a", None, vec![(None, 1)]);
        told.set(0, b"a", Some(b"q"), vec![(None, 1), (Some(x.clone()), 2)]);
        told.set(0, b"a", Some(b"q"), vec![(None, 2), (Some(x.clone()), 2)]);
        assert_eq!(
            deltas(&told),
            [(1, None), (1, None), (2, Some("x".into())), (2, None)],
            "no delta for what stays"
        );
        assert_eq!(told.snapshot().len(), 5, "start, three entries, end");
        told.set(0, b"a", Some(b"q"), vec![(Some(x), 3)]);
        told.set(0, b"a", None, Vec::new());
        assert_eq!(deltas(&told), [(3, Some("x".into())), (0, None), (0, None)]);
        assert_eq!(told.snapshot().len(), 3);
        assert_eq!(
            peer::decode(&told.beat()),
            Ok(Control::Beat { epoch: 9, seq: 7 })
        );
    }

    #[test]
    fn a_pinned_subject_stays_told() {
        let told = Told::new(9, vec!["$G".to_owned()].into(), Rc::default());
        told.pin(0, b"$LDS.x");
        told.set(0, b"$LDS.x", None, Vec::new());
        told.set(0, b"$LDS.x", None, vec![(None, 1)]);
        assert_eq!(deltas(&told), [(1, None)], "told once, kept");
        told.set(0, b"$LDS.x", Some(b"q"), vec![(None, 2)]);
        told.set(0, b"$LDS.x", Some(b"q"), Vec::new());
        assert_eq!(deltas(&told), [(2, None), (0, None)], "but not its queues");
    }
}
