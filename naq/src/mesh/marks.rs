//! Interest ahead of the messages that follow it, as one `nats-server`
//! route carries both in order. naq tells interest on lane 0's control
//! connections and sends messages on each lane's data links: every batch
//! says the last delta made for where it goes, and the receiving lane
//! holds it until every lane of its server took that delta.

use std::cell::{Cell, RefCell};
use std::ops::Range;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use zzq_tokio::signal::StateSignal;

use crate::lane::{Lane, SLOTS};
use crate::server::Shared;

/// The longest a batch waits for the interest it follows. Past it, it goes
/// on, as if that interest had not been told yet.
const HOLD: Duration = Duration::from_secs(2);

/// What the server made and took of interest, by slot.
#[derive(Debug)]
pub(crate) struct Marks {
    /// This server's epoch, in every stamp: set as the mesh starts.
    epoch: AtomicU64,
    /// The last delta made for each slot. The routes share theirs.
    made: Box<[AtomicU64]>,
    /// The epoch and last delta of the server in each slot that every lane
    /// took.
    taken: Box<[Mutex<(u64, u64)>]>,
    /// Signaled as `taken` grows.
    changed: StateSignal,
}

impl Default for Marks {
    fn default() -> Self {
        Marks {
            epoch: AtomicU64::new(0),
            made: (0..SLOTS).map(|_| AtomicU64::new(0)).collect(),
            taken: (0..SLOTS).map(|_| Mutex::new((0, 0))).collect(),
            changed: StateSignal::new(),
        }
    }
}

impl Marks {
    /// Stamps from now on name start `epoch`.
    pub(super) fn start(&self, epoch: u64) {
        // Release: a lane that reads it has the mesh as it was set.
        self.epoch.store(epoch, Ordering::Release);
    }

    /// Notes delta `seq` made for the servers in `slots`.
    pub(super) fn made(&self, slots: Range<u16>, seq: u64) {
        for s in slots {
            if let Some(m) = self.made.get(usize::from(s)) {
                // Release: a lane that stamps it ships after the delta.
                m.store(seq, Ordering::Release);
            }
        }
    }

    /// The stamp of a batch for the server in slot `s`: this server's epoch
    /// and its last delta for it.
    pub(crate) fn stamp(&self, s: u16) -> (u64, u64) {
        let made = self
            .made
            .get(usize::from(s))
            .map_or(0, |m| m.load(Ordering::Acquire));
        (self.epoch.load(Ordering::Acquire), made)
    }

    /// Notes that every lane took delta `seq` of start `epoch` of the
    /// server in slot `s`.
    fn took(&self, s: u16, epoch: u64, seq: u64) {
        let Some(t) = self.taken.get(usize::from(s)) else {
            return;
        };
        {
            // A poisoned lock still holds the marks.
            let mut t = t.lock().unwrap_or_else(PoisonError::into_inner);
            *t = if t.0 == epoch {
                (epoch, t.1.max(seq))
            } else {
                (epoch, seq)
            };
        }
        self.changed.notify_changed();
    }

    /// What every lane took of the server in slot `s`.
    fn taken(&self, s: u16) -> (u64, u64) {
        self.taken.get(usize::from(s)).map_or((0, 0), |t| {
            *t.lock().unwrap_or_else(PoisonError::into_inner)
        })
    }
}

/// What lane 0 heard of the others' interest, waiting to be marked taken:
/// once every lane applied it.
#[derive(Debug, Default)]
pub(crate) struct Taking {
    /// The epoch and delta last noted, by slot: one heard again is not
    /// marked again.
    noted: RefCell<Vec<(u64, u64)>>,
    /// Slot, epoch and delta of what is yet to be marked.
    pending: RefCell<Vec<(u16, u64, u64)>>,
    wake: Notify,
}

impl Taking {
    /// Notes that lane 0 applied the interest of the server in slot `s` up
    /// to `at`, its epoch and delta, if it has its snapshot.
    pub(crate) fn heard(&self, s: u16, at: Option<(u64, u64)>) {
        let Some((epoch, seq)) = at else {
            return;
        };
        let mut noted = self.noted.borrow_mut();
        let at = usize::from(s);
        if noted.len() <= at {
            noted.resize(at + 1, (0, 0));
        }
        if noted[at] == (epoch, seq) {
            return;
        }
        noted[at] = (epoch, seq);
        self.pending.borrow_mut().push((s, epoch, seq));
        self.wake.notify_one();
    }
}

/// Marks what lane 0 heard as taken, once every lane applied the changes
/// it handed them before. Runs on lane 0 and ends with its tasks.
pub(super) async fn mark(shared: Arc<Shared>, taking: Rc<Taking>) {
    loop {
        // A wake while marking is kept: the next round takes it.
        taking.wake.notified().await;
        let pending = std::mem::take(&mut *taking.pending.borrow_mut());
        if pending.is_empty() {
            continue;
        }
        crate::lane::fence_all(&shared).await;
        for (s, epoch, seq) in pending {
            shared.marks.took(s, epoch, seq);
        }
    }
}

/// A lane's part: what it announced and lane 0 made into deltas, and what
/// it knows the other servers' interest taken.
#[derive(Debug, Default)]
pub(crate) struct OnLane {
    /// Interest this lane gained and announced to lane 0.
    announced: Cell<u64>,
    /// Of that, what lane 0 has made into deltas, as this lane knows.
    made: Cell<u64>,
    /// What every lane took of the server in each slot, as last read.
    seen: RefCell<Vec<(u64, u64)>>,
}

impl OnLane {
    /// Notes interest gained here, which lane 0 tells the others.
    pub(crate) fn announced(&self) {
        self.announced.set(self.announced.get() + 1);
    }

    /// Notes what was announced before as made into deltas.
    pub(crate) fn fenced(&self, upto: u64) {
        self.made.set(self.made.get().max(upto));
    }

    /// What this lane announced so far, if lane 0 may not have made it into
    /// deltas yet.
    pub(crate) fn unmade(&self) -> Option<u64> {
        let a = self.announced.get();
        (a > self.made.get()).then_some(a)
    }

    /// Whether the server in one of `slots` that stamped a batch `epoch`,
    /// `seq` has its interest taken that far, as last read.
    fn has(&self, slots: Range<u16>, epoch: u64, seq: u64) -> bool {
        let seen = self.seen.borrow();
        slots
            .filter_map(|s| seen.get(usize::from(s)))
            .any(|&(e, s)| e == epoch && s >= seq)
    }

    /// Reads again what `marks` say of `slots`, then tells as
    /// [`OnLane::has`] does.
    fn read(&self, marks: &Marks, slots: Range<u16>, epoch: u64, seq: u64) -> bool {
        {
            let mut seen = self.seen.borrow_mut();
            for s in slots.clone() {
                let at = usize::from(s);
                if seen.len() <= at {
                    seen.resize(at + 1, (0, 0));
                }
                seen[at] = marks.taken(s);
            }
        }
        self.has(slots, epoch, seq)
    }
}

/// Waits until every lane took the interest that a batch stamped
/// `epoch`, `seq` follows, of the server in one of `slots`, or [`HOLD`]
/// passed.
pub(crate) async fn follow(lane: &Lane, slots: Range<u16>, epoch: u64, seq: u64) {
    let on = &lane.marks;
    if seq == 0 || on.has(slots.clone(), epoch, seq) {
        return;
    }
    let marks = &lane.shared.marks;
    let taken = marks
        .changed
        .until(|| on.read(marks, slots.clone(), epoch, seq).then_some(()));
    // Past the hold, the batch goes on.
    let _ = tokio::time::timeout(HOLD, taken).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lane_sees_a_server_taken_once_its_epoch_and_delta_are_marked() {
        let marks = Marks::default();
        let on = OnLane::default();
        assert!(!on.read(&marks, 0..2, 7, 3));
        marks.took(1, 7, 3);
        assert!(!on.has(0..2, 7, 3), "not read yet");
        assert!(on.read(&marks, 0..2, 7, 3));
        assert!(on.has(0..2, 7, 2));
        assert!(!on.has(0..2, 8, 1), "another start");
        marks.took(1, 7, 2);
        assert_eq!(marks.taken(1), (7, 3), "a delta marked never goes back");
        marks.took(1, 8, 1);
        assert_eq!(marks.taken(1), (8, 1), "a new start begins again");
        marks.took(99, 1, 1);
        assert_eq!(marks.taken(99), (0, 0), "no such slot");
    }

    #[test]
    fn stamps_name_the_start_and_the_last_delta_made() {
        let marks = Marks::default();
        marks.start(5);
        marks.made(0..2, 9);
        assert_eq!((marks.stamp(0), marks.stamp(1)), ((5, 9), (5, 9)));
        assert_eq!(marks.stamp(2), (5, 0));
        assert_eq!(marks.stamp(99), (5, 0));
        let on = OnLane::default();
        assert_eq!(on.unmade(), None);
        on.announced();
        on.announced();
        assert_eq!(on.unmade(), Some(2));
        on.fenced(1);
        assert_eq!(on.unmade(), Some(2));
        on.fenced(2);
        assert_eq!(on.unmade(), None);
    }

    #[test]
    fn what_lane_0_heard_again_is_not_marked_again() {
        let t = Taking::default();
        t.heard(0, None);
        t.heard(2, Some((1, 1)));
        t.heard(2, Some((1, 1)));
        t.heard(2, Some((1, 2)));
        assert_eq!(*t.pending.borrow(), [(2, 1, 1), (2, 1, 2)]);
    }
}
