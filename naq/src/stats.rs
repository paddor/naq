//! Message counters for monitoring: kept where the messages pass, without
//! atomics, and published for other threads once per batch.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

/// Messages and bytes in and out, counted on one thread.
#[derive(Debug, Default)]
pub(crate) struct Tally {
    in_msgs: Cell<u64>,
    in_bytes: Cell<u64>,
    out_msgs: Cell<u64>,
    out_bytes: Cell<u64>,
}

/// Messages and bytes in and out, as numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Totals {
    pub(crate) in_msgs: u64,
    pub(crate) in_bytes: u64,
    pub(crate) out_msgs: u64,
    pub(crate) out_bytes: u64,
}

impl std::ops::AddAssign for Totals {
    fn add_assign(&mut self, o: Totals) {
        self.in_msgs += o.in_msgs;
        self.in_bytes += o.in_bytes;
        self.out_msgs += o.out_msgs;
        self.out_bytes += o.out_bytes;
    }
}

impl Tally {
    /// A message of `bytes` came in.
    #[inline]
    pub(crate) fn took(&self, bytes: usize) {
        self.in_msgs.set(self.in_msgs.get() + 1);
        self.in_bytes.set(self.in_bytes.get() + bytes as u64);
    }

    /// A message of `bytes` went out.
    #[inline]
    pub(crate) fn gave(&self, bytes: usize) {
        self.out_msgs.set(self.out_msgs.get() + 1);
        self.out_bytes.set(self.out_bytes.get() + bytes as u64);
    }

    /// Starts over from none.
    pub(crate) fn reset(&self) {
        for c in [
            &self.in_msgs,
            &self.in_bytes,
            &self.out_msgs,
            &self.out_bytes,
        ] {
            c.set(0);
        }
    }

    pub(crate) const fn totals(&self) -> Totals {
        Totals {
            in_msgs: self.in_msgs.get(),
            in_bytes: self.in_bytes.get(),
            out_msgs: self.out_msgs.get(),
            out_bytes: self.out_bytes.get(),
        }
    }

    /// Hands the counts to other threads through `to`.
    pub(crate) fn publish(&self, to: &Shared) {
        let t = self.totals();
        // Relaxed: counters read now and then; no other data hangs on them.
        to.in_msgs.store(t.in_msgs, Ordering::Relaxed);
        to.in_bytes.store(t.in_bytes, Ordering::Relaxed);
        to.out_msgs.store(t.out_msgs, Ordering::Relaxed);
        to.out_bytes.store(t.out_bytes, Ordering::Relaxed);
    }
}

/// The counts of one lane, for other threads to read.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    in_msgs: AtomicU64,
    in_bytes: AtomicU64,
    out_msgs: AtomicU64,
    out_bytes: AtomicU64,
}

impl Shared {
    pub(crate) fn load(&self) -> Totals {
        // Relaxed: see `Tally::publish`.
        Totals {
            in_msgs: self.in_msgs.load(Ordering::Relaxed),
            in_bytes: self.in_bytes.load(Ordering::Relaxed),
            out_msgs: self.out_msgs.load(Ordering::Relaxed),
            out_bytes: self.out_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Events across the server, rare enough for atomics.
#[derive(Debug, Default)]
pub(crate) struct Events {
    pub(crate) slow_consumers: AtomicU64,
    pub(crate) stale: AtomicU64,
}

impl Events {
    /// Counts one more.
    pub(crate) fn note(counter: &AtomicU64) {
        // Relaxed: a counter, read now and then.
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_reach_other_threads_when_published() {
        let t = Tally::default();
        let s = Shared::default();
        t.took(10);
        t.took(5);
        t.gave(7);
        assert_eq!(s.load(), Totals::default());
        t.publish(&s);
        let want = Totals {
            in_msgs: 2,
            in_bytes: 15,
            out_msgs: 1,
            out_bytes: 7,
        };
        assert_eq!(s.load(), want);
        let mut sum = want;
        sum += want;
        assert_eq!(sum.in_bytes, 30);
    }
}
