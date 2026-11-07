//! Work for a lane from other lanes.
//!
//! Senders queue under a lock and wake the lane through a [`DataSignal`]
//! only when the queue was empty, so a burst costs one wake, and the lane
//! takes the whole queue at once. Senders to a full mailbox wait for room
//! through a [`StateSignal`], which slows them down instead of dropping.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use zzq_tokio::signal::{DataSignal, StateSignal};

/// Keeps a value on cache lines of its own. x86 fetches lines in pairs.
#[repr(align(128))]
#[derive(Debug)]
struct Line<T>(T);

#[derive(Debug)]
struct Shared<T> {
    state: Line<Mutex<State<T>>>,
    /// For the lane: items queued, or the mailbox closed.
    ready: Line<DataSignal>,
    /// For waiting senders: the lane took a full queue, or it closed.
    room: StateSignal,
    cap: usize,
}

#[derive(Debug)]
struct State<T> {
    items: Vec<T>,
    /// A sender waits for room.
    full: bool,
    closed: bool,
}

impl<T> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `item` and wakes the lane if the queue was empty.
    fn put(&self, mut st: MutexGuard<'_, State<T>>, item: T) {
        let wake = st.items.is_empty();
        st.items.push(item);
        drop(st);
        // The lock orders pushes and takes, so only the push into an empty
        // queue needs to wake the lane.
        if wake {
            self.ready.0.mark();
        }
    }
}

/// A mailbox whose [`Mailbox::send`] waits while `cap` items are queued.
pub(crate) fn mailbox<T>(cap: usize) -> (Mailbox<T>, Receiver<T>) {
    let shared = Arc::new(Shared {
        state: Line(Mutex::new(State {
            items: Vec::new(),
            full: false,
            closed: false,
        })),
        ready: Line(DataSignal::new()),
        room: StateSignal::new(),
        cap: cap.max(1),
    });
    (
        Mailbox {
            shared: shared.clone(),
        },
        Receiver { shared },
    )
}

/// The sending side, for any lane.
#[derive(Debug)]
pub(crate) struct Mailbox<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Mailbox<T> {
    /// Queues `item` without waiting, beyond the cap too. Drops it once the
    /// mailbox is closed.
    pub(crate) fn push(&self, item: T) {
        let st = self.shared.lock();
        if !st.closed {
            self.shared.put(st, item);
        }
    }

    /// Queues `item` unless the mailbox is full or closed: whether it did.
    pub(crate) fn offer(&self, item: T) -> bool {
        let st = self.shared.lock();
        if st.closed || st.items.len() >= self.shared.cap {
            return false;
        }
        self.shared.put(st, item);
        true
    }

    /// Whether nothing is queued.
    pub(crate) fn is_empty(&self) -> bool {
        self.shared.lock().items.is_empty()
    }

    /// Queues `item`, waiting while the mailbox is full. Drops it once the
    /// mailbox is closed.
    pub(crate) async fn send(&self, item: T) {
        let mut item = Some(item);
        self.shared
            .room
            .until(|| {
                let mut st = self.shared.lock();
                if st.closed {
                    return Some(());
                }
                if st.items.len() < self.shared.cap {
                    self.shared.put(st, item.take()?);
                    return Some(());
                }
                st.full = true;
                None
            })
            .await;
    }
}

/// The lane's side. Dropping it closes the mailbox and drops what is
/// queued.
#[derive(Debug)]
pub(crate) struct Receiver<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Receiver<T> {
    /// Moves everything queued into `out`, which should be empty, waiting
    /// until there is something. False once the mailbox is closed.
    pub(crate) async fn recv_all(&self, out: &mut Vec<T>) -> bool {
        loop {
            let (full, closed) = {
                let mut st = self.shared.lock();
                // Swapping hands the emptied vector back for reuse.
                std::mem::swap(&mut st.items, out);
                (std::mem::take(&mut st.full), st.closed)
            };
            if full {
                self.shared.room.notify_changed();
            }
            if !out.is_empty() {
                return true;
            }
            if closed {
                return false;
            }
            self.shared.ready.0.ready().await;
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let left = {
            let mut st = self.shared.lock();
            st.closed = true;
            std::mem::take(&mut st.items)
        };
        drop(left);
        self.shared.ready.0.mark();
        self.shared.room.notify_changed();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn the_lane_takes_a_burst_at_once_and_senders_wait_for_room() {
        let (tx, rx) = mailbox::<u32>(2);
        let tx = Arc::new(tx);
        tx.send(0).await;
        tx.send(1).await;
        let t = tx.clone();
        let waiting = tokio::spawn(async move { t.send(2).await });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "full");
        tx.push(3);

        let mut got = Vec::new();
        assert!(rx.recv_all(&mut got).await);
        assert_eq!(got, [0, 1, 3]);
        let sent = tokio::time::timeout(Duration::from_secs(1), waiting).await;
        assert!(matches!(sent, Ok(Ok(()))), "room wakes the sender");
        got.clear();
        assert!(rx.recv_all(&mut got).await);
        assert_eq!(got, [2]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_dropped_lane_side_drops_what_is_queued_and_frees_senders() {
        let (tx, rx) = mailbox::<Arc<()>>(1);
        let item = Arc::new(());
        tx.push(item.clone());
        let tx = Arc::new(tx);
        let t = tx.clone();
        let i = item.clone();
        let waiting = tokio::spawn(async move { t.send(i).await });
        tokio::task::yield_now().await;
        drop(rx);
        let sent = tokio::time::timeout(Duration::from_secs(1), waiting).await;
        assert!(matches!(sent, Ok(Ok(()))), "closing frees the sender");
        tx.push(item.clone());
        assert_eq!(Arc::strong_count(&item), 1, "nothing kept");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_offer_to_a_full_or_closed_mailbox_is_dropped() {
        let (tx, rx) = mailbox::<u32>(2);
        assert!(tx.offer(1) && tx.offer(2));
        assert!(!tx.offer(3), "full");
        let mut got = Vec::new();
        assert!(rx.recv_all(&mut got).await);
        assert_eq!(got, [1, 2]);
        assert!(tx.offer(4), "room again");
        drop(rx);
        assert!(!tx.offer(5), "closed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_lane_waits_until_something_is_queued() {
        let (tx, rx) = mailbox::<u32>(4);
        let mut got = Vec::new();
        let early = tokio::time::timeout(Duration::from_millis(20), rx.recv_all(&mut got)).await;
        assert!(early.is_err(), "nothing queued");
        tx.push(7);
        assert!(rx.recv_all(&mut got).await);
        assert_eq!(got, [7]);
    }
}
