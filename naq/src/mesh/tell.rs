//! Telling the servers that dial this one of its interest: a sender for
//! each, so one that falls behind holds up no other.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use naq_proto::peer::{self, Control};
use omq_tokio::{IdentitySocket, Message, Socket};
use tokio::sync::Notify;

use super::Mesh;

/// How often the deltas sent so far are told.
const BEAT: Duration = Duration::from_secs(1);

/// Servers told at once, at most: as many as there may be routes.
const OTHERS: usize = 64;

/// Messages waiting for one server, at most. Past it, they are dropped
/// and a snapshot goes next.
const QUEUE: usize = 1 << 16;

/// What waits to be sent to a server.
#[derive(Debug)]
enum Item {
    Msg(Bytes),
    /// All of this server's interest, as of when it is sent.
    Snapshot,
}

/// A server that dialed this one, and what waits to be sent to it.
#[derive(Debug)]
struct Other {
    /// Its routing identity.
    id: Bytes,
    queue: RefCell<VecDeque<Item>>,
    /// Counts its `Hello`s.
    greeted: Cell<u64>,
    /// Set when this server stops telling.
    closed: Cell<bool>,
    wake: Notify,
}

impl Other {
    fn new(id: Bytes) -> Other {
        Other {
            id,
            queue: RefCell::default(),
            greeted: Cell::new(0),
            closed: Cell::new(false),
            wake: Notify::new(),
        }
    }

    /// Queues `item`. One too many drops all queued: a snapshot goes
    /// next instead.
    fn push(&self, item: Item) {
        let mut q = self.queue.borrow_mut();
        if q.len() < QUEUE {
            q.push_back(item);
        } else {
            q.clear();
            q.push_back(Item::Snapshot);
        }
        drop(q);
        self.wake.notify_one();
    }

    /// Starts over for a `Hello` from it: `hello` back, then a snapshot.
    fn greet(&self, hello: Bytes) {
        self.greeted.set(self.greeted.get() + 1);
        {
            let mut q = self.queue.borrow_mut();
            q.clear();
            q.extend([Item::Msg(hello), Item::Snapshot]);
        }
        self.wake.notify_one();
    }
}

/// The servers being told.
type Others = Rc<RefCell<Vec<Rc<Other>>>>;

/// Stops the senders of the servers being told when dropped.
struct Close(Others);

impl Drop for Close {
    fn drop(&mut self) {
        for o in self.0.borrow().iter() {
            o.closed.set(true);
            o.wake.notify_one();
        }
    }
}

/// Answers each server that dials `router` and says `Hello` of cluster
/// `cluster`: with `hello` and a snapshot of this server's interest, then
/// its deltas and beats.
pub(super) async fn answer(router: Socket, cluster: &str, hello: &Bytes, mesh: &Rc<Mesh>) {
    let Ok(ids) = router.identity_routing() else {
        return;
    };
    let others = Close(Rc::default());
    let mut beat = tokio::time::interval(BEAT);
    loop {
        // Cancel-safe: a dropped receive takes no message, a dropped
        // `notified` keeps its permit, and the interval keeps its deadline.
        tokio::select! {
            got = ids.recv_from() => {
                let Ok((who, msg)) = got else { return };
                let Ok(bytes) = msg.into_bytes() else { continue };
                let who = who.to_bytes();
                match peer::decode(&bytes) {
                    Ok(Control::Hello(h)) if h.cluster == cluster.as_bytes() => {
                        if let Some(o) = other(&ids, &others.0, who, mesh) {
                            o.greet(hello.clone());
                        }
                    }
                    Ok(Control::Resync) => {
                        if let Some(o) = others.0.borrow().iter().find(|o| o.id == who) {
                            o.push(Item::Snapshot);
                        }
                    }
                    _ => {}
                }
            }
            () = mesh.told.wake.notified() => {
                let deltas = mesh.told.take();
                for o in others.0.borrow().iter() {
                    for d in &deltas {
                        o.push(Item::Msg(d.clone()));
                    }
                }
            }
            _ = beat.tick() => {
                let b = mesh.told.beat();
                for o in others.0.borrow().iter() {
                    o.push(Item::Msg(b.clone()));
                }
            }
        }
    }
}

/// The server of routing identity `who` among `others`, with a sender
/// of its own; `None` if there are as many as can be.
fn other(ids: &IdentitySocket, others: &Others, who: Bytes, mesh: &Rc<Mesh>) -> Option<Rc<Other>> {
    if let Some(o) = others.borrow().iter().find(|o| o.id == who) {
        return Some(o.clone());
    }
    if others.borrow().len() >= OTHERS {
        return None;
    }
    let o = Rc::new(Other::new(who));
    others.borrow_mut().push(o.clone());
    tokio::task::spawn_local(send(ids.clone(), o.clone(), mesh.clone(), others.clone()));
    Some(o)
}

/// Sends `other` what waits for it, in order. Ends when this server stops
/// telling, or when a send finds `other` gone and it said no `Hello`
/// since: then it leaves `others`.
async fn send(ids: IdentitySocket, other: Rc<Other>, mesh: Rc<Mesh>, others: Others) {
    while !other.closed.get() {
        let greeted = other.greeted.get();
        let item = other.queue.borrow_mut().pop_front();
        let sent = match item {
            None => {
                other.wake.notified().await;
                continue;
            }
            Some(Item::Msg(m)) => ids.send_to(&other.id, Message::single(m)).await,
            Some(Item::Snapshot) => snapshot(&ids, &other.id, &mesh).await,
        };
        if sent.is_err() && other.greeted.get() == greeted {
            others.borrow_mut().retain(|o| !Rc::ptr_eq(o, &other));
            return;
        }
    }
}

/// Sends `who` a snapshot of this server's interest.
async fn snapshot(ids: &IdentitySocket, who: &Bytes, mesh: &Mesh) -> omq_tokio::Result<()> {
    for part in mesh.told.snapshot() {
        ids.send_to(who, Message::single(part)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(o: &Other) -> Vec<&'static str> {
        o.queue
            .borrow()
            .iter()
            .map(|i| match i {
                Item::Msg(_) => "msg",
                Item::Snapshot => "snapshot",
            })
            .collect()
    }

    #[test]
    fn a_server_too_far_behind_gets_a_snapshot_instead() {
        let o = Other::new(Bytes::new());
        for _ in 0..QUEUE {
            o.push(Item::Msg(Bytes::new()));
        }
        assert_eq!(o.queue.borrow().len(), QUEUE);
        o.push(Item::Msg(Bytes::new()));
        assert_eq!(kinds(&o), ["snapshot"]);
        o.push(Item::Msg(Bytes::new()));
        assert_eq!(kinds(&o), ["snapshot", "msg"]);
    }

    #[test]
    fn a_hello_starts_a_server_over() {
        let o = Other::new(Bytes::new());
        o.push(Item::Msg(Bytes::new()));
        o.greet(Bytes::from_static(b"hello"));
        assert_eq!(kinds(&o), ["msg", "snapshot"]);
        assert_eq!(o.greeted.get(), 1);
    }
}
