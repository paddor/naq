//! Telling other servers of this one's interest: a sender for each, so
//! one that falls behind holds up no other.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use naq_proto::peer::{self, Control, Role};
use omq_tokio::{IdentitySocket, Message, Socket};
use tokio::sync::Notify;

use super::Mesh;
use super::told::Told;

/// How often the deltas sent so far are told.
pub(super) const BEAT: Duration = Duration::from_secs(1);

/// Servers told at once, at most: as many as there may be routes.
const OTHERS: usize = 64;

/// Messages waiting for one server, at most. Past it, they are dropped
/// and a snapshot goes next.
const QUEUE: usize = 1 << 16;

/// What waits to be sent to a server.
#[derive(Debug)]
pub(super) enum Item {
    Msg(Bytes),
    /// All of this server's interest, as of when it is sent.
    Snapshot,
}

/// Where a server is told.
#[derive(Debug, Clone)]
pub(super) enum Sink {
    /// A ROUTER, to the routing identity of the server.
    Router(IdentitySocket, Bytes),
    /// A DEALER, to the one server it dialed.
    Dealer(Socket),
}

impl Sink {
    async fn send(&self, m: Bytes) -> omq_tokio::Result<()> {
        match self {
            Sink::Router(ids, to) => ids.send_to(to, Message::single(m)).await,
            Sink::Dealer(s) => s.send(Message::single(m)).await,
        }
    }
}

/// A server told of this one's interest, and what waits to be sent to it.
#[derive(Debug)]
pub(super) struct Other {
    sink: Sink,
    /// What it is told, and its snapshots come from.
    told: Rc<Told>,
    queue: RefCell<VecDeque<Item>>,
    /// Counts its `Hello`s.
    greeted: Cell<u64>,
    /// Set when this server stops telling it.
    closed: Cell<bool>,
    wake: Notify,
}

impl Other {
    pub(super) fn new(sink: Sink, told: Rc<Told>) -> Other {
        Other {
            sink,
            told,
            queue: RefCell::default(),
            greeted: Cell::new(0),
            closed: Cell::new(false),
            wake: Notify::new(),
        }
    }

    /// Queues `item`. One too many drops all queued: a snapshot goes
    /// next instead.
    pub(super) fn push(&self, item: Item) {
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

    /// Starts over for a `Hello` from it: `hello` back if given, then a
    /// snapshot.
    pub(super) fn greet(&self, hello: Option<Bytes>) {
        self.greeted.set(self.greeted.get() + 1);
        {
            let mut q = self.queue.borrow_mut();
            q.clear();
            q.extend(hello.map(Item::Msg));
            q.push_back(Item::Snapshot);
        }
        self.wake.notify_one();
    }

    /// Queues the deltas of what it is told, then a beat if `beat`.
    pub(super) fn tell(&self, beat: bool) {
        for d in self.told.take() {
            self.push(Item::Msg(d));
        }
        if beat {
            self.push(Item::Msg(self.told.beat()));
        }
    }

    /// Stops its sender.
    pub(super) fn close(&self) {
        self.closed.set(true);
        self.wake.notify_one();
    }

    /// Whether it is told at routing identity `who`.
    fn is(&self, who: &[u8]) -> bool {
        matches!(&self.sink, Sink::Router(_, to) if **to == *who)
    }
}

/// The servers being told.
type Others = Rc<RefCell<Vec<Rc<Other>>>>;

/// Stops the senders of the servers being told when dropped.
struct Close(Others);

impl Drop for Close {
    fn drop(&mut self) {
        for o in self.0.borrow().iter() {
            o.close();
        }
    }
}

/// Answers each server that dials `router` and says `Hello` of cluster
/// `cluster`: with the first of `hellos` and a snapshot of this server's
/// interest, then its deltas and beats. Once this server is in lame duck
/// mode, every server hears the second of `hellos`, and those that dial
/// later too.
pub(super) async fn answer(router: Socket, cluster: &str, hellos: &[Bytes; 2], mesh: &Rc<Mesh>) {
    let mut hello = &hellos[0];
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
                    Ok(Control::Hello(h)) if h.role == Role::Route && h.cluster == cluster.as_bytes() => {
                        if let Some(o) = other(&ids, &others.0, who, mesh) {
                            o.greet(Some(hello.clone()));
                        }
                    }
                    Ok(Control::Resync) => {
                        if let Some(o) = others.0.borrow().iter().find(|o| o.is(&who)) {
                            o.push(Item::Snapshot);
                        }
                    }
                    _ => {}
                }
            }
            () = mesh.lamed.notified() => {
                hello = &hellos[1];
                for o in others.0.borrow().iter() {
                    o.push(Item::Msg(hello.clone()));
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
    if let Some(o) = others.borrow().iter().find(|o| o.is(&who)) {
        return Some(o.clone());
    }
    if others.borrow().len() >= OTHERS {
        return None;
    }
    let o = Rc::new(Other::new(
        Sink::Router(ids.clone(), who),
        mesh.told.clone(),
    ));
    others.borrow_mut().push(o.clone());
    let (all, me) = (others.clone(), o.clone());
    tokio::task::spawn_local(send(o.clone(), move || {
        all.borrow_mut().retain(|o| !Rc::ptr_eq(o, &me));
    }));
    Some(o)
}

/// Sends `other` what waits for it, in order, until this server stops
/// telling it. A send that finds it gone, with no `Hello` since, ends it:
/// then `gone` runs.
pub(super) async fn send(other: Rc<Other>, gone: impl FnOnce()) {
    while !other.closed.get() {
        let greeted = other.greeted.get();
        let item = other.queue.borrow_mut().pop_front();
        let sent = match item {
            None => {
                other.wake.notified().await;
                continue;
            }
            Some(Item::Msg(m)) => other.sink.send(m).await,
            Some(Item::Snapshot) => snapshot(&other).await,
        };
        if sent.is_err() && other.greeted.get() == greeted {
            gone();
            return;
        }
    }
}

/// Sends `other` a snapshot of what it is told.
async fn snapshot(other: &Other) -> omq_tokio::Result<()> {
    for part in other.told.snapshot() {
        other.sink.send(part).await?;
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

    fn other() -> Other {
        let ctx = omq_tokio::Context::current();
        let s = ctx.socket(omq_tokio::SocketType::Dealer, omq_tokio::Options::default());
        let told = Told::new(
            1,
            std::sync::Arc::new(crate::accounts::Accounts::of(&[])),
            Rc::default(),
        );
        Other::new(Sink::Dealer(s), Rc::new(told))
    }

    #[tokio::test]
    async fn a_server_too_far_behind_gets_a_snapshot_instead() {
        let o = other();
        for _ in 0..QUEUE {
            o.push(Item::Msg(Bytes::new()));
        }
        assert_eq!(o.queue.borrow().len(), QUEUE);
        o.push(Item::Msg(Bytes::new()));
        assert_eq!(kinds(&o), ["snapshot"]);
        o.push(Item::Msg(Bytes::new()));
        assert_eq!(kinds(&o), ["snapshot", "msg"]);
    }

    #[tokio::test]
    async fn a_hello_starts_a_server_over() {
        let o = other();
        o.push(Item::Msg(Bytes::new()));
        o.greet(Some(Bytes::from_static(b"hello")));
        assert_eq!(kinds(&o), ["msg", "snapshot"]);
        assert_eq!(o.greeted.get(), 1);
        o.greet(None);
        assert_eq!(kinds(&o), ["snapshot"]);
        o.told.set(0, b"a", None, vec![(None, 1)]);
        o.tell(true);
        assert_eq!(kinds(&o), ["snapshot", "msg", "msg"], "a delta and a beat");
    }
}
