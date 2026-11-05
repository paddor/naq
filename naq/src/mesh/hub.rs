//! naq leafs that dial this server as their hub, over OMQ. Each gets a
//! slot and a sender of its own, hears of all interest but its own and its
//! cluster's, and tells of its own.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use naq_proto::peer::{self, Control, Hello, Role};
use omq_tokio::{IdentitySocket, MonitorEvent, MonitorStream, Socket};
use tokio::time::Instant;

use super::interest::{Change, Heard};
use super::tell::{self, BEAT, Item, Other, Sink};
use super::told::Told;
use super::view::{self, ForLeaf};
use super::{Mesh, resync};
use crate::lane::{Control as LaneControl, Lane, SLOTS};
use crate::server::Shared;

/// How long a leaf may stay silent before it is let go: past a few beats.
const SILENT: Duration = Duration::from_secs(5);

/// Identities of leafs gone, at most, whose late `Hello` is refused.
const DEAD: usize = 64;

/// A naq leaf linked here.
#[derive(Debug)]
pub(crate) struct Leaf {
    pub(crate) slot: u16,
    /// The routing identity of its control connection: its server ID, its
    /// remote, and a count of its connections.
    id: Bytes,
    pub(crate) name: String,
    pub(crate) cluster: Rc<[u8]>,
    pub(crate) account: u32,
    /// Its interest, as applied.
    pub(crate) heard: Heard,
    /// What it is told.
    pub(crate) told: Rc<Told>,
    other: Rc<Other>,
    /// Its ID in `/leafz`.
    pub(crate) link: u64,
    /// When it last sent anything.
    heard_at: Instant,
}

/// What this server, as hub, tells its leafs of itself.
#[derive(Debug)]
pub(super) struct Me {
    /// The account every leaf binds.
    account: u32,
    epoch: u64,
    /// The data endpoints of its lanes, separated by blanks.
    data: String,
    /// Where naq leafs dial it, as bound.
    url: String,
}

impl Me {
    /// What `shared`'s server of start `epoch` tells its leafs, whose lanes
    /// take the data of leafs at `data`, and which leafs dial at
    /// `leafnodes`.
    pub(super) fn new(
        shared: &Shared,
        data: &[String],
        epoch: u64,
        leafnodes: Option<SocketAddr>,
    ) -> Me {
        Me {
            account: super::leafnodes_account(shared),
            epoch,
            data: data.join(" "),
            url: leafnodes.map(|a| a.to_string()).unwrap_or_default(),
        }
    }

    /// The hub `Hello` of `shared`'s server, naming where leafs dial it and
    /// the servers of `mesh` that are up.
    fn hello(&self, shared: &Shared, mesh: &Mesh) -> Bytes {
        let cluster = shared.opts.cluster.as_ref().map_or("", |c| &c.name);
        let mut urls = self.url.clone();
        for u in mesh
            .peers
            .borrow()
            .iter()
            .filter(|p| p.up)
            .flat_map(|p| &p.leaf_urls)
        {
            urls.push(' ');
            urls.push_str(u);
        }
        let mut hello = Vec::new();
        Control::Hello(Hello {
            role: Role::Hub,
            account: shared.accounts[self.account as usize].as_bytes(),
            epoch: self.epoch,
            server_id: shared.server_id.as_bytes(),
            name: shared.opts.server_name.as_bytes(),
            cluster: cluster.as_bytes(),
            data: self.data.as_bytes(),
            client_urls: b"",
            leaf_urls: urls.as_bytes(),
        })
        .encode(&mut hello);
        hello.into()
    }
}

/// Serves the naq leafs that dial `router`, whose monitor is `events`, from
/// `lane`, lane 0, of `mesh`: links each that says `Hello`, tells it of
/// interest and takes its own, and lets it go when its connection is gone
/// or it falls silent.
pub(super) async fn serve(
    lane: Rc<Lane>,
    mesh: Rc<Mesh>,
    (router, mut events): (Socket, MonitorStream),
    me: Me,
) {
    let Ok(ids) = router.identity_routing() else {
        return;
    };
    let mut hub = Guard(Hub {
        shared: lane.shared.clone(),
        lane,
        mesh,
        ids,
        me,
        dead: VecDeque::new(),
    });
    let mut beat = tokio::time::interval(BEAT);
    loop {
        // Cancel-safe: a dropped receive takes no message or event, a
        // dropped `notified` keeps its permit, and the interval keeps its
        // deadline.
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(MonitorEvent::Disconnected { peer, .. }) => {
                    if let Some(id) = peer.peer_identity {
                        hub.0.gone(&id);
                    }
                }
                Err(omq_tokio::MonitorRecvError::Closed) => return,
                _ => {}
            },
            got = hub.0.ids.recv_from() => {
                let Ok((who, msg)) = got else { return };
                if let Ok(bytes) = msg.into_bytes() {
                    hub.0.take(who.to_bytes(), &bytes);
                }
            }
            () = hub.0.mesh.leaf_wake.notified() => {
                for l in hub.0.mesh.leafs.borrow().iter() {
                    l.other.tell(false);
                }
            }
            _ = beat.tick() => hub.0.beat(),
        }
    }
}

/// Lets every leaf go when dropped: the hub stops.
struct Guard(Hub);

impl Drop for Guard {
    fn drop(&mut self) {
        let all: Vec<Bytes> = self
            .0
            .mesh
            .leafs
            .borrow()
            .iter()
            .map(|l| l.id.clone())
            .collect();
        for id in all {
            self.0.unlink(&id);
        }
    }
}

/// The hub side of lane 0.
struct Hub {
    shared: Arc<Shared>,
    lane: Rc<Lane>,
    mesh: Rc<Mesh>,
    ids: IdentitySocket,
    me: Me,
    /// Identities of leafs gone, newest last.
    dead: VecDeque<Bytes>,
}

impl Hub {
    /// Acts on message `msg` of the leaf of routing identity `who`.
    fn take(&mut self, who: Bytes, msg: &[u8]) {
        let Ok(c) = peer::decode(msg) else {
            return;
        };
        if let Control::Hello(h) = &c {
            if h.role == Role::Leaf && !self.dead.contains(&who) {
                self.hello(who, h);
            }
            return;
        }
        let mut leafs = self.mesh.leafs.borrow_mut();
        let Some(l) = leafs.iter_mut().find(|l| l.id == who) else {
            return;
        };
        l.heard_at = Instant::now();
        if c == Control::Resync {
            l.other.push(Item::Snapshot);
            return;
        }
        let (slot, account) = (l.slot, l.account);
        let shared = &self.shared;
        if l.heard
            .take(&c, &mut |ch| interest(shared, slot, account, ch))
        {
            l.other.push(Item::Msg(resync()));
        }
    }

    /// Links the leaf of routing identity `who`, which said `Hello` `h`:
    /// in place of an older link of the same remote, and once.
    fn hello(&mut self, who: Bytes, h: &Hello<'_>) {
        let remote = remote_of(&who);
        let older: Vec<Bytes> = self
            .mesh
            .leafs
            .borrow()
            .iter()
            .filter(|l| l.id != who && remote_of(&l.id) == remote)
            .map(|l| l.id.clone())
            .collect();
        for id in older {
            self.unlink(&id);
        }
        if let Some(l) = self
            .mesh
            .leafs
            .borrow_mut()
            .iter_mut()
            .find(|l| l.id == who)
        {
            l.heard.take(&Control::Hello(*h), &mut |_| {});
            l.other.greet(Some(self.me.hello(&self.shared, &self.mesh)));
            return;
        }
        let first = self.lane.slots.first_leaf();
        let slot = {
            let leafs = self.mesh.leafs.borrow();
            (first..SLOTS as u16).find(|s| !leafs.iter().any(|l| l.slot == *s))
        };
        let Some(slot) = slot else {
            return;
        };
        self.link(slot, who, h);
    }

    /// Puts the leaf of routing identity `who`, which said `h`, in slot
    /// `slot`, and starts telling it.
    fn link(&self, slot: u16, who: Bytes, h: &Hello<'_>) {
        let account = self.me.account;
        for tx in &*self.shared.lanes {
            tx.control(LaneControl::Link {
                slot,
                id: who.to_vec().into(),
                cluster: h.cluster.into(),
                account,
            });
        }
        let told = Rc::new(Told::new(
            self.mesh.epoch,
            self.shared.accounts.clone(),
            self.mesh.leaf_wake.clone(),
        ));
        let cluster: Rc<[u8]> = h.cluster.into();
        self.fill(&told, slot, &cluster);
        let other = Rc::new(Other::new(
            Sink::Router(self.ids.clone(), who.clone()),
            told.clone(),
        ));
        other.greet(Some(self.me.hello(&self.shared, &self.mesh)));
        tokio::task::spawn_local(tell::send(other.clone(), || {}));
        let mut heard = Heard::default();
        heard.take(&Control::Hello(*h), &mut |_| {});
        self.mesh.leafs.borrow_mut().push(Leaf {
            slot,
            id: who,
            name: String::from_utf8_lossy(h.name).into_owned(),
            cluster,
            account,
            heard,
            told,
            other,
            link: self.shared.next_client(),
            heard_at: Instant::now(),
        });
    }

    /// Fills `told` with what the leaf in slot `slot`, of cluster
    /// `cluster`, hears of now. Its snapshot carries it: no delta goes.
    fn fill(&self, told: &Told, slot: u16, cluster: &[u8]) {
        let account = self.me.account;
        let index = self.lane.index(account).borrow();
        let routes = self.mesh.peers.borrow();
        let leaf = ForLeaf {
            slot,
            cluster,
            account: self.shared.accounts[account as usize].as_bytes(),
            routes: &routes,
        };
        let slots = &self.lane.slots;
        index.each(|filter, i| {
            told.set(
                account,
                filter,
                None,
                view::leaf(&index, slots, leaf, filter, None),
            );
            for (q, _) in &i.queues {
                let v = view::leaf(&index, slots, leaf, filter, Some(q));
                told.set(account, filter, Some(q), v);
            }
        });
        told.take();
    }

    /// Lets the leaf of routing identity `id` go, if it is linked; else
    /// keeps its `Hello`, if one comes late, from linking it.
    fn gone(&mut self, id: &Bytes) {
        if !self.unlink(id) {
            if self.dead.len() >= DEAD {
                self.dead.pop_front();
            }
            self.dead.push_back(id.clone());
        }
    }

    /// Lets the leaf of routing identity `id` go: its interest, its slot
    /// and its sender. Returns whether it was linked.
    fn unlink(&self, id: &[u8]) -> bool {
        let leaf = {
            let mut leafs = self.mesh.leafs.borrow_mut();
            let Some(at) = leafs.iter().position(|l| *l.id == *id) else {
                return false;
            };
            leafs.swap_remove(at)
        };
        let Leaf {
            slot,
            account,
            mut heard,
            other,
            ..
        } = leaf;
        other.close();
        let shared = &self.shared;
        heard.forget(&mut |ch| interest(shared, slot, account, ch));
        for tx in &*shared.lanes {
            tx.control(LaneControl::Unlink { slot });
        }
        true
    }

    /// Beats to every leaf; lets those go that fell silent.
    fn beat(&self) {
        let now = Instant::now();
        let silent: Vec<Bytes> = self
            .mesh
            .leafs
            .borrow()
            .iter()
            .filter(|l| {
                l.other.tell(true);
                now.duration_since(l.heard_at) > SILENT
            })
            .map(|l| l.id.clone())
            .collect();
        for id in silent {
            self.unlink(&id);
        }
    }
}

/// Sets the interest of the leaf in slot `slot`, bound to `account`, on
/// every lane, as change `c` says. Its account name is the leaf's.
fn interest(shared: &Shared, slot: u16, account: u32, (_, subject, queue, weight): Change<'_>) {
    for tx in &*shared.lanes {
        tx.control(LaneControl::Server {
            account,
            subject: subject.into(),
            queue: queue.map(Into::into),
            server: slot,
            weight,
        });
    }
}

/// The remote of a leaf's routing identity: its server ID and remote,
/// before the count of its connections.
fn remote_of(id: &[u8]) -> &[u8] {
    id.iter()
        .rposition(|&b| b == b'/')
        .map_or(id, |at| &id[..at])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_of_one_remote_share_the_start_of_their_identity() {
        assert_eq!(remote_of(b"NID/0/3"), b"NID/0");
        assert_eq!(remote_of(b"x"), b"x");
    }
}
