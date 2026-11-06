//! naq leafs that dial this server as their hub, over OMQ. Each that logs
//! in gets a slot and a sender of its own, hears of all interest but its
//! own and its cluster's, and tells of its own.

mod login;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use naq_proto::peer::{self, Control, Hello, Role};

use login::{Greeted, Logins, Outcome};
use omq_tokio::{IdentitySocket, Message, MonitorEvent, MonitorStream, Socket};
use tokio::time::Instant;

use super::interest::{Change, Heard};
use super::tell::{self, BEAT, Item, Other, Sink};
use super::told::Told;
use super::view::{self, ForLeaf};
use super::{Mesh, error, resync};
use crate::auth::Grant;
use crate::lane::{Control as LaneControl, Lane, SLOTS};
use crate::leaf::loop_error;
use crate::perms::LinkPerms;
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
    pub(crate) carries: Carries,
}

/// What the link of a leaf carries.
#[derive(Debug, Default)]
pub(crate) struct Carries {
    /// What goes to it and comes from it, if not all.
    pub(crate) perms: Option<Arc<LinkPerms>>,
    /// It hears of no interest of other leafs and hubs.
    pub(crate) isolated: bool,
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
    /// the servers of `mesh` that are up, with `nonce` for a leaf to sign.
    fn hello(&self, shared: &Shared, mesh: &Mesh, nonce: &str) -> Bytes {
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
            account: shared.accounts.name(self.account).as_bytes(),
            epoch: self.epoch,
            server_id: shared.server_id.as_bytes(),
            name: shared.opts.server_name.as_bytes(),
            cluster: cluster.as_bytes(),
            data: self.data.as_bytes(),
            client_urls: b"",
            leaf_urls: urls.as_bytes(),
            nonce: nonce.as_bytes(),
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
        logins: Logins::new(&lane.shared, me.account),
        shared: lane.shared.clone(),
        lane,
        mesh,
        ids,
        me,
        dead: VecDeque::new(),
    });
    let mut beat = tokio::time::interval(BEAT);
    loop {
        // Cancel-safe: a dropped receive takes no message, event or
        // outcome, a dropped `notified` keeps its permit, and the interval
        // keeps its deadline.
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
            o = hub.0.logins.next() => hub.0.outcome(o),
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
    logins: Logins,
}

impl Hub {
    /// Acts on message `msg` of the leaf of routing identity `who`.
    fn take(&mut self, who: Bytes, msg: &[u8]) {
        let Ok(c) = peer::decode(msg) else {
            return;
        };
        match &c {
            Control::Hello(h) => {
                if h.role == Role::Leaf && !self.dead.contains(&who) {
                    self.hello(who, h);
                }
                return;
            }
            Control::Connect(cn) => {
                let o = self.logins.connect(&who, cn);
                self.outcome(o);
                return;
            }
            _ => {}
        }
        let mut leafs = self.mesh.leafs.borrow_mut();
        let Some(l) = leafs.iter_mut().find(|l| l.id == who) else {
            return;
        };
        l.heard_at = Instant::now();
        match c {
            Control::Resync => {
                l.other.push(Item::Snapshot);
                return;
            }
            // The leaf lets the link go.
            Control::Error(_) => {
                drop(leafs);
                self.unlink(&who);
                return;
            }
            _ => {}
        }
        let (slot, account) = (l.slot, l.account);
        let perms = l.carries.perms.as_deref();
        let shared = &self.shared;
        let lds = shared.accounts.lds(account);
        let mut looped = false;
        let lost = l.heard.take(&c, &mut |ch| {
            looped |= ch.1 == lds && ch.3 > 0;
            interest(shared, slot, account, perms, ch);
        });
        if lost {
            l.other.push(Item::Msg(resync()));
        }
        drop(leafs);
        if looped {
            // Our own subject came back: the links loop. The leaf waits
            // before it dials again.
            let why = error(&loop_error(shared.accounts.name(account)));
            self.unlink(&who);
            let ids = self.ids.clone();
            tokio::task::spawn_local(async move {
                let _ = ids.send_to(&who, Message::single(why)).await;
            });
        }
    }

    /// Greets the leaf of routing identity `who`, which said `Hello` `h`,
    /// with a nonce to log in with. One linked starts over.
    fn hello(&mut self, who: Bytes, h: &Hello<'_>) {
        self.unlink(&who);
        let nonce = self.logins.greet(who.clone(), h);
        let hello = self.me.hello(&self.shared, &self.mesh, &nonce);
        self.send(who, hello);
    }

    /// Acts on what came of a login.
    fn outcome(&mut self, o: Outcome) {
        match o {
            Outcome::Pass(g, grant) => self.admit(g, &grant),
            Outcome::Fail(who) => self.send(who, error("Authorization Violation")),
            Outcome::Later | Outcome::Unknown => {}
        }
    }

    /// Links leaf `g`, which logged in with `grant`: in place of an older
    /// link of the same remote, in a free slot.
    fn admit(&mut self, g: Greeted, grant: &Grant) {
        let remote = remote_of(&g.who);
        let older: Vec<Bytes> = self
            .mesh
            .leafs
            .borrow()
            .iter()
            .filter(|l| remote_of(&l.id) == remote)
            .map(|l| l.id.clone())
            .collect();
        for id in older {
            self.unlink(&id);
        }
        let first = self.lane.slots.first_leaf();
        let slot = {
            let leafs = self.mesh.leafs.borrow();
            (first..SLOTS as u16).find(|s| !leafs.iter().any(|l| l.slot == *s))
        };
        let Some(slot) = slot else {
            return;
        };
        let carries = Carries {
            perms: LinkPerms::of_leaf(grant.perms.as_deref(), &g.deny).map(Arc::new),
            isolated: g.isolate,
        };
        self.link(slot, g, grant.account, carries);
    }

    /// Sends `m` to the leaf of routing identity `who`, linked or not.
    fn send(&self, who: Bytes, m: Bytes) {
        let ids = self.ids.clone();
        tokio::task::spawn_local(async move {
            let _ = ids.send_to(&who, Message::single(m)).await;
        });
    }

    /// Puts leaf `g`, bound to `account`, whose link carries `carries`, in
    /// slot `slot`, and starts telling it.
    fn link(&self, slot: u16, g: Greeted, account: u32, carries: Carries) {
        for tx in &*self.shared.lanes {
            tx.control(LaneControl::Link {
                slot,
                id: g.who.to_vec().into(),
                cluster: g.cluster.to_vec().into(),
                account,
                perms: carries.perms.clone(),
            });
        }
        let told = Rc::new(Told::new(
            self.mesh.epoch,
            self.shared.accounts.clone(),
            self.mesh.leaf_wake.clone(),
        ));
        {
            let routes = self.mesh.peers.borrow();
            let leaf = ForLeaf {
                slot,
                cluster: &g.cluster,
                account: self.shared.accounts.name(account).as_bytes(),
                routes: &routes,
                isolated: carries.isolated,
            };
            self.fill(&told, account, leaf, carries.perms.as_deref());
        }
        let other = Rc::new(Other::new(
            Sink::Router(self.ids.clone(), g.who.clone()),
            told.clone(),
        ));
        other.greet(None);
        tokio::task::spawn_local(tell::send(other.clone(), || {}));
        let link = self.shared.next_client();
        self.shared.log.info(format_args!(
            "lid:{link} - Leafnode connection created {}",
            g.name
        ));
        self.mesh.leafs.borrow_mut().push(Leaf {
            slot,
            id: g.who,
            name: g.name,
            cluster: g.cluster,
            account,
            heard: Heard::of(g.epoch),
            told,
            other,
            link,
            heard_at: Instant::now(),
            carries,
        });
    }

    /// Fills `told` with what `leaf`, bound to `account`, of permissions
    /// `perms` if any, hears of now. Its snapshot carries it: no delta
    /// goes.
    fn fill(&self, told: &Told, account: u32, leaf: ForLeaf<'_>, perms: Option<&LinkPerms>) {
        let index = self.lane.index(account).borrow();
        let slots = &self.lane.slots;
        index.each(|filter, i| {
            if perms.is_some_and(|p| !p.tells(filter)) {
                return;
            }
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
        told.pin(account, self.shared.accounts.lds(account));
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
            carries,
            link,
            name,
            ..
        } = leaf;
        self.shared.log.info(format_args!(
            "lid:{link} - Leafnode connection closed: Client Closed - Remote: {name}"
        ));
        other.close();
        let shared = &self.shared;
        let perms = carries.perms.as_deref();
        heard.forget(&mut |ch| interest(shared, slot, account, perms, ch));
        for tx in &*shared.lanes {
            tx.control(LaneControl::Unlink { slot });
        }
        true
    }

    /// Beats to every leaf; lets those go that fell silent, and those that
    /// did not log in in time.
    fn beat(&mut self) {
        let now = Instant::now();
        for who in self.logins.expire(now) {
            self.send(who, error("Authentication Timeout"));
        }
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

/// Sets the interest of the leaf in slot `slot`, bound to `account`, of
/// permissions `perms` if any, on every lane, as change `c` says: but in
/// this server's own loop detection subject, and in what the link may not
/// send to. Its account name is the leaf's.
fn interest(
    shared: &Shared,
    slot: u16,
    account: u32,
    perms: Option<&LinkPerms>,
    (_, subject, queue, weight, _): Change<'_>,
) {
    if subject == shared.accounts.lds(account) || perms.is_some_and(|p| !p.takes_interest(subject))
    {
        return;
    }
    for tx in &*shared.lanes {
        tx.control(LaneControl::Server {
            account,
            subject: subject.into(),
            queue: queue.map(Into::into),
            server: slot,
            weight: weight.into(),
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
