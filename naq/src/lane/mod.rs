//! A lane's state: its share of the server, on the lane's thread.
//!
//! Every lane holds the interest of the whole server. A subscription is
//! added on its own lane, then announced to the others through their
//! control mailboxes. A publish is matched on the publisher's lane, which
//! encodes it for its own subscribers and forwards it once, in a batch, to
//! each other lane with interest.

mod data;
mod peer;
mod publish;
mod route;
mod slots;

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use tokio::sync::oneshot;

pub(crate) use data::{Batch, Imported, Outs, Source};
pub(crate) use publish::{Routing, inject};
pub(crate) use route::{Queue, Queued};
#[cfg(test)]
pub(crate) use slots::Linked;
pub(crate) use slots::{SLOTS, Slots, bit};

use crate::accounts::CHUNK;
use crate::conn::{Client, SpentReads};
use crate::index::Index;
use crate::mailbox::{self, Mailbox, Receiver};
use crate::server::Shared;
use crate::stats::Tally;
use rustc_hash::FxHashMap;

/// Batches a lane may have queued for another before the sender waits.
const DATA_BATCHES: usize = 8;

thread_local! {
    /// Lane state by server and lane index: a process may run several
    /// servers, and a thread may run lanes of several.
    static LANES: RefCell<HashMap<(u64, usize), Rc<Lane>>> = RefCell::new(HashMap::new());
}

/// Changes for a lane from the others.
#[derive(Debug)]
pub(crate) enum Control {
    /// Lane `lane` gained or lost a subscription to `subject` of
    /// `account`, in `queue` if given.
    Interest {
        lane: usize,
        account: u32,
        subject: Box<[u8]>,
        queue: Option<Box<[u8]>>,
        add: bool,
    },
    /// Link `peer` gained, changed or lost interest in `subject` of
    /// `account`, in `queue` if given: lost with weight 0.
    Peer {
        account: u32,
        subject: Box<[u8]>,
        queue: Option<Box<[u8]>>,
        peer: crate::index::Peer,
    },
    /// Answered once the controls before it are applied.
    Fence(oneshot::Sender<()>),
    /// The claims of `account` changed: its clients check themselves again.
    Refresh { account: u32 },
    /// Account `account` was added with imports: their taps go in.
    Imports { account: u32 },
    /// The server shuts down: every client and link closes; answered once
    /// they are gone, or after a while.
    Shutdown(oneshot::Sender<()>),
    /// Answered with the lane's clients, for monitoring.
    Clients(oneshot::Sender<Vec<crate::monitor::ConnInfo>>),
    /// The server in slot `server` has `weight` members in `subject` of
    /// `account`, in `queue` if given; none to remove them.
    Server {
        account: u32,
        subject: Box<[u8]>,
        queue: Option<Box<[u8]>>,
        server: u16,
        weight: crate::index::Members,
    },
    /// Server `server` of the cluster takes this lane's data at `endpoint`.
    Push { server: u16, endpoint: String },
    /// The server in slot `server` is gone: its data link closes, and
    /// sends waiting on it give up.
    Gone { server: u16 },
    /// A naq hub or leaf, of control identity `id`, cluster `cluster`, is
    /// in slot `slot`, bound to `account`, with the permissions of its link
    /// if any. A leaf gets its data link here.
    Link {
        slot: u16,
        id: Box<[u8]>,
        cluster: Box<[u8]>,
        account: u32,
        perms: Option<Arc<crate::perms::LinkPerms>>,
    },
    /// Slot `slot` is free again: its data link closes.
    Unlink { slot: u16 },
    /// The naq hub in slot `slot` takes data at `endpoints`, one per lane,
    /// from this server as leaf of control identity `id`.
    HubData {
        slot: u16,
        id: Box<[u8]>,
        endpoints: Vec<String>,
    },
    /// Answered with the lane's leaf node links, for monitoring.
    Links(oneshot::Sender<crate::monitor::Links>),
    /// Answered by lane 0 with the routes of the cluster, for monitoring.
    Routes(
        crate::monitor::Subs,
        oneshot::Sender<Vec<crate::monitor::RouteInfo>>,
    ),
}

/// The ways into a lane, for every lane.
#[derive(Debug)]
pub(crate) struct LaneTx {
    control: Mailbox<Control>,
    data: Mailbox<Batch>,
}

impl LaneTx {
    /// Hands the lane a control.
    pub(crate) fn control(&self, c: Control) {
        self.control.push(c);
    }

    /// Whether no batch waits for the lane: those it took, it delivered.
    pub(crate) fn no_data(&self) -> bool {
        self.data.is_empty()
    }
}

/// The lane's ends of its mailboxes.
#[derive(Debug)]
pub(crate) struct LaneRx {
    control: Receiver<Control>,
    data: Receiver<Batch>,
}

/// The mailboxes of one lane.
pub(crate) fn mailboxes() -> (LaneTx, LaneRx) {
    // Unbounded: a client queues at most one read of subscriptions before
    // its next fence, so connections bound the controls.
    let (control, control_rx) = mailbox::mailbox(usize::MAX);
    let (data, data_rx) = mailbox::mailbox(DATA_BATCHES);
    (
        LaneTx { control, data },
        LaneRx {
            control: control_rx,
            data: data_rx,
        },
    )
}

/// A subscription that got its maximum of messages: client and SID.
type Spent = (Rc<Client>, Box<[u8]>);

/// The indexes of one chunk of accounts.
type Indexes = Box<[RefCell<Index>]>;

/// State of one lane. Only its own thread touches it.
#[derive(Debug)]
pub(crate) struct Lane {
    pub(crate) id: usize,
    pub(crate) shared: Arc<Shared>,
    /// Interest of every client of the server, by account: those of the
    /// first chunk of accounts here, those of the later ones in chunks made
    /// on first use.
    first: Box<[RefCell<Index>; CHUNK]>,
    later: Box<[OnceCell<Indexes>]>,
    /// Clients with output their writers have not been woken for.
    dirty: RefCell<Vec<Rc<Client>>>,
    /// Subscriptions that got their maximum of messages, by client and SID.
    spent: RefCell<Vec<Spent>>,
    /// State of the random numbers for queue picks.
    rng: Cell<u64>,
    /// Messages in and out on this lane.
    pub(crate) tally: Tally,
    /// Clients on this lane, by ID.
    pub(crate) clients: RefCell<FxHashMap<u64, Rc<Client>>>,
    /// Read buffers of its clients that batches may still refer to.
    pub(crate) reads: SpentReads,
    /// Buffers of batches for other servers that may still be in flight.
    pub(crate) batches: SpentReads,
    /// Leaf node links on this lane.
    pub(crate) links: RefCell<Vec<Rc<crate::leaf::LinkSide>>>,
    /// Links the message being routed reaches.
    hits: peer::Hits,
    /// The other servers of the cluster, on lane 0 with a cluster.
    pub(crate) mesh: RefCell<Option<Rc<crate::mesh::Mesh>>>,
    /// This lane's data link to each server reached over OMQ, by slot,
    /// once it said where.
    pub(crate) sends: RefCell<Vec<Option<crate::mesh::DataLink>>>,
    /// The servers reached over OMQ, by slot.
    pub(crate) slots: Slots,
    /// This lane's ROUTER for the data of naq leafs, on a hub.
    pub(crate) leaf_router: RefCell<Option<omq_tokio::IdentitySocket>>,
    /// Room for the subject a shadow delivers with.
    shadow_subject: RefCell<Vec<u8>>,
    /// The taps the message being routed met.
    taps: RefCell<Vec<crate::imports::service::Tap>>,
    /// The message being delivered came through a service import: shadows
    /// do not get it.
    pub(crate) imported: Cell<bool>,
    /// Account ids by name, as this lane met them.
    account_ids: RefCell<FxHashMap<Box<[u8]>, u32>>,
    /// Connections that closed and are still writing what was left.
    pub(crate) ending: Rc<Cell<usize>>,
}

/// A connection counted as ending on its lane, until dropped.
#[derive(Debug)]
pub(crate) struct Ending(Rc<Cell<usize>>);

impl Drop for Ending {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

impl Lane {
    /// Counts a connection as ending until the guard drops: a shutdown
    /// waits for it.
    pub(crate) fn ending(&self) -> Ending {
        self.ending.set(self.ending.get() + 1);
        Ending(self.ending.clone())
    }

    /// The interest in `account`, an id of the server's.
    #[inline]
    pub(crate) fn index(&self, account: u32) -> &RefCell<Index> {
        match self.first.get(account as usize) {
            Some(i) => i,
            None => self.later_index(account),
        }
    }

    /// The interest in `account`, past the first chunk of accounts.
    #[cold]
    #[inline(never)]
    fn later_index(&self, account: u32) -> &RefCell<Index> {
        let (chunk, at) = crate::accounts::place(account);
        &self.later[chunk - 1].get_or_init(indexes)[at]
    }

    /// The id of account `name`, if the server has it: kept, as ids are
    /// never reused.
    pub(crate) fn account_id(&self, name: &[u8]) -> Option<u32> {
        if let Some(&id) = self.account_ids.borrow().get(name) {
            return Some(id);
        }
        let id = self.shared.accounts.id_of(name)?;
        self.account_ids.borrow_mut().insert(name.into(), id);
        Some(id)
    }

    /// Notes the taps of interest the message being routed met.
    pub(crate) fn note_taps(&self, taps: &[crate::imports::service::Tap]) {
        self.taps.borrow_mut().extend_from_slice(taps);
    }

    /// The taps noted since the last call.
    pub(crate) fn take_taps(&self) -> std::vec::IntoIter<crate::imports::service::Tap> {
        std::mem::take(&mut *self.taps.borrow_mut()).into_iter()
    }

    /// Number of other servers of the cluster.
    pub(crate) fn servers(&self) -> usize {
        routes(&self.shared)
    }

    /// Number of lanes of the server.
    pub(crate) fn lanes(&self) -> usize {
        self.shared.lanes.len()
    }

    /// Notes that `client` has new output. Its writer wakes at the next
    /// [`Lane::flush`], so a batch of messages costs one wake.
    #[inline]
    pub(crate) fn mark(&self, client: &Rc<Client>) {
        if !client.dirty.replace(true) {
            self.dirty.borrow_mut().push(client.clone());
        }
    }

    /// Wakes the writers of every client marked since the last flush, and
    /// publishes the lane's counts.
    pub(crate) fn flush(&self) {
        self.tally.publish(&self.shared.counts[self.id]);
        let mut dirty = self.dirty.take();
        for c in dirty.drain(..) {
            c.dirty.set(false);
            c.wake_writer();
        }
        // Hands the emptied vector back, keeping its capacity.
        let mut slot = self.dirty.borrow_mut();
        if slot.is_empty() {
            *slot = dirty;
        }
    }

    /// Tells the links on this lane that interest in `filter` of `account`,
    /// in `queue` if given, changed: of a client or of a link's hub.
    pub(crate) fn changed(&self, account: u32, filter: &[u8], queue: Option<&[u8]>) {
        if let Some(mesh) = self.mesh.borrow().as_ref() {
            mesh.changed(self, account, filter, queue);
        }
        let links = self.links.borrow();
        if links.is_empty() {
            return;
        }
        let index = self.index(account).borrow();
        for l in links.iter().filter(|l| l.account == account) {
            l.update(&index, filter, queue, self.slots.leafs());
            self.mark(&l.client);
        }
    }

    /// Tells every other lane that this one gained or lost a subscription
    /// to `subject` of `account`, in `queue` if given.
    pub(crate) fn announce(&self, account: u32, subject: &[u8], queue: Option<&[u8]>, add: bool) {
        for (i, tx) in self.shared.lanes.iter().enumerate() {
            if i != self.id {
                tx.control.push(Control::Interest {
                    lane: self.id,
                    account,
                    subject: subject.into(),
                    queue: queue.map(Into::into),
                    add,
                });
            }
        }
    }

    /// Waits until every other lane applied what this one announced.
    pub(crate) async fn fence(&self) {
        let mut answers = Vec::with_capacity(self.lanes());
        for (i, tx) in self.shared.lanes.iter().enumerate() {
            if i != self.id {
                let (done, answer) = oneshot::channel();
                tx.control.push(Control::Fence(done));
                answers.push(answer);
            }
        }
        for a in answers {
            // An error means the lane stopped: nothing left to wait for.
            let _ = a.await;
        }
    }

    /// Puts the naq hub or leaf `linked` in slot `slot`; a leaf gets its
    /// data link on this lane.
    fn link(&self, slot: u16, linked: slots::Linked) {
        let id = linked.id.clone();
        self.slots.link(slot, linked);
        if !self.slots.is_hub(slot) {
            crate::mesh::leaf(self, slot, &id);
        }
    }

    /// Hands `batch` to lane `to`, waiting while it has its fill.
    pub(crate) async fn ship(&self, to: usize, batch: Batch) {
        self.shared.lanes[to].data.send(batch).await;
    }

    #[expect(clippy::too_many_lines, reason = "a flat match, one arm per control")]
    fn control(&self, c: Control) {
        match c {
            Control::Interest {
                lane,
                account,
                subject,
                queue,
                add,
            } => {
                self.index(account)
                    .borrow_mut()
                    .remote(&subject, queue.as_deref(), lane, add);
                self.changed(account, &subject, queue.as_deref());
            }
            Control::Peer {
                account,
                subject,
                queue,
                peer,
            } => {
                self.index(account)
                    .borrow_mut()
                    .peer(&subject, queue.as_deref(), peer);
                self.changed(account, &subject, queue.as_deref());
            }
            Control::Fence(done) => {
                let _ = done.send(());
            }
            Control::Imports { account } => crate::imports::service::install_account(self, account),
            Control::Refresh { account } => {
                for c in self.clients.borrow().values() {
                    if c.account.get() == account {
                        c.refresh();
                    }
                }
            }
            Control::Shutdown(done) => crate::stop::lane(self, done),
            Control::Clients(answer) => {
                let _ = answer.send(crate::monitor::conns(self));
            }
            Control::Server {
                account,
                subject,
                queue,
                server,
                weight,
            } => {
                self.index(account)
                    .borrow_mut()
                    .server(&subject, queue.as_deref(), server, weight);
                // Links and servers hear of the interest of leafs.
                self.changed(account, &subject, queue.as_deref());
                if queue.is_none() {
                    let add = weight.all > 0;
                    crate::imports::shadow::server(self, account, &subject, server, add);
                }
            }
            Control::Push { server, endpoint } => crate::mesh::push(self, server, &endpoint),
            Control::Gone { server } => crate::mesh::gone(self, server),
            Control::Link {
                slot,
                id,
                cluster,
                account,
                perms,
            } => self.link(
                slot,
                slots::Linked {
                    id: id.into(),
                    cluster: cluster.into(),
                    account,
                    perms,
                },
            ),
            Control::Unlink { slot } => {
                self.slots.unlink(slot);
                crate::mesh::gone(self, slot);
            }
            Control::HubData {
                slot,
                id,
                endpoints,
            } => {
                if let Some(me) = get(self.shared.id, self.id) {
                    crate::mesh::hub(&me, slot, &id, &endpoints);
                }
            }
            Control::Links(answer) => {
                let _ = answer.send(crate::monitor::links(self));
            }
            Control::Routes(subs, answer) => {
                let _ = answer.send(crate::monitor::routes(self, subs));
            }
        }
    }
}

/// A chunk of indexes, of accounts with no interest yet.
#[cold]
fn indexes() -> Indexes {
    (0..CHUNK).map(|_| RefCell::default()).collect()
}

/// Sets up lane `id` of the server on the calling lane thread, with the
/// tasks that take its mailboxes.
pub(crate) fn install(shared: Arc<Shared>, id: usize, rx: LaneRx) {
    let key = (shared.id, id);
    let servers = routes(&shared);
    let hubs = crate::mesh::hubs(&shared.opts);
    let lane = Rc::new(Lane {
        id,
        first: Box::new(std::array::from_fn(|_| RefCell::default())),
        later: (1..shared.accounts.room())
            .map(|_| OnceCell::new())
            .collect(),
        shared,
        dirty: RefCell::default(),
        spent: RefCell::default(),
        rng: Cell::new(seed()),
        tally: Tally::default(),
        clients: RefCell::default(),
        reads: SpentReads::default(),
        batches: SpentReads::default(),
        links: RefCell::default(),
        hits: peer::Hits::default(),
        mesh: RefCell::default(),
        sends: RefCell::new(vec![None; servers]),
        slots: Slots::new(servers, hubs),
        leaf_router: RefCell::default(),
        shadow_subject: RefCell::default(),
        taps: RefCell::default(),
        imported: Cell::new(false),
        account_ids: RefCell::default(),
        ending: Rc::default(),
    });
    crate::imports::service::install(&lane);
    if let Some(c) = &lane.shared.callouts {
        c.install(&lane);
    }
    crate::sys::install(&lane);
    crate::resolver::sync::start(&lane);
    LANES.with(|l| l.borrow_mut().insert(key, lane.clone()));
    let LaneRx { control, data } = rx;
    let l = lane.clone();
    tokio::task::spawn_local(async move {
        let mut controls = Vec::new();
        while control.recv_all(&mut controls).await {
            for c in controls.drain(..) {
                l.control(c);
            }
            // Wakes the links told of interest.
            l.flush();
        }
    });
    tokio::task::spawn_local(data::run(lane, data));
}

/// The state of lane `index` of server `id`, on that lane's thread.
pub(crate) fn get(id: u64, index: usize) -> Option<Rc<Lane>> {
    LANES.with(|l| l.borrow().get(&(id, index)).cloned())
}

/// A different seed for every lane.
fn seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u8(0);
    h.finish()
}

/// Routes of `shared`'s cluster.
fn routes(shared: &Shared) -> usize {
    shared.opts.cluster.as_ref().map_or(0, |c| c.routes.len())
}
