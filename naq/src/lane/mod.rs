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

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use tokio::sync::oneshot;

pub(crate) use data::{Batch, Outs};
pub(crate) use publish::Routing;
pub(crate) use route::{Queue, Queued};

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
    /// Answered with the lane's clients, for monitoring.
    Clients(oneshot::Sender<Vec<crate::monitor::ConnInfo>>),
    /// Server `server` of the cluster, by route, has `weight` members in
    /// `subject` of `account`, in `queue` if given; 0 for none.
    Server {
        account: u32,
        subject: Box<[u8]>,
        queue: Option<Box<[u8]>>,
        server: u16,
        weight: u32,
    },
    /// Server `server` of the cluster takes this lane's data at `endpoint`.
    Push { server: u16, endpoint: String },
    /// Server `server` of the cluster is gone: its data link closes, and
    /// sends waiting on it give up.
    Gone { server: u16 },
    /// Answered with the lane's leaf node links, for monitoring.
    Links(oneshot::Sender<Vec<crate::monitor::LeafInfo>>),
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

/// State of one lane. Only its own thread touches it.
#[derive(Debug)]
pub(crate) struct Lane {
    pub(crate) id: usize,
    pub(crate) shared: Arc<Shared>,
    /// Interest of every client of the server, by account.
    indexes: Box<[RefCell<Index>]>,
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
    /// Leaf node links on this lane.
    pub(crate) links: RefCell<Vec<Rc<crate::leaf::LinkSide>>>,
    /// Links the message being routed reaches.
    hits: peer::Hits,
    /// The other servers of the cluster, on lane 0 with a cluster.
    pub(crate) mesh: RefCell<Option<Rc<crate::mesh::Mesh>>>,
    /// This lane's data link to each other server of the cluster, by route,
    /// once it said where.
    pub(crate) pushes: RefCell<Vec<Option<omq_tokio::Socket>>>,
}

impl Lane {
    /// The interest in `account`, an id of the server's.
    #[inline]
    pub(crate) fn index(&self, account: u32) -> &RefCell<Index> {
        &self.indexes[account as usize]
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
            let index = self.index(account).borrow();
            mesh.told.update(&index, account, filter, queue);
        }
        let links = self.links.borrow();
        if links.is_empty() {
            return;
        }
        let index = self.index(account).borrow();
        for l in links.iter().filter(|l| l.account == account) {
            l.update(&index, filter, queue);
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

    /// Hands `batch` to lane `to`, waiting while it has its fill.
    pub(crate) async fn ship(&self, to: usize, batch: Batch) {
        self.shared.lanes[to].data.send(batch).await;
    }

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
            }
            Control::Push { server, endpoint } => crate::mesh::push(self, server, &endpoint),
            Control::Gone { server } => crate::mesh::gone(self, server),
            Control::Links(answer) => {
                let _ = answer.send(crate::monitor::links(self));
            }
            Control::Routes(subs, answer) => {
                let _ = answer.send(crate::monitor::routes(self, subs));
            }
        }
    }
}

/// Sets up lane `id` of the server on the calling lane thread, with the
/// tasks that take its mailboxes.
pub(crate) fn install(shared: Arc<Shared>, id: usize, rx: LaneRx) {
    let key = (shared.id, id);
    let servers = routes(&shared);
    let lane = Rc::new(Lane {
        id,
        indexes: (0..shared.accounts.len())
            .map(|_| RefCell::default())
            .collect(),
        shared,
        dirty: RefCell::default(),
        spent: RefCell::default(),
        rng: Cell::new(seed()),
        tally: Tally::default(),
        clients: RefCell::default(),
        reads: SpentReads::default(),
        links: RefCell::default(),
        hits: peer::Hits::default(),
        mesh: RefCell::default(),
        pushes: RefCell::new(vec![None; servers]),
    });
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
