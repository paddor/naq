//! A lane's state: its share of the server, on the lane's thread.
//!
//! Every lane holds the interest of the whole server. A subscription is
//! added on its own lane, then announced to the others through their
//! control mailboxes. A publish is matched on the publisher's lane, which
//! encodes it for its own subscribers and forwards it once, in a batch, to
//! each other lane with interest.

mod data;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use naq_proto::client::Pub;
use naq_proto::encode::Msg;
use tokio::sync::oneshot;

pub(crate) use data::{Batch, Fwd};

use crate::conn::Client;
use crate::index::{Entry, Index};
use crate::mailbox::{self, Mailbox, Receiver};
use crate::server::Shared;

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
    /// Lane `lane` gained or lost a subscription to `subject`.
    Interest {
        lane: usize,
        subject: Box<[u8]>,
        add: bool,
    },
    /// Answered once the controls before it are applied.
    Fence(oneshot::Sender<()>),
}

/// The ways into a lane, for every lane.
#[derive(Debug)]
pub(crate) struct LaneTx {
    control: Mailbox<Control>,
    data: Mailbox<Batch>,
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

/// State of one lane. Only its own thread touches it.
#[derive(Debug)]
pub(crate) struct Lane {
    pub(crate) id: usize,
    pub(crate) shared: Arc<Shared>,
    /// Interest of every client of the server.
    pub(crate) index: RefCell<Index>,
    /// Clients with output their writers have not been woken for.
    dirty: RefCell<Vec<Rc<Client>>>,
}

impl Lane {
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

    /// Wakes the writers of every client marked since the last flush.
    pub(crate) fn flush(&self) {
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

    /// Encodes `m` for the subscriptions `local` on this lane, skipping
    /// those of client `skip` (0 skips none: IDs start at 1). Returns a
    /// subscriber now past the stall mark.
    #[inline]
    pub(crate) fn deliver(&self, local: &[Entry], m: &Pub<'_>, skip: u64) -> Option<Rc<Client>> {
        let opts = &self.shared.opts;
        let mut stalled = None;
        for e in local {
            let c = &e.client;
            if c.is_closed() || c.id == skip {
                continue;
            }
            let len = {
                let mut out = c.out.borrow_mut();
                Msg {
                    subject: m.subject,
                    sid: &e.sid,
                    reply: m.reply,
                    headers: m.headers.filter(|_| c.headers.get()),
                    payload: m.payload,
                }
                .encode(&mut *out);
                out.len()
            };
            self.mark(c);
            if len > opts.max_pending {
                // A slow consumer.
                c.close();
            } else if len > opts.max_pending / 4 * 3 {
                stalled = Some(c.clone());
            }
        }
        stalled
    }

    /// Tells every other lane that this one gained or lost a subscription
    /// to `subject`.
    pub(crate) fn announce(&self, subject: &[u8], add: bool) {
        for (i, tx) in self.shared.lanes.iter().enumerate() {
            if i != self.id {
                tx.control.push(Control::Interest {
                    lane: self.id,
                    subject: subject.into(),
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
            Control::Interest { lane, subject, add } => {
                self.index.borrow_mut().remote(&subject, lane, add);
            }
            Control::Fence(done) => {
                let _ = done.send(());
            }
        }
    }
}

/// Sets up lane `id` of the server on the calling lane thread, with the
/// tasks that take its mailboxes.
pub(crate) fn install(shared: Arc<Shared>, id: usize, rx: LaneRx) {
    let key = (shared.id, id);
    let lane = Rc::new(Lane {
        id,
        shared,
        index: RefCell::default(),
        dirty: RefCell::default(),
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
        }
    });
    tokio::task::spawn_local(data::run(lane, data));
}

/// The state of lane `index` of server `id`, on that lane's thread.
pub(crate) fn get(id: u64, index: usize) -> Option<Rc<Lane>> {
    LANES.with(|l| l.borrow().get(&(id, index)).cloned())
}
