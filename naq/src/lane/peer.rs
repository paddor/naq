//! Leaf node links as subscribers: the interest of their hubs on every
//! lane, and one message to each link a message reaches.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use naq_proto::client::Pub;

use super::{Control, Lane};
use crate::conn::Client;
use crate::index::Peer;

/// Links the message being routed reaches, gathered so each gets it once:
/// for plain interest, a queue group pick, or both.
#[derive(Debug, Default)]
pub(crate) struct Hits {
    /// Hits in use, at the start of `all`; the rest keep their buffers.
    /// A `Cell`, so routing tests it with one load.
    used: Cell<usize>,
    all: RefCell<Vec<Hit>>,
}

#[derive(Debug, Default)]
struct Hit {
    link: u64,
    /// For a shadow, the import of the link's account it stands for: see
    /// [`Peer::shadow`].
    shadow: u32,
    /// The link's queue groups picked, separated by blanks.
    queues: Vec<u8>,
}

impl Lane {
    /// Tells every other lane that `peer` gained, changed or lost interest
    /// in `subject` of `account`, in `queue` if given: lost with weight 0.
    pub(crate) fn announce_peer(
        &self,
        account: u32,
        subject: &[u8],
        queue: Option<&[u8]>,
        peer: Peer,
    ) {
        for (i, tx) in self.shared.lanes.iter().enumerate() {
            if i != self.id {
                tx.control(Control::Peer {
                    account,
                    subject: subject.into(),
                    queue: queue.map(Into::into),
                    peer,
                });
            }
        }
    }

    /// Notes that the link of `p`, on this lane, gets the message being
    /// routed: for its plain interest, or for a member of queue group
    /// `queue`. A shadow gets nothing of a service import.
    pub(crate) fn hit_link(&self, p: Peer, queue: Option<&[u8]>) {
        if p.shadow != Peer::DIRECT && self.imported.get() {
            return;
        }
        let used = self.hits.used.get();
        let mut all = self.hits.all.borrow_mut();
        let at = all[..used]
            .iter()
            .position(|h| h.link == p.link && h.shadow == p.shadow);
        let at = at.unwrap_or_else(|| {
            if used == all.len() {
                all.push(Hit::default());
            }
            let h = &mut all[used];
            h.link = p.link;
            h.shadow = p.shadow;
            h.queues.clear();
            self.hits.used.set(used + 1);
            used
        });
        if let Some(q) = queue {
            let h = &mut all[at];
            if !h.queues.is_empty() {
                h.queues.push(b' ');
            }
            h.queues.extend_from_slice(q);
        }
    }

    /// Whether links were noted since the last [`Lane::send_hits`].
    #[inline]
    pub(crate) const fn has_hits(&self) -> bool {
        self.hits.used.get() > 0
    }

    /// Sends `m` once to every link noted since the last call, with the
    /// queue groups picked for it. Notes a link past the stall mark in
    /// `stalled`.
    #[inline(never)]
    pub(crate) fn send_hits(&self, m: &Pub<'_>, stalled: &mut Option<Rc<Client>>) {
        let all = self.hits.all.borrow();
        let links = self.links.borrow();
        for h in &all[..self.hits.used.replace(0)] {
            // A link that ended since gets nothing.
            let Some(l) = links.iter().find(|l| l.id == h.link) else {
                continue;
            };
            if h.shadow == Peer::DIRECT {
                l.deliver(self, m, &h.queues, stalled);
                continue;
            }
            let imports = &self.shared.imports[l.account as usize].streams;
            if let Some(im) = imports.get(h.shadow as usize) {
                let mut subject = Vec::new();
                im.deliver_as(m.subject, &mut subject);
                l.deliver(
                    self,
                    &Pub {
                        subject: &subject,
                        ..*m
                    },
                    &h.queues,
                    stalled,
                );
            }
        }
    }
}
