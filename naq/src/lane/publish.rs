//! Routing a message from the lane it came in on: delivered here,
//! forwarded once to each other lane with interest, and handed to links.

use std::rc::Rc;

use naq_proto::client::Pub;
use naq_proto::leaf;

use super::{Lane, Out, Queue, Queued};
use crate::conn::Client;
use crate::index::{Few, Found, Interest, Peer};

/// A message being routed on the lane it came in on.
pub(crate) struct Routing<'a, 'p> {
    lane: &'a Lane,
    /// Messages for each other lane.
    fwd: &'a mut [Out],
    p: &'a Pub<'p>,
    /// The read buffer `p` lies in.
    buf: &'a [u8],
    /// Who gets nothing: a client without echo, or the link a message
    /// came from; 0 for nobody.
    skip: u64,
    /// From a link: the message whose list names the queue groups that get
    /// a pick. Without one, every group does.
    from: Option<&'a leaf::Msg<'p>>,
    /// A subscriber past the stall mark.
    pub(crate) stalled: Option<Rc<Client>>,
    /// Some subscription got it, here, on another lane or at a hub.
    pub(crate) delivered: bool,
}

impl<'a, 'p> Routing<'a, 'p> {
    /// Routes `p`, which lies in `buf`, on `lane`, with `fwd` for the other
    /// lanes, to all but client or link `skip`.
    #[inline]
    pub(crate) const fn new(
        lane: &'a Lane,
        fwd: &'a mut [Out],
        p: &'a Pub<'p>,
        buf: &'a [u8],
        skip: u64,
    ) -> Self {
        Routing {
            lane,
            fwd,
            p,
            buf,
            skip,
            from: None,
            stalled: None,
            delivered: false,
        }
    }

    /// Only the queue groups message `m` of a link lists get a pick.
    pub(crate) const fn listed(mut self, m: &'a leaf::Msg<'p>) -> Self {
        self.from = Some(m);
        self
    }

    /// Routes the message to the interest `found` for its subject.
    #[inline]
    pub(crate) fn route(&mut self, found: &Found<'_>) {
        match found {
            Found::One(i) => {
                self.plain(i, false);
                for (name, _) in &i.queues {
                    if self.picks(name) {
                        self.queue(found, 0, name);
                    }
                }
            }
            Found::Many(all) => self.many(found, all),
        }
        if self.lane.has_hits() {
            self.lane.send_hits(self.p, &mut self.stalled);
        }
    }

    /// Whether queue group `name` gets a pick.
    #[inline]
    fn picks(&self, name: &[u8]) -> bool {
        self.from.is_none_or(|m| m.queue_names().any(|n| n == name))
    }

    /// Delivers to the plain subscriptions of `i` here, and forwards to
    /// each other lane with some; with `once`, unless forwarded there for
    /// another filter already.
    #[expect(
        clippy::inline_always,
        reason = "measured: a call here costs every publish"
    )]
    #[inline(always)]
    fn plain(&mut self, i: &Interest, once: bool) {
        self.delivered |= self
            .lane
            .deliver(&i.plain.local, self.p, self.skip, &mut self.stalled);
        for &(to, _) in &i.plain.lanes {
            self.fwd[to].plain(self.buf, self.p, once);
            self.delivered = true;
        }
        if !i.plain.peers.is_empty() {
            self.peers(&i.plain.peers);
        }
    }

    /// Hands the message to links with plain interest, but the one it came
    /// from: here, or forwarded to their lanes.
    #[inline(never)]
    fn peers(&mut self, peers: &[Peer]) {
        for p in peers {
            if p.lane != self.lane.id {
                self.fwd[p.lane].plain(self.buf, self.p, true);
            } else if p.link != self.skip {
                self.lane.hit_link(p.link, None);
            } else {
                continue;
            }
            self.delivered = true;
        }
    }

    /// Routes to the filters in `all`, wildcard ones among them: each
    /// plain subscription once, each queue group once across filters.
    #[inline(never)]
    fn many(&mut self, found: &Found<'_>, all: &Few<'_, Interest>) {
        for i in all.iter() {
            self.plain(i, true);
        }
        for (k, i) in all.iter().enumerate() {
            for (name, _) in &i.queues {
                if !merged_before(all, k, name) && self.picks(name) {
                    self.queue(found, k, name);
                }
            }
        }
    }

    /// Delivers to one member of queue group `name`, from the `k`th match
    /// on, here or on the lane of the member picked.
    fn queue(&mut self, found: &Found<'_>, k: usize, name: &[u8]) {
        let q = Queue {
            name,
            groups: found.queue_groups(k, name),
        };
        match self
            .lane
            .deliver_queue(&q, self.p, self.skip, &mut self.stalled)
        {
            Queued::Here => self.delivered = true,
            Queued::Lane(to) => {
                self.fwd[to].queue(self.buf, self.p, name);
                self.delivered = true;
            }
            Queued::Nowhere => {}
        }
    }
}

/// Whether queue group `name` of `found[k]` was in an earlier match, and
/// so got its pick already.
fn merged_before(found: &Few<'_, Interest>, k: usize, name: &[u8]) -> bool {
    found
        .iter()
        .take(k)
        .any(|i| i.queues.iter().any(|(n, _)| **n == *name))
}
