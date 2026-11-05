//! Routing a message from the lane it came in on: delivered here,
//! forwarded once to each other lane and each other server with interest,
//! and handed to links.

use std::rc::Rc;

use naq_proto::client::Pub;
use naq_proto::peer;

use super::{Lane, Outs, Queue, Queued};
use crate::conn::Client;
use crate::index::{Few, Found, Interest, Peer};

/// A message being routed on the lane it came in on.
pub(crate) struct Routing<'a, 'p> {
    lane: &'a Lane,
    /// Messages for each other lane and server.
    out: &'a mut Outs,
    p: &'a Pub<'p>,
    /// The message as clients get it: `p` but for some of a hub.
    d: &'a Pub<'p>,
    /// The read buffer `p` lies in.
    buf: &'a [u8],
    /// Who gets nothing: a client without echo, or the link a message
    /// came from; 0 for nobody.
    skip: u64,
    /// The queue groups that get a pick, separated by blanks, as a link or
    /// another server named them; `None` for every group.
    listed: Option<&'a [u8]>,
    /// The slots of servers it does not go to, as bits: see
    /// [`super::Slots`].
    skips: u64,
    /// It goes to links with plain interest: not when a server sent it.
    links: bool,
    /// The servers it went to already, and those it skips, as bits by
    /// slot.
    sent: u64,
    /// A subscriber past the stall mark.
    pub(crate) stalled: Option<Rc<Client>>,
    /// Some subscription got it, here, on another lane or at a hub.
    pub(crate) delivered: bool,
}

impl<'a, 'p> Routing<'a, 'p> {
    /// Routes `p`, which lies in `buf`, on `lane`, with `out` for the other
    /// lanes and servers, to all but client or link `skip`.
    #[inline]
    pub(crate) const fn new(
        lane: &'a Lane,
        out: &'a mut Outs,
        p: &'a Pub<'p>,
        buf: &'a [u8],
        skip: u64,
    ) -> Self {
        Routing {
            lane,
            out,
            p,
            d: p,
            buf,
            skip,
            listed: None,
            skips: 0,
            links: true,
            sent: 0,
            stalled: None,
            delivered: false,
        }
    }

    /// The message came from a link, listing `queues`, separated by blanks:
    /// only those get a pick. Clients get it as `d`. Other servers of the
    /// cluster do not: they have links to the hub of their own, as in
    /// `nats-server`.
    pub(crate) const fn by_link(mut self, queues: &'a [u8], d: &'a Pub<'p>) -> Self {
        self.listed = Some(queues);
        self.d = d;
        let skips = self.lane.slots.go_hub_skips();
        self.skip_servers(skips)
    }

    /// The message came from the server in a slot, for one member of
    /// `queue` if given, else for plain subscriptions. It goes to no server
    /// in `skips`; from another server of the cluster, to links only for a
    /// queue group.
    pub(crate) const fn by_server(mut self, queue: Option<&'a [u8]>, skips: u64) -> Self {
        self.listed = Some(match queue {
            Some(q) => q,
            None => b"",
        });
        self.links = false;
        self.skip_servers(skips)
    }

    /// The message came from a naq hub or leaf: [`Routing::by_server`], but
    /// links with plain interest get it too.
    pub(crate) const fn by_linked(self, queue: Option<&'a [u8]>, skips: u64) -> Self {
        let mut r = self.by_server(queue, skips);
        r.links = true;
        r
    }

    /// It goes to no server in `skips`.
    const fn skip_servers(mut self, skips: u64) -> Self {
        self.skips = skips;
        self.sent = skips;
        self
    }

    /// Routes the message to the interest `found` for its subject.
    #[inline]
    pub(crate) fn route(&mut self, found: &Found<'_>) {
        // Links whose permissions hold it back get it as if sent already.
        let denied = self.lane.slots.denies(self.p.subject);
        self.skips |= denied;
        self.sent |= denied;
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
        self.listed
            .is_none_or(|l| peer::words(l).any(|n| n == name))
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
            .deliver(&i.plain.local, self.d, self.skip, &mut self.stalled);
        for &(to, _) in &i.plain.lanes {
            self.out.lanes[to].plain(self.buf, self.p, once);
            self.delivered = true;
        }
        if !i.plain.peers.is_empty() {
            self.peers(&i.plain.peers);
        }
        if !i.plain.servers.is_empty() {
            self.send_servers(&i.plain.servers);
        }
    }

    /// Sends the message once to each server with plain interest, but
    /// those it skips.
    #[inline(never)]
    fn send_servers(&mut self, servers: &[(u16, crate::index::Members)]) {
        for &(s, _) in servers {
            let bit = super::bit(s);
            if self.sent & bit == 0 {
                self.sent |= bit;
                self.out.server(self.lane, s, self.p, None);
                self.delivered = true;
            }
        }
    }

    /// Hands the message to links with plain interest, but the one it came
    /// from: here, or forwarded to their lanes.
    #[inline(never)]
    fn peers(&mut self, peers: &[Peer]) {
        if !self.links {
            return;
        }
        for p in peers {
            if p.lane != self.lane.id {
                self.out.lanes[p.lane].plain(self.buf, self.p, true);
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
            skips: self.skips,
        };
        match self
            .lane
            .deliver_queue(&q, self.d, self.skip, &mut self.stalled)
        {
            Queued::Here => self.delivered = true,
            Queued::Lane(to) => {
                self.out.lanes[to].queue(self.buf, self.p, name);
                self.delivered = true;
            }
            Queued::Server(s) => {
                self.out.server(self.lane, s, self.p, Some(name));
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
