//! Delivering a message to the subscriptions on a lane, and picking one
//! member of a queue group.

use std::rc::Rc;

use naq_proto::client::Pub;
use naq_proto::encode::Msg;

use super::Lane;
use crate::conn::Client;
use crate::index::{Entry, Few, Group, Members, Peer};

/// Where a queue group's message went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Queued {
    /// To a member on this lane.
    Here,
    /// To be forwarded to a member on this lane.
    Lane(usize),
    /// To be sent to a member at this server of the cluster, by route.
    Server(u16),
    /// No member took it.
    Nowhere,
}

/// A queue group to deliver to: its name, and its groups in the filters a
/// subject matches.
#[derive(Debug)]
pub(crate) struct Queue<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) groups: Few<'a, Group>,
    /// The slots of servers whose members do not get it, as bits.
    pub(crate) skips: u64,
}

/// Where a queue group's pick went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pick {
    /// The `n`th member on this lane, counted across the groups.
    Local(usize),
    /// A member on another lane.
    Lane(usize),
    /// A member at another server, by route.
    Server(u16),
}

/// Members on this lane, across `groups`.
fn local_len(groups: &Few<'_, Group>) -> usize {
    groups.iter().map(|g| g.local.len()).sum()
}

/// Offers the members on this lane across `groups` to `take`, from the
/// `start`th on, until it takes one.
fn first_taker(
    groups: &Few<'_, Group>,
    start: usize,
    mut take: impl FnMut(&Entry) -> bool,
) -> bool {
    let len = local_len(groups);
    (0..len).any(|i| nth_local(groups, (start + i) % len).is_some_and(&mut take))
}

/// The `n`th member on this lane, across `groups`.
fn nth_local<'a>(groups: &Few<'a, Group>, mut n: usize) -> Option<&'a Entry> {
    for g in groups.iter() {
        match g.local.get(n) {
            Some(e) => return Some(e),
            None => n -= g.local.len(),
        }
    }
    None
}

impl Lane {
    /// A random number below `n`, which is not 0.
    pub(crate) fn below(&self, n: u64) -> u64 {
        // wyrand: fast, and good enough to spread messages.
        let s = self.rng.get().wrapping_add(0xa076_1d64_78bd_642f);
        self.rng.set(s);
        let t = u128::from(s) * u128::from(s ^ 0xe703_7ed1_a0b4_28db);
        let r = (t >> 64) as u64 ^ t as u64;
        ((u128::from(r) * u128::from(n)) >> 64) as u64
    }

    /// Encodes `m` for subscription `e`, unless it is client `skip`'s (0
    /// skips none: IDs start at 1), closed or spent. Notes a subscriber
    /// past the stall mark in `stalled`.
    #[inline]
    pub(crate) fn deliver_to(
        &self,
        e: &Entry,
        m: &Pub<'_>,
        skip: u64,
        stalled: &mut Option<Rc<Client>>,
    ) -> bool {
        if e.shadow.is_some() {
            return self.deliver_shadow(e, m, skip, stalled);
        }
        self.deliver_entry(e, m, skip, stalled)
    }

    /// [`Lane::deliver_to`] for a shadow: with the subject its importer
    /// has. Out of line: few subscriptions are shadows.
    #[cold]
    #[inline(never)]
    fn deliver_shadow(
        &self,
        e: &Entry,
        m: &Pub<'_>,
        skip: u64,
        stalled: &mut Option<Rc<Client>>,
    ) -> bool {
        let Some(im) = e.shadow.as_ref().filter(|_| !self.imported.get()) else {
            return false;
        };
        let mut subject = self.shadow_subject.take();
        subject.clear();
        im.deliver_as(m.subject, &mut subject);
        let got = self.deliver_entry(
            e,
            &Pub {
                subject: &subject,
                ..*m
            },
            skip,
            stalled,
        );
        self.shadow_subject.replace(subject);
        got
    }

    /// [`Lane::deliver_to`] with `m` as it is.
    #[inline]
    fn deliver_entry(
        &self,
        e: &Entry,
        m: &Pub<'_>,
        skip: u64,
        stalled: &mut Option<Rc<Client>>,
    ) -> bool {
        let c = &e.client;
        if c.is_closed() || c.id == skip || e.is_spent() || (c.guarded.get() && !c.accepts(m)) {
            return false;
        }
        let headers = m.headers.filter(|_| c.headers.get());
        let len = {
            let mut out = c.out.borrow_mut();
            Msg {
                subject: m.subject,
                sid: &e.sid,
                reply: m.reply,
                headers,
                payload: m.payload,
            }
            .encode(&mut *out);
            out.len()
        };
        let size = m.payload.len() + headers.map_or(0, <[u8]>::len);
        self.tally.gave(size);
        c.tally.gave(size);
        self.mark(c);
        e.delivered.set(e.delivered.get() + 1);
        if e.is_spent() {
            self.spent.borrow_mut().push((c.clone(), e.sid.clone()));
        }
        let opts = &self.shared.opts;
        if len > opts.max_pending {
            // A slow consumer.
            crate::stats::Events::note(&self.shared.events.slow_consumers);
            c.close();
        } else if len > opts.max_pending / 4 * 3 {
            *stalled = Some(c.clone());
        }
        true
    }

    /// Encodes `m` for every subscription in `local`. Returns whether any
    /// took it.
    #[inline]
    pub(crate) fn deliver(
        &self,
        local: &[Entry],
        m: &Pub<'_>,
        skip: u64,
        stalled: &mut Option<Rc<Client>>,
    ) -> bool {
        let mut any = false;
        for e in local {
            any |= self.deliver_to(e, m, skip, stalled);
        }
        any
    }

    /// Picks the member of the queue group made of `groups` that gets the
    /// next message: each member on any lane as likely as the others, and
    /// those at the routes not in `skips`, each as many as its weight, as
    /// in `nats-server`. Without one, a member at a naq hub or leaf, or one
    /// a route has for its leafs, not in `skips`, by weight.
    fn pick(&self, groups: &Few<'_, Group>, skips: u64) -> Option<Pick> {
        let fallback = self.slots.fallback();
        let first = |s: u16, m: Members| -> u64 {
            let b = super::bit(s);
            if (skips | fallback) & b == 0 {
                u64::from(m.first())
            } else {
                0
            }
        };
        let remote = |g: &Group| -> u64 { g.servers.iter().map(|&(s, m)| first(s, m)).sum() };
        let total: u64 = groups.iter().map(|g| g.weight() + remote(g)).sum();
        if total == 0 {
            return self.pick_last(groups, skips, fallback);
        }
        let mut n = self.below(total);
        let local = local_len(groups) as u64;
        if n < local {
            return Some(Pick::Local(n as usize));
        }
        n -= local;
        for &(lane, count) in groups.iter().flat_map(|g| &g.lanes) {
            if n < u64::from(count) {
                return Some(Pick::Lane(lane));
            }
            n -= u64::from(count);
        }
        for &(s, m) in groups.iter().flat_map(|g| &g.servers) {
            let w = first(s, m);
            if n < w {
                return Some(Pick::Server(s));
            }
            n -= w;
        }
        None
    }

    /// Picks a member at a naq hub or leaf, all in `fallback`, or one a
    /// route has for its leafs, not in `skips`, each as likely as its
    /// weight. Out of line: queue groups have members here or at routes,
    /// mostly.
    #[inline(never)]
    fn pick_last(&self, groups: &Few<'_, Group>, skips: u64, fallback: u64) -> Option<Pick> {
        let last = |s: u16, m: Members| -> u64 {
            let b = super::bit(s);
            if skips & b != 0 {
                0
            } else if fallback & b != 0 {
                u64::from(m.all)
            } else {
                u64::from(m.of_leafs)
            }
        };
        let all = || groups.iter().flat_map(|g| &g.servers);
        let total: u64 = all().map(|&(s, m)| last(s, m)).sum();
        if total == 0 {
            return None;
        }
        let mut n = self.below(total);
        for &(s, m) in all() {
            let w = last(s, m);
            if n < w {
                return Some(Pick::Server(s));
            }
            n -= w;
        }
        None
    }

    /// Delivers `m` to one member of queue group `q`:
    /// each client member on any lane as likely as the others. Without one,
    /// a link with `peers`, as the hub of the link gets it only as a last
    /// resort.
    pub(crate) fn deliver_queue(
        &self,
        q: &Queue<'_>,
        m: &Pub<'_>,
        skip: u64,
        stalled: &mut Option<Rc<Client>>,
    ) -> Queued {
        let groups = &q.groups;
        let lane = match self.pick(groups, q.skips) {
            None => None,
            Some(Pick::Server(s)) => return Queued::Server(s),
            Some(Pick::Lane(l)) => Some(l),
            Some(Pick::Local(n)) => {
                if first_taker(groups, n, |e| self.deliver_to(e, m, skip, stalled)) {
                    return Queued::Here;
                }
                // No member here took it: one on another lane may.
                groups.iter().find_map(|g| g.lanes.first().map(|&(l, _)| l))
            }
        };
        match lane {
            Some(l) => Queued::Lane(l),
            None => self.to_peer(groups, q.name, skip),
        }
    }

    /// Sends a message for queue group `name` to one of the links of
    /// `groups` but link `skip`, each as likely as its weight says, if
    /// there is one.
    fn to_peer(&self, groups: &Few<'_, Group>, name: &[u8], skip: u64) -> Queued {
        let peers = || {
            groups
                .iter()
                .flat_map(|g| &g.peers)
                .filter(move |p| p.link != skip)
        };
        let total: u64 = peers().map(|p| u64::from(p.weight)).sum();
        if total == 0 {
            return Queued::Nowhere;
        }
        let mut n = self.below(total);
        let Some(&p) = peers().find(|p| {
            let hit = n < u64::from(p.weight);
            n = n.saturating_sub(u64::from(p.weight));
            hit
        }) else {
            return Queued::Nowhere;
        };
        self.to_link(p, name)
    }

    /// Hands a message for queue group `name` to link `p`: here, or on its
    /// lane.
    fn to_link(&self, p: Peer, name: &[u8]) -> Queued {
        if p.lane == self.id {
            self.hit_link(p, Some(name));
            Queued::Here
        } else {
            Queued::Lane(p.lane)
        }
    }

    /// Delivers `m`, from another lane, to one member on this lane of queue
    /// group `q`, chosen at random; without one, to a link here if `peers`.
    pub(crate) fn deliver_any(
        &self,
        q: &Queue<'_>,
        m: &Pub<'_>,
        peers: bool,
        stalled: &mut Option<Rc<Client>>,
    ) {
        let groups = &q.groups;
        let len = local_len(groups) as u64;
        if len > 0 {
            let start = self.below(len) as usize;
            // The publisher is on another lane: nothing to skip.
            if first_taker(groups, start, |e| self.deliver_to(e, m, 0, stalled)) {
                return;
            }
        }
        let here = groups
            .iter()
            .flat_map(|g| &g.peers)
            .find(|p| p.lane == self.id);
        if let Some(&p) = here.filter(|_| peers) {
            self.hit_link(p, Some(q.name));
        }
    }

    /// Ends the subscriptions that got their maximum of messages.
    pub(crate) fn expire(&self) {
        let spent = self.spent.take();
        for (c, sid) in spent {
            c.unsubscribe(self, &sid);
        }
    }
}
