//! Delivering a message to the subscriptions on a lane, and picking one
//! member of a queue group.

use std::rc::Rc;

use naq_proto::client::Pub;
use naq_proto::encode::Msg;

use super::Lane;
use crate::conn::Client;
use crate::index::{Entry, Few, Group};

/// Where a queue group's message went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Queued {
    /// To a member on this lane.
    Here,
    /// To be forwarded to a member on this lane.
    Lane(usize),
    /// No member took it.
    Nowhere,
}

/// Where a queue group's pick went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pick {
    /// The `n`th member on this lane, counted across the groups.
    Local(usize),
    /// A member on another lane.
    Lane(usize),
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
    /// next message: each member on any lane as likely as the others.
    fn pick(&self, groups: &Few<'_, Group>) -> Option<Pick> {
        let total: u64 = groups.iter().map(Group::weight).sum();
        if total == 0 {
            return None;
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
        None
    }

    /// Delivers `m` to one member of the queue group made of `groups`, each
    /// member on any lane as likely as the others.
    pub(crate) fn deliver_queue(
        &self,
        groups: &Few<'_, Group>,
        m: &Pub<'_>,
        skip: u64,
        stalled: &mut Option<Rc<Client>>,
    ) -> Queued {
        let lane = match self.pick(groups) {
            None => return Queued::Nowhere,
            Some(Pick::Lane(l)) => Some(l),
            Some(Pick::Local(n)) => {
                if first_taker(groups, n, |e| self.deliver_to(e, m, skip, stalled)) {
                    return Queued::Here;
                }
                // No member here took it: one on another lane may.
                groups.iter().find_map(|g| g.lanes.first().map(|&(l, _)| l))
            }
        };
        lane.map_or(Queued::Nowhere, Queued::Lane)
    }

    /// Delivers `m`, from another lane, to one member on this lane of the
    /// queue group made of `groups`, chosen at random.
    pub(crate) fn deliver_any(
        &self,
        groups: &Few<'_, Group>,
        m: &Pub<'_>,
        stalled: &mut Option<Rc<Client>>,
    ) {
        let len = local_len(groups) as u64;
        if len > 0 {
            let start = self.below(len) as usize;
            // The publisher is on another lane: nothing to skip.
            first_taker(groups, start, |e| self.deliver_to(e, m, 0, stalled));
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
