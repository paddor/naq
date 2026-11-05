//! A link's side on its lane: where its output goes, and the local
//! interest it told the hub of, kept current.

use std::cell::RefCell;
use std::rc::Rc;

use naq_proto::client::Pub;
use naq_proto::{leaf, subject};
use rustc_hash::FxHashMap;

use crate::conn::Client;
use crate::index::{Index, Peer};
use crate::lane::Lane;
use crate::perms::LinkPerms;
use crate::{Remote, Rules};

/// Subjects `nats-server` denies on every link of an account that is not
/// the system account: a literal one in an `LS+` ends the link.
const DENIED: [&[u8]; 3] = [b"$JS.API.>", b"$KV.>", b"$OBJ.>"];

/// What the hub was told, by filter and queue group: 1 for plain
/// interest, the member count for a queue group.
type Told = FxHashMap<(Box<[u8]>, Option<Box<[u8]>>), u32>;

/// What monitoring shows of a link.
#[derive(Debug, Default, Clone)]
pub(crate) struct Facts {
    /// The hub's server name.
    pub(crate) name: String,
    /// Where it was dialed.
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) websocket: bool,
    /// Isolation was asked for.
    pub(crate) isolated: bool,
}

/// A link on its lane.
#[derive(Debug)]
pub(crate) struct LinkSide {
    /// Its client ID.
    pub(crate) id: u64,
    /// The local account it binds.
    pub(crate) account: u32,
    /// Its output to the hub.
    pub(crate) client: Rc<Client>,
    /// The hub takes header blocks (`HMSG`).
    headers: bool,
    /// What the link may send and take: `publish` for messages to the hub
    /// and its interest in literal subjects, `subscribe` for messages from
    /// it and the interest it is told of. `None` limits nothing.
    perms: Option<LinkPerms>,
    pub(crate) facts: Facts,
    told: RefCell<Told>,
    /// The hub's interest, as its `LS+` and `LS-` left it: the weight of
    /// each queue group, 1 for plain interest.
    hub: RefCell<Told>,
}

impl LinkSide {
    pub(crate) fn new(
        account: u32,
        client: Rc<Client>,
        headers: bool,
        perms: Option<LinkPerms>,
        facts: Facts,
    ) -> LinkSide {
        LinkSide {
            id: client.id,
            account,
            client,
            headers,
            perms,
            facts,
            told: RefCell::default(),
            hub: RefCell::default(),
        }
    }

    /// Applies an `LS+` of the hub, with `add`, or an `LS-`, on lane
    /// `lane` and every other. Interest is a set: a repeated `LS+` sets a
    /// queue group's weight, one `LS-` removes it whatever its weight.
    pub(crate) fn hub_interest(&self, lane: &Lane, i: &leaf::Interest<'_>, add: bool) {
        if !subject::is_valid_filter(i.subject)
            || denied(i.subject)
            || !self.takes_interest(i.subject)
        {
            return;
        }
        let key = (Box::from(i.subject), i.queue.map(Box::from));
        let weight = i.weight.max(1);
        let mut hub = self.hub.borrow_mut();
        if add {
            if hub.insert(key, weight) == Some(weight) {
                return;
            }
        } else if hub.remove(&key).is_none() {
            return;
        }
        drop(hub);
        self.set_peer(lane, i.subject, i.queue, if add { weight } else { 0 });
    }

    /// The subjects the hub has interest in, once for each `LS+`.
    pub(crate) fn hub_subjects(&self) -> Vec<String> {
        let hub = self.hub.borrow();
        let mut all: Vec<String> = hub
            .keys()
            .map(|(s, _)| String::from_utf8_lossy(s).into_owned())
            .collect();
        all.sort_unstable();
        all
    }

    /// Forgets the hub's interest on every lane, as the link ends.
    pub(crate) fn forget_hub(&self, lane: &Lane) {
        let hub = std::mem::take(&mut *self.hub.borrow_mut());
        for (subject, queue) in hub.into_keys() {
            self.set_peer(lane, &subject, queue.as_deref(), 0);
        }
    }

    /// Sets the link's weight in `subject`, in `queue` if given, on every
    /// lane, and that of its shadows in the accounts its own imports
    /// streams from; 0 removes them.
    fn set_peer(&self, lane: &Lane, subject: &[u8], queue: Option<&[u8]>, weight: u32) {
        let peer = Peer {
            lane: lane.id,
            link: self.id,
            weight,
            shadow: Peer::DIRECT,
        };
        put_peer(lane, self.account, subject, queue, peer);
        let streams = &lane.shared.accounts.imports(self.account).streams;
        for (k, im) in streams.iter().enumerate() {
            if let Some(shadow) = im.shadow(subject) {
                // Imports are few: their count fits.
                let peer = Peer {
                    shadow: k as u32,
                    ..peer
                };
                put_peer(lane, im.from, &shadow, queue, peer);
            }
        }
    }

    /// Encodes `m` for the hub: for its plain interest, and for one member
    /// each of queue groups `queues`. Notes a link past the stall mark in
    /// `stalled`; one past `max_pending` is closed, as a slow consumer.
    pub(crate) fn deliver(
        &self,
        lane: &Lane,
        m: &Pub<'_>,
        queues: &[u8],
        stalled: &mut Option<Rc<Client>>,
    ) {
        let c = &self.client;
        if c.is_closed() || !self.perms.as_ref().is_none_or(|p| p.sends(m.subject)) {
            return;
        }
        let headers = m.headers.filter(|_| self.headers);
        let len = {
            let mut out = c.out.borrow_mut();
            leaf::Msg {
                subject: m.subject,
                reply: m.reply,
                queues,
                headers,
                payload: m.payload,
            }
            .encode(&mut *out);
            out.len()
        };
        let size = m.payload.len() + headers.map_or(0, <[u8]>::len);
        lane.tally.gave(size);
        c.tally.gave(size);
        lane.mark(c);
        let opts = &lane.shared.opts;
        if len > opts.max_pending {
            crate::stats::Events::note(&lane.shared.events.slow_consumers);
            c.close();
        } else if len > opts.max_pending / 4 * 3 {
            *stalled = Some(c.clone());
        }
    }

    /// Tells the hub of all interest in `index`, its account's, with that
    /// of the naq leafs in `leafs`, and of `lds`, the loop detection
    /// subject.
    pub(crate) fn snapshot(&self, index: &Index, lds: &[u8], leafs: u64) {
        let mut out = self.client.out.borrow_mut();
        let mut told = self.told.borrow_mut();
        index.each(|filter, i| {
            if denied(filter) || !self.tells(filter) {
                return;
            }
            if i.plain.told(filter, self.id, leafs) + i.taps_told(false) > 0 {
                leaf::sub(&mut *out, filter, None);
                told.insert((filter.into(), None), 1);
            }
            for (q, g) in &i.queues {
                let n = members(g.told(filter, self.id, leafs));
                if n > 0 {
                    leaf::sub(&mut *out, filter, Some((q, n)));
                    told.insert((filter.into(), Some(q.clone())), n);
                }
            }
        });
        leaf::sub(&mut *out, lds, None);
    }

    /// Tells the hub what changed of the interest in `filter`, in `queue`
    /// if given, as `index` has it now, with that of the naq leafs in
    /// `leafs`.
    pub(crate) fn update(&self, index: &Index, filter: &[u8], queue: Option<&[u8]>, leafs: u64) {
        if denied(filter) || !self.tells(filter) {
            return;
        }
        let n = index.count(filter, queue, self.id, leafs);
        let key = (Box::from(filter), queue.map(Box::from));
        let mut told = self.told.borrow_mut();
        let was = told.get(&key).copied().unwrap_or(0);
        // Plain interest is there or not; a queue group tells its count.
        let same = if queue.is_none() {
            (n > 0) == (was > 0)
        } else {
            n == was
        };
        if same {
            return;
        }
        let mut out = self.client.out.borrow_mut();
        if n == 0 {
            told.remove(&key);
            leaf::unsub(&mut *out, filter, queue);
        } else {
            let n = if queue.is_none() { 1 } else { n };
            told.insert(key, n);
            leaf::sub(&mut *out, filter, queue.map(|q| (q, n)));
        }
    }
}

/// Sets `peer` in `subject` of `account`, in `queue` if given, on every
/// lane, and tells the other links.
fn put_peer(lane: &Lane, account: u32, subject: &[u8], queue: Option<&[u8]>, peer: Peer) {
    lane.index(account).borrow_mut().peer(subject, queue, peer);
    lane.announce_peer(account, subject, queue, peer);
    lane.changed(account, subject, queue);
}

impl LinkSide {
    /// Whether the hub hears of interest in `filter`.
    fn tells(&self, filter: &[u8]) -> bool {
        self.perms.as_ref().is_none_or(|p| p.tells(filter))
    }

    /// Whether the hub's interest in `subject` counts.
    fn takes_interest(&self, subject: &[u8]) -> bool {
        self.perms
            .as_ref()
            .is_none_or(|p| p.takes_interest(subject))
    }

    /// Whether a message of the hub on `subject` comes in.
    pub(crate) fn takes(&self, subject: &[u8]) -> bool {
        self.perms.as_ref().is_none_or(|p| p.takes(subject))
    }
}

/// The permissions of a link: the hub's `export` and `import`, with the
/// remote's `deny_exports` and `deny_imports` added. `None` without any.
pub(crate) fn perms(export: Rules, import: Rules, r: &Remote) -> Option<LinkPerms> {
    let merge = |mut rules: Rules, deny: &[String]| {
        rules.deny.extend_from_slice(deny);
        rules
    };
    LinkPerms::new(
        merge(export, &r.deny_exports),
        merge(import, &r.deny_imports),
    )
}

/// Members of a group, as an `LS+` weight.
fn members(n: u64) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Whether `filter` is a literal subject no link carries: interest in it
/// and messages on it stay on their side.
pub(super) fn denied(filter: &[u8]) -> bool {
    subject::is_literal(filter) && DENIED.iter().any(|d| subject::matches(d, filter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Entry;

    fn told(side: &LinkSide) -> String {
        let out = std::mem::take(&mut *side.client.out.borrow_mut());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn the_hub_hears_of_interest_once_and_of_queue_counts_always() {
        let side = LinkSide::new(0, Rc::new(Client::new(9)), true, None, Facts::default());
        let mut idx = Index::default();
        let c = Rc::new(Client::new(1));
        idx.insert(b"a", None, Entry::new(c.clone(), b"1"));
        idx.insert(b"a.*", Some(b"q"), Entry::new(c.clone(), b"2"));
        idx.insert(b"$KV.b.k", None, Entry::new(c.clone(), b"3"));
        side.snapshot(&idx, b"$LDS.x", 0);
        let first = told(&side);
        assert!(
            first.contains("LS+ a\r\n") && first.contains("LS+ a.* q 1\r\n"),
            "{first}"
        );
        assert!(
            first.ends_with("LS+ $LDS.x\r\n") && !first.contains("$KV"),
            "{first}"
        );

        idx.insert(b"a", None, Entry::new(c.clone(), b"4"));
        side.update(&idx, b"a", None, 0);
        idx.remote(b"a.*", Some(b"q"), 1, true);
        side.update(&idx, b"a.*", Some(b"q"), 0);
        idx.insert(b"$KV.b.k", None, Entry::new(c.clone(), b"5"));
        side.update(&idx, b"$KV.b.k", None, 0);
        assert_eq!(told(&side), "LS+ a.* q 2\r\n");

        idx.remove(b"a", None, 1, b"1");
        side.update(&idx, b"a", None, 0);
        assert_eq!(told(&side), "");
        idx.remove(b"a", None, 1, b"4");
        side.update(&idx, b"a", None, 0);
        idx.remote(b"a.*", Some(b"q"), 1, false);
        side.update(&idx, b"a.*", Some(b"q"), 0);
        idx.remove(b"a.*", Some(b"q"), 1, b"2");
        side.update(&idx, b"a.*", Some(b"q"), 0);
        assert_eq!(told(&side), "LS- a\r\nLS+ a.* q 1\r\nLS- a.* q\r\n");
        // A new subject after the snapshot.
        idx.insert(b"b", None, Entry::new(c, b"6"));
        side.update(&idx, b"b", None, 0);
        assert_eq!(told(&side), "LS+ b\r\n");
        // The interest of a naq leaf here; not of a route.
        idx.server(b"c", None, 3, 1);
        idx.server(b"d", None, 0, 1);
        side.update(&idx, b"c", None, crate::lane::bit(3));
        side.update(&idx, b"d", None, crate::lane::bit(3));
        assert_eq!(told(&side), "LS+ c\r\n");
    }
}
