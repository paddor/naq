//! Interest index of a lane: which subscriptions and which other lanes a
//! subject reaches. Every lane holds the interest of the whole server.
//!
//! Literal filters sit in a hash map, filters with wildcards in a token
//! trie. A subject matches the literal filter it names and every wildcard
//! filter that fits it.

mod literal;
mod trie;

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

use naq_proto::subject;

use crate::conn::Client;
use crate::imports::StreamImport;
use crate::imports::service::Tap;

/// One subscription on this lane.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) client: Rc<Client>,
    /// Subscription ID the client chose.
    pub(crate) sid: Box<[u8]>,
    /// Messages delivered so far.
    pub(crate) delivered: Cell<u64>,
    /// Messages it may get in total; 0 for no limit.
    pub(crate) max: Cell<u64>,
    /// For a shadow, the stream import of the client's subscription it
    /// stands for in the exporting account: its messages are delivered
    /// with the subject the importer has.
    pub(crate) shadow: Option<Arc<StreamImport>>,
}

impl Entry {
    pub(crate) fn new(client: Rc<Client>, sid: &[u8]) -> Entry {
        Entry {
            client,
            sid: sid.into(),
            delivered: Cell::new(0),
            max: Cell::new(0),
            shadow: None,
        }
    }

    /// The shadow of subscription `sid` of `client`, for import `im`. It
    /// has no maximum of its own.
    pub(crate) fn shadow(client: Rc<Client>, sid: &[u8], im: Arc<StreamImport>) -> Entry {
        Entry {
            shadow: Some(im),
            ..Entry::new(client, sid)
        }
    }

    /// Reached its maximum: it takes nothing more.
    #[inline]
    pub(crate) const fn is_spent(&self) -> bool {
        let max = self.max.get();
        max != 0 && self.delivered.get() >= max
    }
}

/// A leaf node link with interest: subscriptions at its hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Peer {
    /// The lane the link is on.
    pub(crate) lane: usize,
    /// The link's client ID.
    pub(crate) link: u64,
    /// Members of a queue group at the hub; 1 for plain interest; 0 for
    /// none, to remove it.
    pub(crate) weight: u32,
    /// For a shadow of the link's interest in the account it imports a
    /// stream from, that import's place among those of the link's
    /// account; [`Peer::DIRECT`] for the link's own.
    pub(crate) shadow: u32,
}

impl Peer {
    /// Not a shadow.
    pub(crate) const DIRECT: u32 = u32::MAX;
}

/// Subscribers of one filter, or of one queue group on it.
#[derive(Debug, Default)]
pub(crate) struct Group {
    /// Subscriptions on this lane.
    pub(crate) local: Vec<Entry>,
    /// Other lanes with subscriptions, and how many each has.
    pub(crate) lanes: Vec<(usize, u32)>,
    /// Links whose hubs have subscriptions. A queue group's message goes
    /// to one only when no client here or on another lane takes it.
    pub(crate) peers: Vec<Peer>,
    /// Other servers with subscriptions, by slot, and how many each has.
    pub(crate) servers: Vec<(u16, Members)>,
}

/// The members of a group at another server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Members {
    /// All of them; 1 for plain interest.
    pub(crate) all: u32,
    /// Those a route has for its leafs: a queue group's message goes to
    /// them only when no other member takes it, as in `nats-server`.
    pub(crate) of_leafs: u32,
}

impl Members {
    /// Those a queue group's message goes to first.
    #[inline]
    pub(crate) const fn first(self) -> u32 {
        self.all.saturating_sub(self.of_leafs)
    }
}

impl From<u32> for Members {
    /// `all` members, none for leafs.
    fn from(all: u32) -> Members {
        Members { all, of_leafs: 0 }
    }
}

impl Group {
    const fn is_empty(&self) -> bool {
        self.local.is_empty()
            && self.lanes.is_empty()
            && self.peers.is_empty()
            && self.servers.is_empty()
    }

    /// Sets the members at server `server`; none removes it.
    fn set_server(&mut self, server: u16, m: Members) {
        let at = self.servers.iter().position(|&(s, _)| s == server);
        match (at, m.all) {
            (Some(at), 0) => {
                self.servers.swap_remove(at);
            }
            (Some(at), _) => self.servers[at].1 = m,
            (None, 0) => {}
            (None, _) => self.servers.push((server, m)),
        }
    }

    /// Adds `peer`, or its new weight; with weight 0, removes it.
    fn set_peer(&mut self, peer: Peer) {
        let add = peer.weight > 0;
        let at = self
            .peers
            .iter()
            .position(|p| p.lane == peer.lane && p.link == peer.link && p.shadow == peer.shadow);
        match (at, add) {
            (Some(at), true) => self.peers[at] = peer,
            (None, true) => self.peers.push(peer),
            (Some(at), false) => {
                self.peers.swap_remove(at);
            }
            (None, false) => {}
        }
    }

    /// Members across all lanes.
    pub(crate) fn weight(&self) -> u64 {
        self.local.len() as u64 + self.lanes.iter().map(|&(_, n)| u64::from(n)).sum::<u64>()
    }

    /// Members as link `link` tells its hub of them: the clients', those
    /// of the naq leafs in `leafs`, as bits by slot, and for the loop
    /// detection subject `filter`, those at the hubs of other links, as
    /// `nats-server` tells them.
    pub(crate) fn told(&self, filter: &[u8], link: u64, leafs: u64) -> u64 {
        let of_leafs = self
            .servers
            .iter()
            .filter(|&&(s, _)| leafs & crate::lane::bit(s) != 0)
            .map(|&(_, m)| u64::from(m.all))
            .sum::<u64>();
        let mine = self.weight() + of_leafs;
        if !filter.starts_with(b"$LDS.") {
            return mine;
        }
        let others = self.peers.iter().filter(|p| p.link != link);
        mine + others.map(|p| u64::from(p.weight)).sum::<u64>()
    }

    fn count(&mut self, lane: usize, add: bool) {
        let at = self.lanes.iter().position(|&(l, _)| l == lane);
        match (at, add) {
            (Some(at), true) => self.lanes[at].1 += 1,
            (None, true) => self.lanes.push((lane, 1)),
            (Some(at), false) => {
                self.lanes[at].1 -= 1;
                if self.lanes[at].1 == 0 {
                    self.lanes.swap_remove(at);
                }
            }
            (None, false) => {}
        }
    }
}

/// Interest in one filter.
#[derive(Debug, Default)]
pub(crate) struct Interest {
    /// Plain subscriptions: each gets every message.
    pub(crate) plain: Group,
    /// Queue groups by name: each gets every message once.
    pub(crate) queues: Vec<(Box<[u8]>, Group)>,
    /// What imports do with messages on the filter: the same on every
    /// lane, acted on by the lane a message comes in on.
    pub(crate) taps: Vec<Tap>,
}

impl Interest {
    const fn is_empty(&self) -> bool {
        self.plain.is_empty() && self.queues.is_empty() && self.taps.is_empty()
    }

    /// The taps that count as plain interest: see [`Index::taps_told`].
    pub(crate) fn taps_told(&self, to_routes: bool) -> u64 {
        let counts = |t: &&Tap| {
            !to_routes
                || matches!(
                    t,
                    Tap::Responses(_)
                        | Tap::Callout(_)
                        | Tap::Sys(_)
                        | Tap::Shadow {
                            to_routes: true,
                            ..
                        }
                )
        };
        self.taps.iter().filter(counts).count() as u64
    }

    /// The group for `queue`, or the plain one.
    fn group(&mut self, queue: Option<&[u8]>) -> &mut Group {
        let Some(name) = queue else {
            return &mut self.plain;
        };
        let at = self
            .queues
            .iter()
            .position(|(n, _)| **n == *name)
            .unwrap_or_else(|| {
                self.queues.push((name.into(), Group::default()));
                self.queues.len() - 1
            });
        &mut self.queues[at].1
    }

    /// Applies `f` to the group for `queue`, if there is one, and forgets
    /// the group once it is empty.
    fn change<T>(&mut self, queue: Option<&[u8]>, f: impl FnOnce(&mut Group) -> T) -> Option<T> {
        let Some(name) = queue else {
            return Some(f(&mut self.plain));
        };
        let at = self.queues.iter().position(|(n, _)| **n == *name)?;
        let out = f(&mut self.queues[at].1);
        if self.queues[at].1.is_empty() {
            self.queues.swap_remove(at);
        }
        Some(out)
    }
}

/// A few items, kept inline up to four.
#[derive(Debug)]
pub(crate) struct Few<'a, T> {
    first: [Option<&'a T>; 4],
    more: Vec<&'a T>,
}

impl<'a, T> Few<'a, T> {
    pub(crate) const fn new() -> Self {
        Few {
            first: [None; 4],
            more: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn push(&mut self, item: &'a T) {
        match self.first.iter_mut().find(|s| s.is_none()) {
            Some(slot) => *slot = Some(item),
            None => self.more.push(item),
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.first[0].is_none()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &'a T> + '_ {
        self.first
            .iter()
            .map_while(|s| *s)
            .chain(self.more.iter().copied())
    }
}

/// The filters a subject matches.
#[derive(Debug)]
pub(crate) enum Found<'a> {
    /// Only its literal filter: no wildcard filter is subscribed to.
    One(&'a Interest),
    /// Any number, wildcard ones among them.
    Many(Few<'a, Interest>),
}

impl<'a> Found<'a> {
    /// The members of queue group `name` from the `from`th match on: across
    /// filters, one group.
    pub(crate) fn queue_groups(&self, from: usize, name: &[u8]) -> Few<'a, Group> {
        let mut groups = Few::new();
        let mut add = |i: &'a Interest| {
            for (n, g) in &i.queues {
                if **n == *name {
                    groups.push(g);
                }
            }
        };
        match self {
            Found::One(i) => add(i),
            Found::Many(found) => found.iter().skip(from).for_each(add),
        }
        groups
    }
}

/// Interest by filter.
#[derive(Debug, Default)]
pub(crate) struct Index {
    literal: literal::Literals,
    wild: trie::Node,
    /// Subscriptions of this lane added and removed, shadows too.
    inserts: u64,
    removes: u64,
}

impl Index {
    /// Adds subscription `entry` to `filter`, in `queue` if given.
    pub(crate) fn insert(&mut self, filter: &[u8], queue: Option<&[u8]>, entry: Entry) {
        self.inserts += 1;
        self.interest(filter).group(queue).local.push(entry);
    }

    /// Subscriptions of this lane added and removed so far, shadows too.
    pub(crate) const fn changes(&self) -> (u64, u64) {
        (self.inserts, self.removes)
    }

    /// Adds `tap` to `filter`.
    pub(crate) fn tap(&mut self, filter: &[u8], tap: Tap) {
        self.interest(filter).taps.push(tap);
    }

    /// Removes the taps of `filter` that `drop` picks.
    pub(crate) fn untap(&mut self, filter: &[u8], drop: impl Fn(&Tap) -> bool) {
        let keep = |i: &mut Interest| i.taps.retain(|t| !drop(t));
        if subject::is_literal(filter) {
            self.literal.change(filter, keep);
        } else {
            self.wild.change(filter, keep);
        }
    }

    /// Whether `filter` has a tap `has` picks.
    pub(crate) fn has_tap(&self, filter: &[u8], has: impl Fn(&Tap) -> bool) -> bool {
        self.interest_of(filter)
            .is_some_and(|i| i.taps.iter().any(has))
    }

    /// Removes subscription `sid` of client `id`.
    pub(crate) fn remove(&mut self, filter: &[u8], queue: Option<&[u8]>, id: u64, sid: &[u8]) {
        self.drop_local(filter, queue, |e| {
            e.client.id == id && *e.sid == *sid && e.shadow.is_none()
        });
    }

    /// Removes the shadows of subscription `sid` of client `id`.
    pub(crate) fn remove_shadow(
        &mut self,
        filter: &[u8],
        queue: Option<&[u8]>,
        id: u64,
        sid: &[u8],
    ) {
        self.drop_local(filter, queue, |e| {
            e.client.id == id && *e.sid == *sid && e.shadow.is_some()
        });
    }

    /// Removes the subscriptions of this lane in `filter`, in `queue` if
    /// given, that `drop` picks, and counts them.
    fn drop_local(&mut self, filter: &[u8], queue: Option<&[u8]>, drop: impl Fn(&Entry) -> bool) {
        let mut gone = 0;
        self.change(filter, queue, |g| {
            let before = g.local.len();
            g.local.retain(|e| !drop(e));
            gone = before - g.local.len();
        });
        // Lengths fit.
        self.removes += gone as u64;
    }

    /// Counts a subscription that lane `lane` gained, or lost.
    pub(crate) fn remote(&mut self, filter: &[u8], queue: Option<&[u8]>, lane: usize, add: bool) {
        if add {
            self.interest(filter).group(queue).count(lane, true);
        } else {
            self.change(filter, queue, |g| g.count(lane, false));
        }
    }

    /// Adds `peer`'s interest in `filter`, in `queue` if given, or its new
    /// weight; with weight 0, removes it.
    pub(crate) fn peer(&mut self, filter: &[u8], queue: Option<&[u8]>, peer: Peer) {
        if peer.weight > 0 {
            self.interest(filter).group(queue).set_peer(peer);
        } else {
            self.change(filter, queue, |g| g.set_peer(peer));
        }
    }

    /// Sets the members `m` server `server` has in `filter`, in `queue` if
    /// given; none removes them.
    pub(crate) fn server(
        &mut self,
        filter: &[u8],
        queue: Option<&[u8]>,
        server: u16,
        m: impl Into<Members>,
    ) {
        let m = m.into();
        if m.all > 0 {
            self.interest(filter).group(queue).set_server(server, m);
        } else {
            self.change(filter, queue, |g| g.set_server(server, m));
        }
    }

    /// The subscribers of the plain subscriptions of `filter`, or of its
    /// queue group `queue`, if any.
    pub(crate) fn group(&self, filter: &[u8], queue: Option<&[u8]>) -> Option<&Group> {
        let interest = self.interest_of(filter)?;
        match queue {
            None => Some(&interest.plain),
            Some(q) => interest
                .queues
                .iter()
                .find(|(n, _)| **n == *q)
                .map(|(_, g)| g),
        }
    }

    /// The interest in `filter`, if any.
    fn interest_of(&self, filter: &[u8]) -> Option<&Interest> {
        if subject::is_literal(filter) {
            self.literal.get(filter)
        } else {
            self.wild.get(filter)
        }
    }

    /// The taps of imports in `filter` that count as plain interest of
    /// this server: for links, all; for routes, only those of responses,
    /// as `nats-server` tells routes none of its import subscriptions.
    pub(crate) fn taps_told(&self, filter: &[u8], to_routes: bool) -> u64 {
        self.interest_of(filter)
            .map_or(0, |i| i.taps_told(to_routes))
    }

    /// Client members of the plain subscriptions of `filter`, or of its
    /// queue group `queue`, on any lane.
    #[cfg(test)]
    pub(crate) fn clients(&self, filter: &[u8], queue: Option<&[u8]>) -> u32 {
        self.group(filter, queue)
            .map_or(0, |g| u32::try_from(g.weight()).unwrap_or(u32::MAX))
    }

    /// Subscription `sid` of client `id`.
    pub(crate) fn find(
        &self,
        filter: &[u8],
        queue: Option<&[u8]>,
        id: u64,
        sid: &[u8],
    ) -> Option<&Entry> {
        self.group(filter, queue)?
            .local
            .iter()
            .find(|e| e.client.id == id && *e.sid == *sid && e.shadow.is_none())
    }

    /// Members of the plain subscriptions of `filter`, or of its queue
    /// group `queue`, as link `link` tells its hub of them, with the naq
    /// leafs in `leafs`: see [`Group::told`].
    /// For plain interest, the taps of imports count too.
    pub(crate) fn count(&self, filter: &[u8], queue: Option<&[u8]>, link: u64, leafs: u64) -> u32 {
        let taps = if queue.is_none() {
            self.taps_told(filter, false)
        } else {
            0
        };
        self.group(filter, queue).map_or(0, |g| {
            u32::try_from(g.told(filter, link, leafs) + taps).unwrap_or(u32::MAX)
        })
    }

    /// Calls `f` with every filter and its interest.
    pub(crate) fn each(&self, mut f: impl FnMut(&[u8], &Interest)) {
        self.literal.each(&mut f);
        self.wild.each(&mut Vec::new(), &mut f);
    }

    /// The interest of every filter that matches `subject`, if any does.
    #[expect(
        clippy::inline_always,
        reason = "measured: a call here costs every publish"
    )]
    #[inline(always)]
    pub(crate) fn matches(&self, subject: &[u8]) -> Option<Found<'_>> {
        let literal = self.literal.get(subject);
        if self.wild.is_empty() {
            return literal.map(Found::One);
        }
        let mut found = Few::new();
        if let Some(i) = literal {
            found.push(i);
        }
        if subject::has_all_tokens(subject) {
            self.wild.matches(subject, &mut found);
        }
        (!found.is_empty()).then_some(Found::Many(found))
    }

    fn interest(&mut self, filter: &[u8]) -> &mut Interest {
        if subject::is_literal(filter) {
            self.literal.interest(filter)
        } else {
            self.wild.interest(filter)
        }
    }

    /// Applies `f` to the group for `queue` in `filter`, and forgets what
    /// is left empty.
    fn change(&mut self, filter: &[u8], queue: Option<&[u8]>, f: impl FnOnce(&mut Group)) {
        if !subject::is_literal(filter) {
            self.wild.change(filter, |i| {
                i.change(queue, f);
            });
            return;
        }
        self.literal.change(filter, |i| {
            i.change(queue, f);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lanes(idx: &Index, subject: &[u8]) -> Vec<Vec<(usize, u32)>> {
        match idx.matches(subject) {
            None => Vec::new(),
            Some(Found::One(i)) => vec![i.plain.lanes.clone()],
            Some(Found::Many(f)) => f.iter().map(|i| i.plain.lanes.clone()).collect(),
        }
    }

    #[test]
    fn other_lanes_are_counted_until_their_last_subscription_goes() {
        let mut idx = Index::default();
        idx.remote(b"a", None, 1, true);
        idx.remote(b"a", None, 1, true);
        idx.remote(b"a", None, 2, true);
        assert_eq!(lanes(&idx, b"a"), [vec![(1, 2), (2, 1)]]);
        idx.remote(b"a", None, 1, false);
        idx.remote(b"a", None, 2, false);
        assert_eq!(lanes(&idx, b"a"), [vec![(1, 1)]]);
        idx.remote(b"a", None, 3, false);
        idx.remote(b"b", None, 1, false);
        idx.remote(b"a", None, 1, false);
        assert!(idx.matches(b"a").is_none(), "forgotten");
        assert!(idx.literal.is_empty());
    }

    #[test]
    fn a_subject_matches_its_literal_and_wildcard_filters() {
        let mut idx = Index::default();
        for (i, f) in ["a.b", "a.*", "a.>", "*.b", ">", "a.b.c", "a.*.c", "b.*"]
            .iter()
            .enumerate()
        {
            idx.remote(f.as_bytes(), None, i, true);
        }
        let hit = |s: &[u8]| {
            let mut got: Vec<_> = lanes(&idx, s).into_iter().map(|l| l[0].0).collect();
            got.sort_unstable();
            got
        };
        assert_eq!(hit(b"a.b"), [0, 1, 2, 3, 4]);
        assert_eq!(hit(b"a.b.c"), [2, 4, 5, 6]);
        assert_eq!(hit(b"a"), [4]);
        assert_eq!(hit(b"a..b"), Vec::<usize>::new());
        assert_eq!(hit(b"a.b."), Vec::<usize>::new());
        assert_eq!(hit(b"a.*"), [1, 2, 4], "a wildcard published is a token");
    }

    #[test]
    fn links_are_peers_apart_from_client_members() {
        let mut idx = Index::default();
        let p = Peer {
            lane: 1,
            link: 7,
            weight: 3,
            shadow: Peer::DIRECT,
        };
        idx.peer(b"a.*", Some(b"q"), p);
        idx.peer(b"a.*", Some(b"q"), Peer { weight: 5, ..p });
        idx.peer(b"a.b", None, Peer { weight: 1, ..p });
        let groups = match idx.matches(b"a.b") {
            Some(Found::Many(f)) => f
                .iter()
                .map(|i| (i.plain.peers.clone(), i.queues.len()))
                .collect::<Vec<_>>(),
            other => panic!("{other:?}"),
        };
        assert_eq!(groups.len(), 2);
        assert_eq!(
            idx.count(b"a.*", Some(b"q"), 8, 0),
            0,
            "links are told of client members"
        );
        idx.peer(b"$LDS.x", None, Peer { weight: 1, ..p });
        assert_eq!(idx.count(b"$LDS.x", None, 8, 0), 1, "and of loop detection");
        assert_eq!(idx.count(b"$LDS.x", None, 7, 0), 0, "of other links only");
        idx.peer(b"$LDS.x", None, Peer { weight: 0, ..p });
        let Some(Found::Many(f)) = idx.matches(b"a.c") else {
            panic!("a.* matches")
        };
        let g = f.iter().next().unwrap();
        assert_eq!(g.queues[0].1.peers, [Peer { weight: 5, ..p }]);
        idx.peer(b"a.*", Some(b"q"), Peer { weight: 0, ..p });
        idx.peer(b"a.b", None, Peer { weight: 0, ..p });
        idx.peer(b"a.b", None, Peer { weight: 0, ..p });
        assert!(idx.matches(b"a.b").is_none(), "forgotten");
        assert!(idx.wild.is_empty() && idx.literal.is_empty());
    }

    #[test]
    fn servers_of_the_cluster_are_members_apart_from_clients() {
        let mut idx = Index::default();
        idx.server(b"a.*", None, 2, 1);
        idx.server(b"a.*", Some(b"q"), 2, 3);
        idx.server(b"a.*", Some(b"q"), 2, 5);
        idx.server(b"lit", None, 0, 1);
        let Some(Found::Many(f)) = idx.matches(b"a.b") else {
            panic!("a.* matches")
        };
        let i = f.iter().next().unwrap();
        assert_eq!(i.plain.servers, [(2, 1.into())]);
        assert_eq!(i.queues[0].1.servers, [(2, 5.into())]);
        assert_eq!(idx.clients(b"a.*", Some(b"q")), 0, "no client members");
        idx.server(b"a.*", None, 2, 0);
        idx.server(b"a.*", Some(b"q"), 2, 0);
        idx.server(b"lit", None, 0, 0);
        idx.server(b"lit", None, 0, 0);
        assert!(idx.matches(b"a.b").is_none() && idx.matches(b"lit").is_none());
        assert!(idx.wild.is_empty() && idx.literal.is_empty());
    }

    #[test]
    fn every_filter_is_walked_and_counted() {
        let mut idx = Index::default();
        for f in ["a.b", "a.*", "a.>", ">", "*", "a.*.c", "b"] {
            idx.remote(f.as_bytes(), None, 1, true);
        }
        idx.remote(b"a.*", Some(b"q"), 1, true);
        idx.remote(b"a.*", Some(b"q"), 2, true);
        let mut seen = Vec::new();
        idx.each(|f, i| seen.push((String::from_utf8_lossy(f).into_owned(), i.queues.len())));
        seen.sort();
        let want = [
            ("*", 0),
            (">", 0),
            ("a.*", 1),
            ("a.*.c", 0),
            ("a.>", 0),
            ("a.b", 0),
            ("b", 0),
        ];
        assert_eq!(seen, want.map(|(f, q)| (f.to_owned(), q)));
        assert_eq!(idx.count(b"a.*", Some(b"q"), 0, 0), 2);
        assert_eq!(idx.count(b"a.*", None, 0, 0), 1);
        assert_eq!(idx.count(b"a.b", None, 0, 0), 1);
        assert_eq!(idx.count(b"a.b", Some(b"q"), 0, 0), 0);
        assert_eq!(idx.count(b"x", None, 0, 0), 0);
    }

    #[test]
    fn wildcard_filters_are_forgotten_once_empty() {
        let mut idx = Index::default();
        idx.remote(b"a.*.c", None, 1, true);
        idx.remote(b"a.>", Some(b"q"), 1, true);
        idx.remote(b"a.*.c", None, 1, false);
        assert!(!idx.wild.is_empty());
        idx.remote(b"a.>", Some(b"q"), 1, false);
        assert!(idx.wild.is_empty());
    }

    #[test]
    fn queue_groups_are_apart_from_plain_interest() {
        let mut idx = Index::default();
        idx.remote(b"a", Some(b"q"), 1, true);
        idx.remote(b"a", Some(b"q"), 2, true);
        idx.remote(b"a", Some(b"r"), 1, true);
        let Some(Found::One(i)) = idx.matches(b"a") else {
            panic!("one literal match");
        };
        assert!(i.plain.is_empty());
        let w: Vec<_> = i.queues.iter().map(|(n, g)| (&**n, g.weight())).collect();
        assert_eq!(w, [(&b"q"[..], 2), (&b"r"[..], 1)]);
    }

    #[test]
    fn wildcard_subscriptions_are_found_removed_and_counted() {
        let c = Rc::new(Client::new(7));
        let mut idx = Index::default();
        let subs: [(&[u8], Option<&[u8]>); 4] = [
            (b"a.*.c", None),
            (b"a.>", Some(b"q")),
            (b"*.b", None),
            (b">", None),
        ];
        for (i, (f, q)) in subs.iter().enumerate() {
            idx.insert(f, *q, Entry::new(c.clone(), i.to_string().as_bytes()));
        }
        for (i, (f, q)) in subs.iter().enumerate() {
            let sid = i.to_string();
            assert!(idx.find(f, *q, 7, sid.as_bytes()).is_some(), "{i}");
            assert!(idx.find(f, *q, 8, sid.as_bytes()).is_none());
        }
        for (f, q) in [
            (&b"a.*.d"[..], None),
            (b"b.>", None),
            (b"x.*", None),
            (b"a.>", None),
        ] {
            assert!(idx.find(f, q, 7, b"0").is_none());
            idx.remove(f, q, 7, b"0");
        }
        assert!(idx.find(b"a.>", Some(b"r"), 7, b"1").is_none());
        assert_eq!(idx.changes(), (4, 0), "misses remove nothing");
        for (i, (f, q)) in subs.iter().enumerate() {
            idx.remove(f, *q, 7, i.to_string().as_bytes());
        }
        assert!(idx.wild.is_empty());
        assert_eq!(idx.changes(), (4, 4));
    }

    #[test]
    fn few_keeps_order_past_its_inline_room() {
        let items: Vec<u32> = (0..7).collect();
        let mut few = Few::new();
        assert!(few.is_empty());
        for i in &items {
            few.push(i);
        }
        assert_eq!(few.iter().copied().collect::<Vec<_>>(), items);
    }
}
