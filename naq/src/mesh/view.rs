//! What each kind of server is told of this one's interest, as the
//! index and the slots have it now.

use super::Peer;
use super::told::ByOrigin;
use crate::index::Index;
use crate::lane::{Slots, bit};

/// What the routes hear of the interest in `filter`, in `queue` if given:
/// the members of clients, and those of the leafs of each cluster, as
/// `nats-server` tells its routes of leaf interest with its origin. Plain
/// interest is there or not; a queue group tells its member count.
pub(super) fn routes(
    index: &Index,
    slots: &Slots,
    filter: &[u8],
    queue: Option<&[u8]>,
) -> ByOrigin {
    let Some(g) = index.group(filter, queue) else {
        return Vec::new();
    };
    let mut all: ByOrigin = Vec::new();
    let clients = u32::try_from(g.weight()).unwrap_or(u32::MAX);
    if clients > 0 {
        all.push((None, clients));
    }
    let leafs = slots.leafs();
    for &(s, w) in g.servers.iter().filter(|&&(s, _)| leafs & bit(s) != 0) {
        let Some(l) = slots.linked(s) else {
            continue;
        };
        match all
            .iter_mut()
            .find(|(o, _)| o.as_deref() == Some(&*l.cluster))
        {
            Some((_, sum)) => *sum = sum.saturating_add(w),
            None => all.push((Some(l.cluster), w)),
        }
    }
    if queue.is_none() {
        for (_, w) in &mut all {
            *w = 1;
        }
    }
    all
}

/// What a naq hub hears of the interest in `filter`, in `queue` if given:
/// the members of clients and of leafs, as a Go leaf tells its hub.
pub(super) fn hub(index: &Index, slots: &Slots, filter: &[u8], queue: Option<&[u8]>) -> ByOrigin {
    one(
        u64::from(index.count(filter, queue, 0, slots.leafs())),
        queue,
    )
}

/// The interest a naq leaf hears of.
#[derive(Debug, Clone, Copy)]
pub(super) struct ForLeaf<'a> {
    /// The leaf's slot.
    pub(super) slot: u16,
    /// Its cluster, empty for none.
    pub(super) cluster: &'a [u8],
    /// The name of the account its link binds.
    pub(super) account: &'a [u8],
    /// The routes, whose interest names the leaf cluster it is of.
    pub(super) routes: &'a [Peer],
}

/// What naq leaf `leaf` hears of the interest in `filter`, in `queue` if
/// given: all of it, of clients, routes, hubs and links, but its own and,
/// unless it has none, that of its cluster, at this server or at its
/// routes, as `nats-server` keeps it from a leaf cluster.
pub(super) fn leaf(
    index: &Index,
    slots: &Slots,
    leaf: ForLeaf<'_>,
    filter: &[u8],
    queue: Option<&[u8]>,
) -> ByOrigin {
    let Some(g) = index.group(filter, queue) else {
        return Vec::new();
    };
    let skips = bit(leaf.slot) | slots.of_cluster(leaf.cluster);
    let servers = g.servers.iter().filter(|&&(s, _)| skips & bit(s) == 0);
    let mut n = g.weight() + servers.map(|&(_, w)| u64::from(w)).sum::<u64>();
    n += g.peers.iter().map(|p| u64::from(p.weight)).sum::<u64>();
    if !leaf.cluster.is_empty() {
        for &(s, _) in g.servers.iter().filter(|&&(s, _)| slots.is_route(s)) {
            let of_cluster = leaf.routes.get(usize::from(s)).map_or(0, |r| {
                r.heard.of_origin(leaf.account, filter, queue, leaf.cluster)
            });
            n = n.saturating_sub(u64::from(of_cluster));
        }
    }
    one(n, queue)
}

/// `n` members from no origin: plain interest is there or not, a queue
/// group tells its member count.
fn one(n: u64, queue: Option<&[u8]>) -> ByOrigin {
    match (n, queue) {
        (0, _) => Vec::new(),
        (_, None) => vec![(None, 1)],
        (n, Some(_)) => vec![(None, u32::try_from(n).unwrap_or(u32::MAX))],
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use naq_proto::peer::{Control, Hello, Interest, Role};

    use super::*;
    use crate::conn::Client;
    use crate::index::Entry;
    use crate::lane::Linked;

    #[test]
    fn routes_hear_of_clients_and_of_leafs_by_cluster() {
        let slots = Slots::new(1, 0);
        let x: Rc<[u8]> = Rc::from(&b"x"[..]);
        for s in [1, 2] {
            slots.link(
                s,
                Linked {
                    id: Rc::from(&[s as u8][..]),
                    cluster: x.clone(),
                    account: 0,
                },
            );
        }
        let mut idx = Index::default();
        let c = Rc::new(Client::new(1));
        assert_eq!(routes(&idx, &slots, b"a", None), ByOrigin::new());
        idx.insert(b"a", None, Entry::new(c.clone(), b"1"));
        idx.insert(b"a", None, Entry::new(c.clone(), b"2"));
        assert_eq!(routes(&idx, &slots, b"a", None), [(None, 1)]);
        idx.insert(b"a", Some(b"q"), Entry::new(c, b"3"));
        for (s, w) in [(0, 4), (1, 2), (2, 3)] {
            idx.server(b"a", Some(b"q"), s, w);
        }
        assert_eq!(
            routes(&idx, &slots, b"a", Some(b"q")),
            [(None, 1), (Some(x.clone()), 5)],
            "not the route's members"
        );
        idx.server(b"a", None, 1, 1);
        idx.remove(b"a", None, 1, b"1");
        idx.remove(b"a", None, 1, b"2");
        assert_eq!(routes(&idx, &slots, b"a", None), [(Some(x), 1)]);
    }

    /// A route that told of `i` alone.
    fn route_with(i: Interest<'_>) -> Peer {
        let mut route = Peer::default();
        let mut apply = |_: super::super::interest::Change<'_>| {};
        let hello = Hello {
            role: Role::Route,
            account: b"",
            epoch: 1,
            server_id: b"",
            name: b"",
            cluster: b"",
            data: b"",
            client_urls: b"",
            leaf_urls: b"",
        };
        for c in [
            Control::Hello(hello),
            Control::SnapshotStart { epoch: 1, seq: 0 },
            Control::Entry(i),
            Control::SnapshotEnd { epoch: 1 },
        ] {
            route.heard.take(&c, &mut apply);
        }
        route
    }

    #[test]
    fn a_leaf_hears_of_all_but_its_own_and_its_cluster() {
        let slots = Slots::new(1, 1);
        let link = |s: u16, cluster: &[u8]| {
            slots.link(
                s,
                Linked {
                    id: Rc::from(&[s as u8][..]),
                    cluster: cluster.into(),
                    account: 0,
                },
            );
        };
        link(2, b"x");
        link(3, b"x");
        link(4, b"");
        let mut idx = Index::default();
        for (s, w) in [(0, 7), (1, 1), (2, 2), (3, 4), (4, 8)] {
            idx.server(b"a", Some(b"q"), s, w);
        }
        let of = |slot, cluster| ForLeaf {
            slot,
            cluster,
            account: b"$G",
            routes: &[],
        };
        let at = |l| leaf(&idx, &slots, l, b"a", Some(b"q"));
        assert_eq!(at(of(2, b"x")), [(None, 16)], "not slots 2 and 3");
        assert_eq!(at(of(4, b"")), [(None, 14)], "all but its own");
        let route = route_with(Interest {
            account: b"$G",
            subject: b"a",
            queue: Some(b"q"),
            weight: 5,
            origin: Some(b"x"),
        });
        let with_route = leaf(
            &idx,
            &slots,
            ForLeaf {
                routes: &[route],
                ..of(2, b"x")
            },
            b"a",
            Some(b"q"),
        );
        assert_eq!(with_route, [(None, 11)], "nor its cluster at the route");
        assert_eq!(hub(&idx, &slots, b"a", Some(b"q")), [(None, 14)]);
        idx.server(b"p", None, 0, 1);
        assert!(hub(&idx, &slots, b"p", None).is_empty(), "no route's");
        assert_eq!(leaf(&idx, &slots, of(2, b"x"), b"p", None), [(None, 1)]);
    }
}
