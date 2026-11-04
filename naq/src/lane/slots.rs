//! The servers a lane reaches over OMQ, by slot: the routes of its
//! cluster first, then the naq hubs it dials, then the naq leafs that dial
//! it. A slot is a server of [`crate::index::Group::servers`]; its kind
//! decides where the messages it sends go, and what it hears of.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// Slots in all: their bits fit a `u64`.
pub(crate) const SLOTS: usize = 64;

/// The bit of slot `s`.
#[inline]
pub(crate) const fn bit(s: u16) -> u64 {
    1 << (s as u64 % SLOTS as u64)
}

/// A naq hub or leaf linked in a slot.
#[derive(Debug, Clone)]
pub(crate) struct Linked {
    /// The routing identity of the leaf's control connection, which names
    /// its data channels too.
    pub(crate) id: Rc<[u8]>,
    /// Its cluster, empty for none.
    pub(crate) cluster: Rc<[u8]>,
    /// The account its link binds here.
    pub(crate) account: u32,
}

/// The slots of a lane's server.
#[derive(Debug, Default)]
pub(crate) struct Slots {
    /// Routes, as bits.
    routes: u64,
    /// naq hubs, as bits.
    hubs: u64,
    /// naq leafs linked now, as bits.
    leafs: Cell<u64>,
    /// The hub or leaf in each slot, by slot.
    by_slot: RefCell<Vec<Option<Linked>>>,
}

impl Slots {
    /// Slots for `routes` routes, then `hubs` naq hubs.
    pub(crate) fn new(routes: usize, hubs: usize) -> Slots {
        let ones = |n: usize| if n >= SLOTS { u64::MAX } else { (1 << n) - 1 };
        Slots {
            routes: ones(routes),
            hubs: ones(routes + hubs) & !ones(routes),
            leafs: Cell::new(0),
            by_slot: RefCell::default(),
        }
    }

    /// The first slot of naq leafs.
    pub(crate) const fn first_leaf(&self) -> u16 {
        (self.routes | self.hubs).count_ones() as u16
    }

    /// Puts hub or leaf `linked` in slot `s`, which is not a route's.
    pub(crate) fn link(&self, s: u16, linked: Linked) {
        let mut all = self.by_slot.borrow_mut();
        let at = usize::from(s);
        if all.len() <= at {
            all.resize(at + 1, None);
        }
        all[at] = Some(linked);
        if self.hubs & bit(s) == 0 {
            self.leafs.set(self.leafs.get() | bit(s));
        }
    }

    /// Empties slot `s`.
    pub(crate) fn unlink(&self, s: u16) {
        if let Some(slot) = self.by_slot.borrow_mut().get_mut(usize::from(s)) {
            *slot = None;
        }
        self.leafs.set(self.leafs.get() & !bit(s));
    }

    /// The hub or leaf in slot `s`, if one.
    pub(crate) fn linked(&self, s: u16) -> Option<Linked> {
        self.by_slot.borrow().get(usize::from(s)).cloned().flatten()
    }

    /// The slot of the leaf of control identity `id`, if one is linked.
    pub(crate) fn find(&self, id: &[u8]) -> Option<u16> {
        let all = self.by_slot.borrow();
        let at = all
            .iter()
            .position(|l| l.as_ref().is_some_and(|l| *l.id == *id))?;
        // Slots are below 64: they fit.
        Some(at as u16)
    }

    /// Whether slot `s` is a route's.
    #[inline]
    pub(crate) const fn is_route(&self, s: u16) -> bool {
        self.routes & bit(s) != 0
    }

    /// Whether slot `s` is a naq hub's.
    #[inline]
    pub(crate) const fn is_hub(&self, s: u16) -> bool {
        self.hubs & bit(s) != 0
    }

    /// The naq leafs linked now, as bits.
    #[inline]
    pub(crate) const fn leafs(&self) -> u64 {
        self.leafs.get()
    }

    /// Hubs and leafs, as bits: their queue members get a message only
    /// when there is none elsewhere.
    #[inline]
    pub(crate) const fn fallback(&self) -> u64 {
        self.hubs | self.leafs.get()
    }

    /// The leafs of cluster `cluster`, as bits; none for an empty one.
    pub(crate) fn of_cluster(&self, cluster: &[u8]) -> u64 {
        if cluster.is_empty() {
            return 0;
        }
        let all = self.by_slot.borrow();
        let mut bits = 0;
        for (s, l) in all.iter().enumerate() {
            if l.as_ref().is_some_and(|l| *l.cluster == *cluster) {
                // Slots are below 64: they fit.
                bits |= bit(s as u16);
            }
        }
        bits & self.leafs.get()
    }

    /// The slots a message of a route skips, from a leaf of cluster
    /// `origin` if one: other routes, hubs, and that cluster's leafs, which
    /// got it there.
    pub(crate) fn route_skips(&self, origin: Option<&[u8]>) -> u64 {
        self.routes | self.hubs | origin.map_or(0, |o| self.of_cluster(o))
    }

    /// The slots a message of a Go hub skips: routes, as every server
    /// links to the hub of its own.
    #[inline]
    pub(crate) const fn go_hub_skips(&self) -> u64 {
        self.routes
    }

    /// The slots a message of the naq hub in slot `s` skips: routes, and
    /// that hub.
    pub(crate) const fn hub_skips(&self, s: u16) -> u64 {
        self.routes | bit(s)
    }

    /// The slots a message of the naq leaf in slot `s` skips: that leaf,
    /// and the others of its cluster, which got it there.
    pub(crate) fn leaf_skips(&self, s: u16) -> u64 {
        bit(s) | self.linked(s).map_or(0, |l| self.of_cluster(&l.cluster))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(cluster: &[u8]) -> Linked {
        Linked {
            id: cluster.into(),
            cluster: cluster.into(),
            account: 0,
        }
    }

    #[test]
    fn routes_come_first_then_hubs_then_leafs() {
        let s = Slots::new(2, 1);
        assert_eq!(s.first_leaf(), 3);
        assert!(s.is_route(1) && !s.is_route(2));
        assert!(s.is_hub(2) && !s.is_hub(3));
        assert_eq!(s.go_hub_skips(), 0b11);
        assert_eq!(s.route_skips(None), 0b111);
        assert_eq!(s.hub_skips(2), 0b111);
        s.link(2, of(b"x"));
        s.link(3, of(b"x"));
        s.link(5, of(b"x"));
        s.link(4, of(b""));
        assert_eq!(s.leafs(), 0b11_1000, "the hub is no leaf");
        assert_eq!(s.fallback(), 0b11_1100);
        assert_eq!(s.of_cluster(b"x"), 0b10_1000);
        assert_eq!(s.of_cluster(b""), 0, "leafs of no cluster are apart");
        assert_eq!(s.route_skips(Some(b"x")), 0b10_1111);
        assert_eq!(s.leaf_skips(3), 0b10_1000);
        assert_eq!(s.leaf_skips(4), 0b1_0000);
        assert_eq!(s.find(b"x"), Some(2), "the first of that identity");
        assert_eq!(s.find(b"y"), None);
        s.unlink(3);
        assert!(s.linked(3).is_none() && s.linked(5).is_some());
        assert_eq!(s.of_cluster(b"x"), 0b10_0000);
        assert_eq!(Slots::new(SLOTS, 0).route_skips(None), u64::MAX);
    }
}
