//! `/accstatz`: the connections of each account, and what they sent and
//! got, as `nats-server` counts them.

use std::sync::{Mutex, PoisonError};

use rustc_hash::FxHashMap;
use serde::Serialize;

use super::http::Response;
use super::query::{Query, Refused};
use super::{Counted, accountz, ask_all, now, pretty, subsz};
use crate::lane::Lane;
use crate::server::Shared;
use crate::stats::Totals;

/// What connections of an account did.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Traffic {
    /// Of all of them: clients and links. In is what they published.
    all: Totals,
    /// Of its links.
    leafs: Totals,
    /// Times one was a slow consumer.
    slow: u64,
}

impl std::ops::AddAssign for Traffic {
    fn add_assign(&mut self, t: Traffic) {
        self.all += t.all;
        self.leafs += t.leafs;
        self.slow += t.slow;
    }
}

impl Traffic {
    /// Of a connection that passed `t` and closed for `why`; a link if
    /// `leaf`.
    pub(super) fn closed(t: Totals, leaf: bool, why: &str) -> Traffic {
        Traffic {
            all: t,
            leafs: if leaf { t } else { Totals::default() },
            slow: u64::from(why.starts_with("Slow Consumer")),
        }
    }
}

/// What the connections of each account that closed did, by id.
#[derive(Debug, Default)]
pub(super) struct Gone(Mutex<FxHashMap<u32, Traffic>>);

impl Gone {
    /// Adds `t`, of a connection of `account` that closed.
    pub(super) fn add(&self, account: u32, t: Traffic) {
        // A poisoned lock still holds the counts.
        *self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(account)
            .or_default() += t;
    }

    /// What the connections of `account` that closed did.
    fn of(&self, account: u32) -> Traffic {
        let gone = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        gone.get(&account).copied().unwrap_or_default()
    }
}

/// What a lane has of one account.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Use {
    pub(super) clients: usize,
    pub(super) leafs: usize,
    /// Subscriptions in its index, and those added and removed.
    pub(super) subs: u64,
    pub(super) inserts: u64,
    pub(super) removes: u64,
    /// What its open connections did.
    traffic: Traffic,
}

impl std::ops::AddAssign for Use {
    fn add_assign(&mut self, u: Use) {
        self.clients += u.clients;
        self.leafs += u.leafs;
        self.subs += u.subs;
        self.inserts += u.inserts;
        self.removes += u.removes;
        self.traffic += u.traffic;
    }
}

/// The accounts a request is about.
#[derive(Debug, Clone, Copy)]
pub(super) enum Which {
    /// The first so many.
    All(u32),
    /// The one of this id.
    One(u32),
}

impl Which {
    /// Their ids, in order.
    const fn ids(self) -> std::ops::Range<u32> {
        match self {
            Which::All(n) => 0..n,
            Which::One(id) => id..id.saturating_add(1),
        }
    }

    /// How many they are.
    const fn len(self) -> usize {
        let ids = self.ids();
        (ids.end - ids.start) as usize
    }

    /// The place of account `a` among them, if it is one.
    fn at(self, a: u32) -> Option<usize> {
        let ids = self.ids();
        ids.contains(&a).then(|| (a - ids.start) as usize)
    }
}

/// What a lane finds of some accounts.
#[derive(Debug)]
struct Found {
    /// By place among the accounts.
    uses: Vec<Use>,
    /// Messages of naq hubs and leafs on the lane, by slot.
    slots: Vec<(u16, Totals)>,
    /// On lane 0, the naq links that are up: their slots, and the places
    /// of their accounts.
    links: Vec<(u16, usize)>,
}

/// What `lane` has of the accounts of `which`.
fn found(lane: &Lane, which: Which) -> Found {
    let mut uses = vec![Use::default(); which.len()];
    for c in lane.clients.borrow().values() {
        if let Some(i) = which.at(c.account.get()) {
            uses[i].clients += 1;
            uses[i].traffic.all += c.tally.totals();
        }
    }
    for l in lane.links.borrow().iter() {
        if let Some(i) = which.at(l.account) {
            let t = l.client.tally.totals();
            uses[i].leafs += 1;
            uses[i].traffic.all += t;
            uses[i].traffic.leafs += t;
        }
    }
    let mut links = Vec::new();
    if let Some(mesh) = lane.mesh.borrow().as_ref() {
        let leafs = mesh.leafs.borrow();
        let hubs = mesh.hubs.borrow();
        let up = leafs.iter().map(|l| (l.slot, l.account));
        let up = up.chain(hubs.iter().filter(|h| h.up).map(|h| (h.slot, h.account)));
        for (slot, a) in up {
            if let Some(i) = which.at(a) {
                uses[i].leafs += 1;
                links.push((slot, i));
            }
        }
    }
    for (a, u) in which.ids().zip(&mut uses) {
        let f = subsz::found(lane, &[a], false, b"");
        (u.subs, u.inserts, u.removes) = (f.subs, f.inserts, f.removes);
    }
    Found {
        uses,
        slots: lane.slots.totals(),
        links,
    }
}

/// What every lane has of the accounts of `which`, by place: what their
/// connections did since the server started, and the subscriptions
/// `nats-server` counts.
pub(super) async fn uses(shared: &Shared, which: Which) -> Vec<Use> {
    let lanes = ask_all(shared, move |lane| found(lane, which)).await;
    let mut all = vec![Use::default(); which.len()];
    let links: Vec<(u16, usize)> = lanes.iter().flat_map(|f| f.links.clone()).collect();
    for f in &lanes {
        for (u, &f) in all.iter_mut().zip(&f.uses) {
            *u += f;
        }
        for &(slot, t) in &f.slots {
            for &(_, i) in links.iter().filter(|(s, _)| *s == slot) {
                all[i].traffic.all += t;
                all[i].traffic.leafs += t;
            }
        }
    }
    for (a, u) in which.ids().zip(&mut all) {
        u.traffic += shared.monitor.gone.of(a);
        let extra = subsz::extra(shared, a);
        u.subs += extra;
        u.inserts += extra;
    }
    all
}

/// Messages and their bytes.
#[derive(Debug, Serialize)]
struct MsgBytes {
    msgs: u64,
    bytes: u64,
}

/// Messages one way, in all and over each kind of peer.
#[derive(Debug, Serialize)]
struct DataStats {
    msgs: u64,
    bytes: u64,
    gateways: MsgBytes,
    routes: MsgBytes,
    leafs: MsgBytes,
}

impl DataStats {
    /// `msgs` and `bytes` in all, `leaf_msgs` and `leaf_bytes` of them
    /// over links.
    const fn of(msgs: u64, bytes: u64, leaf_msgs: u64, leaf_bytes: u64) -> DataStats {
        DataStats {
            msgs,
            bytes,
            gateways: MsgBytes { msgs: 0, bytes: 0 },
            routes: MsgBytes { msgs: 0, bytes: 0 },
            leafs: MsgBytes {
                msgs: leaf_msgs,
                bytes: leaf_bytes,
            },
        }
    }
}

/// One account, as `/accstatz` shows it.
#[derive(Debug, Serialize)]
struct AccountStat<'a> {
    acc: &'a str,
    name: String,
    conns: usize,
    leafnodes: usize,
    total_conns: usize,
    num_subscriptions: u64,
    sent: DataStats,
    received: DataStats,
    slow_consumers: u64,
}

impl AccountStat<'_> {
    fn of<'a>(shared: &'a Shared, name: &'a str, u: &Use) -> AccountStat<'a> {
        let (all, leafs) = (u.traffic.all, u.traffic.leafs);
        AccountStat {
            acc: name,
            name: accountz::name_tag(shared, name),
            conns: u.clients,
            leafnodes: u.leafs,
            total_conns: u.clients + u.leafs,
            num_subscriptions: u.subs,
            sent: DataStats::of(all.out_msgs, all.out_bytes, leafs.out_msgs, leafs.out_bytes),
            received: DataStats::of(all.in_msgs, all.in_bytes, leafs.in_msgs, leafs.in_bytes),
            slow_consumers: u.traffic.slow,
        }
    }
}

#[derive(Debug, Serialize)]
#[expect(clippy::struct_field_names, reason = "the keys nats-server writes")]
struct AccountStatz<'a> {
    server_id: &'a str,
    now: String,
    account_statz: Vec<AccountStat<'a>>,
}

/// `/accstatz`: the accounts with connections here, every one if
/// `unused`.
pub(super) async fn answer(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    shared.monitor.count(Counted::Accstatz);
    let unused = q.bool("unused")?;
    let all = uses(shared, Which::All(shared.accounts.len())).await;
    let stats = shared
        .accounts
        .iter()
        .zip(&all)
        .filter(|((_, a), u)| {
            (unused || u.clients + u.leafs > 0) && accountz::in_use(shared, &a.name)
        })
        .map(|((_, a), u)| AccountStat::of(shared, &a.name, u))
        .collect();
    Ok(pretty(&AccountStatz {
        server_id: &shared.server_id,
        now: now(),
        account_statz: stats,
    }))
}
