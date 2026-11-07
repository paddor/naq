//! What monitoring knows of connections: the open ones, as their lanes
//! tell them, and a ring of those that closed, as `nats-server` keeps it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use super::accstatz::Traffic;
use super::query::Subs;
use crate::conn::Client;
use crate::lane::Lane;
use crate::stats::Totals;

/// One connection, open or closed, as `/connz` shows it.
#[derive(Debug, Clone)]
pub(super) struct Conn {
    pub(super) cid: u64,
    /// A link to a hub, not a client.
    pub(super) leaf: bool,
    pub(super) websocket: bool,
    pub(super) ip: String,
    pub(super) port: u16,
    pub(super) start: SystemTime,
    pub(super) last: SystemTime,
    /// When it closed, and why, if it did.
    pub(super) stop: Option<(SystemTime, &'static str)>,
    pub(super) rtt: Duration,
    pub(super) pending: usize,
    pub(super) totals: Totals,
    pub(super) stalls: u64,
    /// How many subscriptions it has, and those asked for.
    pub(super) nsubs: usize,
    pub(super) subs: Vec<Sub>,
    pub(super) name: String,
    pub(super) lang: String,
    pub(super) version: String,
    pub(super) tls: Option<Box<crate::tls::Facts>>,
    pub(super) login: Login,
}

/// Who a connection logged in as.
#[derive(Debug, Clone, Default)]
pub(super) struct Login {
    /// Its user, as `nats-server` names it in monitoring.
    pub(super) user: String,
    /// Its account's name.
    pub(super) account: String,
    /// The key that issued its user: for a JWT, the signer; for an NKey,
    /// its account.
    pub(super) issuer: String,
    pub(super) jwt: Option<Box<crate::jwt::trust::Shown>>,
}

/// One subscription of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Sub {
    pub(super) subject: String,
    pub(super) queue: Option<String>,
    pub(super) sid: String,
    /// Messages it got, and the most it may; 0 for no limit.
    pub(super) msgs: u64,
    pub(super) max: u64,
}

/// What `/connz` asks a lane for.
#[derive(Debug, Clone)]
pub(super) struct Want {
    /// One connection, if not 0.
    pub(super) cid: u64,
    /// The connections of one account, if any.
    pub(super) account: Option<u32>,
    /// The connections of one user, if not empty.
    pub(super) user: String,
    pub(super) subs: Subs,
}

impl Want {
    fn takes(&self, cid: u64, account: u32, user: &str) -> bool {
        (self.cid == 0 || self.cid == cid)
            && self.account.is_none_or(|a| a == account)
            && (self.user.is_empty() || self.user == user)
    }
}

/// The open connections of `lane` that `want` asks for, its clients and
/// its links to hubs, and how many of them are in the account it asks
/// for: `nats-server` counts those as the total.
pub(super) fn open(lane: &Lane, want: &Want) -> (usize, Vec<Conn>) {
    let in_account = |a: u32| want.account.is_none_or(|w| w == a);
    let clients = lane.clients.borrow();
    let links = lane.links.borrow();
    let mut total = 0;
    let mut all = Vec::new();
    for c in clients.values().filter(|c| in_account(c.account.get())) {
        total += 1;
        if want.takes(c.id, c.account.get(), c.meta.borrow().raw_user()) {
            all.push(client(lane, c, want.subs));
        }
    }
    for l in links.iter().filter(|l| in_account(l.account)) {
        total += 1;
        if want.takes(l.id, l.account, "") {
            all.push(link(lane, l, want.subs));
        }
    }
    (total, all)
}

/// Client `c` of `lane`, with as much of its subscriptions as `subs` asks.
fn client(lane: &Lane, c: &Client, subs: Subs) -> Conn {
    let meta = c.meta.borrow();
    let account = c.account.get();
    let accounts = &lane.shared.accounts;
    let issuer = match (&meta.jwt, meta.how) {
        (Some(j), _) => j.issuer.clone(),
        (None, Some(crate::conn::How::Nkey)) => accounts.name(account).to_owned(),
        _ => String::new(),
    };
    Conn {
        cid: c.id,
        leaf: false,
        websocket: meta.websocket,
        ip: meta.ip.clone(),
        port: meta.port,
        start: meta.start,
        last: c.seen.last_at(meta.start),
        stop: None,
        rtt: c.rtt.get(),
        pending: c.out.borrow().len(),
        totals: c.tally.totals(),
        stalls: c.seen.stalls.get(),
        nsubs: c.subs.borrow().len(),
        subs: if subs == Subs::None {
            Vec::new()
        } else {
            subs_of(lane, c)
        },
        name: meta.name.clone().unwrap_or_default(),
        lang: meta.lang.clone().unwrap_or_default(),
        version: meta.version.clone().unwrap_or_default(),
        tls: meta.tls.clone(),
        login: Login {
            user: meta.raw_user().to_owned(),
            account: accounts.name(account).to_owned(),
            issuer,
            jwt: meta.jwt.clone(),
        },
    }
}

/// The subscriptions of client `c` of `lane`, with what its index knows
/// of them.
fn subs_of(lane: &Lane, c: &Client) -> Vec<Sub> {
    let index = lane.index(c.account.get()).borrow();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    c.subs
        .borrow()
        .iter()
        .map(|(sid, s)| {
            let e = index.find(&s.subject, s.queue.as_deref(), c.id, sid);
            Sub {
                subject: text(&s.subject),
                queue: s.queue.as_deref().map(text),
                sid: text(sid),
                msgs: e.map_or(0, |e| e.delivered.get()),
                max: e.map_or(0, |e| e.max.get()),
            }
        })
        .collect()
}

/// Link `l` of `lane` to a hub, with the subjects of its hub's interest
/// if `subs` asks.
fn link(lane: &Lane, l: &crate::leaf::LinkSide, subs: Subs) -> Conn {
    let c = &l.client;
    let meta = c.meta.borrow();
    let hub = l.hub_subjects();
    Conn {
        cid: l.id,
        leaf: true,
        websocket: false,
        ip: l.facts.ip.clone(),
        port: l.facts.port,
        start: meta.start,
        last: c.seen.last_at(meta.start),
        stop: None,
        rtt: c.rtt.get(),
        pending: c.out.borrow().len(),
        totals: c.tally.totals(),
        stalls: 0,
        nsubs: hub.len(),
        subs: if subs == Subs::None {
            Vec::new()
        } else {
            hub.into_iter()
                .map(|subject| Sub {
                    subject,
                    queue: None,
                    sid: String::new(),
                    msgs: 0,
                    max: 0,
                })
                .collect()
        },
        name: l.facts.name.clone(),
        lang: String::new(),
        version: String::new(),
        tls: None,
        login: Login {
            account: lane.shared.accounts.name(l.account).to_owned(),
            ..Login::default()
        },
    }
}

/// The connections that closed, newest last, as many as the server keeps.
#[derive(Debug)]
pub(crate) struct Closed {
    ring: Mutex<VecDeque<Arc<Conn>>>,
    most: usize,
}

impl Closed {
    /// A ring of the last `most` closed connections; 0 keeps 10000, as
    /// `nats-server` does.
    pub(crate) const fn new(most: usize) -> Closed {
        let most = if most == 0 { 10_000 } else { most };
        Closed {
            ring: Mutex::new(VecDeque::new()),
            most,
        }
    }

    fn push(&self, c: Conn) {
        // A poisoned lock still holds the ring.
        let mut ring = self
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if ring.len() == self.most {
            ring.pop_front();
        }
        ring.push_back(Arc::new(c));
    }

    /// The closed connections, oldest first.
    pub(super) fn all(&self) -> Vec<Arc<Conn>> {
        let ring = self
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ring.iter().cloned().collect()
    }
}

/// Keeps client `c` of `lane`, closed now for `why`, among the closed
/// connections: with its subscriptions, as it has them still.
pub(crate) fn closed(lane: &Lane, c: &Client, why: &'static str) {
    let now = SystemTime::now();
    let mut conn = client(lane, c, Subs::Detail);
    conn.stop = Some((now, why));
    // Go keeps no peer certificates of a closed connection.
    if let Some(t) = &mut conn.tls {
        t.peers.clear();
    }
    let traffic = Traffic::closed(conn.totals, false, why);
    lane.shared.monitor.gone.add(c.account.get(), traffic);
    lane.shared.monitor.closed.push(conn);
}

/// Keeps link `l` of `lane`, closed now for `why`, among the closed
/// connections.
pub(crate) fn link_closed(lane: &Lane, l: &crate::leaf::LinkSide, why: &'static str) {
    let mut conn = link(lane, l, Subs::Detail);
    conn.stop = Some((SystemTime::now(), why));
    let traffic = Traffic::closed(conn.totals, true, why);
    lane.shared.monitor.gone.add(l.account, traffic);
    lane.shared.monitor.closed.push(conn);
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A connection of ID `cid` and nothing else.
    pub(in crate::monitor) fn conn(cid: u64) -> Conn {
        Conn {
            cid,
            leaf: false,
            websocket: false,
            ip: String::new(),
            port: 0,
            start: SystemTime::UNIX_EPOCH,
            last: SystemTime::UNIX_EPOCH,
            stop: None,
            rtt: Duration::ZERO,
            pending: 0,
            totals: Totals::default(),
            stalls: 0,
            nsubs: 0,
            subs: Vec::new(),
            name: String::new(),
            lang: String::new(),
            version: String::new(),
            tls: None,
            login: Login::default(),
        }
    }

    #[test]
    fn the_ring_keeps_the_newest() {
        let ring = Closed::new(2);
        for cid in 1..=3 {
            ring.push(conn(cid));
        }
        let cids: Vec<u64> = ring.all().iter().map(|c| c.cid).collect();
        assert_eq!(cids, [2, 3]);
        assert_eq!(Closed::new(0).most, 10_000);
    }

    #[test]
    fn a_want_filters_by_id_account_and_user() {
        let mut w = Want {
            cid: 0,
            account: None,
            user: String::new(),
            subs: Subs::None,
        };
        assert!(w.takes(1, 0, ""));
        w.cid = 2;
        assert!(!w.takes(1, 0, "") && w.takes(2, 0, ""));
        w.account = Some(3);
        assert!(!w.takes(2, 0, "") && w.takes(2, 3, ""));
        w.user = "u".into();
        assert!(!w.takes(2, 3, "v") && w.takes(2, 3, "u"));
    }
}
