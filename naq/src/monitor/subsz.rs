//! `/subsz`: the subscriptions of the accounts, as `nats-server` counts
//! and lists them.

use naq_proto::subject;
use serde::Serialize;

use super::connz::SubDetail;
use super::http::Response;
use super::query::{Query, Refused};
use super::{Counted, ask_all, now, pretty, text};
use crate::index::{Entry, Group, Interest};
use crate::lane::Lane;
use crate::server::Shared;

/// Subscriptions listed at most, unless a request asks otherwise.
const LIMIT: i64 = 1024;

/// What a lane finds of the subscriptions of some accounts.
#[derive(Debug, Default)]
pub(super) struct Found {
    /// Subscriptions in its index: of its clients, and on lane 0 those of
    /// routes and links, which every lane has.
    pub(super) subs: u64,
    /// Subscriptions of its clients added and removed so far.
    pub(super) inserts: u64,
    pub(super) removes: u64,
    list: Vec<Listed>,
}

/// One subscription of a client, as listed.
#[derive(Debug)]
struct Listed {
    account: String,
    /// The name its account goes by.
    tag: String,
    subject: String,
    queue: Option<String>,
    sid: String,
    msgs: u64,
    max: u64,
    cid: u64,
}

/// The groups of `i`: its plain subscriptions, then each queue group.
fn groups(i: &Interest) -> impl Iterator<Item = (Option<&[u8]>, &Group)> {
    std::iter::once((None, &i.plain)).chain(i.queues.iter().map(|(n, g)| (Some(&**n), g)))
}

/// The subscriptions of `accounts` on `lane`; those of its clients listed
/// if `list`, and only those that take a message on `test`, if not
/// empty.
pub(super) fn found(lane: &Lane, accounts: &[u32], list: bool, test: &[u8]) -> Found {
    let mut f = Found::default();
    for &a in accounts {
        let index = lane.index(a).borrow();
        let (inserts, removes) = index.changes();
        f.inserts += inserts;
        f.removes += removes;
        index.each(|filter, i| {
            let listed = list && (test.is_empty() || subject::matches(filter, test));
            for (queue, g) in groups(i) {
                let others = if lane.id == 0 {
                    g.servers.len() + g.peers.len()
                } else {
                    0
                };
                // Lengths fit.
                f.subs += (g.local.len() + others) as u64;
                if listed {
                    f.list
                        .extend(g.local.iter().map(|e| listed_of(lane, filter, queue, e)));
                }
            }
        });
    }
    f
}

/// Subscription `e` of `lane` to `filter`, in `queue` if given, as listed.
fn listed_of(lane: &Lane, filter: &[u8], queue: Option<&[u8]>, e: &Entry) -> Listed {
    let c = &e.client;
    let account = lane.shared.accounts.name(c.account.get()).to_owned();
    let tag = c
        .meta
        .borrow()
        .jwt
        .as_ref()
        .map_or_else(|| account.clone(), |j| j.account_name.clone());
    Listed {
        account,
        tag,
        subject: text(filter),
        queue: queue.map(text),
        sid: text(&e.sid),
        msgs: e.delivered.get(),
        max: e.max.get(),
        cid: c.id,
    }
}

/// The subscriptions `nats-server` has in account `id` that naq's index
/// does not: one for each service import, and one for the replies of
/// requests into it, once there was one.
pub(super) fn extra(shared: &Shared, id: u32) -> u64 {
    // Imports are few: their count fits.
    let n = |a: &crate::accounts::Account| a.imports().services.len() as u64;
    shared
        .accounts
        .get(id)
        .map_or(0, |a| n(a) + u64::from(a.responses.asked()))
}

/// What `nats-server` tells of its sublist and its cache of matches.
/// naq's index keeps no such cache: those counts are 0.
#[derive(Debug, Default, Serialize)]
pub(super) struct Stats {
    num_subscriptions: u64,
    num_cache: u32,
    num_inserts: u64,
    num_removes: u64,
    num_matches: u64,
    cache_hit_rate: f64,
    max_fanout: u32,
    avg_fanout: f64,
}

impl Stats {
    /// Of `subs` subscriptions, after `inserts` and `removes`.
    pub(super) fn of(subs: u64, inserts: u64, removes: u64) -> Stats {
        Stats {
            num_subscriptions: subs,
            num_inserts: inserts,
            num_removes: removes,
            ..Stats::default()
        }
    }
}

#[derive(Debug, Serialize)]
struct Subsz<'a> {
    server_id: &'a str,
    now: String,
    #[serde(flatten)]
    stats: Stats,
    total: usize,
    offset: i64,
    limit: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subscriptions_list: Vec<SubDetail<'a>>,
}

/// `/subsz`, `/subscriptionsz`: `subs` lists the subscriptions of
/// clients, paged by `offset` and `limit`, and only those that take a
/// message on `test`; `acc` takes one account.
pub(super) async fn answer(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    shared.monitor.count(Counted::Subsz);
    let list = q.bool("subs")?;
    let offset = q.int("offset")?.max(0);
    let limit = match q.int("limit")? {
        l if l <= 0 => LIMIT,
        l => l,
    };
    let test = q.get("test").to_owned();
    if !test.is_empty() && !subject::is_valid_literal(test.as_bytes()) {
        return Err(format!(
            "invalid test subject, must be valid publish subject: {test}"
        ));
    }
    let acc = q.get("acc");
    let accounts: Vec<u32> = if acc.is_empty() {
        (0..shared.accounts.len()).collect()
    } else {
        shared.accounts.id(acc).into_iter().collect()
    };
    let extra: u64 = accounts.iter().map(|&a| extra(shared, a)).sum();
    let lanes = ask_all(shared, move |lane| {
        found(lane, &accounts, list, test.as_bytes())
    })
    .await;
    let (mut subs, mut inserts, mut removes) = (extra, extra, 0);
    let mut all = Vec::new();
    for f in lanes {
        subs += f.subs;
        inserts += f.inserts;
        removes += f.removes;
        all.extend(f.list);
    }
    // `nats-server` lists them in no set order.
    all.sort_by(|a, b| (&a.account, a.cid, &a.sid).cmp(&(&b.account, b.cid, &b.sid)));
    let n = all.len();
    // Offset and limit are not negative here.
    let start = usize::try_from(offset).unwrap_or(n).min(n);
    let end = start + usize::try_from(limit).unwrap_or(n).min(n - start);
    Ok(pretty(&Subsz {
        server_id: &shared.server_id,
        now: now(),
        stats: Stats::of(subs, inserts, removes),
        total: n,
        offset,
        limit,
        subscriptions_list: all[start..end].iter().map(detail).collect(),
    }))
}

/// `l`, as `nats-server` details it.
fn detail(l: &Listed) -> SubDetail<'_> {
    SubDetail {
        account: &l.account,
        account_tag: &l.tag,
        subject: &l.subject,
        qgroup: l.queue.as_deref(),
        sid: &l.sid,
        msgs: l.msgs,
        max: l.max,
        cid: l.cid,
    }
}
