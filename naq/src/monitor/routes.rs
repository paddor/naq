//! `/routez`: the routes to the other servers of the cluster.

use std::time::SystemTime;

use serde::Serialize;

use super::connz::SubDetail;
use super::http::Response;
use super::query::{Query, Refused, Subs};
use super::{Counted, ask_all, pretty, text};
use crate::lane::Lane;
use crate::server::Shared;
use crate::stats::Totals;
use crate::times::{rfc3339_nano, uptime};

/// A route to a server that is up, as lane 0 knows it.
#[derive(Debug)]
struct Route {
    /// Its slot.
    slot: u16,
    remote_id: String,
    remote_name: String,
    host: String,
    port: u16,
    since: SystemTime,
    last: SystemTime,
    /// The subscriptions it told of, with as much as was asked.
    nsubs: usize,
    subs: Vec<Told>,
}

/// One subscription a route told of.
#[derive(Debug)]
struct Told {
    subject: String,
    queue: Option<String>,
    /// The ID `nats-server` gives it.
    sid: String,
    /// The members of its queue group there.
    weight: u32,
}

/// The routes of `lane`, lane 0, to servers that are up, with their
/// subscriptions if `subs` asks.
fn routes(lane: &Lane, subs: Subs) -> Vec<Route> {
    let Some(mesh) = lane.mesh.borrow().clone() else {
        return Vec::new();
    };
    let peers = mesh.peers.borrow();
    peers
        .iter()
        .enumerate()
        .filter_map(|(i, p)| Some((i, p, p.up?)))
        .map(|(i, p, up)| Route {
            // Routes are few: their count fits.
            slot: i as u16,
            remote_id: p.server_id.clone(),
            remote_name: p.name.clone(),
            host: p.host.clone(),
            port: p.port,
            since: up.since,
            last: up.last,
            nsubs: p.heard.len(),
            subs: if subs == Subs::None {
                Vec::new()
            } else {
                p.heard
                    .entries()
                    .map(|(account, subject, queue, weight, _)| Told {
                        subject: text(subject),
                        queue: queue.map(text),
                        sid: sid(account, subject, queue),
                        weight,
                    })
                    .collect()
            },
        })
        .collect()
}

/// The ID `nats-server` gives a subscription of a route: `R`, the
/// account, the subject and the queue group, if one.
fn sid(account: &[u8], subject: &[u8], queue: Option<&[u8]>) -> String {
    let mut parts = vec![&b"R"[..], account, subject];
    parts.extend(queue);
    text(&parts.join(&b' '))
}

/// What a lane tells for `/routez`: its counts of each route, and on
/// lane 0 the routes.
#[derive(Debug)]
struct Found {
    counts: Vec<(u16, Totals)>,
    routes: Option<Vec<Route>>,
}

/// The routes to servers that are up, each with what it passed over
/// every lane, and with its subscriptions as `subs` asks.
async fn gather(shared: &Shared, subs: Subs) -> Vec<(Route, Totals)> {
    let mut lanes = ask_all(shared, move |lane| Found {
        counts: lane.slots.totals(),
        routes: (lane.id == 0).then(|| routes(lane, subs)),
    })
    .await;
    let routes = lanes
        .iter_mut()
        .find_map(|f| f.routes.take())
        .unwrap_or_default();
    routes
        .into_iter()
        .map(|r| {
            let mut t = Totals::default();
            for f in &lanes {
                for &(_, c) in f.counts.iter().filter(|(s, _)| *s == r.slot) {
                    t += c;
                }
            }
            (r, t)
        })
        .collect()
}

/// The routes to servers that are up: the ID of each, the name of its
/// server, and what it passed.
pub(super) async fn totals(shared: &Shared) -> Vec<(u64, String, Totals)> {
    gather(shared, Subs::None)
        .await
        .into_iter()
        .map(|(r, t)| (u64::from(r.slot) + 1, r.remote_name, t))
        .collect()
}

/// One route, as `/routez` shows it.
#[derive(Debug, Serialize)]
struct RouteInfo<'a> {
    rid: u64,
    remote_id: &'a str,
    remote_name: &'a str,
    did_solicit: bool,
    is_configured: bool,
    ip: &'a str,
    port: u16,
    start: String,
    last_activity: String,
    rtt: &'static str,
    uptime: String,
    idle: String,
    pending_size: usize,
    in_msgs: u64,
    out_msgs: u64,
    in_bytes: u64,
    out_bytes: u64,
    subscriptions: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subscriptions_list: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subscriptions_list_detail: Vec<Detail<'a>>,
    compression: &'static str,
}

impl<'a> RouteInfo<'a> {
    /// Route `r`, which passed `t` over every lane, as `subs` asks for it
    /// at `now`. Its ID is its place among the routes, from 1.
    fn of(r: &'a Route, t: Totals, subs: Subs, now: SystemTime) -> RouteInfo<'a> {
        let since = |at: SystemTime| uptime(now.duration_since(at).unwrap_or_default());
        let rid = u64::from(r.slot) + 1;
        RouteInfo {
            rid,
            remote_id: &r.remote_id,
            remote_name: &r.remote_name,
            // Each server dials every route it lists.
            did_solicit: true,
            is_configured: true,
            ip: &r.host,
            port: r.port,
            start: rfc3339_nano(r.since),
            last_activity: rfc3339_nano(r.last),
            rtt: "0s",
            uptime: since(r.since),
            idle: since(r.last),
            pending_size: 0,
            in_msgs: t.in_msgs,
            out_msgs: t.out_msgs,
            in_bytes: t.in_bytes,
            out_bytes: t.out_bytes,
            subscriptions: r.nsubs,
            subscriptions_list: if subs == Subs::List {
                r.subs.iter().map(|s| s.subject.as_str()).collect()
            } else {
                Vec::new()
            },
            subscriptions_list_detail: if subs == Subs::Detail {
                r.subs.iter().map(|s| detail(s, rid)).collect()
            } else {
                Vec::new()
            },
            compression: "off",
        }
    }
}

/// A subscription of a route, as `nats-server` details it, without an
/// account; for a queue group, with its members at the other server.
#[derive(Debug, Serialize)]
struct Detail<'a> {
    #[serde(flatten)]
    sub: SubDetail<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_weight: Option<u32>,
}

/// Subscription `s` of route `rid`, in detail.
fn detail(s: &Told, rid: u64) -> Detail<'_> {
    Detail {
        sub: SubDetail {
            account: "",
            account_tag: "",
            subject: &s.subject,
            qgroup: s.queue.as_deref(),
            sid: &s.sid,
            msgs: 0,
            max: 0,
            cid: rid,
        },
        queue_weight: s.queue.as_ref().map(|_| s.weight),
    }
}

#[derive(Debug, Serialize)]
struct Routez<'a> {
    server_id: &'a str,
    server_name: &'a str,
    now: String,
    num_routes: usize,
    routes: Vec<RouteInfo<'a>>,
}

/// `/routez`: `subs` for the subjects of each route, `subs=detail` for
/// details.
pub(super) async fn answer(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    let subs = q.subs()?;
    shared.monitor.asked(q, Counted::Routez);
    let routes = gather(shared, subs).await;
    let now = SystemTime::now();
    let infos = routes
        .iter()
        .map(|(r, t)| RouteInfo::of(r, *t, subs, now))
        .collect::<Vec<_>>();
    let opts = shared.opts();
    let name = Some(opts.server_name.as_str())
        .filter(|n| !n.is_empty())
        .unwrap_or(&shared.server_id);
    Ok(pretty(&Routez {
        server_id: &shared.server_id,
        server_name: name,
        now: rfc3339_nano(now),
        num_routes: infos.len(),
        routes: infos,
    }))
}
