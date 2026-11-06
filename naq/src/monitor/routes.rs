//! `/routez`: the routes to the other servers of the cluster.

use serde::Serialize;

use super::http::Response;
use super::query::{Query, Refused, Subs};
use super::{Counted, ask_first, now, pretty, text};
use crate::lane::Lane;
use crate::server::Shared;

/// One route of the cluster, as `/routez` shows it.
#[derive(Debug, Serialize)]
struct RouteInfo {
    rid: usize,
    remote_id: String,
    remote_name: String,
    did_solicit: bool,
    is_configured: bool,
    ip: String,
    port: u16,
    subscriptions: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subscriptions_list: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subscriptions_list_detail: Vec<SubDetail>,
}

/// One subscription a route told of, as `nats-server` details it, and
/// the members of its queue group there.
#[derive(Debug, Serialize)]
struct SubDetail {
    account: String,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    qgroup: Option<String>,
    sid: String,
    msgs: u64,
    cid: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_weight: Option<u32>,
}

/// The routes of the cluster to servers that are up, as lane 0 knows
/// them, with as much of their subscriptions as `subs` asks.
fn routes(lane: &Lane, subs: Subs) -> Vec<RouteInfo> {
    let Some(mesh) = lane.mesh.borrow().clone() else {
        return Vec::new();
    };
    let peers = mesh.peers.borrow();
    peers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.up)
        .map(|(i, p)| {
            let mut r = RouteInfo {
                rid: i + 1,
                remote_id: p.server_id.clone(),
                remote_name: p.name.clone(),
                did_solicit: true,
                is_configured: true,
                ip: p.host.clone(),
                port: p.port,
                subscriptions: p.heard.len(),
                subscriptions_list: Vec::new(),
                subscriptions_list_detail: Vec::new(),
            };
            match subs {
                Subs::None => {}
                Subs::List => r.subscriptions_list = p.heard.entries().map(|e| text(e.1)).collect(),
                Subs::Detail => {
                    r.subscriptions_list_detail = p
                        .heard
                        .entries()
                        .map(|(account, subject, queue, weight, _)| SubDetail {
                            account: text(account),
                            subject: text(subject),
                            qgroup: queue.map(text),
                            sid: sid(account, subject, queue),
                            msgs: 0,
                            cid: i + 1,
                            queue_weight: queue.map(|_| weight),
                        })
                        .collect();
                }
            }
            r
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

#[derive(Debug, Serialize)]
struct Routez<'a> {
    server_id: &'a str,
    now: String,
    num_routes: usize,
    routes: Vec<RouteInfo>,
}

/// `/routez`: `subs` for the subjects of each route, `subs=detail` for
/// details.
pub(super) async fn answer(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    let subs = q.subs()?;
    shared.monitor.count(Counted::Routez);
    let routes = ask_first(shared, move |lane| routes(lane, subs))
        .await
        .unwrap_or_default();
    Ok(pretty(&Routez {
        server_id: &shared.server_id,
        now: now(),
        num_routes: routes.len(),
        routes,
    }))
}
