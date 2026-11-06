//! `/connz`: the clients, as `nats-server` lists its connections.

use std::time::SystemTime;

use serde::Serialize;

use super::http::Response;
use super::query::{Query, Refused};
use super::{Counted, ask_all, now, pretty};
use crate::lane::Lane;
use crate::server::Shared;
use crate::times::{rfc3339_nano, uptime};

/// One client, as `/connz` shows it.
#[derive(Debug, Serialize)]
struct ConnInfo {
    cid: u64,
    kind: &'static str,
    #[serde(rename = "type")]
    kind_of: &'static str,
    ip: String,
    port: u16,
    start: String,
    rtt: String,
    uptime: String,
    pending_bytes: usize,
    in_msgs: u64,
    out_msgs: u64,
    in_bytes: u64,
    out_bytes: u64,
    subscriptions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lang: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    account: String,
}

/// The clients of `lane`.
fn conns(lane: &Lane) -> Vec<ConnInfo> {
    let now = SystemTime::now();
    lane.clients
        .borrow()
        .values()
        .map(|c| {
            let meta = c.meta.borrow();
            let t = c.tally.totals();
            ConnInfo {
                cid: c.id,
                kind: "Client",
                kind_of: if meta.websocket { "websocket" } else { "nats" },
                ip: meta.ip.clone(),
                port: meta.port,
                start: rfc3339_nano(meta.start),
                rtt: super::rtt(c.rtt.get()),
                uptime: uptime(now.duration_since(meta.start).unwrap_or_default()),
                pending_bytes: c.out.borrow().len(),
                in_msgs: t.in_msgs,
                out_msgs: t.out_msgs,
                in_bytes: t.in_bytes,
                out_bytes: t.out_bytes,
                subscriptions: c.subs.borrow().len(),
                name: meta.name.clone(),
                lang: meta.lang.clone(),
                version: meta.version.clone(),
                account: lane.shared.accounts.name(c.account.get()).to_owned(),
            }
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct Connz<'a> {
    server_id: &'a str,
    now: String,
    num_connections: usize,
    total: usize,
    offset: i64,
    limit: i64,
    connections: Vec<ConnInfo>,
}

/// `/connz`.
pub(super) async fn answer(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    q.bool("auth")?;
    q.subs()?;
    q.int("offset")?;
    let limit = q.int("limit")?;
    q.uint("cid")?;
    shared.monitor.count(Counted::Connz);
    let mut conns: Vec<_> = ask_all(shared, conns).await.into_iter().flatten().collect();
    conns.sort_by_key(|c| c.cid);
    let n = conns.len();
    Ok(pretty(&Connz {
        server_id: &shared.server_id,
        now: now(),
        num_connections: n,
        total: n,
        offset: 0,
        limit: if limit <= 0 { 1024 } else { limit },
        connections: conns,
    }))
}
