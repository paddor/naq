//! What the server counts, as `nats-server` sends it in `STATSZ`.

use rustc_hash::FxHashSet;
use serde::Serialize;

use super::accstatz::MsgBytes;
use super::ask_all;
use super::varz::{Kinds, counts, on_lane, usage};
use crate::lane::Lane;
use crate::server::Shared;
use crate::times::rfc3339_nano;

/// Go's `ServerStats`, in its order.
#[derive(Debug, Serialize)]
pub(crate) struct ServerStats {
    start: String,
    mem: u64,
    cores: usize,
    cpu: f64,
    connections: u64,
    total_connections: u64,
    active_accounts: usize,
    subscriptions: usize,
    sent: MsgBytes,
    sent_to_clients: MsgBytes,
    received: MsgBytes,
    received_from_clients: MsgBytes,
    slow_consumers: u64,
    #[serde(skip_serializing_if = "Kinds::is_zero")]
    slow_consumer_stats: Kinds,
    #[serde(skip_serializing_if = "is_zero")]
    stale_connections: u64,
    #[serde(skip_serializing_if = "Kinds::is_zero")]
    stale_connection_stats: Kinds,
    #[serde(skip_serializing_if = "is_zero")]
    stalled_clients: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    routes: Vec<RouteStat>,
    active_servers: usize,
    gomaxprocs: usize,
}

/// One route, as Go's `RouteStat`.
#[derive(Debug, Serialize)]
struct RouteStat {
    rid: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    sent: MsgBytes,
    received: MsgBytes,
    pending: u64,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature serde's skip_serializing_if calls"
)]
const fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// The accounts with clients or links on `lane`.
fn accounts(lane: &Lane) -> FxHashSet<u32> {
    let clients = lane.clients.borrow();
    let links = lane.links.borrow();
    let mut all: FxHashSet<u32> = clients.values().map(|c| c.account.get()).collect();
    all.extend(links.iter().map(|l| l.account));
    all
}

/// What `shared`'s server counts now.
pub(crate) async fn statsz(shared: &Shared) -> ServerStats {
    let lanes = ask_all(shared, |lane| (on_lane(lane), accounts(lane))).await;
    let (on, used): (Vec<_>, Vec<_>) = lanes.into_iter().unzip();
    let mut active: FxHashSet<u32> = used.into_iter().flatten().collect();
    // Go counts its system client in the system account.
    active.extend(shared.system);
    let c = counts(shared, &on);
    let (mem, cpu) = usage(&shared.monitor.cpu);
    let routes: Vec<RouteStat> = super::routes::totals(shared)
        .await
        .into_iter()
        .map(|(rid, name, t)| RouteStat {
            rid,
            name,
            sent: MsgBytes {
                msgs: t.out_msgs,
                bytes: t.out_bytes,
            },
            received: MsgBytes {
                msgs: t.in_msgs,
                bytes: t.in_bytes,
            },
            pending: 0,
        })
        .collect();
    let active_servers = routes.len() + 1;
    ServerStats {
        start: rfc3339_nano(shared.started),
        mem,
        cores: std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
        cpu,
        connections: c.connections,
        total_connections: c.total_connections,
        active_accounts: active.len(),
        subscriptions: c.subscriptions,
        sent: MsgBytes {
            msgs: c.out_msgs,
            bytes: c.out_bytes,
        },
        sent_to_clients: MsgBytes {
            msgs: c.out_client_msgs,
            bytes: c.out_client_bytes,
        },
        received: MsgBytes {
            msgs: c.in_msgs,
            bytes: c.in_bytes,
        },
        received_from_clients: MsgBytes {
            msgs: c.in_client_msgs,
            bytes: c.in_client_bytes,
        },
        slow_consumers: c.slow_consumers,
        slow_consumer_stats: Kinds::slow(shared),
        stale_connections: c.stale_connections,
        stale_connection_stats: Kinds::stale(shared),
        stalled_clients: c.stalled_clients,
        routes,
        active_servers,
        gomaxprocs: shared.lanes.len(),
    }
}
