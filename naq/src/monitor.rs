//! Monitoring over HTTP, as much of `nats-server`'s as tools and harnesses
//! use: `/healthz`, `/varz`, `/connz`, `/routez` and `/leafz`, in its JSON.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use zzq_tokio::transport::{Driver, Listener};

use crate::lane::{Control, Lane};
use crate::server::Shared;
use crate::stats::Totals;

/// Longest request head read.
const MAX_REQUEST: usize = 8 << 10;

/// How long a request may take to arrive.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// One client, as `/connz` shows it.
#[derive(Debug, Serialize)]
pub(crate) struct ConnInfo {
    cid: u64,
    kind: &'static str,
    #[serde(rename = "type")]
    kind_of: &'static str,
    ip: String,
    port: u16,
    start: String,
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
pub(crate) fn conns(lane: &Lane) -> Vec<ConnInfo> {
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
                kind_of: "nats",
                ip: meta.ip.clone(),
                port: meta.port,
                start: rfc3339(meta.start),
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
                account: lane.shared.accounts[c.account.get() as usize].clone(),
            }
        })
        .collect()
}

/// One leaf node link, as `/leafz` shows it.
#[derive(Debug, Serialize)]
pub(crate) struct LeafInfo {
    id: u64,
    name: String,
    is_spoke: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_isolated: bool,
    account: String,
    ip: String,
    port: u16,
    in_msgs: u64,
    out_msgs: u64,
    in_bytes: u64,
    out_bytes: u64,
    subscriptions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    subscriptions_list: Option<Vec<String>>,
    compression: &'static str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    websocket: bool,
}

/// The leaf node links of `lane`, with the subjects of their hubs'
/// interest.
pub(crate) fn links(lane: &Lane) -> Vec<LeafInfo> {
    lane.links
        .borrow()
        .iter()
        .map(|l| {
            let t = l.client.tally.totals();
            let subs = l.hub_subjects();
            let f = &l.facts;
            LeafInfo {
                id: l.id,
                name: f.name.clone(),
                is_spoke: true,
                is_isolated: f.isolated,
                account: lane.shared.accounts[l.account as usize].clone(),
                ip: f.ip.clone(),
                port: f.port,
                in_msgs: t.in_msgs,
                out_msgs: t.out_msgs,
                in_bytes: t.in_bytes,
                out_bytes: t.out_bytes,
                subscriptions: subs.len(),
                subscriptions_list: Some(subs),
                compression: "off",
                websocket: f.websocket,
            }
        })
        .collect()
}

/// How much of each route's subscriptions `/routez` lists: `subs=1`
/// for subjects, `subs=detail` for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subs {
    None,
    List,
    Detail,
}

/// One route of the cluster, as `/routez` shows it.
#[derive(Debug, Serialize)]
pub(crate) struct RouteInfo {
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
pub(crate) struct SubDetail {
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
/// them, with as much of their subscriptions as `subs` asks; none on
/// other lanes.
pub(crate) fn routes(lane: &Lane, subs: Subs) -> Vec<RouteInfo> {
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
                        .map(|(account, subject, queue, weight)| SubDetail {
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

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The ID `nats-server` gives a subscription of a route: `R`, the
/// account, the subject and the queue group, if one.
fn sid(account: &[u8], subject: &[u8], queue: Option<&[u8]>) -> String {
    let mut parts = vec![&b"R"[..], account, subject];
    parts.extend(queue);
    text(&parts.join(&b' '))
}

/// Serves monitoring on `listener` until it closes.
pub(crate) async fn serve(mut listener: Listener, shared: Arc<Shared>) {
    loop {
        let stream = match listener.accept().await {
            Ok(s) => s,
            Err(zzq_tokio::Error::Closed) => return,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let shared = shared.clone();
        tokio::task::spawn_local(async move {
            let _ = stream.drive(Http { shared }).await;
        });
    }
}

struct Http {
    shared: Arc<Shared>,
}

impl Driver for Http {
    type Output = ();

    async fn run<R, W>(self, mut r: R, mut w: W)
    where
        R: tokio::io::AsyncRead + Unpin + 'static,
        W: tokio::io::AsyncWrite + Unpin + 'static,
    {
        {
            let Ok(Some(target)) = tokio::time::timeout(READ_TIMEOUT, request(&mut r)).await else {
                return;
            };
            let (status, body) = answer(&self.shared, &target).await;
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = w.write_all(head.as_bytes()).await;
            let _ = w.write_all(&body).await;
            let _ = w.shutdown().await;
        }
    }
}

/// The target of a `GET`, path and query, once its head is in.
async fn request<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Option<String> {
    let mut buf = Vec::new();
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() > MAX_REQUEST {
            return None;
        }
        let mut chunk = [0u8; 1024];
        let n = r.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line = buf.split(|&b| b == b'\r').next()?;
    let mut parts = std::str::from_utf8(line).ok()?.split(' ');
    let (method, target) = (parts.next()?, parts.next()?);
    (method == "GET").then(|| target.to_owned())
}

async fn answer(shared: &Shared, target: &str) -> (&'static str, Vec<u8>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let json = match path.trim_end_matches('/') {
        "/healthz" => serde_json::json!({ "status": "ok" }),
        "/varz" => varz(shared),
        "/connz" => connz(shared).await,
        "/leafz" => leafz(shared, wants_subs(query)).await,
        "/routez" => routez(shared, subs(query)).await,
        _ => return ("404 Not Found", b"{\"error\":\"not found\"}".to_vec()),
    };
    // Cannot fail: plain values only.
    (
        "200 OK",
        serde_json::to_vec_pretty(&json).unwrap_or_default(),
    )
}

fn varz(shared: &Shared) -> serde_json::Value {
    let mut t = Totals::default();
    for c in &*shared.counts {
        t += c.load();
    }
    let now = SystemTime::now();
    let o = &shared.opts;
    // Relaxed: counters read now and then.
    let load = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
    serde_json::json!({
        "server_id": shared.server_id,
        "server_name": o.server_name,
        "version": env!("CARGO_PKG_VERSION"),
        "proto": 1,
        "go": "",
        "host": o.host,
        "port": shared.addr.port(),
        "auth_required": shared.auth.is_some(),
        "max_connections": 65536,
        "ping_interval": o.ping_interval.as_nanos() as u64,
        "ping_max": o.max_pings_out,
        "auth_timeout": shared.auth.as_ref().map_or(0.0, |a| a.timeout.as_secs_f64()),
        "max_control_line": o.max_control_line,
        "max_payload": o.max_payload,
        "max_pending": o.max_pending,
        "write_deadline": o.write_deadline.as_nanos() as u64,
        "start": rfc3339(shared.started),
        "now": rfc3339(now),
        "uptime": uptime(now.duration_since(shared.started).unwrap_or_default()),
        "cores": std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
        "connections": count_clients(shared),
        "total_connections": shared.total_clients(),
        "in_msgs": t.in_msgs,
        "in_bytes": t.in_bytes,
        "in_client_msgs": t.in_msgs,
        "in_client_bytes": t.in_bytes,
        "out_msgs": t.out_msgs,
        "out_bytes": t.out_bytes,
        "out_client_msgs": t.out_msgs,
        "out_client_bytes": t.out_bytes,
        "slow_consumers": load(&shared.events.slow_consumers),
        "stale_connections": load(&shared.events.stale),
    })
}

/// Clients connected now: accepted and not yet gone.
fn count_clients(shared: &Shared) -> u64 {
    shared.total_clients() - load_gone(shared)
}

fn load_gone(shared: &Shared) -> u64 {
    // Relaxed: a counter read now and then.
    shared.gone.load(std::sync::atomic::Ordering::Relaxed)
}

async fn connz(shared: &Shared) -> serde_json::Value {
    let mut waits = Vec::with_capacity(shared.lanes.len());
    for tx in &*shared.lanes {
        let (answer, wait) = oneshot::channel();
        tx.control(Control::Clients(answer));
        waits.push(wait);
    }
    let mut conns = Vec::new();
    for w in waits {
        // A lane that stopped has no clients to show.
        conns.extend(w.await.unwrap_or_default());
    }
    conns.sort_by_key(|c| c.cid);
    let n = conns.len();
    serde_json::json!({
        "server_id": shared.server_id,
        "now": rfc3339(SystemTime::now()),
        "num_connections": n,
        "total": n,
        "offset": 0,
        "limit": n.max(1024),
        "connections": conns,
    })
}

/// Whether `query` asks for subscription lists, as `subs=1` or `subs=true`.
fn wants_subs(query: &str) -> bool {
    query
        .split('&')
        .any(|kv| matches!(kv, "subs=1" | "subs=true"))
}

/// How much of the subscriptions `query` asks for: `subs=detail`, else
/// as [`wants_subs`].
fn subs(query: &str) -> Subs {
    if query
        .split('&')
        .any(|kv| kv.eq_ignore_ascii_case("subs=detail"))
    {
        Subs::Detail
    } else if wants_subs(query) {
        Subs::List
    } else {
        Subs::None
    }
}

async fn routez(shared: &Shared, subs: Subs) -> serde_json::Value {
    let (answer, wait) = oneshot::channel();
    shared.lanes[0].control(Control::Routes(subs, answer));
    // A lane that stopped has no routes to show.
    let routes = wait.await.unwrap_or_default();
    serde_json::json!({
        "server_id": shared.server_id,
        "now": rfc3339(SystemTime::now()),
        "num_routes": routes.len(),
        "routes": routes,
    })
}

async fn leafz(shared: &Shared, subs: bool) -> serde_json::Value {
    let mut waits = Vec::with_capacity(shared.lanes.len());
    for tx in &*shared.lanes {
        let (answer, wait) = oneshot::channel();
        tx.control(Control::Links(answer));
        waits.push(wait);
    }
    let mut leafs = Vec::new();
    for w in waits {
        // A lane that stopped has no links to show.
        leafs.extend(w.await.unwrap_or_default());
    }
    leafs.sort_by_key(|l| l.id);
    if !subs {
        for l in &mut leafs {
            l.subscriptions_list = None;
        }
    }
    serde_json::json!({
        "server_id": shared.server_id,
        "now": rfc3339(SystemTime::now()),
        "leafnodes": leafs.len(),
        "leafs": leafs,
    })
}

/// `t` as RFC 3339 in UTC, with nanoseconds, as Go writes times.
fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (y, m, day) = civil(days.cast_signed());
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        d.subsec_nanos()
    )
}

/// Year, month and day of `days` since 1970-01-01.
pub(crate) const fn civil(days: i64) -> (i64, u32, u32) {
    // Howard Hinnant's days-to-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// `d` as `nats-server` writes uptimes: `1d2h3m4s`, leading zeros left out.
fn uptime(d: Duration) -> String {
    let s = d.as_secs();
    let (days, h, m, sec) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60, s % 60);
    let mut out = String::new();
    for (n, unit) in [(days, 'd'), (h, 'h'), (m, 'm')] {
        if n > 0 || !out.is_empty() {
            let _ = write!(out, "{n}{unit}");
        }
    }
    out + &format!("{sec}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_written_as_go_writes_them() {
        let t = UNIX_EPOCH + Duration::new(1_700_000_000, 5);
        assert_eq!(rfc3339(t), "2023-11-14T22:13:20.000000005Z");
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(civil(-1), (1969, 12, 31));
        assert_eq!(civil(11_016), (2000, 2, 29));
        assert_eq!(uptime(Duration::from_secs(4)), "4s");
        assert_eq!(uptime(Duration::from_secs(3601)), "1h0m1s");
        assert_eq!(uptime(Duration::from_secs(90_061)), "1d1h1m1s");
    }
}
