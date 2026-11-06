//! `/varz`: the server's settings and counts, in `nats-server`'s fields.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;

use super::http::Response;
use super::{ask_all, pretty};
use crate::lane::Lane;
use crate::server::Shared;
use crate::stats::Totals;
use crate::times::{rfc3339_nano, uptime};

/// An object with no fields: `{}`.
#[derive(Debug, Serialize)]
pub(super) struct Empty {}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature serde's skip_serializing_if calls"
)]
const fn is_false(b: &bool) -> bool {
    !*b
}

/// What `/varz` shows, in Go's order.
#[derive(Debug, Serialize)]
struct Varz<'a> {
    server_id: &'a str,
    server_name: &'a str,
    version: &'static str,
    proto: u8,
    go: &'static str,
    host: &'a str,
    port: u16,
    #[serde(skip_serializing_if = "is_false")]
    auth_required: bool,
    #[serde(skip_serializing_if = "is_false")]
    tls_required: bool,
    #[serde(skip_serializing_if = "is_false")]
    tls_verify: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    connect_urls: Vec<String>,
    max_connections: u32,
    ping_interval: u64,
    ping_max: u32,
    http_host: &'a str,
    http_port: u16,
    http_base_path: &'a str,
    https_port: u16,
    auth_timeout: f64,
    max_control_line: usize,
    max_payload: usize,
    max_pending: usize,
    cluster: Cluster<'a>,
    gateway: Empty,
    leaf: Leaf<'a>,
    mqtt: Empty,
    websocket: Websocket<'a>,
    jetstream: Empty,
    tls_timeout: f64,
    write_deadline: u64,
    start: String,
    now: String,
    uptime: String,
    mem: u64,
    cores: usize,
    gomaxprocs: usize,
    cpu: f64,
    #[serde(flatten)]
    counts: Counts,
    http_req_stats: BTreeMap<&'static str, u64>,
    config_load_time: String,
    config_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_account: Option<&'a str>,
    slow_consumer_stats: Kinds,
    stale_connection_stats: Kinds,
    disk_io_wait_stats: DiskIo,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_cert_not_after: Option<String>,
}

/// The counts of `/varz`, in Go's order.
#[derive(Debug, Default, Serialize)]
struct Counts {
    connections: u64,
    total_connections: u64,
    routes: usize,
    remotes: usize,
    leafnodes: usize,
    in_msgs: u64,
    in_bytes: u64,
    in_client_msgs: u64,
    in_client_bytes: u64,
    out_msgs: u64,
    out_bytes: u64,
    out_client_msgs: u64,
    out_client_bytes: u64,
    slow_consumers: u64,
    stale_connections: u64,
    stalled_clients: u64,
    subscriptions: usize,
}

/// `cluster` of `/varz`.
#[derive(Debug, Default, Serialize)]
struct Cluster<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    addr: &'a str,
    #[serde(rename = "cluster_port", skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_timeout: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_timeout: Option<f64>,
}

/// `leaf` of `/varz`.
#[derive(Debug, Default, Serialize)]
struct Leaf<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    host: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_timeout: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_timeout: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    remotes: Vec<Remote<'a>>,
}

/// A leaf node remote, in `leaf` of `/varz`.
#[derive(Debug, Serialize)]
struct Remote<'a> {
    local_account: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_timeout: Option<f64>,
    urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny: Option<Deny<'a>>,
}

/// What a remote may not import or export.
#[derive(Debug, Serialize)]
struct Deny<'a> {
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    exports: &'a [String],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    imports: &'a [String],
}

/// `websocket` of `/varz`.
#[derive(Debug, Default, Serialize)]
struct Websocket<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    host: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_auth_user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    handshake_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_timeout: Option<f64>,
    #[serde(skip_serializing_if = "is_false")]
    no_tls: bool,
    #[serde(skip_serializing_if = "is_false")]
    same_origin: bool,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    allowed_origins: &'a [String],
    #[serde(skip_serializing_if = "is_false")]
    compression: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_cert_not_after: Option<String>,
}

/// Counts by kind of connection.
#[derive(Debug, Default, Serialize)]
struct Kinds {
    clients: u64,
    routes: u64,
    gateways: u64,
    leafs: u64,
}

impl Kinds {
    fn of_clients(clients: u64) -> Kinds {
        Kinds {
            clients,
            ..Kinds::default()
        }
    }
}

/// Disk waits of JetStream: none.
#[derive(Debug, Default, Serialize)]
struct DiskIo {
    waiters: u8,
    waits: u8,
    wait_time: u8,
    max_wait_time: u8,
}

/// What a lane counts for `/varz`.
#[derive(Debug, Default)]
struct OnLane {
    subscriptions: usize,
    leafs: usize,
    routes: usize,
}

/// The counts of `lane`: the subscriptions of its clients, its links to
/// Go hubs, and on lane 0, the naq links and routes that are up.
fn on_lane(lane: &Lane) -> OnLane {
    let subscriptions = lane
        .clients
        .borrow()
        .values()
        .map(|c| c.subs.borrow().len())
        .sum();
    let mut leafs = lane.links.borrow().len();
    let mut routes = 0;
    if let Some(mesh) = lane.mesh.borrow().as_ref() {
        leafs += mesh.leafs.borrow().len() + mesh.hubs.borrow().iter().filter(|h| h.up).count();
        routes = mesh.peers.borrow().iter().filter(|p| p.up).count();
    }
    OnLane {
        subscriptions,
        leafs,
        routes,
    }
}

/// `/varz`.
pub(super) async fn answer(shared: &Shared) -> Response {
    let lanes = ask_all(shared, on_lane).await;
    pretty(&varz(shared, &lanes))
}

fn varz<'a>(s: &'a Shared, lanes: &[OnLane]) -> Varz<'a> {
    let o = &s.opts;
    let now = SystemTime::now();
    let (mem, cpu) = usage(&s.monitor.cpu);
    let tls = s.tls.as_ref();
    Varz {
        server_id: &s.server_id,
        server_name: Some(o.server_name.as_str())
            .filter(|n| !n.is_empty())
            .unwrap_or(&s.server_id),
        version: env!("CARGO_PKG_VERSION"),
        proto: 1,
        go: "",
        host: &o.host,
        port: s.addr.port(),
        auth_required: s.auth.is_some(),
        tls_required: tls.is_some(),
        tls_verify: tls.is_some_and(|t| t.verify),
        connect_urls: connect_urls(s),
        max_connections: 65536,
        ping_interval: nanos(o.ping_interval),
        ping_max: o.max_pings_out,
        http_host: o.http_host.as_deref().unwrap_or(&o.host),
        http_port: s.monitor.http.map_or(0, |a| a.port()),
        http_base_path: &o.http_base_path,
        https_port: s.monitor.https.map_or(0, |a| a.port()),
        auth_timeout: o.auth_timeout.as_secs_f64(),
        max_control_line: o.max_control_line,
        max_payload: o.max_payload,
        max_pending: o.max_pending,
        cluster: cluster(s),
        gateway: Empty {},
        leaf: leaf(s),
        mqtt: Empty {},
        websocket: websocket(s),
        jetstream: Empty {},
        tls_timeout: o.tls.as_ref().map_or(2.0, |t| t.timeout.as_secs_f64()),
        write_deadline: nanos(o.write_deadline),
        start: rfc3339_nano(s.started),
        now: rfc3339_nano(now),
        uptime: uptime(now.duration_since(s.started).unwrap_or_default()),
        mem,
        cores: std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
        gomaxprocs: s.lanes.len(),
        cpu,
        counts: counts(s, lanes),
        http_req_stats: s.monitor.stats(),
        config_load_time: rfc3339_nano(s.monitor.loaded),
        config_digest: &s.monitor.digest,
        system_account: s.system.map(|a| s.accounts.name(a)),
        slow_consumer_stats: Kinds {
            clients: s.events.slow_clients.get(),
            leafs: s.events.slow_leafs.get(),
            ..Kinds::default()
        },
        stale_connection_stats: Kinds::of_clients(s.events.stale_clients.get()),
        disk_io_wait_stats: DiskIo::default(),
        tls_cert_not_after: tls.and_then(|t| t.not_after).map(rfc3339_nano),
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// The counts of `s`, with what `lanes` found.
fn counts(s: &Shared, lanes: &[OnLane]) -> Counts {
    let (mut clients, mut all) = (Totals::default(), Totals::default());
    for (c, p) in s.counts.iter().zip(&*s.peer_counts) {
        clients += c.load();
        all += c.load();
        all += p.load();
    }
    let routes = lanes.iter().map(|l| l.routes).sum();
    let e = &s.events;
    Counts {
        connections: s.total_clients() - s.gone.load(std::sync::atomic::Ordering::Relaxed),
        total_connections: s.total_clients(),
        routes,
        remotes: routes,
        leafnodes: lanes.iter().map(|l| l.leafs).sum(),
        in_msgs: all.in_msgs,
        in_bytes: all.in_bytes,
        in_client_msgs: clients.in_msgs,
        in_client_bytes: clients.in_bytes,
        out_msgs: all.out_msgs,
        out_bytes: all.out_bytes,
        out_client_msgs: clients.out_msgs,
        out_client_bytes: clients.out_bytes,
        slow_consumers: e.slow_clients.get() + e.slow_leafs.get(),
        stale_connections: e.stale_clients.get(),
        stalled_clients: e.stalls.get(),
        subscriptions: lanes.iter().map(|l| l.subscriptions).sum(),
    }
}

/// The client URLs of the cluster once another server told of its own:
/// this server's first.
fn connect_urls(s: &Shared) -> Vec<String> {
    // A poisoned lock still holds the list.
    let others = s
        .connect_urls
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if others.is_empty() {
        return Vec::new();
    }
    std::iter::once(s.addr.to_string())
        .chain(others.iter().cloned())
        .collect()
}

fn cluster(s: &Shared) -> Cluster<'_> {
    let Some(c) = &s.opts.cluster else {
        return Cluster::default();
    };
    Cluster {
        name: &c.name,
        addr: &c.host,
        port: s
            .monitor
            .mesh
            .get()
            .and_then(|m| m.cluster)
            .map(|a| a.port()),
        auth_timeout: Some(2.0),
        urls: c.routes.iter().map(|r| host_port(r, 6222)).collect(),
        tls_timeout: Some(2.0),
    }
}

fn leaf(s: &Shared) -> Leaf<'_> {
    let o = &s.opts;
    let mut l = Leaf::default();
    if let Some(n) = &o.leafnodes {
        l.host = &n.host;
        l.port = s
            .monitor
            .mesh
            .get()
            .and_then(|m| m.leafnodes)
            .map(|a| a.port());
        l.auth_timeout = Some(n.auth_timeout.as_secs_f64());
        l.tls_timeout = Some(2.0);
    }
    l.remotes = o
        .remotes
        .iter()
        .map(|r| Remote {
            local_account: r.account.as_deref().unwrap_or("$G"),
            tls_timeout: r.tls.as_ref().map(|t| t.timeout.as_secs_f64()),
            urls: r.urls.iter().map(|u| host_port(u, 7422)).collect(),
            deny: (!r.deny_imports.is_empty() || !r.deny_exports.is_empty()).then_some(Deny {
                exports: &r.deny_exports,
                imports: &r.deny_imports,
            }),
        })
        .collect();
    l
}

fn websocket(s: &Shared) -> Websocket<'_> {
    let (Some(w), Some(door)) = (&s.opts.websocket, &s.ws) else {
        return Websocket::default();
    };
    let default = crate::Websocket::default().handshake_timeout;
    Websocket {
        host: &w.host,
        port: Some(door.addr.port()),
        no_auth_user: w.auth.no_auth_user.as_deref(),
        handshake_timeout: (w.handshake_timeout != default).then(|| nanos(w.handshake_timeout)),
        auth_timeout: w.auth.timeout.map(|t| t.as_secs_f64()),
        no_tls: w.no_tls,
        same_origin: w.same_origin,
        allowed_origins: &w.allowed_origins,
        compression: w.compression,
        tls_cert_not_after: door
            .tls
            .as_ref()
            .and_then(|t| t.not_after)
            .map(rfc3339_nano),
    }
}

/// `url` as `host:port`, as Go shows a URL's host: no scheme, no user,
/// and port `port` if it has none.
fn host_port(url: &str, port: u16) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.split(['/', '?']).next().unwrap_or(rest);
    let host = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    let has_port = match host.rsplit_once(':') {
        Some((h, p)) => !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && !h.ends_with(':'),
        None => false,
    };
    if has_port || host.is_empty() {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    }
}

/// The process's CPU time at a moment.
#[derive(Debug, Clone, Copy)]
pub(super) struct Cpu {
    at: Instant,
    ticks: u64,
    /// Percent of a core, as last worked out.
    percent: f64,
}

/// How long a CPU sample counts before the next is taken.
const SAMPLE: Duration = Duration::from_secs(1);

/// The resident memory of the process, in bytes, and its CPU use in
/// percent of a core since the last sample, as `nats-server` reads them
/// on Linux; zeros where `/proc` does not tell.
fn usage(last: &std::sync::Mutex<Option<Cpu>>) -> (u64, f64) {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return (0, 0.0);
    };
    // Fields after the command, which ends at the last `)`.
    let fields: Vec<&str> = stat
        .rsplit_once(')')
        .map_or("", |(_, r)| r)
        .split_whitespace()
        .collect();
    let field = |i: usize| {
        fields
            .get(i)
            .and_then(|f| f.parse::<u64>().ok())
            .unwrap_or(0)
    };
    // utime, stime and rss are fields 14, 15 and 24, counted from 1 with
    // the pid and command; here from 0 after them.
    let ticks = field(11) + field(12);
    let rss = field(21) * page_size();
    let now = Instant::now();
    // A poisoned lock still holds the last sample.
    let mut last = last
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let percent = match *last {
        Some(c) if now - c.at < SAMPLE => return (rss, c.percent),
        Some(c) => percent(ticks.saturating_sub(c.ticks), now - c.at),
        None => percent(ticks, process_age(&fields).unwrap_or(SAMPLE)),
    };
    *last = Some(Cpu {
        at: now,
        ticks,
        percent,
    });
    (rss, percent)
}

/// Percent of a core that `ticks` of CPU time in `over` are, in tenths
/// cut, as Go works it out.
fn percent(ticks: u64, over: Duration) -> f64 {
    // A tick is a hundredth of a second, as Go takes it.
    let tenths = (ticks as f64 * 10.0 / over.as_secs_f64().max(0.001)).floor();
    tenths / 10.0
}

/// How long the process of `fields` has run, from its start time and
/// the system's uptime.
fn process_age(fields: &[&str]) -> Option<Duration> {
    let start: u64 = fields.get(19)?.parse().ok()?;
    let up = std::fs::read_to_string("/proc/uptime").ok()?;
    let up: f64 = up.split_whitespace().next()?.parse().ok()?;
    Some(Duration::from_secs_f64(
        (up - start as f64 / 100.0).max(0.001),
    ))
}

/// The size of a memory page: 4 KiB, or what `/proc/self/smaps` says.
fn page_size() -> u64 {
    std::fs::read_to_string("/proc/self/smaps")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("KernelPageSize:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        })
        .map_or(4096, |kb| kb * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_show_their_host_and_port() {
        assert_eq!(host_port("nats://u:p@h:4", 7422), "h:4");
        assert_eq!(host_port("nats-leaf://t@h", 7422), "h:7422");
        assert_eq!(host_port("h:5", 1), "h:5");
        assert_eq!(host_port("h", 1), "h:1");
        assert_eq!(host_port("naq://h:6/x", 1), "h:6");
        assert_eq!(host_port("[::1]:7", 1), "[::1]:7");
        assert_eq!(host_port("", 1), "");
    }

    #[test]
    fn cpu_is_in_tenths_of_a_percent() {
        assert_eq!(percent(50, Duration::from_secs(1)), 50.0);
        assert_eq!(percent(1, Duration::from_secs(3)), 0.3);
        assert_eq!(percent(250, Duration::from_secs(1)), 250.0);
        let last = std::sync::Mutex::new(None);
        let (mem, _) = usage(&last);
        assert!(mem > 0);
        assert!(last.lock().unwrap().is_some());
        // Within a second, the last sample stands.
        let (_, again) = usage(&last);
        assert_eq!(Some(again), last.lock().unwrap().map(|c| c.percent));
        // A sample older than a second gives way to a new one.
        *last.lock().unwrap() = Some(Cpu {
            at: Instant::now().checked_sub(Duration::from_secs(5)).unwrap(),
            ticks: 0,
            percent: -1.0,
        });
        let (_, fresh) = usage(&last);
        assert!(fresh >= 0.0, "{fresh}");
        assert!(page_size() >= 4096);
    }
}
