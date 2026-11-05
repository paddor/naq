//! The mesh: the naq servers this one reaches over OMQ. The other
//! servers of a fixed cluster, the naq leafs that dial it as their hub,
//! and the naq hubs it dials as a leaf.
//!
//! Lane 0 holds the control sockets: a ROUTER on the cluster port, which
//! answers each server that dials it, and a DEALER to each route, which
//! learns that server's interest; a ROUTER for naq leafs, and a DEALER to
//! each naq hub. Every lane binds a PULL for data from routes and a ROUTER
//! for data from leafs. See `tmp/nats/MESH.md`.

mod control;
mod data;
mod hub;
mod interest;
mod spoke;
mod tell;
mod told;
mod view;

pub(crate) use data::{DataLink, gone, hub, leaf, push};
pub(crate) use interest::Heard;
use told::Told;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;

use bytes::Bytes;
use naq_proto::peer::Control;
use omq_tokio::{Options, SocketType};
use tokio::sync::{Notify, oneshot};
use zzq_tokio::LaneHandle;

use crate::Options as ServerOptions;
use crate::server::Shared;

/// The port of a route URL without one, as in `nats-server`.
const PORT: u16 = 6222;

/// Why `opts.cluster` cannot run as given.
pub(crate) fn validate(opts: &ServerOptions) -> Result<(), String> {
    let Some(c) = &opts.cluster else {
        return Ok(());
    };
    if c.routes.len() > 64 {
        return Err("cluster: more than 64 routes".into());
    }
    for r in &c.routes {
        route(r)?;
    }
    Ok(())
}

/// Host and port of route URL `s`: `nats-route://`, `nats://` or a bare
/// `host:port`. Route credentials are not supported yet.
fn route(s: &str) -> Result<(String, u16), String> {
    let bad = |why: &str| format!("cluster route {s:?}: {why}");
    let rest = match s.trim().split_once("://") {
        Some((scheme, rest)) => {
            if !["nats-route", "nats"].contains(&scheme.to_ascii_lowercase().as_str()) {
                return Err(bad("scheme not supported"));
            }
            rest
        }
        None => s.trim(),
    };
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if hostport.contains('@') {
        return Err(bad("credentials not supported"));
    }
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, after) = v6
            .split_once(']')
            .ok_or_else(|| bad("expected host:port"))?;
        match after {
            "" => (h, PORT),
            p => (
                h,
                p.strip_prefix(':')
                    .and_then(|p| p.parse().ok())
                    .ok_or_else(|| bad("bad port"))?,
            ),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| bad("bad port"))?),
            None => (hostport, PORT),
        }
    };
    if host.is_empty() {
        return Err(bad("expected host:port"));
    }
    Ok((host.to_owned(), port))
}

/// An OMQ endpoint of `host` and `port`.
fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("tcp://[{host}]:{port}")
    } else {
        format!("tcp://{host}:{port}")
    }
}

/// What lane 0 knows of the servers reached over OMQ, and what it told
/// them: routes, naq leafs here, and naq hubs dialed.
#[derive(Debug)]
pub(crate) struct Mesh {
    /// Random for each start of this server.
    epoch: u64,
    /// Account names, by ID.
    accounts: Box<[String]>,
    /// The other servers of the cluster, by route.
    pub(crate) peers: RefCell<Vec<Peer>>,
    /// What the routes are told.
    pub(crate) told: Rc<Told>,
    /// The naq leafs linked here.
    pub(crate) leafs: RefCell<Vec<hub::Leaf>>,
    /// Woken when what a leaf is told has deltas.
    leaf_wake: Rc<Notify>,
    /// The naq hubs dialed, in the order of their remotes.
    pub(crate) hubs: RefCell<Vec<spoke::Hub>>,
}

impl Mesh {
    /// The mesh of `shared`'s server, of start `epoch`.
    fn new(shared: &Shared, epoch: u64) -> Mesh {
        let first = routes(&shared.opts);
        let hubs = (0..shared.opts.remotes.len())
            .filter(|&r| crate::leaf::is_naq(&shared.opts.remotes[r]))
            .enumerate()
            // Slots are below 64: they fit.
            .map(|(k, r)| spoke::Hub::new(shared, r, (first + k) as u16, epoch))
            .collect();
        Mesh {
            epoch,
            accounts: shared.accounts.clone(),
            peers: RefCell::default(),
            told: Rc::new(Told::new(epoch, shared.accounts.clone(), Rc::default())),
            leafs: RefCell::default(),
            leaf_wake: Rc::default(),
            hubs: RefCell::new(hubs),
        }
    }

    /// Tells the others what changed of the interest in `filter` of
    /// `account`, in `queue` if given, as `lane`, lane 0, has it now: the
    /// routes, the naq leafs and the naq hubs of that account.
    pub(crate) fn changed(
        &self,
        lane: &crate::lane::Lane,
        account: u32,
        filter: &[u8],
        queue: Option<&[u8]>,
    ) {
        let index = &*lane.index(account).borrow();
        let slots = &lane.slots;
        let routes = view::routes(index, slots, filter, queue);
        self.told.set(account, filter, queue, routes);
        let name = self
            .accounts
            .get(account as usize)
            .map_or("$G", String::as_str);
        let peers = self.peers.borrow();
        for l in self.leafs.borrow().iter().filter(|l| l.account == account) {
            let leaf = view::ForLeaf {
                slot: l.slot,
                cluster: &l.cluster,
                account: name.as_bytes(),
                routes: &peers,
            };
            let v = view::leaf(index, slots, leaf, filter, queue);
            l.told.set(account, filter, queue, v);
        }
        for h in self.hubs.borrow().iter().filter(|h| h.account == account) {
            h.told.set(
                account,
                filter,
                queue,
                view::hub(index, slots, filter, queue),
            );
        }
    }
}

/// Another server of the cluster, as its route shows it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Peer {
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Its `Hello` came, and the connection holds.
    pub(crate) up: bool,
    pub(crate) server_id: String,
    pub(crate) name: String,
    pub(crate) epoch: u64,
    /// The data endpoint of each of its lanes.
    pub(crate) data: Vec<String>,
    /// Its interest, as applied.
    pub(crate) heard: Heard,
    /// Where its clients connect.
    pub(crate) client_urls: Vec<String>,
    /// Where naq leafs dial it, if they may.
    pub(crate) leaf_urls: Vec<String>,
}

/// Options of every socket of the mesh: heartbeats find a peer gone, and
/// a connection that does not greet in time is tried again.
fn socket_options(identity: Bytes) -> Options {
    Options {
        identity,
        heartbeat_interval: Some(std::time::Duration::from_secs(1)),
        heartbeat_timeout: Some(std::time::Duration::from_secs(3)),
        heartbeat_ttl: Some(std::time::Duration::from_secs(3)),
        handshake_timeout: Some(std::time::Duration::from_secs(3)),
        reconnect: omq_tokio::ReconnectPolicy::Fixed(std::time::Duration::from_millis(100)),
        ..Options::default()
    }
}

/// A `Resync`, encoded.
fn resync() -> Bytes {
    let mut out = Vec::new();
    Control::Resync.encode(&mut out);
    out.into()
}

/// Routes of the cluster of `opts`.
fn routes(opts: &ServerOptions) -> usize {
    opts.cluster.as_ref().map_or(0, |c| c.routes.len())
}

/// The naq hubs `opts` dial.
pub(crate) fn hubs(opts: &ServerOptions) -> usize {
    opts.remotes
        .iter()
        .filter(|r| crate::leaf::is_naq(r))
        .count()
}

/// The account every naq leaf binds on `shared`'s server.
fn leafnodes_account(shared: &Shared) -> u32 {
    let name = shared
        .opts
        .leafnodes
        .as_ref()
        .and_then(|l| l.account.as_deref())
        .unwrap_or("$G");
    // Known to exist: the options were checked. Accounts are few.
    shared.accounts.iter().position(|a| a == name).unwrap_or(0) as u32
}

/// Where lane 0 bound the ports of the mesh.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Bound {
    /// The cluster port, if there is a cluster.
    pub(crate) cluster: Option<SocketAddr>,
    /// The port naq leafs dial, if any.
    pub(crate) leafnodes: Option<SocketAddr>,
}

/// Whether `opts` reach any server over OMQ: a cluster, naq leafs or naq
/// hubs.
pub(crate) fn wanted(opts: &ServerOptions) -> bool {
    opts.cluster.is_some() || opts.leafnodes.is_some() || hubs(opts) > 0
}

/// Binds a ROUTER at `host:port` of `ctx`, for `role`. Returns it, its
/// monitor, made before it binds, and where it is bound.
async fn router(
    ctx: &omq_tokio::Context,
    host: &str,
    port: u16,
) -> Result<(omq_tokio::Socket, omq_tokio::MonitorStream, SocketAddr), String> {
    // Mandatory: a peer's full queue holds the sender up instead of losing
    // part of a snapshot.
    let router = ctx.socket(
        SocketType::Router,
        Options {
            router_mandatory: true,
            ..socket_options(Bytes::new())
        },
    );
    let events = router.monitor();
    let bound = router
        .bind(endpoint(host, port))
        .await
        .map_err(|e| e.to_string())?
        .to_string();
    let addr = socket_addr(&bound).ok_or_else(|| format!("bound {bound}"))?;
    Ok((router, events, addr))
}

/// Runs what `shared`'s server reaches over OMQ from lane 0: binds the
/// cluster port and the port of naq leafs and tells `ready` where, binds
/// data sockets on each of `lanes`, dials every route and every naq hub,
/// and answers what dials it.
pub(crate) async fn run(
    shared: Arc<Shared>,
    lanes: Box<[LaneHandle]>,
    ready: std::sync::mpsc::SyncSender<Result<Bound, String>>,
) {
    let Some(lane) = crate::lane::get(shared.id, 0) else {
        return;
    };
    let mut epoch = [0u8; 8];
    // An epoch of 0 on failure still tells a start apart from none.
    let _ = getrandom::getrandom(&mut epoch);
    let epoch = u64::from_le_bytes(epoch);
    // In place before the server serves clients: none of their interest
    // goes untold.
    let mesh = Rc::new(Mesh::new(&shared, epoch));
    *lane.mesh.borrow_mut() = Some(mesh.clone());
    let ctx = omq_tokio::Context::current();
    let mut bound = Bound::default();
    let cluster = match &shared.opts.cluster {
        Some(c) => match router(&ctx, &c.host, c.port).await {
            Ok((r, _, at)) => {
                bound.cluster = Some(at);
                Some((c.clone(), r))
            }
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        },
        None => None,
    };
    let leafs = match &shared.opts.leafnodes {
        Some(l) => match router(&ctx, &l.host, l.port).await {
            Ok((r, events, at)) => {
                bound.leafnodes = Some(at);
                Some((l.host.clone(), r, events))
            }
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        },
        None => None,
    };
    let _ = ready.send(Ok(bound));
    if let Some((host, r, events)) = leafs {
        let data = bind_data(shared.id, &lanes, &host, Data::Leafs).await;
        let me = hub::Me::new(&shared, &data, epoch, bound.leafnodes);
        tokio::task::spawn_local(hub::serve(lane.clone(), mesh.clone(), (r, events), me));
    }
    for at in 0..mesh.hubs.borrow().len() {
        tokio::task::spawn_local(spoke::dial(shared.clone(), mesh.clone(), at));
    }
    if let Some((c, r)) = cluster {
        let data = bind_data(shared.id, &lanes, &c.host, Data::Routes).await;
        let me = control::Me::new(&shared, &c, &data, epoch, bound.leafnodes);
        control::serve(&shared, &mesh, me, &c, r).await;
    }
}

/// What the data socket of a lane takes.
#[derive(Debug, Clone, Copy)]
enum Data {
    /// The batches of routes, on a PULL.
    Routes,
    /// The batches of naq leafs, on a ROUTER their channels dial.
    Leafs,
}

/// Binds a data socket for `kind` on host `host` on each of `lanes`, and
/// returns their endpoints in lane order. One that cannot bind gives an
/// empty endpoint.
async fn bind_data(server: u64, lanes: &[LaneHandle], host: &str, kind: Data) -> Vec<String> {
    let mut waits = Vec::with_capacity(lanes.len());
    for l in lanes {
        let (tx, rx) = oneshot::channel();
        let host = host.to_owned();
        let index = l.index();
        let spawned = l.spawn(move || async move {
            let Some(lane) = crate::lane::get(server, index) else {
                return;
            };
            let ctx = omq_tokio::Context::current();
            let (socket_type, opts) = match kind {
                Data::Routes => (SocketType::Pull, socket_options(Bytes::new())),
                // Mandatory: a leaf's full channel holds the lane up, as a
                // full PUSH does.
                Data::Leafs => (
                    SocketType::Router,
                    Options {
                        router_mandatory: true,
                        ..socket_options(Bytes::new())
                    },
                ),
            };
            let s = ctx.socket(socket_type, opts);
            let at = s.bind(endpoint(&host, 0)).await.map(|e| e.to_string());
            let ok = at.is_ok();
            let _ = tx.send(at.unwrap_or_default());
            if !ok {
                return;
            }
            match kind {
                Data::Routes => data::receive(lane, s).await,
                Data::Leafs => {
                    let Ok(ids) = s.identity_routing() else {
                        return;
                    };
                    *lane.leaf_router.borrow_mut() = Some(ids.clone());
                    data::receive_leafs(lane, ids).await;
                }
            }
        });
        if spawned.is_ok() {
            waits.push(rx);
        }
    }
    let mut all = Vec::with_capacity(waits.len());
    for w in waits {
        all.push(w.await.unwrap_or_default());
    }
    all
}

/// The address of endpoint `e`, `tcp://host:port`.
fn socket_addr(e: &str) -> Option<SocketAddr> {
    e.strip_prefix("tcp://")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_give_host_and_port() {
        for (s, want) in [
            ("nats-route://a:7000", ("a", 7000)),
            ("nats://b", ("b", PORT)),
            ("c:1", ("c", 1)),
            (" [::1]:9 ", ("::1", 9)),
            ("[::1]", ("::1", PORT)),
        ] {
            assert_eq!(route(s), Ok((want.0.to_owned(), want.1)), "{s}");
        }
        for (s, why) in [
            ("ws://a", "scheme not supported"),
            ("nats-route://u:p@a", "credentials not supported"),
            ("a:x", "bad port"),
            ("nats://", "expected host:port"),
        ] {
            assert_eq!(route(s).unwrap_err(), format!("cluster route {s:?}: {why}"));
        }
        assert_eq!(endpoint("::1", 2), "tcp://[::1]:2");
        assert_eq!(socket_addr("tcp://127.0.0.1:5"), "127.0.0.1:5".parse().ok());
    }
}
