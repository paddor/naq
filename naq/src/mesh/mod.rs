//! The mesh: the other naq servers of a fixed cluster, over OMQ.
//!
//! Lane 0 holds the control sockets: a ROUTER on the cluster port, which
//! answers each server that dials it, and a DEALER to each route, which
//! learns that server's interest. Every lane binds a PULL for data from
//! the others. See `tmp/nats/MESH.md`.

mod control;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use omq_tokio::{Options, SocketType};
use tokio::sync::oneshot;
use zzq_tokio::LaneHandle;

use crate::server::Shared;
use crate::{Cluster, Options as ServerOptions};

/// The port of a route URL without one, as in `nats-server`.
const PORT: u16 = 6222;

/// Why `opts.cluster` cannot run as given.
pub(crate) fn validate(opts: &ServerOptions) -> Result<(), String> {
    let Some(c) = &opts.cluster else {
        return Ok(());
    };
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

/// What lane 0 knows of the other servers, by route.
#[derive(Debug, Default)]
pub(crate) struct Mesh {
    pub(crate) peers: RefCell<Vec<Peer>>,
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
}

/// Options of every socket of the mesh: heartbeats find a peer gone.
fn socket_options(identity: Bytes) -> Options {
    Options {
        identity,
        heartbeat_interval: Some(std::time::Duration::from_secs(1)),
        heartbeat_timeout: Some(std::time::Duration::from_secs(3)),
        reconnect: omq_tokio::ReconnectPolicy::Fixed(std::time::Duration::from_millis(100)),
        ..Options::default()
    }
}

/// Runs the mesh of `shared`'s cluster from lane 0: binds the control
/// port and tells `ready` where, binds a data socket on each of `lanes`,
/// and dials every route.
pub(crate) async fn run(
    shared: Arc<Shared>,
    lanes: Box<[LaneHandle]>,
    ready: std::sync::mpsc::SyncSender<Result<SocketAddr, String>>,
) {
    let Some(c) = shared.opts.cluster.clone() else {
        return;
    };
    let Some(lane) = crate::lane::get(shared.id, 0) else {
        return;
    };
    let ctx = omq_tokio::Context::current();
    let router = ctx.socket(SocketType::Router, socket_options(Bytes::new()));
    let bound = match router.bind(endpoint(&c.host, c.port)).await {
        Ok(at) => at.to_string(),
        Err(e) => {
            let _ = ready.send(Err(e.to_string()));
            return;
        }
    };
    let Some(addr) = socket_addr(&bound) else {
        let _ = ready.send(Err(format!("bound {bound}")));
        return;
    };
    let _ = ready.send(Ok(addr));
    let data = bind_data(&lanes, &c).await;
    let mesh = std::rc::Rc::new(Mesh::default());
    *lane.mesh.borrow_mut() = Some(mesh.clone());
    let me = control::Me::new(&shared, &c, &data);
    control::serve(&lane, &mesh, me, &c, router).await;
}

/// Binds a data socket on each of `lanes`, and returns their endpoints in
/// lane order. One that cannot bind gives an empty endpoint.
async fn bind_data(lanes: &[LaneHandle], c: &Cluster) -> Vec<String> {
    let mut waits = Vec::with_capacity(lanes.len());
    for l in lanes {
        let (tx, rx) = oneshot::channel();
        let host = c.host.clone();
        let spawned = l.spawn(move || async move {
            let ctx = omq_tokio::Context::current();
            let pull = ctx.socket(SocketType::Pull, socket_options(Bytes::new()));
            let at = pull.bind(endpoint(&host, 0)).await.map(|e| e.to_string());
            let ok = at.is_ok();
            let _ = tx.send(at.unwrap_or_default());
            if ok {
                // Data comes with the routing of it; until then, drained.
                while pull.recv().await.is_ok() {}
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
