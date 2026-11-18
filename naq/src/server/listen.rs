//! The listeners of a server and its accept loops, on lane 0.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use zzq_tokio::transport::{Listener, TransportOptions};
use zzq_tokio::{Context, Endpoint, LaneHandle};

use super::Shared;
use crate::error::io;
use crate::{Error, Options, conn, lane};

/// How long the accept loop pauses after a failed accept, such as when the
/// process is out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(10);

/// The listeners of a server, bound.
pub(super) struct Ports {
    client: Listener,
    monitor: Option<Listener>,
    ws: Option<Listener>,
}

/// Starts the lanes, then the accept loops of `ports` on lane 0. Returns
/// where lane 0 bound the ports of the servers reached over OMQ.
pub(super) fn run(
    ctx: &Context,
    shared: &Arc<Shared>,
    rxs: Vec<lane::LaneRx>,
    ports: Ports,
    monitor_tls: Option<tokio_rustls::TlsAcceptor>,
) -> Result<crate::mesh::Bound, Error> {
    let lanes: Box<[LaneHandle]> = (0..ctx.lanes()).map(|i| ctx.lane(i).clone()).collect();
    for (l, rx) in lanes.iter().zip(rxs) {
        let (s, index) = (shared.clone(), l.index());
        l.run(move || lane::install(s, index, rx))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    let first = ctx.lane(0);
    shared.monitor.set_tls(monitor_tls);
    if let Some(m) = ports.monitor {
        let s = shared.clone();
        first
            .spawn(move || crate::monitor::serve(m, s))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    if let Some(w) = ports.ws {
        let (l, s, open) = (
            lanes.clone(),
            shared.clone(),
            crate::lame::Accepting::open(shared),
        );
        first
            .spawn(move || accept(w, l, s, Via::Websocket, open))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    // A naq hub is dialed with the cluster, over OMQ.
    for hub in shared.live.hubs.all() {
        let s = shared.clone();
        lanes[hub.lane]
            .spawn(move || crate::leaf::run(s, hub))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    let mesh = if crate::mesh::wanted(&shared.opts()) {
        let (ready, bound) = std::sync::mpsc::sync_channel(1);
        let (l, s) = (lanes.clone(), shared.clone());
        first
            .spawn(move || crate::mesh::run(s, l, ready))
            .map_err(|e| Error::Lanes(io(e)))?;
        mesh_bound(&bound, shared)?
    } else {
        crate::mesh::Bound::default()
    };
    let (c, s, open) = (
        ports.client,
        shared.clone(),
        crate::lame::Accepting::open(shared),
    );
    first
        .spawn(move || accept(c, lanes, s, Via::Client, open))
        .map_err(|e| Error::Lanes(io(e)))?;
    Ok(mesh)
}

/// Where the cluster port and the port of naq leafs were bound, once lane
/// 0 tells it.
fn mesh_bound(
    bound: &std::sync::mpsc::Receiver<Result<crate::mesh::Bound, String>>,
    shared: &Shared,
) -> Result<crate::mesh::Bound, Error> {
    let opts = &shared.opts();
    let ports = [
        opts.cluster
            .as_ref()
            .map(|c| format!("{}:{}", c.host, c.port)),
        opts.leafnodes
            .as_ref()
            .map(|l| format!("{}:{}", l.host, l.port)),
    ];
    let addr = ports.into_iter().flatten().collect::<Vec<_>>().join(", ");
    let failed = |why: String| Error::Listen {
        addr: addr.clone(),
        source: std::io::Error::other(why),
    };
    match bound.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(Ok(at)) => Ok(at),
        Ok(Err(why)) => Err(failed(why)),
        Err(_) => Err(failed("lane 0 did not bind it".into())),
    }
}

/// Where a server's listeners are bound.
pub(super) struct Addrs {
    pub(super) client: SocketAddr,
    pub(super) monitor: Option<SocketAddr>,
    pub(super) ws: Option<SocketAddr>,
}

/// The listeners of `opts`: for clients, monitoring and WebSocket.
pub(super) fn bind_all(ctx: &Context, opts: &Options) -> Result<(Ports, Addrs), Error> {
    let listen = |source| Error::Listen {
        addr: format!("{}:{}", opts.host, opts.port),
        source,
    };
    let (client, addr) = bind(ctx, &opts.host, opts.port).map_err(listen)?;
    let monitor = bind_monitor(ctx, opts)?;
    let ws = bind_websocket(ctx, opts)?;
    let at = Addrs {
        client: addr,
        monitor: monitor.as_ref().map(|(_, a)| *a),
        ws: ws.as_ref().map(|(_, a)| *a),
    };
    let ports = Ports {
        client,
        monitor: monitor.map(|(l, _)| l),
        ws: ws.map(|(l, _)| l),
    };
    Ok((ports, at))
}

/// Binds the monitoring port, HTTP or HTTPS, if `opts` want one.
fn bind_monitor(ctx: &Context, opts: &Options) -> Result<Option<(Listener, SocketAddr)>, Error> {
    let Some(port) = opts.http_port.or(opts.https_port) else {
        return Ok(None);
    };
    let host = opts.http_host.as_deref().unwrap_or(&opts.host);
    let bound = bind(ctx, host, port).map_err(|source| Error::Listen {
        addr: format!("{host}:{port}"),
        source,
    })?;
    Ok(Some(bound))
}

/// Binds the WebSocket port, if `opts` want one.
fn bind_websocket(ctx: &Context, opts: &Options) -> Result<Option<(Listener, SocketAddr)>, Error> {
    let Some(w) = &opts.websocket else {
        return Ok(None);
    };
    let bound = bind(ctx, &w.host, w.port).map_err(|source| Error::Listen {
        addr: format!("{}:{}", w.host, w.port),
        source,
    })?;
    Ok(Some(bound))
}

/// The address `host` names: itself, or for a name such as `localhost`,
/// its first IPv4 address if it has one, as Go listens.
fn resolve(host: &str) -> std::io::Result<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_owned());
    }
    let addrs: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(host, 0))?.collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .map(|a| a.ip().to_string())
        .ok_or_else(|| std::io::Error::other(format!("no address for {host}")))
}

/// Binds `host` and `port` on lane 0, where the accept loops run. The
/// IPv4 wildcard binds as `[::]`, for IPv6 clients too, as Go binds it.
fn bind(ctx: &Context, host: &str, port: u16) -> std::io::Result<(Listener, SocketAddr)> {
    let ip = resolve(host)?;
    if ip == "0.0.0.0"
        && let Ok((l, at)) = bind_ip(ctx, "::".into(), port)
    {
        return Ok((l, SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), at.port())));
    }
    bind_ip(ctx, ip, port)
}

/// Binds address `ip` and `port` on lane 0.
fn bind_ip(ctx: &Context, ip: String, port: u16) -> std::io::Result<(Listener, SocketAddr)> {
    let endpoint = Endpoint::Tcp { host: ip, port };
    let (tx, rx) = std::sync::mpsc::channel();
    let c = ctx.clone();
    ctx.lane(0)
        .spawn(move || async move {
            let bound = Listener::bind(&c, &endpoint, &TransportOptions::default()).await;
            // The listener must not keep the lanes alive.
            drop(c);
            let _ = tx.send(bound);
        })
        .map_err(io)?;
    let listener = rx
        .recv()
        .map_err(|_| std::io::Error::other("lane 0 stopped"))?
        .map_err(io)?;
    let Endpoint::Tcp { host, port } = listener.endpoint() else {
        return Err(std::io::Error::other("not a TCP listener"));
    };
    let ip = host
        .parse()
        .map_err(|_| std::io::Error::other(format!("not an address: {host}")))?;
    Ok((listener, SocketAddr::new(ip, port)))
}

/// The kind of client a port takes.
#[derive(Debug, Clone, Copy)]
enum Via {
    Client,
    Websocket,
}

/// Accepts clients at `door` and hands them to the lanes in turn, until
/// the server stops or goes into lame duck mode. `open` counts the loop
/// open until the listener closed.
async fn accept(
    listener: Listener,
    lanes: Box<[LaneHandle]>,
    shared: Arc<Shared>,
    door: Via,
    open: crate::lame::Accepting,
) {
    accept_until(listener, &lanes, &shared, door).await;
    drop(open);
}

/// Accepts clients at `door` and hands them to `lanes` in turn, until the
/// server stops or goes into lame duck mode, then closes `listener`.
async fn accept_until(
    mut listener: Listener,
    lanes: &[LaneHandle],
    shared: &Arc<Shared>,
    door: Via,
) {
    let mut next = 0;
    loop {
        // Cancel-safe: an accept dropped takes no connection.
        let got = tokio::select! {
            got = listener.accept() => got,
            () = crate::lame::started(shared) => return,
        };
        let stream = match got {
            Ok(s) => s,
            Err(zzq_tokio::Error::Closed) => return,
            Err(_) => {
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        if crate::stop::stopping(shared) || crate::lame::on(shared) {
            return;
        }
        let lane = &lanes[next % lanes.len()];
        next += 1;
        let (s, index) = (shared.clone(), lane.index());
        // Fails only once the lane stopped, which drops the stream.
        let _ = match door {
            Via::Client => lane.spawn(move || conn::run(s, index, stream)),
            Via::Websocket => lane.spawn(move || crate::ws::run(s, index, stream)),
        };
    }
}
