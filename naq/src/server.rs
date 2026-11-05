//! Starting and stopping a server: lanes, the listener, accepting clients.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use zzq_tokio::transport::{Listener, TransportOptions};
use zzq_tokio::{Config, Context, Endpoint, LaneHandle};

use crate::auth::{self, Auth};
use crate::error::io;
use crate::tls::Acceptor;
use crate::{Error, Options, conn, lane, stats};

/// How long the accept loop pauses after a failed accept, such as when the
/// process is out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(10);

/// Tells servers in one process apart, for the lanes' state.
static NEXT_SERVER: AtomicU64 = AtomicU64::new(1);

/// What every lane of a server shares. Read only.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) id: u64,
    pub(crate) opts: Options,
    /// Where clients connect, as bound.
    pub(crate) addr: SocketAddr,
    /// Random part of the server ID in `INFO`.
    pub(crate) server_id: String,
    /// The way into each lane.
    pub(crate) lanes: Box<[lane::LaneTx]>,
    /// Account names by id, `$G` first.
    pub(crate) accounts: Box<[String]>,
    /// The imports of each account, by id.
    pub(crate) imports: Box<[crate::imports::Imports]>,
    /// The requests this server sent into each account through service
    /// imports, by id.
    pub(crate) responses: Box<[Arc<crate::imports::service::Responses>]>,
    /// The system account, if there is one.
    pub(crate) system: Option<u32>,
    /// The hash of the server's name that replies tracked for latency end
    /// in, with a system account, as `nats-server` makes it.
    pub(crate) node: Option<[u8; 8]>,
    /// What clients must authenticate with, if anything.
    pub(crate) auth: Option<Auth>,
    /// What WebSocket clients authenticate with, where it is not `auth`.
    ws_auth: Option<Auth>,
    /// The loop detection subject of each account on leaf node links.
    pub(crate) lds: Box<[String]>,
    /// Message counts of each lane.
    pub(crate) counts: Box<[stats::Shared]>,
    /// Slow consumers and stale clients so far.
    pub(crate) events: stats::Events,
    /// When the server started.
    pub(crate) started: std::time::SystemTime,
    /// Clients that went away.
    pub(crate) gone: AtomicU64,
    /// TLS for clients, if they must use it.
    pub(crate) tls: Option<crate::tls::Acceptor>,
    /// The WebSocket port, if there is one.
    pub(crate) ws: Option<crate::ws::Door>,
    /// TLS to the hub of each leaf node remote.
    pub(crate) leaf_tls: Box<[crate::leaf::Connector]>,
    /// Where the clients of the other servers of the cluster connect, as
    /// they told it.
    pub(crate) connect_urls: std::sync::Mutex<Vec<String>>,
    next_client: AtomicU64,
}

impl Shared {
    /// What clients authenticate with, over WebSocket if `ws`, if anything.
    pub(crate) const fn auth_for(&self, ws: bool) -> Option<&Auth> {
        match &self.ws_auth {
            Some(a) if ws => Some(a),
            _ => self.auth.as_ref(),
        }
    }

    /// A new client ID, unique in this server. IDs start at 1.
    pub(crate) fn next_client(&self) -> u64 {
        // Relaxed: IDs only need to be distinct.
        self.next_client.fetch_add(1, Ordering::Relaxed)
    }

    /// Notes that a client went away.
    pub(crate) fn client_gone(&self) {
        // Relaxed: a counter, read now and then.
        self.gone.fetch_add(1, Ordering::Relaxed);
    }

    /// Clients accepted so far.
    pub(crate) fn total_clients(&self) -> u64 {
        // Relaxed: a count read now and then.
        self.next_client.load(Ordering::Relaxed) - 1
    }
}

/// A running server. Dropping it stops the server and closes its
/// connections.
#[derive(Debug)]
pub struct Server {
    // Held, not used: the lanes stop when the last clone drops.
    _ctx: Context,
    addr: SocketAddr,
    monitor: Option<SocketAddr>,
    websocket: Option<SocketAddr>,
    mesh: crate::mesh::Bound,
}

impl Server {
    /// Starts a server and returns once it listens for clients.
    ///
    /// # Errors
    ///
    /// [`Error::Options`] if `opts` contradict themselves, [`Error::Tls`] if
    /// the TLS certificates or key cannot be read,
    /// [`Error::Lanes`] if the lane threads cannot start,
    /// [`Error::Listen`] if the client, WebSocket or monitoring port cannot
    /// be bound.
    pub fn start(opts: &Options) -> Result<Server, Error> {
        let setup = check(opts)?;
        let accounts = auth::accounts(opts);
        let system = auth::system(opts, &accounts);
        let auth = Auth::new(opts, &accounts);
        let ws_auth = Auth::websocket(opts, auth.as_ref());
        let ctx = Context::with_config(&Config {
            io_threads: lanes(opts.lanes),
            name: "naq".into(),
            ..Config::default()
        })
        .map_err(|e| Error::Lanes(io(e)))?;
        let listen = |source| Error::Listen {
            addr: format!("{}:{}", opts.host, opts.port),
            source,
        };
        let (client, addr) = bind(&ctx, &opts.host, opts.port).map_err(listen)?;
        let monitor = bind_monitor(&ctx, opts)?;
        let ws = bind_websocket(&ctx, opts)?;
        let monitor_addr = monitor.as_ref().map(|(_, a)| *a);
        let ws_addr = ws.as_ref().map(|(_, a)| *a);
        let (txs, rxs): (Vec<_>, Vec<_>) = (0..ctx.lanes()).map(|_| lane::mailboxes()).unzip();
        let shared = Arc::new(Shared {
            id: NEXT_SERVER.fetch_add(1, Ordering::Relaxed),
            opts: opts.clone(),
            addr,
            server_id: server_id(),
            lanes: txs.into_boxed_slice(),
            lds: accounts.iter().map(|_| crate::leaf::lds()).collect(),
            accounts,
            auth,
            ws_auth,
            counts: (0..ctx.lanes()).map(|_| stats::Shared::default()).collect(),
            events: stats::Events::default(),
            started: std::time::SystemTime::now(),
            gone: AtomicU64::new(0),
            tls: setup.tls,
            ws: door(opts, ws_addr, setup.ws_tls),
            leaf_tls: setup.leaf_tls,
            responses: (0..setup.imports.len())
                .map(|_| Arc::new(crate::imports::service::Responses::new(random())))
                .collect(),
            imports: setup.imports,
            system,
            node: system.map(|_| node(&opts.server_name)),
            connect_urls: std::sync::Mutex::default(),
            next_client: AtomicU64::new(1),
        });
        let ports = Ports {
            client,
            monitor: monitor.map(|(l, _)| l),
            ws: ws.map(|(l, _)| l),
        };
        let mesh = run(&ctx, &shared, rxs, ports)?;
        Ok(Server {
            _ctx: ctx,
            addr,
            monitor: monitor_addr,
            websocket: ws_addr,
            mesh,
        })
    }

    /// Where clients connect.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Where monitoring is served, if it is.
    pub const fn monitor_addr(&self) -> Option<SocketAddr> {
        self.monitor
    }

    /// Where WebSocket clients connect, if they may.
    pub const fn websocket_addr(&self) -> Option<SocketAddr> {
        self.websocket
    }

    /// Where the other servers of its cluster connect, if it has one.
    pub const fn cluster_addr(&self) -> Option<SocketAddr> {
        self.mesh.cluster
    }

    /// Where naq leaf nodes connect, if it takes them
    /// ([`Options::leafnodes`]).
    pub const fn leafnode_addr(&self) -> Option<SocketAddr> {
        self.mesh.leafnodes
    }
}

/// The WebSocket port of `opts`, bound at `addr`, with TLS `tls`.
fn door(
    opts: &Options,
    addr: Option<SocketAddr>,
    tls: Option<Acceptor>,
) -> Option<crate::ws::Door> {
    let opts = opts.websocket.clone()?;
    Some(crate::ws::Door {
        opts,
        tls,
        addr: addr?,
    })
}

/// TLS as the options set it up, its files read.
struct Setup {
    /// For the client port.
    tls: Option<Acceptor>,
    /// For the WebSocket port.
    ws_tls: Option<Acceptor>,
    /// For each leaf node remote.
    leaf_tls: Box<[crate::leaf::Connector]>,
    /// The imports of each account, by id.
    imports: Box<[crate::imports::Imports]>,
}

/// Checks `opts` and reads the TLS files they name: for the client port,
/// the WebSocket port and the leaf node remotes.
fn check(opts: &Options) -> Result<Setup, Error> {
    auth::validate(opts).map_err(Error::Options)?;
    let imports = crate::imports::link(opts).map_err(Error::Options)?;
    crate::leaf::validate(opts).map_err(Error::Options)?;
    crate::mesh::validate(opts).map_err(Error::Options)?;
    if let Some(w) = &opts.websocket {
        crate::ws::validate(w).map_err(Error::Options)?;
    }
    let tls = opts.tls.as_ref().map(Acceptor::new).transpose()?;
    let ws_tls = opts
        .websocket
        .as_ref()
        .and_then(|w| w.tls.as_ref())
        .map(Acceptor::new)
        .transpose()?;
    let leaf_tls = opts
        .remotes
        .iter()
        .map(crate::leaf::Connector::new)
        .collect::<Result<_, _>>()?;
    Ok(Setup {
        tls,
        ws_tls,
        leaf_tls,
        imports,
    })
}

/// The listeners of a server, bound.
struct Ports {
    client: Listener,
    monitor: Option<Listener>,
    ws: Option<Listener>,
}

/// Starts the lanes, then the accept loops of `ports` on lane 0. Returns
/// where lane 0 bound the ports of the servers reached over OMQ.
fn run(
    ctx: &Context,
    shared: &Arc<Shared>,
    rxs: Vec<lane::LaneRx>,
    ports: Ports,
) -> Result<crate::mesh::Bound, Error> {
    let lanes: Box<[LaneHandle]> = (0..ctx.lanes()).map(|i| ctx.lane(i).clone()).collect();
    for (l, rx) in lanes.iter().zip(rxs) {
        let (s, index) = (shared.clone(), l.index());
        l.run(move || lane::install(s, index, rx))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    let first = ctx.lane(0);
    if let Some(m) = ports.monitor {
        let s = shared.clone();
        first
            .spawn(move || crate::monitor::serve(m, s))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    if let Some(w) = ports.ws {
        let (l, s) = (lanes.clone(), shared.clone());
        first
            .spawn(move || accept(w, l, s, Door::Websocket))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    // A naq hub is dialed with the cluster, over OMQ.
    let go =
        (0..shared.opts.remotes.len()).filter(|&i| !crate::leaf::is_naq(&shared.opts.remotes[i]));
    for index in go {
        let lane = &lanes[index % lanes.len()];
        let (s, at) = (shared.clone(), lane.index());
        lane.spawn(move || crate::leaf::run(s, at, index))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    let mesh = if crate::mesh::wanted(&shared.opts) {
        let (ready, bound) = std::sync::mpsc::sync_channel(1);
        let (l, s) = (lanes.clone(), shared.clone());
        first
            .spawn(move || crate::mesh::run(s, l, ready))
            .map_err(|e| Error::Lanes(io(e)))?;
        mesh_bound(&bound, shared)?
    } else {
        crate::mesh::Bound::default()
    };
    let (c, s) = (ports.client, shared.clone());
    first
        .spawn(move || accept(c, lanes, s, Door::Client))
        .map_err(|e| Error::Lanes(io(e)))?;
    Ok(mesh)
}

/// Where the cluster port and the port of naq leafs were bound, once lane
/// 0 tells it.
fn mesh_bound(
    bound: &std::sync::mpsc::Receiver<Result<crate::mesh::Bound, String>>,
    shared: &Shared,
) -> Result<crate::mesh::Bound, Error> {
    let opts = &shared.opts;
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

/// The lanes to run for `wanted`: 0 is one per core the process may run on.
fn lanes(wanted: usize) -> usize {
    if wanted > 0 {
        return wanted;
    }
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

/// Binds the monitoring port, if `opts` want one.
fn bind_monitor(ctx: &Context, opts: &Options) -> Result<Option<(Listener, SocketAddr)>, Error> {
    let Some(port) = opts.http_port else {
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
enum Door {
    Client,
    Websocket,
}

/// Accepts clients at `door` and hands them to the lanes in turn.
async fn accept(mut listener: Listener, lanes: Box<[LaneHandle]>, shared: Arc<Shared>, door: Door) {
    let mut next = 0;
    loop {
        let stream = match listener.accept().await {
            Ok(s) => s,
            Err(zzq_tokio::Error::Closed) => return,
            Err(_) => {
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let lane = &lanes[next % lanes.len()];
        next += 1;
        let (s, index) = (shared.clone(), lane.index());
        // Fails only once the lane stopped, which drops the stream.
        let _ = match door {
            Door::Client => lane.spawn(move || conn::run(s, index, stream)),
            Door::Websocket => lane.spawn(move || crate::ws::run(s, index, stream)),
        };
    }
}

/// 22 random-looking characters, as `nats-server` IDs have.
/// The hash of server name `name`: eight letters or digits from its
/// SHA-256, as `nats-server` makes it.
fn node(name: &str) -> [u8; 8] {
    use sha2::Digest;
    let sum = sha2::Sha256::digest(name.as_bytes());
    let mut h = [0; 8];
    for (b, s) in h.iter_mut().zip(sum) {
        *b = crate::imports::service::base62(u64::from(s));
    }
    h
}

/// Numbers below what they are asked for, made from fresh random state.
fn random() -> impl FnMut(u64) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let state = std::collections::hash_map::RandomState::new();
    let mut n = 0u64;
    move |below| {
        let mut h = state.build_hasher();
        h.write_u64(n);
        n += 1;
        h.finish() % below
    }
}

fn server_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let state = std::collections::hash_map::RandomState::new();
    let mut id = String::with_capacity(22);
    let mut bits = 0u64;
    for i in 0..22 {
        if i % 12 == 0 {
            let mut h = state.build_hasher();
            h.write_usize(i);
            bits = h.finish();
        }
        id.push(char::from(ALPHABET[(bits & 31) as usize]));
        bits >>= 5;
    }
    id
}
