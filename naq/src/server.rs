//! Starting and stopping a server: lanes, the listener, accepting clients.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use zzq_tokio::transport::{Listener, TransportOptions};
use zzq_tokio::{Config, Context, Endpoint, LaneHandle};

use crate::auth::{self, Auth};
use crate::error::io;
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
    /// What clients must authenticate with, if anything.
    pub(crate) auth: Option<Auth>,
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
    next_client: AtomicU64,
}

impl Shared {
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
}

impl Server {
    /// Starts a server and returns once it listens for clients.
    ///
    /// # Errors
    ///
    /// [`Error::Options`] if `opts` contradict themselves, [`Error::Tls`] if
    /// the TLS certificates or key cannot be read,
    /// [`Error::Lanes`] if the lane threads cannot start,
    /// [`Error::Listen`] if the client or monitoring port cannot be bound.
    pub fn start(opts: &Options) -> Result<Server, Error> {
        auth::validate(opts).map_err(Error::Options)?;
        let tls = opts
            .tls
            .as_ref()
            .map(crate::tls::Acceptor::new)
            .transpose()?;
        let accounts = auth::accounts(opts);
        let auth = Auth::new(opts, &accounts);
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
        let (listener, addr) = bind(&ctx, &opts.host, opts.port).map_err(listen)?;
        let monitor = bind_monitor(&ctx, opts)?;
        let monitor_addr = monitor.as_ref().map(|(_, a)| *a);
        let (txs, rxs): (Vec<_>, Vec<_>) = (0..ctx.lanes()).map(|_| lane::mailboxes()).unzip();
        let shared = Arc::new(Shared {
            id: NEXT_SERVER.fetch_add(1, Ordering::Relaxed),
            opts: opts.clone(),
            addr,
            server_id: server_id(),
            lanes: txs.into_boxed_slice(),
            accounts,
            auth,
            counts: (0..ctx.lanes()).map(|_| stats::Shared::default()).collect(),
            events: stats::Events::default(),
            started: std::time::SystemTime::now(),
            gone: AtomicU64::new(0),
            tls,
            next_client: AtomicU64::new(1),
        });
        let lanes: Box<[LaneHandle]> = (0..ctx.lanes()).map(|i| ctx.lane(i).clone()).collect();
        for (l, rx) in lanes.iter().zip(rxs) {
            let (s, index) = (shared.clone(), l.index());
            l.run(move || lane::install(s, index, rx))
                .map_err(|e| Error::Lanes(io(e)))?;
        }
        if let Some((m, _)) = monitor {
            let s = shared.clone();
            ctx.lane(0)
                .spawn(move || crate::monitor::serve(m, s))
                .map_err(|e| Error::Lanes(io(e)))?;
        }
        ctx.lane(0)
            .spawn(move || accept(listener, lanes, shared))
            .map_err(|e| Error::Lanes(io(e)))?;
        Ok(Server {
            _ctx: ctx,
            addr,
            monitor: monitor_addr,
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

/// Binds `host` and `port` on lane 0, where the accept loops run.
fn bind(ctx: &Context, host: &str, port: u16) -> std::io::Result<(Listener, SocketAddr)> {
    let endpoint = Endpoint::Tcp {
        host: resolve(host)?,
        port,
    };
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

/// Accepts clients and hands them to the lanes in turn.
async fn accept(mut listener: Listener, lanes: Box<[LaneHandle]>, shared: Arc<Shared>) {
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
        let _ = lane.spawn(move || conn::run(s, index, stream));
    }
}

/// 22 random-looking characters, as `nats-server` IDs have.
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
