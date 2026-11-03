//! Starting and stopping a server: lanes, the listener, accepting clients.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use zzq_tokio::transport::{Listener, TransportOptions};
use zzq_tokio::{Config, Context, Endpoint, LaneHandle};

use crate::auth::{self, Auth};
use crate::error::io;
use crate::{Error, Options, conn, lane};

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
    next_client: AtomicU64,
}

impl Shared {
    /// A new client ID, unique in this server. IDs start at 1.
    pub(crate) fn next_client(&self) -> u64 {
        // Relaxed: IDs only need to be distinct.
        self.next_client.fetch_add(1, Ordering::Relaxed)
    }
}

/// A running server. Dropping it stops the server and closes its
/// connections.
#[derive(Debug)]
pub struct Server {
    // Held, not used: the lanes stop when the last clone drops.
    _ctx: Context,
    addr: SocketAddr,
}

impl Server {
    /// Starts a server and returns once it listens for clients.
    ///
    /// # Errors
    ///
    /// [`Error::Options`] if `opts` contradict themselves,
    /// [`Error::Lanes`] if the lane threads cannot start,
    /// [`Error::Listen`] if the client port cannot be bound.
    pub fn start(opts: &Options) -> Result<Server, Error> {
        auth::validate(opts).map_err(Error::Options)?;
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
        let (listener, addr) = bind(&ctx, opts).map_err(listen)?;
        let (txs, rxs): (Vec<_>, Vec<_>) = (0..ctx.lanes()).map(|_| lane::mailboxes()).unzip();
        let shared = Arc::new(Shared {
            id: NEXT_SERVER.fetch_add(1, Ordering::Relaxed),
            opts: opts.clone(),
            addr,
            server_id: server_id(),
            lanes: txs.into_boxed_slice(),
            accounts,
            auth,
            next_client: AtomicU64::new(1),
        });
        let lanes: Box<[LaneHandle]> = (0..ctx.lanes()).map(|i| ctx.lane(i).clone()).collect();
        for (l, rx) in lanes.iter().zip(rxs) {
            let (s, index) = (shared.clone(), l.index());
            l.run(move || lane::install(s, index, rx))
                .map_err(|e| Error::Lanes(io(e)))?;
        }
        ctx.lane(0)
            .spawn(move || accept(listener, lanes, shared))
            .map_err(|e| Error::Lanes(io(e)))?;
        Ok(Server { _ctx: ctx, addr })
    }

    /// Where clients connect.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// The lanes to run for `wanted`: 0 is one per core the process may run on.
fn lanes(wanted: usize) -> usize {
    if wanted > 0 {
        return wanted;
    }
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

/// Binds the client port on lane 0, where the accept loop runs.
fn bind(ctx: &Context, opts: &Options) -> std::io::Result<(Listener, SocketAddr)> {
    let endpoint = Endpoint::Tcp {
        host: opts.host.clone(),
        port: opts.port,
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
