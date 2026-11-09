//! Starting and stopping a server: lanes, the listener, accepting clients.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use zzq_tokio::transport::{Listener, TransportOptions};
use zzq_tokio::{Config, Context, Endpoint, LaneHandle};

use crate::auth::{self, Auth, Logins};
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
    /// The options as last loaded: those it started with, then those of
    /// each reload.
    options: std::sync::RwLock<Arc<Options>>,
    /// The most bytes a client may have waiting ([`Options::max_pending`]),
    /// which no reload changes.
    pub(crate) max_pending: usize,
    /// Where clients connect, as bound.
    pub(crate) addr: SocketAddr,
    /// The server ID in `INFO`: the public key of `keys.server`.
    pub(crate) server_id: String,
    pub(crate) keys: Keys,
    /// The way into each lane.
    pub(crate) lanes: Box<[lane::LaneTx]>,
    /// The accounts, by id, `$G` first.
    pub(crate) accounts: Arc<crate::accounts::Accounts>,
    /// The system account, if there is one.
    pub(crate) system: Option<u32>,
    /// The directory resolver, if there is one.
    pub(crate) resolver: Option<crate::resolver::Dir>,
    /// What the server keeps for its services on `$SYS`.
    pub(crate) sys: crate::sys::State,
    /// What clients must authenticate with, if anything.
    logins: std::sync::RwLock<Arc<Logins>>,
    /// The operator mode users log in under, if any: no reload changes
    /// it.
    trust: Option<Arc<crate::jwt::trust::Trust>>,
    /// The auth callouts clients log in through, if any.
    pub(crate) callouts: Option<crate::callout::Callouts>,
    /// Where the server logs to.
    pub(crate) log: crate::log::Log,
    /// It shuts down: no new connections.
    pub(crate) stopping: std::sync::atomic::AtomicBool,
    /// Where it stands in lame duck mode.
    pub(crate) lame: crate::lame::Lame,
    /// Message counts of the clients of each lane.
    pub(crate) counts: Box<[stats::Shared]>,
    /// Message counts of the links and routes of each lane.
    pub(crate) peer_counts: Box<[stats::Shared]>,
    /// What monitoring keeps.
    pub(crate) monitor: crate::monitor::State,
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
    /// What its reloads keep.
    pub(crate) reload: crate::reload::State,
    next_client: AtomicU64,
}

impl Shared {
    /// The options as last loaded.
    pub(crate) fn opts(&self) -> Arc<Options> {
        self.options
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Takes `opts` as the options from now on.
    pub(crate) fn set_opts(&self, opts: Options) {
        *self.options.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(opts);
    }

    /// What clients authenticate with, over WebSocket if `ws`, if anything.
    pub(crate) fn logins(&self) -> Arc<Logins> {
        self.logins
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Takes the logins `opts` ask for, of users in `accounts`, the
    /// server's by id, from now on.
    pub(crate) fn relogin(&self, opts: &Options, accounts: &[String]) {
        let logins = Logins::new(opts, accounts, self.trust.as_ref());
        *self.logins.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(logins);
    }

    /// The operator mode users log in under, if any.
    pub(crate) fn trust(&self) -> Option<&crate::jwt::trust::Trust> {
        self.trust.as_deref()
    }

    /// A new client ID, unique in this server. IDs start at 1.
    pub(crate) fn next_client(&self) -> u64 {
        // Relaxed: IDs only need to be distinct.
        self.next_client.fetch_add(1, Ordering::Relaxed)
    }

    /// Counts client `id` among the connections of `account`, unless the
    /// account has all it may across the cluster, as far as this server
    /// knows.
    pub(crate) fn count(&self, account: u32, id: u64) -> bool {
        let Some(a) = self.accounts.get(account) else {
            return false;
        };
        let limit = usize::try_from(a.limit()).ok();
        // The others' first: the two locks do not nest.
        let remote = limit.map_or(0, |_| self.sys.remote.conns(account));
        let mut ids = a.conns.lock().unwrap_or_else(PoisonError::into_inner);
        if limit.is_some_and(|l| ids.len() + remote >= l) {
            return false;
        }
        ids.insert(id);
        drop(ids);
        crate::sys::conns_changed(self, account);
        true
    }

    /// Lets client `id` of `account` that [`Shared::count`] counted go.
    pub(crate) fn uncount(&self, account: u32, id: u64) {
        let Some(a) = self.accounts.get(account) else {
            return;
        };
        let gone = a
            .conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        if gone {
            crate::sys::conns_changed(self, account);
        }
    }

    /// Whether client `id` of `account` is among the oldest `limit`
    /// connections, those an account of that many keeps.
    pub(crate) fn kept(&self, account: u32, id: u64, limit: i64) -> bool {
        let Ok(limit) = usize::try_from(limit) else {
            return true;
        };
        let Some(a) = self.accounts.get(account) else {
            return true;
        };
        let ids = a.conns.lock().unwrap_or_else(PoisonError::into_inner);
        ids.range(..id).count() < limit
    }

    /// Where the server listens, as bound.
    pub(crate) fn bound(&self) -> crate::log::banner::Bound {
        let mesh = self.monitor.mesh.get().copied().unwrap_or_default();
        crate::log::banner::Bound {
            client: self.addr,
            monitor: self.monitor.addr(),
            websocket: self.ws.as_ref().map(|w| w.addr),
            leafnodes: mesh.leafnodes,
            cluster: mesh.cluster,
        }
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

/// A running server. Dropping it stops the server at once and drops its
/// connections; [`Server::shutdown`] lets them close first.
#[derive(Debug)]
pub struct Server {
    // Held, not used: the lanes stop when the last clone drops.
    _ctx: Context,
    shared: Arc<Shared>,
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
    /// be bound, [`Error::Log`] if the log cannot be opened,
    /// [`Error::Write`] if the process ID or ports file cannot be written.
    pub fn start(opts: &Options) -> Result<Server, Error> {
        let setup = check(opts)?;
        let log = crate::log::Log::new(&opts.log).map_err(Error::Log)?;
        let accounts = auth::accounts(opts);
        let system = auth::system(opts, &accounts);
        let logins = Logins::new(opts, &accounts, None);
        let ctx = context(opts)?;
        let (ports, at) = bind_all(&ctx, opts)?;
        let (txs, rxs): (Vec<_>, Vec<_>) = (0..ctx.lanes()).map(|_| lane::mailboxes()).unzip();
        let keys = Keys::new();
        let started = std::time::SystemTime::now();
        let node = node(&opts.server_name);
        let shared = Arc::new(Shared {
            id: NEXT_SERVER.fetch_add(1, Ordering::Relaxed),
            options: std::sync::RwLock::new(Arc::new(opts.clone())),
            max_pending: opts.max_pending,
            addr: at.client,
            callouts: crate::callout::Callouts::new(opts, &accounts, logins.auth.as_ref(), node),
            server_id: keys.server.public_key(),
            keys,
            lanes: txs.into_boxed_slice(),
            accounts: Arc::new(new_accounts(
                &accounts,
                setup.imports,
                setup.resolver.is_some(),
                opts,
            )),
            resolver: setup.resolver,
            trust: logins.auth.as_ref().and_then(Auth::trust_arc).cloned(),
            logins: std::sync::RwLock::new(Arc::new(logins)),
            log,
            stopping: std::sync::atomic::AtomicBool::new(false),
            lame: crate::lame::Lame::default(),
            counts: (0..ctx.lanes()).map(|_| stats::Shared::default()).collect(),
            peer_counts: (0..ctx.lanes()).map(|_| stats::Shared::default()).collect(),
            monitor: crate::monitor::State::new(opts, started, at.monitor),
            events: stats::Events::default(),
            started,
            gone: AtomicU64::new(0),
            tls: setup.tls,
            ws: door(opts, at.ws, setup.ws_tls),
            leaf_tls: setup.leaf_tls,
            system,
            sys: crate::sys::State::new(system.map(|_| node)),
            connect_urls: std::sync::Mutex::default(),
            reload: crate::reload::State::default(),
            next_client: AtomicU64::new(1),
        });
        let mesh = run(&ctx, &shared, rxs, ports, setup.monitor_tls)?;
        let _ = shared.monitor.mesh.set(mesh);
        *shared.reload.ports() = announce(&shared)?;
        Ok(Server {
            _ctx: ctx,
            shared,
            addr: at.client,
            monitor: at.monitor,
            websocket: at.ws,
            mesh,
        })
    }

    /// Stops the server as `nats-server` does: it takes no more
    /// connections, closes those it has with `Server Shutdown`, lets them
    /// write what is left for a few seconds, then stops its lanes.
    ///
    /// # Panics
    ///
    /// Called from within an async runtime, which it would block.
    pub fn shutdown(self) {
        crate::stop::server(&self.shared);
    }

    /// Puts the server in lame duck mode, as `nats-server` does, then shuts
    /// it down as [`Server::shutdown`] does. It takes no more clients,
    /// tells those it has and the other servers of its cluster that it
    /// goes, and after [`Options::lame_duck_grace_period`] closes its
    /// clients one by one, spread over the rest of
    /// [`Options::lame_duck_duration`], so that they do not all reconnect
    /// at once. Returns once it stopped.
    ///
    /// # Panics
    ///
    /// Called from within an async runtime, which it would block.
    pub fn lame_duck_shutdown(self) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build();
        // Without a runtime for its timers, it shuts down at once.
        if let Ok(rt) = rt {
            rt.block_on(self.lame_duck());
        }
        self.shutdown();
    }

    /// Lame duck mode, up to the shutdown that follows it.
    pub(crate) fn lame_duck(&self) -> impl Future<Output = ()> + 'static {
        crate::lame::run(self.shared.clone())
    }

    /// Serves until one of `signals` stops it, and shuts it down, as
    /// `nats-server` handles signals: `INT` and `TERM` stop it, `USR2`
    /// puts it in lame duck mode first, `USR1` opens the log file again,
    /// `HUP` reloads the configuration ([`Server::reload`]).
    ///
    /// # Panics
    ///
    /// Called from within an async runtime.
    pub fn wait_for_signals(self, signals: crate::Signals) {
        signals.wait(&self);
        self.shutdown();
    }

    /// Reloads the configuration, as `nats-server` does on `HUP`: reads the
    /// options again, from [`Options::config_file`] or as
    /// [`Server::reload_with`] set, and takes them if the server can take
    /// every change, else none. Clients take the new limits at once.
    ///
    /// # Errors
    ///
    /// [`Error::Reload`] for a change the running server cannot take, such
    /// as of a port, or without a configuration file; the errors of
    /// [`Options::from_file`], and those of [`Server::start`] for options
    /// that contradict themselves.
    pub fn reload(&self) -> Result<(), Error> {
        crate::reload::reload(&self.shared)
    }

    /// Reads the options again with `read` at each reload, in place of
    /// [`Options::from_file`] of [`Options::config_file`]: for options that
    /// come from more than a file, such as flags given on the command
    /// line.
    pub fn reload_with(&self, read: impl Fn() -> Result<Options, Error> + Send + Sync + 'static) {
        self.shared.reload.read_with(Arc::new(read));
    }

    /// Opens the log file again at its path, as after another tool moved
    /// it away. Without a log file, it logs that it did nothing.
    pub fn reopen_log(&self) {
        self.shared.log.reopen();
    }

    pub(crate) fn log(&self) -> &crate::log::Log {
        &self.shared.log
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

/// The accounts `names`, with `imports`, room for more if `growing`, and
/// the connection limits `opts` give them.
fn new_accounts(
    names: &[String],
    imports: Box<[crate::imports::Imports]>,
    growing: bool,
    opts: &Options,
) -> crate::accounts::Accounts {
    let accounts = crate::accounts::Accounts::new(names, imports, growing, responses);
    for a in &opts.accounts {
        let id = accounts.id(&a.name);
        if let (Some(acc), Some(n)) = (id.and_then(|id| accounts.get(id)), a.max_connections) {
            acc.set_limit(i64::from(n));
        }
    }
    accounts
}

/// The engine context of the lanes `opts` ask for.
fn context(opts: &Options) -> Result<Context, Error> {
    Context::with_config(&Config {
        io_threads: lanes(opts.lanes),
        name: "naq".into(),
        ..Config::default()
    })
    .map_err(|e| Error::Lanes(io(e)))
}

/// Logs the start of `shared`, and writes its process ID and ports files.
/// Returns the ports file.
fn announce(shared: &Shared) -> Result<Option<std::path::PathBuf>, Error> {
    let bound = shared.bound();
    let o = &shared.opts();
    let write = |path: &std::path::Path| {
        let path = path.display().to_string();
        move |source| Error::Write { path, source }
    };
    // Before the server says it is ready: a tool that waits for that
    // finds the file.
    if let Some(p) = &o.pid_file {
        crate::files::pid(p).map_err(write(p))?;
    }
    crate::log::banner::log(shared, &bound);
    let Some(dir) = &o.ports_file_dir else {
        return Ok(None);
    };
    crate::files::ports(dir, o, &bound)
        .map(Some)
        .map_err(write(dir))
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(p) = self.shared.reload.ports().take() {
            let _ = std::fs::remove_file(p);
        }
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
    /// The directory resolver, if there is one.
    resolver: Option<crate::resolver::Dir>,
    /// For the HTTPS monitoring port.
    monitor_tls: Option<tokio_rustls::TlsAcceptor>,
}

/// Checks `opts` and reads the TLS files they name: for the client port,
/// the WebSocket port and the leaf node remotes.
fn check(opts: &Options) -> Result<Setup, Error> {
    validate(opts)?;
    let imports = crate::imports::link(opts).map_err(Error::Options)?;
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
        resolver: crate::resolver::Dir::open(opts).map_err(Error::Options)?,
        monitor_tls: crate::monitor::acceptor(opts)?,
    })
}

/// Checks that `opts` do not contradict themselves.
///
/// # Errors
///
/// [`Error::Options`] or [`Error::Tls`], as [`Server::start`] gives them.
pub(crate) fn validate(opts: &Options) -> Result<(), Error> {
    auth::validate(opts).map_err(Error::Options)?;
    crate::imports::link(opts).map_err(Error::Options)?;
    crate::leaf::validate(opts).map_err(Error::Options)?;
    crate::mesh::validate(opts).map_err(Error::Options)?;
    crate::lame::validate(opts).map_err(Error::Options)?;
    crate::monitor::validate(opts)?;
    if let Some(w) = &opts.websocket {
        crate::ws::validate(w).map_err(Error::Options)?;
    }
    Ok(())
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
    monitor_tls: Option<tokio_rustls::TlsAcceptor>,
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
            .spawn(move || crate::monitor::serve(m, s, monitor_tls))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    if let Some(w) = ports.ws {
        let (l, s, open) = (
            lanes.clone(),
            shared.clone(),
            crate::lame::Door::open(shared),
        );
        first
            .spawn(move || accept(w, l, s, Door::Websocket, open))
            .map_err(|e| Error::Lanes(io(e)))?;
    }
    // A naq hub is dialed with the cluster, over OMQ.
    let go = (0..shared.opts().remotes.len())
        .filter(|&i| !crate::leaf::is_naq(&shared.opts().remotes[i]));
    for index in go {
        let lane = &lanes[index % lanes.len()];
        let (s, at) = (shared.clone(), lane.index());
        lane.spawn(move || crate::leaf::run(s, at, index))
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
        crate::lame::Door::open(shared),
    );
    first
        .spawn(move || accept(c, lanes, s, Door::Client, open))
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

/// The lanes to run for `wanted`: 0 is one per core the process may run on.
fn lanes(wanted: usize) -> usize {
    if wanted > 0 {
        return wanted;
    }
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

/// Where a server's listeners are bound.
struct Addrs {
    client: SocketAddr,
    monitor: Option<SocketAddr>,
    ws: Option<SocketAddr>,
}

/// The listeners of `opts`: for clients, monitoring and WebSocket.
fn bind_all(ctx: &Context, opts: &Options) -> Result<(Ports, Addrs), Error> {
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
enum Door {
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
    door: Door,
    open: crate::lame::Door,
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
    door: Door,
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
            Door::Client => lane.spawn(move || conn::run(s, index, stream)),
            Door::Websocket => lane.spawn(move || crate::ws::run(s, index, stream)),
        };
    }
}

/// The hash of server name `name`: eight letters or digits from its
/// SHA-256, as `nats-server` makes it.
pub(crate) fn node(name: &str) -> [u8; 8] {
    use sha2::Digest;
    let sum = sha2::Sha256::digest(name.as_bytes());
    let mut h = [0; 8];
    for (b, s) in h.iter_mut().zip(sum) {
        *b = crate::imports::service::base62(u64::from(s));
    }
    h
}

/// A response map with a fresh reply prefix, for a new account.
pub(crate) fn responses() -> crate::imports::service::Responses {
    crate::imports::service::Responses::new(random())
}

/// Numbers below what they are asked for, made from fresh random state.
pub(crate) fn random() -> impl FnMut(u64) -> u64 {
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

/// The keys a server makes at each start, as `nats-server` does.
pub(crate) struct Keys {
    /// Its NKey: it signs auth callout requests.
    pub(crate) server: nkeys::KeyPair,
    /// Its curve key, for sealed auth callouts.
    pub(crate) xkey: nkeys::XKey,
}

impl Keys {
    fn new() -> Keys {
        Keys {
            server: nkeys::KeyPair::new_server(),
            xkey: nkeys::XKey::new(),
        }
    }
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("server", &self.server.public_key())
            .field("xkey", &self.xkey.public_key())
            .finish()
    }
}
