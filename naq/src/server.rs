//! Starting and stopping a server: lanes, the listener, accepting clients.

mod listen;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};

use zzq_tokio::{Config, Context};

use crate::auth::{self, Auth, Logins};
use crate::error::io;
use crate::swap::Swap;
use crate::tls::Acceptor;
use crate::{Error, Options, lane, stats};

/// The `nats-server` version naq answers as, to clients, tools, hubs and
/// auth callouts: the one it matches, on which they gate features. naq's
/// own version is in its banner and `--version`.
pub(crate) const NATS_VERSION: &str = "2.15.2";

/// Tells servers in one process apart, for the lanes' state.
static NEXT_SERVER: AtomicU64 = AtomicU64::new(1);

/// What every lane of a server shares. Read only.
#[derive(Debug)]
pub(crate) struct Shared {
    /// What tells it apart.
    pub(crate) ident: Ident,
    /// What a reload swaps.
    pub(crate) live: Live,
    /// What it counts.
    pub(crate) tally: Tally,
    /// The most bytes a client may have waiting ([`Options::max_pending`]),
    /// which no reload changes.
    pub(crate) max_pending: usize,
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
    /// What monitoring keeps.
    pub(crate) monitor: crate::monitor::State,
    /// The WebSocket port, if there is one.
    pub(crate) ws: Option<crate::ws::Door>,
    /// Where the clients of the other servers of the cluster connect, as
    /// they told it.
    pub(crate) connect_urls: std::sync::Mutex<Vec<String>>,
    /// What its reloads keep.
    pub(crate) reload: crate::reload::State,
    /// The interest made and taken across the mesh, for batches to follow.
    pub(crate) marks: Arc<crate::mesh::Marks>,
}

/// What tells a server apart, set as it starts.
#[derive(Debug)]
pub(crate) struct Ident {
    /// Tells servers in one process apart.
    pub(crate) id: u64,
    /// Where clients connect, as bound.
    pub(crate) addr: SocketAddr,
    /// The server ID in `INFO`: the public key of `keys.server`.
    pub(crate) server_id: String,
    pub(crate) keys: Keys,
    /// When the server started.
    pub(crate) started: std::time::SystemTime,
}

/// What a reload swaps while the server runs.
#[derive(Debug)]
pub(crate) struct Live {
    /// The options as last loaded: those it started with, then those of
    /// each reload.
    options: Swap<Arc<Options>>,
    /// What clients must authenticate with, if anything.
    logins: Swap<Arc<Logins>>,
    /// TLS for clients, if they must use it.
    pub(crate) tls: crate::tls::Current,
    /// The remotes to `nats-server` hubs it dials.
    pub(crate) hubs: crate::leaf::HubRemotes,
}

/// What a server counts.
#[derive(Debug)]
pub(crate) struct Tally {
    /// Message counts of the clients of each lane.
    pub(crate) counts: Box<[stats::Shared]>,
    /// Message counts of the links and routes of each lane.
    pub(crate) peer_counts: Box<[stats::Shared]>,
    /// Slow consumers and stale clients so far.
    pub(crate) events: stats::Events,
    /// Clients that went away.
    pub(crate) gone: AtomicU64,
    next_client: AtomicU64,
}

impl Tally {
    fn new(lanes: usize) -> Tally {
        let counts = || (0..lanes).map(|_| stats::Shared::default()).collect();
        Tally {
            counts: counts(),
            peer_counts: counts(),
            events: stats::Events::default(),
            gone: AtomicU64::new(0),
            next_client: AtomicU64::new(1),
        }
    }
}

impl Shared {
    /// The options as last loaded.
    pub(crate) fn opts(&self) -> Arc<Options> {
        self.live.options.get()
    }

    /// Takes `opts` as the options from now on.
    pub(crate) fn set_opts(&self, opts: Options) {
        self.live.options.set(Arc::new(opts));
    }

    /// What clients authenticate with, if anything.
    pub(crate) fn logins(&self) -> Arc<Logins> {
        self.live.logins.get()
    }

    /// Takes the logins `opts` ask for, of users in `accounts`, the
    /// server's by id, from now on.
    pub(crate) fn relogin(&self, opts: &Options, accounts: &[String]) {
        let logins = Logins::new(opts, accounts, self.trust.as_ref());
        self.live.logins.set(Arc::new(logins));
    }

    /// The operator mode users log in under, if any.
    pub(crate) fn trust(&self) -> Option<&crate::jwt::trust::Trust> {
        self.trust.as_deref()
    }

    /// Its name with options `o`, as `nats-server` names itself: its ID
    /// when it has no name.
    pub(crate) fn name<'a>(&'a self, o: &'a Options) -> &'a str {
        if o.server_name.is_empty() {
            &self.ident.server_id
        } else {
            &o.server_name
        }
    }

    /// A new client ID, unique in this server. IDs start at 1.
    pub(crate) fn next_client(&self) -> u64 {
        // Relaxed: IDs only need to be distinct.
        self.tally.next_client.fetch_add(1, Ordering::Relaxed)
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
            client: self.ident.addr,
            monitor: self.monitor.addr(),
            websocket: self.ws.as_ref().map(|w| w.addr),
            leafnodes: mesh.leafnodes,
            cluster: mesh.cluster,
        }
    }

    /// Notes that a client went away.
    pub(crate) fn client_gone(&self) {
        // Relaxed: a counter, read now and then.
        self.tally.gone.fetch_add(1, Ordering::Relaxed);
    }

    /// Clients accepted so far.
    pub(crate) fn total_clients(&self) -> u64 {
        // Relaxed: a count read now and then.
        self.tally.next_client.load(Ordering::Relaxed) - 1
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
        let tls = setup.tls;
        let log = crate::log::Log::new(&opts.log).map_err(Error::Log)?;
        let accounts = auth::accounts(opts);
        let system = auth::system(opts, &accounts);
        let logins = Logins::new(opts, &accounts, None);
        let ctx = context(opts)?;
        let (ports, at) = listen::bind_all(&ctx, opts)?;
        let (txs, rxs): (Vec<_>, Vec<_>) = (0..ctx.lanes()).map(|_| lane::mailboxes()).unzip();
        let keys = Keys::new();
        let started = std::time::SystemTime::now();
        let node = node(&opts.server_name);
        let shared = Arc::new(Shared {
            callouts: crate::callout::Callouts::new(opts, &accounts, logins.auth.as_ref(), node),
            ident: Ident {
                id: NEXT_SERVER.fetch_add(1, Ordering::Relaxed),
                addr: at.client,
                server_id: keys.server.public_key(),
                keys,
                started,
            },
            tally: Tally::new(ctx.lanes()),
            max_pending: opts.max_pending,
            lanes: txs.into_boxed_slice(),
            accounts: Arc::new(new_accounts(
                &accounts,
                setup.imports,
                setup.resolver.is_some(),
                opts,
            )),
            resolver: setup.resolver,
            trust: logins.auth.as_ref().and_then(Auth::trust).cloned(),
            log,
            stopping: std::sync::atomic::AtomicBool::new(false),
            lame: crate::lame::Lame::default(),
            monitor: crate::monitor::State::new(opts, started, at.monitor),
            ws: door(opts, at.ws, tls.ws),
            live: Live {
                options: Swap::new(Arc::new(opts.clone())),
                logins: Swap::new(Arc::new(logins)),
                tls: Swap::new(tls.clients.map(Arc::new)),
                hubs: crate::leaf::HubRemotes::new(tls.hubs, ctx.lanes()),
            },
            system,
            sys: crate::sys::State::new(system.map(|_| node)),
            connect_urls: std::sync::Mutex::default(),
            reload: crate::reload::State::default(),
            marks: Arc::default(),
        });
        let mesh = listen::run(&ctx, &shared, rxs, ports, tls.https)?;
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
        tls: Swap::new(tls.map(Arc::new)),
        addr: addr?,
    })
}

/// What the options set up, checked and their files read.
struct Setup {
    tls: Tls,
    /// The imports of each account, by id.
    imports: Box<[crate::imports::Imports]>,
    /// The directory resolver, if there is one.
    resolver: Option<crate::resolver::Dir>,
}

/// The TLS of options, their files read: a start and each reload read it
/// here, so that a reload misses no port.
pub(crate) struct Tls {
    /// Of the client port.
    pub(crate) clients: Option<Acceptor>,
    /// Of the WebSocket port.
    pub(crate) ws: Option<Acceptor>,
    /// Of the HTTPS monitoring port.
    pub(crate) https: Option<tokio_rustls::TlsAcceptor>,
    /// The remotes to `nats-server` hubs, with their TLS.
    pub(crate) hubs: Vec<(crate::Remote, crate::leaf::Connector)>,
}

impl Tls {
    /// The TLS of `o`.
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] for a file that cannot be read.
    pub(crate) fn read(o: &Options) -> Result<Tls, Error> {
        let ws = o.websocket.as_ref().and_then(|w| w.tls.as_ref());
        Ok(Tls {
            clients: o.tls.as_ref().map(Acceptor::new).transpose()?,
            ws: ws.map(Acceptor::new).transpose()?,
            https: crate::monitor::acceptor(o)?,
            hubs: crate::leaf::to_hubs(o)?,
        })
    }
}

/// Checks `opts` and reads the files they name.
fn check(opts: &Options) -> Result<Setup, Error> {
    let imports = linked(opts)?;
    Ok(Setup {
        tls: Tls::read(opts)?,
        imports,
        resolver: crate::resolver::Dir::open(opts).map_err(Error::Options)?,
    })
}

/// Checks that `opts` do not contradict themselves.
///
/// # Errors
///
/// [`Error::Options`] or [`Error::Tls`], as [`Server::start`] gives them.
pub(crate) fn validate(opts: &Options) -> Result<(), Error> {
    linked(opts).map(drop)
}

/// The imports of each account of `opts`, by id, once `opts` are checked
/// not to contradict themselves.
fn linked(opts: &Options) -> Result<Box<[crate::imports::Imports]>, Error> {
    auth::validate(opts).map_err(Error::Options)?;
    let imports = crate::imports::link(opts).map_err(Error::Options)?;
    crate::leaf::validate(opts).map_err(Error::Options)?;
    crate::mesh::validate(opts).map_err(Error::Options)?;
    crate::lame::validate(opts).map_err(Error::Options)?;
    crate::monitor::validate(opts)?;
    if let Some(w) = &opts.websocket {
        crate::ws::validate(w).map_err(Error::Options)?;
    }
    Ok(imports)
}

/// The lanes to run for `wanted`: 0 is one per core the process may run on.
fn lanes(wanted: usize) -> usize {
    if wanted > 0 {
        return wanted;
    }
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
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

/// Puts `all` in an order picked at random by `below`.
pub(crate) fn shuffle<T>(all: &mut [T], mut below: impl FnMut(u64) -> u64) {
    for i in (1..all.len()).rev() {
        // Below `i + 1`: it fits.
        let j = below(i as u64 + 1) as usize;
        all.swap(i, j);
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
