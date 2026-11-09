//! Reloading the configuration while the server runs, as `nats-server`
//! reloads it on `HUP`: the options are read again and checked whole. The
//! first change the server cannot take refuses them all; else they are
//! taken, and each change is applied and logged in the order of Go's
//! options.

mod diff;
mod users;

use std::sync::{Arc, Mutex, PoisonError};

use crate::server::Shared;
use crate::{Error, Options};

use diff::Change;

/// How a server reads its options again.
pub(crate) type Read = dyn Fn() -> Result<Options, Error> + Send + Sync;

/// What a server keeps for its reloads.
#[derive(Default)]
pub(crate) struct State {
    /// One reload at a time.
    one: Mutex<()>,
    /// How the options are read again; `None` reads the configuration
    /// file again.
    read: Mutex<Option<Arc<Read>>>,
    /// The ports file written, which a reload moves and the server
    /// removes as it stops.
    ports: Mutex<Option<std::path::PathBuf>>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State").finish_non_exhaustive()
    }
}

impl State {
    /// The ports file written, if any.
    pub(crate) fn ports(&self) -> std::sync::MutexGuard<'_, Option<std::path::PathBuf>> {
        self.ports.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reads the options again with `read` from now on.
    pub(crate) fn read_with(&self, read: Arc<Read>) {
        *self.read.lock().unwrap_or_else(PoisonError::into_inner) = Some(read);
    }
}

/// What follows the changes, once all are applied.
#[derive(Debug, Default)]
struct After {
    /// The log is set up anew.
    logging: bool,
    /// `STATSZ` goes out.
    statsz: bool,
}

/// Reads the options of `shared`'s server again and takes them, as
/// `nats-server` reloads: all of them, or none.
///
/// # Errors
///
/// They cannot be read, or hold a change the server cannot take.
pub(crate) fn reload(shared: &Shared) -> Result<(), Error> {
    let state = &shared.reload;
    let _one = state.one.lock().unwrap_or_else(PoisonError::into_inner);
    let read = state
        .read
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let new = match read {
        Some(read) => read()?,
        None => again(shared)?,
    };
    take(shared, new)
}

/// The options of the configuration file `shared`'s server read.
fn again(shared: &Shared) -> Result<Options, Error> {
    let Some(path) = shared.opts().config_file.clone() else {
        return Err(Error::Reload(
            "can only reload config when a file is provided using -c or --config".into(),
        ));
    };
    Options::from_file(path)
}

/// Takes `new` in place of the options of `shared`'s server, unless it
/// holds a change the server cannot take.
fn take(shared: &Shared, mut new: Options) -> Result<(), Error> {
    crate::server::validate(&new)?;
    let tls = Tls::read(&new)?;
    let old = shared.opts();
    let at = diff::At {
        port: shared.addr.port(),
        tls: tls.differs(shared),
    };
    let changes = diff::changes(&old, &new, at).map_err(Error::Reload)?;
    // A free port picked at the start stays the one asked for.
    if new.port == 0 || new.port == shared.addr.port() {
        new.port = old.port;
    }
    shared.set_opts(new);
    let new = shared.opts();
    tls.take(shared);
    let mut after = After::default();
    for c in &changes {
        apply(shared, &new, c, &mut after);
    }
    if after.logging
        && let Err(e) = shared.log.set(&new.log)
    {
        shared
            .log
            .error(format_args!("Failed to reload the log: {e}"));
    }
    // As `nats-server`: users and accounts always, and the clients
    // checked again, with the new limits, pings and traces.
    users::take(shared, &new);
    users::recheck(shared);
    if after.statsz {
        crate::sys::statsz(shared);
    }
    let digest = shared.monitor.reloaded(&new);
    shared
        .log
        .info(format_args!("Reloaded server configuration {digest}"));
    Ok(())
}

/// The TLS of options, read: of clients, of WebSocket clients, and of
/// monitoring over HTTPS.
struct Tls {
    clients: Option<crate::tls::Acceptor>,
    ws: Option<crate::tls::Acceptor>,
    /// Of the HTTPS monitoring port.
    https: Option<tokio_rustls::TlsAcceptor>,
}

impl Tls {
    /// The TLS of `o`, its files read.
    fn read(o: &Options) -> Result<Tls, Error> {
        let ws = o.websocket.as_ref().and_then(|w| w.tls.as_ref());
        Ok(Tls {
            clients: o.tls.as_ref().map(crate::tls::Acceptor::new).transpose()?,
            ws: ws.map(crate::tls::Acceptor::new).transpose()?,
            https: crate::monitor::acceptor(o)?,
        })
    }

    /// Whether the TLS of clients is not that `shared`'s server has.
    fn differs(&self, shared: &Shared) -> bool {
        match (shared.tls.get(), &self.clients) {
            (Some(now), Some(next)) => now.differs(next),
            (now, next) => now.is_some() != next.is_some(),
        }
    }

    /// Has the server take it for the clients that come from now on.
    fn take(self, shared: &Shared) {
        shared.tls.set(self.clients);
        shared.monitor.set_tls(self.https);
        if let Some(door) = &shared.ws {
            door.tls.set(self.ws);
        }
    }
}

/// Applies change `c` to `new`, and logs it as `nats-server` does; what
/// has to follow goes to `after`.
fn apply(shared: &Shared, new: &Options, c: &Change, after: &mut After) {
    match c {
        Change::PidFile(path) => pid_file(shared, path.as_deref()),
        Change::PortsFileDir(dir) => ports_file(shared, new, dir.as_deref()),
        c => shared.log.info(format_args!("Reloaded: {}", said(c))),
    }
    match c {
        Change::Trace(_)
        | Change::Debug(_)
        | Change::TraceHeaders(_)
        | Change::Logtime(_)
        | Change::LogFile(_)
        | Change::Syslog(_)
        | Change::RemoteSyslog(_)
        | Change::MaxTracedMsgLen(_) => after.logging = true,
        Change::Tags | Change::Metadata => after.statsz = true,
        _ => {}
    }
}

/// What `nats-server` logs of change `c`, after `Reloaded: `; the pid and
/// ports files log their own.
fn said(c: &Change) -> String {
    use crate::log::go_duration;
    match c {
        Change::Trace(on) => format!("trace = {on}"),
        Change::Debug(on) => format!("debug = {on}"),
        Change::TraceHeaders(on) => format!("trace_headers = {on}"),
        Change::Logtime(on) => format!("logtime = {on}"),
        Change::NkeyUsers => "authorization nkey users".into(),
        Change::Users => "authorization users".into(),
        Change::Accounts => "accounts".into(),
        Change::Username => "authorization username".into(),
        Change::Password => "authorization password".into(),
        Change::Token => "authorization token".into(),
        Change::AuthTimeout(d) => format!("authorization timeout = {}", diff::seconds(*d)),
        Change::LogFile(path) => format!("log_file = {path}"),
        Change::Syslog(on) => format!("syslog = {on}"),
        Change::RemoteSyslog(url) => format!("remote_syslog = {url}"),
        Change::MaxTracedMsgLen(n) => format!("max_traced_msg_len = {n}"),
        Change::PingInterval(d) => format!("ping_interval = {}", go_duration(*d)),
        Change::PingMax(n) => format!("ping_max = {n}"),
        Change::MaxControlLine(n) => format!("max_control_line = {n}"),
        Change::MaxPayload(n) => format!("max_payload = {n}"),
        Change::WriteDeadline(d) => format!("write_deadline = {}", go_duration(*d)),
        Change::TlsTimeout(d) => format!("tls timeout = {}", diff::seconds(*d)),
        Change::Tls(true) => "tls = enabled".into(),
        Change::Tls(false) => "tls = disabled".into(),
        Change::HandshakeFirst(on) => format!("Client TLS handshake first: {on}"),
        Change::Fallback(d) => format!(
            "Client TLS handshake first fallback delay: {}",
            go_duration(*d)
        ),
        Change::Tags => "tags".into(),
        Change::Metadata => "metadata".into(),
        Change::PidFile(_) | Change::PortsFileDir(_) => String::new(),
    }
}

/// Writes the process ID to `path`, if there is one, as `nats-server`
/// does on a reload: the file at the old path stays.
fn pid_file(shared: &Shared, path: Option<&std::path::Path>) {
    let Some(path) = path else {
        return;
    };
    if let Err(e) = crate::files::pid(path) {
        shared
            .log
            .error(format_args!("Failed to write pidfile: {e}"));
    }
    shared
        .log
        .info(format_args!("Reloaded: pid_file = {}", path.display()));
}

/// Moves the ports file to `dir`, as `new` asks.
fn ports_file(shared: &Shared, new: &Options, dir: Option<&std::path::Path>) {
    let log = &shared.log;
    let mut held = shared.reload.ports();
    if let Some(p) = held.take()
        && let Err(e) = std::fs::remove_file(&p)
    {
        log.error(format_args!(
            "Error cleaning up ports file {}: {e}",
            p.display()
        ));
    }
    if let Some(dir) = dir {
        let bound = shared.bound();
        match crate::files::ports(dir, new, &bound) {
            Ok(p) => *held = Some(p),
            Err(e) => log.error(format_args!(
                "Error writing ports file ({}): {e}",
                dir.display()
            )),
        }
    }
    drop(held);
    let dir = dir.map(|d| d.display().to_string()).unwrap_or_default();
    log.info(format_args!("Reloaded: ports_file_dir = {dir}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_state_shows_without_the_reader() {
        let s = State::default();
        s.read_with(Arc::new(|| Ok(Options::default())));
        assert_eq!(format!("{s:?}"), "State { .. }");
    }
}
