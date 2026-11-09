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
    let old = shared.opts();
    let changes = diff::changes(&old, &new, shared.addr.port()).map_err(Error::Reload)?;
    // A free port picked at the start stays the one asked for.
    if new.port == 0 || new.port == shared.addr.port() {
        new.port = old.port;
    }
    shared.set_opts(new);
    let new = shared.opts();
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

/// Applies change `c` to `new`, and logs it as `nats-server`
/// does; what has to follow goes to `after`.
fn apply(shared: &Shared, new: &Options, c: &Change, after: &mut After) {
    let log = &shared.log;
    let info = |args: std::fmt::Arguments<'_>| log.info(args);
    match c {
        Change::Trace(on) => info(format_args!("Reloaded: trace = {on}")),
        Change::Debug(on) => info(format_args!("Reloaded: debug = {on}")),
        Change::TraceHeaders(on) => info(format_args!("Reloaded: trace_headers = {on}")),
        Change::Logtime(on) => info(format_args!("Reloaded: logtime = {on}")),
        Change::NkeyUsers => info(format_args!("Reloaded: authorization nkey users")),
        Change::Users => info(format_args!("Reloaded: authorization users")),
        Change::Accounts => info(format_args!("Reloaded: accounts")),
        Change::Username => info(format_args!("Reloaded: authorization username")),
        Change::Password => info(format_args!("Reloaded: authorization password")),
        Change::Token => info(format_args!("Reloaded: authorization token")),
        Change::AuthTimeout(d) => {
            let d = diff::seconds(*d);
            info(format_args!("Reloaded: authorization timeout = {d}"));
        }
        Change::LogFile(path) => info(format_args!("Reloaded: log_file = {path}")),
        Change::Syslog(on) => info(format_args!("Reloaded: syslog = {on}")),
        Change::RemoteSyslog(url) => info(format_args!("Reloaded: remote_syslog = {url}")),
        Change::MaxTracedMsgLen(n) => info(format_args!("Reloaded: max_traced_msg_len = {n}")),
        Change::PingInterval(d) => {
            let d = crate::log::go_duration(*d);
            info(format_args!("Reloaded: ping_interval = {d}"));
        }
        Change::PingMax(n) => info(format_args!("Reloaded: ping_max = {n}")),
        Change::MaxControlLine(n) => info(format_args!("Reloaded: max_control_line = {n}")),
        Change::MaxPayload(n) => info(format_args!("Reloaded: max_payload = {n}")),
        Change::WriteDeadline(d) => {
            let d = crate::log::go_duration(*d);
            info(format_args!("Reloaded: write_deadline = {d}"));
        }
        Change::PidFile(path) => pid_file(shared, path.as_deref()),
        Change::PortsFileDir(dir) => ports_file(shared, new, dir.as_deref()),
        Change::Tags => info(format_args!("Reloaded: tags")),
        Change::Metadata => info(format_args!("Reloaded: metadata")),
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
