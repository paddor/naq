//! What changed between the options a server runs with and those it is to
//! reload, in the order of `nats-server`'s options, named as Go names
//! them: the changes to apply, or the first the server cannot take.

use std::path::PathBuf;
use std::time::Duration;

use crate::log::go_duration;
use crate::{LogTo, Login, Options, Trace};

/// A change a reload applies, in the order `nats-server` applies them.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Change {
    Trace(bool),
    Debug(bool),
    TraceHeaders(bool),
    Logtime(bool),
    NkeyUsers,
    /// Always, as `nats-server` takes users and accounts as changed.
    Users,
    /// Always, as for [`Change::Users`].
    Accounts,
    Username,
    Password,
    Token,
    PingInterval(Duration),
    PingMax(u32),
    AuthTimeout(Duration),
    MaxControlLine(usize),
    MaxPayload(usize),
    PidFile(Option<PathBuf>),
    PortsFileDir(Option<PathBuf>),
    LogFile(String),
    Syslog(bool),
    RemoteSyslog(String),
    WriteDeadline(Duration),
    MaxTracedMsgLen(usize),
    TlsTimeout(Duration),
    /// TLS now, if `true`.
    Tls(bool),
    HandshakeFirst(bool),
    Fallback(Duration),
    Tags,
    Metadata,
}

/// A value as Go's `%v` writes it.
trait Go {
    fn go(&self) -> String;
}

impl Go for String {
    fn go(&self) -> String {
        self.clone()
    }
}

impl Go for bool {
    fn go(&self) -> String {
        self.to_string()
    }
}

impl Go for u64 {
    fn go(&self) -> String {
        self.to_string()
    }
}

impl Go for usize {
    fn go(&self) -> String {
        self.to_string()
    }
}

impl Go for Duration {
    fn go(&self) -> String {
        go_duration(*self)
    }
}

impl Go for Option<String> {
    fn go(&self) -> String {
        self.clone().unwrap_or_default()
    }
}

impl Go for Vec<String> {
    fn go(&self) -> String {
        format!("[{}]", self.join(" "))
    }
}

/// Go's refusal of a change to field `name` from `old` to `new`.
pub(super) fn refusal(name: &str, old: &str, new: &str) -> String {
    format!("config reload not supported for {name}: old={old}, new={new}")
}

/// Refuses a change of field `name`, if there is one.
fn fixed<T: PartialEq + Go>(name: &str, old: &T, new: &T) -> Result<(), String> {
    if old == new {
        return Ok(());
    }
    Err(refusal(name, &old.go(), &new.go()))
}

/// What the server has now, that its options do not tell.
#[derive(Debug, Clone, Copy)]
pub(super) struct At {
    /// Where its client port is bound.
    pub(super) port: u16,
    /// The TLS of the new options serves other certificates, or verifies
    /// clients otherwise, or there is TLS now and was none, or the other
    /// way.
    pub(super) tls: bool,
}

/// The changes from `old` to `new`, for a server at `at`: in the order of `nats-server`'s options, or the first
/// change the server cannot take, in Go's words.
pub(super) fn changes(old: &Options, new: &Options, at: At) -> Result<Vec<Change>, String> {
    let mut d = Diff {
        old,
        new,
        tls: at.tls,
        out: Vec::new(),
    };
    d.head(at.port)?;
    d.logging();
    d.auth()?;
    d.limits()?;
    d.mesh()?;
    d.files()?;
    d.tail()?;
    Ok(d.out)
}

/// The changes found so far between two sets of options.
struct Diff<'a> {
    old: &'a Options,
    new: &'a Options,
    /// See [`At::tls`].
    tls: bool,
    out: Vec<Change>,
}

impl Diff<'_> {
    /// Adds `change` if `changed`.
    fn push(&mut self, changed: bool, change: Change) {
        if changed {
            self.out.push(change);
        }
    }

    /// Who the server is and where it listens, which stay: a free port
    /// picked at the start, `port`, too.
    fn head(&self, port: u16) -> Result<(), String> {
        let (o, n) = (self.old, self.new);
        fixed("ServerName", &o.server_name, &n.server_name)?;
        fixed("Host", &o.host, &n.host)?;
        if n.port != 0 && n.port != port {
            return Err(refusal("Port", &port.to_string(), &n.port.to_string()));
        }
        fixed("Lanes", &o.lanes, &n.lanes)
    }

    /// The levels and format of the log.
    fn logging(&mut self) {
        let (o, n) = (&self.old.log, &self.new.log);
        let traces = |l: &crate::Logging| l.trace != Trace::Off;
        let headers = |l: &crate::Logging| l.trace == Trace::Headers;
        self.push(traces(o) != traces(n), Change::Trace(traces(n)));
        self.push(o.debug != n.debug, Change::Debug(n.debug));
        self.push(headers(o) != headers(n), Change::TraceHeaders(headers(n)));
        self.push(o.time != n.time, Change::Logtime(n.time));
    }

    /// Who may log in. Users and accounts change always, as
    /// `nats-server` takes them.
    fn auth(&mut self) -> Result<(), String> {
        let (o, n) = (self.old, self.new);
        let nkeys = |x: &'_ Options| {
            let of = |u: &&crate::User| matches!(u.login, Login::Nkey(_));
            x.users.iter().filter(of).cloned().collect::<Vec<_>>()
        };
        self.push(nkeys(o) != nkeys(n), Change::NkeyUsers);
        self.out.extend([Change::Users, Change::Accounts]);
        accounts(o, n)?;
        no_auth_user(o, n)?;
        let sys = |x: &Options| x.system_account.clone().unwrap_or_else(|| "$SYS".into());
        fixed("SystemAccount", &sys(o), &sys(n))?;
        fixed(
            "NoSystemAccount",
            &o.no_system_account,
            &n.no_system_account,
        )?;
        let user = |x: &Options| x.user.as_ref().map(|u| u.0.clone());
        let pass = |x: &Options| x.user.as_ref().map(|u| u.1.clone());
        self.push(user(o) != user(n), Change::Username);
        self.push(pass(o) != pass(n), Change::Password);
        self.push(o.token != n.token, Change::Token);
        if o.auth_callout != n.auth_callout {
            return Err(refusal("AuthCallout", "{...}", "{...}"));
        }
        Ok(())
    }

    /// Pings, monitoring and the limits of clients.
    fn limits(&mut self) -> Result<(), String> {
        let (o, n) = (self.old, self.new);
        let ping = o.ping_interval != n.ping_interval;
        self.push(ping, Change::PingInterval(n.ping_interval));
        let pings = o.max_pings_out != n.max_pings_out;
        self.push(pings, Change::PingMax(n.max_pings_out));
        fixed("HTTPHost", &o.http_host, &n.http_host)?;
        fixed("HTTPPort", &http_port(o.http_port), &http_port(n.http_port))?;
        fixed("HTTPBasePath", &o.http_base_path, &n.http_base_path)?;
        let https = (http_port(o.https_port), http_port(n.https_port));
        fixed("HTTPSPort", &https.0, &https.1)?;
        let auth = o.auth_timeout != n.auth_timeout;
        self.push(auth, Change::AuthTimeout(n.auth_timeout));
        let line = o.max_control_line != n.max_control_line;
        self.push(line, Change::MaxControlLine(n.max_control_line));
        let payload = o.max_payload != n.max_payload;
        self.push(payload, Change::MaxPayload(n.max_payload));
        fixed("MaxPending", &o.max_pending, &n.max_pending)
    }

    /// The cluster and leaf nodes: no change yet.
    fn mesh(&self) -> Result<(), String> {
        let (o, n) = (self.old, self.new);
        if o.cluster != n.cluster {
            return Err(refusal("Cluster", "{...}", "{...}"));
        }
        let leafs = o.leafnodes == n.leafnodes
            && o.remotes == n.remotes
            && o.leaf_reconnect == n.leaf_reconnect;
        if !leafs {
            return Err(refusal("LeafNode", "{...}", "{...}"));
        }
        // Its TLS may change, not come or go.
        let bare = |x: &Options| {
            let w = x.websocket.as_ref()?;
            Some((
                w.tls.is_some(),
                crate::Websocket {
                    tls: None,
                    ..w.clone()
                },
            ))
        };
        if bare(o) != bare(n) {
            return Err(refusal("Websocket", "{...}", "{...}"));
        }
        Ok(())
    }

    /// The pid and ports files, where the log goes, as Go's `LogFile`,
    /// `Syslog` and `RemoteSyslog`, how its files rotate, and TLS.
    fn files(&mut self) -> Result<(), String> {
        let (o, n) = (self.old, self.new);
        self.push(
            o.pid_file != n.pid_file,
            Change::PidFile(n.pid_file.clone()),
        );
        let ports = o.ports_file_dir != n.ports_file_dir;
        self.push(ports, Change::PortsFileDir(n.ports_file_dir.clone()));
        let file = |o: &Options| match &o.log.to {
            Some(LogTo::File(p)) => p.display().to_string(),
            _ => String::new(),
        };
        let syslog = |o: &Options| matches!(o.log.to, Some(LogTo::Syslog));
        let remote = |o: &Options| match &o.log.to {
            Some(LogTo::RemoteSyslog(u)) => u.clone(),
            _ => String::new(),
        };
        self.push(file(o) != file(n), Change::LogFile(file(n)));
        fixed("LogSizeLimit", &o.log.size_limit, &n.log.size_limit)?;
        fixed("LogMaxFiles", &o.log.max_files, &n.log.max_files)?;
        self.push(syslog(o) != syslog(n), Change::Syslog(syslog(n)));
        self.push(remote(o) != remote(n), Change::RemoteSyslog(remote(n)));
        self.tls_of_clients()
    }

    /// The TLS of clients, as Go's `TLSTimeout`, `TLSMap`, `TLSConfig` and
    /// `TLSHandshakeFirst`, with its fallback. Without TLS, the timeout is
    /// Go's default.
    fn tls_of_clients(&mut self) -> Result<(), String> {
        let (o, n) = (self.old, self.new);
        let timeout = |x: &Options| x.tls.as_ref().map_or(Duration::from_secs(2), |t| t.timeout);
        self.push(timeout(o) != timeout(n), Change::TlsTimeout(timeout(n)));
        let map = |x: &Options| x.tls.as_ref().is_some_and(|t| t.map);
        fixed("TLSMap", &map(o), &map(n))?;
        self.push(self.tls, Change::Tls(n.tls.is_some()));
        let first = |x: &Options| x.tls.as_ref().is_some_and(|t| t.handshake_first);
        self.push(first(o) != first(n), Change::HandshakeFirst(first(n)));
        let fallback = |x: &Options| x.tls.as_ref().and_then(|t| t.fallback).unwrap_or_default();
        self.push(fallback(o) != fallback(n), Change::Fallback(fallback(n)));
        Ok(())
    }

    /// The rest, from `write_deadline` on.
    fn tail(&mut self) -> Result<(), String> {
        let (o, n) = (self.old, self.new);
        let deadline = o.write_deadline != n.write_deadline;
        self.push(deadline, Change::WriteDeadline(n.write_deadline));
        fixed(
            "MaxClosedClients",
            &o.max_closed_clients,
            &n.max_closed_clients,
        )?;
        let (od, nd) = (&o.lame_duck_duration, &n.lame_duck_duration);
        fixed("LameDuckDuration", od, nd)?;
        let (og, ng) = (&o.lame_duck_grace_period, &n.lame_duck_grace_period);
        fixed("LameDuckGracePeriod", og, ng)?;
        let traced = o.log.max_traced != n.log.max_traced;
        self.push(traced, Change::MaxTracedMsgLen(n.log.max_traced));
        fixed("TrustedKeys", &o.trusted_keys, &n.trusted_keys)?;
        fixed("TrustedOperators", &o.operators, &n.operators)?;
        if o.resolver.is_some() != n.resolver.is_some() {
            return Err(
                "config reload does not support moving to or from an account resolver".into(),
            );
        }
        if o.resolver != n.resolver || o.resolver_preload != n.resolver_preload {
            return Err(refusal("AccountResolver", "{...}", "{...}"));
        }
        self.push(o.server_tags != n.server_tags, Change::Tags);
        self.push(o.server_metadata != n.server_metadata, Change::Metadata);
        Ok(())
    }
}

/// Refuses changes of the exports and imports of an account both `old`
/// and `new` have: naq links them once.
fn accounts(old: &Options, new: &Options) -> Result<(), String> {
    for a in &new.accounts {
        let before = old.accounts.iter().find(|b| b.name == a.name);
        if before.is_some_and(|b| b.exports != a.exports || b.imports != a.imports) {
            return Err(format!(
                "config reload not supported for Accounts: the exports and imports of {:?}",
                a.name
            ));
        }
    }
    Ok(())
}

/// Refuses a change of the `no_auth_user`, as `nats-server` does, but its
/// removal with the user of its name.
fn no_auth_user(old: &Options, new: &Options) -> Result<(), String> {
    let (o, n) = (&old.no_auth_user, &new.no_auth_user);
    let kept = |name: &str| {
        new.users
            .iter()
            .any(|u| matches!(&u.login, Login::Password { user, .. } if user == name))
    };
    match (o, n) {
        _ if o == n => Ok(()),
        (Some(name), None) if !kept(name) => Ok(()),
        _ => Err(refusal("NoAuthUser", &o.go(), &n.go())),
    }
}

/// A monitoring port as Go's options hold it: 0 for none, -1 for any.
fn http_port(p: Option<u16>) -> String {
    match p {
        None => "0".into(),
        Some(0) => "-1".into(),
        Some(p) => p.to_string(),
    }
}

/// `d` in seconds, as Go's options hold some durations.
pub(super) fn seconds(d: Duration) -> String {
    d.as_secs_f64().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server bound at `port`, its TLS as it was.
    const fn at(port: u16) -> At {
        At { port, tls: false }
    }

    fn opts() -> Options {
        Options {
            port: 4222,
            ..Options::default()
        }
    }

    #[test]
    fn changes_come_in_the_order_of_go_options() {
        let old = opts();
        let mut new = opts();
        new.server_tags = vec!["a".into()];
        new.max_payload = 512;
        new.log.debug = true;
        new.ping_interval = Duration::from_secs(5);
        new.log.trace = Trace::Headers;
        assert_eq!(
            changes(&old, &new, at(4222)),
            Ok(vec![
                Change::Trace(true),
                Change::Debug(true),
                Change::TraceHeaders(true),
                Change::Users,
                Change::Accounts,
                Change::PingInterval(Duration::from_secs(5)),
                Change::MaxPayload(512),
                Change::Tags,
            ])
        );
    }

    #[test]
    fn the_first_change_the_server_cannot_take_refuses_all_in_go_words() {
        let old = opts();
        let mut new = opts();
        new.max_payload = 512;
        new.port = 4223;
        new.server_name = "zed".into();
        assert_eq!(
            changes(&old, &new, at(4222)),
            Err("config reload not supported for ServerName: old=naq, new=zed".into())
        );
        new.server_name = "naq".into();
        assert_eq!(
            changes(&old, &new, at(4222)),
            Err("config reload not supported for Port: old=4222, new=4223".into())
        );
        let mut new = opts();
        new.lame_duck_duration = Duration::from_secs(60);
        assert_eq!(
            changes(&old, &new, at(4222)),
            Err("config reload not supported for LameDuckDuration: old=2m0s, new=1m0s".into())
        );
        let mut new = opts();
        new.log.size_limit = 1000;
        assert_eq!(
            changes(&old, &new, at(4222)),
            Err("config reload not supported for LogSizeLimit: old=0, new=1000".into())
        );
        let mut new = opts();
        new.http_port = Some(0);
        assert_eq!(
            changes(&old, &new, at(4222)),
            Err("config reload not supported for HTTPPort: old=0, new=-1".into())
        );
    }

    #[test]
    fn a_free_port_stays_the_one_bound() {
        let mut old = opts();
        old.port = 0;
        let new = old.clone();
        let none = Ok(vec![Change::Users, Change::Accounts]);
        assert_eq!(changes(&old, &new, at(34567)), none);
        let mut new = old.clone();
        new.port = 34567;
        assert_eq!(changes(&old, &new, at(34567)), none);
    }

    #[test]
    fn the_log_sinks_are_go_s_three_fields() {
        let mut old = opts();
        old.log.to = Some(LogTo::Syslog);
        let mut new = opts();
        new.log.to = Some(LogTo::File("/x.log".into()));
        assert_eq!(
            changes(&old, &new, at(4222)),
            Ok(vec![
                Change::Users,
                Change::Accounts,
                Change::LogFile("/x.log".into()),
                Change::Syslog(false)
            ])
        );
    }

    #[test]
    fn a_resolver_cannot_come_or_go() {
        let old = opts();
        let mut new = opts();
        new.resolver = Some(crate::Resolver::Memory);
        assert_eq!(
            changes(&old, &new, at(4222)),
            Err("config reload does not support moving to or from an account resolver".into())
        );
    }
    /// The refusal of `change` to the options, in Go's words.
    fn refused(change: impl FnOnce(&mut Options)) -> String {
        let old = opts();
        let mut new = opts();
        change(&mut new);
        changes(&old, &new, at(4222)).unwrap_err()
    }

    #[test]
    fn values_print_as_go_prints_them() {
        assert_eq!(
            refused(|o| o.http_host = Some("h".into())),
            "config reload not supported for HTTPHost: old=, new=h"
        );
        assert_eq!(
            refused(|o| o.max_closed_clients = 5),
            "config reload not supported for MaxClosedClients: old=10000, new=5"
        );
        assert_eq!(
            refused(|o| o.log.max_files = 3),
            "config reload not supported for LogMaxFiles: old=0, new=3"
        );
        assert_eq!(
            refused(|o| o.no_system_account = true),
            "config reload not supported for NoSystemAccount: old=false, new=true"
        );
        assert_eq!(
            refused(|o| o.trusted_keys = vec!["A".into(), "B".into()]),
            "config reload not supported for TrustedKeys: old=[], new=[A B]"
        );
        assert_eq!(
            refused(|o| o.https_port = Some(8443)),
            "config reload not supported for HTTPSPort: old=0, new=8443"
        );
        assert_eq!(
            refused(|o| o.http_base_path = "/x".into()),
            "config reload not supported for HTTPBasePath: old=, new=/x"
        );
    }

    #[test]
    fn whole_blocks_refuse_without_their_values() {
        let whole = |name: &str| {
            format!("config reload not supported for {name}: old={{...}}, new={{...}}")
        };
        assert_eq!(
            refused(|o| o.websocket = Some(crate::Websocket::default())),
            whole("Websocket")
        );
        assert_eq!(
            refused(|o| {
                o.auth_callout = Some(crate::AuthCallout {
                    issuer: "A".into(),
                    account: None,
                    auth_users: Vec::new(),
                    xkey: None,
                    allowed_accounts: Vec::new(),
                });
            }),
            whole("AuthCallout")
        );
        let mut old = opts();
        old.resolver = Some(crate::Resolver::Memory);
        let mut new = old.clone();
        new.resolver_preload = vec![("A".into(), "jwt".into())];
        assert_eq!(changes(&old, &new, at(4222)), Err(whole("AccountResolver")));
    }

    #[test]
    fn a_remote_syslog_is_its_url() {
        let old = opts();
        let mut new = opts();
        new.log.to = Some(LogTo::RemoteSyslog("udp://h:514".into()));
        new.log.time = false;
        assert_eq!(
            changes(&old, &new, at(4222)),
            Ok(vec![
                Change::Logtime(false),
                Change::Users,
                Change::Accounts,
                Change::RemoteSyslog("udp://h:514".into()),
            ])
        );
    }
}
