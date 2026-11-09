//! What a server logs as it starts, in the order of `nats-server`.

use std::net::SocketAddr;

use crate::server::Shared;
use crate::{Login, Options};

/// Where a started server listens.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bound {
    pub(crate) client: SocketAddr,
    pub(crate) monitor: Option<SocketAddr>,
    pub(crate) websocket: Option<SocketAddr>,
    pub(crate) leafnodes: Option<SocketAddr>,
    pub(crate) cluster: Option<SocketAddr>,
}

/// Logs the start of the server `shared`, bound at `at`.
pub(crate) fn log(shared: &Shared, at: &Bound) {
    let (log, o) = (&shared.log, &shared.opts());
    log.info(format_args!("Starting naq"));
    log.info(format_args!("  Version:  {}", env!("CARGO_PKG_VERSION")));
    if let Some(c) = &o.cluster {
        log.info(format_args!("  Cluster:  {}", c.name));
    }
    log.info(format_args!("  Name:     {}", o.server_name));
    log.info(format_args!("  ID:       {}", shared.server_id));
    if plain_passwords(o) {
        log.warn(format_args!(
            "Plaintext passwords detected, use nkeys or bcrypt"
        ));
    }
    if let Some(path) = &o.config_file {
        let digest = shared.monitor.loaded().digest;
        let digest = if digest.is_empty() {
            String::new()
        } else {
            format!(" ({digest})")
        };
        log.info(format_args!(
            "Using configuration file: {}{digest}",
            path.display()
        ));
    }
    let host = |h: Option<&str>, a: SocketAddr| join(h.unwrap_or(&o.host), a.port());
    if let Some(m) = at.monitor {
        let h = host(o.http_host.as_deref(), m);
        let scheme = if o.https_port.is_some() {
            "https"
        } else {
            "http"
        };
        log.info(format_args!("Starting {scheme} monitor on {h}"));
    }
    if let (Some(w), Some(ws)) = (at.websocket, &o.websocket) {
        let scheme = if ws.tls.is_some() { "wss" } else { "ws" };
        let h = host(Some(&ws.host), w);
        log.info(format_args!(
            "Listening for websocket clients on {scheme}://{h}"
        ));
    }
    if let (Some(l), Some(leaf)) = (at.leafnodes, &o.leafnodes) {
        let h = host(Some(&leaf.host), l);
        log.info(format_args!("Listening for leafnode connections on {h}"));
    }
    let h = host(None, at.client);
    log.info(format_args!("Listening for client connections on {h}"));
    log.info(format_args!("Server is ready"));
    if let (Some(r), Some(c)) = (at.cluster, &o.cluster) {
        log.info(format_args!("Cluster name is {}", c.name));
        let h = host(Some(&c.host), r);
        log.info(format_args!("Listening for route connections on {h}"));
    }
}

/// Whether a password in `o` is neither empty nor a bcrypt hash.
fn plain_passwords(o: &Options) -> bool {
    let plain = |p: &str| !p.is_empty() && !crate::auth::is_bcrypt(p);
    o.user.as_ref().is_some_and(|(_, p)| plain(p))
        || o.users.iter().any(|u| match &u.login {
            Login::Password { password, .. } => plain(password),
            _ => false,
        })
}

/// `host:port`, with an IPv6 host in brackets.
fn join(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_join_their_ports_with_v6_in_brackets() {
        assert_eq!(join("0.0.0.0", 4222), "0.0.0.0:4222");
        assert_eq!(join("::1", 4222), "[::1]:4222");
    }

    #[test]
    fn plain_passwords_are_those_neither_empty_nor_hashed() {
        let user = |password: &str| crate::User {
            login: Login::Password {
                user: "a".into(),
                password: password.into(),
            },
            account: None,
            permissions: None,
            connection_types: Vec::new(),
        };
        let mut o = Options::default();
        assert!(!plain_passwords(&o));
        o.users = vec![user("$2a$11$abc"), user("")];
        assert!(!plain_passwords(&o));
        o.users.push(user("secret"));
        assert!(plain_passwords(&o));
        let o = Options {
            user: Some(("u".into(), "p".into())),
            ..Options::default()
        };
        assert!(plain_passwords(&o));
    }
}
