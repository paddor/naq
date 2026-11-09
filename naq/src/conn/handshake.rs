//! `INFO` for a new client, and its `CONNECT` options.

use serde::{Deserialize, Serialize};

use crate::auth::Creds;
use crate::server::Shared;

/// A client's options. Before its `CONNECT` and for fields it leaves out,
/// they are the defaults of `nats-server`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the flags of CONNECT, as sent"
)]
pub(super) struct ClientOpts {
    /// `+OK` after every operation but `PING` and `PONG`.
    pub(super) verbose: bool,
    /// Publish subjects are checked.
    pub(super) pedantic: bool,
    /// Messages it publishes reach its own subscriptions.
    pub(super) echo: bool,
    /// Takes `HPUB` and `HMSG`.
    pub(super) headers: bool,
    /// Protocol version; 1 and up take `INFO` at any time.
    pub(super) protocol: i32,
    /// Wants status 503 for requests no one got.
    pub(super) no_responders: bool,
}

impl Default for ClientOpts {
    fn default() -> Self {
        ClientOpts {
            verbose: true,
            pedantic: true,
            echo: true,
            headers: false,
            protocol: 0,
            no_responders: false,
        }
    }
}

/// The `CONNECT` fields this server reads. Others are ignored.
#[derive(Debug, Deserialize)]
struct Connect {
    verbose: Option<bool>,
    pedantic: Option<bool>,
    echo: Option<bool>,
    headers: Option<bool>,
    protocol: Option<i32>,
    no_responders: Option<bool>,
    user: Option<String>,
    pass: Option<String>,
    auth_token: Option<String>,
    nkey: Option<String>,
    sig: Option<String>,
    jwt: Option<String>,
    name: Option<String>,
    lang: Option<String>,
    version: Option<String>,
}

/// A client's name, language and library version, as its `CONNECT` gave.
pub(super) type Names = (Option<String>, Option<String>, Option<String>);

impl ClientOpts {
    /// Applies the JSON of a `CONNECT`, and returns the credentials and
    /// names in it.
    pub(super) fn apply(&mut self, json: &[u8]) -> Result<(Creds, Names), serde_json::Error> {
        let c: Connect = serde_json::from_slice(json)?;
        let keep = |new: Option<bool>, old| new.unwrap_or(old);
        *self = ClientOpts {
            verbose: keep(c.verbose, self.verbose),
            pedantic: keep(c.pedantic, self.pedantic),
            echo: keep(c.echo, self.echo),
            headers: keep(c.headers, self.headers),
            protocol: c.protocol.unwrap_or(self.protocol),
            no_responders: keep(c.no_responders, self.no_responders),
        };
        let creds = Creds {
            user: c.user,
            pass: c.pass,
            token: c.auth_token,
            nkey: c.nkey,
            sig: c.sig,
            jwt: c.jwt,
        };
        Ok((creds, (c.name, c.lang, c.version)))
    }
}

/// An `INFO` to a client, its fields in the order of `nats-server`.
#[derive(Debug, Serialize)]
#[expect(clippy::struct_excessive_bools, reason = "the flags of INFO, as sent")]
struct Info<'a> {
    server_id: &'a str,
    server_name: &'a str,
    version: &'a str,
    proto: u8,
    go: &'a str,
    host: &'a str,
    port: u16,
    headers: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    auth_required: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    tls_required: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    tls_verify: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    tls_available: bool,
    max_payload: usize,
    client_id: u64,
    client_ip: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    /// With a cluster: this server's client URL, unless it is in lame duck
    /// mode, then the others'.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    connect_urls: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    ldm: bool,
    #[serde(rename = "connect_info", skip_serializing_if = "std::ops::Not::not")]
    bound: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_account: Option<&'a str>,
    /// The server's curve key, for sealed auth callouts.
    xkey: String,
}

/// The client an `INFO` is for.
pub(super) struct To<'a> {
    pub(super) id: u64,
    pub(super) ip: &'a str,
    /// For it to sign, if it may log in with an NKey.
    pub(super) nonce: Option<&'a str>,
    /// It came over WebSocket.
    pub(super) ws: bool,
    /// The largest message it may publish.
    pub(super) max_payload: usize,
}

/// Which `INFO` a client gets.
#[derive(Debug, Clone, Copy)]
pub(super) enum Kind<'a> {
    /// The first, before its `CONNECT`.
    First,
    /// The one that follows its first `PONG`: it names the account the
    /// client is bound to.
    Bound(&'a str),
    /// One at any time, as the cluster changed: it says the server is in
    /// lame duck mode if `ldm`.
    Async { ldm: bool },
}

/// Appends the `INFO` of `kind` for client `to`.
pub(super) fn info(shared: &Shared, to: &To<'_>, kind: Kind<'_>, out: &mut Vec<u8>) {
    // A WebSocket client sees its own port, and TLS as that port has it.
    let ws = shared.ws.as_ref().filter(|_| to.ws);
    let (host, port, tls) = match ws {
        Some(w) => (w.opts.host.as_str(), w.addr.port(), w.tls.is_some()),
        None => (
            shared.opts.host.as_str(),
            shared.addr.port(),
            shared.tls.is_some(),
        ),
    };
    let bound = match kind {
        Kind::Bound(account) => Some(account),
        Kind::First | Kind::Async { .. } => None,
    };
    let auth_required = match (kind, shared.auth_for(to.ws)) {
        // Before the CONNECT, a client need not authenticate if it may
        // connect as the no_auth_user; over WebSocket, `nats-server` asks
        // all the same.
        (Kind::First, Some(a)) => to.ws || !a.open(),
        (Kind::Bound(_), a) => a.is_some(),
        // As the server's own INFO has it: for clients not over WebSocket.
        (Kind::Async { .. }, _) => shared.auth.is_some(),
        (Kind::First, None) => false,
    };
    let info = Info {
        server_id: &shared.server_id,
        server_name: &shared.opts.server_name,
        version: env!("CARGO_PKG_VERSION"),
        proto: 1,
        go: "",
        host,
        port,
        headers: true,
        auth_required,
        tls_required: tls,
        tls_verify: shared.tls.as_ref().is_some_and(|t| t.verify),
        tls_available: tls && ws.is_some(),
        max_payload: to.max_payload,
        client_id: to.id,
        client_ip: to.ip,
        nonce: to.nonce,
        connect_urls: connect_urls(shared),
        ldm: matches!(kind, Kind::Async { ldm: true }),
        bound: bound.is_some(),
        remote_account: bound,
        xkey: shared.keys.xkey.public_key(),
    };
    // Cannot fail: no maps, no fallible serializers.
    let json = serde_json::to_vec(&info).unwrap_or_default();
    naq_proto::encode::info(out, &json);
}

/// The client URLs of the cluster, this server's first, unless it is in
/// lame duck mode, as `nats-server` lists them; none without a cluster.
fn connect_urls(shared: &Shared) -> Vec<String> {
    if shared.opts.cluster.is_none() {
        return Vec::new();
    }
    let mut all = Vec::new();
    if !crate::lame::on(shared) {
        all.push(shared.addr.to_string());
    }
    // A poisoned lock still holds the list.
    let others = shared
        .connect_urls
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    all.extend(others.iter().cloned());
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_overrides_only_the_fields_it_has() {
        let mut o = ClientOpts::default();
        o.apply(br#"{"verbose":false,"headers":true,"name":"x","lang":"rust"}"#)
            .unwrap();
        assert_eq!(
            o,
            ClientOpts {
                verbose: false,
                pedantic: true,
                echo: true,
                headers: true,
                protocol: 0,
                no_responders: false,
            }
        );
        o.apply(br#"{"echo":false}"#).unwrap();
        assert!(!o.echo && !o.verbose && o.headers);
        o.apply(br#"{"protocol":1}"#).unwrap();
        assert_eq!(o.protocol, 1);
        assert!(o.apply(b"{").is_err());
        assert!(o.apply(br#"{"echo":1}"#).is_err());
    }
}
