//! `INFO` for a new client, and its `CONNECT` options.

use serde::{Deserialize, Serialize};

use crate::server::Shared;

/// A client's options. Before its `CONNECT` and for fields it leaves out,
/// they are the defaults of `nats-server`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ClientOpts {
    /// `+OK` after every operation but `PING` and `PONG`.
    pub(super) verbose: bool,
    /// Messages it publishes reach its own subscriptions.
    pub(super) echo: bool,
    /// Takes `HPUB` and `HMSG`.
    pub(super) headers: bool,
}

impl Default for ClientOpts {
    fn default() -> Self {
        ClientOpts {
            verbose: true,
            echo: true,
            headers: false,
        }
    }
}

/// The `CONNECT` fields this server reads. Others are ignored.
#[derive(Debug, Deserialize)]
struct Connect {
    verbose: Option<bool>,
    echo: Option<bool>,
    headers: Option<bool>,
}

impl ClientOpts {
    /// Applies the JSON of a `CONNECT`.
    pub(super) fn apply(&mut self, json: &[u8]) -> Result<(), serde_json::Error> {
        let c: Connect = serde_json::from_slice(json)?;
        let keep = |new: Option<bool>, old| new.unwrap_or(old);
        *self = ClientOpts {
            verbose: keep(c.verbose, self.verbose),
            echo: keep(c.echo, self.echo),
            headers: keep(c.headers, self.headers),
        };
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct Info<'a> {
    server_id: &'a str,
    server_name: &'a str,
    version: &'a str,
    proto: u8,
    go: &'a str,
    host: &'a str,
    port: u16,
    headers: bool,
    max_payload: usize,
    client_id: u64,
}

/// Appends the `INFO` for client `id`.
pub(super) fn info(shared: &Shared, id: u64, out: &mut Vec<u8>) {
    let info = Info {
        server_id: &shared.server_id,
        server_name: &shared.opts.server_name,
        version: env!("CARGO_PKG_VERSION"),
        proto: 1,
        go: "",
        host: &shared.opts.host,
        port: shared.addr.port(),
        headers: true,
        max_payload: shared.opts.max_payload,
        client_id: id,
    };
    // Cannot fail: no maps, no fallible serializers.
    let json = serde_json::to_vec(&info).unwrap_or_default();
    naq_proto::encode::info(out, &json);
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
                echo: true,
                headers: true,
            }
        );
        o.apply(br#"{"echo":false}"#).unwrap();
        assert!(!o.echo && !o.verbose && o.headers);
        assert!(o.apply(b"{").is_err());
        assert!(o.apply(br#"{"echo":1}"#).is_err());
    }
}
