//! What the server sends on `$SYS`: the block that names it, and the
//! envelope of its answers, as `nats-server` writes them.

use std::sync::atomic::Ordering;

use serde::Serialize;

use crate::monitor::json;

use crate::server::Shared;

/// The server sending a message, as `nats-server` names itself in them.
#[derive(Debug, Serialize)]
pub(crate) struct ServerInfo<'a> {
    name: &'a str,
    host: &'a str,
    id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    cluster: &'a str,
    ver: &'static str,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    tags: &'a [String],
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    metadata: &'a std::collections::BTreeMap<String, String>,
    jetstream: bool,
    flags: u8,
    seq: u64,
    time: String,
}

impl<'a> ServerInfo<'a> {
    /// `shared`'s server, sending a message now: the next in its count.
    pub(crate) fn of(shared: &'a Shared) -> ServerInfo<'a> {
        let o = &shared.opts;
        ServerInfo {
            name: name(shared),
            host: &o.host,
            id: &shared.server_id,
            cluster: o.cluster.as_ref().map_or("", |c| c.name.as_str()),
            ver: env!("CARGO_PKG_VERSION"),
            tags: &o.server_tags,
            metadata: &o.server_metadata,
            jetstream: false,
            flags: 0,
            // Relaxed: the numbers only need to grow.
            seq: shared.sys.seq.fetch_add(1, Ordering::Relaxed) + 1,
            time: crate::times::rfc3339_nano(std::time::SystemTime::now()),
        }
    }
}

/// The name of `shared`'s server, as `nats-server` names itself: its ID
/// when it has no name.
pub(crate) fn name(shared: &Shared) -> &str {
    let n = &shared.opts.server_name;
    if n.is_empty() { &shared.server_id } else { n }
}

/// An error of an answer, as Go's `ApiError`.
#[derive(Debug, Serialize)]
pub(crate) struct ApiError {
    code: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
}

impl ApiError {
    pub(crate) const fn new(code: u16, description: String) -> ApiError {
        ApiError { code, description }
    }
}

/// An answer of `shared`'s server, as Go writes its `ServerAPIResponse`:
/// the server, `data` if there is any, then `error` if there is one.
pub(crate) fn envelope(shared: &Shared, data: Option<&[u8]>, error: Option<&ApiError>) -> Vec<u8> {
    let mut b = b"{\"server\":".to_vec();
    b.extend(json::compact(&ServerInfo::of(shared)));
    if let Some(d) = data {
        b.extend_from_slice(b",\"data\":");
        b.extend_from_slice(d);
    }
    if let Some(e) = error {
        b.extend_from_slice(b",\"error\":");
        b.extend(json::compact(e));
    }
    b.push(b'}');
    b
}
