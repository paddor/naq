//! The pages with little to show in naq: the index, `/healthz`, and those
//! of what naq does not have, as `nats-server` shows them without it:
//! JetStream, gateways, Raft and Go's internal queues.

use std::fmt::Write as _;

use serde::Serialize;

use super::http::Response;
use super::query::{Query, Refused};
use super::varz::Empty;
use super::{now, pretty};
use crate::server::Shared;

/// The endpoints the index links to.
const LINKS: [&str; 11] = [
    "varz",
    "connz",
    "routez",
    "gatewayz",
    "leafz",
    "subsz",
    "accountz",
    "accstatz",
    "jsz",
    "healthz",
    "debug/vars",
];

/// The index: a link to each endpoint.
pub(super) fn index(shared: &Shared) -> Response {
    let base = shared.monitor.base.trim_end_matches('/');
    let mut page = format!(
        "<html lang=\"en\">\n<head><title>naq</title></head>\n<body>\n<h1>naq v{}</h1>\n",
        env!("CARGO_PKG_VERSION")
    );
    for l in LINKS {
        let _ = writeln!(page, "<a href=\"{base}/{l}\">{l}</a><br/>");
    }
    page.push_str("</body>\n</html>\n");
    Response::html(page)
}

/// `/gatewayz` without gateways, in Go order.
#[derive(Debug, Serialize)]
struct Gatewayz<'a> {
    server_id: &'a str,
    now: String,
    outbound_gateways: Empty,
    inbound_gateways: Empty,
}

/// `/gatewayz`, without gateways.
pub(super) fn gatewayz(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    q.subs()?;
    q.bool("accs")?;
    Ok(pretty(&Gatewayz {
        server_id: &shared.server_id,
        now: now(),
        outbound_gateways: Empty {},
        inbound_gateways: Empty {},
    }))
}

/// JetStream API calls: none.
#[derive(Debug, Default, Serialize)]
struct Api {
    level: u8,
    total: u8,
    errors: u8,
}

/// JetStream limits: none.
#[derive(Debug, Default, Serialize)]
struct Limits {
    max_memory: u8,
    max_storage: u8,
}

/// `/jsz` without JetStream, in Go order.
#[derive(Debug, Default, Serialize)]
struct Jsz {
    memory: u8,
    storage: u8,
    reserved_memory: u8,
    reserved_storage: u8,
    accounts: u8,
    ha_assets: u8,
    api: Api,
    server_id: String,
    now: String,
    disabled: bool,
    config: Limits,
    streams: u8,
    consumers: u8,
    messages: u8,
    bytes: u8,
    total: u8,
}

/// `/jsz`, without JetStream.
pub(super) fn jsz(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    for key in [
        "accounts",
        "streams",
        "consumers",
        "direct-consumers",
        "config",
    ] {
        q.bool(key)?;
    }
    q.int("offset")?;
    q.int("limit")?;
    let leader = q.bool("leader-only")?;
    q.bool("raft")?;
    q.bool("stream-leader-only")?;
    if leader {
        return Err("filtered response: not leader".into());
    }
    Ok(pretty(&Jsz {
        server_id: shared.server_id.clone(),
        now: now(),
        disabled: true,
        ..Jsz::default()
    }))
}

/// `/ipqueuesz`: Go's internal queues; naq has none of them.
pub(super) fn ipqueuesz(q: &Query) -> Result<Response, Refused> {
    q.bool("all")?;
    Ok(Response::json(200, b"{}".to_vec()))
}

/// `/debug/vars`, as Go's `expvar` writes it: the command line.
pub(super) fn expvar() -> Response {
    let args: Vec<String> = std::env::args().collect();
    let mut body = b"{\n\"cmdline\": ".to_vec();
    body.extend(super::json::compact(&args));
    body.extend_from_slice(b"\n}\n");
    let mut r = Response::json(200, body);
    r.headers = vec![("Content-Type", "application/json; charset=utf-8".into())];
    r
}

/// One failed check of `/healthz` with `details`.
#[derive(Debug, Serialize)]
struct Failed {
    #[serde(rename = "type")]
    kind: &'static str,
    error: String,
}

/// What `/healthz` says.
#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<Failed>,
}

/// `/healthz`: whether the server takes connections. Without JetStream,
/// that is all there is to check.
pub(super) fn healthz(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    let js_enabled = q.bool("js-enabled")?;
    if js_enabled {
        shared.log.warn(format_args!(
            "Healthcheck: js-enabled deprecated, use js-enabled-only instead"
        ));
    }
    for key in ["js-enabled-only", "js-server-only", "js-meta-only"] {
        q.bool(key)?;
    }
    let details = q.bool("details")?;
    let failed = if q.get("account").is_empty() && !q.get("stream").is_empty() {
        Some((
            400,
            "BAD_REQUEST",
            "\"account\" must not be empty when checking stream health",
        ))
    } else if q.get("stream").is_empty() && !q.get("consumer").is_empty() {
        Some((
            400,
            "BAD_REQUEST",
            "\"stream\" must not be empty when checking consumer health",
        ))
    } else if crate::stop::stopping(shared) {
        Some((
            500,
            "CONNECTION",
            "failed to be ready for connections after 1ms: server",
        ))
    } else {
        None
    };
    let Some((status, kind, why)) = failed else {
        return Ok(Response::json(200, br#"{"status":"ok"}"#.to_vec()));
    };
    let health = if details {
        shared
            .log
            .warn(format_args!("Healthcheck failed: 1 errors"));
        Health {
            status: "error",
            error: String::new(),
            errors: vec![Failed {
                kind,
                error: why.into(),
            }],
        }
    } else {
        shared
            .log
            .warn(format_args!("Healthcheck failed: {}", go_quote(why)));
        Health {
            status: "error",
            error: why.into(),
            errors: Vec::new(),
        }
    };
    Ok(Response::json(status, super::json::compact(&health)))
}

/// `s` as Go's `%q` writes text without control characters.
fn go_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
