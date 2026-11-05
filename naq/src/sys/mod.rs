//! The server's own services in the system account: requests on `$SYS`
//! subjects it answers, as `nats-server` answers them. So far, updates of
//! account JWTs.

mod claims;

use std::sync::atomic::{AtomicU64, Ordering};

use naq_proto::client::Pub;
use serde_json::{Value, json};

use crate::imports::service::Tap;
use crate::lane::{Lane, Outs};
use crate::server::Shared;

/// A request the server answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Service {
    /// An account JWT to take in place of the account's.
    ClaimsUpdate,
}

/// Puts the interest of the server's services into the index of the
/// system account on `lane`: in operator mode, where it has one.
pub(crate) fn install(lane: &Lane) {
    let shared = &lane.shared;
    let trusting = shared.auth.as_ref().and_then(crate::auth::Auth::trust);
    let (Some(sys), Some(_)) = (shared.system, trusting) else {
        return;
    };
    let mut index = lane.index(sys).borrow_mut();
    for filter in claims::UPDATES {
        index.tap(filter, Tap::Sys(Service::ClaimsUpdate));
    }
}

/// Answers request `m` for `service`, which came in the system account on
/// `lane`; what goes on is held in `out`. Whether it took it.
pub(crate) fn answer(lane: &Lane, out: &mut Outs, service: Service, m: &Pub<'_>) -> bool {
    match service {
        Service::ClaimsUpdate => claims::update(lane, out, m),
    }
}

/// Sends `data` to `reply` in the system account, as `nats-server` sends
/// its answers: with the server that sends it, and an empty reply.
fn respond(lane: &Lane, out: &mut Outs, reply: &[u8], data: &Value) {
    let shared = &lane.shared;
    let Some(sys) = shared.system else {
        return;
    };
    let mut body = data.clone();
    body["server"] = server_info(shared);
    let payload = body.to_string();
    let m = Pub {
        subject: reply,
        reply: Some(b""),
        headers: None,
        payload: payload.as_bytes(),
    };
    crate::lane::inject(lane, out, sys, &m);
}

/// The server sending a message, as `nats-server` names itself in them.
fn server_info(shared: &Shared) -> Value {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    // Relaxed: the numbers only need to be distinct.
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    let mut info = json!({
        "name": shared.opts.server_name,
        "host": shared.opts.host,
        "id": shared.server_id,
        "ver": env!("CARGO_PKG_VERSION"),
        "jetstream": false,
        "flags": 0,
        "seq": seq,
        "time": crate::imports::latency::rfc3339_nano(std::time::SystemTime::now()),
    });
    if let Some(c) = &shared.opts.cluster {
        info["cluster"] = c.name.clone().into();
    }
    info
}
