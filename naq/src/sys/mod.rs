//! The server's own services in the system account: requests on `$SYS`
//! subjects it answers, as `nats-server` answers them. So far, those of
//! account JWTs.

mod claims;
mod directory;

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
    /// An account JWT for a directory resolver to store.
    ClaimsStore,
    /// A lookup of an account JWT in a full resolver.
    Lookup,
    /// The accounts a directory resolver has.
    List,
    /// Accounts for a directory resolver to delete.
    Delete,
    /// A request for the JWTs a full resolver has, with the hash of the
    /// asking server's.
    Pack,
    /// JWTs another server sent this full resolver, as it asked.
    Packed,
    /// Answers to the lookups of JWTs this server sent the others.
    Lookups,
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
    let Some(dir) = &shared.resolver else {
        return;
    };
    index.tap(directory::UPDATE, Tap::Sys(Service::ClaimsStore));
    index.tap(directory::LIST, Tap::Sys(Service::List));
    index.tap(directory::DELETE, Tap::Sys(Service::Delete));
    index.tap(&dir.lookups.filter(), Tap::Sys(Service::Lookups));
    if dir.full {
        index.tap(directory::LOOKUP, Tap::Sys(Service::Lookup));
        index.tap(crate::resolver::sync::PACK, Tap::Sys(Service::Pack));
        let inbox = crate::resolver::sync::pack_inbox(shared);
        index.tap(&inbox, Tap::Sys(Service::Packed));
    }
}

/// The trust of `shared`'s server, in operator mode.
fn trust(shared: &Shared) -> Option<&crate::jwt::trust::Trust> {
    shared.auth.as_ref().and_then(crate::auth::Auth::trust)
}

/// Answers request `m` for `service`, which came in the system account on
/// `lane`; what goes on is held in `out`. Whether it took it.
pub(crate) fn answer(lane: &Lane, out: &mut Outs, service: Service, m: &Pub<'_>) -> bool {
    match service {
        Service::ClaimsUpdate if lane.shared.resolver.is_some() => {
            let key = claims::account_of(m.subject);
            key.is_some_and(|k| directory::update(lane, out, m, Some(&k)))
        }
        Service::ClaimsUpdate => claims::update(lane, out, m),
        Service::ClaimsStore => directory::update(lane, out, m, None),
        Service::Lookup => directory::lookup(lane, out, m),
        Service::List => directory::list(lane, out, m),
        Service::Delete => directory::delete(lane, out, m),
        Service::Pack => crate::resolver::sync::pack(lane, out, m),
        Service::Packed => crate::resolver::sync::packed(lane, m),
        Service::Lookups => lane
            .shared
            .resolver
            .as_ref()
            .is_some_and(|d| d.lookups.answer(m.subject, m.payload)),
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
        "time": crate::times::rfc3339_nano(std::time::SystemTime::now()),
    });
    if let Some(c) = &shared.opts.cluster {
        info["cluster"] = c.name.clone().into();
    }
    info
}
