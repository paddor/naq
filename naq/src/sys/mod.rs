//! The server's own services in the system account: requests on `$SYS`
//! subjects it answers, as `nats-server` answers them.

mod account;
mod claims;
mod directory;
mod encode;
mod later;
mod reply;
mod server;
mod unmarshal;

use std::sync::atomic::AtomicU64;

use naq_proto::client::Pub;
use serde_json::Value;

pub(crate) use server::Z;

use crate::imports::service::Tap;
use crate::lane::{Lane, Outs};
use crate::server::Shared;

/// What a server keeps for its services.
#[derive(Debug)]
pub(crate) struct State {
    /// The hash of the server's name that its inboxes on `$SYS` end in,
    /// as `nats-server` makes it, with a system account.
    pub(crate) node: Option<[u8; 8]>,
    /// The number of the last message it sent on `$SYS`.
    seq: AtomicU64,
    /// The requests it answers now.
    busy: later::Busy,
}

impl State {
    /// The state of a server whose name hashes to `node`.
    pub(crate) fn new(node: Option<[u8; 8]>) -> State {
        State {
            node,
            seq: AtomicU64::new(0),
            busy: later::Busy::default(),
        }
    }
}

/// A request the server answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Service {
    /// A request to the server, for what its last token names.
    Server(Z),
    /// `$SYS.REQ.SERVER.PING`: `STATSZ` by its old subject.
    Ping,
    /// A request about an account, for what its last token names.
    Account(account::X),
    /// `$SYS.REQ.ACCOUNT.PING.STATZ`: the statistics of every account.
    AccountPing,
    /// A user's request for its own details.
    UserInfo,
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

/// An event ID as `nats-server` makes them: 22 letters or digits.
fn event_id() -> String {
    let mut raw = [0u8; 22];
    // Without randomness, the IDs only repeat.
    let _ = getrandom::getrandom(&mut raw);
    raw.iter()
        .map(|&b| char::from(crate::imports::service::base62(u64::from(b) % 62)))
        .collect()
}

impl Service {
    /// Whether only the server a client is on answers it: other servers
    /// do not hear of its interest.
    pub(crate) const fn local(self) -> bool {
        matches!(self, Service::UserInfo)
    }
}

/// Reads `data` as the body of each server request, as Go reads it.
///
/// # Panics
///
/// When Go's check and `serde_json` disagree on whether it is JSON.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz(data: &[u8]) {
    unmarshal::fuzz(data);
    for z in Z::ALL {
        let _ = unmarshal::decode(data, &z.fields());
    }
}

/// Puts the interest of the server's services into the index of the
/// system account on `lane`, if it has one: those of JWTs in operator
/// mode only.
pub(crate) fn install(lane: &Lane) {
    let shared = &lane.shared;
    let Some(sys) = shared.system else {
        return;
    };
    let mut index = lane.index(sys).borrow_mut();
    server::install(&mut index, &shared.server_id);
    account::install(&mut index);
    if trust(shared).is_none() {
        return;
    }
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
/// `lane` from client `from`, if a client sent it; what goes on is held in
/// `out`. Whether it took it.
pub(crate) fn answer(
    lane: &Lane,
    out: &mut Outs,
    service: Service,
    m: &Pub<'_>,
    from: Option<&crate::conn::Client>,
) -> bool {
    match service {
        Service::Server(z) => server::take(lane, out, z, m),
        Service::Ping => server::take(lane, out, Z::Statsz, m),
        Service::Account(x) => account::take(lane, Some(x), m),
        Service::AccountPing => account::take(lane, None, m),
        Service::UserInfo => account::user_info(lane, m, from),
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

/// Sends `answer`, which holds `data` or `error`, to `reply` in the
/// system account, as `nats-server` sends its answers: with the server
/// that sends it first, and an empty reply.
fn respond(lane: &Lane, out: &mut Outs, reply: &[u8], answer: &Value) {
    let shared = &lane.shared;
    let Some(sys) = shared.system else {
        return;
    };
    let info = crate::monitor::json::compact(&reply::ServerInfo::of(shared));
    let mut payload = [&b"{\"server\":"[..], &info].concat();
    for key in ["data", "error"] {
        if let Some(v) = answer.get(key) {
            payload.extend_from_slice(format!(",\"{key}\":{v}").as_bytes());
        }
    }
    payload.push(b'}');
    let a = later::Answer::new(reply.to_vec(), payload);
    later::send_now(lane, out, sys, &a);
}
