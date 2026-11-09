//! `$SYS.REQ.SERVER.<id>.KICK` and `.LDM`: requests about one connection
//! of this server, as `nats-server` takes them. A kick closes it with the
//! reason `Kicked`; `LDM` sends a client the `INFO` of lame duck mode.

use std::sync::Arc;

use naq_proto::client::Pub;

use super::Service;
use super::later::{Answer, Asked, later};
use super::reply::{self, ApiError};
use super::server::{self, FILTERS};
use super::unmarshal::{self, Fields, Kind};
use crate::conn::Close;
use crate::imports::service::Tap;
use crate::index::Index;
use crate::lane::Lane;
use crate::server::Shared;

/// What a request about one connection asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Act {
    /// `KICK`: close it.
    Kick,
    /// `LDM`: tell it the server is in lame duck mode.
    Ldm,
}

/// Go's `KickClientReq`.
const KICK: Fields = Fields {
    name: "KickClientReq",
    keys: [&[("cid", Kind::Uint)], &[]],
};

/// Go's `LDMClientReq`.
const LDM: Fields = Fields {
    name: "LDMClientReq",
    keys: [&[("cid", Kind::Uint)], &[]],
};

impl Act {
    /// Go's type of its body.
    const fn fields(self) -> &'static Fields {
        match self {
            Act::Kick => &KICK,
            Act::Ldm => &LDM,
        }
    }
}

/// The filters a kick takes, as Go's `EventFilterOptions`.
const FILTERED: Fields = Fields {
    name: "EventFilterOptions",
    keys: [FILTERS, &[]],
};

/// Puts the taps of kicks and `LDM` into `index`, the system account's of
/// a server of ID `id`.
pub(super) fn install(index: &mut Index, id: &str) {
    for (act, token) in [(Act::Kick, "KICK"), (Act::Ldm, "LDM")] {
        let subject = format!("$SYS.REQ.SERVER.{id}.{token}");
        index.tap(subject.as_bytes(), Tap::Sys(Service::Conn(act)));
    }
}

/// Takes request `m` for `act`, which came on `lane`.
pub(super) fn take(lane: &Lane, act: Act, m: &Pub<'_>) -> bool {
    later(lane, m, move |shared, asked| answer(shared, asked, act));
    true
}

/// Does `act` to the connection `asked` names, and answers: none for a
/// body that does not name one, or without a reply, as `nats-server` does
/// nothing then.
async fn answer(shared: Arc<Shared>, asked: Asked, act: Act) -> Option<Answer> {
    let s = &*shared;
    let cid = match unmarshal::decode(&asked.body, act.fields()) {
        Ok(set) => set.uint("cid"),
        Err(why) => {
            // Go's text, for both.
            s.log.error(format_args!(
                "Error unmarshalling kick client request: {why}"
            ));
            return None;
        }
    };
    if asked.reply.is_empty() {
        return None;
    }
    match server::options(s, &asked, &FILTERED) {
        Ok(Some(_)) => {}
        Ok(None) => return None,
        Err(a) => return Some(a),
    }
    let done = match act {
        Act::Kick => kick(s, cid).await,
        Act::Ldm => ldm(s, cid).await,
    };
    let e = done.err().map(|why| ApiError::new(500, why.into()));
    Some(Answer::new(
        asked.reply,
        reply::envelope(s, None, e.as_ref()),
    ))
}

/// Closes client or link to a hub `cid` of `shared`'s server as kicked,
/// or says it has none.
async fn kick(shared: &Shared, cid: u64) -> Result<(), &'static str> {
    let found = crate::monitor::ask_all(shared, move |lane| {
        if let Some(c) = lane.clients.borrow().get(&cid) {
            c.kick(Close::Kicked);
            return true;
        }
        let links = lane.links.borrow();
        let link = links.iter().find(|l| l.id == cid);
        link.inspect(|l| l.client.kick(Close::Kicked)).is_some()
    })
    .await;
    if found.contains(&true) {
        Ok(())
    } else {
        Err("no such client or leafnode id")
    }
}

/// Sends client `cid` of `shared`'s server the `INFO` of lame duck mode,
/// or says why not, as `nats-server` does.
async fn ldm(shared: &Shared, cid: u64) -> Result<(), &'static str> {
    let found = crate::monitor::ask_all(shared, move |lane| {
        let clients = lane.clients.borrow();
        let c = clients.get(&cid)?;
        if !c.inform(true) {
            return Some(false);
        }
        let log = &lane.shared.log;
        if log.debugs() {
            let label = c.label(&lane.shared, true);
            log.debug(format_args!(
                "{label} - Sending Lame Duck Mode info to client"
            ));
        }
        Some(true)
    })
    .await;
    match found.into_iter().flatten().next() {
        Some(true) => Ok(()),
        Some(false) => Err(
            "client does not support Lame Duck Mode or is not ready to receive the notification",
        ),
        None => Err("no such client id"),
    }
}
