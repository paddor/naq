//! `$SYS.REQ.SERVER.<id>.KICK`: a request to close a connection of this
//! server, as `nats-server` closes it, with the reason `Kicked`.

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

/// Go's `KickClientReq`.
const KICK: Fields = Fields {
    name: "KickClientReq",
    keys: [&[("cid", Kind::Uint)], &[]],
};

/// The filters a kick takes, as Go's `EventFilterOptions`.
const FILTERED: Fields = Fields {
    name: "EventFilterOptions",
    keys: [FILTERS, &[]],
};

/// Puts the tap of kicks into `index`, the system account's of a server
/// of ID `id`.
pub(super) fn install(index: &mut Index, id: &str) {
    let subject = format!("$SYS.REQ.SERVER.{id}.KICK");
    index.tap(subject.as_bytes(), Tap::Sys(Service::Kick));
}

/// Takes kick `m`, which came on `lane`.
pub(super) fn take(lane: &Lane, m: &Pub<'_>) -> bool {
    later(lane, m, answer);
    true
}

/// Closes the connection kick `asked` names, and answers: none for a
/// body that does not name one, or without a reply, as `nats-server` does
/// nothing then.
async fn answer(shared: Arc<Shared>, asked: Asked) -> Option<Answer> {
    let s = &*shared;
    let cid = match unmarshal::decode(&asked.body, &KICK) {
        Ok(set) => set.uint("cid"),
        Err(why) => {
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
    let body = if kick(s, cid).await {
        reply::envelope(s, None, None)
    } else {
        let e = ApiError::new(500, "no such client or leafnode id".into());
        reply::envelope(s, None, Some(&e))
    };
    Some(Answer::new(asked.reply, body))
}

/// Closes client or link to a hub `cid` of `shared`'s server as kicked:
/// whether it has one.
async fn kick(shared: &Shared, cid: u64) -> bool {
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
    found.contains(&true)
}
