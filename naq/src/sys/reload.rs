//! `$SYS.REQ.SERVER.<id>.RELOAD`: a reload of the configuration, as
//! `nats-server` takes it. A failed reload is told in the answer alone,
//! not logged.

use std::sync::Arc;

use naq_proto::client::Pub;

use super::Service;
use super::kick::FILTERED;
use super::later::{Answer, Asked, later};
use super::reply::{self, ApiError};
use super::server;
use crate::imports::service::Tap;
use crate::index::Index;
use crate::lane::Lane;
use crate::server::Shared;

/// Puts the tap of reloads into `index`, the system account's of a server
/// of ID `id`.
pub(super) fn install(index: &mut Index, id: &str) {
    let subject = format!("$SYS.REQ.SERVER.{id}.RELOAD");
    index.tap(subject.as_bytes(), Tap::Sys(Service::Reload));
}

/// Takes reload request `m`, which came on `lane`.
pub(super) fn take(lane: &Lane, m: &Pub<'_>) -> bool {
    later(lane, m, answer);
    true
}

/// Reloads, unless the request has no reply or its filters leave this
/// server out, and answers.
async fn answer(shared: Arc<Shared>, asked: Asked) -> Option<Answer> {
    if asked.reply.is_empty() {
        return None;
    }
    match server::options(&shared, &asked, &FILTERED) {
        Ok(Some(_)) => {}
        Ok(None) => return None,
        Err(a) => return Some(a),
    }
    // Off the lane: a reload reads files and tells the lanes.
    let s = shared.clone();
    let done = tokio::task::spawn_blocking(move || crate::reload::reload(&s)).await;
    let why = match done {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(crate::error::chain(&e)),
        Err(_) => Some("config reload failed".into()),
    };
    let Some(why) = why else {
        let payload = reply::envelope(&shared, None, None);
        return Some(Answer::encoded(asked.reply, &asked.headers, payload));
    };
    let e = ApiError::new(500, why);
    Some(Answer::new(
        asked.reply,
        reply::envelope(&shared, None, Some(&e)),
    ))
}
