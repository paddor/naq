//! Data between the servers of the mesh: each lane's link to each other
//! server, and what comes in on each lane.

use std::rc::Rc;

use bytes::Bytes;
use naq_proto::client::Pub;
use naq_proto::peer;
use omq_tokio::{Socket, SocketType};

use super::socket_options;
use crate::conn::{self, Client};
use crate::lane::{Lane, Outs, Routing};

/// Gives `lane` a data link to server `server`, by route, at `endpoint`,
/// in place of the one it had.
pub(crate) fn push(lane: &Lane, server: u16, endpoint: &str) {
    let s = omq_tokio::Context::current().socket(SocketType::Push, socket_options(Bytes::new()));
    let (dial, at) = (s.clone(), endpoint.to_owned());
    tokio::task::spawn_local(async move {
        let _ = dial.connect(at).await;
    });
    if let Some(slot) = lane.pushes.borrow_mut().get_mut(usize::from(server)) {
        *slot = Some(s);
    }
}

/// Routes what the other servers send `lane` on `pull`: to its clients,
/// its other lanes and its links, never to another server.
pub(super) async fn receive(lane: Rc<Lane>, pull: Socket) {
    let mut out = Outs::new(&lane);
    let mark = lane.shared.opts.max_pending / 4 * 3;
    loop {
        let Ok(msg) = pull.recv().await else {
            return;
        };
        let Ok(chunk) = msg.into_bytes() else {
            continue;
        };
        let stalled = route(&lane, &mut out, &chunk);
        lane.flush();
        lane.expire();
        lane.ship_chunk(&mut out, chunk, false).await;
        // A subscriber past the stall mark slows the other server to its
        // pace: its link fills up meanwhile.
        if let Some(sub) = stalled {
            conn::stall(&sub, mark).await;
        }
    }
}

/// Routes the records of the batch in `chunk`. Returns a subscriber past
/// the stall mark, if one.
fn route(lane: &Lane, out: &mut Outs, chunk: &[u8]) -> Option<Rc<Client>> {
    let b = peer::Batch::parse(chunk).ok()?;
    let account = lane
        .shared
        .accounts
        .iter()
        .position(|a| a.as_bytes() == b.account)?;
    // Accounts are few: their count fits.
    out.account = account as u32;
    let index = lane.index(out.account).borrow();
    let mut stalled = None;
    for r in b.records() {
        let Ok(r) = r else { break };
        let p = Pub {
            subject: r.subject,
            reply: r.reply,
            headers: r.headers,
            payload: r.payload,
        };
        let size = p.payload.len() + p.headers.map_or(0, <[u8]>::len);
        lane.tally.took(size);
        let Some(found) = index.matches(p.subject) else {
            continue;
        };
        let mut routing = Routing::new(lane, out, &p, chunk, 0).by_server(r.queue);
        routing.route(&found);
        if let Some(s) = routing.stalled {
            stalled = Some(s);
        }
    }
    stalled
}
