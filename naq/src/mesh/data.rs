//! Data between servers over OMQ: each lane's link to each server, by
//! slot, and what comes in on each lane.
//!
//! A lane sends to each route's lane on a PUSH, and takes from all routes
//! on a PULL. A naq leaf dials every lane of its hub with a DEALER per
//! channel, so that no hub dials a leaf: lane `j` of a hub sends on channel `j`, lane `i` of a
//! leaf on channel `i`.

use std::rc::Rc;

use bytes::Bytes;
use naq_proto::client::Pub;
use naq_proto::peer;
use omq_tokio::{IdentitySocket, Message, Socket, SocketType};

use super::socket_options;
use crate::conn::{self, Client};
use crate::lane::{Lane, Outs, Routing, Source, bit};

/// A lane's data link to the server in a slot.
#[derive(Debug, Clone)]
pub(crate) enum DataLink {
    /// A PUSH to the lane of a route.
    Push(Socket),
    /// This lane's ROUTER for naq leafs, to the channel of one.
    Leaf(IdentitySocket, Bytes),
    /// A DEALER to the lane of a naq hub, and the lane's channels to
    /// the hub that only take its data, when it has more lanes.
    Hub(Socket, Rc<[Socket]>),
}

impl DataLink {
    /// Sends `batch`. One the link cannot take is dropped, as Core may
    /// drop.
    pub(crate) async fn send(&self, batch: Bytes) {
        let m = Message::single(batch);
        let _ = match self {
            DataLink::Push(s) | DataLink::Hub(s, _) => s.send(m).await,
            DataLink::Leaf(ids, to) => ids.send_to(to, m).await,
        };
    }
}

/// Puts `link` in `lane`'s slot `s`, in place of what was there, which is
/// closed.
fn set(lane: &Lane, s: u16, link: Option<DataLink>) {
    let old = {
        let mut all = lane.sends.borrow_mut();
        let at = usize::from(s);
        if all.len() <= at {
            all.resize(at + 1, None);
        }
        std::mem::replace(&mut all[at], link)
    };
    let all: Vec<Socket> = match old {
        Some(DataLink::Push(s)) => vec![s],
        Some(DataLink::Hub(s, rest)) => std::iter::once(s).chain(rest.iter().cloned()).collect(),
        Some(DataLink::Leaf(..)) | None => return,
    };
    tokio::task::spawn_local(async move {
        for s in all {
            let _ = s.close().await;
        }
    });
}

/// Gives `lane` a data link to server `server`, by route, at `endpoint`,
/// in place of the one it had.
pub(crate) fn push(lane: &Lane, server: u16, endpoint: &str) {
    let s = omq_tokio::Context::current().socket(SocketType::Push, socket_options(Bytes::new()));
    let (dial, at) = (s.clone(), endpoint.to_owned());
    tokio::task::spawn_local(async move {
        let _ = dial.connect(at).await;
    });
    set(lane, server, Some(DataLink::Push(s)));
}

/// Closes `lane`'s data link to the server in slot `server`: sends waiting
/// on it fail, and what it holds is dropped.
pub(crate) fn gone(lane: &Lane, server: u16) {
    set(lane, server, None);
    // Counted again once it is back, as a new route.
    lane.slots.tally(server).reset();
}

/// Gives `lane` a data link to the naq leaf in slot `s`, of control
/// identity `id`: its channel of this lane, on the lane's ROUTER.
pub(crate) fn leaf(lane: &Lane, s: u16, id: &[u8]) {
    let ids = lane.leaf_router.borrow().clone();
    let Some(ids) = ids else {
        return;
    };
    let to = channel(id, lane.id);
    set(lane, s, Some(DataLink::Leaf(ids, to)));
}

/// The identity of channel `c` of the leaf of control identity `id`.
fn channel(id: &[u8], c: usize) -> Bytes {
    let mut to = id.to_vec();
    to.extend_from_slice(format!("/{c}").as_bytes());
    to.into()
}

/// Dials, from `lane`, the channels of this lane to the naq hub in slot
/// `s` at `endpoints`, one per lane of the hub, as leaf of control
/// identity `id`; and routes what the hub sends on them.
pub(crate) fn hub(lane: &Rc<Lane>, s: u16, id: &[u8], endpoints: &[String]) {
    gone(lane, s);
    if endpoints.is_empty() {
        return;
    }
    let lanes = lane.lanes();
    let channels = lanes.max(endpoints.len());
    let ctx = omq_tokio::Context::current();
    let open = |c: usize| {
        let dealer = ctx.socket(SocketType::Dealer, socket_options(channel(id, c)));
        let (dial, at) = (dealer.clone(), endpoints[c % endpoints.len()].clone());
        tokio::task::spawn_local(async move {
            let _ = dial.connect(at).await;
        });
        tokio::task::spawn_local(receive_hub(lane.clone(), dealer.clone(), s));
        dealer
    };
    let send = open(lane.id);
    let rest = (lane.id + lanes..channels)
        .step_by(lanes)
        .map(open)
        .collect();
    set(lane, s, Some(DataLink::Hub(send, rest)));
}

/// Where a batch comes from.
#[derive(Debug, Clone, Copy)]
enum From {
    Route,
    /// The naq hub in a slot.
    Hub(u16),
    /// The naq leaf in a slot.
    Leaf(u16),
}

/// Routes what the routes send `lane` on `pull`: to its clients, its
/// other lanes, its links and its naq leafs; never to another route.
pub(super) async fn receive(lane: Rc<Lane>, pull: Socket) {
    let mut out = Outs::new(&lane);
    loop {
        let Ok(msg) = pull.recv().await else {
            return;
        };
        if let Ok(chunk) = msg.into_bytes() {
            take(&lane, &mut out, chunk, From::Route).await;
        }
    }
}

/// Routes what the naq leafs send `lane` on its ROUTER `ids`.
pub(super) async fn receive_leafs(lane: Rc<Lane>, ids: IdentitySocket) {
    let mut out = Outs::new(&lane);
    loop {
        let Ok((who, msg)) = ids.recv_from().await else {
            return;
        };
        let who = who.to_bytes();
        let Some(s) = leaf_of(&who).and_then(|id| lane.slots.find(id)) else {
            continue;
        };
        if let Ok(chunk) = msg.into_bytes() {
            take(&lane, &mut out, chunk, From::Leaf(s)).await;
        }
    }
}

/// Routes what the naq hub in slot `s` sends `lane` on `dealer`, until it
/// closes.
async fn receive_hub(lane: Rc<Lane>, dealer: Socket, s: u16) {
    let mut out = Outs::new(&lane);
    loop {
        let Ok(msg) = dealer.recv().await else {
            return;
        };
        if let Ok(chunk) = msg.into_bytes() {
            take(&lane, &mut out, chunk, From::Hub(s)).await;
        }
    }
}

/// Routes batch `chunk` from `from` on `lane`, and hands on what is for
/// its other lanes.
async fn take(lane: &Lane, out: &mut Outs, chunk: Bytes, from: From) {
    let mark = lane.shared.opts.max_pending / 4 * 3;
    let stalled = route(lane, out, &chunk, from);
    lane.flush();
    lane.expire();
    let source = match from {
        From::Route => Source::Server,
        From::Hub(_) => Source::Hub,
        From::Leaf(_) => Source::Leaf,
    };
    lane.ship_imported(out).await;
    lane.ship_servers(out).await;
    lane.ship_chunk(out, chunk, source).await;
    // A subscriber past the stall mark slows the sender to its pace: its
    // link fills up meanwhile.
    if let Some(sub) = stalled {
        conn::stall(&sub, mark, &lane.shared.events.stalls).await;
    }
}

/// Routes the records of the batch in `chunk`, from `from`. Returns a
/// subscriber past the stall mark, if one.
fn route(lane: &Lane, out: &mut Outs, chunk: &[u8], from: From) -> Option<Rc<Client>> {
    let b = peer::Batch::parse(chunk).ok()?;
    let slots = &lane.slots;
    let skips = begin(lane, out, &b, from)?;
    let index = lane.index(out.account).borrow();
    // The naq hub or leaf it came from, and that one if its link may hold
    // some back.
    let link = match from {
        From::Route => None,
        From::Hub(s) | From::Leaf(s) => Some(s),
    };
    let held = link.filter(|&s| slots.guarded() & bit(s) != 0);
    let (mut msgs, mut bytes) = (0, 0);
    let mut stalled = None;
    for r in b.records() {
        let Ok(r) = r else { break };
        if held.is_some_and(|s| !slots.takes(s, r.subject)) {
            continue;
        }
        let p = Pub {
            subject: r.subject,
            reply: r.reply,
            headers: r.headers,
            payload: r.payload,
        };
        let size = p.payload.len() + p.headers.map_or(0, <[u8]>::len);
        msgs += 1;
        bytes += size as u64;
        let Some(found) = index.matches(p.subject) else {
            continue;
        };
        let routing = Routing::new(lane, out, &p, chunk, 0).with_imports();
        let mut routing = match from {
            From::Route => routing.by_server(r.queue, skips),
            From::Hub(_) | From::Leaf(_) => routing.by_linked(r.queue, skips),
        };
        // A record for a queue group is that group's alone: plain
        // subscriptions get a record of their own.
        if r.queue.is_some() {
            routing.route_queues(&found);
        } else {
            routing.route(&found);
        }
        let (tapped, skips) = (routing.tapped(), routing.skips());
        if let Some(s) = routing.stalled {
            stalled = Some(s);
        }
        if tapped && let Some(s) = import(lane, out, &p, from, skips) {
            stalled = Some(s);
        }
    }
    lane.peers.took_many(msgs, bytes);
    if let Some(s) = link {
        slots.tally(s).took_many(msgs, bytes);
    }
    stalled
}

/// Sends `p`, from `from`, through the imports it met. Returns a
/// subscriber past the stall mark, if one. From a route, only responses
/// go through: requests went through where they were published.
#[cold]
#[inline(never)]
fn import(lane: &Lane, out: &mut Outs, p: &Pub<'_>, from: From, skips: u64) -> Option<Rc<Client>> {
    let source = match from {
        From::Route => Source::Server,
        From::Hub(_) => Source::Hub,
        From::Leaf(_) => Source::Leaf,
    };
    let from = crate::imports::service::From {
        client: None,
        skip: 0,
        source,
        skips,
    };
    let account = out.account;
    crate::imports::service::run(lane, out, p, account, from).1
}

/// Readies `out` for batch `b` from `from`: its account and origin.
/// Returns the slots its messages skip; `None` for an account or a link
/// this server has not.
fn begin(lane: &Lane, out: &mut Outs, b: &peer::Batch<'_>, from: From) -> Option<u64> {
    let slots = &lane.slots;
    let (account, skips) = match from {
        From::Route => {
            let account = lane.account_id(b.account)?;
            out.set_origin(b.origin);
            (account, slots.route_skips(b.origin))
        }
        From::Hub(s) => {
            out.set_origin(None);
            (slots.linked(s)?.account, slots.hub_skips(s))
        }
        From::Leaf(s) => {
            let l = slots.linked(s)?;
            out.set_origin(Some(&l.cluster));
            (l.account, slots.leaf_skips(s))
        }
    };
    out.account = account;
    Some(skips)
}

/// The control identity of the leaf of channel identity `c`: what comes
/// before its last `/`.
fn leaf_of(c: &[u8]) -> Option<&[u8]> {
    let at = c.iter().rposition(|&b| b == b'/')?;
    Some(&c[..at])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_is_named_after_its_leaf() {
        let c = channel(b"N/0/3", 7);
        assert_eq!(&c[..], b"N/0/3/7");
        assert_eq!(leaf_of(&c), Some(&b"N/0/3"[..]));
        assert_eq!(leaf_of(b"x"), None);
    }
}
