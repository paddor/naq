//! Publishes forwarded from other lanes.

use std::rc::Rc;

use bytes::{Buf, Bytes, BytesMut};
use naq_proto::client::Pub;
use naq_proto::peer;

use super::Lane;
use crate::conn::SpentReads;
use crate::index::Found;
use crate::mailbox::Receiver;

/// Offset and length in a batch's chunk, or in its queue names; or
/// [`Span::NONE`]. Without an `Option`, a forward stays 40 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span(u32, u32);

impl Span {
    /// No part.
    const NONE: Span = Span(u32::MAX, 0);

    /// Where `part` lies in `base`, which holds it.
    #[inline]
    fn of(base: &[u8], part: &[u8]) -> Span {
        let at = part.as_ptr() as usize - base.as_ptr() as usize;
        Span(at as u32, part.len() as u32)
    }

    /// Where `part`, if any, lies in `base`.
    #[inline]
    fn of_some(base: &[u8], part: Option<&[u8]>) -> Span {
        part.map_or(Span::NONE, |p| Span::of(base, p))
    }

    #[inline]
    fn get(self, chunk: &[u8]) -> &[u8] {
        let (at, len) = (self.0 as usize, self.1 as usize);
        chunk.get(at..at + len).unwrap_or_default()
    }

    /// The part, unless this is [`Span::NONE`].
    #[inline]
    fn get_some(self, chunk: &[u8]) -> Option<&[u8]> {
        (self != Span::NONE).then(|| self.get(chunk))
    }
}

/// One publish in a batch.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fwd {
    subject: Span,
    reply: Span,
    headers: Span,
    payload: Span,
    /// For one member of this queue group, in the batch's names; else, as
    /// [`Span::NONE`], for the plain subscriptions.
    queue: Span,
}

impl Fwd {
    /// `p`, which lies in `base`.
    #[inline]
    fn of(base: &[u8], p: &Pub<'_>, queue: Span) -> Fwd {
        Fwd {
            subject: Span::of(base, p.subject),
            reply: Span::of_some(base, p.reply),
            headers: Span::of_some(base, p.headers),
            payload: Span::of(base, p.payload),
            queue,
        }
    }
}

/// Publishes one lane read and routed for another: slices of the read
/// buffer, which the batch keeps.
#[derive(Debug)]
pub(crate) struct Batch {
    pub(crate) chunk: Bytes,
    pub(crate) out: Out,
    pub(crate) from: Origin,
}

/// Where the publishes of a batch come from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Origin {
    /// The publisher's account.
    pub(crate) account: u32,
    pub(crate) source: Source,
    /// They came through a service import: shadows do not get them.
    pub(crate) imported: bool,
}

/// Who sent a message to this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// One of its clients.
    Client,
    /// A hub, over a link: clients may get its messages otherwise, see
    /// [`crate::leaf::for_clients`].
    Hub,
    /// Another server of the cluster. Links to hubs do not get its
    /// messages: the hub has a link of its own to that server, as in
    /// `nats-server`.
    Server,
    /// A naq leaf, over OMQ.
    Leaf,
}

/// Least room a batch for a server takes.
const SERVER_ROOM: usize = 16 << 10;

/// What one read leaves for others: publishes for each other lane, and
/// records for each server reached over OMQ.
#[derive(Debug)]
pub(crate) struct Outs {
    pub(crate) lanes: Box<[Out]>,
    /// A batch for each server, by slot. It grows to the slots sent to.
    servers: Vec<ServerBatch>,
    /// The publisher's account, which the batches are of.
    pub(crate) account: u32,
    /// The leaf cluster the publishes come from, with `from_leaf`.
    origin: Vec<u8>,
    from_leaf: bool,
    /// Its publishes came through a service import.
    of_service: bool,
    /// What imports routed in other accounts, if any did yet.
    imported: Option<Box<Imported>>,
}

/// Messages imports routed in other accounts: in a buffer of their own,
/// with the forwards and records of each account.
#[derive(Debug, Default)]
pub(crate) struct Imported {
    /// Their subjects, replies, headers and payloads.
    pub(crate) arena: BytesMut,
    /// The publishes for other lanes and servers, an `Outs` per account.
    pub(crate) outs: Vec<Outs>,
    /// Room to build subjects and headers in.
    pub(crate) subject: Vec<u8>,
    pub(crate) headers: Vec<u8>,
    /// Room for parts of a message in the arena, copied out of it.
    pub(crate) kept: Vec<u8>,
}

impl Imported {
    /// The `Outs` of `account` among `outs`, for messages that came
    /// through a service import if `of_service`, made on first use.
    pub(crate) fn outs_of<'o>(
        outs: &'o mut Vec<Outs>,
        lane: &Lane,
        account: u32,
        of_service: bool,
    ) -> &'o mut Outs {
        let at = outs
            .iter()
            .position(|o| o.account == account && o.of_service == of_service)
            .unwrap_or_else(|| {
                let mut o = Outs::new(lane);
                o.account = account;
                o.of_service = of_service;
                outs.push(o);
                outs.len() - 1
            });
        &mut outs[at]
    }
}

impl Outs {
    /// Room for every other lane and route of `lane`'s server.
    pub(crate) fn new(lane: &Lane) -> Outs {
        Outs {
            lanes: (0..lane.lanes()).map(|_| Out::default()).collect(),
            servers: (0..lane.servers())
                .map(|_| ServerBatch::default())
                .collect(),
            account: 0,
            origin: Vec::new(),
            from_leaf: false,
            of_service: false,
            imported: None,
        }
    }

    /// Room for what imports route in other accounts.
    pub(crate) fn imported(&mut self, lane: &Lane) -> &mut Imported {
        let _ = lane;
        self.imported.get_or_insert_with(Box::default)
    }

    /// The publishes come from a leaf of cluster `origin`, if one: the
    /// batches say so.
    pub(crate) fn set_origin(&mut self, origin: Option<&[u8]>) {
        self.from_leaf = origin.is_some();
        self.origin.clear();
        self.origin.extend_from_slice(origin.unwrap_or_default());
    }

    /// Appends `p` to the batch for server `s`, for its plain
    /// subscriptions, or for one member of queue group `queue`. A new
    /// batch takes its buffer from `lane`'s spent batches.
    pub(crate) fn server(&mut self, lane: &Lane, s: u16, p: &Pub<'_>, queue: Option<&[u8]>) {
        let at = usize::from(s);
        if at >= super::SLOTS {
            return;
        }
        if self.servers.len() <= at {
            self.servers.resize_with(at + 1, ServerBatch::default);
        }
        let batch = &mut self.servers[at];
        if batch.buf.is_empty() {
            batch.open(&lane.batches);
            let name = lane
                .shared
                .accounts
                .get(self.account as usize)
                .map_or("$G", String::as_str);
            let origin = self.from_leaf.then_some(&self.origin[..]);
            peer::batch(&mut batch.buf, origin, name.as_bytes());
        }
        peer::Record {
            subject: p.subject,
            reply: p.reply,
            headers: p.headers,
            payload: p.payload,
            queue,
        }
        .encode(&mut batch.buf);
        batch.msgs += 1;
        batch.bytes += (p.payload.len() + p.headers.map_or(0, <[u8]>::len)) as u64;
    }
}

/// The batch for one server, and the room the next one takes.
#[derive(Debug, Default)]
struct ServerBatch {
    /// From the lane's spent batches; none between reads.
    buf: BytesMut,
    /// A bit more than the last batch took.
    room: usize,
    /// Its messages and their bytes, for the server's tally.
    msgs: u64,
    bytes: u64,
}

impl ServerBatch {
    /// Gives a new batch a buffer from `spent`, unless it has one.
    fn open(&mut self, spent: &SpentReads) {
        if self.buf.capacity() == 0 {
            self.buf = spent.take(self.room.max(SERVER_ROOM));
        }
    }

    /// The batch so far, if any. Its buffer goes back to `spent`, to be
    /// filled again once the batch is sent and dropped.
    fn take(&mut self, spent: &SpentReads) -> Option<Bytes> {
        if self.buf.is_empty() {
            return None;
        }
        let mut buf = std::mem::take(&mut self.buf);
        self.room = buf.len() + buf.len() / 4;
        (self.msgs, self.bytes) = (0, 0);
        let batch = buf.split().freeze();
        spent.retire(buf);
        Some(batch)
    }
}

/// The publishes of one read for one other lane.
#[derive(Debug, Default)]
pub(crate) struct Out {
    msgs: Vec<Fwd>,
    /// Names of the queue groups they are for.
    names: Vec<u8>,
}

impl Out {
    pub(crate) const fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    /// The publishes so far. Their place gets vectors of the same size, so
    /// the next batch does not grow from empty.
    pub(crate) fn take(&mut self) -> Out {
        let msgs = Vec::with_capacity(self.msgs.len());
        let names = Vec::with_capacity(self.names.len());
        Out {
            msgs: std::mem::replace(&mut self.msgs, msgs),
            names: std::mem::replace(&mut self.names, names),
        }
    }

    /// Forwards `p`, which lies in `base`, for the lane's plain
    /// subscriptions. With `once`, not if the last forward was that already.
    #[inline]
    pub(crate) fn plain(&mut self, base: &[u8], p: &Pub<'_>, once: bool) {
        let f = Fwd::of(base, p, Span::NONE);
        if once
            && self
                .msgs
                .last()
                .is_some_and(|l| l.payload == f.payload && l.queue == Span::NONE)
        {
            return;
        }
        self.msgs.push(f);
    }

    /// Forwards `p`, which lies in `base`, for one member of queue group
    /// `name` on the lane.
    pub(crate) fn queue(&mut self, base: &[u8], p: &Pub<'_>, name: &[u8]) {
        let at = self.names.len();
        self.names.extend_from_slice(name);
        let span = Span(at as u32, name.len() as u32);
        self.msgs.push(Fwd::of(base, p, span));
    }
}

/// Delivers what other lanes forward, to this lane's subscribers.
pub(super) async fn run(lane: Rc<Lane>, rx: Receiver<Batch>) {
    let mark = lane.shared.opts.max_pending / 4 * 3;
    let mut batches = Vec::new();
    while rx.recv_all(&mut batches).await {
        let mut stalled = None;
        for b in batches.drain(..) {
            lane.imported.set(b.from.imported);
            let msgs = &b.out.msgs;
            for (k, f) in msgs.iter().enumerate() {
                lane.deliver_fwd(&b, f, &mut stalled);
                // The forwards of one message come in a row: links get it
                // once, after the last.
                if lane.has_hits() && msgs.get(k + 1).is_none_or(|n| n.payload != f.payload) {
                    lane.send_hits(&pub_of(&b, f), &mut stalled);
                }
            }
        }
        lane.imported.set(false);
        lane.flush();
        lane.expire();
        // A subscriber past the stall mark slows its publishers: they wait
        // for room in this lane's mailbox meanwhile.
        if let Some(c) = stalled {
            crate::conn::stall(&c, mark).await;
        }
        tokio::task::yield_now().await;
    }
}

/// Forward `f` of batch `b` as a publish.
fn pub_of<'b>(b: &'b Batch, f: &Fwd) -> Pub<'b> {
    Pub {
        subject: f.subject.get(&b.chunk),
        reply: f.reply.get_some(&b.chunk),
        headers: f.headers.get_some(&b.chunk),
        payload: f.payload.get(&b.chunk),
    }
}

impl Lane {
    /// Drops the `at` bytes parsed from `buf`, handing those that the
    /// messages in `out` refer to over to their lanes, as batches from
    /// `source`, and sends the batches for other servers.
    pub(crate) async fn ship_reads(
        &self,
        out: &mut Outs,
        buf: &mut BytesMut,
        at: usize,
        source: Source,
    ) {
        self.ship_imported(out).await;
        self.ship_servers(out).await;
        if out.lanes.iter().all(Out::is_empty) {
            buf.advance(at);
            return;
        }
        let chunk = buf.split_to(at).freeze();
        self.ship_chunk(out, chunk, source).await;
    }

    /// Hands `chunk`, which the messages in `out` refer to, over to their
    /// lanes, as batches from `source`.
    pub(crate) async fn ship_chunk(&self, out: &mut Outs, chunk: Bytes, source: Source) {
        let from = Origin {
            account: out.account,
            source,
            imported: out.of_service,
        };
        for (to, out) in out.lanes.iter_mut().enumerate() {
            if !out.is_empty() {
                let batch = Batch {
                    chunk: chunk.clone(),
                    out: out.take(),
                    from,
                };
                self.ship(to, batch).await;
            }
        }
    }

    /// Hands what imports routed with `out` over to the other lanes and
    /// servers, in one chunk of the arena.
    pub(crate) async fn ship_imported(&self, out: &mut Outs) {
        // Shadows of naq links write records only: the arena may be empty.
        let Some(imported) = out.imported.as_deref_mut() else {
            return;
        };
        let chunk = imported.arena.split().freeze();
        for out in &mut imported.outs {
            self.ship_servers(out).await;
            if !out.lanes.iter().all(Out::is_empty) {
                self.ship_chunk(out, chunk.clone(), Source::Client).await;
            }
        }
    }

    /// Sends the batch for each server that has one, on this lane's link
    /// to it; without a link, it is dropped, as Core may drop. Its buffer
    /// goes back to the lane's spent batches, to be filled again once the
    /// batch is sent.
    pub(crate) async fn ship_servers(&self, out: &mut Outs) {
        for (s, b) in out.servers.iter_mut().enumerate() {
            let (msgs, bytes) = (b.msgs, b.bytes);
            let Some(batch) = b.take(&self.batches) else {
                continue;
            };
            // Slots are below 64: they fit.
            self.slots.tally(s as u16).gave_many(msgs, bytes);
            let link = self.sends.borrow().get(s).cloned().flatten();
            if let Some(link) = link {
                link.send(batch).await;
            }
        }
    }

    /// Notes the links on this lane among `peers`, for a message from
    /// `source`. Out of line, as most interest has none: the loop of
    /// [`run`] stays small.
    #[inline(never)]
    fn peers_here(&self, peers: &[crate::index::Peer], source: Source) {
        if source == Source::Server {
            return;
        }
        for p in peers.iter().filter(|p| p.lane == self.id) {
            self.hit_link(*p, None);
        }
    }

    /// Delivers `m`, forwarded for one member of queue group `name` of
    /// `found`, to one member on this lane, else to a link here.
    #[inline(never)]
    fn deliver_fwd_queue(
        &self,
        found: &Found<'_>,
        name: &[u8],
        m: &Pub<'_>,
        stalled: &mut Option<Rc<crate::conn::Client>>,
    ) {
        let q = super::Queue {
            name,
            groups: found.queue_groups(0, name),
            // Other lanes leave servers to the lane the message came in on.
            skips: u64::MAX,
        };
        self.deliver_any(&q, m, true, stalled);
    }

    /// Delivers forward `f` of batch `b` to the subscriptions on this lane.
    #[inline]
    fn deliver_fwd(&self, b: &Batch, f: &Fwd, stalled: &mut Option<Rc<crate::conn::Client>>) {
        let p = pub_of(b, f);
        let index = self.index(b.from.account).borrow();
        let Some(found) = index.matches(p.subject) else {
            return;
        };
        let remapped = if b.from.source == Source::Hub {
            crate::leaf::for_clients(&p)
        } else {
            None
        };
        let to_clients = remapped.as_ref().unwrap_or(&p);
        // The publisher is on another lane: nothing to skip.
        match (&found, f.queue.get_some(&b.out.names)) {
            (Found::One(i), None) => {
                self.deliver(&i.plain.local, to_clients, 0, stalled);
                if !i.plain.peers.is_empty() {
                    self.peers_here(&i.plain.peers, b.from.source);
                }
            }
            (Found::Many(all), None) => {
                for i in all.iter() {
                    self.deliver(&i.plain.local, to_clients, 0, stalled);
                    if !i.plain.peers.is_empty() {
                        self.peers_here(&i.plain.peers, b.from.source);
                    }
                }
            }
            (_, Some(name)) => self.deliver_fwd_queue(&found, name, to_clients, stalled),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_batch_leaves_room_for_as_many() {
        let base = b"PUB a 1\r\nx\r\n";
        let p = Pub {
            subject: &base[4..5],
            reply: None,
            headers: None,
            payload: &base[9..10],
        };
        let mut out = Out::default();
        for _ in 0..5 {
            out.plain(base, &p, false);
        }
        out.queue(base, &p, b"q");
        let taken = out.take();
        assert_eq!((taken.msgs.len(), &taken.names[..]), (6, &b"q"[..]));
        assert!(out.is_empty() && out.names.is_empty());
        assert!(out.msgs.capacity() >= 6 && out.names.capacity() >= 1);
    }

    #[test]
    fn a_batch_for_a_server_fills_its_buffer_again_once_sent() {
        let spent = SpentReads::default();
        let mut b = ServerBatch::default();
        assert!(b.take(&spent).is_none());
        b.open(&spent);
        b.buf.resize(20_000, 1);
        let first = b.take(&spent).unwrap();
        let at = first.as_ptr();
        assert_eq!((first.len(), b.room, b.buf.capacity()), (20_000, 25_000, 0));
        // In flight, its buffer is not filled again.
        b.open(&spent);
        assert_ne!(b.buf.as_ptr(), at);
        assert!(b.buf.capacity() >= 25_000);
        b.buf.extend_from_slice(&[2; 100]);
        let second = b.take(&spent).unwrap();
        assert_eq!((&second[..], b.room), (&[2; 100][..], 125));
        drop(first);
        b.open(&spent);
        assert_eq!(b.buf.as_ptr(), at, "sent and dropped, it is filled again");
        assert!(b.buf.capacity() >= SERVER_ROOM);
    }
}
