//! The read loop: parses what a client sends and acts on it.

use std::rc::Rc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use naq_proto::client::{self, ClientOp, Limits, ParseError, Parsed, Pub, Sub, Unsub};
use naq_proto::{encode, subject};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{Client, Close, Conn};
use crate::index::{Entry, Few, Found, Index, Interest};
use crate::lane::{Batch, Lane, Out, Queued};

/// Bytes a read may fill at least. With less room, the buffer grows by
/// [`READ_CHUNK`] or takes back what was parsed already.
const READ_ROOM: usize = 16 << 10;
const READ_CHUNK: usize = 256 << 10;

/// Longest a publisher waits at a time for a subscriber past the stall
/// mark, as in `nats-server`.
const STALL_MAX: Duration = Duration::from_millis(5);

/// Where parsing a buffer stopped.
enum Stop {
    /// At the end of what was read; `Some` is the length of the operation
    /// that starts there.
    More(Option<usize>),
    /// At a `PING` that must wait until every lane has this client's
    /// subscriptions.
    Fence,
}

/// What to do after an operation.
enum Step {
    Next,
    Fence,
}

impl Conn {
    pub(super) async fn read_loop<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> Close {
        let opts = &self.lane.shared.opts;
        let limits = Limits {
            max_control_line: opts.max_control_line,
            max_payload: opts.max_payload,
        };
        let stall_mark = opts.max_pending / 4 * 3;
        let mut buf = BytesMut::with_capacity(READ_CHUNK);
        loop {
            let (at, stop) = self.parse(&buf, &limits);
            self.lane.flush();
            self.lane.expire();
            self.ship(&mut buf, at).await;
            let need = match stop {
                Ok(Stop::More(need)) => need,
                Ok(Stop::Fence) => {
                    self.lane.fence().await;
                    self.unfenced = false;
                    self.pong();
                    self.lane.flush();
                    continue;
                }
                Err(close) => return close,
            };
            if let Some(sub) = self.stalled.take() {
                stall(&sub, stall_mark).await;
            }
            // Lets the writers just woken run before the next read, so output
            // leaves in step with input instead of in bursts.
            tokio::task::yield_now().await;
            if self.client.is_closed() {
                return Close::Kicked;
            }
            make_room(&mut buf, need);
            // Cancel-safe: a dropped read took no bytes, and a dropped
            // `notified` passes its wake on.
            tokio::select! {
                biased;
                () = self.client.stop.notified() => return Close::Kicked,
                n = r.read_buf(&mut buf) => match n {
                    Ok(0) | Err(_) => return Close::Lost,
                    Ok(_) => {}
                },
            }
        }
    }

    /// Acts on the operations at the start of `buf`. Returns the bytes they
    /// took and why it stopped.
    fn parse(&mut self, buf: &[u8], limits: &Limits) -> (usize, Result<Stop, Close>) {
        let mut at = 0;
        loop {
            match client::parse(&buf[at..], limits) {
                Ok(Parsed::Op(op, used)) => {
                    let step = self.handle(op, buf);
                    at += used;
                    match step {
                        Ok(Step::Next) => {}
                        Ok(Step::Fence) => return (at, Ok(Stop::Fence)),
                        Err(close) => return (at, Err(close)),
                    }
                }
                Ok(Parsed::Partial(need)) => return (at, Ok(Stop::More(need))),
                Err(e) => return (at, Err(Close::Parse(e))),
            }
        }
    }

    /// Drops the `at` bytes parsed from `buf`, handing those that publishes
    /// for other lanes refer to over to those lanes.
    async fn ship(&mut self, buf: &mut BytesMut, at: usize) {
        if self.fwd.iter().all(Out::is_empty) {
            buf.advance(at);
            return;
        }
        let chunk = buf.split_to(at).freeze();
        for to in 0..self.fwd.len() {
            if self.fwd[to].is_empty() {
                continue;
            }
            let out = std::mem::take(&mut self.fwd[to]);
            let batch = Batch {
                chunk: chunk.clone(),
                out,
            };
            self.lane.ship(to, batch).await;
        }
    }

    // Inlined into the parse loop; what is rare stays out of line, so it
    // remains small enough.
    #[inline]
    fn handle(&mut self, op: ClientOp<'_>, buf: &[u8]) -> Result<Step, Close> {
        match op {
            ClientOp::Pub(p) => {
                if p.headers.is_some() && !self.opts.headers {
                    return Err(Close::NoHeaders);
                }
                if self.opts.pedantic && !subject::is_valid_literal(p.subject) {
                    // Delivered all the same, as by `nats-server`.
                    self.error("Invalid Publish Subject");
                }
                self.ok();
                self.publish(&p, buf);
            }
            ClientOp::Sub(s) => self.subscribe(&s),
            ClientOp::Unsub(u) => {
                self.unsubscribe(&u);
                self.ok();
            }
            ClientOp::Ping if self.unfenced => return Ok(Step::Fence),
            ClientOp::Ping => self.pong(),
            ClientOp::Pong => {}
            ClientOp::Connect(json) => self.connect(json)?,
            _ => return Err(Close::Parse(ParseError::UnknownOp)),
        }
        Ok(Step::Next)
    }

    /// Encodes the message for every plain subscription on this lane and
    /// one member of each queue group here, and queues it once for each
    /// other lane with interest. `p` lies in `buf`.
    #[inline]
    fn publish(&mut self, p: &Pub<'_>, buf: &[u8]) {
        let index = self.lane.index.borrow();
        let Some(found) = index.matches(p.subject) else {
            self.nobody_got(&index, p);
            return;
        };
        let mut r = Routing {
            lane: &self.lane,
            fwd: &mut self.fwd,
            p,
            buf,
            skip: if self.opts.echo { 0 } else { self.client.id },
            stalled: None,
            delivered: false,
        };
        match &found {
            Found::One(i) => {
                r.plain(i, false);
                for (name, _) in &i.queues {
                    r.queue(&found, 0, name);
                }
            }
            Found::Many(all) => r.many(&found, all),
        }
        if let Some(s) = r.stalled {
            self.stalled = Some(s);
        }
        if !r.delivered {
            self.nobody_got(&index, p);
        }
    }

    /// Applies a `CONNECT`.
    #[inline(never)]
    fn connect(&mut self, json: &[u8]) -> Result<(), Close> {
        self.opts.apply(json).map_err(|_| Close::Connect)?;
        self.client.headers.set(self.opts.headers);
        self.connected = true;
        if !(0..=1).contains(&self.opts.protocol) {
            return Err(Close::Refused("invalid client protocol"));
        }
        if self.opts.no_responders && !self.opts.headers {
            return Err(Close::Refused("no responders requires headers support"));
        }
        self.ok();
        Ok(())
    }

    /// After a publish no subscription got: the status 503 to a requester
    /// that asked for it.
    #[cold]
    #[inline(never)]
    fn nobody_got(&self, index: &Index, p: &Pub<'_>) {
        if self.opts.no_responders
            && let Some(reply) = p.reply
            && no_responders(index, &self.client, reply, p.subject)
        {
            self.lane.mark(&self.client);
        }
    }

    #[inline(never)]
    fn subscribe(&mut self, s: &Sub<'_>) {
        if self.client.subs.borrow().contains_key(s.sid) {
            return self.ok();
        }
        if !subject::is_valid_filter(s.subject) {
            return self.error("Invalid Subject");
        }
        let sub = super::Sub {
            subject: s.subject.into(),
            queue: s.queue.map(Into::into),
        };
        self.client.subs.borrow_mut().insert(s.sid.into(), sub);
        let entry = Entry::new(self.client.clone(), s.sid);
        self.lane
            .index
            .borrow_mut()
            .insert(s.subject, s.queue, entry);
        self.lane.announce(s.subject, s.queue, true);
        self.unfenced = self.lane.lanes() > 1;
        self.ok();
    }

    /// Ends a subscription, now or after its maximum of messages.
    #[inline(never)]
    fn unsubscribe(&mut self, u: &Unsub<'_>) {
        let max = u.max.unwrap_or(0) as u64;
        if max > 0 {
            let subs = self.client.subs.borrow();
            let Some(sub) = subs.get(u.sid) else {
                return;
            };
            let index = self.lane.index.borrow();
            let queue = sub.queue.as_deref();
            if let Some(e) = index.find(&sub.subject, queue, self.client.id, u.sid)
                && max > e.delivered.get()
            {
                e.max.set(max);
                return;
            }
        }
        self.client.unsubscribe(&self.lane, u.sid);
    }
}

/// Tells `client` that no one got its request on `subject`: a status 503
/// to its own subscription on `reply`, if it has one. Returns whether it
/// had one.
fn no_responders(index: &Index, client: &Client, reply: &[u8], subject: &[u8]) -> bool {
    let own = |i: &Interest| {
        i.plain
            .local
            .iter()
            .find(|e| e.client.id == client.id)
            .map(|e| e.sid.clone())
    };
    let sid = match index.matches(reply) {
        Some(Found::One(i)) => own(i),
        Some(Found::Many(all)) => all.iter().find_map(own),
        None => None,
    };
    let Some(sid) = sid else {
        return false;
    };
    encode::no_responders(&mut *client.out.borrow_mut(), reply, &sid, subject);
    true
}

/// A publish being routed on its lane.
struct Routing<'a, 'p> {
    lane: &'a Lane,
    /// Publishes for each other lane.
    fwd: &'a mut [Out],
    p: &'a Pub<'p>,
    /// The read buffer `p` lies in.
    buf: &'a [u8],
    /// The publisher's client ID without echo, else 0.
    skip: u64,
    /// A subscriber past the stall mark.
    stalled: Option<Rc<Client>>,
    /// Some subscription got it, here or on another lane.
    delivered: bool,
}

impl Routing<'_, '_> {
    /// Delivers to the plain subscriptions of `i` here, and forwards to
    /// each other lane with some; with `once`, unless forwarded there for
    /// another filter already.
    #[expect(
        clippy::inline_always,
        reason = "measured: a call here costs every publish"
    )]
    #[inline(always)]
    fn plain(&mut self, i: &Interest, once: bool) {
        self.delivered |= self
            .lane
            .deliver(&i.plain.local, self.p, self.skip, &mut self.stalled);
        for &(to, _) in &i.plain.lanes {
            self.fwd[to].plain(self.buf, self.p, once);
            self.delivered = true;
        }
    }

    /// Routes to the filters in `all`, wildcard ones among them: each
    /// plain subscription once, each queue group once across filters.
    #[inline(never)]
    fn many(&mut self, found: &Found<'_>, all: &Few<'_, Interest>) {
        for i in all.iter() {
            self.plain(i, true);
        }
        for (k, i) in all.iter().enumerate() {
            for (name, _) in &i.queues {
                if !merged_before(all, k, name) {
                    self.queue(found, k, name);
                }
            }
        }
    }

    /// Delivers to one member of queue group `name`, from the `k`th match
    /// on, here or on the lane of the member picked.
    fn queue(&mut self, found: &Found<'_>, k: usize, name: &[u8]) {
        let groups = found.queue_groups(k, name);
        match self
            .lane
            .deliver_queue(&groups, self.p, self.skip, &mut self.stalled)
        {
            Queued::Here => self.delivered = true,
            Queued::Lane(to) => {
                self.fwd[to].queue(self.buf, self.p, name);
                self.delivered = true;
            }
            Queued::Nowhere => {}
        }
    }
}

/// Whether queue group `name` of `found[k]` was in an earlier match, and
/// so got its pick already.
fn merged_before(found: &Few<'_, Interest>, k: usize, name: &[u8]) -> bool {
    found
        .iter()
        .take(k)
        .any(|i| i.queues.iter().any(|(n, _)| **n == *name))
}

/// Gives `buf`, which holds at most the start of one operation, room for
/// the next read: [`READ_ROOM`] at least, the rest of an operation of
/// `need` bytes. Takes back the space parsed already where it can, so a
/// busy connection reuses one buffer.
fn make_room(buf: &mut BytesMut, need: Option<usize>) {
    let room = need.map_or(READ_ROOM, |n| n.saturating_sub(buf.len()).max(READ_ROOM));
    if buf.capacity() - buf.len() < room {
        // Asks for no more than a buffer of READ_CHUNK holds besides what is
        // left, so a buffer of that size takes its parsed space back.
        buf.reserve(room.max(READ_CHUNK - buf.len().min(READ_CHUNK)));
    }
}

/// Waits up to [`STALL_MAX`] while `sub` has more than `mark` bytes queued,
/// so its publisher slows to its pace.
pub(crate) async fn stall(sub: &Rc<Client>, mark: usize) {
    let drained = sub.drained.notified();
    tokio::pin!(drained);
    // Registered before the check, so a drain after it is not missed.
    drained.as_mut().enable();
    if sub.is_closed() || sub.out.borrow().len() <= mark {
        return;
    }
    let _ = tokio::time::timeout(STALL_MAX, drained).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_busy_connection_reuses_its_read_buffer() {
        let mut buf = BytesMut::with_capacity(READ_CHUNK);
        for partial in [0, 5, 1000] {
            buf.resize(READ_CHUNK, b'x');
            buf.advance(READ_CHUNK - partial);
            make_room(&mut buf, None);
            assert_eq!(buf.len(), partial);
            assert!(buf.capacity() >= READ_ROOM);
            assert!(buf.capacity() <= READ_CHUNK, "grew: {}", buf.capacity());
        }
    }

    #[test]
    fn a_large_operation_gets_room_for_all_of_it() {
        let mut buf = BytesMut::with_capacity(READ_CHUNK);
        buf.extend_from_slice(b"PUB a 1000000");
        make_room(&mut buf, Some(1_000_020));
        assert!(buf.capacity() >= 1_000_020);
    }
}
