//! The read loop: parses what a client sends and acts on it.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use bytes::BytesMut;
use naq_proto::client::{self, ClientOp, Limits, ParseError, Parsed, Pub, Sub, Unsub};
use naq_proto::{encode, subject};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;

use super::login::Later;
use super::ping::Tick;
use super::{Client, Close, Conn};
use crate::index::{Entry, Found, Index, Interest};
use crate::lane::Routing;
use crate::perms::quoted;

/// Bytes a read may fill at least. With less room, the buffer takes back
/// what was parsed already, or the read goes on in a buffer of
/// [`READ_CHUNK`].
const READ_ROOM: usize = 16 << 10;
pub(crate) const READ_CHUNK: usize = 256 << 10;
/// Spent read buffers a lane keeps; beyond these, the oldest is let go.
const SPENT_MAX: usize = 8;

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
    /// After a `CONNECT` whose login finishes off the parse loop.
    Login(Box<Later>),
}

/// What to do after an operation.
pub(super) enum Step {
    Next,
    Fence,
    Login(Box<Later>),
}

impl Conn {
    pub(super) async fn read_loop<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> Close {
        let stall_mark = self.lane.shared.opts.max_pending / 4 * 3;
        let mut buf = self.lane.reads.take(READ_CHUNK);
        let timer = tokio::time::sleep_until(self.ping.next);
        tokio::pin!(timer);
        loop {
            let limits = self.bounds.limits;
            let (at, stop) = self.parse(&buf, &limits);
            self.note_busy();
            self.lane.flush();
            self.lane.expire();
            self.ship(&mut buf, at).await;
            let need = match self.on_stop(stop).await {
                Ok(Some(need)) => need,
                Ok(None) => continue,
                Err(close) => return close,
            };
            if let Some(sub) = self.stalled.take()
                && stall(&sub, stall_mark, &self.lane.shared.events.stalls).await
            {
                let stalls = &self.client.seen.stalls;
                stalls.set(stalls.get() + 1);
            }
            // Lets the writers just woken run before the next read, so output
            // leaves in step with input instead of in bursts.
            tokio::task::yield_now().await;
            if self.client.is_closed() {
                return Close::Kicked;
            }
            make_room(&mut buf, need, &self.lane.reads);
            let due = [self.auth_by, self.bounds.deadline.map(|(t, _)| t)]
                .into_iter()
                .flatten()
                .fold(self.ping.next, Instant::min);
            if timer.deadline() != due {
                timer.as_mut().reset(due);
            }
            // Cancel-safe: a dropped read took no bytes, a dropped `notified`
            // passes its wake on, and the timer keeps its deadline.
            tokio::select! {
                biased;
                () = self.client.stop.notified() => if let Some(close) = self.woken() {
                    return close;
                },
                () = &mut timer => {
                    if let Some(close) = self.timer_fired() {
                        return close;
                    }
                }
                n = r.read_buf(&mut buf) => match n {
                    Ok(0) | Err(_) => return Close::Lost,
                    Ok(_) => {}
                },
            }
        }
    }

    /// Acts on a wake by the server: a close, an `INFO` to send, or a
    /// change of its account.
    fn woken(&mut self) -> Option<Close> {
        if self.client.is_closed() {
            return Some(Close::Kicked);
        }
        if let Some(ldm) = self.client.take_info() {
            self.inform(ldm);
        }
        if self.client.take_refresh() {
            return self.refresh().err();
        }
        None
    }

    /// Notes that the client was active, if the read just parsed held
    /// messages, subscriptions or a `PING`.
    fn note_busy(&mut self) {
        if std::mem::take(&mut self.busy) {
            let now = Instant::now();
            self.ping.active(now);
            self.client.seen.last.set(now.into_std());
        }
    }

    /// Acts on why parsing stopped: `Some` is reading on, for an operation of
    /// that many bytes if known; `None` is parsing again first.
    async fn on_stop(&mut self, stop: Result<Stop, Close>) -> Result<Option<Option<usize>>, Close> {
        match stop? {
            Stop::More(need) => return Ok(Some(need)),
            Stop::Fence => {
                self.lane.fence().await;
                self.unfenced = false;
                self.pong();
            }
            Stop::Login(l) => {
                let login = self.later(*l).await;
                self.refused(login)?;
            }
        }
        self.lane.flush();
        Ok(None)
    }

    /// The timer fired: the end of the time to authenticate or of the
    /// user's JWT, or a `PING`.
    fn timer_fired(&mut self) -> Option<Close> {
        let now = Instant::now();
        if self.auth_by.is_some_and(|t| t <= now) {
            return Some(Close::AuthTimeout);
        }
        if let Some((t, why)) = self.bounds.deadline
            && t <= now
        {
            return Some(why);
        }
        self.ping_tick()
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
                        Ok(Step::Login(l)) => return (at, Ok(Stop::Login(l))),
                        Err(close) => return (at, Err(close)),
                    }
                }
                Ok(Parsed::Partial(need)) => return (at, Ok(Stop::More(need))),
                Err(e) => {
                    self.log_parse(&e, &buf[at..]);
                    return (at, Err(Close::Parse(e)));
                }
            }
        }
    }

    /// Drops the `at` bytes parsed from `buf`, handing those that publishes
    /// for other lanes refer to over to those lanes.
    async fn ship(&mut self, buf: &mut BytesMut, at: usize) {
        self.lane
            .ship_reads(&mut self.out, buf, at, crate::lane::Source::Client)
            .await;
    }

    // Inlined into the parse loop; what is rare stays out of line, so it
    // remains small enough.
    #[inline]
    fn handle(&mut self, op: ClientOp<'_>, buf: &[u8]) -> Result<Step, Close> {
        if self.watch.on {
            self.watched(&op)?;
        }
        match op {
            ClientOp::Pub(p) => {
                if p.headers.is_some() && !self.opts.headers {
                    return Err(Close::NoHeaders);
                }
                if self.opts.pedantic && !subject::is_valid_literal(p.subject) {
                    // Delivered all the same, as by `nats-server`.
                    self.error("Invalid Publish Subject");
                }
                let size = p.payload.len() + p.headers.map_or(0, <[u8]>::len);
                self.lane.tally.took(size);
                self.client.tally.took(size);
                if (self.client.guarded.get() || reserved(&p)) && !self.may_send(&p) {
                    return Ok(Step::Next);
                }
                self.ok();
                self.busy = true;
                self.publish(&p, buf);
            }
            ClientOp::Sub(s) => {
                self.busy = true;
                self.subscribe(&s);
            }
            ClientOp::Unsub(u) => {
                self.unsubscribe(&u);
                self.ok();
            }
            ClientOp::Ping if self.unfenced => {
                self.busy = true;
                return Ok(Step::Fence);
            }
            ClientOp::Ping => {
                self.busy = true;
                self.pong();
            }
            ClientOp::Pong => {
                if let Some(rtt) = self.ping.pong(Instant::now()) {
                    self.client.rtt.set(rtt);
                }
            }
            ClientOp::Connect(json) => return self.connect(json),
            _ => return Err(Close::Parse(ParseError::UnknownOp)),
        }
        Ok(Step::Next)
    }

    /// Encodes the message for every plain subscription on this lane and
    /// one member of each queue group here, queues it once for each other
    /// lane with interest, and hands it to links. `p` lies in `buf`.
    #[inline]
    fn publish(&mut self, p: &Pub<'_>, buf: &[u8]) {
        let index = self.lane.index(self.client.account.get()).borrow();
        let Some(found) = index.matches(p.subject) else {
            self.nobody_got(&index, p);
            return;
        };
        let skip = if self.opts.echo { 0 } else { self.client.id };
        let mut r = Routing::new(&self.lane, &mut self.out, p, buf, skip).with_imports();
        r.route(&found);
        let (mut delivered, tapped) = (r.delivered, r.tapped());
        if let Some(s) = r.stalled {
            self.stalled = Some(s);
        }
        if tapped {
            let (got, stalled) = import(&self.lane, &mut self.out, &self.client, skip, p);
            delivered |= got;
            if stalled.is_some() {
                self.stalled = stalled;
            }
        }
        if !delivered {
            self.nobody_got(&index, p);
        }
    }

    /// What a watched client sends goes by here first: it is traced, and
    /// until it authenticates, it may send nothing but a `CONNECT`.
    #[cold]
    #[inline(never)]
    fn watched(&mut self, op: &ClientOp<'_>) -> Result<(), Close> {
        if self.watch.tracing {
            self.trace_in(op);
        }
        if self.auth_by.is_some() && !matches!(op, ClientOp::Connect(_)) {
            self.without_connect()?;
        }
        Ok(())
    }

    /// The ping timer fired: maybe a `PING`, maybe the end.
    #[inline(never)]
    fn ping_tick(&mut self) -> Option<Close> {
        let opts = &self.lane.shared.opts;
        match self
            .ping
            .tick(Instant::now(), self.ping.interval, opts.max_pings_out)
        {
            Tick::Quiet => None,
            Tick::Ping => {
                if self.watch.tracing {
                    self.trace_out("PING", None);
                }
                self.reply(encode::PING);
                self.lane.flush();
                None
            }
            Tick::Stale => {
                self.lane.shared.events.stale_clients.note();
                Some(Close::Stale)
            }
        }
    }

    /// Whether it may send `p`, as `nats-server` checks a client's
    /// publish: not to a subject a gateway reserves, as its permissions
    /// say, not to `$NRG.`, and not with a reply imports and JetStream
    /// reserve. If not, it is told.
    #[cold]
    #[inline(never)]
    fn may_send(&self, p: &Pub<'_>) -> bool {
        // A traced client is guarded: its payload is traced here.
        if self.watch.tracing {
            self.trace_payload_in(p);
        }
        let subject = p.subject;
        if subject.starts_with(b"_GR_.") && subject.len() > 5
            || subject.starts_with(b"$GR.") && subject.len() > 4
        {
            self.refuse_publish(subject);
            return false;
        }
        if self.client.guarded.get() && !self.may_publish(subject) {
            return false;
        }
        if subject.starts_with(b"$NRG.") {
            self.refuse_publish(subject);
            return false;
        }
        if let Some(reply) = p.reply.filter(|r| is_reserved_reply(r)) {
            self.log_violation(format_args!(
                "Publish Violation - Reply {:?}",
                String::from_utf8_lossy(reply)
            ));
            self.error(&format!(
                "Permissions Violation for Publish with Reply of {}",
                quoted(reply)
            ));
            return false;
        }
        true
    }

    /// Whether its permissions let it publish to `subject`; if not, it is
    /// told.
    #[cold]
    #[inline(never)]
    fn may_publish(&self, subject: &[u8]) -> bool {
        let held = self.client.held.borrow().clone();
        if held.is_none_or(|h| h.may_publish(subject)) {
            return true;
        }
        self.refuse_publish(subject);
        false
    }

    /// Tells it and the log it may not publish to `subject`.
    #[cold]
    fn refuse_publish(&self, subject: &[u8]) {
        self.log_violation(format_args!(
            "Publish Violation - Subject {:?}",
            String::from_utf8_lossy(subject)
        ));
        self.error(&publish_violation(subject));
    }

    /// Whether its permissions let it subscribe as `s` asks; if not, it is
    /// told.
    #[cold]
    #[inline(never)]
    fn may_subscribe(&self, s: &Sub<'_>) -> bool {
        let held = self.client.held.borrow().clone();
        if held.is_none_or(|h| h.perms.subscribe(s.subject, s.queue)) {
            return true;
        }
        let (subject, sid) = (
            String::from_utf8_lossy(s.subject),
            String::from_utf8_lossy(s.sid),
        );
        match s.queue {
            Some(q) => self.log_violation(format_args!(
                "Subscription Violation - Subject {subject:?}, Queue: {:?}, SID {sid}",
                String::from_utf8_lossy(q)
            )),
            None => self.log_violation(format_args!(
                "Subscription Violation - Subject {subject:?}, SID {sid}"
            )),
        }
        let text = match s.queue {
            Some(q) => format!(
                "Permissions Violation for Subscription to {} using queue {}",
                quoted(s.subject),
                quoted(q)
            ),
            None => format!(
                "Permissions Violation for Subscription to {}",
                quoted(s.subject)
            ),
        };
        self.error(&text);
        false
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
        if self.client.guarded.get() && !self.may_subscribe(s) {
            return;
        }
        if self.client.subs.borrow().contains_key(s.sid) {
            return self.ok();
        }
        let subs = self.client.subs.borrow().len();
        if usize::try_from(self.bounds.subs).is_ok_and(|max| subs >= max) {
            return self.error("maximum subscriptions exceeded");
        }
        if !subject::is_valid_filter(s.subject) {
            return self.error("Invalid Subject");
        }
        let entry = Entry::new(self.client.clone(), s.sid);
        let account = self.client.account.get();
        self.lane
            .index(account)
            .borrow_mut()
            .insert(s.subject, s.queue, entry);
        self.lane.announce(account, s.subject, s.queue, true);
        self.lane.changed(account, s.subject, s.queue);
        let shadows =
            crate::imports::shadow::add(&self.lane, &self.client, s.sid, s.subject, s.queue);
        let sub = super::Sub {
            subject: s.subject.into(),
            queue: s.queue.map(Into::into),
            shadows,
        };
        self.client.subs.borrow_mut().insert(s.sid.into(), sub);
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
            let index = self.lane.index(self.client.account.get()).borrow();
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

/// Sends `p`, published by `client` on `lane`, through the imports it met,
/// to all but client `skip`, with `out` for what goes on. Returns whether
/// they got it to anyone, and a subscriber past the stall mark.
#[cold]
#[inline(never)]
fn import(
    lane: &crate::lane::Lane,
    out: &mut crate::lane::Outs,
    client: &Client,
    skip: u64,
    p: &Pub<'_>,
) -> (bool, Option<Rc<Client>>) {
    let from = crate::imports::service::From {
        client: Some(client),
        skip,
        source: crate::lane::Source::Client,
        skips: 0,
    };
    crate::imports::service::run(lane, out, p, client.account.get(), from)
}

/// Whether a client publish may hit a reserved subject or reply: they
/// all start with `_` or `$`.
#[inline]
fn reserved(p: &Pub<'_>) -> bool {
    let odd = |s: &[u8]| matches!(s.first(), Some(b'_' | b'$'));
    odd(p.subject) || p.reply.is_some_and(odd)
}

/// Whether `reply` is one service imports, JetStream acks or gateways
/// reserve, as `nats-server` keeps them from clients.
fn is_reserved_reply(reply: &[u8]) -> bool {
    let past = |prefix: &[u8]| reply.len() > prefix.len() && reply.starts_with(prefix);
    reply.len() > 3 && reply.starts_with(b"_R_.")
        || past(b"$JS.ACK.")
        || past(b"_GR_.")
        || past(b"$GR.")
}

/// The error for a publish to `subject` that is not allowed.
fn publish_violation(subject: &[u8]) -> String {
    format!("Permissions Violation for Publish to {}", quoted(subject))
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

/// Gives `buf`, which holds at most the start of one operation, room for
/// the next read: [`READ_ROOM`] at least, the rest of an operation of
/// `need` bytes. Takes back the space parsed already where nothing else
/// refers to it, so a busy connection reuses one buffer. Where batches on
/// other lanes still do, the read goes on in a buffer from `spent`.
pub(crate) fn make_room(buf: &mut BytesMut, need: Option<usize>, spent: &SpentReads) {
    let room = need.map_or(READ_ROOM, |n| n.saturating_sub(buf.len()).max(READ_ROOM));
    if buf.capacity() - buf.len() >= room {
        return;
    }
    // No more than a buffer of READ_CHUNK holds besides what is left, so a
    // buffer of that size takes its parsed space back.
    let want = room.max(READ_CHUNK - buf.len().min(READ_CHUNK));
    if buf.try_reclaim(want) {
        return;
    }
    let mut next = spent.take(buf.len() + want);
    next.extend_from_slice(buf);
    spent.retire(std::mem::replace(buf, next));
}

/// Read buffers a lane fills again once no batch refers to them, oldest
/// first. The lane does not allocate per buffer, and a buffer is not freed
/// by the lane that drops its last batch.
#[derive(Debug, Default)]
pub(crate) struct SpentReads(RefCell<VecDeque<BytesMut>>);

impl SpentReads {
    /// A buffer with room for `len` bytes: a spent one nothing refers to
    /// any more, else a new one.
    pub(crate) fn take(&self, len: usize) -> BytesMut {
        let mut spent = self.0.borrow_mut();
        let free = spent.iter_mut().position(|b| b.try_reclaim(len));
        free.and_then(|i| spent.remove(i))
            .unwrap_or_else(|| BytesMut::with_capacity(len))
    }

    /// Keeps `buf`, which batches on other lanes may still refer to.
    pub(crate) fn retire(&self, mut buf: BytesMut) {
        buf.clear();
        let mut spent = self.0.borrow_mut();
        if spent.len() == SPENT_MAX {
            spent.pop_front();
        }
        spent.push_back(buf);
    }
}

/// Waits up to [`STALL_MAX`] while `sub` has more than `mark` bytes queued,
/// so its publisher slows to its pace, and counts the wait in `stalls`.
/// Tells whether it waited.
pub(crate) async fn stall(sub: &Rc<Client>, mark: usize, stalls: &crate::stats::Counter) -> bool {
    let drained = sub.drained.notified();
    tokio::pin!(drained);
    // Registered before the check, so a drain after it is not missed.
    drained.as_mut().enable();
    if sub.is_closed() || sub.out.borrow().len() <= mark {
        return false;
    }
    stalls.note();
    let _ = tokio::time::timeout(STALL_MAX, drained).await;
    true
}

#[cfg(test)]
mod tests {
    use bytes::Buf;

    use super::*;

    #[test]
    fn a_busy_connection_reuses_its_read_buffer() {
        let spent = SpentReads::default();
        let mut buf = BytesMut::with_capacity(READ_CHUNK);
        let start = buf.as_ptr();
        for partial in [0, 5, 1000] {
            buf.resize(READ_CHUNK, b'x');
            buf.advance(READ_CHUNK - partial);
            make_room(&mut buf, None, &spent);
            assert_eq!(buf.len(), partial);
            assert_eq!(buf.as_ptr(), start);
            assert!(buf.capacity() >= READ_ROOM);
            assert!(buf.capacity() <= READ_CHUNK, "grew: {}", buf.capacity());
        }
    }

    #[test]
    fn a_large_operation_gets_room_for_all_of_it() {
        let mut buf = BytesMut::with_capacity(READ_CHUNK);
        buf.extend_from_slice(b"PUB a 1000000");
        make_room(&mut buf, Some(1_000_020), &SpentReads::default());
        assert!(buf.capacity() >= 1_000_020);
    }

    #[test]
    fn a_read_buffer_is_filled_again_once_no_batch_refers_to_it() {
        let spent = SpentReads::default();
        let mut buf = spent.take(READ_CHUNK);
        let first = buf.as_ptr();
        buf.resize(READ_CHUNK, b'x');
        // A batch for another lane holds what was parsed; a partial
        // operation of 7 bytes is left.
        let batch = buf.split_to(READ_CHUNK - 7).freeze();
        make_room(&mut buf, None, &spent);
        assert_eq!(&buf[..], b"xxxxxxx");
        assert!(buf.capacity() >= READ_CHUNK - 7);
        drop(batch);
        buf.resize(READ_CHUNK, b'y');
        let held = buf.split_to(READ_CHUNK - 3).freeze();
        make_room(&mut buf, None, &spent);
        assert_eq!((&buf[..], buf.as_ptr()), (&b"yyy"[..], first));
        assert!(buf.capacity() >= READ_CHUNK - 3);
        drop(held);
    }

    #[test]
    fn a_lane_keeps_few_spent_read_buffers() {
        let spent = SpentReads::default();
        let held: Vec<_> = (0..SPENT_MAX + 3)
            .map(|_| {
                let mut b = BytesMut::with_capacity(64);
                b.resize(64, 0);
                let h = b.split_to(60).freeze();
                spent.retire(b);
                h
            })
            .collect();
        assert_eq!(spent.0.borrow().len(), SPENT_MAX);
        // All still referred to: a new buffer.
        assert!(spent.take(64).capacity() >= 64);
        assert_eq!(spent.0.borrow().len(), SPENT_MAX);
        drop(held);
        assert!(spent.take(64).capacity() >= 64);
        assert_eq!(spent.0.borrow().len(), SPENT_MAX - 1);
    }
}
