//! The read loop: parses what a client sends and acts on it.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use naq_proto::client::{self, ClientOp, Limits, ParseError, Parsed, Pub, Sub, Unsub};
use naq_proto::{encode, subject};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;

use super::ping::Tick;
use super::{Client, Close, Conn, Stage};
use crate::auth::{Check, Creds, Grant, Pending};
use crate::index::{Entry, Few, Found, Index, Interest, Peer};
use crate::lane::{Batch, Lane, Out, Queue, Queued};
use crate::perms::{Held, quoted};

/// Bytes a read may fill at least. With less room, the buffer takes back
/// what was parsed already, or the read goes on in a buffer of
/// [`READ_CHUNK`].
const READ_ROOM: usize = 16 << 10;
const READ_CHUNK: usize = 256 << 10;
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
    /// After a `CONNECT` whose password must be compared off the lane.
    Verify(Box<Pending>),
}

/// What to do after an operation.
enum Step {
    Next,
    Fence,
    Verify(Box<Pending>),
}

impl Conn {
    pub(super) async fn read_loop<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> Close {
        let opts = &self.lane.shared.opts;
        let limits = Limits {
            max_control_line: opts.max_control_line,
            max_payload: opts.max_payload,
        };
        let stall_mark = opts.max_pending / 4 * 3;
        let mut buf = self.lane.reads.take(READ_CHUNK);
        let timer = tokio::time::sleep_until(self.ping.next);
        tokio::pin!(timer);
        loop {
            let (at, stop) = self.parse(&buf, &limits);
            if std::mem::take(&mut self.busy) {
                self.ping.active(Instant::now());
            }
            self.lane.flush();
            self.lane.expire();
            self.ship(&mut buf, at).await;
            let need = match self.on_stop(stop).await {
                Ok(Some(need)) => need,
                Ok(None) => continue,
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
            make_room(&mut buf, need, &self.lane.reads);
            let due = self
                .auth_by
                .map_or(self.ping.next, |t| t.min(self.ping.next));
            if timer.deadline() != due {
                timer.as_mut().reset(due);
            }
            // Cancel-safe: a dropped read took no bytes, a dropped `notified`
            // passes its wake on, and the timer keeps its deadline.
            tokio::select! {
                biased;
                () = self.client.stop.notified() => return Close::Kicked,
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
            Stop::Verify(p) => self.verify(*p).await?,
        }
        self.lane.flush();
        Ok(None)
    }

    /// The timer fired: the end of the time to authenticate, or a `PING`.
    fn timer_fired(&mut self) -> Option<Close> {
        if self.auth_by.is_some_and(|t| t <= Instant::now()) {
            return Some(Close::AuthTimeout);
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
                        Ok(Step::Verify(p)) => return (at, Ok(Stop::Verify(p))),
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
            let out = self.fwd[to].take();
            let batch = Batch {
                chunk: chunk.clone(),
                out,
                account: self.client.account.get(),
            };
            self.lane.ship(to, batch).await;
        }
    }

    // Inlined into the parse loop; what is rare stays out of line, so it
    // remains small enough.
    #[inline]
    fn handle(&mut self, op: ClientOp<'_>, buf: &[u8]) -> Result<Step, Close> {
        if self.auth_by.is_some() && !matches!(op, ClientOp::Connect(_)) {
            self.without_connect()?;
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
                if self.client.guarded.get() && !self.may_publish(p.subject) {
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
            ClientOp::Pong => self.ping.pong(),
            ClientOp::Connect(json) => return self.connect(json),
            _ => return Err(Close::Parse(ParseError::UnknownOp)),
        }
        Ok(Step::Next)
    }

    /// Encodes the message for every plain subscription on this lane and
    /// one member of each queue group here, and queues it once for each
    /// other lane with interest. `p` lies in `buf`.
    #[inline]
    fn publish(&mut self, p: &Pub<'_>, buf: &[u8]) {
        let index = self.lane.index(self.client.account.get()).borrow();
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
        if self.lane.has_hits() {
            self.lane.send_hits(p, &mut r.stalled);
        }
        if let Some(s) = r.stalled {
            self.stalled = Some(s);
        }
        if !r.delivered {
            self.nobody_got(&index, p);
        }
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
                self.reply(encode::PING);
                self.lane.flush();
                None
            }
            Tick::Stale => {
                crate::stats::Events::note(&self.lane.shared.events.stale);
                Some(Close::Stale)
            }
        }
    }

    /// Applies a `CONNECT`.
    #[inline(never)]
    fn connect(&mut self, json: &[u8]) -> Result<Step, Close> {
        let (mut creds, names) = self.opts.apply(json).map_err(|_| Close::Connect)?;
        if let Some(cookies) = &self.via.cookies {
            creds.fill(cookies);
        }
        {
            let mut meta = self.client.meta.borrow_mut();
            (meta.name, meta.lang, meta.version) = names;
        }
        self.client.headers.set(self.opts.headers);
        if let Some(auth) = self.lane.shared.auth_for(self.via.ws) {
            let nonce = self.nonce.as_deref().unwrap_or_default();
            match auth.check(&creds, nonce.as_bytes()) {
                Check::Pass(account) => self.bind(account),
                Check::Fail => return Err(Close::Auth),
                Check::Bcrypt(p) => return Ok(Step::Verify(Box::new(p))),
            }
        }
        self.connected()?;
        Ok(Step::Next)
    }

    /// An operation before any `CONNECT`: the client is the `no_auth_user`,
    /// if there is one; else it is refused.
    #[cold]
    #[inline(never)]
    fn without_connect(&mut self) -> Result<(), Close> {
        let auth = self.lane.shared.auth_for(self.via.ws);
        match auth.map(|a| a.check(&Creds::default(), b"")) {
            Some(Check::Pass(account)) => {
                self.bind(account);
                Ok(())
            }
            _ => Err(Close::Auth),
        }
    }

    /// Compares a password with its bcrypt hash off the lane, then finishes
    /// the `CONNECT`.
    async fn verify(&mut self, p: Pending) -> Result<(), Close> {
        let grant = p.grant.clone();
        let holds = tokio::task::spawn_blocking(move || p.holds()).await;
        if !matches!(holds, Ok(true)) {
            return Err(Close::Auth);
        }
        self.bind(grant);
        self.connected()
    }

    /// Puts the client into `account`. Subscriptions in another it had are
    /// dropped, as a new `CONNECT` drops them in `nats-server`.
    fn bind(&mut self, grant: Grant) {
        self.auth_by = None;
        let held = grant.perms.map(|p| Rc::new(Held::new(p)));
        self.client.guarded.set(held.is_some());
        *self.client.held.borrow_mut() = held;
        if self.client.account.get() == grant.account {
            return;
        }
        let sids: Vec<_> = self.client.subs.borrow().keys().cloned().collect();
        for sid in sids {
            self.client.unsubscribe(&self.lane, &sid);
        }
        self.client.account.set(grant.account);
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
        self.error(&format!(
            "Permissions Violation for Publish to {}",
            quoted(subject)
        ));
        false
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

    /// The rest of a `CONNECT`, from a client that is who it says.
    fn connected(&mut self) -> Result<(), Close> {
        if self.stage == Stage::Fresh {
            self.stage = Stage::Connected;
        }
        let interval = self.ping.interval;
        let jitter = super::ping::jitter(interval, |n| self.lane.below(n));
        self.ping.connected(Instant::now(), interval, jitter);
        if !(0..=1).contains(&self.opts.protocol) {
            return Err(Close::Refused(super::BAD_PROTOCOL));
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
        if self.client.guarded.get() && !self.may_subscribe(s) {
            return;
        }
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
        let account = self.client.account.get();
        self.lane
            .index(account)
            .borrow_mut()
            .insert(s.subject, s.queue, entry);
        self.lane.announce(account, s.subject, s.queue, true);
        self.lane.changed(account, s.subject, s.queue);
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
        if !i.plain.peers.is_empty() {
            self.peers(&i.plain.peers);
        }
    }

    /// Hands the message to links with plain interest: here, or forwarded
    /// to their lanes.
    #[inline(never)]
    fn peers(&mut self, peers: &[Peer]) {
        for p in peers {
            if p.lane == self.lane.id {
                self.lane.hit_link(p.link, None);
            } else {
                self.fwd[p.lane].plain(self.buf, self.p, true);
            }
        }
        self.delivered = true;
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
        let q = Queue {
            name,
            groups: found.queue_groups(k, name),
        };
        match self
            .lane
            .deliver_queue(&q, self.p, self.skip, &mut self.stalled)
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
/// `need` bytes. Takes back the space parsed already where nothing else
/// refers to it, so a busy connection reuses one buffer. Where batches on
/// other lanes still do, the read goes on in a buffer from `spent`.
fn make_room(buf: &mut BytesMut, need: Option<usize>, spent: &SpentReads) {
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
    fn take(&self, len: usize) -> BytesMut {
        let mut spent = self.0.borrow_mut();
        let free = spent.iter_mut().position(|b| b.try_reclaim(len));
        free.and_then(|i| spent.remove(i))
            .unwrap_or_else(|| BytesMut::with_capacity(len))
    }

    /// Keeps `buf`, which batches on other lanes may still refer to.
    fn retire(&self, mut buf: BytesMut) {
        buf.clear();
        let mut spent = self.0.borrow_mut();
        if spent.len() == SPENT_MAX {
            spent.pop_front();
        }
        spent.push_back(buf);
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
