//! The read loop: parses what a client sends and acts on it.

use std::rc::Rc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use naq_proto::client::{self, ClientOp, Limits, ParseError, Parsed, Pub, Sub, Unsub};
use naq_proto::encode::{self, Msg};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{Client, Close, Conn};
use crate::index::Entry;

/// Bytes a read may fill at least. With less room, the buffer grows by
/// [`READ_CHUNK`] or takes back what was parsed already.
const READ_ROOM: usize = 16 << 10;
const READ_CHUNK: usize = 256 << 10;

/// Longest a publisher waits at a time for a subscriber past the stall
/// mark, as in `nats-server`.
const STALL_MAX: Duration = Duration::from_millis(5);

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
            let mut at = 0;
            let parsed = loop {
                match client::parse(&buf[at..], &limits) {
                    Ok(Parsed::Op(op, used)) => {
                        if let Err(close) = self.handle(op) {
                            break Err(close);
                        }
                        at += used;
                    }
                    Ok(Parsed::Partial(need)) => break Ok(need),
                    Err(e) => break Err(Close::Parse(e)),
                }
            };
            buf.advance(at);
            self.lane.flush();
            let need = match parsed {
                Ok(need) => need,
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

    fn handle(&mut self, op: ClientOp<'_>) -> Result<(), Close> {
        match op {
            ClientOp::Pub(p) => self.publish(&p),
            ClientOp::Sub(s) => self.subscribe(&s),
            ClientOp::Unsub(u) => self.unsubscribe(&u),
            ClientOp::Ping => {
                self.reply(encode::PONG);
                return Ok(());
            }
            ClientOp::Pong => return Ok(()),
            ClientOp::Connect(json) => {
                self.opts.apply(json).map_err(|_| Close::Connect)?;
                self.client.headers.set(self.opts.headers);
            }
            _ => return Err(Close::Parse(ParseError::UnknownOp)),
        }
        if self.opts.verbose {
            self.reply(encode::OK);
        }
        Ok(())
    }

    /// Encodes the message for every subscription it reaches.
    #[inline]
    fn publish(&mut self, p: &Pub<'_>) {
        let lane = &*self.lane;
        let opts = &lane.shared.opts;
        let stall_at = opts.max_pending / 4 * 3;
        let index = lane.index.borrow();
        for e in index.matches(p.subject) {
            let c = &e.client;
            if c.is_closed() || (!self.opts.echo && c.id == self.client.id) {
                continue;
            }
            let len = {
                let mut out = c.out.borrow_mut();
                Msg {
                    subject: p.subject,
                    sid: &e.sid,
                    reply: p.reply,
                    headers: p.headers.filter(|_| c.headers.get()),
                    payload: p.payload,
                }
                .encode(&mut *out);
                out.len()
            };
            lane.mark(c);
            if len > opts.max_pending {
                // A slow consumer.
                c.close();
            } else if len > stall_at {
                self.stalled = Some(c.clone());
            }
        }
    }

    fn subscribe(&mut self, s: &Sub<'_>) {
        if s.queue.is_some() {
            return self.error("Queue Groups Not Supported");
        }
        if s.subject
            .split(|&b| b == b'.')
            .any(|t| t == b"*" || t == b">")
        {
            return self.error("Wildcards Not Supported");
        }
        if self.subs.contains_key(s.sid) {
            return;
        }
        self.subs.insert(s.sid.into(), s.subject.into());
        let entry = Entry {
            client: self.client.clone(),
            sid: s.sid.into(),
        };
        self.lane.index.borrow_mut().insert(s.subject, entry);
    }

    fn unsubscribe(&mut self, u: &Unsub<'_>) {
        if u.max.is_some_and(|m| m > 0) {
            return self.error("UNSUB Maximum Not Supported");
        }
        if let Some(subject) = self.subs.remove(u.sid) {
            let id = self.client.id;
            self.lane.index.borrow_mut().remove(&subject, id, u.sid);
        }
    }
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
async fn stall(sub: &Rc<Client>, mark: usize) {
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
