//! Publishes forwarded from other lanes.

use std::rc::Rc;

use bytes::Bytes;
use naq_proto::client::Pub;

use super::Lane;
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
    /// The publisher's account.
    pub(crate) account: u32,
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
    /// Notes the links on this lane among `peers`.
    #[inline]
    fn peers_here(&self, peers: &[crate::index::Peer]) {
        for p in peers.iter().filter(|p| p.lane == self.id) {
            self.hit_link(p.link, None);
        }
    }

    /// Delivers forward `f` of batch `b` to the subscriptions on this lane.
    #[inline]
    fn deliver_fwd(&self, b: &Batch, f: &Fwd, stalled: &mut Option<Rc<crate::conn::Client>>) {
        let p = pub_of(b, f);
        let index = self.index(b.account).borrow();
        let Some(found) = index.matches(p.subject) else {
            return;
        };
        // The publisher is on another lane: nothing to skip.
        match (&found, f.queue.get_some(&b.out.names)) {
            (Found::One(i), None) => {
                self.deliver(&i.plain.local, &p, 0, stalled);
                self.peers_here(&i.plain.peers);
            }
            (Found::Many(all), None) => {
                for i in all.iter() {
                    self.deliver(&i.plain.local, &p, 0, stalled);
                    self.peers_here(&i.plain.peers);
                }
            }
            (_, Some(name)) => {
                let q = super::Queue {
                    name,
                    groups: found.queue_groups(0, name),
                };
                self.deliver_any(&q, &p, true, stalled);
            }
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
}
