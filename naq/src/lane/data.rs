//! Publishes forwarded from other lanes.

use std::rc::Rc;

use bytes::Bytes;
use naq_proto::client::Pub;

use super::Lane;
use crate::index::queue_groups;
use crate::mailbox::Receiver;

/// Offset and length in a batch's chunk, or in its queue names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span(u32, u32);

impl Span {
    /// Where `part` lies in `base`, which holds it.
    #[inline]
    fn of(base: &[u8], part: &[u8]) -> Span {
        let at = part.as_ptr() as usize - base.as_ptr() as usize;
        Span(at as u32, part.len() as u32)
    }

    #[inline]
    fn get(self, chunk: &[u8]) -> &[u8] {
        let (at, len) = (self.0 as usize, self.1 as usize);
        chunk.get(at..at + len).unwrap_or_default()
    }
}

/// One publish in a batch.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fwd {
    subject: Span,
    reply: Option<Span>,
    headers: Option<Span>,
    payload: Span,
    /// For one member of this queue group, in the batch's names; else for
    /// the plain subscriptions.
    queue: Option<Span>,
}

impl Fwd {
    /// `p`, which lies in `base`.
    #[inline]
    fn of(base: &[u8], p: &Pub<'_>, queue: Option<Span>) -> Fwd {
        Fwd {
            subject: Span::of(base, p.subject),
            reply: p.reply.map(|r| Span::of(base, r)),
            headers: p.headers.map(|h| Span::of(base, h)),
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

    /// Forwards `p`, which lies in `base`, for the lane's plain
    /// subscriptions; once, however many filters it matched.
    #[inline]
    pub(crate) fn plain(&mut self, base: &[u8], p: &Pub<'_>) {
        let f = Fwd::of(base, p, None);
        if !self
            .msgs
            .last()
            .is_some_and(|l| l.payload == f.payload && l.queue.is_none())
        {
            self.msgs.push(f);
        }
    }

    /// Forwards `p`, which lies in `base`, for one member of queue group
    /// `name` on the lane.
    pub(crate) fn queue(&mut self, base: &[u8], p: &Pub<'_>, name: &[u8]) {
        let at = self.names.len();
        self.names.extend_from_slice(name);
        let span = Span(at as u32, name.len() as u32);
        self.msgs.push(Fwd::of(base, p, Some(span)));
    }
}

/// Delivers what other lanes forward, to this lane's subscribers.
pub(super) async fn run(lane: Rc<Lane>, rx: Receiver<Batch>) {
    let mark = lane.shared.opts.max_pending / 4 * 3;
    let mut batches = Vec::new();
    while rx.recv_all(&mut batches).await {
        let mut stalled = None;
        for b in batches.drain(..) {
            for f in &b.out.msgs {
                lane.deliver_fwd(&b, f, &mut stalled);
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

impl Lane {
    /// Delivers forward `f` of batch `b` to the subscriptions on this lane.
    #[inline]
    fn deliver_fwd(&self, b: &Batch, f: &Fwd, stalled: &mut Option<Rc<crate::conn::Client>>) {
        let p = Pub {
            subject: f.subject.get(&b.chunk),
            reply: f.reply.map(|s| s.get(&b.chunk)),
            headers: f.headers.map(|s| s.get(&b.chunk)),
            payload: f.payload.get(&b.chunk),
        };
        let index = self.index.borrow();
        let found = index.matches(p.subject);
        match f.queue {
            None => {
                for i in found.iter() {
                    // The publisher is on another lane: nothing to skip.
                    self.deliver(&i.plain.local, &p, 0, stalled);
                }
            }
            Some(q) => {
                let groups = queue_groups(&found, 0, q.get(&b.out.names));
                self.deliver_any(&groups, &p, stalled);
            }
        }
    }
}
