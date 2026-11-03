//! Publishes forwarded from other lanes.

use std::rc::Rc;

use bytes::Bytes;
use naq_proto::client::Pub;

use super::Lane;
use crate::mailbox::Receiver;

/// Offset and length in a batch's chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span(u32, u32);

impl Span {
    /// Where `part` lies in `base`, which holds it.
    #[inline]
    pub(crate) fn of(base: &[u8], part: &[u8]) -> Span {
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
    pub(crate) subject: Span,
    pub(crate) reply: Option<Span>,
    pub(crate) headers: Option<Span>,
    pub(crate) payload: Span,
}

impl Fwd {
    /// `p`, which lies in `base`.
    #[inline]
    pub(crate) fn of(base: &[u8], p: &Pub<'_>) -> Fwd {
        Fwd {
            subject: Span::of(base, p.subject),
            reply: p.reply.map(|r| Span::of(base, r)),
            headers: p.headers.map(|h| Span::of(base, h)),
            payload: Span::of(base, p.payload),
        }
    }
}

/// Publishes one lane read and routed for another: slices of the read
/// buffer, which the batch keeps.
#[derive(Debug)]
pub(crate) struct Batch {
    pub(crate) chunk: Bytes,
    pub(crate) msgs: Vec<Fwd>,
}

/// Delivers what other lanes forward, to this lane's subscribers.
pub(super) async fn run(lane: Rc<Lane>, rx: Receiver<Batch>) {
    let mark = lane.shared.opts.max_pending / 4 * 3;
    let mut batches = Vec::new();
    while rx.recv_all(&mut batches).await {
        let mut stalled = None;
        for b in batches.drain(..) {
            let index = lane.index.borrow();
            for f in &b.msgs {
                let p = Pub {
                    subject: f.subject.get(&b.chunk),
                    reply: f.reply.map(|s| s.get(&b.chunk)),
                    headers: f.headers.map(|s| s.get(&b.chunk)),
                    payload: f.payload.get(&b.chunk),
                };
                if let Some(i) = index.matches(p.subject) {
                    // The publisher is on another lane: nothing to skip.
                    stalled = lane.deliver(&i.local, &p, 0).or(stalled);
                }
            }
        }
        lane.flush();
        // A subscriber past the stall mark slows its publishers: they wait
        // for room in this lane's mailbox meanwhile.
        if let Some(c) = stalled {
            crate::conn::stall(&c, mark).await;
        }
        tokio::task::yield_now().await;
    }
}
