//! Requests whose answers take a while: copied out of the lane's buffers,
//! answered by a task of the lane, as many at once as the server allows.

use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use naq_proto::client::Pub;

use super::encode::Encoding;
use crate::lane::{Lane, Outs};
use crate::server::Shared;

/// Requests a server answers at once, at most: more are dropped.
const MOST: usize = 64;

/// A request, as it came.
#[derive(Debug, Clone)]
pub(crate) struct Asked {
    pub(crate) reply: Vec<u8>,
    pub(crate) headers: Vec<u8>,
    pub(crate) body: Vec<u8>,
}

impl Asked {
    pub(crate) fn of(m: &Pub<'_>) -> Asked {
        Asked {
            reply: m.reply.unwrap_or_default().to_vec(),
            headers: m.headers.unwrap_or_default().to_vec(),
            body: m.payload.to_vec(),
        }
    }
}

/// A message the server sends in the system account.
#[derive(Debug)]
pub(crate) struct Answer {
    pub(crate) to: Vec<u8>,
    pub(crate) headers: Option<Vec<u8>>,
    pub(crate) payload: Vec<u8>,
}

impl Answer {
    /// `payload` to `to`.
    pub(crate) const fn new(to: Vec<u8>, payload: Vec<u8>) -> Answer {
        Answer {
            to,
            headers: None,
            payload,
        }
    }

    /// `payload` to `to`, compressed as the request headers `asked` ask:
    /// not at all without headers.
    pub(crate) fn encoded(to: Vec<u8>, asked: &[u8], payload: Vec<u8>) -> Answer {
        if asked.is_empty() {
            return Answer::new(to, payload);
        }
        let e = Encoding::of(asked);
        Answer {
            to,
            headers: e
                .header()
                .map(|h| format!("NATS/1.0\r\nContent-Encoding: {h}\r\n\r\n").into_bytes()),
            payload: e.apply(payload),
        }
    }
}

/// The requests a server answers now.
#[derive(Debug, Default)]
pub(crate) struct Busy(AtomicUsize);

impl Busy {
    /// Takes one more, if fewer than [`MOST`] are taken.
    fn enter(&self) -> bool {
        // Relaxed: a count; nothing else hangs on it.
        let n = self.0.fetch_add(1, Ordering::Relaxed);
        if n >= MOST {
            self.leave();
        }
        n < MOST
    }

    fn leave(&self) {
        // Relaxed: see `enter`.
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One of them, until it is answered.
struct Turn(Arc<Shared>);

impl Turn {
    fn take(shared: &Arc<Shared>) -> Option<Turn> {
        shared.sys.busy.enter().then(|| Turn(shared.clone()))
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        self.0.sys.busy.leave();
    }
}

/// Answers `m`, which came on `lane`, with what `answer` makes of it, if
/// anything, once it has; dropped if the server answers too many now.
pub(crate) fn later<F, Fut>(lane: &Lane, m: &Pub<'_>, answer: F)
where
    F: FnOnce(Arc<Shared>, Asked) -> Fut + 'static,
    Fut: Future<Output = Option<Answer>> + 'static,
{
    let Some(turn) = Turn::take(&lane.shared) else {
        return;
    };
    let Some(me) = crate::lane::get(lane.shared.id, lane.id) else {
        return;
    };
    let asked = Asked::of(m);
    tokio::task::spawn_local(async move {
        let shared = turn.0.clone();
        if let Some(a) = answer(shared, asked).await {
            send(&me, &a).await;
        }
        drop(turn);
    });
}

/// Sends `a` from `lane`, in the system account.
pub(crate) async fn send(lane: &Rc<Lane>, a: &Answer) {
    let Some(sys) = lane.shared.system else {
        return;
    };
    let mut out = Outs::new(lane);
    send_now(lane, &mut out, sys, a);
    lane.flush();
    lane.ship_imported(&mut out).await;
}

/// Sends `a` from `lane` in account `sys` with `out`, as `nats-server`
/// sends its own messages: with an empty reply.
pub(crate) fn send_now(lane: &Lane, out: &mut Outs, sys: u32, a: &Answer) {
    let m = Pub {
        subject: &a.to,
        reply: Some(b""),
        headers: a.headers.as_deref(),
        payload: &a.payload,
    };
    crate::lane::inject(lane, out, sys, &m);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_answers_so_many_requests_at_once() {
        let busy = Busy::default();
        assert!((0..MOST).all(|_| busy.enter()));
        assert!(!busy.enter());
        busy.leave();
        assert!(busy.enter());
    }

    #[test]
    fn answers_are_compressed_as_asked_and_only_then() {
        let plain = Answer::encoded(b"r".to_vec(), b"", b"x".to_vec());
        assert!(plain.headers.is_none());
        let asked = b"NATS/1.0\r\nAccept-Encoding: gzip\r\n\r\n";
        let gz = Answer::encoded(b"r".to_vec(), asked, b"x".to_vec());
        assert_eq!(
            gz.headers.as_deref(),
            Some(&b"NATS/1.0\r\nContent-Encoding: gzip\r\n\r\n"[..])
        );
        let other = Answer::encoded(b"r".to_vec(), b"NATS/1.0\r\nX: 1\r\n\r\n", b"x".to_vec());
        assert!(other.headers.is_none());
    }
}
