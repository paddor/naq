//! The writer: hands a client's queued output to the socket.

use std::rc::Rc;
use std::sync::Arc;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::Client;
use crate::server::Shared;
use crate::stats::Events;

/// Writes `client`'s output until the connection closes. It takes all that
/// is queued at once and writes it in one go, so the output of a batch of
/// messages costs one write. A write that takes longer than the server's
/// `write_deadline` closes the client as a slow consumer.
pub(super) async fn writer<W: AsyncWrite + Unpin>(
    client: Rc<Client>,
    mut w: W,
    shared: Arc<Shared>,
) {
    let deadline = shared.opts.write_deadline;
    // The buffer the next swap hands to the client, keeping its capacity.
    let mut spare = Vec::new();
    loop {
        let buf = std::mem::replace(&mut *client.out.borrow_mut(), std::mem::take(&mut spare));
        if buf.is_empty() {
            spare = buf;
            if client.is_closed() {
                break;
            }
            // A wake since the swap is kept, so output queued meanwhile is
            // not missed.
            client.wake.notified().await;
            continue;
        }
        client.drained.notify_waiters();
        // Cancel-safe enough: on a timeout the client closes, and what was
        // left unwritten no longer matters.
        match tokio::time::timeout(deadline, w.write_all(&buf)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                client.close();
                return;
            }
            Err(_) => {
                Events::note(&shared.events.slow_consumers);
                client.close();
                return;
            }
        }
        spare = buf;
        spare.clear();
    }
    let _ = w.shutdown().await;
}
