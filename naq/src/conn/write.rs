//! The writer: hands a client's queued output to the socket.

use std::rc::Rc;
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::Client;

/// Writes `client`'s output until the connection closes. It takes all that
/// is queued at once and writes it in one go, so the output of a batch of
/// messages costs one write. A write that takes longer than `deadline`
/// closes the client as a slow consumer.
pub(super) async fn writer<W: AsyncWrite + Unpin>(
    client: Rc<Client>,
    mut w: W,
    deadline: Duration,
) {
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
        if !matches!(
            tokio::time::timeout(deadline, w.write_all(&buf)).await,
            Ok(Ok(()))
        ) {
            client.close();
            return;
        }
        spare = buf;
        spare.clear();
    }
    let _ = w.shutdown().await;
}
