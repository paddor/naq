//! The writer: hands a client's queued output to the socket.

use std::rc::Rc;
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::Client;

/// Writes `client`'s output until the connection closes. It takes all that
/// is queued at once and writes it in one go, so the output of a batch of
/// messages costs one write. A write that takes longer than `deadline`
/// closes the client as a slow consumer, after a call to `slow`.
pub(super) async fn writer<W: AsyncWrite + Unpin>(
    client: Rc<Client>,
    mut w: W,
    deadline: Duration,
    slow: impl FnOnce(),
) {
    // The buffer the next swap hands to the client, keeping its capacity.
    let mut spare = Vec::new();
    loop {
        let buf = std::mem::replace(&mut *client.out.borrow_mut(), std::mem::take(&mut spare));
        let idle = buf.is_empty();
        if idle && client.is_closed() {
            break;
        }
        if !idle {
            client.drained.notify_waiters();
        }
        // Cancel-safe enough: on a timeout the client closes, and what was
        // left unwritten no longer matters.
        match tokio::time::timeout(deadline, put(&mut w, &buf)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                client.close();
                return;
            }
            Err(_) => {
                slow();
                client.close();
                return;
            }
        }
        spare = buf;
        spare.clear();
        if idle {
            // A wake since the swap is kept, so output queued meanwhile is
            // not missed.
            client.wake.notified().await;
        }
    }
    let _ = w.shutdown().await;
}

/// Writes `buf` and flushes: a stream that buffers, as TLS does, sends
/// only then. With `buf` empty, the stream still sends what it has of its
/// own, such as WebSocket control frames.
async fn put<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> std::io::Result<()> {
    w.write_all(buf).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn output_leaves_a_buffered_stream_before_the_writer_waits() {
        let client = Rc::new(Client::new(1));
        let (near, mut far) = tokio::io::duplex(1 << 16);
        client.out.borrow_mut().extend_from_slice(b"PING\r\n");
        let run = writer(
            client.clone(),
            tokio::io::BufWriter::new(near),
            Duration::from_secs(5),
            || (),
        );
        tokio::pin!(run);
        let mut got = [0u8; 6];
        let read = tokio::time::timeout(Duration::from_secs(1), far.read_exact(&mut got));
        tokio::select! {
            () = &mut run => panic!("the writer stopped"),
            r = read => assert!(r.is_ok(), "the output stayed in the buffer"),
        }
        assert_eq!(&got, b"PING\r\n");
    }

    #[tokio::test]
    async fn a_write_past_the_deadline_closes_a_slow_consumer() {
        let client = Rc::new(Client::new(1));
        let (near, _far) = tokio::io::duplex(4);
        client
            .out
            .borrow_mut()
            .extend_from_slice(b"more than four bytes");
        let slow = std::cell::Cell::new(false);
        let run = writer(client.clone(), near, Duration::from_millis(10), || {
            slow.set(true);
        });
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .unwrap();
        assert!(slow.get() && client.is_closed());
    }
}
