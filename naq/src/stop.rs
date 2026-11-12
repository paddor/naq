//! Stopping the server as `nats-server` does: no new connections, then
//! every client and link closes with `Server Shutdown`, its output written,
//! before the lanes stop.

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::conn::Close;
use crate::lane::{Control, Lane};
use crate::server::Shared;

/// Longest a lane waits for its connections to go: a writer gets two
/// seconds to write what is left.
const WAIT: Duration = Duration::from_secs(3);

/// How often a lane looks whether its connections are gone.
const TICK: Duration = Duration::from_millis(5);

/// Stops `shared`: refuses new connections and closes those of every lane,
/// waiting until they are gone.
///
/// # Panics
///
/// Called from within an async runtime.
pub(crate) fn server(shared: &Shared) {
    crate::sys::last_word(shared, crate::sys::Word::Shutdown);
    shared.log.info(format_args!("Initiating Shutdown..."));
    // Release: a loop that sees it also sees the log line above.
    shared.stopping.store(true, Ordering::Release);
    let waits: Vec<_> = shared
        .lanes
        .iter()
        .map(|tx| {
            let (done, wait) = oneshot::channel();
            tx.control(Control::Shutdown(done));
            wait
        })
        .collect();
    for w in waits {
        // A lane gone already has no connections.
        let _ = w.blocking_recv();
    }
    shared.log.info(format_args!("Server Exiting.."));
}

/// Closes the clients and links of `lane` for a shutdown, once it
/// delivered what other lanes had sent it, and answers `done` once they
/// are gone, or after [`WAIT`].
pub(crate) fn lane(lane: &Lane, done: oneshot::Sender<()>) {
    let Some(lane) = crate::lane::get(lane.shared.id, lane.id) else {
        let _ = done.send(());
        return;
    };
    tokio::task::spawn_local(async move {
        let until = Instant::now() + WAIT;
        // The data loop delivers what it takes in one go: once nothing
        // waits, the clients have it.
        while !lane.shared.lanes[lane.id].no_data() && Instant::now() < until {
            tokio::time::sleep(TICK).await;
        }
        for c in lane.clients.borrow().values() {
            c.kick(Close::Shutdown);
        }
        for l in lane.links.borrow().iter() {
            l.client.kick(Close::Shutdown);
        }
        while !gone(&lane) && Instant::now() < until {
            tokio::time::sleep(TICK).await;
        }
        let _ = done.send(());
    });
}

/// Whether the connections of `lane` are gone, their output written.
fn gone(lane: &Lane) -> bool {
    lane.clients.borrow().is_empty() && lane.links.borrow().is_empty() && lane.ending.get() == 0
}

/// Whether the server stops: loops that make connections end.
pub(crate) fn stopping(shared: &Shared) -> bool {
    // Acquire: pairs with the store in `server`.
    shared.stopping.load(Ordering::Acquire)
}
