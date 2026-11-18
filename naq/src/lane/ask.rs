//! Work handed to a lane from elsewhere, and what it finds there.

use tokio::sync::oneshot;

use super::{Control, Lane};
use crate::server::Shared;

/// What `f` finds on every lane, in lane order. A lane that stopped finds
/// nothing.
pub(crate) async fn ask_all<T, F>(shared: &Shared, f: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(&Lane) -> T + Clone + Send + 'static,
{
    let waits: Vec<_> = (0..shared.lanes.len())
        .map(|i| {
            let (tx, rx) = oneshot::channel();
            let f = f.clone();
            shared.lanes[i].control(Control::Ask(Ask(Box::new(move |lane| {
                let _ = tx.send(f(lane));
            }))));
            rx
        })
        .collect();
    let mut all = Vec::with_capacity(waits.len());
    for w in waits {
        if let Ok(t) = w.await {
            all.push(t);
        }
    }
    all
}

/// What `f` finds on lane `lane` of `shared`'s server; `None` if the lane
/// stopped.
pub(crate) async fn ask<T: Send + 'static>(
    shared: &Shared,
    lane: usize,
    f: impl FnOnce(&Lane) -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = oneshot::channel();
    on_lane(shared, lane, move |lane| {
        let _ = tx.send(f(lane));
    });
    rx.await.ok()
}

/// Hands `f` to lane `lane` of `shared`'s server, to run there. A lane
/// that stopped drops it.
pub(crate) fn on_lane(shared: &Shared, lane: usize, f: impl FnOnce(&Lane) + Send + 'static) {
    if let Some(tx) = shared.lanes.get(lane) {
        tx.control(Control::Ask(Ask(Box::new(f))));
    }
}

/// Work handed to a lane: it runs there, and sends what it finds back.
pub(crate) struct Ask(Box<dyn FnOnce(&Lane) + Send>);

impl Ask {
    /// Runs it on `lane`.
    pub(crate) fn run(self, lane: &Lane) {
        (self.0)(lane);
    }
}

impl std::fmt::Debug for Ask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ask")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_work_shows_without_the_closure() {
        assert_eq!(format!("{:?}", Ask(Box::new(|_| {}))), "Ask");
    }
}
