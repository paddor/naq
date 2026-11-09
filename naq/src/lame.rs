//! Lame duck mode, as `nats-server` has it: the server takes no more
//! clients, tells those it has and the other servers of its cluster that it
//! goes, and closes its clients over a while, before it shuts down.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::Instant;
use zzq_tokio::signal::StateSignal;

use crate::conn::Close;
use crate::lane::Lane;
use crate::server::Shared;
use crate::times::go_duration;

/// Longest a close waits for its connection to go.
const GONE: Duration = Duration::from_secs(1);

/// How often a close looks whether its connection is gone.
const TICK: Duration = Duration::from_millis(5);

/// Where a server stands in lame duck mode.
#[derive(Debug, Default)]
pub(crate) struct Lame {
    /// It is in lame duck mode.
    on: AtomicBool,
    /// Accept loops of clients still open.
    doors: AtomicUsize,
    /// Changes as it starts, and as each accept loop closes.
    changed: StateSignal,
}

/// Why the lame duck mode of `opts` cannot work, as `nats-server` says it.
pub(crate) fn validate(opts: &crate::Options) -> Result<(), String> {
    let (d, g) = (opts.lame_duck_duration, opts.lame_duck_grace_period);
    if g >= d {
        return Err(format!(
            "lame duck grace period ({}) should be strictly lower than lame duck duration ({})",
            go_duration(g),
            go_duration(d)
        ));
    }
    Ok(())
}

/// Whether `shared`'s server is in lame duck mode.
pub(crate) fn on(shared: &Shared) -> bool {
    // Acquire: pairs with the swap in `run`.
    shared.lame.on.load(Ordering::Acquire)
}

/// Waits until `shared`'s server is in lame duck mode. Cancel-safe.
pub(crate) async fn started(shared: &Shared) {
    shared.lame.changed.until(|| on(shared).then_some(())).await;
}

/// An accept loop of clients, counted open until dropped: lame duck mode
/// waits for it to close.
#[derive(Debug)]
pub(crate) struct Door(Arc<Shared>);

impl Door {
    /// Counts an accept loop of `shared`'s server open.
    pub(crate) fn open(shared: &Arc<Shared>) -> Door {
        // Relaxed: the server has not started, nothing reads it yet.
        shared.lame.doors.fetch_add(1, Ordering::Relaxed);
        Door(shared.clone())
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        let lame = &self.0.lame;
        // Release: lame duck mode, which reads it, then finds the listener
        // closed.
        lame.doors.fetch_sub(1, Ordering::Release);
        lame.changed.notify_changed();
    }
}

/// Puts `shared`'s server in lame duck mode, as `nats-server` does: it
/// takes no more clients, says `LAMEDUCK` as its last word on `$SYS`, tells
/// the other servers and its clients, then closes its clients and links to
/// hubs, spread over the lame duck duration once the grace period is over.
/// Returns once the last is closed; at once if it has none, is in lame
/// duck mode already, or stops. The server shuts down then.
pub(crate) async fn run(shared: Arc<Shared>) {
    // AcqRel: pairs with `on`; one call goes on.
    if crate::stop::stopping(&shared) || shared.lame.on.swap(true, Ordering::AcqRel) {
        return;
    }
    shared.log.info(format_args!(
        "Entering lame duck mode, stop accepting new clients"
    ));
    crate::sys::last_word(&shared, crate::sys::Word::LameDuck);
    let lame = &shared.lame;
    lame.changed.notify_changed();
    // Acquire: pairs with the release in `Door::drop`.
    let closed = || (lame.doors.load(Ordering::Acquire) == 0).then_some(());
    lame.changed.until(closed).await;
    let mut all = connections(&shared).await;
    if all.is_empty() || crate::stop::stopping(&shared) {
        return;
    }
    let mut below = crate::server::random();
    shuffle(&mut all, &mut below);
    tell_routes(&shared);
    tell_clients(&shared).await;
    let o = &shared.opts;
    tokio::time::sleep(o.lame_duck_grace_period).await;
    shared.log.info(format_args!("Closing existing clients"));
    let spread = Spread::new(o.lame_duck_duration, o.lame_duck_grace_period, all.len());
    for (i, &(lane, id)) in all.iter().enumerate() {
        close(&shared, lane, id).await;
        if i + 1 == all.len() {
            break;
        }
        if let Some(pause) = spread.pause(i, &mut below) {
            tokio::time::sleep(pause).await;
        }
    }
}

/// The clients and links to hubs of every lane: lane and ID.
async fn connections(shared: &Shared) -> Vec<(usize, u64)> {
    let found = crate::monitor::ask_all(shared, |lane| {
        let clients = lane.clients.borrow();
        let links = lane.links.borrow();
        let ids = clients.keys().copied().chain(links.iter().map(|l| l.id));
        ids.map(|id| (lane.id, id)).collect::<Vec<_>>()
    })
    .await;
    found.into_iter().flatten().collect()
}

/// Puts `all` in an order picked at random by `below`.
fn shuffle<T>(all: &mut [T], below: &mut impl FnMut(u64) -> u64) {
    for i in (1..all.len()).rev() {
        // Below `i + 1`: it fits.
        let j = below(i as u64 + 1) as usize;
        all.swap(i, j);
    }
}

/// Tells the other servers of the cluster that this one goes: their
/// clients no longer hear of it.
fn tell_routes(shared: &Shared) {
    crate::monitor::on_lane(shared, 0, |lane| {
        if let Some(mesh) = lane.mesh.borrow().as_ref() {
            mesh.lame();
        }
    });
}

/// Sends each client that takes one an `INFO` that says the server is in
/// lame duck mode.
async fn tell_clients(shared: &Shared) {
    crate::monitor::ask_all(shared, |lane| {
        for c in lane.clients.borrow().values() {
            c.inform(true);
        }
    })
    .await;
}

/// Closes client or link to a hub `id` of lane `lane` as the server shuts
/// down, and waits until it is gone, its close logged, for [`GONE`] at
/// most.
async fn close(shared: &Shared, lane: usize, id: u64) {
    let kick = move |lane: &Lane| {
        if let Some(c) = lane.clients.borrow().get(&id) {
            c.kick(Close::Shutdown);
        }
        if let Some(l) = lane.links.borrow().iter().find(|l| l.id == id) {
            l.client.kick(Close::Shutdown);
        }
        there(lane, id)
    };
    let mut left = crate::monitor::ask(shared, lane, kick).await;
    let until = Instant::now() + GONE;
    while left == Some(true) && Instant::now() < until {
        tokio::time::sleep(TICK).await;
        left = crate::monitor::ask(shared, lane, move |lane: &Lane| there(lane, id)).await;
    }
}

/// Whether client or link to a hub `id` is still on `lane`.
fn there(lane: &Lane, id: u64) -> bool {
    lane.clients.borrow().contains_key(&id) || lane.links.borrow().iter().any(|l| l.id == id)
}

/// How lame duck mode spreads the closes of its connections, as
/// `nats-server` does: over its duration less the grace period, a
/// second apart at most.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Spread {
    /// The time between closes, in nanoseconds.
    every: u64,
    /// Connections closed between pauses, past a nanosecond each.
    batch: u64,
}

impl Spread {
    /// The spread of `n` closes in lame duck mode of `duration` and `grace`.
    fn new(duration: Duration, grace: Duration, n: usize) -> Spread {
        const SECOND: u64 = 1_000_000_000;
        let ns = |d: Duration| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        let window = match ns(duration).saturating_sub(ns(grace)) {
            0 => SECOND,
            w => w,
        };
        let n = (n as u64).max(1);
        match window / n {
            0 => Spread {
                every: 1,
                batch: n / window,
            },
            every => Spread {
                every: every.min(SECOND),
                batch: 1,
            },
        }
    }

    /// The pause after the close of connection `i`, if one comes: half the
    /// time between closes, or more, as `below` picks it.
    fn pause(&self, i: usize, below: &mut impl FnMut(u64) -> u64) -> Option<Duration> {
        if self.batch != 1 && !(i as u64).is_multiple_of(self.batch) {
            return None;
        }
        let pause = below(self.every).max(self.every / 2);
        Some(Duration::from_nanos(pause))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn closes_are_a_second_apart_at_most_as_in_nats_server() {
        let s = Spread::new(120 * S, 10 * S, 4);
        assert_eq!(
            s,
            Spread {
                every: 1_000_000_000,
                batch: 1
            }
        );
        let s = Spread::new(30 * S, 10 * S, 40);
        assert_eq!(
            s,
            Spread {
                every: 500_000_000,
                batch: 1
            }
        );
    }

    #[test]
    fn a_window_of_nothing_is_a_second() {
        let s = Spread::new(10 * S, 10 * S, 4);
        assert_eq!(
            s,
            Spread {
                every: 250_000_000,
                batch: 1
            }
        );
    }

    #[test]
    fn more_closes_than_nanoseconds_go_in_batches() {
        let d = Duration::from_nanos(10);
        let s = Spread::new(d, Duration::ZERO, 25);
        assert_eq!(s, Spread { every: 1, batch: 2 });
        let mut below = |_| 0;
        assert_eq!(s.pause(0, &mut below), Some(Duration::ZERO));
        assert_eq!(s.pause(1, &mut below), None);
        assert_eq!(s.pause(2, &mut below), Some(Duration::ZERO));
    }

    #[test]
    fn a_pause_is_half_the_time_between_closes_or_more() {
        let s = Spread::new(30 * S, 10 * S, 40);
        let half = Duration::from_millis(250);
        assert_eq!(s.pause(0, &mut |_| 0), Some(half));
        assert_eq!(
            s.pause(1, &mut |n| n - 1),
            Some(Duration::from_nanos(499_999_999))
        );
        assert_eq!(
            s.pause(2, &mut |n| n / 4 * 3),
            Some(Duration::from_millis(375))
        );
    }

    #[test]
    fn a_shuffle_keeps_every_item() {
        let mut all: Vec<u32> = (0..10).collect();
        let mut below = crate::server::random();
        shuffle(&mut all, &mut below);
        let mut sorted = all.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..10).collect::<Vec<_>>());
        let mut one = [7];
        shuffle(&mut one, &mut below);
        assert_eq!(one, [7]);
    }

    #[test]
    fn a_grace_period_must_be_below_the_duration() {
        let mut o = crate::Options::default();
        assert_eq!(validate(&o), Ok(()));
        o.lame_duck_grace_period = 120 * S;
        assert_eq!(
            validate(&o),
            Err(
                "lame duck grace period (2m0s) should be strictly lower than lame duck duration (2m0s)"
                    .into()
            )
        );
    }
}
