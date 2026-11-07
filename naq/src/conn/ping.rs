//! PINGs to a client, and closing it once it stops answering, as
//! `nats-server` does.

use std::time::Duration;

use tokio::time::Instant;

/// The first PING after a `CONNECT` comes this soon at the latest, to
/// measure the round trip.
const FIRST: Duration = Duration::from_secs(2);

/// How long a measured round trip counts as current.
const RTT_FRESH: Duration = Duration::from_secs(3600);

/// What the ping timer does when it fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tick {
    /// Nothing: the client was busy lately.
    Quiet,
    /// Send a `PING`.
    Ping,
    /// Close the client: it left too many `PING`s unanswered.
    Stale,
}

/// The ping state of a client.
#[derive(Debug)]
pub(super) struct Pinger {
    /// When the timer fires next.
    pub(super) next: Instant,
    /// Time between `PING`s to a quiet client.
    pub(super) interval: Duration,
    /// `PING`s sent and not answered.
    out: u32,
    /// The last read with messages or subscriptions in it, or a `PING`.
    last_in: Instant,
    /// When a `PING` last went out.
    sent_at: Option<Instant>,
    /// When the client connected.
    start: Instant,
}

impl Pinger {
    /// A client accepted at `now`.
    pub(super) fn new(now: Instant, interval: Duration) -> Pinger {
        Pinger {
            next: now + interval,
            interval,
            out: 0,
            last_in: now,
            sent_at: None,
            start: now,
        }
    }

    /// The round trip as far as it is known at a `CONNECT` at `now`: the
    /// time from the connection to it, as `nats-server` takes it.
    pub(super) fn first_rtt(&self, now: Instant) -> Duration {
        now - self.start
    }

    /// After a `CONNECT` at `now`: the next `PING` comes early, delayed by
    /// `jitter` so that clients that connect together do not get theirs
    /// together.
    pub(super) fn connected(&mut self, now: Instant, interval: Duration, jitter: Duration) {
        self.next = now + interval.min(FIRST) + jitter;
    }

    /// The client sent messages, subscriptions or a `PING`.
    pub(super) const fn active(&mut self, now: Instant) {
        self.last_in = now;
    }

    /// The client answered a `PING` at `now`. Returns the round trip, if
    /// a `PING` was out.
    pub(super) fn pong(&mut self, now: Instant) -> Option<Duration> {
        let out = std::mem::take(&mut self.out);
        self.sent_at.filter(|_| out > 0).map(|t| now - t)
    }

    /// The timer fired at `now`.
    pub(super) fn tick(&mut self, now: Instant, interval: Duration, max_out: u32) -> Tick {
        self.next = now + interval;
        let fresh = self.sent_at.is_some_and(|t| now - t < RTT_FRESH);
        if now - self.last_in < interval && fresh {
            return Tick::Quiet;
        }
        if self.out >= max_out {
            return Tick::Stale;
        }
        self.out += 1;
        self.sent_at = Some(now);
        Tick::Ping
    }
}

/// Up to a fifth of the first interval, from a random `pick` below `n`.
pub(super) fn jitter(interval: Duration, pick: impl FnOnce(u64) -> u64) -> Duration {
    let n = (interval.min(FIRST) / 5).as_nanos() as u64;
    if n == 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(pick(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn the_first_ping_comes_early_then_one_per_quiet_interval() {
        let t0 = Instant::now();
        let mut p = Pinger::new(t0, 2 * MIN);
        assert_eq!(p.next, t0 + 2 * MIN);
        p.connected(
            t0 + Duration::from_millis(3),
            2 * MIN,
            Duration::from_millis(100),
        );
        assert_eq!(
            p.first_rtt(t0 + Duration::from_millis(3)),
            Duration::from_millis(3),
            "from the connection to its CONNECT"
        );
        assert_eq!(
            p.next,
            t0 + Duration::from_millis(3) + FIRST + Duration::from_millis(100)
        );
        // The first always goes out, busy or not: it measures the round trip.
        p.active(p.next);
        let sent = p.next;
        assert_eq!(p.tick(sent, 2 * MIN, 2), Tick::Ping);
        assert_eq!(
            p.pong(sent + Duration::from_millis(2)),
            Some(Duration::from_millis(2))
        );
        assert_eq!(p.pong(sent + Duration::from_millis(5)), None, "no PING out");
        // Busy within the interval: nothing.
        let t = p.next;
        p.active(t - Duration::from_secs(1));
        assert_eq!(p.tick(t, 2 * MIN, 2), Tick::Quiet);
        // Quiet for a whole interval: a PING.
        assert_eq!(p.tick(p.next, 2 * MIN, 2), Tick::Ping);
    }

    #[test]
    fn a_client_is_stale_past_its_unanswered_pings() {
        let t0 = Instant::now();
        let mut p = Pinger::new(t0, MIN);
        assert_eq!(p.tick(p.next, MIN, 2), Tick::Ping);
        assert_eq!(p.tick(p.next, MIN, 2), Tick::Ping);
        assert_eq!(p.tick(p.next, MIN, 2), Tick::Stale);
        p.pong(p.next);
        assert_eq!(p.tick(p.next, MIN, 2), Tick::Ping);
    }

    #[test]
    fn jitter_is_under_a_fifth_of_the_first_interval() {
        assert_eq!(
            jitter(2 * MIN, |n| n - 1),
            Duration::from_nanos(400_000_000 - 1)
        );
        assert_eq!(
            jitter(Duration::from_millis(50), |n| n / 2),
            Duration::from_millis(5)
        );
        assert_eq!(jitter(Duration::ZERO, |_| unreachable!()), Duration::ZERO);
    }
}
