//! The other servers a server hears from on `$SYS`, as `nats-server`
//! tracks them: known by their `STATSZ`, forgotten once they say they go
//! or fall quiet, with the connections of each account they tell of.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use naq_proto::client::Pub;
use rustc_hash::FxHashMap;
use serde::Deserialize;
use tokio::time::Instant;

use super::Service;
use super::send::Event;
use crate::imports::service::Tap;
use crate::index::Index;
use crate::lane::Lane;
use crate::monitor::query::quote;
use crate::server::Shared;

/// A server not heard from for this long is taken for gone.
pub(super) const QUIET: Duration = Duration::from_secs(150);

/// How often the servers are checked for those gone quiet.
pub(super) const SWEEP: Duration = Duration::from_secs(90);

/// The other servers heard from.
#[derive(Debug, Default)]
pub(crate) struct Remote(Mutex<Known>);

/// What a server knows of the others.
#[derive(Debug, Default)]
struct Known {
    /// By ID.
    servers: FxHashMap<String, Seen>,
    /// The connections of each account, by its id, then by the ID of the
    /// server that told of them: none there for none.
    accounts: FxHashMap<u32, FxHashMap<String, Counts>>,
}

impl Known {
    /// Forgets server `id`: whether it knew it.
    fn forget(&mut self, id: &str) -> bool {
        self.accounts.retain(|_, by| {
            by.remove(id);
            !by.is_empty()
        });
        self.servers.remove(id).is_some()
    }
}

/// The connections of an account on one server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Counts {
    pub(super) clients: usize,
    pub(super) leafs: usize,
}

/// The last message of a server.
#[derive(Debug, Clone, Copy)]
struct Seen {
    /// Its number.
    seq: u64,
    /// When it came.
    at: Instant,
}

/// What a message of a server told of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Heard {
    /// It is new.
    New,
    /// It is known, and the message came in order.
    Again,
    /// The message is older than one before it.
    Late,
}

impl Remote {
    fn lock(&self) -> MutexGuard<'_, Known> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes message `seq` of server `id`, come at `now`: as
    /// `nats-server`'s `updateRemoteServer`, a message out of order does
    /// not count as a sign of life.
    pub(super) fn heard(&self, id: &str, seq: u64, now: Instant) -> Heard {
        let all = &mut self.lock().servers;
        let Some(seen) = all.get_mut(id) else {
            all.insert(id.to_owned(), Seen { seq, at: now });
            return Heard::New;
        };
        if seq <= seen.seq {
            return Heard::Late;
        }
        *seen = Seen { seq, at: now };
        Heard::Again
    }

    /// Forgets server `id`: whether it knew it.
    pub(super) fn forget(&self, id: &str) -> bool {
        self.lock().forget(id)
    }

    /// Forgets the servers not heard from in [`QUIET`] before `now`, and
    /// returns their IDs.
    pub(super) fn sweep(&self, now: Instant) -> Vec<String> {
        let mut known = self.lock();
        let quiet: Vec<String> = known
            .servers
            .iter()
            .filter(|(_, s)| now.saturating_duration_since(s.at) > QUIET)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &quiet {
            known.forget(id);
        }
        quiet
    }

    /// The number of servers known.
    pub(crate) fn len(&self) -> usize {
        self.lock().servers.len()
    }

    /// Notes what server `id` told of the connections of `account`. Each
    /// message tells them all, so one out of order counts still, as in
    /// `nats-server`.
    pub(super) fn counted(&self, id: &str, account: u32, counts: Counts) {
        let mut known = self.lock();
        let by = known.accounts.entry(account).or_default();
        if counts == Counts::default() {
            by.remove(id);
            if by.is_empty() {
                known.accounts.remove(&account);
            }
        } else {
            by.insert(id.to_owned(), counts);
        }
    }

    /// The clients of `account` on the other servers.
    pub(crate) fn conns(&self, account: u32) -> usize {
        let known = self.lock();
        let by = known.accounts.get(&account);
        by.map_or(0, |by| by.values().map(|c| c.clients).sum())
    }
}

/// Puts the taps of other servers' messages into `index`, the system
/// account's: their interest goes to the other servers, so that their
/// `STATSZ` and farewells come here.
pub(super) fn install(index: &mut Index) {
    index.tap(b"$SYS.SERVER.*.STATSZ", Tap::Sys(Service::Heard));
    index.tap(b"$SYS.SERVER.*.SHUTDOWN", Tap::Sys(Service::Gone));
    index.tap(b"$SYS.SERVER.*.LAMEDUCK", Tap::Sys(Service::Gone));
}

/// The server block of a message, as far as tracking reads it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct Sender {
    pub(super) id: String,
    pub(super) seq: u64,
}

/// A `STATSZ` message, as far as tracking reads it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Stats {
    server: Sender,
}

/// Takes `STATSZ` message `m` of another server, which came on `lane`.
pub(super) fn statsz(lane: &Lane, m: &Pub<'_>) -> bool {
    let s = &lane.shared;
    if m.payload.is_empty() {
        s.log.debug(format_args!(
            "Received empty server info for remote server update"
        ));
        return true;
    }
    let Ok(stats) = serde_json::from_slice::<Stats>(m.payload) else {
        s.log.debug(format_args!(
            "Received bad server info for remote server update"
        ));
        return true;
    };
    if stats.server.id != s.server_id {
        heard(s, &stats.server);
    }
    true
}

/// Notes a message of server `from`, as `nats-server` does: a new server
/// gets this one's `STATSZ` at once.
pub(super) fn heard(s: &Shared, from: &Sender) {
    match s.sys.remote.heard(&from.id, from.seq, Instant::now()) {
        Heard::New => s.sys.outbox.post(Event::Statsz { forced: false }),
        Heard::Again => {}
        Heard::Late => s.log.error(format_args!(
            "Received out of order remote server update from: {}",
            quote(&from.id)
        )),
    }
}

/// Takes `m`, another server's farewell, which came on `lane`: the
/// server its subject names is forgotten, if the farewell names a server.
pub(super) fn gone(lane: &Lane, m: &Pub<'_>) -> bool {
    let s = &lane.shared;
    let subject = String::from_utf8_lossy(m.subject);
    let Some(id) = subject
        .split('.')
        .nth(2)
        .filter(|_| subject.split('.').count() >= 4)
    else {
        s.log.debug(format_args!(
            "Received remote server shutdown on bad subject {}",
            quote(&subject)
        ));
        return true;
    };
    if m.payload.is_empty() {
        s.log.error(format_args!(
            "Remote server sent invalid (empty) shutdown message to {}",
            quote(&subject)
        ));
        return true;
    }
    if serde_json::from_slice::<Sender>(m.payload).is_err() {
        s.log.debug(format_args!(
            "Received bad server info for remote server shutdown"
        ));
        return true;
    }
    s.sys.remote.forget(id);
    true
}

/// Forgets the servers of `s` gone quiet by `now`, as `nats-server`
/// takes them for gone.
pub(super) fn sweep(s: &Shared, now: Instant) {
    for id in s.sys.remote.sweep(now) {
        s.log.debug(format_args!(
            "Detected orphan remote server: {}",
            quote(&id)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_are_new_then_known_and_late_messages_do_not_count() {
        let r = Remote::default();
        let t0 = Instant::now();
        assert_eq!(r.heard("a", 5, t0), Heard::New);
        assert_eq!(r.heard("a", 6, t0), Heard::Again);
        let later = t0 + QUIET;
        assert_eq!(r.heard("a", 6, later), Heard::Late, "the same again");
        assert_eq!(r.heard("a", 2, later), Heard::Late);
        assert_eq!(r.len(), 1);
        assert!(
            r.sweep(later + Duration::from_secs(1)) == ["a"],
            "late messages are no sign of life"
        );
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn the_clients_of_an_account_are_summed_until_their_servers_go() {
        let r = Remote::default();
        let t0 = Instant::now();
        let n = |clients, leafs| Counts { clients, leafs };
        r.heard("a", 1, t0);
        r.counted("a", 4, n(2, 1));
        r.counted("b", 4, n(3, 0));
        r.counted("b", 5, n(1, 0));
        assert_eq!(r.conns(4), 5);
        r.counted("b", 4, n(1, 0));
        assert_eq!(r.conns(4), 3, "each message tells them all");
        assert!(r.forget("a"));
        assert_eq!(r.conns(4), 1);
        r.counted("b", 4, n(0, 0));
        assert_eq!(r.conns(4), 0);
        assert!(!r.forget("b"), "known by its counts alone");
        assert_eq!(r.conns(5), 0, "forgotten with it");
        r.heard("c", 1, t0);
        r.counted("c", 4, n(1, 0));
        r.sweep(t0 + QUIET + Duration::from_secs(1));
        assert_eq!(r.conns(4), 0, "gone quiet");
    }

    #[test]
    fn servers_go_when_they_say_so_or_fall_quiet() {
        let r = Remote::default();
        let t0 = Instant::now();
        r.heard("a", 1, t0);
        r.heard("b", 1, t0 + QUIET);
        assert!(r.sweep(t0 + QUIET).is_empty(), "not past the limit");
        assert_eq!(r.sweep(t0 + QUIET + Duration::from_millis(1)), ["a"]);
        assert!(r.forget("b"));
        assert!(!r.forget("b"));
    }
}
