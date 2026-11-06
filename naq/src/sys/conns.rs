//! The connections of each account on `$SYS`, as `nats-server` tells the
//! other servers of them: `CONNS` on each change and every 30 seconds while
//! there are any, and answers to `CONNS` requests. What the others tell
//! caps the clients of an account across the cluster.

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use naq_proto::client::Pub;
use rustc_hash::FxHashMap;
use serde::Deserialize;
use tokio::time::Instant;

use super::Service;
use super::account::{X, account_of};
use super::remote::{Counts, Sender};
use super::send::Event;
use super::unmarshal;
use crate::conn::Close;
use crate::imports::service::Tap;
use crate::index::Index;
use crate::lane::Lane;
use crate::server::Shared;

/// The type of a `CONNS` message.
pub(super) const CONNS: &str = "io.nats.server.advisory.v1.account_connections";

/// While an account has connections, `CONNS` goes out this often.
pub(super) const HEARTBEAT: Duration = Duration::from_secs(30);

/// Notes that the connections of `account` changed: `CONNS` goes out,
/// unless it is `$G`, as in `nats-server`.
pub(crate) fn changed(s: &Shared, account: u32) {
    if s.system.is_some() && account != crate::accounts::GLOBAL {
        s.sys.outbox.post(Event::Conns(account));
    }
}

/// Puts the taps of other servers' `CONNS` into `index`, the system
/// account's of a server of ID `id`: those of each change, and the
/// answers to its own requests.
pub(super) fn install(index: &mut Index, id: &str) {
    index.tap(b"$SYS.SERVER.ACCOUNT.*.CONNS", Tap::Sys(Service::Conns));
    let inbox = format!("$SYS._INBOX_.{id}");
    index.tap(inbox.as_bytes(), Tap::Sys(Service::Conns));
}

/// Takes `CONNS` request `m` about the account its subject names, which
/// came on `lane`: the sender answers, if the account has clients here.
pub(super) fn asked(lane: &Lane, m: &Pub<'_>) -> bool {
    let s = &lane.shared;
    let acc = account_of(m.subject);
    if !m.payload.is_empty() {
        match unmarshal::decode(m.payload, &X::Conns.fields()) {
            Ok(set) if set.str("acc") == acc => {}
            Ok(_) => {
                s.log.error(format_args!(
                    "Error unmarshalled account does not match subject"
                ));
                return true;
            }
            Err(why) => {
                s.log.error(format_args!(
                    "Error unmarshalling account connections request message: {why}"
                ));
                return true;
            }
        }
    }
    if let Some(reply) = m.reply.filter(|r| !r.is_empty()) {
        s.sys.outbox.post(Event::Answer {
            account: acc,
            reply: reply.to_vec(),
        });
    }
    true
}

/// A `CONNS` message of another server, as far as tracking reads it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Told {
    server: Sender,
    acc: String,
    conns: usize,
    leafnodes: usize,
}

/// Takes `m`, the connections of an account on another server, which came
/// on `lane`: they count against the account's limit here, and close the
/// newest clients here past it.
pub(super) fn heard(lane: &Lane, m: &Pub<'_>) -> bool {
    let s = &lane.shared;
    if m.payload.is_empty() {
        s.log.error(format_args!("No message body provided"));
        return true;
    }
    let told: Told = match serde_json::from_slice(m.payload) {
        Ok(t) => t,
        Err(e) => {
            s.log.error(format_args!(
                "Error unmarshalling account connection event message: {e}"
            ));
            return true;
        }
    };
    // Of an account it does not have, it need not know.
    let Some(account) = s.accounts.id(&told.acc) else {
        return true;
    };
    if told.server.id == s.server_id {
        s.log.error(format_args!(
            "Processing our own account connection event message: ignored"
        ));
        return true;
    }
    let counts = Counts {
        clients: told.conns,
        leafs: told.leafnodes,
    };
    s.sys.remote.counted(&told.server.id, account, counts);
    rebalance(s, account);
    super::remote::heard(s, &told.server);
    true
}

/// Closes the newest clients of `account` here past its limit across the
/// cluster, as `nats-server` does once the others count more than it
/// knew: harsh, but those closed come back.
fn rebalance(s: &Arc<Shared>, account: u32) {
    let Some(a) = s.accounts.get(account) else {
        return;
    };
    let Ok(limit) = usize::try_from(a.limit()) else {
        return;
    };
    // The others' first: the two locks do not nest.
    let remote = s.sys.remote.conns(account);
    let ids = a.conns.lock().unwrap_or_else(PoisonError::into_inner);
    let kicked = newest(&ids, remote, limit);
    drop(ids);
    if kicked.is_empty() {
        return;
    }
    let shared = s.clone();
    tokio::task::spawn_local(async move {
        crate::monitor::ask_all(&shared, move |lane| {
            let clients = lane.clients.borrow();
            for c in kicked.iter().filter_map(|id| clients.get(id)) {
                c.kick(Close::AccountConns);
            }
        })
        .await;
    });
}

/// The newest of the clients `ids` here that put an account past `limit`,
/// with `remote` clients on the other servers.
fn newest(ids: &BTreeSet<u64>, remote: usize, limit: usize) -> Vec<u64> {
    let over = (ids.len() + remote).saturating_sub(limit);
    ids.iter().rev().take(over).copied().collect()
}

/// When `CONNS` of each account goes out next.
#[derive(Debug, Default)]
pub(super) struct Beats {
    by_time: BTreeSet<(Instant, u32)>,
    by_account: FxHashMap<u32, Instant>,
}

impl Beats {
    /// `CONNS` of `account` went out at `now`, of `total` connections:
    /// again in [`HEARTBEAT`], unless it has none.
    pub(super) fn sent(&mut self, account: u32, total: usize, now: Instant) {
        if let Some(at) = self.by_account.remove(&account) {
            self.by_time.remove(&(at, account));
        }
        if total > 0 {
            let at = now + HEARTBEAT;
            self.by_account.insert(account, at);
            self.by_time.insert((at, account));
        }
    }

    /// When the next is due, if any is.
    pub(super) fn next(&self) -> Option<Instant> {
        self.by_time.first().map(|&(at, _)| at)
    }

    /// The accounts due at `now`, taken off.
    pub(super) fn due(&mut self, now: Instant) -> Vec<u32> {
        let later = self.by_time.split_off(&(now, u32::MAX));
        let due = std::mem::replace(&mut self.by_time, later);
        let due: Vec<u32> = due.into_iter().map(|(_, a)| a).collect();
        for a in &due {
            self.by_account.remove(a);
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_newest_clients_past_the_limit_go() {
        let ids: BTreeSet<u64> = [3, 7, 9, 12].into();
        assert_eq!(newest(&ids, 0, 4), Vec::<u64>::new());
        assert_eq!(newest(&ids, 1, 4), [12]);
        assert_eq!(newest(&ids, 3, 5), [12, 9]);
        assert_eq!(newest(&ids, 10, 2), [12, 9, 7, 3], "no more than it has");
    }

    #[test]
    fn an_account_beats_while_it_has_connections() {
        let t0 = Instant::now();
        let mut b = Beats::default();
        b.sent(1, 2, t0);
        b.sent(2, 1, t0 + Duration::from_secs(1));
        assert_eq!(b.next(), Some(t0 + HEARTBEAT));
        b.sent(1, 1, t0 + Duration::from_secs(5));
        assert_eq!(b.next(), Some(t0 + Duration::from_secs(1) + HEARTBEAT));
        assert_eq!(b.due(t0 + HEARTBEAT), [0u32; 0]);
        assert_eq!(b.due(t0 + Duration::from_secs(40)), [2, 1]);
        assert_eq!(b.next(), None);
        b.sent(3, 1, t0);
        b.sent(3, 0, t0);
        assert_eq!(b.next(), None, "none once it has none");
    }
}
