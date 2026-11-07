//! The timers of a directory resolver on lane 0: expired JWTs go, and a
//! full resolver compares its JWTs with those of the other servers, as
//! `nats-server` does every `interval`.

use std::sync::{Arc, Weak};
use std::time::SystemTime;

use naq_proto::client::Pub;

use crate::lane::{Lane, Outs};
use crate::server::Shared;

/// Packs of JWTs are asked for on this subject.
pub(crate) const PACK: &[u8] = b"$SYS.REQ.CLAIMS.PACK";

/// Starts the timers of the directory resolver of `lane`'s server, if it
/// has one, on lane 0.
pub(crate) fn start(lane: &Lane) {
    let Some(dir) = lane.shared.resolver.as_ref().filter(|_| lane.id == 0) else {
        return;
    };
    let weak = Arc::downgrade(&lane.shared);
    tokio::task::spawn_local(sweep(weak.clone()));
    if dir.full {
        tokio::task::spawn_local(sync(weak));
    }
}

/// Removes the expired JWTs of the store, now and then, while the server
/// runs.
async fn sweep(shared: Weak<Shared>) {
    loop {
        let Some(every) = shared
            .upgrade()
            .and_then(|s| s.resolver.as_ref().map(|d| d.store.sweep_every()))
        else {
            return;
        };
        tokio::time::sleep(every).await;
        let Some(s) = shared.upgrade() else {
            return;
        };
        if let Some(d) = &s.resolver {
            d.store.expire(SystemTime::now());
        }
    }
}

/// Asks the other servers for the JWTs this one lacks, every `interval`,
/// with the hash of its own: answers come to its pack inbox.
async fn sync(shared: Weak<Shared>) {
    let Some(every) = shared
        .upgrade()
        .and_then(|s| s.resolver.as_ref().map(|d| d.opts.interval))
    else {
        return;
    };
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        tick.tick().await;
        let Some(s) = shared.upgrade() else {
            return;
        };
        let (Some(dir), Some(sys), Some(lane)) = (&s.resolver, s.system, crate::lane::get(s.id, 0))
        else {
            return;
        };
        let (hash, inbox) = (dir.store.hash(), pack_inbox(&s));
        let mut out = Outs::new(&lane);
        let m = Pub {
            subject: PACK,
            reply: Some(&inbox),
            headers: None,
            payload: &hash,
        };
        crate::lane::inject(&lane, &mut out, sys, &m);
        lane.flush();
        lane.ship_imported(&mut out).await;
    }
}

/// Where the packs this server asked for come: `$SYS._INBOX.`, the hash of
/// its name, `.`, its pack token.
pub(crate) fn pack_inbox(shared: &Shared) -> Vec<u8> {
    let node = shared.sys.node.unwrap_or_default();
    let token = shared
        .resolver
        .as_ref()
        .map(|d| d.pack_token)
        .unwrap_or_default();
    [&b"$SYS._INBOX."[..], &node, b".", &token].concat()
}

/// Answers the pack request `m`, which carries the hash of the asking
/// server: nothing but an empty message if it has the same JWTs, else
/// each JWT in a message of its own, then an empty one.
pub(crate) fn pack(lane: &Lane, out: &mut Outs, m: &Pub<'_>) -> bool {
    let shared = &lane.shared;
    let (Some(dir), Some(sys)) = (shared.resolver.as_ref().filter(|d| d.full), shared.system)
    else {
        return false;
    };
    let Some(reply) = m.reply.filter(|r| !r.is_empty()) else {
        return true;
    };
    let mut send = |payload: &[u8]| {
        let m = Pub {
            subject: reply,
            reply: Some(b""),
            headers: None,
            payload,
        };
        crate::lane::inject(lane, out, sys, &m);
    };
    if m.payload != dir.store.hash() {
        for jwt in dir.store.pack() {
            send(jwt.as_bytes());
        }
    }
    send(b"");
    true
}

/// Takes in the pack `m` that came to this server's pack inbox: the JWTs
/// newer than its own, applied to the accounts in use.
pub(crate) fn packed(lane: &Lane, m: &Pub<'_>) -> bool {
    let shared = &lane.shared;
    let Some(dir) = &shared.resolver else {
        return false;
    };
    if m.payload.is_empty() {
        return true;
    }
    let Ok(changed) = dir.store.merge(&String::from_utf8_lossy(m.payload)) else {
        return true;
    };
    for key in changed {
        let Some(jwt) = dir.store.load(&key) else {
            continue;
        };
        super::stored(lane, &key, &jwt);
    }
    true
}
