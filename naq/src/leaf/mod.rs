//! Leaf node links this server dials: one per remote, on a lane of its
//! own, dialing again whenever it ends.

mod creds;
mod link;
mod side;
mod tls;
pub(crate) mod url;

pub(crate) use link::{LOOP_DELAY, err_delay, loop_error};
pub(crate) use side::{Facts, LinkSide};
pub(crate) use tls::Connector;
pub(crate) use url::HubUrl;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use naq_proto::client::Pub;
use naq_proto::subject;

use crate::lane;
use crate::server::Shared;

/// The URLs a hub told of last: of its cluster's leaf node ports, and of
/// its WebSocket ports.
#[derive(Debug, Default)]
pub(super) struct Told {
    pub(super) nats: Vec<String>,
    pub(super) ws: Vec<String>,
}

/// How a link ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ended {
    /// The hub could not be reached.
    Unreached,
    /// It ended, and the hub asked to wait this long beyond the interval.
    Closed { delay: Duration },
}

/// Message `m` of a hub as a client gets it, if it differs: a JetStream
/// ack reply that ends in `@` and a subject was matched for that subject,
/// which the client gets with the reply before the `@`, as `nats-server`
/// hands it on.
pub(crate) fn for_clients<'a>(m: &Pub<'a>) -> Option<Pub<'a>> {
    let reply = m
        .reply
        .filter(|r| r.len() > 8 && r.starts_with(b"$JS.ACK."))?;
    let mut dots = 0;
    let at = reply.iter().position(|&b| {
        dots += usize::from(b == b'.');
        b == b'@' && dots >= 8
    })?;
    (at + 1 < reply.len()).then(|| Pub {
        subject: &reply[at + 1..],
        reply: Some(&reply[..at]),
        ..*m
    })
}

/// A fresh loop detection subject: `$LDS.` and 22 random letters and
/// digits, as `nats-server` makes them.
pub(crate) fn lds() -> String {
    use std::hash::{BuildHasher, Hasher};
    const DIGITS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let state = std::collections::hash_map::RandomState::new();
    let mut s = String::from("$LDS.");
    for i in 0..22u8 {
        let mut h = state.build_hasher();
        h.write_u8(i);
        s.push(char::from(
            DIGITS[(h.finish() % DIGITS.len() as u64) as usize],
        ));
    }
    s
}

/// Why `opts.remotes` and `opts.leafnodes` cannot run as given.
pub(crate) fn validate(opts: &crate::Options) -> Result<(), String> {
    if let Some(a) = opts.leafnodes.as_ref().and_then(|l| l.account.as_deref())
        && a != "$G"
        && !opts.accounts.iter().any(|x| x == a)
    {
        return Err(format!("leafnodes: no account {a:?}"));
    }
    let mut seen = Vec::new();
    for r in &opts.remotes {
        if r.urls.is_empty() {
            return Err("leafnode remote without a url".into());
        }
        let urls = r
            .urls
            .iter()
            .map(|u| HubUrl::parse(u))
            .collect::<Result<Vec<_>, _>>()?;
        if urls.iter().any(|u| u.ws.is_some()) && urls.iter().any(|u| u.ws.is_none()) {
            return Err("leafnode remote: websocket and other urls mixed".into());
        }
        if urls.iter().any(|u| u.naq) {
            naq_remote(r, &urls)?;
        }
        if let Some(a) = r.account.as_deref()
            && a != "$G"
            && !opts.accounts.iter().any(|x| x == a)
        {
            return Err(format!("leafnode remote: no account {a:?}"));
        }
        for (key, list) in [
            ("deny_imports", &r.deny_imports),
            ("deny_exports", &r.deny_exports),
        ] {
            if let Some(s) = list
                .iter()
                .find(|s| !subject::is_valid_filter(s.as_bytes()))
            {
                return Err(format!("leafnode remote: {key}: invalid subject {s:?}"));
            }
        }
        if r.credentials.is_some() && r.nkey.is_some() {
            return Err("leafnode remote: both credentials and an nkey".into());
        }
        // The seed stays out of the message: it is a secret.
        if r.nkey.as_deref().is_some_and(|s| !creds::is_user_seed(s)) {
            return Err("leafnode remote: nkey is not a user seed".into());
        }
        let key = (
            r.account.as_deref().unwrap_or("$G"),
            urls,
            &r.credentials,
            &r.nkey,
        );
        if seen.contains(&key) {
            return Err("leafnode remotes: the same account, urls and credentials twice".into());
        }
        seen.push(key);
    }
    Ok(())
}

/// Why remote `r` of a naq hub at `urls` cannot run as given: its URLs are
/// all naq ones, and it has none of what a Go hub takes.
fn naq_remote(r: &crate::Remote, urls: &[HubUrl]) -> Result<(), String> {
    if !urls.iter().all(|u| u.naq) {
        return Err("leafnode remote: naq and other urls mixed".into());
    }
    let more = r.credentials.is_some()
        || r.nkey.is_some()
        || r.tls.is_some()
        || !r.deny_imports.is_empty()
        || !r.deny_exports.is_empty()
        || r.request_isolation
        || urls.iter().any(|u| u.user.is_some());
    if more {
        return Err("leafnode remote: naq url with options it takes no part of".into());
    }
    Ok(())
}

/// Whether remote `r` dials a naq hub, over OMQ. Of a valid remote.
pub(crate) fn is_naq(r: &crate::Remote) -> bool {
    r.urls
        .first()
        .and_then(|u| HubUrl::parse(u).ok())
        .is_some_and(|u| u.naq)
}

/// Serves remote `index` on lane `lane`: dials its hub, serves the link,
/// and dials again once it ends, as `nats-server` does.
pub(crate) async fn run(shared: Arc<Shared>, lane: usize, index: usize) {
    let Some(lane) = lane::get(shared.id, lane) else {
        return;
    };
    let remote = &shared.opts.remotes[index];
    // Valid: the options were checked.
    let all: Vec<HubUrl> = remote
        .urls
        .iter()
        .filter_map(|u| HubUrl::parse(u).ok())
        .collect();
    let mut urls: VecDeque<HubUrl> = all.iter().cloned().collect();
    if !remote.no_randomize {
        for i in (1..urls.len()).rev() {
            let j = lane.below(i as u64 + 1) as usize;
            urls.swap(i, j);
        }
    }
    let interval = shared.opts.leaf_reconnect;
    let told = RefCell::new(None);
    loop {
        let Some(url) = urls.pop_front() else {
            return;
        };
        urls.push_back(url.clone());
        let wait = match link::session(&lane, index, &url, &all, &told).await {
            // Some jitter, so leafs do not dial a hub in step.
            Ended::Unreached => interval + interval.mul_f64(lane.below(1000) as f64 / 1000.0),
            Ended::Closed { delay } => interval + delay,
        };
        // The hub's latest word on its cluster, as `nats-server` takes it.
        if let Some(t) = told.take() {
            let found = if all.first().is_some_and(|u| u.ws.is_some()) {
                t.ws
            } else {
                t.nats
            };
            urls = url::rebuild(&found, &all).into();
        }
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_reply(reply: &[u8]) -> Pub<'_> {
        Pub {
            subject: b"_INBOX.x",
            reply: Some(reply),
            headers: None,
            payload: b"hi",
        }
    }

    #[test]
    fn clients_get_a_jetstream_message_of_a_hub_for_its_own_subject() {
        let m = with_reply(b"$JS.ACK.S.C.1.2.3.4.0@orders.1");
        let got = for_clients(&m).unwrap();
        assert_eq!(got.subject, b"orders.1");
        assert_eq!(got.reply, Some(&b"$JS.ACK.S.C.1.2.3.4.0"[..]));
        assert_eq!(got.payload, b"hi");
        // An `@` in a stream name comes before the eighth dot.
        let named = with_reply(b"$JS.ACK.S@x.C.1.2.3.4.0@orders.1");
        assert_eq!(for_clients(&named).unwrap().subject, b"orders.1");
        for plain in [
            &b"$JS.ACK.S.C.1.2.3.4.0"[..],
            b"$JS.ACK.S.C.1.2.3.4.0@",
            b"_INBOX.y@orders.1",
            b"$JS.ACK.",
        ] {
            assert!(for_clients(&with_reply(plain)).is_none(), "{plain:?}");
        }
        assert!(for_clients(&Pub { reply: None, ..m }).is_none());
    }
}
