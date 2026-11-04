//! Leaf node links this server dials: one per remote, on a lane of its
//! own, dialing again whenever it ends.

mod creds;
mod link;
mod side;
mod tls;
mod url;

pub(crate) use side::LinkSide;
pub(crate) use tls::Connector;
pub(crate) use url::HubUrl;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use crate::lane;
use crate::server::Shared;

/// How a link ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ended {
    /// The hub could not be reached.
    Unreached,
    /// It ended, and the hub asked to wait this long beyond the interval.
    Closed { delay: Duration },
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

/// Why `opts.remotes` cannot run as given.
pub(crate) fn validate(opts: &crate::Options) -> Result<(), String> {
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
        if let Some(a) = r.account.as_deref()
            && a != "$G"
            && !opts.accounts.iter().any(|x| x == a)
        {
            return Err(format!("leafnode remote: no account {a:?}"));
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
    loop {
        let Some(url) = urls.pop_front() else {
            return;
        };
        urls.push_back(url.clone());
        let wait = match link::session(&lane, index, &url, &all).await {
            // Some jitter, so leafs do not dial a hub in step.
            Ended::Unreached => interval + interval.mul_f64(lane.below(1000) as f64 / 1000.0),
            Ended::Closed { delay } => interval + delay,
        };
        tokio::time::sleep(wait).await;
    }
}
