//! Directory resolvers (`type: full`, `type: cache`): account JWTs kept in
//! a store, and the accounts they add while the server runs, as
//! `nats-server` fetches them for the clients that need them.

pub(crate) mod lookups;
pub(crate) mod sync;

use std::sync::Arc;

use naq_proto::client::Pub;

use crate::jwt::store::Store;
use crate::jwt::trust::live::Status;
use crate::lane::{Control, Lane, Outs};
use crate::{Delete, Options, Resolver};

/// Most accounts one login adds: its own and those it imports from.
const MOST_ADDED: usize = 64;

/// The directory resolver of a server.
#[derive(Debug)]
pub(crate) struct Dir {
    pub(crate) store: Store,
    /// A full resolver, with every account; else a cache.
    pub(crate) full: bool,
    pub(crate) opts: crate::Directory,
    /// Ends the subject of its pack inbox, where the JWTs of the other
    /// servers come.
    pub(crate) pack_token: [u8; 8],
    /// The lookups of JWTs it sent the other servers.
    pub(crate) lookups: Arc<lookups::Lookups>,
}

impl Dir {
    /// The directory resolver of `opts`, if they have one, its store
    /// opened and given the preloads.
    ///
    /// # Errors
    ///
    /// If the directory cannot be made or read.
    pub(crate) fn open(opts: &Options) -> Result<Option<Dir>, String> {
        let (full, d) = match &opts.resolver {
            Some(Resolver::Full(d)) => (true, d),
            Some(Resolver::Cache(d)) => (false, d),
            _ => return Ok(None),
        };
        let limit = d.limit.unwrap_or(if full { usize::MAX } else { 1000 });
        let (delete, ttl) = if full {
            (d.delete, None)
        } else {
            (Delete::Remove, d.ttl)
        };
        let store = Store::open(&d.dir, delete, limit, !full, ttl)
            .map_err(|e| format!("resolver dir {}: {e}", d.dir.display()))?;
        for (key, jwt) in &opts.resolver_preload {
            // As `nats-server`: one that does not go in is only logged.
            let _ = store.save_if_newer(key, jwt);
        }
        Ok(Some(Dir {
            store,
            full,
            opts: d.clone(),
            pack_token: crate::callout::token(),
            lookups: Arc::new(lookups::Lookups::new(crate::server::node(
                &opts.server_name,
            ))),
        }))
    }
}

/// Applies JWT `jwt`, just stored for account `key`, to the account, if
/// the server has it in use: its clients on every lane check themselves
/// again.
pub(crate) fn stored(lane: &Lane, key: &str, jwt: &str) {
    let trust = lane.shared.auth.as_ref().and_then(crate::auth::Auth::trust);
    if let Some(Status::Updated(id)) = trust.map(|t| t.stored(key, jwt)) {
        lane.shared
            .accounts
            .get(id)
            .map(crate::accounts::Account::touch);
        for l in &lane.shared.lanes {
            l.control(Control::Refresh { account: id });
        }
    }
}

/// Fetches account `key` for a client on `lane`, with the accounts it
/// imports from, as `nats-server` builds an account it fetched: each from
/// the store, else from the other servers, their imports linked and their
/// taps on every lane. Its id, if its JWT holds.
pub(crate) async fn fetch(lane: &Lane, key: &str) -> Option<u32> {
    let shared = &lane.shared;
    let dir = shared.resolver.as_ref()?;
    let trust = shared.auth.as_ref()?.trust()?;
    let mut added = Vec::new();
    let mut want = vec![key.to_owned()];
    let mut tried = 0;
    while let Some(k) = want.pop() {
        if tried >= MOST_ADDED || trust.claims_of(&k).is_some() {
            continue;
        }
        tried += 1;
        let jwt = match dir.store.load(&k) {
            Some(jwt) => jwt,
            None => match ask(lane, &k).await {
                // As `nats-server`: stored before it is checked.
                Some(jwt) if dir.store.save_if_newer(&k, &jwt).is_ok() => jwt,
                _ => continue,
            },
        };
        let Some(c) = trust.verified(&k, &jwt) else {
            continue;
        };
        let Some(id) = shared.accounts.add(&k, crate::server::responses) else {
            continue;
        };
        want.extend(c.nats.imports.iter().map(|i| i.account.clone()));
        trust.insert(id, &k, c, &jwt);
        added.push(id);
    }
    if !added.is_empty() {
        link(lane, &added);
    }
    trust.claims_of(key).map(|a| a.id)
}

/// Asks the other servers for the JWT of account `key`, as long as the
/// resolver waits: the first one any has.
async fn ask(lane: &Lane, key: &str) -> Option<String> {
    let shared = &lane.shared;
    let (dir, sys) = (shared.resolver.as_ref()?, shared.system?);
    let servers = lane.servers();
    if servers == 0 {
        return None;
    }
    let (reply, mut ticket) = dir.lookups.wait(servers)?;
    let subject = format!("$SYS.REQ.ACCOUNT.{key}.CLAIMS.LOOKUP");
    let mut out = Outs::new(lane);
    let m = Pub {
        subject: subject.as_bytes(),
        reply: Some(&reply),
        headers: None,
        payload: b"",
    };
    crate::lane::inject(lane, &mut out, sys, &m);
    lane.flush();
    lane.ship_imported(&mut out).await;
    let jwt = tokio::time::timeout(dir.opts.timeout, &mut ticket.answer)
        .await
        .ok()?
        .ok()?;
    (!jwt.is_empty()).then(|| String::from_utf8_lossy(&jwt).into_owned())
}

/// Links the imports of the accounts `added` to the server's, and puts
/// their taps on `lane`; the other lanes are told to.
fn link(lane: &Lane, added: &[u32]) {
    let shared = &lane.shared;
    let Some(trust) = shared.auth.as_ref().and_then(crate::auth::Auth::trust) else {
        return;
    };
    let defs = (0..shared.accounts.len())
        .map(|id| {
            let name = shared.accounts.name(id);
            trust.claims_of(name).map_or_else(
                || crate::imports::defs::Def {
                    name: name.to_owned(),
                    ..Default::default()
                },
                |a| crate::imports::defs::of_jwt(name, &a.claims.nats),
            )
        })
        .collect();
    let mut all = crate::imports::link::relink(defs, shared.system.is_some());
    for &id in added {
        let (Some(a), Some(imports)) = (shared.accounts.get(id), all.get_mut(id as usize)) else {
            continue;
        };
        if !imports.is_empty() {
            a.set_imports(std::mem::take(imports));
        }
        crate::imports::service::install_account(lane, id);
        for (i, tx) in shared.lanes.iter().enumerate() {
            if i != lane.id {
                tx.control(Control::Imports { account: id });
            }
        }
    }
}
