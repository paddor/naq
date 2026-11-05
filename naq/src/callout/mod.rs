//! Auth callout, as in `nats-server`: a client logs in as an auth service
//! answers. The server sends a request it signs about the client to
//! `$SYS.REQ.USER.AUTH` in the callout account, and the answer on its
//! reply puts the client in an account with permissions, or keeps it out.
//!
//! The users of the service log in as configured. In config mode the
//! callout is the `auth_callout` block; in operator mode, each account
//! whose JWT names auth users has its own.

pub(crate) mod request;
pub(crate) mod response;
mod waiting;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) use waiting::{Waiting, token};

use crate::auth::{Auth, Check, Creds, GLOBAL};
use crate::jwt::claims;
use crate::lane::Lane;
use crate::perms::Perms;
use crate::server::Shared;
use crate::{AuthCallout, Options};

/// The subject requests go to.
pub(crate) const SUBJECT: &[u8] = b"$SYS.REQ.USER.AUTH";

/// The callouts of a server.
#[derive(Debug)]
pub(crate) struct Callouts {
    /// Config mode: the callout.
    config: Option<Config>,
    /// The accounts services answer in.
    accounts: Vec<u32>,
    /// The requests waiting for answers.
    pub(crate) waiting: Arc<Waiting>,
}

/// The callout of config mode.
#[derive(Debug)]
struct Config {
    /// The account the service answers in.
    account: u32,
    /// The key that signs its answers.
    issuer: String,
    users: Vec<String>,
    /// The accounts whose users call out; empty for all.
    allowed: Vec<u32>,
    /// The service's curve key, if requests are sealed.
    xkey: Option<String>,
}

/// What a client's login goes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Hook {
    /// What it gave decides, as without a callout.
    Keep,
    /// It is a user of the service of account `.0`: what it gave decides,
    /// and in that account it may not publish requests.
    Own(u32),
    /// The service decides.
    Call(Plan),
    /// What it gave decides if its password holds; else the service.
    Verify(Plan),
}

/// A callout to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The account the service answers in.
    account: u32,
    mode: response::Mode,
    xkey: Option<String>,
}

/// A request made, ready to send, and how to check its answer.
#[derive(Debug)]
pub(crate) struct Call {
    pub(crate) ask: response::Ask,
    /// The request: a JWT, or one sealed.
    pub(crate) payload: Vec<u8>,
    /// Headers that name the server's curve key, for a sealed request.
    pub(crate) headers: Option<Vec<u8>>,
}

/// Why options with a callout cannot run.
pub(crate) fn validate(opts: &Options) -> Result<(), String> {
    let Some(c) = &opts.auth_callout else {
        return Ok(());
    };
    if !opts.operators.is_empty() || !opts.trusted_keys.is_empty() {
        return Err(
            "operators do not allow authorization callouts to be configured directly".into(),
        );
    }
    if opts.no_system_account {
        return Err("auth_callout: needs the system account".into());
    }
    let account = |a: &String| opts.accounts.iter().any(|x| x.name == *a);
    if let Some(a) = c.account.as_ref().filter(|a| *a != "$G" && !account(a)) {
        return Err(format!("auth_callout: no account {a:?}"));
    }
    if let Some(a) = c.allowed_accounts.iter().find(|a| !account(a)) {
        return Err(format!(
            "auth_callout: allowed account {a:?} not found in configured accounts"
        ));
    }
    if let Some(u) = c.auth_users.iter().find(|u| !known_user(opts, u)) {
        return Err(format!("auth_callout: no user {u:?}"));
    }
    Ok(())
}

/// Whether `name` names a user of `opts`: by name or NKey, the single
/// one, or that of WebSocket clients.
fn known_user(opts: &Options, name: &str) -> bool {
    let listed = opts.users.iter().any(|u| match &u.login {
        crate::Login::Password { user, .. } => user == name,
        crate::Login::Nkey(key) => key == name,
    });
    let ws = opts.websocket.as_ref().and_then(|w| w.auth.user.as_ref());
    listed
        || opts.user.as_ref().is_some_and(|(u, _)| u == name)
        || ws.is_some_and(|(u, _)| u == name)
}

impl Callouts {
    /// The callouts of `opts`, with `names` the server's accounts by id,
    /// `trust` its operator mode, if any, and `node` the hash of its name.
    pub(crate) fn new(
        opts: &Options,
        names: &[String],
        auth: Option<&Auth>,
        node: [u8; 8],
    ) -> Option<Callouts> {
        let id = |n: &str| names.iter().position(|a| a == n).map(|i| i as u32);
        let config = opts.auth_callout.as_ref().map(|c: &AuthCallout| Config {
            account: c.account.as_deref().and_then(id).unwrap_or(GLOBAL),
            issuer: c.issuer.clone(),
            users: c.auth_users.clone(),
            allowed: c.allowed_accounts.iter().filter_map(|a| id(a)).collect(),
            xkey: c.xkey.clone(),
        });
        let mut accounts: Vec<u32> = config.iter().map(|c| c.account).collect();
        if let Some(t) = auth.and_then(Auth::trust) {
            accounts.extend(t.callouts().map(|a| a.id));
        }
        if accounts.is_empty() {
            return None;
        }
        accounts.sort_unstable();
        accounts.dedup();
        Some(Callouts {
            config,
            accounts,
            waiting: Arc::new(Waiting::new(node)),
        })
    }

    /// Puts the interest of the answers into the indexes of `lane`.
    pub(crate) fn install(&self, lane: &Lane) {
        let filter = self.waiting.filter();
        for &a in &self.accounts {
            lane.index(a).borrow_mut().tap(
                &filter,
                crate::imports::service::Tap::Callout(self.waiting.clone()),
            );
        }
    }

    /// What the login of a client that gave `creds` to `auth`, and got
    /// `normal` from it, goes through: as `nats-server` hooks the callout
    /// in after its own checks.
    pub(crate) fn hook(&self, auth: Option<&Auth>, creds: &Creds, normal: Option<&Check>) -> Hook {
        let Some(c) = &self.config else {
            return operator(auth, creds, normal);
        };
        // As `nats-server` takes them: the accounts it decides on, then the
        // users it is for.
        let kept_out = |account: u32| {
            !c.allowed.is_empty() && account != GLOBAL && !c.allowed.contains(&account)
        };
        let own = auth
            .and_then(|a| a.id_of(creds))
            .is_some_and(|id| c.users.iter().any(|u| u == id));
        let plan = Plan {
            account: c.account,
            mode: response::Mode::Config {
                issuer: c.issuer.clone(),
            },
            xkey: c.xkey.clone(),
        };
        match normal {
            Some(Check::Pass(g)) if kept_out(g.account) => Hook::Keep,
            // In an account it does not decide on if the password holds.
            Some(Check::Bcrypt(p)) if kept_out(p.grant.account) => {
                if own {
                    Hook::Keep
                } else {
                    Hook::Verify(plan)
                }
            }
            _ if own => Hook::Own(c.account),
            _ => Hook::Call(plan),
        }
    }
}

/// Permissions `perms` that deny publishing requests too: those of a client
/// of a callout account the service decided on, or one of its own users.
pub(crate) fn guarded(perms: Option<&Perms>) -> Arc<Perms> {
    Arc::new(Perms::denying(perms, SUBJECT))
}

/// What a login goes through in operator mode: the callout of the account
/// of the user JWT the client gave, where its account has one and the user
/// is none of the service's own.
fn operator(auth: Option<&Auth>, creds: &Creds, normal: Option<&Check>) -> Hook {
    let Some(trust) = auth.and_then(Auth::trust) else {
        return Hook::Keep;
    };
    let Some(user) = creds
        .jwt
        .as_deref()
        .and_then(|j| crate::jwt::decode::<claims::User>(j).ok())
    else {
        return Hook::Keep;
    };
    let issuer = &user.nats.issuer_account;
    let key = if issuer.is_empty() { &user.iss } else { issuer };
    let Some(account) = trust.account(key) else {
        return Hook::Keep;
    };
    let a = &account.claims.nats.authorization;
    if a.auth_users.is_empty() {
        return Hook::Keep;
    }
    if a.auth_users.contains(&user.sub) {
        return Hook::Own(account.id);
    }
    // One that failed its own checks is kept out at once: `nats-server`
    // asks in `$G`, where nobody answers.
    match normal {
        Some(Check::User(u)) if u.account == account.id => Hook::Call(Plan {
            account: account.id,
            mode: response::Mode::Operator {
                key: key.clone(),
                allowed: a.allowed_accounts.clone(),
            },
            xkey: (!a.xkey.is_empty()).then(|| a.xkey.clone()),
        }),
        _ => Hook::Keep,
    }
}

/// The request of `plan` about client `about`, from the server of
/// `shared`, and how to check its answer. The service has `timeout`
/// seconds to answer.
pub(crate) fn call(shared: &Shared, plan: &Plan, about: &request::About<'_>) -> Call {
    let user = nkeys::KeyPair::new_user().public_key();
    let issuer = match &plan.mode {
        response::Mode::Config { issuer } => issuer.as_str(),
        response::Mode::Operator { key, .. } => key.as_str(),
    };
    let now = |after: std::time::Duration| {
        (SystemTime::now() + after)
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs().cast_signed())
    };
    let server_xkey = shared.keys.xkey.public_key();
    let sealed = plan
        .xkey
        .as_deref()
        .and_then(|k| nkeys::XKey::from_public_key(k).ok());
    let from = request::From {
        server: &shared.keys.server,
        name: &shared.opts.server_name,
        host: &shared.opts.host,
        cluster: shared.opts.cluster.as_ref().map_or("", |c| c.name.as_str()),
        issuer,
        user_nkey: &user,
        xkey: sealed.as_ref().map(|_| server_xkey.as_str()),
        iat: now(std::time::Duration::ZERO),
        exp: now(shared.opts.auth_timeout),
    };
    let jwt = request::jwt(&from, about);
    let (payload, headers) = match &sealed {
        // Sealing to a valid key does not fail.
        Some(to) => (
            shared
                .keys
                .xkey
                .seal(jwt.as_bytes(), to)
                .unwrap_or_default(),
            Some(format!("NATS/1.0\r\nNats-Server-Xkey: {server_xkey}\r\n\r\n").into_bytes()),
        ),
        None => (jwt.into_bytes(), None),
    };
    Call {
        ask: response::Ask {
            account: plan.account,
            user_nkey: user,
            mode: plan.mode.clone(),
            sealed_by: sealed,
            user: about.creds.and_then(|c| c.user.clone()),
        },
        payload,
        headers,
    }
}

#[cfg(test)]
mod tests;
