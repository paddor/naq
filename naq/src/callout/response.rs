//! The answer of an auth service, checked as `nats-server` checks it, and
//! the user it lets in. Every answer that does not hold keeps the client
//! out the same way; why goes nowhere but here.

use std::time::{Duration, UNIX_EPOCH};

use crate::ConnectionType;
use crate::jwt::claims::{self, NO_LIMIT};
use crate::jwt::trust::{self, User};
use crate::jwt::{Claims, decode, is_key, now};
use crate::server::Shared;

/// Whose answers a callout takes, and where they put clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Config mode: answers come signed by `issuer`, and name the account
    /// they put a client in.
    Config { issuer: String },
    /// Operator mode: answers come signed by the callout account `key` or
    /// one of its signing keys; a client goes to the account that issued
    /// its user, that or one `allowed`.
    Operator { key: String, allowed: Vec<String> },
}

/// What an answer must hold to.
#[derive(Debug)]
pub(crate) struct Ask {
    /// The account the service answers in.
    pub(crate) account: u32,
    /// The user key the answer must name.
    pub(crate) user_nkey: String,
    pub(crate) mode: Mode,
    /// The service's curve key, where requests and answers may be sealed.
    pub(crate) sealed_by: Option<nkeys::XKey>,
    /// The user name the client gave: it stays, unless the answer names
    /// another.
    pub(crate) user: Option<String>,
}

/// The user answer `payload` lets in, for a client connecting as `kind`
/// to the server of `shared`; why not, if not.
pub(crate) fn decide(
    ask: &Ask,
    payload: &[u8],
    shared: &Shared,
    kind: ConnectionType,
) -> Result<User, String> {
    if payload.is_empty() {
        return Err("no reason supplied".into());
    }
    let (text, sealed) = match &ask.sealed_by {
        Some(from) if !payload.starts_with(b"eyJ") => {
            let open = shared
                .keys
                .xkey
                .open(payload, from)
                .map_err(|e| format!("error decrypting auth callout response: {e}"))?;
            (open, true)
        }
        _ => (payload.to_vec(), false),
    };
    let text = String::from_utf8(text).map_err(|_| "not a JWT".to_owned())?;
    let r = decode::<claims::AuthResponse>(&text).map_err(|e| e.to_string())?;
    let trust = shared.auth.as_ref().and_then(crate::auth::Auth::trust);
    holds(&r, ask, &shared.server_id, sealed, trust)?;
    let user = decode::<claims::User>(&r.nats.jwt).map_err(|e| e.to_string())?;
    if user.out_of_time(now()) {
        return Err("user JWT is expired".into());
    }
    if user.sub != ask.user_nkey {
        return Err("user JWT is not for the expected user".into());
    }
    let mut u = match &ask.mode {
        Mode::Config { issuer } => placed(&user, issuer, shared, kind)?,
        Mode::Operator { key, allowed } => trust
            .ok_or_else(|| "no operator".to_owned())?
            .placed(&user, key, allowed, kind)?,
    };
    u.key = if user.name.is_empty() {
        ask.user.clone().unwrap_or_default()
    } else {
        user.name.clone()
    };
    Ok(u)
}

/// Why answer `r` does not hold for `ask`, at a server of ID `server` and
/// operator mode `trust`, if any; a sealed one needs no issuer check, as
/// in `nats-server`: the seal tells who sent it.
fn holds(
    r: &Claims<claims::AuthResponse>,
    ask: &Ask,
    server: &str,
    sealed: bool,
    trust: Option<&trust::Trust>,
) -> Result<(), String> {
    let n = &r.nats;
    if !is_key(&r.sub, 'U') || !is_key(&r.aud, 'N') {
        return Err("subject or audience is not a user and a server key".into());
    }
    if n.jwt.is_empty() == n.error.is_empty() {
        return Err("only one of error and jwt must be set".into());
    }
    if !n.issuer_account.is_empty() && !is_key(&n.issuer_account, 'A') {
        return Err("issuer_account is not an account key".into());
    }
    if r.out_of_time(now()) {
        return Err("response is expired".into());
    }
    if r.sub != ask.user_nkey {
        return Err("response is not for the expected user".into());
    }
    if r.aud != server {
        return Err("response is not for this server".into());
    }
    if !sealed {
        let signed = match &ask.mode {
            Mode::Config { issuer } => r.iss == *issuer,
            Mode::Operator { key, .. } => {
                let signs = |iss: &String| {
                    trust
                        .and_then(|t| t.account(key))
                        .is_some_and(|a| a.claims.nats.signing_keys.0.contains_key(iss))
                };
                (n.issuer_account.is_empty() || n.issuer_account == *key)
                    && (r.iss == *key || signs(&r.iss))
            }
        };
        if !signed {
            return Err("auth callout signing key is unknown".into());
        }
    }
    if !n.error.is_empty() {
        return Err(format!(
            "auth callout service returned an error: {}",
            n.error
        ));
    }
    Ok(())
}

/// The user of user JWT `user` in config mode: signed by the callout's
/// `issuer`, in the account its audience names.
fn placed(
    user: &Claims<claims::User>,
    issuer: &str,
    shared: &Shared,
    kind: ConnectionType,
) -> Result<User, String> {
    if !user.nats.issuer_account.is_empty() {
        return Err("issuer_account outside operator mode".into());
    }
    if user.iss != issuer {
        return Err(format!("wrong issuer, expected {issuer:?}"));
    }
    let account = shared
        .accounts
        .iter()
        .position(|a| *a == user.aud)
        .ok_or_else(|| format!("no valid account {:?}", user.aud))?;
    let limits = &user.nats.limits;
    let end = trust::time_left(limits)?;
    if !trust::connects_as(limits, kind) {
        return Err("not allowed to use connection type".into());
    }
    let exp = (user.exp > 0).then(|| UNIX_EPOCH + Duration::from_secs(user.exp.cast_unsigned()));
    Ok(User {
        // Accounts are few: their count fits.
        account: account as u32,
        perms: trust::defaults(&limits.permissions),
        key: String::new(),
        subs: NO_LIMIT,
        payload: NO_LIMIT,
        conns: NO_LIMIT,
        expires: [exp, end].into_iter().flatten().min(),
    })
}

#[cfg(test)]
mod tests;
