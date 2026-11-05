//! Account JWTs that change while the server runs, as `nats-server` takes
//! them: an update is checked and put in place of the old claims, then the
//! account's users check themselves again against it.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{JwtAccount, Trust, tighter};
use crate::jwt::claims::{self, NO_LIMIT};
use crate::jwt::{Claims, decode, now};
use crate::perms::Perms;

/// What a connection keeps of how it logged in, to check itself again once
/// its account changes.
#[derive(Debug, Clone)]
pub(crate) struct Kept {
    /// The public key of its account.
    pub(crate) account: String,
    /// The user JWT it gave, if any: a callout user has none.
    pub(crate) jwt: Option<String>,
    /// The user's key, and when its JWT was issued.
    pub(crate) key: String,
    pub(crate) iat: i64,
    /// The signing key that issued its user, if not the account itself,
    /// and the template that key had then.
    pub(crate) signer: Option<(String, Option<claims::UserLimits>)>,
    /// The account's default permissions it got, if it has none of its
    /// own: `None` if it has.
    pub(crate) defaults: Option<Defaults>,
    /// Its own limits, before the account's: most subscriptions, largest
    /// payload, and when it expires.
    pub(crate) subs: i64,
    pub(crate) payload: i64,
    pub(crate) expires: Option<SystemTime>,
}

/// The default permissions of an account: none, or these.
#[derive(Debug, Clone)]
pub(crate) struct Defaults(pub(crate) Option<Arc<Perms>>);

impl Defaults {
    /// Whether these are `other`, the same permissions.
    fn same(&self, other: Option<&Arc<Perms>>) -> bool {
        match (&self.0, other) {
            (Some(x), Some(y)) => Arc::ptr_eq(x, y),
            (x, y) => x.is_none() && y.is_none(),
        }
    }
}

/// What becomes of a user once its account changed.
#[derive(Debug, Clone)]
pub(crate) enum Refresh {
    /// It stays, with these limits now.
    Stays(Stays),
    /// It goes: why.
    Goes(Gone),
}

/// The limits of a user that stays.
#[derive(Debug, Clone)]
pub(crate) struct Stays {
    pub(crate) subs: i64,
    pub(crate) payload: i64,
    /// Most connections of the account.
    pub(crate) conns: i64,
    /// The account's new default permissions, if the user takes them and
    /// they changed.
    pub(crate) defaults: Option<Defaults>,
    /// When it may no longer be connected, and whether its account's
    /// expiry is what ends it.
    pub(crate) expires: Option<(SystemTime, bool)>,
}

/// Why a user goes once its account changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gone {
    /// The account is gone or expired.
    Expired,
    /// The account revoked it.
    Revoked,
    /// It is a bearer user, and the account no longer takes them, or its
    /// JWT no longer reads.
    Bearer,
    /// The signing key that issued it is gone, or its template changed.
    Unsigned,
}

/// How an update of account `key` went: as `nats-server` answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    /// The account takes the claims: its id.
    Updated(u32),
    /// The same claims again.
    Same,
    /// No such account is loaded.
    Skipped,
    /// The update does not hold: the message, then why.
    Failed(&'static str, String),
}

impl Trust {
    /// Takes account JWT `jwt`, sent to update account `key`, as
    /// `nats-server` takes it with a memory resolver: an account loaded
    /// gets the claims, if they hold.
    pub(crate) fn update(&self, key: &str, jwt: &str) -> Status {
        let failed = |why: String| Status::Failed("jwt update resulted in error", why);
        if jwt.is_empty() {
            return Status::Failed("jwt update error", "request body is empty".into());
        }
        let claims = match decode::<claims::Account>(jwt) {
            Ok(c) => c,
            Err(e) => return failed(e.to_string()),
        };
        if claims.sub != key {
            return failed("subject does not match jwt content".into());
        }
        let Ok(mut all) = self.accounts.write() else {
            return Status::Skipped;
        };
        let Some(old) = all.get(key).filter(|a| a.is_loaded()) else {
            return Status::Skipped;
        };
        if old.jwt == jwt {
            return Status::Same;
        }
        let trusted = self.signers.contains(&claims.iss);
        if !trusted
            || claims.out_of_time(now())
            || super::super::validate::account(&claims).is_err()
        {
            return failed("account validation failed".into());
        }
        let account = JwtAccount::new(old.id, claims, jwt.to_owned());
        account.load();
        let id = account.id;
        all.insert(key.to_owned(), Arc::new(account));
        Status::Updated(id)
    }

    /// What becomes of the user that logged in as `kept`, now its account
    /// may have changed, as `nats-server` checks its clients after an
    /// update.
    pub(crate) fn refresh(&self, kept: &Kept) -> Refresh {
        let Some(account) = self.account(&kept.account) else {
            return Refresh::Goes(Gone::Expired);
        };
        let a = &account.claims;
        if a.out_of_time(now()) {
            return Refresh::Goes(Gone::Expired);
        }
        if let Some(gone) = revoked(a, kept) {
            return Refresh::Goes(gone);
        }
        if let Some((key, scope)) = &kept.signer {
            match a.nats.signing_keys.0.get(key) {
                Some(now) if now.as_ref().map(|s| &s.template) == scope.as_ref() => {}
                _ => return Refresh::Goes(Gone::Unsigned),
            }
        }
        let defaults = kept
            .defaults
            .as_ref()
            .filter(|had| !had.same(account.defaults.as_ref()))
            .map(|_| Defaults(account.defaults.clone()));
        let user_end = kept.expires.map(|t| (t, false));
        let account_end = (a.exp > 0).then(|| (at(a.exp), true));
        Refresh::Stays(Stays {
            subs: tighter(kept.subs, a.nats.limits.subs),
            payload: tighter(kept.payload, a.nats.limits.payload),
            conns: a.nats.limits.conn,
            defaults,
            expires: [user_end, account_end].into_iter().flatten().min(),
        })
    }
}

/// Why account `a` revokes the user of `kept`, if it does: by its JWT,
/// which it reads again where the account revokes or refuses bearers, or
/// by its key and the time it was issued, for a callout user.
fn revoked(a: &Claims<claims::Account>, kept: &Kept) -> Option<Gone> {
    let revocations = &a.nats.revocations;
    let disallow = a.nats.limits.disallow_bearer;
    let revoked = |key: &str, iat: i64| {
        let by = |k: &str| revocations.get(k).is_some_and(|&t| t >= iat);
        by(key) || by("*")
    };
    match &kept.jwt {
        Some(jwt) if !revocations.is_empty() || disallow => {
            let Ok(user) = decode::<claims::User>(jwt) else {
                return Some(Gone::Bearer);
            };
            if user.nats.limits.bearer_token && disallow {
                return Some(Gone::Bearer);
            }
            // As nats-io/jwt: a user of no issue time is revoked too.
            (user.iat == 0 || revoked(&user.sub, user.iat)).then_some(Gone::Revoked)
        }
        None if kept.iat > 0 && revoked(&kept.key, kept.iat) => Some(Gone::Revoked),
        _ => None,
    }
}

/// When `t` is, in seconds since the epoch.
fn at(t: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(t.cast_unsigned())
}

impl Kept {
    /// What a callout user in account `account` keeps: its key, and when
    /// its JWT was issued.
    pub(crate) fn of_callout(account: &str, user: &Claims<claims::User>) -> Kept {
        Kept {
            account: account.to_owned(),
            jwt: None,
            key: user.sub.clone(),
            iat: user.iat,
            signer: None,
            defaults: None,
            subs: NO_LIMIT,
            payload: NO_LIMIT,
            expires: None,
        }
    }
}

#[cfg(test)]
mod tests;
