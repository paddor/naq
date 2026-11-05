//! Accounts a directory resolver adds while the server runs, and the
//! updates it stores, as `nats-server` takes them.

use std::sync::Arc;

use super::live::Status;
use super::{JwtAccount, Trust};
use crate::jwt::claims::{self, Account};
use crate::jwt::{Claims, decode};

/// What a directory resolver makes of an update: as `nats-server`
/// answers it, and the claims to store if it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stored {
    /// It holds: store it, under this account.
    Store(String),
    /// A cache skips an account not in use: this one.
    Skipped(String),
    /// It does not hold: the account to name, the message, then why.
    Failed(String, &'static str, String),
}

impl Trust {
    /// The account a user of JWT `jwt` is of, if its JWT holds and the
    /// server has no such account yet: one a resolver may fetch.
    pub(crate) fn missing(&self, jwt: &str) -> Option<String> {
        let user = decode::<claims::User>(jwt).ok()?;
        let issuer = &user.nats.issuer_account;
        let key = if issuer.is_empty() {
            user.iss
        } else {
            issuer.clone()
        };
        let known = self.accounts.read().ok()?.contains_key(&key);
        (!known && crate::jwt::is_key(&key, 'A')).then_some(key)
    }

    /// The claims of account JWT `jwt`, if they are of account `key`,
    /// signed by a key the server trusts, and hold: as `nats-server`
    /// checks a JWT it fetched.
    pub(crate) fn verified(&self, key: &str, jwt: &str) -> Option<Claims<Account>> {
        let c = decode::<Account>(jwt).ok()?;
        let holds = c.sub == key
            && self.signers.contains(&c.iss)
            && crate::jwt::validate::account(&c).is_ok();
        holds.then_some(c)
    }

    /// Takes account `key` of claims `c`, from JWT `jwt`, as account `id`
    /// of the server: loaded, as the resolver fetched it for a client.
    pub(crate) fn insert(&self, id: u32, key: &str, c: Claims<Account>, jwt: &str) {
        let account = JwtAccount::new(id, c, jwt.to_owned());
        account.load();
        if let Ok(mut all) = self.accounts.write() {
            all.entry(key.to_owned())
                .or_insert_with(|| Arc::new(account));
        }
    }

    /// The claims of account `key`, if the server has them.
    pub(crate) fn claims_of(&self, key: &str) -> Option<Arc<JwtAccount>> {
        self.accounts.read().ok()?.get(key).cloned()
    }

    /// Forgets account `key`, deleted: its id, if it had one. Its users
    /// then find no account.
    pub(crate) fn remove(&self, key: &str) -> Option<u32> {
        self.accounts.write().ok()?.remove(key).map(|a| a.id)
    }

    /// Whether the server may delete accounts on behalf of `iss`: an
    /// operator key it trusts, or one of their signing keys.
    pub(crate) fn may_delete(&self, iss: &str) -> bool {
        self.signers.iter().any(|s| s == iss)
    }

    /// What a directory resolver makes of account JWT `jwt`, sent on
    /// `subject_key`'s update subject if given, else on
    /// `$SYS.REQ.CLAIMS.UPDATE`; `cache` if it is a cache, which only
    /// takes accounts in use. As `nats-server` checks it, in its order.
    pub(crate) fn to_store(&self, subject_key: Option<&str>, jwt: &str, cache: bool) -> Stored {
        let (error, invalid) = if cache {
            (
                "jwt update cache resulted in error",
                "jwt update cache validation failed",
            )
        } else {
            ("jwt update resulted in error", "jwt validation failed")
        };
        let named = |c: &str| subject_key.unwrap_or(c).to_owned();
        let c = match decode::<Account>(jwt) {
            Ok(c) => c,
            Err(e) => {
                let who = if cache { subject_key } else { None };
                return Stored::Failed(who.unwrap_or("n/a").into(), error, e.to_string());
            }
        };
        let strict = self.strict && c.iss == self.operator;
        let invalid_now =
            || crate::jwt::validate::account(&c).map_err(|e| format!("validation errors: [{e}]"));
        let mismatch = subject_key.is_some_and(|k| k != c.sub);
        if !cache && subject_key.is_some() {
            // A full resolver checks the claims before the subject.
            if let Err(e) = invalid_now() {
                return Stored::Failed(c.sub.clone(), invalid, e);
            }
        }
        if mismatch {
            let why = "subject does not match jwt content".into();
            return Stored::Failed(named(&c.sub), error, why);
        }
        if strict {
            let why = "operator requires issuer to be a signing key".into();
            return Stored::Failed(named(&c.sub), error, why);
        }
        if !cache
            && subject_key.is_none()
            && let Err(e) = invalid_now()
        {
            return Stored::Failed(c.sub.clone(), invalid, e);
        }
        if cache && self.claims_of(&c.sub).is_none_or(|a| !a.is_loaded()) {
            return Stored::Skipped(named(&c.sub));
        }
        if cache && let Err(e) = invalid_now() {
            return Stored::Failed(c.sub.clone(), invalid, e);
        }
        Stored::Store(c.sub)
    }

    /// Applies the JWT `jwt` a directory resolver stored for account
    /// `key`, as a memory resolver takes an update: to an account in use,
    /// if the JWT holds. `nats-server` logs what does not.
    pub(crate) fn stored(&self, key: &str, jwt: &str) -> Status {
        self.update(key, jwt)
    }
}
