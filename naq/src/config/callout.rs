//! `authorization { auth_callout { issuer, account, auth_users, xkey,
//! allowed_accounts } }`, as `nats-server` reads it.

use super::parse::{Item, Value};
use super::{Bad, string};
use crate::AuthCallout;

/// The `auth_callout` (or `auth_hook`) block `item`.
pub(super) fn callout(item: &Item) -> Result<AuthCallout, Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "auth_callout: expected a map".into()));
    };
    let mut c = AuthCallout {
        issuer: String::new(),
        account: None,
        auth_users: Vec::new(),
        xkey: None,
        allowed_accounts: Vec::new(),
    };
    for (k, v) in m {
        let k = k.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("auth_callout: {k}: {reason}"));
        let text = || string(v).ok_or_else(|| bad("expected a string"));
        let list = || names(v).ok_or_else(|| bad("expected a list of strings"));
        match k.as_str() {
            "issuer" => {
                c.issuer = text()?;
                if !crate::jwt::is_key(&c.issuer, 'A') {
                    return Err(bad("expected a public account NKey"));
                }
            }
            "account" | "acc" => c.account = Some(text()?),
            "auth_users" | "users" => c.auth_users = list()?,
            "xkey" | "key" => {
                let key = text()?;
                if !is_curve_key(&key) {
                    return Err(bad("expected a public curve key"));
                }
                c.xkey = Some(key);
            }
            "allowed_accounts" => c.allowed_accounts = list()?,
            _ => return Err(bad("not supported")),
        }
    }
    if c.issuer.is_empty() {
        return Err((item.line, "auth_callout: an issuer is required".into()));
    }
    if c.auth_users.is_empty() {
        return Err((item.line, "auth_callout: auth_users are required".into()));
    }
    Ok(c)
}

/// Whether `key` is a public curve key (`X...`).
pub(crate) fn is_curve_key(key: &str) -> bool {
    key.starts_with('X') && nkeys::XKey::from_public_key(key).is_ok()
}

/// A list of strings, not a single one.
fn names(item: &Item) -> Option<Vec<String>> {
    match &item.value {
        Value::Array(a) => a.iter().map(string).collect(),
        _ => None,
    }
}
