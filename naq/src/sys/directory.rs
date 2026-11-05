//! The `$SYS` services of a directory resolver, as `nats-server` answers
//! them: updates it stores, lookups of the JWTs it has, the list of them,
//! and deletes.

use naq_proto::client::Pub;
use serde_json::{Value, json};

use crate::jwt::trust::dir::Stored;
use crate::lane::{Control, Lane, Outs};

/// Account JWTs to store, not named by the subject.
pub(super) const UPDATE: &[u8] = b"$SYS.REQ.CLAIMS.UPDATE";
/// Lookups of an account JWT: of a full resolver.
pub(super) const LOOKUP: &[u8] = b"$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP";
/// Asks for the accounts stored.
pub(super) const LIST: &[u8] = b"$SYS.REQ.CLAIMS.LIST";
/// Deletes of accounts.
pub(super) const DELETE: &[u8] = b"$SYS.REQ.CLAIMS.DELETE";

/// How an update or delete went: the message, or the message and why not.
type Outcome = Result<String, (String, String)>;

/// Takes account JWT `m` to store: for the account `key` its subject
/// names, if it does. Answers it, and applies it to an account in use.
pub(super) fn update(lane: &Lane, out: &mut Outs, m: &Pub<'_>, key: Option<&str>) -> bool {
    let shared = &lane.shared;
    let (Some(dir), Some(trust)) = (&shared.resolver, super::trust(shared)) else {
        return false;
    };
    let jwt = String::from_utf8_lossy(m.payload);
    let cache = if dir.full { "" } else { " cache" };
    let (account, outcome) = match trust.to_store(key, &jwt, !dir.full) {
        Stored::Store(k) => match dir.store.save(&k, &jwt) {
            Ok(changed) => {
                if changed {
                    crate::resolver::stored(lane, &k, &jwt);
                }
                let done = if dir.full {
                    "jwt updated"
                } else {
                    "jwt updated cache"
                };
                (k, Ok(done.into()))
            }
            Err(e) => (k, Err((format!("jwt update{cache} resulted in error"), e))),
        },
        Stored::Skipped(k) => (k, Ok("jwt update cache skipped".into())),
        Stored::Failed(k, message, why) => (k, Err((message.into(), why))),
    };
    if let Some(reply) = m.reply.filter(|r| !r.is_empty()) {
        super::respond(lane, out, reply, &status(&account, outcome));
    }
    true
}

/// The answer to an update of `account`, if named, that came to
/// `outcome`.
fn status(account: &str, outcome: Outcome) -> Value {
    let mut v = match outcome {
        Ok(message) => json!({"data": {"code": 200, "message": message}}),
        Err((message, why)) => json!({"error": {
            "code": 500,
            "description": format!("{message} - {why}"),
        }}),
    };
    if !account.is_empty()
        && let Some(o) = v.as_object_mut().and_then(|o| o.values_mut().next())
    {
        o["account"] = account.into();
    }
    v
}

/// Answers the lookup `m` with the JWT of the account its subject names,
/// or nothing if the store has none: a full resolver's.
pub(super) fn lookup(lane: &Lane, out: &mut Outs, m: &Pub<'_>) -> bool {
    let Some(dir) = lane.shared.resolver.as_ref().filter(|d| d.full) else {
        return false;
    };
    let Some(reply) = m.reply.filter(|r| !r.is_empty()) else {
        return true;
    };
    let tokens: Vec<&[u8]> = m.subject.split(|&b| b == b'.').collect();
    let Some(key) = tokens.get(3).and_then(|k| std::str::from_utf8(k).ok()) else {
        return true;
    };
    // As `nats-server`: no answer to a key that is none.
    if tokens.len() != 6 || !crate::jwt::is_key(key, 'A') {
        return true;
    }
    let jwt = dir.store.load(key).unwrap_or_default();
    raw(lane, out, reply, jwt.as_bytes());
    true
}

/// Sends `payload` as it is to `reply` in the system account.
fn raw(lane: &Lane, out: &mut Outs, reply: &[u8], payload: &[u8]) {
    let Some(sys) = lane.shared.system else {
        return;
    };
    let m = Pub {
        subject: reply,
        reply: Some(b""),
        headers: None,
        payload,
    };
    crate::lane::inject(lane, out, sys, &m);
}

/// Answers `m` with the keys of the accounts stored, in order.
pub(super) fn list(lane: &Lane, out: &mut Outs, m: &Pub<'_>) -> bool {
    let Some(dir) = &lane.shared.resolver else {
        return false;
    };
    let Some(reply) = m.reply.filter(|r| !r.is_empty()) else {
        return true;
    };
    let mut keys: Vec<String> = dir
        .store
        .pack()
        .into_iter()
        .filter_map(|p| Some(p.split_once('|')?.0.to_owned()))
        .collect();
    keys.sort_unstable();
    super::respond(lane, out, reply, &json!({"data": keys}));
    true
}

/// Deletes the accounts the generic JWT `m` names, if an operator key
/// signed it for itself, and answers it.
pub(super) fn delete(lane: &Lane, out: &mut Outs, m: &Pub<'_>) -> bool {
    let shared = &lane.shared;
    let (Some(dir), Some(trust)) = (&shared.resolver, super::trust(shared)) else {
        return false;
    };
    let jwt = String::from_utf8_lossy(m.payload);
    let outcome = match deletes(lane, &jwt) {
        Err((by, why)) => Err((format!("delete accounts request by {by} failed"), why)),
        Ok(keys) => {
            let mut errs = Vec::new();
            for key in &keys {
                match dir.store.delete(key) {
                    Ok(_) => {
                        if let Some(id) = trust.remove(key) {
                            for l in &shared.lanes {
                                l.control(Control::Refresh { account: id });
                            }
                        }
                    }
                    Err(e) => errs.push(e),
                }
            }
            let done = keys.len() - errs.len();
            if errs.is_empty() {
                Ok(format!("deleted {done} accounts"))
            } else {
                Err((
                    format!("deleted {done} accounts, failed for {}", errs.len()),
                    errs.join("\n"),
                ))
            }
        }
    };
    if let Some(reply) = m.reply.filter(|r| !r.is_empty()) {
        super::respond(lane, out, reply, &status("", outcome));
    }
    true
}

/// The accounts delete request `jwt` names, as `nats-server` checks it;
/// else who asked, and why it does not hold.
fn deletes(lane: &Lane, jwt: &str) -> Result<Vec<String>, (String, String)> {
    let shared = &lane.shared;
    let c = crate::jwt::decode_generic::<Value>(jwt).map_err(|e| (String::new(), e.to_string()))?;
    let fail = |why: &str| Err((c.sub.clone(), why.to_owned()));
    let deletes = shared.resolver.as_ref().is_some_and(|d| d.store.deletes());
    if !deletes {
        return fail("delete must be enabled in server config");
    }
    if c.sub != c.iss {
        return fail("not self signed");
    }
    if !super::trust(shared).is_some_and(|t| t.may_delete(&c.iss)) {
        return fail("not trusted");
    }
    let Some(list) = c.nats.get("accounts").and_then(Value::as_array) else {
        return fail("malformed request");
    };
    let system = shared.system.map(|s| shared.accounts.name(s));
    let mut keys = Vec::with_capacity(list.len());
    for entry in list {
        let Some(key) = entry.as_str().filter(|k| crate::jwt::is_key(k, 'A')) else {
            return fail("malformed request");
        };
        if Some(key) == system {
            return fail("not allowed to delete system account");
        }
        keys.push(key.to_owned());
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_name_their_account_only_if_there_is_one() {
        let ok = status("AX", Ok("jwt updated".into()));
        assert_eq!(
            ok,
            json!({"data": {"account": "AX", "code": 200, "message": "jwt updated"}})
        );
        let failed = status("", Err(("deleted 0 accounts".into(), "no".into())));
        assert_eq!(
            failed,
            json!({"error": {"code": 500, "description": "deleted 0 accounts - no"}})
        );
    }
}
