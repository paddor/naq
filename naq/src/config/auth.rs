//! `authorization`, `accounts` and `no_auth_user`.

use std::time::Duration;

use super::parse::{Item, Value};
use super::{Bad, string};
use crate::{Login, Options, Permissions, Responses, Rules, User};

/// `authorization { user, password, token, timeout, users }`.
pub(super) fn authorization(o: &mut Options, item: &Item) -> Result<(), Bad> {
    let map = map(item, "authorization")?;
    let (mut user, mut password) = (None, None);
    for (key, v) in map {
        let key = key.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("authorization: {key}: {reason}"));
        match key.as_str() {
            "user" | "username" => user = Some(string(v).ok_or_else(|| bad("expected a string"))?),
            "pass" | "password" => {
                password = Some(string(v).ok_or_else(|| bad("expected a string"))?);
            }
            "token" => o.token = Some(string(v).ok_or_else(|| bad("expected a string"))?),
            "timeout" => {
                o.auth_timeout = timeout(v).ok_or_else(|| bad("expected seconds or a duration"))?;
            }
            "users" => o.users.extend(users(v, None)?),
            "default_permissions" | "default_permission" | "permissions" => {
                o.default_permissions = Some(permissions(v)?);
            }
            _ => return Err(bad("not supported")),
        }
    }
    match (user, password) {
        (Some(user), password) => o.users.push(User {
            login: Login::Password {
                user,
                password: password.unwrap_or_default(),
            },
            account: None,
            permissions: None,
        }),
        (None, Some(_)) => return Err((item.line, "authorization: password without user".into())),
        (None, None) => {}
    }
    Ok(())
}

/// `accounts { NAME { users } }`, or `accounts [NAME]`.
pub(super) fn accounts(o: &mut Options, item: &Item) -> Result<(), Bad> {
    let mut add = |name: &str, line: u32| {
        if name == "$G" {
            return Err((line, format!("accounts: {name:?} is a reserved account")));
        }
        if o.accounts.iter().any(|a| a == name) {
            return Err((line, format!("accounts: {name:?} twice")));
        }
        o.accounts.push(name.to_owned());
        Ok(())
    };
    match &item.value {
        Value::Array(names) => {
            for n in names {
                let name = string(n).ok_or_else(|| (n.line, "accounts: expected names".into()))?;
                add(&name, n.line)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            let mut found = Vec::new();
            for (name, v) in entries {
                add(name, v.line)?;
                for (key, field) in map(v, "accounts")? {
                    match key.to_ascii_lowercase().as_str() {
                        "users" => found.extend(users(field, Some(name))?),
                        k => {
                            return Err((
                                field.line,
                                format!("accounts: {name}: {k}: not supported"),
                            ));
                        }
                    }
                }
            }
            o.users.extend(found);
            Ok(())
        }
        _ => Err((item.line, "accounts: expected a map or a list".into())),
    }
}

/// A `users` list: each user a map of `user` and `password`, or of `nkey`.
fn users(item: &Item, account: Option<&str>) -> Result<Vec<User>, Bad> {
    let Value::Array(list) = &item.value else {
        return Err((item.line, "users: expected a list".into()));
    };
    list.iter()
        .map(|u| {
            let (mut user, mut password, mut nkey, mut perms) = (None, None, None, None);
            for (key, v) in map(u, "users")? {
                let key = key.to_ascii_lowercase();
                let bad = |reason: &str| (v.line, format!("users: {key}: {reason}"));
                match key.as_str() {
                    "user" | "username" => {
                        user = Some(string(v).ok_or_else(|| bad("expected a string"))?);
                    }
                    "pass" | "password" => {
                        password = Some(string(v).ok_or_else(|| bad("expected a string"))?);
                    }
                    "permissions" | "permission" | "authorization" => perms = Some(permissions(v)?),
                    "nkey" => {
                        let k = string(v).ok_or_else(|| bad("expected a string"))?;
                        if !crate::auth::is_user_nkey(&k) {
                            return Err(bad("not a public user NKey"));
                        }
                        nkey = Some(k);
                    }
                    _ => return Err(bad("not supported")),
                }
            }
            let account = account.map(str::to_owned);
            if let Some(key) = nkey {
                if user.is_some() || password.is_some() {
                    return Err((u.line, "users: an NKey user has no name or password".into()));
                }
                return Ok(User {
                    login: Login::Nkey(key),
                    account,
                    permissions: perms,
                });
            }
            let user = user.ok_or_else(|| (u.line, "users: a user needs a name".to_owned()))?;
            Ok(User {
                login: Login::Password {
                    user,
                    password: password.unwrap_or_default(),
                },
                account,
                permissions: perms,
            })
        })
        .collect()
}

fn map<'i>(item: &'i Item, what: &str) -> Result<&'i [(String, Item)], Bad> {
    match &item.value {
        Value::Map(m) => Ok(m),
        _ => Err((item.line, format!("{what}: expected a map"))),
    }
}

/// Seconds, whole or not, or a duration.
fn timeout(item: &Item) -> Option<Duration> {
    match &item.value {
        Value::Int(n) => u64::try_from(*n).ok().map(Duration::from_secs),
        Value::Float(f) => Duration::try_from_secs_f64(*f).ok(),
        Value::Str(_) => super::duration(item).ok(),
        _ => None,
    }
}

/// `permissions { publish, subscribe, allow_responses }`.
fn permissions(item: &Item) -> Result<Permissions, Bad> {
    let mut p = Permissions::default();
    for (key, v) in map(item, "permissions")? {
        let key = key.to_ascii_lowercase();
        match key.as_str() {
            "pub" | "publish" | "import" => p.publish = rules(v, false)?,
            "sub" | "subscribe" | "export" => p.subscribe = rules(v, true)?,
            "allow_responses" | "publish_allow_responses" => p.responses = responses(v)?,
            _ => return Err((v.line, format!("permissions: {key}: not supported"))),
        }
    }
    Ok(p)
}

/// A subject, a list of them (all allowed), or `{ allow, deny }`.
fn rules(item: &Item, queues: bool) -> Result<Rules, Bad> {
    let Value::Map(m) = &item.value else {
        return Ok(Rules {
            allow: Some(subjects(item, queues)?),
            deny: Vec::new(),
        });
    };
    let mut r = Rules::default();
    for (key, v) in m {
        match key.to_ascii_lowercase().as_str() {
            "allow" => r.allow = Some(subjects(v, queues)?),
            "deny" => r.deny = subjects(v, queues)?,
            k => return Err((v.line, format!("permissions: {k}: not supported"))),
        }
    }
    Ok(r)
}

/// Subjects, each maybe with a queue group after a blank where `queues`.
fn subjects(item: &Item, queues: bool) -> Result<Vec<String>, Bad> {
    let list = match &item.value {
        Value::Array(a) => a.iter().collect(),
        _ => vec![item],
    };
    list.into_iter()
        .map(|i| {
            let s =
                string(i).ok_or_else(|| (i.line, "permissions: expected subjects".to_owned()))?;
            let (subject, queue) = match s.split_once(' ') {
                Some((subj, q)) if queues && !q.trim().is_empty() => (subj, Some(q.trim())),
                _ => (s.as_str(), None),
            };
            if !naq_proto::subject::is_valid_filter(subject.as_bytes())
                || queue.is_some_and(|q| q.contains(' '))
            {
                return Err((i.line, format!("permissions: bad subject {s:?}")));
            }
            Ok(s)
        })
        .collect()
}

/// `true`, `false` or `{ max, expires }`.
fn responses(item: &Item) -> Result<Option<Responses>, Bad> {
    let mut r = Responses::default();
    match &item.value {
        Value::Bool(on) => Ok(on.then_some(r)),
        Value::Map(m) => {
            for (key, v) in m {
                let bad = |reason: &str| (v.line, format!("allow_responses: {key}: {reason}"));
                match key.to_ascii_lowercase().as_str() {
                    "max" | "max_msgs" | "max_messages" | "max_responses" => {
                        let Value::Int(n) = v.value else {
                            return Err(bad("expected a count"));
                        };
                        let n = u32::try_from(n).map_err(|_| bad("expected a count"))?;
                        if n != 0 {
                            r.max = n;
                        }
                    }
                    "expires" | "expiration" | "ttl" => {
                        let Value::Str(_) = v.value else {
                            return Err(bad("expected a duration"));
                        };
                        let d = super::duration(v).map_err(|e| bad(&e))?;
                        if !d.is_zero() {
                            r.expires = d;
                        }
                    }
                    _ => return Err(bad("not supported")),
                }
            }
            Ok(Some(r))
        }
        _ => Err((
            item.line,
            "allow_responses: expected a boolean or a map".into(),
        )),
    }
}
