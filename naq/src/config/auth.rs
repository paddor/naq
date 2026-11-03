//! `authorization`, `accounts` and `no_auth_user`.

use std::time::Duration;

use super::parse::{Item, Value};
use super::{Bad, string};
use crate::{Login, Options, User};

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

/// A `users` list: each user a map of `user` and `password`.
fn users(item: &Item, account: Option<&str>) -> Result<Vec<User>, Bad> {
    let Value::Array(list) = &item.value else {
        return Err((item.line, "users: expected a list".into()));
    };
    list.iter()
        .map(|u| {
            let (mut user, mut password) = (None, None);
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
                    _ => return Err(bad("not supported")),
                }
            }
            let user = user.ok_or_else(|| (u.line, "users: a user needs a name".to_owned()))?;
            Ok(User {
                login: Login::Password {
                    user,
                    password: password.unwrap_or_default(),
                },
                account: account.map(str::to_owned),
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
