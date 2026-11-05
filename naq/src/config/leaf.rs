//! The `leafnodes` block: the hubs this server dials.

use super::auth::timeout;
use super::parse::{Item, Value};
use super::{Bad, duration, int, listen, seconds, string};
use crate::{Leafnodes, Login, Options, Remote, RemoteTls, User};

/// `leafnodes { remotes, reconnect, listen, host, port, authorization }`.
/// The port of a hub takes naq leaf nodes, over OMQ.
pub(super) fn leafnodes(o: &mut Options, item: &Item) -> Result<(), Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "leafnodes: expected a map".into()));
    };
    for (k, v) in m {
        let k = k.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("leafnodes: {k}: {reason}"));
        match k.as_str() {
            "remotes" => {
                let Value::Array(list) = &v.value else {
                    return Err(bad("expected a list"));
                };
                for r in list {
                    o.remotes.push(remote(r)?);
                }
            }
            "reconnect" | "reconnect_delay" | "reconnect_interval" => {
                o.leaf_reconnect = duration(v).map_err(|e| bad(&e))?;
            }
            "listen" => {
                let (host, port) = listen(v).ok_or_else(|| bad("expected host:port"))?;
                let l = o.leafnodes.get_or_insert_with(Leafnodes::default);
                if let Some(h) = host {
                    l.host = h;
                }
                l.port = port;
            }
            "host" | "net" => {
                o.leafnodes.get_or_insert_with(Leafnodes::default).host =
                    string(v).ok_or_else(|| bad("expected a string"))?;
            }
            "port" => {
                o.leafnodes.get_or_insert_with(Leafnodes::default).port =
                    int(v).ok_or_else(|| bad("expected a port"))?;
            }
            "authorization" => {
                authorization(o.leafnodes.get_or_insert_with(Leafnodes::default), v)?;
            }
            _ => return Err(bad("not supported")),
        }
    }
    Ok(())
}

/// `authorization { user, password, nkey, users, account, timeout }`: who
/// naq leafs log in as, and the account of those without a user of their
/// own.
fn authorization(l: &mut Leafnodes, item: &Item) -> Result<(), Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "leafnodes: authorization: expected a map".into()));
    };
    let (mut user, mut password, mut nkey) = (None, None, None);
    for (k, v) in m {
        let k = k.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("leafnodes: authorization: {k}: {reason}"));
        let text = || string(v).ok_or_else(|| bad("expected a string"));
        match k.as_str() {
            "user" | "username" => user = Some(text()?),
            "pass" | "password" => password = Some(text()?),
            "nkey" => {
                let key = text()?;
                if !crate::auth::is_user_nkey(&key) {
                    return Err(bad("not a public user NKey"));
                }
                nkey = Some(key);
            }
            "users" => l.users.extend(users(v)?),
            "account" => l.account = Some(text()?),
            "timeout" => {
                l.auth_timeout = timeout(v).ok_or_else(|| bad("expected seconds or a duration"))?;
            }
            _ => return Err(bad("not supported")),
        }
    }
    let bad = |reason: &str| (item.line, format!("leafnodes: authorization: {reason}"));
    let single = match (user, password, nkey) {
        (Some(_), _, Some(_)) => return Err(bad("a user cannot go with an nkey")),
        (None, Some(_), _) => return Err(bad("password without user")),
        (Some(user), password, None) => Some(Login::Password {
            user,
            password: password.unwrap_or_default(),
        }),
        (None, None, Some(key)) => Some(Login::Nkey(key)),
        (None, None, None) => None,
    };
    if let Some(login) = single {
        if !l.users.is_empty() {
            return Err(bad("a single user cannot go with users"));
        }
        l.users.push(User {
            login,
            account: l.account.clone(),
            permissions: None,
        });
    }
    Ok(())
}

/// The `users` of naq leafs: each a map of `user`, `password` and
/// `account`.
fn users(item: &Item) -> Result<Vec<User>, Bad> {
    let Value::Array(list) = &item.value else {
        return Err((
            item.line,
            "leafnodes: authorization: users: expected a list".into(),
        ));
    };
    list.iter()
        .map(|u| {
            let Value::Map(m) = &u.value else {
                return Err((
                    u.line,
                    "leafnodes: authorization: users: expected maps".into(),
                ));
            };
            let (mut user, mut password, mut account) = (None, None, None);
            for (k, v) in m {
                let k = k.to_ascii_lowercase();
                let bad = |reason: &str| {
                    let at = format!("leafnodes: authorization: users: {k}");
                    (v.line, format!("{at}: {reason}"))
                };
                let text = string(v).ok_or_else(|| bad("expected a string"));
                match k.as_str() {
                    "user" | "username" => user = Some(text?),
                    "pass" | "password" => password = Some(text?),
                    "account" => account = Some(text?),
                    _ => return Err(bad("not supported")),
                }
            }
            let user = user.ok_or_else(|| {
                (
                    u.line,
                    "leafnodes: authorization: users: a user without a name".into(),
                )
            })?;
            Ok(User {
                login: Login::Password {
                    user,
                    password: password.unwrap_or_default(),
                },
                account,
                permissions: None,
            })
        })
        .collect()
}

/// One remote: `{ url, urls, account, no_randomize, credentials, nkey,
/// tls, deny_imports, deny_exports, request_isolation }`.
fn remote(item: &Item) -> Result<Remote, Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "leafnodes: remotes: expected a map".into()));
    };
    let mut r = Remote::default();
    for (k, v) in m {
        let k = k.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("leafnodes: remotes: {k}: {reason}"));
        match k.as_str() {
            "url" | "urls" => match &v.value {
                Value::Str(s) => r.urls.push(s.clone()),
                Value::Array(a) => {
                    for u in a {
                        r.urls
                            .push(string(u).ok_or_else(|| bad("expected strings"))?);
                    }
                }
                _ => return Err(bad("expected a string or a list")),
            },
            "account" | "local" => {
                r.account = Some(string(v).ok_or_else(|| bad("expected a string"))?);
            }
            "no_randomize" | "dont_randomize" => {
                r.no_randomize = match v.value {
                    Value::Bool(b) => b,
                    _ => return Err(bad("expected true or false")),
                };
            }
            "credentials" | "creds" => {
                r.credentials = Some(string(v).ok_or_else(|| bad("expected a string"))?.into());
            }
            "nkey" | "seed" => {
                r.nkey = Some(string(v).ok_or_else(|| bad("expected a string"))?);
            }
            "tls" => r.tls = Some(tls(v)?),
            "deny_imports" | "deny_import" => {
                r.deny_imports = subjects(v).ok_or_else(|| bad("expected a subject or a list"))?;
            }
            "deny_exports" | "deny_export" => {
                r.deny_exports = subjects(v).ok_or_else(|| bad("expected a subject or a list"))?;
            }
            "request_isolation" => {
                r.request_isolation = match v.value {
                    Value::Bool(b) => b,
                    _ => return Err(bad("expected true or false")),
                };
            }
            _ => return Err(bad("not supported")),
        }
    }
    Ok(r)
}

/// A remote's `tls { cert_file, key_file, ca_file, timeout,
/// handshake_first }`.
fn tls(item: &Item) -> Result<RemoteTls, Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "leafnodes: remotes: tls: expected a map".into()));
    };
    let mut t = RemoteTls::default();
    for (k, v) in m {
        let k = k.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("leafnodes: remotes: tls: {k}: {reason}"));
        let path = || {
            string(v)
                .map(std::path::PathBuf::from)
                .ok_or_else(|| bad("expected a path"))
        };
        match k.as_str() {
            "cert_file" => t.cert_file = Some(path()?),
            "key_file" => t.key_file = Some(path()?),
            "ca_file" => t.ca_file = Some(path()?),
            "timeout" => t.timeout = seconds(v).map_err(|e| bad(&e))?,
            "handshake_first" | "first" | "immediate" => {
                t.handshake_first = match v.value {
                    Value::Bool(b) => b,
                    _ => return Err(bad("expected true or false")),
                };
            }
            _ => return Err(bad("not supported")),
        }
    }
    Ok(t)
}

/// A subject, or a list of them.
fn subjects(item: &Item) -> Option<Vec<String>> {
    match &item.value {
        Value::Str(s) => Some(vec![s.clone()]),
        Value::Array(a) => a.iter().map(string).collect(),
        _ => None,
    }
}
