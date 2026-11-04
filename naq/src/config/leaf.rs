//! The `leafnodes` block: the hubs this server dials.

use super::parse::{Item, Value};
use super::{Bad, duration, int, listen, seconds, string};
use crate::{Leafnodes, Options, Remote, RemoteTls};

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
                o.leafnodes.get_or_insert_with(Leafnodes::default).account = authorization(v)?;
            }
            _ => return Err(bad("not supported")),
        }
    }
    Ok(())
}

/// The account of `authorization { account }`, which every naq leaf binds.
/// Users of leafs are not supported yet.
fn authorization(item: &Item) -> Result<Option<String>, Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "leafnodes: authorization: expected a map".into()));
    };
    let mut account = None;
    for (k, v) in m {
        let bad = |reason: &str| (v.line, format!("leafnodes: authorization: {k}: {reason}"));
        match k.to_ascii_lowercase().as_str() {
            "account" => account = Some(string(v).ok_or_else(|| bad("expected a string"))?),
            _ => return Err(bad("not supported")),
        }
    }
    Ok(account)
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
