//! The `leafnodes` block: the hubs this server dials.

use super::parse::{Item, Value};
use super::{Bad, duration, seconds, string};
use crate::{Options, Remote, RemoteTls};

/// `leafnodes { remotes, reconnect }`. naq takes no leaf nodes of its own:
/// the keys of a hub are not supported.
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
            _ => return Err(bad("not supported")),
        }
    }
    Ok(())
}

/// One remote: `{ url, urls, account, no_randomize, credentials, nkey,
/// tls }`.
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
