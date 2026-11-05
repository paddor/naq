//! `operator`, `trusted_keys`, `resolver` and `resolver_preload`: the
//! operators a server trusts, and where their accounts come from.

use super::parse::{Item, Value};
use super::{Bad, string};
use crate::{Options, Resolver};

/// The keys this module reads, with their `nats-server` aliases.
pub(super) const KEYS: &[&str] = &[
    "operator",
    "operators",
    "root",
    "roots",
    "root_operator",
    "root_operators",
    "trusted_keys",
    "trusted",
    "resolver",
    "account_resolver",
    "accounts_resolver",
    "resolver_preload",
];

pub(super) fn apply(o: &mut Options, key: &str, item: &Item) -> Result<(), Bad> {
    let bad = |line: u32, reason: &str| (line, format!("{key}: {reason}"));
    match key {
        "trusted_keys" | "trusted" => {
            for k in strings(item).ok_or_else(|| bad(item.line, "expected keys"))? {
                if !crate::jwt::is_key(&k, 'O') {
                    return Err(bad(
                        item.line,
                        &format!("{k:?} is not a public operator key"),
                    ));
                }
                o.trusted_keys.push(k);
            }
        }
        "resolver" | "account_resolver" | "accounts_resolver" => {
            o.resolver = Some(resolver(item).map_err(|r| bad(item.line, &r))?);
        }
        "resolver_preload" => {
            let Value::Map(m) = &item.value else {
                return Err(bad(item.line, "expected a map of account keys to JWTs"));
            };
            for (k, v) in m {
                let jwt = string(v).ok_or_else(|| bad(v.line, "expected a JWT"))?;
                o.resolver_preload.push((k.clone(), jwt));
            }
        }
        _ => {
            for op in strings(item).ok_or_else(|| bad(item.line, "expected JWTs or files"))? {
                o.operators.push(read(&op).map_err(|r| bad(item.line, &r))?);
            }
        }
    }
    Ok(())
}

/// A string, or a list of them.
fn strings(item: &Item) -> Option<Vec<String>> {
    match &item.value {
        Value::Array(a) => a.iter().map(string).collect(),
        _ => string(item).map(|s| vec![s]),
    }
}

/// An operator JWT given as it is, or in a file, decorated or not.
fn read(given: &str) -> Result<String, String> {
    if given.starts_with("eyJ") {
        return Ok(given.to_owned());
    }
    let text = std::fs::read_to_string(given).map_err(|e| format!("cannot read {given:?}: {e}"))?;
    Ok(undecorated(&text).to_owned())
}

/// The JWT in `text`: the line after a `-----BEGIN ...-----` line, or all
/// of it.
pub(crate) fn undecorated(text: &str) -> &str {
    let mut lines = text.lines().map(str::trim);
    while let Some(l) = lines.next() {
        if l.starts_with("---") && l.contains("BEGIN") {
            return lines.next().unwrap_or_default();
        }
    }
    text.trim()
}

/// `MEMORY` and the others `nats-server` reads; only `MEMORY` is served.
fn resolver(item: &Item) -> Result<Resolver, String> {
    match &item.value {
        // As `nats-server` matches it: anywhere in the string.
        Value::Str(s) if s.to_ascii_lowercase().contains("mem") => Ok(Resolver::Memory),
        Value::Str(s) if s.to_ascii_uppercase().starts_with("URL(") => {
            Err("URL resolvers are not supported".into())
        }
        Value::Map(_) => Err("directory resolvers are not supported".into()),
        _ => Err("should be MEMORY".into()),
    }
}
