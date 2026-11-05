//! `operator`, `trusted_keys`, `resolver` and `resolver_preload`: the
//! operators a server trusts, and where their accounts come from.

use super::parse::{Item, Value};
use super::{Bad, string, strings};
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

/// What `nats-server` says of a resolver it cannot read.
const UNREAD: &str = "error parsing account resolver, should be MEM or  URL(\"url\") or a map \
                      containing dir and type state=[FULL|CACHE])";

/// `MEMORY`, a directory resolver, or the others `nats-server` reads,
/// which are not served.
fn resolver(item: &Item) -> Result<Resolver, String> {
    match &item.value {
        // As `nats-server` matches it: anywhere in the string.
        Value::Str(s) if s.to_ascii_lowercase().contains("mem") => Ok(Resolver::Memory),
        Value::Str(s) if s.to_ascii_uppercase().starts_with("URL(") => {
            Err("URL resolvers are not supported".into())
        }
        Value::Map(m) => directory(m),
        _ => Err(UNREAD.into()),
    }
}

/// A resolver given as a map: of `type` full, cache or memory.
fn directory(m: &[(String, Item)]) -> Result<Resolver, String> {
    let get = |k: &str| m.iter().rev().find(|(key, _)| key == k).map(|(_, v)| v);
    let text = |k: &str| get(k).and_then(string).unwrap_or_default();
    let flag = |k: &str| match get(k).map(|v| &v.value) {
        Some(Value::Bool(b)) => Ok(Some(*b)),
        None => Ok(None),
        Some(_) => Err(format!("{k}: expected true or false")),
    };
    let span = |k: &str| get(k).map(super::duration).transpose();
    let (delete, hard) = (flag("allow_delete")?.unwrap_or(false), flag("hard_delete")?);
    let (ttl, interval, timeout) = (span("ttl")?, span("interval")?, span("timeout")?);
    let mut d = crate::Directory::new(text("dir"));
    if let Some(n) = get("limit") {
        let n: i64 = super::int(n).ok_or("limit: expected a number")?;
        d.limit = usize::try_from(n).ok().filter(|&n| n > 0);
    }
    if let Some(t) = timeout {
        if t.is_zero() {
            return Err("Fetch timeout 0s is too smal".into());
        }
        d.timeout = t;
    }
    let kind = text("type").to_ascii_uppercase();
    match kind.as_str() {
        "MEM" | "MEMORY" => return Ok(Resolver::Memory),
        "CACHE" | "FULL" => check_dir(&d.dir)?,
        _ => return Err(UNREAD.into()),
    }
    if kind == "CACHE" {
        if interval.is_some_and(|i| !i.is_zero()) {
            return Err("CACHE does not accept sync".into());
        }
        if delete {
            return Err("CACHE does not accept allow_delete".into());
        }
        if hard.is_some() {
            return Err("CACHE does not accept hard_delete".into());
        }
        d.ttl = ttl.filter(|t| !t.is_zero());
        d.delete = crate::Delete::Remove;
        return Ok(Resolver::Cache(d));
    }
    if ttl.is_some_and(|t| !t.is_zero()) {
        return Err("FULL does not accept ttl".into());
    }
    if hard.is_some() && !delete {
        return Err("hard_delete has no effect without delete".into());
    }
    d.delete = match (delete, hard) {
        (false, _) => crate::Delete::No,
        (true, Some(true)) => crate::Delete::Remove,
        (true, _) => crate::Delete::Rename,
    };
    if let Some(i) = interval.filter(|i| !i.is_zero()) {
        d.interval = i;
    }
    Ok(Resolver::Full(d))
}

/// Why `dir` cannot hold the JWTs of a directory resolver, as
/// `nats-server` checks it: there, it must be a directory its owner may
/// enter.
fn check_dir(dir: &std::path::Path) -> Result<(), String> {
    if dir.as_os_str().is_empty() {
        return Err("dir has no value and needs to point to a directory".into());
    }
    let Ok(meta) = std::fs::metadata(dir) else {
        return Ok(());
    };
    #[cfg(unix)]
    let enter = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o100 != 0;
    #[cfg(not(unix))]
    let enter = true;
    if !meta.is_dir() || !enter {
        return Err("dir needs to point to an accessible directory".into());
    }
    Ok(())
}
