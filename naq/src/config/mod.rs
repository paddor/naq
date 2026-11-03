//! `nats-server` configuration files, the part of them naq serves.

mod auth;
mod parse;

use std::path::Path;
use std::time::Duration;

use parse::{Item, Map, Value};

use crate::{Error, Options};

/// Keys of `nats-server` that only change its logs, ignored here.
const IGNORED: &[&str] = &[
    "debug",
    "trace",
    "trace_verbose",
    "logtime",
    "logtime_utc",
    "logfile",
    "log_file",
    "log_size_limit",
    "log_max_num",
    "syslog",
    "remote_syslog",
    "pidfile",
    "pid_file",
];

impl Options {
    /// Reads a `nats-server` configuration file. Keys it leaves out keep
    /// their default; keys naq does not serve yet are an error.
    ///
    /// # Errors
    ///
    /// [`Error::Read`] if the file cannot be read, [`Error::Config`] if it
    /// does not parse or holds a key or value naq cannot use.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Options, Error> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.display().to_string(),
            source,
        })?;
        from_text(&text, Some(path))
    }
}

impl std::str::FromStr for Options {
    type Err = Error;

    /// Reads a `nats-server` configuration from text, as
    /// [`Options::from_file`] reads it from a file. Includes are relative to
    /// the current directory.
    fn from_str(text: &str) -> Result<Options, Error> {
        from_text(text, None)
    }
}

fn from_text(text: &str, file: Option<&Path>) -> Result<Options, Error> {
    let at = |line: u32, f: Option<&Path>| match f {
        Some(f) => format!("{}:{line}", f.display()),
        None => format!("line {line}"),
    };
    let map = parse::parse(text, file).map_err(|e| Error::Config {
        at: at(e.line, e.file.as_deref()),
        reason: e.reason,
    })?;
    let mut opts = Options::default();
    apply(&mut opts, &map).map_err(|(line, reason)| Error::Config {
        at: at(line, file),
        reason,
    })?;
    crate::auth::validate(&opts).map_err(|reason| Error::Config {
        at: file.map_or_else(|| "config".into(), |f| f.display().to_string()),
        reason,
    })?;
    Ok(opts)
}

/// A key's value could not be used: its line and why.
pub(super) type Bad = (u32, String);

fn apply(o: &mut Options, map: &Map) -> Result<(), Bad> {
    for (key, item) in map {
        let key = key.to_ascii_lowercase();
        let bad = |reason: &str| (item.line, format!("{key}: {reason}"));
        match key.as_str() {
            "listen" => {
                let (host, port) = listen(item).ok_or_else(|| bad("expected host:port"))?;
                if let Some(h) = host {
                    o.host = h;
                }
                o.port = port;
            }
            "host" | "net" => o.host = string(item).ok_or_else(|| bad("expected a string"))?,
            "port" => o.port = int(item).ok_or_else(|| bad("expected a port"))?,
            "server_name" => {
                let name = string(item).ok_or_else(|| bad("expected a string"))?;
                if name.contains(' ') {
                    return Err(bad("server name cannot contain spaces"));
                }
                o.server_name = name;
            }
            "max_payload" => {
                o.max_payload = size(item, i32::MAX).ok_or_else(|| bad("expected a size"))?;
            }
            "max_control_line" => {
                o.max_control_line = size(item, i32::MAX).ok_or_else(|| bad("expected a size"))?;
            }
            "max_pending" => {
                o.max_pending = size(item, i64::MAX).ok_or_else(|| bad("expected a size"))?;
            }
            "ping_interval" => o.ping_interval = duration(item).map_err(|e| bad(&e))?,
            "ping_max" => o.max_pings_out = int(item).ok_or_else(|| bad("expected a count"))?,
            "write_deadline" => o.write_deadline = duration(item).map_err(|e| bad(&e))?,
            "authorization" => auth::authorization(o, item)?,
            "http" => {
                let (host, port) = listen(item).ok_or_else(|| bad("expected host:port"))?;
                o.http_host = host;
                o.http_port = Some(port);
            }
            "tls" => o.tls = Some(tls(item)?),
            "http_port" | "monitor_port" => {
                o.http_port = Some(int(item).ok_or_else(|| bad("expected a port"))?);
            }
            "accounts" => auth::accounts(o, item)?,
            "no_auth_user" => {
                o.no_auth_user = Some(string(item).ok_or_else(|| bad("expected a string"))?);
            }
            k if IGNORED.contains(&k) => {}
            _ => return Err(bad("not supported")),
        }
    }
    Ok(())
}

/// `tls { cert_file, key_file, ca_file, verify, timeout, handshake_first }`.
fn tls(item: &Item) -> Result<crate::Tls, Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "tls: expected a map".into()));
    };
    let (mut cert, mut key, mut ca) = (None, None, None);
    let mut t = crate::Tls {
        cert_file: std::path::PathBuf::default(),
        key_file: std::path::PathBuf::default(),
        ca_file: None,
        verify: false,
        timeout: Duration::from_secs(2),
        handshake_first: false,
    };
    for (k, v) in m {
        let k = k.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("tls: {k}: {reason}"));
        let path = || {
            string(v)
                .map(std::path::PathBuf::from)
                .ok_or_else(|| bad("expected a path"))
        };
        let flag = || match v.value {
            Value::Bool(b) => Ok(b),
            _ => Err(bad("expected true or false")),
        };
        match k.as_str() {
            "cert_file" => cert = Some(path()?),
            "key_file" => key = Some(path()?),
            "ca_file" => ca = Some(path()?),
            "verify" => t.verify = flag()?,
            "handshake_first" | "first" | "immediate" => t.handshake_first = flag()?,
            "timeout" => {
                t.timeout = match v.value {
                    Value::Int(n) => u64::try_from(n)
                        .map(Duration::from_secs)
                        .map_err(|_| bad("expected seconds"))?,
                    Value::Float(f) => {
                        Duration::try_from_secs_f64(f).map_err(|_| bad("expected seconds"))?
                    }
                    _ => duration(v).map_err(|e| bad(&e))?,
                };
            }
            _ => return Err(bad("not supported")),
        }
    }
    t.cert_file = cert.ok_or_else(|| (item.line, "tls: cert_file missing".to_owned()))?;
    t.key_file = key.ok_or_else(|| (item.line, "tls: key_file missing".to_owned()))?;
    t.ca_file = ca;
    Ok(t)
}

pub(super) fn string(item: &Item) -> Option<String> {
    match &item.value {
        Value::Str(s) => Some(s.clone()),
        _ => None,
    }
}

fn int<T: TryFrom<i64>>(item: &Item) -> Option<T> {
    match item.value {
        Value::Int(n) => T::try_from(n).ok(),
        _ => None,
    }
}

/// A size of at most `max`, not negative.
fn size(item: &Item, max: impl Into<i64>) -> Option<usize> {
    let n: i64 = int(item)?;
    if n < 0 || n > max.into() {
        return None;
    }
    usize::try_from(n).ok()
}

/// `host:port`, `:port` or a bare port.
fn listen(item: &Item) -> Option<(Option<String>, u16)> {
    match &item.value {
        Value::Int(_) => Some((None, int(item)?)),
        Value::Str(s) => {
            let (host, port) = s.rsplit_once(':')?;
            let port = port.parse().ok()?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            Some(((!host.is_empty()).then(|| host.to_owned()), port))
        }
        _ => None,
    }
}

/// A duration as Go writes it (`2m`, `1.5s`, `1h30m`); a number is seconds.
pub(super) fn duration(item: &Item) -> Result<Duration, String> {
    match &item.value {
        Value::Int(n) => u64::try_from(*n)
            .map(Duration::from_secs)
            .map_err(|_| "expected a duration".into()),
        Value::Str(s) => go_duration(s).ok_or_else(|| format!("bad duration {s:?}")),
        _ => Err("expected a duration".into()),
    }
}

/// Parses Go's `time.Duration` text, without a sign.
fn go_duration(s: &str) -> Option<Duration> {
    if s == "0" {
        return Some(Duration::ZERO);
    }
    if s.is_empty() {
        return None;
    }
    let mut rest = s;
    let mut total = 0f64;
    while !rest.is_empty() {
        let num_len = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let (num, after) = rest.split_at(num_len);
        let unit_len = after
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(after.len());
        let (unit, next) = after.split_at(unit_len);
        let n: f64 = num.parse().ok()?;
        let scale = match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        total += n * scale;
        rest = next;
    }
    Some(Duration::from_secs_f64(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_go_writes_them() {
        assert_eq!(go_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(go_duration("1h30m"), Some(Duration::from_mins(90)));
        assert_eq!(go_duration("1.5s"), Some(Duration::from_millis(1500)));
        assert_eq!(go_duration("250ms"), Some(Duration::from_millis(250)));
        assert_eq!(go_duration("10us"), Some(Duration::from_micros(10)));
        assert_eq!(go_duration("0"), Some(Duration::ZERO));
        for bad in ["", "5", "1x", "m", "1.2.3s"] {
            assert_eq!(go_duration(bad), None, "{bad}");
        }
    }

    #[test]
    fn listen_takes_a_host_and_port_or_a_port() {
        let item = |value| Item { value, line: 1 };
        assert_eq!(
            listen(&item(Value::Str("127.0.0.1:4333".into()))),
            Some((Some("127.0.0.1".into()), 4333))
        );
        assert_eq!(
            listen(&item(Value::Str(":4333".into()))),
            Some((None, 4333))
        );
        assert_eq!(
            listen(&item(Value::Str("[::1]:4333".into()))),
            Some((Some("::1".into()), 4333))
        );
        assert_eq!(listen(&item(Value::Int(4333))), Some((None, 4333)));
        assert_eq!(listen(&item(Value::Str("nohost".into()))), None);
        assert_eq!(listen(&item(Value::Bool(true))), None);
    }
}
