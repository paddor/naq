//! The keys of `nats-server` about its log.

use super::parse::{Item, Value};
use super::{Bad, int, string};
use crate::{LogTo, Options, Trace};

/// The keys `apply` takes.
pub(super) const KEYS: &[&str] = &[
    "debug",
    "trace",
    "trace_verbose",
    "trace_headers",
    "logtime",
    "logtime_utc",
    "logfile",
    "log_file",
    "logfile_size_limit",
    "log_size_limit",
    "logfile_max_num",
    "log_max_num",
    "syslog",
    "remote_syslog",
    "max_traced_msg_len",
];

/// Applies `key`, one of [`KEYS`], to the log of `o`.
pub(super) fn apply(o: &mut Options, key: &str, item: &Item) -> Result<(), Bad> {
    let bad = |reason: &str| (item.line, format!("{key}: {reason}"));
    let flag = || match item.value {
        Value::Bool(b) => Ok(b),
        _ => Err(bad("expected true or false")),
    };
    let text = || string(item).ok_or_else(|| bad("expected a string"));
    let l = &mut o.log;
    match key {
        "debug" => l.debug = flag()?,
        // The server's own client is traced as any other.
        "trace" | "trace_verbose" => l.trace.set(flag()?),
        "trace_headers" => {
            l.trace = if flag()? { Trace::Headers } else { Trace::Off };
        }
        "logtime" => l.time = flag()?,
        // Lines are in UTC anyway.
        "logtime_utc" => _ = flag()?,
        "logfile" | "log_file" => {
            let path = text()?;
            if !path.is_empty() {
                l.prefer(LogTo::File(path.into()));
            }
        }
        "logfile_size_limit" | "log_size_limit" => {
            l.size_limit = int(item).ok_or_else(|| bad("expected a count"))?;
        }
        "logfile_max_num" | "log_max_num" => {
            l.max_files = int(item).ok_or_else(|| bad("expected a count"))?;
        }
        "syslog" => {
            if flag()? {
                l.prefer(LogTo::Syslog);
            }
        }
        "remote_syslog" => {
            let url = text()?;
            if !url.is_empty() {
                l.prefer(LogTo::RemoteSyslog(url));
            }
        }
        _ => l.max_traced = int(item).ok_or_else(|| bad("expected a count"))?,
    }
    Ok(())
}
