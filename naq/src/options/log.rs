//! What the server logs, and where to.

use std::path::PathBuf;

/// What the server logs, and where to. The lines are those of
/// `nats-server`: `[pid] date time [LVL] text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logging {
    /// Where the lines go. `None`, the default, logs nothing; the `naq`
    /// binary then logs to stderr.
    pub to: Option<LogTo>,
    /// Debug lines too, such as a client's connect and close (`debug`).
    pub debug: bool,
    /// Which protocol operations of clients are traced too.
    pub trace: Trace,
    /// Lines start with the time, in UTC (`logtime`).
    pub time: bool,
    /// A log file past this many bytes is renamed and started again; 0
    /// never (`log_size_limit`).
    pub size_limit: u64,
    /// Log files kept as it rotates, the current one counted; 0 keeps all
    /// (`log_max_num`).
    pub max_files: usize,
    /// Traced payloads are cut at this many bytes; 0 traces them whole
    /// (`max_traced_msg_len`).
    pub max_traced: usize,
}

impl Default for Logging {
    fn default() -> Self {
        Logging {
            to: None,
            debug: false,
            trace: Trace::Off,
            time: true,
            size_limit: 0,
            max_files: 0,
            max_traced: 0,
        }
    }
}

impl Logging {
    /// Logs to `to`, unless it logs somewhere `nats-server` prefers: a
    /// file, then a remote syslog, then the local syslog, then stderr. Of
    /// two of a kind, the later wins.
    pub fn prefer(&mut self, to: LogTo) {
        if self.to.as_ref().is_none_or(|t| t.rank() <= to.rank()) {
            self.to = Some(to);
        }
    }
}

/// Which protocol operations of clients a log traces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Trace {
    /// None.
    #[default]
    Off,
    /// Each, messages with their headers and payloads (`trace`).
    On,
    /// Each, messages with their headers alone (`trace_headers`).
    Headers,
}

impl Trace {
    /// Traces as `on` says, keeping to headers alone if it did.
    pub const fn set(&mut self, on: bool) {
        *self = match (on, *self) {
            (false, _) => Trace::Off,
            (true, Trace::Off) => Trace::On,
            (true, t) => t,
        };
    }
}

/// Where log lines go.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogTo {
    /// Standard error; colored where it is a terminal.
    Stderr,
    /// A file, appended to (`log_file`).
    File(PathBuf),
    /// The local syslog, as facility `daemon` (`syslog`).
    Syslog,
    /// A syslog server at a `udp://`, `tcp://` or `unix://` URL
    /// (`remote_syslog`).
    RemoteSyslog(String),
}

impl LogTo {
    const fn rank(&self) -> u8 {
        match self {
            LogTo::Stderr => 0,
            LogTo::Syslog => 1,
            LogTo::RemoteSyslog(_) => 2,
            LogTo::File(_) => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_wins_over_syslogs_and_stderr_in_any_order_and_the_last_file_wins() {
        let mut l = Logging::default();
        l.prefer(LogTo::Syslog);
        l.prefer(LogTo::File("a.log".into()));
        l.prefer(LogTo::RemoteSyslog("udp://h:514".into()));
        l.prefer(LogTo::Stderr);
        assert_eq!(l.to, Some(LogTo::File("a.log".into())));
        let mut l = Logging::default();
        l.prefer(LogTo::Stderr);
        l.prefer(LogTo::Syslog);
        assert_eq!(l.to, Some(LogTo::Syslog));
        l.prefer(LogTo::File("a.log".into()));
        l.prefer(LogTo::File("b.log".into()));
        assert_eq!(l.to, Some(LogTo::File("b.log".into())));
    }
}
