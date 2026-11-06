//! The server's log: lines as `nats-server` writes them, to stderr, a file
//! or a syslog.

pub(crate) mod banner;
mod file;
mod syslog;

use std::fmt;
use std::io::{IsTerminal as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{LogTo, Logging, Trace};

/// How much a line matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    /// Its label, as `nats-server` writes it.
    const fn label(self) -> &'static str {
        match self {
            Level::Error => "ERR",
            Level::Warn => "WRN",
            Level::Info => "INF",
            Level::Debug => "DBG",
            Level::Trace => "TRC",
        }
    }

    /// Its label's color on a terminal.
    const fn color(self) -> &'static str {
        match self {
            Level::Error => "31",
            Level::Warn => "0;93",
            Level::Info => "32",
            Level::Debug => "36",
            Level::Trace => "33",
        }
    }
}

/// Where the lines of a server go, and which.
#[derive(Debug)]
pub(crate) struct Log {
    sink: Option<Mutex<Sink>>,
    // Relaxed: a line more or less as they change is fine.
    debug: AtomicBool,
    trace: AtomicBool,
    format: Format,
    /// Traced payloads are cut at this many bytes; 0 for whole.
    pub(crate) max_traced: usize,
    /// Only the headers of traced messages.
    pub(crate) trace_headers: bool,
}

/// How a line starts.
#[derive(Debug, Clone, Copy)]
struct Format {
    pid: u32,
    time: bool,
    color: bool,
}

#[derive(Debug)]
enum Sink {
    Stderr,
    File(file::File),
    Syslog(syslog::Syslog),
}

impl Log {
    /// A log as `l` asks for.
    ///
    /// # Errors
    ///
    /// The log file cannot be opened, or the syslog not reached.
    pub(crate) fn new(l: &Logging) -> std::io::Result<Log> {
        let format = Format {
            pid: std::process::id(),
            time: l.time,
            color: matches!(l.to, Some(LogTo::Stderr)) && std::io::stderr().is_terminal(),
        };
        let sink = match &l.to {
            None => None,
            Some(LogTo::Stderr) => Some(Sink::Stderr),
            Some(LogTo::File(path)) => Some(Sink::File(file::File::open(path, l)?)),
            Some(LogTo::Syslog) => Some(Sink::Syslog(syslog::Syslog::local()?)),
            Some(LogTo::RemoteSyslog(url)) => Some(Sink::Syslog(syslog::Syslog::remote(url)?)),
        };
        let on = sink.is_some();
        let log = Log {
            sink: sink.map(Mutex::new),
            debug: AtomicBool::new(on && l.debug),
            trace: AtomicBool::new(on && l.trace != Trace::Off),
            format,
            max_traced: l.max_traced,
            trace_headers: l.trace == Trace::Headers,
        };
        if let Some(note) = log.lock().and_then(|mut s| s.take_note()) {
            log.info(format_args!("{note}"));
        }
        Ok(log)
    }

    /// Whether debug lines are written.
    pub(crate) fn debugs(&self) -> bool {
        self.debug.load(Ordering::Relaxed)
    }

    /// Whether trace lines are written.
    pub(crate) fn traces(&self) -> bool {
        self.trace.load(Ordering::Relaxed)
    }

    pub(crate) fn error(&self, args: fmt::Arguments<'_>) {
        self.write(Level::Error, args);
    }

    pub(crate) fn warn(&self, args: fmt::Arguments<'_>) {
        self.write(Level::Warn, args);
    }

    pub(crate) fn info(&self, args: fmt::Arguments<'_>) {
        self.write(Level::Info, args);
    }

    pub(crate) fn debug(&self, args: fmt::Arguments<'_>) {
        if self.debugs() {
            self.write(Level::Debug, args);
        }
    }

    pub(crate) fn trace(&self, args: fmt::Arguments<'_>) {
        if self.traces() {
            self.write(Level::Trace, args);
        }
    }

    /// Opens the log file again, as after it was moved away.
    pub(crate) fn reopen(&self) {
        let Some(mut sink) = self.lock() else {
            return;
        };
        let Sink::File(f) = &mut *sink else {
            drop(sink);
            self.info(format_args!("File log re-open ignored, not a file logger"));
            return;
        };
        match f.reopen() {
            Ok(()) => {
                drop(sink);
                self.info(format_args!("File log re-opened"));
            }
            Err(e) => {
                drop(sink);
                self.error(format_args!("Unable to re-open the log file: {e}"));
            }
        }
    }

    fn lock(&self) -> Option<MutexGuard<'_, Sink>> {
        let sink = self.sink.as_ref()?;
        Some(sink.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn write(&self, level: Level, args: fmt::Arguments<'_>) {
        let Some(mut sink) = self.lock() else {
            return;
        };
        match &mut *sink {
            Sink::Stderr => {
                let line = self.format.line(level, args, "\n");
                // A log that cannot be written has nowhere to say so.
                let _ = std::io::stderr().write_all(line.as_bytes());
            }
            Sink::File(f) => f.write(self.format, &self.format.line(level, args, "\n")),
            Sink::Syslog(s) => s.send(level, &fmt::format(args)),
        }
    }
}

impl Sink {
    /// What the sink has to say of itself, once.
    const fn take_note(&mut self) -> Option<String> {
        match self {
            Sink::File(f) => f.take_note(),
            Sink::Stderr | Sink::Syslog(_) => None,
        }
    }
}

impl Format {
    /// A line of `level` with `args`, ending in `end`.
    fn line(self, level: Level, args: fmt::Arguments<'_>, end: &str) -> String {
        use fmt::Write as _;
        let mut line = String::with_capacity(96);
        let _ = write!(line, "[{}] ", self.pid);
        if self.time {
            let t = Parts::of(SystemTime::now());
            let _ = write!(
                line,
                "{:04}/{:02}/{:02} {:02}:{:02}:{:02}.{:06} ",
                t.year,
                t.month,
                t.day,
                t.hour,
                t.min,
                t.sec,
                t.nanos / 1000
            );
        }
        let label = level.label();
        if self.color {
            let _ = write!(line, "[\x1b[{}m{label}\x1b[0m] ", level.color());
        } else {
            let _ = write!(line, "[{label}] ");
        }
        let _ = line.write_fmt(args);
        line.push_str(end);
        line
    }
}

/// `b` quoted as Go quotes bytes (`%q`): printable text as it is, the
/// rest escaped.
pub(crate) fn quote(b: &[u8]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(b.len() + 2);
    s.push('"');
    for chunk in b.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => s.push_str(r#"\""#),
                '\\' => s.push_str(r"\\"),
                '\n' => s.push_str(r"\n"),
                '\r' => s.push_str(r"\r"),
                '\t' => s.push_str(r"\t"),
                c if c.is_control() => {
                    let _ = write!(s, r"\x{:02x}", u32::from(c));
                }
                c => s.push(c),
            }
        }
        for x in chunk.invalid() {
            let _ = write!(s, r"\x{x:02x}");
        }
    }
    s.push('"');
    s
}

/// `d` as Go writes a `time.Duration`: `10s`, `1m30s`, `1.5s`, `250ms`.
pub(crate) fn go_duration(d: std::time::Duration) -> String {
    let nanos = d.as_nanos();
    let unit = |n: u128, per: u128, name: &str| {
        let whole = n / per;
        let frac = n % per;
        if frac == 0 {
            format!("{whole}{name}")
        } else {
            let digits = per.ilog10() as usize;
            let f = format!("{frac:0digits$}");
            format!("{whole}.{}{name}", f.trim_end_matches('0'))
        }
    };
    match nanos {
        0 => "0s".into(),
        1..1_000 => format!("{nanos}ns"),
        1_000..1_000_000 => unit(nanos, 1_000, "\u{b5}s"),
        1_000_000..1_000_000_000 => unit(nanos, 1_000_000, "ms"),
        _ => {
            let secs = nanos / 1_000_000_000;
            let (h, m) = (secs / 3600, secs % 3600 / 60);
            let s = unit(nanos % 60_000_000_000, 1_000_000_000, "s");
            match (h, m) {
                (0, 0) => s,
                (0, m) => format!("{m}m{s}"),
                (h, m) => format!("{h}h{m}m{s}"),
            }
        }
    }
}

/// The parts of a time, in UTC.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Parts {
    pub(crate) year: i64,
    pub(crate) month: u32,
    pub(crate) day: u32,
    pub(crate) hour: u64,
    pub(crate) min: u64,
    pub(crate) sec: u64,
    pub(crate) nanos: u32,
}

impl Parts {
    pub(crate) fn of(t: SystemTime) -> Parts {
        let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = d.as_secs();
        let (days, rest) = (secs / 86_400, secs % 86_400);
        let (year, month, day) = crate::monitor::civil(days.cast_signed());
        Parts {
            year,
            month,
            day,
            hour: rest / 3600,
            min: rest % 3600 / 60,
            sec: rest % 60,
            nanos: d.subsec_nanos(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_starts_with_the_pid_the_time_and_the_label() {
        let f = Format {
            pid: 7,
            time: false,
            color: false,
        };
        assert_eq!(
            f.line(Level::Warn, format_args!("a {}", 1), "\n"),
            "[7] [WRN] a 1\n"
        );
        let f = Format { color: true, ..f };
        assert_eq!(
            f.line(Level::Info, format_args!("b"), "\r\n"),
            "[7] [\x1b[32mINF\x1b[0m] b\r\n"
        );
        let f = Format { time: true, ..f };
        let line = f.line(Level::Debug, format_args!("c"), "\n");
        // [7] 2026/11/06 02:18:09.898497 [..DBG..] c
        assert_eq!(line.as_bytes()[8], b'/');
        assert_eq!(line.as_bytes()[23], b'.');
        assert!(line.ends_with("DBG\x1b[0m] c\n"), "{line}");
    }

    #[test]
    fn durations_print_as_go_prints_them() {
        use std::time::Duration as D;
        assert_eq!(go_duration(D::ZERO), "0s");
        assert_eq!(go_duration(D::from_secs(10)), "10s");
        assert_eq!(go_duration(D::from_secs(120)), "2m0s");
        assert_eq!(go_duration(D::from_secs(3723)), "1h2m3s");
        assert_eq!(go_duration(D::from_millis(1500)), "1.5s");
        assert_eq!(go_duration(D::from_millis(250)), "250ms");
        assert_eq!(go_duration(D::from_micros(1500)), "1.5ms");
        assert_eq!(go_duration(D::from_nanos(1500)), "1.5\u{b5}s");
        assert_eq!(go_duration(D::from_nanos(7)), "7ns");
    }

    #[test]
    fn parts_split_a_time_in_utc() {
        let t = UNIX_EPOCH + std::time::Duration::new(1_762_395_489, 898_497_000);
        let p = Parts::of(t);
        assert_eq!(
            (p.year, p.month, p.day, p.hour, p.min, p.sec, p.nanos),
            (2025, 11, 6, 2, 18, 9, 898_497_000)
        );
    }

    #[test]
    fn each_level_has_the_label_and_color_of_nats_server() {
        let all = [
            (Level::Error, "ERR", "31"),
            (Level::Warn, "WRN", "0;93"),
            (Level::Info, "INF", "32"),
            (Level::Debug, "DBG", "36"),
            (Level::Trace, "TRC", "33"),
        ];
        for (level, label, color) in all {
            assert_eq!((level.label(), level.color()), (label, color));
        }
    }

    #[test]
    fn a_log_to_a_syslog_sends_its_lines_there_and_reopens_nothing() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let url = format!("udp://{}", server.local_addr().unwrap());
        let l = Log::new(&Logging {
            to: Some(LogTo::RemoteSyslog(url)),
            debug: true,
            ..Logging::default()
        })
        .unwrap();
        l.debug(format_args!("d"));
        l.reopen();
        let mut got = Vec::new();
        for _ in 0..2 {
            let mut buf = [0; 256];
            let n = server.recv(&mut buf).unwrap();
            got.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        assert!(
            got[0].starts_with("<7>") && got[0].ends_with(": d\n"),
            "{got:?}"
        );
        assert!(
            got[1].ends_with(": File log re-open ignored, not a file logger\n"),
            "{got:?}"
        );
        assert!(
            Log::new(&Logging {
                to: Some(LogTo::RemoteSyslog("ftp://h".into())),
                ..Logging::default()
            })
            .is_err()
        );
    }

    #[test]
    fn quoting_escapes_what_is_not_printable() {
        // Bytes: a " \ LF CR TAB 0x01 0xff, then e-acute in UTF-8.
        let input = b"a\"\\\n\r\t\x01\xff\xc3\xa9";
        assert_eq!(quote(input), "\"a\\\"\\\\\\n\\r\\t\\x01\\xff\u{e9}\"");
    }

    #[test]
    fn a_log_to_nowhere_writes_no_debug_or_trace() {
        let l = Log::new(&Logging {
            debug: true,
            trace: Trace::On,
            ..Logging::default()
        })
        .unwrap();
        assert!(!l.debugs() && !l.traces());
        l.info(format_args!("nowhere"));
    }
}
