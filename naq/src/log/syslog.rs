//! Log lines sent to a syslog, local or remote, as Go's `log/syslog`
//! sends them for `nats-server`.

use std::io::Write as _;
use std::net::{TcpStream, UdpSocket};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::PathBuf;
use std::time::SystemTime;

use super::{Level, Parts};

/// The local syslog sockets Go tries, in order.
const LOCAL: &[&str] = &["/dev/log", "/var/run/syslog", "/var/run/log"];

/// Facility `daemon`, of the local syslog.
const DAEMON: u8 = 3 << 3;

#[derive(Debug)]
pub(super) struct Syslog {
    target: Target,
    conn: Conn,
    /// The program's name.
    tag: String,
    /// The host's name, for a remote syslog.
    host: Option<String>,
    pid: u32,
}

#[derive(Debug, Clone)]
enum Target {
    Dgram(PathBuf),
    Unix(PathBuf),
    Udp(String),
    Tcp(String),
}

#[derive(Debug)]
enum Conn {
    Dgram(UnixDatagram),
    Unix(UnixStream),
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl Syslog {
    /// The syslog of this host, as facility `daemon`.
    pub(super) fn local() -> std::io::Result<Syslog> {
        let mut last = std::io::Error::other("no syslog socket");
        for path in LOCAL {
            for target in [Target::Dgram(path.into()), Target::Unix(path.into())] {
                match target.connect() {
                    Ok(conn) => return Ok(Syslog::new(target, conn, None)),
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    /// The syslog at `url`: `udp://host:port`, `tcp://host:port` or
    /// `unix:///path`.
    pub(super) fn remote(url: &str) -> std::io::Result<Syslog> {
        let bad = || std::io::Error::other(format!("bad syslog URL {url:?}"));
        let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
        let host = || {
            rest.split('/')
                .next()
                .filter(|h| !h.is_empty())
                .ok_or_else(bad)
        };
        let target = match scheme {
            "udp" => Target::Udp(host()?.into()),
            "tcp" => Target::Tcp(host()?.into()),
            "unix" => Target::Unix(PathBuf::from(&rest[rest.find('/').ok_or_else(bad)?..])),
            _ => {
                return Err(std::io::Error::other(format!(
                    "error invalid network type: {scheme:?}"
                )));
            }
        };
        let conn = target.connect()?;
        Ok(Syslog::new(target, conn, Some(hostname())))
    }

    fn new(target: Target, conn: Conn, host: Option<String>) -> Syslog {
        let tag = std::env::args_os()
            .next()
            .map(PathBuf::from)
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "naq".into());
        Syslog {
            target,
            conn,
            tag,
            host,
            pid: std::process::id(),
        }
    }

    /// Sends `text` at `level`, connecting again once if that fails.
    pub(super) fn send(&mut self, level: Level, text: &str) {
        let msg = self.message(level, text, SystemTime::now());
        if self.conn.send(msg.as_bytes()).is_ok() {
            return;
        }
        if let Ok(conn) = self.target.connect() {
            self.conn = conn;
            let _ = self.conn.send(msg.as_bytes());
        }
    }

    /// The syslog message of `text` at `level`, at `now`.
    fn message(&self, level: Level, text: &str, now: SystemTime) -> String {
        let severity = match level {
            Level::Error => 3,
            Level::Warn => 4,
            Level::Info | Level::Trace => 5,
            Level::Debug => 7,
        };
        let t = Parts::of(now);
        let nl = if text.ends_with('\n') { "" } else { "\n" };
        let (tag, pid) = (&self.tag, self.pid);
        match &self.host {
            // Facility `kern`, as Go dials it.
            Some(host) => format!(
                "<{severity}>{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z {host} {tag}[{pid}]: {text}{nl}",
                t.year, t.month, t.day, t.hour, t.min, t.sec
            ),
            None => format!(
                "<{}>{} {:>2} {:02}:{:02}:{:02} {tag}[{pid}]: {text}{nl}",
                DAEMON + severity,
                month(t.month),
                t.day,
                t.hour,
                t.min,
                t.sec
            ),
        }
    }
}

impl Target {
    fn connect(&self) -> std::io::Result<Conn> {
        match self {
            Target::Dgram(p) => {
                let s = UnixDatagram::unbound()?;
                s.connect(p)?;
                Ok(Conn::Dgram(s))
            }
            Target::Unix(p) => Ok(Conn::Unix(UnixStream::connect(p)?)),
            Target::Udp(at) => {
                let s = UdpSocket::bind(if at.starts_with('[') {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })?;
                s.connect(at.as_str())?;
                Ok(Conn::Udp(s))
            }
            Target::Tcp(at) => Ok(Conn::Tcp(TcpStream::connect(at.as_str())?)),
        }
    }
}

impl Conn {
    fn send(&mut self, b: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Dgram(s) => s.send(b).map(drop),
            Conn::Unix(s) => s.write_all(b),
            Conn::Udp(s) => s.send(b).map(drop),
            Conn::Tcp(s) => s.write_all(b),
        }
    }
}

/// The host's name, as the kernel has it.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

const fn month(m: u32) -> &'static str {
    match m {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        _ => "Dec",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    #[test]
    fn remote_messages_carry_the_host_and_a_kernel_priority() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let url = format!("udp://{}", server.local_addr().unwrap());
        let mut s = Syslog::remote(&url).unwrap();
        s.tag = "naq".into();
        s.host = Some("h".into());
        s.pid = 9;
        assert_eq!(
            s.message(Level::Info, "Server is ready", at(1_762_395_511)),
            "<5>2025-11-06T02:18:31Z h naq[9]: Server is ready\n"
        );
        assert_eq!(
            s.message(Level::Debug, "x\n", at(0)),
            "<7>1970-01-01T00:00:00Z h naq[9]: x\n"
        );
        s.send(Level::Warn, "w");
        let mut buf = [0; 128];
        let n = server.recv(&mut buf).unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.starts_with("<4>") && got.ends_with(": w\n"), "{got}");
    }

    #[test]
    fn local_messages_carry_a_daemon_priority_and_no_host() {
        let server = UnixDatagram::unbound().unwrap();
        let mut s = Syslog::new(Target::Udp(String::new()), Conn::Dgram(server), None);
        s.tag = "naq".into();
        s.pid = 9;
        assert_eq!(
            s.message(Level::Error, "e", at(1_762_395_511)),
            "<27>Nov  6 02:18:31 naq[9]: e\n"
        );
        assert_eq!(
            s.message(Level::Trace, "t", at(1_762_395_511)).get(..4),
            Some("<29>")
        );
    }

    #[test]
    fn remote_urls_take_udp_tcp_and_unix_only() {
        let err = Syslog::remote("http://h:1").unwrap_err();
        assert_eq!(err.to_string(), "error invalid network type: \"http\"");
        assert!(Syslog::remote("udp://").is_err());
        assert!(Syslog::remote("nonsense").is_err());
        let path = std::env::temp_dir().join(format!("naq-syslog-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut log = Syslog::remote(&format!("unix://{}", path.display())).unwrap();
        log.send(Level::Info, "u");
        let (mut conn, _) = listener.accept().unwrap();
        let mut got = String::new();
        drop(log);
        std::io::Read::read_to_string(&mut conn, &mut got).unwrap();
        assert!(got.ends_with(": u\n"), "{got}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_tcp_syslog_gone_is_dialed_again() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let mut log = Syslog::remote(&url).unwrap();
        let (first, _) = listener.accept().unwrap();
        drop(first);
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut again = loop {
            log.send(Level::Info, "again");
            if let Ok((c, _)) = listener.accept() {
                break c;
            }
            assert!(std::time::Instant::now() < deadline, "not dialed again");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        drop(log);
        again.set_nonblocking(false).unwrap();
        let mut got = String::new();
        std::io::Read::read_to_string(&mut again, &mut got).unwrap();
        assert!(got.ends_with(": again\n"), "{got}");
    }

    #[test]
    fn a_local_syslog_takes_datagrams() {
        let path = std::env::temp_dir().join(format!("naq-dgram-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let server = UnixDatagram::bind(&path).unwrap();
        let target = Target::Dgram(path.clone());
        let conn = target.connect().unwrap();
        let mut log = Syslog::new(target, conn, None);
        log.send(Level::Warn, "w");
        let mut buf = [0; 128];
        let n = server.recv(&mut buf).unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.starts_with("<28>") && got.ends_with(": w\n"), "{got}");
        let _ = std::fs::remove_file(&path);
        // Where the host has a syslog, it is reached; else that fails.
        let _ = Syslog::local();
    }
}
