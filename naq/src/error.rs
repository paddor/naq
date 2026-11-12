//! Server errors.

use std::io;

/// Why a server did not start, or its configuration could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The client port could not be bound.
    #[error("cannot listen on {addr}")]
    Listen {
        /// Host and port as configured.
        addr: String,
        /// The socket error.
        #[source]
        source: io::Error,
    },
    /// The IO lanes could not start.
    #[error("cannot start the IO lanes")]
    Lanes(#[source] io::Error),
    /// A configuration file could not be read.
    #[error("cannot read {path}")]
    Read {
        /// The file.
        path: String,
        /// The read error.
        #[source]
        source: io::Error,
    },
    /// The TLS certificates or key cannot be used.
    #[error("tls: {0}")]
    Tls(String),
    /// Options that contradict themselves.
    #[error("bad options: {0}")]
    Options(String),
    /// The process ID or ports file cannot be written.
    #[error("cannot write {path}")]
    Write {
        /// The file.
        path: String,
        /// The write error.
        #[source]
        source: io::Error,
    },
    /// The log file cannot be opened, or the syslog not reached.
    #[error("cannot log")]
    Log(#[source] io::Error),
    /// A reload holds a change the running server cannot take, or cannot
    /// read the options again: `nats-server`'s words.
    #[error("{0}")]
    Reload(String),
    /// A configuration does not parse, or holds what naq cannot use.
    #[error("{at}: {reason}")]
    Config {
        /// File and line, or the line alone.
        at: String,
        /// What is wrong.
        reason: String,
    },
}

/// `e` and its sources, on one line.
pub(crate) fn chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg = format!("{msg}: {s}");
        src = s.source();
    }
    msg
}

/// An engine error as an I/O error, so engine types stay private.
pub(crate) fn io(e: zzq_tokio::Error) -> io::Error {
    match e {
        zzq_tokio::Error::Io(e) | zzq_tokio::Error::AddressInUse { source: e, .. } => e,
        e => io::Error::other(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_errors_become_io_errors_with_their_kind() {
        let e = io(zzq_tokio::Error::Io(io::Error::from(
            io::ErrorKind::AddrInUse,
        )));
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
        let e = io(zzq_tokio::Error::Closed);
        assert_eq!(e.kind(), io::ErrorKind::Other);
        assert_eq!(e.to_string(), "context is shut down");
    }
}
