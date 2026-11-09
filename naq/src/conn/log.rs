//! A client's log lines, as `nats-server` writes them.

use std::fmt::{self, Write as _};

use naq_proto::client::ParseError;

use super::{Client, Close, Conn, Stage};
use crate::server::Shared;

/// Bytes of the input a parse error shows, as in `nats-server`.
const SNIPPET: usize = 32;

/// What a client logged in with, for its log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum How {
    User,
    Nkey,
    Jwt,
    Token,
}

impl How {
    /// What `creds` log in with, if anything.
    pub(super) const fn of(creds: &crate::auth::Creds) -> Option<How> {
        if creds.user.is_some() {
            Some(How::User)
        } else if creds.nkey.is_some() {
            Some(How::Nkey)
        } else if creds.jwt.is_some() {
            Some(How::Jwt)
        } else if creds.token.is_some() {
            Some(How::Token)
        } else {
            None
        }
    }
}

impl Client {
    /// What its log lines start with: its address and id, and once it
    /// `connected`, its names and user.
    pub(crate) fn label(&self, shared: &Shared, connected: bool) -> String {
        let meta = self.meta.borrow();
        let kind = if meta.websocket { "wid" } else { "cid" };
        let mut s = if meta.ip.contains(':') {
            format!("[{}]:{} - {kind}:{}", meta.ip, meta.port, self.id)
        } else {
            format!("{}:{} - {kind}:{}", meta.ip, meta.port, self.id)
        };
        if !connected {
            return s;
        }
        let names: Vec<String> = [
            meta.version.as_ref().map(|v| format!("v{v}")),
            meta.lang.clone(),
            meta.name.clone(),
        ]
        .into_iter()
        .flatten()
        .filter(|n| !n.is_empty())
        .collect();
        let user = meta.user.as_deref().unwrap_or_default();
        let who = match meta.how {
            Some(How::User) => Some(format!("user:{user}")),
            Some(How::Nkey) => Some(format!("nkey:{user}")),
            Some(How::Jwt) => Some(format!("jwt:{user}")),
            Some(How::Token) => Some("token".to_owned()),
            None => None,
        };
        if !names.is_empty() {
            let _ = write!(s, " - {:?}", names.join(":"));
        }
        if let Some(who) = who {
            let account = shared.accounts.name(self.account.get());
            let _ = write!(s, " - {:?}", format!("{account}/{who}"));
        }
        s
    }
}

impl Conn {
    pub(super) fn label(&self) -> String {
        self.client
            .label(&self.lane.shared, self.stage != Stage::Fresh)
    }

    fn log_debug(&self, args: fmt::Arguments<'_>) {
        let log = &self.lane.shared.log;
        if log.debugs() {
            log.debug(format_args!("{} - {args}", self.label()));
        }
    }

    fn log_info(&self, args: fmt::Arguments<'_>) {
        self.lane
            .shared
            .log
            .info(format_args!("{} - {args}", self.label()));
    }

    fn log_error(&self, args: fmt::Arguments<'_>) {
        self.lane
            .shared
            .log
            .error(format_args!("{} - {args}", self.label()));
    }

    #[cold]
    pub(super) fn log_created(&self) {
        self.log_debug(format_args!("Client connection created"));
    }

    /// Logs why the connection ends.
    #[cold]
    /// Whom the client logged in as, as `nats-server` names it.
    pub(super) fn auth_user(&self) -> String {
        let meta = self.client.meta.borrow();
        let user = meta.user.as_deref().unwrap_or_default();
        match meta.how {
            Some(How::User) => format!("User {user:?}"),
            Some(How::Nkey) => format!("Nkey {user:?}"),
            Some(How::Jwt) => format!("JWT User {user:?}"),
            Some(How::Token) => "Token \"[REDACTED]\"".to_owned(),
            None => "User \"N/A\"".to_owned(),
        }
    }

    pub(super) fn log_why(&self, close: Close) {
        let o = &self.lane.shared.opts();
        match close {
            Close::Auth => {
                let named = self.client.meta.borrow().how.is_some();
                let who = if named {
                    format!(" - {}", self.auth_user())
                } else {
                    String::new()
                };
                self.log_error(format_args!("authentication error{who}"));
            }
            Close::AuthTimeout => self.log_debug(format_args!("Authentication Timeout")),
            Close::Stale => self.log_debug(format_args!("Stale Client Connection - Closing")),
            Close::SlowPending => self.log_info(format_args!(
                "Slow Consumer Detected: MaxPending of {} Exceeded",
                o.max_pending
            )),
            Close::SlowWrite(bytes) => self.log_info(format_args!(
                "Slow Consumer Detected: WriteDeadline of {} exceeded with 1 chunks of {bytes} total bytes.",
                crate::log::go_duration(o.write_deadline)
            )),
            Close::AccountConns | Close::MaxSubs => {
                if let Some(text) = super::farewell(close) {
                    self.log_error(format_args!("{text}"));
                }
            }
            Close::UserExpired | Close::Revoked | Close::AccountExpired => {
                if let Some(text) = super::farewell(close) {
                    self.log_debug(format_args!("{text}"));
                }
            }
            _ => {}
        }
    }

    /// Logs that the connection ends for `close`.
    #[cold]
    pub(super) fn log_closed(&self, close: Close) {
        self.log_debug(format_args!("Client connection closed: {}", close.reason()));
    }

    /// Logs that parsing failed with `e` on `rest`.
    #[cold]
    #[inline(never)]
    pub(super) fn log_parse(&self, e: &ParseError, rest: &[u8]) {
        match e {
            ParseError::MaxPayload(size) => self.log_error(format_args!(
                "maximum payload exceeded: {size} vs {}",
                self.bounds.limits.max_payload
            )),
            ParseError::ControlLine => {}
            _ => self.log_error(format_args!(
                "Client parser ERROR: proto='{}...'",
                snippet(rest)
            )),
        }
    }

    /// Logs that its permissions refused it `what`.
    #[cold]
    pub(super) fn log_violation(&self, what: fmt::Arguments<'_>) {
        self.log_error(what);
    }
}

/// The start of `rest`, quoted as Go quotes bytes. As in `nats-server`, a
/// short input loses its last byte.
fn snippet(rest: &[u8]) -> String {
    let end = if rest.len() > SNIPPET {
        SNIPPET
    } else {
        rest.len().saturating_sub(1)
    };
    crate::log::quote(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippets_quote_the_input_as_go_does() {
        assert_eq!(snippet(b"FOO BAR\r\n"), r#""FOO BAR\r""#);
        assert_eq!(snippet(b""), r#""""#);
        assert_eq!(snippet(b"a\"\\\t\x01b"), r#""a\"\\\t\x01""#);
        let long = [b'x'; 40];
        assert_eq!(snippet(&long).len(), SNIPPET + 2);
    }
}
