//! Lookups of account JWTs this server sent the others, waiting for their
//! answers on `$SYS._INBOX.<server hash>.<token>`, as `nats-server` takes
//! them: empty answers until every server said it has none, else the
//! first JWT.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustc_hash::FxHashMap;
use tokio::sync::oneshot;

use crate::callout::token;

/// Most lookups that wait at once; past them, clients are refused.
const MAX_WAITING: usize = 1 << 12;

/// A reply token.
type Token = [u8; 8];

/// One lookup: the empty answers it still waits for, and where its answer
/// goes.
type Waiter = (usize, oneshot::Sender<Bytes>);

/// The lookups waiting for answers, shared by every lane.
#[derive(Debug)]
pub(crate) struct Lookups {
    /// `$SYS._INBOX.`, the hash of the server name, `.`.
    prefix: Box<[u8]>,
    pending: Mutex<FxHashMap<Token, Waiter>>,
}

impl Lookups {
    /// The lookups of a server whose name hashes to `node`.
    pub(crate) fn new(node: [u8; 8]) -> Lookups {
        Lookups {
            prefix: [&b"$SYS._INBOX."[..], &node, b"."].concat().into(),
            pending: Mutex::default(),
        }
    }

    /// The filter of the answers.
    pub(crate) fn filter(&self) -> Vec<u8> {
        [&self.prefix[..], b"*"].concat()
    }

    /// A lookup that `servers` will answer: its reply subject, and the
    /// ticket its answer comes on. `None` if too many wait.
    pub(crate) fn wait(self: &Arc<Self>, servers: usize) -> Option<(Vec<u8>, Ticket)> {
        let (tx, rx) = oneshot::channel();
        let token = token();
        {
            let mut p = self.pending.lock().ok()?;
            if p.len() >= MAX_WAITING || p.contains_key(&token) {
                return None;
            }
            p.insert(token, (servers, tx));
        }
        let reply = [&self.prefix[..], &token].concat();
        let ticket = Ticket {
            lookups: self.clone(),
            token,
            answer: rx,
        };
        Some((reply, ticket))
    }

    /// Takes `payload`, which came on `subject`, as an answer to the
    /// lookup it names: whether one waited for it.
    pub(crate) fn answer(&self, subject: &[u8], payload: &[u8]) -> bool {
        let Some(token) = subject
            .strip_prefix(&self.prefix[..])
            .and_then(|t| Token::try_from(t).ok())
        else {
            return false;
        };
        let Ok(mut p) = self.pending.lock() else {
            return false;
        };
        let Some((left, _)) = p.get_mut(&token) else {
            return false;
        };
        *left = left.saturating_sub(1);
        // Empty answers say "not here": wait for the others.
        if payload.is_empty() && *left > 0 {
            return true;
        }
        let Some((_, tx)) = p.remove(&token) else {
            return false;
        };
        drop(p);
        tx.send(Bytes::copy_from_slice(payload)).is_ok()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.pending.lock().map_or(0, |p| p.len())
    }
}

/// A lookup waiting for its answer; dropped, it waits no more.
#[derive(Debug)]
pub(crate) struct Ticket {
    lookups: Arc<Lookups>,
    token: Token,
    /// The answer: a JWT, or empty if no server has one.
    pub(crate) answer: oneshot::Receiver<Bytes>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut p) = self.lookups.pending.lock() {
            p.remove(&self.token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_answers_count_until_every_server_said_so() {
        let l = Arc::new(Lookups::new(*b"NUmM6cRx"));
        assert_eq!(l.filter(), b"$SYS._INBOX.NUmM6cRx.*");
        let (reply, mut ticket) = l.wait(2).unwrap();
        assert!(!l.answer(b"other", b""));
        assert!(l.answer(&reply, b""));
        assert!(ticket.answer.try_recv().is_err(), "one server left");
        assert!(l.answer(&reply, b""));
        assert_eq!(ticket.answer.try_recv().unwrap(), "", "none has it");
        let (reply, mut ticket) = l.wait(3).unwrap();
        assert!(l.answer(&reply, b"JWT"));
        assert!(!l.answer(&reply, b"late"), "the first JWT only");
        assert_eq!(ticket.answer.try_recv().unwrap(), "JWT");
        let (_, ticket) = l.wait(1).unwrap();
        drop(ticket);
        assert_eq!(l.len(), 0, "given up on: forgotten");
    }
}
