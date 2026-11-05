//! The callout requests waiting for answers, by the token of their reply
//! subject, `$SYS._INBOX.<server hash>.<token>`, as `nats-server` names it.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustc_hash::FxHashMap;
use tokio::sync::oneshot;

/// Most requests that wait at once; past them, clients are refused.
const MAX_WAITING: usize = 1 << 16;

/// A reply token: eight letters or digits.
type Token = [u8; 8];

/// The requests waiting for answers, shared by every lane.
#[derive(Debug)]
pub(crate) struct Waiting {
    /// `$SYS._INBOX.`, the hash of the server name, `.`.
    prefix: Box<[u8]>,
    /// By token: the callout account, and where its answer goes.
    pending: Mutex<FxHashMap<Token, (u32, oneshot::Sender<Bytes>)>>,
}

impl Waiting {
    /// The requests of a server whose name hashes to `node`.
    pub(crate) fn new(node: [u8; 8]) -> Waiting {
        Waiting {
            prefix: [&b"$SYS._INBOX."[..], &node, b"."].concat().into(),
            pending: Mutex::default(),
        }
    }

    /// The filter of the replies: the interest the answers meet.
    pub(crate) fn filter(&self) -> Vec<u8> {
        [&self.prefix[..], b"*"].concat()
    }

    /// A request into `account`, with token `token`: its reply subject,
    /// and the ticket its answer comes on. `None` if too many wait, or the
    /// token is taken.
    pub(crate) fn wait(self: &Arc<Self>, account: u32, token: Token) -> Option<(Vec<u8>, Ticket)> {
        let (tx, rx) = oneshot::channel();
        {
            let mut p = self.pending.lock().ok()?;
            if p.len() >= MAX_WAITING || p.contains_key(&token) {
                return None;
            }
            p.insert(token, (account, tx));
        }
        let reply = [&self.prefix[..], &token].concat();
        let ticket = Ticket {
            waiting: self.clone(),
            token,
            answer: rx,
        };
        Some((reply, ticket))
    }

    /// Takes `payload`, which came on `subject` in `account`, as the answer
    /// to the request it names. The first answer is the one taken. Whether
    /// a request waited for it.
    pub(crate) fn answer(&self, account: u32, subject: &[u8], payload: &[u8]) -> bool {
        let Some(token) = subject
            .strip_prefix(&self.prefix[..])
            .and_then(|t| Token::try_from(t).ok())
        else {
            return false;
        };
        let Ok(mut p) = self.pending.lock() else {
            return false;
        };
        if p.get(&token).is_none_or(|(a, _)| *a != account) {
            return false;
        }
        let Some((_, tx)) = p.remove(&token) else {
            return false;
        };
        drop(p);
        // A request given up on is gone: nobody takes the answer.
        tx.send(Bytes::copy_from_slice(payload)).is_ok()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.pending.lock().map_or(0, |p| p.len())
    }
}

/// A request waiting for its answer. Dropped, it waits no more.
#[derive(Debug)]
pub(crate) struct Ticket {
    waiting: Arc<Waiting>,
    token: Token,
    /// The answer, once it comes.
    pub(crate) answer: oneshot::Receiver<Bytes>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut p) = self.waiting.pending.lock() {
            p.remove(&self.token);
        }
    }
}

/// A fresh reply token.
pub(crate) fn token() -> Token {
    let mut raw = [0u8; 8];
    // The OS failing to give randomness leaves the token predictable, not
    // wrong: the answer still has to name the request's user key.
    let _ = getrandom::getrandom(&mut raw);
    raw.map(|b| crate::imports::service::base62(u64::from(b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_answer_in_the_account_goes_to_its_request() {
        let w = Arc::new(Waiting::new(*b"NUmM6cRx"));
        assert_eq!(w.filter(), b"$SYS._INBOX.NUmM6cRx.*");
        let (reply, mut ticket) = w.wait(3, *b"abcdefgh").unwrap();
        assert_eq!(reply, b"$SYS._INBOX.NUmM6cRx.abcdefgh");
        assert!(w.wait(3, *b"abcdefgh").is_none(), "a token once");
        assert!(!w.answer(4, &reply, b"x"), "another account");
        assert!(!w.answer(3, b"$SYS._INBOX.NUmM6cRx.abc", b"x"), "no token");
        assert!(!w.answer(3, b"other.abcdefgh", b"x"));
        assert!(w.answer(3, &reply, b"yes"));
        assert!(!w.answer(3, &reply, b"again"), "the first only");
        assert_eq!(ticket.answer.try_recv().unwrap(), "yes");
        drop(ticket);
        assert_eq!(w.len(), 0);
        let (reply, ticket) = w.wait(3, token()).unwrap();
        drop(ticket);
        assert_eq!(w.len(), 0, "given up on: forgotten");
        assert!(!w.answer(3, &reply, b"late"));
    }
}
