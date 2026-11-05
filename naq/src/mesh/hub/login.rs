//! How naq leafs log in to this hub: after its `Hello`, with a nonce,
//! each sends a `Connect` with its credentials, checked as `nats-server`
//! checks those of Go leafs.

use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use naq_proto::peer::{self, Connect, Hello};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::ConnectionType;
use crate::auth::{Auth, Check, Creds, Grant, Origin};
use crate::server::Shared;

/// Leafs greeted and not logged in yet, at most: the oldest goes first.
const WAITING: usize = 64;

/// A leaf greeted, which has yet to log in.
#[derive(Debug)]
pub(super) struct Greeted {
    /// The routing identity of its control connection.
    pub(super) who: Bytes,
    nonce: String,
    at: Instant,
    pub(super) name: String,
    pub(super) cluster: Rc<[u8]>,
    pub(super) epoch: u64,
    /// What it takes no messages on, from its `Connect`.
    pub(super) deny: Vec<String>,
    /// It hears of no interest of other leafs.
    pub(super) isolate: bool,
}

/// What came of a `Connect`.
#[derive(Debug)]
pub(super) enum Outcome {
    /// The leaf links, with what it was granted.
    Pass(Greeted, Grant),
    /// It does not, at this routing identity.
    Fail(Bytes),
    /// A bcrypt comparison runs: the outcome comes from [`Logins::next`].
    Later,
    /// No such leaf was greeted, or not lately.
    Unknown,
}

/// The leafs logging in.
#[derive(Debug)]
pub(super) struct Logins {
    auth: Option<Auth>,
    /// The account of a leaf that needs no credentials.
    account: u32,
    timeout: Duration,
    waiting: VecDeque<Greeted>,
    /// Bcrypt comparisons that ended.
    done: (
        mpsc::UnboundedSender<Outcome>,
        mpsc::UnboundedReceiver<Outcome>,
    ),
}

impl Logins {
    /// The logins of naq leafs of `shared`'s server, which binds those that
    /// need no credentials to `account`.
    pub(super) fn new(shared: &Shared, account: u32) -> Logins {
        let opts = &shared.opts;
        Logins {
            auth: Auth::leafnodes(opts, &shared.accounts, shared.auth.as_ref()),
            account,
            timeout: opts
                .leafnodes
                .as_ref()
                .map_or(Duration::from_secs(2), |l| l.auth_timeout),
            waiting: VecDeque::new(),
            done: mpsc::unbounded_channel(),
        }
    }

    /// Notes the leaf of routing identity `who`, which said `h`, as
    /// greeted: in place of an earlier greeting of it. Returns the nonce it
    /// signs.
    pub(super) fn greet(&mut self, who: Bytes, h: &Hello<'_>) -> String {
        self.waiting.retain(|g| g.who != who);
        if self.waiting.len() >= WAITING {
            self.waiting.pop_front();
        }
        let nonce = crate::auth::nonce();
        self.waiting.push_back(Greeted {
            who,
            nonce: nonce.clone(),
            at: Instant::now(),
            name: String::from_utf8_lossy(h.name).into_owned(),
            cluster: h.cluster.into(),
            epoch: h.epoch,
            deny: Vec::new(),
            isolate: false,
        });
        nonce
    }

    /// Checks the credentials `c` of the leaf of routing identity `who`.
    pub(super) fn connect(&mut self, who: &[u8], c: &Connect<'_>) -> Outcome {
        let Some(at) = self.waiting.iter().position(|g| *g.who == *who) else {
            return Outcome::Unknown;
        };
        let Some(mut g) = self.waiting.remove(at) else {
            return Outcome::Unknown;
        };
        g.deny = peer::words(c.deny_pub)
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect();
        g.isolate = c.isolate;
        let Some(auth) = &self.auth else {
            let grant = Grant {
                account: self.account,
                perms: None,
            };
            return Outcome::Pass(g, grant);
        };
        let leaf = Origin::of(ConnectionType::Leafnode);
        match auth.check(&mut creds(c), g.nonce.as_bytes(), leaf) {
            Check::Pass(grant) => Outcome::Pass(g, grant),
            // Leafs give no JWT: they log in otherwise.
            Check::Fail | Check::User(_) => Outcome::Fail(g.who),
            Check::Bcrypt(p) => {
                let tx = self.done.0.clone();
                tokio::task::spawn_local(async move {
                    let grant = p.grant.clone();
                    // Slow by design: off the lane.
                    let holds = tokio::task::spawn_blocking(move || p.holds()).await;
                    let _ = tx.send(if holds.unwrap_or(false) {
                        Outcome::Pass(g, grant)
                    } else {
                        Outcome::Fail(g.who)
                    });
                });
                Outcome::Later
            }
        }
    }

    /// The outcome of the next bcrypt comparison that ends. Cancel-safe.
    pub(super) async fn next(&mut self) -> Outcome {
        // Never `None`: this holds a sender.
        self.done.1.recv().await.unwrap_or(Outcome::Later)
    }

    /// Lets go of the leafs that did not log in in time. Returns their
    /// routing identities.
    pub(super) fn expire(&mut self, now: Instant) -> Vec<Bytes> {
        let mut late = Vec::new();
        while self
            .waiting
            .front()
            .is_some_and(|g| now.duration_since(g.at) > self.timeout)
        {
            if let Some(g) = self.waiting.pop_front() {
                late.push(g.who);
            }
        }
        late
    }
}

/// The credentials of `c`, as a client's.
fn creds(c: &Connect<'_>) -> Creds {
    let text = |b: &[u8]| (!b.is_empty()).then(|| String::from_utf8_lossy(b).into_owned());
    Creds {
        user: text(c.user),
        pass: text(c.pass),
        token: text(c.token),
        nkey: text(c.nkey),
        sig: text(c.sig),
        jwt: None,
    }
}
