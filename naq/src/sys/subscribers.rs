//! `$SYS.DEBUG.SUBSCRIBERS`: how many subscribe to a subject, or to a
//! queue group on it, in the account that asks, across the cluster, as
//! `nats-server` counts them; and `$SYS.REQ.ACCOUNT.NSUBS`, how a server
//! asks the others that have connections of the account for their counts.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use naq_proto::client::Pub;
use naq_proto::subject;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use super::Service;
use super::later::{Answer, Asked, later};
use crate::imports::info::{self, ClientInfo};
use crate::imports::service::Tap;
use crate::index::{Found, Group, Index, Interest};
use crate::lane::{Lane, Outs};
use crate::server::Shared;

/// The subject of the count.
const DEBUG: &[u8] = b"$SYS.DEBUG.SUBSCRIBERS";

/// The subject of the count a server asks the others for.
const NSUBS: &[u8] = b"$SYS.REQ.ACCOUNT.NSUBS";

/// How long a count waits for the other servers.
const WAIT: Duration = Duration::from_millis(500);

/// Counts that wait at once, at most; past them, a count is of this
/// server alone.
const MOST: usize = 1 << 12;

/// Puts the taps of counts into `index`, the system account's, with the
/// answers to this server's at `tallies`.
pub(super) fn install(index: &mut Index, tallies: &Tallies) {
    index.tap(DEBUG, Tap::Sys(Service::Subscribers));
    index.tap(NSUBS, Tap::Sys(Service::Nsubs));
    index.tap(&tallies.filter(), Tap::Sys(Service::Counted));
}

/// What a count is of: the subscribers of `subject`, or of queue group
/// `queue` on it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Of {
    subject: Vec<u8>,
    /// Empty is no group: on a filter with wildcards, plain subscribers.
    queue: Option<Vec<u8>>,
}

impl Of {
    /// The count `body` asks for, as Go reads it: a subject, then a group
    /// after one space.
    fn parse(body: &[u8]) -> Of {
        let body = body.trim_ascii();
        let mut words = body.split(|&b| b == b' ');
        let subject = words.next().unwrap_or_default().to_vec();
        Of {
            subject,
            queue: words.next().map(<[u8]>::to_vec),
        }
    }

    /// The subscribers in `index` it counts, with the naq leafs `leafs`
    /// as bits by slot: those of clients and of naq leafs, not those of
    /// other servers or of hubs.
    fn count(&self, index: &Index, leafs: u64) -> u64 {
        let queue = self.queue.as_deref();
        if subject::is_literal(&self.subject) {
            let Some(found) = index.matches(&self.subject) else {
                return 0;
            };
            return match found {
                Found::One(i) => members(i, queue, leafs),
                Found::Many(all) => all.iter().map(|i| members(i, queue, leafs)).sum(),
            };
        }
        let mut n = 0;
        index.each(|filter, i| {
            if subject::is_subset(filter, &self.subject) {
                n += subscriptions(i, queue, leafs);
            }
        });
        n
    }
}

/// The members of `i` that a count of a literal subject takes: plain ones
/// without `queue`, those of `queue` else, a naq leaf's queue group as
/// many as it has.
fn members(i: &Interest, queue: Option<&[u8]>, leafs: u64) -> u64 {
    let weight = |g: &Group| {
        let of_leafs = g.servers.iter().filter(|&&(s, _)| in_slots(leafs, s));
        g.weight() + of_leafs.map(|&(_, m)| u64::from(m.all)).sum::<u64>()
    };
    let plain = if queue.is_none() { weight(&i.plain) } else { 0 };
    let groups = i
        .queues
        .iter()
        .filter(|(n, _)| queue.is_none_or(|q| **n == *q));
    plain + groups.map(|(_, g)| weight(g)).sum::<u64>()
}

/// The subscriptions of `i` that a count of a filter with wildcards takes,
/// one each: plain ones without `queue` or with an empty one, those of
/// `queue` else.
fn subscriptions(i: &Interest, queue: Option<&[u8]>, leafs: u64) -> u64 {
    let each = |g: &Group| {
        let of_leafs = g.servers.iter().filter(|&&(s, _)| in_slots(leafs, s));
        g.weight() + of_leafs.count() as u64
    };
    let plain = if queue.is_none_or(<[u8]>::is_empty) {
        each(&i.plain)
    } else {
        0
    };
    let groups = i
        .queues
        .iter()
        .filter(|(n, _)| queue.is_none_or(|q| **n == *q));
    plain + groups.map(|(_, g)| each(g)).sum::<u64>()
}

/// Whether slot `slot` is among `slots`, as bits.
const fn in_slots(slots: u64, slot: u16) -> bool {
    slots & crate::lane::bit(slot) != 0
}

/// Takes count request `m`, which came on `lane`: answered once the other
/// servers with connections of the account told theirs.
pub(super) fn take(lane: &Lane, m: &Pub<'_>) -> bool {
    if m.reply.is_some_and(|r| !r.is_empty()) {
        let at = lane.id;
        later(lane, m, move |shared, asked| answer(shared, at, asked));
    }
    true
}

/// The account a count `asked` is of: the one its `Nats-Request-Info`
/// names, the service it went through first; else the system account,
/// where the client that asked is.
fn account_of(s: &Shared, asked: &Asked) -> Option<u32> {
    let header = info::header(&asked.headers, info::HEADER);
    match header.map(serde_json::from_slice::<ClientInfo>) {
        Some(Err(_)) => None,
        Some(Ok(ci)) if !ci.service.is_empty() => s.accounts.id(&ci.service),
        Some(Ok(ci)) if !ci.account.is_empty() => s.accounts.id(&ci.account),
        _ => s.system,
    }
}

/// The answer to count `asked`, which came on lane `at`: the count here,
/// and those the others tell in [`WAIT`].
async fn answer(shared: Arc<Shared>, at: usize, asked: Asked) -> Option<Answer> {
    let s = &*shared;
    let account = account_of(s, &asked)?;
    let of = Of::parse(&asked.body);
    let lane = crate::lane::get(s.id, at)?;
    let here = of.count(&lane.index(account).borrow(), lane.slots.leafs());
    let expected = s.sys.remote.serving(account);
    let more = match (expected, s.system) {
        (0, _) | (_, None) => 0,
        (n, Some(sys)) => match Ticket::new(&shared, n) {
            Some((inbox, ticket)) => {
                ask(&lane, sys, &inbox, s.accounts.name(account), &of).await;
                ticket.sum().await
            }
            None => 0,
        },
    };
    let n = i64::try_from(here).unwrap_or(i64::MAX).saturating_add(more);
    Some(Answer::new(asked.reply, n.to_string().into_bytes()))
}

/// Go's `accNumSubsReq`: a queue group in base 64.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Req {
    acc: String,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue: Option<String>,
}

/// Asks the other servers from `lane` for their count `of` in account
/// `acc`, answered to `inbox` in the system account `sys`.
async fn ask(lane: &Lane, sys: u32, inbox: &[u8], acc: &str, of: &Of) {
    let req = Req {
        acc: acc.to_owned(),
        subject: String::from_utf8_lossy(&of.subject).into_owned(),
        queue: of
            .queue
            .as_deref()
            .filter(|q| !q.is_empty())
            .map(|q| data_encoding::BASE64.encode(q)),
    };
    let payload = crate::monitor::json::compact(&req);
    let m = Pub {
        subject: NSUBS,
        reply: Some(inbox),
        headers: None,
        payload: &payload,
    };
    let mut out = Outs::new(lane);
    crate::lane::inject(lane, &mut out, sys, &m);
    lane.flush();
    lane.ship_imported(&mut out).await;
}

/// Takes `m`, another server's request for this one's count, which came
/// on `lane`: answered if the account has connections here.
pub(super) fn nsubs(lane: &Lane, m: &Pub<'_>) -> bool {
    let s = &lane.shared;
    if m.payload.is_empty() {
        s.log.error(format_args!("request requires a body"));
        return true;
    }
    let req = serde_json::from_slice::<Req>(m.payload).map_err(|e| e.to_string());
    let of = req.and_then(|r| {
        let queue = r.queue.map(|q| data_encoding::BASE64.decode(q.as_bytes()));
        let queue = queue.transpose().map_err(|e| e.to_string())?;
        let subject = r.subject.into_bytes();
        Ok((r.acc, Of { subject, queue }))
    });
    let (acc, of) = match of {
        Ok(o) => o,
        Err(e) => {
            s.log.error(format_args!(
                "Error unmarshalling account nsubs request message: {e}"
            ));
            return true;
        }
    };
    let Some(account) = s.accounts.id(&acc) else {
        return true;
    };
    if m.reply.is_some_and(|r| !r.is_empty()) {
        let at = lane.id;
        later(lane, m, move |shared, asked| async move {
            let c = crate::monitor::conns(&shared, account).await?;
            if c.total == 0 {
                return None;
            }
            let lane = crate::lane::get(shared.id, at)?;
            let n = of.count(&lane.index(account).borrow(), lane.slots.leafs());
            Some(Answer::new(asked.reply, n.to_string().into_bytes()))
        });
    }
    true
}

/// Counts of this server that wait for the others' answers, on
/// `$SYS._INBOX.<server hash>.<token>`.
#[derive(Debug)]
pub(crate) struct Tallies {
    /// `$SYS._INBOX.`, the hash of the server name, `.`.
    prefix: Box<[u8]>,
    pending: Mutex<FxHashMap<Token, Tally>>,
}

/// A reply token.
type Token = [u8; 8];

/// One count: the answers it still waits for, their sum so far, and who
/// hears once they all came.
#[derive(Debug)]
struct Tally {
    left: usize,
    sum: i64,
    done: Option<oneshot::Sender<()>>,
}

impl Tallies {
    /// The counts of a server whose name hashes to `node`.
    pub(crate) fn new(node: [u8; 8]) -> Tallies {
        Tallies {
            prefix: [&b"$SYS._INBOX."[..], &node, b"."].concat().into(),
            pending: Mutex::default(),
        }
    }

    /// The filter of the answers.
    fn filter(&self) -> Vec<u8> {
        [&self.prefix[..], b"*"].concat()
    }

    /// Takes `payload`, which came on `subject`, as an answer to the count
    /// it names: whether one waited for it. An answer that is not a
    /// number counts as one, but adds nothing, as in `nats-server`.
    pub(super) fn answer(&self, subject: &[u8], payload: &[u8]) -> bool {
        let Some(token) = subject
            .strip_prefix(&self.prefix[..])
            .and_then(|t| Token::try_from(t).ok())
        else {
            return false;
        };
        let mut p = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(t) = p.get_mut(&token) else {
            return false;
        };
        let n = std::str::from_utf8(payload)
            .ok()
            .and_then(|n| n.parse::<i32>().ok());
        t.sum = t.sum.saturating_add(n.map_or(0, i64::from));
        t.left = t.left.saturating_sub(1);
        if t.left == 0
            && let Some(done) = t.done.take()
        {
            let _ = done.send(());
        }
        true
    }
}

/// A count waiting for the answers of the others; dropped, it waits no
/// more.
struct Ticket {
    shared: Arc<Shared>,
    token: Token,
    done: oneshot::Receiver<()>,
}

impl Ticket {
    /// A count `servers` will answer: its inbox, and its ticket. `None` if
    /// too many wait.
    fn new(shared: &Arc<Shared>, servers: usize) -> Option<(Vec<u8>, Ticket)> {
        let tallies = &shared.sys.tallies;
        let (tx, rx) = oneshot::channel();
        let token = crate::callout::token();
        let mut p = tallies
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if p.len() >= MOST || p.contains_key(&token) {
            return None;
        }
        let tally = Tally {
            left: servers,
            sum: 0,
            done: Some(tx),
        };
        p.insert(token, tally);
        drop(p);
        let inbox = [&tallies.prefix[..], &token].concat();
        let ticket = Ticket {
            shared: shared.clone(),
            token,
            done: rx,
        };
        Some((inbox, ticket))
    }

    /// The sum of the answers that came once all did, or in [`WAIT`].
    async fn sum(mut self) -> i64 {
        // A timeout is fine: the answers that came count.
        let _ = tokio::time::timeout(WAIT, &mut self.done).await;
        let tallies = &self.shared.sys.tallies;
        let mut p = tallies
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        p.remove(&self.token).map_or(0, |t| t.sum)
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let tallies = &self.shared.sys.tallies;
        let mut p = tallies
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        p.remove(&self.token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_names_a_subject_then_a_group_after_one_space() {
        let of = |b: &[u8]| {
            let o = Of::parse(b);
            (o.subject, o.queue)
        };
        assert_eq!(of(b"foo.bar"), (b"foo.bar".to_vec(), None));
        assert_eq!(
            of(b" foo.bar q \r\n"),
            (b"foo.bar".to_vec(), Some(b"q".to_vec()))
        );
        assert_eq!(
            of(b"foo.baz   r"),
            (b"foo.baz".to_vec(), Some(Vec::new())),
            "two spaces name an empty group"
        );
        assert_eq!(of(b""), (Vec::new(), None));
    }

    #[test]
    fn naq_leafs_count_by_their_members_for_a_subject_and_once_for_a_filter() {
        use crate::index::Members;
        let leaf = 3;
        let plain = Group {
            lanes: vec![(1, 2)],
            servers: vec![(leaf, Members::from(1)), (4, Members::from(1))],
            ..Group::default()
        };
        let q = Group {
            lanes: vec![(1, 1)],
            servers: vec![(leaf, Members::from(5))],
            ..Group::default()
        };
        let i = Interest {
            plain,
            queues: vec![(b"q".to_vec().into(), q)],
            ..Interest::default()
        };
        let leafs = crate::lane::bit(leaf);
        assert_eq!(members(&i, None, leafs), 3 + 6, "slot 4 is not a leaf");
        assert_eq!(members(&i, Some(b"q"), leafs), 6);
        assert_eq!(members(&i, Some(b""), leafs), 0);
        assert_eq!(subscriptions(&i, None, leafs), 3 + 2);
        assert_eq!(subscriptions(&i, Some(b""), leafs), 3, "plain ones");
        assert_eq!(subscriptions(&i, Some(b"q"), leafs), 2);
    }

    #[test]
    fn answers_add_up_until_the_last() {
        let t = Tallies::new(*b"NUmM6cRx");
        let (tx, mut rx) = oneshot::channel();
        let token = *b"abcdefgh";
        let tally = Tally {
            left: 3,
            sum: 0,
            done: Some(tx),
        };
        let lock = || t.pending.lock().unwrap_or_else(PoisonError::into_inner);
        lock().insert(token, tally);
        let to = b"$SYS._INBOX.NUmM6cRx.abcdefgh";
        assert!(t.answer(to, b"4"));
        assert!(t.answer(to, b"no"), "counted, adding nothing");
        assert!(rx.try_recv().is_err());
        assert!(!t.answer(b"$SYS._INBOX.NUmM6cRx.zzzzzzzz", b"1"));
        assert!(t.answer(to, b"-1"));
        assert!(rx.try_recv().is_ok(), "all came");
        assert_eq!(lock()[&token].sum, 3);
    }
}
