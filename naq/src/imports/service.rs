//! Service imports: requests of an importer, sent on to the exporting
//! account with a reply of its own, and the responses to them, sent back.
//!
//! Both are taps: interest an index holds on every lane, the same on each,
//! that the lane a message comes in on acts on once it routed it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use naq_proto::client::Pub;
use rustc_hash::FxHashMap;

use super::info::{self, ClientInfo};
use super::latency::{self, Outcome, Track};
use super::{ExportId, ServiceImport};
use crate::ResponseType;
use crate::conn::Client;
use crate::lane::{Imported, Lane, Outs, Routing, Source};

/// Interest an import puts in an index.
#[derive(Debug, Clone)]
pub(crate) enum Tap {
    /// A service import's subscription, in the importer.
    Service(Arc<ServiceImport>),
    /// The responses to requests this server sent into the account, on
    /// `_R_.<prefix>.>`.
    Responses(Arc<Responses>),
    /// The answers to auth callout requests, on `$SYS._INBOX.<hash>.*`.
    Callout(Arc<crate::callout::Waiting>),
    /// A service of the server in the system account.
    Sys(crate::sys::Service),
    /// A shadow of the plain interest of a naq hub or leaf in `slot`, bound
    /// to account `importer`, for its stream import `import`.
    Shadow {
        slot: u16,
        importer: u32,
        import: u32,
        /// The routes hear of it: the interest is a naq leaf's.
        to_routes: bool,
    },
}

/// Most requests waiting for responses in one account.
const MAX_PENDING: usize = 1 << 18;

/// Most imports one message goes through, one after the other.
const MAX_DEPTH: usize = 8;

/// Most imports one message sets off, chained ones counted.
const MAX_WORK: usize = 64;

/// The requests sent into one account, by the token of their reply.
#[derive(Debug)]
pub(crate) struct Responses {
    /// `_R_.`, six letters or digits, `.`: the replies of this server's
    /// requests into the account.
    prefix: [u8; 11],
    pending: Mutex<FxHashMap<[u8; 6], Response>>,
}

/// Where the responses to one request go.
#[derive(Debug, Clone)]
struct Response {
    /// The account the request came from.
    to: u32,
    /// The reply the requester gave, there.
    reply: Box<[u8]>,
    kind: ResponseType,
    /// How long it waits for a response.
    threshold: Duration,
    /// When it was made, or last got a response.
    at: Instant,
    /// The export the request went through.
    export: ExportId,
    /// Its latency sample to come, if it is sampled.
    track: Option<Box<Track>>,
}

impl Responses {
    /// The responses of an account, with a reply prefix from `random`.
    pub(crate) fn new(mut random: impl FnMut(u64) -> u64) -> Responses {
        let mut prefix = *b"_R_.000000.";
        for b in &mut prefix[4..10] {
            *b = base62(random(62));
        }
        Responses {
            prefix,
            pending: Mutex::default(),
        }
    }

    /// The filter of the replies: `_R_.<prefix>.>`.
    pub(crate) fn filter(&self) -> Vec<u8> {
        let mut f = self.prefix.to_vec();
        f.push(b'>');
        f
    }

    /// Drops the requests older than their threshold at `now`. Returns
    /// those of them that are sampled.
    pub(crate) fn expire(&self, now: Instant) -> Vec<Track> {
        let mut sampled = Vec::new();
        if let Ok(mut p) = self.pending.lock() {
            p.retain(|_, r| {
                let keep = now.saturating_duration_since(r.at) < r.threshold;
                if !keep && let Some(t) = r.track.take() {
                    sampled.push(*t);
                }
                keep
            });
        }
        sampled
    }

    /// Waits for responses to `r`: writes its reply, with a token from
    /// `random`, into `out`. A sampled request's reply ends in `node`, the
    /// server's hash, and `T`, as `nats-server` tracks it. `None` if too
    /// many wait already.
    fn wait(
        &self,
        r: Response,
        mut random: impl FnMut(u64) -> u64,
        node: Option<&[u8; 8]>,
        out: &mut Vec<u8>,
    ) -> Option<[u8; 6]> {
        let mut pending = self.pending.lock().ok()?;
        if pending.len() >= MAX_PENDING {
            return None;
        }
        let token = loop {
            let mut t = [0; 6];
            for b in &mut t {
                *b = base62(random(62));
            }
            if !pending.contains_key(&t) {
                break t;
            }
        };
        let tracked = r.track.is_some();
        pending.insert(token, r);
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(&token);
        if let Some(node) = node.filter(|_| tracked) {
            out.push(b'.');
            out.extend_from_slice(node);
            out.extend_from_slice(b".T");
        }
        Some(token)
    }

    /// The request of reply `subject`: taken out if it gets one response.
    fn take(&self, subject: &[u8]) -> Option<([u8; 6], Response)> {
        let rest = subject.strip_prefix(&self.prefix[..])?;
        let (token, tail) = rest.split_at_checked(6)?;
        // A sampled request's reply: `.<node>.T` follows.
        let tracked = tail.len() == 11 && tail[0] == b'.' && tail.ends_with(b".T");
        if !(tail.is_empty() || tracked) {
            return None;
        }
        let token: [u8; 6] = token.try_into().ok()?;
        let mut pending = self.pending.lock().ok()?;
        let r = match pending.get(&token)?.kind {
            ResponseType::Singleton => pending.remove(&token)?,
            _ => pending.get(&token)?.clone(),
        };
        Some((token, r))
    }

    /// After a response to `token`: it waits on if `more`, else it is done
    /// and returned.
    fn answered(&self, token: [u8; 6], more: bool) -> Option<Response> {
        let mut p = self.pending.lock().ok()?;
        if more {
            if let Some(r) = p.get_mut(&token) {
                r.at = Instant::now();
            }
            None
        } else {
            p.remove(&token)
        }
    }

    /// Requests waiting.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.pending.lock().map_or(0, |p| p.len())
    }
}

pub(crate) const fn base62(n: u64) -> u8 {
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[n as usize % 62]
}

/// Puts the taps of every import of the server into the indexes of
/// `lane`.
pub(crate) fn install(lane: &Lane) {
    let shared = &lane.shared;
    let mut answers = vec![false; shared.accounts.len() as usize];
    for (a, account) in shared.accounts.iter() {
        for si in &account.imports().services {
            lane.index(a)
                .borrow_mut()
                .tap(&si.from, Tap::Service(si.clone()));
            answers[a as usize] = true;
            if let Some(to) = answers.get_mut(si.to as usize) {
                *to = true;
            }
        }
    }
    for (a, account) in shared.accounts.iter() {
        if answers.get(a as usize) == Some(&true) {
            let r = &account.responses;
            lane.index(a)
                .borrow_mut()
                .tap(&r.filter(), Tap::Responses(r.clone()));
        }
    }
    if lane.id == 0 && (answers.contains(&true) || shared.accounts.growing()) {
        tokio::task::spawn_local(sweep(Arc::downgrade(shared)));
    }
}

/// Puts the taps of the imports of `account`, an account added while the
/// server runs, into the indexes of `lane`, unless they are there: those
/// of its service imports, and the response taps of it and its
/// exporters. Lane 0 tells the other servers.
pub(crate) fn install_account(lane: &Lane, account: u32) {
    let shared = &lane.shared;
    let Some(a) = shared.accounts.get(account) else {
        return;
    };
    let mut added: Vec<(u32, Vec<u8>)> = Vec::new();
    for si in &a.imports().services {
        let mut index = lane.index(account).borrow_mut();
        if !index.has_tap(
            &si.from,
            |t| matches!(t, Tap::Service(x) if Arc::ptr_eq(x, si)),
        ) {
            index.tap(&si.from, Tap::Service(si.clone()));
            added.push((account, si.from.to_vec()));
        }
        drop(index);
        for to in [account, si.to] {
            let Some(r) = shared.accounts.get(to).map(|x| &x.responses) else {
                continue;
            };
            let filter = r.filter();
            let mut index = lane.index(to).borrow_mut();
            if !index.has_tap(
                &filter,
                |t| matches!(t, Tap::Responses(x) if Arc::ptr_eq(x, r)),
            ) {
                index.tap(&filter, Tap::Responses(r.clone()));
                added.push((to, filter));
            }
        }
    }
    for (account, filter) in added {
        lane.changed(account, &filter, None);
    }
}

/// Drops the requests past their threshold, every second, while the
/// server runs.
async fn sweep(shared: std::sync::Weak<crate::server::Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let Some(s) = shared.upgrade() else {
            return;
        };
        let now = Instant::now();
        let expired: Vec<Track> = s
            .accounts
            .iter()
            .flat_map(|(_, a)| a.responses.expire(now))
            .collect();
        if expired.is_empty() {
            continue;
        }
        // The samples of requests that timed out go out from lane 0.
        let Some(lane) = crate::lane::get(s.id, 0) else {
            return;
        };
        let mut out = Outs::new(&lane);
        for t in &expired {
            let json = latency::sample(&lane, t, Outcome::Timeout, None);
            latency::publish(&lane, &mut out, t.account, &t.subject, &json);
        }
        lane.flush();
        lane.ship_imported(&mut out).await;
    }
}

/// Where a message comes from, for the imports it meets.
#[derive(Debug, Clone, Copy)]
pub(crate) struct From<'a> {
    /// The publishing client, if a client published it.
    pub(crate) client: Option<&'a Client>,
    /// Who gets nothing: the publisher without echo; 0 for nobody.
    pub(crate) skip: u64,
    /// Who sent it to this server.
    pub(crate) source: Source,
    /// The slots of servers it does not go to, as bits.
    pub(crate) skips: u64,
}

/// Offsets of a message's parts in an arena.
#[derive(Debug, Clone, Copy)]
struct Parts {
    subject: (usize, usize),
    reply: Option<(usize, usize)>,
    headers: Option<(usize, usize)>,
    payload: (usize, usize),
}

impl Parts {
    fn of<'a>(&self, arena: &'a [u8]) -> Pub<'a> {
        let get = |(at, len): (usize, usize)| &arena[at..at + len];
        Pub {
            subject: get(self.subject),
            reply: self.reply.map(get),
            headers: self.headers.map(get),
            payload: get(self.payload),
        }
    }
}

/// The exports a message went through, in order.
#[derive(Debug, Clone, Copy, Default)]
struct Chain {
    exports: [ExportId; MAX_DEPTH],
    len: usize,
    /// Whether the last import shared the requester's details.
    share: bool,
}

impl Chain {
    fn has(&self, e: ExportId) -> bool {
        self.exports[..self.len].contains(&e)
    }

    /// The chain past export `e`, if it is not full.
    const fn then(mut self, e: ExportId, share: bool) -> Option<Chain> {
        if self.len == MAX_DEPTH {
            return None;
        }
        self.exports[self.len] = e;
        self.len += 1;
        self.share = share;
        Some(self)
    }
}

/// A message that met an import.
#[derive(Debug, Clone, Copy)]
struct Work {
    /// The message's account.
    account: u32,
    /// The message: in the arena, or the one first routed.
    msg: Option<Parts>,
    chain: Chain,
}

/// The imports one message sets off, run on the lane it came in on.
struct Run<'r, 'm> {
    lane: &'r Lane,
    out: &'r mut Outs,
    /// The message first routed.
    m: &'r Pub<'m>,
    from: From<'r>,
    /// A subscriber past the stall mark.
    stalled: Option<std::rc::Rc<Client>>,
    /// Imports it may still run.
    budget: usize,
}

/// Runs the imports message `m` of `account`, from `from`, met while it
/// was routed on `lane`, and those the messages they route meet in turn.
/// Their messages go out with `out`. Returns whether any was delivered,
/// and a subscriber past the stall mark.
pub(crate) fn run(
    lane: &Lane,
    out: &mut Outs,
    m: &Pub<'_>,
    account: u32,
    from: From<'_>,
) -> (bool, Option<std::rc::Rc<Client>>) {
    let taps: Vec<Tap> = lane.take_taps().collect();
    let mut r = Run {
        lane,
        out,
        m,
        from,
        stalled: None,
        budget: MAX_WORK,
    };
    let delivered = r.taps(&taps, account, None, Chain::default());
    (delivered, r.stalled)
}

impl Run<'_, '_> {
    /// Runs `taps`, met by the message at `msg` of `account`, which came
    /// through `chain`. Returns whether any got it to anyone.
    fn taps(&mut self, taps: &[Tap], account: u32, msg: Option<Parts>, chain: Chain) -> bool {
        let mut delivered = false;
        for tap in taps {
            if self.budget == 0 {
                break;
            }
            self.budget -= 1;
            let w = Work {
                account,
                msg,
                chain,
            };
            delivered |= match *tap {
                Tap::Service(ref si) => self.request(w, si),
                Tap::Responses(ref r) => self.response(w, r),
                Tap::Callout(ref c) => self.callout(w, c),
                Tap::Sys(s) => self.sys(w, s),
                Tap::Shadow {
                    slot,
                    importer,
                    import,
                    ..
                } => self.shadow(w, slot, importer, import),
            };
        }
        delivered
    }

    /// Routes the message at `parts` in `account`, then runs the taps it
    /// met. Returns whether anyone got it, through those taps too.
    fn route_on(&mut self, parts: Parts, account: u32, chain: Chain) -> bool {
        let mut delivered = self.route(parts, account);
        let met: Vec<Tap> = self.lane.take_taps().collect();
        if !met.is_empty() {
            delivered |= self.taps(&met, account, Some(parts), chain);
        }
        delivered
    }

    /// Sends the message `w` holds to the naq hub or leaf in `slot`, as
    /// a message of `owner`, its account, with the subject its stream
    /// import `import` gives it. Not one that came through a service
    /// import, nor one the slot does not get.
    fn shadow(&mut self, w: Work, slot: u16, owner: u32, import: u32) -> bool {
        let lane = self.lane;
        if w.msg.is_some() || self.from.skips & crate::lane::bit(slot) != 0 {
            return false;
        }
        let streams = &lane.shared.accounts.imports(owner).streams;
        let Some(im) = streams.get(import as usize) else {
            return false;
        };
        let imported = self.out.imported(lane);
        let mut subject = std::mem::take(&mut imported.subject);
        subject.clear();
        im.deliver_as(self.m.subject, &mut subject);
        let p = Pub {
            subject: &subject,
            ..*self.m
        };
        Imported::outs_of(&mut imported.outs, lane, owner, false).server(lane, slot, &p, None);
        imported.subject = subject;
        true
    }

    /// Sends the request `w` holds on into the exporter of `si`, with a
    /// reply of this server's and `Nats-Request-Info`. A sampled request's
    /// latency sample goes out when it is done.
    fn request(&mut self, w: Work, si: &ServiceImport) -> bool {
        // A route's request was imported where it was published.
        if self.from.source == Source::Server || w.chain.has(si.export) {
            return false;
        }
        let Some(chain) = w.chain.then(si.export, si.share) else {
            return false;
        };
        let (lane, m) = (self.lane, self.m);
        let Some(responses) = lane.shared.accounts.get(si.to).map(|a| &a.responses) else {
            return false;
        };
        let imported = self.out.imported(lane);
        let src = message(m, &imported.arena, w.msg);
        let mut subject = std::mem::take(&mut imported.subject);
        subject.clear();
        si.rewrite_into(src.subject, &mut subject);
        let ci = client_info(lane, src.headers, &w, si.share, self.from);
        let track = track(lane, si, &ci, src.headers);
        let json = serde_json::to_vec(&ci).unwrap_or_default();
        let mut headers = std::mem::take(&mut imported.headers);
        headers.clear();
        info::set(src.headers, info::HEADER, &json, &mut headers);
        let src_reply = src.reply.map(<[u8]>::to_vec);
        let mut reply = Vec::new();
        let (token, bad) = match &src_reply {
            Some(r) if r.starts_with(b"$JS.ACK.") => {
                reply.clone_from(r);
                (None, None)
            }
            Some(r) => {
                let waiting = waiting(si, w.account, r, track);
                let node = lane.shared.node.as_ref();
                let Some(t) = responses.wait(waiting, |n| lane.below(n), node, &mut reply) else {
                    imported.subject = subject;
                    imported.headers = headers;
                    return false;
                };
                (Some(t), None)
            }
            // Without a reply, a sampled request is a bad one.
            None => (None, track),
        };
        let new = New {
            subject: &subject,
            reply: src_reply.as_ref().map(|_| &reply[..]),
            headers: Some(&headers),
        };
        let parts = push(imported, m, w.msg, &new);
        imported.subject = subject;
        imported.headers = headers;
        let delivered = self.route_on(parts, si.to, chain);
        if let Some(t) = bad {
            self.sample(&t, Outcome::BadRequest, None);
        }
        if !delivered
            && let Some(t) = token
            && let Some(t) = responses.answered(t, false).and_then(|r| r.track)
        {
            self.sample(&t, Outcome::Unavailable, None);
        }
        delivered
    }

    /// Sends the response `w` holds back to the requester, by the reply it
    /// came on. The first one sends the latency sample of a sampled
    /// request.
    /// Has the server answer the request `w` holds, for service `s`.
    fn sys(&mut self, w: Work, s: crate::sys::Service) -> bool {
        let (lane, m) = (self.lane, self.m);
        let imported = self.out.imported(lane);
        let src = message(m, &imported.arena, w.msg);
        // Copied out: the answer goes into the arena it lies in.
        let (subject, reply, payload) = (
            src.subject.to_vec(),
            src.reply.map(<[u8]>::to_vec),
            src.payload.to_vec(),
        );
        let m = Pub {
            subject: &subject,
            reply: reply.as_deref(),
            headers: None,
            payload: &payload,
        };
        crate::sys::answer(lane, self.out, s, &m)
    }

    /// Hands the answer `w` holds to the auth callout request it names.
    fn callout(&mut self, w: Work, c: &crate::callout::Waiting) -> bool {
        let (lane, m) = (self.lane, self.m);
        let imported = self.out.imported(lane);
        let src = message(m, &imported.arena, w.msg);
        c.answer(w.account, src.subject, src.payload)
    }

    fn response(&mut self, w: Work, r: &Responses) -> bool {
        let (lane, m) = (self.lane, self.m);
        let imported = self.out.imported(lane);
        let src = message(m, &imported.arena, w.msg);
        let empty = src.headers.is_none() && src.payload.is_empty();
        let src_reply = src.reply.map(<[u8]>::to_vec);
        let Some((token, mut wait)) = r.take(src.subject) else {
            return false;
        };
        let Some(chain) = w
            .chain
            .then(wait.export, w.chain.share)
            .filter(|_| !w.chain.has(wait.export))
        else {
            return false;
        };
        // A reply of the responder's goes back the other way.
        let mut reply = Vec::new();
        let back = match &src_reply {
            Some(rr) if !rr.starts_with(b"$JS.ACK.") => {
                let back = Response {
                    to: w.account,
                    reply: rr.as_slice().into(),
                    at: Instant::now(),
                    track: None,
                    ..wait.clone()
                };
                let waits = lane.shared.accounts.get(wait.to).map(|a| &a.responses);
                if waits
                    .and_then(|w| w.wait(back, |n| lane.below(n), None, &mut reply))
                    .is_none()
                {
                    return false;
                }
                Some(&reply[..])
            }
            Some(rr) => Some(&rr[..]),
            None => None,
        };
        let new = New {
            subject: &wait.reply,
            reply: back,
            headers: None,
        };
        let parts = push(imported, m, w.msg, &new);
        let delivered = self.route_on(parts, wait.to, chain);
        if wait.kind != ResponseType::Singleton {
            r.answered(token, delivered && !empty);
        }
        if let Some(t) = wait.track.take() {
            let responder = self.from.client.map(|c| details(lane, c));
            let outcome = if delivered {
                Outcome::Answered
            } else {
                Outcome::Unavailable
            };
            self.sample(&t, outcome, responder.as_ref());
        }
        delivered
    }

    /// Sends the latency sample of the request `t` tracks, which came to
    /// `outcome`.
    fn sample(&mut self, t: &Track, outcome: Outcome, responder: Option<&ClientInfo>) {
        let json = latency::sample(self.lane, t, outcome, responder);
        latency::publish(self.lane, self.out, t.account, &t.subject, &json);
    }
}

/// The latency tracking of a request through `si` by requester `ci`, with
/// headers `headers`, if its export samples it.
fn track(
    lane: &Lane,
    si: &ServiceImport,
    ci: &ClientInfo,
    headers: Option<&[u8]>,
) -> Option<Box<Track>> {
    let l = si.service.latency.as_ref()?;
    let header = latency::sampled(l, headers, |n| lane.below(n))?.header();
    Some(Box::new(Track {
        requestor: ci.clone(),
        start: SystemTime::now(),
        at: Instant::now(),
        header,
        account: si.to,
        subject: l.subject.as_bytes().into(),
    }))
}

/// The responses to a request of account `to` through `si`, with reply
/// `r` there, wait for, sampled as `track` says.
fn waiting(si: &ServiceImport, to: u32, r: &[u8], track: Option<Box<Track>>) -> Response {
    Response {
        to,
        reply: r.into(),
        kind: si.service.response,
        threshold: si.service.threshold,
        at: Instant::now(),
        export: si.export,
        track,
    }
}

/// The message at `msg` in `arena`, or `m`.
fn message<'a>(m: &'a Pub<'a>, arena: &'a [u8], msg: Option<Parts>) -> Pub<'a> {
    msg.map_or(*m, |p| p.of(arena))
}

/// The `Nats-Request-Info` of a request `w` holds, with headers
/// `headers`, through an import that shares the requester's details if
/// `share`: of the publisher on the first import, else what the last one
/// set, with this account as the service.
fn client_info(
    lane: &Lane,
    headers: Option<&[u8]>,
    w: &Work,
    share: bool,
    from: From<'_>,
) -> ClientInfo {
    let shared = &lane.shared;
    let name = shared.accounts.name(w.account).to_owned();
    let before = headers
        .and_then(|h| info::header(h, info::HEADER))
        .and_then(|v| serde_json::from_slice::<ClientInfo>(v).ok());
    if w.chain.len > 0
        && let Some(mut ci) = before
    {
        ci.service = name;
        if !w.chain.share && share {
            server_details(lane, &mut ci);
        }
        return ci;
    }
    let mut ci = ClientInfo {
        account: name,
        ..ClientInfo::default()
    };
    let Some(c) = from.client else {
        return ci;
    };
    if share {
        return details(lane, c);
    }
    ci.rtt = u64::try_from(c.rtt.get().as_nanos()).unwrap_or(u64::MAX);
    ci
}

/// All `nats-server` tells of client `c`: its account, round trip,
/// connection, names and server.
fn details(lane: &Lane, c: &Client) -> ClientInfo {
    let meta = c.meta.borrow();
    let mut ci = ClientInfo {
        account: lane.shared.accounts.name(c.account.get()).to_owned(),
        rtt: u64::try_from(c.rtt.get().as_nanos()).unwrap_or(u64::MAX),
        start: Some(crate::monitor::rfc3339(meta.start)),
        host: meta.ip.clone(),
        id: c.id,
        user: meta.user.clone().unwrap_or_default(),
        name: meta.name.clone().unwrap_or_default(),
        lang: meta.lang.clone().unwrap_or_default(),
        version: meta.version.clone().unwrap_or_default(),
        kind: "Client".into(),
        client_type: if meta.websocket { "websocket" } else { "nats" }.into(),
        ..ClientInfo::default()
    };
    server_details(lane, &mut ci);
    ci
}

/// Adds the server's name and cluster to `ci`.
fn server_details(lane: &Lane, ci: &mut ClientInfo) {
    let opts = &lane.shared.opts;
    ci.server.clone_from(&opts.server_name);
    if let Some(c) = &opts.cluster {
        ci.cluster.clone_from(&c.name);
    }
}

/// What a message an import routes has of its own.
struct New<'n> {
    subject: &'n [u8],
    reply: Option<&'n [u8]>,
    /// `None` keeps those of the source.
    headers: Option<&'n [u8]>,
}

/// Writes a message into the arena of `imported`: the parts of `new`,
/// the source's headers where `new` has none, and the source's payload.
/// The source is `m`, or the message at `src` in the arena.
fn push(imported: &mut Imported, m: &Pub<'_>, src: Option<Parts>, new: &New<'_>) -> Parts {
    let New {
        subject,
        reply,
        headers,
    } = *new;
    let Imported { arena, kept, .. } = imported;
    // What comes from the arena is copied out first: it grows below.
    kept.clear();
    let mut kept_headers = None;
    if let Some(p) = src {
        let s = p.of(arena);
        if headers.is_none()
            && let Some(h) = s.headers
        {
            kept.extend_from_slice(h);
            kept_headers = Some(h.len());
        }
        kept.extend_from_slice(s.payload);
    }
    let mut put = |b: &[u8]| {
        let at = arena.len();
        arena.extend_from_slice(b);
        (at, b.len())
    };
    let subject = put(subject);
    let reply = reply.map(&mut put);
    let headers = match (headers, src) {
        (Some(h), _) => Some(put(h)),
        (None, None) => m.headers.map(&mut put),
        (None, Some(_)) => kept_headers.map(|n| put(&kept[..n])),
    };
    let payload = match src {
        None => put(m.payload),
        Some(_) => put(&kept[kept_headers.unwrap_or(0)..]),
    };
    Parts {
        subject,
        reply,
        headers,
        payload,
    }
}

impl Run<'_, '_> {
    /// Routes the message at `parts` of the arena in `account`, as a
    /// client's publish there: every queue group picks. Shadows here skip
    /// it, as `nats-server` keeps service imports from stream exports.
    /// Returns whether anyone got it.
    fn route(&mut self, parts: Parts, account: u32) -> bool {
        let lane = self.lane;
        let Imported { arena, outs, .. } = self.out.imported(lane);
        let base: &[u8] = arena;
        let p = parts.of(base);
        let out = Imported::outs_of(outs, lane, account, true);
        let index = lane.index(account).borrow();
        let Some(found) = index.matches(p.subject) else {
            return false;
        };
        lane.imported.set(true);
        let mut r = Routing::new(lane, out, &p, base, self.from.skip).with_imports();
        r.route(&found);
        lane.imported.set(false);
        if r.stalled.is_some() {
            self.stalled = r.stalled.take();
        }
        r.delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiting(kind: ResponseType, threshold: Duration) -> Response {
        Response {
            to: 2,
            reply: b"inbox"[..].into(),
            kind,
            threshold,
            at: Instant::now(),
            export: (1, 0),
            track: None,
        }
    }

    #[test]
    fn a_request_waits_under_a_reply_of_its_own_until_answered() {
        let mut n = 0;
        let r = Responses::new(|_| {
            n += 1;
            n
        });
        assert_eq!(&r.filter()[..4], b"_R_.");
        assert_eq!(r.filter().len(), 12);
        let mut reply = Vec::new();
        let mut k = 0;
        let token = r
            .wait(
                waiting(ResponseType::Singleton, Duration::from_secs(9)),
                |_| {
                    k += 7;
                    k
                },
                None,
                &mut reply,
            )
            .unwrap();
        assert_eq!(&reply[11..], &token);
        assert!(r.take(b"_R_.nothere.abcdef").is_none());
        let (t, got) = r.take(&reply).unwrap();
        assert_eq!((t, &*got.reply), (token, &b"inbox"[..]));
        assert_eq!(r.len(), 0, "a singleton is taken out by its response");
        reply.clear();
        let token = r
            .wait(
                waiting(ResponseType::Stream, Duration::from_secs(9)),
                |n| n - 1,
                None,
                &mut reply,
            )
            .unwrap();
        assert!(r.take(&reply).is_some());
        r.answered(token, true);
        assert_eq!(r.len(), 1, "a stream waits on");
        r.answered(token, false);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn a_request_past_its_threshold_is_dropped() {
        let r = Responses::new(|n| n / 2);
        let mut reply = Vec::new();
        let mut k = 0;
        let mut next = |n| {
            k += 1;
            k % n
        };
        r.wait(
            waiting(ResponseType::Singleton, Duration::from_millis(5)),
            &mut next,
            None,
            &mut reply,
        )
        .unwrap();
        r.wait(
            waiting(ResponseType::Singleton, Duration::from_secs(60)),
            &mut next,
            None,
            &mut reply,
        )
        .unwrap();
        r.expire(Instant::now() + Duration::from_secs(1));
        assert_eq!(r.len(), 1);
    }
}
