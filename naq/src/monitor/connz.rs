//! `/connz`: the connections, open and closed, as `nats-server` lists
//! them: filtered, sorted, paged, and in its fields.

use std::sync::Arc;
use std::time::SystemTime;

use serde::Serialize;

use super::conns::{Conn, Sub, Want, open};
use super::http::Response;
use super::query::{Query, Refused, Subs};
use super::{Counted, ask_all, pretty, rtt};
use crate::server::Shared;
use crate::times::{rfc3339_nano, uptime};

/// The connections a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    Closed,
    Any,
}

impl State {
    /// `state`, as `nats-server` reads it: any case; `all` is `any`.
    fn of(q: &Query) -> Result<State, Refused> {
        let v = q.get("state");
        match v.to_ascii_lowercase().as_str() {
            "" | "open" => Ok(State::Open),
            "closed" => Ok(State::Closed),
            "any" | "all" => Ok(State::Any),
            _ => Err(format!("Error decoding state for {v}")),
        }
    }
}

/// How connections are sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sort {
    Cid,
    Subs,
    Pending,
    MsgsTo,
    MsgsFrom,
    BytesTo,
    BytesFrom,
    Last,
    Idle,
    Uptime,
    Rtt,
    Stop,
    Reason,
}

impl Sort {
    /// `sort`, as `nats-server` reads it; `start` is `cid`.
    fn of(v: &str) -> Result<Sort, Refused> {
        Ok(match v {
            "" | "cid" | "start" => Sort::Cid,
            "subs" => Sort::Subs,
            "pending" => Sort::Pending,
            "msgs_to" => Sort::MsgsTo,
            "msgs_from" => Sort::MsgsFrom,
            "bytes_to" => Sort::BytesTo,
            "bytes_from" => Sort::BytesFrom,
            "last" => Sort::Last,
            "idle" => Sort::Idle,
            "uptime" => Sort::Uptime,
            "rtt" => Sort::Rtt,
            "stop" => Sort::Stop,
            "reason" => Sort::Reason,
            _ => return Err(format!("invalid sorting option: {v}")),
        })
    }

    /// Sorts `all` by this, as `nats-server` does; ties go by ID.
    fn apply(self, all: &mut [Arc<Conn>], now: SystemTime) {
        all.sort_by_key(|c| c.cid);
        let since = |t: SystemTime, c: &Conn| {
            c.stop
                .map_or(now, |(s, _)| s)
                .duration_since(t)
                .unwrap_or_default()
        };
        let t = |c: &Conn| c.totals;
        match self {
            Sort::Cid => {}
            Sort::Subs => all.sort_by_key(|c| std::cmp::Reverse(c.nsubs)),
            Sort::Pending => all.sort_by_key(|c| std::cmp::Reverse(c.pending)),
            Sort::MsgsTo => all.sort_by_key(|c| std::cmp::Reverse(t(c).out_msgs)),
            Sort::MsgsFrom => all.sort_by_key(|c| std::cmp::Reverse(t(c).in_msgs)),
            Sort::BytesTo => all.sort_by_key(|c| std::cmp::Reverse(t(c).out_bytes)),
            Sort::BytesFrom => all.sort_by_key(|c| std::cmp::Reverse(t(c).in_bytes)),
            Sort::Last => all.sort_by_key(|c| std::cmp::Reverse(c.last)),
            Sort::Idle => all
                .sort_by_key(|c| std::cmp::Reverse(now.duration_since(c.last).unwrap_or_default())),
            Sort::Uptime => all.sort_by_key(|c| since(c.start, c)),
            Sort::Rtt => all.sort_by_key(|c| std::cmp::Reverse(c.rtt)),
            Sort::Stop => all.sort_by_key(|c| std::cmp::Reverse(c.stop.map(|(s, _)| s))),
            Sort::Reason => all.sort_by_key(|c| c.stop.map(|(_, r)| r)),
        }
    }
}

/// What a request asks for.
#[derive(Debug)]
struct Ask {
    sort: Sort,
    auth: bool,
    state: State,
    offset: i64,
    limit: i64,
    want: Want,
    /// The account named, if one is.
    account: String,
}

impl Ask {
    /// The request of `q`, read in `nats-server`'s order: the first value
    /// it cannot take refuses it. Counted once the query is read.
    fn of(shared: &Shared, q: &Query) -> Result<Ask, Refused> {
        let auth = q.bool("auth")?;
        let subs = q.subs()?;
        let offset = q.int("offset")?;
        let limit = q.int("limit")?;
        let cid = q.uint("cid")?;
        let state = State::of(q)?;
        shared.monitor.count(Counted::Connz);
        let sort = Sort::of(q.get("sort"))?;
        for (by, name) in [(Sort::Stop, "stop"), (Sort::Reason, "reason")] {
            if sort == by && state != State::Closed {
                return Err(format!("sort by {name} only valid on closed connections"));
            }
        }
        let limit = match (cid, limit) {
            (1.., _) => 1,
            (_, ..=0) => 1024,
            _ => limit,
        };
        Ok(Ask {
            sort,
            auth,
            state,
            offset: offset.max(0),
            limit,
            want: Want {
                cid,
                account: None,
                user: q.get("user").to_owned(),
                subs,
            },
            account: q.get("acc").to_owned(),
        })
    }
}

/// `/connz`.
pub(super) async fn answer(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    let mut ask = Ask::of(shared, q)?;
    let now = SystemTime::now();
    if !ask.account.is_empty() {
        let Some(id) = shared.accounts.id(&ask.account) else {
            // An account it does not know: no connections, as Go answers.
            return Ok(pretty(&Connz {
                server_id: "",
                now: rfc3339_nano(now),
                num_connections: 0,
                total: 0,
                offset: ask.offset,
                limit: ask.limit,
                connections: None,
            }));
        };
        ask.want.account = Some(id);
    }
    let (total, mut all) = gather(shared, &ask).await;
    // MQTT clients naq has none of.
    if !q.get("mqtt_client").is_empty() {
        all.clear();
    }
    ask.sort.apply(&mut all, now);
    // Offset and limit are not negative here.
    let n = all.len();
    let start = usize::try_from(ask.offset).unwrap_or(n).min(n);
    let end = start + usize::try_from(ask.limit).unwrap_or(n).min(n - start);
    let page: Vec<ConnInfo<'_>> = all[start..end]
        .iter()
        .map(|c| ConnInfo::of(c, &ask, now))
        .collect();
    Ok(pretty(&Connz {
        server_id: &shared.server_id,
        now: rfc3339_nano(now),
        num_connections: page.len(),
        total,
        offset: ask.offset,
        limit: ask.limit,
        connections: Some(page),
    }))
}

/// The connections `ask` asks for: the open ones of every lane, then the
/// closed ones; for one ID, the open one if there is one. And how many
/// connections are in the state and account it asks for, as
/// `nats-server` counts its total.
async fn gather(shared: &Shared, ask: &Ask) -> (usize, Vec<Arc<Conn>>) {
    let mut all = Vec::new();
    let mut total = 0;
    if ask.state != State::Closed {
        let want = ask.want.clone();
        for (n, conns) in ask_all(shared, move |lane| open(lane, &want)).await {
            total += n;
            all.extend(conns.into_iter().map(Arc::new));
        }
    }
    let one = ask.want.cid > 0;
    if ask.state != State::Open && (!one || all.is_empty()) {
        let w = &ask.want;
        let account = w.account.map(|a| shared.accounts.name(a));
        let closed = shared.monitor.closed.all();
        let mut closed: Vec<_> = closed
            .into_iter()
            .filter(|c| account.is_none_or(|a| c.login.account == a))
            .collect();
        total += closed.len();
        closed.retain(|c| {
            (w.cid == 0 || c.cid == w.cid) && (w.user.is_empty() || c.login.user == w.user)
        });
        all.extend(closed);
        if one {
            all.truncate(1);
        }
    } else if ask.state == State::Any {
        total += shared
            .monitor
            .closed
            .all()
            .iter()
            .filter(|c| {
                ask.want
                    .account
                    .is_none_or(|a| c.login.account == shared.accounts.name(a))
            })
            .count();
    }
    (total, all)
}

#[derive(Debug, Serialize)]
struct Connz<'a> {
    server_id: &'a str,
    now: String,
    num_connections: usize,
    total: usize,
    offset: i64,
    limit: i64,
    connections: Option<Vec<ConnInfo<'a>>>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature serde's skip_serializing_if calls"
)]
const fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// One connection, in `nats-server`'s fields and order.
#[derive(Debug, Serialize)]
struct ConnInfo<'a> {
    cid: u64,
    kind: &'static str,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    of_type: Option<&'static str>,
    ip: &'a str,
    port: u16,
    #[serde(flatten)]
    times: Times,
    #[serde(flatten)]
    counts: Counts,
    #[serde(skip_serializing_if = "str::is_empty")]
    name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    lang: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    version: &'a str,
    #[serde(flatten)]
    tls: Option<Handshake<'a>>,
    #[serde(skip_serializing_if = "str::is_empty")]
    authorized_user: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    account: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subscriptions_list: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subscriptions_list_detail: Vec<SubDetail<'a>>,
    #[serde(flatten)]
    issued: Issued<'a>,
}

/// When a connection came, was last active and closed.
#[derive(Debug, Serialize)]
struct Times {
    start: String,
    last_activity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    rtt: String,
    uptime: String,
    idle: String,
}

/// What passed over a connection.
#[derive(Debug, Serialize)]
struct Counts {
    pending_bytes: usize,
    in_msgs: u64,
    out_msgs: u64,
    in_bytes: u64,
    out_bytes: u64,
    #[serde(skip_serializing_if = "is_zero")]
    stalls: u64,
    subscriptions: usize,
}

/// A connection's TLS.
#[derive(Debug, Serialize)]
struct Handshake<'a> {
    #[serde(rename = "tls_version")]
    version: &'static str,
    #[serde(rename = "tls_cipher_suite")]
    cipher: &'a str,
    #[serde(rename = "tls_peer_certs", skip_serializing_if = "<[_]>::is_empty")]
    peers: &'a [crate::tls::PeerCert],
    #[serde(rename = "tls_first", skip_serializing_if = "std::ops::Not::not")]
    first: bool,
}

/// What issued a connection's user.
#[derive(Debug, Default, Serialize)]
struct Issued<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    jwt: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    issuer_key: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    name_tag: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    tags: &'a [String],
}

/// One subscription of a connection.
#[derive(Debug, Serialize)]
struct SubDetail<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    account: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    account_tag: &'a str,
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    qgroup: Option<&'a str>,
    sid: &'a str,
    msgs: u64,
    #[serde(skip_serializing_if = "is_zero")]
    max: u64,
    cid: u64,
}

impl<'a> ConnInfo<'a> {
    /// `c` as `ask` shows it, at `now`.
    fn of(c: &'a Conn, ask: &Ask, now: SystemTime) -> ConnInfo<'a> {
        let end = c.stop.map_or(now, |(s, _)| s);
        let closed = c.stop.is_some();
        let since = |t: SystemTime| uptime(end.duration_since(t).unwrap_or_default());
        let account = (c.login.account != "$G").then_some(c.login.account.as_str());
        let subs = ask.want.subs;
        ConnInfo {
            cid: c.cid,
            kind: if c.leaf { "Leafnode" } else { "Client" },
            of_type: (!c.leaf).then_some(if c.websocket { "websocket" } else { "nats" }),
            ip: &c.ip,
            port: c.port,
            times: Times {
                start: rfc3339_nano(c.start),
                last_activity: rfc3339_nano(c.last),
                stop: c.stop.map(|(s, _)| rfc3339_nano(s)),
                reason: c.stop.map(|(_, r)| r),
                rtt: rtt(c.rtt),
                uptime: since(c.start),
                idle: since(c.last),
            },
            counts: Counts {
                pending_bytes: c.pending,
                in_msgs: c.totals.in_msgs,
                out_msgs: c.totals.out_msgs,
                in_bytes: c.totals.in_bytes,
                out_bytes: c.totals.out_bytes,
                stalls: c.stalls,
                subscriptions: c.nsubs,
            },
            name: &c.name,
            lang: &c.lang,
            version: &c.version,
            tls: c.tls.as_deref().map(|t| Handshake {
                version: t.version,
                cipher: &t.cipher,
                peers: if ask.auth { &t.peers } else { &[] },
                first: t.first,
            }),
            authorized_user: if ask.auth { &c.login.user } else { "" },
            account: account.filter(|_| ask.auth).unwrap_or_default(),
            subscriptions_list: if subs == Subs::List {
                c.subs.iter().map(|s| s.subject.as_str()).collect()
            } else {
                Vec::new()
            },
            subscriptions_list_detail: if subs == Subs::Detail {
                c.subs.iter().map(|s| SubDetail::of(s, c, closed)).collect()
            } else {
                Vec::new()
            },
            issued: Issued::of(c, ask.auth),
        }
    }
}

/// The name an account goes by: in its JWT, if it has one, else its name.
fn name_tag(c: &Conn) -> &str {
    c.login
        .jwt
        .as_ref()
        .map_or(&c.login.account, |j| &j.account_name)
}

impl<'a> Issued<'a> {
    /// What issued `c`'s user, as `nats-server` shows it: for an open
    /// connection, with `auth` only; for a closed one, as kept, and the
    /// account's name with `auth`.
    fn of(c: &'a Conn, auth: bool) -> Issued<'a> {
        let j = c.login.jwt.as_deref();
        let full = Issued {
            jwt: j.and_then(|j| j.jwt.as_deref()).unwrap_or_default(),
            issuer_key: &c.login.issuer,
            name_tag: "",
            tags: j.map_or(&[][..], |j| &j.tags),
        };
        match (c.stop.is_some(), auth) {
            (false, false) => Issued::default(),
            (false, true) => Issued {
                name_tag: name_tag(c),
                ..full
            },
            (true, _) => {
                let global = c.login.account == "$G";
                let tag = if auth && !global {
                    name_tag(c)
                } else {
                    j.map_or("", |j| j.user_name.as_str())
                };
                Issued {
                    name_tag: tag,
                    ..full
                }
            }
        }
    }
}

impl<'a> SubDetail<'a> {
    /// Subscription `s` of `c`; with its account for a closed one.
    fn of(s: &'a Sub, c: &'a Conn, closed: bool) -> SubDetail<'a> {
        SubDetail {
            account: if closed { &c.login.account } else { "" },
            account_tag: if closed { name_tag(c) } else { "" },
            subject: &s.subject,
            qgroup: s.queue.as_deref(),
            sid: &s.sid,
            msgs: s.msgs,
            max: s.max,
            cid: c.cid,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::monitor::conns::tests::conn;

    #[test]
    fn every_sort_orders_as_nats_server_does_and_ties_go_by_id() {
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let now = t0 + Duration::from_secs(100);
        let mut all: Vec<Arc<Conn>> = (1..=3)
            .map(|cid| {
                let mut c = conn(cid);
                let n = cid as usize;
                c.nsubs = n;
                c.pending = 4 - n;
                c.totals.out_msgs = cid;
                c.totals.in_msgs = 4 - cid;
                c.totals.out_bytes = cid * 10;
                c.totals.in_bytes = 40 - cid * 10;
                c.start = t0 + Duration::from_secs(cid);
                c.last = t0 + Duration::from_secs(10 * cid);
                c.rtt = Duration::from_micros(cid);
                c.stop = Some((t0 + Duration::from_secs(50 - cid), ["b", "c", "a"][n - 1]));
                Arc::new(c)
            })
            .collect();
        for (sort, want) in [
            ("cid", [1, 2, 3]),
            ("subs", [3, 2, 1]),
            ("pending", [1, 2, 3]),
            ("msgs_to", [3, 2, 1]),
            ("msgs_from", [1, 2, 3]),
            ("bytes_to", [3, 2, 1]),
            ("bytes_from", [1, 2, 3]),
            ("last", [3, 2, 1]),
            ("idle", [1, 2, 3]),
            ("uptime", [3, 2, 1]),
            ("rtt", [3, 2, 1]),
            ("stop", [1, 2, 3]),
            ("reason", [3, 1, 2]),
        ] {
            Sort::of(sort).unwrap().apply(&mut all, now);
            let got: Vec<u64> = all.iter().map(|c| c.cid).collect();
            assert_eq!(got, want, "{sort}");
        }
        // Equal keys keep the order of their IDs.
        let mut same: Vec<Arc<Conn>> = [3, 1, 2].map(|cid| Arc::new(conn(cid))).into();
        Sort::Subs.apply(&mut same, now);
        assert_eq!(same.iter().map(|c| c.cid).collect::<Vec<_>>(), [1, 2, 3]);
    }

    #[test]
    fn sort_options_are_those_of_nats_server() {
        for (v, s) in [
            ("", Sort::Cid),
            ("start", Sort::Cid),
            ("bytes_from", Sort::BytesFrom),
            ("idle", Sort::Idle),
            ("pending", Sort::Pending),
            ("rtt", Sort::Rtt),
            ("last", Sort::Last),
        ] {
            assert_eq!(Sort::of(v), Ok(s), "{v}");
        }
        assert_eq!(Sort::of("CID"), Err("invalid sorting option: CID".into()));
        assert_eq!(State::of(&Query::parse("state=ALL")), Ok(State::Any));
        assert!(State::of(&Query::parse("state=x")).is_err());
    }
}
