//! Requests to the server on `$SYS.REQ.SERVER`: to every server on
//! `PING`, or to this one by its ID, answered as `nats-server` answers
//! them, with what its monitoring endpoints show.

use std::sync::Arc;

use naq_proto::client::Pub;
use serde::Serialize;

use super::Service;
use super::later::{Answer, Asked, later, send_now};
use super::reply::{self, ApiError, ServerInfo};
use super::send::{Event, Note};
use super::unmarshal::{self, Fields, Kind, Set};
use crate::imports::service::Tap;
use crate::index::Index;
use crate::lane::{Lane, Outs};
use crate::monitor::query::Query;
use crate::monitor::{self, Shown, json};
use crate::server::Shared;

/// What a server request asks for: the last token of its subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Z {
    Idz,
    Statsz,
    Varz,
    Subsz,
    Connz,
    Routez,
    Gatewayz,
    Leafz,
    Accountz,
    Jsz,
    Healthz,
    Profilez,
    Expvarz,
    Ipqueuesz,
    Raftz,
}

const STR: Kind = Kind::Str("string");
const BOOL: Kind = Kind::Bool;
const INT: Kind = Kind::Int("int");

/// The keys of Go's `EventFilterOptions`: which servers answer.
pub(super) const FILTERS: &[(&str, Kind)] = &[
    ("server_name", STR),
    ("cluster", STR),
    ("host", STR),
    ("exact_match", BOOL),
    ("tags", Kind::Strs),
    ("domain", STR),
];

/// The keys of Go's `ConnzOptions`.
pub(super) const CONNZ: &[(&str, Kind)] = &[
    ("sort", Kind::Str("server.SortOpt")),
    ("auth", BOOL),
    ("subscriptions", BOOL),
    ("subscriptions_detail", BOOL),
    ("offset", INT),
    ("limit", INT),
    ("cid", Kind::Uint),
    ("mqtt_client", STR),
    ("state", Kind::Int("server.ConnState")),
    ("user", STR),
    ("acc", STR),
    ("filter_subject", STR),
];

/// The keys of Go's `SubszOptions`.
pub(super) const SUBSZ: &[(&str, Kind)] = &[
    ("offset", INT),
    ("limit", INT),
    ("subscriptions", BOOL),
    ("account", STR),
    ("test", STR),
];

const ROUTEZ: &[(&str, Kind)] = &[("subscriptions", BOOL), ("subscriptions_detail", BOOL)];

const GATEWAYZ: &[(&str, Kind)] = &[
    ("name", STR),
    ("accounts", BOOL),
    ("account_name", STR),
    ("subscriptions", BOOL),
    ("subscriptions_detail", BOOL),
];

/// The keys of Go's `LeafzOptions`.
pub(super) const LEAFZ: &[(&str, Kind)] = &[("subscriptions", BOOL), ("account", STR)];

const ACCOUNTZ: &[(&str, Kind)] = &[("account", STR)];

/// The keys of Go's `JSzOptions`.
pub(super) const JSZ: &[(&str, Kind)] = &[
    ("account", STR),
    ("accounts", BOOL),
    ("streams", BOOL),
    ("consumer", BOOL),
    ("direct_consumer", BOOL),
    ("config", BOOL),
    ("leader_only", BOOL),
    ("offset", INT),
    ("limit", INT),
    ("raft", BOOL),
    ("stream_leader_only", BOOL),
];

const HEALTHZ: &[(&str, Kind)] = &[
    ("js-enabled", BOOL),
    ("js-enabled-only", BOOL),
    ("js-server-only", BOOL),
    ("js-meta-only", BOOL),
    ("account", STR),
    ("stream", STR),
    ("consumer", STR),
    ("details", BOOL),
];

const PROFILEZ: &[(&str, Kind)] = &[
    ("name", STR),
    ("debug", INT),
    ("duration", Kind::Int("time.Duration")),
];

const IPQUEUESZ: &[(&str, Kind)] = &[("all", BOOL), ("filter", STR)];

const RAFTZ: &[(&str, Kind)] = &[("account", STR), ("group", STR)];

impl Z {
    pub(crate) const ALL: [Z; 15] = [
        Z::Idz,
        Z::Statsz,
        Z::Varz,
        Z::Subsz,
        Z::Connz,
        Z::Routez,
        Z::Gatewayz,
        Z::Leafz,
        Z::Accountz,
        Z::Jsz,
        Z::Healthz,
        Z::Profilez,
        Z::Expvarz,
        Z::Ipqueuesz,
        Z::Raftz,
    ];

    /// The last token of its subject.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Z::Idz => "IDZ",
            Z::Statsz => "STATSZ",
            Z::Varz => "VARZ",
            Z::Subsz => "SUBSZ",
            Z::Connz => "CONNZ",
            Z::Routez => "ROUTEZ",
            Z::Gatewayz => "GATEWAYZ",
            Z::Leafz => "LEAFZ",
            Z::Accountz => "ACCOUNTZ",
            Z::Jsz => "JSZ",
            Z::Healthz => "HEALTHZ",
            Z::Profilez => "PROFILEZ",
            Z::Expvarz => "EXPVARZ",
            Z::Ipqueuesz => "IPQUEUESZ",
            Z::Raftz => "RAFTZ",
        }
    }

    /// The Go struct its body is read into.
    pub(super) const fn fields(self) -> Fields {
        let (name, own): (&str, &[(&str, Kind)]) = match self {
            Z::Idz | Z::Statsz => ("StatszEventOptions", &[]),
            Z::Varz => ("VarzEventOptions", &[]),
            Z::Subsz => ("SubszEventOptions", SUBSZ),
            Z::Connz => ("ConnzEventOptions", CONNZ),
            Z::Routez => ("RoutezEventOptions", ROUTEZ),
            Z::Gatewayz => ("GatewayzEventOptions", GATEWAYZ),
            Z::Leafz => ("LeafzEventOptions", LEAFZ),
            Z::Accountz => ("AccountzEventOptions", ACCOUNTZ),
            Z::Jsz => ("JszEventOptions", JSZ),
            Z::Healthz => ("HealthzEventOptions", HEALTHZ),
            Z::Profilez => ("ProfilezEventOptions", PROFILEZ),
            Z::Expvarz => ("ExpvarzEventOptions", &[]),
            Z::Ipqueuesz => ("IpqueueszEventOptions", IPQUEUESZ),
            Z::Raftz => ("RaftzEventOptions", RAFTZ),
        };
        Fields {
            name,
            keys: [own, FILTERS],
        }
    }
}

/// The monitoring query of `z` that the options `set` make.
fn query(z: Z, set: &Set) -> Query {
    Query::of_pairs(pairs(z, set))
}

/// The monitoring query of `z` that the options `set` make, as the keys
/// and values of its HTTP endpoint.
pub(super) fn pairs(z: Z, set: &Set) -> Vec<(String, String)> {
    let subs = if set.bool("subscriptions_detail") {
        "detail"
    } else if set.bool("subscriptions") {
        "1"
    } else {
        ""
    };
    let b = |k: &str| set.bool(k).to_string();
    let n = |k: &str| set.int(k).to_string();
    let s = |k: &str| set.str(k).to_owned();
    let pairs: Vec<(&str, String)> = match z {
        Z::Connz => vec![
            ("sort", s("sort")),
            ("auth", b("auth")),
            ("subs", subs.into()),
            ("offset", n("offset")),
            ("limit", n("limit")),
            ("cid", set.uint("cid").to_string()),
            ("mqtt_client", s("mqtt_client")),
            ("state", state(set.int("state")).into()),
            ("user", s("user")),
            ("acc", s("acc")),
        ],
        Z::Subsz => vec![
            ("subs", b("subscriptions")),
            ("offset", n("offset")),
            ("limit", n("limit")),
            ("acc", s("account")),
            ("test", s("test")),
        ],
        Z::Routez => vec![("subs", subs.into())],
        Z::Gatewayz => vec![("subs", subs.into()), ("accs", b("accounts"))],
        Z::Leafz => vec![("subs", b("subscriptions")), ("acc", s("account"))],
        Z::Accountz => vec![("acc", s("account"))],
        Z::Jsz => vec![
            ("acc", s("account")),
            ("accounts", b("accounts")),
            ("streams", b("streams")),
            ("consumers", b("consumer")),
            ("direct-consumers", b("direct_consumer")),
            ("config", b("config")),
            ("leader-only", b("leader_only")),
            ("offset", n("offset")),
            ("limit", n("limit")),
            ("raft", b("raft")),
            ("stream-leader-only", b("stream_leader_only")),
        ],
        Z::Healthz => HEALTHZ
            .iter()
            .map(|&(k, kind)| (k, if kind == BOOL { b(k) } else { s(k) }))
            .collect(),
        _ => Vec::new(),
    };
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

/// Go's `ConnState` `n` as `/connz` names it: other numbers ask for open
/// connections.
const fn state(n: i64) -> &'static str {
    match n {
        1 => "closed",
        2 => "all",
        _ => "open",
    }
}

/// Whether this server answers a request filtered by `set`, as
/// `nats-server`'s `filterRequest` decides.
pub(super) fn wanted(shared: &Shared, set: &Set) -> bool {
    let o = &shared.opts;
    let me = Me {
        name: reply::name(shared),
        host: &o.host,
        cluster: o.cluster.as_ref().map_or("", |c| c.name.as_str()),
        tags: &o.server_tags,
    };
    me.fits(set)
}

/// What filters pick a server by.
struct Me<'a> {
    name: &'a str,
    host: &'a str,
    cluster: &'a str,
    tags: &'a [String],
}

impl Me<'_> {
    /// Whether the filters `set` pick it.
    fn fits(&self, set: &Set) -> bool {
        let exact = set.bool("exact_match");
        let fits = |want: &str, have: &str| {
            want.is_empty()
                || if exact {
                    want == have
                } else {
                    have.contains(want)
                }
        };
        let tags = set.strs("tags").iter().all(|t| {
            let t = t.trim().to_lowercase();
            self.tags.contains(&t)
        });
        // A JetStream domain asks for none: naq has none.
        let domain = set.str("domain").is_empty();
        fits(set.str("server_name"), self.name)
            && fits(set.str("host"), self.host)
            && fits(set.str("cluster"), self.cluster)
            && tags
            && domain
    }
}

impl Z {
    /// The monitoring endpoint it shows, if one does.
    const fn shown(self) -> Option<Shown> {
        Some(match self {
            Z::Varz => Shown::Varz,
            Z::Subsz => Shown::Subsz,
            Z::Connz => Shown::Connz,
            Z::Routez => Shown::Routez,
            Z::Gatewayz => Shown::Gatewayz,
            Z::Leafz => Shown::Leafz,
            Z::Accountz => Shown::Accountz,
            Z::Jsz => Shown::Jsz,
            _ => return None,
        })
    }
}

/// Puts the taps of server requests into `index`, the system account's
/// of a server of ID `id`.
pub(super) fn install(index: &mut Index, id: &str) {
    index.tap(b"$SYS.REQ.SERVER.PING", Tap::Sys(Service::Ping));
    for z in Z::ALL {
        for to in ["PING", id] {
            let subject = format!("$SYS.REQ.SERVER.{to}.{}", z.name());
            index.tap(subject.as_bytes(), Tap::Sys(Service::Server(z)));
        }
    }
}

/// Takes request `m` for `z`, which came on `lane`, with `out` for what
/// goes on. A request without a reply is dropped, but for `STATSZ`.
pub(super) fn take(lane: &Lane, out: &mut Outs, z: Z, m: &Pub<'_>) -> bool {
    let reply = m.reply.filter(|r| !r.is_empty());
    match (z, reply) {
        (Z::Idz, Some(to)) => {
            let shared = &*lane.shared;
            let id = Idz {
                name: reply::name(shared),
                host: &shared.opts.host,
                id: &shared.server_id,
            };
            if let Some(sys) = shared.system {
                send_now(
                    lane,
                    out,
                    sys,
                    &Answer::new(to.to_vec(), json::compact(&id)),
                );
            }
        }
        (Z::Statsz, Some(_)) => later(lane, m, statsz),
        (Z::Statsz, None) => broadcast_asked(&lane.shared, m.payload),
        (_, Some(_)) => later(lane, m, move |shared, asked| answer(shared, z, asked)),
        (_, None) => {}
    }
    true
}

/// What `IDZ` tells.
#[derive(Debug, Serialize)]
struct Idz<'a> {
    name: &'a str,
    host: &'a str,
    id: &'a str,
}

/// The options of request `asked` in `fields`: `Ok(None)` if they pass
/// this server by, `Err` with Go's 400 answer if they cannot be read.
pub(super) fn options(
    shared: &Shared,
    asked: &Asked,
    fields: &Fields,
) -> Result<Option<Set>, Answer> {
    if asked.body.is_empty() {
        return Ok(Some(Set::default()));
    }
    match unmarshal::decode(&asked.body, fields) {
        Ok(set) => Ok(wanted(shared, &set).then_some(set)),
        Err(why) => Err(Answer::new(
            asked.reply.clone(),
            reply::envelope(shared, None, Some(&ApiError::new(400, why))),
        )),
    }
}

/// The answer to `STATSZ` request `asked`.
async fn statsz(shared: Arc<Shared>, asked: Asked) -> Option<Answer> {
    let s = &*shared;
    match options(s, &asked, &Z::Statsz.fields()) {
        Ok(Some(_)) => {}
        Ok(None) => return None,
        Err(a) => return Some(a),
    }
    Some(Answer::new(asked.reply, broadcast(s).await))
}

/// Takes a `STATSZ` request without a reply, with `body`: the server
/// broadcasts `STATSZ` at once, past the rate limit, unless the filters
/// pass it by; the error of a body it cannot read goes out on the
/// broadcast subject.
fn broadcast_asked(s: &Shared, body: &[u8]) {
    let Some(sys) = s.system else {
        return;
    };
    let event = if body.is_empty() {
        Event::Statsz { forced: true }
    } else {
        match unmarshal::decode(body, &Z::Statsz.fields()) {
            Ok(set) if wanted(s, &set) => Event::Statsz { forced: true },
            Ok(_) => return,
            Err(why) => {
                let to = format!("$SYS.SERVER.{}.STATSZ", s.server_id).into_bytes();
                Event::Note(Note::error(sys, to, &ApiError::new(400, why)))
            }
        }
    };
    s.sys.outbox.post(event);
}

/// The `STATSZ` message of `s`, as it is now: the counts taken first,
/// then the server block, numbered.
pub(super) async fn broadcast(s: &Shared) -> Vec<u8> {
    let statsz = monitor::statsz(s).await;
    json::compact(&Statsz {
        server: ServerInfo::of(s),
        statsz,
    })
}

/// A `STATSZ` message, as Go's `ServerStatsMsg`.
#[derive(Debug, Serialize)]
struct Statsz<'a> {
    server: ServerInfo<'a>,
    statsz: monitor::ServerStats,
}

/// The answer to request `asked` for `z`, as `nats-server`'s `zReq`
/// gives it: none if it passes this server by.
async fn answer(shared: Arc<Shared>, z: Z, asked: Asked) -> Option<Answer> {
    let s = &*shared;
    let set = match options(s, &asked, &z.fields()) {
        Ok(Some(set)) => set,
        Ok(None) => return None,
        Err(a) => return Some(a),
    };
    let q = query(z, &set);
    let data = match z.shown() {
        Some(e) => monitor::shown(s, e, &q).await,
        None => Ok(own(s, z, &set, &q)),
    };
    answered(s, asked, data, true)
}

/// The answer to `asked` with `data`, as `zReq` gives it: compressed as
/// asked; none if it is Go's `errSkipZreq`; else a 500, with `data`
/// `null` if `null`.
pub(super) fn answered(
    s: &Shared,
    asked: Asked,
    data: Result<Vec<u8>, String>,
    null: bool,
) -> Option<Answer> {
    match data {
        Ok(d) => {
            let body = reply::envelope(s, Some(&d), None);
            Some(Answer::encoded(asked.reply, &asked.headers, body))
        }
        Err(why) if why.starts_with("filtered response") => None,
        Err(why) => {
            let e = ApiError::new(500, why);
            let data = null.then_some(&b"null"[..]);
            Some(Answer::new(asked.reply, reply::envelope(s, data, Some(&e))))
        }
    }
}

/// The data of `z`, with options `set` and query `q`, where no
/// monitoring endpoint shows it.
fn own(s: &Shared, z: Z, set: &Set, q: &Query) -> Vec<u8> {
    match z {
        Z::Healthz => monitor::health(s, q).map_or_else(String::into_bytes, |h| json::compact(&h)),
        Z::Profilez => json::compact(&Profilez::of(set.str("name"))),
        Z::Expvarz => json::compact(&Expvarz {
            memstats: None,
            cmdline: std::env::args().collect(),
        }),
        _ => b"{}".to_vec(),
    }
}

/// `PROFILEZ`, as Go's `ProfilezStatus`.
#[derive(Debug, Serialize)]
struct Profilez {
    profile: Option<String>,
    error: String,
}

impl Profilez {
    /// The answer for profile `name`: naq has none of Go's profiles.
    fn of(name: &str) -> Profilez {
        let error = if name.is_empty() {
            "Profile name not specified".to_owned()
        } else {
            format!("Profile {} not found", crate::monitor::query::quote(name))
        };
        Profilez {
            profile: None,
            error,
        }
    }
}

/// `EXPVARZ`, as Go's `ExpvarzStatus`: naq has no Go memory statistics.
#[derive(Debug, Serialize)]
struct Expvarz {
    memstats: Option<()>,
    cmdline: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(z: Z, body: &str) -> Set {
        unmarshal::decode(body.as_bytes(), &z.fields()).unwrap()
    }

    #[test]
    fn options_become_the_query_of_the_endpoint() {
        let q = query(
            Z::Connz,
            &set(
                Z::Connz,
                r#"{"subscriptions":true,"subscriptions_detail":true,"state":1,"cid":3,"acc":"A"}"#,
            ),
        );
        assert_eq!(
            (q.get("subs"), q.get("state"), q.get("cid"), q.get("acc")),
            ("detail", "closed", "3", "A")
        );
        let q = query(
            Z::Connz,
            &set(Z::Connz, r#"{"subscriptions":true,"state":9}"#),
        );
        assert_eq!((q.get("subs"), q.get("state")), ("1", "open"));
        assert_eq!(
            query(Z::Connz, &set(Z::Connz, r#"{"state":2}"#)).get("state"),
            "all"
        );
        let q = query(
            Z::Subsz,
            &set(
                Z::Subsz,
                r#"{"subscriptions":true,"account":"A","test":"x"}"#,
            ),
        );
        assert_eq!(
            (q.get("subs"), q.get("acc"), q.get("test")),
            ("true", "A", "x")
        );
        let q = query(
            Z::Jsz,
            &set(Z::Jsz, r#"{"consumer":true,"leader_only":true}"#),
        );
        assert_eq!((q.get("consumers"), q.get("leader-only")), ("true", "true"));
        let q = query(
            Z::Healthz,
            &set(Z::Healthz, r#"{"js-enabled-only":true,"stream":"s"}"#),
        );
        assert_eq!((q.get("js-enabled-only"), q.get("stream")), ("true", "s"));
        let q = query(
            Z::Leafz,
            &set(Z::Leafz, r#"{"subscriptions":true,"account":"A"}"#),
        );
        assert_eq!((q.get("subs"), q.get("acc")), ("true", "A"));
        assert_eq!(
            query(Z::Accountz, &set(Z::Accountz, r#"{"account":"A"}"#)).get("acc"),
            "A"
        );
        assert_eq!(
            query(Z::Gatewayz, &set(Z::Gatewayz, r#"{"accounts":true}"#)).get("accs"),
            "true"
        );
        assert_eq!(
            query(Z::Routez, &set(Z::Routez, r#"{"subscriptions":true}"#)).get("subs"),
            "1"
        );
        assert_eq!(query(Z::Varz, &Set::default()).get("subs"), "");
    }

    #[test]
    fn filters_pick_servers_as_nats_server_does() {
        let tags = ["az:1".to_owned(), "probe".to_owned()];
        let me = Me {
            name: "s1",
            host: "127.0.0.1",
            cluster: "c1",
            tags: &tags,
        };
        let fits = |body: &str| me.fits(&set(Z::Varz, body));
        assert!(fits("{}"));
        assert!(fits(r#"{"server_name":"s","host":"0.0","cluster":"c"}"#));
        assert!(!fits(r#"{"server_name":"s","exact_match":true}"#));
        assert!(fits(
            r#"{"server_name":"s1","cluster":"c1","exact_match":true}"#
        ));
        assert!(!fits(r#"{"host":"x"}"#));
        assert!(fits(r#"{"tags":[" AZ:1","probe"]}"#));
        assert!(!fits(r#"{"tags":["az:2"]}"#));
        assert!(!fits(r#"{"domain":"d"}"#));
    }

    #[test]
    fn profiles_are_none_of_go_s() {
        assert_eq!(Profilez::of("").error, "Profile name not specified");
        assert_eq!(Profilez::of("heap").error, "Profile \"heap\" not found");
        assert_eq!(Z::Idz.shown(), None);
        assert_eq!(Z::Connz.shown(), Some(Shown::Connz));
    }
}
