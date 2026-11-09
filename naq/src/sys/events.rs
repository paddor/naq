//! Events of connections on `$SYS`, as `nats-server` sends them: a client
//! or a link to a hub came or went, or a client failed to log in.

use std::time::SystemTime;

use serde::Serialize;

use super::send::{Event, Note};
use crate::conn::{Client, Close};
use crate::lane::Lane;
use crate::monitor::json;
use crate::server::Shared;
use crate::times::rfc3339_nano;

/// The type of a `CONNECT` event.
const CONNECT: &str = "io.nats.server.advisory.v1.client_connect";

/// The type of a `DISCONNECT` event, and of an authentication error.
const DISCONNECT: &str = "io.nats.server.advisory.v1.client_disconnect";

/// What an event is of: a client, or a link to a hub.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Of<'a> {
    Client(&'a Client),
    Link(&'a crate::leaf::LinkSide),
}

impl<'a> Of<'a> {
    /// The client it is, or the link's.
    fn client(self) -> &'a Client {
        match self {
            Of::Client(c) => c,
            Of::Link(l) => &l.client,
        }
    }
}

/// Tells of `of`, which logged in on `lane`: `CONNECT` in its account.
pub(crate) fn connected(lane: &Lane, of: Of<'_>) {
    let s = &lane.shared;
    let Some(sys) = s.system else {
        return;
    };
    let c = of.client();
    let account = s.accounts.name(c.account.get());
    let mut tail = b",\"client\":".to_vec();
    tail.extend(json::compact(&Who::of(s, of, None)));
    tail.push(b'}');
    s.sys.outbox.post(Event::Note(Note {
        account: sys,
        to: format!("$SYS.ACCOUNT.{account}.CONNECT").into_bytes(),
        head: head(CONNECT, SystemTime::now()),
        tail,
    }));
}

/// Tells of `of`, closed on `lane` for `close`: first the authentication
/// errors of a login refused, to the account the client was in if it
/// tried to log in, `refused`, then `DISCONNECT` in its account.
pub(crate) fn closed(lane: &Lane, of: Of<'_>, close: Close, refused: Option<u32>) {
    let s = &lane.shared;
    let Some(sys) = s.system else {
        return;
    };
    let now = SystemTime::now();
    let c = of.client();
    let account = c.account.get();
    let gone = |acc: Option<&str>| {
        let mut who = Who::of(s, of, Some(now));
        if let Some(a) = acc {
            who.acc = a;
        }
        let t = c.tally.totals();
        let tail = json::compact(&Gone {
            client: who,
            sent: MsgBytes {
                msgs: t.in_msgs,
                bytes: t.in_bytes,
            },
            received: MsgBytes {
                msgs: t.out_msgs,
                bytes: t.out_bytes,
            },
            reason: close.reason(),
        });
        // Its fields go on after those of the head.
        [&b","[..], &tail[1..]].concat()
    };
    if close == Close::Auth {
        if let Some(a) = refused {
            let name = s.accounts.name(a);
            s.sys.outbox.post(Event::Note(Note {
                account: a,
                to: b"$SYS.ACCOUNT.CLIENT.AUTH.ERR".to_vec(),
                head: head(DISCONNECT, now),
                tail: gone(Some(name)),
            }));
        }
        s.sys.outbox.post(Event::Note(Note {
            account: sys,
            to: format!("$SYS.SERVER.{}.CLIENT.AUTH.ERR", s.server_id).into_bytes(),
            head: head(DISCONNECT, now),
            tail: gone(None),
        }));
    }
    let name = s.accounts.name(account);
    s.sys.outbox.post(Event::Note(Note {
        account: sys,
        to: format!("$SYS.ACCOUNT.{name}.DISCONNECT").into_bytes(),
        head: head(DISCONNECT, now),
        tail: gone(None),
    }));
}

/// The head of an event of type `kind` at `now`, as Go's `TypedEvent`,
/// up to the block of the server that sends it.
pub(super) fn head(kind: &'static str, now: SystemTime) -> Vec<u8> {
    let mut h = json::compact(&Typed {
        kind,
        id: super::event_id(),
        timestamp: rfc3339_nano(now),
    });
    h.pop();
    h.extend_from_slice(b",\"server\":");
    h
}

/// Go's `TypedEvent`.
#[derive(Debug, Serialize)]
struct Typed {
    #[serde(rename = "type")]
    kind: &'static str,
    id: String,
    timestamp: String,
}

/// What a `DISCONNECT` event tells past the server.
#[derive(Debug, Serialize)]
struct Gone<'a> {
    client: Who<'a>,
    sent: MsgBytes,
    received: MsgBytes,
    reason: &'static str,
}

/// Messages and their bytes.
#[derive(Debug, Serialize)]
struct MsgBytes {
    msgs: u64,
    bytes: u64,
}

/// A connection, as Go's `ClientInfo` tells of it in events: every field
/// left out when empty.
#[derive(Debug, Serialize)]
struct Who<'a> {
    start: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    host: String,
    #[serde(skip_serializing_if = "is_zero")]
    id: u64,
    #[serde(skip_serializing_if = "str::is_empty")]
    acc: &'a str,
    #[serde(skip_serializing_if = "String::is_empty")]
    user: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    lang: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ver: String,
    /// In nanoseconds.
    #[serde(skip_serializing_if = "is_zero")]
    rtt: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwt: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    issuer_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name_tag: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    kind: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    client_type: &'static str,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature serde's skip_serializing_if calls"
)]
const fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl<'a> Who<'a> {
    /// `of` on server `s`, stopped at `stop` if it did.
    fn of(s: &'a Shared, of: Of<'_>, stop: Option<SystemTime>) -> Who<'a> {
        let c = of.client();
        let acc = s.accounts.name(c.account.get());
        let rtt = crate::times::go_rtt(c.rtt.get());
        let rtt = u64::try_from(rtt.as_nanos()).unwrap_or(u64::MAX);
        let meta = c.meta.borrow();
        let mut who = Who {
            start: rfc3339_nano(meta.start),
            host: meta.ip.clone(),
            id: c.id,
            acc,
            user: meta.raw_user().to_owned(),
            name: meta.name.clone().unwrap_or_default(),
            lang: meta.lang.clone().unwrap_or_default(),
            ver: meta.version.clone().unwrap_or_default(),
            rtt: if stop.is_some() { rtt } else { 0 },
            stop: stop.map(rfc3339_nano),
            jwt: None,
            issuer_key: String::new(),
            name_tag: crate::monitor::name_tag(s, acc),
            tags: Vec::new(),
            kind: "Client",
            client_type: if meta.websocket { "websocket" } else { "nats" },
        };
        if let Some(j) = &meta.jwt {
            who.jwt.clone_from(&j.jwt);
            who.issuer_key.clone_from(&j.issuer);
            who.tags.clone_from(&j.tags);
        }
        if let Of::Link(l) = of {
            who.host.clone_from(&l.facts.ip);
            who.name.clone_from(&l.facts.name);
            who.kind = "Leafnode";
            who.client_type = "";
        }
        who
    }
}
