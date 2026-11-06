//! Requests about an account on `$SYS.REQ.ACCOUNT`, and a user's about
//! itself on `$SYS.REQ.USER`, answered as `nats-server` answers them. The
//! other accounts reach them through the imports each one has.

use std::sync::Arc;
use std::time::SystemTime;

use naq_proto::client::Pub;
use serde::Serialize;

use super::Service;
use super::later::{Answer, Asked, later};
use super::reply::{self, ApiError};
use super::server::{self, CONNZ, FILTERS, JSZ, LEAFZ, SUBSZ, Z};
use super::unmarshal::{Fields, Kind, Set};
use crate::conn::Client;
use crate::imports::info::{self, ClientInfo};
use crate::imports::service::Tap;
use crate::index::Index;
use crate::lane::Lane;
use crate::monitor::{self, Shown, query::Query};
use crate::server::Shared;

/// What an account request asks for: the last token of its subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum X {
    Subsz,
    Connz,
    Leafz,
    Jsz,
    Info,
    Statz,
    Conns,
}

/// The keys of Go's `AccountStatzOptions`.
const STATZ: &[(&str, Kind)] = &[("accounts", Kind::Strs), ("include_unused", Kind::Bool)];

/// The keys of Go's `accNumConnsReq` that matter.
const CONNS: &[(&str, Kind)] = &[("acc", Kind::Str("string"))];

impl X {
    const ALL: [X; 7] = [
        X::Subsz,
        X::Connz,
        X::Leafz,
        X::Jsz,
        X::Info,
        X::Statz,
        X::Conns,
    ];

    /// The last token of its subject.
    const fn name(self) -> &'static str {
        match self {
            X::Subsz => "SUBSZ",
            X::Connz => "CONNZ",
            X::Leafz => "LEAFZ",
            X::Jsz => "JSZ",
            X::Info => "INFO",
            X::Statz => "STATZ",
            X::Conns => "CONNS",
        }
    }

    /// The Go struct its body is read into.
    pub(super) const fn fields(self) -> Fields {
        let (name, keys): (&str, [&[(&str, Kind)]; 2]) = match self {
            X::Subsz => ("SubszEventOptions", [SUBSZ, FILTERS]),
            X::Connz => ("ConnzEventOptions", [CONNZ, FILTERS]),
            X::Leafz => ("LeafzEventOptions", [LEAFZ, FILTERS]),
            X::Jsz => ("JszEventOptions", [JSZ, FILTERS]),
            X::Info => ("AccInfoEventOptions", [&[], FILTERS]),
            X::Statz => ("AccountStatzEventOptions", [STATZ, FILTERS]),
            X::Conns => ("accNumConnsReq", [CONNS, &[]]),
        };
        Fields { name, keys }
    }
}

/// Puts the taps of account and user requests into `index`, the system
/// account's.
pub(super) fn install(index: &mut Index) {
    for x in X::ALL {
        let subject = format!("$SYS.REQ.ACCOUNT.*.{}", x.name());
        index.tap(subject.as_bytes(), Tap::Sys(Service::Account(x)));
    }
    index.tap(
        b"$SYS.REQ.ACCOUNT.PING.STATZ",
        Tap::Sys(Service::AccountPing),
    );
    index.tap(b"$SYS.REQ.USER.*.INFO", Tap::Sys(Service::UserInfo));
}

/// The account a request on `subject` is about: its token 4.
pub(super) fn account_of(subject: &[u8]) -> String {
    let token = subject.split(|&b| b == b'.').nth(3).unwrap_or_default();
    String::from_utf8_lossy(token).into_owned()
}

/// Takes account request `m` for `x`, which came on `lane`, or with `x`
/// `None`, `$SYS.REQ.ACCOUNT.PING.STATZ`. A request without a reply is
/// dropped.
pub(super) fn take(lane: &Lane, x: Option<X>, m: &Pub<'_>) -> bool {
    if x == Some(X::Conns) {
        return super::conns::asked(lane, m);
    }
    if m.reply.is_some_and(|r| !r.is_empty()) {
        later(lane, m, move |shared, asked| answer(shared, x, asked));
    }
    true
}

/// The answer to `asked`, an account request for `x`, or for `None` a
/// `STATZ` of every account, if this server gives one.
async fn answer(shared: Arc<Shared>, x: Option<X>, asked: Asked) -> Option<Answer> {
    let s = &*shared;
    let acc = account_of(&asked.subject);
    let fields = x.map_or(X::Statz.fields(), X::fields);
    let set = match server::options(s, &asked, &fields) {
        Ok(Some(set)) => set,
        Ok(None) => return None,
        Err(a) => return Some(a),
    };
    // The subject names the account, whatever the body says.
    let shown = |z: Z, e: Shown, key: &str, forced: &[(&str, &str)]| {
        let mut pairs = server::pairs(z, &set);
        pairs.retain(|(k, _)| k != key && !forced.iter().any(|(f, _)| f == k));
        pairs.push((key.to_owned(), acc.clone()));
        pairs.extend(forced.iter().map(|&(k, v)| (k.to_owned(), v.to_owned())));
        (e, Query::of_pairs(pairs))
    };
    let data = match x {
        Some(X::Subsz) => {
            let (e, q) = shown(Z::Subsz, Shown::Subsz, "acc", &[("subs", "true")]);
            monitor::shown(s, e, &q).await
        }
        Some(X::Connz) => {
            let (e, q) = shown(Z::Connz, Shown::Connz, "acc", &[]);
            monitor::shown(s, e, &q).await
        }
        Some(X::Leafz) => {
            let (e, q) = shown(Z::Leafz, Shown::Leafz, "acc", &[]);
            monitor::shown(s, e, &q).await
        }
        Some(X::Jsz) => Err("jetstream not enabled".to_owned()),
        Some(X::Info) => monitor::account_info(s, &acc).await,
        // Account `PING` is the ping of every account.
        Some(X::Statz) if acc == "PING" => return None,
        Some(X::Statz) => return statz(s, asked, Some(&[acc]), &set).await,
        Some(X::Conns) | None => {
            let names = set.strs("accounts");
            let names = (!names.is_empty()).then_some(names);
            return statz(s, asked, names, &set).await;
        }
    };
    server::answered(s, asked, data, true)
}

/// The `STATZ` answer to `asked` about the accounts `names`, or every
/// one: none if no account has connections here, unless `set` asks for
/// those unused too.
async fn statz(s: &Shared, asked: Asked, names: Option<&[String]>, set: &Set) -> Option<Answer> {
    let unused = set.bool("include_unused");
    let (n, data) = monitor::statz(s, names, unused).await;
    if n == 0 && !unused {
        return None;
    }
    server::answered(s, asked, Ok(data), false)
}

/// Takes user request `m`, which came on `lane` from client `from`, if a
/// client sent it: the answer tells who it is, as its `Nats-Request-Info`
/// says, with its permissions and when it expires.
pub(super) fn user_info(lane: &Lane, m: &Pub<'_>, from: Option<&Client>) -> bool {
    if m.reply.is_some_and(|r| !r.is_empty()) {
        let (perms, expires) = (from.and_then(permissions), from.map_or(0, expires));
        later(lane, m, move |shared, asked| async move {
            Some(user(&shared, asked, perms, expires))
        });
    }
    true
}

/// The answer to user request `asked`, from a client with `permissions`
/// that expires in `expires` nanoseconds.
fn user(s: &Shared, asked: Asked, permissions: Option<Perms>, expires: u64) -> Answer {
    let header = info::header(&asked.headers, info::HEADER);
    let ci = match header.map(serde_json::from_slice::<ClientInfo>) {
        None => ClientInfo::default(),
        Some(Ok(ci)) => ci,
        Some(Err(_)) => {
            let e = ApiError::new(400, String::new());
            return Answer::new(asked.reply, reply::envelope(s, None, Some(&e)));
        }
    };
    let known = !ci.account.is_empty()
        && s.accounts.id(&ci.account).is_some()
        && monitor::in_use(s, &ci.account);
    let user = UserInfo {
        user: &ci.user,
        account: &ci.account,
        account_name: if known {
            monitor::name_tag(s, &ci.account)
        } else {
            String::new()
        },
        user_name: &ci.name_tag,
        permissions,
        expires,
    };
    let body = reply::envelope(s, Some(&monitor::json::compact(&user)), None);
    Answer::new(asked.reply, body)
}

/// A user, as Go's `UserInfo`.
#[derive(Debug, Serialize)]
struct UserInfo<'a> {
    user: &'a str,
    account: &'a str,
    #[serde(skip_serializing_if = "String::is_empty")]
    account_name: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    user_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<Perms>,
    /// In nanoseconds.
    #[serde(skip_serializing_if = "is_zero")]
    expires: u64,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature serde's skip_serializing_if calls"
)]
const fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Permissions, as Go's `Permissions` shows them.
#[derive(Debug, Serialize)]
struct Perms {
    publish: Rule,
    subscribe: Rule,
    #[serde(skip_serializing_if = "Option::is_none")]
    responses: Option<Replies>,
}

/// One side of them, as Go's `SubjectPermission`.
#[derive(Debug, Serialize)]
struct Rule {
    #[serde(skip_serializing_if = "Option::is_none")]
    allow: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny: Vec<String>,
}

/// The replies allowed, as Go's `ResponsePermission`.
#[derive(Debug, Serialize)]
struct Replies {
    max: u32,
    /// In nanoseconds.
    ttl: u64,
}

impl Perms {
    fn of(p: &crate::Permissions) -> Perms {
        let rule = |r: &crate::Rules| Rule {
            allow: r.allow.clone().filter(|a| !a.is_empty()),
            deny: r.deny.clone(),
        };
        Perms {
            publish: rule(&p.publish),
            subscribe: rule(&p.subscribe),
            responses: p.responses.map(|r| Replies {
                max: r.max,
                ttl: u64::try_from(r.expires.as_nanos()).unwrap_or(u64::MAX),
            }),
        }
    }
}

/// The permissions of client `c`, if any limit it.
fn permissions(c: &Client) -> Option<Perms> {
    c.held.borrow().as_ref().map(|h| Perms::of(h.perms.rules()))
}

/// How long until client `c` expires, in nanoseconds, cut to whole
/// seconds as Go cuts it; 0 if it does not.
fn expires(c: &Client) -> u64 {
    let Some(t) = c.meta.borrow().expires else {
        return 0;
    };
    let left = t.duration_since(SystemTime::now()).unwrap_or_default();
    left.as_secs().saturating_mul(1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_account_of_a_request_is_its_fourth_token() {
        assert_eq!(account_of(b"$SYS.REQ.ACCOUNT.A.CONNZ"), "A");
        assert_eq!(X::Statz.fields().name, "AccountStatzEventOptions");
        assert!(X::ALL.iter().all(|x| !x.name().is_empty()));
    }
}
