//! `/accountz`: the accounts of the server, and one of them in detail, as
//! `nats-server` shows them.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustc_hash::FxHashMap;
use serde::Serialize;

use super::accstatz::{self, Which};
use super::http::Response;
use super::json::Ordered;
use super::query::{Query, Refused};
use super::subsz::Stats;
use super::{Counted, now, pretty, text};
use crate::accounts::Account;
use crate::imports::defs::{self, Def};
use crate::jwt::trust::JwtAccount;
use crate::server::Shared;
use crate::times::rfc3339_nano;
use crate::{Export, ExportKind, ResponseType, Sampling};

/// The account of a JWT of `name`, if the server trusts one.
fn jwt_of(shared: &Shared, name: &str) -> Option<Arc<JwtAccount>> {
    shared.auth.as_ref()?.trust()?.claims_of(name)
}

/// Whether account `name` is in use as `nats-server` has accounts: one of
/// a JWT once a client looked it up.
pub(crate) fn in_use(shared: &Shared, name: &str) -> bool {
    jwt_of(shared, name).is_none_or(|j| j.is_loaded())
}

/// The name account `name` goes by: in its JWT, if it has a name there.
pub(crate) fn name_tag(shared: &Shared, name: &str) -> String {
    jwt_of(shared, name)
        .map(|a| a.claims.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| name.to_owned())
}

/// Latency samples of a service, as `nats-server` shows them.
#[derive(Debug, Serialize)]
struct Latency<'a> {
    sampling: Rate,
    results: &'a str,
}

/// Which requests are sampled: a percent, or `headers`.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Rate {
    Percent(u8),
    Headers(&'static str),
}

impl<'a> Latency<'a> {
    fn of(l: &'a crate::Latency) -> Latency<'a> {
        Latency {
            sampling: match l.sampling {
                Sampling::Percent(p) => Rate::Percent(p),
                Sampling::Headers => Rate::Headers("headers"),
            },
            results: &l.subject,
        }
    }
}

/// An export, as `nats-server` shows it.
#[derive(Debug, Serialize)]
struct ExportInfo<'a> {
    subject: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    token_req: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_latency: Option<Latency<'a>>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    approved_accounts: &'a [String],
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    revoked_activations: BTreeMap<&'a str, String>,
}

/// Revocations `r`, by key, as `nats-server` shows them: at the time of
/// each.
fn revoked(r: &FxHashMap<String, i64>) -> BTreeMap<&str, String> {
    let at = |secs: &i64| {
        let secs = u64::try_from(*secs).unwrap_or(0);
        rfc3339_nano(UNIX_EPOCH + Duration::from_secs(secs))
    };
    r.iter().map(|(k, t)| (k.as_str(), at(t))).collect()
}

/// The exports of `d`: services, then streams.
fn exports(d: &Def) -> Vec<ExportInfo<'_>> {
    let all = || d.exports.iter().zip(&d.tokens);
    let services = all().filter(|(e, _)| matches!(e.kind, ExportKind::Service(_)));
    let streams = all().filter(|(e, _)| matches!(e.kind, ExportKind::Stream));
    services
        .chain(streams)
        .map(|(e, token)| export(e, token.as_ref()))
        .collect()
}

/// Export `e`, which takes a token if `token` holds its revocations.
fn export<'a>(e: &'a Export, token: Option<&'a FxHashMap<String, i64>>) -> ExportInfo<'a> {
    let (kind, response_type, latency) = match &e.kind {
        ExportKind::Stream => ("stream", None, None),
        ExportKind::Service(s) => {
            let response = match s.response {
                ResponseType::Singleton => "Singleton",
                ResponseType::Stream => "Streamed",
                ResponseType::Chunked => "Chunked",
            };
            (
                "service",
                Some(response),
                s.latency.as_ref().map(Latency::of),
            )
        }
    };
    ExportInfo {
        subject: &e.subject,
        kind,
        token_req: token.is_some(),
        response_type,
        service_latency: latency,
        approved_accounts: e.accounts.as_deref().unwrap_or_default(),
        revoked_activations: token.map(revoked).unwrap_or_default(),
    }
}

/// An import, as `nats-server` shows it.
#[derive(Debug, Serialize)]
struct ImportInfo<'a> {
    /// The subjects in the exporter.
    subject: String,
    account: &'a str,
    /// The subjects in the importer, of a service.
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    local_subject: String,
    #[serde(rename = "type")]
    kind: &'static str,
    invalid: bool,
    share: bool,
    tracking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency: Option<Latency<'a>>,
}

/// The imports of `a`, of `shared`'s accounts: streams, then services.
fn imports<'a>(shared: &'a Shared, a: &'a Account) -> Vec<ImportInfo<'a>> {
    let i = a.imports();
    let streams = i.streams.iter().map(|s| ImportInfo {
        subject: text(&s.subject),
        account: shared.accounts.name(s.from),
        to: None,
        local_subject: text(&s.to),
        kind: "stream",
        invalid: false,
        share: false,
        tracking: false,
        latency: None,
    });
    let services = i.services.iter().map(|s| ImportInfo {
        subject: text(&s.subject),
        account: shared.accounts.name(s.to),
        to: Some(text(&s.from)),
        local_subject: text(&s.from),
        kind: "service",
        invalid: false,
        share: s.share,
        tracking: false,
        latency: s.service.latency.as_ref().map(Latency::of),
    });
    streams.chain(services).collect()
}

/// One account in detail.
#[derive(Debug, Serialize)]
#[expect(clippy::struct_excessive_bools, reason = "the flags nats-server shows")]
struct AccountInfo<'a> {
    account_name: &'a str,
    update_time: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_system: bool,
    expired: bool,
    complete: bool,
    jetstream_enabled: bool,
    leafnode_connections: usize,
    client_connections: usize,
    subscriptions: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exports: Vec<ExportInfo<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    imports: Vec<ImportInfo<'a>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    jwt: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    issuer_key: String,
    name_tag: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    /// Its claims, as its JWT writes them.
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded_jwt: Option<Ordered>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    revoked_user: BTreeMap<&'a str, String>,
    sublist_stats: Stats,
}

#[derive(Debug, Serialize)]
struct Accountz<'a> {
    server_id: &'a str,
    now: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_account: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accounts: Option<Vec<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_detail: Option<AccountInfo<'a>>,
}

/// The exports and imports of account `acc`, of id `id`, with JWT `jwt`
/// if it has one: those of the system account with the services the
/// server adds to it.
fn def_of(shared: &Shared, id: u32, acc: &str, jwt: Option<&Arc<JwtAccount>>) -> Def {
    let def = jwt.map_or_else(
        || defs::of(&shared.opts(), &[acc.to_owned()]).pop(),
        |j| Some(defs::of_jwt(acc, &j.claims.nats)),
    );
    let mut def = def.unwrap_or_default();
    if shared.system == Some(id) {
        crate::imports::system::add(std::slice::from_mut(&mut def), 0);
    }
    def
}

/// `/accountz`: the names of the accounts, or account `acc` in detail.
pub(super) async fn answer(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    shared.monitor.asked(q, Counted::Accountz);
    let mut page = Accountz {
        server_id: &shared.server_id,
        now: now(),
        system_account: shared.system.map(|id| shared.accounts.name(id)),
        accounts: None,
        account_detail: None,
    };
    let acc = q.get("acc");
    if acc.is_empty() {
        let names = shared.accounts.iter().map(|(_, a)| &*a.name);
        page.accounts = Some(names.filter(|n| in_use(shared, n)).collect());
        return Ok(pretty(&page));
    }
    let found = shared.accounts.id(acc).filter(|_| in_use(shared, acc));
    let Some((id, a)) = found.and_then(|id| Some((id, shared.accounts.get(id)?))) else {
        return Err(format!("Account {acc} does not exist"));
    };
    let u = accstatz::uses(shared, Which::One(id))
        .await
        .pop()
        .unwrap_or_default();
    let jwt = jwt_of(shared, acc);
    let def = def_of(shared, id, acc, jwt.as_ref());
    page.account_detail = Some(AccountInfo {
        account_name: &a.name,
        update_time: rfc3339_nano(a.updated()),
        is_system: shared.system == Some(id),
        expired: jwt.as_ref().is_some_and(|j| expired(j.claims.exp)),
        complete: true,
        jetstream_enabled: false,
        leafnode_connections: u.leafs,
        client_connections: u.clients,
        subscriptions: u.subs,
        exports: exports(&def),
        imports: imports(shared, a),
        jwt: jwt.as_ref().map(|j| j.jwt.clone()).unwrap_or_default(),
        issuer_key: jwt
            .as_ref()
            .map(|j| j.claims.iss.clone())
            .unwrap_or_default(),
        name_tag: name_tag(shared, acc),
        tags: jwt
            .as_ref()
            .map(|j| j.claims.nats.tags.clone())
            .unwrap_or_default(),
        decoded_jwt: jwt.as_ref().and_then(|j| Ordered::of_jwt(&j.jwt)),
        revoked_user: jwt
            .as_ref()
            .map(|j| revoked(&j.claims.nats.revocations))
            .unwrap_or_default(),
        sublist_stats: Stats::of(u.subs, u.inserts, u.removes),
    });
    Ok(pretty(&page))
}

/// Whether a JWT that expires at `exp`, seconds since the epoch, has; 0
/// for never.
fn expired(exp: i64) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH);
    let now = now.map_or(0, |d| d.as_secs().cast_signed());
    exp != 0 && exp <= now
}
