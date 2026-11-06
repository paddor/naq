//! Operator mode: the operators a server trusts, the accounts their keys
//! signed, and users that log in with a JWT their account signed, as
//! `nats-server` checks them.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustc_hash::FxHashMap;

use super::claims::{self, NO_LIMIT};
use super::{Claims, decode, now};
use crate::auth::Origin;
use crate::perms::Perms;
use crate::{ConnectionType, Options, Resolver};

/// The operators a server trusts, and the accounts they signed.
#[derive(Debug)]
pub(crate) struct Trust {
    /// Keys that may sign account JWTs.
    signers: Vec<String>,
    /// Accounts must be signed by an operator's signing key, and users by
    /// an account's signing key.
    strict: bool,
    /// The key of the first operator, if any: the one `nats-server` checks
    /// strict signing against.
    operator: String,
    /// The accounts of JWTs, by public key. Updates replace them.
    accounts: RwLock<FxHashMap<String, Arc<JwtAccount>>>,
}

/// An account of a JWT.
#[derive(Debug)]
pub(crate) struct JwtAccount {
    /// Its id among the server's accounts.
    pub(crate) id: u32,
    pub(crate) claims: Claims<claims::Account>,
    /// The JWT, as given.
    pub(crate) jwt: String,
    /// A client looked it up: as `nats-server` loads accounts on first use,
    /// only these take updates.
    loaded: std::sync::atomic::AtomicBool,
    /// The permissions of its users that have none of their own.
    defaults: Option<Arc<Perms>>,
}

/// A user that logged in with a JWT.
#[derive(Debug, Clone)]
pub(crate) struct User {
    /// Its account's id.
    pub(crate) account: u32,
    pub(crate) perms: Option<Arc<Perms>>,
    /// Its public key.
    pub(crate) key: String,
    /// Most subscriptions and largest payload; [`NO_LIMIT`] for none.
    pub(crate) subs: i64,
    pub(crate) payload: i64,
    /// Most connections of its account; [`NO_LIMIT`] for none.
    pub(crate) conns: i64,
    /// When it may no longer be connected.
    pub(crate) expires: Option<SystemTime>,
    /// When its account expires, if it does.
    pub(crate) account_expires: Option<SystemTime>,
    /// What it keeps to check itself again once its account changes.
    pub(crate) kept: Option<Box<live::Kept>>,
    /// What monitoring shows of it.
    pub(crate) shown: Box<Shown>,
}

/// What monitoring shows of a user of a JWT, as `nats-server` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Shown {
    /// Its JWT; `None` for a bearer token, which is not shown.
    pub(crate) jwt: Option<String>,
    /// The key that signed it: its account or a signing key.
    pub(crate) issuer: String,
    pub(crate) tags: Vec<String>,
    /// The name of its account: in the account's JWT, else its key.
    pub(crate) account_name: String,
    /// The name in its JWT.
    pub(crate) user_name: String,
}

impl Shown {
    /// What monitoring shows of `user`, which an auth callout let in
    /// without a JWT of its own, in account `account`.
    pub(crate) fn placed(user: &Claims<claims::User>, account: &str) -> Shown {
        Shown {
            jwt: None,
            issuer: user.iss.clone(),
            tags: user.nats.tags.clone(),
            account_name: account.to_owned(),
            user_name: user.name.clone(),
        }
    }

    /// What monitoring shows of `user`, logged in with `jwt` to account
    /// `a`: its JWT unless a bearer token.
    fn of(
        user: &Claims<claims::User>,
        jwt: &str,
        bearer: bool,
        a: &Claims<claims::Account>,
    ) -> Shown {
        Shown {
            jwt: (!bearer).then(|| jwt.to_owned()),
            ..Shown::placed(user, account_name(a))
        }
    }
}

/// The name of account `a`: in its JWT, else its key.
fn account_name(a: &Claims<claims::Account>) -> &str {
    Some(a.name.as_str())
        .filter(|n| !n.is_empty())
        .unwrap_or(&a.sub)
}

impl PartialEq for User {
    /// The same key in the same account, with the same limits.
    fn eq(&self, o: &User) -> bool {
        (
            self.account,
            &self.key,
            self.subs,
            self.payload,
            self.conns,
            self.expires,
        ) == (o.account, &o.key, o.subs, o.payload, o.conns, o.expires)
    }
}

impl Eq for User {}

impl JwtAccount {
    /// Account `id` of `claims`, decoded from `jwt`.
    pub(crate) fn new(id: u32, claims: Claims<claims::Account>, jwt: String) -> JwtAccount {
        JwtAccount {
            id,
            defaults: defaults(&claims.nats.default_permissions),
            claims,
            jwt,
            loaded: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Marks it used.
    pub(crate) fn load(&self) {
        // Relaxed: a flag on its own, read under the accounts' lock.
        self.loaded
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether it was used.
    pub(crate) fn is_loaded(&self) -> bool {
        // Relaxed: as in `load`.
        self.loaded.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The startup rules of `nats-server` for operator mode.
pub(crate) fn validate(opts: &Options) -> Result<(), String> {
    if opts.operators.is_empty() && opts.trusted_keys.is_empty() {
        if opts.resolver.is_some() || !opts.resolver_preload.is_empty() {
            return Err("a resolver needs trusted operators".into());
        }
        return Ok(());
    }
    if !opts.operators.is_empty() && !opts.trusted_keys.is_empty() {
        return Err("conflicting options for 'TrustedKeys' and 'TrustedOperators'".into());
    }
    if opts.resolver.is_none() {
        return Err("operators require an account resolver to be configured".into());
    }
    if !opts.accounts.is_empty() {
        return Err("operators do not allow Accounts to be configured directly".into());
    }
    if !opts.users.is_empty() || opts.user.is_some() || opts.token.is_some() {
        return Err("operators do not allow users to be configured directly".into());
    }
    for op in &opts.operators {
        let c = decode::<claims::Operator>(op)
            .map_err(|e| format!("error parsing operator JWT: {e}"))?;
        let named = &c.nats.system_account;
        if let Some(sys) = &opts.system_account
            && !named.is_empty()
            && sys != named
        {
            return Err("system_account in config and operator JWT must be identical".into());
        }
    }
    if matches!(opts.resolver, Some(Resolver::Full(_) | Resolver::Cache(_))) {
        if opts.operators.is_empty() {
            return Err("Could not start resolver: no operator key found".into());
        }
        if opts.system_account.is_none() && system_account(opts).is_none() {
            return Err(
                "using nats based account resolver - the system account needs to be \
                        specified in configuration or the operator jwt"
                    .into(),
            );
        }
    }
    for (key, jwt) in &opts.resolver_preload {
        if !super::is_key(key, 'A') {
            return Err(format!(
                "resolver_preload: {key:?} is not a public account key"
            ));
        }
        let c = decode::<claims::Account>(jwt)
            .map_err(|e| format!("resolver_preload: invalid account JWT: {e}"))?;
        if c.sub != *key {
            return Err(format!(
                "resolver_preload: the JWT of {key:?} is of another account"
            ));
        }
    }
    Ok(())
}

/// The system account an operator JWT names, if one does and the options
/// name none.
pub(crate) fn system_account(opts: &Options) -> Option<String> {
    opts.operators
        .iter()
        .filter_map(|op| decode::<claims::Operator>(op).ok())
        .map(|c| c.nats.system_account)
        .find(|s| !s.is_empty())
}

impl Trust {
    /// The trust of `opts`, with the accounts of their preloads among
    /// `names`, the server's accounts by id; `None` outside operator mode.
    /// The options were validated.
    pub(crate) fn new(opts: &Options, names: &[String]) -> Option<Trust> {
        if opts.operators.is_empty() && opts.trusted_keys.is_empty() {
            return None;
        }
        let mut signers = opts.trusted_keys.clone();
        let mut strict = false;
        let mut operator = String::new();
        for c in opts
            .operators
            .iter()
            .filter_map(|op| decode::<claims::Operator>(op).ok())
        {
            strict |= c.nats.strict_signing_key_usage;
            if operator.is_empty() {
                operator.clone_from(&c.sub);
            }
            if !c.nats.strict_signing_key_usage {
                signers.push(c.sub.clone());
            }
            signers.extend(c.nats.signing_keys);
        }
        let t = Trust {
            signers,
            strict,
            operator,
            accounts: RwLock::default(),
        };
        let system = opts.system_account.clone().or_else(|| system_account(opts));
        for (key, jwt) in &opts.resolver_preload {
            // One that fails the checks of nats-io/jwt is no account.
            let Some(claims) = decode::<claims::Account>(jwt)
                .ok()
                .filter(|c| super::validate::account(c).is_ok())
            else {
                continue;
            };
            // Kept though its issuer is not trusted: its users fail.
            let Some(id) = names.iter().position(|n| n == key) else {
                continue;
            };
            // Accounts are few: their count fits.
            let account = JwtAccount::new(id as u32, claims, jwt.clone());
            // As in `nats-server`, the system account is there from the start.
            if Some(key) == system.as_ref() {
                account.load();
            }
            if let Ok(mut all) = t.accounts.write() {
                all.insert(key.clone(), Arc::new(account));
            }
        }
        Some(t)
    }

    /// The account of public key `key`, if its JWT holds: signed by a key
    /// this server trusts.
    pub(crate) fn account(&self, key: &str) -> Option<Arc<JwtAccount>> {
        let all = self.accounts.read().ok()?;
        all.get(key)
            .filter(|a| self.signers.contains(&a.claims.iss))
            .cloned()
    }

    /// The user of JWT `jwt`, with `sig` the signature of `nonce`, that
    /// connects from `origin`, as `nats-server` checks it; `None` if it
    /// does not hold.
    pub(crate) fn login(
        &self,
        jwt: &str,
        sig: Option<&str>,
        nonce: &[u8],
        origin: Origin<'_>,
    ) -> Option<User> {
        let user = decode::<claims::User>(jwt).ok()?;
        let at = now();
        let issuer = &user.nats.issuer_account;
        if user.out_of_time(at) || (!issuer.is_empty() && !super::is_key(issuer, 'A')) {
            return None;
        }
        let key = if issuer.is_empty() { &user.iss } else { issuer };
        let account = self.account(key)?;
        account.load();
        let a = &account.claims;
        if a.out_of_time(at) {
            return None;
        }
        let templated = self.template(&user, key, a)?;
        let limits = templated.as_ref().unwrap_or(&user.nats.limits);
        let bearer = limits.bearer_token;
        if (bearer && a.nats.limits.disallow_bearer) || !connects_as(limits, origin.kind) {
            return None;
        }
        if !bearer && !super::super::auth::signed(&user.sub, nonce, sig) {
            return None;
        }
        let revoked = |k: &str| a.nats.revocations.get(k).is_some_and(|&t| t >= user.iat);
        if revoked(&user.sub) || revoked("*") {
            return None;
        }
        if !from_allowed(&limits.src, origin.ip) {
            return None;
        }
        let window_end = time_left(limits).ok()?;
        let expires = [expiry(&user), window_end].into_iter().flatten().min();
        let own = &limits.permissions;
        let perms = if own.is_empty() {
            account.defaults.clone()
        } else {
            defaults(own)
        };
        let kept = live::Kept {
            jwt: Some(jwt.to_owned()),
            defaults: own
                .is_empty()
                .then(|| live::Defaults(account.defaults.clone())),
            subs: limits.subs,
            payload: limits.payload,
            expires,
            ..kept_of(&user, key, a)
        };
        Some(User {
            account: account.id,
            perms,
            key: user.sub.clone(),
            subs: tighter(limits.subs, a.nats.limits.subs),
            payload: tighter(limits.payload, a.nats.limits.payload),
            conns: a.nats.limits.conn,
            expires,
            account_expires: expiry(a),
            kept: Some(Box::new(kept)),
            shown: Box::new(Shown::of(&user, jwt, bearer, a)),
        })
    }
}

/// What a user of user JWT claims `user` in account `key` of claims `a`
/// keeps of its account: its key, issue time and signer.
fn kept_of(user: &Claims<claims::User>, key: &str, a: &Claims<claims::Account>) -> live::Kept {
    live::Kept {
        signer: signer_of(user, key, a),
        ..live::Kept::of_callout(key, user)
    }
}

/// The signing key that issued `user` of account `key` of claims `a`, if
/// not the account itself, with the template it has.
fn signer_of(
    user: &Claims<claims::User>,
    key: &str,
    a: &Claims<claims::Account>,
) -> Option<(String, Option<claims::UserLimits>)> {
    let scope = a
        .nats
        .signing_keys
        .0
        .get(&user.iss)
        .filter(|_| user.iss != key)?;
    Some((user.iss.clone(), scope.as_ref().map(|s| s.template.clone())))
}

/// When claims `c` expire, if they do.
fn expiry<T>(c: &Claims<T>) -> Option<SystemTime> {
    (c.exp > 0).then(|| UNIX_EPOCH + Duration::from_secs(c.exp.cast_unsigned()))
}

impl Trust {
    /// The limits of `user`, whose account is `key` of claims `a`, if its
    /// issuer is a scoped signing key: its template, filled in. `Some(None)`
    /// if the issuer is the account or a plain signing key; `None` if the
    /// issuer may not sign it.
    #[expect(
        clippy::option_option,
        reason = "a user's own limits, a template's, or none"
    )]
    fn template(
        &self,
        user: &Claims<claims::User>,
        key: &str,
        a: &Claims<claims::Account>,
    ) -> Option<Option<claims::UserLimits>> {
        if user.iss == key {
            // In strict mode, only signing keys sign users.
            return (!self.strict && user.nats.issuer_account.is_empty()).then_some(None);
        }
        let Some(scope) = a.nats.signing_keys.0.get(&user.iss)? else {
            return Some(None);
        };
        // A scoped user brings nothing of its own.
        if !user.nats.limits.is_empty() {
            return None;
        }
        let v = super::template::Values { user, account: a };
        super::template::fill(&scope.template, &v).map(Some)
    }
}

impl Trust {
    /// The ids of the accounts whose users call out: those that name auth
    /// users.
    pub(crate) fn callouts(&self) -> Vec<u32> {
        let Ok(all) = self.accounts.read() else {
            return Vec::new();
        };
        all.values()
            .filter(|a| !a.claims.nats.authorization.auth_users.is_empty())
            .map(|a| a.id)
            .collect()
    }

    /// The user an answer of the callout of account `callout` lets in
    /// with user JWT `user`, connecting as `kind`, as `nats-server` places
    /// it: in the account that issued it, the callout account or one of
    /// `allowed`, with its permissions and the account's limits; the
    /// user's own limits do not count. Why not, if not.
    pub(crate) fn placed(
        &self,
        user: &Claims<claims::User>,
        callout: &str,
        allowed: &[String],
        kind: ConnectionType,
    ) -> Result<User, String> {
        let issuer = &user.nats.issuer_account;
        let key = if issuer.is_empty() { &user.iss } else { issuer };
        let any = allowed.len() == 1 && allowed[0] == "*";
        if key != callout && !any && !allowed.contains(key) {
            return Err(format!("account {:?} not permitted", user.iss));
        }
        let account = self
            .account(key)
            .ok_or_else(|| format!("no valid account {key:?}"))?;
        let a = &account.claims;
        let templated = self
            .template(user, key, a)
            .ok_or_else(|| format!("user JWT issuer {:?} is not known", user.iss))?;
        let limits = templated.as_ref().unwrap_or(&user.nats.limits);
        let end = time_left(limits)?;
        if !connects_as(limits, kind) {
            return Err("not allowed to use connection type".into());
        }
        let exp =
            (user.exp > 0).then(|| UNIX_EPOCH + Duration::from_secs(user.exp.cast_unsigned()));
        let own = &limits.permissions;
        let mut kept = live::Kept::of_callout(key, user);
        kept.defaults = own
            .is_empty()
            .then(|| live::Defaults(account.defaults.clone()));
        Ok(User {
            account: account.id,
            perms: if own.is_empty() {
                account.defaults.clone()
            } else {
                defaults(own)
            },
            key: user.sub.clone(),
            subs: a.nats.limits.subs,
            payload: a.nats.limits.payload,
            conns: a.nats.limits.conn,
            expires: [exp, end].into_iter().flatten().min(),
            account_expires: expiry(a),
            kept: Some(Box::new(kept)),
            shown: Box::new(Shown::placed(user, account_name(a))),
        })
    }
}

/// When the time window of `limits` ends, if it does; an error outside
/// it.
pub(crate) fn time_left(limits: &claims::UserLimits) -> Result<Option<SystemTime>, String> {
    match window(&limits.times, &limits.times_location, SystemTime::now()) {
        Window::Always => Ok(None),
        Window::Until(t) => Ok(Some(t)),
        Window::Outside => Err("outside of valid connect times".into()),
    }
}

/// The tighter of two limits, [`NO_LIMIT`] being none.
const fn tighter(a: i64, b: i64) -> i64 {
    match (a, b) {
        (NO_LIMIT, x) | (x, NO_LIMIT) => x,
        (a, b) if a < b => a,
        (_, b) => b,
    }
}

/// Permissions of JWT permissions `p`, if they limit anything, as
/// `nats-server` builds them: responses default to one within two minutes.
pub(crate) fn defaults(p: &claims::Permissions) -> Option<Arc<Perms>> {
    if p.is_empty() {
        return None;
    }
    let rules = |q: &claims::Permission| crate::Rules {
        allow: (!q.allow.is_empty()).then(|| q.allow.clone()),
        deny: q.deny.clone(),
    };
    let responses = p.resp.map(|r| {
        let d = crate::Responses::default();
        crate::Responses {
            max: u32::try_from(r.max)
                .ok()
                .filter(|&m| m > 0)
                .unwrap_or(d.max),
            expires: u64::try_from(r.ttl)
                .ok()
                .filter(|&t| t > 0)
                .map_or(d.expires, Duration::from_nanos),
        }
    });
    Some(Arc::new(Perms::new(&crate::Permissions {
        publish: rules(&p.publish),
        subscribe: rules(&p.subscribe),
        responses,
    })))
}

/// Whether a user of `limits` may connect as `kind`: by its allowed
/// connection types, of which `nats-server` drops those it does not know.
/// None known of some given is none allowed.
pub(crate) fn connects_as(limits: &claims::UserLimits, kind: ConnectionType) -> bool {
    let types = &limits.allowed_connection_types;
    types.is_empty()
        || types
            .iter()
            .filter_map(|t| ConnectionType::named(t))
            .any(|t| t == kind)
}

/// Whether `ip` is in one of `cidrs`; any IP is with none.
fn from_allowed(cidrs: &[String], ip: Option<IpAddr>) -> bool {
    if cidrs.is_empty() {
        return true;
    }
    let Some(ip) = ip else {
        return false;
    };
    cidrs.iter().any(|c| in_cidr(c, ip))
}

/// Whether `ip` is in CIDR `cidr`.
fn in_cidr(cidr: &str, ip: IpAddr) -> bool {
    let Some((net, bits)) = cidr.trim().split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

/// Where a time is among daily windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Window {
    /// There are none: any time will do.
    Always,
    /// In one, which ends then.
    Until(SystemTime),
    /// In none.
    Outside,
}

/// Where `now` is among daily windows `times`, in location `location`.
/// Only UTC is served: an empty location, which `nats-server` takes as its
/// own, is taken as UTC.
fn window(times: &[claims::TimeRange], location: &str, now: SystemTime) -> Window {
    if times.is_empty() {
        return Window::Always;
    }
    if !location.is_empty() && !location.eq_ignore_ascii_case("UTC") {
        return Window::Outside;
    }
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (day, of_day) = (secs - secs % 86_400, secs % 86_400);
    for t in times {
        let (Some(start), Some(end)) = (clock(&t.start), clock(&t.end)) else {
            continue;
        };
        // A window past midnight ends the next day.
        let inside = if start <= end {
            (start..end).contains(&of_day)
        } else {
            of_day >= start || of_day < end
        };
        if inside {
            let end_day = if start > end && of_day >= start {
                day + 86_400
            } else {
                day
            };
            return Window::Until(UNIX_EPOCH + Duration::from_secs(end_day + end));
        }
    }
    Window::Outside
}

/// Seconds into the day of `HH:MM:SS`.
fn clock(t: &str) -> Option<u64> {
    let mut parts = t.split(':').map(|p| p.parse::<u64>().ok());
    let (h, m, s) = (parts.next()??, parts.next()??, parts.next()??);
    (h < 24 && m < 60 && s < 60 && parts.next().is_none()).then_some(h * 3600 + m * 60 + s)
}

pub(crate) mod dir;
pub(crate) mod live;

#[cfg(test)]
mod tests;
