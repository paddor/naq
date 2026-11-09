//! A client logging in: its `CONNECT` checked against the users, a
//! password compared off the lane, an auth callout, and the account and
//! limits it gets.

use std::rc::Rc;

use tokio::time::Instant;

use super::read::Step;
use super::{Close, Conn, Stage};
use crate::ConnectionType;
use crate::auth::{Auth, Check, Creds, Grant, Origin, Pending};
use crate::callout::{self, Call, Hook, Plan};
use crate::perms::Held;

/// When a connection of subscription limit `limit`, with `subs` of them,
/// is closed, and why: at once if it is at its limit, as `nats-server`
/// tells it and closes it; else at `expires`, its account's if `.1`.
fn deadline(
    limit: i64,
    subs: usize,
    expires: Option<(std::time::SystemTime, bool)>,
) -> Option<(Instant, Close)> {
    if usize::try_from(limit).is_ok_and(|l| subs >= l) {
        return Some((
            Instant::now() + std::time::Duration::from_millis(20),
            Close::MaxSubs,
        ));
    }
    expires.map(|(t, account)| {
        let left = t
            .duration_since(std::time::SystemTime::now())
            .unwrap_or_default();
        let why = if account {
            Close::AccountExpired
        } else {
            Close::UserExpired
        };
        (Instant::now() + left, why)
    })
}

/// The largest payload a client may send: the server's, or `user`'s
/// limit if that is lower; -1 is none.
fn cap(user: i64, server: usize) -> usize {
    usize::try_from(user).map_or(server, |p| p.min(server))
}

/// A subscription its permissions no longer allow: its SID, subject and
/// queue group.
type Forbidden = (Box<[u8]>, Box<[u8]>, Option<Box<[u8]>>);

/// A login that finishes off the parse loop.
#[derive(Debug)]
pub(super) enum Later {
    /// A password to compare off the lane; if it does not hold, the
    /// callout to make, if any.
    Verify(Pending, Option<Call>),
    /// A callout to make.
    Call(Call),
    /// An account to fetch, of this key, then the login again with what
    /// the client gave.
    Fetch(String, Box<(Creds, Names)>),
}

/// The names a client gives in its `CONNECT`.
type Names = super::handshake::Names;

impl Conn {
    /// Applies a `CONNECT`.
    #[inline(never)]
    pub(super) fn connect(&mut self, json: &[u8]) -> Result<Step, Close> {
        self.client.seen.active();
        // As `nats-server`: estimated at every `CONNECT`, before the login.
        let rtt = self.ping.first_rtt(Instant::now());
        self.client.rtt.set(rtt);
        let (mut creds, names) = self.opts.apply(json).map_err(|_| Close::Connect)?;
        if let Some(cookies) = &self.via.cookies {
            creds.fill(cookies);
        }
        self.client.headers.set(self.opts.headers);
        let login = self.login(creds, names, false);
        self.refused(login)
    }

    /// Notes the account the client was in if `login` was refused.
    pub(super) fn refused<T>(&mut self, login: Result<T, Close>) -> Result<T, Close> {
        if matches!(login, Err(Close::Auth)) {
            let account = self.client.account.get();
            self.bounds.refused.get_or_insert(account);
        }
        login
    }

    /// Logs the client in with `creds` and `names`: once more if
    /// `fetched`, the account its JWT named fetched since.
    fn login(&mut self, mut creds: Creds, names: Names, fetched: bool) -> Result<Step, Close> {
        let shared = self.lane.shared.clone();
        let logins = shared.logins();
        let auth = logins.of(self.via.ws);
        let check = auth.map(|auth| {
            let nonce = self.nonce.as_deref().unwrap_or_default();
            auth.check(&mut creds, nonce.as_bytes(), self.origin())
        });
        if let Some(Check::Fetch(key)) = check {
            if fetched || shared.resolver.is_none() {
                return Err(Close::Auth);
            }
            let later = Later::Fetch(key, Box::new((creds, names)));
            return Ok(Step::Login(Box::new(later)));
        }
        let hook = shared
            .callouts
            .as_ref()
            .map_or(Hook::Keep, |c| c.hook(auth, &creds, check.as_ref()));
        let call = match &hook {
            Hook::Keep | Hook::Own(_) => None,
            Hook::Call(plan) | Hook::Verify(plan) => Some(self.call(plan, auth, &creds, &names)),
        };
        self.note_login(auth, &creds, names);
        // What a reload checks again: logins without a callout.
        let keep = matches!(hook, Hook::Keep);
        // A user of the service may not ask for others in its account.
        let own = |account: u32, perms: Option<std::sync::Arc<crate::perms::Perms>>| match hook {
            Hook::Own(a) if a == account => Some(callout::guarded(perms.as_deref())),
            _ => perms,
        };
        let later = match (check, call) {
            (_, Some(c)) if matches!(hook, Hook::Call(_)) => Later::Call(c),
            (Some(Check::Bcrypt(mut p)), call) => {
                p.grant.perms = own(p.grant.account, p.grant.perms.take());
                self.prove(keep, creds, Some(p.hash()));
                Later::Verify(p, call)
            }
            (Some(Check::Pass(mut g)), _) => {
                g.perms = own(g.account, g.perms.take());
                self.prove(keep, creds, None);
                self.bind(g)?;
                return self.connected().map(|()| Step::Next);
            }
            (Some(Check::User(mut u)), _) => {
                u.perms = own(u.account, u.perms.take());
                self.bind_user(&u)?;
                return self.connected().map(|()| Step::Next);
            }
            (None, _) => {
                self.prove(keep, creds, None);
                return self.connected().map(|()| Step::Next);
            }
            (Some(Check::Fail | Check::Fetch(_)), _) => return Err(Close::Auth),
        };
        Ok(Step::Login(Box::new(later)))
    }

    /// Notes who the client says it is, with `creds` and `names`, as
    /// `auth` knows it.
    fn note_login(&self, auth: Option<&Auth>, creds: &Creds, names: Names) {
        let mut meta = self.client.meta.borrow_mut();
        (meta.name, meta.lang, meta.version) = names;
        meta.websocket = self.via.ws;
        meta.how = super::log::How::of(creds);
        // A client without credentials is the no_auth_user, if any.
        let free = auth
            .filter(|_| creds.is_blank())
            .and_then(|a| a.id_of(creds))
            .map(str::to_owned);
        meta.user = creds.user.clone().or_else(|| creds.nkey.clone()).or(free);
    }

    /// Keeps `creds`, which held against bcrypt `hash` if any, for a reload
    /// to check again, if `keep`.
    fn prove(&mut self, keep: bool, creds: Creds, hash: Option<&str>) {
        self.bounds.login = keep.then(|| {
            Box::new(super::Proven {
                creds,
                hash: hash.map(str::to_owned),
            })
        });
    }

    /// The callout of `plan` for a client that gave `creds` to `auth`.
    #[cold]
    fn call(
        &self,
        plan: &Plan,
        auth: Option<&Auth>,
        creds: &Creds,
        names: &super::handshake::Names,
    ) -> Call {
        let mut creds = creds.clone();
        let jwt = auth.and_then(Auth::trust).and(creds.jwt.as_deref());
        let user = jwt.and_then(|j| crate::jwt::decode::<crate::jwt::claims::User>(j).ok());
        if let Some(a) = auth {
            a.fill_free(&mut creds);
        }
        if user.is_none() {
            // Outside operator mode, `nats-server` drops a JWT.
            creds.jwt = None;
        }
        let about = callout::request::About {
            id: self.client.id,
            ip: &self.ip,
            websocket: self.via.ws,
            creds: Some(&creds),
            name: names.0.as_deref(),
            lang: names.1.as_deref(),
            version: names.2.as_deref(),
            protocol: self.opts.protocol,
            nonce: self.nonce.as_deref(),
            jwt_user: user
                .as_ref()
                .map(|u| (u.sub.as_str(), u.nats.tags.as_slice(), u.name.as_str())),
            tls: self.via.tls.as_deref(),
        };
        callout::call(&self.lane.shared, plan, &about)
    }

    /// An operation before any `CONNECT`: the client is the `no_auth_user`,
    /// if there is one and it does not call out; else it is refused.
    #[cold]
    #[inline(never)]
    pub(super) fn without_connect(&mut self) -> Result<(), Close> {
        let shared = self.lane.shared.clone();
        let logins = shared.logins();
        let auth = logins.of(self.via.ws);
        let check = auth.map(|a| a.check(&mut Creds::default(), b"", self.origin()));
        if let Some(c) = &shared.callouts
            && matches!(
                c.hook(auth, &Creds::default(), check.as_ref()),
                Hook::Call(_) | Hook::Verify(_)
            )
        {
            return Err(Close::Auth);
        }
        match check {
            Some(Check::Pass(grant)) => {
                self.prove(true, Creds::default(), None);
                self.bind(grant)
            }
            _ => Err(Close::Auth),
        }
    }

    /// The kind of connection the client is.
    const fn kind(&self) -> ConnectionType {
        if self.via.ws {
            ConnectionType::Websocket
        } else {
            ConnectionType::Standard
        }
    }

    /// How the client connects, for the checks of its login.
    pub(super) fn origin(&self) -> Origin<'_> {
        Origin {
            ip: self.ip.parse().ok(),
            kind: self.kind(),
            cert: self.via.cert.as_deref(),
        }
    }

    /// Finishes login `l`, then the `CONNECT`.
    pub(super) async fn later(&mut self, l: Later) -> Result<(), Close> {
        match l {
            Later::Call(c) => self.callout(c).await,
            Later::Fetch(key, given) => {
                let (creds, names) = *given;
                let lane = self.lane.clone();
                let fetch = crate::resolver::fetch(&lane, &key);
                tokio::pin!(fetch);
                let fetched = loop {
                    tokio::select! {
                        biased;
                        () = self.client.stop.notified() => {
                            if self.client.is_closed() {
                                return Err(Close::Kicked);
                            }
                            // Not logged in yet: a reload or a change of
                            // its account is nothing to it.
                            self.lane.refreshed(self.client.id);
                        },
                        id = &mut fetch => break id,
                    }
                };
                fetched.ok_or(Close::Auth)?;
                match self.login(creds, names, true)? {
                    Step::Login(l) => Box::pin(self.later(*l)).await,
                    _ => Ok(()),
                }
            }
            Later::Verify(p, call) => {
                let grant = p.grant.clone();
                let holds = tokio::task::spawn_blocking(move || p.holds()).await;
                if matches!(holds, Ok(true)) {
                    self.bind(grant)?;
                    return self.connected();
                }
                match call {
                    Some(c) => self.callout(c).await,
                    None => Err(Close::Auth),
                }
            }
        }
    }

    /// Asks the auth service of `c` about the client, and waits for its
    /// answer as long as clients have to log in: it lets the client in,
    /// into its account, or keeps it out.
    async fn callout(&mut self, c: Call) -> Result<(), Close> {
        let shared = self.lane.shared.clone();
        let Some(callouts) = &shared.callouts else {
            return Err(Close::Auth);
        };
        let account = c.ask.account;
        let Some((reply, mut ticket)) = callouts.waiting.wait(account, callout::token()) else {
            return Err(Close::Auth);
        };
        let request = naq_proto::client::Pub {
            subject: callout::SUBJECT,
            reply: Some(&reply),
            headers: c.headers.as_deref(),
            payload: &c.payload,
        };
        crate::lane::inject(&self.lane, &mut self.out, account, &request);
        self.lane.flush();
        self.lane.ship_imported(&mut self.out).await;
        // Cancel-safe: a dropped wait loses nothing; the ticket keeps the
        // request until it goes.
        let timeout = tokio::time::sleep(shared.opts().auth_timeout);
        tokio::pin!(timeout);
        let answer = loop {
            tokio::select! {
                biased;
                () = self.client.stop.notified() => {
                    if self.client.is_closed() {
                        return Err(Close::Kicked);
                    }
                    // Not logged in yet: a reload or a change of its
                    // account is nothing to it.
                    self.lane.refreshed(self.client.id);
                },
                a = &mut ticket.answer => break a.ok(),
                () = &mut timeout => break None,
            }
        };
        drop(ticket);
        let decided = answer.and_then(|payload| {
            callout::response::decide(&c.ask, &payload, &shared, self.kind()).ok()
        });
        let Some(mut user) = decided else {
            // A refusal goes to the callout's account.
            self.bounds.refused = Some(account);
            return Err(Close::Auth);
        };
        if user.account == account {
            user.perms = Some(callout::guarded(user.perms.as_deref()));
        }
        // As the service decided: no reload checks it again.
        self.bounds.login = None;
        self.bind_user(&user)?;
        self.connected()
    }

    /// Puts the client into the account of `grant`, unless the account has
    /// all the clients it may across the cluster.
    pub(super) fn bind(&mut self, grant: Grant) -> Result<(), Close> {
        self.join(grant.account)?;
        self.auth_by = None;
        self.watch.on = self.watch.tracing;
        let held = grant.perms.map(|p| Rc::new(Held::new(p)));
        self.client
            .guarded
            .set(held.is_some() || self.client.traced.get());
        *self.client.held.borrow_mut() = held;
        self.enter(grant.account);
        Ok(())
    }

    /// Counts the client among the clients of `account`, unless it has all
    /// it may across the cluster: then the client goes, refused by it, as
    /// in `nats-server`.
    fn join(&mut self, account: u32) -> Result<(), Close> {
        if self.bounds.counted == Some(account) {
            return Ok(());
        }
        let shared = self.lane.shared.clone();
        if !shared.count(account, self.client.id) {
            self.enter(account);
            return Err(Close::AccountConns);
        }
        if let Some(a) = self.bounds.counted.replace(account) {
            shared.uncount(a, self.client.id);
        }
        Ok(())
    }

    /// Moves the client to `account`. Subscriptions in another it had are
    /// dropped, as a new `CONNECT` drops them in `nats-server`.
    fn enter(&mut self, account: u32) {
        self.out.account = account;
        if self.client.account.get() == account {
            return;
        }
        let sids: Vec<_> = self.client.subs.borrow().keys().cloned().collect();
        for sid in sids {
            self.client.unsubscribe(&self.lane, &sid);
        }
        self.client.account.set(account);
    }

    /// Puts the client into the account of user `u` of a JWT, with its
    /// limits, unless the account has all the connections it may.
    #[cold]
    #[inline(never)]
    fn bind_user(&mut self, u: &crate::jwt::trust::User) -> Result<(), Close> {
        let shared = self.lane.shared.clone();
        if let Some(a) = shared.accounts.get(u.account) {
            a.set_limit(u.conns);
        }
        self.bind(Grant {
            account: u.account,
            perms: u.perms.clone(),
        })?;
        self.bounds.payload = u.payload;
        self.bounds.limits.max_payload = cap(u.payload, shared.opts().max_payload);
        self.bounds.subs = u.subs;
        let user = u.expires.map(|t| (t, false));
        let account = u.account_expires.map(|t| (t, true));
        let expires = [user, account].into_iter().flatten().min();
        self.bounds.deadline = deadline(u.subs, 0, expires);
        self.bounds.kept.clone_from(&u.kept);
        if shared.resolver.is_some() {
            // The taps of an account added since this lane was told.
            crate::imports::service::install_account(&self.lane, u.account);
        }
        let mut meta = self.client.meta.borrow_mut();
        meta.user = Some(u.key.clone());
        meta.jwt = Some(u.shown.clone());
        meta.expires = expires.map(|(t, _)| t);
        Ok(())
    }

    /// Checks the login again once the server's options or its account
    /// changed, as `nats-server` checks its clients after a reload or an
    /// update: the client may stay with new limits and permissions, or go.
    pub(super) async fn refresh(&mut self) -> Result<(), Close> {
        self.retake();
        let done = if self.bounds.login.is_some() {
            self.relogin().await
        } else {
            self.recheck()
        };
        // A client that goes tells as it ends, its close logged.
        if done.is_ok() {
            self.lane.refreshed(self.client.id);
        }
        done
    }

    /// Checks a JWT login again, as for an update of its account.
    #[cold]
    #[inline(never)]
    fn recheck(&mut self) -> Result<(), Close> {
        use crate::jwt::trust::live::{Gone, Refresh};
        let shared = self.lane.shared.clone();
        let trust = shared.trust();
        let (Some(trust), Some(kept)) = (trust, self.bounds.kept.as_deref_mut()) else {
            return Ok(());
        };
        let s = match trust.refresh(kept) {
            Refresh::Stays(s) => s,
            Refresh::Goes(Gone::Expired) => return Err(Close::AccountExpired),
            Refresh::Goes(Gone::Revoked) => return Err(Close::Revoked),
            Refresh::Goes(Gone::Bearer) => return Err(Close::Auth),
            Refresh::Goes(Gone::Unsigned) => return Err(Close::Unsigned),
        };
        let account = self.client.account.get();
        if let Some(a) = shared.accounts.get(account) {
            a.set_limit(s.conns);
        }
        // The newest connections past the limit go first.
        if !shared.kept(account, self.client.id, s.conns) {
            return Err(Close::AccountConns);
        }
        if let Some(defaults) = &s.defaults {
            kept.defaults = Some(defaults.clone());
        }
        self.bounds.payload = s.payload;
        self.bounds.limits.max_payload = cap(s.payload, shared.opts().max_payload);
        self.bounds.subs = s.subs;
        let subs = self.client.subs.borrow().len();
        self.bounds.deadline = deadline(s.subs, subs, s.expires);
        if let Some(defaults) = s.defaults {
            self.bind(Grant {
                account,
                perms: defaults.0,
            })?;
            self.drop_forbidden(false);
        }
        self.lane.flush();
        Ok(())
    }

    /// Takes the server's options anew, as after a reload: the limits of
    /// what the client sends, the time between pings, and whether it is
    /// traced.
    fn retake(&mut self) {
        let shared = self.lane.shared.clone();
        let opts = shared.opts();
        let limits = &mut self.bounds.limits;
        limits.max_control_line = opts.max_control_line;
        limits.max_payload = cap(self.bounds.payload, opts.max_payload);
        // WebSocket clients may ping at their own pace.
        let own = self.via.ws
            && shared
                .ws
                .as_ref()
                .is_some_and(|w| w.opts.ping_interval.is_some());
        if !own {
            self.ping.interval = opts.ping_interval;
        }
        let tracing = shared.log.traces();
        self.client.traced.set(tracing);
        self.client
            .guarded
            .set(tracing || self.client.held.borrow().is_some());
        self.watch.tracing = tracing;
        self.watch.on = tracing || self.auth_by.is_some();
    }

    /// Ends the subscriptions its permissions no longer allow, and tells
    /// it; logs each if `logged`, as `nats-server` does on a reload.
    pub(super) fn drop_forbidden(&mut self, logged: bool) {
        let held = self.client.held.borrow().clone();
        let Some(held) = held else {
            return;
        };
        let forbidden: Vec<Forbidden> = self
            .client
            .subs
            .borrow()
            .iter()
            .filter(|(_, s)| !held.perms.subscribe(&s.subject, s.queue.as_deref()))
            .map(|(sid, s)| (sid.clone(), s.subject.clone(), s.queue.clone()))
            .collect();
        let who = logged.then(|| self.auth_user());
        for (sid, subject, queue) in forbidden {
            self.client.unsubscribe(&self.lane, &sid);
            let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
            let (subject, sid) = (text(&subject), text(&sid));
            let using = queue.map(|q| format!(" using queue {:?}", text(&q)));
            let using = using.unwrap_or_default();
            self.error(&format!(
                "Permissions Violation for Subscription to {subject:?}{using} (sid {sid:?})"
            ));
            if let Some(who) = &who {
                self.lane.shared.log.info(format_args!(
                    "Removed sub {subject:?}{using} (sid {sid:?}) for {who} - not authorized"
                ));
            }
        }
    }

    /// The rest of a `CONNECT`, from a client that is who it says.
    fn connected(&mut self) -> Result<(), Close> {
        crate::sys::connected(&self.lane, crate::sys::Of::Client(&self.client));
        if self.stage == Stage::Fresh {
            self.stage = Stage::Connected;
        }
        let interval = self.ping.interval;
        let jitter = super::ping::jitter(interval, |n| self.lane.below(n));
        self.ping.connected(Instant::now(), interval, jitter);
        if !(0..=1).contains(&self.opts.protocol) {
            return Err(Close::Refused(super::BAD_PROTOCOL));
        }
        if self.opts.no_responders && !self.opts.headers {
            return Err(Close::Refused("no responders requires headers support"));
        }
        self.ok();
        Ok(())
    }
}
