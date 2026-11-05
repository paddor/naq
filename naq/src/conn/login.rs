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

/// A login that finishes off the parse loop.
#[derive(Debug)]
pub(super) enum Later {
    /// A password to compare off the lane; if it does not hold, the
    /// callout to make, if any.
    Verify(Pending, Option<Call>),
    /// A callout to make.
    Call(Call),
}

impl Conn {
    /// Applies a `CONNECT`.
    #[inline(never)]
    pub(super) fn connect(&mut self, json: &[u8]) -> Result<Step, Close> {
        let (mut creds, names) = self.opts.apply(json).map_err(|_| Close::Connect)?;
        if let Some(cookies) = &self.via.cookies {
            creds.fill(cookies);
        }
        self.client.headers.set(self.opts.headers);
        let shared = self.lane.shared.clone();
        let auth = shared.auth_for(self.via.ws);
        let check = auth.map(|auth| {
            let nonce = self.nonce.as_deref().unwrap_or_default();
            auth.check(&mut creds, nonce.as_bytes(), self.origin())
        });
        let hook = shared
            .callouts
            .as_ref()
            .map_or(Hook::Keep, |c| c.hook(auth, &creds, check.as_ref()));
        let call = match &hook {
            Hook::Keep | Hook::Own(_) => None,
            Hook::Call(plan) | Hook::Verify(plan) => Some(self.call(plan, auth, &creds, &names)),
        };
        {
            let mut meta = self.client.meta.borrow_mut();
            (meta.name, meta.lang, meta.version) = names;
            meta.websocket = self.via.ws;
            meta.user = creds.user.or(creds.nkey);
        }
        // A user of the service may not ask for others in its account.
        let own = |account: u32, perms: Option<std::sync::Arc<crate::perms::Perms>>| match hook {
            Hook::Own(a) if a == account => Some(callout::guarded(perms.as_deref())),
            _ => perms,
        };
        let later = match (check, call) {
            (_, Some(c)) if matches!(hook, Hook::Call(_)) => Later::Call(c),
            (Some(Check::Bcrypt(mut p)), call) => {
                p.grant.perms = own(p.grant.account, p.grant.perms.take());
                Later::Verify(p, call)
            }
            (Some(Check::Pass(mut g)), _) => {
                g.perms = own(g.account, g.perms.take());
                self.bind(g);
                return self.connected().map(|()| Step::Next);
            }
            (Some(Check::User(mut u)), _) => {
                u.perms = own(u.account, u.perms.take());
                self.bind_user(&u)?;
                return self.connected().map(|()| Step::Next);
            }
            (None, _) => return self.connected().map(|()| Step::Next),
            (Some(Check::Fail), _) => return Err(Close::Auth),
        };
        Ok(Step::Login(Box::new(later)))
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
        let auth = shared.auth_for(self.via.ws);
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
            Some(Check::Pass(account)) => {
                self.bind(account);
                Ok(())
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
    fn origin(&self) -> Origin<'_> {
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
            Later::Verify(p, call) => {
                let grant = p.grant.clone();
                let holds = tokio::task::spawn_blocking(move || p.holds()).await;
                if matches!(holds, Ok(true)) {
                    self.bind(grant);
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
        let answer = tokio::select! {
            biased;
            () = self.client.stop.notified() => return Err(Close::Kicked),
            a = &mut ticket.answer => a.ok(),
            () = tokio::time::sleep(shared.opts.auth_timeout) => None,
        };
        drop(ticket);
        let payload = answer.ok_or(Close::Auth)?;
        let mut user = callout::response::decide(&c.ask, &payload, &shared, self.kind())
            .map_err(|_| Close::Auth)?;
        if user.account == account {
            user.perms = Some(callout::guarded(user.perms.as_deref()));
        }
        self.bind_user(&user)?;
        self.connected()
    }

    /// Puts the client into `account`. Subscriptions in another it had are
    /// dropped, as a new `CONNECT` drops them in `nats-server`.
    pub(super) fn bind(&mut self, grant: Grant) {
        self.auth_by = None;
        self.out.account = grant.account;
        let held = grant.perms.map(|p| Rc::new(Held::new(p)));
        self.client.guarded.set(held.is_some());
        *self.client.held.borrow_mut() = held;
        if self.client.account.get() == grant.account {
            return;
        }
        let sids: Vec<_> = self.client.subs.borrow().keys().cloned().collect();
        for sid in sids {
            self.client.unsubscribe(&self.lane, &sid);
        }
        self.client.account.set(grant.account);
    }

    /// Puts the client into the account of user `u` of a JWT, with its
    /// limits, unless the account has all the connections it may.
    #[cold]
    #[inline(never)]
    fn bind_user(&mut self, u: &crate::jwt::trust::User) -> Result<(), Close> {
        let shared = self.lane.shared.clone();
        if self.bounds.counted != Some(u.account) {
            if !shared.count(u.account, u.conns) {
                return Err(Close::AccountConns);
            }
            if let Some(a) = self.bounds.counted.replace(u.account) {
                shared.uncount(a);
            }
        }
        self.bind(Grant {
            account: u.account,
            perms: u.perms.clone(),
        });
        let server = shared.opts.max_payload;
        self.bounds.limits.max_payload =
            usize::try_from(u.payload).map_or(server, |p| p.min(server));
        self.bounds.subs = u.subs;
        self.bounds.deadline = if u.subs == 0 {
            // As `nats-server` does: once it is in, it is told and closed.
            Some((
                Instant::now() + std::time::Duration::from_millis(20),
                Close::MaxSubs,
            ))
        } else {
            u.expires.map(|t| {
                let left = t
                    .duration_since(std::time::SystemTime::now())
                    .unwrap_or_default();
                (Instant::now() + left, Close::UserExpired)
            })
        };
        self.client.meta.borrow_mut().user = Some(u.key.clone());
        Ok(())
    }

    /// The rest of a `CONNECT`, from a client that is who it says.
    fn connected(&mut self) -> Result<(), Close> {
        if self.stage == Stage::Fresh {
            self.stage = Stage::Connected;
        }
        let interval = self.ping.interval;
        let jitter = super::ping::jitter(interval, |n| self.lane.below(n));
        let rtt = self.ping.connected(Instant::now(), interval, jitter);
        self.client.rtt.set(rtt);
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
