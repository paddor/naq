//! A client checked again as the server reloads its users, as
//! `nats-server` checks its clients: one whose user went or moved to
//! another account goes, one whose secret no longer holds is refused, and
//! one that stays takes its new permissions.

use std::rc::Rc;

use super::{Close, Conn};
use crate::auth::{Check, Grant};
use crate::perms::Held;

impl Conn {
    /// Logs the client in again with what it logged in with, against the
    /// users the server has now, if it logged in so.
    #[cold]
    #[inline(never)]
    pub(super) async fn relogin(&mut self) -> Result<(), Close> {
        let Some(proven) = self.bounds.login.as_deref() else {
            return Ok(());
        };
        let mut creds = proven.creds.clone();
        let hash = proven.hash.clone();
        let shared = self.lane.shared.clone();
        let logins = shared.logins();
        let auth = logins.of(self.via.ws);
        let account = self.client.account.get();
        // As `nats-server`: a user or NKey it no longer has, or has in
        // another account, moved; the client reconnects to find out.
        let named = creds.user.is_some() || creds.nkey.is_some();
        if named && auth.and_then(|a| a.account_of(&creds)) != Some(account) {
            return Err(Close::Moved);
        }
        let Some(auth) = auth else {
            self.regrant(Grant {
                account,
                perms: None,
            });
            return Ok(());
        };
        let nonce = self.nonce.clone().unwrap_or_default();
        let grant = match auth.check(&mut creds, nonce.as_bytes(), self.origin()) {
            Check::Pass(g) => g,
            // The same hash: the password held against it already.
            Check::Bcrypt(p) if hash.as_deref() == Some(p.hash()) => p.grant,
            Check::Bcrypt(p) => {
                let (grant, hash) = (p.grant.clone(), p.hash().to_owned());
                let holds = tokio::task::spawn_blocking(move || p.holds()).await;
                if !matches!(holds, Ok(true)) {
                    return Err(Close::Auth);
                }
                if let Some(l) = self.bounds.login.as_deref_mut() {
                    l.hash = Some(hash);
                }
                grant
            }
            Check::Fail | Check::User(_) | Check::Fetch(_) => return Err(Close::Auth),
        };
        if grant.account != account {
            return Err(Close::Moved);
        }
        self.regrant(grant);
        Ok(())
    }

    /// Gives the client the permissions of `grant`, its account's, and
    /// ends the subscriptions they no longer allow.
    fn regrant(&mut self, grant: Grant) {
        let same = match (self.client.held.borrow().as_deref(), grant.perms.as_deref()) {
            (Some(h), Some(p)) => h.perms.rules() == p.rules(),
            (None, None) => true,
            _ => false,
        };
        if !same {
            let held = grant.perms.map(|p| Rc::new(Held::new(p)));
            let traced = self.client.traced.get();
            self.client.guarded.set(traced || held.is_some());
            *self.client.held.borrow_mut() = held;
        }
        self.drop_forbidden(true);
    }
}
