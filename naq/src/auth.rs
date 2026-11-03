//! Who may connect, and the account each client gets.

use std::time::Duration;

use rustc_hash::FxHashMap;

use crate::{Login, Options};

/// The account id of `$G`, the global account.
pub(crate) const GLOBAL: u32 = 0;

/// The users and token clients must authenticate with.
#[derive(Debug)]
pub(crate) struct Auth {
    /// By user name: the password or its hash, and the account id.
    users: FxHashMap<String, (String, u32)>,
    token: Option<String>,
    no_auth_user: Option<String>,
    /// How long a client has to authenticate.
    pub(crate) timeout: Duration,
}

/// What a client gave in its `CONNECT`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Creds {
    pub(crate) user: Option<String>,
    pub(crate) pass: Option<String>,
    pub(crate) token: Option<String>,
}

/// The outcome of checking credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Check {
    /// They hold, for this account.
    Pass(u32),
    /// They do not.
    Fail,
    /// They hold if a bcrypt comparison does.
    Bcrypt(Pending),
}

/// A bcrypt comparison still to make: slow by design, so not on a lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pending {
    hash: String,
    password: String,
    /// The account the client gets if it holds.
    pub(crate) account: u32,
}

impl Pending {
    /// Whether the password matches the hash.
    pub(crate) fn holds(&self) -> bool {
        bcrypt::verify(&self.password, &self.hash).unwrap_or(false)
    }
}

/// Account names by id: `$G` first, then those of `opts`.
pub(crate) fn accounts(opts: &Options) -> Box<[String]> {
    std::iter::once("$G".to_owned())
        .chain(opts.accounts.iter().cloned())
        .collect()
}

/// Why `opts` cannot run as given.
pub(crate) fn validate(opts: &Options) -> Result<(), String> {
    if opts.token.is_some() && !opts.users.is_empty() {
        return Err("a token cannot go with users".into());
    }
    let mut seen = Vec::new();
    for u in &opts.users {
        let Login::Password { user, .. } = &u.login;
        if seen.contains(&user) {
            return Err(format!("user {user:?} twice"));
        }
        seen.push(user);
        if let Some(a) = &u.account
            && !opts.accounts.contains(a)
        {
            return Err(format!("user {user:?}: no account {a:?}"));
        }
    }
    if let Some(n) = &opts.no_auth_user
        && !seen.contains(&n)
    {
        return Err(format!("no_auth_user {n:?} is not a user"));
    }
    Ok(())
}

impl Auth {
    /// The authentication `opts` ask for, if any. `opts` are valid.
    pub(crate) fn new(opts: &Options, accounts: &[String]) -> Option<Auth> {
        if opts.users.is_empty() && opts.token.is_none() {
            return None;
        }
        let id = |name: Option<&String>| {
            name.and_then(|n| accounts.iter().position(|a| a == n))
                .map_or(GLOBAL, |i| i as u32)
        };
        let users = opts
            .users
            .iter()
            .map(|u| {
                let Login::Password { user, password } = &u.login;
                (user.clone(), (password.clone(), id(u.account.as_ref())))
            })
            .collect();
        Some(Auth {
            users,
            token: opts.token.clone(),
            no_auth_user: opts.no_auth_user.clone(),
            timeout: opts.auth_timeout,
        })
    }

    /// Whether clients may connect without credentials, as the
    /// `no_auth_user`.
    pub(crate) const fn open(&self) -> bool {
        self.no_auth_user.is_some()
    }

    /// Checks what a client gave.
    pub(crate) fn check(&self, c: &Creds) -> Check {
        let blank = c.user.is_none() && c.pass.is_none() && c.token.is_none();
        let user = match (&c.user, &self.no_auth_user) {
            (Some(u), _) => Some(u),
            (None, Some(u)) if blank => {
                // Known to exist: the options were validated.
                return self
                    .users
                    .get(u)
                    .map_or(Check::Fail, |(_, a)| Check::Pass(*a));
            }
            (None, _) => None,
        };
        if let Some(name) = user
            && let Some((secret, account)) = self.users.get(name)
        {
            return compare(secret, c.pass.as_deref().unwrap_or_default(), *account);
        }
        match (&self.token, &c.token) {
            (Some(t), Some(given)) => compare(t, given, GLOBAL),
            _ => Check::Fail,
        }
    }
}

/// Compares what a client gave with `secret`, plain or a bcrypt hash.
fn compare(secret: &str, given: &str, account: u32) -> Check {
    if is_bcrypt(secret) {
        return Check::Bcrypt(Pending {
            hash: secret.to_owned(),
            password: given.to_owned(),
            account,
        });
    }
    if same(secret.as_bytes(), given.as_bytes()) {
        Check::Pass(account)
    } else {
        Check::Fail
    }
}

fn is_bcrypt(s: &str) -> bool {
    ["$2a$", "$2b$", "$2x$", "$2y$"]
        .iter()
        .any(|p| s.starts_with(p))
}

/// Whether `a` and `b` are equal, in a time that does not tell where they
/// differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::User;

    fn user(name: &str, password: &str, account: Option<&str>) -> User {
        User {
            login: Login::Password {
                user: name.into(),
                password: password.into(),
            },
            account: account.map(Into::into),
        }
    }

    fn creds(user: Option<&str>, pass: Option<&str>, token: Option<&str>) -> Creds {
        Creds {
            user: user.map(Into::into),
            pass: pass.map(Into::into),
            token: token.map(Into::into),
        }
    }

    #[test]
    fn users_pass_into_their_account_with_the_right_password() {
        let opts = Options {
            accounts: vec!["A".into()],
            users: vec![user("a", "pa", Some("A")), user("g", "pg", None)],
            no_auth_user: Some("g".into()),
            ..Options::default()
        };
        validate(&opts).unwrap();
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        assert_eq!(
            auth.check(&creds(Some("a"), Some("pa"), None)),
            Check::Pass(1)
        );
        assert_eq!(auth.check(&creds(Some("a"), Some("pg"), None)), Check::Fail);
        assert_eq!(auth.check(&creds(Some("x"), Some("pa"), None)), Check::Fail);
        assert_eq!(
            auth.check(&creds(None, None, None)),
            Check::Pass(GLOBAL),
            "no_auth_user"
        );
        assert_eq!(auth.check(&creds(None, Some("pa"), None)), Check::Fail);
        assert_eq!(auth.check(&creds(None, None, Some("t"))), Check::Fail);
    }

    #[test]
    fn a_token_passes_into_the_global_account() {
        let opts = Options {
            token: Some("s3cret".into()),
            ..Options::default()
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        assert_eq!(
            auth.check(&creds(None, None, Some("s3cret"))),
            Check::Pass(GLOBAL)
        );
        assert_eq!(auth.check(&creds(None, None, Some("s3cre"))), Check::Fail);
        assert_eq!(auth.check(&creds(None, None, None)), Check::Fail);
    }

    #[test]
    fn bcrypt_hashes_are_compared_off_the_lane() {
        let hash = bcrypt::hash("pw", 4).unwrap();
        let opts = Options {
            users: vec![user("b", &hash, None)],
            ..Options::default()
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        let Check::Bcrypt(p) = auth.check(&creds(Some("b"), Some("pw"), None)) else {
            panic!("not deferred");
        };
        assert_eq!(p.account, GLOBAL);
        assert!(p.holds());
        let Check::Bcrypt(p) = auth.check(&creds(Some("b"), Some("nope"), None)) else {
            panic!("not deferred");
        };
        assert!(!p.holds());
        let broken = Pending {
            hash: "$2a$bad".into(),
            password: "pw".into(),
            account: GLOBAL,
        };
        assert!(!broken.holds());
    }

    #[test]
    fn no_auth_means_no_check() {
        assert!(Auth::new(&Options::default(), &["$G".into()]).is_none());
    }

    #[test]
    fn options_that_contradict_themselves_are_refused() {
        let bad = [
            Options {
                token: Some("t".into()),
                users: vec![user("a", "p", None)],
                ..Options::default()
            },
            Options {
                users: vec![user("a", "p", None), user("a", "q", None)],
                ..Options::default()
            },
            Options {
                users: vec![user("a", "p", Some("B"))],
                ..Options::default()
            },
            Options {
                users: vec![user("a", "p", None)],
                no_auth_user: Some("b".into()),
                ..Options::default()
            },
        ];
        for o in &bad {
            assert!(validate(o).is_err(), "{o:?}");
        }
    }
}
