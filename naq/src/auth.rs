//! Who may connect, and the account each client gets.

use std::time::Duration;

use data_encoding::{BASE64, BASE64URL_NOPAD};
use rustc_hash::FxHashMap;

use crate::{Login, Options};

/// The account id of `$G`, the global account.
pub(crate) const GLOBAL: u32 = 0;

/// The users and token clients must authenticate with.
#[derive(Debug)]
pub(crate) struct Auth {
    /// By user name: the password or its hash, and the account id.
    users: FxHashMap<String, (String, u32)>,
    /// By public NKey: the account id.
    nkeys: FxHashMap<String, u32>,
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
    pub(crate) nkey: Option<String>,
    /// The nonce signed, in base64.
    pub(crate) sig: Option<String>,
}

impl Creds {
    const fn is_blank(&self) -> bool {
        self.user.is_none() && self.pass.is_none() && self.token.is_none() && self.nkey.is_none()
    }
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
        let user = name(&u.login);
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

/// What names a user: its user name or its NKey.
const fn name(login: &Login) -> &String {
    match login {
        Login::Password { user, .. } => user,
        Login::Nkey(key) => key,
    }
}

/// Whether `key` is a public user NKey.
pub(crate) fn is_user_nkey(key: &str) -> bool {
    key.starts_with('U') && nkeys::KeyPair::from_public_key(key).is_ok()
}

/// A fresh nonce for a client to sign: 11 random bytes in URL-safe base64.
pub(crate) fn nonce() -> String {
    let mut raw = [0u8; 11];
    // The OS failing to give randomness leaves the nonce all zeros: still
    // a nonce, but a guessable one. It does not happen on supported systems.
    let _ = getrandom::getrandom(&mut raw);
    BASE64URL_NOPAD.encode(&raw)
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
        let (mut users, mut nkeys) = (FxHashMap::default(), FxHashMap::default());
        for u in &opts.users {
            let account = id(u.account.as_ref());
            match &u.login {
                Login::Password { user, password } => {
                    users.insert(user.clone(), (password.clone(), account));
                }
                Login::Nkey(key) => {
                    nkeys.insert(key.clone(), account);
                }
            }
        }
        Some(Auth {
            users,
            nkeys,
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

    /// Whether clients get a nonce to sign: some users have NKeys.
    pub(crate) fn wants_nonce(&self) -> bool {
        !self.nkeys.is_empty()
    }

    /// Checks what a client gave, after an `INFO` with `nonce`.
    pub(crate) fn check(&self, c: &Creds, nonce: &[u8]) -> Check {
        if c.is_blank()
            && let Some(u) = &self.no_auth_user
        {
            // Known to exist: the options were validated.
            let account = self
                .users
                .get(u)
                .map(|(_, a)| a)
                .or_else(|| self.nkeys.get(u));
            return account.map_or(Check::Fail, |a| Check::Pass(*a));
        }
        if let Some(key) = &c.nkey {
            return match self.nkeys.get(key) {
                Some(a) if signed(key, nonce, c.sig.as_deref()) => Check::Pass(*a),
                _ => Check::Fail,
            };
        }
        let user = c.user.as_ref();
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

/// Whether `sig` is `nonce` signed with the seed of public NKey `key`.
fn signed(key: &str, nonce: &[u8], sig: Option<&str>) -> bool {
    let Some(sig) = sig else {
        return false;
    };
    let Ok(sig) = BASE64URL_NOPAD
        .decode(sig.as_bytes())
        .or_else(|_| BASE64.decode(sig.as_bytes()))
    else {
        return false;
    };
    nkeys::KeyPair::from_public_key(key).is_ok_and(|k| k.verify(nonce, &sig).is_ok())
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
            ..Creds::default()
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
            auth.check(&creds(Some("a"), Some("pa"), None), b""),
            Check::Pass(1)
        );
        assert_eq!(
            auth.check(&creds(Some("a"), Some("pg"), None), b""),
            Check::Fail
        );
        assert_eq!(
            auth.check(&creds(Some("x"), Some("pa"), None), b""),
            Check::Fail
        );
        assert_eq!(
            auth.check(&creds(None, None, None), b""),
            Check::Pass(GLOBAL),
            "no_auth_user"
        );
        assert_eq!(auth.check(&creds(None, Some("pa"), None), b""), Check::Fail);
        assert_eq!(auth.check(&creds(None, None, Some("t")), b""), Check::Fail);
    }

    #[test]
    fn a_token_passes_into_the_global_account() {
        let opts = Options {
            token: Some("s3cret".into()),
            ..Options::default()
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        assert_eq!(
            auth.check(&creds(None, None, Some("s3cret")), b""),
            Check::Pass(GLOBAL)
        );
        assert_eq!(
            auth.check(&creds(None, None, Some("s3cre")), b""),
            Check::Fail
        );
        assert_eq!(auth.check(&creds(None, None, None), b""), Check::Fail);
    }

    #[test]
    fn bcrypt_hashes_are_compared_off_the_lane() {
        let hash = bcrypt::hash("pw", 4).unwrap();
        let opts = Options {
            users: vec![user("b", &hash, None)],
            ..Options::default()
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        let Check::Bcrypt(p) = auth.check(&creds(Some("b"), Some("pw"), None), b"") else {
            panic!("not deferred");
        };
        assert_eq!(p.account, GLOBAL);
        assert!(p.holds());
        let Check::Bcrypt(p) = auth.check(&creds(Some("b"), Some("nope"), None), b"") else {
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

    /// A user NKey made for these tests: its seed and public key.
    const SEED: &str = "SUABXPISJ672XCVCU7XD7CVTTXYTBXTGZ4LX3WZCSLCPKHDPCXCLZVMVPI";
    const PUBLIC: &str = "UDDERIQLR7DRZ5U2RYQVMHORTX3VOIBJNN7PBBMML2L4TIQKHZDVQERZ";

    #[test]
    fn an_nkey_user_passes_with_the_nonce_signed() {
        let opts = Options {
            accounts: vec!["A".into()],
            users: vec![User {
                login: Login::Nkey(PUBLIC.into()),
                account: Some("A".into()),
            }],
            ..Options::default()
        };
        validate(&opts).unwrap();
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        assert!(auth.wants_nonce());
        let nonce = nonce();
        assert_eq!(nonce.len(), 15);
        let sig = nkeys::KeyPair::from_seed(SEED)
            .unwrap()
            .sign(nonce.as_bytes())
            .unwrap();
        let with = |sig: Option<String>| Creds {
            nkey: Some(PUBLIC.into()),
            sig,
            ..Creds::default()
        };
        let n = nonce.as_bytes();
        assert_eq!(
            auth.check(&with(Some(BASE64URL_NOPAD.encode(&sig))), n),
            Check::Pass(1)
        );
        assert_eq!(
            auth.check(&with(Some(BASE64.encode(&sig))), n),
            Check::Pass(1)
        );
        assert_eq!(
            auth.check(&with(Some(BASE64URL_NOPAD.encode(&sig))), b"other"),
            Check::Fail
        );
        assert_eq!(auth.check(&with(None), n), Check::Fail);
        assert_eq!(auth.check(&with(Some("!!".into())), n), Check::Fail);
        let stranger = Creds {
            nkey: Some("UNKNOWN".into()),
            ..with(None)
        };
        assert_eq!(auth.check(&stranger, n), Check::Fail);
        assert!(is_user_nkey(PUBLIC));
        assert!(!is_user_nkey(SEED));
        assert!(!is_user_nkey("UABC"));
    }

    #[test]
    fn an_nkey_no_auth_user_needs_no_signature() {
        let opts = Options {
            users: vec![User {
                login: Login::Nkey(PUBLIC.into()),
                account: None,
            }],
            no_auth_user: Some(PUBLIC.into()),
            ..Options::default()
        };
        validate(&opts).unwrap();
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        assert_eq!(auth.check(&Creds::default(), b"x"), Check::Pass(GLOBAL));
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
