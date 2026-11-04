//! Who may connect, and the account each client gets.

use std::sync::Arc;
use std::time::Duration;

use data_encoding::{BASE64, BASE64URL_NOPAD};
use rustc_hash::FxHashMap;

use crate::perms::Perms;
use crate::{Login, Options};

/// The account id of `$G`, the global account.
pub(crate) const GLOBAL: u32 = 0;

/// The users and token clients must authenticate with.
#[derive(Debug, Clone)]
pub(crate) struct Auth {
    /// By user name: the password or its hash, and the account id.
    users: FxHashMap<String, (String, Grant)>,
    /// By public NKey.
    nkeys: FxHashMap<String, Grant>,
    /// For token clients.
    token_grant: Grant,
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
    /// Takes the credentials of `other` this has not.
    pub(crate) fn fill(&mut self, other: &Creds) {
        let blank = |f: &Option<String>| f.as_deref().is_none_or(str::is_empty);
        if blank(&self.user) {
            self.user.clone_from(&other.user);
        }
        if blank(&self.pass) {
            self.pass.clone_from(&other.pass);
        }
        if blank(&self.token) {
            self.token.clone_from(&other.token);
        }
    }

    const fn is_blank(&self) -> bool {
        self.user.is_none() && self.pass.is_none() && self.token.is_none() && self.nkey.is_none()
    }
}

/// What a client that authenticated gets: its account and permissions.
#[derive(Debug, Clone)]
pub(crate) struct Grant {
    pub(crate) account: u32,
    /// `None`: it may publish and subscribe to anything.
    pub(crate) perms: Option<Arc<Perms>>,
}

impl PartialEq for Grant {
    fn eq(&self, other: &Grant) -> bool {
        let same = match (&self.perms, &other.perms) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (a, b) => a.is_none() && b.is_none(),
        };
        self.account == other.account && same
    }
}

impl Eq for Grant {}

/// The outcome of checking credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Check {
    /// They hold.
    Pass(Grant),
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
    /// What the client gets if it holds.
    pub(crate) grant: Grant,
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
    if opts.user.is_some() && !opts.users.is_empty() {
        return Err("a single user cannot go with users".into());
    }
    if opts.user.is_some() && opts.token.is_some() {
        return Err("a token cannot go with a user".into());
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
    let Some(ws) = opts.websocket.as_ref().map(|w| &w.auth) else {
        return Ok(());
    };
    if ws.user.is_some() && ws.token.is_some() {
        return Err("websocket: a token cannot go with a user".into());
    }
    if let Some(n) = &ws.no_auth_user {
        if ws.user.is_some() || ws.token.is_some() {
            return Err("websocket: no_auth_user cannot go with a user or token of its own".into());
        }
        if !seen.contains(&n) {
            return Err(format!("websocket: no_auth_user {n:?} is not a user"));
        }
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
        if opts.users.is_empty() && opts.user.is_none() && opts.token.is_none() {
            return None;
        }
        let id = |name: Option<&String>| {
            name.and_then(|n| accounts.iter().position(|a| a == n))
                .map_or(GLOBAL, |i| i as u32)
        };
        let defaults = opts
            .default_permissions
            .as_ref()
            .map(|p| Arc::new(Perms::new(p)));
        let (mut users, mut nkeys) = (FxHashMap::default(), FxHashMap::default());
        for u in &opts.users {
            let grant = Grant {
                account: id(u.account.as_ref()),
                perms: u
                    .permissions
                    .as_ref()
                    .map(|p| Arc::new(Perms::new(p)))
                    .or_else(|| defaults.clone()),
            };
            match &u.login {
                Login::Password { user, password } => {
                    users.insert(user.clone(), (password.clone(), grant));
                }
                Login::Nkey(key) => {
                    nkeys.insert(key.clone(), grant);
                }
            }
        }
        // As in `nats-server`, the single user and token clients have no
        // permissions: defaults are for users of lists.
        let bare = Grant {
            account: GLOBAL,
            perms: None,
        };
        if let Some((user, password)) = &opts.user {
            users.insert(user.clone(), (password.clone(), bare.clone()));
        }
        Some(Auth {
            users,
            nkeys,
            token_grant: bare,
            token: opts.token.clone(),
            no_auth_user: opts.no_auth_user.clone(),
            timeout: opts.auth_timeout,
        })
    }

    /// What WebSocket clients authenticate with, where it is not
    /// `general`, the others': a user or token of their own, which stand
    /// alone, or their own `no_auth_user` or timeout.
    pub(crate) fn websocket(opts: &Options, general: Option<&Auth>) -> Option<Auth> {
        let ws = &opts.websocket.as_ref()?.auth;
        let timeout = ws.timeout.unwrap_or(opts.auth_timeout);
        if ws.user.is_some() || ws.token.is_some() {
            // As `nats-server`, without permissions: those come with users.
            let grant = Grant {
                account: GLOBAL,
                perms: None,
            };
            let users = ws
                .user
                .iter()
                .map(|(u, p)| (u.clone(), (p.clone(), grant.clone())));
            return Some(Auth {
                users: users.collect(),
                nkeys: FxHashMap::default(),
                token_grant: grant,
                token: ws.token.clone(),
                no_auth_user: None,
                timeout,
            });
        }
        if ws.no_auth_user.is_none() && ws.timeout.is_none() {
            return None;
        }
        let mut auth = general?.clone();
        if ws.no_auth_user.is_some() {
            auth.no_auth_user.clone_from(&ws.no_auth_user);
        }
        auth.timeout = timeout;
        Some(auth)
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
                .map(|(_, g)| g)
                .or_else(|| self.nkeys.get(u));
            return account.map_or(Check::Fail, |g| Check::Pass(g.clone()));
        }
        if let Some(key) = &c.nkey {
            return match self.nkeys.get(key) {
                Some(g) if signed(key, nonce, c.sig.as_deref()) => Check::Pass(g.clone()),
                _ => Check::Fail,
            };
        }
        let user = c.user.as_ref();
        if let Some(name) = user
            && let Some((secret, grant)) = self.users.get(name)
        {
            return compare(secret, c.pass.as_deref().unwrap_or_default(), grant);
        }
        match (&self.token, &c.token) {
            (Some(t), Some(given)) => compare(t, given, &self.token_grant),
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
fn compare(secret: &str, given: &str, grant: &Grant) -> Check {
    if is_bcrypt(secret) {
        return Check::Bcrypt(Pending {
            hash: secret.to_owned(),
            password: given.to_owned(),
            grant: grant.clone(),
        });
    }
    if same(secret.as_bytes(), given.as_bytes()) {
        Check::Pass(grant.clone())
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
    use crate::{Permissions, User};

    fn pass(account: u32) -> Check {
        Check::Pass(Grant {
            account,
            perms: None,
        })
    }

    fn user(name: &str, password: &str, account: Option<&str>) -> User {
        User {
            login: Login::Password {
                user: name.into(),
                password: password.into(),
            },
            account: account.map(Into::into),
            permissions: None,
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
            pass(1)
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
            pass(GLOBAL),
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
            pass(GLOBAL)
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
        assert_eq!(p.grant.account, GLOBAL);
        assert!(p.holds());
        let Check::Bcrypt(p) = auth.check(&creds(Some("b"), Some("nope"), None), b"") else {
            panic!("not deferred");
        };
        assert!(!p.holds());
        let broken = Pending {
            hash: "$2a$bad".into(),
            password: "pw".into(),
            grant: Grant {
                account: GLOBAL,
                perms: None,
            },
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
                permissions: None,
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
            pass(1)
        );
        assert_eq!(auth.check(&with(Some(BASE64.encode(&sig))), n), pass(1));
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
                permissions: None,
            }],
            no_auth_user: Some(PUBLIC.into()),
            ..Options::default()
        };
        validate(&opts).unwrap();
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        assert_eq!(auth.check(&Creds::default(), b"x"), pass(GLOBAL));
    }

    #[test]
    fn websocket_clients_may_log_in_otherwise() {
        let accounts = ["$G".to_owned()];
        let with = |ws: crate::WebsocketAuth| Options {
            users: vec![user("al", "pa", None), user("bo", "pb", None)],
            no_auth_user: Some("al".into()),
            auth_timeout: Duration::from_secs(5),
            websocket: Some(crate::Websocket {
                auth: ws,
                ..crate::Websocket::default()
            }),
            ..Options::default()
        };
        let none = with(crate::WebsocketAuth::default());
        assert!(Auth::websocket(&none, Auth::new(&none, &accounts).as_ref()).is_none());

        // A user of their own stands alone: the others' do not pass.
        let o = with(crate::WebsocketAuth {
            user: Some(("web".into(), "pw".into())),
            timeout: Some(Duration::from_secs(1)),
            ..crate::WebsocketAuth::default()
        });
        let ws = Auth::websocket(&o, Auth::new(&o, &accounts).as_ref()).unwrap();
        assert_eq!(
            ws.check(&creds(Some("web"), Some("pw"), None), b""),
            pass(0)
        );
        assert_eq!(
            ws.check(&creds(Some("al"), Some("pa"), None), b""),
            Check::Fail
        );
        assert_eq!(ws.check(&Creds::default(), b""), Check::Fail);
        assert_eq!(ws.timeout, Duration::from_secs(1));

        let o = with(crate::WebsocketAuth {
            token: Some("t".into()),
            ..crate::WebsocketAuth::default()
        });
        let ws = Auth::websocket(&o, None).unwrap();
        assert_eq!(ws.check(&creds(None, None, Some("t")), b""), pass(0));
        assert_eq!(ws.timeout, Duration::from_secs(5));

        // A no_auth_user of their own, among the same users.
        let o = with(crate::WebsocketAuth {
            no_auth_user: Some("bo".into()),
            ..crate::WebsocketAuth::default()
        });
        let general = Auth::new(&o, &accounts);
        let ws = Auth::websocket(&o, general.as_ref()).unwrap();
        assert_eq!(ws.no_auth_user.as_deref(), Some("bo"));
        assert_eq!(ws.check(&creds(Some("al"), Some("pa"), None), b""), pass(0));
        assert!(validate(&o).is_ok());

        // A timeout alone, where clients authenticate at all.
        let o = with(crate::WebsocketAuth {
            timeout: Some(Duration::from_secs(1)),
            ..crate::WebsocketAuth::default()
        });
        let ws = Auth::websocket(&o, Auth::new(&o, &accounts).as_ref()).unwrap();
        assert_eq!(
            (ws.timeout, ws.no_auth_user.as_deref()),
            (Duration::from_secs(1), Some("al"))
        );
        assert!(Auth::websocket(&o, None).is_none());
    }

    #[test]
    fn default_permissions_go_to_users_of_lists_only() {
        let accounts = ["$G".to_owned()];
        let defaults = Some(Permissions::default());
        let single = Options {
            user: Some(("u".into(), "p".into())),
            default_permissions: defaults.clone(),
            ..Options::default()
        };
        let auth = Auth::new(&single, &accounts).unwrap();
        assert_eq!(auth.check(&creds(Some("u"), Some("p"), None), b""), pass(0));
        let token = Options {
            token: Some("t".into()),
            default_permissions: defaults.clone(),
            ..Options::default()
        };
        let auth = Auth::new(&token, &accounts).unwrap();
        assert_eq!(auth.check(&creds(None, None, Some("t")), b""), pass(0));
        let listed = Options {
            users: vec![user("a", "p", None)],
            default_permissions: defaults,
            ..Options::default()
        };
        let auth = Auth::new(&listed, &accounts).unwrap();
        let Check::Pass(g) = auth.check(&creds(Some("a"), Some("p"), None), b"") else {
            panic!("a list user passes");
        };
        assert!(g.perms.is_some());
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
            Options {
                user: Some(("u".into(), "p".into())),
                users: vec![user("a", "p", None)],
                ..Options::default()
            },
            Options {
                user: Some(("u".into(), "p".into())),
                token: Some("t".into()),
                ..Options::default()
            },
        ];
        for o in &bad {
            assert!(validate(o).is_err(), "{o:?}");
        }
    }
}
