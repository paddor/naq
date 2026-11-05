//! Who may connect, and the account each client gets.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use data_encoding::{BASE64, BASE64URL_NOPAD};
use rustc_hash::FxHashMap;

use crate::perms::Perms;
use crate::tls::cert::Names;
use crate::tls::dn::Dn;
use crate::{ConnectionType, Login, Options};

/// The account id of `$G`, the global account.
pub(crate) const GLOBAL: u32 = 0;

/// The users and token clients must authenticate with.
#[derive(Debug, Clone)]
pub(crate) struct Auth {
    /// By user name: the password or its hash, and what it gets.
    users: FxHashMap<String, (String, Listed)>,
    /// By public NKey.
    nkeys: FxHashMap<String, Listed>,
    /// The users whose names are DNs, for certificates to name.
    dns: Vec<(Dn, String)>,
    /// The users come in a list, not alone: certificates name them, where
    /// a listener maps certificates to users.
    listed: bool,
    /// For token clients.
    token_grant: Grant,
    token: Option<String>,
    no_auth_user: Option<String>,
    /// In operator mode: who signs the accounts and users.
    trust: Option<Arc<crate::jwt::trust::Trust>>,
    /// How long a client has to authenticate.
    pub(crate) timeout: Duration,
}

/// A user of a list: what it gets, and how it may log in.
#[derive(Debug, Clone)]
struct Listed {
    grant: Grant,
    /// The kinds of connection it may log in over.
    kinds: Kinds,
    /// It has no password and a listener maps certificates to it: it
    /// logs in with its certificate only.
    cert_only: bool,
}

/// Kinds of connection, as a set; none at all is any.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Kinds(u8);

impl Kinds {
    fn of(types: &[ConnectionType]) -> Kinds {
        Kinds(types.iter().fold(0, |k, &t| k | Kinds::bit(t)))
    }

    const fn bit(t: ConnectionType) -> u8 {
        1 << t as u8
    }

    const fn allows(self, t: ConnectionType) -> bool {
        self.0 == 0 || self.0 & Kinds::bit(t) != 0
    }
}

/// How a client connects, for the checks that depend on it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Origin<'a> {
    /// Its address, if known.
    pub(crate) ip: Option<IpAddr>,
    pub(crate) kind: ConnectionType,
    /// What its certificate names, where its listener maps certificates
    /// to users (`verify_and_map`).
    pub(crate) cert: Option<&'a Names>,
}

impl Origin<'_> {
    /// A client of kind `kind`, from nowhere known.
    pub(crate) const fn of(kind: ConnectionType) -> Origin<'static> {
        Origin {
            ip: None,
            kind,
            cert: None,
        }
    }
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
    /// A user JWT, in operator mode.
    pub(crate) jwt: Option<String>,
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
        self.user.is_none()
            && self.pass.is_none()
            && self.token.is_none()
            && self.nkey.is_none()
            && self.jwt.is_none()
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
    /// A user JWT holds: its user.
    User(Box<crate::jwt::trust::User>),
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

#[cfg(test)]
impl Pending {
    /// A comparison that never holds, of a user that gets `grant`.
    pub(crate) const fn for_tests(grant: Grant) -> Pending {
        Pending {
            hash: String::new(),
            password: String::new(),
            grant,
        }
    }
}

/// The name of the system account `nats-server` makes.
pub(crate) const SYSTEM: &str = "$SYS";

/// Account names by id: `$G` first, then those of `opts`, then those of
/// the JWTs preloaded, by public key, then `$SYS` if the server makes it.
pub(crate) fn accounts(opts: &Options) -> Box<[String]> {
    let made = system_name(opts).is_none()
        && !opts.no_system_account
        && !opts.accounts.iter().any(|a| a.name == SYSTEM);
    std::iter::once("$G".to_owned())
        .chain(opts.accounts.iter().map(|a| a.name.clone()))
        .chain(opts.resolver_preload.iter().map(|(key, _)| key.clone()))
        .chain(made.then(|| SYSTEM.to_owned()))
        .collect()
}

/// The system account `opts` or their operator JWT name, if any.
fn system_name(opts: &Options) -> Option<String> {
    opts.system_account
        .clone()
        .or_else(|| crate::jwt::trust::system_account(opts))
}

/// The id of the system account among `names`, the server's accounts, if
/// it has one.
pub(crate) fn system(opts: &Options, names: &[String]) -> Option<u32> {
    let chosen = system_name(opts);
    let name = match &chosen {
        Some(n) => n.as_str(),
        None if opts.no_system_account && !opts.accounts.iter().any(|a| a.name == SYSTEM) => {
            return None;
        }
        None => SYSTEM,
    };
    // Accounts are few: their count fits.
    names.iter().position(|n| n == name).map(|i| i as u32)
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
            && !opts.accounts.iter().any(|x| x.name == *a)
        {
            return Err(format!("user {user:?}: no account {a:?}"));
        }
    }
    if let Some(n) = &opts.no_auth_user
        && !seen.contains(&n)
    {
        return Err(format!("no_auth_user {n:?} is not a user"));
    }
    crate::jwt::trust::validate(opts)?;
    crate::callout::validate(opts)?;
    if let Some(a) = system_name(opts)
        && !accounts(opts).contains(&a)
    {
        return Err(format!("system_account: no account {a:?}"));
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
    /// Nobody known yet, and clients have `timeout` to log in.
    fn empty(timeout: Duration) -> Auth {
        Auth {
            users: FxHashMap::default(),
            nkeys: FxHashMap::default(),
            dns: Vec::new(),
            listed: false,
            token_grant: Grant {
                account: GLOBAL,
                perms: None,
            },
            token: None,
            no_auth_user: None,
            trust: None,
            timeout,
        }
    }

    /// The authentication `opts` ask for, if any. `opts` are valid.
    pub(crate) fn new(opts: &Options, accounts: &[String]) -> Option<Auth> {
        if let Some(t) = crate::jwt::trust::Trust::new(opts, accounts) {
            return Some(Auth {
                trust: Some(Arc::new(t)),
                ..Auth::empty(opts.auth_timeout)
            });
        }
        if opts.users.is_empty() && opts.user.is_none() && opts.token.is_none() {
            return None;
        }
        let mut auth = Auth {
            token: opts.token.clone(),
            no_auth_user: opts.no_auth_user.clone(),
            ..Auth::empty(opts.auth_timeout)
        };
        auth.list(opts, accounts);
        // As in `nats-server`, the single user and token clients have no
        // permissions: defaults are for users of lists.
        if let Some((user, password)) = &opts.user {
            let alone = Listed {
                grant: auth.token_grant.clone(),
                kinds: Kinds::default(),
                cert_only: false,
            };
            auth.users.insert(user.clone(), (password.clone(), alone));
        }
        Some(auth)
    }

    /// Takes in the users `opts` list, into their accounts among
    /// `accounts`.
    fn list(&mut self, opts: &Options, accounts: &[String]) {
        let defaults = opts
            .default_permissions
            .as_ref()
            .map(|p| Arc::new(Perms::new(p)));
        let maps = (
            opts.tls.as_ref().is_some_and(|t| t.map),
            opts.websocket
                .as_ref()
                .and_then(|w| w.tls.as_ref())
                .is_some_and(|t| t.map),
        );
        for u in &opts.users {
            let grant = Grant {
                account: id(accounts, u.account.as_ref()),
                perms: u
                    .permissions
                    .as_ref()
                    .map(|p| Arc::new(Perms::new(p)))
                    .or_else(|| defaults.clone()),
            };
            let kinds = Kinds::of(&u.connection_types);
            match &u.login {
                Login::Password { user, password } => {
                    let cert_only = password.is_empty()
                        && self.no_auth_user.as_ref() != Some(user)
                        && ((maps.0 && kinds.allows(ConnectionType::Standard))
                            || (maps.1 && kinds.allows(ConnectionType::Websocket)));
                    if let Some(dn) = Dn::parse(user) {
                        self.dns.push((dn, user.clone()));
                    }
                    let l = Listed {
                        grant,
                        kinds,
                        cert_only,
                    };
                    self.users.insert(user.clone(), (password.clone(), l));
                    self.listed = true;
                }
                Login::Nkey(key) => {
                    let l = Listed {
                        grant,
                        kinds,
                        cert_only: false,
                    };
                    self.nkeys.insert(key.clone(), l);
                }
            }
        }
    }

    /// What WebSocket clients authenticate with, where it is not
    /// `general`, the others': a user or token of their own, which stand
    /// alone, or their own `no_auth_user` or timeout.
    pub(crate) fn websocket(opts: &Options, general: Option<&Auth>) -> Option<Auth> {
        let ws = &opts.websocket.as_ref()?.auth;
        let timeout = ws.timeout.unwrap_or(opts.auth_timeout);
        if ws.user.is_some() || ws.token.is_some() {
            // As `nats-server`, without permissions: those come with users.
            let mut auth = Auth {
                token: ws.token.clone(),
                ..Auth::empty(timeout)
            };
            if let Some((u, p)) = &ws.user {
                let alone = Listed {
                    grant: auth.token_grant.clone(),
                    kinds: Kinds::default(),
                    cert_only: false,
                };
                auth.users.insert(u.clone(), (p.clone(), alone));
            }
            return Some(auth);
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

    /// What naq leafs log in with, by `opts.leafnodes`: its users, into
    /// their accounts without permissions; else what clients log in with,
    /// `general`. `None`: any leaf links.
    pub(crate) fn leafnodes(
        opts: &Options,
        accounts: &crate::accounts::Accounts,
        general: Option<&Auth>,
    ) -> Option<Auth> {
        let l = opts.leafnodes.as_ref()?;
        if l.users.is_empty() {
            let mut auth = general?.clone();
            auth.timeout = l.auth_timeout;
            return Some(auth);
        }
        let mut auth = Auth::empty(l.auth_timeout);
        for u in &l.users {
            let listed = Listed {
                grant: Grant {
                    account: u
                        .account
                        .as_deref()
                        .and_then(|n| accounts.id(n))
                        .unwrap_or(GLOBAL),
                    perms: None,
                },
                kinds: Kinds::default(),
                cert_only: false,
            };
            match &u.login {
                Login::Password { user, password } => {
                    auth.users.insert(user.clone(), (password.clone(), listed));
                }
                Login::Nkey(key) => {
                    auth.nkeys.insert(key.clone(), listed);
                }
            }
        }
        Some(auth)
    }

    /// The operator mode users log in under, if any.
    pub(crate) fn trust(&self) -> Option<&crate::jwt::trust::Trust> {
        self.trust.as_deref()
    }

    /// Whom credentials `c` name, before any secret is checked, as
    /// `nats-server` tells auth callout users: a configured NKey, the
    /// `no_auth_user` for none, or a configured user name.
    pub(crate) fn id_of<'a>(&'a self, c: &'a Creds) -> Option<&'a str> {
        if !self.nkeys.is_empty()
            && let Some(key) = &c.nkey
        {
            return self.nkeys.contains_key(key).then_some(key.as_str());
        }
        if c.is_blank() {
            return self.no_auth_user.as_deref();
        }
        c.user.as_deref().filter(|u| self.users.contains_key(*u))
    }

    /// Credentials `c` as `nats-server` fills them in for none: those of
    /// the `no_auth_user`.
    pub(crate) fn fill_free(&self, c: &mut Creds) {
        let Some(u) = self.no_auth_user.as_ref().filter(|_| c.is_blank()) else {
            return;
        };
        if self.nkeys.contains_key(u) {
            c.nkey = Some(u.clone());
        } else if let Some((pass, _)) = self.users.get(u) {
            c.user = Some(u.clone());
            c.pass = Some(pass.clone());
        }
    }

    /// Whether clients may connect without credentials, as the
    /// `no_auth_user`.
    pub(crate) const fn open(&self) -> bool {
        self.no_auth_user.is_some()
    }

    /// Whether clients get a nonce to sign: some users have NKeys, or
    /// they log in with JWTs.
    pub(crate) fn wants_nonce(&self) -> bool {
        !self.nkeys.is_empty() || self.trust.is_some()
    }

    /// Checks what a client that connects as `origin` gave, after an
    /// `INFO` with `nonce`: in operator mode, its user JWT. The user its
    /// certificate names becomes its user, as in `nats-server`.
    pub(crate) fn check(&self, c: &mut Creds, nonce: &[u8], origin: Origin<'_>) -> Check {
        if let Some(t) = &self.trust {
            let user = c
                .jwt
                .as_deref()
                .and_then(|jwt| t.login(jwt, c.sig.as_deref(), nonce, origin));
            return user.map_or(Check::Fail, |u| Check::User(Box::new(u)));
        }
        let free = self.no_auth_user.as_ref().filter(|_| c.is_blank());
        // NKeys first, where there are any, as `nats-server` takes them.
        let key = c
            .nkey
            .as_ref()
            .or_else(|| free.filter(|u| self.nkeys.contains_key(*u)));
        if !self.nkeys.is_empty()
            && let Some(key) = key
        {
            let Some(l) = self.nkeys.get(key).filter(|l| l.kinds.allows(origin.kind)) else {
                return Check::Fail;
            };
            // The `no_auth_user` signs nothing.
            let free = self.no_auth_user.as_ref() == Some(key);
            return if free || signed(key, nonce, c.sig.as_deref()) {
                Check::Pass(l.grant.clone())
            } else {
                Check::Fail
            };
        }
        if self.listed
            && let Some(names) = origin.cert
        {
            return self.mapped(c, names, origin.kind);
        }
        if let Some(name) = free.or(c.user.as_ref())
            && let Some((secret, l)) = self.users.get(name)
        {
            if !l.kinds.allows(origin.kind) || l.cert_only {
                return Check::Fail;
            }
            if free.is_some() {
                return Check::Pass(l.grant.clone());
            }
            return compare(secret, c.pass.as_deref().unwrap_or_default(), &l.grant);
        }
        match (&self.token, &c.token) {
            (Some(t), Some(given)) => compare(t, given, &self.token_grant),
            _ => Check::Fail,
        }
    }

    /// The login of the user certificate `names` names, over a connection
    /// of kind `kind`: with its password, if it has one.
    fn mapped(&self, c: &mut Creds, names: &Names, kind: ConnectionType) -> Check {
        let known = |u: &str| self.users.get(u).is_some_and(|(_, l)| l.kinds.allows(kind));
        let user = names.user(known, &self.dns);
        let Some((name, (secret, l))) = user.and_then(|u| self.users.get_key_value(&u)) else {
            return Check::Fail;
        };
        c.user = Some(name.clone());
        compare(secret, c.pass.as_deref().unwrap_or_default(), &l.grant)
    }
}

/// The id of account `name` among `accounts`; `$G` for none.
fn id(accounts: &[String], name: Option<&String>) -> u32 {
    name.and_then(|n| accounts.iter().position(|a| a == n))
        // Accounts are few: their count fits.
        .map_or(GLOBAL, |i| i as u32)
}

/// Whether `sig` is `nonce` signed with the seed of public NKey `key`.
pub(crate) fn signed(key: &str, nonce: &[u8], sig: Option<&str>) -> bool {
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
            connection_types: Vec::new(),
        }
    }

    /// What `auth` makes of `c` from a plain client.
    fn check(auth: &Auth, c: &Creds, nonce: &[u8]) -> Check {
        auth.check(&mut c.clone(), nonce, Origin::of(ConnectionType::Standard))
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
            check(&auth, &creds(Some("a"), Some("pa"), None), b""),
            pass(1)
        );
        assert_eq!(
            check(&auth, &creds(Some("a"), Some("pg"), None), b""),
            Check::Fail
        );
        assert_eq!(
            check(&auth, &creds(Some("x"), Some("pa"), None), b""),
            Check::Fail
        );
        assert_eq!(
            check(&auth, &creds(None, None, None), b""),
            pass(GLOBAL),
            "no_auth_user"
        );
        assert_eq!(
            check(&auth, &creds(None, Some("pa"), None), b""),
            Check::Fail
        );
        assert_eq!(
            check(&auth, &creds(None, None, Some("t")), b""),
            Check::Fail
        );
    }

    #[test]
    fn a_token_passes_into_the_global_account() {
        let opts = Options {
            token: Some("s3cret".into()),
            ..Options::default()
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        assert_eq!(
            check(&auth, &creds(None, None, Some("s3cret")), b""),
            pass(GLOBAL)
        );
        assert_eq!(
            check(&auth, &creds(None, None, Some("s3cre")), b""),
            Check::Fail
        );
        assert_eq!(check(&auth, &creds(None, None, None), b""), Check::Fail);
    }

    #[test]
    fn bcrypt_hashes_are_compared_off_the_lane() {
        let hash = bcrypt::hash("pw", 4).unwrap();
        let opts = Options {
            users: vec![user("b", &hash, None)],
            ..Options::default()
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        let Check::Bcrypt(p) = check(&auth, &creds(Some("b"), Some("pw"), None), b"") else {
            panic!("not deferred");
        };
        assert_eq!(p.grant.account, GLOBAL);
        assert!(p.holds());
        let Check::Bcrypt(p) = check(&auth, &creds(Some("b"), Some("nope"), None), b"") else {
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
                connection_types: Vec::new(),
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
            check(&auth, &with(Some(BASE64URL_NOPAD.encode(&sig))), n),
            pass(1)
        );
        assert_eq!(check(&auth, &with(Some(BASE64.encode(&sig))), n), pass(1));
        assert_eq!(
            check(&auth, &with(Some(BASE64URL_NOPAD.encode(&sig))), b"other"),
            Check::Fail
        );
        assert_eq!(check(&auth, &with(None), n), Check::Fail);
        assert_eq!(check(&auth, &with(Some("!!".into())), n), Check::Fail);
        let stranger = Creds {
            nkey: Some("UNKNOWN".into()),
            ..with(None)
        };
        assert_eq!(check(&auth, &stranger, n), Check::Fail);
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
                connection_types: Vec::new(),
            }],
            no_auth_user: Some(PUBLIC.into()),
            ..Options::default()
        };
        validate(&opts).unwrap();
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        assert_eq!(check(&auth, &Creds::default(), b"x"), pass(GLOBAL));
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
            check(&ws, &creds(Some("web"), Some("pw"), None), b""),
            pass(0)
        );
        assert_eq!(
            check(&ws, &creds(Some("al"), Some("pa"), None), b""),
            Check::Fail
        );
        assert_eq!(check(&ws, &Creds::default(), b""), Check::Fail);
        assert_eq!(ws.timeout, Duration::from_secs(1));

        let o = with(crate::WebsocketAuth {
            token: Some("t".into()),
            ..crate::WebsocketAuth::default()
        });
        let ws = Auth::websocket(&o, None).unwrap();
        assert_eq!(check(&ws, &creds(None, None, Some("t")), b""), pass(0));
        assert_eq!(ws.timeout, Duration::from_secs(5));

        // A no_auth_user of their own, among the same users.
        let o = with(crate::WebsocketAuth {
            no_auth_user: Some("bo".into()),
            ..crate::WebsocketAuth::default()
        });
        let general = Auth::new(&o, &accounts);
        let ws = Auth::websocket(&o, general.as_ref()).unwrap();
        assert_eq!(ws.no_auth_user.as_deref(), Some("bo"));
        assert_eq!(
            check(&ws, &creds(Some("al"), Some("pa"), None), b""),
            pass(0)
        );
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
        assert_eq!(
            check(&auth, &creds(Some("u"), Some("p"), None), b""),
            pass(0)
        );
        let token = Options {
            token: Some("t".into()),
            default_permissions: defaults.clone(),
            ..Options::default()
        };
        let auth = Auth::new(&token, &accounts).unwrap();
        assert_eq!(check(&auth, &creds(None, None, Some("t")), b""), pass(0));
        let listed = Options {
            users: vec![user("a", "p", None)],
            default_permissions: defaults,
            ..Options::default()
        };
        let auth = Auth::new(&listed, &accounts).unwrap();
        let Check::Pass(g) = check(&auth, &creds(Some("a"), Some("p"), None), b"") else {
            panic!("a list user passes");
        };
        assert!(g.perms.is_some());
    }

    /// The names of a certificate of common name `cn`.
    fn names_of(cn: &str) -> Names {
        let mut p = rcgen::CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().unwrap();
        Names::of(p.self_signed(&key).unwrap().der())
    }

    /// Options with a client listener that maps certificates, and `users`.
    fn mapping(users: Vec<User>) -> Options {
        Options {
            tls: Some(crate::Tls {
                cert_file: "c".into(),
                key_file: "k".into(),
                ca_file: Some("ca".into()),
                verify: true,
                map: true,
                timeout: Duration::from_secs(1),
                handshake_first: false,
                fallback: None,
            }),
            users,
            ..Options::default()
        }
    }

    #[test]
    fn a_certificate_names_the_user_where_its_listener_maps_them() {
        let opts = mapping(vec![
            user("CN=alice", "", Some("A")),
            user("bob", "p", None),
        ]);
        let opts = Options {
            accounts: vec!["A".into()],
            ..opts
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        let alice = names_of("alice");
        let mapped = |c: &mut Creds, n: &Names| {
            let origin = Origin {
                cert: Some(n),
                ..Origin::of(ConnectionType::Standard)
            };
            auth.check(c, b"", origin)
        };
        let mut c = creds(Some("bob"), None, None);
        assert_eq!(mapped(&mut c, &alice), pass(1), "the certificate wins");
        assert_eq!(c.user.as_deref(), Some("CN=alice"));
        let mut c = creds(Some("bob"), Some("p"), None);
        assert_eq!(mapped(&mut c, &alice), Check::Fail, "a password it has not");
        let mut c = creds(Some("bob"), Some("p"), None);
        assert_eq!(mapped(&mut c, &names_of("bob")), Check::Fail);
        assert_eq!(
            mapped(&mut Creds::default(), &Names::default()),
            Check::Fail
        );
        // Elsewhere, a user certificates name logs in with them only.
        assert_eq!(
            check(&auth, &creds(Some("CN=alice"), None, None), b""),
            Check::Fail
        );
        assert_eq!(
            check(&auth, &creds(Some("bob"), Some("p"), None), b""),
            pass(0)
        );
    }

    #[test]
    fn the_no_auth_user_needs_no_certificate() {
        let mut opts = mapping(vec![user("CN=alice", "", None)]);
        opts.no_auth_user = Some("CN=alice".into());
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        assert_eq!(check(&auth, &Creds::default(), b""), pass(0));
        assert_eq!(
            check(&auth, &creds(Some("CN=alice"), None, None), b""),
            pass(0)
        );
    }

    #[test]
    fn users_log_in_over_the_kinds_of_connection_they_may() {
        let ws_only = vec![ConnectionType::Websocket];
        let opts = Options {
            users: vec![
                User {
                    connection_types: ws_only.clone(),
                    ..user("w", "p", None)
                },
                User {
                    login: Login::Nkey(PUBLIC.into()),
                    account: None,
                    permissions: None,
                    connection_types: ws_only,
                },
            ],
            ..Options::default()
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        let as_ws =
            |c: &Creds| auth.check(&mut c.clone(), b"n", Origin::of(ConnectionType::Websocket));
        let w = creds(Some("w"), Some("p"), None);
        assert_eq!(check(&auth, &w, b""), Check::Fail);
        assert_eq!(as_ws(&w), pass(0));
        let sig = nkeys::KeyPair::from_seed(SEED).unwrap().sign(b"n").unwrap();
        let nkey = Creds {
            nkey: Some(PUBLIC.into()),
            sig: Some(BASE64URL_NOPAD.encode(&sig)),
            ..Creds::default()
        };
        assert_eq!(check(&auth, &nkey, b"n"), Check::Fail);
        assert_eq!(as_ws(&nkey), pass(0));
    }

    #[test]
    fn an_nkey_is_passed_over_where_no_user_has_one() {
        let opts = Options {
            users: vec![user("a", "p", None)],
            ..Options::default()
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        let c = Creds {
            nkey: Some(PUBLIC.into()),
            ..creds(Some("a"), Some("p"), None)
        };
        assert_eq!(check(&auth, &c, b""), pass(0));
    }

    #[test]
    fn credentials_name_users_before_any_secret_is_checked() {
        let opts = Options {
            users: vec![
                user("a", "p", None),
                User {
                    login: Login::Nkey(PUBLIC.into()),
                    account: None,
                    permissions: None,
                    connection_types: Vec::new(),
                },
            ],
            no_auth_user: Some("a".into()),
            ..Options::default()
        };
        let auth = Auth::new(&opts, &accounts(&opts)).unwrap();
        let nkey = |key: &str| Creds {
            nkey: Some(key.into()),
            ..Creds::default()
        };
        assert_eq!(auth.id_of(&nkey(PUBLIC)), Some(PUBLIC));
        assert_eq!(auth.id_of(&nkey("UOTHER")), None, "an NKey no user has");
        assert_eq!(
            auth.id_of(&creds(Some("a"), Some("wrong"), None)),
            Some("a")
        );
        assert_eq!(auth.id_of(&creds(Some("x"), None, None)), None);
        assert_eq!(auth.id_of(&Creds::default()), Some("a"), "the no_auth_user");
        let mut free = Creds::default();
        auth.fill_free(&mut free);
        assert_eq!(free, creds(Some("a"), Some("p"), None));
        let mut given = creds(Some("b"), None, None);
        auth.fill_free(&mut given);
        assert_eq!(given, creds(Some("b"), None, None), "only for none");
        let by_key = Options {
            no_auth_user: Some(PUBLIC.into()),
            ..opts
        };
        let auth = Auth::new(&by_key, &accounts(&by_key)).unwrap();
        let mut free = Creds::default();
        auth.fill_free(&mut free);
        assert_eq!(free, nkey(PUBLIC));
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
