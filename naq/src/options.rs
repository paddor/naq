//! Server settings.

use std::time::Duration;

/// Server settings. The defaults are those of `nats-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Host to listen on for clients.
    pub host: String,
    /// Port to listen on for clients. 0 picks a free one.
    pub port: u16,
    /// IO lanes, each on a thread of its own. 0, the default, is one per
    /// core the process may run on.
    pub lanes: usize,
    /// Name in `INFO`.
    pub server_name: String,
    /// Largest message a client may publish, headers included
    /// (`max_payload`).
    pub max_payload: usize,
    /// Longest arguments of a control line (`max_control_line`).
    pub max_control_line: usize,
    /// Most bytes waiting to be written to one client (`max_pending`). Past
    /// three quarters of it, its publishers wait; past it, it is closed as a
    /// slow consumer.
    pub max_pending: usize,
    /// Time between `PING`s to a client that sent nothing meanwhile
    /// (`ping_interval`). The first comes 2 seconds after the `CONNECT` at
    /// the latest.
    pub ping_interval: Duration,
    /// `PING`s a client may leave unanswered; at the next, it is closed as
    /// stale (`ping_max`).
    pub max_pings_out: u32,
    /// Longest a write to a client may take; past it, the client is closed
    /// as a slow consumer (`write_deadline`).
    pub write_deadline: Duration,
    /// Accounts besides the global one, `$G`, by name (`accounts`). Each has
    /// subjects of its own.
    pub accounts: Vec<String>,
    /// Who may connect (`authorization { users }`, the `users` of
    /// `accounts`). With no users, no [`Options::user`] and no token, anyone
    /// may, into `$G`.
    pub users: Vec<User>,
    /// The one user clients log in as, with its password, plain or a bcrypt
    /// hash (`authorization { user, password }`): into `$G`, without
    /// permissions. It cannot go with [`Options::users`].
    pub user: Option<(String, String)>,
    /// The token clients give instead of users (`authorization { token }`),
    /// plain or a bcrypt hash: into `$G`, without permissions.
    pub token: Option<String>,
    /// The user a client that gives no credentials connects as
    /// (`no_auth_user`).
    pub no_auth_user: Option<String>,
    /// How long a client has to authenticate, from the moment it connects
    /// (`authorization { timeout }`).
    pub auth_timeout: Duration,
    /// Port for monitoring over HTTP (`http_port`): `/healthz`, `/varz`,
    /// `/connz`, `/leafz`. `None` serves none; 0 picks a free port.
    pub http_port: Option<u16>,
    /// Host for monitoring; `None` for [`Options::host`] (`http`).
    pub http_host: Option<String>,
    /// TLS for every client (`tls`).
    pub tls: Option<Tls>,
    /// WebSocket clients, on a port of their own (`websocket`).
    pub websocket: Option<Websocket>,
    /// Permissions of users that have none of their own
    /// (`authorization { default_permissions }`).
    pub default_permissions: Option<Permissions>,
    /// Hubs this server dials as a leaf node (`leafnodes { remotes }`).
    pub remotes: Vec<Remote>,
    /// naq leaf nodes this server takes as their hub, over OMQ
    /// (`leafnodes { listen }`), if any.
    pub leafnodes: Option<Leafnodes>,
    /// How long a leaf node link waits, once it ended, before it dials
    /// again (`leafnodes { reconnect }`).
    pub leaf_reconnect: Duration,
    /// The other naq servers of its cluster (`cluster`), if any.
    pub cluster: Option<Cluster>,
}

/// A fixed mesh of naq servers (`cluster`): each lists the others, and
/// each forwards client traffic straight to the others with interest, over
/// OMQ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    /// The cluster's name (`name`): a server of another one is refused.
    pub name: String,
    /// Host to listen on for the other servers (`host`, `listen`).
    pub host: String,
    /// Port to listen on (`port`, `listen`); 0 picks a free one.
    pub port: u16,
    /// The other servers (`routes`): `nats-route://host:port`, or
    /// `nats://` or a bare `host:port`.
    pub routes: Vec<String>,
}

/// The port naq leaf nodes dial (`leafnodes { listen }`), over OMQ, with
/// the remote URL `naq://host:port`, and who they log in as. Go leaf nodes
/// cannot dial it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leafnodes {
    /// Host to listen on (`host`, `listen`).
    pub host: String,
    /// Port to listen on (`port`, `listen`); 0 picks a free one.
    pub port: u16,
    /// The account a naq leaf binds without a user of its own
    /// (`authorization { account }`); `None` for `$G`.
    pub account: Option<String>,
    /// The users naq leafs log in as, each into its account or `$G`,
    /// without permissions: the single one of `authorization { user,
    /// password }` or `{ nkey }`, into [`Leafnodes::account`], or those of
    /// `authorization { users }`. Without any, a naq leaf logs in as the
    /// server's clients do, into its user's account, and without those
    /// either into [`Leafnodes::account`].
    pub users: Vec<User>,
    /// How long a naq leaf has to log in once its hub greeted it
    /// (`authorization { timeout }`).
    pub auth_timeout: Duration,
}

impl Default for Leafnodes {
    fn default() -> Leafnodes {
        Leafnodes {
            host: "0.0.0.0".into(),
            port: 7422,
            account: None,
            users: Vec::new(),
            auth_timeout: Duration::from_secs(2),
        }
    }
}

impl Default for Cluster {
    fn default() -> Cluster {
        Cluster {
            name: String::new(),
            host: "0.0.0.0".into(),
            port: 6222,
            routes: Vec::new(),
        }
    }
}

/// A user that may connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// How it proves who it is.
    pub login: Login,
    /// The account it uses; `None` for `$G`.
    pub account: Option<String>,
    /// What it may publish and subscribe to; `None` for the default
    /// permissions, if any, else anything.
    pub permissions: Option<Permissions>,
}

/// What a user may publish and subscribe to (`permissions`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permissions {
    /// Subjects it may publish to.
    pub publish: Rules,
    /// Subjects it may subscribe to. An entry `subject queue` allows that
    /// queue group only.
    pub subscribe: Rules,
    /// Replies it may publish to requests it got, even where `publish`
    /// does not allow them (`allow_responses`). With these and no `publish`
    /// allow list, it may publish replies only.
    pub responses: Option<Responses>,
}

/// Subjects allowed, and those denied among them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    /// Filters allowed; `None` allows every subject.
    pub allow: Option<Vec<String>>,
    /// Filters denied, whatever `allow` says.
    pub deny: Vec<String>,
}

/// Replies a user may publish to requests it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Responses {
    /// Replies to one request.
    pub max: u32,
    /// How long after the request; zero for no limit.
    pub expires: Duration,
}

impl Default for Responses {
    /// One reply within two minutes, as `nats-server` defaults.
    fn default() -> Self {
        Responses {
            max: 1,
            expires: Duration::from_secs(120),
        }
    }
}

/// How a user proves who it is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Login {
    /// `user` and `pass` in its `CONNECT`. The password here is plain or a
    /// bcrypt hash (`$2a$...`).
    Password {
        /// The user name.
        user: String,
        /// The password, or its hash.
        password: String,
    },
    /// `nkey` in its `CONNECT`, a public user NKey (`U...`), with `sig`: the
    /// nonce of the server's `INFO`, signed with the key's seed.
    Nkey(String),
}

impl Default for Options {
    fn default() -> Self {
        Options {
            host: "0.0.0.0".into(),
            port: 4222,
            lanes: 0,
            server_name: "naq".into(),
            max_payload: 1 << 20,
            max_control_line: 4096,
            max_pending: 64 << 20,
            ping_interval: Duration::from_secs(120),
            max_pings_out: 2,
            write_deadline: Duration::from_secs(10),
            accounts: Vec::new(),
            users: Vec::new(),
            user: None,
            token: None,
            no_auth_user: None,
            auth_timeout: Duration::from_secs(2),
            default_permissions: None,
            remotes: Vec::new(),
            leafnodes: None,
            leaf_reconnect: Duration::from_secs(1),
            cluster: None,
            http_port: None,
            http_host: None,
            tls: None,
            websocket: None,
        }
    }
}

/// TLS for clients (`tls`). By default the server sends `INFO` in the clear
/// and the client starts the handshake after it, as NATS clients do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    /// PEM file of the server's certificate chain (`cert_file`).
    pub cert_file: std::path::PathBuf,
    /// PEM file of its private key (`key_file`).
    pub key_file: std::path::PathBuf,
    /// PEM file of the certificate authorities client certificates must
    /// chain to (`ca_file`).
    pub ca_file: Option<std::path::PathBuf>,
    /// Clients must present a certificate that chains to `ca_file`
    /// (`verify`).
    pub verify: bool,
    /// How long a handshake may take (`timeout`).
    pub timeout: Duration,
    /// The handshake comes first, before `INFO` (`handshake_first`).
    pub handshake_first: bool,
    /// With `handshake_first`, how long a client has to start TLS; one that
    /// does not gets `INFO` in the clear and then the handshake, as by
    /// default (`handshake_first: "300ms"`). `None` waits for TLS only.
    pub fallback: Option<Duration>,
}

/// WebSocket clients (`websocket`): NATS over binary frames, after an HTTP
/// upgrade on a port of their own, as `ws://` or, with TLS, `wss://`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Websocket {
    /// Host to listen on (`host`). It defaults to `0.0.0.0`, whatever
    /// [`Options::host`] is, as in `nats-server`.
    pub host: String,
    /// Port to listen on (`port`). 0 picks a free one.
    pub port: u16,
    /// TLS for every WebSocket client (`tls`): the handshake comes first,
    /// before the upgrade. `handshake_first` and `fallback` do not apply.
    pub tls: Option<Tls>,
    /// Plain `ws://` is meant (`no_tls`): without it, `tls` is required,
    /// as `nats-server` requires it.
    pub no_tls: bool,
    /// A browser's `Origin` must be the host and port it connected to
    /// (`same_origin`).
    pub same_origin: bool,
    /// Origins browsers may connect from, as `http` or `https` URLs
    /// (`allowed_origins`). Empty allows any.
    pub allowed_origins: Vec<String>,
    /// How long TLS and the upgrade may take (`handshake_timeout`). Zero
    /// waits without limit, as `nats-server` does by default.
    pub handshake_timeout: Duration,
    /// Messages are compressed for clients that ask (`compression`).
    pub compression: bool,
    /// Headers added to every upgrade response (`headers`).
    pub headers: Vec<(String, String)>,
    /// Time between `PING`s to WebSocket clients, in place of
    /// [`Options::ping_interval`] (`ping_interval`).
    pub ping_interval: Option<Duration>,
    /// Cookies that carry credentials for a `CONNECT` without them.
    pub cookies: Cookies,
    /// Credentials of WebSocket clients in place of the server's.
    pub auth: WebsocketAuth,
}

impl Default for Websocket {
    fn default() -> Self {
        Websocket {
            host: "0.0.0.0".into(),
            port: 0,
            tls: None,
            no_tls: false,
            same_origin: false,
            allowed_origins: Vec::new(),
            handshake_timeout: Duration::from_secs(10),
            compression: false,
            headers: Vec::new(),
            ping_interval: None,
            cookies: Cookies::default(),
            auth: WebsocketAuth::default(),
        }
    }
}

/// Names of cookies that carry credentials, for clients such as browsers
/// that cannot put them in their `CONNECT` (`user_cookie`, `pass_cookie`,
/// `token_cookie`). A field the `CONNECT` has wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cookies {
    /// The cookie with the user name.
    pub user: Option<String>,
    /// The cookie with the password.
    pub pass: Option<String>,
    /// The cookie with the token.
    pub token: Option<String>,
}

/// Credentials of WebSocket clients in place of the server's (the
/// `websocket` block's `authorization` and `no_auth_user`), as in
/// `nats-server`. With any of `user`, `token` or `no_auth_user`, WebSocket
/// clients must authenticate, and the server's own credentials stand in
/// for them as follows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebsocketAuth {
    /// The user WebSocket clients log in as, with its password, plain or a
    /// bcrypt hash (`authorization { user, password }`). With it or
    /// [`WebsocketAuth::token`], they log in with these alone: not with
    /// [`Options::users`], [`Options::user`] or [`Options::token`].
    pub user: Option<(String, String)>,
    /// The token WebSocket clients give (`authorization { token }`).
    pub token: Option<String>,
    /// The user a WebSocket client that gives no credentials connects as,
    /// one of [`Options::users`], in place of [`Options::no_auth_user`]
    /// (`no_auth_user`).
    pub no_auth_user: Option<String>,
    /// How long a WebSocket client has to authenticate, in place of
    /// [`Options::auth_timeout`] (`authorization { timeout }`).
    pub timeout: Option<Duration>,
}

/// A hub this server dials as a leaf node (`leafnodes { remotes }`): a
/// link that binds a local account to the hub account its credentials
/// give, and carries interest and messages both ways.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Remote {
    /// The hub's URLs, tried in turn (`url`, `urls`): `nats-leaf://` or
    /// `nats://` with `user:password@` or a token as `token@` if it takes
    /// them, or a bare `host:port`. The port defaults to 7422. A naq hub
    /// is dialed over OMQ at `naq://host:port` URLs, all of them naq ones,
    /// with credentials as above, and of the other options only `account`,
    /// `no_randomize` and `nkey`.
    /// A hub tells of the URLs of its cluster's servers, which come first
    /// once it did.
    pub urls: Vec<String>,
    /// The local account the link binds (`account`); `None` for `$G`.
    pub account: Option<String>,
    /// URLs are tried in the order given (`no_randomize`); else shuffled.
    pub no_randomize: bool,
    /// A credentials file (`credentials`, `creds`): a user JWT, sent to
    /// the hub, and the seed that signs its nonce. Read at each dial.
    pub credentials: Option<std::path::PathBuf>,
    /// A user NKey seed (`nkey`, `seed`), `SU...`: the link sends its
    /// public key and signs the hub's nonce with it. Not with
    /// [`Remote::credentials`].
    pub nkey: Option<String>,
    /// Subjects the link takes no messages on and tells the hub of no
    /// interest in (`deny_imports`); the hub learns them too.
    pub deny_imports: Vec<String>,
    /// Subjects the link sends no messages on and takes no hub interest in
    /// (`deny_exports`).
    pub deny_exports: Vec<String>,
    /// The hub sends this link no interest of its other leaf nodes
    /// (`request_isolation`).
    pub request_isolation: bool,
    /// TLS to the hub (`tls`). Without it, the link starts TLS only when
    /// the hub asks for it, and trusts the system's certificate
    /// authorities.
    pub tls: Option<RemoteTls>,
}

/// TLS of a leaf node link (`tls` of a remote): the handshake after the
/// hub's `INFO`, or before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTls {
    /// PEM file of a certificate chain the link presents, for hubs that
    /// verify leafs (`cert_file`), with `key_file`.
    pub cert_file: Option<std::path::PathBuf>,
    /// PEM file of its private key (`key_file`).
    pub key_file: Option<std::path::PathBuf>,
    /// PEM file of the certificate authorities the hub's certificate must
    /// chain to (`ca_file`); without it, the system's.
    pub ca_file: Option<std::path::PathBuf>,
    /// How long a handshake may take (`timeout`).
    pub timeout: Duration,
    /// The handshake comes first, before the hub's `INFO`
    /// (`handshake_first`). The hub must expect it.
    pub handshake_first: bool,
}

impl Default for RemoteTls {
    fn default() -> RemoteTls {
        RemoteTls {
            cert_file: None,
            key_file: None,
            ca_file: None,
            timeout: Duration::from_secs(2),
            handshake_first: false,
        }
    }
}
