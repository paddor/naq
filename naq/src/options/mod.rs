//! Server settings.

mod log;

pub use log::{LogTo, Logging, Trace};

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
    /// Accounts besides the global one, `$G` (`accounts`). Each has
    /// subjects of its own, and those it imports from others.
    pub accounts: Vec<Account>,
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
    /// Port for monitoring over HTTP (`http_port`, `http`): the endpoints
    /// of `nats-server`, such as `/healthz`, `/varz` and `/connz`. `None`
    /// serves none; 0 picks a free port. Not with [`Options::https_port`].
    pub http_port: Option<u16>,
    /// Port for monitoring over HTTPS (`https_port`, `https`), with the
    /// certificate of [`Options::tls`], which it needs. Clients present no
    /// certificate.
    pub https_port: Option<u16>,
    /// Host for monitoring; `None` for [`Options::host`] (`http`, `https`).
    pub http_host: Option<String>,
    /// Closed connections monitoring keeps for `/connz` (`max_closed_clients`):
    /// the newest that many. 0 keeps 10000, the default.
    pub max_closed_clients: usize,
    /// The path monitoring is served under (`http_base_path`): `/mon`
    /// serves `/mon/varz`. Empty for the root.
    pub http_base_path: String,
    /// TLS for every client (`tls`).
    pub tls: Option<Tls>,
    /// WebSocket clients, on a port of their own (`websocket`).
    pub websocket: Option<Websocket>,
    /// Permissions of users that have none of their own
    /// (`authorization { default_permissions }`).
    pub default_permissions: Option<Permissions>,
    /// Clients log in as an auth service answers
    /// (`authorization { auth_callout }`).
    pub auth_callout: Option<AuthCallout>,
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
    /// The account the server sends its own messages in, such as latency
    /// samples (`system_account`). `None` takes an account named `$SYS`
    /// if there is one, else makes one, unless
    /// [`Options::no_system_account`].
    pub system_account: Option<String>,
    /// No system account is made (`no_system_account`).
    pub no_system_account: bool,
    /// The JWTs of the operators whose accounts the server trusts
    /// (`operator`): users then log in with a JWT their account signed.
    pub operators: Vec<String>,
    /// Operator keys trusted without a JWT (`trusted_keys`).
    pub trusted_keys: Vec<String>,
    /// Where the JWTs of accounts come from (`resolver`), with trusted
    /// operators.
    pub resolver: Option<Resolver>,
    /// Account JWTs the resolver starts with, by the account's public key
    /// (`resolver_preload`).
    pub resolver_preload: Vec<(String, String)>,
    /// What the server logs, and where to.
    pub log: Logging,
    /// The configuration file the options came from, as
    /// [`Options::from_file`] sets it.
    pub config_file: Option<std::path::PathBuf>,
    /// Where the server writes its process ID as it starts (`pid_file`).
    pub pid_file: Option<std::path::PathBuf>,
    /// Where the server writes the URLs it listens at as it starts, in a
    /// file of the program's name and process ID, removed as it stops
    /// (`ports_file_dir`).
    pub ports_file_dir: Option<std::path::PathBuf>,
}

/// Where the JWTs of accounts come from (`resolver`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resolver {
    /// Those of [`Options::resolver_preload`] only (`MEMORY`).
    Memory,
    /// All of them, kept in a directory and shared with the other servers
    /// of the cluster (`type: full`).
    Full(Directory),
    /// Those in use, fetched from servers of the cluster with a full
    /// resolver and kept in a directory a while (`type: cache`).
    Cache(Directory),
}

/// The directory of a full or cache resolver, and how it keeps account
/// JWTs: one file `<account key>.jwt` each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    /// Where the files are (`dir`); made if missing.
    pub dir: std::path::PathBuf,
    /// Whether a full resolver deletes accounts when asked, and how
    /// (`allow_delete`, `hard_delete`). A cache removes them.
    pub delete: Delete,
    /// The most JWTs kept (`limit`): `None` for no limit in a full
    /// resolver, 1000 in a cache, which then drops the least used.
    pub limit: Option<usize>,
    /// How often a full resolver compares its JWTs with those of the
    /// other servers (`interval`).
    pub interval: Duration,
    /// How long a cache keeps a JWT since it was last used (`ttl`); `None`
    /// keeps it until it expires or is dropped.
    pub ttl: Option<Duration>,
    /// How long a fetch from the other servers waits (`timeout`).
    pub timeout: Duration,
}

impl Directory {
    /// A directory resolver in `dir`, with the defaults of `nats-server`.
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Directory {
        Directory {
            dir: dir.into(),
            delete: Delete::No,
            limit: None,
            interval: Duration::from_secs(60),
            ttl: None,
            timeout: Duration::from_millis(1900),
        }
    }
}

/// Whether a full resolver deletes accounts when asked, and how.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Delete {
    /// It refuses (the default).
    #[default]
    No,
    /// It renames the file to `<account key>.jwt.deleted` (`allow_delete`).
    Rename,
    /// It removes the file (`allow_delete` and `hard_delete`).
    Remove,
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

/// An account besides `$G` (`accounts`): subjects of its own, those it
/// lets others import, and those it imports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    /// Its name.
    pub name: String,
    /// What other accounts may import from it (`exports`).
    pub exports: Vec<Export>,
    /// What it takes from other accounts (`imports`).
    pub imports: Vec<Import>,
}

impl From<&str> for Account {
    /// An account named `name`, without exports and imports.
    fn from(name: &str) -> Account {
        Account {
            name: name.into(),
            ..Account::default()
        }
    }
}

/// Subjects an account lets others import (`exports`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// The subjects, a filter, as the account has them (`stream` or
    /// `service`).
    pub subject: String,
    /// What is exported: messages, or requests to a service.
    pub kind: ExportKind,
    /// The accounts that may import it (`accounts`); `None` for all.
    pub accounts: Option<Vec<String>>,
    /// The token of `subject`, counted from 1, that an importer must fill
    /// with its own name (`account_token_position`). It is a `*`.
    pub token_position: Option<usize>,
}

/// What an account exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportKind {
    /// The messages published to the subjects (`stream`).
    Stream,
    /// Requests to a service on the subjects (`service`).
    Service(ServiceExport),
}

/// How an exported service answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceExport {
    /// How many responses a request gets (`response_type`).
    pub response: ResponseType,
    /// How long a request may wait for its responses
    /// (`response_threshold`).
    pub threshold: Duration,
    /// Latency samples of its requests, if any (`latency`).
    pub latency: Option<Latency>,
}

impl Default for ServiceExport {
    /// One response, within two minutes, as `nats-server` defaults.
    fn default() -> ServiceExport {
        ServiceExport {
            response: ResponseType::Singleton,
            threshold: Duration::from_secs(120),
            latency: None,
        }
    }
}

/// How many responses a service request gets (`response_type`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResponseType {
    /// One (`singleton`).
    #[default]
    Singleton,
    /// Any number, until the threshold (`stream`).
    Stream,
    /// Any number, until the threshold or an empty one (`chunked`).
    Chunked,
}

/// Latency samples of the requests to a service (`latency`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Latency {
    /// Which requests are sampled (`sampling`).
    pub sampling: Sampling,
    /// Where the samples go, in the exporting account (`subject`).
    pub subject: String,
}

/// Which requests to a service get a latency sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sampling {
    /// This percent of them, 1 to 100.
    Percent(u8),
    /// Those whose headers ask for a trace (`headers`).
    Headers,
}

/// Subjects an account takes from another (`imports`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The account it imports from (`account`).
    pub account: String,
    /// The subjects, as that account has them (`subject`).
    pub subject: String,
    /// The subjects as the importer has them (`to`, or `prefix` before
    /// `subject`); `None` for `subject`.
    pub to: Option<String>,
    /// What is imported: messages, or a service.
    pub kind: ImportKind,
}

/// What an account imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// Messages (`stream`).
    Stream,
    /// A service (`service`).
    Service {
        /// Its requests carry the details of the requester (`share`).
        share: bool,
    },
}

/// Auth callout (`authorization { auth_callout }`): a client logs in as
/// an auth service answers a request about it on `$SYS.REQ.USER.AUTH`,
/// as in `nats-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCallout {
    /// The public account key that signs the service's answers (`issuer`).
    pub issuer: String,
    /// The account the service answers in (`account`); `None` for `$G`.
    pub account: Option<String>,
    /// The users of the service, by name or NKey: they log in as
    /// configured (`auth_users`).
    pub auth_users: Vec<String>,
    /// The service's public curve key, if requests and answers are sealed
    /// (`xkey`).
    pub xkey: Option<String>,
    /// The accounts whose users call out; empty is all (`allowed_accounts`).
    pub allowed_accounts: Vec<String>,
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
    /// The kinds of connection it may log in over
    /// (`allowed_connection_types`); empty allows any.
    pub connection_types: Vec<ConnectionType>,
}

/// A kind of connection a user may be limited to, as `nats-server` names
/// them. naq serves no MQTT or in-process clients, so users limited to
/// those never log in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConnectionType {
    /// Clients over TCP, with TLS or without (`STANDARD`).
    Standard,
    /// Clients over WebSocket (`WEBSOCKET`).
    Websocket,
    /// Leaf nodes and naq links (`LEAFNODE`).
    Leafnode,
    /// Leaf nodes over WebSocket (`LEAFNODE_WS`).
    LeafnodeWs,
    /// MQTT clients (`MQTT`).
    Mqtt,
    /// MQTT clients over WebSocket (`MQTT_WS`).
    MqttWs,
    /// Clients in the same process (`IN_PROCESS`).
    InProcess,
}

impl ConnectionType {
    /// Every kind, by its name.
    const ALL: [(&str, ConnectionType); 7] = [
        ("STANDARD", ConnectionType::Standard),
        ("WEBSOCKET", ConnectionType::Websocket),
        ("LEAFNODE", ConnectionType::Leafnode),
        ("LEAFNODE_WS", ConnectionType::LeafnodeWs),
        ("MQTT", ConnectionType::Mqtt),
        ("MQTT_WS", ConnectionType::MqttWs),
        ("IN_PROCESS", ConnectionType::InProcess),
    ];

    /// The kind named `name`, in any case.
    pub(crate) fn named(name: &str) -> Option<ConnectionType> {
        Self::ALL
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|&(_, t)| t)
    }
}

impl std::fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = Self::ALL
            .iter()
            .find(|(_, t)| t == self)
            .map_or("", |(n, _)| n);
        f.write_str(name)
    }
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
            auth_callout: None,
            remotes: Vec::new(),
            leafnodes: None,
            leaf_reconnect: Duration::from_secs(1),
            cluster: None,
            system_account: None,
            no_system_account: false,
            operators: Vec::new(),
            trusted_keys: Vec::new(),
            resolver: None,
            resolver_preload: Vec::new(),
            http_port: None,
            https_port: None,
            http_host: None,
            http_base_path: String::new(),
            max_closed_clients: 10_000,
            tls: None,
            websocket: None,
            log: Logging::default(),
            config_file: None,
            pid_file: None,
            ports_file_dir: None,
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
    /// Clients log in as the user their certificate names, as
    /// `nats-server` maps it: by e-mail address, DNS name or URI, then by
    /// subject (`verify_and_map`). It needs `verify`.
    pub map: bool,
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
    /// with credentials as above, and all other options but `credentials`
    /// and `tls`.
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
