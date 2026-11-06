//! One client connection: `INFO`, the read loop and the writer.

mod handshake;
mod log;
mod login;
mod ping;
mod read;
mod trace;
mod write;

pub(crate) use read::{READ_CHUNK, SpentReads, make_room, stall};
pub(crate) use write::writer;

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use naq_proto::client::ParseError;
use naq_proto::encode;
use rustc_hash::FxHashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use zzq_tokio::transport::{Driver, Stream};

use crate::auth::Creds;
use crate::lane::{self, Lane, Outs};
use crate::perms::Held;
use crate::server::Shared;
use crate::stats::Tally;

/// How long a closed connection's writer may take to write what is left,
/// such as to a client that stopped reading.
const CLOSE_LINGER: Duration = Duration::from_secs(2);

/// What a connection's reader, its writer and the subscriptions that reach
/// it share.
#[derive(Debug)]
pub(crate) struct Client {
    pub(crate) id: u64,
    /// Output the writer has not taken yet.
    pub(crate) out: RefCell<Vec<u8>>,
    /// Marked on the lane for a writer wake.
    pub(crate) dirty: Cell<bool>,
    /// Takes headers (`HMSG`), as its `CONNECT` said.
    pub(crate) headers: Cell<bool>,
    /// Subscriptions by SID.
    pub(crate) subs: RefCell<FxHashMap<Box<[u8]>, Sub>>,
    /// Its account's id.
    pub(crate) account: Cell<u32>,
    /// Its permissions, if any limit it.
    pub(crate) held: RefCell<Option<Rc<Held>>>,
    /// Whether `held` is set or it is traced: deliveries check it.
    pub(crate) guarded: Cell<bool>,
    /// Its protocol is traced.
    pub(crate) traced: Cell<bool>,
    /// Messages it sent and got.
    pub(crate) tally: Tally,
    /// The round trip to it, as last measured.
    pub(crate) rtt: Cell<Duration>,
    /// Who it is, for monitoring.
    pub(crate) meta: RefCell<Meta>,
    closed: Cell<bool>,
    /// Its account changed: the read loop checks it again.
    refresh: Cell<bool>,
    /// Why the server ended it, once it did.
    ended: Cell<Option<Close>>,
    /// Wakes the writer.
    wake: Notify,
    /// The writer took the output: room for publishers that wait.
    drained: Notify,
    /// Stops the read loop.
    stop: Notify,
}

impl Client {
    pub(crate) fn new(id: u64) -> Client {
        Client {
            id,
            out: RefCell::default(),
            dirty: Cell::new(false),
            headers: Cell::new(false),
            subs: RefCell::default(),
            account: Cell::new(crate::auth::GLOBAL),
            held: RefCell::default(),
            guarded: Cell::new(false),
            traced: Cell::new(false),
            tally: Tally::default(),
            rtt: Cell::new(Duration::ZERO),
            meta: RefCell::new(Meta {
                ip: String::new(),
                port: 0,
                start: std::time::SystemTime::now(),
                websocket: false,
                user: None,
                how: None,
                name: None,
                lang: None,
                version: None,
            }),
            closed: Cell::new(false),
            refresh: Cell::new(false),
            ended: Cell::new(None),
            wake: Notify::new(),
            drained: Notify::new(),
            stop: Notify::new(),
        }
    }

    pub(crate) fn wake_writer(&self) {
        self.wake.notify_one();
    }

    pub(crate) const fn is_closed(&self) -> bool {
        self.closed.get()
    }

    /// Tells the read loop its account changed: it checks the login again.
    pub(crate) fn refresh(&self) {
        self.refresh.set(true);
        self.stop.notify_one();
    }

    /// Whether its account changed since it last looked.
    pub(crate) const fn take_refresh(&self) -> bool {
        self.refresh.replace(false)
    }

    /// Why the server ended the connection, once it did.
    pub(crate) const fn ended(&self) -> Option<Close> {
        self.ended.get()
    }

    /// Ends subscription `sid`, on this lane and then on the others.
    pub(crate) fn unsubscribe(&self, lane: &Lane, sid: &[u8]) {
        let Some(sub) = self.subs.borrow_mut().remove(sid) else {
            return;
        };
        if self.traced.get() {
            self.trace_delsub(&lane.shared, sid);
        }
        let (queue, account) = (sub.queue.as_deref(), self.account.get());
        lane.index(account)
            .borrow_mut()
            .remove(&sub.subject, queue, self.id, sid);
        lane.announce(account, &sub.subject, queue, false);
        lane.changed(account, &sub.subject, queue);
        crate::imports::shadow::remove(lane, self, sid, queue, &sub.shadows);
    }

    /// Whether its permissions let it get `m`. Notes requests it may reply
    /// to.
    #[cold]
    #[inline(never)]
    pub(crate) fn accepts(&self, m: &naq_proto::client::Pub<'_>) -> bool {
        let held = self.held.borrow();
        let Some(h) = held.as_ref() else {
            return true;
        };
        if h.perms.hides(m.subject) {
            return false;
        }
        if let Some(reply) = m.reply {
            h.got_request(reply, tokio::time::Instant::now());
        }
        true
    }

    /// Waits until the server closes the connection.
    pub(crate) async fn stopped(&self) {
        self.stop.notified().await;
    }

    /// Closes the connection for `why`, unless it was closed already.
    pub(crate) fn kick(&self, why: Close) {
        if self.ended.get().is_none() && !self.closed.get() {
            self.ended.set(Some(why));
        }
        self.close();
    }

    /// Closes the connection once the writer wrote what is queued.
    pub(crate) fn close(&self) {
        if !self.closed.replace(true) {
            self.stop.notify_one();
            self.wake.notify_one();
        }
    }
}

/// What monitoring shows of a client.
#[derive(Debug)]
pub(crate) struct Meta {
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) start: std::time::SystemTime,
    /// It came over WebSocket.
    pub(crate) websocket: bool,
    /// Who it logged in as, if anyone: a user name or an NKey.
    pub(crate) user: Option<String>,
    /// What it logged in with, for its log lines.
    pub(crate) how: Option<log::How>,
    /// From its `CONNECT`.
    pub(crate) name: Option<String>,
    pub(crate) lang: Option<String>,
    pub(crate) version: Option<String>,
}

/// A subscription of a client.
#[derive(Debug)]
pub(crate) struct Sub {
    pub(crate) subject: Box<[u8]>,
    pub(crate) queue: Option<Box<[u8]>>,
    /// Its shadows in the accounts its account imports streams from.
    pub(crate) shadows: Vec<crate::imports::shadow::Shadowed>,
}

/// How far a client's handshake got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// No `CONNECT` yet.
    Fresh,
    /// Sent its `CONNECT`.
    Connected,
    /// Got its first `PONG` after the `CONNECT`.
    Ready,
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Close {
    /// The client closed it, or reading failed.
    Lost,
    /// The server closed it.
    Kicked,
    /// It let more output wait than `max_pending`: a slow consumer.
    SlowPending,
    /// A write of this many bytes to it took longer than `write_deadline`:
    /// a slow consumer.
    SlowWrite(usize),
    /// A write to it failed.
    WriteError,
    /// The server shuts down.
    Shutdown,
    /// The client broke the protocol.
    Parse(ParseError),
    /// The `CONNECT` was not valid.
    Connect,
    /// An `HPUB` from a client that did not ask for headers.
    NoHeaders,
    /// A `CONNECT` the server refuses, with the `-ERR` it gets.
    Refused(&'static str),
    /// It left too many `PING`s unanswered.
    Stale,
    /// It did not authenticate.
    Auth,
    /// It did not authenticate in time.
    AuthTimeout,
    /// Its account has as many connections as it may.
    AccountConns,
    /// Its user JWT expired, or its time window ended.
    UserExpired,
    /// It may have no subscriptions at all.
    MaxSubs,
    /// Its account revoked its user.
    Revoked,
    /// Its account expired, or is gone.
    AccountExpired,
    /// The key that signed its user no longer may: closed without a word.
    Unsigned,
}

impl Close {
    /// Why it ended, in the words of `nats-server`.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Close::Lost => "Client Closed",
            Close::Kicked => "Kicked",
            Close::SlowPending => "Slow Consumer (Pending Bytes)",
            Close::SlowWrite(_) => "Slow Consumer (Write Deadline)",
            Close::WriteError => "Write Error",
            Close::Shutdown => "Server Shutdown",
            Close::Parse(ParseError::MaxPayload(_)) => "Maximum Message Payload Exceeded",
            Close::Parse(ParseError::ControlLine) => "Maximum Control Line Exceeded",
            Close::Parse(_) | Close::Connect => "Parse Error",
            Close::NoHeaders => "Protocol Violation",
            Close::Refused(text) if text == BAD_PROTOCOL => "Bad Client Protocol Version",
            Close::Refused(_) => "No Responders Requires Headers",
            Close::Stale => "Stale Connection",
            Close::Auth | Close::Unsigned => "Authentication Failure",
            Close::AuthTimeout => "Authentication Timeout",
            Close::AccountConns => "Maximum Account Connections Exceeded",
            Close::UserExpired | Close::AccountExpired => "Authentication Expired",
            Close::MaxSubs => "Maximum Subscriptions Exceeded",
            Close::Revoked => "Credentials Revoked",
        }
    }
}

/// The refusal of a `CONNECT` with a protocol other than 0 and 1.
pub(crate) const BAD_PROTOCOL: &str = "invalid client protocol";

/// What a client's transport adds to it.
#[derive(Debug)]
pub(crate) struct Via {
    /// It came over WebSocket.
    pub(crate) ws: bool,
    /// Credentials from its cookies, for a `CONNECT` without them.
    pub(crate) cookies: Option<Box<Creds>>,
    /// What its certificate names, where its listener maps certificates
    /// to users.
    pub(crate) cert: Option<Box<crate::tls::cert::Names>>,
    /// Its TLS, as auth callout requests tell it.
    pub(crate) tls: Option<Box<crate::callout::request::TlsInfo>>,
}

/// The reader's side of a connection.
#[derive(Debug)]
struct Conn {
    lane: Rc<Lane>,
    client: Rc<Client>,
    opts: handshake::ClientOpts,
    /// A subscriber this connection fed is past the stall mark.
    stalled: Option<Rc<Client>>,
    /// Publishes for other lanes from the current read, by lane.
    out: Outs,
    /// Subscriptions changed since the last `PING`: the next waits until
    /// every lane applied them.
    unfenced: bool,
    /// Its address, for `INFO`.
    ip: String,
    /// How far its handshake got.
    stage: Stage,
    /// Its `PING`s.
    ping: ping::Pinger,
    /// Sent messages, subscriptions or a `PING` in the current read.
    busy: bool,
    /// Until it authenticates: when its time to runs out.
    auth_by: Option<tokio::time::Instant>,
    /// What it may sign to log in with an NKey.
    nonce: Option<Box<str>>,
    via: Via,
    /// What its user may do, beyond the server's limits.
    bounds: Bounds,
    watch: Watch,
}

/// Whether what a client sends goes by `watched` first, and why.
#[derive(Debug, Clone, Copy)]
struct Watch {
    /// Until it authenticates, or while it is traced.
    on: bool,
    /// Its protocol is traced.
    tracing: bool,
}

/// The limits of a connection's user, set as it logs in.
#[derive(Debug)]
struct Bounds {
    /// The largest control line and payload it may send.
    limits: naq_proto::client::Limits,
    /// Most subscriptions it may have; -1 for no limit.
    subs: i64,
    /// When it is closed, and why: its JWT expires.
    deadline: Option<(tokio::time::Instant, Close)>,
    /// The account whose connection count holds it.
    counted: Option<u32>,
    /// How it logged in to a JWT account, to check itself again once the
    /// account changes.
    kept: Option<Box<crate::jwt::trust::live::Kept>>,
}

/// Runs a client connection that reached lane `index`.
pub(crate) async fn run(shared: Arc<Shared>, index: usize, stream: Stream) {
    let Some(lane) = lane::get(shared.id, index) else {
        return;
    };
    let (ip, port) = peer(&stream);
    let (hello, info) = greet(&lane, ip, port, false);
    if lane.shared.tls.is_some() {
        return crate::tls::serve(lane, hello, info, stream).await;
    }
    hello.client.out.borrow_mut().extend_from_slice(&info);
    let shared = lane.shared.clone();
    let driver = ConnDriver { lane, hello };
    if stream.drive(driver).await.is_err() {
        shared.client_gone();
    }
}

/// A client to serve, as its transport brought it.
#[derive(Debug)]
pub(crate) struct Hello {
    pub(crate) client: Rc<Client>,
    /// What it may sign to log in with an NKey.
    pub(crate) nonce: Option<Box<str>>,
    pub(crate) via: Via,
}

/// A new client from `ip` and `port`, over WebSocket if `ws`, and its
/// `INFO`.
pub(crate) fn greet(lane: &Lane, ip: String, port: u16, ws: bool) -> (Hello, Vec<u8>) {
    let client = Rc::new(Client::new(lane.shared.next_client()));
    let nonce = lane
        .shared
        .auth_for(ws)
        .filter(|a| a.wants_nonce())
        .map(|_| crate::auth::nonce().into_boxed_str());
    let mut info = Vec::new();
    let to = handshake::To {
        id: client.id,
        ip: &ip,
        nonce: nonce.as_deref(),
        ws,
        max_payload: lane.shared.opts.max_payload,
    };
    handshake::info(&lane.shared, &to, None, &mut info);
    {
        let mut meta = client.meta.borrow_mut();
        meta.ip = ip;
        meta.port = port;
    }
    let via = Via {
        ws,
        cookies: None,
        cert: None,
        tls: None,
    };
    (Hello { client, nonce, via }, info)
}

/// The client's IP address, as text.
fn peer(stream: &Stream) -> (String, u16) {
    match stream {
        Stream::Tcp(s) => s
            .peer_addr()
            .map(|a| (a.ip().to_canonical().to_string(), a.port()))
            .unwrap_or_default(),
        _ => (String::new(), 0),
    }
}

struct ConnDriver {
    lane: Rc<Lane>,
    hello: Hello,
}

impl Driver for ConnDriver {
    type Output = ();

    fn run<R, W>(self, reader: R, writer: W) -> impl Future<Output = ()>
    where
        R: AsyncRead + Unpin + 'static,
        W: AsyncWrite + Unpin + 'static,
    {
        serve(self.lane, self.hello, reader, writer)
    }
}

/// Serves a client whose `INFO` went out or is queued, over `r` and `w`.
pub(crate) async fn serve<R, W>(lane: Rc<Lane>, hello: Hello, mut r: R, w: W)
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
{
    let Hello { client, nonce, via } = hello;
    lane.clients.borrow_mut().insert(client.id, client.clone());
    let opts = &lane.shared.opts;
    let shared = lane.shared.clone();
    let slow = move || shared.events.slow_clients.note();
    let deadline = lane.shared.opts.write_deadline;
    let writer = tokio::task::spawn_local(write::writer(client.clone(), w, deadline, slow));
    client.wake_writer();
    let now = tokio::time::Instant::now();
    let ws_ping = via.ws.then(|| lane.shared.ws.as_ref()?.opts.ping_interval);
    let ping = ping::Pinger::new(now, ws_ping.flatten().unwrap_or(opts.ping_interval));
    let auth_by = lane.shared.auth_for(via.ws).map(|a| now + a.timeout);
    let out = Outs::new(&lane);
    let ip = client.meta.borrow().ip.clone();
    let limits = naq_proto::client::Limits {
        max_control_line: opts.max_control_line,
        max_payload: opts.max_payload,
    };
    let tracing = lane.shared.log.traces();
    if tracing {
        client.traced.set(true);
        client.guarded.set(true);
    }
    let mut conn = Conn {
        lane,
        client,
        opts: handshake::ClientOpts::default(),
        stalled: None,
        out,
        unfenced: false,
        ip,
        stage: Stage::Fresh,
        ping,
        busy: false,
        auth_by,
        nonce,
        via,
        bounds: Bounds {
            limits,
            subs: -1,
            deadline: None,
            counted: None,
            kept: None,
        },
        watch: Watch {
            on: tracing || auth_by.is_some(),
            tracing,
        },
    };
    conn.log_created();
    let close = conn.read_loop(&mut r).await;
    conn.end(close, writer).await;
}

impl Conn {
    /// Queues bytes for this client.
    fn reply(&self, bytes: &[u8]) {
        self.client.out.borrow_mut().extend_from_slice(bytes);
        self.lane.mark(&self.client);
    }

    /// Queues `+OK` in verbose mode.
    fn ok(&self) {
        if self.opts.verbose {
            if self.watch.tracing {
                self.trace_out("OK", None);
            }
            self.reply(encode::OK);
        }
    }

    /// Queues `PONG`, and after the first since the `CONNECT`, an `INFO` for
    /// clients that take one at any time.
    fn pong(&mut self) {
        if self.watch.tracing {
            self.trace_out("PONG", None);
        }
        self.reply(encode::PONG);
        if self.stage != Stage::Connected {
            return;
        }
        self.stage = Stage::Ready;
        if self.opts.protocol >= 1 {
            let shared = &self.lane.shared;
            let account = shared.accounts.name(self.client.account.get());
            let to = handshake::To {
                id: self.client.id,
                ip: &self.ip,
                nonce: self.nonce.as_deref(),
                ws: self.via.ws,
                max_payload: self.bounds.limits.max_payload,
            };
            handshake::info(
                shared,
                &to,
                Some(account),
                &mut self.client.out.borrow_mut(),
            );
        }
    }

    /// Queues `-ERR 'text'` for this client.
    fn error(&self, text: &str) {
        if self.watch.tracing {
            self.trace_out("-ERR", Some(text));
        }
        naq_proto::encode::err(&mut *self.client.out.borrow_mut(), text);
        self.lane.mark(&self.client);
    }

    /// Removes the connection's interest, writes what is left and closes.
    async fn end(&mut self, close: Close, mut writer: JoinHandle<()>) {
        // Kicked by another, it was told why.
        let close = match (close, self.client.ended()) {
            (Close::Kicked, Some(why)) => why,
            _ => close,
        };
        self.log_why(close);
        if let Some(text) = farewell(close) {
            self.error(text);
        }
        self.log_closed(close);
        let sids: Vec<_> = self.client.subs.borrow().keys().cloned().collect();
        for sid in sids {
            self.client.unsubscribe(&self.lane, &sid);
        }
        self.lane.clients.borrow_mut().remove(&self.client.id);
        if let Some(a) = self.bounds.counted.take() {
            self.lane.shared.uncount(a, self.client.id);
        }
        self.lane.shared.client_gone();
        self.lane.flush();
        self.client.ended.set(Some(close));
        self.client.close();
        let _ending = self.lane.ending();
        if tokio::time::timeout(CLOSE_LINGER, &mut writer)
            .await
            .is_err()
        {
            writer.abort();
        }
    }
}

/// The `-ERR` a connection gets before it is closed for `close`, as
/// `nats-server` sends it.
const fn farewell(close: Close) -> Option<&'static str> {
    match close {
        Close::Parse(ParseError::MaxPayload(_)) => Some("Maximum Payload Violation"),
        Close::Parse(ParseError::ControlLine) => Some("maximum control line exceeded"),
        Close::Refused(text) => Some(text),
        Close::Stale => Some("Stale Connection"),
        Close::Auth => Some("Authorization Violation"),
        Close::AuthTimeout => Some("Authentication Timeout"),
        Close::AccountConns => Some("maximum account active connections exceeded"),
        Close::UserExpired => Some("User Authentication Expired"),
        Close::MaxSubs => Some("maximum subscriptions exceeded"),
        Close::Revoked => Some("User Authentication Revoked"),
        Close::AccountExpired => Some("Account Authentication Expired"),
        Close::Parse(ParseError::Args(_) | ParseError::Size(_) | ParseError::HeaderSize)
        | Close::Lost
        | Close::Kicked
        | Close::SlowPending
        | Close::SlowWrite(_)
        | Close::WriteError
        | Close::Shutdown
        | Close::Connect
        | Close::Unsigned
        | Close::NoHeaders => None,
        Close::Parse(_) => Some("Unknown Protocol Operation"),
    }
}
