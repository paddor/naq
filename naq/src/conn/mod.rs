//! One client connection: `INFO`, the read loop and the writer.

mod handshake;
mod ping;
mod read;
mod write;

pub(crate) use read::{SpentReads, stall};

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
use crate::lane::{self, Lane, Out};
use crate::perms::Held;
use crate::server::Shared;
use crate::stats::{Events, Tally};

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
    /// Whether `held` is set: deliveries check it.
    pub(crate) guarded: Cell<bool>,
    /// Messages it sent and got.
    pub(crate) tally: Tally,
    /// Who it is, for monitoring.
    pub(crate) meta: RefCell<Meta>,
    closed: Cell<bool>,
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
            tally: Tally::default(),
            meta: RefCell::new(Meta {
                ip: String::new(),
                port: 0,
                start: std::time::SystemTime::now(),
                name: None,
                lang: None,
                version: None,
            }),
            closed: Cell::new(false),
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

    /// Why the server ended the connection, once it did.
    pub(crate) const fn ended(&self) -> Option<Close> {
        self.ended.get()
    }

    /// Ends subscription `sid`, on this lane and then on the others.
    pub(crate) fn unsubscribe(&self, lane: &Lane, sid: &[u8]) {
        let Some(sub) = self.subs.borrow_mut().remove(sid) else {
            return;
        };
        let (queue, account) = (sub.queue.as_deref(), self.account.get());
        lane.index(account)
            .borrow_mut()
            .remove(&sub.subject, queue, self.id, sid);
        lane.announce(account, &sub.subject, queue, false);
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
    /// The server closed it, as for a slow consumer.
    Kicked,
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
    fwd: Vec<Out>,
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
        .auth
        .as_ref()
        .filter(|a| a.wants_nonce())
        .map(|_| crate::auth::nonce().into_boxed_str());
    let mut info = Vec::new();
    let to = handshake::To {
        id: client.id,
        ip: &ip,
        nonce: nonce.as_deref(),
        ws,
    };
    handshake::info(&lane.shared, &to, None, &mut info);
    {
        let mut meta = client.meta.borrow_mut();
        meta.ip = ip;
        meta.port = port;
    }
    let via = Via { ws, cookies: None };
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
    let slow = move || Events::note(&shared.events.slow_consumers);
    let deadline = lane.shared.opts.write_deadline;
    let writer = tokio::task::spawn_local(write::writer(client.clone(), w, deadline, slow));
    client.wake_writer();
    let now = tokio::time::Instant::now();
    let ws_ping = via.ws.then(|| lane.shared.ws.as_ref()?.opts.ping_interval);
    let ping = ping::Pinger::new(now, ws_ping.flatten().unwrap_or(opts.ping_interval));
    let auth_by = lane.shared.auth.as_ref().map(|a| now + a.timeout);
    let fwd = (0..lane.lanes()).map(|_| Out::default()).collect();
    let ip = client.meta.borrow().ip.clone();
    let mut conn = Conn {
        lane,
        client,
        opts: handshake::ClientOpts::default(),
        stalled: None,
        fwd,
        unfenced: false,
        ip,
        stage: Stage::Fresh,
        ping,
        busy: false,
        auth_by,
        nonce,
        via,
    };
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
            self.reply(encode::OK);
        }
    }

    /// Queues `PONG`, and after the first since the `CONNECT`, an `INFO` for
    /// clients that take one at any time.
    fn pong(&mut self) {
        self.reply(encode::PONG);
        if self.stage != Stage::Connected {
            return;
        }
        self.stage = Stage::Ready;
        if self.opts.protocol >= 1 {
            let shared = &self.lane.shared;
            let account = &shared.accounts[self.client.account.get() as usize];
            let to = handshake::To {
                id: self.client.id,
                ip: &self.ip,
                nonce: self.nonce.as_deref(),
                ws: self.via.ws,
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
        naq_proto::encode::err(&mut *self.client.out.borrow_mut(), text);
        self.lane.mark(&self.client);
    }

    /// Removes the connection's interest, writes what is left and closes.
    async fn end(&mut self, close: Close, mut writer: JoinHandle<()>) {
        if let Some(text) = farewell(close) {
            self.error(text);
        }
        let sids: Vec<_> = self.client.subs.borrow().keys().cloned().collect();
        for sid in sids {
            self.client.unsubscribe(&self.lane, &sid);
        }
        self.lane.clients.borrow_mut().remove(&self.client.id);
        self.lane.shared.client_gone();
        self.lane.flush();
        self.client.ended.set(Some(close));
        self.client.close();
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
        Close::Parse(ParseError::Args(_) | ParseError::Size(_) | ParseError::HeaderSize)
        | Close::Lost
        | Close::Kicked
        | Close::Connect
        | Close::NoHeaders => None,
        Close::Parse(_) => Some("Unknown Protocol Operation"),
    }
}
