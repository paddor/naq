//! One client connection: `INFO`, the read loop and the writer.

mod handshake;
mod read;
mod write;

pub(crate) use read::stall;

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

use crate::lane::{self, Lane, Out};
use crate::server::Shared;

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
    closed: Cell<bool>,
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
            closed: Cell::new(false),
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

    /// Ends subscription `sid`, on this lane and then on the others.
    pub(crate) fn unsubscribe(&self, lane: &Lane, sid: &[u8]) {
        let Some(sub) = self.subs.borrow_mut().remove(sid) else {
            return;
        };
        let queue = sub.queue.as_deref();
        lane.index
            .borrow_mut()
            .remove(&sub.subject, queue, self.id, sid);
        lane.announce(&sub.subject, queue, false);
    }

    /// Closes the connection once the writer wrote what is queued.
    pub(crate) fn close(&self) {
        if !self.closed.replace(true) {
            self.stop.notify_one();
            self.wake.notify_one();
        }
    }
}

/// A subscription of a client.
#[derive(Debug)]
pub(crate) struct Sub {
    pub(crate) subject: Box<[u8]>,
    pub(crate) queue: Option<Box<[u8]>>,
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Close {
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
    /// Sent its `CONNECT`.
    connected: bool,
    /// Got its first `PONG` after the `CONNECT`.
    ponged: bool,
}

/// Runs a client connection that reached lane `index`.
pub(crate) async fn run(shared: Arc<Shared>, index: usize, stream: Stream) {
    let Some(lane) = lane::get(shared.id, index) else {
        return;
    };
    let ip = peer_ip(&stream);
    let _ = stream.drive(ConnDriver { lane, ip }).await;
}

/// The client's IP address, as text.
fn peer_ip(stream: &Stream) -> String {
    match stream {
        Stream::Tcp(s) => s
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

struct ConnDriver {
    lane: Rc<Lane>,
    ip: String,
}

impl Driver for ConnDriver {
    type Output = ();

    fn run<R, W>(self, reader: R, writer: W) -> impl Future<Output = ()>
    where
        R: AsyncRead + Unpin + 'static,
        W: AsyncWrite + Unpin + 'static,
    {
        serve(self.lane, self.ip, reader, writer)
    }
}

async fn serve<R, W>(lane: Rc<Lane>, ip: String, mut r: R, w: W)
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
{
    let client = Rc::new(Client::new(lane.shared.next_client()));
    handshake::info(
        &lane.shared,
        client.id,
        &ip,
        false,
        &mut client.out.borrow_mut(),
    );
    let writer = tokio::task::spawn_local(write::writer(client.clone(), w));
    client.wake_writer();
    let fwd = (0..lane.lanes()).map(|_| Out::default()).collect();
    let mut conn = Conn {
        lane,
        client,
        opts: handshake::ClientOpts::default(),
        stalled: None,
        fwd,
        unfenced: false,
        ip,
        connected: false,
        ponged: false,
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
        if !self.connected || std::mem::replace(&mut self.ponged, true) {
            return;
        }
        if self.opts.protocol >= 1 {
            let mut out = self.client.out.borrow_mut();
            handshake::info(&self.lane.shared, self.client.id, &self.ip, true, &mut out);
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
        self.lane.flush();
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
        Close::Parse(ParseError::ControlLine) => Some("Maximum Control Line Exceeded"),
        Close::Refused(text) => Some(text),
        Close::Parse(ParseError::Args(_) | ParseError::Size(_) | ParseError::HeaderSize)
        | Close::Lost
        | Close::Kicked
        | Close::Connect
        | Close::NoHeaders => None,
        Close::Parse(_) => Some("Unknown Protocol Operation"),
    }
}
