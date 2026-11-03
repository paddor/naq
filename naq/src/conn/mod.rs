//! One client connection: `INFO`, the read loop and the writer.

mod handshake;
mod read;
mod write;

pub(crate) use read::stall;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use naq_proto::client::ParseError;
use naq_proto::encode;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use zzq_tokio::transport::{Driver, Stream};

use crate::lane::{self, Fwd, Lane};
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
    closed: Cell<bool>,
    /// Wakes the writer.
    wake: Notify,
    /// The writer took the output: room for publishers that wait.
    drained: Notify,
    /// Stops the read loop.
    stop: Notify,
}

impl Client {
    fn new(id: u64) -> Client {
        Client {
            id,
            out: RefCell::default(),
            dirty: Cell::new(false),
            headers: Cell::new(false),
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

    /// Closes the connection once the writer wrote what is queued.
    pub(crate) fn close(&self) {
        if !self.closed.replace(true) {
            self.stop.notify_one();
            self.wake.notify_one();
        }
    }
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
}

/// The reader's side of a connection.
#[derive(Debug)]
struct Conn {
    lane: Rc<Lane>,
    client: Rc<Client>,
    /// Subscriptions by SID, with their subject.
    subs: HashMap<Box<[u8]>, Box<[u8]>>,
    opts: handshake::ClientOpts,
    /// A subscriber this connection fed is past the stall mark.
    stalled: Option<Rc<Client>>,
    /// Publishes for other lanes from the current read, by lane.
    fwd: Vec<Vec<Fwd>>,
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
    let fwd = (0..lane.lanes()).map(|_| Vec::new()).collect();
    let mut conn = Conn {
        lane,
        client,
        subs: HashMap::new(),
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
        {
            let mut index = self.lane.index.borrow_mut();
            for (sid, subject) in self.subs.drain() {
                index.remove(&subject, self.client.id, &sid);
                self.lane.announce(&subject, false);
            }
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
        Close::Parse(ParseError::Args(_) | ParseError::Size(_) | ParseError::HeaderSize)
        | Close::Lost
        | Close::Kicked
        | Close::Connect
        | Close::NoHeaders => None,
        Close::Parse(_) => Some("Unknown Protocol Operation"),
    }
}
