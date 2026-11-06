//! One leaf node link: the handshake with the hub, then the link until it
//! ends.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use naq_proto::client::{Limits, Pub};
use naq_proto::encode;
use naq_proto::leaf::{self, LeafOp, Parsed};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use super::{Ended, Facts, HubUrl, LinkSide, Told, creds, side};
use crate::Rules;
use crate::conn::{self, Client};
use crate::lane::{Lane, Outs, Routing, Source};
use crate::perms::LinkPerms;
use crate::ws;

/// Time to connect to a hub.
const DIAL: Duration = Duration::from_secs(1);
/// Time the hub has to send its first `INFO`.
const FIRST_INFO: Duration = Duration::from_secs(1);
/// Time the hub has to answer the `CONNECT` with an `INFO`.
const CONNECT_INFO: Duration = Duration::from_secs(2);
/// The wait after an error that says the link loops.
pub(crate) const LOOP_DELAY: Duration = Duration::from_secs(30);
/// The wait after a hub refuses this server's version.
const VERSION_DELAY: Duration = Duration::from_secs(5);
/// How long the writer may take to write what is left at the end.
const LINGER: Duration = Duration::from_secs(1);

/// What a link reads of the hub's `INFO`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
#[expect(clippy::struct_excessive_bools, reason = "the flags of the hub's INFO")]
struct HubInfo {
    client_id: u64,
    cluster: Option<String>,
    headers: bool,
    tls_required: bool,
    leafnode_urls: Vec<String>,
    ws_connect_urls: Vec<String>,
    info_on_connect: bool,
    connect_info: bool,
    nonce: String,
    server_name: String,
    /// What the link may send to the hub, in `connect_info`.
    export: Option<Acl>,
    /// What it may take from the hub.
    import: Option<Acl>,
}

/// Subjects allowed, and those denied among them, as an `INFO` gives them.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Acl {
    allow: Option<Vec<String>>,
    deny: Vec<String>,
}

impl From<Option<Acl>> for Rules {
    fn from(a: Option<Acl>) -> Rules {
        let a = a.unwrap_or_default();
        Rules {
            allow: a.allow,
            deny: a.deny,
        }
    }
}

/// What the handshake settled.
struct Terms {
    /// The link carries header blocks.
    headers: bool,
    perms: Option<LinkPerms>,
    facts: Facts,
}

/// The leaf's `CONNECT`. Without `compress_mode`, the hub stays
/// uncompressed.
#[derive(Debug, Serialize)]
struct Connect<'a> {
    version: &'a str,
    name: &'a str,
    /// The cluster of this server, if one: the hub keeps interest and
    /// messages of a cluster from its other servers' links.
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<&'a str>,
    headers: bool,
    remote_account: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pass: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
    /// The remote's `deny_imports`, which the hub sends the link nothing on.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    deny_pub: &'a [String],
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    isolate: bool,
}

/// Why a link ends: the wait the hub asked for, beyond the interval.
type End = Duration;

/// What an established link keeps track of.
#[derive(Debug, Default)]
struct State {
    /// `PING`s the hub has not answered.
    pings_out: u32,
    /// The wait an `-ERR` of the hub asked for.
    delay: End,
}

/// A link's read side: the whole stream until the handshake is done.
struct Link<'l, R> {
    lane: &'l Rc<Lane>,
    io: R,
    buf: BytesMut,
    limits: Limits,
    /// Messages of the hub for each other lane, from the last read.
    out: Outs,
    /// A subscriber past the stall mark.
    stalled: Option<Rc<Client>>,
    /// The link as a client of the lane: its output to the hub.
    client: Rc<Client>,
    /// The URLs of the hub's cluster it told of last.
    told: &'l RefCell<Option<Told>>,
}

/// Dials the hub at `url`, one of `urls`, for remote `remote`, serves the
/// link and returns how it ended.
pub(super) async fn session(
    lane: &Rc<Lane>,
    remote: usize,
    url: &HubUrl,
    urls: &[HubUrl],
    told: &RefCell<Option<Told>>,
) -> Ended {
    let dial = timeout(DIAL, TcpStream::connect((url.host.as_str(), url.port)));
    let tcp = match dial.await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => return Ended::Unreached(e.to_string()),
        Err(_) => return Ended::Unreached("i/o timeout".into()),
    };
    let _ = tcp.set_nodelay(true);
    let d = Dial {
        lane,
        remote,
        url,
        urls,
        told,
    };
    let delay = if url.ws.is_some() {
        d.websocket(tcp).await
    } else {
        d.nats(tcp).await
    };
    Ended::Closed { delay }
}

/// A connection to a hub, made for a remote.
struct Dial<'a> {
    lane: &'a Rc<Lane>,
    remote: usize,
    url: &'a HubUrl,
    /// All of the remote's URLs.
    urls: &'a [HubUrl],
    told: &'a RefCell<Option<Told>>,
}

impl Dial<'_> {
    /// The link over `tcp`: TLS comes first, after the hub's first `INFO`,
    /// or not at all, as remote and hub say.
    async fn nats(&self, mut tcp: TcpStream) -> End {
        let (lane, remote, url) = (self.lane, self.remote, self.url);
        let tls = &lane.shared.leaf_tls[remote];
        let mut buf = lane.reads.take(conn::READ_CHUNK);
        if tls.first() {
            return match tls.connect(tcp, url, self.urls).await {
                Some(s) => Link::new(self, s, buf).run(remote, url, None).await,
                None => End::ZERO,
            };
        }
        let limits = limits(lane);
        match timeout(FIRST_INFO, info(&mut tcp, &mut buf, &limits, lane)).await {
            Ok(Ok(first)) if tls.after_info(first.tls_required) => {
                match tls.connect(tcp, url, self.urls).await {
                    Some(s) => Link::new(self, s, buf).run(remote, url, Some(first)).await,
                    None => End::ZERO,
                }
            }
            Ok(Ok(first)) => {
                Link::new(self, tcp, buf)
                    .run(remote, url, Some(first))
                    .await
            }
            Ok(Err(delay)) => delay,
            Err(_) => End::ZERO,
        }
    }

    /// The link over WebSocket frames on `tcp`: TLS first for `wss://` or
    /// a remote with `tls`, then the upgrade. No TLS after `INFO`, as in
    /// `nats-server`.
    async fn websocket(&self, tcp: TcpStream) -> End {
        let (lane, remote, url) = (self.lane, self.remote, self.url);
        let tls = &lane.shared.leaf_tls[remote];
        let buf = lane.reads.take(conn::READ_CHUNK);
        if url.wss || tls.after_info(false) {
            match tls.connect(tcp, url, self.urls).await {
                Some(s) => Link::new(self, s, buf).over_ws(remote, url).await,
                None => End::ZERO,
            }
        } else {
            Link::new(self, tcp, buf).over_ws(remote, url).await
        }
    }
}

/// Limits of a link: `nats-server` allows it 16 control lines.
fn limits(lane: &Lane) -> Limits {
    let opts = &lane.shared.opts;
    Limits {
        max_control_line: opts.max_control_line.saturating_mul(16),
        max_payload: opts.max_payload,
    }
}

/// Writes `bytes` to `io` and flushes them: a WebSocket writer holds a
/// frame until then.
async fn send<S: AsyncWrite + Unpin>(io: &mut S, bytes: &[u8]) -> Result<(), End> {
    io.write_all(bytes).await.map_err(|_| End::ZERO)?;
    io.flush().await.map_err(|_| End::ZERO)
}

/// Reads up to the next `INFO` from `io` into `buf`, answering `PING`s on
/// the way.
async fn info<S>(
    io: &mut S,
    buf: &mut BytesMut,
    limits: &Limits,
    lane: &Lane,
) -> Result<HubInfo, End>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match leaf::parse(buf, limits) {
            Ok(Parsed::Op(op, used)) => {
                let info = match op {
                    LeafOp::Info(json) => {
                        Some(serde_json::from_slice(json).map_err(|_| End::ZERO)?)
                    }
                    LeafOp::Ping => {
                        send(io, encode::PONG).await?;
                        None
                    }
                    LeafOp::Err(text) => return Err(err_delay(text)),
                    _ => None,
                };
                buf.advance(used);
                if let Some(info) = info {
                    return Ok(info);
                }
            }
            Ok(Parsed::Partial(need)) => {
                conn::make_room(buf, need, &lane.reads);
                match io.read_buf(buf).await {
                    Ok(0) | Err(_) => return Err(End::ZERO),
                    Ok(_) => {}
                }
            }
            Err(_) => return Err(End::ZERO),
        }
    }
}

impl<R> Link<'_, R> {
    /// Notes the URLs of the hub's cluster `info` tells of, if any.
    fn learn(&self, info: &HubInfo) {
        if !info.leafnode_urls.is_empty() || !info.ws_connect_urls.is_empty() {
            *self.told.borrow_mut() = Some(Told {
                nats: info.leafnode_urls.clone(),
                ws: info.ws_connect_urls.clone(),
            });
        }
    }
}

impl<'l, S: AsyncRead + AsyncWrite + Unpin + 'static> Link<'l, S> {
    /// A link of `lane` over `io`, with what was read of it in `buf`.
    fn new(d: &Dial<'l>, io: S, buf: BytesMut) -> Self {
        let lane = d.lane;
        Link {
            lane,
            io,
            buf,
            limits: limits(lane),
            out: Outs::new(lane),
            stalled: None,
            client: Rc::new(Client::new(lane.shared.next_client())),
            told: d.told,
        }
    }

    /// Upgrades the link to WebSocket, then the handshake for remote
    /// `remote` and the link over its frames.
    async fn over_ws(mut self, remote: usize, url: &HubUrl) -> End {
        let path = url.ws.as_deref().unwrap_or_default();
        let up = ws::client::upgrade(&mut self.io, &url.host, url.port, path);
        let Ok(Some(pre)) = timeout(FIRST_INFO, up).await else {
            return End::ZERO;
        };
        let max = self.lane.shared.opts.max_payload;
        let Link {
            lane,
            io,
            buf,
            limits,
            out,
            stalled,
            client,
            told,
        } = self;
        let io = ws::client::stream(io, pre, client.clone(), max);
        let link = Link {
            lane,
            io,
            buf,
            limits,
            out,
            stalled,
            client,
            told,
        };
        link.run(remote, url, None).await
    }

    /// The handshake for remote `remote` with the hub at `url`, after its
    /// `first` INFO if read already, then the link until it ends.
    async fn run(mut self, remote: usize, url: &HubUrl, first: Option<HubInfo>) -> End {
        match self.handshake(remote, url, first).await {
            Ok(terms) => {
                let (mut link, w) = self.split();
                link.serve(remote, w, terms).await
            }
            Err(delay) => delay,
        }
    }

    /// The checks of the hub's `first` INFO, read here unless given, the
    /// `CONNECT`, and the `INFO` that answers it. Returns what they settled.
    async fn handshake(
        &mut self,
        remote: usize,
        url: &HubUrl,
        first: Option<HubInfo>,
    ) -> Result<Terms, End> {
        let info = match first {
            Some(info) => info,
            None => timeout(FIRST_INFO, self.info())
                .await
                .map_err(|_| End::ZERO)??,
        };
        if info.client_id == 0 || (!info.info_on_connect && info.leafnode_urls.is_empty()) {
            // A client port, not a leaf node port.
            return Err(End::ZERO);
        }
        if let Some(text) = info.cluster.as_deref().and_then(cluster_error) {
            let mut out = Vec::new();
            encode::err(&mut out, text);
            let _ = send(&mut self.io, &out).await;
            return Err(End::ZERO);
        }
        let opts = &self.lane.shared.opts;
        let r = &opts.remotes[remote];
        let account = r.account.as_deref().unwrap_or("$G");
        // A file gone or broken ends this dial; the next reads it again.
        let proof = creds::prove(r, &info.nonce).map_err(|_| End::ZERO)?;
        let token = url.pass.is_none().then_some(url.user.as_deref()).flatten();
        let connect = Connect {
            version: env!("CARGO_PKG_VERSION"),
            name: &opts.server_name,
            cluster: opts.cluster.as_ref().map(|c| c.name.as_str()),
            headers: info.headers,
            remote_account: account,
            user: url.user.as_deref(),
            pass: url.pass.as_deref(),
            // A user without a password is a token too, as `nats-server`
            // sends it.
            auth_token: token,
            jwt: proof.jwt,
            nkey: proof.nkey,
            sig: proof.sig,
            deny_pub: &r.deny_imports,
            isolate: r.request_isolation,
        };
        let mut out = Vec::new();
        leaf::connect(&mut out, &serde_json::to_vec(&connect).unwrap_or_default());
        send(&mut self.io, &out).await?;
        let answer = timeout(CONNECT_INFO, self.info())
            .await
            .map_err(|_| End::ZERO)??;
        if !answer.connect_info {
            return Err(End::ZERO);
        }
        self.learn(&info);
        self.learn(&answer);
        Ok(Terms {
            headers: info.headers,
            perms: side::perms(answer.export.into(), answer.import.into(), r),
            facts: Facts {
                name: info.server_name,
                ip: url.host.clone(),
                port: url.port,
                websocket: url.ws.is_some(),
                isolated: r.request_isolation,
            },
        })
    }

    /// Reads up to the next `INFO`, answering `PING`s on the way.
    async fn info(&mut self) -> Result<HubInfo, End> {
        info(&mut self.io, &mut self.buf, &self.limits, self.lane).await
    }

    /// The link's read side, and its write side for the writer.
    fn split(self) -> (Link<'l, ReadHalf<S>>, WriteHalf<S>) {
        let (r, w) = tokio::io::split(self.io);
        let link = Link {
            lane: self.lane,
            io: r,
            buf: self.buf,
            limits: self.limits,
            out: self.out,
            stalled: self.stalled,
            client: self.client,
            told: self.told,
        };
        (link, w)
    }
}

impl<R: AsyncRead + Unpin> Link<'_, R> {
    /// Serves the established link of remote `remote` until it ends: tells
    /// the hub of local interest, answers and sends `PING`s, routes what
    /// the hub sends, and notes what it says.
    async fn serve<W: AsyncWrite + Unpin + 'static>(
        &mut self,
        remote: usize,
        w: W,
        terms: Terms,
    ) -> End {
        let shared = &self.lane.shared;
        let name = shared.opts.remotes[remote]
            .account
            .as_deref()
            .unwrap_or("$G");
        // Known to exist: the options were checked.
        let account = shared.accounts.id(name).unwrap_or(0);
        let client = self.client.clone();
        client.account.set(account);
        self.out.account = account;
        let mut writer: JoinHandle<()> = tokio::task::spawn_local(crate::conn::writer(
            client.clone(),
            w,
            shared.opts.write_deadline,
            || (),
        ));
        let side = Rc::new(LinkSide::new(
            account,
            client.clone(),
            terms.headers,
            terms.perms,
            terms.facts,
        ));
        let lds = shared.accounts.lds(account);
        side.snapshot(
            &self.lane.index(account).borrow(),
            lds,
            self.lane.slots.leafs(),
        );
        self.lane.links.borrow_mut().push(side.clone());
        self.lane.mark(&client);
        let label = format!("{}:{} - lid:{}", side.facts.ip, side.facts.port, client.id);
        shared.log.info(format_args!(
            "{label} - Leafnode connection created for account: {name} "
        ));
        let end = self.read_loop(&side, lds).await;
        self.lane.links.borrow_mut().retain(|l| l.id != side.id);
        side.forget_hub(self.lane);
        let why = client
            .ended()
            .map_or("Client Closed", crate::conn::Close::reason);
        shared.log.info(format_args!(
            "{label} - Leafnode connection closed: {why} - Remote: {}",
            side.facts.name
        ));
        client.close();
        if timeout(LINGER, &mut writer).await.is_err() {
            writer.abort();
        }
        end
    }

    async fn read_loop(&mut self, side: &LinkSide, lds: &[u8]) -> End {
        let lane = self.lane;
        let client = &side.client;
        let opts = &lane.shared.opts;
        let interval = opts.ping_interval;
        let mark = opts.max_pending / 4 * 3;
        let mut st = State::default();
        let mut buf = std::mem::take(&mut self.buf);
        let timer = tokio::time::sleep(interval);
        tokio::pin!(timer);
        loop {
            let (at, stop) = self.parse(&buf, side, lds, &mut st);
            lane.flush();
            lane.expire();
            lane.ship_reads(&mut self.out, &mut buf, at, Source::Hub)
                .await;
            let need = match stop {
                Ok(need) => need,
                Err(end) => return end,
            };
            // A subscriber past the stall mark slows the hub to its pace.
            if let Some(sub) = self.stalled.take() {
                conn::stall(&sub, mark, &lane.shared.events.stalls).await;
            }
            tokio::task::yield_now().await;
            conn::make_room(&mut buf, need, &lane.reads);
            // Cancel-safe: a dropped read took no bytes, a dropped
            // `notified` passes its wake on, and the timer keeps its deadline.
            tokio::select! {
                biased;
                () = client.stopped() => return st.delay,
                () = &mut timer => {
                    if st.pings_out >= opts.max_pings_out {
                        self.send_err(client, "Stale Connection");
                        return st.delay;
                    }
                    st.pings_out += 1;
                    self.send(client, encode::PING);
                    timer.as_mut().reset(Instant::now() + interval);
                }
                n = self.io.read_buf(&mut buf) => match n {
                    Ok(0) | Err(_) => return st.delay,
                    Ok(_) => {}
                },
            }
        }
    }

    /// Acts on the operations at the start of `buf`. Returns the bytes they
    /// took, and the length of the operation after them if known, or how
    /// the link ends.
    fn parse(
        &mut self,
        buf: &[u8],
        side: &LinkSide,
        lds: &[u8],
        st: &mut State,
    ) -> (usize, Result<Option<usize>, End>) {
        let mut at = 0;
        loop {
            match leaf::parse(&buf[at..], &self.limits) {
                Ok(Parsed::Op(LeafOp::Msg(m), used)) => {
                    self.inbound(&m, buf, side);
                    at += used;
                }
                Ok(Parsed::Op(op, used)) => {
                    if let Err(end) = self.handle(op, side, lds, st) {
                        return (at, Err(end));
                    }
                    at += used;
                }
                Ok(Parsed::Partial(need)) => return (at, Ok(need)),
                Err(_) => return (at, Err(st.delay)),
            }
        }
    }

    /// Acts on what the hub sent but messages. `Err` ends the link.
    fn handle(
        &self,
        op: LeafOp<'_>,
        side: &LinkSide,
        lds: &[u8],
        st: &mut State,
    ) -> Result<(), End> {
        let client = &side.client;
        match op {
            LeafOp::Ping => self.send(client, encode::PONG),
            LeafOp::Pong => st.pings_out = 0,
            LeafOp::Err(text) => {
                st.delay = st.delay.max(err_delay(text));
                if st.delay == LOOP_DELAY {
                    return Err(st.delay);
                }
            }
            LeafOp::Connect(_) => return Err(st.delay),
            // News of the hub's cluster.
            LeafOp::Info(json) => {
                if let Ok(info) = serde_json::from_slice::<HubInfo>(json) {
                    self.learn(&info);
                }
            }
            LeafOp::Sub(i) if i.subject == lds => {
                // Our own subject came back: the links loop.
                let account = self.lane.shared.accounts.name(client.account.get());
                self.send_err(client, &loop_error(account));
                return Err(LOOP_DELAY);
            }
            LeafOp::Sub(i) => side.hub_interest(self.lane, &i, true),
            LeafOp::Unsub(i) => side.hub_interest(self.lane, &i, false),
            // A later `INFO`, `+OK`: nothing to act on. Messages were
            // routed already.
            _ => {}
        }
        Ok(())
    }

    /// Routes message `m` of the hub, which lies in `buf`, as the hub
    /// asks: to every plain subscription, to one member of each queue
    /// group it lists, and to other links, but never back to this one.
    fn inbound(&mut self, m: &leaf::Msg<'_>, buf: &[u8], side: &LinkSide) {
        let lane = self.lane;
        let len = m.payload.len() + m.headers.map_or(0, <[u8]>::len);
        lane.peers.took(len);
        side.client.tally.took(len);
        if side::denied(m.subject) || !side.takes(m.subject) {
            return;
        }
        let p = Pub {
            subject: m.subject,
            reply: m.reply,
            headers: m.headers,
            payload: m.payload,
        };
        let index = lane.index(side.account).borrow();
        let Some(found) = index.matches(p.subject) else {
            return;
        };
        let d = super::for_clients(&p);
        let d = d.as_ref().unwrap_or(&p);
        let mut r = Routing::new(lane, &mut self.out, &p, buf, side.id)
            .by_link(m.queues, d)
            .with_imports();
        r.route(&found);
        let (tapped, skips) = (r.tapped(), r.skips());
        if let Some(stall) = r.stalled {
            self.stalled = Some(stall);
        }
        if tapped {
            let from = crate::imports::service::From {
                client: None,
                skip: side.id,
                source: Source::Hub,
                skips,
            };
            let (_, stall) =
                crate::imports::service::run(lane, &mut self.out, &p, side.account, from);
            if stall.is_some() {
                self.stalled = stall;
            }
        }
    }

    /// Queues `bytes` for the hub.
    fn send(&self, client: &Rc<Client>, bytes: &[u8]) {
        client.out.borrow_mut().extend_from_slice(bytes);
        self.lane.mark(client);
    }

    /// Queues `-ERR 'text'` for the hub.
    fn send_err(&self, client: &Rc<Client>, text: &str) {
        encode::err(&mut *client.out.borrow_mut(), text);
        self.lane.mark(client);
        self.lane.flush();
    }
}

/// The error a leaf sends for the hub's cluster name, if it may not use it.
fn cluster_error(name: &str) -> Option<&'static str> {
    if name.contains(' ') {
        Some("cluster name cannot contain spaces")
    } else if name == "_" {
        Some("cluster name is reserved")
    } else {
        None
    }
}

/// The error a link of `account` that loops ends with, as `nats-server`
/// words it.
pub(crate) fn loop_error(account: &str) -> String {
    format!("Loop detected for leafnode account={account:?}. Delaying attempt to reconnect for 30s")
}

/// How long to wait before dialing again after the hub sent `-ERR text`.
pub(crate) fn err_delay(text: &[u8]) -> End {
    let has = |s: &[u8]| text.windows(s.len()).any(|w| w == s);
    if has(b"Loop detected") || has(b"remote leafnode has same cluster name") {
        LOOP_DELAY
    } else if has(b"minimum version required") {
        VERSION_DELAY
    } else {
        End::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn some_errors_make_the_leaf_wait_longer() {
        assert_eq!(
            err_delay(b"Loop detected for leafnode account=\"$G\"."),
            LOOP_DELAY
        );
        assert_eq!(
            err_delay(b"remote leafnode has same cluster name"),
            LOOP_DELAY
        );
        assert_eq!(
            err_delay(b"connection rejected since minimum version required is \"2.9.0\""),
            VERSION_DELAY
        );
        assert_eq!(err_delay(b"Authorization Violation"), End::ZERO);
    }

    #[test]
    fn cluster_names_with_blanks_or_reserved_are_refused() {
        assert_eq!(
            cluster_error("a b"),
            Some("cluster name cannot contain spaces")
        );
        assert_eq!(cluster_error("_"), Some("cluster name is reserved"));
        assert_eq!(cluster_error("hub"), None);
    }
}
