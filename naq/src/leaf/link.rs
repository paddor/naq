//! One leaf node link: the handshake with the hub, then the link until it
//! ends.

use std::rc::Rc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use naq_proto::client::{Limits, Pub};
use naq_proto::encode;
use naq_proto::leaf::{self, LeafOp, Parsed};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use super::{Ended, HubUrl, LinkSide, side};
use crate::conn::{self, Client};
use crate::lane::{Lane, Out, Routing};

/// Time to connect to a hub.
const DIAL: Duration = Duration::from_secs(1);
/// Time the hub has to send its first `INFO`.
const FIRST_INFO: Duration = Duration::from_secs(1);
/// Time the hub has to answer the `CONNECT` with an `INFO`.
const CONNECT_INFO: Duration = Duration::from_secs(2);
/// The wait after an error that says the link loops.
const LOOP_DELAY: Duration = Duration::from_secs(30);
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
    info_on_connect: bool,
    connect_info: bool,
}

/// The leaf's `CONNECT`. Without `compress_mode`, the hub stays
/// uncompressed.
#[derive(Debug, Serialize)]
struct Connect<'a> {
    version: &'a str,
    name: &'a str,
    headers: bool,
    remote_account: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pass: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_token: Option<&'a str>,
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

/// A link's read side.
struct Link<'l> {
    lane: &'l Rc<Lane>,
    r: OwnedReadHalf,
    buf: BytesMut,
    limits: Limits,
    /// Messages of the hub for each other lane, from the last read.
    fwd: Box<[Out]>,
    /// A subscriber past the stall mark.
    stalled: Option<Rc<Client>>,
}

/// Dials the hub at `url` for remote `remote`, serves the link and returns
/// how it ended.
pub(super) async fn session(lane: &Rc<Lane>, remote: usize, url: &HubUrl) -> Ended {
    let dial = timeout(DIAL, TcpStream::connect((url.host.as_str(), url.port)));
    let Ok(Ok(stream)) = dial.await else {
        return Ended::Unreached;
    };
    let _ = stream.set_nodelay(true);
    let (r, mut w) = stream.into_split();
    let opts = &lane.shared.opts;
    let mut link = Link {
        lane,
        r,
        buf: lane.reads.take(conn::READ_CHUNK),
        // `nats-server` allows a leaf link 16 control lines.
        limits: Limits {
            max_control_line: opts.max_control_line.saturating_mul(16),
            max_payload: opts.max_payload,
        },
        fwd: (0..lane.lanes()).map(|_| Out::default()).collect(),
        stalled: None,
    };
    let delay = match link.handshake(remote, url, &mut w).await {
        Ok(headers) => link.serve(remote, w, headers).await,
        Err(delay) => delay,
    };
    Ended::Closed { delay }
}

impl Link<'_> {
    /// The hub's `INFO`, the `CONNECT`, and the `INFO` that answers it.
    /// Returns whether the link carries header blocks.
    async fn handshake(
        &mut self,
        remote: usize,
        url: &HubUrl,
        w: &mut OwnedWriteHalf,
    ) -> Result<bool, End> {
        let info = timeout(FIRST_INFO, self.info(w))
            .await
            .map_err(|_| End::ZERO)??;
        if info.client_id == 0 || (!info.info_on_connect && info.leafnode_urls.is_empty()) {
            // A client port, not a leaf node port.
            return Err(End::ZERO);
        }
        if let Some(text) = info.cluster.as_deref().and_then(cluster_error) {
            let mut out = Vec::new();
            encode::err(&mut out, text);
            let _ = w.write_all(&out).await;
            return Err(End::ZERO);
        }
        if info.tls_required {
            // TLS to hubs comes later.
            return Err(End::ZERO);
        }
        let opts = &self.lane.shared.opts;
        let account = opts.remotes[remote].account.as_deref().unwrap_or("$G");
        let token = url.pass.is_none().then_some(url.user.as_deref()).flatten();
        let connect = Connect {
            version: env!("CARGO_PKG_VERSION"),
            name: &opts.server_name,
            headers: info.headers,
            remote_account: account,
            user: url.user.as_deref(),
            pass: url.pass.as_deref(),
            // A user without a password is a token too, as `nats-server`
            // sends it.
            auth_token: token,
        };
        let mut out = Vec::new();
        leaf::connect(&mut out, &serde_json::to_vec(&connect).unwrap_or_default());
        w.write_all(&out).await.map_err(|_| End::ZERO)?;
        let answer = timeout(CONNECT_INFO, self.info(w))
            .await
            .map_err(|_| End::ZERO)??;
        if !answer.connect_info {
            return Err(End::ZERO);
        }
        Ok(info.headers)
    }

    /// Reads up to the next `INFO`, answering `PING`s on the way.
    async fn info(&mut self, w: &mut OwnedWriteHalf) -> Result<HubInfo, End> {
        loop {
            match leaf::parse(&self.buf, &self.limits) {
                Ok(Parsed::Op(op, used)) => {
                    let info = match op {
                        LeafOp::Info(json) => {
                            Some(serde_json::from_slice(json).map_err(|_| End::ZERO)?)
                        }
                        LeafOp::Ping => {
                            w.write_all(encode::PONG).await.map_err(|_| End::ZERO)?;
                            None
                        }
                        LeafOp::Err(text) => return Err(err_delay(text)),
                        _ => None,
                    };
                    self.buf.advance(used);
                    if let Some(info) = info {
                        return Ok(info);
                    }
                }
                Ok(Parsed::Partial(need)) => self.read(need).await?,
                Err(_) => return Err(End::ZERO),
            }
        }
    }

    /// Reads more, for an operation of `need` bytes if known.
    async fn read(&mut self, need: Option<usize>) -> Result<(), End> {
        conn::make_room(&mut self.buf, need, &self.lane.reads);
        match self.r.read_buf(&mut self.buf).await {
            Ok(0) | Err(_) => Err(End::ZERO),
            Ok(_) => Ok(()),
        }
    }

    /// Serves the established link of remote `remote` until it ends: tells
    /// the hub of local interest, answers and sends `PING`s, and notes what
    /// the hub says.
    async fn serve(&mut self, remote: usize, w: OwnedWriteHalf, headers: bool) -> End {
        let shared = &self.lane.shared;
        let name = shared.opts.remotes[remote]
            .account
            .as_deref()
            .unwrap_or("$G");
        // Known to exist: the options were checked.
        let account = shared.accounts.iter().position(|a| a == name).unwrap_or(0) as u32;
        let client = Rc::new(Client::new(shared.next_client()));
        client.account.set(account);
        let mut writer: JoinHandle<()> = tokio::task::spawn_local(crate::conn::writer(
            client.clone(),
            w,
            shared.opts.write_deadline,
            || (),
        ));
        let side = Rc::new(LinkSide::new(account, client.clone(), headers));
        let lds = shared.lds[account as usize].as_bytes();
        side.snapshot(&self.lane.index(account).borrow(), lds);
        self.lane.links.borrow_mut().push(side.clone());
        self.lane.mark(&client);
        let end = self.read_loop(&side, lds).await;
        self.lane.links.borrow_mut().retain(|l| l.id != side.id);
        side.forget_hub(self.lane);
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
            lane.ship_reads(&mut self.fwd, &mut buf, at, side.account)
                .await;
            let need = match stop {
                Ok(need) => need,
                Err(end) => return end,
            };
            // A subscriber past the stall mark slows the hub to its pace.
            if let Some(sub) = self.stalled.take() {
                conn::stall(&sub, mark).await;
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
                n = self.r.read_buf(&mut buf) => match n {
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
            LeafOp::Sub(i) if i.subject == lds => {
                // Our own subject came back: the links loop.
                let account = &self.lane.shared.accounts[client.account.get() as usize];
                self.send_err(
                client,
                &format!("Loop detected for leafnode account={account:?}. Delaying attempt to reconnect for 30s"),
            );
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
        lane.tally.took(len);
        side.client.tally.took(len);
        if side::denied(m.subject) {
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
        let mut r = Routing::new(lane, &mut self.fwd, &p, buf, side.id).listed(m);
        r.route(&found);
        if let Some(s) = r.stalled {
            self.stalled = Some(s);
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

/// How long to wait before dialing again after the hub sent `-ERR text`.
fn err_delay(text: &[u8]) -> End {
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
