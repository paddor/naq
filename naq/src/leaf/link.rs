//! One leaf node link: the handshake with the hub, then the link until it
//! ends.

use std::rc::Rc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use naq_proto::client::Limits;
use naq_proto::encode;
use naq_proto::leaf::{self, LeafOp, Parsed};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use super::{Ended, HubUrl};
use crate::conn::Client;
use crate::lane::Lane;

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
/// Bytes a read may fill at least.
const READ_ROOM: usize = 16 << 10;
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

/// A link's read side.
struct Link<'l> {
    lane: &'l Rc<Lane>,
    r: OwnedReadHalf,
    buf: BytesMut,
    limits: Limits,
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
        buf: BytesMut::with_capacity(READ_ROOM),
        // `nats-server` allows a leaf link 16 control lines.
        limits: Limits {
            max_control_line: opts.max_control_line.saturating_mul(16),
            max_payload: opts.max_payload,
        },
    };
    let delay = match link.handshake(remote, url, &mut w).await {
        Ok(()) => link.serve(w).await,
        Err(delay) => delay,
    };
    Ended::Closed { delay }
}

impl Link<'_> {
    /// The hub's `INFO`, the `CONNECT`, and the `INFO` that answers it.
    async fn handshake(
        &mut self,
        remote: usize,
        url: &HubUrl,
        w: &mut OwnedWriteHalf,
    ) -> Result<(), End> {
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
        Ok(())
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
        let room = need.map_or(READ_ROOM, |n| {
            n.saturating_sub(self.buf.len()).max(READ_ROOM)
        });
        self.buf.reserve(room);
        match self.r.read_buf(&mut self.buf).await {
            Ok(0) | Err(_) => Err(End::ZERO),
            Ok(_) => Ok(()),
        }
    }

    /// Serves the established link until it ends: answers and sends
    /// `PING`s, and notes what the hub says.
    async fn serve(&mut self, w: OwnedWriteHalf) -> End {
        let shared = &self.lane.shared;
        let client = Rc::new(Client::new(shared.next_client()));
        let mut writer: JoinHandle<()> = tokio::task::spawn_local(crate::conn::writer(
            client.clone(),
            w,
            shared.opts.write_deadline,
            || (),
        ));
        let end = self.read_loop(&client).await;
        client.close();
        if timeout(LINGER, &mut writer).await.is_err() {
            writer.abort();
        }
        end
    }

    async fn read_loop(&mut self, client: &Rc<Client>) -> End {
        let opts = &self.lane.shared.opts;
        let interval = opts.ping_interval;
        let mut pings_out = 0;
        let mut delay = End::ZERO;
        let timer = tokio::time::sleep(interval);
        tokio::pin!(timer);
        loop {
            loop {
                match leaf::parse(&self.buf, &self.limits) {
                    Ok(Parsed::Op(op, used)) => {
                        match op {
                            LeafOp::Ping => self.send(client, encode::PONG),
                            LeafOp::Pong => pings_out = 0,
                            LeafOp::Err(text) => {
                                delay = delay.max(err_delay(text));
                                if delay == LOOP_DELAY {
                                    return delay;
                                }
                            }
                            LeafOp::Connect(_) => return delay,
                            // Interest and messages come with the routing
                            // across the link.
                            _ => {}
                        }
                        self.buf.advance(used);
                    }
                    Ok(Parsed::Partial(need)) => {
                        let room = need.map_or(READ_ROOM, |n| {
                            n.saturating_sub(self.buf.len()).max(READ_ROOM)
                        });
                        self.buf.reserve(room);
                        break;
                    }
                    Err(_) => return delay,
                }
            }
            self.lane.flush();
            // Cancel-safe: a dropped read took no bytes, a dropped
            // `notified` passes its wake on, and the timer keeps its deadline.
            tokio::select! {
                biased;
                () = client.stopped() => return delay,
                () = &mut timer => {
                    if pings_out >= opts.max_pings_out {
                        self.send_err(client, "Stale Connection");
                        return delay;
                    }
                    pings_out += 1;
                    self.send(client, encode::PING);
                    timer.as_mut().reset(Instant::now() + interval);
                }
                n = self.r.read_buf(&mut self.buf) => match n {
                    Ok(0) | Err(_) => return delay,
                    Ok(_) => {}
                },
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
