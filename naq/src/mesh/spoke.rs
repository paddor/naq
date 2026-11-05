//! naq hubs this server dials as a leaf, over OMQ: a control connection
//! each, with a routing identity of its own for every connection, and data
//! channels to every lane of the hub.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use naq_proto::peer::{self, Control, Hello, Role};
use omq_tokio::{MonitorEvent, MonitorStream, Socket, SocketType};

use super::control::{reachable, reachable_url};
use super::interest::{Change, Heard};
use super::tell::{self, BEAT, Item, Other, Sink};
use super::told::Told;
use super::{Mesh, endpoint, resync, socket_options};
use crate::lane::Control as LaneControl;
use crate::leaf::{HubUrl, url};
use crate::server::Shared;

/// How long a hub has to say `Hello` on a new connection, before the next
/// URL is tried.
const GREET: Duration = Duration::from_secs(3);

/// A naq hub dialed as a leaf.
#[derive(Debug)]
pub(crate) struct Hub {
    pub(crate) slot: u16,
    /// Its remote, by index.
    remote: usize,
    /// The local account the link binds.
    pub(crate) account: u32,
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Its `Hello` came, and the connection holds.
    pub(crate) up: bool,
    pub(crate) name: String,
    /// Its interest, as applied.
    pub(crate) heard: Heard,
    /// What it is told, kept up while it is down too.
    pub(crate) told: Rc<Told>,
    /// Its ID in `/leafz`.
    pub(crate) link: u64,
}

impl Hub {
    /// The hub of remote `remote` of `shared`'s server, a naq one, in slot
    /// `slot`, told by a teller of start `epoch`.
    pub(super) fn new(shared: &Shared, remote: usize, slot: u16, epoch: u64) -> Hub {
        let r = &shared.opts.remotes[remote];
        // Valid: the options were checked.
        let url = r.urls.first().and_then(|u| HubUrl::parse(u).ok());
        let (host, port) = url.map(|u| (u.host, u.port)).unwrap_or_default();
        let name = r.account.as_deref().unwrap_or("$G");
        // Known to exist: the options were checked.
        let account = shared.accounts.iter().position(|a| a == name).unwrap_or(0);
        Hub {
            slot,
            remote,
            // Accounts are few: their count fits.
            account: account as u32,
            host,
            port,
            up: false,
            name: String::new(),
            heard: Heard::default(),
            told: Rc::new(Told::new(epoch, shared.accounts.clone(), Rc::default())),
            link: shared.next_client(),
        }
    }
}

/// Dials hub `at` of `mesh` again and again, at each of its URLs in turn,
/// with a new routing identity for every connection, and serves each until
/// it is gone. Once a hub said where the leafs of its cluster dial, those
/// URLs come first, as `nats-server` orders them.
pub(super) async fn dial(shared: Arc<Shared>, mesh: Rc<Mesh>, at: usize) {
    let Some(lane) = crate::lane::get(shared.id, 0) else {
        return;
    };
    let remote = mesh.hubs.borrow()[at].remote;
    let r = &shared.opts.remotes[remote];
    // Valid: the options were checked.
    let configured: Vec<HubUrl> = r
        .urls
        .iter()
        .filter_map(|u| HubUrl::parse(u).ok())
        .collect();
    let mut urls: VecDeque<HubUrl> = configured.iter().cloned().collect();
    if !r.no_randomize {
        for i in (1..urls.len()).rev() {
            let j = lane.below(i as u64 + 1) as usize;
            urls.swap(i, j);
        }
    }
    let ctx = omq_tokio::Context::current();
    let interval = shared.opts.leaf_reconnect;
    let mut n = 0u64;
    loop {
        let Some(url) = urls.pop_front() else {
            return;
        };
        urls.push_back(url.clone());
        n += 1;
        let id = format!("{}/{remote}/{n}", shared.server_id);
        let s = ctx.socket(SocketType::Dealer, socket_options(id.clone().into()));
        let events = s.monitor();
        let mut found = None;
        if s.connect(endpoint(&url.host, url.port)).await.is_ok() {
            {
                let mut hubs = mesh.hubs.borrow_mut();
                hubs[at].host.clone_from(&url.host);
                hubs[at].port = url.port;
            }
            let link = Link {
                shared: &shared,
                mesh: &mesh,
                at,
                id: id.into(),
                s: &s,
                found: RefCell::new(None),
            };
            link.serve(events).await;
            link.down();
            found = link.found.take();
        }
        let _ = s.close().await;
        let wait = match found {
            Some(found) => {
                urls = url::rebuild(&found, &configured).into();
                interval
            }
            // Some jitter, so leafs do not dial a hub in step.
            None => interval + interval.mul_f64(lane.below(1000) as f64 / 1000.0),
        };
        tokio::time::sleep(wait).await;
    }
}

/// One connection to a hub.
struct Link<'a> {
    shared: &'a Arc<Shared>,
    mesh: &'a Rc<Mesh>,
    /// The hub, by index in `mesh.hubs`.
    at: usize,
    /// The connection's routing identity.
    id: Bytes,
    s: &'a Socket,
    /// Where the leafs of the hub's cluster dial, once it said.
    found: RefCell<Option<Vec<String>>>,
}

impl Link<'_> {
    /// Says `Hello` once the connection is up, links the hub once it says
    /// its own, tells it of interest and takes its own, until the
    /// connection is gone, or until it fails or the hub says nothing in
    /// time.
    async fn serve(&self, mut events: MonitorStream) {
        let greet = tokio::time::sleep(GREET);
        tokio::pin!(greet);
        let told = self.mesh.hubs.borrow()[self.at].told.clone();
        let other = Rc::new(Other::new(Sink::Dealer(self.s.clone()), told.clone()));
        let _stop = Stop(other.clone());
        tokio::task::spawn_local(tell::send(other.clone(), || {}));
        let mut beat = tokio::time::interval(BEAT);
        loop {
            // Cancel-safe: a dropped receive takes no message or event, a
            // dropped `notified` keeps its permit, and the interval and the
            // sleep keep their deadlines.
            tokio::select! {
                ev = events.recv() => match ev {
                    Ok(MonitorEvent::HandshakeSucceeded { .. })
                    | Err(omq_tokio::MonitorRecvError::Lagged(_)) => {
                        let _ = self.s.send(omq_tokio::Message::single(self.hello())).await;
                    }
                    Ok(
                        MonitorEvent::Disconnected { .. }
                        | MonitorEvent::ConnectDelayed { .. }
                        | MonitorEvent::HandshakeFailed { .. },
                    )
                    | Err(_) => return,
                    Ok(_) => {}
                },
                () = &mut greet, if !self.is_up() => return,
                msg = self.s.recv() => {
                    let Ok(msg) = msg else { return };
                    let Ok(bytes) = msg.into_bytes() else { continue };
                    if let Some(answer) = self.take(&bytes, &other) {
                        let _ = self.s.send(omq_tokio::Message::single(answer)).await;
                    }
                }
                () = told.wake.notified() => {
                    if self.is_up() {
                        other.tell(false);
                    } else {
                        // Its snapshot carries them.
                        told.take();
                    }
                }
                _ = beat.tick() => {
                    if self.is_up() {
                        other.tell(true);
                    }
                }
            }
        }
    }

    fn is_up(&self) -> bool {
        self.mesh.hubs.borrow()[self.at].up
    }

    /// This server's `Hello` to the hub, as its leaf.
    fn hello(&self) -> Bytes {
        let shared = self.shared;
        let account = self.mesh.hubs.borrow()[self.at].account;
        let cluster = shared.opts.cluster.as_ref().map_or("", |c| &c.name);
        let mut out = Vec::new();
        Control::Hello(Hello {
            role: Role::Leaf,
            account: shared.accounts[account as usize].as_bytes(),
            epoch: self.mesh.epoch,
            server_id: shared.server_id.as_bytes(),
            name: shared.opts.server_name.as_bytes(),
            cluster: cluster.as_bytes(),
            data: b"",
            client_urls: b"",
            leaf_urls: b"",
        })
        .encode(&mut out);
        out.into()
    }

    /// Acts on message `msg` of the hub, told by `other`. Returns what to
    /// answer, if anything.
    fn take(&self, msg: &[u8], other: &Other) -> Option<Bytes> {
        let c = peer::decode(msg).ok()?;
        match &c {
            Control::Hello(h) if h.role == Role::Hub => self.met(h, other),
            Control::Hello(_) => return None,
            Control::Resync => {
                other.push(Item::Snapshot);
                return None;
            }
            _ => {}
        }
        let mut hubs = self.mesh.hubs.borrow_mut();
        let hub = &mut hubs[self.at];
        let (slot, account) = (hub.slot, hub.account);
        let shared = self.shared;
        let lost = hub
            .heard
            .take(&c, &mut |ch| interest(shared, slot, account, ch));
        lost.then(resync)
    }

    /// Links the hub, which said `Hello` `h`: in its slot on every lane,
    /// with data channels to its lanes; and tells it of interest anew.
    fn met(&self, h: &Hello<'_>, other: &Other) {
        let (slot, account, host) = {
            let mut hubs = self.mesh.hubs.borrow_mut();
            let hub = &mut hubs[self.at];
            hub.up = true;
            hub.name = String::from_utf8_lossy(h.name).into_owned();
            (hub.slot, hub.account, hub.host.clone())
        };
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let endpoints: Vec<String> = peer::words(h.data)
            .map(|e| reachable(&text(e), &host))
            .collect();
        let found = peer::words(h.leaf_urls)
            .map(|u| reachable_url(&text(u), &host))
            .collect();
        *self.found.borrow_mut() = Some(found);
        for tx in &*self.shared.lanes {
            tx.control(LaneControl::Link {
                slot,
                id: self.id.to_vec().into(),
                cluster: h.cluster.into(),
                account,
            });
            tx.control(LaneControl::HubData {
                slot,
                id: self.id.to_vec().into(),
                endpoints: endpoints.clone(),
            });
        }
        other.greet(None);
    }

    /// The hub is gone: its interest, its data channels, its slot.
    fn down(&self) {
        let mut hubs = self.mesh.hubs.borrow_mut();
        let hub = &mut hubs[self.at];
        let (slot, account) = (hub.slot, hub.account);
        let shared = self.shared;
        hub.heard
            .forget(&mut |ch| interest(shared, slot, account, ch));
        hub.up = false;
        drop(hubs);
        for tx in &*shared.lanes {
            tx.control(LaneControl::Unlink { slot });
        }
    }
}

/// Stops a sender when dropped.
struct Stop(Rc<Other>);

impl Drop for Stop {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Sets the interest of the hub in slot `slot` of a link that binds
/// `account` on every lane, as change `c` says. Its account name is the
/// hub's.
fn interest(shared: &Shared, slot: u16, account: u32, (_, subject, queue, weight): Change<'_>) {
    for tx in &*shared.lanes {
        tx.control(LaneControl::Server {
            account,
            subject: subject.into(),
            queue: queue.map(Into::into),
            server: slot,
            weight,
        });
    }
}
