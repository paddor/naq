//! naq hubs this server dials as a leaf, over OMQ: a control connection
//! each, with a routing identity of its own for every connection, and data
//! channels to every lane of the hub.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use naq_proto::peer::{self, Connect, Control, Hello, Role};
use omq_tokio::{MonitorEvent, MonitorStream, Socket, SocketType};

use super::control::{reachable, reachable_url};
use super::interest::{Change, Heard};
use super::tell::{self, BEAT, Item, Other, Sink};
use super::told::Told;
use super::{Mesh, endpoint, error, resync, socket_options};
use crate::Rules;
use crate::lane::Control as LaneControl;
use crate::leaf::{HubUrl, LOOP_DELAY, err_delay, loop_error, url};
use crate::perms::LinkPerms;
use crate::server::Shared;

/// How long a hub has to say `Hello` on a new connection, before the next
/// URL is tried.
const GREET: Duration = Duration::from_secs(3);

/// A naq hub dialed as a leaf.
#[derive(Debug)]
pub(crate) struct Hub {
    pub(crate) slot: u16,
    /// Its remote.
    remote: Rc<crate::Remote>,
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
    /// What the link carries, by the remote's `deny_exports` and
    /// `deny_imports`, if not all.
    pub(crate) perms: Option<Arc<LinkPerms>>,
    /// It asked for no interest of the hub's other leafs.
    pub(crate) isolated: bool,
}

impl Hub {
    /// The hub of remote `remote`, a naq one, of `shared`'s server, in slot
    /// `slot`, told by a teller of start `epoch`.
    pub(super) fn new(shared: &Shared, remote: &crate::Remote, slot: u16, epoch: u64) -> Hub {
        let r = remote;
        // Valid: the options were checked.
        let url = r.urls.first().and_then(|u| HubUrl::parse(u).ok());
        let (host, port) = url.map(|u| (u.host, u.port)).unwrap_or_default();
        let name = r.account.as_deref().unwrap_or("$G");
        // Known to exist: the options were checked.
        let account = shared.accounts.id(name).unwrap_or(0);
        let told = Rc::new(
            Told::new(epoch, shared.accounts.clone(), Rc::default())
                .stamping(shared.marks.clone(), slot..slot + 1),
        );
        told.pin(account, shared.accounts.lds(account));
        // Its snapshot carries it.
        told.take();
        Hub {
            slot,
            remote: Rc::new(remote.clone()),
            // Accounts are few: their count fits.
            account,
            host,
            port,
            up: false,
            name: String::new(),
            heard: Heard::default(),
            told,
            link: shared.next_client(),
            perms: crate::leaf::perms(Rules::default(), Rules::default(), r).map(Arc::new),
            isolated: r.request_isolation,
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
    let r = mesh.hubs.borrow()[at].remote.clone();
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
    let interval = shared.opts().leaf_reconnect;
    let mut n = 0u64;
    loop {
        let Some(url) = urls.pop_front() else {
            return;
        };
        urls.push_back(url.clone());
        n += 1;
        let id = format!("{}/{at}/{n}", shared.server_id);
        let (found, delay) = connect(&shared, &mesh, at, &url, id).await;
        let wait = match found {
            Some(found) => {
                urls = url::rebuild(&found, &configured).into();
                interval
            }
            // Some jitter, so leafs do not dial a hub in step.
            None => interval + interval.mul_f64(lane.below(1000) as f64 / 1000.0),
        };
        tokio::time::sleep(wait + delay).await;
    }
}

/// Connects to hub `at` of `mesh` at `url`, as routing identity `id`, and
/// serves the link until it is gone. Returns where the leafs of the hub's
/// cluster dial, if it said, and how much longer to wait before the next
/// dial.
async fn connect(
    shared: &Arc<Shared>,
    mesh: &Rc<Mesh>,
    at: usize,
    url: &HubUrl,
    id: String,
) -> (Option<Vec<String>>, Duration) {
    let ctx = omq_tokio::Context::current();
    let s = ctx.socket(SocketType::Dealer, socket_options(id.clone().into()));
    let events = s.monitor();
    let mut ended = (None, Duration::ZERO);
    if s.connect(endpoint(&url.host, url.port)).await.is_ok() {
        {
            let mut hubs = mesh.hubs.borrow_mut();
            hubs[at].host.clone_from(&url.host);
            hubs[at].port = url.port;
        }
        let link = Link {
            shared,
            mesh,
            at,
            id: id.into(),
            s: &s,
            url,
            said: RefCell::new(None),
            greeted: Cell::new(false),
            end: Cell::new(None),
        };
        link.serve(events).await;
        link.down();
        let said = link.said.take();
        ended = (said.map(|s| s.urls), link.end.get().unwrap_or_default());
    }
    let _ = s.close().await;
    ended
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
    /// The URL dialed, with the credentials it holds.
    url: &'a HubUrl,
    /// What the hub said in its `Hello`, once it did.
    said: RefCell<Option<Said>>,
    /// This server logged in and sent its snapshot.
    greeted: Cell<bool>,
    /// Set once the link cannot go on: the wait before the next dial.
    end: Cell<Option<Duration>>,
}

/// What a hub says of itself in its `Hello`.
#[derive(Debug)]
struct Said {
    /// Where each of its lanes takes data.
    endpoints: Vec<String>,
    cluster: Box<[u8]>,
    /// Where the leafs of its cluster dial.
    urls: Vec<String>,
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
                    if self.end.get().is_some() {
                        return;
                    }
                }
                () = told.wake.notified() => {
                    if self.greeted.get() {
                        other.tell(false);
                    } else {
                        // Its snapshot carries them.
                        told.take();
                    }
                }
                _ = beat.tick() => {
                    if self.greeted.get() {
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
        let opts = shared.opts();
        let cluster = opts.cluster.as_ref().map_or("", |c| &c.name);
        let mut out = Vec::new();
        Control::Hello(Hello {
            role: Role::Leaf,
            account: shared.accounts.name(account).as_bytes(),
            epoch: self.mesh.epoch,
            server_id: shared.server_id.as_bytes(),
            name: shared.opts().server_name.as_bytes(),
            cluster: cluster.as_bytes(),
            data: b"",
            client_urls: b"",
            leaf_urls: b"",
            nonce: b"",
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
            Control::Error(why) => {
                self.end.set(Some(err_delay(why)));
                return None;
            }
            // The hub took this server in.
            Control::SnapshotStart { .. } if !self.is_up() => self.linked(),
            _ => {}
        }
        let mut hubs = self.mesh.hubs.borrow_mut();
        let hub = &mut hubs[self.at];
        let (slot, account) = (hub.slot, hub.account);
        let perms = hub.perms.as_deref();
        let shared = self.shared;
        let lds = shared.accounts.lds(account);
        let mut looped = false;
        let lost = hub.heard.take(&c, &mut |ch| {
            looped |= ch.1 == lds && ch.3 > 0;
            interest(shared, slot, account, perms, ch);
        });
        self.mesh.taking.heard(slot, hub.heard.taken());
        if looped {
            // Our own subject came back: the links loop.
            self.end.set(Some(LOOP_DELAY));
            return Some(error(&loop_error(shared.accounts.name(account))));
        }
        lost.then(resync)
    }

    /// Notes what the hub said in `Hello` `h`, and logs in with the nonce it
    /// gave, then tells it of interest anew.
    fn met(&self, h: &Hello<'_>, other: &Other) {
        let host = self.url.host.as_str();
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        self.mesh.hubs.borrow_mut()[self.at].name = text(h.name);
        *self.said.borrow_mut() = Some(Said {
            endpoints: peer::words(h.data)
                .map(|e| reachable(&text(e), host))
                .collect(),
            cluster: h.cluster.into(),
            urls: peer::words(h.leaf_urls)
                .map(|u| reachable_url(&text(u), host))
                .collect(),
        });
        match self.login(h.nonce) {
            Ok(connect) => {
                other.greet(Some(connect));
                self.greeted.set(true);
            }
            Err(_) => self.end.set(Some(Duration::ZERO)),
        }
    }

    /// This server's `Connect`, with the credentials of its URL and its
    /// remote, and `nonce` signed if it has an NKey.
    ///
    /// # Errors
    ///
    /// A seed that cannot sign.
    fn login(&self, nonce: &[u8]) -> Result<Bytes, String> {
        let r = self.mesh.hubs.borrow()[self.at].remote.clone();
        let proof = crate::leaf::prove(&r, &String::from_utf8_lossy(nonce))?;
        let (user, pass, token) = match (&self.url.user, &self.url.pass) {
            (Some(u), Some(p)) => (u.as_str(), p.as_str(), ""),
            (Some(t), None) => ("", "", t.as_str()),
            _ => ("", "", ""),
        };
        let nkey = proof.nkey.unwrap_or_default();
        let sig = proof.sig.unwrap_or_default();
        let deny_pub = r.deny_imports.join(" ");
        let mut out = Vec::new();
        Control::Connect(Connect {
            user: user.as_bytes(),
            pass: pass.as_bytes(),
            token: token.as_bytes(),
            nkey: nkey.as_bytes(),
            sig: sig.as_bytes(),
            deny_pub: deny_pub.as_bytes(),
            isolate: r.request_isolation,
        })
        .encode(&mut out);
        Ok(out.into())
    }

    /// The hub took this server in: it links in the hub's slot on every
    /// lane, with data channels to the hub's lanes.
    fn linked(&self) {
        let (slot, account, perms) = {
            let mut hubs = self.mesh.hubs.borrow_mut();
            let hub = &mut hubs[self.at];
            hub.up = true;
            self.shared.log.info(format_args!(
                "{}:{} - lid:{} - Leafnode connection created for account: {} ",
                hub.host,
                hub.port,
                hub.link,
                self.shared.accounts.name(hub.account)
            ));
            (hub.slot, hub.account, hub.perms.clone())
        };
        crate::sys::conns_changed(self.shared, account);
        let said = self.said.borrow();
        let Some(said) = said.as_ref() else {
            return;
        };
        for tx in &*self.shared.lanes {
            tx.control(LaneControl::Link {
                slot,
                id: self.id.to_vec().into(),
                cluster: said.cluster.clone(),
                account,
                perms: perms.clone(),
            });
            tx.control(LaneControl::HubData {
                slot,
                id: self.id.to_vec().into(),
                endpoints: said.endpoints.clone(),
            });
        }
    }

    /// The hub is gone: its interest, its data channels, its slot.
    fn down(&self) {
        let mut hubs = self.mesh.hubs.borrow_mut();
        let hub = &mut hubs[self.at];
        let (slot, account) = (hub.slot, hub.account);
        let perms = hub.perms.as_deref();
        let shared = self.shared;
        hub.heard
            .forget(&mut |ch| interest(shared, slot, account, perms, ch));
        let was_up = std::mem::take(&mut hub.up);
        if was_up {
            shared.log.info(format_args!(
                "{}:{} - lid:{} - Leafnode connection closed: Client Closed - Remote: {}",
                hub.host, hub.port, hub.link, hub.name
            ));
        }
        drop(hubs);
        for tx in &*shared.lanes {
            tx.control(LaneControl::Unlink { slot });
        }
        if was_up {
            crate::sys::conns_changed(shared, account);
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
/// `account`, of permissions `perms` if any, on every lane, as change `c`
/// says: but in this server's own loop detection subject, and in what the
/// link may not send to. Its account name is the hub's.
fn interest(
    shared: &Shared,
    slot: u16,
    account: u32,
    perms: Option<&LinkPerms>,
    (_, subject, queue, weight, _): Change<'_>,
) {
    if subject == shared.accounts.lds(account) || perms.is_some_and(|p| !p.takes_interest(subject))
    {
        return;
    }
    for tx in &*shared.lanes {
        tx.control(LaneControl::Server {
            account,
            subject: subject.into(),
            queue: queue.map(Into::into),
            server: slot,
            weight: weight.into(),
        });
    }
}
