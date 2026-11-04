//! Control between the servers of the mesh: who they are, and their
//! interest.

use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use naq_proto::peer::{self, Control, Hello};
use omq_tokio::{Message, MonitorEvent, Socket, SocketType};

use super::interest::{Change, Heard};
use super::{Mesh, Peer, endpoint, route, socket_options};
use crate::Cluster;
use crate::lane::Control as LaneControl;
use crate::server::Shared;

/// How often the deltas sent so far are told.
const BEAT: Duration = Duration::from_secs(1);

/// What this server tells the others of itself.
#[derive(Debug)]
pub(super) struct Me {
    /// Its routing identity: its server ID.
    id: Bytes,
    cluster: String,
    /// Its `Hello`, encoded.
    hello: Bytes,
}

impl Me {
    /// The `Hello` of `shared`'s server of start `epoch` in cluster `c`,
    /// with the data endpoints of its lanes.
    pub(super) fn new(shared: &Shared, c: &Cluster, data: &[String], epoch: u64) -> Me {
        let data = data.join(" ");
        let urls = shared.addr.to_string();
        let mut hello = Vec::new();
        Control::Hello(Hello {
            epoch,
            server_id: shared.server_id.as_bytes(),
            name: shared.opts.server_name.as_bytes(),
            cluster: c.name.as_bytes(),
            data: data.as_bytes(),
            client_urls: urls.as_bytes(),
        })
        .encode(&mut hello);
        Me {
            id: Bytes::copy_from_slice(shared.server_id.as_bytes()),
            cluster: c.name.clone(),
            hello: hello.into(),
        }
    }
}

/// Serves the control of the mesh on lane 0: dials every route of `c`,
/// noting the servers in `mesh`, and answers those that dial `router`.
pub(super) async fn serve(
    shared: &Arc<Shared>,
    mesh: &Rc<Mesh>,
    me: Me,
    c: &Cluster,
    router: Socket,
) {
    let me = Rc::new(me);
    {
        let mut peers = mesh.peers.borrow_mut();
        for url in &c.routes {
            // Valid: the options were checked.
            let (host, port) = route(url).unwrap_or_default();
            peers.push(Peer {
                host,
                port,
                ..Peer::default()
            });
        }
    }
    for i in 0..c.routes.len() {
        tokio::task::spawn_local(dial(shared.clone(), mesh.clone(), me.clone(), i));
    }
    answer(router, &me, mesh).await;
}

/// Answers each server that dials this one: with this one's `Hello` and a
/// snapshot of its interest, then the deltas and beats of it.
async fn answer(router: Socket, me: &Me, mesh: &Mesh) {
    let Ok(ids) = router.identity_routing() else {
        return;
    };
    // The servers that dialed this one, by routing identity.
    let mut others: Vec<Bytes> = Vec::new();
    let mut beat = tokio::time::interval(BEAT);
    loop {
        // Cancel-safe: a dropped receive takes no message, a dropped
        // `notified` keeps its permit, and the interval keeps its deadline.
        tokio::select! {
            got = ids.recv_from() => {
                let Ok((who, msg)) = got else { return };
                let Ok(bytes) = msg.into_bytes() else { continue };
                let who = who.to_bytes();
                match peer::decode(&bytes) {
                    Ok(Control::Hello(h)) if h.cluster == me.cluster.as_bytes() => {
                        if !others.contains(&who) {
                            others.push(who.clone());
                        }
                        let _ = ids.send_to(&who, Message::single(me.hello.clone())).await;
                        snapshot(&ids, &who, mesh).await;
                    }
                    Ok(Control::Resync) if others.contains(&who) => {
                        snapshot(&ids, &who, mesh).await;
                    }
                    _ => {}
                }
            }
            () = mesh.told.wake.notified() => {
                for delta in mesh.told.take() {
                    for who in &others {
                        let _ = ids.send_to(who, Message::single(delta.clone())).await;
                    }
                }
            }
            _ = beat.tick() => {
                let b = mesh.told.beat();
                for who in &others {
                    let _ = ids.send_to(who, Message::single(b.clone())).await;
                }
            }
        }
    }
}

/// Sends `who` a snapshot of this server's interest.
async fn snapshot(ids: &omq_tokio::IdentitySocket, who: &Bytes, mesh: &Mesh) {
    for part in mesh.told.snapshot() {
        let _ = ids.send_to(who, Message::single(part)).await;
    }
}

/// Dials route `i` of `mesh` and keeps track of the server there: says
/// `Hello` on each connection, notes the one it answers with, and applies
/// its interest on every lane.
async fn dial(shared: Arc<Shared>, mesh: Rc<Mesh>, me: Rc<Me>, i: usize) {
    let ctx = omq_tokio::Context::current();
    let s = ctx.socket(SocketType::Dealer, socket_options(me.id.clone()));
    let mut events = s.monitor();
    let (host, port) = {
        let peers = mesh.peers.borrow();
        (peers[i].host.clone(), peers[i].port)
    };
    if s.connect(endpoint(&host, port)).await.is_err() {
        return;
    }
    let mut heard = Heard::default();
    let mut apply = |c: Change<'_>| server_interest(&shared, i, c);
    loop {
        // Cancel-safe: a dropped receive takes no message or event.
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(MonitorEvent::HandshakeSucceeded { .. }) | Err(omq_tokio::MonitorRecvError::Lagged(_)) => {
                    let _ = s.send(Message::single(me.hello.clone())).await;
                }
                Ok(MonitorEvent::Disconnected { .. }) => {
                    heard.forget(&mut apply);
                    {
                        let mut peers = mesh.peers.borrow_mut();
                        peers[i].up = false;
                        peers[i].subscriptions = 0;
                    }
                    connect_urls(&shared, &mesh);
                }
                Ok(_) => {}
                Err(_) => return,
            },
            msg = s.recv() => {
                let Ok(msg) = msg else { return };
                let Ok(bytes) = msg.into_bytes() else { continue };
                let Ok(c) = peer::decode(&bytes) else { continue };
                if let Control::Hello(h) = &c
                    && !met(&shared, &mesh, i, h, &me)
                {
                    continue;
                }
                if heard.take(&c, &mut apply) {
                    let mut out = Vec::new();
                    Control::Resync.encode(&mut out);
                    let _ = s.send(Message::single(Bytes::from(out))).await;
                }
                mesh.peers.borrow_mut()[i].subscriptions = heard.len();
            }
        }
    }
}

/// Sets the interest of the server of route `i` on every lane, as change
/// `c` says, if its account is one of this server's.
fn server_interest(shared: &Shared, i: usize, (account, subject, queue, weight): Change<'_>) {
    let Some(account) = shared.accounts.iter().position(|a| a.as_bytes() == account) else {
        return;
    };
    // Routes are few: their count fits.
    let server = i as u16;
    for tx in &*shared.lanes {
        tx.control(LaneControl::Server {
            account: account as u32,
            subject: subject.into(),
            queue: queue.map(Into::into),
            server,
            weight,
        });
    }
}

/// Notes the server of route `i` as its `Hello` `h` tells, and tells the
/// lanes where it takes data, if that changed. Returns whether it is of
/// this cluster.
fn met(shared: &Shared, mesh: &Mesh, i: usize, h: &Hello<'_>, me: &Me) -> bool {
    if h.cluster != me.cluster.as_bytes() {
        return false;
    }
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let mut peers = mesh.peers.borrow_mut();
    let p = &mut peers[i];
    p.up = true;
    p.server_id = text(h.server_id);
    p.name = text(h.name);
    p.epoch = h.epoch;
    let data: Vec<String> = peer::words(h.data).map(text).collect();
    if data != p.data && !data.is_empty() {
        for (lane, tx) in shared.lanes.iter().enumerate() {
            tx.control(LaneControl::Push {
                // Routes are few: their count fits.
                server: i as u16,
                endpoint: reachable(&data[lane % data.len()], &p.host),
            });
        }
        p.data = data;
    }
    p.client_urls = peer::words(h.client_urls)
        .map(|u| reachable_url(&text(u), &p.host))
        .collect();
    drop(peers);
    connect_urls(shared, mesh);
    true
}

/// Notes where the clients of the servers that are up connect, for the
/// `INFO` of this server's clients.
fn connect_urls(shared: &Shared, mesh: &Mesh) {
    let urls: Vec<String> = mesh
        .peers
        .borrow()
        .iter()
        .filter(|p| p.up)
        .flat_map(|p| p.client_urls.iter().cloned())
        .collect();
    // A poisoned lock still holds the list.
    *shared
        .connect_urls
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = urls;
}

/// Client URL `url`, `host:port`, of a server dialed at `host`: on that
/// host, where it listens on every address.
fn reachable_url(url: &str, host: &str) -> String {
    match url.rsplit_once(':') {
        Some(("0.0.0.0" | "[::]", port)) if host.contains(':') => format!("[{host}]:{port}"),
        Some(("0.0.0.0" | "[::]", port)) => format!("{host}:{port}"),
        _ => url.to_owned(),
    }
}

/// Data endpoint `at` of a server dialed at `host`: on that host, where it
/// listens on every address.
fn reachable(at: &str, host: &str) -> String {
    let any = at
        .strip_prefix("tcp://")
        .and_then(|rest| rest.rsplit_once(':'))
        .filter(|(h, _)| matches!(*h, "0.0.0.0" | "[::]" | "*"));
    match any.and_then(|(_, port)| port.parse().ok()) {
        Some(port) => endpoint(host, port),
        None => at.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_on_every_address_is_reached_on_its_route_host() {
        assert_eq!(reachable("tcp://0.0.0.0:7", "h"), "tcp://h:7");
        assert_eq!(reachable("tcp://[::]:7", "::1"), "tcp://[::1]:7");
        assert_eq!(reachable("tcp://10.0.0.1:7", "h"), "tcp://10.0.0.1:7");
        assert_eq!(reachable("bogus", "h"), "bogus");
        assert_eq!(reachable_url("0.0.0.0:4222", "h"), "h:4222");
        assert_eq!(reachable_url("[::]:4222", "::1"), "[::1]:4222");
        assert_eq!(reachable_url("10.0.0.1:4222", "h"), "10.0.0.1:4222");
    }
}
