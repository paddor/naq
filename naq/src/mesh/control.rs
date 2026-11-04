//! Control between the servers of the mesh: who they are, for now.

use std::rc::Rc;

use bytes::Bytes;
use naq_proto::peer::{self, Control, Hello};
use omq_tokio::{Message, MonitorEvent, Socket, SocketType};

use super::{Mesh, Peer, endpoint, route, socket_options};
use crate::Cluster;
use crate::lane::Lane;
use crate::server::Shared;

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
    /// The `Hello` of `shared`'s server in cluster `c`, with the data
    /// endpoints of its lanes.
    pub(super) fn new(shared: &Shared, c: &Cluster, data: &[String]) -> Me {
        let mut epoch = [0u8; 8];
        // An epoch of 0 on failure still tells a start apart from none.
        let _ = getrandom::getrandom(&mut epoch);
        let data = data.join(" ");
        let urls = shared.addr.to_string();
        let mut hello = Vec::new();
        Control::Hello(Hello {
            epoch: u64::from_le_bytes(epoch),
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
pub(super) async fn serve(_lane: &Rc<Lane>, mesh: &Rc<Mesh>, me: Me, c: &Cluster, router: Socket) {
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
        tokio::task::spawn_local(dial(mesh.clone(), me.clone(), i));
    }
    answer(router, &me).await;
}

/// Answers each server that dials this one with this one's `Hello`.
async fn answer(router: Socket, me: &Me) {
    let Ok(ids) = router.identity_routing() else {
        return;
    };
    loop {
        let Ok((who, msg)) = ids.recv_from().await else {
            return;
        };
        let Ok(bytes) = msg.into_bytes() else {
            continue;
        };
        if let Ok(Control::Hello(h)) = peer::decode(&bytes)
            && h.cluster == me.cluster.as_bytes()
        {
            let _ = ids.send_to(who, Message::single(me.hello.clone())).await;
        }
    }
}

/// Dials route `i` of `mesh` and keeps track of the server there: says
/// `Hello` on each connection, and notes the one it answers with.
async fn dial(mesh: Rc<Mesh>, me: Rc<Me>, i: usize) {
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
    loop {
        // Cancel-safe: a dropped receive takes no message or event.
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(MonitorEvent::HandshakeSucceeded { .. }) | Err(omq_tokio::MonitorRecvError::Lagged(_)) => {
                    let _ = s.send(Message::single(me.hello.clone())).await;
                }
                Ok(MonitorEvent::Disconnected { .. }) => mesh.peers.borrow_mut()[i].up = false,
                Ok(_) => {}
                Err(_) => return,
            },
            msg = s.recv() => {
                let Ok(msg) = msg else { return };
                let Ok(bytes) = msg.into_bytes() else { continue };
                if let Ok(Control::Hello(h)) = peer::decode(&bytes) {
                    met(&mesh, i, &h, &me);
                }
            }
        }
    }
}

/// Notes the server of route `i` as its `Hello` `h` tells, if it is of
/// this cluster.
fn met(mesh: &Mesh, i: usize, h: &Hello<'_>, me: &Me) {
    if h.cluster != me.cluster.as_bytes() {
        return;
    }
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let mut peers = mesh.peers.borrow_mut();
    let p = &mut peers[i];
    p.up = true;
    p.server_id = text(h.server_id);
    p.name = text(h.name);
    p.epoch = h.epoch;
    p.data = peer::words(h.data).map(text).collect();
}
