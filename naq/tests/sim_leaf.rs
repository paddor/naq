//! A seeded random simulation of naq leafs of a cluster of two naq hubs,
//! whose route goes through proxies. The route is cut, loudly or
//! silently, and comes back; a hub or leaf starts again, and the leafs of
//! a hub gone link to the other. Once quiet, each server heard the
//! interest it should over each route and link. See `sim/world.rs`.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use naq::{Cluster, Leafnodes, Options, Remote, Server};

#[path = "mesh/cluster.rs"]
mod cluster;
mod proxy;
#[path = "sim/world.rs"]
mod world;

use cluster::{WAIT, free_port, get, heard};
use proxy::{BLACKHOLE, CUT, OPEN, Proxy};
use world::{Links, Peer, Rng, Sim, World, links, subjects, told};

const HUBS: usize = 2;
/// Leaf `k` is server `HUBS + k`, and dials hub `k % HUBS` first.
const LEAFS: usize = 3;

/// Options of server `name` with two lanes, monitoring and no system
/// account.
fn base(name: &str) -> Options {
    Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        http_port: Some(0),
        server_name: name.into(),
        leaf_reconnect: Duration::from_millis(50),
        // What routes tell is then the interest of clients, without the
        // server's own in the system account.
        no_system_account: true,
        ..Options::default()
    }
}

/// The hubs, their leafs, and what keeps them apart.
struct Leafs {
    cluster_ports: [u16; HUBS],
    leaf_ports: [u16; HUBS],
    /// Hub `i`'s route to the other.
    proxies: [Proxy; HUBS],
    servers: Vec<Option<Server>>,
    /// How the route between the hubs is cut, if it is.
    apart: Option<u8>,
    /// The hub each leaf links to, as of the last quiet.
    hub_of: [Option<usize>; LEAFS],
}

impl Leafs {
    fn new() -> Leafs {
        let cluster_ports = [free_port(), free_port()];
        let mut w = Leafs {
            cluster_ports,
            leaf_ports: [free_port(), free_port()],
            proxies: [1, 0].map(|j| Proxy::to("127.0.0.1", cluster_ports[j])),
            servers: (0..HUBS + LEAFS).map(|_| None).collect(),
            apart: None,
            hub_of: [None; LEAFS],
        };
        for s in 0..HUBS + LEAFS {
            w.start(s);
        }
        w
    }

    fn start(&mut self, s: usize) {
        let o = if s < HUBS {
            Options {
                leafnodes: Some(Leafnodes {
                    host: "127.0.0.1".into(),
                    port: self.leaf_ports[s],
                    account: None,
                    ..Leafnodes::default()
                }),
                cluster: Some(Cluster {
                    name: "h".into(),
                    host: "127.0.0.1".into(),
                    port: self.cluster_ports[s],
                    routes: vec![format!("nats-route://127.0.0.1:{}", self.proxies[s].port)],
                }),
                ..base(&format!("h{s}"))
            }
        } else {
            let k = s - HUBS;
            Options {
                remotes: vec![Remote {
                    urls: (0..HUBS)
                        .map(|i| format!("naq://127.0.0.1:{}", self.leaf_ports[(k + i) % HUBS]))
                        .collect(),
                    no_randomize: true,
                    ..Remote::default()
                }],
                ..base(&format!("l{k}"))
            }
        };
        self.servers[s] = Some(Server::start(&o).unwrap());
    }

    fn set_route(&self, state: u8) {
        for p in &self.proxies {
            if state == CUT {
                p.cut();
            } else {
                p.set(state);
            }
        }
    }

    /// The part of the world server `s` is in, as of the last quiet.
    const fn part(&self, s: usize) -> usize {
        let hub = if s < HUBS {
            Some(s)
        } else {
            self.hub_of[s - HUBS]
        };
        match hub {
            Some(h) if self.apart.is_some() => h,
            Some(_) => 0,
            None => s,
        }
    }

    /// Notes the hub each leaf links to, by `zs`, each leaf's `/leafz`:
    /// what is wrong, if a leaf links to none while a hub is up.
    fn note_hubs(&mut self, zs: &[Option<serde_json::Value>]) -> Option<String> {
        let up: Vec<usize> = (0..HUBS).filter(|&i| self.servers[i].is_some()).collect();
        for (k, z) in zs.iter().enumerate() {
            self.hub_of[k] = None;
            let Some(z) = z else { continue };
            let names: Vec<String> = links(z).into_iter().map(|l| l.0).collect();
            let hub = up.iter().find(|&&i| names == [format!("h{i}")]);
            if hub.is_none() && !(up.is_empty() && names.is_empty()) {
                return Some(format!("l{k} links to {names:?}, hubs up: {up:?}"));
            }
            self.hub_of[k] = hub.copied();
        }
        None
    }

    /// The clients a route from hub `i` holds interest for: its own and
    /// its leafs'.
    fn held_at<'a>(&'a self, clients: &'a [Peer], i: usize) -> impl Iterator<Item = &'a Peer> {
        clients.iter().filter(move |c| {
            c.server == i || (c.server >= HUBS && self.hub_of[c.server - HUBS] == Some(i))
        })
    }

    /// What is not as quiet would have it, if anything.
    fn wrong(&mut self, clients: &[Peer]) -> Option<String> {
        let zs: Vec<Option<serde_json::Value>> = (HUBS..HUBS + LEAFS)
            .map(|s| self.servers[s].as_ref().map(|l| get(l, "/leafz?subs=1")))
            .collect();
        if let Some(w) = self.note_hubs(&zs) {
            return Some(w);
        }
        for i in (0..HUBS).filter(|&i| self.servers[i].is_some()) {
            if let Some(w) = self.wrong_at_hub(clients, i) {
                return Some(w);
            }
        }
        for (k, z) in zs.iter().enumerate() {
            let (Some(z), Some(h)) = (z, self.hub_of[k]) else {
                continue;
            };
            let at = HUBS + k;
            let others = clients
                .iter()
                .filter(|c| c.server != at && self.reach(at, c.server));
            let want = vec![(format!("h{h}"), subjects(others))];
            let got = links(z);
            if got != want {
                return Some(format!("l{k} heard {got:?}, not {want:?}"));
            }
        }
        None
    }

    /// What hub `i` heard wrong of the other one and of its leafs, if
    /// anything.
    fn wrong_at_hub(&self, clients: &[Peer], i: usize) -> Option<String> {
        let h = self.servers[i].as_ref().unwrap();
        let j = 1 - i;
        let got = heard(h, &format!("h{j}")).map(|all| {
            all.into_iter()
                .filter(|t| !t.0.starts_with("$LDS."))
                .collect()
        });
        let want = (self.servers[j].is_some() && self.apart.is_none())
            .then(|| told(self.held_at(clients, j)));
        if got != want {
            return Some(format!("h{i} heard of h{j}: {got:?}, not {want:?}"));
        }
        let got = links(&get(h, "/leafz?subs=1"));
        let want: Links = (0..LEAFS)
            .filter(|&k| self.hub_of[k] == Some(i))
            .map(|k| {
                let mine = clients.iter().filter(|c| c.server == HUBS + k);
                (format!("l{k}"), subjects(mine))
            })
            .collect();
        (got != want).then(|| format!("h{i} heard of its leafs {got:?}, not {want:?}"))
    }
}

impl World for Leafs {
    fn addrs(&self) -> Vec<Option<SocketAddr>> {
        self.servers
            .iter()
            .map(|s| s.as_ref().map(Server::addr))
            .collect()
    }

    fn quiet(&mut self, clients: &[Peer]) {
        let deadline = Instant::now() + WAIT;
        loop {
            let Some(wrong) = self.wrong(clients) else {
                return;
            };
            assert!(Instant::now() < deadline, "{wrong}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn reach(&self, i: usize, j: usize) -> bool {
        self.part(i) == self.part(j)
    }

    /// The route is cut or back, or a server stops or starts again.
    fn change(&mut self, rng: &mut Rng) -> (String, Option<usize>) {
        if rng.below(3) == 0 {
            if self.apart.take().is_some() {
                self.set_route(OPEN);
                return ("route back".into(), None);
            }
            let state = *rng.pick(&[CUT, BLACKHOLE]);
            self.set_route(state);
            self.apart = Some(state);
            return (format!("route cut, state {state}"), None);
        }
        let mut s = rng.below(HUBS + LEAFS);
        // Cut silently, the route still holds the loop detection subjects
        // of a hub's leafs: the other hub would tell them back as they
        // link to it, and they would wait out a loop, as leafs of
        // `nats-server` do.
        if s < HUBS && self.servers[s].is_some() && self.apart == Some(BLACKHOLE) {
            s = HUBS + rng.below(LEAFS);
        }
        if self.servers[s].take().is_some() {
            (format!("server {s} stops"), Some(s))
        } else {
            self.start(s);
            (format!("server {s} starts again"), None)
        }
    }

    fn heal(&mut self) {
        if self.apart.take().is_some() {
            self.set_route(OPEN);
        }
        for s in 0..HUBS + LEAFS {
            if self.servers[s].is_none() {
                self.start(s);
            }
        }
    }
}

#[test]
fn leafs_of_a_hub_cluster_hold_their_interest_and_deliveries_through_random_steps() {
    Sim::new(1, Leafs::new()).run();
}

#[test]
fn leafs_of_a_hub_cluster_hold_through_other_random_steps() {
    Sim::new(2, Leafs::new()).run();
}

#[test]
fn leafs_of_a_hub_cluster_hold_through_yet_other_random_steps() {
    Sim::new(3, Leafs::new()).run();
}
