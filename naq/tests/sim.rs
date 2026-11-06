//! A seeded random simulation of a cluster of three whose routes go
//! through proxies: a server is cut off, loudly or silently, and comes
//! back; a server starts again. Once quiet, each server heard of each
//! other one the interest its clients hold. See `sim/world.rs`.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::net::SocketAddr;

use naq::Server;

#[path = "mesh/cluster.rs"]
mod cluster;
mod proxy;
#[path = "sim/world.rs"]
mod world;

use cluster::{node, proxied, quiet};
use proxy::{BLACKHOLE, CUT, OPEN, Proxy};
use world::{Peer, Rng, Sim, World, told};

/// The cluster, and what keeps it apart.
struct Mesh {
    ports: Vec<u16>,
    proxies: Vec<Vec<Option<Proxy>>>,
    servers: Vec<Option<Server>>,
    /// The server cut off from the others, and how.
    apart: Option<(usize, u8)>,
}

impl Mesh {
    fn new() -> Mesh {
        let (servers, proxies) = proxied();
        let ports = servers
            .iter()
            .map(|s| s.cluster_addr().unwrap().port())
            .collect();
        Mesh {
            ports,
            proxies,
            servers: servers.into_iter().map(Some).collect(),
            apart: None,
        }
    }

    /// Whether the partition keeps servers `i` and `j` apart.
    fn kept_apart(&self, i: usize, j: usize) -> bool {
        self.apart.is_some_and(|(k, _)| (i == k) != (j == k))
    }

    /// Sets every proxy between server `k` and the others to `state`.
    fn isolate(&self, k: usize, state: u8) {
        for j in (0..self.servers.len()).filter(|&j| j != k) {
            for p in [&self.proxies[k][j], &self.proxies[j][k]] {
                let p = p.as_ref().unwrap();
                if state == CUT {
                    p.cut();
                } else {
                    p.set(state);
                }
            }
        }
    }

    fn partition_or_heal(&mut self, rng: &mut Rng) -> String {
        if let Some((k, _)) = self.apart.take() {
            self.isolate(k, OPEN);
            format!("server {k} back")
        } else {
            let k = rng.below(self.servers.len());
            let state = *rng.pick(&[CUT, BLACKHOLE]);
            self.isolate(k, state);
            self.apart = Some((k, state));
            format!("server {k} cut off, state {state}")
        }
    }

    fn start(&mut self, k: usize) {
        let routes: Vec<u16> = self.proxies[k].iter().flatten().map(|p| p.port).collect();
        self.servers[k] = Some(node(k, self.ports[k], &routes));
    }
}

impl World for Mesh {
    fn addrs(&self) -> Vec<Option<SocketAddr>> {
        self.servers
            .iter()
            .map(|s| s.as_ref().map(Server::addr))
            .collect()
    }

    /// Each server heard of each other one what its clients hold, unless
    /// kept apart.
    fn quiet(&mut self, clients: &[Peer]) {
        let up: Vec<Option<&Server>> = self.servers.iter().map(Option::as_ref).collect();
        let want: Vec<_> = (0..self.servers.len())
            .map(|i| told(clients.iter().filter(|c| c.server == i)))
            .collect();
        quiet(&up, |i, j| self.kept_apart(i, j), &want);
    }

    fn reach(&self, i: usize, j: usize) -> bool {
        !self.kept_apart(i, j)
    }

    /// A server is cut off or back, or stops or starts again.
    fn change(&mut self, rng: &mut Rng) -> (String, Option<usize>) {
        if rng.below(3) != 0 {
            return (self.partition_or_heal(rng), None);
        }
        let k = rng.below(self.servers.len());
        if self.servers[k].take().is_some() {
            (format!("server {k} stops"), Some(k))
        } else {
            self.start(k);
            (format!("server {k} starts again"), None)
        }
    }

    fn heal(&mut self) {
        if let Some((k, _)) = self.apart.take() {
            self.isolate(k, OPEN);
        }
        for k in 0..self.servers.len() {
            if self.servers[k].is_none() {
                self.start(k);
            }
        }
    }
}

#[test]
fn a_cluster_holds_its_interest_and_deliveries_through_random_steps() {
    Sim::new(1, Mesh::new()).run();
}

#[test]
fn a_cluster_holds_through_other_random_steps() {
    Sim::new(2, Mesh::new()).run();
}

#[test]
fn a_cluster_holds_through_yet_other_random_steps() {
    Sim::new(3, Mesh::new()).run();
}
