//! The load generator across a cluster of naq servers.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::net::TcpListener;
use std::time::Duration;

use naq::{Cluster, Options, Server};
use naq_bench::load::{self, Config};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Three servers, each with routes to the others.
fn cluster() -> Vec<Server> {
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    (0..3)
        .map(|i| {
            Server::start(&Options {
                host: "127.0.0.1".into(),
                port: 0,
                lanes: 2,
                server_name: format!("n{i}"),
                cluster: Some(Cluster {
                    name: "c".into(),
                    host: "127.0.0.1".into(),
                    port: ports[i],
                    routes: (0..3)
                        .filter(|&j| j != i)
                        .map(|j| format!("nats-route://127.0.0.1:{}", ports[j]))
                        .collect(),
                }),
                ..Options::default()
            })
            .unwrap()
        })
        .collect()
}

/// Publishers on the first server, `subs` subscribers on the others
/// first, then on it.
fn across(servers: &[Server], subs: usize, queue: Option<&str>) -> Config {
    Config {
        addr: servers[0].addr(),
        sub_addrs: servers[1..]
            .iter()
            .chain(&servers[..1])
            .map(Server::addr)
            .collect(),
        subs,
        queue: queue.map(Into::into),
        warmup: Duration::from_millis(50),
        duration: Duration::from_millis(200),
        drain: Duration::from_secs(5),
        window: 256 << 10,
        batch: 16 << 10,
        server_pids: vec![std::process::id()],
        ..Config::default()
    }
}

#[test]
fn messages_cross_a_cluster_once_its_interest_has() {
    let servers = cluster();
    let r = load::run(&across(&servers, 1, None)).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert!(r.published > 0);
    assert_eq!(r.delivered, r.published);
    assert!(r.server_cpu_pct.is_some());
}

#[test]
fn fan_out_and_queue_groups_span_the_cluster() {
    let servers = cluster();
    let r = load::run(&across(&servers, 3, None)).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.delivered, 3 * r.published);
    let r = load::run(&across(&servers, 3, Some("q"))).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.delivered, r.published);
}
