//! Clusters of naq servers for tests: started on free ports, through
//! proxies if need be, and the oracle of a quiet one.
//!
//! Each test crate uses a part of it.
#![allow(dead_code, reason = "each test crate uses a part")]

use std::time::{Duration, Instant};

use naq::{Options, Server};

pub(crate) use super::common::free_port;
use super::common::{self, local};
use super::proxy::Proxy;

/// Longest wait for anything a test expects.
pub(crate) const WAIT: Duration = Duration::from_secs(5);

/// Options of server `n{i}` of cluster `c`, two lanes, on cluster port
/// `port` with routes to `routes`.
pub(crate) fn options(i: usize, port: u16, routes: &[u16]) -> Options {
    let o = Options {
        http_port: Some(0),
        server_name: format!("n{i}"),
        cluster: Some(common::cluster(port, routes)),
        // What routes tell is then the interest of clients, without the
        // server's own in the system account.
        no_system_account: true,
        ..Options::default()
    };
    local(o, 2)
}

/// Server `n{i}` of cluster `c`, as [`options`] has it.
pub(crate) fn node(i: usize, port: u16, routes: &[u16]) -> Server {
    Server::start(&options(i, port, routes)).unwrap()
}

/// Interest one server tells the others of: subject, queue group and its
/// members there, 1 for plain interest.
pub(crate) type Told = (String, Option<String>, u64);

/// `entries`, sorted, as [`heard`] gives them.
pub(crate) fn told(entries: &[(&str, Option<&str>, u64)]) -> Vec<Told> {
    let mut all: Vec<Told> = entries
        .iter()
        .map(|&(s, q, w)| (s.to_owned(), q.map(str::to_owned), w))
        .collect();
    all.sort();
    all
}

/// What `s` heard of the interest of server `name`, sorted; `None`
/// while its route is down.
pub(crate) fn heard(s: &Server, name: &str) -> Option<Vec<Told>> {
    let z = get(s, "/routez?subs=detail");
    let r = z["routes"]
        .as_array()?
        .iter()
        .find(|r| r["remote_name"] == name)?;
    let mut all: Vec<Told> = r["subscriptions_list_detail"]
        .as_array()
        .map(|subs| {
            subs.iter()
                .map(|d| {
                    (
                        d["subject"].as_str().unwrap().to_owned(),
                        d["qgroup"].as_str().map(str::to_owned),
                        d["queue_weight"].as_u64().unwrap_or(1),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    all.sort();
    Some(all)
}

/// The oracle of a quiet cluster. Waits until each server `n{i}` that is
/// up, `Some` in `servers`, heard of each other one `n{j}` what `want[j]`
/// says of its clients, if `apart(i, j)` does not keep them apart, and
/// has no route to it otherwise.
pub(crate) fn quiet(
    servers: &[Option<&Server>],
    apart: impl Fn(usize, usize) -> bool,
    want: &[Vec<Told>],
) {
    let deadline = Instant::now() + WAIT;
    loop {
        let mut wrong = None;
        for (i, s) in servers.iter().enumerate() {
            let Some(s) = s else { continue };
            for (j, other) in servers.iter().enumerate().filter(|&(j, _)| j != i) {
                let got = heard(s, &format!("n{j}"));
                let expect = other.filter(|_| !apart(i, j)).map(|_| want[j].clone());
                if got != expect {
                    wrong = Some(format!("n{i} heard of n{j}: {got:?}, not {expect:?}"));
                }
            }
        }
        let Some(wrong) = wrong else { return };
        assert!(Instant::now() < deadline, "{wrong}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `GET path` on `s`'s monitoring port.
pub(crate) fn get(s: &Server, path: &str) -> serde_json::Value {
    common::get(s.monitor_addr().unwrap(), path)
}

/// Three servers whose routes go through proxies, by server and route.
pub(crate) fn proxied() -> (Vec<Server>, Vec<Vec<Option<Proxy>>>) {
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let proxies: Vec<Vec<Option<Proxy>>> = (0..3)
        .map(|i| {
            (0..3)
                .map(|j| (i != j).then(|| Proxy::to("127.0.0.1", ports[j])))
                .collect()
        })
        .collect();
    let servers = (0..3)
        .map(|i| {
            let routes: Vec<u16> = proxies[i].iter().flatten().map(|p| p.port).collect();
            node(i, ports[i], &routes)
        })
        .collect();
    (servers, proxies)
}
