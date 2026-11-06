//! The server's own services on `$SYS` in a cluster: requests to every
//! server reach every server, and each answers for itself.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use naq::{Options, Server};

const WAIT: Duration = Duration::from_secs(10);

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Server `n<i>` of a cluster on `ports`, with a user `sys` of the system
/// account and a user `a` of account `A`.
fn member(i: usize, ports: &[u16]) -> Server {
    let routes: Vec<String> = (0..ports.len())
        .filter(|&j| j != i)
        .map(|j| format!("\"nats-route://127.0.0.1:{}\"", ports[j]))
        .collect();
    let conf = format!(
        "server_name: n{i}\n\
         accounts {{ SYS {{ users [{{user: sys, password: p}}] }}, A {{ users [{{user: a, password: p}}] }} }}\n\
         system_account: SYS\n\
         cluster {{ name: c, listen: \"127.0.0.1:{}\", routes: [{}] }}\n",
        ports[i],
        routes.join(", ")
    );
    let opts: Options = conf.parse().unwrap();
    Server::start(&Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        ..opts
    })
    .unwrap()
}

fn cluster(n: usize) -> Vec<Server> {
    let ports: Vec<u16> = (0..n).map(|_| free_port()).collect();
    (0..n).map(|i| member(i, &ports)).collect()
}

/// A user of the system account.
struct Sys {
    w: TcpStream,
    r: BufReader<TcpStream>,
    /// The ID of its server.
    server_id: String,
    next: u32,
}

impl Sys {
    fn new(at: SocketAddr) -> Sys {
        Sys::of(at, "sys")
    }

    /// A client of user `user`.
    fn of(at: SocketAddr, user: &str) -> Sys {
        let w = TcpStream::connect(at).unwrap();
        let mut r = BufReader::new(w.try_clone().unwrap());
        let mut info = String::new();
        r.read_line(&mut info).unwrap();
        let info: serde_json::Value =
            serde_json::from_str(info.trim_start_matches("INFO ")).unwrap();
        let mut s = Sys {
            w,
            r,
            server_id: info["server_id"].as_str().unwrap().to_owned(),
            next: 0,
        };
        s.send(&format!(
            "CONNECT {{\"user\":\"{user}\",\"pass\":\"p\"}}\r\nSUB _R.> 1\r\nPING\r\n"
        ));
        s
    }

    fn send(&mut self, text: &str) {
        self.w.write_all(text.as_bytes()).unwrap();
    }

    /// The answers to a request on `subject`, as many as come in `wait`
    /// or `n` of them.
    fn ask(&mut self, subject: &str, n: usize, wait: Duration) -> Vec<serde_json::Value> {
        self.next += 1;
        let reply = format!("_R.{}", self.next);
        self.send(&format!("PUB {subject} {reply} 0\r\n\r\n"));
        // Answers to an earlier request come late.
        self.messages(n, wait, |s| s == reply)
    }

    /// The messages that come in `wait` on subjects `keep` takes, as many
    /// as come or `n` of them.
    fn messages(
        &mut self,
        n: usize,
        wait: Duration,
        keep: impl Fn(&str) -> bool,
    ) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + wait;
        let mut all = Vec::new();
        while all.len() < n {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            self.w.set_read_timeout(Some(left)).unwrap();
            let mut line = String::new();
            if self.r.read_line(&mut line).is_err() {
                break;
            }
            if line.starts_with("PING") {
                self.send("PONG\r\n");
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.first() != Some(&"MSG") {
                continue;
            }
            let size: usize = words.last().unwrap().parse().unwrap();
            let mut payload = vec![0; size + 2];
            self.r.read_exact(&mut payload).unwrap();
            if keep(words[1]) {
                all.push(serde_json::from_slice(&payload[..size]).unwrap());
            }
        }
        all
    }

    /// The answers of all `n` servers to a request on `subject`, once the
    /// cluster has met.
    fn ask_all(&mut self, subject: &str, n: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + WAIT;
        loop {
            let all = self.ask(subject, n, Duration::from_millis(500));
            if all.len() == n {
                return all;
            }
            assert!(Instant::now() < deadline, "{subject}: {all:?}");
        }
    }
}

/// The names of the servers that sent `answers`, sorted.
fn names(answers: &[serde_json::Value], at: &str) -> Vec<String> {
    let mut names: Vec<String> = answers
        .iter()
        .map(|a| a.pointer(at).unwrap().as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn every_server_of_a_cluster_answers_a_ping() {
    let servers = cluster(3);
    let mut c = Sys::new(servers[0].addr());
    let idz = c.ask_all("$SYS.REQ.SERVER.PING.IDZ", 3);
    assert_eq!(names(&idz, "/name"), ["n0", "n1", "n2"]);
    let varz = c.ask_all("$SYS.REQ.SERVER.PING.VARZ", 3);
    assert_eq!(names(&varz, "/server/name"), ["n0", "n1", "n2"]);
    for v in &varz {
        assert_eq!(v["server"]["cluster"], "c");
        assert_eq!(v["data"]["server_name"], v["server"]["name"]);
    }
    let statsz = c.ask_all("$SYS.REQ.SERVER.PING", 3);
    let routes: BTreeMap<String, usize> = statsz
        .iter()
        .map(|s| {
            let name = s["server"]["name"].as_str().unwrap().to_owned();
            assert_eq!(s["statsz"]["active_servers"], 3);
            (name, s["statsz"]["routes"].as_array().unwrap().len())
        })
        .collect();
    assert_eq!(routes.values().collect::<Vec<_>>(), [&2, &2, &2]);
}

#[test]
fn a_server_asked_by_its_id_answers_alone() {
    let servers = cluster(2);
    let far = Sys::new(servers[1].addr()).server_id;
    let mut c = Sys::new(servers[0].addr());
    // Once the cluster has met, the far server answers for itself.
    c.ask_all("$SYS.REQ.SERVER.PING.IDZ", 2);
    let one = c.ask(
        &format!("$SYS.REQ.SERVER.{far}.IDZ"),
        2,
        Duration::from_millis(500),
    );
    assert_eq!(names(&one, "/name"), ["n1"]);
    assert_eq!(one[0]["id"], far.as_str());
}

#[test]
fn a_ping_without_a_reply_has_each_server_send_its_statsz() {
    let servers = cluster(2);
    let mut c = Sys::new(servers[0].addr());
    c.ask_all("$SYS.REQ.SERVER.PING.IDZ", 2);
    c.send("SUB $SYS.SERVER.*.STATSZ 2\r\nPING\r\n");
    let deadline = Instant::now() + WAIT;
    let mut from: Vec<String> = Vec::new();
    while from.len() < 2 {
        assert!(Instant::now() < deadline, "{from:?}");
        c.send("PUB $SYS.REQ.SERVER.PING 0\r\n\r\n");
        let got = c.messages(usize::MAX, Duration::from_millis(300), |subject| {
            subject.ends_with(".STATSZ")
        });
        for s in got {
            let name = s["server"]["name"].as_str().unwrap().to_owned();
            assert!(s["statsz"]["connections"].as_u64().is_some());
            if !from.contains(&name) {
                from.push(name);
            }
        }
    }
    from.sort();
    assert_eq!(from, ["n0", "n1"]);
}

#[test]
fn accounts_ask_every_server_of_a_cluster_of_themselves() {
    let servers = cluster(3);
    let mut a = Sys::of(servers[0].addr(), "a");
    let _far = Sys::of(servers[1].addr(), "a");
    let conns = a.ask_all("$SYS.REQ.SERVER.PING.CONNZ", 3);
    let mut held: Vec<u64> = conns
        .iter()
        .map(|c| c["data"]["num_connections"].as_u64().unwrap())
        .collect();
    held.sort_unstable();
    assert_eq!(held, [0, 1, 1]);
    // Only the servers where the account has clients tell of it.
    let statz = a.ask_all("$SYS.REQ.ACCOUNT.PING.STATZ", 2);
    assert_eq!(names(&statz, "/server/name"), ["n0", "n1"]);
    for z in &statz {
        assert_eq!(z["data"]["account_statz"][0]["acc"], "A");
    }
    // Only its own server answers who a user is.
    let me = a.ask("$SYS.REQ.USER.INFO", 3, Duration::from_millis(500));
    assert_eq!(names(&me, "/server/name"), ["n0"]);
    assert_eq!(me[0]["data"]["account"], "A");
}
