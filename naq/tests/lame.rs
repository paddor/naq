//! Lame duck mode, as `nats-server` has it: no new clients, an `INFO` that
//! says so, the other servers of the cluster told, closes spread over a
//! while, then the shutdown.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use naq::{Cluster, LogTo, Logging, Options, Server};

const WAIT: Duration = Duration::from_secs(10);

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A directory of its own for test `name`.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("naq-lame-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Options of a server on a free port, logging debug lines to `log`, in
/// lame duck mode for `duration` after a grace period of `grace`.
fn opts(log: &Path, duration: Duration, grace: Duration) -> Options {
    Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 2,
        lame_duck_duration: duration,
        lame_duck_grace_period: grace,
        log: Logging {
            to: Some(LogTo::File(log.to_path_buf())),
            debug: true,
            time: false,
            ..Logging::default()
        },
        ..Options::default()
    }
}

/// A raw client.
struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
    /// The ID of its server, from its first `INFO`.
    server_id: String,
}

impl Client {
    /// Connects to `at` with `connect`, and reads up to its `PONG`.
    fn new(at: SocketAddr, connect: &str) -> Client {
        let w = TcpStream::connect(at).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let mut r = BufReader::new(w.try_clone().unwrap());
        let mut first = String::new();
        r.read_line(&mut first).unwrap();
        let info: serde_json::Value =
            serde_json::from_str(first.strip_prefix("INFO ").unwrap().trim_end()).unwrap();
        let server_id = info["server_id"].as_str().unwrap().to_owned();
        let mut c = Client { w, r, server_id };
        c.send(&format!("CONNECT {connect}\r\nPING\r\n"));
        while c.line() != "PONG\r\n" {}
        c
    }

    fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
    }

    /// The next line; empty once the connection closed.
    fn line(&mut self) -> String {
        let mut line = String::new();
        let _ = self.r.read_line(&mut line);
        line
    }

    /// The next `INFO` it gets at any time, as JSON: not the one that
    /// follows its `CONNECT`.
    fn info(&mut self) -> serde_json::Value {
        loop {
            let line = self.line();
            assert!(!line.is_empty(), "closed");
            let Some(json) = line.strip_prefix("INFO ") else {
                continue;
            };
            let info: serde_json::Value = serde_json::from_str(json.trim_end()).unwrap();
            if info["connect_info"] != true {
                return info;
            }
        }
    }

    /// The messages it gets in `wait`, or `n` of them: subject and JSON
    /// payload.
    fn msgs(&mut self, n: usize, wait: Duration) -> Vec<(String, serde_json::Value)> {
        let deadline = Instant::now() + wait;
        let mut all = Vec::new();
        while all.len() < n {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            self.w.set_read_timeout(Some(left)).unwrap();
            let line = self.line();
            if line.is_empty() {
                break;
            }
            if line == "PING\r\n" {
                self.send("PONG\r\n");
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.first() != Some(&"MSG") {
                continue;
            }
            let size: usize = words.last().unwrap().parse().unwrap();
            let mut payload = vec![0; size + 2];
            self.r.read_exact(&mut payload).unwrap();
            let json = serde_json::from_slice(&payload[..size]).unwrap();
            all.push((words[1].to_owned(), json));
        }
        self.w.set_read_timeout(Some(WAIT)).unwrap();
        all
    }

    /// What it gets until the server closes it, and when that was.
    fn closed(&mut self) -> (String, Instant) {
        let mut rest = String::new();
        let _ = self.r.read_to_string(&mut rest);
        (rest, Instant::now())
    }
}

/// The `connect_urls` of `info`.
fn urls(info: &serde_json::Value) -> Vec<String> {
    info["connect_urls"]
        .as_array()
        .map(|a| a.iter().map(|u| u.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

/// Waits until `at` refuses connections.
fn refuses(at: SocketAddr) {
    let deadline = Instant::now() + WAIT;
    while TcpStream::connect(at).is_ok() {
        assert!(Instant::now() < deadline, "{at} still takes clients");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Puts `s` in lame duck mode on a thread of its own, which returns once
/// it stopped.
fn lame(s: Server) -> std::thread::JoinHandle<Instant> {
    std::thread::spawn(move || {
        s.lame_duck_shutdown();
        Instant::now()
    })
}

/// Where each of `lines` is in `text`, as they must come in that order.
fn in_order(text: &str, lines: &[&str]) {
    let mut at = 0;
    for l in lines {
        let found = text[at..].find(l);
        assert!(found.is_some(), "no {l:?} after {at} in {text}");
        at += found.unwrap() + l.len();
    }
}

#[test]
fn a_server_in_lame_duck_mode_tells_its_clients_and_closes_them_one_by_one() {
    let d = dir("clients");
    let log = d.join("s.log");
    let grace = Duration::from_millis(300);
    let s = Server::start(&opts(&log, Duration::from_secs(3), grace)).unwrap();
    let at = s.addr();
    let mut told = Client::new(at, r#"{"protocol":1}"#);
    let old = Client::new(at, "{}");
    let started = Instant::now();
    let done = lame(s);
    // Read at once: its close comes in its own time.
    let old = std::thread::spawn(move || {
        let mut old = old;
        old.closed()
    });
    let info = told.info();
    assert_eq!(info["ldm"], true, "{info}");
    assert_eq!(info["client_id"], 1, "{info}");
    assert!(info.get("connect_urls").is_none(), "no cluster: {info}");
    refuses(at);
    let (rest, first) = told.closed();
    assert_eq!(rest, "");
    let (rest, second) = old.join().unwrap();
    assert_eq!(rest, "", "a client of protocol 0 gets no INFO");
    let (first, second) = (first.min(second), first.max(second));
    assert!(first - started >= grace, "closed in the grace period");
    // Two closes over 2.7 s: a second apart at most, half of it at least.
    assert!(
        second - first >= Duration::from_millis(450),
        "{:?}",
        second - first
    );
    let stopped = done.join().unwrap();
    assert!(stopped >= second);
    let text = std::fs::read_to_string(&log).unwrap();
    in_order(
        &text,
        &[
            "[INF] Entering lame duck mode, stop accepting new clients\n",
            "[INF] Closing existing clients\n",
            "Client connection closed: Server Shutdown\n",
            "Client connection closed: Server Shutdown\n",
            "[INF] Initiating Shutdown...\n",
            "[INF] Server Exiting..\n",
        ],
    );
}

#[test]
fn a_server_without_clients_shuts_down_at_once_in_lame_duck_mode() {
    let d = dir("none");
    let log = d.join("s.log");
    let grace = Duration::from_secs(5);
    let s = Server::start(&opts(&log, Duration::from_secs(10), grace)).unwrap();
    let started = Instant::now();
    s.lame_duck_shutdown();
    assert!(started.elapsed() < grace, "{:?}", started.elapsed());
    let text = std::fs::read_to_string(&log).unwrap();
    in_order(
        &text,
        &[
            "[INF] Entering lame duck mode, stop accepting new clients\n",
            "[INF] Initiating Shutdown...\n",
        ],
    );
    assert!(!text.contains("Closing existing clients"), "{text}");
}

#[test]
fn a_grace_period_not_below_the_duration_is_refused() {
    let d = dir("bad");
    let s = Duration::from_secs(1);
    let err = Server::start(&opts(&d.join("s.log"), s, s)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "bad options: lame duck grace period (1s) should be strictly lower than lame duck duration (1s)"
    );
}

/// Server `n{i}` of a cluster on `ports`, in lame duck mode for 3 s after
/// a grace period of half a second.
fn member(i: usize, ports: &[u16]) -> Server {
    let routes = (0..ports.len())
        .filter(|&j| j != i)
        .map(|j| format!("nats-route://127.0.0.1:{}", ports[j]))
        .collect();
    let d = dir(&format!("n{i}-{}", ports[i]));
    Server::start(&Options {
        server_name: format!("n{i}"),
        cluster: Some(Cluster {
            name: "c".into(),
            host: "127.0.0.1".into(),
            port: ports[i],
            routes,
        }),
        no_system_account: true,
        ..opts(
            &d.join("s.log"),
            Duration::from_secs(3),
            Duration::from_millis(500),
        )
    })
    .unwrap()
}

/// The `INFO`s `c` gets until one lists `want` as its `connect_urls`.
fn until_urls(c: &mut Client, want: &[String]) -> serde_json::Value {
    loop {
        let info = c.info();
        if urls(&info) == want {
            return info;
        }
    }
}

#[test]
fn clients_hear_where_the_cluster_is_as_servers_come_and_go_lame() {
    let ports = [free_port(), free_port()];
    let n0 = member(0, &ports);
    let mut a = Client::new(n0.addr(), r#"{"protocol":1}"#);
    let n1 = member(1, &ports);
    let (u0, u1) = (n0.addr().to_string(), n1.addr().to_string());
    // A route that comes up brings an INFO with its server's URL.
    until_urls(&mut a, &[u0.clone(), u1.clone()]);
    let mut b = Client::new(n1.addr(), r#"{"protocol":1}"#);
    let mut old = Client::new(n1.addr(), "{}");
    let done = lame(n0);
    let info = a.info();
    assert_eq!(info["ldm"], true, "{info}");
    assert_eq!(
        urls(&info),
        std::slice::from_ref(&u1),
        "the others' URLs alone"
    );
    // Its route says it goes: n1's clients leave it out.
    let info = until_urls(&mut b, std::slice::from_ref(&u1));
    assert!(info.get("ldm").is_none(), "{info}");
    let (rest, _) = a.closed();
    assert_eq!(rest, "");
    done.join().unwrap();
    old.send("PING\r\n");
    assert_eq!(
        old.line(),
        "PONG\r\n",
        "a client of protocol 0 gets no INFO"
    );
}

/// Server `n{i}` of a cluster on `ports` with a system account, in lame
/// duck mode for 3 s after a grace period of half a second.
fn sys_member(i: usize, ports: &[u16]) -> Server {
    let routes: Vec<String> = (0..ports.len())
        .filter(|&j| j != i)
        .map(|j| format!("\"nats-route://127.0.0.1:{}\"", ports[j]))
        .collect();
    let conf = format!(
        "server_name: n{i}\n\
         accounts {{ SYS {{ users [{{user: sys, password: p}}] }} }}\n\
         system_account: SYS\n\
         cluster {{ name: c, listen: \"127.0.0.1:{}\", routes: [{}] }}\n",
        ports[i],
        routes.join(", ")
    );
    let parsed: Options = conf.parse().unwrap();
    let d = dir(&format!("sys-n{i}-{}", ports[i]));
    let o = opts(
        &d.join("s.log"),
        Duration::from_secs(3),
        Duration::from_millis(500),
    );
    Server::start(&Options {
        host: o.host.clone(),
        port: 0,
        lanes: 2,
        log: o.log.clone(),
        lame_duck_duration: o.lame_duck_duration,
        lame_duck_grace_period: o.lame_duck_grace_period,
        ..parsed
    })
    .unwrap()
}

const SYS: &str = r#"{"user":"sys","pass":"p"}"#;

/// The servers that answer a ping of `c` in a moment, by name, sorted.
fn ping(c: &mut Client, n: usize) -> Vec<String> {
    c.send("PUB $SYS.REQ.SERVER.PING _R.1 0\r\n\r\n");
    let mut names: Vec<String> = c
        .msgs(n, Duration::from_millis(500))
        .into_iter()
        .filter(|(subject, _)| subject == "_R.1")
        .map(|(_, a)| a["server"]["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_server_in_lame_duck_mode_says_so_on_sys_and_nothing_after() {
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let mut servers: Vec<Server> = (0..3).map(|i| sys_member(i, &ports)).collect();
    let mut c = Client::new(servers[0].addr(), SYS);
    c.send("SUB $SYS.SERVER.*.LAMEDUCK 1\r\nSUB $SYS.SERVER.*.SHUTDOWN 2\r\nSUB _R.> 3\r\n");
    let deadline = Instant::now() + WAIT;
    while ping(&mut c, 3).len() < 3 {
        assert!(Instant::now() < deadline, "the cluster did not meet");
    }
    let n2 = servers.pop().unwrap();
    // A client keeps it in lame duck mode for the grace period.
    let held = Client::new(n2.addr(), SYS);
    let id = held.server_id.clone();
    let done = lame(n2);
    let said = loop {
        let m = c.msgs(1, WAIT).pop().unwrap();
        if !m.0.starts_with("_R.") {
            break m;
        }
    };
    assert_eq!(said.0, format!("$SYS.SERVER.{id}.LAMEDUCK"));
    assert_eq!(said.1["name"], "n2", "the block of the server alone");
    // It answers no more.
    assert_eq!(ping(&mut c, 3), ["n0", "n1"]);
    done.join().unwrap();
    let after = c.msgs(1, Duration::from_millis(500));
    assert!(
        after.iter().all(|(s, _)| !s.ends_with(".SHUTDOWN")),
        "{after:?}"
    );
    drop(held);
}

#[test]
fn an_ldm_request_tells_one_client_and_is_logged() {
    let d = dir("request");
    let log = d.join("s.log");
    let parsed: Options = "accounts { SYS { users [{user: sys, password: p}] } }\n\
                           system_account: SYS\n"
        .parse()
        .unwrap();
    let o = opts(&log, Duration::from_secs(3), Duration::from_millis(500));
    let s = Server::start(&Options {
        host: o.host.clone(),
        port: 0,
        lanes: 2,
        log: o.log.clone(),
        ..parsed
    })
    .unwrap();
    let mut sys = Client::new(s.addr(), SYS);
    let mut told = Client::new(
        s.addr(),
        r#"{"user":"sys","pass":"p","protocol":1,"name":"t"}"#,
    );
    let id = sys.server_id.clone();
    sys.send(&format!(
        "SUB _R.> 1\r\nPUB $SYS.REQ.SERVER.{id}.LDM _R.1 9\r\n{{\"cid\":2}}\r\n"
    ));
    let answer = sys.msgs(1, WAIT);
    assert_eq!(answer[0].0, "_R.1");
    assert!(answer[0].1.get("error").is_none(), "{:?}", answer[0].1);
    let info = told.info();
    assert_eq!(info["ldm"], true, "{info}");
    assert!(info.get("connect_urls").is_none(), "{info}");
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(
        text.contains(r#"- cid:2 - "t" - "SYS/user:sys" - Sending Lame Duck Mode info to client"#),
        "{text}"
    );
    s.shutdown();
}
