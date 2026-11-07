//! The log: lines as `nats-server` writes them. Client lines are checked
//! against `nats-server` too when `NAQ_GO` names one.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use naq::{LogTo, Logging, Options, Server};

const WAIT: Duration = Duration::from_secs(10);

/// A directory of its own for test `name`.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("naq-log-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A server running, naq or `nats-server`: held until dropped.
struct Target {
    _naq: Option<Server>,
    _go: Option<Go>,
}

struct Go(Child);

impl Drop for Go {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts `conf` in `d` on naq, or on `nats-server` from `bin`, logging to
/// `server.log` there.
fn start(d: &Path, conf: &str, bin: Option<&Path>) -> Target {
    let path = d.join("server.conf");
    std::fs::write(&path, conf).unwrap();
    let Some(bin) = bin else {
        let mut o = Options::from_file(&path).unwrap();
        o.lanes = 2;
        return Target {
            _naq: Some(Server::start(&o).unwrap()),
            _go: None,
        };
    };
    let child = Command::new(bin)
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Not by a connection: that would be logged as a client.
    lines_once(&d.join("server.log"), |l| {
        l.iter().any(|l| l.ends_with("Server is ready"))
    });
    Target {
        _naq: None,
        _go: Some(Go(child)),
    }
}

/// A raw client.
struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
}

impl Client {
    /// Connects to `port` with `connect`, and waits for its `PONG`.
    fn new(port: u16, connect: &str) -> Client {
        let w = TcpStream::connect(("127.0.0.1", port)).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let r = BufReader::new(w.try_clone().unwrap());
        let mut c = Client { w, r };
        c.line();
        c.send(&format!("CONNECT {connect}\r\nPING\r\n"));
        c
    }

    fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
    }

    fn line(&mut self) -> String {
        let mut line = String::new();
        let n = self.r.read_line(&mut line).unwrap();
        assert!(n > 0, "closed");
        line
    }

    /// Reads up to the next `PONG`.
    fn pong(&mut self) {
        while self.line() != "PONG\r\n" {}
    }

    /// Reads until the server closes the connection.
    fn closed(mut self) {
        let mut rest = Vec::new();
        let _ = self.r.read_to_end(&mut rest);
    }
}

/// The lines of the log at `path`, once `ready` holds for them.
fn lines_once(path: &Path, ready: impl Fn(&[String]) -> bool) -> Vec<String> {
    let deadline = Instant::now() + WAIT;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if ready(&lines) {
            return lines;
        }
        assert!(Instant::now() < deadline, "log not ready: {lines:#?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn closed(n: usize) -> impl Fn(&[String]) -> bool {
    move |lines| {
        lines
            .iter()
            .filter(|l| l.contains("Client connection closed"))
            .count()
            >= n
    }
}

/// The client lines of `lines`, without the process ID, with ports and
/// client IDs numbered in order of their first appearance.
fn client_lines(lines: &[String]) -> Vec<String> {
    let mut cids: Vec<String> = Vec::new();
    lines
        .iter()
        .filter(|l| l.contains(" - cid:"))
        .map(|l| {
            let l = l.split_once("] ").map_or(l.as_str(), |(_, rest)| rest);
            let (head, rest) = l.split_once(" - cid:").unwrap();
            let host = head.rsplit_once(" 127.0.0.1:").map_or("", |(h, _)| h);
            let (cid, rest) = rest.split_once(' ').unwrap_or((rest, ""));
            if !cids.iter().any(|c| c == cid) {
                cids.push(cid.to_owned());
            }
            let n = cids.iter().position(|c| c == cid).unwrap() + 1;
            format!("{host} 127.0.0.1:P - cid:{n} {rest}")
        })
        .collect()
}

/// Runs `script` against naq and, if `NAQ_GO` names one, `nats-server`,
/// each running `conf` with its log in a file; checks both logged the
/// same client lines. Returns naq's.
fn both(name: &str, conf: &str, script: impl Fn(u16, &Path) -> Vec<String>) -> Vec<String> {
    let go = std::env::var_os("NAQ_GO").map(PathBuf::from);
    let mut seen: Vec<Vec<String>> = Vec::new();
    for bin in [None, go.as_deref()] {
        if seen.len() == 1 && bin.is_none() {
            break;
        }
        let d = dir(&format!("{name}-{}", seen.len()));
        let port = free_port();
        let log = d.join("server.log");
        let text = format!(
            "listen: 127.0.0.1:{port}\nlog_file: {:?}\nlogtime: false\n{conf}",
            log.display().to_string()
        );
        let server = start(&d, &text, bin);
        seen.push(client_lines(&script(port, &log)));
        drop(server);
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    seen.swap_remove(0)
}

const USERS: &str = r#"
debug: true
max_payload: 512
authorization {
  users: [
    {user: a, password: p, permissions: {publish: {deny: ["secret"]}, subscribe: {deny: ["secret"]}}}
  ]
}
"#;

#[test]
fn clients_are_logged_as_they_connect_err_and_close() {
    let lines = both("clients", USERS, |port, log| {
        let mut c = Client::new(
            port,
            r#"{"verbose":false,"name":"app1","lang":"ruby","version":"1.0","user":"a","pass":"p"}"#,
        );
        c.pong();
        c.send("PUB secret 2\r\nhi\r\nSUB secret 1\r\nPING\r\n");
        c.pong();
        drop(c);
        lines_once(log, closed(1));
        Client::new(port, r#"{"verbose":false,"user":"a","pass":"x"}"#).closed();
        lines_once(log, closed(2));
        let mut c = Client::new(port, r#"{"verbose":false,"user":"a","pass":"p"}"#);
        c.pong();
        c.send(&format!("PUB big 600\r\n{}\r\n", "x".repeat(600)));
        c.closed();
        lines_once(log, closed(3))
    });
    let who = r#"- "v1.0:ruby:app1" - "$G/user:a" -"#;
    assert_eq!(
        lines,
        [
            "[DBG] 127.0.0.1:P - cid:1 - Client connection created".to_owned(),
            format!(r#"[ERR] 127.0.0.1:P - cid:1 {who} Publish Violation - Subject "secret""#),
            format!(
                r#"[ERR] 127.0.0.1:P - cid:1 {who} Subscription Violation - Subject "secret", SID 1"#
            ),
            format!("[DBG] 127.0.0.1:P - cid:1 {who} Client connection closed: Client Closed"),
            "[DBG] 127.0.0.1:P - cid:2 - Client connection created".into(),
            r#"[ERR] 127.0.0.1:P - cid:2 - authentication error - User "a""#.into(),
            "[DBG] 127.0.0.1:P - cid:2 - Client connection closed: Authentication Failure".into(),
            "[DBG] 127.0.0.1:P - cid:3 - Client connection created".into(),
            r#"[ERR] 127.0.0.1:P - cid:3 - "$G/user:a" - maximum payload exceeded: 600 vs 512"#
                .into(),
            r#"[DBG] 127.0.0.1:P - cid:3 - "$G/user:a" - Client connection closed: Maximum Message Payload Exceeded"#.into(),
        ]
    );
}

#[test]
fn a_traced_client_shows_what_it_sent_and_got() {
    let lines = both("trace", "trace: true\n", |port, log| {
        let mut c = Client::new(port, r#"{"verbose":false,"headers":true,"name":"t"}"#);
        c.pong();
        c.send(
            "SUB foo 1\r\nSUB bar q 2\r\nPUB foo r 5\r\nhello\r\n\
             HPUB foo 12 14\r\nNATS/1.0\r\n\r\nhi\r\nUNSUB 1\r\nPING\r\n",
        );
        c.pong();
        drop(c);
        lines_once(log, |l| l.iter().any(|l| l.contains("DELSUB 2")))
    });
    let t = r#"[TRC] 127.0.0.1:P - cid:1 - "t" -"#;
    let want: Vec<String> = [
        r#"<<- [CONNECT {"verbose":false,"headers":true,"name":"t"}]"#,
        "<<- [PING]",
        "->> [PONG]",
        "<<- [SUB foo 1]",
        "<<- [SUB bar q 2]",
        "<<- [PUB foo r 5]",
        r#"<<- MSG_PAYLOAD: ["hello"]"#,
        "->> [MSG foo 1 r 5]",
        r#"->> MSG_PAYLOAD: ["hello"]"#,
        "<<- [HPUB foo 12 14]",
        r#"<<- MSG_PAYLOAD: ["NATS/1.0\r\n\r\nhi"]"#,
        "->> [HMSG foo 1 12 14]",
        r#"->> MSG_PAYLOAD: ["NATS/1.0\r\n\r\nhi"]"#,
        "<<- [UNSUB 1]",
        "<-> [DELSUB 1]",
        "<<- [PING]",
        "->> [PONG]",
        "<-> [DELSUB 2]",
    ]
    .iter()
    .map(|l| format!("{t} {l}"))
    .collect();
    let traced: Vec<String> = lines
        .into_iter()
        .filter(|l| l.starts_with("[TRC]"))
        .collect();
    // Before its CONNECT, a client's lines carry no names.
    assert_eq!(
        traced[0],
        format!(
            "[TRC] 127.0.0.1:P - cid:1 - {}",
            want[0].strip_prefix(&format!("{t} ")).unwrap()
        )
    );
    assert_eq!(traced[1..], want[1..]);
}

/// A server on a free port that logs to a file in `d` as `log` says.
fn logging(d: &Path, log: &Logging) -> (Server, PathBuf) {
    let path = d.join("server.log");
    let o = Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        server_name: "logged".into(),
        log: Logging {
            to: Some(LogTo::File(path.clone())),
            time: false,
            ..log.clone()
        },
        ..Options::default()
    };
    (Server::start(&o).unwrap(), path)
}

#[test]
fn a_server_logs_its_start_in_the_order_of_nats_server() {
    let d = dir("banner");
    let (s, path) = logging(&d, &Logging::default());
    let lines = lines_once(&path, |l| l.iter().any(|l| l.ends_with("Server is ready")));
    let pid = std::process::id();
    let text: Vec<String> = lines
        .iter()
        .map(|l| l.strip_prefix(&format!("[{pid}] ")).unwrap().to_owned())
        .collect();
    assert_eq!(text[0], "[INF] Starting naq");
    assert_eq!(
        text[1],
        format!("[INF]   Version:  {}", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(text[2], "[INF]   Name:     logged");
    assert!(text[3].starts_with("[INF]   ID:       N"), "{}", text[3]);
    assert_eq!(
        text[4],
        format!(
            "[INF] Listening for client connections on 127.0.0.1:{}",
            s.addr().port()
        )
    );
    assert_eq!(text[5], "[INF] Server is ready");
    assert_eq!(text.len(), 6);
}

#[test]
fn a_client_that_breaks_the_protocol_is_logged_with_what_it_sent() {
    let d = dir("parse");
    let (s, path) = logging(&d, &Logging::default());
    let mut c = Client::new(s.addr().port(), r#"{"verbose":false}"#);
    c.pong();
    c.send("FOO BAR\r\n");
    c.closed();
    let lines = lines_once(&path, |l| l.iter().any(|l| l.contains("parser ERROR")));
    let line = lines.iter().find(|l| l.contains("parser ERROR")).unwrap();
    assert!(
        line.ends_with(r#" - cid:1 - Client parser ERROR: proto='"FOO BAR\r"...'"#),
        "{line}"
    );
    assert!(line.contains("[ERR] 127.0.0.1:"), "{line}");
}

#[test]
fn a_reopened_log_goes_on_in_a_new_file_at_its_path() {
    let d = dir("reopen");
    let (s, path) = logging(&d, &Logging::default());
    lines_once(&path, |l| l.iter().any(|l| l.ends_with("Server is ready")));
    std::fs::rename(&path, d.join("old.log")).unwrap();
    s.reopen_log();
    let lines = lines_once(&path, |l| !l.is_empty());
    assert!(lines[0].ends_with("[INF] File log re-opened"), "{lines:?}");
    let old = std::fs::read_to_string(d.join("old.log")).unwrap();
    assert!(old.contains("Server is ready"));
}

#[test]
fn debug_lines_are_left_out_unless_asked_for() {
    let d = dir("quiet");
    let (s, path) = logging(&d, &Logging::default());
    let mut c = Client::new(s.addr().port(), r#"{"verbose":false}"#);
    c.pong();
    drop(c);
    let (s2, path2) = logging(
        &dir("loud"),
        &Logging {
            debug: true,
            ..Logging::default()
        },
    );
    let mut c = Client::new(s2.addr().port(), r#"{"verbose":false}"#);
    c.pong();
    drop(c);
    lines_once(&path2, closed(1));
    let quiet = std::fs::read_to_string(&path).unwrap();
    assert!(
        !quiet.contains("[DBG]") && !quiet.contains("Client connection"),
        "{quiet}"
    );
    drop((s, s2));
}

/// Server `n{i}` of a cluster on cluster port `port`, routed to `routes`,
/// logging to `n{i}.log` in `d`.
fn routed(d: &Path, i: usize, port: u16, routes: &[u16]) -> (Server, PathBuf) {
    let path = d.join(format!("n{i}.log"));
    let o = Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        server_name: format!("n{i}"),
        cluster: Some(naq::Cluster {
            name: "c".into(),
            host: "127.0.0.1".into(),
            port,
            routes: routes
                .iter()
                .map(|p| format!("nats-route://127.0.0.1:{p}"))
                .collect(),
        }),
        log: Logging {
            to: Some(LogTo::File(path.clone())),
            time: false,
            ..Logging::default()
        },
        ..Options::default()
    };
    (Server::start(&o).unwrap(), path)
}

#[test]
fn routes_are_logged_as_they_come_and_go() {
    let d = dir("routes");
    let ports = [free_port(), free_port()];
    let (a, a_log) = routed(&d, 0, ports[0], &[ports[1]]);
    let (b, b_log) = routed(&d, 1, ports[1], &[ports[0]]);
    let has = |l: &[String], text: &str| l.iter().any(|l| l.contains(text));
    let created = format!("127.0.0.1:{} - rid:0 - Route connection created", ports[1]);
    let lines = lines_once(&a_log, |l| has(l, &created));
    assert!(has(&lines, "[INF] Cluster name is c"), "{lines:#?}");
    let listening = format!(
        "[INF] Listening for route connections on 127.0.0.1:{}",
        ports[0]
    );
    assert!(has(&lines, &listening), "{lines:#?}");
    lines_once(&b_log, |l| has(l, "rid:0 - Route connection created"));
    drop(b);
    let closed = format!(
        "127.0.0.1:{} - rid:0 - Router connection closed: Client Closed - Remote: n1",
        ports[1]
    );
    lines_once(&a_log, |l| has(l, &closed));
    drop(a);
}

#[test]
fn traced_payloads_are_cut_at_the_most_asked_for() {
    let lines = both(
        "cut",
        "debug: true\ntrace: true\nmax_traced_msg_len: 3\n",
        |port, log| {
            let mut c = Client::new(port, r#"{"verbose":false,"pedantic":true}"#);
            c.pong();
            c.send("SUB foo 1\r\nUNSUB 1 5\r\nPUB foo 5\r\nhello\r\nPUB foo..bar 2\r\nhi\r\nPONG\r\nPING\r\n");
            c.pong();
            drop(c);
            lines_once(log, |l| l.iter().any(|l| l.contains("DELSUB 1")))
        },
    );
    let t = "[TRC] 127.0.0.1:P - cid:1 -";
    let traced: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.strip_prefix(&format!("{t} ")))
        .collect();
    assert_eq!(
        traced[3..],
        [
            "<<- [SUB foo 1]",
            "<<- [UNSUB 1 5]",
            "<<- [PUB foo 5]",
            r#"<<- MSG_PAYLOAD: ["hel..."]"#,
            "->> [MSG foo 1 5]",
            r#"->> MSG_PAYLOAD: ["hel..."]"#,
            "<<- [PUB foo..bar 2]",
            "->> [-ERR Invalid Publish Subject]",
            r#"<<- MSG_PAYLOAD: ["hi"]"#,
            "<<- [PONG]",
            "<<- [PING]",
            "->> [PONG]",
            "<-> [DELSUB 1]",
        ]
    );
}

#[test]
fn traced_headers_leave_out_payloads() {
    let lines = both(
        "headers",
        "debug: true\ntrace_headers: true\n",
        |port, log| {
            let mut c = Client::new(port, r#"{"verbose":false,"headers":true}"#);
            c.pong();
            c.send("PUB foo 2\r\nhi\r\nHPUB foo 18 20\r\nNATS/1.0\r\nA: b\r\n\r\nhi\r\nPING\r\n");
            c.pong();
            drop(c);
            lines_once(log, closed(1))
        },
    );
    let payloads: Vec<&String> = lines.iter().filter(|l| l.contains("MSG_PAYLOAD")).collect();
    assert_eq!(payloads.len(), 1, "{lines:#?}");
    assert!(
        payloads[0].ends_with(r#"<<- MSG_PAYLOAD: ["NATS/1.0\r\nA: b"]"#),
        "{payloads:?}"
    );
}
