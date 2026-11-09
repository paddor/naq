//! Reloading the configuration while the server runs, as `nats-server`
//! reloads it: on `HUP`, on `$SYS.REQ.SERVER.<id>.RELOAD` and through
//! [`Server::reload`]. Checked against `nats-server` too when `NAQ_GO`
//! names one.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use naq::{Options, Server};

const NAQ: &str = env!("CARGO_BIN_EXE_naq");
const WAIT: Duration = Duration::from_secs(10);

/// A directory of its own for test `name`.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("naq-reload-{name}-{}", std::process::id()));
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

/// Whether `line` ends a reload, as it went or not.
fn ends_reload(line: &str) -> bool {
    line.contains("Reloaded server configuration")
        || line.contains("Failed to reload server configuration")
}

/// A server binary running a configuration file, logging to a file.
struct Proc {
    child: Child,
    dir: PathBuf,
    port: u16,
    /// What every version of the file starts with: where it listens and
    /// logs.
    head: String,
}

impl Proc {
    /// Runs `bin` in `dir` with `conf`, and waits until it is ready.
    fn start(bin: &Path, dir: &Path, conf: &str, args: &[&str]) -> Proc {
        let port = free_port();
        let log = dir.join("server.log");
        let head = format!(
            "listen: 127.0.0.1:{port}\nlog_file: {:?}\nlogtime: false\n",
            log.display().to_string()
        );
        let path = dir.join("server.conf");
        std::fs::write(&path, format!("{head}{conf}")).unwrap();
        let p = Proc {
            child: Command::new(bin)
                .arg("-c")
                .arg(&path)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
            dir: dir.to_path_buf(),
            port,
            head,
        };
        lines_once(&p.log(), |l| {
            l.iter().any(|l| l.ends_with("Server is ready"))
        });
        p
    }

    fn log(&self) -> PathBuf {
        self.dir.join("server.log")
    }

    /// Writes the configuration file anew with `conf`.
    fn write(&self, conf: &str) {
        let text = format!("{}{conf}", self.head);
        std::fs::write(self.dir.join("server.conf"), text).unwrap();
    }

    /// Sends `HUP`, and waits until the reload is logged as done.
    fn hup(&self) {
        let before = self.reloads();
        let ok = Command::new("kill")
            .args(["-s", "HUP", &self.child.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok);
        lines_once(&self.log(), |l| {
            l.iter().filter(|l| ends_reload(l)).count() > before
        });
    }

    /// Reloads logged so far.
    fn reloads(&self) -> usize {
        let text = std::fs::read_to_string(self.log()).unwrap_or_default();
        text.lines().filter(|l| ends_reload(l)).count()
    }
}

impl Drop for Proc {
    /// Stops the server as `TERM` does, so that it exits as it would, and
    /// kills it if it does not.
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-s", "TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The binaries to check: naq, and `nats-server` if `NAQ_GO` names one.
fn binaries() -> Vec<PathBuf> {
    let mut all = vec![PathBuf::from(NAQ)];
    all.extend(std::env::var_os("NAQ_GO").map(PathBuf::from));
    all
}

/// The reload lines of `lines`, without process IDs and digests.
fn reload_lines(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| {
            let rest = l.split_once("] ").map_or(l.as_str(), |(_, r)| r);
            let own = rest.starts_with("[INF] Reloaded")
                || rest.contains("Failed to reload")
                || rest.contains("Trapped");
            own.then(|| match rest.split_once(" (sha256:") {
                Some((head, _)) => format!("{head} (sha256:...)"),
                None => rest.to_owned(),
            })
        })
        .collect()
}

/// Runs `steps` against each binary, each a configuration to write and
/// reload; checks both logged the same reload lines. Returns naq's.
fn reloads(name: &str, first: &str, steps: &[&str]) -> Vec<String> {
    let mut seen: Vec<Vec<String>> = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("{name}-{i}"));
        let p = Proc::start(bin, &d, first, &[]);
        for step in steps {
            p.write(step);
            p.hup();
        }
        seen.push(reload_lines(&lines_once(&p.log(), |_| true)));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    seen.swap_remove(0)
}

#[test]
fn reloads_are_logged_as_nats_server_logs_them() {
    let first = "server_name: s1\nmax_payload: 1024\n";
    let changed = "server_name: s1\nmax_payload: 2048\ndebug: true\ntrace: true\n\
                   ping_interval: \"30s\"\nping_max: 5\nmax_control_line: 2048\n\
                   write_deadline: \"5s\"\nmax_traced_msg_len: 10\n\
                   server_tags: [\"a\"]\nserver_metadata: {k: v}\n";
    let renamed = "server_name: s2\n";
    let lame = "server_name: s1\nlame_duck_duration: \"1m\"\n";
    let lines = reloads("logged", first, &[changed, changed, renamed, lame, first]);
    assert_eq!(
        lines,
        [
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: trace = true",
            "[INF] Reloaded: debug = true",
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded: ping_interval = 30s",
            "[INF] Reloaded: ping_max = 5",
            "[INF] Reloaded: max_control_line = 2048",
            "[INF] Reloaded: max_payload = 2048",
            "[INF] Reloaded: write_deadline = 5s",
            "[INF] Reloaded: max_traced_msg_len = 10",
            "[INF] Reloaded: tags",
            "[INF] Reloaded: metadata",
            "[INF] Reloaded server configuration (sha256:...)",
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded server configuration (sha256:...)",
            r#"[INF] Trapped "hangup" signal"#,
            "[ERR] Failed to reload server configuration: \
             config reload not supported for ServerName: old=s1, new=s2",
            r#"[INF] Trapped "hangup" signal"#,
            "[ERR] Failed to reload server configuration: \
             config reload not supported for LameDuckDuration: old=2m0s, new=1m0s",
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: trace = false",
            "[INF] Reloaded: debug = false",
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded: ping_interval = 2m0s",
            "[INF] Reloaded: ping_max = 2",
            "[INF] Reloaded: max_control_line = 4096",
            "[INF] Reloaded: max_payload = 1024",
            "[INF] Reloaded: write_deadline = 10s",
            "[INF] Reloaded: max_traced_msg_len = 0",
            "[INF] Reloaded: tags",
            "[INF] Reloaded: metadata",
            "[INF] Reloaded server configuration (sha256:...)",
        ]
    );
}

/// A raw client.
struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
    /// Its first `INFO`.
    info: serde_json::Value,
}

impl Client {
    /// Connects to `port` with `connect`, and reads up to its `PONG`.
    fn new(port: u16, connect: &str) -> Client {
        let w = TcpStream::connect(("127.0.0.1", port)).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let mut r = BufReader::new(w.try_clone().unwrap());
        let mut first = String::new();
        r.read_line(&mut first).unwrap();
        let info = serde_json::from_str(first.strip_prefix("INFO ").unwrap().trim_end()).unwrap();
        let mut c = Client { w, r, info };
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
        self.r.read_line(&mut line).unwrap();
        line
    }

    /// What it gets until the server closes the connection.
    fn rest(mut self) -> String {
        let mut rest = String::new();
        let _ = self.r.read_to_string(&mut rest);
        rest
    }
}

#[test]
fn live_clients_take_a_lower_max_payload_at_once_and_new_ones_see_it() {
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("payload-{i}"));
        let p = Proc::start(bin, &d, "max_payload: 1024\n", &[]);
        let mut c = Client::new(p.port, r#"{"verbose":false}"#);
        assert_eq!(c.info["max_payload"], 1024);
        p.write("max_payload: 512\n");
        p.hup();
        let fresh = Client::new(p.port, r#"{"verbose":false}"#);
        let big = "x".repeat(600);
        c.send(&format!("PUB a 600\r\n{big}\r\n"));
        seen.push((fresh.info["max_payload"].clone(), c.rest()));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    assert_eq!(seen[0].0, 512);
    assert_eq!(seen[0].1, "-ERR 'Maximum Payload Violation'\r\n");
}

#[test]
fn flags_given_at_the_start_hold_over_the_file_on_a_reload() {
    let d = dir("flags");
    let flag_port = free_port();
    let port = flag_port.to_string();
    let p = Proc::start(
        NAQ.as_ref(),
        &d,
        "",
        &["-p", &port, "--max_traced_msg_len", "7"],
    );
    p.write("max_payload: 512\n");
    p.hup();
    let lines = reload_lines(&lines_once(&p.log(), |_| true));
    assert_eq!(
        lines,
        [
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded: max_payload = 512",
            "[INF] Reloaded server configuration (sha256:...)",
        ]
    );
    let c = Client::new(flag_port, r#"{"verbose":false}"#);
    assert_eq!(c.info["max_payload"], 512);
}

#[test]
fn a_server_without_a_configuration_file_cannot_reload() {
    let o = Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        ..Options::default()
    };
    let s = Server::start(&o).unwrap();
    let e = s.reload().unwrap_err();
    assert_eq!(
        e.to_string(),
        "can only reload config when a file is provided using -c or --config"
    );
    s.shutdown();
}

#[test]
fn reload_with_reads_the_options_its_own_way_and_a_refusal_changes_nothing() {
    let d = dir("read-with");
    let o = Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        http_port: Some(0),
        ..Options::default()
    };
    let s = Server::start(&o).unwrap();
    let varz = || {
        let at = s.monitor_addr().unwrap();
        let mut c = TcpStream::connect(at).unwrap();
        c.write_all(b"GET /varz HTTP/1.0\r\n\r\n").unwrap();
        let mut body = String::new();
        c.read_to_string(&mut body).unwrap();
        let (_, json) = body.split_once("\r\n\r\n").unwrap();
        serde_json::from_str::<serde_json::Value>(json).unwrap()
    };
    let first = varz();
    let next = std::sync::Arc::new(std::sync::Mutex::new(o.clone()));
    let read = next.clone();
    s.reload_with(move || Ok(read.lock().unwrap().clone()));
    // A port of its own refuses the lower payload with it.
    let mut refused = o.clone();
    refused.max_payload = 512;
    refused.http_port = Some(1);
    *next.lock().unwrap() = refused;
    let e = s.reload().unwrap_err();
    assert_eq!(
        e.to_string(),
        "config reload not supported for HTTPPort: old=-1, new=1"
    );
    let after = varz();
    assert_eq!(after["max_payload"], 1 << 20);
    assert_eq!(after["config_load_time"], first["config_load_time"]);
    let mut lower = o.clone();
    lower.max_payload = 512;
    *next.lock().unwrap() = lower;
    s.reload().unwrap();
    let after = varz();
    assert_eq!(after["max_payload"], 512);
    assert_ne!(after["config_load_time"], first["config_load_time"]);
    drop(d);
    s.shutdown();
}

/// `line` without its process ID, with the address and ID of its client,
/// if any, as `P` and `N`.
fn plain(line: &str) -> String {
    let rest = line.split_once("] ").map_or(line, |(_, r)| r);
    let Some((head, tail)) = rest.split_once(" 127.0.0.1:") else {
        return rest.to_owned();
    };
    let tail = tail.split_once(" - cid:").map_or(tail, |(_, t)| t);
    let tail = tail.split_once(' ').map_or("", |(_, t)| t);
    format!("{head} 127.0.0.1:P - cid:N {tail}")
}

#[test]
fn the_log_moves_to_a_new_file_and_live_clients_are_traced() {
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("log-{i}"));
        let p = Proc::start(bin, &d, "", &[]);
        let mut c = Client::new(p.port, r#"{"verbose":false,"name":"app"}"#);
        let moved = d.join("moved.log");
        p.write(&format!(
            "log_file: {:?}\ntrace: true\n",
            moved.display().to_string()
        ));
        let ok = Command::new("kill")
            .args(["-s", "HUP", &p.child.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok);
        lines_once(&moved, |l| l.iter().any(|l| ends_reload(l)));
        c.send("PUB a 2\r\nhi\r\nPING\r\n");
        while c.line() != "PONG\r\n" {}
        let old = lines_once(&p.log(), |l| l.iter().any(|l| l.contains("log_file")));
        let new = lines_once(&moved, |l| l.iter().any(|l| l.contains("->> [PONG]")));
        let from = old.iter().position(|l| l.contains("Trapped")).unwrap();
        // The directories and digests are those of each run.
        let at = d.display().to_string();
        let mask = |l: &String| {
            let l = plain(l).replace(&at, "DIR");
            l.split_once(" (sha256:")
                .map_or(l.clone(), |(h, _)| h.to_owned())
        };
        let old: Vec<String> = old[from..].iter().map(mask).collect();
        let new: Vec<String> = new.iter().map(mask).collect();
        seen.push((old, new));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    let (old, new) = &seen[0];
    assert_eq!(
        old,
        &[
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: trace = true",
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded: log_file = DIR/moved.log",
        ]
    );
    assert_eq!(
        new,
        &[
            "[INF] Reloaded server configuration",
            r#"[TRC] 127.0.0.1:P - cid:N - "app" - <<- [PUB a 2]"#,
            r#"[TRC] 127.0.0.1:P - cid:N - "app" - <<- MSG_PAYLOAD: ["hi"]"#,
            r#"[TRC] 127.0.0.1:P - cid:N - "app" - <<- [PING]"#,
            r#"[TRC] 127.0.0.1:P - cid:N - "app" - ->> [PONG]"#,
        ]
    );
}

#[test]
fn live_clients_ping_at_the_new_interval_from_their_next_ping() {
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("ping-{i}"));
        let p = Proc::start(bin, &d, "ping_interval: \"1h\"\n", &[]);
        let mut c = Client::new(p.port, r#"{"verbose":false}"#);
        p.write("ping_interval: \"200ms\"\n");
        p.hup();
        // The first, as for any client, then at the new interval.
        assert_eq!(c.line(), "PING\r\n");
        c.send("PONG\r\n");
        let at = Instant::now();
        assert_eq!(c.line(), "PING\r\n");
        assert!(
            at.elapsed() < Duration::from_secs(1),
            "{bin:?}: {:?}",
            at.elapsed()
        );
    }
}

/// The configuration of a system account with user `sys`.
const SYSTEM: &str = "server_name: s1\naccounts { SYS { users [{user: sys, password: p}] } }\n\
                      system_account: SYS\n";

/// Asks for a reload on `$SYS` as `c`, of the server of ID `id`, and
/// returns the answer, its server block masked.
fn ask_reload(c: &mut Client, id: &str) -> serde_json::Value {
    c.send(&format!("PUB $SYS.REQ.SERVER.{id}.RELOAD _R 0\r\n\r\n"));
    let head = c.line();
    assert!(head.starts_with("MSG _R 1 "), "{head}");
    let mut a: serde_json::Value = serde_json::from_str(c.line().trim_end()).unwrap();
    a["server"] = serde_json::Value::Null;
    a
}

#[test]
fn a_reload_asked_on_sys_answers_how_it_went_and_logs_only_a_success() {
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("sys-{i}"));
        let p = Proc::start(bin, &d, SYSTEM, &[]);
        let mut c = Client::new(p.port, r#"{"verbose":false,"user":"sys","pass":"p"}"#);
        let id = c.info["server_id"].as_str().unwrap().to_owned();
        c.send("SUB _R 1\r\nPING\r\n");
        while c.line() != "PONG\r\n" {}
        p.write(&format!("{SYSTEM}max_payload: 512\n"));
        let went = ask_reload(&mut c, &id);
        p.write(&SYSTEM.replace("s1", "s2"));
        let refused = ask_reload(&mut c, &id);
        let lines = lines_once(&p.log(), |l| l.iter().any(|l| ends_reload(l)));
        seen.push((went, refused, reload_lines(&lines)));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    let (went, refused, lines) = &seen[0];
    assert_eq!(went, &serde_json::json!({"server": null}));
    assert_eq!(
        refused,
        &serde_json::json!({
            "server": null,
            "error": {
                "code": 500,
                "description": "config reload not supported for ServerName: old=s1, new=s2"
            }
        })
    );
    assert_eq!(
        lines,
        &[
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded: max_payload = 512",
            "[INF] Reloaded server configuration (sha256:...)",
        ]
    );
}

#[test]
fn a_reload_writes_the_pid_to_a_new_path_and_moves_the_ports_file() {
    let d = dir("files");
    let (one, two) = (d.join("one"), d.join("two"));
    std::fs::create_dir_all(&one).unwrap();
    std::fs::create_dir_all(&two).unwrap();
    let o = Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        pid_file: Some(one.join("naq.pid")),
        ports_file_dir: Some(one.clone()),
        ..Options::default()
    };
    let s = Server::start(&o).unwrap();
    let ports = |dir: &Path| {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "ports"))
            .count()
    };
    assert_eq!(ports(&one), 1);
    let mut moved = o.clone();
    moved.pid_file = Some(two.join("naq.pid"));
    moved.ports_file_dir = Some(two.clone());
    s.reload_with(move || Ok(moved.clone()));
    s.reload().unwrap();
    let pid = std::process::id().to_string();
    assert_eq!(std::fs::read_to_string(two.join("naq.pid")).unwrap(), pid);
    // The old one stays, as in nats-server.
    assert_eq!(std::fs::read_to_string(one.join("naq.pid")).unwrap(), pid);
    assert_eq!((ports(&one), ports(&two)), (0, 1));
    s.shutdown();
    assert_eq!(ports(&two), 0);
}

#[test]
fn a_reload_from_its_file_logs_what_it_cannot_write_and_goes_on() {
    let d = dir("unwritable");
    let (log, one) = (d.join("server.log"), d.join("one"));
    std::fs::create_dir_all(&one).unwrap();
    let conf = d.join("server.conf");
    let head = format!(
        "listen: 127.0.0.1:-1\nlog_file: {:?}\nlogtime: false\n",
        log.display().to_string()
    );
    let first = format!("ports_file_dir: {:?}\n", one.display().to_string());
    std::fs::write(&conf, format!("{head}{first}")).unwrap();
    let s = Server::start(&Options::from_file(&conf).unwrap()).unwrap();
    // Gone already: it cannot be removed.
    let ports = std::fs::read_dir(&one)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(&ports).unwrap();
    let missing = d.join("missing");
    let m = missing.display().to_string();
    let next = format!(
        "pid_file: {:?}\nports_file_dir: {:?}\nlog_file: {:?}\ntrace_headers: true\n",
        format!("{m}/naq.pid"),
        m,
        format!("{m}/server.log")
    );
    std::fs::write(&conf, format!("{head}{next}")).unwrap();
    s.reload().unwrap();
    let lines = lines_once(&log, |l| l.iter().any(|l| ends_reload(l)));
    let from = lines.iter().position(|l| l.contains("Reloaded:")).unwrap();
    let gone = "No such file or directory (os error 2)";
    let shown: Vec<String> = lines[from..]
        .iter()
        .map(|l| plain(l).replace(&ports.display().to_string(), "PORTS"))
        .map(|l| {
            l.split_once(" (sha256:")
                .map_or(l.clone(), |(h, _)| h.to_owned())
        })
        .collect();
    assert_eq!(
        shown,
        [
            "[INF] Reloaded: trace = true".to_owned(),
            "[INF] Reloaded: trace_headers = true".to_owned(),
            "[INF] Reloaded: authorization users".to_owned(),
            "[INF] Reloaded: accounts".to_owned(),
            format!("[ERR] Failed to write pidfile: {gone}"),
            format!("[INF] Reloaded: pid_file = {m}/naq.pid"),
            format!("[ERR] Error cleaning up ports file PORTS: {gone}"),
            format!("[ERR] Error writing ports file ({m}): {gone}"),
            format!("[INF] Reloaded: ports_file_dir = {m}"),
            format!("[INF] Reloaded: log_file = {m}/server.log"),
            format!("[ERR] Failed to reload the log: {gone}"),
            "[INF] Reloaded server configuration".to_owned(),
        ]
    );
    s.shutdown();
}

/// Users `a` and `b` in account `APP`, and what `extra` adds.
fn app(extra: &str, a: &str, b: &str) -> String {
    format!("debug: true\naccounts {{\n  APP {{ users: [{a}, {b}] }}\n{extra}}}\n")
}

/// The lines of the log a reload of live clients leaves: those of the
/// server at `INF` and above but for its start, and those of clients
/// closing, from the first reload on.
/// Clients closed by one reload are in no set order: `nats-server` walks
/// a map.
fn auth_lines(lines: &[String]) -> Vec<String> {
    let from = lines.iter().position(|l| l.contains("Trapped")).unwrap();
    let mut all: Vec<String> = lines[from..]
        .iter()
        .map(|l| plain(l))
        .filter(|l| {
            !l.starts_with("[DBG]") && !l.starts_with("[TRC]")
                || l.contains("Client connection closed")
        })
        .map(|l| {
            l.split_once(" (sha256:")
                .map_or(l.clone(), |(h, _)| format!("{h} (sha256:...)"))
        })
        .collect();
    let closed = |l: &String| l.contains("Client connection closed: Client Closed");
    let mut i = 0;
    while i < all.len() {
        let run = all[i..].iter().take_while(|l| closed(l)).count();
        all[i..i + run].sort();
        i += run.max(1);
    }
    all
}

#[test]
fn live_clients_lose_subscriptions_their_permissions_no_longer_allow() {
    let a = "{user: a, password: a}";
    let b = "{user: b, password: b}";
    let denied =
        "{user: a, password: a, permissions: {publish: {deny: foo}, subscribe: {deny: foo}}}";
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("perms-{i}"));
        let p = Proc::start(bin, &d, &app("", a, b), &[]);
        let mut ca = Client::new(
            p.port,
            r#"{"verbose":false,"user":"a","pass":"a","name":"ca"}"#,
        );
        ca.send("SUB foo 1\r\nSUB bar q 2\r\nPING\r\n");
        while ca.line() != "PONG\r\n" {}
        p.write(&app("", denied, b));
        p.hup();
        let got = ca.line();
        ca.send("PUB foo 1\r\nx\r\nPUB bar 1\r\ny\r\nPING\r\n");
        let after = [ca.line(), ca.line(), ca.line()];
        let lines = lines_once(&p.log(), |l| l.iter().any(|l| ends_reload(l)));
        seen.push((got, after, auth_lines(&lines)));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    let (got, after, lines) = &seen[0];
    assert_eq!(
        got,
        "-ERR 'Permissions Violation for Subscription to \"foo\" (sid \"1\")'\r\n"
    );
    assert_eq!(
        after[0],
        "-ERR 'Permissions Violation for Publish to \"foo\"'\r\n"
    );
    assert_eq!(after[1], "MSG bar 2 1\r\n");
    assert_eq!(
        lines,
        &[
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            r#"[INF] Removed sub "foo" (sid "1") for User "a" - not authorized"#,
            "[INF] Reloaded server configuration (sha256:...)",
            r#"[ERR] 127.0.0.1:P - cid:N - "ca" - "APP/user:a" - Publish Violation - Subject "foo""#,
        ]
    );
}

#[test]
fn live_clients_whose_users_went_moved_or_lost_their_password_go() {
    let (user_a, user_b, user_c) = (
        "{user: a, password: a}",
        "{user: b, password: b}",
        "{user: c, password: c}",
    );
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("users-{i}"));
        let first = app(
            "  OTHER { users: [] }\n",
            user_a,
            &format!("{user_b}, {user_c}"),
        );
        let p = Proc::start(bin, &d, &first, &[]);
        let login = |u: &str| {
            let connect = format!(r#"{{"verbose":false,"user":"{u}","pass":"{u}","name":"{u}"}}"#);
            Client::new(p.port, &connect)
        };
        let (ca, cb, cc) = (login("a"), login("b"), login("c"));
        // b goes, c moves to OTHER.
        p.write(&app(
            &format!("  OTHER {{ users: [{user_c}] }}\n"),
            user_a,
            "{user: x, password: x}",
        ));
        p.hup();
        let (b_got, c_got) = (cb.rest(), cc.rest());
        // a's password changes.
        p.write(&app("", "{user: a, password: a2}", user_b));
        p.hup();
        let a_got = ca.rest();
        let lines = lines_once(&p.log(), |l| {
            l.iter().filter(|l| ends_reload(l)).count() >= 2
        });
        seen.push((a_got, b_got, c_got, auth_lines(&lines)));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    let (a_got, b_got, c_got, lines) = &seen[0];
    assert_eq!(a_got, "-ERR 'Authorization Violation'\r\n");
    assert_eq!((b_got.as_str(), c_got.as_str()), ("", ""));
    assert_eq!(
        lines,
        &[
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            r#"[DBG] 127.0.0.1:P - cid:N - "b" - "APP/user:b" - Client connection closed: Client Closed"#,
            r#"[DBG] 127.0.0.1:P - cid:N - "c" - "APP/user:c" - Client connection closed: Client Closed"#,
            "[INF] Reloaded server configuration (sha256:...)",
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            r#"[ERR] 127.0.0.1:P - cid:N - "a" - "APP/user:a" - authentication error - User "a""#,
            r#"[DBG] 127.0.0.1:P - cid:N - "a" - "APP/user:a" - Client connection closed: Authentication Failure"#,
            "[INF] Reloaded server configuration (sha256:...)",
        ]
    );
}

#[test]
fn the_single_user_and_the_token_reload_and_hold_their_clients_to_them() {
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("single-{i}"));
        let single = "authorization { user: u, password: p }\n";
        let p = Proc::start(bin, &d, single, &[]);
        let mut cu = Client::new(
            p.port,
            r#"{"verbose":false,"user":"u","pass":"p","name":"u"}"#,
        );
        // Unchanged: the client stays.
        p.write(single);
        p.hup();
        cu.send("PING\r\n");
        let stayed = cu.line();
        p.write("authorization { user: u, password: p2 }\n");
        p.hup();
        let u_got = cu.rest();
        p.write("authorization { token: t }\n");
        p.hup();
        let ct = Client::new(p.port, r#"{"verbose":false,"auth_token":"t","name":"t"}"#);
        p.write("authorization { token: t2 }\n");
        p.hup();
        let t_got = ct.rest();
        let lines = lines_once(&p.log(), |l| {
            l.iter().filter(|l| ends_reload(l)).count() >= 4
        });
        seen.push((stayed, u_got, t_got, reload_lines(&lines)));
    }
    // nats-server closes the clients of the single user at every reload,
    // as moved: they are not of its user list.
    if let [naq, go] = &seen[..] {
        assert_eq!((&naq.2, &naq.3), (&go.2, &go.3), "naq, then nats-server");
    }
    let (stayed, u_got, t_got, lines) = &seen[0];
    assert_eq!(stayed, "PONG\r\n");
    assert_eq!(u_got, "-ERR 'Authorization Violation'\r\n");
    assert_eq!(t_got, "-ERR 'Authorization Violation'\r\n");
    assert_eq!(
        lines,
        &[
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded server configuration (sha256:...)",
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded: authorization password",
            "[INF] Reloaded server configuration (sha256:...)",
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded: authorization username",
            "[INF] Reloaded: authorization password",
            "[INF] Reloaded: authorization token",
            "[INF] Reloaded server configuration (sha256:...)",
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded: authorization token",
            "[INF] Reloaded server configuration (sha256:...)",
        ]
    );
}

#[test]
fn an_account_a_reload_adds_takes_its_users_apart_from_the_others() {
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("added-{i}"));
        let first = "accounts { APP { users: [{user: a, password: a}] } }\n";
        let p = Proc::start(bin, &d, first, &[]);
        let mut ca = Client::new(p.port, r#"{"verbose":false,"user":"a","pass":"a"}"#);
        ca.send("SUB x 1\r\nPING\r\n");
        while ca.line() != "PONG\r\n" {}
        p.write(
            "accounts { APP { users: [{user: a, password: a}] }, \
             NEW { users: [{user: n, password: n}] } }\n",
        );
        p.hup();
        let mut cn = Client::new(p.port, r#"{"verbose":false,"user":"n","pass":"n"}"#);
        cn.send("SUB x 1\r\nPUB x 2\r\nhi\r\nPING\r\n");
        let n_got = [cn.line(), cn.line(), cn.line()];
        ca.send("PING\r\n");
        let a_got = ca.line();
        seen.push((n_got, a_got));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    let (n_got, a_got) = &seen[0];
    assert_eq!(n_got, &["MSG x 1 2\r\n", "hi\r\n", "PONG\r\n"]);
    assert_eq!(a_got, "PONG\r\n", "APP got nothing of NEW");
}

#[test]
fn clients_of_a_server_without_users_must_log_in_once_it_has_some() {
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("open-{i}"));
        let p = Proc::start(bin, &d, "", &[]);
        let c = Client::new(p.port, r#"{"verbose":false}"#);
        p.write("authorization { users: [{user: a, password: a}] }\n");
        p.hup();
        let fresh = Client::new(p.port, r#"{"verbose":false,"user":"a","pass":"a"}"#);
        seen.push((c.rest(), fresh.info["auth_required"].clone()));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    assert_eq!(seen[0].0, "-ERR 'Authorization Violation'\r\n");
    assert_eq!(seen[0].1, true);
}

#[test]
fn the_no_auth_user_goes_only_with_its_user() {
    let users = "authorization { users: [{user: a, password: a}, {user: b, password: b}] }\n";
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("noauth-{i}"));
        let p = Proc::start(bin, &d, &format!("{users}no_auth_user: a\n"), &[]);
        p.write(&format!("{users}no_auth_user: b\n"));
        p.hup();
        p.write(users);
        p.hup();
        p.write("authorization { users: [{user: b, password: b}] }\n");
        p.hup();
        let lines = lines_once(&p.log(), |l| {
            l.iter().filter(|l| ends_reload(l)).count() >= 3
        });
        seen.push(reload_lines(&lines));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    let refused =
        "[ERR] Failed to reload server configuration: config reload not supported for NoAuthUser";
    assert_eq!(
        seen[0],
        [
            r#"[INF] Trapped "hangup" signal"#.to_owned(),
            format!("{refused}: old=a, new=b"),
            r#"[INF] Trapped "hangup" signal"#.to_owned(),
            format!("{refused}: old=a, new="),
            r#"[INF] Trapped "hangup" signal"#.to_owned(),
            "[INF] Reloaded: authorization users".to_owned(),
            "[INF] Reloaded: accounts".to_owned(),
            "[INF] Reloaded server configuration (sha256:...)".to_owned(),
        ]
    );
}

#[test]
fn nkey_users_and_the_login_timeout_reload_and_links_of_accounts_do_not() {
    let key = nkeys::KeyPair::new_user().public_key();
    let accounts =
        "accounts { A { exports: [{stream: x}] }, B { users: [{user: b, password: b}] } }\n";
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        let d = dir(&format!("nkeys-{i}"));
        let p = Proc::start(bin, &d, accounts, &[]);
        let users = format!("authorization {{ timeout: 3, users: [{{nkey: {key}}}] }}\n");
        p.write(&format!("{accounts}{users}"));
        p.hup();
        let imports = accounts.replace(
            "users:",
            "imports: [{stream: {account: A, subject: x}}], users:",
        );
        p.write(&format!("{imports}{users}"));
        p.hup();
        let lines = lines_once(&p.log(), |l| {
            l.iter().filter(|l| ends_reload(l)).count() >= 2
        });
        seen.push(reload_lines(&lines));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq[..6], go[..6], "naq, then nats-server");
    }
    assert_eq!(
        seen[0],
        [
            r#"[INF] Trapped "hangup" signal"#,
            "[INF] Reloaded: authorization nkey users",
            "[INF] Reloaded: authorization users",
            "[INF] Reloaded: accounts",
            "[INF] Reloaded: authorization timeout = 3",
            "[INF] Reloaded server configuration (sha256:...)",
            r#"[INF] Trapped "hangup" signal"#,
            "[ERR] Failed to reload server configuration: config reload not supported for \
             Accounts: the exports and imports of \"B\"",
        ]
    );
}

#[test]
fn a_bcrypt_password_holds_against_a_new_hash_of_it_and_not_another() {
    let hash = |p: &str| bcrypt::hash(p, 4).unwrap();
    let d = dir("bcrypt");
    let conf = |h: &str| format!("authorization {{ users: [{{user: a, password: \"{h}\"}}] }}\n");
    let p = Proc::start(NAQ.as_ref(), &d, &conf(&hash("p")), &[]);
    let mut c = Client::new(p.port, r#"{"verbose":false,"user":"a","pass":"p"}"#);
    for h in [hash("p"), hash("p")] {
        p.write(&conf(&h));
        p.hup();
        c.send("PING\r\n");
        assert_eq!(c.line(), "PONG\r\n", "the same password holds");
    }
    p.write(&conf(&hash("q")));
    p.hup();
    assert_eq!(c.rest(), "-ERR 'Authorization Violation'\r\n");
}

/// Writes a certificate for 127.0.0.1 that expires in `year`, and its key,
/// to `name-cert.pem` and `name-key.pem` in `dir`.
fn cert(dir: &Path, name: &str, year: i32) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    params.not_after = rcgen::date_time_ymd(year, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(dir.join(format!("{name}-cert.pem")), cert.pem()).unwrap();
    std::fs::write(dir.join(format!("{name}-key.pem")), key.serialize_pem()).unwrap();
}

/// The first `INFO` a client of `port` gets.
fn first_info(port: u16) -> serde_json::Value {
    let w = TcpStream::connect(("127.0.0.1", port)).unwrap();
    w.set_read_timeout(Some(WAIT)).unwrap();
    let mut line = String::new();
    BufReader::new(w).read_line(&mut line).unwrap();
    serde_json::from_str(line.strip_prefix("INFO ").unwrap().trim_end()).unwrap()
}

/// What `bin` does as its TLS changes: whether its first and last
/// clients must use TLS, and its reload lines.
fn tls_steps(i: usize, bin: &Path) -> (serde_json::Value, serde_json::Value, Vec<String>) {
    let d = dir(&format!("tls-{i}"));
    cert(&d, "a", 2030);
    let files = format!(
        "cert_file: {:?}, key_file: {:?}",
        d.join("a-cert.pem").display().to_string(),
        d.join("a-key.pem").display().to_string()
    );
    let tls = format!("tls {{ {files} }}\n");
    let p = Proc::start(bin, &d, &tls, &[]);
    let before = first_info(p.port)["tls_required"].clone();
    // The same files, then others in their place.
    p.hup();
    cert(&d, "a", 2031);
    p.hup();
    p.write(&format!(
        "tls {{ {files}, timeout: 3, handshake_first: \"300ms\" }}\n"
    ));
    p.hup();
    p.write("");
    p.hup();
    let after = first_info(p.port)["tls_required"].clone();
    let ca = d.join("a-cert.pem").display().to_string();
    p.write(&format!(
        "tls {{ {files}, verify_and_map: true, ca_file: {ca:?} }}\n"
    ));
    p.hup();
    let lines = lines_once(&p.log(), |l| {
        l.iter().filter(|l| ends_reload(l)).count() >= 5
    });
    (before, after, reload_lines(&lines))
}

#[test]
fn tls_reloads_for_new_clients_when_its_files_or_settings_change() {
    let mut seen = Vec::new();
    for (i, bin) in binaries().iter().enumerate() {
        seen.push(tls_steps(i, bin));
    }
    if let [naq, go] = &seen[..] {
        assert_eq!(naq, go, "naq, then nats-server");
    }
    let (before, after, lines) = &seen[0];
    assert_eq!(
        (before, after),
        (&serde_json::json!(true), &serde_json::Value::Null)
    );
    let trapped = r#"[INF] Trapped "hangup" signal"#;
    let (users, accounts) = (
        "[INF] Reloaded: authorization users",
        "[INF] Reloaded: accounts",
    );
    let done = "[INF] Reloaded server configuration (sha256:...)";
    assert_eq!(
        lines,
        &[
            trapped,
            users,
            accounts,
            done,
            trapped,
            users,
            accounts,
            "[INF] Reloaded: tls = enabled",
            done,
            trapped,
            users,
            accounts,
            "[INF] Reloaded: authorization timeout = 4",
            "[INF] Reloaded: tls timeout = 3",
            "[INF] Reloaded: Client TLS handshake first: true",
            "[INF] Reloaded: Client TLS handshake first fallback delay: 300ms",
            done,
            trapped,
            users,
            accounts,
            "[INF] Reloaded: authorization timeout = 2",
            "[INF] Reloaded: tls timeout = 2",
            "[INF] Reloaded: tls = disabled",
            "[INF] Reloaded: Client TLS handshake first: false",
            "[INF] Reloaded: Client TLS handshake first fallback delay: 0s",
            done,
            trapped,
            "[ERR] Failed to reload server configuration: \
             config reload not supported for TLSMap: old=false, new=true",
        ]
    );
}

#[test]
fn new_clients_get_the_certificates_a_reload_read_and_websocket_ones_too() {
    let at = dir("certs");
    cert(&at, "a", 2030);
    cert(&at, "w", 2030);
    let tls = |name: &str| naq::Tls {
        cert_file: at.join(format!("{name}-cert.pem")),
        key_file: at.join(format!("{name}-key.pem")),
        ca_file: None,
        verify: false,
        map: false,
        timeout: Duration::from_secs(2),
        handshake_first: false,
        fallback: None,
    };
    let opts = Options {
        host: "127.0.0.1".into(),
        port: 0,
        lanes: 1,
        http_port: Some(0),
        tls: Some(tls("a")),
        websocket: Some(naq::Websocket {
            host: "127.0.0.1".into(),
            tls: Some(tls("w")),
            ..naq::Websocket::default()
        }),
        ..Options::default()
    };
    let server = Server::start(&opts).unwrap();
    let varz = || {
        let mut c = TcpStream::connect(server.monitor_addr().unwrap()).unwrap();
        c.write_all(b"GET /varz HTTP/1.0\r\n\r\n").unwrap();
        let mut body = String::new();
        c.read_to_string(&mut body).unwrap();
        let (_, json) = body.split_once("\r\n\r\n").unwrap();
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        (
            v["tls_cert_not_after"].as_str().unwrap()[..4].to_owned(),
            v["websocket"]["tls_cert_not_after"].as_str().unwrap()[..4].to_owned(),
        )
    };
    assert_eq!(varz(), ("2030".to_owned(), "2030".to_owned()));
    let next = std::sync::Arc::new(std::sync::Mutex::new(opts.clone()));
    let read = next.clone();
    server.reload_with(move || Ok(read.lock().unwrap().clone()));
    cert(&at, "a", 2031);
    cert(&at, "w", 2032);
    server.reload().unwrap();
    assert_eq!(varz(), ("2031".to_owned(), "2032".to_owned()));
    // WebSocket TLS may change, not go.
    let mut plain = opts.clone();
    if let Some(w) = plain.websocket.as_mut() {
        w.tls = None;
        w.no_tls = true;
    }
    *next.lock().unwrap() = plain;
    let e = server.reload().unwrap_err().to_string();
    assert!(
        e.starts_with("config reload not supported for Websocket"),
        "{e}"
    );
    server.shutdown();
}
