//! Service imports between accounts. Each scenario runs against naq, and
//! against `nats-server` too when `NAQ_GO` names one: both must behave
//! the same.

#![expect(clippy::unwrap_used, clippy::panic, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use naq::{Options, Server};

const WAIT: Duration = Duration::from_secs(5);

/// E exports services; I imports them; C imports from I, which imports
/// from E, for a chain.
const CONF: &str = r#"
accounts {
  E {
    users: [{user: e, password: p}, {user: r, password: p, permissions: {publish: {deny: ">"}, allow_responses: true}}]
    exports: [
      {service: "svc.>"}
      {service: "shr.>"}
      {service: single}
      {service: strm, response_type: stream}
      {service: "a.*.*"}
      {service: back}
      {service: dual}
      {service: slow, response_threshold: "1s"}
      {stream: "svc.>"}
      {service: self}
      {service: lat, latency: "lat.results"}
      {service: lat2, latency: {sampling: headers, subject: "lat.results"}}
      {service: lat3, response_threshold: "1s", latency: "lat.results"}
    ]
    imports: [{service: {account: E, subject: self}, to: me}]
  }
  F {
    users: [{user: f, password: p}]
    exports: [{service: dual}]
  }
  X {
    users: [{user: x, password: p}]
    imports: [{stream: {account: E, subject: "svc.>"}, prefix: x}]
  }
  I {
    users: [{user: i, password: p}]
    exports: [{service: "chain.>"}]
    imports: [
      {service: {account: E, subject: "svc.>"}}
      {service: {account: E, subject: single}, to: loc.single}
      {service: {account: E, subject: strm}}
      {service: {account: E, subject: "a.*.*"}, to: "b.$2.$1"}
      {service: {account: E, subject: "shr.>"}, to: "shared.>", share: true}
      {service: {account: E, subject: back}}
      {service: {account: E, subject: "svc.>"}, to: "chain.>"}
      {service: {account: E, subject: dual}}
      {service: {account: F, subject: dual}}
      {service: {account: E, subject: slow}}
      {service: {account: E, subject: lat}}
      {service: {account: E, subject: lat2}}
      {service: {account: E, subject: lat3}}
    ]
  }
  C {
    users: [{user: c, password: p}]
    imports: [{service: {account: I, subject: "chain.>"}}]
  }
}
"#;

/// A server running `CONF`: naq, or `nats-server`.
enum Target {
    Naq(Server),
    Go { _go: GoServer, port: u16 },
}

impl Target {
    fn addr(&self) -> SocketAddr {
        match self {
            Target::Naq(s) => s.addr(),
            Target::Go { port, .. } => SocketAddr::from(([127, 0, 0, 1], *port)),
        }
    }

    fn login(&self, user: &str, extra: &str) -> Client {
        Client::new(
            self.addr(),
            &format!(r#"{{"verbose":false,"user":"{user}","pass":"p"{extra}}}"#),
        )
    }
}

/// naq, then `nats-server` if `NAQ_GO` names one, each running `CONF`.
fn targets() -> Vec<(&'static str, Target)> {
    let mut opts: Options = CONF.parse().unwrap();
    opts.host = "127.0.0.1".into();
    opts.port = 0;
    opts.lanes = 2;
    let mut all = vec![("naq", Target::Naq(Server::start(&opts).unwrap()))];
    if let Some(go) = go() {
        all.push(("go", go));
    }
    all
}

fn go() -> Option<Target> {
    let bin = PathBuf::from(std::env::var_os("NAQ_GO")?);
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = std::env::temp_dir().join(format!("naq-imports-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("go.conf");
    std::fs::write(&path, format!("listen: 127.0.0.1:{port}\n{CONF}")).unwrap();
    let child = Command::new(bin)
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let go = GoServer { child, dir };
    let deadline = Instant::now() + WAIT;
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "nats-server did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(Target::Go { _go: go, port })
}

struct GoServer {
    child: Child,
    dir: PathBuf,
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A message a client got.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Msg {
    subject: String,
    sid: String,
    reply: Option<String>,
    headers: Option<String>,
    payload: String,
}

struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
}

impl Client {
    fn new(addr: SocketAddr, connect: &str) -> Client {
        let w = TcpStream::connect(addr).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let mut c = Client {
            r: BufReader::new(w.try_clone().unwrap()),
            w,
        };
        assert!(c.line().starts_with("INFO "));
        c.send(&format!("CONNECT {connect}\r\nPING\r\n"));
        assert_eq!(c.line(), "PONG");
        c
    }

    fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
    }

    /// Round trip: everything sent before has been handled.
    fn flush(&mut self) {
        self.send("PING\r\n");
        assert_eq!(self.line(), "PONG");
    }

    fn line(&mut self) -> String {
        loop {
            let mut l = String::new();
            assert_ne!(self.r.read_line(&mut l).unwrap(), 0, "closed");
            let l = l.trim_end_matches("\r\n").to_owned();
            if l != "PING" {
                return l;
            }
            self.send("PONG\r\n");
        }
    }

    fn bytes(&mut self, n: usize) -> String {
        let mut b = vec![0; n + 2];
        self.r.read_exact(&mut b).unwrap();
        b.truncate(n);
        String::from_utf8(b).unwrap()
    }

    /// The next message; anything else fails.
    fn msg(&mut self) -> Msg {
        let l = self.line();
        let parts: Vec<&str> = l.split(' ').collect();
        match parts[0] {
            "MSG" => {
                let (reply, size) = match parts.len() {
                    4 => (None, parts[3]),
                    _ => (Some(parts[3].to_owned()), parts[4]),
                };
                Msg {
                    subject: parts[1].into(),
                    sid: parts[2].into(),
                    reply,
                    headers: None,
                    payload: self.bytes(size.parse().unwrap()),
                }
            }
            "HMSG" => {
                let n = parts.len();
                let (hlen, total): (usize, usize) =
                    (parts[n - 2].parse().unwrap(), parts[n - 1].parse().unwrap());
                let reply = (n == 6).then(|| parts[3].to_owned());
                let all = self.bytes(total);
                Msg {
                    subject: parts[1].into(),
                    sid: parts[2].into(),
                    reply,
                    headers: Some(all[..hlen].to_owned()),
                    payload: all[hlen..].to_owned(),
                }
            }
            _ => panic!("not a message: {l}"),
        }
    }

    /// Sends `PING` and expects nothing but the `PONG`.
    fn nothing(&mut self) {
        self.send("PING\r\n");
        assert_eq!(self.line(), "PONG", "nothing else came first");
    }
}

/// Whether `reply` is a reply of a service import: `_R_.`, six letters or
/// digits, `.`, six more.
fn is_import_reply(reply: &str) -> bool {
    let parts: Vec<&str> = reply.split('.').collect();
    parts.len() == 3
        && parts[0] == "_R_"
        && parts[1..]
            .iter()
            .all(|p| p.len() == 6 && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// The `Nats-Request-Info` of `m`, as JSON.
fn request_info(m: &Msg) -> serde_json::Value {
    let h = m.headers.as_deref().unwrap();
    let line = h
        .lines()
        .find_map(|l| l.strip_prefix("Nats-Request-Info: "))
        .unwrap_or_else(|| panic!("no request info in {h:?}"));
    serde_json::from_str(line).unwrap()
}

#[test]
fn a_request_goes_through_an_import_and_its_response_comes_back() {
    for (name, t) in targets() {
        let mut svc = t.login("e", r#","headers":true"#);
        svc.send("SUB svc.> 1\r\n");
        svc.flush();
        let mut req = t.login("i", r#","headers":true"#);
        req.send("SUB inbox.1 1\r\nPUB svc.foo inbox.1 3\r\nreq\r\n");
        req.flush();
        let got = svc.msg();
        assert_eq!(
            (got.subject.as_str(), got.payload.as_str()),
            ("svc.foo", "req"),
            "{name}"
        );
        let reply = got.reply.clone().unwrap();
        assert!(is_import_reply(&reply), "{name}: {reply}");
        let info = request_info(&got);
        assert_eq!(info["acc"], "I", "{name}: {info}");
        assert!(info["rtt"].as_u64().unwrap() > 0, "{name}: {info}");
        assert_eq!(info.as_object().unwrap().len(), 2, "{name}: {info}");
        // One response gets through; the second finds no request.
        svc.send(&format!("PUB {reply} 2\r\nok\r\nPUB {reply} 3\r\ntwo\r\n"));
        svc.flush();
        let back = req.msg();
        assert_eq!(
            (
                back.subject.as_str(),
                back.sid.as_str(),
                back.payload.as_str()
            ),
            ("inbox.1", "1", "ok"),
            "{name}"
        );
        assert_eq!(back.reply, None, "{name}");
        req.nothing();
    }
}

#[test]
fn a_request_header_replaces_what_the_requester_sent_and_goes_last() {
    for (name, t) in targets() {
        let mut svc = t.login("e", r#","headers":true"#);
        let mut plain = t.login("e", r#","headers":false"#);
        svc.send("SUB svc.> 1\r\n");
        plain.send("SUB svc.> 2\r\n");
        svc.flush();
        plain.flush();
        let mut req = t.login("i", r#","headers":true"#);
        let h = "NATS/1.0\r\nX-A: 1\r\nNats-Request-Info: {\"acc\":\"evil\"}\r\n\r\n";
        req.send(&format!(
            "HPUB svc.h inbox.2 {} {}\r\n{h}hi\r\n",
            h.len(),
            h.len() + 2
        ));
        req.flush();
        let got = svc.msg();
        let headers = got.headers.clone().unwrap();
        assert!(
            headers.starts_with("NATS/1.0\r\nX-A: 1\r\nNats-Request-Info: {\"acc\":\"I\","),
            "{name}: {headers:?}"
        );
        assert!(headers.ends_with("}\r\n\r\n"), "{name}: {headers:?}");
        let bare = plain.msg();
        assert_eq!(
            (bare.headers, bare.payload.as_str()),
            (None, "hi"),
            "{name}"
        );
        // A request without headers gets them all the same.
        req.send("PUB svc.n 1\r\nx\r\n");
        req.flush();
        let h = svc.msg().headers.unwrap();
        assert!(
            h.starts_with("NATS/1.0\r\nNats-Request-Info: {\"acc\":\"I\""),
            "{name}: {h:?}"
        );
    }
}

#[test]
fn a_streamed_service_answers_until_an_empty_response() {
    for (name, t) in targets() {
        let mut svc = t.login("e", "");
        svc.send("SUB strm 1\r\n");
        svc.flush();
        let mut req = t.login("i", "");
        req.send("SUB inbox.3 1\r\nPUB strm inbox.3 1\r\nq\r\n");
        req.flush();
        let reply = svc.msg().reply.unwrap();
        svc.send(&format!(
            "PUB {reply} 2\r\nr1\r\nPUB {reply} 2\r\nr2\r\nPUB {reply} 0\r\n\r\nPUB {reply} 2\r\nr3\r\n"
        ));
        svc.flush();
        let got: Vec<String> = (0..3).map(|_| req.msg().payload).collect();
        assert_eq!(got, ["r1", "r2", ""], "{name}");
        req.nothing();
    }
}

#[test]
fn a_request_nobody_takes_gets_no_responders_with_the_importers_subject() {
    for (name, t) in targets() {
        let mut req = t.login("i", r#","headers":true,"no_responders":true"#);
        req.send("SUB inbox.4 1\r\nPUB loc.single inbox.4 1\r\nq\r\n");
        let m = req.msg();
        assert_eq!(
            m.headers.as_deref(),
            Some("NATS/1.0 503\r\nNats-Subject: loc.single\r\n\r\n"),
            "{name}"
        );
        assert_eq!(
            (m.subject.as_str(), m.payload.as_str()),
            ("inbox.4", ""),
            "{name}"
        );
    }
}

#[test]
fn an_import_maps_subjects_into_the_exporter() {
    for (name, t) in targets() {
        let mut svc = t.login("e", "");
        svc.send("SUB a.> 1\r\nSUB single 2\r\n");
        svc.flush();
        let mut req = t.login("i", "");
        req.send("PUB b.x.y 1\r\n1\r\nPUB loc.single 1\r\n2\r\n");
        req.flush();
        let subjects: Vec<String> = (0..2).map(|_| svc.msg().subject).collect();
        assert_eq!(subjects, ["a.y.x", "single"], "{name}");
    }
}

#[test]
fn a_shared_import_tells_the_service_who_asked() {
    for (name, t) in targets() {
        let mut svc = t.login("e", r#","headers":true"#);
        svc.send("SUB shr.> 1\r\n");
        svc.flush();
        let mut req = t.login("i", r#","name":"asker","lang":"rust","version":"1.2""#);
        req.send("PUB shared.x 1\r\nq\r\n");
        req.flush();
        let got = svc.msg();
        assert_eq!(got.subject, "shr.x", "{name}");
        let info = request_info(&got);
        for (k, v) in [
            ("acc", "I"),
            ("user", "i"),
            ("name", "asker"),
            ("lang", "rust"),
            ("ver", "1.2"),
            ("host", "127.0.0.1"),
            ("kind", "Client"),
            ("client_type", "nats"),
        ] {
            assert_eq!(info[k], v, "{name}: {k} in {info}");
        }
        for k in ["start", "id", "rtt", "server"] {
            assert!(info.get(k).is_some(), "{name}: no {k} in {info}");
        }
    }
}

#[test]
fn a_response_allowed_once_goes_through_once() {
    for (name, t) in targets() {
        let mut svc = t.login("r", "");
        svc.send("SUB single 1\r\n");
        svc.flush();
        let mut req = t.login("i", "");
        req.send("SUB inbox.5 1\r\nPUB loc.single inbox.5 1\r\nq\r\n");
        req.flush();
        let reply = svc.msg().reply.unwrap();
        svc.send(&format!("PUB {reply} 1\r\na\r\nPUB {reply} 1\r\nb\r\n"));
        assert_eq!(
            svc.line(),
            format!("-ERR 'Permissions Violation for Publish to \"{reply}\"'"),
            "{name}"
        );
        assert_eq!(req.msg().payload, "a", "{name}");
        req.nothing();
    }
}

#[test]
fn a_chain_of_imports_names_each_service_on_the_way() {
    for (name, t) in targets() {
        let mut svc = t.login("e", r#","headers":true"#);
        svc.send("SUB svc.> 1\r\n");
        svc.flush();
        let mut req = t.login("c", "");
        req.send("SUB inbox.6 1\r\nPUB chain.z inbox.6 1\r\nq\r\n");
        req.flush();
        let got = svc.msg();
        assert_eq!(got.subject, "svc.z", "{name}");
        let info = request_info(&got);
        assert_eq!(
            (info["acc"].as_str(), info["svc"].as_str()),
            (Some("C"), Some("I")),
            "{name}: {info}"
        );
        svc.send(&format!("PUB {} 2\r\nok\r\n", got.reply.unwrap()));
        svc.flush();
        assert_eq!(req.msg().payload, "ok", "{name}");
    }
}

#[test]
fn a_response_with_a_reply_can_be_answered_by_the_requester() {
    for (name, t) in targets() {
        let mut svc = t.login("e", "");
        svc.send("SUB back 1\r\nSUB breply 2\r\n");
        svc.flush();
        let mut req = t.login("i", "");
        req.send("SUB inbox.7 1\r\nPUB back inbox.7 1\r\nq\r\n");
        req.flush();
        let reply = svc.msg().reply.unwrap();
        svc.send(&format!("PUB {reply} breply 1\r\nr\r\n"));
        svc.flush();
        let r = req.msg();
        let again = r.reply.unwrap();
        assert!(is_import_reply(&again) && again != reply, "{name}: {again}");
        req.send(&format!("PUB {again} 2\r\nre\r\n"));
        req.flush();
        let last = svc.msg();
        assert_eq!(
            (last.subject.as_str(), last.payload.as_str()),
            ("breply", "re"),
            "{name}"
        );
    }
}

#[test]
fn an_importer_subscribed_to_its_import_subject_gets_the_request_too() {
    for (name, t) in targets() {
        let mut svc = t.login("e", "");
        svc.send("SUB svc.> 1\r\n");
        svc.flush();
        let mut own = t.login("i", "");
        own.send("SUB svc.* 1\r\n");
        own.flush();
        let mut req = t.login("i", "");
        req.send("PUB svc.k 1\r\nq\r\n");
        req.flush();
        assert_eq!(own.msg().subject, "svc.k", "{name}");
        assert_eq!(svc.msg().subject, "svc.k", "{name}");
    }
}

#[test]
fn a_request_through_an_import_skips_stream_imports_of_the_exporter() {
    for (name, t) in targets() {
        let mut watcher = t.login("x", "");
        watcher.send("SUB x.svc.> 1\r\n");
        watcher.flush();
        let mut svc = t.login("e", "");
        svc.send("SUB svc.> 1\r\n");
        svc.flush();
        let mut req = t.login("i", "");
        req.send("PUB svc.q 1\r\nq\r\n");
        req.flush();
        assert_eq!(svc.msg().subject, "svc.q", "{name}");
        // A publish of the exporter's own reaches the stream import.
        svc.send("PUB svc.d 1\r\nd\r\n");
        assert_eq!(svc.msg().subject, "svc.d", "{name}");
        assert_eq!(
            watcher.msg().subject,
            "x.svc.d",
            "{name}: only the direct publish"
        );
    }
}

#[test]
fn two_exporters_behind_one_subject_both_get_the_request() {
    for (name, t) in targets() {
        let mut e = t.login("e", "");
        let mut f = t.login("f", "");
        for c in [&mut e, &mut f] {
            c.send("SUB dual 1\r\n");
            c.flush();
        }
        let mut req = t.login("i", "");
        req.send("PUB dual 1\r\nq\r\n");
        req.flush();
        assert_eq!(e.msg().subject, "dual", "{name}");
        assert_eq!(f.msg().subject, "dual", "{name}");
    }
}

#[test]
fn a_self_import_keeps_a_clients_requests_from_itself_without_echo() {
    for (name, t) in targets() {
        let mut quiet = t.login("e", r#","echo":false"#);
        quiet.send("SUB self 1\r\nPUB me 1\r\nq\r\n");
        quiet.nothing();
        let mut other = t.login("e", "");
        other.send("PUB me 1\r\nw\r\n");
        other.flush();
        let m = quiet.msg();
        assert_eq!(
            (m.subject.as_str(), m.payload.as_str()),
            ("self", "w"),
            "{name}"
        );
    }
}

#[test]
fn a_response_past_the_threshold_finds_no_request() {
    for (name, t) in targets() {
        let mut svc = t.login("e", "");
        svc.send("SUB slow 1\r\n");
        svc.flush();
        let mut req = t.login("i", "");
        req.send("SUB inbox.8 1\r\nPUB slow inbox.8 1\r\nq\r\n");
        req.flush();
        let reply = svc.msg().reply.unwrap();
        std::thread::sleep(Duration::from_millis(2500));
        svc.send(&format!("PUB {reply} 1\r\nr\r\n"));
        svc.flush();
        req.nothing();
        let _ = name;
    }
}

/// The latency sample `m` carries, once its line had an empty reply.
fn sample(m: &Msg) -> serde_json::Value {
    assert_eq!(
        m.reply.as_deref(),
        Some(""),
        "a sample's reply is empty: {m:?}"
    );
    serde_json::from_str(&m.payload).unwrap()
}

#[test]
fn a_sampled_request_sends_its_latency_when_answered() {
    for (name, t) in targets() {
        let mut watch = t.login("e", "");
        watch.send("SUB lat.results 1\r\n");
        watch.flush();
        let mut svc = t.login("e", r#","name":"svc""#);
        svc.send("SUB lat 1\r\n");
        svc.flush();
        let mut req = t.login("i", "");
        req.send("SUB inbox.9 1\r\nPUB lat inbox.9 1\r\nq\r\n");
        req.flush();
        let reply = svc.msg().reply.unwrap();
        let parts: Vec<&str> = reply.split('.').collect();
        assert_eq!(
            (parts.len(), parts[0], parts[3].len(), parts[4]),
            (5, "_R_", 8, "T"),
            "{name}: {reply}"
        );
        svc.send(&format!("PUB {reply} 2\r\nok\r\n"));
        svc.flush();
        assert_eq!(req.msg().payload, "ok", "{name}");
        let s = sample(&watch.msg());
        assert_eq!(
            s["type"], "io.nats.server.metric.v1.service_latency",
            "{name}: {s}"
        );
        assert_eq!(s["status"], 200, "{name}: {s}");
        assert_eq!(s["requestor"]["acc"], "I", "{name}: {s}");
        assert_eq!(
            (&s["responder"]["acc"], &s["responder"]["name"]),
            (&"E".into(), &"svc".into()),
            "{name}: {s}"
        );
        for k in ["id", "timestamp", "start", "service", "system", "total"] {
            assert!(s.get(k).is_some(), "{name}: no {k} in {s}");
        }
        assert!(s.get("description").is_none(), "{name}: {s}");
        assert!(
            s["total"].as_u64().unwrap() >= s["service"].as_u64().unwrap(),
            "{name}: {s}"
        );
    }
}

#[test]
fn a_sampled_request_without_a_reply_or_a_service_says_so() {
    for (name, t) in targets() {
        let mut watch = t.login("e", "");
        watch.send("SUB lat.results 1\r\n");
        watch.flush();
        let mut req = t.login("i", "");
        req.send("PUB lat 1\r\nq\r\n");
        req.flush();
        let s = sample(&watch.msg());
        assert_eq!(
            (&s["status"], &s["description"]),
            (&400.into(), &"Bad Request".into()),
            "{name}: {s}"
        );
        assert_eq!(s["requestor"]["acc"], "I", "{name}: {s}");
        assert_eq!(s["total"], 0, "{name}: {s}");
        req.send("SUB inbox.10 1\r\nPUB lat inbox.10 1\r\nq\r\n");
        req.flush();
        let s = sample(&watch.msg());
        assert_eq!(
            (&s["status"], &s["description"]),
            (&503.into(), &"Service Unavailable".into()),
            "{name}: {s}"
        );
    }
}

#[test]
fn a_trace_header_asks_for_a_sample() {
    for (name, t) in targets() {
        let mut watch = t.login("e", "");
        watch.send("SUB lat.results 1\r\n");
        watch.flush();
        let mut svc = t.login("e", r#","headers":true"#);
        svc.send("SUB lat2 1\r\n");
        svc.flush();
        let mut req = t.login("i", r#","headers":true"#);
        let h = "NATS/1.0\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00\r\n\r\n";
        req.send(&format!(
            "SUB inbox.11 1\r\nHPUB lat2 inbox.11 {} {}\r\n{h}q\r\n",
            h.len(),
            h.len() + 1
        ));
        req.flush();
        let reply = svc.msg().reply.unwrap();
        assert_eq!(
            reply.split('.').count(),
            3,
            "{name}: not sampled, not tracked: {reply}"
        );
        svc.send(&format!("PUB {reply} 1\r\na\r\n"));
        svc.flush();
        req.msg();
        let h = h.replace("-00\r\n\r\n", "-01\r\n\r\n");
        req.send(&format!(
            "HPUB lat2 inbox.11 {} {}\r\n{h}q\r\n",
            h.len(),
            h.len() + 1
        ));
        req.flush();
        let reply = svc.msg().reply.unwrap();
        svc.send(&format!("PUB {reply} 1\r\nb\r\n"));
        svc.flush();
        assert_eq!(req.msg().payload, "b", "{name}");
        let s = sample(&watch.msg());
        assert_eq!(s["status"], 200, "{name}: {s}");
        assert_eq!(
            s["header"]["Traceparent"][0],
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "{name}: {s}"
        );
    }
}

#[test]
fn a_sampled_request_without_a_response_in_time_says_so() {
    for (name, t) in targets() {
        let mut watch = t.login("e", "");
        watch.send("SUB lat.results 1\r\n");
        watch.flush();
        let mut svc = t.login("e", "");
        svc.send("SUB lat3 1\r\n");
        svc.flush();
        let mut req = t.login("i", "");
        req.send("SUB inbox.12 1\r\nPUB lat3 inbox.12 1\r\nq\r\n");
        req.flush();
        svc.msg();
        // Within twice the threshold, as `nats-server` sweeps.
        let s = sample(&watch.msg());
        assert_eq!(
            (&s["status"], &s["description"]),
            (&504.into(), &"Service Timeout".into()),
            "{name}: {s}"
        );
    }
}
