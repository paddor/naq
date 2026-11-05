//! Full and cache resolvers: account JWTs stored in a directory through
//! `$SYS` requests, looked up, listed, deleted, and the accounts they add
//! for the clients that log in. Each scenario runs against naq, and
//! against `nats-server` too when `NAQ_GO` names one: both must behave
//! the same.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use naq::{Options, Server};
use nkeys::KeyPair;
use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(5);

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed()
}

/// Claims `payload`, signed by `kp`.
fn sign(kp: &KeyPair, payload: &Value) -> String {
    let h = BASE64URL_NOPAD.encode(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let p = BASE64URL_NOPAD.encode(payload.to_string().as_bytes());
    let sig = kp.sign(format!("{h}.{p}").as_bytes()).unwrap();
    format!("{h}.{p}.{}", BASE64URL_NOPAD.encode(&sig))
}

/// The fields of `more` set on `into`.
fn merge(into: &mut Value, more: Value) {
    if let Value::Object(m) = more {
        for (k, v) in m {
            into[k] = v;
        }
    }
}

/// The operator and the system account of the tests.
struct World {
    op: KeyPair,
    sys: KeyPair,
}

impl World {
    fn new() -> World {
        World {
            op: KeyPair::new_operator(),
            sys: KeyPair::new_account(),
        }
    }

    /// The JWT of account `kp` with open limits and `more` in its body,
    /// signed by the operator.
    fn account(&self, kp: &KeyPair, more: Value) -> String {
        let open = json!({"conn": -1, "leaf": -1, "subs": -1, "data": -1, "payload": -1, "imports": -1, "exports": -1, "wildcards": true});
        let mut nats = json!({"type": "account", "version": 2, "limits": open});
        merge(&mut nats, more);
        let claims = json!({"jti": format!("J{}", jti()), "iat": now(), "iss": self.op.public_key(), "sub": kp.public_key(), "nats": nats});
        sign(&self.op, &claims)
    }

    /// The configuration of a server whose resolver is `resolver`, a map
    /// body in which `DIR` stands for its directory.
    fn conf(&self, resolver: &str) -> impl Fn(&Path) -> String {
        let operator = json!({"jti": "O", "iat": now(), "iss": self.op.public_key(), "sub": self.op.public_key(), "nats": {"type": "operator", "version": 2}});
        let head = format!(
            "operator: {}\nsystem_account: {}\nresolver_preload {{\n  {}: {}\n}}\n",
            sign(&self.op, &operator),
            self.sys.public_key(),
            self.sys.public_key(),
            self.account(&self.sys, json!({})),
        );
        let resolver = resolver.to_owned();
        move |dir: &Path| {
            let body = resolver.replace("DIR", &format!("{:?}", dir.display().to_string()));
            format!("{head}resolver {{ {body} }}\n")
        }
    }
}

/// A distinct `jti` part.
fn jti() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    // Relaxed: only uniqueness matters.
    N.fetch_add(1, Ordering::Relaxed)
}

/// A bearer user JWT in account `account`.
fn bearer(account: &KeyPair) -> String {
    let body = json!({"type": "user", "version": 2, "bearer_token": true, "subs": -1, "data": -1, "payload": -1});
    let claims = json!({"jti": "U", "iat": now() - 1, "iss": account.public_key(), "sub": KeyPair::new_user().public_key(), "nats": body});
    sign(account, &claims)
}

enum Target {
    Naq(Server, Scratch),
    Go(GoServer, u16),
}

impl Target {
    fn addr(&self) -> SocketAddr {
        match self {
            Target::Naq(s, _) => s.addr(),
            Target::Go(_, port) => SocketAddr::from(([127, 0, 0, 1], *port)),
        }
    }

    /// The directory of its resolver.
    fn dir(&self) -> PathBuf {
        match self {
            Target::Naq(_, s) => s.0.join("jwt"),
            Target::Go(g, _) => g.dir.0.join("jwt"),
        }
    }
}

/// A directory of a test's own, removed when it drops.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "naq-resolver-{}-{name}-{}",
            std::process::id(),
            jti()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct GoServer {
    child: Child,
    dir: Scratch,
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// naq, then `nats-server` if `NAQ_GO` names one, each running the
/// configuration `conf` makes for its directory.
fn targets(conf: impl Fn(&Path) -> String) -> Vec<(&'static str, Target)> {
    let scratch = Scratch::new("naq");
    let mut opts: Options = conf(&scratch.0.join("jwt")).parse().unwrap();
    opts.host = "127.0.0.1".into();
    opts.port = 0;
    opts.lanes = 2;
    let naq = Target::Naq(Server::start(&opts).unwrap(), scratch);
    let mut all = vec![("naq", naq)];
    if let Some(bin) = std::env::var_os("NAQ_GO").map(PathBuf::from) {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = Scratch::new("go");
        let path = dir.0.join("go.conf");
        let text = conf(&dir.0.join("jwt"));
        std::fs::write(&path, format!("listen: 127.0.0.1:{port}\n{text}")).unwrap();
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
        all.push(("go", Target::Go(go, port)));
    }
    all
}

/// A connection, read line by line.
struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
}

impl Client {
    /// Connects with user JWT `jwt`: the first line after the `CONNECT`
    /// and a `PING`.
    fn connect(t: &Target, jwt: &str) -> (Client, String) {
        Client::connect_with(t, jwt, "")
    }

    /// As [`Client::connect`], with the CONNECT fields `extra` too.
    fn connect_with(t: &Target, jwt: &str, extra: &str) -> (Client, String) {
        let w = TcpStream::connect(t.addr()).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let mut c = Client {
            r: BufReader::new(w.try_clone().unwrap()),
            w,
        };
        c.line();
        c.send(&format!(
            "CONNECT {{\"verbose\":false,\"protocol\":0,\"jwt\":\"{jwt}\"{extra}}}\r\nPING\r\n"
        ));
        let first = c.line();
        (c, first)
    }

    /// Logs in with user JWT `jwt`.
    fn login(t: &Target, jwt: &str) -> Client {
        let (c, first) = Client::connect(t, jwt);
        assert_eq!(first, "PONG", "logged in");
        c
    }

    fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
    }

    /// The next line from the server, past its `PING`s, which get their
    /// `PONG`.
    fn line(&mut self) -> String {
        loop {
            let mut l = String::new();
            assert_ne!(self.r.read_line(&mut l).unwrap(), 0, "closed");
            if l != "PING\r\n" {
                return l.trim_end_matches("\r\n").to_owned();
            }
            self.send("PONG\r\n");
        }
    }

    /// The payloads of the answers to `payload` on `subject`, until an
    /// empty one, or the first if `one`.
    fn ask(&mut self, subject: &str, payload: &str, one: bool) -> Vec<String> {
        self.send(&format!(
            "SUB _R.> 99\r\nPUB {subject} _R.1 {}\r\n{payload}\r\n",
            payload.len()
        ));
        let mut all = Vec::new();
        loop {
            let head = self.line();
            assert!(head.starts_with("MSG _R.1 99 "), "{head}");
            let body = self.line();
            let done = one || body.is_empty();
            all.push(body);
            if done {
                break;
            }
        }
        self.send("UNSUB 99\r\nPING\r\n");
        assert_eq!(self.line(), "PONG");
        all
    }

    /// The header lines of the status that comes back for `payload` on
    /// `subject` asked with `SUB _R.> 99`: no one answered.
    fn no_responders(&mut self, subject: &str, payload: &str) -> Vec<String> {
        self.send(&format!(
            "PUB {subject} _R.1 {}\r\n{payload}\r\n",
            payload.len()
        ));
        let head = self.line();
        assert!(head.starts_with("HMSG _R.1 99 "), "{subject}: {head}");
        let status = std::iter::from_fn(|| Some(self.line()))
            .take_while(|l| !l.is_empty())
            .collect();
        assert_eq!(self.line(), "", "{subject}: no payload");
        status
    }

    /// The answer to `payload` on `subject`, in JSON, without the server
    /// that sent it.
    fn json(&mut self, subject: &str, payload: &str) -> Value {
        let mut v: Value = serde_json::from_str(&self.ask(subject, payload, true)[0]).unwrap();
        v.as_object_mut().unwrap().remove("server");
        v
    }
}

/// What a full resolver says of an update of `key` that went well.
fn stored(key: &str) -> Value {
    json!({"data": {"account": key, "code": 200, "message": "jwt updated"}})
}

#[test]
fn an_account_stored_by_update_lets_its_users_in() {
    let w = World::new();
    let a = KeyPair::new_account();
    for (name, t) in targets(w.conf("type: full, dir: DIR, timeout: 300ms")) {
        let (_, first) = Client::connect(&t, &bearer(&a));
        assert_eq!(
            first, "-ERR 'Authorization Violation'",
            "{name}: unknown yet"
        );
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let jwt = w.account(&a, json!({}));
        let key = a.public_key();
        assert_eq!(
            sys.json("$SYS.REQ.CLAIMS.UPDATE", &jwt),
            stored(&key),
            "{name}"
        );
        assert!(t.dir().join(format!("{key}.jwt")).exists(), "{name}");
        let mut c = Client::login(&t, &bearer(&a));
        c.send("SUB s 1\r\nPUB s 2\r\nhi\r\n");
        assert_eq!(c.line(), "MSG s 1 2", "{name}");
        let lookup = format!("$SYS.REQ.ACCOUNT.{key}.CLAIMS.LOOKUP");
        assert_eq!(sys.ask(&lookup, "", true), [jwt], "{name}");
        let other = KeyPair::new_account().public_key();
        let missing = format!("$SYS.REQ.ACCOUNT.{other}.CLAIMS.LOOKUP");
        assert_eq!(sys.ask(&missing, "", true), [""], "{name}: nothing");
        let mut keys = vec![key, w.sys.public_key()];
        keys.sort();
        let list = sys.json("$SYS.REQ.CLAIMS.LIST", "");
        assert_eq!(list, json!({"data": keys}), "{name}");
    }
}

#[test]
fn updates_are_answered_as_a_full_resolver_answers_them() {
    let w = World::new();
    let (a, b) = (KeyPair::new_account(), KeyPair::new_account());
    for (name, t) in targets(w.conf("type: full, dir: DIR")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let by_a = format!("$SYS.REQ.ACCOUNT.{}.CLAIMS.UPDATE", a.public_key());
        let garbage = sys.json(&by_a, "x");
        let failed = |account: &str, why: &str| json!({"error": {"account": account, "code": 500, "description": why}});
        assert_eq!(
            garbage,
            failed("n/a", "jwt update resulted in error - expected 3 chunks"),
            "{name}"
        );
        let of_b = w.account(&b, json!({}));
        assert_eq!(
            sys.json(&by_a, &of_b),
            failed(
                &a.public_key(),
                "jwt update resulted in error - subject does not match jwt content"
            ),
            "{name}"
        );
        let jwt = w.account(&a, json!({}));
        assert_eq!(sys.json(&by_a, &jwt), stored(&a.public_key()), "{name}");
        assert_eq!(
            sys.json(&by_a, &jwt),
            stored(&a.public_key()),
            "{name}: the same again"
        );
        let old = format!("$SYS.ACCOUNT.{}.CLAIMS.UPDATE", b.public_key());
        assert_eq!(sys.json(&old, &of_b), stored(&b.public_key()), "{name}");
    }
}

#[test]
fn a_store_packs_its_jwts_for_a_server_of_another_hash() {
    let w = World::new();
    let a = KeyPair::new_account();
    for (name, t) in targets(w.conf("type: full, dir: DIR")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let jwt = w.account(&a, json!({}));
        sys.json("$SYS.REQ.CLAIMS.UPDATE", &jwt);
        let mut pack = sys.ask("$SYS.REQ.CLAIMS.PACK", "x", false);
        assert_eq!(pack.pop().as_deref(), Some(""), "{name}: an empty one last");
        pack.sort();
        let mut want = vec![
            format!("{}|{jwt}", a.public_key()),
            format!(
                "{}|{}",
                w.sys.public_key(),
                std::fs::read_to_string(t.dir().join(format!("{}.jwt", w.sys.public_key())))
                    .unwrap()
            ),
        ];
        want.sort();
        assert_eq!(pack, want, "{name}");
    }
}

#[test]
fn deletes_expire_the_clients_of_the_accounts_they_name() {
    let w = World::new();
    let a = KeyPair::new_account();
    let request = |nats: Value| {
        let claims = json!({"jti": "D", "iat": now(), "iss": w.op.public_key(), "sub": w.op.public_key(), "nats": nats});
        sign(&w.op, &claims)
    };
    for (name, t) in targets(w.conf("type: full, dir: DIR, allow_delete: true")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        sys.json("$SYS.REQ.CLAIMS.UPDATE", &w.account(&a, json!({})));
        let mut c = Client::login(&t, &bearer(&a));
        let failed = |why: &str| json!({"error": {"code": 500, "description": why}});
        let of_sys =
            request(json!({"accounts": [w.sys.public_key()], "type": "generic", "version": 2}));
        let who = w.op.public_key();
        assert_eq!(
            sys.json("$SYS.REQ.CLAIMS.DELETE", &of_sys),
            failed(&format!(
                "delete accounts request by {who} failed - not allowed to delete system account"
            )),
            "{name}"
        );
        let bad = request(json!({"type": "generic", "version": 2}));
        assert_eq!(
            sys.json("$SYS.REQ.CLAIMS.DELETE", &bad),
            failed(&format!(
                "delete accounts request by {who} failed - malformed request"
            )),
            "{name}"
        );
        let delete =
            request(json!({"accounts": [a.public_key()], "type": "generic", "version": 2}));
        assert_eq!(
            sys.json("$SYS.REQ.CLAIMS.DELETE", &delete),
            json!({"data": {"code": 200, "message": "deleted 1 accounts"}}),
            "{name}"
        );
        assert_eq!(c.line(), "-ERR 'Account Authentication Expired'", "{name}");
        let gone = t.dir().join(format!("{}.jwt.deleted", a.public_key()));
        assert!(gone.exists(), "{name}: renamed");
    }
}

#[test]
fn deletes_need_the_resolver_to_allow_them() {
    let w = World::new();
    for (name, t) in targets(w.conf("type: full, dir: DIR")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let nats = json!({"accounts": [KeyPair::new_account().public_key()], "type": "generic", "version": 2});
        let claims = json!({"jti": "D", "iat": now(), "iss": w.op.public_key(), "sub": w.op.public_key(), "nats": nats});
        let answer = sys.json("$SYS.REQ.CLAIMS.DELETE", &sign(&w.op, &claims));
        let why = format!(
            "delete accounts request by {} failed - delete must be enabled in server config",
            w.op.public_key()
        );
        assert_eq!(
            answer,
            json!({"error": {"code": 500, "description": why}}),
            "{name}"
        );
    }
}

#[test]
fn an_account_fetched_at_login_brings_the_accounts_it_imports_from() {
    let w = World::new();
    let (svc, app) = (KeyPair::new_account(), KeyPair::new_account());
    for (name, t) in targets(w.conf("type: full, dir: DIR")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let exports = json!({"exports": [
            {"name": "q", "subject": "q", "type": "service"},
            {"name": "s", "subject": "s", "type": "stream"},
        ]});
        sys.json("$SYS.REQ.CLAIMS.UPDATE", &w.account(&svc, exports));
        let imports = json!({"imports": [
            {"name": "q", "subject": "q", "account": svc.public_key(), "type": "service"},
            {"name": "s", "subject": "s", "account": svc.public_key(), "type": "stream"},
        ]});
        sys.json("$SYS.REQ.CLAIMS.UPDATE", &w.account(&app, imports));
        let mut user = Client::login(&t, &bearer(&app));
        user.send("SUB s 1\r\nSUB _INBOX.> 2\r\nPING\r\n");
        assert_eq!(user.line(), "PONG");
        let mut service = Client::login(&t, &bearer(&svc));
        service.send("SUB q 1\r\nPING\r\n");
        assert_eq!(service.line(), "PONG");
        service.send("PUB s 4\r\nnews\r\n");
        assert_eq!(user.line(), "MSG s 1 4", "{name}: streamed");
        assert_eq!(user.line(), "news");
        user.send("PUB q _INBOX.r 3\r\nask\r\n");
        let head = service.line();
        assert!(head.starts_with("MSG q 1 _R_."), "{name}: {head}");
        let reply = head.split(' ').nth(3).unwrap().to_owned();
        assert_eq!(service.line(), "ask");
        service.send(&format!("PUB {reply} 6\r\nanswer\r\n"));
        assert_eq!(user.line(), "MSG _INBOX.r 2 6", "{name}: answered");
        assert_eq!(user.line(), "answer");
    }
}

#[test]
fn a_cache_skips_updates_of_accounts_not_in_use() {
    let w = World::new();
    let a = KeyPair::new_account();
    for (name, t) in targets(w.conf("type: cache, dir: DIR")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let by_a = format!("$SYS.REQ.ACCOUNT.{}.CLAIMS.UPDATE", a.public_key());
        let answer = sys.json(&by_a, &w.account(&a, json!({})));
        let skipped = json!({"data": {"account": a.public_key(), "code": 200, "message": "jwt update cache skipped"}});
        assert_eq!(answer, skipped, "{name}");
        let by_sys = format!("$SYS.REQ.ACCOUNT.{}.CLAIMS.UPDATE", w.sys.public_key());
        let answer = sys.json(&by_sys, &w.account(&w.sys, json!({})));
        let done = json!({"data": {"account": w.sys.public_key(), "code": 200, "message": "jwt updated cache"}});
        assert_eq!(answer, done, "{name}: the system account is in use");
    }
}

/// A free port on the loopback, from a range of this process's own.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 31_000 - (std::process::id() % 400) as u16 * 30;
    loop {
        // Relaxed: only uniqueness matters.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = base - n % 2_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A cluster of two naq servers, of the resolvers `resolvers`, each with
/// the JWTs `files` has for it in its directory from the start.
fn cluster(w: &World, resolvers: [&str; 2], files: [&[(&KeyPair, String)]; 2]) -> Vec<Target> {
    let ports = [free_port(), free_port()];
    (0..2)
        .map(|i| {
            let scratch = Scratch::new("cluster");
            let dir = scratch.0.join("jwt");
            std::fs::create_dir_all(&dir).unwrap();
            for (kp, jwt) in files[i] {
                std::fs::write(dir.join(format!("{}.jwt", kp.public_key())), jwt).unwrap();
            }
            let cluster = format!(
                "cluster {{ name: c, listen: \"127.0.0.1:{}\", routes: [\"nats-route://127.0.0.1:{}\"] }}\nserver_name: n{i}\n",
                ports[i],
                ports[1 - i]
            );
            let text = format!("{cluster}{}", w.conf(resolvers[i])(&dir));
            let mut opts: Options = text.parse().unwrap();
            opts.host = "127.0.0.1".into();
            opts.port = 0;
            opts.lanes = 2;
            Target::Naq(Server::start(&opts).unwrap(), scratch)
        })
        .collect()
}

/// Logs in with `jwt`, again until the server lets it in.
fn login_until_in(t: &Target, jwt: &str) -> Client {
    let deadline = Instant::now() + WAIT;
    loop {
        let (c, first) = Client::connect(t, jwt);
        if first == "PONG" {
            return c;
        }
        assert!(Instant::now() < deadline, "not let in: {first}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_cache_fetches_the_accounts_of_its_clients_from_a_full_resolver() {
    let w = World::new();
    let a = KeyPair::new_account();
    let jwt = w.account(&a, json!({}));
    let full = [(&a, jwt.clone())];
    let resolvers = [
        "type: full, dir: DIR",
        "type: cache, dir: DIR, timeout: 300ms",
    ];
    let servers = cluster(&w, resolvers, [&full, &[]]);
    let mut sub = Client::login(&servers[0], &bearer(&a));
    sub.send("SUB s 1\r\nPING\r\n");
    assert_eq!(sub.line(), "PONG");
    let mut publisher = login_until_in(&servers[1], &bearer(&a));
    let cached = servers[1].dir().join(format!("{}.jwt", a.public_key()));
    assert_eq!(std::fs::read_to_string(cached).unwrap(), jwt, "stored");
    // The interest of an account the cache lacked reached it all the same.
    let deadline = Instant::now() + WAIT;
    loop {
        publisher.send("PUB s 2\r\nhi\r\nPING\r\n");
        assert_eq!(publisher.line(), "PONG");
        sub.send("PING\r\n");
        let line = sub.line();
        if line == "MSG s 1 2" {
            break;
        }
        assert_eq!(line, "PONG");
        assert!(Instant::now() < deadline, "nothing came");
    }
}

#[test]
fn full_resolvers_of_a_cluster_take_the_jwts_they_lack_from_each_other() {
    let w = World::new();
    let a = KeyPair::new_account();
    let jwt = w.account(&a, json!({}));
    let full = [(&a, jwt.clone())];
    let resolvers = [
        "type: full, dir: DIR",
        "type: full, dir: DIR, interval: 100ms",
    ];
    let servers = cluster(&w, resolvers, [&full, &[]]);
    let synced = servers[1].dir().join(format!("{}.jwt", a.public_key()));
    let deadline = Instant::now() + WAIT;
    while std::fs::read_to_string(&synced).ok().as_deref() != Some(jwt.as_str()) {
        assert!(Instant::now() < deadline, "not synced");
        std::thread::sleep(Duration::from_millis(20));
    }
    Client::login(&servers[1], &bearer(&a));
}

#[test]
fn the_system_account_may_come_from_the_directory() {
    let w = World::new();
    let operator = json!({"jti": "O", "iat": now(), "iss": w.op.public_key(), "sub": w.op.public_key(), "nats": {"type": "operator", "version": 2}});
    let (op, sys) = (sign(&w.op, &operator), w.account(&w.sys, json!({})));
    let conf = |dir: &Path| {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(format!("{}.jwt", w.sys.public_key())), &sys).unwrap();
        format!(
            "operator: {op}\nsystem_account: {}\nresolver {{ type: full, dir: {:?} }}\n",
            w.sys.public_key(),
            dir.display().to_string()
        )
    };
    for (name, t) in targets(conf) {
        let mut c = Client::login(&t, &bearer(&w.sys));
        let list = c.json("$SYS.REQ.CLAIMS.LIST", "");
        assert_eq!(list, json!({"data": [w.sys.public_key()]}), "{name}");
    }
}

#[test]
fn updates_that_do_not_validate_are_refused_by_either_resolver() {
    let w = World::new();
    let a = KeyPair::new_account();
    let too_many = json!({
        "limits": {"conn": -1, "leaf": -1, "subs": -1, "data": -1, "payload": -1, "imports": 0, "exports": -1, "wildcards": true},
        "imports": [{"name": "s", "subject": "s", "account": w.sys.public_key(), "type": "stream"}],
    });
    for (name, t) in targets(w.conf("type: full, dir: DIR")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let answer = sys.json("$SYS.REQ.CLAIMS.UPDATE", &w.account(&a, too_many.clone()));
        // nats-server lists every error, this one twice; naq the first.
        let why = "jwt validation failed - validation errors: [the account contains more imports than allowed by the operator";
        assert_eq!(answer["error"]["account"], a.public_key(), "{name}");
        let description = answer["error"]["description"].as_str().unwrap();
        assert!(description.starts_with(why), "{name}: {description}");
    }
    for (name, t) in targets(w.conf("type: cache, dir: DIR")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let by_sys = format!("$SYS.REQ.ACCOUNT.{}.CLAIMS.UPDATE", w.sys.public_key());
        let answer = sys.json(&by_sys, &w.account(&w.sys, too_many.clone()));
        // nats-server lists every error, this one twice; naq the first.
        let why = "jwt update cache validation failed - validation errors: [the account contains more imports than allowed by the operator";
        assert_eq!(answer["error"]["account"], w.sys.public_key(), "{name}");
        let description = answer["error"]["description"].as_str().unwrap();
        assert!(description.starts_with(why), "{name}: {description}");
    }
}

#[test]
fn a_strict_operator_takes_accounts_of_its_signing_keys_only() {
    let (op, signer, sys) = (
        KeyPair::new_operator(),
        KeyPair::new_operator(),
        KeyPair::new_account(),
    );
    let w = World { op, sys };
    let operator = json!({"jti": "O", "iat": now(), "iss": w.op.public_key(), "sub": w.op.public_key(),
        "nats": {"type": "operator", "version": 2, "strict_signing_key_usage": true, "signing_keys": [signer.public_key()]}});
    // Under a strict operator, users come from signing keys too.
    let user_signer = KeyPair::new_account();
    let account = |kp: &KeyPair, by: &KeyPair| {
        let nats = json!({"type": "account", "version": 2, "signing_keys": [user_signer.public_key()],
            "limits": {"conn": -1, "subs": -1, "payload": -1, "data": -1, "imports": -1, "exports": -1, "wildcards": true}});
        let claims = json!({"jti": format!("J{}", jti()), "iat": now(), "iss": by.public_key(), "sub": kp.public_key(), "nats": nats});
        sign(by, &claims)
    };
    let (op_jwt, sys_jwt) = (sign(&w.op, &operator), account(&w.sys, &signer));
    let body = json!({"type": "user", "version": 2, "bearer_token": true, "subs": -1, "data": -1, "payload": -1, "issuer_account": w.sys.public_key()});
    let user = json!({"jti": "U", "iat": now() - 1, "iss": user_signer.public_key(), "sub": KeyPair::new_user().public_key(), "nats": body});
    let sys_user = sign(&user_signer, &user);
    let conf = |dir: &Path| {
        format!(
            "operator: {op_jwt}\nsystem_account: {}\nresolver_preload {{\n  {}: {sys_jwt}\n}}\nresolver {{ type: full, dir: {:?} }}\n",
            w.sys.public_key(),
            w.sys.public_key(),
            dir.display().to_string()
        )
    };
    let a = KeyPair::new_account();
    for (name, t) in targets(conf) {
        let mut sys = Client::login(&t, &sys_user);
        let answer = sys.json("$SYS.REQ.CLAIMS.UPDATE", &account(&a, &w.op));
        let why = "jwt update resulted in error - operator requires issuer to be a signing key";
        let refused =
            json!({"error": {"account": a.public_key(), "code": 500, "description": why}});
        assert_eq!(answer, refused, "{name}");
        let answer = sys.json("$SYS.REQ.CLAIMS.UPDATE", &account(&a, &signer));
        assert_eq!(answer, stored(&a.public_key()), "{name}");
    }
}

#[test]
fn deletes_come_from_trusted_operators_for_themselves() {
    let w = World::new();
    for (name, t) in targets(w.conf("type: full, dir: DIR, allow_delete: true")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let nats = json!({"accounts": [KeyPair::new_account().public_key()], "type": "generic", "version": 2});
        let other = KeyPair::new_operator();
        let by = |kp: &KeyPair, sub: &str| {
            let claims = json!({"jti": "D", "iat": now(), "iss": kp.public_key(), "sub": sub, "nats": nats.clone()});
            sign(kp, &claims)
        };
        let refused = |who: &str, why: &str| json!({"error": {"code": 500, "description": format!("delete accounts request by {who} failed - {why}")}});
        let not_self = by(&w.op, &w.sys.public_key());
        assert_eq!(
            sys.json("$SYS.REQ.CLAIMS.DELETE", &not_self),
            refused(&w.sys.public_key(), "not self signed"),
            "{name}"
        );
        let untrusted = by(&other, &other.public_key());
        assert_eq!(
            sys.json("$SYS.REQ.CLAIMS.DELETE", &untrusted),
            refused(&other.public_key(), "not trusted"),
            "{name}"
        );
    }
}

#[test]
fn a_cache_drops_a_jwt_its_ttl_after_its_last_use() {
    let w = World::new();
    for (name, t) in targets(w.conf("type: cache, dir: DIR, ttl: \"300ms\"")) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let by_sys = format!("$SYS.REQ.ACCOUNT.{}.CLAIMS.UPDATE", w.sys.public_key());
        sys.json(&by_sys, &w.account(&w.sys, json!({})));
        let file = t.dir().join(format!("{}.jwt", w.sys.public_key()));
        let deadline = Instant::now() + WAIT;
        while file.exists() {
            assert!(Instant::now() < deadline, "{name}: still there");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Requests to the services of the system account: by a client of
/// account `a`, to store `b`, close and delete `a`, list, look up and
/// pack the JWTs, and ping the servers.
fn system_requests(w: &World, a: &KeyPair, b: &KeyPair) -> Vec<(String, String)> {
    let of_b = w.account(b, json!({}));
    let closed = w.account(a, json!({"limits": {"conn": 0}}));
    let delete = json!({"jti": "D", "iat": now(), "iss": w.op.public_key(), "sub": w.op.public_key(), "nats": {"accounts": [a.public_key()], "type": "generic", "version": 2}});
    let (a, b) = (a.public_key(), b.public_key());
    vec![
        ("$SYS.REQ.CLAIMS.UPDATE".into(), of_b.clone()),
        (format!("$SYS.REQ.ACCOUNT.{b}.CLAIMS.UPDATE"), of_b),
        (format!("$SYS.REQ.ACCOUNT.{a}.CLAIMS.UPDATE"), closed),
        ("$SYS.REQ.CLAIMS.LIST".into(), String::new()),
        ("$SYS.REQ.CLAIMS.DELETE".into(), sign(&w.op, &delete)),
        (format!("$SYS.REQ.ACCOUNT.{a}.CLAIMS.LOOKUP"), String::new()),
        ("$SYS.REQ.CLAIMS.PACK".into(), String::new()),
        ("$SYS.REQ.SERVER.PING".into(), String::new()),
    ]
}

#[test]
fn system_requests_from_another_account_reach_no_service() {
    let w = World::new();
    let (a, b) = (KeyPair::new_account(), KeyPair::new_account());
    let resolver = "type: full, dir: DIR, allow_delete: true, timeout: \"300ms\"";
    for (name, t) in targets(w.conf(resolver)) {
        let mut sys = Client::login(&t, &bearer(&w.sys));
        let jwt = w.account(&a, json!({}));
        let ok = sys.json("$SYS.REQ.CLAIMS.UPDATE", &jwt);
        assert_eq!(ok, stored(&a.public_key()), "{name}");
        let no_responders = r#","headers":true,"no_responders":true"#;
        let (mut c, first) = Client::connect_with(&t, &bearer(&a), no_responders);
        assert_eq!(first, "PONG", "{name}");
        c.send("SUB _R.> 99\r\n");
        for (subject, payload) in system_requests(&w, &a, &b) {
            let status = c.no_responders(&subject, &payload);
            let want = [
                "NATS/1.0 503".to_owned(),
                format!("Nats-Subject: {subject}"),
            ];
            assert_eq!(status, want, "{name}");
        }
        // Nor does it hear what goes on in the system account.
        c.send("UNSUB 99\r\nSUB $SYS.> 1\r\nPING\r\n");
        assert_eq!(c.line(), "PONG", "{name}");
        let list = sys.json("$SYS.REQ.CLAIMS.LIST", "");
        let mut keys = [a.public_key(), w.sys.public_key()];
        keys.sort();
        assert_eq!(
            list,
            json!({"data": keys}),
            "{name}: nothing stored or deleted"
        );
        let other = Client::login(&t, &bearer(&a));
        drop(other);
        let (_, refused) = Client::connect(&t, &bearer(&b));
        assert_eq!(refused, "-ERR 'Authorization Violation'", "{name}");
        sys.send("PING\r\n");
        assert_eq!(sys.line(), "PONG", "{name}");
        c.send("PING\r\n");
        assert_eq!(c.line(), "PONG", "{name}: still in, and heard nothing");
    }
}

#[test]
fn a_client_of_an_account_no_server_has_is_refused_in_time() {
    let w = World::new();
    let a = KeyPair::new_account();
    let dead = free_port();
    // A route that is never up: each server of its own port.
    let cluster = || {
        format!(
            "cluster {{ name: c, listen: \"127.0.0.1:{}\", routes: [\"nats-route://127.0.0.1:{dead}\"] }}\n",
            free_port()
        )
    };
    for (resolver, routed) in [
        ("type: cache, dir: DIR, timeout: \"300ms\"", false),
        ("type: full, dir: DIR, timeout: \"300ms\"", true),
    ] {
        let conf = w.conf(resolver);
        let more = |dir: &Path| {
            let routes = if routed { cluster() } else { String::new() };
            format!("{routes}{}", conf(dir))
        };
        for (name, t) in targets(more) {
            let started = Instant::now();
            let (_, first) = Client::connect(&t, &bearer(&a));
            assert_eq!(
                first, "-ERR 'Authorization Violation'",
                "{name}: {resolver}"
            );
            let took = started.elapsed();
            assert!(
                took < Duration::from_secs(2),
                "{name}: {resolver}: {took:?}"
            );
            Client::login(&t, &bearer(&w.sys));
        }
    }
}

#[test]
fn a_cache_whose_full_resolver_is_gone_refuses_the_accounts_it_lacks() {
    let w = World::new();
    let (a, b) = (KeyPair::new_account(), KeyPair::new_account());
    let full = [
        (&a, w.account(&a, json!({}))),
        (&b, w.account(&b, json!({}))),
    ];
    let resolvers = [
        "type: full, dir: DIR",
        "type: cache, dir: DIR, timeout: \"300ms\"",
    ];
    let mut servers = cluster(&w, resolvers, [&full, &[]]);
    login_until_in(&servers[1], &bearer(&a));
    drop(servers.remove(0));
    let started = Instant::now();
    let (_, first) = Client::connect(&servers[0], &bearer(&b));
    assert_eq!(first, "-ERR 'Authorization Violation'");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    // What it fetched before stays in use.
    Client::login(&servers[0], &bearer(&a));
}
