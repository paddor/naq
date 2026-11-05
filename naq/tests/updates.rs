//! Account JWTs updated while clients are connected, over
//! `$SYS.REQ.ACCOUNT.<id>.CLAIMS.UPDATE`: the update is answered, and the
//! account's clients are checked again. Each scenario runs against naq,
//! and against `nats-server` too when `NAQ_GO` names one: both must
//! behave the same.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
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

/// The operator, the system account and the accounts of the tests.
struct World {
    op: KeyPair,
    sys: KeyPair,
    a: KeyPair,
    signer: KeyPair,
}

impl World {
    fn new() -> World {
        World {
            op: KeyPair::new_operator(),
            sys: KeyPair::new_account(),
            a: KeyPair::new_account(),
            signer: KeyPair::new_account(),
        }
    }

    /// The JWT of account `kp` with open limits and `more` in its body,
    /// signed by the operator.
    fn account(&self, kp: &KeyPair, more: Value) -> String {
        account_jwt(&self.op, kp, more)
    }

    /// The configuration both servers run.
    fn conf(&self) -> String {
        let operator = json!({"jti": "O", "iat": now(), "iss": self.op.public_key(), "sub": self.op.public_key(), "nats": {"type": "operator", "version": 2}});
        let a = self.account(&self.a, json!({"signing_keys": [self.signer.public_key()]}));
        format!(
            "operator: {}\nsystem_account: {}\nresolver: MEMORY\nresolver_preload {{\n  {}: {}\n  {}: {}\n}}\n",
            sign(&self.op, &operator),
            self.sys.public_key(),
            self.sys.public_key(),
            self.account(&self.sys, json!({})),
            self.a.public_key(),
            a,
        )
    }
}

/// The JWT of account `kp` with open limits and `more` in its body, signed
/// by `by`, with a `jti` of its own.
fn account_jwt(by: &KeyPair, kp: &KeyPair, more: Value) -> String {
    let open = || json!({"conn": -1, "leaf": -1, "subs": -1, "data": -1, "payload": -1, "imports": -1, "exports": -1, "wildcards": true});
    let mut nats = json!({"type": "account", "version": 2, "limits": open()});
    let limits = more.get("limits").cloned();
    merge(&mut nats, more);
    if let Some(l) = limits {
        let mut all = open();
        merge(&mut all, l);
        nats["limits"] = all;
    }
    let claims = json!({"jti": format!("J{}", rand_jti()), "iat": now(), "iss": by.public_key(), "sub": kp.public_key(), "nats": nats});
    sign(by, &claims)
}

/// A distinct `jti` part.
fn rand_jti() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    // Relaxed: only uniqueness matters.
    N.fetch_add(1, Ordering::Relaxed)
}

/// A bearer user JWT in the account of `issuer`, with `nats` in its body.
fn bearer(issuer: &KeyPair, account: &KeyPair, nats: Value) -> String {
    bearer_of(issuer, account, &KeyPair::new_user().public_key(), nats)
}

/// A bearer user JWT of key `user`, as [`bearer`] makes it.
fn bearer_of(issuer: &KeyPair, account: &KeyPair, user: &str, nats: Value) -> String {
    let mut body = json!({"type": "user", "version": 2, "bearer_token": true, "subs": -1, "data": -1, "payload": -1});
    merge(&mut body, nats);
    let mut claims = json!({"jti": "U", "iat": now() - 1, "iss": issuer.public_key(), "sub": user, "nats": body});
    if issuer.public_key() != account.public_key() {
        claims["nats"]["issuer_account"] = account.public_key().into();
    }
    sign(issuer, &claims)
}

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

/// naq, then `nats-server` if `NAQ_GO` names one, each running `conf`.
fn targets(conf: &str) -> Vec<(&'static str, Target)> {
    let mut opts: Options = conf.parse().unwrap();
    opts.host = "127.0.0.1".into();
    opts.port = 0;
    opts.lanes = 2;
    let mut all = vec![("naq", Target::Naq(Server::start(&opts).unwrap()))];
    if let Some(bin) = std::env::var_os("NAQ_GO").map(PathBuf::from) {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = std::env::temp_dir().join(format!("naq-updates-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("go.conf");
        std::fs::write(&path, format!("listen: 127.0.0.1:{port}\n{conf}")).unwrap();
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
        all.push(("go", Target::Go { _go: go, port }));
    }
    all
}

/// A connection, read line by line.
struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
}

impl Client {
    /// Logs in with user JWT `jwt` and waits for the `PONG`.
    fn login(t: &Target, jwt: &str) -> Client {
        let w = TcpStream::connect(t.addr()).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let mut c = Client {
            r: BufReader::new(w.try_clone().unwrap()),
            w,
        };
        c.line();
        c.send(&format!(
            "CONNECT {{\"verbose\":false,\"protocol\":0,\"jwt\":\"{jwt}\"}}\r\nPING\r\n"
        ));
        assert_eq!(c.line(), "PONG", "logged in");
        c
    }

    fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
    }

    /// The next line from the server, past its `PING`s, which get their
    /// `PONG`: the first comes 2 s after the client connected.
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

    /// Whether the server closed it, with nothing more to say.
    fn closed(&mut self) -> bool {
        let mut rest = String::new();
        self.r.read_to_string(&mut rest).is_ok() && rest.is_empty()
    }

    /// Whether it is still there: a `PING` gets its `PONG`.
    fn alive(&mut self) -> bool {
        self.send("PING\r\n");
        self.line() == "PONG"
    }

    /// Sends the account JWT `jwt` as an update on `subject`, and returns
    /// the answer, without the server that sent it.
    fn update(&mut self, subject: &str, jwt: &str) -> Value {
        self.send(&format!(
            "SUB _R.> 99\r\nPUB {subject} _R.1 {}\r\n{jwt}\r\n",
            jwt.len()
        ));
        let head = self.line();
        assert!(head.starts_with("MSG _R.1 99 "), "{head}");
        let mut v: Value = serde_json::from_str(&self.line()).unwrap();
        v.as_object_mut().unwrap().remove("server");
        self.send("UNSUB 99\r\n");
        v
    }
}

/// The subject an update of account `kp` goes to.
fn subject(kp: &KeyPair) -> String {
    format!("$SYS.REQ.ACCOUNT.{}.CLAIMS.UPDATE", kp.public_key())
}

#[test]
fn updates_are_answered_as_nats_server_answers_them() {
    let w = World::new();
    for (name, t) in targets(&w.conf()) {
        let mut sys = Client::login(&t, &bearer(&w.sys, &w.sys, json!({})));
        let a = w.account(&w.a, json!({}));
        // As `nats-server` loads accounts on first use: no client used it yet.
        let early = sys.update(&subject(&w.a), &a);
        assert_eq!(early["data"]["message"], "jwt update skipped", "{name}");
        let _user = Client::login(&t, &bearer(&w.a, &w.a, json!({})));
        let ok = sys.update(&subject(&w.a), &a);
        assert_eq!(
            ok,
            json!({"data": {"account": w.a.public_key(), "code": 200, "message": "jwt updated"}}),
            "{name}"
        );
        let stranger = KeyPair::new_account();
        let skipped = sys.update(&subject(&stranger), &w.account(&stranger, json!({})));
        assert_eq!(skipped["data"]["message"], "jwt update skipped", "{name}");
        let other = sys.update(&subject(&stranger), &a);
        assert_eq!(
            other["error"]["description"],
            "jwt update resulted in error - subject does not match jwt content",
            "{name}"
        );
        let untrusted = account_jwt(&KeyPair::new_operator(), &w.a, json!({}));
        let e = sys.update(&subject(&w.a), &untrusted);
        assert_eq!(e["error"]["code"], 500, "{name}: {e}");
        assert!(
            e["error"]["description"]
                .as_str()
                .unwrap()
                .starts_with("jwt update resulted in error"),
            "{name}: {e}"
        );
        let garbage = sys.update(&subject(&w.a), "x");
        assert_eq!(garbage["error"]["code"], 500, "{name}");
    }
}

#[test]
fn a_revoked_or_bearer_user_goes_once_its_account_says_so() {
    let w = World::new();
    for (name, t) in targets(&w.conf()) {
        let mut sys = Client::login(&t, &bearer(&w.sys, &w.sys, json!({})));
        let user = KeyPair::new_user().public_key();
        let mut revoked = Client::login(&t, &bearer_of(&w.a, &w.a, &user, json!({})));
        let jwt = w.account(&w.a, json!({"revocations": {user: now()}}));
        sys.update(&subject(&w.a), &jwt);
        assert_eq!(
            revoked.line(),
            "-ERR 'User Authentication Revoked'",
            "{name}"
        );
        let mut b = Client::login(&t, &bearer(&w.a, &w.a, json!({})));
        sys.update(
            &subject(&w.a),
            &w.account(&w.a, json!({"limits": {"disallow_bearer": true}})),
        );
        assert_eq!(b.line(), "-ERR 'Authorization Violation'", "{name}");
    }
}

#[test]
fn limits_and_default_permissions_apply_to_the_clients_there() {
    let w = World::new();
    for (name, t) in targets(&w.conf()) {
        let mut sys = Client::login(&t, &bearer(&w.sys, &w.sys, json!({})));
        let mut older = Client::login(&t, &bearer(&w.a, &w.a, json!({})));
        older.send("SUB x 1\r\nSUB y 2\r\nSUB x q 3\r\nPING\r\n");
        assert_eq!(older.line(), "PONG");
        let mut newer = Client::login(&t, &bearer(&w.a, &w.a, json!({})));
        sys.update(
            &subject(&w.a),
            &w.account(&w.a, json!({"limits": {"conn": 1}})),
        );
        assert_eq!(
            newer.line(),
            "-ERR 'maximum account active connections exceeded'",
            "{name}"
        );
        assert!(older.alive(), "{name}: the oldest stays");
        let deny = json!({"default_permissions": {"sub": {"deny": ["x"]}}});
        sys.update(&subject(&w.a), &w.account(&w.a, deny));
        // In no order: nats-server walks a map.
        let mut errs = [older.line(), older.line()];
        errs.sort();
        assert_eq!(
            errs,
            [
                "-ERR 'Permissions Violation for Subscription to \"x\" (sid \"1\")'",
                "-ERR 'Permissions Violation for Subscription to \"x\" using queue \"q\" (sid \"3\")'",
            ],
            "{name}"
        );
        assert!(older.alive(), "{name}");
        sys.update(
            &subject(&w.a),
            &w.account(&w.a, json!({"limits": {"payload": 4}})),
        );
        // Answered once the update is through: the limit holds by then.
        assert!(older.alive(), "{name}");
        older.send("PUB y 5\r\nhello\r\n");
        assert_eq!(older.line(), "-ERR 'Maximum Payload Violation'", "{name}");
    }
}

#[test]
fn a_user_at_its_new_subscription_limit_goes() {
    let w = World::new();
    for (name, t) in targets(&w.conf()) {
        let mut sys = Client::login(&t, &bearer(&w.sys, &w.sys, json!({})));
        let mut c = Client::login(&t, &bearer(&w.a, &w.a, json!({})));
        c.send("SUB x 1\r\nPING\r\n");
        assert_eq!(c.line(), "PONG");
        sys.update(
            &subject(&w.a),
            &w.account(&w.a, json!({"limits": {"subs": 1}})),
        );
        assert_eq!(c.line(), "-ERR 'maximum subscriptions exceeded'", "{name}");
        assert!(c.closed(), "{name}");
    }
}

#[test]
fn a_user_of_a_signing_key_the_account_drops_goes_without_a_word() {
    let w = World::new();
    for (name, t) in targets(&w.conf()) {
        let mut sys = Client::login(&t, &bearer(&w.sys, &w.sys, json!({})));
        let mut c = Client::login(&t, &bearer(&w.signer, &w.a, json!({})));
        let mut own = Client::login(&t, &bearer(&w.a, &w.a, json!({})));
        sys.update(&subject(&w.a), &w.account(&w.a, json!({})));
        assert!(c.closed(), "{name}");
        assert!(own.alive(), "{name}: a user of the account's own key stays");
    }
}

#[test]
fn clients_go_when_their_account_expires() {
    let w = World::new();
    for (name, t) in targets(&w.conf()) {
        let mut sys = Client::login(&t, &bearer(&w.sys, &w.sys, json!({})));
        let mut c = Client::login(&t, &bearer(&w.a, &w.a, json!({})));
        let jwt = w.account(&w.a, json!({"signing_keys": [w.signer.public_key()]}));
        let mut claims: Value = serde_json::from_slice(
            &BASE64URL_NOPAD
                .decode(jwt.split('.').nth(1).unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
        claims["exp"] = (now() + 2).into();
        claims["jti"] = "EXP".into();
        sys.update(&subject(&w.a), &sign(&w.op, &claims));
        assert_eq!(c.line(), "-ERR 'Account Authentication Expired'", "{name}");
    }
}

/// A free port on the loopback, from a range of this process's own.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 30_000 - (std::process::id() % 400) as u16 * 30;
    loop {
        // Relaxed: only uniqueness matters.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = base - n % 2_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

#[test]
fn an_update_at_one_server_of_the_cluster_reaches_the_clients_of_another() {
    let w = World::new();
    let ports = [free_port(), free_port()];
    let server = |i: usize| {
        let cluster = format!(
            "cluster {{ name: c, listen: \"127.0.0.1:{}\", routes: [\"nats-route://127.0.0.1:{}\"] }}\nserver_name: n{i}\n",
            ports[i],
            ports[1 - i]
        );
        let mut opts: Options = format!("{cluster}{}", w.conf()).parse().unwrap();
        opts.host = "127.0.0.1".into();
        opts.port = 0;
        opts.lanes = 2;
        Target::Naq(Server::start(&opts).unwrap())
    };
    let (a, b) = (server(0), server(1));
    let user = KeyPair::new_user().public_key();
    let mut c = Client::login(&b, &bearer_of(&w.a, &w.a, &user, json!({})));
    let mut sys = Client::login(&a, &bearer(&w.sys, &w.sys, json!({})));
    let revoked = w.account(&w.a, json!({"revocations": {user.clone(): now()}}));
    // Sent again until it reaches the other server, as the route may not
    // be up yet; the server it reaches first answers it.
    let deadline = Instant::now() + WAIT;
    sys.send("SUB _R.> 99\r\n");
    loop {
        sys.send(&format!(
            "PUB {} _R.1 {}\r\n{revoked}\r\n",
            subject(&w.a),
            revoked.len()
        ));
        c.send("PING\r\n");
        let line = c.line();
        if line == "-ERR 'User Authentication Revoked'" {
            break;
        }
        assert_eq!(line, "PONG");
        assert!(Instant::now() < deadline, "not revoked");
        std::thread::sleep(Duration::from_millis(50));
    }
}
