//! Operator mode: users log in with JWTs that accounts the operator
//! signed issued. Each scenario runs against naq, and against
//! `nats-server` too when `NAQ_GO` names one: both must behave the same.

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

/// No limit at all, as nats-io/jwt writes it.
const OPEN: i64 = -1;

/// `nats` as the body of claims of `sub`, signed by `kp`.
fn mint(kp: &KeyPair, sub: &str, nats: &Value, more: &Value) -> String {
    let mut payload = json!({"jti": format!("J{}", now()), "iat": now(), "iss": kp.public_key(), "sub": sub, "nats": nats});
    for (k, v) in more.as_object().unwrap() {
        payload[k] = v.clone();
    }
    let h = BASE64URL_NOPAD.encode(
        json!({"typ": "JWT", "alg": "ed25519-nkey"})
            .to_string()
            .as_bytes(),
    );
    let p = BASE64URL_NOPAD.encode(payload.to_string().as_bytes());
    let sig = kp.sign(format!("{h}.{p}").as_bytes()).unwrap();
    format!("{h}.{p}.{}", BASE64URL_NOPAD.encode(&sig))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed()
}

/// Limits of no limit at all, for an account.
fn open_account() -> Value {
    json!({"conn": OPEN, "leaf": OPEN, "subs": OPEN, "data": OPEN, "payload": OPEN, "imports": OPEN, "exports": OPEN, "wildcards": true})
}

/// The operator, and its accounts: open `A`, `B` of one connection, `C`
/// with no limits written, `D` that refuses bearer users and revoked user
/// `R`, and `S` with a signing key.
struct World {
    operator: KeyPair,
    a: KeyPair,
    b: KeyPair,
    c: KeyPair,
    d: KeyPair,
    s: KeyPair,
    signer: KeyPair,
    revoked: KeyPair,
}

impl World {
    fn new() -> World {
        World {
            operator: KeyPair::new_operator(),
            a: KeyPair::new_account(),
            b: KeyPair::new_account(),
            c: KeyPair::new_account(),
            d: KeyPair::new_account(),
            s: KeyPair::new_account(),
            signer: KeyPair::new_account(),
            revoked: KeyPair::new_user(),
        }
    }

    /// The configuration both servers run.
    fn conf(&self) -> String {
        let op = mint(
            &self.operator,
            &self.operator.public_key(),
            &json!({"type": "operator", "version": 2}),
            &json!({}),
        );
        let account = |kp: &KeyPair, body: Value| {
            let mut nats = json!({"type": "account", "version": 2});
            for (k, v) in body.as_object().unwrap() {
                nats[k] = v.clone();
            }
            format!(
                "  {}: {}\n",
                kp.public_key(),
                mint(&self.operator, &kp.public_key(), &nats, &json!({}))
            )
        };
        let mut b = open_account();
        b["conn"] = 1.into();
        let mut d = open_account();
        d["disallow_bearer"] = true.into();
        format!(
            "operator: {op}\nresolver: MEMORY\nresolver_preload {{\n{}{}{}{}{}}}\n",
            account(&self.a, json!({"limits": open_account()})),
            account(&self.b, json!({"limits": b})),
            account(&self.c, json!({})),
            account(
                &self.d,
                json!({"limits": d, "revocations": {self.revoked.public_key(): now() + 100}})
            ),
            account(
                &self.s,
                json!({"limits": open_account(), "signing_keys": [self.signer.public_key()]})
            ),
        )
    }
}

/// A user JWT of key `user`, issued by `issuer`, with body `nats` added to
/// open limits, and claims `more`.
fn user(issuer: &KeyPair, user: &KeyPair, nats: &Value, more: &Value) -> String {
    let mut body =
        json!({"type": "user", "version": 2, "subs": OPEN, "data": OPEN, "payload": OPEN});
    for (k, v) in nats.as_object().unwrap() {
        body[k] = v.clone();
    }
    mint(issuer, &user.public_key(), &body, more)
}

/// A server running `conf`: naq, or `nats-server`.
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
        let dir = std::env::temp_dir().join(format!("naq-operator-{}-{port}", std::process::id()));
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

/// A connection, read line by line.
struct Client {
    w: TcpStream,
    r: BufReader<TcpStream>,
    nonce: String,
}

impl Client {
    /// Connects and reads the `INFO`.
    fn dial(t: &Target) -> Client {
        let w = TcpStream::connect(t.addr()).unwrap();
        w.set_read_timeout(Some(WAIT)).unwrap();
        let mut c = Client {
            r: BufReader::new(w.try_clone().unwrap()),
            w,
            nonce: String::new(),
        };
        let info: Value = serde_json::from_str(c.line().strip_prefix("INFO ").unwrap()).unwrap();
        assert_eq!(info["auth_required"], true);
        info["nonce"].as_str().unwrap().clone_into(&mut c.nonce);
        c
    }

    /// Logs in as user `kp` of JWT `jwt`, signing the nonce, with `extra`
    /// CONNECT fields, and sends `PING`.
    fn login(t: &Target, kp: Option<&KeyPair>, jwt: &str, extra: &str) -> Client {
        let mut c = Client::dial(t);
        let sig = kp.map_or(String::new(), |k| {
            format!(
                r#","sig":"{}""#,
                BASE64URL_NOPAD.encode(&k.sign(c.nonce.as_bytes()).unwrap())
            )
        });
        c.send(&format!(
            "CONNECT {{\"verbose\":false,\"protocol\":1,\"jwt\":\"{jwt}\"{sig}{extra}}}\r\nPING\r\n"
        ));
        c
    }

    fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
    }

    fn line(&mut self) -> String {
        let mut l = String::new();
        assert_ne!(self.r.read_line(&mut l).unwrap(), 0, "closed");
        l.trim_end_matches("\r\n").to_owned()
    }

    /// Whether the server closed the connection, after what came.
    fn closed(&mut self) -> bool {
        let mut rest = String::new();
        self.r.read_to_string(&mut rest).is_ok() && !rest.contains("PONG")
    }
}

/// Expects a login that holds: `PONG`, then the `INFO` naming account
/// `account` and the largest payload `max_payload`.
fn logged_in(c: &mut Client, name: &str, account: &str, max_payload: u64) {
    assert_eq!(c.line(), "PONG", "{name}");
    let info: Value = serde_json::from_str(c.line().strip_prefix("INFO ").unwrap()).unwrap();
    assert_eq!(info["connect_info"], true, "{name}: {info}");
    assert_eq!(info["remote_account"], account, "{name}: {info}");
    assert_eq!(info["max_payload"], max_payload, "{name}: {info}");
}

/// Expects the login to be refused with `-ERR 'Authorization Violation'`.
fn refused(c: &mut Client, name: &str, why: &str) {
    assert_eq!(c.line(), "-ERR 'Authorization Violation'", "{name}: {why}");
    assert!(c.closed(), "{name}: {why}");
}

#[test]
fn a_user_of_a_jwt_logs_in_by_signing_the_nonce() {
    let w = World::new();
    let conf = w.conf();
    for (name, t) in targets(&conf) {
        let u = KeyPair::new_user();
        let jwt = user(&w.a, &u, &json!({}), &json!({}));
        let mut c = Client::login(&t, Some(&u), &jwt, "");
        logged_in(&mut c, name, &w.a.public_key(), 1 << 20);
        c.send("SUB x 1\r\nPUB x 2\r\nhi\r\nPING\r\n");
        assert_eq!(
            [c.line(), c.line(), c.line()],
            ["MSG x 1 2", "hi", "PONG"],
            "{name}"
        );
        // Another key's signature, none, or none of a JWT.
        let other = KeyPair::new_user();
        refused(
            &mut Client::login(&t, Some(&other), &jwt, ""),
            name,
            "wrong signer",
        );
        refused(&mut Client::login(&t, None, &jwt, ""), name, "no signature");
        let mut bare = Client::dial(&t);
        bare.send("CONNECT {\"verbose\":false}\r\nPING\r\n");
        refused(&mut bare, name, "no JWT");
    }
}

#[test]
fn a_signature_of_another_connection_s_nonce_is_refused() {
    let w = World::new();
    let nkey = KeyPair::new_user();
    let config = format!(
        "authorization {{ users: [{{nkey: {}}}] }}\n",
        nkey.public_key()
    );
    let jwt_user = KeyPair::new_user();
    let jwt = user(&w.a, &jwt_user, &json!({}), &json!({}));
    let nkey_field = format!(r#","nkey":"{}""#, nkey.public_key());
    for (conf, kp, jwt, extra) in [
        (w.conf(), &jwt_user, jwt.as_str(), ""),
        (config, &nkey, "", nkey_field.as_str()),
    ] {
        for (name, t) in targets(&conf) {
            let mut first = Client::login(&t, Some(kp), jwt, extra);
            assert_eq!(first.line(), "PONG", "{name}: {extra}");
            let sig = BASE64URL_NOPAD.encode(&kp.sign(first.nonce.as_bytes()).unwrap());
            let mut again = Client::dial(&t);
            assert_ne!(again.nonce, first.nonce, "{name}: a fresh nonce");
            again.send(&format!(
                "CONNECT {{\"verbose\":false,\"protocol\":1,\"jwt\":\"{jwt}\",\"sig\":\"{sig}\"{extra}}}\r\nPING\r\n"
            ));
            refused(&mut again, name, "a signature of another nonce");
        }
    }
}

#[test]
fn a_user_jwt_out_of_its_time_or_of_an_unknown_account_is_refused() {
    let w = World::new();
    let conf = w.conf();
    for (name, t) in targets(&conf) {
        let u = KeyPair::new_user();
        let past = user(&w.a, &u, &json!({}), &json!({"exp": now() - 10}));
        refused(&mut Client::login(&t, Some(&u), &past, ""), name, "expired");
        let future = user(&w.a, &u, &json!({}), &json!({"nbf": now() + 100}));
        refused(
            &mut Client::login(&t, Some(&u), &future, ""),
            name,
            "not yet valid",
        );
        let stranger = user(&KeyPair::new_account(), &u, &json!({}), &json!({}));
        refused(
            &mut Client::login(&t, Some(&u), &stranger, ""),
            name,
            "unknown account",
        );
        let soon = user(&w.a, &u, &json!({}), &json!({"exp": now() + 2}));
        let mut c = Client::login(&t, Some(&u), &soon, "");
        logged_in(&mut c, name, &w.a.public_key(), 1 << 20);
        c.w.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut l = c.line();
        while l == "PING" {
            c.send("PONG\r\n");
            l = c.line();
        }
        assert_eq!(l, "-ERR 'User Authentication Expired'", "{name}");
    }
}

#[test]
fn revocations_bearer_users_and_signing_keys_hold_as_the_account_says() {
    let w = World::new();
    let conf = w.conf();
    for (name, t) in targets(&conf) {
        let revoked = user(&w.d, &w.revoked, &json!({}), &json!({}));
        refused(
            &mut Client::login(&t, Some(&w.revoked), &revoked, ""),
            name,
            "revoked",
        );
        let u = KeyPair::new_user();
        let bearer = user(&w.a, &u, &json!({"bearer_token": true}), &json!({}));
        logged_in(
            &mut Client::login(&t, None, &bearer, ""),
            name,
            &w.a.public_key(),
            1 << 20,
        );
        let refused_bearer = user(&w.d, &u, &json!({"bearer_token": true}), &json!({}));
        refused(
            &mut Client::login(&t, None, &refused_bearer, ""),
            name,
            "bearer refused",
        );
        let good = user(
            &w.signer,
            &u,
            &json!({"issuer_account": w.s.public_key()}),
            &json!({}),
        );
        logged_in(
            &mut Client::login(&t, Some(&u), &good, ""),
            name,
            &w.s.public_key(),
            1 << 20,
        );
        let unnamed = user(&w.signer, &u, &json!({}), &json!({}));
        refused(
            &mut Client::login(&t, Some(&u), &unnamed, ""),
            name,
            "signing key without issuer_account",
        );
        let foreign = user(
            &KeyPair::new_account(),
            &u,
            &json!({"issuer_account": w.s.public_key()}),
            &json!({}),
        );
        refused(
            &mut Client::login(&t, Some(&u), &foreign, ""),
            name,
            "signer not of the account",
        );
    }
}

#[test]
fn connection_types_and_sources_limit_where_a_user_connects_from() {
    let w = World::new();
    let conf = w.conf();
    for (name, t) in targets(&conf) {
        let u = KeyPair::new_user();
        for (types, ok) in [
            (json!(["WEBSOCKET"]), false),
            (json!(["BOGUS"]), false),
            (json!(["MQTT", "BOGUS"]), false),
            (json!(["standard"]), true),
        ] {
            let jwt = user(
                &w.a,
                &u,
                &json!({"allowed_connection_types": types}),
                &json!({}),
            );
            let mut c = Client::login(&t, Some(&u), &jwt, "");
            if ok {
                logged_in(&mut c, name, &w.a.public_key(), 1 << 20);
            } else {
                refused(&mut c, name, &types.to_string());
            }
        }
        let far = user(&w.a, &u, &json!({"src": ["10.0.0.0/8"]}), &json!({}));
        refused(&mut Client::login(&t, Some(&u), &far, ""), name, "src");
        let near = user(
            &w.a,
            &u,
            &json!({"src": "10.0.0.0/8,127.0.0.0/8"}),
            &json!({}),
        );
        logged_in(
            &mut Client::login(&t, Some(&u), &near, ""),
            name,
            &w.a.public_key(),
            1 << 20,
        );
    }
}

#[test]
fn limits_left_out_are_zero_and_limits_hold() {
    let w = World::new();
    let conf = w.conf();
    for (name, t) in targets(&conf) {
        let u = KeyPair::new_user();
        // An account without limits takes no connections.
        let none = user(&w.c, &u, &json!({}), &json!({}));
        let mut c = Client::login(&t, Some(&u), &none, "");
        assert_eq!(
            c.line(),
            "-ERR 'maximum account active connections exceeded'",
            "{name}"
        );
        // A user without subscriptions is told once it is in, and closed.
        let mut nosubs = json!({"type": "user", "version": 2, "payload": OPEN});
        nosubs["data"] = OPEN.into();
        let jwt = mint(&w.a, &u.public_key(), &nosubs, &json!({}));
        let mut c = Client::login(&t, Some(&u), &jwt, "");
        logged_in(&mut c, name, &w.a.public_key(), 1 << 20);
        assert_eq!(c.line(), "-ERR 'maximum subscriptions exceeded'", "{name}");
        assert!(c.closed(), "{name}");
        // Two subscriptions, not three; a payload of ten bytes, not eleven.
        let jwt = user(&w.a, &u, &json!({"subs": 2, "payload": 10}), &json!({}));
        let mut c = Client::login(&t, Some(&u), &jwt, "");
        logged_in(&mut c, name, &w.a.public_key(), 10);
        c.send("SUB a 1\r\nSUB b 2\r\nSUB c 3\r\nPING\r\n");
        assert_eq!(
            [c.line(), c.line()],
            ["-ERR 'maximum subscriptions exceeded'", "PONG"],
            "{name}"
        );
        c.send("PUB a 11\r\n01234567890\r\n");
        assert_eq!(c.line(), "-ERR 'Maximum Payload Violation'", "{name}");
        // One connection of account B.
        let first = user(&w.b, &u, &json!({}), &json!({}));
        let mut one = Client::login(&t, Some(&u), &first, "");
        logged_in(&mut one, name, &w.b.public_key(), 1 << 20);
        let mut two = Client::login(&t, Some(&u), &first, "");
        assert_eq!(
            two.line(),
            "-ERR 'maximum account active connections exceeded'",
            "{name}"
        );
        drop(one);
    }
}

/// Accounts `x`, exporting streams and services, `y`, importing them,
/// one by token, and `z`, whose token is of another account, with the
/// configuration that preloads them.
fn sharing() -> (String, KeyPair, KeyPair, KeyPair) {
    let operator = KeyPair::new_operator();
    let (x, y, z) = (
        KeyPair::new_account(),
        KeyPair::new_account(),
        KeyPair::new_account(),
    );
    let account = |kp: &KeyPair, body: Value| {
        let mut nats = json!({"type": "account", "version": 2, "limits": open_account()});
        for (k, v) in body.as_object().unwrap() {
            nats[k] = v.clone();
        }
        format!(
            "  {}: {}\n",
            kp.public_key(),
            mint(&operator, &kp.public_key(), &nats, &json!({}))
        )
    };
    let token = |sub: &KeyPair, subject: &str| {
        mint(
            &x,
            &sub.public_key(),
            &json!({"type": "activation", "version": 2, "subject": subject, "kind": "service"}),
            &json!({}),
        )
    };
    let op = mint(
        &operator,
        &operator.public_key(),
        &json!({"type": "operator", "version": 2}),
        &json!({}),
    );
    let conf = format!(
        "operator: {op}\nresolver: MEMORY\nresolver_preload {{\n{}{}{}}}\n",
        account(
            &x,
            json!({"exports": [
                {"subject": "s.>", "type": "stream"},
                {"subject": "svc", "type": "service"},
                {"subject": "priv", "type": "service", "token_req": true},
                {"subject": "other", "type": "service", "token_req": true},
            ]})
        ),
        account(
            &y,
            json!({"imports": [
                {"subject": "s.>", "account": x.public_key(), "type": "stream", "to": "from"},
                {"subject": "svc", "account": x.public_key(), "type": "service"},
                {"subject": "priv", "account": x.public_key(), "type": "service", "token": token(&y, "priv")},
            ]})
        ),
        // A token of another account: nats-io/jwt refuses the whole account.
        account(
            &z,
            json!({"imports": [
                {"subject": "other", "account": x.public_key(), "type": "service", "token": token(&x, "other")},
            ]})
        ),
    );
    (conf, x, y, z)
}

#[test]
fn accounts_share_streams_and_services_their_jwts_export_and_import() {
    let (conf, x, y, z) = sharing();
    for (name, t) in targets(&conf) {
        let (ux, uy) = (KeyPair::new_user(), KeyPair::new_user());
        let mut cx = Client::login(&t, Some(&ux), &user(&x, &ux, &json!({}), &json!({})), "");
        logged_in(&mut cx, name, &x.public_key(), 1 << 20);
        let mut cy = Client::login(&t, Some(&uy), &user(&y, &uy, &json!({}), &json!({})), "");
        logged_in(&mut cy, name, &y.public_key(), 1 << 20);
        cy.send("SUB from.s.> 1\r\nPING\r\n");
        assert_eq!(cy.line(), "PONG", "{name}");
        cx.send("SUB svc 1\r\nSUB priv 2\r\nSUB other 3\r\nPUB s.a 1\r\na\r\nPING\r\n");
        assert_eq!(cx.line(), "PONG", "{name}");
        assert_eq!([cy.line(), cy.line()], ["MSG from.s.a 1 1", "a"], "{name}");
        // A service, and one by token; `other` it does not import.
        cy.send("PUB other 1\r\no\r\nPUB svc 1\r\nq\r\nPUB priv 1\r\np\r\nPING\r\n");
        assert_eq!(cy.line(), "PONG", "{name}");
        let got: Vec<String> = (0..4).map(|_| cx.line()).collect();
        assert!(
            got[0].starts_with("MSG svc 1 ") && got[2].starts_with("MSG priv 2 "),
            "{name}: {got:?}"
        );
        let uz = KeyPair::new_user();
        let jwt = user(&z, &uz, &json!({}), &json!({}));
        refused(
            &mut Client::login(&t, Some(&uz), &jwt, ""),
            name,
            "account of a bad token",
        );
    }
}

#[test]
fn a_user_of_a_scoped_signing_key_gets_its_template() {
    let operator = KeyPair::new_operator();
    let (q, scoped) = (KeyPair::new_account(), KeyPair::new_account());
    let template =
        json!({"pub": {"allow": ["{{name()}}.>"]}, "sub": {"allow": ["{{name()}}.>", "_INBOX.>"]}});
    let nats = json!({"type": "account", "version": 2, "limits": open_account(),
        "signing_keys": [{"kind": "user_scope", "key": scoped.public_key(), "role": "r", "template": template}]});
    let op = mint(
        &operator,
        &operator.public_key(),
        &json!({"type": "operator", "version": 2}),
        &json!({}),
    );
    let acc = mint(&operator, &q.public_key(), &nats, &json!({}));
    let conf = format!(
        "operator: {op}\nresolver: MEMORY\nresolver_preload {{\n  {}: {acc}\n}}\n",
        q.public_key()
    );
    for (name, t) in targets(&conf) {
        let u = KeyPair::new_user();
        // A scoped user brings nothing of its own: the template is all.
        let jwt = mint(
            &scoped,
            &u.public_key(),
            &json!({"type": "user", "version": 2, "issuer_account": q.public_key()}),
            &json!({"name": "svc"}),
        );
        let mut c = Client::login(&t, Some(&u), &jwt, "");
        logged_in(&mut c, name, &q.public_key(), 1 << 20);
        c.send("SUB svc.x 1\r\nPUB svc.x 1\r\na\r\nPUB other 1\r\nb\r\nPING\r\n");
        assert_eq!(
            [c.line(), c.line(), c.line(), c.line()],
            [
                "MSG svc.x 1 1",
                "a",
                "-ERR 'Permissions Violation for Publish to \"other\"'",
                "PONG"
            ],
            "{name}"
        );
        let own = user(
            &scoped,
            &u,
            &json!({"issuer_account": q.public_key()}),
            &json!({}),
        );
        refused(
            &mut Client::login(&t, Some(&u), &own, ""),
            name,
            "scoped user with limits",
        );
    }
}

#[test]
fn a_strict_operator_takes_only_what_its_signing_keys_signed() {
    let (operator, op_signer) = (KeyPair::new_operator(), KeyPair::new_operator());
    let (by_signer, by_operator, signer) = (
        KeyPair::new_account(),
        KeyPair::new_account(),
        KeyPair::new_account(),
    );
    let op = mint(
        &operator,
        &operator.public_key(),
        &json!({"type": "operator", "version": 2, "strict_signing_key_usage": true, "signing_keys": [op_signer.public_key()]}),
        &json!({}),
    );
    let nats = json!({"type": "account", "version": 2, "limits": open_account(), "signing_keys": [signer.public_key()]});
    let good = mint(&op_signer, &by_signer.public_key(), &nats, &json!({}));
    let bad = mint(&operator, &by_operator.public_key(), &nats, &json!({}));
    let conf = format!(
        "operator: {op}\nresolver: MEMORY\nresolver_preload {{\n  {}: {good}\n  {}: {bad}\n}}\n",
        by_signer.public_key(),
        by_operator.public_key()
    );
    for (name, t) in targets(&conf) {
        let u = KeyPair::new_user();
        let good = user(
            &signer,
            &u,
            &json!({"issuer_account": by_signer.public_key()}),
            &json!({}),
        );
        logged_in(
            &mut Client::login(&t, Some(&u), &good, ""),
            name,
            &by_signer.public_key(),
            1 << 20,
        );
        let by_account = user(&by_signer, &u, &json!({}), &json!({}));
        refused(
            &mut Client::login(&t, Some(&u), &by_account, ""),
            name,
            "user by the account key",
        );
        let of_bad = user(
            &signer,
            &u,
            &json!({"issuer_account": by_operator.public_key()}),
            &json!({}),
        );
        refused(
            &mut Client::login(&t, Some(&u), &of_bad, ""),
            name,
            "account by the operator key",
        );
    }
}
