//! Auth callout: clients log in as an auth service answers. The service
//! here is a client of the test, answering by the user name a client
//! gave. Each scenario runs against naq, and against `nats-server` too
//! when `NAQ_GO` names one: both must behave the same.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use naq::{Options, Server};
use nkeys::{KeyPair, XKey};
use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(5);
const DENIED: &str = "-ERR 'Authorization Violation'";

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

/// The claims of JWT `jwt`, unchecked.
fn claims(jwt: &str) -> Value {
    let body = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&BASE64URL_NOPAD.decode(body.as_bytes()).unwrap()).unwrap()
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
        let dir = std::env::temp_dir().join(format!("naq-callout-{}-{port}", std::process::id()));
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

/// A stream a client talks over: TCP, or TLS over it.
trait Stream: Read + Write + Send {}

impl<T: Read + Write + Send> Stream for T {}

/// A connection, read line by line.
struct Client {
    r: BufReader<Box<dyn Stream>>,
    info: Value,
}

impl Client {
    /// Connects, reads the `INFO`, and sends `connect` with `PING`.
    fn login(t: &Target, connect: &Value) -> Client {
        Client::login_over(t, connect, None)
    }

    /// As [`Client::login`], over TLS of `tls` if given.
    fn login_over(t: &Target, connect: &Value, tls: Option<&Pki>) -> Client {
        let mut tcp = TcpStream::connect(t.addr()).unwrap();
        tcp.set_read_timeout(Some(WAIT)).unwrap();
        // Byte by byte: what follows the `INFO` is the handshake's.
        let mut info = Vec::new();
        let mut b = [0u8; 1];
        while !info.ends_with(b"\r\n") {
            assert_eq!(tcp.read(&mut b).unwrap(), 1, "closed");
            info.push(b[0]);
        }
        let stream: Box<dyn Stream> = match tls {
            Some(pki) => Box::new(pki.wrap(tcp)),
            None => Box::new(tcp),
        };
        let line = String::from_utf8(info).unwrap();
        let mut c = Client {
            r: BufReader::new(stream),
            info: serde_json::from_str(line.trim_end().strip_prefix("INFO ").unwrap()).unwrap(),
        };
        let mut fields = json!({"verbose": false, "protocol": 1, "headers": true});
        for (k, v) in connect.as_object().unwrap() {
            fields[k] = v.clone();
        }
        c.send(&format!("CONNECT {fields}\r\nPING\r\n"));
        c
    }

    fn send(&mut self, s: &str) {
        self.r.get_mut().write_all(s.as_bytes()).unwrap();
    }

    fn line(&mut self) -> String {
        let mut l = String::new();
        assert_ne!(self.r.read_line(&mut l).unwrap(), 0, "closed");
        l.trim_end_matches("\r\n").to_owned()
    }

    /// The account it logged in to, or the error that kept it out.
    fn outcome(&mut self) -> String {
        let first = self.line();
        if first != "PONG" {
            return first;
        }
        let info: Value = serde_json::from_str(self.line().strip_prefix("INFO ").unwrap()).unwrap();
        info["remote_account"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

/// How the service answers: by the user name a client gave.
#[derive(Clone)]
struct Service {
    issuer: Arc<KeyPair>,
    /// Its curve key, where requests come sealed.
    xkey: Option<Arc<XKey>>,
    /// In operator mode, the keys of the accounts it puts users in, by
    /// the names it gives them; else the issuer signs every user.
    signers: Vec<(&'static str, Arc<KeyPair>)>,
    /// The requests it got.
    seen: Arc<std::sync::Mutex<Vec<Value>>>,
}

impl Service {
    fn new(issuer: &Arc<KeyPair>) -> Service {
        Service {
            issuer: issuer.clone(),
            xkey: None,
            signers: Vec::new(),
            seen: Arc::default(),
        }
    }

    /// Answers the requests on `t`, logged in to `account` with `connect`
    /// over TLS of `tls` if given, until the test ends.
    fn run(self, t: &Target, connect: &Value, account: &str, tls: Option<&Pki>) {
        let mut c = Client::login_over(t, connect, tls);
        assert_eq!(c.outcome(), account, "the service logs in");
        c.send("SUB $SYS.REQ.USER.AUTH 1\r\nPING\r\n");
        assert_eq!(c.line(), "PONG");
        std::thread::spawn(move || {
            while let Some((reply, headers, payload)) = next_msg(&mut c) {
                let answer = self.answer(&headers, &payload);
                let Some(answer) = answer else { continue };
                let mut out = format!("PUB {reply} {}\r\n", answer.len()).into_bytes();
                out.extend_from_slice(&answer);
                out.extend_from_slice(b"\r\n");
                if c.r.get_mut().write_all(&out).is_err() {
                    return;
                }
            }
        });
    }

    /// The answer to request `payload` with `headers`, if it answers.
    fn answer(&self, headers: &str, payload: &[u8]) -> Option<Vec<u8>> {
        let (jwt, from) = match &self.xkey {
            Some(x) => {
                let key = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("Nats-Server-Xkey: "))
                    .unwrap();
                let from = XKey::from_public_key(key.trim()).unwrap();
                (
                    String::from_utf8(x.open(payload, &from).unwrap()).unwrap(),
                    Some(from),
                )
            }
            None => (String::from_utf8(payload.to_vec()).unwrap(), None),
        };
        let req = claims(&jwt);
        self.seen.lock().unwrap().push(req.clone());
        // The server of the client asks: this one, or another of its
        // cluster.
        let server = req["nats"]["server_id"]["id"].as_str().unwrap();
        assert_eq!(req["iss"], server, "the server signs: {req}");
        assert_eq!(req["aud"], "nats-authorization-request");
        assert_eq!(req["nats"]["type"], "authorization_request");
        let user_nkey = req["nats"]["user_nkey"].as_str().unwrap();
        let opts = &req["nats"]["connect_opts"];
        let name = opts["user"]
            .as_str()
            .or(opts["auth_token"].as_str())
            .unwrap_or_default();
        let answer = self.decide(name, user_nkey, server)?;
        Some(match (&self.xkey, from) {
            (Some(x), Some(from)) if name != "plain" => x.seal(answer.as_bytes(), &from).unwrap(),
            _ => answer.into_bytes(),
        })
    }

    /// The answer for user `name`: a response JWT, or nothing.
    fn decide(&self, name: &str, user_nkey: &str, server: &str) -> Option<String> {
        let issuer = &self.issuer;
        let user = |account, nats, more| self.user(account, user_nkey, nats, more);
        let respond = |by: &KeyPair, sub: &str, aud: &str, nats| respond(by, sub, aud, nats);
        let grant = |jwt: String| respond(issuer, user_nkey, server, json!({"jwt": jwt}));
        let granted = || user("FOO", json!({"pub": {"allow": ["foo.>"]}}), json!({}));
        let other_user = KeyPair::new_user().public_key();
        let other_server = KeyPair::new_server().public_key();
        Some(match name {
            "letin" | "plain" => grant(granted()),
            "intoauth" => grant(user("AUTH", json!({}), json!({}))),
            "nowhere" => grant(user("NOPE", json!({}), json!({}))),
            "ws" => {
                let ws = json!({"allowed_connection_types": ["WEBSOCKET"]});
                grant(user("FOO", ws, json!({})))
            }
            "expired" => grant(user("FOO", json!({}), json!({"exp": now() - 10}))),
            "error" => respond(issuer, user_nkey, server, json!({"error": "nope"})),
            "both" => {
                let both = json!({"error": "nope", "jwt": granted()});
                respond(issuer, user_nkey, server, both)
            }
            "othersub" => respond(issuer, &other_user, server, json!({"jwt": granted()})),
            "otheraud" => respond(issuer, user_nkey, &other_server, json!({"jwt": granted()})),
            "othersigner" => {
                let stranger = KeyPair::new_account();
                respond(&stranger, user_nkey, server, json!({"jwt": granted()}))
            }
            "empty" => String::new(),
            "silent" => return None,
            _ => respond(issuer, user_nkey, server, json!({"error": "not you"})),
        })
    }

    /// A user JWT of key `user_nkey` for `account`, with body `nats` and
    /// claims `more`, signed by the issuer or the account's key.
    fn user(&self, account: &str, user_nkey: &str, nats: Value, more: Value) -> String {
        let mut body = json!({"type": "user", "version": 2, "subs": -1, "data": -1, "payload": -1});
        merge(&mut body, nats);
        let by = self
            .signers
            .iter()
            .find(|(n, _)| *n == account)
            .map_or(&self.issuer, |(_, kp)| kp);
        let mut c = json!({"jti": "U", "iat": now(), "iss": by.public_key(), "sub": user_nkey, "aud": account, "nats": body});
        merge(&mut c, more);
        sign(by, &c)
    }
}

/// A response JWT for `sub` at server `aud`, with body `nats`, signed by
/// `by`.
fn respond(by: &KeyPair, sub: &str, aud: &str, nats: Value) -> String {
    let mut body = json!({"type": "authorization_response", "version": 2});
    merge(&mut body, nats);
    let claims = json!({"jti": "R", "iat": now(), "iss": by.public_key(), "sub": sub, "aud": aud, "nats": body});
    sign(by, &claims)
}

/// The fields of `more` set on `into`.
fn merge(into: &mut Value, more: Value) {
    if let Value::Object(m) = more {
        for (k, v) in m {
            into[k] = v;
        }
    }
}

/// The next message `c` gets: its reply, headers and payload.
fn next_msg(c: &mut Client) -> Option<(String, String, Vec<u8>)> {
    let mut l = String::new();
    // Quiet a while: the read times out, and the service waits on.
    while !l.ends_with('\n') {
        match c.r.read_line(&mut l) {
            Ok(0) => return None,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return None,
        }
    }
    let words: Vec<&str> = l.split_whitespace().collect();
    let (reply, hlen, total) = match words.first().copied() {
        Some("MSG") => (words[3], 0, words[4].parse::<usize>().ok()?),
        Some("HMSG") => (words[3], words[4].parse().ok()?, words[5].parse().ok()?),
        Some("PING") => {
            c.send("PONG\r\n");
            return next_msg(c);
        }
        _ => return next_msg(c),
    };
    let mut body = vec![0; total + 2];
    c.r.read_exact(&mut body).ok()?;
    body.truncate(total);
    let payload = body.split_off(hlen);
    Some((reply.to_owned(), String::from_utf8(body).ok()?, payload))
}

/// The config of a server with a callout in account `AUTH` for issuer
/// `issuer`, and `more` in its block.
fn conf(issuer: &KeyPair, more: &str) -> String {
    format!(
        "accounts {{\n  AUTH {{ users: [{{user: auth, password: pwd}}] }}\n  APP {{ users: [{{user: appuser, password: pwd}}] }}\n  FOO {{}}\n}}\n\
         authorization {{\n  timeout: 1\n  auth_callout {{\n    issuer: {}\n    account: AUTH\n    auth_users: [auth]\n{more}  }}\n}}\n",
        issuer.public_key()
    )
}

#[test]
fn the_service_lets_clients_in_where_it_says() {
    let issuer = Arc::new(KeyPair::new_account());
    for (name, t) in targets(&conf(&issuer, "")) {
        Service::new(&issuer).run(&t, &json!({"user": "auth", "pass": "pwd"}), "AUTH", None);
        for (connect, want) in [
            (json!({"user": "letin"}), "FOO"),
            (json!({"auth_token": "letin"}), "FOO"),
            (json!({"user": "intoauth"}), "AUTH"),
            // A user that logs in as configured still goes to the service.
            (json!({"user": "appuser", "pass": "pwd"}), DENIED),
            (json!({}), DENIED),
            (json!({"user": "auth", "pass": "wrong"}), DENIED),
        ] {
            let got = Client::login(&t, &connect).outcome();
            assert_eq!(got, want, "{name}: {connect}");
        }
        // Clients of the callout account may not ask for others: the
        // service's own users neither.
        let mut c = Client::login(&t, &json!({"user": "auth", "pass": "pwd"}));
        assert_eq!(c.outcome(), "AUTH");
        c.send("PUB $SYS.REQ.USER.AUTH 0\r\n\r\nPING\r\n");
        assert_ne!(c.line(), "PONG", "{name}");
        let mut c = Client::login(&t, &json!({"user": "intoauth"}));
        assert_eq!(c.outcome(), "AUTH");
        c.send("PUB $SYS.REQ.USER.AUTH 0\r\n\r\nPING\r\n");
        assert_eq!(
            c.line(),
            "-ERR 'Permissions Violation for Publish to \"$SYS.REQ.USER.AUTH\"'",
            "{name}"
        );
        let mut c = Client::login(&t, &json!({"user": "letin"}));
        assert_eq!(c.outcome(), "FOO");
        c.send("PUB bar 0\r\n\r\nPING\r\n");
        assert_eq!(
            c.line(),
            "-ERR 'Permissions Violation for Publish to \"bar\"'",
            "{name}: the permissions the service gave"
        );
    }
}

#[test]
fn answers_that_do_not_hold_keep_clients_out() {
    let issuer = Arc::new(KeyPair::new_account());
    for (name, t) in targets(&conf(&issuer, "")) {
        Service::new(&issuer).run(&t, &json!({"user": "auth", "pass": "pwd"}), "AUTH", None);
        for user in [
            "nowhere",
            "ws",
            "expired",
            "error",
            "both",
            "othersub",
            "otheraud",
            "othersigner",
            "empty",
            "silent",
        ] {
            let got = Client::login(&t, &json!({"user": user})).outcome();
            assert_eq!(got, DENIED, "{name}: {user}");
        }
    }
}

#[test]
fn allowed_accounts_keep_the_users_of_others_as_configured() {
    let issuer = Arc::new(KeyPair::new_account());
    for (name, t) in targets(&conf(&issuer, "    allowed_accounts: [FOO]\n")) {
        Service::new(&issuer).run(&t, &json!({"user": "auth", "pass": "pwd"}), "AUTH", None);
        for (connect, want) in [
            (json!({"user": "appuser", "pass": "pwd"}), "APP"),
            (json!({"user": "appuser", "pass": "wrong"}), DENIED),
            (json!({"user": "letin"}), "FOO"),
        ] {
            let got = Client::login(&t, &connect).outcome();
            assert_eq!(got, want, "{name}: {connect}");
        }
        // Its users are none the service decides on: they may ask, as in
        // `nats-server`.
        let mut c = Client::login(&t, &json!({"user": "auth", "pass": "pwd"}));
        assert_eq!(c.outcome(), "AUTH");
        c.send("PUB $SYS.REQ.USER.AUTH 0\r\n\r\nPING\r\n");
        assert_eq!(c.line(), "PONG", "{name}");
    }
}

#[test]
fn sealed_requests_and_answers_go_by_curve_keys() {
    let issuer = Arc::new(KeyPair::new_account());
    let xkey = Arc::new(XKey::new());
    let more = format!("    xkey: {}\n", xkey.public_key());
    for (name, t) in targets(&conf(&issuer, &more)) {
        let service = Service {
            xkey: Some(xkey.clone()),
            ..Service::new(&issuer)
        };
        service.run(&t, &json!({"user": "auth", "pass": "pwd"}), "AUTH", None);
        for (connect, want) in [
            (json!({"user": "letin"}), "FOO"),
            // An answer in the clear holds too.
            (json!({"user": "plain"}), "FOO"),
            (json!({"user": "someone"}), DENIED),
        ] {
            let got = Client::login(&t, &connect).outcome();
            assert_eq!(got, want, "{name}: {connect}");
        }
    }
}

#[test]
fn callout_options_that_cannot_run_are_refused() {
    let issuer = KeyPair::new_account().public_key();
    for (more, why) in [
        ("    account: NOPE\n", "no account"),
        ("    allowed_accounts: [NOPE]\n", "allowed account"),
        ("    auth_users: [ghost]\n", "no user"),
        ("    xkey: AXYZ\n", "curve key"),
        ("    bogus: 1\n", "not supported"),
    ] {
        let text = format!(
            "accounts {{ A {{ users: [{{user: auth, password: p}}] }} }}\nauthorization {{ auth_callout {{\n    issuer: {issuer}\n    account: A\n    auth_users: [auth]\n{more}  }} }}\n"
        );
        let e = text.parse::<Options>().unwrap_err().to_string();
        assert!(e.contains(why), "{more}: {e}");
    }
    for (block, why) in [
        ("issuer: UABC, auth_users: [a]", "public account NKey"),
        ("auth_users: [a]", "issuer is required"),
        (&*format!("issuer: {issuer}"), "auth_users are required"),
    ] {
        let text = format!("authorization {{ auth_callout {{ {block} }} }}\n");
        let e = text.parse::<Options>().unwrap_err().to_string();
        assert!(e.contains(why), "{block}: {e}");
    }
}

/// A CA, a server certificate for 127.0.0.1 and a client one, in PEM files
/// of a directory of the test's own.
struct Pki {
    dir: PathBuf,
    client: Arc<rustls::ClientConfig>,
}

impl Pki {
    fn new() -> Pki {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair as Key};
        let dir = std::env::temp_dir().join(format!("naq-callout-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = Key::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
        let issuer = Issuer::new(ca, ca_key);
        let mut client = None;
        for (who, names) in [
            ("server", vec!["127.0.0.1".to_owned()]),
            ("client", vec!["probe".to_owned()]),
        ] {
            let key = Key::generate().unwrap();
            let cert = CertificateParams::new(names)
                .unwrap()
                .signed_by(&key, &issuer)
                .unwrap();
            std::fs::write(dir.join(format!("{who}.pem")), cert.pem()).unwrap();
            std::fs::write(dir.join(format!("{who}-key.pem")), key.serialize_pem()).unwrap();
            client = Some((cert.der().clone(), key.serialize_der()));
        }
        let (cert, key) = client.unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![cert], key.try_into().unwrap())
            .unwrap();
        Pki {
            dir,
            client: Arc::new(cfg),
        }
    }

    /// The `tls` block of a server that wants client certificates.
    fn conf(&self) -> String {
        let p = |f: &str| self.dir.join(f).display().to_string();
        format!(
            "tls {{\n  cert_file: \"{}\"\n  key_file: \"{}\"\n  ca_file: \"{}\"\n  verify: true\n}}\n",
            p("server.pem"),
            p("server-key.pem"),
            p("ca.pem")
        )
    }

    fn ca_pem(&self) -> String {
        std::fs::read_to_string(self.dir.join("ca.pem")).unwrap()
    }

    /// TLS over `tcp`, with the client certificate.
    fn wrap(&self, tcp: TcpStream) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let conn = rustls::ClientConnection::new(self.client.clone(), name).unwrap();
        rustls::StreamOwned::new(conn, tcp)
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Request `r` without what differs between servers and runs: times,
/// keys, IDs and the server's version.
fn comparable(r: &Value) -> Value {
    let mut r = r.clone();
    assert_eq!(
        r["exp"].as_i64().unwrap() - r["iat"].as_i64().unwrap(),
        1,
        "{r}"
    );
    for k in ["iat", "exp", "jti", "iss"] {
        r.as_object_mut().unwrap().remove(k);
    }
    let n = r["nats"].as_object_mut().unwrap();
    n.remove("user_nkey");
    for k in ["id", "version"] {
        n["server_id"].as_object_mut().unwrap().remove(k);
    }
    n["client_info"].as_object_mut().unwrap().remove("id");
    if let Some(tls) = n.get_mut("client_tls").and_then(Value::as_object_mut) {
        // Each server picks a suite of its own.
        assert!(
            tls.remove("cipher")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("TLS_")
        );
    }
    r
}

#[test]
fn requests_tell_the_service_what_nats_server_tells_it() {
    let issuer = Arc::new(KeyPair::new_account());
    let pki = Pki::new();
    let conf = format!("server_name: S\n{}{}", pki.conf(), conf(&issuer, ""));
    let mut requests = Vec::new();
    for (name, t) in targets(&conf) {
        let service = Service::new(&issuer);
        let seen = service.seen.clone();
        service.run(
            &t,
            &json!({"user": "auth", "pass": "pwd"}),
            "AUTH",
            Some(&pki),
        );
        let connect = json!({"user": "probe", "pass": "secret", "name": "myname", "lang": "rust", "version": "9.9"});
        let mut c = Client::login_over(&t, &connect, Some(&pki));
        let xkey = c.info["xkey"].as_str().unwrap_or_default();
        assert!(xkey.starts_with('X'), "{name}: INFO tells the curve key");
        let got = c.outcome();
        assert_eq!(got, DENIED, "{name}");
        let r = seen.lock().unwrap().pop().unwrap();
        let tls = &r["nats"]["client_tls"];
        assert_eq!(tls["version"], "1.3", "{name}: {r}");
        assert_eq!(
            tls["verified_chains"][0][1],
            pki.ca_pem(),
            "{name}: the leaf, then its CA"
        );
        requests.push((name, comparable(&r)));
    }
    if let [(_, naq), (_, go)] = &requests[..] {
        assert_eq!(naq, go);
    }
}

/// The config of operator `op` with a system account and `accounts`, each
/// with more of its JWT's body.
fn operator_conf(op: &KeyPair, accounts: &[(&KeyPair, Value)]) -> String {
    let open = json!({"conn": -1, "leaf": -1, "subs": -1, "data": -1, "payload": -1, "imports": -1, "exports": -1, "wildcards": true});
    let account = |kp: &KeyPair, more: &Value| {
        let mut nats = json!({"type": "account", "version": 2, "limits": open});
        for (k, v) in more.as_object().unwrap() {
            nats[k] = v.clone();
        }
        let claims = json!({"jti": "A", "iat": now(), "iss": op.public_key(), "sub": kp.public_key(), "nats": nats});
        format!("  {}: {}\n", kp.public_key(), sign(op, &claims))
    };
    let operator = json!({"jti": "O", "iat": now(), "iss": op.public_key(), "sub": op.public_key(), "nats": {"type": "operator", "version": 2}});
    // Without a system account, `nats-server` panics at the first callout.
    let sys = KeyPair::new_account();
    let mut preload = account(&sys, &json!({}));
    for (kp, more) in accounts {
        preload += &account(kp, more);
    }
    format!(
        "operator: {}\nsystem_account: {}\nresolver: MEMORY\nresolver_preload {{\n{preload}}}\n",
        sign(op, &operator),
        sys.public_key()
    )
}

#[test]
fn operator_mode_accounts_call_out_to_their_own_service() {
    let op = KeyPair::new_operator();
    let (auth, test, other) = (
        Arc::new(KeyPair::new_account()),
        Arc::new(KeyPair::new_account()),
        Arc::new(KeyPair::new_account()),
    );
    let svc = KeyPair::new_user();
    let authz = json!({"authorization": {"auth_users": [svc.public_key()], "allowed_accounts": [test.public_key()]}});
    let conf = operator_conf(
        &op,
        &[(&auth, authz), (&test, json!({})), (&other, json!({}))],
    );
    let bearer = |kp: &KeyPair| {
        let nats = json!({"type": "user", "version": 2, "bearer_token": true, "subs": -1, "data": -1, "payload": -1});
        sign(
            &auth,
            &json!({"jti": "B", "iat": now(), "iss": auth.public_key(), "sub": kp.public_key(), "nats": nats}),
        )
    };
    let sentinel = bearer(&KeyPair::new_user());
    for (name, t) in targets(&conf) {
        let service = Service {
            signers: vec![
                ("FOO", test.clone()),
                ("AUTH", auth.clone()),
                ("NOPE", other.clone()),
            ],
            ..Service::new(&auth)
        };
        service.run(&t, &json!({"jwt": bearer(&svc)}), &auth.public_key(), None);
        for (token, want) in [
            ("letin", test.public_key()),
            ("intoauth", auth.public_key()),
            ("nowhere", DENIED.to_owned()),
            ("someone", DENIED.to_owned()),
        ] {
            let got = Client::login(&t, &json!({"jwt": sentinel, "auth_token": token})).outcome();
            assert_eq!(got, want, "{name}: {token}");
        }
        let no_jwt = Client::login(&t, &json!({"user": "letin"})).outcome();
        assert_eq!(no_jwt, DENIED, "{name}");
    }
}

/// A free port on the loopback, from a range of this process's own, so
/// that the ports the other tests bind do not take it.
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

#[test]
fn a_service_at_another_server_of_the_cluster_answers() {
    let issuer = Arc::new(KeyPair::new_account());
    let ports = [free_port(), free_port()];
    let server = |i: usize| {
        let cluster = format!(
            "cluster {{ name: c, listen: \"127.0.0.1:{}\", routes: [\"nats-route://127.0.0.1:{}\"] }}\nserver_name: n{i}\n",
            ports[i],
            ports[1 - i]
        );
        let mut opts: Options = format!("{cluster}{}", conf(&issuer, "")).parse().unwrap();
        opts.host = "127.0.0.1".into();
        opts.port = 0;
        opts.lanes = 2;
        Target::Naq(Server::start(&opts).unwrap())
    };
    let (a, b) = (server(0), server(1));
    Service::new(&issuer).run(&b, &json!({"user": "auth", "pass": "pwd"}), "AUTH", None);
    // Until the service's interest reaches the other server.
    let deadline = Instant::now() + WAIT;
    loop {
        let got = Client::login(&a, &json!({"user": "letin"})).outcome();
        if got == "FOO" {
            break;
        }
        assert!(Instant::now() < deadline, "{got}");
    }
    let got = Client::login(&a, &json!({"user": "someone"})).outcome();
    assert_eq!(got, DENIED);
}

#[test]
fn a_hashed_password_decides_where_the_service_does_not() {
    let issuer = Arc::new(KeyPair::new_account());
    let hash = bcrypt::hash("pwd", 4).unwrap();
    let text = conf(&issuer, "    allowed_accounts: [FOO]\n").replace(
        "{user: appuser, password: pwd}",
        &format!("{{user: appuser, password: \"{hash}\"}}"),
    );
    for (name, t) in targets(&text) {
        Service::new(&issuer).run(&t, &json!({"user": "auth", "pass": "pwd"}), "AUTH", None);
        for (connect, want) in [
            (json!({"user": "appuser", "pass": "pwd"}), "APP"),
            (json!({"user": "appuser", "pass": "wrong"}), DENIED),
        ] {
            let got = Client::login(&t, &connect).outcome();
            assert_eq!(got, want, "{name}: {connect}");
        }
    }
}

#[test]
fn a_client_that_acts_before_its_connect_is_refused() {
    let issuer = Arc::new(KeyPair::new_account());
    for (name, t) in targets(&conf(&issuer, "")) {
        Service::new(&issuer).run(&t, &json!({"user": "auth", "pass": "pwd"}), "AUTH", None);
        let mut tcp = TcpStream::connect(t.addr()).unwrap();
        tcp.set_read_timeout(Some(WAIT)).unwrap();
        tcp.write_all(b"PING\r\n").unwrap();
        let mut r = BufReader::new(tcp);
        let mut info = String::new();
        r.read_line(&mut info).unwrap();
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), DENIED, "{name}");
    }
}
