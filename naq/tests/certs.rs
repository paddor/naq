//! Clients that log in as the users their TLS certificates name
//! (`verify_and_map`), and users limited to kinds of connection. Each
//! scenario runs against naq, and against `nats-server` too when `NAQ_GO`
//! names one: both must behave the same.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use naq::{Options, Server};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, SanType,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const WAIT: Duration = Duration::from_secs(5);

/// A CA and a server certificate for 127.0.0.1, in PEM files of a
/// directory of the test's own; client certificates on demand.
struct Pki {
    dir: PathBuf,
    ca: Issuer<'static, KeyPair>,
}

impl Pki {
    fn new(name: &str) -> Pki {
        let dir = std::env::temp_dir().join(format!("naq-certs-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        std::fs::write(dir.join("ca.pem"), ca.self_signed(&key).unwrap().pem()).unwrap();
        let pki = Pki {
            dir,
            ca: Issuer::new(ca, key),
        };
        let server = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
        pki.mint("server", &server);
        pki
    }

    /// Certificate `params`, signed by the CA, in `{name}.pem`, and its key
    /// in `{name}-key.pem`.
    fn mint(&self, name: &str, params: &CertificateParams) {
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.ca).unwrap();
        std::fs::write(self.path(&format!("{name}.pem")), cert.pem()).unwrap();
        std::fs::write(self.path(&format!("{name}-key.pem")), key.serialize_pem()).unwrap();
    }

    /// A client certificate `name` of `subject` and alternative names `alt`.
    fn client(&self, name: &str, subject: &[(DnType, &str)], alt: &[SanType]) {
        let mut p = CertificateParams::default();
        p.distinguished_name = DistinguishedName::new();
        for (t, v) in subject {
            p.distinguished_name.push(t.clone(), *v);
        }
        p.subject_alt_names = alt.to_vec();
        self.mint(name, &p);
    }

    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    /// The `tls` block of a server that maps certificates to users.
    fn conf(&self) -> String {
        let p = |f: &str| self.path(f).display().to_string();
        format!(
            "tls {{\n  cert_file: \"{}\"\n  key_file: \"{}\"\n  ca_file: \"{}\"\n  verify_and_map: true\n}}\n",
            p("server.pem"),
            p("server-key.pem"),
            p("ca.pem")
        )
    }

    /// A client side that trusts the CA and presents certificate `name`.
    fn config(&self, name: &str) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(self.path("ca.pem")).unwrap())
            .unwrap();
        let chain = vec![CertificateDer::from_pem_file(self.path(&format!("{name}.pem"))).unwrap()];
        let key = PrivateKeyDer::from_pem_file(self.path(&format!("{name}-key.pem"))).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .unwrap();
        Arc::new(cfg)
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
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

/// naq, then `nats-server` if `NAQ_GO` names one, each running `conf`.
fn targets(conf: &str, dir: &Path) -> Vec<(&'static str, Target)> {
    let mut opts: Options = conf.parse().unwrap();
    opts.host = "127.0.0.1".into();
    opts.port = 0;
    opts.lanes = 1;
    let mut all = vec![("naq", Target::Naq(Server::start(&opts).unwrap()))];
    if let Some(bin) = std::env::var_os("NAQ_GO").map(PathBuf::from) {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let path = dir.join("go.conf");
        std::fs::write(&path, format!("listen: 127.0.0.1:{port}\n{conf}")).unwrap();
        let child = Command::new(bin)
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let go = GoServer { child };
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
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What the server says first to a client of certificate `cert` that
/// sends `connect` and publishes to `subject`: `PONG` if it may, else an
/// error.
fn first_reply(t: &Target, pki: &Pki, cert: &str, connect: &str, subject: &str) -> String {
    let tcp = TcpStream::connect(t.addr()).unwrap();
    tcp.set_read_timeout(Some(WAIT)).unwrap();
    let mut clear = BufReader::new(tcp.try_clone().unwrap());
    let mut info = String::new();
    clear.read_line(&mut info).unwrap();
    assert!(info.contains(r#""tls_verify":true"#), "{info}");
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let conn = ClientConnection::new(pki.config(cert), name).unwrap();
    let mut tls = BufReader::new(StreamOwned::new(conn, tcp));
    write!(
        tls.get_mut(),
        "CONNECT {}\r\nPUB {subject} 0\r\n\r\nPING\r\n",
        quiet(connect)
    )
    .unwrap();
    let mut line = String::new();
    tls.read_line(&mut line).unwrap();
    line.trim_end().to_owned()
}

fn ia5(s: &str) -> SanType {
    let (kind, value) = s.split_once(':').unwrap();
    let v = value.try_into().unwrap();
    match kind {
        "email" => SanType::Rfc822Name(v),
        "dns" => SanType::DnsName(v),
        _ => SanType::URI(v),
    }
}

const DENIED: &str = "-ERR 'Authorization Violation'";

/// `CONNECT` fields `json`, quiet.
fn quiet(json: &str) -> String {
    let rest = json.strip_prefix('{').unwrap();
    let sep = if rest == "}" { "" } else { "," };
    format!(r#"{{"verbose":false{sep}{rest}"#)
}

/// Client certificates of every way of naming a user.
fn clients(pki: &Pki) {
    let email = DnType::CustomDnType(vec![1, 2, 840, 113_549, 1, 9, 1]);
    let dc = DnType::CustomDnType(vec![0, 9, 2342, 19_200_300, 100, 1, 25]);
    let us = (DnType::CountryName, "US");
    let acme = (DnType::OrganizationName, "Acme");
    let cn = |n| (DnType::CommonName, n);
    pki.client(
        "alice",
        &[cn("alice")],
        &[
            ia5("uri:spiffe://acme.com/alice"),
            ia5("dns:alice.acme.com"),
            ia5("email:alice@acme.com"),
        ],
    );
    pki.client(
        "svc",
        &[cn("svc")],
        &[ia5("dns:svc.acme.com"), ia5("uri:spiffe://acme.com/svc")],
    );
    pki.client("bob", &[us.clone(), acme.clone(), cn("bob")], &[]);
    pki.client("bob2", &[us, acme, cn("bob2")], &[]);
    pki.client(
        "carol",
        &[(dc, "acme"), cn("carol"), (email.clone(), "carol@acme.com")],
        &[],
    );
    pki.client("dave", &[cn("dave"), (email, "dave@acme.com")], &[]);
    for name in ["eve", "web", "pw"] {
        pki.client(name, &[cn(name)], &[]);
    }
}

#[test]
fn certificates_name_users_as_nats_server_maps_them() {
    let pki = Pki::new("map");
    clients(&pki);
    let user = |name: &str, who: &str, more: &str| {
        format!("    {{user: \"{name}\", permissions: {{publish: \"who.{who}\"}}{more}}}\n")
    };
    let users = [
        user("alice@acme.com", "email", ""),
        user("alice.acme.com", "dns", ""),
        user("spiffe://acme.com/svc", "uri", ""),
        user("CN=bob, O=Acme, C=US", "dn", ""),
        user("C=US,O=Acme,CN=bob2", "reordered", ""),
        user("CN=carol,DC=acme", "dc", ""),
        user("CN=dave", "text", ""),
        user(
            "CN=web",
            "web",
            ", allowed_connection_types: [\"WEBSOCKET\"]",
        ),
        user("CN=pw", "pw", ", password: \"s3cret\""),
    ];
    let conf = format!(
        "{}authorization {{\n  users = [\n{}  ]\n}}\n",
        pki.conf(),
        users.concat()
    );
    for (name, t) in targets(&conf, &pki.dir) {
        for (cert, connect, subject, want) in [
            ("alice", "{}", "who.email", "PONG"),
            ("svc", "{}", "who.uri", "PONG"),
            ("bob", "{}", "who.dn", "PONG"),
            ("bob2", "{}", "who.reordered", "PONG"),
            ("carol", "{}", "who.dc", "PONG"),
            ("dave", "{}", "who.text", "PONG"),
            // The certificate names the user, whatever the CONNECT says.
            ("alice", r#"{"user":"CN=dave"}"#, "who.email", "PONG"),
            (
                "alice",
                r#"{"user":"CN=pw","pass":"s3cret"}"#,
                "who.email",
                DENIED,
            ),
            ("eve", "{}", "who.eve", DENIED),
            ("web", "{}", "who.web", DENIED),
            ("pw", "{}", "who.pw", DENIED),
            ("pw", r#"{"pass":"s3cret"}"#, "who.pw", "PONG"),
        ] {
            let got = first_reply(&t, &pki, cert, connect, subject);
            assert_eq!(got, want, "{name}: {cert} {connect}");
        }
    }
}

/// A plain client's first reply after logging in with `connect`.
fn plain_reply(t: &Target, connect: &str) -> String {
    let tcp = TcpStream::connect(t.addr()).unwrap();
    tcp.set_read_timeout(Some(WAIT)).unwrap();
    let mut r = BufReader::new(tcp.try_clone().unwrap());
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    (&tcp)
        .write_all(format!("CONNECT {}\r\nPING\r\n", quiet(connect)).as_bytes())
        .unwrap();
    line.clear();
    r.read_line(&mut line).unwrap();
    line.trim_end().to_owned()
}

#[test]
fn users_log_in_only_over_the_kinds_of_connection_they_may() {
    let dir = std::env::temp_dir().join(format!("naq-certs-kinds-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = "authorization {\n  users = [\n    {user: a, password: p, allowed_connection_types: [\"STANDARD\"]}\n    {user: w, password: p, allowed_connection_types: \"websocket\"}\n    {user: l, password: p, connection_types: [\"LEAFNODE\", \"MQTT\"]}\n    {user: any, password: p, allowed_connection_types: []}\n  ]\n}\nno_auth_user: w\n";
    for (name, t) in targets(conf, &dir) {
        for (connect, want) in [
            (r#"{"user":"a","pass":"p"}"#, "PONG"),
            (r#"{"user":"any","pass":"p"}"#, "PONG"),
            (r#"{"user":"w","pass":"p"}"#, DENIED),
            (r#"{"user":"l","pass":"p"}"#, DENIED),
            // The `no_auth_user` too may only connect as it may.
            ("{}", DENIED),
        ] {
            assert_eq!(plain_reply(&t, connect), want, "{name}: {connect}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_connection_types_are_an_error() {
    let bad = "authorization { users = [ {user: a, password: p, allowed_connection_types: [\"STANDARD\", \"BOGUS\"]} ] }";
    let e = bad.parse::<Options>().unwrap_err().to_string();
    assert!(e.contains(r#"invalid connection types ["BOGUS"]"#), "{e}");
}
