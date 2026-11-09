//! The request a server sends an auth service about a client: a JWT it
//! signs with its own key, claims in the order `nats-server` writes them,
//! sealed to the service's curve key where it has one.

use data_encoding::{BASE32_NOPAD, BASE64, BASE64URL_NOPAD};
use serde::Serialize;
use sha2::Digest;

use crate::auth::Creds;

/// What the request says of the client.
#[derive(Debug, Default)]
pub(crate) struct About<'a> {
    pub(crate) id: u64,
    pub(crate) ip: &'a str,
    pub(crate) websocket: bool,
    /// What its `CONNECT` gave: credentials, then name, language and
    /// library version.
    pub(crate) creds: Option<&'a Creds>,
    pub(crate) name: Option<&'a str>,
    pub(crate) lang: Option<&'a str>,
    pub(crate) version: Option<&'a str>,
    pub(crate) protocol: i32,
    /// The nonce of its `INFO`.
    pub(crate) nonce: Option<&'a str>,
    /// In operator mode: the subject, tags and name of the user JWT it gave.
    pub(crate) jwt_user: Option<(&'a str, &'a [String], &'a str)>,
    pub(crate) tls: Option<&'a TlsInfo>,
}

/// The TLS of a client's connection, as a request tells it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TlsInfo {
    /// `1.2` or `1.3`.
    pub(crate) version: &'static str,
    /// The cipher suite, by Go's name.
    pub(crate) cipher: String,
    /// The certificates of its verified chain, leaf first, in PEM.
    pub(crate) chain: Vec<String>,
}

/// Who sends the request, and to whom.
#[derive(Debug)]
pub(crate) struct From<'a> {
    pub(crate) server: &'a nkeys::KeyPair,
    pub(crate) name: &'a str,
    pub(crate) host: &'a str,
    pub(crate) cluster: &'a str,
    /// The callout's issuer: its account key.
    pub(crate) issuer: &'a str,
    /// The public key of the user the answer must name.
    pub(crate) user_nkey: &'a str,
    /// The server's curve key, when the request is sealed.
    pub(crate) xkey: Option<&'a str>,
    /// When it is made, and when it is too late to answer: seconds since
    /// the epoch.
    pub(crate) iat: i64,
    pub(crate) exp: i64,
}

#[derive(Serialize)]
struct Claims<'a> {
    aud: &'a str,
    exp: i64,
    #[serde(skip_serializing_if = "str::is_empty")]
    jti: &'a str,
    iat: i64,
    iss: &'a str,
    sub: &'a str,
    nats: Nats<'a>,
}

#[derive(Serialize)]
struct Nats<'a> {
    server_id: Server<'a>,
    user_nkey: &'a str,
    client_info: ClientInfo<'a>,
    connect_opts: ConnectOpts<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_tls: Option<ClientTls<'a>>,
    #[serde(rename = "type")]
    kind: &'static str,
    version: u8,
}

#[derive(Serialize)]
struct Server<'a> {
    name: &'a str,
    host: &'a str,
    id: &'a str,
    version: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    cluster: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    xkey: Option<&'a str>,
}

#[derive(Serialize)]
struct ClientInfo<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    host: &'a str,
    #[serde(skip_serializing_if = "is_zero")]
    id: u64,
    #[serde(skip_serializing_if = "str::is_empty")]
    user: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    name: &'a str,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    tags: &'a [String],
    #[serde(skip_serializing_if = "str::is_empty")]
    name_tag: &'a str,
    kind: &'static str,
    #[serde(rename = "type")]
    kind_of: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    nonce: &'a str,
}

#[derive(Serialize)]
struct ConnectOpts<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    jwt: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    nkey: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    sig: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    auth_token: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    user: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pass: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    lang: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    version: &'a str,
    protocol: i32,
}

#[derive(Serialize)]
struct ClientTls<'a> {
    version: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    cipher: &'a str,
    #[serde(skip_serializing_if = "<[Vec<String>]>::is_empty")]
    verified_chains: &'a [Vec<String>],
}

#[expect(clippy::trivially_copy_pass_by_ref, reason = "serde hands a reference")]
const fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// The request about client `c` from `f`, signed: a JWT.
pub(crate) fn jwt(f: &From<'_>, c: &About<'_>) -> String {
    let creds = c.creds.cloned().unwrap_or_default();
    let chains: Vec<Vec<String>> = c
        .tls
        .iter()
        .filter(|t| !t.chain.is_empty())
        .map(|t| t.chain.clone())
        .collect();
    let server_id = f.server.public_key();
    let nats = |jti| Claims {
        aud: "nats-authorization-request",
        exp: f.exp,
        jti,
        iat: f.iat,
        iss: &server_id,
        sub: f.issuer,
        nats: Nats {
            server_id: Server {
                name: f.name,
                host: f.host,
                id: &server_id,
                version: crate::server::NATS_VERSION,
                cluster: f.cluster,
                xkey: f.xkey,
            },
            user_nkey: f.user_nkey,
            client_info: client_info(c, &creds),
            connect_opts: connect_opts(c, &creds),
            client_tls: c.tls.map(|t| ClientTls {
                version: t.version,
                cipher: &t.cipher,
                verified_chains: &chains,
            }),
            kind: "authorization_request",
            version: 2,
        },
    };
    // As nats-io/jwt makes it: the hash of the claims without one.
    let unhashed = serde_json::to_vec(&nats("")).unwrap_or_default();
    let jti = BASE32_NOPAD.encode(&sha2::Sha512_256::digest(&unhashed));
    let payload = serde_json::to_vec(&nats(&jti)).unwrap_or_default();
    sign(f.server, &payload)
}

/// Who client `c` of credentials `creds` is.
fn client_info<'a>(c: &About<'a>, creds: &'a Creds) -> ClientInfo<'a> {
    let (jwt_sub, tags, name_tag) = c.jwt_user.unwrap_or_default();
    // As `nats-server` names the user: its NKey, its name, its JWT's
    // subject, or a token it hides.
    let user = [&creds.nkey, &creds.user]
        .into_iter()
        .find_map(|s| s.as_deref().filter(|s| !s.is_empty()))
        .or((!jwt_sub.is_empty()).then_some(jwt_sub))
        .or(creds.token.as_ref().map(|_| "[REDACTED]"))
        .unwrap_or_default();
    let signed = creds.sig.as_deref().is_some_and(|s| !s.is_empty());
    ClientInfo {
        host: c.ip,
        id: c.id,
        user,
        name: c.name.unwrap_or_default(),
        tags,
        name_tag,
        kind: "Client",
        kind_of: if c.websocket { "websocket" } else { "nats" },
        nonce: c.nonce.filter(|_| signed).unwrap_or_default(),
    }
}

/// What the `CONNECT` of client `c` of credentials `creds` gave.
fn connect_opts<'a>(c: &About<'a>, creds: &'a Creds) -> ConnectOpts<'a> {
    let text = |s: &'a Option<String>| s.as_deref().unwrap_or_default();
    ConnectOpts {
        jwt: text(&creds.jwt),
        nkey: text(&creds.nkey),
        sig: text(&creds.sig),
        auth_token: text(&creds.token),
        user: text(&creds.user),
        pass: text(&creds.pass),
        name: c.name.unwrap_or_default(),
        lang: c.lang.unwrap_or_default(),
        version: c.version.unwrap_or_default(),
        protocol: c.protocol,
    }
}

/// JWT claims `payload`, signed by `key`.
pub(crate) fn sign(key: &nkeys::KeyPair, payload: &[u8]) -> String {
    let head = BASE64URL_NOPAD.encode(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let body = BASE64URL_NOPAD.encode(payload);
    let signed = format!("{head}.{body}");
    // A key made by the server signs: it has its seed.
    let sig = key.sign(signed.as_bytes()).unwrap_or_default();
    format!("{signed}.{}", BASE64URL_NOPAD.encode(&sig))
}

/// Certificate `der` in PEM, as Go writes it.
pub(crate) fn pem(der: &[u8]) -> String {
    let b64 = BASE64.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests;
