//! JWTs of decentralized auth, as nats-io/jwt v2 reads them: three
//! base64url parts, a header naming the NKey algorithm, claims signed by
//! their issuer's key over the header and the claims.

pub(crate) mod claims;
pub(crate) mod template;
pub(crate) mod trust;
pub(crate) mod validate;

use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use serde::de::DeserializeOwned;

/// The largest JWT taken, as in nats-io/jwt.
const MAX_SIZE: usize = 1 << 20;

/// Why a JWT does not hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Invalid {
    #[error("token too large")]
    TooLarge,
    #[error("expected 3 chunks")]
    Chunks,
    #[error("bad encoding")]
    Encoding,
    #[error("bad header")]
    Header,
    #[error("bad claims: {0}")]
    Claims(String),
    #[error("not {0} claims")]
    Kind(&'static str),
    #[error("version {0} claims are not supported")]
    Version(u32),
    #[error("signature verification failed")]
    Signature,
    #[error("issuer is not a {0} key")]
    Issuer(&'static str),
}

/// What kind of JWT a claim is, and the keys that may issue it.
pub(crate) trait Body: DeserializeOwned + Default {
    /// The `nats.type` of the claims.
    const TYPE: &'static str;
    /// The first letters of the keys that may issue it.
    const ISSUERS: &'static [char];
}

impl Body for claims::Operator {
    const TYPE: &'static str = "operator";
    const ISSUERS: &'static [char] = &['O'];
}

impl Body for claims::Account {
    const TYPE: &'static str = "account";
    const ISSUERS: &'static [char] = &['A', 'O'];
}

impl Body for claims::User {
    const TYPE: &'static str = "user";
    const ISSUERS: &'static [char] = &['A'];
}

impl Body for claims::AuthResponse {
    const TYPE: &'static str = "authorization_response";
    const ISSUERS: &'static [char] = &['A'];
}

impl Body for claims::Activation {
    const TYPE: &'static str = "activation";
    const ISSUERS: &'static [char] = &['A', 'O'];
}

/// The claims of a JWT, its body of type `T` under `nats`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Claims<T> {
    pub(crate) jti: String,
    /// Seconds since the epoch, as `exp` and `nbf`; 0 for none.
    pub(crate) iat: i64,
    pub(crate) exp: i64,
    pub(crate) nbf: i64,
    pub(crate) iss: String,
    pub(crate) sub: String,
    pub(crate) name: String,
    pub(crate) aud: String,
    pub(crate) nats: T,
}

impl<T> Claims<T> {
    /// Whether it expired, or is not valid yet, at `now`, seconds since the
    /// epoch.
    pub(crate) const fn out_of_time(&self, now: i64) -> bool {
        (self.exp > 0 && now > self.exp) || (self.nbf > 0 && self.nbf > now)
    }
}

/// `nats.type` and `nats.version`, to tell the kind and version of claims.
#[derive(Deserialize)]
struct Kind {
    #[serde(default, rename = "type")]
    v1_type: Option<String>,
    #[serde(default)]
    nats: KindFields,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct KindFields {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
}

#[derive(Deserialize)]
struct Header {
    #[serde(default)]
    typ: String,
    #[serde(default)]
    alg: String,
}

/// Decodes `token` as claims of `T`, signed by its issuer, which must be a
/// key that may issue them. Time is not checked.
pub(crate) fn decode<T: Body>(token: &str) -> Result<Claims<T>, Invalid> {
    let token = token.trim();
    if token.len() > MAX_SIZE {
        return Err(Invalid::TooLarge);
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [header, payload, sig] = parts[..] else {
        return Err(Invalid::Chunks);
    };
    let h: Header = serde_json::from_slice(&base64(header)?).map_err(|_| Invalid::Header)?;
    let alg = h.alg.to_ascii_lowercase();
    if !h.typ.eq_ignore_ascii_case("jwt") || (alg != "ed25519" && alg != "ed25519-nkey") {
        return Err(Invalid::Header);
    }
    let data = base64(payload)?;
    let kind: Kind = serde_json::from_slice(&data).map_err(|e| Invalid::Claims(e.to_string()))?;
    if kind.v1_type.is_some() {
        return Err(Invalid::Version(1));
    }
    match kind.nats.version {
        0 | 3.. => return Err(Invalid::Version(kind.nats.version)),
        _ => {}
    }
    if kind.nats.kind != T::TYPE {
        return Err(Invalid::Kind(T::TYPE));
    }
    let claims: Claims<T> =
        serde_json::from_slice(&data).map_err(|e| Invalid::Claims(e.to_string()))?;
    let signed = &token[..header.len() + 1 + payload.len()];
    let key = nkeys::KeyPair::from_public_key(&claims.iss).map_err(|_| Invalid::Signature)?;
    key.verify(signed.as_bytes(), &base64(sig)?)
        .map_err(|_| Invalid::Signature)?;
    if !claims.iss.starts_with(T::ISSUERS) {
        return Err(Invalid::Issuer(T::TYPE));
    }
    Ok(claims)
}

fn base64(part: &str) -> Result<Vec<u8>, Invalid> {
    BASE64URL_NOPAD
        .decode(part.as_bytes())
        .map_err(|_| Invalid::Encoding)
}

/// The seconds since the epoch now.
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}

/// Whether `key` is a public key of the kind its first letter `prefix`
/// names, with a valid checksum.
pub(crate) fn is_key(key: &str, prefix: char) -> bool {
    key.starts_with(prefix) && nkeys::KeyPair::from_public_key(key).is_ok()
}

#[cfg(test)]
mod tests;
