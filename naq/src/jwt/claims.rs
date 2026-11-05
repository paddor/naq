//! The claims of operator, account, user and activation JWTs that the
//! server reads, as nats-io/jwt v2 has them: every field may be left out,
//! and a number left out is 0.

use rustc_hash::FxHashMap;
use serde::{Deserialize, Deserializer};

/// No limit, where a limit is a count.
pub(crate) const NO_LIMIT: i64 = -1;

/// The body of an operator JWT.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Operator {
    pub(crate) signing_keys: Vec<String>,
    pub(crate) system_account: String,
    pub(crate) strict_signing_key_usage: bool,
    pub(crate) account_server_url: String,
    pub(crate) assert_server_version: String,
}

/// The body of an account JWT.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Account {
    pub(crate) imports: Vec<Import>,
    pub(crate) exports: Vec<Export>,
    pub(crate) limits: AccountLimits,
    pub(crate) signing_keys: SigningKeys,
    pub(crate) revocations: FxHashMap<String, i64>,
    pub(crate) default_permissions: Permissions,
    pub(crate) mappings: FxHashMap<String, serde_json::Value>,
    pub(crate) authorization: Authorization,
    pub(crate) tags: Vec<String>,
}

/// The limits of an account, and of each of its users.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct AccountLimits {
    pub(crate) subs: i64,
    pub(crate) data: i64,
    pub(crate) payload: i64,
    pub(crate) imports: i64,
    pub(crate) exports: i64,
    pub(crate) wildcards: bool,
    pub(crate) disallow_bearer: bool,
    pub(crate) conn: i64,
    pub(crate) leaf: i64,
}

/// Auth callout of an account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Authorization {
    pub(crate) auth_users: Vec<String>,
    pub(crate) allowed_accounts: Vec<String>,
    pub(crate) xkey: String,
}

/// Whether an export or import is of messages or a service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    #[default]
    #[serde(skip)]
    Unknown,
    Stream,
    Service,
}

/// An export of an account JWT.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Export {
    pub(crate) name: String,
    pub(crate) subject: String,
    #[serde(rename = "type")]
    pub(crate) kind: Kind,
    pub(crate) token_req: bool,
    pub(crate) revocations: FxHashMap<String, i64>,
    pub(crate) response_type: String,
    /// In nanoseconds.
    pub(crate) response_threshold: i64,
    pub(crate) service_latency: Option<ServiceLatency>,
    pub(crate) account_token_position: u32,
    pub(crate) allow_trace: bool,
}

/// The latency samples of an exported service.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct ServiceLatency {
    /// A percent; 0 for headers.
    #[serde(deserialize_with = "sampling")]
    pub(crate) sampling: i64,
    pub(crate) results: String,
}

/// A percent, or `"headers"` for 0.
fn sampling<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Rate {
        Number(i64),
        Text(String),
    }
    match Rate::deserialize(d)? {
        Rate::Number(n) => Ok(n),
        Rate::Text(t) if t.eq_ignore_ascii_case("headers") => Ok(0),
        Rate::Text(t) => Err(serde::de::Error::custom(format!("bad sampling {t:?}"))),
    }
}

/// An import of an account JWT.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Import {
    pub(crate) name: String,
    pub(crate) subject: String,
    pub(crate) account: String,
    pub(crate) token: String,
    pub(crate) to: String,
    pub(crate) local_subject: String,
    #[serde(rename = "type")]
    pub(crate) kind: Kind,
    pub(crate) share: bool,
    pub(crate) allow_trace: bool,
}

/// The signing keys of an account: plain ones, and scoped ones with the
/// template their users get.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SigningKeys(pub(crate) FxHashMap<String, Option<Box<UserScope>>>);

/// A scoped signing key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct UserScope {
    pub(crate) kind: String,
    pub(crate) key: String,
    #[serde(default)]
    pub(crate) role: String,
    #[serde(default = "UserLimits::unlimited", deserialize_with = "template")]
    pub(crate) template: UserLimits,
}

/// A scoped key's template: the limits it leaves out are none, as
/// nats-io/jwt decodes it over a new scope.
fn template<'de, D: Deserializer<'de>>(d: D) -> Result<UserLimits, D::Error> {
    let mut v = serde_json::Value::deserialize(d)?;
    if let Some(m) = v.as_object_mut() {
        for k in ["subs", "data", "payload"] {
            m.entry(k).or_insert(NO_LIMIT.into());
        }
    }
    UserLimits::deserialize(v).map_err(serde::de::Error::custom)
}

impl<'de> Deserialize<'de> for SigningKeys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Key {
            Plain(String),
            Scoped(Box<UserScope>),
        }
        let keys = Vec::<Key>::deserialize(d)?;
        Ok(SigningKeys(
            keys.into_iter()
                .map(|k| match k {
                    Key::Plain(k) => (k, None),
                    Key::Scoped(s) => (s.key.clone(), Some(s)),
                })
                .collect(),
        ))
    }
}

/// What a user may publish and subscribe to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Permissions {
    #[serde(rename = "pub")]
    pub(crate) publish: Permission,
    #[serde(rename = "sub")]
    pub(crate) subscribe: Permission,
    pub(crate) resp: Option<ResponsePermission>,
}

impl Permissions {
    /// None at all: an account's default permissions apply.
    pub(crate) const fn is_empty(&self) -> bool {
        self.publish.is_empty() && self.subscribe.is_empty() && self.resp.is_none()
    }
}

/// Subjects allowed and denied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Permission {
    pub(crate) allow: Vec<String>,
    pub(crate) deny: Vec<String>,
}

impl Permission {
    pub(crate) const fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

/// Replies a user may publish to requests it got.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct ResponsePermission {
    pub(crate) max: i64,
    /// In nanoseconds.
    pub(crate) ttl: i64,
}

/// What a user may do, and from where and when, as a user JWT and a
/// scoped signing key's template have it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct UserLimits {
    #[serde(flatten)]
    pub(crate) permissions: Permissions,
    pub(crate) subs: i64,
    pub(crate) data: i64,
    pub(crate) payload: i64,
    #[serde(deserialize_with = "cidrs")]
    pub(crate) src: Vec<String>,
    pub(crate) times: Vec<TimeRange>,
    pub(crate) times_location: String,
    pub(crate) bearer_token: bool,
    pub(crate) proxy_required: bool,
    pub(crate) allowed_connection_types: Vec<String>,
}

impl UserLimits {
    /// A scoped signing key's template left out: no limits.
    fn unlimited() -> UserLimits {
        UserLimits {
            subs: NO_LIMIT,
            data: NO_LIMIT,
            payload: NO_LIMIT,
            ..UserLimits::default()
        }
    }

    /// Nothing is set, as a user of a scoped signing key must leave it.
    pub(crate) fn is_empty(&self) -> bool {
        *self == UserLimits::default()
    }
}

/// CIDRs as a list, or as one string separated by commas.
fn cidrs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum List {
        All(Vec<String>),
        One(String),
    }
    Ok(match List::deserialize(d)? {
        List::All(all) => all,
        List::One(s) => s
            .to_ascii_lowercase()
            .split(',')
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty())
            .collect(),
    })
}

/// A daily window a user may connect in, `HH:MM:SS` to `HH:MM:SS`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct TimeRange {
    pub(crate) start: String,
    pub(crate) end: String,
}

/// The body of a user JWT.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct User {
    #[serde(flatten)]
    pub(crate) limits: UserLimits,
    pub(crate) issuer_account: String,
    pub(crate) tags: Vec<String>,
}

/// The body of an activation JWT: a token to import an export.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Activation {
    pub(crate) subject: String,
    pub(crate) kind: Kind,
    pub(crate) issuer_account: String,
}
