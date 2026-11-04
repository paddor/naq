//! The `websocket` block.

use super::parse::{Item, Value};
use super::{Bad, duration, string};
use crate::{Websocket, WebsocketAuth};

/// `websocket { listen, host, port, no_tls, tls, same_origin,
/// allowed_origins, handshake_timeout, compression, headers,
/// ping_interval, user_cookie, pass_cookie, token_cookie, authorization,
/// no_auth_user, advertise }`. Without a port, or with port 0, there is
/// none, as in `nats-server`; -1 picks a free one. `advertise` changes
/// nothing on one server: only a cluster tells clients about it.
pub(super) fn websocket(item: &Item) -> Result<Option<Websocket>, Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "websocket: expected a map".into()));
    };
    let mut w = Websocket::default();
    let mut on = false;
    for (k, v) in m {
        let k = k.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("websocket: {k}: {reason}"));
        let text = || string(v).ok_or_else(|| bad("expected a string"));
        let flag = || match v.value {
            Value::Bool(b) => Ok(b),
            _ => Err(bad("expected true or false")),
        };
        match k.as_str() {
            "listen" => {
                let (host, port) = super::listen(v).ok_or_else(|| bad("expected host:port"))?;
                if let Some(h) = host {
                    w.host = h;
                }
                w.port = port;
                on = port != 0;
            }
            "host" | "net" => w.host = text()?,
            "port" => {
                let p = port(v).ok_or_else(|| bad("expected a port"))?;
                on = p != 0;
                // -1: a free one.
                w.port = u16::try_from(p).unwrap_or(0);
            }
            "no_tls" => w.no_tls = flag()?,
            "tls" => w.tls = Some(super::tls(v)?),
            "same_origin" => w.same_origin = flag()?,
            "allowed_origins" | "allowed_origin" | "allow_origins" | "allow_origin" | "origins"
            | "origin" => {
                w.allowed_origins = strings(v).ok_or_else(|| bad("expected strings"))?;
            }
            "handshake_timeout" => w.handshake_timeout = duration(v).map_err(|e| bad(&e))?,
            "compress" | "compression" => w.compression = flag()?,
            "headers" => w.headers = headers(v).ok_or_else(|| bad("expected a map of strings"))?,
            "ping_interval" => w.ping_interval = Some(duration(v).map_err(|e| bad(&e))?),
            "user_cookie" => w.cookies.user = Some(text()?),
            "pass_cookie" => w.cookies.pass = Some(text()?),
            "token_cookie" => w.cookies.token = Some(text()?),
            "authorization" | "authentication" => auth(&mut w.auth, v)?,
            "no_auth_user" => w.auth.no_auth_user = Some(text()?),
            "advertise" => drop(text()?),
            // Without trusted operators, as naq has none, `nats-server`
            // refuses it too.
            "jwt_cookie" => {
                return Err(bad(&format!(
                    "trusted operators or trusted keys configuration is required for JWT authentication via cookie {:?}",
                    text()?
                )));
            }
            _ => return Err(bad("not supported")),
        }
    }
    Ok(on.then_some(w))
}

/// `authorization { user, password, token, timeout }` of the `websocket`
/// block. A timeout of 0 leaves the server's, as in `nats-server`.
fn auth(a: &mut WebsocketAuth, item: &Item) -> Result<(), Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "websocket: authorization: expected a map".into()));
    };
    let (mut user, mut password) = (None, None);
    for (k, v) in m {
        let k = k.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("websocket: authorization: {k}: {reason}"));
        let text = || string(v).ok_or_else(|| bad("expected a string"));
        match k.as_str() {
            "user" | "username" => user = Some(text()?),
            "pass" | "password" => password = Some(text()?),
            "token" => a.token = Some(text()?),
            "timeout" => {
                let t =
                    super::auth::timeout(v).ok_or_else(|| bad("expected seconds or a duration"))?;
                a.timeout = (!t.is_zero()).then_some(t);
            }
            _ => return Err(bad("not supported")),
        }
    }
    match (user, password) {
        (Some(user), password) => a.user = Some((user, password.unwrap_or_default())),
        (None, Some(_)) => {
            return Err((
                item.line,
                "websocket: authorization: password without user".into(),
            ));
        }
        (None, None) => {}
    }
    Ok(())
}

/// A port, or -1 for a free one.
fn port(item: &Item) -> Option<i64> {
    match item.value {
        Value::Int(n) if (-1..=65_535).contains(&n) => Some(n),
        _ => None,
    }
}

/// A string or an array of them.
fn strings(item: &Item) -> Option<Vec<String>> {
    match &item.value {
        Value::Str(s) => Some(vec![s.clone()]),
        Value::Array(a) => a.iter().map(string).collect(),
        _ => None,
    }
}

/// A map of header names to values.
fn headers(item: &Item) -> Option<Vec<(String, String)>> {
    let Value::Map(m) = &item.value else {
        return None;
    };
    m.iter()
        .map(|(k, v)| Some((k.clone(), string(v)?)))
        .collect()
}
