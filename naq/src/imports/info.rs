//! `Nats-Request-Info`: who sent a request through a service import, as
//! `nats-server` tells the service.

use serde::{Deserialize, Serialize};

/// The header a request through a service import carries.
pub(crate) const HEADER: &[u8] = b"Nats-Request-Info";

/// The requester, as `nats-server`'s `ClientInfo` has it: every field left
/// out when empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClientInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) start: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) host: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) id: u64,
    #[serde(default, rename = "acc", skip_serializing_if = "String::is_empty")]
    pub(crate) account: String,
    #[serde(default, rename = "svc", skip_serializing_if = "String::is_empty")]
    pub(crate) service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) lang: String,
    #[serde(default, rename = "ver", skip_serializing_if = "String::is_empty")]
    pub(crate) version: String,
    /// In nanoseconds.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) rtt: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) cluster: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) client_type: String,
    /// Fields naq does not fill, kept as they came.
    #[serde(flatten)]
    pub(crate) rest: serde_json::Map<String, serde_json::Value>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde passes a reference"
)]
const fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// The value of header `key` in header block `headers`, if it has it.
pub(crate) fn header<'h>(headers: &'h [u8], key: &[u8]) -> Option<&'h [u8]> {
    lines(headers).find_map(|l| value(l, key))
}

/// The value of line `l` if it is header `key`.
fn value<'l>(l: &'l [u8], key: &[u8]) -> Option<&'l [u8]> {
    let rest = l.strip_prefix(key)?.strip_prefix(b":")?;
    Some(rest.trim_ascii())
}

/// The header lines of `headers`, past the status line, up to the blank
/// one.
fn lines(headers: &[u8]) -> impl Iterator<Item = &[u8]> {
    headers
        .split(|&b| b == b'\n')
        .skip(1)
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .take_while(|l| !l.is_empty())
}

/// Writes `headers`, or a fresh header block, into `out` with header
/// `key` set to `value`: the old line dropped, the new one last, as
/// `nats-server` sets it.
pub(crate) fn set(headers: Option<&[u8]>, key: &[u8], value: &[u8], out: &mut Vec<u8>) {
    match headers {
        Some(h) => {
            let status = h.split(|&b| b == b'\n').next().unwrap_or_default();
            out.extend_from_slice(status.strip_suffix(b"\r").unwrap_or(status));
            out.extend_from_slice(b"\r\n");
            for l in lines(h).filter(|l| self::value(l, key).is_none()) {
                out.extend_from_slice(l);
                out.extend_from_slice(b"\r\n");
            }
        }
        None => out.extend_from_slice(b"NATS/1.0\r\n"),
    }
    out.extend_from_slice(key);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_set_goes_last_and_replaces_the_old_one() {
        let mut out = Vec::new();
        set(None, HEADER, b"{}", &mut out);
        assert_eq!(out, b"NATS/1.0\r\nNats-Request-Info: {}\r\n\r\n");
        out.clear();
        let h = b"NATS/1.0 503\r\nNats-Request-Info: {\"acc\":\"evil\"}\r\nX-A: 1\r\n\r\n";
        set(Some(h), HEADER, b"{\"acc\":\"A\"}", &mut out);
        assert_eq!(
            out,
            b"NATS/1.0 503\r\nX-A: 1\r\nNats-Request-Info: {\"acc\":\"A\"}\r\n\r\n"
        );
        assert_eq!(header(&out, HEADER), Some(&b"{\"acc\":\"A\"}"[..]));
        assert_eq!(header(&out, b"X-B"), None);
    }

    #[test]
    fn client_info_leaves_out_what_is_empty_and_keeps_what_it_does_not_know() {
        let ci = ClientInfo {
            account: "A".into(),
            rtt: 405_721,
            ..ClientInfo::default()
        };
        assert_eq!(
            serde_json::to_string(&ci).unwrap(),
            r#"{"acc":"A","rtt":405721}"#
        );
        let back: ClientInfo =
            serde_json::from_str(r#"{"acc":"A","svc":"B","jwt":"x","rtt":7}"#).unwrap();
        assert_eq!((back.service.as_str(), back.rtt), ("B", 7));
        assert_eq!(
            serde_json::to_string(&back).unwrap(),
            r#"{"acc":"A","svc":"B","rtt":7,"jwt":"x"}"#
        );
    }
}
