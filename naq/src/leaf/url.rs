//! The URLs of a hub.

/// The port of a hub URL without one, as in `nats-server`.
const PORT: u16 = 7422;

/// A hub to dial, and the credentials its URL holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HubUrl {
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The user, or the token if there is no password.
    pub(crate) user: Option<String>,
    pub(crate) pass: Option<String>,
    /// Over WebSocket (`ws://`, `wss://`): the URL's path.
    pub(crate) ws: Option<String>,
    /// TLS from the start (`wss://`).
    pub(crate) wss: bool,
    /// A naq hub, over OMQ (`naq://`).
    pub(crate) naq: bool,
}

impl HubUrl {
    /// Reads `nats-leaf://`, `nats://`, `ws://`, `wss://`, `naq://` or a
    /// bare `host:port`, with `user:password@` or `token@` before the host.
    /// A path is kept for WebSocket only.
    pub(crate) fn parse(s: &str) -> Result<HubUrl, String> {
        let s = s.trim();
        let bad = |why: &str| format!("leafnode url {s:?}: {why}");
        let (scheme, rest) = match s.split_once("://") {
            Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
            None => (String::new(), s),
        };
        if !["", "nats-leaf", "nats", "ws", "wss", "naq"].contains(&scheme.as_str()) {
            return Err(bad("scheme not supported"));
        }
        let (rest, path) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
        let path = path.split(['?', '#']).next().unwrap_or_default();
        let (userinfo, hostport) = match rest.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, rest),
        };
        let (host, port) = host_port(hostport).ok_or_else(|| bad("expected host:port"))?;
        let (user, pass) = match userinfo.map(|u| u.split_once(':').unwrap_or((u, ""))) {
            Some((u, p)) => {
                let user = decode(u).ok_or_else(|| bad("bad user"))?;
                let pass = decode(p).ok_or_else(|| bad("bad password"))?;
                (Some(user), (!p.is_empty()).then_some(pass))
            }
            None => (None, None),
        };
        Ok(HubUrl {
            host,
            port,
            user: user.filter(|u| !u.is_empty()),
            pass,
            ws: scheme.starts_with("ws").then(|| path.to_owned()),
            wss: scheme == "wss",
            naq: scheme == "naq",
        })
    }
}

/// The URLs to dial after a hub told of `found`, `host:port` each: those
/// but the ones configured already, then the `configured` ones, as
/// `nats-server` orders them. Found ones take the scheme of the configured
/// ones and the credentials of the first configured URL with some.
pub(crate) fn rebuild(found: &[String], configured: &[HubUrl]) -> Vec<HubUrl> {
    let scheme = match configured.first().map(|u| u.ws.is_some()) {
        Some(true) if configured.iter().any(|u| u.wss) => "wss",
        Some(true) => "ws",
        _ => "nats-leaf",
    };
    let creds = configured.iter().find(|u| u.user.is_some());
    let mut urls: Vec<HubUrl> = found
        .iter()
        .filter_map(|f| HubUrl::parse(&format!("{scheme}://{f}")).ok())
        .filter(|f| {
            !configured
                .iter()
                .any(|c| c.host == f.host && c.port == f.port)
        })
        .map(|mut f| {
            if let Some(c) = creds {
                f.user.clone_from(&c.user);
                f.pass.clone_from(&c.pass);
            }
            f
        })
        .collect();
    urls.extend_from_slice(configured);
    urls
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`.
fn host_port(s: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(v6) = s.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        match after {
            "" => (host, None),
            p => (host, Some(p.strip_prefix(':')?)),
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(p) => p.parse().ok()?,
        None => PORT,
    };
    Some((host.to_owned(), port))
}

/// `s` with `%XX` escapes decoded, as UTF-8.
fn decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hex = [bytes.next()?, bytes.next()?];
            out.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(host: &str, port: u16, user: Option<&str>, pass: Option<&str>) -> HubUrl {
        HubUrl {
            host: host.into(),
            port,
            user: user.map(Into::into),
            pass: pass.map(Into::into),
            ws: None,
            wss: false,
            naq: false,
        }
    }

    #[test]
    fn hub_urls_give_where_and_who() {
        for (s, want) in [
            ("nats-leaf://hub:7000", url("hub", 7000, None, None)),
            (
                "nats://u:p%40ss@hub",
                url("hub", 7422, Some("u"), Some("p@ss")),
            ),
            ("tok@10.0.0.1:1/x", url("10.0.0.1", 1, Some("tok"), None)),
            ("NATS-LEAF://[::1]:9", url("::1", 9, None, None)),
            ("[::1]", url("::1", 7422, None, None)),
            (" hub ", url("hub", 7422, None, None)),
            ("nats://hub/x?y#z", url("hub", 7422, None, None)),
        ] {
            assert_eq!(HubUrl::parse(s), Ok(want), "{s}");
        }
        let ws = HubUrl::parse("ws://u@hub:80/a/b?q").unwrap();
        assert_eq!(
            (ws.ws.as_deref(), ws.wss, ws.port),
            (Some("/a/b"), false, 80)
        );
        assert_eq!(ws.user.as_deref(), Some("u"));
        let wss = HubUrl::parse("WSS://hub").unwrap();
        assert_eq!((wss.ws.as_deref(), wss.wss), (Some(""), true));
        let naq = HubUrl::parse("naq://hub:9").unwrap();
        assert_eq!((naq.naq, naq.port, naq.ws.as_deref()), (true, 9, None));
    }

    #[test]
    fn urls_a_hub_tells_of_come_first_with_the_credentials_configured() {
        let configured = [
            HubUrl::parse("nats://h1:1").unwrap(),
            HubUrl::parse("nats://u:p@h2:2").unwrap(),
        ];
        let found = ["h3:3".to_owned(), "h1:1".to_owned(), "bad:x".to_owned()];
        let urls = rebuild(&found, &configured);
        assert_eq!(urls[0], url("h3", 3, Some("u"), Some("p")));
        assert_eq!(&urls[1..], &configured);
        let ws = [HubUrl::parse("wss://h1").unwrap()];
        let urls = rebuild(&["h4:4".to_owned()], &ws);
        assert_eq!((urls[0].ws.as_deref(), urls[0].wss), (Some(""), true));
        assert_eq!(rebuild(&[], &ws), ws);
    }

    #[test]
    fn urls_naq_cannot_dial_are_an_error() {
        for (s, why) in [
            ("http://hub", "scheme not supported"),
            ("nats://", "expected host:port"),
            ("hub:x", "expected host:port"),
            ("hub:70000", "expected host:port"),
            ("[::1", "expected host:port"),
            ("[::1]9", "expected host:port"),
            ("u%zz@hub", "bad user"),
            ("u:%@hub", "bad password"),
            ("u:%ff@hub", "bad password"),
        ] {
            let e = HubUrl::parse(s).unwrap_err();
            assert_eq!(e, format!("leafnode url {:?}: {why}", s.trim()), "{s}");
        }
    }
}
