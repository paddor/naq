//! The files a server writes of itself: its process ID, and where it
//! listens.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::Options;
use crate::log::banner::Bound;

/// Writes the process ID to `path`, as `nats-server` does: no newline,
/// readable by the owner alone.
pub(crate) fn pid(path: &Path) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).write(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)?
        .write_all(std::process::id().to_string().as_bytes())
}

/// Writes where the server bound at `at` listens to a file in `dir`, as
/// `nats-server` names it: the program's name, then the process ID.
/// Returns the file.
pub(crate) fn ports(dir: &Path, opts: &Options, at: &Bound) -> std::io::Result<PathBuf> {
    let program = std::env::args_os()
        .next()
        .map(PathBuf::from)
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "naq".into());
    let path = dir.join(format!("{program}_{}.ports", std::process::id()));
    std::fs::write(&path, ports_json(opts, at).to_string())?;
    Ok(path)
}

/// The URLs of `at`, by kind, as `nats-server` writes its ports file.
fn ports_json(opts: &Options, at: &Bound) -> serde_json::Value {
    let url = |scheme: &str, host: &str, a: SocketAddr| {
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        serde_json::json!([format!("{scheme}://{host}:{}", a.port())])
    };
    let mut m = serde_json::Map::new();
    let scheme = if opts.tls.is_some() { "tls" } else { "nats" };
    m.insert("nats".into(), url(scheme, &opts.host, at.client));
    if let Some(a) = at.monitor {
        let host = opts.http_host.as_deref().unwrap_or(&opts.host);
        let scheme = if opts.https_port.is_some() {
            "https"
        } else {
            "http"
        };
        m.insert("monitoring".into(), url(scheme, host, a));
    }
    if let (Some(a), Some(c)) = (at.cluster, &opts.cluster) {
        m.insert("cluster".into(), url("nats", &c.host, a));
    }
    if let (Some(a), Some(w)) = (at.websocket, &opts.websocket) {
        let scheme = if w.tls.is_some() { "wss" } else { "ws" };
        m.insert("websocket".into(), url(scheme, &w.host, a));
    }
    serde_json::Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ports_file_names_each_listener_by_its_kind() {
        let at = Bound {
            client: "127.0.0.1:4222".parse().unwrap(),
            monitor: Some("127.0.0.1:8222".parse().unwrap()),
            websocket: None,
            leafnodes: None,
            cluster: None,
        };
        let o = Options {
            host: "::1".into(),
            ..Options::default()
        };
        assert_eq!(
            ports_json(&o, &at).to_string(),
            r#"{"monitoring":["http://[::1]:8222"],"nats":["nats://[::1]:4222"]}"#
        );
        let o = Options {
            https_port: Some(0),
            http_host: Some("127.0.0.1".into()),
            ..o
        };
        assert!(
            ports_json(&o, &at)
                .to_string()
                .contains(r#""monitoring":["https://127.0.0.1:8222"]"#)
        );
    }
}
