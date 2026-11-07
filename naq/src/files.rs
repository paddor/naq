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
    whole(path, std::process::id().to_string().as_bytes())
}

/// Writes `bytes` to `path` whole: to a file beside it, then renamed, so
/// that a reader finds none or all of it. Readable by the owner alone.
fn whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut beside = path.as_os_str().to_owned();
    beside.push(format!(".{}.tmp", std::process::id()));
    let beside = PathBuf::from(beside);
    let mut o = std::fs::OpenOptions::new();
    o.create(true).write(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let written = o.open(&beside).and_then(|mut f| f.write_all(bytes));
    match written.and_then(|()| std::fs::rename(&beside, path)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&beside);
            Err(e)
        }
    }
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
    whole(&path, ports_json(opts, at).to_string().as_bytes())?;
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
    fn a_file_is_written_whole_or_not_at_all() {
        let dir = std::env::temp_dir().join(format!("naq-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("taken/inside")).unwrap();
        let p = dir.join("naq.pid");
        pid(&p).unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            std::process::id().to_string()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // A directory in the way: nothing is left beside it.
        assert!(pid(&dir.join("taken")).is_err());
        assert!(pid(&dir.join("none/naq.pid")).is_err());
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 2, "{left:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
