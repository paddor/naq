//! Options from `nats-server` configuration files.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::path::PathBuf;
use std::time::Duration;

use naq::{Error, Options};

/// A directory of its own for test `name`.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("naq-config-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_file_sets_what_it_names_and_leaves_the_rest() {
    let d = dir("file");
    std::fs::write(d.join("limits.conf"), "max_pending: 2MB\nping_max: 5\n").unwrap();
    let path = d.join("server.conf");
    std::fs::write(
        &path,
        "# A server.\nlisten: 127.0.0.1:4333\nserver_name: edge\nmax_payload = 64KB\n\
         MAX_CONTROL_LINE 512\nping_interval: \"30s\"\nwrite_deadline: 2\ndebug: true\n\
         include limits.conf\n",
    )
    .unwrap();
    let o = Options::from_file(&path).unwrap();
    assert_eq!(
        o,
        Options {
            host: "127.0.0.1".into(),
            port: 4333,
            server_name: "edge".into(),
            max_payload: 64 << 10,
            max_control_line: 512,
            max_pending: 2 << 20,
            ping_interval: Duration::from_secs(30),
            max_pings_out: 5,
            write_deadline: Duration::from_secs(2),
            ..Options::default()
        }
    );
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn text_parses_as_options() {
    let o: Options = "host: ::1\nport: 4444\nlisten: :4555\n".parse().unwrap();
    assert_eq!((o.host.as_str(), o.port), ("::1", 4555));
}

#[test]
fn what_naq_cannot_use_is_an_error_with_its_line() {
    for (text, at, reason) in [
        ("port: 1\ncluster {}\n", "line 2", "cluster: not supported"),
        ("port: x\n", "line 1", "port: expected a port"),
        ("port: 70000\n", "line 1", "port: expected a port"),
        (
            "max_payload: -1\n",
            "line 1",
            "max_payload: expected a size",
        ),
        (
            "max_payload: 4GB\n",
            "line 1",
            "max_payload: expected a size",
        ),
        (
            "server_name: \"a b\"\n",
            "line 1",
            "server_name: server name cannot contain spaces",
        ),
        (
            "ping_interval: \"2x\"\n",
            "line 1",
            "ping_interval: bad duration \"2x\"",
        ),
        (
            "write_deadline: true\n",
            "line 1",
            "write_deadline: expected a duration",
        ),
        (
            "write_deadline: -1\n",
            "line 1",
            "write_deadline: expected a duration",
        ),
        ("listen: nohost\n", "line 1", "listen: expected host:port"),
        ("host: 1\n", "line 1", "host: expected a string"),
        (
            "server_name: 1\n",
            "line 1",
            "server_name: expected a string",
        ),
        ("a: [\n", "line 2", "unexpected end, `]` missing"),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { at: a, reason: r }) => {
                assert_eq!((a.as_str(), r.as_str()), (at, reason), "{text:?}");
            }
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

#[test]
fn errors_name_the_file() {
    let d = dir("errors");
    let path = d.join("bad.conf");
    std::fs::write(&path, "\n\nbogus: 1\n").unwrap();
    let e = Options::from_file(&path).unwrap_err();
    assert_eq!(
        e.to_string(),
        format!("{}:3: bogus: not supported", path.display())
    );
    let missing = d.join("missing.conf");
    let e = Options::from_file(&missing).unwrap_err();
    assert!(matches!(e, Error::Read { .. }), "{e:?}");
    assert!(std::error::Error::source(&e).is_some());
    std::fs::remove_dir_all(&d).unwrap();
}
