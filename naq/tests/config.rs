//! Options from `nats-server` configuration files.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::path::PathBuf;
use std::time::Duration;

use naq::{Error, LogTo, Logging, Options, Trace, WebsocketAuth};

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
            log: Logging {
                debug: true,
                ..Logging::default()
            },
            config_file: Some(path.clone()),
            ..Options::default()
        }
    );
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn log_keys_set_what_and_where_the_server_logs() {
    let o: Options = "debug: true\ntrace_verbose: true\nlogtime: false\nlogtime_utc: true\n\
                      syslog: true\nlog_file: \"/var/log/naq.log\"\nlog_size_limit: 1MB\n\
                      log_max_num: 3\nmax_traced_msg_len: 64\n"
        .parse()
        .unwrap();
    assert_eq!(
        o.log,
        Logging {
            to: Some(LogTo::File("/var/log/naq.log".into())),
            debug: true,
            trace: Trace::On,
            time: false,
            size_limit: 1 << 20,
            max_files: 3,
            max_traced: 64,
        }
    );
    let o: Options = "remote_syslog: \"udp://h:514\"\nsyslog: true\ntrace_headers: true\n"
        .parse()
        .unwrap();
    assert_eq!(o.log.to, Some(LogTo::RemoteSyslog("udp://h:514".into())));
    assert_eq!(o.log.trace, Trace::Headers);
    let e = "debug: 1\n".parse::<Options>().unwrap_err();
    assert_eq!(e.to_string(), "line 1: debug: expected true or false");
}

#[test]
fn text_parses_as_options() {
    let o: Options = "host: ::1\nport: 4444\nlisten: :4555\n".parse().unwrap();
    assert_eq!((o.host.as_str(), o.port), ("::1", 4555));
}

#[test]
fn what_naq_cannot_use_is_an_error_with_its_line() {
    for (text, at, reason) in [
        ("port: 1\ngateway {}\n", "line 2", "gateway: not supported"),
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

#[test]
fn users_tokens_and_accounts_come_from_their_blocks() {
    let o: Options = "authorization {\n  timeout: 0.5\n  users: [{user: v, pass: q}]\n}\n\
                      accounts {\n  A { users: [{username: a, password: x}] }\n  B {}\n}\n\
                      no_auth_user: a\n"
        .parse()
        .unwrap();
    assert_eq!(names(&o), ["A", "B"]);
    assert_eq!(o.auth_timeout, Duration::from_millis(500));
    assert_eq!(o.no_auth_user.as_deref(), Some("a"));
    let users: Vec<_> = o
        .users
        .iter()
        .map(|u| {
            let naq::Login::Password { user, password } = &u.login else {
                panic!("{u:?}")
            };
            (user.as_str(), password.as_str(), u.account.as_deref())
        })
        .collect();
    assert_eq!(users, [("v", "q", None), ("a", "x", Some("A"))]);
    let typed: Options =
        "authorization { users: [{user: w, clients: [websocket, Leafnode_WS, mqtt_ws, in_process]}] }\n"
            .parse()
            .unwrap();
    let kinds = &typed.users[0].connection_types;
    let named: Vec<String> = kinds.iter().map(ToString::to_string).collect();
    assert_eq!(named, ["WEBSOCKET", "LEAFNODE_WS", "MQTT_WS", "IN_PROCESS"]);
    let one: Options = "authorization { user: u, password: p }\n".parse().unwrap();
    assert_eq!(one.user, Some(("u".into(), "p".into())));
    assert_eq!(one.users.len(), 0);
    let t: Options = "authorization { token: abc, timeout: \"3s\" }\naccounts [X, Y]\n"
        .parse()
        .unwrap();
    assert_eq!(t.token.as_deref(), Some("abc"));
    assert_eq!(t.auth_timeout, Duration::from_secs(3));
    assert_eq!(names(&t), ["X", "Y"]);
}

#[test]
fn users_lists_naq_cannot_read_are_an_error() {
    for (text, reason) in [
        (
            "authorization { users: [{nkey: UABC}] }\n",
            "users: nkey: not a public user NKey",
        ),
        (
            "authorization { users: [{password: p}] }\n",
            "users: a user needs a name",
        ),
        (
            "authorization { users: [{nkey: UDDERIQLR7DRZ5U2RYQVMHORTX3VOIBJNN7PBBMML2L4TIQKHZDVQERZ, user: x}] }\n",
            "users: an NKey user has no name or password",
        ),
        ("authorization { users: 1 }\n", "users: expected a list"),
        (
            "authorization { users: [{user: a, allowed_connection_types: 1}] }\n",
            "users: allowed_connection_types: expected strings",
        ),
        ("authorization { users: [1] }\n", "users: expected a map"),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

#[test]
fn auth_that_contradicts_itself_is_an_error() {
    for (text, reason) in [
        (
            "authorization { token: t, users: [{user: a}] }\n",
            "a token cannot go with users",
        ),
        (
            "authorization { user: u, users: [{user: a}] }\n",
            "a single user cannot go with users",
        ),
        (
            "authorization { user: u }\naccounts { A { users: [{user: a}] } }\n",
            "a single user cannot go with users",
        ),
        (
            "authorization { user: u, token: t }\n",
            "a token cannot go with a user",
        ),
        (
            "authorization { user: u }\nno_auth_user: u\n",
            "no_auth_user \"u\" is not a user",
        ),
        (
            "no_auth_user: nobody\n",
            "no_auth_user \"nobody\" is not a user",
        ),
        (
            "authorization { users: [{user: a}, {user: a}] }\n",
            "user \"a\" twice",
        ),
        (
            "authorization { password: p }\n",
            "authorization: password without user",
        ),
        (
            "authorization { bogus: 1 }\n",
            "authorization: bogus: not supported",
        ),
        (
            "authorization { timeout: true }\n",
            "authorization: timeout: expected seconds or a duration",
        ),
        ("authorization: 1\n", "authorization: expected a map"),
        (
            "accounts { $G {} }\n",
            "accounts: \"$G\" is a reserved account",
        ),
        ("accounts [A, A]\n", "accounts: \"A\" twice"),
        (
            "accounts { A { mappings: {} } }\n",
            "accounts: A: mappings: not supported",
        ),
        ("accounts [1]\n", "accounts: expected names"),
        ("accounts: 1\n", "accounts: expected a map or a list"),
        ("accounts { A: 1 }\n", "accounts: expected a map"),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

#[test]
fn a_server_refuses_options_that_contradict_themselves() {
    let o = Options {
        token: Some("t".into()),
        no_auth_user: Some("x".into()),
        ..Options::default()
    };
    assert!(matches!(naq::Server::start(&o), Err(Error::Options(_))));
}

#[test]
fn nkey_users_come_from_the_users_list() {
    let key = "UDDERIQLR7DRZ5U2RYQVMHORTX3VOIBJNN7PBBMML2L4TIQKHZDVQERZ";
    let o: Options = format!("authorization {{ users: [{{nkey: {key}}}] }}\nno_auth_user: {key}\n")
        .parse()
        .unwrap();
    assert_eq!(o.users[0].login, naq::Login::Nkey(key.into()));
}

#[test]
fn permissions_come_in_every_form_nats_server_takes() {
    let opts: Options = "authorization {\n  default_permissions: {publish: [a, b], subscribe: {deny: c}}\n  users: [\n    \
                         {user: u, permissions: {pub: {allow: \"x.>\", deny: [x.y]}, sub: \"q w\", allow_responses: {max: 3, expires: \"5s\"}}}\n    \
                         {user: v, permissions: {allow_responses: true}}\n  ]\n}\n"
        .parse()
        .unwrap();
    let defaults = opts.default_permissions.unwrap();
    assert_eq!(
        defaults.publish.allow.as_deref(),
        Some(&["a".to_owned(), "b".to_owned()][..])
    );
    assert_eq!(defaults.subscribe.allow, None);
    assert_eq!(defaults.subscribe.deny, ["c"]);
    let first = opts.users[0].permissions.clone().unwrap();
    assert_eq!(
        first.publish.allow.as_deref(),
        Some(&["x.>".to_owned()][..])
    );
    assert_eq!(first.publish.deny, ["x.y"]);
    assert_eq!(
        first.subscribe.allow.as_deref(),
        Some(&["q w".to_owned()][..])
    );
    assert_eq!(
        first.responses,
        Some(naq::Responses {
            max: 3,
            expires: Duration::from_secs(5)
        })
    );
    let second = opts.users[1].permissions.clone().unwrap();
    assert_eq!(second.responses, Some(naq::Responses::default()));
    let off: Options =
        "authorization { users: [{user: a, permissions: {allow_responses: false}}] }\n"
            .parse()
            .unwrap();
    assert_eq!(off.users[0].permissions.clone().unwrap().responses, None);
}

#[test]
fn permissions_naq_cannot_use_are_an_error() {
    for (perms, reason) in [
        ("{bogus: 1}", "permissions: bogus: not supported"),
        ("{publish: {only: x}}", "permissions: only: not supported"),
        ("{publish: [1]}", "permissions: expected subjects"),
        ("{publish: \"a..b\"}", "permissions: bad subject \"a..b\""),
        (
            "{allow_responses: 1}",
            "allow_responses: expected a boolean or a map",
        ),
        (
            "{allow_responses: {max: x}}",
            "allow_responses: max: expected a count",
        ),
        (
            "{allow_responses: {expires: 5}}",
            "allow_responses: expires: expected a duration",
        ),
        (
            "{allow_responses: {bad: 5}}",
            "allow_responses: bad: not supported",
        ),
        ("1", "permissions: expected a map"),
    ] {
        let text = format!("authorization {{ users: [{{user: a, permissions: {perms}}}] }}\n");
        match text.parse::<Options>() {
            Err(Error::Config { reason: got, .. }) => assert_eq!(got, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

#[test]
fn monitoring_takes_a_port_or_a_host_and_port() {
    let o: Options = "http_port: 8222\n".parse().unwrap();
    assert_eq!((o.http_port, o.http_host), (Some(8222), None));
    let o: Options = "monitor_port: 8333\n".parse().unwrap();
    assert_eq!(o.http_port, Some(8333));
    let o: Options = "http: 127.0.0.1:8444\n".parse().unwrap();
    assert_eq!(
        (o.http_port, o.http_host.as_deref()),
        (Some(8444), Some("127.0.0.1"))
    );
    assert!("http: nope\n".parse::<Options>().is_err());
    // As in nats-server: -1 picks a free port, 0 serves none.
    let port = |text: &str| text.parse::<Options>().unwrap();
    assert_eq!(port("http_port: -1\n").http_port, Some(0));
    assert_eq!(port("http_port: 0\n").http_port, None);
    assert_eq!(port("http: \"127.0.0.1:-1\"\n").http_port, Some(0));
    let o = port("https: \"[::1]:8443\"\nhttp_base_path: mon\n");
    assert_eq!(
        (
            o.https_port,
            o.http_host.as_deref(),
            o.http_base_path.as_str()
        ),
        (Some(8443), Some("::1"), "mon")
    );
    assert_eq!(port("https_port: 8443\n").https_port, Some(8443));
    assert_eq!(port("http: 8222\n").http_port, Some(8222));
    for bad in [
        "http_port: 70000\n",
        "https_port: x\n",
        "https: \"h:x\"\n",
        "https: true\n",
        "http_base_path: 1\n",
    ] {
        assert!(bad.parse::<Options>().is_err(), "{bad:?}");
    }
}

#[test]
fn the_websocket_block_sets_its_own_port() {
    let o: Options = "websocket {\n  listen: 127.0.0.1:8080\n  no_tls: true\n  same_origin: true\n  \
                      allowed_origins: http://a.example\n  handshake_timeout: \"5s\"\n  compression: true\n  \
                      headers { X-Frame-Options: DENY }\n  ping_interval: 30\n  user_cookie: u\n  \
                      pass_cookie: p\n  token_cookie: t\n}\n"
        .parse()
        .unwrap();
    let w = o.websocket.unwrap();
    assert_eq!(
        w,
        naq::Websocket {
            host: "127.0.0.1".into(),
            port: 8080,
            no_tls: true,
            same_origin: true,
            allowed_origins: vec!["http://a.example".into()],
            handshake_timeout: Duration::from_secs(5),
            compression: true,
            headers: vec![("X-Frame-Options".into(), "DENY".into())],
            ping_interval: Some(Duration::from_secs(30)),
            cookies: naq::Cookies {
                user: Some("u".into()),
                pass: Some("p".into()),
                token: Some("t".into()),
            },
            ..naq::Websocket::default()
        }
    );
    let o: Options = "ws { port: -1, no_tls: true, origins: [\"https://b\"] }\n"
        .parse()
        .unwrap();
    let w = o.websocket.unwrap();
    assert_eq!((w.host.as_str(), w.port), ("0.0.0.0", 0));
    assert_eq!(w.allowed_origins, ["https://b"]);
    let o: Options = "websocket { no_tls: true }\n".parse().unwrap();
    assert_eq!(o.websocket, None, "no port, no websocket");
    let o: Options = "websocket { port: 0, no_tls: true }\n".parse().unwrap();
    assert_eq!(o.websocket, None);
}

#[test]
fn websocket_clients_may_have_credentials_of_their_own() {
    let o: Options = "authorization { users [ {user: a, password: b} ] }\n\
        websocket {\n  port: 1\n  no_tls: true\n  advertise: \"ws.example:443\"\n  \
        no_auth_user: a\n  authorization { timeout: 0.5 }\n}\n"
        .parse()
        .unwrap();
    let want = WebsocketAuth {
        no_auth_user: Some("a".into()),
        timeout: Some(Duration::from_millis(500)),
        ..WebsocketAuth::default()
    };
    assert_eq!(o.websocket.unwrap().auth, want);
    let o: Options =
        "websocket { port: 1, no_tls: true, authentication { username: u, pass: p, timeout: 0 } }"
            .parse()
            .unwrap();
    let want = WebsocketAuth {
        user: Some(("u".into(), "p".into())),
        ..WebsocketAuth::default()
    };
    assert_eq!(o.websocket.unwrap().auth, want);
    let o: Options = "websocket { port: 1, no_tls: true, authorization { user: u } }"
        .parse()
        .unwrap();
    assert_eq!(
        o.websocket.unwrap().auth.user,
        Some(("u".into(), String::new()))
    );
}

#[test]
fn websocket_settings_that_cannot_run_are_an_error() {
    for (text, reason) in [
        (
            "websocket { port: 1 }",
            "websocket requires TLS configuration",
        ),
        (
            "websocket { port: 1, no_tls: true, allowed_origins: [\"ftp://x\"] }",
            "unable to parse allowed origin \"ftp://x\": allowed origins must be absolute URLs with http or https scheme",
        ),
        (
            "websocket { port: 1, no_tls: true, headers { Upgrade: x } }",
            "websocket: invalid header \"Upgrade\" not allowed",
        ),
        (
            "websocket { port: 1, no_tls: true, authorization { user: u, token: t } }",
            "websocket: a token cannot go with a user",
        ),
        (
            "authorization { users [ {user: a, password: b} ] }\n\
             websocket { port: 1, no_tls: true, no_auth_user: a, authorization { token: t } }",
            "websocket: no_auth_user cannot go with a user or token of its own",
        ),
        (
            "websocket { port: 1, no_tls: true, no_auth_user: x }",
            "websocket: no_auth_user \"x\" is not a user",
        ),
    ] {
        let e = text.parse::<Options>().unwrap_err();
        assert!(
            matches!(&e, Error::Config { reason: r, .. } if r == reason),
            "{text}: {e}"
        );
    }
}

#[test]
fn websocket_credentials_naq_cannot_use_are_an_error() {
    for (text, reason) in [
        (
            "websocket { port: 1, no_tls: true, jwt_cookie: j }",
            "websocket: jwt_cookie: trusted operators or trusted keys configuration is required for JWT authentication via cookie \"j\"",
        ),
        (
            "websocket { port: 1, no_tls: true, advertise: 1 }",
            "websocket: advertise: expected a string",
        ),
        (
            "websocket { port: 1, no_tls: true, authorization: 1 }",
            "websocket: authorization: expected a map",
        ),
        (
            "websocket { port: 1, no_tls: true, authorization { pass: p } }",
            "websocket: authorization: password without user",
        ),
        (
            "websocket { port: 1, no_tls: true, authorization { users: [] } }",
            "websocket: authorization: users: not supported",
        ),
        (
            "websocket { port: 1, no_tls: true, authorization { timeout: x } }",
            "websocket: authorization: timeout: expected seconds or a duration",
        ),
        (
            "websocket { port: 1, no_tls: true, authorization { token: 1 } }",
            "websocket: authorization: token: expected a string",
        ),
    ] {
        let e = text.parse::<Options>().unwrap_err();
        assert!(
            matches!(&e, Error::Config { reason: r, .. } if r == reason),
            "{text}: {e}"
        );
    }
}

#[test]
fn websocket_settings_naq_cannot_use_are_an_error() {
    for (text, reason) in [
        (
            "websocket { port: 1, no_tls: true, bogus: 1 }",
            "websocket: bogus: not supported",
        ),
        (
            "websocket { port: 70000 }",
            "websocket: port: expected a port",
        ),
        (
            "websocket { port: 1, no_tls: 1 }",
            "websocket: no_tls: expected true or false",
        ),
        (
            "websocket { port: 1, headers: 1 }",
            "websocket: headers: expected a map of strings",
        ),
        (
            "websocket { port: 1, origins: 1 }",
            "websocket: origins: expected strings",
        ),
        (
            "websocket { port: 1, ping_interval: x }",
            "websocket: ping_interval: bad duration \"x\"",
        ),
        (
            "websocket { port: 1, user_cookie: 1 }",
            "websocket: user_cookie: expected a string",
        ),
        (
            "websocket { port: 1, listen: x }",
            "websocket: listen: expected host:port",
        ),
        ("websocket: 1", "websocket: expected a map"),
    ] {
        let e = text.parse::<Options>().unwrap_err();
        assert!(
            matches!(&e, Error::Config { reason: r, .. } if r == reason),
            "{text}: {e}"
        );
    }
}

/// A user NKey seed.
const SEED: &str = "SUABXPISJ672XCVCU7XD7CVTTXYTBXTGZ4LX3WZCSLCPKHDPCXCLZVMVPI";

/// A public user NKey.
const KEY: &str = "UDDERIQLR7DRZ5U2RYQVMHORTX3VOIBJNN7PBBMML2L4TIQKHZDVQERZ";

#[test]
fn remotes_come_from_the_leafnodes_block() {
    let o: Options = "accounts [A]\nleafnodes {\n  reconnect: 2\n  remotes [\n    \
                      { url: \"nats-leaf://h:1\", account: A, no_randomize: true }\n    \
                      { urls: [\"a\", \"b:2\"], creds: u.creds }\n    \
                      { urls: [\"a\", \"b:2\"], seed: {SEED} }\n  ]\n}\n"
        .replace("{SEED}", SEED)
        .parse()
        .unwrap();
    assert_eq!(o.leaf_reconnect, Duration::from_secs(2));
    assert_eq!(
        o.remotes,
        [
            naq::Remote {
                urls: vec!["nats-leaf://h:1".into()],
                account: Some("A".into()),
                no_randomize: true,
                ..naq::Remote::default()
            },
            naq::Remote {
                urls: vec!["a".into(), "b:2".into()],
                credentials: Some("u.creds".into()),
                ..naq::Remote::default()
            },
            naq::Remote {
                urls: vec!["a".into(), "b:2".into()],
                nkey: Some(SEED.into()),
                ..naq::Remote::default()
            },
        ]
    );
}

#[test]
fn the_port_of_a_hub_comes_from_the_leafnodes_block() {
    let o: Options =
        "accounts [A]\nleafnodes { listen: \"127.0.0.1:7000\", authorization { account: A } }\n"
            .parse()
            .unwrap();
    assert_eq!(
        o.leafnodes,
        Some(naq::Leafnodes {
            host: "127.0.0.1".into(),
            port: 7000,
            account: Some("A".into()),
            ..naq::Leafnodes::default()
        })
    );
    let o: Options = "leafnodes { port: 7001, host: h }".parse().unwrap();
    assert_eq!(
        o.leafnodes,
        Some(naq::Leafnodes {
            host: "h".into(),
            port: 7001,
            account: None,
            ..naq::Leafnodes::default()
        })
    );
    let o: Options = "leafnodes { remotes: [{url: \"naq://h:1\"}] }"
        .parse()
        .unwrap();
    assert_eq!(o.leafnodes, None);
    assert_eq!(o.remotes[0].urls, ["naq://h:1"]);
    let o: Options = "leafnodes { remotes: [{urls: [\"naq://h:1\", \"naq://i:2\"]}] }"
        .parse()
        .unwrap();
    assert_eq!(o.remotes[0].urls, ["naq://h:1", "naq://i:2"]);
}

#[test]
fn naq_leafs_log_in_as_the_leafnodes_block_says() {
    let user = |login, account: Option<&str>| naq::User {
        login,
        account: account.map(Into::into),
        permissions: None,
        connection_types: Vec::new(),
    };
    let password = |u: &str, p: &str| naq::Login::Password {
        user: u.into(),
        password: p.into(),
    };
    let users = |text: &str| {
        let o: Options = format!("accounts [A]\nleafnodes {{ authorization {{ {text} }} }}")
            .parse()
            .unwrap();
        o.leafnodes.unwrap()
    };
    let l = users("user: u, password: p, account: A, timeout: 3");
    assert_eq!(l.users, [user(password("u", "p"), Some("A"))]);
    assert_eq!(l.auth_timeout, std::time::Duration::from_secs(3));
    let l = users(&format!("nkey: {KEY}"));
    assert_eq!(l.users, [user(naq::Login::Nkey(KEY.into()), None)]);
    let l = users("users: [{user: a, password: b, account: A}, {username: c, pass: d}]");
    assert_eq!(
        l.users,
        [
            user(password("a", "b"), Some("A")),
            user(password("c", "d"), None)
        ]
    );
}

#[test]
fn naq_leaf_logins_that_cannot_work_are_an_error() {
    for (text, reason) in [
        (
            "leafnodes { authorization: 1 }",
            "leafnodes: authorization: expected a map",
        ),
        (
            "leafnodes { authorization { user: u, nkey: UDDERIQLR7DRZ5U2RYQVMHORTX3VOIBJNN7PBBMML2L4TIQKHZDVQERZ } }",
            "leafnodes: authorization: a user cannot go with an nkey",
        ),
        (
            "leafnodes { authorization { users: [1] } }",
            "leafnodes: authorization: users: expected maps",
        ),
        (
            "leafnodes { authorization { token: t } }",
            "leafnodes: authorization: token: not supported",
        ),
        (
            "leafnodes { authorization { password: p } }",
            "leafnodes: authorization: password without user",
        ),
        (
            "leafnodes { authorization { nkey: x } }",
            "leafnodes: authorization: nkey: not a public user NKey",
        ),
        (
            "leafnodes { authorization { user: u, users: [{user: v}] } }",
            "leafnodes: authorization: a single user cannot go with users",
        ),
        (
            "leafnodes { authorization { users: [{password: p}] } }",
            "leafnodes: authorization: users: a user without a name",
        ),
        (
            "leafnodes { authorization { users: [{user: u, nkey: k}] } }",
            "leafnodes: authorization: users: nkey: not supported",
        ),
        (
            "leafnodes { authorization { users: [{user: u}, {user: u}] } }",
            "leafnodes: user \"u\" twice",
        ),
        (
            "leafnodes { authorization { users: [{user: u, account: B}] } }",
            "leafnodes: user \"u\": no account \"B\"",
        ),
        (
            "leafnodes { authorization { users: 1 } }",
            "leafnodes: authorization: users: expected a list",
        ),
        (
            "leafnodes { authorization { timeout: x } }",
            "leafnodes: authorization: timeout: expected seconds or a duration",
        ),
    ] {
        config_error(text, reason);
    }
}

#[test]
fn naq_leafs_and_hubs_that_cannot_work_are_an_error() {
    for (text, reason) in [
        ("leafnodes { port: x }", "leafnodes: port: expected a port"),
        (
            "leafnodes { authorization { account: B } }",
            "leafnodes: no account \"B\"",
        ),
        (
            "leafnodes { remotes: [{urls: [\"naq://h\", h]}] }",
            "leafnode remote: naq and other urls mixed",
        ),
        (
            "leafnodes { remotes: [{urls: [h, \"naq://h\"]}] }",
            "leafnode remote: naq and other urls mixed",
        ),
        (
            "leafnodes { remotes: [{url: \"naq://h\", credentials: x.creds}] }",
            "leafnode remote: naq url with options it takes no part of",
        ),
    ] {
        config_error(text, reason);
    }
}

#[test]
fn leafnodes_naq_cannot_use_are_an_error() {
    for (text, reason) in [
        ("leafnodes: 1", "leafnodes: expected a map"),
        (
            "leafnodes { remotes: 1 }",
            "leafnodes: remotes: expected a list",
        ),
        (
            "leafnodes { remotes: [1] }",
            "leafnodes: remotes: expected a map",
        ),
        (
            "leafnodes { remotes: [{bogus: 1}] }",
            "leafnodes: remotes: bogus: not supported",
        ),
        (
            "leafnodes { remotes: [{url: 1}] }",
            "leafnodes: remotes: url: expected a string or a list",
        ),
        (
            "leafnodes { remotes: [{urls: [1]}] }",
            "leafnodes: remotes: urls: expected strings",
        ),
        (
            "leafnodes { remotes: [{url: h, account: 1}] }",
            "leafnodes: remotes: account: expected a string",
        ),
        (
            "leafnodes { remotes: [{url: h, no_randomize: 1}] }",
            "leafnodes: remotes: no_randomize: expected true or false",
        ),
        (
            "leafnodes { reconnect: x }",
            "leafnodes: reconnect: bad duration \"x\"",
        ),
        (
            "leafnodes { remotes: [{}] }",
            "leafnode remote without a url",
        ),
        (
            "leafnodes { remotes: [{url: \"http://h\"}] }",
            "leafnode url \"http://h\": scheme not supported",
        ),
        (
            "leafnodes { remotes: [{urls: [\"ws://h\", h]}] }",
            "leafnode remote: websocket and other urls mixed",
        ),
        (
            "leafnodes { remotes: [{url: h, account: B}] }",
            "leafnode remote: no account \"B\"",
        ),
        (
            "leafnodes { remotes: [{url: h}, {url: \"nats://h:7422\"}] }",
            "leafnode remotes: the same account, urls and credentials twice",
        ),
    ] {
        config_error(text, reason);
    }
}

#[test]
fn remote_credentials_that_cannot_work_are_an_error() {
    for (text, reason) in [
        (
            "leafnodes { remotes: [{url: h, creds: c, nkey: n}] }",
            "leafnode remote: both credentials and an nkey",
        ),
        (
            "leafnodes { remotes: [{url: h, nkey: SUnot}] }",
            "leafnode remote: nkey is not a user seed",
        ),
        (
            "leafnodes { remotes: [{url: h, creds: 1}] }",
            "leafnodes: remotes: creds: expected a string",
        ),
        (
            "leafnodes { remotes: [{url: h, nkey: 1}] }",
            "leafnodes: remotes: nkey: expected a string",
        ),
    ] {
        config_error(text, reason);
    }
}

/// Asserts that `text` is a config error for `reason`.
fn config_error(text: &str, reason: &str) {
    let e = text.parse::<Options>().err();
    assert!(
        matches!(&e, Some(Error::Config { reason: r, .. }) if r == reason),
        "{text:?}: {e:?}"
    );
}

#[test]
fn a_remote_takes_a_tls_block() {
    let o: Options = "leafnodes { remotes: [{ url: h, tls { cert_file: c.pem, key_file: k.pem, \
                      ca_file: ca.pem, timeout: 0.5, handshake_first: true } }] }\n"
        .parse()
        .unwrap();
    assert_eq!(
        o.remotes[0].tls,
        Some(naq::RemoteTls {
            cert_file: Some("c.pem".into()),
            key_file: Some("k.pem".into()),
            ca_file: Some("ca.pem".into()),
            timeout: Duration::from_millis(500),
            handshake_first: true,
        })
    );
    let whole: Options = "leafnodes { remotes: [{ url: h, tls { timeout: 3 } }] }"
        .parse()
        .unwrap();
    assert_eq!(
        whole.remotes[0].tls.as_ref().unwrap().timeout,
        Duration::from_secs(3)
    );
    for (text, reason) in [
        (
            "leafnodes { remotes: [{url: h, tls: 1}] }",
            "leafnodes: remotes: tls: expected a map",
        ),
        (
            "leafnodes { remotes: [{url: h, tls { verify: true }}] }",
            "leafnodes: remotes: tls: verify: not supported",
        ),
        (
            "leafnodes { remotes: [{url: h, tls { ca_file: 1 }}] }",
            "leafnodes: remotes: tls: ca_file: expected a path",
        ),
        (
            "leafnodes { remotes: [{url: h, tls { first: 1 }}] }",
            "leafnodes: remotes: tls: first: expected true or false",
        ),
        (
            "leafnodes { remotes: [{url: h, tls { timeout: -1 }}] }",
            "leafnodes: remotes: tls: timeout: expected seconds",
        ),
        (
            "leafnodes { remotes: [{url: h, tls { timeout: x }}] }",
            "leafnodes: remotes: tls: timeout: bad duration \"x\"",
        ),
    ] {
        config_error(text, reason);
    }
}

#[test]
fn a_remote_tls_file_that_cannot_be_read_stops_the_start() {
    let o = Options {
        port: 0,
        remotes: vec![naq::Remote {
            urls: vec!["h".into()],
            tls: Some(naq::RemoteTls {
                ca_file: Some("/nonexistent/ca.pem".into()),
                ..naq::RemoteTls::default()
            }),
            ..naq::Remote::default()
        }],
        ..Options::default()
    };
    let e = naq::Server::start(&o).unwrap_err();
    assert!(matches!(e, Error::Tls(_)), "{e}");
}

#[test]
fn a_remote_takes_denies_and_isolation() {
    let o: Options = "leafnodes { remotes: [{ url: h, deny_imports: a, deny_export: [\"b.*\", c], \
                      request_isolation: true }] }\n"
        .parse()
        .unwrap();
    let r = &o.remotes[0];
    assert_eq!(
        (
            &r.deny_imports[..],
            &r.deny_exports[..],
            r.request_isolation
        ),
        (
            &["a".to_owned()][..],
            &["b.*".to_owned(), "c".to_owned()][..],
            true
        )
    );
    for (text, reason) in [
        (
            "leafnodes { remotes: [{url: h, deny_imports: 1}] }",
            "leafnodes: remotes: deny_imports: expected a subject or a list",
        ),
        (
            "leafnodes { remotes: [{url: h, deny_exports: {}}] }",
            "leafnodes: remotes: deny_exports: expected a subject or a list",
        ),
        (
            "leafnodes { remotes: [{url: h, request_isolation: 1}] }",
            "leafnodes: remotes: request_isolation: expected true or false",
        ),
        (
            "leafnodes { remotes: [{url: h, deny_exports: \"a..b\"}] }",
            "leafnode remote: deny_exports: invalid subject \"a..b\"",
        ),
    ] {
        config_error(text, reason);
    }
}

#[test]
fn the_cluster_block_names_the_other_servers() {
    let o: Options = "cluster {\n  name: c\n  listen: \"127.0.0.1:7244\"\n  routes [\n    \
                      \"nats-route://a:6222\"\n    b:6223\n  ]\n}\n"
        .parse()
        .unwrap();
    assert_eq!(
        o.cluster,
        Some(naq::Cluster {
            name: "c".into(),
            host: "127.0.0.1".into(),
            port: 7244,
            routes: vec!["nats-route://a:6222".into(), "b:6223".into()],
        })
    );
    let o: Options = "cluster { host: h, port: 1, routes: x:2 }".parse().unwrap();
    let c = o.cluster.unwrap();
    assert_eq!(
        (c.host.as_str(), c.port, &c.routes[..]),
        ("h", 1, &["x:2".to_owned()][..])
    );
    for (text, reason) in [
        ("cluster: 1", "cluster: expected a map"),
        (
            "cluster { pool_size: 3 }",
            "cluster: pool_size: not supported",
        ),
        (
            "cluster { listen: x }",
            "cluster: listen: expected host:port",
        ),
        (
            "cluster { routes: 1 }",
            "cluster: routes: expected a string or a list",
        ),
        (
            "cluster { routes: [1] }",
            "cluster: routes: expected strings",
        ),
        ("cluster { name: 1 }", "cluster: name: expected a string"),
        ("cluster { host: 1 }", "cluster: host: expected a string"),
        ("cluster { port: x }", "cluster: port: expected a port"),
    ] {
        config_error(text, reason);
    }
}

/// The names of the accounts of `o`.
fn names(o: &Options) -> Vec<&str> {
    o.accounts.iter().map(|a| a.name.as_str()).collect()
}

#[test]
fn exports_and_imports_come_from_their_accounts() {
    let o: Options = "accounts {\n\
        E { exports [{stream: \"s.>\"},\n\
                     {service: \"svc.*\", accounts: [I], response_type: chunked, threshold: \"5s\"},\n\
                     {service: \"req.*\", account_token_position: 2}] }\n\
        I { imports [{stream: {account: E, subject: \"s.>\"}, prefix: pre},\n\
                     {service: {account: E, subject: \"svc.*\"}, to: \"loc.*\", share: true},\n\
                     {service: {account: E, subject: \"req.I\"}}] }\n}\n"
        .parse()
        .unwrap();
    let e = &o.accounts[0];
    assert_eq!(e.exports.len(), 3);
    assert_eq!(e.exports[0].kind, naq::ExportKind::Stream);
    let naq::ExportKind::Service(s) = &e.exports[1].kind else {
        panic!("{:?}", e.exports[1])
    };
    assert_eq!(
        e.exports[1].accounts.as_deref(),
        Some(&["I".to_owned()][..])
    );
    assert_eq!(
        (s.response, s.threshold),
        (naq::ResponseType::Chunked, Duration::from_secs(5))
    );
    assert_eq!(e.exports[2].token_position, Some(2));
    let i = &o.accounts[1].imports;
    assert_eq!((i[0].account.as_str(), i[0].subject.as_str()), ("E", "s.>"));
    assert_eq!(i[0].to.as_deref(), Some("pre.s.>"));
    assert_eq!(i[0].kind, naq::ImportKind::Stream);
    assert_eq!(i[1].to.as_deref(), Some("loc.*"));
    assert_eq!(i[1].kind, naq::ImportKind::Service { share: true });
    assert_eq!(
        (i[2].to.as_deref(), i[2].kind),
        (None, naq::ImportKind::Service { share: false })
    );
}

#[test]
fn exports_naq_cannot_use_are_an_error() {
    for (text, reason) in [
        (
            "accounts { A { exports: {stream: a} } }\n",
            "exports: expected a list",
        ),
        (
            "accounts { A { exports: [a] } }\n",
            "exports: expected a map",
        ),
        (
            "accounts { A { exports: [{stream: a, service: b}] } }\n",
            "exports: both a stream and a service",
        ),
        (
            "accounts { A { exports: [{accounts: [B]}] } }\n",
            "exports: expected a stream or a service",
        ),
        (
            "accounts { A { exports: [{stream: a, response_type: stream}] } }\n",
            "exports: a response directive on a stream",
        ),
        (
            "accounts { A { exports: [{stream: a, latency: l}] } }\n",
            "exports: a latency directive on a stream",
        ),
        (
            "accounts { A { exports: [{service: a, response_type: many}] } }\n",
            "exports: response_type: unknown response type",
        ),
        (
            "accounts { A { exports: [{service: a, latency: {sampling: 101, subject: l}}] } }\n",
            "exports: latency: bad sampling, should be 1-100% or headers",
        ),
        (
            "accounts { A { exports: [{service: a, latency: {sampling: 50}}] } }\n",
            "exports: latency: a subject is required",
        ),
        (
            "accounts { A { exports: [{service: a, allow_trace: true}] } }\n",
            "exports: allow_trace: not supported",
        ),
        (
            "accounts { A { exports: [{service: a, weight: 1}] } }\n",
            "exports: weight: not supported",
        ),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

#[test]
fn imports_naq_cannot_use_are_an_error() {
    for (text, reason) in [
        (
            "accounts { A { imports: [{stream: {account: B}}] } }\n",
            "imports: stream: expected an account and a subject",
        ),
        (
            "accounts { A { imports: [{stream: {account: B, subject: a}, prefix: p, to: q}] } }\n",
            "imports: a stream import cannot have both a prefix and a to",
        ),
        (
            "accounts { A { imports: [{stream: {account: B, subject: a}, prefix: \"p.*\"}] } }\n",
            "imports: a stream import prefix cannot have wildcards",
        ),
        (
            "accounts { A { imports: [{service: {account: B, subject: a}, prefix: p}] } }\n",
            "imports: a prefix on a service",
        ),
        (
            "accounts { A { imports: [{stream: {account: B, subject: a}, share: true}] } }\n",
            "imports: share on a stream",
        ),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

#[test]
fn imports_their_exports_do_not_allow_are_an_error() {
    let text = "accounts { E { exports [{stream: \"a.*\"}] }\n\
                I { imports [{stream: {account: E, subject: \"a.>\"}}] } }\n";
    match text.parse::<Options>() {
        Err(Error::Config { at, reason }) => {
            assert_eq!(at, "config");
            assert_eq!(
                reason,
                "account \"I\": stream import \"a.>\": not authorized"
            );
        }
        other => panic!("{other:?}"),
    }
    let mut opts = Options::default();
    opts.accounts.push("I".into());
    opts.accounts[0].imports.push(naq::Import {
        account: "E".into(),
        subject: "a".into(),
        to: None,
        kind: naq::ImportKind::Stream,
    });
    assert!(matches!(naq::Server::start(&opts), Err(Error::Options(_))));
}

#[test]
fn the_system_account_comes_from_its_keys() {
    let o: Options = "system_account: S\naccounts { S {} }\n".parse().unwrap();
    assert_eq!(o.system_account.as_deref(), Some("S"));
    let o: Options = "no_sys_acc: true\n".parse().unwrap();
    assert!(o.no_system_account);
    for (text, reason) in [
        ("system_account: 1\n", "system_account: expected a string"),
        (
            "no_system_account: 1\n",
            "no_system_account: expected true or false",
        ),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

/// An operator JWT, signed by a fresh operator key.
fn operator_jwt() -> String {
    use data_encoding::BASE64URL_NOPAD;
    let op = nkeys::KeyPair::new_operator();
    let h = BASE64URL_NOPAD.encode(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let body = format!(
        r#"{{"iss":"{k}","sub":"{k}","nats":{{"type":"operator","version":2}}}}"#,
        k = op.public_key()
    );
    let p = BASE64URL_NOPAD.encode(body.as_bytes());
    let sig = op.sign(format!("{h}.{p}").as_bytes()).unwrap();
    format!("{h}.{p}.{}", BASE64URL_NOPAD.encode(&sig))
}

#[test]
fn operator_mode_comes_from_its_keys() {
    let op = operator_jwt();
    let o: Options = format!("operator: {op}\nresolver: MEMORY\n")
        .parse()
        .unwrap();
    assert_eq!(
        (o.operators.len(), o.resolver),
        (1, Some(naq::Resolver::Memory))
    );
    let key = nkeys::KeyPair::new_operator().public_key();
    let o: Options = format!("trusted_keys: [{key}]\nresolver: mem\n")
        .parse()
        .unwrap();
    assert_eq!(o.trusted_keys, [key]);
    let d = dir("operator");
    let file = d.join("op.jwt");
    std::fs::write(
        &file,
        format!("-----BEGIN NATS OPERATOR JWT-----\n{op}\n------END NATS OPERATOR JWT------\n"),
    )
    .unwrap();
    let o: Options = format!(
        "operator: {:?}\nresolver: MEMORY\n",
        file.display().to_string()
    )
    .parse()
    .unwrap();
    assert_eq!(o.operators, [op]);
}

#[test]
fn operator_mode_that_cannot_run_is_an_error() {
    let op = operator_jwt();
    for (text, reason) in [
        (
            format!("operator: {op}\n"),
            "operators require an account resolver to be configured",
        ),
        (
            format!("operator: {op}\nresolver: MEMORY\naccounts [A]\n"),
            "operators do not allow Accounts to be configured directly",
        ),
        (
            format!("operator: {op}\nresolver: MEMORY\nauthorization {{ token: t }}\n"),
            "operators do not allow users to be configured directly",
        ),
        (
            "resolver: MEMORY\n".to_owned(),
            "a resolver needs trusted operators",
        ),
        (
            format!("operator: {op}\nresolver: MEMORY\nresolver_preload {{ ABC: x.y.z }}\n"),
            "resolver_preload: \"ABC\" is not a public account key",
        ),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
    for (text, reason) in [
        (
            "trusted_keys: [ABC]\n",
            "trusted_keys: \"ABC\" is not a public operator key",
        ),
        (
            "resolver: URL(\"http://x\")\n",
            "resolver: URL resolvers are not supported",
        ),
        (
            "operator: nothere.jwt\n",
            "operator: cannot read \"nothere.jwt\": No such file or directory (os error 2)",
        ),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

#[test]
fn operator_keys_naq_cannot_use_are_an_error() {
    let (one, two) = (operator_jwt(), operator_jwt());
    let o: Options = format!("operators: [{one}, {two}]\nresolver: MEMORY\n")
        .parse()
        .unwrap();
    assert_eq!(o.operators.len(), 2);
    for (text, reason) in [
        (
            "resolver_preload: 1\n".to_owned(),
            "resolver_preload: expected a map of account keys to JWTs",
        ),
        (
            "resolver_preload: { A: [1] }\n".to_owned(),
            "resolver_preload: expected a JWT",
        ),
        (
            "resolver: 1\n".to_owned(),
            "resolver: error parsing account resolver, should be MEM or  URL(\"url\") or a map \
             containing dir and type state=[FULL|CACHE])",
        ),
        (
            "operator: 1\n".to_owned(),
            "operator: expected JWTs or files",
        ),
        (
            "trusted_keys: 1\n".to_owned(),
            "trusted_keys: expected keys",
        ),
        (
            format!("operator: {one}\nresolver: MEMORY\nsystem_account: X\n"),
            "system_account: no account \"X\"",
        ),
        (
            format!(
                "operator: {one}\ntrusted_keys: {}\nresolver: MEMORY\n",
                nkeys::KeyPair::new_operator().public_key()
            ),
            "conflicting options for 'TrustedKeys' and 'TrustedOperators'",
        ),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

/// An operator JWT, a system account key, a directory and its path as a
/// config string, and the config lines of the first two.
fn resolver_setup() -> (String, String, PathBuf, String, String) {
    let op = operator_jwt();
    let sys = nkeys::KeyPair::new_account().public_key();
    let d = dir("resolver");
    let path = format!("{:?}", d.join("jwt").display().to_string());
    let head = format!("operator: {op}\nsystem_account: {sys}\n");
    (op, sys, d, path, head)
}

#[test]
fn directory_resolvers_come_from_their_maps() {
    let (op, _, d, path, head) = resolver_setup();
    let full = format!(
        "{head}resolver {{ type: full, dir: {path}, allow_delete: true, hard_delete: true, \
         limit: 5, interval: \"2m\", timeout: \"1s\" }}\n"
    );
    let o: Options = full.parse().unwrap();
    let mut want = naq::Directory::new(d.join("jwt"));
    want.delete = naq::Delete::Remove;
    want.limit = Some(5);
    want.interval = std::time::Duration::from_secs(120);
    want.timeout = std::time::Duration::from_secs(1);
    assert_eq!(o.resolver, Some(naq::Resolver::Full(want)));
    let cache = format!("{head}resolver {{ type: CACHE, dir: {path}, ttl: \"1m\", limit: 0 }}\n");
    let o: Options = cache.parse().unwrap();
    let mut want = naq::Directory::new(d.join("jwt"));
    want.delete = naq::Delete::Remove;
    want.ttl = Some(std::time::Duration::from_secs(60));
    assert_eq!(o.resolver, Some(naq::Resolver::Cache(want)));
    let mem: Options = format!("operator: {op}\nresolver {{ type: mem }}\n")
        .parse()
        .unwrap();
    assert_eq!(mem.resolver, Some(naq::Resolver::Memory));
}

#[test]
fn directory_resolver_maps_that_do_not_hold_are_an_error() {
    let (_, _, d, path, head) = resolver_setup();
    let file = d.join("file");
    std::fs::write(&file, "x").unwrap();
    let at_file = format!("{:?}", file.display().to_string());
    for (body, reason) in [
        (
            "type: full".to_owned(),
            "dir has no value and needs to point to a directory",
        ),
        (
            format!("type: full, dir: {at_file}"),
            "dir needs to point to an accessible directory",
        ),
        (
            format!("type: cache, dir: {path}, allow_delete: true"),
            "CACHE does not accept allow_delete",
        ),
        (
            format!("type: cache, dir: {path}, interval: \"1m\""),
            "CACHE does not accept sync",
        ),
        (
            format!("type: cache, dir: {path}, hard_delete: false"),
            "CACHE does not accept hard_delete",
        ),
        (
            format!("type: full, dir: {path}, ttl: \"1m\""),
            "FULL does not accept ttl",
        ),
        (
            format!("type: full, dir: {path}, hard_delete: true"),
            "hard_delete has no effect without delete",
        ),
        (
            format!("type: full, dir: {path}, timeout: \"0s\""),
            "Fetch timeout 0s is too smal",
        ),
        (
            format!("type: full, dir: {path}, limit: x"),
            "limit: expected a number",
        ),
        (
            format!("type: full, dir: {path}, allow_delete: 1"),
            "allow_delete: expected true or false",
        ),
        (
            format!("type: other, dir: {path}"),
            "error parsing account resolver, should be MEM or  URL(\"url\") or a map \
             containing dir and type state=[FULL|CACHE])",
        ),
    ] {
        let text = format!("{head}resolver {{ {body} }}\n");
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => {
                assert_eq!(r, format!("resolver: {reason}"), "{body}");
            }
            other => panic!("{body}: {other:?}"),
        }
    }
}

#[test]
fn directory_resolvers_need_an_operator_and_a_system_account() {
    let (op, sys, _, path, _) = resolver_setup();
    let key = nkeys::KeyPair::new_operator().public_key();
    for (text, reason) in [
        (
            format!("operator: {op}\nresolver {{ type: full, dir: {path} }}\n"),
            "using nats based account resolver - the system account needs to be specified in \
             configuration or the operator jwt",
        ),
        (
            format!(
                "trusted_keys: [{key}]\nsystem_account: {sys}\nresolver {{ type: full, dir: {path} }}\n"
            ),
            "Could not start resolver: no operator key found",
        ),
    ] {
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}
