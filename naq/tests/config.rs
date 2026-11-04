//! Options from `nats-server` configuration files.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::path::PathBuf;
use std::time::Duration;

use naq::{Error, Options, WebsocketAuth};

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

#[test]
fn users_tokens_and_accounts_come_from_their_blocks() {
    let o: Options = "authorization {\n  timeout: 0.5\n  users: [{user: v, pass: q}]\n}\n\
                      accounts {\n  A { users: [{username: a, password: x}] }\n  B {}\n}\n\
                      no_auth_user: a\n"
        .parse()
        .unwrap();
    assert_eq!(o.accounts, ["A", "B"]);
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
    let one: Options = "authorization { user: u, password: p }\n".parse().unwrap();
    assert_eq!(one.user, Some(("u".into(), "p".into())));
    assert_eq!(one.users.len(), 0);
    let t: Options = "authorization { token: abc, timeout: \"3s\" }\naccounts [X, Y]\n"
        .parse()
        .unwrap();
    assert_eq!(t.token.as_deref(), Some("abc"));
    assert_eq!(t.auth_timeout, Duration::from_secs(3));
    assert_eq!(t.accounts, ["X", "Y"]);
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
            "accounts { A { exports: [] } }\n",
            "accounts: A: exports: not supported",
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
    assert!("http_port: -1\n".parse::<Options>().is_err());
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
fn leafnodes_naq_cannot_use_are_an_error() {
    for (text, reason) in [
        ("leafnodes: 1", "leafnodes: expected a map"),
        ("leafnodes { port: 7422 }", "leafnodes: port: not supported"),
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
            "leafnodes { remotes: [{url: \"ws://h\"}] }",
            "leafnode url \"ws://h\": scheme not supported",
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
        match text.parse::<Options>() {
            Err(Error::Config { reason: r, .. }) => assert_eq!(r, reason, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
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
