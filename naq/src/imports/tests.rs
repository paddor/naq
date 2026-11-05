use super::*;
use crate::{Options, ResponseType};

fn link_text(text: &str) -> Result<Box<[Imports]>, String> {
    let opts: Options = text.parse().map_err(|e: crate::Error| e.to_string())?;
    link(&opts)
}

#[test]
fn a_stream_import_takes_its_subjects_as_the_export_allows() {
    let all = link_text(
        "accounts { E { exports [{stream: \"s.>\"}, {stream: lit}] }\n\
         I { imports [{stream: {account: E, subject: \"s.>\"}, prefix: pre},\n\
                      {stream: {account: E, subject: lit}, to: \"x.*\"},\n\
                      {stream: {account: E, subject: \"s.a\"}}] } }",
    )
    .unwrap();
    let s = &all[2].streams;
    assert_eq!(
        (s[0].from, &*s[0].subject, &*s[0].to),
        (1, &b"s.>"[..], &b"pre.s.>"[..])
    );
    assert!(matches!(s[0].rewrite, Rewrite::Map(_)));
    assert_eq!(s[1].rewrite, Rewrite::Fixed(b"x.*"[..].into()));
    assert_eq!(s[2].rewrite, Rewrite::Same);
    assert!(all[0].streams.is_empty() && all[1].streams.is_empty());
}

#[test]
fn an_import_the_export_does_not_allow_is_an_error() {
    for (text, reason) in [
        (
            "accounts { E { exports [{stream: \"a.*\"}] }\n\
             I { imports [{stream: {account: E, subject: \"a.>\"}}] } }",
            "not authorized",
        ),
        (
            "accounts { E { exports [{stream: a, accounts: [X]}] }, X {}\n\
             I { imports [{stream: {account: E, subject: a}}] } }",
            "not authorized",
        ),
        (
            "accounts { E { exports [{service: a}] }\n\
             I { imports [{stream: {account: E, subject: a}}] } }",
            "not authorized",
        ),
        (
            "accounts { I { imports [{service: {account: E, subject: a}}] } }",
            "no account \"E\"",
        ),
        (
            "accounts { E { exports [{service: \"req.*.svc\", account_token_position: 2}] }\n\
             I { imports [{service: {account: E, subject: \"req.*.svc\"}}] } }",
            "not authorized",
        ),
    ] {
        let e = link_text(text).unwrap_err();
        assert!(e.contains(reason), "{e} for {text}");
    }
}

#[test]
fn an_export_names_who_may_import_it() {
    let ok = [
        "accounts { E { exports [{stream: a, accounts: [I]}] }\n\
         I { imports [{stream: {account: E, subject: a}}] } }",
        "accounts { E { exports [{stream: a, accounts: []}] }\n\
         I { imports [{stream: {account: E, subject: a}}] } }",
        "accounts { E { exports [{service: \"req.*.svc\", account_token_position: 2}] }\n\
         I { imports [{service: {account: E, subject: \"req.I.svc\"}}] } }",
        "accounts { E { exports [{service: \"a.*\"}] }\n\
         I { imports [{service: {account: E, subject: \"a.b\"}}] } }",
    ];
    for text in ok {
        link_text(text).unwrap();
    }
}

#[test]
fn imports_that_close_a_cycle_are_an_error() {
    let stream = "accounts {\n\
        A { exports [{stream: s}], imports [{stream: {account: B, subject: s}}] }\n\
        B { exports [{stream: s}], imports [{stream: {account: A, subject: s}}] } }";
    assert!(link_text(stream).unwrap_err().contains("cycle"));
    let service = "accounts {\n\
        A { exports [{service: q}], imports [{service: {account: B, subject: q}}] }\n\
        B { exports [{service: q}], imports [{service: {account: A, subject: q}}] } }";
    assert!(link_text(service).unwrap_err().contains("cycle"));
    let chain = "accounts {\n\
        A { imports [{service: {account: B, subject: q}}] }\n\
        B { exports [{service: q}], imports [{service: {account: C, subject: q}}] }\n\
        C { exports [{service: q}] } }";
    link_text(chain).unwrap();
}

#[test]
fn an_import_twice_is_an_error() {
    let streams = "accounts { E { exports [{stream: \"s.>\"}] }\n\
        I { imports [{stream: {account: E, subject: \"s.>\"}},\n\
                     {stream: {account: E, subject: \"s.>\"}, prefix: p}] } }";
    assert!(link_text(streams).unwrap_err().contains("exists already"));
    let services = "accounts { E { exports [{service: \"q.>\"}] }\n\
        I { imports [{service: {account: E, subject: q.a}, to: x},\n\
                     {service: {account: E, subject: q.b}, to: x}] } }";
    assert!(link_text(services).unwrap_err().contains("twice"));
    let two = "accounts { E { exports [{service: q}] }, F { exports [{service: q}] }\n\
        I { imports [{service: {account: E, subject: q}},\n\
                     {service: {account: F, subject: q}}] } }";
    assert_eq!(link_text(two).unwrap()[3].services.len(), 2);
}

#[test]
fn a_service_import_maps_its_subjects_to_the_exporter() {
    let all = link_text(
        "accounts { E { exports [{service: \"a.*.*\"}, {service: \"svc.>\"}, {service: single, response_type: stream, threshold: \"5s\"}] }\n\
         I { imports [{service: {account: E, subject: \"a.*.*\"}, to: \"b.$2.$1\"},\n\
                      {service: {account: E, subject: \"svc.>\"}, share: true},\n\
                      {service: {account: E, subject: single}, to: \"loc.*\"}] } }",
    )
    .unwrap();
    let s = &all[2].services;
    let Rewrite::Map(tr) = &s[0].rewrite else {
        panic!("{:?}", s[0].rewrite)
    };
    let mut out = Vec::new();
    tr.apply(b"b.x.y", &mut out);
    assert_eq!((&*s[0].from, &out[..]), (&b"b.*.*"[..], &b"a.y.x"[..]));
    assert_eq!((s[1].rewrite.clone(), s[1].share), (Rewrite::Same, true));
    assert_eq!(s[2].rewrite, Rewrite::Fixed(b"single"[..].into()));
    assert_eq!(s[2].service.response, ResponseType::Stream);
    assert_eq!(s[2].service.threshold, std::time::Duration::from_secs(5));
}

#[test]
fn bad_exports_and_transforms_are_an_error() {
    for (text, reason) in [
        (
            "accounts { E { exports [{stream: \"a.>.b\"}] } }",
            "invalid subject",
        ),
        (
            "accounts { E { exports [{stream: \"a.b\", account_token_position: 2}] } }",
            "token position",
        ),
        (
            "accounts { E { exports [{service: s, latency: lat, response_type: stream}] } }",
            "singleton",
        ),
        (
            "accounts { E { exports [{service: \"s.*\", latency: \"s.x\"}] } }",
            "latency subject",
        ),
        (
            "no_sys_acc: true\naccounts { E { exports [{service: s, latency: lat}] } }",
            "latency needs a system account",
        ),
        (
            "accounts { E { exports [{stream: \"a.*\"}] }\n\
             I { imports [{stream: {account: E, subject: \"a.*\"}, to: \"b.*.*\"}] } }",
            "wildcard index out of range in $2: [2]",
        ),
        (
            "accounts { E { exports [{service: \"a.*\"}] }\n\
             I { imports [{service: {account: E, subject: \"a.*\"}, to: \"b.c\"}] } }",
            "not using all of the token wildcard(s) in b.c",
        ),
    ] {
        let e = link_text(text).unwrap_err();
        assert!(e.contains(reason), "{e} for {text}");
    }
}

#[test]
fn a_shadow_takes_the_subject_the_exporter_has_for_a_subscription() {
    let all = link_text(
        "accounts { E { exports [{stream: \"s.>\"}, {stream: lit}, {stream: \"w.*\"}] }\n\
         I { imports [{stream: {account: E, subject: \"s.>\"}, prefix: pre},\n\
                      {stream: {account: E, subject: lit}, to: \"x.*\"},\n\
                      {stream: {account: E, subject: \"w.*\"}}] } }",
    )
    .unwrap();
    let [pre, lit, w] = [0, 1, 2].map(|k| all[2].streams[k].clone());
    let shadow = |im: &StreamImport, f: &str| {
        im.shadow(f.as_bytes())
            .map(|s| String::from_utf8(s).unwrap())
    };
    // The import's own subject, a narrower one, a wider one, an overlap.
    assert_eq!(shadow(&pre, "pre.s.>").as_deref(), Some("s.>"));
    assert_eq!(shadow(&pre, "pre.s.a.*").as_deref(), Some("s.a.*"));
    assert_eq!(shadow(&pre, ">").as_deref(), Some("s.>"));
    assert_eq!(shadow(&pre, "pre.*.x").as_deref(), Some("s.x"));
    assert_eq!(shadow(&pre, "pre.t.x"), None);
    assert_eq!(shadow(&pre, "*.*"), None);
    assert_eq!(shadow(&lit, "x.y").as_deref(), Some("lit"));
    assert_eq!(shadow(&w, "w.a").as_deref(), Some("w.a"));
    assert_eq!(shadow(&w, "*.a").as_deref(), Some("w.a"));
    let mut out = Vec::new();
    pre.deliver_as(b"s.a.b", &mut out);
    lit.deliver_as(b"lit", &mut out);
    w.deliver_as(b"w.q", &mut out);
    assert_eq!(out, b"pre.s.a.bx.*w.q");
}

#[test]
fn a_cycle_through_three_accounts_is_an_error_and_a_chain_is_not() {
    let streams = "accounts {\n\
        A { exports [{stream: \"s.>\"}], imports [{stream: {account: B, subject: \"s.>\"}}] }\n\
        B { exports [{stream: \"s.>\"}], imports [{stream: {account: C, subject: \"s.a\"}}] }\n\
        C { exports [{stream: \"s.>\"}], imports [{stream: {account: A, subject: \"s.>\"}}] } }";
    assert!(link_text(streams).unwrap_err().contains("cycle"));
    let services = "accounts {\n\
        C { exports [{service: \"q.>\"}], imports [{service: {account: A, subject: \"q.a\"}}] }\n\
        B { exports [{service: \"q.>\"}], imports [{service: {account: C, subject: \"q.>\"}}] }\n\
        A { exports [{service: \"q.>\"}], imports [{service: {account: B, subject: \"q.>\"}}] } }";
    assert!(link_text(services).unwrap_err().contains("cycle"));
    let chain = "accounts {\n\
        C { exports [{service: \"q.>\"}] }\n\
        B { exports [{service: \"q.>\"}], imports [{service: {account: C, subject: \"q.a\"}}] }\n\
        A { imports [{service: {account: B, subject: \"q.>\"}}] } }";
    link_text(chain).unwrap();
    for bad in [
        "accounts { E { exports [{stream: \">\"}] }, I { imports [{stream: {account: E, subject: \"a.>.b\"}}] } }",
        "accounts { E { exports [{service: \">\"}] }, I { imports [{service: {account: E, subject: \"a\"}, to: \"b..c\"}] } }",
    ] {
        assert!(
            link_text(bad).unwrap_err().contains("invalid subject"),
            "{bad}"
        );
    }
}

#[test]
fn latency_takes_the_system_account_the_server_makes_or_names() {
    link_text("accounts { E { exports [{service: s, latency: lat}] } }").unwrap();
    link_text("system_account: S\naccounts { S {}, E { exports [{service: s, latency: lat}] } }")
        .unwrap();
    let opts: Options = "no_sys_acc: true\naccounts { $SYS {} }".parse().unwrap();
    let names = crate::auth::accounts(&opts);
    assert_eq!(crate::auth::system(&opts, &names), Some(1));
    let made: Options = "accounts { A {} }".parse().unwrap();
    let names = crate::auth::accounts(&made);
    assert_eq!(
        (&*names, crate::auth::system(&made, &names)),
        (&["$G".to_owned(), "A".into(), "$SYS".into()][..], Some(2))
    );
    let none: Options = "no_system_account: true".parse().unwrap();
    assert_eq!(
        crate::auth::system(&none, &crate::auth::accounts(&none)),
        None
    );
    let bad = "system_account: S"
        .parse::<Options>()
        .unwrap_err()
        .to_string();
    assert!(bad.contains("system_account: no account"), "{bad}");
}
