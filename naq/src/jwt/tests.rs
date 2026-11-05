use data_encoding::BASE64URL_NOPAD;
use nkeys::KeyPair;
use serde_json::json;

use super::claims::{Account, Activation, Kind, Operator, User};
use super::*;

/// `payload` as a JWT signed by `kp` under header `header`.
fn mint_with(kp: &KeyPair, header: &serde_json::Value, payload: &serde_json::Value) -> String {
    let h = BASE64URL_NOPAD.encode(header.to_string().as_bytes());
    let p = BASE64URL_NOPAD.encode(payload.to_string().as_bytes());
    let sig = kp.sign(format!("{h}.{p}").as_bytes()).unwrap();
    format!("{h}.{p}.{}", BASE64URL_NOPAD.encode(&sig))
}

/// Claims of `sub` with body `nats`, signed by `kp`.
fn mint(kp: &KeyPair, sub: &str, nats: &serde_json::Value) -> String {
    let header = json!({"typ": "JWT", "alg": "ed25519-nkey"});
    let payload = json!({"jti": "J", "iat": 1, "iss": kp.public_key(), "sub": sub, "nats": nats});
    mint_with(kp, &header, &payload)
}

#[test]
fn an_account_jwt_decodes_with_its_body() {
    let op = KeyPair::new_operator();
    let acc = KeyPair::new_account();
    let token = mint(
        &op,
        &acc.public_key(),
        &json!({"type": "account", "version": 2,
            "limits": {"conn": -1, "subs": 5},
            "signing_keys": ["AKEY", {"kind": "user_scope", "key": "ASCOPED", "role": "r", "template": {"pub": {"allow": ["a"]}}}],
            "exports": [{"subject": "svc.>", "type": "service", "response_threshold": 1_000_000_000_i64,
                "service_latency": {"sampling": "headers", "results": "lat"}}],
            "imports": [{"subject": "s.>", "account": "AX", "type": "stream", "local_subject": "x.>"}],
            "revocations": {"*": 5}}),
    );
    let c = decode::<Account>(&token).unwrap();
    assert_eq!(
        (c.iss.as_str(), c.sub.as_str()),
        (&*op.public_key(), &*acc.public_key())
    );
    assert_eq!(
        (
            c.nats.limits.conn,
            c.nats.limits.subs,
            c.nats.limits.payload
        ),
        (-1, 5, 0)
    );
    let keys = &c.nats.signing_keys.0;
    assert_eq!(keys.get("AKEY"), Some(&None));
    let scope = keys["ASCOPED"].as_ref().unwrap();
    assert_eq!(scope.template.permissions.publish.allow, ["a"]);
    assert_eq!(
        scope.template.subs, -1,
        "a template's limits default to none"
    );
    let e = &c.nats.exports[0];
    assert_eq!(
        (e.kind, e.response_threshold),
        (Kind::Service, 1_000_000_000)
    );
    assert_eq!(e.service_latency.as_ref().unwrap().sampling, 0);
    assert_eq!(c.nats.imports[0].local_subject, "x.>");
    assert_eq!(c.nats.revocations["*"], 5);
}

#[test]
fn a_user_jwt_decodes_with_its_permissions_and_limits() {
    let acc = KeyPair::new_account();
    let token = mint(
        &acc,
        "UUSER",
        &json!({"type": "user", "version": 2, "pub": {"allow": ["a.>"]}, "sub": {"deny": ["b"]},
            "resp": {"max": 2, "ttl": 5}, "subs": -1, "payload": 10,
            "src": "10.0.0.0/8, 127.0.0.1/32", "times": [{"start": "01:00:00", "end": "02:00:00"}],
            "bearer_token": true, "allowed_connection_types": ["STANDARD"], "issuer_account": "AISS",
            "tags": ["t:1"]}),
    );
    let c = decode::<User>(&token).unwrap();
    let l = &c.nats.limits;
    assert_eq!(l.permissions.publish.allow, ["a.>"]);
    assert_eq!(l.permissions.subscribe.deny, ["b"]);
    assert_eq!(l.permissions.resp.unwrap().max, 2);
    assert_eq!((l.subs, l.data, l.payload), (-1, 0, 10));
    assert_eq!(l.src, ["10.0.0.0/8", "127.0.0.1/32"]);
    assert_eq!(l.times[0].end, "02:00:00");
    assert!(l.bearer_token && !l.is_empty());
    assert_eq!(c.nats.issuer_account, "AISS");
}

#[test]
fn a_jwt_that_does_not_hold_is_refused() {
    let op = KeyPair::new_operator();
    let acc = KeyPair::new_account();
    let good = mint(
        &op,
        &acc.public_key(),
        &json!({"type": "account", "version": 2}),
    );
    assert!(decode::<Account>(&good).is_ok());
    // Another body, the signature over the first.
    let (head, rest) = good.split_once('.').unwrap();
    let sig = rest.split_once('.').unwrap().1;
    let other = BASE64URL_NOPAD.encode(
        json!({"iss": op.public_key(), "sub": "x", "nats": {"type": "account", "version": 2}})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(
        decode::<Account>(&format!("{head}.{other}.{sig}")),
        Err(Invalid::Signature)
    );
    assert_eq!(decode::<User>(&good), Err(Invalid::Kind("user")));
    assert_eq!(decode::<Account>("a.b"), Err(Invalid::Chunks));
    assert_eq!(decode::<Account>("a.b.c.d"), Err(Invalid::Chunks));
    assert_eq!(decode::<Account>("!.b.c"), Err(Invalid::Encoding));
    let v3 = mint(&op, "A", &json!({"type": "account", "version": 3}));
    assert_eq!(decode::<Account>(&v3), Err(Invalid::Version(3)));
    let none = mint(&op, "A", &json!({"type": "account"}));
    assert_eq!(decode::<Account>(&none), Err(Invalid::Version(0)));
    let v1 = mint_with(
        &op,
        &json!({"typ": "JWT", "alg": "ed25519"}),
        &json!({"iss": op.public_key(), "type": "account"}),
    );
    assert_eq!(decode::<Account>(&v1), Err(Invalid::Version(1)));
    let rsa = mint_with(&op, &json!({"typ": "JWT", "alg": "RS256"}), &json!({}));
    assert_eq!(decode::<Account>(&rsa), Err(Invalid::Header));
    // A user may only be issued by an account key.
    let by_operator = mint(&op, "U", &json!({"type": "user", "version": 2}));
    assert_eq!(decode::<User>(&by_operator), Err(Invalid::Issuer("user")));
    let big = "a".repeat(MAX_SIZE + 1);
    assert_eq!(decode::<Account>(&big), Err(Invalid::TooLarge));
}

#[test]
fn the_old_algorithm_name_and_any_case_pass() {
    let op = KeyPair::new_operator();
    let token = mint_with(
        &op,
        &json!({"typ": "jwt", "alg": "ED25519"}),
        &json!({"iss": op.public_key(), "sub": op.public_key(),
            "nats": {"type": "operator", "version": 2, "signing_keys": ["OSK"], "system_account": "ASYS"}}),
    );
    let c = decode::<Operator>(&token).unwrap();
    assert_eq!(
        (c.nats.signing_keys.len(), c.nats.system_account.as_str()),
        (1, "ASYS")
    );
    let act = mint(
        &KeyPair::new_account(),
        "AIMP",
        &json!({"type": "activation", "version": 2, "subject": "s.>", "kind": "stream"}),
    );
    assert_eq!(decode::<Activation>(&act).unwrap().nats.kind, Kind::Stream);
}

#[test]
fn time_bounds_hold_both_ways() {
    let c = Claims {
        exp: 10,
        nbf: 5,
        nats: (),
        ..Claims::default()
    };
    assert!(c.out_of_time(4) && !c.out_of_time(5) && !c.out_of_time(10) && c.out_of_time(11));
    assert!(!Claims::<()>::default().out_of_time(now()));
    assert!(is_key(&KeyPair::new_account().public_key(), 'A'));
    assert!(!is_key("AXX", 'A') && !is_key(&KeyPair::new_user().public_key(), 'A'));
}
