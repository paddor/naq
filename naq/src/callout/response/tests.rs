use super::*;

/// A body of user JWT `j`.
fn jwt(j: &str) -> claims::AuthResponse {
    claims::AuthResponse {
        jwt: j.into(),
        ..claims::AuthResponse::default()
    }
}

/// A body of error `e`.
fn error(e: &str) -> claims::AuthResponse {
    claims::AuthResponse {
        error: e.into(),
        ..claims::AuthResponse::default()
    }
}

/// An answer for `user` at server `server`, issued by `iss`, with body
/// `nats`.
fn answer(
    iss: &str,
    user: &str,
    server: &str,
    nats: claims::AuthResponse,
) -> Claims<claims::AuthResponse> {
    Claims {
        iss: iss.into(),
        sub: user.into(),
        aud: server.into(),
        nats,
        ..Claims::default()
    }
}

#[test]
fn answers_hold_only_for_the_request_server_and_signer() {
    let issuer = nkeys::KeyPair::new_account().public_key();
    let user = nkeys::KeyPair::new_user().public_key();
    let server = nkeys::KeyPair::new_server().public_key();
    let ask = Ask {
        account: 1,
        user_nkey: user.clone(),
        mode: Mode::Config {
            issuer: issuer.clone(),
        },
        sealed_by: None,
        user: None,
    };
    let check = |r: &Claims<claims::AuthResponse>, sealed| holds(r, &ask, &server, sealed, None);
    assert!(check(&answer(&issuer, &user, &server, jwt("x")), false).is_ok());
    let other_user = nkeys::KeyPair::new_user().public_key();
    let other_server = nkeys::KeyPair::new_server().public_key();
    let other_signer = nkeys::KeyPair::new_account().public_key();
    for (r, why) in [
        (
            answer(&issuer, &other_user, &server, jwt("x")),
            "expected user",
        ),
        (
            answer(&issuer, &user, &other_server, jwt("x")),
            "this server",
        ),
        (answer(&issuer, &user, "S", jwt("x")), "server key"),
        (
            answer(&other_signer, &user, &server, jwt("x")),
            "signing key",
        ),
        (answer(&issuer, &user, &server, jwt("")), "only one"),
        (
            answer(&issuer, &user, &server, error("nope")),
            "returned an error",
        ),
        (
            answer(
                &issuer,
                &user,
                &server,
                claims::AuthResponse {
                    issuer_account: "A".into(),
                    ..jwt("x")
                },
            ),
            "issuer_account",
        ),
        (
            Claims {
                exp: 1,
                ..answer(&issuer, &user, &server, jwt("x"))
            },
            "expired",
        ),
    ] {
        let e = check(&r, false).unwrap_err();
        assert!(e.contains(why), "{why}: {e}");
    }
    // Sealed, the seal tells who sent it, as in `nats-server`.
    assert!(check(&answer(&other_signer, &user, &server, jwt("x")), true).is_ok());
}

#[test]
fn an_operator_mode_answer_comes_from_the_callout_account() {
    let key = nkeys::KeyPair::new_account().public_key();
    let user = nkeys::KeyPair::new_user().public_key();
    let server = nkeys::KeyPair::new_server().public_key();
    let ask = Ask {
        account: 1,
        user_nkey: user.clone(),
        mode: Mode::Operator {
            key: key.clone(),
            allowed: Vec::new(),
        },
        sealed_by: None,
        user: None,
    };
    let body = |issuer_account: &str| claims::AuthResponse {
        jwt: "x".into(),
        issuer_account: issuer_account.into(),
        ..claims::AuthResponse::default()
    };
    let check = |r| holds(&r, &ask, &server, false, None);
    assert!(check(answer(&key, &user, &server, body(""))).is_ok());
    assert!(check(answer(&key, &user, &server, body(&key))).is_ok());
    let other = nkeys::KeyPair::new_account().public_key();
    assert!(check(answer(&key, &user, &server, body(&other))).is_err());
    assert!(
        check(answer(&other, &user, &server, body(""))).is_err(),
        "no trust: no signing keys"
    );
}
