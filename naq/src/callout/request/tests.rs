use super::*;

fn decoded(jwt: &str) -> serde_json::Value {
    let body = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&BASE64URL_NOPAD.decode(body.as_bytes()).unwrap()).unwrap()
}

/// The payload of `jwt`, as text.
fn raw(jwt: &str) -> String {
    let body = jwt.split('.').nth(1).unwrap();
    String::from_utf8(BASE64URL_NOPAD.decode(body.as_bytes()).unwrap()).unwrap()
}

/// A request of server `server` about a user `bob` who signed a nonce,
/// over TLS.
fn sample(server: &nkeys::KeyPair) -> String {
    let issuer = nkeys::KeyPair::new_account().public_key();
    let creds = Creds {
        user: Some("bob".into()),
        pass: Some("secret".into()),
        sig: Some("s".into()),
        ..Creds::default()
    };
    let tls = TlsInfo {
        version: "1.3",
        cipher: "TLS_AES_128_GCM_SHA256".into(),
        chain: vec!["PEM".into()],
    };
    let about = About {
        id: 7,
        ip: "127.0.0.1",
        creds: Some(&creds),
        name: Some("me"),
        protocol: 1,
        nonce: Some("n"),
        tls: Some(&tls),
        ..About::default()
    };
    let from = From {
        server,
        name: "S",
        host: "0.0.0.0",
        cluster: "",
        issuer: &issuer,
        user_nkey: "UKEY",
        xkey: None,
        iat: 10,
        exp: 12,
    };
    jwt(&from, &about)
}

#[test]
fn a_request_is_signed_by_the_server_with_claims_in_go_order() {
    let server = nkeys::KeyPair::new_server();
    let jwt = sample(&server);
    let (signed, sig) = jwt.rsplit_once('.').unwrap();
    let sig = BASE64URL_NOPAD.decode(sig.as_bytes()).unwrap();
    assert!(server.verify(signed.as_bytes(), &sig).is_ok());
    let raw = raw(&jwt);
    let at: Vec<usize> = ["aud", "exp", "jti", "iat", "iss", "sub", "nats"]
        .iter()
        .map(|k| raw.find(&format!("\"{k}\":")).unwrap())
        .collect();
    assert!(at.is_sorted(), "{raw}");
    let c = decoded(&jwt);
    assert_eq!(c["iss"], server.public_key());
    let n = &c["nats"];
    assert_eq!(n["client_info"]["user"], "bob");
    assert_eq!(
        n["client_info"]["nonce"], "n",
        "the nonce, as it signed one"
    );
    assert_eq!(n["client_info"]["type"], "nats");
    assert_eq!(n["connect_opts"]["pass"], "secret");
    assert_eq!(n["client_tls"]["verified_chains"][0][0], "PEM");
    assert!(n["server_id"].get("cluster").is_none());
}

#[test]
fn a_request_is_named_by_the_hash_of_its_claims() {
    let jwt = sample(&nkeys::KeyPair::new_server());
    let raw = raw(&jwt);
    // As nats-io/jwt makes it: the hash of the claims without one.
    let jti = decoded(&jwt)["jti"].as_str().unwrap().to_owned();
    let unhashed = raw.replace(&format!("\"jti\":\"{jti}\","), "");
    let hash = BASE32_NOPAD.encode(&sha2::Sha512_256::digest(unhashed.as_bytes()));
    assert_eq!(jti, hash);
}

#[test]
fn the_user_a_request_names_is_the_one_nats_server_names() {
    let server = nkeys::KeyPair::new_server();
    let from = From {
        server: &server,
        name: "S",
        host: "h",
        cluster: "c",
        issuer: "A",
        user_nkey: "U",
        xkey: Some("XKEY"),
        iat: 0,
        exp: 0,
    };
    let user_of = |creds: Creds, jwt_user: Option<(&str, &[String], &str)>| {
        let about = About {
            creds: Some(&creds),
            jwt_user,
            websocket: true,
            ..About::default()
        };
        decoded(&jwt(&from, &about))["nats"]["client_info"].clone()
    };
    let token = Creds {
        token: Some("t".into()),
        ..Creds::default()
    };
    assert_eq!(user_of(token.clone(), None)["user"], "[REDACTED]");
    let tags = ["tier:gold".to_owned()];
    let info = user_of(token, Some(("UJWT", &tags, "sentinel")));
    assert_eq!(info["user"], "UJWT");
    assert_eq!(info["tags"][0], "tier:gold");
    assert_eq!(info["name_tag"], "sentinel");
    assert_eq!(info["type"], "websocket");
    let nkey = Creds {
        nkey: Some("UN".into()),
        user: Some("u".into()),
        ..Creds::default()
    };
    assert_eq!(user_of(nkey, None)["user"], "UN", "an NKey first");
    let c = decoded(&jwt(&from, &About::default()));
    assert_eq!(c["nats"]["server_id"]["xkey"], "XKEY");
    assert_eq!(c["nats"]["server_id"]["cluster"], "c");
    assert!(
        c["nats"]["client_info"].get("nonce").is_none(),
        "nothing signed"
    );
}

#[test]
fn certificates_go_out_in_pem_as_go_writes_them() {
    let der = vec![7u8; 100];
    let pem = pem(&der);
    let lines: Vec<&str> = pem.lines().collect();
    assert_eq!(lines[0], "-----BEGIN CERTIFICATE-----");
    assert_eq!(lines[1].len(), 64);
    assert_eq!(*lines.last().unwrap(), "-----END CERTIFICATE-----");
    assert!(pem.ends_with("-----\n"));
    let body: String = lines[1..lines.len() - 1].concat();
    assert_eq!(BASE64.decode(body.as_bytes()).unwrap(), der);
}
