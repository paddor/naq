use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

use super::*;

/// The names of a certificate of only the subject of DER `hex`.
fn of_subject(hex: &str) -> Names {
    let der = data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap();
    let mut d = der.as_slice();
    Names {
        subject: subject(expect(&mut d, 0x30).unwrap()).unwrap(),
        ..Names::default()
    }
}

/// The DN of `n` as `[T=v|T=v]...`.
fn dn_of(n: &Names) -> Option<String> {
    let dn = n.dn()?;
    let rdns = dn.0.iter().map(|rdn| {
        let attrs: Vec<String> = rdn.iter().map(|(t, v)| format!("{t}={v}")).collect();
        format!("[{}]", attrs.join("|"))
    });
    Some(rdns.collect())
}

/// Subjects and what Go 1.24 made of them: `ToRDNSequence().String()`,
/// the domain components, and `ldap.FromRawCertSubject`.
const SUBJECTS: [(&str, &str, &str, Option<&str>); 11] = [
    (
        "3048310b3009060355040613025553310d300b060355040a130441636d65310c300a060355040b1303456e67310c300a060355040b13034f7073310e300c06035504031305616c696365",
        "CN=alice,OU=Eng+OU=Ops,O=Acme,C=US",
        "",
        Some("[CN=alice][OU=Ops][OU=Eng][O=Acme][C=US]"),
    ),
    (
        "3036310b30090603550406130255533119300a060355040b1303456e67300b060355040a130441636d65310c300a06035504031303626f62",
        "CN=bob,OU=Eng,O=Acme,C=US",
        "",
        Some("[CN=bob][O=Acme|OU=Eng][C=US]"),
    ),
    (
        "303e31133011060a0992268993f22c6401191303636f6d31173015060a0992268993f22c64011913076578616d706c65310e300c060355040313056361726f6c",
        "CN=carol",
        "DC=com,DC=example",
        Some("[CN=carol][DC=example][DC=com]"),
    ),
    (
        "301c311a301806035504030c1120612c622b6322645c653c663e673b6820",
        r#"CN=\ a\,b\+c\"d\\e\<f\>g\;h\ "#,
        "",
        Some(r#"[CN= a,b+c"d\e<f>g;h ]"#),
    ),
    (
        "301c310c300a06035504030c03237823310c300a060355040a1303612062",
        r"CN=\#x#,O=a b",
        "",
        Some("[O=a b][CN=#x#]"),
    ),
    (
        "3021310e300c060355040313056669727374310f300d060355040313067365636f6e64",
        "CN=second",
        "",
        Some("[CN=second][CN=first]"),
    ),
    (
        "302d310d300b0603550403130464617665311c301a06092a864886f70d0109010c0d646176654061636d652e636f6d",
        "CN=dave",
        "",
        None,
    ),
    (
        "3066310b3009060355040513023432310d300b0603550411130438303030310f300d060355040913064d61696e2031310f300d060355040713065a7572696368310b3009060355040813025a48310b3009060355040613024348310c300a06035504031303657665",
        "SERIALNUMBER=42,CN=eve,POSTALCODE=8000,STREET=Main 1,L=Zurich,ST=ZH,C=CH",
        "",
        Some("[CN=eve][C=CH][ST=ZH][L=Zurich][STREET=Main 1][POSTALCODE=8000][SERIALNUMBER=42]"),
    ),
    ("300b3109300706035504031300", "", "", Some("[CN=]")),
    ("300b3109300706035504061300", "C=", "", Some("[C=]")),
    (
        "301631143008060355040313017830080603550403130179",
        "CN=y",
        "",
        Some("[CN=y|CN=x]"),
    ),
];

#[test]
fn a_subject_reads_as_go_writes_it_and_as_go_ldap_reads_it() {
    for (hex, text, dcs, dn) in SUBJECTS {
        let n = of_subject(hex);
        assert_eq!(n.written(), text, "{hex}");
        assert_eq!(n.dcs(), dcs, "{hex}");
        assert_eq!(dn_of(&n).as_deref(), dn, "{hex}");
    }
}

/// A certificate of `subject` and alternative names `alt`, signed by
/// itself.
fn cert(subject: &[(DnType, &str)], alt: Vec<SanType>) -> Vec<u8> {
    let mut p = CertificateParams::default();
    p.distinguished_name = DistinguishedName::new();
    for (t, v) in subject {
        p.distinguished_name.push(t.clone(), *v);
    }
    p.subject_alt_names = alt;
    let key = KeyPair::generate().unwrap();
    p.self_signed(&key).unwrap().der().to_vec()
}

fn ia5(s: &str) -> rcgen::string::Ia5String {
    s.try_into().unwrap()
}

#[test]
fn a_certificate_gives_its_alternative_names_and_subject() {
    let der = cert(
        &[(DnType::CommonName, "alice")],
        vec![
            SanType::URI(ia5("spiffe://acme/alice")),
            SanType::DnsName(ia5("alice.acme")),
            SanType::Rfc822Name(ia5("alice@acme")),
            SanType::IpAddress([127, 0, 0, 1].into()),
        ],
    );
    let n = Names::of(&der);
    assert_eq!(n.emails, ["alice@acme"]);
    assert_eq!(n.dns, ["alice.acme"]);
    assert_eq!(n.uris, ["spiffe://acme/alice"]);
    assert_eq!(n.written(), "CN=alice");
    assert_eq!(
        Names::of(&der[..der.len() - 1]),
        Names::default(),
        "cut short"
    );
    assert_eq!(Names::of(b"not a certificate"), Names::default());
}

#[test]
fn a_user_is_found_in_the_order_nats_server_tries_names() {
    let dns = |names: &[&str]| -> Vec<(Dn, String)> {
        names
            .iter()
            .filter_map(|n| Dn::parse(n).map(|d| (d, (*n).to_owned())))
            .collect()
    };
    let n = Names::of(&cert(
        &[
            (DnType::OrganizationName, "Acme"),
            (DnType::CommonName, "alice"),
        ],
        vec![
            SanType::URI(ia5("spiffe://acme/alice")),
            SanType::DnsName(ia5("alice.acme")),
            SanType::Rfc822Name(ia5("alice@acme")),
        ],
    ));
    let find = |users: &[&str]| {
        let known = |u: &str| users.contains(&u);
        n.user(known, &dns(users))
    };
    let all = [
        "CN=alice,O=Acme",
        "O=Acme,CN=alice",
        "cn=alice, o=Acme",
        "spiffe://acme/alice",
        "alice.acme",
        "alice@acme",
    ];
    for (users, want) in [
        (&all[..], "alice@acme"),
        (&all[..5], "alice.acme"),
        (&all[..4], "spiffe://acme/alice"),
        // The DN by position, whatever its spelling, then in any order.
        (&all[1..3], "cn=alice, o=Acme"),
        (&all[1..2], "O=Acme,CN=alice"),
    ] {
        assert_eq!(find(users).as_deref(), Some(want), "{users:?}");
    }
    assert_eq!(find(&["CN=bob"]), None);
    assert_eq!(n.user(|_| false, &dns(&all)), None, "none known");
    assert_eq!(Names::default().user(|_| true, &[]), None, "nothing named");
}

#[test]
fn a_subject_go_ldap_cannot_read_is_found_as_text() {
    let email = DnType::CustomDnType(vec![1, 2, 840, 113_549, 1, 9, 1]);
    let dc = DnType::CustomDnType(vec![0, 9, 2342, 19_200_300, 100, 1, 25]);
    let n = Names::of(&cert(
        &[
            (dc, "acme"),
            (DnType::CommonName, "carol"),
            (email, "c@acme"),
        ],
        Vec::new(),
    ));
    assert!(n.dn().is_none(), "an e-mail type go-ldap has no name for");
    let found = |users: &[&str]| n.user(|u| users.contains(&u), &[]);
    assert_eq!(
        found(&["CN=carol", "CN=carol,DC=acme"]).as_deref(),
        Some("CN=carol,DC=acme"),
        "with the domain components first"
    );
    assert_eq!(found(&["CN=carol"]).as_deref(), Some("CN=carol"));
    // Only a type Go has no name for: a subject still, but no text.
    let other = Names::of(&cert(
        &[(DnType::CustomDnType(vec![1, 2, 3]), "x")],
        Vec::new(),
    ));
    assert_eq!(other.user(str::is_empty, &[]), None);
}

#[test]
fn strings_decode_as_go_decodes_them() {
    assert_eq!(string(0x0c, "é".as_bytes()).as_deref(), Some("é"));
    assert_eq!(string(0x0c, &[0xff]), None);
    assert_eq!(
        string(0x13, b"a-Z 09'()+,./:=?*&").as_deref(),
        Some("a-Z 09'()+,./:=?*&")
    );
    assert_eq!(string(0x13, b"a@b"), None);
    assert_eq!(string(0x16, b"a@b").as_deref(), Some("a@b"));
    assert_eq!(string(0x16, &[0x80]), None);
    assert_eq!(string(0x12, b"12 3").as_deref(), Some("12 3"));
    assert_eq!(string(0x12, b"1a"), None);
    assert_eq!(
        string(0x14, &[b'a', 0xe9]).as_deref(),
        Some("aé"),
        "Latin-1"
    );
    assert_eq!(
        string(0x1e, &[0, b'h', 0, 0xe9, 0, 0]).as_deref(),
        Some("hé")
    );
    assert_eq!(string(0x1e, &[0, b'h', 0]), None, "odd");
    assert_eq!(string(0x1e, &[0xd8, 0]), None, "a surrogate");
    assert_eq!(string(0x1e, &[0xff, 0xfe]), None, "a noncharacter");
    assert_eq!(string(0x04, b"x"), None, "no string");
}

#[test]
fn der_elements_read_with_short_and_long_lengths() {
    let mut d: &[u8] = &[0x04, 0x01, 7, 0x04, 0x81, 0x01, 8, 0x02];
    assert_eq!(element(&mut d), Some((0x04, &[7][..])));
    assert_eq!(element(&mut d), Some((0x04, &[8][..])));
    assert_eq!(element(&mut d), None, "no length");
    for bad in [
        &[0x1f, 0x01, 0][..],
        &[0x04, 0x80],
        &[0x04, 0x85, 0, 0, 0, 0, 1],
        &[0x04, 0x82, 0],
        &[0x04, 0x02, 0],
    ] {
        assert_eq!(element(&mut &bad[..]), None, "{bad:?}");
    }
    assert_eq!(expect(&mut &[0x04, 0x00][..], 0x30), None);
}

#[test]
fn a_certificate_of_no_subject_names_its_client_by_its_alternative_names() {
    // With no subject, the alternative names are critical.
    let n = Names::of(&cert(&[], vec![SanType::Rfc822Name(ia5("svc@acme"))]));
    assert_eq!(n.emails, ["svc@acme"]);
    assert_eq!(
        n.user(|u| u == "svc@acme", &[]).as_deref(),
        Some("svc@acme")
    );
    assert_eq!(n.user(|_| false, &[]), None);
}

#[test]
fn a_certificate_tells_when_it_expires() {
    let key = KeyPair::generate().unwrap();
    let rfc = |p: &CertificateParams| {
        let der = p.self_signed(&key).unwrap().der().to_vec();
        not_after(&der).map(crate::times::rfc3339_nano)
    };
    let mut p = CertificateParams::new(vec!["a".to_owned()]).unwrap();
    // UTCTime before 2050, GeneralizedTime from it.
    p.not_after = rcgen::date_time_ymd(2031, 2, 3);
    assert_eq!(rfc(&p).as_deref(), Some("2031-02-03T00:00:00Z"));
    p.not_after = rcgen::date_time_ymd(2071, 12, 31);
    assert_eq!(rfc(&p).as_deref(), Some("2071-12-31T00:00:00Z"));
    assert_eq!(not_after(b"\x30\x00"), None);
    assert_eq!(
        asn1_time(0x17, b"991231235959Z")
            .map(crate::times::rfc3339_nano)
            .as_deref(),
        Some("1999-12-31T23:59:59Z")
    );
    assert_eq!(asn1_time(0x17, b"9912312359Z"), None);
    assert_eq!(asn1_time(0x18, b"2031020300000x"), None);
    assert_eq!(asn1_time(0x04, b"991231235959Z"), None);
}
