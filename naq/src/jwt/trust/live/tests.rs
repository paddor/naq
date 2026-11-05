use super::*;
use crate::jwt::claims::UserScope;

fn trust_of(a: claims::Account) -> (Trust, String) {
    let key = nkeys::KeyPair::new_account().public_key();
    let mut accounts = rustc_hash::FxHashMap::default();
    let claims = Claims {
        iss: "OP".into(),
        sub: key.clone(),
        nats: a,
        ..Claims::default()
    };
    accounts.insert(
        key.clone(),
        Arc::new(JwtAccount::new(1, claims, "J".into())),
    );
    let t = Trust {
        signers: vec!["OP".into()],
        strict: false,
        accounts: std::sync::RwLock::new(accounts),
    };
    (t, key)
}

fn kept(account: &str) -> Kept {
    Kept {
        account: account.into(),
        jwt: None,
        key: "UKEY".into(),
        iat: 10,
        signer: None,
        defaults: None,
        subs: NO_LIMIT,
        payload: NO_LIMIT,
        expires: None,
    }
}

#[test]
fn a_user_of_a_scope_that_changed_goes() {
    let scope = |subs: i64| {
        let mut template = claims::UserLimits::unlimited();
        template.subs = subs;
        Some(Box::new(UserScope {
            kind: "user_scope".into(),
            key: "ASK".into(),
            role: String::new(),
            template,
        }))
    };
    let mut a = claims::Account::default();
    a.signing_keys.0.insert("ASK".into(), scope(5));
    let (t, key) = trust_of(a);
    let mut k = kept(&key);
    k.signer = Some(("ASK".into(), scope(5).map(|s| s.template)));
    assert!(matches!(t.refresh(&k), Refresh::Stays(_)));
    k.signer = Some(("ASK".into(), scope(6).map(|s| s.template)));
    assert!(
        matches!(t.refresh(&k), Refresh::Goes(Gone::Unsigned)),
        "its template changed"
    );
    k.signer = Some(("AGONE".into(), None));
    assert!(
        matches!(t.refresh(&k), Refresh::Goes(Gone::Unsigned)),
        "its key is gone"
    );
    assert!(
        matches!(t.refresh(&kept("ANONE")), Refresh::Goes(Gone::Expired)),
        "no account"
    );
}

#[test]
fn a_callout_user_is_revoked_by_its_key_and_issue_time() {
    let mut a = claims::Account::default();
    a.revocations.insert("UKEY".into(), 10);
    let (t, key) = trust_of(a);
    assert!(matches!(
        t.refresh(&kept(&key)),
        Refresh::Goes(Gone::Revoked)
    ));
    let mut later = kept(&key);
    later.iat = 11;
    let Refresh::Stays(s) = t.refresh(&later) else {
        panic!("issued after");
    };
    assert_eq!((s.subs, s.payload), (0, 0), "limits left out are zero");
}

#[test]
fn an_update_holds_only_for_the_account_it_names() {
    let (t, key) = trust_of(claims::Account::default());
    assert_eq!(
        t.update(&key, ""),
        Status::Failed("jwt update error", "request body is empty".into())
    );
    assert!(matches!(
        t.update(&key, "x"),
        Status::Failed("jwt update resulted in error", _)
    ));
    assert_eq!(
        t.update("AOTHER", "J"),
        Status::Failed("jwt update resulted in error", "expected 3 chunks".into())
    );
}

#[test]
fn default_permissions_are_given_again_only_once_they_changed() {
    let mut a = claims::Account::default();
    a.default_permissions.publish.deny = vec!["x".into()];
    let (t, key) = trust_of(a);
    let account = t.account(&key).unwrap();
    let mut k = kept(&key);
    k.defaults = Some(Defaults(account.defaults.clone()));
    let Refresh::Stays(s) = t.refresh(&k) else {
        panic!("stays");
    };
    assert!(s.defaults.is_none(), "the same ones");
    k.defaults = Some(Defaults(None));
    let Refresh::Stays(s) = t.refresh(&k) else {
        panic!("stays");
    };
    assert!(s.defaults.is_some_and(|d| d.0.is_some()), "new ones");
}
