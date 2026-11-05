use super::*;
use crate::auth::Grant;
use crate::{Login, User};

fn user(name: &str, account: &str) -> User {
    User {
        login: Login::Password {
            user: name.into(),
            password: "p".into(),
        },
        account: Some(account.into()),
        permissions: None,
        connection_types: Vec::new(),
    }
}

/// Options of accounts `AUTH` and `APP`, users `auth` and `app`, and a
/// callout in `AUTH` with `allowed` accounts.
fn options(allowed: &[&str]) -> Options {
    Options {
        accounts: ["AUTH", "APP"].iter().map(|&a| a.into()).collect(),
        users: vec![user("auth", "AUTH"), user("app", "APP")],
        auth_callout: Some(AuthCallout {
            issuer: nkeys::KeyPair::new_account().public_key(),
            account: Some("AUTH".into()),
            auth_users: vec!["auth".into()],
            xkey: None,
            allowed_accounts: allowed.iter().map(|&a| a.into()).collect(),
        }),
        ..Options::default()
    }
}

fn creds(user: &str, pass: &str) -> Creds {
    Creds {
        user: Some(user.into()),
        pass: Some(pass.into()),
        ..Creds::default()
    }
}

#[test]
fn users_of_the_service_keep_their_login_and_others_call_out() {
    let opts = options(&[]);
    let names = crate::auth::accounts(&opts);
    let auth = Auth::new(&opts, &names).unwrap();
    let c = Callouts::new(&opts, &names, Some(&auth), *b"hash0000").unwrap();
    let hook = |cr: &Creds| {
        let normal = auth.check(
            &mut cr.clone(),
            b"",
            crate::auth::Origin::of(crate::ConnectionType::Standard),
        );
        c.hook(Some(&auth), cr, Some(&normal))
    };
    assert_eq!(hook(&creds("auth", "p")), Hook::Own(1));
    assert_eq!(
        hook(&creds("auth", "wrong")),
        Hook::Own(1),
        "and fails as it does"
    );
    assert!(matches!(hook(&creds("app", "p")), Hook::Call(_)));
    assert!(matches!(hook(&creds("stranger", "x")), Hook::Call(_)));
    assert!(
        matches!(c.hook(None, &Creds::default(), None), Hook::Call(_)),
        "no users at all"
    );
}

#[test]
fn allowed_accounts_keep_the_others_as_configured() {
    let opts = options(&["AUTH"]);
    let names = crate::auth::accounts(&opts);
    let auth = Auth::new(&opts, &names).unwrap();
    let c = Callouts::new(&opts, &names, Some(&auth), *b"hash0000").unwrap();
    let pass = |account| {
        Check::Pass(Grant {
            account,
            perms: None,
        })
    };
    assert_eq!(
        c.hook(Some(&auth), &creds("app", "p"), Some(&pass(2))),
        Hook::Keep
    );
    assert!(matches!(
        c.hook(Some(&auth), &creds("app", "p"), Some(&pass(GLOBAL))),
        Hook::Call(_)
    ));
    assert!(matches!(
        c.hook(Some(&auth), &creds("app", "p"), Some(&Check::Fail)),
        Hook::Call(_)
    ));
    let pending = crate::auth::Pending::for_tests(Grant {
        account: 2,
        perms: None,
    });
    assert!(matches!(
        c.hook(
            Some(&auth),
            &creds("app", "p"),
            Some(&Check::Bcrypt(pending))
        ),
        Hook::Verify(_)
    ));
}

#[test]
fn clients_of_the_callout_account_may_not_ask_for_others() {
    let opts = options(&[]);
    let names = crate::auth::accounts(&opts);
    let perms = guarded(None);
    assert!(!perms.publish(SUBJECT) && perms.publish(b"other"));
    assert!(Callouts::new(&opts, &names, None, *b"hash0000").is_some());
    assert!(Callouts::new(&Options::default(), &names, None, *b"hash0000").is_none());
}

#[test]
fn callouts_that_cannot_run_are_refused() {
    assert!(validate(&options(&[])).is_ok());
    let mut o = options(&[]);
    o.no_system_account = true;
    assert!(validate(&o).unwrap_err().contains("system account"));
    let mut o = options(&[]);
    o.trusted_keys = vec!["O".into()];
    assert!(validate(&o).unwrap_err().contains("operators"));
    let mut o = options(&[]);
    o.auth_callout.as_mut().unwrap().account = Some("$G".into());
    assert!(validate(&o).is_ok(), "$G is always there");
    o.websocket = Some(crate::Websocket {
        auth: crate::WebsocketAuth {
            user: Some(("web".into(), "p".into())),
            ..crate::WebsocketAuth::default()
        },
        ..crate::Websocket::default()
    });
    o.auth_callout.as_mut().unwrap().auth_users = vec!["web".into()];
    assert!(validate(&o).is_ok(), "the WebSocket user is a user");
}

#[test]
fn a_service_user_in_an_account_it_does_not_decide_on_keeps_its_password() {
    let mut opts = options(&["APP"]);
    opts.users[0].login = Login::Password {
        user: "auth".into(),
        password: "$2a$04$x".into(),
    };
    let names = crate::auth::accounts(&opts);
    let auth = Auth::new(&opts, &names).unwrap();
    let c = Callouts::new(&opts, &names, Some(&auth), *b"hash0000").unwrap();
    let pending = crate::auth::Pending::for_tests(Grant {
        account: 1,
        perms: None,
    });
    let normal = Check::Bcrypt(pending);
    assert_eq!(
        c.hook(Some(&auth), &creds("auth", "p"), Some(&normal)),
        Hook::Keep
    );
    let pending = crate::auth::Pending::for_tests(Grant {
        account: 2,
        perms: None,
    });
    let normal = Check::Bcrypt(pending);
    assert_eq!(
        c.hook(Some(&auth), &creds("auth", "p"), Some(&normal)),
        Hook::Own(1)
    );
}
