//! The blocking checks nats-io/jwt makes of an account JWT before
//! `nats-server` takes the account: one that fails is no account at all.

use naq_proto::subject;

use super::claims::{self, Kind, NO_LIMIT};
use super::{Claims, decode};

/// Why the account of claims `c` does not hold, if it does not.
pub(crate) fn account(c: &Claims<claims::Account>) -> Result<(), String> {
    let a = &c.nats;
    imports(&c.sub, &a.imports)?;
    exports(&a.exports)?;
    let l = &a.limits;
    let more =
        |n: usize, limit: i64| limit != NO_LIMIT && i64::try_from(n).is_ok_and(|n| n > limit);
    if more(a.imports.len(), l.imports) {
        return Err("the account contains more imports than allowed by the operator".into());
    }
    if more(a.exports.len(), l.exports) {
        return Err("the account contains more exports than allowed by the operator".into());
    }
    if l.exports != NO_LIMIT
        && !l.wildcards
        && a.exports
            .iter()
            .any(|e| !subject::is_literal(e.subject.as_bytes()))
    {
        return Err(
            "the account contains wildcard exports that are not allowed by the operator".into(),
        );
    }
    for (key, scope) in &a.signing_keys.0 {
        let k = scope.as_ref().map_or(key, |s| &s.key);
        if !super::is_key(k, 'A') {
            return Err(format!("{k:?} is not a valid account signing key"));
        }
    }
    // Not served: an account that needs them is refused, not half served.
    if !a.mappings.is_empty() {
        return Err("subject mappings are not supported".into());
    }
    if !a.authorization.auth_users.is_empty() {
        return Err("auth callout is not supported".into());
    }
    Ok(())
}

/// Whether `s` is a subject an export or import may name.
fn valid(s: &str) -> bool {
    !s.is_empty() && !s.contains(' ') && subject::is_valid_filter(s.as_bytes())
}

/// The imports of account `key`.
fn imports(key: &str, all: &[claims::Import]) -> Result<(), String> {
    let mut services: Vec<(&str, &str)> = Vec::new();
    for i in all {
        let bad = |why: &str| Err(format!("import {:?}: {why}", i.subject));
        if i.kind == Kind::Unknown {
            return bad("invalid import type");
        }
        if i.kind == Kind::Service && i.allow_trace {
            return bad("AllowTrace only valid for stream import");
        }
        if i.account.is_empty() {
            return bad("account to import from is not specified");
        }
        if !valid(&i.subject) || (!i.local_subject.is_empty() && !valid(&i.local_subject)) {
            return bad("invalid subject");
        }
        if !i.local_subject.is_empty() && !i.to.is_empty() {
            return bad("Local Subject replaces To");
        }
        if i.share && i.kind != Kind::Service {
            return bad("sharing information is only valid for services");
        }
        if !i.token.is_empty() {
            token(key, i)?;
        }
        if i.kind == Kind::Service {
            let mine = [&i.to, &i.local_subject, &i.subject]
                .into_iter()
                .find(|s| !s.is_empty())
                .map_or("", String::as_str);
            let overlaps = services.iter().any(|&(acc, other)| {
                acc == i.account
                    && (subject::is_subset(mine.as_bytes(), other.as_bytes())
                        || subject::is_subset(other.as_bytes(), mine.as_bytes()))
            });
            if overlaps {
                return bad("overlapping subject namespace in the same account");
            }
            services.push((&i.account, mine));
        }
    }
    Ok(())
}

/// The activation token of import `i` of account `key`.
fn token(key: &str, i: &claims::Import) -> Result<(), String> {
    let bad = |why: &str| Err(format!("import {:?}: {why}", i.subject));
    let Ok(act) = decode::<claims::Activation>(&i.token) else {
        return bad("invalid activation token");
    };
    if act.iss != i.account && act.nats.issuer_account != i.account {
        return bad("activation token doesn't match account for import");
    }
    if act.sub != key {
        return bad("activation token doesn't match account it is being included in");
    }
    if act.nats.kind != i.kind {
        return bad("mismatch between token import type and type of import");
    }
    let subj = if i.kind == Kind::Service && !i.to.is_empty() {
        &i.to
    } else {
        &i.subject
    };
    if !subject::is_subset(subj.as_bytes(), act.nats.subject.as_bytes()) {
        return bad("activation token import subject doesn't match import");
    }
    Ok(())
}

/// The exports of an account.
fn exports(all: &[claims::Export]) -> Result<(), String> {
    for e in all {
        let bad = |why: &str| Err(format!("export {:?}: {why}", e.subject));
        let service = e.kind == Kind::Service;
        match (e.kind, e.response_type.as_str()) {
            (Kind::Unknown, _) => return bad("invalid export type"),
            (Kind::Service, "" | "Singleton" | "Stream" | "Chunked") | (Kind::Stream, "") => {}
            _ => return bad("invalid response type"),
        }
        if e.kind == Kind::Stream && e.allow_trace {
            return bad("AllowTrace only valid for service export");
        }
        if let Some(l) = &e.service_latency {
            if !service {
                return bad("latency tracking only permitted for services");
            }
            if !(0..=100).contains(&l.sampling)
                || !valid(&l.results)
                || !subject::is_literal(l.results.as_bytes())
            {
                return bad("invalid latency");
            }
        }
        if e.response_threshold < 0 || (e.response_threshold > 0 && !service) {
            return bad("invalid response threshold");
        }
        if !valid(&e.subject) {
            return bad("invalid subject");
        }
        if e.account_token_position > 0 {
            let at = e
                .subject
                .split('.')
                .nth(e.account_token_position as usize - 1);
            if at != Some("*") {
                return bad("the account token position must match a *");
            }
        }
    }
    for kind in [Kind::Stream, Kind::Service] {
        let subjects: Vec<&str> = all
            .iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.subject.as_str())
            .collect();
        for (i, a) in subjects.iter().enumerate() {
            if subjects
                .iter()
                .enumerate()
                .any(|(j, b)| i != j && subject::is_subset(a.as_bytes(), b.as_bytes()))
            {
                return Err(format!("export subject {a:?} is held by another"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::claims::{Account, AccountLimits, Export, Import, ServiceLatency, SigningKeys};

    fn open() -> AccountLimits {
        AccountLimits {
            imports: NO_LIMIT,
            exports: NO_LIMIT,
            wildcards: true,
            ..AccountLimits::default()
        }
    }

    fn check(a: Account) -> Result<(), String> {
        account(&Claims {
            sub: "AKEY".into(),
            nats: a,
            ..Claims::default()
        })
    }

    fn import(f: impl FnOnce(&mut Import)) -> Account {
        let mut i = Import {
            subject: "s".into(),
            account: "AX".into(),
            kind: Kind::Stream,
            ..Import::default()
        };
        f(&mut i);
        Account {
            imports: vec![i],
            limits: open(),
            ..Account::default()
        }
    }

    fn export(f: impl FnOnce(&mut Export)) -> Account {
        let mut e = Export {
            subject: "s".into(),
            kind: Kind::Service,
            ..Export::default()
        };
        f(&mut e);
        Account {
            exports: vec![e],
            limits: open(),
            ..Account::default()
        }
    }

    #[test]
    fn imports_that_nats_io_jwt_refuses_refuse_the_account() {
        assert!(check(import(|_| {})).is_ok());
        for (a, why) in [
            (import(|i| i.kind = Kind::Unknown), "invalid import type"),
            (
                import(|i| {
                    i.kind = Kind::Service;
                    i.allow_trace = true;
                }),
                "AllowTrace",
            ),
            (import(|i| i.account.clear()), "not specified"),
            (import(|i| i.subject = "a..b".into()), "invalid subject"),
            (
                import(|i| {
                    i.local_subject = "l".into();
                    i.to = "t".into();
                }),
                "replaces To",
            ),
            (import(|i| i.share = true), "only valid for services"),
            (
                import(|i| i.token = "x.y.z".into()),
                "invalid activation token",
            ),
        ] {
            let e = check(a).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
        let mut two = import(|i| i.kind = Kind::Service);
        two.imports.push(Import {
            subject: "s.>".into(),
            ..two.imports[0].clone()
        });
        two.imports[0].subject = "s.x".into();
        assert!(check(two).unwrap_err().contains("overlapping"));
    }

    #[test]
    fn exports_that_overlap_refuse_the_account() {
        let mut held = export(|e| e.subject = "s.>".into());
        held.exports.push(Export {
            subject: "s.x".into(),
            ..held.exports[0].clone()
        });
        assert!(check(held).unwrap_err().contains("held by another"));
    }

    #[test]
    fn exports_that_nats_io_jwt_refuses_refuse_the_account() {
        assert!(check(export(|_| {})).is_ok());
        for (a, why) in [
            (export(|e| e.kind = Kind::Unknown), "invalid export type"),
            (
                export(|e| e.response_type = "Many".into()),
                "invalid response type",
            ),
            (
                export(|e| {
                    e.kind = Kind::Stream;
                    e.response_type = "Stream".into();
                }),
                "invalid response type",
            ),
            (
                export(|e| {
                    e.kind = Kind::Stream;
                    e.allow_trace = true;
                }),
                "AllowTrace",
            ),
            (
                export(|e| {
                    e.kind = Kind::Stream;
                    e.service_latency = Some(ServiceLatency {
                        sampling: 1,
                        results: "r".into(),
                    });
                }),
                "only permitted for services",
            ),
            (
                export(|e| {
                    e.service_latency = Some(ServiceLatency {
                        sampling: 101,
                        results: "r".into(),
                    });
                }),
                "invalid latency",
            ),
            (
                export(|e| e.response_threshold = -1),
                "invalid response threshold",
            ),
            (export(|e| e.subject = "a b".into()), "invalid subject"),
            (
                export(|e| {
                    e.subject = "a.b".into();
                    e.account_token_position = 2;
                }),
                "must match a *",
            ),
        ] {
            let e = check(a).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
    }

    #[test]
    fn limits_and_keys_that_nats_io_jwt_refuses_refuse_the_account() {
        let mut a = import(|_| {});
        a.limits.imports = 0;
        assert!(check(a).unwrap_err().contains("more imports"));
        let mut a = export(|_| {});
        a.limits.exports = 0;
        assert!(check(a).unwrap_err().contains("more exports"));
        let mut a = export(|e| e.subject = "s.*".into());
        a.limits.exports = 5;
        a.limits.wildcards = false;
        assert!(check(a).unwrap_err().contains("wildcard exports"));
        let a = Account {
            limits: open(),
            signing_keys: SigningKeys([("AXX".to_owned(), None)].into_iter().collect()),
            ..Account::default()
        };
        assert!(
            check(a)
                .unwrap_err()
                .contains("not a valid account signing key")
        );
        let a = Account {
            limits: open(),
            mappings: [("a".to_owned(), serde_json::json!([]))]
                .into_iter()
                .collect(),
            ..Account::default()
        };
        assert!(check(a).unwrap_err().contains("mappings"));
        let a = Account {
            limits: open(),
            authorization: crate::jwt::claims::Authorization {
                auth_users: vec!["U".into()],
                ..Default::default()
            },
            ..Account::default()
        };
        assert!(check(a).unwrap_err().contains("auth callout"));
    }
}
