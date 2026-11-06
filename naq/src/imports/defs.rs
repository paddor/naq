//! Accounts as linking sees them: their exports and imports, from the
//! config or from their JWTs.

use std::time::Duration;

use rustc_hash::FxHashMap;

use crate::jwt::claims::{self, Kind};
use crate::{Export, ExportKind, Import, ImportKind, Latency, Options, ResponseType, Sampling};

/// An account's exports and imports.
#[derive(Debug, Clone, Default)]
pub(crate) struct Def {
    pub(crate) name: String,
    pub(crate) exports: Vec<Export>,
    /// For each export, whether importers need an activation token, and
    /// those revoked, by importer key: `None` for none.
    pub(crate) tokens: Vec<Option<FxHashMap<String, i64>>>,
    /// Imports, with the activation token each gives.
    pub(crate) imports: Vec<(Import, Option<String>)>,
    /// The keys that may sign activation tokens of its exports.
    pub(crate) signing_keys: Vec<String>,
    /// From a JWT: an import that does not link is left out, as
    /// `nats-server` leaves it, where the config's is an error.
    pub(crate) lenient: bool,
    /// How many of the imports, the last, the server added itself: the
    /// services of the system account. They need no authorization, and
    /// one that does not link is left out.
    pub(crate) added: usize,
}

/// The accounts of `names`, the server's by id, as `opts` define them.
pub(crate) fn of(opts: &Options, names: &[String]) -> Vec<Def> {
    names
        .iter()
        .map(|name| {
            if let Some(a) = opts.accounts.iter().find(|a| a.name == *name) {
                return Def {
                    name: name.clone(),
                    exports: a.exports.clone(),
                    tokens: vec![None; a.exports.len()],
                    imports: a.imports.iter().map(|i| (i.clone(), None)).collect(),
                    signing_keys: Vec::new(),
                    lenient: false,
                    added: 0,
                };
            }
            let jwt = opts.resolver_preload.iter().find(|(k, _)| k == name);
            let claims = jwt
                .and_then(|(_, j)| crate::jwt::decode::<claims::Account>(j).ok())
                .filter(|c| crate::jwt::validate::account(c).is_ok());
            claims.map_or_else(
                || Def {
                    name: name.clone(),
                    ..Def::default()
                },
                |c| of_jwt(name, &c.nats),
            )
        })
        .collect()
}

/// The account `name` of JWT body `a`.
pub(crate) fn of_jwt(name: &str, a: &claims::Account) -> Def {
    let mut d = Def {
        name: name.to_owned(),
        signing_keys: a.signing_keys.0.keys().cloned().collect(),
        lenient: true,
        ..Def::default()
    };
    for e in &a.exports {
        let kind = match e.kind {
            Kind::Stream => ExportKind::Stream,
            Kind::Service => ExportKind::Service(service(e)),
            Kind::Unknown => continue,
        };
        d.exports.push(Export {
            subject: e.subject.clone(),
            kind,
            accounts: None,
            token_position: (e.account_token_position > 0)
                .then_some(e.account_token_position as usize),
        });
        d.tokens.push(e.token_req.then(|| e.revocations.clone()));
    }
    for i in &a.imports {
        let Some(im) = import(i) else {
            continue;
        };
        let token = (!i.token.is_empty()).then(|| i.token.clone());
        d.imports.push((im, token));
    }
    d
}

/// How exported service `e` answers.
fn service(e: &claims::Export) -> crate::ServiceExport {
    let d = crate::ServiceExport::default();
    let response = match e.response_type.as_str() {
        "Stream" => ResponseType::Stream,
        "Chunked" => ResponseType::Chunked,
        _ => ResponseType::Singleton,
    };
    let threshold = u64::try_from(e.response_threshold)
        .ok()
        .filter(|&t| t > 0)
        .map_or(d.threshold, Duration::from_nanos);
    let latency = e.service_latency.as_ref().map(|l| Latency {
        sampling: u8::try_from(l.sampling)
            .ok()
            .filter(|&n| n > 0)
            .map_or(Sampling::Headers, |n| Sampling::Percent(n.min(100))),
        subject: l.results.clone(),
    });
    crate::ServiceExport {
        response,
        threshold,
        latency,
    }
}

/// JWT import `i` as an import, as `nats-server` reads it: a stream's
/// `to` is a prefix, `local_subject` its subjects here; a service's
/// `subject` is the importer's, `to` or `local_subject` the other side.
fn import(i: &claims::Import) -> Option<Import> {
    match i.kind {
        Kind::Stream => {
            let to = if !i.local_subject.is_empty() {
                Some(i.local_subject.clone())
            } else if !i.to.is_empty() {
                let dot = if i.to.ends_with('.') { "" } else { "." };
                Some(format!("{}{dot}{}", i.to, i.subject))
            } else {
                None
            };
            Some(Import {
                account: i.account.clone(),
                subject: i.subject.clone(),
                to,
                kind: ImportKind::Stream,
            })
        }
        Kind::Service => {
            let (remote, local) = if !i.local_subject.is_empty() {
                (i.subject.clone(), Some(i.local_subject.clone()))
            } else if !i.to.is_empty() {
                (i.to.clone(), Some(i.subject.clone()))
            } else {
                (i.subject.clone(), None)
            };
            Some(Import {
                account: i.account.clone(),
                subject: remote,
                to: local,
                kind: ImportKind::Service { share: i.share },
            })
        }
        Kind::Unknown => None,
    }
}

/// Whether activation token `token` lets account `importer` import
/// `subject`, a service if `service`, from `exporter` by the export with
/// revocations `revoked`, as `nats-server` checks it.
pub(crate) fn activated(
    exporter: &Def,
    revoked: &FxHashMap<String, i64>,
    importer: &str,
    subject: &str,
    token: Option<&str>,
) -> bool {
    let Some(c) = token.and_then(|t| crate::jwt::decode::<claims::Activation>(t).ok()) else {
        return false;
    };
    if c.out_of_time(crate::jwt::now()) || c.sub != importer {
        return false;
    }
    let by = if c.nats.issuer_account.is_empty() {
        c.iss == exporter.name
    } else {
        c.nats.issuer_account == exporter.name && exporter.signing_keys.contains(&c.iss)
    };
    let held = naq_proto::subject::is_subset(subject.as_bytes(), c.nats.subject.as_bytes());
    let gone = |k: &str| revoked.get(k).is_some_and(|&t| t >= c.iat);
    by && held && !gone(&c.sub) && !gone("*")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::claims::{Export as JwtExport, Import as JwtImport, ServiceLatency};

    /// An account of a service export, a stream export by token, one of
    /// no kind, and imports of each form.
    fn sample() -> claims::Account {
        claims::Account {
            exports: vec![
                JwtExport {
                    subject: "svc".into(),
                    kind: Kind::Service,
                    response_type: "Chunked".into(),
                    response_threshold: 5_000_000_000,
                    service_latency: Some(ServiceLatency {
                        sampling: 0,
                        results: "lat".into(),
                    }),
                    ..JwtExport::default()
                },
                JwtExport {
                    subject: "s.*".into(),
                    kind: Kind::Stream,
                    token_req: true,
                    account_token_position: 2,
                    ..JwtExport::default()
                },
                JwtExport {
                    subject: "x".into(),
                    ..JwtExport::default()
                },
            ],
            imports: vec![
                JwtImport {
                    subject: "a.>".into(),
                    account: "AX".into(),
                    kind: Kind::Stream,
                    local_subject: "b.>".into(),
                    ..JwtImport::default()
                },
                JwtImport {
                    subject: "q".into(),
                    account: "AX".into(),
                    kind: Kind::Service,
                    local_subject: "lq".into(),
                    share: true,
                    ..JwtImport::default()
                },
                JwtImport {
                    subject: "q2".into(),
                    account: "AX".into(),
                    kind: Kind::Service,
                    to: "remote".into(),
                    ..JwtImport::default()
                },
                JwtImport {
                    subject: "u".into(),
                    ..JwtImport::default()
                },
            ],
            ..claims::Account::default()
        }
    }

    #[test]
    fn jwt_exports_and_imports_read_as_nats_server_reads_them() {
        let d = of_jwt("AME", &sample());
        assert!(d.lenient);
        assert_eq!(d.exports.len(), 2, "one of an unknown kind is left out");
        let ExportKind::Service(s) = &d.exports[0].kind else {
            panic!("{:?}", d.exports[0])
        };
        assert_eq!(
            (s.response, s.threshold),
            (ResponseType::Chunked, Duration::from_secs(5))
        );
        assert_eq!(s.latency.as_ref().unwrap().sampling, Sampling::Headers);
        assert_eq!((d.tokens[0].is_none(), d.tokens[1].is_some()), (true, true));
        assert_eq!(d.exports[1].token_position, Some(2));
        let im: Vec<_> = d
            .imports
            .iter()
            .map(|(i, _)| (i.subject.as_str(), i.to.as_deref()))
            .collect();
        assert_eq!(
            im,
            [
                ("a.>", Some("b.>")),
                ("q", Some("lq")),
                ("remote", Some("q2"))
            ]
        );
        assert_eq!(d.imports[1].0.kind, ImportKind::Service { share: true });
    }
}
