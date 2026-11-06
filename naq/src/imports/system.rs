//! The services of the system account that the others import, as
//! `nats-server` adds them: its exports, and four imports of every other
//! account, unless they are there already.

use naq_proto::subject;

use super::defs::Def;
use crate::{Export, ExportKind, Import, ImportKind, ResponseType, ServiceExport};

/// The services the system account exports: the account requests that
/// name their importer in token 4, the count of subscribers, and the
/// users' own details.
fn exports() -> [Export; 4] {
    let service = |subject: &str, response, token_position| Export {
        subject: subject.to_owned(),
        kind: ExportKind::Service(ServiceExport {
            response,
            ..ServiceExport::default()
        }),
        accounts: None,
        token_position,
    };
    [
        service("$SYS.REQ.ACCOUNT.*.CONNZ", ResponseType::Stream, Some(4)),
        service("$SYS.REQ.ACCOUNT.*.STATZ", ResponseType::Stream, Some(4)),
        service("$SYS.DEBUG.SUBSCRIBERS", ResponseType::Singleton, None),
        service("$SYS.REQ.USER.*.INFO", ResponseType::Singleton, None),
    ]
}

/// Adds the services of system account `defs[system]` to `defs`: its
/// exports, its import of its users' details, and the imports of the
/// others.
pub(crate) fn add(defs: &mut [Def], system: usize) {
    let Some(sys) = defs.get_mut(system) else {
        return;
    };
    let name = sys.name.clone();
    for e in exports() {
        // An export of the config that holds it comes first.
        let held = sys.exports.iter().any(|x| {
            matches!(x.kind, ExportKind::Service(_))
                && subject::is_subset(e.subject.as_bytes(), x.subject.as_bytes())
        });
        if !held {
            sys.exports.push(e);
            sys.tokens.push(None);
        }
    }
    import(
        sys,
        &name,
        "$SYS.REQ.USER.INFO",
        "$SYS.REQ.USER.{}.INFO",
        true,
    );
    for (_, d) in defs.iter_mut().enumerate().filter(|&(i, _)| i != system) {
        import(
            d,
            &name,
            "$SYS.REQ.ACCOUNT.PING.CONNZ",
            "$SYS.REQ.ACCOUNT.{}.CONNZ",
            false,
        );
        import(
            d,
            &name,
            "$SYS.REQ.SERVER.PING.CONNZ",
            "$SYS.REQ.ACCOUNT.{}.CONNZ",
            false,
        );
        import(
            d,
            &name,
            "$SYS.REQ.ACCOUNT.PING.STATZ",
            "$SYS.REQ.ACCOUNT.{}.STATZ",
            false,
        );
        import(
            d,
            &name,
            "$SYS.REQ.USER.INFO",
            "$SYS.REQ.USER.{}.INFO",
            true,
        );
    }
}

/// Adds to `d` the import of service `to` of account `from`, with `{}` in
/// it the name of `d`, as its subject `local`; unless `d` imports `local`
/// from `from` already.
fn import(d: &mut Def, from: &str, local: &str, to: &str, share: bool) {
    let has = d.imports.iter().any(|(i, _)| {
        i.account == from
            && matches!(i.kind, ImportKind::Service { .. })
            && i.to.as_deref().unwrap_or(&i.subject) == local
    });
    if has {
        return;
    }
    let i = Import {
        account: from.to_owned(),
        subject: to.replace("{}", &d.name),
        to: Some(local.to_owned()),
        kind: ImportKind::Service { share },
    };
    d.imports.push((i, None));
    d.added += 1;
}
