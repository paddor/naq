//! Linking imports to exports, checked as `nats-server` checks them.

use naq_proto::subject;

use super::transform::{self, Transform};
use super::{Imports, Rewrite, ServiceImport, StreamImport};
use crate::{ExportKind, ImportKind, Options, ResponseType, ServiceExport};

/// The imports of every account, by account id: `$G` first, then those of
/// the options in their order.
pub(crate) fn link(opts: &Options) -> Result<Box<[Imports]>, String> {
    let all_names = crate::auth::accounts(opts);
    let names: Vec<&str> = all_names.iter().map(String::as_str).collect();
    let all = names.iter().map(|_| Imports::default()).collect();
    check_exports(opts)?;
    let mut l = Linker { opts, names, all };
    // As `nats-server` links them: every stream import, then every service
    // import. A cycle shows on the import that closes it.
    for (i, a) in opts.accounts.iter().enumerate() {
        for im in a.imports.iter().filter(|im| im.kind == ImportKind::Stream) {
            let s = l.stream(&a.name, im).map_err(|e| {
                format!("account {:?}: stream import {:?}: {e}", a.name, im.subject)
            })?;
            l.all[i + 1].streams.push(std::sync::Arc::new(s));
        }
    }
    for (i, a) in opts.accounts.iter().enumerate() {
        for im in &a.imports {
            let ImportKind::Service { share } = im.kind else {
                continue;
            };
            let s = l.service(&a.name, im, share).map_err(|e| {
                format!("account {:?}: service import {:?}: {e}", a.name, im.subject)
            })?;
            if let Some(dup) = l.all[i + 1]
                .services
                .iter()
                .find(|d| d.to == s.to && d.from == s.from)
            {
                return Err(format!(
                    "account {:?}: service import {:?} twice from account {:?}",
                    a.name,
                    String::from_utf8_lossy(&dup.from),
                    l.names[dup.to as usize]
                ));
            }
            l.all[i + 1].services.push(std::sync::Arc::new(s));
        }
    }
    Ok(l.all.into())
}

/// Checks the exports of every account on their own.
fn check_exports(opts: &Options) -> Result<(), String> {
    for a in &opts.accounts {
        for e in &a.exports {
            let bad =
                |reason: &str| format!("account {:?}: export {:?}: {reason}", a.name, e.subject);
            if !subject::is_valid_filter(e.subject.as_bytes()) {
                return Err(bad("invalid subject"));
            }
            if let Some(n) = e.token_position
                && e.subject.split('.').nth(n - 1) != Some("*")
            {
                return Err(bad("the account token position is no `*`"));
            }
            let ExportKind::Service(s) = &e.kind else {
                continue;
            };
            if let Some(l) = &s.latency {
                if s.response != ResponseType::Singleton {
                    return Err(bad("latency needs a singleton response type"));
                }
                let exported = a.exports.iter().any(|x| {
                    matches!(x.kind, ExportKind::Service(_))
                        && subject::is_subset(l.subject.as_bytes(), x.subject.as_bytes())
                });
                if !subject::is_valid_literal(l.subject.as_bytes()) || exported {
                    return Err(bad("invalid latency subject"));
                }
                if crate::auth::system(opts, &crate::auth::accounts(opts)).is_none() {
                    return Err(bad("latency needs a system account"));
                }
            }
        }
    }
    Ok(())
}

/// The export of account `exporter` that an import of `subject`, of the
/// kind `service` says, is of, and its place among the account's exports:
/// the one of that subject, else the first that holds it.
fn export_of<'o>(
    opts: &'o Options,
    exporter: &str,
    subject: &str,
    service: bool,
) -> Option<(u32, &'o crate::Export)> {
    let a = opts.accounts.iter().find(|a| a.name == exporter)?;
    let of_kind =
        |(_, e): &(usize, &crate::Export)| matches!(e.kind, ExportKind::Service(_)) == service;
    let mut all = a.exports.iter().enumerate().filter(of_kind);
    all.clone()
        .find(|(_, e)| e.subject == subject)
        .or_else(|| all.find(|(_, e)| subject::is_subset(subject.as_bytes(), e.subject.as_bytes())))
        .map(|(i, e)| (i as u32, e))
}

/// Whether account `importer` may import `subject` by export `e`.
fn allows(e: &crate::Export, importer: &str, subject: &str) -> bool {
    if let Some(n) = e.token_position {
        // An import of the export's subject as it is names no account.
        return e.subject != subject && subject.split('.').nth(n - 1) == Some(importer);
    }
    e.accounts
        .as_ref()
        .is_none_or(|a| a.is_empty() || a.iter().any(|x| x == importer))
}

/// The id of account `name`.
fn id(names: &[&str], name: &str) -> Result<u32, String> {
    names
        .iter()
        .position(|n| *n == name && name != "$G")
        .map(|i| i as u32)
        .ok_or_else(|| format!("no account {name:?}"))
}

/// The imports linked so far.
struct Linker<'o> {
    opts: &'o Options,
    /// Account names by id.
    names: Vec<&'o str>,
    /// Imports by account id.
    all: Vec<Imports>,
}

impl Linker<'_> {
    /// Links stream import `im` of account `importer`.
    fn stream(&self, importer: &str, im: &crate::Import) -> Result<StreamImport, String> {
        let (opts, names, all) = (self.opts, &self.names[..], &self.all[..]);
        let from = id(names, &im.account)?;
        if !subject::is_valid_filter(im.subject.as_bytes()) {
            return Err("invalid subject".into());
        }
        let authorized = export_of(opts, &im.account, &im.subject, false)
            .is_some_and(|(_, e)| allows(e, importer, &im.subject));
        if !authorized {
            return Err("not authorized".into());
        }
        let to = im.to.clone().unwrap_or_else(|| im.subject.clone());
        let me = id(names, importer)?;
        for s in [&to, &im.subject] {
            if self.stream_cycle(from, s, &mut vec![me]) {
                return Err("the import forms a cycle".into());
            }
        }
        let rewrite = if subject::is_literal(im.subject.as_bytes()) {
            if to == im.subject {
                Rewrite::Same
            } else {
                Rewrite::Fixed(to.as_bytes().into())
            }
        } else if to == im.subject {
            Rewrite::Same
        } else {
            let tr = Transform::new(&im.subject, &transform::tokenize(&to))
                .map_err(|e| format!("cannot map {:?} to {to:?}: {e}", im.subject))?;
            Rewrite::Map(tr)
        };
        let back = match &rewrite {
            Rewrite::Map(tr) => tr.reverse(),
            _ => None,
        };
        let to = transform::untokenize(&to);
        if all[me as usize]
            .streams
            .iter()
            .any(|s| s.from == from && *s.subject == *im.subject.as_bytes())
        {
            return Err("the stream import exists already".into());
        }
        Ok(StreamImport {
            from,
            subject: im.subject.as_bytes().into(),
            to: to.as_bytes().into(),
            rewrite,
            back,
        })
    }

    /// Whether a stream import of `to` from account `from` would close a
    /// cycle back to an account in `seen`, as `nats-server` follows them:
    /// while the account exports a stream that holds `to`, through its stream
    /// imports that collide with it.
    fn stream_cycle(&self, from: u32, to: &str, seen: &mut Vec<u32>) -> bool {
        let (opts, all) = (self.opts, &self.all);
        let name = self.names[from as usize];
        let exports = opts
            .accounts
            .iter()
            .find(|a| a.name == name)
            .is_some_and(|a| {
                a.exports.iter().any(|e| {
                    e.kind == ExportKind::Stream
                        && subject::is_subset(to.as_bytes(), e.subject.as_bytes())
                })
            });
        if !exports || seen.len() >= MAX_DEPTH {
            return false;
        }
        for s in &all[from as usize].streams {
            if !subject::collide(to.as_bytes(), &s.to) {
                continue;
            }
            if seen.contains(&s.from) {
                return true;
            }
            seen.push(from);
            let next = if subject::is_subset(&s.to, to.as_bytes()) {
                String::from_utf8_lossy(&s.to).into_owned()
            } else {
                to.to_owned()
            };
            if self.stream_cycle(s.from, &next, seen) {
                return true;
            }
        }
        false
    }

    /// Links service import `im` of account `importer`.
    fn service(
        &self,
        importer: &str,
        im: &crate::Import,
        share: bool,
    ) -> Result<ServiceImport, String> {
        let (opts, names, all) = (self.opts, &self.names[..], &self.all[..]);
        let to = id(names, &im.account)?;
        // `subject` is the exporter's side, `from` the importer's.
        let remote = &im.subject;
        let local = im.to.clone().unwrap_or_else(|| remote.clone());
        if !subject::is_valid_filter(remote.as_bytes())
            || !subject::is_valid_filter(local.as_bytes())
        {
            return Err("invalid subject".into());
        }
        let Some((at, export)) =
            export_of(opts, &im.account, remote, true).filter(|(_, e)| allows(e, importer, remote))
        else {
            return Err("not authorized".into());
        };
        let me = id(names, importer)?;
        let wild = !subject::is_literal(remote.as_bytes());
        let checked = if wild {
            transform::untokenize(&local)
        } else {
            local.clone()
        };
        if service_cycle(all, to, &checked, &mut vec![me]) {
            return Err("the import forms a cycle".into());
        }
        let (from, rewrite) = if !wild {
            (
                local.clone(),
                if local == *remote {
                    Rewrite::Same
                } else {
                    Rewrite::Fixed(remote.as_bytes().into())
                },
            )
        } else if local == *remote {
            (local.clone(), Rewrite::Same)
        } else {
            let remote = transform::untokenize(remote);
            let tr = Transform::new(&remote, &transform::tokenize(&local))
                .map_err(|e| format!("cannot map {local:?} to {remote:?}: {e}"))?;
            let tr = tr
                .reverse()
                .ok_or_else(|| format!("cannot map {local:?} to {remote:?}"))?;
            (transform::untokenize(&local), Rewrite::Map(tr))
        };
        let service = match &export.kind {
            ExportKind::Service(s) => s.clone(),
            ExportKind::Stream => ServiceExport::default(),
        };
        Ok(ServiceImport {
            to,
            from: from.as_bytes().into(),
            subject: remote.as_bytes().into(),
            rewrite,
            share,
            service,
            export: (to, at),
        })
    }
}

/// Most accounts a cycle search walks, as in `nats-server`.
const MAX_DEPTH: usize = 1024;

/// Whether a service import of `from` into account `to` would close a
/// cycle back to an account in `seen`, as `nats-server` follows them:
/// through the service imports of `to` whose subject in their exporter
/// collides with it.
fn service_cycle(all: &[Imports], to: u32, from: &str, seen: &mut Vec<u32>) -> bool {
    if seen.len() >= MAX_DEPTH {
        return false;
    }
    for s in &all[to as usize].services {
        if !subject::collide(from.as_bytes(), &s.subject) {
            continue;
        }
        if seen.contains(&s.to) {
            return true;
        }
        seen.push(to);
        let next = if subject::is_subset(&s.from, from.as_bytes()) {
            String::from_utf8_lossy(&s.from).into_owned()
        } else {
            from.to_owned()
        };
        if service_cycle(all, s.to, &next, seen) {
            return true;
        }
    }
    false
}
