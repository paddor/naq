//! Linking imports to exports, checked as `nats-server` checks them.

use naq_proto::subject;

use super::defs::{self, Def};
use super::transform::{self, Transform};
use super::{Imports, Rewrite, ServiceImport, StreamImport};
use crate::{ExportKind, ImportKind, Options, ResponseType, ServiceExport};

/// The imports of every account, by account id: `$G` first, then those of
/// the options in their order.
pub(crate) fn link(opts: &Options) -> Result<Box<[Imports]>, String> {
    link_in(opts, &crate::auth::accounts(opts))
}

/// The imports of the accounts `all_names`, the server's by id, as `opts`
/// define them.
pub(crate) fn link_in(opts: &Options, all_names: &[String]) -> Result<Box<[Imports]>, String> {
    let names: Vec<&str> = all_names.iter().map(String::as_str).collect();
    let all = names.iter().map(|_| Imports::default()).collect();
    let mut defs = defs::of(opts, all_names);
    let system = crate::auth::system(opts, all_names);
    if let Some(s) = system {
        super::system::add(&mut defs, s as usize);
    }
    check_exports(&mut defs, system.is_some())?;
    let mut l = Linker {
        defs: &defs,
        names,
        all,
    };
    // As `nats-server` links them: every stream import, then every service
    // import. A cycle shows on the import that closes it.
    l.streams()?;
    l.services()?;
    Ok(l.all.into())
}

/// The imports of every account of `defs`, by id, all from JWTs: as
/// `link` links them, leaving out what does not hold, with the services
/// of the `system` account if there is one.
pub(crate) fn relink(mut defs: Vec<Def>, system: Option<u32>) -> Vec<Imports> {
    if let Some(s) = system {
        super::system::add(&mut defs, s as usize);
    }
    // Lenient: nothing is an error.
    let _ = check_exports(&mut defs, system.is_some());
    let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    let all = names.iter().map(|_| Imports::default()).collect();
    let mut l = Linker {
        defs: &defs,
        names,
        all,
    };
    let _ = l.streams();
    let _ = l.services();
    l.all
}

/// Checks the exports of every account on their own: those of a config
/// that do not hold are an error, those of a JWT are left out. Latency
/// samples need a `system` account.
fn check_exports(defs: &mut [Def], system: bool) -> Result<(), String> {
    for d in defs {
        let mut keep = Vec::with_capacity(d.exports.len());
        for e in &d.exports {
            let fault = export_fault(e, &d.exports, system);
            keep.push(fault.is_none());
            if let Some(f) = fault
                && !d.lenient
            {
                return Err(format!("account {:?}: export {:?}: {f}", d.name, e.subject));
            }
        }
        let mut k = keep.iter();
        d.exports.retain(|_| k.next() == Some(&true));
        let mut k = keep.iter();
        d.tokens.retain(|_| k.next() == Some(&true));
    }
    Ok(())
}

/// Why export `e`, among `all` of its account, does not hold, if it does
/// not.
fn export_fault(e: &crate::Export, all: &[crate::Export], system: bool) -> Option<&'static str> {
    if !subject::is_valid_filter(e.subject.as_bytes()) {
        return Some("invalid subject");
    }
    if let Some(n) = e.token_position
        && e.subject.split('.').nth(n - 1) != Some("*")
    {
        return Some("the account token position is no `*`");
    }
    let ExportKind::Service(s) = &e.kind else {
        return None;
    };
    let l = s.latency.as_ref()?;
    if s.response != ResponseType::Singleton {
        return Some("latency needs a singleton response type");
    }
    let exported = all.iter().any(|x| {
        matches!(x.kind, ExportKind::Service(_))
            && subject::is_subset(l.subject.as_bytes(), x.subject.as_bytes())
    });
    if !subject::is_valid_literal(l.subject.as_bytes()) || exported {
        return Some("invalid latency subject");
    }
    (!system).then_some("latency needs a system account")
}

/// The export of account `exporter` that an import of `subject`, of the
/// kind `service` says, is of, and its place among the account's exports:
/// the one of that subject, else the first that holds it.
fn export_of<'d>(
    exporter: &'d Def,
    subject: &str,
    service: bool,
) -> Option<(u32, &'d crate::Export)> {
    let of_kind =
        |(_, e): &(usize, &crate::Export)| matches!(e.kind, ExportKind::Service(_)) == service;
    let mut all = exporter.exports.iter().enumerate().filter(of_kind);
    all.clone()
        .find(|(_, e)| e.subject == subject)
        .or_else(|| all.find(|(_, e)| subject::is_subset(subject.as_bytes(), e.subject.as_bytes())))
        .map(|(i, e)| (i as u32, e))
}

/// Whether account `importer` may import `subject` from `exporter` by its
/// export at `at`, with activation token `token` if it gives one.
fn allows(exporter: &Def, at: u32, importer: &str, subject: &str, token: Option<&str>) -> bool {
    let e = &exporter.exports[at as usize];
    if let Some(n) = e.token_position {
        // An import of the export's subject as it is names no account.
        return e.subject != subject && subject.split('.').nth(n - 1) == Some(importer);
    }
    if let Some(Some(revoked)) = exporter.tokens.get(at as usize) {
        return defs::activated(exporter, revoked, importer, subject, token);
    }
    e.accounts
        .as_ref()
        .is_none_or(|a| a.is_empty() || a.iter().any(|x| x == importer))
}

/// What service import of `remote` as `local`, `wild` if `remote` is a
/// filter, takes requests on, and how it rewrites their subjects.
fn rewrite(local: &str, remote: &str, wild: bool) -> Result<(String, Rewrite), String> {
    Ok(if !wild {
        (
            local.to_owned(),
            if local == remote {
                Rewrite::Same
            } else {
                Rewrite::Fixed(remote.as_bytes().into())
            },
        )
    } else if local == remote {
        (local.to_owned(), Rewrite::Same)
    } else {
        let remote = transform::untokenize(remote);
        let tr = Transform::new(&remote, &transform::tokenize(local))
            .map_err(|e| format!("cannot map {local:?} to {remote:?}: {e}"))?;
        let tr = tr
            .reverse()
            .ok_or_else(|| format!("cannot map {local:?} to {remote:?}"))?;
        (transform::untokenize(local), Rewrite::Map(tr))
    })
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
    /// Accounts by id.
    defs: &'o [Def],
    /// Account names by id.
    names: Vec<&'o str>,
    /// Imports by account id.
    all: Vec<Imports>,
}

impl Linker<'_> {
    /// Links the stream imports of every account.
    fn streams(&mut self) -> Result<(), String> {
        let defs = self.defs;
        for (i, d) in defs.iter().enumerate() {
            for (im, token) in d
                .imports
                .iter()
                .filter(|(im, _)| im.kind == ImportKind::Stream)
            {
                match self.stream(&d.name, im, token.as_deref()) {
                    Ok(s) => self.all[i].streams.push(std::sync::Arc::new(s)),
                    Err(_) if d.lenient => {}
                    Err(e) => {
                        return Err(format!(
                            "account {:?}: stream import {:?}: {e}",
                            d.name, im.subject
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Links the service imports of every account.
    fn services(&mut self) -> Result<(), String> {
        let defs = self.defs;
        for (i, d) in defs.iter().enumerate() {
            let own = d.imports.len() - d.added;
            for (k, (im, token)) in d.imports.iter().enumerate() {
                let ImportKind::Service { .. } = im.kind else {
                    continue;
                };
                let added = k >= own;
                let s = match self.service(&d.name, im, token.as_deref(), added) {
                    Ok(s) => s,
                    Err(_) if d.lenient || added => continue,
                    Err(e) => {
                        return Err(format!(
                            "account {:?}: service import {:?}: {e}",
                            d.name, im.subject
                        ));
                    }
                };
                let dup = self.all[i]
                    .services
                    .iter()
                    .find(|x| x.to == s.to && x.from == s.from);
                if let Some(dup) = dup {
                    if d.lenient {
                        continue;
                    }
                    return Err(format!(
                        "account {:?}: service import {:?} twice from account {:?}",
                        d.name,
                        String::from_utf8_lossy(&dup.from),
                        self.names[dup.to as usize]
                    ));
                }
                self.all[i].services.push(std::sync::Arc::new(s));
            }
        }
        Ok(())
    }

    /// Links stream import `im` of account `importer`.
    fn stream(
        &self,
        importer: &str,
        im: &crate::Import,
        token: Option<&str>,
    ) -> Result<StreamImport, String> {
        let (names, all) = (&self.names[..], &self.all[..]);
        let from = id(names, &im.account)?;
        if !subject::is_valid_filter(im.subject.as_bytes()) {
            return Err("invalid subject".into());
        }
        let exporter = &self.defs[from as usize];
        let authorized = export_of(exporter, &im.subject, false)
            .is_some_and(|(at, _)| allows(exporter, at, importer, &im.subject, token));
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
        let all = &self.all;
        let exports = self.defs[from as usize].exports.iter().any(|e| {
            e.kind == ExportKind::Stream && subject::is_subset(to.as_bytes(), e.subject.as_bytes())
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
        token: Option<&str>,
        added: bool,
    ) -> Result<ServiceImport, String> {
        let share = matches!(im.kind, ImportKind::Service { share: true });
        let (names, all) = (&self.names[..], &self.all[..]);
        let to = id(names, &im.account)?;
        // `subject` is the exporter's side, `from` the importer's.
        let remote = &im.subject;
        let local = im.to.clone().unwrap_or_else(|| remote.clone());
        if !subject::is_valid_filter(remote.as_bytes())
            || !subject::is_valid_filter(local.as_bytes())
        {
            return Err("invalid subject".into());
        }
        let exporter = &self.defs[to as usize];
        let Some((at, export)) = export_of(exporter, remote, true)
            .filter(|&(at, _)| added || allows(exporter, at, importer, remote, token))
        else {
            return Err("not authorized".into());
        };
        // `$G` imports only what the server adds.
        let me = names
            .iter()
            .position(|n| *n == importer)
            .map(|i| i as u32)
            .ok_or_else(|| format!("no account {importer:?}"))?;
        let wild = !subject::is_literal(remote.as_bytes());
        let checked = if wild {
            transform::untokenize(&local)
        } else {
            local.clone()
        };
        if service_cycle(all, to, &checked, &mut vec![me]) {
            return Err("the import forms a cycle".into());
        }
        let (from, rewrite) = rewrite(&local, remote, wild)?;
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
