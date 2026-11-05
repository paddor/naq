//! `exports` and `imports` of an account in `accounts`.

use super::parse::{Item, Value};
use super::{Bad, string};
use crate::{
    Export, ExportKind, Import, ImportKind, Latency, ResponseType, Sampling, ServiceExport,
};

/// An `exports` list: each item a map of `stream` or `service`, and what
/// goes with it.
pub(super) fn exports(item: &Item) -> Result<Vec<Export>, Bad> {
    list(item, "exports")?.iter().map(export).collect()
}

/// An `imports` list: each item a map of `stream` or `service`, and what
/// goes with it.
pub(super) fn imports(item: &Item) -> Result<Vec<Import>, Bad> {
    list(item, "imports")?.iter().map(import).collect()
}

fn list<'i>(item: &'i Item, what: &str) -> Result<&'i [Item], Bad> {
    match &item.value {
        Value::Array(a) => Ok(a),
        _ => Err((item.line, format!("{what}: expected a list"))),
    }
}

fn entries<'i>(item: &'i Item, what: &str) -> Result<&'i [(String, Item)], Bad> {
    match &item.value {
        Value::Map(m) => Ok(m),
        _ => Err((item.line, format!("{what}: expected a map"))),
    }
}

/// The parts of an export item, before they make an [`Export`].
#[derive(Default)]
struct ExportItem {
    stream: Option<String>,
    service: Option<String>,
    accounts: Option<Vec<String>>,
    response: Option<ResponseType>,
    threshold: Option<std::time::Duration>,
    latency: Option<Latency>,
    token_position: Option<usize>,
}

fn export(item: &Item) -> Result<Export, Bad> {
    let mut e = ExportItem::default();
    for (key, v) in entries(item, "exports")? {
        let key = key.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("exports: {key}: {reason}"));
        let text = || string(v).ok_or_else(|| bad("expected a string"));
        match key.as_str() {
            "stream" => e.stream = Some(text()?),
            "service" => e.service = Some(text()?),
            "accounts" => e.accounts = Some(names(v).ok_or_else(|| bad("expected names"))?),
            "response" | "response_type" => {
                if e.response.is_some() {
                    return Err(bad("a second response type"));
                }
                e.response = Some(response(&text()?).ok_or_else(|| bad("unknown response type"))?);
            }
            "threshold" | "response_threshold" | "response_max_time" | "response_time" => {
                if e.threshold.is_some() {
                    return Err(bad("a second response threshold"));
                }
                e.threshold = Some(super::duration(v).map_err(|r| bad(&r))?);
            }
            "latency" => e.latency = Some(latency(v)?),
            "account_token_position" => {
                let n = super::int::<usize>(v).filter(|&n| n > 0);
                e.token_position = Some(n.ok_or_else(|| bad("expected a token position"))?);
            }
            "allow_trace" => flag_off(v, &key, "exports")?,
            _ => return Err(bad("not supported")),
        }
    }
    e.finish(item.line)
}

impl ExportItem {
    /// The export the parts make, from the item at `line`.
    fn finish(self, line: u32) -> Result<Export, Bad> {
        let e = self;
        match (e.stream, e.service) {
            (Some(_), Some(_)) => Err((line, "exports: both a stream and a service".into())),
            (None, None) => Err((line, "exports: expected a stream or a service".into())),
            (Some(subject), None) => {
                if e.response.is_some() || e.threshold.is_some() {
                    return Err((line, "exports: a response directive on a stream".into()));
                }
                if e.latency.is_some() {
                    return Err((line, "exports: a latency directive on a stream".into()));
                }
                Ok(Export {
                    subject,
                    kind: ExportKind::Stream,
                    accounts: e.accounts,
                    token_position: e.token_position,
                })
            }
            (None, Some(subject)) => {
                let d = ServiceExport::default();
                let service = ServiceExport {
                    response: e.response.unwrap_or(d.response),
                    threshold: e.threshold.unwrap_or(d.threshold),
                    latency: e.latency,
                };
                Ok(Export {
                    subject,
                    kind: ExportKind::Service(service),
                    accounts: e.accounts,
                    token_position: e.token_position,
                })
            }
        }
    }
}

/// A list of account names; an empty one is none, as in `nats-server`.
fn names(item: &Item) -> Option<Vec<String>> {
    let Value::Array(a) = &item.value else {
        return None;
    };
    a.iter().map(string).collect()
}

fn response(name: &str) -> Option<ResponseType> {
    match name.to_ascii_lowercase().as_str() {
        "single" | "singleton" => Some(ResponseType::Singleton),
        "stream" => Some(ResponseType::Stream),
        "chunk" | "chunked" => Some(ResponseType::Chunked),
        _ => None,
    }
}

/// `latency`: the subject samples go to, or `{ sampling, subject }`.
fn latency(item: &Item) -> Result<Latency, Bad> {
    let bad = |line: u32, reason: &str| (line, format!("exports: latency: {reason}"));
    let entries = match &item.value {
        Value::Str(s) => {
            return Ok(Latency {
                sampling: Sampling::Percent(100),
                subject: s.clone(),
            });
        }
        Value::Map(m) => m,
        _ => return Err(bad(item.line, "expected a subject or a map")),
    };
    let (mut sampling, mut subject) = (Sampling::Percent(100), None);
    // `nats-server` looks these up as written, and skips any other key.
    for (key, v) in entries {
        match key.as_str() {
            "sampling" => {
                sampling = self::sampling(v)
                    .ok_or_else(|| bad(v.line, "bad sampling, should be 1-100% or headers"))?;
            }
            "subject" => {
                subject = Some(string(v).ok_or_else(|| bad(v.line, "expected a subject"))?);
            }
            _ => {}
        }
    }
    let subject = subject.ok_or_else(|| bad(item.line, "a subject is required"))?;
    Ok(Latency { sampling, subject })
}

/// A percent, as a number or `"N%"`, or `"headers"`.
fn sampling(item: &Item) -> Option<Sampling> {
    let n = match &item.value {
        Value::Int(n) => *n,
        Value::Str(s) if s.eq_ignore_ascii_case("headers") => return Some(Sampling::Headers),
        Value::Str(s) => s.trim_end_matches('%').trim().parse().ok()?,
        _ => return None,
    };
    u8::try_from(n)
        .ok()
        .filter(|n| (1..=100).contains(n))
        .map(Sampling::Percent)
}

/// A key naq takes only when off: message tracing is not served.
fn flag_off(v: &Item, key: &str, what: &str) -> Result<(), Bad> {
    match v.value {
        Value::Bool(false) => Ok(()),
        Value::Bool(true) => Err((v.line, format!("{what}: {key}: not supported"))),
        _ => Err((v.line, format!("{what}: {key}: expected true or false"))),
    }
}

fn import(item: &Item) -> Result<Import, Bad> {
    let (mut stream, mut service, mut prefix, mut to, mut share) = (None, None, None, None, None);
    for (key, v) in entries(item, "imports")? {
        let key = key.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("imports: {key}: {reason}"));
        let text = || string(v).ok_or_else(|| bad("expected a string"));
        match key.as_str() {
            "stream" => stream = Some(remote(v, &key)?),
            "service" => service = Some(remote(v, &key)?),
            "prefix" => prefix = Some(text()?),
            "to" => to = Some(text()?),
            "share" => match v.value {
                Value::Bool(b) => share = Some(b),
                _ => return Err(bad("expected true or false")),
            },
            "allow_trace" => flag_off(v, &key, "imports")?,
            _ => return Err(bad("not supported")),
        }
    }
    let line = item.line;
    let bad = |reason: &str| (line, format!("imports: {reason}"));
    let ((account, subject), kind) = match (stream, service) {
        (Some(_), Some(_)) => return Err(bad("both a stream and a service")),
        (None, None) => return Err(bad("expected a stream or a service")),
        (Some(r), None) => {
            if share.is_some() {
                return Err(bad("share on a stream"));
            }
            (r, ImportKind::Stream)
        }
        (None, Some(r)) => {
            if prefix.is_some() {
                return Err(bad("a prefix on a service"));
            }
            let share = share.unwrap_or(false);
            (r, ImportKind::Service { share })
        }
    };
    if let Some(p) = prefix {
        if to.is_some() {
            return Err(bad("a stream import cannot have both a prefix and a to"));
        }
        if !naq_proto::subject::is_valid_literal(p.trim_end_matches('.').as_bytes()) {
            return Err(bad("a stream import prefix cannot have wildcards"));
        }
        let dot = if p.ends_with('.') { "" } else { "." };
        to = Some(format!("{p}{dot}{subject}"));
    }
    Ok(Import {
        account,
        subject,
        to,
        kind,
    })
}

/// `{ account, subject }`: the account imported from and its subjects.
fn remote(item: &Item, key: &str) -> Result<(String, String), Bad> {
    let bad = |line: u32, reason: &str| (line, format!("imports: {key}: {reason}"));
    let Value::Map(m) = &item.value else {
        return Err(bad(item.line, "expected an account and a subject"));
    };
    let (mut account, mut subject) = (None, None);
    for (k, v) in m {
        let text = || string(v).ok_or_else(|| bad(v.line, "expected a string"));
        match k.to_ascii_lowercase().as_str() {
            "account" => account = Some(text()?),
            "subject" => subject = Some(text()?),
            k => return Err(bad(v.line, &format!("{k}: not supported"))),
        }
    }
    match (account, subject) {
        (Some(a), Some(s)) if !a.is_empty() && !s.is_empty() => Ok((a, s)),
        _ => Err(bad(item.line, "expected an account and a subject")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exports of the `exports` key in `text`.
    fn parse(text: &str) -> Result<Vec<Export>, Bad> {
        let map = super::super::parse::parse(text, None).unwrap();
        exports(&map[0].1)
    }

    #[test]
    fn latency_takes_a_subject_or_a_sampling_and_a_subject() {
        let all = parse(
            "exports: [{service: a, latency: lat}, {service: b, latency: {sampling: \"50%\", subject: l, other: 1}},\n\
             {service: c, latency: {sampling: headers, subject: l}}, {service: d, latency: {sampling: 7, subject: l}, allow_trace: false}]",
        )
        .unwrap();
        let samplings: Vec<_> = all
            .iter()
            .map(|e| match &e.kind {
                ExportKind::Service(ServiceExport {
                    latency: Some(l), ..
                }) => (l.sampling, l.subject.as_str()),
                k => panic!("{k:?}"),
            })
            .collect();
        assert_eq!(
            samplings,
            [
                (Sampling::Percent(100), "lat"),
                (Sampling::Percent(50), "l"),
                (Sampling::Headers, "l"),
                (Sampling::Percent(7), "l"),
            ]
        );
    }

    #[test]
    fn a_directive_twice_or_of_the_wrong_kind_is_an_error() {
        for (text, reason) in [
            (
                "exports: [{service: a, response: single, response_type: stream}]",
                "exports: response_type: a second response type",
            ),
            (
                "exports: [{service: a, threshold: 1s, response_time: 2s}]",
                "exports: response_time: a second response threshold",
            ),
            (
                "exports: [{service: a, latency: 1}]",
                "exports: latency: expected a subject or a map",
            ),
            (
                "exports: [{service: a, latency: {subject: 1}}]",
                "exports: latency: expected a subject",
            ),
            (
                "exports: [{service: a, allow_trace: 1}]",
                "exports: allow_trace: expected true or false",
            ),
            (
                "exports: [{service: a, account_token_position: 0}]",
                "exports: account_token_position: expected a token position",
            ),
            (
                "exports: [{service: a, accounts: B}]",
                "exports: accounts: expected names",
            ),
        ] {
            assert_eq!(parse(text).unwrap_err().1, reason, "{text}");
        }
    }

    #[test]
    fn an_import_item_names_one_kind_of_remote() {
        let map = super::super::parse::parse(
            "imports: [{stream: {account: A, subject: s}, service: {account: A, subject: s}}]\n\
             i2: [{service: {account: A, subject: s}, share: 1}]\n\
             i3: [{service: {account: A, subject: s, weight: 1}}]\n\
             i4: [{service: a}]\n\
             i5: [{}]\n\
             i6: [{stream: {account: A, subject: s}, allow_trace: false, prefix: \"p.\"}]",
            None,
        )
        .unwrap();
        let reasons: Vec<_> = map[..5]
            .iter()
            .map(|(_, item)| imports(item).unwrap_err().1)
            .collect();
        assert_eq!(
            reasons,
            [
                "imports: both a stream and a service",
                "imports: share: expected true or false",
                "imports: service: weight: not supported",
                "imports: service: expected an account and a subject",
                "imports: expected a stream or a service",
            ]
        );
        let ok = imports(&map[5].1).unwrap();
        assert_eq!(ok[0].to.as_deref(), Some("p.s"));
    }
}
