//! Subjects shared between accounts: exports, and the imports of them,
//! linked and checked as `nats-server` checks them.

mod info;
pub(crate) mod latency;
mod link;
pub(crate) mod service;
pub(crate) mod shadow;
mod transform;

pub(crate) use link::link;
pub(crate) use transform::Transform;

use naq_proto::subject;

use crate::ServiceExport;

/// How a message's subject changes on its way into the importer, or the
/// exporter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Rewrite {
    /// It stays: both sides are the same filter.
    Same,
    /// It becomes this subject, whatever it was: the other side is
    /// literal.
    Fixed(Box<[u8]>),
    /// It is transformed.
    Map(Transform),
}

/// A stream import: messages of the exporter on `subject`, delivered in
/// the importer on `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamImport {
    /// The exporting account's id.
    pub(crate) from: u32,
    /// The subjects in the exporter.
    pub(crate) subject: Box<[u8]>,
    /// The subjects in the importer.
    pub(crate) to: Box<[u8]>,
    /// From the exporter's subject to the importer's.
    pub(crate) rewrite: Rewrite,
    /// The transform back, with [`Rewrite::Map`].
    pub(crate) back: Option<Transform>,
}

impl StreamImport {
    /// The subject a shadow of a subscription to `filter` in the importer
    /// has in the exporter, if the import overlaps `filter`: as
    /// `nats-server` makes it.
    pub(crate) fn shadow(&self, filter: &[u8]) -> Option<Vec<u8>> {
        let to = &*self.to;
        if filter == to {
            return Some(self.subject.to_vec());
        }
        let narrow = |f: &[u8]| -> Vec<u8> {
            match (&self.rewrite, &self.back) {
                (Rewrite::Map(_), Some(back)) => {
                    let mut out = Vec::with_capacity(f.len());
                    back.apply(f, &mut out);
                    out
                }
                (Rewrite::Same, _) => f.to_vec(),
                _ => self.subject.to_vec(),
            }
        };
        if subject::is_subset(filter, to) {
            return Some(narrow(filter));
        }
        let mut tokens: Vec<&[u8]> = filter.split(|&b| b == b'.').collect();
        let wild = tokens.iter().any(|t| *t == b"*") || tokens.last() == Some(&&b">"[..]);
        if !wild {
            return None;
        }
        if subject::is_subset(to, filter) {
            return Some(self.subject.to_vec());
        }
        // A partial overlap: the filter narrowed to the import, token by
        // token.
        let im: Vec<&[u8]> = to.split(|&b| b == b'.').collect();
        for (t, i) in tokens.iter_mut().zip(&im) {
            if *t == b"*" && *i != b">" {
                *t = i;
            }
        }
        let last = tokens.len() - 1;
        if tokens[last] == b">" && im.len() >= tokens.len() {
            tokens[last] = im[last];
            tokens.extend_from_slice(&im[last + 1..]);
        }
        let overlap = tokens.join(&b'.');
        if !subject::is_subset(&overlap, to) {
            return None;
        }
        Some(match (&self.rewrite, &self.back) {
            (Rewrite::Map(_), Some(back)) => {
                let mut out = Vec::with_capacity(overlap.len());
                back.apply(&overlap, &mut out);
                out
            }
            _ => overlap,
        })
    }

    /// Writes the subject a message on `subject` in the exporter has in
    /// the importer into `out`.
    pub(crate) fn deliver_as(&self, subject: &[u8], out: &mut Vec<u8>) {
        match &self.rewrite {
            Rewrite::Same => out.extend_from_slice(subject),
            Rewrite::Fixed(to) => out.extend_from_slice(to),
            Rewrite::Map(tr) => tr.apply(subject, out),
        }
    }
}

/// A service import: requests of the importer on `from`, sent to the
/// exporter on `subject`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceImport {
    /// The exporting account's id.
    pub(crate) to: u32,
    /// The subjects in the importer: its import subscription.
    pub(crate) from: Box<[u8]>,
    /// The subjects in the exporter.
    pub(crate) subject: Box<[u8]>,
    /// From the importer's subject to the exporter's.
    pub(crate) rewrite: Rewrite,
    /// Requests carry the details of the requester.
    pub(crate) share: bool,
    /// How the service answers, from its export.
    pub(crate) service: ServiceExport,
    /// The export it imports.
    pub(crate) export: ExportId,
}

/// An export: the account's id and the export's place among its exports.
pub(crate) type ExportId = (u32, u32);

impl ServiceImport {
    /// Writes the subject a request on `subject` in the importer has in
    /// the exporter into `out`.
    pub(crate) fn rewrite_into(&self, subject: &[u8], out: &mut Vec<u8>) {
        match &self.rewrite {
            Rewrite::Same => out.extend_from_slice(subject),
            Rewrite::Fixed(to) => out.extend_from_slice(to),
            Rewrite::Map(tr) => tr.apply(subject, out),
        }
    }
}

/// The imports of one account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Imports {
    pub(crate) streams: Vec<std::sync::Arc<StreamImport>>,
    pub(crate) services: Vec<std::sync::Arc<ServiceImport>>,
}

#[cfg(test)]
mod tests;
