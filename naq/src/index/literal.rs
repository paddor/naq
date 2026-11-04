//! Literal filters, by subject.
//!
//! A hash table whose hash and key compare inline: a lookup happens for
//! every publish.

use std::hash::Hasher;

use hashbrown::HashTable;
use rustc_hash::FxHasher;

use super::Interest;

#[derive(Debug)]
struct Filter {
    subject: Box<[u8]>,
    interest: Interest,
}

/// The literal filters with interest.
#[derive(Debug, Default)]
pub(super) struct Literals {
    table: HashTable<Filter>,
}

#[inline]
fn hash(subject: &[u8]) -> u64 {
    let mut h = FxHasher::default();
    h.write(subject);
    h.finish()
}

/// Whether `a` and `b` hold the same bytes. Short ones are compared here,
/// not in a call to `memcmp`.
#[expect(
    clippy::inline_always,
    reason = "measured: a call here costs every publish"
)]
#[inline(always)]
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && if a.len() <= 16 {
            a.iter().zip(b).all(|(x, y)| x == y)
        } else {
            a == b
        }
}

impl Literals {
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// The interest in `subject`, if there is any.
    #[expect(
        clippy::inline_always,
        reason = "measured: a call here costs every publish"
    )]
    #[inline(always)]
    pub(super) fn get(&self, subject: &[u8]) -> Option<&Interest> {
        self.table
            .find(hash(subject), |f| same(&f.subject, subject))
            .map(|f| &f.interest)
    }

    /// Calls `f` with every subject and its interest.
    pub(super) fn each(&self, f: &mut impl FnMut(&[u8], &Interest)) {
        for filter in &self.table {
            f(&filter.subject, &filter.interest);
        }
    }

    /// The interest in `subject`, made if new.
    pub(super) fn interest(&mut self, subject: &[u8]) -> &mut Interest {
        let entry = self.table.entry(
            hash(subject),
            |f| same(&f.subject, subject),
            |f| hash(&f.subject),
        );
        &mut entry
            .or_insert_with(|| Filter {
                subject: subject.into(),
                interest: Interest::default(),
            })
            .into_mut()
            .interest
    }

    /// Applies `f` to the interest in `subject`, if there is any, and
    /// forgets the subject once nothing is left.
    pub(super) fn change(&mut self, subject: &[u8], f: impl FnOnce(&mut Interest)) {
        let Ok(mut entry) = self
            .table
            .find_entry(hash(subject), |e| same(&e.subject, subject))
        else {
            return;
        };
        f(&mut entry.get_mut().interest);
        if entry.get().interest.is_empty() {
            entry.remove();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_subjects_compare_by_every_byte() {
        let long = [b'a'; 40];
        let mut other = long;
        other[39] = b'b';
        assert!(same(b"orders", b"orders"));
        assert!(!same(b"orders", b"orderz"));
        assert!(!same(b"order", b"orders"));
        assert!(same(&long, &long));
        assert!(!same(&long, &other));
    }

    #[test]
    fn a_subject_is_forgotten_once_its_interest_is_gone() {
        let mut l = Literals::default();
        let long = [b'x'; 40];
        for s in [&b"a"[..], &long] {
            l.interest(s).plain.count(1, true);
            assert!(l.get(s).is_some());
            l.change(b"missing", |_| {});
            l.change(s, |i| i.plain.count(1, false));
            assert!(l.get(s).is_none());
        }
        assert!(l.is_empty());
    }
}
