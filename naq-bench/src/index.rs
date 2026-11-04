//! Match cost of subject indexes on one core: a hash map of literal
//! subjects, as the skeleton has, against zzq's MQTT topic trie.

use std::hint::black_box;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;
use serde::Serialize;
use zzq_proto::trie::TopicTrie;

/// What a run looks up in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// `FxHashMap` of literal subjects.
    Hash,
    /// zzq's topic trie, literal filters only.
    Trie,
    /// zzq's topic trie, with a `+` and a `#` filter matching each subject
    /// as well.
    Wild,
}

impl Kind {
    /// Every kind.
    pub const ALL: [Kind; 3] = [Kind::Hash, Kind::Trie, Kind::Wild];
}

/// Lookup cost for one index size.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// What was looked up in.
    pub kind: Kind,
    /// Distinct subjects in the index.
    pub subjects: usize,
    /// Nanoseconds per lookup.
    pub ns_lookup: f64,
    /// Matches found per lookup.
    pub matches: f64,
}

/// Measures `kind` with `subjects` distinct subjects for `duration`.
pub fn run(kind: Kind, subjects: usize, duration: Duration) -> Report {
    let subjects = subjects.max(1);
    let names: Vec<String> = (0..subjects)
        .map(|i| format!("orders.{i}.created"))
        .collect();
    let topics: Vec<String> = names.iter().map(|s| s.replace('.', "/")).collect();
    let mut found = 0u64;
    // Lookups between clock reads, so reading the clock costs little.
    let reps = (4096 / subjects).max(1);
    let round = reps * subjects;
    let (ns, lookups) = match kind {
        Kind::Hash => {
            let map: FxHashMap<Box<[u8]>, u32> = names
                .iter()
                .enumerate()
                .map(|(i, s)| (s.as_bytes().into(), i as u32))
                .collect();
            timed(duration, round, || {
                for _ in 0..reps {
                    for s in &names {
                        found += u64::from(map.contains_key(black_box(s.as_bytes())));
                    }
                }
            })
        }
        Kind::Trie | Kind::Wild => {
            let mut trie = TopicTrie::new();
            for (i, t) in topics.iter().enumerate() {
                trie.insert(t, i as u32);
                if kind == Kind::Wild {
                    trie.insert(&format!("orders/{i}/+"), i as u32);
                    trie.insert(&format!("orders/{i}/#"), i as u32);
                }
            }
            timed(duration, round, || {
                for _ in 0..reps {
                    for t in &topics {
                        trie.for_each_match(black_box(t), |v| {
                            black_box(v);
                            found += 1;
                        });
                    }
                }
            })
        }
    };
    Report {
        kind,
        subjects,
        ns_lookup: ns,
        matches: found as f64 / lookups as f64,
    }
}

/// Runs `round`, `lookups` lookups each, until `duration` is over, at
/// least once. Returns nanoseconds per lookup and the lookups made.
fn timed(duration: Duration, lookups: usize, mut round: impl FnMut()) -> (f64, u64) {
    let start = Instant::now();
    let mut made = 0u64;
    loop {
        round();
        made += lookups as u64;
        if start.elapsed() >= duration {
            break;
        }
    }
    (start.elapsed().as_secs_f64() * 1e9 / made as f64, made)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_finds_its_subjects() {
        for kind in Kind::ALL {
            // Not even a moment: one round still counts.
            let r = run(kind, 10, Duration::ZERO);
            assert!(r.ns_lookup > 0.0, "{r:?}");
            let want = if kind == Kind::Wild { 3.0 } else { 1.0 };
            assert!((r.matches - want).abs() < f64::EPSILON, "{r:?}");
        }
    }
}
