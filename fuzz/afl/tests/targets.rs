//! Replays the seeds, their truncations and one-byte flips through every
//! target, plus inputs that once failed. Run with `cargo afl test`.

/// Minimized inputs that made a target fail, by target name.
const REGRESSIONS: &[(&str, &[u8])] = &[
    // A closing brace in an array was an empty value, read forever.
    ("config", b"a: [}"),
    // A duration too long for Duration.
    ("config", b"ping_interval: \"99999999999999999999h\""),
    // A size suffix that starts with a character of two bytes.
    ("config", "a: 2\u{280}".as_bytes()),
];

fn variants(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![seed.to_vec()];
    out.extend((0..seed.len()).map(|n| seed[..n].to_vec()));
    out.extend((0..seed.len()).map(|i| {
        let mut v = seed.to_vec();
        v[i] ^= 0xff;
        v
    }));
    out
}

#[test]
fn every_target_survives_its_seeds_and_their_neighbors() {
    for (name, body) in naq_fuzz::TARGETS {
        let seeds = naq_fuzz::seeds::for_target(name);
        assert!(!seeds.is_empty(), "{name} has no seeds");
        for seed in &seeds {
            for input in variants(seed) {
                body(&input);
            }
        }
    }
}

#[test]
fn regressions_stay_fixed() {
    for (name, input) in REGRESSIONS {
        let (_, body) = naq_fuzz::TARGETS
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("no target {name}"));
        body(input);
    }
}
