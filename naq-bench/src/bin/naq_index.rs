//! Measures subject lookups: a hash map of literal subjects against zzq's
//! MQTT topic trie.

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use naq_bench::{cli, index};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", cli::INDEX_USAGE);
        return ExitCode::SUCCESS;
    }
    let a = match cli::index_args(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("naq_index: {e}\n{}", cli::INDEX_USAGE);
            return ExitCode::from(2);
        }
    };
    for &n in &a.subjects {
        for kind in index::Kind::ALL {
            let r = index::run(kind, n, a.duration);
            let line = cli::index_record(&a, &r).to_string();
            println!("{line}");
            eprintln!(
                "naq_index: {kind:?} {n} subjects: {:.1} ns/lookup, {} matches",
                r.ns_lookup, r.matches
            );
            if let Some(path) = &a.record {
                let appended = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut f| writeln!(f, "{line}"));
                if let Err(e) = appended {
                    eprintln!("naq_index: {}: {e}", path.display());
                    return ExitCode::FAILURE;
                }
            }
        }
    }
    ExitCode::SUCCESS
}
