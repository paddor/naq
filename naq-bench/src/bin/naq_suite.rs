//! Runs the same load against `nats-server` and naq, then the perf gate.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use naq_bench::{cli, suite};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", cli::SUITE_USAGE);
        return ExitCode::SUCCESS;
    }
    let bins = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_owned))
        .unwrap_or_default();
    let go = std::env::var_os("NAQ_GO").map(PathBuf::from);
    let mut plan = match cli::suite_args(&args, &bins, go) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("naq_suite: {e}\n{}", cli::SUITE_USAGE);
            return ExitCode::from(2);
        }
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    plan.out
        .tags
        .entry("session".into())
        .or_insert_with(|| ts.to_string());
    let mut out = std::io::stdout();
    let samples = match suite::run(&plan, &mut out) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("naq_suite: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rows = suite::rows(&plan.cells, &samples);
    print!("\n{}", suite::table(&rows));
    let v = suite::verdict(&rows);
    println!("{}", v.line);
    if v.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
