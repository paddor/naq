//! Drives a NATS server with sustained publish/subscribe load.

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use naq_bench::{cli, load};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", cli::LOAD_USAGE);
        return ExitCode::SUCCESS;
    }
    let a = match cli::load_args(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("naq_load: {e}\n{}", cli::LOAD_USAGE);
            return ExitCode::from(2);
        }
    };
    let report = match load::run(&a.cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("naq_load: {e}");
            return ExitCode::FAILURE;
        }
    };
    let line = cli::record(&a, &report).to_string();
    println!("{line}");
    eprintln!("naq_load: {}", cli::summary(&report));
    if !report.is_clean() {
        eprintln!("naq_load: not clean, not recorded");
        return ExitCode::FAILURE;
    }
    if let Some(path) = &a.record {
        let appended = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = appended {
            eprintln!("naq_load: {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
