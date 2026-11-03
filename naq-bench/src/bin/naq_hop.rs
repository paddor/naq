//! Measures a batched OMQ hop between two lanes: throughput and latency.

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use naq_bench::{cli, hop};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", cli::HOP_USAGE);
        return ExitCode::SUCCESS;
    }
    let a = match cli::hop_args(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("naq_hop: {e}\n{}", cli::HOP_USAGE);
            return ExitCode::from(2);
        }
    };
    let r = match hop::run(&a.cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("naq_hop: {e}");
            return ExitCode::FAILURE;
        }
    };
    let line = cli::hop_record(&a, &r).to_string();
    println!("{line}");
    eprintln!(
        "naq_hop: {:?} {} B in {} B batches: {:.2}M msgs/s, {:.0} MB/s, rtt p50 {:.1} us, p99 {:.1} us",
        r.mode,
        r.payload,
        r.batch,
        r.msgs_s / 1e6,
        r.mb_s,
        r.rtt_p50_us,
        r.rtt_p99_us
    );
    if let Some(path) = &a.record {
        let appended = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = appended {
            eprintln!("naq_hop: {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
