//! Measures the NATS codec on one core: parsing `PUB`, encoding `MSG`.

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use naq_bench::{cli, codec};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", cli::CODEC_USAGE);
        return ExitCode::SUCCESS;
    }
    let a = match cli::codec_args(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("naq_codec: {e}\n{}", cli::CODEC_USAGE);
            return ExitCode::from(2);
        }
    };
    for &kernel in &a.kernels {
        let r = match codec::run(kernel, &a.cfg) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("naq_codec: {e}");
                return ExitCode::FAILURE;
            }
        };
        let line = cli::codec_record(&a, &r).to_string();
        println!("{line}");
        eprintln!(
            "naq_codec: {kernel:?} {} B: {:.2}M msgs/s, {:.1} ns/msg, in {:.0} MB/s, out {:.0} MB/s",
            r.payload,
            r.msgs_s / 1e6,
            r.ns_msg,
            r.in_mb_s,
            r.out_mb_s
        );
        if let Some(path) = &a.record {
            let appended = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut f| writeln!(f, "{line}"));
            if let Err(e) = appended {
                eprintln!("naq_codec: {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
