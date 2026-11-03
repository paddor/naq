//! A fake NATS server that measures the load generator alone.

use std::process::ExitCode;

use naq_bench::cli;
use naq_bench::sink::Sink;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", cli::SINK_USAGE);
        return ExitCode::SUCCESS;
    }
    let (addr, mode) = match cli::sink_args(&args) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("naq_sink: {e}\n{}", cli::SINK_USAGE);
            return ExitCode::from(2);
        }
    };
    let sink = match Sink::spawn(addr, mode) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("naq_sink: {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "naq_sink: Listening for client connections on {} ({mode:?})",
        sink.addr()
    );
    loop {
        std::thread::park();
    }
}
