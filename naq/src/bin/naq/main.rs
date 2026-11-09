//! The `naq` server binary.

mod flags;
mod signal;

use std::fmt::Write as _;
use std::process::ExitCode;

use sha2::Digest as _;

use flags::{Bad, Run};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match flags::parse(&args) {
        Ok(Run::Serve(opts)) => serve(*opts, args),
        Ok(Run::Help) => {
            println!("{}", flags::USAGE);
            ExitCode::SUCCESS
        }
        Ok(Run::HelpTls) => {
            println!("{}", flags::TLS_USAGE);
            ExitCode::SUCCESS
        }
        Ok(Run::Version) => {
            println!("naq: v{}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Run::Check(path)) => {
            let digest = std::fs::read(&path)
                .map(sha2::Sha256::digest)
                .unwrap_or_default();
            let hex = digest.iter().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
            eprintln!(
                "naq: configuration file {} is valid (sha256:{hex})",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Ok(Run::Signal(spec)) => match signal::send(&spec) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("naq: {e}");
                ExitCode::FAILURE
            }
        },
        Err(Bad::Usage(e)) => {
            eprintln!("naq: {e}\n{}", flags::USAGE);
            ExitCode::from(2)
        }
        Err(Bad::Config(e)) => {
            eprintln!("naq: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Serves `opts`, which `args` gave, until a signal stops the server. A
/// reload reads them again from `args`.
fn serve(mut opts: naq::Options, args: Vec<String>) -> ExitCode {
    to_stderr(&mut opts);
    // Caught before the server starts, as by `nats-server`: a signal sent
    // once the process ID file is there does not end the process.
    let signals = match naq::Signals::catch() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("naq: cannot handle signals: {e}");
            return ExitCode::FAILURE;
        }
    };
    let server = match naq::Server::start(&opts) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("naq: {}", flags::chain(&e));
            return ExitCode::FAILURE;
        }
    };
    server.reload_with(move || reread(&args));
    server.wait_for_signals(signals);
    ExitCode::SUCCESS
}

/// The options `args` give now, as a reload reads them: the configuration
/// file again, then the flags over it.
fn reread(args: &[String]) -> Result<naq::Options, naq::Error> {
    match flags::parse(args) {
        Ok(Run::Serve(mut opts)) => {
            to_stderr(&mut opts);
            Ok(*opts)
        }
        Err(Bad::Config(e) | Bad::Usage(e)) => Err(naq::Error::Reload(e)),
        Ok(_) => Err(naq::Error::Reload("the flags no longer serve".into())),
    }
}

/// Logs to stderr, unless `opts` log elsewhere.
fn to_stderr(opts: &mut naq::Options) {
    if opts.log.to.is_none() {
        opts.log.to = Some(naq::LogTo::Stderr);
    }
}
