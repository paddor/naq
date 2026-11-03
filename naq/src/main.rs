//! The `naq` server binary.

use std::process::ExitCode;

const USAGE: &str = "\
usage: naq [options]
  -c, --config FILE    configuration file, as for nats-server; the flags
                       below override it
  -a, --addr HOST      host to listen on (0.0.0.0)
  -p, --port PORT      client port (4222)
  --lanes N            IO lanes, one thread each (one per core)
  --name NAME          server name (naq)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let opts = match options(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("naq: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let server = match naq::Server::start(&opts) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("naq: {}", chain(&e));
            return ExitCode::FAILURE;
        }
    };
    let addr = server.addr();
    eprintln!(
        "[naq] Listening for client connections on {}:{}",
        opts.host,
        addr.port()
    );
    loop {
        std::thread::park();
    }
}

fn options(args: &[String]) -> Result<naq::Options, String> {
    let mut o = match config(args)? {
        Some(path) => naq::Options::from_file(path).map_err(|e| chain(&e))?,
        None => naq::Options::default(),
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let bad = || format!("bad value {val:?} for {flag}");
        match flag.as_str() {
            "-c" | "--config" => {}
            "-a" | "--addr" => o.host.clone_from(val),
            "-p" | "--port" => o.port = val.parse().map_err(|_| bad())?,
            "--lanes" => o.lanes = val.parse().map_err(|_| bad())?,
            "--name" => o.server_name.clone_from(val),
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    Ok(o)
}

/// The configuration file the flags name, if any.
fn config(args: &[String]) -> Result<Option<&str>, String> {
    let Some(at) = args.iter().position(|a| a == "-c" || a == "--config") else {
        return Ok(None);
    };
    match args.get(at + 1) {
        Some(path) => Ok(Some(path)),
        None => Err(format!("{} needs a value", args[at])),
    }
}

/// `e` and its sources, on one line.
fn chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg = format!("{msg}: {s}");
        src = s.source();
    }
    msg
}
