//! The `naq` server binary.

use std::process::ExitCode;

const USAGE: &str = "\
usage: naq [options]
  -c, --config FILE    configuration file, as for nats-server; the flags
                       below override it
  -a, --addr HOST      host to listen on (0.0.0.0)
  -p, --port PORT      client port (4222); -1 picks a free one
  -m, --http_port PORT monitoring port for /healthz, /varz, /connz
  --lanes N            IO lanes, one thread each (one per core)
  --name NAME          server name (naq)
  -l, --log FILE       write the log to FILE, not to stderr
  -P, --pid FILE       write the process ID to FILE
  --store_dir DIR      accepted for nats-server harnesses; naq has no store";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let (opts, files) = match options(&args) {
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
    if let Some(pid) = &files.pid
        && let Err(e) = std::fs::write(pid, std::process::id().to_string())
    {
        eprintln!("naq: cannot write {}: {e}", pid.display());
        return ExitCode::FAILURE;
    }
    let line = format!(
        "[naq] Listening for client connections on {}:{}\n",
        opts.host,
        server.addr().port()
    );
    if let Err(e) = log(files.log.as_deref(), &line) {
        eprintln!("naq: cannot write the log: {e}");
        return ExitCode::FAILURE;
    }
    loop {
        std::thread::park();
    }
}

/// Files the flags name besides the configuration.
#[derive(Debug, Default)]
struct Files {
    log: Option<std::path::PathBuf>,
    pid: Option<std::path::PathBuf>,
}

/// Appends `line` to the log: `file`, or stderr.
fn log(file: Option<&std::path::Path>, line: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    match file {
        Some(f) => std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(f)?
            .write_all(line.as_bytes()),
        None => std::io::stderr().write_all(line.as_bytes()),
    }
}

fn options(args: &[String]) -> Result<(naq::Options, Files), String> {
    let mut files = Files::default();
    let mut o = match config(args)? {
        Some(path) => naq::Options::from_file(path).map_err(|e| chain(&e))?,
        None => naq::Options::default(),
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let bad = || format!("bad value {val:?} for {flag}");
        match flag.as_str() {
            // Read before, or not used: naq has no store.
            "-c" | "--config" | "--store_dir" => {}
            "-a" | "--addr" => o.host.clone_from(val),
            "-p" | "--port" if val == "-1" => o.port = 0,
            "-p" | "--port" => o.port = val.parse().map_err(|_| bad())?,
            "-l" | "--log" => files.log = Some(val.into()),
            "-P" | "--pid" => files.pid = Some(val.into()),
            "--lanes" => o.lanes = val.parse().map_err(|_| bad())?,
            "-m" | "--http_port" => o.http_port = Some(val.parse().map_err(|_| bad())?),
            "--name" => o.server_name.clone_from(val),
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    Ok((o, files))
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
