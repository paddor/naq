//! The `naq` server binary.

use std::process::ExitCode;

use naq::LogTo;

const USAGE: &str = "\
usage: naq [options]
  -c, --config FILE      configuration file, as for nats-server; the flags
                         below override it
  -a, --addr HOST        host to listen on (0.0.0.0)
  -p, --port PORT        client port (4222); -1 picks a free one
  -m, --http_port PORT   monitoring port for /healthz, /varz, /connz
  --lanes N              IO lanes, one thread each (one per core)
  -n, --name NAME        server name (naq)
  -P, --pid FILE         write the process ID to FILE
  --store_dir DIR        accepted for nats-server harnesses; naq has no store

logging:
  -l, --log FILE         log to FILE, not to stderr
  -s, --syslog           log to the local syslog
  -r, --remote_syslog URL
                         log to the syslog at udp://, tcp:// or unix:// URL
  -D, --debug            debug lines too
  -V, --trace            protocol traces too
  -DV                    both
  -T, --logtime          times on lines (on; -T=false for none)
  --log_size_limit N     rotate the log file past N bytes
  --max_traced_msg_len N cut traced payloads at N bytes";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let (mut opts, files) = match options(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("naq: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if opts.log.to.is_none() {
        opts.log.to = Some(LogTo::Stderr);
    }
    let _server = match naq::Server::start(&opts) {
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
    loop {
        std::thread::park();
    }
}

/// Files the flags name besides the configuration.
#[derive(Debug, Default)]
struct Files {
    pid: Option<std::path::PathBuf>,
}

fn options(args: &[String]) -> Result<(naq::Options, Files), String> {
    let mut files = Files::default();
    let mut o = match config(args)? {
        Some(path) => naq::Options::from_file(path).map_err(|e| chain(&e))?,
        None => naq::Options::default(),
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (arg.as_str(), None),
        };
        let name = name
            .strip_prefix("--")
            .or_else(|| name.strip_prefix('-'))
            .ok_or_else(|| format!("unknown argument {arg:?}"))?;
        if switch(&mut o, name, inline)? {
            continue;
        }
        let val = match inline {
            Some(v) => v,
            None => it
                .next()
                .map(String::as_str)
                .ok_or_else(|| format!("{arg} needs a value"))?,
        };
        let bad = || format!("bad value {val:?} for {arg}");
        match name {
            // Read before, or not used: naq has no store.
            "c" | "config" | "store_dir" | "sd" => {}
            "a" | "addr" | "net" => o.host = val.into(),
            "p" | "port" if val == "-1" => o.port = 0,
            "p" | "port" => o.port = val.parse().map_err(|_| bad())?,
            "P" | "pid" => files.pid = Some(val.into()),
            "lanes" => o.lanes = val.parse().map_err(|_| bad())?,
            "m" | "http_port" => o.http_port = Some(val.parse().map_err(|_| bad())?),
            "n" | "name" | "server_name" => o.server_name = val.into(),
            "l" | "log" => o.log.to = Some(LogTo::File(val.into())),
            "r" | "remote_syslog" => o.log.prefer(LogTo::RemoteSyslog(val.into())),
            "log_size_limit" => o.log.size_limit = val.parse().map_err(|_| bad())?,
            "max_traced_msg_len" => o.log.max_traced = val.parse().map_err(|_| bad())?,
            _ => return Err(format!("unknown argument {arg:?}")),
        }
    }
    Ok((o, files))
}

/// Applies flag `name` if it is a switch: on alone, or as its `=value`
/// says. Whether it was one.
fn switch(o: &mut naq::Options, name: &str, value: Option<&str>) -> Result<bool, String> {
    let on = || match value {
        None | Some("true" | "1" | "t" | "T" | "TRUE" | "True") => Ok(true),
        Some("false" | "0" | "f" | "F" | "FALSE" | "False") => Ok(false),
        Some(v) => Err(format!("bad value {v:?} for -{name}")),
    };
    let l = &mut o.log;
    match name {
        "D" | "debug" => l.debug = on()?,
        "V" | "trace" | "VV" => l.trace.set(on()?),
        "DV" | "DVV" => {
            l.debug = on()?;
            l.trace.set(l.debug);
        }
        "T" | "logtime" => l.time = on()?,
        // Lines are in UTC anyway.
        "logtime_utc" => _ = on()?,
        "s" | "syslog" => {
            if on()? {
                l.prefer(LogTo::Syslog);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// The configuration file the flags name, if any.
fn config(args: &[String]) -> Result<Option<&str>, String> {
    for (at, arg) in args.iter().enumerate() {
        for flag in ["-c", "--config", "-config"] {
            if arg == flag {
                return match args.get(at + 1) {
                    Some(path) => Ok(Some(path)),
                    None => Err(format!("{arg} needs a value")),
                };
            }
            if let Some(path) = arg.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
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
