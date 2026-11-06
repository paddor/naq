//! The flags of `nats-server`, as Go's `flag` package reads them: `-x` and
//! `--x` alike, values as `-x v` or `-x=v`, switches as `-x` or `-x=false`.

use std::path::PathBuf;

use naq::{Cluster, LogTo, Options, Tls};

pub(crate) const USAGE: &str = "\
usage: naq [options]

server:
  -c, --config FILE        configuration file, as for nats-server; the
                           flags below override it
  -t                       check the configuration file and exit
  -a, --addr HOST          host to listen on (0.0.0.0)
  -p, --port PORT          client port (4222); -1 picks a free one
  -n, --name NAME          server name (naq)
  -m, --http_port PORT     monitoring port
  --lanes N                IO lanes, one thread each (one per core)
  -P, --pid FILE           write the process ID to FILE
  --ports_file_dir DIR     write the ports the server listens on to DIR
  --store_dir DIR          accepted for nats-server harnesses; naq has no store
  -sl, --signal CMD[=PID]  send stop, quit, term, reopen, reload or ldm to a
                           running naq: by process ID, pid file, or the one
                           running
  -v, --version            print the version and exit
  -h, --help               print this and exit

logging:
  -l, --log FILE           log to FILE, not to stderr
  -s, --syslog             log to the local syslog
  -r, --remote_syslog URL  log to the syslog at udp://, tcp:// or unix:// URL
  -D, --debug              debug lines too
  -V, --trace              protocol traces too
  -DV                      both
  -T, --logtime            times on lines (on; -T=false for none)
  --log_size_limit N       rotate the log file past N bytes
  --max_traced_msg_len N   cut traced payloads at N bytes

authorization:
  --user USER              user clients log in as
  --pass PASSWORD          its password
  --auth TOKEN             token clients log in with

TLS (see --help_tls):
  --tls                    TLS for clients
  --tlscert FILE           server certificate chain
  --tlskey FILE            its private key
  --tlscacert FILE         authorities of client certificates
  --tlsverify              clients must present a certificate

cluster:
  --cluster URL            cluster listen address, nats://host:port
  --cluster_name NAME      cluster name
  --routes URLS            routes to the other servers, comma separated";

pub(crate) const TLS_USAGE: &str = "\
TLS for clients:
  --tls                    TLS for clients, with --tlscert and --tlskey;
                           --tls=false drops the TLS of the configuration
  --tlscert FILE           PEM file of the server certificate chain
  --tlskey FILE            PEM file of its private key
  --tlscacert FILE         PEM file of the authorities client certificates
                           must chain to
  --tlsverify              clients must present a certificate that chains
                           to --tlscacert

Any TLS flag replaces the tls block of the configuration file.";

/// Flags of `nats-server` naq does not serve.
const UNSERVED: &[&str] = &[
    "ms",
    "https_port",
    "js",
    "jetstream",
    "client_advertise",
    "cluster_advertise",
    "no_advertise",
    "connect_retries",
    "profile",
];

/// What the flags ask for.
#[derive(Debug)]
pub(crate) enum Run {
    Serve(Box<Options>),
    Help,
    HelpTls,
    Version,
    /// Check the configuration file at this path.
    Check(PathBuf),
    /// Send this `--signal` value.
    Signal(String),
}

/// Why the flags cannot be used.
#[derive(Debug)]
pub(crate) enum Bad {
    /// Flags misused: exit 2, with the usage.
    Usage(String),
    /// The configuration, or what the flags make of it, is wrong: exit 1.
    Config(String),
}

/// The TLS flags given.
#[derive(Debug, Default)]
struct TlsFlags {
    tls: Option<bool>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    ca: Option<PathBuf>,
    verify: bool,
}

/// What `args` ask for.
pub(crate) fn parse(args: &[String]) -> Result<Run, Bad> {
    let mut o = match config(args).map_err(Bad::Usage)? {
        Some(path) => naq::Options::from_file(path).map_err(|e| Bad::Config(chain(&e)))?,
        None => naq::Options::default(),
    };
    let mut tls = TlsFlags::default();
    let mut check = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if !arg.starts_with('-') {
            return match arg.as_str() {
                "version" => Ok(Run::Version),
                "help" => Ok(Run::Help),
                a => Err(Bad::Usage(format!("unrecognized command: {a:?}"))),
            };
        }
        let (name, inline) = split(arg)?;
        match switch(&mut o, &mut tls, name, inline).map_err(Bad::Usage)? {
            Some(Run::Check(_)) => check = true,
            Some(run) => return Ok(run),
            None if is_switch(name) => {}
            None => {
                let val = match inline {
                    Some(v) => v,
                    None => it
                        .next()
                        .map(String::as_str)
                        .ok_or_else(|| Bad::Usage(format!("{arg} needs a value")))?,
                };
                if let Some(run) = value(&mut o, &mut tls, name, val, arg)? {
                    return Ok(run);
                }
            }
        }
    }
    if check {
        let path = config(args).map_err(Bad::Usage)?.ok_or_else(|| {
            Bad::Config(
                "must specify [-c, --config] option to check configuration file syntax".into(),
            )
        })?;
        return Ok(Run::Check(path.into()));
    }
    apply_tls(&mut o, tls).map_err(Bad::Config)?;
    Ok(Run::Serve(Box::new(o)))
}

/// The name of flag `arg` without its dashes, and its `=value`, if any.
fn split(arg: &str) -> Result<(&str, Option<&str>), Bad> {
    let (name, inline) = arg
        .split_once('=')
        .map_or((arg, None), |(n, v)| (n, Some(v)));
    let name = name
        .strip_prefix("--")
        .or_else(|| name.strip_prefix('-'))
        .ok_or_else(|| Bad::Usage(format!("unknown argument {arg:?}")))?;
    Ok((name, inline))
}

const fn is_switch(name: &str) -> bool {
    matches!(
        name.as_bytes(),
        b"D" | b"debug"
            | b"V"
            | b"trace"
            | b"VV"
            | b"DV"
            | b"DVV"
            | b"T"
            | b"logtime"
            | b"logtime_utc"
            | b"s"
            | b"syslog"
            | b"tls"
            | b"tlsverify"
            | b"t"
            | b"v"
            | b"version"
            | b"h"
            | b"help"
            | b"help_tls"
    )
}

/// Applies switch `name`, on alone or as its `=value` says. `Some` is
/// what to run instead of a server; `None` for a switch applied or not a
/// switch.
fn switch(
    o: &mut Options,
    tls: &mut TlsFlags,
    name: &str,
    value: Option<&str>,
) -> Result<Option<Run>, String> {
    if !is_switch(name) {
        return Ok(None);
    }
    let on = match value {
        None | Some("true" | "1" | "t" | "T" | "TRUE" | "True") => true,
        Some("false" | "0" | "f" | "F" | "FALSE" | "False") => false,
        Some(v) => return Err(format!("bad value {v:?} for -{name}")),
    };
    let l = &mut o.log;
    match name {
        "D" | "debug" => l.debug = on,
        "V" | "trace" | "VV" => l.trace.set(on),
        "DV" | "DVV" => {
            l.debug = on;
            l.trace.set(on);
        }
        "T" | "logtime" => l.time = on,
        "s" | "syslog" if on => l.prefer(LogTo::Syslog),
        "tls" => tls.tls = Some(on),
        "tlsverify" => tls.verify = on,
        "t" if on => return Ok(Some(Run::Check(PathBuf::new()))),
        "v" | "version" if on => return Ok(Some(Run::Version)),
        "h" | "help" if on => return Ok(Some(Run::Help)),
        "help_tls" if on => return Ok(Some(Run::HelpTls)),
        // Lines are in UTC anyway (`logtime_utc`).
        _ => {}
    }
    Ok(None)
}

/// Applies flag `name` with value `val`, as `arg` gave it.
fn value(
    o: &mut Options,
    tls: &mut TlsFlags,
    name: &str,
    val: &str,
    arg: &str,
) -> Result<Option<Run>, Bad> {
    let bad = || Bad::Usage(format!("bad value {val:?} for {arg}"));
    match name {
        // Read before, or not used: naq has no store.
        "c" | "config" | "store_dir" | "sd" => {}
        "sl" | "signal" => return Ok(Some(Run::Signal(val.into()))),
        "a" | "addr" | "net" => o.host = val.into(),
        "p" | "port" if val == "-1" => o.port = 0,
        "p" | "port" => o.port = val.parse().map_err(|_| bad())?,
        "n" | "name" | "server_name" => o.server_name = val.into(),
        "P" | "pid" => o.pid_file = Some(val.into()),
        "ports_file_dir" => o.ports_file_dir = Some(val.into()),
        "lanes" => o.lanes = val.parse().map_err(|_| bad())?,
        "m" | "http_port" => o.http_port = Some(val.parse().map_err(|_| bad())?),
        "l" | "log" => o.log.to = Some(LogTo::File(val.into())),
        "r" | "remote_syslog" => o.log.prefer(LogTo::RemoteSyslog(val.into())),
        "log_size_limit" => o.log.size_limit = val.parse().map_err(|_| bad())?,
        "max_traced_msg_len" => o.log.max_traced = val.parse().map_err(|_| bad())?,
        "user" => {
            let pass = o.user.take().map(|(_, p)| p).unwrap_or_default();
            o.user = Some((val.into(), pass));
        }
        "pass" => {
            let user = o.user.take().map(|(u, _)| u).unwrap_or_default();
            o.user = Some((user, val.into()));
        }
        "auth" => o.token = Some(val.into()),
        "tlscert" => tls.cert = Some(val.into()),
        "tlskey" => tls.key = Some(val.into()),
        "tlscacert" => tls.ca = Some(val.into()),
        "cluster" | "cluster_listen" => cluster_listen(o, val).map_err(Bad::Config)?,
        "cluster_name" => cluster_of(o).name = val.into(),
        "routes" => routes(o, val).map_err(Bad::Config)?,
        n if UNSERVED.contains(&n) => {
            return Err(Bad::Usage(format!("{arg} is not served by naq")));
        }
        _ => return Err(Bad::Usage(format!("unknown argument {arg:?}"))),
    }
    Ok(None)
}

/// The cluster of `o`, made if it has none.
fn cluster_of(o: &mut Options) -> &mut Cluster {
    o.cluster.get_or_insert_with(|| Cluster {
        name: String::new(),
        host: "0.0.0.0".into(),
        port: 6222,
        routes: Vec::new(),
    })
}

/// `--cluster nats://host:port`: where the cluster listens; empty for no
/// cluster, port -1 for a free one.
fn cluster_listen(o: &mut Options, url: &str) -> Result<(), String> {
    if url.is_empty() {
        o.cluster = None;
        return Ok(());
    }
    let bad = || format!("bad cluster URL {url:?}");
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
    let (host, port) = rest.rsplit_once(':').ok_or_else(bad)?;
    let port = match port {
        "-1" => 0,
        p => p.parse().map_err(|_| bad())?,
    };
    let c = cluster_of(o);
    c.host = host.trim_start_matches('[').trim_end_matches(']').into();
    c.port = port;
    Ok(())
}

/// `--routes a,b`: the routes of the cluster; empty for none.
fn routes(o: &mut Options, urls: &str) -> Result<(), String> {
    let routes: Vec<String> = urls
        .split(',')
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_owned)
        .collect();
    match &mut o.cluster {
        Some(c) => c.routes = routes,
        None if routes.is_empty() => {}
        None => return Err("solicited routes require cluster capabilities, e.g. --cluster".into()),
    }
    Ok(())
}

/// Replaces the TLS of `o` as the TLS flags say, if any were given.
fn apply_tls(o: &mut Options, f: TlsFlags) -> Result<(), String> {
    let given =
        f.tls.is_some() || f.cert.is_some() || f.key.is_some() || f.ca.is_some() || f.verify;
    if !given {
        return Ok(());
    }
    if f.tls == Some(false) && f.cert.is_none() && f.key.is_none() {
        o.tls = None;
        return Ok(());
    }
    let given = |p: Option<PathBuf>| p.filter(|p| !p.as_os_str().is_empty());
    let cert_file = given(f.cert).ok_or("TLS Server certificate must be present and valid")?;
    let key_file = given(f.key).ok_or("TLS Server private key must be present and valid")?;
    o.tls = Some(Tls {
        cert_file,
        key_file,
        ca_file: f.ca,
        verify: f.verify,
        map: false,
        timeout: std::time::Duration::from_secs(2),
        handshake_first: false,
        fallback: None,
    });
    Ok(())
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
pub(crate) fn chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg = format!("{msg}: {s}");
        src = s.source();
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve(args: &[&str]) -> Options {
        let args: Vec<String> = args.iter().map(|&a| a.to_owned()).collect();
        match parse(&args) {
            Ok(Run::Serve(o)) => *o,
            other => panic!("{other:?}"),
        }
    }

    fn bad(args: &[&str]) -> Bad {
        let args: Vec<String> = args.iter().map(|&a| a.to_owned()).collect();
        parse(&args).unwrap_err()
    }

    #[test]
    fn tls_flags_make_the_tls_of_clients() {
        let o = serve(&[
            "--tlscert",
            "c.pem",
            "--tlskey=k.pem",
            "--tlscacert",
            "ca.pem",
            "--tlsverify",
        ]);
        let t = o.tls.unwrap();
        assert_eq!(
            (t.cert_file, t.key_file, t.ca_file, t.verify),
            ("c.pem".into(), "k.pem".into(), Some("ca.pem".into()), true)
        );
        assert!(serve(&["--tls=false"]).tls.is_none());
        assert!(matches!(
            bad(&["--tlskey", "k.pem", "--tlscert="]),
            Bad::Config(_)
        ));
        let Bad::Config(e) = bad(&["--tlscert", "c.pem"]) else {
            panic!("no config error");
        };
        assert_eq!(e, "TLS Server private key must be present and valid");
    }

    #[test]
    fn cluster_flags_make_the_cluster() {
        let o = serve(&[
            "--cluster",
            "nats://u:p@127.0.0.1:-1",
            "--cluster_name",
            "c",
            "--routes",
            "a, b,",
        ]);
        let c = o.cluster.unwrap();
        assert_eq!(
            (
                c.name.as_str(),
                c.host.as_str(),
                c.port,
                c.routes.as_slice()
            ),
            ("c", "127.0.0.1", 0, &["a".to_owned(), "b".to_owned()][..])
        );
        let c = serve(&["--cluster_listen=[::1]:7222"]).cluster.unwrap();
        assert_eq!((c.host.as_str(), c.port), ("::1", 7222));
        assert!(
            serve(&["--cluster", "nats://h:1", "--cluster", ""])
                .cluster
                .is_none()
        );
        assert!(serve(&["--routes", ""]).cluster.is_none());
        assert!(matches!(
            bad(&["--cluster", "nats://nohost"]),
            Bad::Config(_)
        ));
        assert!(matches!(bad(&["--cluster", "h:x"]), Bad::Config(_)));
    }

    #[test]
    fn user_pass_and_token_flags_set_the_single_user() {
        assert_eq!(
            serve(&["--pass", "p", "--user", "u"]).user,
            Some(("u".into(), "p".into()))
        );
        assert_eq!(serve(&["--auth", "t"]).token, Some("t".into()));
    }

    #[test]
    fn switches_take_go_spellings_and_commands_end_the_flags() {
        let o = serve(&[
            "-DV=true",
            "-s=0",
            "--logtime_utc",
            "-n",
            "x",
            "-P",
            "p",
            "--ports_file_dir",
            "d",
        ]);
        assert!(o.log.debug && o.log.trace != naq::Trace::Off);
        assert_eq!(o.log.to, None);
        assert_eq!(
            (o.server_name.as_str(), o.pid_file, o.ports_file_dir),
            ("x", Some("p".into()), Some("d".into()))
        );
        for (args, run) in [
            (&["-h"][..], "Help"),
            (&["--help_tls"], "HelpTls"),
            (&["-p", "1", "version"], "Version"),
        ] {
            let args: Vec<String> = args.iter().map(|&a| a.to_owned()).collect();
            assert!(
                format!("{:?}", parse(&args).unwrap()).starts_with(run),
                "{args:?}"
            );
        }
        assert!(matches!(bad(&["-D=maybe"]), Bad::Usage(_)));
        assert!(matches!(bad(&["--profile", "1"]), Bad::Usage(e) if e.contains("not served")));
        assert!(matches!(bad(&["-c"]), Bad::Usage(_)));
    }
}
