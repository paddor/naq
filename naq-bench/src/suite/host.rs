//! Processes on the host: the idle check, servers, clusters and load
//! runs.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{Host, Server, SuiteError};

/// Share of idle CPU time a run waits for.
const IDLE: f64 = 0.90;
/// Idle probes before giving up.
const IDLE_TRIES: usize = 60;
/// Processes that mean someone is building.
const BUILDERS: [&str; 5] = ["rustc", "cargo", "cc1", "go", "ld"];
/// Time a server gets to open its port.
const START_LIMIT: Duration = Duration::from_secs(10);
/// Between checks on a starting server or a load run.
const POLL: Duration = Duration::from_millis(20);

/// What one idle probe saw: the idle share and a builder, if one runs.
pub(super) type Probe = (f64, Option<String>);

/// Waits until a probe sees an idle machine and no build.
pub(super) fn wait_idle(
    out: &mut dyn Write,
    mut probe: impl FnMut() -> Probe,
) -> Result<(), SuiteError> {
    for _ in 0..IDLE_TRIES {
        let (idle, builder) = probe();
        if idle >= IDLE && builder.is_none() {
            return Ok(());
        }
        let builder = builder.map_or_else(String::new, |b| format!(", {b} running"));
        writeln!(
            out,
            "naq_suite: waiting for idle ({:.0}% idle{builder})",
            idle * 100.0
        )?;
    }
    Err(SuiteError::Busy)
}

/// The idle share over one second, and a running builder.
pub(super) fn probe() -> Probe {
    let before = cpu_times();
    thread::sleep(Duration::from_secs(1));
    let idle = match (before, cpu_times()) {
        (Some((t0, i0)), Some((t1, i1))) if t1 > t0 => (i1 - i0) as f64 / (t1 - t0) as f64,
        _ => 0.0,
    };
    (idle, builder())
}

/// Total and idle (with I/O wait) ticks of all CPUs.
fn cpu_times() -> Option<(u64, u64)> {
    stat_times(&std::fs::read_to_string("/proc/stat").ok()?)
}

/// Parses the `cpu` line of `/proc/stat`.
fn stat_times(stat: &str) -> Option<(u64, u64)> {
    let mut f = stat
        .lines()
        .next()?
        .strip_prefix("cpu ")?
        .split_whitespace();
    let ticks: Vec<u64> = f.by_ref().map(str::parse).collect::<Result<_, _>>().ok()?;
    let idle = ticks.get(3)? + ticks.get(4)?;
    Some((ticks.iter().sum(), idle))
}

/// The name of a running compiler or build tool.
fn builder() -> Option<String> {
    std::fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
        .filter_map(|e| std::fs::read_to_string(e.path().join("comm")).ok())
        .map(|c| c.trim_end().to_owned())
        .find(|c| BUILDERS.contains(&c.as_str()))
}

/// `program`, under `taskset -c cpus` unless `cpus` is empty.
fn pinned(cpus: &str, program: &Path) -> Command {
    if cpus.is_empty() {
        return Command::new(program);
    }
    let mut c = Command::new("taskset");
    c.arg("-c").arg(cpus).arg(program);
    c
}

/// Started servers, killed on drop.
#[derive(Debug)]
pub(super) struct Cluster(Vec<Running>);

impl Cluster {
    /// Starts `nodes` servers of `server`, in one cluster if more than
    /// one, and waits for their client ports. A lone server logs to
    /// `base.log`; server `i` of a cluster to `base-n{i}.log`, with its
    /// configuration in `base-n{i}.conf`.
    pub(super) fn start(
        host: &Host,
        server: &Server,
        nodes: usize,
        base: &Path,
    ) -> Result<Cluster, SuiteError> {
        if nodes <= 1 {
            let log = suffixed(base, ".log");
            let one = Running::start(&host.server_cpus, host.port, server, &[], &log)?;
            return Ok(Cluster(vec![one]));
        }
        let fits = |first: u16| u16::try_from(usize::from(first) + nodes - 1).is_ok();
        if !fits(host.port) || !fits(host.cluster_port) {
            return Err(SuiteError::Ports(nodes));
        }
        let mut all = Vec::with_capacity(nodes);
        for i in 0..nodes {
            let conf = suffixed(base, &format!("-n{i}.conf"));
            std::fs::write(&conf, node_conf(host.cluster_port, i, nodes))?;
            let args = ["-c".into(), conf.display().to_string()];
            let log = suffixed(base, &format!("-n{i}.log"));
            let port = host.port + i as u16;
            all.push(Running::start(
                &host.server_cpus,
                port,
                server,
                &args,
                &log,
            )?);
        }
        Ok(Cluster(all))
    }

    /// The servers' process IDs, in order.
    pub(super) fn pids(&self) -> Vec<u32> {
        self.0.iter().map(Running::pid).collect()
    }
}

/// `base` with `suffix` appended to its file name.
fn suffixed(base: &Path, suffix: &str) -> PathBuf {
    let mut s = OsString::from(base);
    s.push(suffix);
    s.into()
}

/// The configuration of server `node` of a cluster of `nodes`, whose
/// cluster ports start at `first` and fit: a name of its own and routes
/// to all the others. `nats-server` and naq read it alike.
fn node_conf(first: u16, node: usize, nodes: usize) -> String {
    let port = |i: usize| first + i as u16;
    let mut c = format!(
        "server_name: n{node}\ncluster {{\n  name: naq-bench\n  listen: 127.0.0.1:{}\n  routes: [\n",
        port(node)
    );
    for i in (0..nodes).filter(|&i| i != node) {
        let _ = writeln!(c, "    nats-route://127.0.0.1:{}", port(i));
    }
    c.push_str("  ]\n}\n");
    c
}

/// A started server, killed on drop.
#[derive(Debug)]
pub(super) struct Running(Child);

impl Running {
    /// Starts `server` on CPUs `cpus` with client port `port`, `extra`
    /// before its args, and waits for its port.
    pub(super) fn start(
        cpus: &str,
        port: u16,
        server: &Server,
        extra: &[String],
        log: &Path,
    ) -> Result<Running, SuiteError> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        // A server already there would answer for the new one.
        TcpListener::bind(addr).map_err(|_| SuiteError::PortInUse(port))?;
        let f = File::create(log)?;
        let fail = |why: String| SuiteError::Server {
            name: server.name.clone(),
            why,
            log: log.to_owned(),
        };
        let child = pinned(cpus, &server.program)
            .args(["-a", "127.0.0.1", "-p", &port.to_string()])
            .args(extra)
            .args(&server.args)
            .stdin(Stdio::null())
            .stdout(f.try_clone()?)
            .stderr(f)
            .spawn()
            .map_err(|e| fail(format!("cannot start {}: {e}", server.program.display())))?;
        let mut r = Running(child);
        let deadline = Instant::now() + START_LIMIT;
        loop {
            if let Some(status) = r.0.try_wait()? {
                return Err(fail(format!("exited at start ({status})")));
            }
            if TcpStream::connect_timeout(&addr, POLL).is_ok() {
                return Ok(r);
            }
            if Instant::now() > deadline {
                return Err(fail("port not open".into()));
            }
            thread::sleep(POLL);
        }
    }

    /// The server's process ID (`taskset` execs it).
    pub(super) fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs `naq_load` and returns its record. Writes the command and the
/// load's own output to `out`.
pub(super) fn load(
    cpus: &str,
    program: &Path,
    args: &[String],
    limit: Duration,
    out: &mut dyn Write,
) -> Result<Value, SuiteError> {
    writeln!(out, "$ {} {}", program.display(), args.join(" "))?;
    let mut child = pinned(cpus, program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| SuiteError::Load(format!("cannot start {}: {e}", program.display())))?;
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SuiteError::Load(format!("timed out after {limit:?}")));
        }
        thread::sleep(POLL);
    };
    let (mut stdout, mut stderr) = (String::new(), String::new());
    if let Some(mut p) = child.stdout.take() {
        p.read_to_string(&mut stdout)?;
    }
    if let Some(mut p) = child.stderr.take() {
        p.read_to_string(&mut stderr)?;
    }
    write!(out, "{stderr}")?;
    if !status.success() {
        return Err(SuiteError::Load(format!("failed ({status})")));
    }
    stdout
        .lines()
        .find_map(|l| serde_json::from_str::<Value>(l).ok())
        .ok_or_else(|| SuiteError::Load("no record on stdout".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server that runs `body` as a shell script, whatever its arguments.
    fn script(dir: &Path, body: &str) -> Server {
        use std::os::unix::fs::PermissionsExt;
        let program = dir.join("server.sh");
        std::fs::write(&program, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        Server {
            name: "sh".into(),
            program,
            args: vec!["--x".into()],
        }
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn idle_ticks_come_from_the_cpu_line() {
        let stat = "cpu  10 2 8 70 10 0 0 0 0 0\ncpu0 1 1 1 1 1 0 0 0 0 0\n";
        assert_eq!(stat_times(stat), Some((100, 80)));
        assert_eq!(stat_times("cpu0 1 2 3 4 5\n"), None);
        assert_eq!(stat_times("cpu  1 2 x\n"), None);
        assert_eq!(stat_times("cpu  1 2 3\n"), None);
        assert!(cpu_times().is_some());
        // Whatever runs now, the scan works.
        let _ = builder();
    }

    #[test]
    fn the_idle_wait_retries_then_gives_up() {
        let mut seen = vec![(1.0, None), (0.95, Some("rustc".into())), (0.5, None)];
        let mut out = Vec::new();
        wait_idle(&mut out, || seen.pop().unwrap()).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out,
            "naq_suite: waiting for idle (50% idle)\n\
             naq_suite: waiting for idle (95% idle, rustc running)\n"
        );
        let e = wait_idle(&mut Vec::new(), || (0.1, None)).unwrap_err();
        assert!(matches!(e, SuiteError::Busy));
        let (idle, _) = probe();
        assert!((0.0..=1.0).contains(&idle), "{idle}");
    }

    #[test]
    fn programs_run_pinned_only_with_a_cpu_list() {
        let c = pinned("", Path::new("x"));
        assert_eq!(c.get_program(), "x");
        let c = pinned("4-5", Path::new("x"));
        assert_eq!(c.get_program(), "taskset");
        assert_eq!(c.get_args().collect::<Vec<_>>(), ["-c", "4-5", "x"]);
    }

    #[test]
    fn servers_that_do_not_come_up_name_their_log() {
        let dir = std::env::temp_dir().join(format!("naq-suite-host-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("s.log");
        let port = free_port();
        let e = Running::start(
            "",
            port,
            &script(&dir, "echo \"$@\" >&2; exit 3"),
            &[],
            &log,
        )
        .unwrap_err();
        assert!(e.to_string().starts_with("sh: exited at start"), "{e}");
        assert!(e.to_string().ends_with("s.log"), "{e}");
        let said = std::fs::read_to_string(&log).unwrap();
        assert_eq!(said, format!("-a 127.0.0.1 -p {port} --x\n"));
        let missing = Server {
            program: dir.join("missing"),
            ..script(&dir, "")
        };
        let e = Running::start("", port, &missing, &[], &log).unwrap_err();
        assert!(e.to_string().contains("cannot start"), "{e}");
        let taken = TcpListener::bind("127.0.0.1:0").unwrap();
        let busy = taken.local_addr().unwrap().port();
        let e = Running::start("", busy, &script(&dir, ""), &[], &log).unwrap_err();
        assert!(matches!(e, SuiteError::PortInUse(_)), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn each_server_of_a_cluster_routes_to_all_the_others() {
        assert_eq!(
            node_conf(6222, 1, 3),
            "server_name: n1\ncluster {\n  name: naq-bench\n  listen: 127.0.0.1:6223\n  \
             routes: [\n    nats-route://127.0.0.1:6222\n    nats-route://127.0.0.1:6224\n  ]\n}\n"
        );
        assert_eq!(
            suffixed(Path::new("/l/naq-x-16-0"), "-n2.log"),
            Path::new("/l/naq-x-16-0-n2.log")
        );
    }

    /// A free port below the kernel's ephemeral ones: one that tests that
    /// release a port they bound to port 0 do not take again.
    fn low_port() -> u16 {
        let base = 20_000 + (std::process::id() % 1_000) as u16 * 10;
        (base..base + 10)
            .find(|&p| TcpListener::bind((Ipv4Addr::LOCALHOST, p)).is_ok())
            .unwrap()
    }

    #[test]
    fn a_cluster_that_does_not_come_up_names_the_log_of_its_server() {
        let dir = std::env::temp_dir().join(format!("naq-suite-cluster-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("sh-x-16-0");
        let mut h = Host {
            port: low_port(),
            cluster_port: 6222,
            server_cpus: String::new(),
            load_cpus: String::new(),
            idle_check: false,
        };
        let failing = script(&dir, "echo \"$@\" >&2; exit 3");
        let e = Cluster::start(&h, &failing, 3, &base).unwrap_err();
        assert!(e.to_string().ends_with("sh-x-16-0-n0.log"), "{e}");
        let said = std::fs::read_to_string(dir.join("sh-x-16-0-n0.log")).unwrap();
        let conf = dir.join("sh-x-16-0-n0.conf");
        assert_eq!(
            said,
            format!("-a 127.0.0.1 -p {} -c {} --x\n", h.port, conf.display())
        );
        assert!(
            std::fs::read_to_string(&conf)
                .unwrap()
                .starts_with("server_name: n0\n")
        );
        let e = Cluster::start(&h, &failing, 1, &base).unwrap_err();
        assert!(e.to_string().ends_with("sh-x-16-0.log"), "{e}");
        h.port = 65534;
        let e = Cluster::start(&h, &failing, 3, &base).unwrap_err();
        assert!(matches!(e, SuiteError::Ports(3)), "{e}");
        h.port = free_port();
        h.cluster_port = 65535;
        let e = Cluster::start(&h, &failing, 2, &base).unwrap_err();
        assert!(matches!(e, SuiteError::Ports(2)), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_runs_return_their_record_or_why_not() {
        let sh = Path::new("/bin/sh");
        let run = |script: &str, limit: Duration| {
            let mut out = Vec::new();
            let args = ["-c".into(), script.into()];
            let r = load("", sh, &args, limit, &mut out);
            (r, String::from_utf8(out).unwrap())
        };
        let long = Duration::from_secs(10);
        let (r, out) = run("echo note; echo '{\"a\":1}'; echo said >&2", long);
        assert_eq!(r.unwrap()["a"], 1);
        assert!(
            out.starts_with("$ /bin/sh -c ") && out.ends_with("said\n"),
            "{out}"
        );
        let (r, out) = run("echo why >&2; exit 1", long);
        assert!(r.unwrap_err().to_string().starts_with("naq_load: failed"));
        assert!(out.ends_with("why\n"), "{out}");
        let (r, _) = run("echo plain", long);
        assert!(r.unwrap_err().to_string().contains("no record"));
        let (r, _) = run("sleep 5", Duration::from_millis(50));
        assert!(r.unwrap_err().to_string().contains("timed out"));
        let mut out = Vec::new();
        let e = load("", Path::new("/nonexistent"), &[], long, &mut out).unwrap_err();
        assert!(e.to_string().contains("cannot start"), "{e}");
    }
}
