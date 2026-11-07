//! `--signal`: a signal for a running server, as `nats-server --signal`
//! sends it.

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// The name `pgrep` finds servers by.
const PROGRAM: &str = "naq";

/// Sends the signal `spec` names, `cmd[=pid]`: to the process ID given,
/// read from the pid file given, to those that start with it if it ends
/// in `*`, or to the one server running.
pub(crate) fn send(spec: &str) -> Result<(), String> {
    let mut parts = spec.split('=');
    let cmd = parts.next().unwrap_or_default();
    let target = parts.next();
    if parts.next().is_some() {
        return Err(format!("invalid signal parameters: {spec:?}"));
    }
    let sig = match cmd {
        "stop" => Signal::SIGKILL,
        "quit" => Signal::SIGINT,
        "term" => Signal::SIGTERM,
        "reopen" => Signal::SIGUSR1,
        "reload" => Signal::SIGHUP,
        "ldm" => Signal::SIGUSR2,
        _ => return Err(format!("unknown signal {cmd:?}")),
    };
    for pid in pids(target)? {
        kill(Pid::from_raw(pid), sig).map_err(|e| format!("signal {cmd:?} {pid}: {e}"))?;
    }
    Ok(())
}

/// The processes `target` names.
fn pids(target: Option<&str>) -> Result<Vec<i32>, String> {
    let Some(t) = target.filter(|t| !t.is_empty()) else {
        return match running()?.as_slice() {
            [] => Err(format!("no {PROGRAM} processes running")),
            [one] => Ok(vec![*one]),
            many => Err(format!(
                "multiple {PROGRAM} processes running:\n{}",
                many.iter()
                    .map(i32::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            )),
        };
    };
    // A pid file, or the process ID itself.
    let text = std::fs::read_to_string(t).unwrap_or_else(|_| t.to_owned());
    let text = text.trim();
    if let Some(prefix) = text.strip_suffix('*') {
        return Ok(running()?
            .into_iter()
            .filter(|p| p.to_string().starts_with(prefix))
            .collect());
    }
    text.parse()
        .map(|p| vec![p])
        .map_err(|_| format!("invalid pid: {text}"))
}

/// The servers running, by `pgrep`, but this process.
fn running() -> Result<Vec<i32>, String> {
    let out = std::process::Command::new("pgrep")
        .args(["-x", PROGRAM])
        .output()
        .map_err(|_| "unable to resolve pid, try providing one".to_owned())?;
    let me = i32::try_from(std::process::id()).unwrap_or_default();
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .filter(|&p| p != me)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_read_as_pids_pid_files_or_globs() {
        assert_eq!(pids(Some("42")), Ok(vec![42]));
        let file = std::env::temp_dir().join(format!("naq-sig-{}.pid", std::process::id()));
        std::fs::write(&file, "43\n").unwrap();
        assert_eq!(pids(Some(file.to_str().unwrap())), Ok(vec![43]));
        std::fs::remove_file(&file).unwrap();
        // No process ID starts with this.
        assert_eq!(pids(Some("0*")), Ok(vec![]));
        assert_eq!(pids(Some("x")), Err("invalid pid: x".into()));
    }
}
