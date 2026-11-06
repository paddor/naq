//! The signals a server handles, as `nats-server` handles them.

use tokio::signal::unix::{SignalKind, signal};

use crate::Server;

/// Waits for a signal that stops `server`, acting on the others as they
/// come.
pub(crate) async fn wait(server: &Server) -> std::io::Result<()> {
    let mut int = signal(SignalKind::interrupt())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut usr2 = signal(SignalKind::user_defined2())?;
    let log = server.log();
    // `recv` is cancel-safe: a signal missed by one branch is kept.
    loop {
        let name = tokio::select! {
            _ = int.recv() => "interrupt",
            _ = term.recv() => "terminated",
            _ = usr2.recv() => "user defined signal 2",
            _ = usr1.recv() => "user defined signal 1",
            _ = hup.recv() => "hangup",
        };
        log.info(format_args!("Trapped {name:?} signal"));
        match name {
            "user defined signal 1" => server.reopen_log(),
            "hangup" => log.error(format_args!(
                "Failed to reload server configuration: config reload not supported"
            )),
            _ => return Ok(()),
        }
    }
}
