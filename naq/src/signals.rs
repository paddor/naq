//! The signals a server handles, as `nats-server` handles them.

use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::Server;

/// The signals `nats-server` handles, caught from the moment this is made:
/// `INT`, `TERM`, `USR1`, `USR2` and `HUP` no longer end the process. Make
/// it before starting the server, as `nats-server` installs its handlers
/// before it takes connections or writes its process ID file; then hand it
/// to [`Server::wait_for_signals`].
///
/// # Examples
///
/// ```no_run
/// let signals = naq::Signals::catch()?;
/// let server = naq::Server::start(&naq::Options::default())?;
/// server.wait_for_signals(signals);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct Signals {
    /// Where the handlers run.
    rt: tokio::runtime::Runtime,
    int: Signal,
    term: Signal,
    hup: Signal,
    usr1: Signal,
    usr2: Signal,
}

impl Signals {
    /// Catches the signals from now on.
    ///
    /// # Errors
    ///
    /// The handlers cannot be installed.
    pub fn catch() -> std::io::Result<Signals> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let caught = {
            let _in = rt.enter();
            (
                signal(SignalKind::interrupt())?,
                signal(SignalKind::terminate())?,
                signal(SignalKind::hangup())?,
                signal(SignalKind::user_defined1())?,
                signal(SignalKind::user_defined2())?,
            )
        };
        let (int, term, hup, usr1, usr2) = caught;
        Ok(Signals {
            rt,
            int,
            term,
            hup,
            usr1,
            usr2,
        })
    }

    /// Waits for a signal that stops `server`, acting on the others as
    /// they come.
    pub(crate) fn wait(self, server: &Server) {
        let log = server.log();
        let Signals {
            rt,
            mut int,
            mut term,
            mut hup,
            mut usr1,
            mut usr2,
        } = self;
        rt.block_on(async {
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
                    _ => return,
                }
            }
        });
    }
}
