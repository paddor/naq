//! The signals a server handles, as `nats-server` handles them.

use std::pin::Pin;

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
    /// they come. `USR2` puts it in lame duck mode, which stops it once
    /// its clients are gone; meanwhile `TERM` and `USR2` do nothing, and
    /// `INT` stops it at once.
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
            let mut lame: Option<Pin<Box<dyn Future<Output = ()>>>> = None;
            loop {
                // `recv` is cancel-safe: a signal missed by one branch is
                // kept. Lame duck mode goes on where it was.
                let caught = tokio::select! {
                    _ = int.recv() => Caught::Int,
                    _ = term.recv() => Caught::Term,
                    _ = usr2.recv() => Caught::Usr2,
                    _ = usr1.recv() => Caught::Usr1,
                    _ = hup.recv() => Caught::Hup,
                    () = async { if let Some(l) = lame.as_mut() { l.await } }, if lame.is_some() => return,
                };
                log.info(format_args!("Trapped {:?} signal", caught.name()));
                match caught {
                    Caught::Term | Caught::Usr2 if lame.is_some() => {}
                    Caught::Int | Caught::Term => return,
                    Caught::Usr2 => lame = Some(Box::pin(server.lame_duck())),
                    Caught::Usr1 => server.reopen_log(),
                    Caught::Hup => log.error(format_args!(
                        "Failed to reload server configuration: config reload not supported"
                    )),
                }
            }
        });
    }
}

/// A signal caught.
#[derive(Debug, Clone, Copy)]
enum Caught {
    Int,
    Term,
    Hup,
    Usr1,
    Usr2,
}

impl Caught {
    /// Its name, as Go logs it.
    const fn name(self) -> &'static str {
        match self {
            Caught::Int => "interrupt",
            Caught::Term => "terminated",
            Caught::Hup => "hangup",
            Caught::Usr1 => "user defined signal 1",
            Caught::Usr2 => "user defined signal 2",
        }
    }
}
