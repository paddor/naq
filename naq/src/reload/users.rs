//! Users and accounts on a reload, as `nats-server` reloads its
//! authorization: the accounts the options add, the logins made anew, and
//! every client checked again.

use std::time::Duration;

use crate::Options;
use crate::lane::Control;
use crate::server::Shared;

/// How long a reload waits for the clients to check themselves again.
const RECHECK: Duration = Duration::from_secs(2);

/// Takes the accounts and users of `new`.
pub(super) fn take(shared: &Shared, new: &Options) {
    let names = accounts(shared, new);
    shared.relogin(new, &names);
}

/// The names of the server's accounts, by id, with those `new` adds:
/// their imports linked and their taps on every lane. Outside operator
/// mode, each takes the connection limit `new` gives it.
fn accounts(shared: &Shared, new: &Options) -> Vec<String> {
    let all = &shared.accounts;
    let before = all.len();
    for a in &new.accounts {
        all.add(&a.name, crate::server::responses);
    }
    let names: Vec<String> = (0..all.len()).map(|id| all.name(id).to_owned()).collect();
    // Checked whole with the options already: they link.
    let linked = (all.len() > before)
        .then(|| crate::imports::link::link_in(new, &names).ok())
        .flatten();
    for (imports, id) in linked
        .into_iter()
        .flatten()
        .zip(0u32..)
        .skip(before as usize)
    {
        if let Some(a) = all.get(id)
            && !imports.is_empty()
        {
            a.set_imports(imports);
        }
        for lane in &shared.lanes {
            lane.control(Control::Imports { account: id });
        }
    }
    if shared.trust().is_none() {
        for (_, a) in all.iter() {
            let limit = new.accounts.iter().find(|x| x.name == a.name);
            let limit = limit.and_then(|x| x.max_connections);
            a.set_limit(limit.map_or(-1, i64::from));
        }
    }
    names
}

/// Has every client check itself again, and waits until all did, a while
/// at most.
pub(super) fn recheck(shared: &Shared) {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    for lane in 0..shared.lanes.len() {
        let tx = tx.clone();
        crate::monitor::on_lane(shared, lane, move |lane| lane.reload(tx));
    }
    drop(tx);
    // Nothing is sent: every sender dropped, or the time is up.
    let _ = rx.recv_timeout(RECHECK);
}
