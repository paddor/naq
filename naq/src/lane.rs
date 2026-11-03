//! A lane's state: its share of the server, on the lane's thread.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use crate::conn::Client;
use crate::index::Index;
use crate::server::Shared;

thread_local! {
    /// Lane state by server and lane index: a process may run several
    /// servers, and a thread may run lanes of several.
    static LANES: RefCell<HashMap<(u64, usize), Rc<Lane>>> = RefCell::new(HashMap::new());
}

/// State of one lane. Only its own thread touches it.
#[derive(Debug)]
pub(crate) struct Lane {
    pub(crate) shared: Arc<Shared>,
    /// Interest of every client of the server.
    pub(crate) index: RefCell<Index>,
    /// Clients with output their writers have not been woken for.
    dirty: RefCell<Vec<Rc<Client>>>,
}

impl Lane {
    /// Notes that `client` has new output. Its writer wakes at the next
    /// [`Lane::flush`], so a batch of messages costs one wake.
    #[inline]
    pub(crate) fn mark(&self, client: &Rc<Client>) {
        if !client.dirty.replace(true) {
            self.dirty.borrow_mut().push(client.clone());
        }
    }

    /// Wakes the writers of every client marked since the last flush.
    pub(crate) fn flush(&self) {
        let mut dirty = self.dirty.take();
        for c in dirty.drain(..) {
            c.dirty.set(false);
            c.wake_writer();
        }
        // Hands the emptied vector back, keeping its capacity.
        let mut slot = self.dirty.borrow_mut();
        if slot.is_empty() {
            *slot = dirty;
        }
    }
}

/// Sets up lane `index` of the server on the calling lane thread.
pub(crate) fn install(shared: Arc<Shared>, index: usize) {
    let key = (shared.id, index);
    let lane = Rc::new(Lane {
        shared,
        index: RefCell::default(),
        dirty: RefCell::default(),
    });
    LANES.with(|l| l.borrow_mut().insert(key, lane));
}

/// The state of lane `index` of server `id`, on that lane's thread.
pub(crate) fn get(id: u64, index: usize) -> Option<Rc<Lane>> {
    LANES.with(|l| l.borrow().get(&(id, index)).cloned())
}
