//! Shadows: a subscription's stand-ins in the accounts its own imports
//! streams from.

use std::rc::Rc;

use crate::conn::Client;
use crate::index::Entry;
use crate::lane::Lane;

/// Where a shadow went: the exporting account and the subject there.
pub(crate) type Shadowed = (u32, Box<[u8]>);

/// Adds the shadows that subscription `sid` of `client` to `filter`, in
/// `queue` if given, gets on `lane`, one per stream import that overlaps
/// it, and announces them as interest of their accounts.
pub(crate) fn add(
    lane: &Lane,
    client: &Rc<Client>,
    sid: &[u8],
    filter: &[u8],
    queue: Option<&[u8]>,
) -> Vec<Shadowed> {
    let account = client.account.get();
    let Some(imports) = lane.shared.imports.get(account as usize) else {
        return Vec::new();
    };
    let mut made = Vec::new();
    for im in &imports.streams {
        let Some(subject) = im.shadow(filter) else {
            continue;
        };
        let entry = Entry::shadow(client.clone(), sid, im.clone());
        lane.index(im.from)
            .borrow_mut()
            .insert(&subject, queue, entry);
        lane.announce(im.from, &subject, queue, true);
        lane.changed(im.from, &subject, queue);
        made.push((im.from, subject.into()));
    }
    made
}

/// Removes the shadows `made` of subscription `sid` of `client`, in
/// `queue` if given, from `lane`, and announces it.
pub(crate) fn remove(
    lane: &Lane,
    client: &Client,
    sid: &[u8],
    queue: Option<&[u8]>,
    made: &[Shadowed],
) {
    for (account, subject) in made {
        lane.index(*account)
            .borrow_mut()
            .remove_shadow(subject, queue, client.id, sid);
        lane.announce(*account, subject, queue, false);
        lane.changed(*account, subject, queue);
    }
}
