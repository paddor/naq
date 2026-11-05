//! Shadows: a subscription's stand-ins in the accounts its own imports
//! streams from.

use std::rc::Rc;

use crate::conn::Client;
use crate::imports::service::Tap;
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
    let imports = lane.shared.accounts.imports(account);
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

/// Sets the shadows of the plain interest in `filter` of `account` of the
/// naq hub or leaf in `slot`, on `lane`: there with `add`, else gone.
/// Queue groups of naq links get no shadows: their messages go to the
/// link's account only.
pub(crate) fn server(lane: &Lane, account: u32, filter: &[u8], slot: u16, add: bool) {
    let imports = lane.shared.accounts.imports(account);
    if lane.slots.is_route(slot) {
        return;
    }
    for (k, im) in imports.streams.iter().enumerate() {
        let Some(subject) = im.shadow(filter) else {
            continue;
        };
        // Imports are few: their count fits.
        let import = k as u32;
        let this = |t: &Tap| {
            matches!(*t, Tap::Shadow { slot: s, importer: a, import: i, .. }
                if s == slot && a == account && i == import)
        };
        let mut index = lane.index(im.from).borrow_mut();
        let has = index.has_tap(&subject, this);
        if add && !has {
            let to_routes = !lane.slots.is_hub(slot);
            index.tap(
                &subject,
                Tap::Shadow {
                    slot,
                    importer: account,
                    import,
                    to_routes,
                },
            );
        } else if !add && has {
            index.untap(&subject, this);
        } else {
            continue;
        }
        drop(index);
        lane.changed(im.from, &subject, None);
    }
}
