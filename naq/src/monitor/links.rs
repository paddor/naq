//! `/leafz`: the leaf node links, to Go hubs and to naq hubs and leafs.

use serde::Serialize;

use super::http::Response;
use super::query::{Query, Refused};
use super::{ask_all, now, pretty, text};
use crate::lane::Lane;
use crate::perms::LinkPerms;
use crate::server::Shared;
use crate::stats::Totals;

/// One leaf node link, as `/leafz` shows it.
#[derive(Debug, Serialize)]
struct LeafInfo {
    id: u64,
    name: String,
    is_spoke: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_isolated: bool,
    account: String,
    ip: String,
    port: u16,
    in_msgs: u64,
    out_msgs: u64,
    in_bytes: u64,
    out_bytes: u64,
    subscriptions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    subscriptions_list: Option<Vec<String>>,
    compression: &'static str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    websocket: bool,
    /// The slot of a naq link, whose messages every lane counts.
    #[serde(skip)]
    slot: Option<u16>,
}

/// What a lane tells of leaf node links.
#[derive(Debug, Default)]
struct Links {
    links: Vec<LeafInfo>,
    /// Messages of naq hubs and leafs on the lane, by slot.
    slots: Vec<(u16, Totals)>,
}

/// The leaf node links of `lane`, with the subjects of their hubs'
/// interest, and its counts of naq links; on lane 0, the naq leafs and
/// naq hubs too.
fn links(lane: &Lane) -> Links {
    let mut all = go_links(lane);
    if let Some(mesh) = lane.mesh.borrow().as_ref() {
        naq_links(lane, mesh, &mut all);
    }
    Links {
        links: all,
        slots: lane.slots.totals(),
    }
}

/// The links of `lane` to Go hubs.
fn go_links(lane: &Lane) -> Vec<LeafInfo> {
    lane.links
        .borrow()
        .iter()
        .map(|l| {
            let t = l.client.tally.totals();
            let subs = l.hub_subjects();
            let f = &l.facts;
            LeafInfo {
                id: l.id,
                name: f.name.clone(),
                is_spoke: true,
                is_isolated: f.isolated,
                account: lane.shared.accounts.name(l.account).to_owned(),
                ip: f.ip.clone(),
                port: f.port,
                in_msgs: t.in_msgs,
                out_msgs: t.out_msgs,
                in_bytes: t.in_bytes,
                out_bytes: t.out_bytes,
                subscriptions: subs.len(),
                subscriptions_list: Some(subs),
                compression: "off",
                websocket: f.websocket,
                slot: None,
            }
        })
        .collect()
}

/// Adds the naq leafs linked here and the naq hubs that are up, of
/// `mesh` on `lane`, to `all`, with the subjects of their interest.
fn naq_links(lane: &Lane, mesh: &crate::mesh::Mesh, all: &mut Vec<LeafInfo>) {
    let accounts = &lane.shared.accounts;
    // Interest a link's permissions leave out is not applied: not listed.
    let info = |id,
                name: &str,
                spoke,
                account: u32,
                heard: &crate::mesh::Heard,
                perms: Option<&LinkPerms>| {
        let mut subs: Vec<String> = heard
            .entries()
            .filter(|e| perms.is_none_or(|p| p.takes_interest(e.1)))
            .map(|e| text(e.1))
            .collect();
        subs.sort_unstable();
        LeafInfo {
            id,
            name: name.to_owned(),
            is_spoke: spoke,
            is_isolated: false,
            account: accounts.name(account).to_owned(),
            ip: String::new(),
            port: 0,
            in_msgs: 0,
            out_msgs: 0,
            in_bytes: 0,
            out_bytes: 0,
            subscriptions: subs.len(),
            subscriptions_list: Some(subs),
            compression: "off",
            websocket: false,
            slot: None,
        }
    };
    for l in mesh.leafs.borrow().iter() {
        let perms = l.carries.perms.as_deref();
        let mut i = info(l.link, &l.name, false, l.account, &l.heard, perms);
        i.is_isolated = l.carries.isolated;
        i.slot = Some(l.slot);
        all.push(i);
    }
    for h in mesh.hubs.borrow().iter().filter(|h| h.up) {
        let mut i = info(
            h.link,
            &h.name,
            true,
            h.account,
            &h.heard,
            h.perms.as_deref(),
        );
        i.ip.clone_from(&h.host);
        i.port = h.port;
        i.is_isolated = h.isolated;
        i.slot = Some(h.slot);
        all.push(i);
    }
}

#[derive(Debug, Serialize)]
struct Leafz<'a> {
    server_id: &'a str,
    now: String,
    leafnodes: usize,
    leafs: Vec<LeafInfo>,
}

/// `/leafz`: `subs` for the subjects of each link, `acc` for the links
/// of one account.
pub(super) async fn answer(shared: &Shared, q: &Query) -> Result<Response, Refused> {
    let subs = q.bool("subs")?;
    let acc = q.get("acc").to_owned();
    let (mut leafs, mut slots) = (Vec::new(), Vec::new());
    for lane in ask_all(shared, links).await {
        leafs.extend(lane.links);
        slots.extend(lane.slots);
    }
    leafs.retain(|l| acc.is_empty() || l.account == acc);
    // Every lane counts the messages of naq links.
    for l in &mut leafs {
        let Some(s) = l.slot else { continue };
        for &(_, t) in slots.iter().filter(|&&(at, _)| at == s) {
            l.in_msgs += t.in_msgs;
            l.in_bytes += t.in_bytes;
            l.out_msgs += t.out_msgs;
            l.out_bytes += t.out_bytes;
        }
    }
    leafs.sort_by_key(|l| l.id);
    if !subs {
        for l in &mut leafs {
            l.subscriptions_list = None;
        }
    }
    Ok(pretty(&Leafz {
        server_id: &shared.server_id,
        now: now(),
        leafnodes: leafs.len(),
        leafs,
    }))
}
