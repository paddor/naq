//! Leaf nodes on a reload, as `nats-server` reloads its `LeafNode` options:
//! remotes to `nats-server` hubs come and go, and their TLS changes.
//! Nothing else may change: not the port naq leafs dial, nor the remotes
//! to naq hubs, whose slots the mesh fixed at the start.

use std::time::Duration;

use crate::leaf::{Connector, HubRemote, is_naq, same};
use crate::server::Shared;
use crate::{Leafnodes, Options, Remote};

/// Go's refusal of a change to field `field` of `LeafNode`.
fn refusal(field: &str, old: &str, new: &str) -> String {
    format!("config reload not supported for LeafNode: field {field:?}: old={old}, new={new}")
}

/// Whether the remotes to `nats-server` hubs of `new` are not those of
/// `old`, or the change of leaf nodes the server cannot take, in Go's
/// words.
pub(super) fn changed(old: &Options, new: &Options) -> Result<bool, String> {
    hub_port(old.leafnodes.as_ref(), new.leafnodes.as_ref())?;
    if old.leaf_reconnect != new.leaf_reconnect {
        let (o, n) = (old.leaf_reconnect, new.leaf_reconnect);
        let go = crate::log::go_duration;
        return Err(refusal("ReconnectInterval", &go(o), &go(n)));
    }
    let naq = |x: &Options| {
        x.remotes
            .iter()
            .filter(|r| is_naq(r))
            .cloned()
            .collect::<Vec<_>>()
    };
    if naq(old) != naq(new) {
        return Err("config reload not supported for LeafNode: remotes of naq hubs".into());
    }
    let go = |x: &'_ Options| {
        x.remotes
            .iter()
            .filter(|r| !is_naq(r))
            .cloned()
            .collect::<Vec<_>>()
    };
    let (before, after) = (go(old), go(new));
    let mut moved = before.len() != after.len();
    for r in &after {
        match before.iter().find(|b| same(b, r)) {
            Some(b) => same_but_tls(b, r)?,
            None => moved = true,
        }
    }
    Ok(moved)
}

/// Refuses a change of the port naq leafs dial, field by field as Go
/// names them.
fn hub_port(old: Option<&Leafnodes>, new: Option<&Leafnodes>) -> Result<(), String> {
    if old == new {
        return Ok(());
    }
    let none = Leafnodes {
        host: String::new(),
        port: 0,
        ..Leafnodes::default()
    };
    let (o, n) = (old.unwrap_or(&none), new.unwrap_or(&none));
    let users = |l: &Leafnodes| format!("[{} users]", l.users.len());
    let seconds = |d: Duration| d.as_secs_f64().to_string();
    let account = |l: &Leafnodes| l.account.clone().unwrap_or_default();
    if o.users != n.users {
        return Err(refusal("Users", &users(o), &users(n)));
    }
    if o.host != n.host {
        return Err(refusal("Host", &o.host, &n.host));
    }
    if o.port != n.port {
        return Err(refusal("Port", &o.port.to_string(), &n.port.to_string()));
    }
    if o.account != n.account {
        return Err(refusal("Account", &account(o), &account(n)));
    }
    Err(refusal(
        "AuthTimeout",
        &seconds(o.auth_timeout),
        &seconds(n.auth_timeout),
    ))
}

/// Refuses a change of remote `old` to `new`, the same remote, but of its
/// TLS.
fn same_but_tls(old: &Remote, new: &Remote) -> Result<(), String> {
    let bare = |r: &Remote| Remote {
        tls: None,
        ..r.clone()
    };
    if bare(old) == bare(new) {
        return Ok(());
    }
    let list = |l: &[String]| format!("[{}]", l.join(" "));
    let (field, o, n) = if old.no_randomize != new.no_randomize {
        let s = |b: bool| b.to_string();
        ("NoRandomize", s(old.no_randomize), s(new.no_randomize))
    } else if old.deny_imports != new.deny_imports {
        (
            "DenyImports",
            list(&old.deny_imports),
            list(&new.deny_imports),
        )
    } else if old.deny_exports != new.deny_exports {
        (
            "DenyExports",
            list(&old.deny_exports),
            list(&new.deny_exports),
        )
    } else {
        let s = |b: bool| b.to_string();
        let (o, n) = (old.request_isolation, new.request_isolation);
        ("RequestIsolation", s(o), s(n))
    };
    Err(format!(
        "config reload not supported for LeafNode: remote {}: field {field:?}: old={o}, new={n}",
        HubRemote::name(new)
    ))
}

/// Removes the remotes to `nats-server` hubs `new` no longer has, closing
/// their links, and dials those it adds; logs each removal as
/// `nats-server` does.
pub(super) fn apply(shared: &Shared, new: &Options) {
    let keep: Vec<&Remote> = new.remotes.iter().filter(|r| !is_naq(r)).collect();
    for (hub, link) in shared.hubs.remove_others(&keep) {
        let name = HubRemote::name(&hub.remote);
        shared
            .log
            .info(format_args!("Reloaded: LeafNode Remote {name} removed"));
        if let Some(id) = link {
            crate::monitor::on_lane(shared, hub.lane, move |lane| {
                if let Some(l) = lane.links.borrow().iter().find(|l| l.id == id) {
                    l.client.kick(crate::conn::Close::Dropped);
                }
            });
        }
    }
    let have = shared.hubs.all();
    for r in keep.into_iter().filter(|r| !have.iter().any(|h| h.is(r))) {
        let tls = match Connector::new(r) {
            Ok(tls) => tls,
            Err(e) => {
                let e = crate::error::chain(&e);
                shared
                    .log
                    .error(format_args!("Can't add a leafnode remote: {e}"));
                continue;
            }
        };
        let hub = shared.hubs.add(r.clone(), tls, shared.lanes.len());
        crate::monitor::on_lane(shared, hub.lane, move |lane| {
            let shared = lane.shared.clone();
            tokio::task::spawn_local(crate::leaf::run(shared, hub));
        });
    }
}

/// Has the remotes `hubs` the server keeps take their TLS anew, read with
/// the options: their next dial uses it.
pub(super) fn retls(shared: &Shared, hubs: Vec<(Remote, Connector)>) {
    for (r, tls) in hubs {
        shared.hubs.retls(&r, tls);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(remotes: &[&str]) -> Options {
        Options {
            remotes: remotes
                .iter()
                .map(|&u| Remote {
                    urls: vec![u.to_owned()],
                    ..Remote::default()
                })
                .collect(),
            ..Options::default()
        }
    }

    #[test]
    fn remotes_to_go_hubs_come_and_go_and_those_to_naq_hubs_stay() {
        let old = with(&["nats-leaf://h:1", "naq://n:1"]);
        assert_eq!(changed(&old, &old), Ok(false));
        let fewer = with(&["naq://n:1"]);
        assert_eq!(changed(&old, &fewer), Ok(true));
        let more = with(&["nats-leaf://h:1", "nats-leaf://h:2", "naq://n:1"]);
        assert_eq!(changed(&old, &more), Ok(true));
        let other = with(&["nats-leaf://h:1", "naq://n:2"]);
        assert_eq!(
            changed(&old, &other),
            Err("config reload not supported for LeafNode: remotes of naq hubs".into())
        );
        let mut tls = old.clone();
        tls.remotes[0].tls = Some(crate::RemoteTls::default());
        assert_eq!(changed(&old, &tls), Ok(false), "TLS changes in place");
        let mut isolated = old.clone();
        isolated.remotes[0].request_isolation = true;
        assert_eq!(
            changed(&old, &isolated),
            Err(
                r#"config reload not supported for LeafNode: remote urls=["nats-leaf://h:1"], account="$G": field "RequestIsolation": old=false, new=true"#
                    .into()
            )
        );
        let mut ordered = old.clone();
        ordered.remotes[0].no_randomize = true;
        assert!(
            changed(&old, &ordered)
                .unwrap_err()
                .contains(r#"field "NoRandomize""#)
        );
        let mut exports = old;
        exports.remotes[0].deny_exports = vec!["x".into()];
        assert!(
            changed(&with(&["nats-leaf://h:1", "naq://n:1"]), &exports)
                .unwrap_err()
                .ends_with(r#"field "DenyExports": old=[], new=[x]"#)
        );
    }

    /// A change of the port naq leafs dial.
    type Change<'a> = &'a dyn Fn(&mut Leafnodes);

    #[test]
    fn the_port_naq_leafs_dial_and_the_reconnect_interval_stay() {
        let old = Options::default();
        let new = Options {
            leaf_reconnect: Duration::from_secs(2),
            ..Options::default()
        };
        assert_eq!(
            changed(&old, &new),
            Err(r#"config reload not supported for LeafNode: field "ReconnectInterval": old=1s, new=2s"#.into())
        );
        let hub = |f: &dyn Fn(&mut Leafnodes)| {
            let mut l = Leafnodes::default();
            f(&mut l);
            Options {
                leafnodes: Some(l),
                ..Options::default()
            }
        };
        let base = hub(&|_| {});
        assert_eq!(
            changed(&old, &base),
            Err(
                r#"config reload not supported for LeafNode: field "Host": old=, new=0.0.0.0"#
                    .into()
            )
        );
        let cases: [(Change<'_>, &str); 4] = [
            (&|l| l.port = 7423, r#""Port": old=7422, new=7423"#),
            (
                &|l| l.account = Some("A".into()),
                r#""Account": old=, new=A"#,
            ),
            (
                &|l| {
                    l.users.push(crate::User {
                        login: crate::Login::Nkey("U".into()),
                        account: None,
                        permissions: None,
                        connection_types: Vec::new(),
                    });
                },
                r#""Users": old=[0 users], new=[1 users]"#,
            ),
            (
                &|l| l.auth_timeout = Duration::from_secs(3),
                r#""AuthTimeout": old=2, new=3"#,
            ),
        ];
        for (change, says) in cases {
            let e = changed(&base, &hub(change)).unwrap_err();
            assert!(e.ends_with(says), "{e}");
        }
    }
}
