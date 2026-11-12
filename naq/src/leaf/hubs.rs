//! The remotes to `nats-server` hubs a server dials, each served by a link
//! on a lane of its own, as a reload adds and removes them.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use super::Connector;
use crate::Remote;

/// A remote to a `nats-server` hub, while the server serves it.
#[derive(Debug)]
pub(crate) struct HubRemote {
    pub(crate) remote: Remote,
    /// The lane its link runs on.
    pub(crate) lane: usize,
    /// TLS to its hub, read again at each reload.
    tls: RwLock<Arc<Connector>>,
    /// A reload removed it: it dials no more, and its link goes.
    gone: AtomicBool,
    /// The ID of its link while one is up; 0 for none.
    link: AtomicU64,
}

impl HubRemote {
    /// Remote `remote`, with TLS `tls`, served on lane `lane`.
    pub(crate) fn new(remote: Remote, tls: Connector, lane: usize) -> HubRemote {
        HubRemote {
            remote,
            lane,
            tls: RwLock::new(Arc::new(tls)),
            gone: AtomicBool::new(false),
            link: AtomicU64::new(0),
        }
    }

    /// TLS to its hub, now.
    pub(crate) fn tls(&self) -> Arc<Connector> {
        self.tls
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether a reload removed it.
    pub(crate) fn is_gone(&self) -> bool {
        // Acquire: pairs with `remove`; a link that sees it gone goes.
        self.gone.load(Ordering::Acquire)
    }

    /// Notes link `id` up for it, or none for 0. Whether it is still
    /// wanted: a link up for a remote removed meanwhile goes.
    pub(crate) fn linked(&self, id: u64) -> bool {
        // SeqCst, with `remove`: either the reload sees the link and
        // closes it, or the link sees the removal.
        self.link.store(id, Ordering::SeqCst);
        !self.gone.load(Ordering::SeqCst)
    }

    /// Marks it removed, and returns the ID of its link, if one is up.
    fn remove(&self) -> Option<u64> {
        // SeqCst: see `linked`.
        self.gone.store(true, Ordering::SeqCst);
        let id = self.link.load(Ordering::SeqCst);
        (id != 0).then_some(id)
    }

    /// The name `nats-server` gives a remote in its log, its passwords
    /// masked: its URLs, account, and credentials file or NKey.
    pub(crate) fn name(r: &Remote) -> String {
        let urls: Vec<String> = r.urls.iter().map(|u| format!("{:?}", masked(u))).collect();
        let account = r.account.as_deref().unwrap_or("$G");
        let extra = match (&r.credentials, &r.nkey) {
            (Some(c), _) => format!(", credentials={:?}", c.display().to_string()),
            (None, Some(_)) => ", nkey=\"[REDACTED]\"".to_owned(),
            (None, None) => String::new(),
        };
        format!("urls=[{}], account={account:?}{extra}", urls.join(" "))
    }

    /// Whether it is the remote `r` names.
    pub(crate) fn is(&self, r: &Remote) -> bool {
        same(&self.remote, r)
    }
}

/// Whether `a` and `b` name the same remote, as `nats-server` matches them
/// on a reload: by URLs, account, and credentials file or NKey.
pub(crate) fn same(a: &Remote, b: &Remote) -> bool {
    a.urls == b.urls && a.account == b.account && a.credentials == b.credentials && a.nkey == b.nkey
}

/// URL `u` with its password, if any, as `xxxxx`.
fn masked(u: &str) -> String {
    let Some((scheme, rest)) = u.split_once("://") else {
        return u.to_owned();
    };
    let Some((who, at)) = rest.split_once('@') else {
        return u.to_owned();
    };
    match who.split_once(':') {
        Some((user, _)) => format!("{scheme}://{user}:xxxxx@{at}"),
        None => u.to_owned(),
    }
}

/// The remotes to `nats-server` hubs a server serves.
#[derive(Debug, Default)]
pub(crate) struct HubRemotes {
    all: Mutex<Vec<Arc<HubRemote>>>,
    /// Remotes added so far, to spread them over the lanes.
    added: AtomicUsize,
}

impl HubRemotes {
    /// The remotes `hubs`, with their TLS, spread over `lanes` lanes.
    pub(crate) fn new(hubs: Vec<(Remote, Connector)>, lanes: usize) -> HubRemotes {
        let all = HubRemotes::default();
        for (remote, tls) in hubs {
            all.add(remote, tls, lanes);
        }
        all
    }

    /// Adds remote `remote`, with TLS `tls`, on one of `lanes` lanes.
    pub(crate) fn add(&self, remote: Remote, tls: Connector, lanes: usize) -> Arc<HubRemote> {
        // Relaxed: a count that spreads them.
        let n = self.added.fetch_add(1, Ordering::Relaxed);
        let hub = Arc::new(HubRemote::new(remote, tls, n % lanes.max(1)));
        self.lock().push(hub.clone());
        hub
    }

    /// Those served now.
    pub(crate) fn all(&self) -> Vec<Arc<HubRemote>> {
        self.lock().clone()
    }

    /// Removes those of the remotes not among `keep`, and returns each,
    /// with the ID of its link, if one is up.
    pub(crate) fn remove_others(&self, keep: &[&Remote]) -> Vec<(Arc<HubRemote>, Option<u64>)> {
        let mut all = self.lock();
        let (kept, gone): (Vec<_>, Vec<_>) =
            all.drain(..).partition(|h| keep.iter().any(|r| h.is(r)));
        *all = kept;
        drop(all);
        gone.into_iter()
            .map(|h| {
                let link = h.remove();
                (h, link)
            })
            .collect()
    }

    /// Takes `tls` for the remote it serves that `r` names.
    pub(crate) fn retls(&self, r: &Remote, tls: Connector) {
        if let Some(h) = self.lock().iter().find(|h| h.is(r)) {
            *h.tls.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(tls);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Arc<HubRemote>>> {
        self.all.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(urls: &[&str], account: Option<&str>) -> Remote {
        Remote {
            urls: urls.iter().map(|&u| u.to_owned()).collect(),
            account: account.map(str::to_owned),
            ..Remote::default()
        }
    }

    #[test]
    fn a_remote_is_named_as_nats_server_logs_it() {
        let r = remote(
            &["nats-leaf://a:secret@127.0.0.1:7422", "nats-leaf://t@h:1"],
            Some("APP"),
        );
        assert_eq!(
            HubRemote::name(&r),
            r#"urls=["nats-leaf://a:xxxxx@127.0.0.1:7422" "nats-leaf://t@h:1"], account="APP""#
        );
        let mut r = remote(&["h:1"], None);
        r.nkey = Some("SU...".into());
        assert_eq!(
            HubRemote::name(&r),
            r#"urls=["h:1"], account="$G", nkey="[REDACTED]""#
        );
        r.nkey = None;
        r.credentials = Some("/a.creds".into());
        assert!(HubRemote::name(&r).ends_with(r#", credentials="/a.creds""#));
    }

    #[test]
    fn removed_remotes_go_with_their_link_and_a_link_up_meanwhile_sees_it() {
        let hubs = HubRemotes::default();
        let tls = || Connector::new(&Remote::default()).unwrap();
        let (a, b) = (remote(&["h:1"], None), remote(&["h:2"], None));
        let ha = hubs.add(a.clone(), tls(), 2);
        let hb = hubs.add(b, tls(), 2);
        assert_eq!((ha.lane, hb.lane), (0, 1));
        assert!(hb.linked(7));
        let gone = hubs.remove_others(&[&a]);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].1, Some(7));
        assert!(hb.is_gone() && !hb.linked(8), "removed");
        assert!(ha.linked(9) && !ha.is_gone());
        hubs.retls(&a, tls());
        assert_eq!(hubs.all().len(), 1);
    }
}
