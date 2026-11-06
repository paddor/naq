//! Permissions, as `nats-server` applies them: what a client may publish
//! and subscribe to, the messages its wildcard subscriptions may not get,
//! and the replies it may publish.

use std::cell::RefCell;

use naq_proto::subject;
use rustc_hash::FxHashMap;
use tokio::time::Instant;

use crate::{Permissions, Responses, Rules};

/// Publish decisions a client caches, at most.
const CACHE: usize = 128;

/// Requests a client may hold replies for, at most.
const REPLIES: usize = 4096;

/// A filter, and the queue group it is for, if one.
type Entry = (Box<[u8]>, Option<Box<[u8]>>);

/// Filters, each maybe for one queue group.
#[derive(Debug, Default)]
struct Filters(Vec<Entry>);

impl Filters {
    fn new(list: &[String]) -> Filters {
        Filters(
            list.iter()
                .map(|f| match f.split_once(' ') {
                    Some((s, q)) => (s.as_bytes().into(), Some(q.trim().as_bytes().into())),
                    None => (f.as_bytes().into(), None),
                })
                .collect(),
        )
    }

    /// The entries whose filter matches `subject`, taken as a subject.
    fn matching<'a>(&'a self, subject: &'a [u8]) -> impl Iterator<Item = Option<&'a [u8]>> + 'a {
        self.0
            .iter()
            .filter(move |(f, _)| subject::matches(f, subject))
            .map(|(_, q)| q.as_deref())
    }

    /// Whether any plain entry matches `subject`.
    fn plain(&self, subject: &[u8]) -> bool {
        self.matching(subject).any(|q| q.is_none())
    }
}

#[derive(Debug, Default)]
struct Compiled {
    allow: Option<Filters>,
    deny: Filters,
}

impl Compiled {
    fn new(r: &Rules) -> Compiled {
        Compiled {
            allow: r.allow.as_deref().map(Filters::new),
            deny: Filters::new(&r.deny),
        }
    }
}

/// A user's permissions, ready to check.
#[derive(Debug)]
pub(crate) struct Perms {
    publish: Compiled,
    subscribe: Compiled,
    responses: Option<Responses>,
    /// The rules, as given.
    rules: Permissions,
}

impl Perms {
    pub(crate) fn new(p: &Permissions) -> Perms {
        let mut publish = Compiled::new(&p.publish);
        if p.responses.is_some() && publish.allow.is_none() {
            // Replies, and nothing else.
            publish.allow = Some(Filters::default());
        }
        Perms {
            publish,
            subscribe: Compiled::new(&p.subscribe),
            responses: p.responses,
            rules: p.clone(),
        }
    }

    /// The rules, as given.
    pub(crate) const fn rules(&self) -> &Permissions {
        &self.rules
    }

    /// Permissions `p`, or none, that deny publishing to `subject` too.
    pub(crate) fn denying(p: Option<&Perms>, subject: &[u8]) -> Perms {
        let mut rules = p.map(|p| p.rules.clone()).unwrap_or_default();
        rules
            .publish
            .deny
            .push(String::from_utf8_lossy(subject).into_owned());
        Perms::new(&rules)
    }

    /// Whether the rules let it publish to `subject`; replies aside.
    pub(crate) fn publish(&self, subject: &[u8]) -> bool {
        self.publish.allow.as_ref().is_none_or(|a| a.plain(subject))
            && !self.publish.deny.plain(subject)
    }

    /// Whether it may subscribe to `filter`, in `queue` if given. A filter
    /// is checked as a subject against the rules, as `nats-server` checks it.
    pub(crate) fn subscribe(&self, filter: &[u8], queue: Option<&[u8]>) -> bool {
        let (allow, deny) = (&self.subscribe.allow, &self.subscribe.deny);
        let decide = |f: &Filters| -> bool {
            let hit = f.matching(filter);
            match queue {
                // A queue entry only counts for a queue subscription.
                Some(q) => {
                    let (mut plain, mut queued, mut named) = (false, false, false);
                    for e in hit {
                        match e {
                            None => plain = true,
                            Some(name) => {
                                queued = true;
                                named |= name == q;
                            }
                        }
                    }
                    if queued { named } else { plain }
                }
                None => f.plain(filter),
            }
        };
        allow.as_ref().is_none_or(decide) && !decide(deny)
    }

    /// Whether messages on `subject` are kept from its subscriptions: a
    /// wildcard subscription may span subjects the rules deny.
    #[inline]
    pub(crate) fn hides(&self, subject: &[u8]) -> bool {
        !self.subscribe.deny.0.is_empty() && self.subscribe.deny.plain(subject)
    }

    /// Whether it may publish replies to requests it gets.
    pub(crate) const fn takes_replies(&self) -> bool {
        self.responses.is_some()
    }
}

/// The permissions of a leaf node link, from this side of it, as
/// `nats-server` applies them: what goes over it, and what comes.
#[derive(Debug)]
pub(crate) struct LinkPerms(Perms);

impl LinkPerms {
    /// Permissions that send what `sends` lets publish and take what
    /// `takes` lets subscribe. `None` where both let everything through.
    pub(crate) fn new(sends: Rules, takes: Rules) -> Option<LinkPerms> {
        let open = |r: &Rules| r.allow.is_none() && r.deny.is_empty();
        (!open(&sends) || !open(&takes)).then(|| {
            LinkPerms(Perms::new(&Permissions {
                publish: sends,
                subscribe: takes,
                responses: None,
            }))
        })
    }

    /// Those of a hub to a leaf that logged in as a user of permissions
    /// `user`, if any, and takes nothing on `deny`: the leaf gets what the
    /// user may subscribe to, and sends what it may publish, as
    /// `nats-server` turns them around for a leaf.
    pub(crate) fn of_leaf(user: Option<&Perms>, deny: &[String]) -> Option<LinkPerms> {
        let (mut sends, takes) = user
            .map(|p| (p.rules.subscribe.clone(), p.rules.publish.clone()))
            .unwrap_or_default();
        sends.deny.extend_from_slice(deny);
        LinkPerms::new(sends, takes)
    }

    /// Whether a message on `subject` goes over the link.
    #[inline]
    pub(crate) fn sends(&self, subject: &[u8]) -> bool {
        self.0.publish(subject)
    }

    /// Whether the other side hears of interest in `filter`.
    pub(crate) fn tells(&self, filter: &[u8]) -> bool {
        self.0.subscribe(filter, None)
    }

    /// Whether interest of the other side in `subject` counts: one the link
    /// may not send to is left out where literal, as `nats-server` leaves it
    /// out. Loop detection and gateway reply subjects always count.
    pub(crate) fn takes_interest(&self, subject: &[u8]) -> bool {
        !subject::is_literal(subject) || internal(subject) || self.0.publish(subject)
    }

    /// Whether a message of the other side on `subject` comes in. Replies
    /// of service imports and JetStream acks always do.
    pub(crate) fn takes(&self, subject: &[u8]) -> bool {
        subject.starts_with(b"_R_.")
            || subject.starts_with(b"$JS.ACK.")
            || self.0.subscribe(subject, None)
    }
}

/// Loop detection and gateway reply subjects, which no permission holds
/// back.
fn internal(subject: &[u8]) -> bool {
    [b"$LDS.".as_slice(), b"_GR_.", b"$GR."]
        .iter()
        .any(|p| subject.starts_with(p))
}

/// A client's permissions with what it learned: decisions on subjects it
/// published to, and the replies it may publish.
#[derive(Debug)]
pub(crate) struct Held {
    pub(crate) perms: std::sync::Arc<Perms>,
    cache: RefCell<FxHashMap<Box<[u8]>, bool>>,
    /// Reply subjects of requests it got: when, and replies sent since.
    replies: RefCell<FxHashMap<Box<[u8]>, Asked>>,
}

/// When a request came, and how many replies went to it since.
type Asked = (Instant, u32);

impl Held {
    pub(crate) fn new(perms: std::sync::Arc<Perms>) -> Held {
        Held {
            perms,
            cache: RefCell::default(),
            replies: RefCell::default(),
        }
    }

    /// Whether it may publish to `subject` now.
    pub(crate) fn may_publish(&self, subject: &[u8]) -> bool {
        let cached = self.cache.borrow().get(subject).copied();
        let ok = cached.unwrap_or_else(|| {
            let ok = self.perms.publish(subject);
            let mut cache = self.cache.borrow_mut();
            if cache.len() >= CACHE {
                cache.clear();
            }
            cache.insert(subject.into(), ok);
            ok
        });
        ok || self.reply_allowed(subject)
    }

    /// Notes that it got a request with `reply`.
    pub(crate) fn got_request(&self, reply: &[u8], now: Instant) {
        if !self.perms.takes_replies() {
            return;
        }
        let mut replies = self.replies.borrow_mut();
        if replies.len() >= REPLIES {
            let expires = self.perms.responses.map(|r| r.expires).unwrap_or_default();
            replies.retain(|_, (t, _)| expires.is_zero() || now - *t < expires);
            if replies.len() >= REPLIES {
                return;
            }
        }
        replies.insert(reply.into(), (now, 0));
    }

    /// Takes one of the replies it may publish to `subject`.
    fn reply_allowed(&self, subject: &[u8]) -> bool {
        let Some(r) = self.perms.responses else {
            return false;
        };
        let mut replies = self.replies.borrow_mut();
        let Some((at, sent)) = replies.get_mut(subject) else {
            return false;
        };
        *sent += 1;
        let ok =
            (r.max == 0 || *sent <= r.max) && (r.expires.is_zero() || at.elapsed() <= r.expires);
        if !ok || (r.max != 0 && *sent >= r.max) {
            replies.remove(subject);
        }
        ok
    }
}

/// `subject` quoted as Go's `%q` quotes it.
pub(crate) fn quoted(subject: &[u8]) -> String {
    let mut s = String::from("\"");
    for c in String::from_utf8_lossy(subject).chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            c if c.is_control() => s.push_str(&c.escape_default().to_string()),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn rules(allow: Option<&[&str]>, deny: &[&str]) -> Rules {
        Rules {
            allow: allow.map(|a| a.iter().map(|s| (*s).to_owned()).collect()),
            deny: deny.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn publish_needs_an_allow_and_no_deny() {
        let p = Perms::new(&Permissions {
            publish: rules(Some(&["orders.>"]), &["orders.secret"]),
            ..Permissions::default()
        });
        assert!(p.publish(b"orders.new"));
        assert!(!p.publish(b"orders.secret"));
        assert!(!p.publish(b"other"));
        let open = Perms::new(&Permissions::default());
        assert!(open.publish(b"anything"));
    }

    #[test]
    fn subscribe_checks_filters_as_subjects_and_queue_entries() {
        let p = Perms::new(&Permissions {
            subscribe: rules(Some(&["a.>", "q.* workers"]), &["a.secret", "q.x workers"]),
            ..Permissions::default()
        });
        assert!(p.subscribe(b"a.b", None));
        assert!(p.subscribe(b"a.*", None), "a wildcard inside the allow");
        assert!(!p.subscribe(b">", None), "wider than the allow");
        assert!(!p.subscribe(b"a.secret", None));
        assert!(p.subscribe(b"q.y", Some(b"workers")));
        assert!(!p.subscribe(b"q.y", Some(b"others")));
        assert!(
            !p.subscribe(b"q.y", None),
            "a queue entry allows its queue only"
        );
        assert!(
            !p.subscribe(b"q.x", Some(b"workers")),
            "denied for that queue"
        );
        assert!(
            p.subscribe(b"a.b", Some(b"any")),
            "a plain entry allows any queue"
        );
        assert!(p.hides(b"a.secret"));
        assert!(!p.hides(b"a.b"));
    }

    #[test]
    fn replies_go_through_for_requests_got_up_to_the_maximum() {
        let p = Perms::new(&Permissions {
            responses: Some(Responses {
                max: 2,
                expires: Duration::ZERO,
            }),
            ..Permissions::default()
        });
        let held = Held::new(std::sync::Arc::new(p));
        assert!(
            !held.may_publish(b"_INBOX.1"),
            "replies only, and none asked"
        );
        held.got_request(b"_INBOX.1", Instant::now());
        assert!(held.may_publish(b"_INBOX.1"));
        assert!(held.may_publish(b"_INBOX.1"));
        assert!(!held.may_publish(b"_INBOX.1"), "past the maximum");
    }

    #[test]
    fn replies_expire() {
        let p = Perms::new(&Permissions {
            responses: Some(Responses {
                max: 0,
                expires: Duration::from_millis(1),
            }),
            ..Permissions::default()
        });
        let held = Held::new(std::sync::Arc::new(p));
        held.got_request(b"r", Instant::now() - Duration::from_secs(1));
        assert!(!held.may_publish(b"r"));
    }

    #[test]
    fn the_cache_keeps_decisions_and_stays_bounded() {
        let held = Held::new(std::sync::Arc::new(Perms::new(&Permissions {
            publish: rules(Some(&["ok.*"]), &[]),
            ..Permissions::default()
        })));
        for i in 0..CACHE * 2 {
            assert!(held.may_publish(format!("ok.{i}").as_bytes()));
            assert!(held.may_publish(format!("ok.{i}").as_bytes()));
        }
        assert!(!held.may_publish(b"no"));
        assert!(held.cache.borrow().len() <= CACHE);
    }

    #[test]
    fn subjects_are_quoted_as_go_quotes_them() {
        assert_eq!(quoted(b"a.b"), "\"a.b\"");
        assert_eq!(quoted(b"a\"b\\"), "\"a\\\"b\\\\\"");
    }
}
