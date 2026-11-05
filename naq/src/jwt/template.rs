//! The permission templates of scoped signing keys, filled in for a user
//! as `nats-server` fills them: `{{name()}}`, `{{subject()}}`,
//! `{{account-name()}}`, `{{account-subject()}}`, `{{tag(k)}}` and
//! `{{account-tag(k)}}`.

use super::Claims;
use super::claims::{self, Permission, UserLimits};

/// Most subjects one template entry may become.
const MAX_EXPANSIONS: usize = 4096;

/// What a template fills in with.
pub(crate) struct Values<'a> {
    pub(crate) user: &'a Claims<claims::User>,
    pub(crate) account: &'a Claims<claims::Account>,
}

/// Template `t` filled in from `v`; `None` if a deny entry names a tag
/// the user lacks, or an entry has an operation not defined.
pub(crate) fn fill(t: &UserLimits, v: &Values<'_>) -> Option<UserLimits> {
    let mut out = t.clone();
    fill_permission(&mut out.permissions.publish, v)?;
    fill_permission(&mut out.permissions.subscribe, v)?;
    Some(out)
}

/// `p` filled in: allow entries that cannot be are left out, and if none
/// is left of some, everything is denied.
fn fill_permission(p: &mut Permission, v: &Values<'_>) -> Option<()> {
    let had = !p.allow.is_empty();
    p.allow = list(&p.allow, v, false)?;
    p.deny = list(&p.deny, v, true)?;
    if had && p.allow.is_empty() {
        p.deny.push(">".into());
    }
    Some(())
}

/// The entries of `all` filled in; with `strict`, one that cannot be
/// fails them all.
fn list(all: &[String], v: &Values<'_>, strict: bool) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(all.len());
    for entry in all {
        let ops = holes(entry);
        if ops.is_empty() {
            out.push(entry.clone());
            continue;
        }
        let mut values: Vec<Vec<String>> = Vec::with_capacity(ops.len());
        for (_, op) in &ops {
            let vals = value(op.trim(), v)?;
            values.push(if vals.is_empty() {
                if strict {
                    return None;
                }
                vec![" ".to_owned()]
            } else {
                vals
            });
        }
        let count = values
            .iter()
            .map(Vec::len)
            .try_fold(1usize, usize::checked_mul)?;
        if count > MAX_EXPANSIONS || out.len() + count > MAX_EXPANSIONS {
            return None;
        }
        for pick in product(&values) {
            let mut s = entry.clone();
            for ((hole, _), val) in ops.iter().zip(&pick) {
                s = s.replace(hole.as_str(), val);
            }
            if s.contains(' ') || !naq_proto::subject::is_valid_filter(s.as_bytes()) {
                if strict {
                    return None;
                }
                continue;
            }
            out.push(s);
        }
    }
    Some(out)
}

/// The `{{...}}` holes of `entry`, with the operation inside each.
fn holes(entry: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut rest = entry;
    while let Some(at) = rest.find("{{") {
        let after = &rest[at + 2..];
        let Some(end) = after.find('}') else {
            break;
        };
        let inner = &after[..end];
        if !inner.is_empty() && after[end..].starts_with("}}") {
            found.push((format!("{{{{{inner}}}}}"), inner.to_owned()));
            rest = &after[end + 2..];
        } else {
            rest = &after[end..];
        }
    }
    found
}

/// What operation `op` stands for; `None` if it is not defined.
fn value(op: &str, v: &Values<'_>) -> Option<Vec<String>> {
    let is = |name: &str| op.eq_ignore_ascii_case(name);
    if is("name()") {
        return Some(vec![v.user.name.clone()]);
    }
    if is("subject()") {
        return Some(vec![v.user.sub.clone()]);
    }
    if is("account-name()") {
        return Some(vec![v.account.name.clone()]);
    }
    if is("account-subject()") {
        return Some(vec![v.user.nats.issuer_account.clone()]);
    }
    let call = |prefix: &str| {
        let head = op.get(..prefix.len())?;
        (head.eq_ignore_ascii_case(prefix) && op.ends_with(')'))
            .then(|| &op[prefix.len()..op.len() - 1])
    };
    let (tags, key) = if let Some(k) = call("account-tag(") {
        (&v.account.nats.tags, k)
    } else {
        (&v.user.nats.tags, call("tag(")?)
    };
    let prefix = format!("{}:", key.to_ascii_lowercase());
    Some(
        tags.iter()
            .filter_map(|t| t.strip_prefix(&prefix))
            .map(str::to_owned)
            .collect(),
    )
}

/// Every pick of one value from each list of `values`, in order.
fn product(values: &[Vec<String>]) -> Vec<Vec<String>> {
    values.iter().fold(vec![Vec::new()], |acc, vals| {
        acc.iter()
            .flat_map(|pick| {
                vals.iter().map(move |v| {
                    let mut p = pick.clone();
                    p.push(v.clone());
                    p
                })
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(name: &str, tags: &[&str]) -> (Claims<claims::User>, Claims<claims::Account>) {
        let user = Claims {
            name: name.into(),
            sub: "UKEY".into(),
            nats: claims::User {
                tags: tags.iter().map(|t| (*t).to_owned()).collect(),
                issuer_account: "AKEY".into(),
                ..claims::User::default()
            },
            ..Claims::default()
        };
        let account = Claims {
            name: "acc".into(),
            nats: claims::Account {
                tags: vec!["dept:eng".into()],
                ..claims::Account::default()
            },
            ..Claims::default()
        };
        (user, account)
    }

    fn filled(
        allow: &[&str],
        deny: &[&str],
        name: &str,
        tags: &[&str],
    ) -> Option<(Vec<String>, Vec<String>)> {
        let (user, account) = values(name, tags);
        let mut t = UserLimits::default();
        t.permissions.publish.allow = allow.iter().map(|s| (*s).to_owned()).collect();
        t.permissions.publish.deny = deny.iter().map(|s| (*s).to_owned()).collect();
        let v = Values {
            user: &user,
            account: &account,
        };
        let p = fill(&t, &v)?.permissions.publish;
        Some((p.allow, p.deny))
    }

    #[test]
    fn a_template_fills_in_names_keys_and_tags() {
        let (allow, _) = filled(
            &[
                "{{name()}}.>",
                "{{subject()}}.x",
                "{{account-name()}}.{{account-subject()}}",
                "{{tag(t)}}.{{account-tag(dept)}}",
                "plain",
            ],
            &[],
            "svc",
            &["t:a", "t:b", "u:c"],
        )
        .unwrap();
        assert_eq!(
            allow,
            ["svc.>", "UKEY.x", "acc.AKEY", "a.eng", "b.eng", "plain"]
        );
    }

    #[test]
    fn a_missing_tag_drops_an_allow_entry_and_fails_a_deny_one() {
        let (allow, deny) = filled(&["{{tag(t)}}.x"], &[], "svc", &[]).unwrap();
        assert_eq!(allow, Vec::<String>::new());
        assert_eq!(deny, [">"], "nothing allowed is left: all is denied");
        assert!(filled(&[], &["{{tag(t)}}"], "svc", &[]).is_none());
        assert!(
            filled(&["{{nope()}}"], &[], "svc", &[]).is_none(),
            "an unknown operation"
        );
        assert_eq!(
            holes("a.{{x}}.{b}}.{{ y }}"),
            [
                ("{{x}}".into(), "x".into()),
                ("{{ y }}".into(), " y ".into())
            ]
        );
    }
}
