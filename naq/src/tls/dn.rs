//! Distinguished names as `nats-server` parses and compares them, with its
//! copy of go-ldap: user names like `CN=alice,O=Acme` against the subject
//! of a client certificate.

/// A distinguished name: its RDNs, most specific first, each a set of
/// attribute types and values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Dn(pub(super) Vec<Vec<(String, String)>>);

impl Dn {
    /// The DN `text` writes out (RFC 4514, as go-ldap reads it), if it is
    /// one.
    pub(crate) fn parse(text: &str) -> Option<Dn> {
        let mut state = Parse::default();
        let bytes = text.as_bytes();
        let mut at = 0;
        while let Some(&byte) = bytes.get(at) {
            if state.escaping {
                state.escaping = false;
                state.trailing = 0;
                if b" \"#+,;<=>\\".contains(&byte) {
                    state.buf.push(byte);
                } else {
                    // Not a special character: two hex digits.
                    let pair = bytes.get(at..at + 2)?;
                    state.buf.push(hex(pair[0])? << 4 | hex(pair[1])?);
                    at += 1;
                }
            } else {
                state.step(byte, bytes.get(at + 1).copied())?;
            }
            at += 1;
        }
        state.end()
    }

    /// Whether `other` is the same DN: the same RDNs in the same order
    /// (`distinguishedNameMatch`).
    pub(crate) fn same(&self, other: &Dn) -> bool {
        self.0.len() == other.0.len() && self.0.iter().zip(&other.0).all(|(a, b)| same_rdn(a, b))
    }

    /// Whether `other` has the same RDNs, in any order.
    pub(crate) fn same_rdns(&self, other: &Dn) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        let mut taken = vec![false; other.0.len()];
        self.0.iter().all(|mine| {
            let found = other
                .0
                .iter()
                .enumerate()
                .find(|(j, theirs)| !taken[*j] && same_rdn(mine, theirs));
            found.is_some_and(|(j, _)| {
                taken[j] = true;
                true
            })
        })
    }
}

/// The state of a DN being parsed.
#[derive(Default)]
struct Parse {
    rdns: Vec<Vec<(String, String)>>,
    rdn: Vec<(String, String)>,
    /// The type of the attribute being read; empty before its `=`.
    kind: String,
    buf: Vec<u8>,
    escaping: bool,
    /// Spaces at the end of `buf` that were not escaped: they are cut.
    trailing: usize,
}

impl Parse {
    /// Takes unescaped character `c`, before `next`.
    fn step(&mut self, c: u8, next: Option<u8>) -> Option<()> {
        match c {
            b'\\' => {
                self.trailing = 0;
                self.escaping = true;
            }
            b'=' => {
                self.kind = self.take()?;
                // A value in BER, not supported.
                if next == Some(b'#') {
                    return None;
                }
            }
            b',' | b'+' => {
                if self.kind.is_empty() {
                    return None;
                }
                let value = self.take()?;
                self.rdn.push((std::mem::take(&mut self.kind), value));
                if c == b',' {
                    self.rdns.push(std::mem::take(&mut self.rdn));
                }
            }
            // Spaces before a type or value.
            b' ' if self.buf.is_empty() => {}
            _ => {
                self.trailing = if c == b' ' { self.trailing + 1 } else { 0 };
                self.buf.push(c);
            }
        }
        Some(())
    }

    /// What was read since the last `=`, `,` or `+`, without trailing
    /// spaces.
    fn take(&mut self) -> Option<String> {
        let mut s = std::mem::take(&mut self.buf);
        s.truncate(s.len() - self.trailing);
        self.trailing = 0;
        String::from_utf8(s).ok()
    }

    /// The DN, once all is read. An attribute without a value is left
    /// out, and so is a last backslash.
    fn end(mut self) -> Option<Dn> {
        if !self.buf.is_empty() {
            if self.kind.is_empty() {
                return None;
            }
            let value = self.take()?;
            self.rdn.push((self.kind, value));
            self.rdns.push(self.rdn);
        }
        Some(Dn(self.rdns))
    }
}

/// The value of hex digit `c`.
fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// Whether RDNs `a` and `b` hold the same attributes, in any order; types
/// in any case.
fn same_rdn(a: &[(String, String)], b: &[(String, String)]) -> bool {
    let holds = |x: &[(String, String)], y: &[(String, String)]| {
        y.iter().all(|(t, v)| {
            x.iter()
                .any(|(t2, v2)| t.eq_ignore_ascii_case(t2) && v == v2)
        })
    };
    a.len() == b.len() && holds(a, b) && holds(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dn(rdns: &[&[(&str, &str)]]) -> Dn {
        Dn(rdns
            .iter()
            .map(|r| {
                r.iter()
                    .map(|(t, v)| ((*t).to_owned(), (*v).to_owned()))
                    .collect()
            })
            .collect())
    }

    #[test]
    fn a_dn_parses_as_go_ldap_parses_it() {
        assert_eq!(
            Dn::parse("CN=alice, O=Acme+OU=Eng ,C=US").unwrap(),
            dn(&[
                &[("CN", "alice")],
                &[("O", "Acme"), ("OU", "Eng")],
                &[("C", "US")]
            ])
        );
        assert_eq!(
            Dn::parse(r"CN=a\,b\41\ ,O=x").unwrap(),
            dn(&[&[("CN", "a,bA ")], &[("O", "x")]]),
            "escapes, and an escaped space stays"
        );
        assert_eq!(Dn::parse("CN=a,").unwrap(), dn(&[&[("CN", "a")]]));
        assert_eq!(Dn::parse("CN=").unwrap(), dn(&[]), "no value: nothing");
        assert_eq!(Dn::parse("alice@acme.com"), None, "no type");
        assert_eq!(Dn::parse("=a"), None);
        assert_eq!(Dn::parse(",CN=a"), None);
        assert_eq!(Dn::parse("CN=#04"), None, "BER");
        assert_eq!(Dn::parse(r"CN=a\").unwrap(), dn(&[&[("CN", "a")]]));
        assert_eq!(Dn::parse(r"CN=a\4"), None);
        assert_eq!(Dn::parse(r"CN=a\zz"), None);
    }

    #[test]
    fn dns_match_by_position_or_by_rdns_in_any_order() {
        let a = Dn::parse("CN=alice,OU=Eng+O=Acme").unwrap();
        let b = Dn::parse("cn=alice,o=Acme+ou=Eng").unwrap();
        assert!(a.same(&b), "types in any case, attributes in any order");
        let moved = Dn::parse("O=Acme+OU=Eng,CN=alice").unwrap();
        assert!(!a.same(&moved) && a.same_rdns(&moved));
        let other = Dn::parse("CN=alice,O=Acme").unwrap();
        assert!(!a.same(&other) && !a.same_rdns(&other));
        let twice = Dn::parse("CN=a,CN=a").unwrap();
        let once = Dn::parse("CN=a,CN=b").unwrap();
        assert!(!twice.same_rdns(&once), "each RDN matches once");
        assert!(
            !Dn::parse("CN=Alice")
                .unwrap()
                .same(&Dn::parse("CN=alice").unwrap())
        );
    }
}
