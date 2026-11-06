//! The query of a monitoring request, read as Go's `net/url` and
//! `nats-server` read it: the first value of a key wins, and a value that
//! does not parse is refused with Go's words.

use std::fmt::Write as _;

/// The keys and values of a query, decoded, in order.
#[derive(Debug, Default)]
pub(crate) struct Query {
    pairs: Vec<(String, String)>,
    /// It came over HTTP, not in a `$SYS` request: `http_req_stats`
    /// counts it.
    pub(super) http: bool,
}

/// A value the request cannot have: the 400 body.
pub(crate) type Refused = String;

impl Query {
    /// The pairs of `raw`, as `url.ParseQuery` takes them: split at `&`;
    /// a pair with `;` or a bad escape is left out.
    pub(crate) fn parse(raw: &str) -> Query {
        let pairs = raw
            .split('&')
            .filter(|p| !p.is_empty() && !p.contains(';'))
            .filter_map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                Some((unescape(k)?, unescape(v)?))
            })
            .collect();
        Query { pairs, http: true }
    }

    /// The options of a `$SYS` request, as the keys and values of the
    /// HTTP endpoint that shows the same.
    pub(crate) const fn of_pairs(pairs: Vec<(String, String)>) -> Query {
        Query { pairs, http: false }
    }

    /// The first value of `key`, or `""`.
    pub(crate) fn get(&self, key: &str) -> &str {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map_or("", |(_, v)| v)
    }

    /// `key` as a bool, as `strconv.ParseBool` takes it; empty is false.
    pub(crate) fn bool(&self, key: &str) -> Result<bool, Refused> {
        match self.get(key) {
            "" | "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
            "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
            v => Err(format!(
                "Error decoding boolean for '{key}': strconv.ParseBool: parsing {}: invalid syntax",
                quote(v)
            )),
        }
    }

    /// `key` as an int, as `strconv.Atoi` takes it; empty is 0.
    pub(crate) fn int(&self, key: &str) -> Result<i64, Refused> {
        let v = self.get(key);
        if v.is_empty() {
            return Ok(0);
        }
        let digits = v.strip_prefix(['+', '-']).unwrap_or(v);
        let why = |what| {
            format!(
                "Error decoding int for '{key}': strconv.Atoi: parsing {}: {what}",
                quote(v)
            )
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(why("invalid syntax"));
        }
        v.parse().map_err(|_| why("value out of range"))
    }

    /// `key` as a uint64, as `strconv.ParseUint(v, 10, 64)` takes it;
    /// empty is 0.
    pub(crate) fn uint(&self, key: &str) -> Result<u64, Refused> {
        let v = self.get(key);
        if v.is_empty() {
            return Ok(0);
        }
        let why = |what| {
            format!(
                "Error decoding uint64 for '{key}': strconv.ParseUint: parsing {}: {what}",
                quote(v)
            )
        };
        if !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(why("invalid syntax"));
        }
        v.parse().map_err(|_| why("value out of range"))
    }

    /// `subs`: `detail` in any case, else a bool.
    pub(crate) fn subs(&self) -> Result<Subs, Refused> {
        if self.get("subs").eq_ignore_ascii_case("detail") {
            return Ok(Subs::Detail);
        }
        Ok(if self.bool("subs")? {
            Subs::List
        } else {
            Subs::None
        })
    }
}

/// How much of the subscriptions a request asks for: `subs=1` for
/// subjects, `subs=detail` for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subs {
    None,
    List,
    Detail,
}

/// `s` with `+` as a space and `%XX` escapes decoded, as
/// `url.QueryUnescape` does; `None` for a bad escape or bytes that are
/// not UTF-8.
pub(crate) fn unescape(s: &str) -> Option<String> {
    percent(s, true)
}

/// `s` with `%XX` escapes decoded, and `+` kept if `plus` is not a
/// space.
pub(crate) fn percent(s: &str, plus: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b.get(i + 1..i + 3)?;
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' if plus => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// `s` quoted as Go's `strconv.Quote` does it, for printable text.
pub(crate) fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            c if c.is_control() => {
                let n = u32::from(c);
                let _ = if n < 0x80 {
                    write!(out, "\\x{n:02x}")
                } else {
                    write!(out, "\\u{n:04x}")
                };
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_value_of_a_key_wins() {
        let q = Query::parse("a=1&a=2&b=x+y%21&c&;d=1&e=%zz&&f=");
        assert_eq!(q.get("a"), "1");
        assert_eq!(q.get("b"), "x y!");
        assert_eq!(q.get("c"), "");
        assert_eq!(q.get("d"), "");
        assert_eq!(q.get("e"), "");
        assert_eq!(q.get("nope"), "");
        assert_eq!(q.pairs.len(), 5);
    }

    #[test]
    fn bools_are_read_as_go_reads_them() {
        let q = Query::parse("a=T&b=False&c=yes&d=");
        assert_eq!(q.bool("a"), Ok(true));
        assert_eq!(q.bool("b"), Ok(false));
        assert_eq!(q.bool("d"), Ok(false));
        assert_eq!(
            q.bool("c").unwrap_err(),
            r#"Error decoding boolean for 'c': strconv.ParseBool: parsing "yes": invalid syntax"#
        );
    }

    #[test]
    fn numbers_are_read_as_go_reads_them() {
        let q = Query::parse("a=-5&b=%2B7&c=x&d=99999999999999999999&e=-1&f=18446744073709551615");
        assert_eq!(q.int("a"), Ok(-5));
        assert_eq!(q.int("b"), Ok(7));
        assert_eq!(q.int("none"), Ok(0));
        assert_eq!(
            q.int("c").unwrap_err(),
            r#"Error decoding int for 'c': strconv.Atoi: parsing "x": invalid syntax"#
        );
        assert_eq!(
            q.int("d").unwrap_err(),
            r#"Error decoding int for 'd': strconv.Atoi: parsing "99999999999999999999": value out of range"#
        );
        assert_eq!(q.uint("f"), Ok(u64::MAX));
        assert_eq!(q.uint("none"), Ok(0));
        assert_eq!(
            q.uint("e").unwrap_err(),
            r#"Error decoding uint64 for 'e': strconv.ParseUint: parsing "-1": invalid syntax"#
        );
        assert!(q.uint("d").unwrap_err().ends_with(": value out of range"));
    }

    #[test]
    fn subs_is_detail_or_a_bool() {
        assert_eq!(Query::parse("subs=DeTail").subs(), Ok(Subs::Detail));
        assert_eq!(Query::parse("subs=1").subs(), Ok(Subs::List));
        assert_eq!(Query::parse("").subs(), Ok(Subs::None));
        assert!(Query::parse("subs=x").subs().is_err());
    }

    #[test]
    fn quoting_escapes_what_go_escapes() {
        assert_eq!(
            quote("a\"b\\c\n\u{1}\u{85}\u{8}\t\r\u{7}\u{b}\u{c}"),
            r#""a\"b\\c\n\x01\u0085\b\t\r\a\v\f""#
        );
        assert_eq!(percent("a+b%2F", false).as_deref(), Some("a+b/"));
        assert_eq!(percent("%ff", false), None);
    }
}
