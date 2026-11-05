//! Subject transforms of imports, as `nats-server` makes them strict: the
//! destination takes the source's `*` tokens by `$N` or `{{wildcard(N)}}`,
//! all of them, and has `>` where the source has it.

/// A transform from subjects matching a source filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Transform {
    /// The source filter's tokens.
    src: Vec<Box<[u8]>>,
    /// The source and destination as written.
    src_text: String,
    dest_text: String,
    /// The destination's tokens.
    dest: Vec<Part>,
}

/// A token of a transform's destination.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    /// Written as it is.
    Literal(Box<[u8]>),
    /// The token of the subject at this index: a `*` of the source.
    Token(usize),
    /// `>`: the rest of the subject.
    Rest,
}

/// Why a transform cannot be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Invalid {
    /// A side is no valid subject, the destination has a `*`, or only one
    /// side has `>`.
    #[error("invalid subject")]
    Subject,
    /// The destination names a `*` the source lacks.
    #[error("invalid mapping destination: wildcard index out of range in {0}")]
    OutOfRange(String),
    /// The destination leaves out some `*` of the source.
    #[error("invalid mapping destination: not using all of the token wildcard(s) in {0}")]
    Unused(String),
    /// The destination uses a function other than `wildcard`.
    #[error(
        "invalid mapping destination: the only mapping function allowed for import transforms is {{{{Wildcard()}}}} in {0}"
    )]
    Function(String),
}

impl Transform {
    /// The transform from `src` to `dest`, strict as an import's must be.
    pub(crate) fn new(src: &str, dest: &str) -> Result<Transform, Invalid> {
        let (stoks, wilds, src_tail) = info(src).ok_or(Invalid::Subject)?;
        let (dtoks, dwilds, dest_tail) = info(dest).ok_or(Invalid::Subject)?;
        if dwilds > 0 || src_tail != dest_tail {
            return Err(Invalid::Subject);
        }
        // The index in the source of its `n`th `*`, from 1.
        let star = |n: usize| {
            stoks
                .iter()
                .enumerate()
                .filter(|(_, t)| **t == "*")
                .nth(n.wrapping_sub(1))
                .map(|(i, _)| i)
        };
        let mut used = 0;
        let mut parts = Vec::with_capacity(dtoks.len());
        for t in &dtoks {
            let part = match placeholder(t) {
                Holder::None if *t == ">" => Part::Rest,
                Holder::None => Part::Literal(t.as_bytes().into()),
                Holder::Wildcard(n) if wilds > 0 || src_tail => {
                    let at = star(n).ok_or_else(|| Invalid::OutOfRange(format!("{t}: [{n}]")))?;
                    used += 1;
                    Part::Token(at)
                }
                Holder::Wildcard(_) => return Err(Invalid::OutOfRange((*t).to_owned())),
                Holder::Function => return Err(Invalid::Function((*t).to_owned())),
            };
            parts.push(part);
        }
        if used < wilds {
            return Err(Invalid::Unused(dest.to_owned()));
        }
        Ok(Transform {
            src: stoks.iter().map(|t| t.as_bytes().into()).collect(),
            src_text: src.to_owned(),
            dest_text: dest.to_owned(),
            dest: parts,
        })
    }

    /// Writes `subject`, which the source matches, transformed into `out`.
    /// Wildcards in it pass as tokens: a filter maps as a subject does.
    pub(crate) fn apply(&self, subject: &[u8], out: &mut Vec<u8>) {
        let tokens: Vec<&[u8]> = subject.split(|&b| b == b'.').collect();
        for (i, p) in self.dest.iter().enumerate() {
            if i > 0 {
                out.push(b'.');
            }
            match p {
                Part::Literal(t) => out.extend_from_slice(t),
                Part::Token(at) => out.extend_from_slice(tokens.get(*at).copied().unwrap_or(b"")),
                Part::Rest => {
                    let from = self.src.len().saturating_sub(1);
                    let rest = tokens.get(from..).unwrap_or_default();
                    for (k, t) in rest.iter().enumerate() {
                        if k > 0 {
                            out.push(b'.');
                        }
                        out.extend_from_slice(t);
                    }
                }
            }
        }
    }

    /// The transform back, made as `nats-server` makes it: from the
    /// destination with its placeholders as `*`, to the source with its
    /// `*` tokens as the destination's placeholders, in their order.
    pub(crate) fn reverse(&self) -> Option<Transform> {
        let src = untokenize(&self.dest_text);
        let mut holders = self
            .dest_text
            .split('.')
            .filter(|t| matches!(placeholder(t), Holder::Wildcard(_)));
        let dest: Vec<&str> = self
            .src_text
            .split('.')
            .map(|t| if t == "*" { holders.next() } else { Some(t) })
            .collect::<Option<_>>()?;
        Transform::new(&src, &dest.join(".")).ok()
    }
}

/// The tokens of `s`, how many are `*`, and whether it ends in `>`; `None`
/// if it is no valid filter.
fn info(s: &str) -> Option<(Vec<&str>, usize, bool)> {
    if !naq_proto::subject::is_valid_filter(s.as_bytes()) {
        return None;
    }
    let tokens: Vec<&str> = s.split('.').collect();
    let wilds = tokens.iter().filter(|t| **t == "*").count();
    let tail = tokens.last() == Some(&">");
    Some((tokens, wilds, tail))
}

/// What a destination token is.
enum Holder {
    /// A literal.
    None,
    /// `$N` or `{{wildcard(N)}}`.
    Wildcard(usize),
    /// Another mapping function.
    Function,
}

fn placeholder(t: &str) -> Holder {
    if let Some(n) = t.strip_prefix('$') {
        // Other tokens starting with `$` are literals.
        return n.parse().map_or(Holder::None, Holder::Wildcard);
    }
    let Some(inner) = t
        .strip_prefix("{{")
        .and_then(|t| t.strip_suffix("}}"))
        .filter(|_| t.len() > 4)
    else {
        return Holder::None;
    };
    let inner = inner.trim();
    let Some(args) = inner
        .strip_prefix("wildcard")
        .or_else(|| inner.strip_prefix("Wildcard"))
        .and_then(|a| a.trim_start().strip_prefix('('))
        .and_then(|a| a.strip_suffix(')'))
    else {
        return Holder::Function;
    };
    args.trim()
        .parse()
        .map_or(Holder::Function, Holder::Wildcard)
}

/// `subject` with each `*` as `$1`, `$2`, ... in order.
pub(crate) fn tokenize(subject: &str) -> String {
    let mut n = 0;
    let tokens: Vec<String> = subject
        .split('.')
        .map(|t| {
            if t == "*" {
                n += 1;
                format!("${n}")
            } else {
                t.to_owned()
            }
        })
        .collect();
    tokens.join(".")
}

/// `subject` with each placeholder as `*`.
pub(crate) fn untokenize(subject: &str) -> String {
    let tokens: Vec<&str> = subject
        .split('.')
        .map(|t| match placeholder(t) {
            Holder::Wildcard(_) => "*",
            _ => t,
        })
        .collect();
    tokens.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(t: &Transform, s: &str) -> String {
        let mut out = Vec::new();
        t.apply(s.as_bytes(), &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_transform_moves_wildcard_tokens_and_the_rest() {
        let t = Transform::new("a.*.*", "b.$2.$1").unwrap();
        assert_eq!(apply(&t, "a.x.y"), "b.y.x");
        let t = Transform::new("s.>", "pre.s.>").unwrap();
        assert_eq!(apply(&t, "s.x.y"), "pre.s.x.y");
        let t = Transform::new("a.*.>", "{{wildcard(1)}}.b.>").unwrap();
        assert_eq!(apply(&t, "a.x.y.z"), "x.b.y.z");
        assert_eq!(apply(&t, "a.*.>"), "*.b.>", "a filter maps as a subject");
    }

    #[test]
    fn a_reversed_transform_maps_back() {
        let t = Transform::new("a.*.*", "b.$2.$1").unwrap();
        let r = t.reverse().unwrap();
        assert_eq!(apply(&r, "b.y.x"), "a.x.y");
        let t = Transform::new("s.*.x", "pre.$1.x")
            .unwrap()
            .reverse()
            .unwrap();
        assert_eq!(apply(&t, "pre.q.x"), "s.q.x");
        let t = Transform::new("s.>", "pre.s.>").unwrap().reverse().unwrap();
        assert_eq!(apply(&t, "pre.s.a.b"), "s.a.b");
    }

    #[test]
    fn an_import_transform_must_be_strict() {
        assert_eq!(
            Transform::new("a.*", "b.*.*"),
            Err(Invalid::Subject),
            "no * in the destination"
        );
        assert_eq!(
            Transform::new("a.*", "b.$1.$2").unwrap_err().to_string(),
            "invalid mapping destination: wildcard index out of range in $2: [2]"
        );
        assert_eq!(
            Transform::new("a.*", "b.c").unwrap_err().to_string(),
            "invalid mapping destination: not using all of the token wildcard(s) in b.c"
        );
        assert!(matches!(
            Transform::new("a.*", "{{partition(2,1)}}"),
            Err(Invalid::Function(_))
        ));
        assert_eq!(Transform::new("a.>", "b"), Err(Invalid::Subject));
        assert_eq!(
            Transform::new("a.b", "c.$1").unwrap_err(),
            Invalid::OutOfRange("$1".into())
        );
        assert!(
            Transform::new("a.$x", "b.$x").is_ok(),
            "a $ that is no number is a literal"
        );
    }

    #[test]
    fn placeholders_turn_into_wildcards_and_back() {
        assert_eq!(tokenize("a.*.b.*"), "a.$1.b.$2");
        assert_eq!(untokenize("a.$2.{{wildcard(1)}}.$x"), "a.*.*.$x");
    }
}
