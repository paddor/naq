//! The `nats-server` configuration syntax: keys and values separated by
//! `:`, `=` or blanks, maps in braces, arrays in brackets, comments after
//! `#` or `//`, `$variables`, and `include`.

use std::path::{Path, PathBuf};

/// Includes may nest this deep.
const MAX_INCLUDE_DEPTH: usize = 8;

/// Maps and arrays may nest this deep.
const MAX_DEPTH: usize = 64;

/// A value, with the line it starts on.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Item {
    pub(crate) value: Value,
    pub(crate) line: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Array(Vec<Item>),
    Map(Map),
}

/// Keys and their values, in file order. A later key replaces an earlier.
pub(crate) type Map = Vec<(String, Item)>;

/// Where a parse failed, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) file: Option<PathBuf>,
    pub(crate) line: u32,
    pub(crate) reason: String,
}

/// Parses `text`, read from `file` if given: includes are relative to its
/// directory, else to the current one.
pub(crate) fn parse(text: &str, file: Option<&Path>) -> Result<Map, Failure> {
    let mut p = Parser {
        src: text.as_bytes(),
        at: 0,
        line: 1,
        file: file.map(Path::to_path_buf),
        scopes: Vec::new(),
        includes: 0,
        depth: 0,
    };
    p.map_body(None)
}

struct Parser<'a> {
    src: &'a [u8],
    at: usize,
    line: u32,
    file: Option<PathBuf>,
    /// Maps being read, outermost first: `$variables` look in them.
    scopes: Vec<Map>,
    includes: usize,
    depth: usize,
}

/// Ends a bare string or a number.
const fn ends_bare(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b';' | b',' | b']' | b'}')
}

impl Parser<'_> {
    fn fail<T>(&self, reason: impl Into<String>) -> Result<T, Failure> {
        Err(Failure {
            file: self.file.clone(),
            line: self.line,
            reason: reason.into(),
        })
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.at += 1;
        if b == b'\n' {
            self.line += 1;
        }
        Some(b)
    }

    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.bump();
        }
    }

    /// Skips a comment, if one starts here.
    fn skip_comment(&mut self) -> bool {
        let starts = self.peek() == Some(b'#') || self.src[self.at..].starts_with(b"//");
        if starts {
            while !matches!(self.peek(), None | Some(b'\n')) {
                self.bump();
            }
        }
        starts
    }

    /// Skips blanks, line ends, comments and the separators `sep`.
    fn skip_space(&mut self, sep: &[u8]) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => {
                    self.bump();
                }
                Some(b) if sep.contains(&b) => {
                    self.bump();
                }
                _ if self.skip_comment() => {}
                _ => return,
            }
        }
    }

    /// Key and value pairs up to `end`, or to the end of the input.
    fn map_body(&mut self, end: Option<u8>) -> Result<Map, Failure> {
        self.scopes.push(Map::new());
        loop {
            self.skip_space(b",;");
            match self.peek() {
                None if end.is_none() => break,
                None => return self.fail("unexpected end, `}` missing"),
                Some(b) if Some(b) == end => {
                    self.bump();
                    break;
                }
                Some(_) => {}
            }
            let line = self.line;
            let key = self.key()?;
            if key == "include" && matches!(self.peek(), Some(b' ' | b'\t')) {
                self.include()?;
                continue;
            }
            self.skip_blanks();
            if matches!(self.peek(), Some(b'=' | b':')) {
                self.bump();
                self.skip_blanks();
            }
            let mut item = self.value()?;
            item.line = line;
            self.set(key, item);
        }
        Ok(self.scopes.pop().unwrap_or_default())
    }

    /// Puts `key` into the map being read, replacing an earlier value.
    fn set(&mut self, key: String, item: Item) {
        if let Some(map) = self.scopes.last_mut() {
            match map.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = item,
                None => map.push((key, item)),
            }
        }
    }

    fn key(&mut self) -> Result<String, Failure> {
        if let Some(q @ (b'"' | b'\'')) = self.peek() {
            self.bump();
            return self.quoted(q);
        }
        let start = self.at;
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'=' | b':' | b'{' | b'[') {
                break;
            }
            self.bump();
        }
        if self.at == start {
            return self.fail("expected a key");
        }
        self.text(start, self.at)
    }

    fn text(&self, from: usize, to: usize) -> Result<String, Failure> {
        match std::str::from_utf8(&self.src[from..to]) {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => self.fail("not UTF-8"),
        }
    }

    fn value(&mut self) -> Result<Item, Failure> {
        let line = self.line;
        let value = match self.peek() {
            None | Some(b'\r' | b'\n') => return self.fail("expected a value"),
            Some(b'[') => {
                self.bump();
                self.nested(Self::array)?
            }
            Some(b'{') => {
                self.bump();
                Value::Map(self.nested(|p| p.map_body(Some(b'}')))?)
            }
            Some(q @ (b'"' | b'\'')) => {
                self.bump();
                Value::Str(self.quoted(q)?)
            }
            Some(_) => self.bare()?,
        };
        Ok(Item { value, line })
    }

    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Failure>) -> Result<T, Failure> {
        if self.depth >= MAX_DEPTH {
            return self.fail("nested too deep");
        }
        self.depth += 1;
        let out = f(self);
        self.depth -= 1;
        out
    }

    fn array(&mut self) -> Result<Value, Failure> {
        let mut items = Vec::new();
        loop {
            self.skip_space(b",");
            match self.peek() {
                None => return self.fail("unexpected end, `]` missing"),
                Some(b']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                Some(_) => items.push(self.value()?),
            }
        }
    }

    /// A quoted string after its opening `q`. Double quotes take escapes.
    fn quoted(&mut self, q: u8) -> Result<String, Failure> {
        let mut out = Vec::new();
        loop {
            match self.bump() {
                None => return self.fail("unterminated string"),
                Some(b) if b == q => break,
                Some(b'\\') if q == b'"' => match self.bump() {
                    Some(b't') => out.push(b'\t'),
                    Some(b'n') => out.push(b'\n'),
                    Some(b'r') => out.push(b'\r'),
                    Some(e @ (b'"' | b'\\')) => out.push(e),
                    _ => return self.fail("bad escape in string"),
                },
                Some(b) => out.push(b),
            }
        }
        String::from_utf8(out).or_else(|_| self.fail("not UTF-8"))
    }

    /// A value without quotes: a number, a boolean, a variable or a string.
    fn bare(&mut self) -> Result<Value, Failure> {
        let start = self.at;
        while self.peek().is_some_and(|b| !ends_bare(b)) {
            self.bump();
        }
        let word = self.text(start, self.at)?;
        if let Some(n) = number(&word) {
            return Ok(n);
        }
        match word.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" => return Ok(Value::Bool(true)),
            "false" | "no" | "off" => return Ok(Value::Bool(false)),
            _ => {}
        }
        match word.strip_prefix('$') {
            // A bcrypt hash, not a variable.
            Some(v) if v.starts_with("2a$") || v.starts_with("2b$") || v.starts_with("2y$") => {
                Ok(Value::Str(word))
            }
            Some(v) => self.variable(v),
            None => Ok(Value::Str(word)),
        }
    }

    /// The value of `$name`: the nearest key of that name in the maps being
    /// read, else the environment variable.
    fn variable(&self, name: &str) -> Result<Value, Failure> {
        for map in self.scopes.iter().rev() {
            if let Some((_, item)) = map.iter().find(|(k, _)| k == name) {
                return Ok(item.value.clone());
            }
        }
        match std::env::var(name) {
            Ok(v) => Ok(number(&v).unwrap_or(Value::Str(v))),
            Err(_) => self.fail(format!("variable `${name}` is not defined")),
        }
    }

    /// `include path`: the keys of that file go into the map being read.
    fn include(&mut self) -> Result<(), Failure> {
        self.skip_blanks();
        let path = match self.value()?.value {
            Value::Str(s) => PathBuf::from(s),
            _ => return self.fail("include needs a path"),
        };
        if self.includes >= MAX_INCLUDE_DEPTH {
            return self.fail("includes nested too deep");
        }
        let path = match self.file.as_deref().and_then(Path::parent) {
            Some(dir) if path.is_relative() => dir.join(path),
            _ => path,
        };
        let text = std::fs::read_to_string(&path)
            .or_else(|e| self.fail(format!("include {}: {e}", path.display())))?;
        let mut inner = Parser {
            src: text.as_bytes(),
            at: 0,
            line: 1,
            file: Some(path),
            scopes: std::mem::take(&mut self.scopes),
            includes: self.includes + 1,
            depth: self.depth,
        };
        let result = inner.map_body(None);
        self.scopes = std::mem::take(&mut inner.scopes);
        for (k, v) in result? {
            self.set(k, v);
        }
        Ok(())
    }
}

/// `word` as a number: an integer with an optional size suffix (`k` for
/// 1000, `kb` for 1024, up to `e`), or a float.
fn number(word: &str) -> Option<Value> {
    let digits = word
        .bytes()
        .enumerate()
        .take_while(|&(i, b)| b.is_ascii_digit() || (i == 0 && b == b'-'))
        .count();
    if digits == 0 || (digits == 1 && word.starts_with('-')) {
        return None;
    }
    let (num, suffix) = word.split_at(digits);
    let n: i64 = num.parse().ok()?;
    let suffix = suffix.to_ascii_lowercase();
    if suffix.starts_with('.') {
        return word.parse().ok().map(Value::Float);
    }
    let (unit, binary) = match suffix.as_str() {
        "" => return Some(Value::Int(n)),
        s => {
            let (u, rest) = s.split_at(1);
            match rest {
                "" => (u, false),
                "b" | "i" | "ib" => (u, true),
                _ => return None,
            }
        }
    };
    let power = "kmgtpe".find(unit)? as u32 + 1;
    let base: i64 = if binary { 1024 } else { 1000 };
    n.checked_mul(base.checked_pow(power)?).map(Value::Int)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get<'m>(map: &'m Map, key: &str) -> &'m Value {
        &map.iter().find(|(k, _)| k == key).unwrap().1.value
    }

    #[test]
    fn keys_take_any_separator_and_values_their_types() {
        let m = parse(
            "a: 1\nb = two\nc three\n\"d e\": 'f g'\nh: \"x\\ty\"\ni: [1, 2\n 3]\nj { k: yes }\nl: 1.5\nm: -3\n",
            None,
        )
        .unwrap();
        assert_eq!(get(&m, "a"), &Value::Int(1));
        assert_eq!(get(&m, "b"), &Value::Str("two".into()));
        assert_eq!(get(&m, "c"), &Value::Str("three".into()));
        assert_eq!(get(&m, "d e"), &Value::Str("f g".into()));
        assert_eq!(get(&m, "h"), &Value::Str("x\ty".into()));
        let Value::Array(a) = get(&m, "i") else {
            panic!()
        };
        assert_eq!(a.len(), 3);
        let Value::Map(j) = get(&m, "j") else {
            panic!()
        };
        assert_eq!(get(j, "k"), &Value::Bool(true));
        assert_eq!(get(&m, "l"), &Value::Float(1.5));
        assert_eq!(get(&m, "m"), &Value::Int(-3));
    }

    #[test]
    fn sizes_have_decimal_and_binary_suffixes() {
        assert_eq!(number("2k"), Some(Value::Int(2000)));
        assert_eq!(number("2KB"), Some(Value::Int(2048)));
        assert_eq!(number("1mib"), Some(Value::Int(1 << 20)));
        assert_eq!(number("1g"), Some(Value::Int(1_000_000_000)));
        assert_eq!(number("10s"), None, "a duration stays a string");
        assert_eq!(number("0.0.0.0:4222"), None);
        assert_eq!(number("-"), None);
        assert_eq!(number("9e"), Some(Value::Int(9_000_000_000_000_000_000)));
        assert_eq!(number("99e"), None, "overflow");
    }

    #[test]
    fn comments_go_to_the_line_end() {
        let m = parse("# top\na: 1 # after\n// slashes\nb: x#y\n", None).unwrap();
        assert_eq!(get(&m, "a"), &Value::Int(1));
        assert_eq!(get(&m, "b"), &Value::Str("x#y".into()));
    }

    #[test]
    fn variables_look_in_enclosing_maps_then_the_environment() {
        let m = parse(
            "v: 5\nm { w: 6, a: $v, b: $w }\nc: $PATH\nd: $2a$10$abc\n",
            None,
        )
        .unwrap();
        let Value::Map(inner) = get(&m, "m") else {
            panic!()
        };
        assert_eq!(get(inner, "a"), &Value::Int(5));
        assert_eq!(get(inner, "b"), &Value::Int(6));
        assert!(matches!(get(&m, "c"), Value::Str(_)));
        assert_eq!(get(&m, "d"), &Value::Str("$2a$10$abc".into()));
        let e = parse("a: $NAQ_NO_SUCH_VARIABLE\n", None).unwrap_err();
        assert_eq!(e.line, 1);
    }

    #[test]
    fn a_later_key_replaces_an_earlier_one() {
        let m = parse("a: 1\na: 2\n", None).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(get(&m, "a"), &Value::Int(2));
    }

    #[test]
    fn broken_input_names_its_line() {
        for (text, line) in [
            ("a: 1\nb: [1, 2\n", 3),
            ("a {\n b: 1\n", 3),
            ("a: \"open\n", 2),
            ("a:\n", 1),
            ("a: \"\\q\"\n", 1),
            ("{", 1),
        ] {
            let e = parse(text, None).unwrap_err();
            assert_eq!(e.line, line, "{text:?}: {e:?}");
        }
        let deep = "a: ".to_owned() + &"[".repeat(100);
        assert!(parse(&deep, None).is_err());
    }

    #[test]
    fn includes_read_files_next_to_the_includer() {
        let dir = std::env::temp_dir().join(format!("naq-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("inner.conf"), "b: 2\nc: $a\n").unwrap();
        std::fs::write(dir.join("loop.conf"), "include loop.conf\n").unwrap();
        let outer = dir.join("outer.conf");
        let m = parse("a: 1\ninclude 'inner.conf'\n", Some(&outer)).unwrap();
        assert_eq!(get(&m, "b"), &Value::Int(2));
        assert_eq!(get(&m, "c"), &Value::Int(1));
        assert!(parse("include missing.conf\n", Some(&outer)).is_err());
        assert!(parse("include loop.conf\n", Some(&outer)).is_err());
        assert!(parse("include {}\n", Some(&outer)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
