//! Request bodies as `nats-server` reads them, with Go's `json.Unmarshal`
//! into a struct of options: its syntax and type errors in its words, keys
//! matched without regard to ASCII case, the last of a key winning, and
//! unknown keys ignored.

/// Nesting deeper than this is an error, as in Go.
const MAX_DEPTH: usize = 10_000;

/// The Go type of an option, as its errors name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A string type, by its Go name.
    Str(&'static str),
    /// `bool`.
    Bool,
    /// A signed integer type of 64 bits, by its Go name.
    Int(&'static str),
    /// `uint64`.
    Uint,
    /// `[]string`.
    Strs,
}

/// The options of one Go struct: its name, and the JSON keys of the two
/// structs it embeds.
#[derive(Debug)]
pub(crate) struct Fields {
    /// The struct's name, without its package.
    pub(crate) name: &'static str,
    pub(crate) keys: [&'static [(&'static str, Kind)]; 2],
}

/// A value a body gave an option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Str(String),
    Bool(bool),
    Int(i64),
    Uint(u64),
    Strs(Vec<String>),
}

/// The options a body set, by key.
#[derive(Debug, Default)]
pub(crate) struct Set(Vec<(&'static str, Value)>);

impl Set {
    fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// The string `key` was set to, or `""`.
    pub(crate) fn str(&self, key: &str) -> &str {
        match self.get(key) {
            Some(Value::Str(s)) => s,
            _ => "",
        }
    }

    /// Whether `key` was set to true.
    pub(crate) fn bool(&self, key: &str) -> bool {
        matches!(self.get(key), Some(Value::Bool(true)))
    }

    /// The integer `key` was set to, or 0.
    pub(crate) fn int(&self, key: &str) -> i64 {
        match self.get(key) {
            Some(Value::Int(n)) => *n,
            _ => 0,
        }
    }

    /// The unsigned integer `key` was set to, or 0.
    pub(crate) fn uint(&self, key: &str) -> u64 {
        match self.get(key) {
            Some(Value::Uint(n)) => *n,
            _ => 0,
        }
    }

    /// The strings `key` was set to, or none.
    pub(crate) fn strs(&self, key: &str) -> &[String] {
        match self.get(key) {
            Some(Value::Strs(s)) => s,
            _ => &[],
        }
    }

    fn set(&mut self, key: &'static str, v: Value) {
        match self.0.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = v,
            None => self.0.push((key, v)),
        }
    }
}

/// The options `body` sets in `fields`, or Go's error.
pub(crate) fn decode(body: &[u8], fields: &Fields) -> Result<Set, String> {
    check(body)?;
    let mut r = Reader { b: body, at: 0 };
    r.space();
    let mut set = Set::default();
    match r.peek() {
        b'{' => {}
        b'n' => return Ok(set),
        c => {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type server.{}",
                what(c),
                fields.name
            ));
        }
    }
    let mut first: Option<String> = None;
    r.at += 1;
    loop {
        r.space();
        if r.peek() == b'}' {
            break;
        }
        let key = r.string();
        r.space();
        r.at += 1; // ':'
        r.space();
        let raw = r.value();
        let field = fields
            .keys
            .iter()
            .flat_map(|g| g.iter())
            .find(|(k, _)| k.eq_ignore_ascii_case(&key));
        if let Some(&(name, kind)) = field {
            match typed(raw, kind) {
                Ok(Some(v)) => set.set(name, v),
                Err((found, ty)) if first.is_none() => {
                    first = Some(format!(
                        "json: cannot unmarshal {found} into Go struct field {}.{name} of type {ty}",
                        fields.name
                    ));
                }
                Ok(None) | Err(_) => {}
            }
        }
        r.space();
        if r.peek() == b',' {
            r.at += 1;
        }
    }
    first.map_or(Ok(set), Err)
}

/// The Go name of `kind`.
const fn go_type(kind: Kind) -> &'static str {
    match kind {
        Kind::Str(t) | Kind::Int(t) => t,
        Kind::Bool => "bool",
        Kind::Uint => "uint64",
        Kind::Strs => "[]string",
    }
}

/// What a value starting with `c` is, as Go's type errors name it.
const fn what(c: u8) -> &'static str {
    match c {
        b'{' => "object",
        b'[' => "array",
        b'"' => "string",
        b't' | b'f' => "bool",
        _ => "number",
    }
}

/// What Go found where it wanted a type: what the value was, and the
/// type.
type Misfit = (String, &'static str);

/// The valid JSON `raw` as an option of `kind`: none for `null`.
fn typed(raw: &[u8], kind: Kind) -> Result<Option<Value>, Misfit> {
    let c = raw[0];
    if c == b'n' {
        return Ok(None);
    }
    let ty = go_type(kind);
    let number = || (format!("number {}", text(raw)), ty);
    let v = match (kind, c) {
        (Kind::Str(_), b'"') => Value::Str(Reader { b: raw, at: 0 }.string()),
        (Kind::Bool, b't' | b'f') => Value::Bool(c == b't'),
        (Kind::Int(_), b'-' | b'0'..=b'9') => Value::Int(text(raw).parse().map_err(|_| number())?),
        (Kind::Uint, b'-' | b'0'..=b'9') => Value::Uint(text(raw).parse().map_err(|_| number())?),
        (Kind::Strs, b'[') => Value::Strs(strings(raw)?),
        _ => return Err((what(c).into(), ty)),
    };
    Ok(Some(v))
}

/// The strings of the valid JSON array `raw`; `null` elements are empty.
fn strings(raw: &[u8]) -> Result<Vec<String>, Misfit> {
    let mut r = Reader { b: raw, at: 1 };
    let mut all = Vec::new();
    let mut first = None;
    loop {
        r.space();
        if r.peek() == b']' {
            break;
        }
        let v = r.value();
        match v[0] {
            b'"' => all.push(Reader { b: v, at: 0 }.string()),
            b'n' => all.push(String::new()),
            c => {
                all.push(String::new());
                first.get_or_insert(what(c));
            }
        }
        r.space();
        if r.peek() == b',' {
            r.at += 1;
        }
    }
    // Go names the type of the element.
    first.map_or(Ok(all), |found| Err((found.into(), "string")))
}

fn text(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap_or_default()
}

/// Reads JSON already checked to be valid.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn peek(&self) -> u8 {
        self.b.get(self.at).copied().unwrap_or(0)
    }

    fn space(&mut self) {
        while matches!(self.peek(), b' ' | b'\t' | b'\r' | b'\n') {
            self.at += 1;
        }
    }

    /// The value here, as it is written.
    fn value(&mut self) -> &'a [u8] {
        let start = self.at;
        let mut depth = 0usize;
        loop {
            match self.peek() {
                b'"' => self.skip_string(),
                b'{' | b'[' => {
                    depth += 1;
                    self.at += 1;
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                    self.at += 1;
                }
                0 => break,
                _ if depth == 0 => {
                    // A number or literal.
                    while self.peek().is_ascii_alphanumeric() || b".+-".contains(&self.peek()) {
                        self.at += 1;
                    }
                }
                _ => self.at += 1,
            }
            if depth == 0 {
                break;
            }
        }
        &self.b[start..self.at]
    }

    /// Moves past the string here.
    const fn skip_string(&mut self) {
        self.at += 1;
        while self.at < self.b.len() {
            let c = self.b[self.at];
            self.at += if c == b'\\' { 2 } else { 1 };
            if c == b'"' {
                return;
            }
        }
    }

    /// The string here, decoded as Go decodes it: bad UTF-8 and lone
    /// surrogates become U+FFFD.
    fn string(&mut self) -> String {
        self.at += 1;
        let mut out = Vec::new();
        loop {
            let c = self.peek();
            self.at += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek();
                    self.at += 1;
                    match e {
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let ch = self.unicode();
                            let mut buf = [0; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The character of the `\u` escape here, with its pair if it is a
    /// surrogate.
    fn unicode(&mut self) -> char {
        let hi = self.hex4();
        if !(0xd800..0xdc00).contains(&hi) {
            return char::from_u32(hi).unwrap_or('\u{fffd}');
        }
        let rest = &self.b[self.at..];
        if rest.starts_with(b"\\u") {
            let save = self.at;
            self.at += 2;
            let lo = self.hex4();
            if (0xdc00..0xe000).contains(&lo) {
                let c = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
                return char::from_u32(c).unwrap_or('\u{fffd}');
            }
            self.at = save;
        }
        '\u{fffd}'
    }

    fn hex4(&mut self) -> u32 {
        let digits = &self.b[self.at..self.at + 4];
        self.at += 4;
        u32::from_str_radix(text(digits), 16).unwrap_or(0xfffd)
    }
}

/// Checks `data` with Go's check and with `serde_json`.
///
/// # Panics
///
/// When they disagree on text `serde_json` reads to the end, nested
/// within its limit.
#[cfg(feature = "fuzzing")]
pub(super) fn fuzz(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let theirs = serde_json::from_str::<serde::de::IgnoredAny>(text);
    if theirs
        .as_ref()
        .is_err_and(|e| e.to_string().contains("recursion limit"))
    {
        return;
    }
    assert_eq!(check(data).is_ok(), theirs.is_ok(), "{text:?}");
}

/// Where Go's scanner is in a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    BeginValueOrEmpty,
    BeginValue,
    BeginStringOrEmpty,
    BeginString,
    EndValue,
    EndTop,
    InString,
    InStringEsc,
    /// In a `\u` escape, with this many hex digits to come.
    InStringEscU(u8),
    Neg,
    One,
    Zero,
    Dot,
    Dot0,
    E,
    ESign,
    E0,
    /// In a literal, at this byte of it.
    Literal(&'static [u8], u8),
}

/// What an open object or array waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Open {
    ObjectKey,
    ObjectValue,
    ArrayValue,
}

/// Whether `data` is JSON, or the error Go's `checkValid` gives.
fn check(data: &[u8]) -> Result<(), String> {
    let mut s = Scanner {
        step: Step::BeginValue,
        open: Vec::new(),
        end_top: false,
    };
    for &c in data {
        s.step(c)?;
    }
    if s.end_top {
        return Ok(());
    }
    s.step(b' ')?;
    if s.end_top {
        Ok(())
    } else {
        Err("unexpected end of JSON input".into())
    }
}

/// Go's JSON scanner, one byte at a time.
struct Scanner {
    step: Step,
    open: Vec<Open>,
    end_top: bool,
}

/// A syntax error at byte `c`, in Go's words.
fn invalid(c: u8, context: &str) -> String {
    format!("invalid character {} {context}", quote_char(c))
}

const fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

impl Scanner {
    fn step(&mut self, c: u8) -> Result<(), String> {
        match self.step {
            Step::BeginValueOrEmpty => {
                if is_space(c) {
                    Ok(())
                } else if c == b']' {
                    self.end_value(c)
                } else {
                    self.begin_value(c)
                }
            }
            Step::BeginValue => self.begin_value(c),
            Step::BeginStringOrEmpty => {
                if is_space(c) {
                    Ok(())
                } else if c == b'}' {
                    if let Some(top) = self.open.last_mut() {
                        *top = Open::ObjectValue;
                    }
                    self.end_value(c)
                } else {
                    self.begin_string(c)
                }
            }
            Step::BeginString => self.begin_string(c),
            Step::EndValue => self.end_value(c),
            Step::EndTop => {
                if is_space(c) {
                    Ok(())
                } else {
                    Err(invalid(c, "after top-level value"))
                }
            }
            Step::InString | Step::InStringEsc | Step::InStringEscU(_) => self.string(c),
            Step::Literal(word, at) => self.literal(c, word, at),
            _ => self.number(c),
        }
    }

    /// A step in a string.
    fn string(&mut self, c: u8) -> Result<(), String> {
        self.step = match (self.step, c) {
            (Step::InString, b'"') => Step::EndValue,
            (Step::InString, b'\\') => Step::InStringEsc,
            (Step::InString, ..0x20) => return Err(invalid(c, "in string literal")),
            (Step::InStringEsc, b'u') => Step::InStringEscU(4),
            (Step::InStringEscU(_), _) if !c.is_ascii_hexdigit() => {
                return Err(invalid(c, "in \\u hexadecimal character escape"));
            }
            (Step::InString | Step::InStringEscU(1), _)
            | (Step::InStringEsc, b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"') => {
                Step::InString
            }
            (Step::InStringEsc, _) => return Err(invalid(c, "in string escape code")),
            (Step::InStringEscU(n), _) => Step::InStringEscU(n - 1),
            (s, _) => s,
        };
        Ok(())
    }

    /// A step in a number.
    fn number(&mut self, c: u8) -> Result<(), String> {
        let next = match (self.step, c) {
            (Step::Neg, b'0') => Step::Zero,
            (Step::Neg, b'1'..=b'9') => Step::One,
            (Step::Neg, _) => return Err(invalid(c, "in numeric literal")),
            (Step::One | Step::Dot0 | Step::E0, b'0'..=b'9') => self.step,
            (Step::One | Step::Zero, b'.') => Step::Dot,
            (Step::One | Step::Zero | Step::Dot0, b'e' | b'E') => Step::E,
            (Step::Dot, b'0'..=b'9') => Step::Dot0,
            (Step::Dot, _) => {
                return Err(invalid(c, "after decimal point in numeric literal"));
            }
            (Step::E, b'+' | b'-') => Step::ESign,
            (Step::E | Step::ESign, b'0'..=b'9') => Step::E0,
            (Step::E | Step::ESign, _) => {
                return Err(invalid(c, "in exponent of numeric literal"));
            }
            _ => return self.end_value(c),
        };
        self.step = next;
        Ok(())
    }

    /// A step in literal `word`, at byte `at` of it.
    fn literal(&mut self, c: u8, word: &'static [u8], at: u8) -> Result<(), String> {
        let want = word[usize::from(at)];
        if c != want {
            let name = text(word);
            return Err(invalid(
                c,
                &format!("in literal {name} (expecting {})", quote_char(want)),
            ));
        }
        self.step = if usize::from(at) + 1 == word.len() {
            Step::EndValue
        } else {
            Step::Literal(word, at + 1)
        };
        Ok(())
    }

    fn push(&mut self, c: u8, open: Open) -> Result<(), String> {
        self.open.push(open);
        if self.open.len() > MAX_DEPTH {
            return Err(invalid(c, "exceeded max depth"));
        }
        Ok(())
    }

    fn begin_value(&mut self, c: u8) -> Result<(), String> {
        if is_space(c) {
            return Ok(());
        }
        self.step = match c {
            b'{' => {
                self.step = Step::BeginStringOrEmpty;
                return self.push(c, Open::ObjectKey);
            }
            b'[' => {
                self.step = Step::BeginValueOrEmpty;
                return self.push(c, Open::ArrayValue);
            }
            b'"' => Step::InString,
            b'-' => Step::Neg,
            b'0' => Step::Zero,
            b'1'..=b'9' => Step::One,
            b't' => Step::Literal(b"true", 1),
            b'f' => Step::Literal(b"false", 1),
            b'n' => Step::Literal(b"null", 1),
            _ => return Err(invalid(c, "looking for beginning of value")),
        };
        Ok(())
    }

    fn begin_string(&mut self, c: u8) -> Result<(), String> {
        if is_space(c) {
            return Ok(());
        }
        if c != b'"' {
            return Err(invalid(c, "looking for beginning of object key string"));
        }
        self.step = Step::InString;
        Ok(())
    }

    fn end_value(&mut self, c: u8) -> Result<(), String> {
        let Some(&top) = self.open.last() else {
            self.step = Step::EndTop;
            self.end_top = true;
            return self.step(c);
        };
        if is_space(c) {
            self.step = Step::EndValue;
            return Ok(());
        }
        match (top, c) {
            (Open::ObjectKey, b':') => {
                *self.open.last_mut().unwrap_or(&mut Open::ObjectKey) = Open::ObjectValue;
                self.step = Step::BeginValue;
            }
            (Open::ObjectKey, _) => return Err(invalid(c, "after object key")),
            (Open::ObjectValue, b',') => {
                if let Some(t) = self.open.last_mut() {
                    *t = Open::ObjectKey;
                }
                self.step = Step::BeginString;
            }
            (Open::ArrayValue, b',') => self.step = Step::BeginValue,
            (Open::ObjectValue, b'}') | (Open::ArrayValue, b']') => self.pop(),
            (Open::ObjectValue, _) => return Err(invalid(c, "after object key:value pair")),
            (Open::ArrayValue, _) => return Err(invalid(c, "after array element")),
        }
        Ok(())
    }

    fn pop(&mut self) {
        self.open.pop();
        if self.open.is_empty() {
            self.step = Step::EndTop;
            self.end_top = true;
        } else {
            self.step = Step::EndValue;
        }
    }
}

/// `c` quoted as Go's `quoteChar` quotes a byte.
fn quote_char(c: u8) -> String {
    match c {
        b'\'' => r"'\''".into(),
        b'"' => "'\"'".into(),
        0x07 => r"'\a'".into(),
        0x08 => r"'\b'".into(),
        0x0c => r"'\f'".into(),
        b'\n' => r"'\n'".into(),
        b'\r' => r"'\r'".into(),
        b'\t' => r"'\t'".into(),
        0x0b => r"'\v'".into(),
        b'\\' => r"'\\'".into(),
        ..0x20 | 0x7f => format!(r"'\x{c:02x}'"),
        // Go quotes the byte as the rune of its value.
        0x80..=0xa0 | 0xad => format!(r"'\u{c:04x}'"),
        _ => format!("'{}'", char::from(c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELDS: Fields = Fields {
        name: "ConnzEventOptions",
        keys: [
            &[
                ("sort", Kind::Str("server.SortOpt")),
                ("auth", Kind::Bool),
                ("offset", Kind::Int("int")),
                ("cid", Kind::Uint),
            ],
            &[("server_name", Kind::Str("string")), ("tags", Kind::Strs)],
        ],
    };

    fn err(body: &[u8]) -> String {
        decode(body, &FIELDS).unwrap_err()
    }

    #[test]
    fn syntax_errors_are_in_go_s_words() {
        let cases: [(&[u8], &str); 7] = [
            (b"", "unexpected end of JSON input"),
            (b" \t", "unexpected end of JSON input"),
            (b"{\"a\":1,", "unexpected end of JSON input"),
            (
                b"{\"a\":1,}",
                "invalid character '}' looking for beginning of object key string",
            ),
            (
                b"[1,]",
                "invalid character ']' looking for beginning of value",
            ),
            (
                b"nope",
                "invalid character 'o' in literal null (expecting 'u')",
            ),
            (b"{\"a\":1}x", "invalid character 'x' after top-level value"),
        ];
        for (body, want) in cases {
            assert_eq!(err(body), want, "{:?}", String::from_utf8_lossy(body));
        }
        let deep = "[".repeat(MAX_DEPTH + 1);
        assert_eq!(
            err(deep.as_bytes()),
            "invalid character '[' exceeded max depth"
        );
    }

    #[test]
    fn bad_tokens_are_named_as_go_names_them() {
        let cases: [(&[u8], &str); 15] = [
            (b"\"a\nb\"", "invalid character '\\n' in string literal"),
            (b"\"\\q\"", "invalid character 'q' in string escape code"),
            (
                b"\"\\u12x4\"",
                "invalid character 'x' in \\u hexadecimal character escape",
            ),
            (b"-", "invalid character ' ' in numeric literal"),
            (b"01", "invalid character '1' after top-level value"),
            (
                b"1.",
                "invalid character ' ' after decimal point in numeric literal",
            ),
            (
                b"1e+",
                "invalid character ' ' in exponent of numeric literal",
            ),
            (
                b"tru",
                "invalid character ' ' in literal true (expecting 'e')",
            ),
            (b"{\"a\" 1}", "invalid character '1' after object key"),
            (
                b"{\"a\":1 \"b\":2}",
                "invalid character '\"' after object key:value pair",
            ),
            (b"[1 2]", "invalid character '2' after array element"),
            (
                b"{'a':1}",
                "invalid character '\\'' looking for beginning of object key string",
            ),
            (
                b"\x00",
                "invalid character '\\x00' looking for beginning of value",
            ),
            (
                b"\xc3\xa9",
                "invalid character '\u{c3}' looking for beginning of value",
            ),
            (
                b"\x85",
                "invalid character '\\u0085' looking for beginning of value",
            ),
        ];
        for (body, want) in cases {
            assert_eq!(err(body), want, "{:?}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn values_of_the_wrong_type_are_named_as_go_names_them() {
        let cases: [(&[u8], &str); 9] = [
            (
                b"[]",
                "array into Go value of type server.ConnzEventOptions",
            ),
            (
                b"true",
                "bool into Go value of type server.ConnzEventOptions",
            ),
            (
                b"{\"sort\":1}",
                "number into Go struct field ConnzEventOptions.sort of type server.SortOpt",
            ),
            (
                b"{\"auth\":\"x\"}",
                "string into Go struct field ConnzEventOptions.auth of type bool",
            ),
            (
                b"{\"offset\":1.5}",
                "number 1.5 into Go struct field ConnzEventOptions.offset of type int",
            ),
            (
                b"{\"cid\":-1}",
                "number -1 into Go struct field ConnzEventOptions.cid of type uint64",
            ),
            (
                b"{\"tags\":\"x\"}",
                "string into Go struct field ConnzEventOptions.tags of type []string",
            ),
            (
                b"{\"tags\":[1]}",
                "number into Go struct field ConnzEventOptions.tags of type string",
            ),
            (
                b"{\"cid\":{},\"sort\":[]}",
                "object into Go struct field ConnzEventOptions.cid of type uint64",
            ),
        ];
        for (body, want) in cases {
            assert_eq!(err(body), format!("json: cannot unmarshal {want}"));
        }
    }

    #[test]
    fn keys_match_in_any_case_and_the_last_one_wins() {
        let body = b"{\"SORT\":\"a\",\"Auth\":true,\"sort\":\"b\",\"zzz\":[[{\"a\":[1]}]],\"offset\":-1,\"cid\":7,\"tags\":[null,\"x\"],\"server_name\":null}";
        let set = decode(body, &FIELDS).unwrap();
        assert_eq!(set.str("sort"), "b");
        assert!(set.bool("auth"));
        assert_eq!(set.int("offset"), -1);
        assert_eq!(set.uint("cid"), 7);
        assert_eq!(set.strs("tags"), ["", "x"]);
        assert_eq!(set.str("server_name"), "");
        assert_eq!(decode(b"null", &FIELDS).unwrap().0.len(), 0);
    }

    #[test]
    fn space_escapes_and_every_literal_read_as_in_go() {
        let body = b" { \"sort\" : \"\\b\\f\\n\\r\\t\\ud800\\u0041\" , \"tags\" : [ ] , \"auth\" : false , \"offset\" : -0 } ";
        let set = decode(body, &FIELDS).unwrap();
        assert_eq!(set.str("sort"), "\u{8}\u{c}\n\r\t\u{fffd}A");
        assert!(!set.bool("auth"));
        assert_eq!(set.int("offset"), 0);
        assert_eq!(set.strs("tags"), [] as [String; 0]);
        for (c, want) in [
            (b'\x07', r"'\a'"),
            (8, r"'\b'"),
            (0x0b, r"'\v'"),
            (0x0c, r"'\f'"),
            (b'\r', r"'\r'"),
            (b'\t', r"'\t'"),
            (b'\\', r"'\\'"),
            (b'"', "'\"'"),
            (0x7f, r"'\x7f'"),
            (0xad, r"'\u00ad'"),
        ] {
            assert_eq!(quote_char(c), want);
        }
    }

    #[test]
    fn strings_decode_as_go_decodes_them() {
        let body = b"{\"server_name\":\"a\\u00e9\\ud83d\\ude00\\ud800\\n\\/\\\"\xff\"}";
        let set = decode(body, &FIELDS).unwrap();
        assert_eq!(
            set.str("server_name"),
            "a\u{e9}\u{1f600}\u{fffd}\n/\"\u{fffd}"
        );
    }
}
