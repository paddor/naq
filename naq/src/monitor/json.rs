//! JSON as Go's `encoding/json` writes it: `<`, `>`, `&`, U+2028 and
//! U+2029 escaped, floats without a needless `.0`, and `MarshalIndent`'s
//! layout.

use std::io;

use serde::Serialize;
use serde_json::ser::{CompactFormatter, Formatter, PrettyFormatter};

/// `v` as `json.MarshalIndent(v, "", indent)` writes it.
pub(crate) fn indented<T: Serialize + ?Sized>(v: &T, indent: &[u8]) -> Vec<u8> {
    encode(v, PrettyFormatter::with_indent(indent))
}

/// `v` as `json.MarshalIndent(v, "", "  ")` writes it.
pub(crate) fn pretty<T: Serialize + ?Sized>(v: &T) -> Vec<u8> {
    indented(v, b"  ")
}

/// `v` as `json.Marshal` writes it.
pub(crate) fn compact<T: Serialize + ?Sized>(v: &T) -> Vec<u8> {
    encode(v, CompactFormatter)
}

fn encode<T: Serialize + ?Sized, F: Formatter>(v: &T, f: F) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    let mut ser = serde_json::Serializer::with_formatter(&mut out, Go(f));
    // Cannot fail: it writes to memory, and nothing here serializes with
    // errors of its own.
    let _ = v.serialize(&mut ser);
    out
}

/// A formatter that writes what `F` lays out as Go would.
struct Go<F>(F);

impl<F: Formatter> Formatter for Go<F> {
    fn write_f32<W: ?Sized + io::Write>(&mut self, w: &mut W, v: f32) -> io::Result<()> {
        self.write_f64(w, f64::from(v))
    }

    fn write_f64<W: ?Sized + io::Write>(&mut self, w: &mut W, v: f64) -> io::Result<()> {
        w.write_all(float(v).as_bytes())
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        s: &str,
    ) -> io::Result<()> {
        let b = s.as_bytes();
        let mut start = 0;
        for (i, &c) in b.iter().enumerate() {
            let escape: &[u8] = match c {
                b'<' => b"\\u003c",
                b'>' => b"\\u003e",
                b'&' => b"\\u0026",
                // U+2028 and U+2029, whose encodings start so.
                0xA8 if i >= 2 && b[i - 2..i] == [0xE2, 0x80] => b"\\u2028",
                0xA9 if i >= 2 && b[i - 2..i] == [0xE2, 0x80] => b"\\u2029",
                _ => continue,
            };
            let lead = if c >= 0x80 { 2 } else { 0 };
            w.write_all(&b[start..i - lead])?;
            w.write_all(escape)?;
            start = i + 1;
        }
        w.write_all(&b[start..])
    }

    fn begin_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.begin_array(w)
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.end_array(w)
    }

    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_array_value(w, first)
    }

    fn end_array_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.end_array_value(w)
    }

    fn begin_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.begin_object(w)
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.end_object(w)
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_object_key(w, first)
    }

    fn end_object_key<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.end_object_key(w)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.begin_object_value(w)
    }

    fn end_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.end_object_value(w)
    }
}

/// `v` as Go writes a `float64`: the shortest digits that read back as
/// it, in exponent form below 1e-6 and from 1e21.
fn float(v: f64) -> String {
    if !v.is_finite() {
        // Go refuses these; none is ever written.
        return "0".into();
    }
    let size = v.abs();
    if size != 0.0 && !(1e-6..1e21).contains(&size) {
        let text = format!("{v:e}");
        return match text.split_once('e') {
            Some((digits, exp)) if !exp.starts_with('-') => format!("{digits}e+{exp}"),
            _ => text,
        };
    }
    format!("{v}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped_as_go_escapes_them() {
        let s = "a\u{8}b\u{c}c\u{2028}d\u{2029}<&>\u{1}\u{e9}\t\"\\\u{7f}";
        let want = "\"a\\bb\\fc\\u2028d\\u2029\\u003c\\u0026\\u003e\\u0001".to_owned()
            + "\u{e9}"
            + r#"\t\"\\"#
            + "\u{7f}\"";
        assert_eq!(String::from_utf8(compact(s)).unwrap(), want);
        assert_eq!(compact("foo.>"), b"\"foo.\\u003e\"");
        assert_eq!(compact("\u{2027}x"), "\"\u{2027}x\"".as_bytes());
    }

    #[test]
    fn floats_are_written_as_go_writes_them() {
        for (v, want) in [
            (2.0, "2"),
            (1.5, "1.5"),
            (0.0, "0"),
            (-0.0, "-0"),
            (4.0 / 9.0, "0.4444444444444444"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1.5e-7, "1.5e-7"),
            (1e-10, "1e-10"),
            (0.000_001, "0.000001"),
            (f64::NAN, "0"),
        ] {
            assert_eq!(float(v), want, "{v}");
        }
        assert_eq!(compact(&2.5f32), b"2.5");
    }

    #[test]
    fn layout_is_that_of_marshal_indent() {
        #[derive(Serialize)]
        struct S {
            a: Vec<u8>,
            b: std::collections::BTreeMap<&'static str, u8>,
            c: Vec<u8>,
        }
        let s = S {
            a: vec![],
            b: [("y", 2), ("x", 1)].into(),
            c: vec![1],
        };
        assert_eq!(
            String::from_utf8(pretty(&s)).unwrap(),
            "{\n  \"a\": [],\n  \"b\": {\n    \"x\": 1,\n    \"y\": 2\n  },\n  \"c\": [\n    1\n  ]\n}"
        );
        assert_eq!(indented(&serde_json::json!({}), b"   "), b"{}");
        assert_eq!(compact(&s), br#"{"a":[],"b":{"x":1,"y":2},"c":[1]}"#);
    }
}
