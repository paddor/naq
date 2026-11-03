//! Subject rules against the cases `nats-server` tests.

use naq_proto::subject::{has_all_tokens, is_literal, is_valid_filter, is_valid_literal, matches};

#[test]
fn filters_need_every_token_and_a_tail_wildcard_last() {
    for ok in [
        "foo", "foo.bar", "*", ">", "foo.*", "foo.>", "*.bar.>", "a*.b", "foo.>b",
    ] {
        assert!(is_valid_filter(ok.as_bytes()), "{ok}");
    }
    for bad in [
        "",
        ".",
        "foo.",
        ".foo",
        "foo..bar",
        "foo.>.bar",
        ">.foo",
        "foo.>.>",
    ] {
        assert!(!is_valid_filter(bad.as_bytes()), "{bad}");
    }
}

#[test]
fn wildcards_are_whole_tokens() {
    assert!(is_literal(b"foo.bar"));
    assert!(is_literal(b"foo*.bar>"));
    assert!(!is_literal(b"foo.*"));
    assert!(!is_literal(b">"));
    assert!(is_valid_literal(b"foo.b*r"));
    assert!(!is_valid_literal(b"foo.*"));
    assert!(!is_valid_literal(b"foo..bar"));
    assert!(!is_valid_literal(b""));
}

#[test]
fn a_subject_with_an_empty_token_is_incomplete() {
    assert!(has_all_tokens(b"a.b"));
    for bad in ["", ".", "a.", ".a", "a..b"] {
        assert!(!has_all_tokens(bad.as_bytes()), "{bad}");
    }
}

#[test]
fn filters_match_as_in_nats_server() {
    let yes = [
        ("foo", "foo"),
        ("*", "foo"),
        (">", "foo.bar"),
        ("foo.*", "foo.bar"),
        ("foo.*.baz", "foo.bar.baz"),
        ("foo.>", "foo.bar.baz"),
        ("*.*", "foo.bar"),
        ("foo.*", "foo.*"),
    ];
    for (f, s) in yes {
        assert!(matches(f.as_bytes(), s.as_bytes()), "{f} {s}");
    }
    let no = [
        ("foo", "bar"),
        ("foo.*", "foo"),
        ("foo.*", "foo.bar.baz"),
        ("foo.>", "foo"),
        ("*", "foo.bar"),
        ("foo.bar", "foo.*"),
        ("foo.*", "foo."),
        ("*", ""),
    ];
    for (f, s) in no {
        assert!(!matches(f.as_bytes(), s.as_bytes()), "{f} {s}");
    }
}
