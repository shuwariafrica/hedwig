//! The parser a control client's bytes meet first. It must be total, bounded
//! and strict, and the renderer must be its inverse.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::json::{DEPTH, Flaw, Json, JsonError, Layout, parse, render};

mod support;
use support::{Seeded, random};

fn flaw(text: &str) -> (usize, Flaw) {
    let JsonError { at, flaw } = parse(text).expect_err("must be refused");
    (at, flaw)
}

/// Known answers, the escapes among them taken from RFC 8259 section 7.
#[test]
fn values_parse_to_what_they_say() {
    assert_eq!(parse("null"), Ok(Json::Null));
    assert_eq!(parse(" true "), Ok(Json::Bool(true)));
    assert_eq!(parse("false"), Ok(Json::Bool(false)));
    assert_eq!(parse("0"), Ok(Json::Number(0)));
    assert_eq!(parse("-7"), Ok(Json::Number(-7)));
    assert_eq!(
        parse("18446744073709551615"),
        Ok(Json::Number(i128::from(u64::MAX)))
    );
    assert_eq!(
        parse("-9223372036854775808"),
        Ok(Json::Number(i128::from(i64::MIN)))
    );
    assert_eq!(
        parse(r#""\uD834\uDD1E""#),
        Ok(Json::Text("\u{1d11e}".to_owned()))
    );
    assert_eq!(
        parse(r#""a\"b\\c\/d\b\f\n\r\t\u00e9""#),
        Ok(Json::Text("a\"b\\c/d\u{8}\u{c}\n\r\t\u{e9}".to_owned()))
    );
    assert_eq!(
        parse("[1, [], {\"k\": \"v\", \"n\": null}]"),
        Ok(Json::List(vec![
            Json::Number(1),
            Json::List(vec![]),
            Json::Map(vec![
                ("k".to_owned(), Json::Text("v".to_owned())),
                ("n".to_owned(), Json::Null),
            ]),
        ]))
    );
}

/// One case per flaw, each with the byte it is reported at.
#[test]
fn every_flaw_is_reported_where_it_is() {
    assert_eq!(flaw(""), (0, Flaw::End));
    assert_eq!(flaw("[1,"), (3, Flaw::End));
    assert_eq!(flaw("\"abc"), (4, Flaw::End));
    assert_eq!(flaw("tru"), (3, Flaw::End));
    assert_eq!(flaw("{\"a\""), (4, Flaw::End));
    assert_eq!(flaw("\"a\\"), (3, Flaw::End));
    assert_eq!(flaw("x"), (0, Flaw::Unexpected));
    assert_eq!(flaw("[1 2]"), (3, Flaw::Unexpected));
    assert_eq!(flaw("{1:2}"), (1, Flaw::Unexpected));
    assert_eq!(flaw("{\"a\" 1}"), (5, Flaw::Unexpected));
    assert_eq!(flaw("{\"a\":1 \"b\":2}"), (7, Flaw::Unexpected));
    assert_eq!(flaw("trux"), (0, Flaw::Unexpected));
    assert_eq!(flaw("1.5"), (0, Flaw::Number));
    assert_eq!(flaw("1e3"), (0, Flaw::Number));
    assert_eq!(flaw("01"), (0, Flaw::Number));
    assert_eq!(flaw("-"), (0, Flaw::Number));
    assert_eq!(flaw("18446744073709551616"), (0, Flaw::Number));
    assert_eq!(flaw("-9223372036854775809"), (0, Flaw::Number));
    assert_eq!(
        flaw("1111111111111111111111111111111111111111"),
        (0, Flaw::Number)
    );
    assert_eq!(flaw(r#""\x""#), (1, Flaw::Escape));
    assert_eq!(flaw(r#""\u12g4""#), (1, Flaw::Escape));
    assert_eq!(flaw(r#""\uD834""#), (1, Flaw::Escape));
    assert_eq!(flaw(r#""\uD834A""#), (1, Flaw::Escape));
    assert_eq!(flaw(r#""\uD834\u0041""#), (1, Flaw::Escape));
    assert_eq!(flaw(r#""\uDD1E""#), (1, Flaw::Escape));
    assert_eq!(flaw("\"a\nb\""), (2, Flaw::Control));
    assert_eq!(flaw("{\"a\":1,\"a\":2}"), (7, Flaw::DuplicateKey));
    assert_eq!(flaw("1 2"), (2, Flaw::Trailing));
    assert_eq!(flaw("{}x"), (2, Flaw::Trailing));
}

#[test]
fn nesting_is_accepted_to_the_bound_and_refused_one_past_it() {
    let at_bound = format!("{}{}", "[".repeat(DEPTH), "]".repeat(DEPTH));
    assert!(parse(&at_bound).is_ok());
    let past = format!("{}{}", "[".repeat(DEPTH + 1), "]".repeat(DEPTH + 1));
    assert_eq!(flaw(&past), (DEPTH, Flaw::Depth));
    let maps = "{\"a\":".repeat(DEPTH + 1);
    assert_eq!(flaw(&maps).1, Flaw::Depth);
    // A megabyte of opening brackets costs one refusal, not a megabyte of stack.
    assert_eq!(flaw(&"[".repeat(1 << 20)), (DEPTH, Flaw::Depth));
}

/// A line is one frame, so a rendered line must hold no line feed whatever
/// the text inside it holds.
#[test]
fn a_rendered_line_never_contains_a_line_feed() {
    let value = Json::Map(vec![(
        "words".to_owned(),
        Json::Text("first\nsecond\r\n\u{0}\u{1f}\u{2028}".to_owned()),
    )]);
    let line = render(&value, Layout::Line);
    assert!(!line.contains('\n'));
    assert_eq!(
        line,
        "{\"words\":\"first\\nsecond\\r\\n\\u0000\\u001f\u{2028}\"}"
    );
    assert_eq!(parse(&line), Ok(value));
}

#[test]
fn a_page_is_indented_and_ends_with_a_line_feed() {
    let value = Json::Map(vec![
        ("version".to_owned(), Json::Number(1)),
        ("grants".to_owned(), Json::List(vec![])),
        (
            "burst".to_owned(),
            Json::Map(vec![("requests".to_owned(), Json::Number(20))]),
        ),
    ]);
    assert_eq!(
        render(&value, Layout::Page),
        "{\n  \"version\": 1,\n  \"grants\": [],\n  \"burst\": {\n    \"requests\": 20\n  }\n}\n"
    );
}

/// Both directions over generated values: render then parse gives the value
/// back, and parse then render gives the text back, in both layouts.
#[test]
fn render_and_parse_are_inverses() {
    let mut seeded = Seeded(2026);
    for _ in 0..3000 {
        let value = random(&mut seeded, 4);
        for layout in [Layout::Line, Layout::Page] {
            let text = render(&value, layout);
            let parsed = parse(&text).expect("what was rendered parses");
            assert_eq!(parsed, value, "{text}");
            assert_eq!(render(&parsed, layout), text);
        }
    }
}

/// Totality: damaged input is refused or accepted, never a panic, and
/// whatever is accepted survives its own round trip.
#[test]
fn damaged_input_never_panics_and_accepted_input_round_trips() {
    let mut seeded = Seeded(41);
    let scraps = [
        "\"", "\\", "{", "}", "[", "]", ",", ":", "-", "0", "e", "\\u", "\u{e9}", " ",
    ];
    let mut accepted = 0;
    for _ in 0..20_000 {
        let mut text = render(&random(&mut seeded, 3), Layout::Line);
        for _ in 0..=seeded.below(3) {
            let mut at = seeded.below(text.len() + 1);
            while !text.is_char_boundary(at) {
                at -= 1;
            }
            if seeded.next().is_multiple_of(2) {
                text.insert_str(at, seeded.pick(&scraps));
            } else if at < text.len() {
                text.remove(at);
            }
        }
        if let Ok(value) = parse(&text) {
            accepted += 1;
            assert_eq!(parse(&render(&value, Layout::Line)), Ok(value));
        }
    }
    assert!(accepted > 0, "some damage must leave valid text");
}

#[test]
fn a_flaw_is_worded_with_its_offset() {
    let error = parse("{\"a\":1,\"a\":2}").expect_err("a duplicate key");
    assert_eq!(error.to_string(), "a key given twice at byte 7");
}
