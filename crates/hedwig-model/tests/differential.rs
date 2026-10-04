//! The parser set against `serde_json`'s, which is fuzzed continuously and
//! read by far more people than will ever read this one. `serde_json` is a
//! test dependency only.
//!
//! Two properties. Whatever this parser accepts, the reference accepts and
//! reads as the same value. Whatever the reference accepts and this parser
//! refuses is refused for one of the reasons the subset exists: a number
//! that is not a plain integer in range, a repeated key, or nesting past the
//! bound.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::json::{Flaw, Json, Layout, parse, render};
use serde_json::Value;

mod support;
use support::{Seeded, random};

fn same(ours: &Json, theirs: &Value) -> bool {
    match (ours, theirs) {
        (Json::Null, Value::Null) => true,
        (Json::Bool(ours), Value::Bool(theirs)) => ours == theirs,
        (Json::Number(ours), Value::Number(theirs)) => {
            let theirs = theirs
                .as_u64()
                .map(i128::from)
                .or_else(|| theirs.as_i64().map(i128::from));
            theirs == Some(*ours)
        }
        (Json::Text(ours), Value::String(theirs)) => ours == theirs,
        (Json::List(ours), Value::Array(theirs)) => {
            ours.len() == theirs.len() && ours.iter().zip(theirs).all(|(a, b)| same(a, b))
        }
        (Json::Map(ours), Value::Object(theirs)) => {
            ours.len() == theirs.len()
                && ours
                    .iter()
                    .all(|(key, value)| theirs.get(key).is_some_and(|other| same(value, other)))
        }
        _ => false,
    }
}

/// Whether both accept `text`, having checked that they agree about it.
fn agree(text: &str) -> bool {
    let theirs: Result<Value, _> = serde_json::from_str(text);
    let verdict = match (parse(text), theirs) {
        (Ok(ours), Ok(theirs)) if same(&ours, &theirs) => Ok(true),
        (Ok(_), Ok(_)) => Err(format!("read differently: {text}")),
        (Ok(_), Err(error)) => Err(format!(
            "accepted what the reference refuses ({error}): {text}"
        )),
        (Err(error), Ok(_))
            if !matches!(error.flaw, Flaw::Number | Flaw::DuplicateKey | Flaw::Depth) =>
        {
            Err(format!(
                "refused valid JSON as {:?} at byte {}: {text}",
                error.flaw, error.at
            ))
        }
        (Err(_), _) => Ok(false),
    };
    verdict.expect("the two parsers agree")
}

#[test]
fn what_is_rendered_the_reference_reads_as_the_same_value() {
    let mut seeded = Seeded(9);
    for _ in 0..3000 {
        let value = random(&mut seeded, 4);
        for layout in [Layout::Line, Layout::Page] {
            let text = render(&value, layout);
            let theirs: Value = serde_json::from_str(&text).expect("the reference reads it");
            assert!(same(&value, &theirs), "{text}");
        }
    }
}

#[test]
fn the_pinned_frames_are_json_to_the_reference_too() {
    let corpus = include_str!("corpus.jsonl");
    let mut frames = 0;
    for line in corpus.lines() {
        assert!(agree(line), "{line}");
        frames += 1;
    }
    assert!(frames > 200);
}

#[test]
fn damaged_input_is_never_read_differently_from_the_reference() {
    let mut seeded = Seeded(77);
    let scraps = [
        "\"", "\\", "{", "}", "[", "]", ",", ":", "-", "0", "1", ".", "e", r"\u", r"\ud834",
        "\u{e9}", " ", "\n", "null", "true", "\u{0}",
    ];
    let mut both = 0;
    let mut stricter = 0;
    for _ in 0..40_000 {
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
        let ours = parse(&text).is_ok();
        if agree(&text) {
            both += 1;
        } else if !ours && serde_json::from_str::<Value>(&text).is_ok() {
            stricter += 1;
        }
    }
    assert!(both > 1000, "many damaged texts are still valid: {both}");
    assert!(stricter > 0, "and some are valid JSON outside the subset");
}

/// The subset's three refusals, each on input the reference accepts.
#[test]
fn the_subset_is_stricter_in_exactly_three_ways() {
    for (text, flaw) in [
        ("1.5", Flaw::Number),
        ("1e3", Flaw::Number),
        ("18446744073709551616", Flaw::Number),
        ("{\"a\":1,\"a\":2}", Flaw::DuplicateKey),
    ] {
        assert!(serde_json::from_str::<Value>(text).is_ok(), "{text}");
        assert_eq!(parse(text).expect_err("outside the subset").flaw, flaw);
    }
    let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
    assert!(serde_json::from_str::<Value>(&deep).is_ok());
    assert_eq!(parse(&deep).expect_err("too deep").flaw, Flaw::Depth);
}
