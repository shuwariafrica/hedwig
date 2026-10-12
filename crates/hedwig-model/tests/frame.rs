//! Bytes cut into frames: however the bytes arrive, the same lines come out,
//! a line too long to be a frame is refused, and a line that has been read
//! leaves nothing of itself in the buffer.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::frame::{Frames, Line, Overlong};
use hedwig_model::wire::FRAME;

mod support;
use support::Seeded;

/// Feeds `bytes` in the pieces `sizes` gives and returns every line found.
fn cut(bytes: &[u8], mut sizes: impl FnMut() -> usize) -> Vec<Option<String>> {
    let mut frames = Frames::default();
    let mut lines = Vec::new();
    let mut rest = bytes;
    loop {
        while let Some(found) = frames.line() {
            lines.push(match found {
                Line::Text(text) => Some(text.to_owned()),
                Line::NotText => None,
            });
            frames.erase();
        }
        if rest.is_empty() {
            return lines;
        }
        let room = frames.room().unwrap();
        let count = sizes().clamp(1, room.len()).min(rest.len());
        let (now, later) = rest.split_at(count);
        room.get_mut(..count).unwrap().copy_from_slice(now);
        frames.filled(count);
        rest = later;
    }
}

/// The lines are the same whether the bytes arrive one at a time, all at
/// once, or in any pieces between, including a line far longer than the
/// buffer starts.
#[test]
fn the_same_lines_come_out_however_the_bytes_arrive() {
    let long = "x".repeat(20_000);
    let text = format!("{{\"id\":1}}\r\n\n{long}\nlast\nunfinished");
    let expected = vec![
        Some("{\"id\":1}\r".to_owned()),
        Some(String::new()),
        Some(long),
        Some("last".to_owned()),
    ];
    assert_eq!(cut(text.as_bytes(), || 1), expected);
    assert_eq!(cut(text.as_bytes(), || usize::MAX), expected);
    let mut seeded = Seeded(7);
    for _ in 0..200 {
        assert_eq!(cut(text.as_bytes(), || seeded.below(5000) + 1), expected);
    }
}

#[test]
fn a_line_that_is_not_text_is_told_apart_and_the_next_is_still_found() {
    let lines = cut(b"ok\n\xff\xfe\nok again\n", || 3);
    assert_eq!(
        lines,
        [Some("ok".to_owned()), None, Some("ok again".to_owned())]
    );
}

/// A frame may be as long as the written form allows and no longer: one byte
/// more with no end of line is refused, and the buffer never holds more.
#[test]
fn a_line_is_at_most_a_frame_long() {
    let feed = |length: usize| {
        let mut frames = Frames::default();
        let mut left = length;
        while left > 0 {
            let room = frames.room()?;
            let count = room.len().min(left);
            room.get_mut(..count).unwrap().fill(b'a');
            frames.filled(count);
            left -= count;
        }
        Ok::<Frames, Overlong>(frames)
    };
    let mut full = feed(FRAME).unwrap();
    assert!(full.line().is_none());
    let room = full.room().unwrap();
    assert_eq!(
        room.len(),
        1,
        "room for the end of the line and nothing else"
    );
    *room.first_mut().unwrap() = b'\n';
    full.filled(1);
    assert!(matches!(full.line(), Some(Line::Text(text)) if text.len() == FRAME));

    let mut over = feed(FRAME + 1).unwrap();
    assert!(over.line().is_none());
    assert_eq!(over.room(), Err(Overlong));
}

/// Once a line has been read and erased, the buffer holds only what came
/// after it: the bytes it occupied are the following line or zero.
#[test]
fn a_line_that_was_read_is_erased_from_the_buffer() {
    let mut frames = Frames::default();
    let bytes = b"correct horse battery\nnext\n";
    frames
        .room()
        .unwrap()
        .get_mut(..bytes.len())
        .unwrap()
        .copy_from_slice(bytes);
    frames.filled(bytes.len());
    assert_eq!(frames.line(), Some(Line::Text("correct horse battery")));
    frames.erase();
    // What is left is the second line, moved to the front, and zero after it.
    let room = frames.room().unwrap();
    let whole = room.len() + "next\n".len();
    assert!(room.iter().all(|byte| *byte == 0), "{room:?}");
    assert_eq!(frames.line(), Some(Line::Text("next")));
    frames.erase();
    let room = frames.room().unwrap();
    assert_eq!(room.len(), whole, "the whole buffer is free again");
    assert!(
        room.iter().all(|byte| *byte == 0),
        "nothing of either line is left"
    );
}
