//! An answer to a prompt can be the person's passphrase. It crosses the core
//! as bytes in a frame buffer, as a string the parser builds, and as the
//! secret inside the request - and none of those may go back to the
//! allocator still holding any of it.
//!
//! The allocator here looks inside every block as it is given up. The type
//! system cannot express "this memory was erased", so this is asserted at
//! run time.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use hedwig_core::dispatch::{Core, Input, Link, Now};
use hedwig_model::config::{Catalogue, Configuration};
use hedwig_model::frame::{Frames, Line};
use hedwig_model::protocol::{PROTOCOL, Request, ToCore};
use hedwig_model::remote::Remotes;
use hedwig_model::trail::{ClientKind, Integrity, Origin, Tick, Timestamp};
use hedwig_model::wire::read;

/// The first bytes of the passphrase the frames below carry. Anything that
/// held part of the passphrase held at least these.
const MARK: &[u8] = b"correct horse";

static WATCHING: AtomicBool = AtomicBool::new(false);
static GIVEN_UP_HOLDING_IT: AtomicUsize = AtomicUsize::new(0);
/// The size of the last block caught, which says what it was.
static SIZE_OF_THE_LAST: AtomicUsize = AtomicUsize::new(0);

struct Watching;

fn look(block: *mut u8, size: usize) {
    if !WATCHING.load(Ordering::Relaxed) || size < MARK.len() {
        return;
    }
    // SAFETY: the block is live and `size` bytes long: it is inspected before
    // the allocator is told to take it back.
    let bytes = unsafe { std::slice::from_raw_parts(block, size) };
    if bytes.windows(MARK.len()).any(|window| window == MARK) {
        GIVEN_UP_HOLDING_IT.fetch_add(1, Ordering::Relaxed);
        SIZE_OF_THE_LAST.store(size, Ordering::Relaxed);
    }
}

// SAFETY: every call is passed to the system allocator unchanged; blocks are
// only read, and only while they are still allocated.
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        look(block, layout.size());
        // SAFETY: as above.
        unsafe { System.dealloc(block, layout) }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // Growing a block may move it and leave the old bytes behind.
        look(block, layout.size());
        // SAFETY: as above.
        unsafe { System.realloc(block, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

const NOW: Now = Now {
    at: Timestamp(1_790_000_000_000),
    tick: Tick(0),
};

/// An answer as a terminal sends it: short, with characters the written form
/// escapes, so the parser builds the string in pieces.
const SHORT: &str = r#"{"id":2,"request":{"answer":{"prompt":7,"answer":{"text":"correct horse \"battery\" é staple"}}}}"#;

/// The same answer made longer than the frame buffer starts, so the buffer
/// has to grow while it holds the passphrase.
fn long() -> Vec<u8> {
    // Sized once: a vector that grew would leave its earlier copies in memory
    // the allocator hands out again, and the watch would find them in
    // whatever block that was.
    let mut frame = Vec::with_capacity(16 * 1024);
    frame.extend_from_slice(br#"{"id":3,"request":{"answer":{"prompt":7,"answer":{"text":""#);
    for _ in 0..600 {
        frame.extend_from_slice(b"correct horse ");
    }
    frame.extend_from_slice(br#""}}}}"#);
    frame
}

/// Carries one frame through the core as a client's bytes are carried: into
/// the frame buffer, parsed, handed to the deciding function, and dropped.
fn carry(core: &mut Core, frames: &mut Frames, frame: &[u8]) {
    let link = Link(1);
    let mut rest = frame;
    while !rest.is_empty() {
        let room = frames.room().unwrap();
        let count = room.len().min(rest.len());
        let (now, later) = rest.split_at(count);
        room.get_mut(..count).unwrap().copy_from_slice(now);
        frames.filled(count);
        rest = later;
    }
    if let Some(end) = frames.room().unwrap().first_mut() {
        *end = b'\n';
    }
    frames.filled(1);
    let Some(Line::Text(text)) = frames.line() else {
        panic!("a frame");
    };
    let frame: ToCore = read(text).unwrap();
    frames.erase();
    assert!(matches!(frame.request, Request::Answer { .. }));
    // No prompt is waiting, so the gate refuses it; the secret has been
    // through everything an accepted answer goes through before that.
    let step = core.step(Input::Asked { link, frame }, NOW);
    assert_eq!(step.effects.len(), 1);
}

#[test]
fn nothing_that_held_an_answer_is_given_up_still_holding_it() {
    let mut core = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        Vec::new(),
        "0.2.0".to_owned(),
    );
    let origin = Origin {
        process: 1,
        logon: 1,
        session: 0,
        integrity: Integrity::High,
    };
    core.begin(origin, None, Vec::new(), NOW);
    let link = Link(1);
    core.step(
        Input::Arrived {
            link,
            peer: Some(origin.into()),
        },
        NOW,
    );
    let hello = ToCore {
        id: 1,
        request: Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Terminal,
            attends: Remotes::Every,
        },
    };
    core.step(Input::Asked { link, frame: hello }, NOW);
    // The test's own copy of the long frame outlives the watch, so it is not
    // what the watch would catch.
    let long = long();

    WATCHING.store(true, Ordering::Relaxed);
    {
        let mut frames = Frames::default();
        carry(&mut core, &mut frames, SHORT.as_bytes());
        carry(&mut core, &mut frames, &long);
    }
    WATCHING.store(false, Ordering::Relaxed);
    assert_eq!(
        GIVEN_UP_HOLDING_IT.load(Ordering::Relaxed),
        0,
        "a block of {} bytes",
        SIZE_OF_THE_LAST.load(Ordering::Relaxed)
    );

    // The instrument itself: a plain copy of the same frame, dropped, is
    // caught.
    WATCHING.store(true, Ordering::Relaxed);
    drop(SHORT.to_owned());
    WATCHING.store(false, Ordering::Relaxed);
    assert_eq!(GIVEN_UP_HOLDING_IT.load(Ordering::Relaxed), 1);
    drop(long);
}
