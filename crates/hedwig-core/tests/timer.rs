//! The deadline thread, on a clock the suite moves: it says a deadline has
//! passed when it has and not before, once, and a deadline set after the
//! clock jumped past it is said at once.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use hedwig_core::timer::Timer;
use hedwig_model::trail::Tick;

/// A timer on a clock read from `now`, which says each deadline on the
/// channel returned.
fn timer(now: &Arc<AtomicU64>) -> (Timer, mpsc::Receiver<()>) {
    let (said, heard) = mpsc::channel();
    let clock = Arc::clone(now);
    let timer = Timer::start(
        move || Tick(clock.load(Ordering::SeqCst)),
        move || {
            let _ = said.send(());
        },
    );
    (timer, heard)
}

#[test]
fn a_deadline_is_said_when_it_passes_and_once() {
    let now = Arc::new(AtomicU64::new(1_000));
    let (timer, heard) = timer(&now);
    timer.set(Some(Tick(1_200)));
    assert_eq!(
        heard.recv_timeout(Duration::from_millis(100)),
        Err(RecvTimeoutError::Timeout),
        "not before the clock reaches it"
    );
    now.store(1_200, Ordering::SeqCst);
    let started = Instant::now();
    heard.recv_timeout(Duration::from_secs(5)).expect("said");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        heard.recv_timeout(Duration::from_millis(300)),
        Err(RecvTimeoutError::Timeout),
        "once"
    );
}

#[test]
fn a_deadline_the_clock_jumped_past_is_said_as_soon_as_it_is_set() {
    let now = Arc::new(AtomicU64::new(0));
    let (timer, heard) = timer(&now);
    timer.set(Some(Tick(3_600_000)));
    // The wait is for an hour of the thread's own time; the clock jumps an
    // hour, and setting the deadline again - what every step does - says it.
    now.store(3_600_000 + 5, Ordering::SeqCst);
    timer.set(Some(Tick(3_600_000)));
    heard
        .recv_timeout(Duration::from_secs(5))
        .expect("said at once");
}

#[test]
fn a_later_deadline_replaces_an_earlier_one_and_none_ends_waiting() {
    let now = Arc::new(AtomicU64::new(0));
    let (timer, heard) = timer(&now);
    timer.set(Some(Tick(50)));
    timer.set(None);
    // Both are taken while the clock is short of the first.
    std::thread::sleep(Duration::from_millis(200));
    now.store(100, Ordering::SeqCst);
    assert_eq!(
        heard.recv_timeout(Duration::from_millis(300)),
        Err(RecvTimeoutError::Timeout)
    );
    timer.set(Some(Tick(150)));
    now.store(150, Ordering::SeqCst);
    heard.recv_timeout(Duration::from_secs(5)).expect("said");
}

/// On the real clock, a deadline a quarter of a second away is said after
/// it, and within a bound.
#[test]
fn on_the_trails_clock_a_deadline_is_kept() {
    let started = hedwig_win::clock::elapsed();
    let ticks = move || {
        let since = hedwig_win::clock::elapsed().saturating_sub(started);
        Tick(u64::try_from(since.as_millis()).unwrap())
    };
    let (said, heard) = mpsc::channel();
    let timer = Timer::start(ticks, move || {
        let _ = said.send(());
    });
    let before = Instant::now();
    timer.set(Some(Tick(250)));
    heard.recv_timeout(Duration::from_secs(5)).expect("said");
    let waited = before.elapsed();
    assert!(waited >= Duration::from_millis(240), "{waited:?}");
    assert!(waited < Duration::from_secs(3), "{waited:?}");
}

/// A sleep Windows did not announce: the clock jumps with nothing set again,
/// and the deadline inside the jump is still said, within the timer's bound.
#[test]
fn a_deadline_passed_in_an_unannounced_sleep_is_said_within_the_bound() {
    let now = Arc::new(AtomicU64::new(0));
    let (timer, heard) = timer(&now);
    timer.set(Some(Tick(3_600_000)));
    std::thread::sleep(Duration::from_millis(100));
    now.store(3_600_000 + 5, Ordering::SeqCst);
    let jumped = Instant::now();
    heard
        .recv_timeout(hedwig_core::PATIENCE + Duration::from_secs(3))
        .expect("said without being set again");
    assert!(jumped.elapsed() <= hedwig_core::PATIENCE + Duration::from_secs(1));
}
