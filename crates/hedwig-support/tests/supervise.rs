//! A supervisor over cores that break down on cue: one that panics, one that
//! faults, one that stops answering, one that never becomes ready, one that
//! says something else, and a program that is not there.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_client::{Standing, look};
use hedwig_core::record::Claim;
use hedwig_core::store::Places;
use hedwig_core::supervise::{Found, Pace, Ran, Supervisor, Watch};
use hedwig_model::process::{CoreState, Exit, Running};
use hedwig_model::trail::Breakdown;
use hedwig_model::wire::read;
use hedwig_support::Folder;

/// Quick enough for a suite, and far enough apart that a loaded machine does
/// not take a busy core for a stuck one.
const WATCH: Watch = Watch {
    every: Duration::from_millis(50),
    within: Duration::from_millis(1500),
};

const PACE: Pace = Pace {
    settled: Duration::from_secs(60),
    first: Duration::from_millis(40),
    longest: Duration::from_millis(160),
};

fn child() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_child"))
}

fn supervisor(program: PathBuf, folder: &Path) -> Supervisor {
    Supervisor {
        program,
        arguments: vec![OsString::from("script"), folder.as_os_str().to_owned()],
        watch: WATCH,
        pace: PACE,
        clock: hedwig_win::clock::elapsed,
    }
}

/// What each run was told of the run before it.
fn afters(folder: &Path) -> Vec<Option<Breakdown>> {
    fs::read_to_string(folder.join("afters"))
        .unwrap_or_default()
        .lines()
        .map(|written| read::<Option<Breakdown>>(written).unwrap())
        .collect()
}

/// Runs a supervisor over the plan until it ends, and gives what it
/// announced, what each run was told, and how it ended.
fn run(folder: &Folder, plan: &str) -> (Vec<Running>, Vec<Option<Breakdown>>, Exit) {
    fs::write(folder.path().join("plan"), plan).unwrap();
    let places = Places::at(folder.path().to_path_buf()).unwrap();
    let claim = Claim::take(&places).unwrap();
    let mut announced = Vec::new();
    let exit = supervisor(child(), folder.path()).run(claim, Some(&mut announced));
    let announced = String::from_utf8(announced)
        .unwrap()
        .lines()
        .map(|written| read::<Running>(written).unwrap())
        .collect();
    assert!(
        Claim::take(&places).is_ok(),
        "the record is nobody's once the supervisor has ended"
    );
    (announced, afters(folder.path()), exit)
}

/// A core that panics after it was serving is started again, and the next
/// one is told the last ended with a panic's status. The starter heard only
/// the first thing there was to say: that a core was serving.
#[test]
fn a_core_that_panics_is_started_again_and_the_next_is_told() {
    let folder = Folder::new("panic");
    let (announced, afters, exit) = run(&folder, "panic\nstop\n");
    assert_eq!(exit, Exit::Stopped);
    assert_eq!(
        afters,
        [None, Some(Breakdown::Exited { status: 101 })],
        "a panic ends a Rust process with 101"
    );
    assert_eq!(announced.len(), 1);
    assert!(matches!(
        announced.first().unwrap().core,
        CoreState::Serving { .. }
    ));
}

/// An access violation ends the process at once with its own status, and no
/// dialog waits for someone to dismiss it.
#[test]
fn a_core_that_faults_is_ended_by_the_fault_and_started_again() {
    let folder = Folder::new("fault");
    let began = Instant::now();
    let (_, afters, exit) = run(&folder, "fault\nstop\n");
    assert_eq!(exit, Exit::Stopped);
    assert_eq!(
        afters,
        [
            None,
            Some(Breakdown::Exited {
                status: 0xc000_0005
            })
        ]
    );
    assert!(began.elapsed() < Duration::from_secs(30));
}

/// A core that stops answering is ended, with everything it started that
/// did not ask to leave its job, and the next one is told the last one hung.
/// What asked to leave - as the person's `GnuPG` agent is started - outlives
/// it.
#[test]
fn a_core_that_stops_answering_is_ended_with_everything_it_started() {
    let folder = Folder::new("hang");
    let began = Instant::now();
    let (announced, afters, exit) = run(&folder, "hang\nstop\n");
    assert_eq!(exit, Exit::Stopped);
    assert_eq!(afters, [None, Some(Breakdown::Hung)]);
    assert!(
        began.elapsed() >= WATCH.within,
        "it was given its time to answer"
    );
    assert_eq!(announced.len(), 1, "it was serving before it hung");

    let grandchild = fs::read_to_string(folder.path().join("grandchild")).unwrap();
    let (process, created) = grandchild.split_once(' ').unwrap();
    let (process, created) = (process.parse().unwrap(), created.parse().unwrap());
    assert!(
        hedwig_support::ended_within(process, created, Duration::from_secs(10)),
        "what the core started ended with it"
    );
    let left = fs::read_to_string(folder.path().join("left")).unwrap();
    let (process, created) = left.split_once(' ').unwrap();
    let (process, created): (u32, u64) = (process.parse().unwrap(), created.parse().unwrap());
    assert!(
        !hedwig_support::ended_within(process, created, Duration::from_secs(1)),
        "what asked to leave the job outlived it"
    );
    hedwig_win::process::end(process, created, 0).unwrap();
}

/// How far ahead of the real clock the supervisor in
/// `a_core_is_not_ended_for_time_the_workstation_slept` is told it is.
static SLEPT: AtomicU64 = AtomicU64::new(0);

fn clock_that_slept() -> Duration {
    hedwig_win::clock::elapsed() + Duration::from_secs(SLEPT.load(Ordering::SeqCst))
}

/// The workstation sleeps between the supervisor's question and the core's
/// answer: an hour passes on the clock, and neither process ran for it. The
/// core is not ended for that hour. Were the wait measured on the clock
/// alone, the core would be ended as hung and a second one started.
#[test]
fn a_core_is_not_ended_for_time_the_workstation_slept() {
    let folder = Folder::new("slept");
    fs::write(
        folder.path().join("plan"),
        "slow
stop
",
    )
    .unwrap();
    let places = Places::at(folder.path().to_path_buf()).unwrap();
    let claim = Claim::take(&places).unwrap();
    let supervisor = Supervisor {
        clock: clock_that_slept,
        ..supervisor(child(), folder.path())
    };
    let asked = folder.path().join("asked");
    let sleeper = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !asked.exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        SLEPT.store(3600, Ordering::SeqCst);
    });
    let exit = supervisor.run(claim, None::<Vec<u8>>);
    sleeper.join().unwrap();
    assert_eq!(exit, Exit::Stopped);
    assert_eq!(afters(folder.path()), [None], "one core, never ended");

    // The measure itself: an hour between two readings counts as one step,
    // and time read in steps counts in full.
    let mut ran = Ran::new(clock_that_slept, WATCH.step());
    assert_eq!(WATCH.step(), Duration::from_millis(300));
    let before = ran.now();
    SLEPT.store(7200, Ordering::SeqCst);
    let after = ran.now();
    let counted = after.saturating_sub(before);
    assert!(counted <= WATCH.step(), "{counted:?}");
    thread::sleep(Duration::from_millis(50));
    let later = ran.now().saturating_sub(after);
    assert!(later >= Duration::from_millis(40) && later <= WATCH.step());
}

/// A core that never becomes ready is watched from the start, not from when
/// it says it is ready.
#[test]
fn a_core_that_never_becomes_ready_is_ended_too() {
    let folder = Folder::new("mute");
    let (announced, afters, exit) = run(&folder, "mute\nstop\n");
    assert_eq!(exit, Exit::Stopped);
    assert_eq!(afters, [None, Some(Breakdown::Hung)]);
    // The first thing there was to say was that the first core broke down.
    assert!(matches!(
        &announced.first().unwrap().core,
        CoreState::Restarting {
            cause: Breakdown::Hung,
            ..
        }
    ));
}

/// A program that answers with something that is not a report is not a core
/// this supervisor can run: it is ended, and started again like any other.
#[test]
fn a_core_that_says_something_else_is_ended() {
    let folder = Folder::new("garble");
    let (_, afters, exit) = run(&folder, "garble\nstop\n");
    assert_eq!(exit, Exit::Stopped);
    assert_eq!(
        afters,
        [
            None,
            Some(Breakdown::Exited {
                status: hedwig_win::process::ENDED
            })
        ]
    );
}

/// A core that ends by itself with one of Hedwig's own statuses is a
/// breakdown like any other unless the status is the person's stop, and the
/// record says what it wrote last so a client can say why nothing answers.
#[test]
fn a_core_that_ends_with_a_status_leaves_its_last_words_in_the_record() {
    let folder = Folder::new("exit");
    let (announced, afters, exit) = run(&folder, "exit:4\nexit:4\nstop\n");
    assert_eq!(exit, Exit::Stopped);
    let storage = Breakdown::Exited {
        status: u32::from(Exit::Storage.status()),
    };
    assert_eq!(afters, [None, Some(storage), Some(storage)]);
    assert_eq!(
        announced.first().unwrap().core,
        CoreState::Restarting {
            cause: storage,
            said: "the stand-in core ends with 4".to_owned()
        }
    );
}

/// A program that cannot be started is tried again, and runs once it can be.
/// Meanwhile the record says so, in the system's own words.
#[test]
fn a_program_that_is_not_there_is_tried_again_until_it_is() {
    let folder = Folder::new("unstarted");
    fs::write(folder.path().join("plan"), "stop\n").unwrap();
    let places = Places::at(folder.path().to_path_buf()).unwrap();
    let claim = Claim::take(&places).unwrap();
    let program = folder.path().join("not-yet.exe");
    let supervisor = supervisor(program.clone(), folder.path());
    let running = thread::spawn(move || supervisor.run(claim, None::<Vec<u8>>));

    let deadline = Instant::now() + Duration::from_secs(30);
    let said = loop {
        if let Ok(Standing::Known(running)) = look(folder.path())
            && let CoreState::Restarting { cause, said } = running.core
        {
            assert_eq!(cause, Breakdown::Unstarted);
            break said;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    };
    assert!(!said.is_empty(), "the reason is the system's own");
    fs::copy(child(), &program).unwrap();
    assert_eq!(running.join().unwrap(), Exit::Stopped);
    assert_eq!(afters(folder.path()), [Some(Breakdown::Unstarted)]);
}

/// The next core starts at once after one that ran long enough to have been
/// sound, and after ones that failed young the wait doubles to a limit.
#[test]
fn the_wait_grows_while_cores_fail_young_and_is_nothing_after_a_sound_one() {
    let pace = Pace::default();
    assert_eq!(pace.settled, Duration::from_secs(60));
    let seconds = Duration::from_secs;
    let mut young = 0;
    let mut waits = Vec::new();
    for _ in 0..9 {
        let (wait, failed) = pace.wait(seconds(3), young);
        waits.push(wait.as_secs());
        young = failed;
    }
    assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
    assert_eq!(pace.wait(seconds(59), 3), (seconds(8), 4));
    assert_eq!(pace.wait(seconds(60), 9), (Duration::ZERO, 0));
    assert_eq!(pace.wait(seconds(3), u32::MAX).0, seconds(60));
    assert_eq!(Watch::default().within, hedwig_core::PATIENCE);
    assert_eq!(hedwig_core::PATIENCE, seconds(5));
}

/// A supervisor that finds another running leaves it, unless it is itself in
/// a desktop session and the other's core is in session 0.
#[test]
fn a_desktop_logon_replaces_only_a_core_that_has_no_desktop() {
    assert_eq!(Found::decide(2, 0), Found::Replace);
    assert_eq!(Found::decide(1, 0), Found::Replace);
    for (own, theirs) in [(0, 0), (0, 2), (2, 2), (3, 2), (2, 1)] {
        assert_eq!(
            Found::decide(own, theirs),
            Found::Leave,
            "{own} finds {theirs}"
        );
    }
}
