//! The clock, being told of sleep, the known folder, replacing a file, and telling one
//! process from another.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;

use hedwig_win::clock::elapsed;
use hedwig_win::power::{Turn, watch};
use hedwig_win::process::{EndError, Job, end, instance, own};
use hedwig_win::token::{Sid, Token};
use windows_sys::Win32::System::WindowsProgramming::{
    QueryInterruptTime, QueryUnbiasedInterruptTime,
};

/// Interrupt time, which Windows documents as counting sleep by saying its
/// unbiased form does not: a second witness for the clock the trail uses.
fn interrupt() -> Duration {
    let mut hundreds = 0u64;
    // SAFETY: a valid out pointer.
    unsafe { QueryInterruptTime(&raw mut hundreds) };
    Duration::from_nanos(hundreds.saturating_mul(100))
}

/// Unbiased interrupt time, which "does not include time the system spends
/// in sleep or hibernation": what the machine was awake for.
fn unbiased() -> Duration {
    let mut hundreds = 0u64;
    // SAFETY: a valid out pointer.
    unsafe { QueryUnbiasedInterruptTime(&raw mut hundreds) };
    Duration::from_nanos(hundreds.saturating_mul(100))
}

/// The clock never goes back, and moves with real time while the machine is
/// awake.
#[test]
fn the_clock_advances_and_never_goes_back() {
    let mut counted = elapsed();
    for _ in 0..10_000 {
        let next = elapsed();
        assert!(next >= counted);
        counted = next;
    }
    let before = elapsed();
    thread::sleep(Duration::from_millis(200));
    let moved = elapsed().saturating_sub(before);
    assert!(
        moved >= Duration::from_millis(150) && moved < Duration::from_secs(5),
        "{moved:?}"
    );
}

/// The clock the trail uses agrees with Windows' own clock that counts
/// sleep, and is not behind the one that does not. What separates those two
/// is the time this machine has been asleep since it started, which is
/// printed: on a machine that has slept it is that sleep, on one that has
/// not it is nothing.
#[test]
fn the_trails_clock_counts_the_sleep_the_unbiased_clock_leaves_out() {
    let counted = elapsed();
    let witness = interrupt();
    let woken = unbiased();
    let slack = Duration::from_millis(250);
    assert!(
        counted.abs_diff(witness) < slack,
        "the performance counter reads {counted:?} and interrupt time {witness:?}"
    );
    assert!(counted + slack >= woken, "{counted:?} against {woken:?}");
    println!(
        "since this machine started: {counted:?} by the clock that counts sleep,          {woken:?} awake, {:?} asleep",
        counted.saturating_sub(woken)
    );
}

/// The two power events Hedwig acts on are told apart from the rest, and a
/// process with no window can ask to be told of them.
#[test]
fn a_process_with_no_window_is_told_of_sleep_and_waking() {
    assert_eq!(Turn::from_event(4), Some(Turn::Sleeping));
    assert_eq!(Turn::from_event(18), Some(Turn::Woke));
    // The person's own activity after a wake, a battery warning, a setting
    // changed: none is a turn.
    for other in [7, 9, 10, 0x8013] {
        assert_eq!(Turn::from_event(other), None);
    }
    watch(|turn| println!("the workstation is {turn:?}")).unwrap();
}

/// A process with no window is told whether a network is reached as soon as
/// it asks, and the connectivity levels are told apart: none is none, one
/// Windows does not know says nothing, and every other is some network.
#[test]
fn a_process_with_no_window_is_told_whether_a_network_is_reached() {
    use hedwig_win::network::{Reach, watch as network};
    use windows_sys::Win32::Networking::WinSock::{
        NetworkConnectivityLevelHintConstrainedInternetAccess, NetworkConnectivityLevelHintHidden,
        NetworkConnectivityLevelHintInternetAccess, NetworkConnectivityLevelHintLocalAccess,
        NetworkConnectivityLevelHintNone, NetworkConnectivityLevelHintUnknown,
    };
    let (said, heard) = std::sync::mpsc::channel();
    network(move |reach| {
        let _ = said.send(reach);
    })
    .unwrap();
    let first = heard
        .recv_timeout(Duration::from_secs(10))
        .expect("told at once");
    assert!(matches!(first, Reach::Some | Reach::None));
    assert_eq!(Reach::from_level(NetworkConnectivityLevelHintUnknown), None);
    assert_eq!(
        Reach::from_level(NetworkConnectivityLevelHintNone),
        Some(Reach::None)
    );
    for level in [
        NetworkConnectivityLevelHintLocalAccess,
        NetworkConnectivityLevelHintInternetAccess,
        NetworkConnectivityLevelHintConstrainedInternetAccess,
        NetworkConnectivityLevelHintHidden,
    ] {
        assert_eq!(Reach::from_level(level), Some(Reach::Some));
    }
}

/// Nothing Hedwig runs ever asks Windows to keep the workstation awake: it
/// sleeps as its own settings say. Every source of the workspace is read,
/// and none names a call that says the system, the display or the process
/// is required.
#[test]
fn nothing_asks_windows_to_keep_the_workstation_awake() {
    const ASKS: [&str; 4] = [
        "SetThreadExecutionState",
        "PowerSetRequest",
        "PowerCreateRequest",
        "ES_SYSTEM_REQUIRED",
    ];
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let mut folders = vec![workspace];
    let mut read = 0;
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "target" && !name.starts_with('.') {
                    folders.push(path);
                }
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = fs::read_to_string(&path).unwrap();
                // This file names the calls in order to look for them.
                if text.contains("fn nothing_asks_windows_to_keep_the_workstation_awake") {
                    continue;
                }
                for ask in ASKS {
                    assert!(!text.contains(ask), "{} names {ask}", path.display());
                }
                read += 1;
            }
        }
    }
    assert!(read > 50, "the workspace's sources were read: {read}");
}

#[test]
fn the_known_folder_is_a_folder_that_exists() {
    let local = hedwig_win::folder::local().unwrap();
    assert!(local.is_absolute() && local.is_dir(), "{}", local.display());
    println!("local application data resolves to {}", local.display());
}

#[test]
fn replacing_a_file_leaves_the_new_one_under_the_old_name() {
    let folder = std::env::temp_dir().join(format!("hedwig-design-replace-{}", std::process::id()));
    fs::create_dir_all(&folder).unwrap();
    let (old, new) = (folder.join("kept.json"), folder.join("kept.json.new"));
    fs::write(&old, "old").unwrap();
    fs::write(&new, "new").unwrap();
    hedwig_win::file::replace(&new, &old).unwrap();
    assert_eq!(fs::read_to_string(&old).unwrap(), "new");
    assert!(!new.exists());

    // With nothing there yet it is a plain move.
    fs::write(&new, "first").unwrap();
    let fresh = folder.join("fresh.json");
    hedwig_win::file::replace(&new, &fresh).unwrap();
    assert_eq!(fs::read_to_string(&fresh).unwrap(), "first");
    assert!(
        hedwig_win::file::replace(&new, &fresh).is_err(),
        "nothing to move"
    );
    fs::remove_dir_all(&folder).unwrap();
}

#[test]
fn random_bytes_differ_from_one_draw_to_the_next() {
    let (mut one, mut two) = ([0u8; 16], [0u8; 16]);
    hedwig_win::random::fill(&mut one).unwrap();
    hedwig_win::random::fill(&mut two).unwrap();
    assert_ne!(one, two);
    assert_ne!(one, [0u8; 16]);
}

#[test]
fn a_token_says_whose_it_is_and_where_it_stands() {
    let token = Token::own().unwrap();
    let user = token.user().unwrap();
    let text = user.to_text().unwrap();
    assert!(text.starts_with("S-1-5-"), "{text}");
    assert_eq!(Sid::from_text(&text).unwrap(), user);
    assert_ne!(Sid::from_text("S-1-5-32-544").unwrap(), user);
    assert!(Sid::from_text("not an identifier").is_err());
    let standing = token.standing().unwrap();
    assert!(standing.integrity >= 0x2000, "{standing:?}");
    assert_ne!(standing.logon, 0);
    println!("this process: {text} {standing:x?}");
}

/// A process is named by its number and the moment it was created. The same
/// number at another moment is another process, and is neither found alive
/// nor ended.
#[test]
fn a_process_is_told_from_another_with_the_same_number() {
    let (process, created) = own().unwrap();
    assert_eq!(process, std::process::id());
    // This process's number at another moment is another process: gone.
    assert!(matches!(end(process, created + 1, 1), Err(EndError::Gone)));

    let mut child = Command::new(std::env::var_os("ComSpec").unwrap())
        .args(["/c", "pause"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let (number, at) = instance(&child).unwrap();
    assert!(matches!(end(number, at + 1, 7), Err(EndError::Gone)));
    assert_eq!(
        child.try_wait().unwrap(),
        None,
        "the wrong moment ends nothing"
    );
    end(number, at, 7).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(7));
    assert!(matches!(end(number, at, 7), Err(EndError::Gone)));
}

#[test]
fn a_job_ends_everything_in_it() {
    let job = Job::new().unwrap();
    let mut child = Command::new(std::env::var_os("ComSpec").unwrap())
        .args(["/c", "pause"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(!job.holds(&child).unwrap());
    job.hold(&child).unwrap();
    assert!(job.holds(&child).unwrap());
    job.end().unwrap();
    let status = child.wait().unwrap().code().unwrap();
    assert_eq!(status.cast_unsigned(), hedwig_win::process::ENDED);
    println!(
        "this process is in a job of its starter's: {}",
        hedwig_win::process::in_a_job().unwrap()
    );
}
