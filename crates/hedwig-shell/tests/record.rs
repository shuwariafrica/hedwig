//! The record's watch, over a folder of the suite's own: what wakes it, and
//! what does not.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use hedwig_model::trail::{FORM, Form};
use hedwig_model::wire::line;
use hedwig_shell::record::{Seen, Stop, Watch};

const RECORD: &str = "running.json";
/// Long enough for any notification Windows has to arrive.
const SETTLE: Duration = Duration::from_secs(2);

fn folder(name: &str) -> PathBuf {
    let folder = std::env::temp_dir().join(format!("Hedwig watch {name} {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder).unwrap();
    folder
}

/// Waits on `watch` on a thread of its own; what it saw arrives on the
/// receiver.
fn waiting(mut watch: Watch) -> mpsc::Receiver<Option<Seen>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(watch.wait());
    });
    receiver
}

#[test]
fn the_record_written_wakes_the_watch_and_the_trail_does_not() {
    let folder = folder("record");
    let (watch, stop) = Watch::new(&folder, RECORD).unwrap();
    let seen = waiting(watch);
    // The trail as the core writes it: the line naming its form first.
    let form = line(&Form { trail: FORM });
    std::fs::write(folder.join("trail.jsonl"), format!("{form}\n")).unwrap();
    std::fs::write(folder.join("configuration.json"), "{}").unwrap();
    // The interface's own files, which it keeps in a folder inside the core's.
    std::fs::create_dir_all(folder.join("interface")).unwrap();
    std::fs::write(folder.join("interface").join("grant"), "{}").unwrap();
    assert!(seen.recv_timeout(SETTLE).is_err(), "another file woke it");
    std::fs::write(folder.join(RECORD), r#"{"core":"starting"}"#).unwrap();
    assert_eq!(seen.recv_timeout(SETTLE).unwrap(), Some(Seen::Record));
    stop.stop();
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn a_record_rewritten_through_a_handle_held_open_wakes_it_each_time() {
    use std::io::{Seek, SeekFrom, Write};
    let folder = folder("held");
    // As the supervisor holds and rewrites it, for as long as it lives.
    let mut held = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(folder.join(RECORD))
        .unwrap();
    let (mut watch, stop) = Watch::new(&folder, RECORD).unwrap();
    for state in [
        r#""starting""#,
        r#"{"serving":{"pipe":"a","process":1}}"#,
        r#""starting""#,
    ] {
        let (sender, receiver) = mpsc::channel();
        let waited = std::thread::spawn(move || {
            let seen = watch.wait();
            let _ = sender.send(seen);
            watch
        });
        std::thread::sleep(Duration::from_millis(100));
        let text = format!(r#"{{"core":{state}}}"#);
        held.seek(SeekFrom::Start(0)).unwrap();
        held.write_all(text.as_bytes()).unwrap();
        held.set_len(text.len() as u64).unwrap();
        assert_eq!(
            receiver.recv_timeout(SETTLE).unwrap(),
            Some(Seen::Record),
            "{state}"
        );
        watch = waited.join().unwrap();
    }
    stop.stop();
    drop(held);
    let _ = std::fs::remove_dir_all(&folder);
}

fn sleeper() -> std::process::Child {
    Command::new("cmd")
        .args(["/c", "ping -n 30 127.0.0.1 >nul"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
fn the_supervisor_followed_ending_wakes_it_and_one_of_another_time_is_not_followed() {
    let folder = folder("supervisor");
    let mut child = sleeper();
    let (process, created) = hedwig_win::process::instance(&child).unwrap();

    // Of that number, created at another time: a number used again.
    let (mut watch, stop) = Watch::new(&folder, RECORD).unwrap();
    watch.follow(Some((process, created + 1)));
    let seen = waiting(watch);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        seen.recv_timeout(SETTLE).is_err(),
        "followed another process"
    );
    stop.stop();

    let mut child = sleeper();
    let (process, created) = hedwig_win::process::instance(&child).unwrap();
    let (mut watch, stop) = Watch::new(&folder, RECORD).unwrap();
    watch.follow(Some((process, created)));
    let seen = waiting(watch);
    assert!(
        seen.recv_timeout(Duration::from_millis(300)).is_err(),
        "woke while it ran"
    );
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(seen.recv_timeout(SETTLE).unwrap(), Some(Seen::Ended));
    stop.stop();
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn a_watch_stopped_from_another_thread_ends_its_wait() {
    let folder = folder("stop");
    let (watch, stop): (Watch, Stop) = Watch::new(&folder, RECORD).unwrap();
    let seen = waiting(watch);
    stop.stop();
    assert_eq!(seen.recv_timeout(SETTLE).unwrap(), None);
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn a_folder_that_does_not_exist_is_refused() {
    let folder = std::env::temp_dir().join(format!("Hedwig watch absent {}", std::process::id()));
    assert!(Watch::new(&folder, RECORD).is_err());
}
