//! The interface as a process, against a real core: a Hedwig started in a
//! folder of the suite's own by the command-line stand-in the workspace
//! builds, the interface started beside it, and the core asked what it
//! sees. At a desktop the icon is in the notification area for the few
//! seconds this takes, its tooltip naming the suite's folder.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hedwig_model::trail::Presence;
use hedwig_shell::{desk, host};
use hedwig_win::token::Token;

#[path = "support/restart.rs"]
mod restart;

const INTERFACE: &str = env!("CARGO_BIN_EXE_hedwig-interface");

/// The command-line stand-in built with the workspace, which starts the
/// `hedwig.exe` beside it.
fn stand_in() -> PathBuf {
    let path = Path::new(INTERFACE).with_file_name("command.exe");
    assert!(
        path.exists(),
        "{} is built with the workspace",
        path.display()
    );
    path
}

/// Asks the Hedwig of the suite's folder `word`, through the stand-in.
fn command(folder: &Path, word: &str) -> (Option<i32>, String) {
    let output = Command::new(stand_in())
        .arg(word)
        .arg("--folder")
        .arg(folder)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// Everything the suite started, ended whatever happens.
struct Started {
    folder: PathBuf,
    interface: Option<Child>,
}

impl Drop for Started {
    fn drop(&mut self) {
        if let Some(interface) = &mut self.interface {
            let _ = interface.kill();
            let _ = interface.wait();
        }
        let _ = command(&self.folder, "stop");
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

fn within(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done()
}

#[test]
#[ignore = "needs the desktop's foreground"]
fn the_interface_attends_the_core_as_what_it_is_and_outlives_it() {
    let folder = std::env::temp_dir().join(format!("hedwig probe {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let mut started = Started {
        folder: folder.clone(),
        interface: None,
    };

    if !desk::interactive() {
        // An SSH session: the interface says there is no desktop and ends.
        let status = Command::new(INTERFACE)
            .args(["tray", "--folder"])
            .arg(&folder)
            .status()
            .unwrap();
        println!("no desktop here; the interface ended with {status}");
        assert_eq!(status.code(), Some(4));
        return;
    }

    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");
    let interface = Command::new(INTERFACE)
        .args(["tray", "--folder"])
        .arg(&folder)
        .spawn()
        .unwrap();
    let process = interface.id();
    started.interface = Some(interface);

    // The core reads the interface from the pipe: what kind of client it
    // says it is, and the process and session Windows says it is.
    let own = Token::own().unwrap().standing().unwrap();
    let presence = match desk::desktop().presence() {
        Presence::Present => "present",
        Presence::CardOnly => "card-only",
        Presence::Engaged => "engaged",
        Presence::Away => "away",
    };
    let mut seen = String::new();
    let attached = within(Duration::from_secs(10), || {
        seen = command(&folder, "status").1;
        seen.contains(r#""kind":"interface""#)
            && seen.contains(&format!(r#""presence":"{presence}""#))
    });
    println!("the core's status while the interface attends:\n{seen}");
    assert!(attached, "the interface did not attach");
    assert!(
        seen.contains(&format!(r#""process":{process},"#)),
        "{process}"
    );
    assert!(seen.contains(&format!(r#""session":{}"#, own.session)));
    println!(
        "this desktop: session {}, the person is {presence}",
        own.session
    );

    // Attending with nothing painted, the interface has loaded neither
    // library a painted surface sets its text with.
    let modules = Command::new("tasklist")
        .args(["/m", "/fo", "csv", "/nh", "/fi"])
        .arg(format!("PID eq {process}"))
        .output()
        .unwrap();
    let modules = String::from_utf8_lossy(&modules.stdout).to_lowercase();
    assert!(modules.contains("hedwig-interface.exe"), "{modules}");
    for library in ["d2d1.dll", "dwrite.dll"] {
        assert!(!modules.contains(library), "{library} is loaded at rest");
    }
    let held = Command::new("tasklist")
        .args(["/fo", "csv", "/nh", "/fi"])
        .arg(format!("PID eq {process}"))
        .output()
        .unwrap();
    println!(
        "the interface attending, as Windows lists it: {}",
        String::from_utf8_lossy(&held.stdout).trim()
    );

    // The core is stopped. The interface is a client, not a part of it: it
    // stays, to say that Hedwig is not running.
    let (status, said) = command(&folder, "stop");
    assert_eq!((status, said.trim()), (Some(0), "stopped"));
    std::thread::sleep(Duration::from_millis(500));
    let interface = started.interface.as_mut().unwrap();
    assert_eq!(interface.try_wait().unwrap(), None, "still running");

    // Closing its window ends it, with the status that says the person did.
    assert!(host::end_running(&folder));
    let mut ended = None;
    within(Duration::from_secs(10), || {
        ended = interface.try_wait().unwrap();
        ended.is_some()
    });
    assert_eq!(ended.and_then(|status| status.code()), Some(0));
    started.interface = None;
}

/// The presence is one for each person, desktop and hedwig. The person's
/// second start, from the Start menu, asks the first for the window and ends;
/// the start at logon ends with nothing shown.
#[test]
#[ignore = "needs the desktop's foreground"]
fn a_second_start_asks_the_first_for_the_window_and_ends() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let folder = std::env::temp_dir().join(format!("Hedwig second {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let mut started = Started {
        folder: folder.clone(),
        interface: None,
    };
    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");
    let first = Command::new(INTERFACE)
        .args(["tray", "--folder"])
        .arg(&folder)
        .spawn()
        .unwrap();
    started.interface = Some(first);
    let title = format!("Hedwig ({})", folder.file_name().unwrap().to_string_lossy());
    // The first has made its unshown window once the core lists it.
    assert!(within(Duration::from_secs(10), || command(
        &folder, "status"
    )
    .1
    .contains(r#""kind":"interface""#)));

    let at_logon = Command::new(INTERFACE)
        .args(["tray", "--folder"])
        .arg(&folder)
        .status()
        .unwrap();
    assert_eq!(at_logon.code(), Some(0));
    let window = Path::new(INTERFACE).with_file_name("hedwig-window.exe");
    if window.exists() {
        // Nothing opened the window: its claim is free.
        assert!(matches!(
            hedwig_shell::window::claim(&folder).unwrap(),
            hedwig_shell::window::Claim::Held(_)
        ));
    }

    let person = Command::new(INTERFACE)
        .arg("--folder")
        .arg(&folder)
        .status()
        .unwrap();
    assert_eq!(person.code(), Some(0));
    let first = started.interface.as_mut().unwrap();
    assert_eq!(first.try_wait().unwrap(), None, "the first stays");
    if window.exists() {
        let opened = within(Duration::from_secs(20), || {
            let listed = Command::new("tasklist")
                .args(["/fo", "csv", "/nh", "/fi"])
                .arg(format!("WINDOWTITLE eq {title}"))
                .output()
                .unwrap();
            String::from_utf8_lossy(&listed.stdout).contains("hedwig-window.exe")
        });
        let _ = Command::new("taskkill")
            .args(["/fi"])
            .arg(format!("WINDOWTITLE eq {title}"))
            .output();
        assert!(opened, "the first presence opened no window");
    } else {
        println!("no hedwig-window.exe beside the interface; the window was not looked for");
    }
    assert!(host::end_running(&folder));
}

/// The core the record names now, by its process number.
fn serving(folder: &Path) -> Option<u32> {
    let record = std::fs::read_to_string(folder.join("running.json")).ok()?;
    let (_, after) = record.split_once(r#""serving":"#)?;
    let (_, number) = after.split_once(r#""process":"#)?;
    number
        .split(|character: char| !character.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// Nothing the person does at the icon is needed for it to find hedwig: one
/// started after the presence, from a terminal or by the start at logon, is
/// attended within moments, and so is the core its supervisor starts again
/// after the last one broke down.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_interface_attends_a_hedwig_started_after_it_and_its_core_started_again() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let folder = std::env::temp_dir().join(format!("Hedwig later {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let mut started = Started {
        folder: folder.clone(),
        interface: None,
    };
    started.interface = Some(
        Command::new(INTERFACE)
            .args(["tray", "--folder"])
            .arg(&folder)
            .spawn()
            .unwrap(),
    );
    std::thread::sleep(Duration::from_secs(2));

    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");
    let began = Instant::now();
    let attends = |folder: &Path| {
        command(folder, "status")
            .1
            .contains(r#""kind":"interface""#)
    };
    assert!(
        within(Duration::from_secs(10), || attends(&folder)),
        "a Hedwig started after the interface was not attended"
    );
    println!(
        "attended {} ms after Hedwig started",
        began.elapsed().as_millis()
    );

    // The core breaks down: its supervisor writes that it is restarting, and
    // then that the next one serves.
    let first = serving(&folder).unwrap();
    let killed = Command::new("taskkill")
        .args(["/f", "/pid"])
        .arg(first.to_string())
        .output()
        .unwrap();
    assert!(killed.status.success(), "{killed:?}");
    let began = Instant::now();
    assert!(
        within(Duration::from_secs(30), || serving(&folder)
            .is_some_and(|next| next != first)
            && attends(&folder)),
        "the core started again was not attended"
    );
    println!(
        "the core started again attended {} ms after the first was ended",
        began.elapsed().as_millis()
    );
    assert!(host::end_running(&folder));
}

#[test]
fn an_argument_it_does_not_know_is_refused_before_anything_is_shown() {
    for arguments in [vec!["--unknown"], vec!["--folder"], vec!["tray", "window"]] {
        let status = Command::new(INTERFACE).args(&arguments).status().unwrap();
        assert_eq!(status.code(), Some(2), "{arguments:?}");
    }
}

/// An installer of Windows' own that replaces the icon's program - Restart
/// Manager's shutdown, as setup's update and removal ask of what holds
/// Hedwig's files - closes the icon, which ends as the person closing it
/// does, and the core sees it go.
#[test]
#[ignore = "needs the desktop's foreground"]
fn windows_own_installers_close_the_icon() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let folder = std::env::temp_dir().join(format!("Hedwig restart {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let mut started = Started {
        folder: folder.clone(),
        interface: None,
    };
    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");
    let presence = Command::new(INTERFACE)
        .args(["tray", "--folder"])
        .arg(&folder)
        .spawn()
        .unwrap();
    let process = presence.id();
    started.interface = Some(presence);
    assert!(within(Duration::from_secs(10), || command(
        &folder, "status"
    )
    .1
    .contains(r#""kind":"interface""#)));

    let (holders, shut) = restart::shut_down(Path::new(INTERFACE));
    assert!(
        holders.contains(&(process, "Hedwig icon".to_owned())),
        "{holders:?}"
    );
    assert_eq!(shut, 0);
    let presence = started.interface.as_mut().unwrap();
    assert!(within(Duration::from_secs(10), || presence
        .try_wait()
        .unwrap()
        .is_some()));
    assert_eq!(presence.try_wait().unwrap().unwrap().code(), Some(0));
    assert!(within(Duration::from_secs(10), || !command(
        &folder, "status"
    )
    .1
    .contains(r#""kind":"interface""#)));
}
