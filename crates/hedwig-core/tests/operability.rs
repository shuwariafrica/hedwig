//! What keeps Hedwig operable on the workstation: the `Run` values kept in
//! step with the person's choices, the diagnostics ring bounded by the core
//! itself, and the payload carried in Windows' own compression.
//!
//! The `Run` values written here are named for a folder of the suite's own,
//! as a second Hedwig's are, and are taken back before each test ends.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::ffi::OsStr;
use std::fs;

use hedwig_core::diagnostics::{BOUND, NEWER, OLDER, Ring, lines};
use hedwig_core::startup::{StartupError, keep};
use hedwig_model::install::{AtSignIn, Names, Placement, Starts};
use hedwig_model::process::Diagnostic;
use hedwig_model::setting::Autostart;
use hedwig_model::text::Words;
use hedwig_model::trail::Timestamp;
use hedwig_win::registry::{RUN, own, remove_value, set_text};

mod common;
use common::Folder;

/// Takes back the suite's own `Run` values whatever the test did.
struct Taken(Names);

impl Drop for Taken {
    fn drop(&mut self) {
        for starts in Starts::ALL {
            let _ = remove_value(RUN, &self.0.run_value(starts));
        }
    }
}

/// What one keeping found for each choice, every keeping having been
/// carried out.
fn found(kept: [(Starts, Result<AtSignIn, StartupError>); 2]) -> [(Starts, AtSignIn); 2] {
    kept.map(|(starts, kept)| (starts, kept.unwrap()))
}

#[test]
fn the_run_values_follow_the_choices_and_say_what_windows_starts() {
    let data = Folder::new("startup-data");
    let program = Folder::new("startup program");
    let names = Names::keyed(&data.path().to_string_lossy());
    let _taken = Taken(names.clone());
    for starts in Starts::ALL {
        fs::write(program.path().join(starts.program()), b"").unwrap();
    }
    let folder = program.path().to_str().unwrap();
    let both = |hedwig, icon| [(Starts::Hedwig, hedwig), (Starts::Icon, icon)];

    let kept = keep(
        &names,
        program.path(),
        Autostart::AtLogon,
        Autostart::AtLogon,
    );
    assert_eq!(found(kept), both(AtSignIn::AsChosen, AtSignIn::AsChosen));
    for starts in Starts::ALL {
        let written = own(RUN, &names.run_value(starts)).unwrap();
        assert_eq!(
            written.as_deref(),
            Some(OsStr::new(&names.run_command(folder, starts))),
            "{starts:?}"
        );
    }

    let kept = keep(&names, program.path(), Autostart::AtLogon, Autostart::Off);
    assert_eq!(found(kept), both(AtSignIn::AsChosen, AtSignIn::AsChosen));
    assert_ne!(own(RUN, &names.run_value(Starts::Hedwig)).unwrap(), None);
    assert_eq!(own(RUN, &names.run_value(Starts::Icon)).unwrap(), None);

    // A value of the same name that starts a program elsewhere is not this
    // installation's: turning the setting off leaves it, and says so.
    let elsewhere = r#""C:\Elsewhere\hedwig.exe" serve"#;
    set_text(RUN, &names.run_value(Starts::Hedwig), OsStr::new(elsewhere)).unwrap();
    let kept = keep(&names, program.path(), Autostart::Off, Autostart::Off);
    assert_eq!(
        found(kept),
        both(
            AtSignIn::Another(Some(Words::try_from(elsewhere).unwrap())),
            AtSignIn::AsChosen
        )
    );
    assert_eq!(
        own(RUN, &names.run_value(Starts::Hedwig))
            .unwrap()
            .as_deref(),
        Some(OsStr::new(elsewhere))
    );
    // And turning it on puts this installation's in its place.
    let kept = keep(&names, program.path(), Autostart::AtLogon, Autostart::Off);
    assert_eq!(found(kept), both(AtSignIn::AsChosen, AtSignIn::AsChosen));
    assert_eq!(
        own(RUN, &names.run_value(Starts::Hedwig))
            .unwrap()
            .as_deref(),
        Some(OsStr::new(&names.run_command(folder, Starts::Hedwig)))
    );

    // The icon is written only where its executable is, and its choice then
    // starts nothing.
    fs::remove_file(program.path().join(Starts::Icon.program())).unwrap();
    let kept = keep(
        &names,
        program.path(),
        Autostart::AtLogon,
        Autostart::AtLogon,
    );
    assert_eq!(found(kept), both(AtSignIn::AsChosen, AtSignIn::Absent));
    assert_eq!(own(RUN, &names.run_value(Starts::Icon)).unwrap(), None);
}

#[test]
fn a_folder_windows_cannot_start_hedwig_from_is_said_and_nothing_written() {
    let data = Folder::new("startup-refused");
    let names = Names::keyed(&data.path().to_string_lossy());
    let _taken = Taken(names.clone());
    let split = Folder::new("x.exe y");
    fs::write(split.path().join(Starts::Hedwig.program()), b"").unwrap();
    let [(_, hedwig), (_, icon)] = keep(&names, split.path(), Autostart::AtLogon, Autostart::Off);
    let refused = hedwig.unwrap_err();
    assert!(matches!(
        refused,
        StartupError::Placement(Placement::Splits { .. })
    ));
    let AtSignIn::Unkept(said) = refused.found() else {
        panic!("{refused:?}")
    };
    assert!(said.as_str().starts_with("Hedwig cannot be installed at "));
    assert_eq!(own(RUN, &names.run_value(Starts::Hedwig)).unwrap(), None);
    // The other choice is kept apart from it.
    assert_eq!(icon.unwrap(), AtSignIn::AsChosen);
}

fn diagnostic(number: usize) -> Diagnostic {
    Diagnostic {
        at: Timestamp(1_790_000_000_000 + number as u64),
        from: "channel 7".to_owned(),
        said: format!("line {number}: {}", "x".repeat(200)),
    }
}

#[test]
fn the_diagnostics_ring_holds_two_bounded_files_oldest_first() {
    let folder = Folder::new("ring");
    let mut ring = Ring::new(folder.path());
    let lines_per_file = usize::try_from(BOUND).unwrap() / 260;
    let written = lines_per_file * 3;
    for number in 0..written {
        ring.write(&diagnostic(number)).unwrap();
    }
    for name in [NEWER, OLDER] {
        let size = fs::metadata(folder.path().join(name)).unwrap().len();
        assert!(size <= BOUND, "{name}: {size}");
    }
    let kept = lines(folder.path());
    let numbers: Vec<usize> = kept
        .iter()
        .map(|line| {
            let said: Diagnostic = hedwig_model::wire::read(line).unwrap();
            said.said
                .strip_prefix("line ")
                .and_then(|rest| rest.split(':').next())
                .and_then(|number| number.parse().ok())
                .unwrap()
        })
        .collect();
    assert!(
        numbers
            .windows(2)
            .all(|pair| pair.first().map(|first| first + 1) == pair.get(1).copied()),
        "in order"
    );
    assert_eq!(numbers.last(), Some(&(written - 1)), "the newest is kept");
    assert!(numbers.len() < written, "the oldest went");
}

#[test]
fn a_payload_reads_back_through_windows_own_compression() {
    let whole: Vec<u8> = (0..300_000u32)
        .flat_map(|n| (n % 251).to_le_bytes())
        .collect();
    let packed = hedwig_win::pack::compress(&whole).unwrap();
    assert!(packed.len() < whole.len());
    assert_eq!(
        hedwig_win::pack::decompress(&packed, whole.len()).unwrap(),
        whole
    );
    assert!(hedwig_win::pack::decompress(&packed, whole.len() + 1).is_err());
    assert!(
        hedwig_win::pack::decompress(packed.get(..packed.len() / 2).unwrap(), whole.len()).is_err()
    );
}

#[test]
fn restart_manager_names_the_program_holding_a_file() {
    let folder = Folder::new("held");
    let held = folder.path().join("held.txt");
    fs::write(&held, b"held").unwrap();
    let mut child = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$f=[IO.File]::Open('{}','Open','Read','None'); Start-Sleep 30",
                held.display()
            ),
        ])
        .spawn()
        .unwrap();
    let mut named = Vec::new();
    for _ in 0..100 {
        named = hedwig_win::in_use::using(std::slice::from_ref(&held)).unwrap();
        if !named.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // It is not Hedwig's, so it is not asked to close.
    hedwig_win::in_use::close(
        std::slice::from_ref(&held),
        folder.path().join("program").as_path(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let still = hedwig_win::in_use::using(std::slice::from_ref(&held)).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        named.iter().any(|holder| holder.process == child.id()),
        "{named:?}"
    );
    assert!(
        still.iter().any(|holder| holder.process == child.id()),
        "{still:?}"
    );
}

/// Takes back the suite's own Start entry whatever the test did.
struct Unlisted(std::path::PathBuf);

impl Drop for Unlisted {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// The shell's own reader of a shortcut, Windows Script Host's, run apart
/// from Hedwig: the target, arguments and folder it starts in, a line each.
fn read_back(link: &std::path::Path) -> Vec<String> {
    let read = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "$l=(New-Object -ComObject WScript.Shell).CreateShortcut('{}'); \
                 $l.TargetPath; $l.Arguments; $l.WorkingDirectory",
                link.display()
            ),
        ])
        .output()
        .unwrap();
    assert!(read.status.success(), "{read:?}");
    String::from_utf8(read.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A path in full, as the shell reads a shortcut's target back whatever was
/// written: a runner's temporary folder can be an 8.3 short name.
fn long(path: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    let full = fs::canonicalize(path).unwrap();
    full.to_str()
        .and_then(|full| full.strip_prefix(r"\\?\"))
        .map_or_else(|| full.clone(), std::path::PathBuf::from)
}

/// The application identity the shell reads from a shortcut, through its own
/// property system, run apart from Hedwig.
fn identity_of(link: &std::path::Path) -> String {
    let (folder, file) = (link.parent().unwrap(), link.file_name().unwrap());
    let read = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "(New-Object -ComObject Shell.Application).NameSpace('{}').ParseName('{}')\
                 .ExtendedProperty('System.AppUserModel.ID')",
                folder.display(),
                file.to_string_lossy()
            ),
        ])
        .output()
        .unwrap();
    assert!(read.status.success(), "{read:?}");
    String::from_utf8(read.stdout).unwrap().trim().to_owned()
}

#[test]
fn the_start_entry_opens_the_icons_program_of_its_own_hedwig_under_its_identity() {
    let data = Folder::new("start-data");
    let program = Folder::new("start program");
    let names = Names::keyed(&data.path().to_string_lossy());
    let link = hedwig_win::folder::start_menu()
        .unwrap()
        .join(names.shortcut());
    let _unlisted = Unlisted(link.clone());
    let icon = program.path().join(Starts::Icon.program());
    fs::write(&icon, b"").unwrap();

    hedwig_win::shortcut::make(&link, &icon, &names.shortcut_arguments(), &names.entry()).unwrap();
    let [target, arguments, folder] = <[String; 3]>::try_from(read_back(&link)).unwrap();
    assert_eq!(
        [long(target), long(folder)],
        [long(&icon), long(program.path())]
    );
    assert_eq!(arguments, names.shortcut_arguments());
    assert_eq!(identity_of(&link), names.entry());
    assert!(names.entry().starts_with("ShuwariAfrica.Hedwig."));

    // Made again, as an update does, it is replaced, not doubled.
    hedwig_win::shortcut::make(&link, &icon, "", &names.entry()).unwrap();
    assert_eq!(read_back(&link).get(1).map(String::as_str), Some(""));
    assert_eq!(identity_of(&link), names.entry());

    let nowhere = program.path().join("missing").join("Hedwig.lnk");
    assert!(hedwig_win::shortcut::make(&nowhere, &icon, "", &names.entry()).is_err());
    assert!(!nowhere.exists());
}
