//! What the window's executable asks of Windows through this crate: its
//! claim of one window for each person, desktop and Hedwig; the shell's
//! dialog for choosing a file; a moment as the person's Windows writes it.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::path::Path;
use std::time::{Duration, Instant};

use hedwig_model::install::Names;
use hedwig_shell::pick::{Dialog, Purpose, choose};
use hedwig_shell::window::{Claim, claim, close, key, window_of};
use hedwig_shell::{clock, desk};

/// A Hedwig's presence and window are claimed under the key its own
/// installation is named by: the program folder and the Start entry of the
/// Hedwig that keeps its files in that folder.
#[test]
fn a_folder_has_one_key_its_installation_is_named_by_whatever_its_case() {
    let folder = r"C:\Users\Someone\AppData\Local\hedwig";
    let one = key(Path::new(folder));
    assert_eq!(one.len(), 16);
    assert!(one.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(
        Names::keyed(folder).program_folder(),
        format!("Hedwig {one}")
    );
    assert_eq!(Names::keyed(folder).shortcut(), format!("Hedwig {one}.lnk"));
    assert_eq!(
        one,
        key(Path::new(r"c:\users\someone\appdata\local\HEDWIG"))
    );
    assert_ne!(
        one,
        key(Path::new(r"C:\Users\Someone\AppData\Local\hedwig-2"))
    );
}

/// A second claim while the first is held and shows no window waits for the
/// holder to end, which this process does not, and then leaves the window
/// to the holder. Once the first is let go, the claim is free again.
#[test]
fn a_held_claim_is_not_taken_and_a_released_one_is() {
    let folder = std::env::temp_dir().join(format!("Hedwig claim {}", std::process::id()));
    let first = claim(&folder).unwrap();
    assert!(matches!(first, Claim::Held(_)), "{first:?}");
    let started = Instant::now();
    let second = claim(&folder).unwrap();
    assert!(matches!(second, Claim::Starting), "{second:?}");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(1900) && waited < Duration::from_secs(10),
        "{waited:?}"
    );
    drop(first);
    assert!(matches!(claim(&folder).unwrap(), Claim::Held(_)));
}

#[test]
fn a_moment_is_written_as_this_persons_windows_writes_one() {
    let written = clock::written(0);
    assert!(
        written.contains("1970") || written.contains("70"),
        "{written}"
    );
    assert_ne!(clock::written(1_790_000_000_000), written);
}

/// The dialog comes up as a window of this process, and closing it is
/// choosing nothing.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_shells_dialog_opens_and_closing_it_chooses_nothing() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let shown = std::thread::spawn(|| {
        choose(
            &Dialog {
                purpose: Purpose::Read,
                title: "hedwig probe: choose nothing",
                name: "",
                kinds: &[("Hedwig configuration (*.json)", "*.json")],
                extension: "json",
            },
            None,
        )
    });
    let me = std::process::id();
    let until = Instant::now() + Duration::from_secs(20);
    while window_of(me).is_none() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(window_of(me).is_some(), "the dialog came up");
    assert!(close(me));
    assert_eq!(shown.join().unwrap().unwrap(), None);
}
