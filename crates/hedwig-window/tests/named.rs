//! The executable as Windows names it and shows it: its version
//! information names Hedwig, and its icon, at every size Windows draws it,
//! is the emblem as the view draws it.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::path::Path;

use hedwig_view::emblem::{Emblem, Ink};
use hedwig_view::resource::SIDES;
use hedwig_view::style::{Mode, Rgb};
use windows_sys::Win32::UI::WindowsAndMessaging::DestroyIcon;

#[path = "../../hedwig-shell/tests/support/drawn.rs"]
mod drawn;
#[path = "../../hedwig-interface/tests/support/named.rs"]
mod named;

/// Task Manager, Settings' start-up list and Explorer name the executable
/// by its version information; each string is Hedwig's.
#[test]
fn windows_names_the_executable_hedwig() {
    let file = Path::new(env!("CARGO_BIN_EXE_hedwig-window"));
    for (key, value) in [
        ("FileDescription", "Hedwig"),
        ("ProductName", "Hedwig"),
        ("CompanyName", "Shuwari Africa"),
        ("OriginalFilename", "hedwig-window.exe"),
        (
            "LegalCopyright",
            "Copyright (c) 2026 the hedwig contributors",
        ),
        ("FileVersion", env!("CARGO_PKG_VERSION")),
        (
            "ProductVersion",
            concat!(env!("CARGO_PKG_VERSION"), " (", env!("HEDWIG_COMMIT"), ")"),
        ),
    ] {
        assert_eq!(named::version(file, key).as_deref(), Some(value), "{key}");
    }
}

/// Windows loads the executable's icon at every size an executable is
/// drawn at and draws it as the view drew the emblem: the PNG of each image
/// read by Windows' own decoder.
#[test]
fn windows_shows_the_emblem_as_the_executables_icon() {
    let file = Path::new(env!("CARGO_BIN_EXE_hedwig-window"));
    let ground = Rgb::new(0x20, 0x20, 0x20);
    for side in SIDES {
        let edge = i32::try_from(side).unwrap();
        let icon = named::icon(file, edge).expect("Windows loads the icon");
        let shown = drawn::drawn(icon, side, ground);
        // SAFETY: the icon is this test's own copy.
        unsafe { DestroyIcon(icon) };
        let want = drawn::meant(&Emblem::PLAIN.draw(side, Ink::Taskbar(Mode::Dark)), ground);
        assert_eq!(drawn::agree(&shown, &want), Ok(()), "{side}");
    }
}
