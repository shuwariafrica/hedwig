//! Hedwig's window: where a person sets Hedwig up and reviews what of theirs
//! is reachable from where.
//!
//! It is a process of its own that exists while the window is open, started
//! by the presence when the person asks for it, and a client of the core's
//! control pipe like any other. What it shows is `hedwig_view`'s function of
//! what the core last said; WinUI 3, through `windows-reactor`, draws it.
//! There is one window for each person, desktop and hedwig: a second start
//! brings the first forward and ends.
//!
//! `hedwig-window --folder <dir>` attends the Hedwig that keeps its files
//! there in place of the person's own.

#![forbid(unsafe_code)]
#![windows_subsystem = "windows"]
#![allow(
    clippy::multiple_crate_versions,
    reason = "windows-link 0.2.1 under windows-sys 0.61.2 beside 0.100.0 under windows-reactor, \
              until windows-sys moves to windows-link 0.100"
)]

mod core;
mod draft;
mod files;
mod show;
mod window;

use std::path::PathBuf;
use std::process::ExitCode;

use hedwig_model::install::Names;
use hedwig_shell::desk;
use hedwig_shell::place::{self, Placing};
use hedwig_shell::window::{Claim, claim, identify};
use hedwig_view::place::Placement;
use windows_reactor::App;

use crate::draft::{Kept, Making};

/// The class of the window WinUI makes, which is the one placed.
const WINUI: &str = "WinUIDesktopWin32WindowClass";

/// Why the window ended, as the status it exits with; the presence's own
/// statuses where they mean the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// The person closed it, or the window already open was brought forward.
    Ended = 0,
    Usage = 2,
    /// This session has no desktop.
    NoDesktop = 4,
    /// Windows refused what the window needs: its claim, or WinUI.
    Shell = 5,
}

fn main() -> ExitCode {
    let mut named = None;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        match (argument.to_str(), &named) {
            (Some("--folder"), None) => match arguments.next() {
                Some(given) => named = Some(PathBuf::from(given)),
                None => return ExitCode::from(Exit::Usage as u8),
            },
            _ => return ExitCode::from(Exit::Usage as u8),
        }
    }
    if !desk::interactive() {
        return ExitCode::from(Exit::NoDesktop as u8);
    }
    let label = named
        .as_ref()
        .and_then(|folder| folder.file_name())
        .map(|name| name.to_string_lossy().into_owned());
    // The installation this window's Start entry is named for: the person's
    // own, or the one keyed by the folder it was started for.
    let installed = named
        .as_ref()
        .map_or_else(Names::own, |folder| Names::keyed(&folder.to_string_lossy()));
    let Some(folder) = core::folder(named) else {
        return ExitCode::from(Exit::Usage as u8);
    };
    let exit = match claim(&folder) {
        Ok(Claim::Held(_held)) => {
            let _ = identify(&installed.entry());
            let title =
                label.map_or_else(|| "Hedwig".to_owned(), |label| format!("Hedwig ({label})"));
            // The window opens where the person left it, on a monitor still
            // there, and is kept where it is when it goes.
            let kept = Some(draft::place(&folder, Making::Place));
            let at = kept
                .as_deref()
                .and_then(|kept| match draft::kept(kept, Placement::read) {
                    Kept::Draft(at) => place::fitted(at),
                    Kept::Nothing | Kept::Unreadable => None,
                });
            let placing = Placing::new(WINUI, at).ok();
            let input = window::Input {
                folder,
                title,
                placed: at.is_some() && placing.is_some(),
            };
            let ran = App::run_component::<window::Window>(input);
            if let (Some(kept), Some(at)) = (kept, placing.as_ref().and_then(Placing::kept)) {
                let _ = draft::keep(&kept, &at.written());
            }
            match ran {
                Ok(()) => Exit::Ended,
                Err(_) => Exit::Shell,
            }
        }
        Ok(Claim::Forwarded | Claim::Starting) => Exit::Ended,
        Err(_) => Exit::Shell,
    };
    ExitCode::from(exit as u8)
}
