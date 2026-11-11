//! `hedwig-setup.exe`: installs Hedwig for the person who runs it, or
//! replaces the version installed, starts it, and says it is done only once
//! it has answered with the version placed.
//!
//! Run by the person, it puts one question - whether to install for their
//! account, and whether Hedwig and its icon then start when they sign in -
//! shows that it is installing, and opens Hedwig's window when Hedwig
//! answers, or says why it could not. `--quiet` asks and shows nothing, and
//! `--at-logon` is the yes to starting at sign-in; `--folder <dir>` installs
//! the Hedwig that keeps its files there, beside the person's own.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use hedwig_client::install::{Choices, Installed, Place, SetupError, install};
use hedwig_model::install::Starts;
use hedwig_model::setting::Autostart;
use hedwig_shell::clock;
use hedwig_shell::question::{Question, account};
use hedwig_view::card::Does;
use hedwig_view::setup;
use hedwig_win::registry::{UNINSTALL, own};

/// What this setup program carries.
static PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.bin"));

/// The status for a command line setup does not take.
const USAGE: u8 = 2;
/// The status where the person cancelled setup's question.
const CANCELLED: u8 = 20;

fn main() -> ExitCode {
    // What setup starts outlives it: it must hold nothing of whoever ran
    // setup, or a script reading setup's output waits as long as Hedwig runs.
    hedwig_win::process::seal();
    let mut quiet = false;
    let mut at_logon = false;
    let mut folder: Option<PathBuf> = None;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--quiet") => quiet = true,
            Some("--at-logon") => at_logon = true,
            Some("--folder") => match arguments.next() {
                Some(dir) => folder = Some(PathBuf::from(dir)),
                None => return ExitCode::from(USAGE),
            },
            _ => return ExitCode::from(USAGE),
        }
    }
    let place = match Place::resolve(folder.clone()) {
        Ok(place) => place,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(13);
        }
    };
    if quiet {
        return quietly(&place, folder, Choices { at_logon });
    }
    asked(&place, folder)
}

/// Installs with nothing shown: what it did, or why not, on its output and
/// in its status.
fn quietly(place: &Place, folder: Option<PathBuf>, choices: Choices) -> ExitCode {
    match placed(place, choices) {
        Ok(installed) => {
            println!(
                "Hedwig {} is installed in {} and running",
                installed.version,
                installed.program.display()
            );
            if let Some(ended) = installed.ended {
                println!(
                    "It ended the removal of Hedwig begun {}: Hedwig serves your remotes again \
                     as you consented",
                    clock::written(ended.at.0)
                );
            }
            start_icon(place, folder, true);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.status())
        }
    }
}

fn placed(place: &Place, choices: Choices) -> Result<Installed, SetupError> {
    install(PAYLOAD, place, choices)
}

/// Puts setup's question to the person, installs as they answered while
/// saying so, and opens Hedwig's window once it answers; where it could not,
/// says why until the person closes it.
fn asked(place: &Place, folder: Option<PathBuf>) -> ExitCode {
    let Ok(mut question) = Question::new("Hedwig setup") else {
        return ExitCode::from(USAGE);
    };
    let account = account().unwrap_or_else(|_| "your account".to_owned());
    // Over a version installed nothing is asked: an update chooses nothing.
    if let Some(installed) = installed(place) {
        let working = place.clone();
        let done = question.during(
            &setup::updating(&installed, env!("CARGO_PKG_VERSION")),
            move || placed(&working, Choices { at_logon: false }),
        );
        return finished(&mut question, done, place, folder);
    }
    let card = setup::asking(&account, &place.program.display().to_string());
    let chosen = question
        .ask(&card)
        .ok()
        .flatten()
        .and_then(|place| card.choices.get(place))
        .map(|choice| &choice.does);
    let Some(Does::Install(start)) = chosen else {
        return ExitCode::from(CANCELLED);
    };
    let choices = Choices {
        at_logon: *start == Autostart::AtLogon,
    };
    let working = place.clone();
    let done = question.during(&setup::installing(&account), move || {
        placed(&working, choices)
    });
    finished(&mut question, done, place, folder)
}

/// The version installed at `place`, as Windows lists it, where one is.
fn installed(place: &Place) -> Option<String> {
    let entry = format!("{UNINSTALL}\\{}", place.names.entry());
    own(&entry, "DisplayVersion")
        .ok()
        .flatten()
        .map(|version| version.to_string_lossy().into_owned())
}

/// Opens Hedwig's window once it answers, or says why it did not.
fn finished(
    question: &mut Question,
    done: std::io::Result<Result<Installed, SetupError>>,
    place: &Place,
    folder: Option<PathBuf>,
) -> ExitCode {
    match done {
        Ok(Ok(installed)) => {
            if let Some(ended) = installed.ended {
                let _ = question.ask(&setup::kept(&clock::written(ended.at.0)));
            }
            question.close();
            start_icon(place, folder, false);
            ExitCode::SUCCESS
        }
        Ok(Err(error)) => {
            let _ = question.ask(&setup::failed(&error.to_string()));
            ExitCode::from(error.status())
        }
        Err(_) => ExitCode::from(USAGE),
    }
}

/// Starts the icon, where it was placed: at sign-in's way when nothing is
/// asked, else as the person starts it, which opens the window's first run.
fn start_icon(place: &Place, folder: Option<PathBuf>, quiet: bool) {
    let icon = place.program.join(Starts::Icon.program());
    if !icon.is_file() {
        return;
    }
    let mut arguments: Vec<OsString> = Vec::new();
    if quiet {
        arguments.push("tray".into());
    }
    if let Some(folder) = folder {
        arguments.push("--folder".into());
        arguments.push(folder.into_os_string());
    }
    let _ = hedwig_client::detach(&icon, &arguments);
}
