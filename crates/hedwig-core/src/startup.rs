//! The person's `Run` values, kept in step with what they chose: one for
//! Hedwig and one for its icon, each written while its setting is at sign-in
//! and removed while it is off. Windows' own Startup switch is never read or
//! written: it is the person's, beside these.

use std::ffi::OsStr;
use std::io;
use std::path::Path;

use hedwig_model::install::{AtSignIn, Names, Placement, Starts, placement};
use hedwig_model::setting::Autostart;
use hedwig_model::text::Words;
use hedwig_win::registry::{RUN, own, remove_value, set_text};

use crate::channel::words;

/// Why a `Run` value could not be kept.
#[derive(Debug)]
pub enum StartupError {
    /// The folder Hedwig runs from is not one a `Run` value can start it
    /// from.
    Placement(Placement),
    /// The folder's path is not text, which a `Run` value must be.
    NotText,
    /// Windows did not say where Hedwig runs from.
    Program(io::Error),
    Registry(io::Error),
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartupError::Placement(placement) => placement.fmt(f),
            StartupError::NotText => {
                f.write_str("the folder Hedwig runs from has a name Windows cannot start it by")
            }
            StartupError::Program(error) => {
                write!(f, "Windows did not say where Hedwig runs from: {error}")
            }
            StartupError::Registry(error) => {
                write!(
                    f,
                    "the values Windows starts at sign-in could not be kept: {error}"
                )
            }
        }
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartupError::Program(error) | StartupError::Registry(error) => Some(error),
            StartupError::Placement(_) | StartupError::NotText => None,
        }
    }
}

impl StartupError {
    /// What the trail records of it.
    pub fn found(&self) -> AtSignIn {
        let said = words(&self.to_string());
        AtSignIn::Unkept(said.unwrap_or_else(|| {
            Words::try_from("the values Windows starts at sign-in could not be kept")
                .unwrap_or_else(|_| unreachable!("the sentence is words"))
        }))
    }
}

/// Writes or removes the `Run` values `names` gives so that Windows starts
/// Hedwig and its icon from `program` exactly as `hedwig` and `icon` say, and
/// returns what Windows will start for each. The icon's value is written
/// only where its executable stands in `program`; a value of either name
/// that starts a program elsewhere is left as it is.
///
/// # Errors
///
/// Each choice's [`StartupError`], apart: the folder cannot be started
/// from, or the registry refused.
pub fn keep(
    names: &Names,
    program: &Path,
    hedwig: Autostart,
    icon: Autostart,
) -> [(Starts, Result<AtSignIn, StartupError>); 2] {
    [(Starts::Hedwig, hedwig), (Starts::Icon, icon)]
        .map(|(starts, chosen)| (starts, kept(names, program, starts, chosen)))
}

fn kept(
    names: &Names,
    program: &Path,
    starts: Starts,
    chosen: Autostart,
) -> Result<AtSignIn, StartupError> {
    let folder = program.to_str().ok_or(StartupError::NotText)?;
    let value = names.run_value(starts);
    let there = program.join(starts.program()).is_file();
    let wanted = match chosen {
        Autostart::AtLogon if there => {
            placement(names, folder).map_err(StartupError::Placement)?;
            Some(names.run_command(folder, starts))
        }
        Autostart::AtLogon | Autostart::Off => None,
    };
    let current = own(RUN, &value).map_err(StartupError::Registry)?;
    if let Some(command) = wanted {
        if current.as_deref() != Some(OsStr::new(&command)) {
            set_text(RUN, &value, OsStr::new(&command)).map_err(StartupError::Registry)?;
        }
        return Ok(AtSignIn::AsChosen);
    }
    match current {
        Some(command) if !names_folder(&command, folder) => {
            Ok(AtSignIn::Another(words(&command.to_string_lossy())))
        }
        Some(_) => {
            remove_value(RUN, &value).map_err(StartupError::Registry)?;
            Ok(unstarted(chosen))
        }
        None => Ok(unstarted(chosen)),
    }
}

/// What Windows starts where this installation writes no value: nothing,
/// which is the choice unless the choice was a program it does not have.
fn unstarted(chosen: Autostart) -> AtSignIn {
    match chosen {
        Autostart::AtLogon => AtSignIn::Absent,
        Autostart::Off => AtSignIn::AsChosen,
    }
}

/// Whether `command` starts a program in `folder`, as [`Names::run_command`]
/// writes one.
fn names_folder(command: &OsStr, folder: &str) -> bool {
    let quoted = format!("\"{folder}\\").to_lowercase();
    command
        .to_str()
        .is_some_and(|command| command.to_lowercase().starts_with(&quoted))
}
