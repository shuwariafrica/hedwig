//! A client of a running Hedwig for a script run by hand: `child ask
//! <folder> <request>` greets the core in `<folder>` as a command, sends one
//! request given in the written form, and prints the reply in it; `child
//! attend <folder>` greets as a terminal attending every remote, so the
//! person is reachable while it runs, and prints each notice in the written
//! form, one to a line, until the core closes the pipe; given a file, it
//! answers each request put to it with the word the file holds then, `once`
//! or `refuse`, as the person would.

use std::io::Write;
use std::path::Path;

use hedwig_client::{Session, Standing, look};
use hedwig_model::process::CoreState;
use hedwig_model::protocol::{Attention, Decision, Needs, Notice, Request};
use hedwig_model::trail::ClientKind;
use hedwig_model::wire::{line, read};

/// Why a session could not be had or used, in words for the script.
#[derive(Debug)]
pub struct Unasked(pub String);

impl std::fmt::Display for Unasked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unasked {}

fn session(folder: &Path, kind: ClientKind) -> Result<Session, Unasked> {
    let standing = look(folder).map_err(|error| Unasked(error.to_string()))?;
    let Standing::Known(running) = standing else {
        return Err(Unasked(format!("no Hedwig serves {}", folder.display())));
    };
    let CoreState::Serving { pipe, .. } = &running.core else {
        return Err(Unasked("the core is not serving".to_owned()));
    };
    let mut session = Session::open(pipe).map_err(|error| Unasked(error.to_string()))?;
    match session.greet(kind) {
        Ok(Ok(_)) => Ok(session),
        Ok(Err(refusal)) => Err(Unasked(refusal.to_string())),
        Err(error) => Err(Unasked(error.to_string())),
    }
}

/// Sends `request`, written as the protocol writes one, and gives the reply
/// as it writes one.
///
/// # Errors
///
/// [`Unasked`] where no Hedwig serves the folder, the request is not one, or
/// the pipe fails.
pub fn ask(folder: &Path, request: &str) -> Result<String, Unasked> {
    let request: Request = read(request).map_err(|error| Unasked(error.to_string()))?;
    let mut session = session(folder, ClientKind::Command)?;
    let reply = session
        .ask(request)
        .map_err(|error| Unasked(error.to_string()))?;
    Ok(match reply {
        Ok(reply) => line(&reply),
        Err(refusal) => format!("refused {} {}", line(&refusal), refusal),
    })
}

/// Attends every remote as a terminal and prints each notice until the core
/// closes the pipe.
///
/// # Errors
///
/// [`Unasked`] where no Hedwig serves the folder.
pub fn attend(folder: &Path, decisions: Option<&Path>) -> Result<(), Unasked> {
    let mut session = session(folder, ClientKind::Terminal)?;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "attending");
    let _ = out.flush();
    while let Ok(notice) = session.notice() {
        let _ = writeln!(out, "{}", line(&notice));
        let _ = out.flush();
        let raised = match &notice {
            Notice::Raised(Needs {
                attention: Attention::Request { request, .. },
                ..
            }) => Some(*request),
            _ => None,
        };
        let word = decisions.and_then(|file| std::fs::read_to_string(file).ok());
        let decision = match word.as_deref().map(str::trim) {
            Some("once") => Some(Decision::Once),
            Some("refuse") => Some(Decision::Refuse),
            _ => None,
        };
        if let (Some(request), Some(decision)) = (raised, decision) {
            let answer = session.ask(Request::Decide { request, decision });
            let _ = writeln!(out, "decided {request:?}: {answer:?}");
            let _ = out.flush();
        }
    }
    Ok(())
}
