//! Hedwig's one executable. Its first argument names what it is this time:
//!
//! - `supervise` is what the `Run` value starts and what a client launches;
//! - `core` is what a supervisor runs, and nothing else does;
//! - `remove [--quiet]` takes back what Hedwig wrote on every remote it can
//!   reach, then removes Hedwig from the workstation.
//!
//! `--folder <dir>` after the role keeps Hedwig's files in that folder rather
//! than the person's own. Where the variable `HEDWIG_PIPE` is set it is a
//! channel's askpass instead: its arguments are what the channel's client
//! asks, and nothing in them is read as a role.

#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use hedwig_client::{Session, Standing, look};
use hedwig_core::PATIENCE;
use hedwig_core::record::{Claim, ClaimError};
use hedwig_core::store::Places;
use hedwig_core::supervise::{Found, Pace, Supervisor, Watch};
use hedwig_model::process::{CoreState, Exit};
use hedwig_model::protocol::{Answer, Hint, Reply, Request};
use hedwig_model::text::PipeName;
use hedwig_model::trail::ClientKind;
use hedwig_model::wire::line;
use hedwig_win::token::Token;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    // Whatever this process starts, it does not hand on the handles it was
    // started with: a supervisor holding its starter's pipe would keep
    // whoever reads that pipe waiting for as long as Hedwig runs.
    hedwig_win::process::seal();
    if let Some(pipe) = std::env::var_os(hedwig_core::channel::PIPE) {
        return ExitCode::from(askpass(&pipe));
    }
    let mut arguments = std::env::args_os().skip(1).peekable();
    let role = arguments.next().and_then(|role| role.into_string().ok());
    // Removal is run by Windows' own list of applications, with nothing
    // typed: `--quiet` where a deployer runs it.
    if role.as_deref() == Some("remove") && arguments.peek().is_some_and(|word| word == "--quiet") {
        arguments.next();
    }
    let folder = match (arguments.next(), arguments.next()) {
        (None, _) => None,
        (Some(flag), Some(folder)) if flag == "--folder" => Some(PathBuf::from(folder)),
        _ => return ExitCode::from(Exit::Usage.status()),
    };
    let places = match folder.clone().map_or_else(Places::resolve, Places::at) {
        Ok(places) => places,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(Exit::Storage.status());
        }
    };
    let exit = match role.as_deref() {
        Some("supervise") => supervise(&places, folder),
        Some("core") => hedwig_core::run::run(places, VERSION),
        Some("remove") => return remove(folder),
        _ => Exit::Usage,
    };
    ExitCode::from(exit.status())
}

/// A channel's askpass: puts what the client asks to the person through the
/// core, and prints the answer for the client to read. Anything but an
/// answer ends with status 1, which the client takes as none given.
///
/// The prompt is every argument: the in-box client quotes one only where it
/// holds a space and does not begin with a single quote, so a server's words
/// can arrive split (`build_commandline_string`,
/// `contrib/win32/win32compat/misc.c:1966-1979` at v9.5.0.0).
fn askpass(pipe: &OsStr) -> u8 {
    let said: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let hint = match std::env::var("SSH_ASKPASS_PROMPT").as_deref() {
        Ok("confirm") => Some(Hint::Confirm),
        Ok("none") => Some(Hint::Notice),
        _ => None,
    };
    let (Ok(pipe), Some(words)) = (
        PipeName::try_from(pipe.to_string_lossy().as_ref()),
        hedwig_core::channel::words(&said.join(" ")),
    ) else {
        return 1;
    };
    let answer = match hedwig_client::ask(&pipe, words, hint) {
        Ok(answer) => answer,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let mut out = std::io::stdout().lock();
    let written = match &answer {
        Answer::Text(secret) => out.write_all(secret.expose().as_bytes()).and_then(|()| {
            out.write_all(
                b"
",
            )
        }),
        Answer::Accept => out.write_all(
            b"yes
",
        ),
        Answer::Decline => return 1,
    };
    match written.and_then(|()| out.flush()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn role_arguments(role: &str, folder: Option<PathBuf>) -> Vec<OsString> {
    let mut arguments = vec![OsString::from(role)];
    if let Some(folder) = folder {
        arguments.push(OsString::from("--folder"));
        arguments.push(folder.into_os_string());
    }
    arguments
}

/// The supervisor's role.
fn supervise(places: &Places, folder: Option<PathBuf>) -> Exit {
    hedwig_win::process::quieten();
    let announce = hedwig_win::process::take_output();
    let claim = match Claim::take(places) {
        Ok(claim) => claim,
        Err(ClaimError::Held) if relieve(places) => match Claim::take(places) {
            Ok(claim) => claim,
            Err(_) => return Exit::AlreadyRunning,
        },
        Err(ClaimError::Held) => return Exit::AlreadyRunning,
        Err(error) => {
            eprintln!("{error}");
            return Exit::Storage;
        }
    };
    let Ok(program) = std::env::current_exe() else {
        return Exit::Usage;
    };
    let supervisor = Supervisor {
        program,
        arguments: role_arguments("core", folder),
        watch: Watch::default(),
        pace: Pace::default(),
        clock: hedwig_win::clock::elapsed,
    };
    supervisor.run(claim, announce)
}

/// Whether the supervisor already running was stopped to make way for this
/// one: when this one is in a desktop session and that one's core is not.
fn relieve(places: &Places) -> bool {
    let Ok(Standing::Known(running)) = look(places.folder()) else {
        return false;
    };
    let CoreState::Serving { pipe, .. } = &running.core else {
        return false;
    };
    let own = Token::own().and_then(|token| token.standing());
    let theirs = Session::open(pipe).ok().and_then(|mut session| {
        session.greet(ClientKind::Command).ok()?.ok()?;
        match session.ask(Request::Status).ok()? {
            Ok(Reply::Status(status)) => Some(status.origin.session),
            _ => None,
        }
    });
    let (Ok(own), Some(theirs)) = (own, theirs) else {
        return false;
    };
    if Found::decide(own.session, theirs) == Found::Leave {
        return false;
    }
    hedwig_client::stop(&Standing::Known(running)).is_ok()
        && hedwig_client::released_within(places.folder(), PATIENCE * 2)
}

/// Removes this installation: takes back what Hedwig wrote on every remote it
/// can reach, then everything of Hedwig's on the workstation. What it could
/// not take back is written on standard output, a remote to a line, and the
/// status says whether anything was left.
fn remove(folder: Option<PathBuf>) -> ExitCode {
    use hedwig_client::install::{Place, finish, removed_status, withdraw};
    let place = match Place::resolve(folder) {
        Ok(place) => place,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(Exit::Storage.status());
        }
    };
    let removed = match withdraw(&place, ClientKind::Command) {
        Ok(removed) => removed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(error.status());
        }
    };
    for remote in &removed.left {
        if !remote.left.is_empty() {
            println!("{}", line(remote));
        }
    }
    match finish(&place) {
        Ok(_) => ExitCode::from(removed_status(&removed).status()),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.status())
        }
    }
}
