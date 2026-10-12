//! What serves a credentials capability: the remote's own `git`, through its
//! own `cache` helper at the forward's socket, asks for a site's credential,
//! and the workstation's own `git credential fill` answers it once the
//! request is decided.
//!
//! The cache helper writes its request and closes its side, then reads the
//! answer to the end (`git-2.56.0/builtin/credential-cache.c:43-70`), so the
//! request is read whole before anything is decided. Its side being closed
//! from the start, a helper that gives up cannot be told from one that waits:
//! a held request waits until it is decided or its channel ends. Only a `get`
//! is ever answered; a `store` and an `erase` are read and closed with
//! nothing said, and an `erase` is told to the deciding thread for the site
//! the forge refused. Whatever is not answered leaves `git` to its next
//! helper and its own prompt.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use hedwig_model::credential::{self, Action, Place, Unfilled, Unread, Wanted};
use hedwig_model::gate::Interaction;
use hedwig_model::text::Program;
use hedwig_model::trail::Failure;
use hedwig_win::process::LEAVING;
use hedwig_win::search::program_on;
use hedwig_win::start::{Environment, given};
use zeroize::Zeroize;

use crate::relay::{Event, QUEUED, Relayed, Settle};

/// What became of a served request's credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// It was given to the remote's `git`.
    Given,
    /// The workstation's `git` gave none: no helper it asks held one for the
    /// site, or one needed to ask the person and could not.
    Nothing,
    /// The remote's `git` was gone when it was to be given.
    Gone,
    /// The workstation's `git` could not be run, or answered out of form.
    Failed(Failure),
}

/// Where a credentials capability's source is: the workstation's own `git`,
/// found as a route's client is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub git: Program,
}

/// What the workstation's `git` is started with: its own `credential fill`,
/// which asks every helper the person configured, with interaction off unless
/// the person allowed the request where a sign-in would show.
pub fn arguments(interaction: Interaction) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = Vec::new();
    if interaction == Interaction::Off {
        // `git`'s own setting (`credential.c:264-282`), which Git Credential
        // Manager reads as well (`gcm-2.9.1/src/shared/Core/Settings.cs:528`).
        arguments.extend(["-c".into(), "credential.interactive=false".into()]);
    }
    arguments.extend(["credential".into(), "fill".into()]);
    arguments
}

/// The workstation's `git`'s variables: `base`, the core's own, with `git`'s
/// own prompt on a terminal off, since the core has no terminal to show it on.
pub fn environment(base: Environment) -> Environment {
    base.with("GIT_TERMINAL_PROMPT", "0")
}

/// Reads a remote's request to its end, at most one byte past the longest,
/// so a longer one is refused by its length.
fn request(client: &mut TcpStream) -> Result<Vec<u8>, Unread> {
    let mut read = Vec::new();
    let limit = u64::try_from(credential::LONGEST + 1).unwrap_or(u64::MAX);
    if client.take(limit).read_to_end(&mut read).is_err() {
        read.zeroize();
        return Err(Unread::TooLong);
    }
    Ok(read)
}

/// What the workstation's `git credential fill` gave for `asked`, or why it
/// gave nothing.
fn fill(
    git: &Path,
    base: Environment,
    asked: &Wanted,
    interaction: Interaction,
) -> Result<credential::Released, Release> {
    // Started outside every job Hedwig holds: the credential system is the
    // person's, and its sign-in may start their browser.
    let (started, mut input, mut said) =
        given(git, &arguments(interaction), &environment(base), LEAVING)
            .map_err(|_| Release::Failed(Failure::Unstartable))?;
    let mut sent = asked.to_fill();
    let written = input.write_all(&sent);
    sent.zeroize();
    drop(input);
    let mut printed = Vec::new();
    let limit = u64::try_from(credential::LONGEST + 1).unwrap_or(u64::MAX);
    let read = (&mut said).take(limit).read_to_end(&mut printed);
    let status = started.wait();
    let answered = match (written, read, status) {
        (Ok(()), Ok(_), Ok(0)) => {
            credential::released(&printed, asked.bearer()).map_err(|unfilled| match unfilled {
                Unfilled::Incomplete => Release::Nothing,
                Unfilled::TooLong | Unfilled::Malformed => Release::Failed(Failure::Mismatched),
            })
        }
        // `git` ends with an error where no helper gave a credential and it
        // could not ask: nothing to release.
        (Ok(()), Ok(_), Ok(_)) => Err(Release::Nothing),
        _ => Err(Release::Failed(Failure::Unreachable)),
    };
    printed.zeroize();
    answered
}

/// Carries one admitted connection to the workstation's credential system.
/// `search` is where `git` is looked for, and `base` the variables it is
/// started with; `tell` reaches the deciding thread. Returns where the
/// deciding thread settles the request.
pub fn carry(
    client: TcpStream,
    source: Credential,
    search: OsString,
    base: Environment,
    tell: impl Fn(Relayed) + Send + 'static,
) -> Arc<Settle> {
    let (events, queue) = mpsc::sync_channel(QUEUED);
    let settle = Arc::new(Settle::new(events));
    let held = Arc::clone(&settle);
    thread::spawn(move || {
        run(client, &source, &search, base, &tell, &queue, &held);
        tell(Relayed::Ended);
    });
    settle
}

fn run(
    mut client: TcpStream,
    source: &Credential,
    search: &OsStr,
    base: Environment,
    tell: &impl Fn(Relayed),
    queue: &Receiver<Event>,
    settle: &Settle,
) {
    let close = |client: &mut TcpStream| {
        let _ = client.shutdown(Shutdown::Both);
    };
    let _ = client.set_read_timeout(Some(crate::PATIENCE));
    let asked = request(&mut client).and_then(|mut bytes| {
        let read = credential::read(&bytes);
        bytes.zeroize();
        let asked = read?;
        let place = asked.wanted.place()?;
        Ok((asked, place))
    });
    let (asked, place) = match asked {
        Ok(asked) => asked,
        Err(unread) => {
            tell(Relayed::Misasked(unread));
            return close(&mut client);
        }
    };
    match asked.action {
        Action::Get => {}
        // Nothing a remote's `git` sends back reaches the workstation's
        // store: the secret that worked, nor the one a site refused.
        Action::Erase => {
            if let Place::Site(_) = place {
                tell(Relayed::Erased(place));
            }
            return close(&mut client);
        }
        Action::Store | Action::Other => return close(&mut client),
    }
    let Ok(git) = program_on(source.git.as_str(), search) else {
        tell(Relayed::Reached(Err(Failure::Unstartable)));
        let _ = crate::relay::wait(queue, settle);
        return close(&mut client);
    };
    tell(Relayed::Wants(place));
    if crate::relay::wait(queue, settle) != Some(Ok(())) {
        return close(&mut client);
    }
    let release = match fill(&git, base, &asked.wanted, settle.interaction()) {
        Ok(released) => {
            let written = client.write_all(&released.answer());
            drop(released);
            if written.is_ok() {
                Release::Given
            } else {
                Release::Gone
            }
        }
        Err(release) => release,
    };
    tell(Relayed::Gave(release));
    close(&mut client);
}
