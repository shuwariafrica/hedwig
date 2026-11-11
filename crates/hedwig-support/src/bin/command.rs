//! A stand-in for the command line, for the suites: each word asks a real
//! `hedwig.exe`'s core and prints what came back in the written form.
//!
//! `command <word> --folder <dir>` acts on the Hedwig whose files are in
//! `<dir>`, never the person's own. `start` launches the `hedwig.exe` beside
//! this program as that folder's supervisor and prints the record it wrote and
//! how the supervisor is tied to this session; `status` asks as a command that
//! leaves and `hello` as a terminal a person is at, each printing the record,
//! who the core says the client is and the status; `activity` prints the
//! record, the client and the newest entries of the trail; `stop` ends that
//! Hedwig and prints `stopped` or `not running`.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::num::NonZeroU8;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hedwig_client::{Launched, OpenError, Session, Standing, look};
use hedwig_core::store::Places;
use hedwig_model::policy::Selector;
use hedwig_model::process::{CoreState, Exit};
use hedwig_model::protocol::{Reply, Request};
use hedwig_model::trail::ClientKind;
use hedwig_model::wire::line;

fn main() -> ExitCode {
    // What `start` launches must not hold what started this process, as
    // `hedwig.exe` hands nothing on to what it starts.
    hedwig_win::process::seal();
    let mut arguments = std::env::args_os().skip(1);
    let word = arguments.next().and_then(|word| word.into_string().ok());
    let folder = match (arguments.next(), arguments.next()) {
        (Some(flag), Some(folder)) if flag == "--folder" => PathBuf::from(folder),
        _ => return ExitCode::from(Exit::Usage.status()),
    };
    let places = match Places::at(folder.clone()) {
        Ok(places) => places,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(Exit::Storage.status());
        }
    };
    let exit = match word.as_deref() {
        Some("start") => start(&folder),
        Some("status") => asked(&places, ClientKind::Command, Request::Status),
        Some("hello") => asked(&places, ClientKind::Terminal, Request::Status),
        Some("activity") => activity(&places),
        Some("stop") => stop(&places),
        _ => Exit::Usage,
    };
    ExitCode::from(exit.status())
}

fn start(folder: &Path) -> Exit {
    let Ok(program) = std::env::current_exe().map(|own| own.with_file_name("hedwig.exe")) else {
        return Exit::Usage;
    };
    let arguments = [
        OsString::from("supervise"),
        OsString::from("--folder"),
        folder.as_os_str().to_owned(),
    ];
    match hedwig_client::launch(&program, &arguments) {
        Ok(Launched { running, tether }) => {
            println!("{}", line(&running));
            println!("{tether:?}");
            Exit::Stopped
        }
        Err(error) => {
            eprintln!("{error}");
            Exit::Usage
        }
    }
}

/// Opens a session with the core the record names, greeted as `kind`.
fn session(places: &Places, kind: ClientKind) -> Result<Session, Exit> {
    let standing = look(places.folder()).map_err(|error| {
        eprintln!("{error}");
        Exit::Storage
    })?;
    let Standing::Known(running) = standing else {
        println!("{standing:?}");
        return Err(Exit::Usage);
    };
    println!("{}", line(&running));
    let CoreState::Serving { pipe, .. } = &running.core else {
        return Err(Exit::Usage);
    };
    let mut session = Session::open(pipe).map_err(|error| {
        eprintln!("{error}");
        match error {
            OpenError::NotOurs { .. } | OpenError::Denied => Exit::Pipe,
            _ => Exit::Usage,
        }
    })?;
    match session.greet(kind) {
        Ok(Ok(you)) => {
            println!("{}", line(&you));
            Ok(session)
        }
        Ok(Err(refusal)) => {
            eprintln!("{refusal}");
            Err(Exit::Usage)
        }
        Err(error) => {
            eprintln!("{error}");
            Err(Exit::Pipe)
        }
    }
}

fn asked(places: &Places, kind: ClientKind, request: Request) -> Exit {
    let mut session = match session(places, kind) {
        Ok(session) => session,
        Err(exit) => return exit,
    };
    match session.ask(request) {
        Ok(Ok(Reply::Status(status))) => println!("{}", line(&status)),
        Ok(Ok(Reply::Activity(entries))) => {
            for entry in entries {
                println!("{}", line(&entry));
            }
        }
        Ok(Ok(other)) => println!("{other:?}"),
        Ok(Err(refusal)) => {
            eprintln!("{refusal}");
            return Exit::Usage;
        }
        Err(error) => {
            eprintln!("{error}");
            return Exit::Pipe;
        }
    }
    Exit::Stopped
}

fn activity(places: &Places) -> Exit {
    let request = Request::Activity {
        remote: Selector::Every,
        before: None,
        limit: NonZeroU8::MAX,
    };
    asked(places, ClientKind::Command, request)
}

fn stop(places: &Places) -> Exit {
    let standing = match look(places.folder()) {
        Ok(standing) => standing,
        Err(error) => {
            eprintln!("{error}");
            return Exit::Storage;
        }
    };
    match hedwig_client::stop(&standing) {
        Ok(stopped) => {
            println!("{}", if stopped { "stopped" } else { "not running" });
            Exit::Stopped
        }
        Err(error) => {
            eprintln!("{error}");
            Exit::Usage
        }
    }
}
