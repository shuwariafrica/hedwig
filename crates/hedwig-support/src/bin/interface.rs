//! A stand-in for the interface's presence, for the suites: `interface <dir>`
//! attaches to the core of the Hedwig whose files are in `<dir>` as the
//! interface does, prints who the core says it is and then what needs the
//! person's attention, one written form to a line, and leaves. It is built
//! from the client and the model alone, as the interface is.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use hedwig_client::{Session, Standing, look};
use hedwig_model::process::CoreState;
use hedwig_model::protocol::{Reply, Request};
use hedwig_model::trail::ClientKind;
use hedwig_model::wire::line;

fn main() -> ExitCode {
    let Some(folder) = std::env::args_os().nth(1).map(PathBuf::from) else {
        return ExitCode::from(2);
    };
    let Ok(Standing::Known(running)) = look(&folder) else {
        return ExitCode::from(2);
    };
    let CoreState::Serving { pipe, .. } = &running.core else {
        return ExitCode::from(2);
    };
    let Ok(mut session) = Session::open(pipe) else {
        return ExitCode::from(6);
    };
    let Ok(Ok(you)) = session.greet(ClientKind::Interface) else {
        return ExitCode::from(6);
    };
    println!("{}", line(&you));
    match session.ask(Request::Attention) {
        Ok(Ok(Reply::Attention(items))) => {
            for item in items {
                println!("{}", line(&item));
            }
            ExitCode::SUCCESS
        }
        _ => ExitCode::from(6),
    }
}
