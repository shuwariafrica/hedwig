//! A pinentry that answers every PIN asked with the stand-in card's PIN and
//! appends every command it is sent to `HEDWIG_PINENTRY_LOG`, so a suite
//! counts the times gpg-agent put the PIN to the person.

use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut log = std::env::var_os("HEDWIG_PINENTRY_LOG")
        .and_then(|path| OpenOptions::new().create(true).append(true).open(path).ok());
    let mut out = io::stdout().lock();
    if writeln!(out, "OK pinentry that knows the PIN")
        .and_then(|()| out.flush())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    // The agent tells its client a pinentry was launched once it has the
    // pinentry's process ID (`agent/call-pinentry.c:694-706`).
    let pid = format!("D {}\nOK", std::process::id());
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let command = line.trim_end_matches('\r');
        if let Some(log) = log.as_mut() {
            let _ = writeln!(log, "{command}");
        }
        let verb = command.split(' ').next().unwrap_or_default();
        let answer = match command {
            "GETINFO pid" => pid.as_str(),
            _ if verb == "GETPIN" => "D 123456\nOK",
            _ => "OK",
        };
        if writeln!(out, "{answer}")
            .and_then(|()| out.flush())
            .is_err()
            || verb == "BYE"
        {
            break;
        }
    }
    ExitCode::SUCCESS
}
