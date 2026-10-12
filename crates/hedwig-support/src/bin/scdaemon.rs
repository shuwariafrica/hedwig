//! A stand-in for scdaemon, which a scratch home's `gpg-agent.conf` names as
//! its `scdaemon-program`, so the agent's own `SCD` passthrough can be driven
//! against a card nobody's workstation holds.
//!
//! The agent starts it as it starts scdaemon, `--multi-server`, and speaks
//! Assuan over its standard streams. It answers each command from a recorded
//! exchange, the file `HEDWIG_CARD` names: a line `> <command>` followed by the
//! lines answering it, ending at the next `>` or the end. A command the
//! exchange does not hold is answered as scdaemon answers one it does not know
//! (`ERR 100663571 Unknown IPC command <SCD>`, `GPG_ERR_ASS_UNKNOWN_CMD`). Every
//! command it is sent is appended, one to a line, to the file `HEDWIG_CARD_LOG`
//! names, so a suite can say what anything asked of a card.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let exchange = std::env::var_os("HEDWIG_CARD")
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| recorded(&text))
        .unwrap_or_default();
    let mut log = std::env::var_os("HEDWIG_CARD_LOG")
        .and_then(|path| OpenOptions::new().create(true).append(true).open(path).ok());
    let mut out = io::stdout().lock();
    if writeln!(out, "OK stand-in scdaemon")
        .and_then(|()| out.flush())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else {
            break;
        };
        let command = line.trim_end_matches('\r');
        if let Some(log) = log.as_mut() {
            let _ = writeln!(log, "{command}");
        }
        let answer = if let Some(answer) = exchange.get(command) {
            answer.clone()
        } else if command.starts_with("OPTION ") || command == "RESTART" || command == "BYE" {
            vec!["OK".to_owned()]
        } else {
            vec!["ERR 100663571 Unknown IPC command <SCD>".to_owned()]
        };
        for said in &answer {
            if writeln!(out, "{said}").is_err() {
                return ExitCode::FAILURE;
            }
        }
        if out.flush().is_err() || command == "BYE" {
            break;
        }
    }
    ExitCode::SUCCESS
}

/// Each command of a recorded exchange, with the lines that answer it.
fn recorded(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut exchange: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some(command) = line.strip_prefix("> ") {
            current = Some(command.to_owned());
            exchange.entry(command.to_owned()).or_default();
        } else if let Some(command) = &current {
            exchange
                .entry(command.clone())
                .or_default()
                .push(line.to_owned());
        }
    }
    exchange
}
