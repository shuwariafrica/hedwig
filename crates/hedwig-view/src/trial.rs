//! A configuration carried to or from a file: written out as the person's
//! own document, and read in only after the core has said what it would do.
//!
//! An import is tried first (`try`), and what it would change is the whole
//! of what the person decides on: every row and every setting that would
//! differ, before and after, and whether it lets more through. Making it is
//! one more act, and the core's gate is met again then.

use std::fmt::Write as _;

use hedwig_model::config::{Document, Reach};
use hedwig_model::protocol::{Contact, Differs, Request, Row, Trial, Tried};
use hedwig_model::wire::{WireError, page, read};

use crate::setting::{SHIPS, Setting, Sheet};
use crate::words::{self, Keyrings};

/// The shell's dialog, in Hedwig's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dialog {
    pub title: &'static str,
    /// The name suggested for a file written.
    pub name: &'static str,
    pub kinds: &'static [(&'static str, &'static str)],
    pub extension: &'static str,
}

const KINDS: &[(&str, &str)] = &[
    ("Hedwig configuration (*.json)", "*.json"),
    ("All files (*.*)", "*.*"),
];

/// Where the person's configuration is written to.
pub const EXPORT: Dialog = Dialog {
    title: "Export your Hedwig configuration",
    name: "hedwig-configuration.json",
    kinds: KINDS,
    extension: "json",
};

/// Where a configuration is read from.
pub const IMPORT: Dialog = Dialog {
    title: "Import a Hedwig configuration",
    name: "",
    kinds: KINDS,
    extension: "json",
};

/// What an export writes and says it wrote: the person's own statements,
/// never the organisation's, which come from it on every workstation.
pub fn written(document: &Document) -> String {
    let mut text = page(document);
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// A file's text as a document.
///
/// # Errors
///
/// The model's account of why the text is not a configuration document.
pub fn document(text: &str) -> Result<Document, WireError> {
    read(text)
}

/// Asks the core what importing `document` would do, making nothing.
pub fn try_import(document: Document) -> Request {
    Request::Try(Box::new(Trial {
        policy: None,
        document: Some(document),
        change: None,
        remotes: Vec::new(),
    }))
}

/// What a trial would do, as the window shows it.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The core's gate would refuse it: nothing would change.
    Refused(String),
    Would {
        /// Whether it can let more through than what holds now.
        wider: bool,
        /// Each thing that would differ, before and after.
        changes: Vec<String>,
    },
}

fn row(row: &Row, keyrings: Keyrings<'_>) -> String {
    let place = row
        .remote
        .as_ref()
        .map_or_else(|| "remotes not yet seen".to_owned(), ToString::to_string);
    let mut text = format!("{} on {place}", row.capability);
    for decides in &row.decides {
        let _ = write!(text, "; {}", words::verb(decides.operation));
        if let Some(key) = &decides.key {
            let _ = write!(text, " with {}", words::key(key, keyrings));
        }
        let _ = write!(text, " {}", words::mode(decides.mode));
    }
    if row.decides.is_empty() {
        let _ = write!(text, ", {}", words::exposure(row.exposure));
    }
    text
}

fn rows(differs: &Differs<Row>, keyrings: Keyrings<'_>) -> String {
    match (&differs.before, &differs.after) {
        (None, Some(after)) => format!("Reachable: {}", row(after, keyrings)),
        (Some(before), None) => format!("No longer reachable: {}", row(before, keyrings)),
        (Some(before), Some(after)) => format!(
            "Changed: {}, where it was {}",
            row(after, keyrings),
            row(before, keyrings)
        ),
        (None, None) => String::new(),
    }
}

fn settings(whose: &str, before: &[Setting], after: &[Setting], into: &mut Vec<String>) {
    for now in after {
        let was = before.iter().find(|was| was.name == now.name);
        // Where nothing was known before, what ships is no change a file made.
        let changed = match was {
            Some(was) => was.value != now.value || was.said != now.said,
            None => now.said != SHIPS,
        };
        if changed {
            let mut text = format!("{whose}: {} becomes {} ({})", now.name, now.value, now.said);
            if let Some(was) = was {
                let _ = write!(text, ", where it is {} ({})", was.value, was.said);
            }
            into.push(text);
        }
    }
}

impl Outcome {
    /// The core's answer to a trial, in the person's words; `keyrings` names
    /// the keys it decides.
    pub fn of(tried: &Tried, contacts: &[Contact], keyrings: Keyrings<'_>) -> Outcome {
        let would = match tried {
            Tried::Refused(refusal) => return Outcome::Refused(words::refusal(refusal, contacts)),
            Tried::Would(would) => would,
        };
        let mut changes: Vec<String> = would
            .rows
            .iter()
            .map(|differs| rows(differs, keyrings))
            .collect();
        for remote in &would.remotes {
            let sheet = |side: Option<&hedwig_model::protocol::RemoteSettings>| {
                side.map(|side| Sheet::remote(side, keyrings))
                    .unwrap_or_default()
            };
            let whose = remote
                .after
                .as_ref()
                .or(remote.before.as_ref())
                .map_or_else(String::new, |side| side.remote.to_string());
            settings(
                &whose,
                &sheet(remote.before.as_ref()),
                &sheet(remote.after.as_ref()),
                &mut changes,
            );
        }
        if let Some(workstation) = &would.workstation {
            let sheet = |side: Option<&hedwig_model::protocol::WorkstationSettings>| {
                side.map(Sheet::workstation).unwrap_or_default()
            };
            settings(
                "This workstation",
                &sheet(workstation.before.as_ref()),
                &sheet(workstation.after.as_ref()),
                &mut changes,
            );
        }
        changes.retain(|change| !change.is_empty());
        Outcome::Would {
            wider: would.reach == Reach::Wider,
            changes,
        }
    }

    /// What the window says above the changes.
    pub fn heading(&self) -> &'static str {
        match self {
            Outcome::Refused(_) => "This file cannot be imported",
            Outcome::Would { wider: true, .. } => {
                "Importing this file lets more reach your workstation"
            }
            Outcome::Would { changes, .. } if changes.is_empty() => {
                "Importing this file changes nothing"
            }
            Outcome::Would { .. } => "Importing this file changes what you have set",
        }
    }
}

/// Makes the import the person has seen tried.
pub fn import(document: Document) -> Request {
    Request::Import(Box::new(document))
}
