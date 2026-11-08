//! What setup puts to the person: whether to install Hedwig for their
//! account, and whether it and its icon start when they sign in, in one
//! question; then that it is installing, or why it could not.
//!
//! Neither answer is set for the person. Installing is not a statement about
//! sign-in, and a box already ticked would be one made for them, so each way
//! of installing is an answer of its own and the keyboard starts on
//! "Cancel", as on every confirmation.

use hedwig_model::setting::Autostart;

use crate::card::{Card, Choice, Does, Subject, Weight};

fn choice(label: &str, does: Does) -> Choice {
    Choice {
        label: label.to_owned(),
        does,
        weight: Weight::Beside,
    }
}

/// The question setup asks, run by the person: `account` is who Hedwig is
/// installed for, `program` the folder it goes in.
pub fn asking(account: &str, program: &str) -> Card {
    Card {
        subject: Subject::Confirming,
        from: None,
        heading: format!("Install Hedwig for {account}?"),
        says: Some(
            "Hedwig is installed for this account alone. Starting it when you sign in also starts \
             its icon in the notification area; you can change either in Hedwig's window later."
                .to_owned(),
        ),
        facts: vec![("Installed in", program.to_owned())],
        typed: false,
        choices: vec![
            choice(
                "Install and start when I sign in",
                Does::Install(Autostart::AtLogon),
            ),
            choice("Install only", Does::Install(Autostart::Off)),
            choice("Cancel", Does::Cancel),
        ],
        allows: None,
        behind: 0,
    }
}

/// What is shown while setup places Hedwig, starts it and waits for it to
/// answer: no answer is offered, since nothing can be stopped half-way.
pub fn installing(account: &str) -> Card {
    Card {
        subject: Subject::Confirming,
        from: None,
        heading: format!("Installing Hedwig for {account}"),
        says: Some(
            "Hedwig is placed, started and asked which version it is. Its window opens when it \
             answers."
                .to_owned(),
        ),
        facts: Vec::new(),
        typed: false,
        choices: Vec::new(),
        allows: None,
        behind: 0,
    }
}

/// What is shown while setup replaces the version installed, `from`, with
/// its own, `to`. Nothing is asked: an update chooses nothing, and every
/// statement the person made stays as it was.
pub fn updating(from: &str, to: &str) -> Card {
    Card {
        subject: Subject::Confirming,
        from: None,
        heading: format!("Updating Hedwig from {from} to {to}"),
        says: Some(
            "Hedwig stops for a moment and its icon and window close; it starts again with \
             everything you set, and its window opens when it answers."
                .to_owned(),
        ),
        facts: Vec::new(),
        typed: false,
        choices: Vec::new(),
        allows: None,
        behind: 0,
    }
}

/// Said once setup has installed over a Hedwig whose removal, begun `since`,
/// had not finished: installing is the person's word that they want Hedwig,
/// so it ended the removal, and Hedwig writes on their remotes again.
pub fn kept(since: &str) -> Card {
    Card {
        subject: Subject::Confirming,
        from: None,
        heading: "Hedwig is installed, and kept".to_owned(),
        says: Some(format!(
            "Hedwig was being removed, since {since}, and the removal had not finished. \
             Installing it again ended that removal: Hedwig serves your remotes again and writes \
             on them what you consented to. To remove it, use Windows' Installed apps."
        )),
        facts: Vec::new(),
        typed: false,
        choices: vec![choice("Close", Does::Cancel)],
        allows: None,
        behind: 0,
    }
}

/// Why setup did not install Hedwig, in setup's own words for the step that
/// failed: nothing after that step was done, and a version installed before
/// runs as it did.
pub fn failed(why: &str) -> Card {
    Card {
        subject: Subject::Confirming,
        from: None,
        heading: "Hedwig was not installed".to_owned(),
        says: Some(capitalised(why)),
        facts: Vec::new(),
        typed: false,
        choices: vec![choice("Close", Does::Cancel)],
        allows: None,
        behind: 0,
    }
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        let mut said: String = first.to_uppercase().chain(chars).collect();
        if !said.ends_with('.') {
            said.push('.');
        }
        said
    })
}
