//! What removal from Settings shows, run as `hedwig-interface.exe remove`:
//! what Hedwig wrote on each remote, with saving the person's settings
//! offered before anything goes; that it is taking that back, and then
//! removing itself; and at the end what is left on each remote it could not
//! reach, to copy and take away by hand.
//!
//! Every card is the confirmation's construction, the person having asked
//! for the removal: the keyboard starts on the safe answer, and no answer is
//! filled with the accent.

use std::fmt::Write as _;

use hedwig_model::protocol::{Request, Withdrawal};

use crate::card::{Card, Choice, Does, Subject, Weight};
use crate::words;

fn choice(label: &str, does: Does) -> Choice {
    Choice {
        label: label.to_owned(),
        does,
        weight: Weight::Beside,
    }
}

fn card(
    heading: &str,
    says: String,
    facts: Vec<(&'static str, String)>,
    choices: Vec<Choice>,
) -> Card {
    Card {
        subject: Subject::Confirming,
        from: None,
        heading: heading.to_owned(),
        says: Some(says),
        facts,
        typed: false,
        choices,
        allows: None,
        behind: 0,
    }
}

/// One remote's writes, said as the window says them.
fn writes(remote: &Withdrawal) -> String {
    let all: Vec<String> = remote.left.iter().map(words::written).collect();
    format!("{}: {}", remote.remote, all.join("; "))
}

fn written(remotes: &[Withdrawal], label: &'static str) -> Vec<(&'static str, String)> {
    remotes
        .iter()
        .filter(|remote| !remote.left.is_empty())
        .map(|remote| (label, writes(remote)))
        .collect()
}

/// What is put to the person before anything goes: what Hedwig wrote on
/// each remote, which it takes back first; that their settings go with it;
/// and saving them first, where Hedwig could read them (`can_save`), with
/// where they were saved once they were (`saved`).
pub fn before(remotes: &[Withdrawal], can_save: bool, saved: Option<&str>) -> Card {
    let mut facts = written(remotes, "Written on");
    let mut says = if facts.is_empty() {
        "Hedwig has nothing left on a remote to take back.".to_owned()
    } else {
        "Hedwig first takes back what it wrote on your remotes with your consent.".to_owned()
    };
    says.push_str(
        " Then everything of Hedwig's on this workstation goes, your settings with it: save them \
         first to set Hedwig up as it is now, here or on another workstation.",
    );
    if let Some(saved) = saved {
        facts.push(("Settings saved to", saved.to_owned()));
    }
    let mut choices = Vec::new();
    if can_save {
        choices.push(choice("Save your settings...", Does::Save));
    }
    choices.push(choice("Remove Hedwig", Does::Proceed));
    choices.push(choice("Cancel", Does::Cancel));
    card("Remove Hedwig?", says, facts, choices)
}

/// What is shown while Hedwig is started, where it does not run, and asked
/// what it wrote.
pub fn asking() -> Card {
    card(
        "Remove Hedwig?",
        "Hedwig is asked what it wrote on your remotes before anything goes.".to_owned(),
        Vec::new(),
        Vec::new(),
    )
}

/// What is shown while Hedwig takes back what it wrote.
pub fn taking_back(remotes: &[Withdrawal]) -> Card {
    card(
        "Taking back what Hedwig wrote",
        "Hedwig connects to each remote it wrote on and takes back what it wrote there. A remote \
         that needs an answer first asks through Hedwig's icon. One that does not answer is given \
         two minutes."
            .to_owned(),
        written(remotes, "Taking back on"),
        Vec::new(),
    )
}

/// What is shown while Hedwig removes itself from this workstation.
pub fn removing() -> Card {
    card(
        "Removing Hedwig",
        "Hedwig stops, its icon and window close, and its files, its entry in Windows' list of \
         applications, its Start entry and what starts it when you sign in go."
            .to_owned(),
        Vec::new(),
        Vec::new(),
    )
}

/// Why taking back did not reach a remote.
fn unreached(remote: &Withdrawal) -> String {
    match &remote.ended {
        _ if remote.surveying => "it had not answered after two minutes".to_owned(),
        Some(end) => words::end(end),
        None => "Hedwig could not connect to it".to_owned(),
    }
}

/// What removal says when it is done: whether everything Hedwig wrote was
/// taken back, and where it was not, what is left on each remote and why;
/// and the one file it leaves, `aside`, which Windows' own clean-up of
/// temporary files removes.
pub fn removed(remotes: &[Withdrawal], aside: &str) -> Card {
    let left: Vec<&Withdrawal> = remotes
        .iter()
        .filter(|remote| !remote.left.is_empty())
        .collect();
    let mut says = String::new();
    if left.is_empty() {
        says.push_str("Everything Hedwig wrote on your remotes was taken back. ");
    } else {
        says.push_str(
            "Hedwig could not reach these remotes, so what it wrote there is still there: remove \
             it by hand. ",
        );
    }
    let _ = write!(
        says,
        "Nothing of Hedwig's is left on this workstation but {aside}, the program that removed \
         it, in your temporary folder, which Windows' own clean-up removes."
    );
    let facts = left
        .iter()
        .map(|remote| {
            (
                "Left on",
                format!("{}; not taken back: {}", writes(remote), unreached(remote)),
            )
        })
        .collect();
    let mut choices = Vec::new();
    if !left.is_empty() {
        choices.push(choice("Copy what is left", Does::Copy));
    }
    choices.push(choice("Close", Does::Cancel));
    let heading = if left.is_empty() {
        "Hedwig is removed"
    } else {
        "Hedwig is removed, and some remotes still hold what it wrote"
    };
    card(heading, says, facts, choices)
}

/// What is left on each remote, as the person copies it: a remote a line,
/// each write beneath it.
pub fn left_text(remotes: &[Withdrawal]) -> String {
    let mut text = String::new();
    for remote in remotes.iter().filter(|remote| !remote.left.is_empty()) {
        let _ = writeln!(text, "{}", remote.remote);
        for left in &remote.left {
            let _ = writeln!(text, "  {}", words::written(left));
        }
    }
    text
}

/// Hedwig could not be asked what it wrote on the remotes: `why` in the
/// client's own words. Removing it anyway leaves whatever it wrote there.
pub fn unasked(why: &str) -> Card {
    card(
        "Hedwig could not take back what it wrote on your remotes",
        format!(
            "{}. So Hedwig cannot say what it wrote on your remotes with your consent, and \
             removing it anyway leaves that there.",
            capitalised(why)
        ),
        Vec::new(),
        vec![
            choice("Remove anyway", Does::Proceed),
            choice("Cancel", Does::Cancel),
        ],
    )
}

/// Hedwig could not remove itself: `why` in the client's own words. Once it
/// has taken back what it wrote it serves no remote until it is kept or
/// removed, so the person is offered both, and closing leaves it so.
pub fn not_removed(why: &str, withdrawn: bool) -> Card {
    let mut says = format!("{}.", capitalised(why));
    let mut choices = vec![choice("Try again", Does::Proceed)];
    if withdrawn {
        says.push_str(
            " Hedwig has taken back what it could and serves no remote until you keep it or \
             remove it: try again to finish, keep Hedwig to serve your remotes again as you \
             consented, or remove it again from Settings later.",
        );
        choices.push(choice("Keep Hedwig", Does::Send(Request::Restore)));
    }
    choices.push(choice("Close", Does::Cancel));
    card("Hedwig was not removed", says, Vec::new(), choices)
}

/// What is shown while Hedwig, stopped by the removal, is started again and
/// kept.
pub fn keeping() -> Card {
    card(
        "Keeping Hedwig",
        "Hedwig starts again and serves your remotes as you consented.".to_owned(),
        Vec::new(),
        Vec::new(),
    )
}

fn capitalised(text: &str) -> String {
    let mut chars = text.trim_end_matches('.').chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}
