//! What removal from Settings shows: what Hedwig wrote, saving the person's
//! settings first, taking back and removing, and what is left on a remote
//! it could not reach.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::protocol::{Request, Withdrawal, Written};
use hedwig_model::text::RemotePath;
use hedwig_model::trail::{ChannelEnd, PromptKind, Write};
use hedwig_view::card::{Card, Does, Subject};
use hedwig_view::removal;

mod common;
use common::support::remote;

fn path(text: &str) -> RemotePath {
    RemotePath::try_from(text).unwrap()
}

fn no_autostart(home: &str) -> Written {
    Written {
        write: Write::NoAutostart,
        place: path(&format!("{home}/.gnupg/common.conf")),
        made: None,
    }
}

/// One remote reached and emptied, one never reached, one not answering.
fn remotes() -> Vec<Withdrawal> {
    vec![
        Withdrawal {
            remote: remote("ssh", "build.example"),
            left: vec![no_autostart("/home/dev")],
            surveying: false,
            ended: None,
        },
        Withdrawal {
            remote: remote("ssh", "gone.example"),
            left: vec![no_autostart("/home/ops")],
            surveying: false,
            ended: Some(ChannelEnd::Declined(PromptKind::Password)),
        },
        Withdrawal {
            remote: remote("ssh", "quiet.example"),
            left: Vec::new(),
            surveying: false,
            ended: None,
        },
    ]
}

fn answers(card: &Card) -> Vec<(&str, &Does)> {
    card.choices
        .iter()
        .map(|choice| (choice.label.as_str(), &choice.does))
        .collect()
}

/// Before anything goes the person sees what Hedwig wrote where, that their
/// settings go with it, and saving them; "Cancel" is the safe answer.
#[test]
fn removal_says_what_hedwig_wrote_and_offers_the_settings_before_anything_goes() {
    let card = removal::before(&remotes(), true, None);
    assert_eq!(card.subject, Subject::Confirming);
    assert_eq!(card.heading, "Remove Hedwig?");
    assert_eq!(
        card.facts,
        vec![
            (
                "Written on",
                "build.example (ssh): no-autostart in /home/dev/.gnupg/common.conf".to_owned()
            ),
            (
                "Written on",
                "gone.example (ssh): no-autostart in /home/ops/.gnupg/common.conf".to_owned()
            ),
        ]
    );
    assert_eq!(
        answers(&card),
        [
            ("Save your settings...", &Does::Save),
            ("Remove Hedwig", &Does::Proceed),
            ("Cancel", &Does::Cancel),
        ]
    );
    let says = card.says.as_deref().unwrap();
    assert!(says.starts_with("Hedwig first takes back"), "{says}");
    assert!(says.contains("your settings with it"), "{says}");

    // Saved, it says where; with nothing written and no settings read, it
    // says so and offers no saving.
    let saved = removal::before(
        &remotes(),
        true,
        Some(r"C:\Users\x\hedwig-configuration.json"),
    );
    assert_eq!(
        saved.facts.last(),
        Some(&(
            "Settings saved to",
            r"C:\Users\x\hedwig-configuration.json".to_owned()
        ))
    );
    let bare = removal::before(&[], false, None);
    assert_eq!(bare.facts, Vec::<(&str, String)>::new());
    assert!(
        bare.says
            .as_deref()
            .unwrap()
            .starts_with("Hedwig has nothing left on a remote to take back.")
    );
    assert_eq!(
        answers(&bare),
        [("Remove Hedwig", &Does::Proceed), ("Cancel", &Does::Cancel)]
    );
}

/// While Hedwig asks, takes back and removes itself, nothing is offered.
#[test]
fn nothing_is_offered_while_hedwig_works() {
    for card in [
        removal::asking(),
        removal::taking_back(&remotes()),
        removal::removing(),
    ] {
        assert!(card.choices.is_empty(), "{}", card.heading);
    }
    assert_eq!(removal::taking_back(&remotes()).facts.len(), 2);
}

/// At the end, what was not taken back is named per remote with why, and
/// can be copied; where everything was, closing is the one answer. Either
/// way the one file left on this workstation is named.
#[test]
fn what_could_not_be_taken_back_is_named_with_why_and_copied() {
    let mut taken = remotes();
    for remote in &mut taken {
        remote.left.clear();
    }
    let clean = removal::removed(&taken, "hedwig-removed-4120.exe");
    assert_eq!(clean.heading, "Hedwig is removed");
    assert_eq!(answers(&clean), [("Close", &Does::Cancel)]);
    assert!(
        clean
            .says
            .as_deref()
            .unwrap()
            .contains("but hedwig-removed-4120.exe, the program that removed it")
    );

    let mut left = remotes();
    left.remove(0);
    left.push(Withdrawal {
        remote: remote("ssh", "slow.example"),
        left: vec![no_autostart("/home/slow")],
        surveying: true,
        ended: None,
    });
    let card = removal::removed(&left, "hedwig-removed-4120.exe");
    assert_eq!(
        card.heading,
        "Hedwig is removed, and some remotes still hold what it wrote"
    );
    assert_eq!(
        card.facts,
        vec![
            (
                "Left on",
                "gone.example (ssh): no-autostart in /home/ops/.gnupg/common.conf; not taken \
                 back: you declined when it asked for a password"
                    .to_owned()
            ),
            (
                "Left on",
                "slow.example (ssh): no-autostart in /home/slow/.gnupg/common.conf; not taken \
                 back: it had not answered after two minutes"
                    .to_owned()
            ),
        ]
    );
    assert_eq!(
        answers(&card),
        [("Copy what is left", &Does::Copy), ("Close", &Does::Cancel)]
    );
    assert_eq!(
        removal::left_text(&left),
        "gone.example (ssh)\n  no-autostart in /home/ops/.gnupg/common.conf\n\
         slow.example (ssh)\n  no-autostart in /home/slow/.gnupg/common.conf\n"
    );
}

/// Where Hedwig cannot be asked, going on is the person's choice, made
/// knowing it leaves what was written; where it cannot remove itself after
/// taking back, they are told it writes on no remote again.
#[test]
fn a_removal_that_cannot_go_on_says_why_and_what_is_left_to_choose() {
    let unasked = removal::unasked("the Hedwig placed did not answer: no record");
    assert_eq!(
        answers(&unasked),
        [("Remove anyway", &Does::Proceed), ("Cancel", &Does::Cancel)]
    );
    assert!(
        unasked
            .says
            .as_deref()
            .unwrap()
            .starts_with("The Hedwig placed did not answer: no record. So Hedwig cannot say")
    );
    let held = removal::not_removed(
        "these still use Hedwig's files; close them and try again: Notepad (4120)",
        true,
    );
    assert_eq!(held.heading, "Hedwig was not removed");
    assert_eq!(
        answers(&held),
        [
            ("Try again", &Does::Proceed),
            ("Keep Hedwig", &Does::Send(Request::Restore)),
            ("Close", &Does::Cancel)
        ]
    );
    assert_eq!(
        held.says.as_deref(),
        Some(
            "These still use Hedwig's files; close them and try again: Notepad (4120). Hedwig \
             has taken back what it could and serves no remote until you keep it or remove it: try again to finish, keep \
             Hedwig to serve your remotes again as you consented, or remove it again from \
             Settings later."
        )
    );
    // Before anything was taken back, there is nothing to keep.
    let early = removal::not_removed("Windows could not say where", false);
    assert_eq!(early.says.as_deref(), Some("Windows could not say where."));
    assert_eq!(
        answers(&early),
        [("Try again", &Does::Proceed), ("Close", &Does::Cancel)]
    );
    assert_eq!(removal::keeping().choices.len(), 0);
}
