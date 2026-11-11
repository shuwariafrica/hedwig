//! Setup's one question, and what it says while it installs and where it
//! could not.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::setting::Autostart;
use hedwig_view::card::{Choice, Does, Subject};
use hedwig_view::setup;

/// Each way of installing is an answer of its own, so nothing about sign-in
/// is chosen for the person, and "Cancel" is the safe answer the keyboard
/// starts on.
#[test]
fn setup_asks_once_with_no_answer_set_for_the_person() {
    let card = setup::asking(
        "arash",
        r"C:\Users\arash\AppData\Local\Programs\ShuwariAfrica\Hedwig",
    );
    assert_eq!(card.subject, Subject::Confirming);
    assert_eq!(card.heading, "Install Hedwig for arash?");
    assert_eq!(
        card.facts,
        vec![(
            "Installed in",
            r"C:\Users\arash\AppData\Local\Programs\ShuwariAfrica\Hedwig".to_owned()
        )]
    );
    let answers: Vec<(&str, &Does)> = card
        .choices
        .iter()
        .map(|choice| (choice.label.as_str(), &choice.does))
        .collect();
    assert_eq!(
        answers,
        [
            (
                "Install and start when I sign in",
                &Does::Install(Autostart::AtLogon)
            ),
            ("Install only", &Does::Install(Autostart::Off)),
            ("Cancel", &Does::Cancel),
        ]
    );
    assert!(
        card.says
            .as_deref()
            .is_some_and(|says| says.contains("also starts its icon")),
        "{:?}",
        card.says
    );
}

/// While setup works nothing is offered; where it could not, setup's own
/// words for the step that failed are the sentence, and closing is the one
/// answer.
#[test]
fn setup_says_it_is_installing_and_why_it_could_not() {
    let updating = setup::updating("0.0.0", "0.0.1");
    assert_eq!(updating.heading, "Updating Hedwig from 0.0.0 to 0.0.1");
    assert!(updating.choices.is_empty(), "an update chooses nothing");

    let installing = setup::installing("arash");
    assert_eq!(installing.heading, "Installing Hedwig for arash");
    assert_eq!(installing.choices, Vec::<Choice>::new());

    let failed =
        setup::failed("these still use Hedwig's files; close them and try again: Notepad (4120)");
    assert_eq!(failed.heading, "Hedwig was not installed");
    assert_eq!(
        failed.says.as_deref(),
        Some("These still use Hedwig's files; close them and try again: Notepad (4120).")
    );
    let [close] = failed.choices.as_slice() else {
        unreachable!("{:?}", failed.choices)
    };
    assert_eq!(
        (close.label.as_str(), &close.does),
        ("Close", &Does::Cancel)
    );
}

/// Installed over a Hedwig whose removal had not finished, setup says
/// that installing kept it, since when it was being removed, what that
/// changes on the person's remotes and how to finish removing it; one answer.
#[test]
fn setup_says_installing_ended_a_removal_under_way() {
    let kept = setup::kept("03/10/2026 14:05");
    assert_eq!(kept.heading, "Hedwig is installed, and kept");
    assert_eq!(
        kept.says.as_deref(),
        Some(
            "Hedwig was being removed, since 03/10/2026 14:05, and the removal had not finished. \
             Installing it again ended that removal: Hedwig serves your remotes again and writes \
             on them what you consented to. To remove it, use Windows' Installed apps."
        )
    );
    let answers: Vec<(&str, &Does)> = kept
        .choices
        .iter()
        .map(|choice| (choice.label.as_str(), &choice.does))
        .collect();
    assert_eq!(answers, [("Close", &Does::Cancel)]);
}
