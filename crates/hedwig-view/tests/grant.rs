//! A grant being made: its written form, kept between the person's edits,
//! and the form that asks for what the model asks for.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::{Exposure, Setup};
use hedwig_model::config::{Activation, Change, Document, Reference};
use hedwig_model::remote::Granted;
use hedwig_view::grant::{Aim, Draft, Form, Unreadable};
use hedwig_view::link::Event;

mod common;
use common::Bench;
use common::support::{name, remote};

fn shipped() -> (Reference, Document) {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    let seen = bench.seen();
    (
        seen.catalogue
            .as_ref()
            .expect("the catalogue was told")
            .reference()
            .clone(),
        seen.document.clone().expect("the document was told"),
    )
}

#[test]
fn a_draft_reads_back_as_written_with_what_names_nothing_yet() {
    let (reference, _) = shipped();
    let mut draft = Draft::default();
    assert_eq!(Draft::read(&draft.written()), Ok(draft.clone()));

    draft.capability = Some(name("gpg"));
    draft.choose_route(name("ssh"), &reference);
    draft.aim_at(Aim::Named, &reference);
    // Half typed: a name no remote can have yet, kept as typed.
    draft.type_name("-oProxy", &reference);
    assert_eq!(draft.remotes, None);
    draft.choose_activation(Activation::OnRequest);
    draft.let_write(true);
    draft.acknowledge("secret", true);
    let text = draft.written();
    let read = Draft::read(&text).unwrap();
    assert_eq!(read, draft);
    assert_eq!(read.written(), text, "and back to the same text");

    draft.type_name("build.example", &reference);
    assert_eq!(
        draft.remotes,
        Some(Granted::One(remote("ssh", "build.example")))
    );
    assert_eq!(Draft::read(&draft.written()), Ok(draft));
}

#[test]
fn what_is_kept_is_unreadable_unless_it_is_a_draft() {
    assert_eq!(Draft::read(""), Err(Unreadable));
    assert_eq!(Draft::read("{\"capability\":null}"), Err(Unreadable));
    let written = Draft::default().written();
    let other = written.replace("\"aim\":\"route\"", "\"aim\":\"everywhere\"");
    assert_eq!(Draft::read(&other), Err(Unreadable));
    let more = written.replace('}', ",\"more\":1}");
    assert_eq!(Draft::read(&more), Err(Unreadable));
}

#[test]
fn the_form_asks_for_what_the_model_asks_for_one_thing_at_a_time() {
    let (reference, document) = shipped();
    let mut draft = Draft::default();
    let form = Form::of(&draft, &reference, &document, None, (None, None), None);
    assert_eq!(form.ready, Err("Choose what to grant.".to_owned()));
    assert!(form.capabilities.iter().any(|choice| choice.label == "gpg"));
    assert!(form.routes.iter().any(|choice| choice.label == "ssh"));
    assert!(form.capabilities.iter().all(|choice| !choice.chosen));

    draft.choose_capability(name("gpg"), &reference, &document);
    assert_eq!(
        Form::of(&draft, &reference, &document, None, (None, None), None).ready,
        Err("Choose which remotes it is granted to.".to_owned())
    );
    draft.choose_route(name("ssh"), &reference);
    let form = Form::of(&draft, &reference, &document, None, (None, None), None);
    assert_eq!(
        form.ready,
        Err("Choose when Hedwig connects to them.".to_owned())
    );
    // ssh lists nothing, so following a remote's life is not offered.
    assert!(
        form.activations
            .iter()
            .all(|choice| choice.value != Activation::WhileRunning),
        "{:?}",
        form.activations
    );
    draft.choose_activation(Activation::OnRequest);
    let form = Form::of(&draft, &reference, &document, None, (None, None), None);
    assert_eq!(
        form.ready,
        Ok("Grant gpg to every remote on ssh".to_owned())
    );
    assert!(!form.writes, "consent to write is never filled in");
    assert_eq!(draft.setup, Setup::Inspect);

    // A capability that exposes more asks the person to name it, and
    // naming it once more is the act that makes the grant.
    draft.choose_capability(name("gpg-unrestricted"), &reference, &document);
    let form = Form::of(&draft, &reference, &document, None, (None, None), None);
    let Err(owed) = &form.ready else {
        unreachable!("{:?}", form.ready)
    };
    assert!(owed.starts_with("Name what this lets them do"), "{owed}");
    let words: Vec<&str> = form.exposes.iter().map(|choice| choice.value).collect();
    for word in &words {
        draft.acknowledge(word, true);
    }
    let form = Form::of(&draft, &reference, &document, None, (None, None), None);
    assert!(form.exposes.iter().all(|choice| choice.chosen));
    assert_eq!(
        form.ready,
        Ok("Grant gpg-unrestricted to every remote on ssh".to_owned())
    );
    let Ok(Change::Grant { terms, .. }) = draft.change(&reference, &document) else {
        unreachable!()
    };
    assert_eq!(terms.acknowledged, draft.acknowledged);
    assert!(!terms.acknowledged.common(Exposure::ACKNOWLEDGED).is_empty());

    // Choosing back the narrower capability unnames what it does not expose.
    draft.choose_capability(name("gpg"), &reference, &document);
    assert_eq!(draft.acknowledged, Exposure::NONE);
}

#[test]
fn a_name_that_cannot_be_a_remote_says_why_where_it_is_typed() {
    let (reference, document) = shipped();
    let mut draft = Draft::default();
    draft.choose_route(name("ssh"), &reference);
    draft.aim_at(Aim::Named, &reference);
    draft.type_name("-oProxyCommand=calc", &reference);
    let form = Form::of(&draft, &reference, &document, None, (None, None), None);
    assert!(form.unnamed.is_some(), "{form:?}");
    assert_eq!(form.typed, "-oProxyCommand=calc", "kept as typed");
    draft.type_name("team-*", &reference);
    let form = Form::of(&draft, &reference, &document, None, (None, None), None);
    assert_eq!(form.unnamed, None);
    assert!(matches!(draft.remotes, Some(Granted::Matching { .. })));
}
