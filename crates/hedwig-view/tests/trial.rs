//! A configuration written out and read back, and an import tried before it
//! is made.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::Exposure;
use hedwig_model::config::{Activation, Change, Document, GrantEntry};
use hedwig_model::protocol::{Request, Tried};
use hedwig_model::remote::Granted;
use hedwig_model::setting::Autostart;
use hedwig_view::link::{Event, Place};
use hedwig_view::trial::{self, Outcome};
use hedwig_view::words::Keyrings;

mod common;
use common::Bench;
use common::support::{grant, name, remote, terms};

fn bench() -> Bench {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    bench
}

fn document(bench: &Bench) -> Document {
    bench
        .seen()
        .document
        .clone()
        .expect("the document was told")
}

fn tried(bench: &mut Bench, document: Document) -> Outcome {
    bench.feed(Event::Wish(Place::Window, trial::try_import(document)));
    let (place, tried) = bench.seen().tried.as_ref().expect("the trial's answer");
    assert_eq!(*place, Place::Window);
    Outcome::of(tried, bench.contacts(), Keyrings::default())
}

#[test]
fn an_export_reads_back_as_the_document_it_was_written_from() {
    let mut bench = bench();
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::Route(name("codespaces"))),
            terms: terms(Activation::WhileRunning, Exposure::NONE),
        }),
    ));
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Autostart(Some(Autostart::AtLogon))),
    ));
    let document = document(&bench);
    assert_eq!(document.grants.len(), 1);
    let text = trial::written(&document);
    assert!(text.ends_with("}\n"), "a page a person reads");
    assert_eq!(trial::document(&text).unwrap(), document);
    // And the other way: a document read from text is written as that text.
    assert_eq!(trial::written(&trial::document(&text).unwrap()), text);
}

#[test]
fn an_import_is_tried_first_and_says_what_it_would_let_through() {
    let mut bench = bench();
    let mut imported = document(&bench);
    imported.grants.push(GrantEntry {
        grant: grant("gpg", Granted::One(remote("ssh", "build.example"))),
        terms: terms(Activation::OnRequest, Exposure::NONE),
    });
    imported.autostart = Some(Autostart::AtLogon);
    let rows_before = bench.rows().to_vec();

    let outcome = tried(&mut bench, imported.clone());
    let Outcome::Would { wider, changes } = &outcome else {
        unreachable!("{outcome:?}")
    };
    assert!(*wider, "a grant added lets more through");
    assert_eq!(
        outcome.heading(),
        "Importing this file lets more reach your workstation"
    );
    assert!(
        changes
            .iter()
            .any(|change| change.starts_with("Reachable: gpg on build.example (ssh)")),
        "{changes:?}"
    );
    assert!(
        changes.iter().any(|change| change
            == "This workstation: Starting Hedwig when you sign in becomes on (your statement for this workstation), where it is off (what Hedwig ships)"),
        "{changes:?}"
    );
    // A remote the file makes known is not said to change in what ships.
    assert!(
        changes
            .iter()
            .all(|change| !change.starts_with("build.example (ssh):")),
        "{changes:?}"
    );
    // A trial makes nothing.
    assert_eq!(bench.rows(), rows_before.as_slice());

    // Made, it is what the trial said.
    bench.feed(Event::Wish(Place::Window, trial::import(imported.clone())));
    assert_eq!(bench.seen().refused, None);
    assert_eq!(document(&bench), imported);
    assert!(bench.seen().tried.is_none(), "another act from the window");
}

#[test]
fn an_import_that_changes_nothing_says_so() {
    let mut bench = bench();
    let same = document(&bench);
    let outcome = tried(&mut bench, same);
    assert_eq!(
        outcome,
        Outcome::Would {
            wider: false,
            changes: Vec::new()
        }
    );
    assert_eq!(outcome.heading(), "Importing this file changes nothing");
}

#[test]
fn a_document_of_another_version_is_refused_with_both_numbers() {
    let mut bench = bench();
    let mut other = document(&bench);
    other.version = 99;
    bench.feed(Event::Wish(Place::Window, trial::try_import(other)));
    let (_, tried) = bench.seen().tried.as_ref().expect("answered");
    assert!(matches!(tried, Tried::Refused(_)), "{tried:?}");
    let outcome = Outcome::of(tried, bench.contacts(), Keyrings::default());
    let Outcome::Refused(why) = &outcome else {
        unreachable!("{outcome:?}")
    };
    assert!(why.contains("99") && why.contains('2'), "{why}");
    assert_eq!(outcome.heading(), "This file cannot be imported");
}

#[test]
fn a_file_that_is_not_a_configuration_says_where_it_is_not() {
    let error = trial::document("{\"version\":2}").unwrap_err();
    assert!(error.to_string().contains("capabilities"), "{error}");
    assert!(trial::document("not json").is_err());
}
