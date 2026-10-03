//! The written form of every frame, entry and document: both directions as
//! equality, the bytes pinned, and every way of being wrong told apart.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::collections::BTreeSet;
use std::fmt::Debug;

use hedwig_model::capability::{Lends, Source};
use hedwig_model::config::{Catalogue, Change, Document, Reference};
use hedwig_model::json::{Flaw, Json, JsonError};
use hedwig_model::organisation::{Limit, Part, Start, Statement};
use hedwig_model::policy::{Basis, Keys};
use hedwig_model::process::{CoreState, Order, Report};
use hedwig_model::protocol::{
    Attachment, Attention, DeviceState, FromCore, Notice, Reply, Request, Standing, ToCore, Tried,
};
use hedwig_model::refusal::{Refusal, Whereabouts, Withheld};
use hedwig_model::remote::{Argument, Granted, Identity, Listing, Member, Remotes};
use hedwig_model::scope::Holder;
use hedwig_model::setting::{Condition, Heard, Longest, Threshold, Volume};
use hedwig_model::text::TextError;
use hedwig_model::trail::{
    Binding, Breakdown, Carriage, ChannelEnd, Dropped, Entry, Event, Finding, Item, Outcome,
    Presence, PromptKind, Target,
};
use hedwig_model::wire::{FRAME, Miss, Shape, Wire, WireError, line, page, read};

mod support;
use support::corpus;

/// value -> text -> value, then text -> value -> text.
fn both_ways<T: Wire + PartialEq + Debug>(value: &T) -> String {
    let text = line(value);
    assert!(!text.contains('\n'), "a frame is one line: {text}");
    let back: T = read(&text).unwrap_or_else(|error| panic_with(&text, &error));
    assert_eq!(&back, value, "{text}");
    assert_eq!(line(&back), text);
    text
}

#[allow(
    clippy::panic,
    reason = "a test failure, with the frame that caused it"
)]
fn panic_with(text: &str, error: &WireError) -> ! {
    panic!("{error}\n{text}")
}

fn all_lines() -> Vec<String> {
    let mut lines = Vec::new();
    lines.extend(corpus::to_core().iter().map(both_ways));
    lines.extend(corpus::from_core().iter().map(both_ways));
    lines.extend(corpus::entries().iter().map(both_ways));
    lines.push(both_ways(&corpus::document()));
    lines.extend(corpus::running().iter().map(both_ways));
    lines.extend(corpus::orders().iter().map(both_ways));
    lines.extend(corpus::reports().iter().map(both_ways));
    lines
}

#[test]
fn every_frame_entry_and_document_survives_both_directions() {
    assert!(all_lines().len() > 200);
}

/// Known answers: the bytes are part of the contract a script reads, so a
/// change to any of them is a change to the protocol and shows here. Set
/// `HEDWIG_MODEL_PIN` to write the file after a deliberate change.
#[test]
fn the_written_form_is_pinned() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus.jsonl");
    let mut written = all_lines().join("\n");
    written.push('\n');
    if std::env::var_os("HEDWIG_MODEL_PIN").is_some() {
        std::fs::write(path, &written).expect("the corpus is written");
    }
    let pinned = std::fs::read_to_string(path).expect("tests/corpus.jsonl exists");
    for (number, (pinned, written)) in pinned.lines().zip(written.lines()).enumerate() {
        assert_eq!(pinned, written, "line {}", number + 1);
    }
    assert_eq!(pinned.lines().count(), written.lines().count());
}

/// The first frames of a session, written out, so the form is visible here
/// and not only in the pinned file.
#[test]
fn a_session_reads_as_it_is_specified() {
    let hello: ToCore =
        read(r#"{"id":1,"request":{"hello":{"protocol":3,"kind":"terminal","attends":"every"}}}"#)
            .expect("the greeting");
    assert_eq!(&hello, corpus::to_core().first().expect("a frame"));
    assert_eq!(
        line(&FromCore::Reply {
            id: 7,
            reply: Err(Refusal::Version { core: 2, client: 1 }),
        }),
        r#"{"reply":{"id":7,"reply":{"refused":{"version":{"core":2,"client":1}}}}}"#
    );
    assert_eq!(
        line(&ToCore {
            id: 2,
            request: Request::Status
        }),
        r#"{"id":2,"request":"status"}"#
    );
}

fn words<T: Wire>(values: &[T]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| match value.put() {
            Json::Text(word) => word,
            Json::Map(mut members) => members.pop().expect("one key").0,
            other => format!("{other:?}"),
        })
        .collect()
}

fn known(words: &[&str]) -> BTreeSet<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

/// Every variant of every choice that carries meaning has an example in the
/// corpus, so none is round-tripped by assumption.
#[test]
fn the_corpus_exercises_every_variant() {
    // The counts the decision records state.
    assert_eq!(Request::WORDS.len(), 37);
    assert_eq!(Event::WORDS.len(), 62);
    assert_eq!(Refusal::WORDS.len(), 61);
    assert_eq!(Change::WORDS.len(), 31);
    assert_eq!(Notice::WORDS.len(), 6);
    assert_eq!(words(&corpus::requests()), known(Request::WORDS));
    assert_eq!(words(&corpus::replies()), known(Reply::WORDS));
    assert_eq!(words(&corpus::notices()), known(Notice::WORDS));
    assert_eq!(words(&corpus::events()), known(Event::WORDS));
    assert_eq!(words(&corpus::refusals()), known(Refusal::WORDS));
    assert_eq!(words(&corpus::withheld()), known(Withheld::WORDS));
    assert_eq!(
        words(&hedwig_model::beyond::Beyond::ALL),
        known(hedwig_model::beyond::Beyond::WORDS)
    );
    let carriages: Vec<Carriage> = corpus::events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Carried { carriage, .. } => Some(carriage),
            _ => None,
        })
        .collect();
    assert_eq!(words(&carriages), known(Carriage::WORDS));
    let targets: Vec<Target> = carriages
        .into_iter()
        .filter_map(|carriage| match carriage {
            Carriage::Reverse(target) => Some(target),
            _ => None,
        })
        .collect();
    assert_eq!(words(&targets), known(Target::WORDS));
    let dropped: Vec<Dropped> = corpus::events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Dropped { why, .. } => Some(why),
            _ => None,
        })
        .collect();
    assert_eq!(words(&dropped), known(Dropped::WORDS));
    let lendable = corpus::lendable();
    let states: Vec<DeviceState> = lendable.iter().map(|device| device.state).collect();
    assert_eq!(words(&states), known(DeviceState::WORDS));
    let attached: Vec<Attachment> = lendable.iter().map(|device| device.attached).collect();
    assert_eq!(words(&attached), known(Attachment::WORDS));

    assert_eq!(words(&corpus::presences()), known(Presence::WORDS));
    assert_eq!(words(&corpus::whereabouts()), known(Whereabouts::WORDS));
    assert_eq!(words(&corpus::changes()), known(Change::WORDS));
    assert_eq!(words(&corpus::attention()), known(Attention::WORDS));
    assert_eq!(words(&corpus::standings()), known(Standing::WORDS));
    assert_eq!(words(&corpus::ends()), known(ChannelEnd::WORDS));
    assert_eq!(words(&corpus::outcomes()), known(Outcome::WORDS));
    assert_eq!(words(&corpus::items()), known(Item::WORDS));
    assert_eq!(words(&corpus::findings()), known(Finding::WORDS));
    assert_eq!(words(&corpus::prompt_kinds()), known(PromptKind::WORDS));
    assert_eq!(words(&corpus::bindings()), known(Binding::WORDS));
    assert_eq!(words(&corpus::bases()), known(Basis::WORDS));
    assert_eq!(words(&corpus::sources()), known(Source::WORDS));
    assert_eq!(words(&corpus::granted()), known(Granted::WORDS));
    assert_eq!(words(&corpus::remotes()), known(Remotes::WORDS));
    assert_eq!(words(&corpus::keys()), known(Keys::WORDS));
    assert_eq!(words(&corpus::thresholds()), known(Threshold::WORDS));
    assert_eq!(words(&corpus::volumes()), known(Volume::WORDS));
    assert_eq!(words(&corpus::conditions()), known(Condition::WORDS));
    assert_eq!(words(&corpus::heard()), known(Heard::WORDS));
    assert_eq!(words(&corpus::longests()), known(Longest::WORDS));
    assert_eq!(words(&corpus::fleet().members), known(Member::WORDS));
    assert_eq!(words(&corpus::breakdowns()), known(Breakdown::WORDS));
    assert_eq!(words(&corpus::limits()), known(Limit::WORDS));
    assert_eq!(words(&corpus::starts()), known(Start::WORDS));
    assert_eq!(words(&corpus::statements()), known(Statement::WORDS));
    let parts: Vec<Part> = corpus::places().iter().map(|place| place.part).collect();
    assert_eq!(words(&parts), known(Part::WORDS));
    assert_eq!(words(&corpus::tried()), known(Tried::WORDS));
    let holders: Vec<Holder> = corpus::holdings()
        .into_iter()
        .map(|holding| holding.holder)
        .collect();
    assert_eq!(words(&holders), known(Holder::WORDS));
    let routes = corpus::routes();
    let listings: Vec<Listing> = routes.iter().map(|route| route.listing.clone()).collect();
    let identities: Vec<Identity> = routes.iter().map(|route| route.identity).collect();
    let arguments: Vec<Argument> = routes
        .iter()
        .flat_map(|route| route.client.before.iter().chain(&route.client.after))
        .cloned()
        .collect();
    assert_eq!(words(&listings), known(Listing::WORDS));
    assert_eq!(words(&identities), known(Identity::WORDS));
    assert_eq!(words(&arguments), known(Argument::WORDS));
    assert_eq!(words(&corpus::orders()), known(Order::WORDS));
    assert_eq!(words(&corpus::reports()), known(Report::WORDS));
    let states: Vec<CoreState> = corpus::running()
        .into_iter()
        .map(|running| running.core)
        .collect();
    assert_eq!(words(&states), known(CoreState::WORDS));
}

fn fault(text: &str) -> (String, Miss) {
    match read::<ToCore>(text).expect_err("must be refused") {
        WireError::Fault(fault) => (fault.path(), fault.miss),
        other => (other.to_string(), Miss::Range),
    }
}

/// One case per way a well-formed JSON text can fail to be a message, each
/// with the path to what is wrong.
#[test]
fn every_miss_is_told_apart_and_located() {
    assert_eq!(
        fault(r#"{"id":"1","request":"status"}"#),
        ("id".to_owned(), Miss::Expected(Shape::Number))
    );
    assert_eq!(
        fault(
            r#"{"id":1,"request":{"check":{"remote":{"route":1,"address":"a"},"capability":"gpg"}}}"#
        ),
        (
            "request.check.remote.route".to_owned(),
            Miss::Expected(Shape::Text)
        )
    );
    assert_eq!(
        fault(
            r#"{"id":1,"request":{"connect":{"remote":{"route":"ssh","address":"a"},"with":"gpg","acknowledged":[]}}}"#
        ),
        (
            "request.connect.with".to_owned(),
            Miss::Expected(Shape::List)
        )
    );
    assert_eq!(fault("[1]"), (String::new(), Miss::Expected(Shape::Record)));
    assert_eq!(
        fault(r#"{"id":1,"request":7}"#),
        ("request".to_owned(), Miss::Expected(Shape::Choice))
    );
    assert_eq!(
        fault(r#"{"id":1,"request":{"status":1,"stop":2}}"#),
        ("request".to_owned(), Miss::Expected(Shape::Choice))
    );
    assert_eq!(
        fault(r#"{"id":1}"#),
        (String::new(), Miss::Missing("request"))
    );
    assert_eq!(
        fault(r#"{"id":1,"request":"status","urgent":true}"#),
        (String::new(), Miss::Unknown("urgent".to_owned()))
    );
    assert_eq!(
        fault(r#"{"id":1,"request":"reboot"}"#),
        ("request".to_owned(), Miss::Unknown("reboot".to_owned()))
    );
    assert_eq!(
        fault(r#"{"id":1,"request":{"reboot":{}}}"#),
        ("request".to_owned(), Miss::Unknown("reboot".to_owned()))
    );
    assert_eq!(
        fault(r#"{"id":1,"request":{"follow":{"after":null,"and":1}}}"#),
        ("request.follow".to_owned(), Miss::Unknown("and".to_owned()))
    );
    assert_eq!(
        fault(
            r#"{"id":1,"request":{"connect":{"remote":{"route":"ssh","address":"a"},"with":[],"acknowledged":["everything"]}}}"#
        ),
        (
            "request.connect.acknowledged".to_owned(),
            Miss::Unknown("everything".to_owned())
        )
    );
    assert_eq!(
        fault(r#"{"id":4294967296,"request":"status"}"#),
        ("id".to_owned(), Miss::Range)
    );
    assert_eq!(
        fault(r#"{"id":-1,"request":"status"}"#),
        ("id".to_owned(), Miss::Range)
    );
    assert_eq!(
        fault(r#"{"id":1,"request":{"activity":{"remote":"every","before":null,"limit":0}}}"#),
        ("request.activity.limit".to_owned(), Miss::Range)
    );
    assert_eq!(
        fault(
            r#"{"id":1,"request":{"connect":{"remote":{"route":"Coder","address":"a"},"with":[],"acknowledged":[]}}}"#
        ),
        (
            "request.connect.remote.route".to_owned(),
            Miss::Text(TextError::Character { found: 'C', at: 0 })
        )
    );
    assert_eq!(
        fault(
            r#"{"id":1,"request":{"connect":{"remote":{"route":"ssh","address":"-oProxyCommand=x"},"with":[],"acknowledged":[]}}}"#
        ),
        (
            "request.connect.remote.address".to_owned(),
            Miss::Text(TextError::LeadingHyphen)
        )
    );
    assert_eq!(
        fault(
            r#"{"id":1,"request":{"connect":{"remote":{"route":"ssh","address":"a"},"with":["gpg",""],"acknowledged":[]}}}"#
        ),
        (
            "request.connect.with.1".to_owned(),
            Miss::Text(TextError::Empty)
        )
    );
}

/// Absence is `null`; a key left out is a missing key, and `null` where a
/// value is required is the wrong shape.
#[test]
fn nothing_is_optional_by_omission() {
    assert_eq!(
        fault(r#"{"id":1,"request":{"follow":{}}}"#),
        ("request.follow".to_owned(), Miss::Missing("after"))
    );
    assert_eq!(
        fault(r#"{"id":null,"request":"status"}"#),
        ("id".to_owned(), Miss::Expected(Shape::Number))
    );
}

#[test]
fn a_frame_over_the_limit_is_refused_before_it_is_parsed() {
    let long = format!("\"{}\"", "a".repeat(FRAME));
    assert_eq!(
        read::<ToCore>(&long),
        Err(WireError::Size { length: FRAME + 2 })
    );
    assert_eq!(
        read::<ToCore>("{"),
        Err(WireError::Json(JsonError {
            at: 1,
            flaw: Flaw::End
        }))
    );
}

#[test]
fn every_wire_error_is_worded_for_the_refusal_that_carries_it() {
    let (path, miss) = fault(
        r#"{"id":1,"request":{"connect":{"remote":{"route":"Coder","address":"a"},"with":[],"acknowledged":[]}}}"#,
    );
    assert_eq!(path, "request.connect.remote.route");
    let said = |text: &str| read::<ToCore>(text).expect_err("refused").to_string();
    assert_eq!(
        said(
            r#"{"id":1,"request":{"connect":{"remote":{"route":"Coder","address":"a"},"with":[],"acknowledged":[]}}}"#
        ),
        "request.connect.remote.route is not accepted: 'C' at byte 0 is not allowed here"
    );
    assert!(matches!(miss, Miss::Text(_)));
    assert_eq!(said("[1]"), "the value should be an object");
    assert_eq!(
        said(r#"{"id":"1","request":"status"}"#),
        "id should be a number"
    );
    assert_eq!(
        said(r#"{"id":1,"request":{"pause":1}}"#),
        "request.pause should be a word, or an object with one key"
    );
    assert_eq!(
        said(
            r#"{"id":1,"request":{"connect":{"remote":{"route":1,"address":"a"},"with":[],"acknowledged":[]}}}"#
        ),
        "request.connect.remote.route should be a string"
    );
    assert_eq!(
        said(
            r#"{"id":1,"request":{"connect":{"remote":{"route":"coder","address":"a"},"with":{},"acknowledged":[]}}}"#
        ),
        "request.connect.with should be a list"
    );
    assert_eq!(said(r#"{"id":1}"#), "the value has no request");
    assert_eq!(
        said(r#"{"id":1,"request":"reboot"}"#),
        "request has \"reboot\", which is not known here"
    );
    assert_eq!(
        said(r#"{"id":-1,"request":"status"}"#),
        "id is out of range"
    );
    assert_eq!(said("{"), "the text ends inside a value at byte 1");
    assert_eq!(
        said(&" ".repeat(FRAME + 1)),
        format!("{} bytes is over the limit of {FRAME}", FRAME + 1)
    );
}

/// The shipped catalogue is a document in the same form a person's own
/// definitions take, and it is already in its canonical layout.
#[test]
fn the_shipped_catalogue_loads_and_is_canonical() {
    let text = include_str!("../data/catalogue.json").replace("\r\n", "\n");
    let reference: Reference = read(&text).expect("the catalogue reads");
    assert_eq!(page(&reference), text);
    let catalogue = Catalogue::shipped().expect("the catalogue is valid");
    assert_eq!(catalogue.reference().capabilities.len(), 14);
    assert_eq!(catalogue.reference().platforms.len(), 7);
    assert_eq!(catalogue.reference().routes.len(), 2);
}

/// A document is exported as a page a person can read and compare, and the
/// page reads back to the same document.
#[test]
fn a_document_round_trips_as_a_page() {
    let document = corpus::document();
    let text = page(&document);
    assert!(text.starts_with("{\n  \"version\": 2,\n  \"capabilities\": [\n"));
    let back: Document = read(&text).expect("the page reads");
    assert_eq!(back, document);
    assert_eq!(page(&back), text);
}

/// An answer to a prompt has to cross the channel, and crosses nothing else:
/// it is in the frame, not in anything printed for a person or a log.
#[test]
fn a_secret_is_in_its_frame_and_in_nothing_printed() {
    let frames = corpus::to_core();
    let answer = frames
        .iter()
        .find(|frame| matches!(frame.request, Request::Answer { .. }))
        .expect("an answer");
    assert!(line(answer).contains(r#"correct horse \"battery\""#));
    assert!(!format!("{answer:?}").contains("horse"));
}

#[test]
fn an_entry_is_one_line_of_the_trail() {
    let entry: Entry = read(
        r#"{"seq":1,"at":1790000000001,"tick":10,"event":{"started":{"version":"0.2.0 (v0.2.0)","origin":{"process":4200,"logon":65470465,"session":2,"integrity":"medium"},"after":null}}}"#,
    )
    .expect("an entry");
    assert_eq!(&entry, corpus::entries().first().expect("an entry"));
}

/// What a grant lends is written as the serials it names - none as an
/// empty list - or as `"every"`; a list naming one serial twice, a word other
/// than `"every"` and a serial no server could give are each refused.
#[test]
fn what_a_grant_lends_is_its_serials_or_every() {
    assert_eq!(both_ways(&Lends::none()), "[]");
    assert_eq!(both_ways(&Lends::Every), r#""every""#);
    assert_eq!(
        both_ways(&corpus::lent()),
        r#"["192.168.1.20:5555","R5CT1234ABC","emulator-5554"]"#
    );
    let miss = |text: &str| match read::<Lends>(text).expect_err("refused") {
        WireError::Fault(fault) => fault.miss,
        other => panic_with(text, &other),
    };
    assert_eq!(miss(r#"["emulator-5554","emulator-5554"]"#), Miss::Repeated);
    assert_eq!(miss(r#""all""#), Miss::Unknown("all".to_owned()));
    assert!(matches!(miss(r#"[""]"#), Miss::Text(TextError::Empty)));
    assert!(matches!(
        miss(r#"["tab\there"]"#),
        Miss::Text(TextError::Character { .. })
    ));
}
