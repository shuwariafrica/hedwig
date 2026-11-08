//! Every setting as the window shows it: where its value comes from, what
//! holds it, and what the person changes there.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU32;

use hedwig_model::capability::Exposure;
use hedwig_model::config::{Activation, Change};
use hedwig_model::install::{AtSignIn, Starts};
use hedwig_model::organisation::Limit;
use hedwig_model::organisation::Part;
use hedwig_model::policy::{KeyName, Keys};
use hedwig_model::protocol::Request;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::setting::{
    Autostart, Burst, CapScope, Diagnostics, Keep, Keepalive, Lengths, Longest, Threshold,
};
use hedwig_model::text::{Fingerprint, Grip, Name, Serial, Words};
use hedwig_model::trail::{Card, Event as Happened, Held, Key, Keyring, Touch, Uses};
use hedwig_view::act::Act;
use hedwig_view::exposure::Shown;
use hedwig_view::link::{Event, Place};
use hedwig_view::setting::{Invalid, Setting, Sheet, Wide};
use hedwig_view::words::Keyrings;

mod common;
use common::Bench;
use common::support::{grant, remote, terms};

fn host() -> RemoteId {
    remote("ssh", "build.example")
}

/// A core that knows one host, with gpg granted to it and its channel up,
/// and the window open.
fn bench() -> Bench {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    wish(
        &mut bench,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(host())),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        }),
    );
    bench.desk.channel_up(&host(), "linux");
    bench.feed(Event::Wish(
        Place::Window,
        Request::Settings {
            remotes: vec![host()],
        },
    ));
    bench
}

fn wish(bench: &mut Bench, request: Request) {
    bench.feed(Event::Wish(Place::Window, request));
    assert_eq!(bench.seen().refused, None);
}

fn sheet(bench: &Bench) -> Sheet {
    let seen = bench.seen();
    Sheet::of(
        seen.settings.as_deref().expect("settings were told"),
        seen.document.as_ref(),
        seen.catalogue.as_ref(),
        seen.keyrings(),
    )
}

fn named<'a>(settings: &'a [Setting], name: &str) -> &'a Setting {
    settings
        .iter()
        .find(|setting| setting.name == name)
        .unwrap_or_else(|| unreachable!("no setting {name}"))
}

fn remote_settings(sheet: &Sheet) -> &[Setting] {
    &sheet
        .remotes
        .iter()
        .find(|section| section.of == host())
        .expect("the host's settings")
        .settings
}

/// Takes the act a label stands for, as the window does when it is chosen.
fn act(shown: Option<&Shown>) -> &Act {
    match shown {
        Some(Shown::Offered { act, .. }) => act,
        other => unreachable!("not offered: {other:?}"),
    }
}

fn request(act: &Act) -> Request {
    match act {
        Act::Send(request) | Act::Confirm { request, .. } => common::clone(request),
        other => unreachable!("not a request: {other:?}"),
    }
}

#[test]
fn every_value_says_whose_statement_it_is_and_what_ships() {
    let bench = bench();
    let sheet = sheet(&bench);
    let lengths = named(
        &sheet.workstation,
        "The lengths a card offers for allowing for a time",
    );
    assert_eq!(lengths.value, "1 minute, 15 minutes, 1 hour");
    assert_eq!(lengths.said, "what Hedwig ships");
    assert_eq!(lengths.clear, None, "nothing of the person's to take away");
    let start = named(&sheet.workstation, "Starting Hedwig when you sign in");
    assert_eq!(
        (start.value.as_str(), start.said.as_str()),
        ("off", "what Hedwig ships")
    );

    let remote = remote_settings(&sheet);
    let names: Vec<&str> = remote.iter().map(|setting| setting.name).collect();
    // The eleven settings less the workstation's two and the route's
    // cadence, each condition's loudness its own: every one is here.
    for wanted in [
        "When requests from here are a burst",
        "A request served without asking",
        "Readiness failing",
        "A channel stopped that only you can fix",
        "A host presenting another key",
        "A refusal you did not make",
        "A held request's card over an application that fills the screen",
        "The longest an allowance from a card may last",
        "How a dead link is noticed",
        "The waits before a lost channel is opened again",
    ] {
        assert!(names.contains(&wanted), "{wanted} missing from {names:?}");
    }
    assert!(
        remote
            .iter()
            .all(|setting| setting.said == "what Hedwig ships"
                || setting.name == "The longest an allowance from a card may last"),
        "{remote:?}"
    );
}

#[test]
fn a_statement_made_in_the_window_is_the_persons_and_can_be_taken_away() {
    let mut bench = bench();
    let sheet = sheet(&bench);
    let burst = named(
        remote_settings(&sheet),
        "When requests from here are a burst",
    );
    // No rate is invented: nothing is a burst until the person says so.
    assert_eq!(burst.value, "never: volume from here is the work");
    assert!(burst.choices.is_empty(), "never is what is in force");
    let entry = burst.entry.clone().expect("typed");
    let made = entry
        .act(
            &["10", "60"],
            Wide::This,
            bench.seen().document.as_ref(),
            bench.seen().catalogue.as_ref(),
            Keyrings::default(),
        )
        .unwrap();
    let made = request(act(Some(&made)));
    assert_eq!(
        made,
        Request::Change(Change::Burst {
            remotes: Remotes::One(host()),
            threshold: Some(Threshold::At(Burst {
                requests: 10.try_into().unwrap(),
                seconds: 60.try_into().unwrap(),
            })),
        })
    );
    wish(&mut bench, made);

    let sheet = self::sheet(&bench);
    let burst = named(
        remote_settings(&sheet),
        "When requests from here are a burst",
    );
    assert_eq!(burst.value, "10 requests within 1 minute");
    assert_eq!(burst.said, "your statement for build.example (ssh)");
    assert!(
        burst.choices.iter().any(
            |choice| matches!(choice, Shown::Offered { label, .. } if label.starts_with("Never"))
        ),
        "{:?}",
        burst.choices
    );
    let cleared = request(act(burst.clear.as_ref()));
    assert_eq!(
        cleared,
        Request::Change(Change::Burst {
            remotes: Remotes::One(host()),
            threshold: None,
        })
    );
    wish(&mut bench, cleared);
    let sheet = self::sheet(&bench);
    let burst = named(
        remote_settings(&sheet),
        "When requests from here are a burst",
    );
    assert_eq!(burst.said, "what Hedwig ships");
}

#[test]
fn the_organisations_starting_point_is_said_as_its_own() {
    let mut bench = bench();
    let line = hedwig_model::wire::line(&Change::Autostart(Some(Autostart::AtLogon)));
    bench.govern(&[(Part::Start, line)]);
    let sheet = sheet(&bench);
    let start = named(&sheet.workstation, "Starting Hedwig when you sign in");
    assert_eq!(start.value, "on");
    assert_eq!(
        start.said,
        "your organisation's starting point for this machine, for this workstation"
    );
    // The person's own statement replaces it, and is theirs to take away.
    wish(&mut bench, request(act(start.choices.first())));
    let sheet = self::sheet(&bench);
    let start = named(&sheet.workstation, "Starting Hedwig when you sign in");
    assert_eq!(
        (start.value.as_str(), start.said.as_str()),
        ("off", "your statement for this workstation")
    );
    assert!(start.clear.is_some());
}

#[test]
fn a_typed_setting_is_made_at_the_width_chosen_or_refused_with_why() {
    let bench = bench();
    let sheet = sheet(&bench);
    let keep = named(remote_settings(&sheet), "How a dead link is noticed")
        .entry
        .clone()
        .expect("typed");
    assert_eq!(
        keep.fields.first().map(|field| field.1.as_str()),
        Some("15"),
        "starts from what is in force"
    );
    assert_eq!(
        keep.act(&["abc", "3"], Wide::This, None, None, Keyrings::default()),
        Err(Invalid::Number {
            field: "Seconds of silence before asking",
            least: 1,
            most: 65535,
        })
    );
    assert_eq!(
        keep.act(&["20", "0"], Wide::This, None, None, Keyrings::default()),
        Err(Invalid::Number {
            field: "Questions unanswered before giving up",
            least: 1,
            most: 255,
        })
    );
    let made = keep.act(
        &["20", "3"],
        Wide::Every,
        bench.seen().document.as_ref(),
        bench.seen().catalogue.as_ref(),
        Keyrings::default(),
    );
    let Ok(Shown::Offered { label, act: every }) = made else {
        unreachable!("{made:?}")
    };
    assert_eq!(label, "Set for every remote");
    assert_eq!(
        request(&every),
        Request::Change(Change::Keepalive {
            remotes: Remotes::Every,
            keepalive: Some(Keepalive {
                every: 20.try_into().unwrap(),
                missed: 3.try_into().unwrap(),
            }),
        })
    );

    let lengths = named(
        &sheet.workstation,
        "The lengths a card offers for allowing for a time",
    )
    .entry
    .clone()
    .expect("typed");
    assert_eq!(
        lengths.fields.first().map(|field| field.1.as_str()),
        Some("1m, 15m, 1h")
    );
    let made = lengths
        .act(&["30s, 2m,1h"], Wide::This, None, None, Keyrings::default())
        .unwrap();
    let expected: Lengths = [30, 120, 3600].into_iter().collect();
    assert_eq!(
        request(act(Some(&made))),
        Request::Change(Change::Lengths(Some(expected)))
    );
    assert_eq!(
        lengths.act(&[" , "], Wide::This, None, None, Keyrings::default()),
        Err(Invalid::NoLength)
    );
    assert_eq!(
        lengths.act(&["5x"], Wide::This, None, None, Keyrings::default()),
        Err(Invalid::Length("5x".to_owned()))
    );
}

#[test]
fn raising_a_cap_is_put_to_the_person_and_lowering_it_is_not() {
    let mut bench = bench();
    let minute = NonZeroU32::new(60).unwrap();
    wish(
        &mut bench,
        Request::Change(Change::Cap {
            scope: CapScope {
                remotes: Remotes::One(host()),
                key: Keys::Every,
            },
            longest: Some(Longest::Seconds(minute)),
        }),
    );
    let sheet = sheet(&bench);
    let cap = named(
        remote_settings(&sheet),
        "The longest an allowance from a card may last",
    );
    assert_eq!(cap.value, "1 minute");
    assert_eq!(
        cap.holds,
        ["you cap an allowance at 1 minute for build.example (ssh)"]
    );
    let document = bench.seen().document.as_ref();
    let vocabulary = bench.seen().catalogue.as_ref();
    let entry = cap.entry.clone().expect("typed");
    let raised = entry
        .act(
            &["3600", "0"],
            Wide::This,
            document,
            vocabulary,
            Keyrings::default(),
        )
        .unwrap();
    assert!(
        matches!(&raised, Shown::Offered { label, act: Act::Confirm { consequence, .. } }
            if label == "Cap for build.example (ssh)..." && consequence.contains("1 hour")),
        "{raised:?}"
    );
    let lowered = entry
        .act(
            &["30", "0"],
            Wide::This,
            document,
            vocabulary,
            Keyrings::default(),
        )
        .unwrap();
    assert!(
        matches!(
            lowered,
            Shown::Offered {
                act: Act::Send(_),
                ..
            }
        ),
        "{lowered:?}"
    );
    assert!(
        matches!(
            &cap.clear,
            Some(Shown::Offered {
                act: Act::Confirm { .. },
                ..
            })
        ),
        "taking the person's cap away lets more through: {:?}",
        cap.clear
    );
    assert_eq!(
        entry.act(
            &["30", "99"],
            Wide::This,
            document,
            vocabulary,
            Keyrings::default()
        ),
        Err(Invalid::Key)
    );
}

/// A cap is for every key, every key that needs no touch,
/// or one key the workstation offers or a card holds, chosen by name: a
/// primary key naming its subkeys too, a subkey alone, a card's key no
/// keyring offers by its keygrip. What is made names the key as chosen.
#[test]
fn a_caps_key_is_chosen_by_name_from_what_the_workstation_offers() {
    let mut bench = bench();
    let grip = |text: &str| Grip::try_from(text).unwrap();
    let fingerprint = |text: &str| Fingerprint::try_from(text).unwrap();
    let primary = fingerprint("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2");
    let subkey = fingerprint("5A6B7C8D9E0F1A20E5D4B6E1A2C3F40516273849");
    bench.desk.trail.push(Happened::Offered {
        capability: Name::try_from("gpg").unwrap(),
        keyring: Keyring {
            keys: vec![
                Key {
                    ssh: None,
                    grip: grip("AA11BB22CC33DD44EE55FF6600771188992233AA"),
                    fingerprint: primary.clone(),
                    primary: primary.clone(),
                    uses: Uses::SIGN,
                    user: Some(Words::try_from("Dev Builder <dev@example.org>").unwrap()),
                    card: None,
                },
                Key {
                    ssh: None,
                    grip: grip("BB22CC33DD44EE55FF6600771188992233AA11BB"),
                    fingerprint: subkey.clone(),
                    primary: primary.clone(),
                    uses: Uses::AUTHENTICATE,
                    user: Some(Words::try_from("Dev Builder <dev@example.org>").unwrap()),
                    card: None,
                },
            ],
            signing: None,
        },
    });
    bench.desk.trail.push(Happened::Card(Card {
        serial: Serial::try_from("D2760001240103040006123456780000").unwrap(),
        keys: vec![Held {
            grip: grip("CC33DD44EE55FF6600771188992233AA11BB22CC"),
            touch: Some(Touch::On),
        }],
        pin: None,
    }));
    // The workstation's keys are read again when the core says they changed.
    bench.told();
    bench.feed(Event::Wish(
        Place::Window,
        Request::Settings {
            remotes: vec![host()],
        },
    ));
    let sheet = sheet(&bench);
    let entry = named(
        remote_settings(&sheet),
        "The longest an allowance from a card may last",
    )
    .entry
    .clone()
    .expect("typed");
    assert_eq!(entry.fields.len(), 1, "only the longest is typed");
    let choice = entry.choice.clone().expect("the keys are chosen");
    assert_eq!(
        choice.options,
        [
            "Every key",
            "Every key that needs no touch",
            "Key 0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2 (Dev Builder <dev@example.org>) and \
             its subkeys",
            "Subkey 5A6B7C8D9E0F1A20E5D4B6E1A2C3F40516273849 (Dev Builder <dev@example.org>)",
            "The key with keygrip CC33DD44EE55FF6600771188992233AA11BB22CC, which is not among \
             the keys this workstation's GnuPG offers",
        ]
    );
    assert_eq!(choice.chosen, 0, "every key, until the person chooses");
    assert_eq!(entry.now(), ["", "0"]);
    let keyrings = bench.seen().keyrings();
    let document = bench.seen().document.as_ref();
    let vocabulary = bench.seen().catalogue.as_ref();
    for (at, key) in [
        ("1", Keys::NeedingNoTouch),
        ("2", Keys::Only(KeyName::Fingerprint(primary))),
        ("3", Keys::Only(KeyName::Fingerprint(subkey))),
        (
            "4",
            Keys::Only(KeyName::Grip(grip(
                "CC33DD44EE55FF6600771188992233AA11BB22CC",
            ))),
        ),
    ] {
        let made = entry
            .act(&["900", at], Wide::This, document, vocabulary, keyrings)
            .unwrap();
        assert_eq!(
            request(act(Some(&made))),
            Request::Change(Change::Cap {
                scope: CapScope {
                    remotes: Remotes::One(host()),
                    key,
                },
                longest: Some(Longest::Seconds(NonZeroU32::new(900).unwrap())),
            })
        );
    }
}

/// Hedwig and its icon each start at sign-in by a statement of their own,
/// each saying that Windows' own switch can also turn it off.
#[test]
fn hedwig_and_its_icon_start_at_sign_in_each_by_its_own_statement() {
    let mut bench = bench();
    let sheet = sheet(&bench);
    let icon = named(
        &sheet.workstation,
        "Starting Hedwig's icon when you sign in",
    );
    assert_eq!(
        (icon.value.as_str(), icon.said.as_str()),
        ("off", "what Hedwig ships")
    );
    for start in [
        "Starting Hedwig when you sign in",
        "Starting Hedwig's icon when you sign in",
    ] {
        let beside = named(&sheet.workstation, start).beside.as_deref();
        assert!(
            beside.is_some_and(|beside| beside.starts_with("Windows' own Startup apps settings")),
            "{beside:?}"
        );
    }
    let chosen = request(act(icon.choices.first()));
    assert_eq!(
        chosen,
        Request::Change(Change::Icon(Some(Autostart::AtLogon)))
    );
    wish(&mut bench, chosen);
    let sheet = self::sheet(&bench);
    let icon = named(
        &sheet.workstation,
        "Starting Hedwig's icon when you sign in",
    );
    assert_eq!(
        (icon.value.as_str(), icon.said.as_str()),
        ("on", "your statement for this workstation")
    );
    assert_eq!(
        request(act(icon.clear.as_ref())),
        Request::Change(Change::Icon(None))
    );
}

/// How long activity is kept and what is written for a supporter: each says
/// whose statement it is and what it costs, and what holds it where an
/// organisation's limit moved it.
#[test]
fn keep_and_diagnostics_say_whose_and_what_holds_them() {
    let mut bench = bench();
    let sheet = sheet(&bench);
    let keep = named(&sheet.workstation, "How long Hedwig keeps what happened");
    assert_eq!(
        (keep.value.as_str(), keep.said.as_str()),
        ("30 days", "what Hedwig ships")
    );
    assert!(
        keep.beside
            .as_deref()
            .is_some_and(|beside| beside.contains("the newest 100,000 entries")),
        "{:?}",
        keep.beside
    );
    let entry = keep.entry.clone().expect("typed");
    assert_eq!(entry.now(), vec!["30".to_owned()]);
    let typed = |typed: &str| {
        entry.act(
            &[typed],
            Wide::This,
            bench.seen().document.as_ref(),
            bench.seen().catalogue.as_ref(),
            Keyrings::default(),
        )
    };
    assert_eq!(
        typed("0"),
        Err(Invalid::Number {
            field: "Days",
            least: 1,
            most: 65535
        })
    );
    let seven = request(act(Some(&typed("7").unwrap())));
    assert_eq!(
        seven,
        Request::Change(Change::Keep(Some(Keep(7.try_into().unwrap()))))
    );
    wish(&mut bench, seven);

    let written = named(
        &sheet.workstation,
        "What Hedwig writes down for a supporter",
    );
    assert_eq!(
        (written.value.as_str(), written.said.as_str()),
        ("what went wrong", "what Hedwig ships")
    );
    let offered: Vec<Request> = written
        .choices
        .iter()
        .map(|choice| request(act(Some(choice))))
        .collect();
    assert_eq!(
        offered,
        [Diagnostics::Off, Diagnostics::Detail]
            .map(|level| Request::Change(Change::Diagnostics(Some(level))))
    );
    wish(&mut bench, common::clone(offered.last().unwrap()));

    // The organisation keeps at least fourteen days and has nothing written
    // past what went wrong: both hold the person's statements, which stand.
    let limits = [
        Limit::KeepAtLeast(Keep(14.try_into().unwrap())),
        Limit::DiagnosticsAtMost(Diagnostics::Faults),
    ]
    .map(|limit| (Part::Limits, hedwig_model::wire::line(&limit)));
    bench.govern(&limits);
    let sheet = self::sheet(&bench);
    let held = "your organisation's limits for this machine".to_owned();
    let keep = named(&sheet.workstation, "How long Hedwig keeps what happened");
    assert_eq!(
        (keep.value.as_str(), keep.said.as_str()),
        ("14 days", "your statement for this workstation")
    );
    assert_eq!(keep.holds, vec![held.clone()]);
    let written = named(
        &sheet.workstation,
        "What Hedwig writes down for a supporter",
    );
    assert_eq!(
        (written.value.as_str(), written.said.as_str()),
        ("what went wrong", "your statement for this workstation")
    );
    assert_eq!(written.holds, vec![held]);
}

/// A start-up choice says what Windows starts at sign-in where that is
/// not what the choice says: another program under Hedwig's name, an icon
/// not installed here, or why the value could not be kept - and nothing
/// before the core has kept the choice in this run, or where Windows does as
/// chosen.
#[test]
fn what_windows_starts_at_sign_in_is_said_beside_each_choice_where_it_differs() {
    let mut bench = bench();
    let instead =
        |bench: &Bench, name: &str| named(&sheet(bench).workstation, name).instead.clone();
    let hedwig = "Starting Hedwig when you sign in";
    let icon = "Starting Hedwig's icon when you sign in";
    assert_eq!(instead(&bench, hedwig), None, "not yet kept in this run");

    let found = [
        (Starts::Hedwig, AtSignIn::AsChosen),
        (
            Starts::Icon,
            AtSignIn::Another(Some(
                Words::try_from(r#""C:\Tools\hedwig-0.1.0\hedwig.exe" tray"#).unwrap(),
            )),
        ),
    ];
    for (starts, found) in found {
        bench.desk.trail.push(Happened::Startup { starts, found });
    }
    bench.told();
    assert_eq!(instead(&bench, hedwig), None, "as chosen");
    assert_eq!(
        instead(&bench, icon).as_deref(),
        Some(
            r#"When you sign in, Windows starts another program under the name of Hedwig's icon, which Hedwig leaves as it is: "C:\Tools\hedwig-0.1.0\hedwig.exe" tray"#
        )
    );

    for (starts, found) in [
        (Starts::Icon, AtSignIn::Absent),
        (
            Starts::Hedwig,
            AtSignIn::Unkept(Words::try_from("Windows refused to write the value").unwrap()),
        ),
    ] {
        bench.desk.trail.push(Happened::Startup { starts, found });
        bench.told();
    }
    assert_eq!(
        instead(&bench, icon).as_deref(),
        Some("Hedwig's icon is not installed here, so Windows starts nothing for it.")
    );
    assert_eq!(
        instead(&bench, hedwig).as_deref(),
        Some("Hedwig could not set this with Windows: Windows refused to write the value.")
    );
    bench.desk.trail.push(Happened::Startup {
        starts: Starts::Icon,
        found: AtSignIn::Another(None),
    });
    bench.told();
    assert_eq!(
        instead(&bench, icon).as_deref(),
        Some(
            "When you sign in, Windows starts another program under the name of Hedwig's icon, \
             which Hedwig leaves as it is."
        )
    );
}

/// A choice of what is written down made for this run - a supporter's
/// request, at the command line - is said as the run's, holds until Hedwig
/// next starts, and is ended from the window in one act; the workstation's
/// choices come back with it.
#[test]
fn a_runs_own_diagnostics_are_said_as_the_runs_and_ended_in_one_act() {
    let mut bench = bench();
    let terminal = bench.desk.attend(
        hedwig_model::trail::ClientKind::Terminal,
        common::support::DESKTOP,
    );
    bench
        .desk
        .send(terminal, Request::Diagnose(Some(Diagnostics::Detail)))
        .unwrap();
    bench.told();
    let sheet_now = sheet(&bench);
    let setting = named(
        &sheet_now.workstation,
        "What Hedwig writes down for a supporter",
    );
    assert_eq!(
        (setting.value.as_str(), setting.said.as_str()),
        (
            "what went wrong, and everything a channel's client says",
            "your choice for this run"
        )
    );
    assert!(
        setting
            .beside
            .as_deref()
            .is_some_and(|beside| beside.starts_with(
                "It holds until Hedwig next starts; then your choice for this workstation decides."
            )),
        "{:?}",
        setting.beside
    );
    assert_eq!(
        setting.clear, None,
        "no statement for this workstation is shown"
    );
    let only: Vec<Request> = setting
        .choices
        .iter()
        .map(|choice| request(act(Some(choice))))
        .collect();
    assert_eq!(only, [Request::Diagnose(None)]);

    wish(&mut bench, Request::Diagnose(None));
    let sheet_after = sheet(&bench);
    let setting = named(
        &sheet_after.workstation,
        "What Hedwig writes down for a supporter",
    );
    assert_eq!(
        (setting.value.as_str(), setting.said.as_str()),
        ("what went wrong", "what Hedwig ships")
    );
    assert_eq!(setting.choices.len(), 2, "the workstation's two others");
}
