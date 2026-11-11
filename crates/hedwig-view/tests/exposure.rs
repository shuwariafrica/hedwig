//! The window: what is reachable from where, what each line offers, and the
//! first grant when nothing is granted.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Instant;

use std::collections::BTreeSet;

use hedwig_model::capability::{Exposure, Home, Lends, Operation, Setup};
use hedwig_model::config::{Activation, Change};
use hedwig_model::holder::{Rights, SignedIn, SourceHolder, StoppedPipe, Whose};
use hedwig_model::policy::{ConnectionScope, KeyName, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{Notice, Request, Row, Topic};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::text::{
    AgentPipe, Fingerprint, Grip, Location, Mark, RemotePath, Serial, ServiceName, TextError, Words,
};
use hedwig_model::trail::{
    self, Card, ChannelEnd, ClientKind, Entry, Event as Happened, Failure, Finding, Health, Held,
    Icon, Missing, PromptKind, Readiness, SignaturePin, State, Touch,
};
use hedwig_view::act::Act;
use hedwig_view::exposure::{self, Board, Line, Shown, Window};
use hedwig_view::grant::{self, Aim, Draft, Field, Owed};
use hedwig_view::link::{Core, Event, Link, Place, Seen};
use hedwig_view::words::Keyrings;

mod common;
use common::support::{grant as granted, name, pattern, remote, terms};
use common::{Bench, clock};

fn workspace() -> RemoteId {
    remote("coder", "dev/build")
}

fn host() -> RemoteId {
    remote("ssh", "build.example")
}

fn refresh(bench: &mut Bench) {
    for topic in [
        Topic::Status,
        Topic::Exposure,
        Topic::Attention,
        Topic::Workstation,
    ] {
        bench.notice(Notice::Stale(topic));
    }
}

fn wish(bench: &mut Bench, request: Request) {
    bench.feed(Event::Wish(Place::Window, request));
}

fn grants(bench: &mut Bench, id: &str, remotes: Granted, acknowledged: Exposure) {
    wish(
        bench,
        Request::Change(Change::Grant {
            grant: granted(id, remotes),
            terms: terms(Activation::OnRequest, acknowledged),
        }),
    );
    assert_eq!(bench.seen().refused, None);
}

fn window(bench: &Bench) -> Window {
    Window::of(bench.link.seen(), &clock, Instant::now())
}

fn lines(window: &Window) -> Vec<&Line> {
    match &window.board {
        Board::Exposure { groups, .. } => groups.iter().flat_map(|group| &group.lines).collect(),
        other => unreachable!("{other:?}"),
    }
}

fn line<'a>(window: &'a Window, remote: &RemoteId, capability: &str) -> &'a Line {
    lines(window)
        .into_iter()
        .find(|line| line.remote.as_ref() == Some(remote) && line.capability.as_str() == capability)
        .expect("a line")
}

/// Every request a shown act would send.
fn requests(shown: &[Shown]) -> Vec<(&str, &Request)> {
    shown
        .iter()
        .filter_map(|shown| match shown {
            Shown::Offered {
                label,
                act: Act::Send(request) | Act::Confirm { request, .. },
            } => Some((label.as_str(), request)),
            _ => None,
        })
        .collect()
}

/// A person has just installed Hedwig. With nothing granted, the window is what
/// this workstation has and a first grant made ready from it - and until the
/// core has said what that is, the window says it is asking.
#[test]
fn with_nothing_granted_the_window_is_the_first_grant() {
    let mut bench = Bench::attached();
    // Attached, the window not yet told what the workstation has.
    match window(&bench).board {
        Board::First(first) => {
            assert_eq!(first.has, None);
            assert_eq!(first.draft, Draft::default());
        }
        other => unreachable!("{other:?}"),
    }

    for (capability, health) in [
        ("gpg", Health::Sound),
        ("gpg-unrestricted", Health::Sound),
        ("ssh-agent", Health::Failing(Failure::Unreachable)),
    ] {
        bench.desk.trail.push(Happened::Source {
            capability: name(capability),
            health,
        });
    }
    bench.desk.trail.push(Happened::Card(Card {
        serial: Serial::try_from("D2760001240103040006123456780000").unwrap(),
        keys: vec![Held {
            grip: Grip::try_from("AA11BB22CC33DD44EE55FF6600771188992233AA").unwrap(),
            touch: Some(Touch::Off),
        }],
        pin: Some(SignaturePin::Once),
    }));
    bench.desk.trail.push(Happened::Appeared {
        remote: workspace(),
    });
    bench.feed(Event::Window(true));
    refresh(&mut bench);

    let Board::First(first) = window(&bench).board else {
        unreachable!()
    };
    assert_eq!(
        first.has.unwrap(),
        [
            "gpg answers on this workstation.",
            "gpg-unrestricted answers on this workstation.",
            "Nothing answers for ssh-agent on this workstation.",
            "dev/build (coder) is running",
        ]
    );
    // The cards apart, since no read says which is in.
    assert_eq!(
        first.cards,
        [
            "On card 12 345 678, the key with keygrip AA11BB22CC33DD44EE55FF6600771188992233AA \
             needs no touch; the PIN is asked once, not for each signature. A remote you grant \
             can then use a key that needs no touch with nobody at the card, and Hedwig's own \
             asking is the only check. With touch required, you cannot sign while you are away \
             from this machine."
        ]
    );
    // The least exposing capability whose own side answers, to the route a
    // running remote is on, for as long as one runs. Consent to write, and
    // what the grant exposes, are never filled in for the person.
    assert_eq!(
        first.draft,
        Draft {
            capability: Some(name("gpg")),
            aim: Aim::Route,
            route: Some(name("coder")),
            typed: String::new(),
            remotes: Some(Granted::Route(name("coder"))),
            activation: Some(Activation::WhileRunning),
            setup: Setup::Inspect,
            lends: Lends::none(),
            acknowledged: Exposure::NONE,
            hosts: std::collections::BTreeMap::new(),
        }
    );

    // Made as it stands, it is one act, and the window becomes what is
    // exposed: first run is never a place of its own.
    let attached = bench.seen();
    let change = first
        .draft
        .change(
            attached.catalogue.as_ref().unwrap().reference(),
            attached.document.as_ref().unwrap(),
        )
        .unwrap();
    wish(&mut bench, Request::Change(change));
    let shown = window(&bench);
    let made = line(&shown, &workspace(), "gpg");
    assert_eq!(made.state, "not connected");
    assert_eq!(made.through, "granted: gpg to every remote on coder");
    assert_eq!(
        made.exposes,
        "use your keys to sign, decrypt and authenticate"
    );
}

/// With nothing on the workstation answering and nothing running, the first
/// grant is left for the person to fill: nothing is made up for them.
#[test]
fn a_workstation_with_nothing_found_prefills_nothing() {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    let Board::First(first) = window(&bench).board else {
        unreachable!()
    };
    assert_eq!(first.has, Some(Vec::new()));
    assert_eq!(first.draft, Draft::default());
    let attached = bench.seen();
    assert_eq!(
        first.draft.change(
            attached.catalogue.as_ref().unwrap().reference(),
            attached.document.as_ref().unwrap()
        ),
        Err(Owed::Capability)
    );
}

/// A grant names what it exposes before it can be asked of the core,
/// the form asks for it with the model's own function, and the core's
/// refusal - were the form wrong - lands on the field it concerns.
#[test]
fn a_grant_says_what_it_exposes_before_it_is_asked() {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    let attached = bench.seen();
    let (reference, document) = (
        attached.catalogue.as_ref().unwrap().reference().clone(),
        attached.document.clone().unwrap(),
    );

    let mut draft = Draft {
        capability: Some(name("adb")),
        ..Draft::default()
    };
    assert_eq!(draft.exposes(&reference, &document), Exposure::SERVICE);
    assert_eq!(draft.change(&reference, &document), Err(Owed::Remotes));
    draft.remotes = Some(grant::named(&name("ssh"), "build.example").unwrap());
    assert_eq!(draft.remotes, Some(Granted::One(host())));
    assert_eq!(draft.change(&reference, &document), Err(Owed::Activation));

    // A plain SSH host cannot be seen starting and stopping, so following
    // its life is not offered.
    assert_eq!(
        draft.activations(&reference),
        [Activation::OnRequest, Activation::Continuous]
    );
    draft.activation = Some(Activation::OnRequest);
    let owed = draft.change(&reference, &document).unwrap_err();
    assert_eq!(owed, Owed::Acknowledgement(Exposure::SERVICE));
    assert_eq!(owed.field(), Field::Acknowledged);
    draft.acknowledged = Exposure::SERVICE;
    let change = draft.change(&reference, &document).unwrap();
    assert_eq!(bench.permits(&Request::Change(change)), Ok(()));

    // A pattern is a line with a `*`; what cannot be an address says why.
    assert_eq!(
        grant::named(&name("coder"), "team-*"),
        Ok(Granted::Matching {
            route: name("coder"),
            pattern: pattern("team-*")
        })
    );
    assert_eq!(
        grant::named(&name("ssh"), "-oProxyCommand=calc"),
        Err(TextError::LeadingHyphen)
    );
    let following = Draft {
        remotes: Some(Granted::Route(name("coder"))),
        ..Draft::default()
    };
    assert!(
        following
            .activations(&reference)
            .contains(&Activation::WhileRunning)
    );

    // The core is the authority: each refusal it can give a grant is shown
    // at the field it is about.
    let unacknowledged = Request::Change(Change::Grant {
        grant: granted("gpg-unrestricted", Granted::One(host())),
        terms: terms(Activation::OnRequest, Exposure::NONE),
    });
    wish(&mut bench, unacknowledged);
    let (_, refusal) = bench.seen().refused.clone().unwrap();
    assert_eq!(grant::blames(&refusal), Field::Acknowledged);
    assert_eq!(
        window(&bench).refused.as_deref(),
        Some(
            "granting gpg-unrestricted exposes key-management, secret, and the grant does not \
             name it"
        )
    );
    let blind = Request::Change(Change::Grant {
        grant: granted("gpg", Granted::One(host())),
        terms: terms(Activation::WhileRunning, Exposure::NONE),
    });
    wish(&mut bench, blind);
    let (_, refusal) = bench.seen().refused.clone().unwrap();
    assert_eq!(grant::blames(&refusal), Field::Activation);
    assert_eq!(
        grant::blames(&Refusal::UnknownRoute(name("nowhere"))),
        Field::Remotes
    );
}

/// A board with a line in every standing a row can have.
fn every_standing() -> Bench {
    let mut bench = Bench::attached();
    grants(
        &mut bench,
        "gpg",
        Granted::Route(name("coder")),
        Exposure::NONE,
    );
    grants(
        &mut bench,
        "gpg",
        Granted::Route(name("ssh")),
        Exposure::NONE,
    );
    grants(
        &mut bench,
        "ssh-agent",
        Granted::Route(name("ssh")),
        Exposure::NONE,
    );
    grants(
        &mut bench,
        "adb",
        Granted::Route(name("codespaces")),
        Exposure::SERVICE,
    );

    // Serving.
    bench.desk.channel_up(&workspace(), "linux");
    // Idle: named by a grant, never connected.
    grants(
        &mut bench,
        "gpg",
        Granted::One(remote("ssh", "idle.example")),
        Exposure::NONE,
    );
    // Connecting.
    bench
        .desk
        .trail
        .open(&remote("ssh", "opening.example"), "linux");
    // Waiting for the person.
    let needing = bench
        .desk
        .trail
        .open(&remote("ssh", "asking.example"), "linux");
    bench.desk.trail.push(Happened::Prompted {
        connection: needing,
        kind: PromptKind::UnknownHostKey,
        words: Words::try_from("SHA256:abc").unwrap(),
    });
    // Not ready.
    let unready = bench
        .desk
        .trail
        .open(&remote("ssh", "unready.example"), "linux");
    for capability in ["gpg", "ssh-agent"] {
        bench.desk.trail.push(Happened::Checked {
            connection: unready,
            capability: name(capability),
            readiness: Readiness::Unready(vec![
                Finding::AgentLive(agent()),
                Finding::PublicKeyAbsent(key()),
            ]),
        });
    }
    // A Windows remote: the agent has no carrier, and gpg needs a write the
    // grant does not allow.
    bench
        .desk
        .trail
        .open(&remote("ssh", "windows.example"), "windows");
    // Stopped for a reason only the person can fix.
    let ended = bench
        .desk
        .channel_up(&remote("ssh", "ended.example"), "linux");
    bench.desk.trail.push(Happened::Down {
        connection: ended,
        end: ChannelEnd::HostKeyChanged(Mark::try_from("SHA256:def").unwrap()),
    });
    // Paused.
    bench
        .desk
        .channel_up(&remote("ssh", "paused.example"), "linux");
    wish(
        &mut bench,
        Request::Pause(Remotes::One(remote("ssh", "paused.example"))),
    );
    refresh(&mut bench);
    bench
}

/// Every standing is said in its own words, and none of them is the type's.
#[test]
fn each_standing_is_said_in_its_own_words() {
    let bench = every_standing();
    let shown = window(&bench);
    let state =
        |at: &str, capability: &str| line(&shown, &remote("ssh", at), capability).state.clone();
    assert_eq!(
        line(&shown, &workspace(), "gpg").state,
        "reachable there at the socket /run/user/2000/gnupg/S.gpg-agent"
    );
    assert_eq!(state("idle.example", "gpg"), "not connected");
    assert_eq!(state("opening.example", "gpg"), "connecting");
    assert_eq!(
        state("asking.example", "gpg"),
        "waiting for a host key to confirm"
    );
    assert_eq!(
        state("unready.example", "gpg"),
        "not ready: the remote's own agent answers at /run/user/1000/gnupg/S.gpg-agent; Hedwig \
         leaves it running, and forwards there once you stop it"
    );
    assert_eq!(
        state("windows.example", "gpg"),
        "cannot be served: on a windows remote gpg works only once Hedwig may write that \
         remote's own tool configuration; the grant does not allow it"
    );
    assert_eq!(
        state("windows.example", "ssh-agent"),
        "cannot be served: a windows remote's own SSH server has no way to carry ssh-agent"
    );
    assert_eq!(
        state("ended.example", "gpg"),
        "stopped: the host presented a key it did not have before, SHA256:def"
    );
    assert_eq!(state("paused.example", "gpg"), "paused");

    let said: BTreeSet<&str> = lines(&shown)
        .iter()
        .map(|line| line.state.as_str())
        .collect();
    assert!(said.len() >= 9, "{said:?}");
    for text in said {
        assert!(
            !text.contains("::") && !text.contains('{') && !text.contains("Some("),
            "{text}"
        );
    }

    // A grant no remote has met is a line of its own, under its own heading.
    let Board::Exposure { groups, .. } = &shown.board else {
        unreachable!()
    };
    let last = groups.last().unwrap();
    assert_eq!(last.heading, "Granted, and no remote has been seen yet");
    assert_eq!(last.lines.len(), 1);
    assert_eq!(
        last.lines.first().unwrap().through,
        "granted: adb to every remote on codespaces"
    );
    assert_eq!(
        last.lines.first().unwrap().exposes,
        "reach a service that checks nobody's identity"
    );
}

/// What a line offers is what the core would carry out: the request each act
/// sends is rebuilt from the row alone and put to the gate. An act the core
/// would refuse is not a control; it is a line that says why not now.
#[test]
fn what_a_line_offers_is_what_the_core_accepts() {
    let bench = every_standing();
    let mut offered = 0;
    let mut withheld = BTreeSet::new();
    for row in bench.rows() {
        for offer in &row.acts {
            let Some(request) = exposure::request_for(row, offer.act) else {
                unreachable!("{:?} on {row:?}", offer.act)
            };
            assert_eq!(bench.permits(&request).err(), offer.withheld, "{row:?}");
        }
    }
    let shown = window(&bench);
    for line in lines(&shown) {
        let row: &Row = bench
            .rows()
            .iter()
            .find(|row| row.remote == line.remote && row.capability == line.capability)
            .unwrap();
        assert_eq!(line.acts.len(), row.acts.len());
        for (shown, offer) in line.acts.iter().zip(&row.acts) {
            match (shown, &offer.withheld) {
                (Shown::Offered { .. }, None) => offered += 1,
                (Shown::Withheld { label, why }, Some(refusal)) => {
                    assert_eq!(*why, refusal.to_string());
                    assert!(!label.ends_with("..."));
                    withheld.insert(why.clone());
                }
                other => unreachable!("{other:?}"),
            }
        }
        // And everything the line would send, the core accepts.
        for (label, request) in requests(&line.acts) {
            assert_eq!(bench.permits(request), Ok(()), "{label} on {line:?}");
        }
        for policy in &line.policy {
            for (label, request) in requests(&policy.changes) {
                assert_eq!(bench.permits(request), Ok(()), "{label} on {line:?}");
            }
        }
    }
    assert!(offered > 20, "{offered}");
    assert!(
        withheld.contains("exposure is paused")
            && withheld.contains("there is no connection to idle.example (ssh)"),
        "{withheld:?}"
    );
}

/// How a remote is decided can be changed for
/// one host from the window. Asking more of the person is carried out at
/// once; letting more through is put to them with what it lets through, and
/// serving with nobody watching says exactly that.
#[test]
fn asking_more_is_one_act_and_letting_more_through_is_confirmed() {
    let mut bench = Bench::attached();
    grants(
        &mut bench,
        "gpg",
        Granted::Route(name("coder")),
        Exposure::NONE,
    );
    let connection = bench.desk.channel_up(&workspace(), "linux");
    refresh(&mut bench);

    let shown = window(&bench);
    let signing = line(&shown, &workspace(), "gpg")
        .policy
        .iter()
        .find(|policy| policy.when == "when it asks to sign")
        .unwrap();
    assert_eq!(signing.now, "served and shown to you");
    assert_eq!(signing.because, "Hedwig's default for what this exposes");
    let scope = RuleScope {
        remotes: Remotes::One(workspace()),
        capability: Selector::Only(name("gpg")),
        operation: Selector::Only(Operation::Sign),
        key: Keys::Every,
    };
    let rule = |mode| {
        Request::Change(Change::Rule {
            scope: scope.clone(),
            mode,
        })
    };
    assert_eq!(
        signing.changes,
        [
            // The row names its connection, so asking first until it ends
            // is offered on a granted capability too.
            Shown::Offered {
                label: "Ask me first, until this connection ends".to_owned(),
                act: Act::Send(Request::Rule {
                    connection,
                    scope: ConnectionScope {
                        capability: Selector::Only(name("gpg")),
                        operation: Selector::Only(Operation::Sign),
                        key: Keys::Every,
                    },
                    mode: Some(Mode::Confirm),
                }),
            },
            Shown::Offered {
                label: "Ask me first, always for this remote".to_owned(),
                act: Act::Send(rule(Mode::Confirm)),
            },
            Shown::Offered {
                label: "Serve even while I am away, always for this remote...".to_owned(),
                act: Act::Confirm {
                    request: rule(Mode::Unattended),
                    consequence: "dev/build (coder) is served gpg when it asks to sign, even \
                                  while nothing can reach you. With a key that needs no touch, \
                                  it can then be used with nobody watching."
                        .to_owned(),
                    answer: "Serve even while I am away".to_owned(),
                },
            },
        ]
    );

    // Asked first by the person's own rule: the way back is confirmed, and
    // the rule itself can be removed.
    wish(&mut bench, rule(Mode::Confirm));
    let shown = window(&bench);
    let signing = line(&shown, &workspace(), "gpg")
        .policy
        .iter()
        .find(|policy| policy.when == "when it asks to sign")
        .unwrap();
    assert_eq!(signing.now, "held until you answer");
    assert_eq!(
        signing.because,
        "your rule for dev/build (coder): gpg, when it asks to sign"
    );
    let labels: Vec<&str> = signing
        .changes
        .iter()
        .map(|shown| match shown {
            Shown::Offered { label, act } => {
                assert!(matches!(act, Act::Confirm { .. }), "{label}");
                label.as_str()
            }
            Shown::Withheld { .. } => unreachable!(),
        })
        .collect();
    assert_eq!(
        labels,
        [
            "Serve and show me, always for this remote...",
            "Serve even while I am away, always for this remote...",
            "Remove your rule for this remote...",
        ]
    );
}

/// What needs the person is listed in the window with what they can do about
/// it there, and every one of those acts is one the core accepts.
#[test]
fn what_needs_the_person_is_listed_with_what_to_do() {
    let bench = every_standing();
    let shown = window(&bench);
    let Board::Exposure { needs, .. } = &shown.board else {
        unreachable!()
    };
    let listed: Vec<(&str, Vec<&str>)> = needs
        .iter()
        .map(|need| {
            let acts = need
                .acts
                .iter()
                .map(|shown| match shown {
                    Shown::Offered { label, .. } => label.as_str(),
                    Shown::Withheld { .. } => unreachable!(),
                })
                .collect();
            (need.sentence.as_str(), acts)
        })
        .collect();
    assert_eq!(
        listed,
        [
            (
                "Connecting to asking.example (ssh) needs a host key to confirm",
                vec!["Answer"]
            ),
            (
                "gpg is not ready on unready.example (ssh): the remote's own agent answers at \
                 /run/user/1000/gnupg/S.gpg-agent; Hedwig leaves it running, and forwards there \
                 once you stop it; and the remote's keyring lacks the public key \
                 0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2, so its gpg cannot use that key",
                vec!["Check again", "Put away"]
            ),
            (
                "ssh-agent is not ready on unready.example (ssh): the remote's own agent answers \
                 at /run/user/1000/gnupg/S.gpg-agent; Hedwig leaves it running, and forwards \
                 there once you stop it; and the remote's keyring lacks the public key \
                 0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2, so its gpg cannot use that key",
                vec!["Check again", "Put away"]
            ),
            (
                "The connection to ended.example (ssh) stopped: the host presented a key it \
                 did not have before, SHA256:def",
                vec!["Connect", "Put away"]
            ),
        ]
    );
    for need in needs {
        for (label, request) in requests(&need.acts) {
            assert_eq!(bench.permits(request), Ok(()), "{label}");
        }
    }
}

/// The last request on a line, and a remote's recent requests, are said with
/// how each ended.
#[test]
fn a_request_is_said_with_how_it_ended() {
    let mut bench = Bench::attached();
    grants(
        &mut bench,
        "gpg",
        Granted::Route(name("coder")),
        Exposure::NONE,
    );
    let connection = bench.desk.channel_up(&workspace(), "linux");
    bench.desk.asks(connection, "gpg", Operation::Sign);
    bench.desk.trail.wait(1_500);
    wish(
        &mut bench,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::Every,
                capability: Selector::Every,
                operation: Selector::Only(Operation::Decrypt),
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    );
    bench.desk.asks(connection, "gpg", Operation::Decrypt);
    refresh(&mut bench);
    // What the core answers for one remote is every entry about it, as
    // the model's own pass reads it from the trail.
    let sets = bench.desk.configuration.sets(&bench.desk.catalogue);
    let entries: Vec<Entry> = trail::about(
        &State::default(),
        &bench.desk.trail.entries,
        &workspace(),
        &sets,
    )
    .cloned()
    .collect();
    let said: Vec<String> = exposure::activity(&entries, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, text)| text)
        .filter(|text| text.contains("asked to"))
        .collect();
    assert_eq!(
        said,
        [
            "t1500: asked to decrypt with gpg - waiting for your answer",
            "t0: asked to sign with gpg - served",
        ]
    );

    // Reviewed in the window, the link asks the core for that remote alone,
    // newest first, a page at a time.
    let from = bench.sent.len();
    bench.feed(Event::Review(Some(workspace())));
    let since = bench.sent.get(from..).unwrap_or_default();
    assert!(
        since.iter().any(|frame| frame.request
            == Request::Activity {
                remote: Selector::Only(workspace()),
                before: None,
                limit: hedwig_view::link::PAGE,
            }),
        "{since:?}"
    );
    let activity = bench.seen().activity.as_ref().unwrap();
    assert_eq!(activity.remote, workspace());
    assert_ne!(activity.entries.as_ref().unwrap().as_slice(), []);
    assert!(!activity.earlier, "fewer than a page: nothing earlier");
    let from = bench.sent.len();
    bench.feed(Event::Earlier);
    assert_eq!(bench.sent.len(), from, "nothing earlier is asked for");
    bench.feed(Event::Review(None));
    assert_eq!(bench.seen().activity, None);
    let shown = window(&bench);
    assert_eq!(
        line(&shown, &workspace(), "gpg").last.as_deref(),
        Some("t1500: asked to decrypt with gpg - waiting for your answer")
    );
}

/// With no core the window says what is true and offers the one thing to do;
/// attached and not yet told, it says it is asking.
#[test]
fn the_window_without_a_core_says_what_is_true() {
    let seen = Seen { core: Core::Absent };
    assert_eq!(
        Window::of(&seen, &clock, Instant::now()).board,
        Board::Off {
            sentence: "Hedwig is not running.".to_owned(),
            act: Some(Act::Start)
        }
    );
    let seen = Seen {
        core: Core::Unreachable("every instance of the pipe is busy".to_owned()),
    };
    assert_eq!(
        Window::of(&seen, &clock, Instant::now()).board,
        Board::Off {
            sentence: "Hedwig cannot be reached: every instance of the pipe is busy.".to_owned(),
            act: Some(Act::Retry)
        }
    );
    assert_eq!(
        Window::of(
            &Seen {
                core: Core::Starting
            },
            &clock,
            Instant::now()
        )
        .board,
        Board::Off {
            sentence: "Hedwig is starting.".to_owned(),
            act: None
        }
    );

    let mut link = Link::default();
    link.handle(Event::Looked(common::serving(common::pipe('a'))));
    link.handle(Event::Opened);
    link.handle(Event::Frame(
        hedwig_model::protocol::FromCore::Reply {
            id: 1,
            reply: Ok(hedwig_model::protocol::Reply::Welcome {
                protocol: hedwig_model::protocol::PROTOCOL,
                version: "0.2.0".to_owned(),
                you: common::support::DESKTOP,
            }),
        },
        Instant::now(),
    ));
    assert_eq!(
        Window::of(link.seen(), &clock, Instant::now()).board,
        Board::Asking
    );
}

/// A rule for one key - the release key always confirmed - is a statement
/// the window makes where the core says how that key's requests are decided.
#[test]
fn a_keys_own_decision_offers_a_rule_for_that_key() {
    let mut bench = Bench::attached();
    grants(&mut bench, "gpg", Granted::One(host()), Exposure::NONE);
    let release =
        KeyName::Grip(Grip::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap());
    wish(
        &mut bench,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::Every,
                capability: Selector::Every,
                operation: Selector::Only(Operation::Sign),
                key: Keys::Only(release.clone()),
            },
            mode: Mode::Confirm,
        }),
    );
    refresh(&mut bench);
    let Board::Exposure { groups, .. } = window(&bench).board else {
        unreachable!("exposure")
    };
    let line = &groups
        .iter()
        .flat_map(|group| &group.lines)
        .find(|line| line.remote == Some(host()))
        .expect("the host's line");
    let keyed = line
        .policy
        .iter()
        .find(|policy| {
            policy.when
                == "when it asks to sign with the key with keygrip \
                    0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2, which is not among the keys this \
                    workstation's GnuPG offers"
        })
        .expect("the key's own decision");
    assert_eq!(keyed.now, "held until you answer");
    let Some(Shown::Offered { label, act }) = keyed
        .changes
        .iter()
        .find(|change| matches!(change, Shown::Offered { label, .. } if label.starts_with("Serve and show me")))
    else {
        unreachable!("{:?}", keyed.changes)
    };
    assert_eq!(label, "Serve and show me, always for this key here...");
    let Act::Confirm { request, .. } = act else {
        unreachable!("{act:?}")
    };
    assert!(
        matches!(request, Request::Change(Change::Rule { scope, .. }) if scope.key == Keys::Only(release.clone()) && scope.remotes == Remotes::One(host())),
        "{request:?}"
    );
}

/// The key the workstation offers in these suites.
fn key() -> Fingerprint {
    Fingerprint::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap()
}

/// Where the remote's own agent answers, on the remotes of these suites.
fn agent() -> RemotePath {
    RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap()
}

/// A channel coming back by itself says on its line how long until it is
/// opened again, counted down on the interface's own clock from the reply
/// that said so, and the window is told when those words next change. Once
/// due, the line says it is coming back and no longer when.
#[test]
fn a_returning_channel_counts_down_on_its_line() {
    let mut bench = Bench::attached();
    grants(&mut bench, "gpg", Granted::One(workspace()), Exposure::NONE);
    wish(
        &mut bench,
        Request::Connect {
            remote: workspace(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    );
    // Five losses before a channel settles: each wait doubles from a second.
    for _ in 0..5 {
        let up = bench.desk.channel_up(&workspace(), "linux");
        bench.desk.trail.push(Happened::Down {
            connection: up,
            end: ChannelEnd::ForwardRefused,
        });
    }
    refresh(&mut bench);
    let told = Instant::now();
    let wait = bench
        .rows()
        .iter()
        .find_map(|row| match row.standing {
            hedwig_model::protocol::Standing::Returning { wait, .. } => wait,
            _ => None,
        })
        .expect("the channel is coming back after a wait")
        .get();
    assert_eq!(wait, 16);
    let at = |after: u64| {
        Window::of(
            bench.link.seen(),
            &clock,
            told + std::time::Duration::from_secs(after),
        )
    };
    let state = |shown: &Window| line(shown, &workspace(), "gpg").state.clone();
    assert_eq!(
        state(&at(0)),
        "connecting again by itself in 16 seconds: the remote's SSH server refused the forward"
    );
    assert_eq!(
        state(&at(5)),
        "connecting again by itself in 11 seconds: the remote's SSH server refused the forward"
    );
    assert!(at(5).changes.is_some_and(|next| next.as_secs() < 1));
    assert_eq!(
        state(&at(16)),
        "connecting again by itself: the remote's SSH server refused the forward"
    );
    assert_eq!(at(16).changes, None);
    // The menu says the same of the remote, as of when it is opened.
    let menu =
        hedwig_view::glance::menu(bench.link.seen(), told + std::time::Duration::from_secs(5));
    assert!(
        format!("{menu:?}").contains("gpg: connecting again by itself in 11 seconds"),
        "{menu:?}"
    );
}

/// Every entry the core gives of one remote's activity is said for
/// the reviewer, distinct from the others and newest first: its connections
/// from their opening to their end, each request with how it ended, what the
/// remote was read as, what readiness found, a test, a prompt, an allowance,
/// a rule for that connection, a pause and a resume that covered it, and a
/// connection turned away by either relay.
#[test]
#[allow(clippy::too_many_lines, reason = "one entry of every kind")]
fn a_remotes_activity_says_every_entry_about_it() {
    use hedwig_model::capability::Operation as Op;
    use hedwig_model::text::{Kernel, Location};
    use hedwig_model::trail::{
        Asking, Binding, ClientId, ConnectionId, Gave, Given, Opener, Outcome, PromptId, RequestId,
        Seq, Serving, Tick, Timestamp,
    };
    let connection = ConnectionId(Seq(1));
    let by = ClientId(Seq(0));
    let events = vec![
        Happened::Opening {
            remote: workspace(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
            opener: Opener::Person(by),
        },
        Happened::Ran {
            connection,
            program: Location::try_from(r"C:\Windows\System32\OpenSSH\ssh.exe").unwrap(),
            release: None,
            asking: Asking::Nobody,
        },
        Happened::Observed {
            connection,
            platform: name("linux"),
        },
        Happened::Checked {
            connection,
            capability: name("gpg"),
            readiness: Readiness::Ready,
        },
        Happened::Up {
            connection,
            serving: vec![Serving {
                capability: name("gpg"),
                binding: Binding::Socket(
                    RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap(),
                ),
            }],
        },
        Happened::Asked {
            connection,
            capability: name("gpg"),
            operation: Op::Sign,
            key: None,
        },
        Happened::Settled {
            request: RequestId(Seq(6)),
            outcome: Outcome::Covered,
        },
        Happened::Settled {
            request: RequestId(Seq(2)),
            outcome: Outcome::Abandoned,
        },
        Happened::Prompted {
            connection,
            kind: PromptKind::KeyPassphrase,
            words: Words::try_from("Enter passphrase for key").unwrap(),
        },
        Happened::Answered {
            prompt: PromptId(Seq(9)),
            by: Some(Gave {
                client: by,
                given: Given::Declined,
            }),
        },
        Happened::Allowed {
            connection,
            capability: name("gpg"),
            operation: Op::Sign,
            key: None,
            until: Tick(60_000),
            by,
        },
        Happened::Ruled {
            connection,
            scope: ConnectionScope {
                capability: Selector::Only(name("gpg")),
                operation: Selector::Only(Op::Decrypt),
                key: Keys::Every,
            },
            mode: Some(Mode::Confirm),
            by,
        },
        Happened::Exercised {
            connection,
            capability: name("gpg"),
            proof: hedwig_model::protocol::Proof::Silent(None),
            by,
        },
        Happened::Paused {
            scope: Remotes::Every,
            by,
        },
        Happened::Resumed {
            scope: Remotes::One(workspace()),
            by,
        },
        Happened::TurnedAway {
            remote: Some(workspace()),
            refusal: Refusal::Unissued,
        },
        Happened::TurnedAway {
            remote: Some(workspace()),
            refusal: Refusal::OffProtocol {
                capability: name("gpg"),
                account: Words::try_from("the remote sent a line of 1,003 bytes").unwrap(),
            },
        },
        Happened::Down {
            connection,
            end: ChannelEnd::Slept,
        },
        Happened::Opening {
            remote: workspace(),
            with: vec![name("gpg")],
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
            opener: Opener::Check(by),
        },
        Happened::Disconnected {
            remote: workspace(),
            by,
        },
        Happened::Gone {
            remote: workspace(),
        },
        Happened::Appeared {
            remote: workspace(),
        },
        Happened::Checked {
            connection,
            capability: name("gpg"),
            readiness: Readiness::Unready(vec![Finding::NoProfile(Refusal::UnknownKernel(
                Kernel::try_from("Haiku").unwrap(),
            ))]),
        },
    ];
    let entries: Vec<Entry> = events
        .into_iter()
        .zip(1..)
        .map(|(event, seq)| Entry {
            seq: Seq(seq),
            at: Timestamp(seq),
            tick: Tick(seq),
            event,
        })
        .collect();
    let said: Vec<String> = exposure::activity(&entries, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, said)| said)
        .collect();
    assert_eq!(
        said,
        [
            "t23: gpg: Hedwig cannot tell which platform the remote is: the remote calls its \
             system Haiku, and no platform profile answers to that; define one to serve it",
            "t22: its route listed it as running",
            "t21: its route no longer listed it as running",
            "t20: disconnected",
            "t19: connecting to check the remote for gpg, as you asked",
            "t18: the connection ended: the workstation went to sleep",
            "t17: a connection was turned away: the connection to gpg was closed because the \
             remote sent a line of 1,003 bytes",
            "t16: a connection was turned away: something on the remote connected to the forward \
             without the bytes Hedwig gave that remote's gpg, and was closed",
            "t15: you resumed dev/build (coder)",
            "t14: you paused every remote",
            "t13: Tested: the remote's own tool ran, and nothing reached this workstation; it said \
             nothing.",
            "t12: for that connection, gpg, when it asks to decrypt: held until you answer",
            "t11: you allowed every request to sign with gpg on that connection, for a time",
            "t10: you declined what it asked",
            "t9: the connection's client asked for the passphrase of a key: Enter passphrase for \
             key",
            "t8: a request asked earlier ended: the remote gave up waiting",
            "t6: asked to sign with gpg - served under what you allowed earlier",
            "t5: connected: gpg reachable there at the socket /run/user/1000/gnupg/S.gpg-agent",
            "t4: gpg is ready there",
            "t3: read the remote as linux",
            r"t2: ran C:\Windows\System32\OpenSSH\ssh.exe, with nothing able to reach you, so it could ask you nothing",
            "t1: connecting, as you asked",
        ]
    );
    let distinct: BTreeSet<&String> = said.iter().collect();
    assert_eq!(distinct.len(), said.len());
}

/// The model's refusal for `capability` failing so, as a sentence begins.
fn refused(capability: &str, failure: Failure) -> String {
    let said = Refusal::SourceUnavailable {
        capability: name(capability),
        failure,
    }
    .to_string();
    let mut letters = said.chars();
    let first = letters.next().unwrap().to_uppercase();
    format!("{}.", first.chain(letters).collect::<String>())
}

/// A holder the core read, in session `session`.
fn holder(program: &str, session: u32, whose: Whose) -> SourceHolder {
    SourceHolder {
        program: Location::try_from(program).unwrap(),
        session,
        whose,
        stopped: None,
    }
}

/// What the relays found of the workstation's side is said where what this
/// workstation has is listed, in the model's words: a POSIX-emulated `GnuPG`
/// neither started nor served; a service whose holder is another account's,
/// said with what holds it and nothing to do; an ADB server Windows does not
/// let Hedwig read - the owner's, started over SSH - and a gpg-agent Windows
/// confines, each with what holds it and the source's own tool that stops it;
/// a host with no address; and a source that answers, with whose program.
#[test]
fn what_answers_for_each_source_is_said_where_the_workstation_is_listed() {
    let mut bench = Bench::attached();
    let found = [
        (
            "gpg",
            Failure::Confined,
            Some(holder("gpg-agent.exe", 2, Whose::Confined)),
        ),
        (
            "playwright",
            Failure::Foreign,
            Some(holder("node.exe", 3, Whose::Another)),
        ),
        (
            "adb",
            Failure::Unidentified,
            Some(holder("adb.exe", 0, Whose::Unread)),
        ),
        ("selenium-grid", Failure::NoAddress, None),
    ];
    for (capability, failure, held) in found.clone() {
        bench.desk.trail.push(Happened::HeldBy {
            capability: name(capability),
            holder: held,
        });
        bench.desk.trail.push(Happened::Source {
            capability: name(capability),
            health: Health::Failing(failure),
        });
    }
    bench.desk.trail.push(Happened::Source {
        capability: name("ssh-agent"),
        health: Health::Sound,
    });
    bench.desk.trail.push(Happened::HeldBy {
        capability: name("ssh-agent"),
        holder: Some(holder(
            r"C:\Program Files\OpenSSH\ssh-agent.exe",
            0,
            Whose::Service {
                services: vec![ServiceName::try_from("ssh-agent").unwrap()],
            },
        )),
    });
    bench.feed(Event::Window(true));
    let Board::First(first) = window(&bench).board else {
        unreachable!("nothing is granted")
    };
    let has = first.has.unwrap();
    let expected = [
        format!(
            "{} gpg is answered by gpg-agent.exe, yours but confined by Windows to less than you, \
             in session 2. If it is yours, gpgconf --kill gpg-agent stops it, and Hedwig starts it \
             again where Hedwig runs when a remote next asks.",
            refused("gpg", Failure::Confined)
        ),
        format!(
            "{} playwright is answered by node.exe, another account's, in session 3.",
            refused("playwright", Failure::Foreign)
        ),
        format!(
            "{} adb is answered by adb.exe in session 0, which Windows does not let Hedwig read. \
             If it is yours, adb kill-server stops it, and your next adb command starts one in the \
             sign-in you run it from.",
            refused("adb", Failure::Unidentified)
        ),
        "selenium-grid names a host this workstation can find no address for.".to_owned(),
        r"ssh-agent answers on this workstation: C:\Program Files\OpenSSH\ssh-agent.exe, which runs the service ssh-agent an administrator installed.".to_owned(),
    ];
    for said in expected {
        assert!(has.contains(&said), "{said}\n{has:#?}");
    }
}

/// Where Hedwig could not read an agent for a capability at a pipe, the line
/// says what ending that agent may cost as well as what it could not tell.
#[test]
fn an_agent_not_read_for_a_pipe_is_said_with_what_ending_it_costs() {
    let mut bench = Bench::attached();
    bench.desk.trail.push(Happened::HeldBy {
        capability: name("ssh-agent"),
        holder: None,
    });
    bench.desk.trail.push(Happened::Source {
        capability: name("ssh-agent"),
        health: Health::Failing(Failure::Undetermined),
    });
    bench.feed(Event::Window(true));
    let Board::First(first) = window(&bench).board else {
        unreachable!("nothing is granted")
    };
    let has = first.has.unwrap();
    let said = "Hedwig could not tell whether a gpg-agent serves the pipe ssh-agent names, so it \
                does not connect to that pipe, since a connection can stop a gpg-agent's pipe; \
                it looks again when a remote next asks. If a gpg-agent of yours is running, it \
                may be the one that serves this pipe, and ending that one ends the pipe; if it \
                is not, ending it, which loses its PIN cache and any card session, lets Hedwig \
                connect to the pipe when a remote next asks, unless something starts it again: \
                gpgconf --kill gpg-agent for one in your default home, or Task Manager for any \
                other."
        .to_owned();
    assert!(has.contains(&said), "{said}\n{has:#?}");
}

/// A change of what answers for a capability reads in an activity that holds
/// it, from then on: whose program, or that nothing answered.
#[test]
fn a_change_of_what_answers_reads_in_an_activity() {
    use hedwig_model::trail::{Seq, Tick, Timestamp};
    let entries: Vec<Entry> = [
        Happened::HeldBy {
            capability: name("adb"),
            holder: Some(holder(
                r"C:\platform-tools\adb.exe",
                0,
                Whose::Person {
                    logon: 7,
                    signed_in: SignedIn::OverTheNetwork,
                    rights: Rights::Administrator,
                },
            )),
        },
        Happened::HeldBy {
            capability: name("adb"),
            holder: None,
        },
    ]
    .into_iter()
    .zip(1..)
    .map(|(event, seq)| Entry {
        seq: Seq(seq),
        at: Timestamp(seq),
        tick: Tick(seq),
        event,
    })
    .collect();
    let said: Vec<String> = exposure::activity(&entries, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, said)| said)
        .collect();
    assert_eq!(
        said,
        [
            "t2: nothing is known to answer for adb on this workstation",
            r"t1: adb is answered by C:\platform-tools\adb.exe, yours, in session 0, signed in over the network, as administrator",
        ]
    );
}

/// A remote's activity says a credential found for nothing, one refused at
/// the forge, and a remote's notice with those turned away before it,
/// though the capabilities they belong to have no surface of their own.
#[test]
fn credentials_and_notices_read_in_a_remotes_activity() {
    use hedwig_model::trail::{ConnectionId, RequestId, Seq, Tick, Timestamp};
    let connection = ConnectionId(Seq(1));
    let events = vec![
        Happened::Unreleased {
            request: RequestId(Seq(1)),
        },
        Happened::Refuted {
            connection,
            capability: name("git-https"),
            site: "https://github.com".parse().unwrap(),
        },
        Happened::Noticed {
            connection,
            capability: name("notices"),
            remark: hedwig_model::text::Remark::try_from("the nightly build finished").unwrap(),
            unheard: 2,
        },
    ];
    let entries: Vec<Entry> = events
        .into_iter()
        .zip(1..)
        .map(|(event, seq)| Entry {
            seq: Seq(seq),
            at: Timestamp(seq),
            tick: Tick(seq),
            event,
        })
        .collect();
    let said: Vec<String> = exposure::activity(&entries, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, said)| said)
        .collect();
    assert_eq!(
        said,
        [
            "t3: said through notices: the nightly build finished (2 notices before it came too \
             fast and were not passed on)",
            "t2: https://github.com refused the credential git-https gave the remote's git; it is \
             unchanged on this workstation",
            "t1: a request for a credential found none on this workstation: the remote's git was \
             given nothing and goes on to its own next helper",
        ]
    );
}

/// While any interface's icon is missing the window says so at the head
/// of its page - the first run's too - in the words the presence's notice
/// gave, naming its session where it is not the window's; once the icon is
/// back the head goes.
#[test]
fn an_icon_the_taskbar_does_not_show_heads_the_window_in_the_notices_words() {
    let mut bench = Bench::viewer();
    bench.attach();
    let presence = bench
        .desk
        .attend(ClientKind::Interface, common::support::DESKTOP);
    bench
        .desk
        .send(presence, Request::Icon(Icon::Missing(Missing::NoTaskbar)))
        .unwrap();
    bench.told();
    let shown = window(&bench);
    assert!(matches!(shown.board, Board::First(_)));
    let heads: Vec<&str> = shown
        .heads
        .iter()
        .map(|head| head.sentence.as_str())
        .collect();
    assert_eq!(
        heads,
        [
            "Windows' taskbar is not running, so Hedwig's icon cannot be shown. A request that \
             needs your answer still comes up as a card, and everything else that needs you is \
             here."
        ]
    );
    let elsewhere = bench
        .desk
        .attend(ClientKind::Interface, common::support::OVER_SSH);
    bench
        .desk
        .send(elsewhere, Request::Icon(Icon::Missing(Missing::Refused)))
        .unwrap();
    bench.told();
    assert_eq!(
        window(&bench)
            .heads
            .get(1)
            .map(|head| head.sentence.as_str()),
        Some(
            "Windows' taskbar does not show Hedwig's icon in session 0. A request that needs your \
             answer still comes up as a card, and everything else that needs you is here."
        )
    );
    for client in [presence, elsewhere] {
        bench.desk.send(client, Request::Icon(Icon::Shown)).unwrap();
        bench.told();
    }
    assert_eq!(window(&bench).heads, []);
}

/// A source whose holder was read before it was tried in this run - the
/// agent's key listing reads the holder and no health - says what holds it
/// and nothing of whether it answers.
#[test]
fn a_holder_read_before_its_source_is_tried_is_said_alone() {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    bench.desk.trail.push(Happened::HeldBy {
        capability: name("ssh-agent"),
        holder: Some(holder(
            r"C:\Program Files\OpenSSH\ssh-agent.exe",
            0,
            Whose::Service {
                services: vec![ServiceName::try_from("ssh-agent").unwrap()],
            },
        )),
    });
    bench.told();
    let Board::First(first) = window(&bench).board else {
        unreachable!()
    };
    let has = first.has.unwrap();
    let said: Vec<&String> = has
        .iter()
        .filter(|line| line.starts_with("ssh-agent"))
        .collect();
    assert_eq!(said.len(), 1, "{has:?}");
    assert!(
        said.iter()
            .all(|line| line.starts_with("ssh-agent is answered by ")
                && !line.contains("answers on this workstation")),
        "{said:?}"
    );
}

/// Where a gpg-agent's pipe has gone though it is set to serve it, the
/// capability's line says so as what was read, and what starts it again; no
/// other line says either.
#[test]
fn a_gpg_agents_stopped_pipe_is_said_with_what_starts_it_again_on_its_capabilitys_line() {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    let mut held = holder(
        r"C:\GnuPG\bin\gpg-agent.exe",
        2,
        Whose::Person {
            logon: 7,
            signed_in: SignedIn::Locally,
            rights: Rights::Standard,
        },
    );
    held.stopped = Some(StoppedPipe {
        pipe: AgentPipe::try_from("mine").unwrap(),
        home: Home::Default,
    });
    bench.desk.trail.push(Happened::HeldBy {
        capability: name("ssh-agent"),
        holder: Some(held),
    });
    bench.desk.trail.push(Happened::HeldBy {
        capability: name("gpg"),
        holder: Some(holder(
            r"C:\GnuPG\bin\gpg-agent.exe",
            2,
            Whose::Person {
                logon: 7,
                signed_in: SignedIn::Locally,
                rights: Rights::Standard,
            },
        )),
    });
    bench.told();
    let Board::First(first) = window(&bench).board else {
        unreachable!()
    };
    let has = first.has.unwrap();
    assert_eq!(
        has.iter()
            .filter(|line| line.contains(r"set to serve \\.\pipe\mine and not serving it"))
            .count(),
        1,
        "{has:?}"
    );
    assert_eq!(
        has.iter()
            .filter(|line| line.contains("Starting it again as you started it makes its pipe again"))
            .count(),
        1,
        "the one capability whose pipe has gone says what to do: {has:?}"
    );
    assert!(
        has.iter()
            .filter(|line| line.contains("Starting it again"))
            .all(|line| line.starts_with("ssh-agent is answered by ")
                && line.contains("and not serving it. Starting it again")),
        "on that capability's own line: {has:?}"
    );
}

/// A remote's activity, reviewed in the window, holds who came
/// to answer for a capability it is served while it is served; and where the
/// trail was compacted it ends with how many older entries went and why,
/// whichever remote they were about.
#[test]
fn a_remotes_activity_holds_its_holders_change_and_ends_where_it_was_cut() {
    let mut bench = Bench::attached();
    grants(&mut bench, "gpg", Granted::One(workspace()), Exposure::NONE);
    bench.desk.channel_up(&workspace(), "linux");
    bench.desk.trail.push(Happened::HeldBy {
        capability: name("gpg"),
        holder: Some(holder(
            r"C:\Program Files\GnuPG\bin\gpg-agent.exe",
            2,
            Whose::Person {
                logon: 7,
                signed_in: SignedIn::Locally,
                rights: Rights::Standard,
            },
        )),
    });
    bench.told();
    bench.feed(Event::Review(Some(workspace())));
    let entries = bench
        .seen()
        .activity
        .as_ref()
        .and_then(|activity| activity.entries.clone())
        .unwrap();
    let said: Vec<String> = exposure::activity(&entries, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, text)| text)
        .collect();
    assert!(
        said.first().is_some_and(|newest| newest
            .contains(r"gpg is answered by C:\Program Files\GnuPG\bin\gpg-agent.exe")),
        "{said:?}"
    );

    // Compacted past a ceiling of three: the oldest page ends at the cut.
    let sets = bench.desk.configuration.sets(&bench.desk.catalogue);
    let (head, kept) = trail::compact(
        State::default(),
        bench.desk.trail.entries.clone(),
        trail::Timestamp(0),
        3,
    );
    let page = trail::page(
        &head,
        &kept,
        &Selector::Only(workspace()),
        &sets,
        None,
        std::num::NonZeroU8::new(50).unwrap(),
    );
    let said: Vec<String> = exposure::activity(&page, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, text)| text)
        .collect();
    let dropped = bench.desk.trail.entries.len() - 3;
    assert!(
        said.last().is_some_and(|oldest| oldest.ends_with(&format!(
            ": nothing before this is kept: Hedwig let go of {dropped} older entries, of every \
             remote's, past the newest 100,000 it keeps so that it starts quickly"
        ))),
        "{said:?}"
    );
    let (head, kept) = trail::compact(
        State::default(),
        bench.desk.trail.entries.clone(),
        trail::Timestamp(u64::MAX),
        100_000,
    );
    let never = remote("ssh", "never.example");
    let page = trail::page(
        &head,
        &kept,
        &Selector::Only(never),
        &sets,
        None,
        std::num::NonZeroU8::new(50).unwrap(),
    );
    let said: Vec<String> = exposure::activity(&page, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, text)| text)
        .collect();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said.first()
            .is_some_and(|only| only.contains("older than you keep activity")),
        "a remote first seen after the cut reads the same: {said:?}"
    );
}
