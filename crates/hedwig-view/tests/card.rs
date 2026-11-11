//! A request, deciding: what the person is shown, what each answer does, and
//! when an answer is taken.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::{NonZeroU8, NonZeroU32};

use hedwig_model::capability::{Exposure, Operation};
use hedwig_model::config::{Activation, Change};
use hedwig_model::gate::{Capped, Verdict};
use hedwig_model::organisation::{Limit, Part};
use hedwig_model::policy::{Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{Answer, Attention, Decision, Notice, Request, Topic, Withdrawn};
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::scope::{Audience, Holder};
use hedwig_model::setting::{Burst, CapScope, FullScreen, Longest, Threshold};
use hedwig_model::text::{Grip, Words};
use hedwig_model::trail::{
    ClientKind, ConnectionId, Event as Happened, Item, Outcome, Presence, PromptId, PromptKind,
    RequestId, Tick,
};
use hedwig_model::wire::line;
use hedwig_view::card::{self, Card, Deck, Desk, Does, Subject, Weight, Why};
use hedwig_view::link::{Event, Place};
use hedwig_view::presence::{Change as PresenceChange, Desktop};
use hedwig_view::words;

mod common;
use common::Bench;
use common::support::{OVER_SSH, grant, name, remote, terms};

const DESK: &str = "the service desk, extension 4400";

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

/// `gpg` on two remotes, both connected, each asking the person before it
/// signs.
fn connected() -> (Bench, ConnectionId, ConnectionId) {
    let mut bench = Bench::attached();
    for remotes in [Granted::Route(name("coder")), Granted::One(host())] {
        bench.feed(Event::Wish(
            Place::Window,
            Request::Change(Change::Grant {
                grant: grant("gpg", remotes),
                terms: terms(Activation::OnRequest, Exposure::NONE),
            }),
        ));
    }
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::Every,
                capability: Selector::Every,
                operation: Selector::Only(Operation::Sign),
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    ));
    let first = bench.desk.channel_up(&workspace(), "linux");
    let second = bench.desk.channel_up(&host(), "linux");
    refresh(&mut bench);
    (bench, first, second)
}

/// The remote asks, and the core holds the request and tells its clients.
fn asks(bench: &mut Bench, connection: ConnectionId) -> RequestId {
    let (request, verdict) = bench.desk.asks(connection, "gpg", Operation::Sign);
    assert!(matches!(verdict, Verdict::Hold(_)), "{verdict:?}");
    let raised = bench
        .desk
        .send(bench.client.unwrap(), Request::Attention)
        .map(|reply| match reply {
            hedwig_model::protocol::Reply::Attention(items) => items,
            other => unreachable!("{other:?}"),
        })
        .unwrap()
        .into_iter()
        .find(|needs| {
            matches!(needs.attention, Attention::Request { request: held, .. } if held == request)
        })
        .unwrap();
    bench.notice(Notice::Raised(raised));
    request
}

fn card(bench: &Bench, deck: &Deck) -> Card {
    deck.card(
        bench.attention(),
        Why {
            rows: bench.rows(),
            contacts: bench.contacts(),
            keyrings: bench.seen().keyrings(),
        },
    )
    .expect("a card")
}

/// The person's own lengths for "allow for a time".
fn lengths(bench: &mut Bench, seconds: &[u32]) {
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Lengths(Some(seconds.iter().copied().collect()))),
    ));
    refresh(bench);
}

fn govern(bench: &mut Bench, lines: &[(Part, String)]) {
    bench.govern(lines);
    refresh(bench);
}

fn labels(card: &Card) -> Vec<&str> {
    card.choices
        .iter()
        .map(|choice| choice.label.as_str())
        .collect()
}

fn take(card: Card, label: &str) -> Request {
    card.choices
        .into_iter()
        .find(|choice| choice.label == label)
        .map(|choice| match choice.does {
            Does::Send(request) => request,
            other => unreachable!("{other:?} on a request's card"),
        })
        .expect("offered")
}

fn minutes(minutes: u32) -> NonZeroU32 {
    NonZeroU32::new(minutes * 60).unwrap()
}

/// A person mid-commit in a remote terminal. The request is put with everything
/// the decision needs on it: which remote, what it asks, with which key, and
/// which statement of the person's own is why they are being asked.
#[test]
fn a_request_is_put_with_who_asks_what_and_why() {
    let (mut bench, connection, _) = connected();
    let request = asks(&mut bench, connection);
    let mut deck = Deck::default();
    assert!(deck.settle(bench.attention(), 1_000));
    assert_eq!(deck.showing(), Some(&Subject::Request(request)));

    let shown = card(&bench, &deck);
    assert_eq!(shown.heading, "dev/build (coder) asks to sign with gpg");
    assert_eq!(
        shown.facts,
        [
            ("From", "dev/build (coder)".to_owned()),
            ("Asks to", "sign with gpg".to_owned()),
            (
                "You are asked because of",
                "your rule for every remote: everything, when it asks to sign".to_owned()
            ),
        ]
    );
    assert!(!shown.typed);
    assert_eq!(shown.behind, 0);
    // The lengths are what ships until the person says otherwise.
    assert_eq!(
        labels(&shown),
        [
            "Allow once",
            "Allow for 1 minute",
            "Allow for 15 minutes",
            "Allow for 1 hour",
            "Refuse",
            "Pause this remote"
        ]
    );

    // The key the dialect's parser read is a fact of its own, where it is
    // never cut; the heading stays the question the answers answer. An
    // allowance covers that key alone, and its sentence says so.
    let keyed = Attention::Request {
        payload: None,
        request,
        remote: workspace(),
        capability: name("gpg"),
        operation: Operation::Sign,
        key: Some(hedwig_model::text::KeyId::Grip(
            Grip::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap(),
        )),
        offers: vec![minutes(15)],
        capped: None,
    };
    let shown = Card::of(
        &keyed,
        Why {
            rows: bench.rows(),
            ..Why::default()
        },
        0,
    )
    .unwrap();
    assert_eq!(shown.heading, "dev/build (coder) asks to sign with gpg");
    assert!(shown.facts.contains(&(
        "Key",
        "the key with keygrip 0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2".to_owned()
    )));
    assert_eq!(
        shown.allows.as_deref(),
        Some(
            "For that time, every request to sign with gpg with the key with keygrip \
             0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2 on this connection is served without \
             asking you."
        )
    );
}

/// The lengths an allowance is offered for are the person's own setting,
/// said as they would say them; with none set, none is offered and nothing
/// says what one would let through.
#[test]
fn an_allowance_is_offered_for_the_lengths_the_person_set() {
    let (mut bench, connection, _) = connected();
    lengths(&mut bench, &[90, 60, 900, 3600, 7200]);
    asks(&mut bench, connection);
    let mut deck = Deck::default();
    deck.settle(bench.attention(), 0);
    let shown = card(&bench, &deck);
    assert_eq!(
        labels(&shown),
        [
            "Allow once",
            "Allow for 1 minute",
            "Allow for 90 seconds",
            "Allow for 15 minutes",
            "Allow for 1 hour",
            "Allow for 2 hours",
            "Refuse",
            "Pause this remote",
        ]
    );
    // One usual answer; what ends more than this request stands apart.
    let weights: Vec<Weight> = shown.choices.iter().map(|choice| choice.weight).collect();
    assert_eq!(weights.first(), Some(&Weight::Usual));
    assert_eq!(weights.last(), Some(&Weight::Apart));
    assert_eq!(
        weights
            .iter()
            .filter(|weight| **weight == Weight::Usual)
            .count(),
        1
    );

    let (mut bench, connection, _) = connected();
    lengths(&mut bench, &[]);
    asks(&mut bench, connection);
    let mut deck = Deck::default();
    deck.settle(bench.attention(), 0);
    let shown = card(&bench, &deck);
    assert_eq!(
        labels(&shown),
        ["Allow once", "Refuse", "Pause this remote"]
    );
    assert_eq!(shown.allows, None);
}

/// A request the organisation's floor holds for asking. The card says
/// whose policy asks, what the person's own statements would have done
/// without it, and whom the organisation says to ask - and offers no answer
/// that would lift the limit, since none can be taken there.
#[test]
fn a_floor_from_above_says_whose_it_is_what_it_moved_and_whom_to_ask() {
    let mut bench = Bench::attached();
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(host())),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        }),
    ));
    let connection = bench.desk.channel_up(&host(), "linux");
    let floor = Limit::Floor {
        scope: RuleScope {
            remotes: Remotes::Every,
            capability: Selector::Only(name("gpg")),
            operation: Selector::Only(Operation::Sign),
            key: Keys::Every,
        },
        mode: Mode::Confirm,
    };
    govern(
        &mut bench,
        &[(Part::Limits, line(&floor)), (Part::Ask, DESK.to_owned())],
    );
    asks(&mut bench, connection);
    let mut deck = Deck::default();
    deck.settle(bench.attention(), 0);
    let shown = card(&bench, &deck);
    assert_eq!(
        shown.facts,
        [
            ("From", "build.example (ssh)".to_owned()),
            ("Asks to", "sign with gpg".to_owned()),
            (
                "You are asked because of",
                "your organisation's policy for this machine, for every remote: gpg, when it \
                 asks to sign"
                    .to_owned()
            ),
            (
                "Without that limit",
                "served and shown to you, by Hedwig's default for what this exposes".to_owned()
            ),
            ("Whom to ask", DESK.to_owned()),
        ]
    );
    assert_eq!(
        labels(&shown),
        [
            "Allow once",
            "Allow for 1 minute",
            "Allow for 15 minutes",
            "Allow for 1 hour",
            "Refuse",
            "Pause this remote"
        ]
    );
}

/// The organisation caps what one gesture can loosen. The card
/// offers only the lengths the core admits for the request, says whose cap
/// took the others away, and whom to ask; a cap of nothing leaves no
/// allowance and no sentence about one.
#[test]
fn a_cap_from_above_offers_fewer_answers_and_says_whose_it_is() {
    for (longest, offered) in [
        (
            Longest::Seconds(minutes(15)),
            vec![
                "Allow once",
                "Allow for 1 minute",
                "Allow for 15 minutes",
                "Refuse",
                "Pause this remote",
            ],
        ),
        (
            Longest::Nothing,
            vec!["Allow once", "Refuse", "Pause this remote"],
        ),
    ] {
        let (mut bench, connection, _) = connected();
        let cap = Limit::Cap {
            scope: CapScope {
                remotes: Remotes::Every,
                key: Keys::Every,
            },
            longest,
        };
        govern(
            &mut bench,
            &[(Part::Limits, line(&cap)), (Part::Ask, DESK.to_owned())],
        );
        asks(&mut bench, connection);
        let mut deck = Deck::default();
        deck.settle(bench.attention(), 0);
        // The held request carries the cap the core decided took lengths
        // away, and the card says it.
        let carried = bench.items().into_iter().find_map(|item| match item {
            Attention::Request { capped, .. } => Some(capped.clone()),
            _ => None,
        });
        assert_eq!(
            carried,
            Some(
                bench
                    .desk
                    .ask_world(|world| world.longest(&workspace(), None))
            )
        );
        assert_eq!(
            carried.flatten().expect("a cap took lengths away"),
            Capped {
                longest,
                holder: Holder::Organisation(Audience::Machine),
                scope: CapScope {
                    remotes: Remotes::Every,
                    key: Keys::Every,
                },
            }
        );
        let shown = deck
            .card(
                bench.attention(),
                Why {
                    rows: bench.rows(),
                    contacts: bench.contacts(),
                    keyrings: bench.seen().keyrings(),
                },
            )
            .unwrap();
        assert_eq!(labels(&shown), offered, "{longest:?}");
        let said = match longest {
            Longest::Nothing => {
                "your organisation's policy for this machine allows nothing for a time for every \
                 remote"
            }
            Longest::Seconds(_) => {
                "your organisation's policy for this machine caps an allowance at 15 minutes for \
                 every remote"
            }
        };
        assert_eq!(
            shown.facts.get(3..).unwrap(),
            [
                ("Allowances", said.to_owned()),
                ("Whom to ask", DESK.to_owned())
            ]
        );
        assert_eq!(shown.allows.is_some(), longest != Longest::Nothing);
        // Every length it offers is one the core accepts.
        for label in labels(&shown)
            .into_iter()
            .filter(|label| label.starts_with("Allow for"))
        {
            let wish = take(card(&bench, &deck), label);
            assert_eq!(bench.permits(&wish), Ok(()), "{label}");
        }
    }
}

/// Each answer is a request the core accepts, and does what its label says.
#[test]
fn each_answer_does_what_it_says() {
    for answer in [
        "Allow once",
        "Allow for 15 minutes",
        "Refuse",
        "Pause this remote",
    ] {
        let (mut bench, connection, _) = connected();
        let request = asks(&mut bench, connection);
        let mut deck = Deck::default();
        deck.settle(bench.attention(), 0);
        let wish = take(card(&bench, &deck), answer);
        assert_eq!(bench.permits(&wish), Ok(()), "{answer}");
        let now = bench.desk.trail.tick();
        bench.feed(Event::Wish(Place::Card, wish));
        assert_eq!(bench.seen().refused, None, "{answer}");

        let client = bench.client.unwrap();
        let events: Vec<&Happened> = bench
            .desk
            .trail
            .entries
            .iter()
            .map(|entry| &entry.event)
            .collect();
        let settled = |outcome| Happened::Settled { request, outcome };
        match answer {
            "Allow once" => {
                assert!(events.contains(&&settled(Outcome::Allowed(client))));
                assert!(
                    !events
                        .iter()
                        .any(|event| matches!(event, Happened::Allowed { .. }))
                );
            }
            "Allow for 15 minutes" => {
                assert!(events.contains(&&settled(Outcome::Allowed(client))));
                assert!(events.contains(&&Happened::Allowed {
                    connection,
                    capability: name("gpg"),
                    operation: Operation::Sign,
                    key: None,
                    until: Tick(now.0 + 900_000),
                    by: client,
                }));
                // The next request like it is served without asking.
                let (_, verdict) = bench.desk.asks(connection, "gpg", Operation::Sign);
                assert_eq!(verdict, Verdict::Serve(Outcome::Covered));
            }
            "Refuse" => {
                assert!(events.contains(&&settled(Outcome::Refused(Refusal::Declined))));
            }
            _ => {
                assert!(events.contains(&&Happened::Paused {
                    scope: Remotes::One(workspace()),
                    by: client
                }));
                assert!(bench.desk.trail.state().link(connection).is_none());
            }
        }
        // Answered, it is no longer asking, and the card has nothing to show.
        assert!(deck.settle(bench.attention(), 10), "{answer}");
        assert_eq!(deck.showing(), None);
    }
}

/// What the person is reading is never replaced by an arrival. A second
/// request waits behind the first, is counted, and takes its place only when
/// the first is answered.
#[test]
fn what_the_person_is_reading_is_never_replaced_by_an_arrival() {
    let (mut bench, first, second) = connected();
    let one = asks(&mut bench, first);
    let mut deck = Deck::default();
    assert!(deck.settle(bench.attention(), 100));

    let two = asks(&mut bench, second);
    assert!(
        !deck.settle(bench.attention(), 200),
        "the card did not change"
    );
    assert_eq!(deck.showing(), Some(&Subject::Request(one)));
    assert_eq!(card(&bench, &deck).behind, 1);

    let allow = take(card(&bench, &deck), "Allow once");
    bench.feed(Event::Wish(Place::Card, allow));
    assert!(deck.settle(bench.attention(), 300));
    assert_eq!(deck.showing(), Some(&Subject::Request(two)));
    let shown = card(&bench, &deck);
    assert_eq!(shown.heading, "build.example (ssh) asks to sign with gpg");
    assert_eq!(shown.behind, 0);
}

/// An answer is taken only once the card has shown its subject for the
/// system's own double-click time, so a press already on its way to whatever
/// was there decides nothing - when the card first appears, and again each
/// time what it shows changes.
#[test]
fn no_answer_is_taken_until_the_card_has_settled() {
    let settle = 500;
    let (mut bench, first, second) = connected();
    let mut deck = Deck::default();
    assert!(!deck.armed(10_000, settle), "nothing is showing");

    asks(&mut bench, first);
    deck.settle(bench.attention(), 1_000);
    assert!(!deck.armed(1_000, settle));
    assert!(!deck.armed(1_499, settle));
    assert!(deck.armed(1_500, settle));

    // A second arrival does not start the wait again: the card is unchanged.
    asks(&mut bench, second);
    deck.settle(bench.attention(), 2_000);
    assert!(deck.armed(2_001, settle));

    // The first is answered; the second slides in under the pointer, and the
    // wait starts again.
    let allow = take(card(&bench, &deck), "Allow once");
    bench.feed(Event::Wish(Place::Card, allow));
    assert!(deck.settle(bench.attention(), 3_000));
    assert!(!deck.armed(3_499, settle));
    assert!(deck.armed(3_500, settle));
}

/// The request is also at the person's terminal over SSH, and they
/// answer it there. The card's request is over: the core says so, the card
/// lets go of it, and an answer given to it anyway is refused in the core's
/// own words rather than applied to something else.
#[test]
fn a_request_answered_elsewhere_leaves_the_card() {
    let (mut bench, connection, _) = connected();
    let terminal = bench.desk.attend(ClientKind::Terminal, OVER_SSH);
    let request = asks(&mut bench, connection);
    let mut deck = Deck::default();
    deck.settle(bench.attention(), 0);
    let late = take(card(&bench, &deck), "Allow once");

    bench
        .desk
        .send(
            terminal,
            Request::Decide {
                request,
                decision: Decision::Refuse,
            },
        )
        .unwrap();
    bench.notice(Notice::Withdrawn(Withdrawn::Request(request)));
    assert_eq!(bench.attention(), []);
    assert!(deck.settle(bench.attention(), 50));
    assert_eq!(deck.showing(), None);

    bench.feed(Event::Wish(Place::Card, late));
    assert_eq!(
        bench.seen().refused,
        Some((Place::Card, Refusal::UnknownRequest(request)))
    );
    assert_eq!(
        Refusal::UnknownRequest(request).to_string(),
        "that request has already been settled"
    );
}

/// A channel's own prompt is put in the same form, with the answers its kind
/// takes. What the person types is never in the view, and never in the trail.
/// A host key's card has no usual answer: OpenSSH
/// itself makes the person type the word.
#[test]
#[allow(clippy::too_many_lines, reason = "one pass over every kind of prompt")]
fn a_prompt_is_put_in_the_same_form_with_its_own_answers() {
    let cases = [
        (
            PromptKind::UnknownHostKey,
            false,
            ("Trust this host", Weight::Beside),
            Answer::Accept,
        ),
        (
            PromptKind::AgentConfirmation,
            false,
            ("Allow", Weight::Usual),
            Answer::Accept,
        ),
        (
            PromptKind::KeyPassphrase,
            true,
            ("Send", Weight::Usual),
            Answer::Accept,
        ),
        (
            PromptKind::Password,
            true,
            ("Send", Weight::Usual),
            Answer::Accept,
        ),
        (
            PromptKind::SecurityKeyPin,
            true,
            ("Send", Weight::Usual),
            Answer::Accept,
        ),
        (
            PromptKind::Challenge,
            true,
            ("Send", Weight::Usual),
            Answer::Accept,
        ),
    ];
    for (kind, typed, (usual, weight), accepted) in cases {
        let mut bench = Bench::attached();
        let connection = bench.desk.trail.open(&host(), "linux");
        let prompt = PromptId(bench.desk.trail.push(Happened::Prompted {
            connection,
            kind,
            words: Words::try_from("SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8").unwrap(),
        }));
        refresh(&mut bench);
        let mut deck = Deck::default();
        deck.settle(bench.attention(), 0);
        assert_eq!(deck.showing(), Some(&Subject::Prompt(prompt)));
        let shown = card(&bench, &deck);
        assert_eq!(shown.typed, typed, "{kind:?}");
        assert_eq!(
            shown.facts,
            [
                ("Connecting to", "build.example (ssh)".to_owned()),
                (
                    "It says",
                    "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".to_owned()
                ),
            ]
        );
        let first = shown.choices.into_iter().next().unwrap();
        assert_eq!((first.label.as_str(), first.weight), (usual, weight));
        let (wish, expected) = match first.does {
            Does::Send(request) => (request, accepted),
            // The surface that holds what was typed builds the request.
            Does::Typed(named) => {
                assert_eq!(named, prompt);
                (
                    Request::Answer {
                        prompt: named,
                        answer: Answer::Text("correct horse battery".to_owned().into()),
                    },
                    Answer::Text("correct horse battery".to_owned().into()),
                )
            }
            other => unreachable!("{other:?} on a prompt's card"),
        };
        assert_eq!(bench.permits(&wish), Ok(()));
        bench.feed(Event::Wish(Place::Card, wish));
        assert_eq!(bench.desk.answered.last(), Some(&expected));
        assert!(
            bench
                .desk
                .trail
                .entries
                .iter()
                .all(|entry| !line(entry).contains("correct horse")),
            "an answer is never recorded"
        );
        assert!(deck.settle(bench.attention(), 10));

        // Declining is always beside it.
        let connection = bench.desk.trail.open(&workspace(), "linux");
        bench.desk.trail.push(Happened::Prompted {
            connection,
            kind,
            words: Words::try_from("again").unwrap(),
        });
        refresh(&mut bench);
        deck.settle(bench.attention(), 20);
        let decline = card(&bench, &deck).choices.into_iter().nth(1).unwrap();
        assert_eq!(decline.weight, Weight::Beside);
        assert!(matches!(
            decline.does,
            Does::Send(Request::Answer {
                answer: Answer::Decline,
                ..
            })
        ));
    }
}

/// A security key waiting for a touch is put to the person with the one
/// answer the core takes for it, giving up; touching the key is the answer,
/// and the core withdraws the card when it is touched.
#[test]
fn a_key_waiting_for_a_touch_offers_only_giving_up() {
    let mut bench = Bench::attached();
    let connection = bench.desk.trail.open(&host(), "linux");
    let prompt = PromptId(bench.desk.trail.push(Happened::Prompted {
        connection,
        kind: PromptKind::SecurityKeyTouch,
        words: Words::try_from("Confirm user presence for key ECDSA-SK").unwrap(),
    }));
    refresh(&mut bench);
    let mut deck = Deck::default();
    deck.settle(bench.attention(), 0);
    let shown = card(&bench, &deck);
    assert_eq!(
        shown.heading,
        "Connecting to build.example (ssh) needs a touch of a security key"
    );
    assert!(!shown.typed);
    assert_eq!(labels(&shown), ["Do not connect"]);
    let wish = take(shown, "Do not connect");
    assert_eq!(bench.permits(&wish), Ok(()));
    let accept = Request::Answer {
        prompt,
        answer: Answer::Accept,
    };
    assert_eq!(
        bench.permits(&accept),
        Err(Refusal::AnswerUnfit {
            kind: PromptKind::SecurityKeyTouch
        })
    );
}

/// A burst from one remote interrupts, and the person says which it is:
/// something wrong, or the rebase they are running.
#[test]
fn a_burst_is_put_to_the_person_who_says_which_it_is() {
    for answer in ["Pause this remote", "This is expected"] {
        let mut bench = Bench::attached();
        bench.feed(Event::Wish(
            Place::Window,
            Request::Change(Change::Grant {
                grant: grant("gpg", Granted::Route(name("coder"))),
                terms: terms(Activation::OnRequest, Exposure::NONE),
            }),
        ));
        bench.feed(Event::Wish(
            Place::Window,
            Request::Change(Change::Burst {
                remotes: Remotes::Every,
                threshold: Some(Threshold::At(Burst {
                    requests: NonZeroU8::new(3).unwrap(),
                    seconds: NonZeroU32::new(60).unwrap(),
                })),
            }),
        ));
        let connection = bench.desk.channel_up(&workspace(), "linux");
        for _ in 0..3 {
            bench.desk.asks(connection, "gpg", Operation::Sign);
        }
        refresh(&mut bench);
        let mut deck = Deck::default();
        deck.settle(bench.attention(), 0);
        assert_eq!(deck.showing(), Some(&Subject::Burst(workspace())));
        let shown = card(&bench, &deck);
        assert_eq!(
            shown.heading,
            "dev/build (coder) made 3 requests in a short time"
        );
        assert_eq!(labels(&shown), ["Pause this remote", "This is expected"]);
        let wish = take(shown, answer);
        assert_eq!(bench.permits(&wish), Ok(()));
        bench.feed(Event::Wish(Place::Card, wish));
        let last = bench
            .desk
            .trail
            .entries
            .iter()
            .rev()
            .find_map(|entry| match &entry.event {
                Happened::Paused { scope, .. } => Some(format!("paused {scope:?}")),
                Happened::PutAway { item, .. } => Some(format!("put away {item:?}")),
                _ => None,
            });
        if answer == "This is expected" {
            assert_eq!(
                last,
                Some(format!("put away {:?}", Item::Burst(workspace())))
            );
            assert!(deck.settle(bench.attention(), 10));
            assert_eq!(deck.showing(), None);
        } else {
            assert_eq!(
                last,
                Some(format!("paused {:?}", Remotes::One(workspace())))
            );
        }
    }
}

/// The card is a window, which do not disturb does not hold back. It is
/// shown over an application that fills the screen unless the person set it
/// not to be for that remote, and never over a presentation, an exclusive
/// display or a desktop nobody is at.
#[test]
fn the_card_is_shown_where_the_desktop_takes_it() {
    use FullScreen::{NotShown, Shown};
    let cases = [
        (Desk::Open, Shown, true),
        (Desk::Open, NotShown, true),
        (Desk::Filled, Shown, true),
        (Desk::Filled, NotShown, false),
        (Desk::Presenting, Shown, false),
        (Desk::Presenting, NotShown, false),
        (Desk::Exclusive, Shown, false),
        (Desk::Exclusive, NotShown, false),
        (Desk::Away, Shown, false),
        (Desk::Away, NotShown, false),
    ];
    for (desk, over, expected) in cases {
        assert_eq!(card::raise(desk, over), expected, "{desk:?} {over:?}");
    }
}

/// What the desktop takes is what the interface tells the core: the card
/// alone while an application fills the screen; nothing, with the person
/// there, while they present or an application holds the display; nothing,
/// and nobody there, while it is locked or the shell sees nobody.
#[test]
fn what_the_desktop_takes_is_the_presence_the_core_is_told() {
    let cases = [
        (Desk::Open, Presence::Present),
        (Desk::Filled, Presence::CardOnly),
        (Desk::Presenting, Presence::Engaged),
        (Desk::Exclusive, Presence::Engaged),
        (Desk::Away, Presence::Away),
    ];
    for (desk, expected) in cases {
        let mut desktop = Desktop::default();
        assert_eq!(
            desktop.apply(PresenceChange::Desk(desk)),
            expected,
            "{desk:?}"
        );
        // Locked or disconnected, nothing is taken whatever the shell says.
        assert_eq!(desktop.apply(PresenceChange::Locked), Presence::Away);
        assert_eq!(
            desktop.apply(PresenceChange::Unlocked),
            expected,
            "{desk:?}"
        );
    }
}

/// A held request reaches the person or is refused as reaching
/// nobody; it never waits where nothing shows it. Over an application that
/// fills the screen the card is the one route, so a remote the person set
/// the card not to be shown for is refused there; a presentation takes
/// nothing, and what was held is refused when it begins. Back at an open
/// desktop, the next request is held and carded.
#[test]
fn a_held_request_no_card_can_show_is_refused_and_never_left_waiting() {
    let mut bench = Bench::attached();
    let host = remote("ssh", "build.example");
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(host.clone())),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        }),
    ));
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::Every,
                capability: Selector::Every,
                operation: Selector::Only(Operation::Sign),
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    ));
    let connection = bench.desk.channel_up(&host, "linux");
    let mut desktop = Desktop::default();
    let held_now = |bench: &mut Bench| -> Vec<RequestId> {
        bench.notice(Notice::Stale(Topic::Attention));
        bench
            .seen()
            .attention
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|needs| match Subject::of(&needs.attention) {
                Some(Subject::Request(request)) => Some(request),
                _ => None,
            })
            .collect()
    };
    let over = |bench: &mut Bench| {
        bench.notice(Notice::Stale(Topic::Configuration));
        card::over(&host, bench.seen().settings.as_deref())
    };

    // An application fills the screen: the card is shown over it, as ships.
    bench.feed(Event::Presence(
        desktop.apply(PresenceChange::Desk(Desk::Filled)),
    ));
    let (first, verdict) = bench.desk.asks(connection, "gpg", Operation::Sign);
    assert!(matches!(verdict, Verdict::Hold(_)), "{verdict:?}");
    assert_eq!(held_now(&mut bench), [first]);
    assert!(card::raise(desktop.desk, over(&mut bench)));

    // The person sets the card not to be shown over it for this remote: a
    // request from it cannot be put to them there, and is refused at once.
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::FullScreen {
            remotes: Remotes::One(host.clone()),
            card: Some(FullScreen::NotShown),
        }),
    ));
    assert!(!card::raise(desktop.desk, over(&mut bench)));
    let (_, verdict) = bench.desk.asks(connection, "gpg", Operation::Sign);
    assert_eq!(
        verdict,
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::FullScreen))
    );
    assert_eq!(
        words::refusal(&Refusal::NobodyReachable(Whereabouts::FullScreen), &[]),
        "an application filled your screen, and you set this remote's request card not to be \
         shown over one"
    );

    // A presentation takes nothing: what was held is refused as it begins.
    bench.feed(Event::Presence(
        desktop.apply(PresenceChange::Desk(Desk::Presenting)),
    ));
    assert_eq!(held_now(&mut bench), Vec::<RequestId>::new());
    let (_, verdict) = bench.desk.asks(connection, "gpg", Operation::Sign);
    assert_eq!(
        verdict,
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Engaged))
    );
    assert_eq!(
        words::refusal(&Refusal::NobodyReachable(Whereabouts::Engaged), &[]),
        "you were presenting, or an application held your display, and no attended terminal \
         would have shown it to you"
    );

    // Back at an open desktop the card is shown whatever the setting.
    bench.feed(Event::Presence(
        desktop.apply(PresenceChange::Desk(Desk::Open)),
    ));
    let (next, verdict) = bench.desk.asks(connection, "gpg", Operation::Sign);
    assert!(matches!(verdict, Verdict::Hold(_)), "{verdict:?}");
    assert_eq!(held_now(&mut bench), [next]);
    assert!(card::raise(desktop.desk, over(&mut bench)));
}

/// Every answer has an access key, and no two share one.
#[test]
fn every_answer_has_its_own_access_key() {
    let labels = [
        "Allow once",
        "Allow for 1 minute",
        "Allow for 15 minutes",
        "Allow for 1 hour",
        "Refuse",
        "Pause this remote",
    ];
    let keyed = card::keyed(labels);
    assert_eq!(
        keyed,
        [
            "&Allow once",
            "A&llow for 1 minute",
            "All&ow for 15 minutes",
            "Allo&w for 1 hour",
            "&Refuse",
            "&Pause this remote",
        ]
    );
    // A label with nothing left to take is left as it is.
    assert_eq!(card::keyed(["a", "a"]), ["&a", "a"]);
}

/// An act chosen from the icon that widens what is reachable or ends what the
/// person would set up again is put to them as a dialog of the card's own
/// construction: the question is the verb, the consequence is said beneath
/// it, and the answers are the verb and "Cancel". Neither is filled with the
/// accent, and each is one gesture.
#[test]
fn a_confirmation_asks_the_act_as_its_question_and_offers_it_and_cancel() {
    let card = Card::confirming(
        "Stop Hedwig",
        "Every remote loses what you granted it until Hedwig is started again, and \
         whatever is being served ends now.",
    );
    assert_eq!(card.subject, Subject::Confirming);
    assert_eq!(card.heading, "Stop Hedwig?");
    assert_eq!(
        card.says.as_deref(),
        Some(
            "Every remote loses what you granted it until Hedwig is started again, and \
             whatever is being served ends now."
        )
    );
    assert!(card.facts.is_empty() && !card.typed && card.allows.is_none());
    let answers: Vec<(&str, &Does, Weight)> = card
        .choices
        .iter()
        .map(|choice| (choice.label.as_str(), &choice.does, choice.weight))
        .collect();
    assert_eq!(
        answers,
        [
            ("Stop Hedwig", &Does::Proceed, Weight::Beside),
            ("Cancel", &Does::Cancel, Weight::Beside),
        ]
    );
    assert_eq!(
        card::keyed(card.choices.iter().map(|choice| choice.label.as_str())),
        ["&Stop Hedwig", "&Cancel"]
    );
    assert_eq!(card.waiting(), None);
    // Nothing the core raises is a confirmation, so the deck never shows one.
    let mut deck = Deck::default();
    assert!(!deck.settle(&[], 0));
    assert_eq!(deck.showing(), None);
}

/// What the cards say, on the card. Where the request's key is on a card
/// Hedwig has read, the card says which - its serial as the card is labelled -
/// and what it asks for before the key is used, so the person knows whether
/// an allowance still needs them at the card; one key on two
/// `YubiKey`s names both, and that either can sign; a key on no card read says
/// nothing of one.
#[test]
fn a_request_names_the_card_its_key_is_on_and_what_that_card_asks_for() {
    let key = Grip::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap();
    let item = Attention::Request {
        payload: None,
        request: RequestId(hedwig_model::trail::Seq(9)),
        remote: workspace(),
        capability: name("gpg"),
        operation: Operation::Sign,
        key: Some(hedwig_model::text::KeyId::Grip(key.clone())),
        offers: vec![minutes(15)],
        capped: None,
    };
    let cards = [hedwig_model::trail::Card {
        serial: hedwig_model::text::Serial::try_from("D2760001240103040006123456780000").unwrap(),
        keys: vec![hedwig_model::trail::Held {
            grip: key,
            touch: Some(hedwig_model::trail::Touch::Cached),
        }],
        pin: None,
    }];
    let on = |cards| {
        Card::of(
            &item,
            Why {
                keyrings: words::Keyrings::new(None, cards),
                ..Why::default()
            },
            0,
        )
        .unwrap()
        .facts
        .into_iter()
        .find(|(name, _)| *name == "On")
    };
    assert_eq!(
        on(&cards),
        Some((
            "On",
            "card 12 345 678, where it needs a touch, which then covers its uses for a time the \
             card sets"
                .to_owned()
        ))
    );
    let mut spare = cards[0].clone();
    spare.serial =
        hedwig_model::text::Serial::try_from("D2760001240103040006876543210000").unwrap();
    if let Some(held) = spare.keys.first_mut() {
        held.touch = Some(hedwig_model::trail::Touch::Off);
    }
    let both = [cards[0].clone(), spare];
    assert_eq!(
        on(&both),
        Some((
            "On",
            "card 12 345 678, where it needs a touch, which then covers its uses for a time the \
             card sets, or card 87 654 321, where it needs no touch: either can sign it, so it \
             counts as a key that needs no touch"
                .to_owned()
        ))
    );
    assert_eq!(on(&[]), None);
}

/// A person whose taskbar does not show Hedwig's icon is told so by a notice of
/// the card's own construction: what still reaches them and where Hedwig is,
/// with opening its window and closing the notice, neither the default. It
/// waits behind every request the core raised, and settles as any card does.
#[test]
fn an_icon_the_taskbar_will_not_show_is_told_behind_what_needs_an_answer() {
    use hedwig_model::trail::Missing as Unseen;

    let refused = Card::unseen(Unseen::Refused, 0);
    assert_eq!(refused.subject, Subject::Unseen(Unseen::Refused));
    assert_eq!(
        refused.heading,
        "Windows' taskbar does not show Hedwig's icon"
    );
    assert_eq!(
        refused.says.as_deref(),
        Some(
            "Hedwig has offered its icon to the taskbar for two minutes; it appears once the \
             taskbar takes it. Until then a request that needs your answer still comes up like \
             this, and everything else that needs you is in Hedwig's window, which starting \
             Hedwig again opens."
        )
    );
    assert_eq!(labels(&refused), ["Open Hedwig", "Close"]);
    assert!(matches!(
        refused.choices.as_slice(),
        [open, close] if matches!(open.does, Does::Proceed) && matches!(close.does, Does::Cancel)
    ));
    assert_eq!(refused.from, None);
    let none = Card::unseen(Unseen::NoTaskbar, 2);
    assert_eq!(
        none.heading,
        "Windows' taskbar is not running, so Hedwig's icon cannot be shown"
    );
    assert!(
        none.says
            .as_deref()
            .unwrap()
            .starts_with("Hedwig's icon appears once the taskbar runs again.")
    );
    assert_eq!(
        none.waiting().as_deref(),
        Some("2 more waiting behind this one")
    );

    // Behind what the core raised; shown, it stays while a request arrives.
    let own = Subject::Unseen(Unseen::Refused);
    let (mut bench, first, _) = connected();
    let request = asks(&mut bench, first);
    let mut deck = Deck::default();
    assert!(deck.settle_with(bench.attention(), Some(&own), 0));
    assert_eq!(deck.showing(), Some(&Subject::Request(request)));
    let mut alone = Deck::default();
    assert!(alone.settle_with(&[], Some(&own), 10));
    assert_eq!(alone.showing(), Some(&own));
    assert!(!alone.armed(10 + 499, 500), "settling as any card does");
    assert!(alone.armed(10 + 500, 500));
    assert!(!alone.settle_with(bench.attention(), Some(&own), 20));
    assert_eq!(alone.showing(), Some(&own));
    // Closed, the request comes up.
    assert!(alone.settle_with(bench.attention(), None, 30));
    assert_eq!(alone.showing(), Some(&Subject::Request(request)));
}

/// A spare `YubiKey`, read for the first time after it signed: the
/// core marks a card's reading stale under the workstation, and the presence
/// reads the cards again under it, so the card for the next request names
/// both cards that hold its key.
#[test]
fn a_cards_first_reading_reaches_the_next_request_card() {
    let (mut bench, _, _) = connected();
    let key = Grip::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap();
    let card = |serial: &str, touch| hedwig_model::trail::Card {
        serial: hedwig_model::text::Serial::try_from(serial).unwrap(),
        keys: vec![hedwig_model::trail::Held {
            grip: key.clone(),
            touch: Some(touch),
        }],
        pin: None,
    };
    bench.desk.trail.push(Happened::Card(card(
        "D2760001240103040006111111110000",
        hedwig_model::trail::Touch::On,
    )));
    refresh(&mut bench);
    bench.desk.trail.push(Happened::Card(card(
        "D2760001240103040006222222220000",
        hedwig_model::trail::Touch::Off,
    )));
    bench.told();
    let read: Vec<&str> = bench
        .seen()
        .workstation
        .as_ref()
        .unwrap()
        .cards
        .iter()
        .map(|card| card.serial.as_str())
        .collect();
    assert_eq!(
        read,
        [
            "D2760001240103040006111111110000",
            "D2760001240103040006222222220000"
        ]
    );
    let named = hedwig_model::text::KeyId::Grip(key.clone());
    assert_eq!(
        words::on_card(&named, bench.seen().keyrings()).as_deref(),
        Some(
            "card 11 111 111, where it needs a touch every time, or card 22 222 222, where it \
             needs no touch: either can sign it, so it counts as a key that needs no touch"
        )
    );
}
