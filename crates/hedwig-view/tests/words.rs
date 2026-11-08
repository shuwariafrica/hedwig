//! The sentences the surfaces share, and when the desktop can show any.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::time::Duration;

use hedwig_model::capability::{Exposure, Operation};
use hedwig_model::config::{Activation, Grant, Reach};
use hedwig_model::gate::Capped;
use hedwig_model::organisation::{GrantScope, Holding, Limit, Part, Place};
use hedwig_model::policy::{
    Basis, ConnectionScope, KeyName, Keys, Limited, Mode, RuleScope, Selector,
};
use hedwig_model::protocol::{
    Attachment, Attention, Contact, DeviceState, Lendable, Offering, Served, Standing,
};
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::scope::{Audience, Holder};
use hedwig_model::setting::{CapScope, Longest};
use hedwig_model::site::Site;
use hedwig_model::text::{
    Address, DeviceSerial, DeviceSocket, Fingerprint, Grip, KeyId, Mark, Name, Pattern, Port,
    Serial, Words,
};
use hedwig_model::trail::{
    Breakdown, Card, Carriage, Carry, ChannelEnd, ClientId, ClientKind, Dropped, Entry, Event,
    Held, Integrity, Key, Keyring, Origin, Outcome, Presence, PromptKind, RequestId, Seq,
    SignaturePin, Store, Tick, Timestamp, Touch, Uses,
};
use hedwig_view::presence::{Change, Desktop};
use hedwig_view::words::{self, Keyrings};

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

/// A keygrip of forty `digit`s.
fn grip(digit: char) -> Grip {
    Grip::try_from(digit.to_string().repeat(40).as_str()).unwrap()
}

/// A version 4 fingerprint of forty `digit`s.
fn fingerprint(digit: char) -> Fingerprint {
    Fingerprint::try_from(digit.to_string().repeat(40).as_str()).unwrap()
}

fn workspace() -> RemoteId {
    RemoteId {
        route: name("coder"),
        address: Address::try_from("dev/build").unwrap(),
    }
}

/// Every sentence is its own, written for the person: none repeats another,
/// and none leaks a type's name or a field.
#[test]
#[allow(clippy::too_many_lines, reason = "one pass over every vocabulary")]
fn every_sentence_is_distinct_and_written_for_the_person() {
    let mark = Mark::try_from("SHA256:abc").unwrap();
    let mut said: Vec<String> = Vec::new();

    said.extend(
        [Operation::Connect, Operation::Sign, Operation::Decrypt]
            .map(|operation| words::asks(&workspace(), &name("gpg"), operation)),
    );
    let kinds = [
        PromptKind::UnknownHostKey,
        PromptKind::KeyPassphrase,
        PromptKind::Password,
        PromptKind::SecurityKeyPin,
        PromptKind::Challenge,
        PromptKind::AgentConfirmation,
        PromptKind::SecurityKeyTouch,
    ];
    said.extend(kinds.map(|kind| words::prompt(kind).to_owned()));
    let ends = [
        ChannelEnd::Closed,
        ChannelEnd::RemoteGone,
        ChannelEnd::Needs(PromptKind::Password),
        ChannelEnd::HostKeyChanged(mark.clone()),
        ChannelEnd::ForwardRefused,
        ChannelEnd::RouteNotSignedIn,
        ChannelEnd::ClientAbsent,
        ChannelEnd::Unstarted(Words::try_from("Access is denied.").unwrap()),
        ChannelEnd::Exited {
            status: 255,
            last: None,
        },
        ChannelEnd::Exited {
            status: 255,
            last: Some(Words::try_from("Permission denied (publickey).").unwrap()),
        },
        ChannelEnd::Declined(PromptKind::UnknownHostKey),
        ChannelEnd::Unauthenticated(Words::try_from("publickey,keyboard-interactive").unwrap()),
        ChannelEnd::NothingCarried,
        ChannelEnd::Slept,
        ChannelEnd::Reshaped,
    ];
    said.extend(ends.iter().map(words::end));
    let returning = Standing::Returning {
        end: ChannelEnd::Slept,
        wait: None,
    };
    said.push(words::standing(&returning, None));
    said.push(words::standing(&returning, Some(Duration::from_secs(18))));
    said.extend(
        [
            Outcome::Served(Basis::Default),
            Outcome::Unseen(Basis::Default),
            Outcome::Allowed(ClientId(Seq(3))),
            Outcome::Covered,
            Outcome::Refused(Refusal::Declined),
            Outcome::Abandoned,
        ]
        .iter()
        .map(words::outcome),
    );
    said.extend(
        [
            ClientKind::Command,
            ClientKind::Terminal,
            ClientKind::Interface,
            ClientKind::Viewer,
            ClientKind::Prompt,
        ]
        .map(|kind| words::client(kind).to_owned()),
    );
    for audience in [Audience::Machine, Audience::Person] {
        said.push(words::audience(audience).to_owned());
        for part in [Part::Limits, Part::Start, Part::Ask] {
            said.push(words::place(Place { audience, part }));
        }
    }
    said.extend(
        [Mode::Unattended, Mode::Notify, Mode::Confirm].map(|mode| words::mode(mode).to_owned()),
    );
    said.extend(
        [Mode::Unattended, Mode::Notify, Mode::Confirm].map(|mode| words::choose(mode).to_owned()),
    );
    said.extend(
        [
            Activation::OnRequest,
            Activation::WhileRunning,
            Activation::Continuous,
        ]
        .map(|activation| words::activation(activation).to_owned()),
    );
    said.extend(
        [
            Breakdown::Exited { status: 101 },
            Breakdown::Hung,
            Breakdown::Unstarted,
        ]
        .map(words::breakdown),
    );
    said.extend([Store::Trail, Store::Configuration].map(|store| words::store(store).to_owned()));
    let every_exposure = [
        Exposure::KEY_USE,
        Exposure::KEY_MANAGEMENT,
        Exposure::SECRET,
        Exposure::SERVICE,
        Exposure::NETWORK,
    ];
    said.extend(every_exposure.map(words::exposure));
    let remotes = [
        Remotes::Every,
        Remotes::Route(name("coder")),
        Remotes::Matching {
            route: name("coder"),
            pattern: Pattern::try_from("team-*").unwrap(),
        },
        Remotes::One(workspace()),
    ];
    said.extend(remotes.iter().map(words::remotes));
    let bases = [
        Basis::Default,
        Basis::Rule(RuleScope {
            remotes: Remotes::Route(name("coder")),
            capability: Selector::Every,
            operation: Selector::Every,
            key: Keys::Every,
        }),
        Basis::Rule(RuleScope {
            remotes: Remotes::One(workspace()),
            capability: Selector::Only(name("gpg")),
            operation: Selector::Only(Operation::Decrypt),
            key: Keys::Every,
        }),
        Basis::Connection(ConnectionScope {
            capability: Selector::Only(name("gpg")),
            operation: Selector::Every,
            key: Keys::Every,
        }),
        Basis::Rule(RuleScope {
            remotes: Remotes::Every,
            capability: Selector::Every,
            operation: Selector::Only(Operation::Sign),
            key: Keys::NeedingNoTouch,
        }),
        Basis::Rule(RuleScope {
            remotes: Remotes::Set(name("clients")),
            capability: Selector::Only(name("gpg")),
            operation: Selector::Only(Operation::Sign),
            key: Keys::Only(KeyName::Fingerprint(fingerprint('F'))),
        }),
        Basis::Start {
            audience: Audience::Person,
            scope: RuleScope {
                remotes: Remotes::Route(name("coder")),
                capability: Selector::Every,
                operation: Selector::Every,
                key: Keys::Every,
            },
        },
        Basis::Limit(Box::new(Limited {
            audience: Audience::Machine,
            scope: RuleScope {
                remotes: Remotes::Every,
                capability: Selector::Every,
                operation: Selector::Only(Operation::Sign),
                key: Keys::Every,
            },
            chose: Mode::Notify,
            basis: Basis::Default,
        })),
    ];
    said.extend(
        bases
            .iter()
            .map(|basis| words::basis(basis, Keyrings::default())),
    );
    said.extend(
        bases
            .iter()
            .filter_map(|basis| words::under(basis, Keyrings::default())),
    );

    let distinct: BTreeSet<&String> = said.iter().collect();
    assert_eq!(distinct.len(), said.len(), "{said:#?}");
    for text in &said {
        assert_ne!(text, "");
        for leak in ["::", "{", "}", "Some(", "None", "_"] {
            assert!(!text.contains(leak), "{text}");
        }
    }
    assert_eq!(
        words::basis(bases.get(2).unwrap(), Keyrings::default()),
        "your rule for dev/build (coder): gpg, when it asks to decrypt"
    );
    assert_eq!(
        words::basis(bases.get(3).unwrap(), Keyrings::default()),
        "what you set for this connection: gpg, whatever it asks"
    );
    // A statement's key is part of its scope, and a set is named as a set.
    assert_eq!(
        words::basis(bases.get(4).unwrap(), Keyrings::default()),
        "your rule for every remote: everything, when it asks to sign, with a key that needs no \
         touch"
    );
    assert_eq!(
        words::basis(bases.get(5).unwrap(), Keyrings::default()),
        "your rule for the remotes in clients: gpg, when it asks to sign, with the key \
         FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    );
    assert_eq!(
        words::basis(bases.get(6).unwrap(), Keyrings::default()),
        "your organisation's starting point for you, for every remote on coder: everything, \
         whatever it asks"
    );
    assert_eq!(
        words::basis(bases.get(7).unwrap(), Keyrings::default()),
        "your organisation's policy for this machine, for every remote: everything, when it asks \
         to sign"
    );
    assert_eq!(
        words::under(bases.get(7).unwrap(), Keyrings::default()).as_deref(),
        Some("served and shown to you, by Hedwig's default for what this exposes")
    );
    assert_eq!(words::under(&Basis::Default, Keyrings::default()), None);
}

/// What the organisation holds is said with whose it is, and
/// whom it says to ask wherever it named someone; a cap is said with whose
/// it is, the person's own included, and what it covers.
#[test]
fn what_is_held_is_said_with_whose_it_is_and_whom_to_ask() {
    let every = CapScope {
        remotes: Remotes::Every,
        key: Keys::Every,
    };
    let cap = |holder, longest| Capped {
        longest,
        holder,
        scope: every.clone(),
    };
    let quarter = Longest::Seconds(NonZeroU32::new(900).unwrap());
    let machine = Holder::Organisation(Audience::Machine);
    assert_eq!(
        words::capped(&cap(machine, quarter), Keyrings::default()),
        "your organisation's policy for this machine caps an allowance at 15 minutes for every \
         remote"
    );
    assert_eq!(
        words::capped(
            &cap(Holder::Organisation(Audience::Person), Longest::Nothing),
            Keyrings::default()
        ),
        "your organisation's policy for you allows nothing for a time for every remote"
    );
    assert_eq!(
        words::capped(
            &Capped {
                longest: quarter,
                holder: Holder::Person,
                scope: CapScope {
                    remotes: Remotes::One(workspace()),
                    key: Keys::NeedingNoTouch,
                },
            },
            Keyrings::default()
        ),
        "you cap an allowance at 15 minutes for dev/build (coder), with a key that needs no touch"
    );
    assert_eq!(
        words::capped(&cap(Holder::Person, Longest::Nothing), Keyrings::default()),
        "you allow nothing for a time for every remote"
    );

    let inspect = Limit::InspectOnly(GrantScope {
        capability: Selector::Every,
        remotes: Remotes::Every,
    });
    assert_eq!(
        words::holding(
            &Holding {
                holder: machine,
                limit: inspect.clone(),
            },
            Keyrings::default()
        ),
        "your organisation's policy for this machine lets no such grant write a remote tool's \
         configuration"
    );
    assert_eq!(
        words::holding(
            &Holding {
                holder: Holder::Person,
                limit: Limit::Cap {
                    scope: every.clone(),
                    longest: quarter,
                },
            },
            Keyrings::default()
        ),
        "you cap an allowance at 15 minutes for every remote"
    );

    let contacts = [Contact {
        audience: Audience::Machine,
        words: Words::try_from("the service desk, extension 4400").unwrap(),
    }];
    let held = Refusal::Held {
        audience: Audience::Machine,
        limit: Box::new(Limit::Withhold {
            exposure: Exposure::SECRET,
            remotes: Remotes::Every,
        }),
    };
    assert_eq!(
        words::refusal(&held, &contacts),
        "your organisation's policy for this machine serves nothing that exposes secret to this \
         remote. Whom to ask: the service desk, extension 4400"
    );
    // Whom to ask is per audience: the policy for the person named nobody.
    assert_eq!(
        words::refusal(&Refusal::Unread(Audience::Person), &contacts),
        "your organisation's limits for you could not all be read, so nothing is served under \
         them until they can be"
    );
    // The person's own refusal is not the organisation's.
    assert_eq!(
        words::refusal(&Refusal::Paused, &contacts),
        "exposure is paused"
    );
    assert_eq!(
        words::stands(&Standing::Unavailable(held), None, &contacts),
        "cannot be served: your organisation's policy for this machine serves nothing that \
         exposes secret to this remote. Whom to ask: the service desk, extension 4400"
    );
}

/// A request served without asking is announced as what the remote did; an
/// allowance says the key it covers.
#[test]
fn what_was_served_and_what_an_allowance_covers_are_said_plainly() {
    let key = KeyId::Grip(grip('A'));
    assert_eq!(
        words::served(
            &Served {
                payload: None,
                request: RequestId(Seq(12)),
                remote: workspace(),
                capability: name("gpg"),
                operation: Operation::Sign,
                key: Some(key.clone()),
            },
            Keyrings::default()
        ),
        "dev/build (coder) signed with gpg, the key with keygrip \
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    // What a served request asked for, where its dialect reads that.
    assert_eq!(
        words::served(
            &Served {
                payload: Some(hedwig_model::trail::Payload::Signature {
                    namespace: Some(Words::try_from("git").unwrap()),
                }),
                request: RequestId(Seq(13)),
                remote: workspace(),
                capability: name("ssh-agent"),
                operation: Operation::Sign,
                key: None,
            },
            Keyrings::default()
        ),
        "dev/build (coder) signed with ssh-agent, for a signature in git's namespace, as git \
         makes for a commit or a tag"
    );
    assert_eq!(
        words::allowance(
            &name("ssh-agent"),
            Operation::Connect,
            None,
            Keyrings::default()
        ),
        "For that time, every request to use ssh-agent on this connection is served without \
         asking you."
    );
    assert_eq!(
        words::allowance(
            &name("gpg"),
            Operation::Sign,
            Some(&key),
            Keyrings::default()
        ),
        "For that time, every request to sign with gpg with the key with keygrip \
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA on this connection is served without asking \
         you."
    );
}

/// What a card asks for before each key on it is
/// used is said key by key, a card that did not say is never said to need no
/// touch, and what leaving a key untouched costs is said with it.
#[test]
fn a_card_says_what_it_asks_for_before_each_key_and_what_that_costs() {
    let offered = [Offering {
        capability: name("gpg"),
        keyring: Keyring {
            keys: vec![Key {
                ssh: None,
                grip: grip('1'),
                fingerprint: fingerprint('A'),
                primary: fingerprint('A'),
                uses: Uses::SIGN,
                user: None,
                card: Some(Serial::try_from("D2760001240100000006").unwrap()),
            }],
            signing: None,
        },
    }];
    let card = Card {
        serial: Serial::try_from("D2760001240100000006").unwrap(),
        keys: vec![
            Held {
                grip: grip('1'),
                touch: Some(Touch::Off),
            },
            Held {
                grip: grip('2'),
                touch: Some(Touch::Cached),
            },
            Held {
                grip: grip('3'),
                touch: Some(Touch::On),
            },
        ],
        pin: Some(SignaturePin::Once),
    };
    let cards = [card.clone()];
    let keyrings = Keyrings::new(Some(&offered), &cards);
    assert_eq!(
        words::card(&card, keyrings),
        "On card D2760001240100000006, key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA needs no \
         touch; the key with keygrip 2222222222222222222222222222222222222222 needs a touch, \
         which then covers its uses for a time the card sets; the key with keygrip \
         3333333333333333333333333333333333333333 needs a touch every time; the PIN is asked \
         once, not for each signature. A remote you grant can then use a key that needs no touch with nobody \
         at the card, and Hedwig's own asking is the only check. With touch required, you \
         cannot sign while you are away from this machine"
    );
    assert_eq!(
        words::attention(&Attention::Safeguards(card.clone()), keyrings),
        words::card(&card, keyrings)
    );
    // The request card says where its key is and what that card asks for.
    assert_eq!(
        words::on_card(&KeyId::Grip(grip('3')), keyrings).as_deref(),
        Some("card D2760001240100000006, where it needs a touch every time")
    );
    assert_eq!(words::on_card(&KeyId::Grip(grip('9')), keyrings), None);

    // A card whose first application is not OpenPGP's says nothing of what
    // it asks for; nothing is claimed of it.
    let unsaid = Card {
        serial: Serial::try_from("PIV0001").unwrap(),
        keys: vec![Held {
            grip: grip('4'),
            touch: None,
        }],
        pin: None,
    };
    let said = words::card(&unsaid, Keyrings::default());
    assert!(
        said.contains("is used as the card asks, which Hedwig has not read"),
        "{said}"
    );
    assert!(said.contains("so as never to switch your card"), "{said}");
    assert!(!said.contains("needs no touch"), "{said}");
    assert!(!said.contains("nobody at the card"), "{said}");
}

/// What needs the person is said as one sentence each, a refusal in the
/// model's own words with how often.
#[test]
fn what_needs_the_person_is_one_sentence_each() {
    let refused = |times| Attention::Refused {
        remote: Some(workspace()),
        refusal: Refusal::NobodyReachable(Whereabouts::Away),
        times,
    };
    assert_eq!(
        words::attention(&refused(1), Keyrings::default()),
        "Refused once for dev/build (coder): no unlocked desktop and no attended terminal would \
         have shown it to you"
    );
    assert_eq!(
        words::attention(
            &Attention::Refused {
                remote: None,
                refusal: Refusal::NoChannel {
                    process: 4711,
                    program: None,
                },
                times: 40,
            },
            Keyrings::default()
        ),
        "Refused 40 times: process 4711 connected without belonging to the channel Hedwig \
         started there"
    );
    // A stopped connection says what its client last said, where it said
    // anything: that line is where an OpenSSH client gives its reason.
    assert_eq!(
        words::attention(
            &Attention::Stopped {
                remote: workspace(),
                end: ChannelEnd::Exited {
                    status: 255,
                    last: Some(Words::try_from("Permission denied (publickey).").unwrap()),
                },
            },
            Keyrings::default()
        ),
        "The connection to dev/build (coder) stopped: the connection's client ended by itself, \
         with status 255. Its last words: Permission denied (publickey)."
    );
    assert_eq!(
        words::attention(
            &Attention::Restarted {
                cause: Breakdown::Hung,
                times: 2,
            },
            Keyrings::default()
        ),
        "Hedwig broke down and was started again, 2 times: it stopped answering. What was \
         connected or allowed when it ended is gone"
    );
    assert_eq!(
        words::attention(
            &Attention::Unreadable {
                store: Store::Trail,
                account: "line 40 is not an entry".to_owned(),
            },
            Keyrings::default()
        ),
        "The record of what happened could not be read and was set aside: line 40 is not an entry"
    );
}

/// What model version 2 adds to what needs the person: a change another
/// client made, what was served unseen, the organisation's statements
/// changing, a route that cannot list its remotes.
#[test]
fn what_else_needs_the_person_is_one_sentence_each() {
    let origin = Origin {
        process: 4711,
        logon: 99,
        session: 3,
        integrity: Integrity::Medium,
    };
    assert_eq!(
        words::attention(
            &Attention::Widened {
                entry: Entry {
                    seq: Seq(40),
                    at: Timestamp(0),
                    tick: Tick(0),
                    event: Event::Changed {
                        change: hedwig_model::config::Change::Revoke(Grant {
                            capability: name("gpg"),
                            remotes: Granted::Route(name("coder")),
                        }),
                        by: ClientId(Seq(2)),
                        reach: Reach::Wider,
                    },
                },
                kind: ClientKind::Command,
                origin,
            },
            Keyrings::default()
        ),
        "A change that lets more through was made from a command or a script in session 3"
    );
    assert_eq!(
        words::attention(
            &Attention::Unseen {
                remote: workspace(),
                served: 4,
            },
            Keyrings::default()
        ),
        "dev/build (coder) was served 4 times while nothing could reach you, as your rule says"
    );
    assert_eq!(
        words::attention(
            &Attention::Policy {
                place: Place {
                    audience: Audience::Machine,
                    part: Part::Limits,
                },
                since: Seq(7),
                arrived: 2,
                withdrawn: 1,
                unread: 1,
            },
            Keyrings::default()
        ),
        "Your organisation's limits for this machine changed: 2 statements arrived and 1 was \
         withdrawn; 1 of its lines cannot be read, so nothing is served under them"
    );
    assert_eq!(
        words::attention(
            &Attention::Unlisted {
                route: name("coder"),
                account: Words::try_from("coder: not logged in").unwrap(),
            },
            Keyrings::default()
        ),
        "coder could not say which of its remotes are running: coder: not logged in"
    );
}

/// The desktop shows the person something only while it is
/// unlocked and its session connected; closing the RDP window is leaving.
#[test]
fn a_locked_or_disconnected_desktop_shows_the_person_nothing() {
    let mut desktop = Desktop::default();
    assert_eq!(desktop.presence(), Presence::Present);
    let steps = [
        (Change::Locked, Presence::Away),
        (Change::Disconnected, Presence::Away),
        // Reconnecting to a desktop that is still locked is not yet back.
        (Change::Connected, Presence::Away),
        (Change::Unlocked, Presence::Present),
        (Change::Disconnected, Presence::Away),
        (Change::Connected, Presence::Present),
    ];
    for (change, expected) in steps {
        assert_eq!(desktop.apply(change), expected, "{change:?}");
    }
    // An interface started on a locked desktop begins away.
    let locked = Desktop {
        locked: true,
        ..Desktop::default()
    };
    assert_eq!(locked.presence(), Presence::Away);
}

/// A channel coming back by itself says when, counted down and rounded up so
/// it is never sooner than the core opens it: seconds under a minute, then
/// whole minutes, then hours. Each wording says how long it stays true, which
/// is when the window shows the next.
#[test]
fn a_returning_channel_says_when_it_is_opened_again_and_how_long_that_stays_true() {
    let seconds = Duration::from_secs;
    let cases = [
        (
            Duration::from_millis(17_500),
            "in 18 seconds",
            Duration::from_millis(500),
        ),
        (seconds(18), "in 18 seconds", seconds(1)),
        (
            Duration::from_millis(400),
            "in 1 second",
            Duration::from_millis(400),
        ),
        (seconds(60), "in 1 minute", seconds(1)),
        (seconds(61), "in 2 minutes", seconds(1)),
        (seconds(120), "in 2 minutes", seconds(60)),
        (seconds(3600), "in 1 hour", seconds(60)),
        (seconds(3_700), "in 1 hour 2 minutes", seconds(40)),
    ];
    for (left, said, stays) in cases {
        assert_eq!(
            words::again(left),
            Some((said.to_owned(), stays)),
            "{left:?}"
        );
    }
    assert_eq!(words::again(Duration::ZERO), None);
    let returning = Standing::Returning {
        end: ChannelEnd::RemoteGone,
        wait: NonZeroU32::new(18),
    };
    assert_eq!(
        words::standing(&returning, Some(seconds(18))),
        "connecting again by itself in 18 seconds: the remote stopped"
    );
    // Due, or with no wait to count: when is not said.
    assert_eq!(
        words::standing(&returning, None),
        "connecting again by itself: the remote stopped"
    );
}

/// A key is named as the person knows it - whose it is, and its own
/// fingerprint, as `gpg` prints it when it signs - wherever a request, an
/// allowance or a statement names it by the keygrip `gpg-agent` uses; one no
/// source offers is said to be a key the workstation's `GnuPG` does not offer.
/// A statement names a key by fingerprint, a primary's naming its subkeys
/// too, and the keys a statement can name are offered by name.
#[test]
#[allow(clippy::too_many_lines, reason = "every surface that names a key")]
fn a_key_is_named_from_the_keys_the_workstation_offers() {
    let ali = Some(Words::try_from("Ali Rashid <ali@example.org>").unwrap());
    let keyring = Keyring {
        keys: vec![
            Key {
                ssh: None,
                grip: grip('1'),
                fingerprint: fingerprint('A'),
                primary: fingerprint('A'),
                uses: Uses::SIGN,
                user: ali.clone(),
                card: None,
            },
            Key {
                ssh: None,
                grip: grip('2'),
                fingerprint: fingerprint('B'),
                primary: fingerprint('A'),
                uses: Uses::SIGN.with(Uses::AUTHENTICATE),
                user: ali,
                card: None,
            },
            Key {
                ssh: None,
                grip: grip('3'),
                fingerprint: fingerprint('C'),
                primary: fingerprint('C'),
                uses: Uses::ENCRYPT,
                user: None,
                card: None,
            },
        ],
        signing: Some(Mark::try_from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap()),
    };
    let offered = [Offering {
        capability: name("gpg"),
        keyring,
    }];
    let card = Card {
        serial: Serial::try_from("D2760001240100000006").unwrap(),
        keys: vec![Held {
            grip: grip('9'),
            touch: Some(Touch::On),
        }],
        pin: None,
    };
    let cards = [card];
    let keyrings = Keyrings::new(Some(&offered), &cards);
    let a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let b = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    assert_eq!(
        words::key(&KeyId::Grip(grip('1')), keyrings),
        format!("key {a} (Ali Rashid <ali@example.org>)")
    );
    assert_eq!(
        words::key(&KeyId::Grip(grip('2')), keyrings),
        format!("subkey {b} (Ali Rashid <ali@example.org>)")
    );
    assert_eq!(
        words::key(&KeyId::Grip(grip('3')), keyrings),
        "key CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    );
    assert_eq!(
        words::key(&KeyId::Grip(grip('7')), keyrings),
        "the key with keygrip 7777777777777777777777777777777777777777, which is not among the \
         keys this workstation's GnuPG offers"
    );
    // Before the core has said what the workstation offers, nothing is
    // claimed of it.
    assert_eq!(
        words::key(&KeyId::Grip(grip('7')), Keyrings::default()),
        "the key with keygrip 7777777777777777777777777777777777777777"
    );

    // A statement's key: a primary's fingerprint names its subkeys with it.
    assert_eq!(
        words::named(&KeyName::Fingerprint(fingerprint('A')), keyrings),
        format!("key {a} (Ali Rashid <ali@example.org>) and its subkeys")
    );
    assert_eq!(
        words::named(&KeyName::Fingerprint(fingerprint('B')), keyrings),
        format!("subkey {b} (Ali Rashid <ali@example.org>)")
    );
    assert_eq!(
        words::named(&KeyName::Fingerprint(fingerprint('E')), keyrings),
        "the key EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE, which is not among the keys this \
         workstation's GnuPG offers"
    );
    assert_eq!(
        words::named(&KeyName::Grip(grip('2')), keyrings),
        words::key(&KeyId::Grip(grip('2')), keyrings)
    );
    // The key a request used is named in a statement by its own
    // fingerprint where the keyring ties it to one, else by its keygrip.
    assert_eq!(
        keyrings.name(&KeyId::Grip(grip('2'))),
        KeyName::Fingerprint(fingerprint('B'))
    );
    assert_eq!(
        keyrings.name(&KeyId::Grip(grip('9'))),
        KeyName::Grip(grip('9'))
    );
    // Every key a statement can name, each once: each primary with its
    // subkeys after it, then a card's key no keyring offers.
    let named: Vec<KeyName> = keyrings.named().into_iter().map(|(_, name)| name).collect();
    assert_eq!(
        named,
        vec![
            KeyName::Fingerprint(fingerprint('A')),
            KeyName::Fingerprint(fingerprint('B')),
            KeyName::Fingerprint(fingerprint('C')),
            KeyName::Grip(grip('9')),
        ]
    );

    let request = Attention::Request {
        payload: None,
        request: RequestId(Seq(9)),
        remote: workspace(),
        capability: name("gpg"),
        operation: Operation::Sign,
        key: Some(KeyId::Grip(grip('2'))),
        offers: Vec::new(),
        capped: None,
    };
    assert_eq!(
        words::attention(&request, keyrings),
        format!(
            "dev/build (coder) asks to sign with gpg, subkey {b} (Ali Rashid <ali@example.org>)"
        )
    );
    assert_eq!(
        words::allowance(
            &name("gpg"),
            Operation::Sign,
            Some(&KeyId::Grip(grip('1'))),
            keyrings
        ),
        format!(
            "For that time, every request to sign with gpg with key {a} (Ali Rashid \
             <ali@example.org>) on this connection is served without asking you."
        )
    );
    assert_eq!(
        words::basis(
            &Basis::Rule(RuleScope {
                remotes: Remotes::One(workspace()),
                capability: Selector::Only(name("gpg")),
                operation: Selector::Only(Operation::Sign),
                key: Keys::Only(KeyName::Fingerprint(fingerprint('A'))),
            }),
            keyrings
        ),
        format!(
            "your rule for dev/build (coder): gpg, when it asks to sign, with key {a} (Ali \
             Rashid <ali@example.org>) and its subkeys"
        )
    );
    assert_eq!(
        words::served(
            &Served {
                payload: None,
                request: RequestId(Seq(12)),
                remote: workspace(),
                capability: name("gpg"),
                operation: Operation::Sign,
                key: Some(KeyId::Grip(grip('1'))),
            },
            keyrings
        ),
        format!("dev/build (coder) signed with gpg, key {a} (Ali Rashid <ali@example.org>)")
    );
}

/// A sign-in in the workstation's browser reads in the remote's activity by
/// the site, never the URL, with the port carried for its answer and why
/// that ended; a refusal of a page lands on the browser capability's line.
#[test]
fn a_sign_in_reads_by_its_site_and_the_port_carried_for_it() {
    let site: Site = "https://signin.example.org".parse().unwrap();
    assert_eq!(
        words::browsed(&site, Some(Port::try_from(41_007).unwrap())),
        "your browser opened https://signin.example.org, its answer carried back to port 41007 \
         on the remote"
    );
    assert_eq!(
        words::browsed(&site, None),
        "your browser opened https://signin.example.org"
    );
    let ends: BTreeSet<&str> = [Carry::Called, Carry::Expired, Carry::Ended]
        .into_iter()
        .map(words::uncarried)
        .collect();
    assert_eq!(ends.len(), 3);
    assert_eq!(
        words::asks(&workspace(), &name("browser"), Operation::Open),
        "dev/build (coder) asks to open a page in browser"
    );
    let refused = Refusal::UnlistedSite {
        capability: name("browser"),
        site,
    };
    assert_eq!(words::about(&refused), Some(&name("browser")));
}

/// A row whose connection was opened only to check the remote says so,
/// and is never said to be connecting; a service's opening served without
/// asking is said as what the remote used.
#[test]
fn a_check_is_told_from_a_connection_and_a_service_opening_from_a_request() {
    assert_eq!(
        words::standing(&Standing::Checking, None),
        "checking the remote"
    );
    assert_eq!(words::standing(&Standing::Opening, None), "connecting");
    assert_eq!(
        words::served(
            &Served {
                payload: None,
                request: RequestId(Seq(30)),
                remote: workspace(),
                capability: name("playwright"),
                operation: Operation::Connect,
                key: None,
            },
            Keyrings::default()
        ),
        "dev/build (coder) used playwright"
    );
}

/// Where a reverse lands reads as the remote's own port, a host as the remote
/// resolves it, or a socket there; the carried entry names the capability.
#[test]
fn a_carried_reverse_says_where_on_the_remote_a_device_reaches() {
    use hedwig_model::text::{Host, Port, RemotePath};
    use hedwig_model::trail::Target;
    let port = |number| Port::try_from(number).unwrap();
    assert_eq!(
        [
            Target::Loopback(port(8081)),
            Target::Host {
                host: Host::try_from("metro.internal").unwrap(),
                port: port(8081),
            },
            Target::Path(RemotePath::try_from("/tmp/metro.sock").unwrap()),
        ]
        .iter()
        .map(words::target)
        .collect::<Vec<_>>(),
        [
            "port 8081 on the remote",
            "metro.internal port 8081, as the remote resolves it",
            "the socket /tmp/metro.sock on the remote",
        ]
    );
    assert_eq!(
        words::carried(
            &name("adb"),
            &Carriage::Reverse(Target::Loopback(port(8081)))
        ),
        "adb carries a reverse on: a device's connections to it reach port 8081 on the remote"
    );
}

/// A device on a grant's list is said by its model, its serial and how it
/// reaches the workstation, with any state that keeps it from being used:
/// every state the server's listing numbers, one it does not as its number.
#[test]
fn every_device_state_reads_as_what_it_means_for_using_the_device() {
    let device = |state| Lendable {
        serial: Some(DeviceSerial::try_from("R5CR10ABC").unwrap()),
        model: None,
        state,
        attached: Attachment::Usb,
    };
    let said: Vec<String> = (1..=13)
        .map(|number| words::device(&device(DeviceState::numbered(number))))
        .collect();
    assert_eq!(
        said,
        [
            "R5CR10ABC, by USB, connecting",
            "R5CR10ABC, by USB, being authorised",
            "R5CR10ABC, by USB, waiting for you to allow USB debugging on the device",
            "R5CR10ABC, by USB, which the ADB server has no permission to open on this \
             workstation",
            "R5CR10ABC, by USB, detached from the ADB server",
            "R5CR10ABC, by USB, offline",
            "R5CR10ABC, by USB, in its bootloader",
            "R5CR10ABC, by USB",
            "R5CR10ABC, by USB, a host",
            "R5CR10ABC, by USB, in recovery",
            "R5CR10ABC, by USB, sideloading",
            "R5CR10ABC, by USB, in rescue",
            "R5CR10ABC, by USB, in a state Hedwig does not know, which the server numbers 13",
        ]
    );
    let connected = Lendable {
        serial: Some(DeviceSerial::try_from("192.168.1.20:5555").unwrap()),
        model: Some(Words::try_from("Pixel_7").unwrap()),
        state: DeviceState::Device,
        attached: Attachment::Socket,
    };
    assert_eq!(
        words::device(&connected),
        "Pixel_7 (192.168.1.20:5555), connected by its address"
    );
    let unnamed = Lendable {
        serial: None,
        ..connected
    };
    assert_eq!(
        words::device(&unnamed),
        "Pixel_7, which the server lists with no serial, connected by its address"
    );
}

/// What an ADB capability stops carrying reads with why, each reason for a
/// forward and a console in the remote's activity.
#[test]
fn every_reason_a_forward_or_a_console_stopped_reads_as_words() {
    let device = DeviceSerial::try_from("emulator-5554").unwrap();
    let forward = Carriage::Forward {
        port: Port::try_from(7100).unwrap(),
        device: device.clone(),
        socket: DeviceSocket::try_from("localabstract:chrome_devtools_remote").unwrap(),
    };
    let console = Carriage::Console {
        port: Port::try_from(5554).unwrap(),
        device,
    };
    let adb = Name::try_from("adb").unwrap();
    assert_eq!(
        [
            Dropped::Removed,
            Dropped::Gone,
            Dropped::Unlent,
            Dropped::Taken
        ]
        .into_iter()
        .map(|why| words::dropped(&adb, &forward, why))
        .collect::<Vec<_>>(),
        [
            "adb stopped carrying the forward from port 7100 on the remote: the remote removed it",
            "adb stopped carrying the forward from port 7100 on the remote: emulator-5554 left \
             the workstation's ADB server",
            "adb stopped carrying the forward from port 7100 on the remote: emulator-5554 is no \
             longer lent to the remote",
            "adb stopped carrying the forward from port 7100 on the remote: something on the \
             remote took port 7100 while the connection was away",
        ]
    );
    assert_eq!(
        words::dropped(&adb, &console, Dropped::Gone),
        "adb stopped carrying the console of emulator-5554: emulator-5554 left the \
         workstation's ADB server"
    );
    assert_eq!(
        words::carried(&adb, &forward),
        "adb carries a forward on: port 7100 on the remote reaches \
         localabstract:chrome_devtools_remote on emulator-5554"
    );
}

/// A painted surface sets a wrapped line so that it breaks between words:
/// a joiner after each hyphen, slash and question mark inside a word, a
/// zero-width space before a word that begins with a slash, nothing between
/// words and nothing doubled.
#[test]
fn a_wrapped_line_is_set_to_break_between_words() {
    assert_eq!(
        words::unbroken("BROWSER in /home/hedwig-e1/.bashrc"),
        "BROWSER in \u{200B}/\u{2060}home/\u{2060}hedwig-\u{2060}e1/\u{2060}.bashrc"
    );
    assert_eq!(
        words::unbroken("Jean-Paul <step-h@ci.example> at rfc2217://x:1?timeout=3"),
        "Jean-\u{2060}Paul <step-\u{2060}h@ci.example> at \
         rfc2217:/\u{2060}/\u{2060}x:1?\u{2060}timeout=3"
    );
    assert_eq!(words::unbroken("a - b / c"), "a - b \u{200B}/ c");
    let once = words::unbroken("dev/build (coder)");
    assert_eq!(words::unbroken(&once).matches('\u{2060}').count(), 1);
}

/// A person's card key signs through `gpg` and logs in through gpg-agent's SSH
/// socket: the keyring's row names it both ways, the keys a statement can
/// name say its SSH form beside its fingerprint, and a login naming it by its
/// public half says which `GnuPG` key it is.
#[test]
fn a_key_is_named_once_across_gpg_and_ssh() {
    let ssh = hedwig_model::text::SshKey::try_from(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/fZgxPr11UWZgHjQXEU/F65sUwfaohdFFly5gtgRRs",
    )
    .unwrap();
    let ssh_said = "ED25519 key SHA256:QCQxMQ7xhfkHmiFYutwBkf8hKrX/lRA6l2MniD/TvBE";
    let ali = Some(Words::try_from("Ali Rashid <ali@example.org>").unwrap());
    let primary = Key {
        ssh: None,
        grip: grip('1'),
        fingerprint: fingerprint('A'),
        primary: fingerprint('A'),
        uses: Uses::SIGN,
        user: ali.clone(),
        card: None,
    };
    let authenticating = Key {
        ssh: Some(ssh.clone()),
        grip: grip('2'),
        fingerprint: fingerprint('B'),
        primary: fingerprint('A'),
        uses: Uses::AUTHENTICATE,
        user: ali,
        card: None,
    };
    let b = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let subkey = format!("subkey {b} (Ali Rashid <ali@example.org>)");
    assert_eq!(
        words::offered(&authenticating),
        format!("{subkey}, which SSH knows as {ssh_said}")
    );
    assert_eq!(
        words::offered(&primary),
        "key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (Ali Rashid <ali@example.org>)",
        "a key with no SSH form is named as gpg names it"
    );

    let offered = [Offering {
        capability: name("gpg"),
        keyring: Keyring {
            keys: vec![primary, authenticating],
            signing: None,
        },
    }];
    let keyrings = Keyrings::new(Some(&offered), &[]);
    assert_eq!(
        words::ssh_key(&ssh, keyrings),
        format!("{ssh_said}, which GnuPG knows as {subkey}")
    );
    assert_eq!(
        words::key(&KeyId::Ssh(ssh.clone()), keyrings),
        format!("{ssh_said}, which GnuPG knows as {subkey}")
    );
    assert_eq!(
        words::ssh_key(&ssh, Keyrings::default()),
        ssh_said,
        "a key no keyring ties is its SSH form alone"
    );
    let listed: Vec<String> = keyrings.named().into_iter().map(|(said, _)| said).collect();
    assert_eq!(
        listed,
        [
            "key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (Ali Rashid <ali@example.org>) and its \
             subkeys"
                .to_owned(),
            format!("{subkey}, which SSH knows as {ssh_said}"),
        ]
    );

    // A primary SSH knows too: its SSH form is its own, and its subkeys
    // follow the whole.
    let mut signing = offered.clone();
    if let Some(key) = signing[0].keyring.keys.first_mut() {
        key.ssh = Some(ssh.clone());
    }
    let keyrings = Keyrings::new(Some(&signing), &[]);
    assert_eq!(
        words::listed(&KeyName::Fingerprint(fingerprint('A')), keyrings),
        format!(
            "key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (Ali Rashid <ali@example.org>), which SSH \
             knows as {ssh_said}, and its subkeys"
        )
    );
}

/// A remote's git credentials and notices, and keys the TPM holds, are
/// said in words wherever the interface shows them, though they have no
/// surface of their own.
#[test]
fn credentials_notices_and_tpm_keys_read_as_words() {
    let site: Site = "https://github.com".parse().unwrap();
    assert_eq!(
        words::payload(&hedwig_model::trail::Payload::Credential { site: site.clone() }),
        "your credential for https://github.com"
    );
    assert_eq!(
        words::written(&hedwig_model::protocol::Written {
            write: hedwig_model::trail::Write::Helper,
            place: hedwig_model::text::RemotePath::try_from("~/.gitconfig").unwrap(),
            made: None,
        }),
        "git's own credential cache helper at Hedwig's socket, in ~/.gitconfig, after your own \
         helpers"
    );
    let noticed = |unheard| Attention::Noticed {
        remote: workspace(),
        notice: Seq(4),
        at: Timestamp(0),
        remark: hedwig_model::text::Remark::try_from("the nightly build finished").unwrap(),
        unheard,
    };
    assert_eq!(
        words::attention(&noticed(0), Keyrings::default()),
        "dev/build (coder) says: the nightly build finished"
    );
    assert_eq!(
        words::attention(&noticed(1), Keyrings::default()),
        "dev/build (coder) says: the nightly build finished (1 notice before it came too fast \
         and was not passed on)"
    );
    assert_eq!(
        words::attention(&noticed(3), Keyrings::default()),
        "dev/build (coder) says: the nightly build finished (3 notices before it came too fast \
         and were not passed on)"
    );
    // A refusal of a remote's credential lands on its capability's line; a
    // refusal of an act on the TPM lands where the act was made.
    for refusal in [
        Refusal::UnlistedCredential {
            capability: name("git-https"),
            site: site.clone(),
        },
        Refusal::NotWeb {
            capability: name("git-https"),
            protocol: None,
        },
        Refusal::Cleartext {
            capability: name("git-https"),
            site,
        },
    ] {
        assert_eq!(
            words::about(&refusal),
            Some(&name("git-https")),
            "{refusal}"
        );
    }
    assert_eq!(
        words::about(&Refusal::Hushed {
            capability: name("notices")
        }),
        Some(&name("notices"))
    );
    assert_eq!(words::about(&Refusal::NoTpm), None);
    assert_eq!(words::about(&Refusal::KeyExists(name("release"))), None);
}

/// A card's serial reads as `GnuPG`'s prompt for that card prints it, which
/// is how the card is labelled: a `YubiKey`'s own number in groups of three,
/// as a pair of them read "11 111 111" at the agent's prompt; another `OpenPGP`
/// card's maker and number; a standard 20-digit serial without its padding;
/// anything else as the card gives it.
#[test]
fn a_cards_serial_reads_as_the_card_is_labelled() {
    for (given, read) in [
        ("D2760001240103040006111111110000", "11 111 111"),
        ("D2760001240103040006012345670000", "1 234 567"),
        ("D2760001240102010005000012340000", "0005 00001234"),
        ("D2760001240103040006ABCDEF010000", "0006 ABCDEF01"),
        ("D2760001240100000060", "D276000124010000006"),
        ("D2760001240100000006", "D2760001240100000006"),
        ("PIV0001", "PIV0001"),
    ] {
        assert_eq!(
            words::serial(&Serial::try_from(given).unwrap()),
            read,
            "{given}"
        );
    }
}

/// One key on two `YubiKey`s: each card's own sentence says what it
/// asks before the key's use and that the key is on the other card too, what
/// that one asks, and that either can sign it, so it counts as a key that
/// needs no touch where one of them asks none; the request card names both.
/// A card the agent's stub names that Hedwig never read is named as unread,
/// and the key counts as needing no touch while it is. Nothing says which card
/// is in.
#[test]
fn one_key_on_two_cards_is_said_with_every_card_and_how_it_counts() {
    let key = grip('1');
    let card = |serial: &str, touch: Touch| Card {
        serial: Serial::try_from(serial).unwrap(),
        keys: vec![Held {
            grip: key.clone(),
            touch: Some(touch),
        }],
        pin: None,
    };
    let first = card("D2760001240103040006111111110000", Touch::On);
    let spare = card("D2760001240103040006222222220000", Touch::Off);
    let offered = |stub: &str| {
        vec![Offering {
            capability: name("gpg"),
            keyring: Keyring {
                keys: vec![Key {
                    ssh: None,
                    grip: key.clone(),
                    fingerprint: fingerprint('A'),
                    primary: fingerprint('A'),
                    uses: Uses::SIGN,
                    user: None,
                    card: Some(Serial::try_from(stub).unwrap()),
                }],
                signing: None,
            },
        }]
    };
    let stub_first = offered("D2760001240103040006111111110000");
    let both = [first.clone(), spare.clone()];
    let keyrings = Keyrings::new(Some(&stub_first), &both);
    let named = KeyId::Grip(key.clone());
    assert_eq!(
        words::on_card(&named, keyrings).as_deref(),
        Some(
            "card 11 111 111, where it needs a touch every time, or card 22 222 222, where it \
             needs no touch: either can sign it, so it counts as a key that needs no touch"
        )
    );
    assert_eq!(
        words::card(&first, keyrings),
        "On card 11 111 111, key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA needs a touch every \
         time, and is also on card 22 222 222, where it needs no touch: either can sign it, so it \
         counts as a key that needs no touch"
    );
    assert!(
        words::card(&spare, keyrings).starts_with(
            "On card 22 222 222, key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA needs no touch, and \
             is also on card 11 111 111, where it needs a touch every time: either can sign it, so \
             it counts as a key that needs no touch."
        ),
        "{}",
        words::card(&spare, keyrings)
    );

    // Both ask a touch, one cached: either can sign, and it needs a touch.
    let cached = card("D2760001240103040006222222220000", Touch::Cached);
    let touching = [first.clone(), cached];
    assert_eq!(
        words::on_card(&named, Keyrings::new(Some(&stub_first), &touching)).as_deref(),
        Some(
            "card 11 111 111, where it needs a touch every time, or card 22 222 222, where it \
             needs a touch, which then covers its uses for a time the card sets: either can sign it"
        )
    );

    // The spare alone read, the stub naming the first: the first is named as
    // unread, and the key counts as needing no touch while it is.
    let stub_unread = [card("D2760001240103040006222222220000", Touch::On)];
    assert_eq!(
        words::on_card(&named, Keyrings::new(Some(&stub_first), &stub_unread)).as_deref(),
        Some(
            "card 22 222 222, where it needs a touch every time, or card 11 111 111, where it is \
             used as the card asks, which Hedwig has not read: either can sign it, so it counts \
             as a key that needs no touch"
        )
    );
    // No card read at all: the stub's card, unread.
    assert_eq!(
        words::on_card(&named, Keyrings::new(Some(&stub_first), &[])).as_deref(),
        Some("card 11 111 111, where it is used as the card asks, which Hedwig has not read")
    );
    // One card, the stub's: one card, as before.
    let one = [first.clone()];
    assert_eq!(
        words::on_card(&named, Keyrings::new(Some(&stub_first), &one)).as_deref(),
        Some("card 11 111 111, where it needs a touch every time")
    );
    for said in [
        words::on_card(&named, keyrings).unwrap_or_default(),
        words::card(&first, keyrings),
        words::card(&spare, keyrings),
    ] {
        for claim in [" in the workstation", " is in", "inserted", "plugged"] {
            assert!(!said.contains(claim), "{said}");
        }
    }
}
