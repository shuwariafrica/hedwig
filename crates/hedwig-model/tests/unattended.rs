//! A grant the person has marked unattended, across the two things that
//! interrupt a core: a new run after a breakdown, and the workstation's
//! sleep. What the person wrote down still holds afterwards; what they said
//! for one connection or one stretch of time does not; and what they stopped
//! stays stopped.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU32;

use hedwig_model::capability::Operation;
use hedwig_model::config::{Catalogue, Change, Configuration};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::policy::{Basis, ConnectionScope, KeyName, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{Attention, Decision};
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::{Granted, Remotes, Sets};
use hedwig_model::text::{Fingerprint, Grip, KeyId, Serial};
use hedwig_model::trail::{
    Breakdown, Card, ClientKind, ConnectionId, Event, Held, Outcome, Store, Touch,
};

mod support;
use support::{DESKTOP, OVER_SSH, Trail, catalogue, granting, name, remote};

struct Scene {
    catalogue: Catalogue,
    configuration: Configuration,
    trail: Trail,
    connection: ConnectionId,
}

/// The rule the person wrote: `gpg` on this one workspace is served with
/// nobody there.
fn written() -> RuleScope {
    RuleScope {
        remotes: Remotes::One(remote("coder", "dev/build")),
        capability: Selector::Only(name("gpg")),
        operation: Selector::Every,
        key: Keys::Every,
    }
}

impl Scene {
    /// `gpg` granted to one Coder workspace and marked unattended there, a
    /// channel open to it, and nobody attached.
    fn new() -> Scene {
        let catalogue = catalogue();
        let host = remote("coder", "dev/build");
        let mut configuration = granting(&catalogue, &[("gpg", Granted::One(host.clone()))]);
        configuration
            .apply(
                &catalogue,
                Change::Rule {
                    scope: written(),
                    mode: Mode::Unattended,
                },
            )
            .unwrap();
        let mut trail = Trail::started();
        let connection = trail.open(&host, "linux");
        Scene {
            catalogue,
            configuration,
            trail,
            connection,
        }
    }

    fn world<T>(&self, ask: impl FnOnce(&World<'_>) -> T) -> T {
        let state = self.trail.state();
        ask(&World {
            catalogue: &self.catalogue,
            configuration: &self.configuration,
            state: &state,
        })
    }

    fn sign(&self) -> Verdict {
        let now = self.trail.tick();
        self.world(|world| world.decide(self.connection, &name("gpg"), Operation::Sign, None, now))
    }

    /// The core broke down and its supervisor started the next.
    fn restart(&mut self, after: Breakdown) {
        self.trail.now = 0;
        self.trail.push(Event::Started {
            version: "0.2.0".to_owned(),
            origin: DESKTOP,
            after: Some(after),
        });
    }

    fn reconnect(&mut self) {
        self.connection = self.trail.open(&remote("coder", "dev/build"), "linux");
    }
}

/// Served with nobody there, and recorded as that.
fn unattended() -> Verdict {
    Verdict::Serve(Outcome::Unseen(Basis::Rule(written())))
}

/// The rule is the person's standing word, kept in the configuration. A core
/// that broke down and was started again serves under it as before, with
/// nobody there - and says that it was restarted to the next person who
/// looks.
#[test]
fn a_rule_the_person_wrote_holds_in_the_run_after_a_breakdown() {
    let mut scene = Scene::new();
    assert_eq!(scene.sign(), unattended());

    scene.restart(Breakdown::Hung);
    // The channel went with the run; its request has nowhere to arrive.
    assert_eq!(
        scene.sign(),
        Verdict::Refuse(Refusal::UnknownConnection(scene.connection))
    );
    scene.reconnect();
    assert_eq!(scene.sign(), unattended());
    let host = remote("coder", "dev/build");
    assert!(!scene.trail.state().reachable(&host, &Sets::NONE));

    scene.restart(Breakdown::Exited { status: 101 });
    scene.reconnect();
    assert_eq!(scene.sign(), unattended());
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    assert_eq!(
        scene.sign(),
        Verdict::Serve(Outcome::Served(Basis::Rule(written()))),
        "with somebody there it is a served request like any other"
    );
    let now = scene.trail.tick();
    let raised: Vec<Attention> = scene
        .world(|world| world.attention(terminal, now))
        .into_iter()
        .map(|needs| needs.attention)
        .collect();
    assert_eq!(
        raised,
        [Attention::Restarted {
            cause: Breakdown::Exited { status: 101 },
            times: 2
        }]
    );
}

/// "Unattended, for this connection" is said to one connection and is gone
/// with it, so it is gone with the run. The next connection is decided as
/// the person's standing rules say: here, refused with nobody there.
#[test]
fn unattended_said_to_one_connection_does_not_cross_a_new_run() {
    let host = remote("coder", "dev/other");
    let catalogue = catalogue();
    let configuration = granting(&catalogue, &[("gpg", Granted::One(host.clone()))]);
    let mut trail = Trail::started();
    let connection = trail.open(&host, "linux");
    let by = trail.attach(ClientKind::Terminal, OVER_SSH);
    let everything = ConnectionScope {
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    };
    trail.push(Event::Ruled {
        connection,
        scope: everything.clone(),
        mode: Some(Mode::Unattended),
        by,
    });
    trail.push(Event::Detached { client: by });
    let mut scene = Scene {
        catalogue,
        configuration,
        trail,
        connection,
    };
    assert_eq!(
        scene.sign(),
        Verdict::Serve(Outcome::Unseen(Basis::Connection(everything)))
    );

    scene.restart(Breakdown::Hung);
    scene.connection = scene.trail.open(&host, "linux");
    assert_eq!(
        scene.sign(),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );
}

/// What the person stopped stays stopped: a pause holds an unattended grant
/// in the run it was set in and in every run after, and so does a trail the
/// core could not read.
#[test]
fn a_pause_and_an_unreadable_trail_hold_an_unattended_grant_across_runs() {
    let mut scene = Scene::new();
    let by = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    scene.trail.push(Event::Paused {
        scope: Remotes::Every,
        by,
    });
    assert_eq!(scene.sign(), Verdict::Refuse(Refusal::Paused));
    scene.restart(Breakdown::Exited { status: 1 });
    scene.reconnect();
    assert_eq!(scene.sign(), Verdict::Refuse(Refusal::Paused));

    let mut scene = Scene::new();
    scene.trail = Trail::default();
    scene.trail.push(Event::Unreadable {
        store: Store::Trail,
        account: "line 3: it is not text".to_owned(),
    });
    scene.restart(Breakdown::Hung);
    scene.reconnect();
    assert_eq!(scene.sign(), Verdict::Refuse(Refusal::Paused));
}

/// The workstation sleeps for an hour and wakes. The run goes on: the rule
/// the person wrote serves as before on the channel that was open. What was
/// timed has run out, because the clock counted the sleep: an allowance
/// given for fifteen minutes before the sleep covers nothing after it.
#[test]
fn a_sleep_leaves_the_rule_standing_and_runs_out_what_was_timed() {
    let mut scene = Scene::new();
    assert_eq!(scene.sign(), unattended());
    scene.trail.push(Event::Sleeping);
    scene.trail.wait(3_600_000);
    scene.trail.push(Event::Woke);
    assert_eq!(scene.sign(), unattended());

    // The same sleep, over a grant that is confirmed and was allowed for
    // fifteen minutes.
    let mut scene = Scene::new();
    scene
        .configuration
        .apply(
            &scene.catalogue,
            Change::Rule {
                scope: written(),
                mode: Mode::Confirm,
            },
        )
        .unwrap();
    let by = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    let decision = Decision::For(NonZeroU32::new(900).unwrap());
    scene.trail.push(Event::Allowed {
        connection: scene.connection,
        capability: name("gpg"),
        operation: Operation::Sign,
        until: decision.until(scene.trail.tick()).unwrap(),
        by,
        key: None,
    });
    assert_eq!(scene.sign(), Verdict::Serve(Outcome::Covered));
    scene.trail.push(Event::Sleeping);
    scene.trail.wait(3_600_000);
    scene.trail.push(Event::Woke);
    assert_eq!(scene.sign(), Verdict::Hold(Basis::Rule(written())));
}

/// What the person writes when only signing is to be served with nobody
/// there: `gpg`, this workspace, `sign`, unattended.
fn signing_alone(key: Keys) -> RuleScope {
    RuleScope {
        operation: Selector::Only(Operation::Sign),
        key,
        ..written()
    }
}

fn scene_with(rules: &[(RuleScope, Mode)], capability: &str) -> Scene {
    let catalogue = catalogue();
    let host = remote("coder", "dev/build");
    let mut configuration = granting(&catalogue, &[(capability, Granted::One(host.clone()))]);
    for (scope, mode) in rules {
        configuration
            .apply(
                &catalogue,
                Change::Rule {
                    scope: scope.clone(),
                    mode: *mode,
                },
            )
            .unwrap();
    }
    let mut trail = Trail::started();
    let connection = trail.open(&host, "linux");
    Scene {
        catalogue,
        configuration,
        trail,
        connection,
    }
}

impl Scene {
    fn ask(&self, capability: &str, operation: Operation, key: Option<&str>) -> Verdict {
        let now = self.trail.tick();
        let key = key.map(|key| KeyId::Grip(Grip::try_from(key).unwrap()));
        self.world(|world| {
            world.decide(
                self.connection,
                &name(capability),
                operation,
                key.as_ref(),
                now,
            )
        })
    }
}

/// The signing key of the keyring the corpus offers.
const GRIP: &str = "64EFB4597F2EB1968F187B7235A461FC48342EC5";
const OTHER: &str = "1F6E5C7F2B3D4051627384A5B6C7D8E9F0A1B2C3";

/// A rule for signing alone serves with nobody there as written: the
/// connection's opening is served under it, since it carries that signature,
/// and recorded as served by that rule; the signature is served; a
/// decryption, which no rule of the person's marks, is refused.
#[test]
fn an_unattended_rule_for_signing_alone_serves_with_nobody_there() {
    let rule = signing_alone(Keys::Every);
    let scene = scene_with(&[(rule.clone(), Mode::Unattended)], "gpg");
    let served = Verdict::Serve(Outcome::Unseen(Basis::Rule(rule)));
    assert_eq!(scene.ask("gpg", Operation::Connect, None), served);
    assert_eq!(scene.ask("gpg", Operation::Sign, Some(GRIP)), served);
    assert_eq!(
        scene.ask("gpg", Operation::Decrypt, Some(GRIP)),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );
}

/// A rule for one key's signatures opens the connection only where the
/// workstation offers that key or a statement names it: here the rule names
/// it. A rule for every key that needs no touch opens it once the source has
/// offered a key, which no card the core has read holds.
#[test]
fn an_opening_follows_a_rule_for_one_key_or_for_keys_needing_no_touch() {
    let one = signing_alone(Keys::Only(KeyName::Grip(Grip::try_from(GRIP).unwrap())));
    let scene = scene_with(&[(one.clone(), Mode::Unattended)], "gpg");
    let served = Verdict::Serve(Outcome::Unseen(Basis::Rule(one)));
    assert_eq!(scene.ask("gpg", Operation::Connect, None), served);
    assert_eq!(scene.ask("gpg", Operation::Sign, Some(GRIP)), served);
    assert_eq!(
        scene.ask("gpg", Operation::Sign, Some(OTHER)),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );

    let untouched = signing_alone(Keys::NeedingNoTouch);
    let mut scene = scene_with(&[(untouched.clone(), Mode::Unattended)], "gpg");
    let refused = Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away));
    assert_eq!(scene.ask("gpg", Operation::Connect, None), refused);
    scene.trail.push(Event::Offered {
        capability: name("gpg"),
        keyring: support::corpus::keyring(),
    });
    let served = Verdict::Serve(Outcome::Unseen(Basis::Rule(untouched)));
    assert_eq!(scene.ask("gpg", Operation::Connect, None), served);
    assert_eq!(scene.ask("gpg", Operation::Sign, Some(GRIP)), served);
}

/// A statement about the opening itself decides it, however the person marked
/// what it carries.
#[test]
fn a_rule_that_names_the_opening_decides_it() {
    let opening = RuleScope {
        operation: Selector::Only(Operation::Connect),
        ..written()
    };
    let scene = scene_with(
        &[
            (signing_alone(Keys::Every), Mode::Unattended),
            (opening, Mode::Confirm),
        ],
        "gpg",
    );
    assert_eq!(
        scene.ask("gpg", Operation::Connect, None),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );
}

/// The unrestricted socket's opening releases key management and secrets,
/// which nothing after it decides: a rule for its signatures does not open
/// it with nobody there. Its opening is decided by what ships: confirmed.
#[test]
fn an_opening_that_releases_more_than_its_requests_is_decided_on_its_own() {
    let rule = RuleScope {
        capability: Selector::Only(name("gpg-unrestricted")),
        ..signing_alone(Keys::Every)
    };
    let scene = scene_with(&[(rule.clone(), Mode::Unattended)], "gpg-unrestricted");
    assert_eq!(
        scene.ask("gpg-unrestricted", Operation::Connect, None),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );
    assert_eq!(
        scene.ask("gpg-unrestricted", Operation::Sign, None),
        Verdict::Serve(Outcome::Unseen(Basis::Rule(rule)))
    );
}

/// With the person there, the opening is served as before and its basis says
/// which statement served it.
#[test]
fn with_the_person_there_the_opening_is_served_and_says_why() {
    let rule = signing_alone(Keys::Every);
    let mut scene = scene_with(&[(rule.clone(), Mode::Confirm)], "gpg");
    scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    assert_eq!(
        scene.ask("gpg", Operation::Connect, None),
        Verdict::Serve(Outcome::Served(Basis::Default))
    );
    assert_eq!(
        scene.ask("gpg", Operation::Sign, None),
        Verdict::Hold(Basis::Rule(rule))
    );
}

/// A rule naming a key by its primary key's fingerprint serves each subkey's
/// request, named by its keygrip, once the source offers the key, and none
/// before. A rule for keys needing no touch stops covering a key once
/// the core has read that its card asks for a touch, even one it then caches.
#[test]
fn a_fingerprint_names_the_offered_subkeys_and_a_card_read_decides_needing_no_touch() {
    let away = Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away));
    let primary = Fingerprint::try_from("07B56DFBBA12BB80FA84939C76F8274EF1651088").unwrap();
    let by_fingerprint = signing_alone(Keys::Only(KeyName::Fingerprint(primary)));
    let mut scene = scene_with(&[(by_fingerprint.clone(), Mode::Unattended)], "gpg");
    assert_eq!(scene.ask("gpg", Operation::Sign, Some(GRIP)), away);
    scene.trail.push(Event::Offered {
        capability: name("gpg"),
        keyring: support::corpus::keyring(),
    });
    let served = Verdict::Serve(Outcome::Unseen(Basis::Rule(by_fingerprint)));
    assert_eq!(scene.ask("gpg", Operation::Sign, Some(GRIP)), served);
    assert_eq!(
        scene.ask(
            "gpg",
            Operation::Sign,
            Some("9A8B7C6D5E4F30211203F4E5D6C7B8A9F0E1D2C3")
        ),
        served,
        "the subkey on the card belongs to the same key"
    );
    assert_eq!(scene.ask("gpg", Operation::Sign, Some(OTHER)), away);

    let untouched = signing_alone(Keys::NeedingNoTouch);
    let mut scene = scene_with(&[(untouched.clone(), Mode::Unattended)], "gpg");
    scene.trail.push(Event::Offered {
        capability: name("gpg"),
        keyring: support::corpus::keyring(),
    });
    scene.trail.push(Event::Card(support::corpus::card()));
    let served = Verdict::Serve(Outcome::Unseen(Basis::Rule(untouched)));
    assert_eq!(
        scene.ask("gpg", Operation::Sign, Some(GRIP)),
        served,
        "touch off"
    );
    assert_eq!(
        scene.ask(
            "gpg",
            Operation::Sign,
            Some("1D3AA6A1A0F4C9B92A3B5F07E6E0D0C3D4E5F601")
        ),
        away,
        "a touch, then cached"
    );
    assert_eq!(
        scene.ask(
            "gpg",
            Operation::Sign,
            Some("9A8B7C6D5E4F30211203F4E5D6C7B8A9F0E1D2C3")
        ),
        served,
        "the card did not say"
    );
}

/// Two cards in serial order, as two `YubiKey`s holding one key:
/// the first sorts before the second, so a reading that took the first card
/// in serial order would decide by it whichever is in.
const FIRST_CARD: &str = "D2760001240103040006111111110000";
const SECOND_CARD: &str = "D2760001240103040006222222220000";

fn on_card(serial: &str, touch: Option<Touch>) -> Event {
    Event::Card(Card {
        serial: Serial::try_from(serial).unwrap(),
        keys: vec![Held {
            grip: Grip::try_from(GRIP).unwrap(),
            touch,
        }],
        pin: None,
    })
}

/// One key on two cards is decided on both, however they were read: under a
/// rule serving keys that need no touch with nobody there, the key is served
/// wherever either card asks no touch or did not say, and not where both ask
/// for one, whichever card was read last.
#[test]
fn one_key_on_two_cards_is_decided_the_same_whichever_card_was_read_last() {
    let away = Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away));
    let untouched = signing_alone(Keys::NeedingNoTouch);
    let served = Verdict::Serve(Outcome::Unseen(Basis::Rule(untouched.clone())));
    let sign = |readings: &[Event]| {
        let mut scene = scene_with(&[(untouched.clone(), Mode::Unattended)], "gpg");
        for reading in readings {
            scene.trail.push(reading.clone());
        }
        scene.ask("gpg", Operation::Sign, Some(GRIP))
    };
    let first_on = on_card(FIRST_CARD, Some(Touch::On));
    let second_off = on_card(SECOND_CARD, Some(Touch::Off));
    assert_eq!(
        sign(std::slice::from_ref(&first_on)),
        away,
        "the first card alone asks a touch"
    );
    assert_eq!(
        sign(&[first_on.clone(), second_off.clone()]),
        served,
        "the second card, which asks none, can sign: the first card in serial order would decide away"
    );
    assert_eq!(
        sign(&[second_off.clone(), first_on.clone()]),
        served,
        "the first card read last"
    );
    assert_eq!(
        sign(&[first_on.clone(), second_off, first_on.clone()]),
        served,
        "the first card read again, the second taken out"
    );
    let second_on = on_card(SECOND_CARD, Some(Touch::On));
    let second_cached = on_card(SECOND_CARD, Some(Touch::Cached));
    let second_unsaid = on_card(SECOND_CARD, None);
    assert_eq!(
        sign(&[first_on.clone(), second_on]),
        away,
        "both ask a touch"
    );
    assert_eq!(
        sign(&[first_on.clone(), second_cached]),
        away,
        "a touch, then cached"
    );
    assert_eq!(
        sign(&[first_on, second_unsaid]),
        served,
        "a card holding the key that did not say"
    );
}

/// The card the agent's stub names is one the key can be signed on: where the
/// core has never read it, nothing is known of what the key meets, whatever
/// the cards it has read say.
#[test]
fn a_key_whose_stub_names_a_card_never_read_needs_no_touch_as_far_as_is_known() {
    let away = Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away));
    let untouched = signing_alone(Keys::NeedingNoTouch);
    let served = Verdict::Serve(Outcome::Unseen(Basis::Rule(untouched.clone())));
    let mut keyring = support::corpus::keyring();
    for key in &mut keyring.keys {
        if key.grip == Grip::try_from(GRIP).unwrap() {
            key.card = Some(Serial::try_from(FIRST_CARD).unwrap());
        }
    }
    let mut scene = scene_with(&[(untouched, Mode::Unattended)], "gpg");
    scene.trail.push(Event::Offered {
        capability: name("gpg"),
        keyring,
    });
    scene.trail.push(on_card(SECOND_CARD, Some(Touch::On)));
    assert_eq!(
        scene.ask("gpg", Operation::Sign, Some(GRIP)),
        served,
        "the stub's card is unread"
    );
    scene.trail.push(on_card(FIRST_CARD, Some(Touch::On)));
    assert_eq!(
        scene.ask("gpg", Operation::Sign, Some(GRIP)),
        away,
        "both read, both ask a touch"
    );
}
