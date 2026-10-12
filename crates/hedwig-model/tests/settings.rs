//! What a person sets beyond grants and rules: what ships, the scope each
//! statement is made at, and what decides between two. A threshold, a volume,
//! the lengths offered and their cap, what is put away for good, and the card
//! over an application that fills the screen.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
#![allow(
    clippy::redundant_closure_for_method_calls,
    reason = "World's methods are early-bound in its lifetime, so their paths are not general enough"
)]

use std::cmp::Ordering;
use std::num::{NonZeroU8, NonZeroU32};

use hedwig_model::capability::{Exposure, Lends, Operation};
use hedwig_model::config::{
    Activation, BurstEntry, CapEntry, Catalogue, Change, Configuration, Denial, Document, Effect,
    FullScreenEntry, HeardEntry, Reach,
};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::policy::{Basis, ConnectionScope, KeyName, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{Attention, Decision, Needs, Request};
use hedwig_model::refusal::{Refusal, Section, Whereabouts};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::scope::{Holder, Strict};
use hedwig_model::setting::{
    Autostart, Burst, CapScope, Condition, Expected, FullScreen, Heard, Lengths, Longest, Said,
    Threshold, Volume, Waits,
};
use hedwig_model::text::{Grip, KeyId, Mark};
use hedwig_model::trail::{
    ChannelEnd, ClientId, ClientKind, ConnectionId, Event, Finding, Item, Opener, Outcome,
    Presence, PromptKind, Readiness, RequestId, Seq,
};
use hedwig_model::wire::{page, read};

mod support;
use support::{
    DESKTOP, OVER_SSH, Seeded, Trail, catalogue, corpus, grant, granting, name, pattern, remote,
    terms,
};

fn prod() -> RemoteId {
    remote("ssh", "prod-1")
}

fn scratch() -> RemoteId {
    remote("ssh", "scratch-7")
}

fn matching(text: &str) -> Remotes {
    Remotes::Matching {
        route: name("ssh"),
        pattern: pattern(text),
    }
}

fn seconds(number: u32) -> NonZeroU32 {
    NonZeroU32::new(number).unwrap()
}

fn burst(requests: u8, within: u32) -> Threshold {
    Threshold::At(Burst {
        requests: NonZeroU8::new(requests).unwrap(),
        seconds: seconds(within),
    })
}

fn release() -> Grip {
    Grip::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap()
}

fn everyday() -> Grip {
    Grip::try_from("9A8B7C6D5E4F30211203F4E5D6C7B8A990817263").unwrap()
}

/// `gpg` granted to every host on `ssh`, a channel open to `prod-1` and one
/// to `scratch-7`, and nobody attached yet.
struct Scene {
    catalogue: Catalogue,
    configuration: Configuration,
    trail: Trail,
    prod: ConnectionId,
    scratch: ConnectionId,
}

impl Scene {
    fn new() -> Scene {
        let catalogue = catalogue();
        let configuration = granting(&catalogue, &[("gpg", Granted::Route(name("ssh")))]);
        let mut trail = Trail::started();
        let prod = trail.open(&prod(), "linux");
        let scratch = trail.open(&scratch(), "linux");
        Scene {
            catalogue,
            configuration,
            trail,
            prod,
            scratch,
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

    fn set(&mut self, change: Change) {
        self.configuration
            .apply(&self.catalogue, change)
            .expect("the change is accepted");
    }

    fn refused(&self, change: Change) -> Refusal {
        let mut attempt = self.configuration.clone();
        let refusal = attempt
            .apply(&self.catalogue, change)
            .expect_err("must be refused");
        assert_eq!(
            attempt, self.configuration,
            "a refused change changes nothing"
        );
        refusal
    }

    fn sign(&self, connection: ConnectionId, key: Option<&Grip>) -> Verdict {
        let now = self.trail.tick();
        let key = key.cloned().map(KeyId::Grip);
        self.world(|world| {
            world.decide(connection, &name("gpg"), Operation::Sign, key.as_ref(), now)
        })
    }

    /// A signature asked for through `connection`, recorded with what the
    /// gate said of it, as the core does.
    fn asks(&mut self, connection: ConnectionId, key: Option<&Grip>) -> (RequestId, Verdict) {
        let verdict = self.sign(connection, key);
        let request = RequestId(self.trail.push(Event::Asked {
            connection,
            capability: name("gpg"),
            operation: Operation::Sign,
            key: key.cloned().map(KeyId::Grip),
        }));
        match &verdict {
            Verdict::Serve(outcome) => self.trail.push(Event::Settled {
                request,
                outcome: outcome.clone(),
            }),
            Verdict::Hold(_) => self.trail.push(Event::Held { request }),
            Verdict::Refuse(refusal) => self.trail.push(Event::Settled {
                request,
                outcome: Outcome::Refused(refusal.clone()),
            }),
        };
        (request, verdict)
    }

    fn needs(&self, client: ClientId) -> Vec<Needs> {
        let now = self.trail.tick();
        self.world(|world| world.attention(client, now))
    }

    fn attention(&self, client: ClientId) -> Vec<Attention> {
        self.needs(client)
            .into_iter()
            .map(|needs| needs.attention)
            .collect()
    }

    fn confirm_signatures(&mut self) {
        self.set(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::Every,
                capability: Selector::Every,
                operation: Selector::Only(Operation::Sign),
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        });
    }
}

const STRANGER: ClientId = ClientId(Seq(0));

/// Nothing ships as a threshold, so volume alone raises nothing. A threshold
/// is set per remote: a production host and a workspace that signs a
/// release's worth of artefacts do not share a number, and a remote where
/// volume is the work has none.
#[test]
fn a_burst_has_a_threshold_per_remote_or_none_there() {
    let mut scene = Scene::new();
    let threshold = |scene: &Scene, remote: &RemoteId| scene.world(|world| world.threshold(remote));
    assert_eq!(threshold(&scene, &prod()).value, Threshold::Never);
    assert_eq!(threshold(&scene, &prod()).said, Said::Ships);

    scene.set(Change::Burst {
        remotes: Remotes::Every,
        threshold: Some(burst(40, 60)),
    });
    scene.set(Change::Burst {
        remotes: matching("prod-*"),
        threshold: Some(burst(5, 60)),
    });
    scene.set(Change::Burst {
        remotes: Remotes::One(scratch()),
        threshold: Some(Threshold::Never),
    });
    assert_eq!(threshold(&scene, &prod()).value, burst(5, 60));
    assert_eq!(
        threshold(&scene, &prod()).said,
        Said::Person(matching("prod-*"))
    );
    assert_eq!(threshold(&scene, &scratch()).value, Threshold::Never);
    assert_eq!(
        threshold(&scene, &remote("ssh", "build-2")).said,
        Said::Person(Remotes::Every)
    );

    // Ten signatures in a second on each: a burst on the production host,
    // and nothing on the one where volume is the work.
    for _ in 0..10 {
        scene.trail.wait(100);
        scene.trail.ask(scene.prod, "gpg", Operation::Sign);
        scene.trail.ask(scene.scratch, "gpg", Operation::Sign);
    }
    assert_eq!(
        scene.needs(STRANGER),
        [Needs {
            attention: Attention::Burst {
                remote: prod(),
                requests: 10
            },
            volume: Volume::Interrupts,
        }]
    );

    // Saying nothing for the workspace again leaves it to the wider
    // statement.
    scene.set(Change::Burst {
        remotes: Remotes::One(scratch()),
        threshold: None,
    });
    assert_eq!(threshold(&scene, &scratch()).value, burst(40, 60));
}

/// Of two thresholds the one reached at the lower rate is the stricter, and
/// of two at one rate the one fewer requests reach: what decides between two
/// patterns that select a remote equally.
#[test]
fn the_stricter_threshold_is_the_one_reached_sooner() {
    let strictest = |thresholds: &[Threshold]| {
        *thresholds
            .iter()
            .max_by(|one, other| one.strictness(other))
            .unwrap()
    };
    assert_eq!(strictest(&[Threshold::Never, burst(200, 1)]), burst(200, 1));
    assert_eq!(strictest(&[burst(40, 60), burst(5, 60)]), burst(5, 60));
    assert_eq!(strictest(&[burst(10, 60), burst(10, 600)]), burst(10, 600));
    assert_eq!(strictest(&[burst(20, 120), burst(10, 60)]), burst(10, 60));
    assert_eq!(burst(10, 60).strictness(&burst(10, 60)), Ordering::Equal);
    assert_eq!(
        Threshold::Never.strictness(&Threshold::Never),
        Ordering::Equal
    );

    let mut scene = Scene::new();
    for (remotes, threshold) in [
        (matching("prod-*"), burst(40, 60)),
        (matching("*-1"), burst(5, 60)),
    ] {
        scene.set(Change::Burst {
            remotes,
            threshold: Some(threshold),
        });
    }
    assert_eq!(
        scene.world(|world| world.threshold(&prod())).value,
        burst(5, 60)
    );
}

/// What ships: a served request is shown, and everything else that waits is
/// announced once. The person changes each per remote, and the most specific
/// statement decides - which lets a busy workspace be quieter than the rule
/// for everything.
#[test]
fn what_reaches_the_person_is_set_per_remote_and_condition() {
    let mut scene = Scene::new();
    let volume = |scene: &Scene, remote: &RemoteId, condition| {
        scene.world(|world| world.volume(remote, condition))
    };
    for condition in corpus::conditions() {
        let ships = match condition {
            Condition::Served => Volume::Shown,
            _ => Volume::Announced,
        };
        assert_eq!(volume(&scene, &prod(), condition).value, ships);
        assert_eq!(volume(&scene, &prod(), condition).said, Said::Ships);
    }

    scene.set(Change::Hear {
        remotes: Remotes::Every,
        heard: Heard::Unready(Waits::Announced),
    });
    scene.set(Change::Hear {
        remotes: matching("scratch-*"),
        heard: Heard::Unready(Waits::Shown),
    });
    scene.set(Change::Hear {
        remotes: Remotes::One(prod()),
        heard: Heard::Served(Waits::Announced),
    });
    scene.set(Change::Hear {
        remotes: Remotes::One(prod()),
        heard: Heard::HostKeyChanged(Volume::Interrupts),
    });
    assert_eq!(
        volume(&scene, &scratch(), Condition::Unready).value,
        Volume::Shown
    );
    assert_eq!(
        volume(&scene, &prod(), Condition::Unready).value,
        Volume::Announced
    );
    assert_eq!(
        volume(&scene, &prod(), Condition::Served).value,
        Volume::Announced
    );
    assert_eq!(
        volume(&scene, &scratch(), Condition::Served).value,
        Volume::Shown
    );
    assert_eq!(
        volume(&scene, &prod(), Condition::HostKeyChanged).value,
        Volume::Interrupts
    );
    // A statement about one condition says nothing about another.
    assert_eq!(
        volume(&scene, &prod(), Condition::Stopped).said,
        Said::Ships
    );

    // The same statement stated again replaces the volume and nothing else;
    // withdrawing it leaves the wider one.
    scene.set(Change::Hear {
        remotes: matching("scratch-*"),
        heard: Heard::Unready(Waits::Announced),
    });
    assert_eq!(scene.configuration.heard().count(), 4);
    scene.set(Change::Unhear {
        remotes: matching("scratch-*"),
        condition: Condition::Unready,
    });
    assert_eq!(
        volume(&scene, &scratch(), Condition::Unready).said,
        Said::Person(Remotes::Every)
    );
}

/// Detection is the core's, what is announced is the person's choice, and
/// what is shown is not a choice: whatever is stated, every condition is
/// still in what needs the person, and what holds a remote up interrupts.
#[test]
fn nothing_a_person_sets_removes_a_condition_or_quiets_what_holds_a_remote_up() {
    let mut seeded = Seeded(0x0005_e771);
    let scopes = [
        Remotes::Every,
        Remotes::Route(name("ssh")),
        matching("prod-*"),
        Remotes::One(prod()),
    ];
    let mut heard = vec![
        Heard::Served(Waits::Shown),
        Heard::Unready(Waits::Shown),
        Heard::Stopped(Waits::Shown),
        Heard::HostKeyChanged(Volume::Shown),
        Heard::Refused(Waits::Shown),
    ];
    heard.extend(corpus::heard());

    let mut scene = Scene::new();
    scene.confirm_signatures();
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    scene.asks(scene.prod, None);
    scene.trail.push(Event::Checked {
        connection: scene.prod,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![Finding::SigningKeyUnset]),
    });
    scene.trail.push(Event::TurnedAway {
        remote: Some(prod()),
        refusal: Refusal::Unattributable,
    });
    scene.trail.push(Event::Down {
        connection: scene.scratch,
        end: ChannelEnd::Needs(PromptKind::Password),
    });
    let shipped = scene.attention(terminal);
    assert_eq!(shipped.len(), 4);

    for _ in 0..500 {
        let mut scene = Scene {
            catalogue: scene.catalogue.clone(),
            configuration: scene.configuration.clone(),
            trail: Trail {
                entries: scene.trail.entries.clone(),
                now: scene.trail.now,
            },
            prod: scene.prod,
            scratch: scene.scratch,
        };
        for _ in 0..seeded.below(8) {
            scene.set(Change::Hear {
                remotes: seeded.pick(&scopes).clone(),
                heard: *seeded.pick(&heard),
            });
        }
        let needs = scene.needs(terminal);
        let raised: Vec<&Attention> = needs.iter().map(|needs| &needs.attention).collect();
        assert_eq!(raised.len(), 4);
        assert!(shipped.iter().all(|item| raised.contains(&item)));
        for needs in &needs {
            match needs.attention {
                Attention::Request { .. } => assert_eq!(needs.volume, Volume::Interrupts),
                Attention::Stopped { .. } => assert_ne!(needs.volume, Volume::Interrupts),
                _ => {}
            }
        }
        assert!(
            needs.windows(2).all(|pair| match pair {
                [louder, quieter] => louder.volume >= quieter.volume,
                _ => true,
            }),
            "the loudest first"
        );
    }
}

/// A request served with nobody reachable, under a rule that says to, is
/// recorded as that and summed up for the person when they return.
#[test]
fn what_was_served_with_nobody_there_is_summed_up_on_return() {
    let mut scene = Scene::new();
    let everywhere = RuleScope {
        remotes: Remotes::One(prod()),
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    };
    scene.set(Change::Rule {
        scope: everywhere.clone(),
        mode: Mode::Unattended,
    });
    for _ in 0..3 {
        let (_, verdict) = scene.asks(scene.prod, None);
        assert_eq!(
            verdict,
            Verdict::Serve(Outcome::Unseen(Basis::Rule(everywhere.clone())))
        );
    }
    assert_eq!(
        scene.asks(scene.scratch, None).1,
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );

    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    assert_eq!(
        scene.asks(scene.prod, None).1,
        Verdict::Serve(Outcome::Served(Basis::Rule(everywhere))),
        "with the person there it is a served request like any other"
    );
    let raised = scene.attention(terminal);
    assert!(raised.contains(&Attention::Unseen {
        remote: prod(),
        served: 3
    }));
    scene.trail.push(Event::PutAway {
        item: Item::Unseen(prod()),
        by: terminal,
    });
    assert!(
        !scene
            .attention(terminal)
            .iter()
            .any(|item| matches!(item, Attention::Unseen { .. }))
    );

    // What they have not seen is kept across a new run.
    scene.trail.push(Event::Detached { client: terminal });
    scene.asks(scene.prod, None);
    scene.trail.push(Event::Started {
        version: "0.2.0".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    let unseen: Vec<Attention> = scene
        .attention(terminal)
        .into_iter()
        .filter(|item| matches!(item, Attention::Unseen { .. }))
        .collect();
    assert_eq!(
        unseen,
        [Attention::Unseen {
            remote: prod(),
            served: 1
        }]
    );
}

/// "I know this remote asks while I am away": that refusal from that remote
/// is put away for good. It is still recorded and counted, another refusal
/// from the same remote is still raised, and so is the same one from another.
#[test]
fn a_refusal_the_person_expects_from_one_remote_is_put_away_for_good() {
    let mut scene = Scene::new();
    for connection in [scene.prod, scene.scratch] {
        assert_eq!(
            scene.asks(connection, None).1,
            Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
        );
    }
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    assert_eq!(scene.attention(terminal).len(), 2);

    let expected = Expected {
        remote: scratch(),
        refusal: Refusal::NobodyReachable(Whereabouts::Away),
    };
    scene.set(Change::Expect(expected.clone()));
    let refused = |times| Attention::Refused {
        remote: Some(prod()),
        refusal: Refusal::NobodyReachable(Whereabouts::Away),
        times,
    };
    assert_eq!(scene.attention(terminal), [refused(1)]);

    scene.trail.push(Event::Detached { client: terminal });
    for connection in [scene.prod, scene.scratch] {
        scene.asks(connection, None);
    }
    scene.trail.push(Event::TurnedAway {
        remote: Some(scratch()),
        refusal: Refusal::Unattributable,
    });
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    assert_eq!(
        scene.attention(terminal),
        [
            refused(2),
            Attention::Refused {
                remote: Some(scratch()),
                refusal: Refusal::Unattributable,
                times: 1
            }
        ]
    );

    // Taken back, what it hid is there with its count.
    scene.set(Change::Unexpect(expected));
    assert!(scene.attention(terminal).contains(&Attention::Refused {
        remote: Some(scratch()),
        refusal: Refusal::NobodyReachable(Whereabouts::Away),
        times: 2
    }));
    assert_eq!(
        scene.refused(Change::Expect(Expected {
            remote: remote("gitpod", "x"),
            refusal: Refusal::Paused,
        })),
        Refusal::UnknownRoute(name("gitpod"))
    );
}

/// Every greeted client may change anything, and a script is a client. What
/// lets more through reaches the person at every client but the one it was
/// made at; what narrows raises nothing.
#[test]
fn a_change_that_lets_more_through_reaches_the_person_wherever_it_was_not_made() {
    let mut scene = Scene::new();
    let interface = scene.trail.attach(ClientKind::Interface, DESKTOP);
    let script = scene.trail.attach(ClientKind::Command, OVER_SSH);
    let changed = |scene: &mut Scene, change: Change, by: ClientId| {
        let reach = scene.configuration.widens(&scene.catalogue, &change);
        scene.set(change.clone());
        scene.trail.push(Event::Changed { change, by, reach });
        reach
    };
    let widened = |scene: &Scene, client: ClientId| {
        scene
            .attention(client)
            .into_iter()
            .filter(|item| matches!(item, Attention::Widened { .. }))
            .count()
    };

    let denial = Denial {
        capability: Selector::Every,
        remotes: Remotes::One(scratch()),
    };
    assert_eq!(
        changed(&mut scene, Change::Deny(denial.clone()), script),
        Reach::NoWider
    );
    assert_eq!(widened(&scene, interface), 0, "a narrowing raises nothing");

    let give = Change::Grant {
        grant: grant("gpg-unrestricted", Granted::One(prod())),
        terms: terms(
            Activation::Continuous,
            Exposure::KEY_MANAGEMENT.with(Exposure::SECRET),
        ),
    };
    assert_eq!(changed(&mut scene, give, script), Reach::Wider);
    assert_eq!(
        changed(&mut scene, Change::Undeny(denial), script),
        Reach::Wider
    );
    let raised = scene.attention(interface);
    assert!(matches!(
        raised.as_slice(),
        [
            Attention::Widened { entry, kind: ClientKind::Command, origin },
            Attention::Widened { .. },
        ] if matches!(entry.event, Event::Changed { change: Change::Grant { .. }, .. })
            && *origin == OVER_SSH
    ));
    assert_eq!(
        widened(&scene, script),
        0,
        "the client that made them is not told of its own"
    );

    // The person's own change at the interface is news to their terminal and
    // not to the interface.
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    let relax = Change::Rule {
        scope: RuleScope {
            remotes: Remotes::Every,
            capability: Selector::Every,
            operation: Selector::Every,
            key: Keys::Every,
        },
        mode: Mode::Notify,
    };
    assert_eq!(changed(&mut scene, relax, interface), Reach::Wider);
    assert_eq!(widened(&scene, interface), 2);
    assert_eq!(widened(&scene, terminal), 3);

    // Each is put away on its own, and what is not put away outlasts a run.
    let first = scene.attention(terminal).first().and_then(Attention::item);
    scene.trail.push(Event::PutAway {
        item: first.unwrap(),
        by: terminal,
    });
    assert_eq!(widened(&scene, terminal), 2);
    scene.trail.push(Event::Started {
        version: "0.2.0".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    assert_eq!(widened(&scene, terminal), 2);
}

/// The acts that are not changes to the configuration and let more through:
/// a resume, a rule on a connection that does not confirm, and a capability
/// added to a connection.
#[test]
fn a_resume_a_relaxed_connection_and_an_added_capability_are_widenings_too() {
    let mut scene = Scene::new();
    let script = scene.trail.attach(ClientKind::Command, OVER_SSH);
    let interface = scene.trail.attach(ClientKind::Interface, DESKTOP);
    let open = ConnectionScope {
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    };
    let quiet = [
        Event::Paused {
            scope: Remotes::Every,
            by: script,
        },
        Event::Ruled {
            connection: scene.prod,
            scope: open.clone(),
            mode: Some(Mode::Confirm),
            by: script,
        },
        Event::Opening {
            remote: remote("ssh", "build-2"),
            with: Vec::new(),
            opener: Opener::Person(script),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    ];
    for event in quiet {
        scene.trail.push(event);
    }
    assert_eq!(scene.attention(interface), Vec::<Attention>::new());

    let loud = [
        Event::Resumed {
            scope: Remotes::Every,
            by: script,
        },
        Event::Ruled {
            connection: scene.prod,
            scope: open.clone(),
            mode: Some(Mode::Unattended),
            by: script,
        },
        Event::Ruled {
            connection: scene.prod,
            scope: open,
            mode: None,
            by: script,
        },
        Event::Opening {
            remote: remote("ssh", "build-3"),
            with: vec![name("adb")],
            opener: Opener::Person(script),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
        Event::Imported {
            by: script,
            reach: Reach::Wider,
        },
    ];
    let acts = loud.len();
    for event in loud {
        scene.trail.push(event);
    }
    assert_eq!(scene.attention(interface).len(), acts);
    assert_eq!(scene.attention(script), Vec::<Attention>::new());
}

/// A client that changes the configuration in a loop cannot grow what the
/// core holds: the newest sixty-four are kept.
#[test]
fn what_let_more_through_is_bounded_and_the_newest_are_kept() {
    let mut scene = Scene::new();
    let script = scene.trail.attach(ClientKind::Command, OVER_SSH);
    let mut last = Seq(0);
    for _ in 0..1000 {
        last = scene.trail.push(Event::Resumed {
            scope: Remotes::Every,
            by: script,
        });
    }
    let raised = scene.attention(STRANGER);
    assert_eq!(raised.len(), 64);
    assert_eq!(
        raised.last().and_then(Attention::item),
        Some(Item::Widened(last))
    );
}

/// Every change is one that can let more through or one that cannot, judged
/// against the configuration it is made to.
#[test]
#[allow(clippy::too_many_lines, reason = "one case per kind of change")]
fn each_change_is_judged_for_whether_it_lets_more_through() {
    let catalogue = catalogue();
    let route = || Granted::Route(name("coder"));
    let mut configuration = Configuration::default();
    let mut judged = |change: Change| {
        let reach = configuration.widens(&catalogue, &change);
        configuration.apply(&catalogue, change).unwrap();
        reach
    };
    let rule = |remotes: Remotes| RuleScope {
        remotes,
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    };
    let give = |activation| Change::Grant {
        grant: grant("gpg", route()),
        terms: terms(activation, Exposure::NONE),
    };
    let cap = |most| Change::Cap {
        scope: CapScope {
            remotes: Remotes::Every,
            key: Keys::Every,
        },
        longest: most,
    };
    let longest = |number| Some(Longest::Seconds(seconds(number)));

    assert_eq!(judged(give(Activation::WhileRunning)), Reach::Wider);
    assert_eq!(judged(give(Activation::OnRequest)), Reach::NoWider);
    assert_eq!(judged(give(Activation::Continuous)), Reach::Wider);
    let narrower = Change::Grant {
        grant: grant("gpg", Granted::One(prod())),
        terms: terms(Activation::OnRequest, Exposure::NONE),
    };
    assert_eq!(judged(narrower), Reach::Wider, "a grant that was not there");
    assert_eq!(
        judged(Change::Revoke(grant("gpg", Granted::One(prod())))),
        Reach::Wider,
        "the narrowest of two: the wider one's terms now decide"
    );
    assert_eq!(
        judged(Change::Revoke(grant("gpg", route()))),
        Reach::NoWider
    );

    assert_eq!(
        judged(Change::Rule {
            scope: rule(Remotes::Every),
            mode: Mode::Confirm
        }),
        Reach::NoWider
    );
    assert_eq!(
        judged(Change::Rule {
            scope: rule(Remotes::Every),
            mode: Mode::Notify
        }),
        Reach::Wider
    );
    assert_eq!(
        judged(Change::Rule {
            scope: rule(Remotes::Every),
            mode: Mode::Notify
        }),
        Reach::NoWider,
        "said again"
    );
    assert_eq!(judged(Change::Unrule(rule(Remotes::Every))), Reach::Wider);
    assert_eq!(
        judged(Change::Rule {
            scope: rule(Remotes::One(prod())),
            mode: Mode::Unattended
        }),
        Reach::Wider
    );
    assert_eq!(
        judged(Change::Unrule(rule(Remotes::One(prod())))),
        Reach::NoWider,
        "nothing is laxer than what it took away"
    );
    assert_eq!(judged(Change::Unrule(rule(Remotes::Every))), Reach::NoWider);

    assert_eq!(
        judged(cap(longest(900))),
        Reach::NoWider,
        "a cap that was not there"
    );
    assert_eq!(judged(cap(longest(60))), Reach::NoWider);
    assert_eq!(judged(cap(longest(3600))), Reach::Wider);
    assert_eq!(judged(cap(None)), Reach::Wider);
    assert_eq!(judged(cap(Some(Longest::Nothing))), Reach::NoWider);

    // What concerns only what the person is told lets nothing more through.
    for change in [
        Change::Burst {
            remotes: Remotes::Every,
            threshold: Some(Threshold::Never),
        },
        Change::Hear {
            remotes: Remotes::Every,
            heard: Heard::Refused(Waits::Shown),
        },
        Change::FullScreen {
            remotes: Remotes::Every,
            card: Some(FullScreen::NotShown),
        },
        Change::Lengths(Some(Lengths::ships())),
        Change::Autostart(Some(Autostart::AtLogon)),
    ] {
        assert_eq!(judged(change), Reach::NoWider);
    }

    // A set a statement selects, or a route or capability one goes by, is
    // redefined under it.
    let mut configuration = granting(&catalogue, &[("gpg", Granted::Route(name("ssh")))]);
    let fleet = corpus::fleet();
    assert_eq!(
        configuration.widens(&catalogue, &Change::DefineSet(fleet.clone())),
        Reach::NoWider
    );
    configuration
        .apply(&catalogue, Change::DefineSet(fleet.clone()))
        .unwrap();
    configuration
        .apply(
            &catalogue,
            Change::Grant {
                grant: grant("gpg", Granted::Set(name("fleet"))),
                terms: terms(Activation::OnRequest, Exposure::NONE),
            },
        )
        .unwrap();
    assert_eq!(
        configuration.widens(&catalogue, &Change::DefineSet(fleet.clone())),
        Reach::NoWider
    );
    let mut grown = fleet;
    grown.members.pop();
    assert_eq!(
        configuration.widens(&catalogue, &Change::DefineSet(grown)),
        Reach::Wider
    );
    let replaced = configuration.export();
    assert_eq!(
        configuration.widens_to(&Configuration::import(&catalogue, replaced.clone()).unwrap()),
        Reach::NoWider
    );
    assert_eq!(
        configuration.widens_to(&Configuration::default()),
        Reach::Wider
    );
    let mut fewer = replaced;
    fewer.grants.pop();
    assert_eq!(
        configuration.widens_to(&Configuration::import(&catalogue, fewer).unwrap()),
        Reach::NoWider
    );
}

/// One minute, fifteen minutes and one hour ship, the person's to change,
/// and one list serves every surface. The person with time to think caps
/// what the same person can allow in one gesture, per remote or per key; the
/// smallest cap that covers the request is what the card offers up to, and
/// the core accepts no length it did not offer.
#[test]
fn the_lengths_offered_are_the_persons_and_capped_per_remote_or_key() {
    let mut scene = Scene::new();
    scene.confirm_signatures();
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    let shipped: Vec<NonZeroU32> = [60, 900, 3600].into_iter().map(seconds).collect();
    let offered = |scene: &Scene, request: RequestId| {
        scene
            .attention(terminal)
            .into_iter()
            .find_map(|item| match item {
                Attention::Request {
                    request: held,
                    offers,
                    ..
                } if held == request => Some(offers),
                _ => None,
            })
            .expect("the request is held")
    };
    let permit = |scene: &Scene, request: RequestId, length: u32| {
        scene.world(|world| {
            world.permit(
                terminal,
                &Request::Decide {
                    request,
                    decision: Decision::For(seconds(length)),
                },
            )
        })
    };

    assert_eq!(scene.world(|world| world.lengths()).said, Said::Ships);
    let (on_prod, _) = scene.asks(scene.prod, Some(&everyday()));
    let (with_release, _) = scene.asks(scene.prod, Some(&release()));
    let (on_scratch, _) = scene.asks(scene.scratch, Some(&everyday()));
    assert_eq!(offered(&scene, on_prod), shipped);
    assert_eq!(scene.world(|world| world.longest(&prod(), None)), None);

    let cap = |remotes, key, longest| Change::Cap {
        scope: CapScope { remotes, key },
        longest: Some(longest),
    };
    scene.set(cap(
        Remotes::One(prod()),
        Keys::Every,
        Longest::Seconds(seconds(900)),
    ));
    scene.set(cap(
        Remotes::Every,
        Keys::Only(KeyName::Grip(release())),
        Longest::Nothing,
    ));
    scene.set(cap(
        Remotes::Every,
        Keys::Every,
        Longest::Seconds(seconds(7200)),
    ));
    assert_eq!(offered(&scene, on_prod), [seconds(60), seconds(900)]);
    assert_eq!(offered(&scene, on_scratch), shipped);
    assert!(
        offered(&scene, with_release).is_empty(),
        "a cap of nothing removes allow-for-a-time there"
    );
    let capped = scene
        .world(|world| world.longest(&prod(), None))
        .expect("a cap covers it");
    assert_eq!(capped.longest, Longest::Seconds(seconds(900)));
    assert_eq!(capped.holder, Holder::Person);
    assert_eq!(capped.scope.remotes, Remotes::One(prod()));

    assert_eq!(permit(&scene, on_prod, 900), Ok(()));
    assert_eq!(
        permit(&scene, on_prod, 3600),
        Err(Refusal::NotOffered {
            seconds: seconds(3600)
        })
    );
    assert_eq!(
        permit(&scene, on_prod, 61),
        Err(Refusal::NotOffered {
            seconds: seconds(61)
        }),
        "inside the cap and not on the list"
    );
    assert_eq!(
        permit(&scene, with_release, 60),
        Err(Refusal::NotOffered {
            seconds: seconds(60)
        })
    );

    // The person's own list replaces what ships, whole.
    scene.set(Change::Lengths(Some([300, 28_800].into_iter().collect())));
    assert_eq!(offered(&scene, on_prod), [seconds(300)]);
    assert_eq!(
        offered(&scene, on_scratch),
        [seconds(300)],
        "eight hours is past the cap every remote has"
    );
    scene.set(Change::Lengths(Some(Lengths::default())));
    assert_eq!(offered(&scene, on_scratch), Vec::<NonZeroU32>::new());
    scene.set(Change::Lengths(None));
    assert_eq!(offered(&scene, on_scratch), shipped);
}

/// An allowance covers what it was given on: the same key, where the request
/// named one. Allowing a commit's signature for fifteen minutes does not
/// cover the release key.
#[test]
fn an_allowance_covers_the_key_it_was_given_for_and_no_other() {
    let mut scene = Scene::new();
    scene.confirm_signatures();
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    let now = scene.trail.tick();
    scene.trail.push(Event::Allowed {
        connection: scene.prod,
        capability: name("gpg"),
        operation: Operation::Sign,
        key: Some(KeyId::Grip(everyday())),
        until: Decision::For(seconds(900)).until(now).unwrap(),
        by: terminal,
    });
    assert_eq!(
        scene.sign(scene.prod, Some(&everyday())),
        Verdict::Serve(Outcome::Covered)
    );
    assert!(matches!(
        scene.sign(scene.prod, Some(&release())),
        Verdict::Hold(_)
    ));
    assert!(matches!(scene.sign(scene.prod, None), Verdict::Hold(_)));
}

/// A person at the desktop behind an application that fills the screen,
/// with Windows holding notifications back, can be shown a card and nothing
/// else. The card is shown there as it ships; where the person has set it
/// not to be for a remote, that remote's request cannot be put to them at
/// that desktop, and is refused as reaching nobody unless another surface
/// can ask.
#[test]
fn a_request_whose_card_is_not_shown_over_a_full_screen_is_refused_not_lost() {
    let mut scene = Scene::new();
    scene.confirm_signatures();
    let interface = scene.trail.attach(ClientKind::Interface, DESKTOP);
    assert_eq!(
        scene.world(|world| world.full_screen(&prod())).value,
        FullScreen::Shown
    );
    scene.trail.push(Event::Presence {
        client: interface,
        presence: Presence::CardOnly,
    });
    assert!(
        matches!(scene.sign(scene.prod, None), Verdict::Hold(_)),
        "as it ships, the card is shown"
    );

    scene.set(Change::FullScreen {
        remotes: Remotes::Every,
        card: Some(FullScreen::NotShown),
    });
    scene.set(Change::FullScreen {
        remotes: Remotes::One(prod()),
        card: Some(FullScreen::Shown),
    });
    assert!(matches!(scene.sign(scene.prod, None), Verdict::Hold(_)));
    assert_eq!(
        scene.sign(scene.scratch, None),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::FullScreen))
    );

    // What is only shown still is: the person is there.
    scene.set(Change::Rule {
        scope: RuleScope {
            remotes: Remotes::One(scratch()),
            capability: Selector::Every,
            operation: Selector::Every,
            key: Keys::Every,
        },
        mode: Mode::Notify,
    });
    assert!(matches!(
        scene.sign(scene.scratch, None),
        Verdict::Serve(Outcome::Served(_))
    ));
    scene.set(Change::Unrule(RuleScope {
        remotes: Remotes::One(scratch()),
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    }));

    // A request held while the desktop was clear is left with nobody to ask
    // when the application covers it, and is refused rather than left.
    scene.trail.push(Event::Presence {
        client: interface,
        presence: Presence::Present,
    });
    let (held, verdict) = scene.asks(scene.scratch, None);
    assert!(matches!(verdict, Verdict::Hold(_)));
    assert_eq!(
        scene.world(|world| world.stranded()),
        Vec::<(RequestId, Whereabouts)>::new()
    );
    scene.trail.push(Event::Presence {
        client: interface,
        presence: Presence::CardOnly,
    });
    assert_eq!(
        scene.world(|world| world.stranded()),
        [(held, Whereabouts::FullScreen)]
    );

    // A terminal over SSH is another surface, and it can ask.
    scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    assert_eq!(
        scene.world(|world| world.stranded()),
        Vec::<(RequestId, Whereabouts)>::new()
    );
    assert!(matches!(scene.sign(scene.scratch, None), Verdict::Hold(_)));
}

/// A terminal opened to answer one remote's prompts is not the person
/// watching every remote: it reaches them for that remote alone, and is told
/// of that remote alone.
#[test]
fn a_surface_that_watches_some_remotes_reaches_the_person_for_those_alone() {
    let mut scene = Scene::new();
    let terminal = scene
        .trail
        .attach_to(ClientKind::Terminal, OVER_SSH, Remotes::One(prod()));
    assert!(matches!(
        scene.sign(scene.prod, None),
        Verdict::Serve(Outcome::Served(_))
    ));
    assert_eq!(
        scene.sign(scene.scratch, None),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away)),
        "nobody watches the other remote"
    );

    scene.confirm_signatures();
    let (on_prod, _) = scene.asks(scene.prod, None);
    let held = scene.needs(terminal);
    let told = |scene: &Scene, needs: &Needs| scene.world(|world| world.hears(needs));
    assert_eq!(
        told(&scene, held.first().unwrap()),
        [(terminal, Volume::Interrupts)]
    );

    // The desktop watches everything, and so hears of both; the terminal of
    // its own remote alone.
    let interface = scene.trail.attach(ClientKind::Interface, DESKTOP);
    let (on_scratch, _) = scene.asks(scene.scratch, None);
    for needs in scene.needs(interface) {
        let expected = match &needs.attention {
            Attention::Request { request, .. } if *request == on_prod => {
                vec![
                    (terminal, Volume::Interrupts),
                    (interface, Volume::Interrupts),
                ]
            }
            Attention::Request { request, .. } if *request == on_scratch => {
                vec![(interface, Volume::Interrupts)]
            }
            other => unreachable!("{other:?}"),
        };
        assert_eq!(told(&scene, &needs), expected);
    }

    // When the desktop locks, the request for the remote only it watched has
    // nobody left to ask.
    scene.trail.push(Event::Presence {
        client: interface,
        presence: Presence::Away,
    });
    assert_eq!(
        scene.world(|world| world.stranded()),
        [(on_scratch, Whereabouts::Away)]
    );
}

/// What interrupts does so on every attending surface at once. What waits is
/// announced once across them - at the present surface the person was last
/// seen at - and shown on the rest, so a person at the desktop with a
/// terminal attached hears each thing once.
#[test]
fn what_waits_is_announced_on_one_surface_and_shown_on_the_rest() {
    let mut scene = Scene::new();
    let interface = scene.trail.attach(ClientKind::Interface, DESKTOP);
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    scene.trail.attach(ClientKind::Command, OVER_SSH);
    scene.trail.push(Event::Checked {
        connection: scene.prod,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![Finding::ToolAbsent(name("gpgconf"))]),
    });
    let unready = |scene: &Scene| scene.needs(STRANGER).pop().expect("failed readiness");
    let told = |scene: &Scene| scene.world(|world| world.hears(&unready(scene)));
    assert_eq!(unready(&scene).volume, Volume::Announced);
    assert_eq!(
        told(&scene),
        [(interface, Volume::Shown), (terminal, Volume::Announced)],
        "the terminal attached last; a script is told nothing"
    );

    // The person does something at the desktop: they are there.
    scene.trail.push(Event::Paused {
        scope: Remotes::One(scratch()),
        by: interface,
    });
    assert_eq!(
        told(&scene),
        [(interface, Volume::Announced), (terminal, Volume::Shown)]
    );

    // The desktop locks: it shows it when they return, and the terminal
    // announces it.
    scene.trail.push(Event::Presence {
        client: interface,
        presence: Presence::Away,
    });
    assert_eq!(
        told(&scene),
        [(interface, Volume::Shown), (terminal, Volume::Announced)]
    );
    scene.trail.push(Event::Detached { client: terminal });
    assert_eq!(told(&scene), [(interface, Volume::Shown)]);

    // Only shown, by the person's choice: nobody announces it.
    scene.trail.push(Event::Presence {
        client: interface,
        presence: Presence::Present,
    });
    scene.set(Change::Hear {
        remotes: Remotes::One(prod()),
        heard: Heard::Unready(Waits::Shown),
    });
    assert_eq!(told(&scene), [(interface, Volume::Shown)]);

    // A served request is announced where the person asked for that, by the
    // same one surface, and nowhere as it ships.
    assert_eq!(scene.world(|world| world.announces(&prod())), None);
    scene.set(Change::Hear {
        remotes: Remotes::One(prod()),
        heard: Heard::Served(Waits::Announced),
    });
    assert_eq!(
        scene.world(|world| world.announces(&prod())),
        Some(interface)
    );
    assert_eq!(scene.world(|world| world.announces(&scratch())), None);
    scene.trail.push(Event::Presence {
        client: interface,
        presence: Presence::Away,
    });
    assert_eq!(scene.world(|world| world.announces(&prod())), None);
}

/// A changed host key on a host the person names interrupts; elsewhere it
/// waits like any stopped channel.
#[test]
fn a_changed_host_key_interrupts_on_the_hosts_the_person_names() {
    let mut scene = Scene::new();
    let fingerprint = Mark::try_from("SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s").unwrap();
    scene.set(Change::Hear {
        remotes: Remotes::One(prod()),
        heard: Heard::HostKeyChanged(Volume::Interrupts),
    });
    for connection in [scene.prod, scene.scratch] {
        scene.trail.push(Event::Down {
            connection,
            end: ChannelEnd::HostKeyChanged(fingerprint.clone()),
        });
    }
    let volumes: Vec<(RemoteId, Volume)> = scene
        .needs(STRANGER)
        .into_iter()
        .filter_map(|needs| match needs.attention {
            Attention::Stopped { remote, .. } => Some((remote, needs.volume)),
            _ => None,
        })
        .collect();
    assert_eq!(
        volumes,
        [(prod(), Volume::Interrupts), (scratch(), Volume::Announced)]
    );
}

/// Every statement a person makes about a setting names remotes that exist,
/// and an imported document meets the same checks.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one case per section of the document"
)]
fn a_setting_names_a_route_and_a_set_that_exist() {
    let scene = Scene::new();
    let nowhere = Remotes::Route(name("gitpod"));
    let unset = Remotes::Set(name("flet"));
    let changes: [fn(Remotes) -> Change; 4] = [
        |remotes| Change::Burst {
            remotes,
            threshold: Some(Threshold::Never),
        },
        |remotes| Change::Hear {
            remotes,
            heard: Heard::Served(Waits::Announced),
        },
        |remotes| Change::FullScreen {
            remotes,
            card: Some(FullScreen::NotShown),
        },
        |remotes| Change::Cap {
            scope: CapScope {
                remotes,
                key: Keys::Every,
            },
            longest: Some(Longest::Nothing),
        },
    ];
    for change in changes {
        assert_eq!(
            scene.refused(change(nowhere.clone())),
            Refusal::UnknownRoute(name("gitpod"))
        );
        assert_eq!(
            scene.refused(change(unset.clone())),
            Refusal::UnknownSet(name("flet"))
        );
    }

    let good = scene.configuration.export();
    let import = |document: Document| {
        Configuration::import(&scene.catalogue, document).expect_err("must be refused")
    };
    assert_eq!(
        import(Document {
            bursts: vec![BurstEntry {
                remotes: nowhere.clone(),
                threshold: Threshold::Never
            }],
            ..good.clone()
        }),
        Refusal::UnknownRoute(name("gitpod"))
    );
    assert_eq!(
        import(Document {
            caps: vec![CapEntry {
                scope: CapScope {
                    remotes: unset,
                    key: Keys::Every
                },
                longest: Longest::Nothing
            }],
            ..good.clone()
        }),
        Refusal::UnknownSet(name("flet"))
    );

    // A document lists no statement twice.
    let every = Remotes::Every;
    let burst_entry = BurstEntry {
        remotes: every.clone(),
        threshold: Threshold::Never,
    };
    let heard_entry = |heard| HeardEntry {
        remotes: every.clone(),
        heard,
    };
    let card = FullScreenEntry {
        remotes: every.clone(),
        card: FullScreen::Shown,
    };
    let cap = CapEntry {
        scope: CapScope {
            remotes: every.clone(),
            key: Keys::Every,
        },
        longest: Longest::Nothing,
    };
    let expected = Expected {
        remote: prod(),
        refusal: Refusal::Paused,
    };
    let repeated = [
        (
            Document {
                bursts: vec![burst_entry.clone(), burst_entry],
                ..good.clone()
            },
            Section::Bursts,
        ),
        (
            Document {
                heard: vec![
                    heard_entry(Heard::Served(Waits::Shown)),
                    heard_entry(Heard::Served(Waits::Announced)),
                ],
                ..good.clone()
            },
            Section::Heard,
        ),
        (
            Document {
                full_screen: vec![card.clone(), card],
                ..good.clone()
            },
            Section::FullScreen,
        ),
        (
            Document {
                caps: vec![cap.clone(), cap],
                ..good.clone()
            },
            Section::Caps,
        ),
        (
            Document {
                expected: vec![expected.clone(), expected],
                ..good.clone()
            },
            Section::Expected,
        ),
    ];
    for (document, section) in repeated {
        assert_eq!(import(document), Refusal::Repeated(section));
    }
}

/// Whether Hedwig starts at logon is a choice for the workstation: off as it
/// ships, and the person's once they say.
#[test]
fn a_setting_for_the_workstation_is_one_choice() {
    let mut scene = Scene::new();
    let autostart = |scene: &Scene| scene.world(|world| world.autostart());
    assert_eq!(autostart(&scene).value, Autostart::Off);
    assert_eq!(autostart(&scene).said, Said::Ships);
    scene.set(Change::Autostart(Some(Autostart::AtLogon)));
    assert_eq!(autostart(&scene).value, Autostart::AtLogon);
    assert!(matches!(autostart(&scene).said, Said::Person(_)));
    scene.set(Change::Autostart(Some(Autostart::Off)));
    assert_eq!(autostart(&scene).value, Autostart::Off);
    assert!(matches!(autostart(&scene).said, Said::Person(_)));

    // Of two lists the stricter is the one that reaches less far; of two
    // starts, the one that starts less.
    let short: Lengths = [60, 900].into_iter().collect();
    let long: Lengths = [60, 3600].into_iter().collect();
    let more: Lengths = [60, 300, 900].into_iter().collect();
    assert_eq!(short.strictness(&long), Ordering::Greater);
    assert_eq!(short.strictness(&more), Ordering::Greater);
    assert_eq!(Lengths::default().strictness(&short), Ordering::Greater);
    assert_eq!(
        Autostart::Off.strictness(&Autostart::AtLogon),
        Ordering::Greater
    );
    assert_eq!(
        FullScreen::Shown.strictness(&FullScreen::NotShown),
        Ordering::Greater
    );
}

/// Every setting is part of the document: it exports, imports and reads
/// back from its page as the same value, in both directions.
#[test]
fn every_setting_exports_and_imports_as_equality() {
    let catalogue = catalogue();
    let mut configuration = granting(&catalogue, &[("gpg", Granted::Route(name("ssh")))]);
    let mut applied = 0;
    for change in corpus::changes() {
        if configuration.apply(&catalogue, change) == Ok(Effect::Changed) {
            applied += 1;
        }
    }
    assert!(applied > 30);
    // The corpus clears each choice after stating it; state them again.
    let document = corpus::document();
    let bursts = document.bursts.into_iter();
    for BurstEntry { remotes, threshold } in bursts.filter(|entry| entry.remotes.set().is_none()) {
        let change = Change::Burst {
            remotes,
            threshold: Some(threshold),
        };
        configuration.apply(&catalogue, change).unwrap();
    }
    for FullScreenEntry { remotes, card } in document.full_screen {
        let change = Change::FullScreen {
            remotes,
            card: Some(card),
        };
        configuration.apply(&catalogue, change).unwrap();
    }

    let document = configuration.export();
    assert_ne!(document.bursts, Vec::<BurstEntry>::new());
    assert_ne!(document.heard, Vec::<HeardEntry>::new());
    assert_ne!(document.full_screen, Vec::<FullScreenEntry>::new());
    let imported = Configuration::import(&catalogue, document.clone()).unwrap();
    assert_eq!(imported, configuration);
    assert_eq!(imported.export(), document);
    assert_eq!(Configuration::restore(document.clone()), Ok(configuration));

    let text = page(&document);
    let read_back: Document = read(&text).unwrap();
    assert_eq!(read_back, document);
    assert_eq!(page(&read_back), text);

    // The lengths are a set: written shortest first, and no length twice.
    let lengths: Lengths = read("[3600,60,900]").unwrap();
    assert_eq!(hedwig_model::wire::line(&lengths), "[60,900,3600]");
    assert_eq!(
        read::<Lengths>("[60,60]").unwrap_err().to_string(),
        "the value lists the same value twice"
    );
    assert_eq!(
        read::<Lengths>("[0]").unwrap_err().to_string(),
        "0 is out of range"
    );

    // Only a changed host key can be made to interrupt, in its written form
    // as in its type.
    assert!(read::<Heard>(r#"{"host-key-changed":"interrupts"}"#).is_ok());
    assert!(read::<Heard>(r#"{"served":"interrupts"}"#).is_err());
    assert!(read::<Heard>(r#"{"request":"shown"}"#).is_err());
}
