//! How a remote's request is decided: what ships, the person's
//! rules down to one host and one connection, allowances that end, and
//! refusal wherever something is missing.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use hedwig_model::capability::{Exposure, Lends, Operation};
use hedwig_model::config::{Catalogue, Change, Configuration, Denial, Reach};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::policy::{Basis, ConnectionScope, Keys, Mode, RuleScope, Selector, default_mode};
use hedwig_model::protocol::Decision;
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::{Granted, Remotes};
use hedwig_model::trail::{
    ChannelEnd, ClientKind, ConnectionId, Event, Opener, Outcome, Presence, Seq, Tick,
};

mod support;
use support::{DESKTOP, OVER_SSH, Trail, catalogue, decided, granting, name, pattern, remote};

/// What ships: a stream to key management or a secret is confirmed, and
/// everything else notified.
#[test]
fn the_default_confirms_a_stream_to_key_management_or_a_secret_and_notifies_otherwise() {
    let quiet = [
        Exposure::NONE,
        Exposure::KEY_USE,
        Exposure::SERVICE,
        Exposure::SERVICE.with(Exposure::NETWORK),
    ];
    let strict = [
        Exposure::KEY_USE.with(Exposure::KEY_MANAGEMENT),
        Exposure::SECRET,
        Exposure::SECRET.with(Exposure::SERVICE),
    ];
    for exposure in quiet {
        for operation in [Operation::Connect, Operation::Sign, Operation::Decrypt] {
            assert_eq!(default_mode(operation, exposure), Mode::Notify);
        }
    }
    for exposure in strict {
        assert_eq!(default_mode(Operation::Connect, exposure), Mode::Confirm);
        assert_eq!(default_mode(Operation::Sign, exposure), Mode::Notify);
        assert_eq!(default_mode(Operation::Decrypt, exposure), Mode::Notify);
    }
}

fn scope(remotes: Remotes, capability: Option<&str>, operation: Option<Operation>) -> RuleScope {
    RuleScope {
        remotes,
        capability: capability.map_or(Selector::Every, |id| Selector::Only(name(id))),
        operation: operation.map_or(Selector::Every, Selector::Only),
        key: Keys::Every,
    }
}

/// The most specific statement decides: the remote first, then the
/// capability, then the operation; a connection's own rule above them all.
#[test]
fn the_most_specific_statement_decides() {
    let host = remote("coder", "dev/build");
    let gpg = name("gpg");
    let ladder = [
        scope(Remotes::Every, None, None),
        scope(Remotes::Every, None, Some(Operation::Sign)),
        scope(Remotes::Every, Some("gpg"), None),
        scope(Remotes::Every, Some("gpg"), Some(Operation::Sign)),
        scope(Remotes::Route(name("coder")), None, None),
        scope(
            Remotes::Matching {
                route: name("coder"),
                pattern: pattern("dev/*"),
            },
            None,
            None,
        ),
        scope(Remotes::One(host.clone()), None, None),
        scope(
            Remotes::One(host.clone()),
            Some("gpg"),
            Some(Operation::Sign),
        ),
    ];
    let resolved = |standing: &BTreeMap<RuleScope, Mode>,
                    connection: &BTreeMap<ConnectionScope, Mode>| {
        decided(
            standing,
            connection,
            &host,
            &gpg,
            Exposure::KEY_USE,
            Operation::Sign,
        )
    };
    let none = BTreeMap::new();
    assert_eq!(resolved(&BTreeMap::new(), &none).basis, Basis::Default);
    assert_eq!(resolved(&BTreeMap::new(), &none).mode, Mode::Notify);

    // Each rung, added above the ones before, takes over - whichever mode
    // the rungs below it hold.
    let mut standing = BTreeMap::new();
    for (rung, rule) in ladder.iter().enumerate() {
        let mode = if rung % 2 == 0 {
            Mode::Confirm
        } else {
            Mode::Unattended
        };
        standing.insert(rule.clone(), mode);
        let decided = resolved(&standing, &none);
        assert_eq!(decided.basis, Basis::Rule(rule.clone()), "rung {rung}");
        assert_eq!(decided.mode, mode, "rung {rung}");
    }

    let wide = ConnectionScope {
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    };
    let narrow = ConnectionScope {
        capability: Selector::Only(gpg.clone()),
        operation: Selector::Only(Operation::Sign),
        key: Keys::Every,
    };
    let mut connection = BTreeMap::from([(wide.clone(), Mode::Confirm)]);
    assert_eq!(
        resolved(&standing, &connection).basis,
        Basis::Connection(wide)
    );
    connection.insert(narrow.clone(), Mode::Notify);
    let decided = resolved(&standing, &connection);
    assert_eq!(decided.basis, Basis::Connection(narrow));
    assert_eq!(decided.mode, Mode::Notify);

    // A rule for another remote, capability or operation is not a candidate.
    let elsewhere = BTreeMap::from([
        (
            scope(Remotes::Route(name("ssh")), None, None),
            Mode::Confirm,
        ),
        (scope(Remotes::Every, Some("adb"), None), Mode::Confirm),
        (
            scope(Remotes::Every, None, Some(Operation::Decrypt)),
            Mode::Confirm,
        ),
    ]);
    assert_eq!(resolved(&elsewhere, &none).basis, Basis::Default);
}

/// Two patterns can select one remote equally narrowly; then the stricter
/// mode decides, whichever order they were written in.
#[test]
fn equally_specific_statements_resolve_to_the_stricter() {
    let host = remote("coder", "dev/build");
    let by_prefix = scope(
        Remotes::Matching {
            route: name("coder"),
            pattern: pattern("dev/*"),
        },
        None,
        None,
    );
    let by_suffix = scope(
        Remotes::Matching {
            route: name("coder"),
            pattern: pattern("*/build"),
        },
        None,
        None,
    );
    for (first, second) in [(Mode::Confirm, Mode::Notify), (Mode::Notify, Mode::Confirm)] {
        let standing = BTreeMap::from([(by_prefix.clone(), first), (by_suffix.clone(), second)]);
        let decided = decided(
            &standing,
            &BTreeMap::new(),
            &host,
            &name("gpg"),
            Exposure::KEY_USE,
            Operation::Sign,
        );
        assert_eq!(decided.mode, Mode::Confirm);
    }
}

struct Scene {
    catalogue: Catalogue,
    configuration: Configuration,
    trail: Trail,
    connection: ConnectionId,
}

impl Scene {
    /// `gpg` and `gpg-unrestricted` granted to one Coder workspace, a channel
    /// open to it, and nobody attached yet.
    fn new() -> Scene {
        let catalogue = catalogue();
        let host = remote("coder", "dev/build");
        let configuration = granting(
            &catalogue,
            &[
                ("gpg", Granted::One(host.clone())),
                ("gpg-unrestricted", Granted::One(host.clone())),
                ("adb", Granted::One(host.clone())),
            ],
        );
        let mut trail = Trail::started();
        let connection = trail.open(&host, "linux");
        Scene {
            catalogue,
            configuration,
            trail,
            connection,
        }
    }

    fn decide(&self, capability: &str, operation: Operation) -> Verdict {
        self.decide_on(self.connection, capability, operation)
    }

    fn decide_on(
        &self,
        connection: ConnectionId,
        capability: &str,
        operation: Operation,
    ) -> Verdict {
        let state = self.trail.state();
        World {
            catalogue: &self.catalogue,
            configuration: &self.configuration,
            state: &state,
        }
        .decide(
            connection,
            &name(capability),
            operation,
            None,
            self.trail.tick(),
        )
    }

    fn rule(&mut self, scope: RuleScope, mode: Mode) {
        self.configuration
            .apply(&self.catalogue, Change::Rule { scope, mode })
            .expect("the rule is accepted");
    }
}

const SERVED: Verdict = Verdict::Serve(Outcome::Served(Basis::Default));

/// Nothing is served on a guess: each thing that can be missing refuses with
/// its own reason.
#[test]
fn a_request_is_refused_wherever_something_is_missing() {
    let mut scene = Scene::new();
    scene.trail.attach(ClientKind::Interface, DESKTOP);
    let host = remote("coder", "dev/build");

    let gone = ConnectionId(Seq(999));
    assert_eq!(
        scene.decide_on(gone, "gpg", Operation::Sign),
        Verdict::Refuse(Refusal::UnknownConnection(gone))
    );
    assert_eq!(
        scene.decide("gpgg", Operation::Sign),
        Verdict::Refuse(Refusal::UnknownCapability(name("gpgg")))
    );
    assert_eq!(
        scene.decide("ssh-agent", Operation::Sign),
        Verdict::Refuse(Refusal::NotGranted {
            capability: name("ssh-agent"),
            remote: host.clone(),
        })
    );
    assert_eq!(
        scene.decide("adb", Operation::Sign),
        Verdict::Refuse(Refusal::OperationNotInDialect {
            capability: name("adb"),
            operation: Operation::Sign,
        })
    );
    assert_eq!(scene.decide("gpg", Operation::Sign), SERVED);

    let by = scene.trail.attach(ClientKind::Command, DESKTOP);
    scene.trail.push(Event::Paused {
        scope: Remotes::Every,
        by,
    });
    assert_eq!(
        scene.decide("gpg", Operation::Sign),
        Verdict::Refuse(Refusal::Paused)
    );
    scene.trail.push(Event::Resumed {
        scope: Remotes::Every,
        by,
    });
    assert_eq!(scene.decide("gpg", Operation::Sign), SERVED);

    scene
        .configuration
        .apply(
            &scene.catalogue,
            Change::Deny(Denial {
                capability: Selector::Only(name("gpg")),
                remotes: Remotes::One(host.clone()),
            }),
        )
        .unwrap();
    assert_eq!(
        scene.decide("gpg", Operation::Sign),
        Verdict::Refuse(Refusal::NotGranted {
            capability: name("gpg"),
            remote: host,
        })
    );
}

/// With touch off and the PIN cached a remote could sign with nobody
/// watching, so a request nobody would see is refused - unless the person
/// has said this grant runs unattended.
#[test]
fn a_request_nobody_would_see_is_refused_unless_the_person_said_otherwise() {
    let mut scene = Scene::new();
    assert_eq!(
        scene.decide("gpg", Operation::Sign),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );
    assert_eq!(
        scene.decide("gpg-unrestricted", Operation::Connect),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );

    // A script attached to ask for status is not a person.
    scene.trail.attach(ClientKind::Command, DESKTOP);
    assert_eq!(
        scene.decide("gpg", Operation::Sign),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );

    let everywhere = scope(Remotes::Every, Some("gpg"), None);
    scene.rule(everywhere.clone(), Mode::Unattended);
    assert_eq!(
        scene.decide("gpg", Operation::Sign),
        Verdict::Serve(Outcome::Unseen(Basis::Rule(everywhere)))
    );
}

/// The desktop is locked and the person is at a terminal over SSH
/// into the workstation. That terminal reaches them, whatever its session,
/// logon session or integrity level.
#[test]
fn a_locked_desktop_is_not_an_absent_person() {
    let mut scene = Scene::new();
    let interface = scene.trail.attach(ClientKind::Interface, DESKTOP);
    assert_eq!(scene.decide("gpg", Operation::Sign), SERVED);

    scene.trail.push(Event::Presence {
        client: interface,
        presence: Presence::Away,
    });
    assert_eq!(
        scene.decide("gpg", Operation::Sign),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );

    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    assert_eq!(scene.decide("gpg", Operation::Sign), SERVED);

    scene.trail.push(Event::Detached { client: terminal });
    assert_eq!(
        scene.decide("gpg", Operation::Sign),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );
    scene.trail.push(Event::Presence {
        client: interface,
        presence: Presence::Present,
    });
    assert_eq!(scene.decide("gpg", Operation::Sign), SERVED);
}

#[test]
fn the_unrestricted_socket_is_confirmed_when_opened_and_notifies_within() {
    let mut scene = Scene::new();
    scene.trail.attach(ClientKind::Interface, DESKTOP);
    assert_eq!(
        scene.decide("gpg-unrestricted", Operation::Connect),
        Verdict::Hold(Basis::Default)
    );
    assert_eq!(scene.decide("gpg-unrestricted", Operation::Sign), SERVED);
    assert_eq!(scene.decide("gpg", Operation::Connect), SERVED);
    assert_eq!(scene.decide("adb", Operation::Connect), SERVED);
}

/// "Allow this for fifteen minutes" is an answer that stands for a bounded
/// time. It ends at its deadline, with its connection, with the core's run,
/// and the moment the person changes what is granted or how it is decided.
#[test]
#[allow(clippy::too_many_lines, reason = "one case per way an allowance ends")]
fn an_allowance_covers_what_it_names_until_anything_ends_it() {
    let host = remote("coder", "dev/build");
    let confirm = scope(
        Remotes::One(host.clone()),
        Some("gpg"),
        Some(Operation::Sign),
    );
    let held = Verdict::Hold(Basis::Rule(confirm.clone()));
    let covered = Verdict::Serve(Outcome::Covered);
    let allowed = |scene: &mut Scene| {
        let by = scene.trail.attach(ClientKind::Interface, DESKTOP);
        let decision = Decision::For(NonZeroU32::new(900).unwrap());
        scene.trail.push(Event::Allowed {
            connection: scene.connection,
            capability: name("gpg"),
            operation: Operation::Sign,
            until: decision.until(scene.trail.tick()).expect("a deadline"),
            by,
            key: None,
        });
        by
    };
    let fresh = || {
        let mut scene = Scene::new();
        scene.rule(confirm.clone(), Mode::Confirm);
        scene
    };

    let mut scene = fresh();
    scene.trail.attach(ClientKind::Interface, DESKTOP);
    assert_eq!(scene.decide("gpg", Operation::Sign), held);

    // It covers the operation named and no other.
    let mut scene = fresh();
    allowed(&mut scene);
    assert_eq!(scene.decide("gpg", Operation::Sign), covered);
    scene.rule(
        scope(
            Remotes::One(host.clone()),
            Some("gpg"),
            Some(Operation::Decrypt),
        ),
        Mode::Confirm,
    );
    assert!(matches!(
        scene.decide("gpg", Operation::Decrypt),
        Verdict::Hold(_)
    ));

    // Its deadline: covered one millisecond before, held at it.
    let mut scene = fresh();
    allowed(&mut scene);
    scene.trail.wait(899_999);
    assert_eq!(scene.decide("gpg", Operation::Sign), covered);
    scene.trail.wait(1);
    assert_eq!(scene.decide("gpg", Operation::Sign), held);

    // A change to the configuration.
    let mut scene = fresh();
    let by = allowed(&mut scene);
    scene.trail.push(Event::Changed {
        change: Change::Autostart(None),
        by,
        reach: Reach::NoWider,
    });
    assert_eq!(scene.decide("gpg", Operation::Sign), held);

    // An import.
    let mut scene = fresh();
    let by = allowed(&mut scene);
    scene.trail.push(Event::Imported {
        by,
        reach: Reach::NoWider,
    });
    assert_eq!(scene.decide("gpg", Operation::Sign), held);

    // A rule set on the connection, even one that does not itself confirm.
    let mut scene = fresh();
    let by = allowed(&mut scene);
    scene.trail.push(Event::Ruled {
        connection: scene.connection,
        scope: ConnectionScope {
            capability: Selector::Only(name("adb")),
            operation: Selector::Every,
            key: Keys::Every,
        },
        mode: Some(Mode::Notify),
        by,
    });
    assert_eq!(scene.decide("gpg", Operation::Sign), held);

    // A pause, even after it is lifted.
    let mut scene = fresh();
    let by = allowed(&mut scene);
    for event in [
        Event::Paused {
            scope: Remotes::Route(name("coder")),
            by,
        },
        Event::Resumed {
            scope: Remotes::Route(name("coder")),
            by,
        },
    ] {
        scene.trail.push(event);
    }
    assert_eq!(scene.decide("gpg", Operation::Sign), held);

    // The connection ending: the next connection starts with none.
    let mut scene = fresh();
    allowed(&mut scene);
    scene.trail.push(Event::Down {
        connection: scene.connection,
        end: ChannelEnd::Exited {
            status: 255,
            last: None,
        },
    });
    scene.connection = scene.trail.open(&host, "linux");
    assert_eq!(scene.decide("gpg", Operation::Sign), held);

    // The core restarting: nothing allowed in one run carries into the next.
    let mut scene = fresh();
    allowed(&mut scene);
    scene.trail.push(Event::Started {
        version: "0.2.0".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    scene.trail.attach(ClientKind::Interface, DESKTOP);
    scene.connection = scene.trail.open(&host, "linux");
    assert_eq!(scene.decide("gpg", Operation::Sign), held);

    // Nobody reachable: an allowance is not a licence to sign unobserved.
    let mut scene = fresh();
    let by = allowed(&mut scene);
    scene.trail.push(Event::Detached { client: by });
    assert_eq!(
        scene.decide("gpg", Operation::Sign),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );
}

/// An override on one connection ends with that connection, which is what
/// bounds it; the next connection to the same remote is decided as before.
#[test]
fn a_rule_on_one_connection_ends_with_it() {
    let host = remote("coder", "dev/build");
    let mut scene = Scene::new();
    let by = scene.trail.attach(ClientKind::Interface, DESKTOP);
    let everything = ConnectionScope {
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    };
    scene.trail.push(Event::Ruled {
        connection: scene.connection,
        scope: everything.clone(),
        mode: Some(Mode::Confirm),
        by,
    });
    assert_eq!(
        scene.decide("gpg", Operation::Sign),
        Verdict::Hold(Basis::Connection(everything.clone()))
    );
    assert_eq!(
        scene.decide("adb", Operation::Connect),
        Verdict::Hold(Basis::Connection(everything.clone()))
    );

    scene.trail.push(Event::Ruled {
        connection: scene.connection,
        scope: everything.clone(),
        mode: None,
        by,
    });
    assert_eq!(scene.decide("gpg", Operation::Sign), SERVED);

    scene.trail.push(Event::Ruled {
        connection: scene.connection,
        scope: everything,
        mode: Some(Mode::Confirm),
        by,
    });
    scene.trail.push(Event::Down {
        connection: scene.connection,
        end: ChannelEnd::Closed,
    });
    scene.connection = scene.trail.open(&host, "linux");
    assert_eq!(scene.decide("gpg", Operation::Sign), SERVED);
}

/// A capability added for one connection is served on that connection and
/// on no other, and a denial beats it as it beats a grant.
#[test]
fn a_capability_added_for_one_connection_lasts_as_long_as_it() {
    let mut scene = Scene::new();
    scene.trail.attach(ClientKind::Interface, DESKTOP);
    let other = remote("coder", "ops/db");
    let with = ConnectionId(scene.trail.push(Event::Opening {
        remote: other.clone(),
        with: vec![name("openocd")],
        opener: Opener::Grant,
        acknowledged: Exposure::NONE,
        lends: Lends::none(),
    }));
    assert_eq!(scene.decide_on(with, "openocd", Operation::Connect), SERVED);
    assert_eq!(
        scene.decide("openocd", Operation::Connect),
        Verdict::Refuse(Refusal::NotGranted {
            capability: name("openocd"),
            remote: remote("coder", "dev/build"),
        })
    );
    scene
        .configuration
        .apply(
            &scene.catalogue,
            Change::Deny(Denial {
                capability: Selector::Every,
                remotes: Remotes::One(other.clone()),
            }),
        )
        .unwrap();
    assert_eq!(
        scene.decide_on(with, "openocd", Operation::Connect),
        Verdict::Refuse(Refusal::NotGranted {
            capability: name("openocd"),
            remote: other,
        })
    );
}

#[test]
fn a_decision_leaves_an_allowance_only_when_it_says_for_how_long() {
    let now = Tick(1_000);
    assert_eq!(Decision::Once.until(now), None);
    assert_eq!(Decision::Refuse.until(now), None);
    assert_eq!(
        Decision::For(NonZeroU32::new(60).unwrap()).until(now),
        Some(Tick(61_000))
    );
    assert_eq!(
        Decision::For(NonZeroU32::MAX).until(Tick(u64::MAX)),
        Some(Tick(u64::MAX))
    );
}

/// An opening follows the most lenient request it carries, and the
/// organisation's floors over the opening and over each request still hold:
/// a floor of `notify` on every opening keeps a connection from being opened
/// with nobody there, whatever the person marked unattended within it.
#[test]
fn an_opening_follows_what_it_carries_and_the_floors_still_hold() {
    use hedwig_model::policy::{Resolved, Rules, Subject, resolve, resolve_opening};
    use hedwig_model::remote::Sets;
    use hedwig_model::scope::Audience;

    let workspace = remote("coder", "dev/build");
    let gpg = name("gpg");
    let signing = RuleScope {
        remotes: Remotes::One(workspace.clone()),
        capability: Selector::Only(gpg.clone()),
        operation: Selector::Only(Operation::Sign),
        key: Keys::Every,
    };
    let person = BTreeMap::from([(signing.clone(), Mode::Unattended)]);
    let every_opening = RuleScope {
        remotes: Remotes::Every,
        capability: Selector::Every,
        operation: Selector::Only(Operation::Connect),
        key: Keys::Every,
    };
    let subject = |operation| Subject {
        remote: &workspace,
        sets: Sets::NONE,
        capability: &gpg,
        exposure: Exposure::KEY_USE,
        operation,
        used: None,
    };
    let connection = BTreeMap::new();
    let open = |floors: &[(Audience, RuleScope, Mode)]| {
        let rules = Rules {
            person: &person,
            connection: &connection,
            start: &[],
            floors,
        };
        let carried =
            [Operation::Sign, Operation::Decrypt].map(|carried| resolve(&rules, &subject(carried)));
        resolve_opening(&rules, &subject(Operation::Connect), carried)
    };
    assert_eq!(
        open(&[]),
        Resolved {
            mode: Mode::Unattended,
            basis: Basis::Rule(signing.clone()),
        }
    );
    let held = open(&[(Audience::Machine, every_opening.clone(), Mode::Notify)]);
    assert_eq!(held.mode, Mode::Notify);
    assert!(matches!(held.basis, Basis::Limit(ref limited)
        if limited.scope == every_opening && limited.chose == Mode::Unattended));
    let every_signature = RuleScope {
        operation: Selector::Only(Operation::Sign),
        ..every_opening
    };
    let held = open(&[(Audience::Person, every_signature, Mode::Notify)]);
    assert_eq!(held.mode, Mode::Notify);
}
