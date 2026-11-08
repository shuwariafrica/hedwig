//! The three kinds of statement and the one way each resolves: a choice by
//! the nearest source and the most specific statement in it, a limit by
//! holding wherever it covers, a set whole or not at all. The first half
//! checks the three over generated cases, with the falsified alternatives
//! kept as negative controls; the second covers the key axis and named sets.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::cmp::Ordering;
use std::collections::BTreeMap;

use hedwig_model::capability::{Exposure, Operation, Setup};
use hedwig_model::config::{Activation, Change, Configuration, Denial, Effect};
use hedwig_model::policy::{
    Attended, Basis, ConnectionScope, KeyName, Keys, Limited, Mode, Resolved, RuleScope, Rules,
    Selector, Subject, Used, default_mode, resolve,
};
use hedwig_model::refusal::{Refusal, Section};
use hedwig_model::remote::{Granted, Member, RemoteId, Remotes, Set, Sets};
use hedwig_model::scope::{
    Audience, Specific, Strict, Tier, admitted, at_least, at_most, choose, nearest,
};
use hedwig_model::text::{Fingerprint, Grip, KeyId};
use hedwig_model::trail::{Key, Touch, Uses};

mod support;
use support::{
    Seeded, capability, catalogue, decided_terms, grant, granting, name, pattern, remote, terms,
};

const MODES: [Mode; 3] = [Mode::Unattended, Mode::Notify, Mode::Confirm];

type Start = Vec<(Audience, RuleScope, Attended)>;
type Floors = Vec<(Audience, RuleScope, Mode)>;

fn rule(remotes: Remotes) -> RuleScope {
    RuleScope {
        remotes,
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    }
}

fn prod() -> RemoteId {
    remote("ssh", "prod-1")
}

fn matching(text: &str) -> Remotes {
    Remotes::Matching {
        route: name("ssh"),
        pattern: pattern(text),
    }
}

/// Every way of stating one of `values`, or nothing, at each of `scopes`.
fn statements<V: Copy>(scopes: &[Remotes], values: &[V]) -> Vec<Vec<(RuleScope, V)>> {
    let mut all: Vec<Vec<(RuleScope, V)>> = vec![Vec::new()];
    for scope in scopes {
        let mut next = Vec::new();
        for stated in &all {
            next.push(stated.clone());
            for value in values {
                let mut with = stated.clone();
                with.push((rule(scope.clone()), *value));
                next.push(with);
            }
        }
        all = next;
    }
    all
}

/// How a signature with `gpg` on `prod-1`, naming no key, is decided.
fn decided(
    person: &BTreeMap<RuleScope, Mode>,
    connection: Option<Mode>,
    start: &[(Audience, RuleScope, Attended)],
    floors: &[(Audience, RuleScope, Mode)],
) -> Resolved {
    let on_connection: BTreeMap<ConnectionScope, Mode> = connection
        .into_iter()
        .map(|mode| {
            let scope = ConnectionScope {
                capability: Selector::Every,
                operation: Selector::Every,
                key: Keys::Every,
            };
            (scope, mode)
        })
        .collect();
    let remote = prod();
    let gpg = name("gpg");
    resolve(
        &Rules {
            person,
            connection: &on_connection,
            start,
            floors,
        },
        &Subject {
            remote: &remote,
            sets: Sets::NONE,
            capability: &gpg,
            exposure: Exposure::KEY_USE,
            operation: Operation::Sign,
            used: None,
        },
    )
}

/// Falsified: a limit as one more statement, ranked above a connection's.
fn ranked_above(choice: Mode, floors: &[(Audience, RuleScope, Mode)]) -> Mode {
    floors
        .iter()
        .max_by_key(|(_, scope, mode)| (scope.remotes.rank(), *mode))
        .map_or(choice, |(_, _, mode)| *mode)
}

/// Falsified: of several limits, the most specific decides.
fn narrowest_limit(choice: Mode, floors: &[(Audience, RuleScope, Mode)]) -> Mode {
    floors
        .iter()
        .max_by_key(|(_, scope, _)| scope.remotes.rank())
        .map_or(choice, |(_, _, mode)| choice.max(*mode))
}

/// Every combination of a person's statements at four scopes, a rule on the
/// connection, an organisation's starting point at two scopes and limits at
/// two: 82,944 cases, a starting point never saying `Unattended`, and the
/// three controls counting what they count here.
#[test]
fn limits_hold_and_choices_stand_over_every_combination() {
    let scopes = [
        Remotes::Every,
        Remotes::Route(name("ssh")),
        matching("prod-*"),
        Remotes::One(prod()),
    ];
    let ends = [Remotes::Every, Remotes::One(prod())];
    let people = statements(&scopes, &MODES);
    let starts = statements(&ends, &[Attended::Notify, Attended::Confirm]);
    let connections = [None, Some(MODES[0]), Some(MODES[1]), Some(MODES[2])];
    // A limit of `Unattended` limits nothing, so a limit is notify or confirm.
    let limit = [None, Some(Mode::Notify), Some(Mode::Confirm)];

    let mut cases = 0u64;
    let (mut rank_loosened, mut narrow_undercut, mut pool_loosened) = (0u64, 0u64, 0u64);
    for person in &people {
        let own: BTreeMap<RuleScope, Mode> = person.iter().cloned().collect();
        for connection in connections {
            let alone = decided(&own, connection, &[], &[]);
            for stated in &starts {
                let start: Start = stated
                    .iter()
                    .map(|(scope, attended)| (Audience::Machine, scope.clone(), *attended))
                    .collect();
                let chosen = decided(&own, connection, &start, &[]);
                if alone.basis != Basis::Default {
                    assert_eq!(
                        chosen, alone,
                        "a starting point never changes what a person's statement decides"
                    );
                }
                let turned: Start = start.iter().rev().cloned().collect();
                assert_eq!(decided(&own, connection, &turned, &[]), chosen);

                // Falsified: one pool of the organisation's and the person's
                // statements, resolved by specificity alone.
                let mut pool = own.clone();
                for (_, scope, attended) in &start {
                    pool.entry(scope.clone()).or_insert(Mode::from(*attended));
                }
                let pooled = decided(&pool, connection, &[], &[]);
                if alone.basis != Basis::Default && pooled.mode < alone.mode {
                    pool_loosened += 1;
                }

                for wide in limit {
                    for narrow in limit {
                        cases += 1;
                        let mut floors: Floors = wide
                            .into_iter()
                            .map(|mode| (Audience::Machine, rule(Remotes::Every), mode))
                            .collect();
                        let without_narrow = decided(&own, connection, &start, &floors);
                        floors.extend(
                            narrow.map(|mode| (Audience::Person, rule(Remotes::One(prod())), mode)),
                        );
                        let effective = decided(&own, connection, &start, &floors);
                        let strictest = floors.iter().map(|(_, _, mode)| *mode).max();

                        assert!(
                            strictest.is_none_or(|floor| effective.mode >= floor),
                            "every limit that covers the remote holds"
                        );
                        assert!(
                            effective.mode >= chosen.mode,
                            "a limit never makes a request less strictly decided"
                        );
                        if strictest.is_none_or(|floor| chosen.mode >= floor) {
                            assert_eq!(
                                effective, chosen,
                                "a choice already inside every limit is left as it was made"
                            );
                        }
                        assert!(
                            effective.mode >= without_narrow.mode,
                            "a further limit never loosens"
                        );
                        let turned: Floors = floors.iter().rev().cloned().collect();
                        assert_eq!(decided(&own, connection, &start, &turned), effective);

                        if ranked_above(chosen.mode, &floors) < chosen.mode {
                            rank_loosened += 1;
                        }
                        let by_narrowest = narrowest_limit(chosen.mode, &floors);
                        if strictest.is_some_and(|floor| by_narrowest < floor) {
                            narrow_undercut += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 82_944);
    // The three controls: each alternative, run over the same cases, does
    // what it was rejected for.
    assert_eq!(
        rank_loosened, 12_292,
        "a limit ranked above a connection's rule loosens what the person chose"
    );
    assert_eq!(
        narrow_undercut, 6_143,
        "the most specific limit deciding lets a narrow limit undercut a wide one"
    );
    assert_eq!(
        pool_loosened, 63,
        "one pool loosens a person's wider, stricter statement"
    );
}

/// The person confirms on one remote; "no less than notify"
/// written as the highest-ranked statement there is lowers that to notify,
/// and as a limit leaves it.
#[test]
fn a_limit_written_as_the_top_ranked_statement_loosens_and_as_a_limit_does_not() {
    let confirm_here = BTreeMap::from([(rule(Remotes::One(prod())), Mode::Confirm)]);
    let as_a_rule = decided(&confirm_here, Some(Mode::Notify), &[], &[]);
    assert_eq!(as_a_rule.mode, Mode::Notify);

    let floor = [(Audience::Machine, rule(Remotes::Every), Mode::Notify)];
    let as_a_limit = decided(&confirm_here, None, &[], &floor);
    assert_eq!(as_a_limit.mode, Mode::Confirm);
    assert_eq!(as_a_limit.basis, Basis::Rule(rule(Remotes::One(prod()))));

    // A limit that does move the choice says so, with what the choice was.
    let notify_here = BTreeMap::from([(rule(Remotes::One(prod())), Mode::Notify)]);
    let floor = [(Audience::Machine, rule(Remotes::Every), Mode::Confirm)];
    assert_eq!(
        decided(&notify_here, None, &[], &floor),
        Resolved {
            mode: Mode::Confirm,
            basis: Basis::Limit(Box::new(Limited {
                audience: Audience::Machine,
                scope: rule(Remotes::Every),
                chose: Mode::Notify,
                basis: Basis::Rule(rule(Remotes::One(prod()))),
            })),
        }
    );
}

/// The other ordered terms take the same limit
/// from the other side, and a value already inside it is left alone.
#[test]
fn a_limit_from_above_holds_a_term_at_the_most_and_leaves_a_lesser_one() {
    let most = |asked, ceiling| at_most(asked, [("the organisation", ceiling)]);
    assert_eq!(
        most(Activation::Continuous, Activation::WhileRunning),
        (Activation::WhileRunning, Some("the organisation"))
    );
    assert_eq!(
        most(Activation::OnRequest, Activation::WhileRunning),
        (Activation::OnRequest, None)
    );
    assert_eq!(
        at_most(Setup::Write, [("the organisation", Setup::Inspect)]),
        (Setup::Inspect, Some("the organisation"))
    );
    assert_eq!(
        at_most(3600u32, [("a", 7200), ("b", 900), ("c", 1800)]),
        (900, Some("b"))
    );
    assert_eq!(at_most(60u32, [("a", 7200), ("b", 900)]), (60, None));
    assert_eq!(
        at_most(60u32, std::iter::empty::<(&str, u32)>()),
        (60, None)
    );
    assert_eq!(
        at_least(Mode::Notify, [("a", Mode::Notify), ("b", Mode::Confirm)]),
        (Mode::Confirm, Some("b"))
    );
    assert_eq!(
        at_least(Mode::Confirm, [("a", Mode::Notify)]),
        (Mode::Confirm, None)
    );
}

/// Over generated limits in both directions: every one holds, none moves a
/// value the other way, and a value inside them all is returned untouched.
#[test]
fn every_limit_holds_over_generated_cases() {
    let mut seeded = Seeded(0x0009_e5c0);
    for _ in 0..4000 {
        let chosen = u32::try_from(seeded.below(100)).unwrap();
        let limits: Vec<(usize, u32)> = (0..seeded.below(5))
            .map(|holder| (holder, u32::try_from(seeded.below(100)).unwrap()))
            .collect();

        let (held, by) = at_most(chosen, limits.iter().copied());
        assert!(limits.iter().all(|(_, most)| held <= *most));
        assert!(held <= chosen);
        assert_eq!(by.is_some(), held != chosen);
        if let Some(holder) = by {
            assert!(
                limits.contains(&(holder, held)),
                "the limit named is the one that binds"
            );
        }

        let (held, by) = at_least(chosen, limits.iter().copied());
        assert!(limits.iter().all(|(_, floor)| held >= *floor));
        assert!(held >= chosen);
        assert_eq!(by.is_some(), held != chosen);

        let mut turned = limits.clone();
        turned.reverse();
        assert_eq!(
            at_most(chosen, turned.iter().copied()),
            at_most(chosen, limits.iter().copied())
        );
        assert_eq!(
            at_least(chosen, turned.iter().copied()),
            at_least(chosen, limits)
        );
    }
}

/// What a grant may expose is admitted whole or
/// refused, never trimmed to what the limit would allow.
#[test]
fn what_a_grant_may_expose_is_admitted_whole_or_refused() {
    let catalogue = catalogue();
    let beyond_key_use_and_service = Exposure::KEY_MANAGEMENT
        .with(Exposure::SECRET)
        .with(Exposure::NETWORK);
    let withheld = [("the organisation", beyond_key_use_and_service)];
    let exposes = |id: &str| capability(&catalogue, id).exposure();
    assert_eq!(admitted(exposes("gpg"), withheld), Ok(()));
    assert_eq!(admitted(exposes("adb"), withheld), Ok(()));
    assert_eq!(
        admitted(exposes("gpg-unrestricted"), withheld),
        Err((
            "the organisation",
            Exposure::KEY_MANAGEMENT.with(Exposure::SECRET)
        )),
        "refused for the member the limit withholds; the use of a key is not served alone"
    );
    assert_eq!(
        admitted(exposes("gpg"), std::iter::empty::<(&str, Exposure)>()),
        Ok(())
    );
    // Of two limits that each withhold something, the same one is named
    // whichever is read first.
    let two = [("b", Exposure::KEY_MANAGEMENT), ("a", Exposure::KEY_USE)];
    let turned = [two[1], two[0]];
    assert_eq!(
        admitted(exposes("gpg-unrestricted"), two),
        Err(("a", Exposure::KEY_USE))
    );
    assert_eq!(
        admitted(exposes("gpg-unrestricted"), turned),
        Err(("a", Exposure::KEY_USE))
    );
}

/// A denial wins from wherever it is made, and
/// the person's document is what it was.
#[test]
fn a_denial_from_above_beats_a_grant_and_leaves_the_document_as_it_was() {
    let catalogue = catalogue();
    let gpg = name("gpg");
    let person = granting(&catalogue, &[("gpg", Granted::Route(name("ssh")))]);
    let mut organisation = Configuration::default();
    organisation
        .apply(
            &catalogue,
            Change::Deny(Denial {
                capability: Selector::Every,
                remotes: matching("dmz-*"),
            }),
        )
        .unwrap();
    let reaches = |remote: &RemoteId| {
        decided_terms(&catalogue, &person, &gpg, remote).is_some()
            && !organisation.denies(&catalogue, &gpg, remote)
    };
    let dmz = remote("ssh", "dmz-1");
    assert!(reaches(&prod()));
    assert!(!reaches(&dmz));
    assert!(
        decided_terms(&catalogue, &person, &gpg, &dmz).is_some(),
        "the grant still stands in the document"
    );
    assert_eq!(
        Configuration::import(&catalogue, person.export()).unwrap(),
        person,
        "which imports as it was exported"
    );
}

/// A value that is not a mode, for the choices that are not modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Value(u32);

impl Strict for Value {
    /// A lower threshold is reached sooner, so it is the stricter.
    fn strictness(&self, other: &Self) -> Ordering {
        other.0.cmp(&self.0)
    }
}

/// A threshold and an urgency resolve per
/// remote by the ranking a mode uses.
#[test]
fn a_choice_that_is_not_a_mode_resolves_by_the_same_ranking() {
    let scratch = remote("ssh", "scratch-7");
    let stated = [(Remotes::Every, Value(40)), (matching("prod-*"), Value(5))];
    let here = |remote: &RemoteId| {
        let covering = stated
            .iter()
            .filter(|(remotes, _)| remotes.covers(remote, &Sets::NONE))
            .map(|(remotes, value)| (remotes, *value));
        nearest(&covering).map(|(_, value)| value)
    };
    assert_eq!(here(&prod()), Some(Value(5)));
    assert_eq!(here(&scratch), Some(Value(40)));

    // Two patterns select the remote equally narrowly: the stricter decides,
    // whichever comes first.
    let equal = [(matching("prod-*"), Value(9)), (matching("*-1"), Value(3))];
    for order in [[0, 1], [1, 0]] {
        let covering = order
            .iter()
            .filter_map(|index| equal.get(*index))
            .map(|(remotes, value)| (remotes, *value));
        assert_eq!(nearest(&covering).map(|(_, value)| value), Some(Value(3)));
    }

    // The nearest source that says anything decides, however wide its
    // statement and however narrow a farther source's.
    let one = Remotes::One(prod());
    let every = Remotes::Every;
    let person = [(&every, Value(40))];
    let for_person = [(&one, Value(2))];
    let for_machine = [(&one, Value(1))];
    let none: [(&Remotes, Value); 0] = [];
    let from = |person: &[(&Remotes, Value)], for_person: &[(&Remotes, Value)]| {
        choose(
            &person.iter().copied(),
            &for_person.iter().copied(),
            &for_machine.iter().copied(),
        )
        .map(|(tier, _, value)| (tier, value))
    };
    assert_eq!(from(&person, &for_person), Some((Tier::Person, Value(40))));
    assert_eq!(
        from(&none, &for_person),
        Some((Tier::Start(Audience::Person), Value(2)))
    );
    assert_eq!(
        from(&none, &none),
        Some((Tier::Start(Audience::Machine), Value(1)))
    );
    assert_eq!(
        choose(
            &none.iter().copied(),
            &none.iter().copied(),
            &none.iter().copied()
        ),
        None,
        "every source silent: what ships decides"
    );
}

fn keyed(remotes: Remotes, key: Keys) -> RuleScope {
    RuleScope {
        key,
        ..rule(remotes)
    }
}

fn release() -> Grip {
    Grip::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap()
}

fn everyday() -> Grip {
    Grip::try_from("9A8B7C6D5E4F30211203F4E5D6C7B8A990817263").unwrap()
}

/// How a signature with `gpg` on `prod-1` is decided when it names `key`.
fn signed_with(
    person: &BTreeMap<RuleScope, Mode>,
    connection: &BTreeMap<ConnectionScope, Mode>,
    key: &Grip,
    touch: Option<Touch>,
) -> Resolved {
    let remote = prod();
    let gpg = name("gpg");
    let key = KeyId::Grip(key.clone());
    resolve(
        &Rules {
            person,
            connection,
            start: &[],
            floors: &[],
        },
        &Subject {
            remote: &remote,
            sets: Sets::NONE,
            capability: &gpg,
            exposure: Exposure::KEY_USE,
            operation: Operation::Sign,
            used: Some(Used {
                id: &key,
                key: None,
                touch,
            }),
        },
    )
}

/// Where a single ranking would put the key among its axes.
#[derive(Clone, Copy)]
enum Placed {
    First,
    Last,
}

/// Falsified: the key as one more axis of a single ranking. Every statement
/// given is taken to cover the request.
fn one_ranking(person: &BTreeMap<RuleScope, Mode>, key: Placed) -> Option<Mode> {
    person
        .iter()
        .max_by_key(|(scope, mode)| {
            let (selects, keys) = standing(scope);
            match key {
                Placed::First => ((keys, 0, 0), selects, **mode),
                Placed::Last => (selects, (keys, 0, 0), **mode),
            }
        })
        .map(|(_, mode)| *mode)
}

/// One person who commits daily and cuts releases: both keys sit behind one
/// capability on one remote under one operation, and the release key is
/// confirmed wherever it is used.
#[test]
fn a_statement_naming_a_key_is_not_relaxed_by_one_naming_only_a_remote() {
    let none = BTreeMap::new();
    let by_key = keyed(Remotes::Every, Keys::Only(KeyName::Grip(release())));
    let by_remote = rule(Remotes::One(prod()));
    let both = BTreeMap::from([
        (by_key.clone(), Mode::Confirm),
        (by_remote.clone(), Mode::Notify),
    ]);
    let with_release = signed_with(&both, &none, &release(), Some(Touch::On));
    assert_eq!(with_release.mode, Mode::Confirm);
    assert_eq!(with_release.basis, Basis::Rule(by_key.clone()));
    let with_everyday = signed_with(&both, &none, &everyday(), Some(Touch::On));
    assert_eq!(with_everyday.mode, Mode::Notify);
    assert_eq!(with_everyday.basis, Basis::Rule(by_remote.clone()));

    // And the reverse: a host the person confirms on is not relaxed by a
    // statement that names only a key.
    let reverse = BTreeMap::from([(by_key, Mode::Unattended), (by_remote, Mode::Confirm)]);
    assert_eq!(
        signed_with(&reverse, &none, &release(), Some(Touch::On)).mode,
        Mode::Confirm
    );

    // The two controls. One ranking with the key as its last axis lets the
    // host's rule relax the release key; with the key as its first, it lets
    // the key's rule relax the host.
    assert_eq!(one_ranking(&both, Placed::Last), Some(Mode::Notify));
    assert_eq!(one_ranking(&reverse, Placed::First), Some(Mode::Unattended));

    // A statement that names both is more specific than either, and decides
    // even where it is the laxer.
    let here = keyed(Remotes::One(prod()), Keys::Only(KeyName::Grip(release())));
    let mut all = both.clone();
    all.insert(here.clone(), Mode::Unattended);
    let decided = signed_with(&all, &none, &release(), Some(Touch::On));
    assert_eq!(decided.mode, Mode::Unattended);
    assert_eq!(decided.basis, Basis::Rule(here));

    // A rule on the connection that names no key does not relax the key's
    // own; one that names it does.
    let open = ConnectionScope {
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    };
    let on_connection = BTreeMap::from([(open.clone(), Mode::Unattended)]);
    assert_eq!(
        signed_with(&both, &on_connection, &release(), Some(Touch::On)).mode,
        Mode::Confirm
    );
    assert_eq!(
        signed_with(&both, &on_connection, &everyday(), Some(Touch::On)).basis,
        Basis::Connection(open.clone())
    );
    let for_release = ConnectionScope {
        key: Keys::Only(KeyName::Grip(release())),
        ..open
    };
    let on_connection = BTreeMap::from([(for_release.clone(), Mode::Notify)]);
    let decided = signed_with(&both, &on_connection, &release(), Some(Touch::On));
    assert_eq!(decided.mode, Mode::Notify);
    assert_eq!(decided.basis, Basis::Connection(for_release));
}

/// "A key whose card needs no touch is never served unasked" is a statement
/// about keys by what their card enforces. A key on no card the core has
/// read is one of them: nothing shows it is observed.
#[test]
fn a_statement_can_name_keys_by_what_their_card_enforces() {
    let none = BTreeMap::new();
    let untouched = keyed(Remotes::Every, Keys::NeedingNoTouch);
    let person = BTreeMap::from([(untouched.clone(), Mode::Confirm)]);
    for (touch, mode) in [
        (Some(Touch::Off), Mode::Confirm),
        (None, Mode::Confirm),
        (Some(Touch::On), Mode::Notify),
    ] {
        assert_eq!(signed_with(&person, &none, &release(), touch).mode, mode);
    }
    // A request that names no key is no key's: only a statement about every
    // key covers it.
    assert_eq!(decided(&person, None, &[], &[]).basis, Basis::Default);

    // One key is narrower than every key of a kind.
    let mut person = person;
    let this = keyed(Remotes::Every, Keys::Only(KeyName::Grip(release())));
    person.insert(this.clone(), Mode::Notify);
    assert_eq!(
        signed_with(&person, &none, &release(), Some(Touch::Off)).basis,
        Basis::Rule(this)
    );
    assert_eq!(
        signed_with(&person, &none, &everyday(), Some(Touch::Off)).basis,
        Basis::Rule(untouched)
    );
}

/// A scope on the two axes a mode's statement can be specific on, for the
/// generated cases below.
fn generated_scope(seeded: &mut Seeded) -> RuleScope {
    let remotes = [
        Remotes::Every,
        Remotes::Route(name("ssh")),
        matching("prod-*"),
        matching("*-1"),
        Remotes::One(prod()),
    ];
    let keys = [
        Keys::Every,
        Keys::NeedingNoTouch,
        Keys::Only(KeyName::Grip(release())),
    ];
    let capability = [Selector::Every, Selector::Only(name("gpg"))];
    RuleScope {
        remotes: seeded.pick(&remotes).clone(),
        capability: seeded.pick(&capability).clone(),
        operation: *seeded.pick(&[Selector::Every, Selector::Only(Operation::Sign)]),
        key: seeded.pick(&keys).clone(),
    }
}

/// Where a scope stands on each axis, as the requirement words it: what it
/// selects - the remote, then the capability, then the operation - and
/// which keys.
fn standing(scope: &RuleScope) -> ((u8, u8, u8), u8) {
    let only = |every: bool| u8::from(!every);
    (
        (
            scope.remotes.rank(),
            only(scope.capability == Selector::Every),
            only(scope.operation == Selector::Every),
        ),
        match scope.key {
            Keys::Every => 0,
            Keys::NeedingNoTouch => 1,
            Keys::Only(_) => 2,
        },
    )
}

/// The choice, stated without the resolution: what decides is a statement
/// that covers the request; none that covers it is more specific on one axis
/// and at least as specific on the other; and no statement left standing that
/// way is stricter.
#[test]
fn what_decides_is_a_most_specific_statement_and_the_strictest_of_those() {
    let mut seeded = Seeded(0x0005_c09e);
    let none = BTreeMap::new();
    for _ in 0..3000 {
        let person: BTreeMap<RuleScope, Mode> = (0..seeded.below(7))
            .map(|_| (generated_scope(&mut seeded), *seeded.pick(&MODES)))
            .collect();
        let decided = signed_with(&person, &none, &release(), Some(Touch::Off));
        let Basis::Rule(by) = &decided.basis else {
            assert!(
                person.is_empty(),
                "every generated scope covers the request"
            );
            assert_eq!(
                decided.mode,
                default_mode(Operation::Sign, Exposure::KEY_USE)
            );
            continue;
        };
        assert_eq!(person.get(by), Some(&decided.mode));
        let outranks = |scope: &RuleScope, other: &RuleScope| {
            let (selects, keys) = standing(scope);
            let (against, other_keys) = standing(other);
            selects >= against && keys >= other_keys && (selects, keys) != (against, other_keys)
        };
        let left_standing = |scope: &RuleScope| !person.keys().any(|other| outranks(other, scope));
        assert!(left_standing(by), "{person:?}");
        let strictest = person
            .iter()
            .filter(|(scope, _)| left_standing(scope))
            .map(|(_, mode)| *mode)
            .max();
        assert_eq!(Some(decided.mode), strictest, "{person:?}");
    }
}

/// A scope is compared with another only through `Specific`: the order is
/// consistent, so nothing depends on which of two is asked first.
#[test]
fn specificity_is_the_same_asked_either_way() {
    let selections = [
        Remotes::Every,
        Remotes::Route(name("ssh")),
        matching("prod-*"),
        Remotes::Set(name("fleet")),
        Remotes::One(prod()),
    ];
    for one in &selections {
        for other in &selections {
            assert_eq!(
                one.specificity(&other),
                other.specificity(&one).map(Ordering::reverse)
            );
        }
    }
    assert_eq!(
        (&matching("prod-*")).specificity(&&Remotes::Set(name("fleet"))),
        Some(Ordering::Equal),
        "a named set and a pattern select equally narrowly"
    );
}

fn fleet() -> Set {
    Set {
        id: name("fleet"),
        members: vec![
            Member::One(remote("ssh", "ec2-203-0-113-7.compute.example")),
            Member::One(remote("coder", "ops/db")),
            Member::Matching {
                route: name("ssh"),
                pattern: pattern("db-*"),
            },
        ],
    }
}

/// Hosts a provider named share no name a pattern could select. The set is
/// named once, and a grant, a denial and a rule each refer to it.
#[test]
fn a_named_set_is_selected_by_a_grant_a_denial_and_a_rule() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    let named = Remotes::Set(name("fleet"));
    let gpg = name("gpg");

    // A statement cannot name a set nothing defines.
    let give = Change::Grant {
        grant: grant("gpg", Granted::Set(name("fleet"))),
        terms: terms(Activation::OnRequest, Exposure::NONE),
    };
    assert_eq!(
        configuration.clone().apply(&catalogue, give.clone()),
        Err(Refusal::UnknownSet(name("fleet")))
    );
    assert_eq!(
        configuration.apply(&catalogue, Change::DefineSet(fleet())),
        Ok(Effect::Changed)
    );
    assert_eq!(
        configuration.apply(&catalogue, Change::DefineSet(fleet())),
        Ok(Effect::Unchanged)
    );
    assert_eq!(configuration.apply(&catalogue, give), Ok(Effect::Changed));

    let provider = remote("ssh", "ec2-203-0-113-7.compute.example");
    let database = remote("ssh", "db-3");
    let workspace = remote("coder", "ops/db");
    let outsider = remote("ssh", "prod-1");
    for member in [&provider, &database, &workspace] {
        assert!(decided_terms(&catalogue, &configuration, &gpg, member).is_some());
    }
    assert_eq!(
        decided_terms(&catalogue, &configuration, &gpg, &outsider),
        None
    );

    // A set is as narrow as a pattern: of a grant to the set and one to a
    // pattern that both cover a remote, the less exposing decides.
    configuration
        .apply(
            &catalogue,
            Change::Grant {
                grant: grant(
                    "gpg",
                    Granted::Matching {
                        route: name("ssh"),
                        pattern: pattern("db-*"),
                    },
                ),
                terms: terms(Activation::Continuous, Exposure::NONE),
            },
        )
        .unwrap();
    let decided = decided_terms(&catalogue, &configuration, &gpg, &database);
    assert_eq!(decided.unwrap().activation, Activation::OnRequest);

    configuration
        .apply(
            &catalogue,
            Change::Rule {
                scope: rule(named.clone()),
                mode: Mode::Confirm,
            },
        )
        .unwrap();
    let sets = configuration.sets(&catalogue);
    let on = |remote: &RemoteId| {
        resolve(
            &Rules {
                person: configuration.rules(),
                connection: &BTreeMap::new(),
                start: &[],
                floors: &[],
            },
            &Subject {
                remote,
                sets,
                capability: &gpg,
                exposure: Exposure::KEY_USE,
                operation: Operation::Sign,
                used: None,
            },
        )
        .mode
    };
    assert_eq!(on(&provider), Mode::Confirm);
    assert_eq!(on(&outsider), Mode::Notify);

    configuration
        .apply(
            &catalogue,
            Change::Deny(Denial {
                capability: Selector::Every,
                remotes: named,
            }),
        )
        .unwrap();
    assert!(configuration.denies(&catalogue, &gpg, &workspace));
    assert!(!configuration.denies(&catalogue, &gpg, &outsider));

    // The document carries the set, and reads back to the same value.
    let document = configuration.export();
    assert_eq!(document.sets, vec![canonical(fleet())]);
    assert_eq!(
        Configuration::import(&catalogue, document).unwrap(),
        configuration
    );
}

/// A set as a document lists it: its members in one order.
fn canonical(mut set: Set) -> Set {
    set.members.sort();
    set
}

#[test]
fn a_set_names_routes_that_exist_lists_no_member_twice_and_stays_while_selected() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    let refused = |configuration: &Configuration, change: Change| {
        let mut attempt = configuration.clone();
        let refusal = attempt.apply(&catalogue, change).unwrap_err();
        assert_eq!(&attempt, configuration, "a refused change changes nothing");
        refusal
    };
    assert_eq!(
        refused(
            &configuration,
            Change::DefineSet(Set {
                id: name("elsewhere"),
                members: vec![Member::One(remote("gitpod", "x"))],
            })
        ),
        Refusal::UnknownRoute(name("gitpod"))
    );
    let twice = Set {
        id: name("twice"),
        members: vec![Member::One(prod()), Member::One(prod())],
    };
    assert_eq!(
        refused(&configuration, Change::DefineSet(twice.clone())),
        Refusal::Repeated(Section::Sets)
    );

    configuration
        .apply(&catalogue, Change::DefineSet(fleet()))
        .unwrap();
    let selecting: [Change; 3] = [
        Change::Grant {
            grant: grant("gpg", Granted::Set(name("fleet"))),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        },
        Change::Deny(Denial {
            capability: Selector::Every,
            remotes: Remotes::Set(name("fleet")),
        }),
        Change::Rule {
            scope: rule(Remotes::Set(name("fleet"))),
            mode: Mode::Confirm,
        },
    ];
    for change in selecting {
        let mut configuration = configuration.clone();
        configuration.apply(&catalogue, change).unwrap();
        assert_eq!(
            refused(&configuration, Change::UndefineSet(name("fleet"))),
            Refusal::SetInUse(name("fleet"))
        );
        // The routes its members are on stay defined while it selects them.
        assert_eq!(
            configuration.sets(&catalogue).routes(&name("fleet")).len(),
            2
        );
    }
    assert_eq!(
        configuration.apply(&catalogue, Change::UndefineSet(name("fleet"))),
        Ok(Effect::Changed)
    );

    // A grant that follows a workspace's life needs every member's route to
    // list its remotes, and `ssh` lists none.
    configuration
        .apply(&catalogue, Change::DefineSet(fleet()))
        .unwrap();
    assert_eq!(
        refused(
            &configuration,
            Change::Grant {
                grant: grant("gpg", Granted::Set(name("fleet"))),
                terms: terms(Activation::WhileRunning, Exposure::NONE),
            }
        ),
        Refusal::ActivationNeedsDiscovery { route: name("ssh") }
    );

    // An imported document meets the same checks.
    let mut document = configuration.export();
    document.sets = vec![twice];
    assert_eq!(
        Configuration::import(&catalogue, document.clone()),
        Err(Refusal::Repeated(Section::Sets))
    );
    document.sets = vec![fleet(), fleet()];
    assert_eq!(
        Configuration::import(&catalogue, document),
        Err(Refusal::Repeated(Section::Sets))
    );
}

fn key_on(grip: &Grip, fingerprint: &str, primary: &str) -> Key {
    Key {
        grip: grip.clone(),
        fingerprint: Fingerprint::try_from(fingerprint).unwrap(),
        primary: Fingerprint::try_from(primary).unwrap(),
        uses: Uses::SIGN,
        user: None,
        card: None,
        ssh: None,
    }
}

/// A key whose card asks for a touch, every time or then not for a while, is
/// not one usable with nobody at its card; one whose card asks for none, or
/// whose card the core has not read or did not say, is.
#[test]
fn needing_no_touch_is_every_key_its_card_does_not_say_asks_for_one() {
    let grip = KeyId::Grip(release());
    let used = |touch| {
        Some(Used {
            id: &grip,
            key: None,
            touch,
        })
    };
    assert!(!Keys::NeedingNoTouch.covers(used(Some(Touch::On))));
    assert!(!Keys::NeedingNoTouch.covers(used(Some(Touch::Cached))));
    assert!(Keys::NeedingNoTouch.covers(used(Some(Touch::Off))));
    assert!(Keys::NeedingNoTouch.covers(used(None)));
    assert!(
        !Keys::NeedingNoTouch.covers(None),
        "a request that uses no key"
    );
}

/// A statement names a key as the person knows it. A primary key's
/// fingerprint names it and every subkey of it; a subkey's names that subkey
/// alone; a keygrip names one key exactly; a fingerprint never names a key the
/// source does not offer, since nothing ties the request's keygrip to it.
#[test]
fn a_fingerprint_names_a_key_and_its_subkeys_and_a_keygrip_one_key() {
    const PRIMARY: &str = "07B56DFBBA12BB80FA84939C76F8274EF1651088";
    const SUBKEY: &str = "5C2E0B8F7A1D3C4E9F60718293A4B5C6D7E8F901";
    const OTHER: &str = "A1B2C3D4E5F60718293A4B5C6D7E8F9001122334";
    let grip = everyday();
    let subkey = key_on(&grip, SUBKEY, PRIMARY);
    let id = KeyId::Grip(grip.clone());
    let offered = Used {
        id: &id,
        key: Some(&subkey),
        touch: None,
    };
    let unoffered = Used {
        key: None,
        ..offered
    };
    let named = |text: &str| Keys::Only(KeyName::Fingerprint(Fingerprint::try_from(text).unwrap()));
    assert!(named(PRIMARY).covers(Some(offered)));
    assert!(named(SUBKEY).covers(Some(offered)));
    assert!(!named(OTHER).covers(Some(offered)));
    assert!(!named(PRIMARY).covers(Some(unoffered)));
    assert!(Keys::Only(KeyName::Grip(everyday())).covers(Some(unoffered)));
    assert!(!Keys::Only(KeyName::Grip(release())).covers(Some(offered)));
    assert!(!named(PRIMARY).covers(None));
}
