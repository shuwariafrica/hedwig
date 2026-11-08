//! The settings a channel's life reads, each a choice made at its scopes:
//! how a client notices a dead link and what waits a lost channel keeps, per
//! remote, and how often a route's platform is asked what runs, per route.
//! The person's statement is nearest, then what the organisation starts this
//! person with, then this machine, then what ships.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod support;

use std::num::{NonZeroU8, NonZeroU16, NonZeroU32};

use hedwig_model::config::{Change, Configuration, Effect, Reach};
use hedwig_model::gate::World;
use hedwig_model::organisation::{Start, Statement};
use hedwig_model::policy::Selector;
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::Remotes;
use hedwig_model::scope::Audience;
use hedwig_model::setting::{Cadence, Keepalive, Returns, Said};
use hedwig_model::trail::{Entry, Event, Integrity, Origin, Seq, State, Tick, Timestamp};

use support::{catalogue, coder, name, remote};

fn keepalive(every: u16, missed: u8) -> Keepalive {
    Keepalive {
        every: NonZeroU16::new(every).unwrap(),
        missed: NonZeroU8::new(missed).unwrap(),
    }
}

fn returns(first: u32, longest: u32) -> Returns {
    Returns {
        first: NonZeroU32::new(first).unwrap(),
        longest: NonZeroU32::new(longest).unwrap(),
    }
}

/// The trail of a run in which the organisation states `starts`.
fn stated(starts: Vec<(Audience, Start)>) -> State {
    let origin = Origin {
        process: 1,
        logon: 1,
        session: 2,
        integrity: Integrity::Medium,
    };
    let mut events = vec![Event::Started {
        version: "0.2.0".to_owned(),
        origin,
        after: None,
    }];
    events.extend(starts.into_iter().map(|(audience, start)| Event::Stated {
        audience,
        statement: Statement::Start(start),
    }));
    let entries: Vec<Entry> = events
        .into_iter()
        .enumerate()
        .map(|(index, event)| Entry {
            seq: Seq(index as u64 + 1),
            at: Timestamp(0),
            tick: Tick(0),
            event,
        })
        .collect();
    State::fold(&entries)
}

#[test]
fn what_ships_is_stated_once_beside_each_type() {
    assert_eq!(Keepalive::SHIPS, keepalive(15, 3));
    assert_eq!(Keepalive::SHIPS.notices_within(), 45);
    assert_eq!(Returns::SHIPS, returns(1, 60));
    assert_eq!(Cadence::SHIPS, Cadence(NonZeroU32::new(60).unwrap()));
    // A longest shorter than the first is every wait.
    assert_eq!(returns(30, 10).wait(1), 10);
    assert_eq!(returns(30, 10).wait(4), 10);
}

#[test]
fn each_is_chosen_nearest_first_and_says_where_it_came_from() {
    let catalogue = catalogue();
    let host = remote("ssh", "ops@bastion.example");
    let state = stated(vec![
        (
            Audience::Machine,
            Start::Keepalive {
                remotes: Remotes::Every,
                keepalive: keepalive(60, 2),
            },
        ),
        (
            Audience::Person,
            Start::Returns {
                remotes: Remotes::Route(name("ssh")),
                returns: returns(5, 300),
            },
        ),
        (
            Audience::Machine,
            Start::Cadence {
                routes: Selector::Only(name("codespaces")),
                cadence: Cadence(NonZeroU32::new(300).unwrap()),
            },
        ),
    ]);
    let mut configuration = Configuration::default();
    let world = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    let chosen = world.keepalive(&host);
    assert_eq!(chosen.value, keepalive(60, 2));
    assert!(matches!(
        chosen.said,
        Said::Start {
            audience: Audience::Machine,
            ..
        }
    ));
    assert_eq!(world.returns(&host).value, returns(5, 300));
    assert_eq!(
        world.returns(&remote("codespaces", "octo-x")).said,
        Said::Ships
    );
    assert_eq!(world.cadence(&name("codespaces")).value.0.get(), 300);
    assert_eq!(world.cadence(&name("coder")).said, Said::Ships);

    // The person's own statement, however wide, is nearest.
    for change in [
        Change::Keepalive {
            remotes: Remotes::Every,
            keepalive: Some(keepalive(20, 5)),
        },
        Change::Returns {
            remotes: Remotes::One(host.clone()),
            returns: Some(returns(2, 120)),
        },
        Change::Cadence {
            routes: Selector::Every,
            cadence: Some(Cadence(NonZeroU32::new(30).unwrap())),
        },
    ] {
        assert_eq!(configuration.widens(&catalogue, &change), Reach::NoWider);
        assert_eq!(configuration.apply(&catalogue, change), Ok(Effect::Changed));
    }
    let world = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    assert_eq!(world.keepalive(&host).value, keepalive(20, 5));
    assert_eq!(
        world.returns(&host).said,
        Said::Person(Remotes::One(host.clone()))
    );
    assert_eq!(world.cadence(&name("codespaces")).value.0.get(), 30);
}

/// A cadence names a route that lists; the route stays defined while one
/// names it.
#[test]
fn a_cadence_names_a_route_that_lists() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    let cadence = Some(Cadence(NonZeroU32::new(120).unwrap()));
    assert_eq!(
        configuration.apply(
            &catalogue,
            Change::Cadence {
                routes: Selector::Only(name("ssh")),
                cadence,
            }
        ),
        Err(Refusal::Unlisted(name("ssh")))
    );
    assert_eq!(
        configuration.apply(
            &catalogue,
            Change::Cadence {
                routes: Selector::Only(name("nowhere")),
                cadence,
            }
        ),
        Err(Refusal::UnknownRoute(name("nowhere")))
    );
    // A route of the person's own that lists, beside what ships.
    let shipped = hedwig_model::config::Catalogue::shipped().unwrap();
    let mine = hedwig_model::remote::Route {
        id: name("mine"),
        ..coder()
    };
    configuration
        .apply(&shipped, Change::DefineRoute(mine))
        .unwrap();
    configuration
        .apply(
            &shipped,
            Change::Cadence {
                routes: Selector::Only(name("mine")),
                cadence,
            },
        )
        .unwrap();
    assert_eq!(
        configuration.apply(&shipped, Change::UndefineRoute(name("mine"))),
        Err(Refusal::RouteInUse(name("mine")))
    );
}
