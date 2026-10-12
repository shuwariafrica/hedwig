//! The organisation's statements as a value the core is given: read through
//! one gate, recorded in the trail, and applied by the resolution each kind
//! has. Limits hold and never loosen; a starting point yields to the person
//! and lets through no more than they accept; what cannot be read holds
//! everything and is said once.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU32;

use hedwig_model::capability::{
    AgentAt, Capability, Exposure, Lends, Offer, Operation, ServiceHost, ServicePort, Setup,
    Source, Stream,
};
use hedwig_model::config::{Activation, Change, Configuration, Denial, Effect, Terms};
use hedwig_model::gate::{Capped, Verdict, World};
use hedwig_model::organisation::{
    GrantScope, Limit, Part, Place, Policy, STATEMENTS, Start, Statement,
};
use hedwig_model::policy::{Attended, Basis, Keys, Limited, Mode, RuleScope, Selector};
use hedwig_model::protocol::{Act, Attention, Decision, Reply, Request, Standing, Through};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::scope::{Audience, Holder};
use hedwig_model::setting::{
    Autostart, Bounded, Burst, CapScope, Diagnostics, Keep, Longest, Said, Settled, Span,
    Threshold, Workstation,
};
use hedwig_model::text::{AgentPipe, Host};
use hedwig_model::trail::{ClientId, ClientKind, Event, Item, Opener, Outcome, Seq, Tick};
use hedwig_model::wire::line;

mod support;
use support::desk::Desk;
use support::{
    DESKTOP, Seeded, Trail, catalogue, corpus, grant, granting, name, port, remote, terms,
};

const MACHINE: Audience = Audience::Machine;
const PERSON: Audience = Audience::Person;

fn at(audience: Audience, part: Part) -> Place {
    Place { audience, part }
}

/// A statement as the line an organisation writes for it.
fn written(audience: Audience, statement: &Statement) -> (Place, String) {
    let text = match statement {
        Statement::Limit(limit) => line(limit),
        Statement::Start(start) => line(start),
        Statement::Ask(words) => words.as_str().to_owned(),
    };
    (at(audience, statement.part()), text)
}

fn limit(audience: Audience, limit: Limit) -> (Place, String) {
    written(audience, &Statement::Limit(limit))
}

fn start(audience: Audience, start: Start) -> (Place, String) {
    written(audience, &Statement::Start(start))
}

fn policy(lines: &[(Place, String)]) -> Policy {
    Policy::read(lines.iter().map(|(place, text)| (*place, text.as_str())))
}

fn host() -> RemoteId {
    remote("ssh", "ops@bastion.example")
}

fn every_grant() -> GrantScope {
    GrantScope {
        capability: Selector::Every,
        remotes: Remotes::Every,
    }
}

/// A desk with an attending interface, `gpg` granted to `host` on request,
/// and a channel up to it.
fn serving(activation: Activation) -> (Desk, ClientId, hedwig_model::trail::ConnectionId) {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(
        interface,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(host())),
            terms: terms(activation, Exposure::NONE),
        }),
    )
    .unwrap();
    let connection = desk.channel_up(&host(), "linux");
    (desk, interface, connection)
}

fn served(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::Serve(_))
}

/// A floor and a starting grant as an organisation writes them, one
/// statement to a line.
const WRITTEN: &str = r#"
{"floor":{"scope":{"remotes":"every","capability":"every","operation":{"only":"sign"},"key":"needing-no-touch"},"mode":"confirm"}}
{"grant":{"grant":{"capability":"gpg","remotes":{"route":"codespaces"}},"activation":"while-running"}}
"#;

#[test]
fn a_statement_is_one_line_a_template_element_holds() {
    let mut lines = WRITTEN.trim().lines();
    let (floor, grant_line) = (lines.next().unwrap(), lines.next().unwrap());
    let read = Policy::read([
        (at(MACHINE, Part::Limits), floor),
        (at(PERSON, Part::Start), grant_line),
    ]);
    assert_eq!(
        read.limits().collect::<Vec<_>>(),
        vec![(
            MACHINE,
            &Limit::Floor {
                scope: RuleScope {
                    remotes: Remotes::Every,
                    capability: Selector::Every,
                    operation: Selector::Only(Operation::Sign),
                    key: Keys::NeedingNoTouch,
                },
                mode: Mode::Confirm,
            }
        )]
    );
    let Some((PERSON, Start::Grant { grant: granted, .. })) = read.start().next() else {
        unreachable!("the starting grant was read")
    };
    assert_eq!(granted, &grant("gpg", Granted::Route(name("codespaces"))));
    for (audience, statement) in read.statements() {
        let (_, text) = written(audience, statement);
        assert!(WRITTEN.contains(&text));
        // What an administrative template's text element holds by default.
        assert!(text.len() <= 1023);
    }
}

#[test]
fn every_statement_reads_back_as_it_was_written_whatever_the_order() {
    let mut lines: Vec<(Place, String)> = corpus::statements()
        .iter()
        .zip([MACHINE, PERSON].into_iter().cycle())
        .map(|(statement, audience)| written(audience, statement))
        .collect();
    let read = policy(&lines);
    assert_eq!(read.unread().count(), 0);
    assert_eq!(read.statements().count(), corpus::statements().len());

    // lines -> value -> lines
    let mut again: Vec<(Place, String)> = read
        .statements()
        .map(|(audience, statement)| written(audience, statement))
        .collect();
    again.sort();
    let mut sorted = lines.clone();
    sorted.sort();
    assert_eq!(again, sorted);
    // value -> lines -> value
    assert_eq!(policy(&again), read);

    lines.reverse();
    assert_eq!(policy(&lines), read);
    let twice: Vec<(Place, String)> = lines.iter().chain(&lines).cloned().collect();
    assert_eq!(policy(&twice), read);
}

#[test]
fn a_limit_line_that_cannot_be_read_holds_everything_and_never_stops_the_person_narrowing() {
    let (mut desk, interface, connection) = serving(Activation::OnRequest);
    assert!(served(&desk.asks(connection, "gpg", Operation::Sign).1));

    let unreadable = policy(&[(at(MACHINE, Part::Limits), r#"{"floor":"every"}"#.to_owned())]);
    let (place, unread) = unreadable.unread().next().expect("an unread line");
    assert_eq!(place, at(MACHINE, Part::Limits));
    assert_eq!(unread.lines, vec![0]);
    assert_eq!(unreadable.unreadable(), Some(MACHINE));
    desk.govern(&unreadable);

    assert_eq!(
        desk.asks(connection, "gpg", Operation::Sign).1,
        Verdict::Refuse(Refusal::Unread(MACHINE))
    );
    assert_eq!(
        desk.row(interface, &host(), &name("gpg")).standing,
        Standing::Unavailable(Refusal::Unread(MACHINE))
    );
    let elsewhere = Request::Connect {
        remote: remote("codespaces", "fluffy-space-7x9q"),
        with: Vec::new(),
        acknowledged: Exposure::NONE,
        lends: Lends::none(),
    };
    assert_eq!(
        desk.send(interface, elsewhere),
        Err(Refusal::Unread(MACHINE))
    );
    assert_eq!(
        Refusal::Unread(MACHINE).to_string(),
        "your organisation's limits for this machine could not all be read, so nothing is \
         served under them until they can be"
    );

    // Said once: one item, and reading the same again records nothing.
    let said = |desk: &Desk| {
        desk.ask_world(|world| world.attention(interface, desk.trail.tick()))
            .into_iter()
            .filter(|needs| matches!(needs.attention, Attention::Policy { unread: 1, .. }))
            .count()
    };
    assert_eq!(said(&desk), 1);
    let recorded = desk.trail.entries.len();
    desk.govern(&unreadable);
    assert_eq!(desk.trail.entries.len(), recorded);

    // The person still narrows.
    let deny = Change::Deny(Denial {
        capability: Selector::Only(name("gpg")),
        remotes: Remotes::One(host()),
    });
    assert_eq!(
        desk.send(interface, Request::Change(deny)),
        Ok(Reply::Changed {
            effect: Effect::Changed,
            held: Vec::new()
        })
    );
    assert!(
        desk.send(interface, Request::Pause(Remotes::One(host())))
            .is_ok()
    );
}

#[test]
fn a_starting_line_that_cannot_be_read_says_nothing_and_is_said() {
    let (mut desk, interface, connection) = serving(Activation::OnRequest);
    let unreadable = policy(&[(at(PERSON, Part::Start), r#"{"grant":{}}"#.to_owned())]);
    assert_eq!(unreadable.unreadable(), None);
    desk.govern(&unreadable);
    assert!(served(&desk.asks(connection, "gpg", Operation::Sign).1));
    let policy_items: Vec<Attention> = desk
        .ask_world(|world| world.attention(interface, desk.trail.tick()))
        .into_iter()
        .map(|needs| needs.attention)
        .filter(|attention| matches!(attention, Attention::Policy { .. }))
        .collect();
    assert!(matches!(
        policy_items.as_slice(),
        [Attention::Policy {
            place: Place {
                audience: Audience::Person,
                part: Part::Start
            },
            unread: 1,
            ..
        }]
    ));
}

#[test]
fn past_the_bound_a_line_is_not_read() {
    let lines: Vec<(Place, String)> = (0..=STATEMENTS)
        .map(|index| (at(MACHINE, Part::Ask), format!("desk {index}")))
        .collect();
    let read = policy(&lines);
    assert_eq!(read.ask(MACHINE).count(), STATEMENTS);
    let (_, unread) = read.unread().next().expect("the line past the bound");
    assert_eq!(unread.lines, vec![u32::try_from(STATEMENTS).unwrap()]);
    assert_eq!(read.unreadable(), None);
}

#[test]
fn a_floor_from_above_holds_the_request_and_names_the_choice_under_it() {
    let (mut desk, interface, connection) = serving(Activation::OnRequest);
    let scope = RuleScope {
        remotes: Remotes::Every,
        capability: Selector::Only(name("gpg")),
        operation: Selector::Only(Operation::Sign),
        key: Keys::Every,
    };
    desk.govern(&policy(&[limit(
        MACHINE,
        Limit::Floor {
            scope: scope.clone(),
            mode: Mode::Confirm,
        },
    )]));
    let limited = |chose: Mode, basis: Basis| {
        Verdict::Hold(Basis::Limit(Box::new(Limited {
            audience: MACHINE,
            scope: scope.clone(),
            chose,
            basis,
        })))
    };
    assert_eq!(
        desk.asks(connection, "gpg", Operation::Sign).1,
        limited(Mode::Notify, Basis::Default)
    );

    let mine = RuleScope {
        remotes: Remotes::One(host()),
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    };
    desk.send(
        interface,
        Request::Change(Change::Rule {
            scope: mine.clone(),
            mode: Mode::Unattended,
        }),
    )
    .unwrap();
    assert_eq!(
        desk.asks(connection, "gpg", Operation::Sign).1,
        limited(Mode::Unattended, Basis::Rule(mine.clone()))
    );
    // The person's rule stands in their document, and decides what the
    // floor does not cover.
    assert_eq!(
        desk.configuration.rules().get(&mine),
        Some(&Mode::Unattended)
    );
    assert!(matches!(
        desk.asks(connection, "gpg", Operation::Decrypt).1,
        Verdict::Serve(Outcome::Served(Basis::Rule(_)))
    ));
}

/// Every floor from either audience holds, none loosens, and a choice
/// already inside them all is returned as it was made.
#[test]
fn floors_from_both_audiences_all_hold_over_generated_cases() {
    let catalogue = catalogue();
    let workspace = remote("ssh", "ops@bastion.example");
    let selections = [
        Remotes::Every,
        Remotes::Route(name("ssh")),
        Remotes::One(workspace.clone()),
        Remotes::Route(name("codespaces")),
    ];
    let modes = [Mode::Unattended, Mode::Notify, Mode::Confirm];
    let scope = |remotes: &Remotes| RuleScope {
        remotes: remotes.clone(),
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    };
    let mut seeded = Seeded(0x5eed_f100);
    for _ in 0..600 {
        let mut configuration = granting(&catalogue, &[("gpg", Granted::One(workspace.clone()))]);
        for remotes in &selections {
            if seeded.below(2) == 0 {
                let change = Change::Rule {
                    scope: scope(remotes),
                    mode: *seeded.pick(&modes),
                };
                configuration.apply(&catalogue, change).unwrap();
            }
        }
        let mut lines = Vec::new();
        let mut floors = Vec::new();
        for audience in [MACHINE, PERSON] {
            for remotes in &selections {
                if seeded.below(3) == 0 {
                    let mode = *seeded.pick(&modes);
                    floors.push((remotes.clone(), mode));
                    lines.push(limit(
                        audience,
                        Limit::Floor {
                            scope: scope(remotes),
                            mode,
                        },
                    ));
                }
            }
        }
        let decided = |lines: &[(Place, String)]| {
            let mut trail = Trail::started();
            for event in Policy::default().changes(&policy(lines)) {
                trail.push(event);
            }
            trail.push(Event::Opening {
                remote: workspace.clone(),
                with: Vec::new(),
                opener: Opener::Grant,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            });
            let state = trail.state();
            let world = World {
                catalogue: &catalogue,
                configuration: &configuration,
                state: &state,
            };
            let row = world
                .rows(ClientId(Seq(0)), Tick(0))
                .into_iter()
                .find(|row| row.remote.as_ref() == Some(&workspace))
                .expect("the grant's row");
            row.decides
                .into_iter()
                .find(|decides| decides.operation == Operation::Sign && decides.key.is_none())
                .expect("how signing is decided")
        };
        let free = decided(&[]);
        let held = decided(&lines);
        let covering = floors
            .iter()
            .filter(|(remotes, _)| remotes.covers(&workspace, &hedwig_model::remote::Sets::NONE))
            .map(|(_, mode)| *mode);
        let floor = covering.clone().max();
        assert_eq!(
            held.mode,
            floor.map_or(free.mode, |floor| floor.max(free.mode))
        );
        assert!(covering.clone().all(|floor| held.mode >= floor));
        if floor.is_none_or(|floor| floor <= free.mode) {
            assert_eq!((held.mode, &held.basis), (free.mode, &free.basis));
        }
    }
}

#[test]
fn an_organisations_denial_beats_a_persons_grant_and_leaves_their_document_as_it_was() {
    let (mut desk, interface, connection) = serving(Activation::OnRequest);
    let before = desk.configuration.export();
    let denial = Limit::Deny(Denial {
        capability: Selector::Only(name("gpg")),
        remotes: Remotes::Route(name("ssh")),
    });
    let denied = policy(&[limit(PERSON, denial.clone())]);
    desk.govern(&denied);
    let held = Refusal::Held {
        audience: PERSON,
        limit: Box::new(denial),
    };
    assert_eq!(
        desk.asks(connection, "gpg", Operation::Sign).1,
        Verdict::Refuse(held.clone())
    );
    assert_eq!(
        desk.row(interface, &host(), &name("gpg")).standing,
        Standing::Unavailable(held.clone())
    );
    assert_eq!(
        held.to_string(),
        "your organisation's policy for you denies it to this remote"
    );
    assert_eq!(desk.configuration.export(), before);
    assert!(Configuration::import(&catalogue(), before).is_ok());

    desk.govern(&Policy::default());
    assert!(served(&desk.asks(connection, "gpg", Operation::Sign).1));
}

#[test]
fn what_a_capability_exposes_is_withheld_or_confined_whoever_defined_it() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    // A service on another host of the network, defined by the person.
    let database = Capability {
        id: name("database"),
        source: Source::Service {
            host: ServiceHost::Named(Host::try_from("db.lab.example").unwrap()),
            port: ServicePort::Fixed(port(5432)),
            stream: Stream::Opaque,
            remote: vec![Offer::Port(ServicePort::Fixed(port(5432)))],
        },
    };
    desk.send(interface, Request::Change(Change::Define(database)))
        .unwrap();
    let workspace = remote("codespaces", "fluffy-space-7x9q");
    for (id, acknowledged) in [
        ("database", Exposure::SERVICE.with(Exposure::NETWORK)),
        (
            "gpg-unrestricted",
            Exposure::KEY_MANAGEMENT.with(Exposure::SECRET),
        ),
    ] {
        for remotes in [Granted::One(host()), Granted::One(workspace.clone())] {
            desk.send(
                interface,
                Request::Change(Change::Grant {
                    grant: grant(id, remotes),
                    terms: terms(Activation::OnRequest, acknowledged),
                }),
            )
            .unwrap();
        }
    }
    let on_host = desk.channel_up(&host(), "linux");
    let on_workspace = desk.channel_up(&workspace, "linux");

    let withhold = Limit::Withhold {
        exposure: Exposure::NETWORK,
        remotes: Remotes::Every,
    };
    let confine = Limit::Confine {
        exposure: Exposure::KEY_MANAGEMENT.with(Exposure::SECRET),
        remotes: Remotes::Route(name("ssh")),
    };
    desk.govern(&policy(&[
        limit(MACHINE, withhold.clone()),
        limit(MACHINE, confine.clone()),
    ]));
    let holds = |desk: &Desk, connection, id: &str| {
        desk.ask_world(|world| world.holds(connection, &name(id)))
    };
    let held = |limit: &Limit| {
        Err(Refusal::Held {
            audience: MACHINE,
            limit: Box::new(limit.clone()),
        })
    };
    assert_eq!(holds(&desk, on_host, "database"), held(&withhold));
    assert_eq!(holds(&desk, on_workspace, "database"), held(&withhold));
    assert_eq!(holds(&desk, on_host, "gpg-unrestricted"), Ok(()));
    assert_eq!(
        holds(&desk, on_workspace, "gpg-unrestricted"),
        held(&confine)
    );
    assert_eq!(
        holds(&desk, on_workspace, "gpg"),
        Err(Refusal::NotGranted {
            capability: name("gpg"),
            remote: workspace.clone(),
        })
    );
    assert_eq!(
        held(&confine).unwrap_err().to_string(),
        "your organisation's policy for this machine serves what exposes key-management, \
         secret only to other remotes"
    );

    // A capability added to a connection alone is held the same way.
    assert_eq!(
        desk.send(
            interface,
            Request::Connect {
                remote: remote("codespaces", "other-space"),
                with: vec![name("database")],
                acknowledged: Exposure::SERVICE.with(Exposure::NETWORK),
                lends: Lends::none(),
            }
        ),
        Err(Refusal::Held {
            audience: MACHINE,
            limit: Box::new(withhold),
        })
    );
}

#[test]
fn activation_and_writing_are_held_at_the_organisations_most() {
    let (mut desk, interface, _) = serving(Activation::Continuous);
    assert!(desk.ask_world(|world| world.wanted(&host())));
    desk.govern(&policy(&[limit(
        MACHINE,
        Limit::Activation {
            scope: every_grant(),
            most: Activation::OnRequest,
        },
    )]));
    assert!(!desk.ask_world(|world| world.wanted(&host())));
    assert!(matches!(
        desk.row(interface, &host(), &name("gpg")).through,
        Through::Grant(_)
    ));

    let windows = remote("ssh", "admin@winsrv.example");
    desk.send(
        interface,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(windows.clone())),
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        }),
    )
    .unwrap();
    let connection = desk.channel_up(&windows, "windows");
    assert!(matches!(
        desk.row(interface, &windows, &name("gpg")).standing,
        Standing::Serving(_)
    ));
    let inspect = Limit::InspectOnly(GrantScope {
        capability: Selector::Only(name("gpg")),
        remotes: Remotes::Route(name("ssh")),
    });
    desk.govern(&policy(&[limit(PERSON, inspect.clone())]));
    let held = Refusal::Held {
        audience: PERSON,
        limit: Box::new(inspect),
    };
    assert_eq!(
        desk.row(interface, &windows, &name("gpg")).standing,
        Standing::Unavailable(held.clone())
    );
    let plan = desk.ask_world(|world| world.plan(connection)).unwrap();
    assert_eq!(plan.get(&name("gpg")), Some(&Err(held)));
}

#[test]
fn the_smaller_of_the_persons_and_the_organisations_caps_decides_what_is_offered() {
    let (mut desk, interface, connection) = serving(Activation::OnRequest);
    let everything = CapScope {
        remotes: Remotes::Every,
        key: Keys::Every,
    };
    let seconds = |seconds: u32| NonZeroU32::new(seconds).unwrap();
    desk.govern(&policy(&[limit(
        MACHINE,
        Limit::Cap {
            scope: everything.clone(),
            longest: Longest::Seconds(seconds(900)),
        },
    )]));
    let longest = |desk: &Desk| desk.ask_world(|world| world.longest(&host(), None));
    assert_eq!(
        longest(&desk),
        Some(Capped {
            longest: Longest::Seconds(seconds(900)),
            holder: Holder::Organisation(MACHINE),
            scope: everything.clone(),
        })
    );
    let mine = CapScope {
        remotes: Remotes::One(host()),
        key: Keys::Every,
    };
    desk.send(
        interface,
        Request::Change(Change::Cap {
            scope: mine.clone(),
            longest: Some(Longest::Seconds(seconds(60))),
        }),
    )
    .unwrap();
    assert_eq!(
        longest(&desk).map(|capped| (capped.longest, capped.holder)),
        Some((Longest::Seconds(seconds(60)), Holder::Person))
    );

    desk.send(
        interface,
        Request::Change(Change::Cap {
            scope: mine,
            longest: None,
        }),
    )
    .unwrap();
    desk.send(
        interface,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::One(host()),
                capability: Selector::Every,
                operation: Selector::Every,
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    )
    .unwrap();
    let (request, verdict) = desk.asks(connection, "gpg", Operation::Sign);
    assert!(matches!(verdict, Verdict::Hold(_)));
    let offers = desk
        .ask_world(|world| world.attention(interface, desk.trail.tick()))
        .into_iter()
        .find_map(|needs| match needs.attention {
            Attention::Request { offers, .. } => Some(offers),
            _ => None,
        })
        .expect("the held request");
    assert_eq!(offers, vec![seconds(60), seconds(900)]);
    let decide = |seconds| Request::Decide {
        request,
        decision: Decision::For(seconds),
    };
    assert_eq!(
        desk.ask_world(|world| world.permit(interface, &decide(seconds(3600)))),
        Err(Refusal::NotOffered {
            seconds: seconds(3600)
        })
    );
}

#[test]
fn a_starting_grant_exposing_key_use_alone_serves_at_once_and_any_other_once_accepted() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let ssh = || Granted::Route(name("ssh"));
    desk.govern(&policy(&[
        start(
            MACHINE,
            Start::Grant {
                grant: grant("gpg", ssh()),
                activation: Activation::OnRequest,
            },
        ),
        start(
            MACHINE,
            Start::Grant {
                grant: grant("adb", ssh()),
                activation: Activation::OnRequest,
            },
        ),
    ]));
    let connection = desk.channel_up(&host(), "linux");
    assert!(served(&desk.asks(connection, "gpg", Operation::Sign).1));
    let waiting = Refusal::ExposureNotAcknowledged {
        capability: name("adb"),
        missing: Exposure::SERVICE,
    };
    assert_eq!(
        desk.asks(connection, "adb", Operation::Connect).1,
        Verdict::Refuse(waiting.clone())
    );

    let row = desk.row(interface, &host(), &name("adb"));
    assert_eq!(
        row.through,
        Through::Start {
            audience: MACHINE,
            grant: grant("adb", ssh()),
        }
    );
    assert_eq!(row.standing, Standing::Unavailable(waiting));
    let acts: Vec<Act> = row.acts.iter().map(|offered| offered.act).collect();
    assert!(acts.contains(&Act::Deny) && acts.contains(&Act::Accept));
    assert!(!acts.contains(&Act::Revoke));
    let gpg: Vec<Act> = desk
        .row(interface, &host(), &name("gpg"))
        .acts
        .iter()
        .map(|offered| offered.act)
        .collect();
    assert!(gpg.contains(&Act::Deny) && !gpg.contains(&Act::Accept));

    let accept = Change::Accept {
        grant: grant("adb", ssh()),
        accepted: hedwig_model::config::Accepted {
            setup: Setup::Inspect,
            acknowledged: Exposure::SERVICE,
            lends: Lends::none(),
        },
    };
    desk.send(interface, Request::Change(accept)).unwrap();
    assert!(served(&desk.asks(connection, "adb", Operation::Connect).1));
}

#[test]
fn the_persons_denial_ends_a_starting_grant_and_no_later_update_undoes_it() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let starting = |activation| {
        start(
            PERSON,
            Start::Grant {
                grant: grant("gpg", Granted::Route(name("ssh"))),
                activation,
            },
        )
    };
    desk.govern(&policy(&[starting(Activation::OnRequest)]));
    let connection = desk.channel_up(&host(), "linux");
    assert!(served(&desk.asks(connection, "gpg", Operation::Sign).1));
    desk.send(
        interface,
        Request::Change(Change::Deny(Denial {
            capability: Selector::Only(name("gpg")),
            remotes: Remotes::Route(name("ssh")),
        })),
    )
    .unwrap();
    let refused = Verdict::Refuse(Refusal::NotGranted {
        capability: name("gpg"),
        remote: host(),
    });
    assert_eq!(desk.asks(connection, "gpg", Operation::Sign).1, refused);
    desk.govern(&policy(&[
        starting(Activation::Continuous),
        start(MACHINE, Start::Autostart(Autostart::AtLogon)),
    ]));
    assert_eq!(desk.asks(connection, "gpg", Operation::Sign).1, refused);
}

#[test]
fn the_persons_own_grant_decides_its_terms_over_a_starting_grant_however_narrow() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.govern(&policy(&[start(
        MACHINE,
        Start::Grant {
            grant: grant("gpg", Granted::One(host())),
            activation: Activation::Continuous,
        },
    )]));
    assert!(desk.ask_world(|world| world.wanted(&host())));
    desk.send(
        interface,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::Route(name("ssh"))),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        }),
    )
    .unwrap();
    assert!(!desk.ask_world(|world| world.wanted(&host())));
    assert_eq!(
        desk.row(interface, &host(), &name("gpg")).through,
        Through::Grant(grant("gpg", Granted::Route(name("ssh"))))
    );
}

#[test]
#[allow(
    clippy::redundant_closure_for_method_calls,
    reason = "the method's lifetime is early-bound, so its path is not general enough"
)]
fn a_starting_choice_yields_to_the_person_and_the_persons_audience_is_the_nearer() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let at_rate = |requests: u8| {
        Threshold::At(Burst {
            requests: std::num::NonZeroU8::new(requests).unwrap(),
            seconds: NonZeroU32::new(60).unwrap(),
        })
    };
    let ssh = Remotes::Route(name("ssh"));
    desk.govern(&policy(&[
        start(
            MACHINE,
            Start::Burst {
                remotes: Remotes::One(host()),
                threshold: at_rate(5),
            },
        ),
        start(
            PERSON,
            Start::Burst {
                remotes: ssh.clone(),
                threshold: at_rate(20),
            },
        ),
        start(MACHINE, Start::Autostart(Autostart::AtLogon)),
    ]));
    assert_eq!(
        desk.ask_world(|world| world.threshold(&host())),
        Settled {
            value: at_rate(20),
            said: Said::Start {
                audience: PERSON,
                scope: ssh,
            },
        }
    );
    assert_eq!(
        desk.ask_world(|world| world.autostart()),
        Settled {
            value: Autostart::AtLogon,
            said: Said::Start {
                audience: MACHINE,
                scope: Workstation,
            },
        }
    );
    desk.send(
        interface,
        Request::Change(Change::Burst {
            remotes: Remotes::Every,
            threshold: Some(Threshold::Never),
        }),
    )
    .unwrap();
    desk.send(
        interface,
        Request::Change(Change::Autostart(Some(Autostart::Off))),
    )
    .unwrap();
    assert_eq!(
        desk.ask_world(|world| world.threshold(&host())).said,
        Said::Person(Remotes::Every)
    );
    assert_eq!(
        desk.ask_world(|world| world.autostart()).said,
        Said::Person(Workstation)
    );
}

#[test]
fn a_starting_rule_stricter_than_what_ships_decides_and_a_laxer_one_waits_for_the_person() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    for (id, acknowledged) in [
        ("gpg", Exposure::NONE),
        (
            "gpg-unrestricted",
            Exposure::KEY_MANAGEMENT.with(Exposure::SECRET),
        ),
    ] {
        desk.send(
            interface,
            Request::Change(Change::Grant {
                grant: grant(id, Granted::One(host())),
                terms: terms(Activation::OnRequest, acknowledged),
            }),
        )
        .unwrap();
    }
    let rule = |id: &str, operation, mode| {
        start(
            PERSON,
            Start::Rule {
                scope: RuleScope {
                    remotes: Remotes::Every,
                    capability: Selector::Only(name(id)),
                    operation: Selector::Only(operation),
                    key: Keys::Every,
                },
                mode,
            },
        )
    };
    desk.govern(&policy(&[
        rule("gpg", Operation::Sign, Attended::Confirm),
        rule("gpg-unrestricted", Operation::Connect, Attended::Notify),
    ]));
    let connection = desk.channel_up(&host(), "linux");
    assert!(matches!(
        desk.asks(connection, "gpg", Operation::Sign).1,
        Verdict::Hold(Basis::Start {
            audience: Audience::Person,
            ..
        })
    ));
    assert_eq!(
        desk.asks(connection, "gpg-unrestricted", Operation::Connect)
            .1,
        Verdict::Hold(Basis::Default)
    );
}

#[test]
fn the_organisations_definitions_join_what_ships_and_a_name_defined_twice_serves_nothing() {
    let Some(Start::Define(defined)) = corpus::starts().into_iter().next() else {
        unreachable!("the corpus starts with a definition")
    };
    let id = defined.id.clone();
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.govern(&policy(&[start(MACHINE, Start::Define(defined.clone()))]));
    let exposure = defined.exposure().common(Exposure::ACKNOWLEDGED);
    desk.send(
        interface,
        Request::Change(Change::Grant {
            grant: grant(id.as_str(), Granted::One(host())),
            terms: terms(Activation::OnRequest, exposure),
        }),
    )
    .unwrap();
    let connection = desk.channel_up(&host(), "linux");
    assert_eq!(desk.ask_world(|world| world.holds(connection, &id)), Ok(()));
    assert_eq!(
        desk.send(interface, Request::Change(Change::Define(defined.clone()))),
        Err(Refusal::Reserved(id.clone()))
    );

    let other = Capability {
        id: id.clone(),
        source: Source::Agent {
            at: AgentAt::Pipe(AgentPipe::well_known()),
        },
    };
    desk.govern(&policy(&[
        start(MACHINE, Start::Define(defined)),
        start(PERSON, Start::Define(other)),
    ]));
    assert_eq!(
        desk.ask_world(|world| world.holds(connection, &id)),
        Err(Refusal::Collides {
            section: hedwig_model::refusal::Section::Capabilities,
            name: id,
        })
    );
}

#[test]
fn the_trail_records_each_change_and_folds_to_the_policy_read() {
    let mut trail = Trail::started();
    let interface = trail.attach(ClientKind::Interface, DESKTOP);
    let first = policy(
        &corpus::statements()
            .iter()
            .zip([MACHINE, PERSON].into_iter().cycle())
            .map(|(statement, audience)| written(audience, statement))
            .collect::<Vec<_>>(),
    );
    let changes = Policy::default().changes(&first);
    assert_eq!(changes.len(), corpus::statements().len());
    for event in changes {
        trail.push(event);
    }
    assert_eq!(trail.state().policy(), &first);

    let mut lines: Vec<(Place, String)> = first
        .statements()
        .skip(1)
        .map(|(audience, statement)| written(audience, statement))
        .collect();
    lines.push(limit(
        PERSON,
        Limit::Withhold {
            exposure: Exposure::SECRET,
            remotes: Remotes::Route(name("codespaces")),
        },
    ));
    lines.push((at(MACHINE, Part::Start), "not a statement".to_owned()));
    let second = policy(&lines);
    let changes = first.changes(&second);
    assert!(matches!(
        changes.as_slice(),
        [
            Event::Unstated { .. },
            Event::Stated { .. },
            Event::Misread {
                unread: Some(_),
                ..
            }
        ]
    ));
    let since = Seq(u64::try_from(trail.entries.len()).unwrap() + 1);
    for event in changes {
        trail.push(event);
    }
    assert_eq!(trail.state().policy(), &second);
    assert_eq!(second.changes(&second), Vec::<Event>::new());

    let items = |trail: &Trail| -> Vec<Attention> {
        let state = trail.state();
        let catalogue = catalogue();
        World {
            catalogue: &catalogue,
            configuration: &Configuration::default(),
            state: &state,
        }
        .attention(interface, trail.tick())
        .into_iter()
        .map(|needs| needs.attention)
        .filter(|attention| matches!(attention, Attention::Policy { .. }))
        .collect()
    };
    // One item per place, however many statements changed there.
    let places: std::collections::BTreeSet<Place> = first
        .statements()
        .map(|(audience, statement)| at(audience, statement.part()))
        .collect();
    assert_eq!(items(&trail).len(), places.len());
    let machine_start = items(&trail)
        .into_iter()
        .find(|attention| {
            matches!(attention, Attention::Policy { place, .. } if *place == at(MACHINE, Part::Start))
        })
        .expect("the machine's starting point changed");
    assert!(matches!(machine_start, Attention::Policy { unread: 1, .. }));
    for place in corpus::places() {
        trail.push(Event::PutAway {
            item: Item::Policy(place),
            by: interface,
        });
    }
    assert_eq!(items(&trail), Vec::<Attention>::new());
    let third = policy(lines.get(1..).expect("a line to withdraw"));
    let later = Seq(u64::try_from(trail.entries.len()).unwrap() + 1);
    for event in second.changes(&third) {
        trail.push(event);
    }
    assert!(later > since);
    assert!(matches!(
        items(&trail).as_slice(),
        [Attention::Policy { since, withdrawn: 1, arrived: 0, .. }] if *since == later
    ));
}

#[test]
fn an_allowance_ends_when_what_the_organisation_states_changes() {
    let (mut desk, interface, connection) = serving(Activation::OnRequest);
    desk.send(
        interface,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::One(host()),
                capability: Selector::Every,
                operation: Selector::Every,
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    )
    .unwrap();
    let (request, _) = desk.asks(connection, "gpg", Operation::Sign);
    desk.send(
        interface,
        Request::Decide {
            request,
            decision: Decision::For(NonZeroU32::new(900).unwrap()),
        },
    )
    .unwrap();
    assert_eq!(
        desk.asks(connection, "gpg", Operation::Sign).1,
        Verdict::Serve(Outcome::Covered)
    );
    desk.govern(&policy(&[(
        at(MACHINE, Part::Ask),
        "the IT desk".to_owned(),
    )]));
    assert!(matches!(
        desk.asks(connection, "gpg", Operation::Sign).1,
        Verdict::Hold(_)
    ));
}

/// The catalogue says whose each definition is, and names every collision
/// with its sources: two audiences of the organisation, and the person's
/// own definition against one the organisation ships later under its name
/// A colliding name is listed only as a collision.
#[test]
fn the_catalogue_says_whose_each_definition_is_and_which_names_collide() {
    use hedwig_model::config::Collision;
    use hedwig_model::protocol::Reply;
    use hedwig_model::refusal::Section;
    use hedwig_model::scope::Tier;
    use hedwig_model::text::Name;

    let Some(Start::Define(defined)) = corpus::starts().into_iter().next() else {
        unreachable!("the corpus starts with a definition")
    };
    let id = defined.id.clone();
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let mine = Capability {
        id: name("bench-licence"),
        source: Source::Agent {
            at: AgentAt::Pipe(AgentPipe::well_known()),
        },
    };
    desk.send(interface, Request::Change(Change::Define(mine.clone())))
        .unwrap();
    let theirs = Capability {
        id: mine.id.clone(),
        source: defined.source.clone(),
    };
    desk.govern(&policy(&[
        start(MACHINE, Start::Define(defined.clone())),
        start(MACHINE, Start::Define(theirs)),
    ]));
    let Ok(Reply::Catalogue(listed)) = desk.send(interface, Request::Catalogue) else {
        unreachable!("the catalogue is a reply to anyone greeted")
    };
    let by = |wanted: &Name| {
        listed
            .capabilities
            .iter()
            .find(|listed| listed.definition.id == *wanted)
            .map(|listed| listed.by)
    };
    assert_eq!(by(&name("gpg")), Some(Tier::Ships));
    assert_eq!(by(&id), Some(Tier::Start(Audience::Machine)));
    assert_eq!(by(&mine.id), None, "a colliding name defines nothing");
    assert_eq!(
        listed.collisions,
        [Collision {
            section: Section::Capabilities,
            name: mine.id.clone(),
            by: vec![Tier::Start(Audience::Machine), Tier::Person],
        }]
    );

    let other = Capability {
        id: id.clone(),
        source: Source::Agent {
            at: AgentAt::Pipe(AgentPipe::well_known()),
        },
    };
    desk.govern(&policy(&[
        start(MACHINE, Start::Define(defined)),
        start(PERSON, Start::Define(other)),
    ]));
    let Ok(Reply::Catalogue(listed)) = desk.send(interface, Request::Catalogue) else {
        unreachable!("the catalogue is a reply to anyone greeted")
    };
    assert!(
        listed
            .capabilities
            .iter()
            .all(|listed| listed.definition.id != id)
    );
    assert!(listed.collisions.contains(&Collision {
        section: Section::Capabilities,
        name: id,
        by: vec![
            Tier::Start(Audience::Machine),
            Tier::Start(Audience::Person)
        ],
    }));
}

fn days(days: u16) -> Keep {
    Keep(std::num::NonZeroU16::new(days).unwrap())
}

#[test]
#[allow(
    clippy::redundant_closure_for_method_calls,
    reason = "the method's lifetime is early-bound, so its path is not general enough"
)]
fn what_starts_at_sign_in_what_is_kept_and_what_is_written_resolve_and_limits_hold_them() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    assert_eq!(
        desk.ask_world(|world| world.icon()),
        Settled {
            value: Autostart::Off,
            said: Said::Ships,
        }
    );
    assert_eq!(
        desk.ask_world(|world| world.keep()),
        Bounded {
            settled: Settled {
                value: Keep::SHIPS,
                said: Said::Ships,
            },
            held: None,
        }
    );
    assert_eq!(
        desk.ask_world(|world| world.diagnostics()).settled.value,
        Diagnostics::Faults
    );
    for change in [
        Change::Icon(Some(Autostart::AtLogon)),
        Change::Keep(Some(days(7))),
        Change::Diagnostics(Some(Diagnostics::Detail)),
    ] {
        desk.send(interface, Request::Change(change)).unwrap();
    }
    assert_eq!(
        desk.ask_world(|world| world.icon()).said,
        Said::Person(Workstation)
    );
    assert_eq!(desk.ask_world(|world| world.keep()).settled.value, days(7));

    desk.govern(&policy(&[
        limit(MACHINE, Limit::KeepAtLeast(days(30))),
        limit(PERSON, Limit::KeepAtLeast(days(14))),
        limit(PERSON, Limit::DiagnosticsAtMost(Diagnostics::Faults)),
        start(MACHINE, Start::Icon(Autostart::Off)),
    ]));
    assert_eq!(
        desk.ask_world(|world| world.keep()),
        Bounded {
            settled: Settled {
                value: days(30),
                said: Said::Person(Workstation),
            },
            held: Some(MACHINE),
        },
        "the strictest least holds the person's seven days, and says whose it is"
    );
    assert_eq!(
        desk.ask_world(|world| world.diagnostics()),
        Bounded {
            settled: Settled {
                value: Diagnostics::Faults,
                said: Said::Person(Span::Workstation),
            },
            held: Some(PERSON),
        }
    );
    assert_eq!(
        desk.ask_world(|world| world.icon()).value,
        Autostart::AtLogon,
        "a starting value never changes what the person stated"
    );
    desk.send(interface, Request::Change(Change::Keep(Some(days(365)))))
        .unwrap();
    desk.govern(&policy(&[limit(MACHINE, Limit::KeepAtMost(days(90)))]));
    assert_eq!(
        desk.ask_world(|world| world.keep()),
        Bounded {
            settled: Settled {
                value: days(90),
                said: Said::Person(Workstation),
            },
            held: Some(MACHINE),
        }
    );
    desk.govern(&policy(&[]));
    assert_eq!(
        desk.ask_world(|world| world.keep()).settled.value,
        days(365),
        "the limit gone, the person's own statement serves as made"
    );
}

/// A run's own choice of what is written is the person's nearer
/// statement, held by the organisation's most as the workstation's is, said
/// as the run's, and gone with the run.
#[test]
#[allow(
    clippy::redundant_closure_for_method_calls,
    reason = "the method's lifetime is early-bound, so its path is not general enough"
)]
fn a_runs_diagnostics_are_nearer_than_the_workstations_and_the_same_limit_holds_them() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(
        interface,
        Request::Change(Change::Diagnostics(Some(Diagnostics::Detail))),
    )
    .unwrap();
    desk.govern(&policy(&[limit(
        PERSON,
        Limit::DiagnosticsAtMost(Diagnostics::Faults),
    )]));
    assert_eq!(
        desk.ask_world(|world| world.diagnostics()),
        Bounded {
            settled: Settled {
                value: Diagnostics::Faults,
                said: Said::Person(Span::Workstation),
            },
            held: Some(PERSON),
        }
    );
    // A choice for this run is the nearer statement, the limit holds it
    // too, and the reply says it is the run's.
    assert_eq!(
        desk.send(interface, Request::Diagnose(Some(Diagnostics::Off))),
        Ok(Reply::Done(Effect::Changed))
    );
    assert_eq!(
        desk.ask_world(|world| world.diagnostics()).settled,
        Settled {
            value: Diagnostics::Off,
            said: Said::Person(Span::Run),
        }
    );
    desk.send(interface, Request::Diagnose(Some(Diagnostics::Detail)))
        .unwrap();
    assert_eq!(
        desk.ask_world(|world| world.diagnostics()),
        Bounded {
            settled: Settled {
                value: Diagnostics::Faults,
                said: Said::Person(Span::Run),
            },
            held: Some(PERSON),
        },
        "the organisation's most holds the run's choice as it holds the workstation's"
    );
    assert_eq!(
        desk.send(interface, Request::Diagnose(Some(Diagnostics::Detail))),
        Ok(Reply::Done(Effect::Unchanged))
    );
    desk.send(interface, Request::Diagnose(None)).unwrap();
    assert_eq!(
        desk.ask_world(|world| world.diagnostics()).settled.said,
        Said::Person(Span::Workstation)
    );
    desk.send(interface, Request::Diagnose(Some(Diagnostics::Off)))
        .unwrap();
    desk.trail.push(Event::Started {
        version: "0.2.1".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    assert_eq!(
        desk.ask_world(|world| world.diagnostics()).settled.said,
        Said::Person(Span::Workstation),
        "a run's choice ends with the run"
    );
}
