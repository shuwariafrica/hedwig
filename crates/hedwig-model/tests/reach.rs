//! Who on a remote reaches a forward, and what lets more of them reach it:
//! taking consent to write back from a capability offered behind a private
//! socket and on a port lets more through, an organisation's limit never
//! does, and a remote whose platform is unknown is carried on a port only
//! where every platform would carry it there.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU16;

use hedwig_model::capability::{Exposure, Form, Lends, ServicePort, Setup, Whom};
use hedwig_model::config::{Accepted, Activation, Change, Reach, Terms};
use hedwig_model::organisation::{GrantScope, Limit, Part, Place, Policy};
use hedwig_model::platform::{AgentForwarding, Platform, Sockets};
use hedwig_model::policy::Selector;
use hedwig_model::protocol::{Request, Standing};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::scope::Audience;
use hedwig_model::text::Kernel;
use hedwig_model::trail::{ClientKind, ConnectionId, Event, Opener};
use hedwig_model::wire::line;

mod support;
use support::desk::Desk;
use support::{DESKTOP, capability, catalogue, grant, granting, name, port, remote};

const UNIX: Sockets = Sockets::Unix {
    path_bytes: NonZeroU16::new(108).unwrap(),
};

fn host() -> RemoteId {
    remote("ssh", "dev@build.example")
}

fn granted(setup: Setup, acknowledged: Exposure) -> Terms {
    Terms {
        activation: Activation::OnRequest,
        setup,
        acknowledged,
        lends: Lends::none(),
    }
}

/// A desk with `capability` granted to `host` with `setup`.
fn desk(capability: &str, setup: Setup, acknowledged: Exposure) -> Desk {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(
        interface,
        Request::Change(Change::Grant {
            grant: grant(capability, Granted::One(host())),
            terms: granted(setup, acknowledged),
        }),
    )
    .unwrap();
    desk
}

fn inspect_only(capability: &str) -> Limit {
    Limit::InspectOnly(GrantScope {
        capability: Selector::Only(name(capability)),
        remotes: Remotes::Every,
    })
}

fn policy(limit: &Limit) -> Policy {
    let place = Place {
        audience: Audience::Person,
        part: Part::Limits,
    };
    Policy::read([(place, line(limit).as_str())])
}

#[test]
fn each_form_says_who_on_the_remote_reaches_it_under_each_setup() {
    let catalogue = catalogue();
    let adb = capability(&catalogue, "adb");
    assert_eq!(adb.reach(UNIX, Setup::Write), Some(Whom::Account));
    assert_eq!(adb.reach(UNIX, Setup::Inspect), Some(Whom::Anyone));
    assert_eq!(
        adb.reach(Sockets::Emulated, Setup::Write),
        Some(Whom::Anyone)
    );
    assert_eq!(
        adb.reach(Sockets::Emulated, Setup::Inspect),
        Some(Whom::Anyone)
    );

    let gpg = capability(&catalogue, "gpg");
    assert_eq!(gpg.reach(UNIX, Setup::Inspect), Some(Whom::Account));
    assert_eq!(
        gpg.reach(Sockets::Emulated, Setup::Write),
        Some(Whom::Account)
    );
    assert_eq!(gpg.reach(Sockets::Emulated, Setup::Inspect), None);

    let browser = support::browser();
    assert_eq!(browser.reach(UNIX, Setup::Write), Some(Whom::Account));
    assert_eq!(browser.reach(UNIX, Setup::Inspect), None);
    assert_eq!(browser.reach(Sockets::Emulated, Setup::Write), None);

    let openocd = capability(&catalogue, "openocd");
    assert_eq!(openocd.reach(UNIX, Setup::Write), Some(Whom::Anyone));
    assert!(openocd.open_everywhere(Setup::Write));
    assert!(adb.open_everywhere(Setup::Inspect));
    assert!(!adb.open_everywhere(Setup::Write));
    assert!(!gpg.open_everywhere(Setup::Inspect));
}

/// ADB-2: from write to inspect, `adb`'s forward leaves the socket only the
/// remote user opens for port 5037, which every user there reaches.
#[test]
fn taking_consent_back_lets_more_through_where_the_forward_moves_to_a_port() {
    let catalogue = catalogue();
    let judged = |id: &str, from: Setup, to: Setup| {
        let mut configuration = granting(&catalogue, &[]);
        // Nothing that opens the person's browser ships: it is theirs.
        configuration
            .apply(&catalogue, Change::Define(support::browser()))
            .unwrap();
        let acknowledged = configuration
            .capability(&catalogue, &name(id))
            .unwrap()
            .exposure();
        configuration
            .apply(
                &catalogue,
                Change::Grant {
                    grant: grant(id, Granted::One(host())),
                    terms: granted(from, acknowledged),
                },
            )
            .unwrap();
        configuration.widens(
            &catalogue,
            &Change::Grant {
                grant: grant(id, Granted::One(host())),
                terms: granted(to, acknowledged),
            },
        )
    };
    assert_eq!(judged("adb", Setup::Write, Setup::Inspect), Reach::Wider);
    assert_eq!(judged("adb", Setup::Inspect, Setup::Write), Reach::Wider);
    assert_eq!(judged("gpg", Setup::Write, Setup::Inspect), Reach::NoWider);
    assert_eq!(judged("gpg", Setup::Inspect, Setup::Write), Reach::Wider);
    assert_eq!(
        judged("browser", Setup::Write, Setup::Inspect),
        Reach::NoWider
    );
    assert_eq!(
        judged("openocd", Setup::Write, Setup::Inspect),
        Reach::NoWider
    );
    assert_eq!(judged("adb", Setup::Write, Setup::Write), Reach::NoWider);

    // An organisation's starting grant, once the person accepted it.
    let accept = |setup| Change::Accept {
        grant: grant("adb", Granted::Route(name("ssh"))),
        accepted: Accepted {
            setup,
            acknowledged: Exposure::SERVICE,
            lends: Lends::none(),
        },
    };
    let mut configuration = granting(&catalogue, &[]);
    configuration
        .apply(&catalogue, accept(Setup::Write))
        .unwrap();
    assert_eq!(
        configuration.widens(&catalogue, &accept(Setup::Inspect)),
        Reach::Wider
    );
}

/// The interface makes the change the person makes, and the core records
/// it as letting more through, which raises it wherever it was not made.
#[test]
fn taking_consent_back_from_adb_reaches_the_person_at_every_other_client() {
    let mut desk = desk("adb", Setup::Write, Exposure::SERVICE);
    let script = desk.attend(ClientKind::Command, DESKTOP);
    let change = Change::Grant {
        grant: grant("adb", Granted::One(host())),
        terms: granted(Setup::Inspect, Exposure::SERVICE),
    };
    assert_eq!(
        desk.ask_world(|world| world.widens(&Request::Change(change.clone()))),
        Reach::Wider
    );
    desk.send(script, Request::Change(change)).unwrap();
    let recorded = desk
        .trail
        .entries
        .iter()
        .rev()
        .find_map(|entry| match &entry.event {
            Event::Changed { reach, .. } => Some(reach),
            _ => None,
        });
    assert_eq!(recorded, Some(&Reach::Wider));
}

/// A platform defined for a system nothing answered to, or one whose
/// sockets take the other shape, moves the forms its remotes take.
#[test]
fn a_platform_that_moves_its_remotes_forms_lets_more_through() {
    let catalogue = catalogue();
    let mut configuration = granting(&catalogue, &[]);
    let plan9 = |sockets| Platform {
        family: name("plan9"),
        kernel: Kernel::try_from("Plan9").unwrap(),
        sockets,
        agent_forwarding: AgentForwarding::Refused,
    };
    let mut judged = |platform: Platform| {
        let change = Change::DefinePlatform(platform);
        let reach = configuration.widens(&catalogue, &change);
        configuration.apply(&catalogue, change).unwrap();
        reach
    };
    assert_eq!(judged(plan9(Sockets::Emulated)), Reach::Wider, "new");
    assert_eq!(judged(plan9(Sockets::Emulated)), Reach::NoWider, "again");
    assert_eq!(judged(plan9(UNIX)), Reach::Wider, "the other shape");
    let longer = Sockets::Unix {
        path_bytes: NonZeroU16::new(104).unwrap(),
    };
    assert_eq!(judged(plan9(longer)), Reach::NoWider, "the same shape");
    let renamed = Platform {
        kernel: Kernel::try_from("Plan9-4e").unwrap(),
        ..plan9(longer)
    };
    assert_eq!(judged(renamed), Reach::Wider, "answering to another system");
    assert_eq!(
        configuration.widens(&catalogue, &Change::UndefinePlatform(name("plan9"))),
        Reach::NoWider
    );
}

/// An organisation's limit holds and never loosens: keeping a grant from
/// writing does not move `adb` to the port the person did not choose.
#[test]
fn a_limit_that_keeps_adb_from_writing_holds_it_rather_than_open_the_port() {
    let mut desk = desk("adb", Setup::Write, Exposure::SERVICE);
    let connection = desk.channel_up(&host(), "linux");
    let plan = desk.ask_world(|world| world.plan(connection)).unwrap();
    assert!(matches!(
        plan.get(&name("adb")),
        Some(Ok(Form::PrivateSocket { .. }))
    ));

    let limit = inspect_only("adb");
    desk.govern(&policy(&limit));
    let held = Refusal::Held {
        audience: Audience::Person,
        limit: Box::new(limit),
    };
    let plan = desk.ask_world(|world| world.plan(connection)).unwrap();
    assert_eq!(plan.get(&name("adb")), Some(&Err(held.clone())));
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    assert!(matches!(
        desk.row(interface, &host(), &name("adb")).standing,
        Standing::Unavailable(refusal) if refusal == held
    ));

    // On a Windows remote the grant's own form is the port, so the limit
    // leaves it as it was.
    let windows = remote("ssh", "dev@winbuild.example");
    let script = desk.attend(ClientKind::Command, DESKTOP);
    desk.send(
        script,
        Request::Change(Change::Grant {
            grant: grant("adb", Granted::One(windows.clone())),
            terms: granted(Setup::Write, Exposure::SERVICE),
        }),
    )
    .unwrap();
    let connection = desk.channel_up(&windows, "windows");
    let plan = desk.ask_world(|world| world.plan(connection)).unwrap();
    assert_eq!(
        plan.get(&name("adb")),
        Some(&Ok(Form::Port(ServicePort::Fixed(port(5037)))))
    );
}

#[test]
fn a_limit_that_keeps_gpg_from_writing_on_a_unix_remote_changes_nothing() {
    let mut desk = desk("gpg", Setup::Write, Exposure::NONE);
    let connection = desk.channel_up(&host(), "linux");
    let before = desk.ask_world(|world| world.plan(connection)).unwrap();
    desk.govern(&policy(&inspect_only("gpg")));
    let after = desk.ask_world(|world| world.plan(connection)).unwrap();
    assert_eq!(before, after);
    assert!(matches!(
        after.get(&name("gpg")),
        Some(Ok(Form::SocketAt(_)))
    ));
}

/// Where no shell answered, a port carries only what the grant would carry
/// on a port on every platform.
#[test]
fn an_unknown_platform_carries_a_port_only_where_the_grant_chose_one_everywhere() {
    let unobserved = |id: &str, setup: Setup, acknowledged: Exposure| {
        let mut desk = desk(id, setup, acknowledged);
        let connection = ConnectionId(desk.trail.push(Event::Opening {
            remote: host(),
            with: Vec::new(),
            opener: Opener::Grant,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        }));
        desk.ask_world(|world| world.plan_unobserved(connection))
            .unwrap()
            .remove(&name(id))
            .unwrap()
    };
    assert_eq!(
        unobserved("adb", Setup::Inspect, Exposure::SERVICE),
        Ok(Form::Port(ServicePort::Fixed(port(5037))))
    );
    assert_eq!(
        unobserved("adb", Setup::Write, Exposure::SERVICE),
        Err(Refusal::PlatformUnobserved(host()))
    );
    assert_eq!(
        unobserved("openocd", Setup::Write, Exposure::SERVICE),
        Ok(Form::Port(ServicePort::Fixed(port(3333))))
    );
    assert_eq!(
        unobserved("gpg", Setup::Write, Exposure::NONE),
        Err(Refusal::PlatformUnobserved(host()))
    );
}
