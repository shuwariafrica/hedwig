//! What a grant lends of a source that holds devices: none until the person
//! names a device, every device only as a choice of its own, the narrowest
//! grant deciding, a capability added to one connection lending what the person
//! named for it, and lending refused wherever the source holds no devices.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::{Exposure, Holds, Lends};
use hedwig_model::config::{Accepted, Activation, Change, Configuration, GrantEntry, Reach, Terms};
use hedwig_model::protocol::{Attachment, DeviceState, Lendable, Notice, Reply, Request, Topic};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId};
use hedwig_model::text::{DeviceSerial, Words};
use hedwig_model::trail::{ClientKind, Failure};

mod support;
use support::desk::Desk;
use support::{DESKTOP, catalogue, grant, name, pattern, remote};

fn host() -> RemoteId {
    remote("ssh", "dev@build.example")
}

fn serial(text: &str) -> DeviceSerial {
    DeviceSerial::try_from(text).unwrap()
}

fn named(serials: &[&str]) -> Lends {
    Lends::devices(serials.iter().map(|text| serial(text)))
}

fn adb_terms(acknowledged: Exposure, lends: Lends) -> Terms {
    Terms {
        activation: Activation::OnRequest,
        setup: hedwig_model::capability::Setup::Inspect,
        acknowledged,
        lends,
    }
}

/// The lending the remote of the desk's live channel holds of `capability`.
fn lending(desk: &Desk, capability: &str) -> Option<(Lends, bool)> {
    let state = desk.trail.state();
    let (_, link) = state.connection(&host()).expect("a channel is up");
    desk.ask_world(|world| world.lending(link, &name(capability)))
}

#[test]
fn a_grant_that_names_no_device_lends_none_and_every_device_is_a_choice_of_its_own() {
    for (lends, network) in [
        (Lends::none(), false),
        (named(&["R5CT1234ABC"]), true),
        (Lends::Every, false),
    ] {
        let mut desk = Desk::new(catalogue());
        let interface = desk.attend(ClientKind::Interface, DESKTOP);
        let acknowledged = if network {
            Exposure::SERVICE.with(Exposure::NETWORK)
        } else {
            Exposure::SERVICE
        };
        desk.send(
            interface,
            Request::Change(Change::Grant {
                grant: grant("adb", Granted::One(host())),
                terms: adb_terms(acknowledged, lends.clone()),
            }),
        )
        .unwrap();
        desk.channel_up(&host(), "linux");
        assert_eq!(lending(&desk, "adb"), Some((lends, network)));
    }
}

#[test]
fn lending_a_device_of_a_source_that_holds_none_is_refused_at_every_door() {
    let catalogue = catalogue();
    let mut desk = Desk::new(catalogue.clone());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let refused = Refusal::Unlendable {
        capability: name("gpg"),
        lent: Holds::Devices,
    };
    let unlendable: Result<Reply, Refusal> = Err(refused.clone());
    let gpg = Change::Grant {
        grant: grant("gpg", Granted::One(host())),
        terms: Terms {
            activation: Activation::OnRequest,
            setup: hedwig_model::capability::Setup::Inspect,
            acknowledged: Exposure::NONE,
            lends: named(&["R5CT1234ABC"]),
        },
    };
    assert_eq!(
        desk.send(interface, Request::Change(gpg.clone())),
        unlendable
    );
    let accept = Change::Accept {
        grant: grant("gpg", Granted::One(host())),
        accepted: Accepted {
            setup: hedwig_model::capability::Setup::Inspect,
            acknowledged: Exposure::NONE,
            lends: Lends::Every,
        },
    };
    assert_eq!(desk.send(interface, Request::Change(accept)), unlendable);
    // The same grant in a document.
    let mut document = Configuration::default().export();
    let Change::Grant { grant, terms } = gpg else {
        unreachable!("a grant")
    };
    document.grants.push(GrantEntry { grant, terms });
    assert_eq!(
        Configuration::import(&catalogue, document).map(drop),
        Err(refused)
    );
    // Added to one connection: refused where nothing added holds devices,
    // lent to the one that does where several are added.
    let connect = |with: &[&str]| Request::Connect {
        remote: host(),
        with: with.iter().map(|id| name(id)).collect(),
        acknowledged: Exposure::SERVICE,
        lends: named(&["emulator-5554"]),
    };
    assert_eq!(desk.send(interface, connect(&["gpg"])), unlendable);
    assert!(desk.send(interface, connect(&["gpg", "adb"])).is_ok());
    // The grant surface asks the source what it holds only where it holds
    // devices.
    assert_eq!(
        desk.send(interface, Request::Devices(name("gpg"))),
        unlendable
    );
    assert!(matches!(
        desk.send(interface, Request::Devices(name("adb"))),
        Err(Refusal::SourceUnavailable { .. })
    ));
}

fn device(serial_text: &str, state: DeviceState) -> Lendable {
    Lendable {
        serial: Some(serial(serial_text)),
        model: Words::try_from("Pixel 8").ok(),
        state,
        attached: Attachment::Usb,
    }
}

/// The devices are what the server lists, and where it lists none the
/// refusal says what failed - nothing answering, something that is no ADB
/// server, a server too old.
#[test]
fn the_devices_are_the_servers_and_a_refusal_says_what_failed() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let unavailable = |failure| {
        Err(Refusal::SourceUnavailable {
            capability: name("adb"),
            failure,
        })
    };
    assert_eq!(
        desk.send(interface, Request::Devices(name("adb"))),
        unavailable(Failure::Unreachable)
    );
    let words = Refusal::SourceUnavailable {
        capability: name("adb"),
        failure: Failure::Unreachable,
    }
    .to_string();
    assert_eq!(words, "nothing answers for adb on this workstation");
    for failure in [Failure::Mismatched, Failure::Outdated, Failure::Foreign] {
        desk.hold_devices(&name("adb"), Err(failure));
        assert_eq!(
            desk.send(interface, Request::Devices(name("adb"))),
            unavailable(failure)
        );
    }
    let phone = vec![device("R5CR10ABC", DeviceState::Device)];
    desk.hold_devices(&name("adb"), Ok(phone.clone()));
    assert_eq!(
        desk.send(interface, Request::Devices(name("adb"))),
        Ok(Reply::Devices(phone))
    );
}

/// A client that listed a source's devices is told once each time what
/// it listed changes, until it leaves; a client that did not list them, or
/// listed another source's, is told nothing.
#[test]
fn a_client_that_listed_the_devices_is_told_when_they_change_until_it_leaves() {
    let mut desk = Desk::new(catalogue());
    let window = desk.attend(ClientKind::Interface, DESKTOP);
    let terminal = desk.attend(ClientKind::Terminal, DESKTOP);
    let stale = Notice::Stale(Topic::Devices(name("adb")));
    assert_eq!(
        Topic::listed(&Request::Devices(name("adb"))),
        Some(Topic::Devices(name("adb")))
    );
    assert_eq!(
        Topic::listed(&Request::Keys(name("ssh-agent"))),
        Some(Topic::Keys(name("ssh-agent")))
    );
    assert_eq!(Topic::listed(&Request::Status), None);
    // Nothing has listed them: a phone attached tells nobody.
    let phone = vec![device("R5CR10ABC", DeviceState::Device)];
    assert_eq!(
        desk.hold_devices(&name("adb"), Ok(phone.clone())),
        Vec::<(hedwig_model::trail::ClientId, Notice)>::new()
    );
    let _ = desk.send(window, Request::Devices(name("adb")));
    let _ = desk.send(terminal, Request::Ports);
    // Authorised on the phone: the window alone is told, once.
    let authorised = vec![
        device("R5CR10ABC", DeviceState::Device),
        device("emulator-5554", DeviceState::Device),
    ];
    assert_eq!(
        desk.hold_devices(&name("adb"), Ok(authorised.clone())),
        vec![(window, stale.clone())]
    );
    assert_eq!(
        desk.hold_devices(&name("adb"), Ok(authorised)),
        Vec::<(hedwig_model::trail::ClientId, Notice)>::new()
    );
    // The server going away is a change too: what it listed no longer
    // stands.
    assert_eq!(
        desk.hold_devices(&name("adb"), Err(Failure::Unreachable)),
        vec![(window, stale)]
    );
    desk.detach(window);
    assert_eq!(
        desk.hold_devices(&name("adb"), Ok(phone)),
        Vec::<(hedwig_model::trail::ClientId, Notice)>::new()
    );
}

#[test]
fn lending_a_device_more_lets_more_through_and_lending_fewer_does_not() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let change = |lends: Lends| Change::Grant {
        grant: grant("adb", Granted::One(host())),
        terms: adb_terms(Exposure::SERVICE, lends),
    };
    let widens = |desk: &Desk, lends: Lends| {
        desk.ask_world(|world| world.widens(&Request::Change(change(lends))))
    };
    desk.send(
        interface,
        Request::Change(change(named(&["emulator-5554"]))),
    )
    .unwrap();
    assert_eq!(widens(&desk, named(&["emulator-5554"])), Reach::NoWider);
    assert_eq!(widens(&desk, Lends::none()), Reach::NoWider);
    assert_eq!(
        widens(&desk, named(&["emulator-5554", "R5CT1234ABC"])),
        Reach::Wider
    );
    assert_eq!(widens(&desk, named(&["R5CT1234ABC"])), Reach::Wider);
    assert_eq!(widens(&desk, Lends::Every), Reach::Wider);
    desk.send(interface, Request::Change(change(Lends::Every)))
        .unwrap();
    assert_eq!(widens(&desk, named(&["R5CT1234ABC"])), Reach::NoWider);
}

#[test]
fn of_two_equally_narrow_grants_the_one_lending_fewer_decides() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    // A pattern and a set select one remote equally narrowly.
    let set = hedwig_model::remote::Set {
        id: name("bench"),
        members: vec![hedwig_model::remote::Member::One(host())],
    };
    desk.send(interface, Request::Change(Change::DefineSet(set)))
        .unwrap();
    for (remotes, lends) in [
        (
            Granted::Matching {
                route: name("ssh"),
                pattern: pattern("dev@*"),
            },
            named(&["emulator-5554", "R5CT1234ABC"]),
        ),
        (Granted::Set(name("bench")), named(&["emulator-5554"])),
    ] {
        desk.send(
            interface,
            Request::Change(Change::Grant {
                grant: grant("adb", remotes),
                terms: adb_terms(Exposure::SERVICE, lends),
            }),
        )
        .unwrap();
    }
    desk.channel_up(&host(), "linux");
    assert_eq!(
        lending(&desk, "adb"),
        Some((named(&["emulator-5554"]), false))
    );
}

#[test]
fn a_capability_added_to_one_connection_lends_what_the_person_named_for_it() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(
        interface,
        Request::Connect {
            remote: host(),
            with: vec![name("adb")],
            acknowledged: Exposure::SERVICE.with(Exposure::NETWORK),
            lends: named(&["192.168.1.20:5555"]),
        },
    )
    .unwrap();
    desk.channel_up(&host(), "linux");
    assert_eq!(
        lending(&desk, "adb"),
        Some((named(&["192.168.1.20:5555"]), true))
    );
}
