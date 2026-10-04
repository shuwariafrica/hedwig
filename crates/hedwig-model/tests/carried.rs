//! What an ADB capability carries on to a remote - its reverses, forwards
//! and consoles: on that capability's row, kept apart from another ADB
//! capability's on the same remote, in the remote's activity, and gone from
//! the row once dropped.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::{
    Capability, Exposure, Lends, Offer, ServiceHost, ServicePort, Setup, Source, Stream,
};
use hedwig_model::config::{Activation, Change, Terms};
use hedwig_model::protocol::{CarriedOn, Request};
use hedwig_model::remote::Sets;
use hedwig_model::remote::{Granted, RemoteId};
use hedwig_model::text::{DeviceSerial, DeviceSocket, Port};
use hedwig_model::trail::{
    Carriage, ClientKind, ConnectionId, Dropped, Event, State, Target, about,
};

mod support;
use support::desk::Desk;
use support::{DESKTOP, catalogue, grant, name, port, remote};

fn host() -> RemoteId {
    remote("ssh", "dev@build.example")
}

/// A second ADB server on the workstation, an emulator host's own.
fn emulator() -> Capability {
    Capability {
        id: name("adb-emulator"),
        source: Source::Service {
            host: ServiceHost::Workstation,
            port: ServicePort::Fixed(port(5038)),
            stream: Stream::Adb,
            remote: vec![Offer::Port(ServicePort::Fixed(port(5038)))],
        },
    }
}

fn carried(connection: ConnectionId, capability: &str, target: &Target, endpoint: Port) -> Event {
    Event::Carried {
        connection,
        capability: name(capability),
        carriage: Carriage::Reverse(target.clone()),
        endpoint,
    }
}

fn reverse(target: &Target, endpoint: Port) -> CarriedOn {
    CarriedOn {
        carriage: Carriage::Reverse(target.clone()),
        endpoint,
    }
}

/// Each ADB capability's row carries the reverses it carried,
/// with the endpoint its own server names, and the remote's activity holds
/// every one of them.
#[test]
fn each_adb_capabilitys_row_carries_its_own_reverses_and_the_activity_holds_them() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(interface, Request::Change(Change::Define(emulator())))
        .unwrap();
    for capability in ["adb", "adb-emulator"] {
        desk.send(
            interface,
            Request::Change(Change::Grant {
                grant: grant(capability, Granted::One(host())),
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Inspect,
                    acknowledged: Exposure::SERVICE,
                    lends: Lends::none(),
                },
            }),
        )
        .unwrap();
    }
    let connection = desk.channel_up(&host(), "linux");
    let metro = Target::Loopback(port(8081));
    let socket = Target::Path(
        hedwig_model::text::RemotePath::try_from("/run/user/1000/metro.sock").unwrap(),
    );
    let entries = [
        desk.trail
            .push(carried(connection, "adb", &metro, port(50131))),
        desk.trail
            .push(carried(connection, "adb", &socket, port(50133))),
        desk.trail
            .push(carried(connection, "adb-emulator", &metro, port(50140))),
    ];

    let reverses =
        |desk: &Desk, capability: &str| desk.row(interface, &host(), &name(capability)).carried;
    assert_eq!(
        reverses(&desk, "adb"),
        [reverse(&metro, port(50131)), reverse(&socket, port(50133)),]
    );
    assert_eq!(
        reverses(&desk, "adb-emulator"),
        [reverse(&metro, port(50140))]
    );

    let activity: Vec<_> = about(&State::default(), &desk.trail.entries, &host(), &Sets::NONE)
        .map(|entry| entry.seq)
        .collect();
    for entry in entries {
        assert!(activity.contains(&entry), "{entry:?}");
    }
    let elsewhere = remote("ssh", "dev@other.example");
    assert!(
        about(
            &State::default(),
            &desk.trail.entries,
            &elsewhere,
            &Sets::NONE
        )
        .all(|entry| !matches!(entry.event, Event::Carried { .. }))
    );
}

/// A forward and a console are on the row beside a reverse, with
/// the core's endpoint for each; a forward the remote removes, and a console
/// whose emulator is no longer lent, leave the row, and the reverse stays.
#[test]
fn forwards_and_consoles_are_on_the_row_until_dropped() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(
        interface,
        Request::Change(Change::Grant {
            grant: grant("adb", Granted::One(host())),
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged: Exposure::SERVICE,
                lends: Lends::Every,
            },
        }),
    )
    .unwrap();
    let connection = desk.channel_up(&host(), "linux");
    let emulator = DeviceSerial::try_from("emulator-5554").unwrap();
    let forward = Carriage::Forward {
        port: port(9222),
        device: emulator.clone(),
        socket: DeviceSocket::try_from("localabstract:chrome_devtools_remote").unwrap(),
    };
    let console = Carriage::Console {
        port: port(5554),
        device: emulator,
    };
    let metro = Target::Loopback(port(8081));
    desk.trail
        .push(carried(connection, "adb", &metro, port(50131)));
    for (carriage, endpoint) in [(&forward, port(58765)), (&console, port(50134))] {
        desk.trail.push(Event::Carried {
            connection,
            capability: name("adb"),
            carriage: carriage.clone(),
            endpoint,
        });
    }
    let row = |desk: &Desk| desk.row(interface, &host(), &name("adb")).carried;
    assert_eq!(
        row(&desk),
        [
            reverse(&metro, port(50131)),
            CarriedOn {
                carriage: forward.clone(),
                endpoint: port(58765),
            },
            CarriedOn {
                carriage: console.clone(),
                endpoint: port(50134),
            },
        ]
    );
    for (carriage, why) in [(forward, Dropped::Removed), (console, Dropped::Unlent)] {
        desk.trail.push(Event::Dropped {
            connection,
            capability: name("adb"),
            carriage,
            why,
        });
    }
    assert_eq!(row(&desk), [reverse(&metro, port(50131))]);
}
