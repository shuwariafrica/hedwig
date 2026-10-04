//! A serial port lent to a remote: a source of its own, carried as RFC 2217 on
//! a port of the remote's loopback, its one decision point the opening, and the
//! port held for one connection at a time, whichever capability or remote names
//! it.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::{
    Capability, Dialect, Exposure, Form, Holds, Lends, Operation, ServicePort, Setup, Source, Whom,
};
use hedwig_model::config::{Activation, Change, Configuration, Terms};
use hedwig_model::gate::Verdict;
use hedwig_model::platform::Sockets;
use hedwig_model::protocol::{Hold, Notice, Reply, Request, SerialPort, Topic, Usb};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Sets};
use hedwig_model::text::{DeviceSerial, PortName, TextError, Words};
use hedwig_model::trail::{ClientKind, Event, Failure, Outcome, State, about};

mod support;
use support::desk::Desk;
use support::{DESKTOP, catalogue, grant, name, port, remote};

fn host() -> RemoteId {
    remote("ssh", "dev@build.example")
}

fn other() -> RemoteId {
    remote("ssh", "ci@runner.example")
}

fn com(text: &str) -> PortName {
    PortName::try_from(text).unwrap()
}

fn board(id: &str, port_name: &str, remote_port: u16) -> Capability {
    Capability {
        id: name(id),
        source: Source::Serial {
            port: com(port_name),
            remote: port(remote_port),
        },
    }
}

fn serial_terms(acknowledged: Exposure, lends: Lends) -> Terms {
    Terms {
        activation: Activation::OnRequest,
        setup: Setup::Inspect,
        acknowledged,
        lends,
    }
}

/// A desk with `capabilities` defined and each granted to both remotes.
fn lent(capabilities: &[Capability]) -> (Desk, hedwig_model::trail::ClientId) {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    for capability in capabilities {
        desk.send(
            interface,
            Request::Change(Change::Define(capability.clone())),
        )
        .unwrap();
        for remote in [host(), other()] {
            desk.send(
                interface,
                Request::Change(Change::Grant {
                    grant: grant(capability.id.as_str(), Granted::One(remote)),
                    terms: serial_terms(Exposure::SERVICE, Lends::none()),
                }),
            )
            .unwrap();
        }
    }
    (desk, interface)
}

/// The relay's report that the port was opened for a served request.
fn take(
    desk: &mut Desk,
    request: hedwig_model::trail::RequestId,
    capability: &str,
    port_name: &str,
) {
    let ask = desk
        .trail
        .entries
        .iter()
        .find(|entry| entry.seq == request.0)
        .unwrap();
    let Event::Asked { connection, .. } = &ask.event else {
        unreachable!("a request")
    };
    let connection = *connection;
    desk.trail.push(Event::Taken {
        request,
        connection,
        capability: name(capability),
        port: com(port_name),
        usb: None,
    });
}

#[test]
fn a_serial_port_is_a_source_of_its_own_carried_on_a_port_every_platform_carries() {
    let capability = board("esp32", "COM5", 4000);
    assert_eq!(capability.dialect(), Dialect::Serial);
    assert_eq!(Dialect::Serial.operations(), &[Operation::Connect]);
    assert_eq!(capability.exposure(), Exposure::SERVICE);
    assert_eq!(
        capability.forms(),
        vec![Form::Port(ServicePort::Fixed(port(4000)))]
    );
    for sockets in [
        Sockets::Emulated,
        Sockets::Unix {
            path_bytes: 108.try_into().unwrap(),
        },
    ] {
        for setup in [Setup::Inspect, Setup::Write] {
            assert_eq!(capability.reach(sockets, setup), Some(Whom::Anyone));
        }
    }
    assert!(capability.open_everywhere(Setup::Inspect));
    assert!(!capability.widens(Setup::Write, Setup::Inspect));
    let consent = capability.consent(None);
    assert!(consent.writes.is_empty() && consent.reaches.is_none() && !consent.keys_unread);
    assert_eq!(capability.complete(), Ok(()));
    assert_eq!(capability.holds(), None);
}

#[test]
fn a_port_name_is_letters_and_digits_and_one_port_whatever_its_case() {
    assert!(com("COM5").same(&com("com5")));
    assert!(!com("COM5").same(&com("COM50")));
    assert_eq!(PortName::try_from(""), Err(TextError::Empty));
    for refused in [
        "C:",
        r"\\.\COM5",
        "COM5 ",
        "PhysicalDrive0\\",
        "COM-5",
        "../COM5",
    ] {
        assert!(
            matches!(
                PortName::try_from(refused),
                Err(TextError::Character { .. })
            ),
            "{refused}"
        );
    }
    assert_eq!(
        PortName::try_from("C".repeat(33).as_str()),
        Err(TextError::TooLong {
            limit: 32,
            length: 33
        })
    );
    assert!(PortName::try_from("CNCA0").is_ok());
}

#[test]
fn a_grant_of_a_serial_port_acknowledges_the_service_and_lends_no_device() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(
        interface,
        Request::Change(Change::Define(board("esp32", "COM5", 4000))),
    )
    .unwrap();
    let grant_with = |acknowledged, lends| {
        Request::Change(Change::Grant {
            grant: grant("esp32", Granted::One(host())),
            terms: serial_terms(acknowledged, lends),
        })
    };
    assert_eq!(
        desk.send(interface, grant_with(Exposure::NONE, Lends::none())),
        Err(Refusal::ExposureNotAcknowledged {
            capability: name("esp32"),
            missing: Exposure::SERVICE,
        })
    );
    let named = Lends::devices([DeviceSerial::try_from("COM5").unwrap()]);
    assert_eq!(
        desk.send(interface, grant_with(Exposure::SERVICE, named)),
        Err(Refusal::Unlendable {
            capability: name("esp32"),
            lent: Holds::Devices,
        })
    );
    assert!(
        desk.send(interface, grant_with(Exposure::SERVICE, Lends::none()))
            .is_ok()
    );
    // The definition survives the document both ways.
    let document = desk.configuration.export();
    let back = Configuration::import(&desk.catalogue, document.clone()).unwrap();
    assert_eq!(back.export(), document);
}

#[test]
fn a_held_port_refuses_every_other_opening_until_its_connection_releases_it() {
    // Two capabilities name one port, in different case; a third names another.
    let (mut desk, interface) = lent(&[
        board("esp32", "COM5", 4000),
        board("esp32-again", "com5", 4001),
        board("nrf", "COM7", 4002),
    ]);
    let here = desk.channel_up(&host(), "linux");
    let there = desk.channel_up(&other(), "windows");
    let (first, verdict) = desk.asks(here, "esp32", Operation::Connect);
    assert!(
        matches!(verdict, Verdict::Serve(Outcome::Served(_))),
        "{verdict:?}"
    );
    take(&mut desk, first, "esp32", "COM5");
    let held = Refusal::PortHeld {
        capability: name("esp32"),
        by: host(),
    };
    // A second connection from the same remote, a monitor beside a flash.
    assert_eq!(
        desk.asks(here, "esp32", Operation::Connect).1,
        Verdict::Refuse(held)
    );
    assert_eq!(
        desk.asks(there, "esp32-again", Operation::Connect).1,
        Verdict::Refuse(Refusal::PortHeld {
            capability: name("esp32-again"),
            by: host(),
        })
    );
    assert!(matches!(
        desk.asks(there, "nrf", Operation::Connect).1,
        Verdict::Serve(_)
    ));
    // The holder's row says so; the other remote's row of the same capability
    // holds nothing.
    let row = desk.row(interface, &host(), &name("esp32"));
    let holding = row.hold.expect("the port is held");
    assert_eq!((holding.request, holding.port), (first, com("COM5")));
    assert_eq!(desk.row(interface, &other(), &name("esp32")).hold, None);
    // Released, the other remote is served.
    desk.trail.push(Event::Released { request: first });
    assert_eq!(desk.row(interface, &host(), &name("esp32")).hold, None);
    let (second, verdict) = desk.asks(there, "esp32-again", Operation::Connect);
    assert!(matches!(verdict, Verdict::Serve(_)), "{verdict:?}");
    take(&mut desk, second, "esp32-again", "com5");
    // A new run holds nothing: what the last run held was closed with it.
    desk.trail.push(Event::Started {
        version: "0.2.0".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    assert_eq!(desk.trail.state().holder(&com("COM5")), None);
}

#[test]
fn the_remote_s_activity_says_when_its_connection_took_the_port_and_gave_it_back() {
    let (mut desk, interface) = lent(&[board("esp32", "COM5", 4000)]);
    let here = desk.channel_up(&host(), "linux");
    let (request, _) = desk.asks(here, "esp32", Operation::Connect);
    take(&mut desk, request, "esp32", "COM5");
    let since = desk.trail.entries.last().map(|entry| entry.at).unwrap();
    assert_eq!(
        desk.row(interface, &host(), &name("esp32")).hold,
        Some(Hold {
            request,
            port: com("COM5"),
            since,
        })
    );
    desk.trail.wait(42_000);
    desk.trail.push(Event::Released { request });
    let ours = |remote: &RemoteId| -> Vec<Event> {
        about(&State::default(), &desk.trail.entries, remote, &Sets::NONE)
            .map(|entry| entry.event.clone())
            .filter(|event| matches!(event, Event::Taken { .. } | Event::Released { .. }))
            .collect()
    };
    assert_eq!(
        ours(&host()),
        vec![
            Event::Taken {
                request,
                connection: here,
                capability: name("esp32"),
                port: com("COM5"),
                usb: None,
            },
            Event::Released { request },
        ]
    );
    assert_eq!(ours(&other()), Vec::<Event>::new());
    assert_eq!(desk.trail.state().hold(&host(), &name("esp32")), None);
}

#[test]
fn an_absent_or_busy_port_stands_on_every_row_of_its_capability_in_words() {
    let (mut desk, interface) = lent(&[board("esp32", "COM5", 4000)]);
    desk.channel_up(&host(), "linux");
    for failure in [Failure::Absent, Failure::Busy] {
        desk.trail.push(Event::Source {
            capability: name("esp32"),
            health: hedwig_model::trail::Health::Failing(failure),
        });
        let refusal = Refusal::SourceUnavailable {
            capability: name("esp32"),
            failure,
        };
        for remote in [host(), other()] {
            assert_eq!(
                desk.row(interface, &remote, &name("esp32")).standing,
                hedwig_model::protocol::Standing::Unavailable(refusal.clone())
            );
        }
        let words = refusal.to_string();
        assert!(words.starts_with("esp32 names a serial port"), "{words}");
    }
}

/// The ports are open to every client, none on a workstation with
/// none; a client that listed them is told once each time they change, until
/// it leaves.
#[test]
fn a_client_that_listed_the_ports_is_told_when_they_change_until_it_leaves() {
    let mut desk = Desk::new(catalogue());
    let viewer = desk.attend(ClientKind::Viewer, DESKTOP);
    let window = desk.attend(ClientKind::Interface, DESKTOP);
    assert_eq!(Topic::listed(&Request::Ports), Some(Topic::Ports));
    assert_eq!(
        desk.send(viewer, Request::Ports),
        Ok(Reply::Ports(Vec::new()))
    );
    let board = vec![SerialPort {
        port: PortName::try_from("COM5").unwrap(),
        name: Words::try_from("USB JTAG/serial debug unit").ok(),
        usb: Some(Usb {
            vendor: 0x303A,
            product: 0x1001,
        }),
    }];
    assert_eq!(
        desk.hold_ports(board.clone()),
        vec![(viewer, Notice::Stale(Topic::Ports))]
    );
    assert_eq!(
        desk.hold_ports(board.clone()),
        Vec::<(hedwig_model::trail::ClientId, Notice)>::new()
    );
    assert_eq!(desk.send(window, Request::Ports), Ok(Reply::Ports(board)));
    desk.detach(viewer);
    assert_eq!(
        desk.hold_ports(Vec::new()),
        vec![(window, Notice::Stale(Topic::Ports))]
    );
}

/// Two capabilities one remote holds whose forms take one spot on it - a
/// port, the socket a remote tool's query names, a variable written - are
/// neither carried, each refused naming the other, whatever kind of source
/// each is; one alone at its spot is carried. The row says why.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one remote holding every kind of spot twice"
)]
fn two_capabilities_at_one_spot_on_a_remote_are_neither_carried() {
    use hedwig_model::capability::{Browser, Query, Spot};
    use hedwig_model::protocol::Standing;
    use hedwig_model::text::Variable;

    let (mut desk, interface) = lent(&[
        board("esp32", "COM5", 4000),
        board("stm32", "COM6", 4000),
        board("nrf52", "COM7", 3333),
        board("rp2040", "COM8", 4001),
    ]);
    let gnupg_release = Capability {
        id: name("gpg-release"),
        source: Source::Gnupg {
            installation: hedwig_model::capability::Installation::Registered,
            home: hedwig_model::capability::Home::Default,
            access: hedwig_model::capability::Access::Restricted,
        },
    };
    let opener = |id: &str| Capability {
        id: name(id),
        source: Source::Browser {
            browser: Browser::Default,
            sites: Vec::new(),
        },
    };
    for capability in [gnupg_release, opener("work"), opener("personal")] {
        desk.send(interface, Request::Change(Change::Define(capability)))
            .unwrap();
    }
    for (id, setup, acknowledged) in [
        ("openocd", Setup::Inspect, Exposure::SERVICE),
        ("gpg", Setup::Inspect, Exposure::NONE),
        ("gpg-release", Setup::Inspect, Exposure::NONE),
        ("work", Setup::Write, Exposure::BROWSER),
        ("personal", Setup::Write, Exposure::BROWSER),
    ] {
        desk.send(
            interface,
            Request::Change(Change::Grant {
                grant: grant(id, Granted::One(host())),
                terms: Terms {
                    setup,
                    ..serial_terms(acknowledged, Lends::none())
                },
            }),
        )
        .unwrap();
    }
    let connection = desk.channel_up(&host(), "linux");
    let plan = desk.ask_world(|world| world.plan(connection)).unwrap();
    let shared = |capability: &str, with: &str, spot: Spot| {
        Err(Refusal::Shared {
            capability: name(capability),
            with: name(with),
            spot,
        })
    };
    let variable = |text: &str| Spot::Variable(Variable::try_from(text).unwrap());
    let expected = [
        ("esp32", shared("esp32", "stm32", Spot::Port(port(4000)))),
        ("stm32", shared("stm32", "esp32", Spot::Port(port(4000)))),
        ("nrf52", shared("nrf52", "openocd", Spot::Port(port(3333)))),
        (
            "openocd",
            shared("openocd", "nrf52", Spot::Port(port(3333))),
        ),
        (
            "gpg",
            shared("gpg", "gpg-release", Spot::Socket(Query::AgentSocket)),
        ),
        (
            "gpg-release",
            shared("gpg-release", "gpg", Spot::Socket(Query::AgentSocket)),
        ),
        (
            "personal",
            shared("personal", "work", variable("GH_BROWSER")),
        ),
        ("work", shared("work", "personal", variable("GH_BROWSER"))),
    ];
    for (id, refused) in &expected {
        assert_eq!(plan.get(&name(id)), Some(refused), "{id}");
    }
    assert_eq!(
        plan.get(&name("rp2040")),
        Some(&Ok(Form::Port(ServicePort::Fixed(port(4001)))))
    );
    let Standing::Unavailable(refusal) = desk.row(interface, &host(), &name("nrf52")).standing
    else {
        unreachable!("a shared port stands on the row")
    };
    assert_eq!(
        refusal.to_string(),
        "nrf52 and openocd both take port 3333 on the remote, so neither is carried; give one of \
         them another remote port"
    );
    assert!(matches!(
        desk.row(interface, &host(), &name("rp2040")).standing,
        Standing::Serving(_)
    ));
    let unobserved = desk
        .ask_world(|world| world.plan_unobserved(connection))
        .unwrap();
    assert_eq!(
        unobserved.get(&name("esp32")),
        expected.first().map(|(_, refused)| refused)
    );
}
