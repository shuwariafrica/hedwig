//! Every remote platform is an instance of one shape. Linux is the instance
//! implemented first; these run the same resolution over all seven shipped
//! profiles and over one nobody has met.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU16;

use hedwig_model::capability::{Exposure, Form, Lends, Query, ServicePort, Setup};
use hedwig_model::config::{Catalogue, Change, Configuration};
use hedwig_model::platform::{AgentForwarding, Platform, Sockets};
use hedwig_model::refusal::Refusal;
use hedwig_model::text::{Kernel, RemotePath};
use hedwig_model::trail::{Event, Opener};

mod support;
use support::{Trail, capability, catalogue, granting, name, port, remote};

fn platform(catalogue: &Catalogue, family: &str) -> Platform {
    Configuration::default()
        .platform(catalogue, &name(family))
        .expect("a shipped platform")
        .clone()
}

const UNIX: [&str; 6] = ["linux", "macos", "freebsd", "openbsd", "netbsd", "illumos"];

#[test]
fn gpg_is_a_socket_on_every_unix_and_a_socket_file_on_windows() {
    let catalogue = catalogue();
    let gpg = capability(&catalogue, "gpg");
    for family in UNIX {
        for setup in [Setup::Inspect, Setup::Write] {
            assert_eq!(
                gpg.carrier(&platform(&catalogue, family), setup),
                Ok(Form::SocketAt(Query::AgentSocket)),
                "{family}"
            );
        }
    }
    let windows = platform(&catalogue, "windows");
    assert_eq!(
        gpg.carrier(&windows, Setup::Write),
        Ok(Form::SocketFileAt(Query::AgentSocket))
    );
}

/// A Windows remote's gpg finds its agent only through a file the core
/// writes there, which is a write the person consents to on the grant.
#[test]
fn the_windows_socket_file_needs_the_grants_consent() {
    let catalogue = catalogue();
    assert_eq!(
        capability(&catalogue, "gpg").carrier(&platform(&catalogue, "windows"), Setup::Inspect),
        Err(Refusal::NeedsRemoteSetup {
            capability: name("gpg"),
            platform: name("windows"),
        })
    );
}

/// A stated limit: nothing of a Windows remote's own carries an
/// SSH agent, and the refusal says so instead of the grant silently doing
/// nothing.
#[test]
fn no_ssh_agent_reaches_a_windows_remote() {
    let catalogue = catalogue();
    let windows = platform(&catalogue, "windows");
    assert_eq!(windows.agent_forwarding, AgentForwarding::Refused);
    for setup in [Setup::Inspect, Setup::Write] {
        assert_eq!(
            capability(&catalogue, "ssh-agent").carrier(&windows, setup),
            Err(Refusal::NoCarrier {
                capability: name("ssh-agent"),
                platform: name("windows"),
            })
        );
    }
    for family in UNIX {
        let unix = platform(&catalogue, family);
        assert_eq!(unix.agent_forwarding, AgentForwarding::Served);
        assert_eq!(
            capability(&catalogue, "ssh-agent").carrier(&unix, Setup::Inspect),
            Ok(Form::SocketAt(Query::AgentSshSocket))
        );
    }
}

/// An endpoint reaches every platform as TCP. Where the remote tool takes a
/// socket path and the person lets the core point it there, it gets a socket
/// only the remote user reaches.
#[test]
fn an_endpoint_is_a_private_socket_where_it_can_be_and_a_port_everywhere() {
    let catalogue = catalogue();
    let adb = capability(&catalogue, "adb");
    let tcp = Ok(Form::Port(ServicePort::Fixed(port(5037))));
    for family in UNIX {
        let unix = platform(&catalogue, family);
        assert_eq!(adb.carrier(&unix, Setup::Inspect), tcp, "{family}");
        assert!(
            matches!(
                adb.carrier(&unix, Setup::Write),
                Ok(Form::PrivateSocket { .. })
            ),
            "{family}"
        );
    }
    let windows = platform(&catalogue, "windows");
    assert_eq!(adb.carrier(&windows, Setup::Inspect), tcp);
    assert_eq!(adb.carrier(&windows, Setup::Write), tcp);
    assert_eq!(
        capability(&catalogue, "openocd").carrier(&windows, Setup::Inspect),
        Ok(Form::Port(ServicePort::Fixed(port(3333))))
    );
}

/// `sun_path` is 104 bytes on macOS and the BSDs and 108 on Linux and
/// illumos; one of them is the terminator.
#[test]
fn a_socket_path_is_checked_against_each_platforms_limit() {
    let catalogue = catalogue();
    let path = |length: usize| {
        RemotePath::try_from(format!("/{}", "a".repeat(length - 1)).as_str()).expect("a path")
    };
    for (family, usable) in [
        ("linux", 107),
        ("illumos", 107),
        ("macos", 103),
        ("freebsd", 103),
        ("openbsd", 103),
        ("netbsd", 103),
    ] {
        let unix = platform(&catalogue, family);
        assert_eq!(unix.admits(&path(usable.into())), Ok(()), "{family}");
        assert_eq!(
            unix.admits(&path(usize::from(usable) + 1)),
            Err(Refusal::SocketPathTooLong {
                usable,
                length: usable + 1
            }),
            "{family}"
        );
    }
    assert_eq!(
        platform(&catalogue, "windows").admits(&path(10)),
        Err(Refusal::NoUnixSockets {
            platform: name("windows")
        })
    );
}

/// The plan for one connection: what each platform's channel forwards for
/// the same grants, from the same code.
#[test]
fn one_set_of_grants_plans_differently_on_each_platform() {
    let catalogue = catalogue();
    let host = remote("ssh", "dev@box");
    let configuration = granting(
        &catalogue,
        &[
            ("gpg", hedwig_model::remote::Granted::One(host.clone())),
            (
                "ssh-agent",
                hedwig_model::remote::Granted::One(host.clone()),
            ),
            ("adb", hedwig_model::remote::Granted::One(host.clone())),
        ],
    );
    let plan = |family: &str| {
        let mut trail = Trail::started();
        let connection = trail.open(&host, family);
        let state = trail.state();
        hedwig_model::gate::World {
            catalogue: &catalogue,
            configuration: &configuration,
            state: &state,
        }
        .plan(connection)
        .expect("a plan")
    };

    let linux = plan("linux");
    assert_eq!(linux.len(), 3);
    assert!(linux.values().all(Result::is_ok));

    let windows = plan("windows");
    assert!(matches!(
        windows.get(&name("gpg")),
        Some(Err(Refusal::NeedsRemoteSetup { .. }))
    ));
    assert!(matches!(
        windows.get(&name("ssh-agent")),
        Some(Err(Refusal::NoCarrier { .. }))
    ));
    assert!(matches!(windows.get(&name("adb")), Some(Ok(Form::Port(_)))));
}

#[test]
fn a_plan_waits_for_the_remote_to_report_its_platform() {
    let catalogue = catalogue();
    let host = remote("ssh", "dev@box");
    let configuration = Configuration::default();
    let mut trail = Trail::started();
    let connection = hedwig_model::trail::ConnectionId(trail.push(Event::Opening {
        remote: host.clone(),
        with: Vec::new(),
        opener: Opener::Grant,
        acknowledged: Exposure::NONE,
        lends: Lends::none(),
    }));
    let state = trail.state();
    let world = hedwig_model::gate::World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    assert_eq!(
        world.plan(connection),
        Err(Refusal::PlatformUnobserved(host))
    );
    let gone = hedwig_model::trail::ConnectionId(hedwig_model::trail::Seq(99));
    assert_eq!(world.plan(gone), Err(Refusal::UnknownConnection(gone)));
}

/// Openness: a platform nobody has met is refused by name until the person
/// defines its profile, and then everything above works for it with no code
/// changed.
#[test]
fn a_platform_nobody_has_met_is_a_definition_away() {
    let catalogue = catalogue();
    let host = remote("ssh", "dev@haiku-box");
    let mut configuration = granting(
        &catalogue,
        &[("gpg", hedwig_model::remote::Granted::One(host.clone()))],
    );
    let mut trail = Trail::started();
    let connection = trail.open(&host, "haiku");
    let state = trail.state();

    let world = hedwig_model::gate::World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    assert_eq!(
        world.plan(connection),
        Err(Refusal::UnknownPlatform(name("haiku")))
    );

    configuration
        .apply(
            &catalogue,
            Change::DefinePlatform(Platform {
                kernel: Kernel::try_from("Haiku").expect("a kernel"),
                family: name("haiku"),
                sockets: Sockets::Unix {
                    path_bytes: NonZeroU16::new(126).expect("non-zero"),
                },
                agent_forwarding: AgentForwarding::Served,
            }),
        )
        .expect("the profile is accepted");
    let world = hedwig_model::gate::World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    assert_eq!(
        world.plan(connection).expect("a plan").get(&name("gpg")),
        Some(&Ok(Form::SocketAt(Query::AgentSocket)))
    );
}

/// A remote is known by what it calls its own system, read by readiness: each
/// shipped profile answers to its own kernel's name, a new system is a new
/// profile with no code changed, and a name two profiles claim is refused
/// rather than settled by order.
#[test]
fn a_remote_is_known_by_the_system_it_names() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    let answering = |configuration: &Configuration, kernel: &str| {
        configuration
            .platform_answering(&catalogue, &Kernel::try_from(kernel).expect("a kernel"))
            .map(|platform| platform.family.clone())
    };
    for (kernel, family) in [
        ("Linux", "linux"),
        ("Darwin", "macos"),
        ("FreeBSD", "freebsd"),
        ("OpenBSD", "openbsd"),
        ("NetBSD", "netbsd"),
        ("SunOS", "illumos"),
        ("Windows_NT", "windows"),
    ] {
        assert_eq!(
            answering(&configuration, kernel),
            Ok(name(family)),
            "{kernel}"
        );
    }
    assert_eq!(
        answering(&configuration, "Haiku"),
        Err(Refusal::UnknownKernel(
            Kernel::try_from("Haiku").expect("a kernel")
        ))
    );
    let haiku = Platform {
        family: name("haiku"),
        kernel: Kernel::try_from("Haiku").expect("a kernel"),
        sockets: Sockets::Unix {
            path_bytes: NonZeroU16::new(126).expect("non-zero"),
        },
        agent_forwarding: AgentForwarding::Served,
    };
    configuration
        .apply(&catalogue, Change::DefinePlatform(haiku.clone()))
        .expect("the profile is accepted");
    assert_eq!(answering(&configuration, "Haiku"), Ok(name("haiku")));

    // A second profile for a system one already answers to is refused where
    // it is made, at every door a definition comes through, and the first
    // still answers.
    let wsl = Platform {
        family: name("wsl"),
        kernel: Kernel::try_from("Linux").expect("a kernel"),
        ..haiku
    };
    let claimed = Refusal::KernelClaimed {
        kernel: Kernel::try_from("Linux").expect("a kernel"),
        first: name("linux"),
        second: name("wsl"),
    };
    assert_eq!(
        configuration.apply(&catalogue, Change::DefinePlatform(wsl.clone())),
        Err(claimed.clone())
    );
    assert_eq!(answering(&configuration, "Linux"), Ok(name("linux")));
    let mut document = configuration.export();
    document.platforms.push(wsl);
    assert_eq!(
        Configuration::import(&catalogue, document.clone()),
        Err(claimed.clone())
    );
    // A document already stored is read back whole, and the claim is refused
    // where a remote's system is matched to a profile.
    let stored = Configuration::restore(document).expect("a stored document reads back");
    assert_eq!(answering(&stored, "Linux"), Err(claimed));
}
