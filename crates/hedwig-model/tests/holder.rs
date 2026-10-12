//! Whose a source's holder is, whether a remote's connection may be carried
//! to it, what the person reads of it, and what they can do about one Hedwig
//! will not serve.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::cell::Cell;

use hedwig_model::capability::{
    AgentAt, Home, Installation, ServiceHost, ServicePort, Source, Stream,
};
use hedwig_model::config::Configuration;
use hedwig_model::gate::World;
use hedwig_model::holder::{Reading, Rights, SignedIn, SourceHolder, Standing, Whose, whose};
use hedwig_model::refusal::{Refusal, Remedy};
use hedwig_model::text::{AgentPipe, Folder, Location, Name, ServiceName};
use hedwig_model::trail::{Event, Failure, Health};

mod support;
use support::{Trail, catalogue, name, port};

fn reading(standing: Standing) -> Reading {
    Reading {
        standing,
        logon: 0x04ef_6c7c,
        signed_in: SignedIn::Locally,
        rights: Rights::Standard,
    }
}

fn services(names: &[&str]) -> Vec<ServiceName> {
    names
        .iter()
        .map(|name| ServiceName::try_from(*name).unwrap())
        .collect()
}

fn holder(program: &str, session: u32, whose: Whose) -> SourceHolder {
    SourceHolder {
        program: Location::try_from(program).unwrap(),
        session,
        whose,
    }
}

#[test]
fn the_person_is_theirs_in_any_logon_and_the_service_list_is_never_asked() {
    for (signed_in, rights) in [
        (SignedIn::Locally, Rights::Standard),
        (SignedIn::Locally, Rights::Administrator),
        (SignedIn::OverTheNetwork, Rights::Administrator),
        (SignedIn::OverTheNetwork, Rights::Standard),
    ] {
        let asked = Cell::new(false);
        let found = whose(
            Some(Reading {
                standing: Standing::Person,
                logon: 7,
                signed_in,
                rights,
            }),
            || {
                asked.set(true);
                services(&["RpcSs"])
            },
        );
        assert_eq!(
            found,
            Whose::Person {
                logon: 7,
                signed_in,
                rights
            }
        );
        assert!(!asked.get());
    }
}

#[test]
fn a_service_is_the_workstations_whatever_its_token_says() {
    for token in [
        None,
        Some(reading(Standing::Another)),
        Some(reading(Standing::Confined)),
    ] {
        assert_eq!(
            whose(token, || services(&["RpcEptMapper", "RpcSs"])),
            Whose::Service {
                services: services(&["RpcEptMapper", "RpcSs"])
            }
        );
    }
}

#[test]
fn every_other_holder_is_said_for_what_was_read() {
    assert_eq!(
        whose(Some(reading(Standing::Confined)), Vec::new),
        Whose::Confined
    );
    assert_eq!(
        whose(Some(reading(Standing::Another)), Vec::new),
        Whose::Another
    );
    assert_eq!(whose(None, Vec::new), Whose::Unread);
}

#[test]
fn only_the_person_and_a_service_are_admitted() {
    let person = Whose::Person {
        logon: 1,
        signed_in: SignedIn::OverTheNetwork,
        rights: Rights::Administrator,
    };
    let cases = [
        (person, Ok(())),
        (
            Whose::Service {
                services: services(&["RpcSs"]),
            },
            Ok(()),
        ),
        (Whose::Confined, Err(Failure::Confined)),
        (Whose::Another, Err(Failure::Foreign)),
        (Whose::Unread, Err(Failure::Unidentified)),
    ];
    for (whose, admitted) in cases {
        assert_eq!(holder("adb.exe", 0, whose).admitted(), admitted);
    }
}

#[test]
fn a_holder_reads_as_only_what_was_read() {
    let cases = [
        (
            holder(
                r"C:\Users\ali\AppData\Local\Android\Sdk\platform-tools\adb.exe",
                0,
                Whose::Person {
                    logon: 1,
                    signed_in: SignedIn::OverTheNetwork,
                    rights: Rights::Administrator,
                },
            ),
            r"C:\Users\ali\AppData\Local\Android\Sdk\platform-tools\adb.exe, yours, in session 0, signed in over the network, as administrator",
        ),
        (
            holder(
                r"C:\Program Files\GnuPG\bin\gpg-agent.exe",
                2,
                Whose::Person {
                    logon: 1,
                    signed_in: SignedIn::Locally,
                    rights: Rights::Standard,
                },
            ),
            r"C:\Program Files\GnuPG\bin\gpg-agent.exe, yours, in session 2",
        ),
        (
            holder(
                "svchost.exe",
                0,
                Whose::Service {
                    services: services(&["RpcEptMapper", "RpcSs"]),
                },
            ),
            "svchost.exe, which runs the services RpcEptMapper, RpcSs an administrator installed",
        ),
        (
            holder(
                "ssh-agent.exe",
                0,
                Whose::Service {
                    services: services(&["ssh-agent"]),
                },
            ),
            "ssh-agent.exe, which runs the service ssh-agent an administrator installed",
        ),
        (
            holder("squat.exe", 2, Whose::Confined),
            "squat.exe, yours but confined by Windows to less than you, in session 2",
        ),
        (
            holder("openocd.exe", 3, Whose::Another),
            "openocd.exe, another account's, in session 3",
        ),
        (
            holder("adb.exe", 0, Whose::Unread),
            "adb.exe in session 0, which Windows does not let Hedwig read",
        ),
    ];
    for (holder, words) in cases {
        assert_eq!(holder.to_string(), words);
    }
}

#[test]
fn each_refusal_says_what_was_read() {
    let words = |failure| {
        Refusal::SourceUnavailable {
            capability: name("adb"),
            failure,
        }
        .to_string()
    };
    assert_eq!(
        words(Failure::Foreign),
        "what answers for adb on this workstation is another account's program and no service \
         an administrator installed, so Hedwig does not carry the remote's connection to it"
    );
    assert_eq!(
        words(Failure::Confined),
        "what answers for adb on this workstation is a program of yours that Windows confines to \
         less than you - at low integrity, restricted, or in an app container - so Hedwig does \
         not carry the remote's connection to it"
    );
    assert_eq!(
        words(Failure::Unidentified),
        "Windows does not let Hedwig read whose program answers for adb on this workstation, and \
         it is no service an administrator installed, so Hedwig does not carry the remote's \
         connection to it"
    );
}

#[test]
fn a_remedy_is_the_sources_own_tool_and_only_for_a_program_that_may_be_the_persons() {
    let adb = |number| Source::Service {
        host: ServiceHost::Workstation,
        port: ServicePort::Fixed(port(number)),
        stream: Stream::Adb,
        remote: Vec::new(),
    };
    let gnupg = |home| Source::Gnupg {
        installation: Installation::Registered,
        home,
        access: hedwig_model::capability::Access::Restricted,
    };
    let folder = Folder::try_from(r"C:\Users\ali\work\gnupg").unwrap();
    let cases = [
        (
            adb(5037),
            "if it is yours, adb kill-server stops it, and your next adb command starts one in \
             the sign-in you run it from",
        ),
        (
            adb(5038),
            "if it is yours, adb -P 5038 kill-server stops it, and your next adb command starts \
             one in the sign-in you run it from",
        ),
        (
            gnupg(Home::Default),
            "if it is yours, gpgconf --kill gpg-agent stops it, and Hedwig starts it again where \
             Hedwig runs when a remote next asks",
        ),
        (
            Source::Agent {
                at: AgentAt::Gnupg {
                    installation: Installation::Registered,
                    home: Home::At(folder),
                },
            },
            "if it is yours, gpgconf --homedir \"C:\\Users\\ali\\work\\gnupg\" --kill gpg-agent \
             stops it, and Hedwig starts it again where Hedwig runs when a remote next asks",
        ),
        (
            Source::Agent {
                at: AgentAt::Pipe(AgentPipe::well_known()),
            },
            "if it is yours, stop it where it was started and start it again in the sign-in \
             Hedwig runs in",
        ),
    ];
    for (source, words) in cases {
        for failure in [Failure::Unidentified, Failure::Confined] {
            assert_eq!(
                Remedy::of(&source, failure).map(|remedy| remedy.to_string()),
                Some(words.to_owned())
            );
        }
        for failure in [Failure::Foreign, Failure::Unreachable, Failure::Mismatched] {
            assert_eq!(Remedy::of(&source, failure), None);
        }
    }
}

#[test]
fn what_holds_each_source_is_folded_into_what_the_workstation_holds() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let mut trail = Trail::started();
    let theirs = holder("adb.exe", 0, Whose::Unread);
    trail.push(Event::Source {
        capability: name("adb"),
        health: Health::Failing(Failure::Unidentified),
    });
    trail.push(Event::HeldBy {
        capability: name("adb"),
        holder: Some(theirs.clone()),
    });
    trail.push(Event::Source {
        capability: name("gpg"),
        health: Health::Failing(Failure::Unreachable),
    });
    trail.push(Event::HeldBy {
        capability: name("gpg"),
        holder: None,
    });
    let state = trail.state();
    let world = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    let found = world.workstation().sources;
    let adb = found
        .iter()
        .find(|found| found.capability == name("adb"))
        .unwrap();
    assert_eq!(adb.holder, Some(theirs));
    assert_eq!(adb.health, Some(Health::Failing(Failure::Unidentified)));
    let gpg = found
        .iter()
        .find(|found| found.capability == name("gpg"))
        .unwrap();
    assert_eq!(gpg.holder, None);
}

/// What holds a source is listed with the workstation once it is read, the
/// source's health or not: the grant form's list of an agent's keys reads the
/// holder and tries nothing else. A reading that found nothing answering, and
/// no health, says nothing to list.
#[test]
fn a_holder_read_before_its_sources_health_is_listed() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let mut trail = Trail::started();
    let agent = holder(
        r"C:\Program Files\1Password\app\8\1Password.exe",
        2,
        Whose::Confined,
    );
    trail.push(Event::HeldBy {
        capability: name("ssh-agent"),
        holder: Some(agent.clone()),
    });
    trail.push(Event::HeldBy {
        capability: name("adb"),
        holder: None,
    });
    let state = trail.state();
    let world = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    let listed: Vec<(Name, Option<Health>, Option<SourceHolder>)> = world
        .workstation()
        .sources
        .into_iter()
        .map(|found| (found.capability, found.health, found.holder))
        .collect();
    assert_eq!(listed, [(name("ssh-agent"), None, Some(agent))]);
}
