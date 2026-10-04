//! An SSH agent carried to a remote: what a grant of one lends, how a
//! request through it is told apart and decided, where its forward sits on a
//! remote, and how a public key is read wherever it enters.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use hedwig_model::capability::{
    AGENT_VARIABLE, AgentAt, Capability, Dialect, Exposure, Form, Holds, Home, Installation, Lends,
    LentKey, Offer, Operation, Query, ServicePort, Setup, Source, Spot, Stream, Toward,
};
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Terms, lendable};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::platform::{AgentForwarding, Platform, Sockets};
use hedwig_model::policy::{Basis, KeyName, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::Request;
use hedwig_model::refusal::{Refusal, Whereabouts, Withheld};
use hedwig_model::remote::{Granted, Remotes};
use hedwig_model::text::{
    AgentPipe, Kernel, KeyId, SshKey, TextError, Variable, base64, ssh_string, to_base64,
};
use hedwig_model::trail::{ClientKind, ConnectionId, Event, Outcome};

mod support;
use support::{DESKTOP, Trail, catalogue, grant, name, remote};

/// A key's public half and a second key, made by the in-box `ssh-keygen`.
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1cuDWSQ4xW25Rb1dBGnBjWHV2DfwPn/bqUaSYf4z15";
const OTHER: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIQfBFoTFcymxqayVAmobeqqsWVKCgyRgJhRE4W7CDjAcuptlxzloqrpI2/N0w2y8dLIaPMBQcggIHZExfGvJ8c=";

fn key(text: &str) -> SshKey {
    SshKey::try_from(text).unwrap()
}

fn lends(keys: &[&str]) -> Lends {
    Lends::of_keys(keys.iter().map(|text| (key(text), Toward::Anywhere.into())))
}

/// RFC 4648 section 10's vectors, both ways.
#[test]
fn base64_reads_and_writes_rfc_4648_s_vectors() {
    for (plain, encoded) in [
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(to_base64(plain.as_bytes()), encoded);
        assert_eq!(base64(encoded).as_deref(), Some(plain.as_bytes()));
    }
    for unread in [
        "", "Zg=", "Zg===", "Z===", "Zh==", "Zm9=", "Zm 9v", "Zm9v\n", "=Zm9", "Zm-v",
    ] {
        assert_eq!(base64(unread), None, "{unread:?}");
    }
}

/// Whatever bytes are written, encoding and reading them back gives them
/// back; a reading of arbitrary text never panics.
#[test]
fn base64_round_trips_every_length_and_reads_noise_without_panicking() {
    let mut random = support::Seeded(0x5eed_0004);
    for length in 0..300 {
        let bytes: Vec<u8> = (0..length)
            .map(|_| random.next().to_le_bytes()[0])
            .collect();
        let encoded = to_base64(&bytes);
        if bytes.is_empty() {
            assert_eq!(base64(&encoded), None, "nothing is not a key's blob");
        } else {
            assert_eq!(base64(&encoded), Some(bytes));
        }
    }
    for _ in 0..5_000 {
        let length = usize::from(random.next().to_le_bytes()[0] % 64);
        let noise: String = (0..length)
            .map(|_| char::from(b"AZaz09+/= \n-"[usize::from(random.next().to_le_bytes()[0] % 12)]))
            .collect();
        let _ = base64(&noise);
        let _ = SshKey::try_from(noise.as_str());
    }
}

/// A public key is its type and its blob, whose first field names the same
/// type; the blob is what a request carries, and a key read from a blob is
/// the key written.
#[test]
fn a_public_key_is_read_as_openssh_writes_it_and_round_trips_through_its_blob() {
    for text in [KEY, OTHER] {
        let read = key(text);
        let blob = read.blob();
        assert_eq!(SshKey::from_blob(&blob), Some(read.clone()));
        let (kind, _) = ssh_string(&blob).unwrap();
        assert_eq!(kind, read.kind().as_bytes());
    }
    let (_, ed25519) = KEY.split_once(' ').unwrap();
    for refused in [
        "ssh-ed25519".to_owned(),
        format!("ssh-rsa {ed25519}"),
        format!("ssh-ed25519  {ed25519}"),
        format!("ssh-ed25519 {ed25519} comment"),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5".to_owned(),
        format!("ssh-ed25519 {}", to_base64(b"\0\0\0\x0bssh-ed25519")),
        format!("ssh-ed25519 {}", to_base64(b"\0\0\0\xffssh-ed25519")),
    ] {
        assert_eq!(
            SshKey::try_from(refused.as_str()),
            Err(TextError::Key),
            "{refused}"
        );
    }
    assert_eq!(SshKey::from_blob(b"\0\0\0\x07ssh-rsa"), None);
    assert_eq!(SshKey::from_blob(b"\0\0"), None);
}

/// A grant lends what its source holds: an agent's keys, a server's
/// devices. Lending the other kind, or anything of a source that holds
/// neither, is refused naming what was lent, at every door.
#[test]
fn a_grant_lends_keys_of_an_agent_and_nothing_of_another_kind() {
    let catalogue = catalogue();
    let agent = Configuration::default()
        .capability(&catalogue, &name("ssh-agent"))
        .unwrap();
    let adb = Configuration::default()
        .capability(&catalogue, &name("adb"))
        .unwrap();
    let gpg = Configuration::default()
        .capability(&catalogue, &name("gpg"))
        .unwrap();
    assert_eq!(agent.holds(), Some(Holds::Keys));
    assert_eq!(lendable(&agent, &lends(&[KEY, OTHER])), Ok(()));
    assert_eq!(lendable(&agent, &Lends::Every), Ok(()));
    assert_eq!(
        lendable(
            &agent,
            &Lends::devices([hedwig_model::text::DeviceSerial::try_from("R5CT1").unwrap()])
        ),
        Err(Refusal::Unlendable {
            capability: name("ssh-agent"),
            lent: Holds::Devices,
        })
    );
    assert_eq!(
        lendable(&adb, &lends(&[KEY])),
        Err(Refusal::Unlendable {
            capability: name("adb"),
            lent: Holds::Keys,
        })
    );
    assert_eq!(
        lendable(&gpg, &Lends::Every).unwrap_err().to_string(),
        "gpg holds no devices to lend; a grant of it lends none"
    );
    assert_eq!(
        lendable(&adb, &lends(&[KEY])).unwrap_err().to_string(),
        "adb holds no keys to lend; a grant of it lends none"
    );

    let mut configuration = Configuration::default();
    let refused = configuration.apply(
        &catalogue,
        Change::Grant {
            grant: grant("gpg", Granted::One(remote("ssh", "build"))),
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged: Exposure::NONE,
                lends: lends(&[KEY]),
            },
        },
    );
    assert_eq!(
        refused,
        Err(Refusal::Unlendable {
            capability: name("gpg"),
            lent: Holds::Keys,
        })
    );
    assert_eq!(configuration, Configuration::default());
}

/// What a grant lends is the keys it names, with where each may be used; a
/// grant of every key lends each anywhere; lending fewer is narrower.
#[test]
fn what_is_lent_is_found_by_key_and_fewer_keys_are_narrower() {
    let toward = Toward::Hosts([key(OTHER)].into());
    let lent = Lends::Named {
        devices: [hedwig_model::text::DeviceSerial::try_from("R5CT1").unwrap()].into(),
        keys: [(key(KEY), LentKey::from(toward.clone()))].into(),
    };
    assert_eq!(lent.key(&key(KEY)), Some(&LentKey::from(toward)));
    assert_eq!(lent.key(&key(OTHER)), None);
    assert_eq!(
        Lends::Every.key(&key(OTHER)),
        Some(&LentKey::from(Toward::Anywhere))
    );
    assert_eq!(lent.keys().count(), 1);
    assert!(lent.lends(&hedwig_model::text::DeviceSerial::try_from("R5CT1").unwrap()));
    assert!(lends(&[KEY, OTHER]).exceeds(&lends(&[KEY])));
    assert!(!lends(&[KEY]).exceeds(&lends(&[KEY, OTHER])));
    assert!(lends(&[KEY]) < lends(&[KEY, OTHER]));
    assert!(lends(&[KEY, OTHER]) < Lends::Every);
}

/// The two places an agent is reached, as written in a definition.
#[test]
fn an_agent_is_reached_at_a_pipe_or_at_a_gnupg_home() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let shipped = |id: &str| configuration.capability(&catalogue, &name(id)).unwrap();
    assert_eq!(
        shipped("ssh-agent").source,
        Source::Agent {
            at: AgentAt::Pipe(AgentPipe::well_known()),
        }
    );
    assert_eq!(
        shipped("gpg-ssh").source,
        Source::Agent {
            at: AgentAt::Gnupg {
                installation: Installation::Registered,
                home: Home::Default,
            },
        }
    );
    for id in ["ssh-agent", "gpg-ssh"] {
        let agent = shipped(id);
        assert_eq!(agent.dialect(), Dialect::SshAgent);
        assert_eq!(agent.exposure(), Exposure::KEY_USE);
    }
    // Windows' own OpenSSH clients and agent name this path
    // (`wmain_common.c:54`, `ssh-agent/agent.c:50` at v10.0.0.0).
    assert_eq!(
        AgentPipe::well_known().to_path(),
        r"\\.\pipe\openssh-ssh-agent"
    );
    assert_eq!(
        AgentPipe::try_from("openssh-ssh-agent"),
        Ok(AgentPipe::well_known())
    );
    assert!(AgentPipe::try_from(r"..\pipe\x").is_err());
    assert!(AgentPipe::try_from("").is_err());
    assert!(AgentPipe::try_from("pageant.ali.0f3c").is_ok());
}

/// An agent's forward takes the socket the remote's `gpgconf` names and the
/// variable every SSH client reads, so a second capability that takes
/// either is refused beside it, each naming the other.
#[test]
fn an_agent_s_forward_takes_its_socket_and_ssh_auth_sock() {
    let catalogue = catalogue();
    let agent = Configuration::default()
        .capability(&catalogue, &name("ssh-agent"))
        .unwrap();
    let variable = Variable::try_from(AGENT_VARIABLE).unwrap();
    let linux = Platform {
        family: name("linux"),
        kernel: Kernel::try_from("Linux").unwrap(),
        sockets: Sockets::Unix {
            path_bytes: std::num::NonZeroU16::new(108).unwrap(),
        },
        agent_forwarding: AgentForwarding::Served,
    };
    let form = agent.carrier(&linux, Setup::Inspect).unwrap();
    assert_eq!(form, Form::SocketAt(Query::AgentSshSocket));
    assert_eq!(
        form.spots(),
        vec![
            Spot::Socket(Query::AgentSshSocket),
            Spot::Variable(variable.clone())
        ]
    );

    // A person's own service behind a socket found through the same
    // variable: the remote's tools could find only one of the two.
    let mut configuration = Configuration::default();
    let theirs = Capability {
        id: name("their-agent"),
        source: Source::Service {
            host: hedwig_model::capability::ServiceHost::Workstation,
            port: ServicePort::Fixed(support::port(7001)),
            stream: Stream::Opaque,
            remote: vec![Offer::PrivateSocket {
                variable: variable.clone(),
                value: hedwig_model::text::Template::try_from("{}").unwrap(),
            }],
        },
    };
    configuration
        .apply(&catalogue, Change::Define(theirs))
        .unwrap();
    let host = remote("ssh", "build");
    for (id, exposure) in [
        ("ssh-agent", Exposure::KEY_USE),
        ("their-agent", Exposure::SERVICE),
    ] {
        configuration
            .apply(
                &catalogue,
                Change::Grant {
                    grant: grant(id, Granted::One(host.clone())),
                    terms: Terms {
                        activation: Activation::OnRequest,
                        setup: Setup::Write,
                        acknowledged: exposure,
                        lends: Lends::none(),
                    },
                },
            )
            .unwrap();
    }
    let mut trail = Trail::started();
    let connection = trail.open(&host, "linux");
    let state = trail.state();
    let world = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    let plan = world.plan(connection).unwrap();
    assert_eq!(
        plan.get(&name("ssh-agent")),
        Some(&Err(Refusal::Shared {
            capability: name("ssh-agent"),
            with: name("their-agent"),
            spot: Spot::Variable(variable.clone()),
        }))
    );
    assert_eq!(
        plan.get(&name("their-agent")),
        Some(&Err(Refusal::Shared {
            capability: name("their-agent"),
            with: name("ssh-agent"),
            spot: Spot::Variable(variable),
        }))
    );
}

struct Scene {
    catalogue: Catalogue,
    configuration: Configuration,
    trail: Trail,
    connection: ConnectionId,
}

/// `ssh-agent` granted to one host, lending `KEY`, the person's `rules`
/// written, a channel open to it, and nobody attached.
fn scene(rules: &[(RuleScope, Mode)]) -> Scene {
    let catalogue = catalogue();
    let host = remote("ssh", "build");
    let mut configuration = Configuration::default();
    configuration
        .apply(
            &catalogue,
            Change::Grant {
                grant: grant("ssh-agent", Granted::One(host.clone())),
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Write,
                    acknowledged: Exposure::KEY_USE,
                    lends: lends(&[KEY]),
                },
            },
        )
        .unwrap();
    for (scope, mode) in rules {
        configuration
            .apply(
                &catalogue,
                Change::Rule {
                    scope: scope.clone(),
                    mode: *mode,
                },
            )
            .unwrap();
    }
    let mut trail = Trail::started();
    let connection = trail.open(&host, "linux");
    Scene {
        catalogue,
        configuration,
        trail,
        connection,
    }
}

impl Scene {
    fn ask(&self, operation: Operation, used: Option<&str>) -> Verdict {
        let state = self.trail.state();
        let world = World {
            catalogue: &self.catalogue,
            configuration: &self.configuration,
            state: &state,
        };
        let used = used.map(|text| KeyId::Ssh(key(text)));
        world.decide(
            self.connection,
            &name("ssh-agent"),
            operation,
            used.as_ref(),
            self.trail.tick(),
        )
    }
}

fn on_build(operation: Selector<Operation>, keys: Keys) -> RuleScope {
    RuleScope {
        remotes: Remotes::One(remote("ssh", "build")),
        capability: Selector::Only(name("ssh-agent")),
        operation,
        key: keys,
    }
}

/// A signature is told from an authentication, so a rule that serves
/// logging in with nobody there leaves a commit's signature to the person:
/// refused while nobody can be asked.
#[test]
fn authenticating_unattended_leaves_signing_to_the_person() {
    let rule = on_build(Selector::Only(Operation::Authenticate), Keys::Every);
    let scene = scene(&[(rule.clone(), Mode::Unattended)]);
    let unseen = Verdict::Serve(Outcome::Unseen(Basis::Rule(rule.clone())));
    assert_eq!(scene.ask(Operation::Authenticate, Some(KEY)), unseen);
    assert_eq!(
        scene.ask(Operation::Connect, None),
        unseen,
        "the opening carries it"
    );
    assert_eq!(
        scene.ask(Operation::Sign, Some(KEY)),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );
    assert_eq!(
        scene.ask(Operation::Decrypt, Some(KEY)),
        Verdict::Refuse(Refusal::OperationNotInDialect {
            capability: name("ssh-agent"),
            operation: Operation::Decrypt,
        })
    );
}

/// A statement names an SSH key by its public half. One for a key the grant
/// lends opens the connection with nobody there, since the opening carries
/// that key's requests; it decides that key's requests and no other key's;
/// and a rule naming the key is not relaxed by one naming only the remote.
#[test]
fn a_statement_naming_an_ssh_key_decides_that_key_alone() {
    let for_key = on_build(
        Selector::Only(Operation::Sign),
        Keys::Only(KeyName::Ssh(key(KEY))),
    );
    let scene_ = scene(&[(for_key.clone(), Mode::Unattended)]);
    let unseen = Verdict::Serve(Outcome::Unseen(Basis::Rule(for_key.clone())));
    assert_eq!(scene_.ask(Operation::Sign, Some(KEY)), unseen);
    assert_eq!(scene_.ask(Operation::Connect, None), unseen);
    assert_eq!(
        scene_.ask(Operation::Sign, Some(OTHER)),
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );

    let confirm_key = on_build(Selector::Every, Keys::Only(KeyName::Ssh(key(KEY))));
    let lax_host = on_build(Selector::Every, Keys::Every);
    let mut scene_ = scene(&[
        (confirm_key.clone(), Mode::Confirm),
        (lax_host, Mode::Unattended),
    ]);
    let client = scene_.trail.attach(ClientKind::Interface, DESKTOP);
    scene_.trail.push(Event::Presence {
        client,
        presence: hedwig_model::trail::Presence::Present,
    });
    assert_eq!(
        scene_.ask(Operation::Authenticate, Some(KEY)),
        Verdict::Hold(Basis::Rule(confirm_key))
    );
}

/// An agent's keys are listed for a grant surface, and only an agent's; an
/// agent nothing answers for is refused saying so.
#[test]
fn only_an_agent_is_asked_for_its_keys() {
    let catalogue = catalogue();
    let mut desk = support::desk::Desk::new(catalogue);
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    assert_eq!(
        desk.send(interface, Request::Keys(name("gpg-ssh"))),
        Err(Refusal::SourceUnavailable {
            capability: name("gpg-ssh"),
            failure: hedwig_model::trail::Failure::Unreachable,
        })
    );
    desk.held.keys.insert(name("gpg-ssh"), Ok(Vec::new()));
    assert_eq!(
        desk.send(interface, Request::Keys(name("gpg-ssh"))),
        Ok(hedwig_model::protocol::Reply::Keys(Vec::new()))
    );
    assert_eq!(
        desk.send(interface, Request::Keys(name("adb"))),
        Err(Refusal::Unlendable {
            capability: name("adb"),
            lent: Holds::Keys,
        })
    );
    assert_eq!(
        desk.send(interface, Request::Devices(name("ssh-agent"))),
        Err(Refusal::Unlendable {
            capability: name("ssh-agent"),
            lent: Holds::Devices,
        })
    );
}

/// What a relay withholds of an agent's request is said for any key's type.
#[test]
fn what_an_agent_s_relay_withholds_is_worded() {
    assert_eq!(
        Withheld::KeyUnlent(key(KEY)).to_string(),
        "it asked for ssh-ed25519, which the grant does not lend"
    );
    assert_eq!(
        Withheld::Elsewhere(key(OTHER)).to_string(),
        "it used ecdsa-sha2-nistp256 for something other than logging in to a host the grant \
         names for it"
    );
    assert!(Withheld::Managing.to_string().contains("SSH agent"));
}
