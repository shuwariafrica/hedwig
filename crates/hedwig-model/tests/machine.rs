//! A key the workstation's TPM holds: a source the core answers for itself,
//! served by the same grant, list and decision as any agent's keys; made,
//! listed and deleted by the person through the control channel, with every
//! lending of a deleted key taken back first.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::collections::{BTreeSet, VecDeque};

use hedwig_model::capability::{
    AgentAt, Dialect, Exposure, Form, Holds, KeyKind, Lends, Operation, Query, Setup, Source,
    Toward,
};
use hedwig_model::config::{Accepted, Activation, Change, Configuration, Effect, Terms, lendable};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::organisation::{Part, Place, Policy, Start};
use hedwig_model::platform::{AgentForwarding, Platform, Sockets};
use hedwig_model::policy::{Basis, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{AgentKey, Notice, Reply, Request, ToCore, Topic};
use hedwig_model::refusal::{Refusal, kind_words};
use hedwig_model::remote::{Granted, Remotes};
use hedwig_model::scope::Audience;
use hedwig_model::text::{Kernel, KeyId, SshKey, Words};
use hedwig_model::trail::{ClientKind, Event, Failure, Presence};
use hedwig_model::wire::{line, read};

mod support;
use support::desk::{Desk, Tpm};
use support::{DESKTOP, Trail, catalogue, grant, name, remote};

/// Public halves of the kinds a TPM makes, written by the in-box
/// `ssh-keygen`.
const P256: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrm25FDDmgurPp+9REqiJK8zAJcpqMSElCklOS/AsegLtx+gx5BUgH5CnBk5aAOQSkrVsP5DuaWeib+dCzCSqo=";
const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGuMSw+svCEHaoiz5zu7/7Abjmzr5dl8p3x+M14Eqo/OJ6lLmHJt6PTF75Xfa2nFbBVvxFSD0C2RkmbseMIgFQIsiJVlHwooW3VPW/dz9iXPyw3GqysWff5Ec30f1gN93P8ePxp4eQvX53+yZSmp4ViMD7oYxTH9/plxKxIGEzczDFPKxZYWHuAmt0KeZru2R7GUx7hD58rqGbZ1fnQgJLUJOfi6FF9u2hkWHfTtBh2fAwJAQttb0se/gTr4alPiTxkI2qr9iQATuaMPfmCOwdwwQtQ7QEfSbbpMrtFQsStsapsWppNgcIg8cLvCFFu7Ek/OzOMOZazuQtMrME8YDz";

fn key(text: &str) -> SshKey {
    SshKey::try_from(text).unwrap()
}

fn lending(keys: &[&str]) -> Lends {
    Lends::of_keys(keys.iter().map(|text| (key(text), Toward::Anywhere.into())))
}

fn listed(name_: &str, text: &str) -> AgentKey {
    AgentKey {
        key: key(text),
        comment: Some(Words::try_from(name_).unwrap()),
    }
}

/// A TPM that makes P-256, P-384 and 2048-bit RSA keys, as this
/// workstation's does, holding `keys` and making `next` in turn.
fn tpm(keys: &[(&str, &str)], next: &[&str]) -> Tpm {
    Tpm {
        kinds: BTreeSet::from([KeyKind::EcdsaP256, KeyKind::EcdsaP384, KeyKind::Rsa2048]),
        keys: keys
            .iter()
            .map(|(name_, text)| (name(name_), key(text)))
            .collect(),
        next: next.iter().map(|text| key(text)).collect::<VecDeque<_>>(),
    }
}

fn linux() -> Platform {
    Platform {
        family: name("linux"),
        kernel: Kernel::try_from("Linux").unwrap(),
        sockets: Sockets::Unix {
            path_bytes: std::num::NonZeroU16::new(108).unwrap(),
        },
        agent_forwarding: AgentForwarding::Served,
    }
}

/// `machine-ssh` ships, and is an agent source in every respect a grant,
/// a remote and the gate read: the agent protocol, key use, keys to lend
/// and nothing else, the remote's agent socket and `SSH_AUTH_SOCK`.
#[test]
fn a_machine_key_is_served_as_any_agent_s_key() {
    let catalogue = catalogue();
    let machine = Configuration::default()
        .capability(&catalogue, &name("machine-ssh"))
        .unwrap();
    assert_eq!(
        machine.source,
        Source::Agent {
            at: AgentAt::Machine
        }
    );
    assert_eq!(machine.dialect(), Dialect::SshAgent);
    assert_eq!(machine.exposure(), Exposure::KEY_USE);
    assert_eq!(machine.holds(), Some(Holds::Keys));
    assert_eq!(
        machine.carrier(&linux(), Setup::Inspect),
        Ok(Form::SocketAt(Query::AgentSshSocket))
    );
    assert_eq!(lendable(&machine, &lending(&[P256, RSA])), Ok(()));
    assert_eq!(
        lendable(
            &machine,
            &Lends::devices([hedwig_model::text::DeviceSerial::try_from("R5CT1").unwrap()])
        ),
        Err(Refusal::Unlendable {
            capability: name("machine-ssh"),
            lent: Holds::Devices,
        })
    );
    assert_eq!(
        read::<Source>(r#"{"agent":{"at":"machine"}}"#),
        Ok(machine.source.clone())
    );
    assert_eq!(line(&machine.source), r#"{"agent":{"at":"machine"}}"#);
}

/// Each kind is written by one word and read back from it, names the key
/// type OpenSSH writes its public half with, and is worded for the person;
/// a word for no kind is refused.
#[test]
fn every_kind_is_written_read_and_named_as_openssh_names_it() {
    let words: Vec<String> = KeyKind::ALL.iter().map(line).collect();
    assert_eq!(
        words,
        [
            r#""ecdsa-p256""#,
            r#""ecdsa-p384""#,
            r#""ecdsa-p521""#,
            r#""rsa-2048""#,
            r#""rsa-3072""#,
            r#""rsa-4096""#
        ]
    );
    for kind in KeyKind::ALL {
        assert_eq!(read::<KeyKind>(&line(&kind)), Ok(kind));
        let request = ToCore {
            id: 9,
            request: Request::MakeKey {
                name: name("laptop"),
                kind,
            },
        };
        assert_eq!(read::<ToCore>(&line(&request)).as_ref(), Ok(&request));
    }
    assert!(read::<KeyKind>(r#""ed25519""#).is_err());
    assert_eq!(
        KeyKind::ALL.map(KeyKind::ssh_type),
        [
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "ssh-rsa",
            "ssh-rsa",
            "ssh-rsa"
        ]
    );
    assert_eq!(key(P256).kind(), KeyKind::EcdsaP256.ssh_type());
    assert_eq!(key(RSA).kind(), KeyKind::Rsa2048.ssh_type());
    assert_eq!(
        KeyKind::ALL.map(kind_words),
        [
            "ECDSA P-256",
            "ECDSA P-384",
            "ECDSA P-521",
            "2048-bit RSA",
            "3072-bit RSA",
            "4096-bit RSA"
        ]
    );
}

/// A key is made under the name the person gives and the kind they choose,
/// answered with its public half, recorded, and listed under its name; every
/// client listing the TPM's keys is told they changed, and a client that
/// lists another agent's is not. A name the TPM holds and a kind it does not
/// make are refused, saying which.
#[test]
fn a_key_is_made_named_listed_and_told_to_every_client_that_lists_them() {
    let mut desk = Desk::new(catalogue());
    desk.held.tpm = Some(tpm(&[], &[P256, RSA]));
    desk.held.keys.insert(name("ssh-agent"), Ok(Vec::new()));
    let window = desk.attend(ClientKind::Interface, DESKTOP);
    let other = desk.attend(ClientKind::Interface, DESKTOP);
    let terminal = desk.attend(ClientKind::Terminal, DESKTOP);
    assert_eq!(
        desk.send(window, Request::Keys(name("machine-ssh"))),
        Ok(Reply::Keys(Vec::new()))
    );
    desk.send(other, Request::Keys(name("ssh-agent"))).unwrap();

    let made = desk.send(
        terminal,
        Request::MakeKey {
            name: name("laptop"),
            kind: KeyKind::EcdsaP256,
        },
    );
    assert_eq!(made, Ok(Reply::Made(listed("laptop", P256))));
    assert_eq!(
        desk.trail.entries.last().unwrap().event,
        Event::KeyMade {
            key: key(P256),
            name: name("laptop"),
            by: terminal,
        }
    );
    assert_eq!(
        desk.told(),
        vec![(window, Notice::Stale(Topic::Keys(name("machine-ssh"))))]
    );
    assert_eq!(
        desk.send(window, Request::Keys(name("machine-ssh"))),
        Ok(Reply::Keys(vec![listed("laptop", P256)]))
    );

    let again = desk.send(
        terminal,
        Request::MakeKey {
            name: name("laptop"),
            kind: KeyKind::Rsa2048,
        },
    );
    assert_eq!(again, Err(Refusal::KeyExists(name("laptop"))));
    assert_eq!(
        again.unwrap_err().to_string(),
        "this workstation's TPM already holds a key of Hedwig's named laptop; give the new one \
         another name"
    );
    let unmade = desk.send(
        terminal,
        Request::MakeKey {
            name: name("big"),
            kind: KeyKind::Rsa4096,
        },
    );
    assert_eq!(unmade, Err(Refusal::KindUnmade(KeyKind::Rsa4096)));
    assert_eq!(
        unmade.unwrap_err().to_string(),
        "this workstation's TPM does not make 4096-bit RSA keys; another kind can be made"
    );
    assert!(desk.told().is_empty(), "nothing changed");
    assert_eq!(
        desk.send(
            terminal,
            Request::MakeKey {
                name: name("azure"),
                kind: KeyKind::Rsa2048,
            },
        ),
        Ok(Reply::Made(listed("azure", RSA)))
    );
}

/// With no TPM the provider answers for, nothing is made or deleted and its
/// keys are not listed, each saying why.
#[test]
fn without_a_tpm_nothing_is_made_listed_or_deleted() {
    let mut desk = Desk::new(catalogue());
    let window = desk.attend(ClientKind::Interface, DESKTOP);
    let listing = desk.send(window, Request::Keys(name("machine-ssh")));
    assert_eq!(
        listing,
        Err(Refusal::SourceUnavailable {
            capability: name("machine-ssh"),
            failure: Failure::NoTpm,
        })
    );
    assert_eq!(
        listing.unwrap_err().to_string(),
        "machine-ssh signs in this workstation's TPM, and Windows' provider for it did not \
         answer for this sign-in"
    );
    let making = desk.send(
        window,
        Request::MakeKey {
            name: name("laptop"),
            kind: KeyKind::EcdsaP256,
        },
    );
    assert_eq!(making, Err(Refusal::NoTpm));
    assert_eq!(
        making.unwrap_err().to_string(),
        "Windows' provider for this workstation's TPM did not answer for this sign-in, so no key \
         can be made or deleted in it here"
    );
    assert_eq!(
        desk.send(window, Request::DeleteKey(key(P256))),
        Err(Refusal::NoTpm)
    );
}

/// A key is deleted by its public half. Every grant and acceptance that
/// lends it lends it no more first, each change recorded before the
/// deletion; other keys stay lent, and a grant of every key needs no change.
/// A key the TPM does not hold is refused and nothing is changed.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one scene: two grants, an acceptance, two deletions"
)]
fn deleting_a_key_takes_it_out_of_every_lending_first() {
    let catalogue = catalogue();
    let mut desk = Desk::new(catalogue.clone());
    desk.held.tpm = Some(tpm(&[("laptop", P256)], &[]));
    let window = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(window, Request::Keys(name("machine-ssh")))
        .unwrap();
    let build = remote("ssh", "build");
    let fleet = remote("ssh", "fleet");
    let granted = |remote_| grant("machine-ssh", Granted::One(remote_));
    let terms = |lends| Terms {
        activation: Activation::OnRequest,
        setup: Setup::Inspect,
        acknowledged: Exposure::NONE,
        lends,
    };
    for (remote_, lends) in [
        (build.clone(), lending(&[P256, RSA])),
        (fleet.clone(), Lends::Every),
    ] {
        desk.send(
            window,
            Request::Change(Change::Grant {
                grant: granted(remote_),
                terms: terms(lends),
            }),
        )
        .unwrap();
    }
    let started = remote("ssh", "starting");
    let text = line(&Start::Grant {
        grant: granted(started.clone()),
        activation: Activation::OnRequest,
    });
    desk.govern(&Policy::read([(
        Place {
            audience: Audience::Machine,
            part: Part::Start,
        },
        text.as_str(),
    )]));
    let accepted = Accepted {
        setup: Setup::Inspect,
        acknowledged: Exposure::NONE,
        lends: lending(&[P256]),
    };
    desk.send(
        window,
        Request::Change(Change::Accept {
            grant: granted(started.clone()),
            accepted: accepted.clone(),
        }),
    )
    .unwrap();
    let before = desk.trail.entries.len();
    desk.told();

    assert_eq!(
        desk.send(window, Request::DeleteKey(key(RSA))),
        Err(Refusal::KeyAbsent(key(RSA)))
    );
    assert_eq!(desk.trail.entries.len(), before, "nothing recorded");
    assert!(
        Refusal::KeyAbsent(key(RSA))
            .to_string()
            .starts_with("this workstation's TPM holds no key Hedwig made whose public half is ")
    );

    assert_eq!(
        desk.send(window, Request::DeleteKey(key(P256))),
        Ok(Reply::Done(Effect::Changed))
    );
    let events: Vec<Event> = desk.trail.entries[before..]
        .iter()
        .map(|entry| entry.event.clone())
        .collect();
    assert_eq!(events.len(), 3);
    assert!(matches!(
        &events[0],
        Event::Changed { change: Change::Grant { grant, terms }, by, .. }
            if *grant == granted(build.clone()) && terms.lends == lending(&[RSA]) && *by == window
    ));
    assert!(matches!(
        &events[1],
        Event::Changed { change: Change::Accept { grant, accepted }, .. }
            if *grant == granted(started.clone()) && accepted.lends == Lends::none()
    ));
    assert_eq!(
        events[2],
        Event::KeyDeleted {
            key: key(P256),
            name: name("laptop"),
            by: window,
        }
    );
    let lends = |remote_: hedwig_model::remote::RemoteId| {
        let wanted = granted(remote_);
        desk.configuration
            .grants()
            .find(|(grant, _)| **grant == wanted)
            .map(|(_, terms)| terms.lends.clone())
    };
    assert_eq!(lends(build), Some(lending(&[RSA])));
    assert_eq!(lends(fleet), Some(Lends::Every));
    assert_eq!(
        desk.configuration.unlending(&key(P256)),
        Vec::<Change>::new()
    );
    assert_eq!(
        desk.told(),
        vec![(window, Notice::Stale(Topic::Keys(name("machine-ssh"))))]
    );
    assert_eq!(
        desk.send(window, Request::Keys(name("machine-ssh"))),
        Ok(Reply::Keys(Vec::new()))
    );
}

/// Nothing at a TPM key asks before it signs, so a statement about every key
/// usable with nobody at it covers a machine key's requests: the person can
/// have every use confirmed in one rule. The opening carries it too.
#[test]
fn a_rule_for_keys_needing_no_touch_covers_a_machine_key() {
    let catalogue = catalogue();
    let host = remote("ssh", "build");
    let rule = RuleScope {
        remotes: Remotes::Every,
        capability: Selector::Every,
        operation: Selector::Only(Operation::Sign),
        key: Keys::NeedingNoTouch,
    };
    let mut configuration = Configuration::default();
    for change in [
        Change::Grant {
            grant: grant("machine-ssh", Granted::One(host.clone())),
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged: Exposure::NONE,
                lends: lending(&[P256]),
            },
        },
        Change::Rule {
            scope: rule.clone(),
            mode: Mode::Confirm,
        },
    ] {
        configuration.apply(&catalogue, change).unwrap();
    }
    let mut trail = Trail::started();
    let connection = trail.open(&host, "linux");
    let client = trail.attach(ClientKind::Interface, DESKTOP);
    trail.push(Event::Presence {
        client,
        presence: Presence::Present,
    });
    let state = trail.state();
    let world = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    let ask = |operation, used: Option<KeyId>| {
        world.decide(
            connection,
            &name("machine-ssh"),
            operation,
            used.as_ref(),
            trail.tick(),
        )
    };
    assert_eq!(
        ask(Operation::Sign, Some(KeyId::Ssh(key(P256)))),
        Verdict::Hold(Basis::Rule(rule))
    );
    assert!(matches!(
        ask(Operation::Authenticate, Some(KeyId::Ssh(key(P256)))),
        Verdict::Serve(_)
    ));
}

/// A list of the TPM's keys is one a client is kept told of, like any
/// agent's, and its notice is written with the capability it names.
#[test]
fn a_list_of_keys_is_kept_current_for_the_client_that_asked() {
    assert_eq!(
        Topic::listed(&Request::Keys(name("machine-ssh"))),
        Some(Topic::Keys(name("machine-ssh")))
    );
    assert_eq!(
        Topic::listed(&Request::MakeKey {
            name: name("laptop"),
            kind: KeyKind::EcdsaP256,
        }),
        None
    );
    assert_eq!(
        line(&Notice::Stale(Topic::Keys(name("machine-ssh")))),
        r#"{"stale":{"keys":"machine-ssh"}}"#
    );
}
