//! A refusal's sentence is for the person reading it: words, with no type's
//! spelling in them, and each operation, section, mode and activation worded
//! as itself.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::collections::BTreeSet;

use hedwig_model::capability::Operation;
use hedwig_model::config::Activation;
use hedwig_model::organisation::Limit;
use hedwig_model::policy::Mode;
use hedwig_model::refusal::{Refusal, Section};
use hedwig_model::scope::Audience;
use hedwig_model::trail::Failure;

mod support;
use support::corpus::{self, SECTIONS};
use support::name;

const FAILURES: [Failure; 12] = [
    Failure::Unresolved,
    Failure::Unreachable,
    Failure::Mismatched,
    Failure::Unserved,
    Failure::NoAddress,
    Failure::Foreign,
    Failure::Unidentified,
    Failure::Unstartable,
    Failure::Unopened,
    Failure::Absent,
    Failure::Busy,
    Failure::Outdated,
];
const OPERATIONS: [Operation; 3] = [Operation::Connect, Operation::Sign, Operation::Decrypt];
const MODES: [Mode; 3] = [Mode::Unattended, Mode::Notify, Mode::Confirm];
const ACTIVATIONS: [Activation; 3] = [
    Activation::OnRequest,
    Activation::WhileRunning,
    Activation::Continuous,
];

fn held(limit: Limit) -> Refusal {
    Refusal::Held {
        audience: Audience::Person,
        limit: Box::new(limit),
    }
}

/// A refusal for every section, operation, mode and activation a sentence
/// words, each once.
fn worded() -> Vec<Vec<Refusal>> {
    let limits = corpus::limits();
    let Some(Limit::Floor { scope: floor, .. }) = limits.first().cloned() else {
        panic!("the corpus starts with a floor");
    };
    let Some(Limit::Activation { scope: most, .. }) = limits.get(1).cloned() else {
        panic!("then a most readily");
    };
    vec![
        SECTIONS.into_iter().map(Refusal::Repeated).collect(),
        OPERATIONS
            .into_iter()
            .map(|operation| Refusal::OperationNotInDialect {
                capability: name("adb"),
                operation,
            })
            .collect(),
        MODES
            .into_iter()
            .map(|mode| {
                held(Limit::Floor {
                    scope: floor.clone(),
                    mode,
                })
            })
            .collect(),
        ACTIVATIONS
            .into_iter()
            .map(|activation| {
                held(Limit::Activation {
                    scope: most.clone(),
                    most: activation,
                })
            })
            .collect(),
    ]
}

/// The spelling each of those has in code, which a sentence must never show.
fn spellings() -> Vec<String> {
    SECTIONS
        .iter()
        .map(|section| format!("{section:?}"))
        .chain(OPERATIONS.iter().map(|operation| format!("{operation:?}")))
        .chain(MODES.iter().map(|mode| format!("{mode:?}")))
        .chain(
            ACTIVATIONS
                .iter()
                .map(|activation| format!("{activation:?}")),
        )
        .collect()
}

#[test]
fn every_refusal_reads_as_words() {
    let spellings = spellings();
    let every: Vec<Refusal> = corpus::refusals()
        .into_iter()
        .chain(worded().into_iter().flatten())
        .collect();
    for refusal in &every {
        let sentence = refusal.to_string();
        assert!(sentence.is_ascii(), "{sentence}");
        assert_eq!(sentence.trim(), sentence, "{refusal:?}");
        assert!(!sentence.contains("  "), "{sentence}");
        assert!(!sentence.ends_with('.'), "{sentence}");
        for word in sentence.split(|c: char| !c.is_ascii_alphanumeric()) {
            assert!(
                !spellings.iter().any(|spelling| spelling == word),
                "{word} in {sentence}"
            );
        }
    }
}

/// A capability is named by whoever defines it, often after its own kind: a
/// failure of its source reads for any name, the kind's own included, and
/// says which of the browser's two ways of starting failed.
#[test]
fn a_sources_failure_reads_for_a_capability_named_after_its_kind() {
    let failing = |capability: &str, failure: Failure| {
        Refusal::SourceUnavailable {
            capability: name(capability),
            failure,
        }
        .to_string()
    };
    assert_eq!(
        failing("browser", Failure::Unstartable),
        "browser names a program that is not on this workstation's search path, or that would \
         not start"
    );
    assert_eq!(
        failing("browser", Failure::Unopened),
        "browser opens addresses with your default browser, and this workstation has none set \
         for web addresses, or the one set would not start"
    );
    for kind in [
        "browser", "serial", "port", "gpg", "gnupg", "host", "service", "agent", "program", "adb",
    ] {
        let held = Refusal::PortHeld {
            capability: name(kind),
            by: support::remote("ssh", "dev@build"),
        }
        .to_string();
        let sentences = FAILURES.map(|failure| failing(kind, failure));
        for sentence in sentences.iter().chain([&held]) {
            assert!(
                !sentence.to_lowercase().contains(&format!("{kind} {kind}")),
                "{sentence}"
            );
        }
    }
}

#[test]
fn each_section_operation_mode_and_activation_is_worded_as_itself() {
    for group in worded() {
        let sentences: BTreeSet<String> = group.iter().map(ToString::to_string).collect();
        assert_eq!(sentences.len(), group.len(), "{sentences:?}");
    }
    assert_eq!(
        Refusal::Repeated(Section::Returns).to_string(),
        "the document lists the same entry twice under waits before a channel comes back"
    );
    assert_eq!(
        Refusal::OperationNotInDialect {
            capability: name("adb"),
            operation: Operation::Sign,
        }
        .to_string(),
        "adb never asks to sign"
    );
    assert_eq!(
        Refusal::Reserved(name("gpg")).to_string(),
        "gpg is defined outside your configuration, by Hedwig or your organisation; choose \
         another name for your own definition"
    );
}

/// What readiness names reads as words too, and says of each whether it keeps
/// the capability from being carried: what stands at the socket's path, or
/// keeps readiness from looking, blocks; what stands between the remote's
/// tool and its use of the key is carried and named.
#[test]
fn every_finding_reads_as_words_and_says_whether_it_blocks() {
    let spellings = spellings();
    let mut blocking = Vec::new();
    for finding in corpus::findings() {
        let sentence = finding.to_string();
        assert!(sentence.is_ascii(), "{sentence}");
        assert_eq!(sentence.trim(), sentence, "{finding:?}");
        assert!(!sentence.contains("  "), "{sentence}");
        assert!(!sentence.ends_with('.'), "{sentence}");
        for word in sentence.split(|c: char| !c.is_ascii_alphanumeric()) {
            assert!(
                !spellings.iter().any(|spelling| spelling == word),
                "{word} in {sentence}"
            );
        }
        if finding.blocks() {
            blocking.push(format!("{finding:?}"));
        }
    }
    let cautions = [
        "AgentAutostarts",
        "KeyboxdStopped",
        "PublicKeyAbsent",
        "KeyringAbsent",
        "SigningKeyUnset",
        "SigningKeyOther",
        "VariableUnset",
        "TheirForward",
        "HelperBeside",
    ];
    // A variable the remote's tool reads its forward by blocks unwritten, and
    // so does git's helper line; `no-autostart` unwritten is carried.
    assert_eq!(
        blocking.len(),
        corpus::findings().len() - cautions.len() - 1
    );
    assert!(
        blocking
            .iter()
            .any(|finding| finding.starts_with("Unwritten { write: Variable"))
    );
    assert!(
        blocking
            .iter()
            .any(|finding| finding.starts_with("Unwritten { write: Helper"))
    );
    assert!(
        !blocking
            .iter()
            .any(|finding| finding.starts_with("Unwritten { write: NoAutostart"))
    );
    assert!(
        blocking
            .iter()
            .all(|finding| !cautions.iter().any(|caution| finding.starts_with(caution)))
    );
}

/// Each write reads as the tool it configures names it, and a write not made
/// reads with those same words: the one source a surface shows before consent
/// and after.
#[test]
fn every_write_reads_in_its_tools_words() {
    use hedwig_model::text::{Fingerprint, Mark, Variable, Words};
    use hedwig_model::trail::{Finding, Write};

    let key = Fingerprint::try_from("07B56DFBBA12BB80FA84939C76F8274EF1651088").unwrap();
    let variable = Variable::try_from("ADB_SERVER_SOCKET").unwrap();
    let pinned = [
        (
            Write::NoAutostart,
            "no-autostart in the remote's GnuPG configuration",
        ),
        (
            Write::PublicKey(key.clone()),
            "the public key 07B56DFBBA12BB80FA84939C76F8274EF1651088 into the remote's keyring",
        ),
        (
            Write::SigningKey(Mark::try_from(key.as_str()).unwrap()),
            "07B56DFBBA12BB80FA84939C76F8274EF1651088 as the remote git's signing key",
        ),
        (
            Write::Variable(variable),
            "ADB_SERVER_SOCKET in your shell's startup on the remote",
        ),
        (
            Write::SocketFile,
            "the file the remote's gpg finds its agent by",
        ),
        (
            Write::Masked,
            "a mask on the remote's own service unit that holds the path the forward needs, which stops the agent it started there",
        ),
    ];
    for (write, words) in pinned {
        assert_eq!(write.to_string(), words);
        let unwritten = Finding::Unwritten {
            write,
            why: Words::try_from("the file is not the remote user's").unwrap(),
        };
        assert_eq!(
            unwritten.to_string(),
            format!("Hedwig did not write {words}: the file is not the remote user's")
        );
    }
}

/// What consent to write names: every write it can, and where the source's
/// keys have not been read, that their public halves and the signing key are
/// written too. Read, each key is named; a capability that writes no keys
/// says nothing of them.
#[test]
fn consent_names_each_write_and_the_keys_not_yet_read() {
    use hedwig_model::trail::Write;

    let catalogue = support::catalogue();
    let gpg = support::capability(&catalogue, "gpg");
    let unread = gpg.consent(None);
    assert_eq!(
        unread.writes,
        [Write::NoAutostart, Write::Masked, Write::SocketFile]
    );
    assert!(unread.keys_unread);
    assert_eq!(
        unread.to_string(),
        "Hedwig may write no-autostart in the remote's GnuPG configuration; a mask on the remote's own service unit that holds the path the forward needs, which stops the agent it started there; the file the remote's gpg finds its agent by; and, once it has read them, the public key of each key your GnuPG offers into the remote's keyring, with the one you sign with as the remote git's signing key"
    );
    let keyring = corpus::keyring();
    let read = gpg.consent(Some(&keyring));
    assert!(!read.keys_unread);
    let primary =
        hedwig_model::text::Fingerprint::try_from("07B56DFBBA12BB80FA84939C76F8274EF1651088")
            .unwrap();
    assert_eq!(
        read.writes,
        [
            Write::NoAutostart,
            Write::Masked,
            Write::SocketFile,
            Write::PublicKey(primary.clone()),
            Write::SigningKey(hedwig_model::text::Mark::try_from(primary.as_str()).unwrap()),
        ]
    );
    let adb = support::capability(&catalogue, "adb").consent(None);
    assert!(!adb.keys_unread);
    assert_eq!(
        adb.to_string(),
        "Hedwig may write ADB_SERVER_SOCKET in your shell's startup on the remote"
    );
    assert!(gpg.consent(None).reaches.is_none());
}

/// Who reaches a service offered behind a private socket and on a port,
/// with consent to write and without it, in the model's words, so every
/// surface that offers the consent says the same; for ADB, which client reads
/// no socket.
#[test]
fn consent_says_who_on_the_remote_reaches_the_service_with_it_and_without() {
    use hedwig_model::capability::{Capability, Offer, ServiceHost, ServicePort, Source, Stream};
    use hedwig_model::text::{Template, Variable};

    let catalogue = support::catalogue();
    let adb = support::capability(&catalogue, "adb").consent(None);
    assert_eq!(
        adb.reaches.unwrap().to_string(),
        "With it, what reads ADB_SERVER_SOCKET on the remote reaches adb through a socket only the remote user can open; without it, through port 5037 there, which every user and program on the remote can reach. Gradle's own client, which runs connectedAndroidTest, reads no socket: a remote that runs Gradle takes ADB on the port, where you leave this off."
    );
    let metro = Capability {
        id: name("metro"),
        source: Source::Service {
            host: ServiceHost::Workstation,
            port: ServicePort::Fixed(support::port(8081)),
            stream: Stream::Opaque,
            remote: vec![
                Offer::Port(ServicePort::Unstated),
                Offer::PrivateSocket {
                    variable: Variable::try_from("METRO_SOCKET").unwrap(),
                    value: Template::try_from("{}").unwrap(),
                },
            ],
        },
    };
    assert_eq!(
        metro.consent(None).reaches.unwrap().to_string(),
        "With it, what reads METRO_SOCKET on the remote reaches metro through a socket only the remote user can open; without it, through a port there, which every user and program on the remote can reach."
    );
    for port_only in ["openocd", "ssh-agent"].map(|id| support::capability(&catalogue, id)) {
        assert!(
            port_only.consent(None).reaches.is_none(),
            "{}",
            port_only.id
        );
    }
    assert!(support::browser().consent(None).reaches.is_none());
}
