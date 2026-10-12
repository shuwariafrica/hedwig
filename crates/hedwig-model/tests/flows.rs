//! The workflows of `REQUIREMENTS.md`, each driven end to end through the
//! protocol's requests and the trail's events, named for the person and what
//! they are after.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU32;

use hedwig_model::capability::{Exposure, Lends, Operation, Setup};
use hedwig_model::config::{Activation, Change, Configuration, Document, Effect, Terms};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::policy::{Basis, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{
    Act, Answer, Attention, Decision, PROTOCOL, Proof, Reply, Request, Row, Standing, Through,
};
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::text::{Fingerprint, Grip, RemotePath, Serial, Words};
use hedwig_model::trail::{
    Binding, Card, ClientKind, Event, Failure, Finding, Health, Held, Outcome, Presence, PromptId,
    PromptKind, Readiness, SignaturePin, Touch,
};
use hedwig_model::wire::{page, read};

mod support;
use support::desk::Desk;
use support::{DESKTOP, OVER_SSH, catalogue, decided_terms, grant, name, remote, terms};

fn granting(id: &str, remotes: Granted, activation: Activation, acknowledged: Exposure) -> Request {
    Request::Change(Change::Grant {
        grant: grant(id, remotes),
        terms: terms(activation, acknowledged),
    })
}

fn rows(desk: &mut Desk, client: hedwig_model::trail::ClientId) -> Vec<Row> {
    match desk.send(client, Request::Exposure) {
        Ok(Reply::Exposure(rows)) => rows,
        other => unreachable_reply(&other),
    }
}

fn attention(desk: &mut Desk, client: hedwig_model::trail::ClientId) -> Vec<Attention> {
    match desk.send(client, Request::Attention) {
        Ok(Reply::Attention(items)) => items.into_iter().map(|needs| needs.attention).collect(),
        other => unreachable_reply(&other),
    }
}

#[allow(clippy::panic, reason = "a test failure")]
fn unreachable_reply(reply: &Result<Reply, Refusal>) -> ! {
    panic!("unexpected reply: {reply:?}")
}

/// Workspaces are created and destroyed daily, so the grant is to
/// the route, made once; a workspace that starts is served with nothing
/// configured for it.
#[test]
fn a_remote_author_signs_in_a_workspace_created_this_morning() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    assert_eq!(
        desk.send(
            interface,
            granting(
                "gpg",
                Granted::Route(name("coder")),
                Activation::WhileRunning,
                Exposure::NONE
            )
        ),
        Ok(Reply::Changed {
            effect: Effect::Changed,
            held: Vec::new()
        })
    );

    // Before any workspace exists the grant is still a row, waiting.
    let waiting = rows(&mut desk, interface);
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting.first().unwrap().remote, None);
    assert_eq!(waiting.first().unwrap().standing, Standing::Idle);
    assert_eq!(waiting.first().unwrap().connection, None);

    let workspace = remote("coder", "dev/monday");
    let wanted = |desk: &Desk| {
        let state = desk.trail.state();
        World {
            catalogue: &desk.catalogue,
            configuration: &desk.configuration,
            state: &state,
        }
        .wanted(&workspace)
    };
    assert!(!wanted(&desk), "nothing runs yet");
    desk.trail.push(Event::Appeared {
        remote: workspace.clone(),
    });
    assert!(wanted(&desk), "the grant follows the workspace's life");

    let connection = desk.channel_up(&workspace, "linux");
    let (request, verdict) = desk.asks(connection, "gpg", Operation::Sign);
    assert_eq!(verdict, Verdict::Serve(Outcome::Served(Basis::Default)));

    let row = desk.row(interface, &workspace, &name("gpg"));
    assert!(matches!(
        row.standing,
        Standing::Serving(Binding::Socket(_))
    ));
    assert_eq!(
        row.connection,
        Some(connection),
        "what a per-connection act names"
    );
    let last = row.last.expect("the last request");
    assert_eq!(last.request.0, request.0);
    assert_eq!(last.operation, Operation::Sign);
    assert_eq!(last.outcome, Some(Outcome::Served(Basis::Default)));
    assert_eq!(
        row.through,
        Through::Grant(grant("gpg", Granted::Route(name("coder"))))
    );

    desk.trail.push(Event::Gone {
        remote: workspace.clone(),
    });
    assert!(!wanted(&desk), "and ends with it");
}

/// Each release signature is a deliberate act, and the
/// signer is at a terminal over SSH into the workstation with its desktop
/// locked.
#[test]
fn a_release_signer_confirms_each_signature_from_a_terminal_over_ssh() {
    let mut desk = Desk::new(catalogue());
    let host = remote("ssh", "release@build.example");
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(
        interface,
        granting(
            "gpg",
            Granted::One(host.clone()),
            Activation::OnRequest,
            Exposure::NONE,
        ),
    )
    .unwrap();
    desk.send(
        interface,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::One(host.clone()),
                capability: Selector::Only(name("gpg")),
                operation: Selector::Only(Operation::Sign),
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    )
    .unwrap();
    desk.send(interface, Request::Presence(Presence::Away))
        .unwrap();

    let terminal = desk.attend(ClientKind::Terminal, OVER_SSH);
    assert_eq!(
        desk.send(
            terminal,
            Request::Connect {
                remote: host.clone(),
                with: Vec::new(),
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            }
        ),
        Ok(Reply::Done(Effect::Changed))
    );
    let connection = desk.channel_up(&host, "linux");

    let (first, verdict) = desk.asks(connection, "gpg", Operation::Sign);
    assert!(matches!(verdict, Verdict::Hold(Basis::Rule(_))));
    // The request interrupts. The grant and the rule's connection were made
    // at the desktop, not at this terminal, so the grant waits beside it.
    assert!(matches!(
        attention(&mut desk, terminal).as_slice(),
        [
            Attention::Request { request, remote, operation: Operation::Sign, .. },
            Attention::Widened { kind: ClientKind::Interface, .. },
        ] if *request == first && *remote == host
    ));
    let grant_seen = attention(&mut desk, terminal)
        .last()
        .and_then(Attention::item)
        .expect("something to put away");
    desk.send(terminal, Request::PutAway(grant_seen)).unwrap();

    // A script attached beside the terminal cannot answer for the person.
    let script = desk.attend(ClientKind::Command, OVER_SSH);
    let decide = |request, decision| Request::Decide { request, decision };
    assert_eq!(
        desk.send(script, decide(first, Decision::Once)),
        Err(Refusal::NotAttending)
    );

    assert_eq!(
        desk.send(terminal, decide(first, Decision::Once)),
        Ok(Reply::Done(Effect::Changed))
    );
    assert_eq!(
        desk.send(terminal, decide(first, Decision::Once)),
        Err(Refusal::UnknownRequest(first)),
        "a request is decided once"
    );
    assert_eq!(attention(&mut desk, terminal), Vec::<Attention>::new());

    let (second, verdict) = desk.asks(connection, "gpg", Operation::Sign);
    assert!(matches!(verdict, Verdict::Hold(_)), "once means once");
    desk.send(
        terminal,
        decide(second, Decision::For(NonZeroU32::new(900).unwrap())),
    )
    .unwrap();
    assert_eq!(
        desk.asks(connection, "gpg", Operation::Sign).1,
        Verdict::Serve(Outcome::Covered)
    );
    assert_eq!(
        desk.asks(connection, "gpg", Operation::Decrypt).1,
        Verdict::Serve(Outcome::Served(Basis::Default)),
        "decryption was never under the rule"
    );

    let (third, _) = {
        desk.trail.wait(900_000);
        desk.asks(connection, "gpg", Operation::Sign)
    };
    assert_eq!(
        desk.send(terminal, decide(third, Decision::Refuse)),
        Ok(Reply::Done(Effect::Changed))
    );
    assert!(
        attention(&mut desk, terminal).is_empty(),
        "their own refusal is not brought back to them"
    );
}

/// The device is on the workstation and this run needs it; the
/// exposure is for this connection, named when asked for, and gone with it.
#[test]
fn a_tester_lends_the_device_to_one_run() {
    let mut desk = Desk::new(catalogue());
    let workspace = remote("coder", "dev/android");
    let terminal = desk.attend(ClientKind::Terminal, DESKTOP);
    let connect = |acknowledged| Request::Connect {
        remote: workspace.clone(),
        with: vec![name("adb")],
        acknowledged,
        lends: Lends::none(),
    };
    assert_eq!(
        desk.send(terminal, connect(Exposure::NONE)),
        Err(Refusal::ExposureNotAcknowledged {
            capability: name("adb"),
            missing: Exposure::SERVICE,
        }),
        "ADB authenticates nobody, and the request must say so"
    );
    assert_eq!(
        desk.send(terminal, connect(Exposure::SERVICE)),
        Ok(Reply::Done(Effect::Changed))
    );
    let connection = desk.channel_up(&workspace, "linux");
    assert_eq!(
        desk.asks(connection, "adb", Operation::Connect).1,
        Verdict::Serve(Outcome::Served(Basis::Default))
    );
    let row = desk.row(terminal, &workspace, &name("adb"));
    assert_eq!(row.through, Through::Connection(connection));
    assert_eq!(row.exposure, Exposure::SERVICE);

    desk.send(
        terminal,
        Request::Disconnect {
            remote: workspace.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        desk.send(
            terminal,
            Request::Disconnect {
                remote: workspace.clone()
            }
        ),
        Ok(Reply::Done(Effect::Unchanged))
    );
    let next = desk.channel_up(&workspace, "linux");
    assert_eq!(
        desk.asks(next, "adb", Operation::Connect).1,
        Verdict::Refuse(Refusal::NotGranted {
            capability: name("adb"),
            remote: workspace,
        })
    );
}

/// What is reachable from where is one question with one answer,
/// and stopping all of it is one act that survives a restart.
#[test]
fn a_reviewer_sees_what_is_exposed_and_stops_it_in_one_act() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let build = remote("coder", "dev/build");
    let bastion = remote("ssh", "ops@bastion.example");
    for request in [
        granting(
            "gpg",
            Granted::Route(name("coder")),
            Activation::WhileRunning,
            Exposure::NONE,
        ),
        granting(
            "gpg-unrestricted",
            Granted::One(bastion.clone()),
            Activation::OnRequest,
            Exposure::KEY_MANAGEMENT.with(Exposure::SECRET),
        ),
    ] {
        desk.send(interface, request).unwrap();
    }
    let on_build = desk.channel_up(&build, "linux");
    let on_bastion = desk.channel_up(&bastion, "freebsd");
    let connect = |remote: &RemoteId| Request::Connect {
        remote: remote.clone(),
        with: Vec::new(),
        acknowledged: Exposure::NONE,
        lends: Lends::none(),
    };

    let exposed = rows(&mut desk, interface);
    assert_eq!(exposed.len(), 2);
    let unrestricted = desk.row(interface, &bastion, &name("gpg-unrestricted"));
    assert_eq!(
        unrestricted.exposure,
        Exposure::KEY_USE
            .with(Exposure::KEY_MANAGEMENT)
            .with(Exposure::SECRET),
        "the row says what the grant exposes"
    );
    assert!(
        unrestricted
            .decides
            .iter()
            .any(|decides| decides.operation == Operation::Connect && decides.mode == Mode::Confirm)
    );

    assert_eq!(
        desk.send(interface, Request::Pause(Remotes::Every)),
        Ok(Reply::Done(Effect::Changed))
    );
    for row in rows(&mut desk, interface) {
        assert_eq!(row.standing, Standing::Paused);
        assert!(
            row.acts
                .iter()
                .any(|offered| offered.act == Act::Resume && offered.withheld.is_none())
        );
    }
    for (connection, capability) in [(on_build, "gpg"), (on_bastion, "gpg-unrestricted")] {
        assert!(matches!(
            desk.asks(connection, capability, Operation::Sign).1,
            Verdict::Refuse(Refusal::UnknownConnection(_))
        ));
    }
    assert_eq!(desk.send(interface, connect(&build)), Err(Refusal::Paused));
    let Ok(Reply::Status(status)) = desk.send(interface, Request::Status) else {
        unreachable!("status is always answered")
    };
    assert_eq!(status.paused, vec![Remotes::Every]);
    assert_eq!(status.connected, Vec::<RemoteId>::new());

    desk.trail.push(Event::Started {
        version: "0.2.0".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    assert_eq!(
        desk.send(interface, connect(&build)),
        Err(Refusal::Paused),
        "a crash does not resume what the person stopped"
    );
    desk.send(interface, Request::Resume(Remotes::Every))
        .unwrap();
    assert!(
        rows(&mut desk, interface)
            .iter()
            .all(|row| row.standing != Standing::Paused)
    );
}

/// A provisioning script speaks the protocol with nothing but the
/// document it keeps in a repository, and reads everything back as data.
#[test]
fn a_provisioner_imports_a_document_and_reads_the_result_as_data() {
    let mut desk = Desk::new(catalogue());
    assert_eq!(
        desk.greet(PROTOCOL + 1, ClientKind::Command, DESKTOP),
        Err(Refusal::Version {
            core: PROTOCOL,
            client: PROTOCOL + 1
        })
    );
    let (script, welcome) = desk
        .greet(PROTOCOL, ClientKind::Command, DESKTOP)
        .expect("the greeting");
    assert!(matches!(welcome, Reply::Welcome { you, .. } if you == DESKTOP));

    let kept = include_str!("kept-document.json");
    let document: Document = read(kept).expect("the kept document reads");
    assert_eq!(
        desk.send(script, Request::Import(Box::new(document.clone()))),
        Ok(Reply::Changed {
            effect: Effect::Changed,
            held: Vec::new()
        })
    );
    let Ok(Reply::Document(exported)) = desk.send(script, Request::Export) else {
        unreachable!("export is always answered")
    };
    assert_eq!(*exported, document);
    assert_eq!(
        page(&exported),
        kept,
        "export gives back the text that was kept"
    );
    assert_eq!(
        decided_terms(
            &desk.catalogue,
            &desk.configuration,
            &name("gpg"),
            &remote("codespaces", "any-workspace")
        ),
        Some(Terms {
            activation: Activation::WhileRunning,
            setup: Setup::Write,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        })
    );

    let widened = Document {
        grants: vec![hedwig_model::config::GrantEntry {
            grant: grant("gpg-unrestricted", Granted::Route(name("codespaces"))),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        }],
        ..document.clone()
    };
    assert!(matches!(
        desk.send(script, Request::Import(Box::new(widened))),
        Err(Refusal::ExposureNotAcknowledged { .. })
    ));
    assert_eq!(
        desk.configuration,
        Configuration::import(&desk.catalogue, document).unwrap(),
        "a refused import leaves the configuration as it was"
    );

    let Ok(Reply::Status(status)) = desk.send(script, Request::Status) else {
        unreachable!("status is always answered")
    };
    assert_eq!(status.version, "0.2.0");
    assert_eq!(status.attached.len(), 1);
    assert_eq!(status.attached.first().unwrap().kind, ClientKind::Command);
    assert_eq!(status.attention, 0);
}

/// When a remote cannot sign, the row that owns the failure says
/// why, and the channel's own questions reach the person in the same place.
#[test]
#[allow(clippy::too_many_lines, reason = "one workflow, start to finish")]
fn a_keeper_finds_why_a_remote_cannot_sign_and_fixes_it_where_it_shows() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let host = remote("ssh", "dev@new-box");
    desk.send(
        interface,
        granting(
            "gpg",
            Granted::One(host.clone()),
            Activation::OnRequest,
            Exposure::NONE,
        ),
    )
    .unwrap();
    assert_eq!(
        desk.send(
            interface,
            Request::Exercise {
                remote: host.clone(),
                capability: name("gpg")
            }
        ),
        Err(Refusal::NotConnected(host.clone())),
        "and the row withholds the act for the same reason"
    );
    let idle = desk.row(interface, &host, &name("gpg"));
    assert!(idle.acts.iter().any(|offered| {
        offered.act == Act::Exercise
            && offered.withheld == Some(Refusal::NotConnected(host.clone()))
    }));

    desk.send(
        interface,
        Request::Connect {
            remote: host.clone(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    )
    .unwrap();
    let connection = desk.trail.state().connection(&host).unwrap().0;
    let prompt = PromptId(desk.trail.push(Event::Prompted {
        connection,
        kind: PromptKind::UnknownHostKey,
        words: Words::try_from("ED25519 key fingerprint is SHA256:uNiVztksCsDhcc0u9e8B.").unwrap(),
    }));
    assert_eq!(
        desk.row(interface, &host, &name("gpg")).standing,
        Standing::Needs(PromptKind::UnknownHostKey)
    );
    assert!(matches!(
        attention(&mut desk, interface).as_slice(),
        [Attention::Prompt { words, .. }] if words.as_str().contains("SHA256:")
    ));
    desk.send(
        interface,
        Request::Answer {
            prompt,
            answer: Answer::Accept,
        },
    )
    .unwrap();
    assert_eq!(desk.answered, vec![Answer::Accept]);
    assert_eq!(
        desk.send(
            interface,
            Request::Answer {
                prompt,
                answer: Answer::Accept
            }
        ),
        Err(Refusal::UnknownPrompt(prompt))
    );

    desk.trail.push(Event::Observed {
        connection,
        platform: name("linux"),
    });
    // The remote's own agent holds the socket: the capability cannot be
    // carried there, and the row says why.
    let socket = RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap();
    let absent = Finding::PublicKeyAbsent(
        Fingerprint::try_from("07B56DFBBA12BB80FA84939C76F8274EF1651088").unwrap(),
    );
    desk.trail.push(Event::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![Finding::AgentLive(socket.clone()), absent.clone()]),
    });
    assert_eq!(
        desk.row(interface, &host, &name("gpg")).standing,
        Standing::Unready(vec![Finding::AgentLive(socket), absent.clone()])
    );
    // A missing public key is carried and named beside the row.
    desk.trail.push(Event::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![absent.clone()]),
    });
    let row = desk.row(interface, &host, &name("gpg"));
    assert!(!matches!(row.standing, Standing::Unready(_)));
    assert_eq!(row.findings, vec![absent]);

    desk.trail.push(Event::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Ready,
    });
    desk.channel_up(&host, "linux");
    let Ok(Reply::Row(checked)) = desk.send(
        interface,
        Request::Check {
            remote: host.clone(),
            capability: name("gpg"),
        },
    ) else {
        unreachable!("the check is answered with the row")
    };
    assert!(matches!(checked.standing, Standing::Serving(_)));

    // The end-to-end proof is a real use of the key, so it is an explicit
    // act, answered at once; what it proves - that the request arrived - is
    // recorded once the remote's tool has run.
    let exercised = desk.send(
        interface,
        Request::Exercise {
            remote: host.clone(),
            capability: name("gpg"),
        },
    );
    assert_eq!(exercised, Ok(Reply::Done(Effect::Changed)));
    let Some(Event::Exercised {
        proof: Proof::Reached(request),
        ..
    }) = desk.trail.entries.last().map(|entry| entry.event.clone())
    else {
        unreachable!("the exercise reaches the core")
    };
    assert_eq!(
        desk.row(interface, &host, &name("gpg"))
            .last
            .map(|last| last.request.0),
        Some(request.0)
    );
}

/// An administrator on a Windows host is told what that host's
/// own SSH server cannot carry, on the row, in words - not left with a grant
/// that silently does nothing.
#[test]
fn an_administrator_is_told_what_a_windows_remote_cannot_carry() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let host = remote("ssh", "admin@winsrv.example");
    for (capability, acknowledged) in [
        ("gpg", Exposure::NONE),
        ("ssh-agent", Exposure::NONE),
        ("openocd", Exposure::SERVICE),
    ] {
        desk.send(
            interface,
            granting(
                capability,
                Granted::One(host.clone()),
                Activation::OnRequest,
                acknowledged,
            ),
        )
        .unwrap();
    }
    desk.channel_up(&host, "windows");

    let agent = desk.row(interface, &host, &name("ssh-agent"));
    let Standing::Unavailable(refusal) = agent.standing else {
        unreachable!("the platform cannot carry it")
    };
    assert_eq!(
        refusal.to_string(),
        "a windows remote's own SSH server has no way to carry ssh-agent"
    );
    assert!(matches!(
        desk.row(interface, &host, &name("gpg")).standing,
        Standing::Unavailable(Refusal::NeedsRemoteSetup { .. })
    ));
    assert!(matches!(
        desk.row(interface, &host, &name("openocd")).standing,
        Standing::Serving(Binding::Port(_))
    ));

    desk.send(
        interface,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(host.clone())),
            terms: Terms {
                setup: Setup::Write,
                ..terms(Activation::OnRequest, Exposure::NONE)
            },
        }),
    )
    .unwrap();
    assert!(!matches!(
        desk.row(interface, &host, &name("gpg")).standing,
        Standing::Unavailable(_)
    ));
}

/// The person locks the desktop and leaves while a request waits for
/// them. The remote is answered with a refusal now, and the person finds it
/// when they return.
#[test]
fn a_request_left_waiting_when_the_person_leaves_is_refused_not_stranded() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let host = remote("coder", "dev/build");
    desk.send(
        interface,
        granting(
            "gpg-unrestricted",
            Granted::One(host.clone()),
            Activation::OnRequest,
            Exposure::KEY_MANAGEMENT.with(Exposure::SECRET),
        ),
    )
    .unwrap();
    let connection = desk.channel_up(&host, "linux");
    let (request, verdict) = desk.asks(connection, "gpg-unrestricted", Operation::Connect);
    assert_eq!(verdict, Verdict::Hold(Basis::Default));

    desk.send(interface, Request::Presence(Presence::Away))
        .unwrap();
    assert!(desk.trail.state().ask(request).is_none(), "it is settled");

    desk.send(interface, Request::Presence(Presence::Present))
        .unwrap();
    assert_eq!(
        attention(&mut desk, interface),
        vec![Attention::Refused {
            remote: Some(host),
            refusal: Refusal::NobodyReachable(Whereabouts::Away),
            times: 1,
        }]
    );
}

/// First run. Before anything is granted the person is shown what this
/// workstation holds, so the first grant is made in its terms.
#[test]
fn a_keeper_on_first_run_sees_what_the_workstation_holds() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let serial = Serial::try_from("D2760001240103040006123456780000").unwrap();
    let workspace = remote("coder", "dev/build");
    for event in [
        Event::Source {
            capability: name("gpg"),
            health: Health::Sound,
        },
        Event::Source {
            capability: name("adb"),
            health: Health::Failing(Failure::Unreachable),
        },
        Event::Card(Card {
            serial: serial.clone(),
            keys: vec![Held {
                grip: Grip::try_from("64EFB4597F2EB1968F187B7235A461FC48342EC5").unwrap(),
                touch: Some(Touch::Off),
            }],
            pin: Some(SignaturePin::Once),
        }),
        Event::Appeared {
            remote: workspace.clone(),
        },
    ] {
        desk.trail.push(event);
    }
    let Ok(Reply::Workstation(held)) = desk.send(interface, Request::Workstation) else {
        unreachable!("always answered")
    };
    assert_eq!(held.sources.len(), 2);
    assert_eq!(held.cards.first().unwrap().serial, serial);
    assert_eq!(held.running, vec![workspace]);
    assert!(
        matches!(
            attention(&mut desk, interface).as_slice(),
            [Attention::Safeguards(_)]
        ),
        "the card's touch policy being off is said before the first grant"
    );
    assert_eq!(rows(&mut desk, interface), Vec::<Row>::new());
}

/// After a power cycle the workstation's agent is not running. The
/// remote sees a dead socket either way; the person is told which side died.
#[test]
fn a_keeper_is_told_when_it_is_the_workstation_side_that_died() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let host = remote("coder", "dev/build");
    desk.send(
        interface,
        granting(
            "gpg",
            Granted::One(host.clone()),
            Activation::OnRequest,
            Exposure::NONE,
        ),
    )
    .unwrap();
    let connection = desk.channel_up(&host, "linux");
    assert!(matches!(
        desk.row(interface, &host, &name("gpg")).standing,
        Standing::Serving(_)
    ));

    let refusal = Refusal::SourceUnavailable {
        capability: name("gpg"),
        failure: Failure::Unreachable,
    };
    let request = desk.trail.ask(connection, "gpg", Operation::Sign);
    desk.trail.push(Event::Source {
        capability: name("gpg"),
        health: Health::Failing(Failure::Unreachable),
    });
    desk.trail.push(Event::Settled {
        request,
        outcome: Outcome::Refused(refusal.clone()),
    });
    assert_eq!(
        desk.row(interface, &host, &name("gpg")).standing,
        Standing::Unavailable(refusal.clone())
    );
    assert_eq!(
        attention(&mut desk, interface),
        vec![Attention::Refused {
            remote: Some(host.clone()),
            refusal,
            times: 1,
        }]
    );

    desk.trail.push(Event::Source {
        capability: name("gpg"),
        health: Health::Sound,
    });
    assert!(matches!(
        desk.row(interface, &host, &name("gpg")).standing,
        Standing::Serving(_)
    ));
}
