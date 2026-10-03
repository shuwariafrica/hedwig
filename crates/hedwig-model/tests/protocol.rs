//! What a control client may do, and that what a surface is shown is what
//! the core will do.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU8;

use hedwig_model::capability::{Exposure, Lends, Operation, Setup};
use hedwig_model::config::{Accepted, Activation, Change, Configuration, Denial};
use hedwig_model::gate::World;
use hedwig_model::policy::{ConnectionScope, Keys, Mode, Selector};
use hedwig_model::protocol::{Act, Decision, Offered, PROTOCOL, Reply, Request, Row, Through};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::trail::{
    self as trail, ChannelEnd, ClientId, ClientKind, ConnectionId, Entry, Event, Presence,
    PromptId, RequestId, Seq, State, Tick,
};

mod support;
use support::desk::Desk;
use support::{DESKTOP, OVER_SSH, catalogue, corpus, grant, name, remote, terms};

fn permit(desk: &Desk, client: ClientId, request: &Request) -> Result<(), Refusal> {
    let state = desk.trail.state();
    World {
        catalogue: &desk.catalogue,
        configuration: &desk.configuration,
        state: &state,
    }
    .permit(client, request)
}

fn give(desk: &mut Desk, client: ClientId, id: &str, remotes: Granted, acknowledged: Exposure) {
    desk.send(
        client,
        Request::Change(Change::Grant {
            grant: grant(id, remotes),
            terms: terms(Activation::OnRequest, acknowledged),
        }),
    )
    .expect("the grant is accepted");
}

#[test]
fn nothing_is_answered_before_the_greeting() {
    let desk = Desk::new(catalogue());
    let stranger = ClientId(Seq(77));
    for request in corpus::requests() {
        let expected = match request {
            Request::Hello { .. } => Ok(()),
            _ => Err(Refusal::NotGreeted),
        };
        assert_eq!(permit(&desk, stranger, &request), expected, "{request:?}");
    }
    assert_eq!(
        permit(
            &desk,
            stranger,
            &Request::Hello {
                protocol: PROTOCOL + 1,
                kind: ClientKind::Interface,
                attends: Remotes::Every,
            }
        ),
        Err(Refusal::Version {
            core: PROTOCOL,
            client: PROTOCOL + 1
        })
    );
}

/// Only a client a person is at may decide, answer or report presence; a
/// script may do everything else.
#[test]
fn only_an_attending_client_answers_for_the_person() {
    let mut desk = Desk::new(catalogue());
    let script = desk.attend(ClientKind::Command, DESKTOP);
    let terminal = desk.attend(ClientKind::Terminal, OVER_SSH);
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let request = RequestId(Seq(900));
    let prompt = PromptId(Seq(901));
    let personal = [
        Request::Decide {
            request,
            decision: Decision::Once,
        },
        Request::Answer {
            prompt,
            answer: hedwig_model::protocol::Answer::Decline,
        },
        Request::Presence(Presence::Away),
    ];
    for asked in &personal {
        assert_eq!(permit(&desk, script, asked), Err(Refusal::NotAttending));
    }
    for client in [terminal, interface] {
        assert_eq!(
            permit(&desk, client, personal.first().unwrap()),
            Err(Refusal::UnknownRequest(request))
        );
        assert_eq!(
            permit(&desk, client, personal.get(1).unwrap()),
            Err(Refusal::UnknownPrompt(prompt))
        );
        assert_eq!(permit(&desk, client, personal.get(2).unwrap()), Ok(()));
    }
    for open in [
        Request::Status,
        Request::Exposure,
        Request::Attention,
        Request::Catalogue,
        Request::Export,
        Request::Pause(Remotes::Every),
        Request::Resume(Remotes::Every),
        Request::Stop,
    ] {
        assert_eq!(permit(&desk, script, &open), Ok(()));
    }
}

#[test]
fn connecting_is_refused_for_each_thing_that_would_make_it_unsafe() {
    let mut desk = Desk::new(catalogue());
    let client = desk.attend(ClientKind::Terminal, DESKTOP);
    let host = remote("ssh", "dev@box");
    let connect = |remote: &RemoteId, with: &[&str], acknowledged| Request::Connect {
        remote: remote.clone(),
        with: with.iter().map(|id| name(id)).collect(),
        acknowledged,
        lends: Lends::none(),
    };
    assert_eq!(
        permit(
            &desk,
            client,
            &connect(&remote("gitpod", "x"), &[], Exposure::NONE)
        ),
        Err(Refusal::UnknownRoute(name("gitpod")))
    );
    assert_eq!(
        permit(&desk, client, &connect(&host, &["gpgg"], Exposure::NONE)),
        Err(Refusal::UnknownCapability(name("gpgg")))
    );
    assert_eq!(
        permit(
            &desk,
            client,
            &connect(&host, &["playwright"], Exposure::SERVICE)
        ),
        Err(Refusal::CapabilityIncomplete {
            capability: name("playwright")
        })
    );
    assert_eq!(
        permit(
            &desk,
            client,
            &connect(&host, &["gpg", "openocd"], Exposure::NONE)
        ),
        Err(Refusal::ExposureNotAcknowledged {
            capability: name("openocd"),
            missing: Exposure::SERVICE
        })
    );
    assert_eq!(
        permit(
            &desk,
            client,
            &connect(&host, &["gpg", "openocd"], Exposure::SERVICE)
        ),
        Ok(())
    );

    desk.send(
        client,
        Request::Change(Change::Deny(Denial {
            capability: Selector::Only(name("openocd")),
            remotes: Remotes::One(host.clone()),
        })),
    )
    .unwrap();
    assert_eq!(
        permit(
            &desk,
            client,
            &connect(&host, &["openocd"], Exposure::SERVICE)
        ),
        Err(Refusal::NotGranted {
            capability: name("openocd"),
            remote: host.clone()
        })
    );
    desk.send(client, Request::Pause(Remotes::Route(name("ssh"))))
        .unwrap();
    assert_eq!(
        permit(&desk, client, &connect(&host, &[], Exposure::NONE)),
        Err(Refusal::Paused)
    );
}

#[test]
fn a_rule_on_a_connection_names_a_live_connection_and_what_it_carries() {
    let mut desk = Desk::new(catalogue());
    let client = desk.attend(ClientKind::Interface, DESKTOP);
    let host = remote("coder", "dev/build");
    give(
        &mut desk,
        client,
        "gpg",
        Granted::One(host.clone()),
        Exposure::NONE,
    );
    give(
        &mut desk,
        client,
        "adb",
        Granted::One(host.clone()),
        Exposure::SERVICE,
    );
    let connection = desk.channel_up(&host, "linux");
    let rule = |connection, capability: Option<&str>, operation| Request::Rule {
        connection,
        scope: ConnectionScope {
            capability: capability.map_or(Selector::Every, |id| Selector::Only(name(id))),
            operation,
            key: Keys::Every,
        },
        mode: Some(Mode::Confirm),
    };
    let gone = ConnectionId(Seq(999));
    assert_eq!(
        permit(&desk, client, &rule(gone, None, Selector::Every)),
        Err(Refusal::UnknownConnection(gone))
    );
    assert_eq!(
        permit(
            &desk,
            client,
            &rule(connection, Some("ssh-agent"), Selector::Every)
        ),
        Err(Refusal::NotGranted {
            capability: name("ssh-agent"),
            remote: host.clone()
        })
    );
    assert_eq!(
        permit(
            &desk,
            client,
            &rule(connection, Some("adb"), Selector::Only(Operation::Decrypt))
        ),
        Err(Refusal::OperationNotInDialect {
            capability: name("adb"),
            operation: Operation::Decrypt
        })
    );
    for accepted in [
        rule(connection, None, Selector::Every),
        rule(connection, None, Selector::Only(Operation::Sign)),
        rule(connection, Some("gpg"), Selector::Only(Operation::Sign)),
        rule(connection, Some("adb"), Selector::Every),
    ] {
        assert_eq!(permit(&desk, client, &accepted), Ok(()));
    }
}

#[test]
fn a_check_or_an_exercise_is_of_something_granted() {
    let mut desk = Desk::new(catalogue());
    let client = desk.attend(ClientKind::Interface, DESKTOP);
    let host = remote("coder", "dev/build");
    let of = |capability: &str| {
        (
            Request::Check {
                remote: host.clone(),
                capability: name(capability),
            },
            Request::Exercise {
                remote: host.clone(),
                capability: name(capability),
            },
        )
    };
    for (capability, refusal) in [
        ("gpgg", Refusal::UnknownCapability(name("gpgg"))),
        (
            "gpg",
            Refusal::NotGranted {
                capability: name("gpg"),
                remote: host.clone(),
            },
        ),
    ] {
        let (check, exercise) = of(capability);
        assert_eq!(permit(&desk, client, &check), Err(refusal.clone()));
        assert_eq!(permit(&desk, client, &exercise), Err(refusal));
    }

    give(
        &mut desk,
        client,
        "gpg",
        Granted::One(host.clone()),
        Exposure::NONE,
    );
    let (check, exercise) = of("gpg");
    assert_eq!(permit(&desk, client, &check), Ok(()));
    assert_eq!(
        permit(&desk, client, &exercise),
        Err(Refusal::NotConnected(host.clone()))
    );
    desk.channel_up(&host, "linux");
    assert_eq!(permit(&desk, client, &exercise), Ok(()));

    desk.trail.push(Event::Paused {
        scope: Remotes::Every,
        by: client,
    });
    assert_eq!(permit(&desk, client, &exercise), Err(Refusal::Paused));
}

/// The request a surface sends for each act on a row, built here from the
/// row alone.
fn request_for(row: &Row, offered: &Offered) -> Request {
    let remote = || row.remote.clone().expect("an act on a remote");
    match offered.act {
        Act::Connect => Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
        Act::Disconnect => Request::Disconnect { remote: remote() },
        Act::Pause => Request::Pause(Remotes::One(remote())),
        Act::Resume => Request::Resume(Remotes::One(remote())),
        Act::Check => Request::Check {
            remote: remote(),
            capability: row.capability.clone(),
        },
        Act::Exercise => Request::Exercise {
            remote: remote(),
            capability: row.capability.clone(),
        },
        Act::Revoke => match &row.through {
            Through::Grant(grant) => Request::Change(Change::Revoke(grant.clone())),
            Through::Start { .. } | Through::Connection(_) => {
                unreachable!("only the person's own grant is revoked")
            }
        },
        Act::Deny | Act::Accept => {
            let Through::Start { grant, .. } = &row.through else {
                unreachable!("only a grant the organisation starts is denied or accepted here")
            };
            Request::Change(if offered.act == Act::Deny {
                Change::Deny(Denial {
                    capability: Selector::Only(grant.capability.clone()),
                    remotes: grant.remotes.clone().into(),
                })
            } else {
                Change::Accept {
                    grant: grant.clone(),
                    accepted: Accepted {
                        setup: Setup::Inspect,
                        acknowledged: row.exposure.common(Exposure::ACKNOWLEDGED),
                        lends: Lends::none(),
                    },
                }
            })
        }
    }
}

/// One policy: every act a row shows as offered is accepted when sent, and
/// every act it shows as withheld is refused with the refusal the row
/// carried - in every state a row can be in.
#[test]
fn what_a_row_offers_is_what_the_core_accepts() {
    let mut desk = Desk::new(catalogue());
    let client = desk.attend(ClientKind::Interface, DESKTOP);
    let build = remote("coder", "dev/build");
    let bastion = remote("ssh", "ops@bastion.example");
    let windows = remote("ssh", "admin@winsrv.example");
    give(
        &mut desk,
        client,
        "gpg",
        Granted::Route(name("coder")),
        Exposure::NONE,
    );
    give(
        &mut desk,
        client,
        "adb",
        Granted::Route(name("codespaces")),
        Exposure::SERVICE,
    );
    give(
        &mut desk,
        client,
        "gpg",
        Granted::One(bastion.clone()),
        Exposure::NONE,
    );
    give(
        &mut desk,
        client,
        "ssh-agent",
        Granted::One(windows.clone()),
        Exposure::NONE,
    );

    let mut seen = std::collections::BTreeSet::new();
    let mut withheld = 0;
    let mut check = |desk: &Desk| {
        let state = desk.trail.state();
        let world = World {
            catalogue: &desk.catalogue,
            configuration: &desk.configuration,
            state: &state,
        };
        for row in world.rows(client, desk.trail.tick()) {
            for offered in &row.acts {
                let answer = world.permit(client, &request_for(&row, offered));
                assert_eq!(answer.err(), offered.withheld, "{row:?}");
                seen.insert(offered.act);
                withheld += usize::from(offered.withheld.is_some());
            }
        }
    };

    check(&desk);
    desk.channel_up(&build, "linux");
    desk.channel_up(&windows, "windows");
    check(&desk);
    desk.send(client, Request::Pause(Remotes::One(build.clone())))
        .unwrap();
    check(&desk);
    desk.send(client, Request::Pause(Remotes::Every)).unwrap();
    check(&desk);
    desk.send(client, Request::Resume(Remotes::Every)).unwrap();
    let connection = desk.channel_up(&bastion, "openbsd");
    desk.trail.push(Event::Down {
        connection,
        end: ChannelEnd::ForwardRefused,
    });
    check(&desk);

    assert_eq!(seen.len(), 7, "every act was shown in some state");
    assert!(withheld > 0, "and some were withheld");
}

#[test]
fn a_row_is_one_capability_on_one_remote_or_a_grant_still_waiting() {
    let mut desk = Desk::new(catalogue());
    let client = desk.attend(ClientKind::Interface, DESKTOP);
    give(
        &mut desk,
        client,
        "gpg",
        Granted::Route(name("coder")),
        Exposure::NONE,
    );
    give(
        &mut desk,
        client,
        "gpg",
        Granted::Route(name("codespaces")),
        Exposure::NONE,
    );
    let rows = |desk: &Desk| {
        let state = desk.trail.state();
        World {
            catalogue: &desk.catalogue,
            configuration: &desk.configuration,
            state: &state,
        }
        .rows(client, desk.trail.tick())
    };
    let waiting = rows(&desk);
    assert_eq!(waiting.len(), 2);
    assert!(waiting.iter().all(|row| row.remote.is_none()));
    assert!(waiting.iter().all(|row| row.decides.is_empty()));
    assert!(waiting.iter().all(|row| {
        row.acts
            == vec![Offered {
                act: Act::Revoke,
                withheld: None,
            }]
    }));

    let build = remote("coder", "dev/build");
    desk.trail.push(Event::Appeared {
        remote: build.clone(),
    });
    let seen = rows(&desk);
    assert_eq!(seen.len(), 2, "the coder grant now has a remote to show");
    let placed: Vec<_> = seen.iter().filter_map(|row| row.remote.clone()).collect();
    assert_eq!(placed, vec![build]);
    let on_build = seen.iter().find(|row| row.remote.is_some()).unwrap();
    assert_eq!(
        on_build
            .decides
            .iter()
            .map(|decides| (decides.operation, decides.mode))
            .collect::<Vec<_>>(),
        vec![
            (Operation::Connect, Mode::Notify),
            (Operation::Authenticate, Mode::Notify),
            (Operation::Sign, Mode::Notify),
            (Operation::Decrypt, Mode::Notify),
        ]
    );
}

#[test]
fn status_is_nothing_before_the_core_has_started_and_typed_after() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let state = State::default();
    let world = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    assert_eq!(world.status(ClientId(Seq(0)), Tick(0)), None);

    let mut desk = Desk::new(catalogue.clone());
    let terminal = desk.attend(ClientKind::Terminal, OVER_SSH);
    let viewer = desk.attend(ClientKind::Viewer, DESKTOP);
    let Ok(Reply::Status(status)) = desk.send(terminal, Request::Status) else {
        unreachable!("status is always answered")
    };
    assert_eq!(status.origin, DESKTOP, "where the core itself runs");
    assert_eq!(
        status.attached.first().unwrap().origin,
        OVER_SSH,
        "and where each client came from: shown, never refused"
    );
    assert_eq!(
        status.attached.first().unwrap().presence,
        Some(Presence::Present)
    );
    // A viewer is never asked anything, so nothing is said of its presence.
    let listed = status
        .attached
        .iter()
        .find(|attached| attached.client == viewer)
        .unwrap();
    assert_eq!((listed.kind, listed.presence), (ClientKind::Viewer, None));
}

/// Activity is read a page at a time, newest first, for one remote or all.
/// One remote's pages, walked back to the start, are what the trail reads as
/// that remote's - its connections, their requests and what settled them -
/// and nothing of another remote's; every remote's are the whole trail.
#[test]
fn activity_is_paged_from_the_newest_backwards() {
    let mut desk = Desk::new(catalogue());
    let client = desk.attend(ClientKind::Interface, DESKTOP);
    let build = remote("coder", "dev/build");
    let other = remote("coder", "ops/db");
    give(
        &mut desk,
        client,
        "gpg",
        Granted::Route(name("coder")),
        Exposure::NONE,
    );
    let on_build = desk.channel_up(&build, "linux");
    let on_other = desk.channel_up(&other, "linux");
    for _ in 0..5 {
        desk.asks(on_build, "gpg", Operation::Sign);
        desk.asks(on_other, "gpg", Operation::Decrypt);
    }
    let walked = |desk: &mut Desk, remote: &Selector<RemoteId>| {
        let mut pages: Vec<Vec<Entry>> = Vec::new();
        let mut before = None;
        loop {
            let Ok(Reply::Activity(entries)) = desk.send(
                client,
                Request::Activity {
                    remote: remote.clone(),
                    before,
                    limit: NonZeroU8::new(3).unwrap(),
                },
            ) else {
                unreachable!("activity is always answered")
            };
            let Some(first) = entries.first() else { break };
            assert!(entries.len() <= 3);
            assert!(entries.is_sorted_by_key(|entry| entry.seq));
            before = Some(first.seq);
            pages.push(entries);
        }
        pages.into_iter().rev().flatten().collect::<Vec<Entry>>()
    };
    let sets = desk.configuration.sets(&desk.catalogue);
    let theirs: Vec<Entry> = trail::about(&State::default(), &desk.trail.entries, &build, &sets)
        .cloned()
        .collect();
    assert_eq!(walked(&mut desk, &Selector::Only(build.clone())), theirs);
    assert_eq!(
        theirs
            .iter()
            .filter(|entry| matches!(&entry.event, Event::Asked { .. }))
            .count(),
        5
    );
    assert!(theirs.iter().all(|entry| !matches!(
        &entry.event,
        Event::Asked { connection, .. } if *connection == on_other
    )));
    assert!(theirs.iter().all(|entry| !matches!(
        &entry.event,
        Event::Opening { remote, .. } if *remote == other
    )));
    assert!(
        theirs
            .iter()
            .any(|entry| matches!(&entry.event, Event::Settled { .. }))
    );
    assert_eq!(walked(&mut desk, &Selector::Every), desk.trail.entries);
}

/// Every refusal is a sentence for the person: one each, none of them a
/// code, and none of them the same as another.
#[test]
fn every_refusal_is_worded_for_the_person() {
    let sentences: Vec<String> = corpus::refusals().iter().map(ToString::to_string).collect();
    let distinct: std::collections::BTreeSet<&String> = sentences.iter().collect();
    assert_eq!(distinct.len(), sentences.len());
    for sentence in &sentences {
        assert!(sentence.len() > 12, "{sentence}");
        assert!(!sentence.contains(['{', '}', '_']), "{sentence}");
    }
    assert_eq!(
        Refusal::ExposureNotAcknowledged {
            capability: name("licence-server"),
            missing: Exposure::SERVICE.with(Exposure::NETWORK),
        }
        .to_string(),
        "granting licence-server exposes service, network, and the grant does not name it"
    );
    assert_eq!(
        Refusal::NotGranted {
            capability: name("adb"),
            remote: remote("coder", "dev/build"),
        }
        .to_string(),
        "adb is not granted to dev/build (coder)"
    );
}

/// What the pipe's reader does with bytes that are not a message: the
/// decoder's account becomes the refusal's words.
#[test]
fn bytes_that_are_not_a_message_are_refused_with_the_decoders_account() {
    let error = hedwig_model::wire::read::<hedwig_model::protocol::ToCore>(
        r#"{"id":1,"request":"reboot"}"#,
    )
    .expect_err("not a request");
    assert_eq!(
        Refusal::Malformed(error.to_string()).to_string(),
        "the message is not valid: request has \"reboot\", which is not known here"
    );
}
