//! The trail is what happened; the state and the attention are folded from
//! it and from nothing else.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::{NonZeroU8, NonZeroU32};

use hedwig_model::capability::Operation;
use hedwig_model::config::{Catalogue, Change, Configuration};
use hedwig_model::gate::World;
use hedwig_model::protocol::{Attention, Needs, Proof, Topic};
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::{Granted, RemoteId, Remotes, Sets};
use hedwig_model::setting::{Burst, Threshold, Volume};
use hedwig_model::text::{Grip, Mark, Serial, Words};
use hedwig_model::trail::{
    Breakdown, Card, ChannelEnd, ClientId, ClientKind, ConnectionId, Entry, Event, Failure,
    Finding, Gave, Given, Health, Held, Item, Outcome, Presence, PromptId, PromptKind, Readiness,
    Seq, SignaturePin, State, Store, Touch,
};
use hedwig_model::wire::{line, read};

mod support;
use support::{DESKTOP, OVER_SSH, Trail, catalogue, corpus, granting, name, remote};

/// What needs the person, as a client that did none of it is told.
fn needs(catalogue: &Catalogue, configuration: &Configuration, trail: &Trail) -> Vec<Needs> {
    let state = trail.state();
    World {
        catalogue,
        configuration,
        state: &state,
    }
    .attention(ClientId(Seq(0)), trail.tick())
}

fn attention(
    catalogue: &Catalogue,
    configuration: &Configuration,
    trail: &Trail,
) -> Vec<Attention> {
    needs(catalogue, configuration, trail)
        .into_iter()
        .map(|needs| needs.attention)
        .collect()
}

fn volumes(catalogue: &Catalogue, configuration: &Configuration, trail: &Trail) -> Vec<Volume> {
    needs(catalogue, configuration, trail)
        .into_iter()
        .map(|needs| needs.volume)
        .collect()
}

/// Folding is the same whether it is done at once or entry by entry, which
/// is what lets the core keep a state and append to a file.
#[test]
fn folding_a_prefix_and_applying_the_rest_equals_folding_it_all() {
    let entries = corpus::entries();
    let whole = State::fold(&entries);
    for cut in [0, 1, entries.len() / 3, entries.len() / 2, entries.len()] {
        let (before, after) = entries.split_at(cut);
        let mut state = State::fold(before);
        for entry in after {
            state.apply(entry);
        }
        assert_eq!(state, whole, "cut at {cut}");
    }
}

/// The trail at rest is one entry per line; reading the file back and
/// folding it gives the state the core held.
#[test]
fn a_trail_read_back_from_its_lines_folds_to_the_same_state() {
    let entries = corpus::entries();
    let file: String = entries.iter().map(|entry| line(entry) + "\n").collect();
    let read_back: Vec<Entry> = file
        .lines()
        .map(|text| read(text).expect("an entry"))
        .collect();
    assert_eq!(read_back, entries);
    assert_eq!(State::fold(&read_back), State::fold(&entries));
}

/// A run ends everything that was live in it. What the person paused stays
/// paused: a core that crashed and came back must not resume exposure they
/// had stopped.
#[test]
fn a_new_run_keeps_what_the_person_stopped_and_drops_what_was_live() {
    let host = remote("coder", "dev/build");
    let mut trail = Trail::started();
    let by = trail.attach(ClientKind::Interface, DESKTOP);
    let connection = trail.open(&host, "linux");
    trail.ask(connection, "gpg", Operation::Sign);
    trail.push(Event::Paused {
        scope: Remotes::One(host.clone()),
        by,
    });
    trail.push(Event::Appeared {
        remote: host.clone(),
    });
    let before = trail.state();
    assert!(before.reachable(&host, &Sets::NONE));
    assert!(before.connection(&host).is_some());
    assert!(before.paused(&host, &Sets::NONE));

    trail.push(Event::Started {
        version: "0.2.1".to_owned(),
        origin: OVER_SSH,
        after: None,
    });
    let after = trail.state();
    assert!(!after.reachable(&host, &Sets::NONE));
    assert!(after.surface(by).is_none());
    assert!(after.connection(&host).is_none());
    assert!(after.link(connection).is_none());
    assert!(
        after.paused(&host, &Sets::NONE),
        "a pause survives a restart"
    );
    assert!(!after.paused(&remote("coder", "ops/db"), &Sets::NONE));

    trail.push(Event::Resumed {
        scope: Remotes::One(host.clone()),
        by,
    });
    assert!(!trail.state().paused(&host, &Sets::NONE));
}

#[test]
fn identifiers_are_the_entries_that_created_them() {
    let host = remote("coder", "dev/build");
    let mut trail = Trail::started();
    let client = trail.attach(ClientKind::Terminal, OVER_SSH);
    let connection = trail.open(&host, "linux");
    let request = trail.ask(connection, "gpg", Operation::Sign);
    let state = trail.state();
    assert_eq!(state.surface(client).unwrap().origin, OVER_SSH);
    assert_eq!(state.link(connection).unwrap().remote, host);
    assert_eq!(state.connection(&host).unwrap().0, connection);
    assert_eq!(state.ask(request).unwrap().operation, Operation::Sign);
    assert!(!state.ask(request).unwrap().held);
    assert!(client.0 < connection.0 && connection.0 < request.0);
}

/// A held request and a channel's prompt are attention until they are
/// settled, and both interrupt.
#[test]
fn a_held_request_and_a_prompt_need_the_person_until_they_are_settled() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let host = remote("coder", "dev/build");
    let mut trail = Trail::started();
    let by = trail.attach(ClientKind::Terminal, OVER_SSH);
    let connection = trail.open(&host, "linux");

    let request = trail.ask(connection, "gpg", Operation::Sign);
    assert!(
        attention(&catalogue, &configuration, &trail).is_empty(),
        "a request not held needs nobody"
    );
    trail.push(Event::Held { request });
    let prompt = PromptId(trail.push(Event::Prompted {
        connection,
        kind: PromptKind::Challenge,
        words: Words::try_from("Verification code:").unwrap(),
    }));

    let raised = attention(&catalogue, &configuration, &trail);
    assert_eq!(raised.len(), 2);
    assert_eq!(
        volumes(&catalogue, &configuration, &trail),
        [Volume::Interrupts, Volume::Interrupts]
    );
    assert!(raised.iter().all(|item| item.item().is_none()));
    assert!(matches!(
        raised.first(),
        Some(Attention::Request { request: held, remote, .. }) if *held == request && *remote == host
    ));
    assert!(matches!(
        raised.get(1),
        Some(Attention::Prompt { prompt: asked, kind: PromptKind::Challenge, .. }) if *asked == prompt
    ));

    trail.push(Event::Settled {
        request,
        outcome: Outcome::Allowed(by),
    });
    trail.push(Event::Answered {
        prompt,
        by: Some(Gave {
            client: by,
            given: Given::Text,
        }),
    });
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        Vec::<Attention>::new()
    );
}

/// A remote that failed readiness is raised once, on its row; being made
/// ready clears it, and so does the person putting it away.
#[test]
fn failed_readiness_is_raised_until_it_passes_or_is_put_away() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let host = remote("coder", "dev/build");
    let mut trail = Trail::started();
    let by = trail.attach(ClientKind::Interface, DESKTOP);
    let connection = trail.open(&host, "linux");
    let unready = |trail: &mut Trail| {
        trail.push(Event::Checked {
            connection,
            capability: name("gpg"),
            readiness: Readiness::Unready(vec![Finding::SigningKeyUnset, Finding::AgentAutostarts]),
        });
    };

    unready(&mut trail);
    let raised = attention(&catalogue, &configuration, &trail);
    assert_eq!(
        raised,
        vec![Attention::Unready {
            remote: host.clone(),
            capability: name("gpg"),
            findings: vec![Finding::SigningKeyUnset, Finding::AgentAutostarts],
        }]
    );
    assert_eq!(
        volumes(&catalogue, &configuration, &trail),
        [Volume::Announced]
    );

    trail.push(Event::PutAway {
        item: raised.first().unwrap().item().unwrap(),
        by,
    });
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        Vec::<Attention>::new()
    );

    unready(&mut trail);
    assert_eq!(
        attention(&catalogue, &configuration, &trail).len(),
        1,
        "a failure after it was put away is a new one"
    );
    trail.push(Event::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Ready,
    });
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        Vec::<Attention>::new()
    );
}

/// A channel that stopped for something only the person can fix says so; one
/// they closed, or whose workspace stopped, does not.
#[test]
fn a_channel_that_stopped_needing_the_person_is_raised() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let host = remote("ssh", "ops@bastion.example");
    for (end, raised) in [
        (ChannelEnd::Closed, false),
        (ChannelEnd::RemoteGone, false),
        (ChannelEnd::Needs(PromptKind::Password), true),
        (
            ChannelEnd::HostKeyChanged(Mark::try_from("SHA256:abc").unwrap()),
            true,
        ),
        (ChannelEnd::Declined(PromptKind::UnknownHostKey), true),
        (
            ChannelEnd::Unauthenticated(Words::try_from("publickey").unwrap()),
            true,
        ),
        (ChannelEnd::RouteNotSignedIn, true),
        (ChannelEnd::ClientAbsent, true),
        // What comes back by itself is on the row and needs nobody.
        (ChannelEnd::ForwardRefused, false),
        (
            ChannelEnd::Exited {
                status: 255,
                last: None,
            },
            false,
        ),
        (ChannelEnd::NothingCarried, false),
        (ChannelEnd::Slept, false),
        (ChannelEnd::Reshaped, false),
    ] {
        let mut trail = Trail::started();
        let by = trail.attach(ClientKind::Interface, DESKTOP);
        let connection = trail.open(&host, "linux");
        trail.push(Event::Down {
            connection,
            end: end.clone(),
        });
        let items = attention(&catalogue, &configuration, &trail);
        if raised {
            assert_eq!(
                items,
                vec![Attention::Stopped {
                    remote: host.clone(),
                    end
                }]
            );
            trail.push(Event::PutAway {
                item: Item::Stopped(host.clone()),
                by,
            });
            assert_eq!(
                attention(&catalogue, &configuration, &trail),
                Vec::<Attention>::new()
            );
            trail.open(&host, "linux");
            assert_eq!(
                attention(&catalogue, &configuration, &trail),
                Vec::<Attention>::new()
            );
        } else {
            assert!(items.is_empty(), "{end:?}");
        }
    }
}

/// A burst is per remote, counted inside the window the person set.
/// Putting it away starts the count again; with no threshold set nothing is
/// counted.
#[test]
fn a_burst_from_one_remote_is_raised_once_per_threshold() {
    let catalogue = catalogue();
    let host = remote("coder", "dev/build");
    let quiet = remote("coder", "ops/db");
    let mut configuration = granting(&catalogue, &[("gpg", Granted::Route(name("coder")))]);
    let mut trail = Trail::started();
    let by = trail.attach(ClientKind::Interface, DESKTOP);
    let connection = trail.open(&host, "linux");
    let other = trail.open(&quiet, "linux");
    let sign = |trail: &mut Trail, connection: ConnectionId, times: usize| {
        for _ in 0..times {
            trail.wait(100);
            trail.ask(connection, "gpg", Operation::Sign);
        }
    };

    sign(&mut trail, connection, 40);
    assert!(
        attention(&catalogue, &configuration, &trail).is_empty(),
        "no threshold is set, so nothing is a burst"
    );
    configuration
        .apply(
            &catalogue,
            Change::Burst {
                remotes: Remotes::Every,
                threshold: Some(Threshold::At(Burst {
                    requests: NonZeroU8::new(20).unwrap(),
                    seconds: NonZeroU32::new(60).unwrap(),
                })),
            },
        )
        .unwrap();
    sign(&mut trail, other, 19);
    let raised = attention(&catalogue, &configuration, &trail);
    assert_eq!(
        raised,
        vec![Attention::Burst {
            remote: host.clone(),
            requests: 40
        }]
    );
    assert_eq!(
        volumes(&catalogue, &configuration, &trail),
        [Volume::Interrupts]
    );

    trail.push(Event::PutAway {
        item: Item::Burst(host.clone()),
        by,
    });
    sign(&mut trail, connection, 19);
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        Vec::<Attention>::new()
    );
    sign(&mut trail, connection, 1);
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        vec![Attention::Burst {
            remote: host.clone(),
            requests: 20
        }]
    );

    trail.wait(60_000);
    assert!(
        attention(&catalogue, &configuration, &trail).is_empty(),
        "the window has passed"
    );

    // The count is kept for at most 255 requests, the most a threshold can ask.
    sign(&mut trail, connection, 600);
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        vec![Attention::Burst {
            remote: host,
            requests: 255
        }]
    );
}

/// A card whose keys can be used with nobody touching it is said once,
/// and said again only if what the card enforces changes.
#[test]
fn a_card_that_needs_no_touch_is_raised_once_per_change() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let serial = Serial::try_from("D2760001240103040006123456780000").unwrap();
    let held = |grip: &str, touch| Held {
        grip: Grip::try_from(grip).unwrap(),
        touch: Some(touch),
    };
    let card = |sign, authenticate| {
        Event::Card(Card {
            serial: serial.clone(),
            keys: vec![
                held("64EFB4597F2EB1968F187B7235A461FC48342EC5", sign),
                held("1D3AA6A1A0F4C9B92A3B5F07E6E0D0C3D4E5F601", Touch::On),
                held("9A8B7C6D5E4F30211203F4E5D6C7B8A9F0E1D2C3", authenticate),
            ],
            pin: Some(SignaturePin::Once),
        })
    };
    let mut trail = Trail::started();
    let by = trail.attach(ClientKind::Interface, DESKTOP);

    trail.push(card(Touch::On, Touch::On));
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        Vec::<Attention>::new()
    );

    trail.push(card(Touch::Off, Touch::On));
    let raised = attention(&catalogue, &configuration, &trail);
    assert!(matches!(
        raised.as_slice(),
        [Attention::Safeguards(card)] if card.leaves_use_unobserved()
    ));
    trail.push(Event::PutAway {
        item: Item::Safeguards(serial.clone()),
        by,
    });
    trail.push(card(Touch::Off, Touch::On));
    assert!(
        attention(&catalogue, &configuration, &trail).is_empty(),
        "the same observation again is not news"
    );
    trail.push(card(Touch::Off, Touch::Off));
    assert_eq!(attention(&catalogue, &configuration, &trail).len(), 1);
}

/// A card read again keeps what it said of a key where the reading leaves it
/// unsaid, since scdaemon reached another card first; what it says anew
/// replaces it, and a key it no longer lists is gone. Its notice is not raised
/// again for a reading that said nothing new.
#[test]
fn a_card_read_again_keeps_what_it_said_where_the_reading_is_silent() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let serial = Serial::try_from("D2760001240103040006123456780000").unwrap();
    let sign = Grip::try_from("64EFB4597F2EB1968F187B7235A461FC48342EC5").unwrap();
    let auth = Grip::try_from("9A8B7C6D5E4F30211203F4E5D6C7B8A9F0E1D2C3").unwrap();
    let reading = |keys: &[(&Grip, Option<Touch>)], pin| Card {
        serial: serial.clone(),
        keys: keys
            .iter()
            .map(|(grip, touch)| Held {
                grip: (*grip).clone(),
                touch: *touch,
            })
            .collect(),
        pin,
    };
    let said = reading(
        &[(&sign, Some(Touch::Off)), (&auth, Some(Touch::On))],
        Some(SignaturePin::Once),
    );
    let silent = reading(&[(&sign, None), (&auth, None)], None);
    assert_eq!(
        said.read_again(&silent),
        said,
        "a silent reading changes nothing"
    );
    assert_eq!(
        silent.read_again(&said),
        said,
        "what is said replaces what was not"
    );
    let anew = reading(&[(&sign, Some(Touch::On)), (&auth, None)], None);
    assert_eq!(
        said.read_again(&anew),
        reading(
            &[(&sign, Some(Touch::On)), (&auth, Some(Touch::On))],
            Some(SignaturePin::Once)
        )
    );
    assert_eq!(
        said.read_again(&reading(&[(&sign, None)], None)),
        reading(&[(&sign, Some(Touch::Off))], Some(SignaturePin::Once)),
        "a key the card no longer lists is gone"
    );

    let mut trail = Trail::started();
    let by = trail.attach(ClientKind::Interface, DESKTOP);
    trail.push(Event::Card(said.clone()));
    assert_eq!(attention(&catalogue, &configuration, &trail).len(), 1);
    trail.push(Event::PutAway {
        item: Item::Safeguards(serial.clone()),
        by,
    });
    trail.push(Event::Card(silent));
    trail.push(Event::Card(said));
    assert!(
        attention(&catalogue, &configuration, &trail).is_empty(),
        "read silent and then the same again, the card has said nothing new"
    );
}

/// A refusal the person did not make themselves is shown with its
/// reason, counted, and kept across a restart until they put it away.
#[test]
fn a_refusal_is_visible_with_its_reason_until_it_is_put_away() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let host = remote("coder", "dev/build");
    let mut trail = Trail::started();
    let by = trail.attach(ClientKind::Interface, DESKTOP);
    let connection = trail.open(&host, "linux");

    for _ in 0..3 {
        let request = trail.ask(connection, "gpg", Operation::Sign);
        trail.push(Event::Settled {
            request,
            outcome: Outcome::Refused(Refusal::NobodyReachable(Whereabouts::Away)),
        });
    }
    let request = trail.ask(connection, "gpg", Operation::Sign);
    trail.push(Event::Settled {
        request,
        outcome: Outcome::Refused(Refusal::Declined),
    });
    trail.push(Event::TurnedAway {
        remote: None,
        refusal: Refusal::NoChannel {
            process: 7312,
            program: None,
        },
    });

    let expected = vec![
        Attention::Refused {
            remote: None,
            refusal: Refusal::NoChannel {
                process: 7312,
                program: None,
            },
            times: 1,
        },
        Attention::Refused {
            remote: Some(host.clone()),
            refusal: Refusal::NobodyReachable(Whereabouts::Away),
            times: 3,
        },
    ];
    let mut raised = attention(&catalogue, &configuration, &trail);
    raised.sort_by_key(|item| {
        matches!(
            item,
            Attention::Refused {
                remote: Some(_),
                ..
            }
        )
    });
    assert_eq!(raised, expected, "their own refusal is not raised");

    trail.push(Event::Started {
        version: "0.2.1".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    assert_eq!(attention(&catalogue, &configuration, &trail).len(), 2);

    for item in raised {
        trail.push(Event::PutAway {
            item: item.item().unwrap(),
            by,
        });
    }
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        Vec::<Attention>::new()
    );
}

/// Refusals are coalesced and their number is bounded, so a process that
/// knocks ten thousand times costs sixty-four entries.
#[test]
fn distinct_refusals_are_bounded_and_the_newest_are_kept() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let mut trail = Trail::started();
    for process in 0..10_000 {
        trail.push(Event::TurnedAway {
            remote: None,
            refusal: Refusal::NoChannel {
                process,
                program: None,
            },
        });
    }
    let raised = attention(&catalogue, &configuration, &trail);
    assert_eq!(raised.len(), 64);
    assert!(raised.iter().all(|item| matches!(
        item,
        Attention::Refused { refusal: Refusal::NoChannel { process, .. }, .. } if *process >= 9_936
    )));
}

/// What interrupts comes before what waits.
#[test]
fn attention_is_ordered_with_what_interrupts_first() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let host = remote("coder", "dev/build");
    let mut trail = Trail::started();
    trail.attach(ClientKind::Interface, DESKTOP);
    let connection = trail.open(&host, "linux");
    trail.push(Event::TurnedAway {
        remote: None,
        refusal: Refusal::Unattributable,
    });
    trail.push(Event::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![Finding::ToolAbsent(name("gpgconf"))]),
    });
    let request = trail.ask(connection, "gpg", Operation::Sign);
    trail.push(Event::Held { request });
    assert_eq!(
        volumes(&catalogue, &configuration, &trail),
        [Volume::Interrupts, Volume::Announced, Volume::Announced]
    );
}

/// Events about a connection, client or request that no longer exists change
/// nothing: the fold is total over any trail.
#[test]
fn an_event_about_something_gone_changes_nothing() {
    let mut trail = Trail::started();
    let before = trail.state();
    let gone = ConnectionId(Seq(500));
    for event in [
        Event::Presence {
            client: ClientId(Seq(500)),
            presence: Presence::Away,
        },
        Event::Observed {
            connection: gone,
            platform: name("linux"),
        },
        Event::Checked {
            connection: gone,
            capability: name("gpg"),
            readiness: Readiness::Ready,
        },
        Event::Up {
            connection: gone,
            serving: Vec::new(),
        },
        Event::Down {
            connection: gone,
            end: ChannelEnd::Closed,
        },
        Event::Held {
            request: hedwig_model::trail::RequestId(Seq(500)),
        },
    ] {
        trail.push(event);
    }
    assert_eq!(trail.state(), before);
}

/// A trail that cannot be read says nothing about what the person paused,
/// so the core starts with everything paused rather than with nothing.
#[test]
fn an_unreadable_trail_leaves_everything_paused() {
    let unknown = State::unknown();
    assert!(unknown.paused(&remote("coder", "dev/build"), &Sets::NONE));
    assert!(unknown.paused(&remote("ssh", "ops@bastion.example"), &Sets::NONE));
    assert!(!unknown.reachable(&remote("coder", "dev/build"), &Sets::NONE));
    assert!(!State::default().paused(&remote("coder", "dev/build"), &Sets::NONE));
}

/// The workstation's own side of a capability is tried per connection; what
/// it last did is kept for the run and shown on every row of that
/// capability.
#[test]
fn the_workstations_own_side_is_remembered_for_the_run() {
    let mut trail = Trail::started();
    assert_eq!(trail.state().source(&name("gpg")), None);
    trail.push(Event::Source {
        capability: name("gpg"),
        health: Health::Failing(Failure::Unreachable),
    });
    assert_eq!(
        trail.state().source(&name("gpg")),
        Some(Health::Failing(Failure::Unreachable))
    );
    trail.push(Event::Source {
        capability: name("gpg"),
        health: Health::Sound,
    });
    assert_eq!(trail.state().source(&name("gpg")), Some(Health::Sound));
    trail.push(Event::Started {
        version: "0.2.1".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    assert_eq!(trail.state().source(&name("gpg")), None);
}

/// A run that broke down is told to the person by the next one, counted
/// until they put it away, and kept across the runs in between: the
/// connections they had opened went with it, and nothing else says why.
#[test]
fn a_breakdown_is_raised_by_the_next_run_until_the_person_puts_it_away() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let mut trail = Trail::started();
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        Vec::<Attention>::new()
    );

    let crashed = Breakdown::Exited {
        status: 0xc000_0005,
    };
    for (cause, times) in [(crashed, 1), (Breakdown::Hung, 2)] {
        trail.push(Event::Started {
            version: "0.2.0".to_owned(),
            origin: DESKTOP,
            after: Some(cause),
        });
        assert_eq!(
            attention(&catalogue, &configuration, &trail),
            [Attention::Restarted { cause, times }]
        );
    }
    let raised = attention(&catalogue, &configuration, &trail);
    let item = raised.first().unwrap();
    assert_eq!(
        volumes(&catalogue, &configuration, &trail),
        [Volume::Announced]
    );
    assert_eq!(item.item(), Some(Item::Restarted));

    // A run the person or their session ended says nothing new and forgets
    // nothing.
    trail.push(Event::Started {
        version: "0.2.0".to_owned(),
        origin: OVER_SSH,
        after: None,
    });
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        [Attention::Restarted {
            cause: Breakdown::Hung,
            times: 2
        }]
    );

    let by = trail.attach(ClientKind::Terminal, OVER_SSH);
    trail.push(Event::PutAway {
        item: Item::Restarted,
        by,
    });
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        Vec::<Attention>::new()
    );
    trail.push(Event::Started {
        version: "0.2.0".to_owned(),
        origin: DESKTOP,
        after: Some(crashed),
    });
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        [Attention::Restarted {
            cause: crashed,
            times: 1
        }],
        "counting starts again once it has been put away"
    );
}

/// A trail that could not be read begins again with an entry saying so. The
/// fold of that entry is the state in which everything is paused, so the
/// pause holds across any number of runs until the person resumes - which a
/// state held only in memory would not.
#[test]
fn an_unreadable_trail_pauses_everything_until_the_person_resumes() {
    let catalogue = catalogue();
    let configuration = granting(&catalogue, &[("gpg", Granted::Route(name("coder")))]);
    let workspace = remote("coder", "dev/build");
    let account = "line 812: a key given twice at byte 7".to_owned();

    let mut trail = Trail::default();
    trail.push(Event::Unreadable {
        store: Store::Trail,
        account: account.clone(),
    });
    assert_eq!(State::fold(&trail.entries), {
        let mut unknown = State::unknown();
        unknown.apply(trail.entries.first().unwrap());
        unknown
    });
    for _ in 0..3 {
        trail.push(Event::Started {
            version: "0.2.0".to_owned(),
            origin: DESKTOP,
            after: None,
        });
        assert!(trail.state().paused(&workspace, &Sets::NONE));
    }
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        [Attention::Unreadable {
            store: Store::Trail,
            account,
        }]
    );

    let by = trail.attach(ClientKind::Interface, DESKTOP);
    trail.push(Event::Resumed {
        scope: Remotes::Every,
        by,
    });
    assert!(!trail.state().paused(&workspace, &Sets::NONE));
    // The resume lets exposure through again, so every client but the one
    // it was made at is told of it as well.
    let raised = attention(&catalogue, &configuration, &trail);
    assert_eq!(raised.len(), 2);
    let resumed = raised.last().and_then(Attention::item).unwrap();
    assert!(matches!(resumed, Item::Widened(_)));
    for item in [Item::Unreadable(Store::Trail), resumed] {
        trail.push(Event::PutAway { item, by });
    }
    assert_eq!(
        attention(&catalogue, &configuration, &trail),
        Vec::<Attention>::new()
    );

    // An unreadable configuration pauses nothing: nothing is granted, which
    // exposes nothing, and the person is told why.
    trail.push(Event::Unreadable {
        store: Store::Configuration,
        account: "grants.0.terms has \"acknowleged\", which is not known here".to_owned(),
    });
    assert!(!trail.state().paused(&workspace, &Sets::NONE));
    let raised = attention(&catalogue, &configuration, &trail);
    assert_eq!(
        raised.first().and_then(Attention::item),
        Some(Item::Unreadable(Store::Configuration))
    );
}

/// Everything about one remote, ended connections included: each connection
/// to it from its opening to its end, its requests and prompts through the
/// entries that named them, what readiness changed there, a connection turned
/// away from its forward, a pause that covers it. Another remote's entries
/// and a change to the configuration are not about it.
#[test]
fn a_remotes_activity_names_everything_about_it_ended_connections_included() {
    use hedwig_model::text::RemotePath;
    use hedwig_model::trail::{Prepared, about};

    let host = remote("coder", "dev/build");
    let other = remote("coder", "dev/docs");
    let mut trail = Trail::started();
    let mut ours = Vec::new();
    let first = trail.open(&host, "linux");
    ours.extend([first.0, Seq(first.0.0 + 1)]);
    let elsewhere = trail.open(&other, "linux");
    ours.push(trail.push(Event::Prepared {
        connection: first,
        capability: name("gpg"),
        prepared: Prepared::Created(RemotePath::try_from("/run/user/1000/gnupg").unwrap()),
    }));
    let request = trail.ask(first, "gpg", Operation::Sign);
    ours.push(request.0);
    trail.ask(elsewhere, "gpg", Operation::Sign);
    ours.push(trail.push(Event::Settled {
        request,
        outcome: Outcome::Refused(Refusal::Declined),
    }));
    let prompt = PromptId(trail.push(Event::Prompted {
        connection: first,
        kind: PromptKind::KeyPassphrase,
        words: Words::try_from("Enter passphrase for key").unwrap(),
    }));
    ours.push(prompt.0);
    ours.push(trail.push(Event::Answered { prompt, by: None }));
    ours.push(trail.push(Event::Down {
        connection: first,
        end: ChannelEnd::Slept,
    }));
    let client = trail.attach(ClientKind::Terminal, OVER_SSH);
    ours.push(trail.push(Event::Paused {
        scope: Remotes::Every,
        by: client,
    }));
    trail.push(Event::Paused {
        scope: Remotes::One(other.clone()),
        by: client,
    });
    ours.push(trail.push(Event::TurnedAway {
        remote: Some(host.clone()),
        refusal: Refusal::Unissued,
    }));
    let second: ConnectionId = trail.open(&host, "linux");
    ours.extend([second.0, Seq(second.0.0 + 1)]);

    let found: Vec<_> = about(&State::default(), &trail.entries, &host, &Sets::NONE)
        .map(|entry| entry.seq)
        .collect();
    assert_eq!(found, ours);
    assert!(
        about(&State::default(), &trail.entries, &other, &Sets::NONE)
            .all(|entry| !ours.contains(&entry.seq) || matches!(entry.event, Event::Paused { .. }))
    );
}

/// What Hedwig wrote is listed with the outermost folder it made there, and
/// taking it back removes it from the list whatever folder it made.
#[test]
fn a_write_is_listed_with_the_folder_it_made_and_its_reversal_removes_it() {
    use hedwig_model::text::RemotePath;
    use hedwig_model::trail::Write;

    let host = remote("coder", "dev/build");
    let mut trail = Trail::started();
    let connection = trail.open(&host, "linux");
    let unit = RemotePath::try_from("/home/dev/.config/systemd/user/gpg-agent.socket").unwrap();
    let config = RemotePath::try_from("/home/dev/.config").unwrap();
    let common = RemotePath::try_from("/home/dev/.gnupg/common.conf").unwrap();
    for (write, place, made) in [
        (Write::Masked, unit.clone(), Some(config.clone())),
        (Write::NoAutostart, common.clone(), None),
    ] {
        trail.push(Event::Wrote {
            connection,
            capability: name("gpg"),
            write,
            place,
            made,
        });
    }
    let state = State::fold(&trail.entries);
    let listed: Vec<_> = state.written(&host).collect();
    assert_eq!(
        listed,
        [
            (&name("gpg"), &Write::NoAutostart, &common, None),
            (&name("gpg"), &Write::Masked, &unit, Some(&config)),
        ]
    );
    trail.push(Event::Unwrote {
        connection,
        capability: name("gpg"),
        write: Write::Masked,
        place: unit,
    });
    let state = State::fold(&trail.entries);
    assert_eq!(
        state.written(&host).collect::<Vec<_>>(),
        [(&name("gpg"), &Write::NoAutostart, &common, None)]
    );
}

/// Every entry of a remote's activity makes `Exposure` stale, under
/// which a surface reads that activity, so a test's result reaches a client
/// whose notice did not fit at the next stale rows; across the corpus, every
/// entry `about` finds for any remote does.
#[test]
fn every_entry_of_a_remotes_activity_makes_exposure_stale() {
    use hedwig_model::trail::about;

    let host = remote("ssh", "dev@build-7.example");
    let mut trail = Trail::started();
    let client = trail.attach(ClientKind::Terminal, DESKTOP);
    let connection = trail.open(&host, "linux");
    trail.push(Event::Exercised {
        connection,
        capability: name("gpg"),
        proof: Proof::Silent(None),
        by: client,
    });
    let entries = corpus::entries();
    let remotes: Vec<RemoteId> = entries
        .iter()
        .chain(&trail.entries)
        .filter_map(|entry| match &entry.event {
            Event::Opening { remote, .. } => Some(remote.clone()),
            _ => None,
        })
        .collect();
    let mut seen = 0;
    for remote in &remotes {
        for source in [&entries, &trail.entries] {
            for entry in about(&State::default(), source, remote, &Sets::NONE) {
                seen += 1;
                assert!(
                    entry.event.touches().contains(&Topic::Exposure),
                    "{:?} is in {remote:?}'s activity",
                    entry.event
                );
            }
        }
    }
    assert!(
        about(&State::default(), &trail.entries, &host, &Sets::NONE)
            .any(|entry| matches!(entry.event, Event::Exercised { .. })),
        "the test is in the activity"
    );
    assert!(seen > 20, "{seen} entries checked");
}

/// The connection `trail` opened to `remote`, up and serving `capabilities`.
fn up(trail: &mut Trail, remote: &RemoteId, capabilities: &[&str]) -> ConnectionId {
    use hedwig_model::text::RemotePath;
    use hedwig_model::trail::{Binding, Serving};

    let connection = trail.open(remote, "linux");
    trail.push(Event::Up {
        connection,
        serving: capabilities
            .iter()
            .map(|capability| Serving {
                capability: name(capability),
                binding: Binding::Socket(RemotePath::try_from("/run/user/1000/gnupg/S.x").unwrap()),
            })
            .collect(),
    });
    connection
}

/// A change of what holds a capability's source is in the activity of
/// each remote whose live connection serves that capability, and of no other:
/// not one whose connection serves something else, is still opening, or has
/// ended.
#[test]
fn a_holders_change_is_in_the_activity_of_each_remote_its_capability_serves() {
    use hedwig_model::trail::about;

    let [both, gpg, adb, opening, ended] =
        ["both", "gpg", "adb", "opening", "ended"].map(|at| remote("coder", at));
    let mut trail = Trail::started();
    let through_both = up(&mut trail, &both, &["gpg", "adb"]);
    up(&mut trail, &gpg, &["gpg"]);
    up(&mut trail, &adb, &["adb"]);
    trail.open(&opening, "linux");
    let gone = up(&mut trail, &ended, &["gpg", "adb"]);
    trail.push(Event::Down {
        connection: gone,
        end: ChannelEnd::Slept,
    });
    let held = |trail: &mut Trail, capability: &str| {
        trail.push(Event::HeldBy {
            capability: name(capability),
            holder: None,
        })
    };
    let gpg_held = held(&mut trail, "gpg");
    let adb_held = held(&mut trail, "adb");
    trail.push(Event::Down {
        connection: through_both,
        end: ChannelEnd::Closed,
    });
    let gpg_again = held(&mut trail, "gpg");

    let holders = |remote: &RemoteId| -> Vec<Seq> {
        about(&State::default(), &trail.entries, remote, &Sets::NONE)
            .filter(|entry| matches!(entry.event, Event::HeldBy { .. }))
            .map(|entry| entry.seq)
            .collect()
    };
    assert_eq!(holders(&both), [gpg_held, adb_held]);
    assert_eq!(holders(&gpg), [gpg_held, gpg_again]);
    assert_eq!(holders(&adb), [adb_held]);
    assert_eq!(holders(&opening), []);
    assert_eq!(holders(&ended), []);
}

/// A remote's activity whose live connection began before the trail was
/// compacted still holds what follows on it: its request's settlement, its
/// prompt's answer, a change of what holds what it serves, and its end.
#[test]
fn a_remotes_activity_reads_its_live_connection_across_a_compaction() {
    use hedwig_model::trail::{Timestamp, about, compact};

    let host = remote("coder", "dev/build");
    let mut trail = Trail::started();
    let connection = up(&mut trail, &host, &["gpg"]);
    let request = trail.ask(connection, "gpg", Operation::Sign);
    let prompt = PromptId(trail.push(Event::Prompted {
        connection,
        kind: PromptKind::KeyPassphrase,
        words: Words::try_from("Enter passphrase for key").unwrap(),
    }));
    let cut = trail.entries.len();
    let after = [
        trail.push(Event::Settled {
            request,
            outcome: Outcome::Refused(Refusal::Declined),
        }),
        trail.push(Event::Answered { prompt, by: None }),
        trail.push(Event::HeldBy {
            capability: name("gpg"),
            holder: None,
        }),
        trail.push(Event::Down {
            connection,
            end: ChannelEnd::Closed,
        }),
    ];
    let whole: Vec<Seq> = about(&State::default(), &trail.entries, &host, &Sets::NONE)
        .map(|entry| entry.seq)
        .filter(|seq| after.contains(seq))
        .collect();
    assert_eq!(whole, after);

    let (head, compacted) = compact(
        State::default(),
        trail.entries.clone(),
        Timestamp(0),
        trail.entries.len() - cut,
    );
    let kept = compacted.first().unwrap();
    assert!(matches!(kept.event, Event::Kept { .. }), "{kept:?}");
    let found: Vec<Seq> = about(&head, &compacted, &host, &Sets::NONE)
        .map(|entry| entry.seq)
        .collect();
    let mut expected = vec![kept.seq];
    expected.extend(after);
    assert_eq!(
        found, expected,
        "the cut, then what followed on the connection"
    );
}

/// Every entry that changes what the workstation's reply says makes
/// `Workstation` stale, whatever else it marks; across the corpus, folded one
/// entry at a time.
#[test]
fn every_entry_that_changes_the_workstation_makes_it_stale() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let workstation = |state: &State| {
        World {
            catalogue: &catalogue,
            configuration: &configuration,
            state,
        }
        .workstation()
    };
    let mut state = State::default();
    let mut changed = 0;
    for entry in corpus::entries() {
        // A compaction's entry stands at a trail's head and folds to the
        // state the entries it replaced did: it changes nothing a client read.
        if matches!(entry.event, Event::Kept { .. }) {
            continue;
        }
        let before = workstation(&state);
        state.apply(&entry);
        if workstation(&state) != before {
            changed += 1;
            assert!(
                entry.event.touches().contains(&Topic::Workstation),
                "{:?} changes the workstation",
                entry.event
            );
        }
    }
    assert!(changed >= 6, "{changed} changes checked");
}
