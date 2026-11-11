//! The interface's conversation with the core: every state it can find the
//! core in, and what it asks when.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Instant;

use hedwig_client::Standing;
use hedwig_model::capability::Exposure;
use hedwig_model::config::{Activation, Change};
use hedwig_model::process::{CoreState, Instance, Running};
use hedwig_model::protocol::{FromCore, Notice, PROTOCOL, Proof, Reply, Request, ToCore, Topic};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, Remotes, Sets};
use hedwig_model::trail::{Breakdown, ClientKind, Event as Happened, Icon, Missing, Presence};
use hedwig_view::act::Act;
use hedwig_view::glance::{self, Glance, Reach};
use hedwig_view::link::{Core, Effect, Event, Link, Place};

mod common;
use common::support::{grant, name, remote, terms};
use common::{Bench, pipe, serving};

fn known(core: CoreState) -> Standing {
    Standing::Known(Running {
        supervisor: Instance {
            process: 4100,
            created: 1,
        },
        core,
    })
}

fn requests(sent: &[ToCore]) -> Vec<&Request> {
    sent.iter().map(|frame| &frame.request).collect()
}

/// A person glancing at the icon when Hedwig does not answer: why not is never
/// "not running" alone, and the one thing to do about it is the icon's click.
#[test]
fn every_way_no_core_answers_is_told_apart() {
    let mut link = Link::default();

    link.handle(Event::Looked(Standing::Absent));
    assert_eq!(link.seen().core, Core::Absent);
    assert_eq!(Glance::of(link.seen()).tip(), "Hedwig is not running");
    assert_eq!(glance::chosen(link.seen()), Act::Start);

    // A record being written, or a core not yet listening.
    for standing in [Standing::Unsettled, known(CoreState::Starting)] {
        link.handle(Event::Looked(standing));
        assert_eq!(link.seen().core, Core::Starting);
        assert_eq!(Glance::of(link.seen()).tip(), "Hedwig is starting");
        assert_eq!(Glance::of(link.seen()).reach, Reach::Wait);
    }

    link.handle(Event::Looked(known(CoreState::Restarting {
        cause: Breakdown::Exited { status: 101 },
        said: "the trail could not be written".to_owned(),
    })));
    assert_eq!(
        Glance::of(link.seen()).tip(),
        "Hedwig broke down and is starting again"
    );
    // The menu and the window say why in full, with the core's last words.
    assert_eq!(
        glance::menu(link.seen(), Instant::now()).first(),
        Some(&glance::Entry::Line(
            "Hedwig broke down and is starting again: it ended by itself, with status 101. \
             Its last words: the trail could not be written"
                .to_owned()
        ))
    );

    // A core is named and its pipe cannot be opened.
    let effects = link.handle(Event::Looked(serving(pipe('a'))));
    assert!(effects.contains(&Effect::Open(pipe('a'))));
    link.handle(Event::Unopened(
        "the pipe does not admit this account".to_owned(),
    ));
    assert_eq!(
        Glance::of(link.seen()).tip(),
        "Hedwig cannot be reached - open this for why"
    );
    assert_eq!(
        glance::why(&link.seen().core).as_deref(),
        Some("Hedwig cannot be reached: the pipe does not admit this account.")
    );
    assert_eq!(glance::chosen(link.seen()), Act::Retry);
    // The same record is not tried again by itself; the person's retry is.
    assert!(
        !link
            .handle(Event::Looked(serving(pipe('a'))))
            .iter()
            .any(|effect| matches!(effect, Effect::Open(_)))
    );
    assert!(link.handle(Event::Retry).contains(&Effect::Look));
    assert!(
        link.handle(Event::Looked(serving(pipe('a'))))
            .contains(&Effect::Open(pipe('a')))
    );
}

/// The interface is a client like any other: it greets as what it is, and
/// asks for exactly what the icon shows - one request at a time, because the
/// core reads a client's next only when it has answered the last.
#[test]
fn attaching_greets_as_the_interface_and_asks_what_the_icon_shows() {
    let mut link = Link::default();
    link.handle(Event::Looked(serving(pipe('a'))));
    let effects = link.handle(Event::Opened);
    assert_eq!(
        effects,
        [
            Effect::Send(ToCore {
                id: 1,
                request: Request::Hello {
                    protocol: PROTOCOL,
                    kind: ClientKind::Interface,
                    attends: Remotes::Every,
                }
            }),
            Effect::Render
        ]
    );
    // Nothing more is sent until that is answered.
    assert_eq!(
        link.handle(Event::Presence(Presence::Present)),
        [Effect::Render]
    );

    let bench = Bench::attached();
    assert_eq!(
        requests(&bench.sent),
        [
            &Request::Hello {
                protocol: PROTOCOL,
                kind: ClientKind::Interface,
                attends: Remotes::Every,
            },
            &Request::Status,
            &Request::Attention,
            &Request::Exposure,
            &Request::Settings {
                remotes: Vec::new()
            },
            &Request::Workstation,
        ]
    );
    let ids: Vec<u32> = bench.sent.iter().map(|frame| frame.id).collect();
    assert_eq!(ids, [1, 2, 3, 4, 5, 6]);
    let attached = bench.seen();
    assert_eq!(
        attached.you, bench.origin,
        "as the core read it from the pipe"
    );
    assert!(attached.status.is_some() && attached.rows.is_some());
    // The keys the workstation offers name a request's key on the card; what
    // only the window shows is not asked for until the window is open.
    assert!(attached.workstation.is_some());
    assert!(attached.catalogue.is_none() && attached.document.is_none());
}

#[test]
fn the_window_asks_for_what_only_it_shows() {
    let mut bench = Bench::attached();
    bench.sent.clear();
    bench.feed(Event::Window(true));
    assert_eq!(
        requests(&bench.sent),
        [&Request::Workstation, &Request::Catalogue, &Request::Export]
    );
    assert!(bench.seen().catalogue.is_some());

    // The configuration going stale is news for the settings everywhere -
    // whom to ask is on the card - and, only while the window shows them, for
    // the document and what is defined outside it.
    let settings = Request::Settings {
        remotes: Vec::new(),
    };
    bench.sent.clear();
    bench.notice(Notice::Stale(Topic::Configuration));
    assert_eq!(
        requests(&bench.sent),
        [&settings, &Request::Catalogue, &Request::Export]
    );
    bench.feed(Event::Window(false));
    bench.sent.clear();
    bench.notice(Notice::Stale(Topic::Configuration));
    assert_eq!(requests(&bench.sent), [&settings]);
}

/// Nothing is knowable only from a notice: told that something is stale, the
/// interface asks again for what it shows - once, however often it is told
/// before it could ask.
#[test]
fn what_went_stale_is_asked_again_once() {
    let mut link = Link::default();
    link.handle(Event::Looked(serving(pipe('a'))));
    link.handle(Event::Opened);
    link.handle(Event::Frame(
        FromCore::Reply {
            id: 1,
            reply: Ok(Reply::Welcome {
                protocol: PROTOCOL,
                version: "0.2.0".to_owned(),
                you: common::support::DESKTOP,
            }),
        },
        Instant::now(),
    ));
    // `status` is outstanding; three notices arrive before its reply.
    for _ in 0..3 {
        let effects = link.handle(Event::Frame(
            FromCore::Notice(Notice::Stale(Topic::Exposure)),
            Instant::now(),
        ));
        assert_eq!(
            effects,
            [Effect::Render],
            "nothing is sent while one is out"
        );
    }

    // Each topic asks again for what it covers and nothing else: the
    // workstation's reply has a topic of its own. The bench answers each
    // before the next notice, so nothing waits to be merged.
    let mut bench = Bench::attached();
    bench.sent.clear();
    for topic in [
        Topic::Status,
        Topic::Exposure,
        Topic::Attention,
        Topic::Workstation,
    ] {
        bench.notice(Notice::Stale(topic));
    }
    assert_eq!(
        requests(&bench.sent),
        [
            &Request::Status,
            &Request::Exposure,
            &Request::Attention,
            &Request::Workstation
        ]
    );
}

/// The desktop locks while a request is held for the person: the
/// interface says it can show nothing before it says anything else, and the
/// core refuses what it was holding.
#[test]
fn leaving_the_desktop_is_said_ahead_of_everything_queued() {
    let mut bench = Bench::attached();
    let workspace = remote("coder", "dev/build");
    bench.feed(Event::Wish(
        Place::Window,
        Request::Pause(Remotes::One(workspace)),
    ));

    // Three things are waiting to be asked when the desktop locks.
    let mut link = Link::default();
    link.handle(Event::Looked(serving(pipe('a'))));
    link.handle(Event::Opened);
    link.handle(Event::Frame(
        FromCore::Reply {
            id: 1,
            reply: Ok(Reply::Welcome {
                protocol: PROTOCOL,
                version: "0.2.0".to_owned(),
                you: common::support::DESKTOP,
            }),
        },
        Instant::now(),
    ));
    link.handle(Event::Presence(Presence::Away));
    let effects = link.handle(Event::Frame(
        FromCore::Reply {
            id: 2,
            reply: Ok(Reply::Attention(Vec::new())),
        },
        Instant::now(),
    ));
    assert!(
        effects.contains(&Effect::Send(ToCore {
            id: 3,
            request: Request::Presence(Presence::Away)
        })),
        "{effects:?}"
    );

    // And through the core: away, then back.
    let someone = remote("coder", "dev/build");
    bench.sent.clear();
    bench.feed(Event::Presence(Presence::Away));
    assert_eq!(
        bench.sent.first().map(|frame| &frame.request),
        Some(&Request::Presence(Presence::Away))
    );
    assert!(!bench.desk.trail.state().reachable(&someone, &Sets::NONE));
    bench.feed(Event::Presence(Presence::Present));
    assert!(bench.desk.trail.state().reachable(&someone, &Sets::NONE));
    // Saying the same thing twice says it once.
    bench.sent.clear();
    bench.feed(Event::Presence(Presence::Present));
    assert_eq!(bench.sent, Vec::<ToCore>::new());
}

/// An interface that starts on a locked desktop says so as soon as it is
/// greeted.
#[test]
fn an_interface_started_on_a_locked_desktop_says_so_first() {
    let someone = remote("coder", "dev/build");
    let mut bench = Bench::new();
    bench.link.handle(Event::Presence(Presence::Away));
    bench.attach();
    assert_eq!(
        bench.sent.get(1).map(|frame| &frame.request),
        Some(&Request::Presence(Presence::Away))
    );
    assert!(!bench.desk.trail.state().reachable(&someone, &Sets::NONE));
}

/// The core goes away - stopped, broken down, replaced by an update.
/// The interface looks for what comes next, shows nothing it was told by the
/// core that is gone, and keeps no act of the person's to carry out later.
#[test]
fn a_core_that_goes_away_is_looked_for_and_nothing_asked_of_it_is_kept() {
    let mut bench = Bench::attached();
    let effects = bench.feed(Event::Closed);
    assert!(effects.contains(&Effect::Look));
    assert_eq!(bench.link.seen().core, Core::Starting);

    // Whatever the person asks now is not done, and they are told so there.
    let effects = bench.feed(Event::Wish(Place::Tray, Request::Pause(Remotes::Every)));
    assert!(effects.contains(&Effect::Undone(Place::Tray)));

    // The supervisor says the core broke down, then names the next one.
    bench.feed(Event::Looked(known(CoreState::Restarting {
        cause: Breakdown::Hung,
        said: String::new(),
    })));
    assert_eq!(
        glance::why(&bench.link.seen().core).as_deref(),
        Some("Hedwig broke down and is starting again: it stopped answering.")
    );
    let effects = bench.link.handle(Event::Looked(serving(pipe('b'))));
    assert!(effects.contains(&Effect::Open(pipe('b'))));
    bench.sent.clear();
    bench.feed(Event::Opened);
    assert!(matches!(
        bench.sent.first().map(|frame| &frame.request),
        Some(Request::Hello { .. })
    ));
    assert!(
        bench
            .sent
            .iter()
            .all(|frame| frame.request != Request::Pause(Remotes::Every))
    );
}

/// While the connection is open its end is what says the core went. A
/// record that names another pipe is another core: the old one is left.
#[test]
fn a_record_that_names_another_pipe_is_another_core() {
    let mut bench = Bench::attached();
    // The record flickering while it is rewritten changes nothing.
    for standing in [Standing::Unsettled, known(CoreState::Starting)] {
        let effects = bench.feed(Event::Looked(standing));
        assert_eq!(effects, [Effect::Render]);
        assert!(bench.link.seen().attached().is_some());
    }
    let effects = bench.link.handle(Event::Looked(serving(pipe('b'))));
    assert_eq!(
        effects,
        [Effect::Hang, Effect::Open(pipe('b')), Effect::Render]
    );
    // No record at all: Hedwig was stopped.
    let mut bench = Bench::attached();
    let effects = bench.feed(Event::Looked(Standing::Absent));
    assert_eq!(effects, [Effect::Hang, Effect::Render]);
    assert_eq!(bench.link.seen().core, Core::Absent);
}

/// The icon outlived an update: the running core speaks another protocol.
/// The person is told which to restart, in the model's own words, and that
/// core is not greeted again.
#[test]
fn a_refused_greeting_is_shown_and_not_repeated_to_the_same_core() {
    let mut link = Link::default();
    link.handle(Event::Looked(serving(pipe('a'))));
    link.handle(Event::Opened);
    let refusal = Refusal::Version { core: 2, client: 1 };
    let effects = link.handle(Event::Frame(
        FromCore::Reply {
            id: 1,
            reply: Err(refusal.clone()),
        },
        Instant::now(),
    ));
    assert_eq!(effects, [Effect::Hang, Effect::Render]);
    assert_eq!(link.seen().core, Core::Refused(refusal.clone()));
    assert_eq!(
        Glance::of(link.seen()).tip(),
        "Hedwig cannot be used from this icon - open this for why"
    );
    assert_eq!(
        glance::why(&link.seen().core).as_deref(),
        Some(
            "Hedwig refused this interface: this client speaks control protocol 1 and the running \
             Hedwig speaks 2; restart Hedwig so both come from the same install."
        )
    );
    // That Hedwig can still be stopped from here, by ending its supervisor.
    assert!(
        glance::menu(link.seen(), Instant::now())
            .iter()
            .any(|entry| matches!(
                entry,
                glance::Entry::Act {
                    act: Act::Stop { .. },
                    ..
                }
            ))
    );
    assert_eq!(
        link.handle(Event::Looked(serving(pipe('a')))),
        [Effect::Render]
    );
    assert!(
        link.handle(Event::Looked(serving(pipe('b'))))
            .contains(&Effect::Open(pipe('b')))
    );
}

/// A frame that answers nothing the interface asked: nothing after it can be
/// matched to a request, so the connection ends and the core is found again.
#[test]
fn a_reply_nobody_waits_for_ends_the_connection() {
    for id in [0, 7] {
        let mut bench = Bench::attached();
        let effects = bench.link.handle(Event::Frame(
            FromCore::Reply {
                id,
                reply: Err(Refusal::Malformed("not a frame".to_owned())),
            },
            Instant::now(),
        ));
        assert_eq!(effects, [Effect::Hang, Effect::Look, Effect::Render]);
        assert_eq!(bench.link.seen().core, Core::Starting);
    }
}

/// A refusal is the core's, typed, and shown where the act was made - never
/// a transport error standing in for it.
#[test]
fn what_the_core_refuses_is_shown_where_it_was_asked() {
    let mut bench = Bench::attached();
    let nowhere = remote("ssh", "build.example");
    let asked = Request::Check {
        remote: nowhere.clone(),
        capability: name("gpg"),
    };
    bench.feed(Event::Wish(Place::Window, asked));
    let refused = Refusal::NotGranted {
        capability: name("gpg"),
        remote: nowhere,
    };
    assert_eq!(bench.seen().refused, Some((Place::Window, refused)));
    // An act from elsewhere leaves it; the next act from the window clears it.
    bench.feed(Event::Wish(Place::Tray, Request::Pause(Remotes::Every)));
    assert!(bench.seen().refused.is_some());
    bench.feed(Event::Wish(Place::Window, Request::Resume(Remotes::Every)));
    assert_eq!(bench.seen().refused, None);
    assert_eq!(
        bench.desk.trail.entries.last().map(|entry| &entry.event),
        Some(&Happened::Resumed {
            scope: Remotes::Every,
            by: bench.client.unwrap()
        })
    );
}

/// After an act the core carried out, the interface asks again for what it
/// shows, whether or not a notice says to.
#[test]
fn an_act_carried_out_is_followed_by_what_it_changed() {
    let mut bench = Bench::attached();
    bench.sent.clear();
    bench.feed(Event::Wish(Place::Tray, Request::Pause(Remotes::Every)));
    assert_eq!(
        requests(&bench.sent),
        [
            &Request::Pause(Remotes::Every),
            &Request::Status,
            &Request::Attention,
            &Request::Exposure,
            &Request::Settings {
                remotes: Vec::new()
            },
        ]
    );
    assert_eq!(Glance::of(bench.link.seen()).reach, Reach::Paused);
}

/// The window greets as a viewer: it is told what went stale as any
/// surface that shows is, it never says where the person is, and the core
/// would refuse it the person's presence were it to say.
#[test]
fn the_window_greets_as_a_viewer_and_says_nothing_of_where_the_person_is() {
    let mut bench = Bench::viewer();
    bench.attach();
    assert_eq!(
        requests(&bench.sent).first(),
        Some(&&Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Viewer,
            attends: Remotes::Every,
        })
    );
    let from = bench.sent.len();
    for presence in [Presence::Away, Presence::Present, Presence::Engaged] {
        bench.feed(Event::Presence(presence));
    }
    let since = bench.sent.get(from..).unwrap_or_default();
    assert!(
        !since
            .iter()
            .any(|frame| matches!(frame.request, Request::Presence(_))),
        "{since:?}"
    );
    assert_eq!(
        bench.permits(&Request::Presence(Presence::Away)),
        Err(Refusal::NotAttending)
    );
    bench.sent.clear();
    bench.notice(Notice::Stale(Topic::Exposure));
    assert_eq!(requests(&bench.sent), [&Request::Exposure]);
}

/// A test is answered at once and what the remote's tool did follows as
/// a notice to the client that asked; where that notice did not fit, it is
/// read from the remote's activity once the rows go stale, and only an
/// exercise recorded after the test was asked settles it.
#[test]
fn a_test_whose_notice_did_not_arrive_is_read_from_the_remotes_activity() {
    let workspace = remote("coder", "dev/build");
    let mut bench = Bench::attached();
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(workspace.clone())),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        }),
    ));
    let connection = bench.desk.channel_up(&workspace, "linux");
    // An earlier test's entry, which the one asked now must not take as its
    // own.
    bench.desk.trail.push(Happened::Exercised {
        connection,
        capability: name("gpg"),
        proof: Proof::Silent(None),
        by: bench.client.unwrap(),
    });
    bench.notice(Notice::Stale(Topic::Exposure));
    let here = Place::Line {
        remote: Some(workspace.clone()),
        capability: name("gpg"),
    };
    bench.feed(Event::Wish(
        here.clone(),
        Request::Exercise {
            remote: workspace.clone(),
            capability: name("gpg"),
        },
    ));
    // The stand-in records the exercise and sends no notice of it.
    assert_eq!(bench.seen().refused, None);
    assert_eq!(bench.seen().testing, Some(here.clone()));
    bench.notice(Notice::Stale(Topic::Exposure));
    assert_eq!(bench.seen().testing, None);
    assert!(
        matches!(
            &bench.seen().exercised,
            Some((place, Proof::Reached(_))) if *place == here
        ),
        "{:?}",
        bench.seen().exercised
    );
}

/// The presence tells the core when it tells the person its icon is
/// missing, and when the icon is back, so the window and the command line
/// say it while it is so; a core that greets it while the icon is still
/// missing - a new run, which knows nothing of it - is told again before
/// anything else is asked. The window has no icon and says nothing of one.
#[test]
fn the_presence_tells_the_core_its_icon_is_missing_and_back_and_a_new_core_again() {
    let mut bench = Bench::attached();
    let icon = |bench: &mut Bench| {
        bench.notice(Notice::Stale(Topic::Status));
        let client = bench.client;
        bench
            .seen()
            .status
            .as_ref()
            .and_then(|status| {
                status
                    .attached
                    .iter()
                    .find(|attached| Some(attached.client) == client)
            })
            .and_then(|attached| attached.icon)
    };
    assert_eq!(icon(&mut bench), None, "nothing said");
    bench.sent.clear();
    bench.feed(Event::Icon(Icon::Missing(Missing::Refused)));
    assert_eq!(
        requests(&bench.sent),
        [&Request::Icon(Icon::Missing(Missing::Refused))]
    );
    assert_eq!(icon(&mut bench), Some(Icon::Missing(Missing::Refused)));
    bench.feed(Event::Icon(Icon::Shown));
    assert_eq!(icon(&mut bench), Some(Icon::Shown));

    // Still missing when a new core is greeted.
    bench.feed(Event::Icon(Icon::Missing(Missing::NoTaskbar)));
    bench.link.handle(Event::Closed);
    bench.desk = common::support::desk::Desk::new(common::support::catalogue());
    bench.sent.clear();
    bench.attach();
    assert_eq!(
        requests(&bench.sent).get(..2),
        Some(
            &[
                &Request::Hello {
                    protocol: PROTOCOL,
                    kind: ClientKind::Interface,
                    attends: Remotes::Every,
                },
                &Request::Icon(Icon::Missing(Missing::NoTaskbar)),
            ][..]
        )
    );
    assert_eq!(icon(&mut bench), Some(Icon::Missing(Missing::NoTaskbar)));

    let mut window = Bench::viewer();
    window.attach();
    window.sent.clear();
    window.feed(Event::Icon(Icon::Missing(Missing::Refused)));
    assert_eq!(window.sent.len(), 0, "a viewer has no icon");
}
