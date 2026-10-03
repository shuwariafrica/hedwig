//! What the core decides, driven with nothing else running: no pipe, no
//! file, no clock. Every case hands the core what would have arrived and
//! reads what it says follows.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::num::{NonZeroU8, NonZeroU32};

use hedwig_core::dispatch::{
    Compaction, Core, Effect, Input, Link, Now, Step, Then, Turn, WAITING,
};
use hedwig_model::capability::{Exposure, Lends, Setup};
use hedwig_model::config::{
    Activation, Catalogue, Change, Configuration, Effect as Changed, Grant, Terms,
};
use hedwig_model::install::{AtSignIn, Starts};
use hedwig_model::policy::{ConnectionScope, Keys, Selector};
use hedwig_model::protocol::{
    Answer, Decision, FromCore, Notice, PROTOCOL, Reply, Request, ToCore, Topic, WindowsStarts,
};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes, Sets};
use hedwig_model::setting::{Autostart, Burst, Diagnostics, Said, Settled, Span, Threshold};
use hedwig_model::text::{Address, Name, Secret, Words};
use hedwig_model::trail::{
    Breakdown, ClientId, ClientKind, ConnectionId, Entry, Event, Integrity, Item, Origin, PromptId,
    RequestId, Seq, Store, Tick, Timestamp,
};
use hedwig_model::wire::{line, read};

const NOW: Now = Now {
    at: Timestamp(1_790_000_000_000),
    tick: Tick(40),
};

const DESKTOP: Origin = Origin {
    process: 4200,
    logon: 0x3e7_0001,
    session: 2,
    integrity: Integrity::Medium,
};

/// A terminal over SSH into the workstation.
const OVER_SSH: Origin = Origin {
    process: 5100,
    logon: 0x3e7_0002,
    session: 0,
    integrity: Integrity::High,
};

fn core() -> Core {
    let mut core = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        Vec::new(),
        "0.2.0".to_owned(),
    );
    core.begin(DESKTOP, None, Vec::new(), NOW);
    core
}

fn sent(step: &Step, to: Link) -> Vec<(&FromCore, Then)> {
    step.effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Send { link, frame, then } if *link == to => Some((frame, *then)),
            _ => None,
        })
        .collect()
}

/// The one reply a step makes to `link`.
fn reply(step: &Step, link: Link) -> (u32, Result<Reply, Refusal>, Then) {
    let replies: Vec<_> = sent(step, link)
        .into_iter()
        .filter_map(|(frame, then)| match frame {
            FromCore::Reply { id, reply } => Some((*id, read(&line(reply)).unwrap(), then)),
            FromCore::Notice(_) => None,
        })
        .collect();
    assert_eq!(replies.len(), 1, "{step:?}");
    replies.into_iter().next().unwrap()
}

fn notices(step: &Step, link: Link) -> Vec<Notice> {
    sent(step, link)
        .into_iter()
        .filter_map(|(frame, _)| match frame {
            FromCore::Notice(notice) => Some(notice.clone()),
            FromCore::Reply { .. } => None,
        })
        .collect()
}

fn ask(core: &mut Core, link: Link, id: u32, request: Request) -> Step {
    let frame = ToCore { id, request };
    core.step(Input::Asked { link, frame }, NOW)
}

/// Connects and greets, and tells the core both frames were written.
fn attend(core: &mut Core, link: Link, kind: ClientKind, origin: Origin) {
    core.step(
        Input::Arrived {
            link,
            peer: Some(origin.into()),
        },
        NOW,
    );
    let hello = Request::Hello {
        protocol: PROTOCOL,
        kind,
        attends: Remotes::Every,
    };
    let step = ask(core, link, 1, hello);
    assert!(matches!(reply(&step, link).1, Ok(Reply::Welcome { .. })));
    written(core, link, 1);
}

fn written(core: &mut Core, link: Link, frames: usize) -> Vec<Step> {
    (0..frames)
        .map(|_| core.step(Input::Sent { link }, NOW))
        .collect()
}

/// A remote every client that watches every remote reaches the person for.
fn somewhere() -> RemoteId {
    RemoteId {
        route: Name::try_from("ssh").unwrap(),
        address: Address::try_from("build.example").unwrap(),
    }
}

fn burst(requests: u8) -> Request {
    Request::Change(Change::Burst {
        remotes: Remotes::Every,
        threshold: Some(Threshold::At(Burst {
            requests: NonZeroU8::new(requests).unwrap(),
            seconds: NonZeroU32::new(60).unwrap(),
        })),
    })
}

/// A run begins by recording what could not be read, then its own start
/// with how the run before it ended, in that order and before anything else.
#[test]
fn a_run_begins_with_what_could_not_be_read_and_how_the_last_one_ended() {
    let mut core = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        Vec::new(),
        "0.2.0".to_owned(),
    );
    let step = core.begin(
        OVER_SSH,
        Some(Breakdown::Hung),
        vec![(Store::Trail, "line 3: it is not text".to_owned())],
        NOW,
    );
    let events: Vec<&Event> = step.entries.iter().map(|entry| &entry.event).collect();
    assert_eq!(
        events,
        [
            &Event::Unreadable {
                store: Store::Trail,
                account: "line 3: it is not text".to_owned()
            },
            &Event::Started {
                version: "0.2.0".to_owned(),
                origin: OVER_SSH,
                after: Some(Breakdown::Hung)
            },
        ]
    );
    assert_eq!(
        step.entries
            .iter()
            .map(|entry| entry.seq)
            .collect::<Vec<_>>(),
        [Seq(1), Seq(2)]
    );
    // A run begins by saying what diagnostics are written and what Windows
    // starts at sign-in, as the settings resolve, and by looking at the files
    // set aside; the trail itself is not rewritten when nothing is dropped.
    assert_eq!(
        step.effects,
        [
            Effect::Diagnose(Diagnostics::Faults),
            Effect::Startup {
                hedwig: Autostart::Off,
                icon: Autostart::Off,
            },
        ]
    );
    assert!(step.keep.is_none());
    assert!(matches!(
        step.compact.as_deref(),
        Some(Compaction { trail: None, raised, .. }) if raised == &[Store::Trail]
    ));
    // An unreadable trail leaves everything paused.
    let anywhere = RemoteId {
        route: Name::try_from("ssh").unwrap(),
        address: Address::try_from("build.example").unwrap(),
    };
    assert!(core.state().paused(&anywhere, &Sets::NONE));
}

/// What keeping the `Run` values found is recorded where it changed, read in
/// the settings, and dropped by a new run, whose own keeping says it again.
#[test]
fn what_windows_starts_at_sign_in_is_recorded_where_it_changes_and_read_in_the_settings() {
    let mut core = core();
    let link = Link(1);
    core.step(
        Input::Arrived {
            link,
            peer: Some(DESKTOP.into()),
        },
        NOW,
    );
    let hello = Request::Hello {
        protocol: PROTOCOL,
        kind: ClientKind::Terminal,
        attends: Remotes::Every,
    };
    ask(&mut core, link, 1, hello);
    let elsewhere = Words::try_from(r#""C:\Programs\hedwig\hedwig.exe" serve"#).unwrap();
    let found = [
        (Starts::Hedwig, AtSignIn::Another(Some(elsewhere.clone()))),
        (Starts::Icon, AtSignIn::AsChosen),
    ];
    let step = core.step(Input::Startup(found.clone()), NOW);
    let events: Vec<&Event> = step.entries.iter().map(|entry| &entry.event).collect();
    assert_eq!(
        events,
        [
            &Event::Startup {
                starts: Starts::Hedwig,
                found: AtSignIn::Another(Some(elsewhere.clone())),
            },
            &Event::Startup {
                starts: Starts::Icon,
                found: AtSignIn::AsChosen,
            },
        ]
    );
    assert!(
        sent(&step, link).iter().any(|(frame, _)| matches!(
            frame,
            FromCore::Notice(Notice::Stale(Topic::Configuration))
        ))
    );
    let again = core.step(Input::Startup(found), NOW);
    assert_eq!(again.entries, Vec::new(), "nothing changed");

    let (_, settings, _) = reply(
        &ask(
            &mut core,
            link,
            2,
            Request::Settings {
                remotes: Vec::new(),
            },
        ),
        link,
    );
    let Ok(Reply::Settings(settings)) = settings else {
        panic!("{settings:?}")
    };
    assert_eq!(
        settings.workstation.windows,
        WindowsStarts {
            hedwig: Some(AtSignIn::Another(Some(elsewhere))),
            icon: Some(AtSignIn::AsChosen),
        }
    );

    let mut next = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        step.entries,
        "0.2.1".to_owned(),
    );
    assert_ne!(next.state().startup(Starts::Hedwig), None);
    next.begin(DESKTOP, None, Vec::new(), NOW);
    assert_eq!(next.state().startup(Starts::Hedwig), None);
}

/// A run's own diagnostics are an entry, read in the settings with the
/// statement they came from, and what the core writes follows them.
#[test]
fn a_runs_own_diagnostics_are_recorded_and_said_as_the_runs() {
    let mut core = core();
    let link = Link(1);
    core.step(
        Input::Arrived {
            link,
            peer: Some(DESKTOP.into()),
        },
        NOW,
    );
    let hello = Request::Hello {
        protocol: PROTOCOL,
        kind: ClientKind::Terminal,
        attends: Remotes::Every,
    };
    ask(&mut core, link, 1, hello);
    let step = ask(
        &mut core,
        link,
        2,
        Request::Diagnose(Some(Diagnostics::Detail)),
    );
    assert_eq!(reply(&step, link).1, Ok(Reply::Done(Changed::Changed)));
    assert!(matches!(
        step.entries.as_slice(),
        [Entry {
            event: Event::Diagnosed {
                level: Some(Diagnostics::Detail),
                ..
            },
            ..
        }]
    ));
    assert!(
        step.effects
            .contains(&Effect::Diagnose(Diagnostics::Detail))
    );
    let (_, settings, _) = reply(
        &ask(
            &mut core,
            link,
            3,
            Request::Settings {
                remotes: Vec::new(),
            },
        ),
        link,
    );
    let Ok(Reply::Settings(settings)) = settings else {
        panic!("{settings:?}")
    };
    assert_eq!(
        settings.workstation.diagnostics.settled,
        Settled {
            value: Diagnostics::Detail,
            said: Said::Person(Span::Run),
        }
    );

    let again = ask(
        &mut core,
        link,
        4,
        Request::Diagnose(Some(Diagnostics::Detail)),
    );
    assert_eq!(reply(&again, link).1, Ok(Reply::Done(Changed::Unchanged)));
    assert_eq!(again.entries, Vec::new());

    let back = ask(&mut core, link, 5, Request::Diagnose(None));
    assert_eq!(reply(&back, link).1, Ok(Reply::Done(Changed::Changed)));
    assert!(
        back.effects
            .contains(&Effect::Diagnose(Diagnostics::Faults))
    );
}

/// Nothing is answered before the greeting, and the greeting records what
/// the pipe said of the client - which the client never states and the core
/// never refuses on: a terminal over SSH is greeted as the desktop is.
#[test]
fn the_greeting_records_what_the_pipe_said_and_refuses_nobody_for_it() {
    let mut core = core();
    let link = Link(1);
    core.step(
        Input::Arrived {
            link,
            peer: Some(OVER_SSH.into()),
        },
        NOW,
    );
    let early = ask(&mut core, link, 1, Request::Status);
    assert_eq!(
        reply(&early, link),
        (1, Err(Refusal::NotGreeted), Then::Continue)
    );
    assert_eq!(early.entries, Vec::<Entry>::new());

    let hello = Request::Hello {
        protocol: PROTOCOL,
        kind: ClientKind::Terminal,
        attends: Remotes::Every,
    };
    let step = ask(&mut core, link, 2, hello);
    let welcome = Reply::Welcome {
        protocol: PROTOCOL,
        version: "0.2.0".to_owned(),
        you: OVER_SSH,
    };
    assert_eq!(reply(&step, link), (2, Ok(welcome), Then::Continue));
    let attached = step.entries.first().unwrap();
    assert_eq!(
        attached.event,
        Event::Attached {
            kind: ClientKind::Terminal,
            origin: OVER_SSH,
            attends: Remotes::Every,
        }
    );
    // The person is reachable through it, whatever session it is in.
    assert!(core.state().reachable(&somewhere(), &Sets::NONE));
    assert_eq!(
        core.state().surface(ClientId(attached.seq)).unwrap().origin,
        OVER_SSH
    );
}

#[test]
fn a_client_of_another_version_or_one_nothing_is_known_of_is_told_and_let_go() {
    let mut core = core();
    let old = Link(1);
    core.step(
        Input::Arrived {
            link: old,
            peer: Some(DESKTOP.into()),
        },
        NOW,
    );
    let hello = |protocol| Request::Hello {
        protocol,
        kind: ClientKind::Command,
        attends: Remotes::Every,
    };
    let step = ask(&mut core, old, 1, hello(PROTOCOL + 1));
    let refused = Err(Refusal::Version {
        core: PROTOCOL,
        client: PROTOCOL + 1,
    });
    assert_eq!(reply(&step, old), (1, refused, Then::Close));
    assert_eq!(step.entries, Vec::<Entry>::new());

    // A client that opened the pipe letting the core learn nothing of it.
    let hidden = Link(2);
    core.step(
        Input::Arrived {
            link: hidden,
            peer: None,
        },
        NOW,
    );
    let step = ask(&mut core, hidden, 1, hello(PROTOCOL));
    assert_eq!(
        reply(&step, hidden),
        (1, Err(Refusal::Unattributable), Then::Close)
    );
    assert_eq!(step.entries, Vec::<Entry>::new());
}

/// A line that carries an id is refused to that id and the connection goes
/// on; one that carries none is refused to id 0 and the connection ends,
/// because nothing can say which reply would answer the client's next.
#[test]
fn a_line_that_is_not_a_request_is_refused_to_its_id_or_ends_the_connection() {
    let mut core = core();
    let link = Link(1);
    attend(&mut core, link, ClientKind::Command, DESKTOP);
    let garbled = |id| Input::Garbled {
        link,
        id,
        account: "request has \"reboot\", which is not known here".to_owned(),
    };
    let malformed = || {
        Err(Refusal::Malformed(
            "request has \"reboot\", which is not known here".to_owned(),
        ))
    };
    let step = core.step(garbled(Some(7)), NOW);
    assert_eq!(reply(&step, link), (7, malformed(), Then::Continue));
    let step = core.step(garbled(None), NOW);
    assert_eq!(reply(&step, link), (0, malformed(), Then::Close));
}

/// Six requests act on a channel. On a route nobody defined, for a request
/// no remote made, a prompt no client raised, a connection that is not live
/// and a capability the remote does not hold, the gate refuses each before
/// the core would have to carry one out.
#[test]
fn the_requests_that_need_a_channel_are_refused_at_the_gate() {
    let mut core = core();
    let link = Link(1);
    attend(&mut core, link, ClientKind::Terminal, OVER_SSH);
    let remote = RemoteId {
        route: Name::try_from("lab").unwrap(),
        address: Address::try_from("dev/build").unwrap(),
    };
    let gpg = Name::try_from("gpg").unwrap();
    let grant = Request::Change(Change::Grant {
        grant: Grant {
            capability: gpg.clone(),
            remotes: Granted::Route(remote.route.clone()),
        },
        terms: Terms {
            activation: Activation::OnRequest,
            setup: Setup::Inspect,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    });
    let connection = ConnectionId(Seq(900));
    let cases = [
        (grant, Refusal::UnknownRoute(remote.route.clone())),
        (
            Request::Connect {
                remote: remote.clone(),
                with: Vec::new(),
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
            Refusal::UnknownRoute(remote.route.clone()),
        ),
        (
            Request::Decide {
                request: RequestId(Seq(900)),
                decision: Decision::Once,
            },
            Refusal::UnknownRequest(RequestId(Seq(900))),
        ),
        (
            Request::Answer {
                prompt: PromptId(Seq(900)),
                answer: Answer::Text(Secret::from("correct horse".to_owned())),
            },
            Refusal::UnknownPrompt(PromptId(Seq(900))),
        ),
        (
            Request::Rule {
                connection,
                scope: ConnectionScope {
                    capability: Selector::Every,
                    operation: Selector::Every,
                    key: Keys::Every,
                },
                mode: None,
            },
            Refusal::UnknownConnection(connection),
        ),
        (
            Request::Check {
                remote: remote.clone(),
                capability: gpg.clone(),
            },
            Refusal::NotGranted {
                capability: gpg.clone(),
                remote: remote.clone(),
            },
        ),
        (
            Request::Exercise {
                remote: remote.clone(),
                capability: gpg.clone(),
            },
            Refusal::NotGranted {
                capability: gpg,
                remote: remote.clone(),
            },
        ),
    ];
    for (id, (request, refusal)) in (2u32..).zip(cases) {
        let step = ask(&mut core, link, id, request);
        assert_eq!(reply(&step, link), (id, Err(refusal), Then::Continue));
        assert!(step.entries.is_empty() && step.keep.is_none());
        written(&mut core, link, 1);
    }
    // What needs no channel is carried out: there is nothing to disconnect.
    let step = ask(&mut core, link, 20, Request::Disconnect { remote });
    assert_eq!(reply(&step, link).1, Ok(Reply::Done(Changed::Unchanged)));
}

/// A change is recorded, kept and answered in one step, in that order: the
/// entry goes to disk, then the document, and only then is the client told.
#[test]
fn a_change_is_recorded_and_kept_before_it_is_answered() {
    let mut core = core();
    let link = Link(1);
    attend(&mut core, link, ClientKind::Command, DESKTOP);
    let on = || Request::Change(Change::Autostart(Some(Autostart::AtLogon)));
    let step = ask(&mut core, link, 2, on());
    assert!(matches!(
        step.entries.first().map(|entry| &entry.event),
        Some(Event::Changed {
            change: Change::Autostart(Some(Autostart::AtLogon)),
            ..
        })
    ));
    let keep = step.keep.as_ref().unwrap();
    assert_eq!(keep.document.autostart, Some(Autostart::AtLogon));
    assert_eq!(
        Some(keep.entry),
        step.entries.first().map(|entry| entry.seq)
    );
    assert_eq!(
        reply(&step, link).1,
        Ok(Reply::Changed {
            effect: Changed::Changed,
            held: Vec::new()
        })
    );
    assert_eq!(core.configuration().autostart(), Some(Autostart::AtLogon));
    written(&mut core, link, 1);

    // Said twice, it changes nothing, records nothing and keeps nothing.
    let step = ask(&mut core, link, 3, on());
    assert_eq!(
        reply(&step, link).1,
        Ok(Reply::Changed {
            effect: Changed::Unchanged,
            held: Vec::new()
        })
    );
    assert!(step.entries.is_empty() && step.keep.is_none());
}

/// A client that follows the trail is a position in it. However far behind
/// it reads, the core holds no more for it than the few frames in flight,
/// and it is given every entry, once, in order.
#[test]
fn a_follower_that_reads_slowly_gets_every_entry_in_order_and_costs_nothing() {
    let mut core = core();
    let (follower, busy) = (Link(1), Link(2));
    attend(&mut core, follower, ClientKind::Command, DESKTOP);
    attend(&mut core, busy, ClientKind::Command, DESKTOP);
    let step = ask(&mut core, follower, 2, Request::Follow { after: None });
    assert_eq!(reply(&step, follower).1, Ok(Reply::Done(Changed::Changed)));
    written(&mut core, follower, 1);

    // A hundred changes while the follower reads nothing.
    let mut recorded = Vec::new();
    let mut received = Vec::new();
    for round in 0..100u8 {
        let step = ask(&mut core, busy, u32::from(round) + 2, burst(round + 1));
        recorded.extend(step.entries.iter().map(|entry| entry.seq));
        received.extend(notices(&step, follower));
        written(&mut core, busy, 1);
    }
    assert_eq!(recorded.len(), 100);
    assert_eq!(
        received.len(),
        usize::from(WAITING) - 1,
        "what is in flight is all that waits for it"
    );

    // As it reads, each frame written makes room for the next entry.
    while received.len() < recorded.len() {
        let before = received.len();
        for step in written(&mut core, follower, 1) {
            received.extend(notices(&step, follower));
        }
        assert_eq!(received.len(), before + 1);
    }
    let got: Vec<Seq> = received
        .iter()
        .map(|notice| match notice {
            Notice::Recorded(entry) => entry.seq,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(got, recorded);

    // Caught up, it is given nothing until something is recorded.
    assert!(
        written(&mut core, follower, usize::from(WAITING) - 1)
            .iter()
            .all(|step| step.effects.is_empty())
    );
    let step = ask(&mut core, busy, 200, burst(7));
    assert_eq!(notices(&step, follower).len(), 1);

    // Following from an entry gives what was recorded after it.
    let late = Link(3);
    attend(&mut core, late, ClientKind::Command, DESKTOP);
    let from = *recorded.get(97).unwrap();
    let step = ask(&mut core, late, 2, Request::Follow { after: Some(from) });
    let caught: Vec<Seq> = notices(&step, late)
        .iter()
        .filter_map(|notice| match notice {
            Notice::Recorded(entry) => Some(entry.seq),
            _ => None,
        })
        .collect();
    assert!(
        caught.starts_with(recorded.get(98..).unwrap()),
        "{caught:?}"
    );
}

/// An attending client is told what it shows has gone stale. When it is not
/// reading, the telling does not pile up: each topic is held once and said
/// once when there is room, and the client asks again for what it shows.
#[test]
fn a_notice_that_does_not_fit_is_said_once_when_there_is_room() {
    let mut core = core();
    let (terminal, busy) = (Link(1), Link(2));
    attend(&mut core, terminal, ClientKind::Terminal, OVER_SSH);
    attend(&mut core, busy, ClientKind::Command, DESKTOP);
    // Greeting `busy` told the terminal its status was stale; it reads that.
    written(&mut core, terminal, 1);

    let mut told = Vec::new();
    for round in 0..60u8 {
        let step = ask(&mut core, busy, u32::from(round) + 2, burst(round + 1));
        told.extend(notices(&step, terminal));
        assert!(
            notices(&step, busy).is_empty(),
            "the one who acted is not told"
        );
        written(&mut core, busy, 1);
    }
    assert_eq!(told.len(), usize::from(WAITING) - 1);

    // It reads what was in flight; what did not fit follows once per topic.
    let mut later = Vec::new();
    for step in written(&mut core, terminal, told.len()) {
        later.extend(notices(&step, terminal));
    }
    let mut topics: Vec<Topic> = later
        .iter()
        .map(|notice| match notice {
            Notice::Stale(topic) => topic.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    topics.sort();
    assert_eq!(
        topics,
        [Topic::Exposure, Topic::Attention, Topic::Configuration]
    );
    // And then nothing more: nothing was queued behind them.
    assert!(
        written(&mut core, terminal, later.len())
            .iter()
            .all(|step| step.effects.is_empty())
    );

    // A reply always has its place, however many notices are in flight.
    for round in 0..60u8 {
        ask(&mut core, busy, u32::from(round) + 100, burst(round + 1));
        written(&mut core, busy, 1);
    }
    let step = ask(&mut core, terminal, 9, Request::Attention);
    assert!(matches!(reply(&step, terminal).1, Ok(Reply::Attention(_))));
}

#[test]
fn stopping_records_who_asked_and_ends_the_core_after_the_reply() {
    let mut core = core();
    let link = Link(1);
    attend(&mut core, link, ClientKind::Command, DESKTOP);
    let step = ask(&mut core, link, 2, Request::Stop);
    assert!(matches!(
        step.entries.first().map(|entry| &entry.event),
        Some(Event::Stopping { .. })
    ));
    assert_eq!(
        reply(&step, link),
        (2, Ok(Reply::Done(Changed::Changed)), Then::Stop)
    );
}

/// A client that leaves is detached in the trail, and with the last surface
/// gone the person is no longer reachable.
#[test]
fn a_client_that_leaves_is_recorded_as_gone() {
    let mut core = core();
    let link = Link(1);
    attend(&mut core, link, ClientKind::Terminal, OVER_SSH);
    assert!(core.state().reachable(&somewhere(), &Sets::NONE));
    let step = core.step(Input::Left { link }, NOW);
    assert!(matches!(
        step.entries.first().map(|entry| &entry.event),
        Some(Event::Detached { .. })
    ));
    assert!(!core.state().reachable(&somewhere(), &Sets::NONE));
    // A connection that never greeted leaves no entry behind.
    core.step(
        Input::Arrived {
            link: Link(2),
            peer: Some(DESKTOP.into()),
        },
        NOW,
    );
    assert_eq!(
        core.step(Input::Left { link: Link(2) }, NOW).entries,
        Vec::<Entry>::new()
    );
}

/// What a person puts away stays put away, through this core as through the
/// model: the request is recorded and the item is gone.
#[test]
fn attention_the_core_itself_raised_is_shown_and_put_away() {
    let mut core = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        Vec::new(),
        "0.2.0".to_owned(),
    );
    let crashed = Breakdown::Exited { status: 101 };
    core.begin(DESKTOP, Some(crashed), Vec::new(), NOW);
    let link = Link(1);
    attend(&mut core, link, ClientKind::Interface, DESKTOP);
    let step = ask(&mut core, link, 2, Request::Attention);
    let Ok(Reply::Attention(items)) = reply(&step, link).1 else {
        panic!("{step:?}");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(
        items.first().unwrap().attention.item(),
        Some(Item::Restarted)
    );
    written(&mut core, link, 1);
    ask(&mut core, link, 3, Request::PutAway(Item::Restarted));
    written(&mut core, link, 1);
    let step = ask(&mut core, link, 4, Request::Attention);
    assert_eq!(reply(&step, link).1, Ok(Reply::Attention(Vec::new())));
    let step = ask(&mut core, link, 5, Request::Pause(Remotes::Every));
    assert_eq!(reply(&step, link).1, Ok(Reply::Done(Changed::Changed)));
}

/// The workstation sleeps and wakes. Both are entries, a follower is given
/// them, and nothing a surface shows is called stale. The run goes on as it
/// was: who was attached is attached, and what was paused is paused.
#[test]
fn a_sleep_and_a_wake_are_recorded_and_the_run_goes_on() {
    let mut core = core();
    let (terminal, follower) = (Link(1), Link(2));
    attend(&mut core, terminal, ClientKind::Terminal, OVER_SSH);
    attend(&mut core, follower, ClientKind::Command, DESKTOP);
    let step = ask(&mut core, follower, 2, Request::Follow { after: None });
    let owed = sent(&step, follower).len();
    written(&mut core, follower, owed);
    let step = ask(&mut core, terminal, 2, Request::Pause(Remotes::Every));
    written(&mut core, terminal, sent(&step, terminal).len());
    written(&mut core, follower, sent(&step, follower).len());

    let slept = core.step(Input::Turned(Turn::Sleeping), NOW);
    let woke = core.step(Input::Turned(Turn::Woke), NOW);
    let events = |step: &Step| -> Vec<Event> {
        step.entries
            .iter()
            .map(|entry| entry.event.clone())
            .collect()
    };
    assert_eq!(events(&slept), [Event::Sleeping]);
    assert_eq!(events(&woke), [Event::Woke]);
    assert!(sent(&slept, terminal).is_empty() && sent(&woke, terminal).is_empty());
    assert!(matches!(
        notices(&slept, follower).as_slice(),
        [Notice::Recorded(entry)] if entry.event == Event::Sleeping
    ));
    written(&mut core, follower, 1);
    assert!(matches!(
        notices(&woke, follower).as_slice(),
        [Notice::Recorded(entry)] if entry.event == Event::Woke
    ));

    assert!(
        core.state().reachable(&somewhere(), &Sets::NONE),
        "the terminal is still attached"
    );
    let host = RemoteId {
        route: Name::try_from("ssh").unwrap(),
        address: Address::try_from("build").unwrap(),
    };
    assert!(core.state().paused(&host, &Sets::NONE));
}
