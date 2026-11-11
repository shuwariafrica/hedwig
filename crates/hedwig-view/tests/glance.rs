//! The notification-area presence: what the icon says, and what its menu
//! offers, in every state the core can be in.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Instant;

use hedwig_model::capability::{Exposure, Lends, Operation};
use hedwig_model::config::{Activation, Change};
use hedwig_model::gate::Verdict;
use hedwig_model::organisation::{Limit, Part, Start};
use hedwig_model::policy::{ConnectionScope, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{Attention, Needs, Notice, Request, Served, Topic};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::scope::Audience;
use hedwig_model::setting::Volume;
use hedwig_model::text::{Fingerprint, Grip, RemotePath, Serial};
use hedwig_model::trail::{
    Card, ChannelEnd, ConnectionId, Event as Happened, Finding, Held, Readiness, RequestId, Seq,
    SignaturePin, Touch,
};
use hedwig_model::wire::line;
use hedwig_view::act::Act;
use hedwig_view::emblem::{Badge, Emblem, Owl};
use hedwig_view::glance::{self, Announcement, Entry, Glance, Reach, TEXT, TIP, Waiting};
use hedwig_view::link::{Core, Effect, Event, Place, Seen};
use hedwig_view::words::Keyrings;

mod common;
use common::Bench;
use common::support::{grant, name, remote, terms};

fn granting(id: &str, remotes: Granted, activation: Activation) -> Request {
    Request::Change(Change::Grant {
        grant: grant(id, remotes),
        terms: terms(activation, Exposure::NONE),
    })
}

/// The core told its attending clients that what they show is stale.
fn refresh(bench: &mut Bench) {
    for topic in [
        Topic::Status,
        Topic::Exposure,
        Topic::Attention,
        Topic::Workstation,
    ] {
        bench.notice(Notice::Stale(topic));
    }
}

fn workspace() -> RemoteId {
    remote("coder", "dev/build")
}

fn host() -> RemoteId {
    remote("ssh", "build.example")
}

/// `gpg` granted to every Coder workspace and to one host, and the workspace
/// connected and serving.
fn serving() -> (Bench, ConnectionId) {
    let mut bench = Bench::attached();
    bench.feed(Event::Wish(
        Place::Window,
        granting(
            "gpg",
            Granted::Route(name("coder")),
            Activation::WhileRunning,
        ),
    ));
    bench.feed(Event::Wish(
        Place::Window,
        granting("gpg", Granted::One(host()), Activation::OnRequest),
    ));
    let connection = bench.desk.channel_up(&workspace(), "linux");
    refresh(&mut bench);
    (bench, connection)
}

fn asking_first(bench: &mut Bench, remote: &RemoteId) {
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::One(remote.clone()),
                capability: Selector::Every,
                operation: Selector::Only(Operation::Sign),
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    ));
}

fn glance(bench: &Bench) -> Glance {
    Glance::of(bench.link.seen())
}

/// Every act a menu holds, through its groups.
fn acts(entries: &[Entry]) -> Vec<(&str, &Act)> {
    entries
        .iter()
        .flat_map(|entry| match entry {
            Entry::Act { label, act, .. } => vec![(label.as_str(), act)],
            Entry::Group { entries, .. } => acts(entries),
            _ => Vec::new(),
        })
        .collect()
}

fn labels(entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| match entry {
            Entry::Line(text) => format!("  {text}"),
            Entry::Rule => "  ---".to_owned(),
            Entry::Act { label, chief, .. } => {
                format!("{} {label}", if *chief { "*" } else { " " })
            }
            Entry::Group { label, .. } => format!("  > {label}"),
        })
        .collect()
}

/// A person mid-work elsewhere, glancing: is what I expose as I intend, and is
/// anything asking me? Each answer is read from the core's rows and
/// attention, and the two are told apart.
#[test]
fn the_icon_answers_both_questions_from_what_the_core_says() {
    // Nothing granted, nothing connected.
    let bench = Bench::attached();
    assert_eq!(
        (glance(&bench).reach, glance(&bench).waiting),
        (Reach::Quiet, Waiting::Nothing)
    );
    assert_eq!(glance(&bench).tip(), "Hedwig - nothing is connected");
    assert_eq!(
        Emblem::of(&glance(&bench)),
        Emblem {
            owl: Owl::Dozing,
            badge: Badge::Nothing
        }
    );

    // One remote reaches something: a row is serving.
    let (mut bench, connection) = serving();
    assert_eq!(glance(&bench).reach, Reach::Reachable(1));
    assert_eq!(glance(&bench).tip(), "Hedwig - reachable from 1 remote");

    // A second, and then a request held for the person.
    bench.desk.channel_up(&host(), "linux");
    asking_first(&mut bench, &workspace());
    let (_, verdict) = bench.desk.asks(connection, "gpg", Operation::Sign);
    assert!(matches!(verdict, Verdict::Hold(_)));
    refresh(&mut bench);
    assert_eq!(
        (glance(&bench).reach, glance(&bench).waiting),
        (Reach::Reachable(2), Waiting::Answer(1))
    );
    assert_eq!(
        glance(&bench).tip(),
        "Hedwig - reachable from 2 remotes - 1 waiting for your answer"
    );
    assert_eq!(
        Emblem::of(&glance(&bench)),
        Emblem {
            owl: Owl::Awake,
            badge: Badge::Answer
        }
    );

    // What waits for a look is counted apart, and never hides what is held.
    bench.desk.trail.push(Happened::Card(Card {
        serial: Serial::try_from("D2760001240103040006123456780000").unwrap(),
        keys: vec![Held {
            grip: Grip::try_from("AA11BB22CC33DD44EE55FF6600771188992233AA").unwrap(),
            touch: Some(Touch::Off),
        }],
        pin: Some(SignaturePin::Forced),
    }));
    refresh(&mut bench);
    assert_eq!(glance(&bench).waiting, Waiting::Answer(1));
    let held = match bench.attention().first().map(|needs| &needs.attention) {
        Some(Attention::Request { request, .. }) => *request,
        other => unreachable!("{other:?}"),
    };
    bench.feed(Event::Wish(
        Place::Card,
        Request::Decide {
            request: held,
            decision: hedwig_model::protocol::Decision::Once,
        },
    ));
    assert_eq!(glance(&bench).waiting, Waiting::Look(1));
    assert_eq!(
        glance(&bench).tip(),
        "Hedwig - reachable from 2 remotes - 1 to look at"
    );
    assert_eq!(Emblem::of(&glance(&bench)).badge, Badge::Look);

    // One remote paused is not everything paused.
    bench.feed(Event::Wish(
        Place::Tray,
        Request::Pause(Remotes::One(host())),
    ));
    assert_eq!(glance(&bench).reach, Reach::Reachable(1));

    // Everything paused: nothing is reachable, and the icon says which.
    bench.feed(Event::Wish(Place::Tray, Request::Pause(Remotes::Every)));
    assert_eq!(glance(&bench).reach, Reach::Paused);
    assert_eq!(
        glance(&bench).tip(),
        "Hedwig - all exposure is paused - 1 to look at"
    );
    assert_eq!(
        Emblem::of(&glance(&bench)),
        Emblem {
            owl: Owl::Dozing,
            badge: Badge::Look
        }
    );
}

/// A remote that failed readiness, a channel that stopped for a reason only
/// the person can fix and a refusal the person did not make are each
/// something to look at, never an interruption. A channel that comes back by
/// itself needs nobody: it is on its row, and its remote stays in the menu.
#[test]
fn what_waits_for_a_look_is_not_an_interruption() {
    let (mut bench, connection) = serving();
    bench.desk.trail.push(Happened::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![
            Finding::AgentLive(RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap()),
            Finding::PublicKeyAbsent(key()),
        ]),
    });
    refresh(&mut bench);
    assert_eq!(glance(&bench).waiting, Waiting::Look(1));
    // A row that is not ready is not reachable.
    assert_eq!(glance(&bench).reach, Reach::Quiet);

    // Lost with nothing wanting it, it is the row's alone.
    bench.desk.trail.push(Happened::Down {
        connection,
        end: ChannelEnd::ForwardRefused,
    });
    refresh(&mut bench);
    assert_eq!(glance(&bench).waiting, Waiting::Look(1));

    // The person connects it, so it is wanted: lost again, it comes back by
    // itself, needs nobody, and its remote stays in the menu saying so. What
    // the lost channel's readiness found went with it.
    bench.feed(Event::Wish(
        Place::Tray,
        Request::Connect {
            remote: workspace(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    ));
    let up = bench.desk.channel_up(&workspace(), "linux");
    bench.desk.trail.push(Happened::Down {
        connection: up,
        end: ChannelEnd::ForwardRefused,
    });
    refresh(&mut bench);
    assert_eq!(glance(&bench).waiting, Waiting::Nothing);
    let menu = glance::menu(bench.link.seen(), Instant::now());
    let own = menu
        .iter()
        .find_map(|entry| match entry {
            Entry::Group { label, entries } if *label == workspace().to_string() => Some(entries),
            _ => None,
        })
        .expect("the remote is in the menu");
    assert_eq!(
        labels(own).first().map(String::as_str),
        Some(
            "  gpg: connecting again by itself in 1 second: the remote's SSH server refused the \
             forward"
        )
    );

    let again = bench.desk.channel_up(&workspace(), "linux");
    bench.desk.trail.push(Happened::Down {
        connection: again,
        end: ChannelEnd::RouteNotSignedIn,
    });
    refresh(&mut bench);
    assert_eq!(glance(&bench).waiting, Waiting::Look(1));
}

/// Until the core has said what is exposed, the icon says it is asking - it
/// never shows "nothing is connected" for "not yet told".
#[test]
fn not_yet_told_is_never_shown_as_nothing() {
    let mut bench = Bench::new();
    bench
        .link
        .handle(Event::Looked(common::serving(common::pipe('a'))));
    bench.link.handle(Event::Opened);
    bench.link.handle(Event::Frame(
        hedwig_model::protocol::FromCore::Reply {
            id: 1,
            reply: Ok(hedwig_model::protocol::Reply::Welcome {
                protocol: hedwig_model::protocol::PROTOCOL,
                version: "0.2.0".to_owned(),
                you: common::support::DESKTOP,
            }),
        },
        Instant::now(),
    ));
    let glance = Glance::of(bench.link.seen());
    assert_eq!(glance.reach, Reach::Wait);
    assert_eq!(glance.tip(), "Hedwig - asking what is exposed");
    assert_eq!(
        labels(&glance::menu(bench.link.seen(), Instant::now())),
        [
            "  Asking Hedwig what is exposed",
            "  ---",
            "  Close this icon"
        ]
    );
}

/// The shell keeps 127 units of a tooltip. No state's tooltip is ever cut,
/// and whatever a core says is fitted rather than overrun.
#[test]
fn a_tooltip_always_fits_what_the_shell_keeps() {
    let long = "x".repeat(400);
    let states = [
        Core::Absent,
        Core::Starting,
        Core::Restarting {
            cause: hedwig_model::trail::Breakdown::Exited { status: u32::MAX },
            said: long.clone(),
        },
        Core::Unreachable(long.clone()),
        Core::Refused(Refusal::Malformed(long)),
    ];
    for core in states {
        let seen = Seen { core };
        let tip = Glance::of(&seen).tip().to_owned();
        assert!(tip.encode_utf16().count() <= TIP, "{tip}");
        assert!(!tip.ends_with("..."), "cut: {tip}");
        // The whole reason is in the menu's first line instead.
        assert!(matches!(
            glance::menu(&seen, Instant::now()).first(),
            Some(Entry::Line(_))
        ));
    }
    let (mut bench, _) = serving();
    bench.feed(Event::Wish(Place::Tray, Request::Pause(Remotes::Every)));
    assert!(glance(&bench).tip().encode_utf16().count() <= TIP);
}

/// The menu as the person reads it, with a workspace serving and a request
/// held: what is waiting comes first and is the default.
#[test]
fn the_menu_puts_what_is_waiting_first() {
    let (mut bench, connection) = serving();
    assert_eq!(
        labels(&glance::menu(bench.link.seen(), Instant::now())),
        [
            "* Open Hedwig",
            "  ---",
            "  Pause all exposure",
            "  ---",
            "  > dev/build (coder)",
            "  ---",
            "  Stop Hedwig...",
            "  Close this icon",
        ]
    );
    assert_eq!(glance::chosen(bench.link.seen()), Act::Open(None));

    asking_first(&mut bench, &workspace());
    bench.desk.asks(connection, "gpg", Operation::Sign);
    refresh(&mut bench);
    let menu = glance::menu(bench.link.seen(), Instant::now());
    assert_eq!(
        labels(&menu).first().map(String::as_str),
        Some("* Answer what is waiting (1)")
    );
    assert_eq!(glance::chosen(bench.link.seen()), Act::Answer);
}

/// From the menu, in one gesture, the
/// person can only reduce what is reachable or have more asked of them:
/// pause everything, pause or disconnect one remote, be asked first. What
/// widens exposure is put to them first with what it does.
#[test]
fn one_gesture_from_the_menu_only_ever_reduces_exposure() {
    let (mut bench, connection) = serving();
    let menu = glance::menu(bench.link.seen(), Instant::now());
    let sent: Vec<&Request> = acts(&menu)
        .into_iter()
        .filter_map(|(_, act)| match act {
            Act::Send(request) => Some(request),
            _ => None,
        })
        .collect();
    assert_eq!(
        sent,
        [
            &Request::Pause(Remotes::Every),
            // Down to one connection: the row names its connection.
            &Request::Rule {
                connection,
                scope: ConnectionScope {
                    capability: Selector::Every,
                    operation: Selector::Every,
                    key: Keys::Every,
                },
                mode: Some(Mode::Confirm),
            },
            &Request::Change(Change::Rule {
                scope: RuleScope {
                    remotes: Remotes::One(workspace()),
                    capability: Selector::Every,
                    operation: Selector::Every,
                    key: Keys::Every,
                },
                mode: Mode::Confirm,
            }),
            &Request::Pause(Remotes::One(workspace())),
            &Request::Disconnect {
                remote: workspace()
            },
        ]
    );

    // Paused, the way back is a confirmation that says what comes back.
    bench.feed(Event::Wish(Place::Tray, Request::Pause(Remotes::Every)));
    let menu = glance::menu(bench.link.seen(), Instant::now());
    let resume = acts(&menu)
        .into_iter()
        .find(|(label, _)| *label == "Resume all exposure...")
        .map(|(_, act)| act);
    assert_eq!(
        resume,
        Some(&Act::Confirm {
            request: Request::Resume(Remotes::Every),
            consequence: "Everything you have granted becomes reachable from its remotes again."
                .to_owned(),
            answer: "Resume all exposure".to_owned(),
        })
    );
    assert!(
        acts(&menu)
            .iter()
            .all(|(_, act)| !matches!(act, Act::Send(Request::Resume(_))))
    );
}

/// Whatever the menu offers, the core carries out: every request it holds is
/// one the gate permits for the interface now.
#[test]
fn what_the_menu_offers_the_core_accepts() {
    let (mut bench, connection) = serving();
    bench.desk.channel_up(&host(), "linux");
    asking_first(&mut bench, &workspace());
    bench.desk.asks(connection, "gpg", Operation::Sign);
    refresh(&mut bench);
    for paused in [false, true] {
        if paused {
            bench.feed(Event::Wish(Place::Tray, Request::Pause(Remotes::Every)));
        }
        let menu = glance::menu(bench.link.seen(), Instant::now());
        let mut checked = 0;
        for (label, act) in acts(&menu) {
            let (Act::Send(request) | Act::Confirm { request, .. }) = act else {
                continue;
            };
            assert_eq!(bench.permits(request), Ok(()), "{label}");
            checked += 1;
        }
        assert!(checked >= 1, "paused {paused}: {checked}");
    }
}

/// Being asked first for a remote is offered until it is so, and then is not
/// offered again.
#[test]
fn being_asked_first_is_offered_until_it_is_so() {
    let (mut bench, _) = serving();
    let always = "Always ask me first for this remote";
    let menu = glance::menu(bench.link.seen(), Instant::now());
    let request = acts(&menu)
        .into_iter()
        .find(|(label, _)| *label == always)
        .map(|(_, act)| match act {
            Act::Send(request) => common::clone(request),
            other => unreachable!("{other:?}"),
        })
        .expect("offered");
    bench.feed(Event::Wish(Place::Tray, request));
    let row = bench
        .rows()
        .iter()
        .find(|row| row.remote == Some(workspace()));
    assert!(
        row.unwrap()
            .decides
            .iter()
            .all(|decides| decides.mode == Mode::Confirm)
    );
    let menu = glance::menu(bench.link.seen(), Instant::now());
    assert!(acts(&menu).iter().all(|(label, _)| *label != always));
}

/// A core started from an SSH session into the workstation persists
/// after that session: the desktop's icon says where it came from, and stops
/// it with one act.
#[test]
fn a_core_started_from_an_ssh_session_is_shown_and_stopped_by_one_act() {
    let mut bench = Bench::over_ssh();
    bench.attach();
    let menu = glance::menu(bench.link.seen(), Instant::now());
    assert_eq!(
        menu.first(),
        Some(&Entry::Line(
            "Hedwig was started outside this desktop, in session 0".to_owned()
        ))
    );
    assert!(
        acts(&menu)
            .iter()
            .any(|(label, act)| *label == "Stop Hedwig..." && matches!(act, Act::Stop { .. }))
    );
    // A core started at this desktop says nothing of the kind.
    let bench = Bench::attached();
    assert!(!matches!(
        glance::menu(bench.link.seen(), Instant::now()).first(),
        Some(Entry::Line(_))
    ));
}

/// The entries of one remote's own menu.
fn own(menu: &[Entry], remote: &RemoteId) -> Vec<String> {
    menu.iter()
        .find_map(|entry| match entry {
            Entry::Group { label, entries } if *label == remote.to_string() => {
                Some(labels(entries))
            }
            _ => None,
        })
        .expect("the remote is in the menu")
}

/// A person glancing on a workstation the organisation set up: a grant the
/// person did not make is said to be the organisation's where it shows.
#[test]
fn a_grant_the_organisation_started_is_said_to_be_its_own() {
    let mut bench = Bench::attached();
    let started = Start::Grant {
        grant: grant("gpg", Granted::One(host())),
        activation: Activation::OnRequest,
    };
    bench.govern(&[(Part::Start, line(&started))]);
    bench.desk.channel_up(&host(), "linux");
    refresh(&mut bench);
    let shown = own(&glance::menu(bench.link.seen(), Instant::now()), &host());
    assert!(
        shown.first().is_some_and(
            |first| first.starts_with("  gpg, from your organisation's starting point: ")
        ),
        "{shown:?}"
    );
    // The person's own acts on the remote are unchanged by whose grant it is.
    assert!(shown.contains(&"  Always ask me first for this remote".to_owned()));
}

/// With no network, channels wait for one: the icon says so, so a remote
/// that reaches nothing is not taken for one that broke.
#[test]
fn no_network_is_said_at_a_glance() {
    let (mut bench, _) = serving();
    bench.desk.trail.push(Happened::Offline);
    refresh(&mut bench);
    assert!(
        glance(&bench).tip().ends_with(" - no network"),
        "{}",
        glance(&bench).tip()
    );
    assert!(
        labels(&glance::menu(bench.link.seen(), Instant::now()))
            .contains(&"  There is no network: connections wait for one".to_owned())
    );
    bench.desk.trail.push(Happened::Online);
    refresh(&mut bench);
    assert!(!glance(&bench).tip().contains("network"));
}

/// The core says how loudly each thing reaches this client: what
/// is only shown is counted and never announced; what is announced or
/// interrupts is handed on to be said, once, with whom to ask where the
/// organisation's policy refused it. A request served without asking is
/// announced as what the remote did.
#[test]
fn what_the_core_raises_is_said_as_loudly_as_it_says_and_once() {
    let mut bench = Bench::attached();
    let desk = "the service desk, extension 4400";
    bench.govern(&[(Part::Ask, desk.to_owned())]);
    refresh(&mut bench);
    let held = Refusal::Held {
        audience: Audience::Machine,
        limit: Box::new(Limit::Withhold {
            exposure: Exposure::SECRET,
            remotes: Remotes::Every,
        }),
    };
    let item = |volume| Needs {
        attention: Attention::Refused {
            remote: Some(host()),
            refusal: held.clone(),
            times: 1,
        },
        volume,
    };

    let effects = bench.notice(Notice::Raised(item(Volume::Shown)));
    assert!(
        !effects
            .iter()
            .any(|effect| matches!(effect, Effect::Raised(_))),
        "{effects:?}"
    );

    let effects = bench.notice(Notice::Raised(item(Volume::Announced)));
    assert!(effects.contains(&Effect::Raised(item(Volume::Announced))));
    let said = Announcement::of(
        &item(Volume::Announced),
        bench.contacts(),
        Keyrings::default(),
    );
    assert_eq!(said.title(), "Hedwig");
    assert_eq!(
        said.text(),
        format!("Refused once for build.example (ssh): {held}. Whom to ask: {desk}")
    );
    assert!(!said.now, "what is announced waits for a quiet moment");
    assert!(Announcement::of(&item(Volume::Interrupts), &[], Keyrings::default()).now);

    let served = Served {
        payload: None,
        request: RequestId(Seq(30)),
        remote: host(),
        capability: name("gpg"),
        operation: Operation::Sign,
        key: None,
    };
    let effects = bench.notice(Notice::Served(served.clone()));
    assert!(effects.contains(&Effect::Served(served.clone())));
    assert_eq!(
        Announcement::served(&served, Keyrings::default()).text(),
        "build.example (ssh) signed with gpg"
    );

    // Never longer than the shell keeps, and cut where it shows.
    let long = Needs {
        attention: Attention::Unlisted {
            route: name("coder"),
            account: hedwig_model::text::Words::try_from("x".repeat(400).as_str()).unwrap(),
        },
        volume: Volume::Announced,
    };
    let said = Announcement::of(&long, &[], Keyrings::default());
    assert_eq!(said.text().encode_utf16().count(), TEXT);
    assert!(said.text().ends_with("..."));
}

/// The key the workstation offers in these suites.
fn key() -> Fingerprint {
    Fingerprint::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap()
}

/// A refused icon is added again a second after, doubling, never later than
/// half a minute after the last try.
#[test]
fn a_refused_icon_is_added_again_sooner_then_less_often() {
    let waits: Vec<u64> = (0..9)
        .map(|tries| glance::added_again(tries).as_secs())
        .collect();
    assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30, 30, 30]);
    assert_eq!(glance::added_again(u32::MAX).as_secs(), 30);
}

/// An icon missing for two minutes is told to the person once, whatever
/// keeps it away, and counted afresh once it has been there; the loop is
/// woken for it, and not once it has been told.
#[test]
fn an_icon_missing_for_two_minutes_is_told_once() {
    use std::time::Duration;

    use glance::{Missing, UNSEEN_AFTER};
    use hedwig_model::trail::Missing as Unseen;

    assert_eq!(UNSEEN_AFTER, Duration::from_secs(120));
    let start = Instant::now();
    let at = |seconds: u64| start + Duration::from_secs(seconds);
    let mut missing = Missing::default();
    assert_eq!(missing.due(), None, "nothing is due before it is missed");
    assert_eq!(missing.missing(at(0), Unseen::Refused), None);
    assert_eq!(missing.due(), Some(at(120)));
    assert_eq!(missing.missing(at(119), Unseen::Refused), None);
    assert_eq!(
        missing.missing(at(121), Unseen::NoTaskbar),
        Some(Unseen::NoTaskbar),
        "why, as it is when told"
    );
    assert_eq!(missing.missing(at(300), Unseen::Refused), None, "once");
    assert_eq!(missing.due(), None);
    missing.shown();
    assert_eq!(missing.due(), None);
    assert_eq!(missing.missing(at(400), Unseen::Refused), None);
    assert_eq!(
        missing.missing(at(520), Unseen::Refused),
        Some(Unseen::Refused),
        "counted afresh"
    );
}
