//! What the core decides with what readiness found, driven with nothing else
//! running: which shell a remote is asked in, what is recorded of what was
//! found and done there, a check with and without a live channel, and an
//! exercise that waits on the remote's tool.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use hedwig_core::dispatch::{Core, Effect, Input, Link, Now, Step, Told};
use hedwig_core::survey::{Answer, At, Dialect, Place, Report, Undo, Unread};
use hedwig_model::capability::{Exposure, Lends, Query, Setup};
use hedwig_model::config::{
    Activation, Catalogue, Change, Configuration, Effect as Changed, Grant, Terms,
};
use hedwig_model::protocol::{
    FromCore, Notice, PROTOCOL, Proof, Reply, Request, Standing, ToCore, Written,
};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::text::{Address, Kernel, Name, Port, RemotePath, Words};
use hedwig_model::trail::{
    Binding, ChannelEnd, ClientKind, ConnectionId, Entry, Event, Finding, Integrity, Opener,
    Origin, Prepared, Readiness, Seq, Serving, Tick, Timestamp, Write,
};

mod common;

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

const LINK: Link = Link(1);

const SOCKET: &str = "/run/user/1000/gnupg/S.gpg-agent";

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn remote() -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from("dev@build-7.example").unwrap(),
    }
}

fn gpg() -> Serving {
    Serving {
        capability: name("gpg"),
        binding: Binding::Socket(RemotePath::try_from(SOCKET).unwrap()),
    }
}

fn adb() -> Serving {
    Serving {
        capability: name("adb"),
        binding: Binding::Port(Port::try_from(5037).unwrap()),
    }
}

struct Scene {
    core: Core,
    asked: u32,
}

impl Scene {
    /// A core with a terminal attached and `gpg` and `adb` granted to every
    /// remote on the `ssh` route, on request, with nothing written; `trail`
    /// is what earlier runs left.
    fn new(trail: Vec<Entry>) -> Scene {
        let mut core = Core::new(
            Catalogue::shipped().unwrap(),
            Configuration::default(),
            trail,
            "0.2.0".to_owned(),
        );
        core.begin(DESKTOP, None, Vec::new(), NOW);
        core.step(
            Input::Arrived {
                link: LINK,
                peer: Some(DESKTOP.into()),
            },
            NOW,
        );
        let mut scene = Scene { core, asked: 0 };
        scene.ask(Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Terminal,
            attends: Remotes::Every,
        });
        for capability in ["gpg", "adb"] {
            let acknowledged = if capability == "adb" {
                Exposure::SERVICE
            } else {
                Exposure::NONE
            };
            scene.ask(Request::Change(Change::Grant {
                grant: Grant {
                    capability: name(capability),
                    remotes: Granted::Route(name("ssh")),
                },
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Inspect,
                    acknowledged,
                    lends: Lends::none(),
                },
            }));
        }
        scene
    }

    fn ask(&mut self, request: Request) -> Step {
        self.asked += 1;
        let frame = ToCore {
            id: self.asked,
            request,
        };
        let step = self.core.step(Input::Asked { link: LINK, frame }, NOW);
        let step = common::keyed(&mut self.core, step, NOW);
        for _ in 0..step
            .effects
            .iter()
            .filter(|effect| matches!(effect, Effect::Send { .. }))
            .count()
        {
            self.core.step(Input::Sent { link: LINK }, NOW);
        }
        step
    }

    fn told(&mut self, connection: ConnectionId, told: Told) -> Step {
        let step = self.core.step(Input::Channel { connection, told }, NOW);
        common::keyed(&mut self.core, step, NOW)
    }

    fn connect(&mut self) -> (ConnectionId, Step) {
        let step = self.ask(Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        });
        let (connection, _) = self.core.state().connection(&remote()).unwrap();
        (connection, step)
    }

    /// A channel to the remote, up with both forwards bound.
    fn up(&mut self) -> ConnectionId {
        let (connection, _) = self.connect();
        self.told(connection, common::placing(&[gpg(), adb()]));
        for capability in ["adb", "gpg"] {
            let capability = name(capability);
            self.told(
                connection,
                Told::Forwarded {
                    capability,
                    bound: true,
                },
            );
        }
        connection
    }
}

fn events(step: &Step) -> Vec<Event> {
    step.entries
        .iter()
        .map(|entry| entry.event.clone())
        .collect()
}

fn acts(step: &Step) -> Vec<&Effect> {
    step.effects
        .iter()
        .filter(|effect| !matches!(effect, Effect::Send { .. }))
        .collect()
}

fn replies(step: &Step) -> Vec<&Result<Reply, Refusal>> {
    step.effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Send {
                frame: FromCore::Reply { reply, .. },
                ..
            } => Some(reply),
            _ => None,
        })
        .collect()
}

fn surveyed_in(step: &Step) -> Option<Dialect> {
    step.effects.iter().find_map(|effect| match effect {
        Effect::Survey { dialect, .. } => Some(*dialect),
        _ => None,
    })
}

fn words(text: &str) -> Words {
    Words::try_from(text).unwrap()
}

fn unread(unread: Unread, last: &str) -> Told {
    Told::Surveyed {
        report: Err((unread, Some(words(last)))),
        theirs: Vec::new(),
    }
}

fn reporting(kernel: &str, dialect: Dialect) -> Told {
    Told::Surveyed {
        report: Ok(Report {
            dialect,
            kernel: Kernel::try_from(kernel).unwrap(),
            shell: Vec::new(),
            answers: std::collections::BTreeMap::default(),
            issued: None,
        }),
        theirs: Vec::new(),
    }
}

/// A remote where no POSIX shell ran the script is asked again in Windows
/// PowerShell on the same attempt. Where neither ran, each capability that
/// needs the remote's answer is named, and one whose far end can be a port
/// is carried there all the same.
#[test]
fn a_remote_no_shell_answers_is_asked_again_and_then_named() {
    let mut scene = Scene::new(Vec::new());
    let (connection, step) = scene.connect();
    assert_eq!(surveyed_in(&step), Some(Dialect::Posix));
    let cmd = "'/bin/sh' is not recognized as an internal or external command,";
    let step = scene.told(connection, unread(Unread::NotBegun, cmd));
    assert_eq!(step.entries, Vec::<Entry>::new());
    assert_eq!(surveyed_in(&step), Some(Dialect::PowerShell));

    let restricted = "This account is restricted to git-shell";
    let step = scene.told(connection, unread(Unread::NotBegun, restricted));
    let why = words(&format!(
        "no shell Hedwig knows ran there; it said \"{restricted}\""
    ));
    assert_eq!(
        events(&step),
        [Event::Checked {
            connection,
            capability: name("gpg"),
            readiness: Readiness::Unready(vec![Finding::Unsurveyed(why)]),
        }]
    );
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Start { serving, .. }] if *serving == [adb()]
    ));
}

/// A POSIX shell on a system no Unix profile answers to - one a Windows host
/// runs for Git - is asked again in PowerShell; a system nothing answers to
/// at all is named with the refusal itself, the system's name in it, and no
/// platform is recorded for it.
#[test]
fn a_system_no_profile_answers_to_is_named() {
    let mut scene = Scene::new(Vec::new());
    let (connection, _) = scene.connect();
    let step = scene.told(
        connection,
        reporting("MINGW64_NT-10.0-26200", Dialect::Posix),
    );
    assert_eq!(step.entries, Vec::<Entry>::new());
    assert_eq!(surveyed_in(&step), Some(Dialect::PowerShell));
    let step = scene.told(connection, reporting("Haiku", Dialect::PowerShell));
    let refusal = Refusal::UnknownKernel(Kernel::try_from("Haiku").unwrap());
    assert_eq!(
        *events(&step).first().unwrap(),
        Event::Checked {
            connection,
            capability: name("gpg"),
            readiness: Readiness::Unready(vec![Finding::NoProfile(refusal)]),
        }
    );
    assert!(scene.core.state().observed(&remote()).is_none());
}

/// A survey cut off before its end, or answering what it was not asked, is
/// not asked again in another shell: that shell ran.
#[test]
fn a_survey_that_ran_and_failed_is_named_not_repeated() {
    let mut scene = Scene::new(Vec::new());
    let (connection, _) = scene.connect();
    let step = scene.told(connection, unread(Unread::Unfinished, "Killed"));
    assert_eq!(surveyed_in(&step), None);
    assert_eq!(
        *events(&step).first().unwrap(),
        Event::Checked {
            connection,
            capability: name("gpg"),
            readiness: Readiness::Unready(vec![Finding::Unsurveyed(words(
                "the remote stopped before readiness finished; it said \"Killed\""
            ))]),
        }
    );
}

/// A remote last reported as a Windows host is asked in PowerShell first,
/// in this run and in a later one, which reads it from the trail.
#[test]
fn a_remote_is_asked_first_in_the_shell_its_platform_takes() {
    let mut scene = Scene::new(Vec::new());
    let (connection, _) = scene.connect();
    scene.told(connection, reporting("Windows_NT", Dialect::Posix));
    assert_eq!(
        scene.core.state().observed(&remote()),
        Some(&name("windows"))
    );
    scene.ask(Request::Disconnect { remote: remote() });
    let (_, step) = scene.connect();
    assert_eq!(surveyed_in(&step), Some(Dialect::PowerShell));

    let entry = |seq: u64, event: Event| Entry {
        seq: Seq(seq),
        at: NOW.at,
        tick: Tick(1),
        event,
    };
    let earlier = vec![
        entry(
            1,
            Event::Opening {
                remote: remote(),
                with: Vec::new(),
                opener: Opener::Grant,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        ),
        entry(
            2,
            Event::Observed {
                connection: ConnectionId(Seq(1)),
                platform: name("windows"),
            },
        ),
        entry(
            3,
            Event::Down {
                connection: ConnectionId(Seq(1)),
                end: ChannelEnd::Closed,
            },
        ),
    ];
    let mut later = Scene::new(earlier);
    let (_, step) = later.connect();
    assert_eq!(surveyed_in(&step), Some(Dialect::PowerShell));
}

/// What readiness changed on the remote is recorded against the capability
/// before the channel starts: the folder it made and the socket it removed.
#[test]
fn what_readiness_did_is_recorded_before_the_channel_starts() {
    let mut scene = Scene::new(Vec::new());
    let (connection, _) = scene.connect();
    let mut told = common::placing(&[gpg(), adb()]);
    let Told::Surveyed {
        report: Ok(report), ..
    } = &mut told
    else {
        unreachable!("a report")
    };
    report.answers.insert(
        name("gpg"),
        Answer {
            place: Some(Place {
                path: SOCKET.as_bytes().to_vec(),
                created: Some(b"/run/user/1000/gnupg".to_vec()),
                at: Some(At::Removed),
                ..Place::default()
            }),
            ..Answer::default()
        },
    );
    let step = scene.told(connection, told);
    let path = |text: &str| RemotePath::try_from(text).unwrap();
    assert_eq!(
        *events(&step).get(1..).unwrap(),
        [
            Event::Prepared {
                connection,
                capability: name("gpg"),
                prepared: Prepared::Created(path("/run/user/1000/gnupg")),
            },
            Event::Prepared {
                connection,
                capability: name("gpg"),
                prepared: Prepared::Removed(path(SOCKET)),
            },
        ]
    );
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Start { serving, .. }] if *serving == [adb(), gpg()]
    ));
}

/// A check with the channel up asks the remote again without touching the
/// channel: the socket its own forward holds is never probed, what is found
/// is recorded where it changed, and nothing starts or ends.
#[test]
fn a_check_on_a_live_channel_asks_again_and_leaves_it_running() {
    let mut scene = Scene::new(Vec::new());
    let connection = scene.up();
    let check = || Request::Check {
        remote: remote(),
        capability: name("gpg"),
    };
    let step = scene.ask(check());
    let [Effect::Survey { plan, dialect, .. }] = acts(&step).as_slice() else {
        panic!("{step:?}");
    };
    assert_eq!(*dialect, Dialect::Posix);
    assert_eq!(plan.ours, [RemotePath::try_from(SOCKET).unwrap()]);
    assert!(matches!(replies(&step).as_slice(), [Ok(Reply::Row(_))]));
    // A second check while one runs asks nothing more.
    let again = scene.ask(check());
    assert_eq!(acts(&again), Vec::<&Effect>::new());

    let mut told = common::placing(&[gpg(), adb()]);
    let Told::Surveyed {
        report: Ok(report), ..
    } = &mut told
    else {
        unreachable!("a report")
    };
    report.answers.get_mut(&name("gpg")).unwrap().autostart = Some(true);
    let step = scene.told(connection, told);
    assert_eq!(
        events(&step),
        [
            Event::Observed {
                connection,
                platform: name("linux")
            },
            Event::Checked {
                connection,
                capability: name("gpg"),
                readiness: Readiness::Unready(vec![Finding::AgentAutostarts]),
            },
        ]
    );
    // The channel's forwards are bound still, so the survey that opened
    // Hedwig's private folder to place them seals it again.
    assert_eq!(acts(&step), [&Effect::Seal { connection }]);
    assert!(scene.core.state().connection(&remote()).is_some());
}

/// A check with nothing live opens a connection for readiness alone, marked
/// as the person's check, and the row says it is being checked rather than
/// connected; with nothing wanting the channel it ends once the remote has
/// answered, and no channel is started.
#[test]
fn a_check_with_no_channel_opens_one_for_readiness_alone() {
    let mut scene = Scene::new(Vec::new());
    let step = scene.ask(Request::Check {
        remote: remote(),
        capability: name("gpg"),
    });
    assert!(matches!(
        events(&step).as_slice(),
        [
            Event::Opening {
                opener: Opener::Check(_),
                ..
            },
            Event::Offered { .. },
            Event::Source { .. }
        ]
    ));
    assert_eq!(surveyed_in(&step), Some(Dialect::Posix));
    let [Ok(Reply::Row(row))] = replies(&step).as_slice() else {
        panic!("{step:?}");
    };
    assert_eq!(row.standing, Standing::Checking);
    let (connection, _) = scene.core.state().connection(&remote()).unwrap();
    let step = scene.told(connection, common::placing(&[gpg(), adb()]));
    assert_eq!(
        events(&step).last(),
        Some(&Event::Down {
            connection,
            end: ChannelEnd::Closed
        })
    );
    assert_eq!(acts(&step), [&Effect::End { connection }]);
}

/// The told result of an exercise: the notice to the client that asked, and
/// the entry that records it.
fn proofs(step: &Step) -> Vec<(Proof, Proof)> {
    let told = step.effects.iter().filter_map(|effect| match effect {
        Effect::Send {
            frame: FromCore::Notice(Notice::Exercised(exercised)),
            ..
        } => Some(exercised.proof.clone()),
        _ => None,
    });
    let recorded = events(step).into_iter().filter_map(|event| match event {
        Event::Exercised { proof, .. } => Some(proof),
        _ => None,
    });
    told.zip(recorded).collect()
}

/// An exercise is answered at once, so the client that asked can answer the
/// request the remote's tool raises; what the tool did is recorded and told
/// to that client once it has run: what it said, or that the remote lacks
/// it; an exercise whose connection ends first is told so; and the forward
/// must be up.
#[test]
fn an_exercise_is_answered_at_once_and_what_the_tool_did_follows() {
    let mut scene = Scene::new(Vec::new());
    let connection = scene.up();
    let exercise = || Request::Exercise {
        remote: remote(),
        capability: name("gpg"),
    };
    let step = scene.ask(exercise());
    assert_eq!(replies(&step), [&Ok(Reply::Done(Changed::Changed))]);
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Exercise { query: Some(Query::AgentSocket), binding, .. }]
            if *binding == gpg().binding
    ));
    let said = words("gpg: signing failed: No secret key");
    let step = scene.told(
        connection,
        Told::Exercised {
            ran: Ok(Some(said.clone())),
        },
    );
    let silent = Proof::Silent(Some(said));
    assert_eq!(proofs(&step), [(silent.clone(), silent)]);
    assert_eq!(replies(&step), Vec::<&Result<Reply, Refusal>>::new());

    scene.ask(exercise());
    let absent = Proof::Unrun(Finding::ToolAbsent(name("gpg")));
    let step = scene.told(
        connection,
        Told::Exercised {
            ran: Err(Finding::ToolAbsent(name("gpg"))),
        },
    );
    assert_eq!(proofs(&step), [(absent.clone(), absent)]);

    scene.ask(exercise());
    let step = scene.told(
        connection,
        Told::Ended {
            status: 255,
            unverified: false,
            last: None,
        },
    );
    let over = Proof::Unrun(Finding::Unsurveyed(words(
        "the channel ended before the remote's tool had run",
    )));
    assert_eq!(proofs(&step), [(over.clone(), over)]);

    let (_, _) = scene.connect();
    let step = scene.ask(exercise());
    assert!(matches!(
        replies(&step).as_slice(),
        [Err(Refusal::NotConnected(refused))] if *refused == remote()
    ));
    assert_eq!(acts(&step), Vec::<&Effect>::new());
}

fn gpg_grant(setup: Setup) -> Request {
    Request::Change(Change::Grant {
        grant: Grant {
            capability: name("gpg"),
            remotes: Granted::Route(name("ssh")),
        },
        terms: Terms {
            activation: Activation::OnRequest,
            setup,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    })
}

fn writing(told: &mut Told, said: &str, write: Write, place: &str) {
    made(told, said, write, place, None);
}

fn made(told: &mut Told, said: &str, write: Write, place: &str, folder: Option<&str>) {
    let Told::Surveyed {
        report: Ok(report), ..
    } = told
    else {
        unreachable!("a report")
    };
    let answer = report.answers.get_mut(&name("gpg")).unwrap();
    let entry = (write, place.as_bytes().to_vec());
    match said {
        "wrote" => answer.wrote.push((
            entry.0,
            entry.1,
            folder.map(|folder| folder.as_bytes().to_vec()),
        )),
        "kept" => answer.kept.push(entry),
        _ => answer.unwrote.push(entry),
    }
}

/// A grant that consents to writes has readiness make them; what it wrote is
/// recorded and listed on the row, found again without a second record, and
/// taken back on the survey after the consent ends.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one remote through consent given, a write found again, and consent ended"
)]
fn what_hedwig_writes_is_recorded_listed_and_taken_back_when_consent_ends() {
    let mut scene = Scene::new(Vec::new());
    scene.ask(gpg_grant(Setup::Write));
    let (connection, step) = scene.connect();
    let [Effect::Survey { plan, .. }] = acts(&step).as_slice() else {
        panic!("{step:?}");
    };
    assert!(plan.writes.contains(&(name("gpg"), Write::NoAutostart)));
    assert!(plan.writes.contains(&(name("gpg"), Write::SocketFile)));
    assert!(plan.writes.contains(&(name("gpg"), Write::Masked)));
    assert_eq!(plan.undo, Vec::<Undo>::new());

    let common = "/home/dev/.gnupg/common.conf";
    let unit = "/home/dev/.config/systemd/user/gpg-agent.socket";
    let mut told = common::placing(&[gpg(), adb()]);
    writing(&mut told, "wrote", Write::NoAutostart, common);
    made(
        &mut told,
        "wrote",
        Write::Masked,
        unit,
        Some("/home/dev/.config"),
    );
    let step = scene.told(connection, told);
    let place = RemotePath::try_from(common).unwrap();
    let masked = RemotePath::try_from(unit).unwrap();
    let config = RemotePath::try_from("/home/dev/.config").unwrap();
    assert!(events(&step).contains(&Event::Wrote {
        connection,
        capability: name("gpg"),
        write: Write::NoAutostart,
        place: place.clone(),
        made: None,
    }));
    assert!(events(&step).contains(&Event::Wrote {
        connection,
        capability: name("gpg"),
        write: Write::Masked,
        place: masked.clone(),
        made: Some(config.clone()),
    }));
    let rows = scene.ask(Request::Exposure);
    let listed = [
        Written {
            write: Write::NoAutostart,
            place: place.clone(),
            made: None,
        },
        Written {
            write: Write::Masked,
            place: masked.clone(),
            made: Some(config.clone()),
        },
    ];
    assert!(matches!(
        replies(&rows).as_slice(),
        [Ok(Reply::Exposure(rows))] if rows.iter().any(|row| row.written == listed)
    ));

    scene.ask(Request::Check {
        remote: remote(),
        capability: name("gpg"),
    });
    let mut told = common::placing(&[gpg(), adb()]);
    writing(&mut told, "kept", Write::NoAutostart, common);
    let step = scene.told(connection, told);
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Wrote { .. }))
    );

    scene.ask(gpg_grant(Setup::Inspect));
    scene.ask(Request::Disconnect { remote: remote() });
    let (connection, step) = scene.connect();
    let [Effect::Survey { plan, .. }] = acts(&step).as_slice() else {
        panic!("{step:?}");
    };
    assert_eq!(plan.writes, Vec::<(Name, Write)>::new());
    assert_eq!(
        plan.undo,
        [
            Undo {
                capability: name("gpg"),
                write: Write::NoAutostart,
                place: place.clone(),
                made: None,
            },
            Undo {
                capability: name("gpg"),
                write: Write::Masked,
                place: masked,
                made: Some(config),
            },
        ]
    );
    let mut told = common::placing(&[gpg(), adb()]);
    writing(&mut told, "unwrote", Write::NoAutostart, common);
    writing(&mut told, "unwrote", Write::Masked, unit);
    let step = scene.told(connection, told);
    assert!(events(&step).contains(&Event::Unwrote {
        connection,
        capability: name("gpg"),
        write: Write::NoAutostart,
        place,
    }));
    assert_eq!(scene.core.state().written(&remote()).count(), 0);
}

/// Removal: `Withdraw` ends every consent, surveys the remote to take back
/// all that was written, records the withdrawal once, and `Withdrawal` says
/// where it stands; afterwards nothing is written again.
#[test]
fn a_withdrawal_takes_back_everything_written_and_says_where_it_stands() {
    let mut scene = Scene::new(Vec::new());
    scene.ask(gpg_grant(Setup::Write));
    let (connection, _) = scene.connect();
    let common = "/home/dev/.gnupg/common.conf";
    let mut told = common::placing(&[gpg(), adb()]);
    writing(&mut told, "wrote", Write::NoAutostart, common);
    scene.told(connection, told);
    let place = RemotePath::try_from(common).unwrap();

    let step = scene.ask(Request::Withdraw);
    assert_eq!(
        events(&step)
            .iter()
            .filter(|event| matches!(event, Event::Withdrawn { .. }))
            .count(),
        1
    );
    let surveys: Vec<_> = acts(&step)
        .into_iter()
        .filter_map(|effect| match effect {
            Effect::Survey {
                connection, plan, ..
            } => Some((connection, plan)),
            _ => None,
        })
        .collect();
    let [(surveyed, plan)] = surveys.as_slice() else {
        panic!("{step:?}");
    };
    assert!(plan.writes.is_empty(), "no consent stands");
    assert_eq!(
        plan.undo,
        [Undo {
            capability: name("gpg"),
            write: Write::NoAutostart,
            place: place.clone(),
            made: None,
        }]
    );
    let [Ok(Reply::Withdrawal(standing))] = replies(&step).as_slice() else {
        panic!("{step:?}");
    };
    let [stands] = standing.as_slice() else {
        panic!("{standing:?}");
    };
    assert_eq!(stands.remote, remote());
    assert!(stands.surveying);
    assert_eq!(stands.left.len(), 1);

    let mut told = common::placing(&[gpg(), adb()]);
    writing(&mut told, "unwrote", Write::NoAutostart, common);
    let step = scene.told(**surveyed, told);
    assert!(events(&step).contains(&Event::Unwrote {
        connection: **surveyed,
        capability: name("gpg"),
        write: Write::NoAutostart,
        place,
    }));
    assert_eq!(scene.core.state().written(&remote()).count(), 0);
    let step = scene.ask(Request::Withdrawal);
    assert!(matches!(
        replies(&step).as_slice(),
        [Ok(Reply::Withdrawal(left))] if left.is_empty()
    ));

    // Withdrawn stays: asked again, nothing more is recorded or surveyed.
    let step = scene.ask(Request::Withdraw);
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Withdrawn { .. }))
    );
    assert!(scene.core.state().withdrawn().is_some());
}

/// A removal that stopped after `Withdraw` leaves Hedwig serving nothing: a
/// connect is refused with why, and the status says since when. Keeping
/// Hedwig ends it once; a channel then opened writes what the person
/// consented to again.
#[test]
fn a_removal_that_did_not_finish_is_said_and_keeping_hedwig_writes_again() {
    let mut scene = Scene::new(Vec::new());
    scene.ask(gpg_grant(Setup::Write));
    let step = scene.ask(Request::Withdraw);
    let began = step
        .entries
        .iter()
        .find(|entry| matches!(entry.event, Event::Withdrawn { .. }))
        .unwrap()
        .seq;

    let connect = || Request::Connect {
        remote: remote(),
        with: Vec::new(),
        acknowledged: Exposure::NONE,
        lends: Lends::none(),
    };
    let step = scene.ask(connect());
    assert_eq!(replies(&step), [&Err(Refusal::Withdrawn)]);
    assert_eq!(events(&step), Vec::<Event>::new());
    let step = scene.ask(Request::Status);
    let [Ok(Reply::Status(status))] = replies(&step).as_slice() else {
        panic!("{step:?}");
    };
    assert_eq!(status.withdrawn.map(|since| since.entry), Some(began));

    let step = scene.ask(Request::Restore);
    assert_eq!(replies(&step), [&Ok(Reply::Done(Changed::Changed))]);
    assert!(matches!(events(&step).as_slice(), [Event::Restored { .. }]));
    let step = scene.ask(Request::Restore);
    assert_eq!(replies(&step), [&Ok(Reply::Done(Changed::Unchanged))]);
    assert_eq!(events(&step), Vec::<Event>::new());

    let step = scene.ask(connect());
    let [Effect::Survey { plan, .. }] = acts(&step).as_slice() else {
        panic!("{step:?}");
    };
    assert!(
        plan.writes.contains(&(name("gpg"), Write::NoAutostart)),
        "{plan:?}"
    );
}
