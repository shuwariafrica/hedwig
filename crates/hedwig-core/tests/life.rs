//! A channel's life, decided with nothing running: what holds it, when it is
//! opened again after it ends and when it is not, what a sleep, a network's
//! return, the person's disconnect and Hedwig's stop do to it, how a route's
//! listing holds a workspace's channel while it runs, and what a grant marked
//! unattended serves across a lost channel. Time is the tick each input
//! carries, so a clock that jumped is one input.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::num::NonZeroU32;

use hedwig_core::dispatch::{Core, Effect, Input, Link, Now, Step, Told, Turn};
use hedwig_model::capability::{Exposure, Lends, Operation, Setup};
use hedwig_model::config::{
    Activation, Catalogue, Change, Configuration, Effect as Changed, Grant, Terms,
};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::policy::{ConnectionScope, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{FromCore, PROTOCOL, Reply, Request, ToCore};
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::Identity;
use hedwig_model::remote::{Argument, Client, Granted, Lister, Listing, RemoteId, Remotes, Route};
use hedwig_model::setting::Returns;
use hedwig_model::text::{Address, Name, Program, RemotePath, Verbatim, Words};
use hedwig_model::trail::{
    Binding, ChannelEnd, ClientKind, ConnectionId, Event, Integrity, Network, Opener, Origin,
    Outcome, PromptKind, Serving, Tick, Timestamp,
};
use hedwig_model::wire::{line, read};

mod common;

const DESKTOP: Origin = Origin {
    process: 4200,
    logon: 0x3e7_0001,
    session: 2,
    integrity: Integrity::Medium,
};

const LINK: Link = Link(1);

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn at(seconds: u64) -> Now {
    Now {
        at: Timestamp(1_790_000_000_000 + seconds * 1000),
        tick: Tick(seconds * 1000),
    }
}

fn host() -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from("dev@build-7.example").unwrap(),
    }
}

fn workspace(address: &str) -> RemoteId {
    RemoteId {
        route: name("lab"),
        address: Address::try_from(address).unwrap(),
    }
}

fn gpg() -> Serving {
    Serving {
        capability: name("gpg"),
        binding: Binding::Socket(RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap()),
    }
}

fn terms(activation: Activation) -> Terms {
    Terms {
        activation,
        setup: Setup::Inspect,
        acknowledged: Exposure::ACKNOWLEDGED,
        lends: Lends::none(),
    }
}

/// A route whose platform lists its running workspaces.
fn lab() -> Route {
    let literal = |text: &str| Verbatim::try_from(text).unwrap();
    Route {
        id: name("lab"),
        client: Client {
            program: Program::try_from("ssh").unwrap(),
            before: Vec::new(),
            after: vec![Argument::Address],
        },
        listing: Listing::Lists(Lister {
            program: Program::try_from("lab-cli").unwrap(),
            arguments: vec![literal("list"), literal("--running")],
            header: 0,
        }),
        identity: Identity::Platform,
    }
}

/// The core, a client of the control pipe, and the tick of the last input.
struct Life {
    core: Core,
    now: u64,
    asked: u32,
}

impl Life {
    /// A core that has begun at tick zero with `changes` made by a command,
    /// which attends nobody: nothing it holds can be put to a person.
    fn new(changes: Vec<Change>) -> Life {
        let mut core = Core::new(
            Catalogue::shipped().unwrap(),
            Configuration::default(),
            Vec::new(),
            "0.2.0".to_owned(),
        );
        core.begin(DESKTOP, None, Vec::new(), at(0));
        core.step(
            Input::Arrived {
                link: LINK,
                peer: Some(DESKTOP.into()),
            },
            at(0),
        );
        let mut life = Life {
            core,
            now: 0,
            asked: 0,
        };
        let hello = Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Command,
            attends: Remotes::Every,
        };
        life.ask(hello);
        for change in changes {
            let step = life.ask(Request::Change(change));
            assert!(
                matches!(
                    reply(&step),
                    Reply::Changed {
                        effect: Changed::Changed,
                        ..
                    }
                ),
                "{step:?}"
            );
        }
        life
    }

    fn step(&mut self, input: Input, seconds: u64) -> Step {
        self.now = seconds;
        let step = self.core.step(input, at(seconds));
        common::keyed(&mut self.core, step, at(seconds))
    }

    fn ask(&mut self, request: Request) -> Step {
        self.asked += 1;
        let frame = ToCore {
            id: self.asked,
            request,
        };
        let step = self.step(Input::Asked { link: LINK, frame }, self.now);
        self.core.step(Input::Sent { link: LINK }, at(self.now));
        step
    }

    fn told(&mut self, connection: ConnectionId, told: Told, seconds: u64) -> Step {
        self.step(Input::Channel { connection, told }, seconds)
    }

    /// Brings the live connection to `remote` up, forwarding `gpg`.
    fn up(&mut self, remote: &RemoteId, seconds: u64) -> ConnectionId {
        let (connection, _) = self.core.state().connection(remote).expect("a connection");
        let placed = common::placing(&[gpg()]);
        let step = self.told(connection, placed, seconds);
        assert!(
            matches!(acts(&step).as_slice(), [Effect::Start { .. }]),
            "{step:?}"
        );
        let forwarded = Told::Forwarded {
            capability: name("gpg"),
            bound: true,
        };
        let step = self.told(connection, forwarded, seconds);
        assert!(
            events(&step).contains(&Event::Up {
                connection,
                serving: vec![gpg()]
            }),
            "{step:?}"
        );
        connection
    }

    /// The live connection's client ends with `end`'s words.
    fn lost(&mut self, connection: ConnectionId, last: &str, seconds: u64) -> Step {
        let ended = Told::Ended {
            status: 255,
            unverified: false,
            last: Words::try_from(last).ok(),
        };
        self.told(connection, ended, seconds)
    }

    fn world<'a>(&'a self, catalogue: &'a Catalogue) -> World<'a> {
        World {
            catalogue,
            configuration: self.core.configuration(),
            state: self.core.state(),
        }
    }
}

fn reply(step: &Step) -> Reply {
    step.effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Send {
                frame: FromCore::Reply { reply, .. },
                ..
            } => Some(
                read::<Result<Reply, Refusal>>(&line(reply))
                    .unwrap()
                    .unwrap(),
            ),
            _ => None,
        })
        .expect("a reply")
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

/// The connection an `Opening` in the step names, and why it was opened.
fn opened(step: &Step) -> Option<(ConnectionId, Opener)> {
    step.entries.iter().find_map(|entry| match &entry.event {
        Event::Opening { opener, .. } => Some((ConnectionId(entry.seq), *opener)),
        _ => None,
    })
}

fn continuous() -> Vec<Change> {
    vec![Change::Grant {
        grant: Grant {
            capability: name("gpg"),
            remotes: Granted::One(host()),
        },
        terms: terms(Activation::Continuous),
    }]
}

const TIMED_OUT: &str = "ssh: connect to host build-7.example port 22: Connection timed out";

/// A continuous grant opens its channel as the core begins, with nobody
/// asking. A channel lost before it settled comes back after a second, then
/// two, doubling; one that settled comes back at once. A deadline the clock
/// jumped over opens it on the first input after the jump.
#[test]
fn a_lost_channel_comes_back_at_its_pace() {
    let mut life = Life::new(Vec::new());
    let step = life.ask(Request::Change(continuous().remove(0)));
    let Some((first, Opener::Grant)) = opened(&step) else {
        panic!("a continuous grant opens its channel: {step:?}");
    };
    assert!(acts(&step).iter().any(|effect| matches!(
        effect,
        Effect::Survey { connection, .. } if *connection == first
    )));
    let first = life.up(&host(), 1);

    // Lost young: back after a second, not before.
    let step = life.lost(first, TIMED_OUT, 5);
    assert!(opened(&step).is_none());
    assert_eq!(life.core.due(), Some(Tick(6_000)));
    assert!(opened(&life.step(Input::Due, 5)).is_none());
    let Some((second, Opener::Again)) = opened(&life.step(Input::Due, 6)) else {
        panic!("opened again after its wait");
    };

    // It fails again before it is up: two seconds.
    life.told(
        second,
        Told::Unstarted {
            end: ChannelEnd::Unstarted(Words::try_from("Access is denied.").unwrap()),
        },
        6,
    );
    assert_eq!(life.core.due(), Some(Tick(8_000)));

    // The clock jumps an hour: the first input after it opens the channel.
    let Some((third, Opener::Again)) = opened(&life.step(Input::Due, 3_606)) else {
        panic!("a jump past the deadline opens it at once");
    };
    assert_eq!(
        life.core
            .state()
            .returning(&host())
            .map(|returning| returning.failed),
        Some(2)
    );

    // Up for a minute, then lost: back in the same step.
    let third_up = life.up(&host(), 3_606);
    assert_eq!(third, third_up);
    let step = life.lost(third, TIMED_OUT, 3_667);
    assert!(events(&step).contains(&Event::Down {
        connection: third,
        end: ChannelEnd::Exited {
            status: 255,
            last: Words::try_from(TIMED_OUT).ok()
        }
    }));
    assert!(
        matches!(opened(&step), Some((_, Opener::Again))),
        "{step:?}"
    );
}

/// The waits are the person's to set, per remote, as any choice is.
#[test]
fn the_waits_are_a_setting() {
    let slow = Returns {
        first: NonZeroU32::new(30).unwrap(),
        longest: NonZeroU32::new(300).unwrap(),
    };
    let mut changes = continuous();
    changes.push(Change::Returns {
        remotes: Remotes::One(host()),
        returns: Some(slow),
    });
    let mut life = Life::new(changes);
    let connection = life.up(&host(), 1);
    life.lost(connection, TIMED_OUT, 2);
    assert_eq!(life.core.due(), Some(Tick(32_000)));
    let catalogue = Catalogue::shipped().unwrap();
    assert_eq!(life.world(&catalogue).returns(&host()).value, slow);
}

/// What only the person can put right is not tried again by itself: a
/// prompt nobody was there for, a changed host key, a server that let the
/// client in no way it could offer, a prompt the person declined, a client
/// that is not installed. Their connect tries again at once.
#[test]
fn what_only_the_person_can_fix_waits_for_them() {
    let ends = [
        ChannelEnd::Needs(PromptKind::KeyPassphrase),
        ChannelEnd::HostKeyChanged(hedwig_model::text::Mark::try_from("SHA256:abc").unwrap()),
        ChannelEnd::Unauthenticated(Words::try_from("publickey").unwrap()),
        ChannelEnd::Declined(PromptKind::UnknownHostKey),
        ChannelEnd::ClientAbsent,
    ];
    for end in ends {
        let mut life = Life::new(continuous());
        let (connection, _) = life.core.state().connection(&host()).unwrap();
        let step = life.told(connection, Told::Unstarted { end: end.clone() }, 3);
        assert!(opened(&step).is_none(), "{end:?}");
        assert_eq!(life.core.due(), None, "{end:?}");
        assert!(opened(&life.step(Input::Due, 86_400)).is_none(), "{end:?}");
        let step = life.ask(Request::Connect {
            remote: host(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        });
        assert!(
            matches!(opened(&step), Some((_, Opener::Person(_)))),
            "{end:?}: {step:?}"
        );
    }
}

/// The workstation going to sleep ends every channel before it sleeps and
/// opens nothing until it wakes; waking opens each again at once.
#[test]
fn a_sleep_ends_every_channel_and_the_wake_brings_them_back() {
    let mut life = Life::new(continuous());
    let connection = life.up(&host(), 1);
    let step = life.step(Input::Turned(Turn::Sleeping), 10);
    assert_eq!(
        events(&step),
        [
            Event::Sleeping,
            Event::Down {
                connection,
                end: ChannelEnd::Slept
            }
        ]
    );
    assert_eq!(acts(&step), [&Effect::End { connection }]);
    assert_eq!(life.core.due(), None, "nothing is due while asleep");
    let step = life.step(Input::Turned(Turn::Woke), 7_210);
    assert!(
        matches!(opened(&step), Some((_, Opener::Again))),
        "{step:?}"
    );
}

/// A wake Windows did not warn of ends what was carried across it.
#[test]
fn a_wake_with_no_warning_ends_what_was_carried_across_it() {
    let mut life = Life::new(continuous());
    let connection = life.up(&host(), 1);
    let step = life.step(Input::Turned(Turn::Woke), 7_210);
    let found = events(&step);
    assert_eq!(found.first(), Some(&Event::Woke));
    assert!(found.contains(&Event::Down {
        connection,
        end: ChannelEnd::Slept
    }));
    assert!(
        matches!(opened(&step), Some((_, Opener::Again))),
        "{step:?}"
    );
}

/// A network's return is recorded and tries every waiting channel at once,
/// whatever was left of its wait; losing it is recorded and waits on.
#[test]
fn a_network_returning_tries_every_waiting_channel_at_once() {
    let mut life = Life::new(continuous());
    let connection = life.up(&host(), 1);
    life.lost(connection, TIMED_OUT, 2);
    for failed in 3..9 {
        let step = life.step(Input::Due, life.core.due().unwrap().0 / 1000);
        let (again, _) = opened(&step).unwrap();
        life.told(
            again,
            Told::Unstarted {
                end: ChannelEnd::Unstarted(Words::try_from("no route").unwrap()),
            },
            life.now,
        );
        assert!(failed > 0);
    }
    let step = life.step(Input::Network(Network::Offline), life.now + 1);
    assert_eq!(events(&step), [Event::Offline]);
    assert!(opened(&step).is_none());
    let waiting = life.core.due().unwrap();
    assert!(waiting.0 > (life.now + 30) * 1000, "a long wait by now");
    let step = life.step(Input::Network(Network::Online), life.now + 2);
    assert_eq!(events(&step).first(), Some(&Event::Online));
    assert!(
        matches!(opened(&step), Some((_, Opener::Again))),
        "{step:?}"
    );
    let same = life.step(Input::Network(Network::Online), life.now + 1);
    assert_eq!(same.entries, Vec::new());
}

/// The person's disconnect is recorded, ends a live channel, and holds the
/// remote down, whatever grant wants it, until they connect.
#[test]
fn the_persons_disconnect_holds_the_remote_down_until_they_connect() {
    let mut life = Life::new(continuous());
    let connection = life.up(&host(), 1);
    let step = life.ask(Request::Disconnect { remote: host() });
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Disconnected { remote, .. }, Event::Down { connection: over, end: ChannelEnd::Closed }]
            if *remote == host() && *over == connection
    ));
    assert!(opened(&step).is_none());
    assert_eq!(life.core.due(), None);
    let again = life.ask(Request::Disconnect { remote: host() });
    assert_eq!(reply(&again), Reply::Done(Changed::Unchanged));
    let step = life.ask(Request::Connect {
        remote: host(),
        with: Vec::new(),
        acknowledged: Exposure::NONE,
        lends: Lends::none(),
    });
    assert!(matches!(opened(&step), Some((_, Opener::Person(_)))));
}

/// A remote the person connected is held while they asked: lost, it comes
/// back as a grant's would, until they disconnect.
#[test]
fn a_remote_the_person_connected_is_held_until_they_disconnect() {
    let mut life = Life::new(vec![Change::Grant {
        grant: Grant {
            capability: name("gpg"),
            remotes: Granted::One(host()),
        },
        terms: terms(Activation::OnRequest),
    }]);
    assert!(
        life.core.state().connection(&host()).is_none(),
        "on request only"
    );
    life.ask(Request::Connect {
        remote: host(),
        with: Vec::new(),
        acknowledged: Exposure::NONE,
        lends: Lends::none(),
    });
    let connection = life.up(&host(), 1);
    life.lost(connection, TIMED_OUT, 2);
    let Some((_, Opener::Again)) = opened(&life.step(Input::Due, 3)) else {
        panic!("the person's connection comes back");
    };
    life.ask(Request::Disconnect { remote: host() });
    assert_eq!(life.core.due(), None);
}

/// A grant revoked, or lowered to on request, ends the channel it held; a
/// grant added reshapes a live one, since a forward cannot be added to a
/// running client.
#[test]
fn a_change_to_what_a_remote_holds_ends_or_reshapes_its_channel() {
    let mut life = Life::new(continuous());
    let connection = life.up(&host(), 1);
    let adb = Change::Grant {
        grant: Grant {
            capability: name("adb"),
            remotes: Granted::One(host()),
        },
        terms: Terms {
            acknowledged: Exposure::SERVICE,
            ..terms(Activation::OnRequest)
        },
    };
    let step = life.ask(Request::Change(adb));
    assert!(events(&step).contains(&Event::Down {
        connection,
        end: ChannelEnd::Reshaped
    }));
    let Some((again, Opener::Again)) = opened(&step) else {
        panic!("opened again with what it holds now");
    };
    let lowered = Change::Grant {
        grant: Grant {
            capability: name("gpg"),
            remotes: Granted::One(host()),
        },
        terms: terms(Activation::OnRequest),
    };
    let step = life.ask(Request::Change(lowered));
    assert!(events(&step).contains(&Event::Down {
        connection: again,
        end: ChannelEnd::Closed
    }));
    assert!(opened(&step).is_none());
}

/// Stopping Hedwig ends every channel, recorded as closed.
#[test]
fn stopping_ends_every_channel() {
    let mut life = Life::new(continuous());
    let connection = life.up(&host(), 1);
    let step = life.ask(Request::Stop);
    assert!(events(&step).contains(&Event::Down {
        connection,
        end: ChannelEnd::Closed
    }));
    assert!(acts(&step).contains(&&Effect::End { connection }));
}

/// A grant that follows a workspace's life lists its route at once and every
/// cadence after; a workspace that appears is opened, one that goes is ended
/// and not tried again. A listing that fails is recorded once, and so is
/// the one after it that succeeds; one that overruns its cadence is ended
/// and tried again.
#[test]
#[allow(clippy::too_many_lines, reason = "one listing's life, told in order")]
fn a_listed_workspace_is_held_while_it_runs() {
    let mut changes = vec![Change::DefineRoute(lab())];
    changes.push(Change::Grant {
        grant: Grant {
            capability: name("gpg"),
            remotes: Granted::Route(name("lab")),
        },
        terms: terms(Activation::WhileRunning),
    });
    let mut life = Life::new(Vec::new());
    let mut listed_at = None;
    for change in changes {
        let step = life.ask(Request::Change(change));
        if acts(&step)
            .iter()
            .any(|effect| matches!(effect, Effect::List { route, .. } if *route == name("lab")))
        {
            listed_at = Some(life.now);
        }
    }
    assert_eq!(listed_at, Some(0), "listed as soon as a grant follows it");
    assert_eq!(
        life.core.due(),
        Some(Tick(60_000)),
        "overdue after a minute"
    );

    let build = workspace("dev/build");
    let listed = Input::Listed {
        route: name("lab"),
        listed: Ok(vec![build.address.clone()]),
    };
    let step = life.step(listed, 4);
    assert_eq!(
        events(&step).first(),
        Some(&Event::Appeared {
            remote: build.clone()
        })
    );
    assert!(
        matches!(opened(&step), Some((_, Opener::Grant))),
        "{step:?}"
    );
    assert_eq!(life.core.due(), Some(Tick(64_000)), "the next a minute on");
    let connection = life.up(&build, 5);

    let step = life.step(Input::Due, 64);
    assert!(
        acts(&step)
            .iter()
            .any(|effect| matches!(effect, Effect::List { .. }))
    );
    let account = Words::try_from("HTTP 401: Bad credentials").unwrap();
    let failed = Input::Listed {
        route: name("lab"),
        listed: Err(account.clone()),
    };
    let step = life.step(failed, 65);
    assert_eq!(
        events(&step),
        [Event::Unlisted {
            route: name("lab"),
            account: Some(account.clone())
        }]
    );
    assert!(
        life.core.state().connection(&build).is_some(),
        "left as it was"
    );
    life.step(Input::Due, 125);
    let again = life.step(
        Input::Listed {
            route: name("lab"),
            listed: Err(account),
        },
        126,
    );
    assert!(again.entries.is_empty(), "said once");

    life.step(Input::Due, 186);
    let step = life.step(
        Input::Listed {
            route: name("lab"),
            listed: Ok(Vec::new()),
        },
        187,
    );
    assert_eq!(
        events(&step),
        [
            Event::Unlisted {
                route: name("lab"),
                account: None
            },
            Event::Gone {
                remote: build.clone()
            },
            Event::Down {
                connection,
                end: ChannelEnd::RemoteGone
            }
        ]
    );
    assert!(opened(&step).is_none());

    // No answer within a minute: ended, said, and started again.
    life.step(Input::Due, 247);
    let step = life.step(Input::Due, 307);
    let found = acts(&step);
    assert!(found.contains(&&Effect::Unlist { route: name("lab") }));
    assert!(
        found
            .iter()
            .any(|effect| matches!(effect, Effect::List { .. }))
    );
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Unlisted { account: Some(said), .. }]
            if said.as_str() == "the listing gave no answer within 60 seconds"
    ));
}

/// Across a lost channel, the standing rule a person wrote serves on
/// the channel that comes back, with nobody there, and is recorded as served
/// unseen; a rule said to the lost connection is gone with it, so the same
/// request is refused as reaching nobody. While the channel is down nothing
/// can arrive through it.
#[test]
fn an_unattended_grant_serves_again_on_the_channel_that_comes_back() {
    let standing = RuleScope {
        remotes: Remotes::One(host()),
        capability: Selector::Only(name("gpg")),
        operation: Selector::Every,
        key: Keys::Every,
    };
    let mut changes = continuous();
    changes.push(Change::Rule {
        scope: standing.clone(),
        mode: Mode::Unattended,
    });
    let catalogue = Catalogue::shipped().unwrap();

    let mut life = Life::new(changes);
    let first = life.up(&host(), 1);
    life.lost(first, TIMED_OUT, 2);
    let decided =
        life.world(&catalogue)
            .decide(first, &name("gpg"), Operation::Sign, None, Tick(2_500));
    assert_eq!(decided, Verdict::Refuse(Refusal::UnknownConnection(first)));
    life.step(Input::Due, 3);
    let second = life.up(&host(), 3);
    let decided =
        life.world(&catalogue)
            .decide(second, &name("gpg"), Operation::Sign, None, Tick(3_500));
    assert!(
        matches!(decided, Verdict::Serve(Outcome::Unseen(_))),
        "{decided:?}"
    );

    // Said to the connection alone, and lost with it.
    let mut life = Life::new(continuous());
    let first = life.up(&host(), 1);
    let rule = Request::Rule {
        connection: first,
        scope: ConnectionScope {
            capability: Selector::Every,
            operation: Selector::Every,
            key: Keys::Every,
        },
        mode: Some(Mode::Unattended),
    };
    life.ask(rule);
    let decided =
        life.world(&catalogue)
            .decide(first, &name("gpg"), Operation::Sign, None, Tick(1_500));
    assert!(
        matches!(decided, Verdict::Serve(Outcome::Unseen(_))),
        "{decided:?}"
    );
    life.lost(first, TIMED_OUT, 2);
    life.step(Input::Due, 3);
    let second = life.up(&host(), 3);
    let decided =
        life.world(&catalogue)
            .decide(second, &name("gpg"), Operation::Sign, None, Tick(3_500));
    assert_eq!(
        decided,
        Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away))
    );
}
