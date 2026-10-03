//! What needs the person is raised once, when it appears: at the volume
//! each watching surface should give it, falling back to `stale` where it
//! does not fit, and never again until it has gone and come back.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::num::{NonZeroU8, NonZeroU32};

use hedwig_core::channel::words;
use hedwig_core::dispatch::{Core, Effect, Input, Link, Now, Step, Told, WAITING};
use hedwig_model::capability::{Exposure, Lends, Operation, Setup};
use hedwig_model::config::{
    Activation, Catalogue, Change, Configuration, Effect as Changed, Grant, Terms,
};
use hedwig_model::protocol::{
    Attention, FromCore, Notice, PROTOCOL, Reply, Request, ToCore, Topic,
};
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::setting::{Burst, FullScreen, Threshold, Volume};
use hedwig_model::text::{Address, Name, RemotePath};
use hedwig_model::trail::{
    Binding, Breakdown, ChannelEnd, ClientKind, ConnectionId, Entry, Event, Icon, Integrity,
    Missing, Opener, Origin, Outcome, Presence, RequestId, Seq, Serving, Tick, Timestamp,
};

mod common;

const DESKTOP: Origin = Origin {
    process: 4200,
    logon: 0x3e7_0001,
    session: 2,
    integrity: Integrity::Medium,
};

/// A terminal at the desktop.
const DESK: Link = Link(1);
/// The interface, attached after it.
const ICON: Link = Link(2);

fn at(tick: u64) -> Now {
    Now {
        at: Timestamp(1_790_000_000_000 + tick),
        tick: Tick(tick),
    }
}

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn remote(address: &str) -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from(address).unwrap(),
    }
}

fn notices(step: &Step, to: Link) -> Vec<Notice> {
    step.effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Send {
                link,
                frame: FromCore::Notice(notice),
                ..
            } if *link == to => Some(notice.clone()),
            _ => None,
        })
        .collect()
}

fn frames(step: &Step, to: Link) -> usize {
    step.effects
        .iter()
        .filter(|effect| matches!(effect, Effect::Send { link, .. } if *link == to))
        .count()
}

fn raised(step: &Step, to: Link) -> Vec<(Attention, Volume)> {
    notices(step, to)
        .into_iter()
        .filter_map(|notice| match notice {
            Notice::Raised(needs) => Some((needs.attention, needs.volume)),
            _ => None,
        })
        .collect()
}

struct Scene {
    core: Core,
    now: Now,
    asked: u32,
}

impl Scene {
    fn new(trail: Vec<Entry>) -> Scene {
        let core = Core::new(
            Catalogue::shipped().unwrap(),
            Configuration::default(),
            trail,
            "0.2.0".to_owned(),
        );
        Scene {
            core,
            now: at(1_000),
            asked: 0,
        }
    }

    fn step(&mut self, input: Input) -> Step {
        self.core.step(input, self.now)
    }

    /// Asks, and says every frame the step sent `link` was written unless
    /// `reading` is false.
    fn ask(&mut self, link: Link, request: Request, reading: bool) -> Step {
        self.asked += 1;
        let frame = ToCore {
            id: self.asked,
            request,
        };
        let step = self.step(Input::Asked { link, frame });
        if reading {
            for _ in 0..frames(&step, link) {
                self.step(Input::Sent { link });
            }
        }
        step
    }

    fn attend(&mut self, link: Link, kind: ClientKind) -> Step {
        self.step(Input::Arrived {
            link,
            peer: Some(DESKTOP.into()),
        });
        self.ask(
            link,
            Request::Hello {
                protocol: PROTOCOL,
                kind,
                attends: Remotes::Every,
            },
            true,
        )
    }

    /// `gpg` granted on request to every remote on `ssh`.
    fn grant(&mut self) {
        self.ask(
            DESK,
            Request::Change(Change::Grant {
                grant: Grant {
                    capability: name("gpg"),
                    remotes: Granted::Route(name("ssh")),
                },
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Inspect,
                    acknowledged: Exposure::NONE,
                    lends: Lends::none(),
                },
            }),
            true,
        );
    }

    /// Connects `remote` from the desk, starts its client, and has the
    /// server turn every way the client offered down.
    fn refused(&mut self, remote: &RemoteId) -> Step {
        self.ask(
            DESK,
            Request::Connect {
                remote: remote.clone(),
                with: Vec::new(),
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
            true,
        );
        let (connection, _) = self.core.state().connection(remote).unwrap();
        let surveyed = self.step(Input::Channel {
            connection,
            told: common::placing(&[Serving {
                capability: name("gpg"),
                binding: Binding::Socket(
                    RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap(),
                ),
            }]),
        });
        // What readiness recorded is read by both surfaces, and whatever
        // that frees a place for, before the channel's end arrives.
        let mut unread = vec![surveyed];
        while let Some(step) = unread.pop() {
            for link in [DESK, ICON] {
                for _ in 0..frames(&step, link) {
                    unread.push(self.step(Input::Sent { link }));
                }
            }
        }
        let denied = format!("{}: Permission denied (publickey).", remote.address);
        self.step(Input::Channel {
            connection,
            told: Told::Ended {
                status: 255,
                unverified: false,
                last: Some(words(&denied).unwrap()),
            },
        })
    }

    fn present(&mut self, link: Link, presence: Presence) {
        self.ask(link, Request::Presence(presence), true);
    }
}

fn stopped(remote: &RemoteId) -> Attention {
    Attention::Stopped {
        remote: remote.clone(),
        end: ChannelEnd::Unauthenticated(words("publickey").unwrap()),
    }
}

/// What is announced is announced by the present surface the person was
/// last seen at and shown by the others, once; one they left is never the
/// one that announces.
#[test]
fn what_is_announced_is_heard_once_across_surfaces() {
    let mut scene = Scene::new(Vec::new());
    scene.core.begin(DESKTOP, None, Vec::new(), scene.now);
    scene.attend(DESK, ClientKind::Terminal);
    scene.attend(ICON, ClientKind::Interface);
    scene.grant();

    let first = remote("build-7.example");
    scene.ask(
        DESK,
        Request::Connect {
            remote: first.clone(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
        true,
    );
    scene.present(ICON, Presence::Present);
    let step = scene.refused(&first);
    assert!(matches!(
        step.entries.last().map(|entry| &entry.event),
        Some(Event::Down {
            end: ChannelEnd::Unauthenticated(_),
            ..
        })
    ));
    assert_eq!(raised(&step, ICON), [(stopped(&first), Volume::Announced)]);
    assert_eq!(raised(&step, DESK), [(stopped(&first), Volume::Shown)]);

    // Anything that happens after is not a second time for it.
    let step = scene.ask(ICON, Request::Presence(Presence::Present), false);
    assert!(raised(&step, ICON).is_empty() && raised(&step, DESK).is_empty());
    for _ in 0..frames(&step, ICON) {
        scene.step(Input::Sent { link: ICON });
    }

    // Seen last but gone away: the other surface announces.
    let second = remote("build-8.example");
    scene.present(ICON, Presence::Present);
    scene.present(ICON, Presence::Away);
    let step = scene.refused(&second);
    assert_eq!(raised(&step, DESK), [(stopped(&second), Volume::Announced)]);
    assert_eq!(raised(&step, ICON), [(stopped(&second), Volume::Shown)]);
}

/// Something that was waiting as the run started is read by a client that
/// attaches, never raised to it; what appears after it attached is.
#[test]
fn only_what_appears_while_a_client_attends_is_raised_to_it() {
    let mut scene = Scene::new(Vec::new());
    let begun = scene
        .core
        .begin(DESKTOP, Some(Breakdown::Hung), Vec::new(), scene.now);
    assert!(
        !begun
            .effects
            .iter()
            .any(|effect| matches!(effect, Effect::Send { .. })),
        "nobody to tell"
    );
    let step = scene.attend(DESK, ClientKind::Terminal);
    assert!(raised(&step, DESK).is_empty(), "{step:?}");
    let step = scene.ask(DESK, Request::Attention, true);
    assert!(
        step.effects.iter().any(|effect| matches!(
            effect,
            Effect::Send { frame: FromCore::Reply { reply: Ok(Reply::Attention(items)), .. }, .. }
                if items.iter().any(|needs| matches!(needs.attention, Attention::Restarted { .. }))
        )),
        "{step:?}"
    );

    scene.grant();
    let later = remote("build-7.example");
    let step = scene.refused(&later);
    assert_eq!(raised(&step, DESK), [(stopped(&later), Volume::Announced)]);
}

/// A burst from a remote: requests recorded in this run by what serves the
/// capability, before any threshold was set.
fn requests() -> Vec<Entry> {
    let mut trail = vec![
        Entry {
            seq: Seq(1),
            at: at(0).at,
            tick: Tick(0),
            event: Event::Started {
                version: "0.2.0".to_owned(),
                origin: DESKTOP,
                after: None,
            },
        },
        Entry {
            seq: Seq(2),
            at: at(10).at,
            tick: Tick(10),
            event: Event::Opening {
                remote: remote("build-7.example"),
                with: Vec::new(),
                opener: Opener::Grant,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        },
    ];
    for (seq, tick) in [(3, 100), (4, 200), (5, 300)] {
        trail.push(Entry {
            seq: Seq(seq),
            at: at(tick).at,
            tick: Tick(tick),
            event: Event::Asked {
                connection: ConnectionId(Seq(2)),
                capability: name("gpg"),
                operation: Operation::Sign,
                key: None,
            },
        });
    }
    trail
}

fn threshold(requests: u8, seconds: u32) -> Request {
    Request::Change(Change::Burst {
        remotes: Remotes::Every,
        threshold: Some(Threshold::At(Burst {
            requests: NonZeroU8::new(requests).unwrap(),
            seconds: NonZeroU32::new(seconds).unwrap(),
        })),
    })
}

/// A burst interrupts every watching surface once, with no count after the
/// first; a surface with no place free for it is told its attention is
/// stale instead, before any entry it follows. When the window ends, it
/// is gone with no notice of its own, and it is raised again if it comes
/// back.
#[test]
fn a_burst_is_raised_once_and_again_only_after_it_has_lapsed() {
    let mut scene = Scene::new(requests());
    scene.attend(DESK, ClientKind::Terminal);
    scene.attend(ICON, ClientKind::Interface);

    // The interface follows the trail and does not read: its places fill.
    let step = scene.ask(ICON, Request::Follow { after: None }, false);
    let mut owed = frames(&step, ICON);
    for _ in 0..usize::from(WAITING) {
        let step = scene.ask(DESK, Request::Pause(Remotes::Every), true);
        owed += frames(&step, ICON);
        let step = scene.ask(DESK, Request::Resume(Remotes::Every), true);
        owed += frames(&step, ICON);
    }
    assert_eq!(
        owed,
        usize::from(WAITING) - 1,
        "every place but the one kept for a reply"
    );

    // The interface itself sets the threshold: its reply takes the place
    // kept for it, and nothing it did marks what it shows stale but this.
    let burst = remote("build-7.example");
    let step = scene.ask(ICON, threshold(3, 60), false);
    owed += frames(&step, ICON);
    assert_eq!(
        raised(&step, DESK),
        [(
            Attention::Burst {
                remote: burst.clone(),
                requests: 3
            },
            Volume::Interrupts
        )]
    );
    assert!(notices(&step, ICON).is_empty(), "no place for it");
    assert_eq!(frames(&step, ICON), 1, "its reply");
    assert_eq!(
        scene.core.due(),
        Some(Tick(60_100)),
        "the first request leaves the window"
    );

    // Counted again with a fourth threshold: the same burst, not a new one.
    let step = scene.ask(DESK, threshold(2, 60), true);
    assert_eq!(raised(&step, DESK), Vec::<(Attention, Volume)>::new());

    // As the interface reads, its attention is said to be stale before any
    // entry it follows, and the burst is not raised to it late.
    let mut read = Vec::new();
    for _ in 0..owed {
        read.extend(notices(&scene.step(Input::Sent { link: ICON }), ICON));
    }
    let stale: Vec<&Notice> = read
        .iter()
        .take_while(|notice| matches!(notice, Notice::Stale(_)))
        .collect();
    assert!(
        stale.contains(&&Notice::Stale(Topic::Attention)),
        "{read:?}"
    );
    assert!(
        !read
            .iter()
            .any(|notice| matches!(notice, Notice::Raised(_))),
        "{read:?}"
    );

    // The window ends: nothing is withdrawn, and what is shown is stale.
    scene.now = at(60_100);
    let step = scene.step(Input::Due);
    assert!(
        notices(&step, DESK)
            .iter()
            .all(|notice| matches!(notice, Notice::Stale(_))),
        "{step:?}"
    );
    assert!(notices(&step, DESK).contains(&Notice::Stale(Topic::Attention)));
    scene.now = at(60_300);
    scene.step(Input::Due);
    assert_eq!(scene.core.due(), None);

    // A longer window takes the same requests in again: a burst again.
    let step = scene.ask(DESK, threshold(3, 3_600), true);
    assert_eq!(
        raised(&step, DESK),
        [(
            Attention::Burst {
                remote: burst,
                requests: 3
            },
            Volume::Interrupts
        )]
    );
}

/// A core whose trail holds a signature asked for through each of two
/// channels, both held, with `gpg` granted for as long as the core runs, so
/// both channels stay wanted.
fn holding_two() -> Scene {
    let mut trail = requests();
    trail.truncate(3);
    let opened = |seq: u64, address: &str| Entry {
        seq: Seq(seq),
        at: at(300 + seq).at,
        tick: Tick(300 + seq),
        event: Event::Opening {
            remote: remote(address),
            with: Vec::new(),
            opener: Opener::Grant,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    };
    let entry = |seq: u64, event: Event| Entry {
        seq: Seq(seq),
        at: at(300 + seq).at,
        tick: Tick(300 + seq),
        event,
    };
    trail.push(entry(
        4,
        Event::Held {
            request: RequestId(Seq(3)),
        },
    ));
    trail.push(opened(5, "scratch-7.example"));
    trail.push(entry(
        6,
        Event::Asked {
            connection: ConnectionId(Seq(5)),
            capability: name("gpg"),
            operation: Operation::Sign,
            key: None,
        },
    ));
    trail.push(entry(
        7,
        Event::Held {
            request: RequestId(Seq(6)),
        },
    ));
    let catalogue = Catalogue::shipped().unwrap();
    let mut configuration = Configuration::default();
    configuration
        .apply(
            &catalogue,
            Change::Grant {
                grant: Grant {
                    capability: name("gpg"),
                    remotes: Granted::Route(name("ssh")),
                },
                terms: Terms {
                    activation: Activation::Continuous,
                    setup: Setup::Inspect,
                    acknowledged: Exposure::NONE,
                    lends: Lends::none(),
                },
            },
        )
        .unwrap();
    Scene {
        core: Core::new(catalogue, configuration, trail, "0.2.0".to_owned()),
        now: at(1_000),
        asked: 0,
    }
}

/// What was held is refused at once, saying where the person was, by
/// whatever leaves nothing to put it to: here a remote's card set not to be
/// shown over the application that fills the screen, and the desktop
/// beginning to take nothing.
#[test]
fn what_was_held_is_refused_once_nothing_can_put_it_to_the_person() {
    let mut scene = holding_two();
    scene.attend(ICON, ClientKind::Interface);
    let held = |step: &Step| {
        step.effects.iter().find_map(|effect| match effect {
            Effect::Send {
                frame:
                    FromCore::Reply {
                        reply: Ok(Reply::Attention(items)),
                        ..
                    },
                ..
            } => Some(
                items
                    .iter()
                    .filter(|needs| matches!(needs.attention, Attention::Request { .. }))
                    .count(),
            ),
            _ => None,
        })
    };
    let step = scene.ask(ICON, Request::Attention, true);
    assert_eq!(held(&step), Some(2), "both requests are held");
    let refused = |step: &Step| -> Vec<(RequestId, Whereabouts)> {
        step.entries
            .iter()
            .filter_map(|entry| match &entry.event {
                Event::Settled {
                    request,
                    outcome: Outcome::Refused(Refusal::NobodyReachable(whereabouts)),
                } => Some((*request, *whereabouts)),
                _ => None,
            })
            .collect()
    };

    let step = scene.ask(ICON, Request::Presence(Presence::CardOnly), true);
    assert!(refused(&step).is_empty(), "the card is shown, as it ships");
    let step = scene.ask(
        ICON,
        Request::Change(Change::FullScreen {
            remotes: Remotes::One(remote("build-7.example")),
            card: Some(FullScreen::NotShown),
        }),
        true,
    );
    assert_eq!(
        refused(&step),
        [(RequestId(Seq(3)), Whereabouts::FullScreen)]
    );
    let step = scene.ask(ICON, Request::Presence(Presence::Engaged), true);
    assert_eq!(refused(&step), [(RequestId(Seq(6)), Whereabouts::Engaged)]);
    let step = scene.ask(ICON, Request::Presence(Presence::Present), true);
    assert!(refused(&step).is_empty(), "nothing is held any more");
}

/// The reply `step` sent `to`.
fn reply(step: &Step, to: Link) -> Option<&Result<Reply, Refusal>> {
    step.effects.iter().find_map(|effect| match effect {
        Effect::Send {
            link,
            frame: FromCore::Reply { reply, .. },
            ..
        } if *link == to => Some(reply),
        _ => None,
    })
}

/// The interface says its icon is missing; the window is told the status is
/// stale and reads why there, for that interface. Said again, nothing is
/// recorded and nobody is told; a terminal, having no icon, is refused.
#[test]
fn what_the_interface_says_of_its_icon_reaches_the_window_through_the_status() {
    const WINDOW: Link = Link(3);
    let mut scene = Scene::new(Vec::new());
    scene.core.begin(DESKTOP, None, Vec::new(), scene.now);
    scene.attend(DESK, ClientKind::Terminal);
    scene.attend(ICON, ClientKind::Interface);
    scene.attend(WINDOW, ClientKind::Viewer);

    let missing = Icon::Missing(Missing::NoTaskbar);
    let step = scene.ask(ICON, Request::Icon(missing), false);
    assert_eq!(reply(&step, ICON), Some(&Ok(Reply::Done(Changed::Changed))));
    assert!(matches!(
        step.entries.as_slice(),
        [Entry {
            event: Event::Icon { icon, .. },
            ..
        }] if *icon == missing
    ));
    assert!(notices(&step, WINDOW).contains(&Notice::Stale(Topic::Status)));
    for link in [ICON, DESK, WINDOW] {
        for _ in 0..frames(&step, link) {
            scene.step(Input::Sent { link });
        }
    }
    let step = scene.ask(WINDOW, Request::Status, true);
    let Some(Ok(Reply::Status(status))) = reply(&step, WINDOW) else {
        panic!("a status");
    };
    let icons: Vec<(ClientKind, Option<Icon>)> = status
        .attached
        .iter()
        .map(|attached| (attached.kind, attached.icon))
        .collect();
    assert_eq!(
        icons,
        [
            (ClientKind::Terminal, None),
            (ClientKind::Interface, Some(missing)),
            (ClientKind::Viewer, None),
        ]
    );

    let step = scene.ask(ICON, Request::Icon(missing), true);
    assert_eq!(
        reply(&step, ICON),
        Some(&Ok(Reply::Done(Changed::Unchanged)))
    );
    assert!(step.entries.is_empty() && notices(&step, WINDOW).is_empty());

    let step = scene.ask(DESK, Request::Icon(Icon::Shown), true);
    assert_eq!(reply(&step, DESK), Some(&Err(Refusal::NoIcon)));
    assert_eq!(step.entries, Vec::<Entry>::new());
}
