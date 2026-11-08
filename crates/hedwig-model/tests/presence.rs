//! Where the person is, as the core reads it from what each attending surface
//! says it can show: whether a request is served, held or refused, and why;
//! which surface announces; what is refused when a change leaves a held
//! request with nobody to put it to; and what a held request and a returning
//! channel say to a client.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod support;

use std::collections::BTreeSet;
use std::num::NonZeroU32;

use hedwig_model::capability::Operation;
use hedwig_model::config::Effect;
use hedwig_model::config::{Activation, Catalogue, Change, Configuration};
use hedwig_model::gate::{Capped, Verdict, World};
use hedwig_model::policy::{Basis, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{Attention, Needs, Reply, Request, Row, Standing, Topic};
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::{Granted, Member, RemoteId, Remotes, Set};
use hedwig_model::scope::Holder;
use hedwig_model::setting::{CapScope, FullScreen, Heard, Longest, Returns, Volume, Waits};
use hedwig_model::trail::{
    ChannelEnd, ClientId, ClientKind, ConnectionId, Event, Finding, Icon, Missing, Outcome,
    Presence, Readiness, RequestId, Tick,
};

use support::desk::Desk;
use support::{DESKTOP, OVER_SSH, Trail, catalogue, granting, name, remote};

fn prod() -> RemoteId {
    remote("ssh", "prod-1")
}

fn scratch() -> RemoteId {
    remote("ssh", "scratch-7")
}

fn seconds(number: u32) -> NonZeroU32 {
    NonZeroU32::new(number).unwrap()
}

/// `gpg` granted to every host on `ssh`, a channel to `prod-1` and one to
/// `scratch-7`, and nobody attached.
struct Scene {
    catalogue: Catalogue,
    configuration: Configuration,
    trail: Trail,
    prod: ConnectionId,
    scratch: ConnectionId,
}

impl Scene {
    fn new() -> Scene {
        let catalogue = catalogue();
        let configuration = granting(&catalogue, &[("gpg", Granted::Route(name("ssh")))]);
        let mut trail = Trail::started();
        let prod = trail.open(&prod(), "linux");
        let scratch = trail.open(&scratch(), "linux");
        Scene {
            catalogue,
            configuration,
            trail,
            prod,
            scratch,
        }
    }

    fn world<T>(&self, ask: impl FnOnce(&World<'_>) -> T) -> T {
        let state = self.trail.state();
        ask(&World {
            catalogue: &self.catalogue,
            configuration: &self.configuration,
            state: &state,
        })
    }

    fn set(&mut self, change: Change) {
        self.configuration
            .apply(&self.catalogue, change)
            .expect("the change is accepted");
    }

    fn rule(&mut self, remotes: Remotes, mode: Mode) {
        self.set(Change::Rule {
            scope: RuleScope {
                remotes,
                capability: Selector::Every,
                operation: Selector::Only(Operation::Sign),
                key: Keys::Every,
            },
            mode,
        });
    }

    fn presence(&mut self, client: ClientId, presence: Presence) {
        self.trail.push(Event::Presence { client, presence });
    }

    fn sign(&self, connection: ConnectionId) -> Verdict {
        let now = self.trail.tick();
        self.world(|world| world.decide(connection, &name("gpg"), Operation::Sign, None, now))
    }

    /// A signature asked for and held, as the core records one.
    fn held(&mut self, connection: ConnectionId) -> RequestId {
        assert!(matches!(self.sign(connection), Verdict::Hold(_)));
        let request = RequestId(self.trail.push(Event::Asked {
            connection,
            capability: name("gpg"),
            operation: Operation::Sign,
            key: None,
        }));
        self.trail.push(Event::Held { request });
        request
    }

    /// What the core does after every step: refuses what was held and can
    /// no longer be put to the person. Returns what it refused.
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "the method's lifetime is early-bound, so its path is not general enough"
    )]
    fn strand(&mut self) -> Vec<(RequestId, Whereabouts)> {
        let stranded = self.world(|world| world.stranded());
        for (request, whereabouts) in &stranded {
            self.trail.push(Event::Settled {
                request: *request,
                outcome: Outcome::Refused(Refusal::NobodyReachable(*whereabouts)),
            });
        }
        stranded
    }

    fn needs(&self, client: ClientId) -> Vec<Needs> {
        let now = self.trail.tick();
        self.world(|world| world.attention(client, now))
    }

    fn row(&self, client: ClientId, remote: &RemoteId) -> Row {
        let now = self.trail.tick();
        self.world(|world| world.rows(client, now))
            .into_iter()
            .find(|row| row.remote.as_ref() == Some(remote))
            .expect("a row for the remote")
    }
}

fn refused(whereabouts: Whereabouts) -> Verdict {
    Verdict::Refuse(Refusal::NobodyReachable(whereabouts))
}

/// A request nobody can be asked about is refused saying where the person
/// was: away; at a desktop that takes nothing; or at one a full-screen
/// application fills, with that remote's card set not to be shown there.
/// Where two surfaces disagree, the one the person was last seen at says.
#[test]
fn a_request_nobody_can_be_asked_about_says_where_the_person_was() {
    let mut scene = Scene::new();
    scene.rule(Remotes::One(prod()), Mode::Confirm);
    assert_eq!(scene.sign(scene.prod), refused(Whereabouts::Away));
    assert_eq!(scene.sign(scene.scratch), refused(Whereabouts::Away));

    let desk = scene.trail.attach(ClientKind::Interface, DESKTOP);
    scene.presence(desk, Presence::Engaged);
    assert_eq!(scene.sign(scene.prod), refused(Whereabouts::Engaged));
    assert_eq!(
        scene.sign(scene.scratch),
        refused(Whereabouts::Engaged),
        "nothing would show it served"
    );

    scene.set(Change::FullScreen {
        remotes: Remotes::One(prod()),
        card: Some(FullScreen::NotShown),
    });
    scene.presence(desk, Presence::CardOnly);
    assert_eq!(scene.sign(scene.prod), refused(Whereabouts::FullScreen));
    assert!(
        matches!(
            scene.sign(scene.scratch),
            Verdict::Serve(Outcome::Served(_))
        ),
        "the person is there, and the icon shows what was served"
    );

    let other = scene.trail.attach(ClientKind::Interface, DESKTOP);
    scene.presence(other, Presence::Engaged);
    assert_eq!(scene.sign(scene.prod), refused(Whereabouts::Engaged));
    scene.presence(desk, Presence::CardOnly);
    assert_eq!(scene.sign(scene.prod), refused(Whereabouts::FullScreen));

    scene.presence(desk, Presence::Away);
    scene.presence(other, Presence::Away);
    assert_eq!(scene.sign(scene.prod), refused(Whereabouts::Away));
    scene.rule(Remotes::One(prod()), Mode::Unattended);
    assert!(matches!(
        scene.sign(scene.prod),
        Verdict::Serve(Outcome::Unseen(Basis::Rule(_)))
    ));

    let sentences: BTreeSet<String> = [
        Whereabouts::Away,
        Whereabouts::Engaged,
        Whereabouts::FullScreen,
    ]
    .into_iter()
    .map(|whereabouts| Refusal::NobodyReachable(whereabouts).to_string())
    .collect();
    assert_eq!(sentences.len(), 3, "{sentences:?}");
}

/// Whatever leaves a held request with nobody to put it to refuses it: a
/// remote's card set not to be shown over the application that fills the
/// screen, a desktop that begins to take nothing, a set a terminal watches
/// that no longer names the remote, a surface that leaves.
#[test]
fn what_leaves_a_held_request_unaskable_refuses_it() {
    let mut scene = Scene::new();
    scene.rule(Remotes::Every, Mode::Confirm);
    let desk = scene.trail.attach(ClientKind::Interface, DESKTOP);
    scene.presence(desk, Presence::CardOnly);
    let on_prod = scene.held(scene.prod);
    let on_scratch = scene.held(scene.scratch);
    assert!(scene.strand().is_empty(), "the card is shown, as it ships");

    scene.set(Change::FullScreen {
        remotes: Remotes::One(prod()),
        card: Some(FullScreen::NotShown),
    });
    assert_eq!(scene.strand(), [(on_prod, Whereabouts::FullScreen)]);
    assert!(scene.strand().is_empty(), "refused once");

    scene.presence(desk, Presence::Engaged);
    assert_eq!(scene.strand(), [(on_scratch, Whereabouts::Engaged)]);

    scene.set(Change::DefineSet(Set {
        id: name("watched"),
        members: vec![Member::One(prod())],
    }));
    let terminal = scene.trail.attach_to(
        ClientKind::Terminal,
        OVER_SSH,
        Remotes::Set(name("watched")),
    );
    let watched = scene.held(scene.prod);
    assert_eq!(scene.strand(), Vec::<(RequestId, Whereabouts)>::new());
    scene.set(Change::DefineSet(Set {
        id: name("watched"),
        members: vec![Member::One(scratch())],
    }));
    assert_eq!(
        scene.strand(),
        [(watched, Whereabouts::Engaged)],
        "the desk the person was last seen at still takes nothing"
    );

    let last = scene.held(scene.scratch);
    scene.trail.push(Event::Detached { client: terminal });
    scene.trail.push(Event::Detached { client: desk });
    assert_eq!(scene.strand(), [(last, Whereabouts::Away)]);
}

/// What is announced goes to a surface that says it now: a present one
/// before one behind a full-screen application, whose notification Windows
/// holds back, whoever the person was last seen at; and never to one that
/// takes nothing.
#[test]
fn what_is_announced_goes_to_a_surface_that_says_it_now() {
    let mut scene = Scene::new();
    let desk = scene.trail.attach(ClientKind::Interface, DESKTOP);
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    scene.trail.push(Event::Checked {
        connection: scene.prod,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![Finding::ToolAbsent(name("gpgconf"))]),
    });
    scene.set(Change::Hear {
        remotes: Remotes::One(prod()),
        heard: Heard::Served(Waits::Announced),
    });
    let told = |scene: &Scene| {
        let unready = scene
            .needs(desk)
            .into_iter()
            .find(|needs| matches!(needs.attention, Attention::Unready { .. }))
            .expect("failed readiness");
        assert_eq!(unready.volume, Volume::Announced);
        scene.world(|world| world.hears(&unready))
    };

    scene.presence(desk, Presence::CardOnly);
    assert_eq!(
        told(&scene),
        [(desk, Volume::Shown), (terminal, Volume::Announced)],
        "the person was last seen at the desk"
    );
    assert_eq!(
        scene.world(|world| world.announces(&prod())),
        Some(terminal)
    );

    scene.trail.push(Event::Detached { client: terminal });
    assert_eq!(told(&scene), [(desk, Volume::Announced)]);
    assert_eq!(scene.world(|world| world.announces(&prod())), Some(desk));

    scene.presence(desk, Presence::Engaged);
    assert_eq!(told(&scene), [(desk, Volume::Shown)]);
    assert_eq!(scene.world(|world| world.announces(&prod())), None);
}

/// A held request names the cap that took some of the lengths offered away,
/// and whose it is; where every length is offered, it names none, though a
/// cap covers it.
#[test]
fn a_held_request_names_the_cap_that_took_lengths_away() {
    let mut scene = Scene::new();
    scene.rule(Remotes::Every, Mode::Confirm);
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    let on_prod = scene.held(scene.prod);
    let on_scratch = scene.held(scene.scratch);
    let held = |scene: &Scene, request: RequestId| {
        scene
            .needs(terminal)
            .into_iter()
            .find_map(|needs| match needs.attention {
                Attention::Request {
                    request: held,
                    offers,
                    capped,
                    ..
                } if held == request => Some((offers, capped)),
                _ => None,
            })
            .expect("held")
    };
    let shipped: Vec<NonZeroU32> = [60, 900, 3600].into_iter().map(seconds).collect();
    assert_eq!(held(&scene, on_prod), (shipped.clone(), None));

    let cap = |remotes, longest| Change::Cap {
        scope: CapScope {
            remotes,
            key: Keys::Every,
        },
        longest: Some(longest),
    };
    scene.set(cap(Remotes::One(prod()), Longest::Seconds(seconds(900))));
    scene.set(cap(Remotes::Every, Longest::Seconds(seconds(28_800))));
    assert_eq!(
        held(&scene, on_prod),
        (
            vec![seconds(60), seconds(900)],
            Some(Capped {
                longest: Longest::Seconds(seconds(900)),
                holder: Holder::Person,
                scope: CapScope {
                    remotes: Remotes::One(prod()),
                    key: Keys::Every,
                },
            })
        )
    );
    assert_eq!(
        held(&scene, on_scratch),
        (shipped, None),
        "a cap covers it and takes nothing away"
    );

    scene.set(cap(Remotes::One(scratch()), Longest::Nothing));
    let (offers, capped) = held(&scene, on_scratch);
    assert_eq!(offers, Vec::<NonZeroU32>::new());
    assert_eq!(capped.map(|capped| capped.longest), Some(Longest::Nothing));
}

/// A channel that comes back by itself says, to the client reading the
/// row, how many seconds from the reply it is opened again: counting down
/// as the core's clock runs, and nothing once it is due or is opened at
/// once.
#[test]
fn a_returning_channel_says_how_long_until_it_is_opened_again() {
    let mut scene = Scene::new();
    let exposure = support::capability(&scene.catalogue, "gpg").exposure();
    scene.set(Change::Grant {
        grant: support::grant("gpg", Granted::Route(name("ssh"))),
        terms: support::terms(Activation::Continuous, exposure),
    });
    scene.set(Change::Returns {
        remotes: Remotes::Every,
        returns: Some(Returns {
            first: seconds(30),
            longest: seconds(600),
        }),
    });
    let terminal = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    let standing = |scene: &Scene| scene.row(terminal, &prod()).standing;

    scene.trail.wait(1000);
    scene.trail.push(Event::Down {
        connection: scene.prod,
        end: ChannelEnd::ForwardRefused,
    });
    assert_eq!(
        standing(&scene),
        Standing::Returning {
            end: ChannelEnd::ForwardRefused,
            wait: Some(seconds(30)),
        }
    );
    scene.trail.wait(12_500);
    assert_eq!(
        standing(&scene),
        Standing::Returning {
            end: ChannelEnd::ForwardRefused,
            wait: Some(seconds(18)),
        },
        "17.5 seconds left, said as the second it is opened in"
    );
    scene.trail.wait(17_500);
    assert_eq!(
        standing(&scene),
        Standing::Returning {
            end: ChannelEnd::ForwardRefused,
            wait: None,
        }
    );

    scene.trail.push(Event::Down {
        connection: scene.scratch,
        end: ChannelEnd::Slept,
    });
    assert_eq!(
        scene.row(terminal, &scratch()).standing,
        Standing::Returning {
            end: ChannelEnd::Slept,
            wait: None,
        },
        "after a sleep it is opened at once"
    );
    assert_eq!(scene.trail.tick(), Tick(31_000));
}

/// What an interface says of its icon is in the status every client reads,
/// for that interface, until it says otherwise or leaves: the window and the
/// command line can say the taskbar does not show Hedwig while the person
/// who closed the presence's own notice looks there. Said again, nothing is
/// recorded; said by a client with no icon, it is refused.
#[test]
fn whether_each_interfaces_icon_is_shown_is_in_the_status_every_client_reads() {
    let mut desk = Desk::new(catalogue());
    let presence = desk.attend(ClientKind::Interface, DESKTOP);
    let window = desk.attend(ClientKind::Viewer, DESKTOP);
    let icon = |desk: &mut Desk, of: ClientId| -> Option<Option<Icon>> {
        let status = match desk.send(window, Request::Status) {
            Ok(Reply::Status(status)) => Some(status),
            _ => None,
        }
        .expect("a status");
        status
            .attached
            .iter()
            .find(|attached| attached.client == of)
            .map(|attached| attached.icon)
    };
    assert_eq!(icon(&mut desk, presence), Some(None), "nothing said yet");

    let refused = Icon::Missing(Missing::Refused);
    assert_eq!(
        desk.send(presence, Request::Icon(refused)),
        Ok(Reply::Done(Effect::Changed))
    );
    let recorded = desk.trail.entries.len();
    assert_eq!(
        desk.send(presence, Request::Icon(refused)),
        Ok(Reply::Done(Effect::Unchanged))
    );
    assert_eq!(
        desk.trail.entries.len(),
        recorded,
        "said again, recorded once"
    );
    assert_eq!(icon(&mut desk, presence), Some(Some(refused)));
    assert_eq!(
        icon(&mut desk, window),
        Some(None),
        "a viewer says nothing of one"
    );

    let none = Icon::Missing(Missing::NoTaskbar);
    desk.send(presence, Request::Icon(none)).unwrap();
    assert_eq!(icon(&mut desk, presence), Some(Some(none)));
    desk.send(presence, Request::Icon(Icon::Shown)).unwrap();
    assert_eq!(icon(&mut desk, presence), Some(Some(Icon::Shown)));
    desk.detach(presence);
    assert_eq!(icon(&mut desk, presence), None, "gone with the interface");

    for kind in [
        ClientKind::Command,
        ClientKind::Terminal,
        ClientKind::Viewer,
    ] {
        let client = desk.attend(kind, OVER_SSH);
        assert_eq!(
            desk.send(client, Request::Icon(refused)),
            Err(Refusal::NoIcon),
            "{kind:?}"
        );
    }
    assert_eq!(
        [Missing::Refused, Missing::NoTaskbar].map(|missing| missing.to_string()),
        [
            "Windows' taskbar does not show Hedwig's icon",
            "Windows' taskbar is not running, so Hedwig's icon cannot be shown",
        ]
    );
}

/// An icon's report is the presence's, never the person at it: it moves
/// nothing of where the person was last seen, so it cannot decide where a
/// refusal says they were.
#[test]
fn an_icon_report_says_nothing_of_where_the_person_is() {
    let mut scene = Scene::new();
    scene.rule(Remotes::One(prod()), Mode::Confirm);
    scene.set(Change::FullScreen {
        remotes: Remotes::One(prod()),
        card: Some(FullScreen::NotShown),
    });
    let desk = scene.trail.attach(ClientKind::Interface, DESKTOP);
    let other = scene.trail.attach(ClientKind::Interface, DESKTOP);
    scene.presence(other, Presence::Engaged);
    scene.presence(desk, Presence::CardOnly);
    assert_eq!(scene.sign(scene.prod), refused(Whereabouts::FullScreen));
    for icon in [Icon::Missing(Missing::Refused), Icon::Shown] {
        scene.trail.push(Event::Icon {
            client: other,
            icon,
        });
        assert_eq!(
            scene.sign(scene.prod),
            refused(Whereabouts::FullScreen),
            "the person was last seen at the desk that fills its screen"
        );
    }
    assert_eq!(
        Event::Icon {
            client: other,
            icon: Icon::Shown,
        }
        .touches(),
        [Topic::Status]
    );
}
