//! What the deciding function makes of a relayed connection: each request it
//! records and decides, the person's word on one it holds, the ways a held
//! one ends without it, what the workstation's side and the remote break,
//! the served request announced, and a client that is kept fresh and never
//! asked.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

mod common;

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use hedwig_core::adb::{Forward, Forwarding, Reverse};
use hedwig_core::agent::{Ask as AgentAsk, Breach as AgentBreach};
use hedwig_core::assuan::{Ask, Breach, Side};
use hedwig_core::channel::Unplaced;
use hedwig_core::dispatch::{Core, Effect, Input, Knock, Link, Now, ReadId, Step};
use hedwig_core::keys::{Cards, Known};
use hedwig_core::relay::Reach;
use hedwig_core::relay::{Relayed, Relaying};
use hedwig_model::capability::{
    Access, AgentAt, Capability, Exposure, Home, Installation, Lends, Operation, Setup, Source,
    Toward,
};
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Grant, Terms};
use hedwig_model::holder::{Rights, SignedIn, SourceHolder, Whose};
use hedwig_model::policy::{Basis, ConnectionScope, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{
    AgentKey, Attention, Decision, FromCore, Notice, PROTOCOL, Reply, Request, Served, ToCore,
    Topic,
};
use hedwig_model::refusal::{Refusal, Whereabouts, Withheld};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::setting::{Heard, Waits};
use hedwig_model::text::Location;
use hedwig_model::text::{
    Address, DeviceSerial, DeviceSocket, Fingerprint, Folder, Grip, KeyId, Mark, Name, Port,
    RemotePath, Serial, SshKey, Words,
};
use hedwig_model::trail::{
    Binding, Card, Carriage, ClientKind, ConnectionId, Dropped, Event, Failure, Health, Held,
    Integrity, Key, Keyring, Origin, Outcome, Payload, Peer, RequestId, Serving, SignaturePin,
    Target, Tick, Timestamp, Touch, Uses,
};

const TERMINAL: Link = Link(1);
const VIEWER: Link = Link(2);
const NOW: Now = Now {
    at: Timestamp(1_790_000_000_000),
    tick: Tick(1_000),
};
const DESKTOP: Origin = Origin {
    process: 4100,
    logon: 0x3e7_0000,
    session: 2,
    integrity: Integrity::Medium,
};
const GRIP: &str = "64EFB4597F2EB1968F187B7235A461FC48342EC5";

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn remote() -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from("dev@build-7.example").unwrap(),
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

struct Scene {
    core: Core,
    asked: u32,
    connection: ConnectionId,
}

impl Scene {
    /// A terminal attached, `gpg` granted to the remote with its keys'
    /// writes consented to, and the channel up forwarding it.
    fn new() -> Scene {
        let socket = RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap();
        Scene::granted("gpg", Exposure::NONE, Binding::Socket(socket))
    }

    /// A terminal attached, `capability` granted to the remote acknowledging
    /// `acknowledged`, and the channel up forwarding it at `binding`.
    fn granted(capability: &str, acknowledged: Exposure, binding: Binding) -> Scene {
        let mut scene = Scene::attached();
        scene.forwarding(capability, acknowledged, binding);
        scene
    }

    /// A terminal attached to a core that has begun.
    fn attached() -> Scene {
        let mut core = Core::new(
            Catalogue::shipped().unwrap(),
            Configuration::default(),
            Vec::new(),
            "0.2.0".to_owned(),
        );
        core.begin(DESKTOP, None, Vec::new(), NOW);
        let mut scene = Scene {
            core,
            asked: 0,
            connection: ConnectionId(hedwig_model::trail::Seq(0)),
        };
        scene.attach(TERMINAL, ClientKind::Terminal);
        scene
    }

    /// `capability` granted to the remote acknowledging `acknowledged`, and
    /// the channel up forwarding it at `binding`.
    fn forwarding(&mut self, capability: &str, acknowledged: Exposure, binding: Binding) {
        let scene = self;
        scene.ask(
            TERMINAL,
            Request::Change(Change::Grant {
                grant: Grant {
                    capability: name(capability),
                    remotes: Granted::One(remote()),
                },
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Write,
                    acknowledged,
                    lends: Lends::none(),
                },
            }),
        );
        scene.ask(
            TERMINAL,
            Request::Connect {
                remote: remote(),
                with: Vec::new(),
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        );
        let (connection, _) = scene.core.state().connection(&remote()).unwrap();
        scene.connection = connection;
        let serving = Serving {
            capability: name(capability),
            binding,
        };
        scene.step(Input::Channel {
            connection,
            told: common::placing(std::slice::from_ref(&serving)),
        });
        scene.step(Input::Channel {
            connection,
            told: hedwig_core::dispatch::Told::Forwarded {
                capability: name(capability),
                bound: true,
            },
        });
    }

    fn step(&mut self, input: Input) -> Step {
        let step = self.core.step(input, NOW);
        common::keyed(&mut self.core, step, NOW)
    }

    fn attach(&mut self, link: Link, kind: ClientKind) {
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
        );
    }

    fn ask(&mut self, link: Link, request: Request) -> Step {
        self.asked += 1;
        let frame = ToCore {
            id: self.asked,
            request,
        };
        let step = self.step(Input::Asked { link, frame });
        for _ in step
            .effects
            .iter()
            .filter(|effect| matches!(effect, Effect::Send { link: to, .. } if *to == link))
        {
            self.core.step(Input::Sent { link }, NOW);
        }
        step
    }

    /// The refusal the reply to `to` carries, if it is one.
    fn refused(step: &Step, to: Link) -> Option<Refusal> {
        step.effects.iter().find_map(|effect| match effect {
            Effect::Send {
                link,
                frame:
                    FromCore::Reply {
                        reply: Err(refusal),
                        ..
                    },
                ..
            } if *link == to => Some(refusal.clone()),
            _ => None,
        })
    }

    /// A connection to the forward's end from the channel's own client.
    fn knock(&mut self, knock: u64) -> Step {
        self.knock_on(knock, "gpg")
    }

    /// A connection to `capability`'s forward's end from the channel's own
    /// client.
    fn knock_on(&mut self, knock: u64, capability: &str) -> Step {
        let peer = Peer {
            origin: DESKTOP,
            program: None,
            channel: Some(self.connection),
        };
        self.step(Input::Knocked {
            knock: Knock(knock),
            connection: self.connection,
            capability: name(capability),
            peer: Some(peer),
        })
    }

    fn relayed(&mut self, knock: u64, relayed: Relayed) -> Step {
        self.step(Input::Relayed {
            knock: Knock(knock),
            relayed,
        })
    }

    fn sign(&mut self, knock: u64) -> Step {
        self.relayed(
            knock,
            Relayed::Asks(Ask {
                operation: Operation::Sign,
                key: Some(Grip::try_from(GRIP).unwrap()),
            }),
        )
    }

    /// A connection served at its opening, as `knock`.
    fn opened(&mut self, knock: u64) {
        self.knock(knock);
        let step = self.relayed(knock, Relayed::Reached(Ok(())));
        assert!(
            acts(&step).contains(&&Effect::Settle {
                knock: Knock(knock),
                verdict: Ok(())
            }),
            "{step:?}"
        );
    }

    /// Every signature on the connection is put to the person.
    fn confirm_signatures(&mut self) {
        let step = self.ask(
            TERMINAL,
            Request::Rule {
                connection: self.connection,
                scope: ConnectionScope {
                    capability: Selector::Only(name("gpg")),
                    operation: Selector::Only(Operation::Sign),
                    key: Keys::Every,
                },
                mode: Some(Mode::Confirm),
            },
        );
        assert_eq!(Scene::refused(&step, TERMINAL), None);
    }
}

fn settled(step: &Step) -> Vec<(RequestId, Outcome)> {
    events(step)
        .into_iter()
        .filter_map(|event| match event {
            Event::Settled { request, outcome } => Some((request, outcome)),
            _ => None,
        })
        .collect()
}

fn asked(step: &Step) -> RequestId {
    step.entries
        .iter()
        .find(|entry| matches!(entry.event, Event::Asked { .. }))
        .map(|entry| RequestId(entry.seq))
        .expect("a request")
}

/// A connection admitted at the forward's end is handed to the `gpg` relay;
/// its opening and its signature are each a request, recorded, decided and
/// settled on the connection, served without asking while the person is
/// reached.
#[test]
fn each_request_is_recorded_decided_and_settled_on_its_connection() {
    let mut scene = Scene::new();
    let step = scene.knock(1);
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Relay {
            knock: Knock(1),
            presents: None,
            ..
        }]
    ));
    let step = scene.relayed(1, Relayed::Reached(Ok(())));
    assert_eq!(
        events(&step)
            .into_iter()
            .filter(|event| matches!(event, Event::Asked { .. } | Event::Settled { .. }))
            .collect::<Vec<_>>(),
        [
            Event::Asked {
                connection: scene.connection,
                capability: name("gpg"),
                operation: Operation::Connect,
                key: None,
            },
            Event::Settled {
                request: asked(&step),
                outcome: Outcome::Served(Basis::Default),
            },
        ]
    );
    let step = scene.sign(1);
    assert_eq!(
        settled(&step),
        [(asked(&step), Outcome::Served(Basis::Default))]
    );
    assert_eq!(
        acts(&step),
        [&Effect::Settle {
            knock: Knock(1),
            verdict: Ok(())
        }]
    );
    assert_eq!(scene.relayed(1, Relayed::Ended).entries, Vec::new());
}

/// A held signature waits for the person; allowed for a minute, it and the
/// next one like it are served, the next without asking.
#[test]
fn a_held_signature_is_settled_by_the_persons_word() {
    let mut scene = Scene::new();
    scene.opened(1);
    scene.confirm_signatures();
    let step = scene.sign(1);
    let request = asked(&step);
    assert_eq!(
        events(&step)
            .into_iter()
            .filter(|event| !matches!(event, Event::Asked { .. }))
            .collect::<Vec<_>>(),
        [Event::Held { request }]
    );
    assert!(acts(&step).is_empty(), "nothing is settled yet");
    let minute = NonZeroU32::new(60).unwrap();
    let step = scene.ask(
        TERMINAL,
        Request::Decide {
            request,
            decision: Decision::For(minute),
        },
    );
    assert!(
        events(&step)
            .iter()
            .any(|event| matches!(event, Event::Allowed { .. }))
    );
    assert!(matches!(
        settled(&step).as_slice(),
        [(settled, Outcome::Allowed(_))] if *settled == request
    ));
    assert_eq!(
        acts(&step),
        [&Effect::Settle {
            knock: Knock(1),
            verdict: Ok(())
        }]
    );
    let step = scene.sign(1);
    assert_eq!(settled(&step), [(asked(&step), Outcome::Covered)]);
}

/// A held request the person refuses, one whose remote gives up, and one the
/// person can no longer be asked about each end with the connection told.
#[test]
fn a_held_request_ends_refused_abandoned_or_stranded() {
    let mut scene = Scene::new();
    scene.opened(1);
    scene.confirm_signatures();
    let request = asked(&scene.sign(1));
    let step = scene.ask(
        TERMINAL,
        Request::Decide {
            request,
            decision: Decision::Refuse,
        },
    );
    assert_eq!(
        settled(&step),
        [(request, Outcome::Refused(Refusal::Declined))]
    );
    assert_eq!(
        acts(&step),
        [&Effect::Settle {
            knock: Knock(1),
            verdict: Err(Refusal::Declined)
        }]
    );

    let request = asked(&scene.sign(1));
    let step = scene.relayed(1, Relayed::Ended);
    assert_eq!(settled(&step), [(request, Outcome::Abandoned)]);

    scene.opened(2);
    let request = asked(&scene.sign(2));
    let step = scene.step(Input::Left { link: TERMINAL });
    let away = Refusal::NobodyReachable(Whereabouts::Away);
    assert_eq!(settled(&step), [(request, Outcome::Refused(away.clone()))]);
    assert!(acts(&step).contains(&&Effect::Settle {
        knock: Knock(2),
        verdict: Err(away)
    }));
}

/// The workstation's side that does not answer is recorded as failing and
/// the connection refused for it; what the remote breaks is recorded against
/// that remote; what the agent breaks, against the workstation's side.
#[test]
fn what_either_side_breaks_is_recorded_where_it_belongs() {
    let mut scene = Scene::new();
    scene.knock(1);
    let step = scene.relayed(1, Relayed::Reached(Err(Failure::Unreachable)));
    let unavailable = Refusal::SourceUnavailable {
        capability: name("gpg"),
        failure: Failure::Unreachable,
    };
    assert!(events(&step).contains(&Event::Source {
        capability: name("gpg"),
        health: Health::Failing(Failure::Unreachable),
    }));
    assert_eq!(
        settled(&step),
        [(asked(&step), Outcome::Refused(unavailable.clone()))]
    );
    assert_eq!(
        acts(&step),
        [&Effect::Settle {
            knock: Knock(1),
            verdict: Err(unavailable)
        }]
    );

    scene.knock(2);
    let step = scene.relayed(2, Relayed::Unpresented);
    assert_eq!(
        events(&step),
        [Event::TurnedAway {
            remote: Some(remote()),
            refusal: Refusal::Unissued
        }]
    );
    scene.opened(3);
    let step = scene.relayed(3, Relayed::Breached(Breach::TooLong(Side::Client)));
    assert!(matches!(
        events(&step).as_slice(),
        [Event::TurnedAway {
            refusal: Refusal::OffProtocol { .. },
            ..
        }]
    ));
    let step = scene.relayed(3, Relayed::Breached(Breach::NotAnswer));
    assert_eq!(
        events(&step),
        [Event::Source {
            capability: name("gpg"),
            health: Health::Failing(Failure::Mismatched),
        }]
    );
}

/// A request served without asking is announced by the one client that
/// announces those, where the person has said to hear them.
#[test]
fn a_request_served_without_asking_is_announced_where_the_person_hears_those() {
    let mut scene = Scene::new();
    scene.ask(
        TERMINAL,
        Request::Change(Change::Hear {
            remotes: Remotes::Every,
            heard: Heard::Served(Waits::Announced),
        }),
    );
    scene.opened(1);
    let step = scene.sign(1);
    assert_eq!(
        notices(&step, TERMINAL).first(),
        Some(&Notice::Served(Served {
            request: asked(&step),
            remote: remote(),
            capability: name("gpg"),
            operation: Operation::Sign,
            key: Some(KeyId::Grip(Grip::try_from(GRIP).unwrap())),
            payload: None,
        }))
    );
}

/// A viewer is told what it shows is stale and is never asked: it reaches
/// nobody, so a request with only a viewer attached is refused, and it may
/// not say where the person is or decide.
#[test]
fn a_viewer_is_kept_fresh_and_never_asked() {
    let mut scene = Scene::new();
    scene.attach(VIEWER, ClientKind::Viewer);
    scene.opened(1);
    let step = scene.sign(1);
    assert!(
        notices(&step, VIEWER).contains(&Notice::Stale(Topic::Exposure)),
        "{step:?}"
    );
    let step = scene.ask(
        VIEWER,
        Request::Presence(hedwig_model::trail::Presence::Present),
    );
    assert_eq!(Scene::refused(&step, VIEWER), Some(Refusal::NotAttending));

    scene.step(Input::Left { link: TERMINAL });
    let step = scene.sign(1);
    assert_eq!(
        settled(&step),
        [(
            asked(&step),
            Outcome::Refused(Refusal::NobodyReachable(Whereabouts::Away))
        )]
    );
}

/// The keys the source offers are read before the survey, recorded, and
/// planned: present on the remote's keyring, imported where the grant
/// consents, and the signing key written for `git`.
#[test]
fn the_keys_read_before_a_survey_are_recorded_and_planned() {
    use hedwig_core::dispatch::Told;
    use hedwig_core::keys::Read;
    use hedwig_model::text::Words;
    use hedwig_model::trail::{Key, Keyring, Uses, Write};

    let mut scene = Scene::new();
    let primary = Fingerprint::try_from("07B56DFBBA12BB80FA84939C76F8274EF1651088").unwrap();
    let keyring = Keyring {
        keys: vec![Key {
            grip: Grip::try_from(GRIP).unwrap(),
            fingerprint: primary.clone(),
            primary: primary.clone(),
            uses: Uses::SIGN,
            user: Words::try_from("Relay Test <relay@example.invalid>").ok(),
            card: None,
            ssh: None,
        }],
        signing: Some(Mark::try_from(primary.as_str()).unwrap()),
    };
    let armour = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n".to_owned();
    let step = scene.core.step(
        Input::Asked {
            link: TERMINAL,
            frame: ToCore {
                id: 90,
                request: Request::Check {
                    remote: remote(),
                    capability: name("gpg"),
                },
            },
        },
        NOW,
    );
    let Some(Effect::Read {
        connection,
        id,
        sources,
        ..
    }) = acts(&step).first().copied()
    else {
        panic!("the keys are read first: {step:?}");
    };
    let (connection, first) = (*connection, *id);
    assert_eq!(connection, scene.connection);
    assert_eq!(sources.len(), 1);
    let read = Read {
        keyring: keyring.clone(),
        armoured: [(primary.clone(), armour.clone())].into(),
        ..Read::default()
    };
    let told = Told::Read {
        id: first,
        read: vec![(name("gpg"), Ok(read.clone()))],
    };
    let step = scene.core.step(Input::Channel { connection, told }, NOW);
    assert!(events(&step).contains(&Event::Offered {
        capability: name("gpg"),
        keyring: keyring.clone(),
    }));
    let Some(Effect::Survey { plan, .. }) = acts(&step)
        .into_iter()
        .find(|effect| matches!(effect, Effect::Survey { .. }))
    else {
        panic!("then the survey: {step:?}");
    };
    assert_eq!(plan.keys, std::slice::from_ref(&primary));
    assert_eq!(plan.armoured.get(&primary), Some(&armour));
    assert!(
        plan.writes
            .contains(&(name("gpg"), Write::PublicKey(primary.clone())))
    );
    assert!(plan.writes.contains(&(
        name("gpg"),
        Write::SigningKey(Mark::try_from(primary.as_str()).unwrap())
    )));

    // Read again, for a key no reading accounts for, and unchanged: nothing
    // is recorded.
    let (again, _) = scene.sign_unread_key(9).expect("the source is read again");
    let step = scene.told_read(again, read);
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Offered { .. })),
        "{step:?}"
    );
}

/// The rule a person writes before leaving the workstation - `gpg` on this
/// remote, signing only, unattended - serves the remote's signature with
/// nobody attached: its connection is opened under that rule, both requests
/// are recorded as served unseen by it, and a decryption no rule marks is
/// refused as reaching nobody.
#[test]
fn an_unattended_rule_for_signing_alone_serves_the_relayed_signature_with_nobody_there() {
    use hedwig_model::policy::RuleScope;

    let mut scene = Scene::new();
    let rule = RuleScope {
        remotes: Remotes::One(remote()),
        capability: Selector::Only(name("gpg")),
        operation: Selector::Only(Operation::Sign),
        key: Keys::Every,
    };
    let step = scene.ask(
        TERMINAL,
        Request::Change(Change::Rule {
            scope: rule.clone(),
            mode: Mode::Unattended,
        }),
    );
    assert_eq!(Scene::refused(&step, TERMINAL), None);
    scene.step(Input::Left { link: TERMINAL });
    let unseen = Outcome::Unseen(Basis::Rule(rule));

    scene.knock(1);
    let step = scene.relayed(1, Relayed::Reached(Ok(())));
    assert_eq!(settled(&step), [(asked(&step), unseen.clone())]);
    assert!(acts(&step).contains(&&Effect::Settle {
        knock: Knock(1),
        verdict: Ok(())
    }));
    let step = scene.sign(1);
    assert_eq!(settled(&step), [(asked(&step), unseen)]);
    let step = scene.relayed(
        1,
        Relayed::Asks(Ask {
            operation: Operation::Decrypt,
            key: Some(Grip::try_from(GRIP).unwrap()),
        }),
    );
    assert_eq!(
        settled(&step),
        [(
            asked(&step),
            Outcome::Refused(Refusal::NobodyReachable(Whereabouts::Away))
        )]
    );
}

/// A remote's activity is everything about it, the connection that ended
/// included: its opening, what crossed it and how each request ended, and its
/// end; the person's change to the configuration is not about it.
#[test]
fn a_remotes_activity_names_its_ended_connection_whole() {
    let mut scene = Scene::new();
    scene.opened(1);
    scene.sign(1);
    scene.relayed(1, Relayed::Ended);
    let connection = scene.connection;
    scene.step(Input::Channel {
        connection,
        told: hedwig_core::dispatch::Told::Ended {
            status: 255,
            unverified: false,
            last: None,
        },
    });
    assert!(scene.core.state().link(connection).is_none(), "it ended");
    let step = scene.ask(
        TERMINAL,
        Request::Activity {
            remote: Selector::Only(remote()),
            before: None,
            limit: std::num::NonZeroU8::MAX,
        },
    );
    let page = step
        .effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Send {
                frame:
                    FromCore::Reply {
                        reply: Ok(Reply::Activity(page)),
                        ..
                    },
                ..
            } => Some(page.clone()),
            _ => None,
        })
        .expect("a page");
    let kinds: Vec<&str> = page
        .iter()
        .map(|entry| match &entry.event {
            Event::Opening { .. } => "opening",
            Event::Asked { .. } => "asked",
            Event::Settled { .. } => "settled",
            Event::Down { .. } => "down",
            Event::Up { .. } => "up",
            Event::Observed { .. } => "observed",
            Event::Checked { .. } => "checked",
            Event::Prepared { .. } => "prepared",
            Event::Wrote { .. } => "wrote",
            Event::Ran { .. } => "ran",
            other => panic!("not about the remote: {other:?}"),
        })
        .collect();
    assert_eq!(kinds.first(), Some(&"opening"));
    assert_eq!(kinds.last(), Some(&"down"));
    assert_eq!(kinds.iter().filter(|kind| **kind == "asked").count(), 2);
    assert_eq!(kinds.iter().filter(|kind| **kind == "settled").count(), 2);
}

fn openocd() -> Scene {
    Scene::granted(
        "openocd",
        Exposure::SERVICE,
        Binding::Port(Port::try_from(3333).unwrap()),
    )
}

/// A connection to a workstation service's forward is handed to the
/// service's relay, carried to the port its source names; its opening is its
/// one request, recorded, decided and settled on its connection.
#[test]
fn a_service_connection_is_carried_to_its_port_and_its_opening_decided() {
    use hedwig_core::relay::Relaying;
    use hedwig_core::service::Service;
    use hedwig_model::capability::ServiceHost;

    let mut scene = openocd();
    let step = scene.knock_on(1, "openocd");
    let [
        Effect::Relay {
            knock: Knock(1),
            source,
            presents: None,
            ..
        },
    ] = acts(&step).as_slice()
    else {
        panic!("{step:?}");
    };
    assert_eq!(
        *source,
        Relaying::Service(Service {
            host: ServiceHost::Workstation,
            port: Port::try_from(3333).unwrap(),
        })
    );
    let step = scene.relayed(1, Relayed::Reached(Ok(())));
    assert_eq!(
        settled(&step),
        [(asked(&step), Outcome::Served(Basis::Default))]
    );
    assert!(acts(&step).contains(&&Effect::Settle {
        knock: Knock(1),
        verdict: Ok(())
    }));
    // The remote's end closing once it is served settles nothing more.
    let step = scene.relayed(1, Relayed::Ended);
    assert_eq!(settled(&step), Vec::<(RequestId, Outcome)>::new());
}

/// A service that is not there, or whose listener is another account's, is
/// the workstation's side failing: the opening is refused as the source
/// unavailable. With nobody there and no rule marking it unattended, the
/// opening is refused as reaching nobody; marked, it is served unseen.
#[test]
fn a_service_absent_foreign_or_unattended_is_decided_as_its_opening() {
    use hedwig_model::policy::RuleScope;

    let mut scene = openocd();
    for (knock, failure) in [(1, Failure::Unreachable), (2, Failure::Foreign)] {
        scene.knock_on(knock, "openocd");
        let step = scene.relayed(knock, Relayed::Reached(Err(failure)));
        let refusal = Refusal::SourceUnavailable {
            capability: name("openocd"),
            failure,
        };
        assert!(events(&step).contains(&Event::Source {
            capability: name("openocd"),
            health: Health::Failing(failure),
        }));
        assert_eq!(
            settled(&step),
            [(asked(&step), Outcome::Refused(refusal.clone()))]
        );
        assert!(acts(&step).contains(&&Effect::Settle {
            knock: Knock(knock),
            verdict: Err(refusal)
        }));
    }

    scene.step(Input::Left { link: TERMINAL });
    scene.knock_on(3, "openocd");
    let step = scene.relayed(3, Relayed::Reached(Ok(())));
    assert_eq!(
        settled(&step),
        [(
            asked(&step),
            Outcome::Refused(Refusal::NobodyReachable(Whereabouts::Away))
        )]
    );

    let rule = RuleScope {
        remotes: Remotes::One(remote()),
        capability: Selector::Only(name("openocd")),
        operation: Selector::Every,
        key: Keys::Every,
    };
    scene.attach(Link(9), ClientKind::Command);
    let step = scene.ask(
        Link(9),
        Request::Change(Change::Rule {
            scope: rule.clone(),
            mode: Mode::Unattended,
        }),
    );
    assert_eq!(Scene::refused(&step, Link(9)), None);
    scene.knock_on(4, "openocd");
    let step = scene.relayed(4, Relayed::Reached(Ok(())));
    assert_eq!(
        settled(&step),
        [(asked(&step), Outcome::Unseen(Basis::Rule(rule)))]
    );
}

/// `adb` granted with consent to write, so a Unix remote takes it at a
/// private socket behind `ADB_SERVER_SOCKET`.
fn adb() -> Scene {
    Scene::granted("adb", Exposure::SERVICE, adb_socket())
}

fn adb_socket() -> Binding {
    Binding::Socket(RemotePath::try_from("/run/user/1000/hedwig/adb").unwrap())
}

fn metro() -> Target {
    Target::Loopback(Port::try_from(8081).unwrap())
}

/// A connection to an `adb` forward is handed to the ADB relay, carried to the
/// port its source names with what its remote has carried and what its grant
/// lends - none, where the grant names no device; its opening is decided as a
/// service's is.
#[test]
fn an_adb_connection_is_carried_to_the_server_and_its_opening_decided() {
    use hedwig_core::relay::Relaying;
    use hedwig_core::service::Service;
    use hedwig_model::capability::ServiceHost;

    let mut scene = adb();
    let step = scene.knock_on(1, "adb");
    let [Effect::Relay { source, .. }] = acts(&step).as_slice() else {
        panic!("{step:?}");
    };
    assert_eq!(
        *source,
        Relaying::Adb {
            service: Service {
                host: ServiceHost::Workstation,
                port: Port::try_from(5037).unwrap(),
            },
            carried: hedwig_core::adb::Carried::default(),
            lending: hedwig_core::adb::Lending {
                lends: Lends::none(),
                network: false,
            },
        }
    );
    let step = scene.relayed(1, Relayed::Reached(Ok(())));
    assert_eq!(
        settled(&step),
        [(asked(&step), Outcome::Served(Basis::Default))]
    );
}

/// What holds an ADB server's port is recorded as its watch reads it, and
/// one Hedwig will not carry a remote's connection to fails the source as a
/// relay's reach would, until the server is the person's again and lists its
/// devices.
#[test]
fn a_server_held_by_what_hedwig_will_not_serve_fails_its_source_saying_whose_it_is() {
    use hedwig_core::devices::{Listing, View};

    let unread = SourceHolder {
        program: Location::try_from("adb.exe").unwrap(),
        session: 0,
        whose: Whose::Unread,
    };
    let theirs = SourceHolder {
        program: Location::try_from(
            r"C:\Users\ali\AppData\Local\Android\Sdk\platform-tools\adb.exe",
        )
        .unwrap(),
        session: 2,
        whose: Whose::Person {
            logon: 7,
            signed_in: SignedIn::Locally,
            rights: Rights::Standard,
        },
    };
    let told = |listing: Listing, holder: &SourceHolder| Input::Devices {
        capability: name("adb"),
        view: View {
            devices: Vec::new(),
            listing,
            holder: Some(holder.clone()),
        },
    };
    let mut scene = adb();
    for failure in [Failure::Unidentified, Failure::Confined, Failure::Foreign] {
        let step = scene.step(told(Listing::Failed(failure), &unread));
        assert!(
            events(&step).contains(&Event::Source {
                capability: name("adb"),
                health: Health::Failing(failure),
            }),
            "{step:?}"
        );
    }
    let again = scene.step(told(Listing::Failed(Failure::Unidentified), &unread));
    assert!(
        !events(&again)
            .iter()
            .any(|event| matches!(event, Event::HeldBy { .. })),
        "the same holder is not recorded again: {again:?}"
    );
    let step = scene.step(told(Listing::Read, &theirs));
    assert_eq!(
        events(&step),
        [
            Event::HeldBy {
                capability: name("adb"),
                holder: Some(theirs.clone()),
            },
            Event::Source {
                capability: name("adb"),
                health: Health::Sound,
            },
        ]
    );
}

/// A server the watch reads as older than platform-tools 35.0.0 fails
/// its source `Outdated`, recorded once; the failure stands while
/// connections reach the server, a client asking for its devices is refused
/// with it, and the source is sound again once the server lists them.
#[test]
fn an_outdated_server_fails_its_source_until_it_lists_its_devices() {
    use hedwig_core::devices::{Listing, View};

    let view = |listing: Listing| View {
        devices: Vec::new(),
        listing,
        holder: None,
    };
    let told = |listing: Listing| Input::Devices {
        capability: name("adb"),
        view: view(listing),
    };
    let health = |health: Health| Event::Source {
        capability: name("adb"),
        health,
    };
    let mut scene = adb();
    let outdated = Health::Failing(Failure::Outdated);
    assert_eq!(
        events(&scene.step(told(Listing::Failed(Failure::Outdated)))),
        [health(outdated)]
    );
    assert_eq!(
        events(&scene.step(told(Listing::Failed(Failure::Outdated)))),
        Vec::<Event>::new()
    );
    scene.knock_on(1, "adb");
    let step = scene.relayed(1, Relayed::Reached(Ok(())));
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Source { .. })),
        "{step:?}"
    );
    let step = scene.step(Input::Lendable {
        link: TERMINAL,
        id: 90,
        capability: name("adb"),
        view: view(Listing::Failed(Failure::Outdated)),
    });
    assert_eq!(
        Scene::refused(&step, TERMINAL),
        Some(Refusal::SourceUnavailable {
            capability: name("adb"),
            failure: Failure::Outdated,
        })
    );
    // A listing that failed otherwise says what failed, and leaves
    // the source's health as it stood.
    for (id, failure) in [
        (91, Failure::Unreachable),
        (92, Failure::Mismatched),
        (93, Failure::NoAddress),
        (94, Failure::Foreign),
    ] {
        let step = scene.step(Input::Lendable {
            link: TERMINAL,
            id,
            capability: name("adb"),
            view: view(Listing::Failed(failure)),
        });
        assert_eq!(
            Scene::refused(&step, TERMINAL),
            Some(Refusal::SourceUnavailable {
                capability: name("adb"),
                failure,
            })
        );
        assert!(events(&step).is_empty(), "{step:?}");
    }
    assert_eq!(
        events(&scene.step(told(Listing::Read))),
        [health(Health::Sound)]
    );
}

/// A request the relay withholds is recorded as the remote turned away, with
/// what it would have done; a breach of the remote's is the remote turned
/// away, one of the server's the source failing.
#[test]
fn a_withheld_request_and_each_breach_are_recorded_against_who_made_them() {
    use hedwig_core::adb::{Breach as Misframed, Side as End};

    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.relayed(1, Relayed::Withheld(Withheld::Ending));
    assert_eq!(
        events(&step),
        [Event::TurnedAway {
            remote: Some(remote()),
            refusal: Refusal::Withheld {
                capability: name("adb"),
                request: Withheld::Ending,
            },
        }]
    );
    let step = scene.relayed(1, Relayed::Misframed(Misframed::Length));
    assert!(matches!(
        events(&step).as_slice(),
        [Event::TurnedAway {
            refusal: Refusal::OffProtocol { .. },
            ..
        }]
    ));
    let step = scene.relayed(1, Relayed::Misframed(Misframed::OutOfTurn(End::Server)));
    assert_eq!(
        events(&step),
        [Event::Source {
            capability: name("adb"),
            health: Health::Failing(Failure::Mismatched),
        }]
    );
}

/// A reverse is given an endpoint for its remote and target once its carrier
/// stands in the asking connection's channel; once the device takes it, it is
/// recorded, and the device's answer is released in the same step - after
/// the record is written - once the carrier stands in the remote's live
/// channel. The same target again is given the same endpoint and recorded
/// once.
#[test]
fn a_reverse_is_given_an_endpoint_recorded_once_taken_and_carried_on() {
    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.relayed(1, Relayed::Reverse(metro()));
    let [
        Effect::Endpoint {
            knock,
            reverse,
            carrier,
            ..
        },
    ] = acts(&step).as_slice()
    else {
        panic!("{step:?}");
    };
    let adb = Reverse {
        remote: remote(),
        capability: name("adb"),
        target: metro(),
    };
    assert_eq!((*knock, reverse), (Knock(1), &adb));
    assert_eq!(carrier.connection, scene.connection);
    let endpoint = Port::try_from(50131).unwrap();
    let step = scene.relayed(
        1,
        Relayed::Reversed {
            target: metro(),
            endpoint,
        },
    );
    assert_eq!(
        events(&step),
        [Event::Carried {
            connection: scene.connection,
            capability: name("adb"),
            carriage: Carriage::Reverse(metro()),
            endpoint,
        }]
    );
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Haul { knock: Some(Knock(1)), reverse, carrier: Ok(carrier) }]
            if carrier.connection == scene.connection && *reverse == adb
    ));
    assert_eq!(
        scene
            .core
            .state()
            .carried(&remote(), &name("adb"))
            .and_then(|carried| carried.get(&Carriage::Reverse(metro()))),
        Some(&endpoint)
    );
    // A later connection is told the reverse its remote carried, and the same
    // reverse again is recorded no more.
    let step = scene.knock_on(2, "adb");
    let [
        Effect::Relay {
            source: Relaying::Adb { carried, .. },
            ..
        },
    ] = acts(&step).as_slice()
    else {
        panic!("{step:?}");
    };
    assert_eq!(carried.reverses, vec![(endpoint, metro())]);
    scene.relayed(2, Relayed::Reached(Ok(())));
    scene.relayed(2, Relayed::Reverse(metro()));
    let step = scene.relayed(
        2,
        Relayed::Reversed {
            target: metro(),
            endpoint,
        },
    );
    assert_eq!(events(&step), Vec::<Event>::new());
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Haul {
            knock: Some(Knock(2)),
            ..
        }]
    ));
}

/// A connection that ends holding a reverse the device did not take ends
/// its carrier - but not while another connection holds a reverse to the
/// same target, and never for a target the remote's record holds.
#[test]
fn a_reverse_not_taken_ends_its_carrier_unless_another_uses_the_target() {
    let mut scene = adb();
    let ask = |scene: &mut Scene, knock: u64, target: Target| {
        scene.knock_on(knock, "adb");
        scene.relayed(knock, Relayed::Reached(Ok(())));
        scene.relayed(knock, Relayed::Reverse(target));
    };
    let unhauled = |step: &Step| -> Vec<Target> {
        acts(step)
            .into_iter()
            .filter_map(|effect| match effect {
                Effect::Unhaul { reverse } => Some(reverse.target.clone()),
                _ => None,
            })
            .collect()
    };
    ask(&mut scene, 1, metro());
    ask(&mut scene, 2, metro());
    let step = scene.relayed(1, Relayed::Ended);
    assert_eq!(unhauled(&step), Vec::new(), "connection 2 holds it");
    let step = scene.relayed(2, Relayed::Ended);
    assert_eq!(unhauled(&step), [metro()]);

    let taken = Target::Loopback(Port::try_from(9000).unwrap());
    ask(&mut scene, 3, taken.clone());
    scene.relayed(
        3,
        Relayed::Reversed {
            target: taken.clone(),
            endpoint: Port::try_from(50132).unwrap(),
        },
    );
    let step = scene.relayed(3, Relayed::Ended);
    assert_eq!(unhauled(&step), Vec::new(), "taken and recorded");
    ask(&mut scene, 4, taken);
    let step = scene.relayed(4, Relayed::Ended);
    assert_eq!(unhauled(&step), Vec::new(), "the record holds the target");
}

/// A reverse nothing can carry - the asking connection's channel gone - is
/// told so, never left waiting; a reverse the device took once no channel is
/// live is told the same, nothing recording it.
#[test]
fn a_reverse_nothing_can_carry_is_told_so() {
    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    scene.knock_on(2, "adb");
    scene.relayed(2, Relayed::Reached(Ok(())));
    scene.relayed(2, Relayed::Reverse(metro()));
    scene.step(Input::Channel {
        connection: scene.connection,
        told: hedwig_core::dispatch::Told::Ended {
            status: 255,
            unverified: false,
            last: None,
        },
    });
    let step = scene.relayed(1, Relayed::Reverse(metro()));
    assert_eq!(
        acts(&step),
        [&Effect::Unhauled {
            knock: Knock(1),
            why: "the remote's channel is down",
        }]
    );
    let step = scene.relayed(
        2,
        Relayed::Reversed {
            target: metro(),
            endpoint: Port::try_from(50131).unwrap(),
        },
    );
    assert_eq!(
        acts(&step),
        [&Effect::Unhauled {
            knock: Knock(2),
            why: "the remote's channel is down",
        }]
    );
    assert_eq!(
        events(&step),
        Vec::<Event>::new(),
        "no link to record it by"
    );
}

/// A reverse asked on an ADB capability the person has since made another
/// kind of service is told so, and the device is never asked.
#[test]
fn a_reverse_whose_capability_no_longer_names_an_adb_server_is_told_so() {
    use hedwig_model::capability::{Capability, Offer, ServiceHost, ServicePort, Source, Stream};

    let mut scene = two_adb_servers();
    scene.knock_on(1, "adb-emulator");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let port = Port::try_from(5038).unwrap();
    let opaque = Capability {
        id: name("adb-emulator"),
        source: Source::Service {
            host: ServiceHost::Workstation,
            port: ServicePort::Fixed(port),
            stream: Stream::Opaque,
            remote: vec![Offer::Port(ServicePort::Fixed(port))],
        },
    };
    let step = scene.ask(TERMINAL, Request::Change(Change::Define(opaque)));
    assert_eq!(Scene::refused(&step, TERMINAL), None);
    let step = scene.relayed(1, Relayed::Reverse(metro()));
    assert_eq!(
        acts(&step),
        [&Effect::Unhauled {
            knock: Knock(1),
            why: "its capability no longer names an ADB server",
        }]
    );
}

/// `adb` and an emulator host's own ADB server, `adb-emulator`, both granted
/// to the remote and served on one channel.
fn two_adb_servers() -> Scene {
    use hedwig_model::capability::{Capability, Offer, ServiceHost, ServicePort, Source, Stream};

    let emulator = Capability {
        id: name("adb-emulator"),
        source: Source::Service {
            host: ServiceHost::Workstation,
            port: ServicePort::Fixed(Port::try_from(5038).unwrap()),
            stream: Stream::Adb,
            remote: vec![Offer::Port(ServicePort::Fixed(
                Port::try_from(5038).unwrap(),
            ))],
        },
    };
    let mut core = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        Vec::new(),
        "0.2.0".to_owned(),
    );
    core.begin(DESKTOP, None, Vec::new(), NOW);
    let mut scene = Scene {
        core,
        asked: 0,
        connection: ConnectionId(hedwig_model::trail::Seq(0)),
    };
    scene.attach(TERMINAL, ClientKind::Terminal);
    scene.ask(TERMINAL, Request::Change(Change::Define(emulator)));
    for capability in ["adb", "adb-emulator"] {
        scene.ask(
            TERMINAL,
            Request::Change(Change::Grant {
                grant: Grant {
                    capability: name(capability),
                    remotes: Granted::One(remote()),
                },
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Write,
                    acknowledged: Exposure::SERVICE,
                    lends: Lends::none(),
                },
            }),
        );
    }
    scene.ask(
        TERMINAL,
        Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    );
    let (connection, _) = scene.core.state().connection(&remote()).unwrap();
    scene.connection = connection;
    let serving = [
        Serving {
            capability: name("adb"),
            binding: adb_socket(),
        },
        Serving {
            capability: name("adb-emulator"),
            binding: Binding::Port(Port::try_from(5038).unwrap()),
        },
    ];
    scene.step(Input::Channel {
        connection,
        told: common::placing(&serving),
    });
    for capability in ["adb", "adb-emulator"] {
        scene.step(Input::Channel {
            connection,
            told: hedwig_core::dispatch::Told::Forwarded {
                capability: name(capability),
                bound: true,
            },
        });
    }
    scene
}

/// Two ADB capabilities on one remote - the person's server and an emulator
/// host's own - each tell their relay only the reverses they carried, since
/// each endpoint admits only its own capability's server.
#[test]
fn each_adb_capability_is_told_only_the_reverses_it_carried() {
    use hedwig_core::relay::Relaying;

    let mut scene = two_adb_servers();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.relayed(1, Relayed::Reverse(metro()));
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Endpoint { reverse, .. }] if reverse.capability == name("adb")
    ));
    let endpoint = Port::try_from(50131).unwrap();
    scene.relayed(
        1,
        Relayed::Reversed {
            target: metro(),
            endpoint,
        },
    );
    let told = |scene: &mut Scene, knock: u64, capability: &str| {
        let step = scene.knock_on(knock, capability);
        match acts(&step).as_slice() {
            [
                Effect::Relay {
                    source: Relaying::Adb { carried, .. },
                    ..
                },
            ] => carried.reverses.clone(),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(told(&mut scene, 2, "adb"), vec![(endpoint, metro())]);
    assert_eq!(told(&mut scene, 3, "adb-emulator"), Vec::new());

    // The same target from the other capability is a reverse of its own.
    scene.relayed(3, Relayed::Reached(Ok(())));
    let step = scene.relayed(3, Relayed::Reverse(metro()));
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Endpoint { reverse, .. }]
            if reverse.capability == name("adb-emulator") && reverse.target == metro()
    ));
}

/// A remote is given endpoints for at most `CARRIED` targets in a run; the
/// next is refused as crowded and recorded so, and a target it already has
/// is still given its endpoint.
#[test]
fn a_remote_has_reverses_carried_to_at_most_carried_targets() {
    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let targets: Vec<Target> = (9000..)
        .take(hedwig_core::adb::CARRIED + 1)
        .map(|number| Target::Loopback(Port::try_from(number).unwrap()))
        .collect();
    let (within, beyond) = targets.split_at(hedwig_core::adb::CARRIED);
    for target in within {
        let step = scene.relayed(1, Relayed::Reverse(target.clone()));
        assert!(matches!(acts(&step).as_slice(), [Effect::Endpoint { .. }]));
    }
    let step = scene.relayed(1, Relayed::Reverse(beyond.first().unwrap().clone()));
    assert_eq!(
        acts(&step),
        [&Effect::Withhold {
            knock: Knock(1),
            withheld: Withheld::Crowded,
        }]
    );
    assert!(matches!(
        events(&step).as_slice(),
        [Event::TurnedAway {
            refusal: Refusal::Withheld {
                request: Withheld::Crowded,
                ..
            },
            ..
        }]
    ));
    let step = scene.relayed(1, Relayed::Reverse(within.first().unwrap().clone()));
    assert!(matches!(acts(&step).as_slice(), [Effect::Endpoint { .. }]));
}

/// A reverse the device did not take - refused, or its remote gone before
/// the answer - gives its place among the remote's `CARRIED` back once its
/// connection ends: a target asked for after `CARRIED` such reverses is given
/// its endpoint, never refused as crowded.
#[test]
fn a_reverse_not_taken_gives_its_place_back_once_its_connection_ends() {
    let mut scene = adb();
    let targets: Vec<Target> = (9000..)
        .take(hedwig_core::adb::CARRIED + 1)
        .map(|number| Target::Loopback(Port::try_from(number).unwrap()))
        .collect();
    let (refused, later) = targets.split_at(hedwig_core::adb::CARRIED);
    for (knock, target) in (1..).zip(refused) {
        scene.knock_on(knock, "adb");
        scene.relayed(knock, Relayed::Reached(Ok(())));
        let step = scene.relayed(knock, Relayed::Reverse(target.clone()));
        assert!(
            matches!(acts(&step).as_slice(), [Effect::Endpoint { .. }]),
            "{step:?}"
        );
        scene.relayed(knock, Relayed::Ended);
    }
    scene.knock_on(100, "adb");
    scene.relayed(100, Relayed::Reached(Ok(())));
    let step = scene.relayed(100, Relayed::Reverse(later.first().unwrap().clone()));
    assert!(
        matches!(acts(&step).as_slice(), [Effect::Endpoint { .. }]),
        "{step:?}"
    );
}

/// When the remote's channel comes back, each reverse it carried in this run
/// is carried on to it again through the new channel, with nothing asked.
#[test]
fn a_returning_channel_carries_the_remotes_reverses_again() {
    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    scene.relayed(1, Relayed::Reverse(metro()));
    let endpoint = Port::try_from(50131).unwrap();
    scene.relayed(
        1,
        Relayed::Reversed {
            target: metro(),
            endpoint,
        },
    );
    let first = scene.connection;
    scene.step(Input::Channel {
        connection: first,
        told: hedwig_core::dispatch::Told::Ended {
            status: 255,
            unverified: false,
            last: None,
        },
    });
    scene.ask(
        TERMINAL,
        Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    );
    let (second, _) = scene.core.state().connection(&remote()).unwrap();
    assert_ne!(second, first);
    let serving = Serving {
        capability: name("adb"),
        binding: adb_socket(),
    };
    scene.step(Input::Channel {
        connection: second,
        told: common::placing(std::slice::from_ref(&serving)),
    });
    let step = scene.step(Input::Channel {
        connection: second,
        told: hedwig_core::dispatch::Told::Forwarded {
            capability: name("adb"),
            bound: true,
        },
    });
    assert!(
        events(&step)
            .iter()
            .any(|event| matches!(event, Event::Up { .. }))
    );
    assert!(matches!(
        acts(&step).as_slice(),
        [
            Effect::Seal { connection: sealed },
            Effect::Haul { knock: None, reverse, carrier: Ok(carrier) },
            Effect::Watch { capability, .. },
        ]
            if *sealed == second && carrier.connection == second && reverse.target == metro()
                && reverse.remote == remote() && reverse.capability == name("adb")
                && *capability == name("adb")
    ));
}

/// `adb`, granted lending every device.
fn lending_adb() -> Scene {
    let mut scene = adb();
    lend_adb(&mut scene, Lends::Every);
    scene
}

fn lend_adb(scene: &mut Scene, lends: Lends) -> Step {
    let step = scene.ask(
        TERMINAL,
        Request::Change(Change::Grant {
            grant: Grant {
                capability: name("adb"),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::SERVICE,
                lends,
            },
        }),
    );
    assert_eq!(Scene::refused(&step, TERMINAL), None);
    step
}

const PHONE_ID: u64 = 3;

fn phone() -> DeviceSerial {
    DeviceSerial::try_from("TESTDEVICE01").unwrap()
}

fn on_the_phone() -> DeviceSocket {
    DeviceSocket::try_from("tcp:7000").unwrap()
}

/// The connection `knock` asks for a forward at `port` on the remote.
fn asks_forward(scene: &mut Scene, knock: u64, port: u16) -> Step {
    scene.knock_on(knock, "adb");
    scene.relayed(knock, Relayed::Reached(Ok(())));
    scene.relayed(
        knock,
        Relayed::Forward {
            port,
            device: phone(),
            socket: on_the_phone(),
        },
    )
}

/// The workstation's server took the forward at `port`.
fn took(port: u16) -> Relayed {
    Relayed::Forwarded {
        forward: Forward {
            port: Port::try_from(port).unwrap(),
            server: Port::try_from(58765).unwrap(),
            device: phone(),
            socket: on_the_phone(),
        },
        replaced: None,
        id: PHONE_ID,
    }
}

fn holds_forward(scene: &Scene, port: u16) -> bool {
    scene
        .core
        .state()
        .carried(&remote(), &name("adb"))
        .into_iter()
        .flatten()
        .any(|(carriage, _)| {
            matches!(carriage, Carriage::Forward { port: at, .. } if at.number() == port)
        })
}

fn channel_ended(scene: &mut Scene) -> Step {
    scene.step(Input::Channel {
        connection: scene.connection,
        told: hedwig_core::dispatch::Told::Ended {
            status: 255,
            unverified: false,
            last: None,
        },
    })
}

/// The remote's channel asked for again, as a new connection: the step that
/// asked.
fn channel_asked(scene: &mut Scene) -> Step {
    let step = scene.ask(
        TERMINAL,
        Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    );
    let (connection, _) = scene.core.state().connection(&remote()).unwrap();
    assert_ne!(connection, scene.connection);
    scene.connection = connection;
    step
}

/// The remote's channel up again as a new connection: the step that said so.
fn channel_back(scene: &mut Scene) -> Step {
    channel_asked(scene);
    channel_up(scene)
}

/// The channel asked for answers: the step that says it is up.
fn channel_up(scene: &mut Scene) -> Step {
    let connection = scene.connection;
    let serving = Serving {
        capability: name("adb"),
        binding: adb_socket(),
    };
    scene.step(Input::Channel {
        connection,
        told: common::placing(std::slice::from_ref(&serving)),
    });
    scene.step(Input::Channel {
        connection,
        told: hedwig_core::dispatch::Told::Forwarded {
            capability: name("adb"),
            bound: true,
        },
    })
}

fn server_holds(devices: Vec<hedwig_core::devices::Device>) -> Input {
    Input::Devices {
        capability: name("adb"),
        view: hedwig_core::devices::View {
            devices,
            listing: hedwig_core::devices::Listing::Read,
            holder: None,
        },
    }
}

fn the_phone() -> hedwig_core::devices::Device {
    hedwig_core::devices::Device {
        serial: phone().as_str().to_owned(),
        state: hedwig_core::devices::State::DEVICE,
        usb: true,
        devpath: String::new(),
        product: String::new(),
        model: String::new(),
        device: String::new(),
        id: PHONE_ID,
    }
}

fn dropped(step: &Step) -> Vec<(ConnectionId, Dropped)> {
    events(step)
        .iter()
        .filter_map(|event| match event {
            Event::Dropped {
                connection, why, ..
            } => Some((*connection, *why)),
            _ => None,
        })
        .collect()
}

fn placed_again(step: &Step) -> Vec<u16> {
    acts(step)
        .iter()
        .filter_map(|act| match act {
            Effect::Replace { forwarding, .. } => Some(forwarding.port.number()),
            _ => None,
        })
        .collect()
}

fn unplaced(step: &Step) -> Vec<u16> {
    acts(step)
        .iter()
        .filter_map(|act| match act {
            Effect::Unplace { forwarding, .. } => Some(forwarding.port.number()),
            _ => None,
        })
        .collect()
}

/// A forward placed again on a returning channel is dropped on that channel,
/// the one the record of it can be folded by, when its device leaves.
#[test]
fn a_forward_placed_again_is_dropped_on_the_channel_that_carries_it() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    assert!(holds_forward(&scene, 7100));
    channel_ended(&mut scene);
    let step = channel_back(&mut scene);
    assert_eq!(placed_again(&step), [7100]);
    let step = scene.step(server_holds(Vec::new()));
    assert_eq!(dropped(&step), [(scene.connection, Dropped::Gone)]);
    assert_eq!(unplaced(&step), [7100]);
    assert!(!holds_forward(&scene, 7100));
}

/// A device that leaves while the channel is away changes nothing until the
/// channel returns, when the forward is dropped rather than placed again.
#[test]
fn a_forward_whose_device_left_while_its_channel_was_away_is_dropped_on_its_return() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    channel_ended(&mut scene);
    let step = scene.step(server_holds(Vec::new()));
    assert_eq!(dropped(&step), Vec::new(), "nothing to record it by");
    assert_eq!(unplaced(&step), Vec::<u16>::new());
    assert!(holds_forward(&scene, 7100));
    let step = channel_back(&mut scene);
    assert_eq!(placed_again(&step), Vec::<u16>::new());
    assert_eq!(dropped(&step), [(scene.connection, Dropped::Gone)]);
    assert!(!holds_forward(&scene, 7100));
}

/// A device no longer lent with no connection to record it by: the server's
/// listener and the endpoint go at once, and only once, and the drop is
/// recorded when the channel returns, in place of placing it again.
#[test]
fn a_forward_whose_device_was_unlent_while_its_channel_was_away_is_dropped_on_its_return() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    channel_ended(&mut scene);
    let step = lend_adb(&mut scene, Lends::none());
    assert!(
        acts(&step)
            .iter()
            .any(|act| matches!(act, Effect::Unlisten { id: PHONE_ID, .. })),
        "{step:?}"
    );
    assert_eq!(unplaced(&step), [7100]);
    assert_eq!(dropped(&step), Vec::new());
    assert!(holds_forward(&scene, 7100), "nothing to record it by");
    let step = scene.step(Input::Due);
    assert_eq!(unplaced(&step), Vec::<u16>::new(), "once");
    let step = channel_asked(&mut scene);
    assert_eq!(dropped(&step), [(scene.connection, Dropped::Unlent)]);
    assert!(!holds_forward(&scene, 7100));
    let step = channel_up(&mut scene);
    assert_eq!(placed_again(&step), Vec::<u16>::new());
    assert_eq!(dropped(&step), Vec::new());
}

/// A removal the server has done, its channel gone before the core could hear
/// of it, is recorded on the return in place of placing the forward again.
#[test]
fn a_forward_removed_as_its_channel_ended_is_not_placed_again() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    scene.knock_on(2, "adb");
    scene.relayed(2, Relayed::Reached(Ok(())));
    channel_ended(&mut scene);
    let step = scene.relayed(2, Relayed::Unforwarded(Port::try_from(7100).unwrap()));
    assert_eq!(dropped(&step), Vec::new());
    assert_eq!(unplaced(&step), [7100]);
    assert!(
        !acts(&step)
            .iter()
            .any(|act| matches!(act, Effect::Unlisten { .. })),
        "the server has let it go: {step:?}"
    );
    let step = channel_asked(&mut scene);
    assert_eq!(dropped(&step), [(scene.connection, Dropped::Removed)]);
    assert!(!holds_forward(&scene, 7100));
    let step = channel_up(&mut scene);
    assert_eq!(placed_again(&step), Vec::<u16>::new());
}

/// A new target for a recorded forward, taken as its channel ended, keeps the
/// listener: it is the recorded forward's.
#[test]
fn a_rebind_the_server_took_as_its_channel_ended_keeps_its_listener() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    scene.knock_on(2, "adb");
    scene.relayed(2, Relayed::Reached(Ok(())));
    channel_ended(&mut scene);
    let held = Forward {
        port: Port::try_from(7100).unwrap(),
        server: Port::try_from(58765).unwrap(),
        device: phone(),
        socket: on_the_phone(),
    };
    let step = scene.relayed(
        2,
        Relayed::Forwarded {
            forward: held.clone(),
            replaced: Some(held),
            id: PHONE_ID,
        },
    );
    assert_eq!(acts(&step), Vec::<&Effect>::new());
}

/// `adb` added to the connection alone, with no grant: the person's terms lend
/// every device.
fn connect_adding_adb(scene: &mut Scene) -> Step {
    connect_adding_adb_lending(scene, Lends::Every)
}

fn connect_adding_adb_lending(scene: &mut Scene, lends: Lends) -> Step {
    let step = scene.ask(
        TERMINAL,
        Request::Connect {
            remote: remote(),
            with: vec![name("adb")],
            acknowledged: Exposure::SERVICE,
            lends,
        },
    );
    let (connection, _) = scene.core.state().connection(&remote()).unwrap();
    assert_ne!(connection, scene.connection);
    scene.connection = connection;
    step
}

/// A terminal attached to a core with nothing granted and no channel.
fn nothing_granted() -> Scene {
    let mut core = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        Vec::new(),
        "0.2.0".to_owned(),
    );
    core.begin(DESKTOP, None, Vec::new(), NOW);
    let mut scene = Scene {
        core,
        asked: 0,
        connection: ConnectionId(hedwig_model::trail::Seq(0)),
    };
    scene.attach(TERMINAL, ClientKind::Terminal);
    scene
}

fn adb_added_to_the_connection() -> Scene {
    let mut scene = nothing_granted();
    connect_adding_adb(&mut scene);
    channel_up(&mut scene);
    scene
}

/// A forward on a capability added to the connection lives through the
/// channel's return as one on a grant does: the person asked for those terms,
/// and the channel comes back with them.
#[test]
fn a_forward_on_a_capability_added_to_the_connection_lives_through_its_channels_return() {
    let mut scene = adb_added_to_the_connection();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    let step = channel_ended(&mut scene);
    assert_eq!(unplaced(&step), Vec::<u16>::new());
    let step = scene.step(Input::Due);
    assert_eq!(unplaced(&step), Vec::<u16>::new());
    assert!(holds_forward(&scene, 7100));
    let step = connect_adding_adb(&mut scene);
    assert_eq!(dropped(&step), Vec::new());
    let step = channel_up(&mut scene);
    assert_eq!(placed_again(&step), [7100]);
}

/// Checking another capability of a remote whose channel is away opens the
/// connection its return would: a forward on a capability added to the
/// connection stays, and is placed again when that connection comes up.
#[test]
fn a_check_while_a_channel_is_away_leaves_a_forward_on_a_capability_added_to_it() {
    let mut scene = nothing_granted();
    scene.ask(
        TERMINAL,
        Request::Change(Change::Grant {
            grant: Grant {
                capability: name("gpg"),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        }),
    );
    connect_adding_adb(&mut scene);
    channel_up(&mut scene);
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    channel_ended(&mut scene);
    let step = scene.ask(
        TERMINAL,
        Request::Check {
            remote: remote(),
            capability: name("gpg"),
        },
    );
    let (checking, link) = scene.core.state().connection(&remote()).unwrap();
    assert_ne!(checking, scene.connection, "a connection to check with");
    assert_eq!(link.lends, Lends::Every, "the terms the person asked for");
    assert_eq!(link.acknowledged, Exposure::SERVICE);
    assert_eq!(dropped(&step), Vec::new());
    assert_eq!(unplaced(&step), Vec::<u16>::new());
    assert!(holds_forward(&scene, 7100));
    scene.connection = checking;
    let step = channel_up(&mut scene);
    assert_eq!(placed_again(&step), [7100]);
}

/// A person's reconnect says what is lent from then on: a forward on a device
/// it no longer names is dropped.
#[test]
fn a_reconnect_lending_other_devices_ends_a_forward_on_one_it_no_longer_names() {
    let mut scene = nothing_granted();
    connect_adding_adb_lending(&mut scene, Lends::devices([phone()]));
    channel_up(&mut scene);
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    assert!(holds_forward(&scene, 7100));
    channel_ended(&mut scene);
    let other = DeviceSerial::try_from("OTHERDEVICE02").unwrap();
    let step = connect_adding_adb_lending(&mut scene, Lends::devices([other]));
    assert_eq!(dropped(&step), [(scene.connection, Dropped::Unlent)]);
    assert!(!holds_forward(&scene, 7100));
}

fn emulator_port() -> Port {
    Port::try_from(5038).unwrap()
}

/// `adb-emulator`, an ADB server at `host`, as the person defines it.
fn emulator_at(host: hedwig_model::capability::ServiceHost) -> Request {
    use hedwig_model::capability::{Offer, ServicePort, Stream};

    let port = ServicePort::Fixed(emulator_port());
    Request::Change(Change::Define(Capability {
        id: name("adb-emulator"),
        source: Source::Service {
            host,
            port,
            stream: Stream::Adb,
            remote: vec![Offer::Port(port)],
        },
    }))
}

/// `adb-emulator` moved to a host the connection never named.
fn emulator_beyond_what_was_named() -> Request {
    use hedwig_model::capability::ServiceHost;
    use hedwig_model::text::Host;

    emulator_at(ServiceHost::Named(Host::try_from("lab.example").unwrap()))
}

/// The forward at 7100 removed from the workstation's server, which took it.
fn unlistened_on_the_workstation() -> Effect {
    Effect::Unlisten {
        server: hedwig_core::service::Service {
            host: hedwig_model::capability::ServiceHost::Workstation,
            port: emulator_port(),
        },
        id: PHONE_ID,
        listener: Port::try_from(58765).unwrap(),
    }
}

/// `adb-emulator` on the workstation added to the connection alone, named as a
/// service and lending every device, with a forward taken at 7100.
fn forwarding_on_an_added_emulator() -> Scene {
    use hedwig_model::capability::ServiceHost;

    let mut scene = nothing_granted();
    scene.ask(TERMINAL, emulator_at(ServiceHost::Workstation));
    scene.ask(
        TERMINAL,
        Request::Connect {
            remote: remote(),
            with: vec![name("adb-emulator")],
            acknowledged: Exposure::SERVICE,
            lends: Lends::Every,
        },
    );
    let (connection, _) = scene.core.state().connection(&remote()).unwrap();
    scene.connection = connection;
    let serving = Serving {
        capability: name("adb-emulator"),
        binding: Binding::Port(emulator_port()),
    };
    scene.step(Input::Channel {
        connection,
        told: common::placing(std::slice::from_ref(&serving)),
    });
    scene.step(Input::Channel {
        connection,
        told: hedwig_core::dispatch::Told::Forwarded {
            capability: name("adb-emulator"),
            bound: true,
        },
    });
    scene.knock_on(1, "adb-emulator");
    scene.relayed(1, Relayed::Reached(Ok(())));
    scene.relayed(
        1,
        Relayed::Forward {
            port: 7100,
            device: phone(),
            socket: on_the_phone(),
        },
    );
    scene.relayed(1, took(7100));
    scene
}

/// A capability added to the connection that comes to expose more than the
/// person named lends nothing further: the forward carried on it goes, though
/// no connection stands to record it by, and its listener goes from the server
/// that took it, not the one the capability names now.
#[test]
fn a_forward_on_an_added_capability_is_unlent_once_it_exposes_more_than_was_named() {
    let mut scene = forwarding_on_an_added_emulator();
    channel_ended(&mut scene);
    let step = scene.ask(TERMINAL, emulator_beyond_what_was_named());
    assert_eq!(Scene::refused(&step, TERMINAL), None);
    assert_eq!(unplaced(&step), [7100]);
    assert!(
        acts(&step).contains(&&unlistened_on_the_workstation()),
        "{step:?}"
    );
    assert_eq!(dropped(&step), Vec::new(), "nothing to record it by");
    // A connection carrying nothing ends in the step that opens it, unrecorded.
    let step = scene.ask(
        TERMINAL,
        Request::Connect {
            remote: remote(),
            with: vec![name("adb-emulator")],
            acknowledged: Exposure::SERVICE.with(Exposure::NETWORK),
            lends: Lends::Every,
        },
    );
    let (connection, _) = scene.core.state().connection(&remote()).unwrap();
    assert_eq!(dropped(&step), [(connection, Dropped::Unlent)]);
}

/// With its channel up the drop is recorded at once, and the listener goes
/// from the server that took it, not the one the capability names now.
#[test]
fn a_forward_unlent_with_its_channel_up_goes_from_the_server_that_took_it() {
    let mut scene = forwarding_on_an_added_emulator();
    let step = scene.ask(TERMINAL, emulator_beyond_what_was_named());
    assert_eq!(Scene::refused(&step, TERMINAL), None);
    assert_eq!(dropped(&step), [(scene.connection, Dropped::Unlent)]);
    assert_eq!(unplaced(&step), [7100]);
    assert!(
        acts(&step).contains(&&unlistened_on_the_workstation()),
        "{step:?}"
    );
}

/// A device lent again before the channel returns does not bring back a
/// listener already taken: the forward is dropped, not placed again.
#[test]
fn a_forward_unlent_and_lent_again_while_its_channel_was_away_is_not_placed_again() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    channel_ended(&mut scene);
    lend_adb(&mut scene, Lends::none());
    lend_adb(&mut scene, Lends::Every);
    let step = channel_asked(&mut scene);
    assert_eq!(dropped(&step), [(scene.connection, Dropped::Unlent)]);
    let step = channel_up(&mut scene);
    assert_eq!(placed_again(&step), Vec::<u16>::new());
}

/// A drop owed from an outage is recorded once: the port asked for again
/// afterwards is a forward of its own, and stays.
#[test]
fn a_forward_asked_for_again_after_its_drop_was_recorded_stays() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    channel_ended(&mut scene);
    lend_adb(&mut scene, Lends::none());
    channel_back(&mut scene);
    assert!(!holds_forward(&scene, 7100));
    lend_adb(&mut scene, Lends::Every);
    asks_forward(&mut scene, 2, 7100);
    let step = scene.relayed(2, took(7100));
    assert_eq!(dropped(&step), Vec::new());
    assert!(holds_forward(&scene, 7100));
    let step = scene.step(Input::Due);
    assert_eq!(dropped(&step), Vec::new());
    assert!(holds_forward(&scene, 7100));
}

/// A forward whose device is unlent while the server answers is dropped as
/// soon as it is recorded, its listener with it.
#[test]
fn a_forward_unlent_while_the_server_answered_is_dropped_once_recorded() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    lend_adb(&mut scene, Lends::none());
    let step = scene.relayed(1, took(7100));
    assert_eq!(dropped(&step), [(scene.connection, Dropped::Unlent)]);
    assert!(
        acts(&step)
            .iter()
            .any(|act| matches!(act, Effect::Unlisten { id: PHONE_ID, .. })),
        "{step:?}"
    );
    assert!(!holds_forward(&scene, 7100));
}

/// A new target for a forward dropped while the server answered has no record
/// to join: its listener goes, and the remote is told through an endpoint that
/// is gone.
#[test]
fn a_new_target_for_a_forward_dropped_meanwhile_is_told_and_its_listener_goes() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    scene.knock_on(2, "adb");
    scene.relayed(2, Relayed::Reached(Ok(())));
    scene.step(server_holds(Vec::new()));
    assert!(!holds_forward(&scene, 7100));
    let held = Forward {
        port: Port::try_from(7100).unwrap(),
        server: Port::try_from(58765).unwrap(),
        device: phone(),
        socket: on_the_phone(),
    };
    let step = scene.relayed(
        2,
        Relayed::Forwarded {
            forward: held.clone(),
            replaced: Some(held),
            id: PHONE_ID,
        },
    );
    assert_eq!(events(&step), Vec::<Event>::new());
    assert!(
        matches!(
            acts(&step).as_slice(),
            [
                Effect::Unlisten { id: PHONE_ID, .. },
                Effect::Listen {
                    knock: Knock(2),
                    ..
                }
            ]
        ),
        "{step:?}"
    );
    assert!(!holds_forward(&scene, 7100));
}

/// The same new target with its channel gone as well: nothing can record it
/// and no remote is there to tell, so only its listener goes.
#[test]
fn a_new_target_for_a_forward_dropped_meanwhile_with_no_channel_has_its_listener_removed() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    scene.knock_on(2, "adb");
    scene.relayed(2, Relayed::Reached(Ok(())));
    scene.step(server_holds(Vec::new()));
    assert!(!holds_forward(&scene, 7100));
    channel_ended(&mut scene);
    let held = Forward {
        port: Port::try_from(7100).unwrap(),
        server: Port::try_from(58765).unwrap(),
        device: phone(),
        socket: on_the_phone(),
    };
    let step = scene.relayed(
        2,
        Relayed::Forwarded {
            forward: held.clone(),
            replaced: Some(held),
            id: PHONE_ID,
        },
    );
    assert_eq!(events(&step), Vec::<Event>::new());
    assert!(
        matches!(
            acts(&step).as_slice(),
            [Effect::Unlisten { id: PHONE_ID, .. }]
        ),
        "{step:?}"
    );
}

/// A forward whose device is still lent and still held is placed again.
#[test]
fn a_forward_still_lent_and_held_is_placed_again_on_its_channels_return() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    channel_ended(&mut scene);
    scene.step(server_holds(vec![the_phone()]));
    let step = channel_back(&mut scene);
    assert_eq!(placed_again(&step), [7100]);
    assert_eq!(dropped(&step), Vec::new());
    assert!(holds_forward(&scene, 7100));
}

/// Only the remote's own refusal says something there took the port; a
/// placing the channel's end cut short leaves the forward for the next
/// return.
#[test]
fn a_forward_placed_again_is_taken_only_by_the_remotes_refusal() {
    let mut scene = lending_adb();
    asks_forward(&mut scene, 1, 7100);
    scene.relayed(1, took(7100));
    let first = scene.connection;
    channel_ended(&mut scene);
    channel_back(&mut scene);
    let forwarding = Forwarding {
        remote: remote(),
        capability: name("adb"),
        port: Port::try_from(7100).unwrap(),
    };
    let refused = || Unplaced::Refused("the remote's ssh server would not listen".to_owned());
    let step = scene.step(Input::Unreplaced {
        connection: scene.connection,
        forwarding: forwarding.clone(),
        why: Unplaced::Unanswered("the remote's channel is down".to_owned()),
    });
    assert_eq!(dropped(&step), Vec::new());
    assert!(holds_forward(&scene, 7100));
    // Of an earlier channel: the forward is placed in a later one now.
    let step = scene.step(Input::Unreplaced {
        connection: first,
        forwarding: forwarding.clone(),
        why: refused(),
    });
    assert_eq!(dropped(&step), Vec::new());
    assert!(holds_forward(&scene, 7100));
    let step = scene.step(Input::Unreplaced {
        connection: scene.connection,
        forwarding,
        why: refused(),
    });
    assert_eq!(dropped(&step), [(scene.connection, Dropped::Taken)]);
    assert!(
        acts(&step)
            .iter()
            .any(|act| matches!(act, Effect::Unlisten { id: PHONE_ID, .. })),
        "the server's listener goes with it: {step:?}"
    );
    assert!(!holds_forward(&scene, 7100));
}

/// A forward its connection held and the core never recorded gives its place
/// back as the connection ends, and its carrier goes.
#[test]
fn a_forward_never_recorded_gives_its_place_back_once_its_connection_ends() {
    let mut scene = adb();
    let eight = u64::try_from(hedwig_core::adb::CARRIED).unwrap();
    for knock in 1..=eight {
        let port = 9000 + u16::try_from(knock).unwrap();
        let step = asks_forward(&mut scene, knock, port);
        assert!(
            matches!(acts(&step).as_slice(), [Effect::Place { .. }]),
            "{step:?}"
        );
        let step = scene.relayed(knock, Relayed::Ended);
        assert_eq!(
            acts(&step),
            [&Effect::Withdraw {
                knock: Knock(knock)
            }]
        );
    }
    let step = asks_forward(&mut scene, 100, 9100);
    assert!(
        matches!(acts(&step).as_slice(), [Effect::Place { .. }]),
        "{step:?}"
    );
}

/// A recorded forward outlives the connection that asked for it, in the place
/// it holds and with its carrier.
#[test]
fn a_recorded_forward_keeps_its_place_and_its_carrier_once_its_connection_ends() {
    let mut scene = lending_adb();
    let eight = u64::try_from(hedwig_core::adb::CARRIED).unwrap();
    for knock in 1..=eight {
        let port = 9000 + u16::try_from(knock).unwrap();
        asks_forward(&mut scene, knock, port);
        scene.relayed(knock, took(port));
        let step = scene.relayed(knock, Relayed::Ended);
        assert_eq!(acts(&step), Vec::<&Effect>::new());
    }
    // A later connection asking for a port the record holds lets nothing go
    // of it when it ends.
    let step = asks_forward(&mut scene, 50, 9001);
    assert!(
        matches!(acts(&step).as_slice(), [Effect::Place { .. }]),
        "{step:?}"
    );
    let step = scene.relayed(50, Relayed::Ended);
    assert_eq!(acts(&step), [&Effect::Withdraw { knock: Knock(50) }]);
    let step = asks_forward(&mut scene, 100, 9100);
    assert!(
        matches!(
            acts(&step).as_slice(),
            [Effect::Withhold {
                withheld: Withheld::Crowded,
                ..
            }]
        ),
        "{step:?}"
    );
}

/// Two connections asking for one port hold one place, until both end.
#[test]
fn a_forward_two_connections_ask_for_keeps_its_place_until_both_end() {
    let mut scene = adb();
    let eight = u64::try_from(hedwig_core::adb::CARRIED).unwrap();
    for knock in 1..=eight {
        asks_forward(&mut scene, knock, 9000 + u16::try_from(knock).unwrap());
    }
    let last = 9000 + u16::try_from(eight).unwrap();
    let step = asks_forward(&mut scene, 50, last);
    assert!(
        matches!(acts(&step).as_slice(), [Effect::Place { .. }]),
        "the same place: {step:?}"
    );
    scene.relayed(eight, Relayed::Ended);
    let step = asks_forward(&mut scene, 51, 9200);
    assert!(
        matches!(
            acts(&step).as_slice(),
            [Effect::Withhold {
                withheld: Withheld::Crowded,
                ..
            }]
        ),
        "connection 50 still holds it: {step:?}"
    );
    scene.relayed(50, Relayed::Ended);
    let step = asks_forward(&mut scene, 52, 9200);
    assert!(
        matches!(acts(&step).as_slice(), [Effect::Place { .. }]),
        "{step:?}"
    );
}

/// A forward from any port that ends unrecorded gives back its own place and
/// no other connection's.
#[test]
fn a_forward_ended_unrecorded_gives_back_only_its_own_place() {
    let mut scene = adb();
    let eight = u64::try_from(hedwig_core::adb::CARRIED).unwrap();
    for knock in 1..=eight {
        asks_forward(&mut scene, knock, 0);
    }
    scene.relayed(1, Relayed::Ended);
    let step = asks_forward(&mut scene, 100, 9100);
    assert!(
        matches!(acts(&step).as_slice(), [Effect::Place { .. }]),
        "{step:?}"
    );
    let step = asks_forward(&mut scene, 101, 9101);
    assert!(
        matches!(
            acts(&step).as_slice(),
            [Effect::Withhold {
                withheld: Withheld::Crowded,
                ..
            }]
        ),
        "{step:?}"
    );
}

/// A forward nothing can place is told why; none is left unanswered.
#[test]
fn a_forward_nothing_can_place_is_told_why() {
    use hedwig_model::capability::{Capability, Offer, ServiceHost, ServicePort, Source, Stream};

    let forward = || Relayed::Forward {
        port: 7100,
        device: phone(),
        socket: on_the_phone(),
    };

    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    channel_ended(&mut scene);
    let step = scene.relayed(1, forward());
    assert_eq!(
        acts(&step),
        [&Effect::NotPlaced {
            knock: Knock(1),
            why: "the remote's channel is down",
        }]
    );

    let mut scene = two_adb_servers();
    scene.knock_on(1, "adb-emulator");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let port = Port::try_from(5038).unwrap();
    let opaque = Capability {
        id: name("adb-emulator"),
        source: Source::Service {
            host: ServiceHost::Workstation,
            port: ServicePort::Fixed(port),
            stream: Stream::Opaque,
            remote: vec![Offer::Port(ServicePort::Fixed(port))],
        },
    };
    let step = scene.ask(TERMINAL, Request::Change(Change::Define(opaque)));
    assert_eq!(Scene::refused(&step, TERMINAL), None);
    let step = scene.relayed(1, forward());
    assert_eq!(
        acts(&step),
        [&Effect::NotPlaced {
            knock: Knock(1),
            why: "its capability no longer names an ADB server",
        }]
    );
}

/// Whatever has no carrier is recorded for the person in the words the remote
/// read, and a carrier that gave no words is recorded as having given none.
#[test]
fn what_has_no_carrier_is_recorded_for_the_person() {
    let turned_away = |why: &str| Event::TurnedAway {
        remote: Some(remote()),
        refusal: Refusal::Withheld {
            capability: name("adb"),
            request: Withheld::Unhauled(Words::try_from(why).unwrap()),
        },
    };
    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.relayed(
        1,
        Relayed::Unhauled("the remote's ssh server would not listen".to_owned()),
    );
    assert_eq!(
        events(&step),
        [turned_away("the remote's ssh server would not listen")]
    );
    let step = scene.relayed(1, Relayed::Unhauled("  ".to_owned()));
    assert_eq!(events(&step), [turned_away("no account was given")]);
    channel_ended(&mut scene);
    let step = scene.relayed(
        1,
        Relayed::Unhauled("the remote's channel is down".to_owned()),
    );
    assert_eq!(
        events(&step),
        [turned_away("the remote's channel is down")],
        "still that remote's"
    );
}

/// A forward the server took as its channel ended has nothing to record it
/// by: the server's listener goes, and the connection's end takes the carrier.
#[test]
fn a_forward_the_server_took_as_its_channel_ended_has_its_listener_removed() {
    let mut scene = adb();
    asks_forward(&mut scene, 1, 7100);
    channel_ended(&mut scene);
    let step = scene.relayed(1, took(7100));
    assert_eq!(events(&step), Vec::<Event>::new());
    assert!(
        matches!(
            acts(&step).as_slice(),
            [Effect::Unlisten {
                id: PHONE_ID,
                listener,
                ..
            }] if listener.number() == 58765
        ),
        "{step:?}"
    );
    let step = scene.relayed(1, Relayed::Ended);
    assert_eq!(acts(&step), [&Effect::Withdraw { knock: Knock(1) }]);
}

/// The stand-in issuer a sign-in's tests open, at a port of its own.
const IDP: &str = "idp.hedwig.test";

/// `sign-in`, a browser capability opening the issuer and the remote's
/// loopback, granted to the remote with consent to write its openers'
/// variables, and the channel up forwarding it to a private socket.
fn sign_in() -> Scene {
    use hedwig_model::capability::{Browser, Capability, Source};
    use hedwig_model::site::Site;
    use hedwig_model::text::Program;

    let capability = Capability {
        id: name("sign-in"),
        source: Source::Browser {
            browser: Browser::Program {
                program: Program::try_from("curl").unwrap(),
                arguments: Vec::new(),
            },
            sites: vec![
                format!("http://{IDP}:8443").parse::<Site>().unwrap(),
                "http://localhost".parse::<Site>().unwrap(),
            ],
        },
    };
    let mut core = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        Vec::new(),
        "0.2.0".to_owned(),
    );
    core.begin(DESKTOP, None, Vec::new(), NOW);
    let mut scene = Scene {
        core,
        asked: 0,
        connection: ConnectionId(hedwig_model::trail::Seq(0)),
    };
    scene.attach(TERMINAL, ClientKind::Terminal);
    scene.ask(TERMINAL, Request::Change(Change::Define(capability)));
    scene.ask(
        TERMINAL,
        Request::Change(Change::Grant {
            grant: Grant {
                capability: name("sign-in"),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::BROWSER,
                lends: Lends::none(),
            },
        }),
    );
    scene.ask(
        TERMINAL,
        Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    );
    let (connection, _) = scene.core.state().connection(&remote()).unwrap();
    scene.connection = connection;
    let serving = Serving {
        capability: name("sign-in"),
        binding: Binding::Socket(RemotePath::try_from("/run/user/1000/hedwig/sign-in").unwrap()),
    };
    scene.step(Input::Channel {
        connection,
        told: common::placing(std::slice::from_ref(&serving)),
    });
    scene.step(Input::Channel {
        connection,
        told: hedwig_core::dispatch::Told::Forwarded {
            capability: name("sign-in"),
            bound: true,
        },
    });
    scene
}

/// An authorisation request coming back to `callback` on the remote's
/// loopback, as AWS CLI's is.
fn authorisation(callback: u16) -> String {
    format!(
        "http://{IDP}:8443/authorize?response_type=code&client_id=c&redirect_uri=http%3A%2F%2F127.0.0.1%3A{callback}%2Foauth%2Fcallback&state=s"
    )
}

/// The browser relay's opening served, then the URL it was posted: what it
/// opens is recorded with the site and the callback's port and never the
/// URL; once the browser has it, the callback is carried through the
/// remote's channel, and when the answer reaches the remote it is no longer.
#[test]
fn a_sign_in_is_opened_recorded_without_its_url_and_its_callback_carried() {
    use hedwig_core::browse::Browse;
    use hedwig_core::relay::Relaying;
    use hedwig_model::capability::Browser;
    use hedwig_model::site::Site;
    use hedwig_model::trail::Carry;

    let mut scene = sign_in();
    let step = scene.knock_on(1, "sign-in");
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Relay {
            source: Relaying::Browse(Browse {
                browser: Browser::Program { .. }
            }),
            ..
        }]
    ));
    let step = scene.relayed(1, Relayed::Reached(Ok(())));
    assert!(matches!(
        settled(&step).as_slice(),
        [(_, Outcome::Served(_))]
    ));
    let url = authorisation(8400);
    let step = scene.relayed(
        1,
        Relayed::Opens {
            asked: url.clone(),
            held: None,
        },
    );
    let request = asked(&step);
    assert!(events(&step).iter().any(|event| matches!(
        event,
        Event::Asked {
            operation: Operation::Open,
            ..
        }
    )));
    assert!(matches!(
        settled(&step).as_slice(),
        [(settled, Outcome::Served(_))] if *settled == request
    ));
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Settle {
            knock: Knock(1),
            verdict: Ok(())
        }]
    ));
    let step = scene.relayed(1, Relayed::Browsed(Ok(())));
    let opened = hedwig_model::site::url(&url).unwrap();
    assert_eq!(
        events(&step),
        [Event::Browsed {
            request,
            site: Site::of(&opened),
            callback: Some(Port::try_from(8400).unwrap()),
        }]
    );
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Call { knock: Knock(1), connection, target: Target::Host { host, port }, .. }]
            if *connection == scene.connection
                && host.as_str() == "127.0.0.1"
                && port.number() == 8400
    ));
    let step = scene.relayed(1, Relayed::Called);
    assert_eq!(
        events(&step),
        [Event::Uncarried {
            request,
            end: Carry::Called
        }]
    );
    assert_eq!(acts(&step), [&Effect::Uncall { knock: Knock(1) }]);
    assert_eq!(
        events(&scene.relayed(1, Relayed::Expired)),
        Vec::<Event>::new()
    );
    // Nothing the trail kept holds the URL.
    let kept = format!("{:?}", scene.core.state());
    assert!(!kept.contains("authorize"), "the URL is in the state");
}

/// Each way a sign-in is not opened: a URL no site admits, refused naming
/// the site that would; a callback port another program holds; a browser
/// that would not start, the source failing; and what is not `curl`'s post,
/// the remote turned away.
#[test]
fn a_sign_in_not_opened_says_why() {
    use hedwig_core::browse::Malformed;
    use hedwig_model::site::Site;

    let mut scene = sign_in();
    let opening = |scene: &mut Scene, knock: u64, asked: &str, held: Option<Port>| {
        scene.knock_on(knock, "sign-in");
        scene.relayed(knock, Relayed::Reached(Ok(())));
        let step = scene.relayed(
            knock,
            Relayed::Opens {
                asked: asked.to_owned(),
                held,
            },
        );
        settled(&step)
    };
    let elsewhere = "https://evil.example/authorize";
    assert!(matches!(
        opening(&mut scene, 1, elsewhere, None).as_slice(),
        [(_, Outcome::Refused(Refusal::UnlistedSite { site, .. }))]
            if *site == Site::of(&hedwig_model::site::url(elsewhere).unwrap())
    ));
    let held = Port::try_from(8400).unwrap();
    assert!(matches!(
        opening(&mut scene, 2, &authorisation(8400), Some(held)).as_slice(),
        [(_, Outcome::Refused(Refusal::CallbackHeld { port, .. }))] if *port == held
    ));
    // The site's refusal comes first: a port held for a URL nobody opens is
    // no matter.
    assert!(matches!(
        opening(&mut scene, 3, elsewhere, Some(held)).as_slice(),
        [(_, Outcome::Refused(Refusal::UnlistedSite { .. }))]
    ));

    opening(&mut scene, 4, &authorisation(8400), None);
    let step = scene.relayed(4, Relayed::Browsed(Err(Failure::Unstartable)));
    assert_eq!(
        events(&step),
        [Event::Source {
            capability: name("sign-in"),
            health: Health::Failing(Failure::Unstartable),
        }]
    );
    assert!(acts(&step).is_empty(), "nothing is carried");

    scene.knock_on(5, "sign-in");
    let step = scene.relayed(5, Relayed::Misread(Malformed::Request));
    assert!(matches!(
        events(&step).as_slice(),
        [Event::TurnedAway {
            refusal: Refusal::OffProtocol { .. },
            ..
        }]
    ));
}

/// A callback whose channel ends is no longer carried, and says so; its
/// relay is stopped.
#[test]
fn a_callback_ends_with_its_channel() {
    use hedwig_model::trail::Carry;

    let mut scene = sign_in();
    scene.knock_on(1, "sign-in");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.relayed(
        1,
        Relayed::Opens {
            asked: authorisation(8400),
            held: None,
        },
    );
    let request = asked(&step);
    scene.relayed(1, Relayed::Browsed(Ok(())));
    let step = scene.step(Input::Channel {
        connection: scene.connection,
        told: hedwig_core::dispatch::Told::Ended {
            status: 255,
            unverified: false,
            last: None,
        },
    });
    assert!(events(&step).contains(&Event::Uncarried {
        request,
        end: Carry::Ended
    }));
    assert!(acts(&step).contains(&&Effect::Uncall { knock: Knock(1) }));
}

const CARD: &str = "D2760001240103040006123456780000";

/// What the source offers: the key `GRIP` names, on `CARD`; and the card as
/// read, asking `touch` before that key's use.
fn read_with(touch: Option<Touch>, card_read: bool) -> hedwig_core::keys::Read {
    let primary = Fingerprint::try_from("07B56DFBBA12BB80FA84939C76F8274EF1651088").unwrap();
    hedwig_core::keys::Read {
        keyring: Keyring {
            keys: vec![Key {
                grip: Grip::try_from(GRIP).unwrap(),
                fingerprint: primary.clone(),
                primary,
                uses: Uses::SIGN,
                user: None,
                card: Some(Serial::try_from(CARD).unwrap()),
                ssh: None,
            }],
            signing: None,
        },
        armoured: BTreeMap::new(),
        cards: Ok(Cards {
            cards: if card_read {
                vec![Card {
                    serial: Serial::try_from(CARD).unwrap(),
                    keys: vec![Held {
                        grip: Grip::try_from(GRIP).unwrap(),
                        touch,
                    }],
                    pin: Some(SignaturePin::Once),
                }]
            } else {
                Vec::new()
            },
            keyless: Vec::new(),
        }),
    }
}

/// The cards a read found, where it read them.
fn cards_of(read: &hedwig_core::keys::Read) -> Vec<Card> {
    read.cards
        .clone()
        .map(|cards| cards.cards)
        .unwrap_or_default()
}

impl Scene {
    /// A standing rule: signatures with a key usable with nobody at its card
    /// are confirmed on this remote, as a careful holder writes it.
    fn confirm_keys_needing_no_touch(&mut self) {
        let step = self.ask(
            TERMINAL,
            Request::Change(Change::Rule {
                scope: RuleScope {
                    remotes: Remotes::One(remote()),
                    capability: Selector::Only(name("gpg")),
                    operation: Selector::Only(Operation::Sign),
                    key: Keys::NeedingNoTouch,
                },
                mode: Mode::Confirm,
            }),
        );
        assert_eq!(Scene::refused(&step, TERMINAL), None);
    }

    /// A signature naming `GRIP`, stepped without the suite's own answer to
    /// a read, and the read it asks for.
    fn sign_unread(&mut self, knock: u64) -> (Step, Option<Asked>) {
        let step = self.core.step(
            Input::Relayed {
                knock: Knock(knock),
                relayed: Relayed::Asks(Ask {
                    operation: Operation::Sign,
                    key: Some(Grip::try_from(GRIP).unwrap()),
                }),
            },
            NOW,
        );
        let read = acts(&step).into_iter().find_map(whole_read);
        (step, read)
    }

    fn told_read(&mut self, (connection, id): Asked, read: hedwig_core::keys::Read) -> Step {
        self.core.step(
            Input::Channel {
                connection,
                told: hedwig_core::dispatch::Told::Read {
                    id,
                    read: vec![(name("gpg"), Ok(read))],
                },
            },
            NOW,
        )
    }
}

/// A read under way: the connection its answer comes on, and the read it
/// answers.
type Asked = (ConnectionId, ReadId);

/// The whole source of one capability, read where `effect` asks for it.
fn whole_read(effect: &Effect) -> Option<Asked> {
    match effect {
        Effect::Read {
            connection,
            id,
            sources,
            ..
        } if sources.len() == 1 => Some((*connection, *id)),
        _ => None,
    }
}

/// A request naming a key no reading accounts for is decided only once its
/// source has been read again, so a statement about a key is never missed
/// for a stale reading; what the card says is recorded, and a key whose card
/// asks for a touch is not one a rule for keys needing no touch covers.
#[test]
fn a_request_for_a_key_no_reading_accounts_for_waits_for_the_source_and_its_card() {
    for (touch, held) in [
        (Some(Touch::On), false),
        (Some(Touch::Cached), false),
        (Some(Touch::Off), true),
        (None, true),
    ] {
        let mut scene = Scene::new();
        scene.confirm_keys_needing_no_touch();
        scene.opened(1);
        let (step, read) = scene.sign_unread(1);
        let read = read.expect("the source is read again first");
        assert!(
            !events(&step)
                .iter()
                .any(|event| matches!(event, Event::Asked { .. })),
            "nothing is decided before the read: {step:?}"
        );
        let step = scene.told_read(read, read_with(touch, true));
        let recorded = events(&step);
        assert!(
            recorded
                .iter()
                .any(|event| matches!(event, Event::Offered { .. }))
        );
        let card = cards_of(&read_with(touch, true))
            .into_iter()
            .next()
            .unwrap();
        assert!(recorded.contains(&Event::Card(card)));
        assert_eq!(
            recorded
                .iter()
                .any(|event| matches!(event, Event::Held { .. })),
            held,
            "{touch:?}: {recorded:?}"
        );
        // The key is accounted for now: the whole source is not read again.
        scene.opened(2);
        let (step, read) = scene.sign_unread(2);
        assert_eq!(read, None, "{step:?}");
    }
}

/// The same card read again is not recorded again.
#[test]
fn a_card_read_unchanged_is_not_recorded_again() {
    let mut scene = Scene::new();
    scene.opened(1);
    let (_, read) = scene.sign_unread(1);
    let connection = read.expect("a read");
    scene.told_read(connection, read_with(Some(Touch::On), true));
    scene.core.step(
        Input::Relayed {
            knock: Knock(1),
            relayed: Relayed::Ended,
        },
        NOW,
    );
    let again = scene.told_read(connection, read_with(Some(Touch::On), true));
    assert!(
        !events(&again)
            .iter()
            .any(|event| matches!(event, Event::Card(_) | Event::Offered { .. })),
        "{again:?}"
    );
}

/// A second card holding the suite's key, as the second of a person's two
/// `YubiKey`s holds theirs.
const SECOND_CARD: &str = "D2760001240103040006222222220000";

fn holding(serial: &str, touch: Option<Touch>) -> Card {
    Card {
        serial: Serial::try_from(serial).unwrap(),
        keys: vec![Held {
            grip: Grip::try_from(GRIP).unwrap(),
            touch,
        }],
        pin: None,
    }
}

/// The source's cards alone, read where `effect` asks for them.
fn cards_read(effect: &Effect) -> Option<Asked> {
    match effect {
        Effect::Cards {
            connection,
            id,
            sources,
            ..
        } if sources.len() == 1 => Some((*connection, *id)),
        _ => None,
    }
}

/// The capability a read of the cards `effect` asks for goes through.
fn cards_read_through(effect: &Effect) -> Option<Name> {
    match effect {
        Effect::Cards { sources, .. } => sources.first().map(|(capability, ..)| capability.clone()),
        _ => None,
    }
}

impl Scene {
    fn told_cards(&mut self, asked: Asked, cards: Vec<Card>) -> Step {
        self.told(
            asked,
            Cards {
                cards,
                keyless: Vec::new(),
            },
        )
    }

    fn told(&mut self, (connection, id): Asked, cards: Cards) -> Step {
        self.core.step(
            Input::Channel {
                connection,
                told: hedwig_core::dispatch::Told::Cards {
                    id,
                    read: vec![(name("gpg"), Ok(cards))],
                },
            },
            NOW,
        )
    }

    fn ended(&mut self, knock: u64) -> Step {
        self.relayed(knock, Relayed::Ended)
    }

    /// A signature on `knock` served at once, the key's card read first.
    fn served_card_signature(&mut self, knock: u64) -> ConnectionId {
        self.opened(knock);
        let (_, read) = self.sign_unread(knock);
        let asked = read.expect("a read");
        let (connection, _) = asked;
        let step = self.told_read(asked, read_with(Some(Touch::On), true));
        assert!(
            settled(&step)
                .iter()
                .any(|(_, outcome)| matches!(outcome, Outcome::Served(_))),
            "{step:?}"
        );
        connection
    }
}

/// Once a signature with a key on a card is served, the agent has had
/// scdaemon scan for whichever card is in: the cards alone are read when its
/// connection ends, and a second card holding the key is recorded.
#[test]
fn the_cards_alone_are_read_once_a_connection_that_used_a_card_ends() {
    let mut scene = Scene::new();
    let connection = scene.served_card_signature(1);
    let step = scene.ended(1);
    let reads: Vec<Asked> = acts(&step).into_iter().filter_map(cards_read).collect();
    let [asked] = reads.as_slice() else {
        panic!("one read of the cards: {step:?}");
    };
    assert_eq!(asked.0, connection);
    assert!(
        !acts(&step)
            .iter()
            .any(|effect| matches!(effect, Effect::Read { .. })),
        "the whole source is not read again"
    );
    let step = scene.told_cards(
        *asked,
        vec![
            holding(SECOND_CARD, Some(Touch::Off)),
            holding(CARD, Some(Touch::On)),
        ],
    );
    assert_eq!(
        events(&step),
        vec![Event::Card(holding(SECOND_CARD, Some(Touch::Off)))],
        "the first card says nothing new; the second is recorded"
    );
    scene.opened(2);
    scene.sign(2);
    let step = scene.ended(2);
    let again = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read after the second use");
    let step = scene.told_cards(again, vec![holding(SECOND_CARD, None)]);
    assert!(
        events(&step).is_empty(),
        "a card read again that leaves its key unsaid says nothing new: {step:?}"
    );
}

/// A request with a key on a card, after one was served through the same
/// source, waits for the cards to be read before it is decided, so a card the
/// agent scanned for is known to it; a second request waits on the same
/// reading; once read, each is decided, the next served one making the cards
/// stale again.
#[test]
fn a_card_request_after_a_card_was_used_waits_for_one_reading_of_the_cards() {
    let mut scene = Scene::new();
    let connection = scene.served_card_signature(1);
    let step = scene.sign(1);
    let reads: Vec<Asked> = acts(&step).into_iter().filter_map(cards_read).collect();
    let [asked] = reads.as_slice() else {
        panic!("one read of the cards: {step:?}");
    };
    let asked = *asked;
    assert_eq!(asked.0, connection);
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Asked { .. })),
        "nothing is decided before the cards are read: {step:?}"
    );
    scene.opened(2);
    let step = scene.sign(2);
    assert!(
        acts(&step).into_iter().find_map(cards_read).is_none()
            && !events(&step)
                .iter()
                .any(|event| matches!(event, Event::Asked { .. })),
        "the second waits on the reading under way: {step:?}"
    );
    let step = scene.told_cards(
        asked,
        vec![
            holding(CARD, Some(Touch::On)),
            holding(SECOND_CARD, Some(Touch::On)),
        ],
    );
    assert_eq!(
        settled(&step).len(),
        2,
        "both waiting requests are decided: {step:?}"
    );
    let step = scene.sign(1);
    assert!(
        acts(&step).into_iter().find_map(cards_read).is_some(),
        "the two served since make the cards stale again: {step:?}"
    );
}

/// A card used while its source's cards are being read leaves them stale
/// after that reading: the reading began before the agent scanned for it.
#[test]
fn a_card_used_while_the_cards_are_read_leaves_them_stale() {
    let mut scene = Scene::new();
    scene.confirm_signatures();
    scene.opened(1);
    let (_, read) = scene.sign_unread(1);
    let connection = read.expect("a read");
    scene.told_read(connection, read_with(Some(Touch::On), true));
    scene.opened(2);
    let held = asked(&scene.sign(2));
    let first = asked(&scene.sign(1));
    let allow = |scene: &mut Scene, request| {
        let step = scene.ask(
            TERMINAL,
            Request::Decide {
                request,
                decision: Decision::Once,
            },
        );
        assert_eq!(Scene::refused(&step, TERMINAL), None);
    };
    allow(&mut scene, first);
    let step = scene.ended(1);
    let reading = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read");
    allow(&mut scene, held);
    let step = scene.told_cards(reading, vec![holding(CARD, Some(Touch::On))]);
    assert_eq!(
        acts(&step).into_iter().find_map(cards_read),
        None,
        "nothing waits, so nothing is read at the answer: {step:?}"
    );
    let step = scene.ended(2);
    assert!(
        acts(&step).into_iter().find_map(cards_read).is_some(),
        "the use allowed during the reading has the cards read at its connection's end: {step:?}"
    );
}

/// A request that is never served uses no card: its connection's end reads
/// nothing.
#[test]
fn a_card_request_never_served_has_nothing_read() {
    let mut scene = Scene::new();
    scene.confirm_signatures();
    scene.opened(1);
    let (_, read) = scene.sign_unread(1);
    let connection = read.expect("a read");
    let step = scene.told_read(connection, read_with(Some(Touch::On), true));
    assert!(
        events(&step)
            .iter()
            .any(|event| matches!(event, Event::Held { .. }))
    );
    let step = scene.ended(1);
    assert!(
        settled(&step)
            .iter()
            .any(|(_, outcome)| *outcome == Outcome::Abandoned)
    );
    assert!(
        acts(&step).into_iter().find_map(cards_read).is_none(),
        "{step:?}"
    );
}

/// A keygrip no reading of the suite's source accounts for.
const UNREAD_GRIP: &str = "1D3AA6A1A0F4C9B92A3B5F07E6E0D0C3D4E5F601";

impl Scene {
    /// A signature on `knock` naming `UNREAD_GRIP`, and the whole read of the
    /// source it asks for.
    fn sign_unread_key(&mut self, knock: u64) -> Option<(Asked, Known)> {
        self.opened(knock);
        let step = self.core.step(
            Input::Relayed {
                knock: Knock(knock),
                relayed: Relayed::Asks(Ask {
                    operation: Operation::Sign,
                    key: Some(Grip::try_from(UNREAD_GRIP).unwrap()),
                }),
            },
            NOW,
        );
        acts(&step).into_iter().find_map(read_and_known)
    }

    /// A signature naming `GRIP` on `knock`, opened now, and the read of the
    /// cards it asks for, if any.
    fn sign_card_key(&mut self, knock: u64) -> (Step, Option<Asked>) {
        self.opened(knock);
        let (step, _) = self.sign_unread(knock);
        let read = acts(&step).into_iter().find_map(cards_read);
        (step, read)
    }

    /// The survey's read of what the source offers, and what it is read on.
    fn surveyed(&mut self) -> Option<(Asked, Known)> {
        let step = self.core.step(
            Input::Asked {
                link: TERMINAL,
                frame: ToCore {
                    id: 91,
                    request: Request::Check {
                        remote: remote(),
                        capability: name("gpg"),
                    },
                },
            },
            NOW,
        );
        acts(&step).into_iter().find_map(read_and_known)
    }
}

/// A whole read `effect` asks for, and the known cards it is read on.
fn read_and_known(effect: &Effect) -> Option<(Asked, Known)> {
    match effect {
        Effect::Read {
            connection,
            id,
            known,
            ..
        } => Some(((*connection, *id), known.clone())),
        _ => None,
    }
}

/// The known cards an effect reading the cards hands over.
fn known_of(effect: &Effect) -> Option<&Known> {
    match effect {
        Effect::Cards { known, .. } => Some(known),
        _ => None,
    }
}

/// Each read of the cards is handed what the core knows - every card it has
/// read, and for the cards alone the keyring the source last offered - so a
/// card it knows is read again from its attributes alone, without a walk.
#[test]
fn the_cards_are_read_on_the_cards_and_keyring_the_core_knows() {
    let mut scene = Scene::new();
    scene.served_card_signature(1);
    let read = read_with(Some(Touch::On), true);
    let step = scene.ended(1);
    let Some(Effect::Cards { sources, known, .. }) = acts(&step)
        .into_iter()
        .find(|effect| cards_read(effect).is_some())
    else {
        panic!("the cards are read: {step:?}");
    };
    assert_eq!(known.cards, cards_of(&read));
    let [(capability, _, keyring)] = sources.as_slice() else {
        panic!("one source: {sources:?}");
    };
    assert_eq!((capability, keyring), (&name("gpg"), &read.keyring));
    let (_, known) = scene.sign_unread_key(2).expect("the whole source is read");
    assert_eq!(
        known.cards,
        cards_of(&read),
        "read again for a key no reading accounts for"
    );
    let (_, known) = scene.surveyed().expect("a read before a survey");
    assert_eq!(known.cards, cards_of(&read), "read before a survey");
}

/// A card a walk found holding no key says nothing about the person, so it
/// is recorded nowhere; the core remembers it for the run, from a read of the
/// cards or of the whole source, so the next read knows it and walks nothing
/// for it.
#[test]
fn a_card_holding_no_key_is_remembered_for_the_run_and_never_recorded() {
    let empty = Serial::try_from(SECOND_CARD).unwrap();
    let mut scene = Scene::new();
    scene.served_card_signature(1);
    let step = scene.ended(1);
    let reading = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read");
    let step = scene.told(
        reading,
        Cards {
            cards: cards_of(&read_with(Some(Touch::On), true)),
            keyless: vec![empty.clone()],
        },
    );
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Card(_))),
        "nothing is recorded of a card holding no key: {step:?}"
    );
    let (step, _) = scene.sign_card_key(2);
    assert!(
        settled(&step)
            .iter()
            .any(|(_, outcome)| matches!(outcome, Outcome::Served(_))),
        "{step:?}"
    );
    let step = scene.ended(2);
    let known = acts(&step)
        .into_iter()
        .find_map(known_of)
        .expect("the cards are read after the use");
    assert_eq!(known.keyless, [empty.clone()].into());
    assert_eq!(known.cards, cards_of(&read_with(Some(Touch::On), true)));
    let cards_on = acts(&step).into_iter().find_map(cards_read).unwrap();
    scene.told_cards(cards_on, cards_of(&read_with(Some(Touch::On), true)));
    let (survey, known) = scene.surveyed().expect("a read before a survey");
    assert_eq!(
        known.keyless,
        [empty.clone()].into(),
        "read before a survey"
    );
    let third = Serial::try_from("D2760001240103040006333333330000").unwrap();
    let mut whole = read_with(Some(Touch::On), true);
    whole.cards = Ok(Cards {
        cards: cards_of(&whole),
        keyless: vec![third.clone()],
    });
    let step = scene.told_read(survey, whole);
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Card(_))),
        "{step:?}"
    );
    scene.sign_card_key(3);
    let step = scene.ended(3);
    let known = acts(&step)
        .into_iter()
        .find_map(known_of)
        .expect("the cards are read after the use");
    assert_eq!(known.keyless, [empty, third].into(), "remembered from both");
}

impl Scene {
    /// The person allows `request` once.
    fn allow_once(&mut self, request: RequestId) {
        let step = self.ask(
            TERMINAL,
            Request::Decide {
                request,
                decision: Decision::Once,
            },
        );
        assert_eq!(Scene::refused(&step, TERMINAL), None);
    }

    /// Two signatures held for the person under `confirm_signatures`, on
    /// knocks 1 and 2, the first allowed and its connection ended, then the
    /// second allowed: the cards read after the first use, and a second use
    /// served while that read is under way.
    fn two_uses_one_read_under_way(&mut self) -> Asked {
        self.confirm_signatures();
        self.opened(1);
        let (_, read) = self.sign_unread(1);
        self.told_read(read.expect("a read"), read_with(Some(Touch::On), true));
        self.opened(2);
        let held = asked(&self.sign(2));
        let first = asked(&self.sign(1));
        self.allow_once(first);
        let step = self.ended(1);
        let reading = acts(&step)
            .into_iter()
            .find_map(cards_read)
            .expect("the cards are read after the first use");
        self.allow_once(held);
        reading
    }
}

/// How many requests a step held for the person.
fn held_for_the_person(step: &Step) -> usize {
    events(step)
        .iter()
        .filter(|event| matches!(event, Event::Asked { .. }))
        .count()
}

/// The suite's card holding `UNREAD_GRIP` beside `GRIP`, as a newer reading
/// names it.
fn newer_reading() -> hedwig_core::keys::Read {
    let mut newer = read_with(Some(Touch::On), true);
    if let Ok(Cards { cards, .. }) = &mut newer.cards
        && let Some(card) = cards.first_mut()
    {
        card.keys.push(Held {
            grip: Grip::try_from(UNREAD_GRIP).unwrap(),
            touch: None,
        });
    }
    newer
}

/// A whole reading of the source recorded while a read of its cards is under
/// way began after the last use, so it stands for that read: what waits on
/// the cards is decided on it. The read it overtook began on the cards as
/// known before it and is never recorded; what waits after a use since is
/// decided only on a read begun after that use.
#[test]
fn a_read_of_the_cards_a_whole_reading_overtook_is_never_recorded() {
    let mut scene = Scene::new();
    scene.served_card_signature(1);
    let step = scene.ended(1);
    let overtaken = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read");
    let (step, again) = scene.sign_card_key(3);
    assert_eq!(again, None, "the read under way serves: {step:?}");
    assert!(settled(&step).is_empty(), "waits for the cards: {step:?}");
    let (whole, _) = scene.sign_unread_key(2).expect("the whole source is read");
    let newer = newer_reading();
    let step = scene.told_read(whole, newer.clone());
    let recorded: Vec<Event> = cards_of(&newer).iter().cloned().map(Event::Card).collect();
    assert!(
        recorded.iter().all(|card| events(&step).contains(card)),
        "the newer reading is recorded: {step:?}"
    );
    assert_eq!(
        settled(&step).len(),
        1,
        "the request waiting on the cards is decided on it: {step:?}"
    );
    let after = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the request naming the new key follows a use since: the cards are read again");
    let step = scene.told_cards(overtaken, cards_of(&read_with(Some(Touch::On), true)));
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Card(_))),
        "the older reading would drop the key the newer one named: {step:?}"
    );
    assert!(
        settled(&step).is_empty() && acts(&step).into_iter().find_map(cards_read).is_none(),
        "nothing is decided on it, and the read begun after the use is waited for: {step:?}"
    );
    let step = scene.told_cards(after, cards_of(&newer));
    assert_eq!(settled(&step).len(), 1, "decided on that read: {step:?}");
}

/// A request waiting on the cards is decided only on a read of them begun
/// after the last use: a read begun before it stands for no read after it, so
/// one is asked at the connection's end, and answered first it decides
/// nothing.
#[test]
fn a_request_is_decided_only_on_a_read_of_the_cards_begun_after_the_last_use() {
    let mut scene = Scene::new();
    let before = scene.two_uses_one_read_under_way();
    let step = scene.ended(2);
    let read = acts(&step).into_iter().find_map(cards_read);
    assert!(
        read.is_some_and(|after| after != before),
        "the read under way, begun before the second use, stands for no read after it: {step:?}"
    );
    let after = read.expect("asserted above");
    scene.opened(3);
    let step = scene.sign(3);
    assert_eq!(
        acts(&step).into_iter().find_map(cards_read),
        None,
        "the read begun after the second use serves: {step:?}"
    );
    assert_eq!(held_for_the_person(&step), 0, "{step:?}");
    let step = scene.told_cards(before, cards_of(&read_with(Some(Touch::On), true)));
    assert_eq!(
        held_for_the_person(&step),
        0,
        "not decided on a read begun before the second use: {step:?}"
    );
    let step = scene.told_cards(after, cards_of(&read_with(Some(Touch::On), true)));
    assert_eq!(held_for_the_person(&step), 1, "{step:?}");
}

/// Two reads of the cards under way are both overtaken by a whole reading
/// recorded meanwhile, and neither is recorded nor made again: the reading,
/// begun after the last use, read the cards after it.
#[test]
fn every_read_of_the_cards_a_whole_reading_overtook_is_set_aside() {
    let mut scene = Scene::new();
    let before = scene.two_uses_one_read_under_way();
    let step = scene.ended(2);
    let after = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read after the second use");
    scene.opened(3);
    scene.sign(3);
    let (whole, _) = scene.sign_unread_key(4).expect("the whole source is read");
    let step = scene.told_read(whole, newer_reading());
    assert_eq!(
        held_for_the_person(&step),
        2,
        "both requests are decided on it, begun after the last use: {step:?}"
    );
    for overtaken in [before, after] {
        let step = scene.told_cards(overtaken, cards_of(&read_with(Some(Touch::On), true)));
        assert!(
            !events(&step)
                .iter()
                .any(|event| matches!(event, Event::Card(_))),
            "{step:?}"
        );
        assert_eq!(
            acts(&step).into_iter().find_map(cards_read),
            None,
            "the cards were read after the last use, so nothing is read again: {step:?}"
        );
    }
}

/// A whole reading begun before the last use overtakes every read of the
/// cards under way and stands for none: what waits on the cards waits for a
/// read made again on what is known now, and is decided on that one.
#[test]
fn a_read_of_the_cards_overtaken_by_a_reading_begun_before_the_last_use_is_made_again() {
    let mut scene = Scene::new();
    scene.confirm_signatures();
    scene.opened(1);
    let (_, read) = scene.sign_unread(1);
    scene.told_read(read.expect("a read"), read_with(Some(Touch::On), true));
    scene.opened(2);
    let held = asked(&scene.sign(2));
    let first = asked(&scene.sign(1));
    scene.allow_once(first);
    let step = scene.ended(1);
    let before = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read after the first use");
    let (whole, _) = scene.sign_unread_key(4).expect("the whole source is read");
    scene.allow_once(held);
    scene.opened(3);
    let step = scene.sign(3);
    let after = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read after the second use");
    let step = scene.told_read(whole, newer_reading());
    assert_eq!(held_for_the_person(&step), 0, "{step:?}");
    let Some(again) = acts(&step).into_iter().find_map(cards_read) else {
        panic!("the cards are read again on the newer reading: {step:?}");
    };
    for overtaken in [before, after] {
        let step = scene.told_cards(overtaken, cards_of(&read_with(Some(Touch::On), true)));
        assert!(
            !events(&step)
                .iter()
                .any(|event| matches!(event, Event::Card(_))),
            "{step:?}"
        );
        assert_eq!(held_for_the_person(&step), 0, "{step:?}");
        assert_eq!(
            acts(&step).into_iter().find_map(cards_read),
            None,
            "{step:?}"
        );
    }
    let step = scene.told_cards(again, cards_of(&newer_reading()));
    assert_eq!(
        held_for_the_person(&step),
        2,
        "both requests are decided on the read made again: {step:?}"
    );
}

impl Scene {
    /// A request signing with `GRIP` on a new connection `knock` to
    /// `capability`'s forward.
    fn sign_through(&mut self, knock: u64, capability: &str) -> Step {
        self.knock_on(knock, capability);
        self.relayed(knock, Relayed::Reached(Ok(())));
        self.core.step(
            Input::Relayed {
                knock: Knock(knock),
                relayed: Relayed::Asks(Ask {
                    operation: Operation::Sign,
                    key: Some(Grip::try_from(GRIP).unwrap()),
                }),
            },
            NOW,
        )
    }

    /// `capability`'s source defined as `source`.
    fn define(&mut self, capability: &str, source: Source) {
        let step = self.ask(
            TERMINAL,
            Request::Change(Change::Define(Capability {
                id: name(capability),
                source,
            })),
        );
        assert_eq!(Scene::refused(&step, TERMINAL), None, "{step:?}");
    }

    /// What `capability`'s source offers, told as the answer to `asked`.
    fn told_read_of(
        &mut self,
        (connection, id): Asked,
        capability: &str,
        read: hedwig_core::keys::Read,
    ) -> Step {
        let told = hedwig_core::dispatch::Told::Read {
            id,
            read: vec![(name(capability), Ok(read))],
        };
        self.core.step(Input::Channel { connection, told }, NOW)
    }

    /// The cards `capability`'s source holds, told as the answer to `asked`.
    fn told_cards_of(
        &mut self,
        (connection, id): Asked,
        capability: &str,
        cards: Vec<Card>,
    ) -> Step {
        let told = hedwig_core::dispatch::Told::Cards {
            id,
            read: vec![(
                name(capability),
                Ok(Cards {
                    cards,
                    keyless: Vec::new(),
                }),
            )],
        };
        self.core.step(Input::Channel { connection, told }, NOW)
    }
}

/// `work`, a capability of the person's own defining that relays the
/// registered `GnuPG`'s default home, forwarded to the remote, with every
/// signature through it put to the person.
fn work_confirmed() -> Scene {
    let mut scene = Scene::attached();
    scene.define(
        "work",
        Source::Gnupg {
            installation: Installation::Registered,
            home: Home::Default,
            access: Access::Restricted,
        },
    );
    let socket = RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap();
    scene.forwarding("work", Exposure::NONE, Binding::Socket(socket));
    let step = scene.ask(
        TERMINAL,
        Request::Rule {
            connection: scene.connection,
            scope: ConnectionScope {
                capability: Selector::Only(name("work")),
                operation: Selector::Only(Operation::Sign),
                key: Keys::Every,
            },
            mode: Some(Mode::Confirm),
        },
    );
    assert_eq!(Scene::refused(&step, TERMINAL), None, "{step:?}");
    scene
}

/// A read of the cards whose capability reaches another agent now - defined
/// again with another `GnuPG` home meanwhile - has nothing of that agent to
/// read again: each request waiting on its cards is decided on what is
/// known, and nothing of the new agent is read for it.
#[test]
fn a_read_of_the_cards_whose_capability_reaches_another_agent_now_decides_what_waits() {
    let mut scene = work_confirmed();
    let step = scene.sign_through(1, "work");
    let whole = acts(&step)
        .into_iter()
        .find_map(whole_read)
        .expect("the source is read");
    let step = scene.told_read_of(whole, "work", read_with(Some(Touch::On), true));
    let first = asked(&step);
    let held = asked(&scene.sign_through(2, "work"));
    scene.allow_once(first);
    let step = scene.ended(1);
    let reading = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read");
    scene.allow_once(held);
    let step = scene.sign_through(3, "work");
    assert_eq!(
        held_for_the_person(&step),
        0,
        "waits for the cards: {step:?}"
    );
    scene.define(
        "work",
        Source::Gnupg {
            installation: Installation::Registered,
            home: Home::At(Folder::try_from(r"C:\Users\dev\other-gnupg").unwrap()),
            access: Access::Restricted,
        },
    );
    let step = scene.told_cards_of(
        reading,
        "work",
        cards_of(&read_with(Some(Touch::Off), true)),
    );
    assert_eq!(
        acts(&step).into_iter().find_map(cards_read),
        None,
        "nothing to read again: {step:?}"
    );
    assert!(
        events(&step)
            .iter()
            .any(|event| matches!(event, Event::Asked { .. } | Event::Settled { .. })),
        "what waited is decided: {step:?}"
    );
}

impl Scene {
    /// Each capability of `granted` granted to the remote, lending what it
    /// names, and the channel up forwarding each at its socket.
    fn forwarding_several(&mut self, granted: Vec<(&str, Lends, &str)>) {
        let mut servings = Vec::new();
        for (capability, lends, path) in granted {
            let step = self.ask(
                TERMINAL,
                Request::Change(Change::Grant {
                    grant: Grant {
                        capability: name(capability),
                        remotes: Granted::One(remote()),
                    },
                    terms: Terms {
                        activation: Activation::OnRequest,
                        setup: Setup::Write,
                        acknowledged: Exposure::NONE,
                        lends,
                    },
                }),
            );
            assert_eq!(Scene::refused(&step, TERMINAL), None, "{step:?}");
            servings.push(Serving {
                capability: name(capability),
                binding: Binding::Socket(RemotePath::try_from(path).unwrap()),
            });
        }
        self.ask(
            TERMINAL,
            Request::Connect {
                remote: remote(),
                with: Vec::new(),
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        );
        let (connection, _) = self.core.state().connection(&remote()).unwrap();
        self.connection = connection;
        self.step(Input::Channel {
            connection,
            told: common::placing(&servings),
        });
        for serving in &servings {
            self.step(Input::Channel {
                connection,
                told: hedwig_core::dispatch::Told::Forwarded {
                    capability: serving.capability.clone(),
                    bound: true,
                },
            });
        }
    }
}

/// `gpg` and `gpg-ssh` granted to the remote, `gpg-ssh` lending `lent`, and
/// the channel up forwarding both: two capabilities reaching one agent.
fn gpg_beside_its_ssh_socket(lent: &SshKey) -> Scene {
    let mut scene = Scene::attached();
    scene.forwarding_several(vec![
        ("gpg", Lends::none(), "/run/user/1000/gnupg/S.gpg-agent"),
        (
            "gpg-ssh",
            Lends::of_keys([(lent.clone(), Toward::Anywhere.into())]),
            "/run/user/1000/gnupg/S.gpg-agent.ssh",
        ),
    ]);
    scene
}

/// A source's `gpg` socket and its SSH socket reach one agent and its cards:
/// a whole reading made through the SSH capability overtakes a read of the
/// cards the `gpg` capability's use asked for, and decides what waits on
/// them.
#[test]
fn a_whole_reading_through_either_capability_of_one_agent_overtakes_its_cards_read() {
    let unknown = SshKey::try_from(
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrm25FDDmgurPp+9REqiJK8zAJcpqMSElCklOS/AsegLtx+gx5BUgH5CnBk5aAOQSkrVsP5DuaWeib+dCzCSqo=",
    )
    .unwrap();
    let mut scene = gpg_beside_its_ssh_socket(&unknown);
    scene.served_card_signature(1);
    let step = scene.ended(1);
    let overtaken = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read");
    let (step, _) = scene.sign_card_key(2);
    assert!(settled(&step).is_empty(), "waits for the cards: {step:?}");
    scene.knock_on(3, "gpg-ssh");
    scene.relayed(3, Relayed::Reached(Ok(())));
    let step = scene.core.step(
        Input::Relayed {
            knock: Knock(3),
            relayed: Relayed::Signs(AgentAsk {
                operation: Operation::Authenticate,
                key: unknown,
                payload: Payload::Authentication {
                    user: None,
                    host: None,
                },
            }),
        },
        NOW,
    );
    let whole = acts(&step)
        .into_iter()
        .find_map(whole_read)
        .expect("the SSH capability's source is read");
    let newer = newer_reading();
    let step = scene.told_read_of(whole, "gpg-ssh", newer.clone());
    let recorded: Vec<Event> = cards_of(&newer).iter().cloned().map(Event::Card).collect();
    assert!(
        recorded.iter().all(|card| events(&step).contains(card)),
        "the newer reading is recorded: {step:?}"
    );
    assert!(
        settled(&step)
            .iter()
            .any(|(_, outcome)| matches!(outcome, Outcome::Served(_))),
        "the gpg request waiting on the cards is decided on it: {step:?}"
    );
    let step = scene.told_cards(overtaken, cards_of(&read_with(Some(Touch::On), true)));
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Card(_))),
        "the gpg capability's older reading is never recorded: {step:?}"
    );
}

/// A whole reading whose cards could not be read says nothing of them: it
/// stands for no read of the cards and overtakes none under way, so what
/// waits on them is decided on the read of the cards alone.
#[test]
fn a_whole_reading_whose_cards_could_not_be_read_stands_for_no_read_of_them() {
    let mut scene = Scene::new();
    scene.served_card_signature(1);
    let step = scene.ended(1);
    let reading = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read");
    let (step, _) = scene.sign_card_key(3);
    assert!(settled(&step).is_empty(), "waits for the cards: {step:?}");
    let (survey, _) = scene.surveyed().expect("a read before a survey");
    let mut failed = read_with(Some(Touch::On), true);
    failed.cards = Err(Failure::Unreachable);
    let step = scene.told_read(survey, failed);
    assert!(
        settled(&step).is_empty(),
        "nothing is decided on a reading whose cards were not read: {step:?}"
    );
    let step = scene.told_cards(reading, cards_of(&newer_reading()));
    assert!(
        events(&step)
            .iter()
            .any(|event| matches!(event, Event::Card(_))),
        "the read of the cards alone is recorded, overtaken by nothing: {step:?}"
    );
    assert_eq!(
        settled(&step).len(),
        1,
        "what waits is decided on it: {step:?}"
    );
}

/// A whole reading overtaken by another recorded first records none of its
/// cards: it began on the cards as known before that one.
#[test]
fn a_whole_reading_another_overtook_records_none_of_its_cards() {
    let mut scene = Scene::new();
    let (survey, _) = scene.surveyed().expect("a read before a survey");
    let (whole, _) = scene.sign_unread_key(2).expect("the source is read again");
    let newer = newer_reading();
    let step = scene.told_read(whole, newer.clone());
    let recorded: Vec<Event> = cards_of(&newer).into_iter().map(Event::Card).collect();
    assert!(
        recorded.iter().all(|card| events(&step).contains(card)),
        "the reading recorded first is recorded: {step:?}"
    );
    let step = scene.told_read(survey, read_with(Some(Touch::On), true));
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Card(_))),
        "the older reading would drop the key the newer one named: {step:?}"
    );
}

/// A read of the cards that failed counts as read: what waits on the cards is
/// decided on what is known, never kept waiting on an agent that does not
/// answer, and nothing is read again for it.
#[test]
fn a_read_of_the_cards_that_failed_decides_what_waits_on_what_is_known() {
    let mut scene = Scene::new();
    scene.served_card_signature(1);
    let step = scene.ended(1);
    let (connection, id) = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read");
    let (step, _) = scene.sign_card_key(3);
    assert!(settled(&step).is_empty(), "waits for the cards: {step:?}");
    let told = hedwig_core::dispatch::Told::Cards {
        id,
        read: vec![(name("gpg"), Err(Failure::Unreachable))],
    };
    let step = scene.core.step(Input::Channel { connection, told }, NOW);
    assert_eq!(
        settled(&step).len(),
        1,
        "decided on what is known: {step:?}"
    );
    assert_eq!(
        acts(&step).into_iter().find_map(cards_read),
        None,
        "nothing is read again: {step:?}"
    );
}

/// A read of the cards after a use that a whole reading begun before that use
/// overtook is made again while the cards are stale, though nothing waits: the
/// cards are read after every use.
#[test]
fn an_overtaken_read_after_a_use_is_made_again_while_the_cards_are_stale() {
    let mut scene = Scene::new();
    scene.confirm_signatures();
    scene.opened(1);
    let (_, read) = scene.sign_unread(1);
    scene.told_read(read.expect("a read"), read_with(Some(Touch::On), true));
    let first = asked(&scene.sign(1));
    let (survey, _) = scene.surveyed().expect("a read before a survey");
    scene.allow_once(first);
    let step = scene.ended(1);
    let overtaken = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read after the use");
    scene.told_read(survey, newer_reading());
    let step = scene.told_cards(overtaken, cards_of(&read_with(Some(Touch::On), true)));
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Card(_))),
        "{step:?}"
    );
    assert!(
        acts(&step).into_iter().find_map(cards_read).is_some(),
        "the cards are read again after the use: {step:?}"
    );
}

/// What waits on an agent's cards is read for through a waiting request's
/// capability that still reaches the agent, where the one the read was made
/// through reaches another now: it is never decided on cards not read after
/// the last use while the agent can still be read.
#[test]
fn what_waits_is_read_for_through_another_capability_still_reaching_the_agent() {
    let ssh = SshKey::try_from(
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrm25FDDmgurPp+9REqiJK8zAJcpqMSElCklOS/AsegLtx+gx5BUgH5CnBk5aAOQSkrVsP5DuaWeib+dCzCSqo=",
    )
    .unwrap();
    let mut scene = Scene::attached();
    scene.define(
        "work-ssh",
        Source::Agent {
            at: AgentAt::Gnupg {
                installation: Installation::Registered,
                home: Home::Default,
            },
        },
    );
    scene.forwarding_several(vec![
        ("gpg", Lends::none(), "/run/user/1000/gnupg/S.gpg-agent"),
        (
            "work-ssh",
            Lends::of_keys([(ssh.clone(), Toward::Anywhere.into())]),
            "/run/user/1000/gnupg/S.gpg-agent.ssh",
        ),
    ]);
    let step = scene.ask(
        TERMINAL,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::One(remote()),
                capability: Selector::Every,
                operation: Selector::Every,
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    );
    assert_eq!(Scene::refused(&step, TERMINAL), None, "{step:?}");
    // The key on the card, which the SSH socket names by its public half.
    let mut read = read_with(Some(Touch::On), true);
    if let Some(key) = read.keyring.keys.first_mut() {
        key.uses = Uses::SIGN.with(Uses::AUTHENTICATE);
        key.ssh = Some(ssh.clone());
    }
    scene.knock_on(1, "work-ssh");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.core.step(
        Input::Relayed {
            knock: Knock(1),
            relayed: Relayed::Signs(AgentAsk {
                operation: Operation::Authenticate,
                key: ssh,
                payload: Payload::Authentication {
                    user: None,
                    host: None,
                },
            }),
        },
        NOW,
    );
    let whole = acts(&step)
        .into_iter()
        .find_map(whole_read)
        .expect("the SSH capability's source is read");
    let first = asked(&scene.told_read_of(whole, "work-ssh", read.clone()));
    let step = scene.sign_through(2, "gpg");
    let step = match acts(&step).into_iter().find_map(whole_read) {
        Some(whole) => scene.told_read_of(whole, "gpg", read.clone()),
        None => step,
    };
    let second = asked(&step);
    scene.allow_once(first);
    let step = scene.ended(1);
    let before = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read after the first use, through work-ssh");
    scene.allow_once(second);
    let step = scene.sign_through(3, "gpg");
    let after = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read after the second use, through gpg");
    assert_eq!(held_for_the_person(&step), 0, "{step:?}");
    scene.define(
        "work-ssh",
        Source::Agent {
            at: AgentAt::Machine,
        },
    );
    let step = scene.told_cards_of(before, "work-ssh", cards_of(&read));
    assert_eq!(
        held_for_the_person(&step),
        0,
        "not decided on a read begun before the second use: {step:?}"
    );
    let step = scene.told_cards_of(after, "gpg", cards_of(&read));
    assert_eq!(held_for_the_person(&step), 1, "{step:?}");
}

/// A scene carrying `gpg` and `work-ssh`, two capabilities of one agent,
/// every request confirmed, with `work-ssh`'s source read and a signature
/// through it held for the person: the scene, the reading and the request.
fn held_through_work_ssh() -> (Scene, hedwig_core::keys::Read, RequestId) {
    let ssh = SshKey::try_from(
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrm25FDDmgurPp+9REqiJK8zAJcpqMSElCklOS/AsegLtx+gx5BUgH5CnBk5aAOQSkrVsP5DuaWeib+dCzCSqo=",
    )
    .unwrap();
    let mut scene = Scene::attached();
    scene.define(
        "work-ssh",
        Source::Agent {
            at: AgentAt::Gnupg {
                installation: Installation::Registered,
                home: Home::Default,
            },
        },
    );
    scene.forwarding_several(vec![
        ("gpg", Lends::none(), "/run/user/1000/gnupg/S.gpg-agent"),
        (
            "work-ssh",
            Lends::of_keys([(ssh.clone(), Toward::Anywhere.into())]),
            "/run/user/1000/gnupg/S.gpg-agent.ssh",
        ),
    ]);
    let step = scene.ask(
        TERMINAL,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::One(remote()),
                capability: Selector::Every,
                operation: Selector::Every,
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    );
    assert_eq!(Scene::refused(&step, TERMINAL), None, "{step:?}");
    let mut read = read_with(Some(Touch::On), true);
    if let Some(key) = read.keyring.keys.first_mut() {
        key.uses = Uses::SIGN.with(Uses::AUTHENTICATE);
        key.ssh = Some(ssh.clone());
    }
    scene.knock_on(1, "work-ssh");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.core.step(
        Input::Relayed {
            knock: Knock(1),
            relayed: Relayed::Signs(AgentAsk {
                operation: Operation::Authenticate,
                key: ssh,
                payload: Payload::Authentication {
                    user: None,
                    host: None,
                },
            }),
        },
        NOW,
    );
    let whole = acts(&step)
        .into_iter()
        .find_map(whole_read)
        .expect("the SSH capability's source is read");
    let first = asked(&scene.told_read_of(whole, "work-ssh", read.clone()));
    (scene, read, first)
}

/// The cards are read on the keyring of their agent: a request through `gpg`,
/// whose own keyring names no key, has them read on the one `work-ssh` offered
/// from the same home, so a known card is not walked.
#[test]
fn the_cards_are_read_on_the_keyring_of_any_capability_of_their_agent() {
    let (mut scene, read, first) = held_through_work_ssh();
    scene.allow_once(first);
    let step = scene.sign_through(2, "gpg");
    let keyring = acts(&step).into_iter().find_map(|effect| match effect {
        Effect::Cards { sources, .. } => sources.first().map(|(_, _, keyring)| keyring.clone()),
        _ => None,
    });
    assert_eq!(keyring, Some(read.keyring), "{step:?}");
}

/// The cards are read on the keyring of the capability they are read through
/// where that names a key, ahead of any other of their agent's, whichever
/// name sorts first among the grants.
#[test]
fn the_cards_are_read_on_their_own_capabilitys_keyring_where_it_names_a_key() {
    let keyring_of = |step: &Step| {
        acts(step).into_iter().find_map(|effect| match effect {
            Effect::Cards { sources, .. } => sources.first().map(|(_, _, keyring)| keyring.clone()),
            _ => None,
        })
    };
    let (mut scene, read, first) = held_through_work_ssh();
    let (survey, _) = scene.surveyed().expect("a read before a survey");
    scene.allow_once(first);
    scene.told_read_of(survey, "gpg", newer_reading());
    let step = scene.sign_through(2, "gpg");
    assert_eq!(
        keyring_of(&step),
        Some(newer_reading().keyring),
        "through gpg: {step:?}"
    );
    let through_gpg = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read through gpg");
    let held = asked(&scene.told_cards_of(through_gpg, "gpg", cards_of(&newer_reading())));
    scene.allow_once(held);
    let step = scene.ended(1);
    assert_eq!(
        keyring_of(&step),
        Some(read.keyring),
        "through work-ssh: {step:?}"
    );
}

/// An overtaken read of the cards after a use, whose capability was defined
/// again meanwhile to reach another agent, is made again through a capability
/// still reaching the agent it read, though nothing waits: the cards are read
/// after every use while that agent can still be read.
#[test]
fn an_overtaken_read_is_made_again_through_a_capability_still_reaching_its_agent() {
    let (mut scene, read, first) = held_through_work_ssh();
    let (survey, _) = scene.surveyed().expect("a read before a survey");
    scene.allow_once(first);
    let step = scene.ended(1);
    let overtaken = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read after the use, through work-ssh");
    scene.define(
        "work-ssh",
        Source::Agent {
            at: AgentAt::Machine,
        },
    );
    scene.told_read_of(survey, "gpg", newer_reading());
    let step = scene.told_cards_of(overtaken, "work-ssh", cards_of(&read));
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Card(_))),
        "{step:?}"
    );
    assert_eq!(
        acts(&step).into_iter().find_map(cards_read_through),
        Some(name("gpg")),
        "the cards are read again after the use, through gpg: {step:?}"
    );
}

/// An overtaken read is not made again through a granted capability where
/// no keyring of the agent names a key: with nothing to tie a slot to a key,
/// that read would walk a card the core knows, with nothing waiting on it.
#[test]
fn an_overtaken_read_is_not_made_again_through_a_capability_with_no_keyring() {
    let (mut scene, read, first) = held_through_work_ssh();
    let (survey, _) = scene.surveyed().expect("a read before a survey");
    scene.allow_once(first);
    let step = scene.ended(1);
    let overtaken = acts(&step)
        .into_iter()
        .find_map(cards_read)
        .expect("the cards are read after the use, through work-ssh");
    scene.define(
        "work-ssh",
        Source::Agent {
            at: AgentAt::Machine,
        },
    );
    // Only work-ssh's part answers: gpg, granted and reaching the agent, has
    // no key in its keyring.
    scene.told_read_of(survey, "work-ssh", newer_reading());
    let step = scene.told_cards_of(overtaken, "work-ssh", cards_of(&read));
    assert_eq!(
        acts(&step).into_iter().find_map(cards_read_through),
        None,
        "no read through a capability with no keyring: {step:?}"
    );
}

/// A request with a key on a card has the cards alone read for it while a
/// whole reading is under way: that reading's `gpg` runs unbounded, a read of
/// the cards alone does not.
#[test]
fn a_card_request_has_the_cards_alone_read_while_a_whole_reading_is_under_way() {
    let mut scene = Scene::new();
    scene.served_card_signature(1);
    scene.sign_unread_key(2).expect("the whole source is read");
    let (step, read) = scene.sign_card_key(3);
    assert!(read.is_some(), "the cards alone are read: {step:?}");
    assert!(settled(&step).is_empty(), "waits for them: {step:?}");
}

/// Lending a device to a remote while one of its ADB connections is
/// open reaches that connection, which leaves the device out or ends where it
/// used one no longer lent; a step that lends nothing new tells it nothing.
#[test]
fn a_change_to_what_the_grant_lends_reaches_each_live_adb_connection() {
    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let phone = Lends::devices([DeviceSerial::try_from("TESTDEVICE01").unwrap()]);
    let step = scene.ask(
        TERMINAL,
        Request::Change(Change::Grant {
            grant: Grant {
                capability: name("adb"),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::SERVICE.with(Exposure::NETWORK),
                lends: phone.clone(),
            },
        }),
    );
    assert!(
        acts(&step).iter().any(|effect| matches!(
            effect,
            Effect::Relend { knock, lending }
                if *knock == Knock(1) && lending.lends == phone && lending.network
        )),
        "{step:?}"
    );
    let again = scene.relayed(
        1,
        Relayed::Selected(DeviceSerial::try_from("TESTDEVICE01").unwrap()),
    );
    assert!(
        !acts(&again)
            .iter()
            .any(|effect| matches!(effect, Effect::Relend { .. }))
    );
}

/// An emulator's console is carried for each lent emulator the server holds,
/// and for no other, asked for once; recorded once its carrier listens;
/// dropped when the emulator leaves or is no longer lent; carried to a
/// remote whose channel comes up while the server is watched; and a command
/// refused at it is the remote turned away.
#[test]
#[allow(clippy::too_many_lines, reason = "one console's life, start to end")]
fn a_console_is_carried_for_each_lent_emulator_and_dropped_when_it_goes() {
    use hedwig_core::devices::{Device, Listing, State, View};
    use hedwig_model::trail::Dropped;

    let emulator = |port: u16, id: u64| Device {
        serial: format!("emulator-{port}"),
        state: State::DEVICE,
        usb: false,
        devpath: String::new(),
        product: "sdk_gphone64_x86_64".to_owned(),
        model: "sdk_gphone64_x86_64".to_owned(),
        device: "emu64xa".to_owned(),
        id,
    };
    let view = |devices: Vec<Device>| Input::Devices {
        capability: name("adb"),
        view: View {
            devices,
            listing: Listing::Read,
            holder: None,
        },
    };
    let lend = |scene: &mut Scene, serials: &[&str]| {
        scene.ask(
            TERMINAL,
            Request::Change(Change::Grant {
                grant: Grant {
                    capability: name("adb"),
                    remotes: Granted::One(remote()),
                },
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Write,
                    acknowledged: Exposure::SERVICE,
                    lends: Lends::devices(
                        serials
                            .iter()
                            .map(|serial| DeviceSerial::try_from(*serial).unwrap()),
                    ),
                },
            }),
        )
    };
    let consoled = |step: &Step| -> Vec<(u16, String)> {
        step.effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Console { port, device, .. } => {
                    Some((port.number(), device.as_str().to_owned()))
                }
                _ => None,
            })
            .collect()
    };
    let unconsoled = |step: &Step| -> Vec<u16> {
        step.effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Unconsole { port, .. } => Some(port.number()),
                _ => None,
            })
            .collect()
    };

    let mut scene = adb();
    let connection = scene.connection;
    lend(&mut scene, &["emulator-5554"]);
    let step = scene.step(view(vec![emulator(5554, 1), emulator(5556, 2)]));
    assert_eq!(consoled(&step), [(5554, "emulator-5554".to_owned())]);

    let carriage = Carriage::Console {
        port: Port::try_from(5554).unwrap(),
        device: DeviceSerial::try_from("emulator-5554").unwrap(),
    };
    let step = scene.step(Input::Consoled {
        connection,
        capability: name("adb"),
        carriage: carriage.clone(),
        endpoint: Port::try_from(50_200).unwrap(),
    });
    assert_eq!(
        events(&step),
        [Event::Carried {
            connection,
            capability: name("adb"),
            carriage: carriage.clone(),
            endpoint: Port::try_from(50_200).unwrap(),
        }]
    );
    let step = scene.step(view(vec![emulator(5554, 1), emulator(5556, 2)]));
    assert!(consoled(&step).is_empty(), "carried once");

    let step = scene.step(Input::Hosted {
        connection,
        capability: name("adb"),
    });
    assert_eq!(
        events(&step),
        [Event::TurnedAway {
            remote: Some(remote()),
            refusal: Refusal::Withheld {
                capability: name("adb"),
                request: Withheld::Hosted,
            },
        }]
    );

    let step = scene.step(view(vec![emulator(5556, 2)]));
    assert_eq!(unconsoled(&step), [5554]);
    assert_eq!(
        events(&step),
        [Event::Dropped {
            connection,
            capability: name("adb"),
            carriage: carriage.clone(),
            why: Dropped::Gone,
        }]
    );

    scene.step(view(vec![emulator(5554, 3), emulator(5556, 2)]));
    scene.step(Input::Consoled {
        connection,
        capability: name("adb"),
        carriage: carriage.clone(),
        endpoint: Port::try_from(50_200).unwrap(),
    });
    let step = lend(&mut scene, &["emulator-5556"]);
    assert_eq!(unconsoled(&step), [5554]);
    assert_eq!(consoled(&step), [(5556, "emulator-5556".to_owned())]);
    assert!(events(&step).contains(&Event::Dropped {
        connection,
        capability: name("adb"),
        carriage,
        why: Dropped::Unlent,
    }));

    // A second remote's channel comes up while the server is watched: the
    // console of the emulator lent to it is carried from the view in hand.
    let second = RemoteId {
        route: name("ssh"),
        address: Address::try_from("dev@build-8.example").unwrap(),
    };
    scene.ask(
        TERMINAL,
        Request::Change(Change::Grant {
            grant: Grant {
                capability: name("adb"),
                remotes: Granted::One(second.clone()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::SERVICE,
                lends: Lends::devices([DeviceSerial::try_from("emulator-5554").unwrap()]),
            },
        }),
    );
    scene.ask(
        TERMINAL,
        Request::Connect {
            remote: second.clone(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    );
    let (other, _) = scene.core.state().connection(&second).unwrap();
    let serving = Serving {
        capability: name("adb"),
        binding: adb_socket(),
    };
    scene.step(Input::Channel {
        connection: other,
        told: common::placing(std::slice::from_ref(&serving)),
    });
    let step = scene.step(Input::Channel {
        connection: other,
        told: hedwig_core::dispatch::Told::Forwarded {
            capability: name("adb"),
            bound: true,
        },
    });
    let carried: Vec<(RemoteId, u16)> = step
        .effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Console { remote, port, .. } => Some((remote.clone(), port.number())),
            _ => None,
        })
        .collect();
    assert_eq!(carried, [(second, 5554)]);
}

const SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1cuDWSQ4xW25Rb1dBGnBjWHV2DfwPn/bqUaSYf4z15";

/// `ssh-agent` granted to the remote with `lends`, at the socket the remote's
/// `gpgconf` names for it.
fn ssh_agent(lends: Lends) -> Scene {
    let socket = RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent.ssh").unwrap();
    let mut scene = Scene::granted("ssh-agent", Exposure::NONE, Binding::Socket(socket));
    scene.ask(
        TERMINAL,
        Request::Change(Change::Grant {
            grant: Grant {
                capability: name("ssh-agent"),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::NONE,
                lends,
            },
        }),
    );
    scene
}

fn lent(key: &SshKey) -> Lends {
    Lends::of_keys([(key.clone(), Toward::Anywhere.into())])
}

/// A connection to an SSH agent is carried with what the grant lends; a
/// signature it holds is asked as the operation its payload makes it, naming
/// its key, and what the payload says is recorded with it, whatever the
/// outcome.
#[test]
fn an_agent_s_signature_is_asked_by_its_key_with_its_payload_recorded() {
    let key = SshKey::try_from(SSH_KEY).unwrap();
    let mut scene = ssh_agent(lent(&key));
    let step = scene.knock_on(1, "ssh-agent");
    assert!(
        acts(&step).iter().any(|effect| matches!(
            effect,
            Effect::Relay {
                source: Relaying::Agent(agent),
                ..
            } if agent.lends == lent(&key)
        )),
        "{step:?}"
    );
    scene.relayed(1, Relayed::Reached(Ok(())));
    let payload = Payload::Authentication {
        user: Some(Words::try_from("git").unwrap()),
        host: None,
    };
    let step = scene.relayed(
        1,
        Relayed::Signs(AgentAsk {
            operation: Operation::Authenticate,
            key: key.clone(),
            payload: payload.clone(),
        }),
    );
    let seen = events(&step);
    let asked = seen
        .iter()
        .position(|event| {
            matches!(
                event,
                Event::Asked {
                    operation: Operation::Authenticate,
                    key: Some(KeyId::Ssh(asked)),
                    ..
                } if *asked == key
            )
        })
        .expect("the signature is asked");
    assert!(
        matches!(seen.get(asked + 1), Some(Event::Payload { payload: recorded, .. }) if *recorded == payload),
        "the payload follows the request at once: {seen:?}"
    );
    assert!(
        acts(&step)
            .iter()
            .any(|effect| matches!(effect, Effect::Settle { knock, verdict: Ok(()) } if *knock == Knock(1))),
        "notify by default, with the terminal attending: {step:?}"
    );
}

/// A held login or signature reaches the person with what it asks to have
/// signed: the card raised for it carries the payload recorded with it, so no
/// surface reads the activity for it.
#[test]
fn a_held_agent_request_raises_its_card_with_its_payload() {
    let key = SshKey::try_from(SSH_KEY).unwrap();
    let host = SshKey::try_from(
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIQfBFoTFcymxqayVAmobeqqsWVKCgyRgJhRE4W7CDjAcuptlxzloqrpI2/N0w2y8dLIaPMBQcggIHZExfGvJ8c=",
    )
    .unwrap();
    let mut scene = ssh_agent(lent(&key));
    scene.attach(VIEWER, ClientKind::Interface);
    scene.ask(
        TERMINAL,
        Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::Every,
                capability: Selector::Every,
                operation: Selector::Every,
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    );
    for (knock, operation, payload) in [
        (
            1,
            Operation::Authenticate,
            Payload::Authentication {
                user: Some(Words::try_from("hedwig-e1").unwrap()),
                host: Some(host.clone()),
            },
        ),
        (
            2,
            Operation::Sign,
            Payload::Signature {
                namespace: Some(Words::try_from("git").unwrap()),
            },
        ),
    ] {
        scene.knock_on(knock, "ssh-agent");
        scene.relayed(knock, Relayed::Reached(Ok(())));
        let step = scene.relayed(
            knock,
            Relayed::Signs(AgentAsk {
                operation,
                key: key.clone(),
                payload: payload.clone(),
            }),
        );
        assert!(
            events(&step)
                .iter()
                .any(|event| matches!(event, Event::Held { .. })),
            "{step:?}"
        );
        let raised: Vec<Attention> = notices(&step, VIEWER)
            .into_iter()
            .filter_map(|notice| match notice {
                Notice::Raised(needs) => Some(needs.attention),
                _ => None,
            })
            .collect();
        assert!(
            raised.iter().any(|attention| matches!(
                attention,
                Attention::Request {
                    operation: raised_for,
                    key: Some(KeyId::Ssh(named)),
                    payload: Some(carried),
                    ..
                } if *raised_for == operation && *named == key && *carried == payload
            )),
            "{raised:?}"
        );
    }
}

/// What a remote breaks of the agent protocol turns it away; what the agent
/// breaks marks the source failing.
#[test]
fn an_agent_protocol_breach_is_the_remote_s_or_the_agent_s() {
    let mut scene = ssh_agent(Lends::none());
    scene.knock_on(1, "ssh-agent");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.relayed(1, Relayed::Strayed(AgentBreach::Malformed));
    assert!(
        events(&step).iter().any(|event| matches!(
            event,
            Event::TurnedAway {
                refusal: Refusal::OffProtocol { .. },
                ..
            }
        )),
        "{step:?}"
    );
    let step = scene.relayed(1, Relayed::Strayed(AgentBreach::NotAnswer));
    assert!(
        events(&step).iter().any(|event| matches!(
            event,
            Event::Source {
                health: Health::Failing(Failure::Mismatched),
                ..
            }
        )),
        "{step:?}"
    );
}

/// What holds the agent's pipe is recorded where it changed, and a key
/// listing asked for by a grant surface is answered from the agent once.
#[test]
fn the_pipe_s_holder_is_recorded_once_and_its_keys_are_listed_on_request() {
    let mut scene = ssh_agent(Lends::none());
    scene.knock_on(1, "ssh-agent");
    let holder = SourceHolder {
        program: Location::try_from(r"C:\Program Files\1Password\app\8\1Password.exe").unwrap(),
        session: 2,
        whose: Whose::Person {
            logon: 7,
            signed_in: SignedIn::Locally,
            rights: Rights::Standard,
        },
    };
    let step = scene.relayed(1, Relayed::Held(Some(holder.clone())));
    assert!(
        events(&step).iter().any(|event| matches!(
            event,
            Event::HeldBy { capability, holder: Some(_) } if *capability == name("ssh-agent")
        )),
        "{step:?}"
    );
    let again = scene.relayed(1, Relayed::Held(Some(holder)));
    assert!(
        !events(&again)
            .iter()
            .any(|event| matches!(event, Event::HeldBy { .. })),
        "{again:?}"
    );
    let gone = scene.relayed(1, Relayed::Held(None));
    assert!(
        events(&gone)
            .iter()
            .any(|event| matches!(event, Event::HeldBy { holder: None, .. })),
        "{gone:?}"
    );

    let step = scene.ask(TERMINAL, Request::Keys(name("ssh-agent")));
    let id = scene.asked;
    assert!(
        acts(&step).iter().any(|effect| matches!(
            effect,
            Effect::Keys { capability, at: AgentAt::Pipe(_), .. } if *capability == name("ssh-agent")
        )),
        "{step:?}"
    );
    let key = SshKey::try_from(SSH_KEY).unwrap();
    let listed = vec![AgentKey { key, comment: None }];
    let step = scene.step(Input::Keys {
        link: TERMINAL,
        id,
        capability: name("ssh-agent"),
        listed: Reach {
            result: Ok(listed.clone()),
            holder: None,
        },
    });
    assert!(
        step.effects.iter().any(|effect| matches!(
            effect,
            Effect::Send {
                frame: FromCore::Reply { reply: Ok(Reply::Keys(keys)), .. },
                ..
            } if *keys == listed
        )),
        "{step:?}"
    );
    let step = scene.step(Input::Keys {
        link: TERMINAL,
        id,
        capability: name("ssh-agent"),
        listed: Reach {
            result: Err(Failure::Occupied),
            holder: None,
        },
    });
    assert_eq!(
        Scene::refused(&step, TERMINAL),
        Some(Refusal::SourceUnavailable {
            capability: name("ssh-agent"),
            failure: Failure::Occupied,
        })
    );
    let step = scene.ask(TERMINAL, Request::Keys(name("gpg")));
    assert!(Scene::refused(&step, TERMINAL).is_some(), "{step:?}");
}

/// A change to the keys a grant lends reaches each live connection to the
/// agent.
#[test]
fn a_change_to_the_keys_lent_reaches_each_live_agent_connection() {
    let key = SshKey::try_from(SSH_KEY).unwrap();
    let mut scene = ssh_agent(Lends::none());
    scene.knock_on(1, "ssh-agent");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.ask(
        TERMINAL,
        Request::Change(Change::Grant {
            grant: Grant {
                capability: name("ssh-agent"),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::NONE,
                lends: lent(&key),
            },
        }),
    );
    assert!(
        acts(&step).iter().any(|effect| matches!(
            effect,
            Effect::Relend { knock, lending } if *knock == Knock(1) && lending.lends == lent(&key)
        )),
        "{step:?}"
    );
}

fn device(serial: &str, usb: bool) -> hedwig_core::devices::Device {
    hedwig_core::devices::Device {
        serial: serial.to_owned(),
        state: hedwig_core::devices::State::DEVICE,
        usb,
        devpath: String::new(),
        product: String::new(),
        model: "Pixel_8".to_owned(),
        device: String::new(),
        id: 1,
    }
}

fn listing(devices: Vec<hedwig_core::devices::Device>) -> hedwig_core::devices::View {
    hedwig_core::devices::View {
        devices,
        listing: hedwig_core::devices::Listing::Read,
        holder: None,
    }
}

/// Whether a step ends the watch of `capability`'s server.
fn unwatches(step: &Step, capability: &str) -> bool {
    acts(step)
        .iter()
        .any(|effect| matches!(effect, Effect::Unwatch { capability: ended } if ended.as_str() == capability))
}

/// A client answered a source's devices lists them for as long as it
/// stays. It is told they are stale each time the server's listing changes
/// what it was answered, and only then; a client that listed nothing is not
/// told; a channel carrying the source keeps its watch when the client
/// leaves.
#[test]
fn a_client_that_listed_the_devices_is_told_each_time_they_change() {
    let mut scene = adb();
    scene.attach(VIEWER, ClientKind::Interface);
    let stale = Notice::Stale(Topic::Devices(name("adb")));
    let phone = device("R5CR10ABC", true);
    let step = scene.ask(VIEWER, Request::Devices(name("adb")));
    let id = scene.asked;
    assert!(
        acts(&step).iter().any(|effect| matches!(
            effect,
            Effect::Lend { link, id: asked, .. } if *link == VIEWER && *asked == id
        )),
        "{step:?}"
    );
    let step = scene.step(Input::Lendable {
        link: VIEWER,
        id,
        capability: name("adb"),
        view: listing(vec![phone.clone()]),
    });
    assert!(notices(&step, VIEWER).is_empty(), "the asker is answered");
    scene.step(Input::Sent { link: VIEWER });
    let told = |scene: &mut Scene, view| {
        let step = scene.step(Input::Devices {
            capability: name("adb"),
            view,
        });
        scene.step(Input::Sent { link: VIEWER });
        let mine = notices(&step, VIEWER);
        let theirs = notices(&step, TERMINAL);
        assert!(!theirs.contains(&Notice::Stale(Topic::Devices(name("adb")))));
        mine.into_iter()
            .filter(|notice| matches!(notice, Notice::Stale(Topic::Devices(_))))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        told(&mut scene, listing(vec![phone.clone()])),
        Vec::<Notice>::new()
    );
    let emulator = device("emulator-5554", false);
    assert_eq!(
        told(&mut scene, listing(vec![phone.clone(), emulator])),
        std::slice::from_ref(&stale)
    );
    assert_eq!(
        told(
            &mut scene,
            hedwig_core::devices::View::failed(Failure::Unreachable)
        ),
        [stale]
    );
    let step = scene.step(Input::Left { link: VIEWER });
    assert!(!unwatches(&step, "adb"), "the channel still carries adb");
}

/// A source no channel carries is watched while a client lists its
/// devices, and its watch ends with the last client listing it.
#[test]
fn the_watch_a_listing_keeps_ends_with_the_last_client_listing_it() {
    let mut scene = Scene::new();
    scene.attach(VIEWER, ClientKind::Interface);
    for link in [TERMINAL, VIEWER] {
        scene.ask(link, Request::Devices(name("adb")));
        let id = scene.asked;
        scene.step(Input::Lendable {
            link,
            id,
            capability: name("adb"),
            view: listing(Vec::new()),
        });
        scene.step(Input::Sent { link });
    }
    let step = scene.step(Input::Left { link: VIEWER });
    assert!(!unwatches(&step, "adb"), "the terminal still lists them");
    let step = scene.step(Input::Left { link: TERMINAL });
    assert!(unwatches(&step, "adb"), "{step:?}");
}

/// A client answered the serial ports lists them while it stays. When
/// Windows says they may have changed, they are listed again only where a
/// client lists them, and it is told they are stale only where they did.
#[test]
fn a_client_that_listed_the_ports_is_told_when_windows_changes_them() {
    use hedwig_model::protocol::{SerialPort, Usb};
    use hedwig_model::text::PortName;

    let mut scene = Scene::new();
    scene.attach(VIEWER, ClientKind::Interface);
    let relisted = |step: &Step| {
        acts(step)
            .iter()
            .any(|effect| matches!(effect, Effect::Ports { asked: None }))
    };
    assert!(
        !relisted(&scene.step(Input::PortsMoved)),
        "nobody lists them"
    );
    let step = scene.ask(VIEWER, Request::Ports);
    let id = scene.asked;
    assert!(acts(&step).iter().any(|effect| matches!(
        effect,
        Effect::Ports { asked: Some((link, asked)) } if *link == VIEWER && *asked == id
    )));
    scene.step(Input::Ports {
        asked: Some((VIEWER, id)),
        ports: Vec::new(),
    });
    scene.step(Input::Sent { link: VIEWER });
    assert!(relisted(&scene.step(Input::PortsMoved)));
    let step = scene.step(Input::Ports {
        asked: None,
        ports: Vec::new(),
    });
    assert!(notices(&step, VIEWER).is_empty(), "nothing changed");
    let board = vec![SerialPort {
        port: PortName::try_from("COM5").unwrap(),
        name: None,
        usb: Some(Usb {
            vendor: 0x303A,
            product: 0x1001,
        }),
    }];
    let step = scene.step(Input::Ports {
        asked: None,
        ports: board,
    });
    assert_eq!(notices(&step, VIEWER), [Notice::Stale(Topic::Ports)]);
    assert!(!notices(&step, TERMINAL).contains(&Notice::Stale(Topic::Ports)));
    scene.step(Input::Sent { link: VIEWER });
    scene.step(Input::Left { link: VIEWER });
    assert!(!relisted(&scene.step(Input::PortsMoved)));
}

/// A signature through gpg-agent's SSH socket naming a key the keyring
/// the core holds does not account for waits for the source to be read
/// again, its payload kept; read, it is decided as the key the keyring ties
/// it to - here by a statement naming that key's `OpenPGP` fingerprint - and
/// a key the reading did not account for is not read for again.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one connection's three requests across two reads"
)]
fn an_unread_ssh_key_waits_for_the_keyring_and_is_decided_as_the_key_it_ties_to() {
    use hedwig_core::dispatch::Told;
    use hedwig_core::keys::Read;
    use hedwig_model::text::Words;
    use hedwig_model::trail::Uses;

    let ssh = SshKey::try_from(SSH_KEY).unwrap();
    let unknown = SshKey::try_from(
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrm25FDDmgurPp+9REqiJK8zAJcpqMSElCklOS/AsegLtx+gx5BUgH5CnBk5aAOQSkrVsP5DuaWeib+dCzCSqo=",
    )
    .unwrap();
    let primary = Fingerprint::try_from("07B56DFBBA12BB80FA84939C76F8274EF1651088").unwrap();
    let socket = RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent.ssh").unwrap();
    let mut scene = Scene::granted("gpg-ssh", Exposure::NONE, Binding::Socket(socket));
    let lends = Lends::of_keys([&ssh, &unknown].map(|key| (key.clone(), Toward::Anywhere.into())));
    for change in [
        Change::Grant {
            grant: Grant {
                capability: name("gpg-ssh"),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::NONE,
                lends,
            },
        },
        Change::Rule {
            scope: RuleScope {
                remotes: Remotes::Every,
                capability: Selector::Every,
                operation: Selector::Every,
                key: Keys::Only(hedwig_model::policy::KeyName::Fingerprint(primary.clone())),
            },
            mode: Mode::Confirm,
        },
    ] {
        scene.ask(TERMINAL, Request::Change(change));
    }
    scene.knock_on(1, "gpg-ssh");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let login = |key: &SshKey| {
        Relayed::Signs(AgentAsk {
            operation: Operation::Authenticate,
            key: key.clone(),
            payload: Payload::Authentication {
                user: Words::try_from("dev").ok(),
                host: None,
            },
        })
    };
    let step = scene.core.step(
        Input::Relayed {
            knock: Knock(1),
            relayed: login(&ssh),
        },
        NOW,
    );
    let first = acts(&step)
        .iter()
        .find_map(|effect| match effect {
            Effect::Read { id, sources, .. }
                if sources
                    .iter()
                    .any(|(capability, _)| *capability == name("gpg-ssh")) =>
            {
                Some(*id)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{step:?}"));
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Asked { .. })),
        "not asked before the keys are read"
    );

    let keyring = Keyring {
        keys: vec![Key {
            grip: Grip::try_from(GRIP).unwrap(),
            fingerprint: Fingerprint::try_from("5A1B9C0D2E3F405162738495A6B7C8D9E0F1A2B3").unwrap(),
            primary,
            uses: Uses::AUTHENTICATE,
            user: None,
            card: None,
            ssh: Some(ssh.clone()),
        }],
        signing: None,
    };
    let read = Read {
        keyring: keyring.clone(),
        ..Read::default()
    };
    let step = scene.core.step(
        Input::Channel {
            connection: scene.connection,
            told: Told::Read {
                id: first,
                read: vec![(name("gpg-ssh"), Ok(read.clone()))],
            },
        },
        NOW,
    );
    let recorded = events(&step);
    assert!(recorded.contains(&Event::Offered {
        capability: name("gpg-ssh"),
        keyring,
    }));
    assert!(
        recorded
            .iter()
            .any(|event| matches!(event, Event::Payload { .. })),
        "the payload kept across the read: {recorded:?}"
    );
    assert!(
        recorded
            .iter()
            .any(|event| matches!(event, Event::Held { .. })),
        "held by the rule naming the key's fingerprint: {recorded:?}"
    );

    // A key the keyring does not offer is read for once, then decided as
    // the key the request names.
    scene.knock_on(2, "gpg-ssh");
    scene.relayed(2, Relayed::Reached(Ok(())));
    let step = scene.core.step(
        Input::Relayed {
            knock: Knock(2),
            relayed: login(&unknown),
        },
        NOW,
    );
    let again = acts(&step)
        .iter()
        .find_map(|effect| match effect {
            Effect::Read { id, .. } => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{step:?}"));
    let step = scene.core.step(
        Input::Channel {
            connection: scene.connection,
            told: Told::Read {
                id: again,
                read: vec![(name("gpg-ssh"), Ok(read))],
            },
        },
        NOW,
    );
    assert!(
        events(&step)
            .iter()
            .any(|event| matches!(event, Event::Asked { .. }))
    );
    scene.knock_on(3, "gpg-ssh");
    scene.relayed(3, Relayed::Reached(Ok(())));
    let step = scene.core.step(
        Input::Relayed {
            knock: Knock(3),
            relayed: login(&unknown),
        },
        NOW,
    );
    assert!(
        !acts(&step)
            .iter()
            .any(|effect| matches!(effect, Effect::Read { .. })),
        "not read for again: {step:?}"
    );
}

/// What `READKEY --format=ssh` answers is read as OpenSSH writes the key:
/// its comment dropped, an ECDSA key's curve named as its type names it
/// where `GnuPG` wrote libgcrypt's name, and a blob whose type is not the one
/// written refused.
#[test]
fn an_agent_s_ssh_form_is_read_as_openssh_writes_it() {
    use hedwig_core::keys::ssh_form;
    let ed25519 = SshKey::try_from(SSH_KEY).unwrap();
    assert_eq!(
        ssh_form(format!("{SSH_KEY} (none)").as_bytes()),
        Some(ed25519.clone())
    );
    assert_eq!(ssh_form(SSH_KEY.as_bytes()), Some(ed25519));
    let written = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAKTklTVCBQLTI1NgAAAEEECTY4fmVl3AQo+qvA7BdkBSYVNnQeaMYaeInknnTq9ZA6WzCtlL0f5RFajKaDdJ/C7n+qreFzDe1iPEdH9gDMuA==";
    let openssh = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAk2OH5lZdwEKPqrwOwXZAUmFTZ0HmjGGniJ5J506vWQOlswrZS9H+URWoymg3Sfwu5/qq3hcw3tYjxHR/YAzLg=";
    let fixed = SshKey::try_from(openssh).unwrap();
    assert_eq!(
        ssh_form(format!("{written} (none)").as_bytes()),
        Some(fixed.clone())
    );
    assert_eq!(ssh_form(openssh.as_bytes()), Some(fixed));
    let (_, blob) = SSH_KEY.split_once(' ').unwrap();
    let mislabelled = format!("ssh-rsa {blob}");
    assert_eq!(ssh_form(mislabelled.as_bytes()), None);
    assert_eq!(ssh_form(b""), None);
    assert_eq!(ssh_form(b"ssh-ed25519"), None);
    assert_eq!(ssh_form(&[0xff, 0xfe]), None);
}

/// A change of what holds a source, read while a remote's
/// connection serves its capability, is in that remote's activity as the
/// core pages it, and every client that shows anything is told its activity
/// and what the workstation holds are stale.
#[test]
fn a_holders_change_is_in_the_activity_of_the_remote_it_serves() {
    use hedwig_core::devices::{Listing, View};

    let holder = SourceHolder {
        program: Location::try_from(r"C:\Android\platform-tools\adb.exe").unwrap(),
        session: 0,
        whose: Whose::Unread,
    };
    let mut scene = adb();
    scene.attach(VIEWER, ClientKind::Viewer);
    let step = scene.step(Input::Devices {
        capability: name("adb"),
        view: View {
            devices: Vec::new(),
            listing: Listing::Failed(Failure::Unidentified),
            holder: Some(holder.clone()),
        },
    });
    let held = Event::HeldBy {
        capability: name("adb"),
        holder: Some(holder),
    };
    assert!(events(&step).contains(&held), "{step:?}");
    for link in [TERMINAL, VIEWER] {
        let told = notices(&step, link);
        for topic in [Topic::Exposure, Topic::Workstation] {
            assert!(
                told.contains(&Notice::Stale(topic.clone())),
                "{link:?} {told:?}"
            );
        }
    }
    let step = scene.ask(
        TERMINAL,
        Request::Activity {
            remote: Selector::Only(remote()),
            before: None,
            limit: std::num::NonZeroU8::MAX,
        },
    );
    let page = step
        .effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Send {
                frame:
                    FromCore::Reply {
                        reply: Ok(Reply::Activity(page)),
                        ..
                    },
                ..
            } => Some(page.clone()),
            _ => None,
        })
        .expect("a page");
    assert!(page.iter().any(|entry| entry.event == held), "{page:?}");
}

/// A client whose request for an agent's keys led the core to read a
/// new holder is told the workstation is stale, as every other client is:
/// its reply is the keys, not what answers for them.
#[test]
fn the_client_whose_listing_read_a_holder_is_told_the_workstation_changed() {
    let mut scene = ssh_agent(Lends::none());
    scene.attach(VIEWER, ClientKind::Viewer);
    scene.ask(VIEWER, Request::Keys(name("ssh-agent")));
    let id = scene.asked;
    let holder = SourceHolder {
        program: Location::try_from(r"C:\Program Files\1Password\app\8\1Password.exe").unwrap(),
        session: 2,
        whose: Whose::Person {
            logon: 7,
            signed_in: SignedIn::Locally,
            rights: Rights::Standard,
        },
    };
    let step = scene.step(Input::Keys {
        link: VIEWER,
        id,
        capability: name("ssh-agent"),
        listed: Reach {
            result: Ok(Vec::new()),
            holder: Some(holder),
        },
    });
    assert!(
        events(&step).iter().any(|event| matches!(
            event,
            Event::HeldBy {
                holder: Some(_),
                ..
            }
        )),
        "{step:?}"
    );
    for link in [VIEWER, TERMINAL] {
        let told = notices(&step, link);
        for topic in [Topic::Workstation, Topic::Exposure] {
            assert!(
                told.contains(&Notice::Stale(topic.clone())),
                "{link:?} {told:?}"
            );
        }
    }
}
