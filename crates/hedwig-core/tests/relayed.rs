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

use hedwig_core::adb::Reverse;
use hedwig_core::agent::{Ask as AgentAsk, Breach as AgentBreach};
use hedwig_core::assuan::{Ask, Breach, Side};
use hedwig_core::dispatch::{Core, Effect, Input, Knock, Link, Now, Step};
use hedwig_core::relay::Reach;
use hedwig_core::relay::{Relayed, Relaying};
use hedwig_model::capability::{AgentAt, Exposure, Lends, Operation, Setup, Toward};
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
    Address, DeviceSerial, Fingerprint, Grip, KeyId, Mark, Name, Port, RemotePath, Serial, SshKey,
    Words,
};
use hedwig_model::trail::{
    Binding, Card, Carriage, ClientKind, ConnectionId, Event, Failure, Health, Held, Integrity,
    Key, Keyring, Origin, Outcome, Payload, Peer, RequestId, Serving, SignaturePin, Target, Tick,
    Timestamp, Touch, Uses,
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
        scene
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
        sources,
    }) = acts(&step).first().copied()
    else {
        panic!("the keys are read first: {step:?}");
    };
    let connection = *connection;
    assert_eq!(connection, scene.connection);
    assert_eq!(sources.len(), 1);
    let read = Read {
        keyring: keyring.clone(),
        armoured: [(primary.clone(), armour.clone())].into(),
        cards: Vec::new(),
    };
    let told = Told::Read {
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

    // Read again and unchanged, nothing is recorded.
    let step = scene.core.step(
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
    assert!(acts(&step).is_empty() || matches!(acts(&step).first(), Some(Effect::Read { .. })));
    let told = Told::Read {
        read: vec![(name("gpg"), Ok(read))],
    };
    let step = scene.core.step(Input::Channel { connection, told }, NOW);
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

/// A reverse is given an endpoint for its remote and target; once the device
/// takes it, it is recorded and carried on to the remote through the channel.
/// The same target again is given the same endpoint and recorded once.
#[test]
fn a_reverse_is_given_an_endpoint_recorded_once_taken_and_carried_on() {
    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
    let step = scene.relayed(1, Relayed::Reverse(metro()));
    let [Effect::Endpoint { knock, reverse, .. }] = acts(&step).as_slice() else {
        panic!("{step:?}");
    };
    let adb = Reverse {
        remote: remote(),
        capability: name("adb"),
        target: metro(),
    };
    assert_eq!((*knock, reverse), (Knock(1), &adb));
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
        [Effect::Haul { connection, reverse, .. }]
            if *connection == scene.connection && *reverse == adb
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
    let step = scene.relayed(
        2,
        Relayed::Reversed {
            target: metro(),
            endpoint,
        },
    );
    assert_eq!(events(&step), Vec::<Event>::new());
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

/// When the remote's channel comes back, each reverse it carried in this run
/// is carried on to it again through the new channel, with nothing asked.
#[test]
fn a_returning_channel_carries_the_remotes_reverses_again() {
    let mut scene = adb();
    scene.knock_on(1, "adb");
    scene.relayed(1, Relayed::Reached(Ok(())));
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
            Effect::Haul { connection, reverse, .. },
            Effect::Watch { capability, .. },
        ]
            if *sealed == second && *connection == second && reverse.target == metro()
                && reverse.remote == remote() && reverse.capability == name("adb")
                && *capability == name("adb")
    ));
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
    }
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
    fn sign_unread(&mut self, knock: u64) -> (Step, Option<ConnectionId>) {
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
        let read = acts(&step).into_iter().find_map(|effect| match effect {
            Effect::Read {
                connection,
                sources,
            } if sources.len() == 1 => Some(*connection),
            _ => None,
        });
        (step, read)
    }

    fn told_read(&mut self, connection: ConnectionId, read: hedwig_core::keys::Read) -> Step {
        self.core.step(
            Input::Channel {
                connection,
                told: hedwig_core::dispatch::Told::Read {
                    read: vec![(name("gpg"), Ok(read))],
                },
            },
            NOW,
        )
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
        let card = read_with(touch, true).cards.into_iter().next().unwrap();
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
fn cards_read(effect: &Effect) -> Option<ConnectionId> {
    match effect {
        Effect::Cards {
            connection,
            sources,
        } if sources.len() == 1 => Some(*connection),
        _ => None,
    }
}

impl Scene {
    fn told_cards(&mut self, connection: ConnectionId, cards: Vec<Card>) -> Step {
        self.core.step(
            Input::Channel {
                connection,
                told: hedwig_core::dispatch::Told::Cards {
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
        let connection = read.expect("a read");
        let step = self.told_read(connection, read_with(Some(Touch::On), true));
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
    assert_eq!(
        acts(&step)
            .into_iter()
            .filter_map(cards_read)
            .collect::<Vec<_>>(),
        vec![connection],
        "{step:?}"
    );
    assert!(
        !acts(&step)
            .iter()
            .any(|effect| matches!(effect, Effect::Read { .. })),
        "the whole source is not read again"
    );
    let step = scene.told_cards(
        connection,
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
    let step = scene.told_cards(connection, vec![holding(SECOND_CARD, None)]);
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
    assert_eq!(
        acts(&step)
            .into_iter()
            .filter_map(cards_read)
            .collect::<Vec<_>>(),
        vec![connection]
    );
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
        connection,
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
    assert!(acts(&step).into_iter().find_map(cards_read).is_some());
    allow(&mut scene, held);
    scene.told_cards(connection, vec![holding(CARD, Some(Touch::On))]);
    let step = scene.ended(2);
    assert!(
        acts(&step).into_iter().find_map(cards_read).is_some(),
        "the signature allowed during the reading still has the cards read: {step:?}"
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
    assert!(
        acts(&step).iter().any(|effect| matches!(
            effect,
            Effect::Read { sources, .. } if sources.iter().any(|(capability, _)| *capability == name("gpg-ssh"))
        )),
        "{step:?}"
    );
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
    assert!(
        acts(&step)
            .iter()
            .any(|effect| matches!(effect, Effect::Read { .. }))
    );
    let step = scene.core.step(
        Input::Channel {
            connection: scene.connection,
            told: Told::Read {
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
