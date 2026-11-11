//! What the deciding function makes of a remote's `git` asking for a
//! credential, and of a remote's job telling the person something: each
//! recorded and decided at the one gate, the site named and the secret never.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

mod common;

use hedwig_core::credential::{Credential, Release};
use hedwig_core::dispatch::{Core, Effect, Input, Knock, Link, Now, Step};
use hedwig_core::relay::{Relayed, Relaying};
use hedwig_model::capability::{Capability, Exposure, Lends, Operation, Setup, Source};
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Grant, Terms};
use hedwig_model::credential::{Place, Unread};
use hedwig_model::protocol::{
    Attention, Decision, FromCore, Notice, PROTOCOL, Reply, Request, ToCore,
};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::site::{Site, url};
use hedwig_model::text::{Address, Name, Program, Remark, RemotePath};
use hedwig_model::trail::{
    Binding, ClientKind, ConnectionId, Event, Failure, Health, Integrity, Item, NOTICE_WINDOW,
    NOTICES_AT_ONCE, Origin, Outcome, Payload, Peer, RequestId, Serving, Tick, Timestamp,
};

const TERMINAL: Link = Link(1);
const DESKTOP: Origin = Origin {
    process: 4100,
    logon: 0x3e7_0000,
    session: 2,
    integrity: Integrity::Medium,
};
const OVER_SSH: Origin = Origin {
    process: 4300,
    logon: 0x3e7_0042,
    session: 0,
    integrity: Integrity::High,
};

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn remote() -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from("build").unwrap(),
    }
}

fn at(tick: u64) -> Now {
    Now {
        at: Timestamp(1_790_000_000_000 + tick),
        tick: Tick(tick),
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

fn raised(step: &Step) -> Vec<Attention> {
    step.effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Send {
                frame: FromCore::Notice(Notice::Raised(needs)),
                ..
            } => Some(needs.attention.clone()),
            _ => None,
        })
        .collect()
}

struct Scene {
    core: Core,
    asked: u32,
    connection: ConnectionId,
    now: u64,
}

impl Scene {
    /// A client attached from `origin`, `capability` defined where it does
    /// not ship and granted to the remote acknowledging what it exposes, and
    /// the channel up forwarding it to a socket in Hedwig's folder.
    fn new(capability: Capability, origin: Origin, kind: ClientKind) -> Scene {
        let mut core = Core::new(
            Catalogue::shipped().unwrap(),
            Configuration::default(),
            Vec::new(),
            "0.2.0".to_owned(),
        );
        core.begin(DESKTOP, None, Vec::new(), at(1_000));
        let mut scene = Scene {
            core,
            asked: 0,
            connection: ConnectionId(hedwig_model::trail::Seq(0)),
            now: 1_000,
        };
        scene.step(Input::Arrived {
            link: TERMINAL,
            peer: Some(origin.into()),
        });
        scene.ask(Request::Hello {
            protocol: PROTOCOL,
            kind,
            attends: Remotes::Every,
        });
        let exposure = capability.exposure();
        let id = capability.id.clone();
        if !matches!(capability.source, Source::Notices) {
            scene.ask(Request::Change(Change::Define(capability)));
        }
        scene.ask(Request::Change(Change::Grant {
            grant: Grant {
                capability: id.clone(),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: exposure,
                lends: Lends::none(),
            },
        }));
        scene.ask(Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        });
        let (connection, _) = scene.core.state().connection(&remote()).unwrap();
        scene.connection = connection;
        let serving = Serving {
            capability: id.clone(),
            binding: Binding::Socket(
                RemotePath::try_from(format!("/run/user/1000/hedwig/{id}").as_str()).unwrap(),
            ),
        };
        scene.step(Input::Channel {
            connection,
            told: common::placing(std::slice::from_ref(&serving)),
        });
        scene.step(Input::Channel {
            connection,
            told: hedwig_core::dispatch::Told::Forwarded {
                capability: id,
                bound: true,
            },
        });
        scene
    }

    fn step(&mut self, input: Input) -> Step {
        let now = at(self.now);
        let step = self.core.step(input, now);
        common::keyed(&mut self.core, step, now)
    }

    fn ask(&mut self, request: Request) -> Step {
        self.asked += 1;
        let frame = ToCore {
            id: self.asked,
            request,
        };
        let step = self.step(Input::Asked {
            link: TERMINAL,
            frame,
        });
        for _ in step
            .effects
            .iter()
            .filter(|effect| matches!(effect, Effect::Send { link: to, .. } if *to == TERMINAL))
        {
            self.core.step(Input::Sent { link: TERMINAL }, at(self.now));
        }
        step
    }

    /// How many of a remote's notices `attention` answers with now.
    fn noticed(&mut self) -> usize {
        let step = self.ask(Request::Attention);
        step.effects
            .iter()
            .find_map(|effect| match effect {
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
                        .filter(|needs| matches!(needs.attention, Attention::Noticed { .. }))
                        .count(),
                ),
                _ => None,
            })
            .expect("attention is answered")
    }

    fn knock(&mut self, knock: u64, capability: &str) -> Step {
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
}

fn credentials() -> Capability {
    Capability {
        id: name("git-https"),
        source: Source::Credentials {
            git: Program::try_from("git").unwrap(),
            sites: vec!["https://github.com".parse::<Site>().unwrap()],
        },
    }
}

fn wants(host: &str) -> Relayed {
    Relayed::Wants(Place::Site(url(&format!("https://{host}/")).unwrap()))
}

fn asked(step: &Step) -> RequestId {
    step.entries
        .iter()
        .find(|entry| matches!(entry.event, Event::Asked { .. }))
        .map(|entry| RequestId(entry.seq))
        .expect("a request")
}

/// A remote's `git` asking for a listed site's credential is recorded with the
/// site, held for the person as what ships asks and put to them naming the
/// site; allowed where a sign-in would show, the relay is let have the
/// workstation's helper ask them, then served.
#[test]
fn a_credential_is_held_naming_its_site_and_served_on_the_persons_word() {
    let mut scene = Scene::new(credentials(), DESKTOP, ClientKind::Interface);
    let step = scene.knock(1, "git-https");
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Relay {
            source: Relaying::Credential(Credential { git }),
            ..
        }] if git.as_str() == "git"
    ));
    let step = scene.relayed(1, wants("github.com"));
    let request = asked(&step);
    let site = "https://github.com".parse::<Site>().unwrap();
    assert_eq!(
        events(&step),
        [
            Event::Asked {
                connection: scene.connection,
                capability: name("git-https"),
                operation: Operation::Connect,
                key: None,
            },
            Event::Payload {
                request,
                payload: Payload::Credential { site: site.clone() },
            },
            Event::Held { request },
        ]
    );
    assert!(raised(&step).iter().any(|attention| matches!(
        attention,
        Attention::Request { payload: Some(Payload::Credential { site: named }), .. }
            if *named == site
    )));
    let step = scene.ask(Request::Decide {
        request,
        decision: Decision::Once,
    });
    assert_eq!(
        acts(&step),
        [
            &Effect::Interact { knock: Knock(1) },
            &Effect::Settle {
                knock: Knock(1),
                verdict: Ok(())
            }
        ]
    );
    let step = scene.relayed(1, Relayed::Gave(Release::Given));
    assert_eq!(
        events(&step),
        [Event::Source {
            capability: name("git-https"),
            health: Health::Sound
        }]
    );
}

/// Allowed from a terminal over SSH, the person is not where the
/// workstation's helper would show its sign-in, so it is not let ask.
#[test]
fn allowed_away_from_the_desktop_the_helper_is_not_let_ask() {
    let mut scene = Scene::new(credentials(), OVER_SSH, ClientKind::Terminal);
    scene.knock(1, "git-https");
    let step = scene.relayed(1, wants("github.com"));
    let request = asked(&step);
    let step = scene.ask(Request::Decide {
        request,
        decision: Decision::Once,
    });
    assert_eq!(
        acts(&step),
        [&Effect::Settle {
            knock: Knock(1),
            verdict: Ok(())
        }]
    );
    // Served and nothing given: the workstation held none, and could not ask.
    let step = scene.relayed(1, Relayed::Gave(Release::Nothing));
    assert!(events(&step).contains(&Event::Unreleased { request }));
}

/// An unlisted site is refused naming the site to add, a site's refusal is
/// recorded as the forge's word only for a site the capability answers for,
/// what is not git's request turns the remote away, and a `git` that cannot
/// run fails the source.
#[test]
fn what_a_credential_relay_tells_is_recorded_where_it_belongs() {
    let mut scene = Scene::new(credentials(), DESKTOP, ClientKind::Interface);
    scene.knock(1, "git-https");
    let step = scene.relayed(1, wants("gitlab.com"));
    let refusal = Refusal::UnlistedCredential {
        capability: name("git-https"),
        site: "https://gitlab.com".parse::<Site>().unwrap(),
    };
    assert!(events(&step).contains(&Event::Settled {
        request: asked(&step),
        outcome: Outcome::Refused(refusal.clone()),
    }));
    assert_eq!(
        acts(&step),
        [&Effect::Settle {
            knock: Knock(1),
            verdict: Err(refusal)
        }]
    );

    scene.knock(2, "git-https");
    let erased =
        |host: &str| Relayed::Erased(Place::Site(url(&format!("https://{host}/")).unwrap()));
    assert_eq!(
        events(&scene.relayed(2, erased("github.com"))),
        [Event::Refuted {
            connection: scene.connection,
            capability: name("git-https"),
            site: "https://github.com".parse::<Site>().unwrap(),
        }]
    );
    assert_eq!(
        events(&scene.relayed(2, erased("gitlab.com"))),
        Vec::<Event>::new()
    );

    scene.knock(3, "git-https");
    let step = scene.relayed(3, Relayed::Misasked(Unread::Host));
    assert!(matches!(
        events(&step).as_slice(),
        [Event::TurnedAway {
            refusal: Refusal::OffProtocol { .. },
            ..
        }]
    ));

    scene.knock(4, "git-https");
    let step = scene.relayed(4, Relayed::Gave(Release::Failed(Failure::Unstartable)));
    assert_eq!(
        events(&step),
        [Event::Source {
            capability: name("git-https"),
            health: Health::Failing(Failure::Unstartable)
        }]
    );
}

fn notices() -> Capability {
    Capability {
        id: name("notices"),
        source: Source::Notices,
    }
}

fn remark(text: &str) -> Relayed {
    Relayed::Says(Remark::try_from(text).unwrap())
}

/// A remote's notice is kept as its words and raised to the person at the
/// volume they hear notices from that remote at, `curl` told at once; it is
/// never held, whoever is there.
#[test]
fn a_notice_is_kept_and_raised_as_the_remotes_words() {
    let mut scene = Scene::new(notices(), DESKTOP, ClientKind::Interface);
    let step = scene.knock(1, "notices");
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Relay {
            source: Relaying::Notify,
            ..
        }]
    ));
    let step = scene.relayed(1, remark("build 4512 finished"));
    let noticed = Event::Noticed {
        connection: scene.connection,
        capability: name("notices"),
        remark: Remark::try_from("build 4512 finished").unwrap(),
        unheard: 0,
    };
    assert_eq!(events(&step), [noticed]);
    assert_eq!(
        acts(&step),
        [&Effect::Settle {
            knock: Knock(1),
            verdict: Ok(())
        }]
    );
    let seq = step.entries.first().unwrap().seq;
    assert!(raised(&step).iter().any(|attention| matches!(
        attention,
        Attention::Noticed { remote: from, notice, remark, unheard: 0, .. }
            if *from == remote() && *notice == seq && remark.as_str() == "build 4512 finished"
    )));
    // Put away, it and every earlier one from that remote are gone.
    assert_eq!(scene.noticed(), 1);
    scene.ask(Request::PutAway(Item::Noticed {
        remote: remote(),
        through: seq,
    }));
    assert_eq!(scene.noticed(), 0);
}

/// What one remote sends is bounded: past [`NOTICES_AT_ONCE`] in a minute a
/// notice is refused for coming too fast and counted, never recorded on its
/// own, and the count is said with the next one kept.
#[test]
fn notices_that_come_too_fast_are_counted_and_said_with_the_next() {
    let mut scene = Scene::new(notices(), DESKTOP, ClientKind::Interface);
    for knock in 1..=u64::try_from(NOTICES_AT_ONCE).unwrap() {
        scene.knock(knock, "notices");
        scene.now += 10;
        let step = scene.relayed(knock, remark("step done"));
        assert!(matches!(
            events(&step).as_slice(),
            [Event::Noticed { unheard: 0, .. }]
        ));
    }
    for knock in 100..103 {
        scene.knock(knock, "notices");
        let step = scene.relayed(knock, remark("step done"));
        assert!(
            events(&step).is_empty(),
            "nothing recorded for one too fast"
        );
        assert_eq!(
            acts(&step),
            [&Effect::Settle {
                knock: Knock(knock),
                verdict: Err(Refusal::Hushed {
                    capability: name("notices")
                })
            }]
        );
    }
    scene.now += NOTICE_WINDOW;
    scene.knock(200, "notices");
    let step = scene.relayed(200, remark("all done"));
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Noticed { unheard: 3, .. }]
    ));
}
