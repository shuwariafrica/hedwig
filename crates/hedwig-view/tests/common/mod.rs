//! A link driven against the model's stand-in core: every request the link
//! sends is carried out by the model's own gate, and the reply fed back.

#![allow(dead_code, reason = "each suite uses a different part")]
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test support")]

use std::time::Instant;

use hedwig_client::Standing;
use hedwig_model::gate::World;
use hedwig_model::organisation::{Part, Place, Policy};
use hedwig_model::process::{CoreState, Instance, Running};
use hedwig_model::protocol::{
    Attention, Contact, FromCore, Needs, Notice, Request, Row, ToCore, Topic,
};
use hedwig_model::refusal::Refusal;
use hedwig_model::scope::Audience;
use hedwig_model::text::PipeName;
use hedwig_model::trail::{ClientId, Event as Happened, Origin, Timestamp};
use hedwig_view::link::{Attached, Effect, Event, Link};

// The model's own test support, read where it lives: one stand-in core.
#[path = "../../../hedwig-model/tests/support/mod.rs"]
pub(crate) mod support;

use support::desk::Desk;
use support::{DESKTOP, OVER_SSH, Trail};

/// Which requests a bench refuses.
pub(crate) type Refuses = fn(&Request) -> bool;

pub(crate) fn pipe(digit: char) -> PipeName {
    PipeName::try_from(format!("hedwig.{}", digit.to_string().repeat(32)).as_str())
        .expect("a pipe name")
}

pub(crate) fn serving(pipe: PipeName) -> Standing {
    Standing::Known(Running {
        supervisor: Instance {
            process: 4100,
            created: 134_037_216_000_000_000,
        },
        core: CoreState::Serving {
            pipe,
            process: 4200,
        },
    })
}

pub(crate) fn clock(at: Timestamp) -> String {
    format!("t{}", at.0 % 1_000_000)
}

pub(crate) struct Bench {
    pub(crate) desk: Desk,
    pub(crate) link: Link,
    pub(crate) client: Option<ClientId>,
    /// What the core reads of the interface from the pipe.
    pub(crate) origin: Origin,
    /// Every frame the link sent, in order.
    pub(crate) sent: Vec<ToCore>,
    /// A request the core refuses as it may refuse any - a frame it could
    /// not read, a version it does not speak - where a suite stands one up:
    /// the model's stand-in answers every request it can.
    pub(crate) refuse: Option<(Refuses, Refusal)>,
}

impl Bench {
    /// A core started at the desktop, and the window's link, not yet
    /// attached to it.
    pub(crate) fn viewer() -> Bench {
        Bench {
            link: Link::viewer(),
            ..Bench::new()
        }
    }

    /// A core started at the desktop, and no link to it yet.
    pub(crate) fn new() -> Bench {
        Bench {
            desk: Desk::new(support::catalogue()),
            link: Link::default(),
            client: None,
            origin: DESKTOP,
            sent: Vec::new(),
            refuse: None,
        }
    }

    /// A core started from an SSH session into the workstation.
    pub(crate) fn over_ssh() -> Bench {
        let mut bench = Bench::new();
        let mut trail = Trail::default();
        trail.push(Happened::Started {
            version: "0.2.0".to_owned(),
            origin: OVER_SSH,
            after: None,
        });
        bench.desk.trail = trail;
        bench
    }

    /// The interface finds the core, attaches, and is told what it shows.
    pub(crate) fn attached() -> Bench {
        let mut bench = Bench::new();
        bench.attach();
        bench
    }

    pub(crate) fn attach(&mut self) {
        let effects = self.link.handle(Event::Looked(serving(pipe('a'))));
        assert!(effects.contains(&Effect::Open(pipe('a'))), "{effects:?}");
        self.feed(Event::Opened);
    }

    /// Hands the link an event and carries out what it asks of the core
    /// until it asks nothing more. Returns every effect along the way.
    pub(crate) fn feed(&mut self, event: Event) -> Vec<Effect> {
        let mut all = Vec::new();
        let mut pending = self.link.handle(event);
        while !pending.is_empty() {
            let mut next = Vec::new();
            for effect in pending {
                match effect {
                    Effect::Send(frame) => {
                        let reply = self.carry_out(frame);
                        next.extend(self.link.handle(Event::Frame(reply, Instant::now())));
                    }
                    other => all.push(other),
                }
            }
            pending = next;
        }
        all
    }

    fn carry_out(&mut self, frame: ToCore) -> FromCore {
        let id = frame.id;
        let reply = match frame.request {
            Request::Hello {
                protocol,
                kind,
                attends,
            } => {
                self.sent.push(ToCore {
                    id,
                    request: Request::Hello {
                        protocol,
                        kind,
                        attends: attends.clone(),
                    },
                });
                self.desk
                    .greet_to(protocol, kind, self.origin, attends)
                    .map(|(client, reply)| {
                        self.client = Some(client);
                        reply
                    })
            }
            request
                if self
                    .refuse
                    .as_ref()
                    .is_some_and(|(refused, _)| refused(&request)) =>
            {
                let refusal = self.refuse.as_ref().expect("matched").1.clone();
                self.sent.push(ToCore { id, request });
                Err(refusal)
            }
            request => {
                let client = self.client.expect("greeted before anything else");
                let reply = self.desk.send(client, clone(&request));
                self.sent.push(ToCore { id, request });
                reply
            }
        };
        FromCore::Reply { id, reply }
    }

    /// The core tells its attending clients something, as it does when the
    /// trail gains an entry they did not cause.
    pub(crate) fn notice(&mut self, notice: Notice) -> Vec<Effect> {
        self.feed(Event::Frame(FromCore::Notice(notice), Instant::now()))
    }

    /// The core tells its attending clients each topic the trail's newest
    /// entry marks stale, as it does for an entry they did not cause.
    pub(crate) fn told(&mut self) {
        let topics = self
            .desk
            .trail
            .entries
            .last()
            .map_or(&[][..], |entry| entry.event.touches());
        for topic in topics {
            self.notice(Notice::Stale(topic.clone()));
        }
    }

    /// Hands the link what the stand-in core told this client, of `told`;
    /// returns how many notices that was.
    pub(crate) fn hear(&mut self, told: Vec<(ClientId, Notice)>) -> usize {
        let mine: Vec<Notice> = told
            .into_iter()
            .filter(|(client, _)| Some(*client) == self.client)
            .map(|(_, notice)| notice)
            .collect();
        let count = mine.len();
        for notice in mine {
            self.notice(notice);
        }
        count
    }

    pub(crate) fn seen(&self) -> &Attached {
        self.link.seen().attached().expect("attached")
    }

    pub(crate) fn rows(&self) -> &[Row] {
        self.seen().rows.as_deref().expect("rows were told")
    }

    pub(crate) fn attention(&self) -> &[Needs] {
        self.seen()
            .attention
            .as_deref()
            .expect("attention was told")
    }

    /// What needs the person, without how loudly.
    pub(crate) fn items(&self) -> Vec<&Attention> {
        self.attention()
            .iter()
            .map(|needs| &needs.attention)
            .collect()
    }

    /// The organisation's policy for this machine is read again as `lines`,
    /// and the core says the configuration changed.
    pub(crate) fn govern(&mut self, lines: &[(Part, String)]) {
        let policy = Policy::read(lines.iter().map(|(part, text)| {
            (
                Place {
                    audience: Audience::Machine,
                    part: *part,
                },
                text.as_str(),
            )
        }));
        self.desk.govern(&policy);
        self.notice(Notice::Stale(Topic::Configuration));
    }

    /// Whom the organisation says to ask, as the core last said.
    pub(crate) fn contacts(&self) -> &[Contact] {
        &self
            .seen()
            .settings
            .as_ref()
            .expect("settings were told")
            .workstation
            .contacts
    }

    /// Whether the core would carry `request` out for the interface now.
    pub(crate) fn permits(&self, request: &Request) -> Result<(), Refusal> {
        let state = self.desk.trail.state();
        World {
            catalogue: &self.desk.catalogue,
            configuration: &self.desk.configuration,
            state: &state,
        }
        .permit(self.client.expect("greeted"), request)
    }
}

/// A request's written form read back: requests are not `Clone`, because one
/// can carry a secret, and the suites need the one that was sent.
pub(crate) fn clone(request: &Request) -> Request {
    hedwig_model::wire::read(&hedwig_model::wire::line(request)).expect("a request reads back")
}
