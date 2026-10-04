//! What the deciding function makes of a connection to a serial
//! capability's forward: carried by the serial relay, its opening decided,
//! the port recorded taken once the relay opened it and released when it
//! closed it; a second connection refused while the port is held; an absent
//! or busy port standing on the capability; the port listing answered.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

mod common;

use hedwig_core::dispatch::{Core, Effect, Input, Knock, Link, Now, Step};
use hedwig_core::relay::{Relayed, Relaying};
use hedwig_core::serial::Serial;
use hedwig_model::capability::{Capability, Exposure, Lends, Setup, Source};
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Grant, Terms};
use hedwig_model::policy::Basis;
use hedwig_model::protocol::{FromCore, PROTOCOL, Reply, Request, SerialPort, ToCore, Usb};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::text::{Address, Name, Port, PortName};
use hedwig_model::trail::{
    Binding, ClientKind, ConnectionId, Event, Failure, Health, Integrity, Origin, Outcome, Peer,
    RequestId, Serving, Tick, Timestamp,
};

const TERMINAL: Link = Link(1);
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

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn com(text: &str) -> PortName {
    PortName::try_from(text).unwrap()
}

fn host(address: &str) -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from(address).unwrap(),
    }
}

fn events(step: &Step) -> Vec<Event> {
    step.entries
        .iter()
        .map(|entry| entry.event.clone())
        .collect()
}

fn settled(step: &Step) -> Vec<Outcome> {
    events(step)
        .into_iter()
        .filter_map(|event| match event {
            Event::Settled { outcome, .. } => Some(outcome),
            _ => None,
        })
        .collect()
}

struct Scene {
    core: Core,
    asked: u32,
    connections: Vec<ConnectionId>,
}

impl Scene {
    /// `esp32` lends COM5 at port 4000 of each remote; a terminal attached;
    /// a channel up to each of `remotes` carrying it.
    fn new(remotes: &[RemoteId]) -> Scene {
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
            connections: Vec::new(),
        };
        scene.step(Input::Arrived {
            link: TERMINAL,
            peer: Some(DESKTOP.into()),
        });
        scene.ask(Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Terminal,
            attends: Remotes::Every,
        });
        scene.ask(Request::Change(Change::Define(Capability {
            id: name("esp32"),
            source: Source::Serial {
                port: com("COM5"),
                remote: Port::try_from(4000).unwrap(),
            },
        })));
        for remote in remotes {
            scene.ask(Request::Change(Change::Grant {
                grant: Grant {
                    capability: name("esp32"),
                    remotes: Granted::One(remote.clone()),
                },
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Inspect,
                    acknowledged: Exposure::SERVICE,
                    lends: Lends::none(),
                },
            }));
            scene.ask(Request::Connect {
                remote: remote.clone(),
                with: Vec::new(),
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            });
            let (connection, _) = scene.core.state().connection(remote).unwrap();
            let serving = Serving {
                capability: name("esp32"),
                binding: Binding::Port(Port::try_from(4000).unwrap()),
            };
            scene.step(Input::Channel {
                connection,
                told: common::placing(std::slice::from_ref(&serving)),
            });
            scene.step(Input::Channel {
                connection,
                told: hedwig_core::dispatch::Told::Forwarded {
                    capability: name("esp32"),
                    bound: true,
                },
            });
            scene.connections.push(connection);
        }
        scene
    }

    fn step(&mut self, input: Input) -> Step {
        let step = self.core.step(input, NOW);
        common::keyed(&mut self.core, step, NOW)
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
        if step
            .effects
            .iter()
            .any(|effect| matches!(effect, Effect::Send { link, .. } if *link == TERMINAL))
        {
            self.core.step(Input::Sent { link: TERMINAL }, NOW);
        }
        step
    }

    fn knock(&mut self, knock: u64, connection: ConnectionId) -> Step {
        self.step(Input::Knocked {
            knock: Knock(knock),
            connection,
            capability: name("esp32"),
            peer: Some(Peer {
                origin: DESKTOP,
                program: None,
                channel: Some(connection),
            }),
        })
    }

    fn relayed(&mut self, knock: u64, relayed: Relayed) -> Step {
        self.step(Input::Relayed {
            knock: Knock(knock),
            relayed,
        })
    }
}

fn served(step: &Step, knock: u64) -> bool {
    step.effects.contains(&Effect::Settle {
        knock: Knock(knock),
        verdict: Ok(()),
    })
}

#[test]
fn a_serial_connection_is_carried_by_the_serial_relay_and_its_port_recorded_taken_and_released() {
    let mut scene = Scene::new(&[host("dev@build.example")]);
    let here = scene.connections[0];
    let step = scene.knock(1, here);
    assert!(
        step.effects.iter().any(|effect| matches!(
            effect,
            Effect::Relay { knock: Knock(1), source: Relaying::Serial(Serial { port }), .. }
                if *port == com("COM5")
        )),
        "{step:?}"
    );
    let step = scene.relayed(1, Relayed::Reached(Ok(())));
    assert_eq!(settled(&step), [Outcome::Served(Basis::Default)]);
    assert!(served(&step, 1));
    let request = step
        .entries
        .iter()
        .find(|entry| matches!(entry.event, Event::Asked { .. }))
        .map(|entry| RequestId(entry.seq))
        .unwrap();
    let chip = Usb {
        vendor: 0x303A,
        product: 0x1001,
    };
    let step = scene.relayed(1, Relayed::Opened(Ok(Some(chip))));
    assert!(events(&step).contains(&Event::Taken {
        request,
        connection: here,
        capability: name("esp32"),
        port: com("COM5"),
        usb: Some(chip),
    }));
    assert!(scene.core.state().holder(&com("COM5")).is_some());
    let step = scene.relayed(1, Relayed::Released);
    assert_eq!(events(&step), [Event::Released { request }]);
    let step = scene.relayed(1, Relayed::Ended);
    assert_eq!(events(&step), Vec::<Event>::new());
    assert_eq!(scene.core.state().holder(&com("COM5")), None);
}

#[test]
fn while_one_connection_holds_the_port_every_other_opening_is_refused_naming_its_remote() {
    let build = host("dev@build.example");
    let ci = host("ci@runner.example");
    let mut scene = Scene::new(&[build.clone(), ci]);
    let (here, there) = (scene.connections[0], scene.connections[1]);
    scene.knock(1, here);
    scene.relayed(1, Relayed::Reached(Ok(())));
    scene.relayed(1, Relayed::Opened(Ok(None)));
    for (knock, connection) in [(2, here), (3, there)] {
        scene.knock(knock, connection);
        let step = scene.relayed(knock, Relayed::Reached(Ok(())));
        let refusal = Refusal::PortHeld {
            capability: name("esp32"),
            by: build.clone(),
        };
        assert_eq!(settled(&step), [Outcome::Refused(refusal.clone())]);
        assert!(step.effects.contains(&Effect::Settle {
            knock: Knock(knock),
            verdict: Err(refusal),
        }));
    }
    scene.relayed(1, Relayed::Released);
    scene.relayed(1, Relayed::Ended);
    scene.knock(4, there);
    let step = scene.relayed(4, Relayed::Reached(Ok(())));
    assert!(served(&step, 4));
}

#[test]
fn an_absent_port_refuses_the_opening_and_a_busy_one_stands_on_the_capability() {
    let mut scene = Scene::new(&[host("dev@build.example")]);
    let here = scene.connections[0];
    scene.knock(1, here);
    let step = scene.relayed(1, Relayed::Reached(Err(Failure::Absent)));
    let refusal = Refusal::SourceUnavailable {
        capability: name("esp32"),
        failure: Failure::Absent,
    };
    assert_eq!(settled(&step), [Outcome::Refused(refusal)]);
    assert!(events(&step).contains(&Event::Source {
        capability: name("esp32"),
        health: Health::Failing(Failure::Absent),
    }));
    scene.relayed(1, Relayed::Ended);
    // Present again and served, the open finds another program holding it:
    // nothing is taken, and the capability says why.
    scene.knock(2, here);
    let step = scene.relayed(2, Relayed::Reached(Ok(())));
    assert!(served(&step, 2));
    let step = scene.relayed(2, Relayed::Opened(Err(Failure::Busy)));
    assert_eq!(
        events(&step),
        [Event::Source {
            capability: name("esp32"),
            health: Health::Failing(Failure::Busy),
        }]
    );
    let step = scene.relayed(2, Relayed::Ended);
    assert_eq!(events(&step), Vec::<Event>::new());
    assert_eq!(scene.core.state().holder(&com("COM5")), None);
}

#[test]
fn the_port_listing_is_read_off_the_deciding_thread_and_answered_to_the_client() {
    let mut scene = Scene::new(&[]);
    let step = scene.ask(Request::Ports);
    let id = scene.asked;
    assert!(step.effects.contains(&Effect::Ports {
        asked: Some((TERMINAL, id))
    }));
    let ports = vec![SerialPort {
        port: com("COM5"),
        name: None,
        usb: Some(Usb {
            vendor: 0x303A,
            product: 0x1001,
        }),
    }];
    let step = scene.step(Input::Ports {
        asked: Some((TERMINAL, id)),
        ports: ports.clone(),
    });
    assert!(step.effects.iter().any(|effect| matches!(
        effect,
        Effect::Send {
            link: TERMINAL,
            frame: FromCore::Reply { id: answered, reply: Ok(Reply::Ports(listed)) },
            ..
        } if *answered == id && *listed == ports
    )));
}

#[test]
fn a_remote_that_breaks_the_protocol_is_turned_away_and_a_port_that_goes_stands_on_the_capability()
{
    use hedwig_core::rfc2217::Breach;
    let mut scene = Scene::new(&[host("dev@build.example")]);
    let here = scene.connections[0];
    scene.knock(1, here);
    scene.relayed(1, Relayed::Reached(Ok(())));
    scene.relayed(1, Relayed::Opened(Ok(None)));
    let step = scene.relayed(1, Relayed::Broke(Breach::Undefined(0x41)));
    let recorded = events(&step);
    let [
        Event::TurnedAway {
            remote: Some(remote),
            refusal:
                Refusal::OffProtocol {
                    capability,
                    account,
                },
        },
    ] = recorded.as_slice()
    else {
        panic!("{step:?}");
    };
    assert_eq!(
        (remote, capability),
        (&host("dev@build.example"), &name("esp32"))
    );
    assert_eq!(account.as_str(), Breach::Undefined(0x41).to_string());
    scene.relayed(1, Relayed::Released);
    scene.relayed(1, Relayed::Ended);
    scene.knock(2, here);
    scene.relayed(2, Relayed::Reached(Ok(())));
    scene.relayed(2, Relayed::Opened(Ok(None)));
    let step = scene.relayed(2, Relayed::Lost(Failure::Absent));
    assert_eq!(
        events(&step),
        [Event::Source {
            capability: name("esp32"),
            health: Health::Failing(Failure::Absent),
        }]
    );
    let step = scene.relayed(2, Relayed::Released);
    assert!(matches!(events(&step).as_slice(), [Event::Released { .. }]));
}
