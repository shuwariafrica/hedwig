//! Shared by the suites: short constructors for validated values, and a seeded
//! generator so a property is tried over the same inputs on every run.

#![allow(dead_code, reason = "each suite uses a different part")]
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test support")]

use std::collections::BTreeMap;

use hedwig_model::capability::{Capability, Exposure, Lends, Operation, Setup};
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Grant, Terms};
use hedwig_model::json::Json;
use hedwig_model::policy::{ConnectionScope, Mode, Resolved, RuleScope, Rules, Subject, resolve};
use hedwig_model::remote::{Granted, RemoteId, Remotes, Route, Sets};
use hedwig_model::text::{Address, Name, Pattern, Port};
use hedwig_model::trail::{
    ClientId, ClientKind, ConnectionId, Entry, Event, Integrity, Opener, Origin, RequestId, Seq,
    State, Tick, Timestamp,
};

pub(crate) mod corpus;
pub(crate) mod desk;

pub(crate) fn name(text: &str) -> Name {
    Name::try_from(text).expect("a valid name")
}

pub(crate) fn address(text: &str) -> Address {
    Address::try_from(text).expect("a valid address")
}

pub(crate) fn pattern(text: &str) -> Pattern {
    Pattern::try_from(text).expect("a valid pattern")
}

pub(crate) fn port(number: u16) -> Port {
    Port::try_from(number).expect("a non-zero port")
}

pub(crate) fn remote(route: &str, at: &str) -> RemoteId {
    RemoteId {
        route: name(route),
        address: address(at),
    }
}

/// A vendor's route as a person or an organisation defines it: the worked
/// definition the documentation publishes. It does not ship.
pub(crate) fn coder() -> Route {
    hedwig_model::wire::read(include_str!("../coder-route.json")).expect("the definition reads")
}

/// The catalogue the suites decide against: what ships, and the one route
/// more an organisation's own catalogue would carry.
pub(crate) fn catalogue() -> Catalogue {
    let shipped = Catalogue::shipped().expect("the shipped catalogue loads");
    let mut reference = shipped.reference();
    reference.routes.push(coder());
    Catalogue::new(reference).expect("the route's name is its own")
}

/// The person's own capability opening their default browser, named after
/// it, before any site is added.
pub(crate) fn browser() -> Capability {
    Capability {
        id: name("browser"),
        source: hedwig_model::capability::Source::Browser {
            browser: hedwig_model::capability::Browser::Default,
            sites: Vec::new(),
        },
    }
}

pub(crate) fn capability(catalogue: &Catalogue, id: &str) -> Capability {
    Configuration::default()
        .capability(catalogue, &name(id))
        .expect("a shipped capability")
}

/// The terms the gate decides for `capability` on `remote` under
/// `configuration` alone, before any limit holds them.
pub(crate) fn decided_terms(
    catalogue: &Catalogue,
    configuration: &Configuration,
    capability: &Name,
    remote: &RemoteId,
) -> Option<Terms> {
    let state = State::default();
    hedwig_model::gate::World {
        catalogue,
        configuration,
        state: &state,
    }
    .terms(capability, remote)
    .map(|(_, terms)| terms)
}

pub(crate) fn grant(capability: &str, remotes: Granted) -> Grant {
    Grant {
        capability: name(capability),
        remotes,
    }
}

pub(crate) fn terms(activation: Activation, acknowledged: Exposure) -> Terms {
    Terms {
        activation,
        setup: Setup::Inspect,
        acknowledged,
        lends: Lends::none(),
    }
}

/// A configuration with each grant applied on request, acknowledging exactly
/// what its capability exposes.
pub(crate) fn granting(catalogue: &Catalogue, grants: &[(&str, Granted)]) -> Configuration {
    let mut configuration = Configuration::default();
    for (id, remotes) in grants {
        let exposure = capability(catalogue, id).exposure();
        configuration
            .apply(
                catalogue,
                Change::Grant {
                    grant: grant(id, remotes.clone()),
                    terms: terms(Activation::OnRequest, exposure),
                },
            )
            .expect("the grant is accepted");
    }
    configuration
}

/// How a request that names no key is decided by the person's statements
/// alone: no organisation says anything and no set is defined.
pub(crate) fn decided(
    standing: &BTreeMap<RuleScope, Mode>,
    connection: &BTreeMap<ConnectionScope, Mode>,
    remote: &RemoteId,
    capability: &Name,
    exposure: Exposure,
    operation: Operation,
) -> Resolved {
    let rules = Rules {
        person: standing,
        connection,
        start: &[],
        floors: &[],
    };
    let subject = Subject {
        remote,
        sets: Sets::NONE,
        capability,
        exposure,
        operation,
        used: None,
    };
    resolve(&rules, &subject)
}

pub(crate) const DESKTOP: Origin = Origin {
    process: 4200,
    logon: 0x3e7_0001,
    session: 2,
    integrity: Integrity::Medium,
};

/// A terminal over SSH into the workstation: session 0, another logon
/// session, High integrity.
pub(crate) const OVER_SSH: Origin = Origin {
    process: 5100,
    logon: 0x3e7_0002,
    session: 0,
    integrity: Integrity::High,
};

/// A trail under construction: numbers entries and advances the clock.
#[derive(Default)]
pub(crate) struct Trail {
    pub(crate) entries: Vec<Entry>,
    pub(crate) now: u64,
}

impl Trail {
    pub(crate) fn started() -> Trail {
        let mut trail = Trail::default();
        trail.push(Event::Started {
            version: "0.2.0".to_owned(),
            origin: DESKTOP,
            after: None,
        });
        trail
    }

    pub(crate) fn push(&mut self, event: Event) -> Seq {
        let seq = Seq(u64::try_from(self.entries.len()).expect("fits") + 1);
        self.entries.push(Entry {
            seq,
            at: Timestamp(1_790_000_000_000 + self.now),
            tick: Tick(self.now),
            event,
        });
        seq
    }

    pub(crate) fn wait(&mut self, milliseconds: u64) {
        self.now += milliseconds;
    }

    pub(crate) fn tick(&self) -> Tick {
        Tick(self.now)
    }

    pub(crate) fn attach(&mut self, kind: ClientKind, origin: Origin) -> ClientId {
        self.attach_to(kind, origin, Remotes::Every)
    }

    /// A client that watches only `attends`.
    pub(crate) fn attach_to(
        &mut self,
        kind: ClientKind,
        origin: Origin,
        attends: Remotes,
    ) -> ClientId {
        ClientId(self.push(Event::Attached {
            kind,
            origin,
            attends,
        }))
    }

    pub(crate) fn open(&mut self, remote: &RemoteId, platform: &str) -> ConnectionId {
        let connection = ConnectionId(self.push(Event::Opening {
            remote: remote.clone(),
            with: Vec::new(),
            opener: Opener::Grant,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        }));
        self.push(Event::Observed {
            connection,
            platform: name(platform),
        });
        connection
    }

    pub(crate) fn ask(
        &mut self,
        connection: ConnectionId,
        capability: &str,
        operation: Operation,
    ) -> RequestId {
        RequestId(self.push(Event::Asked {
            connection,
            capability: name(capability),
            operation,
            key: None,
        }))
    }

    pub(crate) fn state(&self) -> State {
        State::fold(&self.entries)
    }
}

/// `SplitMix64`: enough to vary inputs, and the same sequence every run.
pub(crate) struct Seeded(pub(crate) u64);

impl Seeded {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub(crate) fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).expect("fits")).expect("fits")
    }

    pub(crate) fn pick<'a, T>(&mut self, from: &'a [T]) -> &'a T {
        from.get(self.below(from.len())).expect("a non-empty slice")
    }
}

/// A generated value of the subset, nested at most `depth` deep.
pub(crate) fn random(seeded: &mut Seeded, depth: usize) -> Json {
    let alphabet = [
        "a",
        "\"",
        "\\",
        "\n",
        "\u{e9}",
        "\u{1d11e}",
        "\u{7}",
        " ",
        "/",
    ];
    let text = |seeded: &mut Seeded| -> String {
        (0..seeded.below(6))
            .map(|_| *seeded.pick(&alphabet))
            .collect()
    };
    match seeded.below(if depth == 0 { 4 } else { 6 }) {
        0 => Json::Null,
        1 => Json::Bool(seeded.next().is_multiple_of(2)),
        2 => match seeded.below(4) {
            0 => Json::Number(i128::from(seeded.next())),
            1 => Json::Number(i128::from(seeded.next().cast_signed())),
            2 => Json::Number(i128::from(u64::MAX)),
            _ => Json::Number(i128::from(u8::try_from(seeded.below(100)).unwrap())),
        },
        3 => Json::Text(text(seeded)),
        4 => Json::List(
            (0..seeded.below(4))
                .map(|_| random(seeded, depth - 1))
                .collect(),
        ),
        _ => Json::Map(
            (0..seeded.below(4))
                .map(|index| {
                    (
                        format!("{index}{}", text(seeded)),
                        random(seeded, depth - 1),
                    )
                })
                .collect(),
        ),
    }
}
