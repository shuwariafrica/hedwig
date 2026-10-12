//! What an organisation states about Hedwig, as one value the core is given.
//!
//! An organisation states limits, a starting point and whom to ask, each for
//! a machine or for a person. They are read where Windows keeps an
//! application's policy and given to [`Policy::read`] as lines in the
//! written form ([`crate::wire`]); nothing else builds a policy from what an
//! organisation wrote. The trail records every statement that arrives or is
//! withdrawn ([`Policy::changes`]), so the policy that held at any moment is
//! the fold of the trail, and the core reads the one it holds from
//! [`crate::trail::State::policy`]. The catalogue every decision reads is
//! what ships joined with what the policy defines
//! ([`crate::config::Catalogue::under`]).
//!
//! A limit is outside every choice: [`crate::scope::at_least`],
//! [`crate::scope::at_most`] and [`crate::scope::admitted`] hold what the
//! person and the starting point chose. A starting point is a source of
//! choices farther from the work than the person ([`crate::scope::choose`]):
//! anything the person says replaces it, and it is never copied into their
//! document.

use std::collections::{BTreeMap, BTreeSet};

use crate::capability::{Capability, Exposure};
use crate::config::{Activation, Denial, Grant, Reach, Reference};
use crate::platform::Platform;
use crate::policy::{Attended, Mode, RuleScope, Selector};
use crate::remote::{RemoteId, Remotes, Route, Set, Sets};
use crate::scope::{Audience, Holder};
use crate::setting::{
    Autostart, Cadence, CapScope, Diagnostics, Keep, Keepalive, Longest, Returns, Routes, Threshold,
};
use crate::text::{Name, Words};
use crate::trail::Event;

/// The most statements read from one place. Invariant: a safety bound on
/// what the core holds and records; a line past it is not read.
pub const STATEMENTS: usize = 1024;

/// Which part of an organisation's policy a line belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    /// Limits: every one that covers holds.
    Limits,
    /// The starting point: what the person has not said, said for them.
    Start,
    /// Whom the person asks about what the limits hold, in the
    /// organisation's own words.
    Ask,
}

/// Where a line was read from: whom it is stated for, and which part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Place {
    pub audience: Audience,
    pub part: Part,
}

/// Which grants a limit on their terms covers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantScope {
    pub capability: Selector<Name>,
    pub remotes: Remotes,
}

impl GrantScope {
    pub fn covers(&self, capability: &Name, remote: &RemoteId, sets: &Sets<'_>) -> bool {
        self.capability.covers(capability) && self.remotes.covers(remote, sets)
    }
}

/// A bound the organisation holds. Each one that covers holds, however
/// widely it is stated, and none loosens anything.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Limit {
    /// No request the scope covers is decided less strictly than `mode`.
    Floor { scope: RuleScope, mode: Mode },
    /// No grant the scope covers connects more readily than `most`.
    Activation { scope: GrantScope, most: Activation },
    /// No grant the scope covers writes a remote tool's configuration.
    InspectOnly(GrantScope),
    /// No allowance for what the scope covers lasts longer than `longest`.
    Cap { scope: CapScope, longest: Longest },
    /// A capability that exposes any of `exposure` serves these remotes
    /// nothing, whoever defined it and whenever.
    Withhold {
        exposure: Exposure,
        remotes: Remotes,
    },
    /// A capability that exposes any of `exposure` serves only these
    /// remotes. Several confinements of one member all hold.
    Confine {
        exposure: Exposure,
        remotes: Remotes,
    },
    /// A denial, which beats every grant.
    Deny(Denial),
    /// The trail keeps at least this many days of activity.
    KeepAtLeast(Keep),
    /// The trail keeps at most this many days of activity.
    KeepAtMost(Keep),
    /// The core writes no more about what went wrong than this.
    DiagnosticsAtMost(Diagnostics),
}

/// What the organisation starts a person with. Each is a choice the person's
/// own statements replace, in the words of the change that makes it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Start {
    Define(Capability),
    DefinePlatform(Platform),
    DefineRoute(Route),
    DefineSet(Set),
    /// A grant with what only the organisation can say of it. The exposure
    /// it names and consent to write are the person's to give
    /// ([`crate::config::Change::Accept`]): a capability that exposes only
    /// key use serves at once, and any other once the person accepts it.
    Grant {
        grant: Grant,
        activation: Activation,
    },
    /// A rule, never one that serves with nobody there; one that decides
    /// less strictly than what ships is not in effect.
    Rule {
        scope: RuleScope,
        mode: Attended,
    },
    Burst {
        remotes: Remotes,
        threshold: Threshold,
    },
    /// How a channel's client notices a dead link: what an organisation that
    /// knows its network's idle timeouts starts its people with.
    Keepalive {
        remotes: Remotes,
        keepalive: Keepalive,
    },
    /// The waits before a lost channel is opened again: what an organisation
    /// starts its people with to spare a bastion it runs.
    Returns {
        remotes: Remotes,
        returns: Returns,
    },
    /// How often a route's platform is asked which remotes run, to spare a
    /// platform the organisation runs.
    Cadence {
        routes: Routes,
        cadence: Cadence,
    },
    Autostart(Autostart),
    Icon(Autostart),
    Keep(Keep),
    Diagnostics(Diagnostics),
}

/// One statement, as the trail records it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Statement {
    Limit(Limit),
    Start(Start),
    Ask(Words),
}

impl Statement {
    /// The part of a policy this statement is read from.
    pub fn part(&self) -> Part {
        match self {
            Statement::Limit(_) => Part::Limits,
            Statement::Start(_) => Part::Start,
            Statement::Ask(_) => Part::Ask,
        }
    }
}

/// The lines of one place that could not be read, by their position in
/// what was read, and the account of the first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unread {
    pub lines: Vec<u32>,
    pub account: String,
}

/// What of one place could not be read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Misread {
    pub place: Place,
    pub unread: Unread,
}

/// A limit that holds a value, and who holds it: the organisation for an
/// audience, or the person over what they can loosen in one gesture, whose
/// cap is written as the organisation's is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Holding {
    pub holder: Holder,
    pub limit: Limit,
}

/// Everything the organisation states, for this machine and for this person.
///
/// A limit line that cannot be read holds everything it could have held:
/// nothing is served under that audience's limits until it is read. A
/// starting or asking line that cannot be read says nothing. Either is said
/// once. Neither stops the person pausing, denying or narrowing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    statements: BTreeSet<(Audience, Statement)>,
    unread: BTreeMap<Place, Unread>,
    /// The floors and starting rules in the form the resolution of a mode
    /// reads, kept in step with `statements`.
    floors: Vec<(Audience, RuleScope, Mode)>,
    rules: Vec<(Audience, RuleScope, Attended)>,
}

impl Policy {
    /// The policy these lines state. It refuses nothing: what cannot be read
    /// is kept as that, and the order of the lines changes nothing.
    pub fn read<'a>(lines: impl IntoIterator<Item = (Place, &'a str)>) -> Policy {
        let mut policy = Policy::default();
        let mut counted: BTreeMap<Place, u32> = BTreeMap::new();
        for (place, line) in lines {
            let at = counted.entry(place).or_default();
            let position = *at;
            *at = at.saturating_add(1);
            let read = if usize::try_from(position).map_or(true, |at| at >= STATEMENTS) {
                Err(format!("more than {STATEMENTS} lines"))
            } else {
                statement(place.part, line)
            };
            match read {
                Ok(statement) => {
                    policy.statements.insert((place.audience, statement));
                }
                Err(account) => {
                    let unread = policy.unread.entry(place).or_insert_with(|| Unread {
                        lines: Vec::new(),
                        account,
                    });
                    unread.lines.push(position);
                }
            }
        }
        policy.settle();
        policy
    }

    /// The policy whose statements and unread places were these, as a
    /// compacted trail carries it.
    pub(crate) fn of_parts(
        statements: BTreeSet<(Audience, Statement)>,
        unread: BTreeMap<Place, Unread>,
    ) -> Policy {
        let mut policy = Policy {
            statements,
            unread,
            ..Policy::default()
        };
        policy.settle();
        policy
    }

    /// The statements and the unread places, as a compacted trail carries
    /// them.
    pub(crate) fn parts(&self) -> (&BTreeSet<(Audience, Statement)>, &BTreeMap<Place, Unread>) {
        (&self.statements, &self.unread)
    }

    /// Every statement read, with whom it is stated for.
    pub fn statements(&self) -> impl Iterator<Item = (Audience, &Statement)> + Clone {
        self.statements
            .iter()
            .map(|(audience, statement)| (*audience, statement))
    }

    /// Every limit, with whom it is stated for.
    pub fn limits(&self) -> impl Iterator<Item = (Audience, &Limit)> + Clone {
        self.statements()
            .filter_map(|(audience, statement)| match statement {
                Statement::Limit(limit) => Some((audience, limit)),
                _ => None,
            })
    }

    /// Every starting statement, with whom it is stated for.
    pub fn start(&self) -> impl Iterator<Item = (Audience, &Start)> + Clone {
        self.statements()
            .filter_map(|(audience, statement)| match statement {
                Statement::Start(start) => Some((audience, start)),
                _ => None,
            })
    }

    /// Whom to ask about the limits stated for `audience`.
    pub fn ask(&self, audience: Audience) -> impl Iterator<Item = &Words> {
        self.statements()
            .filter(move |(stated_for, _)| *stated_for == audience)
            .filter_map(|(_, statement)| match statement {
                Statement::Ask(words) => Some(words),
                _ => None,
            })
    }

    /// What could not be read, by place.
    pub fn unread(&self) -> impl Iterator<Item = (Place, &Unread)> {
        self.unread.iter().map(|(place, unread)| (*place, unread))
    }

    /// Every place with lines that could not be read, as a surface shows it.
    pub fn misread(&self) -> Vec<Misread> {
        self.unread
            .iter()
            .map(|(place, unread)| Misread {
                place: *place,
                unread: unread.clone(),
            })
            .collect()
    }

    /// The audience whose limits could not all be read, the machine first:
    /// under it nothing is served.
    pub fn unreadable(&self) -> Option<Audience> {
        self.unread
            .keys()
            .find(|place| place.part == Part::Limits)
            .map(|place| place.audience)
    }

    /// The floors on how requests are decided.
    pub fn floors(&self) -> &[(Audience, RuleScope, Mode)] {
        &self.floors
    }

    /// The starting rules.
    pub fn rules(&self) -> &[(Audience, RuleScope, Attended)] {
        &self.rules
    }

    /// What the starting point stated for `audience` defines.
    pub fn reference(&self, audience: Audience) -> Reference {
        let mut reference = Reference::default();
        for (stated_for, start) in self.start() {
            if stated_for != audience {
                continue;
            }
            match start {
                Start::Define(capability) => reference.capabilities.push(capability.clone()),
                Start::DefinePlatform(platform) => reference.platforms.push(platform.clone()),
                Start::DefineRoute(route) => reference.routes.push(route.clone()),
                Start::DefineSet(set) => reference.sets.push(set.clone()),
                Start::Grant { .. }
                | Start::Rule { .. }
                | Start::Burst { .. }
                | Start::Keepalive { .. }
                | Start::Returns { .. }
                | Start::Cadence { .. }
                | Start::Autostart(_)
                | Start::Icon(_)
                | Start::Keep(_)
                | Start::Diagnostics(_) => {}
            }
        }
        reference
    }

    /// Whether replacing this policy with `next` can let more through: a
    /// limit withdrawn or read where it could not be, or a starting
    /// statement arrived.
    pub fn widens_to(&self, next: &Policy) -> Reach {
        let limits = |policy: &Policy| -> BTreeSet<(Audience, Limit)> {
            policy
                .limits()
                .map(|(audience, limit)| (audience, limit.clone()))
                .collect()
        };
        let start = |policy: &Policy| -> BTreeSet<(Audience, Start)> {
            policy
                .start()
                .map(|(audience, start)| (audience, start.clone()))
                .collect()
        };
        let unread = |policy: &Policy| -> BTreeSet<Audience> {
            policy
                .unread
                .keys()
                .filter(|place| place.part == Part::Limits)
                .map(|place| place.audience)
                .collect()
        };
        let narrower = limits(self).is_subset(&limits(next))
            && start(next).is_subset(&start(self))
            && unread(self).is_subset(&unread(next));
        if narrower {
            Reach::NoWider
        } else {
            Reach::Wider
        }
    }

    /// The entries that record the step from this policy to `next`: each
    /// statement withdrawn, each that arrived, and each place whose unread
    /// lines changed. Folded after this policy, they give `next`.
    pub fn changes(&self, next: &Policy) -> Vec<Event> {
        let withdrawn =
            self.statements
                .difference(&next.statements)
                .map(|(audience, statement)| Event::Unstated {
                    audience: *audience,
                    statement: statement.clone(),
                });
        let arrived = next
            .statements
            .difference(&self.statements)
            .map(|(audience, statement)| Event::Stated {
                audience: *audience,
                statement: statement.clone(),
            });
        let places: BTreeSet<&Place> = self.unread.keys().chain(next.unread.keys()).collect();
        let misread = places
            .into_iter()
            .filter(|place| self.unread.get(place) != next.unread.get(place))
            .map(|place| Event::Misread {
                place: *place,
                unread: next.unread.get(place).cloned(),
            });
        withdrawn.chain(arrived).chain(misread).collect()
    }

    pub(crate) fn stated(&mut self, audience: Audience, statement: Statement) {
        self.statements.insert((audience, statement));
        self.settle();
    }

    pub(crate) fn unstated(&mut self, audience: Audience, statement: &Statement) {
        self.statements.remove(&(audience, statement.clone()));
        self.settle();
    }

    pub(crate) fn note_unread(&mut self, place: Place, unread: Option<Unread>) {
        match unread {
            Some(unread) => self.unread.insert(place, unread),
            None => self.unread.remove(&place),
        };
    }

    fn settle(&mut self) {
        let limits = self.limits();
        self.floors = limits
            .filter_map(|(audience, limit)| match limit {
                Limit::Floor { scope, mode } => Some((audience, scope.clone(), *mode)),
                _ => None,
            })
            .collect();
        self.rules = self
            .start()
            .filter_map(|(audience, start)| match start {
                Start::Rule { scope, mode } => Some((audience, scope.clone(), *mode)),
                _ => None,
            })
            .collect();
    }
}

/// One line of `part`, or the account of why it could not be read.
fn statement(part: Part, line: &str) -> Result<Statement, String> {
    let account = |error: &dyn std::error::Error| error.to_string();
    match part {
        Part::Limits => crate::wire::read(line)
            .map(Statement::Limit)
            .map_err(|error| account(&error)),
        Part::Start => crate::wire::read(line)
            .map(Statement::Start)
            .map_err(|error| account(&error)),
        Part::Ask => Words::try_from(line)
            .map(Statement::Ask)
            .map_err(|error| account(&error)),
    }
}
