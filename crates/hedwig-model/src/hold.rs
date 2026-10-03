//! When the core holds a channel, and when it opens one again.
//!
//! A channel is wanted while the person asked for it in this run and has not
//! disconnected it, or while a grant's activation holds it: continuously, or
//! while the route's platform reports the remote running. A pause, the person's
//! disconnect and a remote the platform reported stopped each hold it down
//! whatever wants it. A channel that ends comes back as its ending says
//! ([`ChannelEnd::back`](crate::trail::ChannelEnd::back)): after a wait that
//! doubles while attempts keep failing, at once, when something wants it again,
//! or only when the person connects.

use std::collections::BTreeSet;

use crate::capability::{Exposure, Lends};
use crate::gate::World;
use crate::organisation::Start;
use crate::remote::{Listing, RemoteId, Remotes};
use crate::scope::{Audience, Tier, choose};
use crate::setting::{Cadence, Keepalive, Returns, Routes, Said, Settled, Threshold};
use crate::text::Name;
use crate::trail::{Back, Opener, Returning, Tick};

/// What opening a channel now asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub remote: RemoteId,
    /// What the person added for their connection alone, what they named it
    /// exposes, and the devices it lends.
    pub with: Vec<Name>,
    pub acknowledged: Exposure,
    pub lends: Lends,
    pub opener: Opener,
}

/// Whether a channel to one remote is opened now, later, or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    Now(Opener),
    /// Its wait ends then.
    At(Tick),
    /// Nothing wants it, one is live, or only the person can bring it back.
    Not,
}

impl World<'_> {
    /// The capabilities a channel to `remote` would carry now: what its
    /// grants reach, and what the person added to the connection they asked
    /// for.
    pub fn carries(&self, remote: &RemoteId) -> BTreeSet<Name> {
        let link = self.state.connection(remote).map(|(_, link)| link);
        let mut held: BTreeSet<Name> = self
            .reaching(remote, link)
            .into_iter()
            .map(|reached| reached.capability.id)
            .collect();
        held.extend(self.state.asked(remote).into_iter().flatten().cloned());
        held
    }

    /// Whether anything wants a channel held to `remote` now, and so why a
    /// new one would be opened: the person's own request, or a grant.
    pub fn wants(&self, remote: &RemoteId) -> Option<Opener> {
        let sets = self.sets();
        if self.state.withdrawn().is_some()
            || self.state.paused(remote, &sets)
            || self.state.released(remote)
            || self.carries(remote).is_empty()
        {
            return None;
        }
        if self.state.asked(remote).is_some() {
            Some(Opener::Again)
        } else if self.wanted(remote) {
            Some(Opener::Grant)
        } else {
            None
        }
    }

    /// Whether a channel to `remote` is opened at `now`, and if not, when.
    pub fn attempt(&self, remote: &RemoteId, now: Tick) -> Attempt {
        let Some(opener) = self.wants(remote) else {
            return Attempt::Not;
        };
        if self.state.asleep() {
            return Attempt::Not;
        }
        // A remote its platform reports stopped is not tried again until it
        // runs; the person's own connect is theirs to make.
        if self.state.connection(remote).is_some() || self.state.gone(remote) {
            return Attempt::Not;
        }
        if self
            .state
            .ended(remote)
            .is_some_and(|(end, _)| end.back() == Back::ByThePerson)
        {
            return Attempt::Not;
        }
        let Some(returning) = self.state.returning(remote) else {
            return Attempt::Now(opener);
        };
        match self.back_at(remote, returning) {
            Some(at) if at > now => Attempt::At(at),
            _ => Attempt::Now(Opener::Again),
        }
    }

    /// When a channel to `remote` that ended as `returning` says is due to
    /// be opened again: its wait after the last ending, or `None` where it
    /// is opened at once.
    pub(crate) fn back_at(&self, remote: &RemoteId, returning: Returning) -> Option<Tick> {
        let wait = self.returns(remote).value.wait(returning.failed);
        (!returning.hurried).then(|| {
            Tick(
                returning
                    .since
                    .0
                    .saturating_add(u64::from(wait).saturating_mul(1000)),
            )
        })
    }

    /// Every remote something could hold a channel to: those the core knows,
    /// those the person asked for, and every one a named set names.
    pub fn holdable(&self) -> BTreeSet<RemoteId> {
        let mut remotes = self.known();
        remotes.extend(self.state.asked_for().cloned());
        remotes.extend(self.sets().ones().cloned());
        remotes
    }

    /// The channels to open at `now`, and the earliest later tick at which
    /// another will be due.
    pub fn due(&self, now: Tick) -> (Vec<Open>, Option<Tick>) {
        let mut open = Vec::new();
        let mut next: Option<Tick> = None;
        for remote in self.holdable() {
            match self.attempt(&remote, now) {
                Attempt::Now(opener) => open.push(Open {
                    with: self
                        .state
                        .asked(&remote)
                        .into_iter()
                        .flatten()
                        .cloned()
                        .collect(),
                    acknowledged: self.state.asked_terms(&remote).0,
                    lends: self.state.asked_terms(&remote).1,
                    remote,
                    opener,
                }),
                Attempt::At(at) => next = Some(next.map_or(at, |next| next.min(at))),
                Attempt::Not => {}
            }
        }
        (open, next)
    }

    /// The earliest tick after `now` at which something changes by time
    /// alone: a channel's wait ends, an allowance lapses, or a request leaves
    /// a burst's window.
    pub fn deadline(&self, now: Tick) -> Option<Tick> {
        let (_, returns) = self.due(now);
        let lapses = self
            .state
            .allowances
            .values()
            .filter(|until| **until > now)
            .min()
            .copied();
        let bursts = self
            .state
            .recent
            .iter()
            .filter_map(|(remote, recent)| {
                let Threshold::At(burst) = self.threshold(remote).value else {
                    return None;
                };
                let window = u64::from(burst.seconds.get()) * 1000;
                recent
                    .iter()
                    .map(|tick| Tick(tick.0.saturating_add(window)))
                    .filter(|end| *end > now)
                    .min()
            })
            .min();
        [returns, lapses, bursts].into_iter().flatten().min()
    }

    /// The routes whose platform is asked which remotes run: those that list,
    /// where a grant follows its remotes' lives.
    pub fn listings(&self) -> BTreeSet<Name> {
        let sets = self.sets();
        let person = self
            .configuration
            .grants()
            .filter(|(_, terms)| terms.activation == crate::config::Activation::WhileRunning)
            .map(|(grant, _)| Remotes::from(grant.remotes.clone()));
        let start = self
            .policy()
            .start()
            .filter_map(|(_, start)| match start {
                Start::Grant { grant, activation }
                    if *activation == crate::config::Activation::WhileRunning =>
                {
                    Some(Remotes::from(grant.remotes.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let routes: BTreeSet<Name> = person
            .chain(start)
            .flat_map(|remotes| {
                remotes
                    .routes(&sets)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect();
        routes
            .into_iter()
            .filter(|route| {
                self.configuration
                    .route(self.catalogue, route)
                    .is_ok_and(|route| matches!(route.listing, Listing::Lists(_)))
            })
            .collect()
    }

    /// How a channel's client to `remote` notices its link has died.
    pub fn keepalive(&self, remote: &RemoteId) -> Settled<Keepalive, Remotes> {
        let stated = self
            .configuration
            .keepalives()
            .iter()
            .map(|(remotes, keepalive)| (remotes, *keepalive));
        let start = |audience: Audience| {
            self.policy()
                .start()
                .filter_map(move |(stated_for, start)| match start {
                    Start::Keepalive { remotes, keepalive } if stated_for == audience => {
                        Some((remotes, *keepalive))
                    }
                    _ => None,
                })
        };
        self.chosen(
            remote,
            stated,
            start(Audience::Person),
            start(Audience::Machine),
            Keepalive::SHIPS,
        )
    }

    /// The waits before a lost channel to `remote` is opened again.
    pub fn returns(&self, remote: &RemoteId) -> Settled<Returns, Remotes> {
        let stated = self
            .configuration
            .returns()
            .iter()
            .map(|(remotes, returns)| (remotes, *returns));
        let start = |audience: Audience| {
            self.policy()
                .start()
                .filter_map(move |(stated_for, start)| match start {
                    Start::Returns { remotes, returns } if stated_for == audience => {
                        Some((remotes, *returns))
                    }
                    _ => None,
                })
        };
        self.chosen(
            remote,
            stated,
            start(Audience::Person),
            start(Audience::Machine),
            Returns::SHIPS,
        )
    }

    /// How often `route`'s platform is asked which remotes run.
    pub fn cadence(&self, route: &Name) -> Settled<Cadence, Routes> {
        let covers = |routes: &Routes| routes.covers(route);
        let stated = self
            .configuration
            .cadences()
            .iter()
            .filter(|(routes, _)| covers(routes))
            .map(|(routes, cadence)| (routes, *cadence));
        let start = |audience: Audience| {
            self.policy()
                .start()
                .filter_map(move |(stated_for, start)| match start {
                    Start::Cadence { routes, cadence }
                        if stated_for == audience && covers(routes) =>
                    {
                        Some((routes, *cadence))
                    }
                    _ => None,
                })
        };
        match choose(&stated, &start(Audience::Person), &start(Audience::Machine)) {
            Some((Tier::Start(audience), scope, value)) => Settled {
                value,
                said: Said::Start {
                    audience,
                    scope: scope.clone(),
                },
            },
            Some((_, scope, value)) => Settled {
                value,
                said: Said::Person(scope.clone()),
            },
            None => Settled {
                value: Cadence::SHIPS,
                said: Said::Ships,
            },
        }
    }
}
