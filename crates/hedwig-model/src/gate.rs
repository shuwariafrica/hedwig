//! The one place a decision is made.
//!
//! [`World::permit`] answers every control request, [`World::decide`] every
//! request a remote makes, and [`World::rows`] and [`World::attention`] build
//! what surfaces show by calling those same two, so an act a surface offers is
//! an act the core accepts. Every setting is resolved here too, by the one
//! function its kind has ([`crate::scope`]).

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use crate::beyond::Beyond;
use crate::capability::{
    Capability, Dialect, Exposure, Form, Holds, Lends, Operation, Setup, Source, Spot,
};
use crate::config::{
    Accepted, Activation, Catalogue, Change, Configuration, Denial, Grant, Reach, Terms,
    acknowledged, lendable,
};
use crate::credential::Place;
use crate::install::Starts;
use crate::organisation::{Holding, Limit, Policy, Start};
use crate::platform::Platform;
use crate::policy::{
    Basis, ConnectionScope, KeyName, Keys, Mode, Resolved, Rules, Selector, Subject, Used,
    opens_more, resolve, resolve_opening,
};
use crate::protocol::{
    Act, Answer, Attached, Attention, CarriedOn, Contact, Decides, Decision, Differs, Found,
    Loudness, Needs, Offered, Offering, PROTOCOL, RemoteSettings, Request, RouteSettings, Row,
    Settings, Standing, Status, Through, Trial, Tried, WindowsStarts, Withdrawal, Workstation,
    WorkstationSettings, Would, Written,
};
use crate::refusal::{Refusal, Whereabouts};
use crate::remote::{Granted, RemoteId, Remotes, Sets};
use crate::scope::{Audience, Holder, Strict, Tier, admitted, at_least, at_most, choose};
use crate::setting::{
    Autostart, Bounded, CapScope, Condition, Diagnostics, FullScreen, Keep, Lengths, Longest, Said,
    Settled, Span, Threshold, Volume, Workstation as Here,
};
use crate::site::{self, Opening, Site};
use crate::text::{KeyId, Name};
use crate::trail::{
    Ask, Asks, Back, ChannelEnd, ClientId, ClientKind, ConnectionId, Finding, Health, Item, Link,
    NOTICE_WINDOW, NOTICES_AT_ONCE, Opener, Outcome, Peer, Phase, Presence, Readiness, RequestId,
    Seq, State, Tick, Timestamp, Write,
};

/// Whether the workstation's own credential helper may ask the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Interaction {
    /// The helper is asked with interaction off (`credential.interactive`
    /// false): it answers from what it holds, or not at all.
    Off,
    /// The person allowed the request where a sign-in's window would show:
    /// the helper may ask them, as it asks for their own `git`.
    Allowed,
}

/// What the core does with a remote's request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Serve(Outcome),
    /// Wait for the person; the basis says which statement asked for that.
    Hold(Basis),
    Refuse(Refusal),
}

/// A way a connection reaches the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Door {
    /// The control pipe. Windows has already admitted the client, by the
    /// pipe's own access list and label.
    Control,
    /// The workstation end of a forward of this connection's channel: a
    /// loopback port, which has no access list.
    Forward(ConnectionId),
    /// The control pipe, for a client that asks the person on a channel's
    /// behalf: only a process in a live channel's job, since what it asks is
    /// put to the person as that remote's.
    Prompt,
}

/// Whom an admitted connection comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// A process of the person's own, in no live channel.
    Person,
    /// A process of the channel the core holds to this remote.
    Remote(RemoteId),
}

/// The longest an allowance for one request may last, and whose cap it is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Capped {
    pub longest: Longest,
    pub holder: Holder,
    pub scope: CapScope,
}

/// A capability a connection's remote holds, as readiness asks about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carried {
    pub capability: Name,
    /// Every form its far end can take, most private first.
    pub forms: Vec<Form>,
    pub setup: Setup,
    /// What the grant consents to have written on the remote for it: none
    /// unless the grant's setup is [`Setup::Write`]. The keys' own writes are
    /// added where the workstation's keys are known.
    pub writes: Vec<Write>,
}

/// What a remote holds of a capability, and on which terms.
pub(crate) struct Reached {
    pub(crate) capability: Capability,
    activation: Activation,
    setup: Setup,
    /// The setup the grant states, before any limit holds it.
    stated: Setup,
    /// The grant's terms as the limits hold them; `None` for a capability
    /// added to a connection alone.
    terms: Option<Terms>,
    /// The devices lent: the grant's, or those the person lent the
    /// connection.
    pub(crate) lends: Lends,
    /// The limits that hold those terms.
    holds: Vec<Holding>,
    /// The organisation's limit that keeps the grant from writing, where
    /// one does.
    writes: Option<Refusal>,
}

impl Reached {
    /// The form `platform` carries this in, or why it carries none. A form
    /// that would need to write, where a limit keeps the grant from it, is
    /// the limit's to explain; so is one that limit leaves more of the remote
    /// reaching than the grant's own would, since a limit only ever holds.
    fn carrier(&self, platform: &Platform) -> Result<Form, Refusal> {
        let form = self
            .capability
            .carrier(platform, self.setup)
            .map_err(|refusal| match (refusal, &self.writes) {
                (Refusal::NeedsRemoteSetup { .. }, Some(held)) => held.clone(),
                (refusal, _) => refusal,
            })?;
        match &self.writes {
            Some(held)
                if self.capability.reach(platform.sockets, self.stated) < Some(form.whom()) =>
            {
                Err(held.clone())
            }
            _ => Ok(form),
        }
    }
}

/// `plan` with every capability whose form takes a spot on the remote another
/// capability's form takes too refused, each naming one other: the remote's
/// SSH server binds a second forward at a spot for neither, and a second
/// write overwrites the first, so carrying either would be a choice nobody
/// made.
fn apart(mut plan: BTreeMap<Name, Result<Form, Refusal>>) -> BTreeMap<Name, Result<Form, Refusal>> {
    let mut taken: BTreeMap<Spot, Vec<Name>> = BTreeMap::new();
    for (id, form) in &plan {
        for spot in form.iter().flat_map(Form::spots) {
            taken.entry(spot).or_default().push(id.clone());
        }
    }
    for (spot, ids) in taken {
        for id in &ids {
            if let Some(with) = ids.iter().find(|other| *other != id) {
                let shared = Refusal::Shared {
                    capability: id.clone(),
                    with: with.clone(),
                    spot: spot.clone(),
                };
                plan.insert(id.clone(), Err(shared));
            }
        }
    }
    plan
}

fn held(audience: Audience, limit: &Limit) -> Refusal {
    Refusal::Held {
        audience,
        limit: Box::new(limit.clone()),
    }
}

/// Whether statements about these keys can cover one request.
fn meet(keys: &Keys, other: &Keys) -> bool {
    !matches!((keys, other), (Keys::Only(key), Keys::Only(against)) if key != against)
}

/// Each thing that differs between `before` and `after`, matched by `same`.
fn differs<T: PartialEq>(
    before: Vec<T>,
    after: Vec<T>,
    same: impl Fn(&T, &T) -> bool,
) -> Vec<Differs<T>> {
    let mut after: Vec<Option<T>> = after.into_iter().map(Some).collect();
    let mut found = Vec::new();
    for old in before {
        let matched = after
            .iter_mut()
            .find(|new| new.as_ref().is_some_and(|new| same(&old, new)))
            .and_then(Option::take);
        if matched.as_ref() != Some(&old) {
            found.push(Differs {
                before: Some(old),
                after: matched,
            });
        }
    }
    found.extend(after.into_iter().flatten().map(|new| Differs {
        before: None,
        after: Some(new),
    }));
    found
}

/// How soon a surface with this presence says what it is told, where it says
/// it at all: a present one now; one behind a full-screen application once
/// Windows lets its notification through.
fn says_now(presence: Presence) -> Option<u8> {
    match presence {
        Presence::Present => Some(1),
        Presence::CardOnly => Some(0),
        Presence::Engaged | Presence::Away => None,
    }
}

/// What is defined outside the person's document, the person's
/// configuration and the folded trail: everything a decision reads.
#[derive(Debug, Clone, Copy)]
pub struct World<'a> {
    pub catalogue: &'a Catalogue,
    pub configuration: &'a Configuration,
    pub state: &'a State,
}

impl World<'_> {
    /// Decides a remote's request, through `connection`, that `capability`'s
    /// browser open `asked`: refused as [`World::decide`] refuses any request,
    /// then where it is not a URL the browser opens or no site of the
    /// capability's admits it, and otherwise decided at its mode. The opening
    /// is what serving it carries.
    pub fn open(
        &self,
        connection: ConnectionId,
        capability: &Name,
        asked: &str,
        now: Tick,
    ) -> (Verdict, Option<Opening>) {
        let verdict = self.decide(connection, capability, Operation::Open, None, now);
        if matches!(verdict, Verdict::Refuse(_)) {
            return (verdict, None);
        }
        let url = match site::url(asked) {
            Ok(url) => url,
            Err(why) => {
                let capability = capability.clone();
                return (
                    Verdict::Refuse(Refusal::Unopenable { capability, why }),
                    None,
                );
            }
        };
        let sites = match self.configuration.capability(self.catalogue, capability) {
            Ok(Capability {
                source: Source::Browser { sites, .. },
                ..
            }) => sites,
            _ => Vec::new(),
        };
        if !sites.iter().any(|site| site.admits(&url)) {
            let refusal = Refusal::UnlistedSite {
                capability: capability.clone(),
                site: Site::of(&url),
            };
            return (Verdict::Refuse(refusal), None);
        }
        (verdict, Some(Opening::of(url)))
    }

    /// Decides a remote's request, through `connection`, that `capability`
    /// release the workstation's credential for `place`: refused as
    /// [`World::decide`] refuses the opening that carries it, then where it
    /// is not for an `https` or `http` site, where the site is on plain
    /// `http` beyond the remote's loopback, or where none of the capability's
    /// sites admits it - each naming the narrowest site that would - and
    /// otherwise decided at the opening's mode, which is `Confirm` unless the
    /// person says otherwise.
    pub fn credential(
        &self,
        connection: ConnectionId,
        capability: &Name,
        place: &Place,
        now: Tick,
    ) -> Verdict {
        let verdict = self.decide(connection, capability, Operation::Connect, None, now);
        if matches!(verdict, Verdict::Refuse(_)) {
            return verdict;
        }
        let capability = capability.clone();
        let url = match place {
            Place::Site(url) => url,
            Place::Other(protocol) => {
                let protocol = protocol.clone();
                return Verdict::Refuse(Refusal::NotWeb {
                    capability,
                    protocol,
                });
            }
        };
        let site = Site::of(url);
        if url.cleartext() {
            return Verdict::Refuse(Refusal::Cleartext { capability, site });
        }
        let sites = match self.configuration.capability(self.catalogue, &capability) {
            Ok(Capability {
                source: Source::Credentials { sites, .. },
                ..
            }) => sites,
            _ => Vec::new(),
        };
        if !sites.iter().any(|listed| listed.admits(url)) {
            return Verdict::Refuse(Refusal::UnlistedCredential { capability, site });
        }
        verdict
    }

    /// Whether the workstation's own credential helper may ask the person to
    /// sign in, for a request that ended with `outcome`: only where the
    /// person allowed it themselves, at a client in the session the core
    /// runs in, which is where a sign-in's window is shown. Anywhere else
    /// they are not there to see it, and the helper is asked with
    /// interaction off.
    pub fn interaction(&self, outcome: &Outcome) -> Interaction {
        let Outcome::Allowed(client) = outcome else {
            return Interaction::Off;
        };
        let core = self
            .state
            .started
            .as_ref()
            .map(|(_, _, _, origin)| origin.session);
        let at = self
            .state
            .surfaces
            .get(client)
            .map(|surface| surface.origin.session);
        if at.is_some() && at == core {
            Interaction::Allowed
        } else {
            Interaction::Off
        }
    }

    /// Whether a notice a remote's job posts through `connection` reaches the
    /// person: refused where [`World::decide`] refuses any request before its
    /// mode - the connection or capability unknown, the capability not
    /// granted, denied, withheld or paused - and where that remote has passed
    /// on [`NOTICES_AT_ONCE`] notices within the last minute. Nothing else is
    /// read: a notice decides nothing, so it has no mode and is never held,
    /// and the person reads it whenever they look.
    ///
    /// # Errors
    ///
    /// The refusal, [`Refusal::Hushed`] for one that comes too fast.
    pub fn notice(
        &self,
        connection: ConnectionId,
        capability: &Name,
        now: Tick,
    ) -> Result<(), Refusal> {
        let link = self
            .state
            .link(connection)
            .ok_or(Refusal::UnknownConnection(connection))?;
        let granted = self.granted(link, capability)?;
        if granted.dialect() != Dialect::Notice {
            return Err(Refusal::OperationNotInDialect {
                capability: granted.id,
                operation: Operation::Connect,
            });
        }
        if self.state.paused(&link.remote, &self.sets()) {
            return Err(Refusal::Paused);
        }
        let recent = self.state.notices.get(&link.remote).map_or(0, |notices| {
            notices
                .recent
                .iter()
                .filter(|tick| tick.0.saturating_add(NOTICE_WINDOW) > now.0)
                .count()
        });
        if recent >= NOTICES_AT_ONCE {
            return Err(Refusal::Hushed {
                capability: capability.clone(),
            });
        }
        Ok(())
    }

    /// Decides one request arriving through `connection`. `key` is the key
    /// the dialect's parser read from it, where there is one.
    ///
    /// Anything unknown, ungranted, denied or paused is refused before a mode
    /// is looked at. A request that would be shown or put to the person is
    /// refused when no surface that watches its remote reaches them.
    pub fn decide(
        &self,
        connection: ConnectionId,
        capability: &Name,
        operation: Operation,
        key: Option<&KeyId>,
        now: Tick,
    ) -> Verdict {
        let Some(link) = self.state.link(connection) else {
            return Verdict::Refuse(Refusal::UnknownConnection(connection));
        };
        let granted = match self.granted(link, capability) {
            Ok(granted) if granted.dialect().operations().contains(&operation) => granted,
            Ok(granted) => {
                return Verdict::Refuse(Refusal::OperationNotInDialect {
                    capability: granted.id,
                    operation,
                });
            }
            Err(refusal) => return Verdict::Refuse(refusal),
        };
        let sets = self.sets();
        if self.state.paused(&link.remote, &sets) {
            return Verdict::Refuse(Refusal::Paused);
        }
        if let Source::Serial { port, .. } = &granted.source
            && let Some(by) = self.state.holder(port)
        {
            return Verdict::Refuse(Refusal::PortHeld {
                capability: granted.id,
                by,
            });
        }
        let resolved = self.resolved(&link.rules, &link.remote, &granted, operation, key);
        let card = self.full_screen(&link.remote).value;
        let shown = self.state.unreached(&link.remote, &sets, FullScreen::Shown);
        let asked = self.state.unreached(&link.remote, &sets, card);
        let allowed = || {
            self.state
                .allowed(connection, capability, operation, key, now)
        };
        match (resolved.mode, shown, asked) {
            (Mode::Unattended | Mode::Notify, None, _) => {
                Verdict::Serve(Outcome::Served(resolved.basis))
            }
            (Mode::Unattended, Some(_), _) => Verdict::Serve(Outcome::Unseen(resolved.basis)),
            (Mode::Confirm, None, _) if allowed() => Verdict::Serve(Outcome::Covered),
            (Mode::Confirm, _, None) => Verdict::Hold(resolved.basis),
            (Mode::Notify, Some(whereabouts), _) | (Mode::Confirm, _, Some(whereabouts)) => {
                Verdict::Refuse(Refusal::NobodyReachable(whereabouts))
            }
        }
    }

    /// Admits a connection at `door`, or refuses it, on what was read of the
    /// process at its other end. `None` is a process nothing could be read
    /// of.
    ///
    /// The control pipe refuses nobody it could read: who may open it is the
    /// pipe's own to say. A forward's end admits only a process in the job
    /// of the channel the forward belongs to, and whatever it admits comes
    /// from that channel's remote.
    ///
    /// ```
    /// use hedwig_model::gate::Door;
    /// use hedwig_model::trail::{ConnectionId, Seq};
    ///
    /// let door = Door::Forward(ConnectionId(Seq(7)));
    /// assert_ne!(door, Door::Control);
    /// ```
    ///
    /// A forward's end is a connection's, never a bare number:
    ///
    /// ```compile_fail
    /// use hedwig_model::gate::Door;
    /// use hedwig_model::trail::{ConnectionId, Seq};
    ///
    /// let door = Door::Forward(7);
    /// assert_ne!(door, Door::Control);
    /// ```
    ///
    /// # Errors
    ///
    /// [`Refusal::Unattributable`] at either door for a process nothing was
    /// read of; at a forward's end, [`Refusal::UnknownConnection`] when its
    /// connection is over and [`Refusal::NoChannel`] for a process outside
    /// its channel's job.
    pub fn admit(&self, door: Door, peer: Option<&Peer>) -> Result<Admitted, Refusal> {
        let peer = peer.ok_or(Refusal::Unattributable)?;
        let of = |connection: ConnectionId| self.state.link(connection).map(|link| &link.remote);
        match door {
            Door::Control => Ok(peer
                .channel
                .and_then(of)
                .map_or(Admitted::Person, |remote| Admitted::Remote(remote.clone()))),
            Door::Prompt => peer.channel.and_then(of).map_or_else(
                || {
                    Err(Refusal::NoChannel {
                        process: peer.origin.process,
                        program: peer.program.clone(),
                    })
                },
                |remote| Ok(Admitted::Remote(remote.clone())),
            ),
            Door::Forward(connection) => {
                let remote = of(connection).ok_or(Refusal::UnknownConnection(connection))?;
                if peer.channel == Some(connection) {
                    Ok(Admitted::Remote(remote.clone()))
                } else {
                    Err(Refusal::NoChannel {
                        process: peer.origin.process,
                        program: peer.program.clone(),
                    })
                }
            }
        }
    }

    /// The held requests that can no longer be put to the person, each with
    /// where the person was. Whatever changed - a surface gone, covered or
    /// engaged, a card set not to be shown, a set that no longer names the
    /// remote - the core refuses these with [`Refusal::NobodyReachable`]
    /// rather than leave the remote waiting.
    pub fn stranded(&self) -> Vec<(RequestId, Whereabouts)> {
        let sets = self.sets();
        self.state
            .asks
            .iter()
            .filter(|(_, ask)| ask.held)
            .filter_map(|(request, ask)| {
                let whereabouts = match self.state.link(ask.connection) {
                    Some(link) => {
                        let card = self.full_screen(&link.remote).value;
                        self.state.unreached(&link.remote, &sets, card)?
                    }
                    None => Whereabouts::Away,
                };
                Some((*request, whereabouts))
            })
            .collect()
    }

    /// Whether the core would carry out `request` for `client` now.
    ///
    /// # Errors
    ///
    /// The refusal the core's reply would carry.
    #[allow(clippy::too_many_lines, reason = "one arm per request")]
    pub fn permit(&self, client: ClientId, request: &Request) -> Result<(), Refusal> {
        if let Request::Hello { protocol, .. } = request {
            return if *protocol == PROTOCOL {
                Ok(())
            } else {
                Err(Refusal::Version {
                    core: PROTOCOL,
                    client: *protocol,
                })
            };
        }
        let surface = self.state.surface(client).ok_or(Refusal::NotGreeted)?;
        let attending = || {
            if surface.kind.attends() {
                Ok(())
            } else {
                Err(Refusal::NotAttending)
            }
        };
        match request {
            Request::Hello { .. }
            | Request::Status
            | Request::Exposure
            | Request::Attention
            | Request::Catalogue
            | Request::Workstation
            | Request::Export
            | Request::Activity { .. }
            | Request::Follow { .. }
            | Request::Disconnect { .. }
            | Request::Resume(_)
            | Request::PutAway(_)
            | Request::Settings { .. }
            | Request::Try(_)
            | Request::Ports
            | Request::MakeKey { .. }
            | Request::DeleteKey(_)
            | Request::Withdraw
            | Request::Withdrawal
            | Request::Restore
            | Request::Bundle
            | Request::Diagnose(_)
            | Request::Stop => Ok(()),
            Request::Pause(scope) => match scope.set() {
                Some(id) if !self.sets().defines(id) => Err(Refusal::UnknownSet(id.clone())),
                _ => Ok(()),
            },
            Request::Presence(_) => attending(),
            Request::Icon(_) => {
                if surface.kind == ClientKind::Interface {
                    Ok(())
                } else {
                    Err(Refusal::NoIcon)
                }
            }
            Request::Change(change) => self.changeable(change),
            Request::Import(document) => {
                Configuration::import(self.catalogue, (**document).clone()).map(drop)
            }
            Request::Connect {
                remote,
                with,
                acknowledged,
                lends,
            } => self.connectable(remote, with, *acknowledged, lends),
            Request::Decide { request, decision } => {
                attending()?;
                self.decidable(*request, *decision)
            }
            Request::Answer { prompt, answer } => {
                attending()?;
                let asked = self
                    .state
                    .prompt(*prompt)
                    .ok_or(Refusal::UnknownPrompt(*prompt))?;
                let fits = matches!(
                    (asked.kind.asks(), answer),
                    (_, Answer::Decline)
                        | (Asks::Text, Answer::Text(_))
                        | (Asks::Consent, Answer::Accept)
                );
                if fits {
                    Ok(())
                } else {
                    Err(Refusal::AnswerUnfit { kind: asked.kind })
                }
            }
            Request::Prompt { .. } => {
                if surface.kind == ClientKind::Prompt {
                    Ok(())
                } else {
                    Err(Refusal::NoChannel {
                        process: surface.origin.process,
                        program: None,
                    })
                }
            }
            Request::Rule {
                connection, scope, ..
            } => self.rulable(*connection, scope),
            Request::Check { remote, capability } => {
                self.unwithdrawn()?;
                self.held_by(remote, capability).map(drop)
            }
            Request::Devices(id) => self.listable(id, Holds::Devices),
            Request::Keys(id) => self.listable(id, Holds::Keys),
            Request::Exercise { remote, capability } => {
                self.unwithdrawn()?;
                self.held_by(remote, capability)?;
                if self.state.paused(remote, &self.sets()) {
                    return Err(Refusal::Paused);
                }
                self.state
                    .connection(remote)
                    .map(drop)
                    .ok_or_else(|| Refusal::NotConnected(remote.clone()))
            }
        }
    }

    /// Whether a connection may be opened at the person's word: none is while
    /// Hedwig is being removed, since one would only take back what it wrote.
    fn unwithdrawn(&self) -> Result<(), Refusal> {
        match self.state.withdrawn() {
            Some(_) => Err(Refusal::Withdrawn),
            None => Ok(()),
        }
    }

    /// Whether a held request may be answered so: it is still held, and a
    /// length it is allowed for is one of those offered for it.
    fn decidable(&self, request: RequestId, decision: Decision) -> Result<(), Refusal> {
        let ask = match self.state.ask(request) {
            Some(ask) if ask.held => ask,
            _ => return Err(Refusal::UnknownRequest(request)),
        };
        match decision {
            Decision::For(seconds) if !self.offers(ask).contains(&seconds) => {
                Err(Refusal::NotOffered { seconds })
            }
            _ => Ok(()),
        }
    }

    /// Whether a rule may be set on a connection: it is live, and the rule
    /// names something it carries.
    fn rulable(&self, connection: ConnectionId, scope: &ConnectionScope) -> Result<(), Refusal> {
        let link = self
            .state
            .link(connection)
            .ok_or(Refusal::UnknownConnection(connection))?;
        let Selector::Only(id) = &scope.capability else {
            return Ok(());
        };
        let capability = self.granted(link, id)?;
        match scope.operation {
            Selector::Only(operation)
                if !capability.dialect().operations().contains(&operation) =>
            {
                Err(Refusal::OperationNotInDialect {
                    capability: capability.id,
                    operation,
                })
            }
            _ => Ok(()),
        }
    }

    /// Whether `change` would be applied: the configuration's own gate, and
    /// a set a pause still selects stays defined.
    fn changeable(&self, change: &Change) -> Result<(), Refusal> {
        if let Change::UndefineSet(id) = change
            && self.state.pauses(id)
        {
            return Err(Refusal::SetInUse(id.clone()));
        }
        self.configuration
            .clone()
            .apply(self.catalogue, change.clone())
            .map(drop)
    }

    /// Whether `request`, carried out now, can let a remote reach more or be
    /// served with less asked of the person: what the core records with a
    /// change, so that it reaches the person wherever it was not made.
    pub fn widens(&self, request: &Request) -> Reach {
        match request {
            Request::Change(change) => self.configuration.widens(self.catalogue, change),
            Request::Import(document) => Configuration::restore((**document).clone())
                .map_or(Reach::NoWider, |next| self.configuration.widens_to(&next)),
            _ => Reach::NoWider,
        }
    }

    /// What a channel forwards once its remote has reported a platform: each
    /// capability the remote holds, in the form that platform carries or with
    /// the reason it carries none.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownConnection`] for a connection that is not live;
    /// [`Refusal::PlatformUnobserved`] before the remote has reported;
    /// [`Refusal::UnknownPlatform`] when no profile has that name.
    pub fn plan(
        &self,
        connection: ConnectionId,
    ) -> Result<BTreeMap<Name, Result<Form, Refusal>>, Refusal> {
        let link = self
            .state
            .link(connection)
            .ok_or(Refusal::UnknownConnection(connection))?;
        let platform = self.platform(link)?;
        Ok(apart(
            self.reaching(&link.remote, Some(link))
                .into_iter()
                .map(|reached| {
                    let form = reached.carrier(platform);
                    (reached.capability.id, form)
                })
                .collect(),
        ))
    }

    /// What readiness asks about on `connection`'s remote: each capability
    /// the remote holds, every form its far end can take on any platform, and
    /// whether the grant lets Hedwig write the remote tool's configuration.
    /// Readiness runs before the platform is known, so no form is left out.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownConnection`] for a connection that is not live.
    pub fn carried(&self, connection: ConnectionId) -> Result<Vec<Carried>, Refusal> {
        let link = self
            .state
            .link(connection)
            .ok_or(Refusal::UnknownConnection(connection))?;
        Ok(self
            .reaching(&link.remote, Some(link))
            .into_iter()
            .map(|reached| Carried {
                forms: reached.capability.forms(),
                writes: match reached.setup {
                    // Hedwig is being removed: no consent stands.
                    Setup::Write if self.state.withdrawn().is_some() => Vec::new(),
                    Setup::Write => {
                        let offered = self.state.offered(&reached.capability.id);
                        reached.capability.consent(offered).writes
                    }
                    Setup::Inspect => Vec::new(),
                },
                capability: reached.capability.id,
                setup: reached.setup,
            })
            .collect())
    }

    /// What a channel forwards when readiness could not learn the remote's
    /// platform: a capability its grant carries on a port on every platform,
    /// as that port, since a port fits every platform; every other capability
    /// is refused as the platform unobserved.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownConnection`] for a connection that is not live.
    pub fn plan_unobserved(
        &self,
        connection: ConnectionId,
    ) -> Result<BTreeMap<Name, Result<Form, Refusal>>, Refusal> {
        let link = self
            .state
            .link(connection)
            .ok_or(Refusal::UnknownConnection(connection))?;
        Ok(apart(
            self.reaching(&link.remote, Some(link))
                .into_iter()
                .map(|reached| {
                    // A port reaches every user of the remote, which the
                    // grant chose only where it does so on every platform.
                    let port = reached
                        .capability
                        .forms()
                        .into_iter()
                        .find(|form| matches!(form, Form::Port(_)))
                        .filter(|_| reached.capability.open_everywhere(reached.stated))
                        .ok_or_else(|| Refusal::PlatformUnobserved(link.remote.clone()));
                    (reached.capability.id, port)
                })
                .collect(),
        ))
    }

    /// Whether `connection`'s remote holds `capability` now: granted to it or
    /// added for the connection, and not denied.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownConnection`], or the reason the remote does not hold
    /// it.
    pub fn holds(&self, connection: ConnectionId, capability: &Name) -> Result<(), Refusal> {
        let link = self
            .state
            .link(connection)
            .ok_or(Refusal::UnknownConnection(connection))?;
        self.granted(link, capability).map(drop)
    }

    /// Each remote Hedwig has written on and not taken everything back from:
    /// what is still there, whether a survey to take it back is under way,
    /// and how the last connection to it ended.
    pub fn withdrawal(&self) -> Vec<Withdrawal> {
        self.state
            .written_on()
            .map(|remote| Withdrawal {
                remote: remote.clone(),
                left: self
                    .state
                    .written(remote)
                    .map(|(_, write, place, made)| Written {
                        write: write.clone(),
                        place: place.clone(),
                        made: made.cloned(),
                    })
                    .collect(),
                surveying: self.state.connection(remote).is_some(),
                ended: self.state.ended(remote).map(|(end, _)| end.clone()),
            })
            .collect()
    }

    /// Whether a grant asks the core to hold a channel to `remote` now, with
    /// nobody asking.
    pub fn wanted(&self, remote: &RemoteId) -> bool {
        !self.state.paused(remote, &self.sets())
            && self
                .reaching(remote, None)
                .iter()
                .any(|reached| match reached.activation {
                    Activation::OnRequest => false,
                    Activation::WhileRunning => self.state.running.contains(remote),
                    Activation::Continuous => true,
                })
    }

    /// One row per capability per remote the core knows, and one per grant
    /// that covers no remote yet, as they stand at `now`.
    pub fn rows(&self, client: ClientId, now: Tick) -> Vec<Row> {
        self.rows_for(client, &[], now)
    }

    /// The rows for every remote the core knows and for each of `named`.
    pub fn rows_for(&self, client: ClientId, named: &[RemoteId], now: Tick) -> Vec<Row> {
        let grants = self.grants();
        let mut remotes = self.known();
        remotes.extend(named.iter().cloned());

        let sets = self.sets();
        let mut rows = Vec::new();
        let mut placed = vec![false; grants.len()];
        for remote in &remotes {
            let link = self.state.connection(remote).map(|(_, link)| link);
            let mut ids: BTreeSet<&Name> = link.iter().flat_map(|link| &link.with).collect();
            for ((_, grant), placed) in grants.iter().zip(placed.iter_mut()) {
                if grant.remotes.covers(remote, &sets) {
                    *placed = true;
                    ids.insert(&grant.capability);
                }
            }
            for id in ids {
                if let Some(through) = self.through(remote, id) {
                    rows.push(self.row(client, id, Some(remote), through, now));
                }
            }
        }
        for ((through, grant), placed) in grants.iter().zip(placed) {
            if !placed {
                rows.push(self.row(client, &grant.capability, None, through.clone(), now));
            }
        }
        rows
    }

    /// Every remote the core knows of: running, connected or ended in this
    /// run, or named by a grant.
    pub(crate) fn known(&self) -> BTreeSet<RemoteId> {
        let mut remotes: BTreeSet<RemoteId> = self.state.running.clone();
        remotes.extend(self.state.links.values().map(|link| link.remote.clone()));
        remotes.extend(self.state.ended.keys().cloned());
        remotes.extend(
            self.grants()
                .iter()
                .filter_map(|(_, grant)| match &grant.remotes {
                    Granted::One(remote) => Some(remote.clone()),
                    _ => None,
                }),
        );
        remotes
    }

    /// Every setting as it stands, where each comes from and what holds it,
    /// for this workstation, every remote the core knows and each of
    /// `named`.
    pub fn settings(&self, named: &[RemoteId]) -> Settings {
        let mut remotes = self.known();
        remotes.extend(named.iter().cloned());
        let policy = self.policy();
        let contacts = [Audience::Machine, Audience::Person]
            .into_iter()
            .flat_map(|audience| {
                policy.ask(audience).map(move |words| Contact {
                    audience,
                    words: words.clone(),
                })
            })
            .collect();
        Settings {
            workstation: WorkstationSettings {
                lengths: self.lengths(),
                autostart: self.autostart(),
                icon: self.icon(),
                windows: WindowsStarts {
                    hedwig: self.state.startup(Starts::Hedwig).cloned(),
                    icon: self.state.startup(Starts::Icon).cloned(),
                },
                keep: self.keep(),
                diagnostics: self.diagnostics(),
                contacts,
                unread: policy.misread(),
            },
            remotes: remotes
                .iter()
                .map(|remote| RemoteSettings {
                    remote: remote.clone(),
                    threshold: self.threshold(remote),
                    volumes: Condition::EVERY
                        .into_iter()
                        .map(|condition| Loudness {
                            condition,
                            volume: self.volume(remote, condition),
                        })
                        .collect(),
                    full_screen: self.full_screen(remote),
                    caps: self.caps(remote),
                    keepalive: self.keepalive(remote),
                    returns: self.returns(remote),
                })
                .collect(),
            routes: self
                .listings()
                .into_iter()
                .map(|route| RouteSettings {
                    cadence: self.cadence(&route),
                    route,
                })
                .collect(),
        }
    }

    /// Every cap on allowances for requests from `remote`, whatever key they
    /// use, the smallest first.
    fn caps(&self, remote: &RemoteId) -> Vec<Capped> {
        let sets = self.sets();
        let person = self
            .configuration
            .caps()
            .iter()
            .map(|(scope, longest)| Capped {
                longest: *longest,
                holder: Holder::Person,
                scope: scope.clone(),
            });
        let organisation = self
            .policy()
            .limits()
            .filter_map(|(audience, limit)| match limit {
                Limit::Cap { scope, longest } => Some(Capped {
                    longest: *longest,
                    holder: Holder::Organisation(audience),
                    scope: scope.clone(),
                }),
                _ => None,
            });
        let mut caps: Vec<Capped> = person
            .chain(organisation)
            .filter(|capped| capped.scope.remotes.covers(remote, &sets))
            .collect();
        caps.sort();
        caps
    }

    /// Each of the organisation's limits that holds what `change` states on
    /// the remotes the core knows; with no change, each that holds anything
    /// the person's configuration states. The statement stays as it was made
    /// and serves as stated once the limit goes.
    pub fn held(&self, client: ClientId, change: Option<&Change>, now: Tick) -> Vec<Holding> {
        let mut held = BTreeSet::new();
        for row in self.rows(client, now) {
            let stated = match (change, &row.through) {
                (None, Through::Grant(_) | Through::Start { .. }) => true,
                (Some(Change::Grant { grant, .. }), Through::Grant(through))
                | (Some(Change::Accept { grant, .. }), Through::Start { grant: through, .. }) => {
                    grant == through
                }
                _ => false,
            };
            if stated {
                held.extend(row.holds.iter().cloned());
                if let Standing::Unavailable(Refusal::Held { audience, limit }) = &row.standing {
                    held.insert(Holding {
                        holder: Holder::Organisation(*audience),
                        limit: (**limit).clone(),
                    });
                }
            }
            for decides in &row.decides {
                let Basis::Limit(limited) = &decides.basis else {
                    continue;
                };
                let stated = match (change, &limited.basis) {
                    (None, Basis::Rule(_)) => true,
                    (Some(Change::Rule { scope, .. }), Basis::Rule(rule)) => scope == rule,
                    _ => false,
                };
                if stated {
                    held.insert(Holding {
                        holder: Holder::Organisation(limited.audience),
                        limit: Limit::Floor {
                            scope: limited.scope.clone(),
                            mode: decides.mode,
                        },
                    });
                }
            }
        }
        let offered = self.lengths().value.iter().last().map(Longest::Seconds);
        let sets = self.sets();
        for remote in self.known() {
            for capped in self.caps(&remote) {
                let Holder::Organisation(audience) = capped.holder else {
                    continue;
                };
                let beyond = |longest: Longest| capped.longest < longest;
                let person = |scope: &CapScope, longest: Longest| {
                    scope.remotes.covers(&remote, &sets)
                        && meet(&scope.key, &capped.scope.key)
                        && beyond(longest)
                };
                let holds = match change {
                    None => {
                        offered.is_some_and(beyond)
                            || self
                                .configuration
                                .caps()
                                .iter()
                                .any(|(scope, longest)| person(scope, *longest))
                    }
                    Some(Change::Cap {
                        scope,
                        longest: Some(longest),
                    }) => person(scope, *longest),
                    Some(Change::Lengths(Some(_))) => offered.is_some_and(beyond),
                    _ => false,
                };
                if holds {
                    held.insert(Holding {
                        holder: Holder::Organisation(audience),
                        limit: Limit::Cap {
                            scope: capped.scope,
                            longest: capped.longest,
                        },
                    });
                }
            }
        }
        held.into_iter().collect()
    }

    /// What `trial` would change, made against what holds now and never
    /// kept: every row and every setting that would differ, and whether it
    /// can let more through. A document or a change the configuration's gate
    /// would refuse is answered with that refusal.
    pub fn tried(&self, client: ClientId, trial: &Trial, now: Tick) -> Tried {
        let mut reach = Reach::NoWider;
        let mut widens = |more: Reach| {
            if more == Reach::Wider {
                reach = Reach::Wider;
            }
        };
        let mut state = self.state.clone();
        let mut catalogue = self.catalogue.clone();
        if let Some(lines) = &trial.policy {
            let next = Policy::read(lines.iter().map(|line| (line.place, line.text.as_str())));
            widens(self.policy().widens_to(&next));
            catalogue = self.catalogue.under(&next);
            state.policy = next;
        }
        let mut configuration = self.configuration.clone();
        if let Some(document) = &trial.document {
            match Configuration::import(&catalogue, document.clone()) {
                Ok(imported) => {
                    widens(configuration.widens_to(&imported));
                    configuration = imported;
                }
                Err(refusal) => return Tried::Refused(refusal),
            }
        }
        if let Some(change) = &trial.change {
            let world = World {
                catalogue: &catalogue,
                configuration: &configuration,
                state: &state,
            };
            if let Err(refusal) = world.changeable(change) {
                return Tried::Refused(refusal);
            }
            widens(configuration.widens(&catalogue, change));
            if let Err(refusal) = configuration.apply(&catalogue, change.clone()) {
                return Tried::Refused(refusal);
            }
        }
        let after = World {
            catalogue: &catalogue,
            configuration: &configuration,
            state: &state,
        };
        let named = &trial.remotes;
        let rows = differs(
            self.rows_for(client, named, now),
            after.rows_for(client, named, now),
            |row: &Row, other: &Row| {
                row.remote == other.remote
                    && row.capability == other.capability
                    && (row.remote.is_some() || row.through == other.through)
            },
        );
        let (before, after) = (self.settings(named), after.settings(named));
        let remotes = differs(before.remotes, after.remotes, |remote, other| {
            remote.remote == other.remote
        });
        let workstation = (before.workstation != after.workstation).then_some(Differs {
            before: Some(before.workstation),
            after: Some(after.workstation),
        });
        Tried::Would(Box::new(Would {
            reach,
            rows,
            remotes,
            workstation,
        }))
    }

    /// Every grant, the person's and those the organisation starts them
    /// with, each with what it is granted through.
    fn grants(&self) -> Vec<(Through, &Grant)> {
        let person = self
            .configuration
            .grants()
            .map(|(grant, _)| (Through::Grant(grant.clone()), grant));
        let start = self
            .policy()
            .start()
            .filter_map(|(audience, start)| match start {
                Start::Grant { grant, .. } => Some((
                    Through::Start {
                        audience,
                        grant: grant.clone(),
                    },
                    grant,
                )),
                _ => None,
            });
        person.chain(start).collect()
    }

    /// Everything that needs the person at `client` now, the loudest first.
    ///
    /// What holds a remote up always interrupts. A burst interrupts where
    /// the remote has a threshold and its requests reach it. Everything else
    /// about a remote is as loud as the person chose for that remote, and is
    /// here whatever they chose. A change that let more through is here for
    /// every client but the one that made it.
    #[allow(
        clippy::too_many_lines,
        reason = "one block per kind of attention: the single place each is raised"
    )]
    pub fn attention(&self, client: ClientId, now: Tick) -> Vec<Needs> {
        let state = self.state;
        let mut items = Vec::new();
        let mut needs = |attention: Attention, volume: Volume| {
            items.push(Needs { attention, volume });
        };
        let heard = |remote: &RemoteId, condition: Condition| self.volume(remote, condition).value;
        for (request, ask) in &state.asks {
            if let (true, Some(link)) = (ask.held, state.link(ask.connection)) {
                let (offers, capped) = self.allowance(ask);
                needs(
                    Attention::Request {
                        request: *request,
                        remote: link.remote.clone(),
                        capability: ask.capability.clone(),
                        operation: ask.operation,
                        key: ask.key.clone(),
                        payload: ask.payload.clone(),
                        offers,
                        capped,
                    },
                    Volume::Interrupts,
                );
            }
        }
        for (prompt, asked) in &state.prompts {
            if let Some(link) = state.link(asked.connection) {
                needs(
                    Attention::Prompt {
                        prompt: *prompt,
                        remote: link.remote.clone(),
                        kind: asked.kind,
                        words: asked.words.clone(),
                    },
                    Volume::Interrupts,
                );
            }
        }
        for (remote, recent) in &state.recent {
            let Threshold::At(burst) = self.threshold(remote).value else {
                continue;
            };
            let window = u64::from(burst.seconds.get()) * 1000;
            let put_away = state
                .put_away
                .get(&Item::Burst(remote.clone()))
                .map(|(_, tick)| *tick);
            let requests = recent
                .iter()
                .filter(|tick| tick.0.saturating_add(window) > now.0)
                .filter(|tick| put_away.is_none_or(|since| **tick > since))
                .count();
            if requests >= usize::from(burst.requests.get()) {
                needs(
                    Attention::Burst {
                        remote: remote.clone(),
                        requests: u32::try_from(requests).unwrap_or(u32::MAX),
                    },
                    Volume::Interrupts,
                );
            }
        }
        let fresh = |item: Item, since: Seq| {
            state
                .put_away
                .get(&item)
                .is_none_or(|(put_away, _)| *put_away < since)
        };
        for ((remote, capability), (findings, since)) in &state.unready {
            let item = Item::Unready {
                remote: remote.clone(),
                capability: capability.clone(),
            };
            if fresh(item, *since) {
                needs(
                    Attention::Unready {
                        remote: remote.clone(),
                        capability: capability.clone(),
                        findings: findings.clone(),
                    },
                    heard(remote, Condition::Unready),
                );
            }
        }
        for (remote, (end, since)) in &state.ended {
            let condition = match end {
                ChannelEnd::HostKeyChanged(_) => Condition::HostKeyChanged,
                // What comes back by itself is on the row, and needs nobody.
                _ if end.back() != Back::ByThePerson => continue,
                _ => Condition::Stopped,
            };
            if fresh(Item::Stopped(remote.clone()), *since) {
                needs(
                    Attention::Stopped {
                        remote: remote.clone(),
                        end: end.clone(),
                    },
                    heard(remote, condition),
                );
            }
        }
        for (serial, (card, since)) in &state.cards {
            if card.leaves_use_unobserved() && fresh(Item::Safeguards(serial.clone()), *since) {
                needs(Attention::Safeguards(card.clone()), Volume::Announced);
            }
        }
        for (item, (times, _)) in &state.refused {
            let Item::Refused { remote, refusal } = item else {
                continue;
            };
            let volume = match remote {
                Some(remote) if self.configuration.expects(remote, refusal) => continue,
                Some(remote) => heard(remote, Condition::Refused),
                None => Condition::Refused.ships(),
            };
            needs(
                Attention::Refused {
                    remote: remote.clone(),
                    refusal: refusal.clone(),
                    times: *times,
                },
                volume,
            );
        }
        if let Some((cause, times)) = state.restarted {
            needs(Attention::Restarted { cause, times }, Volume::Announced);
        }
        for (store, account) in &state.unreadable {
            needs(
                Attention::Unreadable {
                    store: *store,
                    account: account.clone(),
                },
                Volume::Announced,
            );
        }
        for widened in state.widened.values() {
            if widened.entry.event.by() != Some(client) {
                needs(
                    Attention::Widened {
                        entry: widened.entry.clone(),
                        kind: widened.kind,
                        origin: widened.origin,
                    },
                    Volume::Announced,
                );
            }
        }
        for (remote, served) in &state.unseen {
            needs(
                Attention::Unseen {
                    remote: remote.clone(),
                    served: *served,
                },
                Volume::Announced,
            );
        }
        for (remote, notices) in &state.notices {
            for noted in &notices.kept {
                needs(
                    Attention::Noticed {
                        remote: remote.clone(),
                        notice: noted.seq,
                        at: noted.at,
                        remark: noted.remark.clone(),
                        unheard: noted.unheard,
                    },
                    heard(remote, Condition::Noticed),
                );
            }
        }
        for (route, (account, since)) in &state.unlisted {
            if fresh(Item::Unlisted(route.clone()), *since) {
                needs(
                    Attention::Unlisted {
                        route: route.clone(),
                        account: account.clone(),
                    },
                    Volume::Announced,
                );
            }
        }
        for (place, restated) in &state.restated {
            let unread = state
                .policy()
                .unread()
                .find(|(at, _)| at == place)
                .map_or(0, |(_, unread)| {
                    u32::try_from(unread.lines.len()).unwrap_or(u32::MAX)
                });
            needs(
                Attention::Policy {
                    place: *place,
                    since: restated.since,
                    arrived: restated.arrived,
                    withdrawn: restated.withdrawn,
                    unread,
                },
                Volume::Announced,
            );
        }
        // Shown, not announced: the removal that recorded it says so where it
        // runs.
        if let Some(withdrew) = state.withdrawn() {
            needs(Attention::Withdrawn(withdrew), Volume::Shown);
        }
        items.sort_by_key(|needs| std::cmp::Reverse(needs.volume));
        items
    }

    /// Which clients are told of something that needs the person, and how
    /// loudly each says so. Only the clients that watch its remote are told.
    /// What interrupts does so on all of them at once; what is announced is
    /// announced by one and shown by the rest, so a person at the desktop
    /// with a terminal attached hears each thing once. The one is a present
    /// client where there is one, the one the person was last seen at first,
    /// and only then one behind a full-screen application, whose
    /// notification Windows holds back.
    pub fn hears(&self, needs: &Needs) -> Vec<(ClientId, Volume)> {
        let sets = self.sets();
        let told: Vec<(ClientId, Presence, Seq)> = self
            .state
            .surfaces
            .iter()
            .filter(|(_, surface)| surface.kind.attends())
            .filter(|(_, surface)| {
                needs
                    .attention
                    .remote()
                    .is_none_or(|remote| surface.attends.covers(remote, &sets))
            })
            .filter(|(client, _)| match &needs.attention {
                Attention::Widened { entry, .. } => entry.event.by() != Some(**client),
                _ => true,
            })
            .map(|(client, surface)| (*client, surface.presence, surface.seen))
            .collect();
        let herald = told
            .iter()
            .filter_map(|(client, presence, seen)| Some(((says_now(*presence)?, *seen), *client)))
            .max()
            .map(|(_, client)| client);
        told.into_iter()
            .map(|(client, _, _)| {
                let volume = match needs.volume {
                    Volume::Announced if herald != Some(client) => Volume::Shown,
                    volume => volume,
                };
                (client, volume)
            })
            .collect()
    }

    /// The one client that announces a request served to `remote` without
    /// asking, chosen as [`World::hears`] chooses: none where the person only
    /// has those shown, or where nothing that watches the remote can say it.
    pub fn announces(&self, remote: &RemoteId) -> Option<ClientId> {
        if self.volume(remote, Condition::Served).value != Volume::Announced {
            return None;
        }
        let sets = self.sets();
        self.state
            .watching(remote, &sets)
            .filter_map(|(client, surface)| {
                Some(((says_now(surface.presence)?, surface.seen), client))
            })
            .max()
            .map(|(_, client)| client)
    }

    /// What this workstation holds: which capabilities' own side answers,
    /// every card the core has read, and which remotes its routes report
    /// running. No card is said to be in: a card put in is seen by no read
    /// that cannot open one until the agent's own operation scans for it.
    pub fn workstation(&self) -> Workstation {
        Workstation {
            sources: self
                .state
                .sources
                .keys()
                .chain(
                    self.state
                        .holders
                        .iter()
                        .filter(|(_, holder)| holder.is_some())
                        .map(|(capability, _)| capability),
                )
                .collect::<BTreeSet<&Name>>()
                .into_iter()
                .map(|capability| Found {
                    capability: capability.clone(),
                    health: self.state.sources.get(capability).copied(),
                    holder: self.state.holders.get(capability).cloned().flatten(),
                })
                .collect(),
            cards: self
                .state
                .cards
                .values()
                .map(|(card, _)| card.clone())
                .collect(),
            running: self.state.running.iter().cloned().collect(),
            keys: self
                .state
                .offered
                .iter()
                .map(|(capability, keyring)| Offering {
                    capability: capability.clone(),
                    keyring: keyring.clone(),
                })
                .collect(),
        }
    }

    /// Whether Hedwig runs, as what, and whether anything is exposed, as
    /// `client` is told it. `None` before the core has recorded its start.
    pub fn status(&self, client: ClientId, now: Tick) -> Option<Status> {
        let (_, since, version, origin): &(Seq, Timestamp, String, _) =
            self.state.started.as_ref()?;
        Some(Status {
            version: version.clone(),
            since: *since,
            origin: *origin,
            attached: self
                .state
                .surfaces
                .iter()
                .map(|(client, surface)| Attached {
                    client: *client,
                    kind: surface.kind,
                    origin: surface.origin,
                    presence: surface.kind.attends().then_some(surface.presence),
                    icon: surface.icon,
                    attends: surface.attends.clone(),
                })
                .collect(),
            paused: self.state.paused.iter().cloned().collect(),
            connected: self
                .state
                .links
                .values()
                .filter(|link| matches!(link.phase, Phase::Up(_)))
                .map(|link| link.remote.clone())
                .collect(),
            attention: u32::try_from(self.attention(client, now).len()).unwrap_or(u32::MAX),
            network: self.state.network(),
            withdrawn: self.state.withdrawn(),
        })
    }

    /// The named sets every selection of remotes is read against.
    pub fn sets(&self) -> Sets<'_> {
        self.configuration.sets(self.catalogue)
    }

    /// What the organisation states.
    pub fn policy(&self) -> &Policy {
        self.state.policy()
    }

    /// When volume from `remote` is brought to the person's attention.
    pub fn threshold(&self, remote: &RemoteId) -> Settled<Threshold, Remotes> {
        let stated = self
            .configuration
            .bursts()
            .iter()
            .map(|(remotes, threshold)| (remotes, *threshold));
        let start = |audience: Audience| {
            self.policy()
                .start()
                .filter_map(move |(stated_for, start)| match start {
                    Start::Burst { remotes, threshold } if stated_for == audience => {
                        Some((remotes, *threshold))
                    }
                    _ => None,
                })
        };
        self.chosen(
            remote,
            stated,
            start(Audience::Person),
            start(Audience::Machine),
            Threshold::SHIPS,
        )
    }

    /// How loudly `condition` on `remote` reaches the person.
    pub fn volume(&self, remote: &RemoteId, condition: Condition) -> Settled<Volume, Remotes> {
        let stated = self
            .configuration
            .heard()
            .filter(move |(_, heard)| heard.condition() == condition)
            .map(|(remotes, heard)| (remotes, heard.volume()));
        let silent = std::iter::empty();
        self.chosen(remote, stated, silent.clone(), silent, condition.ships())
    }

    /// Whether a held request from `remote` is shown over an application that
    /// fills the screen.
    pub fn full_screen(&self, remote: &RemoteId) -> Settled<FullScreen, Remotes> {
        let stated = self
            .configuration
            .full_screen()
            .iter()
            .map(|(remotes, card)| (remotes, *card));
        let silent = std::iter::empty();
        self.chosen(remote, stated, silent.clone(), silent, FullScreen::SHIPS)
    }

    /// The lengths "allow for a time" offers, before any cap.
    pub fn lengths(&self) -> Settled<Lengths, Here> {
        let stated = self.configuration.lengths().map(|lengths| (Here, lengths));
        let silent = std::iter::empty();
        Self::here(&stated.into_iter(), &silent, &silent).map_or_else(
            || Settled {
                value: Lengths::ships(),
                said: Said::Ships,
            },
            |(said, lengths)| Settled {
                value: lengths.clone(),
                said,
            },
        )
    }

    /// Whether Windows starts the icon when the person logs on at a desktop.
    pub fn icon(&self) -> Settled<Autostart, Here> {
        self.for_workstation(
            self.configuration.icon(),
            |start| match start {
                Start::Icon(icon) => Some(*icon),
                _ => None,
            },
            Autostart::SHIPS,
        )
    }

    /// How many days of activity the trail keeps, held inside every least and
    /// most the organisation states.
    pub fn keep(&self) -> Bounded<Keep> {
        let chosen = self.for_workstation(
            self.configuration.keep(),
            |start| match start {
                Start::Keep(keep) => Some(*keep),
                _ => None,
            },
            Keep::SHIPS,
        );
        let limits: Vec<(Audience, Limit)> = self
            .policy()
            .limits()
            .map(|(audience, limit)| (audience, limit.clone()))
            .collect();
        let floors = limits.iter().filter_map(|(audience, limit)| match limit {
            Limit::KeepAtLeast(keep) => Some((*audience, *keep)),
            _ => None,
        });
        let (raised, floor) = at_least(chosen.value, floors);
        let ceilings = limits.iter().filter_map(|(audience, limit)| match limit {
            Limit::KeepAtMost(keep) => Some((*audience, *keep)),
            _ => None,
        });
        let (value, ceiling) = at_most(raised, ceilings);
        Bounded {
            settled: Settled {
                value,
                said: chosen.said,
            },
            held: ceiling.or(floor),
        }
    }

    /// What the core writes about what went wrong: the person's choice for
    /// this run, else for this workstation, else the organisation's starting
    /// value; held at every most the organisation states.
    pub fn diagnostics(&self) -> Bounded<Diagnostics, Span> {
        let person = self
            .state
            .diagnose()
            .map(|level| (Span::Run, level))
            .into_iter()
            .chain(
                self.configuration
                    .diagnostics()
                    .map(|level| (Span::Workstation, level)),
            );
        let from = |audience: Audience| {
            self.policy()
                .start()
                .filter_map(move |(stated_for, statement)| match statement {
                    Start::Diagnostics(level) if stated_for == audience => {
                        Some((Span::Workstation, *level))
                    }
                    _ => None,
                })
        };
        let chosen = choose(&person, &from(Audience::Person), &from(Audience::Machine)).map_or(
            Settled {
                value: Diagnostics::SHIPS,
                said: Said::Ships,
            },
            |(tier, scope, value)| Settled {
                value,
                said: match tier {
                    Tier::Start(audience) => Said::Start { audience, scope },
                    _ => Said::Person(scope),
                },
            },
        );
        let ceilings: Vec<(Audience, Diagnostics)> = self
            .policy()
            .limits()
            .filter_map(|(audience, limit)| match limit {
                Limit::DiagnosticsAtMost(most) => Some((audience, *most)),
                _ => None,
            })
            .collect();
        let (value, held) = at_most(chosen.value, ceilings);
        Bounded {
            settled: Settled {
                value,
                said: chosen.said,
            },
            held,
        }
    }

    /// A choice made once for the workstation: the person's, else the
    /// organisation's starting value for the person, then for the machine,
    /// else what ships.
    fn for_workstation<V: Strict + Copy>(
        &self,
        person: Option<V>,
        start: impl Fn(&Start) -> Option<V> + Clone,
        ships: V,
    ) -> Settled<V, Here> {
        let stated = person.map(|value| (Here, value));
        let from = |audience: Audience| {
            let start = start.clone();
            self.policy()
                .start()
                .filter_map(move |(stated_for, statement)| {
                    if stated_for == audience {
                        start(statement)
                    } else {
                        None
                    }
                })
                .map(|value| (Here, value))
        };
        Self::here(
            &stated.into_iter(),
            &from(Audience::Person),
            &from(Audience::Machine),
        )
        .map_or(
            Settled {
                value: ships,
                said: Said::Ships,
            },
            |(said, value)| Settled { value, said },
        )
    }

    /// Whether Windows starts Hedwig when the person logs on at a desktop.
    pub fn autostart(&self) -> Settled<Autostart, Here> {
        let stated = self
            .configuration
            .autostart()
            .map(|autostart| (Here, autostart));
        let start = |audience: Audience| {
            self.policy()
                .start()
                .filter_map(move |(stated_for, start)| match start {
                    Start::Autostart(autostart) if stated_for == audience => {
                        Some((Here, *autostart))
                    }
                    _ => None,
                })
        };
        Self::here(
            &stated.into_iter(),
            &start(Audience::Person),
            &start(Audience::Machine),
        )
        .map_or(
            Settled {
                value: Autostart::SHIPS,
                said: Said::Ships,
            },
            |(said, value)| Settled { value, said },
        )
    }

    /// The smallest cap that covers a request from `remote` using `used`;
    /// `None` where no allowance is capped.
    pub fn longest(&self, remote: &RemoteId, used: Option<Used<'_>>) -> Option<Capped> {
        let sets = self.sets();
        let person = self
            .configuration
            .caps()
            .iter()
            .filter(|(scope, _)| scope.covers(remote, &sets, used))
            .map(|(scope, longest)| ((Holder::Person, scope), *longest));
        let organisation = self
            .policy()
            .limits()
            .filter_map(|(audience, limit)| match limit {
                Limit::Cap { scope, longest } if scope.covers(remote, &sets, used) => {
                    Some(((Holder::Organisation(audience), scope), *longest))
                }
                _ => None,
            });
        let unbounded = Longest::Seconds(NonZeroU32::MAX);
        match at_most(unbounded, person.chain(organisation)) {
            (longest, Some((holder, scope))) => Some(Capped {
                longest,
                holder,
                scope: scope.clone(),
            }),
            (_, None) => None,
        }
    }

    /// The lengths a held request may be allowed for: the ones offered, up
    /// to the smallest cap that covers it. The card draws these and the core
    /// accepts no other.
    pub fn offers(&self, ask: &Ask) -> Vec<NonZeroU32> {
        self.allowance(ask).0
    }

    /// The lengths a held request may be allowed for, and the cap that took
    /// any of the lengths offered away: `None` where every length is
    /// admitted, though a cap may cover the request.
    fn allowance(&self, ask: &Ask) -> (Vec<NonZeroU32>, Option<Capped>) {
        let Some(link) = self.state.link(ask.connection) else {
            return (Vec::new(), None);
        };
        let used = ask
            .key
            .as_ref()
            .map(|grip| self.used(&ask.capability, grip));
        let cap = self.longest(&link.remote, used);
        let (offers, taken): (Vec<NonZeroU32>, Vec<NonZeroU32>) = self
            .lengths()
            .value
            .iter()
            .partition(|seconds| cap.as_ref().is_none_or(|cap| cap.longest.admits(*seconds)));
        (offers, cap.filter(|_| !taken.is_empty()))
    }

    /// A choice made per remote: the person's statements that cover `remote`,
    /// then what the organisation starts this person with, then this machine,
    /// then what ships.
    pub(crate) fn chosen<'s, V: Strict + Copy>(
        &self,
        remote: &RemoteId,
        person: impl Iterator<Item = (&'s Remotes, V)> + Clone,
        for_person: impl Iterator<Item = (&'s Remotes, V)> + Clone,
        for_machine: impl Iterator<Item = (&'s Remotes, V)> + Clone,
        ships: V,
    ) -> Settled<V, Remotes> {
        let sets = self.sets();
        let covering = |(remotes, _): &(&Remotes, V)| remotes.covers(remote, &sets);
        match choose(
            &person.filter(covering),
            &for_person.filter(covering),
            &for_machine.filter(covering),
        ) {
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
                value: ships,
                said: Said::Ships,
            },
        }
    }

    /// A choice made once for the workstation.
    fn here<V: Strict + Clone>(
        person: &(impl Iterator<Item = (Here, V)> + Clone),
        for_person: &(impl Iterator<Item = (Here, V)> + Clone),
        for_machine: &(impl Iterator<Item = (Here, V)> + Clone),
    ) -> Option<(Said<Here>, V)> {
        choose(person, for_person, for_machine).map(|(tier, scope, value)| match tier {
            Tier::Start(audience) => (Said::Start { audience, scope }, value),
            _ => (Said::Person(scope), value),
        })
    }

    /// How a request of `operation` with `key` would be decided for `remote`.
    /// An opening that carries nothing its operations do not each decide is
    /// decided from what it carries: every other operation of the dialect,
    /// with no key and with each key [`World::carried_keys`] names.
    fn resolved(
        &self,
        on_connection: &BTreeMap<ConnectionScope, Mode>,
        remote: &RemoteId,
        capability: &Capability,
        operation: Operation,
        key: Option<&KeyId>,
    ) -> Resolved {
        let policy = self.policy();
        let rules = Rules {
            person: self.configuration.rules(),
            connection: on_connection,
            start: policy.rules(),
            floors: policy.floors(),
        };
        let exposure = capability.exposure();
        let subject = |operation, key| self.subject(remote, capability, operation, key);
        let requests: Vec<Operation> = capability
            .dialect()
            .operations()
            .iter()
            .copied()
            .filter(|carried| *carried != Operation::Connect)
            .collect();
        if operation != Operation::Connect || opens_more(exposure) || requests.is_empty() {
            return resolve(&rules, &subject(operation, key));
        }
        let keys = self.carried_keys(on_connection, remote, &capability.id);
        let carried = requests.iter().flat_map(|request| {
            let keyed = keys.iter().map(Some);
            std::iter::once(None)
                .chain(keyed)
                .map(|key| resolve(&rules, &subject(*request, key)))
                .collect::<Vec<_>>()
        });
        resolve_opening(&rules, &subject(operation, key), carried)
    }

    fn subject<'w>(
        &'w self,
        remote: &'w RemoteId,
        capability: &'w Capability,
        operation: Operation,
        key: Option<&'w KeyId>,
    ) -> Subject<'w> {
        Subject {
            remote,
            sets: self.sets(),
            capability: &capability.id,
            exposure: capability.exposure(),
            operation,
            used: key.map(|key| self.used(&capability.id, key)),
        }
    }

    /// What a request through `capability` naming `key` uses: the key the
    /// capability's source offers by its keygrip, or by its SSH public half
    /// through gpg-agent's SSH socket, and what its card asks for. A key no
    /// keyring the core read offers - an agent's other than gpg-agent's, the
    /// TPM's - is the key the request names and nothing more.
    fn used<'s>(&'s self, capability: &Name, key: &'s KeyId) -> Used<'s> {
        let keyring = self.state.offered(capability);
        let offered = keyring.and_then(|keyring| match key {
            KeyId::Grip(grip) => keyring.by_grip(grip),
            KeyId::Ssh(ssh) => keyring.by_ssh(ssh),
        });
        let grip = match key {
            KeyId::Grip(grip) => Some(grip),
            KeyId::Ssh(_) => offered.map(|offered| &offered.grip),
        };
        // The card the agent's stub names can be put in and sign however the
        // cards read since say, so where it was never read nothing is known.
        let stub_unread = offered
            .and_then(|offered| offered.card.as_ref())
            .is_some_and(|serial| self.state.card(serial).is_none());
        Used {
            id: key,
            key: offered,
            touch: grip
                .filter(|_| !stub_unread)
                .and_then(|grip| self.state.touch(grip)),
        }
    }

    /// Every key a request through `capability` from `remote` can be told
    /// apart by: each the capability's source offers, each on a card the
    /// core has read, each a statement names by keygrip or as an SSH key, and
    /// each the remote's grant lends. A statement naming a fingerprint names
    /// only keys the source offers, which are already among them.
    fn carried_keys(
        &self,
        on_connection: &BTreeMap<ConnectionScope, Mode>,
        remote: &RemoteId,
        capability: &Name,
    ) -> BTreeSet<KeyId> {
        let named = self
            .configuration
            .rules()
            .keys()
            .map(|scope| &scope.key)
            .chain(on_connection.keys().map(|scope| &scope.key))
            .filter_map(|keys| match keys {
                Keys::Only(KeyName::Grip(grip)) => Some(KeyId::Grip(grip.clone())),
                Keys::Only(KeyName::Ssh(key)) => Some(KeyId::Ssh(key.clone())),
                Keys::Only(KeyName::Fingerprint(_)) | Keys::Every | Keys::NeedingNoTouch => None,
            });
        // A key the source offers is told apart by the name its dialect's
        // requests give it: its keygrip through the Assuan sockets, its SSH
        // public half through the agent's SSH socket.
        let ssh = self
            .configuration
            .capability(self.catalogue, capability)
            .is_ok_and(|found| found.dialect() == Dialect::SshAgent);
        let keyring = self.state.offered(capability);
        let offered = keyring
            .into_iter()
            .flat_map(|keyring| keyring.keys.iter())
            .filter_map(|key| {
                if ssh {
                    key.ssh.clone().map(KeyId::Ssh)
                } else {
                    Some(KeyId::Grip(key.grip.clone()))
                }
            });
        let cards = self.state.keys().filter_map(|grip| {
            if ssh {
                keyring
                    .and_then(|keyring| keyring.by_grip(grip))
                    .and_then(|key| key.ssh.clone())
                    .map(KeyId::Ssh)
            } else {
                Some(KeyId::Grip(grip.clone()))
            }
        });
        let link = self.state.connection(remote).map(|(_, link)| link);
        let lent: Vec<KeyId> = self
            .reached(remote, link, capability)
            .map(|reached| {
                reached
                    .lends
                    .keys()
                    .map(|(key, _)| KeyId::Ssh(key.clone()))
                    .collect()
            })
            .unwrap_or_default();
        named.chain(cards).chain(offered).chain(lent).collect()
    }

    /// How each operation of `capability` would be decided for `remote`: for
    /// a request that names no key, and for each key a statement names or a
    /// card holds whose requests would be decided otherwise.
    fn decides(
        &self,
        on_connection: &BTreeMap<ConnectionScope, Mode>,
        remote: &RemoteId,
        capability: &Capability,
    ) -> Vec<Decides> {
        let keys = self.carried_keys(on_connection, remote, &capability.id);
        let mut decides = Vec::new();
        for operation in capability.dialect().operations() {
            let of = |key: Option<&KeyId>| {
                let resolved = self.resolved(on_connection, remote, capability, *operation, key);
                Decides {
                    operation: *operation,
                    key: key.cloned(),
                    mode: resolved.mode,
                    basis: resolved.basis,
                }
            };
            let unkeyed = of(None);
            let keyed: Vec<Decides> = if *operation == Operation::Connect {
                Vec::new()
            } else {
                keys.iter()
                    .map(|key| of(Some(key)))
                    .filter(|keyed| (keyed.mode, &keyed.basis) != (unkeyed.mode, &unkeyed.basis))
                    .collect()
            };
            decides.push(unkeyed);
            decides.extend(keyed);
        }
        decides
    }

    /// What `remote` holds of the capability `id`, and on which terms.
    /// `link` is the live connection to it, whose own capabilities count.
    ///
    /// # Errors
    ///
    /// Why nothing of `id` is served to `remote`: a name two sources define
    /// differently, a name nothing defines, a denial or no grant, or a grant
    /// that no longer names everything its capability exposes.
    fn reached(
        &self,
        remote: &RemoteId,
        link: Option<&Link>,
        id: &Name,
    ) -> Result<Reached, Refusal> {
        if let Some(name) = self.configuration.collision(self.catalogue, remote) {
            return Err(Refusal::Collides {
                section: crate::refusal::Section::Sets,
                name,
            });
        }
        let capability = self.configuration.capability(self.catalogue, id)?;
        self.within(&capability, remote)?;
        let ungranted = || Refusal::NotGranted {
            capability: id.clone(),
            remote: remote.clone(),
        };
        if self.configuration.denies(self.catalogue, id, remote) {
            return Err(ungranted());
        }
        let granted = self.granting(id, remote).map(|(_, _, terms)| terms);
        let (activation, setup, lends) = match &granted {
            Some(terms) => {
                acknowledged(&capability, terms.acknowledged)?;
                (terms.activation, terms.setup, terms.lends.clone())
            }
            // One added for the connection alone only ever inspects.
            None => match link.filter(|link| link.with.contains(id)) {
                Some(link) => (Activation::OnRequest, Setup::Inspect, link.lends.clone()),
                None => return Err(ungranted()),
            },
        };
        let sets = self.sets();
        let limits = self.policy().limits();
        let (activation, connects) = at_most(
            activation,
            limits.clone().filter_map(|(audience, limit)| match limit {
                Limit::Activation { scope, most } if scope.covers(id, remote, &sets) => {
                    Some(((audience, limit), *most))
                }
                _ => None,
            }),
        );
        let stated = setup;
        let (setup, writes) = at_most(
            setup,
            limits.filter_map(|(audience, limit)| match limit {
                Limit::InspectOnly(scope) if scope.covers(id, remote, &sets) => {
                    Some(((audience, limit), Setup::Inspect))
                }
                _ => None,
            }),
        );
        let holds = [connects, writes]
            .into_iter()
            .flatten()
            .map(|(audience, limit)| Holding {
                holder: Holder::Organisation(audience),
                limit: limit.clone(),
            })
            .collect();
        Ok(Reached {
            capability,
            activation,
            stated,
            setup,
            terms: granted.map(|terms| Terms {
                activation,
                setup,
                ..terms
            }),
            lends,
            holds,
            writes: writes.map(|(audience, limit)| held(audience, limit)),
        })
    }

    /// Whether the organisation's limits let `capability` serve `remote` at
    /// all: none unread, no denial of theirs covers it, and nothing it
    /// exposes is withheld there. A set is admitted whole or refused.
    fn within(&self, capability: &Capability, remote: &RemoteId) -> Result<(), Refusal> {
        let policy = self.policy();
        if let Some(audience) = policy.unreadable() {
            return Err(Refusal::Unread(audience));
        }
        let sets = self.sets();
        let denial = policy.limits().find(|(_, limit)| {
            matches!(limit, Limit::Deny(denial)
                if denial.capability.covers(&capability.id) && denial.remotes.covers(remote, &sets))
        });
        if let Some((audience, limit)) = denial {
            return Err(held(audience, limit));
        }
        let withheld = policy.limits().filter_map(|(audience, limit)| match limit {
            Limit::Withhold { exposure, remotes } if remotes.covers(remote, &sets) => {
                Some(((audience, limit), *exposure))
            }
            Limit::Confine { exposure, remotes } if !remotes.covers(remote, &sets) => {
                Some(((audience, limit), *exposure))
            }
            _ => None,
        });
        admitted(capability.exposure(), withheld)
            .map_err(|((audience, limit), _)| held(audience, limit))
    }

    /// The grant that decides the terms of `id` on `remote`, and those
    /// terms before the organisation's limits hold them: none where a denial
    /// of the person's covers the pair; otherwise the person's grants, then
    /// what the organisation starts this person with, then this machine;
    /// inside one source the narrowest, and of two equally narrow the less
    /// exposing. A starting grant carries what the person accepted of it,
    /// and nothing more.
    pub fn terms(&self, id: &Name, remote: &RemoteId) -> Option<(Through, Terms)> {
        let (tier, remotes, terms) = self.granting(id, remote)?;
        let grant = Grant {
            capability: id.clone(),
            remotes: remotes.clone(),
        };
        let through = match tier {
            Tier::Start(audience) => Through::Start { audience, grant },
            Tier::Person | Tier::Ships => Through::Grant(grant),
        };
        Some((through, terms))
    }

    /// [`World::terms`] without naming the grant, for the path every request
    /// takes.
    fn granting(&self, id: &Name, remote: &RemoteId) -> Option<(Tier, &Granted, Terms)> {
        if self.configuration.denies(self.catalogue, id, remote) {
            return None;
        }
        let sets = self.sets();
        let person = self
            .configuration
            .grants()
            .filter(|(grant, _)| grant.capability == *id && grant.remotes.covers(remote, &sets))
            .map(|(grant, terms)| (&grant.remotes, terms.clone()));
        let start = |audience: Audience| {
            self.policy()
                .start()
                .filter_map(move |(stated_for, start)| match start {
                    Start::Grant { grant, activation }
                        if stated_for == audience
                            && grant.capability == *id
                            && grant.remotes.covers(remote, &sets) =>
                    {
                        let accepted = self.configuration.accepted(grant);
                        let terms = Terms {
                            activation: *activation,
                            setup: accepted.map_or(Setup::Inspect, |accepted| accepted.setup),
                            acknowledged: accepted
                                .map_or(Exposure::NONE, |accepted| accepted.acknowledged),
                            lends: accepted
                                .map_or_else(Lends::none, |accepted| accepted.lends.clone()),
                        };
                        Some((&grant.remotes, terms))
                    }
                    _ => None,
                })
        };
        choose(&person, &start(Audience::Person), &start(Audience::Machine))
    }

    /// What the remote of connection `link` is lent of capability `id`: the
    /// devices, and whether the grant acknowledges `network`, under which
    /// the remote may have the source attach and remove a lent device by its
    /// address. `None` where it holds the capability on no terms.
    pub fn lending(&self, link: &Link, id: &Name) -> Option<(Lends, bool)> {
        let reached = self.reached(&link.remote, Some(link), id).ok()?;
        let acknowledged = reached
            .terms
            .as_ref()
            .map_or(link.acknowledged, |terms| terms.acknowledged);
        let network = !acknowledged.common(Exposure::NETWORK).is_empty();
        Some((reached.lends, network))
    }

    fn granted(&self, link: &Link, id: &Name) -> Result<Capability, Refusal> {
        self.reached(&link.remote, Some(link), id)
            .map(|reached| reached.capability)
    }

    fn held_by(&self, remote: &RemoteId, id: &Name) -> Result<Capability, Refusal> {
        let link = self.state.connection(remote).map(|(_, link)| link);
        self.reached(remote, link, id)
            .map(|reached| reached.capability)
    }

    /// Everything `remote` holds.
    pub(crate) fn reaching(&self, remote: &RemoteId, link: Option<&Link>) -> Vec<Reached> {
        let sets = self.sets();
        let grants = self.grants();
        let granted = grants
            .iter()
            .filter(|(_, grant)| grant.remotes.covers(remote, &sets))
            .map(|(_, grant)| &grant.capability);
        let ids: BTreeSet<&Name> = link
            .iter()
            .flat_map(|link| &link.with)
            .chain(granted)
            .collect();
        ids.into_iter()
            .filter_map(|id| self.reached(remote, link, id).ok())
            .collect()
    }

    /// What gives `remote` the capability `id`: the grant that decides, or
    /// the live connection it was added to. `None` where it is denied or
    /// nothing gives it.
    fn through(&self, remote: &RemoteId, id: &Name) -> Option<Through> {
        if let Some((through, _)) = self.terms(id, remote) {
            return Some(through);
        }
        self.state
            .connection(remote)
            .filter(|(_, link)| link.with.contains(id))
            .map(|(connection, _)| Through::Connection(connection))
    }

    fn platform(&self, link: &Link) -> Result<&Platform, Refusal> {
        let family = link
            .platform
            .as_ref()
            .ok_or_else(|| Refusal::PlatformUnobserved(link.remote.clone()))?;
        self.configuration.platform(self.catalogue, family)
    }

    /// Whether a grant surface may ask `id`'s source for what it holds of
    /// `lent`: only a source that holds such things lends any.
    fn listable(&self, id: &Name, lent: Holds) -> Result<(), Refusal> {
        let capability = self.configuration.capability(self.catalogue, id)?;
        if capability.holds() == Some(lent) {
            Ok(())
        } else {
            Err(Refusal::Unlendable {
                capability: capability.id,
                lent,
            })
        }
    }

    fn connectable(
        &self,
        remote: &RemoteId,
        with: &[Name],
        named: Exposure,
        lends: &Lends,
    ) -> Result<(), Refusal> {
        self.configuration.route(self.catalogue, &remote.route)?;
        self.unwithdrawn()?;
        if self.state.paused(remote, &self.sets()) {
            return Err(Refusal::Paused);
        }
        if let Some(audience) = self.policy().unreadable() {
            return Err(Refusal::Unread(audience));
        }
        let mut lendable_to = None;
        for id in with {
            let capability = self.configuration.capability(self.catalogue, id)?;
            capability.complete()?;
            self.within(&capability, remote)?;
            if self.configuration.denies(self.catalogue, id, remote) {
                return Err(Refusal::NotGranted {
                    capability: capability.id,
                    remote: remote.clone(),
                });
            }
            acknowledged(&capability, named)?;
            // What is lent goes to whichever added capability holds what a
            // grant lends.
            if lendable_to.is_none() || capability.holds().is_some() {
                lendable_to = Some(capability);
            }
        }
        // With nothing added, what is lent applies to nothing.
        lendable_to.map_or(Ok(()), |capability| lendable(&capability, lends))
    }

    fn row(
        &self,
        client: ClientId,
        id: &Name,
        remote: Option<&RemoteId>,
        through: Through,
        now: Tick,
    ) -> Row {
        let live = remote.and_then(|remote| self.state.connection(remote));
        let link = live.map(|(_, link)| link);
        let capability = self.configuration.capability(self.catalogue, id);
        let reached = match remote {
            Some(remote) => self.reached(remote, link, id).map(Some),
            None => capability.as_ref().map(|_| None).map_err(Clone::clone),
        };
        let (terms, holds) = match &reached {
            Ok(Some(reached)) => (reached.terms.clone(), reached.holds.clone()),
            _ => (None, Vec::new()),
        };
        let failing = match self.state.source(id) {
            Some(Health::Failing(failure)) => Some(Refusal::SourceUnavailable {
                capability: id.clone(),
                failure,
            }),
            _ => None,
        };
        let sets = self.sets();
        let standing = match (remote, live, reached) {
            (Some(remote), ..) if self.state.paused(remote, &sets) => Standing::Paused,
            (.., Err(refusal)) => Standing::Unavailable(refusal),
            _ if failing.is_some() => failing.map_or(Standing::Idle, Standing::Unavailable),
            (_, Some((connection, link)), Ok(Some(reached))) => {
                self.standing(connection, link, &reached)
            }
            (Some(remote), None, ..) => match self.state.ended.get(remote) {
                Some((end, _)) => match self.state.returning(remote) {
                    Some(returning) if self.wants(remote).is_some() => Standing::Returning {
                        end: end.clone(),
                        wait: self.back_at(remote, returning).and_then(|at| {
                            let left = at.0.saturating_sub(now.0).div_ceil(1000);
                            NonZeroU32::new(u32::try_from(left).unwrap_or(u32::MAX))
                        }),
                    },
                    _ if *end == ChannelEnd::Closed => Standing::Idle,
                    _ => Standing::Ended(end.clone()),
                },
                None => Standing::Idle,
            },
            _ => Standing::Idle,
        };
        let unruled = BTreeMap::new();
        let rules = link.map_or(&unruled, |link| &link.rules);
        let decides = match (remote, &capability) {
            (Some(remote), Ok(capability)) => self.decides(rules, remote, capability),
            _ => Vec::new(),
        };
        let acts = self.acts(id, remote, &through);
        Row {
            capability: id.clone(),
            exposure: capability
                .as_ref()
                .map_or(Exposure::NONE, Capability::exposure),
            remote: remote.cloned(),
            connection: live.map(|(connection, _)| connection),
            through,
            standing,
            decides,
            terms,
            holds,
            last: remote
                .and_then(|remote| self.state.last.get(&(remote.clone(), id.clone())).cloned()),
            findings: self.findings(link, remote, id),
            written: remote
                .map(|remote| {
                    self.state
                        .written(remote)
                        .filter(|(capability, _, _, _)| *capability == id)
                        .map(|(_, write, place, made)| Written {
                            write: write.clone(),
                            place: place.clone(),
                            made: made.cloned(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            carried: remote
                .and_then(|remote| self.state.carried(remote, id))
                .into_iter()
                .flatten()
                .map(|(carriage, endpoint)| CarriedOn {
                    carriage: carriage.clone(),
                    endpoint: *endpoint,
                })
                .collect(),
            hold: remote.and_then(|remote| self.state.hold(remote, id)),
            beyond: capability
                .as_ref()
                .map_or_else(|_| Vec::new(), |capability| self.beyond(capability)),
            acts: acts
                .into_iter()
                .map(|(act, request)| Offered {
                    act,
                    withheld: self.permit(client, &request).err(),
                })
                .collect(),
        }
    }

    /// What a row says the remote's tool cannot be given through
    /// `capability`: a serial port last opened over its chip's own USB.
    fn beyond(&self, capability: &Capability) -> Vec<Beyond> {
        match &capability.source {
            Source::Serial { port, .. } => {
                Beyond::of_port(self.state.seen(port)).into_iter().collect()
            }
            _ => Vec::new(),
        }
    }

    /// The acts a row shows and the request each one sends. The row carries
    /// the answer [`World::permit`] gives that request, so the row and the
    /// reply cannot disagree.
    fn acts(
        &self,
        capability: &Name,
        remote: Option<&RemoteId>,
        through: &Through,
    ) -> Vec<(Act, Request)> {
        let mut acts = Vec::new();
        if let Some(remote) = remote {
            let one = Remotes::One(remote.clone());
            acts.push(if self.state.connection(remote).is_some() {
                (
                    Act::Disconnect,
                    Request::Disconnect {
                        remote: remote.clone(),
                    },
                )
            } else {
                (
                    Act::Connect,
                    Request::Connect {
                        remote: remote.clone(),
                        with: Vec::new(),
                        acknowledged: Exposure::NONE,
                        lends: Lends::none(),
                    },
                )
            });
            acts.push(if self.state.paused(remote, &self.sets()) {
                (Act::Resume, Request::Resume(one))
            } else {
                (Act::Pause, Request::Pause(one))
            });
            acts.push((
                Act::Check,
                Request::Check {
                    remote: remote.clone(),
                    capability: capability.clone(),
                },
            ));
            acts.push((
                Act::Exercise,
                Request::Exercise {
                    remote: remote.clone(),
                    capability: capability.clone(),
                },
            ));
        }
        match through {
            Through::Grant(grant) => {
                acts.push((Act::Revoke, Request::Change(Change::Revoke(grant.clone()))));
            }
            Through::Start { grant, .. } => {
                let denial = Denial {
                    capability: Selector::Only(grant.capability.clone()),
                    remotes: grant.remotes.clone().into(),
                };
                acts.push((Act::Deny, Request::Change(Change::Deny(denial))));
                let given = self.configuration.accepted(grant);
                let needed = self
                    .configuration
                    .capability(self.catalogue, &grant.capability)
                    .map_or(Exposure::NONE, |capability| {
                        capability.exposure().common(Exposure::ACKNOWLEDGED)
                    });
                let named = given.map_or(Exposure::NONE, |given| given.acknowledged);
                if !needed.without(named).is_empty() {
                    let accepted = Accepted {
                        setup: given.map_or(Setup::Inspect, |given| given.setup),
                        acknowledged: needed,
                        lends: given.map_or_else(Lends::none, |given| given.lends.clone()),
                    };
                    let accept = Change::Accept {
                        grant: grant.clone(),
                        accepted,
                    };
                    acts.push((Act::Accept, Request::Change(accept)));
                }
            }
            Through::Connection(_) => {}
        }
        acts
    }

    /// What readiness last named for `id` on `remote`: on the live
    /// connection, or on the last one while none is live.
    fn findings(&self, link: Option<&Link>, remote: Option<&RemoteId>, id: &Name) -> Vec<Finding> {
        if let Some(link) = link {
            return match link.readiness.get(id) {
                Some(Readiness::Unready(findings)) => findings.clone(),
                _ => Vec::new(),
            };
        }
        remote
            .and_then(|remote| self.state.unready.get(&(remote.clone(), id.clone())))
            .map(|(findings, _)| findings.clone())
            .unwrap_or_default()
    }

    fn standing(&self, connection: ConnectionId, link: &Link, reached: &Reached) -> Standing {
        let capability = &reached.capability;
        if let Some(prompt) = self
            .state
            .prompts
            .values()
            .find(|prompt| prompt.connection == connection)
        {
            return Standing::Needs(prompt.kind);
        }
        let carried = match self.plan(connection) {
            Ok(plan) => plan
                .get(&capability.id)
                .cloned()
                .map_or(Ok(()), |form| form.map(drop)),
            Err(Refusal::PlatformUnobserved(_)) => Ok(()),
            Err(refusal) => Err(refusal),
        };
        if let Err(refusal) = carried {
            return Standing::Unavailable(refusal);
        }
        if let Some(Readiness::Unready(findings)) = link.readiness.get(&capability.id)
            && findings.iter().any(Finding::blocks)
        {
            return Standing::Unready(findings.clone());
        }
        match &link.phase {
            Phase::Up(serving) => serving
                .iter()
                .find(|serving| serving.capability == capability.id)
                .map_or(Standing::Opening, |serving| {
                    Standing::Serving(serving.binding.clone())
                }),
            Phase::Opening
                if matches!(link.opener, Opener::Check(_)) && link.platform.is_none() =>
            {
                Standing::Checking
            }
            Phase::Opening => Standing::Opening,
        }
    }
}
