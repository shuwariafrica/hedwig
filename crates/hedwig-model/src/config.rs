//! Everything the person configures, as one value.
//!
//! A [`Configuration`] is built by [`Configuration::apply`] and
//! [`Configuration::import`], which put every statement made through the same
//! checks, and by [`Configuration::restore`], which reads back what the person
//! stored and refuses none of it for what has since changed around it.
//! [`Document`] is its plain, ordered form.

use std::collections::{BTreeMap, BTreeSet};

use crate::beyond::Beyond;
use crate::capability::{Capability, Exposure, Holds, Lends, Setup, Source};
use crate::organisation::Policy;
use crate::platform::{Platform, Sockets};
use crate::policy::{Mode, RuleScope, Selector};
use crate::refusal::{Refusal, Section};
use crate::remote::{Discovery, Granted, Member, Named, RemoteId, Remotes, Route, Set, Sets};
use crate::scope::{Audience, Strict, Tier};
use crate::setting::{
    Autostart, Cadence, CapScope, Condition, Diagnostics, Expected, FullScreen, Heard, Keep,
    Keepalive, Lengths, Longest, Returns, Routes, Threshold,
};
use crate::text::{Kernel, Name, SshKey};

/// The version of the document form.
pub const DOCUMENT: u32 = 2;

/// When the core holds a channel to a granted remote. Ordered from least to
/// most exposing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Activation {
    /// Only when the person connects.
    OnRequest,
    /// While the route's platform reports the remote running.
    WhileRunning,
    /// Always, reconnecting when the channel drops.
    Continuous,
}

/// What is granted, to which remotes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Grant {
    pub capability: Name,
    pub remotes: Granted,
}

/// The terms a grant is given on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Terms {
    pub activation: Activation,
    pub setup: Setup,
    /// The exposure the person named when granting. A grant whose capability
    /// exposes more than this serves nothing.
    pub acknowledged: Exposure,
    /// The devices lent, where the capability's source holds devices; none
    /// otherwise.
    pub lends: Lends,
}

impl Strict for Terms {
    /// Of two sets of terms the less exposing is the stricter.
    fn strictness(&self, other: &Self) -> std::cmp::Ordering {
        other.cmp(self)
    }
}

/// What only the person can give a grant the organisation starts them with:
/// the exposure they name, whether the core may write a remote tool's own
/// configuration, and the devices they lend.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Accepted {
    pub setup: Setup,
    pub acknowledged: Exposure,
    /// The devices the person lends: only they know which are theirs.
    pub lends: Lends,
}

/// A capability withheld from remotes a wider grant would reach. A denial
/// beats every grant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Denial {
    pub capability: Selector<Name>,
    pub remotes: Remotes,
}

/// Definitions in their plain form: the catalogue as it ships and as a client
/// receives it, and what an organisation's starting point defines.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reference {
    pub capabilities: Vec<Capability>,
    pub routes: Vec<Route>,
    pub platforms: Vec<Platform>,
    pub sets: Vec<Set>,
}

/// A definition from outside the person's document, and whose it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defined<T> {
    pub definition: T,
    /// What ships, or the organisation's starting point and for whom.
    pub by: Tier,
}

/// A name two sources define differently. Nothing that goes by it is served
/// until all but one rename their definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision {
    pub section: Section,
    pub name: Name,
    /// Every source that defines it, the person among them where they do.
    pub by: Vec<Tier>,
}

/// What a surface lists beside the person's own definitions: each one
/// defined outside their document with whose it is, and every collision.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Definitions {
    pub capabilities: Vec<Defined<Capability>>,
    pub routes: Vec<Defined<Route>>,
    pub platforms: Vec<Defined<Platform>>,
    pub sets: Vec<Defined<Set>>,
    pub collisions: Vec<Collision>,
    /// What a remote's tool cannot be given, for a surface a capability is
    /// defined from: what is absent, with why.
    pub beyond: Vec<Beyond>,
}

impl Definitions {
    /// Takes `name` out of the definitions of `section`, which now collides.
    fn forget(&mut self, section: Section, name: &Name) {
        match section {
            Section::Capabilities => self.capabilities.retain(|d| d.definition.id != *name),
            Section::Routes => self.routes.retain(|d| d.definition.id != *name),
            Section::Platforms => self.platforms.retain(|d| d.definition.family != *name),
            Section::Sets => self.sets.retain(|d| d.definition.id != *name),
            _ => {}
        }
    }
}

/// Everything defined outside the person's own document: the presets, routes
/// and platform profiles Hedwig ships, joined with what the organisation's
/// starting point defines. It is reference data in the same form as a
/// person's own definitions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Catalogue {
    capabilities: BTreeMap<Name, Source>,
    routes: BTreeMap<Name, Route>,
    platforms: BTreeMap<Name, Platform>,
    sets: Named,
    /// The names the organisation defines, and for whom.
    organisation: BTreeMap<(Section, Name), Audience>,
    /// The names two sources define differently, with the sources: each is
    /// shown, and nothing that goes by it is served until one is renamed.
    collided: BTreeMap<(Section, Name), BTreeSet<Tier>>,
    /// What ships, where this catalogue joins an organisation's definitions
    /// to it.
    shipped: Option<Box<Catalogue>>,
}

impl Catalogue {
    /// Builds what ships from its plain form.
    ///
    /// # Errors
    ///
    /// [`Refusal::Reserved`] when a name appears twice in one list: two
    /// entries never collide silently.
    pub fn new(reference: Reference) -> Result<Catalogue, Refusal> {
        let Reference {
            capabilities,
            routes,
            platforms,
            sets,
        } = reference;
        let mut catalogue = Catalogue::default();
        for Capability { id, source } in capabilities {
            if catalogue.capabilities.insert(id.clone(), source).is_some() {
                return Err(Refusal::Reserved(id));
            }
        }
        for route in routes {
            let id = route.id.clone();
            if catalogue.routes.insert(id.clone(), route).is_some() {
                return Err(Refusal::Reserved(id));
            }
        }
        for platform in platforms {
            let family = platform.family.clone();
            if catalogue
                .platforms
                .insert(family.clone(), platform)
                .is_some()
            {
                return Err(Refusal::Reserved(family));
            }
        }
        for Set { id, members } in sets {
            let members = members.into_iter().collect();
            if catalogue.sets.insert(id.clone(), members).is_some() {
                return Err(Refusal::Reserved(id));
            }
        }
        Ok(catalogue)
    }

    /// What ships, joined with what `policy` defines: the catalogue every
    /// decision under that policy reads. No source outranks another: a name
    /// defined twice alike is one definition, and one defined twice
    /// differently is a collision, kept as such.
    #[must_use]
    pub fn under(&self, policy: &Policy) -> Catalogue {
        let shipped = self
            .shipped
            .clone()
            .unwrap_or_else(|| Box::new(self.clone()));
        let mut joined = (*shipped).clone();
        joined.shipped = Some(shipped);
        let (machine, person) = (
            policy.reference(Audience::Machine),
            policy.reference(Audience::Person),
        );
        for (audience, reference) in [(Audience::Machine, &machine), (Audience::Person, &person)] {
            for Capability { id, source } in &reference.capabilities {
                let known = joined.capabilities.get(id).cloned();
                if joined.define(Section::Capabilities, audience, id, known.as_ref(), source) {
                    joined.capabilities.insert(id.clone(), source.clone());
                } else {
                    joined.capabilities.remove(id);
                }
            }
            for route in &reference.routes {
                let known = joined.routes.get(&route.id).cloned();
                if joined.define(Section::Routes, audience, &route.id, known.as_ref(), route) {
                    joined.routes.insert(route.id.clone(), route.clone());
                } else {
                    joined.routes.remove(&route.id);
                }
            }
            for platform in &reference.platforms {
                let family = &platform.family;
                let known = joined.platforms.get(family).cloned();
                if joined.define(
                    Section::Platforms,
                    audience,
                    family,
                    known.as_ref(),
                    platform,
                ) {
                    joined.platforms.insert(family.clone(), platform.clone());
                } else {
                    joined.platforms.remove(family);
                }
            }
            for Set { id, members } in &reference.sets {
                let members: BTreeSet<Member> = members.iter().cloned().collect();
                let known = joined.sets.get(id).cloned();
                joined.define(Section::Sets, audience, id, known.as_ref(), &members);
                // A set whose name collides keeps every member either source
                // gave it: what narrows by the name still covers them all.
                joined.sets.entry(id.clone()).or_default().extend(members);
            }
        }
        joined
    }

    /// Records one definition from the organisation, and answers whether the
    /// name now has exactly that definition.
    fn define<T: PartialEq>(
        &mut self,
        section: Section,
        audience: Audience,
        id: &Name,
        known: Option<&T>,
        offered: &T,
    ) -> bool {
        let named = (section, id.clone());
        if let Some(sources) = self.collided.get_mut(&named) {
            sources.insert(Tier::Start(audience));
            return false;
        }
        match known {
            None => {
                self.organisation.insert(named, audience);
                true
            }
            Some(known) if known == offered => true,
            Some(_) => {
                let first = self
                    .organisation
                    .remove(&named)
                    .map_or(Tier::Ships, Tier::Start);
                let sources = BTreeSet::from([first, Tier::Start(audience)]);
                self.collided.insert(named, sources);
                false
            }
        }
    }

    pub fn reference(&self) -> Reference {
        Reference {
            capabilities: self
                .capabilities
                .iter()
                .map(|(id, source)| Capability {
                    id: id.clone(),
                    source: source.clone(),
                })
                .collect(),
            routes: self.routes.values().cloned().collect(),
            platforms: self.platforms.values().cloned().collect(),
            sets: listed(&self.sets),
        }
    }

    /// A route by name: the client that reaches its remotes, how they are
    /// listed, and what stands for their identity.
    pub fn route(&self, id: &Name) -> Option<&Route> {
        self.routes.get(id)
    }

    /// Whether two sources outside the person's document define `id`
    /// differently.
    pub fn collides(&self, section: Section, id: &Name) -> bool {
        self.collided.contains_key(&(section, id.clone()))
    }

    /// Every name two sources outside the person's document define
    /// differently.
    pub fn collisions(&self) -> impl Iterator<Item = (Section, &Name)> {
        self.collided.keys().map(|(section, id)| (*section, id))
    }

    /// Each definition here with whose it is, and every name two sources
    /// outside the person's document define differently, with the sources. A
    /// name that collides is listed only as a collision: it defines nothing
    /// until one source renames it.
    fn defined(&self) -> Definitions {
        let by = |section: Section, id: &Name| {
            self.organisation
                .get(&(section, id.clone()))
                .map_or(Tier::Ships, |audience| Tier::Start(*audience))
        };
        let clear = |section: Section, id: &Name| !self.collides(section, id);
        Definitions {
            capabilities: self
                .capabilities
                .iter()
                .filter(|(id, _)| clear(Section::Capabilities, id))
                .map(|(id, source)| Defined {
                    definition: Capability {
                        id: id.clone(),
                        source: source.clone(),
                    },
                    by: by(Section::Capabilities, id),
                })
                .collect(),
            routes: self
                .routes
                .values()
                .filter(|route| clear(Section::Routes, &route.id))
                .map(|route| Defined {
                    definition: route.clone(),
                    by: by(Section::Routes, &route.id),
                })
                .collect(),
            platforms: self
                .platforms
                .values()
                .filter(|platform| clear(Section::Platforms, &platform.family))
                .map(|platform| Defined {
                    definition: platform.clone(),
                    by: by(Section::Platforms, &platform.family),
                })
                .collect(),
            sets: listed(&self.sets)
                .into_iter()
                .filter(|set| clear(Section::Sets, &set.id))
                .map(|set| Defined {
                    by: by(Section::Sets, &set.id),
                    definition: set,
                })
                .collect(),
            beyond: Beyond::ALL.to_vec(),
            collisions: self
                .collided
                .iter()
                .map(|((section, name), by)| Collision {
                    section: *section,
                    name: name.clone(),
                    by: by.iter().copied().collect(),
                })
                .collect(),
        }
    }

    /// Where the definition of `id` comes from: what ships, or the
    /// organisation's starting point. `None` for a name nothing here defines.
    pub fn tier(&self, section: Section, id: &Name) -> Option<Tier> {
        let defined = match section {
            Section::Capabilities => self.capabilities.contains_key(id),
            Section::Routes => self.routes.contains_key(id),
            Section::Platforms => self.platforms.contains_key(id),
            Section::Sets => self.sets.contains_key(id),
            _ => false,
        };
        let audience = self.organisation.get(&(section, id.clone()));
        defined.then(|| audience.map_or(Tier::Ships, |audience| Tier::Start(*audience)))
    }
}

fn listed(sets: &Named) -> Vec<Set> {
    sets.iter()
        .map(|(id, members)| Set {
            id: id.clone(),
            members: members.iter().cloned().collect(),
        })
        .collect()
}

/// One change to the configuration. Every variant is idempotent: applying it
/// twice leaves what applying it once left. A choice is cleared by stating
/// `None`, which leaves the nearer sources to say.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Change {
    Grant {
        grant: Grant,
        terms: Terms,
    },
    Revoke(Grant),
    /// Give a grant the organisation starts the person with what only the
    /// person can: the exposure it names, and consent to write.
    Accept {
        grant: Grant,
        accepted: Accepted,
    },
    Unaccept(Grant),
    Deny(Denial),
    Undeny(Denial),
    Rule {
        scope: RuleScope,
        mode: Mode,
    },
    Unrule(RuleScope),
    Define(Capability),
    Undefine(Name),
    DefinePlatform(Platform),
    UndefinePlatform(Name),
    DefineRoute(Route),
    UndefineRoute(Name),
    DefineSet(Set),
    UndefineSet(Name),
    /// When volume from these remotes is brought to the person's attention.
    Burst {
        remotes: Remotes,
        threshold: Option<Threshold>,
    },
    /// How loudly a condition on these remotes reaches the person.
    Hear {
        remotes: Remotes,
        heard: Heard,
    },
    Unhear {
        remotes: Remotes,
        condition: Condition,
    },
    /// Put a refusal from one remote away for good.
    Expect(Expected),
    Unexpect(Expected),
    /// Whether a held request from these remotes is shown over an
    /// application that fills the screen.
    FullScreen {
        remotes: Remotes,
        card: Option<FullScreen>,
    },
    /// The lengths "allow for a time" offers.
    Lengths(Option<Lengths>),
    /// The longest an allowance for what the scope covers may last.
    Cap {
        scope: CapScope,
        longest: Option<Longest>,
    },
    Autostart(Option<Autostart>),
    /// Whether Windows starts the icon when the person signs in at a desktop.
    Icon(Option<Autostart>),
    /// How many days of activity the trail keeps.
    Keep(Option<Keep>),
    /// What the core writes about what went wrong, from now on.
    Diagnostics(Option<Diagnostics>),
    /// How a channel's client to these remotes notices a dead link.
    Keepalive {
        remotes: Remotes,
        keepalive: Option<Keepalive>,
    },
    /// The waits before a lost channel to these remotes is opened again.
    Returns {
        remotes: Remotes,
        returns: Option<Returns>,
    },
    /// How often these routes' platforms are asked which remotes run.
    Cadence {
        routes: Routes,
        cadence: Option<Cadence>,
    },
}

/// Whether an idempotent act found anything to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    Changed,
    Unchanged,
}

/// Whether a change can let a remote reach more, or be served with less
/// asked of the person, than before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reach {
    Wider,
    NoWider,
}

/// One grant with its terms, as a document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantEntry {
    pub grant: Grant,
    pub terms: Terms,
}

/// One of the organisation's grants the person accepted, as a document lists
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedEntry {
    pub grant: Grant,
    pub accepted: Accepted,
}

/// One standing rule, as a document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleEntry {
    pub scope: RuleScope,
    pub mode: Mode,
}

/// One burst threshold, as a document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstEntry {
    pub remotes: Remotes,
    pub threshold: Threshold,
}

/// One volume, as a document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeardEntry {
    pub remotes: Remotes,
    pub heard: Heard,
}

/// One statement about an application that fills the screen, as a document
/// lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullScreenEntry {
    pub remotes: Remotes,
    pub card: FullScreen,
}

/// One cap on allowances, as a document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapEntry {
    pub scope: CapScope,
    pub longest: Longest,
}

/// One keepalive, as a document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeepaliveEntry {
    pub remotes: Remotes,
    pub keepalive: Keepalive,
}

/// One pace of return, as a document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnsEntry {
    pub remotes: Remotes,
    pub returns: Returns,
}

/// One cadence of listing, as a document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CadenceEntry {
    pub routes: Routes,
    pub cadence: Cadence,
}

/// The exported form: complete, ordered, and the only thing import reads. A
/// choice the person has not made is `null`, and the nearer sources say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub version: u32,
    pub capabilities: Vec<Capability>,
    pub platforms: Vec<Platform>,
    pub routes: Vec<Route>,
    pub sets: Vec<Set>,
    pub grants: Vec<GrantEntry>,
    pub accepted: Vec<AcceptedEntry>,
    pub denials: Vec<Denial>,
    pub rules: Vec<RuleEntry>,
    pub bursts: Vec<BurstEntry>,
    pub heard: Vec<HeardEntry>,
    pub expected: Vec<Expected>,
    pub full_screen: Vec<FullScreenEntry>,
    pub lengths: Option<Lengths>,
    pub caps: Vec<CapEntry>,
    pub autostart: Option<Autostart>,
    pub icon: Option<Autostart>,
    pub keep: Option<Keep>,
    pub diagnostics: Option<Diagnostics>,
    pub keepalives: Vec<KeepaliveEntry>,
    pub returns: Vec<ReturnsEntry>,
    pub cadences: Vec<CadenceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Configuration {
    capabilities: BTreeMap<Name, Source>,
    platforms: BTreeMap<Name, Platform>,
    routes: BTreeMap<Name, Route>,
    sets: Named,
    grants: BTreeMap<Grant, Terms>,
    accepted: BTreeMap<Grant, Accepted>,
    denials: BTreeSet<Denial>,
    rules: BTreeMap<RuleScope, Mode>,
    bursts: BTreeMap<Remotes, Threshold>,
    heard: BTreeMap<(Remotes, Condition), Heard>,
    expected: BTreeSet<Expected>,
    full_screen: BTreeMap<Remotes, FullScreen>,
    lengths: Option<Lengths>,
    caps: BTreeMap<CapScope, Longest>,
    autostart: Option<Autostart>,
    icon: Option<Autostart>,
    keep: Option<Keep>,
    diagnostics: Option<Diagnostics>,
    keepalives: BTreeMap<Remotes, Keepalive>,
    returns: BTreeMap<Remotes, Returns>,
    cadences: BTreeMap<Routes, Cadence>,
}

/// Sets a choice, or with `None` clears it.
fn state<K: Ord, V>(stated: &mut BTreeMap<K, V>, key: K, value: Option<V>) {
    match value {
        Some(value) => stated.insert(key, value),
        None => stated.remove(&key),
    };
}

impl Configuration {
    /// Applies one change, or refuses it and leaves the configuration as it
    /// was.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] naming the rule the statement made would break.
    pub fn apply(&mut self, catalogue: &Catalogue, change: Change) -> Result<Effect, Refusal> {
        let mut next = self.clone();
        next.make(catalogue, change)?;
        if next == *self {
            return Ok(Effect::Unchanged);
        }
        *self = next;
        Ok(Effect::Changed)
    }

    /// Makes one statement and checks what it touches.
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per change, each with the check that change owes"
    )]
    fn make(&mut self, catalogue: &Catalogue, change: Change) -> Result<(), Refusal> {
        match change {
            Change::Grant { grant, terms } => {
                self.grants.insert(grant.clone(), terms.clone());
                self.check_grant(catalogue, &grant, &terms)
            }
            Change::Revoke(grant) => {
                self.grants.remove(&grant);
                Ok(())
            }
            Change::Accept { grant, accepted } => {
                self.accepted.insert(grant.clone(), accepted.clone());
                self.check_accepted(catalogue, &grant, &accepted)
            }
            Change::Unaccept(grant) => {
                self.accepted.remove(&grant);
                Ok(())
            }
            Change::Deny(denial) => {
                self.denials.insert(denial.clone());
                self.check_denial(catalogue, &denial)
            }
            Change::Undeny(denial) => {
                self.denials.remove(&denial);
                Ok(())
            }
            Change::Rule { scope, mode } => {
                self.rules.insert(scope.clone(), mode);
                self.check_rule(catalogue, &scope)
            }
            Change::Unrule(scope) => {
                self.rules.remove(&scope);
                Ok(())
            }
            Change::Define(Capability { id, source }) => {
                self.capabilities.insert(id.clone(), source);
                self.check_capability(catalogue, &id)
            }
            Change::Undefine(id) => {
                self.capabilities.remove(&id);
                if self.names(&id) {
                    return Err(Refusal::CapabilityInUse(id));
                }
                Ok(())
            }
            Change::DefinePlatform(platform) => {
                let family = platform.family.clone();
                self.platforms.insert(family.clone(), platform);
                reserved(catalogue, Section::Platforms, &family)?;
                self.check_platform(catalogue, &family)
            }
            Change::UndefinePlatform(family) => {
                self.platforms.remove(&family);
                Ok(())
            }
            Change::DefineRoute(route) => {
                let id = route.id.clone();
                self.routes.insert(id.clone(), route);
                self.check_route(catalogue, &id)
            }
            Change::UndefineRoute(id) => {
                self.routes.remove(&id);
                if self.goes_by(&id) {
                    return Err(Refusal::RouteInUse(id));
                }
                Ok(())
            }
            Change::DefineSet(Set { id, members }) => {
                let distinct: BTreeSet<Member> = members.iter().cloned().collect();
                if distinct.len() != members.len() {
                    return Err(Refusal::Repeated(Section::Sets));
                }
                self.sets.insert(id.clone(), distinct);
                self.check_set(catalogue, &id)
            }
            Change::UndefineSet(id) => {
                self.sets.remove(&id);
                if self.selects(&id) {
                    return Err(Refusal::SetInUse(id));
                }
                Ok(())
            }
            Change::Burst { remotes, threshold } => {
                self.routed(catalogue, &remotes)?;
                state(&mut self.bursts, remotes, threshold);
                Ok(())
            }
            Change::Hear { remotes, heard } => {
                self.routed(catalogue, &remotes)?;
                self.heard.insert((remotes, heard.condition()), heard);
                Ok(())
            }
            Change::Unhear { remotes, condition } => {
                self.heard.remove(&(remotes, condition));
                Ok(())
            }
            Change::Expect(expected) => {
                self.route(catalogue, &expected.remote.route)?;
                self.expected.insert(expected);
                Ok(())
            }
            Change::Unexpect(expected) => {
                self.expected.remove(&expected);
                Ok(())
            }
            Change::FullScreen { remotes, card } => {
                self.routed(catalogue, &remotes)?;
                state(&mut self.full_screen, remotes, card);
                Ok(())
            }
            Change::Lengths(lengths) => {
                self.lengths = lengths;
                Ok(())
            }
            Change::Cap { scope, longest } => {
                self.routed(catalogue, &scope.remotes)?;
                state(&mut self.caps, scope, longest);
                Ok(())
            }
            Change::Autostart(autostart) => {
                self.autostart = autostart;
                Ok(())
            }
            Change::Icon(icon) => {
                self.icon = icon;
                Ok(())
            }
            Change::Keep(keep) => {
                self.keep = keep;
                Ok(())
            }
            Change::Diagnostics(diagnostics) => {
                self.diagnostics = diagnostics;
                Ok(())
            }
            Change::Keepalive { remotes, keepalive } => {
                self.routed(catalogue, &remotes)?;
                state(&mut self.keepalives, remotes, keepalive);
                Ok(())
            }
            Change::Returns { remotes, returns } => {
                self.routed(catalogue, &remotes)?;
                state(&mut self.returns, remotes, returns);
                Ok(())
            }
            Change::Cadence { routes, cadence } => {
                self.lists(catalogue, &routes)?;
                state(&mut self.cadences, routes, cadence);
                Ok(())
            }
        }
    }

    /// Builds a configuration from a document, whole or not at all: every
    /// statement in it is made now, and meets the checks a single change
    /// meets.
    ///
    /// # Errors
    ///
    /// [`Refusal::DocumentVersion`], [`Refusal::Repeated`], or the refusal
    /// [`Configuration::apply`] would give for the offending entry.
    pub fn import(catalogue: &Catalogue, document: Document) -> Result<Configuration, Refusal> {
        let next = Configuration::restore(document)?;
        next.check(catalogue)?;
        Ok(next)
    }

    /// Reads back a document the person stored. Nothing in it is refused for
    /// what it means: a name that is no longer defined, or that another
    /// source now defines too, is a statement that serves nothing until that
    /// is resolved, never a document that cannot be read.
    ///
    /// # Errors
    ///
    /// [`Refusal::DocumentVersion`] and [`Refusal::Repeated`]: a document of
    /// another form, or one that lists an entry twice.
    pub fn restore(document: Document) -> Result<Configuration, Refusal> {
        if document.version != DOCUMENT {
            return Err(Refusal::DocumentVersion {
                found: document.version,
                supported: DOCUMENT,
            });
        }
        let mut next = Configuration {
            lengths: document.lengths,
            autostart: document.autostart,
            icon: document.icon,
            keep: document.keep,
            diagnostics: document.diagnostics,
            ..Configuration::default()
        };
        let once = |fresh: bool, section: Section| {
            if fresh {
                Ok(())
            } else {
                Err(Refusal::Repeated(section))
            }
        };
        for Capability { id, source } in document.capabilities {
            let fresh = next.capabilities.insert(id, source).is_none();
            once(fresh, Section::Capabilities)?;
        }
        for platform in document.platforms {
            let fresh = next
                .platforms
                .insert(platform.family.clone(), platform)
                .is_none();
            once(fresh, Section::Platforms)?;
        }
        for route in document.routes {
            let fresh = next.routes.insert(route.id.clone(), route).is_none();
            once(fresh, Section::Routes)?;
        }
        for Set { id, members } in document.sets {
            let distinct: BTreeSet<Member> = members.iter().cloned().collect();
            let fresh = distinct.len() == members.len() && next.sets.insert(id, distinct).is_none();
            once(fresh, Section::Sets)?;
        }
        for GrantEntry { grant, terms } in document.grants {
            once(next.grants.insert(grant, terms).is_none(), Section::Grants)?;
        }
        for AcceptedEntry { grant, accepted } in document.accepted {
            let fresh = next.accepted.insert(grant, accepted).is_none();
            once(fresh, Section::Accepted)?;
        }
        for denial in document.denials {
            once(next.denials.insert(denial), Section::Denials)?;
        }
        for RuleEntry { scope, mode } in document.rules {
            once(next.rules.insert(scope, mode).is_none(), Section::Rules)?;
        }
        for BurstEntry { remotes, threshold } in document.bursts {
            let fresh = next.bursts.insert(remotes, threshold).is_none();
            once(fresh, Section::Bursts)?;
        }
        for HeardEntry { remotes, heard } in document.heard {
            let fresh = next
                .heard
                .insert((remotes, heard.condition()), heard)
                .is_none();
            once(fresh, Section::Heard)?;
        }
        for expected in document.expected {
            once(next.expected.insert(expected), Section::Expected)?;
        }
        for FullScreenEntry { remotes, card } in document.full_screen {
            let fresh = next.full_screen.insert(remotes, card).is_none();
            once(fresh, Section::FullScreen)?;
        }
        for CapEntry { scope, longest } in document.caps {
            once(next.caps.insert(scope, longest).is_none(), Section::Caps)?;
        }
        for KeepaliveEntry { remotes, keepalive } in document.keepalives {
            let fresh = next.keepalives.insert(remotes, keepalive).is_none();
            once(fresh, Section::Keepalives)?;
        }
        for ReturnsEntry { remotes, returns } in document.returns {
            let fresh = next.returns.insert(remotes, returns).is_none();
            once(fresh, Section::Returns)?;
        }
        for CadenceEntry { routes, cadence } in document.cadences {
            let fresh = next.cadences.insert(routes, cadence).is_none();
            once(fresh, Section::Cadences)?;
        }
        Ok(next)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one field per section of the document"
    )]
    pub fn export(&self) -> Document {
        Document {
            version: DOCUMENT,
            capabilities: self
                .capabilities
                .iter()
                .map(|(id, source)| Capability {
                    id: id.clone(),
                    source: source.clone(),
                })
                .collect(),
            platforms: self.platforms.values().cloned().collect(),
            routes: self.routes.values().cloned().collect(),
            sets: listed(&self.sets),
            grants: self
                .grants
                .iter()
                .map(|(grant, terms)| GrantEntry {
                    grant: grant.clone(),
                    terms: terms.clone(),
                })
                .collect(),
            accepted: self
                .accepted
                .iter()
                .map(|(grant, accepted)| AcceptedEntry {
                    grant: grant.clone(),
                    accepted: accepted.clone(),
                })
                .collect(),
            denials: self.denials.iter().cloned().collect(),
            rules: self
                .rules
                .iter()
                .map(|(scope, mode)| RuleEntry {
                    scope: scope.clone(),
                    mode: *mode,
                })
                .collect(),
            bursts: self
                .bursts
                .iter()
                .map(|(remotes, threshold)| BurstEntry {
                    remotes: remotes.clone(),
                    threshold: *threshold,
                })
                .collect(),
            heard: self
                .heard
                .iter()
                .map(|((remotes, _), heard)| HeardEntry {
                    remotes: remotes.clone(),
                    heard: *heard,
                })
                .collect(),
            expected: self.expected.iter().cloned().collect(),
            full_screen: self
                .full_screen
                .iter()
                .map(|(remotes, card)| FullScreenEntry {
                    remotes: remotes.clone(),
                    card: *card,
                })
                .collect(),
            lengths: self.lengths.clone(),
            caps: self
                .caps
                .iter()
                .map(|(scope, longest)| CapEntry {
                    scope: scope.clone(),
                    longest: *longest,
                })
                .collect(),
            autostart: self.autostart,
            icon: self.icon,
            keep: self.keep,
            diagnostics: self.diagnostics,
            keepalives: self
                .keepalives
                .iter()
                .map(|(remotes, keepalive)| KeepaliveEntry {
                    remotes: remotes.clone(),
                    keepalive: *keepalive,
                })
                .collect(),
            returns: self
                .returns
                .iter()
                .map(|(remotes, returns)| ReturnsEntry {
                    remotes: remotes.clone(),
                    returns: *returns,
                })
                .collect(),
            cadences: self
                .cadences
                .iter()
                .map(|(routes, cadence)| CadenceEntry {
                    routes: routes.clone(),
                    cadence: *cadence,
                })
                .collect(),
        }
    }

    /// A capability by name: the person's own definition, or the one defined
    /// outside their document.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownCapability`] when nothing defines the name, and
    /// [`Refusal::Collides`] when two sources define it differently.
    pub fn capability(&self, catalogue: &Catalogue, id: &Name) -> Result<Capability, Refusal> {
        let source = defined(
            catalogue,
            Section::Capabilities,
            id,
            self.capabilities.get(id),
            catalogue.capabilities.get(id),
        )?;
        source
            .map(|source| Capability {
                id: id.clone(),
                source: source.clone(),
            })
            .ok_or_else(|| Refusal::UnknownCapability(id.clone()))
    }

    /// A platform profile by the family a remote reports.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownPlatform`] and [`Refusal::Collides`], as for a
    /// capability.
    pub fn platform<'a>(
        &'a self,
        catalogue: &'a Catalogue,
        family: &Name,
    ) -> Result<&'a Platform, Refusal> {
        defined(
            catalogue,
            Section::Platforms,
            family,
            self.platforms.get(family),
            catalogue.platforms.get(family),
        )?
        .ok_or_else(|| Refusal::UnknownPlatform(family.clone()))
    }

    /// The platform whose profile answers to what a remote calls its own
    /// system, as readiness read it there. The person's definitions and the
    /// catalogue's are one set here, as for [`Configuration::platform`].
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownKernel`] when no profile answers to it;
    /// [`Refusal::KernelClaimed`] when two do, since which one the remote is
    /// cannot then be said; and what [`Configuration::platform`] refuses for
    /// the one that answers.
    pub fn platform_answering<'a>(
        &'a self,
        catalogue: &'a Catalogue,
        kernel: &Kernel,
    ) -> Result<&'a Platform, Refusal> {
        let families: BTreeSet<&Name> = self
            .platforms
            .values()
            .chain(catalogue.platforms.values())
            .filter(|platform| platform.kernel == *kernel)
            .map(|platform| &platform.family)
            .collect();
        let mut families = families.into_iter();
        match (families.next(), families.next()) {
            (None, _) => Err(Refusal::UnknownKernel(kernel.clone())),
            (Some(family), None) => self.platform(catalogue, family),
            (Some(first), Some(second)) => Err(Refusal::KernelClaimed {
                kernel: kernel.clone(),
                first: first.clone(),
                second: second.clone(),
            }),
        }
    }

    /// A route by name.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownRoute`] and [`Refusal::Collides`], as for a
    /// capability.
    pub fn route<'a>(&'a self, catalogue: &'a Catalogue, id: &Name) -> Result<&'a Route, Refusal> {
        defined(
            catalogue,
            Section::Routes,
            id,
            self.routes.get(id),
            catalogue.routes.get(id),
        )?
        .ok_or_else(|| Refusal::UnknownRoute(id.clone()))
    }

    /// The named sets a selection of remotes is read against: the person's
    /// own, and the ones defined outside their document.
    pub fn sets<'a>(&'a self, catalogue: &'a Catalogue) -> Sets<'a> {
        Sets::new(&self.sets, &catalogue.sets)
    }

    /// A set two sources define differently of which `remote` is a member
    /// under either definition. Nothing is served to such a remote until the
    /// name means one thing.
    pub fn collision(&self, catalogue: &Catalogue, remote: &RemoteId) -> Option<Name> {
        let sets = self.sets(catalogue);
        let between = self
            .sets
            .iter()
            .filter(|(id, members)| {
                catalogue
                    .sets
                    .get(*id)
                    .is_some_and(|other| other != *members)
            })
            .map(|(id, _)| id);
        let outside = catalogue
            .collisions()
            .filter(|(section, _)| *section == Section::Sets)
            .map(|(_, id)| id);
        between
            .chain(outside)
            .find(|id| sets.holds(id, remote))
            .cloned()
    }

    /// Everything defined outside the person's document, with whose each
    /// definition is, and every name two sources define differently - the
    /// person's own definitions among them - with the sources: what a surface
    /// lists beside the person's own definitions.
    pub fn definitions(&self, catalogue: &Catalogue) -> Definitions {
        let mut definitions = catalogue.defined();
        let mut theirs: Vec<(Section, &Name, bool)> = Vec::new();
        theirs.extend(self.capabilities.iter().map(|(id, source)| {
            let differs = catalogue
                .capabilities
                .get(id)
                .is_some_and(|other| other != source);
            (Section::Capabilities, id, differs)
        }));
        theirs.extend(self.routes.iter().map(|(id, route)| {
            let differs = catalogue.routes.get(id).is_some_and(|other| other != route);
            (Section::Routes, id, differs)
        }));
        theirs.extend(self.platforms.iter().map(|(family, platform)| {
            let differs = catalogue
                .platforms
                .get(family)
                .is_some_and(|other| other != platform);
            (Section::Platforms, family, differs)
        }));
        theirs.extend(self.sets.iter().map(|(id, members)| {
            let differs = catalogue.sets.get(id).is_some_and(|other| other != members);
            (Section::Sets, id, differs)
        }));
        for (section, name, differs) in theirs {
            if let Some(known) = definitions
                .collisions
                .iter_mut()
                .find(|collision| collision.section == section && collision.name == *name)
            {
                known.by.push(Tier::Person);
                continue;
            }
            if !differs {
                continue;
            }
            let outside = catalogue.tier(section, name).unwrap_or(Tier::Ships);
            definitions.forget(section, name);
            definitions.collisions.push(Collision {
                section,
                name: name.clone(),
                by: vec![outside, Tier::Person],
            });
        }
        definitions
    }

    /// Whether a denial withholds `capability` from `remote`.
    pub fn denies(&self, catalogue: &Catalogue, capability: &Name, remote: &RemoteId) -> bool {
        let sets = self.sets(catalogue);
        self.denials.iter().any(|denial| {
            denial.capability.covers(capability) && denial.remotes.covers(remote, &sets)
        })
    }

    pub fn grants(&self) -> impl Iterator<Item = (&Grant, &Terms)> + Clone {
        self.grants.iter()
    }

    /// What the person gave the organisation's grant `grant`, if anything.
    pub fn accepted(&self, grant: &Grant) -> Option<&Accepted> {
        self.accepted.get(grant)
    }

    /// The changes after which no grant and no acceptance lends `key`: what
    /// deleting it from the TPM is preceded by, each applied and recorded as
    /// any change is. A grant of every key lends what its source holds, so it
    /// needs none.
    pub fn unlending(&self, key: &SshKey) -> Vec<Change> {
        let without = |lends: &Lends| match lends {
            Lends::Named { devices, keys } if keys.contains_key(key) => Some(Lends::Named {
                devices: devices.clone(),
                keys: keys
                    .iter()
                    .filter(|(lent, _)| *lent != key)
                    .map(|(lent, how)| (lent.clone(), how.clone()))
                    .collect(),
            }),
            Lends::Named { .. } | Lends::Every => None,
        };
        let grants = self.grants.iter().filter_map(|(grant, terms)| {
            without(&terms.lends).map(|lends| Change::Grant {
                grant: grant.clone(),
                terms: Terms {
                    lends,
                    ..terms.clone()
                },
            })
        });
        let accepted = self.accepted.iter().filter_map(|(grant, accepted)| {
            without(&accepted.lends).map(|lends| Change::Accept {
                grant: grant.clone(),
                accepted: Accepted {
                    lends,
                    ..accepted.clone()
                },
            })
        });
        grants.chain(accepted).collect()
    }

    /// The person's standing rules.
    pub fn rules(&self) -> &BTreeMap<RuleScope, Mode> {
        &self.rules
    }

    /// The person's burst thresholds, by the remotes each is for.
    pub fn bursts(&self) -> &BTreeMap<Remotes, Threshold> {
        &self.bursts
    }

    /// The volumes the person chose, each with the remotes it is for.
    pub fn heard(&self) -> impl Iterator<Item = (&Remotes, Heard)> + Clone {
        self.heard
            .iter()
            .map(|((remotes, _), heard)| (remotes, *heard))
    }

    /// Whether the person put this refusal from this remote away for good.
    pub fn expects(&self, remote: &RemoteId, refusal: &Refusal) -> bool {
        self.expected
            .iter()
            .any(|expected| expected.remote == *remote && expected.refusal == *refusal)
    }

    /// The person's statements about an application that fills the screen.
    pub fn full_screen(&self) -> &BTreeMap<Remotes, FullScreen> {
        &self.full_screen
    }

    /// The lengths the person chose to be offered, if they chose.
    pub fn lengths(&self) -> Option<&Lengths> {
        self.lengths.as_ref()
    }

    /// The person's caps on their own allowances.
    pub fn caps(&self) -> &BTreeMap<CapScope, Longest> {
        &self.caps
    }

    /// Whether the person said Hedwig starts at logon, if they said.
    pub fn autostart(&self) -> Option<Autostart> {
        self.autostart
    }

    /// Whether the person said the icon starts at logon, if they said.
    pub fn icon(&self) -> Option<Autostart> {
        self.icon
    }

    /// How many days of activity the person said the trail keeps, if they
    /// said.
    pub fn keep(&self) -> Option<Keep> {
        self.keep
    }

    /// What the person said the core writes about what went wrong, if they
    /// said.
    pub fn diagnostics(&self) -> Option<Diagnostics> {
        self.diagnostics
    }

    /// The person's keepalives, by the remotes each is for.
    pub fn keepalives(&self) -> &BTreeMap<Remotes, Keepalive> {
        &self.keepalives
    }

    /// The person's paces of return, by the remotes each is for.
    pub fn returns(&self) -> &BTreeMap<Remotes, Returns> {
        &self.returns
    }

    /// The person's cadences of listing, by the routes each is for.
    pub fn cadences(&self) -> &BTreeMap<Routes, Cadence> {
        &self.cadences
    }

    /// Whether `change`, made now, can let a remote reach more or be served
    /// with less asked of the person. It errs towards saying so: a change
    /// that might is one that reaches the person.
    pub fn widens(&self, catalogue: &Catalogue, change: &Change) -> Reach {
        // A capability nothing defines is refused when the change is made.
        let moves = |capability: &Name, from: Setup, to: Setup| {
            self.capability(catalogue, capability)
                .map_or(true, |capability| capability.widens(from, to))
        };
        let wider = match change {
            Change::Grant { grant, terms } => self.grants.get(grant).is_none_or(|held| {
                terms.activation > held.activation
                    || moves(&grant.capability, held.setup, terms.setup)
                    || !terms.acknowledged.without(held.acknowledged).is_empty()
                    || terms.lends.exceeds(&held.lends)
            }),
            // The grant revoked may be the narrowest of several, and the next
            // one's terms then decide.
            Change::Revoke(grant) => self
                .grants
                .keys()
                .any(|other| other != grant && other.capability == grant.capability),
            Change::Accept { grant, accepted } => self.accepted.get(grant).is_none_or(|held| {
                moves(&grant.capability, held.setup, accepted.setup)
                    || !accepted.acknowledged.without(held.acknowledged).is_empty()
                    || accepted.lends.exceeds(&held.lends)
            }),
            Change::Undeny(denial) => self.denials.contains(denial),
            Change::Rule { scope, mode } => {
                *mode != Mode::Confirm && self.rules.get(scope).is_none_or(|held| mode < held)
            }
            Change::Unrule(scope) => self
                .rules
                .get(scope)
                .is_some_and(|held| *held != Mode::Unattended),
            Change::Define(Capability { id, source }) => {
                self.names(id) && self.capabilities.get(id) != Some(source)
            }
            // The family's remotes move to the forms the other shape of
            // sockets takes, or a remote whose system nothing answered to is
            // carried at all.
            Change::DefinePlatform(platform) => {
                self.platform(catalogue, &platform.family)
                    .map_or(true, |held| {
                        held.kernel != platform.kernel
                            || !same_shape(held.sockets, platform.sockets)
                    })
            }
            Change::DefineRoute(route) => {
                self.goes_by(&route.id) && self.routes.get(&route.id) != Some(route)
            }
            Change::DefineSet(Set { id, members }) => {
                let members: BTreeSet<Member> = members.iter().cloned().collect();
                self.selects(id) && self.sets.get(id) != Some(&members)
            }
            Change::Cap { scope, longest } => self
                .caps
                .get(scope)
                .is_some_and(|held| longest.is_none_or(|longest| longest > *held)),
            // Nothing outside the document defines a name the person
            // defines, so what is undefined is gone.
            Change::Unaccept(_)
            | Change::Deny(_)
            | Change::Undefine(_)
            | Change::UndefinePlatform(_)
            | Change::UndefineRoute(_)
            | Change::UndefineSet(_)
            | Change::Burst { .. }
            | Change::Hear { .. }
            | Change::Unhear { .. }
            | Change::Expect(_)
            | Change::Unexpect(_)
            | Change::FullScreen { .. }
            | Change::Lengths(_)
            | Change::Autostart(_)
            | Change::Icon(_)
            | Change::Keep(_)
            | Change::Diagnostics(_)
            | Change::Keepalive { .. }
            | Change::Returns { .. }
            | Change::Cadence { .. } => false,
        };
        if wider { Reach::Wider } else { Reach::NoWider }
    }

    /// Whether replacing this configuration with `next` can let more
    /// through: anything but the same exposure with grants taken away and
    /// denials added.
    pub fn widens_to(&self, next: &Configuration) -> Reach {
        let narrower = next.capabilities == self.capabilities
            && next.routes == self.routes
            && next.sets == self.sets
            && next.rules == self.rules
            && next.caps == self.caps
            && next
                .grants
                .iter()
                .all(|(grant, terms)| self.grants.get(grant) == Some(terms))
            && next
                .accepted
                .iter()
                .all(|(grant, accepted)| self.accepted.get(grant) == Some(accepted))
            && self.denials.is_subset(&next.denials);
        if narrower {
            Reach::NoWider
        } else {
            Reach::Wider
        }
    }

    fn names(&self, id: &Name) -> bool {
        let only = Selector::Only(id.clone());
        self.grants.keys().any(|grant| grant.capability == *id)
            || self.accepted.keys().any(|grant| grant.capability == *id)
            || self.denials.iter().any(|denial| denial.capability == only)
            || self.rules.keys().any(|scope| scope.capability == only)
    }

    /// Every selection of remotes the person's statements make.
    fn selections(&self) -> impl Iterator<Item = Remotes> {
        let granted = self.grants.keys().chain(self.accepted.keys());
        let grants = granted.map(|grant| Remotes::from(grant.remotes.clone()));
        let denials = self.denials.iter().map(|denial| denial.remotes.clone());
        let rules = self.rules.keys().map(|scope| scope.remotes.clone());
        let bursts = self.bursts.keys().cloned();
        let heard = self.heard.keys().map(|(remotes, _)| remotes.clone());
        let expected = self
            .expected
            .iter()
            .map(|expected| Remotes::One(expected.remote.clone()));
        let full_screen = self.full_screen.keys().cloned();
        let caps = self.caps.keys().map(|scope| scope.remotes.clone());
        let keepalives = self.keepalives.keys().cloned();
        let returns = self.returns.keys().cloned();
        let cadences = self.cadences.keys().filter_map(|routes| match routes {
            Selector::Every => None,
            Selector::Only(route) => Some(Remotes::Route(route.clone())),
        });
        grants
            .chain(denials)
            .chain(rules)
            .chain(bursts)
            .chain(heard)
            .chain(expected)
            .chain(full_screen)
            .chain(caps)
            .chain(keepalives)
            .chain(returns)
            .chain(cadences)
    }

    /// Whether a statement or a set of the person's own selects remotes on
    /// the route `id`.
    fn goes_by(&self, id: &Name) -> bool {
        let directly = self.selections().any(|remotes| match remotes {
            Remotes::Every | Remotes::Set(_) => false,
            Remotes::Route(route) | Remotes::Matching { route, .. } => route == *id,
            Remotes::One(remote) => remote.route == *id,
        });
        let through_a_set = self
            .sets
            .values()
            .flatten()
            .any(|member| member.route() == id);
        directly || through_a_set
    }

    /// Whether a statement of the person's selects the set `id`.
    pub fn selects(&self, id: &Name) -> bool {
        self.selections().any(|remotes| remotes.set() == Some(id))
    }

    /// Every statement, checked as one made now.
    fn check(&self, catalogue: &Catalogue) -> Result<(), Refusal> {
        for id in self.capabilities.keys() {
            reserved(catalogue, Section::Capabilities, id)?;
        }
        for family in self.platforms.keys() {
            reserved(catalogue, Section::Platforms, family)?;
            self.check_platform(catalogue, family)?;
        }
        for id in self.routes.keys() {
            reserved(catalogue, Section::Routes, id)?;
        }
        for id in self.sets.keys() {
            self.check_set(catalogue, id)?;
        }
        for (grant, terms) in &self.grants {
            self.check_grant(catalogue, grant, terms)?;
        }
        for (grant, accepted) in &self.accepted {
            self.check_accepted(catalogue, grant, accepted)?;
        }
        for denial in &self.denials {
            self.check_denial(catalogue, denial)?;
        }
        for scope in self.rules.keys() {
            self.check_rule(catalogue, scope)?;
        }
        let selections = self
            .bursts
            .keys()
            .chain(self.heard.keys().map(|(remotes, _)| remotes))
            .chain(self.full_screen.keys())
            .chain(self.caps.keys().map(|scope| &scope.remotes))
            .chain(self.keepalives.keys())
            .chain(self.returns.keys());
        for remotes in selections {
            self.routed(catalogue, remotes)?;
        }
        for routes in self.cadences.keys() {
            self.lists(catalogue, routes)?;
        }
        for expected in &self.expected {
            self.route(catalogue, &expected.remote.route)?;
        }
        Ok(())
    }

    fn check_grant(
        &self,
        catalogue: &Catalogue,
        grant: &Grant,
        terms: &Terms,
    ) -> Result<(), Refusal> {
        let capability = self.capability(catalogue, &grant.capability)?;
        capability.complete()?;
        let remotes = Remotes::from(grant.remotes.clone());
        self.routed(catalogue, &remotes)?;
        if terms.activation == Activation::WhileRunning {
            self.listed(catalogue, &remotes)?;
        }
        acknowledged(&capability, terms.acknowledged)?;
        lendable(&capability, &terms.lends)
    }

    fn check_accepted(
        &self,
        catalogue: &Catalogue,
        grant: &Grant,
        accepted: &Accepted,
    ) -> Result<(), Refusal> {
        let capability = self.capability(catalogue, &grant.capability)?;
        self.routed(catalogue, &Remotes::from(grant.remotes.clone()))?;
        acknowledged(&capability, accepted.acknowledged)?;
        lendable(&capability, &accepted.lends)
    }

    fn check_denial(&self, catalogue: &Catalogue, denial: &Denial) -> Result<(), Refusal> {
        if let Selector::Only(id) = &denial.capability {
            self.capability(catalogue, id)?;
        }
        self.routed(catalogue, &denial.remotes)
    }

    fn check_rule(&self, catalogue: &Catalogue, scope: &RuleScope) -> Result<(), Refusal> {
        self.routed(catalogue, &scope.remotes)?;
        let Selector::Only(id) = &scope.capability else {
            return Ok(());
        };
        let capability = self.capability(catalogue, id)?;
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

    /// A definition of the person's own: its name is theirs to use, and
    /// every grant and rule that names it still holds of it.
    fn check_capability(&self, catalogue: &Catalogue, id: &Name) -> Result<(), Refusal> {
        reserved(catalogue, Section::Capabilities, id)?;
        // A site no request could ever be served for is refused where it is
        // named, not at the first push.
        if let Some(Source::Credentials { sites, .. }) = self.capabilities.get(id)
            && let Some(site) = sites.iter().find(|site| site.cleartext())
        {
            return Err(Refusal::Cleartext {
                capability: id.clone(),
                site: site.clone(),
            });
        }
        let only = Selector::Only(id.clone());
        for (grant, terms) in &self.grants {
            if grant.capability == *id {
                self.check_grant(catalogue, grant, terms)?;
            }
        }
        for scope in self.rules.keys() {
            if scope.capability == only {
                self.check_rule(catalogue, scope)?;
            }
        }
        Ok(())
    }

    /// Whether the person's profile `family` answers to a system no other
    /// profile answers to: two that do would leave every remote of that
    /// system with no platform, so the second is refused where it is made.
    fn check_platform(&self, catalogue: &Catalogue, family: &Name) -> Result<(), Refusal> {
        let Some(platform) = self.platforms.get(family) else {
            return Ok(());
        };
        match self.platform_answering(catalogue, &platform.kernel) {
            Err(claimed @ Refusal::KernelClaimed { .. }) => Err(claimed),
            _ => Ok(()),
        }
    }

    fn check_route(&self, catalogue: &Catalogue, id: &Name) -> Result<(), Refusal> {
        reserved(catalogue, Section::Routes, id)?;
        let sets = self.sets(catalogue);
        for (grant, terms) in &self.grants {
            let remotes = Remotes::from(grant.remotes.clone());
            if terms.activation == Activation::WhileRunning && remotes.routes(&sets).contains(id) {
                self.listed(catalogue, &remotes)?;
            }
        }
        Ok(())
    }

    fn check_set(&self, catalogue: &Catalogue, id: &Name) -> Result<(), Refusal> {
        reserved(catalogue, Section::Sets, id)?;
        for member in self.sets.get(id).into_iter().flatten() {
            self.route(catalogue, member.route())?;
        }
        for (grant, terms) in &self.grants {
            if terms.activation == Activation::WhileRunning
                && grant.remotes == Granted::Set(id.clone())
            {
                self.listed(catalogue, &Remotes::from(grant.remotes.clone()))?;
            }
        }
        Ok(())
    }

    /// Whether every route and the set a selection names are defined.
    fn routed(&self, catalogue: &Catalogue, remotes: &Remotes) -> Result<(), Refusal> {
        let sets = self.sets(catalogue);
        if let Some(id) = remotes.set() {
            if !sets.defines(id) {
                return Err(Refusal::UnknownSet(id.clone()));
            }
            let own = self.sets.get(id);
            let differs =
                own.is_some_and(|own| catalogue.sets.get(id).is_some_and(|other| other != own));
            if differs || catalogue.collides(Section::Sets, id) {
                return Err(Refusal::Collides {
                    section: Section::Sets,
                    name: id.clone(),
                });
            }
        }
        for route in remotes.routes(&sets) {
            self.route(catalogue, route)?;
        }
        Ok(())
    }

    /// Whether a route a cadence names is defined and lists its remotes.
    fn lists(&self, catalogue: &Catalogue, routes: &Routes) -> Result<(), Refusal> {
        let Selector::Only(id) = routes else {
            return Ok(());
        };
        if self.route(catalogue, id)?.discovery() == Discovery::Blind {
            return Err(Refusal::Unlisted(id.clone()));
        }
        Ok(())
    }

    /// Whether every route a selection names can say which of its remotes
    /// are running, as a grant that follows a workspace's life needs.
    fn listed(&self, catalogue: &Catalogue, remotes: &Remotes) -> Result<(), Refusal> {
        for id in remotes.routes(&self.sets(catalogue)) {
            if self.route(catalogue, id)?.discovery() == Discovery::Blind {
                return Err(Refusal::ActivationNeedsDiscovery { route: id.clone() });
            }
        }
        Ok(())
    }
}

/// Whether the person may define `id`: a name defined outside their document
/// is not theirs to use.
fn reserved(catalogue: &Catalogue, section: Section, id: &Name) -> Result<(), Refusal> {
    if catalogue.tier(section, id).is_some() || catalogue.collides(section, id) {
        Err(Refusal::Reserved(id.clone()))
    } else {
        Ok(())
    }
}

fn same_shape(one: Sockets, other: Sockets) -> bool {
    matches!(
        (one, other),
        (Sockets::Unix { .. }, Sockets::Unix { .. }) | (Sockets::Emulated, Sockets::Emulated)
    )
}

/// The one definition `id` has between the person's document and what is
/// defined outside it; `None` when neither defines it.
fn defined<'a, T: PartialEq>(
    catalogue: &Catalogue,
    section: Section,
    id: &Name,
    own: Option<&'a T>,
    outside: Option<&'a T>,
) -> Result<Option<&'a T>, Refusal> {
    let differs = matches!((own, outside), (Some(own), Some(outside)) if own != outside);
    if differs || catalogue.collides(section, id) {
        return Err(Refusal::Collides {
            section,
            name: id.clone(),
        });
    }
    Ok(own.or(outside))
}

/// Whether `lends` names only what `capability`'s source holds.
///
/// # Errors
///
/// [`Refusal::Unlendable`] where it lends what the source does not hold: a
/// device of an agent's, a key of a server's, or either of a source that
/// holds neither, everything included.
pub fn lendable(capability: &Capability, lends: &Lends) -> Result<(), Refusal> {
    let holds = capability.holds();
    let unheld = match lends {
        Lends::Named { devices, keys } => [
            (!devices.is_empty()).then_some(Holds::Devices),
            (!keys.is_empty()).then_some(Holds::Keys),
        ]
        .into_iter()
        .flatten()
        .find(|lent| Some(*lent) != holds),
        Lends::Every => match holds {
            Some(_) => None,
            None => Some(Holds::Devices),
        },
    };
    match unheld {
        None => Ok(()),
        Some(lent) => Err(Refusal::Unlendable {
            capability: capability.id.clone(),
            lent,
        }),
    }
}

/// Whether `named` covers everything `capability` exposes that a grant must
/// name.
///
/// # Errors
///
/// [`Refusal::ExposureNotAcknowledged`] with what is not named.
pub fn acknowledged(capability: &Capability, named: Exposure) -> Result<(), Refusal> {
    let missing = capability
        .exposure()
        .common(Exposure::ACKNOWLEDGED)
        .without(named);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Refusal::ExposureNotAcknowledged {
            capability: capability.id.clone(),
            missing,
        })
    }
}
