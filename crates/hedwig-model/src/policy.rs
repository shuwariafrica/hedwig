//! What the core does with a request it is able to serve, and which statement
//! decides that: the first instance of a choice held by limits
//! ([`crate::scope`]).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::capability::{Exposure, Operation};
use crate::remote::{RemoteId, Remotes, Sets};
use crate::scope::{Audience, Specific, Strict, Tier, at_least, choose};
use crate::text::{Fingerprint, Grip, KeyId, Name, SshKey};
use crate::trail::{Key, Touch};

/// Ordered from least to most strict; where two statements are equally
/// specific the stricter one decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// Served and recorded whether or not anything reaches the person.
    Unattended,
    /// Served and recorded while a surface reaches the person; refused
    /// otherwise.
    Notify,
    /// Held until the person allows or refuses it.
    Confirm,
}

impl Strict for Mode {
    fn strictness(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}

/// A mode that needs a surface to reach the person: all an organisation's
/// starting point can choose. Serving with nobody there is only ever a rule
/// the person writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attended {
    Notify,
    Confirm,
}

impl From<Attended> for Mode {
    fn from(attended: Attended) -> Mode {
        match attended {
            Attended::Notify => Mode::Notify,
            Attended::Confirm => Mode::Confirm,
        }
    }
}

/// What ships, and the last thing the choice falls to: confirm a stream opened
/// to anything that manages keys or releases a secret, and notify for
/// everything else. Invariant: no source restates it, and every source's
/// statement is read against it.
pub fn default_mode(operation: Operation, exposure: Exposure) -> Mode {
    if operation == Operation::Connect && opens_more(exposure) {
        Mode::Confirm
    } else {
        Mode::Notify
    }
}

/// Whether a stream opened to a capability of this exposure releases what no
/// operation after its opening decides: key management or a secret, which
/// pass as soon as the stream is open. Such an opening is decided on its own;
/// any other carries nothing its operations do not each decide.
pub fn opens_more(exposure: Exposure) -> bool {
    !exposure
        .common(Exposure::KEY_MANAGEMENT.with(Exposure::SECRET))
        .is_empty()
}

/// Every member of a vocabulary, or one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Selector<T> {
    Every,
    Only(T),
}

impl<T: PartialEq> Selector<T> {
    pub fn covers(&self, value: &T) -> bool {
        match self {
            Selector::Every => true,
            Selector::Only(only) => only == value,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Selector::Every => 0,
            Selector::Only(_) => 1,
        }
    }
}

/// The key a request would use: the key its dialect named, the key the
/// capability's source offers by that keygrip, and what its card asks for
/// before it is used, where the core has read that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Used<'a> {
    pub id: &'a KeyId,
    pub key: Option<&'a Key>,
    pub touch: Option<Touch>,
}

/// How a statement names a key: as the person and their tools know it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyName {
    /// An `OpenPGP` key by a fingerprint: a primary key's names the key and
    /// every subkey of it, a subkey's that subkey alone.
    Fingerprint(Fingerprint),
    /// A key by the keygrip gpg-agent knows it by: what names a key that has
    /// no `OpenPGP` fingerprint.
    Grip(Grip),
    /// An SSH key by its public half, as an agent's request names it.
    Ssh(SshKey),
}

impl KeyName {
    /// Whether a request using `used` uses the key this names, by whichever
    /// dialect it came: the source's keyring ties a key's keygrip, its
    /// fingerprints and its SSH public half together. A name the core cannot
    /// tie to the key a request names is not taken for it.
    pub fn names(&self, used: &Used<'_>) -> bool {
        match self {
            KeyName::Fingerprint(named) => used
                .key
                .is_some_and(|key| key.fingerprint == *named || key.primary == *named),
            KeyName::Grip(grip) => {
                matches!(used.id, KeyId::Grip(used) if used == grip)
                    || used.key.is_some_and(|key| key.grip == *grip)
            }
            KeyName::Ssh(ssh) => {
                matches!(used.id, KeyId::Ssh(used) if used == ssh)
                    || used.key.is_some_and(|key| key.ssh.as_ref() == Some(ssh))
            }
        }
    }
}

/// The keys a statement is about, widest first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Keys {
    /// Whatever key a request uses, and requests that use none.
    Every,
    /// Every key that can be used with nobody at its card: one on no card,
    /// one any card holding it asks no touch for, and one whose card the core
    /// has not read or did not say. A key on several cards needs a touch only
    /// where every one of them asks for one, since any of them can sign.
    NeedingNoTouch,
    Only(KeyName),
}

impl Keys {
    pub fn covers(&self, used: Option<Used<'_>>) -> bool {
        match (self, used) {
            (Keys::Every, _) => true,
            (Keys::NeedingNoTouch, Some(used)) => {
                !matches!(used.touch, Some(Touch::On | Touch::Cached))
            }
            (Keys::Only(name), Some(used)) => name.names(&used),
            (Keys::NeedingNoTouch | Keys::Only(_), None) => false,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Keys::Every => 0,
            Keys::NeedingNoTouch => 1,
            Keys::Only(_) => 2,
        }
    }
}

/// What a standing rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleScope {
    pub remotes: Remotes,
    pub capability: Selector<Name>,
    pub operation: Selector<Operation>,
    pub key: Keys,
}

/// What a rule set on one live connection applies to. It ends with that
/// connection, which is what bounds it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionScope {
    pub capability: Selector<Name>,
    pub operation: Selector<Operation>,
    pub key: Keys,
}

/// What a limit moved, and the limit that moved it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Limited {
    /// Whom the organisation stated the limit for.
    pub audience: Audience,
    /// What the limit covers.
    pub scope: RuleScope,
    /// The mode the choice gave before the limit held it.
    pub chose: Mode,
    /// The statement that choice came from.
    pub basis: Basis,
}

/// Where a request's mode comes from, so a surface can say why.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Basis {
    /// No statement applies; what ships for what the capability exposes.
    Default,
    /// The organisation's starting point.
    Start {
        audience: Audience,
        scope: RuleScope,
    },
    /// One of the person's standing rules.
    Rule(RuleScope),
    /// A rule set on the connection the request came through.
    Connection(ConnectionScope),
    /// An organisation's limit, which moved what one of the others chose.
    Limit(Box<Limited>),
}

/// A request's mode and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub mode: Mode,
    pub basis: Basis,
}

/// Every statement about how requests are decided, by who made it.
#[derive(Debug, Clone, Copy)]
pub struct Rules<'a> {
    /// The person's standing rules.
    pub person: &'a BTreeMap<RuleScope, Mode>,
    /// The rules the person set on the connection the request came through.
    pub connection: &'a BTreeMap<ConnectionScope, Mode>,
    /// The organisation's starting point.
    pub start: &'a [(Audience, RuleScope, Attended)],
    /// The organisation's limits: no request a scope covers is decided less
    /// strictly than its mode.
    pub floors: &'a [(Audience, RuleScope, Mode)],
}

/// What a request is, as far as deciding it goes.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    pub remote: &'a RemoteId,
    /// The named sets a selection of remotes is read against.
    pub sets: Sets<'a>,
    pub capability: &'a Name,
    pub exposure: Exposure,
    pub operation: Operation,
    pub used: Option<Used<'a>>,
}

impl RuleScope {
    pub fn covers(&self, subject: &Subject<'_>) -> bool {
        self.remotes.covers(subject.remote, &subject.sets)
            && self.capability.covers(subject.capability)
            && self.operation.covers(&subject.operation)
            && self.key.covers(subject.used)
    }
}

impl ConnectionScope {
    pub fn covers(&self, subject: &Subject<'_>) -> bool {
        self.capability.covers(subject.capability)
            && self.operation.covers(&subject.operation)
            && self.key.covers(subject.used)
    }
}

/// The rank of a connection's own rules on the remote axis, above every
/// standing scope.
const CONNECTION: u8 = 4;

/// One statement of either scope, so the person's standing rules and what
/// they said on the connection resolve as one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stated<'a> {
    Standing(&'a RuleScope),
    Connection(&'a ConnectionScope),
}

impl Stated<'_> {
    /// Where the statement stands on the two axes it can be specific on:
    /// what it selects - the remote first, then the capability, then the
    /// operation - and which keys.
    fn rank(&self) -> ((u8, u8, u8), u8) {
        match self {
            Stated::Standing(scope) => (
                (
                    scope.remotes.rank(),
                    scope.capability.rank(),
                    scope.operation.rank(),
                ),
                scope.key.rank(),
            ),
            Stated::Connection(scope) => (
                (CONNECTION, scope.capability.rank(), scope.operation.rank()),
                scope.key.rank(),
            ),
        }
    }
}

impl Specific for Stated<'_> {
    fn specificity(&self, other: &Self) -> Option<Ordering> {
        let (selects, keys) = self.rank();
        let (against, other_keys) = other.rank();
        match (selects.cmp(&against), keys.cmp(&other_keys)) {
            (Ordering::Equal, by) | (by, Ordering::Equal) => Some(by),
            (selects, keys) if selects == keys => Some(selects),
            _ => None,
        }
    }
}

/// Resolves the mode for one request.
///
/// A choice: the person's statements decide where any covers the request -
/// the most specific of them, a rule on the connection above every standing
/// one - then the organisation's starting point, then what ships. A statement
/// naming a key and one naming only a remote are each specific where the
/// other is not, and then, as between two patterns that select the same
/// remote, the stricter decides. A starting point never decides less strictly
/// than what ships: that part waits for a rule of the person's own.
///
/// Then the limits: the result is no less strict than any floor that covers
/// the request, and is left alone when it is already inside them all.
pub fn resolve(rules: &Rules<'_>, subject: &Subject<'_>) -> Resolved {
    hold(rules, subject, chosen(rules, subject))
}

/// Resolves the mode for the opening of a stream that carries nothing its
/// operations do not each decide, given how each request it can carry would
/// be decided: every operation of its dialect, with every key one can name.
///
/// A statement that names the opening itself decides it, as for any other
/// request. Otherwise the opening is decided as leniently as the most lenient
/// of what it carries, since refusing it would refuse that request unasked,
/// and each request is decided again when it arrives; of two as lenient, the
/// opening's own choice. The limits that cover the opening then hold it.
pub fn resolve_opening(
    rules: &Rules<'_>,
    subject: &Subject<'_>,
    carried: impl IntoIterator<Item = Resolved>,
) -> Resolved {
    let own = chosen(rules, subject);
    if own.basis.names(subject.operation) {
        return hold(rules, subject, own);
    }
    let lenient = carried.into_iter().fold(
        own,
        |least, next| if next.mode < least.mode { next } else { least },
    );
    hold(rules, subject, lenient)
}

impl Basis {
    /// Whether the statement this basis names speaks of `operation` itself,
    /// rather than of every operation.
    fn names(&self, operation: Operation) -> bool {
        let named = |selected: &Selector<Operation>| *selected == Selector::Only(operation);
        match self {
            Basis::Default => false,
            Basis::Start { scope, .. } | Basis::Rule(scope) => named(&scope.operation),
            Basis::Connection(scope) => named(&scope.operation),
            Basis::Limit(limited) => limited.basis.names(operation),
        }
    }
}

/// The choice alone, before any limit holds it.
fn chosen(rules: &Rules<'_>, subject: &Subject<'_>) -> Resolved {
    let ships = default_mode(subject.operation, subject.exposure);
    let standing = rules
        .person
        .iter()
        .filter(|(scope, _)| scope.covers(subject))
        .map(|(scope, mode)| (Stated::Standing(scope), *mode));
    let connection = rules
        .connection
        .iter()
        .filter(|(scope, _)| scope.covers(subject))
        .map(|(scope, mode)| (Stated::Connection(scope), *mode));
    let start = |audience: Audience| {
        rules
            .start
            .iter()
            .filter(move |(stated_for, scope, _)| *stated_for == audience && scope.covers(subject))
            .map(|(_, scope, attended)| (Stated::Standing(scope), Mode::from(*attended)))
            .filter(move |(_, mode)| *mode >= ships)
    };
    choose(
        &standing.chain(connection),
        &start(Audience::Person),
        &start(Audience::Machine),
    )
    .map_or(
        Resolved {
            mode: ships,
            basis: Basis::Default,
        },
        |(tier, stated, mode)| Resolved {
            mode,
            basis: match (tier, stated) {
                (Tier::Start(audience), Stated::Standing(scope)) => Basis::Start {
                    audience,
                    scope: scope.clone(),
                },
                (_, Stated::Standing(scope)) => Basis::Rule(scope.clone()),
                (_, Stated::Connection(scope)) => Basis::Connection(scope.clone()),
            },
        },
    )
}

/// The organisation's floors over a choice: the result is no less strict than
/// any floor that covers the request.
fn hold(rules: &Rules<'_>, subject: &Subject<'_>, chosen: Resolved) -> Resolved {
    let floors = rules
        .floors
        .iter()
        .filter(|(_, scope, _)| scope.covers(subject))
        .map(|(audience, scope, mode)| ((*audience, scope), *mode));
    match at_least(chosen.mode, floors) {
        (mode, Some((audience, scope))) => Resolved {
            mode,
            basis: Basis::Limit(Box::new(Limited {
                audience,
                scope: scope.clone(),
                chose: chosen.mode,
                basis: chosen.basis,
            })),
        },
        (_, None) => chosen,
    }
}
