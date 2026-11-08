//! A remote, and the ways a grant, a denial or a rule selects remotes.
//!
//! A remote is a route and an address on it. Plain hosts, Coder workspaces,
//! Codespaces and a WSL virtual machine differ in the route they are reached
//! by, never in kind; what a remote's platform can carry is observed when it
//! is first reached and lives in the trail, not here.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::scope::Specific;
use crate::text::{Address, Name, Pattern, Program, TextError, Verbatim};

/// The identity of a remote. It is the pair itself, so a workspace destroyed
/// and recreated under the same name is the same remote, and nothing assigned
/// at storage time has to survive an export.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteId {
    pub route: Name,
    pub address: Address,
}

impl fmt::Display for RemoteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.address, self.route)
    }
}

/// Whether a route's platform can say which of its remotes are running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Discovery {
    /// It lists them, so a grant can follow a workspace's life.
    Lists,
    /// A remote exists for the core only when the person names it.
    Blind,
}

/// One argument of a route's client.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Argument {
    /// Passed exactly as the entry writes it.
    Literal(Verbatim),
    /// The remote's address on the route, as one whole argument.
    Address,
}

impl Argument {
    fn spelt(&self, address: &Address) -> String {
        match self {
            Argument::Literal(text) => text.as_str().to_owned(),
            Argument::Address => address.as_str().to_owned(),
        }
    }
}

/// The program a route reaches its remotes through, and how one remote's
/// address becomes its arguments. The program is an OpenSSH client or hands
/// OpenSSH's options through to one: the core says what a connection is for
/// in those options and in nothing else.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Client {
    pub program: Program,
    /// What the entry passes before the options the core adds.
    pub before: Vec<Argument>,
    /// What it passes after them.
    pub after: Vec<Argument>,
}

impl Client {
    /// The arguments that reach `address`, with the core's own `options`
    /// where the entry places them.
    pub fn arguments(
        &self,
        address: &Address,
        options: impl IntoIterator<Item = String>,
    ) -> Vec<String> {
        let before = self.before.iter().map(|argument| argument.spelt(address));
        let after = self.after.iter().map(|argument| argument.spelt(address));
        before.chain(options).chain(after).collect()
    }
}

/// A line of a listing that is not an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListError {
    /// The line, counted from one over everything the lister printed.
    pub line: usize,
    pub error: TextError,
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {} of the listing is not a remote's address: {}",
            self.line, self.error
        )
    }
}

impl std::error::Error for ListError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// How a route's platform is asked which of its remotes are running: a
/// program of the platform's own, told by its own arguments to print the
/// running ones and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lister {
    pub program: Program,
    pub arguments: Vec<Verbatim>,
    /// The lines printed before the first remote: a table's heading.
    pub header: u8,
}

impl Lister {
    /// The addresses `output` lists: one to a line after the header, with the
    /// blanks around it dropped and empty lines passed over.
    ///
    /// # Errors
    ///
    /// [`ListError`] for the first line that is not an address. A listing is
    /// read whole or not at all: a remote left out would be taken as stopped.
    pub fn addresses(&self, output: &str) -> Result<Vec<Address>, ListError> {
        output
            .lines()
            .enumerate()
            .skip(usize::from(self.header))
            .map(|(index, line)| (index + 1, line.trim()))
            .filter(|(_, line)| !line.is_empty())
            .map(|(line, text)| Address::try_from(text).map_err(|error| ListError { line, error }))
            .collect()
    }
}

/// Whether, and how, a route's running remotes are listed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Listing {
    /// Nothing lists them: a remote exists for the core when the person
    /// names it.
    Blind,
    Lists(Lister),
}

/// What stands for a remote's identity on a route: what makes the machine
/// reached today the one that was reached yesterday.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Identity {
    /// The host's own key, which the client checks against what the person's
    /// SSH configuration holds as known.
    HostKey,
    /// The person's sign-in to the route's platform, which reaches the remote
    /// on their behalf. The entry's arguments give the client no host key to
    /// check, so a remote made again under its name is the same remote.
    Platform,
}

/// A way of reaching remotes through a client the workstation already has.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Route {
    pub id: Name,
    pub client: Client,
    pub listing: Listing,
    pub identity: Identity,
}

impl Route {
    /// Whether a grant on this route can follow a remote's life.
    pub fn discovery(&self) -> Discovery {
        match self.listing {
            Listing::Blind => Discovery::Blind,
            Listing::Lists(_) => Discovery::Lists,
        }
    }
}

/// One entry of a named set of remotes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Member {
    One(RemoteId),
    Matching { route: Name, pattern: Pattern },
}

impl Member {
    pub fn route(&self) -> &Name {
        match self {
            Member::One(remote) => &remote.route,
            Member::Matching { route, .. } => route,
        }
    }

    fn covers(&self, remote: &RemoteId) -> bool {
        match self {
            Member::One(one) => one == remote,
            Member::Matching { route, pattern } => {
                *route == remote.route && pattern.matches(&remote.address)
            }
        }
    }
}

/// Remotes that share no name, named once: a grant, a denial, a rule and a
/// preference can each refer to the set, so hosts a provider named take one
/// entry and not one for every setting.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Set {
    pub id: Name,
    pub members: Vec<Member>,
}

/// The members of every named set, by name.
pub type Named = BTreeMap<Name, BTreeSet<Member>>;

/// The named sets a selection of remotes is read against: the person's own
/// and the ones defined outside their document.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sets<'a> {
    own: Option<&'a Named>,
    outside: Option<&'a Named>,
}

impl<'a> Sets<'a> {
    /// No set is defined: a selection that names one covers nothing.
    pub const NONE: Sets<'static> = Sets {
        own: None,
        outside: None,
    };

    pub fn new(own: &'a Named, outside: &'a Named) -> Sets<'a> {
        Sets {
            own: Some(own),
            outside: Some(outside),
        }
    }

    /// Whether `remote` is a member of the set `id`, under any definition
    /// the name has.
    pub fn holds(&self, id: &Name, remote: &RemoteId) -> bool {
        [self.own, self.outside]
            .into_iter()
            .flatten()
            .filter_map(|named| named.get(id))
            .any(|members| members.iter().any(|member| member.covers(remote)))
    }

    /// The routes the members of `id` are on.
    pub fn routes(&self, id: &Name) -> BTreeSet<&'a Name> {
        [self.own, self.outside]
            .into_iter()
            .flatten()
            .filter_map(|named| named.get(id))
            .flat_map(|members| members.iter().map(Member::route))
            .collect()
    }

    /// Whether any source defines `id`.
    pub fn defines(&self, id: &Name) -> bool {
        [self.own, self.outside]
            .into_iter()
            .flatten()
            .any(|named| named.contains_key(id))
    }

    /// Every remote a set names by itself, under any definition.
    pub fn ones(&self) -> impl Iterator<Item = &'a RemoteId> {
        [self.own, self.outside]
            .into_iter()
            .flatten()
            .flat_map(BTreeMap::values)
            .flatten()
            .filter_map(|member| match member {
                Member::One(remote) => Some(remote),
                Member::Matching { .. } => None,
            })
    }
}

/// The remotes a grant covers. A grant never covers every route at once: the
/// widest it goes is one route, or a set whose members each name theirs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Granted {
    Route(Name),
    Matching {
        route: Name,
        pattern: Pattern,
    },
    /// The members of a named set.
    Set(Name),
    One(RemoteId),
}

/// The remotes a denial, a standing rule, a pause or a preference covers,
/// widest first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Remotes {
    Every,
    Route(Name),
    Matching {
        route: Name,
        pattern: Pattern,
    },
    /// The members of a named set.
    Set(Name),
    One(RemoteId),
}

impl Granted {
    pub fn covers(&self, remote: &RemoteId, sets: &Sets<'_>) -> bool {
        Remotes::from(self.clone()).covers(remote, sets)
    }

    /// How narrowly this selects; the narrower of two grants decides.
    pub fn rank(&self) -> u8 {
        Remotes::from(self.clone()).rank()
    }
}

impl From<Granted> for Remotes {
    fn from(granted: Granted) -> Self {
        match granted {
            Granted::Route(route) => Remotes::Route(route),
            Granted::Matching { route, pattern } => Remotes::Matching { route, pattern },
            Granted::Set(id) => Remotes::Set(id),
            Granted::One(remote) => Remotes::One(remote),
        }
    }
}

impl Remotes {
    pub fn covers(&self, remote: &RemoteId, sets: &Sets<'_>) -> bool {
        match self {
            Remotes::Every => true,
            Remotes::Route(route) => *route == remote.route,
            Remotes::Matching { route, pattern } => {
                *route == remote.route && pattern.matches(&remote.address)
            }
            Remotes::Set(id) => sets.holds(id, remote),
            Remotes::One(one) => one == remote,
        }
    }

    /// How narrowly this selects, from every remote to one. A named set and
    /// a pattern select equally narrowly.
    pub fn rank(&self) -> u8 {
        match self {
            Remotes::Every => 0,
            Remotes::Route(_) => 1,
            Remotes::Matching { .. } | Remotes::Set(_) => 2,
            Remotes::One(_) => 3,
        }
    }

    /// The routes this selection names, and the set it names: what must be
    /// defined for the selection to cover anything.
    pub fn routes<'a>(&'a self, sets: &Sets<'a>) -> BTreeSet<&'a Name> {
        match self {
            Remotes::Every => BTreeSet::new(),
            Remotes::Route(route) | Remotes::Matching { route, .. } => BTreeSet::from([route]),
            Remotes::Set(id) => sets.routes(id),
            Remotes::One(remote) => BTreeSet::from([&remote.route]),
        }
    }

    /// The named set this selection refers to, where it refers to one.
    pub fn set(&self) -> Option<&Name> {
        match self {
            Remotes::Set(id) => Some(id),
            _ => None,
        }
    }
}

impl Specific for &Granted {
    fn specificity(&self, other: &Self) -> Option<Ordering> {
        Some(self.rank().cmp(&other.rank()))
    }
}

impl Specific for &Remotes {
    /// One selection of remotes against another is never incomparable: the
    /// narrower form is the more specific.
    fn specificity(&self, other: &Self) -> Option<Ordering> {
        Some(self.rank().cmp(&other.rank()))
    }
}
