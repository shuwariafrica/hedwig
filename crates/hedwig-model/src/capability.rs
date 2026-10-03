//! A capability: something the workstation holds, the protocol a remote speaks
//! to reach it, and where the remote's own tool looks for it.
//!
//! The dialect and the exposure are read from the source and never stated
//! beside it, so a capability cannot be described as less than it is.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::platform::{Platform, Sockets};
use crate::refusal::Refusal;
use crate::site::Site;
use crate::text::{
    AgentPipe, DeviceSerial, Fingerprint, Folder, Host, Mark, Name, Port, PortName, Program,
    SshKey, Template, Variable, Verbatim, Words,
};
use crate::trail::{Keyring, Write};

/// Which of gpg-agent's two Assuan sockets a capability relays to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Access {
    /// `S.gpg-agent.extra`: signing and decryption, and nothing that manages a
    /// key.
    Restricted,
    /// `S.gpg-agent`: everything the person could ask of the agent themselves.
    Unrestricted,
}

/// Which `GnuPG` on the workstation a capability uses: the folder its tools
/// are in, beneath which `bin` holds `gpgconf`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Installation {
    /// The one `GnuPG`'s own Windows installer registers, under
    /// `Software\GnuPG`, as its own libraries find it.
    Registered,
    /// Another, named by its folder.
    At(Folder),
}

/// The `GnuPG` home whose agent is relayed; `gpgconf` resolves either form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Home {
    /// The one `gpgconf` reports with no home named.
    Default,
    At(Folder),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceHost {
    /// The workstation's own loopback.
    Workstation,
    /// A host only the workstation's network position reaches.
    Named(Host),
}

/// A port a preset may be unable to state: Playwright's server listens where
/// the person started it. An unstated port blocks a grant until a capability
/// defined from the preset states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServicePort {
    Fixed(Port),
    Unstated,
}

/// What a relayed service speaks, as far as the core reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stream {
    /// ADB's smart-socket requests, read so `host:kill` can be refused.
    Adb,
    /// Bytes the core relays without reading.
    Opaque,
}

/// A question only the remote's own tool can answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Query {
    /// `gpgconf --list-dirs agent-socket`.
    AgentSocket,
    /// `gpgconf --list-dirs agent-ssh-socket`.
    AgentSshSocket,
}

/// What a forward takes on a remote that no other forward there can take
/// too: a second forward at it would be refused by the remote's SSH server,
/// or its write would overwrite the first's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Spot {
    Port(Port),
    /// The socket the remote's own tool names in answer to the query.
    Socket(Query),
    /// A variable Hedwig writes for the remote's tools to read.
    Variable(Variable),
    /// The credential helper Hedwig names in the remote `git`'s own
    /// configuration: a second would be asked for every site the first
    /// refuses, and each refusal would name as unlisted a site the other
    /// serves.
    Helper,
}

/// The variable every SSH client and `ssh-keygen -Y sign` find an agent by.
pub const AGENT_VARIABLE: &str = "SSH_AUTH_SOCK";

/// The variables a browser capability's openers are written in: what
/// Python's `webbrowser` and `xdg-open` read, and what `gh` reads first.
pub const OPENER_VARIABLES: [&str; 2] = ["BROWSER", "GH_BROWSER"];

/// The variable a remote's own hooks and scripts tell the person through: a
/// name of Hedwig's own, which Hedwig keeps stable on every remote.
pub const NOTIFY_VARIABLE: &str = "HEDWIG_NOTIFY";

/// Where a service's remote tool can be made to look.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Offer {
    /// A socket in a directory private to the remote user, which the tool is
    /// pointed at through its own variable. Only the remote user reaches it.
    PrivateSocket { variable: Variable, value: Template },
    /// A port on the remote's loopback, which every user of that host reaches.
    Port(ServicePort),
}

/// The remote end of a forward, in the form one platform can carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Form {
    /// A Unix-domain socket at the path the remote's tool names.
    SocketAt(Query),
    /// A loopback port, and at the path the remote's tool names a file holding
    /// that port and sixteen bytes the core issues for that remote.
    SocketFileAt(Query),
    PrivateSocket {
        variable: Variable,
        value: Template,
    },
    Port(ServicePort),
    /// A socket in a directory private to the remote user, which the
    /// remote's own openers are pointed at: `BROWSER` and `GH_BROWSER`, each
    /// a command of the remote's own `curl` that posts the URL there.
    Opener,
    /// A socket in a directory private to the remote user, which the
    /// remote's own `git` asks through its own `cache` helper, named in its
    /// global configuration.
    Helper,
    /// A socket in a directory private to the remote user, which
    /// [`NOTIFY_VARIABLE`] names in a command of the remote's own `curl` that
    /// posts what it is given there.
    Notifier,
}

impl Form {
    fn fits(&self, sockets: Sockets) -> bool {
        match self {
            Form::SocketAt(_)
            | Form::PrivateSocket { .. }
            | Form::Opener
            | Form::Helper
            | Form::Notifier => matches!(sockets, Sockets::Unix { .. }),
            Form::SocketFileAt(_) => matches!(sockets, Sockets::Emulated),
            Form::Port(_) => true,
        }
    }

    /// What carrying this form takes on the remote.
    pub fn spots(&self) -> Vec<Spot> {
        match self {
            // An SSH agent's socket is found through `SSH_AUTH_SOCK`, which
            // Hedwig writes where it may and the person's own configuration
            // sets where it does not.
            Form::SocketAt(Query::AgentSshSocket) => {
                let mut spots = vec![Spot::Socket(Query::AgentSshSocket)];
                spots.extend(Variable::try_from(AGENT_VARIABLE).ok().map(Spot::Variable));
                spots
            }
            Form::SocketAt(query) | Form::SocketFileAt(query) => vec![Spot::Socket(*query)],
            Form::PrivateSocket { variable, .. } => vec![Spot::Variable(variable.clone())],
            Form::Port(ServicePort::Fixed(port)) => vec![Spot::Port(*port)],
            Form::Port(ServicePort::Unstated) => Vec::new(),
            Form::Opener => OPENER_VARIABLES
                .into_iter()
                .filter_map(|name| Variable::try_from(name).ok())
                .map(Spot::Variable)
                .collect(),
            Form::Helper => vec![Spot::Helper],
            Form::Notifier => Variable::try_from(NOTIFY_VARIABLE)
                .ok()
                .map(Spot::Variable)
                .into_iter()
                .collect(),
        }
    }

    /// Whether carrying this form writes the remote tool's own configuration,
    /// which needs the person's consent on the grant.
    pub fn writes(&self) -> bool {
        matches!(
            self,
            Form::SocketFileAt(_)
                | Form::PrivateSocket { .. }
                | Form::Opener
                | Form::Helper
                | Form::Notifier
        )
    }

    /// Who on the remote reaches a forward in this form. The remote's SSH
    /// server binds a socket at mode 600 (`StreamLocalBindMask 0177`), and a
    /// socket file's port admits only who presents the sixteen bytes in it,
    /// which is in the remote user's own folder.
    pub fn whom(&self) -> Whom {
        match self {
            Form::SocketAt(_)
            | Form::SocketFileAt(_)
            | Form::PrivateSocket { .. }
            | Form::Opener
            | Form::Helper
            | Form::Notifier => Whom::Account,
            Form::Port(_) => Whom::Anyone,
        }
    }
}

/// Who on a remote reaches a forward, fewest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Whom {
    /// The remote user's own account.
    Account,
    /// Every user and program on the remote.
    Anyone,
}

/// Each shape a platform's sockets take. Which form a capability takes reads
/// only the shape, never a socket path's length.
const SHAPES: [Sockets; 2] = [
    Sockets::Unix {
        path_bytes: std::num::NonZeroU16::MIN,
    },
    Sockets::Emulated,
];

impl From<&Offer> for Form {
    fn from(offer: &Offer) -> Self {
        match offer {
            Offer::PrivateSocket { variable, value } => Form::PrivateSocket {
                variable: variable.clone(),
                value: value.clone(),
            },
            Offer::Port(port) => Form::Port(*port),
        }
    }
}

/// Whether a grant lets the core write a remote tool's own configuration, or
/// only run that tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Setup {
    Inspect,
    Write,
}

/// What a source holds several of, which a grant lends one by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Holds {
    /// An ADB server's devices.
    Devices,
    /// An SSH agent's keys.
    Keys,
}

/// Where a lent key may be used.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Toward {
    /// To authenticate to any host, and to sign.
    Anywhere,
    /// Only to authenticate, and only to a host whose key is one of these,
    /// named in the request as OpenSSH's servers check it against their own
    /// key (`publickey-hostbound-v00@openssh.com`): nothing else is signed.
    /// Toward no host, the key is listed to the remote and signs nothing.
    Hosts(BTreeSet<SshKey>),
}

impl Toward {
    /// Whether everything `other` lets a key do, this lets it do too.
    pub fn covers(&self, other: &Toward) -> bool {
        match (self, other) {
            (Toward::Anywhere, _) => true,
            (Toward::Hosts(_), Toward::Anywhere) => false,
            (Toward::Hosts(lent), Toward::Hosts(asked)) => asked.is_subset(lent),
        }
    }
}

/// A key a grant lends, besides the key itself: where it may be used, and
/// the comment its agent gave it when the person lent it. The agent is asked
/// for its keys only on the person's act, so the comment they chose the key
/// by is kept here, where every surface and the remote's own list read it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LentKey {
    pub toward: Toward,
    pub comment: Option<Words>,
}

impl From<Toward> for LentKey {
    fn from(toward: Toward) -> Self {
        LentKey {
            toward,
            comment: None,
        }
    }
}

/// Which of a source's devices or keys a grant lends a remote. An ADB server
/// holds every device it sees, and an SSH agent every key put in it, and
/// nothing in either divides what one remote may use from what another may,
/// so the grant is where the person says which a remote sees and uses: for
/// devices, none until named and each only as a choice of its own. A key is
/// lent once, by its public half.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Lends {
    /// What is named; nothing where both are empty, as a grant starts.
    Named {
        devices: BTreeSet<DeviceSerial>,
        keys: BTreeMap<SshKey, LentKey>,
    },
    /// Everything the source holds, now and later.
    Every,
}

impl Lends {
    /// Lends nothing.
    pub fn none() -> Lends {
        Lends::Named {
            devices: BTreeSet::new(),
            keys: BTreeMap::new(),
        }
    }

    /// Lends the devices named.
    pub fn devices(serials: impl IntoIterator<Item = DeviceSerial>) -> Lends {
        Lends::Named {
            devices: serials.into_iter().collect(),
            keys: BTreeMap::new(),
        }
    }

    /// Lends the keys named; a key named twice is lent as named last.
    pub fn of_keys(keys: impl IntoIterator<Item = (SshKey, LentKey)>) -> Lends {
        Lends::Named {
            devices: BTreeSet::new(),
            keys: keys.into_iter().collect(),
        }
    }

    /// Whether `serial` is lent.
    pub fn lends(&self, serial: &DeviceSerial) -> bool {
        match self {
            Lends::Named { devices, .. } => devices.contains(serial),
            Lends::Every => true,
        }
    }

    /// How `key` is lent, or `None` where it is not.
    pub fn key(&self, key: &SshKey) -> Option<&LentKey> {
        const EVERY: &LentKey = &LentKey {
            toward: Toward::Anywhere,
            comment: None,
        };
        match self {
            Lends::Named { keys, .. } => keys.get(key),
            Lends::Every => Some(EVERY),
        }
    }

    /// The keys named, each with how it is lent.
    pub fn keys(&self) -> impl Iterator<Item = (&SshKey, &LentKey)> {
        let named = match self {
            Lends::Named { keys, .. } => Some(keys),
            Lends::Every => None,
        };
        named.into_iter().flatten()
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Lends::Named { devices, keys } if devices.is_empty() && keys.is_empty())
    }

    /// Whether this lets a remote reach anything `other` does not: a device
    /// it does not lend, a key it does not lend, or a key toward a host it
    /// does not lend that key toward. A comment reaches nothing.
    pub fn exceeds(&self, other: &Lends) -> bool {
        match (self, other) {
            (_, Lends::Every) => false,
            (Lends::Every, Lends::Named { .. }) => true,
            (
                Lends::Named { devices, keys },
                Lends::Named {
                    devices: held,
                    keys: lent,
                },
            ) => {
                !devices.is_subset(held)
                    || keys.iter().any(|(key, wanted)| {
                        lent.get(key)
                            .is_none_or(|lent| !lent.toward.covers(&wanted.toward))
                    })
            }
        }
    }

    /// What a remote can reach through what is named, widest first: the
    /// devices and the keys usable anywhere, which have no bound; the hosts
    /// a key may log in to; the logins, a key to a host; the keys bound to
    /// hosts. Each grows with what is lent, so a set within another measures
    /// less, and one that reaches as much measures the same.
    fn measure(&self) -> Option<[usize; 4]> {
        let Lends::Named { devices, keys } = self else {
            return None;
        };
        let mut unbounded = devices.len();
        let mut hosts = BTreeSet::new();
        let mut logins = 0;
        let mut bound = 0;
        for lent in keys.values() {
            match &lent.toward {
                Toward::Anywhere => unbounded += 1,
                Toward::Hosts(named) => {
                    hosts.extend(named);
                    logins += named.len();
                    bound += 1;
                }
            }
        }
        Some([unbounded, hosts.len(), logins, bound])
    }
}

/// From least lent to most, every device and key last: a set before every
/// set that reaches more, so of two grants one lending within the other is
/// the less exposing. Sets neither of which reaches within the other are
/// ordered by what they reach without bound, then by the hosts and logins
/// they reach; sets that reach alike, by what they name, which only keeps
/// the order total.
impl Ord for Lends {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (
                Lends::Named { devices, keys },
                Lends::Named {
                    devices: their_devices,
                    keys: their_keys,
                },
            ) => self
                .measure()
                .cmp(&other.measure())
                .then_with(|| devices.cmp(their_devices))
                .then_with(|| keys.cmp(their_keys)),
            (Lends::Named { .. }, Lends::Every) => Ordering::Less,
            (Lends::Every, Lends::Named { .. }) => Ordering::Greater,
            (Lends::Every, Lends::Every) => Ordering::Equal,
        }
    }
}

impl PartialOrd for Lends {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// gpg-agent, through the socket the installation's `gpgconf` names for
    /// this home.
    Gnupg {
        installation: Installation,
        home: Home,
        access: Access,
    },
    /// An SSH agent on the workstation, the person's own, to which the core
    /// carries a remote's requests, offering only the keys a grant lends.
    Agent { at: AgentAt },
    /// A TCP service the workstation can reach.
    Service {
        host: ServiceHost,
        port: ServicePort,
        stream: Stream,
        remote: Vec<Offer>,
    },
    /// The person's browser, which opens what a remote asks only where one of
    /// `sites` admits it.
    Browser { browser: Browser, sites: Vec<Site> },
    /// A serial port on the workstation, which the core serves as RFC 2217 at
    /// `remote` on the remote's loopback, the port opened for one connection
    /// at a time and closed when it ends. pyserial's `rfc2217://` reads a
    /// host and a TCP port alone, so a port is the only form.
    Serial { port: PortName, remote: Port },
    /// The workstation's own git credential system, asked through `git`'s
    /// own `credential fill`: whatever the person configured there - Git
    /// Credential Manager, a store, a helper of their own - answers a remote's
    /// `git` for a site one of `sites` admits, as it answers theirs.
    Credentials { git: Program, sites: Vec<Site> },
    /// The person's attention: what a remote's job says reaches them by the
    /// routes they have, as that remote's words.
    Notices,
}

/// Where an SSH agent on the workstation is reached.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentAt {
    /// gpg-agent's own SSH socket for a `GnuPG` home, `agent-ssh-socket`,
    /// which gpg-agent on Windows serves with nothing configured, and which
    /// the core starts as it starts the agent for `gpg`.
    Gnupg {
        installation: Installation,
        home: Home,
    },
    /// A named pipe: the well-known one, whichever product holds it, or one of
    /// an agent's own.
    Pipe(AgentPipe),
    /// Hedwig itself, signing in the workstation's TPM with the keys it made
    /// there: no agent on Windows holds such a key.
    Machine,
}

/// What a key Hedwig makes in the workstation's TPM is: each a key type an
/// OpenSSH server and `ssh-keygen -Y verify` accept that a TPM 2.0 may make.
/// Which of them a TPM makes is its own answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyKind {
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    /// RSA is what Azure's hosts and Azure Repos accept of these.
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl KeyKind {
    pub const ALL: [KeyKind; 6] = [
        KeyKind::EcdsaP256,
        KeyKind::EcdsaP384,
        KeyKind::EcdsaP521,
        KeyKind::Rsa2048,
        KeyKind::Rsa3072,
        KeyKind::Rsa4096,
    ];

    /// The key type OpenSSH names its public half by.
    pub fn ssh_type(self) -> &'static str {
        match self {
            KeyKind::EcdsaP256 => "ecdsa-sha2-nistp256",
            KeyKind::EcdsaP384 => "ecdsa-sha2-nistp384",
            KeyKind::EcdsaP521 => "ecdsa-sha2-nistp521",
            KeyKind::Rsa2048 | KeyKind::Rsa3072 | KeyKind::Rsa4096 => "ssh-rsa",
        }
    }
}

/// Which program opens a remote's URL on the workstation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Browser {
    /// What Windows opens an `https` address with for the person.
    Default,
    /// A program found as a route's client is, given `arguments` and then the
    /// URL: a browser and the profile the person signs in to a remote's
    /// services with.
    Program {
        program: Program,
        arguments: Vec<Verbatim>,
    },
}

/// The protocol a capability's remote speaks. Only the Assuan case has a
/// restricted axis, so nothing can ask another dialect about one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dialect {
    Assuan(Access),
    SshAgent,
    Adb,
    Opaque,
    /// A URL posted by the remote's own HTTP client.
    Browser,
    /// RFC 2217: Telnet carrying a serial port's data, its settings and its
    /// control lines.
    Serial,
    /// What `git`'s own `cache` helper sends its daemon: an action, and the
    /// credential `git` asks about.
    Credential,
    /// What the remote's own `curl` posts: words for the person.
    Notice,
}

/// A point at which the core can decide before serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Operation {
    /// A stream is opened to the capability.
    Connect,
    /// A signature that proves who logs in to a host: an SSH user
    /// authentication, a card's `PKAUTH`.
    Authenticate,
    Sign,
    Decrypt,
    /// A URL opened in the person's browser.
    Open,
}

impl Dialect {
    /// The decision points this dialect's parser can raise.
    pub fn operations(self) -> &'static [Operation] {
        match self {
            Dialect::Assuan(_) => &[
                Operation::Connect,
                Operation::Authenticate,
                Operation::Sign,
                Operation::Decrypt,
            ],
            Dialect::SshAgent => &[Operation::Connect, Operation::Authenticate, Operation::Sign],
            // A credential's connection carries one `get`, and serving its
            // opening is releasing the secret.
            Dialect::Adb | Dialect::Opaque | Dialect::Serial | Dialect::Credential => {
                &[Operation::Connect]
            }
            Dialect::Browser => &[Operation::Connect, Operation::Open],
            // A notice asks nothing to be decided: it is the person's to read.
            Dialect::Notice => &[],
        }
    }
}

/// What granting a capability lets a remote do. A set, because a capability
/// can expose several things at once and each gate names the member it needs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Exposure(u8);

impl Exposure {
    pub const NONE: Exposure = Exposure(0);
    /// Signatures, decryptions and authentications made with a key that stays
    /// on the workstation.
    pub const KEY_USE: Exposure = Exposure(1);
    /// Export, passphrase changes and card administration.
    pub const KEY_MANAGEMENT: Exposure = Exposure(1 << 1);
    /// A secret that leaves the workstation and works without it afterwards.
    pub const SECRET: Exposure = Exposure(1 << 2);
    /// A service that authenticates nobody.
    pub const SERVICE: Exposure = Exposure(1 << 3);
    /// Hosts beyond the workstation itself.
    pub const NETWORK: Exposure = Exposure(1 << 4);
    /// Pages opened in the person's browser, where their signed-in sessions
    /// are, and a loopback port of the remote's that a page reaches.
    pub const BROWSER: Exposure = Exposure(1 << 5);
    /// The person's attention: words a remote chooses, shown to the person
    /// as that remote's.
    pub const ATTENTION: Exposure = Exposure(1 << 6);

    /// The members a grant must name before it takes effect.
    pub const ACKNOWLEDGED: Exposure = Exposure(
        Exposure::KEY_MANAGEMENT.0
            | Exposure::SECRET.0
            | Exposure::SERVICE.0
            | Exposure::NETWORK.0
            | Exposure::BROWSER.0
            | Exposure::ATTENTION.0,
    );

    const WORDS: [(Exposure, &'static str); 7] = [
        (Exposure::KEY_USE, "key-use"),
        (Exposure::KEY_MANAGEMENT, "key-management"),
        (Exposure::SECRET, "secret"),
        (Exposure::SERVICE, "service"),
        (Exposure::NETWORK, "network"),
        (Exposure::BROWSER, "browser"),
        (Exposure::ATTENTION, "attention"),
    ];

    #[must_use]
    pub const fn with(self, other: Exposure) -> Exposure {
        Exposure(self.0 | other.0)
    }

    #[must_use]
    pub const fn without(self, other: Exposure) -> Exposure {
        Exposure(self.0 & !other.0)
    }

    #[must_use]
    pub const fn common(self, other: Exposure) -> Exposure {
        Exposure(self.0 & other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The members as the words a document and a surface use for them.
    pub fn words(self) -> impl Iterator<Item = &'static str> {
        Exposure::WORDS
            .into_iter()
            .filter(move |(member, _)| !self.common(*member).is_empty())
            .map(|(_, word)| word)
    }

    pub fn from_word(word: &str) -> Option<Exposure> {
        Exposure::WORDS
            .into_iter()
            .find(|(_, known)| *known == word)
            .map(|(member, _)| member)
    }
}

impl fmt::Debug for Exposure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.words()).finish()
    }
}

/// What a grant's consent to write lets Hedwig write for one capability, as
/// the person is shown it before consenting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    /// Each write, by what it writes.
    pub writes: Vec<Write>,
    /// The keys the capability's source offers are written too and have not
    /// been read, so they cannot be named yet: the public half of each, and
    /// the one the person signs with as `git`'s signing key.
    pub keys_unread: bool,
    /// Where the forward is with consent and where without, for a service
    /// offered both behind a private socket and on a port.
    pub reaches: Option<Reaches>,
}

/// A service offered behind a private socket, which the remote user alone
/// opens and consent to write its variable selects, and on a port, which
/// every user and program on the remote reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaches {
    pub capability: Name,
    pub variable: Variable,
    pub port: ServicePort,
    /// What the service speaks: some of its clients may read no socket.
    pub stream: Stream,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability {
    pub id: Name,
    pub source: Source,
}

impl Capability {
    pub fn dialect(&self) -> Dialect {
        match &self.source {
            Source::Gnupg { access, .. } => Dialect::Assuan(*access),
            Source::Agent { .. } => Dialect::SshAgent,
            Source::Service {
                stream: Stream::Adb,
                ..
            } => Dialect::Adb,
            Source::Service {
                stream: Stream::Opaque,
                ..
            } => Dialect::Opaque,
            Source::Browser { .. } => Dialect::Browser,
            Source::Serial { .. } => Dialect::Serial,
            Source::Credentials { .. } => Dialect::Credential,
            Source::Notices => Dialect::Notice,
        }
    }

    /// What the source holds that a grant lends one by one: an ADB server's
    /// devices and an SSH agent's keys, whatever capability names them.
    pub fn holds(&self) -> Option<Holds> {
        match self.dialect() {
            Dialect::Adb => Some(Holds::Devices),
            Dialect::SshAgent => Some(Holds::Keys),
            Dialect::Assuan(_)
            | Dialect::Opaque
            | Dialect::Browser
            | Dialect::Serial
            | Dialect::Credential
            | Dialect::Notice => None,
        }
    }

    pub fn exposure(&self) -> Exposure {
        match &self.source {
            Source::Gnupg {
                access: Access::Restricted,
                ..
            }
            | Source::Agent { .. } => Exposure::KEY_USE,
            // The standard socket also exports a secret key in the clear,
            // hands out a cached passphrase and returns a stored secret
            // (`command.c`: `EXPORT_KEY`, `GET_PASSPHRASE`, `GET_SECRET`).
            Source::Gnupg {
                access: Access::Unrestricted,
                ..
            } => Exposure::KEY_USE
                .with(Exposure::KEY_MANAGEMENT)
                .with(Exposure::SECRET),
            // Whoever on the remote reaches the port drives the board, and
            // RFC 2217 authenticates nobody.
            Source::Service {
                host: ServiceHost::Workstation,
                ..
            }
            | Source::Serial { .. } => Exposure::SERVICE,
            Source::Service {
                host: ServiceHost::Named(_),
                ..
            } => Exposure::SERVICE.with(Exposure::NETWORK),
            Source::Browser { .. } => Exposure::BROWSER,
            // A credential works at its forge without the workstation for as
            // long as the forge honours it.
            Source::Credentials { .. } => Exposure::SECRET,
            Source::Notices => Exposure::ATTENTION,
        }
    }

    /// The remote forms this capability can take, most private first.
    pub fn forms(&self) -> Vec<Form> {
        match &self.source {
            Source::Gnupg { .. } => vec![
                Form::SocketAt(Query::AgentSocket),
                Form::SocketFileAt(Query::AgentSocket),
            ],
            Source::Agent { .. } => vec![Form::SocketAt(Query::AgentSshSocket)],
            Source::Service { remote, .. } => remote.iter().map(Form::from).collect(),
            Source::Browser { .. } => vec![Form::Opener],
            Source::Serial { remote, .. } => vec![Form::Port(ServicePort::Fixed(*remote))],
            Source::Credentials { .. } => vec![Form::Helper],
            Source::Notices => vec![Form::Notifier],
        }
    }

    /// Everything a grant's consent lets Hedwig write for this capability on
    /// some platform, where `keyring` is what its source last offered: what
    /// the person is shown before consenting, and what a channel's survey
    /// may write.
    pub fn consent(&self, keyring: Option<&Keyring>) -> Consent {
        let writes = match keyring {
            Some(keyring) => self.writes(&keyring.primaries(), keyring.signing.as_ref()),
            None => self.writes(&[], None),
        };
        let keys_unread = matches!(self.source, Source::Gnupg { .. }) && keyring.is_none();
        let reaches = match &self.source {
            Source::Service { remote, stream, .. } => {
                let variable = remote.iter().find_map(|offer| match offer {
                    Offer::PrivateSocket { variable, .. } => Some(variable),
                    Offer::Port(_) => None,
                });
                let port = remote.iter().find_map(|offer| match offer {
                    Offer::Port(port) => Some(*port),
                    Offer::PrivateSocket { .. } => None,
                });
                variable.zip(port).map(|(variable, port)| Reaches {
                    capability: self.id.clone(),
                    variable: variable.clone(),
                    port,
                    stream: *stream,
                })
            }
            Source::Gnupg { .. }
            | Source::Agent { .. }
            | Source::Browser { .. }
            | Source::Serial { .. }
            | Source::Credentials { .. }
            | Source::Notices => None,
        };
        Consent {
            writes,
            keys_unread,
            reaches,
        }
    }

    fn writes(&self, keys: &[Fingerprint], signing: Option<&Mark>) -> Vec<Write> {
        match &self.source {
            Source::Gnupg { .. } => {
                let mut writes = vec![Write::NoAutostart, Write::Masked, Write::SocketFile];
                writes.extend(keys.iter().cloned().map(Write::PublicKey));
                writes.extend(signing.cloned().map(Write::SigningKey));
                writes
            }
            Source::Agent { .. } => {
                let mut writes = vec![Write::Masked];
                writes.extend(Variable::try_from(AGENT_VARIABLE).ok().map(Write::Variable));
                writes
            }
            Source::Service { remote, .. } => remote
                .iter()
                .filter_map(|offer| match offer {
                    Offer::PrivateSocket { variable, .. } => {
                        Some(Write::Variable(variable.clone()))
                    }
                    Offer::Port(_) => None,
                })
                .collect(),
            Source::Browser { .. } => OPENER_VARIABLES
                .into_iter()
                .filter_map(|name| Variable::try_from(name).ok())
                .map(Write::Variable)
                .collect(),
            Source::Serial { .. } => Vec::new(),
            Source::Credentials { .. } => vec![Write::Helper],
            Source::Notices => Variable::try_from(NOTIFY_VARIABLE)
                .ok()
                .map(Write::Variable)
                .into_iter()
                .collect(),
        }
    }

    /// Whether every fact a grant needs is stated.
    ///
    /// # Errors
    ///
    /// [`Refusal::CapabilityIncomplete`] when a port is unstated or a service
    /// names no remote form; [`Refusal::Cleartext`] for a credential's site
    /// on plain `http` beyond the remote's loopback, to which the remote's
    /// `git` would send the secret across the network unencrypted.
    pub fn complete(&self) -> Result<(), Refusal> {
        if let Source::Credentials { sites, .. } = &self.source
            && let Some(site) = sites.iter().find(|site| site.cleartext())
        {
            return Err(Refusal::Cleartext {
                capability: self.id.clone(),
                site: site.clone(),
            });
        }
        let Source::Service { port, remote, .. } = &self.source else {
            return Ok(());
        };
        let unstated = *port == ServicePort::Unstated
            || remote.is_empty()
            || remote.contains(&Offer::Port(ServicePort::Unstated));
        if unstated {
            return Err(Refusal::CapabilityIncomplete {
                capability: self.id.clone(),
            });
        }
        Ok(())
    }

    /// Who on a remote whose sockets are `sockets` reaches this capability's
    /// forward when a grant's setup is `setup`: `None` where it carries none
    /// there.
    pub fn reach(&self, sockets: Sockets, setup: Setup) -> Option<Whom> {
        self.forms()
            .into_iter()
            .filter(|form| form.fits(sockets))
            .find(|form| setup == Setup::Write || !form.writes())
            .map(|form| form.whom())
    }

    /// Whether a grant of this capability moved from `from` to `to` lets more
    /// through: Hedwig writes on the remote where it did not, or on some
    /// platform the forward moves to a form more of the remote reaches.
    /// Taking consent to write back from `adb` does: its forward leaves the
    /// remote user's private socket for port 5037.
    pub fn widens(&self, from: Setup, to: Setup) -> bool {
        to > from
            || SHAPES
                .into_iter()
                .any(|sockets| self.reach(sockets, to) > self.reach(sockets, from))
    }

    /// Whether, on every platform, a grant whose setup is `setup` carries this
    /// capability where every user of the remote reaches it: only then may a
    /// port carry it to a remote whose platform is not known.
    pub fn open_everywhere(&self, setup: Setup) -> bool {
        SHAPES
            .into_iter()
            .all(|sockets| self.reach(sockets, setup) == Some(Whom::Anyone))
    }

    /// The form a remote on `platform` takes this capability in: the first the
    /// platform can carry and the grant's consent covers.
    ///
    /// # Errors
    ///
    /// [`Refusal::NeedsRemoteSetup`] when the platform could carry a form that
    /// writes remote configuration and the grant only inspects;
    /// [`Refusal::NoCarrier`] when the platform's own SSH server can carry
    /// none.
    pub fn carrier(&self, platform: &Platform, setup: Setup) -> Result<Form, Refusal> {
        let mut fitting = self
            .forms()
            .into_iter()
            .filter(|form| form.fits(platform.sockets))
            .peekable();
        if fitting.peek().is_none() {
            return Err(Refusal::NoCarrier {
                capability: self.id.clone(),
                platform: platform.family.clone(),
            });
        }
        fitting
            .find(|form| setup == Setup::Write || !form.writes())
            .ok_or_else(|| Refusal::NeedsRemoteSetup {
                capability: self.id.clone(),
                platform: platform.family.clone(),
            })
    }
}
