//! The activity trail and the state folded from it.
//!
//! The trail is append-only and totally ordered by [`Seq`], never by a clock.
//! Everything the core knows beyond the configuration - who is attached, which
//! channels are up, what awaits the person, what is paused - is
//! [`State::fold`] of the trail, so it cannot drift from what happened.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::NonZeroU8;

use crate::capability::{Exposure, Lends, Operation};
use crate::config::{Change, Reach};
use crate::holder::SourceHolder;
use crate::install::{AtSignIn, Starts};
use crate::organisation::{Part, Place, Policy, Statement, Unread};
use crate::policy::{Basis, ConnectionScope, Mode, Selector};
use crate::protocol::{Hold, Last, Proof, Topic, Usb};
use crate::refusal::{Refusal, Whereabouts};
use crate::remote::{RemoteId, Remotes, Sets};
use crate::scope::{Audience, Strict};
use crate::setting::{Diagnostics, FullScreen, SETTLED};
use crate::site::Site;
use crate::text::{
    DeviceSerial, DeviceSocket, Fingerprint, Grip, Host, KeyId, Location, Mark, Name, Port,
    PortName, Remark, RemotePath, Serial, SshKey, Variable, Words,
};

/// An entry's position in the trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(pub u64);

/// Milliseconds since the core started, on a clock that keeps counting while
/// the workstation is suspended. Deadlines and burst windows are measured on
/// it; it means nothing across a restart, and nothing measured on it survives
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tick(pub u64);

/// Milliseconds since the Unix epoch, UTC. Shown to the person and compared by
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

macro_rules! trail_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub Seq);
    };
}

trail_id!(
    /// A control client, named by the entry that attached it.
    ClientId
);
trail_id!(
    /// One channel to one remote, named by the entry that opened it. A
    /// reconnect is a new connection.
    ConnectionId
);
trail_id!(
    /// One request from a remote, named by the entry that recorded it.
    RequestId
);
trail_id!(
    /// One prompt from a channel's client, named by the entry that raised it.
    PromptId
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Integrity {
    Low,
    Medium,
    High,
    System,
}

/// Where a process stands on the workstation, read from its token by the
/// core. It is recorded and shown and never a reason to refuse: a person's
/// terminal over SSH is another logon session of the same person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    pub process: u32,
    /// The token's `AuthenticationId`.
    pub logon: u64,
    pub session: u32,
    pub integrity: Integrity,
}

/// What the core reads of the process at the other end of a connection,
/// whichever kind of connection it is: a client of the control pipe, or
/// whatever connected to the workstation end of a forward. Each kind of
/// connection has its own way of finding the process; what is read of it
/// then is this, and one policy reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub origin: Origin,
    /// The program the process runs, where Windows would say.
    pub program: Option<Location>,
    /// The channel whose job the process is in, where it is in one: a fact
    /// the kernel keeps, read when the connection arrived.
    pub channel: Option<ConnectionId>,
}

impl From<Origin> for Peer {
    /// A process of which only its standing was read, in no channel's job.
    fn from(origin: Origin) -> Peer {
        Peer {
            origin,
            program: None,
            channel: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClientKind {
    /// Asks and leaves: a script, or one command.
    Command,
    /// A terminal a person is at.
    Terminal,
    /// The interface in a desktop session.
    Interface,
    /// Shows what the core holds and is told when it is stale, and is asked
    /// nothing: a window beside an interface that asks, a status bar. It
    /// never makes the person reachable, so nothing is held for it or
    /// announced through it.
    Viewer,
    /// A channel's client asking the person something, through the program
    /// `SSH_ASKPASS` names. Admitted only from a live channel's job, and
    /// attributed to that channel's remote.
    Prompt,
}

impl ClientKind {
    /// Whether requests and prompts may be put to this client.
    pub fn attends(self) -> bool {
        matches!(self, ClientKind::Terminal | ClientKind::Interface)
    }

    /// Whether this client is told what it shows has gone stale.
    pub fn shows(self) -> bool {
        self.attends() || self == ClientKind::Viewer
    }
}

/// Whether an attending client can currently show the person anything. An
/// interface is away while its desktop is locked or disconnected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Presence {
    Present,
    /// The person is there and only a card would reach them: an application
    /// fills the screen and Windows is holding notifications back. A request
    /// from a remote whose card is not shown over such an application cannot
    /// be put to them here.
    CardOnly,
    /// The person is there and nothing may be shown to them: they are
    /// presenting, or an application holds the display. Nothing is put to
    /// them or announced here.
    Engaged,
    Away,
}

/// Whether Hedwig's icon is on the taskbar, as the presence showing it last
/// said. A presence says so only once its icon has been missing long enough
/// to tell the person, and again when it is back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Icon {
    Shown,
    Missing(Missing),
}

/// Why Hedwig's icon is not on the taskbar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Missing {
    /// A taskbar runs and does not take it.
    Refused,
    /// No taskbar runs.
    NoTaskbar,
}

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Missing::Refused => "Windows' taskbar does not show Hedwig's icon",
            Missing::NoTaskbar => {
                "Windows' taskbar is not running, so Hedwig's icon cannot be shown"
            }
        })
    }
}

/// What a channel's client asks the person for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PromptKind {
    UnknownHostKey,
    KeyPassphrase,
    Password,
    SecurityKeyPin,
    /// A challenge in the server's own words, and anything the client asks
    /// in words the core does not recognise.
    Challenge,
    AgentConfirmation,
    /// A security key waits to be touched. Nothing is answered: the notice
    /// is withdrawn when the key is touched or the client gives up.
    SecurityKeyTouch,
}

/// What an answer to a prompt is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Asks {
    /// Text the person types, never recorded.
    Text,
    /// Yes or no.
    Consent,
    /// Nothing: the person can only decline it.
    Nothing,
}

impl PromptKind {
    pub fn asks(self) -> Asks {
        match self {
            PromptKind::KeyPassphrase
            | PromptKind::Password
            | PromptKind::SecurityKeyPin
            | PromptKind::Challenge => Asks::Text,
            PromptKind::UnknownHostKey | PromptKind::AgentConfirmation => Asks::Consent,
            PromptKind::SecurityKeyTouch => Asks::Nothing,
        }
    }

    /// Whether the person declining it ends the channel, rather than being
    /// handed to the client. Only a passphrase, which the client answers by
    /// trying its next key, and adding a key to an agent, which it answers by
    /// not adding it, are declined with nothing sent anywhere; an empty
    /// password, challenge or PIN would reach the server or the key as a
    /// wrong one, and a host key refused ends the connection anyway.
    pub fn decline_ends(self) -> bool {
        !matches!(
            self,
            PromptKind::KeyPassphrase | PromptKind::AgentConfirmation
        )
    }
}

/// Whom a channel's client may ask, as it was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Asking {
    /// A surface reached the person: the client may ask anything, and the
    /// core puts it to them.
    Person,
    /// Nobody could be asked: the client runs in batch mode, and what it
    /// asks all the same ends the channel as needing the person.
    Nobody,
}

/// How a channel comes back after it ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Back {
    /// After a wait that grows while attempts keep failing.
    Paced,
    /// At once.
    AtOnce,
    /// When something wants it again: the person connects, or a grant's
    /// activation holds it again.
    WhenWanted,
    /// Only when the person connects: nothing the core can do changes what
    /// ended it.
    ByThePerson,
}

/// Why a channel is no longer up.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChannelEnd {
    /// The person disconnected or paused, Hedwig was stopped, or nothing
    /// wants the channel any more.
    Closed,
    /// The route's platform reports the remote stopped.
    RemoteGone,
    /// The client asked the person something and nobody could be asked.
    Needs(PromptKind),
    /// The person declined what the client asked.
    Declined(PromptKind),
    /// The server accepted no way the client could authenticate without
    /// asking the person; carries the methods the server said it would still
    /// accept, in its own words.
    Unauthenticated(Words),
    /// The host presented another key than the one known; carries its
    /// fingerprint. Never a prompt.
    HostKeyChanged(Mark),
    /// The remote's SSH server refused a forward.
    ForwardRefused,
    /// The route's own client is not signed in.
    RouteNotSignedIn,
    /// No folder on the search path holds the route's client.
    ClientAbsent,
    /// The client was found and could not be started; carries the system's
    /// account.
    Unstarted(Words),
    /// The client ended by itself, with this status; `last` is the last line
    /// it wrote, which is where an OpenSSH client says why.
    Exited { status: i32, last: Option<Words> },
    /// Readiness found nothing the remote holds that can be carried there.
    NothingCarried,
    /// The workstation went to sleep.
    Slept,
    /// What the remote holds changed, and the channel is opened again with
    /// what it holds now: a forward cannot be added to a running client.
    Reshaped,
}

impl ChannelEnd {
    /// How the channel comes back while something still wants it.
    pub fn back(&self) -> Back {
        match self {
            ChannelEnd::Exited { .. }
            | ChannelEnd::ForwardRefused
            | ChannelEnd::Unstarted(_)
            | ChannelEnd::NothingCarried => Back::Paced,
            ChannelEnd::Slept | ChannelEnd::Reshaped => Back::AtOnce,
            ChannelEnd::Closed | ChannelEnd::RemoteGone => Back::WhenWanted,
            ChannelEnd::Needs(_)
            | ChannelEnd::Declined(_)
            | ChannelEnd::Unauthenticated(_)
            | ChannelEnd::HostKeyChanged(_)
            | ChannelEnd::RouteNotSignedIn
            | ChannelEnd::ClientAbsent => Back::ByThePerson,
        }
    }
}

/// The release a program's own version resource states, as Windows reads it
/// from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Release {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

impl std::fmt::Display for Release {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Release {
            major,
            minor,
            build,
            revision,
        } = self;
        write!(f, "{major}.{minor}.{build}.{revision}")
    }
}

/// What Hedwig has written on one remote, each by capability, write and
/// place, with what it made for it.
pub(crate) type Writes = BTreeMap<(Name, Write, RemotePath), Option<RemotePath>>;

/// One thing readiness found on a remote, for one capability. Each names
/// what it is about, so the person reads the remote's own path, tool or value
/// rather than a category.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Finding {
    /// Readiness could not learn what it needs of the remote: no shell it
    /// knows ran there, the survey did not finish, or the remote's tool could
    /// not be run. Carries why, in the remote's or the system's words.
    Unsurveyed(Words),
    /// The remote was read, and which platform it is cannot be said: no
    /// profile answers to the system it named, two do, or the one that does
    /// collides. Carries the refusal the platforms gave, so a surface can
    /// offer to define a profile for that system.
    NoProfile(Refusal),
    /// The remote has no tool that says where the capability goes.
    ToolAbsent(Name),
    /// The path the remote's tool named does not fit its platform's
    /// `sun_path`.
    PathTooLong { usable: u16, length: u16 },
    /// The path the remote's tool named cannot be a forward's end.
    PathUnusable,
    /// The socket's directory is on a file system other hosts share, so
    /// another host's socket can be at the same path. Carries the file
    /// system's own name for itself.
    SharedHome(Words),
    /// The directory the socket goes in could not be made; the remote's own
    /// words.
    ParentUncreatable(Words),
    /// Something that is not a socket is at the path.
    Occupied(RemotePath),
    /// The remote's own agent answers at the path. It is left running.
    AgentLive(RemotePath),
    /// A server of the capability's own tool's, the remote's, listens where
    /// the forward would bind - one its client started when it found no
    /// server there. It is left running.
    ServerLive { program: Name, at: Binding },
    /// A unit of the remote's service manager listens at the path, and
    /// starts its program on the first connection there. Nothing connects to
    /// it, so nothing is started; it is left unless the grant consents to
    /// [`Write::Masked`]. Carries the unit as the manager names it.
    UnitListens { unit: Words, path: RemotePath },
    /// Something from elsewhere answers at the path: a forward another
    /// program or another session holds. It is left alone.
    Answers(RemotePath),
    /// Something accepts at the path and says nothing: most often a forward
    /// of a session the remote has not yet noticed is gone.
    Silent(RemotePath),
    /// A socket is at the path, and no tool on the remote can say whether
    /// anything listens there.
    Unprobed(RemotePath),
    /// Nothing listens at the path and the socket could not be removed; the
    /// remote's own words.
    Uncleared(Words),
    /// Something on the remote already listens on the port the forward
    /// needs.
    ListenerPresent(Port),
    /// The route's deployment forbids reverse forwarding.
    ForwardingBlocked,
    /// The remote's SSH server refused the forward when the channel asked
    /// for it; its own log says why.
    ForwardRefused,
    /// The remote's `gpg` starts an agent of its own when the forward is
    /// down, and that agent takes the socket.
    AgentAutostarts,
    /// The remote's `GnuPG` keeps its keys in `keyboxd` and is set not to
    /// start anything, so it cannot read its own keyring.
    KeyboxdStopped,
    /// The remote's keyring lacks the public half of a key the workstation
    /// offers, so the remote's `gpg` cannot use it.
    PublicKeyAbsent(Fingerprint),
    /// The remote's `GnuPG` home has no keyring, so its `gpg` holds no key,
    /// and signing there would make one: an exercise runs nothing.
    KeyringAbsent,
    /// The remote's `git` names no signing key.
    SigningKeyUnset,
    /// The remote's `git` names a signing key the workstation does not
    /// offer; carries the value as `git` holds it.
    SigningKeyOther(Words),
    /// A command the remote's SSH server runs does not have the tool's
    /// variable pointing at the forward, as the survey's own command found
    /// it; carries the variable. Interactive and login shells read what was
    /// written for them all the same.
    VariableUnset(Variable),
    /// The person's own configuration asks for a forward on every connection
    /// to this host, so it rides the channel too; carries the forward as
    /// `ssh -G` states it.
    TheirForward(Words),
    /// A write the grant consents to was not made; carries why, for the
    /// person.
    Unwritten { write: Write, why: Words },
    /// A credential helper of the person's that the remote's `git` gives
    /// everything that succeeds, what Hedwig releases included, and that may
    /// keep it there; carries the helper as `git config` lists it. Hedwig
    /// leaves it: the list of helpers is the person's.
    HelperBeside(Words),
    /// `git`'s own credential cache listens at the path, started by a `git`
    /// that found the forward down and the folder open, and holds there what
    /// succeeded. It is left running.
    CacheLive(RemotePath),
}

impl Finding {
    /// Whether the capability cannot be carried while this holds. A finding
    /// that does not block is carried, and named beside it.
    pub fn blocks(&self) -> bool {
        match self {
            Finding::Unsurveyed(_)
            | Finding::NoProfile(_)
            | Finding::ToolAbsent(_)
            | Finding::PathTooLong { .. }
            | Finding::PathUnusable
            | Finding::SharedHome(_)
            | Finding::ParentUncreatable(_)
            | Finding::Occupied(_)
            | Finding::AgentLive(_)
            | Finding::ServerLive { .. }
            | Finding::UnitListens { .. }
            | Finding::Answers(_)
            | Finding::Silent(_)
            | Finding::Unprobed(_)
            | Finding::Uncleared(_)
            | Finding::ListenerPresent(_)
            | Finding::ForwardingBlocked
            | Finding::ForwardRefused
            | Finding::CacheLive(_) => true,
            // Without the variable, the file or the helper's line, the
            // remote's tool never finds the forward.
            Finding::Unwritten { write, .. } => {
                matches!(
                    write,
                    Write::Variable(_) | Write::SocketFile | Write::Helper
                )
            }
            Finding::AgentAutostarts
            | Finding::KeyboxdStopped
            | Finding::PublicKeyAbsent(_)
            | Finding::KeyringAbsent
            | Finding::SigningKeyUnset
            | Finding::SigningKeyOther(_)
            | Finding::VariableUnset(_)
            | Finding::TheirForward(_)
            | Finding::HelperBeside(_) => false,
        }
    }
}

/// A change to a remote tool's own configuration that Hedwig makes only with
/// the grant's consent, and reverses when the consent ends.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Write {
    /// `no-autostart` in the remote `GnuPG`'s own configuration, so its `gpg`
    /// never starts an agent that takes the socket while the forward is down.
    NoAutostart,
    /// The public half of a key the workstation offers, in the remote's
    /// keyring.
    PublicKey(Fingerprint),
    /// The key `git` signs with, where `git` names none.
    SigningKey(Mark),
    /// A tool's variable, pointing at the forward, in the remote user's shell
    /// startup.
    Variable(Variable),
    /// The file a Windows remote's `gpg` reads its agent's port and nonce from.
    SocketFile,
    /// Each unit of the remote's service manager that listens at the
    /// capability's far end, masked and stopped with the program it started,
    /// so the forward can bind there and the manager never takes the path
    /// back: systemd's `mask --now`. Its place is the unit's file the mask is.
    Masked,
    /// `git`'s own `cache` helper at the capability's socket, in `git`'s
    /// global configuration after the person's own helpers, so they are asked
    /// first.
    Helper,
}

/// What readiness did on a remote before the channel, recorded so the person
/// can read what Hedwig changed there.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Prepared {
    /// A directory a socket goes in, made private to the remote user.
    Created(RemotePath),
    /// A socket nothing listened at, which would refuse the forward.
    Removed(RemotePath),
}

/// What readiness found for one capability: nothing, or what it named. Each
/// finding says whether it keeps the capability from being carried.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Readiness {
    Ready,
    Unready(Vec<Finding>),
}

/// The remote end of an established forward.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Binding {
    Socket(RemotePath),
    SocketFile { file: RemotePath, port: Port },
    Port(Port),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Serving {
    pub capability: Name,
    pub binding: Binding,
}

/// Where on the remote a reverse a remote asked for lands: the host side of
/// its `adb reverse`, as the remote meant it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    /// `tcp:<port>`: the remote's own loopback.
    Loopback(Port),
    /// `tcp:<host>:<port>`: a host as the remote resolves it.
    Host { host: Host, port: Port },
    /// `localfilesystem:<path>`: a socket on the remote.
    Path(RemotePath),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Loopback(port) => write!(f, "tcp:{port}"),
            Target::Host { host, port } => write!(f, "tcp:{host}:{port}"),
            Target::Path(path) => write!(f, "localfilesystem:{path}"),
        }
    }
}

/// What an ADB capability carries on to a remote beside the channel's own
/// forward, each through a carrier of its own in the channel's job.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Carriage {
    /// `adb reverse`: the device's connections to the workstation reach
    /// `target` on the remote. The endpoint is the reverse's host side as the
    /// workstation's server holds it.
    Reverse(Target),
    /// `adb forward`: `port` on the remote's loopback reaches `socket` on the
    /// lent `device`. The endpoint is the workstation's server's listener for
    /// it, as the person's own `adb forward --list` names it.
    Forward {
        port: Port,
        device: DeviceSerial,
        socket: DeviceSocket,
    },
    /// The console of the lent emulator `device`, at `port` on the remote's
    /// loopback, as its serial names it.
    Console { port: Port, device: DeviceSerial },
}

/// Why a forward or a console stopped being carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dropped {
    /// The remote removed it.
    Removed,
    /// Its device left the workstation's server, and the server its forward.
    Gone,
    /// Its device is no longer lent to the remote.
    Unlent,
    /// Its port on the remote was taken while the channel was away, so the
    /// carrier started again could not listen there.
    Taken,
}

/// Why a channel is being opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Opener {
    Person(ClientId),
    /// A grant's activation: the remote started, or the grant is continuous.
    Grant,
    /// Again, after the last one ended, for what wanted that one.
    Again,
    /// The person asked readiness to be run, with no channel live; nothing
    /// more is opened unless something wants the channel.
    Check(ClientId),
}

/// How a request ended.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Served without asking, on this basis.
    Served(Basis),
    /// Served with nobody reachable, because the person's rule says to.
    Unseen(Basis),
    /// Served because this client's person allowed it.
    Allowed(ClientId),
    /// Served under an allowance the person gave earlier.
    Covered,
    Refused(Refusal),
    /// The remote gave up while it was held.
    Abandoned,
}

/// What is wrong with the workstation's own side of a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Failure {
    /// The tool that says where it lives cannot be found.
    Unresolved,
    /// Nothing answers where it lives.
    Unreachable,
    /// Something answers there that is not what the capability names.
    Mismatched,
    /// The source keeps its agent in a form Hedwig neither starts nor serves:
    /// a POSIX-emulated `GnuPG`'s.
    Unserved,
    /// The host a service names has no address the workstation can find.
    NoAddress,
    /// What holds the source on the workstation - the process listening at
    /// its port or serving its pipe - is another account's and runs no
    /// service an administrator installed, so the remote's connection is not
    /// carried to it.
    Foreign,
    /// What holds the source is the person's account confined by Windows to
    /// less than the person - low or untrusted integrity, restricted, an
    /// application container - so the remote's connection is not carried to
    /// it.
    Confined,
    /// Windows does not let the core read whose the holder is, and it runs no
    /// service, so the remote's connection is not carried to it. A holder
    /// started in the core's own logon is always read.
    Unidentified,
    /// The program a capability opens addresses with is not on the search
    /// path, or Windows would not start it.
    Unstartable,
    /// A capability opens addresses with the person's default browser, and
    /// Windows started nothing for the address: no program opens `https` for
    /// the person, or the one that does would not start.
    Unopened,
    /// The serial port a capability names is not among the workstation's
    /// serial ports now.
    Absent,
    /// Another program holds the serial port a capability names open, which
    /// no second program may then open.
    Busy,
    /// The ADB server is older than platform-tools 35.0.0: its
    /// `host-features` names no `devicetracker_proto_format`, so it lists no
    /// devices in the form a lent device is judged by.
    Outdated,
    /// Every instance of an agent's pipe stayed in use for as long as the
    /// core waits: gpg-agent's pipe serves one program at a time.
    Occupied,
    /// Windows' provider for the workstation's TPM would not open or answer
    /// for this logon: there is no TPM, or none it can use.
    NoTpm,
}

/// Whether the workstation's own side of a capability answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Health {
    Sound,
    Failing(Failure),
}

/// What a card asks for before a key on it is used, as the card itself says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Touch {
    /// Nothing: the key can be used with nobody at the card.
    Off,
    /// A touch for every use.
    On,
    /// A touch, which then covers every use for a short time the card sets.
    Cached,
}

/// By how much a card asks of the person before a key's use: no touch, a
/// touch then cached, a touch every time.
impl Strict for Touch {
    fn strictness(&self, other: &Self) -> Ordering {
        fn asks(touch: Touch) -> u8 {
            match touch {
                Touch::Off => 0,
                Touch::Cached => 1,
                Touch::On => 2,
            }
        }
        asks(*self).cmp(&asks(*other))
    }
}

/// Whether the card asks for its PIN at every signature or once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignaturePin {
    Forced,
    Once,
}

/// One key a card holds, and what the card asks for before it is used where
/// the core could read that.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Held {
    pub grip: Grip,
    pub touch: Option<Touch>,
}

/// A card as the core read it through the person's agent: the keys on it, and
/// the card's own per-use controls, the only ones a compromised remote cannot
/// get past. What it asks for is read only of the card scdaemon reaches first,
/// and only where its first application is `OpenPGP`'s, since reading any
/// other would switch the person's card or application. A card taken out is
/// still the card it was: one key may be on several, and any of them may be
/// put in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Card {
    pub serial: Serial,
    pub keys: Vec<Held>,
    /// Whether the card asks for its PIN at every signature or once, where
    /// read.
    pub pin: Option<SignaturePin>,
}

impl Card {
    /// Whether a key on it can be used with nobody at the card, as far as the
    /// card said.
    pub fn leaves_use_unobserved(&self) -> bool {
        self.keys.iter().any(|held| held.touch == Some(Touch::Off))
    }

    /// What the card asks for before `grip` is used, where it holds that key
    /// and said.
    pub fn touch(&self, grip: &Grip) -> Option<Touch> {
        self.keys
            .iter()
            .find(|held| held.grip == *grip)
            .and_then(|held| held.touch)
    }

    /// The card as known once `newer`, a reading of it again, is taken: the
    /// keys `newer` lists, each with what `newer` says before its use, else
    /// what was said before, since a reading leaves a card unsaid where
    /// scdaemon reached another card first; the same for its PIN. A key
    /// `newer` does not list is no longer on the card.
    #[must_use]
    pub fn read_again(&self, newer: &Card) -> Card {
        Card {
            serial: newer.serial.clone(),
            keys: newer
                .keys
                .iter()
                .map(|held| Held {
                    grip: held.grip.clone(),
                    touch: held.touch.or_else(|| self.touch(&held.grip)),
                })
                .collect(),
            pin: newer.pin.or(self.pin),
        }
    }

    /// Whether the two readings ask the same of the person.
    fn asks_as(&self, other: &Card) -> bool {
        self.pin == other.pin
            && self.keys.len() == other.keys.len()
            && self
                .keys
                .iter()
                .all(|held| other.touch(&held.grip) == held.touch)
    }
}

/// What a key may be used for, as `GnuPG`'s listing says: a set, since one
/// key can sign and authenticate.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Uses(u8);

impl Uses {
    pub const NONE: Uses = Uses(0);
    pub const SIGN: Uses = Uses(1);
    pub const ENCRYPT: Uses = Uses(1 << 1);
    pub const AUTHENTICATE: Uses = Uses(1 << 2);

    const WORDS: [(Uses, &'static str); 3] = [
        (Uses::SIGN, "sign"),
        (Uses::ENCRYPT, "encrypt"),
        (Uses::AUTHENTICATE, "authenticate"),
    ];

    #[must_use]
    pub const fn with(self, other: Uses) -> Uses {
        Uses(self.0 | other.0)
    }

    pub const fn has(self, member: Uses) -> bool {
        self.0 & member.0 == member.0 && member.0 != 0
    }

    pub fn words(self) -> impl Iterator<Item = &'static str> {
        Uses::WORDS
            .into_iter()
            .filter(move |(member, _)| self.has(*member))
            .map(|(_, word)| word)
    }

    pub fn from_word(word: &str) -> Option<Uses> {
        Uses::WORDS
            .into_iter()
            .find(|(_, known)| *known == word)
            .map(|(member, _)| member)
    }
}

impl std::fmt::Debug for Uses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.words()).finish()
    }
}

/// A key the workstation's `GnuPG` holds the secret half of, as its own
/// listing names it: a primary key or a subkey.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    /// What a request names it by: the keygrip gpg-agent uses.
    pub grip: Grip,
    pub fingerprint: Fingerprint,
    /// The fingerprint of the key it belongs to, by which a remote's keyring
    /// and `git` know it; its own, for a primary key.
    pub primary: Fingerprint,
    pub uses: Uses,
    /// The primary key's first user ID, as the listing gives it.
    pub user: Option<Words>,
    /// The card it is on, as the agent's stub of it names the card; `None`
    /// for a key whose secret the agent holds itself.
    pub card: Option<Serial>,
    /// Its public half as an SSH key, as the agent itself writes it, by which
    /// a request through the agent's SSH socket names it; `None` for a key
    /// of a kind SSH has none for.
    pub ssh: Option<SshKey>,
}

/// The keys a `GnuPG` capability's source offers, and the one the person
/// signs with where they said which.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Keyring {
    pub keys: Vec<Key>,
    /// What the person's own tools name as their signing key, written as
    /// `git` takes it: the workstation's `git` signing key, else `GnuPG`'s
    /// `default-key`, where it names a key here; else the one key here that
    /// signs, where there is exactly one.
    pub signing: Option<Mark>,
}

impl Keyring {
    /// Each key, once, by its primary fingerprint: what a remote's keyring
    /// holds.
    pub fn primaries(&self) -> Vec<Fingerprint> {
        let mut primaries: Vec<Fingerprint> = Vec::new();
        for key in &self.keys {
            if !primaries.contains(&key.primary) {
                primaries.push(key.primary.clone());
            }
        }
        primaries
    }

    /// Every fingerprint by which a `git` signing key names a key here that
    /// signs, or the key it belongs to.
    pub fn signers(&self) -> Vec<Fingerprint> {
        let mut signers: Vec<Fingerprint> = Vec::new();
        for key in self.keys.iter().filter(|key| key.uses.has(Uses::SIGN)) {
            for name in [&key.primary, &key.fingerprint] {
                if !signers.contains(name) {
                    signers.push(name.clone());
                }
            }
        }
        signers
    }

    /// The key a keygrip names, where it is one of these.
    pub fn by_grip(&self, grip: &Grip) -> Option<&Key> {
        self.keys.iter().find(|key| key.grip == *grip)
    }

    /// The key an SSH request names by its public half, where it is one of
    /// these.
    pub fn by_ssh(&self, ssh: &SshKey) -> Option<&Key> {
        self.keys.iter().find(|key| key.ssh.as_ref() == Some(ssh))
    }
}

/// Why a callback port stopped being carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Carry {
    /// The authorisation server's answer reached the remote's tool.
    Called,
    /// The flow's time ran out first.
    Expired,
    /// The channel it rode ended first.
    Ended,
}

/// How a run of the core ended when neither the person nor the end of their
/// session ended it. The supervisor saw it and tells the next run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Breakdown {
    /// The core's process ended by itself, with this exit status.
    Exited { status: u32 },
    /// The core stopped answering its supervisor, which ended it.
    Hung,
    /// The core could not be started at all.
    Unstarted,
}

/// One of the two things the core keeps on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Store {
    Trail,
    Configuration,
}

/// Something that can be brought to the person's attention and put away by
/// them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Item {
    Unready {
        remote: RemoteId,
        capability: Name,
    },
    Stopped(RemoteId),
    Burst(RemoteId),
    Safeguards(Serial),
    Refused {
        remote: Option<RemoteId>,
        refusal: Refusal,
    },
    Restarted,
    Unreadable(Store),
    /// A change that let more through, by the entry that recorded it.
    Widened(Seq),
    /// What was served to a remote while nobody was reachable.
    Unseen(RemoteId),
    /// What changed in one place of the organisation's policy.
    Policy(Place),
    /// A route's listing that could not be read.
    Unlisted(Name),
    /// A remote's notice, by the entry that recorded it; putting it away puts
    /// away every earlier one from that remote too.
    Noticed {
        remote: RemoteId,
        through: Seq,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The core began a run. Everything attached, connected, held or allowed
    /// in an earlier run is over. `after` is how the run before it broke
    /// down, when its supervisor saw that.
    Started {
        version: String,
        origin: Origin,
        after: Option<Breakdown>,
    },
    /// What the core kept on disk could not be read, and was set aside. For
    /// the trail, whether the person had paused anything is no longer known,
    /// so everything is paused from here; for the configuration, nothing is
    /// granted until a document is imported. `account` is the reader's own.
    Unreadable {
        store: Store,
        account: String,
    },
    /// A client greeted the core. `attends` is the remotes an attending
    /// client watches: a terminal opened to answer one remote's prompts is
    /// not the person watching every remote.
    Attached {
        kind: ClientKind,
        origin: Origin,
        attends: Remotes,
    },
    Presence {
        client: ClientId,
        presence: Presence,
    },
    /// What an interface said of its icon, where it differs from what it
    /// last said. The presence's own report, never the person's act: it
    /// says nothing of where the person is.
    Icon {
        client: ClientId,
        icon: Icon,
    },
    Detached {
        client: ClientId,
    },

    Changed {
        change: Change,
        by: ClientId,
        reach: Reach,
    },
    Imported {
        by: ClientId,
        reach: Reach,
    },
    Paused {
        scope: Remotes,
        by: ClientId,
    },
    Resumed {
        scope: Remotes,
        by: ClientId,
    },

    /// A route's platform reports the remote running.
    Appeared {
        remote: RemoteId,
    },
    Gone {
        remote: RemoteId,
    },
    /// A channel is being opened; the entry names the connection. `with` are
    /// capabilities the person added for this connection alone.
    Opening {
        remote: RemoteId,
        with: Vec<Name>,
        /// What the person named that `with` exposes.
        acknowledged: Exposure,
        /// The devices what `with` adds lends.
        lends: Lends,
        opener: Opener,
    },
    /// The program the channel's client was started from, the release its
    /// file states, where it states one, and whom it was let ask.
    Ran {
        connection: ConnectionId,
        program: Location,
        release: Option<Release>,
        asking: Asking,
    },
    /// The remote reported its platform family.
    Observed {
        connection: ConnectionId,
        platform: Name,
    },
    Checked {
        connection: ConnectionId,
        capability: Name,
        readiness: Readiness,
    },
    /// Readiness changed something on the remote for a capability.
    Prepared {
        connection: ConnectionId,
        capability: Name,
        prepared: Prepared,
    },
    /// Hedwig wrote a remote tool's own configuration, with the grant's
    /// consent; `place` is the file or keyring it went in, and `made` what
    /// did not exist until the write needed it - the outermost folder, or for
    /// a key the keybox its import made - which the reversal takes back with
    /// it.
    Wrote {
        connection: ConnectionId,
        capability: Name,
        write: Write,
        place: RemotePath,
        made: Option<RemotePath>,
    },
    /// Hedwig took back what it wrote there, the consent having ended.
    Unwrote {
        connection: ConnectionId,
        capability: Name,
        write: Write,
        place: RemotePath,
    },
    /// The channel's client asks the person something, in its own or the
    /// server's words; the entry names the prompt.
    Prompted {
        connection: ConnectionId,
        kind: PromptKind,
        words: Words,
    },
    /// The prompt is over: answered at a client, or, with `None`, withdrawn
    /// by the channel's client.
    Answered {
        prompt: PromptId,
        by: Option<Gave>,
    },
    Up {
        connection: ConnectionId,
        serving: Vec<Serving>,
    },
    Down {
        connection: ConnectionId,
        end: ChannelEnd,
    },
    /// The person asked that no channel be held to the remote for now. A
    /// live one ends with its own entry.
    Disconnected {
        remote: RemoteId,
        by: ClientId,
    },
    /// What a route's listing said changed: `account` is why it could not be
    /// read, and `None` is a listing read again.
    Unlisted {
        route: Name,
        account: Option<Words>,
    },

    /// A connection to a workstation endpoint was turned away before any
    /// request.
    TurnedAway {
        remote: Option<RemoteId>,
        refusal: Refusal,
    },
    /// A remote asks; the entry names the request. `key` is the key the
    /// request uses as its dialect names it, where it names one: for Assuan,
    /// the keygrip gpg-agent would use.
    Asked {
        connection: ConnectionId,
        capability: Name,
        operation: Operation,
        key: Option<KeyId>,
    },
    /// The request waits for the person.
    Held {
        request: RequestId,
    },
    Settled {
        request: RequestId,
        outcome: Outcome,
    },
    /// The workstation's browser was given the URL a served request carried:
    /// the site it leads to, and the remote's loopback port carried for its
    /// callback, where it has one. The URL itself is not kept: a device
    /// code's page can carry the code.
    Browsed {
        request: RequestId,
        site: Site,
        callback: Option<Port>,
    },
    /// The callback port a request carried is no longer carried, and why.
    Uncarried {
        request: RequestId,
        end: Carry,
    },
    /// What a request asks for, as its payload says: recorded with the
    /// request, so what each remote did with a key or asked of a site is on
    /// record whatever the outcome.
    Payload {
        request: RequestId,
        payload: Payload,
    },
    /// A served request for a credential found none: no helper the
    /// workstation's `git` asks held one for the site, or one needed to ask
    /// the person and could not. The remote's `git` was given nothing and
    /// goes on to its own next helper.
    Unreleased {
        request: RequestId,
    },
    /// The remote's `git` said `site` refused a credential it was given - the
    /// `erase` it sends after every refusal. The forge's word, not the
    /// workstation's: the credential is unchanged here.
    Refuted {
        connection: ConnectionId,
        capability: Name,
        site: Site,
    },
    /// A remote's job told the person `remark`, through `capability`;
    /// `unheard` is how many of that remote's notices were turned away for
    /// coming too fast since the last one that was not.
    Noticed {
        connection: ConnectionId,
        capability: Name,
        remark: Remark,
        unheard: u32,
    },
    /// What holds `capability`'s source on this workstation - the process
    /// listening at its port or serving its pipe - as the core read it on a
    /// connection it made there, where it differs from the last read; `None`
    /// where nothing answered.
    HeldBy {
        capability: Name,
        holder: Option<SourceHolder>,
    },
    /// What the core writes about what went wrong for the rest of this run,
    /// chosen by `by`; `None` is as this workstation's setting says.
    Diagnosed {
        level: Option<Diagnostics>,
        by: ClientId,
    },
    /// What Windows starts at sign-in for one start-up choice, as the core
    /// found it keeping the choice's `Run` value, where it differs from the
    /// last found in this run.
    Startup {
        starts: Starts,
        found: AtSignIn,
    },
    /// Hedwig made a key in the workstation's TPM, named `name`, at `by`'s
    /// asking. The TPM holds which keys there are; this is what happened.
    KeyMade {
        key: SshKey,
        name: Name,
        by: ClientId,
    },
    /// Hedwig deleted a key it made from the workstation's TPM, at `by`'s
    /// asking. Nothing can bring it back.
    KeyDeleted {
        key: SshKey,
        name: Name,
        by: ClientId,
    },
    /// The person allowed further requests like this one until `until`: the
    /// same operation on the same capability through the same connection,
    /// with the same key where the request named one.
    Allowed {
        connection: ConnectionId,
        capability: Name,
        operation: Operation,
        key: Option<KeyId>,
        until: Tick,
        by: ClientId,
    },
    /// A rule was set on one connection, or cleared with `None`.
    Ruled {
        connection: ConnectionId,
        scope: ConnectionScope,
        mode: Option<Mode>,
        by: ClientId,
    },

    /// The remote's own tool used `capability` once through `connection`,
    /// at the asking of `by`, and this is what it did.
    Exercised {
        connection: ConnectionId,
        capability: Name,
        proof: Proof,
        by: ClientId,
    },

    /// The workstation's side of a capability was tried.
    Source {
        capability: Name,
        health: Health,
    },
    /// A card scdaemon holds, read where it differs from what was last
    /// recorded of it.
    Card(Card),
    /// The keys the source of a `GnuPG` capability offers, read from its own
    /// tools where they differ from what was last recorded.
    Offered {
        capability: Name,
        keyring: Keyring,
    },
    /// What `connection`'s remote asked of an ADB capability, or a console
    /// it was lent, is carried on to it through the core's `endpoint`, held
    /// for this run.
    Carried {
        connection: ConnectionId,
        capability: Name,
        carriage: Carriage,
        endpoint: Port,
    },
    /// A forward or a console carried on to `connection`'s remote is not
    /// carried any more, and why.
    Dropped {
        connection: ConnectionId,
        capability: Name,
        carriage: Carriage,
        why: Dropped,
    },
    /// The serial port `capability` names was opened for the served
    /// `request`, the opening of `connection`, and is held for it alone;
    /// `usb` is the USB device behind it, where it is one.
    Taken {
        request: RequestId,
        connection: ConnectionId,
        capability: Name,
        port: PortName,
        usb: Option<Usb>,
    },
    /// The serial port `request` held was closed: its connection ended.
    Released {
        request: RequestId,
    },
    PutAway {
        item: Item,
        by: ClientId,
    },
    Stopping {
        by: ClientId,
    },
    /// The person removes Hedwig: every consent to write on a remote ends,
    /// and every survey from here takes back what Hedwig wrote there.
    Withdrawn {
        by: ClientId,
    },
    /// The person keeps Hedwig after all: what they consented to is written
    /// again, and channels are held as their grants say.
    Restored {
        by: ClientId,
    },
    /// The entries before this one were dropped: `dropped` of them, cut
    /// where `cut` says. What they folded to is the trail's head, from which
    /// folding what follows gives what folding the whole trail gave.
    Kept {
        dropped: u64,
        cut: Cut,
    },
    /// The organisation now makes this statement: it was read where the
    /// organisation keeps its policy and was not there at the last reading.
    Stated {
        audience: Audience,
        statement: Statement,
    },
    /// The organisation no longer makes this statement.
    Unstated {
        audience: Audience,
        statement: Statement,
    },
    /// What of one place could not be read changed; `None` is every line of
    /// it read.
    Misread {
        place: Place,
        unread: Option<Unread>,
    },
    /// Windows said the workstation is about to sleep. Nothing is served
    /// from here until it wakes, and nothing keeps it awake.
    Sleeping,
    /// Windows said the workstation has woken. The run goes on: `tick` has
    /// counted the sleep, so a deadline that fell inside it has passed.
    Woke,
    /// Windows hints the workstation now reaches no network.
    Offline,
    /// Windows hints it reaches one again: every channel waiting to come
    /// back is tried at once.
    Online,
}

/// Whether the workstation reaches a network, as Windows last hinted. A hint
/// only: a channel is tried whatever it says, and waits for it to change
/// only after an attempt has failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Network {
    #[default]
    Online,
    Offline,
}

/// Who answered a prompt, and what with. The text itself is never recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gave {
    pub client: ClientId,
    pub given: Given,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Given {
    Text,
    Accepted,
    Declined,
}

impl Event {
    /// The client whose act this entry records, where it records one.
    pub fn by(&self) -> Option<ClientId> {
        match self {
            Event::Changed { by, .. }
            | Event::Imported { by, .. }
            | Event::Paused { by, .. }
            | Event::Resumed { by, .. }
            | Event::Allowed { by, .. }
            | Event::Ruled { by, .. }
            | Event::PutAway { by, .. }
            | Event::Stopping { by }
            | Event::Withdrawn { by }
            | Event::Restored { by }
            | Event::Diagnosed { by, .. }
            | Event::Exercised { by, .. }
            | Event::Presence { client: by, .. }
            | Event::Opening {
                opener: Opener::Person(by) | Opener::Check(by),
                ..
            }
            | Event::Disconnected { by, .. }
            | Event::Answered {
                by: Some(Gave { client: by, .. }),
                ..
            }
            | Event::Settled {
                outcome: Outcome::Allowed(by),
                ..
            } => Some(*by),
            _ => None,
        }
    }

    /// Whether this entry records what the core read of the workstation or
    /// its routes, never a client's act. What it makes stale is told to the
    /// client whose request led to the reading too, since that request's
    /// reply does not carry it.
    pub fn is_reading(&self) -> bool {
        matches!(
            self,
            Event::HeldBy { .. }
                | Event::Startup { .. }
                | Event::Source { .. }
                | Event::Card(_)
                | Event::Offered { .. }
                | Event::Appeared { .. }
                | Event::Gone { .. }
        )
    }

    /// Whether this entry records an act that can let a remote reach more,
    /// or be served with less asked of the person, than before it.
    fn lets_more_through(&self) -> bool {
        match self {
            Event::Changed { reach, .. } | Event::Imported { reach, .. } => *reach == Reach::Wider,
            Event::Resumed { .. } | Event::Restored { .. } => true,
            Event::Ruled { mode, .. } => *mode != Some(Mode::Confirm),
            Event::Opening {
                with,
                opener: Opener::Person(_),
                ..
            } => !with.is_empty(),
            _ => false,
        }
    }

    /// Which of what a surface shows this entry makes stale. Everything
    /// [`about`] counts as a remote's activity makes `Exposure` stale, under
    /// which a surface reads that activity; everything that changes what
    /// [`crate::gate::World::workstation`] reads makes `Workstation` stale.
    pub fn touches(&self) -> &'static [Topic] {
        match self {
            Event::Started { .. } => &[Topic::Status, Topic::Workstation],
            Event::Attached { .. }
            | Event::Presence { .. }
            | Event::Icon { .. }
            | Event::Detached { .. }
            | Event::Stopping { .. }
            | Event::Offline
            | Event::Online => &[Topic::Status],
            Event::Kept { .. } => &[Topic::Status, Topic::Exposure],
            Event::Withdrawn { .. } | Event::Restored { .. } => {
                &[Topic::Status, Topic::Exposure, Topic::Attention]
            }
            // Nothing a surface shows changes; a follower is given the entry.
            // A key's making and deleting are told to the clients that list
            // keys under their own topic, which names the capability.
            Event::Sleeping | Event::Woke | Event::KeyMade { .. } | Event::KeyDeleted { .. } => &[],
            Event::Ran { .. }
            | Event::Prepared { .. }
            | Event::Exercised { .. }
            | Event::Wrote { .. }
            | Event::Unwrote { .. }
            | Event::Carried { .. }
            | Event::Dropped { .. }
            | Event::Taken { .. }
            | Event::Released { .. }
            | Event::Browsed { .. }
            | Event::Payload { .. }
            | Event::Refuted { .. }
            | Event::Unreleased { .. }
            | Event::Uncarried { .. } => &[Topic::Exposure],
            Event::Unlisted { .. } => &[Topic::Status, Topic::Attention],
            Event::Changed { .. }
            | Event::Imported { .. }
            | Event::Stated { .. }
            | Event::Unstated { .. }
            | Event::Misread { .. } => &[Topic::Configuration, Topic::Exposure, Topic::Attention],
            Event::Paused { .. } | Event::Resumed { .. } | Event::Disconnected { .. } => {
                &[Topic::Status, Topic::Exposure]
            }
            Event::Card { .. }
            | Event::Unreadable {
                store: Store::Trail,
                ..
            } => &[Topic::Attention, Topic::Workstation],
            Event::PutAway { .. } | Event::Unreadable { .. } => &[Topic::Attention],
            Event::Offered { .. } | Event::HeldBy { .. } => &[Topic::Exposure, Topic::Workstation],
            Event::Startup { .. } | Event::Diagnosed { .. } => &[Topic::Configuration],
            Event::Appeared { .. } | Event::Gone { .. } | Event::Source { .. } => &[
                Topic::Status,
                Topic::Exposure,
                Topic::Attention,
                Topic::Workstation,
            ],
            Event::Opening { .. }
            | Event::Observed { .. }
            | Event::Checked { .. }
            | Event::Up { .. }
            | Event::Down { .. } => &[Topic::Status, Topic::Exposure, Topic::Attention],
            Event::Prompted { .. }
            | Event::Noticed { .. }
            | Event::Answered { .. }
            | Event::TurnedAway { .. }
            | Event::Asked { .. }
            | Event::Held { .. }
            | Event::Settled { .. }
            | Event::Allowed { .. }
            | Event::Ruled { .. } => &[Topic::Exposure, Topic::Attention],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: Seq,
    pub at: Timestamp,
    pub tick: Tick,
    pub event: Event,
}

/// The entries about `remote`, in the trail's order: each connection to it
/// from its opening to its end, live or over, with every request, prompt,
/// allowance and rule on it and what readiness found and changed through it;
/// a change of what holds a capability's source while a connection to it
/// serves that capability; the remote appearing and going; a connection
/// turned away from its forwards; the person disconnecting it; and each pause
/// or resume that covers it, read against `sets`. A change to the
/// configuration is the configuration's, and is read in the whole trail.
///
/// Every remote's activity reaches back to the [`Event::Kept`] that cut the
/// trail, which says how much went and why.
///
/// One pass: a request or a prompt is about the remote its connection is,
/// and the entry that names a connection, a request or a prompt precedes
/// every entry that refers to it, or was folded into `head`, whose live
/// connections, requests and prompts are read from it.
pub fn about<'e>(
    head: &State,
    entries: &'e [Entry],
    remote: &RemoteId,
    sets: &Sets<'_>,
) -> impl Iterator<Item = &'e Entry> {
    let mut connections: BTreeSet<ConnectionId> = BTreeSet::new();
    // What each live connection to the remote serves, from its `Up` to its
    // `Down`.
    let mut serving: BTreeMap<ConnectionId, Vec<Name>> = BTreeMap::new();
    for (connection, link) in &head.links {
        if link.remote == *remote {
            connections.insert(*connection);
            if let Phase::Up(served) = &link.phase {
                serving.insert(*connection, names(served));
            }
        }
    }
    let (live, waiting) = kept(head, &connections);
    let mut requests: BTreeSet<RequestId> = live.into_iter().collect();
    let mut prompts: BTreeSet<PromptId> = waiting.into_iter().collect();
    let mut found = Vec::new();
    for entry in entries {
        let of = |connection: &ConnectionId| connections.contains(connection);
        let concerns = match &entry.event {
            Event::Kept { .. } => true,
            Event::Up {
                connection,
                serving: served,
            } => {
                let ours = of(connection);
                if ours {
                    serving.insert(*connection, names(served));
                }
                ours
            }
            Event::Down { connection, .. } => {
                let ours = of(connection);
                serving.remove(connection);
                ours
            }
            Event::HeldBy { capability, .. } => {
                serving.values().any(|served| served.contains(capability))
            }
            Event::Opening { remote: opened, .. } => {
                let ours = opened == remote;
                if ours {
                    connections.insert(ConnectionId(entry.seq));
                }
                ours
            }
            Event::Asked { connection, .. } => {
                let ours = of(connection);
                if ours {
                    requests.insert(RequestId(entry.seq));
                }
                ours
            }
            Event::Prompted { connection, .. } => {
                let ours = of(connection);
                if ours {
                    prompts.insert(PromptId(entry.seq));
                }
                ours
            }
            Event::Ran { connection, .. }
            | Event::Observed { connection, .. }
            | Event::Checked { connection, .. }
            | Event::Prepared { connection, .. }
            | Event::Wrote { connection, .. }
            | Event::Unwrote { connection, .. }
            | Event::Allowed { connection, .. }
            | Event::Ruled { connection, .. }
            | Event::Exercised { connection, .. }
            | Event::Carried { connection, .. }
            | Event::Dropped { connection, .. }
            | Event::Taken { connection, .. }
            | Event::Refuted { connection, .. }
            | Event::Noticed { connection, .. } => of(connection),
            Event::Held { request }
            | Event::Settled { request, .. }
            | Event::Released { request }
            | Event::Browsed { request, .. }
            | Event::Payload { request, .. }
            | Event::Unreleased { request }
            | Event::Uncarried { request, .. } => requests.contains(request),
            Event::Answered { prompt, .. } => prompts.contains(prompt),
            Event::Appeared { remote: named }
            | Event::Gone { remote: named }
            | Event::Disconnected { remote: named, .. }
            | Event::TurnedAway {
                remote: Some(named),
                ..
            } => named == remote,
            Event::Paused { scope, .. } | Event::Resumed { scope, .. } => {
                scope.covers(remote, sets)
            }
            _ => false,
        };
        if concerns {
            found.push(entry);
        }
    }
    found.into_iter()
}

/// The requests and prompts a compaction kept as live on `connections`.
fn kept(state: &State, connections: &BTreeSet<ConnectionId>) -> (Vec<RequestId>, Vec<PromptId>) {
    let requests = state
        .asks
        .iter()
        .filter(|(_, ask)| connections.contains(&ask.connection))
        .map(|(request, _)| *request)
        .chain(
            state
                .taken
                .iter()
                .filter(|(_, (connection, ..))| connections.contains(connection))
                .map(|(request, _)| *request),
        )
        .collect();
    let prompts = state
        .prompts
        .iter()
        .filter(|(_, prompt)| connections.contains(&prompt.connection))
        .map(|(prompt, _)| *prompt)
        .collect();
    (requests, prompts)
}

/// The capabilities a connection serves.
fn names(serving: &[Serving]) -> Vec<Name> {
    serving
        .iter()
        .map(|serving| serving.capability.clone())
        .collect()
}

/// One page of activity, oldest first: the newest `limit` entries before
/// `before`, of the whole trail or of what [`about`] reads as one remote's.
/// The core and every stand-in for it answer [`crate::protocol::Request::Activity`]
/// with this; `head` is what the entries before the first were folded into.
pub fn page(
    head: &State,
    entries: &[Entry],
    remote: &Selector<RemoteId>,
    sets: &Sets<'_>,
    before: Option<Seq>,
    limit: NonZeroU8,
) -> Vec<Entry> {
    let earlier = |entry: &&Entry| before.is_none_or(|before| entry.seq < before);
    let newest = |found: &mut dyn DoubleEndedIterator<Item = &Entry>| -> Vec<Entry> {
        let mut page: Vec<Entry> = found
            .rev()
            .filter(earlier)
            .take(usize::from(limit.get()))
            .cloned()
            .collect();
        page.reverse();
        page
    };
    match remote {
        Selector::Every => newest(&mut entries.iter()),
        Selector::Only(remote) => {
            let found: Vec<&Entry> = about(head, entries, remote, sets).collect();
            newest(&mut found.into_iter())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surface {
    pub kind: ClientKind,
    pub origin: Origin,
    pub presence: Presence,
    /// What it last said of its icon; `None` until it says anything.
    pub icon: Option<Icon>,
    /// The remotes this client watches.
    pub attends: Remotes,
    /// The last entry that showed the person at this client: it attached,
    /// came back, or did something.
    pub seen: Seq,
}

/// An act that let more through, with who made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Widened {
    pub entry: Entry,
    pub kind: ClientKind,
    pub origin: Origin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Opening,
    Up(Vec<Serving>),
}

/// One live connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub remote: RemoteId,
    pub with: BTreeSet<Name>,
    /// What the person named that `with` exposes.
    pub acknowledged: Exposure,
    /// The devices what `with` adds lends.
    pub lends: Lends,
    /// Why it was opened.
    pub opener: Opener,
    pub phase: Phase,
    /// When the server had answered for every forward.
    pub up: Option<Tick>,
    pub platform: Option<Name>,
    pub readiness: BTreeMap<Name, Readiness>,
    pub rules: BTreeMap<ConnectionScope, Mode>,
}

/// A remote whose channel ended and comes back when its wait is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Returning {
    /// Attempts in a row that ended before they settled.
    pub failed: u32,
    /// When the last one ended.
    pub since: Tick,
    /// Tried at once, whatever the wait: the workstation woke, reaches a
    /// network again, or what the remote holds changed.
    pub hurried: bool,
}

/// What a request asks for, as its dialect reads it: what an SSH agent request
/// asks to have signed, read as OpenSSH's own agent reads it (`ssh-agent.c`,
/// `parse_userauth_request`, `parse_sshsig_request`), or the site a remote's
/// `git` asks a credential for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Payload {
    /// A credential for this site, the narrowest that admits what the
    /// remote's `git` named.
    Credential { site: Site },
    /// A user authentication to an SSH server: the user logged in as, where
    /// it is words, and the server's own key where the request names it,
    /// which an OpenSSH server checks against its own.
    Authentication {
        user: Option<Words>,
        host: Option<SshKey>,
    },
    /// An `SSHSIG` signature, as `ssh-keygen -Y sign` and `git` make one:
    /// its namespace, where it is words - `git` for a commit or a tag.
    Signature { namespace: Option<Words> },
    /// Data in neither form.
    Unread,
}

/// A request not yet settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub connection: ConnectionId,
    pub capability: Name,
    pub operation: Operation,
    pub key: Option<KeyId>,
    /// What it asks for, where its payload was recorded.
    pub payload: Option<Payload>,
    pub held: bool,
}

/// One notice a remote's job sent, kept for the person's attention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Noted {
    pub seq: Seq,
    pub at: Timestamp,
    pub remark: Remark,
    pub unheard: u32,
}

/// What one remote's jobs have told the person: the newest kept, and when
/// the latest arrived in this run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Notices {
    pub(crate) kept: VecDeque<Noted>,
    pub(crate) recent: VecDeque<Tick>,
}

/// The most notices kept for the person's attention per remote, the oldest
/// dropped. Invariant: more than a person reads at a glance; every one stays
/// in the remote's activity.
pub const NOTICES_KEPT: usize = 16;

/// The most notices one remote passes on in [`NOTICE_WINDOW`]; past it a
/// notice is turned away and counted. Invariant: one every six seconds,
/// beyond any job's own milestones a person follows; it keeps a remote from
/// filling the trail and the person's screen.
pub const NOTICES_AT_ONCE: usize = 10;

/// The window [`NOTICES_AT_ONCE`] counts in, in milliseconds of the trail's
/// clock.
pub const NOTICE_WINDOW: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub connection: ConnectionId,
    pub kind: PromptKind,
    pub words: Words,
}

/// The most request times kept per remote, which bounds what a burst
/// threshold can count. Invariant: a performance bound on the fold.
const RECENT: usize = u8::MAX as usize;
/// The most distinct refusals kept for the person's attention. Invariant: a
/// safety bound on what a hostile local process can make the core hold.
const REFUSALS: usize = 64;
/// The most acts that let more through kept for the person's attention, the
/// oldest dropped. Invariant, for the reason `REFUSALS` is: a client that
/// changes the configuration in a loop must not grow the core's state.
const WIDENINGS: usize = 64;

/// Why a compaction cut the trail where it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cut {
    /// What it dropped is older than the person keeps.
    Horizon,
    /// What it dropped is inside the horizon, past the most the trail keeps.
    Ceiling,
}

/// The most entries the trail keeps, on disk and in memory. Invariant: the
/// bound on reading and folding it at every start (232 ms, measured).
pub const CEILING: usize = 100_000;

/// The version of the trail's form, which its first line names
/// (`{"trail":1}`). A build reads its own and every earlier one.
pub const FORM: u32 = 1;

/// The trail's first line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Form {
    pub trail: u32,
}

/// The trail whose entries before the first were folded into `head`, with
/// the entries older than `before`, and any beyond the newest `ceiling`,
/// folded into it too and dropped: one [`Event::Kept`] in their place says
/// how many and why, and the rest are as they were, with their own numbers.
/// Folding the result from its head gives what folding `entries` from
/// `head` gave, and a trail with nothing to drop is returned as it was.
pub fn compact(
    head: State,
    entries: Vec<Entry>,
    before: Timestamp,
    ceiling: usize,
) -> (State, Vec<Entry>) {
    let old = entries
        .iter()
        .position(|entry| entry.at >= before)
        .unwrap_or(entries.len());
    let over = entries.len().saturating_sub(ceiling);
    let (cut, why) = if over > old {
        (over, Cut::Ceiling)
    } else {
        (old, Cut::Horizon)
    };
    let already = |entry: &Entry| matches!(entry.event, Event::Kept { .. });
    let dropped = match entries.get(..cut) {
        None | Some([]) => return (head, entries),
        Some([only]) if already(only) => return (head, entries),
        Some(dropped) => dropped,
    };
    let Some(last) = dropped.last() else {
        return (head, entries);
    };
    let kept = Entry {
        seq: last.seq,
        at: last.at,
        tick: last.tick,
        event: Event::Kept {
            dropped: dropped.iter().filter(|entry| !already(entry)).count() as u64,
            cut: why,
        },
    };
    let head = State::after(head, dropped);
    let mut compacted = Vec::with_capacity(entries.len() - cut + 1);
    compacted.push(kept);
    compacted.extend(entries.into_iter().skip(cut));
    (head, compacted)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct State {
    pub(crate) started: Option<(Seq, Timestamp, String, Origin)>,
    pub(crate) surfaces: BTreeMap<ClientId, Surface>,
    pub(crate) paused: BTreeSet<Remotes>,
    pub(crate) running: BTreeSet<RemoteId>,
    pub(crate) links: BTreeMap<ConnectionId, Link>,
    pub(crate) ended: BTreeMap<RemoteId, (ChannelEnd, Seq)>,
    pub(crate) asks: BTreeMap<RequestId, Ask>,
    pub(crate) prompts: BTreeMap<PromptId, Prompt>,
    pub(crate) allowances: BTreeMap<(ConnectionId, Name, Operation, Option<KeyId>), Tick>,
    pub(crate) recent: BTreeMap<RemoteId, VecDeque<Tick>>,
    pub(crate) last: BTreeMap<(RemoteId, Name), Last>,
    pub(crate) unready: BTreeMap<(RemoteId, Name), (Vec<Finding>, Seq)>,
    /// The platform each remote last reported, which readiness reads to
    /// choose the shell it asks in first.
    pub(crate) observed: BTreeMap<RemoteId, Name>,
    /// What Hedwig has written on each remote and not taken back, as far as
    /// it knows, with where it went and the outermost folder it made for it.
    pub(crate) written: BTreeMap<RemoteId, Writes>,
    pub(crate) refused: BTreeMap<Item, (u32, Seq)>,
    pub(crate) sources: BTreeMap<Name, Health>,
    /// Each card as last read, and the entry since which it has asked what it
    /// asks now.
    pub(crate) cards: BTreeMap<Serial, (Card, Seq)>,
    /// The keys each `GnuPG` capability's source last offered, across runs.
    pub(crate) offered: BTreeMap<Name, Keyring>,
    /// What last held each capability's source in this run.
    pub(crate) holders: BTreeMap<Name, Option<SourceHolder>>,
    /// What Windows starts at sign-in for each start-up choice, as last
    /// found in this run.
    pub(crate) startup: BTreeMap<Starts, AtSignIn>,
    /// What the person chose the core writes about what went wrong for this
    /// run, where they chose.
    pub(crate) diagnose: Option<Diagnostics>,
    /// What each ADB capability carries on to each remote in this run, each
    /// with the core's endpoint for it: a reverse until the run ends, a
    /// forward or a console until it is dropped.
    pub(crate) carried: BTreeMap<(RemoteId, Name), BTreeMap<Carriage, Port>>,
    /// Each serial port held for a served request in this run, with its
    /// connection, its capability and when it was taken.
    pub(crate) taken: BTreeMap<RequestId, (ConnectionId, Name, PortName, Timestamp)>,
    /// The USB device each serial port was last opened over, across runs:
    /// what a row says a remote's tool cannot do through it.
    pub(crate) seen: BTreeMap<String, Usb>,
    pub(crate) put_away: BTreeMap<Item, (Seq, Tick)>,
    /// What each remote's jobs told the person and they have not put away,
    /// across runs.
    pub(crate) notices: BTreeMap<RemoteId, Notices>,
    /// How the last run to break down did so, and how many have since the
    /// person last put the matter away.
    pub(crate) restarted: Option<(Breakdown, u32)>,
    pub(crate) unreadable: BTreeMap<Store, String>,
    /// The acts that let more through and have not been put away.
    pub(crate) widened: BTreeMap<Seq, Widened>,
    /// How many requests each remote was served with nobody reachable, since
    /// the person last put the matter away.
    pub(crate) unseen: BTreeMap<RemoteId, u32>,
    /// What the organisation states, as last read.
    pub(crate) policy: Policy,
    /// What changed in each place of the organisation's policy since the
    /// person last put it away.
    pub(crate) restated: BTreeMap<Place, Restated>,
    /// The remotes the person connected in this run and has not
    /// disconnected, with what they added for the connection.
    pub(crate) asked: BTreeMap<RemoteId, BTreeSet<Name>>,
    /// What the person named that it exposes, and the devices it lends.
    pub(crate) asked_terms: BTreeMap<RemoteId, (Exposure, Lends)>,
    /// The remotes the person disconnected in this run: held by nothing
    /// until they connect.
    pub(crate) released: BTreeSet<RemoteId>,
    /// The remotes whose channel comes back after a wait.
    pub(crate) returning: BTreeMap<RemoteId, Returning>,
    /// The remotes a route reported stopped in this run and not since.
    pub(crate) gone: BTreeSet<RemoteId>,
    /// Why each route's listing could not last be read, and the entry that
    /// said so.
    pub(crate) unlisted: BTreeMap<Name, (Words, Seq)>,
    /// Whether Windows last hinted that a network is reached.
    pub(crate) network: Network,
    /// Whether Windows said the workstation is going to sleep and has not
    /// said it woke.
    pub(crate) asleep: bool,
    /// Whether the person is removing Hedwig, so that nothing is written on
    /// a remote and everything written is taken back, until they keep it.
    pub(crate) withdrawn: Option<Withdrew>,
}

/// Since when the person has been removing Hedwig: from the entry `entry`,
/// recorded at `at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withdrew {
    pub entry: Seq,
    pub at: Timestamp,
}

/// What changed in one place of the organisation's policy since the person
/// last put the matter away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Restated {
    /// The first entry that changed it.
    pub since: Seq,
    pub arrived: u32,
    pub withdrawn: u32,
}

impl State {
    /// The state after every entry, in order.
    pub fn fold<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> State {
        State::after(State::default(), entries)
    }

    /// The state after every entry, in order, from `head`: what the entries
    /// before the first were folded into.
    pub fn after<'a>(head: State, entries: impl IntoIterator<Item = &'a Entry>) -> State {
        let mut state = head;
        for entry in entries {
            state.apply(entry);
        }
        state
    }

    /// What the core holds when it cannot read its trail. Whether the person
    /// had paused anything is then unknown, so everything is paused until
    /// they say otherwise.
    pub fn unknown() -> State {
        State {
            paused: BTreeSet::from([Remotes::Every]),
            ..State::default()
        }
    }

    /// The surfaces that watch `remote`.
    pub fn watching<'a>(
        &'a self,
        remote: &'a RemoteId,
        sets: &'a Sets<'a>,
    ) -> impl Iterator<Item = (ClientId, &'a Surface)> {
        self.surfaces
            .iter()
            .filter(move |(_, surface)| {
                surface.kind.attends() && surface.attends.covers(remote, sets)
            })
            .map(|(client, surface)| (*client, surface))
    }

    /// Why nothing that watches `remote` can put a request from it to the
    /// person now, where `card` says whether its card is shown over an
    /// application that fills the screen; `None` where something can. Where
    /// several surfaces cannot, the one the person was last seen at says
    /// where they were.
    pub fn unreached(
        &self,
        remote: &RemoteId,
        sets: &Sets<'_>,
        card: FullScreen,
    ) -> Option<Whereabouts> {
        let mut last: Option<(Seq, Whereabouts)> = None;
        for (_, surface) in self.watching(remote, sets) {
            let whereabouts = match surface.presence {
                Presence::Present => return None,
                Presence::CardOnly if card == FullScreen::Shown => return None,
                Presence::CardOnly => Whereabouts::FullScreen,
                Presence::Engaged => Whereabouts::Engaged,
                Presence::Away => continue,
            };
            if last.is_none_or(|(seen, _)| surface.seen > seen) {
                last = Some((surface.seen, whereabouts));
            }
        }
        Some(last.map_or(Whereabouts::Away, |(_, whereabouts)| whereabouts))
    }

    /// Whether any surface would show the person something from `remote`
    /// now. A person behind an application that fills the screen is there.
    pub fn reachable(&self, remote: &RemoteId, sets: &Sets<'_>) -> bool {
        self.unreached(remote, sets, FullScreen::Shown).is_none()
    }

    /// Whether a request from `remote` can be put to the person now: a
    /// surface that watches it is present, or would show the card over what
    /// fills its screen.
    pub fn askable(&self, remote: &RemoteId, sets: &Sets<'_>, card: FullScreen) -> bool {
        self.unreached(remote, sets, card).is_none()
    }

    pub fn paused(&self, remote: &RemoteId, sets: &Sets<'_>) -> bool {
        self.paused.iter().any(|scope| scope.covers(remote, sets))
    }

    /// Whether a pause selects the set `id`.
    pub fn pauses(&self, id: &Name) -> bool {
        self.paused.iter().any(|scope| scope.set() == Some(id))
    }

    /// What a request with the key `grip` can meet at a card: the least that
    /// any card read as holding it asks before its use, since any of them may
    /// be the one in when the agent signs, and no read that cannot open a
    /// card says which. `None` for a key on no card the core has read, or
    /// where a card holding it did not say.
    pub fn touch(&self, grip: &Grip) -> Option<Touch> {
        let mut holding = self
            .cards
            .values()
            .filter_map(|(card, _)| card.keys.iter().find(|held| held.grip == *grip));
        let first = holding.next()?.touch?;
        holding.try_fold(first, |least, held| {
            held.touch.map(|touch| match touch.strictness(&least) {
                Ordering::Less => touch,
                Ordering::Equal | Ordering::Greater => least,
            })
        })
    }

    /// The card `serial` as last read.
    pub fn card(&self, serial: &Serial) -> Option<&Card> {
        self.cards.get(serial).map(|(card, _)| card)
    }

    /// Every key the cards the core has read hold.
    pub fn keys(&self) -> impl Iterator<Item = &Grip> {
        self.cards
            .values()
            .flat_map(|(card, _)| card.keys.iter().map(|held| &held.grip))
    }

    /// The keys `capability`'s source last offered.
    pub fn offered(&self, capability: &Name) -> Option<&Keyring> {
        self.offered.get(capability)
    }

    /// What `capability` carries on to `remote` in this run, each with the
    /// core's endpoint for it.
    pub fn carried(
        &self,
        remote: &RemoteId,
        capability: &Name,
    ) -> Option<&BTreeMap<Carriage, Port>> {
        self.carried.get(&(remote.clone(), capability.clone()))
    }

    /// The served request that holds the serial port `capability` names for
    /// `remote`, the port, and when it was taken.
    pub fn hold(&self, remote: &RemoteId, capability: &Name) -> Option<Hold> {
        self.taken
            .iter()
            .find(|(_, (connection, held, _, _))| {
                held == capability
                    && self
                        .links
                        .get(connection)
                        .is_some_and(|link| &link.remote == remote)
            })
            .map(|(request, (_, _, port, since))| Hold {
                request: *request,
                port: port.clone(),
                since: *since,
            })
    }

    /// The USB device `port` was last opened over.
    pub fn seen(&self, port: &PortName) -> Option<Usb> {
        self.seen.get(&port.as_str().to_ascii_uppercase()).copied()
    }

    /// The remote whose served request holds `port`, whatever capability
    /// names it.
    pub fn holder(&self, port: &PortName) -> Option<RemoteId> {
        self.taken
            .values()
            .find(|(_, _, held, _)| held.same(port))
            .and_then(|(connection, ..)| self.links.get(connection))
            .map(|link| link.remote.clone())
    }

    /// What the workstation's side of `capability` last did, if it was tried
    /// in this run.
    pub fn source(&self, capability: &Name) -> Option<Health> {
        self.sources.get(capability).copied()
    }

    /// What last held `capability`'s source, `Some(None)` where nothing
    /// answered; `None` where it was never read.
    pub fn held_by(&self, capability: &Name) -> Option<Option<&SourceHolder>> {
        self.holders.get(capability).map(Option::as_ref)
    }

    pub fn surface(&self, client: ClientId) -> Option<&Surface> {
        self.surfaces.get(&client)
    }

    pub fn link(&self, connection: ConnectionId) -> Option<&Link> {
        self.links.get(&connection)
    }

    /// What Hedwig has written on `remote` and not taken back, by capability,
    /// with where each went and the outermost folder made for it.
    pub fn written(
        &self,
        remote: &RemoteId,
    ) -> impl Iterator<Item = (&Name, &Write, &RemotePath, Option<&RemotePath>)> {
        self.written
            .get(remote)
            .into_iter()
            .flatten()
            .map(|((capability, write, place), made)| (capability, write, place, made.as_ref()))
    }

    /// The stores whose unreadable files are still before the person.
    pub fn unread_stores(&self) -> Vec<Store> {
        self.unreadable.keys().copied().collect()
    }

    /// What the person chose the core writes about what went wrong for this
    /// run, where they chose.
    pub fn diagnose(&self) -> Option<Diagnostics> {
        self.diagnose
    }

    /// What Windows starts at sign-in for `starts`, as last found in this
    /// run.
    pub fn startup(&self, starts: Starts) -> Option<&AtSignIn> {
        self.startup.get(&starts)
    }

    /// Since when the person has been removing Hedwig, where they are.
    pub fn withdrawn(&self) -> Option<Withdrew> {
        self.withdrawn
    }

    /// The remotes Hedwig has written on and not taken everything back from.
    pub fn written_on(&self) -> impl Iterator<Item = &RemoteId> {
        self.written
            .iter()
            .filter(|(_, writes)| !writes.is_empty())
            .map(|(remote, _)| remote)
    }

    /// The platform `remote` last reported, in this run or an earlier one.
    pub fn observed(&self, remote: &RemoteId) -> Option<&Name> {
        self.observed.get(remote)
    }

    /// Every live connection.
    pub fn connections(&self) -> impl Iterator<Item = (ConnectionId, &Link)> {
        self.links.iter().map(|(id, link)| (*id, link))
    }

    /// The live connection to `remote`, if there is one.
    pub fn connection(&self, remote: &RemoteId) -> Option<(ConnectionId, &Link)> {
        self.links
            .iter()
            .find(|(_, link)| link.remote == *remote)
            .map(|(id, link)| (*id, link))
    }

    pub fn ask(&self, request: RequestId) -> Option<&Ask> {
        self.asks.get(&request)
    }

    pub fn prompt(&self, prompt: PromptId) -> Option<&Prompt> {
        self.prompts.get(&prompt)
    }

    /// Every prompt a channel's client waits on.
    pub fn prompts(&self) -> impl Iterator<Item = (PromptId, &Prompt)> {
        self.prompts.iter().map(|(id, prompt)| (*id, prompt))
    }

    /// Whether an allowance the person gave still covers this.
    pub fn allowed(
        &self,
        connection: ConnectionId,
        capability: &Name,
        operation: Operation,
        key: Option<&KeyId>,
        now: Tick,
    ) -> bool {
        self.allowances
            .get(&(connection, capability.clone(), operation, key.cloned()))
            .is_some_and(|until| now < *until)
    }

    /// Applies one entry.
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per event; splitting it would scatter the fold"
    )]
    pub fn apply(&mut self, entry: &Entry) {
        let Entry {
            seq,
            at,
            tick,
            event,
            ..
        } = entry;
        if let Some(surface) = event.by().and_then(|by| self.surfaces.get_mut(&by)) {
            if !matches!(
                event,
                Event::Presence {
                    presence: Presence::Away,
                    ..
                }
            ) {
                surface.seen = *seq;
            }
            if event.lets_more_through() {
                if self.widened.len() == WIDENINGS {
                    self.widened.pop_first();
                }
                let widened = Widened {
                    entry: entry.clone(),
                    kind: surface.kind,
                    origin: surface.origin,
                };
                self.widened.insert(*seq, widened);
            }
        }
        match event {
            Event::Started {
                version,
                origin,
                after,
            } => {
                *self = State {
                    policy: std::mem::take(&mut self.policy),
                    restated: std::mem::take(&mut self.restated),
                    widened: std::mem::take(&mut self.widened),
                    unseen: std::mem::take(&mut self.unseen),
                    started: Some((*seq, *at, version.clone(), *origin)),
                    paused: std::mem::take(&mut self.paused),
                    refused: std::mem::take(&mut self.refused),
                    cards: std::mem::take(&mut self.cards),
                    offered: std::mem::take(&mut self.offered),
                    put_away: std::mem::take(&mut self.put_away),
                    restarted: self.restarted.take(),
                    unreadable: std::mem::take(&mut self.unreadable),
                    observed: std::mem::take(&mut self.observed),
                    written: std::mem::take(&mut self.written),
                    seen: std::mem::take(&mut self.seen),
                    notices: std::mem::take(&mut self.notices),
                    withdrawn: self.withdrawn,
                    ..State::default()
                };
                // What a notice counts against is the trail's clock, which
                // restarts here.
                for notices in self.notices.values_mut() {
                    notices.recent.clear();
                }
                // A burst is put away as of a tick, and ticks restart here.
                self.put_away
                    .retain(|item, _| !matches!(item, Item::Burst(_)));
                if let Some(cause) = after {
                    let times = self.restarted.map_or(0, |(_, times)| times);
                    self.restarted = Some((*cause, times.saturating_add(1)));
                }
            }
            Event::Unreadable { store, account } => {
                if *store == Store::Trail {
                    *self = State::unknown();
                }
                self.unreadable.insert(*store, account.clone());
            }
            Event::Attached {
                kind,
                origin,
                attends,
            } => {
                self.surfaces.insert(
                    ClientId(*seq),
                    Surface {
                        kind: *kind,
                        origin: *origin,
                        presence: Presence::Present,
                        icon: None,
                        attends: attends.clone(),
                        seen: *seq,
                    },
                );
            }
            Event::Presence { client, presence } => {
                if let Some(surface) = self.surfaces.get_mut(client) {
                    surface.presence = *presence;
                }
            }
            Event::Icon { client, icon } => {
                if let Some(surface) = self.surfaces.get_mut(client) {
                    surface.icon = Some(*icon);
                }
            }
            Event::Detached { client } => {
                self.surfaces.remove(client);
            }
            Event::Changed { .. } | Event::Imported { .. } => self.allowances.clear(),
            Event::Paused { scope, .. } => {
                // The fold does not hold who a named set's members are, so a
                // pause over one ends every allowance.
                let covered: Vec<ConnectionId> = self
                    .links
                    .iter()
                    .filter(|(_, link)| {
                        scope.set().is_some() || scope.covers(&link.remote, &Sets::NONE)
                    })
                    .map(|(id, _)| *id)
                    .collect();
                self.allowances
                    .retain(|(connection, ..), _| !covered.contains(connection));
                self.paused.insert(scope.clone());
            }
            Event::Resumed { scope, .. } => {
                self.paused.remove(scope);
            }
            Event::Appeared { remote } => {
                self.running.insert(remote.clone());
                self.gone.remove(remote);
            }
            Event::Gone { remote } => {
                self.running.remove(remote);
                self.gone.insert(remote.clone());
                self.returning.remove(remote);
            }
            Event::Opening {
                remote,
                with,
                acknowledged,
                lends,
                opener,
            } => {
                self.ended.remove(remote);
                if let Opener::Person(_) = opener {
                    self.asked
                        .insert(remote.clone(), with.iter().cloned().collect());
                    self.asked_terms
                        .insert(remote.clone(), (*acknowledged, lends.clone()));
                    self.released.remove(remote);
                    self.returning.remove(remote);
                }
                self.links.insert(
                    ConnectionId(*seq),
                    Link {
                        remote: remote.clone(),
                        with: with.iter().cloned().collect(),
                        acknowledged: *acknowledged,
                        lends: lends.clone(),
                        opener: *opener,
                        phase: Phase::Opening,
                        up: None,
                        platform: None,
                        readiness: BTreeMap::new(),
                        rules: BTreeMap::new(),
                    },
                );
            }
            Event::Observed {
                connection,
                platform,
            } => {
                if let Some(link) = self.links.get_mut(connection) {
                    link.platform = Some(platform.clone());
                    self.observed.insert(link.remote.clone(), platform.clone());
                }
            }
            Event::Checked {
                connection,
                capability,
                readiness,
            } => {
                if let Some(link) = self.links.get_mut(connection) {
                    let key = (link.remote.clone(), capability.clone());
                    match readiness {
                        Readiness::Ready => {
                            self.unready.remove(&key);
                        }
                        Readiness::Unready(findings) => {
                            self.unready.insert(key, (findings.clone(), *seq));
                        }
                    }
                    link.readiness.insert(capability.clone(), readiness.clone());
                }
            }
            Event::Prompted {
                connection,
                kind,
                words,
            } => {
                self.prompts.insert(
                    PromptId(*seq),
                    Prompt {
                        connection: *connection,
                        kind: *kind,
                        words: words.clone(),
                    },
                );
            }
            Event::Answered { prompt, .. } => {
                self.prompts.remove(prompt);
            }
            Event::Up {
                connection,
                serving,
            } => {
                if let Some(link) = self.links.get_mut(connection) {
                    link.phase = Phase::Up(serving.clone());
                    link.up = Some(*tick);
                }
            }
            Event::Down { connection, end } => {
                if let Some(link) = self.links.remove(connection) {
                    self.returned(&link, end, *tick);
                    self.ended.insert(link.remote, (end.clone(), *seq));
                }
                self.prompts
                    .retain(|_, prompt| prompt.connection != *connection);
                self.asks.retain(|_, ask| ask.connection != *connection);
                self.allowances.retain(|(of, ..), _| of != connection);
            }
            Event::TurnedAway { remote, refusal } => {
                self.refuse(remote.clone(), refusal, *seq);
            }
            Event::Asked {
                connection,
                capability,
                operation,
                key,
            } => {
                if let Some(link) = self.links.get(connection) {
                    let recent = self.recent.entry(link.remote.clone()).or_default();
                    if recent.len() == RECENT {
                        recent.pop_front();
                    }
                    recent.push_back(*tick);
                    self.last.insert(
                        (link.remote.clone(), capability.clone()),
                        Last {
                            request: RequestId(*seq),
                            at: *at,
                            operation: *operation,
                            outcome: None,
                        },
                    );
                }
                self.asks.insert(
                    RequestId(*seq),
                    Ask {
                        connection: *connection,
                        capability: capability.clone(),
                        operation: *operation,
                        key: key.clone(),
                        payload: None,
                        held: false,
                    },
                );
            }
            Event::Held { request } => {
                if let Some(ask) = self.asks.get_mut(request) {
                    ask.held = true;
                }
            }
            Event::Settled { request, outcome } => {
                if let Some(last) = self.last.values_mut().find(|last| last.request == *request) {
                    last.outcome = Some(outcome.clone());
                }
                let remote = self
                    .asks
                    .remove(request)
                    .and_then(|ask| self.links.get(&ask.connection))
                    .map(|link| link.remote.clone());
                match (outcome, remote) {
                    (Outcome::Refused(refusal), remote) => self.refuse(remote, refusal, *seq),
                    (Outcome::Unseen(_), Some(remote)) => {
                        let served = self.unseen.entry(remote).or_insert(0);
                        *served = served.saturating_add(1);
                    }
                    _ => {}
                }
            }
            Event::Allowed {
                connection,
                capability,
                operation,
                key,
                until,
                ..
            } => {
                let covers = (*connection, capability.clone(), *operation, key.clone());
                self.allowances.insert(covers, *until);
            }
            Event::Ruled {
                connection,
                scope,
                mode,
                ..
            } => {
                if let Some(link) = self.links.get_mut(connection) {
                    match mode {
                        Some(mode) => link.rules.insert(scope.clone(), *mode),
                        None => link.rules.remove(scope),
                    };
                }
                self.allowances.retain(|(of, ..), _| of != connection);
            }
            Event::Source { capability, health } => {
                self.sources.insert(capability.clone(), *health);
            }
            Event::Card(card) => {
                let kept = match self.cards.get(&card.serial) {
                    Some((known, since)) => {
                        let next = known.read_again(card);
                        let since = if known.asks_as(&next) { *since } else { *seq };
                        (next, since)
                    }
                    None => (card.clone(), *seq),
                };
                self.cards.insert(card.serial.clone(), kept);
            }
            Event::Offered {
                capability,
                keyring,
            } => {
                self.offered.insert(capability.clone(), keyring.clone());
            }
            Event::Carried {
                connection,
                capability,
                carriage,
                endpoint,
            } => {
                if let Some(link) = self.links.get(connection) {
                    self.carried
                        .entry((link.remote.clone(), capability.clone()))
                        .or_default()
                        .insert(carriage.clone(), *endpoint);
                }
            }
            Event::Dropped {
                connection,
                capability,
                carriage,
                ..
            } => {
                if let Some(link) = self.links.get(connection)
                    && let Some(carried) = self
                        .carried
                        .get_mut(&(link.remote.clone(), capability.clone()))
                {
                    carried.remove(carriage);
                }
            }
            Event::Taken {
                request,
                connection,
                capability,
                port,
                usb,
            } => {
                let held = (*connection, capability.clone(), port.clone(), *at);
                self.taken.insert(*request, held);
                let key = port.as_str().to_ascii_uppercase();
                match usb {
                    Some(usb) => self.seen.insert(key, *usb),
                    None => self.seen.remove(&key),
                };
            }
            Event::Released { request } => {
                self.taken.remove(request);
            }
            Event::PutAway { item, .. } => {
                self.refused.remove(item);
                match item {
                    Item::Restarted => self.restarted = None,
                    Item::Unreadable(store) => {
                        self.unreadable.remove(store);
                    }
                    Item::Widened(entry) => {
                        self.widened.remove(entry);
                    }
                    Item::Unseen(remote) => {
                        self.unseen.remove(remote);
                    }
                    Item::Policy(place) => {
                        self.restated.remove(place);
                    }
                    Item::Noticed { remote, through } => {
                        if let Some(notices) = self.notices.get_mut(remote) {
                            notices.kept.retain(|noted| noted.seq > *through);
                        }
                    }
                    _ => {}
                }
                self.put_away.insert(item.clone(), (*seq, *tick));
            }
            Event::Stated {
                audience,
                statement,
            } => {
                self.restate(*seq, *audience, statement.part(), (1, 0));
                self.policy.stated(*audience, statement.clone());
                self.allowances.clear();
            }
            Event::Unstated {
                audience,
                statement,
            } => {
                self.restate(*seq, *audience, statement.part(), (0, 1));
                self.policy.unstated(*audience, statement);
                self.allowances.clear();
            }
            Event::Misread { place, unread } => {
                self.restate(*seq, place.audience, place.part, (0, 0));
                self.policy.note_unread(*place, unread.clone());
                self.allowances.clear();
            }
            Event::Disconnected { remote, .. } => {
                self.asked.remove(remote);
                self.asked_terms.remove(remote);
                self.returning.remove(remote);
                self.released.insert(remote.clone());
            }
            Event::Unlisted { route, account } => match account {
                Some(account) => {
                    self.unlisted.insert(route.clone(), (account.clone(), *seq));
                }
                None => {
                    self.unlisted.remove(route);
                }
            },
            Event::Offline => self.network = Network::Offline,
            Event::Online => {
                self.network = Network::Online;
                for returning in self.returning.values_mut() {
                    returning.hurried = true;
                }
            }
            Event::Sleeping => self.asleep = true,
            Event::Woke => self.asleep = false,
            // Read from the trail by whoever asks what ran; nothing folds.
            Event::Wrote {
                connection,
                capability,
                write,
                place,
                made,
            } => {
                if let Some(link) = self.links.get(connection) {
                    self.written.entry(link.remote.clone()).or_default().insert(
                        (capability.clone(), write.clone(), place.clone()),
                        made.clone(),
                    );
                }
            }
            Event::Unwrote {
                connection,
                capability,
                write,
                place,
            } => {
                if let Some(link) = self.links.get(connection)
                    && let Some(written) = self.written.get_mut(&link.remote)
                {
                    written.remove(&(capability.clone(), write.clone(), place.clone()));
                }
            }
            Event::Withdrawn { .. } => {
                self.withdrawn.get_or_insert(Withdrew {
                    entry: *seq,
                    at: *at,
                });
            }
            Event::Restored { .. } => {
                self.withdrawn = None;
            }
            // What it dropped is folded into the trail's head.
            Event::Kept { .. }
            | Event::Ran { .. }
            | Event::Prepared { .. }
            | Event::Stopping { .. }
            | Event::Exercised { .. }
            | Event::Browsed { .. }
            | Event::Refuted { .. }
            | Event::Unreleased { .. }
            | Event::Uncarried { .. }
            // The TPM's store is the record of which keys there are.
            | Event::KeyMade { .. }
            | Event::KeyDeleted { .. } => {}
            Event::Payload { request, payload } => {
                if let Some(ask) = self.asks.get_mut(request) {
                    ask.payload = Some(payload.clone());
                }
            }
            Event::Noticed {
                connection,
                remark,
                unheard,
                ..
            } => {
                if let Some(link) = self.links.get(connection) {
                    let notices = self.notices.entry(link.remote.clone()).or_default();
                    if notices.kept.len() == NOTICES_KEPT {
                        notices.kept.pop_front();
                    }
                    notices.kept.push_back(Noted {
                        seq: *seq,
                        at: *at,
                        remark: remark.clone(),
                        unheard: *unheard,
                    });
                    if notices.recent.len() == NOTICES_AT_ONCE {
                        notices.recent.pop_front();
                    }
                    notices.recent.push_back(*tick);
                }
            }
            Event::HeldBy { capability, holder } => {
                self.holders.insert(capability.clone(), holder.clone());
            }
            Event::Startup { starts, found } => {
                self.startup.insert(*starts, found.clone());
            }
            Event::Diagnosed { level, .. } => {
                self.diagnose = *level;
            }
        }
    }

    /// How a lost channel's remote comes back, by what ended it.
    fn returned(&mut self, link: &Link, end: &ChannelEnd, tick: Tick) {
        let before = self.returning.remove(&link.remote);
        let returning = match end.back() {
            Back::Paced => {
                let settled = link
                    .up
                    .is_some_and(|up| tick.0.saturating_sub(up.0) >= u64::from(SETTLED) * 1000);
                Returning {
                    failed: if settled {
                        0
                    } else {
                        before.map_or(0, |before| before.failed).saturating_add(1)
                    },
                    since: tick,
                    hurried: false,
                }
            }
            Back::AtOnce => Returning {
                failed: before.map_or(0, |before| before.failed),
                since: tick,
                hurried: true,
            },
            Back::WhenWanted | Back::ByThePerson => return,
        };
        self.returning.insert(link.remote.clone(), returning);
    }

    /// What the person added to a connection they asked for in this run,
    /// where they asked for one and have not disconnected it.
    pub fn asked(&self, remote: &RemoteId) -> Option<&BTreeSet<Name>> {
        self.asked.get(remote)
    }

    /// What the person named that what they added to that connection
    /// exposes, and the devices it lends.
    pub fn asked_terms(&self, remote: &RemoteId) -> (Exposure, Lends) {
        self.asked_terms
            .get(remote)
            .cloned()
            .unwrap_or_else(|| (Exposure::NONE, Lends::none()))
    }

    /// Every remote the person asked for in this run.
    pub fn asked_for(&self) -> impl Iterator<Item = &RemoteId> {
        self.asked.keys()
    }

    /// Whether the person disconnected `remote` in this run.
    pub fn released(&self, remote: &RemoteId) -> bool {
        self.released.contains(remote)
    }

    /// When and how `remote`'s channel comes back, where it is waiting to.
    pub fn returning(&self, remote: &RemoteId) -> Option<Returning> {
        self.returning.get(remote).copied()
    }

    /// Every remote waiting to come back.
    pub fn returns(&self) -> impl Iterator<Item = (&RemoteId, Returning)> {
        self.returning
            .iter()
            .map(|(remote, returning)| (remote, *returning))
    }

    /// Whether a route reported `remote` stopped in this run and not since.
    pub fn gone(&self, remote: &RemoteId) -> bool {
        self.gone.contains(remote)
    }

    /// Whether a route reports `remote` running.
    pub fn running(&self, remote: &RemoteId) -> bool {
        self.running.contains(remote)
    }

    /// How `remote`'s last channel in this run ended, and the entry that
    /// said so.
    pub fn ended(&self, remote: &RemoteId) -> Option<&(ChannelEnd, Seq)> {
        self.ended.get(remote)
    }

    /// Why a route's listing could not last be read, where it could not.
    pub fn unlisted(&self, route: &Name) -> Option<&Words> {
        self.unlisted.get(route).map(|(account, _)| account)
    }

    /// Whether the workstation is between saying it sleeps and saying it
    /// woke: nothing is opened, listed or served meanwhile.
    pub fn asleep(&self) -> bool {
        self.asleep
    }

    /// Whether Windows last hinted that a network is reached.
    pub fn network(&self) -> Network {
        self.network
    }

    /// What the organisation states, as the trail last recorded it.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Counts a change in one place of the organisation's policy towards what
    /// the person is shown of it.
    fn restate(
        &mut self,
        seq: Seq,
        audience: Audience,
        part: Part,
        (arrived, withdrawn): (u32, u32),
    ) {
        let restated = self
            .restated
            .entry(Place { audience, part })
            .or_insert(Restated {
                since: seq,
                arrived: 0,
                withdrawn: 0,
            });
        restated.arrived = restated.arrived.saturating_add(arrived);
        restated.withdrawn = restated.withdrawn.saturating_add(withdrawn);
    }

    fn refuse(&mut self, remote: Option<RemoteId>, refusal: &Refusal, seq: Seq) {
        if !refusal.raises_attention() {
            return;
        }
        let item = Item::Refused {
            remote,
            refusal: refusal.clone(),
        };
        if !self.refused.contains_key(&item) && self.refused.len() == REFUSALS {
            let oldest = self
                .refused
                .iter()
                .min_by_key(|(_, (_, last))| *last)
                .map(|(item, _)| item.clone());
            if let Some(oldest) = oldest {
                self.refused.remove(&oldest);
            }
        }
        let tally = self.refused.entry(item).or_insert((0, seq));
        tally.0 = tally.0.saturating_add(1);
        tally.1 = seq;
    }
}
