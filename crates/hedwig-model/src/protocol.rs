//! The control channel's messages.
//!
//! The command line, the interface and a person's own scripts are all clients
//! of these messages and of nothing else, so they meet one policy. Every
//! request is answered by exactly one reply carrying its `id`; a notice is
//! never an answer, and nothing a notice says is unavailable by asking.

use std::num::{NonZeroU8, NonZeroU32};

use crate::beyond::Beyond;
use crate::capability::{Exposure, KeyKind, Lends, Operation};
use crate::config::{Change, Definitions, Document, Effect, Grant, Reach, Terms};
use crate::gate::Capped;
use crate::holder::SourceHolder;
use crate::install::AtSignIn;
use crate::organisation::{Holding, Misread, Place};
use crate::policy::{Basis, ConnectionScope, Mode, Selector};
use crate::refusal::Refusal;
use crate::remote::{RemoteId, Remotes};
use crate::scope::Audience;
use crate::setting::{
    Autostart, Bounded, Cadence, Condition, Diagnostics, FullScreen, Keep, Keepalive, Lengths,
    Returns, Routes, Settled, Span, Threshold, Volume, Workstation as Here,
};
use crate::text::{
    DeviceSerial, KeyId, Name, Port, PortName, Remark, RemotePath, Secret, SshKey, Words,
};
use crate::trail::{
    Binding, Breakdown, Card, Carriage, ChannelEnd, ClientId, ClientKind, ConnectionId, Entry,
    Finding, Health, Icon, Item, Keyring, Network, Origin, Outcome, Payload, Presence, PromptId,
    PromptKind, RequestId, Seq, Store, Tick, Timestamp, Withdrew, Write,
};

/// The version both ends must speak. A client of another version is refused
/// at the greeting with both numbers. Invariant: a protocol fact a script
/// reads.
pub const PROTOCOL: u32 = 3;

/// What the person decides about a held request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Once,
    /// This request, and the same operation on the same capability through
    /// the same connection for this many seconds.
    For(NonZeroU32),
    Refuse,
}

impl Decision {
    /// When an allowance given at `now` ends; `None` for a decision that
    /// leaves none.
    pub fn until(self, now: Tick) -> Option<Tick> {
        match self {
            Decision::For(seconds) => Some(Tick(
                now.0
                    .saturating_add(u64::from(seconds.get()).saturating_mul(1000)),
            )),
            Decision::Once | Decision::Refuse => None,
        }
    }
}

/// What the person answers a channel's prompt with. The core hands it to the
/// channel's client in its reply to the prompt, and keeps none of it.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Text(Secret),
    Accept,
    Decline,
}

/// What a channel's client said of the answer it wants, in
/// `SSH_ASKPASS_PROMPT`. Read only where the words cannot say it: the in-box
/// client sets the variable in its own environment and never clears it, so
/// after one confirmation every later prompt carries it too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hint {
    /// `confirm`: a yes or a no.
    Confirm,
    /// `none`: a notice with nothing to answer, taken away when done.
    Notice,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// The first message on every connection. `attends` is the remotes an
    /// attending client watches; a command attends none, whatever it names.
    Hello {
        protocol: u32,
        kind: ClientKind,
        attends: Remotes,
    },

    Status,
    Exposure,
    Attention,
    Catalogue,
    /// What this workstation holds, for a first grant made in its terms.
    Workstation,
    Export,
    /// The newest entries older than `before`, for one remote or all.
    Activity {
        remote: Selector<RemoteId>,
        before: Option<Seq>,
        limit: NonZeroU8,
    },
    /// Send every entry after `after` as it is recorded.
    Follow {
        after: Option<Seq>,
    },

    Change(Change),
    /// A whole document, held apart so the frames that carry none stay
    /// small.
    Import(Box<Document>),
    /// Open a channel now. `with` adds capabilities for this connection alone,
    /// `acknowledged` names what they expose and `lends` the devices they
    /// lend.
    Connect {
        remote: RemoteId,
        with: Vec<Name>,
        acknowledged: Exposure,
        lends: Lends,
    },
    Disconnect {
        remote: RemoteId,
    },
    Pause(Remotes),
    Resume(Remotes),
    Decide {
        request: RequestId,
        decision: Decision,
    },
    Answer {
        prompt: PromptId,
        answer: Answer,
    },
    /// A channel's client asks the person something: the words it gave the
    /// program `SSH_ASKPASS` names. Answered when the person answers, or
    /// refused at once where nobody can be asked.
    Prompt {
        words: Words,
        hint: Option<Hint>,
    },
    /// Set a rule on one live connection, or clear it with `None`.
    Rule {
        connection: ConnectionId,
        scope: ConnectionScope,
        mode: Option<Mode>,
    },
    PutAway(Item),
    /// Run readiness for one grant now and report its row.
    Check {
        remote: RemoteId,
        capability: Name,
    },
    /// Have the remote's own tool use the capability once, end to end. For a
    /// signing key this makes a real signature, so it only ever runs when
    /// asked. Answered at once: what the tool did is recorded when it has
    /// run, and told to the client that asked ([`Notice::Exercised`]), which
    /// can meanwhile answer the request the tool raises.
    Exercise {
        remote: RemoteId,
        capability: Name,
    },
    /// An attending client reports whether it can show the person anything.
    Presence(Presence),
    /// The interface reports whether its icon is on the taskbar, so that a
    /// surface it cannot reach, and the command line, can say so.
    Icon(Icon),
    /// Every setting as it stands, for the remotes the core knows and these.
    Settings {
        remotes: Vec<RemoteId>,
    },
    /// What a trial would change, without making it.
    Try(Box<Trial>),
    /// The devices a capability's source holds now, which a grant of it
    /// names what it lends from.
    Devices(Name),
    /// The keys an SSH agent capability's source holds now, which a grant of
    /// it names what it lends from. The agent is asked for its list once, for
    /// this.
    Keys(Name),
    /// Make a key in the workstation's TPM, which only it can ever use.
    MakeKey {
        name: Name,
        kind: KeyKind,
    },
    /// Delete a key Hedwig made in the workstation's TPM, named by its public
    /// half so that exactly the key the person was shown goes; every grant
    /// and acceptance lending it lends it no more. Nothing brings it back.
    DeleteKey(SshKey),
    /// The serial ports the workstation has now, which a capability lending
    /// one is defined from.
    Ports,
    /// The person removes Hedwig: every consent to write on a remote ends,
    /// and a survey is started to each remote Hedwig wrote on, which takes
    /// back what it wrote. Answered at once with [`Reply::Withdrawal`].
    Withdraw,
    /// Where taking back stands, remote by remote, starting nothing.
    Withdrawal,
    /// The person keeps Hedwig after a removal that did not finish: what they
    /// consented to is written on their remotes again, and channels are held
    /// as their grants say. Setup sends it when it installs over a Hedwig
    /// whose removal stopped part-way.
    Restore,
    /// Everything a supporter needs, in one document.
    Bundle,
    /// What the core writes about what went wrong, for this run alone, or
    /// with `None` as this workstation's setting says.
    Diagnose(Option<Diagnostics>),
    Stop,
}

/// What Hedwig has still written on one remote, as a removal sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    pub remote: RemoteId,
    /// What is still there, and where.
    pub left: Vec<Written>,
    /// Whether a connection to it is open now, taking it back.
    pub surveying: bool,
    /// How the last connection to it in this run ended, where one did.
    pub ended: Option<ChannelEnd>,
}

/// A serial port the workstation has now, as Windows describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialPort {
    pub port: PortName,
    /// The device's name as Windows shows it, where it gives one.
    pub name: Option<Words>,
    /// The USB device behind the port, where it is one.
    pub usb: Option<Usb>,
}

impl SerialPort {
    /// What a remote's tool cannot do through this port.
    pub fn beyond(&self) -> Option<Beyond> {
        Beyond::of_port(self.usb)
    }
}

/// A USB device's vendor and product, as its own descriptor gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Usb {
    pub vendor: u16,
    pub product: u16,
}

/// One key an SSH agent holds, as it lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentKey {
    pub key: SshKey,
    /// The comment the agent gives it, where that is words.
    pub comment: Option<Words>,
}

/// One device a capability's source holds, as it names and describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lendable {
    /// `None` for a device the server lists with no serial, which no grant
    /// can name; every device lends it.
    pub serial: Option<DeviceSerial>,
    /// The model the device reports, where it reports one.
    pub model: Option<Words>,
    pub state: DeviceState,
    pub attached: Attachment,
}

/// How a device stands with the server (`adb_host.proto`, `ConnectionState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceState {
    Connecting,
    Authorizing,
    Unauthorized,
    NoPermission,
    Detached,
    Offline,
    Bootloader,
    Device,
    Host,
    Recovery,
    Sideload,
    Rescue,
    /// A state this version does not know, by its number.
    Other(u64),
}

impl DeviceState {
    /// The state the server's listing numbers `number`.
    pub fn numbered(number: u64) -> DeviceState {
        match number {
            1 => DeviceState::Connecting,
            2 => DeviceState::Authorizing,
            3 => DeviceState::Unauthorized,
            4 => DeviceState::NoPermission,
            5 => DeviceState::Detached,
            6 => DeviceState::Offline,
            7 => DeviceState::Bootloader,
            8 => DeviceState::Device,
            9 => DeviceState::Host,
            10 => DeviceState::Recovery,
            11 => DeviceState::Sideload,
            12 => DeviceState::Rescue,
            other => DeviceState::Other(other),
        }
    }
}

/// How a device reaches the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attachment {
    Usb,
    /// A socket: an emulator, or a device connected by its address.
    Socket,
}

/// One line of an organisation's policy, as it would be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub place: Place,
    pub text: String,
}

/// Statements tried against what holds now: an organisation's policy in
/// place of the one read, a document in place of the configuration, and one
/// change made after them. `None` keeps what holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trial {
    pub policy: Option<Vec<Line>>,
    pub document: Option<Document>,
    pub change: Option<Change>,
    /// Remotes to answer for beyond those the core knows.
    pub remotes: Vec<RemoteId>,
}

/// One thing as it is and as it would be; `None` where it is not, or would
/// not be, there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Differs<T> {
    pub before: Option<T>,
    pub after: Option<T>,
}

/// What a trial would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tried {
    /// The configuration's gate would refuse the document or the change.
    Refused(Refusal),
    Would(Box<Would>),
}

/// What would differ were a trial made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Would {
    /// Whether it can let more through than what holds now.
    pub reach: Reach,
    pub rows: Vec<Differs<Row>>,
    pub remotes: Vec<Differs<RemoteSettings>>,
    /// `None` where nothing of the workstation's would differ.
    pub workstation: Option<Differs<WorkstationSettings>>,
}

/// How loudly one condition on one remote reaches the person, and which
/// statement said so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loudness {
    pub condition: Condition,
    pub volume: Settled<Volume, Remotes>,
}

/// Every setting resolved for one remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSettings {
    pub remote: RemoteId,
    pub threshold: Settled<Threshold, Remotes>,
    pub volumes: Vec<Loudness>,
    pub full_screen: Settled<FullScreen, Remotes>,
    /// Every cap on allowances for this remote's requests, the person's and
    /// the organisation's, the smallest first.
    pub caps: Vec<Capped>,
    pub keepalive: Settled<Keepalive, Remotes>,
    pub returns: Settled<Returns, Remotes>,
}

/// Every setting resolved for one route that lists its remotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSettings {
    pub route: Name,
    pub cadence: Settled<Cadence, Routes>,
}

/// Whom to ask about what the organisation's limits for `audience` hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub audience: Audience,
    pub words: Words,
}

/// Every setting of this workstation's, and what stands behind those that
/// come from the organisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkstationSettings {
    pub lengths: Settled<Lengths, Here>,
    pub autostart: Settled<Autostart, Here>,
    pub icon: Settled<Autostart, Here>,
    /// What Windows starts at sign-in for `autostart` and `icon`.
    pub windows: WindowsStarts,
    pub keep: Bounded<Keep>,
    pub diagnostics: Bounded<Diagnostics, Span>,
    pub contacts: Vec<Contact>,
    /// What of the organisation's policy could not be read.
    pub unread: Vec<Misread>,
}

/// What Windows starts at sign-in for each start-up choice, as the core found
/// it keeping their `Run` values in this run; `None` before it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsStarts {
    pub hedwig: Option<AtSignIn>,
    pub icon: Option<AtSignIn>,
}

/// Every setting as it stands and the statement each comes from; a row
/// carries what each remote reaches and how each request is decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub workstation: WorkstationSettings,
    pub remotes: Vec<RemoteSettings>,
    pub routes: Vec<RouteSettings>,
}

/// A write Hedwig has made on a remote with the grant's consent, the file or
/// keyring it went in, and the outermost folder it made there for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub write: Write,
    pub place: RemotePath,
    pub made: Option<RemotePath>,
}

/// An act a row can offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Act {
    Connect,
    Disconnect,
    Pause,
    Resume,
    Revoke,
    /// Deny a grant the organisation starts the person with: the person's
    /// own denial, which no later starting point undoes.
    Deny,
    /// Give a grant the organisation starts the person with the exposure it
    /// needs named.
    Accept,
    Check,
    Exercise,
}

/// Where a row's grant stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Granted, with no channel open.
    Idle,
    /// Readiness is reading the remote because the person asked, with no
    /// channel live; nothing is carried unless something wants it.
    Checking,
    Opening,
    /// The channel's client is waiting for the person.
    Needs(PromptKind),
    Unready(Vec<Finding>),
    Serving(Binding),
    /// Granted, and the remote cannot take it; the refusal says why.
    Unavailable(Refusal),
    Paused,
    /// The channel ended as `end` says and is opened again `wait` seconds
    /// after the reply that carries this, or at once where `wait` is `None`.
    Returning {
        end: ChannelEnd,
        wait: Option<NonZeroU32>,
    },
    Ended(ChannelEnd),
}

/// The last request a remote made of a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Last {
    pub request: RequestId,
    pub at: Timestamp,
    pub operation: Operation,
    /// How it ended; `None` while it is decided or held.
    pub outcome: Option<Outcome>,
}

/// How one operation would be decided on a row, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decides {
    pub operation: Operation,
    /// The key this holds for; `None` for a request that names no key, and
    /// for every key no entry of its own follows.
    pub key: Option<KeyId>,
    pub mode: Mode,
    pub basis: Basis,
}

/// What a row's capability is granted through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Through {
    Grant(Grant),
    /// A grant the organisation starts the person with.
    Start {
        audience: Audience,
        grant: Grant,
    },
    /// Added for the live connection alone.
    Connection(ConnectionId),
}

impl Through {
    /// The grant this is, where it is one.
    pub fn grant(&self) -> Option<&Grant> {
        match self {
            Through::Grant(grant) | Through::Start { grant, .. } => Some(grant),
            Through::Connection(_) => None,
        }
    }
}

/// One capability on one remote: what is reachable from where, how it
/// stands, and what can be done about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub capability: Name,
    pub exposure: Exposure,
    /// `None` for a grant that covers no remote the core has seen yet.
    pub remote: Option<RemoteId>,
    /// The live connection to the remote, which a rule for this connection
    /// alone is set on.
    pub connection: Option<ConnectionId>,
    pub through: Through,
    pub standing: Standing,
    /// How each operation would be decided; empty until there is a remote to
    /// decide for.
    pub decides: Vec<Decides>,
    /// The terms the row's grant serves on, once the organisation's limits
    /// hold them; `None` for a capability added to a connection alone, and
    /// where nothing is served.
    pub terms: Option<Terms>,
    /// Each limit that holds those terms.
    pub holds: Vec<Holding>,
    /// The last request the remote made of this capability.
    pub last: Option<Last>,
    /// What readiness named on the live connection for this capability,
    /// whether or not it keeps the capability from being carried.
    pub findings: Vec<Finding>,
    /// What Hedwig has written on the remote for this capability, with the
    /// grant's consent, and where each went.
    pub written: Vec<Written>,
    /// What this capability carries on to the remote in this run: its
    /// reverses, forwards and consoles.
    pub carried: Vec<CarriedOn>,
    /// The serial port this capability names, where a connection from the
    /// remote holds it now.
    pub hold: Option<Hold>,
    /// What the remote's tool cannot be given through this capability, with
    /// why: a serial port last opened over its chip's own USB.
    pub beyond: Vec<Beyond>,
    pub acts: Vec<Offered>,
}

/// A serial port a remote's connection holds: no other program on the
/// workstation can open it until the connection ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    /// The served opening that holds it.
    pub request: RequestId,
    pub port: PortName,
    pub since: Timestamp,
}

/// One thing an ADB capability carries on to the remote, and the core's
/// endpoint for it: for a reverse the workstation port the ADB server names,
/// which the person's own `adb reverse --list` at the workstation shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarriedOn {
    pub carriage: Carriage,
    pub endpoint: Port,
}

/// An act a row shows, and the refusal the core would give if it were asked
/// now: `None` means it would be carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offered {
    pub act: Act,
    pub withheld: Option<Refusal>,
}

/// Something that needs the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attention {
    Request {
        request: RequestId,
        remote: RemoteId,
        capability: Name,
        operation: Operation,
        key: Option<KeyId>,
        /// What it asks for, where its dialect reads that: the host an SSH
        /// login is to, a signature's namespace, the site a credential is
        /// for.
        payload: Option<Payload>,
        /// The lengths, in seconds, "allow for a time" may be answered with:
        /// the ones offered, up to the smallest cap that covers the request.
        offers: Vec<NonZeroU32>,
        /// The cap that took some of the lengths offered away, and whose it
        /// is; `None` where every length is offered.
        capped: Option<Capped>,
    },
    Prompt {
        prompt: PromptId,
        remote: RemoteId,
        kind: PromptKind,
        words: Words,
    },
    Unready {
        remote: RemoteId,
        capability: Name,
        findings: Vec<Finding>,
    },
    Stopped {
        remote: RemoteId,
        end: ChannelEnd,
    },
    Burst {
        remote: RemoteId,
        requests: u32,
    },
    /// A card lets a key on it be used with nobody there.
    Safeguards(Card),
    Refused {
        remote: Option<RemoteId>,
        refusal: Refusal,
        times: u32,
    },
    /// The core broke down and was started again, this many times since
    /// the person last put the matter away. What was live when it ended - the
    /// connections they opened, what they had allowed - went with it.
    Restarted {
        cause: Breakdown,
        times: u32,
    },
    /// What the core kept on disk could not be read and was set aside.
    Unreadable {
        store: Store,
        account: String,
    },
    /// Something let more through, and was not done at the surface being
    /// shown this: the entry that recorded it, and the client that did it.
    Widened {
        entry: Entry,
        kind: ClientKind,
        origin: Origin,
    },
    /// Requests were served to the remote while nobody was reachable, under
    /// a rule that says to.
    Unseen {
        remote: RemoteId,
        served: u32,
    },
    /// What the organisation states in one place changed: statements
    /// arrived or were withdrawn from entry `since` on, and `unread` of its
    /// lines cannot be read now.
    Policy {
        place: Place,
        since: Seq,
        arrived: u32,
        withdrawn: u32,
        unread: u32,
    },
    /// A route's platform could not say which of its remotes are running:
    /// grants that follow their lives hold nothing new until it can.
    Unlisted {
        route: Name,
        account: Words,
    },
    /// A remote's job told the person `remark`, by the entry `notice`, at
    /// `at`; `unheard` of that remote's notices before it were turned away
    /// for coming too fast. It is that remote's words and carries no act but
    /// putting it away.
    Noticed {
        remote: RemoteId,
        notice: Seq,
        at: Timestamp,
        remark: Remark,
        unheard: u32,
    },
    /// A removal of Hedwig began and has not finished: Hedwig serves no
    /// remote until the person keeps it or removes it. Nothing puts it away.
    Withdrawn(Withdrew),
}

/// Something that needs the person, and how loudly it reaches them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Needs {
    pub attention: Attention,
    pub volume: Volume,
}

impl Attention {
    /// The remote this is about, where it is about one.
    pub fn remote(&self) -> Option<&RemoteId> {
        match self {
            Attention::Request { remote, .. }
            | Attention::Prompt { remote, .. }
            | Attention::Unready { remote, .. }
            | Attention::Stopped { remote, .. }
            | Attention::Burst { remote, .. }
            | Attention::Unseen { remote, .. }
            | Attention::Noticed { remote, .. } => Some(remote),
            Attention::Refused { remote, .. } => remote.as_ref(),
            Attention::Safeguards(_)
            | Attention::Restarted { .. }
            | Attention::Unreadable { .. }
            | Attention::Widened { .. }
            | Attention::Policy { .. }
            | Attention::Unlisted { .. }
            | Attention::Withdrawn(_) => None,
        }
    }

    /// What the person puts away to dismiss it. A request or a prompt has
    /// none: it goes when it is decided or answered.
    pub fn item(&self) -> Option<Item> {
        match self {
            Attention::Request { .. } | Attention::Prompt { .. } | Attention::Withdrawn(_) => None,
            Attention::Unready {
                remote, capability, ..
            } => Some(Item::Unready {
                remote: remote.clone(),
                capability: capability.clone(),
            }),
            Attention::Stopped { remote, .. } => Some(Item::Stopped(remote.clone())),
            Attention::Burst { remote, .. } => Some(Item::Burst(remote.clone())),
            Attention::Safeguards(card) => Some(Item::Safeguards(card.serial.clone())),
            Attention::Refused {
                remote, refusal, ..
            } => Some(Item::Refused {
                remote: remote.clone(),
                refusal: refusal.clone(),
            }),
            Attention::Restarted { .. } => Some(Item::Restarted),
            Attention::Unreadable { store, .. } => Some(Item::Unreadable(*store)),
            Attention::Widened { entry, .. } => Some(Item::Widened(entry.seq)),
            Attention::Unseen { remote, .. } => Some(Item::Unseen(remote.clone())),
            Attention::Policy { place, .. } => Some(Item::Policy(*place)),
            Attention::Unlisted { route, .. } => Some(Item::Unlisted(route.clone())),
            Attention::Noticed { remote, notice, .. } => Some(Item::Noticed {
                remote: remote.clone(),
                through: *notice,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attached {
    pub client: ClientId,
    pub kind: ClientKind,
    pub origin: Origin,
    /// What it last said it can show the person; `None` for a client that
    /// says nothing of that, being one nothing is put to.
    pub presence: Option<Presence>,
    /// What it last said of its icon; `None` for a client that has said
    /// nothing of one, every client but the interface among them.
    pub icon: Option<Icon>,
    /// The remotes it watches.
    pub attends: Remotes,
}

/// Whether Hedwig is running, as what, and whether anything is exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub version: String,
    pub since: Timestamp,
    /// Where the core itself runs; a core started from an SSH session shows
    /// here.
    pub origin: Origin,
    pub attached: Vec<Attached>,
    pub paused: Vec<Remotes>,
    pub connected: Vec<RemoteId>,
    pub attention: u32,
    /// Whether Windows hints that a network is reached: without one,
    /// channels wait for one.
    pub network: Network,
    /// Since when the person has been removing Hedwig, where they are: it
    /// writes on no remote and opens no connection but to take back what it
    /// wrote, until they keep it.
    pub withdrawn: Option<Withdrew>,
}

/// One capability's own side on this workstation, listed once the core has
/// read either whether it answers or what holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub capability: Name,
    /// Whether it answered when last tried; `None` where it has not been
    /// tried in this run, though what holds it was read.
    pub health: Option<Health>,
    /// What last held the source on this workstation; `None` where nothing
    /// answered or none was read.
    pub holder: Option<SourceHolder>,
}

/// The keys one `GnuPG` capability's source offers, by which a surface
/// names the key a request uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offering {
    pub capability: Name,
    pub keyring: Keyring,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workstation {
    pub sources: Vec<Found>,
    /// Every card the core has read, each as it is known, a card taken out
    /// included.
    pub cards: Vec<Card>,
    /// The remotes the routes' platforms report running.
    pub running: Vec<RemoteId>,
    /// What each `GnuPG` capability's source last offered.
    pub keys: Vec<Offering>,
}

/// Whether the remote's own tool reached the core when exercised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// The core saw the request arrive through the chain.
    Reached(RequestId),
    /// The tool ran and nothing arrived; carries the last thing it said, which
    /// is where a remote tool says why.
    Silent(Option<Words>),
    /// The tool could not be run on the remote.
    Unrun(Finding),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    Welcome {
        protocol: u32,
        version: String,
        you: Origin,
    },
    Status(Status),
    Exposure(Vec<Row>),
    Attention(Vec<Needs>),
    Catalogue(Definitions),
    Workstation(Workstation),
    Document(Box<Document>),
    Activity(Vec<Entry>),
    Done(Effect),
    /// A change or an import made, and each limit that holds what it states.
    Changed {
        effect: Effect,
        held: Vec<Holding>,
    },
    Settings(Box<Settings>),
    Tried(Box<Tried>),
    Row(Box<Row>),
    /// The person's answer to a channel's prompt, for that channel's client
    /// alone.
    Answer(Answer),
    /// What a capability's source holds, in the source's own order.
    Devices(Vec<Lendable>),
    /// The keys an SSH agent holds, in its own order.
    Keys(Vec<AgentKey>),
    /// The key made in the workstation's TPM: its public half, to register
    /// where it is to be trusted, and its name.
    Made(AgentKey),
    /// The workstation's serial ports, by name.
    Ports(Vec<SerialPort>),
    /// Where taking back what Hedwig wrote stands, remote by remote.
    Withdrawal(Vec<Withdrawal>),
    /// What a supporter needs, assembled by the core.
    Bundle(Box<Bundle>),
}

/// Everything a supporter needs to find out why a remote cannot reach what
/// the workstation holds, in one document the person sees before it leaves.
/// It holds no secret: nothing the configuration document does not, and the
/// trail's entries, which record no answer and no passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The release of the core that assembled it.
    pub version: String,
    /// The folder it runs from.
    pub program: String,
    /// Windows' own version, as the core read it.
    pub windows: String,
    pub status: Status,
    pub attention: Vec<Needs>,
    pub exposure: Vec<Row>,
    pub settings: Settings,
    /// The newest entries of the activity, at most [`BUNDLED`].
    pub activity: Vec<Entry>,
    /// The diagnostics files' lines, oldest first.
    pub diagnostics: Vec<String>,
    /// The files set aside because they could not be read.
    pub set_aside: Vec<SetAside>,
}

/// The most entries of activity a bundle carries. Invariant: what a
/// supporter reads; the rest stays with the person.
pub const BUNDLED: usize = 1_000;

/// A file set aside because it could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAside {
    pub name: String,
    pub bytes: u64,
    /// When it was set aside, from its name.
    pub at: Timestamp,
}

/// What a notice says is stale; the client asks again for what it shows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Topic {
    Status,
    Exposure,
    Attention,
    Configuration,
    /// What the core has read of this workstation (`Reply::Workstation`):
    /// its sources' health and holders, its cards, the keys its sources
    /// offer, the remotes its routes report running.
    Workstation,
    /// The devices a capability's source holds: told to a client that asked
    /// for them, for as long as it stays attached.
    Devices(Name),
    /// The workstation's serial ports: told to a client that asked for them,
    /// for as long as it stays attached.
    Ports,
    /// The keys a capability's source holds: told to a client that asked for
    /// them, for as long as it stays attached, each time the core learns they
    /// changed - for the TPM, when it makes or deletes one.
    Keys(Name),
}

impl Topic {
    /// What `request` asks for that the core keeps current for the client
    /// that asked: a list that changes while a client shows it, by the
    /// workstation or by another client's act, which the client is told is
    /// stale whenever the core learns it did.
    pub fn listed(request: &Request) -> Option<Topic> {
        match request {
            Request::Devices(capability) => Some(Topic::Devices(capability.clone())),
            Request::Ports => Some(Topic::Ports),
            Request::Keys(capability) => Some(Topic::Keys(capability.clone())),
            _ => None,
        }
    }
}

/// A request served without asking, for a surface that announces those.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    pub request: RequestId,
    pub remote: RemoteId,
    pub capability: Name,
    pub operation: Operation,
    pub key: Option<KeyId>,
    /// What it asked for, where its dialect reads that.
    pub payload: Option<Payload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// To the clients that watch its remote: this now needs the person, and
    /// this is how loudly this client says so. Of the clients told of
    /// something that is announced, one announces it and the rest show it.
    Raised(Needs),
    /// To the one client that announces them: a request was served without
    /// asking, from a remote the person hears those for.
    Served(Served),
    /// To attending clients: a request or prompt they were shown is over.
    Withdrawn(Withdrawn),
    Stale(Topic),
    /// To a client that follows the trail.
    Recorded(Entry),
    /// To the client that asked for an exercise: what the remote's tool did,
    /// as the trail records it.
    Exercised(Exercised),
}

/// What a remote's own tool did when exercised, for the client that asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exercised {
    pub remote: RemoteId,
    pub capability: Name,
    pub proof: Proof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdrawn {
    Request(RequestId),
    Prompt(PromptId),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ToCore {
    pub id: u32,
    pub request: Request,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FromCore {
    Reply {
        id: u32,
        reply: Result<Reply, Refusal>,
    },
    Notice(Notice),
}
