//! The one thread's work, as a function: what arrived, and what follows.
//!
//! [`Core::step`] takes one [`Input`] and returns the entries it adds to the
//! trail and the [`Effect`]s that follow once those entries are on disk. It
//! reads no clock, opens no file and writes to no pipe, so everything the
//! core decides can be driven from a test with nothing else running.
//!
//! It never waits on a client and never grows for one. A client has one
//! request outstanding at a time; a client that follows the trail is a
//! position in it; and any other notice that does not fit becomes "what you
//! show is stale", once per topic.

use std::collections::{BTreeMap, BTreeSet};

use hedwig_model::capability::{
    Access, AgentAt, Capability, Exposure, Form, KeyKind, Lends, Operation, Query, ServicePort,
    Source, Stream,
};
use hedwig_model::config::{Catalogue, Configuration, Document, Effect as Changed};
use hedwig_model::credential::Place;
use hedwig_model::gate::{Door, Interaction, Verdict, World};
use hedwig_model::hold::Open;
use hedwig_model::holder::SourceHolder;
use hedwig_model::install::{AtSignIn, Starts};
use hedwig_model::protocol::{
    AgentKey, Answer, Attention, Decision, Exercised, FromCore, Needs, Notice, PROTOCOL, Proof,
    Reply, Request, Served, ToCore, Topic, Withdrawn,
};
use hedwig_model::refusal::{Refusal, Withheld};
use hedwig_model::remote::{Client, Lister, Listing, RemoteId};
use hedwig_model::setting::Keepalive;
use hedwig_model::site::{Opening, Site};
use hedwig_model::text::{
    Address, DeviceSerial, Fingerprint, Grip, KeyId, Location, Mark, Name, Port, PortName,
    RemotePath, SshKey, Words,
};
use hedwig_model::trail::{
    Asking, Binding, Breakdown, Card, Carriage, Carry, ChannelEnd, ClientId, ClientKind,
    ConnectionId, Dropped, Entry, Event, Failure, Finding, Gave, Given, Health, Item, Network,
    Opener, Origin, Outcome, Payload, Peer, Phase, PromptId, Readiness, Release, RequestId, Seq,
    Serving, State, Store, Target, Tick, Timestamp, Write, page,
};

use crate::adb::Reverse;
use crate::assuan::Breach;
use crate::browse::Browse;
use crate::channel::{asked, ended, words};
use crate::keys::Read;
use crate::relay::{Gnupg, Relayed, Relaying};
use crate::serial::Serial;
use crate::service::Service;
use crate::survey::{Asked, Dialect, Plan, Question, Report, Undo, Unread, place};

/// The most frames a client can have waiting to be written to it. The last
/// place is kept for the reply to its one outstanding request.
pub const WAITING: u8 = 16;

/// One connection to the control pipe, numbered by the server as it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Link(pub u64);

/// One connection to the workstation end of a forward, numbered as it is
/// accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Knock(pub u64);

/// The two readings of the moment an input is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    pub at: Timestamp,
    pub tick: Tick,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    /// A bundle completed with what is on disk, for the client that asked.
    Bundled {
        link: Link,
        id: u32,
        bundle: Box<hedwig_model::protocol::Bundle>,
    },
    /// A client connected and its first frame was read. `peer` is what was
    /// read of it through the pipe, or `None` when it let the core learn
    /// nothing.
    Arrived {
        link: Link,
        peer: Option<Peer>,
    },
    Asked {
        link: Link,
        frame: ToCore,
    },
    /// A line that is not a request. `id` is the one it carried, where it was
    /// well enough formed to carry one.
    Garbled {
        link: Link,
        id: Option<u32>,
        account: String,
    },
    /// One frame queued for the client was written to it.
    Sent {
        link: Link,
    },
    Left {
        link: Link,
    },
    /// Windows said the workstation is about to sleep, or has woken.
    Turned(Turn),
    /// Something became known of one connection's channel.
    Channel {
        connection: ConnectionId,
        told: Told,
    },
    /// Something connected to the workstation end of `capability`'s forward
    /// on `connection`. `peer` is what was read of it through the system's
    /// table of connections, or `None` when nothing could be.
    Knocked {
        knock: Knock,
        connection: ConnectionId,
        capability: Name,
        peer: Option<Peer>,
    },
    /// What a connection handed to a capability's relay says.
    Relayed {
        knock: Knock,
        relayed: Relayed,
    },
    /// The deadline the core last set has passed.
    Due,
    /// Windows hinted that the workstation now reaches a network, or none.
    Network(Network),
    /// What a route's listing found: the addresses it printed, or why it
    /// could not be read.
    Listed {
        route: Name,
        listed: Result<Vec<Address>, Words>,
    },
    /// The devices `capability`'s server holds changed.
    Devices {
        capability: Name,
        view: crate::devices::View,
    },
    /// What `capability`'s server listed for a client that asked, or why it
    /// listed nothing.
    Lendable {
        link: Link,
        id: u32,
        capability: Name,
        view: crate::devices::View,
    },
    /// The keys `capability`'s agent listed for a client that asked, or why
    /// it listed none; with what held its pipe or socket.
    Keys {
        link: Link,
        id: u32,
        capability: Name,
        listed: crate::relay::Reach<Vec<AgentKey>>,
    },
    /// The key made in the TPM for a client that asked, or why none was.
    Made {
        link: Link,
        id: u32,
        name: Name,
        made: Result<AgentKey, Refusal>,
    },
    /// The name of the key Hedwig made whose public half a client asked to
    /// delete, or why there is none.
    Found {
        link: Link,
        id: u32,
        key: SshKey,
        found: Result<Name, Refusal>,
    },
    /// The key deleted from the TPM, or why it was not.
    Deleted {
        link: Link,
        id: u32,
        name: Name,
        key: SshKey,
        deleted: Result<(), Refusal>,
    },
    /// The workstation's serial ports, for a client that asked or after
    /// Windows said they may have changed.
    Ports {
        asked: Option<(Link, u32)>,
        ports: Vec<hedwig_model::protocol::SerialPort>,
    },
    /// Windows said the workstation's serial ports may have changed.
    PortsMoved,
    /// What Windows starts at sign-in for each start-up choice, as keeping
    /// their `Run` values found it.
    Startup([(Starts, AtSignIn); 2]),
    /// A forward placed again when its remote's channel came back could not
    /// listen at its port there: something on the remote took it.
    Retaken {
        forwarding: crate::adb::Forwarding,
    },
    /// A lent emulator's console is carried on to the remote through `endpoint`.
    Consoled {
        connection: ConnectionId,
        capability: Name,
        carriage: Carriage,
        endpoint: Port,
    },
    /// A lent emulator's console could not be carried: its port on the
    /// remote would not listen.
    Unconsoled {
        remote: RemoteId,
        capability: Name,
        port: Port,
    },
    /// A console command from `connection`'s remote that acts on the
    /// workstation was refused.
    Hosted {
        connection: ConnectionId,
        capability: Name,
    },
}

/// What the threads that wait on a channel tell the deciding thread.
#[derive(Debug, PartialEq, Eq)]
pub enum Told {
    /// What readiness found, the answer to [`Effect::Survey`]: the remote's
    /// report, or why none could be read with what the client said last;
    /// and the forwards the person's own configuration declares for the
    /// host.
    Surveyed {
        report: Result<Report, (Unread, Option<Words>)>,
        theirs: Vec<Words>,
    },
    /// The remote's own tool used a capability once, the answer to
    /// [`Effect::Exercise`]: what it said last, or why it could not run.
    Exercised { ran: Result<Option<Words>, Finding> },
    /// What each `GnuPG` capability's source offers, the answer to
    /// [`Effect::Read`], or why it could not be read.
    Read {
        read: Vec<(Name, Result<Read, Failure>)>,
    },
    /// The cards each `GnuPG` capability's source's scdaemon holds, the
    /// answer to [`Effect::Cards`], or why they could not be read.
    Cards {
        read: Vec<(Name, Result<Vec<Card>, Failure>)>,
    },
    /// The client was started, from this program, let ask as `asking`.
    Ran {
        program: Location,
        release: Option<Release>,
        asking: Asking,
    },
    /// No client was started.
    Unstarted { end: ChannelEnd },
    /// The remote's server answered for one capability's forward.
    Forwarded { capability: Name, bound: bool },
    /// The client said the host presents another key than the one known.
    HostKeyChanged { fingerprint: Mark },
    /// The client ended. `unverified` is whether it stopped for want of the
    /// person's word on the host's key; `last` is the last line it wrote.
    Ended {
        status: i32,
        unverified: bool,
        last: Option<Words>,
    },
}

/// What Windows said of the workstation's sleep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    Sleeping,
    Woke,
}

/// What happens to a connection once a frame has been written to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Then {
    /// The client may send its next request.
    Continue,
    /// A notice: it answers nothing, so nothing waits on it.
    Nothing,
    /// The connection ends once the client has had time to read the frame.
    Close,
    /// As [`Then::Close`], and then the core ends.
    Stop,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    Send {
        link: Link,
        frame: FromCore,
        then: Then,
    },
    /// Run readiness on the connection's remote in `dialect`, in the
    /// connection's job, and answer with [`Told::Surveyed`].
    Survey {
        connection: ConnectionId,
        client: Client,
        address: Address,
        dialect: Dialect,
        plan: Plan,
        asking: Asking,
        keepalive: Keepalive,
    },
    /// Have the remote's own tool use `capability` once through the forward
    /// at `binding`, and answer with [`Told::Exercised`].
    Exercise {
        connection: ConnectionId,
        client: Client,
        address: Address,
        dialect: Dialect,
        capability: Name,
        query: Option<Query>,
        binding: Binding,
        asking: Asking,
        keepalive: Keepalive,
    },
    /// Start the channel: the route's client, in a job of its own, with a
    /// forward for each capability in `serving`.
    Start {
        connection: ConnectionId,
        client: Client,
        address: Address,
        serving: Vec<Serving>,
        asking: Asking,
        keepalive: Keepalive,
    },
    /// Ask `route`'s platform which of its remotes are running, and answer
    /// with [`Input::Listed`].
    List { route: Name, lister: Lister },
    /// End `route`'s listing, which has not answered in time.
    Unlist { route: Name },
    /// End the channel's job, and with it every forward.
    End { connection: ConnectionId },
    /// Read what each `GnuPG` source offers, before `connection`'s survey,
    /// and answer with [`Told::Read`].
    Read {
        connection: ConnectionId,
        sources: Vec<(Name, Gnupg)>,
    },
    /// Read the cards alone of each `GnuPG` source, after a card was used
    /// through it, and answer with [`Told::Cards`].
    Cards {
        connection: ConnectionId,
        sources: Vec<(Name, Gnupg)>,
    },
    /// Hand an admitted connection to what carries `capability`, as coming
    /// from `connection`'s remote. `presents` are the bytes a Windows remote's
    /// socket file holds, which its `gpg` sends first.
    Relay {
        knock: Knock,
        connection: ConnectionId,
        capability: Name,
        source: Relaying,
        presents: Option<[u8; 16]>,
    },
    /// Serve the request the relayed connection holds, or refuse it.
    Settle {
        knock: Knock,
        verdict: Result<(), Refusal>,
    },
    /// Let what serves the relayed connection's request ask the person: the
    /// workstation's own credential helper, for a request the person allowed
    /// where its sign-in shows. Given before the word that serves it.
    Interact { knock: Knock },
    /// Close a connection that was turned away, with nothing written to it.
    Refuse { knock: Knock },
    /// Give the reverse the relayed connection holds the endpoint its remote
    /// and capability have for its target, bound now where they have none,
    /// which the capability's ADB server at `server` reaches it through.
    Endpoint {
        knock: Knock,
        reverse: Reverse,
        server: Service,
    },
    /// Refuse the reverse the relayed connection holds.
    Withhold { knock: Knock, withheld: Withheld },
    /// Have the connection's last survey seal Hedwig's private folder on the
    /// remote, now that the channel's forwards are bound there.
    Seal { connection: ConnectionId },
    /// Carry the callback the relayed connection's sign-in comes back to on
    /// to the remote: the route's client again, in `connection`'s job, with a
    /// local forward to `target`, the callback's own host and port there.
    Call {
        knock: Knock,
        connection: ConnectionId,
        client: Client,
        address: Address,
        target: Target,
        asking: Asking,
        keepalive: Keepalive,
    },
    /// Stop carrying the relayed connection's callback, and end its carrier.
    Uncall { knock: Knock },
    /// Carry the endpoint of `reverse` on to its remote: the route's client
    /// again, in `connection`'s job, with a local forward to its target.
    Haul {
        connection: ConnectionId,
        reverse: Reverse,
        client: Client,
        address: Address,
        asking: Asking,
        keepalive: Keepalive,
    },
    /// Place the forward the relayed connection holds on the remote at
    /// `port`, 0 for one the remote's server chooses: the route's client
    /// again, in `carrier.connection`'s job, with a remote forward to an
    /// endpoint of the core's that reaches the capability's server at
    /// `server`. The relayed connection is given the port bound there, or why
    /// none was.
    Place {
        knock: Knock,
        remote: RemoteId,
        capability: Name,
        port: u16,
        server: Service,
        carrier: Carrier,
    },
    /// Place again, at the same port, a forward the remote holds, now its
    /// channel is up again.
    Replace {
        forwarding: crate::adb::Forwarding,
        server: Service,
        carrier: Carrier,
    },
    /// The server's listener a forward goes on to; the relayed connection
    /// that asked for it is answered once its endpoint has it.
    Listen {
        knock: Knock,
        forwarding: crate::adb::Forwarding,
        listener: Port,
    },
    /// End a forward's carrier and let its endpoint go.
    Unplace {
        connection: ConnectionId,
        forwarding: crate::adb::Forwarding,
    },
    /// Have the capability's server remove its forward at `listener`, on
    /// device `id`.
    Unlisten {
        server: Service,
        id: u64,
        listener: Port,
    },
    /// Tell a relayed ADB connection what its grant lends now.
    Relend {
        knock: Knock,
        lending: crate::adb::Lending,
    },
    /// Watch the devices of `capability`'s server, telling the deciding
    /// thread of each change.
    Watch { capability: Name, server: Service },
    /// Stop watching them.
    Unwatch { capability: Name },
    /// List the workstation's serial ports, for the client that asked, or
    /// for the clients that list them where Windows said they may have
    /// changed.
    Ports { asked: Option<(Link, u32)> },
    /// Keep the person's `Run` values in step with these.
    Startup {
        hedwig: hedwig_model::setting::Autostart,
        icon: hedwig_model::setting::Autostart,
    },
    /// Write what goes wrong at this level from here.
    Diagnose(hedwig_model::setting::Diagnostics),
    /// Complete a bundle with what is on disk and the program's own facts,
    /// and answer the client that asked.
    Bundle {
        link: Link,
        id: u32,
        bundle: Box<hedwig_model::protocol::Bundle>,
    },
    /// Ask the agent `at` once which keys it holds, for the client that
    /// asked.
    Keys {
        link: Link,
        id: u32,
        capability: Name,
        at: AgentAt,
    },
    /// Make a key in the TPM, and answer with [`Input::Made`].
    MakeKey {
        link: Link,
        id: u32,
        name: Name,
        kind: KeyKind,
    },
    /// Find the key Hedwig made whose public half is `key`, and answer with
    /// [`Input::Found`].
    FindKey { link: Link, id: u32, key: SshKey },
    /// Delete the key named `name` where its public half is still `key`, and
    /// answer with [`Input::Deleted`]. Every lending of it was taken back
    /// first.
    DeleteKey {
        link: Link,
        id: u32,
        name: Name,
        key: SshKey,
    },
    /// Read the devices `capability`'s server holds, for the client that
    /// asked.
    Lend {
        link: Link,
        id: u32,
        capability: Name,
        server: Service,
    },
    /// Carry the console of the lent emulator `device` on to the remote at
    /// `port` on its loopback: the route's client again with a remote forward
    /// to an endpoint of the core's that authenticates to the console with
    /// the workstation's own token.
    Console {
        remote: RemoteId,
        capability: Name,
        port: Port,
        device: DeviceSerial,
        network: bool,
        carrier: Carrier,
    },
    /// End a console's carrier.
    Unconsole {
        connection: ConnectionId,
        remote: RemoteId,
        capability: Name,
        port: Port,
    },
}

/// What the person added to a connection they open: capabilities for it
/// alone, what they named those expose, and the devices they lend.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Added {
    with: Vec<Name>,
    acknowledged: Exposure,
    lends: Lends,
}

impl Added {
    fn nothing() -> Added {
        Added {
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        }
    }
}

/// One thing a remote has carried on to it through an ADB capability's
/// carrier, as [`crate::adb::CARRIED`] counts it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Slot {
    Reverse(Target),
    Forward(Port),
    /// A forward waiting for its port on the remote.
    Placing(Knock),
    Console(Port),
}

/// What a carrier is started with: the route's client in `connection`'s
/// job, at `address`, let ask as `asking`, kept alive as `keepalive`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carrier {
    pub connection: ConnectionId,
    pub client: Client,
    pub address: Address,
    pub asking: Asking,
    pub keepalive: Keepalive,
}

/// The configuration as one of a step's entries left it.
#[derive(Debug, PartialEq, Eq)]
pub struct Keep {
    /// The entry that records the change.
    pub entry: Seq,
    pub document: Document,
}

/// What one input leads to. The effects are released only when `entries` are
/// on disk and `keep`, if any, has replaced the stored configuration.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Step {
    pub entries: Vec<Entry>,
    pub keep: Option<Keep>,
    /// The trail as it is to be kept from here, once `entries` are on disk.
    pub compact: Option<Box<Compaction>>,
    pub effects: Vec<Effect>,
}

/// A compacted trail for the file-owning thread to put in the file's place,
/// and what of the files set aside it may remove.
#[derive(Debug, PartialEq, Eq)]
pub struct Compaction {
    /// The trail from here - its head and its entries - where it changed.
    pub trail: Option<(Box<State>, Vec<Entry>)>,
    /// Set-aside files older than this go, unless their store is in `raised`.
    pub before: Timestamp,
    /// The stores whose unreadable files are still before the person.
    pub raised: Vec<Store>,
}

/// One day on the wall clock, in the trail's milliseconds.
const DAY: u64 = 86_400_000;

#[derive(Debug, Default)]
struct Attendant {
    peer: Option<Peer>,
    client: Option<ClientId>,
    /// Frames handed to the writer and not yet written.
    waiting: u8,
    /// Topics this client was not told are stale, because nothing fitted.
    stale: BTreeSet<Topic>,
    /// The next entry a follower is owed.
    follows: Option<Seq>,
    /// The lists this client was answered, which it is told are stale
    /// whenever they change, for as long as it stays.
    lists: BTreeSet<Topic>,
    /// For a client that asks on a channel's behalf, that channel.
    channel: Option<ConnectionId>,
}

/// A request that waits for its source's keys to be read: its connection,
/// what it asks, the key it names, and what its payload said.
type Waiting = (Knock, Operation, KeyId, Option<Payload>);

/// A client that has not greeted; no entry creates it, so it attends nothing.
const NOBODY: ClientId = ClientId(Seq(0));

/// A channel whose client has been asked for and has not ended.
#[derive(Debug, Default)]
struct Channel {
    /// The forwards the client was started with.
    asked: Vec<Serving>,
    /// Those the remote's server has not yet answered for.
    pending: BTreeSet<Name>,
    /// Those it bound.
    bound: Vec<Serving>,
}

/// Why a survey runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// Before a channel: it starts with what readiness places.
    Open,
    /// The person asked, with the channel live: only what is found changes.
    Recheck,
    /// The person asked, with no channel live: nothing is started unless
    /// something wants the channel.
    Check,
    /// Hedwig is being removed: the survey takes back what Hedwig wrote, and
    /// the connection ends with it.
    Withdraw,
}

/// A connection a relay carries: what it reaches, and the request it holds
/// for a decision, where it holds one.
#[derive(Debug, Clone)]
struct Streamed {
    connection: ConnectionId,
    capability: Name,
    request: Option<RequestId>,
    /// The request to open a URL, and what opening it carries, kept in
    /// memory only: the URL is never recorded.
    opened: Option<(RequestId, Opening)>,
    /// Whether its callback is carried now.
    calling: bool,
    /// Whether the request in hand uses a key on a card.
    asking_card: bool,
    /// Whether a request using a key on a card was served on it: the cards
    /// are read again once it ends, when scdaemon holds the card the agent
    /// scanned for.
    used_card: bool,
    /// For an ADB connection: what its grant lent when it was last told.
    lending: Option<crate::adb::Lending>,
    /// For a serial connection: the port its capability names, the opening
    /// once it is settled, and whether the port was opened for it.
    port: Option<Taking>,
    /// The request last served on it, which what came of serving it is told
    /// of.
    served: Option<RequestId>,
}

/// A serial connection's port, as far as it has gone.
#[derive(Debug, Clone)]
struct Taking {
    port: PortName,
    opening: Option<RequestId>,
    taken: bool,
}

/// An exercise waiting on the remote's tool, and the client its result is
/// told to.
#[derive(Debug, Clone, Copy)]
struct Exercising {
    link: Link,
    client: ClientId,
    /// The last entry before it started; a request after it is the tool's.
    since: Seq,
}

/// Where one route's listing stands.
#[derive(Debug, Clone, Copy)]
struct Listed {
    /// When the next is due.
    next: Tick,
    /// When the one running was started.
    since: Option<Tick>,
    /// How long, in milliseconds, one may run and the next waits.
    cadence: u64,
}

/// Something that needs the person, as it was raised.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Raised {
    Request(RequestId),
    Prompt(PromptId),
    Item(Item),
}

impl Raised {
    fn of(attention: &Attention) -> Option<Raised> {
        match attention {
            Attention::Request { request, .. } => Some(Raised::Request(*request)),
            Attention::Prompt { prompt, .. } => Some(Raised::Prompt(*prompt)),
            _ => attention.item().map(Raised::Item),
        }
    }
}

pub struct Core {
    catalogue: Catalogue,
    configuration: Configuration,
    /// What the entries before the first were folded into.
    head: State,
    trail: Vec<Entry>,
    state: State,
    version: String,
    /// The level diagnostics were last said to be written at.
    diagnosed: Option<hedwig_model::setting::Diagnostics>,
    /// What was last said Windows starts at sign-in: Hedwig, and its icon.
    starting: Option<(
        hedwig_model::setting::Autostart,
        hedwig_model::setting::Autostart,
    )>,
    links: BTreeMap<Link, Attendant>,
    channels: BTreeMap<ConnectionId, Channel>,
    /// What each live connection was opened to carry.
    opened: BTreeMap<ConnectionId, BTreeSet<Name>>,
    /// Each survey running, in the dialect it runs in and why.
    surveys: BTreeMap<ConnectionId, (Dialect, Purpose)>,
    /// Each exercise running, by its connection, with the capability it
    /// uses.
    exercises: BTreeMap<ConnectionId, (Name, Exercising)>,
    /// The bytes each live connection's Windows socket file holds. Never
    /// recorded: they are what a connection through the forward presents.
    issued: BTreeMap<ConnectionId, [u8; 16]>,
    listings: BTreeMap<Name, Listed>,
    /// Each prompt put to the person, and the request of the client that
    /// asked it, which is answered when the person answers.
    asking: BTreeMap<PromptId, (Link, u32)>,
    /// What needs the person and was raised, with the remote it is about.
    raised: BTreeMap<Raised, Option<RemoteId>>,
    /// Each connection a relay carries, by its knock.
    streams: BTreeMap<Knock, Streamed>,
    /// What each remote has carried on to it in this run through its ADB
    /// capabilities' carriers, which [`crate::adb::CARRIED`] bounds.
    carrying: BTreeMap<RemoteId, BTreeSet<(Name, Slot)>>,
    /// Each forward the server took, by its remote, capability and port on
    /// the remote: the channel it was asked on and its device's transport
    /// id, which a forward ends with when the device leaves the server.
    forwarded: BTreeMap<(RemoteId, Name, Port), (ConnectionId, u64)>,
    /// The ADB capabilities whose servers' devices are watched because a
    /// channel carries them; a client listing one keeps its watch too.
    watched: BTreeSet<Name>,
    /// What each list a client lists answered last: what a change is told
    /// against.
    answered: BTreeMap<Topic, Answered>,
    /// Each watched server's devices as it last listed them: what a change
    /// of lending, or a channel come up while the server is watched already,
    /// is decided against, since its watch tells only of a change.
    viewed: BTreeMap<Name, crate::devices::View>,
    /// The connections whose survey has its sources' keys read.
    keyed: BTreeSet<ConnectionId>,
    /// Each request waiting, before it is decided, for its source to be read
    /// again, since it names a key no reading accounts for: a statement
    /// naming a key by fingerprint must not miss it for a stale reading.
    rereading: BTreeMap<Name, Vec<Waiting>>,
    /// The keygrips a fresh reading did not account for either, by
    /// capability, which are decided as they stand until the next reading.
    sought: BTreeSet<(Name, KeyId)>,
    /// How many requests with a key on a card each source served since its
    /// cards were last read: the agent scanned for a card for each, which no
    /// read that cannot open one sees before.
    cards_stale: BTreeMap<Name, u64>,
    /// Each source's cards read under way, with how many uses it began after.
    cards_reading: BTreeMap<Name, u64>,
    /// Each request with a key on a card waiting for its source's cards to be
    /// read again before it is decided.
    cards_waiting: BTreeMap<Name, Vec<Waiting>>,
    /// Each key's public half, armoured, as the last read found it. Kept in
    /// memory: the bytes are the keyring's, which the trail never copies.
    armoured: BTreeMap<Fingerprint, String>,
    /// How many notices each remote sent too fast since the last one kept:
    /// counted here, never recorded one by one, and said with the next.
    hushed: BTreeMap<RemoteId, u32>,
    /// The tick of the input being handled, or last handled.
    now: Tick,
}

impl Core {
    /// A core over a trail never compacted and the configuration read at
    /// start.
    pub fn new(
        catalogue: Catalogue,
        configuration: Configuration,
        trail: Vec<Entry>,
        version: String,
    ) -> Core {
        Core::resume(catalogue, configuration, State::default(), trail, version)
    }

    /// A core over the trail read at start - its head and its entries - and
    /// the configuration.
    pub fn resume(
        catalogue: Catalogue,
        configuration: Configuration,
        head: State,
        trail: Vec<Entry>,
        version: String,
    ) -> Core {
        Core {
            state: State::after(head.clone(), &trail),
            head,
            catalogue,
            configuration,
            trail,
            version,
            diagnosed: None,
            starting: None,
            links: BTreeMap::new(),
            channels: BTreeMap::new(),
            opened: BTreeMap::new(),
            surveys: BTreeMap::new(),
            exercises: BTreeMap::new(),
            issued: BTreeMap::new(),
            listings: BTreeMap::new(),
            asking: BTreeMap::new(),
            raised: BTreeMap::new(),
            streams: BTreeMap::new(),
            carrying: BTreeMap::new(),
            forwarded: BTreeMap::new(),
            watched: BTreeSet::new(),
            answered: BTreeMap::new(),
            viewed: BTreeMap::new(),
            keyed: BTreeSet::new(),
            rereading: BTreeMap::new(),
            sought: BTreeSet::new(),
            cards_stale: BTreeMap::new(),
            cards_reading: BTreeMap::new(),
            cards_waiting: BTreeMap::new(),
            armoured: BTreeMap::new(),
            hushed: BTreeMap::new(),
            now: Tick(0),
        }
    }

    /// The next tick at which the core has something to do by time alone;
    /// `None` when nothing waits on time.
    pub fn due(&self) -> Option<Tick> {
        let listings = self.listings.values().map(|listed| match listed.since {
            Some(since) => Tick(since.0.saturating_add(listed.cadence)),
            None => listed.next,
        });
        self.world()
            .deadline(self.now)
            .into_iter()
            .chain(listings)
            .min()
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    fn world(&self) -> World<'_> {
        World {
            catalogue: &self.catalogue,
            configuration: &self.configuration,
            state: &self.state,
        }
    }

    fn record(&mut self, step: &mut Step, now: Now, event: Event) -> Seq {
        let seq = Seq(self.trail.last().map_or(0, |last| last.seq.0) + 1);
        let entry = Entry {
            seq,
            at: now.at,
            tick: now.tick,
            event,
        };
        self.state.apply(&entry);
        self.trail.push(entry.clone());
        step.entries.push(entry);
        seq
    }

    /// The first entries of a run: what could not be read, then the start.
    pub fn begin(
        &mut self,
        origin: Origin,
        after: Option<Breakdown>,
        unreadable: Vec<(Store, String)>,
        now: Now,
    ) -> Step {
        let mut step = Step::default();
        for (store, account) in unreadable {
            self.record(&mut step, now, Event::Unreadable { store, account });
        }
        self.record(
            &mut step,
            now,
            Event::Started {
                version: self.version.clone(),
                origin,
                after,
            },
        );
        self.now = now.tick;
        self.compacting(&mut step, now, 0);
        self.diagnosing(&mut step);
        self.starting(&mut step);
        self.hold(&mut step, now);
        // Nobody is attached yet: what waits as the run starts counts as
        // raised, and a client that attaches reads it rather than hearing it.
        self.raise(&mut step);
        step
    }

    /// What the core holds of a supporter's bundle; what is on disk and the
    /// program's own facts are added where the effect is carried out.
    fn bundle(&self, client: ClientId, now: Now) -> Option<hedwig_model::protocol::Bundle> {
        let world = self.world();
        let status = world.status(client, now.tick)?;
        let mut activity: Vec<Entry> = self
            .trail
            .iter()
            .rev()
            .take(hedwig_model::protocol::BUNDLED)
            .cloned()
            .collect();
        activity.reverse();
        Some(hedwig_model::protocol::Bundle {
            version: self.version.clone(),
            program: String::new(),
            windows: String::new(),
            status,
            attention: world.attention(client, now.tick),
            exposure: world.rows(client, now.tick),
            settings: world.settings(&[]),
            activity,
            diagnostics: Vec::new(),
            set_aside: Vec::new(),
        })
    }

    /// Folds what the person keeps no longer, and what is past the ceiling,
    /// into one entry, where the trail holds more than `over` entries past
    /// the ceiling or anything older than the horizon at a run's start.
    fn compacting(&mut self, step: &mut Step, now: Now, over: usize) {
        if self.trail.len() <= hedwig_model::trail::CEILING + over && over > 0 {
            return;
        }
        let keep = self.world().keep().settled.value;
        let before = Timestamp(
            now.at
                .0
                .saturating_sub(u64::from(keep.0.get()).saturating_mul(DAY)),
        );
        let head = |trail: &[Entry]| {
            (
                trail.len(),
                trail
                    .first()
                    .map(|first| (first.seq, matches!(first.event, Event::Kept { .. }))),
            )
        };
        let was = head(&self.trail);
        (self.head, self.trail) = hedwig_model::trail::compact(
            std::mem::take(&mut self.head),
            std::mem::take(&mut self.trail),
            before,
            hedwig_model::trail::CEILING,
        );
        let changed = head(&self.trail) != was;
        // At a run's start the files set aside are looked at whether or not
        // the trail changed.
        if changed || over == 0 {
            step.compact = Some(Box::new(Compaction {
                trail: changed.then(|| (Box::new(self.head.clone()), self.trail.clone())),
                before,
                raised: self.state.unread_stores(),
            }));
        }
    }

    pub fn step(&mut self, input: Input, now: Now) -> Step {
        let mut step = self.stepped(input, now);
        self.compacting(&mut step, now, hedwig_model::trail::CEILING / 10);
        self.diagnosing(&mut step);
        self.starting(&mut step);
        step
    }

    /// Says what Windows starts at sign-in where it differs from the last
    /// said, and at a run's start, so a value the person removed by hand or
    /// one naming a folder Hedwig no longer runs from is put right.
    fn starting(&mut self, step: &mut Step) {
        let world = self.world();
        let now = (world.autostart().value, world.icon().value);
        if self.starting != Some(now) {
            self.starting = Some(now);
            step.effects.push(Effect::Startup {
                hedwig: now.0,
                icon: now.1,
            });
        }
    }

    /// Says the level diagnostics are written at, where it differs from the
    /// last said.
    fn diagnosing(&mut self, step: &mut Step) {
        let level = self.world().diagnostics().settled.value;
        if self.diagnosed != Some(level) {
            self.diagnosed = Some(level);
            step.effects.push(Effect::Diagnose(level));
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one arm per input, each handing it to what decides it"
    )]
    fn stepped(&mut self, input: Input, now: Now) -> Step {
        let mut step = Step::default();
        self.now = now.tick;
        let timed = matches!(
            input,
            Input::Due | Input::Turned(_) | Input::Network(_) | Input::Listed { .. }
        );
        let lapsed = input == Input::Due;
        let actor = match input {
            Input::Arrived { link, peer } => {
                self.links.insert(
                    link,
                    Attendant {
                        peer,
                        ..Attendant::default()
                    },
                );
                Some(link)
            }
            Input::Asked { link, frame } => {
                self.asked(&mut step, now, link, frame);
                Some(link)
            }
            Input::Garbled { link, id, account } => {
                let refused = Err(Refusal::Malformed(account));
                match id {
                    Some(id) => self.reply(&mut step, link, id, refused, Then::Continue),
                    // Which request this was cannot be said, so neither can
                    // which reply answers the client's next one.
                    None => self.reply(&mut step, link, 0, refused, Then::Close),
                }
                Some(link)
            }
            Input::Sent { link } => {
                if let Some(attendant) = self.links.get_mut(&link) {
                    attendant.waiting = attendant.waiting.saturating_sub(1);
                }
                Some(link)
            }
            Input::Left { link } => {
                self.left(&mut step, now, link);
                Some(link)
            }
            Input::Turned(turn) => {
                self.turned(&mut step, now, turn);
                None
            }
            Input::Due => None,
            Input::Network(network) => {
                if network != self.state.network() {
                    let event = match network {
                        Network::Online => Event::Online,
                        Network::Offline => Event::Offline,
                    };
                    self.record(&mut step, now, event);
                }
                None
            }
            Input::Listed { route, listed } => {
                self.listed(&mut step, now, &route, listed);
                None
            }
            Input::Devices { capability, view } => {
                self.devices(&mut step, now, &capability, &view);
                None
            }
            Input::Bundled { link, id, bundle } => {
                self.reply(
                    &mut step,
                    link,
                    id,
                    Ok(Reply::Bundle(bundle)),
                    Then::Continue,
                );
                Some(link)
            }
            Input::Keys {
                link,
                id,
                capability,
                listed,
            } => {
                let answered = match &listed.result {
                    Ok(keys) => Ok(keys.clone()),
                    Err(failure) => Err(*failure),
                };
                self.answer(
                    Topic::Keys(capability.clone()),
                    Answered::Keys(answered),
                    Some(link),
                );
                self.held(&mut step, now, &capability, listed.holder);
                let reply = match listed.result {
                    Ok(keys) => Ok(Reply::Keys(keys)),
                    Err(failure) => Err(Refusal::SourceUnavailable {
                        capability,
                        failure,
                    }),
                };
                self.reply(&mut step, link, id, reply, Then::Continue);
                Some(link)
            }
            Input::Made {
                link,
                id,
                name,
                made,
            } => {
                let reply = made.map(|made| {
                    let event = Event::KeyMade {
                        key: made.key.clone(),
                        name,
                        by: self.client_of(link),
                    };
                    self.record(&mut step, now, event);
                    self.keys_changed();
                    Reply::Made(made)
                });
                self.reply(&mut step, link, id, reply, Then::Continue);
                Some(link)
            }
            Input::Found {
                link,
                id,
                key,
                found,
            } => {
                match found {
                    Ok(name) => {
                        self.unlend(&mut step, now, link, &key);
                        step.effects.push(Effect::DeleteKey {
                            link,
                            id,
                            name,
                            key,
                        });
                    }
                    Err(refusal) => {
                        self.reply(&mut step, link, id, Err(refusal), Then::Continue);
                    }
                }
                Some(link)
            }
            Input::Deleted {
                link,
                id,
                name,
                key,
                deleted,
            } => {
                let reply = deleted.map(|()| {
                    let event = Event::KeyDeleted {
                        key,
                        name,
                        by: self.client_of(link),
                    };
                    self.record(&mut step, now, event);
                    self.keys_changed();
                    Reply::Done(Changed::Changed)
                });
                self.reply(&mut step, link, id, reply, Then::Continue);
                Some(link)
            }
            Input::Lendable {
                link,
                id,
                capability,
                view,
            } => {
                if view.holder.is_some() {
                    self.held(&mut step, now, &capability, view.holder.clone());
                }
                let listed = view.lendable();
                let topic = Topic::Devices(capability.clone());
                self.answer(topic, Answered::Devices(listed.clone()), Some(link));
                let reply =
                    listed
                        .map(Reply::Devices)
                        .map_err(|failure| Refusal::SourceUnavailable {
                            capability,
                            failure,
                        });
                self.reply(&mut step, link, id, reply, Then::Continue);
                Some(link)
            }
            Input::Ports { asked, ports } => {
                let asker = asked.map(|(link, _)| link);
                self.answer(Topic::Ports, Answered::Ports(ports.clone()), asker);
                asked.map(|(link, id)| {
                    self.reply(&mut step, link, id, Ok(Reply::Ports(ports)), Then::Continue);
                    link
                })
            }
            Input::Startup(found) => {
                for (starts, found) in found {
                    if self.state.startup(starts) != Some(&found) {
                        self.record(&mut step, now, Event::Startup { starts, found });
                    }
                }
                None
            }
            Input::PortsMoved => {
                if self.lists(&Topic::Ports) {
                    step.effects.push(Effect::Ports { asked: None });
                }
                None
            }
            Input::Retaken { forwarding } => {
                self.retaken(&mut step, now, &forwarding);
                None
            }
            Input::Consoled {
                connection,
                capability,
                carriage,
                endpoint,
            } => {
                self.consoled(&mut step, now, connection, capability, carriage, endpoint);
                None
            }
            Input::Unconsoled {
                remote,
                capability,
                port,
            } => {
                if let Some(carrying) = self.carrying.get_mut(&remote) {
                    carrying.remove(&(capability, Slot::Console(port)));
                }
                None
            }
            Input::Hosted {
                connection,
                capability,
            } => {
                let remote = self.state.link(connection).map(|link| link.remote.clone());
                let refusal = Refusal::Withheld {
                    capability,
                    request: Withheld::Hosted,
                };
                self.record(&mut step, now, Event::TurnedAway { remote, refusal });
                None
            }
            Input::Channel { connection, told } => {
                self.told(&mut step, now, connection, told);
                None
            }
            Input::Relayed { knock, relayed } => {
                self.relayed(&mut step, now, knock, relayed);
                None
            }
            Input::Knocked {
                knock,
                connection,
                capability,
                peer,
            } => {
                let door = Door::Forward(connection);
                match self.world().admit(door, peer.as_ref()) {
                    Ok(_) => self.relay(&mut step, knock, connection, capability),
                    Err(refusal) => {
                        let remote = self.state.link(connection).map(|link| link.remote.clone());
                        self.record(&mut step, now, Event::TurnedAway { remote, refusal });
                        step.effects.push(Effect::Refuse { knock });
                    }
                }
                None
            }
        };
        // Whatever was recorded - a surface leaving, covered or engaged, a
        // card set not to be shown, a set redefined - may have left something
        // held with nobody to put it to.
        if !step.entries.is_empty() {
            self.strand(&mut step, now);
        }
        let moved = timed || !step.entries.is_empty();
        if moved {
            self.hold(&mut step, now);
        }
        self.tell(&mut step, actor, moved, lapsed);
        step
    }

    /// A client left. A prompt it was asking was taken back by the channel's
    /// client: a key touched, or the client gave up.
    fn left(&mut self, step: &mut Step, now: Now, link: Link) {
        let taken: Vec<PromptId> = self
            .asking
            .iter()
            .filter(|(_, (asker, _))| *asker == link)
            .map(|(prompt, _)| *prompt)
            .collect();
        for prompt in taken {
            self.asking.remove(&prompt);
            if self.state.prompt(prompt).is_some() {
                self.record(step, now, Event::Answered { prompt, by: None });
            }
        }
        let Some(left) = self.links.remove(&link) else {
            return;
        };
        for topic in left.lists {
            if self.lists(&topic) {
                continue;
            }
            self.answered.remove(&topic);
            if let Topic::Devices(capability) = topic
                && !self.watched.contains(&capability)
            {
                step.effects.push(Effect::Unwatch { capability });
            }
        }
        if let Some(client) = left.client {
            self.record(step, now, Event::Detached { client });
        }
    }

    /// The workstation is going to sleep, or woke. Nothing is served asleep,
    /// and a channel carried across a sleep may be dead with nothing to say
    /// so: it ends before, and one Windows did not warn of ends on waking.
    /// Either way it is opened again at once.
    fn turned(&mut self, step: &mut Step, now: Now, turn: Turn) {
        let event = match turn {
            Turn::Sleeping => Event::Sleeping,
            Turn::Woke => Event::Woke,
        };
        self.record(step, now, event);
        let live: Vec<ConnectionId> = self
            .state
            .connections()
            .map(|(connection, _)| connection)
            .collect();
        for connection in live {
            self.down(step, now, connection, ChannelEnd::Slept);
        }
    }

    /// Brings what the core holds in line with what wants it: a live channel
    /// nothing wants any more ends, one whose remote holds something else is
    /// opened again with it, every channel due is opened, and every listing
    /// due is started or, where it overran, ended.
    fn hold(&mut self, step: &mut Step, now: Now) {
        let live: Vec<(ConnectionId, RemoteId)> = self
            .state
            .connections()
            .map(|(connection, link)| (connection, link.remote.clone()))
            .collect();
        for (connection, remote) in live {
            // The person's check holds its connection until the remote has
            // answered, whatever else wants it.
            let checking = matches!(
                self.surveys.get(&connection),
                Some((_, Purpose::Check | Purpose::Withdraw))
            );
            let world = self.world();
            if world.wants(&remote).is_none() && !checking {
                self.down(step, now, connection, ChannelEnd::Closed);
            } else if self
                .opened
                .get(&connection)
                .is_some_and(|opened| *opened != world.carries(&remote))
            {
                self.down(step, now, connection, ChannelEnd::Reshaped);
            }
        }
        self.relend(step, now);
        let (due, _) = self.world().due(now.tick);
        for Open {
            remote,
            with,
            acknowledged,
            lends,
            opener,
        } in due
        {
            let added = Added {
                with,
                acknowledged,
                lends,
            };
            self.open(step, now, &remote, added, opener);
        }
        self.list(step, now);
    }

    /// Records a connection opening and asks where its far ends go.
    fn open(&mut self, step: &mut Step, now: Now, remote: &RemoteId, added: Added, opener: Opener) {
        let opening = Event::Opening {
            remote: remote.clone(),
            with: added.with,
            acknowledged: added.acknowledged,
            lends: added.lends,
            opener,
        };
        let connection = ConnectionId(self.record(step, now, opening));
        let carries = self.world().carries(remote);
        self.opened.insert(connection, carries);
        let purpose = if self.state.withdrawn().is_some() {
            Purpose::Withdraw
        } else if matches!(opener, Opener::Check(_)) {
            Purpose::Check
        } else {
            Purpose::Open
        };
        let dialect = self.dialect(connection);
        self.survey(step, now, connection, dialect, purpose);
    }

    /// The shell a survey of `connection`'s remote is asked in first: the
    /// one the platform it last reported takes.
    fn dialect(&self, connection: ConnectionId) -> Dialect {
        let last = self
            .state
            .link(connection)
            .and_then(|link| self.state.observed(&link.remote))
            .and_then(|family| self.configuration.platform(&self.catalogue, family).ok());
        Dialect::first(last)
    }

    /// Asks for readiness to run on `connection`'s remote in `dialect`.
    fn survey(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        dialect: Dialect,
        purpose: Purpose,
    ) {
        let Some(link) = self.state.link(connection) else {
            return;
        };
        let remote = link.remote.clone();
        let sources = self.keyrings_carried(connection);
        if !sources.is_empty() && !self.keyed.contains(&connection) {
            self.surveys.insert(connection, (dialect, purpose));
            step.effects.push(Effect::Read {
                connection,
                sources,
            });
            return;
        }
        let ours = match &link.phase {
            Phase::Up(serving) => serving
                .iter()
                .filter_map(|serving| match &serving.binding {
                    Binding::Socket(path) | Binding::SocketFile { file: path, .. } => {
                        Some(path.clone())
                    }
                    Binding::Port(_) => None,
                })
                .collect(),
            Phase::Opening => Vec::new(),
        };
        let Ok(client) = self
            .configuration
            .route(&self.catalogue, &remote.route)
            .map(|route| route.client.clone())
        else {
            return self.down(step, now, connection, ChannelEnd::Closed);
        };
        let carried = self.world().carried(connection).unwrap_or_default();
        let writes: Vec<(Name, Write)> = carried
            .iter()
            .flat_map(|carried| {
                carried
                    .writes
                    .iter()
                    .map(|write| (carried.capability.clone(), write.clone()))
            })
            .collect();
        // What Hedwig wrote and no consent covers any more is taken back.
        let undo = self
            .state
            .written(&remote)
            .filter(|(capability, write, _, _)| {
                !writes.contains(&((*capability).clone(), (*write).clone()))
            })
            .map(|(capability, write, place, made)| Undo {
                capability: capability.clone(),
                write: write.clone(),
                place: place.clone(),
                made: made.cloned(),
            })
            .collect();
        let asks = carried
            .into_iter()
            .map(|carried| Asked {
                questions: Question::of(&carried.forms),
                server: self
                    .configuration
                    .capability(&self.catalogue, &carried.capability)
                    .ok()
                    .and_then(|found| crate::survey::server(&found)),
                capability: carried.capability,
            })
            .collect();
        let (keys, _, armoured) = self.offered(connection);
        let (asking, keepalive) = self.asking(&remote);
        self.surveys.insert(connection, (dialect, purpose));
        step.effects.push(Effect::Survey {
            connection,
            client,
            address: remote.address,
            dialect,
            plan: Plan {
                asks,
                ours,
                keys,
                writes,
                undo,
                armoured,
                issued: None,
            },
            asking,
            keepalive,
        });
    }

    /// Whom a connection to `remote` may ask, and how its client notices a
    /// dead link: the same for a survey as for the channel after it.
    fn asking(&self, remote: &RemoteId) -> (Asking, Keepalive) {
        let world = self.world();
        let card = world.full_screen(remote).value;
        let asking = if self.state.askable(remote, &world.sets(), card) {
            Asking::Person
        } else {
            Asking::Nobody
        };
        (asking, world.keepalive(remote).value)
    }

    /// What readiness found. Each capability's findings and what readiness
    /// changed for it are recorded, and a channel is started with what can
    /// be carried, unless the survey was the person's check or a removal's.
    #[allow(clippy::too_many_lines, reason = "one arm per finding and per purpose")]
    fn surveyed(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        report: Result<Report, (Unread, Option<Words>)>,
        theirs: &[Words],
    ) {
        let Some((dialect, purpose)) = self.surveys.remove(&connection) else {
            return;
        };
        let Some(remote) = self.state.link(connection).map(|link| link.remote.clone()) else {
            return;
        };
        let (_, signers, _) = self.offered(connection);
        // The second member is whether another dialect may still answer; the
        // third, what the row says of the remote meanwhile.
        let platform = match &report {
            Ok(report) => self
                .configuration
                .platform_answering(&self.catalogue, &report.kernel)
                .cloned()
                .map_err(|refusal| (true, Some(Finding::NoProfile(refusal)))),
            Err((unread, last)) => Err((
                *unread == Unread::NotBegun,
                why(unread, last.as_ref()).map(Finding::Unsurveyed),
            )),
        };
        // A remote with no POSIX shell, or one whose POSIX shell runs on a
        // system no profile answers to, is asked again in PowerShell.
        if let (Dialect::Posix, Err((true, _))) = (dialect, &platform) {
            return self.survey(step, now, connection, Dialect::PowerShell, purpose);
        }
        // The next survey of this connection reads the keys again.
        self.keyed.remove(&connection);
        let carried = self.world().carried(connection).unwrap_or_default();
        let mut serving = Vec::new();
        if let Ok(report) = &report {
            self.wrote(step, now, connection, &remote, report);
        }
        match (report, platform) {
            (Ok(report), Ok(platform)) => {
                let observed = Event::Observed {
                    connection,
                    platform: platform.family.clone(),
                };
                self.record(step, now, observed);
                let plan = self.world().plan(connection).unwrap_or_default();
                for carried in carried {
                    let Some(Ok(form)) = plan.get(&carried.capability) else {
                        continue;
                    };
                    let answer = report
                        .answers
                        .get(&carried.capability)
                        .cloned()
                        .unwrap_or_default();
                    let placed = place(
                        &carried.capability,
                        form,
                        &platform,
                        &answer,
                        &signers,
                        theirs,
                    );
                    for prepared in placed.prepared {
                        let prepared = Event::Prepared {
                            connection,
                            capability: carried.capability.clone(),
                            prepared,
                        };
                        self.record(step, now, prepared);
                    }
                    self.checked(step, now, connection, &carried.capability, placed.readiness);
                    if let (
                        Some(Serving {
                            binding: Binding::SocketFile { .. },
                            ..
                        }),
                        Some(issued),
                    ) = (&placed.serving, report.issued)
                    {
                        self.issued.insert(connection, issued);
                    }
                    serving.extend(placed.serving);
                }
            }
            (_, Err((_, finding))) => {
                // A port fits every platform, so a capability that can be one
                // is carried without knowing which platform the remote is.
                let ports = self.world().plan_unobserved(connection).unwrap_or_default();
                for carried in carried {
                    if let Some(Ok(Form::Port(ServicePort::Fixed(port)))) =
                        ports.get(&carried.capability)
                    {
                        serving.push(Serving {
                            capability: carried.capability,
                            binding: Binding::Port(*port),
                        });
                    } else if let Some(finding) = finding.clone() {
                        let readiness = Readiness::Unready(vec![finding]);
                        self.checked(step, now, connection, &carried.capability, readiness);
                    }
                }
            }
            (Err(_), Ok(_)) => {}
        }
        match purpose {
            Purpose::Recheck => {}
            Purpose::Withdraw => self.down(step, now, connection, ChannelEnd::Closed),
            Purpose::Check if self.world().wants(&remote).is_none() => {
                self.down(step, now, connection, ChannelEnd::Closed);
            }
            Purpose::Check | Purpose::Open => self.placed(step, now, connection, serving),
        }
        self.reseal(step, connection);
    }

    /// A survey of a live channel opened Hedwig's private folder to place
    /// what it found; the channel's forwards are bound there still, so the
    /// survey seals it again.
    fn reseal(&self, step: &mut Step, connection: ConnectionId) {
        if self
            .channels
            .get(&connection)
            .is_some_and(|channel| channel.pending.is_empty() && !channel.bound.is_empty())
        {
            step.effects.push(Effect::Seal { connection });
        }
    }

    /// Records what Hedwig wrote on the remote and took back, and what it
    /// found still there that its record had lost.
    fn wrote(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        remote: &RemoteId,
        report: &Report,
    ) {
        let place =
            |bytes: &[u8]| RemotePath::try_from(String::from_utf8_lossy(bytes).as_ref()).ok();
        for (capability, answer) in &report.answers {
            for (write, at) in &answer.unwrote {
                if let Some(place) = place(at) {
                    let unwrote = Event::Unwrote {
                        connection,
                        capability: capability.clone(),
                        write: write.clone(),
                        place,
                    };
                    self.record(step, now, unwrote);
                }
            }
            let listed: Vec<(Write, RemotePath)> = self
                .state
                .written(remote)
                .filter(|(of, _, _, _)| *of == capability)
                .map(|(_, write, place, _)| (write.clone(), place.clone()))
                .collect();
            let fresh = answer
                .wrote
                .iter()
                .map(|(write, at, made)| (write, at, made.as_deref(), true));
            let found = answer
                .kept
                .iter()
                .map(|(write, at)| (write, at, None, false));
            for (write, at, made, fresh) in fresh.chain(found) {
                let Some(place) = place(at) else {
                    continue;
                };
                if fresh || !listed.contains(&(write.clone(), place.clone())) {
                    let wrote = Event::Wrote {
                        connection,
                        capability: capability.clone(),
                        write: write.clone(),
                        place,
                        made: made.and_then(|made| {
                            RemotePath::try_from(String::from_utf8_lossy(made).as_ref()).ok()
                        }),
                    };
                    self.record(step, now, wrote);
                }
            }
        }
    }

    /// The sixteen bytes a Windows remote's socket file was written with on
    /// `connection`, which a connection through its forward presents.
    pub fn issued(&self, connection: ConnectionId) -> Option<&[u8; 16]> {
        self.issued.get(&connection)
    }

    /// The `GnuPG` source of `capability`, where it has one.
    fn gnupg(&self, capability: &Name) -> Option<Gnupg> {
        match self.configuration.capability(&self.catalogue, capability) {
            Ok(found) => match found.source {
                Source::Gnupg {
                    installation,
                    home,
                    access,
                } => Some(Gnupg {
                    installation,
                    home,
                    access,
                }),
                Source::Agent { .. }
                | Source::Service { .. }
                | Source::Browser { .. }
                | Source::Serial { .. }
                | Source::Credentials { .. }
                | Source::Notices => None,
            },
            Err(_) => None,
        }
    }

    /// The `GnuPG` capabilities `connection`'s remote holds, with their
    /// sources.
    fn gnupg_carried(&self, connection: ConnectionId) -> Vec<(Name, Gnupg)> {
        self.world()
            .carried(connection)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|carried| {
                Some((carried.capability.clone(), self.gnupg(&carried.capability)?))
            })
            .collect()
    }

    /// Every capability `connection`'s remote holds whose source has a
    /// keyring the core reads: a `GnuPG` capability's, and gpg-agent's SSH
    /// socket's, whose keys are the same and which an SSH request names by
    /// their public half.
    fn keyrings_carried(&self, connection: ConnectionId) -> Vec<(Name, Gnupg)> {
        self.world()
            .carried(connection)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|carried| {
                let source = self.keyring_source(&carried.capability)?;
                Some((carried.capability.clone(), source))
            })
            .collect()
    }

    /// The `GnuPG` whose keyring `capability`'s requests name keys from.
    fn keyring_source(&self, capability: &Name) -> Option<Gnupg> {
        if let Some(gnupg) = self.gnupg(capability) {
            return Some(gnupg);
        }
        match self.configuration.capability(&self.catalogue, capability) {
            Ok(Capability {
                source:
                    Source::Agent {
                        at: AgentAt::Gnupg { installation, home },
                    },
                ..
            }) => Some(Gnupg {
                installation,
                home,
                access: Access::Restricted,
            }),
            _ => None,
        }
    }

    /// What the `GnuPG` capabilities `connection`'s remote holds offer: each
    /// key by its primary fingerprint, every fingerprint a signing key may be
    /// named by, and the armour of each.
    fn offered(
        &self,
        connection: ConnectionId,
    ) -> (
        Vec<Fingerprint>,
        Vec<Fingerprint>,
        BTreeMap<Fingerprint, String>,
    ) {
        let (mut keys, mut signers, mut armoured) = (Vec::new(), Vec::new(), BTreeMap::new());
        for (capability, _) in self.gnupg_carried(connection) {
            let Some(keyring) = self.state.offered(&capability) else {
                continue;
            };
            for key in keyring.primaries() {
                if let Some(block) = self.armoured.get(&key) {
                    armoured.insert(key.clone(), block.clone());
                }
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
            for signer in keyring.signers() {
                if !signers.contains(&signer) {
                    signers.push(signer);
                }
            }
        }
        (keys, signers, armoured)
    }

    /// What the sources offer, read before a survey or again for a request:
    /// recorded where it changed; then the survey run with it, and each
    /// request that waited on it decided.
    fn read(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        read: Vec<(Name, Result<Read, Failure>)>,
    ) {
        let mut waited = Vec::new();
        for (capability, found) in read {
            self.sought.retain(|(of, _)| *of != capability);
            for (knock, operation, key, payload) in
                self.rereading.remove(&capability).unwrap_or_default()
            {
                self.sought.insert((capability.clone(), key.clone()));
                waited.push((knock, operation, key, payload));
            }
            let health = match found {
                Ok(Read {
                    keyring,
                    armoured,
                    cards,
                }) => {
                    if self.state.offered(&capability) != Some(&keyring) {
                        let offered = Event::Offered {
                            capability: capability.clone(),
                            keyring,
                        };
                        self.record(step, now, offered);
                    }
                    self.armoured.extend(armoured);
                    self.known_cards(step, now, cards);
                    Health::Sound
                }
                Err(failure) => Health::Failing(failure),
            };
            self.source(step, now, &capability, health);
        }
        for (knock, operation, key, payload) in waited {
            self.ask_with(step, now, knock, operation, Some(key), payload);
        }
        let Some((dialect, purpose)) = self.surveys.remove(&connection) else {
            return;
        };
        self.keyed.insert(connection);
        self.survey(step, now, connection, dialect, purpose);
    }

    /// Asks for `capability`'s source to be read again, answered as a read
    /// for `connection` is; `false` for a source with no keyring to read.
    fn reread(&self, step: &mut Step, connection: ConnectionId, capability: &Name) -> bool {
        let Some(source) = self.keyring_source(capability) else {
            return false;
        };
        step.effects.push(Effect::Read {
            connection,
            sources: vec![(capability.clone(), source)],
        });
        true
    }

    /// Records each card a reading changes what the core knows of: one never
    /// read, or one whose reading again says something new.
    fn known_cards(&mut self, step: &mut Step, now: Now, cards: Vec<Card>) {
        for card in cards {
            let changed = self
                .state
                .card(&card.serial)
                .is_none_or(|known| known.read_again(&card) != *known);
            if changed {
                self.record(step, now, Event::Card(card));
            }
        }
    }

    /// Asks for `capability`'s source's cards to be read again, unless a
    /// reading begun since its last card use is under way; `false` for a
    /// source with no keyring to read.
    fn read_cards(&mut self, step: &mut Step, connection: ConnectionId, capability: &Name) -> bool {
        let Some(source) = self.keyring_source(capability) else {
            return false;
        };
        let uses = self
            .cards_stale
            .get(capability)
            .copied()
            .unwrap_or_default();
        if self.cards_reading.get(capability) != Some(&uses) {
            self.cards_reading.insert(capability.clone(), uses);
            step.effects.push(Effect::Cards {
                connection,
                sources: vec![(capability.clone(), source)],
            });
        }
        true
    }

    /// The cards a source's scdaemon holds, read after a card was used:
    /// recorded where they changed, no longer stale unless a card was used
    /// again after the reading began, and each request waiting on them
    /// decided on them. A reading that failed leaves the cards as they were.
    fn cards(&mut self, step: &mut Step, now: Now, read: Vec<(Name, Result<Vec<Card>, Failure>)>) {
        for (capability, found) in read {
            let began = self.cards_reading.remove(&capability);
            if let Ok(cards) = found {
                self.known_cards(step, now, cards);
            }
            if began.is_some() && began == self.cards_stale.get(&capability).copied() {
                self.cards_stale.remove(&capability);
            }
            for (knock, operation, key, payload) in
                self.cards_waiting.remove(&capability).unwrap_or_default()
            {
                self.decide_now(step, now, knock, operation, Some(key), payload);
            }
        }
    }

    /// Whether `grip` is on a card: the source's keyring places it on one by
    /// the agent's stub, or a card the core has read holds it.
    fn on_card(&self, capability: &Name, grip: &Grip) -> bool {
        self.state
            .offered(capability)
            .and_then(|keyring| keyring.by_grip(grip))
            .is_some_and(|key| key.card.is_some())
            || self.state.keys().any(|held| held == grip)
    }

    /// Whether some reading of `capability`'s source accounts for `key`: a
    /// key it offers by that keygrip or SSH public half, a card the core has
    /// read, or a reading since the request that named it, which then names
    /// a key the source offers no more of than that.
    fn accounted(&self, capability: &Name, key: &KeyId) -> bool {
        let keyring = self.state.offered(capability);
        let offered = match key {
            KeyId::Grip(grip) => {
                keyring.is_some_and(|keyring| keyring.by_grip(grip).is_some())
                    || self.state.keys().any(|held| held == grip)
            }
            KeyId::Ssh(ssh) => keyring.is_some_and(|keyring| keyring.by_ssh(ssh).is_some()),
        };
        offered || self.sought.contains(&(capability.clone(), key.clone()))
    }

    /// Records how the workstation's side of `capability` answered, where
    /// that changed.
    fn source(&mut self, step: &mut Step, now: Now, capability: &Name, health: Health) {
        if self.state.source(capability) != Some(health) {
            let source = Event::Source {
                capability: capability.clone(),
                health,
            };
            self.record(step, now, source);
        }
    }

    /// What carries `connection`'s connection to `capability`: the relay of a
    /// `GnuPG` source, of a service whose stream is opaque, or of an ADB
    /// server, given the reverses that server's capability has carried on to
    /// the connection's remote.
    /// `None` for what nothing serves yet - the core's own SSH agent - and
    /// for a port the source leaves unstated, which no grant reaches.
    fn relaying(&self, connection: ConnectionId, capability: &Name) -> Option<Relaying> {
        let found = self
            .configuration
            .capability(&self.catalogue, capability)
            .ok()?;
        match found.source {
            Source::Gnupg {
                installation,
                home,
                access,
            } => Some(Relaying::Gnupg(Gnupg {
                installation,
                home,
                access,
            })),
            Source::Service {
                host,
                port: ServicePort::Fixed(port),
                stream: Stream::Opaque,
                ..
            } => Some(Relaying::Service(Service { host, port })),
            Source::Service {
                host,
                port: ServicePort::Fixed(port),
                stream: Stream::Adb,
                ..
            } => {
                let link = self.state.link(connection)?;
                let mut carried = crate::adb::Carried::default();
                for (carriage, endpoint) in self
                    .state
                    .carried(&link.remote, capability)
                    .into_iter()
                    .flatten()
                {
                    match carriage {
                        Carriage::Reverse(target) => {
                            carried.reverses.push((*endpoint, target.clone()));
                        }
                        Carriage::Forward {
                            port,
                            device,
                            socket,
                        } => carried.forwards.push(crate::adb::Forward {
                            port: *port,
                            server: *endpoint,
                            device: device.clone(),
                            socket: socket.clone(),
                        }),
                        Carriage::Console { .. } => {}
                    }
                }
                let (lends, network) = self.world().lending(link, capability)?;
                Some(Relaying::Adb {
                    service: Service { host, port },
                    carried,
                    lending: crate::adb::Lending { lends, network },
                })
            }
            Source::Browser { browser, .. } => Some(Relaying::Browse(Browse { browser })),
            Source::Serial { port, .. } => Some(Relaying::Serial(Serial { port })),
            Source::Credentials { git, .. } => {
                Some(Relaying::Credential(crate::credential::Credential { git }))
            }
            Source::Notices => Some(Relaying::Notify),
            Source::Agent { at } => {
                let link = self.state.link(connection)?;
                let (lends, _) = self.world().lending(link, capability)?;
                Some(Relaying::Agent(crate::ssh::SshAgent { at, lends }))
            }
            Source::Service { .. } => None,
        }
    }

    /// Records what holds `capability`'s source, where that changed.
    fn held(&mut self, step: &mut Step, now: Now, capability: &Name, holder: Option<SourceHolder>) {
        if self.state.held_by(capability) != Some(holder.as_ref()) {
            let held = Event::HeldBy {
                capability: capability.clone(),
                holder,
            };
            self.record(step, now, held);
        }
    }

    /// Hands an admitted connection to what serves its capability; one that
    /// nothing serves is closed with nothing written to it.
    fn relay(&mut self, step: &mut Step, knock: Knock, connection: ConnectionId, capability: Name) {
        let Some(source) = self.relaying(connection, &capability) else {
            step.effects.push(Effect::Refuse { knock });
            return;
        };
        let presents = self
            .state
            .link(connection)
            .and_then(|link| match &link.phase {
                Phase::Up(serving) => serving
                    .iter()
                    .find(|serving| serving.capability == capability)
                    .and_then(|serving| match (&source, &serving.binding) {
                        (Relaying::Gnupg(_), Binding::SocketFile { .. }) => {
                            self.issued.get(&connection).copied()
                        }
                        _ => None,
                    }),
                Phase::Opening => None,
            });
        let lending = match &source {
            Relaying::Adb { lending, .. } => Some(lending.clone()),
            Relaying::Agent(agent) => Some(crate::adb::Lending {
                lends: agent.lends.clone(),
                network: false,
            }),
            _ => None,
        };
        let port = match &source {
            Relaying::Serial(serial) => Some(Taking {
                port: serial.port.clone(),
                opening: None,
                taken: false,
            }),
            _ => None,
        };
        self.streams.insert(
            knock,
            Streamed {
                connection,
                capability: capability.clone(),
                request: None,
                opened: None,
                calling: false,
                asking_card: false,
                used_card: false,
                lending,
                port,
                served: None,
            },
        );
        step.effects.push(Effect::Relay {
            knock,
            connection,
            capability,
            source,
            presents,
        });
    }

    /// What a relayed connection says.
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per thing a relay tells, each recorded or carried out"
    )]
    fn relayed(&mut self, step: &mut Step, now: Now, knock: Knock, relayed: Relayed) {
        let Some(streamed) = self.streams.get(&knock).cloned() else {
            return;
        };
        let remote = self
            .state
            .link(streamed.connection)
            .map(|link| link.remote.clone());
        match relayed {
            Relayed::Unpresented => {
                let refusal = Refusal::Unissued;
                self.record(step, now, Event::TurnedAway { remote, refusal });
            }
            Relayed::Reached(Ok(())) => {
                // A server read as outdated is so until its watch lists its
                // devices, however many connections reach it meanwhile.
                let outdated = Some(Health::Failing(Failure::Outdated));
                if self.state.source(&streamed.capability) != outdated {
                    self.source(step, now, &streamed.capability, Health::Sound);
                }
                self.ask(step, now, knock, Operation::Connect, None);
            }
            Relayed::Reached(Err(failure)) => {
                let capability = streamed.capability.clone();
                self.source(step, now, &capability, Health::Failing(failure));
                let asked = Core::asked_event(&streamed, Operation::Connect, None);
                let request = RequestId(self.record(step, now, asked));
                let refusal = Refusal::SourceUnavailable {
                    capability,
                    failure,
                };
                self.record(
                    step,
                    now,
                    Event::Settled {
                        request,
                        outcome: Outcome::Refused(refusal.clone()),
                    },
                );
                step.effects.push(Effect::Settle {
                    knock,
                    verdict: Err(refusal),
                });
            }
            Relayed::Asks(ask) => {
                self.ask(step, now, knock, ask.operation, ask.key.map(KeyId::Grip));
            }
            Relayed::Signs(ask) => {
                let key = Some(KeyId::Ssh(ask.key));
                self.ask_with(step, now, knock, ask.operation, key, Some(ask.payload));
            }
            Relayed::Strayed(breach) => match breach {
                crate::agent::Breach::TooLong(crate::agent::Side::Client)
                | crate::agent::Breach::Empty(crate::agent::Side::Client)
                | crate::agent::Breach::Cut(crate::agent::Side::Client)
                | crate::agent::Breach::Malformed => {
                    let refusal = Refusal::OffProtocol {
                        capability: streamed.capability.clone(),
                        account: words(&breach.to_string())
                            .unwrap_or_else(|| unreachable!("the breach is worded")),
                    };
                    self.record(step, now, Event::TurnedAway { remote, refusal });
                }
                crate::agent::Breach::TooLong(crate::agent::Side::Agent)
                | crate::agent::Breach::Empty(crate::agent::Side::Agent)
                | crate::agent::Breach::Cut(crate::agent::Side::Agent)
                | crate::agent::Breach::OutOfTurn
                | crate::agent::Breach::NotAnswer => {
                    let failing = Health::Failing(Failure::Mismatched);
                    self.source(step, now, &streamed.capability, failing);
                }
            },
            Relayed::Held(holder) => self.held(step, now, &streamed.capability, holder),
            Relayed::Breached(breach) => match breach {
                Breach::TooLong(crate::assuan::Side::Client)
                | Breach::OutOfTurn(crate::assuan::Side::Client)
                | Breach::Cut(crate::assuan::Side::Client) => {
                    let refusal = Refusal::OffProtocol {
                        capability: streamed.capability.clone(),
                        account: words(&breach.to_string())
                            .unwrap_or_else(|| unreachable!("the breach is worded")),
                    };
                    self.record(step, now, Event::TurnedAway { remote, refusal });
                }
                Breach::TooLong(crate::assuan::Side::Agent)
                | Breach::OutOfTurn(crate::assuan::Side::Agent)
                | Breach::Cut(crate::assuan::Side::Agent)
                | Breach::NotAnswer => {
                    let failing = Health::Failing(Failure::Mismatched);
                    self.source(step, now, &streamed.capability, failing);
                }
            },
            Relayed::Misframed(breach) => self.misframed(step, now, &streamed, remote, breach),
            Relayed::Withheld(request) => {
                let refusal = Refusal::Withheld {
                    capability: streamed.capability.clone(),
                    request,
                };
                self.record(step, now, Event::TurnedAway { remote, refusal });
            }
            // What a lending change ends is told to the connection itself.
            Relayed::Selected(_) => {}
            Relayed::Forward { port, .. } => self.forward(step, now, knock, &streamed, port),
            Relayed::Forwarded {
                forward,
                replaced,
                id,
            } => self.forwarded_on(step, now, knock, &streamed, forward, replaced, id),
            Relayed::Unplaced(port) => {
                self.unplace(step, &streamed, port);
            }
            Relayed::Unforwarded(port) => {
                self.unforwarded(step, now, &streamed, port, Dropped::Removed);
            }
            Relayed::Reverse(target) => self.reverse(step, now, knock, &streamed, target),
            browsing @ (Relayed::Misread(_)
            | Relayed::Opens { .. }
            | Relayed::Browsed(_)
            | Relayed::Called
            | Relayed::Expired) => self.browsing(step, now, knock, &streamed, remote, browsing),
            Relayed::Reversed { target, endpoint } => {
                self.reversed(step, now, &streamed, target, endpoint);
            }
            asking @ (Relayed::Misasked(_)
            | Relayed::Erased(_)
            | Relayed::Wants(_)
            | Relayed::Gave(_)) => self.crediting(step, now, knock, &streamed, remote, asking),
            Relayed::Says(remark) => self.noticing(step, now, knock, &streamed, remote, remark),
            Relayed::Opened(opened) => self.opened(step, now, knock, &streamed, opened),
            Relayed::Broke(breach) => {
                let refusal = Refusal::OffProtocol {
                    capability: streamed.capability.clone(),
                    account: words(&breach.to_string())
                        .unwrap_or_else(|| unreachable!("the breach is worded")),
                };
                self.record(step, now, Event::TurnedAway { remote, refusal });
            }
            Relayed::Lost(failure) => {
                self.source(step, now, &streamed.capability, Health::Failing(failure));
            }
            Relayed::Released => {
                if let Some(Taking {
                    opening: Some(request),
                    taken: true,
                    ..
                }) = streamed.port
                {
                    self.record(step, now, Event::Released { request });
                }
                if let Some(held) = self.streams.get_mut(&knock) {
                    held.port = None;
                }
            }
            Relayed::Ended => {
                let ended = self.streams.remove(&knock);
                if let Some(ended) = ended.as_ref().filter(|ended| {
                    ended.used_card && self.cards_stale.contains_key(&ended.capability)
                }) {
                    self.read_cards(step, ended.connection, &ended.capability);
                }
                if let Some(request) = ended.and_then(|ended| ended.request)
                    && self.state.ask(request).is_some()
                {
                    self.record(
                        step,
                        now,
                        Event::Settled {
                            request,
                            outcome: Outcome::Abandoned,
                        },
                    );
                }
            }
        }
    }

    /// A served serial connection's port was opened, and is held for it
    /// from here; or it could not be, and the source says why.
    fn opened(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        streamed: &Streamed,
        opened: Result<Option<hedwig_model::protocol::Usb>, Failure>,
    ) {
        let capability = &streamed.capability;
        match (opened, &streamed.port) {
            (
                Ok(usb),
                Some(Taking {
                    port,
                    opening: Some(request),
                    ..
                }),
            ) => {
                self.source(step, now, capability, Health::Sound);
                let taken = Event::Taken {
                    request: *request,
                    connection: streamed.connection,
                    capability: capability.clone(),
                    port: port.clone(),
                    usb,
                };
                self.record(step, now, taken);
                if let Some(taking) = self
                    .streams
                    .get_mut(&knock)
                    .and_then(|held| held.port.as_mut())
                {
                    taking.taken = true;
                }
            }
            (Err(failure), ..) => self.source(step, now, capability, Health::Failing(failure)),
            (Ok(_), ..) => {}
        }
    }

    /// An end broke ADB's rules: the remote is turned away, or the
    /// workstation's server marked as failing.
    fn misframed(
        &mut self,
        step: &mut Step,
        now: Now,
        streamed: &Streamed,
        remote: Option<RemoteId>,
        breach: crate::adb::Breach,
    ) {
        use crate::adb::{Breach as Misframed, Side};
        if let Misframed::NotAnswer
        | Misframed::LongAnswer
        | Misframed::OutOfTurn(Side::Server)
        | Misframed::Cut(Side::Server) = breach
        {
            let failing = Health::Failing(Failure::Mismatched);
            self.source(step, now, &streamed.capability, failing);
        } else {
            let refusal = Refusal::OffProtocol {
                capability: streamed.capability.clone(),
                account: words(&breach.to_string())
                    .unwrap_or_else(|| unreachable!("the breach is worded")),
            };
            self.record(step, now, Event::TurnedAway { remote, refusal });
        }
    }

    /// A reverse a relayed ADB connection holds: given the endpoint its
    /// remote has for the target, or one bound now, unless the remote has as
    /// many as it may.
    fn reverse(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        streamed: &Streamed,
        target: Target,
    ) {
        let Some(remote) = self
            .state
            .link(streamed.connection)
            .map(|link| link.remote.clone())
        else {
            return;
        };
        let Some(Relaying::Adb {
            service: server, ..
        }) = self.relaying(streamed.connection, &streamed.capability)
        else {
            return;
        };
        let asked = (streamed.capability.clone(), Slot::Reverse(target.clone()));
        if self.crowded(step, now, knock, &remote, &asked) {
            return;
        }
        self.carrying
            .entry(remote.clone())
            .or_default()
            .insert(asked);
        let capability = streamed.capability.clone();
        step.effects.push(Effect::Endpoint {
            knock,
            reverse: Reverse {
                remote,
                capability,
                target,
            },
            server,
        });
    }

    /// What the credential relay says of a connection.
    fn crediting(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        streamed: &Streamed,
        remote: Option<RemoteId>,
        relayed: Relayed,
    ) {
        let capability = &streamed.capability;
        match relayed {
            Relayed::Misasked(unread) => {
                let refusal = Refusal::OffProtocol {
                    capability: capability.clone(),
                    account: words(&unread.to_string())
                        .unwrap_or_else(|| unreachable!("what was not read is worded")),
                };
                self.record(step, now, Event::TurnedAway { remote, refusal });
            }
            // Only a refusal of a site the capability answers for is the
            // forge's word on what Hedwig released; any other is another
            // helper's.
            Relayed::Erased(Place::Site(url)) => {
                let listed = match self.configuration.capability(&self.catalogue, capability) {
                    Ok(Capability {
                        source: Source::Credentials { sites, .. },
                        ..
                    }) => sites.iter().any(|site| site.admits(&url)),
                    _ => false,
                };
                if listed {
                    let refuted = Event::Refuted {
                        connection: streamed.connection,
                        capability: capability.clone(),
                        site: Site::of(&url),
                    };
                    self.record(step, now, refuted);
                }
            }
            Relayed::Wants(place) => self.asks_credential(step, now, knock, &place),
            Relayed::Gave(release) => match release {
                crate::credential::Release::Given => {
                    self.source(step, now, capability, Health::Sound);
                }
                crate::credential::Release::Nothing => {
                    self.source(step, now, capability, Health::Sound);
                    if let Some(request) = streamed.served {
                        self.record(step, now, Event::Unreleased { request });
                    }
                }
                crate::credential::Release::Gone => {}
                crate::credential::Release::Failed(failure) => {
                    self.source(step, now, capability, Health::Failing(failure));
                }
            },
            _ => {}
        }
    }

    /// A remote's `git` asks for a credential for `place`: decided by the one
    /// gate, recorded with the site it is for and never with the secret.
    fn asks_credential(&mut self, step: &mut Step, now: Now, knock: Knock, place: &Place) {
        let Some(streamed) = self.streams.get(&knock).cloned() else {
            return;
        };
        let verdict =
            self.world()
                .credential(streamed.connection, &streamed.capability, place, now.tick);
        let asked = Core::asked_event(&streamed, Operation::Connect, None);
        let request = RequestId(self.record(step, now, asked));
        if let Place::Site(url) = place {
            let payload = Payload::Credential {
                site: Site::of(url),
            };
            self.record(step, now, Event::Payload { request, payload });
        }
        if let Some(held) = self.streams.get_mut(&knock) {
            held.request = Some(request);
        }
        match verdict {
            Verdict::Serve(outcome) => self.settle(step, now, request, outcome),
            Verdict::Refuse(refusal) => {
                self.settle(step, now, request, Outcome::Refused(refusal));
            }
            Verdict::Hold(_) => {
                self.record(step, now, Event::Held { request });
            }
        }
    }

    /// A remote's job tells the person `remark`: kept, as that remote's
    /// words, unless the gate refuses it; one that comes too fast is counted
    /// and said with the next kept, never recorded on its own.
    fn noticing(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        streamed: &Streamed,
        remote: Option<RemoteId>,
        remark: hedwig_model::text::Remark,
    ) {
        let verdict = self
            .world()
            .notice(streamed.connection, &streamed.capability, now.tick);
        match &verdict {
            Ok(()) => {
                let unheard = remote
                    .as_ref()
                    .and_then(|remote| self.hushed.remove(remote))
                    .unwrap_or(0);
                let noticed = Event::Noticed {
                    connection: streamed.connection,
                    capability: streamed.capability.clone(),
                    remark,
                    unheard,
                };
                self.record(step, now, noticed);
            }
            Err(Refusal::Hushed { .. }) => {
                if let Some(remote) = remote {
                    let count = self.hushed.entry(remote).or_insert(0);
                    *count = count.saturating_add(1);
                }
            }
            Err(refusal) => {
                let refusal = refusal.clone();
                self.record(step, now, Event::TurnedAway { remote, refusal });
            }
        }
        step.effects.push(Effect::Settle { knock, verdict });
    }

    /// What the browser relay says of a connection.
    fn browsing(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        streamed: &Streamed,
        remote: Option<RemoteId>,
        relayed: Relayed,
    ) {
        match relayed {
            Relayed::Misread(malformed) => {
                let refusal = Refusal::OffProtocol {
                    capability: streamed.capability.clone(),
                    account: words(&malformed.to_string())
                        .unwrap_or_else(|| unreachable!("the malformation is worded")),
                };
                self.record(step, now, Event::TurnedAway { remote, refusal });
            }
            Relayed::Opens { asked, held } => self.asks_open(step, now, knock, &asked, held),
            Relayed::Browsed(Ok(())) => self.browsed(step, now, knock, streamed),
            Relayed::Browsed(Err(failure)) => {
                self.source(step, now, &streamed.capability, Health::Failing(failure));
            }
            Relayed::Called => self.uncarried(step, now, knock, Carry::Called),
            Relayed::Expired => self.uncarried(step, now, knock, Carry::Expired),
            _ => {}
        }
    }

    /// A remote's `curl` asks the browser to open `asked`: decided by the one
    /// gate, a callback port another program holds refused before anything
    /// else is done, and recorded without the URL.
    fn asks_open(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        asked: &str,
        held: Option<Port>,
    ) {
        let Some(streamed) = self.streams.get(&knock).cloned() else {
            return;
        };
        let (verdict, opening) =
            self.world()
                .open(streamed.connection, &streamed.capability, asked, now.tick);
        let verdict = match (verdict, held) {
            (Verdict::Refuse(refusal), _) => Verdict::Refuse(refusal),
            (_, Some(port)) => Verdict::Refuse(Refusal::CallbackHeld {
                capability: streamed.capability.clone(),
                port,
            }),
            (verdict, None) => verdict,
        };
        let asked = Core::asked_event(&streamed, Operation::Open, None);
        let request = RequestId(self.record(step, now, asked));
        if let Some(held) = self.streams.get_mut(&knock) {
            held.request = Some(request);
            held.opened = opening.map(|opening| (request, opening));
        }
        match verdict {
            Verdict::Serve(outcome) => self.settle(step, now, request, outcome),
            Verdict::Refuse(refusal) => {
                self.settle(step, now, request, Outcome::Refused(refusal));
            }
            Verdict::Hold(_) => {
                self.record(step, now, Event::Held { request });
            }
        }
    }

    /// The browser was given the served URL: recorded with the site it leads
    /// to and the port its callback comes back to, which is carried on to the
    /// remote through its channel.
    fn browsed(&mut self, step: &mut Step, now: Now, knock: Knock, streamed: &Streamed) {
        self.source(step, now, &streamed.capability, Health::Sound);
        let Some((request, opening)) = streamed.opened.clone() else {
            return;
        };
        let browsed = Event::Browsed {
            request,
            site: Site::of(&opening.url),
            callback: opening.callback.as_ref().map(|callback| callback.port),
        };
        self.record(step, now, browsed);
        let Some(callback) = opening.callback else {
            return;
        };
        let Some(remote) = self
            .state
            .link(streamed.connection)
            .map(|link| link.remote.clone())
        else {
            return;
        };
        let Ok(client) = self
            .configuration
            .route(&self.catalogue, &remote.route)
            .map(|route| route.client.clone())
        else {
            return;
        };
        let (asking, keepalive) = self.asking(&remote);
        let target = if callback.host.as_str() == "localhost" {
            Target::Loopback(callback.port)
        } else {
            Target::Host {
                host: callback.host,
                port: callback.port,
            }
        };
        if let Some(held) = self.streams.get_mut(&knock) {
            held.calling = true;
        }
        step.effects.push(Effect::Call {
            knock,
            connection: streamed.connection,
            client,
            address: remote.address,
            target,
            asking,
            keepalive,
        });
    }

    /// A callback is no longer carried, and why: recorded, and its carrier
    /// ended.
    fn uncarried(&mut self, step: &mut Step, now: Now, knock: Knock, end: Carry) {
        let Some(held) = self.streams.get_mut(&knock).filter(|held| held.calling) else {
            return;
        };
        held.calling = false;
        let Some((request, _)) = held.opened.clone() else {
            return;
        };
        self.record(step, now, Event::Uncarried { request, end });
        step.effects.push(Effect::Uncall { knock });
    }

    /// The device took a reverse: recorded where it is new, and carried on
    /// to the remote through its channel.
    fn reversed(
        &mut self,
        step: &mut Step,
        now: Now,
        streamed: &Streamed,
        target: Target,
        endpoint: Port,
    ) {
        let Some(remote) = self
            .state
            .link(streamed.connection)
            .map(|link| link.remote.clone())
        else {
            return;
        };
        let carriage = Carriage::Reverse(target.clone());
        let known = self
            .state
            .carried(&remote, &streamed.capability)
            .and_then(|carried| carried.get(&carriage))
            == Some(&endpoint);
        if !known {
            let carried = Event::Carried {
                connection: streamed.connection,
                capability: streamed.capability.clone(),
                carriage,
                endpoint,
            };
            self.record(step, now, carried);
        }
        let reverse = Reverse {
            remote,
            capability: streamed.capability.clone(),
            target,
        };
        self.haul(step, streamed.connection, reverse);
    }

    /// Whether `asked` would carry more on to `remote` than it may have:
    /// where it would, the held request is refused and the refusal recorded.
    fn crowded(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        remote: &RemoteId,
        asked: &(Name, Slot),
    ) -> bool {
        let given = self.carrying.get(remote);
        let known = given.is_some_and(|given| given.contains(asked));
        if known || given.map_or(0, BTreeSet::len) < crate::adb::CARRIED {
            return false;
        }
        let withheld = Withheld::Crowded;
        let refusal = Refusal::Withheld {
            capability: asked.0.clone(),
            request: withheld.clone(),
        };
        self.record(
            step,
            now,
            Event::TurnedAway {
                remote: Some(remote.clone()),
                refusal,
            },
        );
        step.effects.push(Effect::Withhold { knock, withheld });
        true
    }

    /// What a carrier for `remote`'s channel `connection` is started with.
    fn carrier(&self, connection: ConnectionId, remote: &RemoteId) -> Option<Carrier> {
        let client = self
            .configuration
            .route(&self.catalogue, &remote.route)
            .ok()?
            .client
            .clone();
        let (asking, keepalive) = self.asking(remote);
        Some(Carrier {
            connection,
            client,
            address: remote.address.clone(),
            asking,
            keepalive,
        })
    }

    /// The server an ADB capability names.
    fn server(&self, capability: &Name) -> Option<Service> {
        let found = self
            .configuration
            .capability(&self.catalogue, capability)
            .ok()?;
        match found.source {
            Source::Service {
                host,
                port: ServicePort::Fixed(port),
                stream: Stream::Adb,
                ..
            } => Some(Service { host, port }),
            _ => None,
        }
    }

    /// A forward a relayed ADB connection holds: placed on the remote,
    /// unless the remote has as much carried as it may.
    fn forward(&mut self, step: &mut Step, now: Now, knock: Knock, streamed: &Streamed, port: u16) {
        let Some(remote) = self
            .state
            .link(streamed.connection)
            .map(|link| link.remote.clone())
        else {
            return;
        };
        let slot = match Port::try_from(port) {
            Ok(port) => Slot::Forward(port),
            Err(_) => Slot::Placing(knock),
        };
        let asked = (streamed.capability.clone(), slot);
        if self.crowded(step, now, knock, &remote, &asked) {
            return;
        }
        let (Some(server), Some(carrier)) = (
            self.server(&streamed.capability),
            self.carrier(streamed.connection, &remote),
        ) else {
            return;
        };
        self.carrying
            .entry(remote.clone())
            .or_default()
            .insert(asked);
        step.effects.push(Effect::Place {
            knock,
            remote,
            capability: streamed.capability.clone(),
            port,
            server,
            carrier,
        });
    }

    /// The server took a forward: recorded, with the one it replaced
    /// dropped, and its endpoint given the server's listener once the record
    /// is written, which is when the remote is answered.
    #[allow(
        clippy::too_many_arguments,
        reason = "what the relay told, and where it came from"
    )]
    fn forwarded_on(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        streamed: &Streamed,
        forward: crate::adb::Forward,
        replaced: Option<crate::adb::Forward>,
        id: u64,
    ) {
        let Some(remote) = self
            .state
            .link(streamed.connection)
            .map(|link| link.remote.clone())
        else {
            return;
        };
        let capability = streamed.capability.clone();
        if let Some(carrying) = self.carrying.get_mut(&remote) {
            carrying.remove(&(capability.clone(), Slot::Placing(knock)));
            carrying.insert((capability.clone(), Slot::Forward(forward.port)));
        }
        if let Some(replaced) = replaced {
            let dropped = Event::Dropped {
                connection: streamed.connection,
                capability: capability.clone(),
                carriage: Carriage::Forward {
                    port: replaced.port,
                    device: replaced.device,
                    socket: replaced.socket,
                },
                why: Dropped::Removed,
            };
            self.record(step, now, dropped);
        }
        self.forwarded.insert(
            (remote.clone(), capability.clone(), forward.port),
            (streamed.connection, id),
        );
        let carried = Event::Carried {
            connection: streamed.connection,
            capability: capability.clone(),
            carriage: Carriage::Forward {
                port: forward.port,
                device: forward.device,
                socket: forward.socket,
            },
            endpoint: forward.server,
        };
        self.record(step, now, carried);
        step.effects.push(Effect::Listen {
            knock,
            forwarding: crate::adb::Forwarding {
                remote,
                capability,
                port: forward.port,
            },
            listener: forward.server,
        });
    }

    /// A forward placed on the remote that the server refused: its carrier
    /// ends and its place is free.
    fn unplace(&mut self, step: &mut Step, streamed: &Streamed, port: Port) {
        let Some(remote) = self
            .state
            .link(streamed.connection)
            .map(|link| link.remote.clone())
        else {
            return;
        };
        if let Some(carrying) = self.carrying.get_mut(&remote) {
            carrying.retain(|(capability, slot)| {
                *capability != streamed.capability
                    || !matches!(slot, Slot::Forward(at) if *at == port)
                        && !matches!(slot, Slot::Placing(_))
            });
        }
        step.effects.push(Effect::Unplace {
            connection: streamed.connection,
            forwarding: crate::adb::Forwarding {
                remote,
                capability: streamed.capability.clone(),
                port,
            },
        });
    }

    /// A forward the remote holds is not carried any more, and why.
    fn unforwarded(
        &mut self,
        step: &mut Step,
        now: Now,
        streamed: &Streamed,
        port: Port,
        why: Dropped,
    ) {
        let Some(remote) = self
            .state
            .link(streamed.connection)
            .map(|link| link.remote.clone())
        else {
            return;
        };
        self.drop_forward(step, now, &remote, &streamed.capability, port, why);
    }

    /// Drops `remote`'s forward at `port` of `capability`: recorded, its
    /// carrier ended, its place free.
    fn drop_forward(
        &mut self,
        step: &mut Step,
        now: Now,
        remote: &RemoteId,
        capability: &Name,
        port: Port,
        why: Dropped,
    ) {
        let held = self
            .state
            .carried(remote, capability)
            .into_iter()
            .flatten()
            .find_map(|(carriage, endpoint)| match carriage {
                Carriage::Forward { port: at, .. } if *at == port => {
                    Some((carriage.clone(), *endpoint))
                }
                _ => None,
            });
        let key = (remote.clone(), capability.clone(), port);
        let asked = self.forwarded.remove(&key);
        if let Some(carrying) = self.carrying.get_mut(remote) {
            carrying.remove(&(capability.clone(), Slot::Forward(port)));
        }
        let Some((carriage, listener)) = held else {
            return;
        };
        let connection = asked.map(|(connection, _)| connection).or_else(|| {
            self.state
                .connection(remote)
                .map(|(connection, _)| connection)
        });
        let Some(connection) = connection else {
            return;
        };
        if why == Dropped::Unlent
            && let (Some(server), Some((_, id))) = (self.server(capability), asked)
        {
            step.effects.push(Effect::Unlisten {
                server,
                id,
                listener,
            });
        }
        let dropped = Event::Dropped {
            connection,
            capability: capability.clone(),
            carriage,
            why,
        };
        self.record(step, now, dropped);
        step.effects.push(Effect::Unplace {
            connection,
            forwarding: crate::adb::Forwarding {
                remote: remote.clone(),
                capability: capability.clone(),
                port,
            },
        });
    }

    /// A forward placed again could not listen at its port on the remote.
    fn retaken(&mut self, step: &mut Step, now: Now, forwarding: &crate::adb::Forwarding) {
        self.drop_forward(
            step,
            now,
            &forwarding.remote,
            &forwarding.capability,
            forwarding.port,
            Dropped::Taken,
        );
    }

    /// The devices `capability`'s server holds changed: each forward whose
    /// device left it ends, and each remote the capability is carried to has
    /// the console of every emulator lent to it that the server holds, and no
    /// other.
    fn devices(
        &mut self,
        step: &mut Step,
        now: Now,
        capability: &Name,
        view: &crate::devices::View,
    ) {
        let listed = Answered::Devices(view.lendable());
        self.answer(Topic::Devices(capability.clone()), listed, None);
        // A view with no holder was read of nothing on this workstation, and
        // says nothing of who holds the port.
        if view.holder.is_some() {
            self.held(step, now, capability, view.holder.clone());
        }
        match view.listing {
            // What the server is, or what holds its port, fails the source
            // as a relay's reach would; a server merely not there yet is
            // left to the connections that reach for it.
            crate::devices::Listing::Failed(
                failure @ (Failure::Outdated
                | Failure::Confined
                | Failure::Foreign
                | Failure::Unidentified),
            ) => {
                self.source(step, now, capability, Health::Failing(failure));
                return;
            }
            crate::devices::Listing::Failed(_) => return,
            crate::devices::Listing::Read => {}
        }
        self.source(step, now, capability, Health::Sound);
        self.viewed.insert(capability.clone(), view.clone());
        let gone: Vec<(RemoteId, Port)> = self
            .forwarded
            .iter()
            .filter(|((_, held, _), (_, id))| held == capability && view.by_id(*id).is_none())
            .map(|((remote, _, port), _)| (remote.clone(), *port))
            .collect();
        for (remote, port) in gone {
            self.drop_forward(step, now, &remote, capability, port, Dropped::Gone);
        }
        self.consoles(step, now, capability, Some(view));
    }

    /// Each remote `capability` is carried to has the console of every
    /// emulator its grant lends that `view` holds, and no other; without a
    /// view, those it has are kept or dropped by what is lent alone.
    fn consoles(
        &mut self,
        step: &mut Step,
        now: Now,
        capability: &Name,
        view: Option<&crate::devices::View>,
    ) {
        let live: Vec<(ConnectionId, hedwig_model::trail::Link)> = self
            .state
            .connections()
            .filter(|(_, link)| match &link.phase {
                Phase::Up(serving) => serving
                    .iter()
                    .any(|serving| serving.capability == *capability),
                Phase::Opening => false,
            })
            .map(|(connection, link)| (connection, link.clone()))
            .collect();
        for (connection, link) in live {
            let Some((lends, network)) = self.world().lending(&link, capability) else {
                continue;
            };
            let held: BTreeMap<Port, DeviceSerial> = self
                .state
                .carried(&link.remote, capability)
                .into_iter()
                .flatten()
                .filter_map(|(carriage, _)| match carriage {
                    Carriage::Console { port, device } => Some((*port, device.clone())),
                    _ => None,
                })
                .collect();
            let wanted: BTreeMap<Port, DeviceSerial> = match view {
                Some(view) => view
                    .devices
                    .iter()
                    .filter(|device| device.lent(&lends))
                    .filter_map(|device| {
                        let serial = device.named()?;
                        Some((crate::console::port(&serial)?, serial))
                    })
                    .collect(),
                None => held
                    .iter()
                    .filter(|(_, serial)| lends.lends(serial))
                    .map(|(port, serial)| (*port, serial.clone()))
                    .collect(),
            };
            for (port, device) in &held {
                if wanted.get(port) == Some(device) {
                    continue;
                }
                let why = if lends.lends(device) {
                    Dropped::Gone
                } else {
                    Dropped::Unlent
                };
                if let Some(carrying) = self.carrying.get_mut(&link.remote) {
                    carrying.remove(&(capability.clone(), Slot::Console(*port)));
                }
                let dropped = Event::Dropped {
                    connection,
                    capability: capability.clone(),
                    carriage: Carriage::Console {
                        port: *port,
                        device: device.clone(),
                    },
                    why,
                };
                self.record(step, now, dropped);
                step.effects.push(Effect::Unconsole {
                    connection,
                    remote: link.remote.clone(),
                    capability: capability.clone(),
                    port: *port,
                });
            }
            for (port, device) in wanted {
                // A console being placed holds its slot until its carrier
                // listens or is said not to.
                let slot = (capability.clone(), Slot::Console(port));
                let given = self.carrying.get(&link.remote);
                if held.contains_key(&port)
                    || given.is_some_and(|given| given.contains(&slot))
                    || given.map_or(0, BTreeSet::len) >= crate::adb::CARRIED
                {
                    continue;
                }
                let Some(carrier) = self.carrier(connection, &link.remote) else {
                    continue;
                };
                self.carrying
                    .entry(link.remote.clone())
                    .or_default()
                    .insert(slot);
                step.effects.push(Effect::Console {
                    remote: link.remote.clone(),
                    capability: capability.clone(),
                    port,
                    device,
                    network,
                    carrier,
                });
            }
        }
    }

    /// A console's carrier was started: recorded.
    fn consoled(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        capability: Name,
        carriage: Carriage,
        endpoint: Port,
    ) {
        let carried = Event::Carried {
            connection,
            capability,
            carriage,
            endpoint,
        };
        self.record(step, now, carried);
    }

    /// What each live ADB connection's grant lends now is told to it where it
    /// changed; a forward whose device is no longer lent ends, and so does a
    /// console.
    fn relend(&mut self, step: &mut Step, now: Now) {
        let streams: Vec<(Knock, ConnectionId, Name, Option<crate::adb::Lending>)> = self
            .streams
            .iter()
            .filter(|(_, streamed)| streamed.lending.is_some())
            .map(|(knock, streamed)| {
                (
                    *knock,
                    streamed.connection,
                    streamed.capability.clone(),
                    streamed.lending.clone(),
                )
            })
            .collect();
        for (knock, connection, capability, told) in streams {
            let Some(link) = self.state.link(connection).cloned() else {
                continue;
            };
            let lending = self.world().lending(&link, &capability).map_or(
                crate::adb::Lending {
                    lends: Lends::none(),
                    network: false,
                },
                |(lends, network)| crate::adb::Lending { lends, network },
            );
            if told.as_ref() != Some(&lending) {
                if let Some(streamed) = self.streams.get_mut(&knock) {
                    streamed.lending = Some(lending.clone());
                }
                step.effects.push(Effect::Relend { knock, lending });
            }
        }
        let forwards: Vec<(RemoteId, Name, Port, DeviceSerial)> = self
            .forwarded
            .keys()
            .filter_map(|(remote, capability, port)| {
                let device = self
                    .state
                    .carried(remote, capability)
                    .into_iter()
                    .flatten()
                    .find_map(|(carriage, _)| match carriage {
                        Carriage::Forward {
                            port: at, device, ..
                        } if at == port => Some(device.clone()),
                        _ => None,
                    })?;
                Some((remote.clone(), capability.clone(), *port, device))
            })
            .collect();
        for (remote, capability, port, device) in forwards {
            let lent = self
                .state
                .connection(&remote)
                .and_then(|(_, link)| self.world().lending(link, &capability))
                .is_some_and(|(lends, _)| lends.lends(&device));
            if !lent {
                self.drop_forward(step, now, &remote, &capability, port, Dropped::Unlent);
            }
        }
        let watched: Vec<Name> = self.watched.iter().cloned().collect();
        for capability in watched {
            let view = self.viewed.get(&capability).cloned();
            self.consoles(step, now, &capability, view.as_ref());
        }
    }

    /// Has `connection`'s channel carry the endpoint of `reverse` on to its
    /// remote.
    fn haul(&self, step: &mut Step, connection: ConnectionId, reverse: Reverse) {
        let Ok(client) = self
            .configuration
            .route(&self.catalogue, &reverse.remote.route)
            .map(|route| route.client.clone())
        else {
            return;
        };
        let (asking, keepalive) = self.asking(&reverse.remote);
        step.effects.push(Effect::Haul {
            connection,
            address: reverse.remote.address.clone(),
            reverse,
            client,
            asking,
            keepalive,
        });
    }

    fn asked_event(streamed: &Streamed, operation: Operation, key: Option<KeyId>) -> Event {
        Event::Asked {
            connection: streamed.connection,
            capability: streamed.capability.clone(),
            operation,
            key,
        }
    }

    /// Records a relayed connection's request and decides it: served,
    /// refused, or held for the person.
    fn ask(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        operation: Operation,
        key: Option<KeyId>,
    ) {
        self.ask_with(step, now, knock, operation, key, None);
    }

    /// As [`Core::ask`], recording what the request's payload says with it
    /// before it is decided, so it is on record whatever the outcome.
    fn ask_with(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        operation: Operation,
        key: Option<KeyId>,
        payload: Option<Payload>,
    ) {
        let Some(streamed) = self.streams.get(&knock).cloned() else {
            return;
        };
        if let Some(named) = &key
            && !self.accounted(&streamed.capability, named)
            && self.reread(step, streamed.connection, &streamed.capability)
        {
            self.rereading
                .entry(streamed.capability.clone())
                .or_default()
                .push((knock, operation, named.clone(), payload));
            return;
        }
        if let Some(named) = &key
            && self.card_key(&streamed.capability, named)
            && self.cards_stale.contains_key(&streamed.capability)
            && self.read_cards(step, streamed.connection, &streamed.capability)
        {
            self.cards_waiting
                .entry(streamed.capability.clone())
                .or_default()
                .push((knock, operation, named.clone(), payload));
            return;
        }
        self.decide_now(step, now, knock, operation, key, payload);
    }

    /// Whether a request naming `key` through `capability` uses a key on a
    /// card: an SSH request's key by the keygrip the source's keyring ties
    /// its public half to, so a card's safeguards are known for it as for a
    /// `gpg` request.
    fn card_key(&self, capability: &Name, key: &KeyId) -> bool {
        match key {
            KeyId::Grip(grip) => self.on_card(capability, grip),
            KeyId::Ssh(ssh) => self
                .state
                .offered(capability)
                .and_then(|keyring| keyring.by_ssh(ssh))
                .is_some_and(|offered| self.on_card(capability, &offered.grip)),
        }
    }

    /// Decides a request on what the core knows now, and records it.
    fn decide_now(
        &mut self,
        step: &mut Step,
        now: Now,
        knock: Knock,
        operation: Operation,
        key: Option<KeyId>,
        payload: Option<Payload>,
    ) {
        let Some(streamed) = self.streams.get(&knock).cloned() else {
            return;
        };
        let card = key
            .as_ref()
            .is_some_and(|key| self.card_key(&streamed.capability, key));
        if let Some(held) = self.streams.get_mut(&knock) {
            held.asking_card = card;
        }
        // Nothing a request's own entry records bears on how it is decided.
        let verdict = self.world().decide(
            streamed.connection,
            &streamed.capability,
            operation,
            key.as_ref(),
            now.tick,
        );
        let asked = Core::asked_event(&streamed, operation, key);
        let request = RequestId(self.record(step, now, asked));
        if let Some(payload) = payload {
            self.record(step, now, Event::Payload { request, payload });
        }
        if let Some(held) = self.streams.get_mut(&knock) {
            held.request = Some(request);
        }
        match verdict {
            Verdict::Serve(outcome) => self.settle(step, now, request, outcome),
            Verdict::Refuse(refusal) => {
                self.settle(step, now, request, Outcome::Refused(refusal));
            }
            Verdict::Hold(_) => {
                self.record(step, now, Event::Held { request });
            }
        }
    }

    /// Records how a request ended and tells the connection that holds it;
    /// one served without asking is announced where the person hears those.
    fn settle(&mut self, step: &mut Step, now: Now, request: RequestId, outcome: Outcome) {
        let ask = self.state.ask(request).cloned();
        let knock = self
            .streams
            .iter()
            .find(|(_, streamed)| streamed.request == Some(request))
            .map(|(knock, _)| *knock);
        let verdict = match &outcome {
            Outcome::Refused(refusal) => Err(refusal.clone()),
            Outcome::Served(_) | Outcome::Unseen(_) | Outcome::Allowed(_) | Outcome::Covered => {
                Ok(())
            }
            Outcome::Abandoned => Err(Refusal::Declined),
        };
        let unasked = matches!(outcome, Outcome::Served(_) | Outcome::Covered);
        let interaction = self.world().interaction(&outcome);
        self.record(step, now, Event::Settled { request, outcome });
        if let Some(knock) = knock {
            if let Some(streamed) = self.streams.get_mut(&knock) {
                streamed.request = None;
                if verdict.is_ok() {
                    streamed.served = Some(request);
                    if streamed.asking_card {
                        streamed.used_card = true;
                        *self
                            .cards_stale
                            .entry(streamed.capability.clone())
                            .or_default() += 1;
                    }
                }
                if let Some(taking) = streamed.port.as_mut() {
                    taking.opening = Some(request);
                }
            }
            // Only the credential relay has anything that asks the person.
            let credential = ask.as_ref().is_some_and(|ask| {
                self.configuration
                    .capability(&self.catalogue, &ask.capability)
                    .is_ok_and(|found| {
                        found.dialect() == hedwig_model::capability::Dialect::Credential
                    })
            });
            if credential && interaction == Interaction::Allowed {
                step.effects.push(Effect::Interact { knock });
            }
            step.effects.push(Effect::Settle { knock, verdict });
        }
        let Some(ask) = ask.filter(|_| unasked) else {
            return;
        };
        let Some(remote) = self
            .state
            .link(ask.connection)
            .map(|link| link.remote.clone())
        else {
            return;
        };
        let Some(client) = self.world().announces(&remote) else {
            return;
        };
        let link = self
            .links
            .iter()
            .find(|(_, attendant)| attendant.client == Some(client))
            .map(|(link, _)| *link);
        if let Some(link) = link {
            let served = Served {
                request,
                remote,
                capability: ask.capability,
                operation: ask.operation,
                key: ask.key,
                payload: ask.payload,
            };
            // Nothing is knowable only from a notice: the row's last request
            // says the same, so one that does not fit is not kept.
            self.notice(step, link, Notice::Served(served));
        }
    }

    /// Records what readiness found for one capability, where it differs
    /// from what the connection last recorded.
    fn checked(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        capability: &Name,
        readiness: Readiness,
    ) {
        let last = self
            .state
            .link(connection)
            .and_then(|link| link.readiness.get(capability));
        if last == Some(&readiness) || (last.is_none() && readiness == Readiness::Ready) {
            return;
        }
        let checked = Event::Checked {
            connection,
            capability: capability.clone(),
            readiness,
        };
        self.record(step, now, checked);
    }

    /// Starts an exercise of `capability` on `connection`, where its forward
    /// is up.
    fn exercise(
        &mut self,
        step: &mut Step,
        connection: Option<ConnectionId>,
        capability: &Name,
    ) -> Result<ConnectionId, Refusal> {
        let (connection, link) = connection
            .and_then(|connection| Some((connection, self.state.link(connection)?)))
            .ok_or_else(|| Refusal::UnknownCapability(capability.clone()))?;
        let remote = link.remote.clone();
        let binding = match &link.phase {
            Phase::Up(serving) => serving
                .iter()
                .find(|serving| serving.capability == *capability)
                .map(|serving| serving.binding.clone()),
            Phase::Opening => None,
        }
        .ok_or_else(|| Refusal::NotConnected(remote.clone()))?;
        if self.exercises.contains_key(&connection) {
            return Err(Refusal::NotConnected(remote));
        }
        let query =
            self.world()
                .plan(connection)
                .ok()
                .and_then(|plan| match plan.get(capability) {
                    Some(Ok(Form::SocketAt(query) | Form::SocketFileAt(query))) => Some(*query),
                    _ => None,
                });
        let client = self
            .configuration
            .route(&self.catalogue, &remote.route)
            .map(|route| route.client.clone())?;
        let (asking, keepalive) = self.asking(&remote);
        let dialect = self.dialect(connection);
        step.effects.push(Effect::Exercise {
            connection,
            client,
            address: remote.address,
            dialect,
            capability: capability.clone(),
            query,
            binding,
            asking,
            keepalive,
        });
        Ok(connection)
    }

    /// The remote's tool has run, or its connection ended first: whether a
    /// request of the capability reached the core meanwhile is recorded, and
    /// told to the client that asked.
    fn exercised(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        ran: Result<Option<Words>, Finding>,
    ) {
        let Some((capability, exercising)) = self.exercises.remove(&connection) else {
            return;
        };
        let Some(remote) = self.state.link(connection).map(|link| link.remote.clone()) else {
            return;
        };
        let proof = match ran {
            Err(finding) => Proof::Unrun(finding),
            Ok(last) => self
                .trail
                .iter()
                .filter(|entry| entry.seq > exercising.since)
                .find_map(|entry| match &entry.event {
                    Event::Asked {
                        connection: asked,
                        capability: of,
                        ..
                    } if *asked == connection && *of == capability => Some(RequestId(entry.seq)),
                    _ => None,
                })
                .map_or(Proof::Silent(last), Proof::Reached),
        };
        let exercised = Event::Exercised {
            connection,
            capability: capability.clone(),
            proof: proof.clone(),
            by: exercising.client,
        };
        self.record(step, now, exercised);
        let told = Notice::Exercised(Exercised {
            remote,
            capability,
            proof,
        });
        // Nothing is knowable only from a notice: the entry says the same.
        self.notice(step, exercising.link, told);
    }

    /// Starts each listing due, and ends each that overran its cadence.
    fn list(&mut self, step: &mut Step, now: Now) {
        if self.state.asleep() {
            return;
        }
        let wanted = self.world().listings();
        let dropped: Vec<Name> = self
            .listings
            .keys()
            .filter(|route| !wanted.contains(*route))
            .cloned()
            .collect();
        for route in dropped {
            if let Some(Listed { since: Some(_), .. }) = self.listings.remove(&route) {
                step.effects.push(Effect::Unlist { route });
            }
        }
        for route in wanted {
            let seconds = self.world().cadence(&route).value.0.get();
            let cadence = u64::from(seconds) * 1000;
            let kept = self.listings.entry(route.clone()).or_insert(Listed {
                next: now.tick,
                since: None,
                cadence,
            });
            kept.cadence = cadence;
            let overran = kept
                .since
                .is_some_and(|since| now.tick.0 >= since.0.saturating_add(cadence));
            if overran {
                kept.since = None;
                kept.next = now.tick;
                step.effects.push(Effect::Unlist {
                    route: route.clone(),
                });
                let account = words(&format!(
                    "the listing gave no answer within {seconds} seconds"
                ));
                self.unlisted(step, now, &route, account);
            }
            let Some(kept) = self.listings.get_mut(&route) else {
                continue;
            };
            if kept.since.is_none() && now.tick >= kept.next {
                let lister = self
                    .configuration
                    .route(&self.catalogue, &route)
                    .ok()
                    .and_then(|route| match &route.listing {
                        Listing::Lists(lister) => Some(lister.clone()),
                        Listing::Blind => None,
                    });
                if let Some(lister) = lister {
                    kept.since = Some(now.tick);
                    step.effects.push(Effect::List { route, lister });
                }
            }
        }
    }

    /// Records what a route's listing could not say, where that changed.
    fn unlisted(&mut self, step: &mut Step, now: Now, route: &Name, account: Option<Words>) {
        if self.state.unlisted(route) != account.as_ref() {
            let event = Event::Unlisted {
                route: route.clone(),
                account,
            };
            self.record(step, now, event);
        }
    }

    /// What a listing found: each remote that stopped is gone, ending its
    /// channel, and each that started has appeared.
    fn listed(
        &mut self,
        step: &mut Step,
        now: Now,
        route: &Name,
        listed: Result<Vec<Address>, Words>,
    ) {
        if let Some(entry) = self.listings.get_mut(route) {
            entry.since = None;
            entry.next = Tick(now.tick.0.saturating_add(entry.cadence));
        }
        let addresses = match listed {
            Ok(addresses) => addresses,
            Err(account) => return self.unlisted(step, now, route, Some(account)),
        };
        self.unlisted(step, now, route, None);
        let running: BTreeSet<RemoteId> = addresses
            .into_iter()
            .map(|address| RemoteId {
                route: route.clone(),
                address,
            })
            .collect();
        let before: BTreeSet<RemoteId> = self
            .world()
            .workstation()
            .running
            .into_iter()
            .filter(|remote| remote.route == *route)
            .collect();
        for remote in before.difference(&running) {
            self.record(
                step,
                now,
                Event::Gone {
                    remote: remote.clone(),
                },
            );
            if let Some((connection, _)) = self.state.connection(remote) {
                self.down(step, now, connection, ChannelEnd::RemoteGone);
            }
        }
        for remote in running.difference(&before) {
            self.record(
                step,
                now,
                Event::Appeared {
                    remote: remote.clone(),
                },
            );
        }
    }

    fn told(&mut self, step: &mut Step, now: Now, connection: ConnectionId, told: Told) {
        match told {
            Told::Surveyed { report, theirs } => {
                self.surveyed(step, now, connection, report, &theirs);
            }
            Told::Exercised { ran } => self.exercised(step, now, connection, ran),
            Told::Read { read } => self.read(step, now, connection, read),
            Told::Cards { read } => self.cards(step, now, read),
            Told::Ran {
                program,
                release,
                asking,
            } => {
                if self.state.link(connection).is_some() {
                    let ran = Event::Ran {
                        connection,
                        program,
                        release,
                        asking,
                    };
                    self.record(step, now, ran);
                }
            }
            Told::Unstarted { end } => self.down(step, now, connection, end),
            Told::Forwarded { capability, bound } => {
                self.forwarded(step, now, connection, &capability, bound);
            }
            Told::HostKeyChanged { fingerprint } => {
                let end = ChannelEnd::HostKeyChanged(fingerprint);
                self.down(step, now, connection, end);
            }
            Told::Ended {
                status,
                unverified,
                last,
            } => self.down(step, now, connection, ended(status, unverified, last)),
        }
    }

    /// Records that a connection is over and has its job ended. One that is
    /// already over is left as it was recorded: the first account stands.
    fn down(&mut self, step: &mut Step, now: Now, connection: ConnectionId, end: ChannelEnd) {
        if self.state.link(connection).is_none() {
            return;
        }
        let unfinished = words("the channel ended before the remote's tool had run")
            .unwrap_or_else(|| unreachable!("fixed words are valid words"));
        self.exercised(step, now, connection, Err(Finding::Unsurveyed(unfinished)));
        let calling: Vec<Knock> = self
            .streams
            .iter()
            .filter(|(_, streamed)| streamed.connection == connection && streamed.calling)
            .map(|(knock, _)| *knock)
            .collect();
        for knock in calling {
            self.uncarried(step, now, knock, Carry::Ended);
        }
        self.channels.remove(&connection);
        self.opened.remove(&connection);
        self.surveys.remove(&connection);
        self.keyed.remove(&connection);
        self.issued.remove(&connection);
        let asked: Vec<PromptId> = self
            .state
            .prompts()
            .filter(|(_, prompt)| prompt.connection == connection)
            .map(|(prompt, _)| prompt)
            .collect();
        for prompt in asked {
            self.asking.remove(&prompt);
        }
        let remote = self.state.link(connection).map(|link| link.remote.clone());
        self.record(step, now, Event::Down { connection, end });
        step.effects.push(Effect::End { connection });
        if let Some(remote) = remote {
            self.unconsoled(step, now, connection, &remote);
        }
        let carried: BTreeSet<Name> = self
            .state
            .connections()
            .filter_map(|(_, link)| match &link.phase {
                Phase::Up(serving) => {
                    Some(serving.iter().map(|serving| serving.capability.clone()))
                }
                Phase::Opening => None,
            })
            .flatten()
            .collect();
        let unwatched: Vec<Name> = self
            .watched
            .iter()
            .filter(|capability| !carried.contains(*capability))
            .cloned()
            .collect();
        for capability in unwatched {
            self.watched.remove(&capability);
            self.viewed.remove(&capability);
            if !self.lists(&Topic::Devices(capability.clone())) {
                step.effects.push(Effect::Unwatch { capability });
            }
        }
    }

    /// The consoles carried through a channel that ended are carried no
    /// more: their carriers were in its job.
    fn unconsoled(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        remote: &RemoteId,
    ) {
        let held: Vec<(Name, Carriage)> = self
            .carrying
            .get(remote)
            .into_iter()
            .flatten()
            .filter_map(|(capability, slot)| match slot {
                Slot::Console(port) => Some((capability.clone(), *port)),
                _ => None,
            })
            .filter_map(|(capability, port)| {
                let carriage = self
                    .state
                    .carried(remote, &capability)
                    .into_iter()
                    .flatten()
                    .find_map(|(carriage, _)| match carriage {
                        Carriage::Console { port: at, .. } if *at == port => Some(carriage.clone()),
                        _ => None,
                    })?;
                Some((capability, carriage))
            })
            .collect();
        for (capability, carriage) in held {
            if let Carriage::Console { port, .. } = &carriage
                && let Some(carrying) = self.carrying.get_mut(remote)
            {
                carrying.remove(&(capability.clone(), Slot::Console(*port)));
            }
            let dropped = Event::Dropped {
                connection,
                capability,
                carriage,
                why: Dropped::Gone,
            };
            self.record(step, now, dropped);
        }
    }

    /// The far ends are known: starts the channel with a forward for each
    /// capability the remote still holds.
    fn placed(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        serving: Vec<Serving>,
    ) {
        let Some(link) = self.state.link(connection) else {
            return;
        };
        if self.channels.contains_key(&connection) {
            return;
        }
        let (route, address) = (link.remote.route.clone(), link.remote.address.clone());
        let serving: Vec<Serving> = serving
            .into_iter()
            .filter(|serving| self.world().holds(connection, &serving.capability).is_ok())
            .collect();
        let client = self
            .configuration
            .route(&self.catalogue, &route)
            .ok()
            .map(|route| route.client.clone());
        let Some(client) = client else {
            return self.down(step, now, connection, ChannelEnd::Closed);
        };
        if serving.is_empty() {
            // The remote holds nothing now, or holds only what cannot be
            // carried there.
            let remote = &link.remote;
            let end = if self.world().carries(remote).is_empty() {
                ChannelEnd::Closed
            } else {
                ChannelEnd::NothingCarried
            };
            return self.down(step, now, connection, end);
        }
        let remote = link.remote.clone();
        let world = self.world();
        let card = world.full_screen(&remote).value;
        let asking = if self.state.askable(&remote, &world.sets(), card) {
            Asking::Person
        } else {
            Asking::Nobody
        };
        let keepalive = world.keepalive(&remote).value;
        let channel = Channel {
            pending: serving
                .iter()
                .map(|serving| serving.capability.clone())
                .collect(),
            asked: serving.clone(),
            bound: Vec::new(),
        };
        self.channels.insert(connection, channel);
        step.effects.push(Effect::Start {
            connection,
            client,
            address,
            serving,
            asking,
            keepalive,
        });
    }

    /// The remote's server answered for one forward. When it has answered for
    /// all of them the channel is up with those it bound, or over if it bound
    /// none.
    fn forwarded(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        capability: &Name,
        bound: bool,
    ) {
        let Some(channel) = self.channels.get_mut(&connection) else {
            return;
        };
        if !channel.pending.remove(capability) {
            return;
        }
        let asked = channel
            .asked
            .iter()
            .find(|serving| serving.capability == *capability)
            .cloned();
        if let (true, Some(serving)) = (bound, asked) {
            channel.bound.push(serving);
        } else {
            let readiness = Readiness::Unready(vec![Finding::ForwardRefused]);
            let checked = Event::Checked {
                connection,
                capability: capability.clone(),
                readiness,
            };
            self.record(step, now, checked);
        }
        let Some(channel) = self.channels.get(&connection) else {
            return;
        };
        if !channel.pending.is_empty() {
            return;
        }
        if channel.bound.is_empty() {
            return self.down(step, now, connection, ChannelEnd::ForwardRefused);
        }
        let serving = channel.bound.clone();
        self.record(
            step,
            now,
            Event::Up {
                connection,
                serving: serving.clone(),
            },
        );
        step.effects.push(Effect::Seal { connection });
        // The reverses each ADB capability the channel serves carried in
        // this run reach the remote again through the channel that is up now.
        let Some(remote) = self.state.link(connection).map(|link| link.remote.clone()) else {
            return;
        };
        let reverses: Vec<Reverse> = serving
            .iter()
            .filter(|serving| {
                self.configuration
                    .capability(&self.catalogue, &serving.capability)
                    .is_ok_and(|found| found.dialect() == hedwig_model::capability::Dialect::Adb)
            })
            .flat_map(|serving| {
                self.state
                    .carried(&remote, &serving.capability)
                    .into_iter()
                    .flat_map(BTreeMap::keys)
                    .filter_map(|carriage| match carriage {
                        Carriage::Reverse(target) => Some(Reverse {
                            remote: remote.clone(),
                            capability: serving.capability.clone(),
                            target: target.clone(),
                        }),
                        _ => None,
                    })
            })
            .collect();
        for reverse in reverses {
            self.haul(step, connection, reverse);
        }
        self.replace(step, now, connection, &remote, &serving);
    }

    /// The forwards each ADB capability the channel serves carried in this
    /// run are placed again at their ports on the remote, and the capability's
    /// server's devices are watched - or, where they are watched already, the
    /// consoles of the emulators lent to the remote are carried.
    fn replace(
        &mut self,
        step: &mut Step,
        now: Now,
        connection: ConnectionId,
        remote: &RemoteId,
        serving: &[Serving],
    ) {
        let adb: Vec<Name> = serving
            .iter()
            .filter(|serving| self.server(&serving.capability).is_some())
            .map(|serving| serving.capability.clone())
            .collect();
        for capability in adb {
            let forwards: Vec<Port> = self
                .state
                .carried(remote, &capability)
                .into_iter()
                .flatten()
                .filter_map(|(carriage, _)| match carriage {
                    Carriage::Forward { port, .. } => Some(*port),
                    _ => None,
                })
                .collect();
            let (Some(server), Some(carrier)) =
                (self.server(&capability), self.carrier(connection, remote))
            else {
                continue;
            };
            for port in forwards {
                step.effects.push(Effect::Replace {
                    forwarding: crate::adb::Forwarding {
                        remote: remote.clone(),
                        capability: capability.clone(),
                        port,
                    },
                    server: server.clone(),
                    carrier: carrier.clone(),
                });
            }
            if self.watched.insert(capability.clone()) {
                step.effects.push(Effect::Watch { capability, server });
            } else if let Some(view) = self.viewed.get(&capability).cloned() {
                self.consoles(step, now, &capability, Some(&view));
            }
        }
    }

    fn reply(
        &mut self,
        step: &mut Step,
        link: Link,
        id: u32,
        reply: Result<Reply, Refusal>,
        then: Then,
    ) {
        if let Some(attendant) = self.links.get_mut(&link) {
            attendant.waiting = attendant.waiting.saturating_add(1);
            step.effects.push(Effect::Send {
                link,
                frame: FromCore::Reply { id, reply },
                then,
            });
        }
    }

    /// Queues a notice if it fits, leaving the last place for a reply.
    fn notice(&mut self, step: &mut Step, link: Link, notice: Notice) -> bool {
        let Some(attendant) = self.links.get_mut(&link) else {
            return false;
        };
        if attendant.waiting >= WAITING - 1 {
            return false;
        }
        attendant.waiting += 1;
        step.effects.push(Effect::Send {
            link,
            frame: FromCore::Notice(notice),
            then: Then::Nothing,
        });
        true
    }

    /// Requests held for a person nobody can now reach are refused at once,
    /// and channels whose client asks them something end as needing them.
    fn strand(&mut self, step: &mut Step, now: Now) {
        for (request, whereabouts) in self.world().stranded() {
            let refusal = Refusal::NobodyReachable(whereabouts);
            self.settle(step, now, request, Outcome::Refused(refusal));
        }
        let world = self.world();
        let sets = world.sets();
        let stranded: Vec<(ConnectionId, hedwig_model::trail::PromptKind)> = self
            .state
            .prompts()
            .filter_map(|(_, prompt)| {
                let link = self.state.link(prompt.connection)?;
                let card = world.full_screen(&link.remote).value;
                (!self.state.askable(&link.remote, &sets, card))
                    .then_some((prompt.connection, prompt.kind))
            })
            .collect();
        for (connection, kind) in stranded {
            self.down(step, now, connection, ChannelEnd::Needs(kind));
        }
    }

    #[allow(clippy::too_many_lines, reason = "one arm per request")]
    fn asked(&mut self, step: &mut Step, now: Now, link: Link, frame: ToCore) {
        let ToCore { id, request } = frame;
        let Some(attendant) = self.links.get(&link) else {
            return;
        };
        let (peer, greeted) = (attendant.peer.clone(), attendant.client);
        let client = greeted.unwrap_or(NOBODY);
        if let Err(refusal) = self.world().permit(client, &request) {
            let then = match request {
                Request::Hello { .. } => Then::Close,
                _ => Then::Continue,
            };
            return self.reply(step, link, id, Err(refusal), then);
        }
        let reply = match request {
            Request::Hello { .. } if greeted.is_some() => Reply::Done(Changed::Unchanged),
            Request::Hello { kind, attends, .. } => {
                let door = if kind == ClientKind::Prompt {
                    Door::Prompt
                } else {
                    Door::Control
                };
                let admitted = self.world().admit(door, peer.as_ref());
                let (Ok(_), Some(peer)) = (&admitted, peer) else {
                    let refusal = admitted.err().unwrap_or(Refusal::Unattributable);
                    return self.reply(step, link, id, Err(refusal), Then::Close);
                };
                let channel = (kind == ClientKind::Prompt)
                    .then_some(peer.channel)
                    .flatten();
                let origin = peer.origin;
                let attached = self.record(
                    step,
                    now,
                    Event::Attached {
                        kind,
                        origin,
                        attends,
                    },
                );
                if let Some(attendant) = self.links.get_mut(&link) {
                    attendant.client = Some(ClientId(attached));
                    attendant.channel = channel;
                }
                Reply::Welcome {
                    protocol: PROTOCOL,
                    version: self.version.clone(),
                    you: origin,
                }
            }
            Request::Status => match self.world().status(client, now.tick) {
                Some(status) => Reply::Status(status),
                None => Reply::Done(Changed::Unchanged),
            },
            Request::Exposure => Reply::Exposure(self.world().rows(client, now.tick)),
            Request::Attention => Reply::Attention(self.world().attention(client, now.tick)),
            Request::Catalogue => Reply::Catalogue(self.configuration.definitions(&self.catalogue)),
            Request::Workstation => Reply::Workstation(self.world().workstation()),
            Request::Export => Reply::Document(Box::new(self.configuration.export())),
            Request::Activity {
                remote,
                before,
                limit,
            } => Reply::Activity(page(
                &self.head,
                &self.trail,
                &remote,
                &self.configuration.sets(&self.catalogue),
                before,
                limit,
            )),
            Request::Follow { after } => {
                let next = after.or_else(|| self.trail.last().map(|last| last.seq));
                if let Some(attendant) = self.links.get_mut(&link) {
                    attendant.follows = Some(Seq(next.map_or(0, |seq| seq.0) + 1));
                }
                Reply::Done(Changed::Changed)
            }
            Request::Change(change) => {
                let reach = self.configuration.widens(&self.catalogue, &change);
                let effect = match self.configuration.apply(&self.catalogue, change.clone()) {
                    Ok(effect) => effect,
                    Err(refusal) => {
                        return self.reply(step, link, id, Err(refusal), Then::Continue);
                    }
                };
                let held = self.world().held(client, Some(&change), now.tick);
                if effect == Changed::Changed {
                    let changed = Event::Changed {
                        change,
                        by: client,
                        reach,
                    };
                    let entry = self.record(step, now, changed);
                    step.keep = Some(Keep {
                        entry,
                        document: self.configuration.export(),
                    });
                }
                Reply::Changed { effect, held }
            }
            Request::Import(document) => {
                let reach = match Configuration::import(&self.catalogue, *document) {
                    Ok(imported) => {
                        let reach = self.configuration.widens_to(&imported);
                        self.configuration = imported;
                        reach
                    }
                    Err(refusal) => {
                        return self.reply(step, link, id, Err(refusal), Then::Continue);
                    }
                };
                let entry = self.record(step, now, Event::Imported { by: client, reach });
                step.keep = Some(Keep {
                    entry,
                    document: self.configuration.export(),
                });
                Reply::Changed {
                    effect: Changed::Changed,
                    held: self.world().held(client, None, now.tick),
                }
            }
            Request::Settings { remotes } => {
                Reply::Settings(Box::new(self.world().settings(&remotes)))
            }
            Request::Try(trial) => {
                Reply::Tried(Box::new(self.world().tried(client, &trial, now.tick)))
            }
            Request::Pause(scope) => {
                let sets = self.configuration.sets(&self.catalogue);
                let covered: Vec<_> = self
                    .state
                    .connections()
                    .filter(|(_, link)| scope.covers(&link.remote, &sets))
                    .map(|(connection, _)| connection)
                    .collect();
                self.record(step, now, Event::Paused { scope, by: client });
                for connection in covered {
                    self.down(step, now, connection, ChannelEnd::Closed);
                }
                Reply::Done(Changed::Changed)
            }
            Request::Prompt { words, hint } => {
                let channel = self
                    .links
                    .get(&link)
                    .and_then(|attendant| attendant.channel);
                let Some(connection) = channel else {
                    return self.reply(step, link, id, Err(Refusal::Unattributable), Then::Close);
                };
                let Some(remote) = self.state.link(connection).map(|link| link.remote.clone())
                else {
                    let refusal = Refusal::UnknownConnection(connection);
                    return self.reply(step, link, id, Err(refusal), Then::Close);
                };
                let kind = asked(&words, hint);
                let world = self.world();
                let card = world.full_screen(&remote).value;
                let Some(whereabouts) = self.state.unreached(&remote, &world.sets(), card) else {
                    let prompted = Event::Prompted {
                        connection,
                        kind,
                        words,
                    };
                    let prompt = PromptId(self.record(step, now, prompted));
                    self.asking.insert(prompt, (link, id));
                    // Answered when the person answers.
                    return;
                };
                self.down(step, now, connection, ChannelEnd::Needs(kind));
                let refused = Err(Refusal::NobodyReachable(whereabouts));
                return self.reply(step, link, id, refused, Then::Close);
            }
            Request::Resume(scope) => {
                self.record(step, now, Event::Resumed { scope, by: client });
                Reply::Done(Changed::Changed)
            }
            Request::PutAway(item) => {
                self.record(step, now, Event::PutAway { item, by: client });
                Reply::Done(Changed::Changed)
            }
            Request::Presence(presence) => {
                self.record(step, now, Event::Presence { client, presence });
                Reply::Done(Changed::Changed)
            }
            Request::Icon(icon) => {
                let said = self.state.surface(client).and_then(|surface| surface.icon);
                if said == Some(icon) {
                    Reply::Done(Changed::Unchanged)
                } else {
                    self.record(step, now, Event::Icon { client, icon });
                    Reply::Done(Changed::Changed)
                }
            }
            Request::Connect {
                remote,
                with,
                acknowledged,
                lends,
            } => {
                if self.state.connection(&remote).is_some() {
                    Reply::Done(Changed::Unchanged)
                } else {
                    let added = Added {
                        with,
                        acknowledged,
                        lends,
                    };
                    self.open(step, now, &remote, added, Opener::Person(client));
                    Reply::Done(Changed::Changed)
                }
            }
            Request::Disconnect { remote } => {
                let live = self
                    .state
                    .connection(&remote)
                    .map(|(connection, _)| connection);
                let held = live.is_some()
                    || self.state.asked(&remote).is_some()
                    || self.state.returning(&remote).is_some()
                    || self.world().wants(&remote).is_some();
                if held {
                    let disconnected = Event::Disconnected { remote, by: client };
                    self.record(step, now, disconnected);
                    if let Some(connection) = live {
                        self.down(step, now, connection, ChannelEnd::Closed);
                    }
                    Reply::Done(Changed::Changed)
                } else {
                    Reply::Done(Changed::Unchanged)
                }
            }
            Request::Rule {
                connection,
                scope,
                mode,
            } => {
                let ruled = Event::Ruled {
                    connection,
                    scope,
                    mode,
                    by: client,
                };
                self.record(step, now, ruled);
                Reply::Done(Changed::Changed)
            }
            // Answered at once; each survey's taking back is recorded as it
            // happens, and `Withdrawal` reads where it stands.
            Request::Withdraw => {
                if self.state.withdrawn().is_none() {
                    self.record(step, now, Event::Withdrawn { by: client });
                }
                let remotes: Vec<RemoteId> = self.state.written_on().cloned().collect();
                for remote in remotes {
                    let live = self
                        .state
                        .connection(&remote)
                        .map(|(connection, _)| connection);
                    match live {
                        Some(connection) if !self.surveys.contains_key(&connection) => {
                            let dialect = self.dialect(connection);
                            self.survey(step, now, connection, dialect, Purpose::Withdraw);
                        }
                        Some(_) => {}
                        None => {
                            self.open(step, now, &remote, Added::nothing(), Opener::Check(client));
                        }
                    }
                }
                Reply::Withdrawal(self.world().withdrawal())
            }
            Request::Withdrawal => Reply::Withdrawal(self.world().withdrawal()),
            // What the person consented to is written again by the surveys the
            // grants' channels start as they are held again.
            Request::Restore => {
                if self.state.withdrawn().is_some() {
                    self.record(step, now, Event::Restored { by: client });
                    Reply::Done(Changed::Changed)
                } else {
                    Reply::Done(Changed::Unchanged)
                }
            }
            Request::Diagnose(level) => {
                if self.state.diagnose() == level {
                    Reply::Done(Changed::Unchanged)
                } else {
                    self.record(step, now, Event::Diagnosed { level, by: client });
                    Reply::Done(Changed::Changed)
                }
            }
            Request::Bundle => match self.bundle(client, now) {
                Some(bundle) => {
                    step.effects.push(Effect::Bundle {
                        link,
                        id,
                        bundle: Box::new(bundle),
                    });
                    return;
                }
                None => Reply::Done(Changed::Unchanged),
            },
            Request::Stop => {
                self.record(step, now, Event::Stopping { by: client });
                let live: Vec<ConnectionId> = self
                    .state
                    .connections()
                    .map(|(connection, _)| connection)
                    .collect();
                for connection in live {
                    self.down(step, now, connection, ChannelEnd::Closed);
                }
                return self.reply(
                    step,
                    link,
                    id,
                    Ok(Reply::Done(Changed::Changed)),
                    Then::Stop,
                );
            }
            Request::Answer { prompt, answer } => {
                let Some(put) = self.state.prompt(prompt).cloned() else {
                    unreachable!("the gate refuses an answer to what was never recorded")
                };
                let given = match &answer {
                    Answer::Text(_) => Given::Text,
                    Answer::Accept => Given::Accepted,
                    Answer::Decline => Given::Declined,
                };
                let by = Some(Gave { client, given });
                self.record(step, now, Event::Answered { prompt, by });
                let asker = self.asking.remove(&prompt);
                if given == Given::Declined && put.kind.decline_ends() {
                    // An empty answer would reach the server or the key as a
                    // wrong one: the client is ended before it can send any.
                    self.down(step, now, put.connection, ChannelEnd::Declined(put.kind));
                } else if let Some((asker, asked_as)) = asker {
                    self.reply(
                        step,
                        asker,
                        asked_as,
                        Ok(Reply::Answer(answer)),
                        Then::Close,
                    );
                }
                Reply::Done(Changed::Changed)
            }
            Request::Decide { request, decision } => {
                let Some(ask) = self.state.ask(request).cloned() else {
                    unreachable!("the gate refuses a decision on what is not held")
                };
                if let Some(until) = decision.until(now.tick) {
                    let allowed = Event::Allowed {
                        connection: ask.connection,
                        capability: ask.capability.clone(),
                        operation: ask.operation,
                        key: ask.key.clone(),
                        until,
                        by: client,
                    };
                    self.record(step, now, allowed);
                }
                let outcome = match decision {
                    Decision::Once | Decision::For(_) => Outcome::Allowed(client),
                    Decision::Refuse => Outcome::Refused(Refusal::Declined),
                };
                self.settle(step, now, request, outcome);
                Reply::Done(Changed::Changed)
            }
            // Readiness runs again on a live channel, which runs on; with none
            // live, a connection is opened for it alone. The row says where
            // the grant stands meanwhile, and what is found marks it stale.
            Request::Check { remote, capability } => {
                let live = self
                    .state
                    .connection(&remote)
                    .map(|(connection, _)| connection);
                match live {
                    Some(connection) if !self.surveys.contains_key(&connection) => {
                        let dialect = self.dialect(connection);
                        self.survey(step, now, connection, dialect, Purpose::Recheck);
                    }
                    Some(_) => {}
                    None => self.open(step, now, &remote, Added::nothing(), Opener::Check(client)),
                }
                let row = self.world().rows(client, now.tick).into_iter().find(|row| {
                    row.capability == capability && row.remote.as_ref() == Some(&remote)
                });
                match row {
                    Some(row) => Reply::Row(Box::new(row)),
                    None => Reply::Done(Changed::Unchanged),
                }
            }
            // Answered at once, so the client can answer what the tool asks
            // of the person; what the tool did follows as a notice.
            // Answered once the server has listed them.
            Request::Ports => {
                step.effects.push(Effect::Ports {
                    asked: Some((link, id)),
                });
                return;
            }
            Request::MakeKey { name, kind } => {
                step.effects.push(Effect::MakeKey {
                    link,
                    id,
                    name,
                    kind,
                });
                return;
            }
            // Found first, so a key the TPM does not hold changes nothing.
            Request::DeleteKey(key) => {
                step.effects.push(Effect::FindKey { link, id, key });
                return;
            }
            Request::Keys(capability) => {
                let Ok(Capability {
                    source: Source::Agent { at },
                    ..
                }) = self.configuration.capability(&self.catalogue, &capability)
                else {
                    let refusal = Refusal::CapabilityIncomplete { capability };
                    return self.reply(step, link, id, Err(refusal), Then::Continue);
                };
                step.effects.push(Effect::Keys {
                    link,
                    id,
                    capability,
                    at,
                });
                return;
            }
            Request::Devices(capability) => {
                let Some(server) = self.server(&capability) else {
                    let refusal = Refusal::CapabilityIncomplete { capability };
                    return self.reply(step, link, id, Err(refusal), Then::Continue);
                };
                step.effects.push(Effect::Lend {
                    link,
                    id,
                    capability,
                    server,
                });
                return;
            }
            Request::Exercise { remote, capability } => {
                let live = self
                    .state
                    .connection(&remote)
                    .map(|(connection, _)| connection);
                match self.exercise(step, live, &capability) {
                    Ok(connection) => {
                        let since = self.trail.last().map_or(Seq(0), |last| last.seq);
                        let exercising = Exercising {
                            link,
                            client,
                            since,
                        };
                        self.exercises.insert(connection, (capability, exercising));
                        Reply::Done(Changed::Changed)
                    }
                    Err(refusal) => {
                        return self.reply(step, link, id, Err(refusal), Then::Continue);
                    }
                }
            }
        };
        self.reply(step, link, id, Ok(reply), Then::Continue);
    }

    /// `answer` is what `topic` answers now: every client that lists it,
    /// but the one `asked` it is given to, is told it is stale where it
    /// changed; the one that asked lists it from now on.
    fn answer(&mut self, topic: Topic, answer: Answered, asked: Option<Link>) {
        let changed = self.answered.get(&topic) != Some(&answer);
        if let Some(attendant) = asked.and_then(|link| self.links.get_mut(&link)) {
            attendant.lists.insert(topic.clone());
        }
        if changed {
            for (link, attendant) in &mut self.links {
                if Some(*link) != asked && attendant.lists.contains(&topic) {
                    attendant.stale.insert(topic.clone());
                }
            }
        }
        if self.lists(&topic) {
            self.answered.insert(topic, answer);
        }
    }

    /// The client a link greeted as, or nobody.
    fn client_of(&self, link: Link) -> ClientId {
        self.links
            .get(&link)
            .and_then(|attendant| attendant.client)
            .unwrap_or(NOBODY)
    }

    /// Every client that lists a TPM source's keys is told they changed: the
    /// core made or deleted one.
    fn keys_changed(&mut self) {
        let machine: Vec<Topic> = self
            .links
            .values()
            .flat_map(|attendant| attendant.lists.iter())
            .filter(|topic| match topic {
                Topic::Keys(capability) => matches!(
                    self.configuration.capability(&self.catalogue, capability),
                    Ok(Capability {
                        source: Source::Agent {
                            at: AgentAt::Machine
                        },
                        ..
                    })
                ),
                _ => false,
            })
            .cloned()
            .collect();
        for topic in machine {
            self.answered.remove(&topic);
            for attendant in self.links.values_mut() {
                if attendant.lists.contains(&topic) {
                    attendant.stale.insert(topic.clone());
                }
            }
        }
    }

    /// Takes `key` out of every grant and acceptance that lends it, each
    /// change recorded and kept as a client's change is, before the key is
    /// deleted.
    fn unlend(&mut self, step: &mut Step, now: Now, link: Link, key: &SshKey) {
        let by = self.client_of(link);
        for change in self.configuration.unlending(key) {
            let reach = self.configuration.widens(&self.catalogue, &change);
            if self.configuration.apply(&self.catalogue, change.clone()) == Ok(Changed::Changed) {
                let entry = self.record(step, now, Event::Changed { change, by, reach });
                step.keep = Some(Keep {
                    entry,
                    document: self.configuration.export(),
                });
            }
        }
    }

    /// Whether any client lists `topic`.
    fn lists(&self, topic: &Topic) -> bool {
        self.links
            .values()
            .any(|attendant| attendant.lists.contains(topic))
    }

    /// Tells each client that watches its remote of what now needs the
    /// person, as loudly as [`World::hears`] says for that client, once;
    /// and of each request or prompt it was told of that is over.
    fn raise(&mut self, step: &mut Step) {
        let (fresh, over, told) = {
            let world = self.world();
            let now: Vec<(Raised, Needs)> = world
                .attention(NOBODY, self.now)
                .into_iter()
                .filter_map(|needs| Raised::of(&needs.attention).map(|raised| (raised, needs)))
                .collect();
            let current: BTreeSet<&Raised> = now.iter().map(|(raised, _)| raised).collect();
            let over: Vec<(Raised, Option<RemoteId>)> = self
                .raised
                .iter()
                .filter(|(raised, _)| !current.contains(raised))
                .map(|(raised, remote)| (raised.clone(), remote.clone()))
                .collect();
            let mut told: Vec<(ClientId, Notice)> = Vec::new();
            let mut fresh: Vec<(Raised, Option<RemoteId>)> = Vec::new();
            for (raised, needs) in &now {
                if self.raised.contains_key(raised) {
                    continue;
                }
                for (client, volume) in world.hears(needs) {
                    let needs = Needs {
                        attention: needs.attention.clone(),
                        volume,
                    };
                    told.push((client, Notice::Raised(needs)));
                }
                fresh.push((raised.clone(), needs.attention.remote().cloned()));
            }
            let sets = world.sets();
            for (raised, remote) in &over {
                let withdrawn = match raised {
                    Raised::Request(request) => Withdrawn::Request(*request),
                    Raised::Prompt(prompt) => Withdrawn::Prompt(*prompt),
                    Raised::Item(_) => continue,
                };
                let Some(remote) = remote else {
                    continue;
                };
                told.extend(
                    self.state
                        .watching(remote, &sets)
                        .map(|(client, _)| (client, Notice::Withdrawn(withdrawn))),
                );
            }
            (fresh, over, told)
        };
        for (raised, remote) in fresh {
            self.raised.insert(raised, remote);
        }
        for (raised, _) in over {
            self.raised.remove(&raised);
        }
        for (client, notice) in told {
            let link = self
                .links
                .iter()
                .find(|(_, attendant)| attendant.client == Some(client))
                .map(|(link, _)| *link);
            if let Some(link) = link
                && !self.notice(step, link, notice)
                && let Some(attendant) = self.links.get_mut(&link)
            {
                attendant.stale.insert(Topic::Attention);
            }
        }
    }

    /// After a step: tells the other attending clients which of what they
    /// show is stale - and the client that acted, of what the core read of
    /// the workstation while serving it - raises and withdraws what needs the
    /// person, and gives every client what it is owed and now fits.
    fn tell(&mut self, step: &mut Step, actor: Option<Link>, moved: bool, lapsed: bool) {
        let mut stale: BTreeSet<Topic> = step
            .entries
            .iter()
            .flat_map(|entry| entry.event.touches())
            .cloned()
            .collect();
        let read: BTreeSet<Topic> = step
            .entries
            .iter()
            .filter(|entry| entry.event.is_reading())
            .flat_map(|entry| entry.event.touches())
            .cloned()
            .collect();
        // An allowance or a burst's window may have ended with no entry.
        if lapsed {
            stale.extend([Topic::Exposure, Topic::Attention]);
        }
        if moved {
            self.raise(step);
        }
        let links: Vec<Link> = self.links.keys().copied().collect();
        for link in links {
            let attends = self
                .links
                .get(&link)
                .and_then(|attendant| attendant.client)
                .and_then(|client| self.state.surface(client))
                .is_some_and(|surface| surface.kind.shows());
            if attends && let Some(attendant) = self.links.get_mut(&link) {
                let told = if Some(link) == actor { &read } else { &stale };
                attendant.stale.extend(told.iter().cloned());
            }
            while let Some(attendant) = self.links.get_mut(&link) {
                let notice = if let Some(topic) = attendant.stale.first().cloned() {
                    Notice::Stale(topic)
                } else if let Some(entry) = attendant
                    .follows
                    .and_then(|next| self.trail.iter().rev().find(|entry| entry.seq == next))
                {
                    Notice::Recorded(entry.clone())
                } else {
                    break;
                };
                let sent = self.notice(step, link, notice.clone());
                let Some(attendant) = self.links.get_mut(&link) else {
                    break;
                };
                if !sent {
                    break;
                }
                match notice {
                    Notice::Stale(topic) => {
                        attendant.stale.remove(&topic);
                    }
                    Notice::Recorded(entry) => attendant.follows = Some(Seq(entry.seq.0 + 1)),
                    Notice::Raised(_)
                    | Notice::Served(_)
                    | Notice::Withdrawn(_)
                    | Notice::Exercised(_) => {}
                }
            }
        }
    }
}

/// What a list a client may list answered: a source's devices, or why it
/// listed none; the workstation's serial ports.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answered {
    Devices(Result<Vec<hedwig_model::protocol::Lendable>, Failure>),
    Ports(Vec<hedwig_model::protocol::SerialPort>),
    Keys(Result<Vec<AgentKey>, Failure>),
}

/// Why readiness could not read a remote, in the person's words, with the
/// last thing the client said where it said anything.
fn why(unread: &Unread, last: Option<&Words>) -> Option<Words> {
    let reason = match unread {
        Unread::NotBegun => "no shell Hedwig knows ran there".to_owned(),
        Unread::Unfinished => "the remote stopped before readiness finished".to_owned(),
        Unread::Malformed(line) => {
            format!("the remote answered something Hedwig did not ask: {line}")
        }
    };
    match last {
        Some(last) => words(&format!("{reason}; it said \"{last}\"")),
        None => words(&reason),
    }
}
