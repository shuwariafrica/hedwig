//! What the interface knows of Hedwig, and how it comes to know it.
//!
//! [`Link`] is the interface's whole conversation with the core as one
//! function: an [`Event`] in - the record was read, the pipe opened, a frame
//! arrived, the person asked for something - and [`Effect`]s out. It opens no
//! pipe and reads no file, so every state a surface can find itself in is a
//! test with no desktop and no core. [`Seen`] is what the surfaces render.

use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU8;
use std::time::{Duration, Instant};

use hedwig_client::Standing;
use hedwig_model::config::{Catalogue, Definitions, Document, Reference};
use hedwig_model::organisation::Holding;
use hedwig_model::policy::Selector;
use hedwig_model::process::CoreState;
use hedwig_model::protocol::{
    Attention, Bundle, Exercised, FromCore, Lendable, Needs, Notice, PROTOCOL, Proof, Reply,
    Request, Row, SerialPort, Served, Settings, Standing as Stands, Status, ToCore, Topic, Tried,
    Withdrawn, Workstation,
};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{RemoteId, Remotes};
use hedwig_model::setting::Volume;
use hedwig_model::text::{Name, PipeName};
use hedwig_model::trail::{
    Breakdown, ClientKind, Entry, Event as Happened, Failure, Icon, Origin, Presence, Seq,
};

use crate::define::Kind;
use crate::words::{AgentKeys, Keyrings};

/// How many entries of one remote's activity are asked for at a time.
pub const PAGE: NonZeroU8 = match NonZeroU8::new(50) {
    Some(page) => page,
    None => NonZeroU8::MIN,
};

/// How many of a remote's newest entries are read for a test whose notice did
/// not arrive: a test records a handful of entries after the one it waits
/// for.
const PROOF: NonZeroU8 = match NonZeroU8::new(16) {
    Some(page) => page,
    None => NonZeroU8::MIN,
};

/// The surface the person acted through, so a refusal is shown where the act
/// was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    Tray,
    Card,
    /// The window's page: a grant made, a setting, an import.
    Window,
    /// One line of the window: a capability on a remote, or a grant no remote
    /// has met.
    Line {
        remote: Option<RemoteId>,
        capability: Name,
    },
    /// The form for a definition being made or changed.
    Defining,
    /// One of the person's own definitions, where it is listed.
    Defined {
        kind: Kind,
        name: Name,
    },
}

/// How the interface stands to the person's core.
#[derive(Debug, PartialEq, Eq, Default)]
pub enum Core {
    /// No Hedwig is running for this person.
    #[default]
    Absent,
    /// A supervisor is there and its core is not answering yet, or the pipe
    /// is being opened.
    Starting,
    /// The last core broke down and its supervisor is starting another.
    /// `said` is the last line that core wrote.
    Restarting {
        cause: Breakdown,
        said: String,
    },
    /// A core is named and its pipe could not be opened; carries the
    /// client's own sentence.
    Unreachable(String),
    /// The core refused the greeting: another install's protocol.
    Refused(Refusal),
    Attached(Box<Attached>),
}

/// What is defined outside the person's document, as the core said it, and
/// the same definitions as the reference data and the catalogue the model's
/// own functions over a document take. A name two sources define differently
/// is in none of them: it defines nothing until all but one rename it.
#[derive(Debug, PartialEq, Eq)]
pub struct Vocabulary {
    pub definitions: Definitions,
    reference: Reference,
    /// `None` where the definitions name one thing twice, which the model
    /// refuses to build a catalogue of.
    catalogue: Option<Catalogue>,
}

impl Vocabulary {
    pub fn new(definitions: Definitions) -> Vocabulary {
        let reference = Reference {
            capabilities: definitions
                .capabilities
                .iter()
                .map(|defined| defined.definition.clone())
                .collect(),
            routes: definitions
                .routes
                .iter()
                .map(|defined| defined.definition.clone())
                .collect(),
            platforms: definitions
                .platforms
                .iter()
                .map(|defined| defined.definition.clone())
                .collect(),
            sets: definitions
                .sets
                .iter()
                .map(|defined| defined.definition.clone())
                .collect(),
        };
        let catalogue = Catalogue::new(reference.clone()).ok();
        Vocabulary {
            definitions,
            reference,
            catalogue,
        }
    }

    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    pub fn catalogue(&self) -> Option<&Catalogue> {
        self.catalogue.as_ref()
    }
}

/// What one remote's activity shows: its entries in the trail's order, as
/// many pages as the person asked for.
#[derive(Debug, PartialEq, Eq)]
pub struct Activity {
    pub remote: RemoteId,
    /// `None` while the first page is asked for.
    pub entries: Option<Vec<Entry>>,
    /// Whether the oldest page read was full, so an earlier one may follow.
    pub earlier: bool,
}

/// What an attached interface has been told. `None` is "asked, not yet
/// answered", which a surface shows as such and never as empty.
#[derive(Debug, PartialEq, Eq)]
pub struct Attached {
    pub version: String,
    /// How the core read this process from the pipe.
    pub you: Origin,
    pub status: Option<Status>,
    /// What needs the person, loudest first, as the core orders it.
    pub attention: Option<Vec<Needs>>,
    pub rows: Option<Vec<Row>>,
    /// When each returning channel is due to be opened again: its wait,
    /// counted from when the reply that said so arrived.
    pub due: BTreeMap<(RemoteId, Name), Instant>,
    /// Every setting with the statement it comes from, and whom to ask about
    /// what the organisation holds.
    pub settings: Option<Box<Settings>>,
    pub workstation: Option<Workstation>,
    pub catalogue: Option<Vocabulary>,
    pub document: Option<Document>,
    /// The activity of the one remote the person is reviewing.
    pub activity: Option<Activity>,
    /// What the last test asked from a place found, until another act is
    /// made from there.
    pub exercised: Option<(Place, Proof)>,
    /// Where a test was asked from, until what the remote's own tool did is
    /// known.
    pub testing: Option<Place>,
    /// The last act the core refused, with where it was made, until another
    /// act is made from there.
    pub refused: Option<(Place, Refusal)>,
    /// What of the organisation's holds the last change or import made from
    /// a place, until another act is made from there; empty where nothing
    /// holds it.
    pub held: Option<(Place, Vec<Holding>)>,
    /// What the last trial asked from a place would do, until another act
    /// is made from there.
    pub tried: Option<(Place, Tried)>,
    /// What a supporter would be given, asked from a place, until another
    /// act is made from there.
    pub bundle: Option<(Place, Box<Bundle>)>,
    /// The devices each capability's source holds, by capability, as last
    /// read: `None` while asked. Read when a surface first shows them, again
    /// when the person asks, and again whenever the core says what it would
    /// answer changed, which it says to the client that read them.
    pub devices: BTreeMap<Name, Option<Result<Vec<Lendable>, Refusal>>>,
    /// The workstation's serial ports as last read: `None` until a surface
    /// shows them, `Some(None)` while asked. Read and kept as the devices
    /// are.
    pub ports: Option<Option<Result<Vec<SerialPort>, Refusal>>>,
    /// The keys each SSH agent capability's source holds, by capability, as
    /// last read: `None` while asked. Read when the person asks, since asking
    /// an agent for its list can make a password manager ask them, and again
    /// when the core says they changed - which it knows only of keys it
    /// makes and deletes itself.
    pub agent_keys: AgentKeys,
}

impl Attached {
    /// The keys the workstation offers, the agents listed and the grants
    /// lend, by which a surface names a key.
    pub fn keyrings(&self) -> Keyrings<'_> {
        Keyrings::new(
            self.workstation.as_ref().map(|found| &found.keys[..]),
            self.workstation
                .as_ref()
                .map_or(&[][..], |found| &found.cards[..]),
        )
        .listing(&self.agent_keys)
        .lent(self.rows.as_deref().unwrap_or_default())
    }

    /// How long until `row`'s channel is opened again, as of `now`; `None`
    /// where it is not returning, or is due.
    pub fn left(&self, row: &Row, now: Instant) -> Option<Duration> {
        let due = self
            .due
            .get(&(row.remote.clone()?, row.capability.clone()))?;
        Some(due.saturating_duration_since(now)).filter(|left| !left.is_zero())
    }

    /// Keeps when `row`'s channel is due, as the reply carrying it arrived at
    /// `at`.
    fn told(&mut self, row: &Row, at: Instant) {
        let Some(remote) = row.remote.clone() else {
            return;
        };
        let key = (remote, row.capability.clone());
        match row.standing {
            Stands::Returning {
                wait: Some(wait), ..
            } => {
                self.due
                    .insert(key, at + Duration::from_secs(u64::from(wait.get())));
            }
            _ => {
                self.due.remove(&key);
            }
        }
    }

    fn new(version: String, you: Origin) -> Attached {
        Attached {
            version,
            you,
            status: None,
            attention: None,
            rows: None,
            due: BTreeMap::new(),
            settings: None,
            workstation: None,
            catalogue: None,
            document: None,
            activity: None,
            exercised: None,
            testing: None,
            refused: None,
            held: None,
            tried: None,
            bundle: None,
            devices: BTreeMap::new(),
            ports: None,
            agent_keys: BTreeMap::new(),
        }
    }
}

/// What the surfaces render.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct Seen {
    pub core: Core,
}

impl Seen {
    pub fn attached(&self) -> Option<&Attached> {
        match &self.core {
            Core::Attached(attached) => Some(attached),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum Event {
    /// The supervisor's record was read: at start, and whenever the folder it
    /// is in changed.
    Looked(Standing),
    /// The pipe the record names is open and is the person's own.
    Opened,
    /// It could not be opened; carries the client's own sentence.
    Unopened(String),
    /// A frame from the core, and when it arrived: what it says of time is
    /// counted from then.
    Frame(FromCore, Instant),
    /// The core closed the connection, or ended.
    Closed,
    /// The desktop was locked or unlocked, disconnected or reconnected. A
    /// viewer reports nothing of where the person is.
    Presence(Presence),
    /// The window that shows exposure was opened or closed, which decides
    /// what is kept fresh.
    Window(bool),
    /// The presence's icon is missing from the taskbar and the person has
    /// been told, or it is back. A viewer has no icon.
    Icon(Icon),
    /// The person asked for something.
    Wish(Place, Request),
    /// The person asked to try an unreachable core again.
    Retry,
    /// The person began reviewing one remote's activity, or stopped.
    Review(Option<RemoteId>),
    /// The person asked for the page of activity before the oldest shown.
    Earlier,
    /// A surface shows the devices a capability's source holds and has none
    /// read: they are read once.
    Devices(Name),
    /// A surface shows the workstation's serial ports and has none read:
    /// they are read once.
    Ports,
    /// The person chose to grant an SSH agent's keys, which are read once
    /// for the choice; elsewhere they are read only when the person asks.
    Keys(Name),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    /// Read the record again.
    Look,
    Open(PipeName),
    Send(ToCore),
    /// Close the connection.
    Hang,
    /// No core is attached, so what the person asked from this place was not
    /// done. Nothing is queued for later: an act nobody can see waiting is an
    /// act the person cannot take back.
    Undone(Place),
    /// Something now needs the person loudly enough to be said and not only
    /// shown. The core sends it to each client that watches its remote; this
    /// one announces it, or puts it on every surface.
    Raised(Needs),
    /// A request was served without asking, and this client is the one that
    /// announces it.
    Served(Served),
    /// What is seen changed.
    Render,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Asked {
    Hello,
    Presence,
    Icon,
    Status,
    Attention,
    Exposure,
    Settings,
    Workstation,
    Catalogue,
    Export,
    Activity {
        remote: RemoteId,
        before: Option<Seq>,
    },
    /// The newest entry of the remote a test is asked for, before it is:
    /// whatever the test records follows it.
    Baseline,
    /// The remote's newest entries, for a test whose notice did not arrive.
    Proof,
    Devices(Name),
    Ports,
    Keys(Name),
    Wish(Place),
}

/// What this client is to the core. The presence asks the person and says
/// where they are; the window shows what the core holds and is asked nothing,
/// so nothing is held for it or announced through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Role {
    #[default]
    Asks,
    Views,
}

/// A test asked for, until what the remote's tool did is known.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Exercising {
    place: Place,
    remote: RemoteId,
    capability: Name,
    /// The remote's newest entry before the test was asked; `None` until read.
    after: Option<Seq>,
}

/// The key the Hedwig whose files are in `folder` is claimed by at this
/// desktop - its presence and its window - which is the key its installation
/// is named by, so a Hedwig installed with `--folder` is one Hedwig to the
/// person wherever they meet it.
pub fn key(folder: &std::path::Path) -> String {
    hedwig_model::install::key(&folder.to_string_lossy())
}

/// The supervisor a record names, by its process number and when it was
/// created as a file time: what a client waits on to learn that Hedwig ended
/// while no core of it was attended, which rewrites nothing.
pub fn supervisor(standing: &Standing) -> Option<(u32, u64)> {
    match standing {
        Standing::Known(running) => Some((running.supervisor.process, running.supervisor.created)),
        Standing::Absent | Standing::Unsettled => None,
    }
}

#[derive(Debug, Default)]
pub struct Link {
    role: Role,
    seen: Seen,
    /// The pipe being opened, open, or last refused.
    pipe: Option<PipeName>,
    open: bool,
    next: u32,
    /// The core reads a client's next request only when it has answered the
    /// last, so one is outstanding at a time.
    waiting: Option<(u32, Asked)>,
    queue: VecDeque<(Asked, Request)>,
    /// What this desktop takes, as last told; the core counts an interface
    /// that has said nothing as present.
    presence: Option<Presence>,
    /// What the presence last said of its icon: said again to a core that
    /// greets it while the icon is missing, since a new run knows nothing of
    /// it.
    icon: Option<Icon>,
    window: bool,
    /// Whether a refusal the source's own tool mends is counted, for which
    /// the presence names that tool from what the capability is defined as.
    mending: bool,
    exercising: Option<Exercising>,
}

impl Link {
    /// The window's link: it greets as a viewer.
    pub fn viewer() -> Link {
        Link {
            role: Role::Views,
            ..Link::default()
        }
    }

    pub fn seen(&self) -> &Seen {
        &self.seen
    }

    pub fn handle(&mut self, event: Event) -> Vec<Effect> {
        let mut effects = Vec::new();
        match event {
            Event::Looked(standing) => self.looked(standing, &mut effects),
            Event::Opened => {
                self.open = true;
                self.next = 1;
                self.waiting = None;
                self.queue.clear();
                // The icon and the card are the person's for every remote
                // they have: nothing at the desktop attends fewer. The window
                // shows every remote too.
                let hello = Request::Hello {
                    protocol: PROTOCOL,
                    kind: match self.role {
                        Role::Asks => ClientKind::Interface,
                        Role::Views => ClientKind::Viewer,
                    },
                    attends: Remotes::Every,
                };
                self.queue.push_back((Asked::Hello, hello));
            }
            Event::Unopened(sentence) => {
                self.open = false;
                self.seen.core = Core::Unreachable(sentence);
            }
            Event::Frame(FromCore::Reply { id, reply }, at) => {
                self.replied(id, reply, at, &mut effects);
            }
            Event::Frame(FromCore::Notice(notice), _) => self.noticed(notice, &mut effects),
            Event::Closed => {
                self.forget();
                self.seen.core = Core::Starting;
                effects.push(Effect::Look);
            }
            Event::Presence(_) | Event::Icon(_) if self.role == Role::Views => {}
            Event::Presence(presence) => self.present(presence),
            Event::Icon(icon) => {
                self.icon = Some(icon);
                if self.seen.attached().is_some() {
                    self.queue.retain(|(asked, _)| *asked != Asked::Icon);
                    self.queue.push_back((Asked::Icon, Request::Icon(icon)));
                }
            }
            Event::Window(open) => {
                self.window = open;
                if open && self.seen.attached().is_some() {
                    self.ask_window();
                }
            }
            Event::Wish(place, request) => self.wished(place, request, &mut effects),
            Event::Retry => {
                if !self.open {
                    self.pipe = None;
                    effects.push(Effect::Look);
                }
            }
            Event::Review(remote) => {
                if let Core::Attached(attached) = &mut self.seen.core {
                    attached.activity = remote.map(|remote| Activity {
                        remote,
                        entries: None,
                        earlier: false,
                    });
                    self.ask_activity(None);
                }
            }
            Event::Devices(capability) => {
                if let Core::Attached(attached) = &mut self.seen.core
                    && !attached.devices.contains_key(&capability)
                {
                    self.ask_devices(capability);
                }
            }
            Event::Ports => {
                if let Core::Attached(attached) = &self.seen.core
                    && attached.ports.is_none()
                {
                    self.ask_ports();
                }
            }
            Event::Keys(capability) => {
                if let Core::Attached(attached) = &self.seen.core
                    && !attached.agent_keys.contains_key(&capability)
                {
                    self.ask_keys(capability);
                }
            }
            Event::Earlier => {
                let oldest = self
                    .seen
                    .attached()
                    .and_then(|attached| attached.activity.as_ref())
                    .filter(|activity| activity.earlier)
                    .and_then(|activity| activity.entries.as_ref()?.first())
                    .map(|entry| entry.seq);
                if let Some(oldest) = oldest {
                    self.ask_activity(Some(oldest));
                }
            }
        }
        self.pump(&mut effects);
        effects.push(Effect::Render);
        effects
    }

    /// What the person asked for from `place`: what was last said there goes,
    /// and the request is queued, a test's after the remote's newest entry
    /// it is measured from. With no core, nothing is kept to do later.
    fn wished(&mut self, place: Place, request: Request, effects: &mut Vec<Effect>) {
        let Core::Attached(attached) = &mut self.seen.core else {
            effects.push(Effect::Undone(place));
            return;
        };
        // Reading the devices again changes nothing, so it leaves what was
        // said at the place standing.
        if let Request::Devices(capability) = request {
            self.ask_devices(capability);
            return;
        }
        if matches!(request, Request::Ports) {
            self.ask_ports();
            return;
        }
        if let Request::Keys(capability) = request {
            self.ask_keys(capability);
            return;
        }
        let from = |said: Option<&Place>| said == Some(&place);
        if from(attached.refused.as_ref().map(|(at, _)| at)) {
            attached.refused = None;
        }
        if from(attached.held.as_ref().map(|(at, _)| at)) {
            attached.held = None;
        }
        if from(attached.tried.as_ref().map(|(at, _)| at)) {
            attached.tried = None;
        }
        if from(attached.bundle.as_ref().map(|(at, _)| at)) {
            attached.bundle = None;
        }
        if from(attached.exercised.as_ref().map(|(at, _)| at)) {
            attached.exercised = None;
        }
        if let Request::Exercise { remote, capability } = &request {
            self.exercising = Some(Exercising {
                place: place.clone(),
                remote: remote.clone(),
                capability: capability.clone(),
                after: None,
            });
            self.queue.push_back((
                Asked::Baseline,
                Request::Activity {
                    remote: Selector::Only(remote.clone()),
                    before: None,
                    limit: NonZeroU8::MIN,
                },
            ));
        }
        self.queue.push_back((Asked::Wish(place), request));
    }

    /// A page of a remote's activity, for what asked for it.
    fn paged(&mut self, asked: Asked, page: Vec<Entry>) {
        let Core::Attached(attached) = &mut self.seen.core else {
            return;
        };
        match asked {
            Asked::Activity { remote, before } => {
                if let Some(activity) = &mut attached.activity
                    && activity.remote == remote
                {
                    let full = page.len() == usize::from(PAGE.get());
                    let entries = activity.entries.get_or_insert_with(Vec::new);
                    let first = entries.is_empty();
                    // The newest page again, or one before the oldest: each
                    // entry once, in the trail's order.
                    entries.extend(page);
                    entries.sort_by_key(|entry| entry.seq);
                    entries.dedup_by_key(|entry| entry.seq);
                    if before.is_some() || first {
                        activity.earlier = full;
                    }
                }
            }
            Asked::Baseline => {
                if let Some(exercising) = &mut self.exercising {
                    exercising.after = Some(page.last().map_or(Seq(0), |entry| entry.seq));
                }
            }
            Asked::Proof => {
                let found = self.exercising.as_ref().and_then(|exercising| {
                    let after = exercising.after?;
                    page.iter().find_map(|entry| match &entry.event {
                        Happened::Exercised {
                            capability, proof, ..
                        } if entry.seq > after && *capability == exercising.capability => {
                            Some(proof.clone())
                        }
                        _ => None,
                    })
                });
                if let Some(proof) = found {
                    self.exercised(proof);
                }
            }
            _ => {}
        }
    }

    fn present(&mut self, presence: Presence) {
        let was = self.presence.unwrap_or(Presence::Present);
        self.presence = Some(presence);
        if presence != was && self.seen.attached().is_some() {
            // Ahead of everything queued: a request held where the person can
            // no longer be asked is refused by this.
            self.queue
                .push_front((Asked::Presence, Request::Presence(presence)));
        }
    }

    fn forget(&mut self) {
        self.pipe = None;
        self.open = false;
        self.waiting = None;
        self.queue.clear();
        self.exercising = None;
        self.mending = false;
    }

    /// Asks for the page of the reviewed remote's activity before `before`,
    /// or its newest page.
    fn ask_activity(&mut self, before: Option<Seq>) {
        let Some(remote) = self
            .seen
            .attached()
            .and_then(|attached| attached.activity.as_ref())
            .map(|activity| activity.remote.clone())
        else {
            return;
        };
        self.enqueue(
            Asked::Activity {
                remote: remote.clone(),
                before,
            },
            Request::Activity {
                remote: Selector::Only(remote),
                before,
                limit: PAGE,
            },
        );
    }

    /// The devices `capability`'s source holds, read afresh; what was read
    /// before stays shown until they are.
    fn ask_devices(&mut self, capability: Name) {
        if let Core::Attached(attached) = &mut self.seen.core {
            attached.devices.entry(capability.clone()).or_insert(None);
        }
        self.enqueue(
            Asked::Devices(capability.clone()),
            Request::Devices(capability),
        );
    }

    /// The keys `capability`'s agent holds, read afresh; what was read before
    /// stays shown until they are.
    fn ask_keys(&mut self, capability: Name) {
        if let Core::Attached(attached) = &mut self.seen.core {
            attached
                .agent_keys
                .entry(capability.clone())
                .or_insert(None);
        }
        self.enqueue(Asked::Keys(capability.clone()), Request::Keys(capability));
    }

    /// The workstation's serial ports, read afresh; what was read before
    /// stays shown until they are.
    fn ask_ports(&mut self) {
        if let Core::Attached(attached) = &mut self.seen.core
            && attached.ports.is_none()
        {
            attached.ports = Some(None);
        }
        self.enqueue(Asked::Ports, Request::Ports);
    }

    /// What a test found, from its notice or from the remote's activity.
    fn exercised(&mut self, proof: Proof) {
        if let (Some(exercising), Core::Attached(attached)) =
            (self.exercising.take(), &mut self.seen.core)
        {
            if attached.testing.as_ref() == Some(&exercising.place) {
                attached.testing = None;
            }
            attached.exercised = Some((exercising.place, proof));
        }
    }

    fn looked(&mut self, standing: Standing, effects: &mut Vec<Effect>) {
        let core = match standing {
            Standing::Absent => None,
            // A record being written says nothing yet.
            Standing::Unsettled => Some(CoreState::Starting),
            Standing::Known(running) => Some(running.core),
        };
        match core {
            Some(CoreState::Serving { pipe, .. }) => {
                if self.pipe.as_ref() == Some(&pipe) {
                    return;
                }
                if self.open {
                    effects.push(Effect::Hang);
                }
                self.forget();
                self.pipe = Some(pipe.clone());
                self.seen.core = Core::Starting;
                effects.push(Effect::Open(pipe));
            }
            // While this connection is open its end is what says the core
            // went; the record only says what comes next.
            Some(_) if self.open => {}
            Some(CoreState::Restarting { cause, said }) => {
                self.forget();
                self.seen.core = Core::Restarting { cause, said };
            }
            Some(CoreState::Starting) => {
                self.forget();
                self.seen.core = Core::Starting;
            }
            None => {
                if self.open {
                    effects.push(Effect::Hang);
                }
                self.forget();
                self.seen.core = Core::Absent;
            }
        }
    }

    fn enqueue(&mut self, asked: Asked, request: Request) {
        if !self.queue.iter().any(|(queued, _)| *queued == asked) {
            self.queue.push_back((asked, request));
        }
    }

    /// Everything an act of the person's can change. The workstation is not
    /// among it: a reading of the core's that the act led to is told to the
    /// client that acted as `Stale(Workstation)`.
    fn ask_always(&mut self) {
        self.enqueue(Asked::Status, Request::Status);
        self.enqueue(Asked::Attention, Request::Attention);
        self.ask_exposure();
        self.ask_settings();
        self.ask_activity(None);
    }

    fn ask_exposure(&mut self) {
        self.enqueue(Asked::Exposure, Request::Exposure);
    }

    fn ask_settings(&mut self) {
        self.enqueue(
            Asked::Settings,
            Request::Settings {
                remotes: Vec::new(),
            },
        );
    }

    /// What the window shows of the configuration: the person's document,
    /// and what is defined outside it, which an organisation's statement or
    /// a definition of the person's that collides with one changes.
    fn ask_configuration(&mut self) {
        self.enqueue(Asked::Catalogue, Request::Catalogue);
        self.enqueue(Asked::Export, Request::Export);
    }

    /// Whether what the person defined is kept fresh: the window shows it, or
    /// the presence names a remedy from it while a refusal it mends is
    /// counted.
    fn defines(&self) -> bool {
        self.window || self.mending
    }

    fn ask_window(&mut self) {
        self.enqueue(Asked::Workstation, Request::Workstation);
        self.enqueue(Asked::Catalogue, Request::Catalogue);
        self.enqueue(Asked::Export, Request::Export);
    }

    fn pump(&mut self, effects: &mut Vec<Effect>) {
        if !self.open || self.waiting.is_some() {
            return;
        }
        if let Some((asked, request)) = self.queue.pop_front() {
            let id = self.next;
            // Zero is the core's own, for a frame it could not read.
            self.next = self.next.wrapping_add(1).max(1);
            if let (Asked::Wish(place), Request::Exercise { .. }, Core::Attached(attached)) =
                (&asked, &request, &mut self.seen.core)
            {
                attached.testing = Some(place.clone());
            }
            self.waiting = Some((id, asked));
            effects.push(Effect::Send(ToCore { id, request }));
        }
    }

    /// The core's answer to the greeting.
    fn greeted(&mut self, reply: Result<Reply, Refusal>, effects: &mut Vec<Effect>) {
        match reply {
            Ok(Reply::Welcome { version, you, .. }) => {
                self.seen.core = Core::Attached(Box::new(Attached::new(version, you)));
                if let Some(presence) = self
                    .presence
                    .filter(|presence| *presence != Presence::Present)
                {
                    self.queue
                        .push_back((Asked::Presence, Request::Presence(presence)));
                }
                if let Some(icon @ Icon::Missing(_)) = self.icon {
                    self.queue.push_back((Asked::Icon, Request::Icon(icon)));
                }
                self.ask_always();
                // The keys a request and the rows name, and what answers for
                // each line's capability.
                self.enqueue(Asked::Workstation, Request::Workstation);
                if self.window {
                    self.ask_window();
                }
            }
            Ok(_) => {
                effects.push(Effect::Hang);
                self.forget();
                self.seen.core = Core::Starting;
                effects.push(Effect::Look);
            }
            Err(refusal) => {
                // The pipe's name is kept, so the same core is not
                // greeted again; a new core has a new name.
                effects.push(Effect::Hang);
                self.open = false;
                self.queue.clear();
                self.seen.core = Core::Refused(refusal);
            }
        }
    }

    fn replied(
        &mut self,
        id: u32,
        reply: Result<Reply, Refusal>,
        at: Instant,
        effects: &mut Vec<Effect>,
    ) {
        let asked = match self.waiting.take() {
            Some((waiting, asked)) if waiting == id => asked,
            // A reply nobody is waiting for, or the core saying it could not
            // read a frame: nothing after it can be matched to a request.
            _ => {
                effects.push(Effect::Hang);
                self.forget();
                self.seen.core = Core::Starting;
                effects.push(Effect::Look);
                return;
            }
        };
        if asked == Asked::Hello {
            self.greeted(reply, effects);
            return;
        }
        let Core::Attached(attached) = &mut self.seen.core else {
            return;
        };
        // A test is answered at once; what the tool did follows as a notice.
        if matches!(&asked, Asked::Wish(place) if attached.testing.as_ref() == Some(place))
            && reply.is_err()
        {
            attached.testing = None;
            self.exercising = None;
        }
        match (asked, reply) {
            (Asked::Status, Ok(Reply::Status(status))) => attached.status = Some(status),
            (Asked::Attention, Ok(Reply::Attention(items))) => {
                // The source's own tool that stops a program of the person's
                // is named from what the capability is defined as: read once
                // a refusal it mends is counted, and kept fresh while one is.
                let mending = items.iter().any(mendable);
                let began = mending && !self.mending;
                self.mending = mending;
                attached.attention = Some(items);
                if began && !self.window {
                    self.ask_configuration();
                }
            }
            (Asked::Exposure, Ok(Reply::Exposure(rows))) => {
                attached.due.clear();
                for row in &rows {
                    attached.told(row, at);
                }
                attached.rows = Some(rows);
            }
            (Asked::Settings, Ok(Reply::Settings(settings))) => attached.settings = Some(settings),
            (Asked::Workstation, Ok(Reply::Workstation(found))) => {
                attached.workstation = Some(found);
            }
            (Asked::Catalogue, Ok(Reply::Catalogue(definitions))) => {
                attached.catalogue = Some(Vocabulary::new(definitions));
            }
            (
                asked @ (Asked::Activity { .. } | Asked::Baseline | Asked::Proof),
                Ok(Reply::Activity(page)),
            ) => self.paged(asked, page),
            (Asked::Export, Ok(Reply::Document(document))) => {
                attached.document = Some(*document);
            }
            (Asked::Devices(capability), Ok(Reply::Devices(listed))) => {
                attached.devices.insert(capability, Some(Ok(listed)));
            }
            (Asked::Devices(capability), Err(refusal)) => {
                attached.devices.insert(capability, Some(Err(refusal)));
            }
            (Asked::Keys(capability), Ok(Reply::Keys(listed))) => {
                attached.agent_keys.insert(capability, Some(Ok(listed)));
            }
            (Asked::Keys(capability), Err(refusal)) => {
                attached.agent_keys.insert(capability, Some(Err(refusal)));
            }
            (Asked::Ports, Ok(Reply::Ports(listed))) => attached.ports = Some(Some(Ok(listed))),
            (Asked::Ports, Err(refusal)) => attached.ports = Some(Some(Err(refusal))),
            (Asked::Wish(place), Err(refusal)) => attached.refused = Some((place, refusal)),
            (Asked::Wish(place), Ok(reply)) => {
                match reply {
                    Reply::Row(row) => {
                        attached.told(&row, at);
                        if let Some(rows) = &mut attached.rows
                            && let Some(known) = rows.iter_mut().find(|known| {
                                known.remote == row.remote && known.capability == row.capability
                            })
                        {
                            *known = *row;
                        }
                    }
                    Reply::Changed { held, .. } => attached.held = Some((place, held)),
                    // A trial changes nothing, so nothing is asked again.
                    Reply::Tried(tried) => {
                        attached.tried = Some((place, *tried));
                        return;
                    }
                    // Assembled from what the core holds; it changes nothing.
                    Reply::Bundle(bundle) => {
                        attached.bundle = Some((place, bundle));
                        return;
                    }
                    _ => {}
                }
                self.ask_always();
                if self.defines() {
                    self.ask_configuration();
                }
            }
            // A refused read leaves what was shown as it was.
            _ => {}
        }
    }

    fn noticed(&mut self, notice: Notice, effects: &mut Vec<Effect>) {
        let Core::Attached(attached) = &mut self.seen.core else {
            return;
        };
        match notice {
            Notice::Raised(needs) => {
                if let Some(items) = &mut attached.attention
                    && !items.contains(&needs)
                {
                    items.push(needs.clone());
                    // Loudest first, as the core orders what it answers.
                    items.sort_by_key(|needs| std::cmp::Reverse(needs.volume));
                }
                if needs.volume != Volume::Shown {
                    effects.push(Effect::Raised(needs));
                }
                self.enqueue(Asked::Attention, Request::Attention);
            }
            Notice::Served(served) => effects.push(Effect::Served(served)),
            Notice::Exercised(Exercised {
                remote,
                capability,
                proof,
            }) => {
                if self.exercising.as_ref().is_some_and(|exercising| {
                    exercising.remote == remote && exercising.capability == capability
                }) {
                    self.exercised(proof);
                }
            }
            Notice::Withdrawn(over) => {
                if let Some(items) = &mut attached.attention {
                    items.retain(|needs| match (&needs.attention, over) {
                        (Attention::Request { request, .. }, Withdrawn::Request(gone)) => {
                            *request != gone
                        }
                        (Attention::Prompt { prompt, .. }, Withdrawn::Prompt(gone)) => {
                            *prompt != gone
                        }
                        _ => true,
                    });
                }
                self.enqueue(Asked::Attention, Request::Attention);
            }
            Notice::Stale(Topic::Status) => self.enqueue(Asked::Status, Request::Status),
            Notice::Stale(Topic::Workstation) => {
                self.enqueue(Asked::Workstation, Request::Workstation);
            }
            Notice::Stale(Topic::Exposure) => {
                self.ask_exposure();
                self.ask_activity(None);
                // A test whose notice did not fit is read from its remote's
                // activity, once the test has been recorded.
                if let Some(Exercising {
                    remote,
                    after: Some(_),
                    ..
                }) = &self.exercising
                {
                    let remote = remote.clone();
                    self.enqueue(
                        Asked::Proof,
                        Request::Activity {
                            remote: Selector::Only(remote),
                            before: None,
                            limit: PROOF,
                        },
                    );
                }
            }
            Notice::Stale(Topic::Attention) => self.enqueue(Asked::Attention, Request::Attention),
            // Told only to the client that read the list: read again what is
            // shown.
            Notice::Stale(Topic::Devices(capability)) => {
                if attached.devices.contains_key(&capability) {
                    self.ask_devices(capability);
                }
            }
            Notice::Stale(Topic::Ports) => {
                if attached.ports.is_some() {
                    self.ask_ports();
                }
            }
            Notice::Stale(Topic::Keys(capability)) => {
                if attached.agent_keys.contains_key(&capability) {
                    self.ask_keys(capability);
                }
            }
            Notice::Stale(Topic::Configuration) => {
                self.ask_settings();
                if self.defines() {
                    self.ask_configuration();
                }
            }
            // The interface follows nothing: what it shows of the trail it
            // asks for a page at a time.
            Notice::Recorded(_) => {}
        }
    }
}

/// Whether `needs` is a refusal of a program that may be the person's, which the
/// source's own tool can stop (`Remedy::of`).
fn mendable(needs: &Needs) -> bool {
    matches!(
        needs.attention,
        Attention::Refused {
            refusal: Refusal::SourceUnavailable {
                failure: Failure::Unidentified | Failure::Confined,
                ..
            },
            ..
        }
    )
}
