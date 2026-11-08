//! The window's one component: the link to the core, what is shown from it,
//! and what the person does there.
//!
//! Every act the window offers is `hedwig_view`'s. A callback names the act
//! by the line it stands on and its label; the act itself is taken from what
//! was last shown when the message arrives, so what is carried out is what
//! the person was looking at, or nothing where it has gone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hedwig_model::config::Document;
use hedwig_model::process::RECORD;
use hedwig_model::protocol::{FromCore, Request};
use hedwig_model::remote::RemoteId;
use hedwig_model::text::{Name, SshKey};
use hedwig_model::trail::Seq;
use hedwig_shell::record::Watch;
use hedwig_shell::{clock, window as one};
use hedwig_view::act::Act;
use hedwig_view::define::{self, Definitions, Kind};
use hedwig_view::exposure::{Board, Group, Shown};
use hedwig_view::grant::{Aim, Draft, Form};
use hedwig_view::link::{self, Attached, Effect, Event, Link, Place};
use hedwig_view::setting::{Sheet, Wide};
use hedwig_view::trial::{self, Outcome};
use hedwig_view::{bundle, exposure, resource, words};
use windows_reactor::{Component, ComponentContext, View, ViewContext};

use crate::core::{self, Connection, Reading};
use crate::draft::{self, Kept, Making};
use crate::{files, show};

/// How long the window is looked for once made: WinUI shows it within this.
const SHOWN: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Input {
    pub(crate) folder: PathBuf,
    pub(crate) title: String,
    /// The window is made where the person left it, so its first size is
    /// not set.
    pub(crate) placed: bool,
}

/// Where an act stands on the screen, and its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum At {
    /// The act offered while no core answers.
    Off,
    Need {
        sentence: String,
        label: String,
    },
    Line {
        remote: Option<RemoteId>,
        capability: Name,
        label: String,
    },
    Policy {
        remote: Option<RemoteId>,
        capability: Name,
        when: String,
        label: String,
    },
    /// A rule for one key that no statement names yet, under a policy.
    KeyRule {
        remote: Option<RemoteId>,
        capability: Name,
        when: String,
        key: String,
        label: String,
    },
    /// Lending a device on a grant's line, or no longer, by the device's
    /// words there: its act's label says whether it is asked first.
    Device {
        remote: Option<RemoteId>,
        capability: Name,
        device: String,
    },
    /// Lending an agent's key on a grant's line, or no longer.
    Key {
        remote: Option<RemoteId>,
        capability: Name,
        key: SshKey,
    },
    /// A choice of a setting, or taking the person's statement away; the
    /// section is a remote's or a route's name, or none for the workstation.
    Setting {
        section: Option<String>,
        name: &'static str,
        label: String,
    },
    /// An act on one of the person's own definitions.
    Defined {
        kind: Kind,
        name: Name,
        label: String,
    },
    /// An act on an entry of a remote's activity, which changes the grant of
    /// `capability` to it.
    Entry {
        remote: RemoteId,
        capability: Name,
        seq: Seq,
        label: String,
    },
}

impl At {
    /// Where an act chosen here is made, so its refusal and what it found are
    /// shown there.
    fn place(&self) -> Place {
        match self {
            At::Line {
                remote, capability, ..
            }
            | At::Policy {
                remote, capability, ..
            }
            | At::KeyRule {
                remote, capability, ..
            }
            | At::Device {
                remote, capability, ..
            }
            | At::Key {
                remote, capability, ..
            } => Place::Line {
                remote: remote.clone(),
                capability: capability.clone(),
            },
            At::Entry {
                remote, capability, ..
            } => Place::Line {
                remote: Some(remote.clone()),
                capability: capability.clone(),
            },
            At::Defined { kind, name, .. } => Place::Defined {
                kind: *kind,
                name: name.clone(),
            },
            At::Off | At::Need { .. } | At::Setting { .. } => Place::Window,
        }
    }
}

/// An edit of the grant being made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Edit {
    Capability(usize),
    Aim(Aim),
    Route(usize),
    Set(usize),
    Typed(String),
    Activation(usize),
    Writes(bool),
    Acknowledge(&'static str, bool),
    /// A device of the form's list, by its place there, lent or not.
    Lend(usize, bool),
    /// Every device, now and later, or none.
    Every(bool),
    /// A key of the form's list, by its place there, lent or not.
    LendKey(usize, bool),
    /// What the person typed for the hosts that key may log in to.
    Hosts(usize, String),
    /// Ask the agent which keys it holds.
    AskKeys,
}

pub(crate) enum Message {
    Looked(Option<hedwig_client::Standing>),
    /// The record changed or the supervisor it named ended: the record as
    /// read then, and the watch, to wait again; none once it cannot.
    Watched(Option<Box<Watch>>, Option<hedwig_client::Standing>),
    Opened(u64, Result<Connection, String>),
    Read(Box<Reading>, Option<(FromCore, Instant)>),
    Wrote(u64, bool),
    Chose(At),
    Confirmed(bool),
    /// Hedwig was started, or could not be: the reason.
    Started(Option<String>),
    Found(PathBuf, Kept<Draft>),
    /// A definition being made, as kept when the window last closed.
    FoundDefinition(PathBuf, Kept<define::Draft>),
    Kept(Result<(), String>),
    Begin,
    Edit(Edit),
    Submit,
    Discard,
    Typing {
        key: String,
        field: usize,
        text: String,
    },
    SetTyped {
        key: String,
        wide: Wide,
    },
    Export,
    Exported(Result<Option<PathBuf>, String>),
    Import,
    Chosen(Result<Option<Document>, String>),
    MakeImport,
    CancelImport,
    /// What a supporter needs: asked of the core, shown, saved or put away.
    MakeBundle,
    SaveBundle,
    SavedBundle(Result<Option<PathBuf>, String>),
    CancelBundle,
    Dismiss,
    /// A choice that was taken away rather than made.
    Nothing,
    Expanded {
        key: String,
        open: bool,
    },
    /// A countdown's words are due to change; carries which wait it was.
    Clock(u64),
    /// Define one of a kind, or change the person's own of that name.
    Define {
        kind: Kind,
        name: Option<Name>,
    },
    /// An edit of the definition being made.
    Defining(define::Edit),
    /// Define the kind of capability the grant form offers at this place,
    /// which nothing known yet is.
    DefineFromGrant(usize),
    /// Define the person's own from the capability the grant form has
    /// chosen, which leaves its port unstated; once made, it is the one
    /// granted.
    Complete,
    /// Read the workstation's serial ports again for the definition being
    /// made.
    PortsAgain,
    /// The page of the reviewed remote's activity before the oldest shown.
    Earlier,
    /// The key chosen under a policy to give its own rule, by the policy's
    /// place and the key's place among those offered.
    KeyChosen {
        policy: String,
        at: usize,
    },
    /// Lend a key on a line only for logging in to the hosts typed beside
    /// it, or for anything where none is.
    Restrict {
        remote: Option<RemoteId>,
        capability: Name,
        key: SshKey,
    },
    DefineSubmit,
    DefineDiscard,
    /// The window is on the screen: its handle, or none if it never came.
    Shown(Option<isize>),
}

/// A confirmation the window asks with WinUI's own dialog.
pub(crate) struct Asking {
    pub(crate) verb: String,
    /// What the dialog's button that carries it out says.
    pub(crate) answer: String,
    pub(crate) consequence: String,
    /// The act, until the person answers.
    request: Option<Request>,
    /// Where the act was chosen, which is where its refusal is shown.
    place: Place,
}

impl Asking {
    /// Whether the dialog is up. An answered one stays in the view, closed
    /// and with its words, since reactor 0.100.0 hides a dialog only when
    /// told it is closed, and one that leaves the view stays on the screen.
    pub(crate) fn open(&self) -> bool {
        self.request.is_some()
    }
}

pub(crate) struct Window {
    folder: PathBuf,
    title: String,
    link: Link,
    turns: u64,
    connection: Option<Connection>,
    /// What the window shows, made again after every event.
    pub(crate) shown: exposure::Window,
    pub(crate) sheet: Option<Sheet>,
    /// The grant being made: the person's partial input, kept on disk.
    pub(crate) draft: Option<Draft>,
    kept: Option<PathBuf>,
    /// The grant being made was asked of the core, and its answer is awaited.
    submitted: bool,
    pub(crate) asking: Option<Asking>,
    /// What the person has typed into a setting, by the setting's key.
    pub(crate) typing: BTreeMap<String, Vec<String>>,
    /// Why what was typed into a setting is not one of its values.
    pub(crate) invalid: Option<(String, String)>,
    /// A configuration chosen to import, while the person sees its trial.
    pub(crate) importing: Option<Document>,
    /// Whether what a supporter needs is asked for, or shown to be saved.
    pub(crate) bundling: Gathering,
    /// What the window says once, until the person's next act.
    pub(crate) said: Option<String>,
    /// The disclosures the person has opened, by their header.
    pub(crate) expanded: BTreeSet<String>,
    /// The key chosen under each policy to give its own rule, by the
    /// policy's place: a view of the person's, kept across a refresh.
    pub(crate) keyed: BTreeMap<String, usize>,
    /// Whether the shell's dialog for choosing a file is up: one at a time,
    /// whatever reaches the window while it is.
    choosing: bool,
    /// The wait for a countdown's words to change, by its number, and when
    /// it ends: one at a time, a later one replacing it.
    clock: Option<(u64, Instant)>,
    waits: u64,
    /// The definition being made or changed: the person's partial input,
    /// kept across every refresh, and on disk, until made or discarded.
    pub(crate) defining: Option<define::Draft>,
    kept_definition: Option<PathBuf>,
    /// The definition being made was asked of the core, and its answer is
    /// awaited.
    defined: bool,
    /// The capability the grant being made had chosen, which leaves its
    /// port unstated, where the definition being made completes it: the
    /// definition is chosen in its place once made.
    completing: Option<Name>,
    /// The executable's icons, given to the window once it is on the screen.
    named: Option<one::Named>,
}

/// The act offered as `label`, taken out of `shown`.
fn pick(shown: &mut Vec<Shown>, label: &str) -> Option<(String, Act)> {
    let place = shown
        .iter()
        .position(|act| matches!(act, Shown::Offered { label: known, .. } if known == label))?;
    match shown.remove(place) {
        Shown::Offered { label, act } => Some((label, act)),
        Shown::Withheld { .. } => None,
    }
}

/// An act on a grant's line by its label - the line's own, what it lends of
/// a server's devices or an agent's keys, or lending one key for anything -
/// taken out of what was shown.
fn line_act(
    groups: &mut [Group],
    remote: Option<&RemoteId>,
    capability: &Name,
    label: &str,
) -> Option<(String, Act)> {
    let line = groups
        .iter_mut()
        .flat_map(|group| group.lines.iter_mut())
        .find(|line| line.remote.as_ref() == remote && line.capability == *capability)?;
    if let Some(found) = pick(&mut line.acts, label) {
        return Some(found);
    }
    if let Some(found) = line
        .lending
        .as_mut()
        .and_then(|lending| pick(&mut lending.acts, label))
    {
        return Some(found);
    }
    let keys = line.keys.as_mut()?;
    if let Some(found) = pick(&mut keys.acts, label) {
        return Some(found);
    }
    let key = keys.keys.iter_mut().find(
        |key| matches!(&key.anywhere, Some(Shown::Offered { label: known, .. }) if known == label),
    )?;
    match key.anywhere.take() {
        Some(Shown::Offered { label, act }) => Some((label, act)),
        _ => None,
    }
}

/// A choice of a setting, or taking the person's statement away, by its
/// label, taken out of the sheet.
fn setting_act(
    sheet: &mut Sheet,
    section: Option<&str>,
    name: &str,
    label: &str,
) -> Option<(String, Act)> {
    let settings = match section {
        None => &mut sheet.workstation,
        Some(section) => sheet
            .remotes
            .iter_mut()
            .find(|of| of.of.to_string() == section)
            .map(|of| &mut of.settings)
            .or_else(|| {
                sheet
                    .routes
                    .iter_mut()
                    .find(|of| of.of.to_string() == section)
                    .map(|of| &mut of.settings)
            })?,
    };
    let setting = settings.iter_mut().find(|setting| setting.name == name)?;
    if let Some(Shown::Offered { label: known, .. }) = &setting.clear
        && known == label
    {
        return match setting.clear.take() {
            Some(Shown::Offered { label, act }) => Some((label, act)),
            _ => None,
        };
    }
    pick(&mut setting.choices, label)
}

/// An act under a line's policy by its label - the policy's own, or one
/// key's rule - taken out of what was shown.
fn policy_act(
    groups: &mut [Group],
    (remote, capability, when): (Option<&RemoteId>, &Name, &str),
    key: Option<&str>,
    label: &str,
) -> Option<(String, Act)> {
    let policy = groups
        .iter_mut()
        .flat_map(|group| group.lines.iter_mut())
        .find(|line| line.remote.as_ref() == remote && line.capability == *capability)?
        .policy
        .iter_mut()
        .find(|policy| policy.when == when)?;
    match key {
        None => pick(&mut policy.changes, label),
        Some(key) => pick(
            &mut policy.keys.iter_mut().find(|rule| rule.key == key)?.changes,
            label,
        ),
    }
}

/// The act of one key on a grant's line, taken out of what was shown.
fn key_act(
    groups: &mut [Group],
    remote: Option<&RemoteId>,
    capability: &Name,
    key: &SshKey,
) -> Option<(String, Act)> {
    let line = groups
        .iter_mut()
        .flat_map(|group| group.lines.iter_mut())
        .find(|line| line.remote.as_ref() == remote && line.capability == *capability)?;
    let shown = line
        .keys
        .as_mut()?
        .keys
        .iter_mut()
        .find(|shown| shown.key == *key)?;
    match shown.act.take() {
        Some(Shown::Offered { label, act }) => Some((label, act)),
        _ => None,
    }
}

/// The key a line's hosts are typed under.
pub(crate) fn hosts_key(remote: Option<&RemoteId>, capability: &Name, key: &SshKey) -> String {
    format!(
        "hosts/{}/{capability}/{key}",
        remote.map(ToString::to_string).unwrap_or_default()
    )
}

/// The act of one device on a grant's line, taken out of what was shown.
fn device_act(
    groups: &mut [Group],
    remote: Option<&RemoteId>,
    capability: &Name,
    device: &str,
) -> Option<(String, Act)> {
    let line = groups
        .iter_mut()
        .flat_map(|group| group.lines.iter_mut())
        .find(|line| line.remote.as_ref() == remote && line.capability == *capability)?;
    let shown = line
        .lending
        .as_mut()?
        .devices
        .iter_mut()
        .find(|shown| shown.label == device)?;
    match shown.act.take() {
        Some(Shown::Offered { label, act }) => Some((label, act)),
        _ => None,
    }
}

fn written(at: hedwig_model::trail::Timestamp) -> String {
    clock::written(at.0)
}

/// The key a typed setting's text is kept by.
pub(crate) fn key(section: Option<&str>, name: &str) -> String {
    format!("{}/{name}", section.unwrap_or_default())
}

impl Window {
    /// Brings what is shown up to date; returns whether the grant being
    /// made changed by it, and is to be kept.
    fn refresh(&mut self) -> bool {
        let mut regranted = false;
        self.shown = exposure::Window::of(self.link.seen(), &written, Instant::now());
        let attached = self.link.seen().attached();
        self.sheet = attached.and_then(|attached| {
            attached.settings.as_deref().map(|settings| {
                Sheet::of(
                    settings,
                    attached.document.as_ref(),
                    attached.catalogue.as_ref(),
                    attached.keyrings(),
                )
            })
        });
        if self.defined
            && let Some(attached) = attached
        {
            if attached
                .held
                .as_ref()
                .is_some_and(|(place, _)| *place == Place::Defining)
            {
                let made = self.defining.as_ref().and_then(define::Draft::named);
                self.defined = false;
                self.defining = None;
                if let Some(place) = self.kept_definition.clone() {
                    let _ = draft::forget(&place);
                }
                // The person's own, defined from the preset the grant had
                // chosen, is now what the grant grants.
                if self.completing.take().is_some()
                    && let (Some(made), Some(grant), Some(vocabulary), Some(document)) = (
                        made,
                        self.draft.as_mut(),
                        &attached.catalogue,
                        &attached.document,
                    )
                {
                    grant.choose_capability(made, vocabulary.reference(), document);
                    regranted = true;
                }
            } else if attached
                .refused
                .as_ref()
                .is_some_and(|(place, _)| *place == Place::Defining)
            {
                self.defined = false;
            }
        }
        if self.submitted
            && let Some(attached) = attached
        {
            if attached
                .held
                .as_ref()
                .is_some_and(|(place, _)| *place == Place::Window)
            {
                // The grant was made: what was kept of it is given up.
                self.submitted = false;
                self.draft = None;
                if let Some(place) = self.kept.clone() {
                    let _ = draft::forget(&place);
                }
            } else if attached
                .refused
                .as_ref()
                .is_some_and(|(place, _)| *place == Place::Window)
            {
                self.submitted = false;
            }
        }
        regranted
    }

    /// Waits until what is shown changes by the clock alone, where it does
    /// sooner than a wait already running ends.
    fn tick(&mut self, context: &ComponentContext<Self>) {
        let Some(changes) = self.shown.changes else {
            self.clock = None;
            return;
        };
        let due = Instant::now() + changes;
        if self.clock.is_some_and(|(_, ends)| ends <= due) {
            return;
        }
        self.waits += 1;
        let wait = self.waits;
        self.clock = Some((wait, due));
        // A whole millisecond past the change, so the words read after it.
        let sleep = changes + Duration::from_millis(1);
        let _ = context.spawn_background(move |_| {
            std::thread::sleep(sleep);
            Message::Clock(wait)
        });
    }

    /// Hands the link an event and carries out what it asks for.
    fn step(&mut self, event: Event, context: &ComponentContext<Self>) {
        for effect in self.link.handle(event) {
            match effect {
                Effect::Look => {
                    let folder = self.folder.clone();
                    let _ =
                        context.spawn_background(move |_| Message::Looked(core::looked(&folder)));
                }
                Effect::Open(name) => {
                    self.hang();
                    self.turns += 1;
                    let turn = self.turns;
                    let _ = context
                        .spawn_background(move |_| Message::Opened(turn, core::open(&name, turn)));
                }
                Effect::Send(frame) => match &self.connection {
                    Some(connection) => {
                        let pipe = std::sync::Arc::clone(&connection.pipe);
                        let turn = connection.turn;
                        let _ = context.spawn_background(move |_| {
                            Message::Wrote(turn, core::write(&pipe, &frame))
                        });
                    }
                    None => self.said = Some(undone()),
                },
                Effect::Hang => self.hang(),
                Effect::Undone(_) => self.said = Some(undone()),
                // The presence announces; the window shows.
                Effect::Raised(_) | Effect::Served(_) | Effect::Render => {}
            }
        }
        if self.refresh() {
            self.keep(context);
        }
    }

    fn hang(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.hang();
        }
    }

    fn wish(&mut self, place: Place, request: Request, context: &ComponentContext<Self>) {
        self.said = None;
        self.submitted = false;
        self.step(Event::Wish(place, request), context);
    }

    /// Carries out an act the person chose at `place` with the words it was
    /// chosen by.
    fn act(&mut self, place: Place, label: &str, act: Act, context: &ComponentContext<Self>) {
        match act {
            Act::Send(request) => self.wish(place, request, context),
            Act::Confirm {
                request,
                consequence,
                answer,
            } => {
                self.asking = Some(Asking {
                    verb: label.trim_end_matches("...").to_owned(),
                    answer,
                    consequence,
                    request: Some(request),
                    place,
                });
            }
            Act::Answer => {
                if !one::bring_card(&self.folder) {
                    self.said = Some(
                        "Hedwig's icon is not running, so nothing at this desktop can ask you. \
                         Start it to answer here."
                            .to_owned(),
                    );
                }
            }
            Act::Start => {
                let folder = self.folder.clone();
                let _ = context.spawn_background(move |_| Message::Started(files::start(&folder)));
            }
            Act::Retry => self.step(Event::Retry, context),
            Act::Define(draft) => self.begin_definition(*draft),
            // Offered by the icon alone.
            Act::Open(_) | Act::Leave | Act::Stop { .. } => {}
        }
    }

    /// The act the person chose, taken out of what was shown.
    fn take(&mut self, at: &At) -> Option<(String, Act)> {
        match (at, &mut self.shown.board) {
            (At::Off, Board::Off { act, .. }) => act.take().map(|act| (String::new(), act)),
            (At::Need { sentence, label }, board) => {
                let needs = match board {
                    Board::Exposure { needs, .. } => &mut needs[..],
                    _ => &mut [],
                };
                self.shown
                    .heads
                    .iter_mut()
                    .chain(needs.iter_mut())
                    .find(|need| need.sentence == *sentence)
                    .and_then(|need| pick(&mut need.acts, label))
            }
            (
                At::Line {
                    remote,
                    capability,
                    label,
                },
                Board::Exposure { groups, .. },
            ) => line_act(groups, remote.as_ref(), capability, label),
            (
                At::Device {
                    remote,
                    capability,
                    device,
                },
                Board::Exposure { groups, .. },
            ) => device_act(groups, remote.as_ref(), capability, device),
            (
                At::Key {
                    remote,
                    capability,
                    key,
                },
                Board::Exposure { groups, .. },
            ) => key_act(groups, remote.as_ref(), capability, key),
            (
                At::Policy {
                    remote,
                    capability,
                    when,
                    label,
                },
                Board::Exposure { groups, .. },
            ) => policy_act(groups, (remote.as_ref(), capability, when), None, label),
            (
                At::KeyRule {
                    remote,
                    capability,
                    when,
                    key,
                    label,
                },
                Board::Exposure { groups, .. },
            ) => policy_act(
                groups,
                (remote.as_ref(), capability, when),
                Some(key),
                label,
            ),
            (
                At::Setting {
                    section,
                    name,
                    label,
                },
                _,
            ) => setting_act(self.sheet.as_mut()?, section.as_deref(), name, label),
            (At::Defined { kind, name, label }, _) => {
                let defined = self
                    .definitions()?
                    .own
                    .into_iter()
                    .find(|defined| defined.kind == *kind && defined.name == *name)?;
                match defined.remove {
                    Shown::Offered { label: known, act } if known == *label => Some((known, act)),
                    _ => None,
                }
            }
            (At::Entry { seq, label, .. }, _) => {
                let (_, mut acts) = self.entry_acts().remove(seq)?;
                pick(&mut acts, label)
            }
            _ => None,
        }
    }

    fn keep(&mut self, context: &ComponentContext<Self>) {
        if let (Some(place), Some(draft)) = (self.kept.clone(), self.draft.clone()) {
            let _ = context.spawn_background(move |_| {
                Message::Kept(
                    draft::keep(&place, &draft.written()).map_err(|error| error.to_string()),
                )
            });
        }
    }

    /// Applies an edit to the grant being made. WinUI also reports the
    /// selections the window sets itself; an edit that changes nothing is
    /// not the person's, and neither keeps nor makes a draft. Returns whether
    /// the draft changed.
    fn edit(&mut self, edit: Edit) -> bool {
        let Some(attached) = self.link.seen().attached() else {
            return false;
        };
        let (Some(vocabulary), Some(document)) = (&attached.catalogue, &attached.document) else {
            return false;
        };
        let (reference, document) = (vocabulary.reference().clone(), document.clone());
        let found = attached.workstation.clone();
        let ready = match &self.shown.board {
            Board::First(first) => first.draft.clone(),
            _ => Draft::default(),
        };
        let before = self.draft.clone().unwrap_or(ready);
        let listed = before
            .capability
            .as_ref()
            .and_then(|capability| attached.devices.get(capability))
            .cloned();
        let keys = before
            .capability
            .as_ref()
            .and_then(|capability| attached.agent_keys.get(capability))
            .cloned();
        let form = Form::of(
            &before,
            &reference,
            &document,
            found.as_ref(),
            (listed.as_ref(), keys.as_ref()),
            None,
        );
        let listed_key = |at: usize| {
            form.keying
                .as_ref()
                .and_then(|keying| keying.keys.get(at))
                .map(|choice| choice.key.clone())
        };
        let mut draft = before.clone();
        match edit {
            Edit::Capability(at) => {
                if let Some(choice) = form.capabilities.get(at) {
                    draft.choose_capability(choice.value.clone(), &reference, &document);
                }
            }
            Edit::Aim(aim) => draft.aim_at(aim, &reference),
            Edit::Route(at) => {
                if let Some(choice) = form.routes.get(at) {
                    draft.choose_route(choice.value.clone(), &reference);
                }
            }
            Edit::Set(at) => {
                if let Some(choice) = form.sets.get(at) {
                    draft.choose_set(choice.value.clone(), &reference);
                }
            }
            Edit::Typed(text) => draft.type_name(&text, &reference),
            Edit::Activation(at) => {
                if let Some(choice) = form.activations.get(at) {
                    draft.choose_activation(choice.value);
                }
            }
            Edit::Writes(writes) => draft.let_write(writes),
            Edit::Acknowledge(word, named) => draft.acknowledge(word, named),
            Edit::Lend(at, lent) => {
                if let Some(serial) = form
                    .lending
                    .as_ref()
                    .and_then(|lending| lending.devices.get(at))
                    .and_then(|choice| choice.value.clone())
                {
                    draft.lend(serial, lent);
                }
            }
            Edit::Every(every) => draft.lend_every(every),
            Edit::LendKey(at, lent) => {
                if let Some(chosen) = form.keying.as_ref().and_then(|keying| keying.keys.get(at)) {
                    draft.lend_key(chosen, lent);
                }
            }
            Edit::Hosts(at, text) => {
                if let Some(key) = listed_key(at) {
                    draft.type_hosts(key, &text);
                }
            }
            // Asking the agent is no change of the draft.
            Edit::AskKeys => {}
        }
        if draft == before {
            return false;
        }
        self.draft = Some(draft);
        true
    }

    fn submit(&mut self, context: &ComponentContext<Self>) {
        let draft = match (&self.draft, &self.shown.board) {
            (Some(draft), _) => draft.clone(),
            (None, Board::First(first)) => first.draft.clone(),
            (None, _) => return,
        };
        let Some(attached) = self.link.seen().attached() else {
            return;
        };
        let (Some(vocabulary), Some(document)) = (&attached.catalogue, &attached.document) else {
            return;
        };
        let change = draft.change(vocabulary.reference(), document);
        if let Ok(change) = change {
            self.wish(Place::Window, Request::Change(change), context);
            self.submitted = true;
        }
    }

    /// Lends `key` on a line only for logging in to the hosts typed beside
    /// it: the act the view makes of what was typed, or why it cannot be
    /// one, beneath the box.
    fn restrict(
        &mut self,
        remote: Option<RemoteId>,
        capability: Name,
        key: &SshKey,
        context: &ComponentContext<Self>,
    ) {
        let typed_key = hosts_key(remote.as_ref(), &capability, key);
        let Some(attached) = self.link.seen().attached() else {
            return;
        };
        let typed = self
            .typing
            .get(&typed_key)
            .and_then(|typed| typed.first().cloned())
            .or_else(|| show::hosts_now(&self.shown, remote.as_ref(), &capability, key))
            .unwrap_or_default();
        match exposure::restrict(attached, remote.as_ref(), &capability, key, &typed) {
            Ok(Shown::Offered { label, act }) => {
                self.invalid = None;
                let place = Place::Line { remote, capability };
                self.act(place, &label, act, context);
            }
            Ok(Shown::Withheld { why, .. }) | Err(why) => self.invalid = Some((typed_key, why)),
        }
        let _ = self.refresh();
    }

    fn set_typed(&mut self, key: &str, wide: Wide, context: &ComponentContext<Self>) {
        let Some(sheet) = &self.sheet else {
            return;
        };
        let entry = sheet
            .workstation
            .iter()
            .map(|setting| (None, setting))
            .chain(sheet.remotes.iter().flat_map(|section| {
                section
                    .settings
                    .iter()
                    .map(move |setting| (Some(section.of.to_string()), setting))
            }))
            .chain(sheet.routes.iter().flat_map(|section| {
                section
                    .settings
                    .iter()
                    .map(move |setting| (Some(section.of.to_string()), setting))
            }))
            .find(|(section, setting)| self::key(section.as_deref(), setting.name) == key)
            .and_then(|(_, setting)| setting.entry.clone());
        let Some(entry) = entry else {
            return;
        };
        let typed: Vec<String> = match self.typing.get(key) {
            Some(typed) => typed.clone(),
            None => entry.now(),
        };
        let typed: Vec<&str> = typed.iter().map(String::as_str).collect();
        let attached = self.link.seen().attached();
        let document = attached.and_then(|attached| attached.document.as_ref());
        let vocabulary = attached.and_then(|attached| attached.catalogue.as_ref());
        let keyrings = attached.map(Attached::keyrings).unwrap_or_default();
        match entry.act(&typed, wide, document, vocabulary, keyrings) {
            Ok(Shown::Offered { label, act }) => {
                self.invalid = None;
                self.typing.remove(key);
                self.act(Place::Window, &label, act, context);
            }
            Ok(Shown::Withheld { why, .. }) => self.invalid = Some((key.to_owned(), why)),
            Err(invalid) => self.invalid = Some((key.to_owned(), invalid.to_string())),
        }
    }
}

fn undone() -> String {
    "Hedwig is not running, so that was not done, and nothing was kept to do later.".to_owned()
}

impl Window {
    /// What the connection to the core brought.
    fn connected(&mut self, message: Message, context: &ComponentContext<Self>) {
        match message {
            Message::Looked(Some(standing)) => self.step(Event::Looked(standing), context),
            Message::Watched(watched, standing) => {
                if let Some(watched) = watched {
                    watch(*watched, self.folder.clone(), context);
                }
                if let Some(standing) = standing {
                    self.step(Event::Looked(standing), context);
                }
            }
            Message::Opened(turn, Ok(connection)) if turn == self.turns => {
                let reading = connection.reading();
                self.connection = Some(connection);
                read(reading, context);
                self.step(Event::Opened, context);
            }
            Message::Opened(turn, Err(sentence)) if turn == self.turns => {
                self.step(Event::Unopened(sentence), context);
            }
            Message::Opened(_, Ok(connection)) => connection.hang(),
            Message::Read(reading, frame) => {
                let current = self
                    .connection
                    .as_ref()
                    .is_some_and(|connection| connection.turn == reading.turn);
                if let (true, Some((frame, at))) = (current, frame) {
                    read(reading, context);
                    self.step(Event::Frame(frame, at), context);
                } else if current {
                    self.hang();
                    self.step(Event::Closed, context);
                }
            }
            Message::Wrote(turn, false)
                if self
                    .connection
                    .as_ref()
                    .is_some_and(|connection| connection.turn == turn) =>
            {
                self.hang();
                self.step(Event::Closed, context);
            }
            Message::Started(failed) => {
                self.said = failed;
                self.step(Event::Retry, context);
            }
            _ => {}
        }
    }

    /// The grant being made: found, kept, edited, made or discarded.
    fn drafted(&mut self, message: Message, context: &ComponentContext<Self>) {
        match message {
            Message::Found(place, kept) => {
                self.kept = Some(place);
                match kept {
                    Kept::Draft(draft) => self.draft = Some(draft),
                    Kept::Unreadable => {
                        self.said = Some(
                            "A grant you were making could not be read back, so the form starts \
                             empty."
                                .to_owned(),
                        );
                    }
                    Kept::Nothing => {}
                }
            }
            Message::Kept(Err(error)) => {
                self.said = Some(format!(
                    "What you are making could not be kept if this window closes: {error}"
                ));
            }
            Message::Begin => {
                self.draft.get_or_insert_with(Draft::default);
                self.keep(context);
            }
            Message::Edit(Edit::AskKeys) => {
                if let Some(capability) = self.form().and_then(|form| {
                    form.keying.as_ref()?;
                    form.capabilities
                        .into_iter()
                        .find(|choice| choice.chosen)
                        .map(|choice| choice.value)
                }) {
                    self.step(
                        Event::Wish(Place::Window, Request::Keys(capability)),
                        context,
                    );
                }
            }
            Message::Edit(edit) => {
                let chose = matches!(edit, Edit::Capability(_));
                if self.edit(edit) {
                    self.keep(context);
                    // Choosing to grant an agent is the person's act: its
                    // keys are read once for it, and never by showing the
                    // form again.
                    if chose
                        && let Some(capability) = self.form().and_then(|form| {
                            form.keying.as_ref()?;
                            form.capabilities
                                .into_iter()
                                .find(|choice| choice.chosen)
                                .map(|choice| choice.value)
                        })
                    {
                        self.step(Event::Keys(capability), context);
                    }
                }
            }
            Message::Submit => self.submit(context),
            Message::Discard => {
                self.draft = None;
                if let Some(place) = self.kept.clone() {
                    let _ = draft::forget(&place);
                }
            }
            _ => {}
        }
    }

    /// A definition opened, edited, found where it was kept, made or
    /// discarded.
    fn defined_message(&mut self, message: Message, context: &ComponentContext<Self>) {
        match message {
            Message::Define { kind, name } => {
                self.define(kind, name.as_ref());
                self.keep_definition(context);
            }
            Message::Complete => {
                if let Some((_, draft)) = self.form().and_then(|form| form.completes)
                    && self.defining.is_none()
                {
                    // The grant chosen so far becomes the person's draft, so
                    // it is there when the definition is made.
                    if self.draft.is_none()
                        && let Board::First(first) = &self.shown.board
                    {
                        self.draft = Some(first.draft.clone());
                        self.keep(context);
                    }
                    self.completing = self.form().and_then(|form| {
                        form.capabilities
                            .into_iter()
                            .find(|choice| choice.chosen)
                            .map(|choice| choice.value)
                    });
                    self.begin_definition(draft);
                    self.keep_definition(context);
                }
            }
            Message::DefineFromGrant(at) => {
                if let Some((_, draft)) = self
                    .form()
                    .and_then(|form| form.defines.into_iter().nth(at))
                {
                    self.begin_definition(draft);
                    self.keep_definition(context);
                }
            }
            Message::PortsAgain => {
                self.step(Event::Wish(Place::Defining, Request::Ports), context);
            }
            Message::Defining(edit) => {
                let attached = self.link.seen().attached();
                let mut changed = false;
                if let (Some(draft), Some(attached)) = (&mut self.defining, attached)
                    && let (Some(vocabulary), Some(document)) =
                        (&attached.catalogue, &attached.document)
                {
                    let before = draft.clone();
                    draft.edit(edit, vocabulary.reference(), document);
                    // WinUI reports what the window sets itself: an edit
                    // that changes nothing is not the person's.
                    changed = *draft != before;
                }
                if changed {
                    self.keep_definition(context);
                }
            }
            Message::FoundDefinition(place, kept) => {
                self.kept_definition = Some(place);
                match kept {
                    Kept::Draft(draft) => self.defining = Some(draft),
                    Kept::Unreadable => {
                        self.said = Some(
                            "A definition you were making could not be read back, so it is not \
                             shown."
                                .to_owned(),
                        );
                    }
                    Kept::Nothing => {}
                }
            }
            Message::DefineSubmit => {
                if let Some(form) = self.definition()
                    && let Ok(Shown::Offered { label, act }) = form.ready
                {
                    self.act(Place::Defining, &label, act, context);
                    self.defined = true;
                }
            }
            Message::DefineDiscard => {
                self.defining = None;
                self.defined = false;
                self.completing = None;
                self.keep_definition(context);
            }
            _ => {}
        }
    }

    /// The configuration written out, or a file read in and tried.
    fn filed(&mut self, message: Message, context: &ComponentContext<Self>) {
        match message {
            Message::Export | Message::Import | Message::SaveBundle if self.choosing => {}
            Message::Exported(_) | Message::Chosen(_) | Message::SavedBundle(_)
                if self.choosing =>
            {
                self.choosing = false;
                self.filed(message, context);
            }
            Message::Export => {
                let document = self
                    .link
                    .seen()
                    .attached()
                    .and_then(|attached| attached.document.clone());
                if let Some(document) = document {
                    self.choosing = true;
                    let _ = context
                        .spawn_background(move |_| Message::Exported(files::export(&document)));
                } else {
                    self.said =
                        Some("Hedwig has not said what your configuration is yet.".to_owned());
                }
            }
            Message::Exported(Ok(Some(path))) => {
                self.said = Some(format!(
                    "Your configuration was written to {}. It holds your own statements; your \
                     organisation's come from it on every workstation.",
                    path.display()
                ));
            }
            Message::Exported(Err(error)) => {
                self.said = Some(format!("Your configuration was not written: {error}"));
            }
            Message::Import => {
                self.choosing = true;
                let _ = context.spawn_background(|_| Message::Chosen(files::import()));
            }
            Message::Chosen(Ok(Some(document))) => {
                self.importing = Some(document.clone());
                self.wish(Place::Window, trial::try_import(document), context);
            }
            Message::Chosen(Err(error)) => self.said = Some(error),
            Message::MakeImport => {
                if let Some(document) = self.importing.take() {
                    self.wish(Place::Window, trial::import(document), context);
                }
            }
            Message::CancelImport => self.importing = None,
            Message::MakeBundle => {
                self.bundling = Gathering::Shown;
                self.wish(Place::Window, Request::Bundle, context);
            }
            Message::SaveBundle => {
                if let Some(written) = self.bundled().map(|bundle| bundle::written(&bundle)) {
                    self.choosing = true;
                    let _ = context
                        .spawn_background(move |_| Message::SavedBundle(files::bundle(&written)));
                }
            }
            Message::SavedBundle(Ok(Some(path))) => {
                self.bundling = Gathering::Off;
                self.said = Some(format!(
                    "What a supporter needs was written to {}. Hedwig sends nothing: send the \
                     file yourself.",
                    path.display()
                ));
            }
            Message::SavedBundle(Err(error)) => {
                self.said = Some(format!("What a supporter needs was not written: {error}"));
            }
            Message::CancelBundle => self.bundling = Gathering::Off,
            _ => {}
        }
    }
}

/// Whether what a supporter needs is in the window: asked of the core and,
/// once it answers, shown to be saved or put away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gathering {
    Off,
    Shown,
}

/// Waits, off the window's thread, until the record changes or the
/// supervisor it names ends, and brings the record as it then reads.
fn watch(mut watch: Watch, folder: PathBuf, context: &ComponentContext<Window>) {
    let _ = context.spawn_background(move |_| {
        watch.follow(core::looked(&folder).as_ref().and_then(link::supervisor));
        let woke = watch.wait();
        Message::Watched(woke.map(|_| Box::new(watch)), core::looked(&folder))
    });
}

/// Starts waiting for the next frame on the connection being read.
fn read(reading: Box<Reading>, context: &ComponentContext<Window>) {
    let _ = context.spawn_background(move |_| {
        let (reading, frame) = core::next(reading);
        Message::Read(reading, frame)
    });
}

impl Component for Window {
    type Input = Input;
    type Message = Message;

    fn create(input: &Input, context: &ComponentContext<Self>) -> Self {
        let mut window = Window {
            folder: input.folder.clone(),
            title: input.title.clone(),
            link: Link::viewer(),
            turns: 0,
            connection: None,
            shown: exposure::Window {
                heads: Vec::new(),
                board: Board::Asking,
                refused: None,
                changes: None,
            },
            sheet: None,
            draft: None,
            kept: None,
            submitted: false,
            asking: None,
            typing: BTreeMap::new(),
            invalid: None,
            importing: None,
            bundling: Gathering::Off,
            said: None,
            expanded: BTreeSet::new(),
            keyed: BTreeMap::new(),
            choosing: false,
            clock: None,
            waits: 0,
            defining: None,
            defined: false,
            completing: None,
            kept_definition: None,
            named: None,
        };
        window.step(Event::Window(true), context);
        let folder = input.folder.clone();
        let _ = context.spawn_background(move |_| Message::Looked(core::looked(&folder)));
        // A Hedwig started or stopped elsewhere, and a core started again,
        // are seen without the person asking; the folder is made where
        // Hedwig has never run, so it can be watched. The watch ends with
        // the window's process.
        if let Ok((watched, _stop)) =
            std::fs::create_dir_all(&input.folder).and_then(|()| Watch::new(&input.folder, RECORD))
        {
            watch(watched, input.folder.clone(), context);
        }
        // WinUI gives no handle to its window: it is found once shown.
        let _ = context.spawn_background(|_| {
            let process = std::process::id();
            let until = Instant::now() + SHOWN;
            loop {
                let found = one::window_of(process);
                if found.is_some() || Instant::now() >= until {
                    return Message::Shown(found);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let folder = input.folder.clone();
        let _ = context.spawn_background(move |_| {
            let place = draft::place(&folder, Making::Grant);
            let kept = draft::kept(&place, Draft::read);
            Message::Found(place, kept)
        });
        let folder = input.folder.clone();
        let _ = context.spawn_background(move |_| {
            let place = draft::place(&folder, Making::Definition);
            let kept = draft::kept(&place, define::Draft::read);
            Message::FoundDefinition(place, kept)
        });
        window
    }

    fn update(&mut self, message: Message, context: &ComponentContext<Self>) {
        match message {
            Message::Looked(_)
            | Message::Watched(..)
            | Message::Opened(..)
            | Message::Read(..)
            | Message::Wrote(..)
            | Message::Started(_) => self.connected(message, context),
            Message::Found(..)
            | Message::Kept(_)
            | Message::Begin
            | Message::Edit(_)
            | Message::Submit
            | Message::Discard => self.drafted(message, context),
            Message::Export
            | Message::Exported(_)
            | Message::Import
            | Message::Chosen(_)
            | Message::MakeImport
            | Message::CancelImport
            | Message::MakeBundle
            | Message::SaveBundle
            | Message::SavedBundle(_)
            | Message::CancelBundle => self.filed(message, context),
            Message::Typing { key, field, text } => {
                let defaults = self
                    .sheet
                    .as_ref()
                    .and_then(|sheet| show::fields(sheet, &key));
                let typed = self
                    .typing
                    .entry(key)
                    .or_insert_with(|| defaults.unwrap_or_default());
                // A box no setting fills, as a key's hosts on a line, starts
                // with nothing in it.
                if typed.len() <= field {
                    typed.resize(field + 1, String::new());
                }
                if let Some(slot) = typed.get_mut(field) {
                    *slot = text;
                }
            }
            Message::SetTyped { key, wide } => self.set_typed(&key, wide, context),
            Message::KeyChosen { policy, at } => {
                self.keyed.insert(policy, at);
            }
            Message::Restrict {
                remote,
                capability,
                key,
            } => self.restrict(remote, capability, &key, context),
            Message::Chose(at) => {
                if let Some((label, act)) = self.take(&at) {
                    self.act(at.place(), &label, act, context);
                }
                let _ = self.refresh();
            }
            Message::Confirmed(yes) => {
                if let Some(asking) = self.asking.as_mut()
                    && let Some(request) = asking.request.take()
                    && yes
                {
                    let place = asking.place.clone();
                    self.wish(place, request, context);
                }
            }
            Message::Dismiss => self.said = None,
            Message::Shown(found) => {
                self.named = found.map(|window| one::name(window, resource::ICON));
            }
            Message::Nothing => {}
            Message::Expanded { key, open } => self.expanded(key, open, context),
            Message::Earlier => self.step(Event::Earlier, context),
            Message::Define { .. }
            | Message::DefineFromGrant(_)
            | Message::Complete
            | Message::PortsAgain
            | Message::Defining(_)
            | Message::FoundDefinition(..)
            | Message::DefineSubmit
            | Message::DefineDiscard => self.defined_message(message, context),
            Message::Clock(wait) => {
                if self.clock.is_some_and(|(running, _)| running == wait) {
                    self.clock = None;
                    let _ = self.refresh();
                }
            }
        }
        self.list_devices(context);
        self.list_ports(context);
        self.tick(context);
    }

    fn view(&self, input: &Input, context: &mut ViewContext<Self>) -> View {
        context.window_title(self.title.clone());
        show::window(self, input.placed, context)
    }
}

impl Window {
    /// Reads the devices of each capability whose devices the window shows -
    /// on a grant's line, or the grant being made - where none are read yet.
    fn list_devices(&mut self, context: &ComponentContext<Self>) {
        let mut shown: Vec<Name> = match &self.shown.board {
            Board::Exposure { groups, .. } => groups
                .iter()
                .flat_map(|group| &group.lines)
                .filter(|line| line.lending.is_some())
                .map(|line| line.capability.clone())
                .collect(),
            _ => Vec::new(),
        };
        if let Some(form) = self.form()
            && form.lending.is_some()
            && let Some(capability) = form
                .capabilities
                .iter()
                .find(|choice| choice.chosen)
                .map(|choice| choice.value.clone())
        {
            shown.push(capability);
        }
        let unread: Vec<Name> = self
            .link
            .seen()
            .attached()
            .map_or_else(Vec::new, |attached| {
                shown
                    .into_iter()
                    .filter(|capability| !attached.devices.contains_key(capability))
                    .collect()
            });
        for capability in unread {
            self.step(Event::Devices(capability), context);
        }
    }

    /// Reads the workstation's serial ports where the definition being made
    /// picks one and none are read yet.
    fn list_ports(&mut self, context: &ComponentContext<Self>) {
        let unread = self
            .defining
            .as_ref()
            .is_some_and(define::Draft::lists_ports)
            && self
                .link
                .seen()
                .attached()
                .is_some_and(|attached| attached.ports.is_none());
        if unread {
            self.step(Event::Ports, context);
        }
    }

    /// The form for the grant being made, where the core has said what
    /// can be granted.
    pub(crate) fn form(&self) -> Option<Form> {
        let attached = self.link.seen().attached()?;
        let (vocabulary, document) = (attached.catalogue.as_ref()?, attached.document.as_ref()?);
        let ready;
        let draft = match (&self.draft, &self.shown.board) {
            (Some(draft), _) => draft,
            (None, Board::First(first)) => {
                ready = first.draft.clone();
                &ready
            }
            (None, _) => return None,
        };
        let refused = attached
            .refused
            .as_ref()
            .filter(|(place, _)| *place == Place::Window)
            .map(|(_, refusal)| refusal);
        let listed = draft
            .capability
            .as_ref()
            .and_then(|capability| attached.devices.get(capability));
        let keys = draft
            .capability
            .as_ref()
            .and_then(|capability| attached.agent_keys.get(capability));
        Some(Form::of(
            draft,
            vocabulary.reference(),
            document,
            attached.workstation.as_ref(),
            (listed, keys),
            refused,
        ))
    }

    /// What a supporter would be given, once the core has assembled it.
    pub(crate) fn bundled(&self) -> Option<hedwig_model::protocol::Bundle> {
        if self.bundling == Gathering::Off {
            return None;
        }
        self.link
            .seen()
            .attached()?
            .bundle
            .as_ref()
            .filter(|(place, _)| *place == Place::Window)
            .map(|(_, bundle)| (**bundle).clone())
    }

    /// What importing the chosen file would do, once the core has said.
    pub(crate) fn outcome(&self) -> Option<Outcome> {
        self.importing.as_ref()?;
        let attached = self.link.seen().attached()?;
        let contacts = attached
            .settings
            .as_ref()
            .map_or(&[][..], |settings| &settings.workstation.contacts[..]);
        attached
            .tried
            .as_ref()
            .filter(|(place, _)| *place == Place::Window)
            .map(|(_, tried)| Outcome::of(tried, contacts, attached.keyrings()))
    }

    /// Opens the form for a definition of `kind`, the person's own `name`
    /// where one is named. One is made at a time: one being made stays until
    /// it is made or discarded.
    fn define(&mut self, kind: Kind, name: Option<&Name>) {
        let document = self
            .link
            .seen()
            .attached()
            .and_then(|attached| attached.document.as_ref());
        let draft = match (name, document) {
            (Some(name), Some(document)) => define::Draft::changing(kind, name, document),
            (Some(_), None) => None,
            (None, _) => Some(define::Draft::new(kind)),
        };
        if let Some(draft) = draft {
            self.begin_definition(draft);
        }
    }

    /// Begins `draft`, where nothing is being defined: what is being made
    /// stays until it is made or discarded. The form is under this
    /// workstation, so its disclosure is opened.
    fn begin_definition(&mut self, draft: define::Draft) {
        if let Some(making) = &self.defining {
            self.said = Some(format!(
                "Make or discard the {} you are defining first.",
                making.kind.noun()
            ));
            return;
        }
        self.defining = Some(draft);
        self.expanded.insert(show::WORKSTATION.to_owned());
    }

    /// A disclosure opened or closed. One remote's activity is read while its
    /// disclosure is open, and one at a time: opening another closes it.
    fn expanded(&mut self, key: String, open: bool, context: &ComponentContext<Self>) {
        let reviewing = show::reviewed(&key).and_then(|heading| {
            self.link
                .seen()
                .attached()?
                .rows
                .as_ref()?
                .iter()
                .filter_map(|row| row.remote.clone())
                .find(|remote| remote.to_string() == heading)
        });
        if open {
            if reviewing.is_some() {
                self.expanded
                    .retain(|known| show::reviewed(known).is_none());
                self.step(Event::Review(reviewing), context);
            }
            self.expanded.insert(key);
        } else {
            if reviewing.is_some() {
                self.step(Event::Review(None), context);
            }
            self.expanded.remove(&key);
        }
    }

    /// Writes the definition being made where it is kept, or forgets it once
    /// there is none.
    fn keep_definition(&mut self, context: &ComponentContext<Self>) {
        let Some(place) = self.kept_definition.clone() else {
            return;
        };
        match self.defining.as_ref().map(define::Draft::written) {
            Some(written) => {
                let _ = context.spawn_background(move |_| {
                    Message::Kept(draft::keep(&place, &written).map_err(|error| error.to_string()))
                });
            }
            None => {
                let _ = draft::forget(&place);
            }
        }
    }

    /// The form for the definition being made, where the core has said what
    /// is defined.
    pub(crate) fn definition(&self) -> Option<define::Form> {
        let draft = self.defining.as_ref()?;
        let attached = self.link.seen().attached()?;
        let (vocabulary, document) = (attached.catalogue.as_ref()?, attached.document.as_ref()?);
        let refused = attached
            .refused
            .as_ref()
            .filter(|(place, _)| *place == Place::Defining)
            .map(|(_, refusal)| refusal.to_string());
        Some(define::Form::of(
            draft,
            vocabulary,
            document,
            attached.ports.as_ref(),
            refused,
        ))
    }

    /// The person's own definitions, and those defined outside their
    /// configuration.
    pub(crate) fn definitions(&self) -> Option<Definitions> {
        let attached = self.link.seen().attached()?;
        let (vocabulary, document) = (attached.catalogue.as_ref()?, attached.document.as_ref()?);
        let refused = attached
            .refused
            .as_ref()
            .and_then(|(place, refusal)| match place {
                Place::Defined { kind, name } => Some((*kind, name, refusal.to_string())),
                _ => None,
            });
        Some(Definitions::of(
            &vocabulary.definitions,
            vocabulary.reference(),
            document,
            refused
                .as_ref()
                .map(|(kind, name, why)| (*kind, *name, why.as_str())),
        ))
    }

    pub(crate) fn held(&self) -> Vec<String> {
        let Some(attached) = self.link.seen().attached() else {
            return Vec::new();
        };
        attached
            .held
            .as_ref()
            .filter(|(place, _)| *place == Place::Window)
            .map(|(_, held)| {
                held.iter()
                    .map(|holding| words::holding(holding, attached.keyrings()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The reviewed remote's activity, newest first, each entry with the
    /// acts due on it and where they are made, and whether an earlier page
    /// may follow; `None` until its first page has come.
    pub(crate) fn activity(&self, remote: &str) -> Option<(Vec<Said>, bool)> {
        let attached = self.link.seen().attached()?;
        let activity = attached
            .activity
            .as_ref()
            .filter(|activity| activity.remote.to_string() == remote)?;
        let entries = activity.entries.as_ref()?;
        let mut acts = self.entry_acts();
        let keyrings = attached.keyrings().of_remote(&activity.remote);
        let said = exposure::activity(entries, &written, keyrings)
            .into_iter()
            .map(|(seq, text)| {
                let (at, acts) = acts
                    .remove(&seq)
                    .map_or((None, Vec::new()), |(capability, acts)| {
                        (Some((activity.remote.clone(), capability, seq)), acts)
                    });
                Said { text, acts, at }
            })
            .collect();
        Some((said, activity.earlier))
    }

    /// The acts due on the reviewed remote's entries, by entry.
    fn entry_acts(&self) -> BTreeMap<Seq, (Name, Vec<Shown>)> {
        let Some(attached) = self.link.seen().attached() else {
            return BTreeMap::new();
        };
        let Some((remote, Some(entries))) = attached
            .activity
            .as_ref()
            .map(|activity| (&activity.remote, activity.entries.as_ref()))
        else {
            return BTreeMap::new();
        };
        exposure::entry_acts(entries, remote, attached)
    }
}

/// An entry of a remote's activity as the window shows it: its words, the
/// acts due on it, and where an act chosen from it is made.
#[derive(Debug)]
pub(crate) struct Said {
    pub(crate) text: String,
    pub(crate) acts: Vec<Shown>,
    pub(crate) at: Option<(RemoteId, Name, Seq)>,
}
