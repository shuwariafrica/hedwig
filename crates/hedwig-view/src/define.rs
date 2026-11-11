//! What the person defines for themselves: a capability, a route, a platform
//! or a set of remotes.
//!
//! The person has time to think: a service Hedwig does not ship, a preset
//! whose port only they know, a platform's own client, a system nobody
//! profiled, hosts that share no name. Each kind is the model's own type,
//! filled in field by field and checked as it is typed; what the core makes of
//! it is the core's, through the same change a command or an imported
//! document makes ([`Change`]). A definition being made is the person's
//! partial input, kept until they make it or discard it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::num::NonZeroU16;

use hedwig_model::beyond::Beyond;
use hedwig_model::capability::{
    Access, AgentAt, Browser, Capability, Home, Installation, Offer, ServiceHost, ServicePort,
    Source, Stream,
};
use hedwig_model::config::{
    Catalogue, Change, Collision, Configuration, Definitions as Outside, Document, Reference,
};
use hedwig_model::json::{self, Json, Layout};
use hedwig_model::organisation::{Part, Place as Where};
use hedwig_model::platform::{AgentForwarding, Platform, Sockets};
use hedwig_model::protocol::{Request, SerialPort};
use hedwig_model::refusal::{Refusal, Section};
use hedwig_model::remote::{
    Argument, Client, Granted, Identity, Lister, Listing, Member, RemoteId, Route, Set,
};
use hedwig_model::scope::Tier;
use hedwig_model::site::Site;
use hedwig_model::text::{
    AgentPipe, Folder, Host, Kernel, Name, Port, PortName, Program, Template, TextError, Variable,
    Verbatim,
};

use crate::act::Act;
use crate::exposure::Shown;
use crate::grant;
use crate::link::Vocabulary;
use crate::setting::{Answer, Judge};
use crate::words;

/// What a definition defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Capability,
    Route,
    Platform,
    Set,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Capability, Kind::Route, Kind::Platform, Kind::Set];

    /// What one of this kind is called where the person reads it.
    pub fn noun(self) -> &'static str {
        match self {
            Kind::Capability => "capability",
            Kind::Route => "route",
            Kind::Platform => "platform",
            Kind::Set => "set of remotes",
        }
    }
}

/// The line of a route's arguments that stands for the remote's address.
pub const ADDRESS: &str = "{address}";

/// How one field is filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Text, kept as typed; `lines` where it holds one item to a line.
    Text { typed: String, lines: bool },
    /// One of a few, by its place.
    Choice { options: Vec<String>, chosen: usize },
    /// One of what the workstation has now, kept by its value - a port's
    /// name - so a list read again never moves the choice to another; the
    /// window sends the chosen value as typed.
    Pick {
        options: Vec<Picked>,
        chosen: Option<usize>,
    },
}

/// One option of a [`Input::Pick`]: what the person reads, and the value the
/// draft keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picked {
    pub label: String,
    pub value: String,
}

/// One field of the form, with why what is in it cannot be used, beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    /// What the field takes, where its label alone does not say.
    pub hint: Option<&'static str>,
    pub input: Input,
    pub invalid: Option<String>,
    /// What the person reads beneath it of what is filled in: the address a
    /// remote's tool opens, what a remote's tool cannot do through a port,
    /// or that the list is being read.
    pub notes: Vec<String>,
    /// Reading again what the field lists - the workstation's serial ports -
    /// by its label.
    pub again: Option<&'static str>,
}

/// The workstation's serial ports, as last read: `None` while asked, the
/// refusal where they could not be read; `None` outside where none was asked.
pub type Ports<'a> = Option<&'a Option<Result<Vec<SerialPort>, Refusal>>>;

/// An edit of the definition being made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    Typed {
        key: String,
        text: String,
    },
    Chose {
        key: String,
        at: usize,
    },
    /// Fill the fields from a definition already known, by name.
    From(usize),
}

/// The definition being made or changed: the person's partial input, field by
/// field, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub kind: Kind,
    /// The name of the definition being changed, which stays its name.
    pub changing: Option<Name>,
    typed: BTreeMap<&'static str, String>,
    chosen: BTreeMap<&'static str, usize>,
}

/// Why a field cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Invalid {
    key: &'static str,
    why: String,
}

fn invalid(key: &'static str, why: impl Into<String>) -> Invalid {
    Invalid {
        key,
        why: why.into(),
    }
}

/// A text field's own check, worded by the model's text error.
fn checked<T>(key: &'static str, text: &str, made: Result<T, TextError>) -> Result<T, Invalid> {
    made.map_err(|error| {
        if text.is_empty() {
            invalid(key, "Nothing is filled in.")
        } else {
            invalid(key, format!("\"{text}\" cannot be used: {error}."))
        }
    })
}

/// The lines a box holds: WinUI's `TextBox` breaks a line with `\r` alone.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split(['\r', '\n'])
        .map(str::trim)
        .filter(|line| !line.is_empty())
}

fn port(key: &'static str, text: &str) -> Result<Port, Invalid> {
    let number: u16 = text.parse().map_err(|_| {
        invalid(
            key,
            format!("\"{text}\" is not a port: a number from 1 to 65535."),
        )
    })?;
    checked(key, text, Port::try_from(number))
}

fn arguments(key: &'static str, text: &str) -> Result<Vec<Argument>, Invalid> {
    lines(text)
        .map(|line| {
            if line == ADDRESS {
                Ok(Argument::Address)
            } else {
                checked(key, line, Verbatim::try_from(line)).map(Argument::Literal)
            }
        })
        .collect()
}

fn spelt(arguments: &[Argument]) -> String {
    arguments
        .iter()
        .map(|argument| match argument {
            Argument::Address => ADDRESS.to_owned(),
            Argument::Literal(text) => text.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn member(text: &str) -> Result<Member, Invalid> {
    let (route, named) = text.split_once(char::is_whitespace).ok_or_else(|| {
        invalid(
            "members",
            format!("\"{text}\" names no route: write the route, a space, then the remote."),
        )
    })?;
    let route = checked("members", route, Name::try_from(route))?;
    match grant::named(&route, named.trim()) {
        Ok(Granted::One(remote)) => Ok(Member::One(remote)),
        Ok(Granted::Matching { route, pattern }) => Ok(Member::Matching { route, pattern }),
        Ok(_) => Err(invalid(
            "members",
            format!("\"{text}\" is not one remote or a pattern."),
        )),
        Err(error) => Err(invalid(
            "members",
            format!("\"{text}\" cannot be used: {error}."),
        )),
    }
}

/// A site from what the person typed, read as the model reads a site's
/// written form, or why it is not one, in a sentence.
fn site(text: &str) -> Result<Site, String> {
    text.parse::<Site>()
        .map_err(|why| format!("\"{text}\" is not a site: {why}."))
}

fn written(member: &Member) -> String {
    match member {
        Member::One(RemoteId { route, address }) => format!("{route} {address}"),
        Member::Matching { route, pattern } => format!("{route} {pattern}"),
    }
}

// Each option is written as it is shown: a program's name keeps its case.
const SOURCES: [&str; 5] = [
    "gpg-agent on this workstation",
    "Your SSH agent, which holds your keys",
    "A service this workstation reaches",
    "Your browser, for a remote's sign-in",
    "A serial port on this workstation, for a board",
];
/// Each of [`SOURCES`] as the object of "Define".
const DEFINES: [&str; 5] = [
    "gpg-agent on this workstation",
    "your SSH agent",
    "a service this workstation reaches",
    "your browser, for a remote's sign-in",
    "a serial port on this workstation, for a board",
];

/// The place of `source`'s kind among [`SOURCES`]; `None` for a kind this
/// form does not define - the workstation's git credentials, the person's
/// attention, keys made in the TPM - which outside the prerelease's core is
/// defined in a document and said in words here.
fn kind_of(source: &Source) -> Option<usize> {
    match source {
        Source::Gnupg { .. } => Some(0),
        Source::Agent {
            at: AgentAt::Machine,
        }
        | Source::Credentials { .. }
        | Source::Notices => None,
        Source::Agent { .. } => Some(1),
        Source::Service { .. } => Some(2),
        Source::Browser { .. } => Some(BROWSER),
        Source::Serial { .. } => Some(SERIAL),
    }
}

/// A capability of the person's own to begin, of each kind of source no
/// capability known by name has - shipped, the organisation's or theirs - so
/// what they would grant is one act away where nothing offers it yet: the
/// browser a remote's sign-in opens, a board's serial port.
pub fn undefined(reference: &Reference, document: &Document) -> Vec<(String, Draft)> {
    let known: std::collections::BTreeSet<usize> = document
        .capabilities
        .iter()
        .chain(&reference.capabilities)
        .filter_map(|capability| kind_of(&capability.source))
        .collect();
    DEFINES
        .iter()
        .enumerate()
        .filter(|(at, _)| !known.contains(at))
        .map(|(at, kind)| (format!("Define {kind}..."), Draft::of_source(at)))
        .collect()
}

/// The place of the serial port among [`SOURCES`].
const SERIAL: usize = 4;
/// The place of the person's browser among [`SOURCES`].
const BROWSER: usize = 3;
const BROWSERS: [&str; 2] = [
    "The one Windows opens web addresses with",
    "A program you name, with its arguments",
];
const ACCESS: [&str; 2] = [
    "Signing and decryption only (its restricted socket)",
    "Everything the agent does (its unrestricted socket)",
];
const STREAMS: [&str; 2] = ["ADB", "Anything else, relayed unread"];
const LISTINGS: [&str; 2] = [
    "Nothing lists them: a remote is there when you name it",
    "A program prints the running ones",
];
const IDENTITIES: [&str; 2] = [
    "The host's own key, checked against the hosts you know",
    "Your sign-in to the platform",
];
const SOCKETS: [&str; 2] = ["Unix-domain sockets", "None: a port, and a file naming it"];
const FORWARDING: [&str; 2] = ["Served", "Refused"];
const AGENTS: [&str; 3] = [
    "The pipe Windows' SSH clients use, whichever program holds it",
    "gpg-agent's SSH socket, for a GnuPG home",
    "Another agent's own pipe",
];

/// Every field any kind has, which a kept draft's keys are read against.
const KEYS: [&str; 31] = [
    "name",
    "source",
    "installation",
    "home",
    "access",
    "host",
    "port",
    "stream",
    "remote-port",
    "variable",
    "value",
    "program",
    "before",
    "after",
    "listing",
    "lister",
    "lister-arguments",
    "header",
    "identity",
    "kernel",
    "sockets",
    "path-bytes",
    "forwarding",
    "members",
    "browser",
    "browser-program",
    "browser-arguments",
    "sites",
    "serial-port",
    "agent",
    "agent-pipe",
];

/// A kept definition being made could not be read back: cut short, or
/// written by a build that wrote it otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable;

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the definition being made could not be read back")
    }
}

impl std::error::Error for Unreadable {}

impl Kind {
    fn word(self) -> &'static str {
        match self {
            Kind::Capability => "capability",
            Kind::Route => "route",
            Kind::Platform => "platform",
            Kind::Set => "set",
        }
    }
}

fn known(key: &str) -> Result<&'static str, Unreadable> {
    KEYS.into_iter()
        .find(|known| *known == key)
        .ok_or(Unreadable)
}

impl Draft {
    /// The draft as one line of JSON: its kind, the name it changes, and each
    /// field as typed or chosen.
    pub fn written(&self) -> String {
        let typed = self
            .typed
            .iter()
            .map(|(key, text)| ((*key).to_owned(), Json::Text(text.clone())))
            .collect();
        let chosen = self
            .chosen
            .iter()
            .map(|(key, at)| {
                (
                    (*key).to_owned(),
                    Json::Number(i128::try_from(*at).unwrap_or(0)),
                )
            })
            .collect();
        json::render(
            &Json::Map(vec![
                ("kind".to_owned(), Json::Text(self.kind.word().to_owned())),
                (
                    "changing".to_owned(),
                    self.changing
                        .as_ref()
                        .map_or(Json::Null, |name| Json::Text(name.to_string())),
                ),
                ("typed".to_owned(), Json::Map(typed)),
                ("chosen".to_owned(), Json::Map(chosen)),
            ]),
            Layout::Line,
        )
    }

    /// A draft from its written form.
    ///
    /// # Errors
    ///
    /// [`Unreadable`] where `text` is not the written form of a draft.
    pub fn read(text: &str) -> Result<Draft, Unreadable> {
        let Ok(Json::Map(members)) = json::parse(text) else {
            return Err(Unreadable);
        };
        let [
            (kind_key, Json::Text(kind)),
            (changing_key, changing),
            (typed_key, Json::Map(typed)),
            (chosen_key, Json::Map(chosen)),
        ] = members.as_slice()
        else {
            return Err(Unreadable);
        };
        if [kind_key, changing_key, typed_key, chosen_key]
            != ["kind", "changing", "typed", "chosen"]
        {
            return Err(Unreadable);
        }
        let kind = Kind::ALL
            .into_iter()
            .find(|known| known.word() == kind)
            .ok_or(Unreadable)?;
        let changing = match changing {
            Json::Null => None,
            Json::Text(name) => Some(Name::try_from(name.as_str()).map_err(|_| Unreadable)?),
            _ => return Err(Unreadable),
        };
        let typed = typed
            .iter()
            .map(|(key, value)| match value {
                Json::Text(text) => Ok((known(key)?, text.clone())),
                _ => Err(Unreadable),
            })
            .collect::<Result<_, _>>()?;
        let chosen = chosen
            .iter()
            .map(|(key, value)| match value {
                Json::Number(at) => {
                    Ok((known(key)?, usize::try_from(*at).map_err(|_| Unreadable)?))
                }
                _ => Err(Unreadable),
            })
            .collect::<Result<_, _>>()?;
        Ok(Draft {
            kind,
            changing,
            typed,
            chosen,
        })
    }

    /// A definition of `kind` from nothing.
    pub fn new(kind: Kind) -> Draft {
        Draft {
            kind,
            changing: None,
            typed: BTreeMap::new(),
            chosen: BTreeMap::new(),
        }
    }

    /// A platform for the system a remote named, which no profile answers
    /// to: the kernel as the remote said it, the rest the person's to fill.
    pub fn platform_for(kernel: &Kernel) -> Draft {
        let mut draft = Draft::new(Kind::Platform);
        draft.put("kernel", kernel.to_string());
        draft
    }

    fn typed(&self, key: &'static str) -> &str {
        self.typed.get(key).map_or("", String::as_str)
    }

    fn chosen(&self, key: &'static str) -> usize {
        self.chosen.get(key).copied().unwrap_or_default()
    }

    fn put(&mut self, key: &'static str, text: impl Into<String>) {
        self.typed.insert(key, text.into());
    }

    fn pick(&mut self, key: &'static str, at: usize) {
        self.chosen.insert(key, at);
    }

    /// The person's own definition named `name`, to be changed.
    pub fn changing(kind: Kind, name: &Name, document: &Document) -> Option<Draft> {
        let mut draft = Draft::new(kind);
        draft.fill(
            kind,
            name,
            &document.capabilities,
            &document.routes,
            &document.platforms,
            &document.sets,
        )?;
        draft.put("name", name.to_string());
        draft.changing = Some(name.clone());
        Some(draft)
    }

    /// Fills every field but the name from the definition `name` of `kind`
    /// among those given; `None` where there is none.
    fn fill(
        &mut self,
        kind: Kind,
        name: &Name,
        capabilities: &[Capability],
        routes: &[Route],
        platforms: &[Platform],
        sets: &[Set],
    ) -> Option<()> {
        match kind {
            Kind::Capability => {
                let found = capabilities.iter().find(|known| known.id == *name)?;
                self.fill_source(&found.source)?;
            }
            Kind::Route => {
                let found = routes.iter().find(|known| known.id == *name)?;
                self.put("program", found.client.program.to_string());
                self.put("before", spelt(&found.client.before));
                self.put("after", spelt(&found.client.after));
                match &found.listing {
                    Listing::Blind => self.pick("listing", 0),
                    Listing::Lists(lister) => {
                        self.pick("listing", 1);
                        self.put("lister", lister.program.to_string());
                        self.put(
                            "lister-arguments",
                            lister
                                .arguments
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join("\n"),
                        );
                        self.put("header", lister.header.to_string());
                    }
                }
                self.pick(
                    "identity",
                    match found.identity {
                        Identity::HostKey => 0,
                        Identity::Platform => 1,
                    },
                );
            }
            Kind::Platform => {
                let found = platforms.iter().find(|known| known.family == *name)?;
                self.put("kernel", found.kernel.to_string());
                match found.sockets {
                    Sockets::Unix { path_bytes } => {
                        self.pick("sockets", 0);
                        self.put("path-bytes", path_bytes.to_string());
                    }
                    Sockets::Emulated => self.pick("sockets", 1),
                }
                self.pick(
                    "forwarding",
                    match found.agent_forwarding {
                        AgentForwarding::Served => 0,
                        AgentForwarding::Refused => 1,
                    },
                );
            }
            Kind::Set => {
                let found = sets.iter().find(|known| known.id == *name)?;
                self.put(
                    "members",
                    found
                        .members
                        .iter()
                        .map(written)
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
        }
        Some(())
    }

    /// A capability of the person's own begun from `capability`, which they
    /// cannot change, opening `site` besides what it opens: its name theirs
    /// to give.
    pub fn opening(capability: &Capability, site: &Site) -> Draft {
        let mut draft = Draft::new(Kind::Capability);
        let _ = draft.fill_source(&capability.source);
        let mut sites = draft.typed("sites").to_owned();
        if !sites.is_empty() {
            sites.push('\n');
        }
        sites.push_str(&site.to_string());
        draft.put("sites", sites);
        draft
    }

    /// A capability of the person's own begun from `capability`, which
    /// leaves what a grant needs unstated: every field it states filled, its
    /// name and the rest the person's to give.
    pub fn completing(capability: &Capability) -> Draft {
        let mut draft = Draft::new(Kind::Capability);
        let _ = draft.fill_source(&capability.source);
        draft
    }

    /// The name typed, where it is one.
    pub fn named(&self) -> Option<Name> {
        Name::try_from(self.typed("name").trim()).ok()
    }

    /// A capability of the person's own whose source is the one at `at`
    /// among those a capability can have, everything else theirs to fill.
    pub fn of_source(at: usize) -> Draft {
        let mut draft = Draft::new(Kind::Capability);
        draft.pick("source", at);
        draft
    }

    /// `None` for a source of a kind this form does not define.
    #[allow(clippy::too_many_lines, reason = "one arm for each kind of source")]
    fn fill_source(&mut self, source: &Source) -> Option<()> {
        kind_of(source)?;
        match source {
            Source::Gnupg {
                installation,
                home,
                access,
            } => {
                self.pick("source", 0);
                self.put(
                    "installation",
                    match installation {
                        Installation::Registered => String::new(),
                        Installation::At(folder) => folder.to_string(),
                    },
                );
                self.put(
                    "home",
                    match home {
                        Home::Default => String::new(),
                        Home::At(folder) => folder.to_string(),
                    },
                );
                self.pick(
                    "access",
                    match access {
                        Access::Restricted => 0,
                        Access::Unrestricted => 1,
                    },
                );
            }
            Source::Agent { at } => {
                self.pick("source", 1);
                match at {
                    AgentAt::Machine => {}
                    AgentAt::Pipe(pipe) if *pipe == AgentPipe::well_known() => {
                        self.pick("agent", 0);
                    }
                    AgentAt::Pipe(pipe) => {
                        self.pick("agent", 2);
                        self.put("agent-pipe", pipe.to_string());
                    }
                    AgentAt::Gnupg { installation, home } => {
                        self.pick("agent", 1);
                        self.put(
                            "installation",
                            match installation {
                                Installation::Registered => String::new(),
                                Installation::At(folder) => folder.to_string(),
                            },
                        );
                        self.put(
                            "home",
                            match home {
                                Home::Default => String::new(),
                                Home::At(folder) => folder.to_string(),
                            },
                        );
                    }
                }
            }
            Source::Service {
                host,
                port,
                stream,
                remote,
            } => {
                self.pick("source", 2);
                self.put(
                    "host",
                    match host {
                        ServiceHost::Workstation => String::new(),
                        ServiceHost::Named(host) => host.to_string(),
                    },
                );
                self.put(
                    "port",
                    match port {
                        ServicePort::Fixed(port) => port.to_string(),
                        ServicePort::Unstated => String::new(),
                    },
                );
                self.pick(
                    "stream",
                    match stream {
                        Stream::Adb => 0,
                        Stream::Opaque => 1,
                    },
                );
                for offer in remote {
                    match offer {
                        Offer::Port(ServicePort::Fixed(port)) => {
                            self.put("remote-port", port.to_string());
                        }
                        Offer::Port(ServicePort::Unstated) => self.put("remote-port", ""),
                        Offer::PrivateSocket { variable, value } => {
                            self.put("variable", variable.to_string());
                            self.put("value", value.to_string());
                        }
                    }
                }
            }
            Source::Browser { browser, sites } => {
                self.pick("source", 3);
                match browser {
                    Browser::Default => self.pick("browser", 0),
                    Browser::Program { program, arguments } => {
                        self.pick("browser", 1);
                        self.put("browser-program", program.to_string());
                        self.put(
                            "browser-arguments",
                            arguments
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join("\n"),
                        );
                    }
                }
                self.put(
                    "sites",
                    sites
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
            Source::Serial { port, remote } => {
                self.pick("source", SERIAL);
                self.put("serial-port", port.to_string());
                self.put("remote-port", remote.to_string());
            }
            Source::Credentials { .. } | Source::Notices => {}
        }
        Some(())
    }

    /// What it can start from: every definition of its kind known by name,
    /// shipped, the organisation's or the person's.
    pub fn starts(&self, reference: &Reference, document: &Document) -> Vec<Name> {
        let mut names: Vec<Name> = match self.kind {
            Kind::Capability => document
                .capabilities
                .iter()
                .chain(&reference.capabilities)
                .filter(|known| kind_of(&known.source).is_some())
                .map(|known| known.id.clone())
                .collect(),
            Kind::Route => document
                .routes
                .iter()
                .chain(&reference.routes)
                .map(|known| known.id.clone())
                .collect(),
            Kind::Platform => document
                .platforms
                .iter()
                .chain(&reference.platforms)
                .map(|known| known.family.clone())
                .collect(),
            Kind::Set => document
                .sets
                .iter()
                .chain(&reference.sets)
                .map(|known| known.id.clone())
                .collect(),
        };
        let mut seen = std::collections::BTreeSet::new();
        names.retain(|name| seen.insert(name.clone()));
        names
    }

    pub fn edit(&mut self, edit: Edit, reference: &Reference, document: &Document) {
        match edit {
            Edit::Typed { key, text } => {
                if let Some(key) = self.keys().into_iter().find(|known| *known == key) {
                    self.put(key, text);
                }
            }
            Edit::Chose { key, at } => {
                if let Some(key) = self.keys().into_iter().find(|known| *known == key) {
                    self.pick(key, at);
                }
            }
            Edit::From(at) => {
                if let Some(name) = self.starts(reference, document).get(at).cloned() {
                    let kind = self.kind;
                    let _ = self.fill(
                        kind,
                        &name,
                        &[
                            document.capabilities.as_slice(),
                            reference.capabilities.as_slice(),
                        ]
                        .concat(),
                        &[document.routes.as_slice(), reference.routes.as_slice()].concat(),
                        &[
                            document.platforms.as_slice(),
                            reference.platforms.as_slice(),
                        ]
                        .concat(),
                        &[document.sets.as_slice(), reference.sets.as_slice()].concat(),
                    );
                }
            }
        }
    }

    /// The keys of the fields shown now, which follow from what is chosen.
    fn keys(&self) -> Vec<&'static str> {
        // A definition changed keeps its name: what is granted or set goes
        // by it.
        let mut keys = if self.changing.is_some() {
            Vec::new()
        } else {
            vec!["name"]
        };
        match self.kind {
            Kind::Capability => {
                keys.push("source");
                match self.chosen("source") {
                    0 => keys.extend(["installation", "home", "access"]),
                    1 => {
                        keys.push("agent");
                        match self.chosen("agent") {
                            1 => keys.extend(["installation", "home"]),
                            2 => keys.push("agent-pipe"),
                            _ => {}
                        }
                    }
                    2 => {
                        keys.extend(["host", "port", "stream", "remote-port", "variable", "value"]);
                    }
                    SERIAL => keys.extend(["serial-port", "remote-port"]),
                    _ => {
                        keys.push("browser");
                        if self.chosen("browser") == 1 {
                            keys.extend(["browser-program", "browser-arguments"]);
                        }
                        keys.push("sites");
                    }
                }
            }
            Kind::Route => {
                keys.extend(["program", "before", "after", "listing"]);
                if self.chosen("listing") == 1 {
                    keys.extend(["lister", "lister-arguments", "header"]);
                }
                keys.push("identity");
            }
            Kind::Platform => {
                keys.extend(["kernel", "sockets"]);
                if self.chosen("sockets") == 0 {
                    keys.push("path-bytes");
                }
                keys.push("forwarding");
            }
            Kind::Set => keys.push("members"),
        }
        keys
    }

    /// The field `key` as the form shows it, and its own check.
    #[allow(clippy::too_many_lines, reason = "one arm for each field any kind has")]
    fn field(&self, key: &'static str, ports: Ports<'_>) -> Field {
        let text = |label, hint, lines| Field {
            key,
            label,
            hint,
            input: Input::Text {
                typed: self.typed(key).to_owned(),
                lines,
            },
            invalid: self.check(key).err().map(|invalid| invalid.why),
            notes: Vec::new(),
            again: None,
        };
        let choice = |label, options: &[&str]| Field {
            key,
            label,
            hint: None,
            input: Input::Choice {
                options: options.iter().map(|&option| option.to_owned()).collect(),
                chosen: self.chosen(key),
            },
            invalid: None,
            notes: Vec::new(),
            again: None,
        };
        let serial = self.chosen("source") == SERIAL;
        match key {
            "name" => text(
                "Name",
                Some("lower-case letters, digits and hyphens"),
                false,
            ),
            "source" => choice("What it is", &SOURCES),
            "installation" => text(
                "GnuPG's folder",
                Some("the folder its bin is in; empty for the one GnuPG's installer registered"),
                false,
            ),
            "home" => text(
                "GnuPG home",
                Some("empty for the one gpgconf uses by itself"),
                false,
            ),
            "access" => choice("What a remote may ask of it", &ACCESS),
            "agent" => choice("Where your agent is", &AGENTS),
            "agent-pipe" => text(
                "Its pipe",
                Some("the name after \\\\.\\pipe\\, as the agent documents it"),
                false,
            ),
            "host" => text("Host", Some("empty for this workstation itself"), false),
            "port" => text("Port", None, false),
            "stream" => choice("What it speaks", &STREAMS),
            "remote-port" if serial => {
                let mut field = text(
                    "Port on the remote",
                    Some("where esptool, PlatformIO or any pyserial tool there connects"),
                    false,
                );
                if let Ok(remote) = port(key, self.typed(key).trim()) {
                    field.notes.push(words::rfc2217(remote));
                }
                field
            }
            "remote-port" => text(
                "Port on the remote",
                Some("where the remote's tool connects"),
                false,
            ),
            "serial-port" => self.port_field(ports),
            "variable" => text(
                "Or a variable the remote's tool reads",
                Some("Hedwig points it at a socket only the remote user reaches"),
                false,
            ),
            "value" => text(
                "Its value",
                Some("with {} where the socket's path goes"),
                false,
            ),
            "program" | "browser-program" => text(
                "Program",
                Some("found on the search path, as ssh is"),
                false,
            ),
            "before" => text(
                "Arguments before Hedwig's options",
                Some("one to a line; {address} is the remote's address"),
                true,
            ),
            "after" => text(
                "Arguments after them",
                Some("one to a line; {address} is the remote's address"),
                true,
            ),
            "listing" => choice("Which remotes are running", &LISTINGS),
            "lister" => text("Program that lists them", None, false),
            "lister-arguments" => text("Its arguments", Some("one to a line"), true),
            "header" => text(
                "Lines before the first remote",
                Some("a table's heading; empty for none"),
                false,
            ),
            "identity" => choice("What makes a remote the same remote", &IDENTITIES),
            "kernel" => text(
                "What the remote calls its system",
                Some("as uname -s prints it there"),
                false,
            ),
            "sockets" => choice("What its SSH server can bind", &SOCKETS),
            "path-bytes" => text(
                "Bytes a socket's path may take",
                Some("its sun_path, terminator included"),
                false,
            ),
            "forwarding" => choice("Agent forwarding by its own SSH server", &FORWARDING),
            "browser" => choice("Which browser opens a page", &BROWSERS),
            "browser-arguments" => text(
                "Its arguments",
                Some(
                    "one to a line, the page's address after them; a browser's profile is chosen here",
                ),
                true,
            ),
            "sites" => text(
                "Sites it opens",
                Some(
                    "one to a line: https://host, https://*.host for it and every name beneath it, \
                     :port where it is not the scheme's own; http://localhost for the remote's own \
                     loopback. A page no site admits is refused, naming the site to add",
                ),
                true,
            ),
            _ => text(
                "Remotes",
                Some("one to a line: the route, a space, then the remote or a pattern with *"),
                true,
            ),
        }
    }

    /// The serial port, picked from the workstation's ports as last read,
    /// with the one the draft names kept among them where it is not there
    /// now, so changing a definition never drops its port unseen.
    fn port_field(&self, ports: Ports<'_>) -> Field {
        let key = "serial-port";
        let named = self.typed(key).trim();
        let (listed, mut notes): (&[SerialPort], Vec<String>) = match ports {
            Some(Some(Ok(listed))) => (listed, Vec::new()),
            Some(Some(Err(refusal))) => (
                &[],
                vec![format!(
                    "This workstation's serial ports could not be read: {refusal}."
                )],
            ),
            Some(None) | None => (
                &[],
                vec!["Reading this workstation's serial ports.".to_owned()],
            ),
        };
        let mut options: Vec<Picked> = listed
            .iter()
            .map(|serial| Picked {
                label: words::serial_port(serial),
                value: serial.port.to_string(),
            })
            .collect();
        let same = |value: &str| value.eq_ignore_ascii_case(named);
        if !named.is_empty() && !options.iter().any(|option| same(&option.value)) {
            options.push(Picked {
                label: format!("{named}, which is not among this workstation's serial ports now"),
                value: named.to_owned(),
            });
        }
        if matches!(ports, Some(Some(Ok(listed))) if listed.is_empty()) && named.is_empty() {
            notes.push(
                "This workstation has no serial port now: plug the board in, then look again."
                    .to_owned(),
            );
        }
        // What a remote's tool cannot do through the port picked, by the USB
        // device Windows lists behind it.
        if let Some(beyond) = listed
            .iter()
            .find(|serial| same(serial.port.as_str()))
            .and_then(SerialPort::beyond)
        {
            notes.push(words::beyond(beyond));
        }
        Field {
            key,
            label: "Serial port",
            hint: Some("as Windows lists it; the remote is lent it for one connection at a time"),
            input: Input::Pick {
                chosen: options.iter().position(|option| same(&option.value)),
                options,
            },
            invalid: self.check(key).err().map(|invalid| invalid.why),
            notes,
            again: Some("Look again for serial ports"),
        }
    }

    /// The fields shown now; `ports` is what a serial port is picked from.
    pub fn fields(&self, ports: Ports<'_>) -> Vec<Field> {
        self.keys()
            .into_iter()
            .map(|key| self.field(key, ports))
            .collect()
    }

    /// Whether the form shows what the workstation's serial ports are.
    pub fn lists_ports(&self) -> bool {
        self.keys().contains(&"serial-port")
    }

    /// The check of one field as typed; an empty optional field passes.
    fn check(&self, key: &'static str) -> Result<(), Invalid> {
        let text = self.typed(key).trim();
        match key {
            "name" => checked(key, text, Name::try_from(text)).map(drop),
            "home" | "installation" if !text.is_empty() => {
                checked(key, text, Folder::try_from(text)).map(drop)
            }
            "host" if !text.is_empty() => checked(key, text, Host::try_from(text)).map(drop),
            "port" | "remote-port"
                if !text.is_empty() || key == "port" || self.chosen("source") == SERIAL =>
            {
                port(key, text).map(drop)
            }
            "serial-port" if text.is_empty() => Err(invalid(key, "Choose the serial port.")),
            "serial-port" => checked(key, text, PortName::try_from(text)).map(drop),
            "agent-pipe" => checked(key, text, AgentPipe::try_from(text)).map(drop),
            "variable" if !text.is_empty() => {
                checked(key, text, Variable::try_from(text)).map(drop)
            }
            "value" if !text.is_empty() || !self.typed("variable").trim().is_empty() => {
                checked(key, text, Template::try_from(text)).map(drop)
            }
            "program" | "lister" | "browser-program" => {
                checked(key, text, Program::try_from(text)).map(drop)
            }
            "before" | "after" | "lister-arguments" => arguments(key, self.typed(key)).map(drop),
            "header" if !text.is_empty() => text.parse::<u8>().map(drop).map_err(|_| {
                invalid(
                    key,
                    format!("\"{text}\" is not a number of lines from 0 to 255."),
                )
            }),
            "kernel" => checked(key, text, Kernel::try_from(text)).map(drop),
            "path-bytes" => text.parse::<NonZeroU16>().map(drop).map_err(|_| {
                invalid(
                    key,
                    format!("\"{text}\" is not a number of bytes from 1 to 65535."),
                )
            }),
            "members" => lines(self.typed(key)).try_for_each(|line| member(line).map(drop)),
            "browser-arguments" => lines(self.typed(key))
                .try_for_each(|line| checked(key, line, Verbatim::try_from(line)).map(drop)),
            "sites" => lines(self.typed(key))
                .try_for_each(|line| site(line).map(drop).map_err(|why| invalid(key, why))),
            _ => Ok(()),
        }
    }

    #[allow(clippy::too_many_lines, reason = "one arm for each kind of source")]
    fn source(&self) -> Result<Source, Invalid> {
        let text = |key| self.typed(key).trim();
        Ok(match self.chosen("source") {
            0 => Source::Gnupg {
                installation: if text("installation").is_empty() {
                    Installation::Registered
                } else {
                    Installation::At(checked(
                        "installation",
                        text("installation"),
                        Folder::try_from(text("installation")),
                    )?)
                },
                home: if text("home").is_empty() {
                    Home::Default
                } else {
                    Home::At(checked(
                        "home",
                        text("home"),
                        Folder::try_from(text("home")),
                    )?)
                },
                access: if self.chosen("access") == 1 {
                    Access::Unrestricted
                } else {
                    Access::Restricted
                },
            },
            1 => Source::Agent {
                at: match self.chosen("agent") {
                    1 => AgentAt::Gnupg {
                        installation: if text("installation").is_empty() {
                            Installation::Registered
                        } else {
                            Installation::At(checked(
                                "installation",
                                text("installation"),
                                Folder::try_from(text("installation")),
                            )?)
                        },
                        home: if text("home").is_empty() {
                            Home::Default
                        } else {
                            Home::At(checked(
                                "home",
                                text("home"),
                                Folder::try_from(text("home")),
                            )?)
                        },
                    },
                    2 => AgentAt::Pipe(checked(
                        "agent-pipe",
                        text("agent-pipe"),
                        AgentPipe::try_from(text("agent-pipe")),
                    )?),
                    _ => AgentAt::Pipe(AgentPipe::well_known()),
                },
            },
            SERIAL => Source::Serial {
                port: checked(
                    "serial-port",
                    text("serial-port"),
                    PortName::try_from(text("serial-port")),
                )?,
                remote: port("remote-port", text("remote-port"))?,
            },
            BROWSER => Source::Browser {
                browser: if self.chosen("browser") == 1 {
                    Browser::Program {
                        program: checked(
                            "browser-program",
                            text("browser-program"),
                            Program::try_from(text("browser-program")),
                        )?,
                        arguments: lines(self.typed("browser-arguments"))
                            .map(|line| {
                                checked("browser-arguments", line, Verbatim::try_from(line))
                            })
                            .collect::<Result<_, _>>()?,
                    }
                } else {
                    Browser::Default
                },
                sites: lines(self.typed("sites"))
                    .map(|line| site(line).map_err(|why| invalid("sites", why)))
                    .collect::<Result<_, _>>()?,
            },
            _ => {
                let mut remote = Vec::new();
                if !text("variable").is_empty() {
                    remote.push(Offer::PrivateSocket {
                        variable: checked(
                            "variable",
                            text("variable"),
                            Variable::try_from(text("variable")),
                        )?,
                        value: checked("value", text("value"), Template::try_from(text("value")))?,
                    });
                }
                if !text("remote-port").is_empty() {
                    remote.push(Offer::Port(ServicePort::Fixed(port(
                        "remote-port",
                        text("remote-port"),
                    )?)));
                }
                if remote.is_empty() {
                    return Err(invalid(
                        "remote-port",
                        "Say where the remote's tool finds it: a port, or a variable and its value.",
                    ));
                }
                Source::Service {
                    host: if text("host").is_empty() {
                        ServiceHost::Workstation
                    } else {
                        ServiceHost::Named(checked(
                            "host",
                            text("host"),
                            Host::try_from(text("host")),
                        )?)
                    },
                    port: ServicePort::Fixed(port("port", text("port"))?),
                    stream: if self.chosen("stream") == 0 {
                        Stream::Adb
                    } else {
                        Stream::Opaque
                    },
                    remote,
                }
            }
        })
    }

    /// The change this draft asks for.
    fn change(&self) -> Result<Change, Invalid> {
        for key in self.keys() {
            self.check(key)?;
        }
        let name = self.changing.clone().map_or_else(
            || {
                checked(
                    "name",
                    self.typed("name").trim(),
                    Name::try_from(self.typed("name").trim()),
                )
            },
            Ok,
        )?;
        let text = |key| self.typed(key).trim();
        Ok(match self.kind {
            Kind::Capability => Change::Define(Capability {
                id: name,
                source: self.source()?,
            }),
            Kind::Route => Change::DefineRoute(Route {
                id: name,
                client: Client {
                    program: checked(
                        "program",
                        text("program"),
                        Program::try_from(text("program")),
                    )?,
                    before: arguments("before", self.typed("before"))?,
                    after: arguments("after", self.typed("after"))?,
                },
                listing: if self.chosen("listing") == 1 {
                    Listing::Lists(Lister {
                        program: checked(
                            "lister",
                            text("lister"),
                            Program::try_from(text("lister")),
                        )?,
                        arguments: lines(self.typed("lister-arguments"))
                            .map(|line| checked("lister-arguments", line, Verbatim::try_from(line)))
                            .collect::<Result<_, _>>()?,
                        header: text("header").parse().unwrap_or_default(),
                    })
                } else {
                    Listing::Blind
                },
                identity: if self.chosen("identity") == 1 {
                    Identity::Platform
                } else {
                    Identity::HostKey
                },
            }),
            Kind::Platform => Change::DefinePlatform(Platform {
                family: name,
                kernel: checked("kernel", text("kernel"), Kernel::try_from(text("kernel")))?,
                sockets: if self.chosen("sockets") == 0 {
                    Sockets::Unix {
                        path_bytes: text("path-bytes")
                            .parse()
                            .map_err(|_| invalid("path-bytes", "Nothing is filled in."))?,
                    }
                } else {
                    Sockets::Emulated
                },
                agent_forwarding: if self.chosen("forwarding") == 1 {
                    AgentForwarding::Refused
                } else {
                    AgentForwarding::Served
                },
            }),
            Kind::Set => Change::DefineSet(Set {
                id: name,
                members: lines(self.typed("members"))
                    .map(member)
                    .collect::<Result<_, _>>()?,
            }),
        })
    }
}

/// What removing the person's `platform` ends: a profile is matched by the
/// system a remote names, never by a name anything holds, so the core takes
/// its removal whatever it serves. Which profile then answers is the model's
/// to say.
fn unanswered(platform: &Platform, reference: &Reference, document: &Document) -> String {
    let (family, kernel) = (&platform.family, &platform.kernel);
    let after = Catalogue::new(reference.clone())
        .ok()
        .and_then(|catalogue| {
            let mut configuration = Configuration::restore(document.clone()).ok()?;
            configuration
                .apply(&catalogue, Change::UndefinePlatform(family.clone()))
                .ok()?;
            Some(
                configuration
                    .platform_answering(&catalogue, kernel)
                    .map(|answering| answering.family.clone()),
            )
        });
    let gone = format!("{family}, your platform, is no longer defined.");
    match after {
        Some(Ok(answering)) => {
            format!("{gone} A remote that calls its system {kernel} is then served as {answering}.")
        }
        // The removal leaves the system unanswered, which says itself.
        Some(Err(Refusal::UnknownKernel(_))) => {
            format!("{gone} A remote that calls its system {kernel} is then served by no profile.")
        }
        Some(Err(refusal)) => format!(
            "{gone} A remote that calls its system {kernel} is then served by no profile: {refusal}."
        ),
        None => gone,
    }
}

/// What defining `platform` lets through: the profile a remote naming its
/// system is served by, which carries what is granted to that remote in the
/// forms its sockets take. Which profile served it before is the model's to
/// say.
fn served(platform: &Platform, vocabulary: &Vocabulary, document: &Document) -> String {
    let (family, kernel) = (&platform.family, &platform.kernel);
    let before = vocabulary.catalogue().and_then(|catalogue| {
        let configuration = Configuration::restore(document.clone()).ok()?;
        Some(
            configuration
                .platform_answering(catalogue, kernel)
                .map(|answering| answering.family.clone()),
        )
    });
    let now = format!(
        "A remote that calls its system {kernel} is then served as {family}: what is granted to \
         it is carried in the forms its sockets take"
    );
    match before {
        Some(Ok(before)) if before == *family => format!("{now}, as you define it here."),
        Some(Ok(before)) => format!("{now}, where it was served as {before}."),
        Some(Err(_)) => format!("{now}, where no profile served it."),
        None => format!("{now}."),
    }
}

/// The form for the definition being made, as the window shows it.
#[derive(Debug, PartialEq, Eq)]
pub struct Form {
    pub heading: String,
    /// What it can start from, and the definition a choice fills it from.
    pub starts: Vec<String>,
    pub fields: Vec<Field>,
    /// The act that makes it, or the sentence of what still stands in the way.
    pub ready: Result<Shown, String>,
    /// The core's refusal of the last time it was asked.
    pub refused: Option<String>,
}

impl Form {
    /// The form for `draft`; `ports` is the workstation's serial ports as
    /// last read, which a serial port is picked from.
    pub fn of(
        draft: &Draft,
        vocabulary: &Vocabulary,
        document: &Document,
        ports: Ports<'_>,
        refused: Option<String>,
    ) -> Form {
        let reference = vocabulary.reference();
        let noun = draft.kind.noun();
        let heading = match &draft.changing {
            Some(name) => format!("Change your {noun} {name}"),
            None => format!("Define a {noun}"),
        };
        let judge = Judge::of(Some(document), Some(vocabulary));
        let ready = draft
            .change()
            .map(|change| {
                let label = match &draft.changing {
                    Some(name) => format!("Change {name}"),
                    None => format!("Define {}", draft.typed("name").trim()),
                };
                let platform = match &change {
                    Change::DefinePlatform(platform) => Some(platform.clone()),
                    _ => None,
                };
                judge.act(label, Answer::Label, change, || match platform {
                    Some(platform) => served(&platform, vocabulary, document),
                    None => format!(
                        "What goes by this name now goes by what you define: anything granted \
                         or set for it takes the {noun} as you define it here."
                    ),
                })
            })
            .map_err(|invalid| match invalid.key {
                "remote-port" if invalid.why.starts_with("Say") => invalid.why,
                _ => "Some of what is filled in cannot be used yet; each says why beneath it."
                    .to_owned(),
            });
        Form {
            heading,
            starts: if draft.changing.is_some() {
                Vec::new()
            } else {
                draft
                    .starts(reference, document)
                    .iter()
                    .map(ToString::to_string)
                    .collect()
            },
            fields: draft.fields(ports),
            ready,
            refused,
        }
    }
}

/// One definition of the person's own, as the window lists it.
#[derive(Debug, PartialEq, Eq)]
pub struct Defined {
    pub kind: Kind,
    pub name: Name,
    /// What it is, in a sentence.
    pub says: String,
    /// What a remote's tool cannot be given through it as defined, in words.
    pub beyond: Option<String>,
    /// Removing it, asked first.
    pub remove: Shown,
    /// The core's refusal of the last act made on it.
    pub refused: Option<String>,
}

/// A name defined outside the person's configuration, and whose it is.
#[derive(Debug, PartialEq, Eq)]
pub struct Elsewhere {
    pub name: Name,
    pub by: String,
    /// What a remote's tool cannot be given through it as defined, in words.
    pub beyond: Option<String>,
}

/// What the person has defined, and what is defined outside their document,
/// by kind.
#[derive(Debug, PartialEq, Eq)]
pub struct Definitions {
    pub own: Vec<Defined>,
    /// The names defined outside the person's configuration - what Hedwig
    /// ships and the organisation's starting point - which they can start
    /// from and cannot change, each with whose it is.
    pub outside: Vec<(Kind, Vec<Elsewhere>)>,
    /// Each name two sources define differently, said with every source:
    /// nothing goes by it until all but one rename it.
    pub collisions: Vec<String>,
    /// What no definition can give a remote's tool, each with why and what
    /// would change it, so the person reads it where they would define it.
    pub beyond: Vec<String>,
}

/// Whose a definition is, as the person reads it.
pub fn whose(tier: Tier) -> String {
    match tier {
        Tier::Ships => "what Hedwig ships".to_owned(),
        Tier::Start(audience) => words::place(Where {
            audience,
            part: Part::Start,
        }),
        Tier::Person => "you".to_owned(),
    }
}

fn section(section: Section) -> Option<Kind> {
    match section {
        Section::Capabilities => Some(Kind::Capability),
        Section::Routes => Some(Kind::Route),
        Section::Platforms => Some(Kind::Platform),
        Section::Sets => Some(Kind::Set),
        _ => None,
    }
}

/// A name two sources define differently, with each of them.
fn collision(collision: &Collision) -> String {
    let noun = section(collision.section).map_or("definition", Kind::noun);
    let by: Vec<String> = collision.by.iter().copied().map(whose).collect();
    let by = match by.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => by.join(""),
    };
    format!(
        "The {noun} {} is defined differently by {by}, so nothing that goes by it is served \
         until all but one of them rename theirs.",
        collision.name
    )
}

#[allow(clippy::too_many_lines, reason = "one arm for each kind of source")]
fn says_source(source: &Source) -> String {
    match source {
        Source::Gnupg {
            installation,
            home,
            access,
        } => {
            let mut text = match access {
                Access::Restricted => "gpg-agent's restricted socket".to_owned(),
                Access::Unrestricted => "gpg-agent's unrestricted socket".to_owned(),
            };
            if let Installation::At(folder) = installation {
                let _ = write!(text, ", of the GnuPG in {folder}");
            }
            if let Home::At(folder) = home {
                let _ = write!(text, ", for the GnuPG home {folder}");
            }
            text
        }
        Source::Agent {
            at: AgentAt::Pipe(pipe),
        } if *pipe == AgentPipe::well_known() => format!(
            "your SSH agent at the pipe {pipe}, which Windows' SSH clients use, whichever program \
             holds it"
        ),
        Source::Agent {
            at: AgentAt::Pipe(pipe),
        } => format!("your SSH agent at the pipe {pipe}"),
        Source::Agent {
            at: AgentAt::Gnupg { installation, home },
        } => {
            let mut text = "gpg-agent's SSH socket".to_owned();
            if let Installation::At(folder) = installation {
                let _ = write!(text, ", of the GnuPG in {folder}");
            }
            if let Home::At(folder) = home {
                let _ = write!(text, ", for the GnuPG home {folder}");
            }
            text
        }
        Source::Serial { port, remote } => format!(
            "the serial port {port} on this workstation. {}",
            words::rfc2217(*remote)
        ),
        Source::Agent {
            at: AgentAt::Machine,
        } => "keys Hedwig makes in this workstation's TPM, which only it can use".to_owned(),
        Source::Credentials { git, sites } if sites.is_empty() => format!(
            "your credentials as {git} credential fill gives them on this workstation, for no \
             site yet: a remote's git is refused, naming the site to add"
        ),
        Source::Credentials { git, sites } => format!(
            "your credentials as {git} credential fill gives them on this workstation, for {}",
            sites
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Source::Notices => {
            "your attention: what a remote's jobs say reaches you, in that remote's words"
                .to_owned()
        }
        Source::Browser { browser, sites } => {
            let opener = match browser {
                Browser::Default => "your default browser".to_owned(),
                Browser::Program { program, .. } => format!("{program}"),
            };
            if sites.is_empty() {
                format!(
                    "{opener}, opening no site yet: a remote's sign-in is refused, naming the \
                     site to add"
                )
            } else {
                format!(
                    "{opener}, opening {}",
                    sites
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
        Source::Service {
            host, port, remote, ..
        } => {
            let at = match host {
                ServiceHost::Workstation => "this workstation".to_owned(),
                ServiceHost::Named(host) => host.to_string(),
            };
            let port = match port {
                ServicePort::Fixed(port) => port.to_string(),
                ServicePort::Unstated => "a port not yet stated".to_owned(),
            };
            let found: Vec<String> = remote
                .iter()
                .map(|offer| match offer {
                    Offer::Port(ServicePort::Fixed(port)) => format!("port {port}"),
                    Offer::Port(ServicePort::Unstated) => "a port not yet stated".to_owned(),
                    Offer::PrivateSocket { variable, .. } => format!("{variable}"),
                })
                .collect();
            format!(
                "the service at {at}, port {port}; on the remote, through {}",
                found.join(" or ")
            )
        }
    }
}

fn says_route(route: &Route) -> String {
    let words = |arguments: &[Argument]| {
        arguments
            .iter()
            .map(|argument| match argument {
                Argument::Address => "<address>".to_owned(),
                Argument::Literal(text) => text.to_string(),
            })
            .collect::<Vec<_>>()
    };
    let mut command = vec![route.client.program.to_string()];
    command.extend(words(&route.client.before));
    command.push("<Hedwig's options>".to_owned());
    command.extend(words(&route.client.after));
    let listed = match &route.listing {
        Listing::Blind => "nothing lists its remotes".to_owned(),
        Listing::Lists(lister) => format!("{} lists the running ones", lister.program),
    };
    let known = match route.identity {
        Identity::HostKey => "each known by its host key",
        Identity::Platform => "each known by your sign-in to the platform",
    };
    format!("{}; {listed}; {known}", command.join(" "))
}

fn says_platform(platform: &Platform) -> String {
    let sockets = match platform.sockets {
        Sockets::Unix { path_bytes } => {
            format!("Unix-domain sockets, paths of up to {path_bytes} bytes")
        }
        Sockets::Emulated => "no Unix-domain sockets".to_owned(),
    };
    let forwarding = match platform.agent_forwarding {
        AgentForwarding::Served => "agent forwarding served",
        AgentForwarding::Refused => "agent forwarding refused",
    };
    format!(
        "a remote that calls its system {}; {sockets}; {forwarding}",
        platform.kernel
    )
}

fn says_set(set: &Set) -> String {
    let members: Vec<String> = set
        .members
        .iter()
        .map(|member| match member {
            Member::One(remote) => remote.to_string(),
            Member::Matching { route, pattern } => format!("{pattern} on {route}"),
        })
        .collect();
    if members.is_empty() {
        "no remote yet".to_owned()
    } else {
        members.join(", ")
    }
}

/// Removing a definition of the person's, asked first with what it ends.
fn removal(name: &Name, undefine: Change, ends: String) -> Shown {
    Shown::Offered {
        label: format!("Remove {name}..."),
        act: Act::Confirm {
            request: Request::Change(undefine),
            consequence: ends,
            answer: format!("Remove {name}"),
        },
    }
}

impl Definitions {
    /// What the window lists: the person's own definitions from their
    /// document, each with removing it; `refused` is the core's refusal of
    /// the last act made on one, by kind and name.
    #[allow(
        clippy::too_many_lines,
        reason = "one list for each kind of definition"
    )]
    pub fn of(
        outside: &Outside,
        reference: &Reference,
        document: &Document,
        refused: Option<(Kind, &Name, &str)>,
    ) -> Definitions {
        let mut own = Vec::new();
        let named_by = |kind: Kind, name: &Name| {
            format!(
                "{name}, your {}, is no longer defined. Hedwig refuses this while anything you \
                 granted or set goes by it.",
                kind.noun()
            )
        };
        let mut add = |kind: Kind, name: &Name, says: String, undefine: Change, ends: String| {
            let refused = refused
                .as_ref()
                .filter(|(at, named, _)| *at == kind && *named == name)
                .map(|(_, _, why)| (*why).to_owned());
            own.push(Defined {
                kind,
                name: name.clone(),
                says,
                beyond: None,
                remove: removal(name, undefine, ends),
                refused,
            });
        };
        for known in &document.capabilities {
            add(
                Kind::Capability,
                &known.id,
                says_source(&known.source),
                Change::Undefine(known.id.clone()),
                named_by(Kind::Capability, &known.id),
            );
        }
        for known in &document.routes {
            add(
                Kind::Route,
                &known.id,
                says_route(known),
                Change::UndefineRoute(known.id.clone()),
                named_by(Kind::Route, &known.id),
            );
        }
        for known in &document.platforms {
            add(
                Kind::Platform,
                &known.family,
                says_platform(known),
                Change::UndefinePlatform(known.family.clone()),
                unanswered(known, reference, document),
            );
        }
        for known in &document.sets {
            add(
                Kind::Set,
                &known.id,
                says_set(known),
                Change::UndefineSet(known.id.clone()),
                named_by(Kind::Set, &known.id),
            );
        }
        // An imported document can leave a service's port unstated, which
        // the form cannot.
        for (defined, known) in own.iter_mut().zip(&document.capabilities) {
            defined.beyond = Beyond::of_capability(known).map(words::beyond);
        }
        let elsewhere = |name: &Name, by: Tier| Elsewhere {
            name: name.clone(),
            by: whose(by),
            beyond: None,
        };
        Definitions {
            own,
            outside: vec![
                (
                    Kind::Capability,
                    outside
                        .capabilities
                        .iter()
                        .map(|known| Elsewhere {
                            beyond: Beyond::of_capability(&known.definition).map(words::beyond),
                            ..elsewhere(&known.definition.id, known.by)
                        })
                        .collect(),
                ),
                (
                    Kind::Route,
                    outside
                        .routes
                        .iter()
                        .map(|known| elsewhere(&known.definition.id, known.by))
                        .collect(),
                ),
                (
                    Kind::Platform,
                    outside
                        .platforms
                        .iter()
                        .map(|known| elsewhere(&known.definition.family, known.by))
                        .collect(),
                ),
                (
                    Kind::Set,
                    outside
                        .sets
                        .iter()
                        .map(|known| elsewhere(&known.definition.id, known.by))
                        .collect(),
                ),
            ],
            collisions: outside.collisions.iter().map(collision).collect(),
            beyond: outside.beyond.iter().copied().map(words::beyond).collect(),
        }
    }
}
