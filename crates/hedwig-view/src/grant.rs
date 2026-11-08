//! A grant being made: what the person has chosen so far, and what is still
//! owed before it can be asked of the core.
//!
//! A draft is partial input, given up only when the person submits it or
//! discards it. The window keeps it on disk in its [`Draft::written`] form,
//! so that it outlives the window's process, the presence, a sign-out and a
//! restart. Nothing here decides whether a grant is allowed - the core
//! does, and its refusal is shown against the field it concerns - but what a
//! grant must name is read with the model's own functions, so the form and
//! the core cannot ask for different things.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use hedwig_model::beyond::Beyond;
use hedwig_model::capability::{
    Capability, Exposure, Holds, Lends, LentKey, Setup, Source, Toward,
};
use hedwig_model::config::{Activation, Change, Document, Grant, Reference, Terms};
use hedwig_model::json::{self, Json, Layout};
use hedwig_model::protocol::{AgentKey, Lendable, Workstation};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Discovery, Granted, RemoteId};
use hedwig_model::text::{Address, DeviceSerial, Name, Pattern, SshKey, TextError, Words};
use hedwig_model::trail::Keyring;
use hedwig_model::wire::Wire;

/// A part of the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Capability,
    Remotes,
    Activation,
    Setup,
    Acknowledged,
    Lends,
}

/// What a draft still owes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owed {
    Capability,
    Remotes,
    Activation,
    /// The grant exposes these and has not named them.
    Acknowledgement(Exposure),
    /// What was typed for the hosts a lent key may log in to names none:
    /// the key, and why.
    Hosts {
        key: SshKey,
        why: String,
    },
    /// The capability chosen leaves what a grant needs unstated - a preset
    /// whose port only the person knows - so the person's own is defined
    /// from it first.
    Incomplete(Name),
}

impl Owed {
    pub fn field(&self) -> Field {
        match self {
            Owed::Capability | Owed::Incomplete(_) => Field::Capability,
            Owed::Remotes => Field::Remotes,
            Owed::Activation => Field::Activation,
            Owed::Acknowledgement(_) => Field::Acknowledged,
            Owed::Hosts { .. } => Field::Lends,
        }
    }
}

/// Which remotes the person is naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aim {
    /// Every remote on the chosen route.
    Route,
    /// One remote, or a pattern, typed on the chosen route.
    Named,
    /// The members of a named set.
    Set,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub capability: Option<Name>,
    pub aim: Aim,
    /// The route the remotes are on, for every remote there or a name.
    pub route: Option<Name>,
    /// What the person typed for one remote or a pattern, kept whether or
    /// not it names any yet.
    pub typed: String,
    /// The remotes the choices above name, once they name some.
    pub remotes: Option<Granted>,
    pub activation: Option<Activation>,
    /// Whether Hedwig may write the remote tool's own configuration. Never
    /// filled in for the person.
    pub setup: Setup,
    pub acknowledged: Exposure,
    /// The devices or keys lent, where the capability's source holds them:
    /// none until the person names one, and every one only as a choice of
    /// its own.
    pub lends: Lends,
    /// What the person typed for the hosts each lent key may log in to, by
    /// key: empty for anywhere.
    pub hosts: BTreeMap<SshKey, String>,
}

impl Default for Draft {
    fn default() -> Draft {
        Draft {
            capability: None,
            aim: Aim::Route,
            route: None,
            typed: String::new(),
            remotes: None,
            activation: None,
            setup: Setup::Inspect,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
            hosts: BTreeMap::new(),
        }
    }
}

/// A draft's written form could not be read back: it was cut short, or
/// written by a build that wrote it otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable;

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the grant being made could not be read back")
    }
}

impl std::error::Error for Unreadable {}

/// The keys of a draft's written form, in the order written.
const KEYS: [&str; 10] = [
    "capability",
    "aim",
    "route",
    "typed",
    "remotes",
    "activation",
    "setup",
    "acknowledged",
    "lends",
    "hosts",
];

impl Aim {
    fn word(self) -> &'static str {
        match self {
            Aim::Route => "route",
            Aim::Named => "named",
            Aim::Set => "set",
        }
    }

    fn from_word(word: &str) -> Option<Aim> {
        [Aim::Route, Aim::Named, Aim::Set]
            .into_iter()
            .find(|aim| aim.word() == word)
    }
}

/// Where a lent key may be used, from what the person typed: anywhere where
/// nothing is, else only for logging in to the hosts each line names by its
/// key, as `ssh-keyscan` or a `known_hosts` line prints it.
///
/// # Errors
///
/// The sentence that says which line names no host's key.
pub fn toward(typed: &str) -> Result<Toward, String> {
    let mut hosts = BTreeSet::new();
    for line in typed
        .split(['\r', '\n'])
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        hosts.insert(crate::fingerprint::key_in(line).ok_or_else(|| {
            format!(
                "\"{line}\" names no host's key: paste each host's key as ssh-keyscan or a \
                 known_hosts line prints it, one to a line."
            )
        })?);
    }
    Ok(if hosts.is_empty() {
        Toward::Anywhere
    } else {
        Toward::Hosts(hosts)
    })
}

/// The hosts a lent key may log in to, as the person reads and types them:
/// each host's key as OpenSSH writes it, one to a line; nothing for
/// anywhere.
pub fn hosts_written(toward: &Toward) -> String {
    match toward {
        Toward::Anywhere => String::new(),
        Toward::Hosts(hosts) => hosts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// What `capability`'s source last offered, where the core has read it.
pub fn offered<'w>(found: Option<&'w Workstation>, capability: &Name) -> Option<&'w Keyring> {
    found?
        .keys
        .iter()
        .find(|offering| offering.capability == *capability)
        .map(|offering| &offering.keyring)
}

/// A capability by name: the person's own definition, or the shipped one.
pub fn capability(reference: &Reference, document: &Document, id: &Name) -> Option<Capability> {
    document
        .capabilities
        .iter()
        .chain(&reference.capabilities)
        .find(|capability| capability.id == *id)
        .cloned()
}

/// The remotes a line of text names on `route`: a pattern when it holds a
/// `*`, one remote otherwise.
pub fn named(route: &Name, text: &str) -> Result<Granted, TextError> {
    if text.contains('*') {
        Ok(Granted::Matching {
            route: route.clone(),
            pattern: Pattern::try_from(text)?,
        })
    } else {
        Ok(Granted::One(RemoteId {
            route: route.clone(),
            address: Address::try_from(text)?,
        }))
    }
}

impl Draft {
    /// The draft as one line of the model's written forms, each field as the
    /// configuration document writes it.
    pub fn written(&self) -> String {
        let fields = [
            self.capability.put(),
            Json::Text(self.aim.word().to_owned()),
            self.route.put(),
            Json::Text(self.typed.clone()),
            self.remotes.put(),
            self.activation.put(),
            self.setup.put(),
            self.acknowledged.put(),
            self.lends.put(),
            Json::Map(
                self.hosts
                    .iter()
                    .map(|(key, typed)| (key.to_string(), Json::Text(typed.clone())))
                    .collect(),
            ),
        ];
        let members = KEYS
            .iter()
            .zip(fields)
            .map(|(key, value)| ((*key).to_owned(), value))
            .collect();
        json::render(&Json::Map(members), Layout::Line)
    }

    /// A draft from its written form.
    ///
    /// # Errors
    ///
    /// [`Unreadable`] where `text` is not the written form of a draft.
    pub fn read(text: &str) -> Result<Draft, Unreadable> {
        let Ok(Json::Map(mut members)) = json::parse(text) else {
            return Err(Unreadable);
        };
        if members.len() != KEYS.len() {
            return Err(Unreadable);
        }
        let mut take = |key: &str| {
            members
                .iter()
                .position(|(known, _)| known == key)
                .map(|at| members.swap_remove(at).1)
                .ok_or(Unreadable)
        };
        let Json::Text(aim) = take("aim")? else {
            return Err(Unreadable);
        };
        let Json::Text(typed) = take("typed")? else {
            return Err(Unreadable);
        };
        let Json::Map(hosts) = take("hosts")? else {
            return Err(Unreadable);
        };
        let hosts = hosts
            .into_iter()
            .map(|(key, typed)| match typed {
                Json::Text(typed) => SshKey::try_from(key.as_str())
                    .map(|key| (key, typed))
                    .map_err(|_| Unreadable),
                _ => Err(Unreadable),
            })
            .collect::<Result<_, _>>()?;
        Ok(Draft {
            capability: Wire::take(take("capability")?).map_err(|_| Unreadable)?,
            aim: Aim::from_word(&aim).ok_or(Unreadable)?,
            route: Wire::take(take("route")?).map_err(|_| Unreadable)?,
            typed,
            remotes: Wire::take(take("remotes")?).map_err(|_| Unreadable)?,
            activation: Wire::take(take("activation")?).map_err(|_| Unreadable)?,
            setup: Wire::take(take("setup")?).map_err(|_| Unreadable)?,
            acknowledged: Wire::take(take("acknowledged")?).map_err(|_| Unreadable)?,
            lends: Wire::take(take("lends")?).map_err(|_| Unreadable)?,
            hosts,
        })
    }

    /// What the chosen capability exposes that a grant must name.
    pub fn exposes(&self, reference: &Reference, document: &Document) -> Exposure {
        self.capability
            .as_ref()
            .and_then(|id| capability(reference, document, id))
            .map_or(Exposure::NONE, |capability| {
                capability.exposure().common(Exposure::ACKNOWLEDGED)
            })
    }

    /// The activations the chosen remotes can have: following a remote's life
    /// needs a route that can see it.
    pub fn activations(&self, reference: &Reference) -> Vec<Activation> {
        // A set's members are on routes this form cannot see, so a grant to
        // one is offered what every route can do.
        let on = self.remotes.as_ref().and_then(|remotes| match remotes {
            Granted::Route(route) | Granted::Matching { route, .. } => Some(route),
            Granted::One(remote) => Some(&remote.route),
            Granted::Set(_) => None,
        });
        let lists = on.is_some_and(|on| {
            reference
                .routes
                .iter()
                .any(|route| route.id == *on && route.discovery() == Discovery::Lists)
        });
        if lists {
            vec![
                Activation::OnRequest,
                Activation::WhileRunning,
                Activation::Continuous,
            ]
        } else {
            vec![Activation::OnRequest, Activation::Continuous]
        }
    }

    /// The change this draft asks for.
    ///
    /// # Errors
    ///
    /// The first thing the draft still owes.
    pub fn change(&self, reference: &Reference, document: &Document) -> Result<Change, Owed> {
        let capability = self.capability.clone().ok_or(Owed::Capability)?;
        if let Some(chosen) = self::capability(reference, document, &capability) {
            chosen
                .complete()
                .map_err(|_| Owed::Incomplete(capability.clone()))?;
        }
        let remotes = self.remotes.clone().ok_or(Owed::Remotes)?;
        let activation = self.activation.ok_or(Owed::Activation)?;
        let owed = self.exposes(reference, document).without(self.acknowledged);
        if !owed.is_empty() {
            return Err(Owed::Acknowledgement(owed));
        }
        let lends = self.lent()?;
        Ok(Change::Grant {
            grant: Grant {
                capability,
                remotes,
            },
            terms: Terms {
                activation,
                setup: self.setup,
                acknowledged: self.acknowledged,
                lends,
            },
        })
    }

    /// What the grant lends, each lent key where the person typed it may be
    /// used.
    fn lent(&self) -> Result<Lends, Owed> {
        let Lends::Named { devices, keys } = &self.lends else {
            return Ok(Lends::Every);
        };
        let keys = keys
            .iter()
            .map(|(key, lent)| {
                let typed = self.hosts.get(key).map_or("", String::as_str);
                let toward = toward(typed).map_err(|why| Owed::Hosts {
                    key: key.clone(),
                    why,
                })?;
                Ok((
                    key.clone(),
                    LentKey {
                        toward,
                        comment: lent.comment.clone(),
                    },
                ))
            })
            .collect::<Result<_, _>>()?;
        Ok(Lends::Named {
            devices: devices.clone(),
            keys,
        })
    }
}

/// The field a refusal of a grant concerns, so it is shown there.
pub fn blames(refusal: &Refusal) -> Field {
    match refusal {
        Refusal::ExposureNotAcknowledged { .. } => Field::Acknowledged,
        Refusal::ActivationNeedsDiscovery { .. } => Field::Activation,
        Refusal::UnknownRoute(_) => Field::Remotes,
        Refusal::NeedsRemoteSetup { .. } => Field::Setup,
        Refusal::Unlendable { .. } => Field::Lends,
        _ => Field::Capability,
    }
}

/// One choice the form offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice<T> {
    pub label: String,
    pub value: T,
    pub chosen: bool,
}

/// The devices a grant lends, where its capability's source holds them.
#[derive(Debug, PartialEq, Eq)]
pub struct Lending {
    /// What the grant lends, said.
    pub lends: String,
    /// Each device the source holds, and each lent that it does not hold
    /// now, with whether it is lent. One the server lists with no serial
    /// cannot be named: lending every device lends it.
    pub devices: Vec<Choice<Option<DeviceSerial>>>,
    /// Whether every device is lent, now and later.
    pub every: bool,
    /// While the source is read, or why it could not be: its devices are
    /// then those already lent.
    pub listing: Option<String>,
}

/// The devices a capability's source holds, as last read: `None` while it
/// is asked, the refusal where it could not be.
pub type Listed<'a> = Option<&'a Option<Result<Vec<Lendable>, Refusal>>>;

impl Lending {
    /// What lends `lends` of the devices `listed` names.
    pub fn of(lends: &Lends, listed: Listed<'_>) -> Lending {
        let (devices, listing): (&[Lendable], Option<String>) = match listed {
            Some(Some(Ok(devices))) => (devices, None),
            Some(Some(Err(refusal))) => (
                &[],
                Some(format!("The devices could not be read: {refusal}.")),
            ),
            Some(None) | None => (
                &[],
                Some("Reading which devices the workstation's ADB server holds.".to_owned()),
            ),
        };
        let mut choices: Vec<Choice<Option<DeviceSerial>>> = devices
            .iter()
            .map(|device| Choice {
                label: crate::words::device(device),
                chosen: device
                    .serial
                    .as_ref()
                    .map_or(*lends == Lends::Every, |serial| lends.lends(serial)),
                value: device.serial.clone(),
            })
            .collect();
        // A device lent and not held now stays a choice, so lending it can be
        // taken back.
        if let Lends::Named { .. } = lends {
            choices.extend(
                crate::words::devices(lends)
                    .filter(|serial| {
                        !devices
                            .iter()
                            .any(|device| device.serial.as_ref() == Some(*serial))
                    })
                    .map(|serial| Choice {
                        label: format!(
                            "{serial}, which the workstation's ADB server does not hold now"
                        ),
                        value: Some(serial.clone()),
                        chosen: true,
                    }),
            );
        }
        Lending {
            lends: crate::words::lends(lends, devices),
            devices: choices,
            every: *lends == Lends::Every,
            listing,
        }
    }
}

/// The keys an agent's source holds, as last read: `None` where nobody has
/// asked, `Some(None)` while it is asked, the refusal where it could not be.
pub type KeysListed<'a> = Option<&'a Option<Result<Vec<AgentKey>, Refusal>>>;

/// One key the grant can lend: what the person reads, whether it is lent,
/// and, lent, where it may be used as typed.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyChoice {
    pub key: SshKey,
    /// The comment the key is lent with: the one its agent listed it with,
    /// or, lent and not listed now, the one the grant keeps.
    pub comment: Option<Words>,
    pub label: String,
    pub chosen: bool,
    /// The hosts it may log in to, as typed; `None` where it is not lent.
    pub hosts: Option<String>,
    /// Why what is typed there names no host, beneath it.
    pub invalid: Option<String>,
}

/// The keys a grant of an SSH agent lends.
#[derive(Debug, PartialEq, Eq)]
pub struct Keying {
    /// What the grant lends, said.
    pub lends: String,
    /// Each key the agent holds, and each lent that it did not list.
    pub keys: Vec<KeyChoice>,
    /// Whether every key is lent, now and later.
    pub every: bool,
    /// That the agent has not been asked, is being asked, or why it could
    /// not be.
    pub listing: Option<String>,
    /// Whether asking the agent which keys it holds is offered: nothing asks
    /// an agent what the person did not.
    pub ask: bool,
    /// What answers for the agent on this workstation, where the core has
    /// read it.
    pub answering: Option<String>,
    /// What the agent's own prompts cannot say, which Hedwig's decision per
    /// remote stands in for.
    pub asks: &'static str,
}

impl Keying {
    /// What `draft` lends of the keys `listed` names, `capability` being
    /// the agent's.
    pub fn of(
        draft: &Draft,
        capability: &Capability,
        listed: KeysListed<'_>,
        found: Option<&Workstation>,
    ) -> Keying {
        let (held, listing, ask): (&[AgentKey], Option<String>, bool) = match listed {
            Some(Some(Ok(keys))) => (keys, None, true),
            Some(Some(Err(refusal))) => (
                &[],
                Some(format!("Your agent's keys could not be read: {refusal}.")),
                true,
            ),
            Some(None) => (
                &[],
                Some("Asking your agent which keys it holds.".to_owned()),
                false,
            ),
            None => (
                &[],
                Some(
                    "Hedwig has not asked your agent which keys it holds: it asks only when you \
                     do, since a password manager can ask you to approve the list."
                        .to_owned(),
                ),
                true,
            ),
        };
        let agents = listed.map(|listed| {
            let mut one = BTreeMap::new();
            one.insert(capability.id.clone(), listed.clone());
            one
        });
        let keyrings = match &agents {
            Some(agents) => crate::words::Keyrings::default().listing(agents),
            None => crate::words::Keyrings::default(),
        };
        let lends = &draft.lends;
        let choice = |key: &SshKey, comment: Option<&Words>| {
            let chosen = lends.key(key).is_some();
            let typed = draft.hosts.get(key).cloned().unwrap_or_default();
            KeyChoice {
                key: key.clone(),
                comment: comment.cloned(),
                label: crate::words::ssh_key_named(key, comment, keyrings),
                chosen,
                invalid: (chosen && *lends != Lends::Every)
                    .then(|| toward(&typed).err())
                    .flatten(),
                hosts: (chosen && *lends != Lends::Every).then_some(typed),
            }
        };
        let mut keys: Vec<KeyChoice> = held
            .iter()
            .map(|listed| choice(&listed.key, listed.comment.as_ref()))
            .collect();
        // A key lent that the agent did not list stays a choice, so lending
        // it can be taken back.
        keys.extend(
            lends
                .keys()
                .filter(|(key, _)| !held.iter().any(|listed| listed.key == **key))
                .map(|(key, lent)| {
                    let mut shown = choice(key, lent.comment.as_ref());
                    if listed.is_some_and(Option::is_some) {
                        shown.label.push_str(", which your agent did not list");
                    }
                    shown
                }),
        );
        Keying {
            lends: crate::words::lends_keys(lends, keyrings),
            keys,
            every: *lends == Lends::Every,
            listing,
            ask,
            answering: answering(capability, found),
            asks: crate::words::AGENT_ASKS,
        }
    }
}

/// What answers for `capability`'s agent on this workstation, as the core
/// last read it.
pub fn answering(capability: &Capability, found: Option<&Workstation>) -> Option<String> {
    let holder = crate::words::found(found, &capability.id)?
        .holder
        .as_ref()?;
    Some(crate::words::answered(&capability.id, holder))
}

/// `listing`, the words for a list of `capability`'s that could not be read,
/// with what the person can do where the refusal is the source failing for a
/// program that may be theirs: the form has no line beside it that says so.
fn mended<T>(
    listing: Option<String>,
    listed: Option<&Option<Result<T, Refusal>>>,
    capability: &Capability,
    found: Option<&Workstation>,
) -> Option<String> {
    let Some(Some(Err(refusal))) = listed else {
        return listing;
    };
    let mended = crate::words::mended(refusal, &capability.source, found);
    match (listing, mended) {
        (Some(listing), Some(mended)) => Some(format!("{listing} {mended}.")),
        (listing, _) => listing,
    }
}

/// The grant form as the window shows it.
#[derive(Debug, PartialEq, Eq)]
pub struct Form {
    pub capabilities: Vec<Choice<Name>>,
    pub aim: Aim,
    pub routes: Vec<Choice<Name>>,
    pub sets: Vec<Choice<Name>>,
    pub typed: String,
    /// Why what was typed names no remote yet.
    pub unnamed: Option<String>,
    pub activations: Vec<Choice<Activation>>,
    /// Whether Hedwig may write the remote tool's own configuration.
    pub writes: bool,
    /// What that consent lets Hedwig write on each remote, said before it is
    /// given, in the model's words; `None` where the capability needs no
    /// write, and the consent is then not asked.
    pub writable: Option<String>,
    /// Each thing the chosen capability lets a remote do that the person
    /// names, with whether they have.
    pub exposes: Vec<Choice<&'static str>>,
    /// The devices the grant lends, where the chosen capability's source
    /// holds them.
    pub lending: Option<Lending>,
    /// The keys the grant lends, where the chosen capability is an SSH
    /// agent's.
    pub keying: Option<Keying>,
    /// Where the remote's tools open the chosen capability, where that is an
    /// address they are told.
    pub opened_at: Option<String>,
    /// What a remote's tool cannot be given through the chosen capability as
    /// defined, said before the grant is asked.
    pub beyond: Option<String>,
    /// A capability of the person's own to define, of each kind nothing
    /// known yet is: what they would grant is not in the list until then.
    pub defines: Vec<(String, crate::define::Draft)>,
    /// Where the capability chosen leaves its port unstated: the act that
    /// begins the person's own from it, and its definition.
    pub completes: Option<(String, crate::define::Draft)>,
    /// The words of the act that makes the grant, or what is still owed.
    pub ready: Result<String, String>,
    /// The core's refusal of the last grant asked, at the field it concerns.
    pub refused: Option<(Field, String)>,
}

/// What is still owed, as the person reads it.
pub fn owed(owed: &Owed) -> String {
    match owed {
        Owed::Capability => "Choose what to grant.".to_owned(),
        Owed::Remotes => "Choose which remotes it is granted to.".to_owned(),
        Owed::Activation => "Choose when Hedwig connects to them.".to_owned(),
        Owed::Acknowledgement(exposure) => format!(
            "Name what this lets them do: {}.",
            crate::words::exposure(*exposure)
        ),
        Owed::Hosts { key, why } => format!(
            "Say where {} may be used: {why}",
            crate::words::ssh_key(key, crate::words::Keyrings::default())
        ),
        // The model's own words for the refusal the core would give.
        Owed::Incomplete(capability) => format!(
            "{}.",
            Refusal::CapabilityIncomplete {
                capability: capability.clone(),
            }
        ),
    }
}

fn choice<T: PartialEq>(label: String, value: T, now: Option<&T>) -> Choice<T> {
    let chosen = now == Some(&value);
    Choice {
        label,
        value,
        chosen,
    }
}

impl Form {
    /// The form for `draft`; `found` is what the workstation has, whose
    /// keys a consent to write names, `listed` the devices the chosen
    /// capability's source holds and `keys` the keys an agent's holds.
    #[allow(clippy::too_many_lines, reason = "one field for each part of the form")]
    pub fn of(
        draft: &Draft,
        reference: &Reference,
        document: &Document,
        found: Option<&Workstation>,
        (listed, keys): (Listed<'_>, KeysListed<'_>),
        refused: Option<&Refusal>,
    ) -> Form {
        let mut names: Vec<Name> = document
            .capabilities
            .iter()
            .chain(&reference.capabilities)
            .map(|capability| capability.id.clone())
            .collect();
        let mut seen = BTreeSet::new();
        names.retain(|id| seen.insert(id.clone()));
        let mut routes: Vec<Name> = document
            .routes
            .iter()
            .chain(&reference.routes)
            .map(|route| route.id.clone())
            .collect();
        let mut seen = BTreeSet::new();
        routes.retain(|id| seen.insert(id.clone()));
        let set = match &draft.remotes {
            Some(Granted::Set(set)) => Some(set),
            _ => None,
        };
        let exposes = draft.exposes(reference, document);
        let chosen = draft
            .capability
            .as_ref()
            .and_then(|id| capability(reference, document, id));
        Form {
            capabilities: names
                .into_iter()
                .map(|id| choice(id.to_string(), id, draft.capability.as_ref()))
                .collect(),
            aim: draft.aim,
            routes: routes
                .into_iter()
                .map(|id| choice(id.to_string(), id, draft.route.as_ref()))
                .collect(),
            sets: document
                .sets
                .iter()
                .map(|known| choice(known.id.to_string(), known.id.clone(), set))
                .collect(),
            typed: draft.typed.clone(),
            unnamed: match (draft.aim, &draft.route) {
                (Aim::Named, Some(route)) if !draft.typed.trim().is_empty() => {
                    named(route, draft.typed.trim())
                        .err()
                        .map(|error| error.to_string())
                }
                _ => None,
            },
            activations: draft
                .activations(reference)
                .into_iter()
                .map(|activation| {
                    choice(
                        crate::words::activation(activation).to_owned(),
                        activation,
                        draft.activation.as_ref(),
                    )
                })
                .collect(),
            writes: draft.setup == Setup::Write,
            lending: chosen
                .as_ref()
                .filter(|chosen| chosen.holds() == Some(Holds::Devices))
                .map(|chosen| {
                    let mut lending = Lending::of(&draft.lends, listed);
                    lending.listing = mended(lending.listing, listed, chosen, found);
                    lending
                }),
            keying: chosen
                .as_ref()
                .filter(|chosen| chosen.holds() == Some(Holds::Keys))
                .map(|chosen| {
                    let mut keying = Keying::of(draft, chosen, keys, found);
                    keying.listing = mended(keying.listing, keys, chosen, found);
                    keying
                }),
            opened_at: chosen.as_ref().and_then(|chosen| match chosen.source {
                Source::Serial { remote, .. } => Some(crate::words::rfc2217(remote)),
                _ => None,
            }),
            beyond: chosen
                .as_ref()
                .and_then(Beyond::of_capability)
                .map(crate::words::beyond),
            defines: crate::define::undefined(reference, document),
            completes: chosen
                .as_ref()
                .filter(|chosen| chosen.complete().is_err())
                .map(|chosen| {
                    (
                        format!("Define {} with its port...", chosen.id),
                        crate::define::Draft::completing(chosen),
                    )
                }),
            writable: chosen.and_then(|chosen| {
                let consent = chosen.consent(offered(found, &chosen.id));
                (!consent.writes.is_empty() || consent.keys_unread).then(|| {
                    match &consent.reaches {
                        Some(reach) => format!("{consent}. {reach}"),
                        None => consent.to_string(),
                    }
                })
            }),
            exposes: exposes
                .words()
                .map(|word| Choice {
                    label: crate::words::exposes(word).to_owned(),
                    value: word,
                    chosen: Exposure::from_word(word)
                        .is_some_and(|member| draft.acknowledged.common(member) == member),
                })
                .collect(),
            ready: match draft.change(reference, document) {
                Ok(Change::Grant { grant, .. }) => Ok(format!(
                    "Grant {} to {}",
                    grant.capability,
                    crate::words::granted(&grant.remotes)
                )),
                Ok(_) => Err(String::new()),
                Err(still) => Err(owed(&still)),
            },
            refused: refused.map(|refusal| (blames(refusal), refusal.to_string())),
        }
    }
}

impl Draft {
    /// The remotes the choices name, kept in step with every edit.
    fn settle(&mut self, reference: &Reference) {
        self.remotes = match (self.aim, &self.route) {
            (Aim::Route, Some(route)) => Some(Granted::Route(route.clone())),
            (Aim::Named, Some(route)) => named(route, self.typed.trim()).ok(),
            (Aim::Set, _) => match self.remotes.take() {
                Some(Granted::Set(set)) => Some(Granted::Set(set)),
                _ => None,
            },
            (_, None) => None,
        };
        // A way of connecting the remotes can no longer have is unchosen.
        if self
            .activation
            .is_some_and(|activation| !self.activations(reference).contains(&activation))
        {
            self.activation = None;
        }
    }

    /// Chooses what to grant. Exposure named for another capability is
    /// unnamed: the person names what this one lets a remote do. Consent to
    /// write is to what this capability writes, so it is asked again for
    /// another.
    pub fn choose_capability(&mut self, id: Name, reference: &Reference, document: &Document) {
        // Devices are another source's under another capability, so none is
        // lent of the one chosen until the person names it.
        if self.capability.as_ref() != Some(&id) {
            self.setup = Setup::Inspect;
            self.lends = Lends::none();
            self.hosts.clear();
        }
        self.capability = Some(id);
        self.acknowledged = self.acknowledged.common(self.exposes(reference, document));
    }

    pub fn aim_at(&mut self, aim: Aim, reference: &Reference) {
        self.aim = aim;
        self.settle(reference);
    }

    pub fn choose_route(&mut self, route: Name, reference: &Reference) {
        self.route = Some(route);
        self.settle(reference);
    }

    pub fn choose_set(&mut self, set: Name, reference: &Reference) {
        self.aim = Aim::Set;
        self.remotes = Some(Granted::Set(set));
        self.settle(reference);
    }

    pub fn type_name(&mut self, text: &str, reference: &Reference) {
        text.clone_into(&mut self.typed);
        self.settle(reference);
    }

    pub fn choose_activation(&mut self, activation: Activation) {
        self.activation = Some(activation);
    }

    /// Whether Hedwig may write the remote tool's own configuration.
    pub fn let_write(&mut self, writes: bool) {
        self.setup = if writes { Setup::Write } else { Setup::Inspect };
    }

    /// Lends `serial`, or stops lending it. Under every device, each is lent
    /// and none is named: the person turns every device off to name them.
    pub fn lend(&mut self, serial: DeviceSerial, lent: bool) {
        if let Lends::Named { devices, .. } = &mut self.lends {
            if lent {
                devices.insert(serial);
            } else {
                devices.remove(&serial);
            }
        }
    }

    /// Lends the key `chosen` names for anything, with the comment its agent
    /// gave it, or stops lending it; what was typed for it goes with it.
    /// Under every key, each is lent and none is named.
    pub fn lend_key(&mut self, chosen: &KeyChoice, lent: bool) {
        if let Lends::Named { keys, .. } = &mut self.lends {
            if lent {
                keys.entry(chosen.key.clone()).or_insert_with(|| LentKey {
                    toward: Toward::Anywhere,
                    comment: chosen.comment.clone(),
                });
            } else {
                keys.remove(&chosen.key);
                self.hosts.remove(&chosen.key);
            }
        }
    }

    /// What the person typed for the hosts a lent key may log in to.
    pub fn type_hosts(&mut self, key: SshKey, text: &str) {
        if self.lends.key(&key).is_some() && self.lends != Lends::Every {
            self.hosts.insert(key, text.to_owned());
        }
    }

    /// Lends everything the source holds, now and later, or nothing.
    pub fn lend_every(&mut self, every: bool) {
        self.lends = if every { Lends::Every } else { Lends::none() };
        self.hosts.clear();
    }

    /// Names, or unnames, one thing the capability lets a remote do.
    pub fn acknowledge(&mut self, word: &str, named: bool) {
        if let Some(member) = Exposure::from_word(word) {
            self.acknowledged = if named {
                self.acknowledged.with(member)
            } else {
                self.acknowledged.without(member)
            };
        }
    }
}
