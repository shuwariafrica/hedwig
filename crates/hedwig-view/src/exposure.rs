//! The window: what of the person's is reachable from where, and the first
//! grant when nothing is.
//!
//! The person is setting up or reviewing. The window is organised around
//! grants - a capability on a remote - and each line carries its own state,
//! its own diagnosis and its own acts, so nothing about a line is somewhere
//! else. With nothing granted the same window shows what this workstation
//! already has and a first grant made ready: first run is this window's
//! empty state, not a place of its own, and nothing records that it was seen.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use hedwig_model::capability::{
    Capability, Exposure as Exposes, Holds, Lends, LentKey, Operation, Setup, Source, Toward,
};
use hedwig_model::config::{
    Accepted, Activation, Change, Denial, Document, Grant, Reference, Terms,
};
use hedwig_model::organisation::{Part, Place as Where};
use hedwig_model::policy::{Basis, ConnectionScope, KeyName, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{
    Act as RowAct, Attention, Contact, Decides, Lendable, Offered, Request, Row, Through,
    Workstation, Written,
};
use hedwig_model::refusal::{Refusal, Withheld};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::scope::Holder;
use hedwig_model::site::Site;
use hedwig_model::text::{DeviceSerial, KeyId, Name, PortName, SshKey, Words};
use hedwig_model::trail::{
    ConnectionId, Entry, Event, Finding, Given, Health, Icon, Opener, Outcome, Payload, Prepared,
    Readiness, RequestId, Seq, Store, Timestamp,
};

use crate::act::Act;
use crate::define;
use crate::glance;
use crate::grant::{self, Draft};
use crate::link::{Attached, Core, Place, Seen};
use crate::setting::{Answer, Judge};
use crate::words::{self, Keyrings};

/// An act as a surface renders it. One the person cannot take now is never a
/// dead control: it is a line that says the act exists and why not now.
#[derive(Debug, PartialEq, Eq)]
pub enum Shown {
    Offered { label: String, act: Act },
    Withheld { label: String, why: String },
}

/// How one operation on a line is decided, and what the person can make of
/// it.
#[derive(Debug, PartialEq, Eq)]
pub struct Policy {
    /// When the remote asks to do this.
    pub when: String,
    pub now: &'static str,
    pub because: String,
    pub changes: Vec<Shown>,
    /// Each key a statement can name here whose requests are decided as
    /// every key's are, with the rule that would decide it otherwise: a key
    /// is given a rule before it is first used.
    pub keys: Vec<KeyRule>,
}

/// A rule for one key that no statement names yet.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyRule {
    /// The key, as the person knows it.
    pub key: String,
    pub changes: Vec<Shown>,
}

/// One capability on one remote, or a grant no remote has yet met.
#[derive(Debug, PartialEq, Eq)]
pub struct Line {
    pub remote: Option<RemoteId>,
    pub capability: Name,
    pub state: String,
    /// What answers for the capability on this workstation, as the core last
    /// read it: its source's health, what held it, and what the person can
    /// do about a program of theirs Hedwig will not carry the remote to.
    pub answers: Vec<String>,
    pub exposes: String,
    /// What it is granted through, in the person's own terms.
    pub through: String,
    /// Where the remote's tools open it, where that is an address they are
    /// told: a serial port's `rfc2217://` URL.
    pub opened_at: Option<String>,
    /// The serial port a connection from the remote holds now, since when.
    pub hold: Option<String>,
    /// What the remote's tool cannot be given through it, each with why and
    /// what would change it.
    pub beyond: Vec<String>,
    /// The last request the remote made of it, when that is known.
    pub last: Option<String>,
    /// Each limit that holds what it serves on, with whose it is and whom to
    /// ask.
    pub holds: Vec<String>,
    /// What readiness found on the remote that does not keep the capability
    /// off the channel: carried, and named beside it.
    pub cautions: Vec<String>,
    /// What Hedwig has written on the remote for this capability, with the
    /// grant's consent, and where.
    pub written: Vec<String>,
    /// Each reverse, forward and console it carries on to the remote in this
    /// run: where each lands there.
    pub carried: Vec<String>,
    /// The devices its grant lends, where its source holds devices.
    pub lending: Option<Lending>,
    /// The keys its grant lends, where its source is an SSH agent.
    pub keys: Option<Keying>,
    /// What a test asked here found, or that one is running.
    pub proof: Option<String>,
    /// The core's refusal of the last act made on this line.
    pub refused: Option<String>,
    /// What the remote was refused of this capability, with how often, for
    /// as long as it needs the person.
    pub turned: Vec<String>,
    /// Each limit that holds what the last change made on this line states.
    pub held: Vec<String>,
    pub acts: Vec<Shown>,
    pub policy: Vec<Policy>,
}

/// What a grant lends of a source's devices, on the grant's line.
#[derive(Debug, PartialEq, Eq)]
pub struct Lending {
    /// What it lends, said.
    pub lends: String,
    /// Each device the source holds, and each lent that it does not hold
    /// now.
    pub devices: Vec<Device>,
    /// While the source is read, or why it could not be.
    pub listing: Option<String>,
    /// Lending every device, or no longer; a device a remote reached for
    /// that is not in the list; reading the list again.
    pub acts: Vec<Shown>,
}

/// One device on a grant's line.
#[derive(Debug, PartialEq, Eq)]
pub struct Device {
    pub label: String,
    pub lent: bool,
    /// Lending it, or no longer; `None` where every device is lent, or where
    /// what is lent is not the person's to change here.
    pub act: Option<Shown>,
}

/// What a grant lends of an SSH agent's keys, on the grant's line.
#[derive(Debug, PartialEq, Eq)]
pub struct Keying {
    /// What it lends, said.
    pub lends: String,
    /// Each key lent, then each the agent listed that is not.
    pub keys: Vec<KeyLine>,
    /// While the agent is asked, or why it could not be.
    pub listing: Option<String>,
    /// What the agent's own prompts cannot say, which Hedwig's decision per
    /// remote stands in for.
    pub asks: &'static str,
    /// Lending every key, or no longer; a key a remote reached for that is
    /// not lent; asking the agent which keys it holds.
    pub acts: Vec<Shown>,
}

/// One key on a grant's line.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyLine {
    pub key: SshKey,
    pub label: String,
    pub lent: bool,
    /// Lending it, or no longer; `None` where every key is lent, or where
    /// what is lent is not the person's to change here.
    pub act: Option<Shown>,
    /// Where it may be used, where it is lent.
    pub toward: Option<String>,
    /// The hosts it may log in to, each host's key as OpenSSH writes it, one
    /// to a line: what the person edits to narrow where it is used. `None`
    /// where that is not theirs to change here.
    pub hosts: Option<String>,
    /// Lending it for anything again, where it is lent toward hosts.
    pub anywhere: Option<Shown>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Group {
    pub heading: String,
    pub lines: Vec<Line>,
}

/// Something that needs the person, with what they can do about it there.
#[derive(Debug, PartialEq, Eq)]
pub struct Need {
    pub sentence: String,
    pub acts: Vec<Shown>,
}

/// The window with nothing granted: what this workstation has, and a first
/// grant made ready in those terms.
#[derive(Debug, PartialEq, Eq)]
pub struct First {
    /// `None` while the core has not yet said.
    pub has: Option<Vec<String>>,
    /// Every card Hedwig has read, each with what it asks before each key on
    /// it is used: apart from what the workstation has, since no read Hedwig
    /// may make says which card is in.
    pub cards: Vec<String>,
    pub draft: Draft,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Board {
    /// No core answers. The sentence says what is true and the act what the
    /// person can do.
    Off {
        sentence: String,
        act: Option<Act>,
    },
    /// Attached, and the core has not yet said what is exposed.
    Asking,
    First(First),
    Exposure {
        needs: Vec<Need>,
        groups: Vec<Group>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Window {
    /// What stands above everything on the page for as long as it is so:
    /// Hedwig being removed, and an icon of Hedwig's the taskbar does not
    /// show. Whatever the board, the first run's included.
    pub heads: Vec<Need>,
    pub board: Board,
    /// The core's refusal of the last thing asked from this window.
    pub refused: Option<String>,
    /// How long until something shown changes by the clock alone: a
    /// channel's countdown. `None` where nothing shown counts down.
    pub changes: Option<Duration>,
}

const UNGRANTED: &str = "Granted, and no remote has been seen yet";

/// The request a row's offer stands for: what the core was asked about when
/// it said whether the act would be carried out.
pub fn request_for(row: &Row, act: RowAct) -> Option<Request> {
    let remote = row.remote.clone();
    match act {
        RowAct::Connect => Some(Request::Connect {
            remote: remote?,
            with: Vec::new(),
            acknowledged: Exposes::NONE,
            lends: Lends::none(),
        }),
        RowAct::Disconnect => Some(Request::Disconnect { remote: remote? }),
        RowAct::Pause => Some(Request::Pause(Remotes::One(remote?))),
        RowAct::Resume => Some(Request::Resume(Remotes::One(remote?))),
        RowAct::Check => Some(Request::Check {
            remote: remote?,
            capability: row.capability.clone(),
        }),
        RowAct::Exercise => Some(Request::Exercise {
            remote: remote?,
            capability: row.capability.clone(),
        }),
        RowAct::Revoke => match &row.through {
            Through::Grant(grant) => Some(Request::Change(Change::Revoke(grant.clone()))),
            Through::Start { .. } | Through::Connection(_) => None,
        },
        RowAct::Deny => match &row.through {
            Through::Start { grant, .. } => Some(Request::Change(Change::Deny(Denial {
                capability: Selector::Only(grant.capability.clone()),
                remotes: grant.remotes.clone().into(),
            }))),
            Through::Grant(_) | Through::Connection(_) => None,
        },
        // What only the person can give a starting grant: the exposure its
        // capability names. Consent to write is never given for them, and no
        // device is lent until they name one.
        RowAct::Accept => match &row.through {
            Through::Start { grant, .. } => Some(Request::Change(Change::Accept {
                grant: grant.clone(),
                accepted: Accepted {
                    setup: Setup::Inspect,
                    acknowledged: row.exposure.common(Exposes::ACKNOWLEDGED),
                    lends: Lends::none(),
                },
            })),
            Through::Grant(_) | Through::Connection(_) => None,
        },
    }
}

fn offered(label: &str, act: Act) -> Shown {
    Shown::Offered {
        label: label.to_owned(),
        act,
    }
}

fn confirm(label: &str, answer: &str, request: Request, consequence: String) -> Shown {
    offered(
        label,
        Act::Confirm {
            request,
            consequence,
            answer: answer.to_owned(),
        },
    )
}

fn place(row: &Row) -> String {
    row.remote
        .as_ref()
        .map_or_else(|| "its remotes".to_owned(), ToString::to_string)
}

fn row_act(row: &Row, offer: &Offered) -> Option<Shown> {
    let (label, consequence) = match offer.act {
        RowAct::Connect => ("Connect", None),
        RowAct::Disconnect => ("Disconnect", None),
        RowAct::Pause => ("Pause this remote", None),
        RowAct::Check => ("Check again", None),
        RowAct::Resume => (
            "Resume this remote...",
            Some(format!(
                "What is granted to {} becomes reachable from it again.",
                place(row)
            )),
        ),
        RowAct::Revoke => (
            "Withdraw this grant...",
            Some(format!(
                "{} is no longer granted to {}, and a connection that carries it stops \
                 carrying it.",
                row.capability,
                match &row.through {
                    Through::Grant(grant) | Through::Start { grant, .. } => {
                        words::granted(&grant.remotes)
                    }
                    Through::Connection(_) => place(row),
                }
            )),
        ),
        RowAct::Deny => (
            "Deny this grant...",
            Some(format!(
                "{} is denied to {}, and your organisation's starting point cannot grant it \
                 there again until you remove the denial.",
                row.capability,
                row.through
                    .grant()
                    .map_or_else(|| place(row), |grant| words::granted(&grant.remotes))
            )),
        ),
        RowAct::Accept => (
            "Accept this grant...",
            Some(format!(
                "{} becomes reachable from {}, which lets it {}.",
                row.capability,
                row.through
                    .grant()
                    .map_or_else(|| place(row), |grant| words::granted(&grant.remotes)),
                words::exposure(row.exposure.common(Exposes::ACKNOWLEDGED))
            )),
        ),
        RowAct::Exercise => (
            "Test with a real request...",
            Some(format!(
                "The remote's own tool uses {} once, for real. With a signing key that makes \
                 a signature, and asks for your touch or PIN as any signature does.",
                row.capability
            )),
        ),
    };
    if let Some(refusal) = &offer.withheld {
        return Some(Shown::Withheld {
            label: label.trim_end_matches("...").to_owned(),
            why: refusal.to_string(),
        });
    }
    let request = request_for(row, offer.act)?;
    Some(match consequence {
        Some(consequence) => confirm(label, label.trim_end_matches("..."), request, consequence),
        None => offered(label, Act::Send(request)),
    })
}

fn loosens(remote: &RemoteId, capability: &Name, asked: Operation, to: Mode) -> String {
    let what = format!("{capability} when it asks to {}", words::verb(asked));
    match to {
        Mode::Unattended => format!(
            "{remote} is served {what}, even while nothing can reach you. With a key that \
             needs no touch, it can then be used with nobody watching."
        ),
        _ => format!(
            "{remote} is served {what}, without asking you first. You are shown each use \
             while something can reach you, and it is refused when nothing can."
        ),
    }
}

/// The rules that would decide requests with `key` otherwise than `decides`
/// decides every key's: each other mode, stricter at once and looser asked
/// first, and asking first until the connection ends.
fn key_rule(
    remote: &RemoteId,
    capability: &Name,
    connection: Option<ConnectionId>,
    decides: &Decides,
    key: &KeyName,
) -> Vec<Shown> {
    let mut changes = Vec::new();
    if let Some(connection) = connection
        && decides.mode != Mode::Confirm
    {
        changes.push(offered(
            "Ask me first for this key, until this connection ends",
            Act::Send(Request::Rule {
                connection,
                scope: ConnectionScope {
                    capability: Selector::Only(capability.clone()),
                    operation: Selector::Only(decides.operation),
                    key: Keys::Only(key.clone()),
                },
                mode: Some(Mode::Confirm),
            }),
        ));
    }
    let scope = RuleScope {
        remotes: Remotes::One(remote.clone()),
        capability: Selector::Only(capability.clone()),
        operation: Selector::Only(decides.operation),
        key: Keys::Only(key.clone()),
    };
    for mode in [Mode::Confirm, Mode::Notify, Mode::Unattended] {
        if mode == decides.mode {
            continue;
        }
        let label = format!("{}, always for this key here", words::choose(mode));
        let request = Request::Change(Change::Rule {
            scope: scope.clone(),
            mode,
        });
        changes.push(if mode > decides.mode {
            offered(&label, Act::Send(request))
        } else {
            confirm(
                &format!("{label}..."),
                words::choose(mode),
                request,
                loosens(remote, capability, decides.operation, mode),
            )
        });
    }
    changes
}

/// Every key a statement can name for `row`'s capability: a `GnuPG`
/// source's, each key the workstation's keyrings offer and each a card
/// holds; an SSH agent's, each key its grant lends and, lending every key,
/// each the agent listed where the person asked. Each with how the person
/// knows it.
fn nameable(row: &Row, attached: &Attached) -> Vec<(String, KeyName)> {
    let (Some(vocabulary), Some(document)) = (&attached.catalogue, &attached.document) else {
        return Vec::new();
    };
    let Some(capability) = grant::capability(vocabulary.reference(), document, &row.capability)
    else {
        return Vec::new();
    };
    let keyrings = attached.keyrings();
    match &capability.source {
        Source::Gnupg { .. } => keyrings.named(),
        Source::Agent { .. } => {
            let lends = row
                .terms
                .as_ref()
                .map(|terms| terms.lends.clone())
                .or_else(|| lent_by(row, document).map(|(lends, _)| lends))
                .unwrap_or_else(Lends::none);
            let mut keys: Vec<&SshKey> = lends.keys().map(|(key, _)| key).collect();
            if lends == Lends::Every
                && let Some(Some(Ok(listed))) = attached.agent_keys.get(&row.capability)
            {
                keys.extend(listed.iter().map(|listed| &listed.key));
            }
            keys.into_iter()
                .map(|key| (words::ssh_key(key, keyrings), KeyName::Ssh(key.clone())))
                .collect()
        }
        Source::Service { .. }
        | Source::Browser { .. }
        | Source::Serial { .. }
        | Source::Credentials { .. }
        | Source::Notices => Vec::new(),
    }
}

/// A rule for each key a statement can name that no entry of `every`
/// decides apart from `decides`, where `decides` is how every key is
/// decided for an operation that names a key; a key with an entry of its own
/// already has its rules there.
fn key_rules(
    remote: &RemoteId,
    capability: &Name,
    connection: Option<ConnectionId>,
    (decides, every): (&Decides, &[Decides]),
    keyrings: Keyrings<'_>,
    nameable: &[(String, KeyName)],
) -> Vec<KeyRule> {
    if decides.key.is_some() || decides.operation == Operation::Connect {
        return Vec::new();
    }
    nameable
        .iter()
        .filter(|(_, name)| {
            !every.iter().any(|other| {
                other.operation == decides.operation
                    && other
                        .key
                        .as_ref()
                        .is_some_and(|key| keyrings.name(key) == *name)
            })
        })
        .map(|(said, name)| KeyRule {
            key: said.clone(),
            changes: key_rule(remote, capability, connection, decides, name),
        })
        .collect()
}

fn policy(
    remote: &RemoteId,
    capability: &Name,
    connection: Option<ConnectionId>,
    (decides, every): (&Decides, &[Decides]),
    keyrings: Keyrings<'_>,
    nameable: &[(String, KeyName)],
) -> Policy {
    // Where the core says how a request with one key is decided, a rule is
    // made for that key: a release key confirmed, an everyday one not.
    let key = decides
        .key
        .as_ref()
        .map_or(Keys::Every, |grip| Keys::Only(keyrings.name(grip)));
    let only = RuleScope {
        remotes: Remotes::One(remote.clone()),
        capability: Selector::Only(capability.clone()),
        operation: Selector::Only(decides.operation),
        key: key.clone(),
    };
    let mut changes = Vec::new();
    if let Some(connection) = connection
        && decides.mode != Mode::Confirm
    {
        changes.push(offered(
            "Ask me first, until this connection ends",
            Act::Send(Request::Rule {
                connection,
                scope: ConnectionScope {
                    capability: Selector::Only(capability.clone()),
                    operation: Selector::Only(decides.operation),
                    key: key.clone(),
                },
                mode: Some(Mode::Confirm),
            }),
        ));
    }
    for mode in [Mode::Confirm, Mode::Notify, Mode::Unattended] {
        if mode == decides.mode {
            continue;
        }
        let label = match &decides.key {
            Some(_) => format!("{}, always for this key here", words::choose(mode)),
            None => format!("{}, always for this remote", words::choose(mode)),
        };
        let request = Request::Change(Change::Rule {
            scope: only.clone(),
            mode,
        });
        // Stricter is carried out at once; anything that lets more through
        // is put to the person with what it lets through.
        changes.push(if mode > decides.mode {
            offered(&label, Act::Send(request))
        } else {
            confirm(
                &format!("{label}..."),
                words::choose(mode),
                request,
                loosens(remote, capability, decides.operation, mode),
            )
        });
    }
    match &decides.basis {
        Basis::Rule(scope) if scope.remotes == only.remotes => changes.push(confirm(
            "Remove your rule for this remote...",
            "Remove your rule",
            Request::Change(Change::Unrule(scope.clone())),
            "What you set more widely, or Hedwig's default, decides again.".to_owned(),
        )),
        Basis::Connection(scope) => {
            if let Some(connection) = connection {
                changes.push(confirm(
                    "Clear what you set for this connection...",
                    "Clear what you set",
                    Request::Rule {
                        connection,
                        scope: scope.clone(),
                        mode: None,
                    },
                    "Your standing rules, or Hedwig's default, decide again.".to_owned(),
                ));
            }
        }
        _ => {}
    }
    let keys = key_rules(
        remote,
        capability,
        connection,
        (decides, every),
        keyrings,
        nameable,
    );
    Policy {
        keys,
        when: match &decides.key {
            Some(mark) => format!(
                "when it asks to {} with {}",
                words::verb(decides.operation),
                words::key(mark, keyrings)
            ),
            None => format!("when it asks to {}", words::verb(decides.operation)),
        },
        now: words::mode(decides.mode),
        because: words::basis(&decides.basis, keyrings),
        changes,
    }
}

/// Consent to write the remote tool's configuration for what `row` is
/// granted through, given or taken back, where its capability needs a write:
/// what is written is named before the person consents.
fn consent(row: &Row, attached: &Attached, judge: &Judge<'_>) -> Option<Shown> {
    let (Some(vocabulary), Some(document)) = (&attached.catalogue, &attached.document) else {
        return None;
    };
    let capability = grant::capability(vocabulary.reference(), document, &row.capability)?;
    let consent = capability.consent(grant::offered(
        attached.workstation.as_ref(),
        &row.capability,
    ));
    let reach = consent.reaches.as_ref();
    if consent.writes.is_empty() && !consent.keys_unread {
        return None;
    }
    let (setup, change): (Setup, Box<dyn Fn(Setup) -> Change>) = match &row.through {
        Through::Grant(grant) => {
            let terms = document
                .grants
                .iter()
                .find(|entry| entry.grant == *grant)?
                .terms
                .clone();
            let grant = grant.clone();
            (
                terms.setup,
                Box::new(move |setup| Change::Grant {
                    grant: grant.clone(),
                    terms: Terms {
                        setup,
                        ..terms.clone()
                    },
                }),
            )
        }
        // The organisation's grant, once accepted: consent is the person's
        // alone to give.
        Through::Start { grant, .. } => {
            let accepted = document
                .accepted
                .iter()
                .find(|entry| entry.grant == *grant)?
                .accepted
                .clone();
            let grant = grant.clone();
            (
                accepted.setup,
                Box::new(move |setup| Change::Accept {
                    grant: grant.clone(),
                    accepted: Accepted {
                        setup,
                        ..accepted.clone()
                    },
                }),
            )
        }
        Through::Connection(_) => return None,
    };
    let remotes = row
        .through
        .grant()
        .map_or_else(|| place(row), |grant| words::granted(&grant.remotes));
    // Whether consenting lets more through is the model's to say.
    Some(match setup {
        Setup::Inspect => judge.act(
            "Let Hedwig write the remote tool's configuration".to_owned(),
            Answer::Words("Let Hedwig write"),
            change(Setup::Write),
            || {
                let mut text = format!(
                    "On {remotes}, where it is missing and never over what you set, {consent}. \
                     Each is marked as Hedwig's where it is, and taken back when you withdraw \
                     this."
                );
                if let Some(reach) = reach {
                    let _ = write!(text, " {reach}");
                }
                text
            },
        ),
        // Taking the consent back moves a private socket's forward to the
        // port, which the reach says where the model counts that as wider.
        Setup::Write => judge.act(
            "Stop Hedwig writing there".to_owned(),
            Answer::Label,
            change(Setup::Inspect),
            || match reach {
                Some(reach) => format!("On {remotes}, Hedwig takes back what it wrote. {reach}"),
                None => format!("On {remotes}, Hedwig takes back what it wrote."),
            },
        ),
    })
}

/// What `row`'s grant lends as the person stated it, and the change that
/// makes it lend otherwise: the grant's own, or for the organisation's, what
/// the person accepted it with. `None` where neither is the person's here.
fn lent_by(row: &Row, document: &Document) -> Option<(Lends, LendChange)> {
    match &row.through {
        Through::Grant(grant) => {
            let terms = document
                .grants
                .iter()
                .find(|entry| entry.grant == *grant)?
                .terms
                .clone();
            Some((
                terms.lends.clone(),
                LendChange::Grant {
                    grant: grant.clone(),
                    terms,
                },
            ))
        }
        Through::Start { grant, .. } => {
            let accepted = document
                .accepted
                .iter()
                .find(|entry| entry.grant == *grant)?
                .accepted
                .clone();
            Some((
                accepted.lends.clone(),
                LendChange::Accept {
                    grant: grant.clone(),
                    accepted,
                },
            ))
        }
        Through::Connection(_) => None,
    }
}

/// The statement a change of what is lent is made to.
enum LendChange {
    Grant { grant: Grant, terms: Terms },
    Accept { grant: Grant, accepted: Accepted },
}

impl LendChange {
    fn to(&self, lends: Lends) -> Change {
        match self {
            LendChange::Grant { grant, terms } => Change::Grant {
                grant: grant.clone(),
                terms: Terms {
                    lends,
                    ..terms.clone()
                },
            },
            LendChange::Accept { grant, accepted } => Change::Accept {
                grant: grant.clone(),
                accepted: Accepted {
                    lends,
                    ..accepted.clone()
                },
            },
        }
    }
}

/// Lending `serial` to what `row` is granted through, or no longer: asked
/// first where the model says it lets more through.
fn lend(
    row: &Row,
    now: &Lends,
    statement: &LendChange,
    serial: &DeviceSerial,
    said: &str,
    judge: &Judge<'_>,
) -> Shown {
    let whom = row
        .through
        .grant()
        .map_or_else(|| place(row), |grant| words::granted(&grant.remotes));
    let mut lends = now.clone();
    if let Lends::Named { devices, .. } = &mut lends {
        if now.lends(serial) {
            devices.remove(serial);
        } else {
            devices.insert(serial.clone());
        }
    }
    if now.lends(serial) {
        judge.act(
            format!("Stop lending {said}"),
            Answer::Label,
            statement.to(lends),
            || format!("{said} is no longer lent to {whom}, and a connection using it ends."),
        )
    } else {
        judge.act(
            format!("Lend {said}"),
            Answer::Words("Lend it"),
            statement.to(lends),
            || words::lending(&whom, said),
        )
    }
}

/// The devices a remote was refused for want of a lending, each that the
/// list on the line does not already offer.
fn reached_for<'a>(
    row: &'a Row,
    attached: &'a Attached,
) -> impl Iterator<Item = &'a DeviceSerial> + 'a {
    attached
        .attention
        .iter()
        .flatten()
        .filter_map(move |needs| match &needs.attention {
            Attention::Refused {
                remote: Some(refused),
                refusal:
                    Refusal::Withheld {
                        capability,
                        request: Withheld::Unlent(Some(serial)),
                    },
                ..
            } if row.remote.as_ref() == Some(refused) && *capability == row.capability => {
                Some(serial)
            }
            _ => None,
        })
}

/// What `row`'s grant lends, where its capability's source holds devices:
/// each device the source holds with lending it or no longer, every device,
/// a device a remote reached for, and reading the list again.
fn lending(row: &Row, attached: &Attached, judge: &Judge<'_>) -> Option<Lending> {
    let (Some(vocabulary), Some(document)) = (&attached.catalogue, &attached.document) else {
        return None;
    };
    let capability = grant::capability(vocabulary.reference(), document, &row.capability)?;
    if capability.holds() != Some(Holds::Devices) {
        return None;
    }
    let stated = lent_by(row, document);
    let lends = row
        .terms
        .as_ref()
        .map(|terms| terms.lends.clone())
        .or_else(|| stated.as_ref().map(|(lends, _)| lends.clone()))
        .unwrap_or_else(Lends::none);
    let listed = attached.devices.get(&row.capability);
    let held: &[Lendable] = match listed {
        Some(Some(Ok(devices))) => devices,
        _ => &[],
    };
    let shown = grant::Lending::of(&lends, listed);
    let devices = shown
        .devices
        .into_iter()
        .map(|choice| {
            let act = match (&choice.value, &stated, &lends) {
                (Some(serial), Some((_, statement)), Lends::Named { .. }) => {
                    let said = words::lent(serial, held);
                    Some(lend(row, &lends, statement, serial, &said, judge))
                }
                _ => None,
            };
            Device {
                label: choice.label,
                lent: choice.chosen,
                act,
            }
        })
        .collect::<Vec<_>>();
    let mut acts = Vec::new();
    if let Some((_, statement)) = &stated {
        let whom = row
            .through
            .grant()
            .map_or_else(|| place(row), |grant| words::granted(&grant.remotes));
        // A device a remote reached for that the list does not offer: the
        // list was read before it came, or could not be.
        let listed_serials: Vec<&DeviceSerial> = held
            .iter()
            .filter_map(|device| device.serial.as_ref())
            .collect();
        let mut offered = BTreeSet::new();
        for serial in reached_for(row, attached) {
            if !lends.lends(serial) && !listed_serials.contains(&serial) && offered.insert(serial) {
                acts.push(lend(
                    row,
                    &lends,
                    statement,
                    serial,
                    &serial.to_string(),
                    judge,
                ));
            }
        }
        acts.push(match lends {
            Lends::Every => judge.act(
                "Stop lending every device".to_owned(),
                Answer::Label,
                statement.to(Lends::none()),
                || {
                    format!(
                        "No device is lent to {whom} until you lend one, and a connection using \
                         one ends."
                    )
                },
            ),
            Lends::Named { .. } => judge.act(
                "Lend every device".to_owned(),
                Answer::Words("Lend every device"),
                statement.to(Lends::Every),
                || {
                    format!(
                        "{whom} can then see and use every device the workstation's ADB server \
                         holds, now and later - your own phone among them whenever it is \
                         attached: install and run apps, open a shell, read and write its files \
                         and its logs."
                    )
                },
            ),
        });
    }
    acts.push(offered(
        "Look again for devices",
        Act::Send(Request::Devices(row.capability.clone())),
    ));
    Some(Lending {
        lends: shown.lends,
        devices,
        listing: shown.listing,
        acts,
    })
}

/// Who a line's grant is to, as the person reads it.
fn whom(row: &Row) -> String {
    row.through
        .grant()
        .map_or_else(|| place(row), |grant| words::granted(&grant.remotes))
}

/// `lends` with `key` lent toward `toward`: with the comment it is lent
/// with, or, lent from now, the one its agent gave it, `listed`.
fn toward_key(lends: &Lends, key: &SshKey, toward: Toward, listed: Option<&Words>) -> Lends {
    let mut lends = lends.clone();
    if let Lends::Named { keys, .. } = &mut lends {
        let comment = keys
            .get(key)
            .map_or_else(|| listed.cloned(), |lent| lent.comment.clone());
        keys.insert(key.clone(), LentKey { toward, comment });
    }
    lends
}

/// `lends` with `key` no longer lent.
fn without_key(lends: &Lends, key: &SshKey) -> Lends {
    let mut lends = lends.clone();
    if let Lends::Named { keys, .. } = &mut lends {
        keys.remove(key);
    }
    lends
}

/// The comment `capability`'s agent gave `key` when the person last had it
/// list its keys.
fn listed<'a>(attached: &'a Attached, capability: &Name, key: &SshKey) -> Option<&'a Words> {
    match attached.agent_keys.get(capability) {
        Some(Some(Ok(listed))) => listed
            .iter()
            .find(|listed| listed.key == *key)
            .and_then(|listed| listed.comment.as_ref()),
        _ => None,
    }
}

/// How a surface names keys for `row`: as its own grant keeps them.
fn keyrings_of<'a>(row: &'a Row, attached: &'a Attached) -> Keyrings<'a> {
    match &row.remote {
        Some(remote) => attached.keyrings().of_capability(remote, &row.capability),
        None => attached.keyrings(),
    }
}

/// Lending `key` for anything, with the comment `listed` its agent gave it,
/// or no longer: asked first where the model says it lets more through.
fn lend_key(
    row: &Row,
    now: &Lends,
    statement: &LendChange,
    (key, listed): (&SshKey, Option<&Words>),
    said: &str,
    judge: &Judge<'_>,
) -> Shown {
    let whom = whom(row);
    if now.key(key).is_some() {
        judge.act(
            format!("Stop lending {said}"),
            Answer::Label,
            statement.to(without_key(now, key)),
            || format!("{said} is no longer lent to {whom}."),
        )
    } else {
        judge.act(
            format!("Lend {said}"),
            Answer::Words("Lend it"),
            statement.to(toward_key(now, key, Toward::Anywhere, listed)),
            || words::lending_key(&whom, said),
        )
    }
}

/// Lending `key`, lent toward named hosts, for anything again: asked first,
/// with what that lets the remote do.
fn anywhere(
    row: &Row,
    now: &Lends,
    statement: &LendChange,
    key: &SshKey,
    said: &str,
    judge: &Judge<'_>,
) -> Shown {
    let whom = whom(row);
    judge.act(
        format!("Lend {said} for anything"),
        Answer::Words("Lend it for anything"),
        statement.to(toward_key(now, key, Toward::Anywhere, None)),
        || words::lending_key(&whom, said),
    )
}

/// What a remote reached for that `row`'s grant does not lend, or lends
/// only toward named hosts, by the refusals that still need the person: each
/// key, and whether it was used beyond those hosts.
fn keys_reached<'a>(
    row: &'a Row,
    attached: &'a Attached,
) -> impl Iterator<Item = (&'a SshKey, bool)> + 'a {
    attached
        .attention
        .iter()
        .flatten()
        .filter_map(move |needs| match &needs.attention {
            Attention::Refused {
                remote: Some(refused),
                refusal:
                    Refusal::Withheld {
                        capability,
                        request,
                    },
                ..
            } if row.remote.as_ref() == Some(refused) && *capability == row.capability => {
                match request {
                    Withheld::KeyUnlent(key) => Some((key, false)),
                    Withheld::Elsewhere(key) => Some((key, true)),
                    _ => None,
                }
            }
            _ => None,
        })
}

/// What `row`'s grant lends, where its capability's source is an SSH agent:
/// each key lent and where it may be used, each the agent listed, a key a
/// remote reached for, every key, and asking the agent which keys it holds,
/// which nothing does unless the person asks.
fn keys(row: &Row, attached: &Attached, judge: &Judge<'_>) -> Option<Keying> {
    let (Some(vocabulary), Some(document)) = (&attached.catalogue, &attached.document) else {
        return None;
    };
    let capability = grant::capability(vocabulary.reference(), document, &row.capability)?;
    if capability.holds() != Some(Holds::Keys) {
        return None;
    }
    let keyrings = keyrings_of(row, attached);
    let stated = lent_by(row, document);
    let lends = row
        .terms
        .as_ref()
        .map(|terms| terms.lends.clone())
        .or_else(|| stated.as_ref().map(|(lends, _)| lends.clone()))
        .unwrap_or_else(Lends::none);
    let comment = |key| listed(attached, &row.capability, key);
    let listed = attached.agent_keys.get(&row.capability);
    let held: Vec<&SshKey> = match listed {
        Some(Some(Ok(keys))) => keys.iter().map(|listed| &listed.key).collect(),
        _ => Vec::new(),
    };
    let named = matches!(lends, Lends::Named { .. });
    let mut shown: Vec<&SshKey> = lends.keys().map(|(key, _)| key).collect();
    shown.extend(held.iter().copied().filter(|key| lends.key(key).is_none()));
    let lines = shown
        .into_iter()
        .map(|key| {
            let said = words::ssh_key(key, keyrings);
            let toward = lends.key(key).map(|lent| &lent.toward);
            let mine = stated.as_ref().filter(|_| named);
            KeyLine {
                key: key.clone(),
                label: said.clone(),
                lent: toward.is_some(),
                act: mine.map(|(_, statement)| {
                    lend_key(row, &lends, statement, (key, comment(key)), &said, judge)
                }),
                toward: toward.map(words::toward),
                hosts: mine.and(toward).map(grant::hosts_written),
                anywhere: mine
                    .zip(toward)
                    .filter(|(_, toward)| **toward != Toward::Anywhere)
                    .map(|((_, statement), _)| anywhere(row, &lends, statement, key, &said, judge)),
            }
        })
        .collect();
    let mut acts = stated
        .as_ref()
        .map(|(_, statement)| lending_keys(row, attached, &lends, statement, &held, judge))
        .unwrap_or_default();
    let (listing, ask) = match listed {
        None => (None, "Show your agent's keys, to lend another"),
        Some(None) => (
            Some("Asking your agent which keys it holds.".to_owned()),
            "",
        ),
        Some(Some(Err(refusal))) => (
            Some(format!("Your agent's keys could not be read: {refusal}.")),
            "Ask your agent again",
        ),
        Some(Some(Ok(_))) => (None, "Ask your agent again"),
    };
    if !ask.is_empty() {
        acts.push(offered(
            ask,
            Act::Send(Request::Keys(row.capability.clone())),
        ));
    }
    Some(Keying {
        lends: words::lends_keys(&lends, keyrings),
        keys: lines,
        listing,
        asks: words::AGENT_ASKS,
        acts,
    })
}

/// What the person can lend from `row`'s line besides each key's own act: a
/// key a remote reached for that the agent did not list, and every key.
fn lending_keys(
    row: &Row,
    attached: &Attached,
    lends: &Lends,
    statement: &LendChange,
    held: &[&SshKey],
    judge: &Judge<'_>,
) -> Vec<Shown> {
    let keyrings = keyrings_of(row, attached);
    let mut acts = Vec::new();
    let mut offered = BTreeSet::new();
    for (key, _) in keys_reached(row, attached) {
        if lends.key(key).is_none() && !held.contains(&key) && offered.insert(key) {
            let said = words::ssh_key(key, keyrings);
            acts.push(lend_key(row, lends, statement, (key, None), &said, judge));
        }
    }
    let whom = whom(row);
    acts.push(match lends {
        Lends::Every => judge.act(
            "Stop lending every key".to_owned(),
            Answer::Label,
            statement.to(Lends::none()),
            || format!("No key is lent to {whom} until you lend one."),
        ),
        Lends::Named { .. } => judge.act(
            "Lend every key".to_owned(),
            Answer::Words("Lend every key"),
            statement.to(Lends::Every),
            || {
                format!(
                    "{whom} can then log in to any host and sign with every key your agent \
                     holds, now and later, each as you set for that remote."
                )
            },
        ),
    });
    acts
}

/// Lending `key` on `capability`'s line for `remote` only for logging in to
/// the hosts `typed` names by their keys, or for anything where it names
/// none: the act, asked first where the model says it lets more through.
///
/// # Errors
///
/// The sentence that says why `typed` names no host, or that the line or
/// its grant is not the person's to change here.
pub fn restrict(
    attached: &Attached,
    remote: Option<&RemoteId>,
    capability: &Name,
    key: &SshKey,
    typed: &str,
) -> Result<Shown, String> {
    let toward = grant::toward(typed)?;
    let unchangeable = || "This grant is not yours to change here.".to_owned();
    let row = attached
        .rows
        .iter()
        .flatten()
        .find(|row| row.remote.as_ref() == remote && row.capability == *capability)
        .ok_or_else(unchangeable)?;
    let (lends, statement) = lent_by(row, attached.document.as_ref().ok_or_else(unchangeable)?)
        .ok_or_else(unchangeable)?;
    let said = words::ssh_key(key, keyrings_of(row, attached));
    let judge = Judge::of(attached.document.as_ref(), attached.catalogue.as_ref());
    let whom = whom(row);
    Ok(match &toward {
        Toward::Anywhere => anywhere(row, &lends, &statement, key, &said, &judge),
        Toward::Hosts(_) => {
            let lets = format!("{said} is then lent to {whom} {}.", words::toward(&toward));
            judge.act(
                "Lend it only for logging in to these hosts".to_owned(),
                Answer::Words("Lend it only there"),
                statement.to(toward_key(&lends, key, toward, None)),
                || lets,
            )
        }
    })
}

/// What a line is read with beside its row: what the core said, when, and
/// the model's judge of what lets more through.
struct Reading<'a> {
    attached: &'a Attached,
    clock: &'a dyn Fn(Timestamp) -> String,
    now: Instant,
    judge: Judge<'a>,
}

/// The last request the remote made of `row`'s capability, and how it ended.
fn last(row: &Row, clock: &dyn Fn(Timestamp) -> String) -> Option<String> {
    row.last.as_ref().map(|last| {
        let mut text = format!(
            "{}: asked to {} {}",
            clock(last.at),
            words::operation(last.operation),
            row.capability
        );
        let _ = write!(
            text,
            " - {}",
            last.outcome
                .as_ref()
                .map_or_else(|| "waiting for your answer".to_owned(), words::outcome)
        );
        text
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one field for each thing a line says"
)]
fn line(row: &Row, connection: Option<ConnectionId>, reading: &Reading<'_>) -> Line {
    let Reading {
        attached,
        clock,
        now,
        judge,
    } = reading;
    let now = *now;
    let keyrings = attached.keyrings();
    let contacts = attached
        .settings
        .as_ref()
        .map_or(&[][..], |settings| &settings.workstation.contacts[..]);
    let here = Place::Line {
        remote: row.remote.clone(),
        capability: row.capability.clone(),
    };
    let proof = if attached.testing.as_ref() == Some(&here) {
        Some("Testing: waiting for the remote's own tool.".to_owned())
    } else {
        attached
            .exercised
            .as_ref()
            .filter(|(place, _)| *place == here)
            .map(|(_, proof)| words::proof(proof, &row.capability))
    };
    let mut acts: Vec<Shown> = row
        .acts
        .iter()
        .filter_map(|offer| row_act(row, offer))
        .collect();
    acts.extend(consent(row, attached, judge));
    acts.extend(define_for(row));
    acts.extend(add_sites(row, attached, judge));
    Line {
        remote: row.remote.clone(),
        capability: row.capability.clone(),
        opened_at: opened_at(row, attached),
        hold: row
            .hold
            .as_ref()
            .zip(row.remote.as_ref())
            .map(|(hold, remote)| words::hold(hold, remote, &clock(hold.since))),
        beyond: row.beyond.iter().copied().map(words::beyond).collect(),
        state: words::stands(&row.standing, attached.left(row, now), contacts),
        answers: answers(attached, &row.capability),
        cautions: row
            .findings
            .iter()
            .filter(|finding| !finding.blocks())
            .map(ToString::to_string)
            .collect(),
        written: row.written.iter().map(words::written).collect(),
        carried: row.carried.iter().map(words::carried_on).collect(),
        lending: lending(row, attached, judge),
        keys: keys(row, attached, judge),
        proof,
        refused: attached
            .refused
            .as_ref()
            .filter(|(place, _)| *place == here)
            .map(|(_, refusal)| words::refusal(refusal, contacts)),
        turned: match (&attached.attention, &row.remote) {
            (Some(attention), Some(remote)) => {
                words::refused_of(attention, remote, &row.capability).collect()
            }
            _ => Vec::new(),
        },
        held: attached
            .held
            .iter()
            .filter(|(place, _)| *place == here)
            .flat_map(|(_, held)| held.iter().map(|holding| words::holding(holding, keyrings)))
            .collect(),
        exposes: words::exposure(row.exposure),
        through: match &row.through {
            Through::Grant(grant) => format!("granted: {}", words::grant(grant)),
            Through::Start { audience, grant } => format!(
                "{}: {}",
                words::place(Where {
                    audience: *audience,
                    part: Part::Start,
                }),
                words::grant(grant)
            ),
            Through::Connection(_) => "added to this connection alone".to_owned(),
        },
        last: last(row, *clock),
        holds: row
            .holds
            .iter()
            .map(|holding| {
                let mut text = words::holding(holding, keyrings);
                if let Holder::Organisation(audience) = holding.holder
                    && let Some(asked) = words::ask(contacts, audience)
                {
                    let _ = write!(text, ". Whom to ask: {asked}");
                }
                text
            })
            .collect(),
        acts,
        policy: row.remote.as_ref().map_or_else(Vec::new, |remote| {
            let nameable = nameable(row, attached);
            row.decides
                .iter()
                .map(|decides| {
                    policy(
                        remote,
                        &row.capability,
                        connection,
                        (decides, &row.decides),
                        keyrings,
                        &nameable,
                    )
                })
                .collect()
        }),
    }
}

/// The address the remote's tools open `row`'s capability at, where it is a
/// serial port: with how long they wait for the person where its opening is
/// held for them.
fn opened_at(row: &Row, attached: &Attached) -> Option<String> {
    let (vocabulary, document) = (attached.catalogue.as_ref()?, attached.document.as_ref()?);
    let Source::Serial { remote, .. } =
        grant::capability(vocabulary.reference(), document, &row.capability)?.source
    else {
        return None;
    };
    Some(
        match row
            .decides
            .iter()
            .find(|decides| decides.operation == Operation::Connect)
        {
            Some(decides) => words::rfc2217_in(remote, decides.mode),
            None => words::rfc2217(remote),
        },
    )
}

/// Where a remote was refused a page its browser capability opens no site
/// for, opening that site from now on. The person's own capability gains the
/// site, asked first with what it lets through; one they cannot change -
/// what Hedwig ships, the organisation's - is where a capability of their own
/// begins, opening it too.
fn add_site(
    capability: &Name,
    site: &Site,
    attached: &Attached,
    judge: &Judge<'_>,
) -> Option<Shown> {
    let (Some(vocabulary), Some(document)) = (&attached.catalogue, &attached.document) else {
        return None;
    };
    let known = grant::capability(vocabulary.reference(), document, capability)?;
    let Source::Browser { browser, sites } = &known.source else {
        return None;
    };
    if sites.contains(site) {
        return None;
    }
    let written = site.to_string();
    if !document
        .capabilities
        .iter()
        .any(|own| own.id == *capability)
    {
        return Some(offered(
            &format!("Define a capability that opens {written}..."),
            Act::Define(Box::new(define::Draft::opening(&known, site))),
        ));
    }
    let mut sites = sites.clone();
    sites.push(site.clone());
    Some(judge.act(
        format!("Open {written} from now on"),
        Answer::Words("Open it from now on"),
        Change::Define(Capability {
            id: capability.clone(),
            source: Source::Browser {
                browser: browser.clone(),
                sites,
            },
        }),
        || {
            format!(
                "A remote {capability} is granted to can then have your browser open {written}, \
                 where your signed-in sessions are, whenever it asks."
            )
        },
    ))
}

/// Each site a remote was refused for `capability` that it can be given,
/// from what needs the person.
fn add_sites(row: &Row, attached: &Attached, judge: &Judge<'_>) -> Vec<Shown> {
    let (Some(attention), Some(remote)) = (&attached.attention, &row.remote) else {
        return Vec::new();
    };
    attention
        .iter()
        .filter_map(|needs| match &needs.attention {
            Attention::Refused {
                remote: Some(refused),
                refusal: Refusal::UnlistedSite { capability, site },
                ..
            } if refused == remote && *capability == row.capability => {
                add_site(capability, site, attached, judge)
            }
            _ => None,
        })
        .collect()
}

/// Where readiness read the remote and no platform profile answers to the
/// system it named, defining one for that system, its kernel filled in.
fn define_for(row: &Row) -> Option<Shown> {
    row.findings.iter().find_map(|finding| match finding {
        Finding::NoProfile(Refusal::UnknownKernel(kernel)) => Some(offered(
            &format!("Define a platform for {kernel}..."),
            Act::Define(Box::new(define::Draft::platform_for(kernel))),
        )),
        _ => None,
    })
}

/// Lending the device a remote was refused for want of a lending, from what
/// needs the person, where its grant is the person's to change and does not
/// lend it now.
fn lend_reached(
    remote: &RemoteId,
    capability: &Name,
    serial: &DeviceSerial,
    reading: &Reading<'_>,
) -> Option<Shown> {
    let attached = reading.attached;
    let row = attached
        .rows
        .iter()
        .flatten()
        .find(|row| row.remote.as_ref() == Some(remote) && row.capability == *capability)?;
    let document = attached.document.as_ref()?;
    let (lends, statement) = lent_by(row, document)?;
    if lends.lends(serial) {
        return None;
    }
    let held = match attached.devices.get(capability) {
        Some(Some(Ok(devices))) => &devices[..],
        _ => &[],
    };
    let said = words::lent(serial, held);
    Some(lend(row, &lends, &statement, serial, &said, &reading.judge))
}

/// Lending the key a remote was refused for want of a lending, or used
/// beyond the hosts it is lent toward, for anything, from what needs the
/// person, where the grant is the person's to change and does not lend it so
/// now.
fn lend_key_reached(
    remote: &RemoteId,
    capability: &Name,
    key: &SshKey,
    reading: &Reading<'_>,
) -> Option<Shown> {
    let attached = reading.attached;
    let row = attached
        .rows
        .iter()
        .flatten()
        .find(|row| row.remote.as_ref() == Some(remote) && row.capability == *capability)?;
    let (lends, statement) = lent_by(row, attached.document.as_ref()?)?;
    let said = words::ssh_key(key, keyrings_of(row, attached));
    match lends.key(key).map(|lent| &lent.toward) {
        None => Some(lend_key(
            row,
            &lends,
            &statement,
            (key, listed(attached, capability, key)),
            &said,
            &reading.judge,
        )),
        Some(Toward::Hosts(_)) => Some(anywhere(
            row,
            &lends,
            &statement,
            key,
            &said,
            &reading.judge,
        )),
        Some(Toward::Anywhere) => None,
    }
}

fn put_away(item: &Attention) -> Option<Shown> {
    item.item()
        .map(|item| offered("Put away", Act::Send(Request::PutAway(item))))
}

fn need(item: &Attention, contacts: &[Contact], reading: &Reading<'_>) -> Need {
    let keyrings = reading.attached.keyrings();
    let mut acts = Vec::new();
    if let Attention::Refused {
        refusal: Refusal::UnlistedSite { capability, site },
        ..
    } = item
    {
        acts.extend(add_site(capability, site, reading.attached, &reading.judge));
    }
    if let Attention::Refused {
        remote: Some(remote),
        refusal:
            Refusal::Withheld {
                capability,
                request: Withheld::Unlent(Some(serial)),
            },
        ..
    } = item
    {
        acts.extend(lend_reached(remote, capability, serial, reading));
    }
    if let Attention::Refused {
        remote: Some(remote),
        refusal:
            Refusal::Withheld {
                capability,
                request: Withheld::KeyUnlent(key) | Withheld::Elsewhere(key),
            },
        ..
    } = item
    {
        acts.extend(lend_key_reached(remote, capability, key, reading));
    }
    match item {
        Attention::Request { .. } | Attention::Prompt { .. } | Attention::Burst { .. } => {
            acts.push(offered("Answer", Act::Answer));
        }
        Attention::Unready {
            remote, capability, ..
        } => acts.push(offered(
            "Check again",
            Act::Send(Request::Check {
                remote: remote.clone(),
                capability: capability.clone(),
            }),
        )),
        Attention::Stopped { remote, .. } => acts.push(offered(
            "Connect",
            Act::Send(Request::Connect {
                remote: remote.clone(),
                with: Vec::new(),
                acknowledged: Exposes::NONE,
                lends: Lends::none(),
            }),
        )),
        Attention::Unreadable {
            store: Store::Trail,
            ..
        } => acts.push(confirm(
            "Resume all exposure...",
            "Resume all exposure",
            Request::Resume(Remotes::Every),
            "Whether you had paused anything is no longer known, so everything was paused. \
             Everything you have granted becomes reachable again."
                .to_owned(),
        )),
        _ => {}
    }
    if !matches!(item, Attention::Burst { .. }) {
        acts.extend(put_away(item));
    }
    let mut sentence = words::attention(item, keyrings);
    if let Attention::Refused { refusal, .. } = item
        && let Some(asked) =
            words::refused_by(refusal).and_then(|audience| words::ask(contacts, audience))
    {
        let _ = write!(sentence, ". Whom to ask: {asked}");
    }
    Need { sentence, acts }
}

/// What happened, entry by entry, as the person reads it: what the entry
/// says, without its time. A request is said with how it ended where that is
/// known, so its end is said apart only where the request is not.
#[allow(
    clippy::too_many_lines,
    reason = "one arm for each kind of entry about a remote"
)]
fn happened(
    event: &Event,
    asked: &BTreeSet<RequestId>,
    taken: &BTreeMap<RequestId, (&Name, &PortName)>,
    keyrings: Keyrings<'_>,
) -> Option<String> {
    // What an agent request asked to have signed is said with the request,
    // or on its own where the request is on an earlier page.
    if let Event::Payload { request, payload } = event {
        return (!asked.contains(request)).then(|| {
            format!(
                "a request asked earlier was for {}",
                words::payload(payload)
            )
        });
    }
    Some(match event {
        Event::Opening {
            with,
            lends,
            opener,
            ..
        } => {
            // A connection opened for nothing named carries whatever is
            // granted to the remote.
            let what = if with.is_empty() {
                String::new()
            } else {
                let mut what = format!(
                    " for {}",
                    with.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                if !lends.is_none() {
                    let _ = write!(what, ", which {}", words::lends(lends, &[]));
                }
                what
            };
            match opener {
                Opener::Person(_) => format!("connecting{what}, as you asked"),
                Opener::Grant => format!("connecting{what}, as its grant says"),
                Opener::Again => format!("connecting{what} again, after the last connection ended"),
                Opener::Check(_) => format!("connecting to check the remote{what}, as you asked"),
            }
        }
        Event::Ran {
            program,
            release,
            asking,
            ..
        } => {
            let mut text = format!("ran {program}");
            if let Some(release) = release {
                let _ = write!(text, ", release {release}");
            }
            if *asking == hedwig_model::trail::Asking::Nobody {
                text.push_str(", with nothing able to reach you, so it could ask you nothing");
            }
            text
        }
        Event::Observed { platform, .. } => format!("read the remote as {platform}"),
        Event::Checked {
            capability,
            readiness,
            ..
        } => match readiness {
            Readiness::Ready => format!("{capability} is ready there"),
            Readiness::Unready(found) => format!(
                "{capability}: {}",
                found
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        },
        // What Hedwig changed on a remote, so the person can read it there.
        Event::Prepared {
            capability,
            prepared,
            ..
        } => match prepared {
            Prepared::Created(path) => {
                format!("made the folder {path} for {capability}, private to the remote user")
            }
            Prepared::Removed(path) => {
                format!("removed the socket {path}, which nothing answered at, for {capability}")
            }
        },
        Event::Wrote {
            capability,
            write,
            place,
            made,
            ..
        } => {
            let mut text = format!(
                "wrote {} for {capability}, with your consent",
                words::written(&Written {
                    write: write.clone(),
                    place: place.clone(),
                    made: None,
                })
            );
            if let Some(made) = made {
                let _ = write!(text, ", making the folder {made}");
            }
            text
        }
        Event::Unwrote {
            capability,
            write,
            place,
            ..
        } => format!(
            "took back {} for {capability}, as your consent ended",
            words::written(&Written {
                write: write.clone(),
                place: place.clone(),
                made: None,
            })
        ),
        Event::Prompted {
            kind, words: said, ..
        } => format!(
            "the connection's client asked for {}: {said}",
            words::prompt(*kind)
        ),
        Event::Answered { by, .. } => match by.map(|gave| gave.given) {
            Some(Given::Text | Given::Accepted) => "you answered what it asked".to_owned(),
            Some(Given::Declined) => "you declined what it asked".to_owned(),
            None => "nobody answered what it asked".to_owned(),
        },
        Event::Up { serving, .. } => {
            let reachable = serving
                .iter()
                .map(|serving| {
                    format!(
                        "{} reachable there at {}",
                        serving.capability,
                        words::binding(&serving.binding)
                    )
                })
                .collect::<Vec<_>>();
            if reachable.is_empty() {
                "connected".to_owned()
            } else {
                format!("connected: {}", reachable.join("; "))
            }
        }
        Event::Down { end, .. } => format!("the connection ended: {}", words::end(end)),
        Event::Disconnected { .. } => "disconnected".to_owned(),
        Event::Appeared { .. } => "its route listed it as running".to_owned(),
        Event::Gone { .. } => "its route no longer listed it as running".to_owned(),
        // A request the ADB relay withheld is refused on its own; the
        // connection that carried it was not turned away.
        Event::TurnedAway {
            refusal: refusal @ Refusal::Withheld { .. },
            ..
        } => refusal.to_string(),
        Event::TurnedAway { refusal, .. } => format!("a connection was turned away: {refusal}"),
        Event::Carried {
            capability,
            carriage,
            ..
        } => words::carried(capability, carriage),
        Event::Dropped {
            capability,
            carriage,
            why,
            ..
        } => words::dropped(capability, carriage, *why),
        Event::Asked {
            capability,
            operation,
            key,
            ..
        } => {
            let mut text = format!("asked to {} {capability}", words::operation(*operation));
            if let Some(key) = key {
                let _ = write!(text, ", {}", words::key(key, keyrings));
            }
            text
        }
        Event::Held { request } if !asked.contains(request) => {
            "a request asked earlier is waiting for your answer".to_owned()
        }
        Event::Settled { request, outcome } if !asked.contains(request) => {
            format!("a request asked earlier ended: {}", words::outcome(outcome))
        }
        Event::Allowed {
            capability,
            operation,
            key,
            ..
        } => {
            let mut text = format!(
                "you allowed every request to {} {capability}",
                words::operation(*operation)
            );
            if let Some(key) = key {
                let _ = write!(text, " with {}", words::key(key, keyrings));
            }
            text.push_str(" on that connection, for a time");
            text
        }
        Event::Ruled { scope, mode, .. } => match mode {
            Some(mode) => format!(
                "for that connection, {}: {}",
                words::connection_scope(scope, keyrings),
                words::mode(*mode)
            ),
            None => format!(
                "for that connection, what you set for {} was cleared",
                words::connection_scope(scope, keyrings)
            ),
        },
        Event::Exercised {
            capability, proof, ..
        } => words::proof(proof, capability),
        Event::Browsed { site, callback, .. } => words::browsed(site, *callback),
        Event::Taken {
            capability,
            port,
            usb,
            ..
        } => words::taken(capability, port, *usb),
        Event::Released { request } => match taken.get(request) {
            Some((capability, port)) => words::released(capability, port),
            None => "a serial port held for a request asked earlier was closed: its connection \
             ended, and the port is free again"
                .to_owned(),
        },
        Event::Uncarried { end, .. } => words::uncarried(*end).to_owned(),
        Event::Paused { scope, .. } => format!("you paused {}", words::remotes(scope)),
        Event::Resumed { scope, .. } => format!("you resumed {}", words::remotes(scope)),
        Event::Unreleased { .. } => "a request for a credential found none on this workstation: \
                                     the remote's git was given nothing and goes on to its own \
                                     next helper"
            .to_owned(),
        Event::Refuted {
            capability, site, ..
        } => format!(
            "{site} refused the credential {capability} gave the remote's git; it is unchanged \
             on this workstation"
        ),
        Event::Noticed {
            capability,
            remark,
            unheard,
            ..
        } => format!(
            "said through {capability}: {}",
            words::notice(remark, *unheard)
        ),
        // What answers for a capability the remote is carried to changed on
        // this workstation, from then on.
        Event::HeldBy { capability, holder } => match holder {
            Some(holder) => words::answered(capability, holder),
            None => format!("nothing is known to answer for {capability} on this workstation"),
        },
        Event::Kept { dropped, cut } => words::kept(*dropped, *cut),
        // Said with the request they hold or settle, and the workstation's
        // own, which no remote's activity holds.
        Event::Held { .. }
        | Event::Settled { .. }
        | Event::Started { .. }
        | Event::Unreadable { .. }
        | Event::Attached { .. }
        | Event::Presence { .. }
        | Event::Detached { .. }
        | Event::Changed { .. }
        | Event::Imported { .. }
        | Event::Unlisted { .. }
        | Event::KeyMade { .. }
        | Event::KeyDeleted { .. }
        | Event::Source { .. }
        | Event::Card { .. }
        | Event::Offered { .. }
        | Event::PutAway { .. }
        | Event::Stopping { .. }
        | Event::Stated { .. }
        | Event::Unstated { .. }
        | Event::Misread { .. }
        | Event::Sleeping
        | Event::Woke
        | Event::Offline
        | Event::Online
        | Event::Payload { .. }
        | Event::Withdrawn { .. }
        | Event::Restored { .. }
        | Event::Icon { .. }
        | Event::Diagnosed { .. }
        | Event::Startup { .. } => return None,
    })
}

/// One remote's activity, newest first, each entry as what it says with its
/// time; a request with how it ended. Entries in a row that say the same -
/// each connection a remote's ADB client opens, served - are one line with
/// how often and from when to when, so what differs is not paged away
/// behind them. `clock` writes a time the way this person's Windows does.
pub fn activity(
    entries: &[Entry],
    clock: &dyn Fn(Timestamp) -> String,
    keyrings: Keyrings<'_>,
) -> Vec<(Seq, String)> {
    let ends: BTreeMap<RequestId, String> = entries
        .iter()
        .filter_map(|entry| match &entry.event {
            Event::Settled {
                request,
                outcome: ended,
            } => Some((*request, words::outcome(ended))),
            Event::Held { request } => Some((*request, "waiting for your answer".to_owned())),
            _ => None,
        })
        .collect();
    let asked: BTreeSet<RequestId> = entries
        .iter()
        .filter(|entry| matches!(entry.event, Event::Asked { .. }))
        .map(|entry| RequestId(entry.seq))
        .collect();
    let payloads: BTreeMap<RequestId, &Payload> = entries
        .iter()
        .filter_map(|entry| match &entry.event {
            Event::Payload { request, payload } => Some((*request, payload)),
            _ => None,
        })
        .collect();
    let taken: BTreeMap<RequestId, (&Name, &PortName)> = entries
        .iter()
        .filter_map(|entry| match &entry.event {
            Event::Taken {
                request,
                capability,
                port,
                ..
            } => Some((*request, (capability, port))),
            _ => None,
        })
        .collect();
    // Newest first: each line's newest entry, its oldest and how many.
    let mut lines: Vec<(Seq, Timestamp, Timestamp, u32, String)> = Vec::new();
    for entry in entries.iter().rev() {
        let Some(mut text) = happened(&entry.event, &asked, &taken, keyrings) else {
            continue;
        };
        if matches!(entry.event, Event::Asked { .. }) {
            if let Some(payload) = payloads.get(&RequestId(entry.seq)) {
                let _ = write!(text, ", for {}", words::payload(payload));
            }
            if let Some(ended) = ends.get(&RequestId(entry.seq)) {
                let _ = write!(text, " - {ended}");
            }
        }
        match lines.last_mut() {
            Some((_, _, oldest, count, said)) if *said == text => {
                *oldest = entry.at;
                *count = count.saturating_add(1);
            }
            _ => lines.push((entry.seq, entry.at, entry.at, 1, text)),
        }
    }
    lines
        .into_iter()
        .map(|(seq, newest, oldest, count, text)| {
            let (from, to) = (clock(oldest), clock(newest));
            let said = match count {
                1 => format!("{to}: {text}"),
                // Within what the clock tells apart, one time.
                _ if from == to => format!("{to}: {text}, {}", words::times(count)),
                _ => format!("{from} to {to}: {text}, {}", words::times(count)),
            };
            (seq, said)
        })
        .collect()
}

/// What the person can do from the entries of `remote`'s activity, by each
/// entry's place, with the capability each act changes: the acts the line
/// and what needs the person offer, on the entries they are due on. A key or
/// a device turned away because the grant does not lend it, or lends the key
/// only toward other hosts, is lent from its entry; a login served with a key
/// the grant lends anywhere can lend it only for logging in to that host
/// from now on. Each only where the grant is the person's to change and the
/// act would change it.
pub fn entry_acts(
    entries: &[Entry],
    remote: &RemoteId,
    attached: &Attached,
) -> BTreeMap<Seq, (Name, Vec<Shown>)> {
    let reading = Reading {
        attached,
        clock: &|_| String::new(),
        now: Instant::now(),
        judge: Judge::of(attached.document.as_ref(), attached.catalogue.as_ref()),
    };
    let ends: BTreeMap<RequestId, &Outcome> = entries
        .iter()
        .filter_map(|entry| match &entry.event {
            Event::Settled { request, outcome } => Some((*request, outcome)),
            _ => None,
        })
        .collect();
    let payloads: BTreeMap<RequestId, &Payload> = entries
        .iter()
        .filter_map(|entry| match &entry.event {
            Event::Payload { request, payload } => Some((*request, payload)),
            _ => None,
        })
        .collect();
    let mut acts = BTreeMap::new();
    for entry in entries {
        let found =
            match &entry.event {
                Event::TurnedAway {
                    refusal:
                        Refusal::Withheld {
                            capability,
                            request: Withheld::KeyUnlent(key) | Withheld::Elsewhere(key),
                        },
                    ..
                } => lend_key_reached(remote, capability, key, &reading)
                    .map(|shown| (capability, shown)),
                Event::TurnedAway {
                    refusal:
                        Refusal::Withheld {
                            capability,
                            request: Withheld::Unlent(Some(serial)),
                        },
                    ..
                } => lend_reached(remote, capability, serial, &reading)
                    .map(|shown| (capability, shown)),
                Event::Asked {
                    capability,
                    key: Some(KeyId::Ssh(key)),
                    ..
                } => {
                    let request = RequestId(entry.seq);
                    let served = matches!(
                        ends.get(&request),
                        Some(
                            Outcome::Served(_)
                                | Outcome::Unseen(_)
                                | Outcome::Allowed(_)
                                | Outcome::Covered
                        )
                    );
                    match payloads.get(&request) {
                        Some(Payload::Authentication {
                            host: Some(host), ..
                        }) if served => only_there(remote, capability, key, host, &reading)
                            .map(|shown| (capability, shown)),
                        _ => None,
                    }
                }
                _ => None,
            };
        if let Some((capability, shown)) = found {
            acts.insert(entry.seq, (capability.clone(), vec![shown]));
        }
    }
    acts
}

/// Lending `key`, which the grant lends anywhere, only for logging in to the
/// host whose key is `host`: lending less, which the model's judge carries
/// out at once, as narrowing on the line is.
fn only_there(
    remote: &RemoteId,
    capability: &Name,
    key: &SshKey,
    host: &SshKey,
    reading: &Reading<'_>,
) -> Option<Shown> {
    let attached = reading.attached;
    let row = attached
        .rows
        .iter()
        .flatten()
        .find(|row| row.remote.as_ref() == Some(remote) && row.capability == *capability)?;
    let (lends, statement) = lent_by(row, attached.document.as_ref()?)?;
    if lends.key(key).map(|lent| &lent.toward) != Some(&Toward::Anywhere) {
        return None;
    }
    let said = words::ssh_key(key, keyrings_of(row, attached));
    let toward = Toward::Hosts(BTreeSet::from([host.clone()]));
    let lets = format!(
        "{said} is then lent to {} {}.",
        whom(row),
        words::toward(&toward)
    );
    Some(reading.judge.act(
        "Lend it only for logging in to this host".to_owned(),
        Answer::Words("Lend it only there"),
        statement.to(toward_key(&lends, key, toward, None)),
        || lets,
    ))
}

/// What `capability` is defined as, where the definitions have been read.
pub fn defined(attached: &Attached, capability: &Name) -> Option<Capability> {
    let (vocabulary, document) = attached
        .catalogue
        .as_ref()
        .zip(attached.document.as_ref())?;
    grant::capability(vocabulary.reference(), document, capability)
}

/// What answers for `capability` on this workstation, as a line says it;
/// nothing until the core has said.
fn answers(attached: &Attached, capability: &Name) -> Vec<String> {
    let defined = defined(attached, capability);
    words::found(attached.workstation.as_ref(), capability).map_or_else(Vec::new, |found| {
        words::answers(found, defined.as_ref().map(|defined| &defined.source))
    })
}

/// The first grant, made ready from what the workstation has: the least
/// exposing capability whose own side answers, to the route a running remote
/// is on, for as long as such a remote runs. Whether Hedwig may write a
/// remote's configuration, and what the grant exposes, are left for the
/// person to say.
pub fn first_draft(found: &Workstation, reference: &Reference, document: &Document) -> Draft {
    let capability = found
        .sources
        .iter()
        .filter(|found| found.health == Some(Health::Sound))
        .filter_map(|found| grant::capability(reference, document, &found.capability))
        .min_by_key(|capability| (capability.exposure(), capability.id.clone()))
        .map(|capability| capability.id);
    let route = found.running.first().map(|remote| remote.route.clone());
    Draft {
        capability,
        activation: route.as_ref().map(|_| Activation::WhileRunning),
        remotes: route.clone().map(Granted::Route),
        route,
        ..Draft::default()
    }
}

fn first(attached: &Attached) -> First {
    let (Some(found), Some(vocabulary), Some(document)) = (
        &attached.workstation,
        &attached.catalogue,
        &attached.document,
    ) else {
        return First {
            has: None,
            cards: Vec::new(),
            draft: Draft::default(),
        };
    };
    let keyrings = attached.keyrings();
    let mut has: Vec<String> = found
        .sources
        .iter()
        .map(|source| {
            let defined = defined(attached, &source.capability);
            words::answers(source, defined.as_ref().map(|defined| &defined.source)).join(" ")
        })
        .collect();
    // The keys each source offers, so the person knows which of theirs a
    // grant puts within reach.
    has.extend(found.keys.iter().map(|offering| {
        let keys: Vec<String> = offering.keyring.keys.iter().map(words::offered).collect();
        let mut text = if keys.is_empty() {
            format!("{} offers no key that can be used", offering.capability)
        } else {
            format!("{} offers {}", offering.capability, keys.join(", "))
        };
        if let Some(signing) = &offering.keyring.signing {
            let _ = write!(text, "; you sign with {signing}");
        }
        text
    }));
    has.extend(
        found
            .running
            .iter()
            .map(|remote| format!("{remote} is running")),
    );
    First {
        has: Some(has),
        cards: found
            .cards
            .iter()
            .map(|card| format!("{}.", words::card(card, keyrings)))
            .collect(),
        draft: first_draft(found, vocabulary.reference(), document),
    }
}

/// The heads of the window's page, from the status: a removal under way,
/// said once here rather than among what needs the person, and each
/// interface's icon the taskbar does not show, in the words of the notice
/// its presence gave, naming its session where it is not this window's.
fn heads(attached: &Attached, clock: &dyn Fn(Timestamp) -> String) -> Vec<Need> {
    let Some(status) = &attached.status else {
        return Vec::new();
    };
    let mut heads = Vec::new();
    if let Some(withdrew) = status.withdrawn {
        heads.push(Need {
            sentence: format!(
                "{}, since {}: it connects to none but to take back what it wrote. Keep Hedwig to \
                 serve your remotes again as you consented, or finish removing it in Windows' \
                 Installed apps.",
                words::BEING_REMOVED,
                clock(withdrew.at)
            ),
            acts: vec![confirm(
                "Keep Hedwig...",
                "Keep Hedwig",
                Request::Restore,
                words::KEEPS.to_owned(),
            )],
        });
    }
    for client in &status.attached {
        let Some(Icon::Missing(missing)) = client.icon else {
            continue;
        };
        let elsewhere = if client.origin.session == attached.you.session {
            String::new()
        } else {
            format!(" in session {}", client.origin.session)
        };
        let sentence = format!(
            "{missing}{elsewhere}. A request that needs your answer still comes up as a card, and \
             everything else that needs you is here."
        );
        if !heads.iter().any(|head: &Need| head.sentence == sentence) {
            heads.push(Need {
                sentence,
                acts: Vec::new(),
            });
        }
    }
    heads
}

impl Window {
    /// What the window shows at `now`. `clock` writes a time the way this
    /// person's Windows does.
    pub fn of(seen: &Seen, clock: &dyn Fn(Timestamp) -> String, now: Instant) -> Window {
        let attached = match &seen.core {
            Core::Attached(attached) => attached,
            other => {
                let act = match other {
                    Core::Absent => Some(Act::Start),
                    Core::Unreachable(_) => Some(Act::Retry),
                    _ => None,
                };
                return Window {
                    heads: Vec::new(),
                    board: Board::Off {
                        sentence: glance::why(other).unwrap_or_default(),
                        act,
                    },
                    refused: None,
                    changes: None,
                };
            }
        };
        let refused = attached
            .refused
            .as_ref()
            .filter(|(place, _)| *place == Place::Window)
            .map(|(_, refusal)| refusal.to_string());
        let heads = heads(attached, clock);
        let (Some(rows), Some(attention)) = (&attached.rows, &attached.attention) else {
            return Window {
                heads,
                board: Board::Asking,
                refused,
                changes: None,
            };
        };
        if rows.is_empty() {
            return Window {
                heads,
                board: Board::First(first(attached)),
                refused,
                changes: None,
            };
        }
        let contacts = attached
            .settings
            .as_ref()
            .map_or(&[][..], |settings| &settings.workstation.contacts[..]);
        // Remotes in order, then the grants no remote has met.
        let mut groups: BTreeMap<(bool, Option<&RemoteId>), Vec<&Row>> = BTreeMap::new();
        for row in rows {
            groups
                .entry((row.remote.is_none(), row.remote.as_ref()))
                .or_default()
                .push(row);
        }
        let reading = Reading {
            attached,
            clock,
            now,
            judge: Judge::of(attached.document.as_ref(), attached.catalogue.as_ref()),
        };
        let groups = groups
            .into_iter()
            .map(|((_, remote), rows)| {
                let connection = glance::connection(&rows);
                Group {
                    heading: remote.map_or_else(|| UNGRANTED.to_owned(), ToString::to_string),
                    lines: rows
                        .iter()
                        .map(|row| line(row, connection, &reading))
                        .collect(),
                }
            })
            .collect();
        let changes = rows
            .iter()
            .filter_map(|row| attached.left(row, now))
            .filter_map(|left| words::again(left).map(|(_, stays)| stays))
            .min();
        Window {
            heads,
            changes,
            board: Board::Exposure {
                needs: attention
                    .iter()
                    .filter(|needs| !matches!(needs.attention, Attention::Withdrawn(_)))
                    .map(|needs| need(&needs.attention, contacts, &reading))
                    .collect(),
                groups,
            },
            refused,
        }
    }
}
