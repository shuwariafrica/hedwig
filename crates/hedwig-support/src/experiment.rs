//! Readiness as a run against a real remote performs it: the core's own survey script for
//! a plan given as words, and the core's own reading and placing of what the
//! remote printed, as one JSON object to a line.
//!
//! A plan's words are `ask=<capability>`, `key=<fingerprint>`,
//! `ours=<path>`, `write=<capability>/<write>` and
//! `undo=<capability>/<write>=<path>[|<folder>]`, a write named as a report
//! names it (`no-autostart`, `masked`, `signing-key:<fingerprint>`,
//! `variable:<name>`) and the folder the outermost one it made.

use hedwig_core::survey::{Answer, Asked, At, Plan, Question, Report, Undo, place, read, theirs};
use hedwig_model::capability::Setup;
use hedwig_model::config::{Catalogue, Configuration};
use hedwig_model::json::{Json, Layout, render};
use hedwig_model::text::{Fingerprint, Mark, Name, RemotePath, Variable};
use hedwig_model::trail::Write;
use hedwig_model::wire::Wire;

/// Why a plan's words or a report could not be taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unusable {
    /// A word of the plan that is none of the five.
    Word(String),
    /// A capability nothing defines, with the core's words.
    Capability(String),
    /// What the core's reader refused the report as.
    Report(String),
    /// A system no profile answers to, with the core's words.
    Platform(String),
}

impl std::fmt::Display for Unusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unusable::Word(word) => write!(f, "not a word of a plan: {word}"),
            Unusable::Capability(why) => write!(f, "no such capability: {why}"),
            Unusable::Report(why) => write!(f, "the report was not read: {why}"),
            Unusable::Platform(why) => write!(f, "the remote's system has no profile: {why}"),
        }
    }
}

impl std::error::Error for Unusable {}

/// A write as a report names it.
fn write_of(word: &str) -> Option<Write> {
    match word.split_once(':') {
        None if word == "no-autostart" => Some(Write::NoAutostart),
        None if word == "socket-file" => Some(Write::SocketFile),
        None if word == "masked" => Some(Write::Masked),
        Some(("public-key", key)) => Fingerprint::try_from(key).ok().map(Write::PublicKey),
        Some(("signing-key", key)) => Mark::try_from(key).ok().map(Write::SigningKey),
        Some(("variable", name)) => Variable::try_from(name).ok().map(Write::Variable),
        _ => None,
    }
}

fn shipped() -> Result<Catalogue, Unusable> {
    Catalogue::shipped().map_err(|error| Unusable::Capability(error.to_string()))
}

/// The plan `words` describe, its questions those the shipped catalogue's
/// capability raises.
///
/// # Errors
///
/// [`Unusable::Word`] for a word that is none of the five or names nothing
/// valid; [`Unusable::Capability`] for a capability nothing defines.
pub fn plan(words: &[String]) -> Result<Plan, Unusable> {
    let catalogue = shipped()?;
    let configuration = Configuration::default();
    let mut plan = Plan::default();
    for word in words {
        let unusable = || Unusable::Word(word.clone());
        let (kind, rest) = word.split_once('=').ok_or_else(unusable)?;
        match kind {
            "ask" => {
                let id = Name::try_from(rest).map_err(|_| unusable())?;
                let capability = configuration
                    .capability(&catalogue, &id)
                    .map_err(|refusal| Unusable::Capability(refusal.to_string()))?;
                plan.asks.push(Asked {
                    capability: id,
                    questions: Question::of(&capability.forms()),
                    server: hedwig_core::survey::server(&capability),
                });
            }
            "key" => plan
                .keys
                .push(Fingerprint::try_from(rest).map_err(|_| unusable())?),
            "ours" => plan
                .ours
                .push(RemotePath::try_from(rest).map_err(|_| unusable())?),
            "write" => {
                let (capability, write) = rest.split_once('/').ok_or_else(unusable)?;
                plan.writes.push((
                    Name::try_from(capability).map_err(|_| unusable())?,
                    write_of(write).ok_or_else(unusable)?,
                ));
            }
            "undo" => {
                let (capability, rest) = rest.split_once('/').ok_or_else(unusable)?;
                let (write, path) = rest.split_once('=').ok_or_else(unusable)?;
                let (path, made) = match path.split_once('|') {
                    Some((path, made)) => (
                        path,
                        Some(RemotePath::try_from(made).map_err(|_| unusable())?),
                    ),
                    None => (path, None),
                };
                plan.undo.push(Undo {
                    capability: Name::try_from(capability).map_err(|_| unusable())?,
                    write: write_of(write).ok_or_else(unusable)?,
                    place: RemotePath::try_from(path).map_err(|_| unusable())?,
                    made,
                });
            }
            _ => return Err(unusable()),
        }
    }
    Ok(plan)
}

fn text(bytes: &[u8]) -> Json {
    Json::Text(String::from_utf8_lossy(bytes).into_owned())
}

fn optional<T>(value: Option<T>, to: impl FnOnce(T) -> Json) -> Json {
    value.map_or(Json::Null, to)
}

fn at(at: &At) -> Json {
    let word = match at {
        At::Free => "free",
        At::Ours => "ours",
        At::Removed => "removed",
        At::Occupied => "occupied",
        At::Agent => "agent",
        At::Server(_) => "server",
        At::Answers => "answers",
        At::Silent => "silent",
        At::Unprobed => "unprobed",
        At::Held(_) => "held",
        At::Uncleared(_) => "uncleared",
    };
    Json::Text(word.to_owned())
}

fn writes(list: &[(Write, Vec<u8>)], what: &str) -> Json {
    Json::List(
        list.iter()
            .map(|(write, place)| {
                Json::Map(vec![
                    (
                        "write".to_owned(),
                        Json::Text(hedwig_core::survey::write_word(write)),
                    ),
                    (what.to_owned(), text(place)),
                ])
            })
            .collect(),
    )
}

fn made(list: &[hedwig_core::survey::Made]) -> Json {
    Json::List(
        list.iter()
            .map(|(write, place, made)| {
                Json::Map(vec![
                    (
                        "write".to_owned(),
                        Json::Text(hedwig_core::survey::write_word(write)),
                    ),
                    ("place".to_owned(), text(place)),
                    ("made".to_owned(), optional(made.as_deref(), text)),
                ])
            })
            .collect(),
    )
}

/// One capability's answer, and what readiness makes of it on `platform`.
fn capability(id: &Name, answer: &Answer, placed: Option<&hedwig_core::survey::Placed>) -> Json {
    let place = answer.place.as_ref();
    let mut fields = vec![
        ("capability".to_owned(), Json::Text(id.as_str().to_owned())),
        (
            "path".to_owned(),
            optional(place, |place| text(&place.path)),
        ),
        (
            "created".to_owned(),
            optional(place.and_then(|place| place.created.as_deref()), text),
        ),
        (
            "uncreatable".to_owned(),
            optional(place.and_then(|place| place.uncreatable.as_deref()), text),
        ),
        (
            "filesystem".to_owned(),
            optional(place.and_then(|place| place.filesystem.as_deref()), text),
        ),
        (
            "at".to_owned(),
            optional(place.and_then(|place| place.at.as_ref()), at),
        ),
        (
            "absent".to_owned(),
            optional(answer.absent.as_ref(), |tool| {
                Json::Text(tool.as_str().to_owned())
            }),
        ),
        (
            "autostart".to_owned(),
            optional(answer.autostart, Json::Bool),
        ),
        ("keyboxd".to_owned(), optional(answer.keyboxd, Json::Bool)),
        (
            "signing".to_owned(),
            optional(answer.signing.as_ref(), |signing| {
                signing.as_deref().map_or(Json::Bool(false), text)
            }),
        ),
        (
            "listeners".to_owned(),
            Json::Map(
                answer
                    .listeners
                    .iter()
                    .map(|(port, listened)| (port.to_string(), Json::Bool(*listened)))
                    .collect(),
            ),
        ),
        (
            "unit".to_owned(),
            optional(
                place.and_then(|place| match &place.at {
                    Some(At::Held(unit)) => Some(unit.as_slice()),
                    _ => None,
                }),
                text,
            ),
        ),
        (
            "commands".to_owned(),
            Json::Map(
                answer
                    .commands
                    .iter()
                    .map(|(variable, seen)| (variable.as_str().to_owned(), Json::Bool(*seen)))
                    .collect(),
            ),
        ),
        ("wrote".to_owned(), made(&answer.wrote)),
        ("kept".to_owned(), writes(&answer.kept, "place")),
        ("unwrote".to_owned(), writes(&answer.unwrote, "place")),
        ("unwritten".to_owned(), writes(&answer.unwritten, "why")),
    ];
    if let Some(placed) = placed {
        let (findings, blocking) = match &placed.readiness {
            hedwig_model::trail::Readiness::Unready(findings) => (
                findings.iter().map(Wire::put).collect(),
                findings.iter().filter(|finding| finding.blocks()).count(),
            ),
            hedwig_model::trail::Readiness::Ready => (Vec::new(), 0),
        };
        fields.extend([
            ("findings".to_owned(), Json::List(findings)),
            (
                "blocking".to_owned(),
                Json::Number(i128::try_from(blocking).unwrap_or(i128::MAX)),
            ),
            (
                "prepared".to_owned(),
                Json::List(placed.prepared.iter().map(Wire::put).collect()),
            ),
            ("carried".to_owned(), Json::Bool(placed.serving.is_some())),
        ]);
    }
    Json::Map(fields)
}

/// How the core reads a channel's client that ended with `status` and `last`
/// as its last line, nothing having ended the channel while it ran: the
/// ending in its written form, and when the channel comes back after it.
pub fn ending(status: i32, last: &str) -> String {
    let end = hedwig_core::channel::ended(status, false, hedwig_core::channel::words(last));
    let back = match end.back() {
        hedwig_model::trail::Back::Paced => "paced",
        hedwig_model::trail::Back::AtOnce => "at-once",
        hedwig_model::trail::Back::WhenWanted => "when-wanted",
        hedwig_model::trail::Back::ByThePerson => "by-the-person",
    };
    render(
        &Json::Map(vec![
            ("end".to_owned(), end.put()),
            ("back".to_owned(), Json::Text(back.to_owned())),
        ]),
        Layout::Line,
    )
}

/// What the remote printed for a survey begun with `nonce`, as the core
/// reads it and places each capability, `stated` being what the route's
/// client said of the host with `-G`: one line naming the system and the
/// person's shell, then one per capability.
///
/// # Errors
///
/// [`Unusable::Report`] where the core's reader refuses the report;
/// [`Unusable::Platform`] for a system no shipped profile answers to;
/// [`Unusable::Capability`] for an answer about a capability nothing defines.
pub fn account(output: &str, nonce: &str, stated: &str) -> Result<Vec<String>, Unusable> {
    let report: Report =
        read(output, nonce).map_err(|unread| Unusable::Report(format!("{unread:?}")))?;
    let catalogue = shipped()?;
    let configuration = Configuration::default();
    let platform = configuration
        .platform_answering(&catalogue, &report.kernel)
        .map_err(|refusal| Unusable::Platform(refusal.to_string()))?;
    let theirs = theirs(stated);
    let mut lines = vec![render(
        &Json::Map(vec![
            (
                "kernel".to_owned(),
                Json::Text(report.kernel.as_str().to_owned()),
            ),
            (
                "platform".to_owned(),
                Json::Text(platform.family.as_str().to_owned()),
            ),
            ("shell".to_owned(), text(&report.shell)),
        ]),
        Layout::Line,
    )];
    for (id, answer) in &report.answers {
        let defined = configuration
            .capability(&catalogue, id)
            .map_err(|refusal| Unusable::Capability(refusal.to_string()))?;
        let placed = defined
            .carrier(platform, Setup::Write)
            .ok()
            .map(|form| place(id, &form, platform, answer, &[], &theirs));
        lines.push(render(
            &capability(id, answer, placed.as_ref()),
            Layout::Line,
        ));
    }
    Ok(lines)
}
