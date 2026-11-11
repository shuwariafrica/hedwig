//! Every setting the person has beyond grants and rules, as the window shows
//! it: its value, the statement it came from, what holds it, and what the
//! person can change there.
//!
//! A remote's settings are shown with that remote's grants, a route's with
//! that route, and the workstation's once, so each is where the person is
//! when they think about it. Every value is the core's (`settings`), and
//! every change is the model's own [`Change`], made at the scope the person
//! chooses: this remote or every remote. A change that can let more through,
//! by the model's own [`Configuration::widens`], is put to the person first.

use std::fmt::{self, Write as _};
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32};

use hedwig_model::config::{Catalogue, Change, Configuration, Document};
use hedwig_model::gate::Capped;
use hedwig_model::install::{AtSignIn, Starts};
use hedwig_model::organisation::Misread;
use hedwig_model::organisation::{Part, Place as Stated};
use hedwig_model::policy::{Keys, Selector};
use hedwig_model::protocol::{
    Loudness, RemoteSettings, Request, RouteSettings, Settings, WindowsStarts, WorkstationSettings,
};
use hedwig_model::remote::{RemoteId, Remotes};
use hedwig_model::scope::Audience;
use hedwig_model::scope::Holder;
use hedwig_model::setting::{
    Autostart, Bounded, Burst, Cadence, CapScope, Condition, Diagnostics, FullScreen, Heard, Keep,
    Keepalive, Lengths, Longest, Returns, Routes, Said, Settled, Span, Threshold, Volume, Waits,
    Workstation,
};
use hedwig_model::text::Name;

use crate::act::Act;
use crate::exposure::Shown;
use crate::link::Vocabulary;
use crate::words::{self, Keyrings};

/// How a value no statement sets is said to come from.
pub(crate) const SHIPS: &str = "what Hedwig ships";

/// One setting as shown.
#[derive(Debug, PartialEq, Eq)]
pub struct Setting {
    pub name: &'static str,
    pub value: String,
    /// Where the value comes from.
    pub said: String,
    /// What Windows does instead of what the value says, where it does
    /// something else.
    pub instead: Option<String>,
    /// Each limit that holds it, with whose it is.
    pub holds: Vec<String>,
    /// What else decides what it does, beside the value.
    pub beside: Option<String>,
    /// The values the person can choose, each a change made at once or put
    /// to them first; the value in force is offered as nothing.
    pub choices: Vec<Shown>,
    /// What the person types to set it, where its values are numbers.
    pub entry: Option<Entry>,
    /// Takes the person's own statement away, so the next source decides.
    pub clear: Option<Shown>,
}

/// The settings of one remote, or one route.
#[derive(Debug, PartialEq, Eq)]
pub struct Section<T> {
    pub of: T,
    pub settings: Vec<Setting>,
}

/// Every setting, placed where it is shown.
#[derive(Debug, PartialEq, Eq)]
pub struct Sheet {
    pub workstation: Vec<Setting>,
    pub remotes: Vec<Section<RemoteId>>,
    pub routes: Vec<Section<Name>>,
    /// Whom the organisation says to ask, in its own words.
    pub contacts: Vec<String>,
    /// What of the organisation's policy cannot be read.
    pub unread: Vec<String>,
}

/// What a typed setting is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Typed {
    /// Requests, within seconds.
    Burst,
    /// Seconds between questions, and how many go unanswered.
    Keepalive,
    /// The first wait and the longest, in seconds.
    Returns,
    /// Seconds between listings.
    Cadence,
    /// The longest an allowance lasts, in seconds, and the key it is for.
    Cap,
    /// The lengths offered, as a list.
    Lengths,
    /// Days of activity kept.
    Keep,
}

/// Where a typed setting is stated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    Remote(RemoteId),
    Route(Name),
    Workstation,
}

/// How widely a statement is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wide {
    /// The remote or route the setting is shown with.
    This,
    /// Every remote, or every route.
    Every,
}

/// A setting the person types, with what is in force now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub typed: Typed,
    pub place: Place,
    /// Each field's name and what it holds now.
    pub fields: Vec<(&'static str, String)>,
    /// What is chosen beside what is typed, where something is.
    pub choice: Option<Choice>,
}

/// A part of a typed setting chosen from what this workstation has rather
/// than typed: the key a cap is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub label: &'static str,
    pub options: Vec<String>,
    /// The option chosen now.
    pub chosen: usize,
    keys: Vec<Keys>,
}

/// Why what was typed is not a value of the setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// A field is not a whole number within its range.
    Number {
        field: &'static str,
        least: u32,
        most: u32,
    },
    /// A length is not a number with `s`, `m` or `h` after it.
    Length(String),
    /// No key is chosen among those offered.
    Key,
    /// The list of lengths is empty.
    NoLength,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Invalid::Number { field, least, most } => {
                write!(f, "{field} is a whole number from {least} to {most}")
            }
            Invalid::Length(text) => write!(
                f,
                "\"{text}\" is not a length: write a number and s, m or h, such as 15m"
            ),
            Invalid::Key => f.write_str("choose the keys the cap is for"),
            Invalid::NoLength => f.write_str("name at least one length, or choose what ships"),
        }
    }
}

impl std::error::Error for Invalid {}

fn said<S>(said: &Said<S>, scope: impl Fn(&S) -> String) -> String {
    match said {
        Said::Ships => SHIPS.to_owned(),
        Said::Start {
            audience,
            scope: at,
        } => format!(
            "{}, for {}",
            words::place(Stated {
                audience: *audience,
                part: Part::Start,
            }),
            scope(at)
        ),
        Said::Person(at) => format!("your statement for {}", scope(at)),
    }
}

fn routes(routes: &Routes) -> String {
    match routes {
        Selector::Every => "every route".to_owned(),
        Selector::Only(route) => route.to_string(),
    }
}

/// A length list as the person would say it.
pub fn lengths(lengths: &Lengths) -> String {
    let all: Vec<String> = lengths.iter().map(words::length).collect();
    if all.is_empty() {
        "none".to_owned()
    } else {
        all.join(", ")
    }
}

/// A length list as the person would type it.
fn typed_lengths(lengths: &Lengths) -> String {
    let all: Vec<String> = lengths
        .iter()
        .map(|seconds| {
            let seconds = seconds.get();
            if seconds.is_multiple_of(3600) {
                format!("{}h", seconds / 3600)
            } else if seconds.is_multiple_of(60) {
                format!("{}m", seconds / 60)
            } else {
                format!("{seconds}s")
            }
        })
        .collect();
    all.join(", ")
}

fn threshold(threshold: Threshold) -> String {
    match threshold {
        Threshold::Never => "never: volume from here is the work".to_owned(),
        Threshold::At(Burst { requests, seconds }) => {
            format!("{requests} requests within {}", words::length(seconds))
        }
    }
}

fn volume(volume: Volume) -> &'static str {
    match volume {
        Volume::Shown => "shown where you look",
        Volume::Announced => "announced once",
        Volume::Interrupts => "put to you at once",
    }
}

fn condition(condition: Condition) -> &'static str {
    match condition {
        Condition::Served => "A request served without asking",
        Condition::Unready => "Readiness failing",
        Condition::Stopped => "A channel stopped that only you can fix",
        Condition::HostKeyChanged => "A host presenting another key",
        Condition::Refused => "A refusal you did not make",
        Condition::Noticed => "A remote's notice",
    }
}

fn keepalive(keepalive: Keepalive) -> String {
    format!(
        "asks after {} of silence, gives up after {} unanswered: a dead link is noticed within {}",
        words::length(NonZeroU32::from(keepalive.every)),
        keepalive.missed,
        NonZeroU32::new(keepalive.notices_within()).map_or_else(String::new, words::length)
    )
}

fn returns(returns: Returns) -> String {
    format!(
        "{} after the first failure, doubling, never longer than {}",
        words::length(returns.first),
        words::length(returns.longest)
    )
}

/// What the model says of each change before it is made: whether it can let
/// more through. Without the document or the catalogue every change is taken
/// to, as the model errs.
pub(crate) struct Judge<'a>(Option<(Configuration, &'a Catalogue)>);

/// What carries out a change put to the person first.
#[derive(Clone, Copy)]
pub(crate) enum Answer {
    /// Its label, short enough for a button.
    Label,
    /// Words shorter than its label.
    Words(&'static str),
}

impl<'a> Judge<'a> {
    pub(crate) fn of(document: Option<&Document>, vocabulary: Option<&'a Vocabulary>) -> Judge<'a> {
        let catalogue = vocabulary.and_then(Vocabulary::catalogue);
        Judge(document.zip(catalogue).and_then(|(document, catalogue)| {
            Some((Configuration::restore(document.clone()).ok()?, catalogue))
        }))
    }

    fn widens(&self, change: &Change) -> bool {
        self.0.as_ref().is_none_or(|(configuration, catalogue)| {
            configuration.widens(catalogue, change) == hedwig_model::config::Reach::Wider
        })
    }

    /// The change as an act: carried out at once, or put to the person with
    /// what it lets through, `label` being the question and the answer that
    /// carries it out, unless `answer` says it shorter.
    pub(crate) fn act(
        &self,
        label: String,
        answer: Answer,
        change: Change,
        lets: impl FnOnce() -> String,
    ) -> Shown {
        let request = Request::Change(change);
        if let Request::Change(change) = &request
            && self.widens(change)
        {
            let answer = match answer {
                Answer::Label => label.clone(),
                Answer::Words(words) => words.to_owned(),
            };
            return Shown::Offered {
                label: format!("{label}..."),
                act: Act::Confirm {
                    request,
                    consequence: lets(),
                    answer,
                },
            };
        }
        Shown::Offered {
            label,
            act: Act::Send(request),
        }
    }
}

fn plain(label: &str, change: Change) -> Shown {
    Shown::Offered {
        label: label.to_owned(),
        act: Act::Send(Request::Change(change)),
    }
}

fn mine(said: &Said<Remotes>) -> Option<Remotes> {
    match said {
        Said::Person(scope) => Some(scope.clone()),
        _ => None,
    }
}

fn burst_setting(settings: &RemoteSettings, this: &Remotes) -> Setting {
    let remote = &settings.remote;
    let at = settings.threshold.value;
    Setting {
        name: "When requests from here are a burst",
        value: threshold(at),
        said: said(&settings.threshold.said, words::remotes),
        holds: Vec::new(),
        instead: None,
        beside: None,
        choices: if at == Threshold::Never {
            Vec::new()
        } else {
            vec![plain(
                "Never: this volume is the work",
                Change::Burst {
                    remotes: this.clone(),
                    threshold: Some(Threshold::Never),
                },
            )]
        },
        entry: Some(Entry {
            typed: Typed::Burst,
            place: Place::Remote(remote.clone()),
            choice: None,
            fields: match at {
                Threshold::At(Burst { requests, seconds }) => vec![
                    ("Requests", requests.to_string()),
                    ("Within seconds", seconds.to_string()),
                ],
                Threshold::Never => vec![
                    ("Requests", String::new()),
                    ("Within seconds", String::new()),
                ],
            },
        }),
        clear: mine(&settings.threshold.said).map(|scope| {
            plain(
                "Remove your statement",
                Change::Burst {
                    remotes: scope,
                    threshold: None,
                },
            )
        }),
    }
}

fn heard(condition: Condition, volume: Volume) -> Option<Heard> {
    let waits = match volume {
        Volume::Shown => Waits::Shown,
        Volume::Announced => Waits::Announced,
        Volume::Interrupts => {
            return (condition == Condition::HostKeyChanged)
                .then_some(Heard::HostKeyChanged(volume));
        }
    };
    Some(match condition {
        Condition::Served => Heard::Served(waits),
        Condition::Unready => Heard::Unready(waits),
        Condition::Stopped => Heard::Stopped(waits),
        Condition::Refused => Heard::Refused(waits),
        Condition::Noticed => Heard::Noticed(waits),
        Condition::HostKeyChanged => Heard::HostKeyChanged(volume),
    })
}

fn loudness_setting(loudness: &Loudness, this: &Remotes) -> Setting {
    let now = loudness.volume.value;
    let offered: &[Volume] = if loudness.condition == Condition::HostKeyChanged {
        &[Volume::Shown, Volume::Announced, Volume::Interrupts]
    } else {
        &[Volume::Shown, Volume::Announced]
    };
    Setting {
        name: condition(loudness.condition),
        value: volume(now).to_owned(),
        said: said(&loudness.volume.said, words::remotes),
        holds: Vec::new(),
        instead: None,
        beside: None,
        choices: offered
            .iter()
            .filter(|volume| **volume != now)
            .filter_map(|volume| {
                heard(loudness.condition, *volume).map(|heard| {
                    plain(
                        &capitalised(self::volume(*volume)),
                        Change::Hear {
                            remotes: this.clone(),
                            heard,
                        },
                    )
                })
            })
            .collect(),
        entry: None,
        clear: mine(&loudness.volume.said).map(|scope| {
            plain(
                "Remove your statement",
                Change::Unhear {
                    remotes: scope,
                    condition: loudness.condition,
                },
            )
        }),
    }
}

fn full_screen_setting(settings: &RemoteSettings, this: &Remotes) -> Setting {
    let card = settings.full_screen.value;
    Setting {
        name: "A held request's card over an application that fills the screen",
        value: match card {
            FullScreen::Shown => "shown".to_owned(),
            FullScreen::NotShown => {
                "not shown: where nothing else can ask you, the request is refused".to_owned()
            }
        },
        said: said(&settings.full_screen.said, words::remotes),
        holds: Vec::new(),
        instead: None,
        beside: None,
        choices: vec![match card {
            FullScreen::Shown => plain(
                "Do not show it there",
                Change::FullScreen {
                    remotes: this.clone(),
                    card: Some(FullScreen::NotShown),
                },
            ),
            FullScreen::NotShown => plain(
                "Show it there",
                Change::FullScreen {
                    remotes: this.clone(),
                    card: Some(FullScreen::Shown),
                },
            ),
        }],
        entry: None,
        clear: mine(&settings.full_screen.said).map(|scope| {
            plain(
                "Remove your statement",
                Change::FullScreen {
                    remotes: scope,
                    card: None,
                },
            )
        }),
    }
}

fn keepalive_setting(settings: &RemoteSettings) -> Setting {
    let remote = &settings.remote;
    let keep = settings.keepalive.value;
    Setting {
        name: "How a dead link is noticed",
        value: keepalive(keep),
        said: said(&settings.keepalive.said, words::remotes),
        holds: Vec::new(),
        instead: None,
        beside: None,
        choices: Vec::new(),
        entry: Some(Entry {
            typed: Typed::Keepalive,
            place: Place::Remote(remote.clone()),
            choice: None,
            fields: vec![
                ("Seconds of silence before asking", keep.every.to_string()),
                (
                    "Questions unanswered before giving up",
                    keep.missed.to_string(),
                ),
            ],
        }),
        clear: mine(&settings.keepalive.said).map(|scope| {
            plain(
                "Remove your statement",
                Change::Keepalive {
                    remotes: scope,
                    keepalive: None,
                },
            )
        }),
    }
}

fn returns_setting(settings: &RemoteSettings) -> Setting {
    let remote = &settings.remote;
    let back = settings.returns.value;
    Setting {
        name: "The waits before a lost channel is opened again",
        value: returns(back),
        said: said(&settings.returns.said, words::remotes),
        holds: Vec::new(),
        instead: None,
        beside: None,
        choices: Vec::new(),
        entry: Some(Entry {
            typed: Typed::Returns,
            place: Place::Remote(remote.clone()),
            choice: None,
            fields: vec![
                ("First wait, in seconds", back.first.to_string()),
                ("Longest wait, in seconds", back.longest.to_string()),
            ],
        }),
        clear: mine(&settings.returns.said).map(|scope| {
            plain(
                "Remove your statement",
                Change::Returns {
                    remotes: scope,
                    returns: None,
                },
            )
        }),
    }
}

fn remote_settings(
    settings: &RemoteSettings,
    document: Option<&Document>,
    judge: &Judge<'_>,
    keyrings: Keyrings<'_>,
) -> Vec<Setting> {
    let remote = &settings.remote;
    let this = Remotes::One(remote.clone());
    let mut all = vec![burst_setting(settings, &this)];
    all.extend(
        settings
            .volumes
            .iter()
            .map(|loudness| loudness_setting(loudness, &this)),
    );
    all.push(full_screen_setting(settings, &this));
    all.push(caps(remote, &settings.caps, judge, keyrings));
    all.push(keepalive_setting(settings));
    all.push(returns_setting(settings));
    if let Some(document) = document {
        for expected in document
            .expected
            .iter()
            .filter(|expected| expected.remote == *remote)
        {
            all.push(Setting {
                name: "A refusal put away for good",
                value: expected.refusal.to_string(),
                said: "your statement".to_owned(),
                holds: Vec::new(),
                instead: None,
                beside: None,
                choices: Vec::new(),
                entry: None,
                clear: Some(plain(
                    "Bring it to your attention again",
                    Change::Unexpect(expected.clone()),
                )),
            });
        }
    }
    all
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn caps(
    remote: &RemoteId,
    capped: &[Capped],
    judge: &Judge<'_>,
    keyrings: Keyrings<'_>,
) -> Setting {
    let longest = capped.first().map(|first| first.longest);
    let mine: Vec<&Capped> = capped
        .iter()
        .filter(|capped| capped.holder == Holder::Person)
        .collect();
    Setting {
        name: "The longest an allowance from a card may last",
        value: match longest {
            None => "no cap".to_owned(),
            Some(Longest::Nothing) => "nothing: no allowance is offered".to_owned(),
            Some(Longest::Seconds(seconds)) => words::length(seconds),
        },
        said: if capped.is_empty() {
            SHIPS.to_owned()
        } else {
            "the smallest cap that covers it".to_owned()
        },
        holds: capped
            .iter()
            .map(|capped| words::capped(capped, keyrings))
            .collect(),
        instead: None,
        beside: None,
        choices: Vec::new(),
        entry: Some(Entry {
            typed: Typed::Cap,
            place: Place::Remote(remote.clone()),
            fields: vec![(
                "Longest, in seconds (0 for none)",
                longest.map_or_else(String::new, |longest| match longest {
                    Longest::Nothing => "0".to_owned(),
                    Longest::Seconds(seconds) => seconds.to_string(),
                }),
            )],
            choice: Some(cap_keys(capped, keyrings)),
        }),
        // Removing a cap of the person's own can let more through, so it is
        // asked first where the model says so.
        clear: mine.first().map(|capped| {
            judge.act(
                "Remove your cap".to_owned(),
                Answer::Label,
                Change::Cap {
                    scope: capped.scope.clone(),
                    longest: None,
                },
                || {
                    format!(
                        "Your cap of {} for {} no longer limits what a card offers.",
                        match capped.longest {
                            Longest::Nothing => "nothing".to_owned(),
                            Longest::Seconds(seconds) => words::length(seconds),
                        },
                        words::remotes(&capped.scope.remotes)
                    )
                },
            )
        }),
    }
}

/// The keys a cap can be for: every key, every key that needs no touch, and
/// each key this workstation offers or a card it holds carries, by name; and
/// the key of a cap of the person's own where none of those is it. Every key
/// is chosen at first.
fn cap_keys(capped: &[Capped], keyrings: Keyrings<'_>) -> Choice {
    let mut options = vec![
        "Every key".to_owned(),
        "Every key that needs no touch".to_owned(),
    ];
    let mut keys = vec![Keys::Every, Keys::NeedingNoTouch];
    for (label, name) in keyrings.named() {
        options.push(capitalised(&label));
        keys.push(Keys::Only(name));
    }
    for capped in capped
        .iter()
        .filter(|capped| capped.holder == Holder::Person)
    {
        if let Keys::Only(name) = &capped.scope.key
            && !keys.contains(&capped.scope.key)
        {
            options.push(capitalised(&words::named(name, keyrings)));
            keys.push(capped.scope.key.clone());
        }
    }
    Choice {
        label: "For",
        options,
        chosen: 0,
        keys,
    }
}

fn route_settings(settings: &RouteSettings) -> Vec<Setting> {
    let cadence = settings.cadence.value;
    vec![Setting {
        name: "How often its platform is asked which remotes run",
        value: format!("every {}", words::length(cadence.0)),
        said: said(&settings.cadence.said, routes),
        holds: Vec::new(),
        instead: None,
        beside: None,
        choices: Vec::new(),
        entry: Some(Entry {
            typed: Typed::Cadence,
            place: Place::Route(settings.route.clone()),
            choice: None,
            fields: vec![("Seconds between listings", cadence.0.to_string())],
        }),
        clear: match &settings.cadence.said {
            Said::Person(scope) => Some(plain(
                "Remove your statement",
                Change::Cadence {
                    routes: scope.clone(),
                    cadence: None,
                },
            )),
            _ => None,
        },
    }]
}

fn misread(misread: &Misread) -> String {
    format!(
        "{}: {} line{} cannot be read ({}), so everything they could hold is held",
        capitalised(&words::place(misread.place)),
        misread.unread.lines.len(),
        if misread.unread.lines.len() == 1 {
            ""
        } else {
            "s"
        },
        misread.unread.account
    )
}

/// Windows' own switch for what starts at sign-in, which Hedwig neither
/// reads nor changes.
const WINDOWS_SWITCH: &str = "Windows' own Startup apps settings can also turn this off; Hedwig \
                              leaves what you set there as it is.";

/// What Windows starts at sign-in for `starts`, where that is not what its
/// choice says; nothing before the core has kept the choice in this run.
fn starts_instead(starts: Starts, found: Option<&AtSignIn>) -> Option<String> {
    let (subject, name) = match starts {
        Starts::Hedwig => ("Hedwig", "Hedwig's name"),
        Starts::Icon => ("Hedwig's icon", "the name of Hedwig's icon"),
    };
    Some(match found? {
        AtSignIn::AsChosen => return None,
        AtSignIn::Another(Some(command)) => format!(
            "When you sign in, Windows starts another program under {name}, which Hedwig leaves \
             as it is: {command}"
        ),
        AtSignIn::Another(None) => format!(
            "When you sign in, Windows starts another program under {name}, which Hedwig leaves \
             as it is."
        ),
        AtSignIn::Absent => {
            format!("{subject} is not installed here, so Windows starts nothing for it.")
        }
        AtSignIn::Unkept(why) => {
            format!("Hedwig could not set this with Windows: {why}.")
        }
    })
}

/// One of the two things that start at sign-in: Hedwig, or its icon.
fn at_sign_in(
    name: &'static str,
    (starts, settled): (Starts, &Settled<Autostart, Workstation>),
    windows: &WindowsStarts,
    on: &str,
    off: &str,
    change: fn(Option<Autostart>) -> Change,
) -> Setting {
    let found = match starts {
        Starts::Hedwig => windows.hedwig.as_ref(),
        Starts::Icon => windows.icon.as_ref(),
    };
    Setting {
        name,
        value: match settled.value {
            Autostart::Off => "off".to_owned(),
            Autostart::AtLogon => "on".to_owned(),
        },
        said: said(&settled.said, |_| "this workstation".to_owned()),
        holds: Vec::new(),
        instead: starts_instead(starts, found),
        beside: Some(WINDOWS_SWITCH.to_owned()),
        choices: vec![match settled.value {
            Autostart::Off => plain(on, change(Some(Autostart::AtLogon))),
            Autostart::AtLogon => plain(off, change(Some(Autostart::Off))),
        }],
        entry: None,
        clear: matches!(settled.said, Said::Person(_))
            .then(|| plain("Remove your statement", change(None))),
    }
}

/// What holds a workstation choice an organisation's limit moved.
fn held(audience: Option<Audience>) -> Vec<String> {
    audience
        .map(|audience| {
            words::place(Stated {
                audience,
                part: Part::Limits,
            })
        })
        .into_iter()
        .collect()
}

fn days(keep: Keep) -> String {
    match keep.0.get() {
        1 => "1 day".to_owned(),
        days => format!("{days} days"),
    }
}

fn keep_setting(keep: &Bounded<Keep>) -> Setting {
    let settled = &keep.settled;
    Setting {
        name: "How long Hedwig keeps what happened",
        value: days(settled.value),
        said: said(&settled.said, |_| "this workstation".to_owned()),
        holds: held(keep.held),
        instead: None,
        beside: Some(format!(
            "Never more than the newest {} entries, which keeps Hedwig quick to start; each \
             remote's activity says where it was cut.",
            words::grouped(u64::try_from(hedwig_model::trail::CEILING).unwrap_or(u64::MAX))
        )),
        choices: Vec::new(),
        entry: Some(Entry {
            typed: Typed::Keep,
            place: Place::Workstation,
            choice: None,
            fields: vec![("Days", settled.value.0.to_string())],
        }),
        clear: matches!(settled.said, Said::Person(_))
            .then(|| plain("Remove your statement", Change::Keep(None))),
    }
}

fn diagnostics(diagnostics: Diagnostics) -> &'static str {
    match diagnostics {
        Diagnostics::Off => "nothing",
        Diagnostics::Faults => "what went wrong",
        Diagnostics::Detail => "what went wrong, and everything a channel's client says",
    }
}

/// Kept as the ring keeps it, whoever chose what is written.
const RING: &str = "It is kept in two files of at most 1 MiB each, the oldest lines going first, \
                    and holds no passphrase or answer of yours.";

/// What is written down, offered at this workstation's scope. A choice made
/// for this run is nearer: while it decides, a statement for this workstation
/// would change nothing written now, so the one act is going back to it.
fn diagnostics_setting(written: &Bounded<Diagnostics, Span>) -> Setting {
    let settled = &written.settled;
    let (said, beside, choices, clear) = if settled.said == Said::Person(Span::Run) {
        (
            "your choice for this run".to_owned(),
            format!(
                "It holds until Hedwig next starts; then your choice for this workstation \
                 decides. {RING}"
            ),
            vec![Shown::Offered {
                label: "Go back to this workstation's choice".to_owned(),
                act: Act::Send(Request::Diagnose(None)),
            }],
            None,
        )
    } else {
        (
            said(&settled.said, |_| "this workstation".to_owned()),
            RING.to_owned(),
            [Diagnostics::Off, Diagnostics::Faults, Diagnostics::Detail]
                .into_iter()
                .filter(|offered| *offered != settled.value)
                .map(|offered| {
                    plain(
                        &format!("Write {}", diagnostics(offered)),
                        Change::Diagnostics(Some(offered)),
                    )
                })
                .collect(),
            matches!(settled.said, Said::Person(_))
                .then(|| plain("Remove your statement", Change::Diagnostics(None))),
        )
    };
    Setting {
        name: "What Hedwig writes down for a supporter",
        value: diagnostics(settled.value).to_owned(),
        said,
        holds: held(written.held),
        instead: None,
        beside: Some(beside),
        choices,
        entry: None,
        clear,
    }
}

fn workstation_settings(workstation: &WorkstationSettings) -> Vec<Setting> {
    let offered = &workstation.lengths;
    let lengths_mine = matches!(offered.said, Said::Person(_));
    vec![
        Setting {
            name: "The lengths a card offers for allowing for a time",
            value: lengths(&offered.value),
            said: said(&offered.said, |_| "this workstation".to_owned()),
            holds: Vec::new(),
            instead: None,
            beside: None,
            choices: Vec::new(),
            entry: Some(Entry {
                typed: Typed::Lengths,
                place: Place::Workstation,
                choice: None,
                fields: vec![("Lengths", typed_lengths(&offered.value))],
            }),
            clear: lengths_mine.then(|| plain("Remove your statement", Change::Lengths(None))),
        },
        at_sign_in(
            "Starting Hedwig when you sign in",
            (Starts::Hedwig, &workstation.autostart),
            &workstation.windows,
            "Start Hedwig when I sign in",
            "Do not start Hedwig when I sign in",
            Change::Autostart,
        ),
        at_sign_in(
            "Starting Hedwig's icon when you sign in",
            (Starts::Icon, &workstation.icon),
            &workstation.windows,
            "Start the icon when I sign in",
            "Do not start the icon when I sign in",
            Change::Icon,
        ),
        keep_setting(&workstation.keep),
        diagnostics_setting(&workstation.diagnostics),
    ]
}

impl Sheet {
    /// One remote's settings, offering nothing a trial could not make.
    pub fn remote(settings: &RemoteSettings, keyrings: Keyrings<'_>) -> Vec<Setting> {
        remote_settings(settings, None, &Judge(None), keyrings)
    }

    /// The workstation's settings.
    pub fn workstation(settings: &WorkstationSettings) -> Vec<Setting> {
        workstation_settings(settings)
    }

    /// The sheet for what the core said. `document` is the person's
    /// configuration and `vocabulary` what is defined outside it, which
    /// together say whether a change lets more through; while either has not
    /// been read, every change that might is asked.
    pub fn of(
        settings: &Settings,
        document: Option<&Document>,
        vocabulary: Option<&Vocabulary>,
        keyrings: Keyrings<'_>,
    ) -> Sheet {
        let judge = Judge::of(document, vocabulary);
        let workstation = &settings.workstation;
        Sheet {
            workstation: workstation_settings(workstation),
            remotes: settings
                .remotes
                .iter()
                .map(|remote| Section {
                    of: remote.remote.clone(),
                    settings: remote_settings(remote, document, &judge, keyrings),
                })
                .collect(),
            routes: settings
                .routes
                .iter()
                .map(|route| Section {
                    of: route.route.clone(),
                    settings: route_settings(route),
                })
                .collect(),
            contacts: workstation
                .contacts
                .iter()
                .map(|contact| {
                    let mut text = capitalised(words::audience(contact.audience));
                    let _ = write!(text, ": ask {}", contact.words);
                    text
                })
                .collect(),
            unread: workstation.unread.iter().map(misread).collect(),
        }
    }
}

fn number(text: &str, field: &'static str, least: u32, most: u32) -> Result<u32, Invalid> {
    text.trim()
        .parse::<u32>()
        .ok()
        .filter(|value| (least..=most).contains(value))
        .ok_or(Invalid::Number { field, least, most })
}

fn length(text: &str) -> Result<NonZeroU32, Invalid> {
    let token = text.trim();
    let invalid = || Invalid::Length(token.to_owned());
    let (digits, unit) = match token.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((at, _)) => (
            token.get(..at).ok_or_else(invalid)?,
            token.get(at..).ok_or_else(invalid)?,
        ),
        None => (token, "m"),
    };
    let scale = match unit.trim() {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return Err(invalid()),
    };
    digits
        .parse::<u32>()
        .ok()
        .and_then(|count| count.checked_mul(scale))
        .and_then(NonZeroU32::new)
        .ok_or_else(invalid)
}

/// Every positive number fits a `NonZero`: the ranges above start at one.
fn nonzero(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap_or(NonZeroU32::MIN)
}

/// A cap typed: the longest, and the keys chosen.
fn cap(
    longest: &str,
    key: Keys,
    remotes: Remotes,
    judge: &Judge<'_>,
    keyrings: Keyrings<'_>,
) -> Result<Shown, Invalid> {
    let seconds = number(longest, "Longest, in seconds (0 for none)", 0, u32::MAX)?;
    let longest = NonZeroU32::new(seconds).map_or(Longest::Nothing, Longest::Seconds);
    let whom = words::remotes(&remotes);
    let what = match &key {
        Keys::Every => whom.clone(),
        Keys::NeedingNoTouch => format!("{whom}, with a key that needs no touch"),
        Keys::Only(name) => format!("{whom}, with {}", words::named(name, keyrings)),
    };
    let scope = CapScope { remotes, key };
    Ok(judge.act(
        format!("Cap for {whom}"),
        Answer::Label,
        Change::Cap {
            scope,
            longest: Some(longest),
        },
        || match longest {
            Longest::Nothing => format!("No allowance is offered for {what}."),
            Longest::Seconds(seconds) => format!(
                "An allowance for {what} can last up to {}, longer than your cap allows now.",
                words::length(seconds)
            ),
        },
    ))
}

/// The days of activity typed for the trail to keep.
fn kept_days(text: &str) -> Result<Keep, Invalid> {
    let days = number(text, "Days", 1, u32::from(u16::MAX))?;
    Ok(Keep(
        NonZeroU16::new(u16::try_from(days).unwrap_or(u16::MAX)).unwrap_or(NonZeroU16::MIN),
    ))
}

/// The lengths typed, as a list separated by commas.
fn offered(text: &str) -> Result<Lengths, Invalid> {
    let offered: Lengths = text
        .split(',')
        .filter(|token| !token.trim().is_empty())
        .map(length)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .collect();
    if offered.iter().next().is_none() {
        return Err(Invalid::NoLength);
    }
    Ok(offered)
}

impl Entry {
    /// What is typed and chosen now, as [`Entry::act`] takes it: each field's
    /// text, then the place of the option chosen where there is a choice.
    pub fn now(&self) -> Vec<String> {
        let mut now: Vec<String> = self.fields.iter().map(|(_, now)| now.clone()).collect();
        if let Some(choice) = &self.choice {
            now.push(choice.chosen.to_string());
        }
        now
    }

    /// The act that sets what was typed, laid out as [`Entry::now`] lays it
    /// out, at the width chosen; a change that lets more through is put to the
    /// person.
    ///
    /// # Errors
    ///
    /// [`Invalid`] naming the first field that holds no value of the setting.
    pub fn act(
        &self,
        typed: &[&str],
        wide: Wide,
        document: Option<&Document>,
        vocabulary: Option<&Vocabulary>,
        keyrings: Keyrings<'_>,
    ) -> Result<Shown, Invalid> {
        let judge = Judge::of(document, vocabulary);
        let field = |at: usize| typed.get(at).copied().unwrap_or_default();
        let remotes = match (&self.place, wide) {
            (Place::Remote(remote), Wide::This) => Remotes::One(remote.clone()),
            _ => Remotes::Every,
        };
        let whom = words::remotes(&remotes);
        let (label, change) = match self.typed {
            Typed::Burst => {
                let requests = number(field(0), "Requests", 1, u32::from(u8::MAX))?;
                let seconds = number(field(1), "Within seconds", 1, u32::MAX)?;
                let burst = Burst {
                    requests: NonZeroU8::new(u8::try_from(requests).unwrap_or(u8::MAX))
                        .unwrap_or(NonZeroU8::MIN),
                    seconds: nonzero(seconds),
                };
                (
                    format!("Set for {whom}"),
                    Change::Burst {
                        remotes,
                        threshold: Some(Threshold::At(burst)),
                    },
                )
            }
            Typed::Keepalive => {
                let every = number(
                    field(0),
                    "Seconds of silence before asking",
                    1,
                    u32::from(u16::MAX),
                )?;
                let missed = number(
                    field(1),
                    "Questions unanswered before giving up",
                    1,
                    u32::from(u8::MAX),
                )?;
                (
                    format!("Set for {whom}"),
                    Change::Keepalive {
                        remotes,
                        keepalive: Some(Keepalive {
                            every: NonZeroU16::new(u16::try_from(every).unwrap_or(u16::MAX))
                                .unwrap_or(NonZeroU16::MIN),
                            missed: NonZeroU8::new(u8::try_from(missed).unwrap_or(u8::MAX))
                                .unwrap_or(NonZeroU8::MIN),
                        }),
                    },
                )
            }
            Typed::Returns => {
                let first = number(field(0), "First wait, in seconds", 1, u32::MAX)?;
                let longest = number(field(1), "Longest wait, in seconds", 1, u32::MAX)?;
                (
                    format!("Set for {whom}"),
                    Change::Returns {
                        remotes,
                        returns: Some(Returns {
                            first: nonzero(first),
                            longest: nonzero(longest),
                        }),
                    },
                )
            }
            Typed::Cadence => {
                let seconds = number(field(0), "Seconds between listings", 1, u32::MAX)?;
                let routes = match (&self.place, wide) {
                    (Place::Route(route), Wide::This) => Selector::Only(route.clone()),
                    _ => Selector::Every,
                };
                (
                    format!("Set for {}", self::routes(&routes)),
                    Change::Cadence {
                        routes,
                        cadence: Some(Cadence(nonzero(seconds))),
                    },
                )
            }
            Typed::Cap => {
                let key = self
                    .choice
                    .as_ref()
                    .and_then(|choice| {
                        let at: usize = field(self.fields.len()).parse().ok()?;
                        choice.keys.get(at).cloned()
                    })
                    .ok_or(Invalid::Key)?;
                return cap(field(0), key, remotes, &judge, keyrings);
            }
            Typed::Lengths => (
                "Set for this workstation".to_owned(),
                Change::Lengths(Some(offered(field(0))?)),
            ),
            Typed::Keep => (
                "Set for this workstation".to_owned(),
                Change::Keep(Some(kept_days(field(0))?)),
            ),
        };
        Ok(judge.act(label, Answer::Label, change, String::new))
    }
}
