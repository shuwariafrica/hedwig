//! The notification-area presence: what the icon says at a glance, and what
//! its menu offers.
//!
//! The person is mid-work in another application and looks once: is what I
//! expose as I intend, and is anything asking me? The icon answers on two
//! axes - [`Reach`] and [`Waiting`] - and both are read from what the core
//! last said, never kept.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use hedwig_model::config::Change;
use hedwig_model::policy::{ConnectionScope, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{
    Act as RowAct, Attention, Contact, Needs, Request, Row, Served, Standing, Through,
};
use hedwig_model::remote::{RemoteId, Remotes};
use hedwig_model::setting::Volume;
use hedwig_model::trail::{self, Carriage, ConnectionId, Network};

use crate::act::Act;
use crate::card::Subject;
use crate::link::{Attached, Core, Seen};
use crate::words::{self, BEING_REMOVED, KEEPS, Keyrings};

/// The longest tooltip the shell keeps: `szTip` is 128 UTF-16 units with its
/// terminator.
pub const TIP: usize = 127;
/// The longest title of a notification the shell keeps (`szInfoTitle`).
pub const TITLE: usize = 63;
/// The longest text of a notification the shell keeps (`szInfo`).
pub const TEXT: usize = 255;

/// Whether anything of the person's is reachable from a remote now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reach {
    /// No core answers.
    Off,
    /// A core is starting, or has not said yet.
    Wait,
    /// The person paused all exposure.
    Paused,
    /// Nothing is connected.
    Quiet,
    /// This many remotes reach something now.
    Reachable(u32),
}

/// Whether anything needs the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Waiting {
    Nothing,
    /// This many things wait for a look and hold nothing up.
    Look(u32),
    /// This many requests or prompts are held until the person answers.
    Answer(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glance {
    pub reach: Reach,
    pub waiting: Waiting,
    tip: String,
}

fn count(items: usize) -> u32 {
    u32::try_from(items).unwrap_or(u32::MAX)
}

fn plural(number: u32, one: &str, many: &str) -> String {
    if number == 1 {
        format!("1 {one}")
    } else {
        format!("{number} {many}")
    }
}

/// `text` cut to `most` UTF-16 units, what the shell keeps, on a character
/// boundary.
fn fit(text: &str, most: usize) -> String {
    if text.encode_utf16().count() <= most {
        return text.to_owned();
    }
    let mut kept = String::new();
    let mut units = 0;
    for character in text.chars() {
        units += character.len_utf16();
        if units > most - 3 {
            break;
        }
        kept.push(character);
    }
    kept.push_str("...");
    kept
}

/// How many of these the card answers: what holds a remote up until the
/// person answers it.
fn answered(attention: &[Needs]) -> usize {
    attention
        .iter()
        .filter(|needs| Subject::of(&needs.attention).is_some())
        .count()
}

/// The remotes that reach something now.
fn reaching(rows: &[Row]) -> BTreeSet<&RemoteId> {
    rows.iter()
        .filter(|row| matches!(row.standing, Standing::Serving(_)))
        .filter_map(|row| row.remote.as_ref())
        .collect()
}

impl Glance {
    fn new(reach: Reach, waiting: Waiting, tip: &str) -> Glance {
        Glance {
            reach,
            waiting,
            tip: fit(tip, TIP),
        }
    }

    pub fn of(seen: &Seen) -> Glance {
        // A tooltip is one short line. Why no core answers can be longer
        // than the shell keeps, so the tooltip says that none does, and the
        // menu and the window say why in full ([`why`]).
        let (reach, tip) = match &seen.core {
            Core::Absent => (Reach::Off, "Hedwig is not running"),
            Core::Starting => (Reach::Wait, "Hedwig is starting"),
            Core::Restarting { .. } => (Reach::Off, "Hedwig broke down and is starting again"),
            Core::Unreachable(_) => (Reach::Off, "Hedwig cannot be reached - open this for why"),
            Core::Refused(_) => (
                Reach::Off,
                "Hedwig cannot be used from this icon - open this for why",
            ),
            Core::Attached(attached) => return Glance::attached(attached),
        };
        Glance::new(reach, Waiting::Nothing, tip)
    }

    fn attached(attached: &Attached) -> Glance {
        let (Some(status), Some(rows), Some(attention)) =
            (&attached.status, &attached.rows, &attached.attention)
        else {
            return Glance::new(
                Reach::Wait,
                Waiting::Nothing,
                "Hedwig - asking what is exposed",
            );
        };
        let reach = if status.paused.contains(&Remotes::Every) {
            Reach::Paused
        } else {
            match count(reaching(rows).len()) {
                0 => Reach::Quiet,
                remotes => Reach::Reachable(remotes),
            }
        };
        let held = answered(attention);
        let waiting = match (count(held), count(attention.len() - held)) {
            (0, 0) => Waiting::Nothing,
            (0, look) => Waiting::Look(look),
            (answer, _) => Waiting::Answer(answer),
        };
        let mut tip = match reach {
            _ if status.withdrawn.is_some() => BEING_REMOVED.to_owned(),
            Reach::Paused => "Hedwig - all exposure is paused".to_owned(),
            Reach::Reachable(remotes) => {
                format!(
                    "Hedwig - reachable from {}",
                    plural(remotes, "remote", "remotes")
                )
            }
            _ => "Hedwig - nothing is connected".to_owned(),
        };
        if status.network == Network::Offline {
            tip.push_str(" - no network");
        }
        match waiting {
            Waiting::Answer(answer) => {
                let _ = write!(tip, " - {answer} waiting for your answer");
            }
            Waiting::Look(look) => {
                let _ = write!(tip, " - {look} to look at");
            }
            Waiting::Nothing => {}
        }
        Glance::new(reach, waiting, &tip)
    }

    /// The icon's tooltip, never longer than [`TIP`] UTF-16 units.
    pub fn tip(&self) -> &str {
        &self.tip
    }
}

/// How long after `tries` refused adds the icon is added again, while the
/// taskbar is there to take it: a second, doubling, never longer than half a
/// minute. The shell refuses an add while its taskbar is starting or too
/// busy to answer; where there is no taskbar at all, the icon waits for the
/// shell to say one was made.
pub fn added_again(tries: u32) -> Duration {
    Duration::from_secs(1_u64 << tries.min(5)).min(Duration::from_secs(30))
}

/// How long the icon is missing before the person is told: longer than a
/// taskbar takes to start, at sign-in or when Explorer is started again, so
/// a shell that is only starting is never reported.
pub const UNSEEN_AFTER: Duration = Duration::from_secs(120);

/// Since when the icon has been missing, and whether the person has been
/// told of it since.
#[derive(Debug, Default)]
pub struct Missing {
    since: Option<Instant>,
    told: bool,
}

impl Missing {
    /// The icon is there: the next absence is counted afresh. Whether the
    /// person had been told it was missing, so the core is told it is back.
    pub fn shown(&mut self) -> bool {
        let told = self.told;
        *self = Missing::default();
        told
    }

    /// The icon is not there at `now`, `why`: what to tell the person, once
    /// it has been missing for [`UNSEEN_AFTER`], and only the first time.
    pub fn missing(&mut self, now: Instant, why: trail::Missing) -> Option<trail::Missing> {
        let since = *self.since.get_or_insert(now);
        if self.told || now.saturating_duration_since(since) < UNSEEN_AFTER {
            return None;
        }
        self.told = true;
        Some(why)
    }

    /// When the person is next to be told, for the loop to wake then; `None`
    /// while the icon is there and once they have been.
    pub fn due(&self) -> Option<Instant> {
        self.since
            .filter(|_| !self.told)
            .map(|since| since + UNSEEN_AFTER)
    }
}

/// Why no core answers, in full: what the menu's first line and the window
/// say. `None` while one does.
pub fn why(core: &Core) -> Option<String> {
    match core {
        Core::Absent => Some("Hedwig is not running.".to_owned()),
        Core::Starting => Some("Hedwig is starting.".to_owned()),
        Core::Restarting { cause, said } => {
            let mut text = format!(
                "Hedwig broke down and is starting again: {}.",
                words::breakdown(*cause)
            );
            if !said.is_empty() {
                let _ = write!(text, " Its last words: {said}");
            }
            Some(text)
        }
        Core::Unreachable(sentence) => Some(format!("Hedwig cannot be reached: {sentence}.")),
        Core::Refused(refusal) => Some(format!("Hedwig refused this interface: {refusal}.")),
        Core::Attached(_) => None,
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Entry {
    /// Words only.
    Line(String),
    Rule,
    Act {
        label: String,
        act: Act,
        /// The command the menu shows as its default.
        chief: bool,
    },
    Group {
        label: String,
        entries: Vec<Entry>,
    },
}

fn act(label: &str, act: Act) -> Entry {
    Entry::Act {
        label: label.to_owned(),
        act,
        chief: false,
    }
}

fn chief(label: String, act: Act) -> Entry {
    Entry::Act {
        label,
        act,
        chief: true,
    }
}

const STOPS: &str = "Every remote loses what you granted it until Hedwig is started again, and \
                     whatever is being served ends now.";
const RESUMES: &str = "Everything you have granted becomes reachable from its remotes again.";

/// The live connection a remote's rows describe, where one is open.
pub fn connection(rows: &[&Row]) -> Option<ConnectionId> {
    rows.iter().find_map(|row| row.connection)
}

fn offers(rows: &[&Row], wanted: RowAct) -> bool {
    rows.iter().any(|row| {
        row.acts
            .iter()
            .any(|offered| offered.act == wanted && offered.withheld.is_none())
    })
}

fn everything<T>() -> Selector<T> {
    Selector::Every
}

/// What the menu says of one row under its remote: where it stands, what
/// is carried and wrong, what Hedwig wrote there, and what the relay refused.
fn row_lines(remote: &RemoteId, row: &Row, attached: &Attached, now: Instant) -> Vec<Entry> {
    // A grant the person did not make is said to be the
    // organisation's where it is shown.
    let from = match row.through {
        Through::Start { .. } => ", from your organisation's starting point",
        Through::Grant(_) | Through::Connection(_) => "",
    };
    let mut lines = vec![Entry::Line(format!(
        "{}{from}: {}",
        row.capability,
        words::standing(&row.standing, attached.left(row, now))
    ))];
    // What readiness found that does not keep it off the channel,
    // and what Hedwig wrote there: the remote as it now stands.
    lines.extend(
        row.findings
            .iter()
            .filter(|finding| !finding.blocks())
            .map(|finding| Entry::Line(format!("{}: also, {finding}", row.capability))),
    );
    if !row.written.is_empty() {
        lines.push(Entry::Line(format!(
            "{}: Hedwig wrote there, with your consent: {}",
            row.capability,
            row.written
                .iter()
                .map(words::written)
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    // Where each reverse, forward and console lands on the remote; the
    // workstation's own port for each is the window's to say.
    if !row.carried.is_empty() {
        let reverses: Vec<String> = row
            .carried
            .iter()
            .filter_map(|carried| match &carried.carriage {
                Carriage::Reverse(to) => Some(words::target(to)),
                Carriage::Forward { .. } | Carriage::Console { .. } => None,
            })
            .collect();
        let mut said = Vec::new();
        if !reverses.is_empty() {
            said.push(format!(
                "a device's connections reach {}",
                reverses.join("; ")
            ));
        }
        said.extend(
            row.carried
                .iter()
                .filter(|carried| !matches!(carried.carriage, Carriage::Reverse(_)))
                .map(|carried| words::carriage(&carried.carriage)),
        );
        lines.push(Entry::Line(format!(
            "{}: {}",
            row.capability,
            said.join("; ")
        )));
    }
    // A serial port this remote's connection holds: the window says since
    // when.
    if let Some(hold) = &row.hold {
        lines.push(Entry::Line(format!(
            "{}: {} is held for this remote's connection",
            row.capability, hold.port
        )));
    }
    // What the relay refused the remote, while it needs the person.
    lines.extend(
        attached
            .attention
            .iter()
            .flat_map(|attention| words::refused_of(attention, remote, &row.capability))
            .map(Entry::Line),
    );
    // Beside a refusal of a program that may be the person's: what answers,
    // and the source's own tool that stops it. Once for the capability: the
    // remedy is the source's, whichever of the failures it was.
    let defined = crate::exposure::defined(attached, &row.capability);
    let mended = attached
        .attention
        .iter()
        .flatten()
        .filter_map(|needs| match &needs.attention {
            Attention::Refused {
                remote: Some(refused),
                refusal,
                ..
            } if refused == remote && words::about(refusal) == Some(&row.capability) => {
                Some(refusal)
            }
            _ => None,
        })
        .find_map(|refusal| {
            words::mended(
                refusal,
                &defined.as_ref()?.source,
                attached.workstation.as_ref(),
            )
        });
    lines.extend(mended.map(Entry::Line));
    lines
}

fn remote_group(remote: &RemoteId, rows: &[&Row], attached: &Attached, now: Instant) -> Entry {
    let mut entries: Vec<Entry> = rows
        .iter()
        .flat_map(|row| row_lines(remote, row, attached, now))
        .collect();
    entries.push(Entry::Rule);
    let asked_first = rows
        .iter()
        .flat_map(|row| &row.decides)
        .all(|decides| decides.mode == Mode::Confirm);
    if !asked_first {
        if let Some(connection) = connection(rows) {
            entries.push(act(
                "Ask me first, until this connection ends",
                Act::Send(Request::Rule {
                    connection,
                    scope: ConnectionScope {
                        capability: everything(),
                        operation: everything(),
                        key: Keys::Every,
                    },
                    mode: Some(Mode::Confirm),
                }),
            ));
        }
        entries.push(act(
            "Always ask me first for this remote",
            Act::Send(Request::Change(Change::Rule {
                scope: RuleScope {
                    remotes: Remotes::One(remote.clone()),
                    capability: everything(),
                    operation: everything(),
                    key: Keys::Every,
                },
                mode: Mode::Confirm,
            })),
        ));
    }
    if offers(rows, RowAct::Pause) {
        entries.push(act(
            "Pause this remote",
            Act::Send(Request::Pause(Remotes::One(remote.clone()))),
        ));
    }
    if offers(rows, RowAct::Disconnect) {
        entries.push(act(
            "Disconnect",
            Act::Send(Request::Disconnect {
                remote: remote.clone(),
            }),
        ));
    }
    // Readiness again, where it named something: what a person fixing the
    // remote does next. It widens nothing.
    for row in rows.iter().filter(|row| !row.findings.is_empty()) {
        if offers(&[row], RowAct::Check) {
            entries.push(act(
                &format!("Check {} again", row.capability),
                Act::Send(Request::Check {
                    remote: remote.clone(),
                    capability: row.capability.clone(),
                }),
            ));
        }
    }
    entries.push(act(
        "How this remote is decided...",
        Act::Open(Some(remote.clone())),
    ));
    Entry::Group {
        label: remote.to_string(),
        entries,
    }
}

/// Whether a row describes a connection that exists now: one its capability
/// cannot be served on is still the remote's, and what refuses it is said
/// under the remote.
fn live(row: &Row) -> bool {
    match row.standing {
        Standing::Opening
        | Standing::Needs(_)
        | Standing::Unready(_)
        | Standing::Serving(_)
        | Standing::Returning { .. } => true,
        Standing::Unavailable(_) => row.connection.is_some(),
        Standing::Idle | Standing::Checking | Standing::Paused | Standing::Ended(_) => false,
    }
}

/// The menu the icon opens at `now`, built when it is opened and never kept:
/// each line, a channel's countdown included, is as the core last said when
/// it opened.
pub fn menu(seen: &Seen, now: Instant) -> Vec<Entry> {
    entries(seen, Some(now))
}

/// The menu's entries; `now` is `None` where no line will be read, as when
/// only the menu's default is sought.
fn entries(seen: &Seen, now: Option<Instant>) -> Vec<Entry> {
    let attached = match &seen.core {
        Core::Attached(attached) => return attached_menu(attached, now),
        other => other,
    };
    let mut entries: Vec<Entry> = why(attached).map(Entry::Line).into_iter().collect();
    match attached {
        Core::Absent => entries.push(chief("Start Hedwig".to_owned(), Act::Start)),
        Core::Unreachable(_) => entries.push(chief("Try again".to_owned(), Act::Retry)),
        _ => {}
    }
    entries.push(Entry::Rule);
    if matches!(attached, Core::Restarting { .. } | Core::Refused(_)) {
        // A Hedwig whose cores keep breaking down, or that another install
        // left running, is still stopped by one act.
        entries.push(act(
            "Stop Hedwig...",
            Act::Stop {
                consequence: STOPS.to_owned(),
            },
        ));
    }
    entries.push(act("Close this icon", Act::Leave));
    entries
}
fn attached_menu(attached: &Attached, now: Option<Instant>) -> Vec<Entry> {
    let leave = act("Close this icon", Act::Leave);
    let (Some(status), Some(rows), Some(attention)) =
        (&attached.status, &attached.rows, &attached.attention)
    else {
        return vec![
            Entry::Line("Asking Hedwig what is exposed".to_owned()),
            Entry::Rule,
            leave,
        ];
    };
    let mut entries = Vec::new();
    if status.origin.session != attached.you.session {
        // A core started from an SSH session persists and is shown on every
        // surface.
        entries.push(Entry::Line(format!(
            "Hedwig was started outside this desktop, in session {}",
            status.origin.session
        )));
    }
    if status.network == Network::Offline {
        entries.push(Entry::Line(
            "There is no network: connections wait for one".to_owned(),
        ));
    }
    // A removal that did not finish: said first, with the one act that ends
    // it short of finishing it, which lets more through.
    if status.withdrawn.is_some() {
        entries.push(Entry::Line(BEING_REMOVED.to_owned()));
        entries.push(act(
            "Keep Hedwig...",
            Act::Confirm {
                request: Request::Restore,
                consequence: KEEPS.to_owned(),
                answer: "Keep Hedwig".to_owned(),
            },
        ));
    }
    let held = answered(attention);
    if held > 0 {
        entries.push(chief(
            format!("Answer what is waiting ({held})"),
            Act::Answer,
        ));
    }
    entries.push(Entry::Act {
        label: "Open Hedwig".to_owned(),
        act: Act::Open(None),
        chief: held == 0,
    });
    entries.push(Entry::Rule);
    if status.paused.contains(&Remotes::Every) {
        entries.push(act(
            "Resume all exposure...",
            Act::Confirm {
                request: Request::Resume(Remotes::Every),
                consequence: RESUMES.to_owned(),
                answer: "Resume all exposure".to_owned(),
            },
        ));
    } else {
        entries.push(act(
            "Pause all exposure",
            Act::Send(Request::Pause(Remotes::Every)),
        ));
    }
    let remotes: BTreeSet<&RemoteId> = rows
        .iter()
        .filter(|row| live(row))
        .filter_map(|row| row.remote.as_ref())
        .collect();
    if !remotes.is_empty() {
        entries.push(Entry::Rule);
    }
    for remote in remotes {
        let of: Vec<&Row> = rows
            .iter()
            .filter(|row| row.remote.as_ref() == Some(remote))
            .collect();
        entries.push(match now {
            Some(now) => remote_group(remote, &of, attached, now),
            None => Entry::Group {
                label: remote.to_string(),
                entries: Vec::new(),
            },
        });
    }
    entries.extend([
        Entry::Rule,
        act(
            "Stop Hedwig...",
            Act::Stop {
                consequence: STOPS.to_owned(),
            },
        ),
        leave,
    ]);
    entries
}

/// A notification raised through the icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    title: String,
    text: String,
    /// Whether it is put to the person now, whatever Windows is holding back
    /// for quiet: what interrupts is.
    pub now: bool,
}

impl Announcement {
    fn new(title: &str, text: &str, now: bool) -> Announcement {
        Announcement {
            title: fit(title, TITLE),
            text: fit(text, TEXT),
            now,
        }
    }

    /// For something that needs the person, with whom to ask where it is a
    /// refusal the organisation's policy gave.
    pub fn of(needs: &Needs, contacts: &[Contact], keyrings: Keyrings<'_>) -> Announcement {
        let title = if Subject::of(&needs.attention).is_some() {
            "Hedwig needs your answer"
        } else {
            "Hedwig"
        };
        let mut text = words::attention(&needs.attention, keyrings);
        if let Attention::Refused { refusal, .. } = &needs.attention
            && let Some(asked) =
                words::refused_by(refusal).and_then(|audience| words::ask(contacts, audience))
        {
            let _ = write!(text, ". Whom to ask: {asked}");
        }
        Announcement::new(title, &text, needs.volume == Volume::Interrupts)
    }

    /// For what the interface itself has to say of an act the person has
    /// just made: that it was not done, and why. The person is there, so it
    /// is put to them now.
    pub fn said(title: &str, text: &str) -> Announcement {
        Announcement::new(title, text, true)
    }

    /// For a request served without asking, which is only ever announced.
    pub fn served(served: &Served, keyrings: Keyrings<'_>) -> Announcement {
        Announcement::new("Hedwig", &words::served(served, keyrings), false)
    }

    /// Never longer than [`TITLE`] UTF-16 units.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Never longer than [`TEXT`] UTF-16 units.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// What a click on the icon, or its keyboard equivalent, does: the menu's
/// default command.
pub fn chosen(seen: &Seen) -> Act {
    entries(seen, None)
        .into_iter()
        .find_map(|entry| match entry {
            Entry::Act {
                act, chief: true, ..
            } => Some(act),
            _ => None,
        })
        .unwrap_or(Act::Open(None))
}
