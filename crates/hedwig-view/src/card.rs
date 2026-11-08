//! A request, deciding: the one thing that is asking the person now.
//!
//! The person is typing in another application when a remote asks, and the
//! request is held for them. A [`Card`] says which remote, what it asks and
//! why they are being asked, and offers the answers; [`Deck`] decides which
//! one thing is shown and for how long it has been; [`raise`] decides whether
//! it may be put on the screen. It is never given the focus: only the person
//! brings it forward.

use std::num::NonZeroU32;

use hedwig_model::capability::Operation;
use hedwig_model::gate::Capped;
use hedwig_model::policy::Basis;
use hedwig_model::protocol::{Answer, Attention, Contact, Decision, Needs, Request, Row, Settings};
use hedwig_model::remote::{RemoteId, Remotes};
use hedwig_model::scope::{Audience, Holder};
use hedwig_model::setting::{Autostart, FullScreen};
use hedwig_model::text::{KeyId, Name};
use hedwig_model::trail::{Item, Missing, Payload, PromptId, PromptKind, RequestId};

use crate::words::{self, Keyrings};

pub use crate::words::length;

/// What a card is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    Request(RequestId),
    Prompt(PromptId),
    Burst(RemoteId),
    /// An act of the person's own, put to them before it is done
    /// ([`Card::confirming`]). Nothing the core raises is one.
    Confirming,
    /// That the presence's icon cannot be shown ([`Card::unseen`]): the
    /// presence's own, shown behind whatever the core raised.
    Unseen(Missing),
}

impl Subject {
    /// The subject of an item the card answers; `None` for one that only
    /// needs a look.
    pub fn of(item: &Attention) -> Option<Subject> {
        match item {
            Attention::Request { request, .. } => Some(Subject::Request(*request)),
            Attention::Prompt { prompt, .. } => Some(Subject::Prompt(*prompt)),
            Attention::Burst { remote, .. } => Some(Subject::Burst(remote.clone())),
            _ => None,
        }
    }
}

/// What choosing an answer does.
#[derive(Debug, PartialEq, Eq)]
pub enum Does {
    Send(Request),
    /// Answer the prompt with what the person typed. The text never enters
    /// this crate: the surface that holds it builds the request.
    Typed(PromptId),
    /// Carry out the act a confirmation was asked for, or a notice offers,
    /// which the surface that shows it holds: stopping Hedwig is not always a
    /// request to the core.
    Proceed,
    /// Leave things as they are: the safe answer of a confirmation, and
    /// closing a notice.
    Cancel,
    /// Install Hedwig, and whether it and its icon start at sign-in: the two
    /// ways setup's question goes ahead ([`crate::setup::asking`]).
    Install(Autostart),
    /// Save the person's settings to a file they choose, before removal
    /// takes them ([`crate::removal::before`]).
    Save,
    /// Copy what removal left on the remotes it could not reach
    /// ([`crate::removal::left_text`]).
    Copy,
}

/// Where an answer stands: the usual one and those beside it are the card's
/// own row of answers; one that lets more through than this request stands
/// with what it lets through said beside it; one that ends more than this
/// request stands apart from all of them, by the remote it ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weight {
    Usual,
    Beside,
    Longer,
    Apart,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Choice {
    pub label: String,
    pub does: Does,
    pub weight: Weight,
}

/// What the card is told beside the item it shows, so it can say why the
/// person is asked and why it offers what it offers.
#[derive(Debug, Clone, Copy, Default)]
pub struct Why<'a> {
    /// The rows, which say which statement decided the request.
    pub rows: &'a [Row],
    /// Whom the organisation says to ask, per audience.
    pub contacts: &'a [Contact],
    /// The keys the workstation offers, by which the request's key is named.
    pub keyrings: Keyrings<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Card {
    pub subject: Subject,
    /// The remote it is about; `None` for a confirmation.
    pub from: Option<RemoteId>,
    pub heading: String,
    /// What the heading's question means, said beneath it: a confirmation's
    /// consequence.
    pub says: Option<String>,
    /// What the person needs to decide, each with what it is.
    pub facts: Vec<(&'static str, String)>,
    /// Whether the answer is text the person types, which is never shown.
    pub typed: bool,
    pub choices: Vec<Choice>,
    /// What an answer that allows for a time lets through, said once beside
    /// those answers; `None` when the card offers none.
    pub allows: Option<String>,
    /// How many more are waiting behind this one.
    pub behind: u32,
}

fn choice(label: &str, request: Request, weight: Weight) -> Choice {
    Choice {
        label: label.to_owned(),
        does: Does::Send(request),
        weight,
    }
}

type Facts = Vec<(&'static str, String)>;

/// Whom to ask, once, for each of the organisation's audiences the card
/// names.
fn whom(facts: &mut Facts, contacts: &[Contact], named: &mut Vec<Audience>, audience: Audience) {
    if named.contains(&audience) {
        return;
    }
    named.push(audience);
    if let Some(words) = words::ask(contacts, audience) {
        facts.push(("Whom to ask", words.to_string()));
    }
}

/// The lengths the core offers a held request and the cap that took the
/// rest, which the core gives from one account so they cannot disagree.
struct Allowed<'a> {
    offers: &'a [NonZeroU32],
    capped: Option<&'a Capped>,
}

/// What a held request asks, in the request's own words.
struct Asked<'a> {
    remote: &'a RemoteId,
    capability: &'a Name,
    operation: Operation,
    key: Option<&'a KeyId>,
    payload: Option<&'a Payload>,
}

fn request(
    request: RequestId,
    asked: &Asked<'_>,
    allowed: &Allowed<'_>,
    why: Why<'_>,
) -> (Facts, Vec<Choice>) {
    let Asked {
        remote,
        capability,
        operation: asked,
        key,
        payload,
    } = *asked;
    // Every key the card names is named as this remote's grant of this
    // capability keeps it.
    let why = Why {
        keyrings: why.keyrings.of_capability(remote, capability),
        ..why
    };
    let mut facts = vec![
        ("From", remote.to_string()),
        (
            "Asks to",
            format!("{} {capability}", words::operation(asked)),
        ),
    ];
    if let Some(key) = key {
        facts.push(("Key", words::key(key, why.keyrings)));
        // Whether the person's card will also ask for a touch decides how
        // much an allowance lets through unseen.
        if let Some(card) = words::on_card(key, why.keyrings) {
            facts.push(("On", card));
        }
    }
    // A login told from a signature, and to which host or in which
    // namespace, before the person allows it.
    if let Some(payload) = payload {
        facts.push(("For", words::payload(payload)));
    }
    // The entry for this key where the row has one, else the one for every
    // key.
    let decided = why
        .rows
        .iter()
        .filter(|row| row.remote.as_ref() == Some(remote) && row.capability == *capability)
        .flat_map(|row| &row.decides)
        .filter(|decides| decides.operation == asked)
        .min_by_key(|decides| decides.key.as_ref() != key);
    let mut named = Vec::new();
    if let Some(decided) = decided {
        facts.push((
            "You are asked because of",
            words::basis(&decided.basis, why.keyrings),
        ));
        if let Basis::Limit(limited) = &decided.basis {
            if let Some(under) = words::under(&decided.basis, why.keyrings) {
                facts.push(("Without that limit", under));
            }
            whom(&mut facts, why.contacts, &mut named, limited.audience);
        }
    }
    if let Some(capped) = allowed.capped {
        facts.push(("Allowances", words::capped(capped, why.keyrings)));
        if let Holder::Organisation(audience) = capped.holder {
            whom(&mut facts, why.contacts, &mut named, audience);
        }
    }
    let decide = |decision| Request::Decide { request, decision };
    let mut choices = vec![choice("Allow once", decide(Decision::Once), Weight::Usual)];
    for seconds in allowed.offers {
        choices.push(choice(
            &format!("Allow for {}", length(*seconds)),
            decide(Decision::For(*seconds)),
            Weight::Longer,
        ));
    }
    choices.push(choice("Refuse", decide(Decision::Refuse), Weight::Beside));
    choices.push(choice(
        "Pause this remote",
        Request::Pause(Remotes::One(remote.clone())),
        Weight::Apart,
    ));
    (facts, choices)
}

/// The answers a prompt of this kind takes, and whether the usual one is
/// text the person types.
fn prompt(prompt: PromptId, kind: PromptKind) -> (bool, Vec<Choice>) {
    let answer = |answer| Request::Answer { prompt, answer };
    let decline = choice("Do not connect", answer(Answer::Decline), Weight::Beside);
    match kind {
        // No usual answer: OpenSSH itself makes the
        // person type the word, and neither answer is filled with the accent.
        PromptKind::UnknownHostKey => (
            false,
            vec![
                choice("Trust this host", answer(Answer::Accept), Weight::Beside),
                decline,
            ],
        ),
        // Touching the key answers it; the card can only give up.
        PromptKind::SecurityKeyTouch => (false, vec![decline]),
        PromptKind::AgentConfirmation => (
            false,
            vec![
                choice("Allow", answer(Answer::Accept), Weight::Usual),
                choice("Refuse", answer(Answer::Decline), Weight::Beside),
            ],
        ),
        PromptKind::KeyPassphrase
        | PromptKind::Password
        | PromptKind::SecurityKeyPin
        | PromptKind::Challenge => (
            true,
            vec![
                Choice {
                    label: "Send".to_owned(),
                    does: Does::Typed(prompt),
                    weight: Weight::Usual,
                },
                decline,
            ],
        ),
    }
}

impl Card {
    /// The card for one item the person answers. An allowance is offered for
    /// each length the core says the request may be allowed for (`offers`):
    /// the person's own lengths, up to the smallest cap that covers it.
    pub fn of(item: &Attention, why: Why<'_>, behind: u32) -> Option<Card> {
        let subject = Subject::of(item)?;
        let mut heading = words::attention(item, why.keyrings);
        let mut allows = None;
        let (facts, typed, choices) = match item {
            Attention::Request {
                request: held,
                remote,
                capability,
                operation,
                key,
                payload,
                offers,
                capped,
            } => {
                let (facts, choices) = request(
                    *held,
                    &Asked {
                        remote,
                        capability,
                        operation: *operation,
                        key: key.as_ref(),
                        payload: payload.as_ref(),
                    },
                    &Allowed {
                        offers,
                        capped: capped.as_ref(),
                    },
                    why,
                );
                // The heading is the question the answers answer; the key is
                // a fact beneath it, where it is never cut.
                heading = words::asks(remote, capability, *operation);
                if !offers.is_empty() {
                    allows = Some(words::allowance(
                        capability,
                        *operation,
                        key.as_ref(),
                        why.keyrings.of_capability(remote, capability),
                    ));
                }
                (facts, false, choices)
            }
            Attention::Prompt {
                prompt: raised,
                remote,
                kind,
                words: said,
            } => {
                let (typed, choices) = prompt(*raised, *kind);
                let facts = vec![
                    ("Connecting to", remote.to_string()),
                    ("It says", said.to_string()),
                ];
                (facts, typed, choices)
            }
            Attention::Burst { remote, .. } => (
                vec![("From", remote.to_string())],
                false,
                vec![
                    choice(
                        "Pause this remote",
                        Request::Pause(Remotes::One(remote.clone())),
                        Weight::Usual,
                    ),
                    choice(
                        "This is expected",
                        Request::PutAway(Item::Burst(remote.clone())),
                        Weight::Beside,
                    ),
                ],
            ),
            _ => return None,
        };
        let from = match item {
            Attention::Request { remote, .. }
            | Attention::Prompt { remote, .. }
            | Attention::Burst { remote, .. } => Some(remote.clone()),
            _ => None,
        };
        Some(Card {
            subject,
            from,
            heading,
            says: None,
            facts,
            typed,
            choices,
            allows,
            behind,
        })
    }

    /// What an act the person chose will do, put to them before it is done:
    /// the verb asked as the heading's question, the consequence beneath it,
    /// and two answers - the verb, and "Cancel", the safe one, which the
    /// keyboard starts on. Neither is filled with the accent: the act widens
    /// what is reachable or ends what the person would set up again, and such
    /// an act is never the one a surface makes prominent.
    pub fn confirming(verb: &str, consequence: &str) -> Card {
        Card {
            subject: Subject::Confirming,
            from: None,
            heading: format!("{verb}?"),
            says: Some(consequence.to_owned()),
            facts: Vec::new(),
            typed: false,
            choices: vec![
                Choice {
                    label: verb.to_owned(),
                    does: Does::Proceed,
                    weight: Weight::Beside,
                },
                Choice {
                    label: "Cancel".to_owned(),
                    does: Does::Cancel,
                    weight: Weight::Beside,
                },
            ],
            allows: None,
            behind: 0,
        }
    }

    /// The notice that the presence's icon cannot be shown, `behind` items
    /// waiting after it: what still reaches the person and where Hedwig is,
    /// with opening its window and closing the notice. Hedwig goes on
    /// offering the icon.
    pub fn unseen(unseen: Missing, behind: u32) -> Card {
        let why = match unseen {
            Missing::Refused => {
                "Hedwig has offered its icon to the taskbar for two minutes; it appears once the \
                 taskbar takes it."
            }
            Missing::NoTaskbar => "Hedwig's icon appears once the taskbar runs again.",
        };
        Card {
            subject: Subject::Unseen(unseen),
            from: None,
            heading: unseen.to_string(),
            says: Some(format!(
                "{why} Until then a request that needs your answer still comes up like this, and \
                 everything else that needs you is in Hedwig's window, which starting Hedwig again \
                 opens."
            )),
            facts: Vec::new(),
            typed: false,
            choices: vec![
                Choice {
                    label: "Open Hedwig".to_owned(),
                    does: Does::Proceed,
                    weight: Weight::Usual,
                },
                Choice {
                    label: "Close".to_owned(),
                    does: Does::Cancel,
                    weight: Weight::Beside,
                },
            ],
            allows: None,
            behind,
        }
    }

    /// What the card says of the others that wait, when any do.
    pub fn waiting(&self) -> Option<String> {
        (self.behind > 0).then(|| format!("{} more waiting behind this one", self.behind))
    }
}
/// Which one thing the card shows, and since when.
#[derive(Debug, Default)]
pub struct Deck {
    showing: Option<Subject>,
    since: u64,
}

impl Deck {
    /// Brings the card in step with what now needs an answer, at `now`
    /// milliseconds. What is showing stays while it still waits, whatever
    /// arrived since: a new arrival never takes the place of what the person
    /// is reading. Returns whether the card shows something else than before.
    pub fn settle(&mut self, attention: &[Needs], now: u64) -> bool {
        self.settle_with(attention, None, now)
    }

    /// The same, with `own`, a subject of the presence's own, waiting after
    /// everything the core raised.
    pub fn settle_with(&mut self, attention: &[Needs], own: Option<&Subject>, now: u64) -> bool {
        let mut waiting = attention
            .iter()
            .filter_map(|needs| Subject::of(&needs.attention))
            .chain(own.cloned());
        if let Some(showing) = &self.showing
            && waiting.clone().any(|subject| subject == *showing)
        {
            return false;
        }
        let next = waiting.next();
        let changed = next != self.showing;
        if changed {
            self.showing = next;
            self.since = now;
        }
        changed
    }

    pub fn showing(&self) -> Option<&Subject> {
        self.showing.as_ref()
    }

    /// The card for what is showing, and how many wait behind it.
    pub fn card(&self, attention: &[Needs], why: Why<'_>) -> Option<Card> {
        let showing = self.showing.as_ref()?;
        let answered = attention
            .iter()
            .filter(|needs| Subject::of(&needs.attention).is_some())
            .count();
        let behind = u32::try_from(answered.saturating_sub(1)).unwrap_or(u32::MAX);
        attention
            .iter()
            .map(|needs| &needs.attention)
            .find(|item| Subject::of(item).as_ref() == Some(showing))
            .and_then(|item| Card::of(item, why, behind))
    }

    /// Whether an answer may be taken yet.
    ///
    /// For `settle` milliseconds after the card begins to show something, no
    /// answer is accepted: a click or a key that was already on its way to
    /// whatever was there before decides nothing. `settle` is the system's
    /// own double-click time, the longest it takes two presses to be one act.
    pub fn armed(&self, now: u64, settle: u32) -> bool {
        self.showing.is_some() && now.saturating_sub(self.since) >= u64::from(settle)
    }
}

/// What the desktop will take, as the shell reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Desk {
    /// An ordinary desktop.
    Open,
    /// An application fills the screen.
    Filled,
    /// The person has told Windows they are presenting and to hold pop-ups.
    Presenting,
    /// A full-screen exclusive application owns the display.
    Exclusive,
    /// Locked, or showing a screen saver.
    Away,
}

/// Whether the person has the card for `remote` shown over an application
/// that fills the screen, as the core resolved it; what ships until the core
/// has said.
pub fn over(remote: &RemoteId, settings: Option<&Settings>) -> FullScreen {
    settings
        .and_then(|settings| {
            settings
                .remotes
                .iter()
                .find(|resolved| resolved.remote == *remote)
        })
        .map_or(FullScreen::SHIPS, |resolved| resolved.full_screen.value)
}

/// Whether the card for a remote may be on the screen now.
///
/// The card is a window, which do not disturb does not hold back. It is
/// shown over an application that fills the screen unless the person set it
/// not to be for that remote (`over`, the core's `full_screen`), since a
/// developer's full-screen terminal is usually where the request came from.
/// It is never shown over a presentation or an exclusive display. Where it
/// is not shown, the interface has told the core what its desktop takes
/// (`presence`), and the core refuses what nobody else can be asked about.
pub fn raise(desk: Desk, over: FullScreen) -> bool {
    match desk {
        Desk::Open => true,
        Desk::Filled => over == FullScreen::Shown,
        Desk::Presenting | Desk::Exclusive | Desk::Away => false,
    }
}

/// The labels with an access key marked in each, no key used twice: the first
/// letter or digit of the label that no earlier label took.
pub fn keyed<'a>(labels: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut taken = Vec::new();
    labels
        .into_iter()
        .map(|label| {
            // A `&` of the label's own is doubled, so it is drawn and read as
            // itself and never taken for the marker.
            let label = label.replace('&', "&&");
            let key = label.char_indices().find(|(_, character)| {
                character.is_ascii_alphanumeric()
                    && !taken.contains(&character.to_ascii_lowercase())
            });
            match key {
                Some((at, character)) => {
                    taken.push(character.to_ascii_lowercase());
                    let (before, from) = label.split_at(at);
                    format!("{before}&{from}")
                }
                None => label,
            }
        })
        .collect()
}
