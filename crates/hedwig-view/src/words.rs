//! The words a surface uses for what the core says.
//!
//! A refusal is worded by the model and by nothing else
//! ([`hedwig_model::refusal::Refusal`]'s `Display`); everything here is what
//! the model leaves unworded, written once so the notification area, the
//! request and the window say the same thing of the same fact.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::num::NonZeroU32;
use std::time::Duration;

use hedwig_model::beyond::Beyond;
use hedwig_model::capability::{Exposure, Lends, Operation, Source, Toward};
use hedwig_model::config::{Activation, Grant};
use hedwig_model::gate::Capped;
use hedwig_model::holder::SourceHolder;
use hedwig_model::organisation::{Holding, Limit, Part, Place};
use hedwig_model::policy::{Basis, ConnectionScope, KeyName, Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{
    AgentKey, Attachment, Attention, CarriedOn, Contact, DeviceState, Found, Hold, Lendable, Needs,
    Offering, Proof, Row, SerialPort, Served, Standing, Usb, Workstation, Written,
};
use hedwig_model::refusal::{Refusal, Remedy};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::scope::{Audience, Holder, Strict};
use hedwig_model::setting::Longest;
use hedwig_model::text::{
    DeviceSerial, Grip, KeyId, Name, Port, PortName, Remark, Serial, SshKey, Words,
};
use hedwig_model::trail::{
    Binding, Breakdown, CEILING, Card, Carriage, Carry, ChannelEnd, ClientKind, Cut, Dropped,
    Event, Failure, Finding, Health, Key, Outcome, Payload, PromptKind, SignaturePin, Store,
    Target, Touch, Write,
};

use crate::fingerprint;

/// The keys each SSH agent capability's source listed, by capability, as
/// last read: `None` while asked.
pub type AgentKeys = BTreeMap<Name, Option<Result<Vec<AgentKey>, Refusal>>>;

/// The keys the workstation's `GnuPG` sources offer, every card the core has
/// read - in or not, which no read says - the keys an SSH agent listed where
/// the person asked, and the comment each grant keeps for a key it lends, as
/// the core last said, by which a key a request or a statement names is told
/// to the person.
#[derive(Debug, Clone, Copy, Default)]
pub struct Keyrings<'a> {
    /// `None` until the core has said.
    offered: Option<&'a [Offering]>,
    cards: &'a [Card],
    /// What each agent listed, whose comments name its keys.
    agents: Option<&'a AgentKeys>,
    /// The rows, whose terms keep the comment each lent key's agent gave it
    /// when the person lent it.
    rows: &'a [Row],
    /// The remote, and the capability, a key is named for: the comment that
    /// remote's own grant keeps is the one its `ssh-add -l` printed.
    within: Option<(&'a RemoteId, Option<&'a Name>)>,
}

impl<'a> Keyrings<'a> {
    pub fn new(offered: Option<&'a [Offering]>, cards: &'a [Card]) -> Keyrings<'a> {
        Keyrings {
            offered,
            cards,
            agents: None,
            rows: &[],
            within: None,
        }
    }

    /// The same, with what the agents listed.
    #[must_use]
    pub fn listing(self, agents: &'a AgentKeys) -> Keyrings<'a> {
        Keyrings {
            agents: Some(agents),
            ..self
        }
    }

    /// The same, with the comments the rows' grants keep for the keys they
    /// lend.
    #[must_use]
    pub fn lent(self, rows: &'a [Row]) -> Keyrings<'a> {
        Keyrings { rows, ..self }
    }

    /// The same, naming keys for what `remote` asked of `capability`.
    #[must_use]
    pub fn of_capability(self, remote: &'a RemoteId, capability: &'a Name) -> Keyrings<'a> {
        Keyrings {
            within: Some((remote, Some(capability))),
            ..self
        }
    }

    /// The same, naming keys for what `remote` asked of any capability.
    #[must_use]
    pub fn of_remote(self, remote: &'a RemoteId) -> Keyrings<'a> {
        Keyrings {
            within: Some((remote, None)),
            ..self
        }
    }

    /// The comment `key` is named with: the one the grant it is named for
    /// keeps, which the remote's own list printed; else the one an agent
    /// gave it when the person last asked; else the one any grant keeps.
    fn comment(self, key: &SshKey) -> Option<&'a Words> {
        let kept = |row: &'a Row| {
            row.terms
                .as_ref()
                .and_then(|terms| terms.lends.key(key))
                .and_then(|lent| lent.comment.as_ref())
        };
        let within = |row: &&'a Row| {
            self.within.is_some_and(|(remote, capability)| {
                row.remote.as_ref() == Some(remote)
                    && capability.is_none_or(|capability| row.capability == *capability)
            })
        };
        let listed = || {
            self.agents
                .into_iter()
                .flat_map(BTreeMap::values)
                .filter_map(|listed| match listed {
                    Some(Ok(keys)) => Some(keys),
                    _ => None,
                })
                .flatten()
                .find(|listed| listed.key == *key)
                .and_then(|listed| listed.comment.as_ref())
        };
        self.rows
            .iter()
            .filter(within)
            .find_map(kept)
            .or_else(listed)
            .or_else(|| self.rows.iter().find_map(kept))
    }

    fn keys(self) -> impl Iterator<Item = &'a Key> {
        self.offered
            .into_iter()
            .flatten()
            .flat_map(|offering| &offering.keyring.keys)
    }

    /// The key a request names by its keygrip.
    fn by_grip(self, grip: &Grip) -> Option<&'a Key> {
        self.keys().find(|key| key.grip == *grip)
    }

    /// The `GnuPG` key whose SSH form is `ssh`: the one key a request through
    /// gpg-agent's SSH socket names by its public half.
    fn by_ssh(self, ssh: &SshKey) -> Option<&'a Key> {
        self.keys().find(|key| key.ssh.as_ref() == Some(ssh))
    }

    /// Every card that can sign with the key `grip`, each with what it asks
    /// before the key's use: each card read as holding it, then the card the
    /// agent's stub of it names where no reading is of that card - which the
    /// agent asks for when no card holding the key is in, and of which
    /// nothing is known.
    fn cards(self, grip: &Grip) -> Vec<(&'a Serial, Option<Touch>)> {
        let mut cards: Vec<(&'a Serial, Option<Touch>)> = self
            .cards
            .iter()
            .filter_map(|card| {
                let held = card.keys.iter().find(|held| held.grip == *grip)?;
                Some((&card.serial, held.touch))
            })
            .collect();
        let stub = self.by_grip(grip).and_then(|key| key.card.as_ref());
        if let Some(stub) = stub
            && !self.cards.iter().any(|card| card.serial == *stub)
        {
            cards.push((stub, None));
        }
        cards
    }

    /// The name a statement about the key a request used gives it: its own
    /// fingerprint where the workstation's keyring ties the keygrip to one,
    /// as the person knows it, else the keygrip; an SSH key by its public
    /// half.
    pub fn name(self, key: &KeyId) -> KeyName {
        match key {
            KeyId::Grip(grip) => self.grip_name(grip),
            KeyId::Ssh(key) => KeyName::Ssh(key.clone()),
        }
    }

    fn grip_name(self, grip: &Grip) -> KeyName {
        self.by_grip(grip).map_or_else(
            || KeyName::Grip(grip.clone()),
            |key| KeyName::Fingerprint(key.fingerprint.clone()),
        )
    }

    /// Every key a statement can name here, each once, as the person reads
    /// it: a primary key, which names its subkeys with it, then each subkey,
    /// then each key a card holds that no keyring offers.
    pub fn named(self) -> Vec<(String, KeyName)> {
        let mut all: Vec<(String, KeyName)> = Vec::new();
        let mut push = |name: KeyName| {
            if !all.iter().any(|(_, known)| *known == name) {
                all.push((listed(&name, self), name));
            }
        };
        let mut keys: Vec<&Key> = self.keys().collect();
        keys.sort_by_key(|key| (key.primary.clone(), key.fingerprint != key.primary));
        for key in keys {
            push(KeyName::Fingerprint(key.fingerprint.clone()));
        }
        for held in self.cards.iter().flat_map(|card| &card.keys) {
            push(self.grip_name(&held.grip));
        }
        all
    }
}

/// A key of the keyring as a row of it says it: as `gpg` names it, and the
/// form SSH knows it by where it has one, so the person sees that the two
/// names are one key.
pub fn offered(key: &Key) -> String {
    match &key.ssh {
        Some(ssh) => format!("{}, which SSH knows as {}", known(key), ssh_form(ssh)),
        None => known(key),
    }
}

/// A key as `gpg` names it: its own fingerprint, "subkey" where it is not the
/// primary, and whose it is.
fn known(key: &Key) -> String {
    let what = if key.fingerprint == key.primary {
        "key"
    } else {
        "subkey"
    };
    match &key.user {
        Some(user) => format!("{what} {} ({user})", key.fingerprint),
        None => format!("{what} {}", key.fingerprint),
    }
}

/// `text` set so that a line breaks between its words and nowhere inside
/// one: a word joiner (U+2060) after each hyphen, slash and question mark
/// that a word goes on after, the places a line otherwise breaks inside a
/// word; and a zero-width space (U+200B) before a word that begins with a
/// slash, since a line may not otherwise break before one even after a space
/// (UAX #14, LB13). A path, an address, a fingerprint or a remote's name then
/// reads as one; a word wider than its line is still broken where it must
/// be. What a painted surface lays out to wrap, never what it says to
/// assistive technology.
pub fn unbroken(text: &str) -> String {
    let mut set = String::with_capacity(text.len() + text.len() / 8);
    let mut characters = text.chars().peekable();
    let mut spaced = false;
    while let Some(character) = characters.next() {
        if character == '/' && spaced {
            set.push('\u{200B}');
        }
        set.push(character);
        spaced = character.is_whitespace();
        if matches!(character, '-' | '/' | '?')
            && characters
                .peek()
                .is_some_and(|next| !next.is_whitespace() && *next != '\u{2060}')
        {
            set.push('\u{2060}');
        }
    }
    set
}

/// A key a request names, as the person knows it: a `GnuPG` key by its own
/// fingerprint, as `gpg` prints it when it signs, and whose it is; an SSH key
/// as `ssh-add -l` prints it. A keygrip no source offers is said to be one,
/// so it is never taken for a fingerprint.
pub fn key(key: &KeyId, keyrings: Keyrings<'_>) -> String {
    match key {
        KeyId::Grip(grip) => gnupg_key(grip, keyrings),
        KeyId::Ssh(key) => ssh_key(key, keyrings),
    }
}

/// An SSH key as `ssh-add -l` prints it: its type, its SHA-256 fingerprint
/// and the comment its agent gives it, where one listed it. A type OpenSSH
/// does not name is shown as the key itself, which `ssh-add -L` prints.
/// One the workstation's `GnuPG` offers says which of its keys it is.
pub fn ssh_key(key: &SshKey, keyrings: Keyrings<'_>) -> String {
    ssh_key_named(key, keyrings.comment(key), keyrings)
}

/// An SSH key as `ssh-add -l` prints it with `comment`: the one a grant
/// being made lends it with.
pub fn ssh_key_named(key: &SshKey, comment: Option<&Words>, keyrings: Keyrings<'_>) -> String {
    let mut text = ssh_form(key);
    if let Some(comment) = comment {
        let _ = write!(text, " ({comment})");
    }
    if let Some(gnupg) = keyrings.by_ssh(key) {
        let _ = write!(text, ", which GnuPG knows as {}", known(gnupg));
    }
    text
}

/// An SSH key by its type and SHA-256 fingerprint, as `ssh-add -l` prints
/// it without the comment.
fn ssh_form(key: &SshKey) -> String {
    match fingerprint::of(key) {
        Some((kind, printed)) => match kind.strip_suffix("-CERT") {
            Some(certified) => format!("{certified} certificate {printed}"),
            None => format!("{kind} key {printed}"),
        },
        None => format!("the key {key}"),
    }
}

/// A host's key as a request names it: by its type and fingerprint, as
/// `ssh-keygen -l` prints the host's own and a forge publishes its own.
pub fn host_key(key: &SshKey) -> String {
    match fingerprint::of(key) {
        Some((kind, printed)) => format!("{kind} {printed}"),
        None => key.to_string(),
    }
}

/// A `GnuPG` key by the keygrip a request names.
pub fn gnupg_key(grip: &Grip, keyrings: Keyrings<'_>) -> String {
    match (keyrings.by_grip(grip), keyrings.offered) {
        (Some(key), _) => known(key),
        (None, Some(_)) => format!(
            "the key with keygrip {grip}, which is not among the keys this workstation's GnuPG \
             offers"
        ),
        (None, None) => format!("the key with keygrip {grip}"),
    }
}

/// A key a statement can name, as the list to choose from says it: as
/// [`named`] does, with a `GnuPG` key's SSH form beside it.
pub fn listed(name: &KeyName, keyrings: Keyrings<'_>) -> String {
    match name {
        KeyName::Fingerprint(fingerprint) => {
            match keyrings.keys().find(|key| key.fingerprint == *fingerprint) {
                // The SSH form is the primary's own; the subkeys follow the
                // whole, set apart where that form stands between.
                Some(key) if key.fingerprint == key.primary => match key.ssh {
                    Some(_) => format!("{}, and its subkeys", offered(key)),
                    None => format!("{} and its subkeys", offered(key)),
                },
                Some(key) => offered(key),
                None => named(name, keyrings),
            }
        }
        KeyName::Grip(_) | KeyName::Ssh(_) => named(name, keyrings),
    }
}

/// The key a statement names, as the person knows it: a primary key's
/// fingerprint names its subkeys with it, and says so.
pub fn named(name: &KeyName, keyrings: Keyrings<'_>) -> String {
    match name {
        KeyName::Grip(grip) => gnupg_key(grip, keyrings),
        KeyName::Ssh(key) => ssh_key(key, keyrings),
        KeyName::Fingerprint(fingerprint) => {
            match keyrings.keys().find(|key| key.fingerprint == *fingerprint) {
                Some(key) if key.fingerprint == key.primary => {
                    format!("{} and its subkeys", known(key))
                }
                Some(key) => known(key),
                None if keyrings.offered.is_some() => format!(
                    "the key {fingerprint}, which is not among the keys this workstation's \
                     GnuPG offers"
                ),
                None => format!("the key {fingerprint}"),
            }
        }
    }
}

/// What a card asks for before a key on it is used, after the key's name.
fn touch(touch: Option<Touch>) -> &'static str {
    match touch {
        Some(Touch::Off) => "needs no touch",
        Some(Touch::On) => "needs a touch every time",
        Some(Touch::Cached) => "needs a touch, which then covers its uses for a time the card sets",
        None => "is used as the card asks, which Hedwig has not read",
    }
}

/// A card's serial number as `GnuPG`'s prompt for that card prints it, which
/// is how the card is labelled: an `OpenPGP` card's by its maker's number and
/// its own, a `YubiKey`'s own number in groups of three as a `YubiKey` 5 is
/// printed; a standard 20-digit one without the digit that only pads it;
/// any other as the card gives it (`agent/findkey.c`, `prompt_for_card`).
pub fn serial(serial: &Serial) -> String {
    let all = serial.as_str();
    if all.len() == 32
        && all.starts_with("D27600012401")
        && let (Some(maker), Some(own)) = (all.get(16..20), all.get(20..28))
    {
        return match own.parse::<u32>() {
            Ok(number) if maker == "0006" && own.bytes().all(|digit| digit.is_ascii_digit()) => {
                format!(
                    "{} {:03} {:03}",
                    number / 1_000_000,
                    number / 1000 % 1000,
                    number % 1000
                )
            }
            _ => format!("{maker} {own}"),
        };
    }
    match all.strip_suffix('0') {
        Some(padded) if all.len() == 20 => padded.to_owned(),
        _ => all.to_owned(),
    }
}

/// What one card asks before a key on it is used, as the key's clause says
/// it.
fn on(serial: &Serial, asks: Option<Touch>) -> String {
    format!("card {}, where it {}", self::serial(serial), touch(asks))
}

/// What the cards `cards` that can sign with one key ask between them, after
/// each is said: that any of them can sign it, and, where they differ and one
/// asks no touch or did not say, that the key counts as needing none - the
/// model's least of what they ask (`Keys::NeedingNoTouch`).
fn between(cards: &[(&Serial, Option<Touch>)]) -> String {
    let any = if cards.len() == 2 {
        "either can sign it"
    } else {
        "any of them can sign it"
    };
    let asks: Vec<Option<Touch>> = cards.iter().map(|(_, asks)| *asks).collect();
    let differ = asks
        .windows(2)
        .any(|pair| matches!(pair, [one, two] if one != two));
    let least = asks.iter().try_fold(None::<Touch>, |least, asks| {
        let asks = (*asks)?;
        Some(Some(match least {
            Some(least) if least.strictness(&asks).is_le() => least,
            _ => asks,
        }))
    });
    match least {
        Some(Some(Touch::On | Touch::Cached)) => any.to_owned(),
        _ if differ => format!("{any}, so it counts as a key that needs no touch"),
        _ => any.to_owned(),
    }
}

/// Every card a request's key is on and what each asks for before the key
/// is used, and, where it is on several, that any can sign it and how the
/// key counts - never one card for a key on two, and nothing of which card
/// is in, which no read Hedwig may make sees. `None` for a key on no card
/// Hedwig has read or the agent names; an SSH key is named by no card
/// reading.
pub fn on_card(key: &KeyId, keyrings: Keyrings<'_>) -> Option<String> {
    let KeyId::Grip(grip) = key else {
        return None;
    };
    let cards = keyrings.cards(grip);
    let said: Vec<String> = cards
        .iter()
        .map(|(serial, asks)| on(serial, *asks))
        .collect();
    match said.as_slice() {
        [] => None,
        [one] => Some(one.clone()),
        _ => Some(format!("{}: {}", said.join(", or "), between(&cards))),
    }
}

/// What a card asks for before each key on it is used, and what that costs
/// the person: both halves, because a key that needs a touch cannot sign
/// while the person is away from this machine. A key also on another card
/// says so, with what that card asks and how the key counts.
pub fn card(card: &Card, keyrings: Keyrings<'_>) -> String {
    // Each key by itself: a primary here is the key the card holds, not its
    // subkeys, and one no keyring offers is a card's key the stub does not
    // name.
    let keys: Vec<String> = card
        .keys
        .iter()
        .map(|held| {
            let name = keyrings
                .by_grip(&held.grip)
                .map_or_else(|| format!("the key with keygrip {}", held.grip), known);
            let mut text = format!("{name} {}", touch(held.touch));
            let cards = keyrings.cards(&held.grip);
            let elsewhere: Vec<String> = cards
                .iter()
                .filter(|(serial, _)| **serial != card.serial)
                .map(|(serial, asks)| on(serial, *asks))
                .collect();
            if !elsewhere.is_empty() {
                let _ = write!(
                    text,
                    ", and is also on {}: {}",
                    elsewhere.join(", and "),
                    between(&cards)
                );
            }
            text
        })
        .collect();
    let mut text = if keys.is_empty() {
        format!(
            "Card {} holds no key Hedwig could read",
            serial(&card.serial)
        )
    } else {
        format!("On card {}, {}", serial(&card.serial), keys.join("; "))
    };
    if card.pin == Some(SignaturePin::Once) {
        text.push_str("; the PIN is asked once, not for each signature");
    }
    if card.leaves_use_unobserved() {
        text.push_str(
            ". A remote you grant can then use a key that needs no touch with nobody at the \
             card, and Hedwig's own asking is the only check. With touch required, you cannot \
             sign while you are away from this machine",
        );
    }
    if card.keys.iter().all(|held| held.touch.is_none()) && !card.keys.is_empty() {
        text.push_str(
            ". Hedwig reads what a card asks for only from the card GnuPG reaches first, in its \
             OpenPGP application, so as never to switch your card",
        );
    }
    text
}

/// What a remote asks to do, as the verb that follows "asks to".
pub fn operation(operation: Operation) -> &'static str {
    match operation {
        Operation::Connect => "use",
        Operation::Authenticate => "log in with",
        Operation::Sign => "sign with",
        Operation::Decrypt => "decrypt with",
        Operation::Open => "open a page in",
    }
}

/// What a remote asks to do, on its own.
pub fn verb(operation: Operation) -> &'static str {
    match operation {
        Operation::Connect => "connect",
        Operation::Authenticate => "log in",
        Operation::Sign => "sign",
        Operation::Decrypt => "decrypt",
        Operation::Open => "open a page",
    }
}

/// What a remote did, as the verb that follows its name.
pub fn did(operation: Operation) -> &'static str {
    match operation {
        Operation::Connect => "used",
        Operation::Authenticate => "logged in with",
        Operation::Sign => "signed with",
        Operation::Decrypt => "decrypted with",
        Operation::Open => "opened a page in",
    }
}

/// What the workstation's browser was given, as the remote's activity says
/// it: the site, never the URL, and the port carried for the sign-in's
/// answer.
pub fn browsed(site: &hedwig_model::site::Site, callback: Option<Port>) -> String {
    match callback {
        Some(port) => format!(
            "your browser opened {site}, its answer carried back to port {port} on the remote"
        ),
        None => format!("your browser opened {site}"),
    }
}

/// Why a sign-in's port stopped being carried.
pub fn uncarried(end: Carry) -> &'static str {
    match end {
        Carry::Called => {
            "the sign-in's answer reached the remote, and its port is no longer carried"
        }
        Carry::Expired => {
            "the sign-in took longer than Hedwig carries its port, which is no longer carried"
        }
        Carry::Ended => "the connection ended, and the sign-in's port is no longer carried",
    }
}

/// The sentence a request is announced with.
pub fn asks(remote: &RemoteId, capability: &Name, asked: Operation) -> String {
    format!("{remote} asks to {} {capability}", operation(asked))
}

/// What an answer that allows for a time lets through. An allowance covers
/// the key the request named and no other, so the sentence names it.
pub fn allowance(
    capability: &Name,
    asked: Operation,
    key: Option<&KeyId>,
    keyrings: Keyrings<'_>,
) -> String {
    let with = key
        .map(|key| format!(" with {}", self::key(key, keyrings)))
        .unwrap_or_default();
    format!(
        "For that time, every request to {} {capability}{with} on this connection is served \
         without asking you.",
        operation(asked)
    )
}

/// A request served without asking, as it is announced.
pub fn served(served: &Served, keyrings: Keyrings<'_>) -> String {
    let mut text = format!(
        "{} {} {}",
        served.remote,
        did(served.operation),
        served.capability
    );
    if let Some(key) = &served.key {
        let keyrings = keyrings.of_capability(&served.remote, &served.capability);
        let _ = write!(text, ", {}", self::key(key, keyrings));
    }
    if let Some(payload) = &served.payload {
        let _ = write!(text, ", for {}", self::payload(payload));
    }
    text
}

/// A length of time as the person would say it.
pub fn length(seconds: NonZeroU32) -> String {
    let seconds = seconds.get();
    let (number, one, many) = if seconds.is_multiple_of(3600) {
        (seconds / 3600, "hour", "hours")
    } else if seconds.is_multiple_of(60) {
        (seconds / 60, "minute", "minutes")
    } else {
        (seconds, "second", "seconds")
    };
    if number == 1 {
        format!("1 {one}")
    } else {
        format!("{number} {many}")
    }
}

/// Whose statements the organisation makes, as the subject of a sentence.
pub fn audience(audience: Audience) -> &'static str {
    match audience {
        Audience::Machine => "your organisation's policy for this machine",
        Audience::Person => "your organisation's policy for you",
    }
}

/// One place of the organisation's policy.
pub fn place(place: Place) -> String {
    let whom = match place.audience {
        Audience::Machine => "this machine",
        Audience::Person => "you",
    };
    match place.part {
        Part::Limits => format!("your organisation's limits for {whom}"),
        Part::Start => format!("your organisation's starting point for {whom}"),
        Part::Ask => format!("whom your organisation says to ask, for {whom}"),
    }
}

/// The audience a refusal names, where it is the organisation's.
pub fn refused_by(refusal: &Refusal) -> Option<Audience> {
    match refusal {
        Refusal::Held { audience, .. } | Refusal::Unread(audience) => Some(*audience),
        _ => None,
    }
}

/// Whom to ask about what the organisation holds for `audience`, in its own
/// words; `None` where it named nobody.
pub fn ask(contacts: &[Contact], audience: Audience) -> Option<&Words> {
    contacts
        .iter()
        .find(|contact| contact.audience == audience)
        .map(|contact| &contact.words)
}

/// A refusal as the person reads it, with whom to ask where the refusal is
/// the organisation's and it named someone.
pub fn refusal(refusal: &Refusal, contacts: &[Contact]) -> String {
    let mut text = refusal.to_string();
    if let Some(words) = refused_by(refusal).and_then(|audience| ask(contacts, audience)) {
        let _ = write!(text, ". Whom to ask: {words}");
    }
    text
}

fn keys(keys: &Keys, keyrings: Keyrings<'_>) -> String {
    match keys {
        Keys::Every => String::new(),
        Keys::NeedingNoTouch => ", with a key that needs no touch".to_owned(),
        Keys::Only(name) => format!(", with {}", named(name, keyrings)),
    }
}

/// A cap on allowances, with whose it is and what it covers.
pub fn capped(capped: &Capped, keyrings: Keyrings<'_>) -> String {
    let what = format!(
        "{}{}",
        remotes(&capped.scope.remotes),
        keys(&capped.scope.key, keyrings)
    );
    match (capped.holder, capped.longest) {
        (Holder::Organisation(whose), Longest::Nothing) => {
            format!("{} allows nothing for a time for {what}", audience(whose))
        }
        (Holder::Organisation(whose), Longest::Seconds(seconds)) => format!(
            "{} caps an allowance at {} for {what}",
            audience(whose),
            length(seconds)
        ),
        (Holder::Person, Longest::Nothing) => format!("you allow nothing for a time for {what}"),
        (Holder::Person, Longest::Seconds(seconds)) => {
            format!("you cap an allowance at {} for {what}", length(seconds))
        }
    }
}

/// A limit that holds a value, with whose it is. The organisation's are
/// worded as the model words the refusal each gives; the person holds only
/// caps on what they can loosen in one gesture.
pub fn holding(holding: &Holding, keyrings: Keyrings<'_>) -> String {
    match (holding.holder, &holding.limit) {
        (Holder::Organisation(whose), limit) => Refusal::Held {
            audience: whose,
            limit: Box::new(limit.clone()),
        }
        .to_string(),
        (Holder::Person, Limit::Cap { scope, longest }) => capped(
            &Capped {
                longest: *longest,
                holder: Holder::Person,
                scope: scope.clone(),
            },
            keyrings,
        ),
        (Holder::Person, _) => "a limit you set".to_owned(),
    }
}

/// What a channel's client wants of the person.
pub fn prompt(kind: PromptKind) -> &'static str {
    match kind {
        PromptKind::UnknownHostKey => "a host key to confirm",
        PromptKind::KeyPassphrase => "the passphrase of a key",
        PromptKind::Password => "a password",
        PromptKind::SecurityKeyPin => "the PIN of a security key",
        PromptKind::Challenge => "an answer to the server's challenge",
        PromptKind::AgentConfirmation => "your confirmation to use a key",
        PromptKind::SecurityKeyTouch => "a touch of a security key",
    }
}

/// What readiness found that does, or does not, keep the capability off the
/// channel, each in the model's own words.
fn findings(found: &[Finding], blocking: bool) -> String {
    found
        .iter()
        .filter(|finding| finding.blocks() == blocking)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// What Hedwig wrote on a remote, where it went, and what it made for it -
/// the outermost folder, or for a key the keybox its import made - which goes
/// when the write is taken back.
pub fn written(written: &Written) -> String {
    let place = &written.place;
    let mut text = match &written.write {
        Write::NoAutostart => format!("no-autostart in {place}"),
        Write::PublicKey(key) => format!("the public key {key}, in the keyring at {place}"),
        Write::SigningKey(key) => format!("{key} as git's signing key, in {place}"),
        Write::Variable(variable) => format!("{variable} in {place}"),
        Write::SocketFile => format!("the socket file {place}"),
        Write::Masked => format!("a mask on the remote's own service unit, at {place}"),
        Write::Helper => format!(
            "git's own credential cache helper at Hedwig's socket, in {place}, after your own \
             helpers"
        ),
    };
    if let Some(made) = &written.made {
        let _ = match &written.write {
            Write::PublicKey(_) if *made == *place => {
                write!(text, ", a keyring Hedwig made for it")
            }
            Write::PublicKey(_) => write!(text, ", and {made}, a keyring Hedwig made for it"),
            _ => write!(text, ", in {made}, a folder Hedwig made for it"),
        };
    }
    text
}

/// Where a reverse a remote asked for lands, as the person would say it.
pub fn target(target: &Target) -> String {
    match target {
        Target::Loopback(port) => format!("port {port} on the remote"),
        Target::Host { host, port } => format!("{host} port {port}, as the remote resolves it"),
        Target::Path(path) => format!("the socket {path} on the remote"),
    }
}

/// What a capability began carrying on to the remote, as its activity says.
pub fn carried(capability: &Name, carriage: &Carriage) -> String {
    match carriage {
        Carriage::Reverse(to) => format!(
            "{capability} carries a reverse on: a device's connections to it reach {}",
            target(to)
        ),
        Carriage::Forward {
            port,
            device,
            socket,
        } => format!(
            "{capability} carries a forward on: port {port} on the remote reaches {socket} on \
             {device}"
        ),
        Carriage::Console { port, device } => {
            format!("{capability} carries the console of {device} on, at port {port} on the remote")
        }
    }
}

/// What a capability stopped carrying on to the remote, and why.
pub fn dropped(capability: &Name, carriage: &Carriage, why: Dropped) -> String {
    let (what, device, port) = match carriage {
        Carriage::Reverse(to) => (format!("the reverse to {}", target(to)), None, None),
        Carriage::Forward { port, device, .. } => (
            format!("the forward from port {port} on the remote"),
            Some(device),
            Some(*port),
        ),
        Carriage::Console { port, device } => (
            format!("the console of {device}"),
            Some(device),
            Some(*port),
        ),
    };
    let why = match (why, device, port) {
        (Dropped::Removed, ..) => "the remote removed it".to_owned(),
        (Dropped::Gone, Some(device), _) => {
            format!("{device} left the workstation's ADB server")
        }
        (Dropped::Unlent, Some(device), _) => format!("{device} is no longer lent to the remote"),
        (Dropped::Taken, _, Some(port)) => {
            format!("something on the remote took port {port} while the connection was away")
        }
        (Dropped::Gone, ..) => "its device left the workstation's ADB server".to_owned(),
        (Dropped::Unlent, ..) => "its device is no longer lent to the remote".to_owned(),
        (Dropped::Taken, ..) => {
            "something on the remote took its place while the connection was away".to_owned()
        }
    };
    format!("{capability} stopped carrying {what}: {why}")
}

/// What a capability carries on to the remote now, as its line says it: for
/// a reverse or a forward, with the port the workstation's own
/// `adb reverse --list` or `adb forward --list` shows for it.
pub fn carried_on(carried: &CarriedOn) -> String {
    let endpoint = carried.endpoint;
    match &carried.carriage {
        Carriage::Reverse(to) => format!(
            "A device's connections reach {}, which adb reverse --list on this workstation \
             shows as tcp:{endpoint}",
            target(to)
        ),
        Carriage::Forward {
            port,
            device,
            socket,
        } => format!(
            "Port {port} on the remote reaches {socket} on {device}, which adb forward --list on \
             this workstation shows as tcp:{endpoint}"
        ),
        Carriage::Console { port, device } => {
            format!("The console of {device} answers at port {port} on the remote")
        }
    }
}

/// What a capability carries on to the remote, as a glance says it: where
/// each lands there, without the workstation's ports.
pub fn carriage(carriage: &Carriage) -> String {
    match carriage {
        Carriage::Reverse(to) => format!("a device's connections reach {}", target(to)),
        Carriage::Forward {
            port,
            device,
            socket,
        } => format!("port {port} reaches {socket} on {device}"),
        Carriage::Console { port, device } => format!("the console of {device} at port {port}"),
    }
}

/// A device as the person knows it: its model where it reports one, its
/// serial, how it reaches the workstation, and a state that keeps it from
/// being used.
pub fn device(device: &Lendable) -> String {
    let serial = device.serial.as_ref().map(ToString::to_string);
    let mut text = match (&device.model, &serial) {
        (Some(model), Some(serial)) => format!("{model} ({serial})"),
        (Some(model), None) => format!("{model}, which the server lists with no serial"),
        (None, Some(serial)) => serial.clone(),
        (None, None) => "a device the server lists with no serial".to_owned(),
    };
    let emulator = serial
        .as_deref()
        .is_some_and(|serial| serial.starts_with("emulator-"));
    text.push_str(match (device.attached, emulator) {
        (Attachment::Usb, _) => ", by USB",
        (Attachment::Socket, true) => ", an emulator",
        (Attachment::Socket, false) => ", connected by its address",
    });
    if let Some(state) = state(device.state) {
        let _ = write!(text, ", {state}");
    }
    text
}

/// What a device's state means for using it; `None` where it is ready.
fn state(state: DeviceState) -> Option<String> {
    Some(match state {
        DeviceState::Device => return None,
        DeviceState::Connecting => "connecting".to_owned(),
        DeviceState::Authorizing => "being authorised".to_owned(),
        DeviceState::Unauthorized => {
            "waiting for you to allow USB debugging on the device".to_owned()
        }
        DeviceState::NoPermission => {
            "which the ADB server has no permission to open on this workstation".to_owned()
        }
        DeviceState::Detached => "detached from the ADB server".to_owned(),
        DeviceState::Offline => "offline".to_owned(),
        DeviceState::Bootloader => "in its bootloader".to_owned(),
        DeviceState::Host => "a host".to_owned(),
        DeviceState::Recovery => "in recovery".to_owned(),
        DeviceState::Sideload => "sideloading".to_owned(),
        DeviceState::Rescue => "in rescue".to_owned(),
        DeviceState::Other(number) => {
            format!("in a state Hedwig does not know, which the server numbers {number}")
        }
    })
}

/// A lent device by its serial, said with its model where the server's
/// listing names it.
pub fn lent(serial: &DeviceSerial, listed: &[Lendable]) -> String {
    listed
        .iter()
        .find(|device| device.serial.as_ref() == Some(serial))
        .and_then(|device| device.model.as_ref())
        .map_or_else(|| serial.to_string(), |model| format!("{model} ({serial})"))
}

/// The devices a grant names, each once.
pub fn devices(lends: &Lends) -> impl Iterator<Item = &DeviceSerial> {
    let named = match lends {
        Lends::Named { devices, .. } => Some(devices),
        Lends::Every => None,
    };
    named.into_iter().flatten()
}

/// What a grant lends of a server's devices, as a sentence's predicate.
pub fn lends(lends: &Lends, listed: &[Lendable]) -> String {
    let named: Vec<&DeviceSerial> = devices(lends).collect();
    match lends {
        Lends::Every => {
            "lends every device the workstation's ADB server holds, now and later".to_owned()
        }
        Lends::Named { .. } if named.is_empty() => {
            "lends no device: the remote sees none until you lend one".to_owned()
        }
        // In the server's order, as the list beside it reads, then those it
        // does not hold now.
        Lends::Named { .. } => {
            let held = listed
                .iter()
                .filter_map(|device| device.serial.as_ref())
                .filter(|serial| named.contains(serial));
            let away = named.iter().copied().filter(|serial| {
                !listed
                    .iter()
                    .any(|device| device.serial.as_ref() == Some(*serial))
            });
            format!(
                "lends {}",
                held.chain(away)
                    .map(|serial| lent(serial, listed))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

/// Where a lent key may be used, after the key's name.
pub fn toward(toward: &Toward) -> String {
    match toward {
        Toward::Anywhere => "for logging in to any host, and for signing".to_owned(),
        Toward::Hosts(hosts) if hosts.is_empty() => {
            "for nothing: no host is named for it to log in to".to_owned()
        }
        Toward::Hosts(hosts) => format!(
            "only for logging in to {} {}, and for nothing else",
            if hosts.len() == 1 {
                "the host whose key is"
            } else {
                "the hosts whose keys are"
            },
            hosts.iter().map(host_key).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// What a grant lends of an agent's keys, as a sentence's predicate: each
/// key and where it may be used.
pub fn lends_keys(lends: &Lends, keyrings: Keyrings<'_>) -> String {
    match lends {
        Lends::Every => "lends every key the agent holds, now and later, for anything".to_owned(),
        Lends::Named { .. } if lends.keys().next().is_none() => {
            "lends no key: the remote is told of none until you lend one".to_owned()
        }
        Lends::Named { .. } => format!(
            "lends {}",
            lends
                .keys()
                .map(|(key, lent)| {
                    format!("{} {}", ssh_key(key, keyrings), toward(&lent.toward))
                })
                .collect::<Vec<_>>()
                .join("; ")
        ),
    }
}

/// What lending a key lets the remotes it is lent to do with it.
pub fn lending_key(whom: &str, what: &str) -> String {
    format!(
        "{whom} can then log in to any host with {what} and sign with it - a commit, a tag, a \
         file - each as you set for that remote."
    )
}

/// What a remote's agent request asks to have signed, as the request's own
/// account: a login, as which user and to which host, or a signature, in
/// which namespace.
pub fn payload(payload: &Payload) -> String {
    match payload {
        Payload::Authentication { user, host } => {
            let mut text = match user {
                Some(user) => format!("a login as {user}"),
                None => "a login as a user that is not words".to_owned(),
            };
            match host {
                Some(host) => {
                    let _ = write!(text, " to the host whose key is {}", host_key(host));
                }
                None => text.push_str(" to a host it does not name"),
            }
            text
        }
        Payload::Signature {
            namespace: Some(namespace),
        } if namespace.as_str() == "git" => {
            "a signature in git's namespace, as git makes for a commit or a tag".to_owned()
        }
        Payload::Signature {
            namespace: Some(namespace),
        } => format!("a signature in the namespace {namespace}"),
        Payload::Signature { namespace: None } => {
            "a signature in a namespace that is not words".to_owned()
        }
        Payload::Unread => "data that is neither a login nor a signature OpenSSH makes".to_owned(),
        Payload::Credential { site } => format!("your credential for {site}"),
    }
}

/// What answers for `capability` on this workstation, in the model's one
/// sentence for the holder; the sentence begins with the capability's name.
pub fn answered(capability: &Name, holder: &SourceHolder) -> String {
    format!("{capability} is answered by {holder}")
}

/// What the core last read of `capability`'s own side on this workstation.
pub fn found<'a>(workstation: Option<&'a Workstation>, capability: &Name) -> Option<&'a Found> {
    workstation?
        .sources
        .iter()
        .find(|found| found.capability == *capability)
}

/// What the person can do about a refusal of `capability` for `failure`,
/// `source` being what it is defined as: the source's own tool, behind "if
/// it is yours", after what answers for it where that was read, so the
/// person can judge whether it is theirs. `None` where no act of the
/// person's own mends it (`Remedy::of`).
pub fn mend(
    capability: &Name,
    source: &Source,
    failure: Failure,
    holder: Option<&SourceHolder>,
) -> Option<String> {
    let remedy = capitalised(Remedy::of(source, failure)?.to_string());
    Some(match holder {
        Some(holder) => format!("{}. {remedy}", answered(capability, holder)),
        None => remedy,
    })
}

/// A capability's own side on this workstation as the core last read it,
/// each sentence as shown: whether its source answers, else the model's
/// refusal for it; what answers for it; and, where Hedwig will not carry a
/// remote's connection to a program that may be the person's, what they can
/// do about it. `source` is what the capability is defined as, where known.
/// A source not yet tried in this run is said by what holds it alone.
pub fn answers(found: &Found, source: Option<&Source>) -> Vec<String> {
    let capability = &found.capability;
    let holder = found.holder.as_ref();
    let failure = match found.health {
        Some(Health::Sound) => {
            return vec![match holder {
                Some(holder) => format!("{capability} answers on this workstation: {holder}."),
                None => format!("{capability} answers on this workstation."),
            }];
        }
        None => {
            return holder
                .map(|holder| format!("{}.", answered(capability, holder)))
                .into_iter()
                .collect();
        }
        Some(Health::Failing(failure)) => failure,
    };
    let refused = Refusal::SourceUnavailable {
        capability: capability.clone(),
        failure,
    };
    let mut said = vec![format!("{}.", begun(refused.to_string(), capability))];
    match source.and_then(|source| mend(capability, source, failure, holder)) {
        Some(mended) => said.push(format!("{mended}.")),
        None => said.extend(holder.map(|holder| format!("{}.", answered(capability, holder)))),
    }
    said
}

/// The same for a refusal of reading a source - its devices or an agent's
/// keys - where it is the source failing.
pub fn mended(
    refusal: &Refusal,
    source: &Source,
    workstation: Option<&Workstation>,
) -> Option<String> {
    let Refusal::SourceUnavailable {
        capability,
        failure,
    } = refusal
    else {
        return None;
    };
    let holder = found(workstation, capability).and_then(|found| found.holder.as_ref());
    mend(capability, source, *failure, holder)
}

/// What an agent's own prompts cannot say, which Hedwig's decision per
/// remote stands in for.
pub const AGENT_ASKS: &str = "Your agent's own prompts - a password manager's approval, a \
     passphrase, a security key's touch - name Hedwig, never the remote, and what your agent \
     remembers of one covers every remote Hedwig carries to it. Hedwig's decision for each \
     remote stands in its place: it asks you first, or shows you, as you set for that remote.";

/// What lending a device lets the remotes it is lent to do with it.
pub fn lending(whom: &str, what: &str) -> String {
    format!(
        "{whom} can then see {what} and use it as a device attached there: install and run \
         apps, open a shell, read and write its files and its logs."
    )
}

/// A USB device as Windows' hardware identifiers and `lsusb` show it, by its
/// vendor and product.
pub fn usb(usb: Usb) -> String {
    format!("the USB device {:04X}:{:04X}", usb.vendor, usb.product)
}

/// A serial port as the person picks it: the name Windows shows for it,
/// which holds the port's own, and the USB device behind it.
pub fn serial_port(serial: &SerialPort) -> String {
    let port = serial.port.as_str();
    let mut text = match &serial.name {
        Some(name)
            if name
                .as_str()
                .to_ascii_uppercase()
                .contains(&port.to_ascii_uppercase()) =>
        {
            name.to_string()
        }
        Some(name) => format!("{name} ({port})"),
        None => port.to_owned(),
    };
    if let Some(device) = serial.usb {
        let _ = write!(text, ", {}", usb(device));
    }
    text
}

/// What a remote's tool cannot be given, why, and what would change it.
pub fn beyond(beyond: Beyond) -> String {
    let mut text = capitalised(beyond.to_string());
    let _ = write!(
        text,
        ". What would change it: {}.",
        beyond.reopens().join("; or ")
    );
    text
}

/// The address the remote's tools open a serial capability at, where how a
/// request of it is decided is not known here: a `Confirm` rule holds the
/// opening for the person, and pyserial gives up after three seconds as its
/// URL ships.
pub fn rfc2217(remote: Port) -> String {
    format!(
        "The remote's esptool, PlatformIO and pyserial tools open it at \
         rfc2217://127.0.0.1:{remote}; where Hedwig asks you first, at \
         rfc2217://127.0.0.1:{remote}?timeout=<seconds>, the seconds a tool there waits for \
         your answer, since pyserial gives up after three"
    )
}

/// The address the remote's tools open a serial capability at, where its
/// opening is decided in `mode`.
pub fn rfc2217_in(remote: Port, mode: Mode) -> String {
    match mode {
        Mode::Confirm => format!(
            "Hedwig asks you first here, so the remote's tools open it at \
             rfc2217://127.0.0.1:{remote}?timeout=<seconds>, the seconds they wait for your \
             answer: pyserial gives up after three as it ships"
        ),
        Mode::Notify | Mode::Unattended => format!(
            "The remote's esptool, PlatformIO and pyserial tools open it at \
             rfc2217://127.0.0.1:{remote}"
        ),
    }
}

/// A serial port a remote's connection holds, from when, as `clock` writes
/// a time.
pub fn hold(hold: &Hold, remote: &RemoteId, since: &str) -> String {
    format!(
        "{} is held for a connection from {remote} since {since}: no other program on this \
         workstation, and no other connection, can open it until that one ends",
        hold.port
    )
}

/// A serial port a connection took, as the remote's activity says it.
pub fn taken(capability: &Name, port: &PortName, over: Option<Usb>) -> String {
    match over {
        Some(device) => format!(
            "{capability} opened {port}, over {}, for that connection alone",
            usb(device)
        ),
        None => format!("{capability} opened {port} for that connection alone"),
    }
}

/// A serial port given back, as the remote's activity says it.
pub fn released(capability: &Name, port: &PortName) -> String {
    format!("{capability} closed {port}: its connection ended, and the port is free again")
}

/// The capability a refusal is about, where it names one: a refusal of a
/// remote's request lands on that capability's line.
pub fn about(refusal: &Refusal) -> Option<&Name> {
    match refusal {
        Refusal::UnknownCapability(capability)
        | Refusal::Reserved(capability)
        | Refusal::CapabilityInUse(capability)
        | Refusal::CapabilityIncomplete { capability, .. }
        | Refusal::ExposureNotAcknowledged { capability, .. }
        | Refusal::Unlendable { capability, .. }
        | Refusal::OperationNotInDialect { capability, .. }
        | Refusal::NoCarrier { capability, .. }
        | Refusal::NeedsRemoteSetup { capability, .. }
        | Refusal::SourceUnavailable { capability, .. }
        | Refusal::NotGranted { capability, .. }
        | Refusal::OffProtocol { capability, .. }
        | Refusal::Withheld { capability, .. }
        | Refusal::UnlistedSite { capability, .. }
        | Refusal::Unopenable { capability, .. }
        | Refusal::CallbackHeld { capability, .. }
        | Refusal::Shared { capability, .. }
        | Refusal::PortHeld { capability, .. }
        | Refusal::UnlistedCredential { capability, .. }
        | Refusal::NotWeb { capability, .. }
        | Refusal::Cleartext { capability, .. }
        | Refusal::Hushed { capability } => Some(capability),
        Refusal::Version { .. }
        | Refusal::NotGreeted
        | Refusal::NotAttending
        | Refusal::NoIcon
        | Refusal::Withdrawn
        | Refusal::Malformed(_)
        | Refusal::UnknownRoute(_)
        | Refusal::UnknownSet(_)
        | Refusal::UnknownPlatform(_)
        | Refusal::UnknownKernel(_)
        | Refusal::KernelClaimed { .. }
        | Refusal::UnknownConnection(_)
        | Refusal::UnknownRequest(_)
        | Refusal::UnknownPrompt(_)
        | Refusal::AnswerUnfit { .. }
        | Refusal::RouteInUse(_)
        | Refusal::SetInUse(_)
        | Refusal::ActivationNeedsDiscovery { .. }
        | Refusal::Unlisted(_)
        | Refusal::Repeated(_)
        | Refusal::Collides { .. }
        | Refusal::NotOffered { .. }
        | Refusal::DocumentVersion { .. }
        | Refusal::NoUnixSockets { .. }
        | Refusal::PlatformUnobserved(_)
        | Refusal::NotConnected(_)
        | Refusal::SocketPathTooLong { .. }
        | Refusal::Paused
        | Refusal::NobodyReachable(_)
        | Refusal::Declined
        | Refusal::NoChannel { .. }
        | Refusal::Unattributable
        | Refusal::Unissued
        | Refusal::Held { .. }
        | Refusal::Unread(_)
        | Refusal::KeyExists(_)
        | Refusal::KindUnmade(_)
        | Refusal::NoTpm
        | Refusal::KeyAbsent(_) => None,
    }
}

/// What `remote` was refused of `capability` and how often, each while it
/// still needs the person: the line's own account of the relay's door.
pub fn refused_of<'a>(
    attention: &'a [Needs],
    remote: &'a RemoteId,
    capability: &'a Name,
) -> impl Iterator<Item = String> + 'a {
    attention
        .iter()
        .filter_map(move |needs| match &needs.attention {
            Attention::Refused {
                remote: Some(refused),
                refusal,
                times: count,
            } if refused == remote && about(refusal) == Some(capability) => {
                Some(format!("{refusal}, {}", times(*count)))
            }
            _ => None,
        })
}

/// What a test of `capability` found: whether the remote's own tool reached
/// this workstation through Hedwig, and where it did not, why.
pub fn proof(proof: &Proof, capability: &Name) -> String {
    match proof {
        Proof::Reached(_) => format!(
            "Tested: the remote's own tool reached {capability} on this workstation through \
             Hedwig."
        ),
        Proof::Silent(Some(said)) => format!(
            "Tested: the remote's own tool ran, and nothing reached this workstation. Its last \
             words: {said}"
        ),
        Proof::Silent(None) => "Tested: the remote's own tool ran, and nothing reached this \
                                workstation; it said nothing."
            .to_owned(),
        Proof::Unrun(finding) => format!("Not tested: {finding}"),
    }
}

/// When a returning channel is opened again, `left` from now, and how long
/// those words stay true; `None` once it is due. Rounded up, so the person is
/// never told sooner than the core opens it.
pub fn again(left: Duration) -> Option<(String, Duration)> {
    let seconds = left.as_secs() + u64::from(left.subsec_nanos() > 0);
    if seconds == 0 {
        return None;
    }
    // The whole seconds the words stand for until they change.
    let (said, until) = if seconds < 60 {
        (plural(seconds, "second", "seconds"), seconds - 1)
    } else {
        let minutes = seconds.div_ceil(60);
        let said = if minutes < 60 {
            plural(minutes, "minute", "minutes")
        } else if minutes.is_multiple_of(60) {
            plural(minutes / 60, "hour", "hours")
        } else {
            format!(
                "{} {}",
                plural(minutes / 60, "hour", "hours"),
                plural(minutes % 60, "minute", "minutes")
            )
        };
        (said, if minutes == 1 { 59 } else { (minutes - 1) * 60 })
    };
    Some((
        format!("in {said}"),
        left.saturating_sub(Duration::from_secs(until)),
    ))
}

fn plural(number: u64, one: &str, many: &str) -> String {
    if number == 1 {
        format!("1 {one}")
    } else {
        format!("{number} {many}")
    }
}

/// Why a channel is no longer up.
pub fn end(end: &ChannelEnd) -> String {
    match end {
        ChannelEnd::Closed => "you closed it".to_owned(),
        ChannelEnd::RemoteGone => "the remote stopped".to_owned(),
        ChannelEnd::Needs(kind) => {
            format!("it needed {} and nothing could reach you", prompt(*kind))
        }
        ChannelEnd::Declined(kind) => {
            format!("you declined when it asked for {}", prompt(*kind))
        }
        ChannelEnd::Unauthenticated(methods) => format!(
            "the server accepted no way to sign in without asking you; it would still take: \
             {methods}"
        ),
        ChannelEnd::HostKeyChanged(mark) => {
            format!("the host presented a key it did not have before, {mark}")
        }
        ChannelEnd::ForwardRefused => "the remote's SSH server refused the forward".to_owned(),
        ChannelEnd::RouteNotSignedIn => "the route's own client is not signed in".to_owned(),
        ChannelEnd::ClientAbsent => {
            "the route's client was not found in any folder on the search path".to_owned()
        }
        ChannelEnd::Unstarted(account) => {
            format!("the route's client could not be started: {account}")
        }
        ChannelEnd::Exited { status, last } => match last {
            Some(last) => format!(
                "the connection's client ended by itself, with status {status}. Its last words: \
                 {last}"
            ),
            None => format!("the connection's client ended by itself, with status {status}"),
        },
        ChannelEnd::NothingCarried => {
            "nothing it was granted can be carried to that remote".to_owned()
        }
        ChannelEnd::Slept => "the workstation went to sleep".to_owned(),
        ChannelEnd::Reshaped => "what it carries changed".to_owned(),
    }
}

pub fn binding(binding: &Binding) -> String {
    match binding {
        Binding::Socket(path) => format!("the socket {path}"),
        Binding::SocketFile { file, port } => format!("port {port}, named in {file}"),
        Binding::Port(port) => format!("port {port}"),
    }
}

/// Where a row stands, as the row's own line. `left` is how long until a
/// returning channel is opened again, counted down from the reply that said.
pub fn standing(standing: &Standing, left: Option<Duration>) -> String {
    match standing {
        Standing::Idle => "not connected".to_owned(),
        Standing::Checking => "checking the remote".to_owned(),
        Standing::Opening => "connecting".to_owned(),
        Standing::Needs(kind) => format!("waiting for {}", prompt(*kind)),
        Standing::Unready(found) => format!("not ready: {}", findings(found, true)),
        Standing::Serving(bound) => format!("reachable there at {}", binding(bound)),
        Standing::Unavailable(refusal) => format!("cannot be served: {refusal}"),
        Standing::Paused => "paused".to_owned(),
        Standing::Returning { end: ended, .. } => match left.and_then(again) {
            Some((when, _)) => format!("connecting again by itself {when}: {}", end(ended)),
            None => format!("connecting again by itself: {}", end(ended)),
        },
        Standing::Ended(ended) => format!("stopped: {}", end(ended)),
    }
}

/// Where a row stands, with whom to ask where the organisation's policy is
/// what keeps it from being served.
pub fn stands(standing: &Standing, left: Option<Duration>, contacts: &[Contact]) -> String {
    let mut text = self::standing(standing, left);
    if let Standing::Unavailable(refused) = standing
        && let Some(asked) = refused_by(refused).and_then(|whose| ask(contacts, whose))
    {
        let _ = write!(text, ". Whom to ask: {asked}");
    }
    text
}

/// What the core does with a request in this mode.
pub fn mode(mode: Mode) -> &'static str {
    match mode {
        Mode::Unattended => "served without asking, even while nothing can reach you",
        Mode::Notify => "served and shown to you",
        Mode::Confirm => "held until you answer",
    }
}

/// The mode as a choice the person makes.
pub fn choose(mode: Mode) -> &'static str {
    match mode {
        Mode::Unattended => "Serve even while I am away",
        Mode::Notify => "Serve and show me",
        Mode::Confirm => "Ask me first",
    }
}

fn selected<T>(selector: &Selector<T>, every: &str, only: impl FnOnce(&T) -> String) -> String {
    match selector {
        Selector::Every => every.to_owned(),
        Selector::Only(only_this) => only(only_this),
    }
}

pub fn remotes(remotes: &Remotes) -> String {
    match remotes {
        Remotes::Every => "every remote".to_owned(),
        Remotes::Route(route) => format!("every remote on {route}"),
        Remotes::Matching { route, pattern } => format!("{pattern} on {route}"),
        Remotes::Set(set) => format!("the remotes in {set}"),
        Remotes::One(remote) => remote.to_string(),
    }
}

pub fn granted(granted: &Granted) -> String {
    remotes(&Remotes::from(granted.clone()))
}

/// A grant as the person made it: what, to where.
pub fn grant(grant: &Grant) -> String {
    format!("{} to {}", grant.capability, granted(&grant.remotes))
}

fn scope(
    capability: &Selector<Name>,
    asked: Selector<Operation>,
    key: &Keys,
    keyrings: Keyrings<'_>,
) -> String {
    let what = selected(capability, "everything", ToString::to_string);
    let when = selected(&asked, "whatever it asks", |asked| {
        format!("when it asks to {}", verb(*asked))
    });
    format!("{what}, {when}{}", keys(key, keyrings))
}

fn statement(rule: &RuleScope, keyrings: Keyrings<'_>) -> String {
    format!(
        "{}: {}",
        remotes(&rule.remotes),
        scope(&rule.capability, rule.operation, &rule.key, keyrings)
    )
}

/// What a statement made for one connection covers.
pub fn connection_scope(scope: &ConnectionScope, keyrings: Keyrings<'_>) -> String {
    self::scope(&scope.capability, scope.operation, &scope.key, keyrings)
}

/// Which statement decided a mode, so a surface can say why.
pub fn basis(basis: &Basis, keyrings: Keyrings<'_>) -> String {
    match basis {
        Basis::Default => "Hedwig's default for what this exposes".to_owned(),
        Basis::Start {
            audience: whose,
            scope: start,
        } => format!(
            "{}, for {}",
            place(Place {
                audience: *whose,
                part: Part::Start,
            }),
            statement(start, keyrings)
        ),
        Basis::Rule(rule) => format!("your rule for {}", statement(rule, keyrings)),
        Basis::Connection(rule) => format!(
            "what you set for this connection: {}",
            connection_scope(rule, keyrings)
        ),
        Basis::Limit(limited) => format!(
            "{}, for {}",
            audience(limited.audience),
            statement(&limited.scope, keyrings)
        ),
    }
}

/// What a limit moved, for a mode an organisation's floor holds: what the
/// person's statements, or what ships, chose under it.
pub fn under(basis: &Basis, keyrings: Keyrings<'_>) -> Option<String> {
    match basis {
        Basis::Limit(limited) => Some(format!(
            "{}, by {}",
            mode(limited.chose),
            self::basis(&limited.basis, keyrings)
        )),
        _ => None,
    }
}

pub fn activation(activation: Activation) -> &'static str {
    match activation {
        Activation::OnRequest => "only when I connect",
        Activation::WhileRunning => "while the remote runs",
        Activation::Continuous => "always, reconnecting when it drops",
    }
}

/// What one member of an exposure lets a remote do, for the person who is
/// about to name it in a grant.
pub fn exposes(word: &str) -> &'static str {
    match word {
        "key-use" => "use your keys to sign, decrypt and authenticate",
        "key-management" => "export keys, change passphrases and administer the card",
        "secret" => "take a secret that works without this workstation afterwards",
        "service" => "reach a service that checks nobody's identity",
        "network" => "reach hosts only this workstation can reach",
        _ => "",
    }
}

/// Every member of an exposure, as one clause.
pub fn exposure(exposure: Exposure) -> String {
    exposure.words().map(exposes).collect::<Vec<_>>().join("; ")
}

pub fn breakdown(breakdown: Breakdown) -> String {
    match breakdown {
        Breakdown::Exited { status } => format!("it ended by itself, with status {status}"),
        Breakdown::Hung => "it stopped answering".to_owned(),
        Breakdown::Unstarted => "it could not be started".to_owned(),
    }
}

pub fn store(store: Store) -> &'static str {
    match store {
        Store::Trail => "the record of what happened",
        Store::Configuration => "your configuration",
    }
}

/// How often, as a count is said after what it counts.
pub fn times(count: u32) -> String {
    if count == 1 {
        "once".to_owned()
    } else {
        format!("{count} times")
    }
}

/// Who made a change, as the person would name it.
pub fn client(kind: ClientKind) -> &'static str {
    match kind {
        ClientKind::Command => "a command or a script",
        ClientKind::Terminal => "a terminal",
        ClientKind::Interface => "Hedwig's icon",
        ClientKind::Viewer => "Hedwig's window, or another program that shows Hedwig",
        ClientKind::Prompt => "a connection's client",
    }
}

/// How a request ended.
pub fn outcome(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Served(_) => "served".to_owned(),
        Outcome::Unseen(_) => "served while nothing could reach you, as your rule says".to_owned(),
        Outcome::Allowed(_) => "served: you allowed it".to_owned(),
        Outcome::Covered => "served under what you allowed earlier".to_owned(),
        Outcome::Refused(refusal) => format!("refused: {refusal}"),
        Outcome::Abandoned => "the remote gave up waiting".to_owned(),
    }
}

/// What readiness found for a capability on a remote: what keeps it off the
/// channel first, then what is carried and still wrong.
fn unready(remote: &RemoteId, capability: &Name, found: &[Finding]) -> String {
    let carried = findings(found, false);
    match (findings(found, true), carried.is_empty()) {
        (blocking, true) => format!("{capability} is not ready on {remote}: {blocking}"),
        (blocking, false) if blocking.is_empty() => {
            format!("{capability} is carried to {remote}, but {carried}")
        }
        (blocking, false) => {
            format!("{capability} is not ready on {remote}: {blocking}; and {carried}")
        }
    }
}

/// `text`, a sentence about `name`, begun as a sentence is: with a capital,
/// unless it begins with the name, which keeps the case it is written in.
pub fn begun(text: String, name: &Name) -> String {
    if text.starts_with(name.as_str()) {
        text
    } else {
        capitalised(text)
    }
}

/// A sentence whose first word is Hedwig's own, begun with a capital.
fn capitalised(text: String) -> String {
    let mut letters = text.chars();
    match letters.next() {
        Some(first) => first.to_uppercase().chain(letters).collect(),
        None => text,
    }
}

/// One thing that needs the person, as a sentence that stands alone.
pub fn attention(item: &Attention, keyrings: Keyrings<'_>) -> String {
    match item {
        Attention::Request {
            remote,
            capability,
            operation,
            key,
            ..
        } => {
            let mut text = asks(remote, capability, *operation);
            if let Some(key) = key {
                let keyrings = keyrings.of_capability(remote, capability);
                let _ = write!(text, ", {}", self::key(key, keyrings));
            }
            text
        }
        Attention::Prompt { remote, kind, .. } => {
            format!("Connecting to {remote} needs {}", prompt(*kind))
        }
        Attention::Unready {
            remote,
            capability,
            findings: found,
        } => unready(remote, capability, found),
        Attention::Stopped { remote, end: ended } => {
            format!("The connection to {remote} stopped: {}", end(ended))
        }
        Attention::Burst { remote, requests } => {
            format!("{remote} made {requests} requests in a short time")
        }
        Attention::Safeguards(held) => card(held, keyrings),
        Attention::Refused {
            remote,
            refusal,
            times: count,
        } => match remote {
            Some(remote) => format!("Refused {} for {remote}: {refusal}", times(*count)),
            None => format!("Refused {}: {refusal}", times(*count)),
        },
        Attention::Restarted {
            cause,
            times: count,
        } => format!(
            "Hedwig broke down and was started again, {}: {}. What was connected or allowed \
             when it ended is gone",
            times(*count),
            breakdown(*cause)
        ),
        Attention::Unreadable {
            store: which,
            account,
        } => capitalised(format!(
            "{} could not be read and was set aside: {account}",
            store(*which)
        )),
        // Keeping Hedwig is the one widening whose entry says what it was:
        // the removal it ended.
        Attention::Widened {
            entry,
            kind,
            origin: from,
        } if matches!(entry.event, Event::Restored { .. }) => format!(
            "Hedwig was kept from {} in session {}: its removal ended, and it serves your remotes again as you consented",
            client(*kind),
            from.session
        ),
        Attention::Widened {
            kind, origin: from, ..
        } => format!(
            "A change that lets more through was made from {} in session {}",
            client(*kind),
            from.session
        ),
        Attention::Unseen { remote, served } => format!(
            "{remote} was served {} while nothing could reach you, as your rule says",
            times(*served)
        ),
        Attention::Policy {
            place: changed,
            arrived,
            withdrawn,
            unread,
            ..
        } => policy_changed(*changed, *arrived, *withdrawn, *unread),
        Attention::Unlisted { route, account } => {
            format!("{route} could not say which of its remotes are running: {account}")
        }
        Attention::Noticed {
            remote,
            remark,
            unheard,
            ..
        } => format!("{remote} says: {}", notice(remark, *unheard)),
        Attention::Withdrawn(_) => BEING_REMOVED.to_owned(),
    }
}

/// What changed in one place of the organisation's policy.
fn policy_changed(changed: Place, arrived: u32, withdrawn: u32, unread: u32) -> String {
    let mut text = capitalised(format!(
        "{} changed: {arrived} {} arrived and {withdrawn} {} withdrawn",
        place(changed),
        if arrived == 1 {
            "statement"
        } else {
            "statements"
        },
        if withdrawn == 1 { "was" } else { "were" }
    ));
    if unread > 0 {
        let _ = write!(
            text,
            "; {unread} of its lines cannot be read, so nothing is served under them"
        );
    }
    text
}

/// What keeping Hedwig does, where a removal is under way: put to the person
/// before `Restore`, which lets more through.
pub const KEEPS: &str = "Hedwig serves your remotes again as you granted them, and writes on each \
                         what you consented to.";

/// A removal under way, as the icon and the window name it.
pub const BEING_REMOVED: &str = "Hedwig is being removed and serves no remote";

/// A count as the person reads it, its thousands apart.
pub(crate) fn grouped(count: u64) -> String {
    let digits = count.to_string();
    let mut out = String::new();
    for (at, digit) in digits.chars().enumerate() {
        if at > 0 && (digits.len() - at).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Where a compaction cut every remote's activity, and why: nothing before
/// it is kept, whichever remote the entries it let go were about.
pub fn kept(dropped: u64, cut: Cut) -> String {
    let entries = match dropped {
        1 => "1 older entry".to_owned(),
        _ => format!("{} older entries", grouped(dropped)),
    };
    match cut {
        Cut::Horizon => format!(
            "nothing before this is kept: Hedwig let go of {entries}, of every remote's, older \
             than you keep activity"
        ),
        Cut::Ceiling => format!(
            "nothing before this is kept: Hedwig let go of {entries}, of every remote's, past the \
             newest {} it keeps so that it starts quickly",
            grouped(u64::try_from(CEILING).unwrap_or(u64::MAX))
        ),
    }
}

/// What a remote's job said, as its words, with how many of that remote's
/// notices before it were turned away for coming too fast.
pub fn notice(remark: &Remark, unheard: u32) -> String {
    if unheard == 0 {
        return remark.to_string();
    }
    format!(
        "{remark} ({} before it came too fast and {} not passed on)",
        notices(unheard),
        if unheard == 1 { "was" } else { "were" }
    )
}

/// How many of a remote's notices, as a count the person reads.
fn notices(count: u32) -> String {
    if count == 1 {
        "1 notice".to_owned()
    } else {
        format!("{count} notices")
    }
}
