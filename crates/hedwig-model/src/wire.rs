//! How every value of the model is written down: a frame on the control
//! channel, an entry of the trail, a configuration document.
//!
//! One mapping serves all three. A record is an object holding exactly its
//! fields, under their names with hyphens; a choice with no data is its word;
//! a choice with data is an object with that word as its one key. Nothing is
//! optional and nothing unknown is skipped: a key that is missing or not
//! expected is a [`Fault`] that names where it is, so a document from another
//! version fails at the door instead of half-applying.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32};

use crate::beyond::Beyond;
use crate::capability::{
    Access, AgentAt, Browser, Capability, Exposure, Holds, Home, Installation, KeyKind, Lends,
    LentKey, Offer, Operation, Query, ServiceHost, ServicePort, Setup, Source, Spot, Stream,
    Toward,
};
use crate::config::{
    Accepted, AcceptedEntry, Activation, BurstEntry, CadenceEntry, CapEntry, Catalogue, Change,
    Collision, Defined, Definitions, Denial, Document, Effect, FullScreenEntry, Grant, GrantEntry,
    HeardEntry, KeepaliveEntry, Reach, Reference, ReturnsEntry, RuleEntry, Terms,
};
use crate::gate::Capped;
use crate::holder::{Rights, SignedIn, SourceHolder, Whose};
use crate::install::{AtSignIn, Index, Packed, Starts};
use crate::json::{self, Json, JsonError, Layout};
use crate::organisation::{
    GrantScope, Holding, Limit, Misread, Part, Place, Policy, Start, Statement, Unread,
};
use crate::platform::{AgentForwarding, Platform, Sockets};
use crate::policy::{
    Attended, Basis, ConnectionScope, KeyName, Keys, Limited, Mode, RuleScope, Selector,
};
use crate::process::{CoreState, Diagnostic, Instance, Order, Report, Running};
use crate::protocol::{
    Act, AgentKey, Answer, Attached, Attachment, Attention, Bundle, CarriedOn, Contact, Decides,
    Decision, DeviceState, Differs, Exercised, Found, FromCore, Hint, Hold, Last, Lendable, Line,
    Loudness, Needs, Notice, Offered, Offering, Proof, RemoteSettings, Reply, Request,
    RouteSettings, Row, SerialPort, Served, SetAside, Settings, Standing, Status, Through, ToCore,
    Topic, Trial, Tried, Usb, WindowsStarts, Withdrawal, Withdrawn, Workstation,
    WorkstationSettings, Would, Written,
};
use crate::refusal::{Refusal, Section, Whereabouts, Withheld};
use crate::remote::{
    Argument, Client, Granted, Identity, Lister, Listing, Member, RemoteId, Remotes, Route, Set,
};
use crate::scope::{Audience, Holder, Tier};
use crate::setting::{
    Autostart, Bounded, Burst, Cadence, CapScope, Condition, Diagnostics, Expected, FullScreen,
    Heard, Keep, Keepalive, Lengths, Longest, Returns, Said, Settled, Span, Threshold, Volume,
    Waits, Workstation as SettingScope,
};
use crate::site::{Site, SiteError, Unopenable};
use crate::text::{
    Address, AgentPipe, DeviceSerial, DeviceSocket, Fingerprint, Folder, Grip, Host, Kernel, KeyId,
    Location, Mark, Name, Pattern, PipeName, Port, PortName, Program, Remark, RemotePath, Secret,
    Serial, ServiceName, SshKey, Template, TextError, Variable, Verbatim, Words,
};
use crate::trail::{
    Ask, Asking, Binding, Breakdown, Card, Carriage, Carry, ChannelEnd, ClientId, ClientKind,
    ConnectionId, Cut, Dropped, Entry, Event, Failure, Finding, Form, Gave, Given, Health, Held,
    Icon, Integrity, Item, Key, Keyring, Link, Missing, Network, Noted, Notices, Opener, Origin,
    Outcome, Payload, Phase, Prepared, Presence, Prompt, PromptId, PromptKind, Readiness, Release,
    RequestId, Restated, Returning, Seq, Serving, SignaturePin, State, Store, Surface, Target,
    Tick, Timestamp, Touch, Uses, Widened, Withdrew, Write,
};

/// The longest frame either end accepts, in bytes. The largest message the
/// protocol defines, a full page of activity, is under a tenth of it.
pub const FRAME: usize = 1 << 20;

/// What a value was expected to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Number,
    Text,
    List,
    Record,
    /// A word, or an object with one key.
    Choice,
}

impl Shape {
    /// The shape as the person writing a document knows it.
    fn words(self) -> &'static str {
        match self {
            Shape::Number => "a number",
            Shape::Text => "a string",
            Shape::List => "a list",
            Shape::Record => "an object",
            Shape::Choice => "a word, or an object with one key",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Miss {
    /// A value of another shape stands where this one was expected.
    Expected(Shape),
    /// A list that is a set holds the same member twice.
    Repeated,
    /// A record lacks this key.
    Missing(&'static str),
    /// A key or a word this version does not know.
    Unknown(String),
    /// A number outside what the field holds.
    Range,
    Text(TextError),
    Site(SiteError),
}

/// What is wrong with a value, and the path from the outermost value to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// Innermost step first.
    path: Vec<String>,
    pub miss: Miss,
}

impl Fault {
    fn new(miss: Miss) -> Fault {
        Fault {
            path: Vec::new(),
            miss,
        }
    }

    fn within(mut self, step: impl Into<String>) -> Fault {
        self.path.push(step.into());
        self
    }

    /// Where the fault is, outermost step first: `grants.2.terms.activation`.
    pub fn path(&self) -> String {
        let mut steps: Vec<&str> = self.path.iter().map(String::as_str).collect();
        steps.reverse();
        steps.join(".")
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.path();
        let at = if path.is_empty() { "the value" } else { &path };
        match &self.miss {
            Miss::Expected(shape) => write!(f, "{at} should be {}", shape.words()),
            Miss::Missing(key) => write!(f, "{at} has no {key}"),
            Miss::Unknown(word) => write!(f, "{at} has {word:?}, which is not known here"),
            Miss::Range => write!(f, "{at} is out of range"),
            Miss::Repeated => write!(f, "{at} lists the same value twice"),
            Miss::Text(error) => write!(f, "{at} is not accepted: {error}"),
            Miss::Site(error) => write!(f, "{at} is not a site: {error}"),
        }
    }
}

/// Why bytes could not be read as a value of the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Longer than [`FRAME`].
    Size {
        length: usize,
    },
    Json(JsonError),
    Fault(Fault),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Size { length } => {
                write!(f, "{length} bytes is over the limit of {FRAME}")
            }
            WireError::Json(error) => write!(f, "{error}"),
            WireError::Fault(fault) => write!(f, "{fault}"),
        }
    }
}

impl std::error::Error for WireError {}

/// A value that has a written form.
pub trait Wire: Sized {
    fn put(&self) -> Json;

    /// # Errors
    ///
    /// The [`Fault`] naming what in `json` is not this type.
    fn take(json: Json) -> Result<Self, Fault>;
}

/// Writes a value as one line, with no line feed in it.
pub fn line<T: Wire>(value: &T) -> String {
    json::render(&value.put(), Layout::Line)
}

/// Writes a value as an indented page, for a document a person reads.
pub fn page<T: Wire>(value: &T) -> String {
    json::render(&value.put(), Layout::Page)
}

/// Reads a value from a line or a page.
///
/// # Errors
///
/// [`WireError::Size`] before anything is parsed, then the parser's or the
/// mapping's account.
pub fn read<T: Wire>(text: &str) -> Result<T, WireError> {
    if text.len() > FRAME {
        return Err(WireError::Size { length: text.len() });
    }
    read_stored(text)
}

/// Reads a value the core wrote to its own folder and is the only writer
/// of, with no bound but the file's: the trail's head grows with the
/// remotes the person has, and a bound a peer's frame needs would set aside
/// a trail that is whole.
///
/// # Errors
///
/// The parser's or the mapping's account.
pub fn read_stored<T: Wire>(text: &str) -> Result<T, WireError> {
    let json = json::parse(text).map_err(WireError::Json)?;
    T::take(json).map_err(WireError::Fault)
}

impl Catalogue {
    /// The catalogue this build ships.
    ///
    /// # Errors
    ///
    /// Only if the embedded document is not a valid catalogue, which the
    /// model's suite checks; the core treats it as a build that must not run.
    pub fn shipped() -> Result<Catalogue, WireError> {
        let reference: Reference = read(include_str!("../data/catalogue.json"))?;
        Catalogue::new(reference)
            .map_err(|refusal| WireError::Fault(Fault::new(Miss::Unknown(refusal.to_string()))))
    }
}

fn key(field: &str) -> String {
    field.replace('_', "-")
}

fn tagged(word: &str, body: Json) -> Json {
    Json::Map(vec![(word.to_owned(), body)])
}

fn tag(json: Json) -> Result<(String, Option<Json>), Fault> {
    match json {
        Json::Text(word) => Ok((word, None)),
        Json::Map(mut members) if members.len() == 1 => match members.pop() {
            Some((word, body)) => Ok((word, Some(body))),
            None => Err(Fault::new(Miss::Expected(Shape::Choice))),
        },
        _ => Err(Fault::new(Miss::Expected(Shape::Choice))),
    }
}

struct Fields(Vec<(String, Json)>);

impl Fields {
    fn of(json: Json) -> Result<Fields, Fault> {
        match json {
            Json::Map(members) => Ok(Fields(members)),
            _ => Err(Fault::new(Miss::Expected(Shape::Record))),
        }
    }

    fn take<T: Wire>(&mut self, field: &'static str) -> Result<T, Fault> {
        let wanted = key(field);
        let at = self
            .0
            .iter()
            .position(|(known, _)| *known == wanted)
            .ok_or_else(|| Fault::new(Miss::Missing(field)))?;
        let (_, json) = self.0.swap_remove(at);
        T::take(json).map_err(|fault| fault.within(wanted))
    }

    fn finish(mut self) -> Result<(), Fault> {
        match self.0.pop() {
            Some((unknown, _)) => Err(Fault::new(Miss::Unknown(unknown))),
            None => Ok(()),
        }
    }
}

macro_rules! record {
    ($type:ident { $($field:ident),+ $(,)? }) => {
        impl Wire for $type {
            fn put(&self) -> Json {
                Json::Map(vec![$((key(stringify!($field)), self.$field.put())),+])
            }

            fn take(json: Json) -> Result<Self, Fault> {
                let mut fields = Fields::of(json)?;
                let value = $type { $($field: fields.take(stringify!($field))?),+ };
                fields.finish()?;
                Ok(value)
            }
        }
    };
}

macro_rules! choice {
    ($type:ident {
        $(unit { $($uword:literal => $unit:ident),* $(,)? })?
        $(one { $($oword:literal => $one:ident),* $(,)? })?
        $(fields { $($fword:literal => $many:ident { $($field:ident),+ $(,)? }),* $(,)? })?
    }) => {
        impl Wire for $type {
            fn put(&self) -> Json {
                match self {
                    $($($type::$unit => Json::Text($uword.to_owned()),)*)?
                    $($($type::$one(inner) => tagged($oword, inner.put()),)*)?
                    $($($type::$many { $($field),+ } => tagged(
                        $fword,
                        Json::Map(vec![$((key(stringify!($field)), $field.put())),+]),
                    ),)*)?
                }
            }

            fn take(json: Json) -> Result<Self, Fault> {
                let (word, body) = tag(json)?;
                match body {
                    None => {
                        $($(if word == $uword {
                            return Ok($type::$unit);
                        })*)?
                    }
                    Some(body) => {
                        $($(if word == $oword {
                            return Wire::take(body)
                                .map($type::$one)
                                .map_err(|fault| fault.within($oword));
                        })*)?
                        $($(if word == $fword {
                            return Fields::of(body)
                                .and_then(|mut fields| {
                                    let value = $type::$many {
                                        $($field: fields.take(stringify!($field))?),+
                                    };
                                    fields.finish()?;
                                    Ok(value)
                                })
                                .map_err(|fault| fault.within($fword));
                        })*)?
                        drop(body);
                    }
                }
                Err(Fault::new(Miss::Unknown(word)))
            }
        }

        impl $type {
            /// Every word this choice is written as.
            pub const WORDS: &[&str] = &[
                $($($uword,)*)?
                $($($oword,)*)?
                $($($fword,)*)?
            ];
        }
    };
}

macro_rules! number {
    ($($type:ty),+) => {$(
        impl Wire for $type {
            fn put(&self) -> Json {
                Json::Number(i128::from(*self))
            }

            fn take(json: Json) -> Result<Self, Fault> {
                match json {
                    Json::Number(number) => {
                        <$type>::try_from(number).map_err(|_| Fault::new(Miss::Range))
                    }
                    _ => Err(Fault::new(Miss::Expected(Shape::Number))),
                }
            }
        }
    )+};
}

number!(u8, u16, u32, u64, i32);

macro_rules! positive {
    ($($type:ty => $inner:ty),+) => {$(
        impl Wire for $type {
            fn put(&self) -> Json {
                self.get().put()
            }

            fn take(json: Json) -> Result<Self, Fault> {
                <$type>::new(<$inner>::take(json)?).ok_or_else(|| Fault::new(Miss::Range))
            }
        }
    )+};
}

positive!(NonZeroU8 => u8, NonZeroU16 => u16, NonZeroU32 => u32);

macro_rules! wrapped {
    ($($type:ident($inner:ty)),+) => {$(
        impl Wire for $type {
            fn put(&self) -> Json {
                self.0.put()
            }

            fn take(json: Json) -> Result<Self, Fault> {
                <$inner>::take(json).map($type)
            }
        }
    )+};
}

wrapped!(
    Seq(u64),
    Tick(u64),
    Timestamp(u64),
    ClientId(Seq),
    ConnectionId(Seq),
    RequestId(Seq),
    PromptId(Seq)
);

macro_rules! text {
    ($($type:ty),+) => {$(
        impl Wire for $type {
            fn put(&self) -> Json {
                Json::Text(self.as_str().to_owned())
            }

            fn take(json: Json) -> Result<Self, Fault> {
                <$type>::try_from(String::take(json)?.as_str())
                    .map_err(|error| Fault::new(Miss::Text(error)))
            }
        }
    )+};
}

text!(
    Name,
    Address,
    Host,
    Variable,
    Template,
    RemotePath,
    Folder,
    Pattern,
    Mark,
    Grip,
    Fingerprint,
    Serial,
    DeviceSerial,
    PortName,
    DeviceSocket,
    Words,
    PipeName,
    Program,
    Verbatim,
    Location,
    ServiceName,
    Kernel,
    AgentPipe,
    SshKey,
    Remark
);

/// A request's key as its dialect names it: a keygrip's forty digits, or a
/// public key, whose space no keygrip has.
impl Wire for KeyId {
    fn put(&self) -> Json {
        match self {
            KeyId::Grip(grip) => grip.put(),
            KeyId::Ssh(key) => key.put(),
        }
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let text = String::take(json)?;
        if text.contains(' ') {
            SshKey::try_from(text.as_str()).map(KeyId::Ssh)
        } else {
            Grip::try_from(text.as_str()).map(KeyId::Grip)
        }
        .map_err(|error| Fault::new(Miss::Text(error)))
    }
}

impl Wire for String {
    fn put(&self) -> Json {
        Json::Text(self.clone())
    }

    fn take(json: Json) -> Result<Self, Fault> {
        match json {
            Json::Text(text) => Ok(text),
            _ => Err(Fault::new(Miss::Expected(Shape::Text))),
        }
    }
}

impl Wire for Secret {
    fn put(&self) -> Json {
        Json::Text(self.expose().to_owned())
    }

    fn take(json: Json) -> Result<Self, Fault> {
        String::take(json).map(Secret::from)
    }
}

impl Wire for Port {
    fn put(&self) -> Json {
        self.number().put()
    }

    fn take(json: Json) -> Result<Self, Fault> {
        Port::try_from(u16::take(json)?).map_err(|error| Fault::new(Miss::Text(error)))
    }
}

impl<T: Wire> Wire for Vec<T> {
    fn put(&self) -> Json {
        Json::List(self.iter().map(Wire::put).collect())
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let Json::List(items) = json else {
            return Err(Fault::new(Miss::Expected(Shape::List)));
        };
        items
            .into_iter()
            .enumerate()
            .map(|(index, item)| T::take(item).map_err(|fault| fault.within(index.to_string())))
            .collect()
    }
}

/// A set is written as a list in its order, and a list that holds a member
/// twice is not one.
impl<T: Wire + Ord> Wire for BTreeSet<T> {
    fn put(&self) -> Json {
        Json::List(self.iter().map(Wire::put).collect())
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let items = Vec::<T>::take(json)?;
        let count = items.len();
        let set: BTreeSet<T> = items.into_iter().collect();
        if set.len() == count {
            Ok(set)
        } else {
            Err(Fault::new(Miss::Repeated))
        }
    }
}

/// A value held behind a pointer is written as the value.
impl<T: Wire> Wire for Box<T> {
    fn put(&self) -> Json {
        (**self).put()
    }

    fn take(json: Json) -> Result<Self, Fault> {
        T::take(json).map(Box::new)
    }
}

/// Absence is written as `null`, never by leaving the key out.
impl<T: Wire> Wire for Option<T> {
    fn put(&self) -> Json {
        self.as_ref().map_or(Json::Null, Wire::put)
    }

    fn take(json: Json) -> Result<Self, Fault> {
        match json {
            Json::Null => Ok(None),
            present => T::take(present).map(Some),
        }
    }
}

impl<T: Wire> Wire for Selector<T> {
    fn put(&self) -> Json {
        match self {
            Selector::Every => Json::Text("every".to_owned()),
            Selector::Only(only) => tagged("only", only.put()),
        }
    }

    fn take(json: Json) -> Result<Self, Fault> {
        match tag(json)? {
            (word, None) if word == "every" => Ok(Selector::Every),
            (word, Some(body)) if word == "only" => T::take(body)
                .map(Selector::Only)
                .map_err(|fault| fault.within("only")),
            (word, _) => Err(Fault::new(Miss::Unknown(word))),
        }
    }
}

impl<T: Wire> Wire for Result<T, Refusal> {
    fn put(&self) -> Json {
        match self {
            Ok(value) => tagged("ok", value.put()),
            Err(refusal) => tagged("refused", refusal.put()),
        }
    }

    fn take(json: Json) -> Result<Self, Fault> {
        match tag(json)? {
            (word, Some(body)) if word == "ok" => {
                T::take(body).map(Ok).map_err(|fault| fault.within("ok"))
            }
            (word, Some(body)) if word == "refused" => Refusal::take(body)
                .map(Err)
                .map_err(|fault| fault.within("refused")),
            (word, _) => Err(Fault::new(Miss::Unknown(word))),
        }
    }
}

/// A set is written as the list of its members' words, in one order.
impl Wire for Exposure {
    fn put(&self) -> Json {
        Json::List(
            self.words()
                .map(|word| Json::Text(word.to_owned()))
                .collect(),
        )
    }

    fn take(json: Json) -> Result<Self, Fault> {
        Vec::<String>::take(json)?
            .into_iter()
            .try_fold(Exposure::NONE, |set, word| {
                Exposure::from_word(&word)
                    .map(|member| set.with(member))
                    .ok_or_else(|| Fault::new(Miss::Unknown(word)))
            })
    }
}

/// The scope of a setting with no remote in it.
impl Wire for SettingScope {
    fn put(&self) -> Json {
        Json::Text("workstation".to_owned())
    }

    fn take(json: Json) -> Result<Self, Fault> {
        match String::take(json)? {
            word if word == "workstation" => Ok(SettingScope),
            word => Err(Fault::new(Miss::Unknown(word))),
        }
    }
}

impl<S: Wire> Wire for Said<S> {
    fn put(&self) -> Json {
        match self {
            Said::Ships => Json::Text("ships".to_owned()),
            Said::Start { audience, scope } => tagged(
                "start",
                Json::Map(vec![
                    (key("audience"), audience.put()),
                    (key("scope"), scope.put()),
                ]),
            ),
            Said::Person(scope) => tagged("person", scope.put()),
        }
    }

    fn take(json: Json) -> Result<Self, Fault> {
        match tag(json)? {
            (word, None) if word == "ships" => Ok(Said::Ships),
            (word, Some(body)) if word == "start" => Fields::of(body)
                .and_then(|mut fields| {
                    let said = Said::Start {
                        audience: fields.take("audience")?,
                        scope: fields.take("scope")?,
                    };
                    fields.finish()?;
                    Ok(said)
                })
                .map_err(|fault| fault.within("start")),
            (word, Some(body)) if word == "person" => S::take(body)
                .map(Said::Person)
                .map_err(|fault| fault.within("person")),
            (word, _) => Err(Fault::new(Miss::Unknown(word))),
        }
    }
}

impl<V: Wire, S: Wire> Wire for Settled<V, S> {
    fn put(&self) -> Json {
        Json::Map(vec![
            (key("value"), self.value.put()),
            (key("said"), self.said.put()),
        ])
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let mut fields = Fields::of(json)?;
        let settled = Settled {
            value: fields.take("value")?,
            said: fields.take("said")?,
        };
        fields.finish()?;
        Ok(settled)
    }
}

choice!(Span { unit { "workstation" => Workstation, "run" => Run } });

impl<V: Wire, S: Wire> Wire for Bounded<V, S> {
    fn put(&self) -> Json {
        Json::Map(vec![
            (key("settled"), self.settled.put()),
            (key("held"), self.held.put()),
        ])
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let mut fields = Fields::of(json)?;
        let bounded = Bounded {
            settled: fields.take("settled")?,
            held: fields.take("held")?,
        };
        fields.finish()?;
        Ok(bounded)
    }
}

impl<T: Wire> Wire for Defined<T> {
    fn put(&self) -> Json {
        Json::Map(vec![
            (key("definition"), self.definition.put()),
            (key("by"), self.by.put()),
        ])
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let mut fields = Fields::of(json)?;
        let defined = Defined {
            definition: fields.take("definition")?,
            by: fields.take("by")?,
        };
        fields.finish()?;
        Ok(defined)
    }
}

impl<T: Wire> Wire for Differs<T> {
    fn put(&self) -> Json {
        Json::Map(vec![
            (key("before"), self.before.put()),
            (key("after"), self.after.put()),
        ])
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let mut fields = Fields::of(json)?;
        let differs = Differs {
            before: fields.take("before")?,
            after: fields.take("after")?,
        };
        fields.finish()?;
        Ok(differs)
    }
}

/// The lengths are written shortest first.
impl Wire for Lengths {
    fn put(&self) -> Json {
        Json::List(self.iter().map(|seconds| seconds.put()).collect())
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let listed = Vec::<NonZeroU32>::take(json)?;
        let lengths: Lengths = listed.iter().copied().collect();
        if lengths.iter().count() == listed.len() {
            Ok(lengths)
        } else {
            Err(Fault::new(Miss::Repeated))
        }
    }
}

choice!(Access { unit { "restricted" => Restricted, "unrestricted" => Unrestricted } });
choice!(Home { unit { "default" => Default } one { "at" => At } });
choice!(Installation { unit { "registered" => Registered } one { "at" => At } });
choice!(ServiceHost { unit { "workstation" => Workstation } one { "named" => Named } });
choice!(ServicePort { unit { "unstated" => Unstated } one { "fixed" => Fixed } });
choice!(Stream { unit { "adb" => Adb, "opaque" => Opaque } });
choice!(Offer {
    one { "port" => Port }
    fields { "private-socket" => PrivateSocket { variable, value } }
});
choice!(Setup { unit { "inspect" => Inspect, "write" => Write } });
choice!(KeyKind {
    unit {
        "ecdsa-p256" => EcdsaP256,
        "ecdsa-p384" => EcdsaP384,
        "ecdsa-p521" => EcdsaP521,
        "rsa-2048" => Rsa2048,
        "rsa-3072" => Rsa3072,
        "rsa-4096" => Rsa4096,
    }
});
choice!(AgentAt {
    unit { "machine" => Machine }
    one { "pipe" => Pipe }
    fields { "gnupg" => Gnupg { installation, home } }
});
choice!(Source {
    unit { "notices" => Notices }
    fields {
        "agent" => Agent { at },
        "gnupg" => Gnupg { installation, home, access },
        "service" => Service { host, port, stream, remote },
        "browser" => Browser { browser, sites },
        "serial" => Serial { port, remote },
        "credentials" => Credentials { git, sites },
    }
});
choice!(Browser {
    unit { "default" => Default }
    fields { "program" => Program { program, arguments } }
});
// A site is its written form, so a document, the command line and the window
// read one alike.
impl Wire for Site {
    fn put(&self) -> Json {
        Json::Text(self.to_string())
    }

    fn take(json: Json) -> Result<Self, Fault> {
        match json {
            Json::Text(text) => text.parse().map_err(|why| Fault::new(Miss::Site(why))),
            _ => Err(Fault::new(Miss::Expected(Shape::Text))),
        }
    }
}
choice!(Query { unit { "agent-socket" => AgentSocket, "agent-ssh-socket" => AgentSshSocket } });
choice!(Spot {
    unit { "helper" => Helper }
    one { "port" => Port, "socket" => Socket, "variable" => Variable }
});
choice!(Beyond {
    unit {
        "apple-device" => AppleDevice,
        "chip-usb" => ChipUsb,
        "port-per-run" => PortPerRun,
    }
});
choice!(Operation {
    unit {
        "connect" => Connect,
        "authenticate" => Authenticate,
        "sign" => Sign,
        "decrypt" => Decrypt,
        "open" => Open,
    }
});
record!(Capability { id, source });

choice!(Sockets { unit { "emulated" => Emulated } fields { "unix" => Unix { path_bytes } } });
choice!(AgentForwarding { unit { "served" => Served, "refused" => Refused } });
record!(Platform {
    family,
    kernel,
    sockets,
    agent_forwarding
});

record!(RemoteId { route, address });
choice!(Argument { unit { "address" => Address } one { "literal" => Literal } });
record!(Client {
    program,
    before,
    after
});
record!(Lister {
    program,
    arguments,
    header
});
choice!(Listing { unit { "blind" => Blind } one { "lists" => Lists } });
choice!(Identity { unit { "host-key" => HostKey, "platform" => Platform } });
record!(Route {
    id,
    client,
    listing,
    identity
});
choice!(Member { one { "one" => One } fields { "matching" => Matching { route, pattern } } });
record!(Set { id, members });
choice!(Granted {
    one { "route" => Route, "set" => Set, "one" => One }
    fields { "matching" => Matching { route, pattern } }
});
choice!(Remotes {
    unit { "every" => Every }
    one { "route" => Route, "set" => Set, "one" => One }
    fields { "matching" => Matching { route, pattern } }
});

choice!(Audience { unit { "machine" => Machine, "person" => Person } });

choice!(Mode { unit { "unattended" => Unattended, "notify" => Notify, "confirm" => Confirm } });
choice!(Attended { unit { "notify" => Notify, "confirm" => Confirm } });
choice!(KeyName { one { "fingerprint" => Fingerprint, "grip" => Grip, "ssh" => Ssh } });
choice!(Keys {
    unit { "every" => Every, "needing-no-touch" => NeedingNoTouch }
    one { "only" => Only }
});
record!(RuleScope {
    remotes,
    capability,
    operation,
    key
});
record!(ConnectionScope {
    capability,
    operation,
    key
});
record!(Limited {
    audience,
    scope,
    chose,
    basis
});
choice!(Basis {
    unit { "default" => Default }
    one { "rule" => Rule, "connection" => Connection, "limit" => Limit }
    fields { "start" => Start { audience, scope } }
});

choice!(Activation {
    unit { "on-request" => OnRequest, "while-running" => WhileRunning, "continuous" => Continuous }
});
record!(Grant {
    capability,
    remotes
});
record!(Terms {
    activation,
    setup,
    acknowledged,
    lends
});
record!(Denial {
    capability,
    remotes
});
record!(Accepted {
    setup,
    acknowledged,
    lends
});
/// What a grant lends: a list, empty where it lends nothing, or `"every"`.
/// A device is its serial and a key a record; a device or a key named twice
/// is refused, so no key is lent two ways at once.
impl Wire for Lends {
    fn put(&self) -> Json {
        match self {
            Lends::Named { devices, keys } => Json::List(
                devices
                    .iter()
                    .map(Wire::put)
                    .chain(keys.iter().map(|(key, lent)| {
                        Json::Map(vec![
                            (self::key("key"), key.put()),
                            (self::key("toward"), lent.toward.put()),
                            (self::key("comment"), lent.comment.put()),
                        ])
                    }))
                    .collect(),
            ),
            Lends::Every => Json::Text("every".to_owned()),
        }
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let listed = match json {
            Json::Text(word) if word == "every" => return Ok(Lends::Every),
            Json::Text(word) => return Err(Fault::new(Miss::Unknown(word))),
            Json::List(listed) => listed,
            _ => return Err(Fault::new(Miss::Expected(Shape::List))),
        };
        let mut devices = BTreeSet::new();
        let mut keys = BTreeMap::new();
        for (index, item) in listed.into_iter().enumerate() {
            let fresh = match item {
                Json::Text(_) => DeviceSerial::take(item).map(|serial| devices.insert(serial)),
                record => lent_key(record).map(|(key, lent)| keys.insert(key, lent).is_none()),
            };
            match fresh {
                Ok(true) => {}
                Ok(false) => return Err(Fault::new(Miss::Repeated).within(index.to_string())),
                Err(fault) => return Err(fault.within(index.to_string())),
            }
        }
        Ok(Lends::Named { devices, keys })
    }
}

fn lent_key(record: Json) -> Result<(SshKey, LentKey), Fault> {
    let mut fields = Fields::of(record)?;
    let key = fields.take("key")?;
    let lent = LentKey {
        toward: fields.take("toward")?,
        comment: fields.take("comment")?,
    };
    fields.finish()?;
    Ok((key, lent))
}
choice!(Toward { unit { "anywhere" => Anywhere } one { "hosts" => Hosts } });
choice!(Holds { unit { "devices" => Devices, "keys" => Keys } });
record!(Burst { requests, seconds });
record!(Keepalive { every, missed });
record!(Returns { first, longest });
wrapped!(Cadence(NonZeroU32));
choice!(Threshold { unit { "never" => Never } one { "at" => At } });
choice!(Volume { unit { "shown" => Shown, "announced" => Announced, "interrupts" => Interrupts } });
choice!(Waits { unit { "shown" => Shown, "announced" => Announced } });
choice!(Condition {
    unit {
        "served" => Served,
        "unready" => Unready,
        "stopped" => Stopped,
        "host-key-changed" => HostKeyChanged,
        "refused" => Refused,
        "noticed" => Noticed,
    }
});
choice!(Heard {
    one {
        "served" => Served,
        "unready" => Unready,
        "stopped" => Stopped,
        "host-key-changed" => HostKeyChanged,
        "refused" => Refused,
        "noticed" => Noticed,
    }
});
choice!(FullScreen { unit { "not-shown" => NotShown, "shown" => Shown } });
choice!(Longest { unit { "nothing" => Nothing } one { "seconds" => Seconds } });
record!(CapScope { remotes, key });
record!(Expected { remote, refusal });
choice!(Autostart { unit { "off" => Off, "at-logon" => AtLogon } });
choice!(Diagnostics { unit { "off" => Off, "faults" => Faults, "detail" => Detail } });
wrapped!(Keep(NonZeroU16));
choice!(Reach { unit { "wider" => Wider, "no-wider" => NoWider } });
record!(GrantScope {
    capability,
    remotes
});
choice!(Limit {
    one {
        "inspect-only" => InspectOnly,
        "deny" => Deny,
        "keep-at-least" => KeepAtLeast,
        "keep-at-most" => KeepAtMost,
        "diagnostics-at-most" => DiagnosticsAtMost,
    }
    fields {
        "floor" => Floor { scope, mode },
        "activation" => Activation { scope, most },
        "cap" => Cap { scope, longest },
        "withhold" => Withhold { exposure, remotes },
        "confine" => Confine { exposure, remotes },
    }
});
choice!(Start {
    one {
        "define" => Define,
        "define-platform" => DefinePlatform,
        "define-route" => DefineRoute,
        "define-set" => DefineSet,
        "autostart" => Autostart,
        "icon" => Icon,
        "keep" => Keep,
        "diagnostics" => Diagnostics,
    }
    fields {
        "grant" => Grant { grant, activation },
        "rule" => Rule { scope, mode },
        "burst" => Burst { remotes, threshold },
        "keepalive" => Keepalive { remotes, keepalive },
        "returns" => Returns { remotes, returns },
        "cadence" => Cadence { routes, cadence },
    }
});
choice!(Statement { one { "limit" => Limit, "start" => Start, "ask" => Ask } });
choice!(Part { unit { "limits" => Limits, "start" => Start, "ask" => Ask } });
record!(Place { audience, part });
record!(Unread { lines, account });
record!(Misread { place, unread });
choice!(Holder { unit { "person" => Person } one { "organisation" => Organisation } });
record!(Holding { holder, limit });
record!(Capped {
    longest,
    holder,
    scope
});
record!(Reference {
    capabilities,
    routes,
    platforms,
    sets
});
choice!(Change {
    one {
        "revoke" => Revoke,
        "unaccept" => Unaccept,
        "deny" => Deny,
        "undeny" => Undeny,
        "unrule" => Unrule,
        "define" => Define,
        "undefine" => Undefine,
        "define-platform" => DefinePlatform,
        "undefine-platform" => UndefinePlatform,
        "define-route" => DefineRoute,
        "undefine-route" => UndefineRoute,
        "define-set" => DefineSet,
        "undefine-set" => UndefineSet,
        "expect" => Expect,
        "unexpect" => Unexpect,
        "lengths" => Lengths,
        "autostart" => Autostart,
        "icon" => Icon,
        "keep" => Keep,
        "diagnostics" => Diagnostics,
    }
    fields {
        "grant" => Grant { grant, terms },
        "accept" => Accept { grant, accepted },
        "rule" => Rule { scope, mode },
        "burst" => Burst { remotes, threshold },
        "hear" => Hear { remotes, heard },
        "unhear" => Unhear { remotes, condition },
        "full-screen" => FullScreen { remotes, card },
        "cap" => Cap { scope, longest },
        "keepalive" => Keepalive { remotes, keepalive },
        "returns" => Returns { remotes, returns },
        "cadence" => Cadence { routes, cadence },
    }
});
choice!(Effect { unit { "changed" => Changed, "unchanged" => Unchanged } });
record!(GrantEntry { grant, terms });
record!(AcceptedEntry { grant, accepted });
record!(RuleEntry { scope, mode });
record!(BurstEntry { remotes, threshold });
record!(HeardEntry { remotes, heard });
record!(FullScreenEntry { remotes, card });
record!(CapEntry { scope, longest });
record!(KeepaliveEntry { remotes, keepalive });
record!(ReturnsEntry { remotes, returns });
record!(CadenceEntry { routes, cadence });
record!(Collision { section, name, by });
record!(Definitions {
    capabilities,
    routes,
    platforms,
    sets,
    collisions,
    beyond
});
choice!(Tier {
    unit { "ships" => Ships, "person" => Person }
    one { "start" => Start }
});
record!(Document {
    version,
    capabilities,
    platforms,
    routes,
    sets,
    grants,
    accepted,
    denials,
    rules,
    bursts,
    heard,
    expected,
    full_screen,
    lengths,
    caps,
    autostart,
    icon,
    keep,
    diagnostics,
    keepalives,
    returns,
    cadences
});

choice!(Section {
    unit {
        "capabilities" => Capabilities,
        "platforms" => Platforms,
        "grants" => Grants,
        "denials" => Denials,
        "rules" => Rules,
        "routes" => Routes,
        "sets" => Sets,
        "accepted" => Accepted,
        "bursts" => Bursts,
        "heard" => Heard,
        "expected" => Expected,
        "full-screen" => FullScreen,
        "caps" => Caps,
        "keepalives" => Keepalives,
        "returns" => Returns,
        "cadences" => Cadences,
    }
});
choice!(Refusal {
    unit {
        "not-greeted" => NotGreeted,
        "not-attending" => NotAttending,
        "no-icon" => NoIcon,
        "paused" => Paused,
        "withdrawn" => Withdrawn,
        "declined" => Declined,
        "unattributable" => Unattributable,
        "unissued" => Unissued,
        "no-tpm" => NoTpm,
    }
    one {
        "malformed" => Malformed,
        "key-exists" => KeyExists,
        "kind-unmade" => KindUnmade,
        "key-absent" => KeyAbsent,
        "unknown-capability" => UnknownCapability,
        "unknown-route" => UnknownRoute,
        "unknown-set" => UnknownSet,
        "unknown-platform" => UnknownPlatform,
        "unknown-kernel" => UnknownKernel,
        "unknown-connection" => UnknownConnection,
        "unknown-request" => UnknownRequest,
        "unknown-prompt" => UnknownPrompt,
        "unlisted" => Unlisted,
        "reserved" => Reserved,
        "capability-in-use" => CapabilityInUse,
        "route-in-use" => RouteInUse,
        "set-in-use" => SetInUse,
        "repeated" => Repeated,
        "platform-unobserved" => PlatformUnobserved,
        "not-connected" => NotConnected,
        "unread" => Unread,
        "nobody-reachable" => NobodyReachable,
    }
    fields {
        "version" => Version { core, client },
        "capability-incomplete" => CapabilityIncomplete { capability },
        "kernel-claimed" => KernelClaimed { kernel, first, second },
        "exposure-not-acknowledged" => ExposureNotAcknowledged { capability, missing },
        "unlendable" => Unlendable { capability, lent },
        "activation-needs-discovery" => ActivationNeedsDiscovery { route },
        "answer-unfit" => AnswerUnfit { kind },
        "operation-not-in-dialect" => OperationNotInDialect { capability, operation },
        "collides" => Collides { section, name },
        "not-offered" => NotOffered { seconds },
        "held" => Held { audience, limit },
        "document-version" => DocumentVersion { found, supported },
        "no-carrier" => NoCarrier { capability, platform },
        "needs-remote-setup" => NeedsRemoteSetup { capability, platform },
        "no-unix-sockets" => NoUnixSockets { platform },
        "socket-path-too-long" => SocketPathTooLong { usable, length },
        "not-granted" => NotGranted { capability, remote },
        "no-channel" => NoChannel { process, program },
        "source-unavailable" => SourceUnavailable { capability, failure },
        "shared" => Shared { capability, with, spot },
        "port-held" => PortHeld { capability, by },
        "off-protocol" => OffProtocol { capability, account },
        "withheld" => Withheld { capability, request },
        "unlisted-site" => UnlistedSite { capability, site },
        "unopenable" => Unopenable { capability, why },
        "callback-held" => CallbackHeld { capability, port },
        "unlisted-credential" => UnlistedCredential { capability, site },
        "not-web" => NotWeb { capability, protocol },
        "cleartext" => Cleartext { capability, site },
        "hushed" => Hushed { capability },
    }
});
choice!(Unopenable {
    unit {
        "too-long" => TooLong,
        "not-url" => NotUrl,
        "scheme" => Scheme,
        "credentials" => Credentials,
        "host" => Host,
    }
});
choice!(Withheld {
    unit {
        "ending" => Ending,
        "every" => Every,
        "unacknowledged" => Unacknowledged,
        "reaching" => Reaching,
        "stopping" => Stopping,
        "long" => Long,
        "uncarriable" => Uncarriable,
        "unforwardable" => Unforwardable,
        "crowded" => Crowded,
        "unlisted" => Unlisted,
        "outdated" => Outdated,
        "unknown" => Unknown,
        "hosted" => Hosted,
        "managing" => Managing,
    }
    one { "unlent" => Unlent, "key-unlent" => KeyUnlent, "elsewhere" => Elsewhere }
});

choice!(Integrity { unit { "low" => Low, "medium" => Medium, "high" => High, "system" => System } });
record!(Origin {
    process,
    logon,
    session,
    integrity
});
choice!(ClientKind {
    unit {
        "command" => Command,
        "terminal" => Terminal,
        "interface" => Interface,
        "viewer" => Viewer,
        "prompt" => Prompt,
    }
});
choice!(Presence {
    unit {
        "present" => Present,
        "card-only" => CardOnly,
        "engaged" => Engaged,
        "away" => Away,
    }
});
choice!(Missing { unit { "refused" => Refused, "no-taskbar" => NoTaskbar } });
choice!(Icon { unit { "shown" => Shown } one { "missing" => Missing } });
choice!(Whereabouts { unit { "away" => Away, "engaged" => Engaged, "full-screen" => FullScreen } });
choice!(PromptKind {
    unit {
        "unknown-host-key" => UnknownHostKey,
        "key-passphrase" => KeyPassphrase,
        "password" => Password,
        "security-key-pin" => SecurityKeyPin,
        "challenge" => Challenge,
        "agent-confirmation" => AgentConfirmation,
        "security-key-touch" => SecurityKeyTouch,
    }
});
choice!(Asking { unit { "person" => Person, "nobody" => Nobody } });
choice!(Given { unit { "text" => Text, "accepted" => Accepted, "declined" => Declined } });
record!(Gave { client, given });
choice!(ChannelEnd {
    unit {
        "closed" => Closed,
        "remote-gone" => RemoteGone,
        "forward-refused" => ForwardRefused,
        "route-not-signed-in" => RouteNotSignedIn,
        "client-absent" => ClientAbsent,
        "nothing-carried" => NothingCarried,
        "slept" => Slept,
        "reshaped" => Reshaped,
    }
    one {
        "needs" => Needs,
        "declined" => Declined,
        "unauthenticated" => Unauthenticated,
        "host-key-changed" => HostKeyChanged,
        "unstarted" => Unstarted,
    }
    fields { "exited" => Exited { status, last } }
});
record!(Release {
    major,
    minor,
    build,
    revision
});
choice!(Finding {
    unit {
        "path-unusable" => PathUnusable,
        "forwarding-blocked" => ForwardingBlocked,
        "forward-refused" => ForwardRefused,
        "agent-autostarts" => AgentAutostarts,
        "keyboxd-stopped" => KeyboxdStopped,
        "signing-key-unset" => SigningKeyUnset,
        "keyring-absent" => KeyringAbsent,
    }
    one {
        "unsurveyed" => Unsurveyed,
        "no-profile" => NoProfile,
        "tool-absent" => ToolAbsent,
        "shared-home" => SharedHome,
        "parent-uncreatable" => ParentUncreatable,
        "occupied" => Occupied,
        "agent-live" => AgentLive,
        "answers" => Answers,
        "silent" => Silent,
        "unprobed" => Unprobed,
        "uncleared" => Uncleared,
        "listener-present" => ListenerPresent,
        "public-key-absent" => PublicKeyAbsent,
        "signing-key-other" => SigningKeyOther,
        "variable-unset" => VariableUnset,
        "their-forward" => TheirForward,
        "helper-beside" => HelperBeside,
        "cache-live" => CacheLive,
    }
    fields {
        "path-too-long" => PathTooLong { usable, length },
        "server-live" => ServerLive { program, at },
        "unwritten" => Unwritten { write, why },
        "unit-listens" => UnitListens { unit, path },
    }
});
choice!(Write {
    unit {
        "no-autostart" => NoAutostart,
        "socket-file" => SocketFile,
        "masked" => Masked,
        "credential-helper" => Helper,
    }
    one {
        "public-key" => PublicKey,
        "signing-key" => SigningKey,
        "variable" => Variable,
    }
});
choice!(Prepared { one { "created" => Created, "removed" => Removed } });
choice!(Readiness { unit { "ready" => Ready } one { "unready" => Unready } });
choice!(Binding {
    one { "socket" => Socket, "port" => Port }
    fields { "socket-file" => SocketFile { file, port } }
});
record!(Serving {
    capability,
    binding
});
choice!(Target {
    one { "loopback" => Loopback, "path" => Path }
    fields { "host" => Host { host, port } }
});
choice!(Opener {
    unit { "grant" => Grant, "again" => Again }
    one { "person" => Person, "check" => Check }
});
choice!(Outcome {
    unit { "covered" => Covered, "abandoned" => Abandoned }
    one {
        "served" => Served,
        "unseen" => Unseen,
        "allowed" => Allowed,
        "refused" => Refused,
    }
});
choice!(Failure {
    unit {
        "unresolved" => Unresolved,
        "unreachable" => Unreachable,
        "mismatched" => Mismatched,
        "unserved" => Unserved,
        "no-address" => NoAddress,
        "foreign" => Foreign,
        "confined" => Confined,
        "unidentified" => Unidentified,
        "unstartable" => Unstartable,
        "unopened" => Unopened,
        "absent" => Absent,
        "busy" => Busy,
        "outdated" => Outdated,
        "occupied" => Occupied,
        "no-tpm" => NoTpm,
    }
});
choice!(Health { unit { "sound" => Sound } one { "failing" => Failing } });
choice!(Carry { unit { "called" => Called, "expired" => Expired, "ended" => Ended } });
choice!(Touch { unit { "off" => Off, "on" => On, "cached" => Cached } });
choice!(SignaturePin { unit { "forced" => Forced, "once" => Once } });
record!(Held { grip, touch });
record!(Card { serial, keys, pin });
impl Wire for Uses {
    fn put(&self) -> Json {
        Json::List(
            self.words()
                .map(|word| Json::Text(word.to_owned()))
                .collect(),
        )
    }

    fn take(json: Json) -> Result<Self, Fault> {
        Vec::<String>::take(json)?
            .into_iter()
            .try_fold(Uses::NONE, |set, word| {
                Uses::from_word(&word)
                    .map(|member| set.with(member))
                    .ok_or_else(|| Fault::new(Miss::Unknown(word)))
            })
    }
}
record!(Key {
    grip,
    fingerprint,
    primary,
    uses,
    user,
    card,
    ssh
});
record!(Keyring { keys, signing });
choice!(Breakdown {
    unit { "hung" => Hung, "unstarted" => Unstarted }
    fields { "exited" => Exited { status } }
});
choice!(Store { unit { "trail" => Trail, "configuration" => Configuration } });
choice!(Item {
    unit { "restarted" => Restarted }
    one {
        "stopped" => Stopped,
        "burst" => Burst,
        "safeguards" => Safeguards,
        "unreadable" => Unreadable,
        "widened" => Widened,
        "unseen" => Unseen,
        "policy" => Policy,
        "unlisted" => Unlisted,
    }
    fields {
        "unready" => Unready { remote, capability },
        "refused" => Refused { remote, refusal },
        "noticed" => Noticed { remote, through },
    }
});
choice!(Event {
    unit { "sleeping" => Sleeping, "woke" => Woke, "offline" => Offline, "online" => Online }
    one { "card" => Card }
    fields {
        "started" => Started { version, origin, after },
        "unreadable" => Unreadable { store, account },
        "attached" => Attached { kind, origin, attends },
        "presence" => Presence { client, presence },
        "icon" => Icon { client, icon },
        "detached" => Detached { client },
        "changed" => Changed { change, by, reach },
        "imported" => Imported { by, reach },
        "paused" => Paused { scope, by },
        "resumed" => Resumed { scope, by },
        "appeared" => Appeared { remote },
        "gone" => Gone { remote },
        "opening" => Opening { remote, with, acknowledged, lends, opener },
        "ran" => Ran { connection, program, release, asking },
        "observed" => Observed { connection, platform },
        "checked" => Checked { connection, capability, readiness },
        "prepared" => Prepared { connection, capability, prepared },
        "wrote" => Wrote { connection, capability, write, place, made },
        "unwrote" => Unwrote { connection, capability, write, place },
        "prompted" => Prompted { connection, kind, words },
        "answered" => Answered { prompt, by },
        "up" => Up { connection, serving },
        "down" => Down { connection, end },
        "disconnected" => Disconnected { remote, by },
        "unlisted" => Unlisted { route, account },
        "turned-away" => TurnedAway { remote, refusal },
        "asked" => Asked { connection, capability, operation, key },
        "held" => Held { request },
        "settled" => Settled { request, outcome },
        "browsed" => Browsed { request, site, callback },
        "uncarried" => Uncarried { request, end },
        "payload" => Payload { request, payload },
        "refuted" => Refuted { connection, capability, site },
        "unreleased" => Unreleased { request },
        "noticed" => Noticed { connection, capability, remark, unheard },
        "held-by" => HeldBy { capability, holder },
        "key-made" => KeyMade { key, name, by },
        "key-deleted" => KeyDeleted { key, name, by },
        "allowed" => Allowed { connection, capability, operation, key, until, by },
        "ruled" => Ruled { connection, scope, mode, by },
        "exercised" => Exercised { connection, capability, proof, by },
        "source" => Source { capability, health },
        "offered" => Offered { capability, keyring },
        "carried" => Carried { connection, capability, carriage, endpoint },
        "dropped" => Dropped { connection, capability, carriage, why },
        "taken" => Taken { request, connection, capability, port, usb },
        "released" => Released { request },
        "put-away" => PutAway { item, by },
        "stopping" => Stopping { by },
        "withdrawn" => Withdrawn { by },
        "restored" => Restored { by },
        "diagnosed" => Diagnosed { level, by },
        "startup" => Startup { starts, found },
        "kept" => Kept { dropped, cut },
        "stated" => Stated { audience, statement },
        "unstated" => Unstated { audience, statement },
        "misread" => Misread { place, unread },
    }
});
choice!(Cut { unit { "horizon" => Horizon, "ceiling" => Ceiling } });
record!(Withdrawal {
    remote,
    left,
    surveying,
    ended
});
record!(SetAside { name, bytes, at });
record!(Bundle {
    version,
    program,
    windows,
    status,
    attention,
    exposure,
    settings,
    activity,
    diagnostics,
    set_aside
});
record!(Form { trail });
record!(Entry {
    seq,
    at,
    tick,
    event
});

choice!(Decision { unit { "once" => Once, "refuse" => Refuse } one { "for" => For } });
choice!(Answer { unit { "accept" => Accept, "decline" => Decline } one { "text" => Text } });
choice!(Hint { unit { "confirm" => Confirm, "notice" => Notice } });
choice!(Request {
    unit {
        "status" => Status,
        "exposure" => Exposure,
        "attention" => Attention,
        "catalogue" => Catalogue,
        "workstation" => Workstation,
        "export" => Export,
        "ports" => Ports,
        "withdraw" => Withdraw,
        "withdrawal" => Withdrawal,
        "restore" => Restore,
        "bundle" => Bundle,
        "stop" => Stop,
    }
    one {
        "change" => Change,
        "import" => Import,
        "pause" => Pause,
        "resume" => Resume,
        "put-away" => PutAway,
        "presence" => Presence,
        "icon" => Icon,
        "try" => Try,
        "devices" => Devices,
        "keys" => Keys,
        "delete-key" => DeleteKey,
        "diagnose" => Diagnose,
    }
    fields {
        "hello" => Hello { protocol, kind, attends },
        "make-key" => MakeKey { name, kind },
        "settings" => Settings { remotes },
        "activity" => Activity { remote, before, limit },
        "follow" => Follow { after },
        "connect" => Connect { remote, with, acknowledged, lends },
        "disconnect" => Disconnect { remote },
        "decide" => Decide { request, decision },
        "answer" => Answer { prompt, answer },
        "prompt" => Prompt { words, hint },
        "rule" => Rule { connection, scope, mode },
        "check" => Check { remote, capability },
        "exercise" => Exercise { remote, capability },
    }
});
choice!(Act {
    unit {
        "connect" => Connect,
        "disconnect" => Disconnect,
        "pause" => Pause,
        "resume" => Resume,
        "revoke" => Revoke,
        "deny" => Deny,
        "accept" => Accept,
        "check" => Check,
        "exercise" => Exercise,
    }
});
choice!(Standing {
    unit { "idle" => Idle, "checking" => Checking, "opening" => Opening, "paused" => Paused }
    one {
        "needs" => Needs,
        "unready" => Unready,
        "serving" => Serving,
        "unavailable" => Unavailable,
        "ended" => Ended,
    }
    fields { "returning" => Returning { end, wait } }
});
record!(Last {
    request,
    at,
    operation,
    outcome
});
record!(Decides {
    operation,
    key,
    mode,
    basis
});
choice!(Through {
    one { "grant" => Grant, "connection" => Connection }
    fields { "start" => Start { audience, grant } }
});
record!(Offered { act, withheld });
record!(Row {
    capability,
    exposure,
    remote,
    connection,
    through,
    standing,
    decides,
    terms,
    holds,
    last,
    findings,
    written,
    carried,
    hold,
    beyond,
    acts
});
record!(CarriedOn { carriage, endpoint });
record!(Hold {
    request,
    port,
    since
});
record!(SerialPort { port, name, usb });
record!(Usb { vendor, product });
record!(Lendable {
    serial,
    model,
    state,
    attached
});
choice!(DeviceState {
    unit {
        "connecting" => Connecting,
        "authorizing" => Authorizing,
        "unauthorized" => Unauthorized,
        "no-permission" => NoPermission,
        "detached" => Detached,
        "offline" => Offline,
        "bootloader" => Bootloader,
        "device" => Device,
        "host" => Host,
        "recovery" => Recovery,
        "sideload" => Sideload,
        "rescue" => Rescue,
    }
    one { "other" => Other }
});
choice!(Attachment { unit { "usb" => Usb, "socket" => Socket } });
choice!(Carriage {
    one { "reverse" => Reverse }
    fields {
        "forward" => Forward { port, device, socket },
        "console" => Console { port, device },
    }
});
choice!(Dropped { unit { "removed" => Removed, "gone" => Gone, "unlent" => Unlent, "taken" => Taken } });
record!(Line { place, text });
record!(Written { write, place, made });
record!(Trial {
    policy,
    document,
    change,
    remotes
});
record!(Loudness { condition, volume });
record!(RemoteSettings {
    remote,
    threshold,
    volumes,
    full_screen,
    caps,
    keepalive,
    returns
});
record!(RouteSettings { route, cadence });
record!(Contact { audience, words });
record!(WorkstationSettings {
    lengths,
    autostart,
    icon,
    windows,
    keep,
    diagnostics,
    contacts,
    unread
});
record!(WindowsStarts { hedwig, icon });
choice!(AtSignIn {
    unit { "as-chosen" => AsChosen, "absent" => Absent }
    one { "another" => Another, "unkept" => Unkept }
});
choice!(Starts { unit { "hedwig" => Hedwig, "icon" => Icon } });
record!(Settings {
    workstation,
    remotes,
    routes
});
record!(Would {
    reach,
    rows,
    remotes,
    workstation
});
choice!(Tried { one { "refused" => Refused, "would" => Would } });
choice!(Attention {
    one { "safeguards" => Safeguards, "withdrawn" => Withdrawn }
    fields {
        "request" => Request { request, remote, capability, operation, key, payload, offers, capped },
        "prompt" => Prompt { prompt, remote, kind, words },
        "unready" => Unready { remote, capability, findings },
        "stopped" => Stopped { remote, end },
        "burst" => Burst { remote, requests },
        "refused" => Refused { remote, refusal, times },
        "restarted" => Restarted { cause, times },
        "unreadable" => Unreadable { store, account },
        "widened" => Widened { entry, kind, origin },
        "unseen" => Unseen { remote, served },
        "policy" => Policy { place, since, arrived, withdrawn, unread },
        "unlisted" => Unlisted { route, account },
        "noticed" => Noticed { remote, notice, at, remark, unheard },
    }
});
record!(Needs { attention, volume });
record!(Served {
    request,
    remote,
    capability,
    operation,
    key,
    payload
});
record!(Attached {
    client,
    kind,
    origin,
    presence,
    icon,
    attends
});
record!(Status {
    version,
    since,
    origin,
    attached,
    paused,
    connected,
    attention,
    network,
    withdrawn
});
choice!(Network { unit { "online" => Online, "offline" => Offline } });
record!(Found {
    capability,
    health,
    holder
});
record!(Offering {
    capability,
    keyring
});
record!(Workstation {
    sources,
    cards,
    running,
    keys
});
record!(SourceHolder {
    program,
    session,
    whose
});
choice!(SignedIn { unit { "locally" => Locally, "over-the-network" => OverTheNetwork } });
choice!(Rights { unit { "standard" => Standard, "administrator" => Administrator } });
choice!(Whose {
    unit { "confined" => Confined, "another" => Another, "unread" => Unread }
    fields {
        "person" => Person { logon, signed_in, rights },
        "service" => Service { services },
    }
});
record!(AgentKey { key, comment });
choice!(Payload {
    unit { "unread" => Unread }
    fields {
        "authentication" => Authentication { user, host },
        "signature" => Signature { namespace },
        "credential" => Credential { site },
    }
});
choice!(Proof { one { "reached" => Reached, "silent" => Silent, "unrun" => Unrun } });
choice!(Reply {
    one {
        "status" => Status,
        "exposure" => Exposure,
        "attention" => Attention,
        "catalogue" => Catalogue,
        "workstation" => Workstation,
        "document" => Document,
        "activity" => Activity,
        "done" => Done,
        "row" => Row,
        "settings" => Settings,
        "tried" => Tried,
        "answer" => Answer,
        "devices" => Devices,
        "keys" => Keys,
        "made" => Made,
        "ports" => Ports,
        "withdrawal" => Withdrawal,
        "bundle" => Bundle,
    }
    fields {
        "welcome" => Welcome { protocol, version, you },
        "changed" => Changed { effect, held },
    }
});
choice!(Topic {
    unit {
        "status" => Status,
        "exposure" => Exposure,
        "attention" => Attention,
        "configuration" => Configuration,
        "workstation" => Workstation,
        "ports" => Ports,
    }
    one { "devices" => Devices, "keys" => Keys }
});
choice!(Withdrawn { one { "request" => Request, "prompt" => Prompt } });
choice!(Notice {
    one {
        "raised" => Raised,
        "served" => Served,
        "withdrawn" => Withdrawn,
        "stale" => Stale,
        "recorded" => Recorded,
        "exercised" => Exercised,
    }
});
record!(Exercised {
    remote,
    capability,
    proof
});
record!(ToCore { id, request });
choice!(FromCore { one { "notice" => Notice } fields { "reply" => Reply { id, reply } } });

record!(Instance { process, created });
choice!(CoreState {
    unit { "starting" => Starting }
    fields {
        "serving" => Serving { pipe, process },
        "restarting" => Restarting { cause, said },
    }
});
record!(Running { supervisor, core });
record!(Diagnostic { at, from, said });
record!(Index { version, files });
record!(Packed { path, bytes });
choice!(Order { unit { "ping" => Ping } fields { "begin" => Begin { after } } });
choice!(Report { unit { "pong" => Pong } fields { "ready" => Ready { pipe } } });

impl Wire for bool {
    fn put(&self) -> Json {
        Json::Bool(*self)
    }

    fn take(json: Json) -> Result<Self, Fault> {
        match json {
            Json::Bool(value) => Ok(value),
            _ => Err(Fault::new(Miss::Expected(Shape::Choice))),
        }
    }
}

/// A tuple is written as a list of its members, in order.
macro_rules! tuple {
    ($($name:ident),+) => {
        impl<$($name: Wire),+> Wire for ($($name,)+) {
            #[allow(non_snake_case, reason = "the members are named for their types")]
            fn put(&self) -> Json {
                let ($($name,)+) = self;
                Json::List(vec![$($name.put()),+])
            }

            #[allow(non_snake_case, reason = "the members are named for their types")]
            fn take(json: Json) -> Result<Self, Fault> {
                let Json::List(items) = json else {
                    return Err(Fault::new(Miss::Expected(Shape::List)));
                };
                let mut items = items.into_iter();
                $(let $name = $name::take(
                    items.next().ok_or_else(|| Fault::new(Miss::Range))?,
                )?;)+
                if items.next().is_some() {
                    return Err(Fault::new(Miss::Range));
                }
                Ok(($($name,)+))
            }
        }
    };
}

tuple!(A, B);
tuple!(A, B, C);
tuple!(A, B, C, D);

/// A map is written as a list of its pairs in key order, and a list that
/// names a key twice is not one.
impl<K: Wire + Ord, V: Wire> Wire for BTreeMap<K, V> {
    fn put(&self) -> Json {
        Json::List(
            self.iter()
                .map(|(key, value)| Json::List(vec![key.put(), value.put()]))
                .collect(),
        )
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let pairs = Vec::<(K, V)>::take(json)?;
        let count = pairs.len();
        let map: BTreeMap<K, V> = pairs.into_iter().collect();
        if map.len() == count {
            Ok(map)
        } else {
            Err(Fault::new(Miss::Repeated))
        }
    }
}

impl<T: Wire> Wire for VecDeque<T> {
    fn put(&self) -> Json {
        Json::List(self.iter().map(Wire::put).collect())
    }

    fn take(json: Json) -> Result<Self, Fault> {
        Vec::<T>::take(json).map(VecDeque::from)
    }
}

record!(Surface {
    kind,
    origin,
    presence,
    icon,
    attends,
    seen
});
choice!(Phase { unit { "opening" => Opening } one { "up" => Up } });
record!(Link {
    remote,
    with,
    acknowledged,
    lends,
    opener,
    phase,
    up,
    platform,
    readiness,
    rules
});
record!(Ask {
    connection,
    capability,
    operation,
    key,
    payload,
    held
});
record!(Prompt {
    connection,
    kind,
    words
});
record!(Noted {
    seq,
    at,
    remark,
    unheard
});
record!(Notices { kept, recent });
record!(Widened {
    entry,
    kind,
    origin
});
record!(Returning {
    failed,
    since,
    hurried
});
record!(Withdrew { entry, at });
record!(Restated {
    since,
    arrived,
    withdrawn
});

impl Wire for Policy {
    fn put(&self) -> Json {
        let (statements, unread) = self.parts();
        Json::Map(vec![
            (key("statements"), statements.put()),
            (key("unread"), unread.put()),
        ])
    }

    fn take(json: Json) -> Result<Self, Fault> {
        let mut fields = Fields::of(json)?;
        let policy = Policy::of_parts(fields.take("statements")?, fields.take("unread")?);
        fields.finish()?;
        Ok(policy)
    }
}

// The whole fold, as a compacted trail carries it in one entry
// (`Event::Kept`): every field, so that folding what follows it gives what
// folding the whole trail gave.
record!(State {
    started,
    surfaces,
    paused,
    running,
    links,
    ended,
    asks,
    prompts,
    allowances,
    recent,
    last,
    unready,
    observed,
    written,
    refused,
    sources,
    cards,
    offered,
    holders,
    startup,
    diagnose,
    carried,
    taken,
    seen,
    put_away,
    notices,
    restarted,
    unreadable,
    widened,
    unseen,
    policy,
    restated,
    asked,
    asked_terms,
    released,
    returning,
    gone,
    unlisted,
    network,
    asleep,
    withdrawn,
});
