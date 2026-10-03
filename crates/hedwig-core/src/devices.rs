//! The devices the workstation's ADB server holds, as its protocol-buffer
//! listing gives them, and which of them a grant lends a remote.
//!
//! The server resolves a selection over every device it holds
//! (`transport.cpp`, `acquire_one_transport`). To a remote it holds only the
//! devices lent: the relay resolves each selection here, over the lent
//! devices alone and by the server's own rules, and sends it on naming the one
//! device found by its transport id, which the server cannot take for another.
//! A listing is the server's own, with every line or entry of a device not
//! lent left out.
//!
//! Everything here is a function of the bytes and the view given to it.

use std::fmt;

use hedwig_model::capability::Lends;
use hedwig_model::holder::SourceHolder;
use hedwig_model::protocol::{Attachment, DeviceState, Lendable};
use hedwig_model::refusal::Withheld;
use hedwig_model::text::{DeviceSerial, Words};
use hedwig_model::trail::Failure;

/// A device's connection state, by the number the server's protocol-buffer
/// listing gives it (`adb_host.proto`, `ConnectionState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct State(pub u64);

impl State {
    /// `NOPERMISSION`: the server skips the device in every selection and
    /// says why instead.
    pub const NO_PERMISSION: State = State(4);
    pub const DEVICE: State = State(8);
}

/// One device as the server lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The server's name for it; empty for a device that reported none.
    pub serial: String,
    pub state: State,
    /// Attached by USB, rather than by a socket: an emulator or a device
    /// connected by its address.
    pub usb: bool,
    pub devpath: String,
    pub product: String,
    pub model: String,
    pub device: String,
    pub id: u64,
}

impl Device {
    /// The serial a grant names it by, where it has one a grant can name.
    pub fn named(&self) -> Option<DeviceSerial> {
        DeviceSerial::try_from(self.serial.as_str()).ok()
    }

    /// How a grant surface lists it.
    pub fn lendable(&self) -> Lendable {
        Lendable {
            serial: self.named(),
            model: Words::try_from(self.model.as_str()).ok(),
            state: DeviceState::numbered(self.state.0),
            attached: if self.usb {
                Attachment::Usb
            } else {
                Attachment::Socket
            },
        }
    }

    /// Whether `lends` lends it.
    pub fn lent(&self, lends: &Lends) -> bool {
        match lends {
            Lends::Every => true,
            Lends::Named { .. } => self.named().is_some_and(|serial| lends.lends(&serial)),
        }
    }

    /// `atransport::MatchesTarget`: whether the server would take `target`
    /// for this device.
    pub fn matches(&self, target: &[u8]) -> bool {
        let name = self.serial.as_bytes();
        if !name.is_empty() {
            if target == name {
                return true;
            }
            if !self.usb && self.matches_address(target) {
                return true;
            }
        }
        target == self.devpath.as_bytes()
            || qualified(target, b"product:", self.product.as_bytes(), false)
            || qualified(target, b"model:", self.model.as_bytes(), true)
            || qualified(target, b"device:", self.device.as_bytes(), false)
    }

    /// A socket transport takes `[tcp:|udp:]<host>[:port]` for its own
    /// address, the port defaulting to its own.
    fn matches_address(&self, target: &[u8]) -> bool {
        let Ok(name) = std::str::from_utf8(self.serial.as_bytes()) else {
            return false;
        };
        let Ok(own) = net_address(name, None) else {
            return false;
        };
        let local = target
            .strip_prefix(b"tcp:")
            .or_else(|| target.strip_prefix(b"udp:"))
            .unwrap_or(target);
        let Ok(local) = std::str::from_utf8(local) else {
            return false;
        };
        net_address(local, own.port)
            .is_ok_and(|theirs| theirs.host == own.host && theirs.port == own.port)
    }
}

/// `qual_match` of `transport.cpp`: `to_test` is `prefix` and then `qual`,
/// each of `qual`'s bytes taken as `_` where `sanitize` and it is not an
/// ASCII letter or digit. An empty `to_test` matches an empty `qual`.
fn qualified(to_test: &[u8], prefix: &[u8], qual: &[u8], sanitize: bool) -> bool {
    if to_test.is_empty() {
        return qual.is_empty();
    }
    if qual.is_empty() {
        return false;
    }
    let Some(rest) = to_test.strip_prefix(prefix) else {
        return false;
    };
    rest.len() == qual.len()
        && rest.iter().zip(qual).all(|(theirs, ours)| {
            let ours = if sanitize && !ours.is_ascii_alphanumeric() {
                b'_'
            } else {
                *ours
            };
            *theirs == ours
        })
}

/// A network address as `android::base::ParseNetAddress` reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAddress {
    pub host: String,
    /// The port written, else the one given as the default; `None` where
    /// neither says one.
    pub port: Option<u16>,
    ipv6: bool,
}

impl NetAddress {
    /// `canonical_address`: how the server names a device it connects to at
    /// this address.
    pub fn canonical(&self, default: u16) -> String {
        let port = self.port.unwrap_or(default);
        if self.ipv6 {
            format!("[{}]:{port}", self.host)
        } else {
            format!("{}:{port}", self.host)
        }
    }
}

/// `ParseNetAddress` (`.ext/libbase/parsenetaddress.cpp`), `port` the value
/// its `port` holds on entry.
///
/// # Errors
///
/// libbase's own words for an address it refuses.
pub fn net_address(address: &str, port: Option<u16>) -> Result<NetAddress, String> {
    let colons = address.matches(':').count();
    let dots = address.matches('.').count();
    let (host, written, ipv6) = if address.starts_with('[') {
        // [::1]:123
        let bad = || format!("bad IPv6 address '{address}'");
        let close = address.find("]:").ok_or_else(bad)?;
        let last = address.rfind("]:").ok_or_else(bad)?;
        (
            address.get(1..close).unwrap_or_default().to_owned(),
            Some(address.get(last + 2..).unwrap_or_default()),
            true,
        )
    } else if dots == 0 && (2..=7).contains(&colons) {
        (address.to_owned(), None, true)
    } else if colons <= 1 {
        let mut pieces = address.split(':');
        let host = pieces.next().unwrap_or_default().to_owned();
        (host, pieces.next(), false)
    } else {
        (String::new(), None, true)
    };
    if host.is_empty() {
        return Err(format!("no host in '{address}'"));
    }
    let port = match written {
        Some(written) => match scanned(written) {
            Some(number @ 1..=65535) => u16::try_from(number).ok(),
            _ => return Err(format!("bad port number '{written}' in '{address}'")),
        },
        None => port,
    };
    Ok(NetAddress { host, port, ipv6 })
}

/// `strtol(text, nullptr, 0)`: leading white space, a sign, then `0x` and
/// hexadecimal digits, `0` and octal ones, or decimal ones; 0 where none.
pub fn strtol(text: &str) -> i64 {
    let text = text.trim_start_matches(c_space);
    let (negative, rest) = match text.as_bytes().first() {
        Some(b'-') => (true, text.get(1..).unwrap_or_default()),
        Some(b'+') => (false, text.get(1..).unwrap_or_default()),
        _ => (false, text),
    };
    let (radix, digits) = if let Some(hex) = rest
        .strip_prefix("0x")
        .or_else(|| rest.strip_prefix("0X"))
        .filter(|hex| hex.bytes().next().is_some_and(|b| b.is_ascii_hexdigit()))
    {
        (16, hex)
    } else if rest.starts_with('0') {
        (8, rest)
    } else {
        (10, rest)
    };
    let end = digits
        .bytes()
        .position(|byte| !char::from(byte).is_digit(radix))
        .unwrap_or(digits.len());
    // Past every port; what this compares is whether a port is positive.
    let number = digits
        .get(..end)
        .and_then(|digits| i64::from_str_radix(digits.get(..digits.len().min(12))?, radix).ok())
        .unwrap_or(0);
    if negative { -number } else { number }
}

/// C's `isspace` in the C locale.
fn c_space(c: char) -> bool {
    c.is_ascii_whitespace() || c == char::from(0x0B)
}

/// `sscanf("%d")`: leading white space, a sign, then the digits that follow,
/// or `None` where none does.
fn scanned(text: &str) -> Option<i64> {
    let text = text.trim_start_matches(c_space);
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, text.get(1..)?),
        Some(b'+') => (false, text.get(1..)?),
        _ => (false, text),
    };
    let end = digits
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(digits.len());
    if end == 0 {
        return None;
    }
    // Ten digits are past every port, and past what this needs to compare.
    let number: i64 = digits.get(..end.min(10))?.parse().ok()?;
    Some(if negative { -number } else { number })
}

/// The devices the server holds, in its listing's order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct View {
    pub devices: Vec<Device>,
    /// Whether the server listed them; where it did not, nothing can be
    /// judged lent.
    pub listing: Listing,
    /// What held the server's port when it was reached for this view.
    pub holder: Option<SourceHolder>,
}

/// Whether the server said which devices it holds, and why not where it did
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    Read,
    /// Nothing was listed: what reaching the server found
    /// ([`Failure::Unreachable`], [`Failure::NoAddress`], and what its holder
    /// is refused as); [`Failure::Mismatched`] where what answered
    /// there lists no devices as an ADB server does; [`Failure::Outdated`]
    /// where it is older than platform-tools 35.0.0, whose `host-features`
    /// names no `devicetracker_proto_format` and which answers no tracker in
    /// protocol buffers.
    Failed(Failure),
}

/// A view nobody has read yet: nothing has answered for it.
impl Default for Listing {
    fn default() -> Listing {
        Listing::Failed(Failure::Unreachable)
    }
}

/// What a protocol-buffer listing cannot be read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the ADB server's listing of its devices could not be read")
    }
}

impl std::error::Error for Unreadable {}

/// One field of a protocol-buffer message: its number, and its value, a
/// number or bytes.
enum Value<'a> {
    Number(u64),
    Bytes(&'a [u8]),
}

/// Walks a protocol-buffer message's fields: total, bounded by the message.
struct Fields<'a>(&'a [u8]);

/// One field read: its number, its value, and the bytes it took.
type Field<'a> = (u64, Value<'a>, &'a [u8]);

fn varint(bytes: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = bytes.split_first()?;
        *bytes = rest;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

impl<'a> Fields<'a> {
    /// The next field, and the bytes it took, or `Err` where the message is
    /// cut or malformed.
    fn next_field(&mut self) -> Option<Result<Field<'a>, Unreadable>> {
        if self.0.is_empty() {
            return None;
        }
        let start = self.0;
        let mut rest = self.0;
        let read = (|| {
            let key = varint(&mut rest)?;
            let value = match key & 7 {
                0 => Value::Number(varint(&mut rest)?),
                1 => {
                    let (eight, after) = rest.split_at_checked(8)?;
                    rest = after;
                    Value::Number(u64::from_le_bytes(eight.try_into().ok()?))
                }
                2 => {
                    let length = usize::try_from(varint(&mut rest)?).ok()?;
                    let (body, after) = rest.split_at_checked(length)?;
                    rest = after;
                    Value::Bytes(body)
                }
                5 => {
                    let (four, after) = rest.split_at_checked(4)?;
                    rest = after;
                    Value::Number(u64::from(u32::from_le_bytes(four.try_into().ok()?)))
                }
                _ => return None,
            };
            Some((key >> 3, value))
        })();
        let Some((number, value)) = read else {
            self.0 = &[];
            return Some(Err(Unreadable));
        };
        let taken = start.len() - rest.len();
        self.0 = rest;
        Some(Ok((number, value, start.get(..taken).unwrap_or_default())))
    }
}

/// `message` with every field numbered in `left_out` left out, the rest byte
/// for byte as they came.
///
/// # Errors
///
/// [`Unreadable`] where the message is cut or malformed.
pub fn without(message: &[u8], left_out: &[u64]) -> Result<Vec<u8>, Unreadable> {
    let mut kept = Vec::with_capacity(message.len());
    let mut fields = Fields(message);
    while let Some(field) = fields.next_field() {
        let (number, _, taken) = field?;
        if !left_out.contains(&number) {
            kept.extend_from_slice(taken);
        }
    }
    Ok(kept)
}

fn text(value: &Value<'_>) -> Result<String, Unreadable> {
    match value {
        Value::Bytes(bytes) => String::from_utf8(bytes.to_vec()).map_err(|_| Unreadable),
        Value::Number(_) => Err(Unreadable),
    }
}

fn number(value: &Value<'_>) -> Result<u64, Unreadable> {
    match value {
        Value::Number(number) => Ok(*number),
        Value::Bytes(_) => Err(Unreadable),
    }
}

/// One `Device` message.
fn device(message: &[u8]) -> Result<Device, Unreadable> {
    let mut found = Device {
        serial: String::new(),
        state: State(0),
        usb: false,
        devpath: String::new(),
        product: String::new(),
        model: String::new(),
        device: String::new(),
        id: 0,
    };
    let mut fields = Fields(message);
    while let Some(field) = fields.next_field() {
        let (number_of, value, _) = field?;
        match number_of {
            1 => found.serial = text(&value)?,
            2 => found.state = State(number(&value)?),
            3 => found.devpath = text(&value)?,
            4 => found.product = text(&value)?,
            5 => found.model = text(&value)?,
            6 => found.device = text(&value)?,
            7 => found.usb = number(&value)? == 1,
            10 => found.id = number(&value)?,
            _ => {}
        }
    }
    Ok(found)
}

impl View {
    /// A `Devices` message, as `host:track-devices-proto-binary` frames
    /// one.
    ///
    /// # Errors
    ///
    /// [`Unreadable`] where it is not one.
    pub fn decode(message: &[u8]) -> Result<View, Unreadable> {
        let mut devices = Vec::new();
        let mut fields = Fields(message);
        while let Some(field) = fields.next_field() {
            match field? {
                (1, Value::Bytes(body), _) => devices.push(device(body)?),
                (1, Value::Number(_), _) => return Err(Unreadable),
                _ => {}
            }
        }
        Ok(View {
            devices,
            listing: Listing::Read,
            holder: None,
        })
    }

    /// A server's listing that could not be had, and why.
    pub fn failed(failure: Failure) -> View {
        View {
            devices: Vec::new(),
            listing: Listing::Failed(failure),
            holder: None,
        }
    }

    pub fn listed(&self) -> bool {
        self.listing == Listing::Read
    }

    /// Why a selection cannot be judged where the server did not list its
    /// devices.
    pub fn unlisted(&self) -> Withheld {
        match self.listing {
            Listing::Failed(Failure::Outdated) => Withheld::Outdated,
            Listing::Read | Listing::Failed(_) => Withheld::Unlisted,
        }
    }

    /// The devices as a grant surface lists them, or why the server listed
    /// none.
    ///
    /// # Errors
    ///
    /// The [`Failure`] the listing failed with.
    pub fn lendable(&self) -> Result<Vec<Lendable>, Failure> {
        match self.listing {
            Listing::Read => Ok(self.devices.iter().map(Device::lendable).collect()),
            Listing::Failed(failure) => Err(failure),
        }
    }

    /// The device the server knows by transport id `id`.
    pub fn by_id(&self, id: u64) -> Option<&Device> {
        self.devices.iter().find(|device| device.id == id)
    }
}

/// How a request selects a device, as the server reads its prefix and its
/// service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// The only device of any kind.
    Any,
    /// The only USB device.
    Usb,
    /// The only device attached by a socket.
    Local,
    /// The device the server takes this text for.
    Target(Vec<u8>),
    /// The device with this transport id.
    Id(u64),
}

/// What a selection comes to among the devices lent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// The one device, which the request is sent on naming.
    One(Device),
    /// No lent device answers to it: the server's own words for that.
    /// `unlent` is the device the server would have taken, where it holds
    /// one the grant does not lend, or `Some(None)` where the selection named
    /// none.
    Missing {
        words: String,
        unlent: Option<Option<DeviceSerial>>,
    },
}

/// What the server says of `selection` where nothing answers to it
/// (`acquire_one_transport`).
pub fn missing(selection: &Selection) -> String {
    match selection {
        Selection::Id(id) => format!("no device with transport id '{id}'"),
        Selection::Target(target) => {
            format!("device '{}' not found", String::from_utf8_lossy(target))
        }
        Selection::Local => "no emulators found".to_owned(),
        Selection::Any => "no devices/emulators found".to_owned(),
        Selection::Usb => "no devices found".to_owned(),
    }
}

/// What the server says of `selection` where more than one device answers
/// to it.
fn ambiguous(selection: &Selection) -> String {
    match selection {
        Selection::Target(target) => format!(
            "more than one device with serial {}",
            String::from_utf8_lossy(target)
        ),
        Selection::Usb => "more than one USB device".to_owned(),
        Selection::Local => "more than one emulator".to_owned(),
        Selection::Any | Selection::Id(_) => "more than one device/emulator".to_owned(),
    }
}

fn answers(device: &Device, selection: &Selection) -> bool {
    match selection {
        Selection::Any => true,
        Selection::Usb => device.usb,
        Selection::Local => !device.usb,
        Selection::Target(target) => device.matches(target),
        Selection::Id(id) => device.id == *id,
    }
}

/// `selection` resolved over the devices `lends` lends, as the server
/// resolves one over all it holds. A device without permission is passed
/// over, as the server passes it over; one lent is still the answer where no
/// other is, so the server says why itself.
pub fn resolve(view: &View, lends: &Lends, selection: &Selection) -> Resolved {
    let answering: Vec<&Device> = view
        .devices
        .iter()
        .filter(|device| answers(device, selection))
        .collect();
    let (lent, unlent): (Vec<&Device>, Vec<&Device>) =
        answering.iter().partition(|device| device.lent(lends));
    let permitted: Vec<&&Device> = lent
        .iter()
        .filter(|device| device.state != State::NO_PERMISSION)
        .collect();
    match (permitted.as_slice(), lent.as_slice()) {
        ([one], _) => Resolved::One((**one).clone()),
        ([], [one, ..]) => Resolved::One((*one).clone()),
        ([_, _, ..], _) => Resolved::Missing {
            words: ambiguous(selection),
            unlent: None,
        },
        ([], []) => {
            let unlent = unlent.first().map(|device| match selection {
                Selection::Any | Selection::Usb | Selection::Local => None,
                Selection::Target(_) | Selection::Id(_) => device.named(),
            });
            Resolved::Missing {
                words: missing(selection),
                unlent,
            }
        }
    }
}

/// Which form a listing takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// `devices`: `serial<TAB>state`.
    Short,
    /// `devices-l`: the serial padded, the state, the device's qualifiers,
    /// and its transport id last.
    Long,
    /// A `Devices` message.
    Binary,
    /// A `Devices` message in protobuf's text format.
    Text,
}

/// One listing's text with only the lines or entries of devices `lends`
/// lends; a line or entry that cannot be told for a device is left out.
/// `view` names the device of each transport id, for the forms that give one.
pub fn kept(listing: &[u8], form: Form, lends: &Lends, view: &View) -> Vec<u8> {
    if matches!(lends, Lends::Every) {
        return listing.to_vec();
    }
    let by_id = |id: Option<u64>| {
        id.and_then(|id| view.by_id(id))
            .is_some_and(|device| device.lent(lends))
    };
    match form {
        Form::Short => lines(listing, |line| {
            line.iter()
                .rposition(|byte| *byte == b'\t')
                .and_then(|tab| line.get(..tab))
                .and_then(|serial| std::str::from_utf8(serial).ok())
                .and_then(|serial| DeviceSerial::try_from(serial).ok())
                .is_some_and(|serial| lends.lends(&serial))
        }),
        Form::Long => lines(listing, |line| {
            let id = line
                .iter()
                .rposition(|byte| *byte == b' ')
                .and_then(|space| line.get(space + 1..))
                .and_then(|last| last.strip_prefix(b"transport_id:"))
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| digits.parse().ok());
            by_id(id)
        }),
        Form::Binary => {
            let mut out = Vec::new();
            let mut fields = Fields(listing);
            while let Some(Ok((number_of, value, taken))) = fields.next_field() {
                let lent = match (number_of, value) {
                    (1, Value::Bytes(body)) => device(body).is_ok_and(|found| found.lent(lends)),
                    _ => false,
                };
                if lent {
                    out.extend_from_slice(taken);
                }
            }
            out
        }
        Form::Text => blocks(listing, by_id),
    }
}

/// The lines of `listing`, each with its line feed, that `keep` keeps.
fn lines(listing: &[u8], keep: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut out = Vec::new();
    for line in listing.split_inclusive(|byte| *byte == b'\n') {
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        if keep(body) {
            out.extend_from_slice(line);
        }
    }
    out
}

/// Protobuf's text format of a `Devices` message: a `device {` line, its
/// fields one to a line, a closing `}`. A string's line break is escaped, so
/// each field is one line. A block is kept where `keep` keeps its transport
/// id.
fn blocks(listing: &[u8], keep: impl Fn(Option<u64>) -> bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut block: Vec<u8> = Vec::new();
    let mut id = None;
    let mut inside = false;
    for line in listing.split_inclusive(|byte| *byte == b'\n') {
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        if !inside {
            if body == b"device {" {
                inside = true;
                block.clear();
                id = None;
                block.extend_from_slice(line);
            }
            continue;
        }
        block.extend_from_slice(line);
        if body == b"}" {
            inside = false;
            if keep(id) {
                out.extend_from_slice(&block);
            }
        } else if let Some(digits) = body.trim_ascii().strip_prefix(b"transport_id: ") {
            id = std::str::from_utf8(digits)
                .ok()
                .and_then(|d| d.parse().ok());
        }
    }
    out
}
