//! The ADB conversation between a remote's client and the workstation's ADB
//! server, as the relay carries it.
//!
//! Until a request hands the stream to a device or to one of the server's
//! own services, the client speaks in requests - four hexadecimal digits
//! giving a length, then that many bytes - and the server answers each. The
//! relay reads each request as the server's own reader does
//! (`sockets.cpp`, `smart_socket_enqueue`), names its service as the server
//! names it, and decides it before the server sees it. To a remote the server
//! holds only the devices its grant lends ([`crate::devices`]): every
//! selection is resolved among them and sent on naming the one found by its
//! transport id, every listing leaves the others out, and nothing changes the
//! server's set of devices but an attachment or a removal of a lent device
//! under the grant's `network`. A request that would end the server, have it
//! reach an address unacknowledged, or stop it is answered here with ADB's
//! `FAIL`; a reverse is carried on to the remote, and a forward listens there.
//!
//! Everything here is a function of the bytes and the view given to it: the
//! relay's threads feed it and carry out what it returns.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

use hedwig_model::capability::Lends;
use hedwig_model::holder::SourceHolder;
use hedwig_model::refusal::Withheld;
use hedwig_model::remote::RemoteId;
use hedwig_model::text::{DeviceSerial, DeviceSocket, Host, Name, Port, RemotePath};
use hedwig_model::trail::{ConnectionId, Failure, Target};
use hedwig_win::Signal;
use hedwig_win::endpoint::{Endpoint, owner};

use crate::channel::Jobs;
use crate::devices::{
    Device, Form, Resolved, Selection, View, kept, missing, net_address, resolve, strtol,
};
use crate::peer::placed;
use crate::relay::{Event, QUEUED, Reach, Relayed, Settle};
use crate::service::{Gate, Service, reach, read_gated};

/// The longest request the relay reads whole: one for the server itself, or a
/// reverse. Invariant: one less than the payload every transport takes
/// (`adb.h`, `MAX_PAYLOAD_V1`), so a reverse never stops the server on the
/// oldest device, and far beyond any request that names a device, an address
/// or a socket.
pub const HELD: usize = 4095;

/// The longest answer the relay reads whole: the server's `OKAY`, then a
/// listing of at most four hexadecimal digits' length.
pub const REPLY: usize = 8 + 0xFFFF;

/// The longest prefix that tells which kind a request is.
const PREFIX: usize = "host-transport-id:".len();

/// The port a device connected by its address is reached at when the
/// address names none (`adb.h`, `DEFAULT_ADB_LOCAL_TRANSPORT_PORT`).
const DEVICE_PORT: u16 = 5555;

/// Which end of the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    Client,
    Server,
}

/// Why the relay stopped carrying a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Breach {
    /// A request whose length is not four hexadecimal digits, or is 0: the
    /// server closes on it.
    Length,
    /// The end spoke when it was not its turn: a client that writes while a
    /// request is with the server, or a server that writes while the client
    /// has the turn.
    OutOfTurn(Side),
    /// The server answered with something no ADB server sends.
    NotAnswer,
    /// The server's answer ran past [`REPLY`].
    LongAnswer,
    /// The end closed in the middle of a request or an answer.
    Cut(Side),
}

impl fmt::Display for Breach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side = |side: &Side| match side {
            Side::Client => "the remote",
            Side::Server => "the ADB server",
        };
        match self {
            Breach::Length => f.write_str("the remote sent a request with a length ADB refuses"),
            Breach::OutOfTurn(at) => write!(f, "{} spoke out of turn", side(at)),
            Breach::NotAnswer => {
                f.write_str("the ADB server answered with something ADB never sends")
            }
            Breach::LongAnswer => f.write_str("the ADB server's answer was too long"),
            Breach::Cut(at) => write!(
                f,
                "{} closed in the middle of a request or its answer",
                side(at)
            ),
        }
    }
}

/// What the remote's grant lends it of the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lending {
    pub lends: Lends,
    /// Whether the grant acknowledges `network`: a remote may then have the
    /// server attach or remove a lent device by its address.
    pub network: bool,
}

/// One of the remote's forwards: `port` on its loopback reaches `socket` on
/// `device` through the server's listener at `server`, which the person's
/// own `adb forward --list` at the workstation shows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Forward {
    pub port: Port,
    pub server: Port,
    pub device: DeviceSerial,
    pub socket: DeviceSocket,
}

/// What the remote has carried on to it through this capability, which a
/// listing names and a removal finds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Carried {
    /// Each reverse, by the endpoint the server names for it.
    pub reverses: Vec<(Port, Target)>,
    pub forwards: Vec<Forward>,
}

/// What the relay does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    ToServer(Vec<u8>),
    ToClient(Vec<u8>),
    /// A reverse to `Target`, held until [`Conversation::carry`] gives the
    /// endpoint it lands on or [`Conversation::withhold`] refuses it.
    Reverse(Target),
    /// The device took the reverse to this target and endpoint.
    Reversed {
        target: Target,
        endpoint: Port,
    },
    /// A request refused here; its `FAIL` is among the outs, and the
    /// conversation is over.
    Withheld(Withheld),
    /// From here everything is carried both ways unread. Nothing the server
    /// has sent is unread when this is given.
    Splice,
    /// The connection uses this lent device from here: what a change to
    /// what the grant lends ends it for.
    Selected(DeviceSerial),
    /// The view may not hold a device the server has just attached: the
    /// relay reads the server's devices afresh and gives the view to
    /// [`Conversation::viewed`].
    Stale,
    /// A wait for a device waits for the server's devices to change, and is
    /// given each new view by [`Conversation::viewed`].
    Await,
    /// A forward the remote asked for at `port` on its loopback, 0 for any,
    /// held until [`Conversation::placed`] gives the port bound there or the
    /// reason none was.
    Forward {
        port: u16,
        device: DeviceSerial,
        socket: DeviceSocket,
    },
    /// The server took the forward, on the device with transport id `id`;
    /// `replaced` is the one it took the place of, at the same port on the
    /// remote.
    Forwarded {
        forward: Forward,
        replaced: Option<Forward>,
        id: u64,
    },
    /// A forward placed on the remote that the server refused, or whose
    /// endpoint the core could not give the server's listener: its carrier
    /// is ended.
    Unplaced(Port),
    /// The forward at this port on the remote is removed.
    Unforwarded(Port),
    /// Every forward of the remote's is removed by the relay, each on a
    /// connection of its own; [`Conversation::removed`] answers the remote.
    RemoveAll(Vec<(u64, Forward)>),
}

/// What a request is, as the server would take it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A switch to a device: the server answers `OKAY`, with the transport's
    /// eight-byte id where `id`, then reads another request.
    Switch { id: bool, selection: Selection },
    /// Refused here.
    Withheld(Withheld),
    /// A reverse to carry on to the remote: the request's text before its
    /// target, and the target.
    Reverse { head: Vec<u8>, target: Target },
    /// A reverse whose answer is read: a listing, or a removal.
    ReverseRead { listing: bool },
    /// Passed, and the stream carried unread after it: a device's service,
    /// or one of the server's that touches no device.
    Passed,
    /// `server-status`: its whole answer read, and passed without the
    /// workstation's own paths.
    Status,
    /// A host service that acts on one device: resolved among those lent and
    /// sent naming it, its answer read whole. `reconnect` answers a device
    /// not there with `OKAY` and the words.
    Selects {
        service: Vec<u8>,
        selection: Selection,
        reconnect: bool,
    },
    /// A listing of the devices, in this form, read whole.
    Listing(Form),
    /// The devices in this form, now and on every change.
    Tracking(Form),
    /// `wait-for-<spec>`: `disconnect` where it waits for the device to go.
    Wait {
        spec: Vec<u8>,
        selection: Selection,
        disconnect: bool,
    },
    /// `connect:`: `serials` are what the server would name the device it
    /// attaches, empty where it attaches none.
    Connect { serials: Vec<String> },
    /// `disconnect:<address>`.
    Disconnect { address: Vec<u8> },
    /// Passed where the grant acknowledges `network`: `pair:` and the mDNS
    /// listings.
    Network,
    /// `forward:`: `local` the remote's own side, `remote` the device's.
    Forward {
        selection: Selection,
        norebind: bool,
        local: Vec<u8>,
        remote: Vec<u8>,
    },
    /// `killforward:<local>`.
    Unforward { local: Vec<u8> },
    /// `killforward-all`.
    UnforwardAll,
    /// `list-forward`.
    ListForwards,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Turn {
    /// The client's next bytes are a request.
    Request,
    /// A passed request's payload still to come from the client.
    Passing(usize),
    /// A switch to `device` is with the server; `asked` is how the remote
    /// selected it, whose words a device gone meanwhile is told in.
    Switching {
        id: bool,
        device: Device,
        asked: Selection,
    },
    /// A reverse waits for the core's word on its target.
    Carrying {
        head: Vec<u8>,
        target: Target,
    },
    /// A reverse is with the device; its whole answer is read.
    Reversing {
        carried: Option<(Target, Port)>,
        listing: bool,
    },
    /// A request sent naming `id` in place of what the remote selected:
    /// its whole answer is read.
    Answering {
        id: u64,
        asked: Selection,
    },
    /// A listing of the devices: its whole answer is read.
    Listing(Form),
    /// The server's status: its whole answer is read.
    Status,
    /// A tracker of the devices: each listing as it comes.
    Tracking {
        form: Form,
        opened: bool,
    },
    /// A wait for a device not yet there.
    Awaiting {
        spec: Vec<u8>,
        selection: Selection,
        disconnect: bool,
    },
    /// The request, held while the relay reads the server's devices afresh.
    Rechecking(Vec<u8>),
    /// A forward waits for its port on the remote.
    Placing {
        device: Device,
        socket: DeviceSocket,
        zero: bool,
    },
    /// A forward on device `id` is with the server; its whole answer is
    /// read.
    Forwarding {
        forward: Forward,
        replaced: Option<Forward>,
        zero: bool,
        id: u64,
    },
    /// The server took the forward at `port` on the remote; `answer` waits
    /// for the core to record it and give its endpoint the server's listener.
    Listening {
        answer: Vec<u8>,
        port: Port,
    },
    /// A removal is with the server; its whole answer is read.
    Unforwarding(Port),
    /// Every forward is being removed.
    Removing,
    /// The server's forwards are listed; its whole answer is read.
    ListingForwards,
    Spliced,
    Over,
}

/// One relayed connection's conversation.
#[derive(Debug)]
pub struct Conversation {
    turn: Turn,
    carried: Carried,
    lending: Lending,
    /// The device a switch selected, which every later request uses.
    selected: Option<Device>,
    /// Whether the held request has been decided against a fresh view.
    rechecked: bool,
    /// A tracker's last listing as the server sent it, read again when what
    /// the grant lends changes.
    tracked: Option<Vec<u8>>,
    client: Vec<u8>,
    server: Vec<u8>,
}

/// The length `digits` give as the server's `unhex` reads them, or `None`
/// where any is not a hexadecimal digit, which the server reads as a length
/// beyond any it accepts.
pub fn length(digits: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(digits).ok()?;
    if text.len() != 4 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(text, 16).ok()
}

/// A request or answer as ADB frames one: four hexadecimal digits, then the
/// text.
pub fn framed(text: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", text.len()).into_bytes();
    out.extend_from_slice(text);
    out
}

/// ADB's refusal: `FAIL`, then the reason framed.
pub fn fail(reason: &str) -> Vec<u8> {
    let mut out = b"FAIL".to_vec();
    out.extend(framed(reason.as_bytes()));
    out
}

/// What the remote's tool is told of a request withheld, as its own client
/// prints a `FAIL`: "error: " and these words. `Ending` takes ADB's own
/// words for a server that rejects `kill` (`adb.cpp`, `handle_host_request`);
/// a device not lent is told in ADB's words for one not there, by the
/// request that asked for it, never by these.
pub fn reason(withheld: &Withheld) -> &'static str {
    match withheld {
        Withheld::Ending => "kill-server rejected by remote server",
        Withheld::Unlent(_) => "Hedwig lends this remote only the devices its grant names",
        Withheld::Every => {
            "Hedwig lets a remote act only on the devices lent to it, never on every device"
        }
        Withheld::Unacknowledged => {
            "Hedwig lets a remote have the workstation's adb server reach the network only \
             where its grant acknowledges network"
        }
        Withheld::Reaching => "Hedwig does not pass an emulator's own request from a remote",
        Withheld::Stopping => "Hedwig refused a request the workstation's adb server stops on",
        Withheld::Long => "Hedwig refused a request longer than any that names a device",
        Withheld::Uncarriable => {
            "Hedwig carries a reverse to a tcp port or a localfilesystem socket on the remote"
        }
        Withheld::Unforwardable => "Hedwig carries a forward from a tcp port on the remote",
        Withheld::Crowded => "Hedwig carries no more for this remote",
        Withheld::Unlisted => "Hedwig cannot read which devices the workstation's adb server holds",
        Withheld::Outdated => {
            "Hedwig lends devices only from an adb server of platform-tools 35.0.0 or later, \
             and the workstation's is older; update platform-tools on the workstation"
        }
        Withheld::Unknown => "Hedwig does not pass a request it does not know",
        // A console's refusal is the console's own `KO`.
        Withheld::Hosted => "Hedwig does not pass that command to an emulator's console",
        // An SSH agent's refusal is that protocol's own failure.
        Withheld::KeyUnlent(_) | Withheld::Elsewhere(_) | Withheld::Managing => {
            "Hedwig does not pass that request"
        }
    }
}

/// `parse_host_service` of `sockets.cpp`: a `host-serial:` request's serial
/// and command, or `None` where the server would close on it.
pub fn host_service(service: &[u8]) -> Option<(&[u8], &[u8])> {
    if service.is_empty() {
        return None;
    }
    // `serial` is always `service[..taken]`, with its last byte a colon.
    let mut taken = 0usize;
    let rest = |taken: usize| service.get(taken..).unwrap_or_default();
    let finish = |taken: usize| {
        let command = rest(taken);
        if taken == 0 || command.is_empty() {
            return None;
        }
        Some((service.get(..taken - 1)?, command))
    };
    for prefix in [
        &b"usb:"[..],
        b"product:",
        b"model:",
        b"device:",
        b"localfilesystem:",
    ] {
        if rest(taken).starts_with(prefix) {
            taken += prefix.len();
            let offset = rest(taken).iter().position(|byte| *byte == b':')?;
            taken += offset + 1;
            return finish(taken);
        }
    }
    if rest(taken).starts_with(b"tcp:") || rest(taken).starts_with(b"udp:") {
        taken += 4;
        if rest(taken).is_empty() {
            return None;
        }
    }
    if rest(taken).starts_with(b"vsock:") {
        let next = rest(taken).iter().position(|byte| *byte == b':')?;
        taken += next + 1;
    }
    let mut found_address = false;
    if rest(taken).first() == Some(&b'[')
        && let Some(end) = rest(taken).iter().position(|byte| *byte == b']')
    {
        taken += end + 1;
        if rest(taken).first() != Some(&b':') {
            return None;
        }
        taken += 1;
        found_address = true;
    }
    if !found_address {
        let offset = rest(taken).iter().position(|byte| *byte == b':')?;
        taken += offset + 1;
    }
    let Some(next) = rest(taken).iter().position(|byte| *byte == b':') else {
        return finish(taken);
    };
    let port = rest(taken).get(..next).unwrap_or_default();
    if port.iter().all(u8::is_ascii_digit) {
        taken += next + 1;
    }
    finish(taken)
}

/// The text up to the first NUL, as a C string ends.
fn until_nul(text: &[u8]) -> &[u8] {
    let end = text
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(text.len());
    text.get(..end).unwrap_or_default()
}

/// Whom a request is for, as `smart_socket_enqueue` reads its prefix.
enum Addressed<'a> {
    /// The server itself, with the service after the prefix and the
    /// selection the prefix makes.
    Server(&'a [u8], Selection),
    /// The server, in a form it closes on before answering.
    Unreadable,
    /// The selected device.
    Device,
}

fn addressed(payload: &[u8]) -> Addressed<'_> {
    if let Some(rest) = payload.strip_prefix(b"host-serial:") {
        return match host_service(rest) {
            Some((serial, command)) => {
                Addressed::Server(command, Selection::Target(serial.to_vec()))
            }
            None => Addressed::Unreadable,
        };
    }
    if let Some(rest) = payload.strip_prefix(b"host-transport-id:") {
        // `ParseUint` of `adb_utils.h` - decimal digits alone - then a colon;
        // the server closes on anything else. An id it would not read is
        // taken as 0, which no transport has, so the command after the colon
        // is still judged: `kill` refused under any spelling of an id.
        let Some(colon) = rest.iter().position(|byte| *byte == b':') else {
            return Addressed::Unreadable;
        };
        let id = rest
            .get(..colon)
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse().ok())
            .unwrap_or(0);
        return match rest.get(colon + 1..) {
            Some(command) => Addressed::Server(command, Selection::Id(id)),
            None => Addressed::Unreadable,
        };
    }
    for (prefix, selection) in [
        (&b"host-usb:"[..], Selection::Usb),
        (b"host-local:", Selection::Local),
        (b"host:", Selection::Any),
    ] {
        if let Some(rest) = payload.strip_prefix(prefix) {
            return Addressed::Server(rest, selection);
        }
    }
    Addressed::Device
}

/// What a switch selects: a transport id from the prefix, else a serial in
/// the service, else the prefix's serial, else a kind the service names, else
/// any (`handle_host_request`, whose switch ignores the prefix's kind).
fn switched(service: &[u8], prefix: &Selection) -> Selection {
    if let Selection::Id(id) = prefix {
        // A legacy `transport-id:` reads its own over the prefix's.
        if let Some(digits) = service.strip_prefix(b"transport-id:")
            && let Some(own) = std::str::from_utf8(digits)
                .ok()
                .and_then(|d| d.parse().ok())
        {
            return Selection::Id(own);
        }
        return Selection::Id(*id);
    }
    if let Some(rest) = service.strip_prefix(b"tport:") {
        if let Some(serial) = rest.strip_prefix(b"serial:") {
            return Selection::Target(serial.to_vec());
        }
        return match (rest, prefix) {
            (_, Selection::Target(serial)) => Selection::Target(serial.clone()),
            (b"usb", _) => Selection::Usb,
            (b"local", _) => Selection::Local,
            _ => Selection::Any,
        };
    }
    if let Some(digits) = service.strip_prefix(b"transport-id:") {
        return std::str::from_utf8(digits)
            .ok()
            .and_then(|digits| digits.parse().ok())
            .map_or(Selection::Id(0), Selection::Id);
    }
    if let Some(serial) = service.strip_prefix(b"transport:") {
        return Selection::Target(serial.to_vec());
    }
    match (service, prefix) {
        (_, Selection::Target(serial)) => Selection::Target(serial.clone()),
        (b"transport-usb", _) => Selection::Usb,
        (b"transport-local", _) => Selection::Local,
        _ => Selection::Any,
    }
}

/// What `connect:<address>` attaches the device as, where it attaches one
/// (`connect_service`, `connect_device`, `connect_emulator`).
fn connected(address: &[u8]) -> Vec<String> {
    let Ok(address) = std::str::from_utf8(address) else {
        return Vec::new();
    };
    if let Some(ports) = address.strip_prefix("emu:") {
        let pieces: Vec<&str> = ports.split(',').collect();
        let [console, adb] = pieces.as_slice() else {
            return Vec::new();
        };
        let console = strtol(console);
        if console <= 0 || strtol(adb) <= 0 {
            return Vec::new();
        }
        return vec![format!("emulator-{console}")];
    }
    if address.starts_with("vsock:") || address.starts_with("localfilesystem:") {
        return vec![address.to_owned()];
    }
    match net_address(address, Some(DEVICE_PORT)) {
        // An mDNS instance is attached by the name it was asked by.
        Ok(parsed) => vec![parsed.canonical(DEVICE_PORT), address.to_owned()],
        Err(_) => Vec::new(),
    }
}

/// The fields of the server's status (`AdbServerStatus`, `adb_host.proto`)
/// that are the workstation's own paths, each naming the person's account:
/// the server's executable, its log, the key store and the known hosts.
const WORKSTATIONS: [u64; 4] = [7, 8, 13, 14];

/// The server's answer to `server-status` without the workstation's paths;
/// an answer that cannot be read is passed as a status that says nothing,
/// and a refusal as it came.
fn status_kept(answer: &[u8]) -> Vec<u8> {
    let Some(text) = answer.strip_prefix(b"OKAY") else {
        return answer.to_vec();
    };
    let status = text
        .get(..4)
        .and_then(length)
        .and_then(|declared| text.get(4..4 + declared))
        .and_then(|status| crate::devices::without(status, &WORKSTATIONS).ok())
        .unwrap_or_default();
    let mut out = b"OKAY".to_vec();
    out.extend(framed(&status));
    out
}

/// What the server would do with a host request's `service`
/// (`handle_host_request`, then `host_service_to_socket`), `prefix` the
/// selection its prefix makes.
fn host_kind(service: &[u8], prefix: Selection) -> Kind {
    if service == b"kill" {
        return Kind::Withheld(Withheld::Ending);
    }
    if service.starts_with(b"transport") || service.starts_with(b"tport:") {
        return Kind::Switch {
            id: service.starts_with(b"tport:"),
            selection: switched(service, &prefix),
        };
    }
    let selects = |reconnect: bool| Kind::Selects {
        service: service.to_vec(),
        selection: prefix.clone(),
        reconnect,
    };
    match service {
        b"version" | b"host-features" => return Kind::Passed,
        b"server-status" => return Kind::Status,
        b"devices" => return Kind::Listing(Form::Short),
        b"devices-l" => return Kind::Listing(Form::Long),
        b"track-devices" => return Kind::Tracking(Form::Short),
        b"track-devices-l" => return Kind::Tracking(Form::Long),
        b"track-devices-proto-binary" => return Kind::Tracking(Form::Binary),
        b"track-devices-proto-text" => return Kind::Tracking(Form::Text),
        b"reconnect-offline" => return Kind::Withheld(Withheld::Every),
        b"features" | b"get-serialno" | b"get-devpath" | b"get-state" | b"attach" | b"detach" => {
            return selects(false);
        }
        b"reconnect" => return selects(true),
        b"mdns:check" | b"mdns:services" | b"track-mdns-services" | b"list-mdns-known-hosts" => {
            return Kind::Network;
        }
        _ => {}
    }
    if service.starts_with(b"emulator:") {
        return Kind::Withheld(Withheld::Reaching);
    }
    if let Some(address) = service.strip_prefix(b"disconnect:") {
        if address.is_empty() {
            return Kind::Withheld(Withheld::Every);
        }
        return Kind::Disconnect {
            address: address.to_vec(),
        };
    }
    if let Some(address) = service.strip_prefix(b"connect:") {
        return Kind::Connect {
            serials: connected(address),
        };
    }
    if service.starts_with(b"pair:") {
        return Kind::Network;
    }
    if let Some(spec) = service.strip_prefix(b"wait-for-") {
        let mut components = spec.split(|byte| *byte == b'-');
        let kind = components.next().unwrap_or_default();
        let states: Vec<&[u8]> = components.collect();
        let selection = match (&prefix, kind) {
            (Selection::Id(_) | Selection::Target(_), _) => prefix.clone(),
            (_, b"usb") => Selection::Usb,
            (_, b"local") => Selection::Local,
            _ => Selection::Any,
        };
        return Kind::Wait {
            spec: spec.to_vec(),
            selection,
            disconnect: states.contains(&&b"disconnect"[..]),
        };
    }
    // `handle_forward_request` reads the service as a C string.
    let forward = until_nul(service);
    if forward == b"list-forward" {
        return Kind::ListForwards;
    }
    if forward == b"killforward-all" {
        return Kind::UnforwardAll;
    }
    if let Some(local) = forward.strip_prefix(b"killforward:") {
        return Kind::Unforward {
            local: local.to_vec(),
        };
    }
    if let Some(body) = forward.strip_prefix(b"forward:") {
        let (norebind, body) = match body.strip_prefix(b"norebind:") {
            Some(body) => (true, body),
            None => (false, body),
        };
        let (local, remote) = match body.iter().position(|byte| *byte == b';') {
            Some(at) => (
                body.get(..at).unwrap_or_default(),
                body.get(at + 1..).unwrap_or_default(),
            ),
            None => (body, &b""[..]),
        };
        return Kind::Forward {
            selection: prefix,
            norebind,
            local: local.to_vec(),
            remote: remote.to_vec(),
        };
    }
    Kind::Withheld(Withheld::Unknown)
}

/// Where a reverse's host side lands on the remote, where the channel's
/// client can carry it there.
pub fn target(spec: &[u8]) -> Option<Target> {
    let spec = std::str::from_utf8(spec).ok()?;
    if let Some(path) = spec
        .strip_prefix("localfilesystem:")
        .or_else(|| spec.strip_prefix("local:"))
    {
        // OpenSSH's `-L` reads a colon as the next field, and only an
        // absolute path is a remote socket to it.
        if !path.starts_with('/') || path.contains(':') {
            return None;
        }
        return RemotePath::try_from(path).ok().map(Target::Path);
    }
    let rest = spec.strip_prefix("tcp:")?;
    let port = |text: &str| {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        text.parse::<u16>()
            .ok()
            .and_then(|n| Port::try_from(n).ok())
    };
    if let Some(port) = port(rest) {
        return Some(Target::Loopback(port));
    }
    let (host, number) = rest.rsplit_once(':')?;
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    Some(Target::Host {
        host: Host::try_from(host).ok()?,
        port: port(number)?,
    })
}

/// The `-L` OpenSSH carries `target` with, from `listen` on the workstation's
/// loopback.
pub fn local_forward(target: &Target, listen: Port) -> String {
    match target {
        Target::Loopback(port) => format!("127.0.0.1:{listen}:localhost:{port}"),
        Target::Host { host, port } if host.as_str().contains(':') => {
            format!("127.0.0.1:{listen}:[{host}]:{port}")
        }
        Target::Host { host, port } => format!("127.0.0.1:{listen}:{host}:{port}"),
        Target::Path(path) => format!("127.0.0.1:{listen}:{path}"),
    }
}

/// The `-R` OpenSSH carries a forward with: `port` on the remote's loopback,
/// 0 for one the remote's server chooses, to `listen` on the workstation's.
pub fn remote_forward(port: u16, listen: Port) -> String {
    format!("{port}:127.0.0.1:{listen}")
}

/// What the server would do with a device request (`connect_to_remote`,
/// `atransport::UpdateReverseConfig`, then the device's `reverse_service`).
fn device_kind(payload: &[u8], length: usize) -> Kind {
    let Some(reverse) = payload.strip_prefix(b"reverse:") else {
        return Kind::Passed;
    };
    if length > HELD {
        return Kind::Withheld(Withheld::Long);
    }
    if let Some(forward) = reverse.strip_prefix(b"forward:") {
        let body = forward.strip_prefix(b"norebind:").unwrap_or(forward);
        let mut pieces = body.split(|byte| *byte == b';');
        let (Some(local), Some(spec), None) = (pieces.next(), pieces.next(), pieces.next()) else {
            // The device refuses it as a bad forward, and nothing listens.
            return Kind::ReverseRead { listing: false };
        };
        if local.is_empty() || spec.is_empty() || spec.first() == Some(&b'*') {
            return Kind::ReverseRead { listing: false };
        }
        return match target(spec) {
            Some(target) => {
                let head_length = payload.len() - spec.len();
                Kind::Reverse {
                    head: payload.get(..head_length).unwrap_or_default().to_vec(),
                    target,
                }
            }
            None => Kind::Withheld(Withheld::Uncarriable),
        };
    }
    if reverse.starts_with(b"killforward:") || reverse == b"killforward-all" {
        return Kind::ReverseRead { listing: false };
    }
    if reverse == b"list-forward" {
        return Kind::ReverseRead { listing: true };
    }
    Kind::Withheld(Withheld::Stopping)
}

/// What a whole request is, from its declared `length` and its payload, or
/// its first bytes, as many as `host-transport-id:` holds, where it is longer
/// than [`HELD`].
pub fn kind(payload: &[u8], length: usize) -> Kind {
    match addressed(payload) {
        Addressed::Server(..) | Addressed::Unreadable if length > HELD => {
            Kind::Withheld(Withheld::Long)
        }
        Addressed::Server(service, selection) => host_kind(service, selection),
        Addressed::Unreadable => Kind::Passed,
        Addressed::Device => device_kind(payload, length),
    }
}

/// A request naming device `id` in place of the remote's selection.
fn naming(id: u64, service: &[u8]) -> Vec<u8> {
    let mut text = format!("host-transport-id:{id}:").into_bytes();
    text.extend_from_slice(service);
    framed(&text)
}

impl Conversation {
    /// A conversation whose opening was served: the client has the turn.
    pub fn opened(carried: Carried, lending: Lending) -> Conversation {
        Conversation {
            turn: Turn::Request,
            carried,
            lending,
            selected: None,
            rechecked: false,
            tracked: None,
            client: Vec::new(),
            server: Vec::new(),
        }
    }

    /// Whether the conversation can carry anything more.
    pub fn open(&self) -> bool {
        self.turn != Turn::Over
    }

    /// Whether everything from here is carried unread.
    pub fn spliced(&self) -> bool {
        self.turn == Turn::Spliced
    }

    /// Whether a reverse waits for the core's word.
    pub fn holds(&self) -> bool {
        matches!(self.turn, Turn::Carrying { .. })
    }

    /// Whether a forward waits for its port on the remote.
    pub fn places(&self) -> bool {
        matches!(self.turn, Turn::Placing { .. })
    }

    /// Whether the server's next bytes are a listing that names its devices
    /// by transport id, which is read against a view taken afresh.
    pub fn lists_by_id(&self) -> bool {
        matches!(
            self.turn,
            Turn::Listing(Form::Long | Form::Text)
                | Turn::Tracking {
                    form: Form::Long | Form::Text,
                    ..
                }
        )
    }

    /// Takes what the client sent.
    ///
    /// # Errors
    ///
    /// The [`Breach`] that ends the conversation; nothing of the request that
    /// breached it was carried.
    pub fn from_client(&mut self, bytes: &[u8], view: &View) -> Result<Vec<Out>, Breach> {
        match &mut self.turn {
            Turn::Spliced => return Ok(vec![Out::ToServer(bytes.to_vec())]),
            Turn::Over => return Ok(Vec::new()),
            Turn::Passing(remaining) => {
                let now = bytes.len().min(*remaining);
                *remaining -= now;
                let mut outs = vec![Out::ToServer(bytes.get(..now).unwrap_or_default().to_vec())];
                if *remaining == 0 {
                    self.turn = Turn::Spliced;
                    let after = bytes.get(now..).unwrap_or_default();
                    if !after.is_empty() {
                        outs.push(Out::ToServer(after.to_vec()));
                    }
                }
                return Ok(outs);
            }
            Turn::Request => {}
            _ => {
                return if bytes.is_empty() {
                    Ok(Vec::new())
                } else {
                    Err(Breach::OutOfTurn(Side::Client))
                };
            }
        }
        self.client.extend_from_slice(bytes);
        self.request(view)
    }

    /// Reads the request in the client's bytes, once enough of it is there to
    /// decide it.
    fn request(&mut self, view: &View) -> Result<Vec<Out>, Breach> {
        let Some(digits) = self.client.get(..4) else {
            return Ok(Vec::new());
        };
        let length = match length(digits) {
            Some(length) if length > 0 => length,
            _ => return Err(Breach::Length),
        };
        let have = self.client.len() - 4;
        let whole = have >= length;
        let decidable = whole || (have >= PREFIX && length > HELD);
        if !decidable {
            return Ok(Vec::new());
        }
        if whole && have > length {
            // The client wrote past its request before it was answered.
            return Err(Breach::OutOfTurn(Side::Client));
        }
        let payload = self.client.get(4..).unwrap_or_default();
        let kind = kind(payload.get(..length.min(have)).unwrap_or_default(), length);
        let request = std::mem::take(&mut self.client);
        Ok(self.decide(kind, request, whole, length - have.min(length), view))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one arm per kind of request, each decided as the server takes it"
    )]
    fn decide(
        &mut self,
        kind: Kind,
        request: Vec<u8>,
        whole: bool,
        remaining: usize,
        view: &View,
    ) -> Vec<Out> {
        let network = self.lending.network;
        match kind {
            Kind::Withheld(withheld) => self.refuse(withheld),
            Kind::Passed if whole => {
                self.turn = Turn::Spliced;
                vec![Out::Splice, Out::ToServer(request)]
            }
            Kind::Passed => {
                self.turn = Turn::Passing(remaining);
                vec![Out::Splice, Out::ToServer(request)]
            }
            Kind::Reverse { head, target } => {
                self.turn = Turn::Carrying {
                    head,
                    target: target.clone(),
                };
                vec![Out::Reverse(target)]
            }
            Kind::ReverseRead { listing } => {
                self.turn = Turn::Reversing {
                    carried: None,
                    listing,
                };
                vec![Out::ToServer(request)]
            }
            Kind::Network if !network => self.refuse(Withheld::Unacknowledged),
            Kind::Network => {
                self.turn = Turn::Spliced;
                vec![Out::Splice, Out::ToServer(request)]
            }
            Kind::Listing(form) => {
                self.turn = Turn::Listing(form);
                vec![Out::ToServer(request)]
            }
            Kind::Tracking(form) => {
                self.turn = Turn::Tracking {
                    form,
                    opened: false,
                };
                vec![Out::ToServer(request)]
            }
            Kind::Connect { .. } | Kind::Disconnect { .. } if !network => {
                self.refuse(Withheld::Unacknowledged)
            }
            Kind::Connect { serials } => self.connect(&serials, request),
            Kind::Disconnect { address } => self.disconnect(&address, request, view),
            Kind::Switch { id, selection } => match self.switch(&selection, request, view) {
                Ok(device) => {
                    let text = if id {
                        format!("host-transport-id:{}:tport:any", device.id)
                    } else {
                        format!("host:transport-id:{}", device.id)
                    };
                    self.turn = Turn::Switching {
                        id,
                        device,
                        asked: selection,
                    };
                    vec![Out::ToServer(framed(text.as_bytes()))]
                }
                Err(outs) => outs,
            },
            Kind::Selects {
                service,
                selection,
                reconnect,
            } => match self.resolved(&selection, request, view) {
                Ok(device) => {
                    self.turn = Turn::Answering {
                        id: device.id,
                        asked: selection,
                    };
                    vec![Out::ToServer(naming(device.id, &service))]
                }
                Err(mut outs) if reconnect => {
                    // `reconnect` answers a device not there with `OKAY`.
                    for out in &mut outs {
                        if let Out::ToClient(bytes) = out
                            && let Some(words) = bytes.strip_prefix(b"FAIL")
                        {
                            let mut answered = b"OKAY".to_vec();
                            answered.extend_from_slice(words);
                            *bytes = answered;
                        }
                    }
                    outs
                }
                Err(outs) => outs,
            },
            Kind::Wait {
                spec,
                selection,
                disconnect,
            } => {
                self.turn = Turn::Awaiting {
                    spec,
                    selection,
                    disconnect,
                };
                self.awaited(view)
            }
            Kind::Forward {
                selection,
                norebind,
                local,
                remote,
            } => match self.resolved(&selection, request, view) {
                Ok(device) => self.forward(device, norebind, &local, &remote),
                Err(outs) => outs,
            },
            Kind::Unforward { local } => self.unforward(&local, view),
            Kind::UnforwardAll => {
                let removing: Vec<(u64, Forward)> = self
                    .carried
                    .forwards
                    .iter()
                    .filter_map(|forward| {
                        let device = view
                            .devices
                            .iter()
                            .find(|device| device.serial == forward.device.as_str())?;
                        Some((device.id, forward.clone()))
                    })
                    .collect();
                self.turn = Turn::Removing;
                vec![Out::RemoveAll(removing)]
            }
            Kind::ListForwards => {
                self.turn = Turn::ListingForwards;
                vec![Out::ToServer(framed(b"host:list-forward"))]
            }
            Kind::Status => {
                self.turn = Turn::Status;
                vec![Out::ToServer(framed(b"host:server-status"))]
            }
        }
    }

    /// The device `selection` comes to among those lent: the one a switch
    /// selected where one did, else resolved in `view`. Where none answers,
    /// the request is held once for a fresh view, then answered in ADB's
    /// words for a device not there.
    fn resolved(
        &mut self,
        selection: &Selection,
        request: Vec<u8>,
        view: &View,
    ) -> Result<Device, Vec<Out>> {
        match &self.selected {
            Some(selected) => Ok(selected.clone()),
            None => self.switch(selection, request, view),
        }
    }

    /// The device `selection` comes to in `view` among those lent, whatever a
    /// switch selected before.
    fn switch(
        &mut self,
        selection: &Selection,
        request: Vec<u8>,
        view: &View,
    ) -> Result<Device, Vec<Out>> {
        if !view.listed() {
            return Err(self.refuse(view.unlisted()));
        }
        match resolve(view, &self.lending.lends, selection) {
            Resolved::One(device) => Ok(device),
            Resolved::Missing { .. } if !self.rechecked => {
                self.rechecked = true;
                self.turn = Turn::Rechecking(request);
                Err(vec![Out::Stale])
            }
            Resolved::Missing { words, unlent } => {
                self.turn = Turn::Over;
                let mut outs = vec![Out::ToClient(fail(&words))];
                if let Some(unlent) = unlent {
                    outs.push(Out::Withheld(Withheld::Unlent(unlent)));
                }
                Err(outs)
            }
        }
    }

    /// `connect:`, under the grant's `network`: passed where the device it
    /// attaches is lent, and where it attaches none, so the server says why.
    fn connect(&mut self, serials: &[String], request: Vec<u8>) -> Vec<Out> {
        let lends = &self.lending.lends;
        let lent = serials.is_empty()
            || serials.iter().any(|serial| {
                DeviceSerial::try_from(serial.as_str()).is_ok_and(|serial| lends.lends(&serial))
            });
        if lent {
            self.turn = Turn::Spliced;
            return vec![Out::Splice, Out::ToServer(request)];
        }
        let named = serials
            .first()
            .and_then(|serial| DeviceSerial::try_from(serial.as_str()).ok());
        self.turn = Turn::Over;
        let words = match &named {
            Some(serial) => {
                format!("Hedwig attaches only a device lent to this remote, not {serial}")
            }
            None => reason(&Withheld::Unlent(None)).to_owned(),
        };
        vec![
            Out::ToClient(fail(&words)),
            Out::Withheld(Withheld::Unlent(named)),
        ]
    }

    /// `disconnect:<address>`, under the grant's `network`: the device the
    /// server would remove, found as it finds one, removed by its serial
    /// where it is lent; refused in the server's words otherwise.
    fn disconnect(&mut self, address: &[u8], request: Vec<u8>, view: &View) -> Vec<Out> {
        let text = String::from_utf8_lossy(address).into_owned();
        if !view.listed() {
            return self.refuse(view.unlisted());
        }
        let serial = if view.devices.iter().any(|device| device.serial == text)
            || text.starts_with("vsock:")
            || text.starts_with("localfilesystem:")
        {
            Ok(text.clone())
        } else {
            net_address(&text, Some(DEVICE_PORT))
                .map(|parsed| parsed.canonical(DEVICE_PORT))
                .map_err(|error| format!("couldn't parse '{text}': {error}"))
        };
        let serial = match serial {
            Ok(serial) => serial,
            Err(words) => {
                self.turn = Turn::Over;
                return vec![Out::ToClient(fail(&words))];
            }
        };
        let found = view.devices.iter().find(|device| device.serial == serial);
        match found {
            Some(device) if device.lent(&self.lending.lends) => {
                self.turn = Turn::Spliced;
                if serial == text {
                    return vec![Out::Splice, Out::ToServer(request)];
                }
                let named = format!("host:disconnect:{serial}");
                vec![Out::Splice, Out::ToServer(framed(named.as_bytes()))]
            }
            None if !self.rechecked => {
                self.rechecked = true;
                self.turn = Turn::Rechecking(request);
                vec![Out::Stale]
            }
            found => {
                self.turn = Turn::Over;
                let mut outs = vec![Out::ToClient(fail(&format!("no such device '{serial}'")))];
                if let Some(device) = found {
                    outs.push(Out::Withheld(Withheld::Unlent(device.named())));
                }
                outs
            }
        }
    }

    /// A wait for a device: sent naming the one lent device it waits on once
    /// there is one, answered here where it waits for one to go and none is
    /// there, and refused where several answer.
    fn awaited(&mut self, view: &View) -> Vec<Out> {
        let Turn::Awaiting {
            spec,
            selection,
            disconnect,
        } = &self.turn
        else {
            return Vec::new();
        };
        let (spec, selection, disconnect) = (spec.clone(), selection.clone(), *disconnect);
        if self.selected.is_none() && !view.listed() {
            return self.refuse(view.unlisted());
        }
        let resolved = match &self.selected {
            Some(selected) => Resolved::One(selected.clone()),
            None => resolve(view, &self.lending.lends, &selection),
        };
        match resolved {
            Resolved::One(device) => {
                let mut service = b"wait-for-".to_vec();
                service.extend_from_slice(&spec);
                self.turn = Turn::Spliced;
                vec![Out::Splice, Out::ToServer(naming(device.id, &service))]
            }
            Resolved::Missing {
                unlent: None,
                words,
            } if words.starts_with("more than one") => {
                self.turn = Turn::Over;
                vec![Out::ToClient(fail(&words))]
            }
            Resolved::Missing { .. } if disconnect => {
                self.turn = Turn::Over;
                vec![Out::ToClient(b"OKAYOKAY".to_vec())]
            }
            Resolved::Missing { .. } => vec![Out::Await],
        }
    }

    /// A new view of the server's devices: a held request decided again, a
    /// wait looked at again, or a tracker's last listing written again.
    pub fn viewed(&mut self, view: &View) -> Vec<Out> {
        match std::mem::replace(&mut self.turn, Turn::Over) {
            Turn::Rechecking(request) => {
                self.turn = Turn::Request;
                self.client = request;
                self.request(view).unwrap_or_default()
            }
            awaiting @ Turn::Awaiting { .. } => {
                self.turn = awaiting;
                self.awaited(view)
            }
            other => {
                self.turn = other;
                Vec::new()
            }
        }
    }

    /// What the grant lends changed: a connection using a device no longer
    /// lent ends, and a tracker's last listing is written again as the grant
    /// now has it.
    pub fn relent(&mut self, lending: Lending, view: &View) -> Vec<Out> {
        self.lending = lending;
        if let Some(selected) = &self.selected
            && !selected.lent(&self.lending.lends)
        {
            self.turn = Turn::Over;
            return Vec::new();
        }
        match (&self.turn, &self.tracked) {
            (Turn::Tracking { form, .. }, Some(last)) => {
                let kept = kept(last, *form, &self.lending.lends, view);
                vec![Out::ToClient(framed(&kept))]
            }
            _ => Vec::new(),
        }
    }

    /// A forward on a lent device: refused where its remote side is not a TCP
    /// port; at a port of the remote's own already, the server's listener
    /// given the new target; otherwise held for its port on the remote.
    fn forward(&mut self, device: Device, norebind: bool, local: &[u8], remote: &[u8]) -> Vec<Out> {
        // The server's own refusal of a malformed forward, after it found
        // the device (`handle_forward_request`).
        let mut body = local.to_vec();
        body.push(b';');
        body.extend_from_slice(remote);
        let bad = || {
            vec![Out::ToClient(fail(&format!(
                "bad forward: {}",
                String::from_utf8_lossy(&body)
            )))]
        };
        if local.is_empty() || remote.is_empty() || remote.first() == Some(&b'*') {
            self.turn = Turn::Over;
            return bad();
        }
        let Some(socket) = std::str::from_utf8(remote)
            .ok()
            .and_then(|remote| DeviceSocket::try_from(remote).ok())
        else {
            self.turn = Turn::Over;
            return bad();
        };
        let Some(port) = local
            .strip_prefix(b"tcp:")
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u16>().ok())
        else {
            return self.refuse(Withheld::Unforwardable);
        };
        let Some(device_serial) = device.named() else {
            return self.refuse(Withheld::Unlent(None));
        };
        let held = self
            .carried
            .forwards
            .iter()
            .find(|forward| forward.port.number() == port && port != 0)
            .cloned();
        match held {
            Some(_) if norebind => {
                self.turn = Turn::Over;
                vec![Out::ToClient(fail("cannot rebind existing socket"))]
            }
            Some(held) => {
                let mut service = format!("forward:tcp:{};", held.server).into_bytes();
                service.extend_from_slice(socket.as_str().as_bytes());
                let forward = Forward {
                    port: held.port,
                    server: held.server,
                    device: device_serial,
                    socket,
                };
                self.turn = Turn::Forwarding {
                    forward,
                    replaced: Some(held),
                    zero: false,
                    id: device.id,
                };
                vec![Out::ToServer(naming(device.id, &service))]
            }
            None => {
                self.turn = Turn::Placing {
                    device,
                    socket: socket.clone(),
                    zero: port == 0,
                };
                vec![Out::Forward {
                    port,
                    device: device_serial,
                    socket,
                }]
            }
        }
    }

    /// The forward held is placed on the remote at `port`, or could not be,
    /// in the words of the remote's server: the server is asked for a
    /// listener of its own choosing to the device.
    pub fn placed(&mut self, placed: Result<Port, String>) -> Vec<Out> {
        let Turn::Placing {
            device,
            socket,
            zero,
        } = std::mem::replace(&mut self.turn, Turn::Over)
        else {
            return Vec::new();
        };
        let port = match placed {
            Ok(port) => port,
            Err(words) => {
                return vec![Out::ToClient(fail(&format!(
                    "cannot bind listener: {words}"
                )))];
            }
        };
        let Some(serial) = device.named() else {
            return vec![Out::Unplaced(port)];
        };
        let mut service = b"forward:tcp:0;".to_vec();
        service.extend_from_slice(socket.as_str().as_bytes());
        self.turn = Turn::Forwarding {
            forward: Forward {
                port,
                // The server's own, read from its answer.
                server: port,
                device: serial,
                socket,
            },
            replaced: None,
            zero,
            id: device.id,
        };
        vec![Out::ToServer(naming(device.id, &service))]
    }

    /// `killforward:`: one of the remote's own forwards is removed from the
    /// server and its carriage ended; another is not there to the remote.
    fn unforward(&mut self, local: &[u8], view: &View) -> Vec<Out> {
        let held = local
            .strip_prefix(b"tcp:")
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| digits.parse::<u16>().ok())
            .and_then(|port| {
                self.carried
                    .forwards
                    .iter()
                    .find(|forward| forward.port.number() == port)
            })
            .cloned();
        let Some(held) = held else {
            self.turn = Turn::Over;
            return vec![Out::ToClient(fail(&format!(
                "listener '{}' not found",
                String::from_utf8_lossy(local)
            )))];
        };
        let device = view
            .devices
            .iter()
            .find(|device| device.serial == held.device.as_str());
        if let Some(device) = device {
            self.turn = Turn::Unforwarding(held.port);
            let service = format!("killforward:tcp:{}", held.server);
            return vec![Out::ToServer(naming(device.id, service.as_bytes()))];
        }
        // The device went, and the server's listener with it.
        self.turn = Turn::Over;
        vec![
            Out::ToClient(b"OKAYOKAY".to_vec()),
            Out::Unforwarded(held.port),
        ]
    }

    /// Every forward of the remote's was removed.
    pub fn removed(&mut self) -> Vec<Out> {
        if self.turn != Turn::Removing {
            return Vec::new();
        }
        self.turn = Turn::Over;
        let mut outs = vec![Out::ToClient(b"OKAYOKAY".to_vec())];
        outs.extend(
            self.carried
                .forwards
                .iter()
                .map(|forward| Out::Unforwarded(forward.port)),
        );
        outs
    }

    fn refuse(&mut self, withheld: Withheld) -> Vec<Out> {
        self.turn = Turn::Over;
        vec![
            Out::ToClient(fail(reason(&withheld))),
            Out::Withheld(withheld),
        ]
    }

    /// The reverse held is carried to `endpoint`: the request goes to the
    /// server naming that endpoint as its host side.
    pub fn carry(&mut self, endpoint: Port) -> Vec<Out> {
        let Turn::Carrying { head, target } = std::mem::replace(&mut self.turn, Turn::Over) else {
            return Vec::new();
        };
        let mut text = head;
        text.extend_from_slice(format!("tcp:{endpoint}").as_bytes());
        self.turn = Turn::Reversing {
            carried: Some((target, endpoint)),
            listing: false,
        };
        vec![Out::ToServer(framed(&text))]
    }

    /// The reverse or forward held is refused.
    pub fn withhold(&mut self, withheld: Withheld) -> Vec<Out> {
        if !self.holds() && !self.places() {
            return Vec::new();
        }
        self.refuse(withheld)
    }

    /// Takes what the server sent.
    ///
    /// # Errors
    ///
    /// The [`Breach`] that ends the conversation.
    pub fn from_server(&mut self, bytes: &[u8], view: &View) -> Result<Vec<Out>, Breach> {
        match &self.turn {
            Turn::Spliced => return Ok(vec![Out::ToClient(bytes.to_vec())]),
            Turn::Over => return Ok(Vec::new()),
            Turn::Switching { .. }
            | Turn::Reversing { .. }
            | Turn::Answering { .. }
            | Turn::Listing(_)
            | Turn::Tracking { .. }
            | Turn::Forwarding { .. }
            | Turn::Unforwarding(_)
            | Turn::ListingForwards
            | Turn::Status => {}
            _ => {
                return if bytes.is_empty() {
                    Ok(Vec::new())
                } else {
                    Err(Breach::OutOfTurn(Side::Server))
                };
            }
        }
        self.server.extend_from_slice(bytes);
        if self.server.len() > REPLY {
            return Err(Breach::LongAnswer);
        }
        match self.turn.clone() {
            Turn::Switching { id, device, asked } => self.switched(id, device, &asked),
            Turn::Tracking { form, opened } => self.tracking(form, opened, view),
            // Every other answer is read until the server closes.
            _ => Ok(Vec::new()),
        }
    }

    /// The server's answer to a switch, once there is enough of it.
    fn switched(
        &mut self,
        id: bool,
        device: Device,
        asked: &Selection,
    ) -> Result<Vec<Out>, Breach> {
        let Some(status) = self.server.get(..4) else {
            return Ok(Vec::new());
        };
        if status == b"OKAY" {
            let whole = if id { 12 } else { 4 };
            if self.server.len() < whole {
                return Ok(Vec::new());
            }
            if self.server.len() > whole {
                return Err(Breach::OutOfTurn(Side::Server));
            }
            self.turn = Turn::Request;
            let serial = device.named();
            self.selected = Some(device);
            let mut outs = vec![Out::ToClient(std::mem::take(&mut self.server))];
            outs.extend(serial.map(Out::Selected));
            return Ok(outs);
        }
        if status != b"FAIL" {
            return Err(Breach::NotAnswer);
        }
        let Some(reason) = self.server.get(4..8).and_then(length) else {
            return if self.server.len() < 8 {
                Ok(Vec::new())
            } else {
                Err(Breach::NotAnswer)
            };
        };
        match self.server.len().cmp(&(8 + reason)) {
            std::cmp::Ordering::Less => Ok(Vec::new()),
            std::cmp::Ordering::Greater => Err(Breach::OutOfTurn(Side::Server)),
            std::cmp::Ordering::Equal => {
                self.turn = Turn::Over;
                let answer = std::mem::take(&mut self.server);
                Ok(vec![Out::ToClient(reworded(answer, device.id, asked))])
            }
        }
    }

    /// A tracker's answer so far: its `OKAY`, then each whole listing, kept
    /// to the devices lent.
    fn tracking(&mut self, form: Form, opened: bool, view: &View) -> Result<Vec<Out>, Breach> {
        let mut outs = Vec::new();
        let mut opened = opened;
        if !opened {
            let Some(status) = self.server.get(..4) else {
                return Ok(outs);
            };
            if status != b"OKAY" {
                // A refusal, read whole when the server closes.
                self.turn = Turn::Answering {
                    id: 0,
                    asked: Selection::Any,
                };
                return Ok(outs);
            }
            self.server.drain(..4);
            outs.push(Out::ToClient(b"OKAY".to_vec()));
            opened = true;
        }
        while let Some(declared) = self.server.get(..4) {
            let Some(declared) = length(declared) else {
                return Err(Breach::NotAnswer);
            };
            let Some(listing) = self.server.get(4..4 + declared) else {
                break;
            };
            let listing = listing.to_vec();
            self.server.drain(..4 + declared);
            outs.push(Out::ToClient(framed(&kept(
                &listing,
                form,
                &self.lending.lends,
                view,
            ))));
            self.tracked = Some(listing);
        }
        self.turn = Turn::Tracking { form, opened };
        Ok(outs)
    }

    /// The server closed.
    ///
    /// # Errors
    ///
    /// [`Breach::Cut`] where it closed in the middle of a switch's answer.
    pub fn server_closed(&mut self, view: &View) -> Result<Vec<Out>, Breach> {
        let answer = std::mem::take(&mut self.server);
        Ok(match std::mem::replace(&mut self.turn, Turn::Over) {
            Turn::Reversing { carried, listing } => self.reversed(answer, carried, listing),
            Turn::Switching { .. } if !answer.is_empty() => return Err(Breach::Cut(Side::Server)),
            Turn::Answering { id, asked } => vec![Out::ToClient(reworded(answer, id, &asked))],
            Turn::Listing(form) => vec![Out::ToClient(self.listing(&answer, form, view))],
            Turn::Forwarding {
                forward,
                replaced,
                zero,
                id,
            } => self.forwarded(&answer, forward, replaced, zero, id),
            Turn::Unforwarding(port) => {
                // Whatever the server says, its listener is gone: removed now,
                // or with its device.
                vec![Out::ToClient(b"OKAYOKAY".to_vec()), Out::Unforwarded(port)]
            }
            Turn::ListingForwards => vec![Out::ToClient(self.forwards_listed(answer))],
            Turn::Status => vec![Out::ToClient(status_kept(&answer))],
            _ => Vec::new(),
        })
    }

    /// A listing's whole answer, kept to the devices lent; a refusal as it
    /// came.
    fn listing(&self, answer: &[u8], form: Form, view: &View) -> Vec<u8> {
        let Some(text) = answer.strip_prefix(b"OKAY") else {
            return answer.to_vec();
        };
        let Some(declared) = text.get(..4).and_then(length) else {
            return answer.to_vec();
        };
        let Some(listing) = text.get(4..4 + declared) else {
            return answer.to_vec();
        };
        let mut out = b"OKAY".to_vec();
        out.extend(framed(&kept(listing, form, &self.lending.lends, view)));
        out
    }

    /// The server's answer to a forward: `OKAY` twice, and the port it bound
    /// where it chose one. Taken, the forward is the core's to record and
    /// listen for, and the remote's answer - the port bound on its own
    /// loopback where it asked for any - waits for [`Conversation::listened`]:
    /// the server's own answer follows its listener (`adb.cpp`,
    /// `install_listener`), and so does the relay's.
    fn forwarded(
        &mut self,
        answer: &[u8],
        mut forward: Forward,
        replaced: Option<Forward>,
        zero: bool,
        id: u64,
    ) -> Vec<Out> {
        let Some(rest) = answer.strip_prefix(b"OKAYOKAY") else {
            let mut outs = vec![Out::ToClient(answer.to_vec())];
            if replaced.is_none() {
                outs.push(Out::Unplaced(forward.port));
            }
            return outs;
        };
        if replaced.is_none() {
            let bound = rest
                .get(..4)
                .and_then(length)
                .and_then(|declared| rest.get(4..4 + declared))
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| digits.parse::<u16>().ok())
                .and_then(|port| Port::try_from(port).ok());
            let Some(bound) = bound else {
                return vec![
                    Out::ToClient(fail("internal error")),
                    Out::Unplaced(forward.port),
                ];
            };
            forward.server = bound;
        }
        let mut answer = b"OKAYOKAY".to_vec();
        if zero {
            answer.extend(framed(forward.port.to_string().as_bytes()));
        }
        self.turn = Turn::Listening {
            answer,
            port: forward.port,
        };
        vec![Out::Forwarded {
            forward,
            replaced,
            id,
        }]
    }

    /// The core recorded the forward the server took and gave its endpoint
    /// the server's listener, or could not, in these words. Only now is the
    /// remote answered; where the endpoint has no listener, the remote reads
    /// ADB's own words for a listener not installed and the carrier is ended.
    pub fn listened(&mut self, listening: Result<(), String>) -> Vec<Out> {
        let Turn::Listening { answer, port } = &self.turn else {
            return Vec::new();
        };
        let (answer, port) = (answer.clone(), *port);
        self.turn = Turn::Over;
        match listening {
            Ok(()) => vec![Out::ToClient(answer)],
            Err(words) => vec![
                Out::ToClient(fail(&format!("cannot bind listener: {words}"))),
                Out::Unplaced(port),
            ],
        }
    }

    /// The server's forwards: those of this remote's, each named by its
    /// port on the remote; no other.
    fn forwards_listed(&self, answer: Vec<u8>) -> Vec<u8> {
        let Some(text) = answer.strip_prefix(b"OKAY") else {
            return answer;
        };
        let Some(lines) = text
            .get(..4)
            .and_then(length)
            .and_then(|declared| text.get(4..4 + declared))
        else {
            return answer;
        };
        let lines = String::from_utf8_lossy(lines);
        let mut written = String::new();
        for line in lines.lines() {
            let mut words = line.splitn(3, ' ');
            let (Some(serial), Some(local), Some(socket)) =
                (words.next(), words.next(), words.next())
            else {
                continue;
            };
            let ours = local
                .strip_prefix("tcp:")
                .and_then(|digits| digits.parse::<u16>().ok())
                .and_then(|server| {
                    self.carried
                        .forwards
                        .iter()
                        .find(|forward| forward.server.number() == server)
                });
            if let Some(forward) = ours {
                let _ = writeln!(written, "{serial} tcp:{} {socket}", forward.port);
            }
        }
        let mut out = b"OKAY".to_vec();
        out.extend(framed(written.as_bytes()));
        out
    }

    /// The client closed.
    ///
    /// # Errors
    ///
    /// [`Breach::Cut`] where it closed in the middle of a request.
    pub fn client_closed(&mut self) -> Result<(), Breach> {
        let cut = matches!(self.turn, Turn::Request) && !self.client.is_empty()
            || matches!(self.turn, Turn::Passing(_));
        self.turn = Turn::Over;
        if cut {
            Err(Breach::Cut(Side::Client))
        } else {
            Ok(())
        }
    }

    /// The device's whole answer to a reverse, for the client: a listing with
    /// each endpoint of this remote's named as the target it carries to.
    fn reversed(
        &self,
        answer: Vec<u8>,
        carried: Option<(Target, Port)>,
        listing: bool,
    ) -> Vec<Out> {
        let mut outs = Vec::new();
        if let Some((target, endpoint)) = carried
            && answer.starts_with(b"OKAYOKAY")
        {
            outs.push(Out::Reversed { target, endpoint });
        }
        let answer = if listing {
            self.reverses_listed(&answer).unwrap_or(answer)
        } else {
            answer
        };
        outs.insert(0, Out::ToClient(answer));
        outs
    }

    /// A reverse listing - `OKAY`, then lines of serial, device side and host
    /// side - with the host side of each of this remote's endpoints written as
    /// the target it carries to.
    fn reverses_listed(&self, answer: &[u8]) -> Option<Vec<u8>> {
        let text = answer.strip_prefix(b"OKAY")?;
        let declared = length(text.get(..4)?)?;
        let lines = text.get(4..)?;
        if lines.len() != declared {
            return None;
        }
        let lines = std::str::from_utf8(lines).ok()?;
        let mut written = String::new();
        for line in lines.split_inclusive('\n') {
            let (body, end) = line
                .strip_suffix('\n')
                .map_or((line, ""), |body| (body, "\n"));
            let named = body.rsplit_once(' ').and_then(|(before, spec)| {
                let endpoint = spec.strip_prefix("tcp:")?.parse::<u16>().ok()?;
                let (_, target) = self
                    .carried
                    .reverses
                    .iter()
                    .find(|(port, _)| port.number() == endpoint)?;
                Some(format!("{before} {target}"))
            });
            written.push_str(named.as_deref().unwrap_or(body));
            written.push_str(end);
        }
        let mut out = b"OKAY".to_vec();
        out.extend(framed(written.as_bytes()));
        Some(out)
    }
}

/// The server's answer to a request sent naming device `id`, in the words it
/// would have used for what the remote asked where the device went
/// meanwhile.
fn reworded(answer: Vec<u8>, id: u64, asked: &Selection) -> Vec<u8> {
    let gone = fail(&missing(&Selection::Id(id)));
    if answer == gone && *asked != Selection::Id(id) {
        return fail(&missing(asked));
    }
    answer
}

/// The request a watch keeps open: every listing of the server's devices, in
/// the form that names each field.
const TRACK: &[u8] = b"host:track-devices-proto-binary";

/// Reads one framed listing: four hexadecimal digits, then that many bytes.
fn listing(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut digits = [0u8; 4];
    stream.read_exact(&mut digits)?;
    let declared = length(&digits).ok_or_else(|| io::Error::other("not a listing"))?;
    let mut body = vec![0u8; declared];
    stream.read_exact(&mut body)?;
    Ok(body)
}

/// What a server that answers [`TRACK`] names among its `host-features`
/// (`.ext/adb/transport.cpp:102`, `kFeatureDeviceTrackerProtoFormat`).
const TRACKER_FEATURE: &[u8] = b"devicetracker_proto_format";

/// Sends one host request on a connection of the relay's own: the stream,
/// its `OKAY` read, or `None` where the server answered anything else.
///
/// # Errors
///
/// What reaching the server found; [`Failure::Mismatched`] where what
/// answered there did not answer as an ADB server does.
fn asked(server: &Service, request: &[u8]) -> Reach<Option<TcpStream>> {
    let reached = reach(server);
    let result = reached.result.and_then(|mut stream| {
        let mut status = [0u8; 4];
        stream
            .set_read_timeout(Some(crate::PATIENCE))
            .and_then(|()| stream.write_all(&framed(request)))
            .and_then(|()| stream.read_exact(&mut status))
            .map_err(|_| Failure::Mismatched)?;
        Ok((&status == b"OKAY").then_some(stream))
    });
    Reach {
        result,
        holder: reached.holder,
    }
}

/// Opens a tracker of the server's devices: its `OKAY` read. A server that
/// refuses it is read as older than platform-tools 35.0.0 only where its
/// `host-features` names no tracker; else what refuses it lists no devices as
/// an ADB server does.
fn tracker(server: &Service) -> Reach<TcpStream> {
    let asked = asked(server, TRACK);
    let result = match asked.result {
        Ok(Some(stream)) => Ok(stream),
        Ok(None) if outdated(server) => Err(Failure::Outdated),
        Ok(None) => Err(Failure::Mismatched),
        Err(failure) => Err(failure),
    };
    Reach {
        result,
        holder: asked.holder,
    }
}

/// Whether the server's `host-features` answer leaves out
/// [`TRACKER_FEATURE`].
fn outdated(server: &Service) -> bool {
    let features = asked(server, b"host:host-features")
        .result
        .ok()
        .flatten()
        .ok_or_else(|| io::Error::other("no features"))
        .and_then(|mut stream| {
            let body = listing(&mut stream);
            let _ = stream.shutdown(Shutdown::Both);
            body
        });
    features.is_ok_and(|features| {
        !features
            .split(|byte| *byte == b',')
            .any(|feature| feature == TRACKER_FEATURE)
    })
}

/// The server's devices as it lists them now, on a connection of the
/// relay's own; unlisted where it cannot say, with why; with what held the
/// server's port.
pub fn query(server: &Service) -> View {
    let tracked = tracker(server);
    let view = match tracked.result {
        Ok(mut stream) => {
            let body = listing(&mut stream);
            let _ = stream.shutdown(Shutdown::Both);
            body.ok()
                .and_then(|body| View::decode(&body).ok())
                .unwrap_or_else(|| View::failed(Failure::Mismatched))
        }
        Err(failure) => View::failed(failure),
    };
    View {
        holder: tracked.holder,
        ..view
    }
}

#[derive(Debug, Default)]
struct Watched {
    view: View,
    /// Whether a tracker holds the view current.
    live: bool,
    /// The tracker's connection, which ending the watch shuts.
    stream: Option<TcpStream>,
    /// Relays waiting for the next change.
    waiting: Vec<SyncSender<Event>>,
}

/// The devices one ADB capability's server holds, kept current by a tracker
/// of the core's own while the capability is carried to any remote: what
/// each selection is resolved in, and what the deciding thread is told of so
/// a forward ends with its device and a lent emulator's console is carried.
pub struct Watch {
    server: Service,
    watched: Mutex<Watched>,
    tell: Box<dyn Fn(&View) + Send + Sync>,
}

impl fmt::Debug for Watch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Watch")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl Watch {
    /// A watch of `server`; `tell` is given each listing.
    pub fn new(server: Service, tell: impl Fn(&View) + Send + Sync + 'static) -> Arc<Watch> {
        Arc::new(Watch {
            server,
            watched: Mutex::new(Watched::default()),
            tell: Box::new(tell),
        })
    }

    /// The current view: the tracker's, else one read now.
    pub fn view(&self) -> View {
        let held = self
            .watched
            .lock()
            .ok()
            .filter(|watched| watched.live)
            .map(|watched| watched.view.clone());
        held.unwrap_or_else(|| self.fresh())
    }

    /// A view read now, on a connection of its own.
    pub fn fresh(&self) -> View {
        query(&self.server)
    }

    /// Has the next change wake `relay`.
    pub(crate) fn notify(&self, relay: SyncSender<Event>) {
        if let Ok(mut watched) = self.watched.lock() {
            watched.waiting.push(relay);
        }
    }

    /// Starts the tracker where none holds the view.
    pub fn ensure(self: &Arc<Self>) {
        let Ok(mut watched) = self.watched.lock() else {
            return;
        };
        if watched.live {
            return;
        }
        let tracked = tracker(&self.server);
        let holder = tracked.holder;
        let mut stream = match tracked.result {
            Ok(stream) => stream,
            // What the server is, or what holds its port, is told; a server
            // not there yet is not, since its first connection starts it.
            Err(
                failure @ (Failure::Outdated
                | Failure::Mismatched
                | Failure::Confined
                | Failure::Foreign
                | Failure::Unidentified),
            ) => {
                drop(watched);
                (self.tell)(&View {
                    holder,
                    ..View::failed(failure)
                });
                return;
            }
            Err(_) => return,
        };
        // The tracker sends the whole list at once: the watch is live only
        // with it in hand, so no decision reads an empty view meanwhile.
        let Some(first) = listing(&mut stream)
            .ok()
            .and_then(|body| View::decode(&body).ok())
        else {
            return;
        };
        // Every listing on this tracker is the one server's, so each view
        // carries what held its port when the tracker reached it.
        let first = View {
            holder: holder.clone(),
            ..first
        };
        let Ok(held) = stream.try_clone() else {
            return;
        };
        watched.view = first.clone();
        watched.live = true;
        watched.stream = Some(held);
        drop(watched);
        (self.tell)(&first);
        let watch = Arc::clone(self);
        thread::spawn(move || watch.track(stream, holder.as_ref()));
    }

    /// Keeps the view current from the tracker's listings; when the tracker
    /// ends other than by [`Watch::end`], the view is told as failed: the
    /// server went away, or sent what no ADB server lists.
    fn track(&self, mut stream: TcpStream, holder: Option<&SourceHolder>) {
        let _ = stream.set_read_timeout(None);
        let ended = loop {
            let Ok(body) = listing(&mut stream) else {
                break Failure::Unreachable;
            };
            let Ok(view) = View::decode(&body) else {
                break Failure::Mismatched;
            };
            let view = View {
                holder: holder.cloned(),
                ..view
            };
            let waiting = match self.watched.lock() {
                Ok(mut watched) => {
                    watched.view = view.clone();
                    std::mem::take(&mut watched.waiting)
                }
                Err(_) => return,
            };
            for relay in waiting {
                let _ = relay.try_send(Event::Viewed);
            }
            (self.tell)(&view);
        };
        let Ok(mut watched) = self.watched.lock() else {
            return;
        };
        watched.live = false;
        let ended_here = watched.stream.take().is_some();
        for relay in std::mem::take(&mut watched.waiting) {
            let _ = relay.try_send(Event::Viewed);
        }
        drop(watched);
        if ended_here {
            (self.tell)(&View::failed(ended));
        }
    }

    /// Ends the tracker.
    pub fn end(&self) {
        if let Ok(mut watched) = self.watched.lock()
            && let Some(stream) = watched.stream.take()
        {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// Removes one of the server's forwards, on a connection of the relay's own.
pub fn unlisten(server: &Service, id: u64, listener: Port) {
    let Ok(mut stream) = reach(server).result else {
        return;
    };
    let _ = stream.set_read_timeout(Some(crate::PATIENCE));
    let service = format!("killforward:tcp:{listener}");
    if stream.write_all(&naming(id, service.as_bytes())).is_ok() {
        let mut answer = Vec::new();
        let _ = stream.take(REPLY as u64).read_to_end(&mut answer);
    }
}

/// Carries one admitted connection to the workstation's ADB server. `tell`
/// reaches the deciding thread. Returns where the deciding thread settles the
/// connection's opening and the run gives a held reverse its endpoint, a held
/// forward its port on the remote, and a change to what the grant lends; the
/// connection itself runs on threads of its own.
pub fn carry(
    client: TcpStream,
    service: Service,
    carried: Carried,
    lending: Lending,
    watch: Arc<Watch>,
    tell: impl Fn(Relayed) + Send + 'static,
) -> Arc<Settle> {
    let (events, queue) = mpsc::sync_channel(QUEUED);
    let settle = Arc::new(Settle::new(events.clone()));
    let held = Arc::clone(&settle);
    thread::spawn(move || {
        let opened = Opened {
            carried,
            lending,
            watch,
        };
        run(&client, &service, opened, &tell, &events, &queue, &held);
        tell(Relayed::Ended);
    });
    settle
}

/// What a connection's conversation starts from.
struct Opened {
    carried: Carried,
    lending: Lending,
    watch: Arc<Watch>,
}

fn run(
    client: &TcpStream,
    service: &Service,
    opened: Opened,
    tell: &impl Fn(Relayed),
    events: &SyncSender<Event>,
    queue: &Receiver<Event>,
    settle: &Settle,
) {
    let reached = reach(service);
    reached.tell(tell);
    let Ok(server) = reached.result else {
        crate::relay::wait(queue, settle);
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    opened.watch.ensure();
    let gate = Arc::new(Gate::default());
    let Ok(reader) = client.try_clone() else {
        return;
    };
    {
        let (events, gate) = (events.clone(), Arc::clone(&gate));
        thread::spawn(move || read_gated(reader, &events, &gate));
    }
    let mut early = Vec::new();
    let word = loop {
        if let Some(word) = settle.take() {
            break Some(word);
        }
        match queue.recv() {
            Ok(Event::Client(bytes)) => early.extend_from_slice(&bytes),
            Ok(Event::ClientClosed) | Err(_) => break None,
            Ok(_) => {}
        }
    };
    gate.open();
    if word != Some(Ok(())) {
        // Refused, or the remote gave up first: nothing reaches the server
        // and nothing is written back.
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
        return;
    }
    let ends = Ends {
        client,
        server: &server,
        service,
        events,
        queue,
        settle,
    };
    converse(&ends, early, opened, tell);
}

/// A connection's two ends and what reaches its thread.
struct Ends<'a> {
    client: &'a TcpStream,
    server: &'a TcpStream,
    service: &'a Service,
    events: &'a SyncSender<Event>,
    queue: &'a Receiver<Event>,
    settle: &'a Settle,
}

/// Reads the server until it closes: to the conversation while it reads the
/// server, straight to the client once the stream is spliced.
fn read_server(
    mut from: TcpStream,
    mut to: TcpStream,
    spliced: &AtomicBool,
    events: &SyncSender<Event>,
) {
    let mut buffer = [0u8; 8192];
    loop {
        let read = from.read(&mut buffer);
        if spliced.load(Ordering::Acquire) {
            match read {
                Ok(0) => {
                    let _ = to.shutdown(Shutdown::Write);
                    return;
                }
                Ok(read) => {
                    if to
                        .write_all(buffer.get(..read).unwrap_or_default())
                        .is_err()
                    {
                        let _ = from.shutdown(Shutdown::Both);
                        return;
                    }
                }
                Err(_) => {
                    let _ = to.shutdown(Shutdown::Both);
                    return;
                }
            }
            continue;
        }
        let event = match read {
            Ok(0) | Err(_) => Event::AgentClosed,
            Ok(read) => Event::Agent(buffer.get(..read).unwrap_or_default().to_vec()),
        };
        let last = matches!(event, Event::AgentClosed);
        if events.send(event).is_err() || last {
            return;
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one connection's loop: every event it is told, and every out it carries out"
)]
fn converse(ends: &Ends<'_>, early: Vec<u8>, opened: Opened, tell: &impl Fn(Relayed)) {
    let Opened {
        carried,
        lending,
        watch,
    } = opened;
    let (client, server) = (ends.client, ends.server);
    let spliced = Arc::new(AtomicBool::new(false));
    let (Ok(from), Ok(to), Ok(mut to_client), Ok(mut to_server)) = (
        server.try_clone(),
        client.try_clone(),
        client.try_clone(),
        server.try_clone(),
    ) else {
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
        return;
    };
    let reading = {
        let (spliced, events) = (Arc::clone(&spliced), ends.events.clone());
        thread::spawn(move || read_server(from, to, &spliced, &events))
    };
    let mut talk = Conversation::opened(carried, lending);
    let mut pending = vec![Event::Client(early)];
    let mut client_done = false;
    'carry: loop {
        let event = match pending.pop() {
            Some(event) => event,
            None => match ends.queue.recv() {
                Ok(event) => event,
                Err(_) => break,
            },
        };
        let outs = match event {
            Event::Client(bytes) if bytes.is_empty() => Ok(Vec::new()),
            // A spliced stream's bytes are the device's: nothing is judged.
            Event::Client(bytes) if talk.spliced() => Ok(vec![Out::ToServer(bytes)]),
            Event::Client(bytes) => talk.from_client(&bytes, &watch.view()),
            Event::Agent(bytes) => {
                let view = if talk.lists_by_id() {
                    watch.fresh()
                } else {
                    watch.view()
                };
                talk.from_server(&bytes, &view)
            }
            Event::ClientClosed => {
                client_done = true;
                talk.client_closed().map(|()| Vec::new())
            }
            Event::AgentClosed => talk.server_closed(&watch.view()),
            Event::Called => Ok(Vec::new()),
            Event::Viewed => Ok(talk.viewed(&watch.view())),
            Event::Settled => match settled(&mut talk, ends.settle, &watch) {
                Some(outs) => Ok(outs),
                // The device it uses is no longer lent.
                None => break,
            },
        };
        let mut outs = match outs {
            Ok(outs) => outs,
            Err(breach) => {
                tell(Relayed::Misframed(breach));
                break;
            }
        };
        let mut at = 0;
        while let Some(out) = outs.get(at).cloned() {
            at += 1;
            let carried = match out {
                Out::ToServer(bytes) => to_server.write_all(&bytes).is_ok(),
                Out::ToClient(bytes) => to_client.write_all(&bytes).is_ok(),
                Out::Splice => {
                    spliced.store(true, Ordering::Release);
                    true
                }
                Out::Stale => {
                    outs.extend(talk.viewed(&watch.fresh()));
                    true
                }
                Out::Await => {
                    watch.notify(ends.events.clone());
                    true
                }
                Out::RemoveAll(removing) => {
                    for (id, forward) in removing {
                        unlisten(ends.service, id, forward.server);
                    }
                    outs.extend(talk.removed());
                    true
                }
                told => {
                    tell(relayed(told));
                    true
                }
            };
            if !carried {
                break 'carry;
            }
        }
        if client_done {
            if spliced.load(Ordering::Acquire) {
                // The client's close is passed on; the server's answer still
                // reaches the client until the server closes too.
                let _ = server.shutdown(Shutdown::Write);
                let _ = reading.join();
            }
            break;
        }
        if !talk.open() && !spliced.load(Ordering::Acquire) {
            break;
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = server.shutdown(Shutdown::Both);
}

/// What the run or the deciding thread settled on the connection's held
/// request, or a change to what the grant lends; `None` where the connection
/// ends for it.
fn settled(talk: &mut Conversation, settle: &Settle, watch: &Watch) -> Option<Vec<Out>> {
    let mut outs = Vec::new();
    if let Some(lending) = settle.take_lending() {
        outs.extend(talk.relent(lending, &watch.view()));
        if !talk.open() {
            return None;
        }
    }
    match settle.take_endpoint() {
        Some(Ok(endpoint)) if talk.holds() => outs.extend(talk.carry(endpoint)),
        Some(Err(Some(withheld))) if talk.holds() || talk.places() => {
            outs.extend(talk.withhold(withheld));
        }
        // No endpoint could be bound: the workstation's side failed, and
        // the connection ends with nothing more said.
        Some(Err(None)) if talk.holds() => return None,
        _ => {}
    }
    if let Some(placed) = settle.take_placed() {
        outs.extend(talk.placed(placed));
    }
    if let Some(listening) = settle.take_listening() {
        outs.extend(talk.listened(listening));
    }
    Some(outs)
}

/// What the deciding thread is told of an out the relay does not carry out
/// itself.
fn relayed(out: Out) -> Relayed {
    match out {
        Out::Reverse(target) => Relayed::Reverse(target),
        Out::Reversed { target, endpoint } => Relayed::Reversed { target, endpoint },
        Out::Withheld(withheld) => Relayed::Withheld(withheld),
        Out::Selected(serial) => Relayed::Selected(serial),
        Out::Forward {
            port,
            device,
            socket,
        } => Relayed::Forward {
            port,
            device,
            socket,
        },
        Out::Forwarded {
            forward,
            replaced,
            id,
        } => Relayed::Forwarded {
            forward,
            replaced,
            id,
        },
        Out::Unplaced(port) => Relayed::Unplaced(port),
        Out::Unforwarded(port) => Relayed::Unforwarded(port),
        // Carried out by the relay itself.
        Out::ToServer(_)
        | Out::ToClient(_)
        | Out::Splice
        | Out::Stale
        | Out::Await
        | Out::RemoveAll(_) => Relayed::Ended,
    }
}

/// How many things one remote may have carried on to it through a
/// capability's carriers in a run: reverses, forwards and consoles together.
/// Invariant: each is a connection of the route's client of its own, and
/// they all start again together when the remote's channel comes back; with
/// the channel's and its survey's own, eight stay under the ten unfinished
/// connections at which OpenSSH's server begins refusing new ones by default
/// (`MaxStartups 10:30:100`).
pub const CARRIED: usize = 8;

/// A reverse one ADB capability carried on to one remote, to one target. Each
/// capability names its own server, which alone its endpoint admits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reverse {
    pub remote: RemoteId,
    pub capability: Name,
    pub target: Target,
}

/// One carried reverse: the endpoint the workstation's ADB server reaches it
/// through, held for the run, and the carrier behind it while the remote's
/// channel is up.
#[derive(Debug)]
struct Held {
    port: Port,
    server: Service,
    /// The channel whose job holds the carrier, and the port it listens on.
    carrier: Mutex<Option<(ConnectionId, Port)>>,
}

/// Every carried reverse's endpoint.
#[derive(Debug, Default)]
pub struct Carriage {
    endpoints: Mutex<BTreeMap<Reverse, Arc<Held>>>,
}

impl Carriage {
    /// The endpoint of `reverse`, bound now where it has none. A connection
    /// to it is carried to the remote only where it comes from the process
    /// listening at `server` - the capability's ADB server - and only through
    /// a carrier in the remote's channel's job.
    ///
    /// # Errors
    ///
    /// What the system said when binding.
    pub fn endpoint(&self, reverse: Reverse, server: Service, jobs: &Jobs) -> io::Result<Port> {
        let mut endpoints = self
            .endpoints
            .lock()
            .map_err(|_| io::Error::other("the carriage was poisoned"))?;
        if let Some(found) = endpoints.get(&reverse) {
            return Ok(found.port);
        }
        let endpoint = Endpoint::bind()?;
        let port = Port::try_from(endpoint.port()).map_err(io::Error::other)?;
        let carried = Arc::new(Held {
            port,
            server,
            carrier: Mutex::new(None),
        });
        endpoints.insert(reverse, Arc::clone(&carried));
        let (stop, jobs) = (Signal::new()?, Arc::clone(jobs));
        thread::spawn(move || {
            while let Ok(Some(stream)) = endpoint.accept(&stop) {
                let (carried, jobs) = (Arc::clone(&carried), Arc::clone(&jobs));
                thread::spawn(move || through(&stream, &carried, &jobs));
            }
        });
        Ok(port)
    }

    /// Whether the carrier of the endpoint of `reverse` is already in
    /// `connection`'s channel.
    pub fn hauled(&self, reverse: &Reverse, connection: ConnectionId) -> bool {
        self.found(reverse)
            .and_then(|carried| carried.carrier.lock().ok().map(|carrier| *carrier))
            .flatten()
            .is_some_and(|(held, _)| held == connection)
    }

    /// The carrier of the endpoint of `reverse` is in `connection`'s channel,
    /// listening at `listen`.
    pub fn haul(&self, reverse: &Reverse, connection: ConnectionId, listen: Port) {
        if let Some(carried) = self.found(reverse)
            && let Ok(mut carrier) = carried.carrier.lock()
        {
            *carrier = Some((connection, listen));
        }
    }

    fn found(&self, reverse: &Reverse) -> Option<Arc<Held>> {
        self.endpoints.lock().ok()?.get(reverse).cloned()
    }
}

/// Carries one connection the workstation's ADB server made to an endpoint,
/// as a device asked, on to the remote through the carrier; anything else
/// that connects is closed with nothing written.
fn through(stream: &TcpStream, carried: &Held, jobs: &Jobs) {
    let from_server = reach(&carried.server)
        .result
        .ok()
        .and_then(|server| owner(&server).ok().flatten())
        .is_some_and(|server| owner(stream).ok().flatten() == Some(server));
    let held = carried.carrier.lock().ok().and_then(|carrier| *carrier);
    let onward = held
        .filter(|_| from_server)
        .and_then(|(connection, listen)| {
            let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listen.number());
            let onward = TcpStream::connect_timeout(&address.into(), crate::PATIENCE).ok()?;
            // The listener must be the carrier: a process in the remote's
            // channel's job, never whatever took the port meanwhile.
            let listener = owner(&onward).ok().flatten()?;
            (placed(listener, jobs).1 == Some(connection)).then_some(onward)
        });
    let Some(onward) = onward else {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    };
    pipe(stream, &onward);
}

/// A forward one ADB capability carries for one remote, by its port there.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Forwarding {
    pub remote: RemoteId,
    pub capability: Name,
    pub port: Port,
}

/// One forward's endpoint: where its carrier hands each of the remote's
/// connections to the core, held for the run so a carrier started again
/// when the channel returns hands them to the same port; the server's
/// listener it goes on to, and the channel whose job holds the carrier.
#[derive(Debug)]
pub struct Listening {
    endpoint: Port,
    server: Service,
    listener: Mutex<Option<Port>>,
    carrier: Mutex<Option<ConnectionId>>,
    stop: Signal,
}

impl Listening {
    /// Ends the endpoint: nothing more is accepted at it.
    pub fn end(&self) {
        let _ = self.stop.raise();
    }
}

/// Every forward's endpoint, by the remote, capability and port on the remote
/// it is for.
#[derive(Debug, Default)]
pub struct Forwards {
    endpoints: Mutex<BTreeMap<Forwarding, Arc<Listening>>>,
}

impl Forwards {
    /// An endpoint bound now, for a forward whose port on the remote is not
    /// known yet. A connection to it is carried on only where it comes from
    /// a process in the job of the channel whose carrier it is, and only to a
    /// listener of the process listening at `server`, the capability's ADB
    /// server.
    ///
    /// # Errors
    ///
    /// What the system said when binding.
    pub fn bind(&self, server: Service, jobs: &Jobs) -> io::Result<(Arc<Listening>, Port)> {
        let bound = Endpoint::bind()?;
        let port = Port::try_from(bound.port()).map_err(io::Error::other)?;
        let listening = Arc::new(Listening {
            endpoint: port,
            server,
            listener: Mutex::new(None),
            carrier: Mutex::new(None),
            stop: Signal::new()?,
        });
        let (held, jobs) = (Arc::clone(&listening), Arc::clone(jobs));
        thread::spawn(move || {
            while let Ok(Some(stream)) = bound.accept(&held.stop) {
                let (listening, jobs) = (Arc::clone(&held), Arc::clone(&jobs));
                thread::spawn(move || onward(&stream, &listening, &jobs));
            }
        });
        Ok((listening, port))
    }

    /// The endpoint is `forwarding`'s from here.
    pub fn keep(&self, forwarding: Forwarding, listening: Arc<Listening>) {
        if let Ok(mut endpoints) = self.endpoints.lock() {
            endpoints.insert(forwarding, listening);
        }
    }

    /// The port of `forwarding`'s endpoint.
    pub fn endpoint_of(&self, forwarding: &Forwarding) -> Option<Port> {
        self.found(forwarding).map(|found| found.endpoint)
    }

    /// The carrier of `forwarding` is in `connection`'s channel.
    pub fn haul(&self, forwarding: &Forwarding, connection: ConnectionId) {
        if let Some(found) = self.found(forwarding)
            && let Ok(mut carrier) = found.carrier.lock()
        {
            *carrier = Some(connection);
        }
    }

    /// The server's listener for `forwarding` is at `listener`; `None` where
    /// it has none any more. Whether `forwarding` still has an endpoint to
    /// take it.
    pub fn listen(&self, forwarding: &Forwarding, listener: Option<Port>) -> bool {
        let Some(found) = self.found(forwarding) else {
            return false;
        };
        let Ok(mut held) = found.listener.lock() else {
            return false;
        };
        *held = listener;
        true
    }

    /// Ends `forwarding`'s endpoint, and gives the port its carrier was
    /// known by.
    pub fn release(&self, forwarding: &Forwarding) -> Option<Port> {
        let found = self.endpoints.lock().ok()?.remove(forwarding)?;
        found.end();
        Some(found.endpoint)
    }

    fn found(&self, forwarding: &Forwarding) -> Option<Arc<Listening>> {
        self.endpoints.lock().ok()?.get(forwarding).cloned()
    }
}

/// Carries one of the remote's connections to a forward on to the server's
/// listener for it; anything else that connects, or a listener another
/// process holds, is closed with nothing written.
fn onward(stream: &TcpStream, listening: &Listening, jobs: &Jobs) {
    let from_carrier = owner(stream).ok().flatten().is_some_and(|process| {
        let carrier = listening.carrier.lock().ok().and_then(|carrier| *carrier);
        carrier.is_some() && placed(process, jobs).1 == carrier
    });
    let listener = listening
        .listener
        .lock()
        .ok()
        .and_then(|listener| *listener);
    let onward = listener.filter(|_| from_carrier).and_then(|listener| {
        let server = reach(&listening.server)
            .result
            .ok()
            .and_then(|server| owner(&server).ok().flatten())?;
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.number());
        let onward = TcpStream::connect_timeout(&address.into(), crate::PATIENCE).ok()?;
        // The listener must be the server's own: the device's, never
        // whatever took the port once the server let it go.
        (owner(&onward).ok().flatten() == Some(server)).then_some(onward)
    });
    let Some(onward) = onward else {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    };
    pipe(stream, &onward);
}

/// Copies both ways until both ends have closed, each direction on its own
/// thread, an end's close passed on as a close of the other's writing half.
pub(crate) fn pipe(one: &TcpStream, other: &TcpStream) {
    let (Ok(mut one_from), Ok(mut other_to), Ok(mut other_from), Ok(mut one_to)) = (
        one.try_clone(),
        other.try_clone(),
        other.try_clone(),
        one.try_clone(),
    ) else {
        return;
    };
    let back = thread::spawn(move || {
        if io::copy(&mut other_from, &mut one_to).is_ok() {
            let _ = one_to.shutdown(Shutdown::Write);
        }
    });
    if io::copy(&mut one_from, &mut other_to).is_ok() {
        let _ = other_to.shutdown(Shutdown::Write);
    }
    let _ = back.join();
    let _ = one.shutdown(Shutdown::Both);
    let _ = other.shutdown(Shutdown::Both);
}
