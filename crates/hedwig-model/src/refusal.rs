//! The one refusal every door gives.
//!
//! A control request, a configuration import, a relayed request and a row that
//! cannot offer an act all answer with this type, from the same checks, so a
//! surface can never offer what the core would refuse. [`Refusal`]'s `Display`
//! is the sentence the person reads; nothing else words a refusal. What
//! readiness names on a remote, [`Finding`], is worded here too.

use std::fmt;
use std::num::NonZeroU32;

use crate::capability::{
    AgentAt, Consent, Exposure, Holds, Home, KeyKind, Operation, Query, Reaches, ServicePort,
    Source, Spot, Stream,
};
use crate::config::Activation;
use crate::organisation::Limit;
use crate::policy::Mode;
use crate::remote::RemoteId;
use crate::scope::Audience;
use crate::setting::{Diagnostics, Longest};
use crate::site::{Site, Unopenable};
use crate::text::{DeviceSerial, Kernel, Location, Name, Port, SshKey, Words};
use crate::trail::{Asks, ConnectionId, Failure, Finding, PromptId, PromptKind, RequestId, Write};

/// What a request withheld at the relay would have done: of the
/// workstation's ADB server, of an emulator's console, or of an SSH agent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Withheld {
    /// `kill`: ended the server, which the person's own tools use too.
    Ending,
    /// Used or changed a device the grant does not lend: the one named, or,
    /// where none was, the device the server would have chosen. The remote's
    /// tool was told what ADB says of a device that is not there.
    Unlent(Option<DeviceSerial>),
    /// Acted on every device the server holds, or every one of a kind: a
    /// bare `disconnect:`, `reconnect-offline`.
    Every,
    /// Had the server reach the workstation's network - `connect:`,
    /// `pair:`, `disconnect:` of an address, the mDNS listings - where the
    /// grant does not acknowledge `network`.
    Unacknowledged,
    /// `emulator:`: had the server attach an emulator at a port the remote
    /// names, which only an emulator sends of itself.
    Reaching,
    /// Stopped the server: a `reverse:` request it does not know.
    Stopping,
    /// A request for the server itself, or a reverse, longer than any that
    /// names a device, an address or a socket.
    Long,
    /// A reverse to something other than a TCP port or a socket path, which
    /// the channel's client cannot carry on to the remote.
    Uncarriable,
    /// A forward from something other than a TCP port on the remote.
    Unforwardable,
    /// Beyond what Hedwig carries on to one remote at once: reverses,
    /// forwards and consoles together.
    Crowded,
    /// The server did not say which devices it holds in a form Hedwig
    /// reads, so no device could be judged lent.
    Unlisted,
    /// The server is older than platform-tools 35.0.0 and lists its devices
    /// in no form Hedwig reads, so no device could be judged lent.
    Outdated,
    /// A request for the server itself that Hedwig does not know, and so
    /// cannot judge against what the grant lends.
    Unknown,
    /// A command to a lent emulator's console that acts on the workstation
    /// rather than the emulated device - its hypervisor, its ports, its
    /// files - or one Hedwig does not know.
    Hosted,
    /// Used an SSH key the grant does not lend. The remote was told the
    /// agent failed, as an agent answers for a key it does not hold.
    KeyUnlent(SshKey),
    /// Used an SSH key the grant lends only toward named hosts for anything
    /// but authenticating to one of them, in a request the host checks.
    Elsewhere(SshKey),
    /// Would have changed or locked the person's agent - added or removed a
    /// key, locked or unlocked it - or used an extension of it Hedwig does
    /// not read.
    Managing,
}

impl fmt::Display for Withheld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Withheld::Ending => f.write_str("it would have ended the workstation's ADB server"),
            Withheld::Unlent(Some(serial)) => {
                write!(f, "it asked for {serial}, which the grant does not lend")
            }
            Withheld::Unlent(None) => f.write_str(
                "it asked for a device without naming one, and the grant lends none of those \
                 the workstation's ADB server holds",
            ),
            Withheld::Every => f.write_str(
                "it would have acted on every device the workstation's ADB server holds",
            ),
            Withheld::Unacknowledged => f.write_str(
                "it would have had the workstation's ADB server reach the workstation's \
                 network, which the grant does not acknowledge",
            ),
            Withheld::Reaching => f.write_str(
                "it would have had the workstation's ADB server attach an emulator at a port \
                 the remote named",
            ),
            Withheld::Stopping => f.write_str("the workstation's ADB server stops on it"),
            Withheld::Long => {
                f.write_str("it was longer than any request that names a device or an address")
            }
            Withheld::Uncarriable => f.write_str(
                "it asked for a reverse to something Hedwig cannot carry on to the remote",
            ),
            Withheld::Unforwardable => f.write_str(
                "it asked for a forward from something other than a TCP port on the remote",
            ),
            Withheld::Crowded => {
                f.write_str("it asked for more than Hedwig carries on to one remote at once")
            }
            Withheld::Unlisted => f.write_str(
                "the workstation's ADB server did not list its devices in a form Hedwig reads",
            ),
            Withheld::Outdated => f.write_str(
                "the workstation's ADB server is older than platform-tools 35.0.0, so no device \
                 could be judged lent",
            ),
            Withheld::Unknown => f.write_str(
                "it was a request of the workstation's ADB server that Hedwig does not know",
            ),
            Withheld::Hosted => f.write_str(
                "it was an emulator console command that acts on the workstation itself, or \
                 one Hedwig does not know",
            ),
            Withheld::KeyUnlent(key) => {
                write!(
                    f,
                    "it asked for {}, which the grant does not lend",
                    key.kind()
                )
            }
            Withheld::Elsewhere(key) => write!(
                f,
                "it used {} for something other than logging in to a host the grant names for it",
                key.kind()
            ),
            Withheld::Managing => f.write_str(
                "it would have changed or locked the person's SSH agent, or used an extension of \
                 it Hedwig does not read",
            ),
        }
    }
}

/// A part of a configuration document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    Capabilities,
    Platforms,
    Grants,
    Denials,
    Rules,
    Routes,
    Sets,
    Accepted,
    Bursts,
    Heard,
    Expected,
    FullScreen,
    Caps,
    Keepalives,
    Returns,
    Cadences,
}

/// Where the person was when nothing that watches a remote could put its
/// request to them, as those surfaces last said: from the surface they were
/// last seen at among those not away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Whereabouts {
    /// No unlocked desktop and no attended terminal watches the remote.
    Away,
    /// At a desktop that shows nothing over what they are doing: presenting,
    /// or an application holding the display.
    Engaged,
    /// At a desktop an application fills, where the person set this
    /// remote's card not to be shown.
    FullScreen,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Refusal {
    /// The client speaks another version of the control protocol.
    Version {
        core: u32,
        client: u32,
    },
    /// A request arrived before the greeting.
    NotGreeted,
    /// A decision or an answer came from a client that attends no person.
    NotAttending,
    /// A client other than the interface said whether its icon is shown: it
    /// has none.
    NoIcon,
    /// The bytes received are not a message of this protocol; carries the
    /// decoder's account.
    Malformed(String),

    UnknownCapability(Name),
    UnknownRoute(Name),
    /// No source defines a set of remotes by this name.
    UnknownSet(Name),
    UnknownPlatform(Name),
    /// A remote calls its system something no platform profile answers to.
    UnknownKernel(Kernel),
    /// Two platform profiles answer to what a remote calls its system.
    KernelClaimed {
        kernel: Kernel,
        first: Name,
        second: Name,
    },
    UnknownConnection(ConnectionId),
    /// The request was already settled, or never existed.
    UnknownRequest(RequestId),
    UnknownPrompt(PromptId),
    /// The answer is not what the prompt asks for: text for a passphrase, a
    /// yes or a no for a host key, nothing but a refusal for a key's touch.
    AnswerUnfit {
        kind: PromptKind,
    },

    /// The name is defined outside the person's document: by what ships, or
    /// by the organisation's starting point.
    Reserved(Name),
    /// Grants, denials or rules still name the capability.
    CapabilityInUse(Name),
    /// Grants, denials or rules still select remotes on the route.
    RouteInUse(Name),
    /// Grants, denials, rules or a pause still select the set.
    SetInUse(Name),
    /// The capability leaves a port or a remote form unstated.
    CapabilityIncomplete {
        capability: Name,
    },
    /// The grant does not name everything the capability exposes.
    ExposureNotAcknowledged {
        capability: Name,
        missing: Exposure,
    },
    /// The grant lends devices or keys of a capability whose source holds
    /// none: `lent` is what was lent.
    Unlendable {
        capability: Name,
        lent: Holds,
    },
    /// A grant that follows a workspace's life, on a route that cannot say
    /// which of its remotes are running.
    ActivationNeedsDiscovery {
        route: Name,
    },
    /// A cadence of listing for a route that lists nothing.
    Unlisted(Name),
    /// A rule for an operation the capability's dialect never raises.
    OperationNotInDialect {
        capability: Name,
        operation: Operation,
    },
    /// A document lists the same entry twice.
    Repeated(Section),
    /// Two sources define the name differently. Nothing that goes by it is
    /// served until one of them is renamed.
    Collides {
        section: Section,
        name: Name,
    },
    /// The length is not one of those offered for the request, or is past
    /// the longest an allowance for it may last.
    NotOffered {
        seconds: NonZeroU32,
    },
    /// A document written for another version of the model.
    DocumentVersion {
        found: u32,
        supported: u32,
    },

    /// The platform's own SSH server carries no form of this capability.
    NoCarrier {
        capability: Name,
        platform: Name,
    },
    /// The platform carries the capability only through a form that writes
    /// the remote tool's configuration, and the grant only inspects.
    NeedsRemoteSetup {
        capability: Name,
        platform: Name,
    },
    NoUnixSockets {
        platform: Name,
    },
    /// The remote has not yet reported what platform it is.
    PlatformUnobserved(RemoteId),
    /// There is no channel to the remote.
    NotConnected(RemoteId),
    /// The workstation's own side of the capability did not answer.
    SourceUnavailable {
        capability: Name,
        failure: Failure,
    },
    /// `capability` and `with`, both held by one remote, take one place on
    /// it, so neither is carried: nothing says which the person meant there.
    Shared {
        capability: Name,
        with: Name,
        spot: Spot,
    },
    /// The serial port a capability names is held for a connection from
    /// `by`, and a port serves one connection at a time.
    PortHeld {
        capability: Name,
        by: RemoteId,
    },
    SocketPathTooLong {
        usable: u16,
        length: u16,
    },

    NotGranted {
        capability: Name,
        remote: RemoteId,
    },
    Paused,
    /// A removal of Hedwig began and has not finished, so it opens no
    /// connection but to take back what it wrote.
    Withdrawn,
    /// Nothing that watches the remote could show it to the person, or put
    /// it to them; where they were is said.
    NobodyReachable(Whereabouts),
    /// The person refused it.
    Declined,
    /// A process that connected to the workstation end of a forward and is
    /// not in the job of the channel that forward belongs to.
    NoChannel {
        process: u32,
        program: Option<Location>,
    },
    /// A connection whose owning process could not be found.
    Unattributable,
    /// A connection through a Windows remote's forward that did not first
    /// present the bytes Hedwig wrote to that remote's socket file: a process
    /// on the remote other than the person's own `gpg`.
    Unissued,
    /// The remote's side said something the capability's protocol does not,
    /// and the connection was closed before any of it was carried.
    OffProtocol {
        capability: Name,
        account: Words,
    },
    /// A request on a relayed ADB connection that is never carried from a
    /// remote; the remote's tool was told so in ADB's own form.
    Withheld {
        capability: Name,
        request: Withheld,
    },
    /// A limit the organisation states for this audience withholds it. The
    /// person's own statements stand, and serve again when the limit goes.
    Held {
        audience: Audience,
        limit: Box<Limit>,
    },
    /// A limit the organisation states for this audience could not be read,
    /// so nothing is served under those limits until it can be.
    Unread(Audience),
    /// A remote asked the workstation's browser to open a URL none of the
    /// capability's sites admits; `site` is the narrowest that would.
    UnlistedSite {
        capability: Name,
        site: Site,
    },
    /// A remote asked the workstation's browser to open something that is
    /// not a URL it opens.
    Unopenable {
        capability: Name,
        why: Unopenable,
    },
    /// The workstation's own loopback port the sign-in comes back to is held
    /// by another program, which the browser would hand the answer to.
    CallbackHeld {
        capability: Name,
        port: Port,
    },
    /// A remote's `git` asked for a credential for a site none of the
    /// capability's sites admits; carries the narrowest that would.
    UnlistedCredential {
        capability: Name,
        site: Site,
    },
    /// A remote's `git` asked for a credential for something other than an
    /// `https` or `http` site: a client certificate's passphrase, a mail
    /// server's login. Carries the protocol it named, where it named one.
    NotWeb {
        capability: Name,
        protocol: Option<Words>,
    },
    /// A credential for a site on plain `http` beyond the remote's loopback,
    /// which the remote's `git` would send across the network unencrypted:
    /// refused when it is asked for and where a capability names the site.
    Cleartext {
        capability: Name,
        site: Site,
    },
    /// The remote's jobs sent more notices than Hedwig passes on in a minute;
    /// this one was turned away and is counted with the next.
    Hushed {
        capability: Name,
    },
    /// The TPM already holds a key of Hedwig's by this name; it is never
    /// overwritten.
    KeyExists(Name),
    /// This workstation's TPM does not make keys of this kind.
    KindUnmade(KeyKind),
    /// Windows' provider for the workstation's TPM would not open or answer
    /// for this logon.
    NoTpm,
    /// The TPM holds no key Hedwig made with this public half.
    KeyAbsent(SshKey),
}

impl Refusal {
    /// Whether the person would otherwise miss it. Their own refusal is not
    /// news to them; everything else at the relay's door is.
    pub fn raises_attention(&self) -> bool {
        matches!(
            self,
            Refusal::NotGranted { .. }
                | Refusal::Paused
                | Refusal::NobodyReachable(_)
                | Refusal::NoChannel { .. }
                | Refusal::Unattributable
                | Refusal::Unissued
                | Refusal::OffProtocol { .. }
                | Refusal::Withheld { .. }
                | Refusal::ExposureNotAcknowledged { .. }
                | Refusal::Collides { .. }
                | Refusal::SourceUnavailable { .. }
                | Refusal::Held { .. }
                | Refusal::Unread(_)
                | Refusal::UnlistedSite { .. }
                | Refusal::Unopenable { .. }
                | Refusal::CallbackHeld { .. }
                | Refusal::UnlistedCredential { .. }
                | Refusal::NotWeb { .. }
                | Refusal::Cleartext { .. }
        )
    }
}

impl fmt::Display for Refusal {
    #[allow(
        clippy::too_many_lines,
        reason = "one sentence per refusal, kept together as the single source of its words"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Version { core, client } => write!(
                f,
                "this client speaks control protocol {client} and the running Hedwig speaks \
                 {core}; restart Hedwig so both come from the same install"
            ),
            Refusal::NotGreeted => f.write_str("the first message must be the greeting"),
            Refusal::NotAttending => {
                f.write_str("only an attended terminal or the interface can answer for the person")
            }
            Refusal::NoIcon => {
                f.write_str("only Hedwig's icon can say whether the taskbar shows it")
            }
            Refusal::Malformed(account) => write!(f, "the message is not valid: {account}"),
            Refusal::UnknownCapability(name) => write!(f, "there is no capability named {name}"),
            Refusal::UnknownRoute(name) => write!(f, "there is no route named {name}"),
            Refusal::UnknownSet(name) => write!(f, "there is no set of remotes named {name}"),
            Refusal::UnknownPlatform(name) => write!(
                f,
                "the remote reports platform {name}, which has no profile; define one to serve it"
            ),
            Refusal::UnknownKernel(kernel) => write!(
                f,
                "the remote calls its system {kernel}, and no platform profile answers to that; define one to serve it"
            ),
            Refusal::KernelClaimed {
                kernel,
                first,
                second,
            } => write!(
                f,
                "both {first} and {second} answer to a system called {kernel}, so which one this remote is cannot be said; rename or remove one"
            ),
            Refusal::UnknownConnection(_) => f.write_str("that connection has ended"),
            Refusal::UnknownRequest(_) => f.write_str("that request has already been settled"),
            Refusal::UnknownPrompt(_) => f.write_str("that prompt has already been answered"),
            Refusal::AnswerUnfit { kind } => f.write_str(match kind.asks() {
                Asks::Text => "that prompt is answered with text",
                Asks::Consent => "that prompt is answered with yes or no",
                Asks::Nothing => "that prompt can only be refused",
            }),
            Refusal::Reserved(name) => write!(
                f,
                "{name} is defined outside your configuration, by Hedwig or your organisation; \
                 choose another name for your own definition"
            ),
            Refusal::CapabilityInUse(name) => write!(
                f,
                "{name} is still named by a grant, a denial or a rule; remove those first"
            ),
            Refusal::RouteInUse(name) => write!(
                f,
                "remotes on {name} are still named by a grant, a denial or a rule; remove those \
                 first"
            ),
            Refusal::SetInUse(name) => write!(
                f,
                "the set {name} is still named by a grant, a denial, a rule or a pause; remove \
                 those first"
            ),
            Refusal::CapabilityIncomplete { capability } => write!(
                f,
                "{capability} does not say which port to use; define a capability that states it"
            ),
            Refusal::ExposureNotAcknowledged {
                capability,
                missing,
            } => {
                write!(f, "granting {capability} exposes")?;
                words(f, *missing)?;
                f.write_str(", and the grant does not name it")
            }
            Refusal::Unlendable { capability, lent } => write!(
                f,
                "{capability} holds no {} to lend; a grant of it lends none",
                match lent {
                    Holds::Devices => "devices",
                    Holds::Keys => "keys",
                }
            ),
            Refusal::ActivationNeedsDiscovery { route } => write!(
                f,
                "remotes on {route} cannot be seen starting and stopping, so a grant there \
                 connects on request or continuously"
            ),
            Refusal::Unlisted(route) => write!(
                f,
                "{route} cannot say which of its remotes are running, so nothing asks it how \
                 often"
            ),
            Refusal::OperationNotInDialect {
                capability,
                operation,
            } => write!(
                f,
                "{capability} never asks to {}",
                operation_words(*operation)
            ),
            Refusal::Repeated(section) => {
                write!(
                    f,
                    "the document lists the same entry twice under {}",
                    section_words(*section)
                )
            }
            Refusal::Collides { name, .. } => write!(
                f,
                "two sources define {name} differently, so nothing that goes by that name is \
                 served; rename one of them"
            ),
            Refusal::NotOffered { seconds } => write!(
                f,
                "an allowance of {seconds} seconds is not offered for that request"
            ),
            Refusal::DocumentVersion { found, supported } => write!(
                f,
                "the document is version {found} and this Hedwig reads version {supported}"
            ),
            Refusal::NoCarrier {
                capability,
                platform,
            } => write!(
                f,
                "a {platform} remote's own SSH server has no way to carry {capability}"
            ),
            Refusal::NeedsRemoteSetup {
                capability,
                platform,
            } => write!(
                f,
                "on a {platform} remote {capability} works only once Hedwig may write that \
                 remote's own tool configuration; the grant does not allow it"
            ),
            Refusal::NoUnixSockets { platform } => {
                write!(f, "a {platform} remote binds no Unix-domain socket")
            }
            Refusal::PlatformUnobserved(remote) => {
                write!(
                    f,
                    "{remote} has not been reached yet, so its platform is not known"
                )
            }
            Refusal::NotConnected(remote) => write!(f, "there is no connection to {remote}"),
            Refusal::SourceUnavailable {
                capability,
                failure,
            } => match failure {
                Failure::Unresolved => write!(
                    f,
                    "the tool that says where {capability} lives on this workstation was not found"
                ),
                Failure::Unreachable => {
                    write!(f, "nothing answers for {capability} on this workstation")
                }
                Failure::Mismatched => write!(
                    f,
                    "what answers for {capability} on this workstation is not what it names"
                ),
                Failure::NoAddress => write!(
                    f,
                    "{capability} names a host this workstation can find no address for"
                ),
                Failure::Foreign => write!(
                    f,
                    "what answers for {capability} on this workstation is another account's \
                     program and no service an administrator installed, so Hedwig does not carry \
                     the remote's connection to it"
                ),
                Failure::Confined => write!(
                    f,
                    "what answers for {capability} on this workstation is a program of yours that \
                     Windows confines to less than you - at low integrity, restricted, or in an \
                     app container - so Hedwig does not carry the remote's connection to it"
                ),
                Failure::Unidentified => write!(
                    f,
                    "Windows does not let Hedwig read whose program answers for {capability} on \
                     this workstation, and it is no service an administrator installed, so Hedwig \
                     does not carry the remote's connection to it"
                ),
                Failure::Unstartable => write!(
                    f,
                    "{capability} names a program that is not on this workstation's search path, \
                     or that would not start"
                ),
                Failure::Unopened => write!(
                    f,
                    "{capability} opens addresses with your default browser, and this workstation \
                     has none set for web addresses, or the one set would not start"
                ),
                Failure::Absent => write!(
                    f,
                    "{capability} names a serial port that is not among this workstation's \
                     serial ports now; the board may be unplugged"
                ),
                Failure::Outdated => write!(
                    f,
                    "{capability} reaches an ADB server older than platform-tools 35.0.0, which \
                     does not list its devices as Hedwig reads them; updating platform-tools on \
                     this workstation serves it"
                ),
                Failure::Busy => write!(
                    f,
                    "{capability} names a serial port that another program on this workstation \
                     has open"
                ),
                Failure::Occupied => write!(
                    f,
                    "{capability}'s agent was busy with another program for longer than Hedwig \
                     waits; an agent that serves one program at a time does this while another \
                     holds it"
                ),
                Failure::Unserved => write!(
                    f,
                    "{capability} names a POSIX-emulated GnuPG, such as Git for Windows' own, \
                     which Hedwig neither starts nor serves; Gpg4win's GnuPG is served"
                ),
                Failure::NoTpm => write!(
                    f,
                    "{capability} signs in this workstation's TPM, and Windows' provider for it \
                     did not answer for this sign-in"
                ),
            },
            Refusal::Shared {
                capability,
                with,
                spot,
            } => {
                match spot {
                    Spot::Port(port) => write!(
                        f,
                        "{capability} and {with} both take port {port} on the remote, so neither \
                         is carried; give one of them another remote port"
                    )?,
                    Spot::Socket(Query::AgentSocket) => write!(
                        f,
                        "{capability} and {with} both take the remote's gpg-agent socket, so \
                         neither is carried"
                    )?,
                    Spot::Socket(Query::AgentSshSocket) => write!(
                        f,
                        "{capability} and {with} both take the remote's gpg-agent SSH socket, so \
                         neither is carried"
                    )?,
                    Spot::Variable(variable) => write!(
                        f,
                        "{capability} and {with} both set {variable} on the remote, so neither is \
                         carried"
                    )?,
                    Spot::Helper => write!(
                        f,
                        "{capability} and {with} both answer the remote git's credential \
                         requests, so neither is carried"
                    )?,
                }
                match spot {
                    Spot::Port(_) => Ok(()),
                    Spot::Socket(_) | Spot::Variable(_) | Spot::Helper => {
                        f.write_str("; grant the remote one of them")
                    }
                }
            }
            Refusal::PortHeld { capability, by } => write!(
                f,
                "{capability} names a serial port lent to a connection from {by}, and a port \
                 serves one connection at a time"
            ),
            Refusal::SocketPathTooLong { usable, length } => write!(
                f,
                "the remote's socket path is {length} bytes and that platform allows {usable}"
            ),
            Refusal::NotGranted { capability, remote } => {
                write!(f, "{capability} is not granted to {remote}")
            }
            Refusal::Paused => f.write_str("exposure is paused"),
            Refusal::Withdrawn => f.write_str(
                "Hedwig is being removed, so it connects to no remote; keep Hedwig to connect \
                 again",
            ),
            Refusal::NobodyReachable(Whereabouts::Away) => f.write_str(
                "no unlocked desktop and no attended terminal would have shown it to you",
            ),
            Refusal::NobodyReachable(Whereabouts::Engaged) => f.write_str(
                "you were presenting, or an application held your display, and no attended \
                 terminal would have shown it to you",
            ),
            Refusal::NobodyReachable(Whereabouts::FullScreen) => f.write_str(
                "an application filled your screen, and you set this remote's request card not \
                 to be shown over one",
            ),
            Refusal::Declined => f.write_str("you refused it"),
            Refusal::NoChannel { process, program } => {
                match program {
                    Some(program) => write!(f, "{program}, process {process},")?,
                    None => write!(f, "process {process}")?,
                }
                f.write_str(" connected without belonging to the channel Hedwig started there")
            }
            Refusal::Unattributable => {
                f.write_str("a connection arrived whose process could not be identified")
            }
            Refusal::Unissued => f.write_str(
                "something on the remote connected to the forward without the bytes Hedwig gave \
                 that remote's gpg, and was closed",
            ),
            Refusal::OffProtocol {
                capability,
                account,
            } => write!(
                f,
                "the connection to {capability} was closed because {account}"
            ),
            Refusal::Withheld {
                capability,
                request,
            } => write!(f, "a request to {capability} was refused because {request}"),
            Refusal::UnlistedSite { capability, site } => write!(
                f,
                "the remote asked to open {site}, which is not among the sites {capability} opens"
            ),
            Refusal::Unopenable { capability, why } => write!(
                f,
                "the remote asked {capability} to open something Hedwig does not open: {why}"
            ),
            Refusal::CallbackHeld { capability, port } => write!(
                f,
                "{capability} did not open the remote's sign-in: another program on this \
                 workstation holds port {port}, which the answer comes back to"
            ),
            Refusal::UnlistedCredential { capability, site } => write!(
                f,
                "the remote's git asked for your credential for {site}, which is not among the \
                 sites {capability} answers for"
            ),
            Refusal::NotWeb {
                capability,
                protocol: Some(protocol),
            } => write!(
                f,
                "the remote's git asked {capability} for a {protocol} credential; it answers for \
                 https and http sites alone"
            ),
            Refusal::NotWeb {
                capability,
                protocol: None,
            } => write!(
                f,
                "the remote's git asked {capability} for a credential naming no protocol; it \
                 answers for https and http sites alone"
            ),
            Refusal::Cleartext { capability, site } => write!(
                f,
                "{capability} does not answer for {site}: the remote's git would send your \
                 credential there across the network unencrypted"
            ),
            Refusal::Hushed { capability } => write!(
                f,
                "the remote sent more notices through {capability} than Hedwig passes on in a \
                 minute; the rest are counted and said with its next"
            ),
            Refusal::KeyExists(name) => write!(
                f,
                "this workstation's TPM already holds a key of Hedwig's named {name}; give the \
                 new one another name"
            ),
            Refusal::KindUnmade(kind) => write!(
                f,
                "this workstation's TPM does not make {} keys; another kind can be made",
                kind_words(*kind)
            ),
            Refusal::NoTpm => f.write_str(
                "Windows' provider for this workstation's TPM did not answer for this sign-in, so \
                 no key can be made or deleted in it here",
            ),
            Refusal::KeyAbsent(key) => write!(
                f,
                "this workstation's TPM holds no key Hedwig made whose public half is {key}"
            ),
            Refusal::Held { audience, limit } => {
                write!(f, "{} ", holder(*audience))?;
                match &**limit {
                    Limit::Floor { mode, .. } => write!(
                        f,
                        "decides no such request with less than {}",
                        mode_words(*mode)
                    ),
                    Limit::Activation { most, .. } => write!(
                        f,
                        "connects no such grant more readily than {}",
                        activation_words(*most)
                    ),
                    Limit::InspectOnly(_) => {
                        f.write_str("lets no such grant write a remote tool's configuration")
                    }
                    Limit::Cap { longest, .. } => match longest {
                        Longest::Nothing => f.write_str("allows no such request for a time"),
                        Longest::Seconds(seconds) => {
                            write!(
                                f,
                                "allows no such request for longer than {seconds} seconds"
                            )
                        }
                    },
                    Limit::Withhold { exposure, .. } => {
                        f.write_str("serves nothing that exposes")?;
                        words(f, *exposure)?;
                        f.write_str(" to this remote")
                    }
                    Limit::Confine { exposure, .. } => {
                        f.write_str("serves what exposes")?;
                        words(f, *exposure)?;
                        f.write_str(" only to other remotes")
                    }
                    Limit::Deny(_) => f.write_str("denies it to this remote"),
                    Limit::KeepAtLeast(keep) => {
                        write!(f, "keeps at least {} days of activity", keep.0)
                    }
                    Limit::KeepAtMost(keep) => {
                        write!(f, "keeps no more than {} days of activity", keep.0)
                    }
                    Limit::DiagnosticsAtMost(most) => match most {
                        Diagnostics::Off => f.write_str("has Hedwig write no diagnostics"),
                        Diagnostics::Faults => {
                            f.write_str("has Hedwig write diagnostics of what went wrong, no more")
                        }
                        Diagnostics::Detail => {
                            f.write_str("lets Hedwig write diagnostics in detail")
                        }
                    },
                }
            }
            Refusal::Unread(audience) => write!(
                f,
                "{} could not all be read, so nothing is served under them until they can be",
                match audience {
                    Audience::Machine => "your organisation's limits for this machine",
                    Audience::Person => "your organisation's limits for you",
                }
            ),
        }
    }
}

fn operation_words(operation: Operation) -> &'static str {
    match operation {
        Operation::Connect => "connect",
        Operation::Authenticate => "authenticate",
        Operation::Sign => "sign",
        Operation::Decrypt => "decrypt",
        Operation::Open => "open",
    }
}

fn section_words(section: Section) -> &'static str {
    match section {
        Section::Capabilities => "capabilities",
        Section::Platforms => "platforms",
        Section::Grants => "grants",
        Section::Denials => "denials",
        Section::Rules => "rules",
        Section::Routes => "routes",
        Section::Sets => "sets of remotes",
        Section::Accepted => "accepted grants",
        Section::Bursts => "burst thresholds",
        Section::Heard => "how loudly things reach you",
        Section::Expected => "refusals you expect",
        Section::FullScreen => "cards over a full-screen application",
        Section::Caps => "caps on allowances",
        Section::Keepalives => "keepalives",
        Section::Returns => "waits before a channel comes back",
        Section::Cadences => "how often platforms are asked what runs",
    }
}

/// What the person consents to before granting a write, one write to a
/// clause: `Hedwig may write <one>; <two>`, and, where the source's keys are
/// not read yet, what of them will be written.
impl fmt::Display for Consent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hedwig may write ")?;
        for (index, write) in self.writes.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{write}")?;
        }
        if self.keys_unread {
            if !self.writes.is_empty() {
                f.write_str("; ")?;
            }
            f.write_str(
                "and, once it has read them, the public key of each key your GnuPG offers into the remote's keyring, with the one you sign with as the remote git's signing key",
            )?;
        }
        Ok(())
    }
}

/// Who on the remote reaches the service with consent to write and without
/// it. For ADB it says too which client reads no socket, so a person whose
/// remote runs Gradle chooses the port knowingly.
impl fmt::Display for Reaches {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Reaches {
            capability,
            variable,
            port,
            stream,
        } = self;
        write!(
            f,
            "With it, what reads {variable} on the remote reaches {capability} through a socket \
             only the remote user can open; without it, through "
        )?;
        match port {
            ServicePort::Fixed(port) => write!(f, "port {port}")?,
            ServicePort::Unstated => f.write_str("a port")?,
        }
        f.write_str(" there, which every user and program on the remote can reach.")?;
        match stream {
            Stream::Adb => f.write_str(
                " Gradle's own client, which runs connectedAndroidTest, reads no socket: a remote \
                 that runs Gradle takes ADB on the port, where you leave this off.",
            ),
            Stream::Opaque => Ok(()),
        }
    }
}

/// A write as the person reads it, in the words of the tool it configures:
/// what consent to write names before it is given, and what a finding says
/// was not written.
impl fmt::Display for Write {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Write::NoAutostart => f.write_str("no-autostart in the remote's GnuPG configuration"),
            Write::PublicKey(key) => write!(f, "the public key {key} into the remote's keyring"),
            Write::SigningKey(key) => write!(f, "{key} as the remote git's signing key"),
            Write::Variable(variable) => {
                write!(f, "{variable} in your shell's startup on the remote")
            }
            Write::SocketFile => f.write_str("the file the remote's gpg finds its agent by"),
            Write::Masked => f.write_str(
                "a mask on the remote's own service unit that holds the path the forward needs, which stops the agent it started there",
            ),
            Write::Helper => f.write_str(
                "git's own cache helper at Hedwig's socket, after your own helpers in the remote git's configuration",
            ),
        }
    }
}

fn mode_words(mode: Mode) -> &'static str {
    match mode {
        Mode::Unattended => "serving with nobody there",
        Mode::Notify => "telling you",
        Mode::Confirm => "asking you first",
    }
}

fn activation_words(activation: Activation) -> &'static str {
    match activation {
        Activation::OnRequest => "when you connect",
        Activation::WhileRunning => "while the remote runs",
        Activation::Continuous => "continuously",
    }
}

fn holder(audience: Audience) -> &'static str {
    match audience {
        Audience::Machine => "your organisation's policy for this machine",
        Audience::Person => "your organisation's policy for you",
    }
}

fn words(f: &mut fmt::Formatter<'_>, exposure: Exposure) -> fmt::Result {
    for (index, word) in exposure.words().enumerate() {
        write!(f, "{} {word}", if index == 0 { "" } else { "," })?;
    }
    Ok(())
}

impl std::error::Error for Refusal {}

/// The sentence the person reads on the remote's row. Each says what is at
/// fault on the remote and, where the person can act, what Hedwig leaves to
/// them.
impl fmt::Display for Finding {
    #[allow(
        clippy::too_many_lines,
        reason = "one sentence per finding, each read on the row as it stands"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::Unsurveyed(why) => write!(f, "Hedwig could not look at the remote: {why}"),
            Finding::NoProfile(refusal) => {
                write!(f, "Hedwig cannot tell which platform the remote is: {refusal}")
            }
            Finding::ToolAbsent(tool) => {
                write!(f, "the remote has no {tool} to say where this goes")
            }
            Finding::PathTooLong { usable, length } => write!(
                f,
                "the remote's socket path is {length} bytes and that system takes at most {usable}"
            ),
            Finding::PathUnusable => f.write_str(
                "the remote's tool named a socket path that holds a character a forward cannot carry",
            ),
            Finding::SharedHome(system) => write!(
                f,
                "the socket's folder is on {system}, which other hosts share, so another host's socket can be at the same path; Hedwig does not forward into it"
            ),
            Finding::ParentUncreatable(said) => {
                write!(f, "the folder for the socket could not be made: {said}")
            }
            Finding::Occupied(path) => write!(
                f,
                "{path} is there and is not a socket; Hedwig leaves it for you to move"
            ),
            Finding::AgentLive(path) => write!(
                f,
                "the remote's own agent answers at {path}; Hedwig leaves it running, and forwards there once you stop it"
            ),
            Finding::ServerLive { program, at } => {
                write!(f, "the remote's own {program} server listens ")?;
                match at {
                    crate::trail::Binding::Socket(path) => write!(f, "at {path}")?,
                    crate::trail::Binding::SocketFile { port, .. }
                    | crate::trail::Binding::Port(port) => write!(f, "on port {port}")?,
                }
                write!(
                    f,
                    "; Hedwig leaves it running, and forwards there once you stop it with {program} kill-server"
                )
            }
            Finding::UnitListens { unit, path } => write!(
                f,
                "the remote's service manager holds {path} for {unit}, and would start the remote's own agent there; Hedwig masks {unit} where you let it write, and otherwise leaves it"
            ),
            Finding::Answers(path) => write!(
                f,
                "something else answers at {path}: a forward another program or session holds; Hedwig leaves it alone"
            ),
            Finding::Silent(path) => write!(
                f,
                "something at {path} accepts and says nothing, most often a session the remote has not yet noticed is gone; Hedwig tries again"
            ),
            Finding::Unprobed(path) => write!(
                f,
                "a socket is at {path}, and the remote has no tool that can tell whether anything listens there; Hedwig leaves it"
            ),
            Finding::Uncleared(said) => {
                write!(f, "nothing listens at the old socket and it could not be removed: {said}")
            }
            Finding::ListenerPresent(port) => write!(
                f,
                "something on the remote already listens on port {port}, so the forward cannot bind there"
            ),
            Finding::ForwardingBlocked => {
                f.write_str("the remote's deployment does not allow reverse forwarding")
            }
            Finding::ForwardRefused => f.write_str(
                "the remote's SSH server refused the forward; its own log says why",
            ),
            Finding::AgentAutostarts => f.write_str(
                "the remote's gpg starts an agent of its own whenever the forward is down, and that agent then holds the socket",
            ),
            Finding::KeyboxdStopped => f.write_str(
                "the remote's GnuPG keeps its keys in keyboxd and is set not to start it, so it cannot read its own keyring",
            ),
            Finding::PublicKeyAbsent(key) => write!(
                f,
                "the remote's keyring lacks the public key {key}, so its gpg cannot use that key"
            ),
            Finding::KeyringAbsent => f.write_str(
                "the remote's GnuPG home has no keyring, so its gpg holds no key to sign with; Hedwig ran nothing, since signing there would make one",
            ),
            Finding::SigningKeyUnset => f.write_str("the remote's git names no signing key"),
            Finding::SigningKeyOther(value) => write!(
                f,
                "the remote's git signs with {value}, a key this workstation does not offer"
            ),
            Finding::VariableUnset(variable) => write!(
                f,
                "a command the remote runs over SSH does not find {variable} pointing at the socket Hedwig forwards, so such a command must set it itself"
            ),
            Finding::Unwritten { write, why } => {
                write!(f, "Hedwig did not write {write}: {why}")
            }
            Finding::TheirForward(forward) => write!(
                f,
                "your configuration asks for \"{forward}\" on every connection to this host, so it rides Hedwig's channel too; `Match originalhost <host> !tagged hedwig` keeps it to your own"
            ),
            Finding::HelperBeside(helper) => write!(
                f,
                "the remote's git gives every credential that works to your helper \"{helper}\" as well, so it may keep what Hedwig releases there; Hedwig leaves your helpers as they are"
            ),
            Finding::CacheLive(path) => write!(
                f,
                "git's own credential cache listens at {path}, started while Hedwig's forward was down, and may hold what worked; Hedwig leaves it running, and forwards there once you stop it with git credential-cache exit --socket {path}"
            ),
        }
    }
}

/// A key's kind as the person reads it.
pub fn kind_words(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::EcdsaP256 => "ECDSA P-256",
        KeyKind::EcdsaP384 => "ECDSA P-384",
        KeyKind::EcdsaP521 => "ECDSA P-521",
        KeyKind::Rsa2048 => "2048-bit RSA",
        KeyKind::Rsa3072 => "3072-bit RSA",
        KeyKind::Rsa4096 => "4096-bit RSA",
    }
}

/// What the person can do about a program of theirs that holds a source
/// where Hedwig will not carry a remote's connection to it: the source's own
/// tool, never an act of Hedwig's on a program that may be another person's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remedy {
    /// ADB's own `kill-server` stops whatever server answers at `port`; the
    /// person's next `adb` command starts one in the sign-in they run it from.
    AdbServer { port: Port },
    /// `gpgconf --kill gpg-agent` stops the agent of `home` through its own
    /// socket; Hedwig starts it again where it runs when a remote next asks.
    GnupgAgent { home: Home },
    /// Anything else: stopped where it was started, and started again in the
    /// sign-in Hedwig runs in.
    Restart,
}

impl Remedy {
    /// What the person can do about `failure` of `source`'s holder; `None`
    /// for a failure no act of the person's own on their program mends.
    pub fn of(source: &Source, failure: Failure) -> Option<Remedy> {
        if !matches!(failure, Failure::Unidentified | Failure::Confined) {
            return None;
        }
        Some(match source {
            Source::Service {
                stream: Stream::Adb,
                port: ServicePort::Fixed(port),
                ..
            } => Remedy::AdbServer { port: *port },
            Source::Gnupg { home, .. }
            | Source::Agent {
                at: AgentAt::Gnupg { home, .. },
            } => Remedy::GnupgAgent { home: home.clone() },
            _ => Remedy::Restart,
        })
    }
}

/// The remedy as the person reads it, each command as they would type it.
impl fmt::Display for Remedy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Remedy::AdbServer { port } => {
                f.write_str("if it is yours, ")?;
                if port.number() == 5037 {
                    f.write_str("adb kill-server")?;
                } else {
                    write!(f, "adb -P {port} kill-server")?;
                }
                f.write_str(
                    " stops it, and your next adb command starts one in the sign-in you run it from",
                )
            }
            Remedy::GnupgAgent { home } => {
                f.write_str("if it is yours, gpgconf ")?;
                if let Home::At(folder) = home {
                    write!(f, "--homedir \"{folder}\" ")?;
                }
                f.write_str(
                    "--kill gpg-agent stops it, and Hedwig starts it again where Hedwig runs when \
                     a remote next asks",
                )
            }
            Remedy::Restart => f.write_str(
                "if it is yours, stop it where it was started and start it again in the sign-in \
                 Hedwig runs in",
            ),
        }
    }
}
