//! One value of every kind the protocol, the trail and a document can carry.
//! The wire suite round-trips all of it and pins its bytes; the coverage
//! checks there fail when a variant is added without an example here.

use std::num::{NonZeroU8, NonZeroU16, NonZeroU32};

use hedwig_model::beyond::Beyond;
use hedwig_model::capability::{
    Access, AgentAt, Browser, Capability, Exposure, Holds, Home, Installation, KeyKind, Lends,
    LentKey, Offer, Operation, Query, ServiceHost, ServicePort, Setup, Source, Spot, Stream,
    Toward,
};
use hedwig_model::config::{
    Accepted, AcceptedEntry, Activation, BurstEntry, CadenceEntry, CapEntry, Change, Collision,
    DOCUMENT, Defined, Definitions, Denial, Document, Effect, FullScreenEntry, GrantEntry,
    HeardEntry, KeepaliveEntry, Reach, ReturnsEntry, RuleEntry,
};
use hedwig_model::gate::Capped;
use hedwig_model::holder::{Rights, SignedIn, SourceHolder, Whose};
use hedwig_model::install::{AtSignIn, Starts};
use hedwig_model::organisation::{
    GrantScope, Holding, Limit, Misread, Part, Place, Start, Statement, Unread,
};
use hedwig_model::platform::{AgentForwarding, Platform, Sockets};
use hedwig_model::policy::{
    Attended, Basis, ConnectionScope, KeyName, Keys, Limited, Mode, RuleScope, Selector,
};
use hedwig_model::process::{CoreState, Instance, Order, Report, Running};
use hedwig_model::protocol::{
    Act, AgentKey, Answer, Attached, Attachment, Attention, Bundle, CarriedOn, Contact, Decides,
    Decision, DeviceState, Differs, Exercised, Found, FromCore, Hint, Hold, Last, Lendable, Line,
    Loudness, Needs, Notice, Offered, Offering, PROTOCOL, Proof, RemoteSettings, Reply, Request,
    RouteSettings, Row, SerialPort, Served, SetAside, Settings, Standing, Status, Through, ToCore,
    Topic, Trial, Tried, Usb, WindowsStarts, Withdrawal, Withdrawn, Workstation,
    WorkstationSettings, Would, Written,
};
use hedwig_model::refusal::{Refusal, Section, Whereabouts, Withheld};
use hedwig_model::remote::{
    Argument, Client, Granted, Identity, Lister, Listing, Member, Remotes, Route, Set,
};
use hedwig_model::scope::{Audience, Holder, Tier};
use hedwig_model::setting::{
    Autostart, Bounded, Burst, Cadence, CapScope, Condition, Diagnostics, Expected, FullScreen,
    Heard, Keep, Keepalive, Lengths, Longest, Returns, Said, Settled, Span, Threshold, Volume,
    Waits, Workstation as SettingScope,
};
use hedwig_model::site::{Site, Unopenable};
use hedwig_model::text::{
    AgentPipe, DeviceSerial, DeviceSocket, Fingerprint, Folder, Grip, Host, Kernel, KeyId,
    Location, Mark, PipeName, Port, PortName, Program, Remark, RemotePath, Secret, Serial,
    ServiceName, SshKey, Template, Variable, Verbatim, Words,
};
use hedwig_model::trail::{
    Asking, Binding, Breakdown, Card, Carriage, Carry, ChannelEnd, ClientId, ClientKind,
    ConnectionId, Dropped, Entry, Event, Failure, Finding, Gave, Given, Health, Held, Icon,
    Integrity, Item, Key, Keyring, Missing, Network, Opener, Outcome, Payload, Prepared, Presence,
    PromptId, PromptKind, Readiness, Release, RequestId, Seq, Serving, SignaturePin, Store, Target,
    Tick, Timestamp, Touch, Uses, Withdrew, Write,
};

use super::{DESKTOP, OVER_SSH, grant, name, pattern, port, remote, terms};

const CLIENT: ClientId = ClientId(Seq(2));
const CONNECTION: ConnectionId = ConnectionId(Seq(5));
const REQUEST: RequestId = RequestId(Seq(9));

/// A long-lived host whose jobs tell the person what they did.
fn ops() -> hedwig_model::remote::RemoteId {
    remote("ssh", "ops@bastion.example")
}
const PROMPT: PromptId = PromptId(Seq(7));

/// A keepalive other than what ships.
pub(crate) fn keepalive() -> Keepalive {
    Keepalive {
        every: NonZeroU16::new(30).expect("non-zero"),
        missed: NonZeroU8::new(4).expect("non-zero"),
    }
}

/// Waits other than what ships.
pub(crate) fn returns() -> Returns {
    Returns {
        first: NonZeroU32::new(5).expect("non-zero"),
        longest: NonZeroU32::new(600).expect("non-zero"),
    }
}

/// A cadence other than what ships.
pub(crate) fn cadence() -> Cadence {
    Cadence(NonZeroU32::new(300).expect("non-zero"))
}

fn mark(text: &str) -> Mark {
    Mark::try_from(text).expect("a valid mark")
}

pub(crate) fn grip(text: &str) -> Grip {
    Grip::try_from(text).expect("a keygrip")
}

/// A key's public half, made by the in-box `ssh-keygen -t ed25519`.
pub(crate) const SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1cuDWSQ4xW25Rb1dBGnBjWHV2DfwPn/bqUaSYf4z15";

/// A key a TPM made, as the in-box `ssh-keygen -t ecdsa` writes one.
pub(crate) const MACHINE_KEY: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrm25FDDmgurPp+9REqiJK8zAJcpqMSElCklOS/AsegLtx+gx5BUgH5CnBk5aAOQSkrVsP5DuaWeib+dCzCSqo=";

/// A host's key, made by the in-box `ssh-keygen -t ecdsa`.
pub(crate) const HOST_KEY: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIQfBFoTFcymxqayVAmobeqqsWVKCgyRgJhRE4W7CDjAcuptlxzloqrpI2/N0w2y8dLIaPMBQcggIHZExfGvJ8c=";

pub(crate) fn ssh_key(text: &str) -> SshKey {
    SshKey::try_from(text).expect("a public key")
}

/// What an SSH agent's grant lends in the corpus: one key anywhere, one
/// only toward one host.
pub(crate) fn lent_keys() -> Lends {
    Lends::of_keys([
        (
            ssh_key(SSH_KEY),
            LentKey {
                toward: Toward::Anywhere,
                comment: Some(Words::try_from("laptop").unwrap()),
            },
        ),
        (
            ssh_key(HOST_KEY),
            Toward::Hosts([ssh_key(SSH_KEY)].into()).into(),
        ),
    ])
}

pub(crate) fn fingerprint(text: &str) -> Fingerprint {
    Fingerprint::try_from(text).expect("a fingerprint")
}

pub(crate) fn serial(text: &str) -> Serial {
    Serial::try_from(text).expect("a serial number")
}

/// The card the keyring's authentication key is on, as scdaemon writes its
/// serial number.
pub(crate) const CARD: &str = "D2760001240103040006123456780000";

/// A primary key that certifies and signs, with a subkey that encrypts and
/// one on a card that authenticates and is offered for SSH, as `GnuPG`
/// 2.5.24 lists them.
pub(crate) fn keyring() -> Keyring {
    let primary = fingerprint("07B56DFBBA12BB80FA84939C76F8274EF1651088");
    let user = Some(Words::try_from("Relay Test <relay@example.invalid>").unwrap());
    let key = |keygrip: &str, print: &str, uses: Uses| Key {
        grip: grip(keygrip),
        fingerprint: fingerprint(print),
        primary: primary.clone(),
        uses,
        user: user.clone(),
        card: uses.has(Uses::AUTHENTICATE).then(|| serial(CARD)),
        ssh: uses.has(Uses::AUTHENTICATE).then(|| ssh_key(SSH_KEY)),
    };
    Keyring {
        keys: vec![
            key(
                "64EFB4597F2EB1968F187B7235A461FC48342EC5",
                "07B56DFBBA12BB80FA84939C76F8274EF1651088",
                Uses::SIGN,
            ),
            key(
                "1D3AA6A1A0F4C9B92A3B5F07E6E0D0C3D4E5F601",
                "5C2E0B8F7A1D3C4E9F60718293A4B5C6D7E8F901",
                Uses::ENCRYPT,
            ),
            key(
                "9A8B7C6D5E4F30211203F4E5D6C7B8A9F0E1D2C3",
                "A1B2C3D4E5F60718293A4B5C6D7E8F9001122334",
                Uses::AUTHENTICATE.with(Uses::SIGN),
            ),
        ],
        signing: Some(mark("07B56DFBBA12BB80FA84939C76F8274EF1651088")),
    }
}

/// The sites a sign-in opens: an authorisation server, the names under a
/// provider's domain on a port of its own, and the remote's loopback.
pub(crate) fn sites() -> Vec<Site> {
    vec![
        "https://oidc.eu-west-1.amazonaws.com"
            .parse::<Site>()
            .unwrap(),
        "https://*.example.invalid:8443".parse::<Site>().unwrap(),
        "http://localhost".parse::<Site>().unwrap(),
    ]
}

pub(crate) fn sources() -> Vec<Source> {
    vec![
        Source::Browser {
            browser: Browser::Default,
            sites: sites(),
        },
        Source::Credentials {
            git: Program::try_from("git").unwrap(),
            sites: vec![
                "https://github.com".parse::<Site>().unwrap(),
                "https://*.dev.azure.com".parse::<Site>().unwrap(),
                "http://localhost:18463".parse::<Site>().unwrap(),
            ],
        },
        Source::Notices,
        Source::Serial {
            port: PortName::try_from("COM5").unwrap(),
            remote: port(4000),
        },
        Source::Browser {
            browser: Browser::Program {
                program: Program::try_from("msedge").unwrap(),
                arguments: vec![Verbatim::try_from("--profile-directory=Work").unwrap()],
            },
            sites: Vec::new(),
        },
        Source::Gnupg {
            installation: Installation::Registered,
            home: Home::Default,
            access: Access::Restricted,
        },
        Source::Gnupg {
            installation: Installation::At(
                Folder::try_from(r"D:\tools\gnupg-2.5.24").expect("a folder"),
            ),
            home: Home::At(Folder::try_from(r"D:\keys\release").expect("a folder")),
            access: Access::Unrestricted,
        },
        Source::Agent {
            at: AgentAt::Pipe(AgentPipe::well_known()),
        },
        Source::Agent {
            at: AgentAt::Gnupg {
                installation: Installation::Registered,
                home: Home::Default,
            },
        },
        Source::Service {
            host: ServiceHost::Workstation,
            port: ServicePort::Fixed(port(5037)),
            stream: Stream::Adb,
            remote: vec![
                Offer::PrivateSocket {
                    variable: Variable::try_from("ADB_SERVER_SOCKET").expect("a variable"),
                    value: Template::try_from("localfilesystem:{}").expect("a template"),
                },
                Offer::Port(ServicePort::Fixed(port(5037))),
            ],
        },
        Source::Service {
            host: ServiceHost::Named(Host::try_from("licence.lab.example").expect("a host")),
            port: ServicePort::Unstated,
            stream: Stream::Opaque,
            remote: vec![Offer::Port(ServicePort::Unstated)],
        },
        Source::Agent {
            at: AgentAt::Machine,
        },
    ]
}

pub(crate) fn platforms() -> Vec<Platform> {
    vec![
        Platform {
            family: name("haiku"),
            kernel: Kernel::try_from("Haiku").unwrap(),
            sockets: Sockets::Unix {
                path_bytes: NonZeroU16::new(126).expect("non-zero"),
            },
            agent_forwarding: AgentForwarding::Served,
        },
        Platform {
            family: name("reactos"),
            kernel: Kernel::try_from("ReactOS").unwrap(),
            sockets: Sockets::Emulated,
            agent_forwarding: AgentForwarding::Refused,
        },
    ]
}

fn literal(text: &str) -> Argument {
    Argument::Literal(Verbatim::try_from(text).expect("an argument"))
}

fn program(text: &str) -> Program {
    Program::try_from(text).expect("a program")
}

/// A route a person defines: reached through another program that lists its
/// running remotes.
pub(crate) fn lab() -> Route {
    Route {
        id: name("lab"),
        client: Client {
            program: program("lab-cli"),
            before: vec![
                literal("bench"),
                literal("ssh"),
                Argument::Address,
                literal("--"),
            ],
            after: Vec::new(),
        },
        listing: Listing::Lists(Lister {
            program: program("lab-cli"),
            arguments: vec![
                Verbatim::try_from("bench").expect("an argument"),
                Verbatim::try_from("list --running").expect("an argument"),
            ],
            header: 1,
        }),
        identity: Identity::Platform,
    }
}

/// The core route, whose client is reached directly and whose remotes nothing
/// lists, and a person's own.
pub(crate) fn routes() -> Vec<Route> {
    vec![
        Route {
            id: name("ssh"),
            client: Client {
                program: program("ssh"),
                before: Vec::new(),
                after: vec![Argument::Address],
            },
            listing: Listing::Blind,
            identity: Identity::HostKey,
        },
        lab(),
    ]
}

/// Hosts a provider named, which share no name a pattern could select, and
/// the ones a pattern does.
pub(crate) fn fleet() -> Set {
    Set {
        id: name("fleet"),
        members: vec![
            Member::One(remote("ssh", "ec2-203-0-113-7.compute.example")),
            Member::Matching {
                route: name("ssh"),
                pattern: pattern("db-*"),
            },
        ],
    }
}

pub(crate) fn granted() -> Vec<Granted> {
    vec![
        Granted::Route(name("coder")),
        Granted::Set(name("fleet")),
        Granted::Matching {
            route: name("coder"),
            pattern: pattern("dev/*"),
        },
        Granted::One(remote("ssh", "ops@bastion.example")),
    ]
}

pub(crate) fn remotes() -> Vec<Remotes> {
    let mut remotes: Vec<Remotes> = granted().into_iter().map(Remotes::from).collect();
    remotes.push(Remotes::Every);
    remotes
}

pub(crate) fn scopes() -> Vec<RuleScope> {
    vec![
        RuleScope {
            remotes: Remotes::Every,
            capability: Selector::Every,
            operation: Selector::Every,
            key: Keys::Every,
        },
        RuleScope {
            remotes: Remotes::One(remote("ssh", "ops@bastion.example")),
            capability: Selector::Only(name("gpg")),
            operation: Selector::Only(Operation::Decrypt),
            key: Keys::Every,
        },
        RuleScope {
            remotes: Remotes::Every,
            capability: Selector::Every,
            operation: Selector::Every,
            key: Keys::NeedingNoTouch,
        },
        RuleScope {
            remotes: Remotes::Set(name("fleet")),
            capability: Selector::Every,
            operation: Selector::Only(Operation::Sign),
            key: Keys::Only(KeyName::Fingerprint(fingerprint(
                "0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2",
            ))),
        },
    ]
}

pub(crate) fn keys() -> Vec<Keys> {
    scopes().into_iter().map(|scope| scope.key).collect()
}

fn connection_scope() -> ConnectionScope {
    ConnectionScope {
        capability: Selector::Only(name("gpg")),
        operation: Selector::Only(Operation::Sign),
        key: Keys::Every,
    }
}

/// The changes to how a channel's life is kept.
fn channel_changes() -> Vec<Change> {
    vec![
        Change::Keepalive {
            remotes: Remotes::Route(name("coder")),
            keepalive: Some(keepalive()),
        },
        Change::Keepalive {
            remotes: Remotes::Every,
            keepalive: None,
        },
        Change::Returns {
            remotes: Remotes::Every,
            returns: Some(returns()),
        },
        Change::Returns {
            remotes: Remotes::Route(name("coder")),
            returns: None,
        },
        Change::Cadence {
            routes: Selector::Only(name("coder")),
            cadence: Some(cadence()),
        },
        Change::Cadence {
            routes: Selector::Every,
            cadence: None,
        },
    ]
}

pub(crate) fn changes() -> Vec<Change> {
    let denial = Denial {
        capability: Selector::Only(name("gpg-unrestricted")),
        remotes: Remotes::Route(name("codespaces")),
    };
    let one = grant("adb", Granted::Route(name("coder")));
    let mut changes = vec![
        Change::Grant {
            grant: one.clone(),
            terms: hedwig_model::config::Terms {
                setup: Setup::Write,
                ..terms(Activation::WhileRunning, Exposure::SERVICE)
            },
        },
        Change::Revoke(one),
        Change::Deny(denial.clone()),
        Change::Undeny(denial),
        Change::Undefine(name("bench-scope")),
        Change::UndefinePlatform(name("haiku")),
        Change::DefineRoute(lab()),
        Change::UndefineRoute(name("lab")),
        Change::DefineSet(fleet()),
        Change::UndefineSet(name("fleet")),
        Change::Accept {
            grant: grant("adb", Granted::Route(name("coder"))),
            accepted: Accepted {
                setup: Setup::Write,
                acknowledged: Exposure::SERVICE,
                lends: lent(),
            },
        },
        Change::Unaccept(grant("adb", Granted::Route(name("coder")))),
        Change::Expect(expected()),
        Change::Unexpect(expected()),
        Change::Unhear {
            remotes: Remotes::Every,
            condition: Condition::Served,
        },
        Change::Lengths(Some(lengths())),
        Change::Lengths(None),
        Change::Autostart(Some(Autostart::AtLogon)),
        Change::Autostart(Some(Autostart::Off)),
        Change::Autostart(None),
        Change::Icon(Some(Autostart::AtLogon)),
        Change::Icon(None),
        Change::Keep(Some(days(90))),
        Change::Keep(None),
        Change::Diagnostics(Some(Diagnostics::Off)),
        Change::Diagnostics(Some(Diagnostics::Detail)),
        Change::Diagnostics(None),
    ];
    changes.extend(channel_changes());
    for remotes in remotes() {
        for threshold in thresholds().into_iter().map(Some).chain([None]) {
            changes.push(Change::Burst {
                remotes: remotes.clone(),
                threshold,
            });
        }
    }
    for heard in heard() {
        changes.push(Change::Hear {
            remotes: Remotes::Every,
            heard,
        });
    }
    for card in [Some(FullScreen::NotShown), Some(FullScreen::Shown), None] {
        changes.push(Change::FullScreen {
            remotes: Remotes::Route(name("coder")),
            card,
        });
    }
    for longest in longests().into_iter().map(Some).chain([None]) {
        changes.push(Change::Cap {
            scope: cap_scope(),
            longest,
        });
    }
    changes.push(Change::Cap {
        scope: ssh_cap_scope(),
        longest: None,
    });
    for scope in scopes() {
        changes.push(Change::Rule {
            scope: scope.clone(),
            mode: Mode::Confirm,
        });
        changes.push(Change::Unrule(scope));
    }
    for (index, source) in sources().into_iter().enumerate() {
        changes.push(Change::Define(Capability {
            id: name(&format!("mine-{index}")),
            source,
        }));
    }
    changes.extend(platforms().into_iter().map(Change::DefinePlatform));
    changes
}

pub(crate) fn thresholds() -> Vec<Threshold> {
    vec![
        Threshold::Never,
        Threshold::At(Burst {
            requests: NonZeroU8::new(20).expect("non-zero"),
            seconds: NonZeroU32::new(60).expect("non-zero"),
        }),
    ]
}

pub(crate) fn volumes() -> Vec<Volume> {
    vec![Volume::Shown, Volume::Announced, Volume::Interrupts]
}

pub(crate) fn conditions() -> Vec<Condition> {
    heard().into_iter().map(Heard::condition).collect()
}

/// One statement for each condition, and a changed host key at each volume.
pub(crate) fn heard() -> Vec<Heard> {
    let mut heard = vec![
        Heard::Served(Waits::Announced),
        Heard::Unready(Waits::Shown),
        Heard::Stopped(Waits::Announced),
        Heard::Refused(Waits::Shown),
        Heard::Noticed(Waits::Announced),
    ];
    heard.extend(volumes().into_iter().map(Heard::HostKeyChanged));
    heard
}

pub(crate) fn longests() -> Vec<Longest> {
    vec![
        Longest::Nothing,
        Longest::Seconds(NonZeroU32::new(900).expect("non-zero")),
    ]
}

pub(crate) fn lengths() -> Lengths {
    [60, 900, 3600, 28_800].into_iter().collect()
}

fn cap_scope() -> CapScope {
    CapScope {
        remotes: Remotes::Set(name("fleet")),
        key: Keys::Only(KeyName::Grip(grip(
            "0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2",
        ))),
    }
}

/// A cap on a key named as an SSH agent names it.
fn ssh_cap_scope() -> CapScope {
    CapScope {
        remotes: Remotes::Every,
        key: Keys::Only(KeyName::Ssh(ssh_key(SSH_KEY))),
    }
}

pub(crate) fn presences() -> Vec<Presence> {
    vec![
        Presence::Present,
        Presence::CardOnly,
        Presence::Engaged,
        Presence::Away,
    ]
}

pub(crate) fn whereabouts() -> Vec<Whereabouts> {
    vec![
        Whereabouts::Away,
        Whereabouts::Engaged,
        Whereabouts::FullScreen,
    ]
}

/// "I know this remote asks while I am away."
pub(crate) fn expected() -> Expected {
    Expected {
        remote: remote("coder", "dev/build"),
        refusal: Refusal::NobodyReachable(Whereabouts::Away),
    }
}

/// Every section of the document.
pub(crate) const SECTIONS: [Section; 16] = [
    Section::Capabilities,
    Section::Platforms,
    Section::Grants,
    Section::Denials,
    Section::Rules,
    Section::Routes,
    Section::Sets,
    Section::Accepted,
    Section::Bursts,
    Section::Heard,
    Section::Expected,
    Section::FullScreen,
    Section::Caps,
    Section::Keepalives,
    Section::Returns,
    Section::Cadences,
];

/// Every refusal the core gives of its own.
#[allow(
    clippy::too_many_lines,
    reason = "one example of every refusal the core gives"
)]
fn refusals_of_the_core() -> Vec<Refusal> {
    let remote = remote("coder", "dev/build");
    let mut refusals = vec![
        Refusal::Version { core: 2, client: 1 },
        Refusal::NotGreeted,
        Refusal::NotAttending,
        Refusal::NoIcon,
        Refusal::Malformed("a key given twice at byte 7".to_owned()),
        Refusal::UnknownCapability(name("gpgg")),
        Refusal::UnknownRoute(name("gitpod")),
        Refusal::UnknownSet(name("flet")),
        Refusal::UnknownPlatform(name("plan9")),
        Refusal::UnknownKernel(Kernel::try_from("GNU").unwrap()),
        Refusal::KernelClaimed {
            kernel: Kernel::try_from("Linux").unwrap(),
            first: name("linux"),
            second: name("wsl"),
        },
        Refusal::UnknownConnection(CONNECTION),
        Refusal::UnknownRequest(REQUEST),
        Refusal::UnknownPrompt(PROMPT),
        Refusal::Reserved(name("gpg")),
        Refusal::CapabilityInUse(name("mine-0")),
        Refusal::RouteInUse(name("lab")),
        Refusal::SetInUse(name("fleet")),
        Refusal::CapabilityIncomplete {
            capability: name("playwright"),
        },
        Refusal::ExposureNotAcknowledged {
            capability: name("gpg-unrestricted"),
            missing: Exposure::KEY_MANAGEMENT,
        },
        Refusal::Unlendable {
            capability: name("gpg"),
            lent: Holds::Devices,
        },
        Refusal::Unlendable {
            capability: name("adb"),
            lent: Holds::Keys,
        },
        Refusal::ActivationNeedsDiscovery { route: name("ssh") },
        Refusal::OperationNotInDialect {
            capability: name("adb"),
            operation: Operation::Sign,
        },
    ];
    refusals.extend(SECTIONS.map(Refusal::Repeated));
    refusals.extend([
        Refusal::Collides {
            section: Section::Capabilities,
            name: name("bench"),
        },
        Refusal::NotOffered {
            seconds: NonZeroU32::new(28_800).expect("non-zero"),
        },
        Refusal::DocumentVersion {
            found: 1,
            supported: 2,
        },
        Refusal::NoCarrier {
            capability: name("ssh-agent"),
            platform: name("windows"),
        },
        Refusal::NeedsRemoteSetup {
            capability: name("gpg"),
            platform: name("windows"),
        },
        Refusal::NoUnixSockets {
            platform: name("windows"),
        },
        Refusal::PlatformUnobserved(remote.clone()),
        Refusal::NotConnected(remote.clone()),
        Refusal::SocketPathTooLong {
            usable: 103,
            length: 118,
        },
        Refusal::NotGranted {
            capability: name("adb"),
            remote,
        },
        Refusal::Paused,
        Refusal::Withdrawn,
        Refusal::NobodyReachable(Whereabouts::Away),
        Refusal::NobodyReachable(Whereabouts::Engaged),
        Refusal::NobodyReachable(Whereabouts::FullScreen),
        Refusal::Declined,
        Refusal::NoChannel {
            process: 7312,
            program: None,
        },
        Refusal::NoChannel {
            process: 7312,
            program: Some(Location::try_from(r"C:\Users\dev\bin\probe.exe").unwrap()),
        },
        Refusal::Unattributable,
        Refusal::SourceUnavailable {
            capability: name("gpg"),
            failure: Failure::Unresolved,
        },
        Refusal::SourceUnavailable {
            capability: name("gpg"),
            failure: Failure::Unreachable,
        },
        Refusal::SourceUnavailable {
            capability: name("gpg"),
            failure: Failure::Mismatched,
        },
    ]);
    refusals.extend(refusals_of_the_relay());
    refusals
}

/// The refusals only a relay gives: of a `gpg` capability, and of a
/// workstation service.
fn refusals_of_the_relay() -> Vec<Refusal> {
    [
        ("adb", Failure::Foreign),
        ("adb", Failure::Confined),
        ("adb", Failure::Unidentified),
        ("selenium-grid", Failure::NoAddress),
        ("gpg", Failure::Unserved),
        ("browser", Failure::Unstartable),
        ("browser", Failure::Unopened),
        ("esp32", Failure::Absent),
        ("esp32", Failure::Busy),
        ("adb", Failure::Outdated),
        ("gpg-ssh", Failure::Occupied),
    ]
    .into_iter()
    .map(|(capability, failure)| Refusal::SourceUnavailable {
        capability: name(capability),
        failure,
    })
    .chain([
        Refusal::PortHeld {
            capability: name("esp32"),
            by: remote("ssh", "dev@build"),
        },
        Refusal::Shared {
            capability: name("esp32"),
            with: name("openocd"),
            spot: Spot::Port(Port::try_from(3333).unwrap()),
        },
        Refusal::Shared {
            capability: name("gpg-release"),
            with: name("gpg"),
            spot: Spot::Socket(Query::AgentSocket),
        },
        Refusal::Shared {
            capability: name("work"),
            with: name("personal"),
            spot: Spot::Variable(Variable::try_from("BROWSER").unwrap()),
        },
        Refusal::Shared {
            capability: name("agent"),
            with: name("ssh-agent"),
            spot: Spot::Socket(Query::AgentSshSocket),
        },
        Refusal::Unissued,
        Refusal::OffProtocol {
            capability: name("gpg"),
            account: Words::try_from("the remote sent a line longer than Assuan allows").unwrap(),
        },
    ])
    .chain(withheld().into_iter().map(|request| Refusal::Withheld {
        capability: name("adb"),
        request,
    }))
    .chain([
        Refusal::UnlistedSite {
            capability: name("browser"),
            site: sites().swap_remove(0),
        },
        Refusal::CallbackHeld {
            capability: name("browser"),
            port: Port::try_from(8000).unwrap(),
        },
    ])
    .chain(
        [
            Unopenable::TooLong,
            Unopenable::NotUrl,
            Unopenable::Scheme,
            Unopenable::Credentials,
            Unopenable::Host,
        ]
        .into_iter()
        .map(|why| Refusal::Unopenable {
            capability: name("browser"),
            why,
        }),
    )
    .collect()
}

/// Every request the ADB relay withholds from the workstation's server.
pub(crate) fn withheld() -> Vec<Withheld> {
    vec![
        Withheld::Ending,
        Withheld::Unlent(Some(DeviceSerial::try_from("R5CT1234ABC").unwrap())),
        Withheld::Unlent(None),
        Withheld::Every,
        Withheld::Unacknowledged,
        Withheld::Reaching,
        Withheld::Stopping,
        Withheld::Long,
        Withheld::Uncarriable,
        Withheld::Unforwardable,
        Withheld::Crowded,
        Withheld::Unlisted,
        Withheld::Outdated,
        Withheld::Unknown,
        Withheld::Hosted,
        Withheld::KeyUnlent(ssh_key(SSH_KEY)),
        Withheld::Elsewhere(ssh_key(SSH_KEY)),
        Withheld::Managing,
    ]
}

/// What a grant lends in the corpus: a phone by its USB serial, an emulator,
/// and a device on the network by its address.
pub(crate) fn lent() -> Lends {
    Lends::devices(
        ["R5CT1234ABC", "emulator-5554", "192.168.1.20:5555"]
            .into_iter()
            .map(|serial| DeviceSerial::try_from(serial).unwrap()),
    )
}

/// Every device in every state a source's listing gives, and every way it
/// is attached.
pub(crate) fn lendable() -> Vec<Lendable> {
    let states = [
        DeviceState::Connecting,
        DeviceState::Authorizing,
        DeviceState::Unauthorized,
        DeviceState::NoPermission,
        DeviceState::Detached,
        DeviceState::Offline,
        DeviceState::Bootloader,
        DeviceState::Device,
        DeviceState::Host,
        DeviceState::Recovery,
        DeviceState::Sideload,
        DeviceState::Rescue,
        DeviceState::Other(99),
    ];
    states
        .into_iter()
        .enumerate()
        .map(|(index, state)| Lendable {
            serial: (index != 2).then(|| {
                DeviceSerial::try_from(format!("emulator-{}", 5554 + 2 * index).as_str()).unwrap()
            }),
            model: (index % 2 == 0).then(|| Words::try_from("sdk_gphone64_x86_64").unwrap()),
            state,
            attached: if index % 3 == 0 {
                Attachment::Usb
            } else {
                Attachment::Socket
            },
        })
        .collect()
}

/// Every refusal, with one for each limit an organisation can state.
/// What a remote's `git` asking for a credential, and a remote's job telling
/// the person something, are refused with.
fn refusals_of_credentials_and_notices() -> Vec<Refusal> {
    vec![
        Refusal::UnlistedCredential {
            capability: name("git-https"),
            site: "https://git.example.invalid".parse::<Site>().unwrap(),
        },
        Refusal::NotWeb {
            capability: name("git-https"),
            protocol: Some(Words::try_from("smtp").unwrap()),
        },
        Refusal::NotWeb {
            capability: name("git-https"),
            protocol: None,
        },
        Refusal::Cleartext {
            capability: name("git-https"),
            site: "http://git.example.invalid".parse::<Site>().unwrap(),
        },
        Refusal::Hushed {
            capability: name("notices"),
        },
        Refusal::SourceUnavailable {
            capability: name("machine-ssh"),
            failure: Failure::NoTpm,
        },
        Refusal::KeyExists(name("laptop")),
        Refusal::KindUnmade(KeyKind::Rsa4096),
        Refusal::NoTpm,
        Refusal::KeyAbsent(ssh_key(MACHINE_KEY)),
    ]
}

pub(crate) fn refusals() -> Vec<Refusal> {
    refusals_of_the_core()
        .into_iter()
        .chain(refusals_of_credentials_and_notices())
        .chain([
            Refusal::AnswerUnfit {
                kind: PromptKind::KeyPassphrase,
            },
            Refusal::Unlisted(name("ssh")),
        ])
        .chain(
            limits()
                .into_iter()
                .zip([Audience::Machine, Audience::Person].into_iter().cycle())
                .map(|(limit, audience)| Refusal::Held {
                    audience,
                    limit: Box::new(limit),
                }),
        )
        .chain([
            Refusal::Unread(Audience::Machine),
            Refusal::Unread(Audience::Person),
        ])
        .collect()
}

/// One of each limit an organisation can state.
pub(crate) fn limits() -> Vec<Limit> {
    let scopes = scopes();
    vec![
        Limit::Floor {
            scope: scopes.get(2).cloned().expect("a scope"),
            mode: Mode::Confirm,
        },
        Limit::Activation {
            scope: GrantScope {
                capability: Selector::Every,
                remotes: Remotes::Route(name("codespaces")),
            },
            most: Activation::OnRequest,
        },
        Limit::InspectOnly(GrantScope {
            capability: Selector::Only(name("gpg")),
            remotes: Remotes::Set(name("fleet")),
        }),
        Limit::Cap {
            scope: cap_scope(),
            longest: Longest::Seconds(NonZeroU32::new(900).expect("non-zero")),
        },
        Limit::Cap {
            scope: CapScope {
                remotes: Remotes::Every,
                key: Keys::Every,
            },
            longest: Longest::Nothing,
        },
        Limit::Withhold {
            exposure: Exposure::NETWORK,
            remotes: Remotes::Every,
        },
        Limit::Confine {
            exposure: Exposure::SECRET.with(Exposure::KEY_MANAGEMENT),
            remotes: Remotes::Route(name("ssh")),
        },
        Limit::Deny(Denial {
            capability: Selector::Only(name("adb")),
            remotes: Remotes::Matching {
                route: name("coder"),
                pattern: pattern("dev/*"),
            },
        }),
        Limit::KeepAtLeast(days(14)),
        Limit::KeepAtMost(days(400)),
        Limit::DiagnosticsAtMost(Diagnostics::Faults),
    ]
}

pub(crate) fn days(days: u16) -> Keep {
    Keep(NonZeroU16::new(days).expect("non-zero"))
}

/// One of each statement an organisation's starting point can make.
pub(crate) fn starts() -> Vec<Start> {
    let reference = document();
    vec![
        Start::Define(
            reference
                .capabilities
                .first()
                .cloned()
                .expect("a capability"),
        ),
        Start::DefinePlatform(platforms().first().cloned().expect("a platform")),
        Start::DefineRoute(lab()),
        Start::DefineSet(fleet()),
        Start::Grant {
            grant: grant("gpg", Granted::Route(name("codespaces"))),
            activation: Activation::WhileRunning,
        },
        Start::Rule {
            scope: scopes().get(1).cloned().expect("a scope"),
            mode: Attended::Confirm,
        },
        Start::Rule {
            scope: scopes().first().cloned().expect("a scope"),
            mode: Attended::Notify,
        },
        Start::Burst {
            remotes: Remotes::Route(name("coder")),
            threshold: Threshold::At(Burst {
                requests: NonZeroU8::new(5).expect("non-zero"),
                seconds: NonZeroU32::new(60).expect("non-zero"),
            }),
        },
        Start::Autostart(Autostart::AtLogon),
        Start::Icon(Autostart::AtLogon),
        Start::Keep(days(60)),
        Start::Diagnostics(Diagnostics::Detail),
        Start::Keepalive {
            remotes: Remotes::Every,
            keepalive: keepalive(),
        },
        Start::Returns {
            remotes: Remotes::Route(name("coder")),
            returns: returns(),
        },
        Start::Cadence {
            routes: Selector::Only(name("coder")),
            cadence: cadence(),
        },
    ]
}

/// Whom to ask, in an organisation's own words.
pub(crate) fn ask() -> Words {
    Words::try_from("IT service desk, extension 4444, or it-desk@example.org").expect("words")
}

pub(crate) fn statements() -> Vec<Statement> {
    let mut statements: Vec<Statement> = limits().into_iter().map(Statement::Limit).collect();
    statements.extend(starts().into_iter().map(Statement::Start));
    statements.push(Statement::Ask(ask()));
    statements
}

pub(crate) fn places() -> Vec<Place> {
    [Audience::Machine, Audience::Person]
        .into_iter()
        .flat_map(|audience| {
            [Part::Limits, Part::Start, Part::Ask]
                .into_iter()
                .map(move |part| Place { audience, part })
        })
        .collect()
}

pub(crate) fn ends() -> Vec<ChannelEnd> {
    vec![
        ChannelEnd::Closed,
        ChannelEnd::RemoteGone,
        ChannelEnd::Needs(PromptKind::KeyPassphrase),
        ChannelEnd::HostKeyChanged(mark("SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s")),
        ChannelEnd::ForwardRefused,
        ChannelEnd::RouteNotSignedIn,
        ChannelEnd::ClientAbsent,
        ChannelEnd::Unstarted(Words::try_from("Access is denied. (os error 5)").unwrap()),
        ChannelEnd::Exited {
            status: -1,
            last: None,
        },
        ChannelEnd::Exited {
            status: 255,
            last: Some(
                Words::try_from("ssh: connect to host build-7 port 22: Connection timed out")
                    .unwrap(),
            ),
        },
        ChannelEnd::Declined(PromptKind::UnknownHostKey),
        ChannelEnd::Unauthenticated(Words::try_from("publickey,keyboard-interactive").unwrap()),
        ChannelEnd::NothingCarried,
        ChannelEnd::Slept,
        ChannelEnd::Reshaped,
    ]
}

pub(crate) fn findings() -> Vec<Finding> {
    let path = || RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap();
    let said = |text: &str| Words::try_from(text).unwrap();
    vec![
        Finding::Unsurveyed(said("no shell Hedwig knows ran there")),
        Finding::NoProfile(Refusal::UnknownKernel(Kernel::try_from("Haiku").unwrap())),
        Finding::ToolAbsent(name("gpgconf")),
        Finding::PathTooLong {
            usable: 103,
            length: 118,
        },
        Finding::PathUnusable,
        Finding::SharedHome(said("nfs4")),
        Finding::ParentUncreatable(said(
            "mkdir: cannot create directory: Read-only file system",
        )),
        Finding::Occupied(path()),
        Finding::AgentLive(path()),
        Finding::ServerLive {
            program: name("adb"),
            at: Binding::Socket(RemotePath::try_from("/run/user/1000/hedwig/adb").unwrap()),
        },
        Finding::ServerLive {
            program: name("adb"),
            at: Binding::Port(Port::try_from(5037).unwrap()),
        },
        Finding::UnitListens {
            unit: said("gpg-agent.socket"),
            path: path(),
        },
        Finding::Answers(path()),
        Finding::Silent(path()),
        Finding::Unprobed(path()),
        Finding::Uncleared(said("rm: cannot remove: Permission denied")),
        Finding::ListenerPresent(Port::try_from(5037).unwrap()),
        Finding::ForwardingBlocked,
        Finding::ForwardRefused,
        Finding::AgentAutostarts,
        Finding::KeyboxdStopped,
        Finding::PublicKeyAbsent(fingerprint("07B56DFBBA12BB80FA84939C76F8274EF1651088")),
        Finding::KeyringAbsent,
        Finding::SigningKeyUnset,
        Finding::SigningKeyOther(said("0xDEADBEEF")),
        Finding::VariableUnset(Variable::try_from("ADB_SERVER_SOCKET").unwrap()),
        Finding::TheirForward(said("localforward 8080 [localhost]:80")),
        Finding::HelperBeside(said("credential.helper store")),
        Finding::CacheLive(RemotePath::try_from("/run/user/1000/hedwig/git-https").unwrap()),
        Finding::Unwritten {
            write: Write::Helper,
            why: said("the socket's path /home/a b/.hedwig holds a character git would split"),
        },
        Finding::Unwritten {
            write: Write::Variable(Variable::try_from("ADB_SERVER_SOCKET").unwrap()),
            why: said("/bin/dash reads its startup from files Hedwig does not know"),
        },
        Finding::Unwritten {
            write: Write::NoAutostart,
            why: said("its keys are in keyboxd, which gpg could no longer start"),
        },
    ]
}

pub(crate) fn writes() -> Vec<Write> {
    let key = || fingerprint("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2");
    vec![
        Write::NoAutostart,
        Write::PublicKey(key()),
        Write::SigningKey(mark(key().as_str())),
        Write::Variable(Variable::try_from("SSH_AUTH_SOCK").unwrap()),
        Write::SocketFile,
        Write::Masked,
        Write::Helper,
    ]
}

pub(crate) fn prompt_kinds() -> Vec<PromptKind> {
    vec![
        PromptKind::UnknownHostKey,
        PromptKind::KeyPassphrase,
        PromptKind::Password,
        PromptKind::SecurityKeyPin,
        PromptKind::Challenge,
        PromptKind::AgentConfirmation,
        PromptKind::SecurityKeyTouch,
    ]
}

pub(crate) fn bindings() -> Vec<Binding> {
    let path = |text: &str| RemotePath::try_from(text).expect("a path");
    vec![
        Binding::Socket(path("/run/user/2000/gnupg/S.gpg-agent")),
        Binding::SocketFile {
            file: path(r"C:\Users\dev\AppData\Local\gnupg\S.gpg-agent"),
            port: port(49731),
        },
        Binding::Port(port(5037)),
    ]
}

pub(crate) fn bases() -> Vec<Basis> {
    let mut bases = vec![Basis::Default, Basis::Connection(connection_scope())];
    bases.extend(scopes().into_iter().map(Basis::Rule));
    let floor = scopes().into_iter().next().expect("a scope");
    for audience in [Audience::Machine, Audience::Person] {
        bases.push(Basis::Start {
            audience,
            scope: floor.clone(),
        });
        bases.push(Basis::Limit(Box::new(Limited {
            audience,
            scope: floor.clone(),
            chose: Mode::Notify,
            basis: Basis::Rule(floor.clone()),
        })));
    }
    bases
}

pub(crate) fn outcomes() -> Vec<Outcome> {
    let mut outcomes = vec![
        Outcome::Allowed(CLIENT),
        Outcome::Covered,
        Outcome::Abandoned,
        Outcome::Unseen(Basis::Rule(scopes().into_iter().next().expect("a scope"))),
    ];
    outcomes.extend(bases().into_iter().map(Outcome::Served));
    outcomes.extend(refusals().into_iter().map(Outcome::Refused));
    outcomes
}

/// A card whose signing key needs no touch, whose decryption key does once in
/// a while, and whose third key's touch the core could not read.
pub(crate) fn card() -> Card {
    Card {
        serial: serial(CARD),
        keys: vec![
            Held {
                grip: grip("64EFB4597F2EB1968F187B7235A461FC48342EC5"),
                touch: Some(Touch::Off),
            },
            Held {
                grip: grip("1D3AA6A1A0F4C9B92A3B5F07E6E0D0C3D4E5F601"),
                touch: Some(Touch::Cached),
            },
            Held {
                grip: grip("9A8B7C6D5E4F30211203F4E5D6C7B8A9F0E1D2C3"),
                touch: None,
            },
        ],
        pin: Some(SignaturePin::Once),
    }
}

pub(crate) fn items() -> Vec<Item> {
    let remote = remote("coder", "dev/build");
    vec![
        Item::Unready {
            remote: remote.clone(),
            capability: name("gpg"),
        },
        Item::Stopped(remote.clone()),
        Item::Burst(remote.clone()),
        Item::Safeguards(serial(CARD)),
        Item::Refused {
            remote: Some(remote.clone()),
            refusal: Refusal::NobodyReachable(Whereabouts::Away),
        },
        Item::Refused {
            remote: None,
            refusal: Refusal::NoChannel {
                process: 7312,
                program: None,
            },
        },
        Item::Restarted,
        Item::Unreadable(Store::Trail),
        Item::Unreadable(Store::Configuration),
        Item::Widened(Seq(41)),
        Item::Unseen(remote),
        Item::Policy(Place {
            audience: Audience::Person,
            part: Part::Start,
        }),
        Item::Unlisted(name("codespaces")),
        Item::Noticed {
            remote: ops(),
            through: Seq(52),
        },
    ]
}

/// An access violation's status, a panic's, and a hang.
pub(crate) fn breakdowns() -> Vec<Breakdown> {
    vec![
        Breakdown::Exited {
            status: 0xc000_0005,
        },
        Breakdown::Exited { status: 101 },
        Breakdown::Hung,
        Breakdown::Unstarted,
    ]
}

fn pipe() -> PipeName {
    PipeName::try_from("hedwig.9f86d081884c7d659a2feaa0c55ad015").expect("a pipe name")
}

pub(crate) fn running() -> Vec<Running> {
    let supervisor = Instance {
        process: 4100,
        created: 134_037_216_000_000_000,
    };
    let mut states = vec![
        CoreState::Starting,
        CoreState::Serving {
            pipe: pipe(),
            process: 4200,
        },
    ];
    states.extend(breakdowns().into_iter().map(|cause| CoreState::Restarting {
        cause,
        said: "the trail could not be written: there is not enough space on the disk".to_owned(),
    }));
    states
        .into_iter()
        .map(|core| Running { supervisor, core })
        .collect()
}

pub(crate) fn orders() -> Vec<Order> {
    let mut orders = vec![Order::Begin { after: None }, Order::Ping];
    orders.extend(
        breakdowns()
            .into_iter()
            .map(|cause| Order::Begin { after: Some(cause) }),
    );
    orders
}

pub(crate) fn reports() -> Vec<Report> {
    vec![Report::Ready { pipe: pipe() }, Report::Pong]
}

#[allow(clippy::too_many_lines, reason = "one example of every event")]
pub(crate) fn events() -> Vec<Event> {
    let remote = remote("coder", "dev/build");
    let mut events = vec![
        Event::Started {
            version: "0.2.0 (v0.2.0)".to_owned(),
            origin: DESKTOP,
            after: None,
        },
        Event::Attached {
            kind: ClientKind::Interface,
            origin: DESKTOP,
            attends: Remotes::Every,
        },
        Event::Attached {
            kind: ClientKind::Terminal,
            origin: OVER_SSH,
            attends: Remotes::Every,
        },
        Event::Attached {
            kind: ClientKind::Viewer,
            origin: DESKTOP,
            attends: Remotes::Every,
        },
        Event::Attached {
            kind: ClientKind::Command,
            origin: hedwig_model::trail::Origin {
                integrity: Integrity::Low,
                ..DESKTOP
            },
            attends: Remotes::Every,
        },
        Event::Attached {
            kind: ClientKind::Terminal,
            origin: OVER_SSH,
            attends: Remotes::One(remote.clone()),
        },
        Event::Presence {
            client: CLIENT,
            presence: Presence::Away,
        },
        Event::Presence {
            client: CLIENT,
            presence: Presence::CardOnly,
        },
        Event::Presence {
            client: CLIENT,
            presence: Presence::Engaged,
        },
        Event::Presence {
            client: CLIENT,
            presence: Presence::Present,
        },
        Event::Icon {
            client: CLIENT,
            icon: Icon::Missing(Missing::NoTaskbar),
        },
        Event::Icon {
            client: CLIENT,
            icon: Icon::Shown,
        },
        Event::Detached { client: CLIENT },
        Event::Imported {
            by: CLIENT,
            reach: Reach::Wider,
        },
        Event::Imported {
            by: CLIENT,
            reach: Reach::NoWider,
        },
        Event::Appeared {
            remote: remote.clone(),
        },
        Event::Gone {
            remote: remote.clone(),
        },
        Event::Opening {
            remote: remote.clone(),
            with: vec![name("adb")],
            opener: Opener::Person(CLIENT),
            acknowledged: Exposure::SERVICE.with(Exposure::NETWORK),
            lends: lent(),
        },
        Event::Opening {
            remote: remote.clone(),
            with: Vec::new(),
            opener: Opener::Grant,
            acknowledged: Exposure::NONE,
            lends: Lends::Every,
        },
        Event::Opening {
            remote: remote.clone(),
            with: Vec::new(),
            opener: Opener::Again,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
        Event::Opening {
            remote: remote.clone(),
            with: Vec::new(),
            opener: Opener::Check(CLIENT),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
        Event::Ran {
            connection: CONNECTION,
            program: Location::try_from(r"C:\Windows\System32\OpenSSH\ssh.exe").unwrap(),
            release: Some(Release {
                major: 9,
                minor: 5,
                build: 6,
                revision: 3,
            }),
            asking: Asking::Person,
        },
        Event::Ran {
            connection: CONNECTION,
            program: Location::try_from(r"C:\Program Files\Git\usr\bin\ssh.exe").unwrap(),
            release: None,
            asking: Asking::Nobody,
        },
        Event::Disconnected {
            remote: remote.clone(),
            by: CLIENT,
        },
        Event::Unlisted {
            route: name("codespaces"),
            account: Some(Words::try_from("HTTP 401: Bad credentials").unwrap()),
        },
        Event::Unlisted {
            route: name("codespaces"),
            account: None,
        },
        Event::Observed {
            connection: CONNECTION,
            platform: name("linux"),
        },
        Event::Checked {
            connection: CONNECTION,
            capability: name("gpg"),
            readiness: Readiness::Ready,
        },
        Event::Checked {
            connection: CONNECTION,
            capability: name("gpg"),
            readiness: Readiness::Unready(findings()),
        },
        Event::Prepared {
            connection: CONNECTION,
            capability: name("gpg"),
            prepared: Prepared::Created(RemotePath::try_from("/home/dev/.gnupg").unwrap()),
        },
        Event::Wrote {
            connection: CONNECTION,
            capability: name("gpg"),
            write: Write::NoAutostart,
            place: RemotePath::try_from("/home/dev/.gnupg/common.conf").unwrap(),
            made: None,
        },
        Event::Wrote {
            connection: CONNECTION,
            capability: name("gpg"),
            write: Write::Masked,
            place: RemotePath::try_from("/home/dev/.config/systemd/user/gpg-agent.socket").unwrap(),
            made: Some(RemotePath::try_from("/home/dev/.config").unwrap()),
        },
        Event::Unwrote {
            connection: CONNECTION,
            capability: name("gpg"),
            write: Write::NoAutostart,
            place: RemotePath::try_from("/home/dev/.gnupg/common.conf").unwrap(),
        },
        Event::Prepared {
            connection: CONNECTION,
            capability: name("gpg"),
            prepared: Prepared::Removed(
                RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap(),
            ),
        },
        Event::Answered {
            prompt: PROMPT,
            by: Some(Gave {
                client: CLIENT,
                given: Given::Text,
            }),
        },
        Event::Answered {
            prompt: PROMPT,
            by: Some(Gave {
                client: CLIENT,
                given: Given::Accepted,
            }),
        },
        Event::Answered {
            prompt: PROMPT,
            by: Some(Gave {
                client: CLIENT,
                given: Given::Declined,
            }),
        },
        Event::Answered {
            prompt: PROMPT,
            by: None,
        },
        Event::Up {
            connection: CONNECTION,
            serving: bindings()
                .into_iter()
                .map(|binding| Serving {
                    capability: name("gpg"),
                    binding,
                })
                .collect(),
        },
        Event::TurnedAway {
            remote: None,
            refusal: Refusal::Unattributable,
        },
        Event::Asked {
            connection: CONNECTION,
            capability: name("gpg"),
            operation: Operation::Sign,
            key: Some(KeyId::Grip(grip(
                "0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2",
            ))),
        },
        Event::Asked {
            connection: CONNECTION,
            capability: name("ssh-agent"),
            operation: Operation::Authenticate,
            key: Some(KeyId::Ssh(ssh_key(SSH_KEY))),
        },
        Event::Payload {
            request: REQUEST,
            payload: Payload::Authentication {
                user: Some(Words::try_from("git").unwrap()),
                host: Some(ssh_key(HOST_KEY)),
            },
        },
        Event::Payload {
            request: REQUEST,
            payload: Payload::Authentication {
                user: None,
                host: None,
            },
        },
        Event::Payload {
            request: REQUEST,
            payload: Payload::Signature {
                namespace: Some(Words::try_from("git").unwrap()),
            },
        },
        Event::Payload {
            request: REQUEST,
            payload: Payload::Unread,
        },
        Event::Payload {
            request: REQUEST,
            payload: Payload::Credential {
                site: "https://github.com".parse::<Site>().unwrap(),
            },
        },
        Event::Unreleased { request: REQUEST },
        Event::Refuted {
            connection: CONNECTION,
            capability: name("git-https"),
            site: "https://github.com".parse::<Site>().unwrap(),
        },
        Event::Noticed {
            connection: CONNECTION,
            capability: name("notices"),
            remark: Remark::try_from("build 4512 finished: 3 failed").unwrap(),
            unheard: 0,
        },
        Event::Noticed {
            connection: CONNECTION,
            capability: name("notices"),
            remark: Remark::try_from("Claude needs your permission to use Bash").unwrap(),
            unheard: 7,
        },
        Event::Startup {
            starts: Starts::Hedwig,
            found: AtSignIn::AsChosen,
        },
        Event::Startup {
            starts: Starts::Icon,
            found: AtSignIn::Absent,
        },
        Event::Startup {
            starts: Starts::Hedwig,
            found: AtSignIn::Another(None),
        },
        Event::Startup {
            starts: Starts::Hedwig,
            found: AtSignIn::Unkept(
                Words::try_from(
                    "the values Windows starts at sign-in could not be kept: Access is denied. \
                     (os error 5)",
                )
                .expect("words"),
            ),
        },
        Event::HeldBy {
            capability: name("ssh-agent"),
            holder: Some(SourceHolder {
                program: Location::try_from(r"C:\Program Files\1Password\app\8\1Password.exe")
                    .unwrap(),
                session: 2,
                whose: Whose::Person {
                    logon: 0x04ef_6c7c,
                    signed_in: SignedIn::Locally,
                    rights: Rights::Standard,
                },
            }),
        },
        Event::HeldBy {
            capability: name("adb"),
            holder: Some(SourceHolder {
                program: Location::try_from(
                    r"C:\Users\ali\AppData\Local\Android\Sdk\platform-tools\adb.exe",
                )
                .unwrap(),
                session: 0,
                whose: Whose::Person {
                    logon: 0x0731_0a2e,
                    signed_in: SignedIn::OverTheNetwork,
                    rights: Rights::Administrator,
                },
            }),
        },
        Event::HeldBy {
            capability: name("licence"),
            holder: Some(SourceHolder {
                program: Location::try_from("svchost.exe").unwrap(),
                session: 0,
                whose: Whose::Service {
                    services: vec![
                        ServiceName::try_from("RpcEptMapper").unwrap(),
                        ServiceName::try_from("RpcSs").unwrap(),
                    ],
                },
            }),
        },
        Event::HeldBy {
            capability: name("adb"),
            holder: Some(SourceHolder {
                program: Location::try_from("adb.exe").unwrap(),
                session: 0,
                whose: Whose::Unread,
            }),
        },
        Event::HeldBy {
            capability: name("openocd"),
            holder: Some(SourceHolder {
                program: Location::try_from(r"C:\Users\ali\AppData\Local\Temp\squat.exe").unwrap(),
                session: 2,
                whose: Whose::Confined,
            }),
        },
        Event::HeldBy {
            capability: name("openocd"),
            holder: Some(SourceHolder {
                program: Location::try_from("openocd.exe").unwrap(),
                session: 3,
                whose: Whose::Another,
            }),
        },
        Event::HeldBy {
            capability: name("ssh-agent"),
            holder: None,
        },
        Event::KeyMade {
            key: ssh_key(MACHINE_KEY),
            name: name("laptop"),
            by: CLIENT,
        },
        Event::KeyDeleted {
            key: ssh_key(MACHINE_KEY),
            name: name("laptop"),
            by: CLIENT,
        },
        Event::Asked {
            connection: CONNECTION,
            capability: name("adb"),
            operation: Operation::Connect,
            key: None,
        },
        Event::Held { request: REQUEST },
        Event::Allowed {
            connection: CONNECTION,
            capability: name("gpg"),
            operation: Operation::Decrypt,
            until: Tick(900_000),
            by: CLIENT,
            key: None,
        },
        Event::Ruled {
            connection: CONNECTION,
            scope: connection_scope(),
            mode: Some(Mode::Unattended),
            by: CLIENT,
        },
        Event::Exercised {
            connection: CONNECTION,
            capability: name("gpg"),
            proof: Proof::Reached(REQUEST),
            by: CLIENT,
        },
        Event::Asked {
            connection: CONNECTION,
            capability: name("browser"),
            operation: Operation::Open,
            key: None,
        },
        Event::Browsed {
            request: REQUEST,
            site: sites().swap_remove(0),
            callback: Some(Port::try_from(41237).unwrap()),
        },
        Event::Browsed {
            request: REQUEST,
            site: "https://github.com".parse::<Site>().unwrap(),
            callback: None,
        },
        Event::Uncarried {
            request: REQUEST,
            end: Carry::Called,
        },
        Event::Uncarried {
            request: REQUEST,
            end: Carry::Expired,
        },
        Event::Uncarried {
            request: REQUEST,
            end: Carry::Ended,
        },
        Event::Ruled {
            connection: CONNECTION,
            scope: ConnectionScope {
                capability: Selector::Every,
                operation: Selector::Every,
                key: Keys::Every,
            },
            mode: None,
            by: CLIENT,
        },
        Event::Card(card()),
        Event::Card(Card {
            serial: serial("FF0200010000000000000000000000"),
            keys: vec![Held {
                grip: grip("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2"),
                touch: Some(Touch::On),
            }],
            pin: Some(SignaturePin::Forced),
        }),
        Event::Card(Card {
            serial: serial("D2760001240103040006876543210000"),
            keys: Vec::new(),
            pin: None,
        }),
        Event::Offered {
            capability: name("gpg"),
            keyring: keyring(),
        },
        Event::Offered {
            capability: name("gpg-unrestricted"),
            keyring: Keyring::default(),
        },
        Event::Carried {
            connection: CONNECTION,
            capability: name("adb"),
            carriage: Carriage::Reverse(Target::Loopback(port(8081))),
            endpoint: port(50131),
        },
        Event::Carried {
            connection: CONNECTION,
            capability: name("adb"),
            carriage: Carriage::Reverse(Target::Host {
                host: Host::try_from("db.internal").unwrap(),
                port: port(5432),
            }),
            endpoint: port(50132),
        },
        Event::Carried {
            connection: CONNECTION,
            capability: name("adb"),
            carriage: Carriage::Reverse(Target::Path(
                RemotePath::try_from("/run/user/1000/metro.sock").unwrap(),
            )),
            endpoint: port(50133),
        },
        Event::Carried {
            connection: CONNECTION,
            capability: name("adb"),
            carriage: forward(),
            endpoint: port(58765),
        },
        Event::Carried {
            connection: CONNECTION,
            capability: name("adb"),
            carriage: console(),
            endpoint: port(50134),
        },
        Event::Dropped {
            connection: CONNECTION,
            capability: name("adb"),
            carriage: forward(),
            why: Dropped::Removed,
        },
        Event::Dropped {
            connection: CONNECTION,
            capability: name("adb"),
            carriage: forward(),
            why: Dropped::Gone,
        },
        Event::Dropped {
            connection: CONNECTION,
            capability: name("adb"),
            carriage: console(),
            why: Dropped::Unlent,
        },
        Event::Dropped {
            connection: CONNECTION,
            capability: name("adb"),
            carriage: forward(),
            why: Dropped::Taken,
        },
        Event::Taken {
            request: RequestId(Seq(301)),
            connection: CONNECTION,
            capability: name("esp32"),
            port: PortName::try_from("COM5").unwrap(),
            usb: Some(Usb {
                vendor: 0x303A,
                product: 0x1001,
            }),
        },
        Event::Taken {
            request: RequestId(Seq(305)),
            connection: CONNECTION,
            capability: name("esp32"),
            port: PortName::try_from("COM3").unwrap(),
            usb: None,
        },
        Event::Released {
            request: RequestId(Seq(301)),
        },
        Event::Source {
            capability: name("gpg"),
            health: Health::Sound,
        },
        Event::Source {
            capability: name("adb"),
            health: Health::Failing(Failure::Unreachable),
        },
        Event::Stopping { by: CLIENT },
        Event::Withdrawn { by: CLIENT },
        Event::Restored { by: CLIENT },
        Event::Diagnosed {
            level: Some(Diagnostics::Detail),
            by: CLIENT,
        },
        Event::Diagnosed {
            level: None,
            by: CLIENT,
        },
        Event::Kept {
            dropped: 3,
            cut: hedwig_model::trail::Cut::Horizon,
        },
        Event::Kept {
            dropped: 4_096,
            cut: hedwig_model::trail::Cut::Ceiling,
        },
        Event::Sleeping,
        Event::Woke,
        Event::Offline,
        Event::Online,
        Event::Unreadable {
            store: Store::Trail,
            account: "line 812: a key given twice at byte 7".to_owned(),
        },
        Event::Unreadable {
            store: Store::Configuration,
            account: "version has 2, and this Hedwig reads 1".to_owned(),
        },
    ];
    events.extend(breakdowns().into_iter().map(|cause| Event::Started {
        version: "0.2.0 (v0.2.0)".to_owned(),
        origin: OVER_SSH,
        after: Some(cause),
    }));
    for kind in [
        ClientKind::Command,
        ClientKind::Terminal,
        ClientKind::Interface,
        ClientKind::Prompt,
    ] {
        for integrity in [Integrity::Medium, Integrity::High, Integrity::System] {
            events.push(Event::Attached {
                kind,
                origin: hedwig_model::trail::Origin {
                    integrity,
                    ..OVER_SSH
                },
                attends: Remotes::Every,
            });
        }
    }
    events.extend(
        changes()
            .into_iter()
            .zip([Reach::Wider, Reach::NoWider].into_iter().cycle())
            .map(|(change, reach)| Event::Changed {
                change,
                by: CLIENT,
                reach,
            }),
    );
    for scope in remotes() {
        events.push(Event::Paused {
            scope: scope.clone(),
            by: CLIENT,
        });
        events.push(Event::Resumed { scope, by: CLIENT });
    }
    events.extend(prompt_kinds().into_iter().map(|kind| Event::Prompted {
        connection: CONNECTION,
        kind,
        words: Words::try_from("Verification code:\n").expect("words"),
    }));
    events.extend(ends().into_iter().map(|end| Event::Down {
        connection: CONNECTION,
        end,
    }));
    events.extend(outcomes().into_iter().map(|outcome| Event::Settled {
        request: REQUEST,
        outcome,
    }));
    events.extend(
        items()
            .into_iter()
            .map(|item| Event::PutAway { item, by: CLIENT }),
    );
    events.extend(
        statements()
            .into_iter()
            .zip([Audience::Machine, Audience::Person].into_iter().cycle())
            .map(|(statement, audience)| Event::Stated {
                audience,
                statement,
            }),
    );
    events.push(Event::Unstated {
        audience: Audience::Machine,
        statement: Statement::Limit(limits().into_iter().last().expect("a limit")),
    });
    events.push(Event::Misread {
        place: Place {
            audience: Audience::Machine,
            part: Part::Limits,
        },
        unread: Some(Unread {
            lines: vec![3, 7],
            account: "limits.3 has \"most\", which is not known here".to_owned(),
        }),
    });
    events.push(Event::Misread {
        place: Place {
            audience: Audience::Machine,
            part: Part::Limits,
        },
        unread: None,
    });
    events
}

pub(crate) fn entries() -> Vec<Entry> {
    events()
        .into_iter()
        .zip(1u64..)
        .map(|(event, number)| Entry {
            seq: Seq(number),
            at: Timestamp(1_790_000_000_000 + number),
            tick: Tick(number * 10),
            event,
        })
        .collect()
}

pub(crate) fn document() -> Document {
    Document {
        version: DOCUMENT,
        capabilities: sources()
            .into_iter()
            .enumerate()
            .map(|(index, source)| Capability {
                id: name(&format!("mine-{index}")),
                source,
            })
            .collect(),
        platforms: platforms(),
        routes: vec![lab()],
        sets: vec![fleet()],
        grants: granted()
            .into_iter()
            .map(|remotes| GrantEntry {
                grant: grant("gpg", remotes),
                terms: terms(Activation::Continuous, Exposure::NONE),
            })
            .collect(),
        accepted: vec![AcceptedEntry {
            grant: grant("adb", Granted::Route(name("coder"))),
            accepted: Accepted {
                setup: Setup::Inspect,
                acknowledged: Exposure::SERVICE,
                lends: Lends::none(),
            },
        }],
        denials: remotes()
            .into_iter()
            .map(|remotes| Denial {
                capability: Selector::Every,
                remotes,
            })
            .collect(),
        rules: scopes()
            .into_iter()
            .zip([Mode::Unattended, Mode::Notify, Mode::Confirm, Mode::Confirm])
            .map(|(scope, mode)| RuleEntry { scope, mode })
            .collect(),
        bursts: remotes()
            .into_iter()
            .zip(thresholds().into_iter().cycle())
            .map(|(remotes, threshold)| BurstEntry { remotes, threshold })
            .collect(),
        heard: heard()
            .into_iter()
            .take(5)
            .map(|heard| HeardEntry {
                remotes: Remotes::Route(name("coder")),
                heard,
            })
            .collect(),
        expected: vec![expected()],
        full_screen: vec![FullScreenEntry {
            remotes: Remotes::Every,
            card: FullScreen::NotShown,
        }],
        lengths: Some(lengths()),
        caps: longests()
            .into_iter()
            .zip([Keys::Every, Keys::NeedingNoTouch])
            .map(|(longest, key)| CapEntry {
                scope: CapScope {
                    remotes: Remotes::Every,
                    key,
                },
                longest,
            })
            .collect(),
        autostart: Some(Autostart::AtLogon),
        icon: Some(Autostart::Off),
        keep: Some(days(45)),
        diagnostics: Some(Diagnostics::Detail),
        keepalives: vec![KeepaliveEntry {
            remotes: Remotes::Every,
            keepalive: keepalive(),
        }],
        returns: vec![ReturnsEntry {
            remotes: Remotes::Route(name("coder")),
            returns: returns(),
        }],
        cadences: vec![CadenceEntry {
            routes: Selector::Only(name("coder")),
            cadence: cadence(),
        }],
    }
}

/// What a channel's askpass asks.
fn prompt_requests() -> Vec<Request> {
    let words = |text: &str| Words::try_from(text).expect("words");
    vec![
        Request::Prompt {
            words: words("Enter passphrase for key 'C:\\Users\\dev\\.ssh\\id_ed25519': "),
            hint: None,
        },
        Request::Prompt {
            words: words("Add key id_ed25519 (dev@build-7) to agent?"),
            hint: Some(Hint::Confirm),
        },
        Request::Prompt {
            words: words(
                "Confirm user presence for key ECDSA-SK \
                 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
            ),
            hint: Some(Hint::Notice),
        },
    ]
}

#[allow(clippy::too_many_lines, reason = "one example of every request")]
pub(crate) fn requests() -> Vec<Request> {
    let remote = remote("coder", "dev/build");
    let mut requests = vec![
        Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Terminal,
            attends: Remotes::Every,
        },
        Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Terminal,
            attends: Remotes::One(remote.clone()),
        },
        Request::Status,
        Request::Exposure,
        Request::Attention,
        Request::Catalogue,
        Request::Workstation,
        Request::Export,
        Request::Activity {
            remote: Selector::Only(remote.clone()),
            before: Some(Seq(400)),
            limit: NonZeroU8::new(50).expect("non-zero"),
        },
        Request::Activity {
            remote: Selector::Every,
            before: None,
            limit: NonZeroU8::MAX,
        },
        Request::Follow {
            after: Some(Seq(12)),
        },
        Request::Follow { after: None },
        Request::Import(Box::new(document())),
        Request::Connect {
            remote: remote.clone(),
            with: vec![name("playwright-ci")],
            acknowledged: Exposure::SERVICE.with(Exposure::NETWORK),
            lends: Lends::none(),
        },
        Request::Connect {
            remote: remote.clone(),
            with: vec![name("adb")],
            acknowledged: Exposure::SERVICE,
            lends: lent(),
        },
        Request::Devices(name("adb")),
        Request::Keys(name("ssh-agent")),
        Request::Connect {
            remote: remote.clone(),
            with: vec![name("ssh-agent")],
            acknowledged: Exposure::KEY_USE,
            lends: lent_keys(),
        },
        Request::Ports,
        Request::Withdraw,
        Request::Withdrawal,
        Request::Restore,
        Request::Bundle,
        Request::Diagnose(Some(Diagnostics::Detail)),
        Request::Diagnose(None),
        Request::Disconnect {
            remote: remote.clone(),
        },
        Request::Decide {
            request: REQUEST,
            decision: Decision::Once,
        },
        Request::Decide {
            request: REQUEST,
            decision: Decision::For(NonZeroU32::new(900).expect("non-zero")),
        },
        Request::Decide {
            request: REQUEST,
            decision: Decision::Refuse,
        },
        Request::Answer {
            prompt: PROMPT,
            answer: Answer::Text(Secret::from("correct horse \"battery\"".to_owned())),
        },
        Request::Answer {
            prompt: PROMPT,
            answer: Answer::Accept,
        },
        Request::Answer {
            prompt: PROMPT,
            answer: Answer::Decline,
        },
        Request::Rule {
            connection: CONNECTION,
            scope: connection_scope(),
            mode: Some(Mode::Confirm),
        },
        Request::Rule {
            connection: CONNECTION,
            scope: connection_scope(),
            mode: None,
        },
        Request::Check {
            remote: remote.clone(),
            capability: name("gpg"),
        },
        Request::Exercise {
            remote,
            capability: name("gpg"),
        },
        Request::Presence(Presence::Away),
        Request::Icon(Icon::Shown),
        Request::Icon(Icon::Missing(Missing::Refused)),
        Request::Icon(Icon::Missing(Missing::NoTaskbar)),
        Request::Stop,
    ];
    requests.extend(changes().into_iter().map(Request::Change));
    for scope in remotes() {
        requests.push(Request::Pause(scope.clone()));
        requests.push(Request::Resume(scope));
    }
    requests.extend(items().into_iter().map(Request::PutAway));
    requests.extend(asking());
    requests.extend(prompt_requests());
    requests.extend(keys_made());
    requests
}

/// The requests that make and delete a key in the workstation's TPM.
fn keys_made() -> Vec<Request> {
    vec![
        Request::MakeKey {
            name: name("laptop"),
            kind: KeyKind::EcdsaP256,
        },
        Request::MakeKey {
            name: name("azure"),
            kind: KeyKind::Rsa2048,
        },
        Request::DeleteKey(ssh_key(MACHINE_KEY)),
    ]
}

/// The requests that ask what holds and what would.
fn asking() -> Vec<Request> {
    vec![
        Request::Settings {
            remotes: vec![remote("ssh", "ops@bastion.example")],
        },
        Request::Try(Box::new(trial())),
        Request::Try(Box::new(Trial {
            policy: None,
            document: None,
            change: None,
            remotes: Vec::new(),
        })),
    ]
}

pub(crate) fn standings() -> Vec<Standing> {
    let mut standings = vec![
        Standing::Idle,
        Standing::Checking,
        Standing::Opening,
        Standing::Needs(PromptKind::UnknownHostKey),
        Standing::Unready(findings()),
        Standing::Unavailable(Refusal::NoCarrier {
            capability: name("ssh-agent"),
            platform: name("windows"),
        }),
        Standing::Paused,
        Standing::Returning {
            end: ChannelEnd::ForwardRefused,
            wait: NonZeroU32::new(41),
        },
        Standing::Returning {
            end: ChannelEnd::Slept,
            wait: None,
        },
    ];
    standings.extend(bindings().into_iter().map(Standing::Serving));
    standings.extend(ends().into_iter().map(Standing::Ended));
    standings
}

#[allow(clippy::too_many_lines, reason = "one row of every standing")]
pub(crate) fn rows() -> Vec<Row> {
    let remote = remote("coder", "dev/build");
    let acts = [
        Act::Connect,
        Act::Disconnect,
        Act::Pause,
        Act::Resume,
        Act::Revoke,
        Act::Deny,
        Act::Accept,
        Act::Check,
        Act::Exercise,
    ];
    standings()
        .into_iter()
        .enumerate()
        .map(|(index, standing)| Row {
            capability: name("gpg"),
            exposure: Exposure::KEY_USE.with(Exposure::KEY_MANAGEMENT),
            remote: (index % 2 == 0).then(|| remote.clone()),
            connection: (index % 4 == 0).then_some(CONNECTION),
            through: match index % 4 {
                0 => Through::Grant(grant("gpg", Granted::Route(name("coder")))),
                2 => Through::Start {
                    audience: Audience::Machine,
                    grant: grant("gpg", Granted::Route(name("codespaces"))),
                },
                _ => Through::Connection(CONNECTION),
            },
            findings: if index % 3 == 0 {
                findings()
            } else {
                Vec::new()
            },
            written: if index % 3 == 1 {
                writes()
                    .into_iter()
                    .map(|write| Written {
                        made: (write == Write::Masked)
                            .then(|| RemotePath::try_from("/home/dev/.config").unwrap()),
                        write,
                        place: RemotePath::try_from("/home/dev/.gnupg/common.conf").unwrap(),
                    })
                    .collect()
            } else {
                Vec::new()
            },
            carried: if index % 3 == 2 {
                vec![
                    CarriedOn {
                        carriage: Carriage::Reverse(Target::Loopback(port(8081))),
                        endpoint: port(50131),
                    },
                    CarriedOn {
                        carriage: Carriage::Reverse(Target::Path(
                            RemotePath::try_from("/run/user/1000/metro.sock").unwrap(),
                        )),
                        endpoint: port(50133),
                    },
                    CarriedOn {
                        carriage: forward(),
                        endpoint: port(58765),
                    },
                    CarriedOn {
                        carriage: console(),
                        endpoint: port(50134),
                    },
                ]
            } else {
                Vec::new()
            },
            beyond: match index % 3 {
                0 => vec![Beyond::ChipUsb],
                1 => vec![Beyond::PortPerRun],
                _ => Vec::new(),
            },
            hold: (index % 3 == 1).then(|| Hold {
                request: RequestId(Seq(301)),
                port: PortName::try_from("COM5").unwrap(),
                since: Timestamp(1_790_000_002_000),
            }),
            standing,
            decides: bases()
                .into_iter()
                .zip([Operation::Connect, Operation::Sign, Operation::Decrypt])
                .map(|(basis, operation)| Decides {
                    operation,
                    mode: Mode::Notify,
                    basis,
                    key: None,
                })
                .collect(),
            terms: (index % 2 == 0).then(|| terms(Activation::OnRequest, Exposure::NONE)),
            holds: if index % 4 == 0 {
                holdings()
            } else {
                Vec::new()
            },
            last: (index % 3 == 0).then(|| Last {
                request: RequestId(Seq(88)),
                at: Timestamp(1_790_000_001_000),
                operation: Operation::Sign,
                outcome: (index % 2 == 0).then_some(Outcome::Covered),
            }),
            acts: acts
                .iter()
                .map(|act| Offered {
                    act: *act,
                    withheld: (*act == Act::Exercise).then_some(Refusal::Paused),
                })
                .collect(),
        })
        .collect()
}

/// Every kind of attention, each at a volume it can have.
pub(crate) fn needs() -> Vec<Needs> {
    attention()
        .into_iter()
        .zip(volumes().into_iter().rev().cycle())
        .map(|(attention, volume)| Needs { attention, volume })
        .collect()
}

pub(crate) fn attention() -> Vec<Attention> {
    let remote = remote("coder", "dev/build");
    vec![
        Attention::Request {
            request: REQUEST,
            remote: remote.clone(),
            capability: name("gpg"),
            operation: Operation::Sign,
            key: Some(KeyId::Grip(grip(
                "0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2",
            ))),
            payload: None,
            offers: lengths().iter().take(2).collect(),
            capped: Some(Capped {
                longest: Longest::Seconds(NonZeroU32::new(900).expect("non-zero")),
                holder: Holder::Organisation(Audience::Person),
                scope: cap_scope(),
            }),
        },
        Attention::Widened {
            entry: entries().into_iter().last().expect("an entry"),
            kind: ClientKind::Command,
            origin: DESKTOP,
        },
        Attention::Unseen {
            remote: remote.clone(),
            served: 12,
        },
        Attention::Prompt {
            prompt: PROMPT,
            remote: remote.clone(),
            kind: PromptKind::UnknownHostKey,
            words: Words::try_from("ED25519 key fingerprint is SHA256:uNiVztksCsDhcc0u9e8B.")
                .expect("words"),
        },
        Attention::Unready {
            remote: remote.clone(),
            capability: name("gpg"),
            findings: findings(),
        },
        Attention::Stopped {
            remote: remote.clone(),
            end: ChannelEnd::ForwardRefused,
        },
        Attention::Burst {
            remote: remote.clone(),
            requests: 40,
        },
        Attention::Safeguards(card()),
        Attention::Refused {
            remote: Some(remote),
            refusal: Refusal::NobodyReachable(Whereabouts::Engaged),
            times: 3,
        },
        Attention::Restarted {
            cause: Breakdown::Hung,
            times: 2,
        },
        Attention::Unreadable {
            store: Store::Trail,
            account: "line 812: a key given twice at byte 7".to_owned(),
        },
        Attention::Policy {
            place: Place {
                audience: Audience::Machine,
                part: Part::Limits,
            },
            since: Seq(40),
            arrived: 3,
            withdrawn: 1,
            unread: 2,
        },
        Attention::Unlisted {
            route: name("codespaces"),
            account: Words::try_from("HTTP 401: Bad credentials").expect("words"),
        },
        Attention::Noticed {
            remote: ops(),
            notice: Seq(52),
            at: Timestamp(1_790_000_000_000),
            remark: Remark::try_from("deploy to eu-west finished").expect("a remark"),
            unheard: 0,
        },
        Attention::Withdrawn(withdrew()),
        Attention::Request {
            request: REQUEST,
            remote: ops(),
            capability: name("git-https"),
            operation: Operation::Connect,
            key: None,
            payload: Some(Payload::Credential {
                site: "https://github.com".parse::<Site>().expect("a site"),
            }),
            offers: lengths().iter().collect(),
            capped: None,
        },
    ]
}

/// What the catalogue answers: a definition of each source, and a collision
/// between the organisation's and the person's own.
fn definitions() -> Definitions {
    Definitions {
        beyond: Beyond::ALL.to_vec(),
        capabilities: vec![Defined {
            definition: Capability {
                id: name("ssh-agent"),
                source: Source::Agent {
                    at: AgentAt::Pipe(AgentPipe::well_known()),
                },
            },
            by: Tier::Ships,
        }],
        routes: routes()
            .into_iter()
            .map(|route| Defined {
                definition: route,
                by: Tier::Start(Audience::Machine),
            })
            .collect(),
        platforms: platforms()
            .into_iter()
            .map(|platform| Defined {
                definition: platform,
                by: Tier::Start(Audience::Person),
            })
            .collect(),
        sets: vec![Defined {
            definition: fleet(),
            by: Tier::Ships,
        }],
        collisions: vec![Collision {
            section: Section::Capabilities,
            name: name("bench-licence"),
            by: vec![Tier::Start(Audience::Machine), Tier::Person],
        }],
    }
}

/// What the workstation's side holds: each source's health, a card, the
/// remotes running and a keyring.
fn workstation() -> Workstation {
    Workstation {
        sources: vec![
            Found {
                capability: name("gpg"),
                health: Some(Health::Sound),
                holder: Some(SourceHolder {
                    program: Location::try_from(r"C:\Program Files\GnuPG\bin\gpg-agent.exe")
                        .unwrap(),
                    session: 2,
                    whose: Whose::Person {
                        logon: 0x04ef_6c7c,
                        signed_in: SignedIn::Locally,
                        rights: Rights::Standard,
                    },
                }),
            },
            Found {
                capability: name("adb"),
                health: Some(Health::Failing(Failure::Unreachable)),
                holder: None,
            },
            Found {
                capability: name("ssh-agent"),
                health: None,
                holder: Some(SourceHolder {
                    program: Location::try_from(r"C:\Windows\System32\OpenSSH\ssh-agent.exe")
                        .unwrap(),
                    session: 0,
                    whose: Whose::Service {
                        services: vec![ServiceName::try_from("ssh-agent").unwrap()],
                    },
                }),
            },
        ],
        cards: vec![card()],
        running: vec![remote("coder", "dev/build")],
        keys: vec![Offering {
            capability: name("gpg"),
            keyring: keyring(),
        }],
    }
}

/// A status with a client of each kind.
pub(crate) fn status() -> Status {
    Status {
        version: "0.2.0 (v0.2.0)".to_owned(),
        since: Timestamp(1_790_000_000_000),
        origin: DESKTOP,
        attached: vec![
            Attached {
                client: CLIENT,
                kind: ClientKind::Terminal,
                origin: OVER_SSH,
                presence: Some(Presence::Present),
                icon: None,
                attends: Remotes::Every,
            },
            Attached {
                client: ClientId(Seq(3)),
                kind: ClientKind::Viewer,
                origin: DESKTOP,
                presence: None,
                icon: None,
                attends: Remotes::Every,
            },
            Attached {
                client: ClientId(Seq(4)),
                kind: ClientKind::Interface,
                origin: DESKTOP,
                presence: Some(Presence::CardOnly),
                icon: Some(Icon::Missing(Missing::Refused)),
                attends: Remotes::Every,
            },
        ],
        paused: remotes(),
        connected: vec![remote("coder", "dev/build")],
        attention: 2,
        network: Network::Offline,
        withdrawn: Some(withdrew()),
    }
}

/// A removal begun and not finished.
pub(crate) fn withdrew() -> Withdrew {
    Withdrew {
        entry: Seq(40),
        at: Timestamp(1_790_000_000_000),
    }
}

/// A supporter's bundle with a part of every kind.
pub(crate) fn bundle() -> Bundle {
    Bundle {
        version: "0.2.0 (v0.2.0)".to_owned(),
        program: "C:\\Users\\dev\\AppData\\Local\\Programs\\ShuwariAfrica\\Hedwig".to_owned(),
        windows: "10.0.26100.6584".to_owned(),
        status: status(),
        attention: needs(),
        exposure: rows(),
        settings: settings(),
        activity: entries(),
        diagnostics: vec![
            "{\"at\":1790000000000,\"from\":\"channel 7\",\"said\":\"Connection refused\"}"
                .to_owned(),
        ],
        set_aside: vec![SetAside {
            name: "trail.unreadable-1790000000000.jsonl".to_owned(),
            bytes: 4096,
            at: Timestamp(1_790_000_000_000),
        }],
    }
}

pub(crate) fn replies() -> Vec<Reply> {
    vec![
        Reply::Welcome {
            protocol: PROTOCOL,
            version: "0.2.0 (v0.2.0)".to_owned(),
            you: OVER_SSH,
        },
        Reply::Status(status()),
        Reply::Exposure(rows()),
        Reply::Attention(needs()),
        Reply::Catalogue(definitions()),
        Reply::Workstation(workstation()),
        Reply::Document(Box::new(document())),
        Reply::Activity(entries()),
        Reply::Done(Effect::Changed),
        Reply::Done(Effect::Unchanged),
        Reply::Changed {
            effect: Effect::Changed,
            held: holdings(),
        },
        Reply::Changed {
            effect: Effect::Unchanged,
            held: Vec::new(),
        },
        Reply::Settings(Box::new(settings())),
        Reply::Row(Box::new(rows().into_iter().next().expect("a row"))),
        Reply::Answer(Answer::Text(Secret::from("correct horse".to_owned()))),
        Reply::Answer(Answer::Accept),
        Reply::Answer(Answer::Decline),
        Reply::Devices(lendable()),
        Reply::Devices(Vec::new()),
        Reply::Keys(vec![
            AgentKey {
                key: ssh_key(SSH_KEY),
                comment: Some(Words::try_from("ali@workstation").unwrap()),
            },
            AgentKey {
                key: ssh_key(HOST_KEY),
                comment: None,
            },
        ]),
        Reply::Made(AgentKey {
            key: ssh_key(MACHINE_KEY),
            comment: Some(Words::try_from("laptop").unwrap()),
        }),
        Reply::Ports(vec![
            SerialPort {
                port: PortName::try_from("COM5").unwrap(),
                name: Some(
                    Words::try_from("Silicon Labs CP210x USB to UART Bridge (COM5)").unwrap(),
                ),
                usb: Some(Usb {
                    vendor: 0x10C4,
                    product: 0xEA60,
                }),
            },
            SerialPort {
                port: PortName::try_from("COM3").unwrap(),
                name: None,
                usb: None,
            },
        ]),
        Reply::Ports(Vec::new()),
        Reply::Withdrawal(vec![
            Withdrawal {
                remote: remote("coder", "dev/build"),
                left: vec![Written {
                    write: Write::NoAutostart,
                    place: RemotePath::try_from("/home/dev/.gnupg/common.conf").expect("a path"),
                    made: None,
                }],
                surveying: false,
                ended: Some(ChannelEnd::Closed),
            },
            Withdrawal {
                remote: remote("ssh", "build.example"),
                left: Vec::new(),
                surveying: true,
                ended: None,
            },
        ]),
        Reply::Bundle(Box::new(bundle())),
    ]
    .into_iter()
    .chain(
        tried()
            .into_iter()
            .map(|tried| Reply::Tried(Box::new(tried))),
    )
    .collect()
}

/// A limit of each holder's.
pub(crate) fn holdings() -> Vec<Holding> {
    vec![
        Holding {
            holder: Holder::Organisation(Audience::Machine),
            limit: limits().get(1).cloned().expect("a limit"),
        },
        Holding {
            holder: Holder::Person,
            limit: Limit::Cap {
                scope: cap_scope(),
                longest: Longest::Seconds(NonZeroU32::new(60).expect("non-zero")),
            },
        },
    ]
}

/// A trial of everything at once: a policy with a line that cannot be read,
/// a document and one change.
pub(crate) fn trial() -> Trial {
    Trial {
        policy: Some(
            statements()
                .into_iter()
                .filter_map(|statement| match statement {
                    Statement::Limit(limit) => Some(Line {
                        place: Place {
                            audience: Audience::Machine,
                            part: Part::Limits,
                        },
                        text: hedwig_model::wire::line(&limit),
                    }),
                    _ => None,
                })
                .chain([Line {
                    place: Place {
                        audience: Audience::Person,
                        part: Part::Ask,
                    },
                    text: "the IT desk".to_owned(),
                }])
                .collect(),
        ),
        document: Some(document()),
        change: changes().into_iter().next(),
        remotes: vec![remote("ssh", "ops@bastion.example")],
    }
}

#[allow(clippy::too_many_lines, reason = "one of every setting")]
pub(crate) fn settings() -> Settings {
    let remote = remote("coder", "dev/build");
    let seconds = |seconds| Longest::Seconds(NonZeroU32::new(seconds).expect("non-zero"));
    Settings {
        workstation: WorkstationSettings {
            lengths: Settled {
                value: lengths(),
                said: Said::Ships,
            },
            autostart: Settled {
                value: Autostart::AtLogon,
                said: Said::Start {
                    audience: Audience::Machine,
                    scope: SettingScope,
                },
            },
            icon: Settled {
                value: Autostart::Off,
                said: Said::Person(SettingScope),
            },
            windows: WindowsStarts {
                hedwig: Some(AtSignIn::AsChosen),
                icon: Some(AtSignIn::Another(Some(
                    Words::try_from(
                        r#""C:\Users\dev\AppData\Local\Programs\hedwig\hedwig.exe" serve"#,
                    )
                    .expect("words"),
                ))),
            },
            keep: Bounded {
                settled: Settled {
                    value: days(14),
                    said: Said::Person(SettingScope),
                },
                held: Some(Audience::Machine),
            },
            diagnostics: Bounded {
                settled: Settled {
                    value: Diagnostics::Detail,
                    said: Said::Person(Span::Run),
                },
                held: None,
            },
            contacts: vec![Contact {
                audience: Audience::Machine,
                words: ask(),
            }],
            unread: vec![Misread {
                place: Place {
                    audience: Audience::Person,
                    part: Part::Start,
                },
                unread: Unread {
                    lines: vec![0],
                    account: "the value has \"grants\", which is not known here".to_owned(),
                },
            }],
        },
        remotes: vec![RemoteSettings {
            remote,
            threshold: Settled {
                value: Threshold::Never,
                said: Said::Person(Remotes::Route(name("coder"))),
            },
            volumes: conditions()
                .into_iter()
                .map(|condition| Loudness {
                    condition,
                    volume: Settled {
                        value: condition.ships(),
                        said: Said::Ships,
                    },
                })
                .collect(),
            full_screen: Settled {
                value: FullScreen::Shown,
                said: Said::Start {
                    audience: Audience::Person,
                    scope: Remotes::Every,
                },
            },
            caps: vec![
                Capped {
                    longest: seconds(60),
                    holder: Holder::Person,
                    scope: cap_scope(),
                },
                Capped {
                    longest: seconds(900),
                    holder: Holder::Organisation(Audience::Person),
                    scope: CapScope {
                        remotes: Remotes::Every,
                        key: Keys::Every,
                    },
                },
            ],
            keepalive: Settled {
                value: keepalive(),
                said: Said::Start {
                    audience: Audience::Machine,
                    scope: Remotes::Every,
                },
            },
            returns: Settled {
                value: Returns::SHIPS,
                said: Said::Ships,
            },
        }],
        routes: vec![RouteSettings {
            route: name("codespaces"),
            cadence: Settled {
                value: cadence(),
                said: Said::Person(Selector::Only(name("codespaces"))),
            },
        }],
    }
}

/// A trial refused, and one answered with every kind of difference.
pub(crate) fn tried() -> Vec<Tried> {
    let rows = rows();
    let settings = settings();
    let remote = settings
        .remotes
        .first()
        .cloned()
        .expect("a remote's settings");
    let quieter = RemoteSettings {
        threshold: Settled {
            value: Threshold::Never,
            said: Said::Ships,
        },
        ..remote.clone()
    };
    vec![
        Tried::Refused(Refusal::UnknownCapability(name("vault"))),
        Tried::Would(Box::new(Would {
            reach: Reach::Wider,
            rows: vec![
                Differs {
                    before: None,
                    after: rows.first().cloned(),
                },
                Differs {
                    before: rows.get(1).cloned(),
                    after: None,
                },
                Differs {
                    before: rows.get(2).cloned(),
                    after: rows.get(3).cloned(),
                },
            ],
            remotes: vec![Differs {
                before: Some(remote),
                after: Some(quieter),
            }],
            workstation: Some(Differs {
                before: Some(settings.workstation.clone()),
                after: Some(WorkstationSettings {
                    contacts: Vec::new(),
                    ..settings.workstation
                }),
            }),
        })),
    ]
}

pub(crate) fn notices() -> Vec<Notice> {
    let mut notices = vec![
        Notice::Withdrawn(Withdrawn::Request(REQUEST)),
        Notice::Withdrawn(Withdrawn::Prompt(PROMPT)),
        Notice::Stale(Topic::Status),
        Notice::Stale(Topic::Exposure),
        Notice::Stale(Topic::Attention),
        Notice::Stale(Topic::Configuration),
        Notice::Stale(Topic::Workstation),
        Notice::Stale(Topic::Devices(name("adb"))),
        Notice::Stale(Topic::Ports),
        Notice::Stale(Topic::Keys(name("machine-ssh"))),
    ];
    notices.extend(needs().into_iter().map(Notice::Raised));
    notices.push(Notice::Served(Served {
        request: REQUEST,
        remote: remote("coder", "dev/build"),
        capability: name("gpg"),
        operation: Operation::Sign,
        key: Some(KeyId::Grip(grip(
            "0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2",
        ))),
        payload: None,
    }));
    notices.push(Notice::Served(Served {
        request: REQUEST,
        remote: remote("coder", "dev/build"),
        capability: name("ssh-agent"),
        operation: Operation::Authenticate,
        key: Some(KeyId::Ssh(ssh_key(SSH_KEY))),
        payload: Some(Payload::Authentication {
            user: Some(Words::try_from("git").unwrap()),
            host: Some(ssh_key(HOST_KEY)),
        }),
    }));
    notices.extend(entries().into_iter().take(3).map(Notice::Recorded));
    notices.extend(proofs().into_iter().map(|proof| {
        Notice::Exercised(Exercised {
            remote: remote("coder", "dev/build"),
            capability: name("gpg"),
            proof,
        })
    }));
    notices
}

/// Each thing a remote's tool can be found to have done when exercised.
pub(crate) fn proofs() -> Vec<Proof> {
    vec![
        Proof::Reached(REQUEST),
        Proof::Silent(None),
        Proof::Silent(Some(
            Words::try_from("gpg: signing failed: No secret key").unwrap(),
        )),
        Proof::Unrun(Finding::ToolAbsent(name("gpg"))),
        Proof::Unrun(Finding::KeyringAbsent),
    ]
}

/// Every frame a client can send, in order.
pub(crate) fn to_core() -> Vec<ToCore> {
    requests()
        .into_iter()
        .zip(1u32..)
        .map(|(request, id)| ToCore { id, request })
        .collect()
}

/// Every frame the core can send, in order.
pub(crate) fn from_core() -> Vec<FromCore> {
    let mut frames: Vec<FromCore> = replies()
        .into_iter()
        .zip(1u32..)
        .map(|(reply, id)| FromCore::Reply {
            id,
            reply: Ok(reply),
        })
        .collect();
    frames.extend(
        refusals()
            .into_iter()
            .zip(100u32..)
            .map(|(refusal, id)| FromCore::Reply {
                id,
                reply: Err(refusal),
            }),
    );
    frames.extend(notices().into_iter().map(FromCore::Notice));
    frames
}

/// A forward a remote asked for, as the trail and a row carry it.
pub(crate) fn forward() -> Carriage {
    Carriage::Forward {
        port: port(9222),
        device: DeviceSerial::try_from("emulator-5554").unwrap(),
        socket: DeviceSocket::try_from("localabstract:chrome_devtools_remote").unwrap(),
    }
}

/// A lent emulator's console, as the trail and a row carry it.
pub(crate) fn console() -> Carriage {
    Carriage::Console {
        port: port(5554),
        device: DeviceSerial::try_from("emulator-5554").unwrap(),
    }
}
