//! Channels held for real: a stand-in client that does on cue what an OpenSSH
//! client does, started by the threads the core uses, in a job of its own -
//! and the workstation's own `ssh.exe`, as far as it goes with no remote.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_core::channel::{Askpass, Channels, Order, PIPE, SET, Setting, environment};
use hedwig_core::dispatch::{Core, Effect, Input, Knock, Link, Now, Step, Told};
use hedwig_core::run::Message;
use hedwig_core::serve::Server;
use hedwig_model::capability::{Exposure, Lends, Setup};
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Grant, Terms};
use hedwig_model::protocol::{PROTOCOL, Request, ToCore};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Argument, Client, Granted, RemoteId, Remotes};
use hedwig_model::setting::Keepalive;
use hedwig_model::text::{Address, Mark, Name, PipeName, Port, Program, RemotePath, Verbatim};
use hedwig_model::trail::{
    Asking, Binding, ChannelEnd, ClientKind, ConnectionId, Event, Integrity, Origin, Peer, Seq,
    Serving, Tick, Timestamp,
};
use hedwig_support::{Folder, ended_within, inheritable};
use hedwig_win::process::{Job, Process};
use hedwig_win::start::{Environment, held};
use hedwig_win::token::Token;

const WAIT: Duration = Duration::from_secs(20);
const CONNECTION: ConnectionId = ConnectionId(Seq(7));

fn child() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_child"))
}

/// Where the channels these tests hold send what they ask: a program of the
/// suite's, through a pipe nothing listens on.
fn askpass() -> Askpass {
    Askpass {
        program: child(),
        pipe: PipeName::try_from("hedwig.00000000000000000000000000000000").unwrap(),
    }
}

fn literal(text: &str) -> Argument {
    Argument::Literal(Verbatim::try_from(text).unwrap())
}

fn gpg() -> Serving {
    Serving {
        capability: Name::try_from("gpg").unwrap(),
        binding: Binding::Socket(RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap()),
    }
}

fn adb() -> Serving {
    Serving {
        capability: Name::try_from("adb").unwrap(),
        binding: Binding::Port(Port::try_from(5037).unwrap()),
    }
}

/// The channels of a core, and what its deciding thread would be told.
struct Held {
    channels: Channels,
    messages: Sender<Message>,
    told: Receiver<Message>,
    passed: RefCell<Vec<Message>>,
    folder: Folder,
}

impl Held {
    /// A core that finds its clients beside the stand-in, and whose own
    /// variables would raise a prompt through a program of the person's.
    fn new(purpose: &str) -> Held {
        let own = Environment::own()
            .with("SSH_ASKPASS", r"C:\Tools\askpass.exe")
            .with("DISPLAY", ":0");
        let setting = Setting {
            search: child().parent().unwrap().as_os_str().to_owned(),
            environment: environment(own, &askpass()),
        };
        let (messages, told) = mpsc::channel();
        Held {
            channels: Channels::new(setting, messages.clone()),
            messages,
            told,
            passed: RefCell::default(),
            folder: Folder::new(purpose),
        }
    }

    /// The next message that is `wanted`; what comes before it is passed
    /// over.
    fn until(&self, wanted: impl Fn(&Message) -> bool) -> Message {
        loop {
            let message = self.told.recv_timeout(WAIT).expect("more is told");
            if wanted(&message) {
                return message;
            }
            // Kept, not dropped: a pipe client's connection lasts as long
            // as what it would be answered through.
            self.passed.borrow_mut().push(message);
        }
    }

    /// The next connection to a forward's end, with what was read of it.
    fn knocked(&self) -> (Name, Option<Peer>) {
        let knocked = self.until(|message| matches!(message, Message::Knocked { .. }));
        let Message::Knocked {
            capability, peer, ..
        } = knocked
        else {
            panic!("a knock");
        };
        (capability, peer)
    }

    /// The loopback port the stand-in was told for the forward that begins
    /// with `far`.
    fn endpoint(&self, far: &str) -> u16 {
        let given = self.given();
        let forward = given
            .get("argument")
            .unwrap()
            .iter()
            .find(|argument| argument.starts_with(far) && argument.contains(":127.0.0.1:"))
            .unwrap();
        forward.rsplit_once(':').unwrap().1.parse().unwrap()
    }

    /// Starts the stand-in as the route's client, told to do `act`.
    fn start(&mut self, act: &str, serving: Vec<Serving>) {
        fs::write(self.folder.path().join("plan"), act).unwrap();
        let client = Client {
            program: Program::try_from("child").unwrap(),
            before: vec![
                literal("stand-in"),
                literal(self.folder.path().to_str().unwrap()),
            ],
            after: vec![Argument::Address],
        };
        self.order(client, serving);
    }

    fn order(&mut self, client: Client, serving: Vec<Serving>) {
        self.channels.start(Order {
            connection: CONNECTION,
            client,
            address: Address::try_from("dev@build-7.example").unwrap(),
            serving,
            asking: Asking::Nobody,
            keepalive: Keepalive::SHIPS,
        });
    }

    /// The next thing the deciding thread is told of the channel.
    fn next(&self) -> Told {
        match self.told.recv_timeout(WAIT).expect("the channel says more") {
            Message::Input(Input::Channel { connection, told }) => {
                assert_eq!(connection, CONNECTION);
                told
            }
            other => panic!("{other:?}"),
        }
    }

    /// What the stand-in was started with, once it has written it.
    fn given(&self) -> BTreeMap<String, Vec<String>> {
        let path = self.folder.path().join("given");
        let deadline = Instant::now() + WAIT;
        let text = loop {
            match fs::read_to_string(&path) {
                Ok(text) if text.contains("argument=") => break text,
                _ if Instant::now() > deadline => panic!("the stand-in wrote nothing"),
                _ => thread::sleep(Duration::from_millis(20)),
            }
        };
        let mut given: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, value) in text.lines().filter_map(|line| line.split_once('=')) {
            given
                .entry(key.to_owned())
                .or_default()
                .push(value.to_owned());
        }
        given
    }
}

fn one(given: &BTreeMap<String, Vec<String>>, key: &str) -> String {
    given
        .get(key)
        .and_then(|values| values.first())
        .unwrap()
        .clone()
}

/// The client is started from the program found by its name, recorded by its
/// whole path; it is in the channel's job from its first moment, holds no
/// handle of the core's, shows no window, has the core's variables less what
/// would raise a prompt, and is given the core's options whole between what
/// the route puts before and after them.
#[test]
fn a_channel_is_started_in_its_job_with_only_what_it_is_given() {
    let mut held = Held::new("start");
    let (mut reads, writes) = std::io::pipe().unwrap();
    inheritable(&writes).unwrap();
    held.start("up", vec![gpg(), adb()]);
    drop(writes);

    let Told::Ran {
        program, release, ..
    } = held.next()
    else {
        panic!("the client ran");
    };
    assert_eq!(Path::new(program.as_str()), child());
    assert_eq!(release, None, "a program whose file states no release");
    for capability in ["gpg", "adb"] {
        let capability = Name::try_from(capability).unwrap();
        let bound = true;
        assert_eq!(held.next(), Told::Forwarded { capability, bound });
    }

    let given = held.given();
    assert_eq!(one(&given, "window"), "false");
    assert_eq!(one(&given, "SSH_ASKPASS"), child().to_str().unwrap());
    assert_eq!(one(&given, "DISPLAY"), "<unset>");
    assert_eq!(one(&given, "SSH_ASKPASS_REQUIRE"), "force");
    assert_eq!(one(&given, PIPE), askpass().pipe.as_str());
    let arguments = given.get("argument").unwrap();
    assert_eq!(arguments.first().map(String::as_str), Some("-N"));
    for set in SET {
        assert!(arguments.iter().any(|argument| argument == set), "{set}");
    }
    let forwards: Vec<&String> = arguments
        .iter()
        .filter(|argument| argument.contains(":127.0.0.1:"))
        .collect();
    assert!(
        matches!(forwards.as_slice(), [socket, port]
            if socket.starts_with("/run/user/1000/gnupg/S.gpg-agent:127.0.0.1:")
                && port.starts_with("5037:127.0.0.1:")),
        "{forwards:?}"
    );
    assert_eq!(
        arguments.last().map(String::as_str),
        Some("dev@build-7.example")
    );

    let client = Process::open(one(&given, "process").parse().unwrap()).unwrap();
    let jobs = held.channels.jobs();
    let job = jobs.lock().unwrap().get(&CONNECTION).cloned().unwrap();
    assert!(job.includes(&client).unwrap());

    // With this process's own end closed, the pipe ends at once unless the
    // client, which is still running, holds it.
    let (done, waited) = mpsc::channel();
    thread::spawn(move || {
        let mut rest = Vec::new();
        let read = std::io::Read::read_to_end(&mut reads, &mut rest);
        let _ = done.send(read.map(|_| rest));
    });
    assert_eq!(waited.recv_timeout(WAIT).unwrap().unwrap(), b"");

    // Ending the channel ends its client.
    held.channels.end(CONNECTION);
    assert!(matches!(held.next(), Told::Ended { .. }));
    assert!(jobs.lock().unwrap().is_empty());
}

/// Each thing a client says or does that ends a channel reaches the deciding
/// thread as what it was.
#[test]
fn what_a_client_says_and_how_it_ends_are_told() {
    let ended = |status: i32, unverified: bool, last: &str| Told::Ended {
        status,
        unverified,
        last: hedwig_core::channel::words(last),
    };
    let changed = Told::HostKeyChanged {
        fingerprint: Mark::try_from("SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s").unwrap(),
    };
    let forwarded = |capability: &str, bound: bool| Told::Forwarded {
        capability: Name::try_from(capability).unwrap(),
        bound,
    };
    let cases: [(&str, Vec<Told>); 6] = [
        (
            "changed",
            vec![changed, ended(255, false, "Host key verification failed.")],
        ),
        (
            "unknown",
            vec![ended(255, true, "Host key verification failed.")],
        ),
        (
            "denied",
            vec![ended(
                255,
                false,
                "dev@build-7.example: Permission denied (publickey).",
            )],
        ),
        ("exit:0", vec![ended(0, false, "")]),
        (
            "refuse-first",
            vec![forwarded("gpg", false), forwarded("adb", true)],
        ),
        (
            "refuse-all",
            vec![forwarded("gpg", false), forwarded("adb", false)],
        ),
    ];
    for (act, expected) in cases {
        let mut held = Held::new("endings");
        held.start(act, vec![gpg(), adb()]);
        assert!(matches!(held.next(), Told::Ran { .. }), "{act}");
        for told in expected {
            assert_eq!(held.next(), told, "{act}");
        }
        held.channels.end(CONNECTION);
    }
}

/// A host that presents another key to a client told not to check strictly
/// leaves that client running with no forward. The core is told of the key
/// while the client runs, and ends it.
#[test]
fn a_changed_host_key_is_told_while_the_client_still_runs() {
    let mut held = Held::new("lenient");
    held.start("changed-lenient", vec![gpg()]);
    assert!(matches!(held.next(), Told::Ran { .. }));
    assert!(matches!(held.next(), Told::HostKeyChanged { .. }));
    assert!(
        held.told.recv_timeout(Duration::from_millis(300)).is_err(),
        "the client has not ended"
    );
    held.channels.end(CONNECTION);
    assert!(matches!(held.next(), Told::Ended { .. }));
}

/// A client that ends and leaves something of its own running is over when
/// it ends: what it left is ended with the job, and does not keep the core
/// waiting on what it still holds.
#[test]
fn what_a_client_leaves_behind_ends_with_its_channel() {
    let mut held = Held::new("linger");
    held.start("linger", vec![gpg()]);
    assert!(matches!(held.next(), Told::Ran { .. }));
    assert_eq!(
        held.next(),
        Told::Ended {
            status: 255,
            unverified: false,
            last: hedwig_core::channel::words(
                "Connection to build-7.example closed by remote host."
            ),
        }
    );
    let left = fs::read_to_string(held.folder.path().join("grandchild")).unwrap();
    let (process, created) = left.split_once(' ').unwrap();
    assert!(ended_within(
        process.parse().unwrap(),
        created.parse().unwrap(),
        WAIT
    ));
}

/// A route whose client is on no folder of the search path, and one whose
/// client is found and is not a program, each end the connection with what
/// happened.
#[test]
fn a_client_that_cannot_be_started_is_told() {
    let mut held = Held::new("absent");
    let client = |program: &str| Client {
        program: Program::try_from(program).unwrap(),
        before: Vec::new(),
        after: vec![Argument::Address],
    };
    held.order(client("no-such-client"), vec![gpg()]);
    let end = ChannelEnd::ClientAbsent;
    assert_eq!(held.next(), Told::Unstarted { end });

    let folder = Folder::new("not-a-program");
    fs::write(folder.path().join("broken.exe"), "not a program").unwrap();
    let setting = Setting {
        search: folder.path().as_os_str().to_owned(),
        environment: environment(Environment::own(), &askpass()),
    };
    let (messages, told) = mpsc::channel();
    let mut channels = Channels::new(setting, messages);
    channels.start(Order {
        connection: CONNECTION,
        client: client("broken"),
        address: Address::try_from("build").unwrap(),
        serving: vec![gpg()],
        asking: Asking::Nobody,
        keepalive: Keepalive::SHIPS,
    });
    let Message::Input(Input::Channel { told, .. }) = told.recv_timeout(WAIT).unwrap() else {
        panic!("told of the channel");
    };
    assert!(
        matches!(&told, Told::Unstarted { end: ChannelEnd::Unstarted(account) }
            if !account.as_str().is_empty()),
        "{told:?}"
    );
}

/// The workstation's own OpenSSH client, held as a channel: found by name,
/// recorded with the release its file states, started with the core's
/// options, and read when it ends. It is sent to a loopback port nothing
/// listens on, with a configuration of the suite's own and no agent, so it
/// reads nothing of the person's and reaches nothing.
#[test]
fn the_workstations_own_client_is_held_and_read() {
    let mut held = Held::new("real");
    held.channels = {
        let (messages, told) = mpsc::channel();
        held.told = told;
        held.messages = messages.clone();
        Channels::new(Setting::own(&askpass()), messages)
    };
    let empty = held.folder.path().join("config");
    fs::write(&empty, "").unwrap();
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let before = [
        "-F",
        empty.to_str().unwrap(),
        "-o",
        "IdentityAgent=none",
        "-p",
    ]
    .into_iter()
    .map(literal)
    .chain([literal(&closed.to_string())])
    .collect();
    let client = Client {
        program: Program::try_from("ssh").unwrap(),
        before,
        after: vec![Argument::Address],
    };
    held.channels.start(Order {
        connection: CONNECTION,
        client,
        address: Address::try_from("127.0.0.1").unwrap(),
        serving: vec![gpg(), adb()],
        asking: Asking::Nobody,
        keepalive: Keepalive::SHIPS,
    });
    let Told::Ran {
        program, release, ..
    } = held.next()
    else {
        panic!("the client ran");
    };
    assert!(
        program.as_str().to_lowercase().ends_with(r"\ssh.exe"),
        "{program}"
    );
    assert!(
        release.is_some_and(|release| release.major >= 8),
        "{release:?}"
    );
    let Told::Ended {
        status,
        unverified,
        last,
    } = held.next()
    else {
        panic!("the client ended");
    };
    assert_eq!((status, unverified), (255, false));
    let last = last.unwrap();
    assert!(
        last.as_str()
            .starts_with("ssh: connect to host 127.0.0.1 port")
            && last.as_str().ends_with("Connection refused"),
        "{last}"
    );
}

const NOW: Now = Now {
    at: Timestamp(1_790_000_000_000),
    tick: Tick(40),
};

fn remote() -> RemoteId {
    RemoteId {
        route: Name::try_from("ssh").unwrap(),
        address: Address::try_from("dev@build-7.example").unwrap(),
    }
}

/// A core with `gpg` and `adb` granted on the `ssh` route, a terminal
/// attached, and a connection to the remote opened and placed. Returns the
/// connection the core named.
fn opened() -> (Core, ConnectionId) {
    let mut core = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        Vec::new(),
        "0.2.0".to_owned(),
    );
    let origin = Origin {
        process: std::process::id(),
        logon: 1,
        session: 2,
        integrity: Integrity::Medium,
    };
    core.begin(origin, None, Vec::new(), NOW);
    let link = Link(1);
    let peer = Some(origin.into());
    core.step(Input::Arrived { link, peer }, NOW);
    let mut ask = |id: u32, request: Request| {
        let frame = ToCore { id, request };
        core.step(Input::Asked { link, frame }, NOW);
        core.step(Input::Sent { link }, NOW);
    };
    ask(
        1,
        Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Terminal,
            attends: Remotes::Every,
        },
    );
    for capability in ["gpg", "adb"] {
        ask(
            2,
            Request::Change(Change::Grant {
                grant: Grant {
                    capability: Name::try_from(capability).unwrap(),
                    remotes: Granted::Route(Name::try_from("ssh").unwrap()),
                },
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Inspect,
                    acknowledged: Exposure::ACKNOWLEDGED,
                    lends: Lends::none(),
                },
            }),
        );
    }
    ask(
        3,
        Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    );
    let (connection, _) = core.state().connection(&remote()).unwrap();
    (core, connection)
}

/// A process of the same person that no channel started: the stand-in, in a
/// job of the suite's own that ends it when the test does.
struct Stranger {
    job: Job,
    process: u32,
}

impl Stranger {
    fn start(arguments: &[&str]) -> Stranger {
        let job = Job::new().unwrap();
        let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
        let (held, _errors) = held(&child(), &arguments, &Environment::own(), &job).unwrap();
        Stranger {
            job,
            process: held.id(),
        }
    }
}

impl Drop for Stranger {
    fn drop(&mut self) {
        let _ = self.job.end();
    }
}

/// What a step carries out besides what it sends to clients.
fn acts(step: &Step) -> Vec<&Effect> {
    step.effects
        .iter()
        .filter(|effect| !matches!(effect, Effect::Send { .. }))
        .collect()
}

fn events(step: &Step) -> Vec<Event> {
    step.entries
        .iter()
        .map(|entry| entry.event.clone())
        .collect()
}

/// The whole of admission, with the real threads, the real table of
/// connections and the real jobs behind the deciding function. The channel's
/// client connects to each forward's end and is admitted as the remote's; a
/// process of the same person that the channel did not start - one the suite
/// starts, and the suite itself - is turned away, by name.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one channel's forwards, each knock in order"
)]
fn only_the_channels_own_processes_are_admitted_at_its_forwards() {
    let (mut core, connection) = opened();
    let mut held = Held::new("admit");
    fs::write(held.folder.path().join("plan"), "knock").unwrap();
    let serving = vec![gpg(), adb()];
    let placed = hedwig_support::placing(&serving);
    let step = core.step(
        Input::Channel {
            connection,
            told: placed,
        },
        NOW,
    );
    let Some(Effect::Start { serving, .. }) = step
        .effects
        .iter()
        .find(|effect| matches!(effect, Effect::Start { .. }))
    else {
        panic!("{step:?}");
    };
    let client = Client {
        program: Program::try_from("child").unwrap(),
        before: vec![
            literal("stand-in"),
            literal(held.folder.path().to_str().unwrap()),
        ],
        after: vec![Argument::Address],
    };
    held.channels.start(Order {
        connection,
        client,
        address: remote().address,
        serving: serving.clone(),
        asking: Asking::Nobody,
        keepalive: Keepalive::SHIPS,
    });

    let standin: u32 = one(&held.given(), "process").parse().unwrap();
    let knock = |core: &mut Core, number: u64, capability: Name, peer: Option<Peer>| {
        core.step(
            Input::Knocked {
                knock: Knock(number),
                connection,
                capability,
                peer,
            },
            NOW,
        )
    };
    let mut admitted = Vec::new();
    for number in 1..=2 {
        let (capability, peer) = held.knocked();
        let read = peer.clone().unwrap();
        assert_eq!(read.origin.process, standin);
        assert_eq!(read.channel, Some(connection));
        assert_eq!(
            read.program.as_ref().map(|p| PathBuf::from(p.as_str())),
            Some(child())
        );
        let step = knock(&mut core, number, capability.clone(), peer);
        assert!(step.entries.is_empty(), "{step:?}");
        // Admitted, `gpg` goes to its relay; nothing serves `adb` yet, and its
        // connection is closed with nothing written to it.
        let handed = match &step.effects[..] {
            [
                Effect::Relay {
                    knock: Knock(handed),
                    connection: of,
                    capability: relayed,
                    presents: None,
                    ..
                },
            ] => *handed == number && *of == connection && *relayed == capability,
            [
                Effect::Refuse {
                    knock: Knock(closed),
                },
            ] => *closed == number && capability == adb().capability,
            _ => false,
        };
        assert!(handed, "{step:?}");
        admitted.push(capability);
    }
    admitted.sort();
    assert_eq!(admitted, [adb().capability, gpg().capability]);

    // A process of the same person, started by the suite and so in no
    // channel's job, knows the port and is turned away all the same.
    let port = held.endpoint("5037");
    let stranger = Stranger::start(&["knock", &port.to_string()]);
    let (capability, peer) = held.knocked();
    assert_eq!(capability, adb().capability);
    let read = peer.clone().unwrap();
    assert_eq!(
        (read.origin.process, read.channel),
        (stranger.process, None)
    );
    let step = knock(&mut core, 3, capability, peer);
    assert_eq!(
        events(&step),
        [Event::TurnedAway {
            remote: Some(remote()),
            refusal: Refusal::NoChannel {
                process: stranger.process,
                program: read.program.clone(),
            },
        }]
    );
    assert_eq!(acts(&step), [&Effect::Refuse { knock: Knock(3) }]);
    assert_eq!(
        read.program.map(|p| PathBuf::from(p.as_str())),
        Some(child())
    );
    drop(stranger);

    // And so is the suite's own connection.
    let _own = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (_, peer) = held.knocked();
    let read = peer.unwrap();
    assert_eq!(
        (read.origin.process, read.channel),
        (std::process::id(), None)
    );
    held.channels.end(connection);
}

/// What the channel's client starts is the channel's: a process it started
/// connects to the forward's end and is read as in the channel's job, as
/// `gh` starts the `ssh.exe` that connects. It shows no window either.
#[test]
fn a_process_the_client_started_is_admitted_as_the_channels_own() {
    let mut held = Held::new("descend");
    held.start("descend", vec![gpg()]);
    let standin: u32 = one(&held.given(), "process").parse().unwrap();
    let (capability, peer) = held.knocked();
    let peer = peer.unwrap();
    assert_eq!(capability, gpg().capability);
    assert_eq!(peer.channel, Some(CONNECTION));
    assert_ne!(peer.origin.process, standin);
    assert_eq!(
        fs::read_to_string(held.folder.path().join("descendant")).unwrap(),
        "window=false\n"
    );
    held.channels.end(CONNECTION);
}

/// The control pipe's reader feeds the same policy the same thing: a client
/// of the pipe that a channel's client started is read as in that channel's
/// job, and one the suite started as in none.
#[test]
fn a_control_client_is_placed_by_the_same_reading() {
    let mut held = Held::new("pipe");
    let mut drawn = [0u8; 16];
    hedwig_win::random::fill(&mut drawn).unwrap();
    let pipe = format!("hedwig.{:032x}", u128::from_le_bytes(drawn));
    let name = PipeName::try_from(pipe.as_str()).unwrap();
    let owner = Token::own().unwrap().user().unwrap();
    let jobs = held.channels.jobs();
    let _server = Server::listen(&name, &owner, jobs, held.messages.clone()).unwrap();
    let arrived = |held: &Held| {
        let arrived =
            held.until(|message| matches!(message, Message::Input(Input::Arrived { .. })));
        let Message::Input(Input::Arrived { peer, .. }) = arrived else {
            panic!("a client");
        };
        peer.unwrap()
    };

    held.start(&format!("probe:{pipe}"), vec![gpg()]);
    let standin: u32 = one(&held.given(), "process").parse().unwrap();
    let inside = arrived(&held);
    assert_eq!(inside.channel, Some(CONNECTION));
    assert_ne!(inside.origin.process, standin);
    assert_eq!(
        inside.program.map(|p| PathBuf::from(p.as_str())),
        Some(child())
    );

    let outside = Stranger::start(&["probe", &pipe]);
    let read = arrived(&held);
    assert_eq!((read.origin.process, read.channel), (outside.process, None));
    held.channels.end(CONNECTION);
}
