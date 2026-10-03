//! What the core decides about a channel, driven with nothing else running:
//! when one is asked for, what it is started with, what each thing its
//! client says leads to, and how each ending is recorded.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use hedwig_core::channel::{
    Askpass, Heard, PIPE, SET, ended, environment, forward, heard, options, words,
};
use hedwig_core::dispatch::{Core, Effect, Input, Knock, Link, Now, Step, Then, Told};
use hedwig_core::relay::{Gnupg, Relaying};
use hedwig_core::survey::{At, Dialect};
use hedwig_model::capability::{Access, Exposure, Home, Installation, Lends, Setup};
use hedwig_model::config::{
    Activation, Catalogue, Change, Configuration, Effect as Changed, Grant, Terms,
};
use hedwig_model::protocol::{Attention, FromCore, PROTOCOL, Reply, Request, ToCore};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::setting::Keepalive;
use hedwig_model::text::{Address, Location, Mark, Name, PipeName, Port, RemotePath, Words};
use hedwig_model::trail::{
    Asking, Back, Binding, ChannelEnd, ClientId, ClientKind, ConnectionId, Event, Finding, Health,
    Integrity, Opener, Origin, Peer, PromptKind, Readiness, Release, Serving, Tick, Timestamp,
};
use hedwig_model::wire::{line, read};
use hedwig_win::start::Environment;

mod common;

const NOW: Now = Now {
    at: Timestamp(1_790_000_000_000),
    tick: Tick(40),
};

const DESKTOP: Origin = Origin {
    process: 4200,
    logon: 0x3e7_0001,
    session: 2,
    integrity: Integrity::Medium,
};

const LINK: Link = Link(1);

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn remote() -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from("dev@build-7.example").unwrap(),
    }
}

fn gpg() -> Serving {
    Serving {
        capability: name("gpg"),
        binding: Binding::Socket(RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap()),
    }
}

fn adb() -> Serving {
    Serving {
        capability: name("adb"),
        binding: Binding::Port(Port::try_from(5037).unwrap()),
    }
}

fn ask(core: &mut Core, id: u32, request: Request) -> Step {
    let frame = ToCore { id, request };
    let step = core.step(Input::Asked { link: LINK, frame }, NOW);
    let step = common::keyed(core, step, NOW);
    core.step(Input::Sent { link: LINK }, NOW);
    step
}

fn reply(step: &Step) -> Reply {
    step.effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Send {
                frame: FromCore::Reply { reply, .. },
                ..
            } => Some(
                read::<Result<Reply, Refusal>>(&line(reply))
                    .unwrap()
                    .unwrap(),
            ),
            _ => None,
        })
        .unwrap()
}

fn events(step: &Step) -> Vec<Event> {
    step.entries
        .iter()
        .map(|entry| entry.event.clone())
        .collect()
}

/// What a step has carried out besides what it sends to clients.
fn acts(step: &Step) -> Vec<&Effect> {
    step.effects
        .iter()
        .filter(|effect| !matches!(effect, Effect::Send { .. }))
        .collect()
}

fn grant(core: &mut Core, id: u32, capability: &str) {
    let change = Change::Grant {
        grant: Grant {
            capability: name(capability),
            remotes: Granted::Route(name("ssh")),
        },
        terms: Terms {
            activation: Activation::OnRequest,
            setup: Setup::Inspect,
            acknowledged: Exposure::ACKNOWLEDGED,
            lends: Lends::none(),
        },
    };
    let step = ask(core, id, Request::Change(change));
    assert_eq!(
        reply(&step),
        Reply::Changed {
            effect: Changed::Changed,
            held: Vec::new()
        }
    );
}

/// A core with a terminal attached and `gpg` and `adb` granted to every
/// remote on the `ssh` route.
fn core() -> Core {
    let mut core = Core::new(
        Catalogue::shipped().unwrap(),
        Configuration::default(),
        Vec::new(),
        "0.2.0".to_owned(),
    );
    core.begin(DESKTOP, None, Vec::new(), NOW);
    core.step(
        Input::Arrived {
            link: LINK,
            peer: Some(DESKTOP.into()),
        },
        NOW,
    );
    let hello = Request::Hello {
        protocol: PROTOCOL,
        kind: ClientKind::Terminal,
        attends: Remotes::Every,
    };
    ask(&mut core, 1, hello);
    grant(&mut core, 2, "gpg");
    grant(&mut core, 3, "adb");
    core
}

fn connect(core: &mut Core) -> (ConnectionId, Step) {
    let step = ask(
        core,
        10,
        Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    );
    let (connection, _) = core.state().connection(&remote()).unwrap();
    (connection, step)
}

/// A core whose channel to the remote has been started with both forwards.
fn started() -> (Core, ConnectionId) {
    let mut core = core();
    let (connection, _) = connect(&mut core);
    let serving = vec![gpg(), adb()];
    told(&mut core, connection, common::placing(&serving));
    (core, connection)
}

fn told(core: &mut Core, connection: ConnectionId, told: Told) -> Step {
    core.step(Input::Channel { connection, told }, NOW)
}

fn forwarded(core: &mut Core, connection: ConnectionId, capability: &str, bound: bool) -> Step {
    let capability = name(capability);
    told(core, connection, Told::Forwarded { capability, bound })
}

/// The person's request opens the connection: it is recorded as theirs, the
/// keys the workstation offers are read, the far ends are asked for, and
/// asking again changes nothing.
#[test]
fn a_connect_opens_the_connection_once() {
    let mut core = core();
    let (connection, step) = connect(&mut core);
    assert_eq!(reply(&step), Reply::Done(Changed::Changed));
    assert!(matches!(
        events(&step).as_slice(),
        [
            Event::Opening { remote: opened, opener: Opener::Person(ClientId(_)), .. },
            Event::Offered { .. },
            Event::Source { health: Health::Sound, .. },
        ] if *opened == remote()
    ));
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Survey { connection: surveyed, dialect: Dialect::Posix, .. }]
            if *surveyed == connection
    ));
    let (same, again) = connect(&mut core);
    assert_eq!(same, connection);
    assert_eq!(reply(&again), Reply::Done(Changed::Unchanged));
    assert!(again.entries.is_empty() && acts(&again).is_empty());
}

/// Once the far ends are known the channel is started from the route's own
/// client, for the capabilities the remote holds and no other.
#[test]
fn the_channel_starts_with_a_forward_for_each_capability_held() {
    let mut core = core();
    let (connection, _) = connect(&mut core);
    let stray = Serving {
        capability: name("openocd"),
        binding: Binding::Port(Port::try_from(3333).unwrap()),
    };
    let serving = vec![gpg(), stray, adb()];
    let step = told(&mut core, connection, common::placing(&serving));
    assert_eq!(
        events(&step),
        [Event::Observed {
            connection,
            platform: name("linux")
        }]
    );
    let catalogue = Catalogue::shipped().unwrap();
    let client = catalogue.route(&name("ssh")).unwrap().client.clone();
    assert_eq!(
        acts(&step),
        [&Effect::Start {
            connection,
            client,
            address: remote().address,
            serving: vec![adb(), gpg()],
            asking: Asking::Person,
            keepalive: Keepalive::SHIPS,
        }]
    );
    // Told twice, it is started once.
    let serving = vec![gpg()];
    let again = told(&mut core, connection, common::placing(&serving));
    assert!(again.entries.is_empty() && again.effects.is_empty());
}

/// A remote whose readiness can carry nothing it holds gets no channel now,
/// and is tried again after a wait: what is missing there can be put right.
#[test]
fn nothing_carried_ends_the_connection() {
    let mut core = core();
    let (connection, _) = connect(&mut core);
    let mut placing = common::placing(&[gpg(), adb()]);
    let Told::Surveyed {
        report: Ok(report), ..
    } = &mut placing
    else {
        unreachable!("a report")
    };
    let socket = RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap();
    let gpg_answer = report.answers.get_mut(&name("gpg")).unwrap();
    gpg_answer.place.as_mut().unwrap().at = Some(At::Agent);
    let adb_answer = report.answers.get_mut(&name("adb")).unwrap();
    adb_answer.listeners.insert(port(5037), true);
    let step = told(&mut core, connection, placing);
    let end = ChannelEnd::NothingCarried;
    assert_eq!(
        events(&step),
        [
            Event::Observed {
                connection,
                platform: name("linux")
            },
            Event::Checked {
                connection,
                capability: name("adb"),
                readiness: Readiness::Unready(vec![Finding::ListenerPresent(port(5037))]),
            },
            Event::Checked {
                connection,
                capability: name("gpg"),
                readiness: Readiness::Unready(vec![Finding::AgentLive(socket)]),
            },
            Event::Down { connection, end }
        ]
    );
    assert_eq!(acts(&step), [&Effect::End { connection }]);
    assert!(core.state().connection(&remote()).is_none());
}

/// The program the client was started from is recorded, with the release its
/// file states.
#[test]
fn the_client_a_channel_ran_is_recorded() {
    let (mut core, connection) = started();
    let program = Location::try_from(r"C:\Windows\System32\OpenSSH\ssh.exe").unwrap();
    let release = Some(Release {
        major: 9,
        minor: 5,
        build: 6,
        revision: 3,
    });
    let ran = Told::Ran {
        program: program.clone(),
        release,
        asking: Asking::Nobody,
    };
    let step = told(&mut core, connection, ran);
    assert_eq!(
        events(&step),
        [Event::Ran {
            connection,
            program,
            release,
            asking: Asking::Nobody,
        }]
    );
}

/// The channel is up when the remote's server has answered for every
/// forward, with those it bound; then the survey that placed them seals
/// Hedwig's private folder.
#[test]
fn the_channel_is_up_when_every_forward_is_answered() {
    let (mut core, connection) = started();
    let first = forwarded(&mut core, connection, "gpg", true);
    assert!(first.entries.is_empty(), "one forward is still unanswered");
    let second = forwarded(&mut core, connection, "adb", true);
    assert_eq!(
        events(&second),
        [Event::Up {
            connection,
            serving: vec![gpg(), adb()]
        }]
    );
    // The channel carries `adb`, so its server's devices are watched from
    // here.
    assert!(matches!(
        acts(&second).as_slice(),
        [Effect::Seal { connection: sealed }, Effect::Watch { capability, .. }]
            if *sealed == connection && *capability == name("adb")
    ));
    // An answer heard twice changes nothing.
    assert_eq!(
        forwarded(&mut core, connection, "adb", true).entries,
        Vec::new()
    );
}

/// A forward the server refuses is recorded against its capability, and the
/// others are served.
#[test]
fn one_refused_forward_leaves_the_others_served() {
    let (mut core, connection) = started();
    let refused = forwarded(&mut core, connection, "adb", false);
    assert_eq!(
        events(&refused),
        [Event::Checked {
            connection,
            capability: name("adb"),
            readiness: Readiness::Unready(vec![Finding::ForwardRefused]),
        }]
    );
    let bound = forwarded(&mut core, connection, "gpg", true);
    assert_eq!(
        events(&bound),
        [Event::Up {
            connection,
            serving: vec![gpg()]
        }]
    );
}

/// When the server refuses every forward there is nothing to hold the
/// channel for: it is over, and its job is ended.
#[test]
fn every_forward_refused_ends_the_channel() {
    let (mut core, connection) = started();
    forwarded(&mut core, connection, "gpg", false);
    let step = forwarded(&mut core, connection, "adb", false);
    let end = ChannelEnd::ForwardRefused;
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Checked { .. }, Event::Down { end: found, .. }] if *found == end
    ));
    assert_eq!(acts(&step), [&Effect::End { connection }]);
}

/// A host that presents another key ends the channel at once, whatever its
/// client goes on to do, and the first account of the ending stands.
#[test]
fn a_changed_host_key_ends_the_channel_and_is_never_a_prompt() {
    let (mut core, connection) = started();
    let fingerprint = Mark::try_from("SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s").unwrap();
    let changed = Told::HostKeyChanged {
        fingerprint: fingerprint.clone(),
    };
    let step = told(&mut core, connection, changed);
    let end = ChannelEnd::HostKeyChanged(fingerprint);
    assert_eq!(events(&step), [Event::Down { connection, end }]);
    assert_eq!(acts(&step), [&Effect::End { connection }]);
    let ended = Told::Ended {
        status: 255,
        unverified: false,
        last: words("Host key verification failed."),
    };
    let after = told(&mut core, connection, ended);
    assert!(after.entries.is_empty() && after.effects.is_empty());
}

/// A client that ends by itself is recorded with its status and its last
/// words; one that stopped for want of the person's word on the host's key
/// is recorded as needing them, and one the server would not let in as not
/// authenticated, with the ways it would still accept.
#[test]
fn a_client_that_ends_is_recorded_with_why() {
    let last = words("ssh: connect to host build-7.example port 22: Connection timed out");
    let refused = words("dev@build-7.example: Permission denied (publickey,keyboard-interactive).");
    let cases = [
        (
            (255, false, last.clone()),
            ChannelEnd::Exited { status: 255, last },
        ),
        (
            (255, false, refused),
            ChannelEnd::Unauthenticated(words("publickey,keyboard-interactive").unwrap()),
        ),
        (
            (0, false, None),
            ChannelEnd::Exited {
                status: 0,
                last: None,
            },
        ),
        (
            (255, true, words("Host key verification failed.")),
            ChannelEnd::Needs(PromptKind::UnknownHostKey),
        ),
    ];
    for ((status, unverified, last), end) in cases {
        assert_eq!(ended(status, unverified, last.clone()), end);
        let (mut core, connection) = started();
        let ended = Told::Ended {
            status,
            unverified,
            last,
        };
        let step = told(&mut core, connection, ended);
        assert_eq!(events(&step), [Event::Down { connection, end }]);
        assert_eq!(acts(&step), [&Effect::End { connection }]);
    }
}

/// A link that went dead ends the in-box client in one of two ways: Windows'
/// TCP gives up retransmitting the keepalive's packet, and the disconnect the
/// client then sends fails (`clientloop.c:1635-1640` at v9.5.0.0), or the
/// keepalive's own count runs out first (`:503-510`). Each is a loss the
/// channel comes back from by itself, at its pace.
#[test]
fn a_dead_link_ends_the_channel_as_exited_and_it_comes_back_paced() {
    for line in [
        "client_loop: send disconnect: Connection reset",
        "Timeout, server 20.26.192.41 not responding.",
    ] {
        let last = words(line);
        let end = ended(255, false, last.clone());
        assert_eq!(end, ChannelEnd::Exited { status: 255, last });
        assert_eq!(end.back(), Back::Paced);
    }
}

/// A client that could not be started ends the connection with the reason.
#[test]
fn a_client_that_cannot_be_started_is_recorded() {
    let account = Words::try_from("Access is denied. (os error 5)").unwrap();
    for end in [ChannelEnd::ClientAbsent, ChannelEnd::Unstarted(account)] {
        let (mut core, connection) = started();
        let unstarted = Told::Unstarted { end: end.clone() };
        let step = told(&mut core, connection, unstarted);
        assert_eq!(events(&step), [Event::Down { connection, end }]);
    }
}

/// The person's disconnect, and a pause that covers the remote, are recorded
/// and end the channel's job.
#[test]
fn a_disconnect_and_a_pause_end_the_channel() {
    let end = ChannelEnd::Closed;
    let (mut core, connection) = started();
    let step = ask(&mut core, 20, Request::Disconnect { remote: remote() });
    assert_eq!(reply(&step), Reply::Done(Changed::Changed));
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Disconnected { remote: gone, .. }, Event::Down { connection: over, end: why }]
            if *gone == remote() && *over == connection && *why == end
    ));
    assert_eq!(acts(&step), [&Effect::End { connection }]);

    let (mut core, connection) = started();
    let step = ask(&mut core, 20, Request::Pause(Remotes::Every));
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Paused { .. }, Event::Down { end: found, .. }] if *found == end
    ));
    assert_eq!(acts(&step), [&Effect::End { connection }]);
    // What was heard of the channel afterwards is no longer about anything.
    assert_eq!(
        forwarded(&mut core, connection, "gpg", true).entries,
        Vec::new()
    );
}

/// A capability revoked between the request and the start is not forwarded:
/// the connection is opened again for what the remote holds now, and the
/// far ends found for the first are about nothing.
#[test]
fn a_capability_revoked_before_the_start_is_left_out() {
    let mut core = core();
    let (connection, _) = connect(&mut core);
    let revoke = Change::Revoke(Grant {
        capability: name("adb"),
        remotes: Granted::Route(name("ssh")),
    });
    let step = ask(&mut core, 30, Request::Change(revoke));
    let reshaped: Vec<ConnectionId> = step
        .entries
        .iter()
        .filter_map(|entry| match &entry.event {
            Event::Opening {
                opener: Opener::Again,
                ..
            } => Some(ConnectionId(entry.seq)),
            _ => None,
        })
        .collect();
    assert!(events(&step).contains(&Event::Down {
        connection,
        end: ChannelEnd::Reshaped
    }));
    let [again] = reshaped.as_slice() else {
        panic!("opened again: {step:?}");
    };
    let stale = told(&mut core, connection, common::placing(&[gpg(), adb()]));
    assert!(stale.entries.is_empty() && stale.effects.is_empty());
    let serving = vec![gpg(), adb()];
    let step = told(&mut core, *again, common::placing(&serving));
    assert!(matches!(
        acts(&step).as_slice(),
        [Effect::Start { serving, .. }] if *serving == [gpg()]
    ));
}

fn port(number: u16) -> Port {
    Port::try_from(number).unwrap()
}

/// A forward is written as OpenSSH reads it: a port as it is, a path with
/// every character the client would split on kept by a backslash.
#[test]
fn a_forward_is_written_as_the_client_reads_it() {
    let socket = |path: &str| Binding::Socket(RemotePath::try_from(path).unwrap());
    let cases = [
        (
            gpg().binding,
            "/run/user/1000/gnupg/S.gpg-agent:127.0.0.1:50123",
        ),
        (adb().binding, "5037:127.0.0.1:50123"),
        (
            Binding::SocketFile {
                file: RemotePath::try_from("C:/Users/dev/AppData/Roaming/gnupg/S.gpg-agent")
                    .unwrap(),
                port: port(49211),
            },
            "49211:127.0.0.1:50123",
        ),
        (
            socket("/home/a:b/S.agent"),
            r"/home/a\:b/S.agent:127.0.0.1:50123",
        ),
        (socket(r"/tmp/a\b"), r"/tmp/a\\b:127.0.0.1:50123"),
        (socket("[x]/s"), r"\[x]/s:127.0.0.1:50123"),
        (socket("S.agent"), "./S.agent:127.0.0.1:50123"),
    ];
    for (binding, written) in cases {
        assert_eq!(forward(&binding, port(50123)), written);
    }
}

/// The options are no session, whether the client may ask, each setting as
/// its own `-o`, the keepalive, and each forward as its own `-R`.
#[test]
fn the_options_are_whole_arguments() {
    let keepalive = Keepalive {
        every: std::num::NonZeroU16::new(30).unwrap(),
        missed: std::num::NonZeroU8::new(4).unwrap(),
    };
    for (asking, batch) in [
        (Asking::Person, "BatchMode=no"),
        (Asking::Nobody, "BatchMode=yes"),
    ] {
        let given = options(&[(gpg(), port(50123))], asking, keepalive);
        let settings: Vec<&str> = given
            .windows(2)
            .filter(|pair| pair.first().is_some_and(|flag| flag == "-o"))
            .filter_map(|pair| pair.get(1).map(String::as_str))
            .collect();
        let mut expected = vec![batch];
        expected.extend(SET);
        expected.extend(["ServerAliveInterval=30", "ServerAliveCountMax=4"]);
        assert_eq!(settings, expected);
    }
    let given = options(
        &[(gpg(), port(50123)), (adb(), port(50124))],
        Asking::Nobody,
        Keepalive::SHIPS,
    );
    assert_eq!(given.first().map(String::as_str), Some("-N"));
    let forwards: Vec<&str> = given
        .windows(2)
        .filter(|pair| pair.first().is_some_and(|flag| flag == "-R"))
        .filter_map(|pair| pair.get(1).map(String::as_str))
        .collect();
    assert_eq!(
        forwards,
        [
            "/run/user/1000/gnupg/S.gpg-agent:127.0.0.1:50123",
            "5037:127.0.0.1:50124"
        ]
    );
    assert_eq!(given.len(), 1 + 2 * (1 + SET.len() + 2) + 4);
}

/// Each line the core reads, in the client's own words.
#[test]
fn what_the_client_says_is_read() {
    let cases = [
        (
            // As the in-box client writes it: its file by the path it was
            // built from.
            r"debug1: C:\\__w\\1\\s\\ssh.c:ssh_confirm_remote_forward():1839 (pid=7312): remote forward success for: listen /run/user/1000/gnupg/S.gpg-agent:-2, connect 127.0.0.1:50123",
            Heard::Forward {
                endpoint: 50123,
                bound: true,
            },
        ),
        (
            "debug1: ssh.c:ssh_confirm_remote_forward():1965 (pid=7312): remote forward failure \
             for: listen 5037, connect 127.0.0.1:50124",
            Heard::Forward {
                endpoint: 50124,
                bound: false,
            },
        ),
        (
            // A carrier's port of the remote's choosing, as the in-box client
            // says it with the `LogVerbose` it is started with.
            r"C:\\__w\\1\\s\\ssh.c:ssh_confirm_remote_forward():1860 (pid=7312): Allocated port 44863 for remote forward to 127.0.0.1:20881",
            Heard::Allocated {
                port: 44863,
                endpoint: 20881,
            },
        ),
        (
            "Allocated port 44863 for remote forward to 127.0.0.1:20881",
            Heard::Allocated {
                port: 44863,
                endpoint: 20881,
            },
        ),
        (
            "dev@build-7.example: Allocated port 1 for remote forward to 127.0.0.1:20881",
            Heard::Other,
        ),
        (
            r"C:\\__w\\1\\s\\ssh.c:ssh_confirm_remote_forward():1860 (pid=7312): Allocated port 44863 for remote forward to 127.0.0.1:no",
            Heard::Other,
        ),
        (
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
            Heard::Changed,
        ),
        (
            "The fingerprint for the ED25519 key sent by the remote host is",
            Heard::Presents,
        ),
        ("Host key verification failed.", Heard::Unverified),
        (
            "Warning: remote port forwarding failed for listen port 5037",
            Heard::Other,
        ),
        (
            "debug1: ssh.c:ssh_confirm_remote_forward():1839 (pid=7312): remote forward success \
             for: listen 5037, connect 127.0.0.1:no",
            Heard::Other,
        ),
        // The same words from anything but the function that answers.
        (
            "remote forward success for: listen 5037, connect 127.0.0.1:50123",
            Heard::Other,
        ),
        (
            "dev@build-7.example: Permission denied (publickey).",
            Heard::Other,
        ),
    ];
    for (line, read) in cases {
        assert_eq!(heard(line), read, "{line}");
    }
}

/// Words kept from a client hold nothing that drives a terminal and are no
/// longer than words may be.
#[test]
fn a_clients_words_are_kept_safe_to_show() {
    assert_eq!(
        words("\u{1b}[31mssh: connect to host build-7 port 22: Connection refused\r").unwrap(),
        Words::try_from("[31mssh: connect to host build-7 port 22: Connection refused").unwrap()
    );
    assert_eq!(words(&"x".repeat(5000)).unwrap().as_str().len(), 1024);
    assert_eq!(words(" \r\n"), None);
}

/// The channel's variables are the core's own, with every prompt sent to
/// Hedwig through the core's pipe and none to a program of the person's.
#[test]
fn the_channels_environment_sends_every_prompt_to_hedwig() {
    let own = Environment::own()
        .with("SSH_ASKPASS", r"C:\Tools\askpass.exe")
        .with("Display", ":0")
        .with("SSH_ASKPASS_REQUIRE", "never")
        .with("SSH_ASKPASS_PROMPT", "confirm");
    let askpass = Askpass {
        program: r"C:\Program Files\hedwig\hedwig.exe".into(),
        pipe: PipeName::try_from("hedwig.9f86d081884c7d659a2feaa0c55ad015").unwrap(),
    };
    let environment = environment(own, &askpass);
    assert_eq!(
        environment.get("SSH_ASKPASS"),
        Some(r"C:\Program Files\hedwig\hedwig.exe".as_ref())
    );
    assert_eq!(environment.get("DISPLAY"), None);
    assert_eq!(environment.get("SSH_ASKPASS_PROMPT"), None);
    assert_eq!(
        environment.get("ssh_askpass_require"),
        Some("force".as_ref())
    );
    assert_eq!(
        environment.get(PIPE),
        Some("hedwig.9f86d081884c7d659a2feaa0c55ad015".as_ref())
    );
    assert_eq!(
        environment.get("PATH").map(std::ffi::OsStr::to_os_string),
        std::env::var_os("PATH")
    );
}

/// A process at a forward's end: one of `channel`'s own, or of none.
fn knocker(channel: Option<ConnectionId>) -> Peer {
    Peer {
        origin: Origin {
            process: 7312,
            ..DESKTOP
        },
        program: Some(Location::try_from(r"C:\Windows\System32\OpenSSH\ssh.exe").unwrap()),
        channel,
    }
}

fn knock(core: &mut Core, number: u64, connection: ConnectionId, peer: Option<Peer>) -> Step {
    core.step(
        Input::Knocked {
            knock: Knock(number),
            connection,
            capability: name("gpg"),
            peer,
        },
        NOW,
    )
}

/// A connection to a forward's end made by a process of that channel's job
/// is handed on as its remote's, whether or not the channel is yet up, and
/// admitting it is not an entry.
#[test]
fn a_connection_from_the_channels_own_job_is_handed_on() {
    let (mut core, connection) = started();
    let step = knock(&mut core, 1, connection, Some(knocker(Some(connection))));
    assert_eq!(step.entries, Vec::new());
    assert_eq!(
        acts(&step),
        [&Effect::Relay {
            knock: Knock(1),
            connection,
            capability: name("gpg"),
            source: Relaying::Gnupg(Gnupg {
                installation: Installation::Registered,
                home: Home::Default,
                access: Access::Restricted,
            }),
            presents: None,
        }]
    );
}

/// A process in no channel's job, one in another channel's, and one nothing
/// could be read of are each turned away: recorded against the remote whose
/// forward it was, closed, and brought to the person's attention once,
/// however often it happens.
#[test]
fn a_connection_from_outside_the_channel_is_turned_away_and_recorded() {
    let (mut core, connection) = started();
    let other = ConnectionId(hedwig_model::trail::Seq(9_000));
    let stranger = Refusal::NoChannel {
        process: 7312,
        program: knocker(None).program,
    };
    let cases = [
        (Some(knocker(None)), stranger.clone()),
        (Some(knocker(Some(other))), stranger.clone()),
        (None, Refusal::Unattributable),
    ];
    for (number, (peer, refusal)) in (1u64..).zip(cases) {
        let step = knock(&mut core, number, connection, peer);
        assert_eq!(
            events(&step),
            [Event::TurnedAway {
                remote: Some(remote()),
                refusal
            }]
        );
        assert_eq!(
            acts(&step),
            [&Effect::Refuse {
                knock: Knock(number)
            }]
        );
    }
    let Reply::Attention(items) = reply(&ask(&mut core, 40, Request::Attention)) else {
        panic!("attention");
    };
    assert!(items.iter().any(|needs| needs.attention
        == Attention::Refused {
            remote: Some(remote()),
            refusal: stranger.clone(),
            times: 2,
        }));
}

/// A connection to the forward of a channel that is over is turned away,
/// whoever made it.
#[test]
fn a_connection_to_a_channel_that_is_over_is_turned_away() {
    let (mut core, connection) = started();
    ask(&mut core, 20, Request::Disconnect { remote: remote() });
    let step = knock(&mut core, 1, connection, Some(knocker(Some(connection))));
    assert_eq!(
        events(&step),
        [Event::TurnedAway {
            remote: None,
            refusal: Refusal::UnknownConnection(connection)
        }]
    );
    assert_eq!(acts(&step), [&Effect::Refuse { knock: Knock(1) }]);
}

/// The control pipe asks the same policy and is refused nobody it could
/// read: a client that is itself a process of a channel greets like any
/// other, and one nothing was read of is told so and let go.
#[test]
fn the_control_pipe_refuses_only_a_client_nothing_was_read_of() {
    let (mut core, connection) = started();
    let link = Link(2);
    let peer = Some(knocker(Some(connection)));
    core.step(Input::Arrived { link, peer }, NOW);
    let hello = |id| ToCore {
        id,
        request: Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Command,
            attends: Remotes::Every,
        },
    };
    let frame = hello(1);
    let step = core.step(Input::Asked { link, frame }, NOW);
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Attached { origin, .. }] if origin.process == 7312
    ));

    let link = Link(3);
    core.step(Input::Arrived { link, peer: None }, NOW);
    let frame = hello(1);
    let step = core.step(Input::Asked { link, frame }, NOW);
    assert_eq!(step.entries, Vec::new());
    assert!(step.effects.iter().any(|effect| matches!(
        effect,
        Effect::Send {
            frame: FromCore::Reply {
                reply: Err(Refusal::Unattributable),
                ..
            },
            then: Then::Close,
            ..
        }
    )));
}
