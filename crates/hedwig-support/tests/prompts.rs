//! Prompts through the real route: the workstation's own OpenSSH client,
//! held as a channel by the core's threads, asks through Hedwig's own
//! executable as its askpass, which asks the core through the control pipe
//! from inside the channel's job; a terminal of the suite's answers as the
//! person. The client is sent to this workstation's own SSH server on
//! loopback, with a configuration and a known-hosts file of the suite's own
//! and no agent, so it reads nothing of the person's and offers the server no
//! key: the host key's prompt is the one it raises before anything is
//! authenticated.
//!
//! Where no SSH server listens on loopback, the suites that need one say so
//! and pass: they are evidence only where the workstation has one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_client::Session;
use hedwig_core::channel::{Askpass, Channels, Order, Setting, environment};
use hedwig_core::dispatch::{Core, Effect, Input, Now, Step};
use hedwig_core::run::Message;
use hedwig_core::serve::{Out, Server};
use hedwig_model::capability::{Exposure, Lends, Setup};
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Grant, Terms};
use hedwig_model::protocol::{Answer, Attention, Notice, Reply, Request};
use hedwig_model::remote::{Argument, Client, Granted, Identity, Listing, RemoteId, Route};
use hedwig_model::text::{Address, Name, PipeName, Program, RemotePath, Secret, Verbatim};
use hedwig_model::trail::{
    Binding, ChannelEnd, ClientKind, Event, Gave, Given, PromptKind, Serving, Tick, Timestamp,
};
use hedwig_model::wire::line;
use hedwig_support::Folder;
use hedwig_win::process::Job;
use hedwig_win::start::{Environment, held};
use hedwig_win::token::Token;

const WAIT: Duration = Duration::from_secs(30);

fn built(name: &str) -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_child")).with_file_name(name)
}

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn now() -> Now {
    Now {
        at: Timestamp(1_790_000_000_000),
        tick: Tick(1_000),
    }
}

/// Whether this workstation's own SSH server answers on loopback.
fn server_listens() -> bool {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 22));
    TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok()
}

/// A route to this workstation's own SSH server that reads nothing of the
/// person's: an empty configuration, a known-hosts file of the suite's, no
/// agent, and no key to offer.
fn loopback(folder: &Path) -> Route {
    let known = folder.join("known_hosts");
    let config = folder.join("config");
    fs::write(&config, "").unwrap();
    let literal = |text: String| Argument::Literal(Verbatim::try_from(text.as_str()).unwrap());
    let options = [
        "-F".to_owned(),
        config.to_str().unwrap().to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", known.to_str().unwrap()),
        "-o".to_owned(),
        format!("GlobalKnownHostsFile={}", known.to_str().unwrap()),
        "-o".to_owned(),
        "IdentityAgent=none".to_owned(),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        "-o".to_owned(),
        "IdentityFile=none".to_owned(),
        "-o".to_owned(),
        "PreferredAuthentications=publickey".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=ask".to_owned(),
    ];
    Route {
        id: name("loopback"),
        client: Client {
            program: Program::try_from("ssh").unwrap(),
            before: options.into_iter().map(literal).collect(),
            after: vec![Argument::Address],
        },
        listing: Listing::Blind,
        identity: Identity::HostKey,
    }
}

fn remote() -> RemoteId {
    RemoteId {
        route: name("loopback"),
        address: Address::try_from("127.0.0.1").unwrap(),
    }
}

/// The core, the pipe it serves and the channels it holds, on one thread of
/// the suite's that does what the core's own deciding thread does, less the
/// disk: it steps the core on what arrives and carries out what follows.
struct Harness {
    core: Core,
    channels: Channels,
    _server: Server,
    told: Receiver<Message>,
    outboxes: BTreeMap<hedwig_core::dispatch::Link, Sender<Out>>,
    pipe: PipeName,
    /// Whether to answer the core's survey at once with a far end for `gpg`,
    /// standing for readiness.
    places: bool,
    trail: Vec<Event>,
}

impl Harness {
    /// A core with `gpg` granted on request to the loopback route, serving
    /// a pipe of its own; `places` stands for readiness.
    fn new(folder: &Path, places: bool) -> Harness {
        let catalogue = Catalogue::shipped().unwrap();
        let mut configuration = Configuration::default();
        let grant = Change::Grant {
            grant: Grant {
                capability: name("gpg"),
                remotes: Granted::Route(name("loopback")),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        };
        for change in [Change::DefineRoute(loopback(folder)), grant] {
            configuration.apply(&catalogue, change).unwrap();
        }
        let mut core = Core::new(catalogue, configuration, Vec::new(), "0.2.0".to_owned());
        core.begin(origin(), None, Vec::new(), now());
        let (messages, told) = mpsc::channel();
        let mut drawn = [0u8; 16];
        hedwig_win::random::fill(&mut drawn).unwrap();
        let pipe =
            PipeName::try_from(format!("hedwig.{:032x}", u128::from_le_bytes(drawn)).as_str())
                .unwrap();
        let askpass = Askpass {
            program: built("hedwig.exe"),
            pipe: pipe.clone(),
        };
        let setting = Setting {
            search: std::env::var_os("PATH").unwrap(),
            environment: environment(Environment::own(), &askpass),
        };
        let channels = Channels::new(setting, messages.clone());
        let owner = Token::own().unwrap().user().unwrap();
        let server = Server::listen(&pipe, &owner, channels.jobs(), messages).unwrap();
        Harness {
            core,
            channels,
            _server: server,
            told,
            outboxes: BTreeMap::new(),
            pipe,
            places,
            trail: Vec::new(),
        }
    }

    /// Carries out a step's effects, as the core's own thread does once
    /// its entries are on disk.
    fn carry(&mut self, step: Step) {
        self.trail
            .extend(step.entries.iter().map(|entry| entry.event.clone()));
        for effect in step.effects {
            match effect {
                Effect::Send { link, frame, then } => {
                    let text = line(&frame);
                    if let Some(outbox) = self.outboxes.get(&link) {
                        let _ = outbox.send(Out { text, then });
                    }
                }
                Effect::Survey { connection, .. } if self.places => {
                    let serving = vec![Serving {
                        capability: name("gpg"),
                        binding: Binding::Socket(
                            RemotePath::try_from("/tmp/hedwig-design-prompts.sock").unwrap(),
                        ),
                    }];
                    let placed = hedwig_support::placing(&serving);
                    let step = self.core.step(
                        Input::Channel {
                            connection,
                            told: placed,
                        },
                        now(),
                    );
                    self.carry(step);
                }
                Effect::Start {
                    connection,
                    client,
                    address,
                    serving,
                    asking,
                    keepalive,
                } => self.channels.start(Order {
                    connection,
                    client,
                    address,
                    serving,
                    asking,
                    keepalive,
                }),
                Effect::End { connection } => self.channels.end(connection),
                // The suite is about prompts: the source is read as holding
                // no keys, and the person's own GnuPG is never asked.
                Effect::Read {
                    connection,
                    sources,
                } => {
                    let read = sources
                        .into_iter()
                        .map(|(capability, _)| (capability, Ok(hedwig_core::keys::Read::default())))
                        .collect();
                    let told = hedwig_core::dispatch::Told::Read { read };
                    let step = self.core.step(Input::Channel { connection, told }, now());
                    self.carry(step);
                }
                _ => {}
            }
        }
    }

    /// Runs until `done` holds of what the trail records, or the wait ends.
    fn until(&mut self, done: impl Fn(&[Event]) -> bool) {
        let started = Instant::now();
        while !done(&self.trail) {
            let left = WAIT.saturating_sub(started.elapsed());
            assert!(!left.is_zero(), "gave up waiting: {:#?}", self.trail);
            let Ok(message) = self.told.recv_timeout(left) else {
                continue;
            };
            match message {
                Message::Opened { link, outbox } => {
                    self.outboxes.insert(link, outbox);
                }
                Message::Input(input) => {
                    if let Input::Left { link } = &input {
                        self.outboxes.remove(link);
                    }
                    let step = self.core.step(input, now());
                    self.carry(step);
                }
                _ => {}
            }
        }
    }
}

fn origin() -> hedwig_model::trail::Origin {
    let standing = Token::own().unwrap().standing().unwrap();
    hedwig_model::trail::Origin {
        process: std::process::id(),
        logon: standing.logon,
        session: standing.session,
        integrity: hedwig_core::serve::integrity(standing.integrity),
    }
}

/// A terminal of the suite's, as the person: it greets, connects the remote,
/// waits for the channel's prompt, answers it with `answer`, and says what
/// it was asked.
fn person(pipe: PipeName, answer: Answer) -> Receiver<(PromptKind, String)> {
    let (said, heard) = mpsc::channel();
    thread::spawn(move || {
        let mut session = Session::open(&pipe).unwrap();
        session.greet(ClientKind::Terminal).unwrap().unwrap();
        let connect = Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        };
        session.ask(connect).unwrap().unwrap();
        loop {
            let Ok(notice) = session.notice() else {
                return;
            };
            if let Notice::Raised(needs) = notice
                && let Attention::Prompt {
                    prompt,
                    kind,
                    words,
                    ..
                } = needs.attention
            {
                let _ = said.send((kind, words.as_str().to_owned()));
                let reply = session.ask(Request::Answer { prompt, answer }).unwrap();
                assert!(matches!(reply, Ok(Reply::Done(_))), "{reply:?}");
                return;
            }
        }
    });
    heard
}

fn ended(events: &[Event]) -> Option<ChannelEnd> {
    events.iter().find_map(|event| match event {
        Event::Down { end, .. } => Some(end.clone()),
        _ => None,
    })
}

/// The person refuses the host's key: asked through Hedwig as the remote's,
/// in the client's own words, and the channel ends as declined with nothing
/// written to the known hosts.
#[test]
#[ignore = "needs an SSH server listening on loopback port 22"]
fn an_unknown_host_key_is_put_to_the_person_and_declined() {
    assert!(
        server_listens(),
        "needs an SSH server listening on loopback port 22"
    );
    let folder = Folder::new("prompt-declined");
    let mut harness = Harness::new(folder.path(), true);
    let asked = person(harness.pipe.clone(), Answer::Decline);
    harness.until(|events| ended(events).is_some());
    let (kind, words) = asked.recv_timeout(WAIT).unwrap();
    assert_eq!(kind, PromptKind::UnknownHostKey);
    assert!(
        words.starts_with("The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established."),
        "{words}"
    );
    assert!(harness.trail.iter().any(|event| matches!(
        event,
        Event::Ran {
            asking: hedwig_model::trail::Asking::Person,
            ..
        }
    )));
    assert!(harness.trail.iter().any(|event| matches!(
        event,
        Event::Answered {
            by: Some(Gave {
                given: Given::Declined,
                ..
            }),
            ..
        }
    )));
    assert_eq!(
        ended(&harness.trail),
        Some(ChannelEnd::Declined(PromptKind::UnknownHostKey))
    );
    let known = fs::read_to_string(folder.path().join("known_hosts")).unwrap_or_default();
    assert!(known.is_empty(), "nothing trusted: {known}");
}

/// The person accepts it: the client is handed `yes`, trusts the key, goes
/// on to authenticate with nothing to offer, and the channel ends as not
/// authenticated, with the ways the server would still accept.
#[test]
#[ignore = "needs an SSH server listening on loopback port 22"]
fn an_unknown_host_key_accepted_is_trusted_and_the_client_goes_on() {
    assert!(
        server_listens(),
        "needs an SSH server listening on loopback port 22"
    );
    let folder = Folder::new("prompt-accepted");
    let mut harness = Harness::new(folder.path(), true);
    let asked = person(harness.pipe.clone(), Answer::Accept);
    harness.until(|events| ended(events).is_some());
    assert_eq!(
        asked.recv_timeout(WAIT).unwrap().0,
        PromptKind::UnknownHostKey
    );
    let known = fs::read_to_string(folder.path().join("known_hosts")).unwrap();
    assert!(known.starts_with("127.0.0.1 "), "{known}");
    let end = ended(&harness.trail);
    assert!(
        matches!(&end, Some(ChannelEnd::Unauthenticated(accepts)) if accepts.as_str().contains("publickey")),
        "{end:?}: {:#?}",
        harness.trail
    );
}

/// With nobody to ask, the client starts in batch mode, raises nothing, and
/// the channel ends as needing the person for the host's key.
#[test]
#[ignore = "needs an SSH server listening on loopback port 22"]
fn with_nobody_to_ask_nothing_is_raised() {
    assert!(
        server_listens(),
        "needs an SSH server listening on loopback port 22"
    );
    let folder = Folder::new("prompt-nobody");
    let mut harness = Harness::new(folder.path(), true);
    let pipe = harness.pipe.clone();
    thread::spawn(move || {
        let mut session = Session::open(&pipe).unwrap();
        session.greet(ClientKind::Command).unwrap().unwrap();
        let connect = Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        };
        session.ask(connect).unwrap().unwrap();
        thread::sleep(WAIT);
    });
    harness.until(|events| ended(events).is_some());
    assert!(harness.trail.iter().any(|event| matches!(
        event,
        Event::Ran {
            asking: hedwig_model::trail::Asking::Nobody,
            ..
        }
    )));
    assert!(
        !harness
            .trail
            .iter()
            .any(|event| matches!(event, Event::Prompted { .. }))
    );
    assert_eq!(
        ended(&harness.trail),
        Some(ChannelEnd::Needs(PromptKind::UnknownHostKey))
    );
}

/// A passphrase typed by the person reaches the program that asked and
/// nothing else: `ssh-keygen`, which asks through the same code as the
/// client, is started in the channel's job, the person's text decrypts the
/// key, and the trail holds that it was text and never the text.
#[test]
fn a_passphrase_reaches_the_program_that_asked_and_the_trail_never_holds_it() {
    let folder = Folder::new("prompt-passphrase");
    let key = folder.path().join("key");
    let passphrase = "correct horse battery staple";
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", passphrase, "-C", "probe", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    fs::remove_file(key.with_extension("pub")).unwrap();

    let mut harness = Harness::new(folder.path(), false);
    let asked = person(
        harness.pipe.clone(),
        Answer::Text(Secret::from(passphrase.to_owned())),
    );
    harness.until(|events| {
        events
            .iter()
            .any(|event| matches!(event, Event::Opening { .. }))
    });
    let (connection, _) = harness.core.state().connection(&remote()).unwrap();
    let job = std::sync::Arc::new(Job::new().unwrap());
    harness
        .channels
        .jobs()
        .lock()
        .unwrap()
        .insert(connection, std::sync::Arc::clone(&job));
    let askpass = Askpass {
        program: built("hedwig.exe"),
        pipe: harness.pipe.clone(),
    };
    let keygen =
        hedwig_win::search::program_on("ssh-keygen", &std::env::var_os("PATH").unwrap()).unwrap();
    let arguments: Vec<OsString> = vec!["-y".into(), "-f".into(), key.clone().into_os_string()];
    let (started, _errors) = held(
        &keygen,
        &arguments,
        &environment(Environment::own(), &askpass),
        &job,
    )
    .unwrap();
    harness.until(|events| {
        events
            .iter()
            .any(|event| matches!(event, Event::Answered { .. }))
    });
    // `ssh-keygen` asks in words of its own, which the core does not know
    // as a client's passphrase: a question answered with text.
    assert_eq!(
        asked.recv_timeout(WAIT).unwrap(),
        (PromptKind::Challenge, "Enter passphrase:".to_owned())
    );
    assert_eq!(started.wait().unwrap(), 0, "the key was decrypted");
    let written: String = harness.trail.iter().map(line).collect();
    assert!(written.contains("\"given\":\"text\""));
    assert!(!written.contains(passphrase));
    let _ = job.end();
}

/// Why the prompt route is forced even where nobody can be asked: a client
/// told never to use askpass reads a prompt batch mode does not stop from
/// the console it was given, which no window shows, and waits for ever.
#[test]
fn a_prompt_with_askpass_refused_waits_on_a_console_nobody_sees() {
    let folder = Folder::new("prompt-never");
    let key = folder.path().join("key");
    let made = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "passphrase",
            "-C",
            "probe",
            "-f",
        ])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    fs::remove_file(key.with_extension("pub")).unwrap();
    let job = Job::new().unwrap();
    let keygen =
        hedwig_win::search::program_on("ssh-keygen", &std::env::var_os("PATH").unwrap()).unwrap();
    let never = Environment::own()
        .without("SSH_ASKPASS")
        .without("DISPLAY")
        .with("SSH_ASKPASS_REQUIRE", "never");
    let arguments: Vec<OsString> = vec!["-y".into(), "-f".into(), key.into_os_string()];
    let (started, _errors) = held(&keygen, &arguments, &never, &job).unwrap();
    let (said, heard) = mpsc::channel();
    thread::spawn(move || {
        let _ = said.send(started.wait());
    });
    assert!(
        heard.recv_timeout(Duration::from_secs(5)).is_err(),
        "still waiting after five seconds"
    );
    job.end().unwrap();
    assert!(heard.recv_timeout(WAIT).is_ok(), "ended with its job");
}
