//! The relay of a `gpg` capability, run for real: `GnuPG` 2.5.24's own agent on
//! a home of the suite's, and its own `gpg` as the remote's client - the
//! Windows form of a remote, whose `gpg` reads a socket file naming the
//! relay's port and the bytes Hedwig issued - or a client replaying what
//! that `gpg` sends. The suite plays the deciding thread.
//!
//! `HEDWIG_GNUPG` names the installation, which `scripts\fetch-test-tools.ps1`
//! lays out from `GnuPG`'s own Windows build.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use hedwig_core::assuan::{Ask, Breach, Nonce, Side};
use hedwig_core::keys;
use hedwig_core::relay::{Agents, Gnupg, Relayed, Settle, carry, listed};
use hedwig_model::capability::{Access, Home, Installation, Operation};
use hedwig_model::holder::Whose;
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::text::{Fingerprint, Folder as Place, Grip, Mark, Name, Serial};
use hedwig_model::trail::{Card, Failure, Held, SignaturePin, Touch, Uses};
use hedwig_support::lower::{Less, token};
use hedwig_support::{Folder, SCDAEMON_LOG, readerless};
use hedwig_win::process::{Job, Process};
use hedwig_win::start::{Environment, held};
use hedwig_win::token::Token;

const WAIT: Duration = Duration::from_secs(30);

/// `GnuPG`'s own Windows build, laid out as an installation.
fn installation() -> PathBuf {
    let folder = std::env::var_os("HEDWIG_GNUPG")
        .map(PathBuf::from)
        .expect("HEDWIG_GNUPG names GnuPG's Windows build: run scripts\\fetch-test-tools.ps1");
    assert!(
        folder.join("bin").join("gpgconf.exe").is_file(),
        "{} holds bin\\gpgconf.exe",
        folder.display()
    );
    folder
}

fn tool(name: &str) -> PathBuf {
    installation().join("bin").join(name)
}

/// A `GnuPG` home of the suite's own, whose scdaemon opens no reader. Its
/// agent, if one was started, is stopped and its socket folder removed when
/// it is dropped.
struct Scratch {
    folder: Folder,
}

impl Scratch {
    fn new(purpose: &str) -> Scratch {
        let folder = Folder::new(purpose);
        readerless(folder.path()).unwrap();
        Scratch { folder }
    }

    fn path(&self) -> &Path {
        self.folder.path()
    }

    fn run(&self, program: &str, arguments: &[&str]) -> Output {
        Command::new(tool(program))
            .arg("--homedir")
            .arg(self.path())
            .args(arguments)
            .output()
            .unwrap()
    }

    fn dir(&self, name: &str) -> PathBuf {
        let printed = self.run("gpgconf.exe", &["--list-dirs"]).stdout;
        let value = listed(&printed, name).unwrap();
        PathBuf::from(String::from_utf8(value).unwrap())
    }

    /// A key that signs, with no passphrase; its fingerprint and keygrip.
    fn key(&self) -> (Fingerprint, Grip) {
        let made = self.run(
            "gpg.exe",
            &[
                "--batch",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Relay Test <relay@example.invalid>",
                "ed25519",
                "sign",
                "never",
            ],
        );
        assert!(made.status.success(), "{made:?}");
        let listed = self.run(
            "gpg.exe",
            &[
                "--batch",
                "--with-colons",
                "--with-keygrip",
                "--list-secret-keys",
            ],
        );
        let text = String::from_utf8(listed.stdout).unwrap();
        let field = |kind: &str| {
            text.lines()
                .find(|line| line.starts_with(kind))
                .and_then(|line| line.split(':').nth(9))
                .unwrap()
        };
        (
            Fingerprint::try_from(field("fpr:")).unwrap(),
            Grip::try_from(field("grp:")).unwrap(),
        )
    }

    /// Its scdaemon never loaded PC/SC, so it listed no reader and reached no
    /// card: what the agent asked of it had nothing to open.
    fn reached_no_reader(&self) {
        let log = std::fs::read_to_string(self.path().join(SCDAEMON_LOG)).unwrap();
        assert!(log.contains("failed to open driver"), "{log}");
        assert!(!log.contains("detected reader"), "{log}");
    }

    fn launch(&self) {
        let launched = self.run("gpgconf.exe", &["--launch", "gpg-agent"]);
        assert!(launched.status.success(), "{launched:?}");
    }

    fn source(&self, access: Access) -> Gnupg {
        Gnupg {
            installation: Installation::At(
                Place::try_from(installation().to_string_lossy().as_ref()).unwrap(),
            ),
            home: Home::At(Place::try_from(self.path().to_string_lossy().as_ref()).unwrap()),
            access,
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Never through `installation`, which panics where GnuPG is not
        // named: a panic while a test unwinds aborts the whole suite.
        let Some(folder) = std::env::var_os("HEDWIG_GNUPG") else {
            return;
        };
        let gpgconf = |arguments: &[&str]| {
            Command::new(PathBuf::from(&folder).join("bin").join("gpgconf.exe"))
                .arg("--homedir")
                .arg(self.path())
                .args(arguments)
                .output()
                .ok()
        };
        let sockets = gpgconf(&["--list-dirs"])
            .and_then(|listing| listed(&listing.stdout, "socketdir"))
            .and_then(|value| String::from_utf8(value).ok())
            .map(PathBuf::from);
        let _ = gpgconf(&["--kill", "all"]);
        if let Some(sockets) = sockets
            && sockets
                .parent()
                .is_some_and(|parent| parent.ends_with("gnupg"))
        {
            let _ = std::fs::remove_dir_all(sockets);
        }
    }
}

/// What the suite, as the deciding thread, answers each request.
#[derive(Clone)]
struct Answers {
    connect: Result<(), Refusal>,
    sign: Result<(), Refusal>,
}

/// A relay listening on a loopback port for one connection, carrying it to
/// `source`'s agent, decided by `answers`. Everything the connection told
/// the deciding thread is sent on, in order.
fn relay(
    source: Gnupg,
    presents: Option<[u8; 16]>,
    answers: Answers,
) -> (u16, Receiver<Relayed>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen, told) = mpsc::channel();
    let running = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (relayed, heard) = mpsc::channel();
        let settle: Arc<Settle> = carry(
            stream,
            presents.map(Nonce::new),
            source,
            Arc::new(Agents::default()),
            move |said| {
                let _ = relayed.send(said);
            },
        );
        while let Ok(said) = heard.recv_timeout(WAIT) {
            let verdict = match &said {
                Relayed::Reached(Ok(())) => Some(answers.connect.clone()),
                Relayed::Reached(Err(failure)) => Some(Err(Refusal::SourceUnavailable {
                    capability: Name::try_from("gpg").unwrap(),
                    failure: *failure,
                })),
                Relayed::Asks(_) => Some(answers.sign.clone()),
                _ => None,
            };
            let ended = said == Relayed::Ended;
            seen.send(said).unwrap();
            if let Some(verdict) = verdict {
                settle.settle(verdict);
            }
            if ended {
                break;
            }
        }
    });
    (port, told, running)
}

/// What the relay told, but for what held the agent's port, which is told
/// first wherever the agent was reached and is the person's gpg-agent.
fn heard(told: &Receiver<Relayed>) -> Vec<Relayed> {
    let mut heard: Vec<Relayed> = told.iter().collect();
    if let Some(Relayed::Held(held)) = heard.first() {
        let holder = held.as_ref().expect("the agent's port is held");
        assert!(
            matches!(holder.whose, Whose::Person { .. })
                && holder.program.as_str().ends_with("gpg-agent.exe"),
            "{holder:?}"
        );
        heard.remove(0);
    }
    heard
}

/// A remote's home whose `gpg` holds `workstation`'s public key, and whose
/// socket file names `port` and `issued`, as Hedwig writes it on a Windows
/// remote.
fn remote(workstation: &Scratch, port: u16, issued: [u8; 16]) -> Scratch {
    let remote = Scratch::new("relay-remote");
    let exported = workstation.run("gpg.exe", &["--batch", "--armor", "--export"]);
    let armour = workstation.path().join("public.asc");
    std::fs::write(&armour, exported.stdout).unwrap();
    let imported = remote.run(
        "gpg.exe",
        &["--batch", "--import", armour.to_str().unwrap()],
    );
    assert!(imported.status.success(), "{imported:?}");
    let socket = remote.dir("agent-socket");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let mut file = format!("{port}\n").into_bytes();
    file.extend_from_slice(&issued);
    std::fs::write(socket, file).unwrap();
    remote
}

fn sign(remote: &Scratch, key: &Fingerprint) -> Output {
    let message = remote.path().join("message.txt");
    std::fs::write(&message, "signed through Hedwig's relay\n").unwrap();
    remote.run(
        "gpg.exe",
        &[
            "--batch",
            "--no-autostart",
            "--yes",
            "--local-user",
            key.as_str(),
            "--detach-sign",
            "--output",
            remote.path().join("message.sig").to_str().unwrap(),
            message.to_str().unwrap(),
        ],
    )
}

const ISSUED: [u8; 16] = *b"\x07hedwig\x00issued\n\r";

/// The relay, live: the remote's `gpg` signs with the workstation's key
/// through a relay that holds the signature until it is allowed, and the
/// signature verifies on the remote.
#[test]
fn a_remote_gpg_signs_through_a_confirming_relay_and_the_signature_verifies() {
    let workstation = Scratch::new("relay-workstation");
    let (fingerprint, grip) = workstation.key();
    workstation.launch();
    let answers = Answers {
        connect: Ok(()),
        sign: Ok(()),
    };
    let (port, told, running) = relay(
        workstation.source(Access::Restricted),
        Some(ISSUED),
        answers,
    );
    let remote = remote(&workstation, port, ISSUED);
    let signed = sign(&remote, &fingerprint);
    assert!(signed.status.success(), "{signed:?}");
    running.join().unwrap();
    assert_eq!(
        heard(&told),
        [
            Relayed::Reached(Ok(())),
            Relayed::Asks(Ask {
                operation: Operation::Sign,
                key: Some(grip),
            }),
            Relayed::Ended,
        ]
    );
    let verified = remote.run(
        "gpg.exe",
        &[
            "--batch",
            "--verify",
            remote.path().join("message.sig").to_str().unwrap(),
            remote.path().join("message.txt").to_str().unwrap(),
        ],
    );
    assert!(verified.status.success(), "{verified:?}");
    assert!(String::from_utf8_lossy(&verified.stderr).contains("Good signature"));
}

/// The remote's `gpg` says the code's own words: those gpg-agent uses when
/// its owner denies a key, and when nobody confirmed it. A connection refused
/// at its opening is, to `gpg`, an agent that is not running, whatever the
/// code.
#[test]
fn a_refusal_reaches_the_remote_gpg_as_the_agents_own_words() {
    let workstation = Scratch::new("relay-refusals");
    let (fingerprint, _) = workstation.key();
    workstation.launch();
    let cases = [
        (Ok(()), Err(Refusal::Declined), "Operation cancelled"),
        (
            Ok(()),
            Err(Refusal::NobodyReachable(Whereabouts::Away)),
            "Not confirmed",
        ),
        (Err(Refusal::Paused), Ok(()), "No agent running"),
    ];
    for (connect, sign_answer, words) in cases {
        let answers = Answers {
            connect,
            sign: sign_answer,
        };
        let (port, told, running) = relay(
            workstation.source(Access::Restricted),
            Some(ISSUED),
            answers,
        );
        let remote = remote(&workstation, port, ISSUED);
        let signed = sign(&remote, &fingerprint);
        running.join().unwrap();
        drop(told);
        assert!(!signed.status.success(), "{signed:?}");
        let said = String::from_utf8_lossy(&signed.stderr);
        assert!(said.contains(words), "{words} in {said}");
    }
}

/// Reads one Assuan line.
fn line(stream: &mut TcpStream) -> String {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).unwrap() == 1 {
        line.push(byte[0]);
        if byte == *b"\n" {
            break;
        }
    }
    String::from_utf8_lossy(&line).into_owned()
}

/// Sends `command` and reads until the answer that ends it.
fn transact(stream: &mut TcpStream, command: &str) -> Vec<String> {
    stream.write_all(command.as_bytes()).unwrap();
    let mut answer = Vec::new();
    loop {
        let read = line(stream);
        let last = read.starts_with("OK") || read.starts_with("ERR") || read.is_empty();
        answer.push(read);
        if last {
            return answer;
        }
    }
}

/// The exchange `gpg --detach-sign` makes, as `GnuPG` 2.5.24 recorded it, sent
/// line for line by a client of a Unix remote's form, which presents nothing
/// first: every answer comes back, and the signature only once allowed.
#[test]
fn the_recorded_exchange_passes_both_ways_and_the_signature_waits_for_its_decision() {
    let workstation = Scratch::new("relay-recorded");
    let (_, grip) = workstation.key();
    workstation.launch();
    let answers = Answers {
        connect: Ok(()),
        sign: Ok(()),
    };
    let (port, told, running) = relay(workstation.source(Access::Restricted), None, answers);
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    assert!(line(&mut client).starts_with("OK Pleased to meet you"));
    let recorded = [
        "RESET\n".to_owned(),
        "OPTION ttytype=xterm-256color\n".to_owned(),
        "GETINFO version\n".to_owned(),
        "OPTION allow-pinentry-notify\n".to_owned(),
        "OPTION agent-awareness=2.1.0\n".to_owned(),
        "SCD SERIALNO\n".to_owned(),
        "RESET\n".to_owned(),
        format!("SIGKEY {grip}\n"),
        "SETKEYDESC Please+enter+the+passphrase%0A\n".to_owned(),
        "SETHASH 10 9FF3973FEA743195C97D82EB0689663A0823DEA11866A8BF8A79CC5A25A9B0844C86099A13CFD01E40FAB8ADFB8C62B244C7992D0916C74D21A629E672210446\n".to_owned(),
    ];
    let mut answers = Vec::new();
    for command in &recorded {
        answers.push(transact(&mut client, command));
    }
    // The restricted socket's own answers pass unchanged: what it forbids a
    // remote, and the scdaemon's for a card, whatever reader the workstation
    // has.
    for index in [1, 3] {
        assert_eq!(answers[index], ["ERR 67109115 Forbidden <GPG Agent>\n"]);
    }
    assert_eq!(answers[2], ["D 2.5.24\n", "OK\n"]);
    assert_eq!(answers[5], ["ERR 100663614 Service is not running <SCD>\n"]);
    workstation.reached_no_reader();
    for index in [0, 6, 7, 8, 9] {
        assert_eq!(
            answers[index].last().unwrap(),
            "OK\n",
            "{index}: {:?}",
            answers[index]
        );
    }
    let signed = transact(&mut client, "PKSIGN\n");
    assert!(
        signed[0].starts_with("D (7:sig-val(5:eddsa(1:r32:"),
        "{signed:?}"
    );
    assert_eq!(signed.last().unwrap(), "OK\n");
    assert_eq!(transact(&mut client, "BYE\n"), ["OK closing connection\n"]);
    running.join().unwrap();
    assert_eq!(
        heard(&told),
        [
            Relayed::Reached(Ok(())),
            Relayed::Asks(Ask {
                operation: Operation::Sign,
                key: Some(grip),
            }),
            Relayed::Ended,
        ]
    );
}

/// gpg-agent ends a connection that sends a line past the limit, and runs
/// none of it; the relay ends it too, carries none of it, and says why.
#[test]
fn an_over_long_line_ends_the_connection_at_the_agent_and_at_the_relay() {
    let workstation = Scratch::new("relay-cut");
    workstation.key();
    workstation.launch();
    let mut smuggled = vec![b'A'; 1002];
    smuggled.extend_from_slice(b"GETINFO version\n");

    let file = std::fs::read(workstation.dir("agent-extra-socket")).unwrap();
    let (port, nonce) = file.split_at(file.iter().position(|byte| *byte == b'\n').unwrap());
    let port: u16 = std::str::from_utf8(port).unwrap().parse().unwrap();
    let mut direct = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    direct.write_all(&nonce[1..]).unwrap();
    assert!(line(&mut direct).starts_with("OK"));
    direct.write_all(&smuggled).unwrap();
    let mut after = Vec::new();
    let _ = direct.read_to_end(&mut after);
    let after = String::from_utf8_lossy(&after);
    assert!(
        !after.contains("2.5.24"),
        "nothing of the line runs: {after}"
    );

    let answers = Answers {
        connect: Ok(()),
        sign: Ok(()),
    };
    let (port, told, running) = relay(workstation.source(Access::Restricted), None, answers);
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    assert!(line(&mut client).starts_with("OK"));
    client.write_all(&smuggled).unwrap();
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "nothing is answered");
    running.join().unwrap();
    assert_eq!(
        heard(&told),
        [
            Relayed::Reached(Ok(())),
            Relayed::Breached(Breach::TooLong(Side::Client)),
            Relayed::Ended,
        ]
    );
}

/// A process on a Windows remote that cannot read the remote's socket file
/// does not know the bytes it holds, and is closed with nothing said to it
/// and nothing reaching the agent.
#[test]
fn a_remote_process_without_the_issued_bytes_is_closed_unanswered() {
    let workstation = Scratch::new("relay-unissued");
    workstation.launch();
    let answers = Answers {
        connect: Ok(()),
        sign: Ok(()),
    };
    let (port, told, running) = relay(
        workstation.source(Access::Restricted),
        Some(ISSUED),
        answers,
    );
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    client.write_all(&[0u8; 16]).unwrap();
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, Vec::<u8>::new());
    running.join().unwrap();
    assert_eq!(heard(&told), [Relayed::Unpresented, Relayed::Ended]);
}

/// Grants `folder` to the person's account alone, nothing inherited, so a
/// token reads what is made in it only through the account: Administrators,
/// enabled in a full administrator's token, would read it too otherwise.
fn the_account_alone(folder: &Path) {
    let account = Token::own().unwrap().user().unwrap().to_text().unwrap();
    let set = Command::new(r"C:\Windows\System32\icacls.exe")
        .arg(folder)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("*{account}:(OI)(CI)F"),
        ])
        .output()
        .unwrap();
    assert!(set.status.success(), "{set:?}");
}

/// The listener is given the file's bytes only where its own token would be
/// let read the file: parity, whatever lowered the token - a restricting
/// list, the account made deny-only - and a lower integrity level, which the
/// file's label lets read, is no reason to refuse.
#[test]
fn the_listener_is_given_the_bytes_only_where_it_could_read_the_socket_file() {
    let workstation = Scratch::new("relay-listener");
    the_account_alone(workstation.path());
    workstation.launch();
    let file = workstation.dir("agent-extra-socket");
    // Low integrity may read the file but is not the person: the agent's
    // listener must be both.
    let person = Token::own().unwrap().user().unwrap();
    for (less, reads, the_person) in [
        (Less::Same, true, true),
        (Less::Low, true, false),
        (Less::RestrictedToEveryone, false, false),
        (Less::AccountDenyOnly, false, false),
    ] {
        let token = Token::from(token(less).unwrap());
        assert_eq!(token.may_read(&file).unwrap(), reads, "{less:?}");
        assert_eq!(
            token.is_the_person(&person).unwrap(),
            the_person,
            "{less:?}"
        );
    }
    // The agent itself, found as the relay finds it, and read as the
    // person's.
    let reached = Agents::default().reach(&workstation.source(Access::Restricted));
    assert!(
        matches!(&reached.holder, Some(holder) if matches!(holder.whose, Whose::Person { .. })
            && holder.program.as_str().ends_with("gpg-agent.exe")),
        "{:?}",
        reached.holder
    );
    let (agent, greeting) = reached.result.unwrap();
    assert!(greeting.starts_with(b"OK Pleased to meet you"));
    let listener = hedwig_win::endpoint::owner(&agent).unwrap().unwrap();
    let process = Process::open(listener).unwrap();
    assert!(process.program().unwrap().ends_with("gpg-agent.exe"));
    assert!(process.token_to_check().unwrap().may_read(&file).unwrap());
}

/// The agent Hedwig starts is the person's: started from inside a job that
/// allows leaving it, it is outside the job and outlives it; from inside one
/// that does not, it is not started at all.
#[test]
fn the_agent_hedwig_starts_is_left_outside_its_job() {
    let child = PathBuf::from(env!("CARGO_BIN_EXE_child"));
    for (job, starts) in [
        (Job::leavable().unwrap(), true),
        (Job::new().unwrap(), false),
    ] {
        let workstation = Scratch::new("relay-launch");
        let arguments: Vec<OsString> = vec![
            "launch".into(),
            installation().into_os_string(),
            workstation.path().as_os_str().to_owned(),
        ];
        let (launcher, _) = held(&child, &arguments, &Environment::own(), &job).unwrap();
        let status = launcher.wait().unwrap();
        assert_eq!(status == 0, starts, "{status}");
        let socket = workstation.dir("agent-extra-socket");
        if !starts {
            assert!(!socket.exists(), "no agent was started");
            continue;
        }
        let (agent, _) = Agents::default()
            .reach(&workstation.source(Access::Restricted))
            .result
            .unwrap();
        let owner = hedwig_win::endpoint::owner(&agent).unwrap().unwrap();
        let process = Process::open(owner).unwrap();
        assert!(!job.includes(&process).unwrap(), "the agent left the job");
        drop(agent);
        drop(job);
        assert!(
            Agents::default()
                .reach(&workstation.source(Access::Restricted))
                .result
                .is_ok(),
            "and outlives it"
        );
    }
}

/// What the source offers, read with its own tools: the key, the keygrip the
/// agent knows it by, the one key that signs as the signing key, and its
/// public half, which another home imports.
#[test]
fn the_keys_read_back_as_the_sources_own_tools_list_them() {
    let workstation = Scratch::new("relay-keys");
    let (fingerprint, grip) = workstation.key();
    let search = std::env::var_os("PATH").unwrap_or_default();
    let agents = Agents::default();
    let read = keys::read(&agents, &workstation.source(Access::Restricted), &search).unwrap();
    let [key] = read.keyring.keys.as_slice() else {
        panic!("one key: {read:?}");
    };
    assert_eq!(key.grip, grip);
    assert_eq!(key.fingerprint, fingerprint);
    assert_eq!(key.primary, fingerprint);
    assert!(key.uses.has(Uses::SIGN));
    assert_eq!(
        key.user.as_ref().map(hedwig_model::text::Words::as_str),
        Some("Relay Test <relay@example.invalid>")
    );
    assert_eq!(
        read.keyring.signing.as_ref().map(Mark::as_str),
        Some(fingerprint.as_str())
    );
    assert_eq!(key.card, None);
    assert!(read.cards.is_empty(), "no card: {:?}", read.cards);
    let armour = read.armoured.get(&fingerprint).unwrap();
    assert!(armour.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    let other = Scratch::new("relay-keys-import");
    let file = other.path().join("key.asc");
    std::fs::write(&file, armour).unwrap();
    let imported = other.run("gpg.exe", &["--batch", "--import", file.to_str().unwrap()]);
    assert!(imported.status.success(), "{imported:?}");
}

/// Git for Windows' own `GnuPG` answers `gpgconf` with POSIX paths: it is named
/// as what Hedwig does not serve, and never started.
#[test]
fn a_posix_emulated_gnupg_is_named_and_never_started() {
    let git = Path::new(r"C:\Program Files\Git\usr");
    assert!(
        git.join("bin").join("gpgconf.exe").is_file(),
        "Git for Windows is installed where it installs"
    );
    let source = Gnupg {
        installation: Installation::At(Place::try_from(git.to_str().unwrap()).unwrap()),
        home: Home::Default,
        access: Access::Restricted,
    };
    assert_eq!(
        Agents::default().reach(&source).result.err(),
        Some(Failure::Unserved)
    );
    let search = std::env::var_os("PATH").unwrap_or_default();
    assert_eq!(
        keys::read(&Agents::default(), &source, &search).err(),
        Some(Failure::Unserved)
    );
}

/// The two cards of the recorded exchange: the one scdaemon reaches first,
/// holding the suite's key in its signing slot, and a second one, as scdaemon
/// 2.5.24 writes their serial numbers.
const FIRST_CARD: &str = "D2760001240103040006123456780000";
const SECOND_CARD: &str = "D2760001240103040006876543210000";

/// A keygrip on the second card, which no key of the home is.
const SECOND_GRIP: &str = "0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2";

impl Scratch {
    /// Makes the key `grip` names a stub of a key on `card`'s signing slot, as
    /// gpg-agent writes one when it learns a card: `shadowed-private-key`, the
    /// secret gone, `(shadowed t1-v1 (<serial> OPENPGP.1))` in its place.
    fn on_card(&self, grip: &Grip, card: &str) {
        let file = self
            .path()
            .join("private-keys-v1.d")
            .join(format!("{grip}.key"));
        let text = std::fs::read_to_string(&file).unwrap();
        let start = text.find("(d #").unwrap();
        let end = start + text[start..].find("#)").unwrap() + 2;
        let stub = format!(
            "{}{}",
            text[..start].replace("(private-key", "(shadowed-private-key"),
            text[end..].replacen("))", &format!("(shadowed t1-v1 (#{card}# OPENPGP.1))))"), 1)
        );
        std::fs::write(&file, stub).unwrap();
    }

    /// Has the agent start the stand-in scdaemon, answering from `exchange`
    /// and logging every command it is sent, and starts the agent.
    fn with_card(&self, exchange: &str) -> PathBuf {
        let stand_in = env!("CARGO_BIN_EXE_scdaemon");
        std::fs::write(
            self.path().join("gpg-agent.conf"),
            format!("scdaemon-program {stand_in}\n"),
        )
        .unwrap();
        // The agent the key's making started knows nothing of the stand-in.
        let stopped = self.run("gpgconf.exe", &["--kill", "gpg-agent"]);
        assert!(stopped.status.success(), "{stopped:?}");
        let recording = self.path().join("card.txt");
        std::fs::write(&recording, exchange).unwrap();
        let log = self.path().join("card.log");
        let launched = Command::new(tool("gpgconf.exe"))
            .arg("--homedir")
            .arg(self.path())
            .args(["--launch", "gpg-agent"])
            .env("HEDWIG_CARD", &recording)
            .env("HEDWIG_CARD_LOG", &log)
            .output()
            .unwrap();
        assert!(launched.status.success(), "{launched:?}");
        log
    }
}

/// What scdaemon answers for the two cards: `KEYINFO --list` naming each key
/// with its card and slot; the first card's serial number, application,
/// capabilities, the flags that say what each slot asks for, and the PIN's
/// status, each in the form scdaemon 2.5.24's `send_status_info` writes it
/// (`scd/app-openpgp.c`, `do_getattr`; `scd/command.c`, `send_status_info`).
fn exchange(grip: &Grip, application: &str) -> String {
    [
        "> KEYINFO --list".to_owned(),
        format!("S KEYINFO {grip} T {FIRST_CARD} OPENPGP.1 sc"),
        format!("S KEYINFO {SECOND_GRIP} T {SECOND_CARD} OPENPGP.3 a"),
        "OK".to_owned(),
        "> GETATTR SERIALNO".to_owned(),
        format!("S SERIALNO {FIRST_CARD}"),
        "OK".to_owned(),
        "> GETATTR APPTYPE".to_owned(),
        format!("S APPTYPE {application}"),
        "OK".to_owned(),
        "> GETATTR EXTCAP".to_owned(),
        "S EXTCAP gc=1+ki=1+fc=1+pd=1+mcl3=2048+aac=1+sm=0+si=5+dec=1+bt=1+kdf=1".to_owned(),
        "OK".to_owned(),
        "> GETATTR UIF".to_owned(),
        "S UIF-1 %01+".to_owned(),
        "S UIF-2 %00+".to_owned(),
        "S UIF-3 %03+".to_owned(),
        "OK".to_owned(),
        "> GETATTR CHV-STATUS".to_owned(),
        "S CHV-STATUS +1+127+127+127+3+0+3".to_owned(),
        "OK".to_owned(),
    ]
    .join("\n")
}

/// Everything anything sent the stand-in scdaemon, each command checked to be
/// the agent's own to start a session or one of the reads: nothing that opens
/// a card, switches one or its application, resets one, or names a key.
fn only_reads(log: &Path) -> Vec<String> {
    let sent: Vec<String> = std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    for command in &sent {
        let read = matches!(
            command.as_str(),
            "KEYINFO --list"
                | "GETATTR SERIALNO"
                | "GETATTR APPTYPE"
                | "GETATTR EXTCAP"
                | "GETATTR UIF"
                | "GETATTR CHV-STATUS"
        );
        let agents_own = command == "GETINFO socket_name"
            || command.starts_with("OPTION event-signal=")
            || command == "RESTART"
            || command == "killscd";
        assert!(read || agents_own, "{command} was sent to the card");
    }
    sent
}

/// The cards are read through the person's agent: the key's card from its
/// stub, which key each card holds, and what the first card asks for before
/// each, while nothing sent could open a card, switch one or its application,
/// or reset one.
#[test]
fn the_cards_are_read_through_the_agent_and_nothing_sent_opens_or_switches_one() {
    let workstation = Scratch::new("relay-cards");
    let (_, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let log = workstation.with_card(&exchange(&grip, "openpgp"));
    let search = std::env::var_os("PATH").unwrap_or_default();
    let read = keys::read(
        &Agents::default(),
        &workstation.source(Access::Restricted),
        &search,
    )
    .unwrap();
    let [key] = read.keyring.keys.as_slice() else {
        panic!("the stub is listed as a key: {read:?}");
    };
    assert_eq!(key.grip, grip);
    assert_eq!(key.card.as_ref().map(Serial::as_str), Some(FIRST_CARD));
    assert_eq!(
        read.cards,
        vec![
            Card {
                serial: Serial::try_from(FIRST_CARD).unwrap(),
                keys: vec![Held {
                    grip: grip.clone(),
                    touch: Some(Touch::On),
                }],
                pin: Some(SignaturePin::Once),
            },
            Card {
                serial: Serial::try_from(SECOND_CARD).unwrap(),
                keys: vec![Held {
                    grip: Grip::try_from(SECOND_GRIP).unwrap(),
                    touch: None,
                }],
                pin: None,
            },
        ]
    );
    let sent = only_reads(&log);
    let reads: Vec<&str> = sent
        .iter()
        .map(String::as_str)
        .filter(|command| command.starts_with("GETATTR"))
        .collect();
    assert_eq!(
        reads,
        [
            "GETATTR SERIALNO",
            "GETATTR APPTYPE",
            "GETATTR EXTCAP",
            "GETATTR UIF",
            "GETATTR CHV-STATUS"
        ]
    );
}

/// A first card whose selected application is not `OpenPGP`'s - Kleopatra
/// left it on PIV - has its keys named and nothing it asks for read: reading
/// it would switch the person's application.
#[test]
fn a_first_card_in_another_application_is_named_and_not_switched() {
    let workstation = Scratch::new("relay-cards-piv");
    let (_, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let log = workstation.with_card(&exchange(&grip, "piv"));
    let cards =
        keys::read_cards(&Agents::default(), &workstation.source(Access::Restricted)).unwrap();
    assert_eq!(cards.len(), 2);
    assert!(
        cards
            .iter()
            .all(|card| card.pin.is_none() && card.keys.iter().all(|held| held.touch.is_none())),
        "{cards:?}"
    );
    let sent = only_reads(&log);
    assert!(
        !sent.iter().any(|command| command == "GETATTR UIF"),
        "{sent:?}"
    );
}

/// With `GnuPG`'s own scdaemon and no card it holds, nothing is read:
/// `KEYINFO --list` walks only the cards scdaemon holds.
#[test]
fn with_no_card_scdaemon_holds_nothing_is_read() {
    let workstation = Scratch::new("relay-cards-none");
    workstation.key();
    workstation.launch();
    let cards =
        keys::read_cards(&Agents::default(), &workstation.source(Access::Restricted)).unwrap();
    assert!(cards.is_empty(), "{cards:?}");
}
