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

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use hedwig_core::assuan::{Ask, Breach, Nonce, Side};
use hedwig_core::dispatch::{Effect, Input, ReadId, Told};
use hedwig_core::keys::{self, Cards, Known};
use hedwig_core::relay::{Agents, Gnupg, Relayed, Settle, carry, listed};
use hedwig_core::run::{Message, start_read};
use hedwig_model::capability::{Access, Home, Installation, Operation};
use hedwig_model::holder::Whose;
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::text::{Fingerprint, Folder as Place, Grip, Mark, Name, Serial};
use hedwig_model::trail::{
    Card, ConnectionId, Failure, Held, Keyring, Seq, SignaturePin, Touch, Uses,
};
use hedwig_support::lower::{Less, token};
use hedwig_support::{Folder, SCDAEMON_LOG, readerless, retire_home};
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
        if let Some(folder) = std::env::var_os("HEDWIG_GNUPG") {
            retire_home(&PathBuf::from(folder).join("bin"), self.path());
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

/// Leaves `folder` and everything in it granted to the person's account
/// alone, so a token reads them only through the account: Administrators,
/// enabled in a full administrator's token, would read them too otherwise.
/// Every entry goes first, those a file was made with included, which no
/// change to its folder's list takes from the file.
fn the_account_alone(folder: &Path) {
    let account = Token::own().unwrap().user().unwrap().to_text().unwrap();
    let icacls = |arguments: &[&str]| {
        let set = Command::new(r"C:\Windows\System32\icacls.exe")
            .arg(folder)
            .args(arguments)
            .output()
            .unwrap();
        assert!(set.status.success(), "{set:?}");
    };
    icacls(&["/reset", "/T"]);
    icacls(&[
        "/inheritance:r",
        "/grant:r",
        &format!("*{account}:(OI)(CI)F"),
    ]);
}

/// The listener is given the file's bytes only where its own token would be
/// let read the file: parity, whatever lowered the token - a restricting
/// list, the account made deny-only - and a lower integrity level, which the
/// file's label lets read, is no reason to refuse.
#[test]
fn the_listener_is_given_the_bytes_only_where_it_could_read_the_socket_file() {
    let workstation = Scratch::new("relay-listener");
    workstation.launch();
    // GnuPG puts a home's sockets below the person's local application data,
    // in a `d.` folder named for this home alone, which the scratch removes.
    let sockets = workstation.dir("socketdir");
    assert!(
        sockets
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("d.")),
        "{}",
        sockets.display()
    );
    the_account_alone(&sockets);
    let file = workstation.dir("agent-extra-socket");
    assert!(file.starts_with(&sockets), "{}", file.display());
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
    let read = keys::read(
        &agents,
        &workstation.source(Access::Restricted),
        &search,
        &Known::default(),
    )
    .unwrap();
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
    assert!(cards_in(&read).is_empty(), "no card: {:?}", cards_in(&read));
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
        keys::read(&Agents::default(), &source, &search, &Known::default()).err(),
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

/// What scdaemon answers for the two cards: the cards it holds; `KEYINFO
/// --list` naming each key with its card and slot; the first card's serial
/// number, application, the fingerprint in its signing slot, capabilities, the
/// flags that say what each slot asks for, and the PIN's status, each in the
/// form scdaemon 2.5.24 writes it (`scd/app.c`,
/// `send_serialno_and_app_status`; `scd/app-openpgp.c`, `do_getattr`;
/// `scd/command.c`, `send_status_info`).
fn exchange(grip: &Grip, fingerprint: &Fingerprint, application: &str) -> String {
    [
        "> GETINFO card_list".to_owned(),
        format!("S SERIALNO {FIRST_CARD}"),
        format!("S SERIALNO {SECOND_CARD}"),
        "OK".to_owned(),
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
        "> GETATTR KEY-FPR".to_owned(),
        format!("S KEY-FPR 1 {fingerprint}"),
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
            "GETINFO card_list"
                | "KEYINFO --list"
                | "GETATTR SERIALNO"
                | "GETATTR APPTYPE"
                | "GETATTR KEY-FPR"
                | "GETATTR EXTCAP"
                | "GETATTR UIF"
                | "GETATTR CHV-STATUS"
        );
        assert!(
            read || agents_own(command),
            "{command} was sent to the card"
        );
    }
    sent
}

/// A command the agent sends scdaemon to start or end a session of its own.
fn agents_own(command: &str) -> bool {
    command == "GETINFO socket_name"
        || command.starts_with("OPTION event-signal=")
        || command == "RESTART"
        || command == "killscd"
}

/// The cards are read through the person's agent: the key's card from its
/// stub, which key each card holds, and what the first card asks for before
/// each, while nothing sent could open a card, switch one or its application,
/// or reset one.
#[test]
fn the_cards_are_read_through_the_agent_and_nothing_sent_opens_or_switches_one() {
    let workstation = Scratch::new("relay-cards");
    let (fingerprint, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let log = workstation.with_card(&exchange(&grip, &fingerprint, "openpgp"));
    let search = std::env::var_os("PATH").unwrap_or_default();
    let read = keys::read(
        &Agents::default(),
        &workstation.source(Access::Restricted),
        &search,
        &Known::default(),
    )
    .unwrap();
    let [key] = read.keyring.keys.as_slice() else {
        panic!("the stub is listed as a key: {read:?}");
    };
    assert_eq!(key.grip, grip);
    assert_eq!(key.card.as_ref().map(Serial::as_str), Some(FIRST_CARD));
    assert_eq!(
        cards_in(&read),
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
    let (fingerprint, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let log = workstation.with_card(&exchange(&grip, &fingerprint, "piv"));
    let cards = keys::read_cards(
        &Agents::default(),
        &workstation.source(Access::Restricted),
        &Known::default(),
        &Keyring::default(),
    )
    .unwrap()
    .cards;
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

/// A whole reading whose card read fails - scdaemon answering the card list
/// only after twice `PATIENCE`, so the agent is silent past it - keeps the keys
/// its listing read and says the cards could not be read, never that no card
/// is held.
#[test]
fn a_whole_reading_whose_card_read_fails_says_so_and_keeps_its_keys() {
    let workstation = Scratch::new("relay-cards-silent");
    let (fingerprint, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    workstation.with_card(&delayed(
        &exchange(&grip, &fingerprint, "openpgp"),
        "GETINFO card_list",
        hedwig_core::PATIENCE * 2,
    ));
    let search = std::env::var_os("PATH").unwrap_or_default();
    let read = keys::read(
        &Agents::default(),
        &workstation.source(Access::Restricted),
        &search,
        &Known::default(),
    )
    .unwrap();
    assert!(!read.keyring.keys.is_empty(), "{read:?}");
    assert!(read.cards.is_err(), "{read:?}");
}

/// `exchange` with `command` answered only after `late`, as scdaemon held by
/// another card operation answers. The stand-in sleeps through it, so it
/// outlives a test whose read gave up first by what remains of `late`.
fn delayed(exchange: &str, command: &str, late: Duration) -> String {
    let heading = format!("> {command}");
    let pause = format!("PAUSE {}", late.as_millis());
    let mut lines = Vec::new();
    for line in exchange.lines() {
        lines.push(line);
        if line == heading {
            lines.push(&pause);
        }
    }
    lines.join("\n") + "\n"
}

/// With `GnuPG`'s own scdaemon and no card it holds, nothing is read:
/// `KEYINFO --list` walks only the cards scdaemon holds.
#[test]
fn with_no_card_scdaemon_holds_nothing_is_read() {
    let workstation = Scratch::new("relay-cards-none");
    workstation.key();
    workstation.launch();
    let cards = keys::read_cards(
        &Agents::default(),
        &workstation.source(Access::Restricted),
        &Known::default(),
        &Keyring::default(),
    )
    .unwrap()
    .cards;
    assert!(cards.is_empty(), "{cards:?}");
}

/// After a use, with every card scdaemon holds one the core has read, the card
/// read lists the cards and asks the first for its attributes alone: no
/// keygrip lookup, which would select each application of each card and have
/// the card forget its verified PIN. A card never read, or a slot the keyring
/// cannot tie to a key the card is known to hold, has the cards walked.
#[test]
fn a_known_card_is_read_after_a_use_without_a_keygrip_lookup() {
    let workstation = Scratch::new("relay-cards-known");
    let (fingerprint, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let log = workstation.with_card(&exchange(&grip, &fingerprint, "openpgp"));
    let search = std::env::var_os("PATH").unwrap_or_default();
    let (agents, source) = (Agents::default(), workstation.source(Access::Restricted));
    let read = keys::read(&agents, &source, &search, &Known::default()).unwrap();
    assert_eq!(cards_in(&read).len(), 2, "{read:?}");
    let since = |mark: usize| -> Vec<String> {
        only_reads(&log)
            .into_iter()
            .skip(mark)
            .filter(|command| !agents_own(command))
            .collect()
    };
    let mark = only_reads(&log).len();
    let again =
        keys::read_cards(&agents, &source, &knowing(&cards_in(&read)), &read.keyring).unwrap();
    assert_eq!(again.cards, cards_in(&read)[..1]);
    assert_eq!(
        since(mark),
        [
            "GETINFO card_list",
            "GETATTR SERIALNO",
            "GETATTR APPTYPE",
            "GETATTR EXTCAP",
            "GETATTR UIF",
            "GETATTR CHV-STATUS",
            "GETATTR KEY-FPR"
        ]
    );
    let mark = only_reads(&log).len();
    let first_only = keys::read_cards(
        &agents,
        &source,
        &knowing(&cards_in(&read)[..1]),
        &read.keyring,
    )
    .unwrap();
    assert_eq!(
        first_only.cards,
        cards_in(&read),
        "a card never read has the cards walked"
    );
    assert!(
        since(mark)
            .iter()
            .any(|command| command == "KEYINFO --list")
    );
    let mark = only_reads(&log).len();
    let unnamed = keys::read_cards(
        &agents,
        &source,
        &knowing(&cards_in(&read)),
        &Keyring::default(),
    )
    .unwrap();
    assert_eq!(
        unnamed.cards,
        cards_in(&read),
        "a slot the keyring cannot name has the cards walked"
    );
    assert!(
        since(mark)
            .iter()
            .any(|command| command == "KEYINFO --list")
    );
}

/// With every card scdaemon holds known and the first in another application,
/// nothing more is read: its attributes would need its application switched.
#[test]
fn a_known_first_card_in_another_application_has_nothing_more_read() {
    let workstation = Scratch::new("relay-cards-known-piv");
    let (fingerprint, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let log = workstation.with_card(&exchange(&grip, &fingerprint, "piv"));
    let (agents, source) = (Agents::default(), workstation.source(Access::Restricted));
    let walked =
        keys::read_cards(&agents, &source, &Known::default(), &Keyring::default()).unwrap();
    let mark = only_reads(&log).len();
    let again = keys::read_cards(
        &agents,
        &source,
        &knowing(&walked.cards),
        &Keyring::default(),
    )
    .unwrap();
    assert_eq!(again, Cards::default());
    let sent: Vec<String> = only_reads(&log)
        .into_iter()
        .skip(mark)
        .filter(|command| !agents_own(command))
        .collect();
    assert_eq!(
        sent,
        ["GETINFO card_list", "GETATTR SERIALNO", "GETATTR APPTYPE"]
    );
}

/// A card list naming no card has nothing more asked: a `GETATTR` with no card
/// held would have scdaemon scan the readers for one.
#[test]
fn a_card_list_naming_no_card_has_nothing_more_asked() {
    let workstation = Scratch::new("relay-cards-empty-list");
    workstation.key();
    let log = workstation.with_card("> GETINFO card_list\nOK");
    let cards = keys::read_cards(
        &Agents::default(),
        &workstation.source(Access::Restricted),
        &Known::default(),
        &Keyring::default(),
    )
    .unwrap()
    .cards;
    assert_eq!(cards, []);
    let sent: Vec<String> = only_reads(&log)
        .into_iter()
        .filter(|command| !agents_own(command))
        .collect();
    assert_eq!(sent, ["GETINFO card_list"]);
}

/// A third card held, the stand-in's, on which `KEYINFO --list` names no key.
const KEYLESS_CARD: &str = "D2760001240103040006555555550000";

/// A card scdaemon holds on which a walk names no key is returned as holding
/// none, for the core to remember and record nowhere; a read that knows it
/// walks nothing for it.
#[test]
fn a_held_card_naming_no_key_is_walked_once() {
    let workstation = Scratch::new("relay-cards-keyless");
    let (fingerprint, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let listed = format!("S SERIALNO {FIRST_CARD}\nS SERIALNO {SECOND_CARD}\nOK");
    let exchange = exchange(&grip, &fingerprint, "openpgp").replacen(
        &listed,
        &format!(
            "S SERIALNO {FIRST_CARD}\nS SERIALNO {SECOND_CARD}\nS SERIALNO {KEYLESS_CARD}\nOK"
        ),
        1,
    );
    assert!(exchange.contains(KEYLESS_CARD), "the card list names three");
    let log = workstation.with_card(&exchange);
    let search = std::env::var_os("PATH").unwrap_or_default();
    let (agents, source) = (Agents::default(), workstation.source(Access::Restricted));
    let read = keys::read(&agents, &source, &search, &Known::default()).unwrap();
    let keyless = Serial::try_from(KEYLESS_CARD).unwrap();
    assert_eq!(keyless_in(&read), std::slice::from_ref(&keyless));
    assert!(
        cards_in(&read).iter().all(|card| card.serial != keyless),
        "{read:?}"
    );
    let mark = only_reads(&log).len();
    let known = Known {
        cards: cards_in(&read).clone(),
        keyless: BTreeSet::from([keyless]),
    };
    let again = keys::read_cards(&agents, &source, &known, &read.keyring).unwrap();
    assert_eq!(
        again.cards,
        cards_in(&read)[..1],
        "the first card's attributes"
    );
    assert!(
        !only_reads(&log)
            .iter()
            .skip(mark)
            .any(|command| command == "KEYINFO --list"),
        "a card known to hold no key is not walked again"
    );
}

/// A card the core has read on which a later walk names no key keeps what it
/// said: the walk returns it neither read again nor holding none, so the
/// core's record of it stands.
#[test]
fn a_known_card_a_walk_names_no_key_on_keeps_its_word() {
    let workstation = Scratch::new("relay-cards-unnamed");
    let (fingerprint, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let both = exchange(&grip, &fingerprint, "openpgp");
    let second = format!("S KEYINFO {SECOND_GRIP} T {SECOND_CARD} OPENPGP.3 a\n");
    let first_named = both.replacen(&second, "", 1);
    assert_ne!(first_named, both, "the walk names the first card alone");
    workstation.with_card(&first_named);
    let (agents, source) = (Agents::default(), workstation.source(Access::Restricted));
    let second_card = Card {
        serial: Serial::try_from(SECOND_CARD).unwrap(),
        keys: vec![Held {
            grip: Grip::try_from(SECOND_GRIP).unwrap(),
            touch: None,
        }],
        pin: None,
    };
    let first_card = Card {
        serial: Serial::try_from(FIRST_CARD).unwrap(),
        keys: vec![Held {
            grip: grip.clone(),
            touch: Some(Touch::On),
        }],
        pin: Some(SignaturePin::Once),
    };
    // A keyring that cannot name the first card's slot has the cards walked.
    let walked = keys::read_cards(
        &agents,
        &source,
        &knowing(&[first_card.clone(), second_card]),
        &Keyring::default(),
    )
    .unwrap();
    assert_eq!(
        walked,
        Cards {
            cards: vec![first_card],
            keyless: Vec::new(),
        }
    );
}

/// A card a walk once found holding no key, recorded since with a key, is read
/// as recorded: its slots emptied again leave out a key it is known to hold,
/// which has the cards walked.
#[test]
fn a_card_recorded_since_it_held_no_key_is_read_as_recorded() {
    let workstation = Scratch::new("relay-cards-was-keyless");
    let (fingerprint, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let full = exchange(&grip, &fingerprint, "openpgp");
    let slot = format!("S KEY-FPR 1 {fingerprint}\n");
    let emptied = full.replacen(&slot, "", 1);
    assert_ne!(emptied, full, "the first card's slots are empty");
    let log = workstation.with_card(&emptied);
    let search = std::env::var_os("PATH").unwrap_or_default();
    let (agents, source) = (Agents::default(), workstation.source(Access::Restricted));
    let read = keys::read(&agents, &source, &search, &Known::default()).unwrap();
    let first = Serial::try_from(FIRST_CARD).unwrap();
    let known = Known {
        cards: cards_in(&read).clone(),
        keyless: BTreeSet::from([first]),
    };
    let mark = only_reads(&log).len();
    keys::read_cards(&agents, &source, &known, &read.keyring).unwrap();
    assert!(
        only_reads(&log)
            .iter()
            .skip(mark)
            .any(|command| command == "KEYINFO --list"),
        "the key it is known to hold is in no slot"
    );
}

/// A first card known to hold no key is read from its slots alone: still
/// empty, nothing more is asked; a key put on it since is a changed slot,
/// which has the cards walked.
#[test]
fn a_first_card_known_to_hold_no_key_is_read_from_its_slots() {
    let workstation = Scratch::new("relay-cards-keyless-first");
    let (fingerprint, grip) = workstation.key();
    workstation.on_card(&grip, FIRST_CARD);
    let edits = [
        (
            format!("S SERIALNO {FIRST_CARD}\nS SERIALNO {SECOND_CARD}\nOK"),
            format!("S SERIALNO {FIRST_CARD}\nS SERIALNO {KEYLESS_CARD}\nOK"),
        ),
        (
            format!("S KEYINFO {SECOND_GRIP} T {SECOND_CARD} OPENPGP.3 a\n"),
            String::new(),
        ),
        (
            format!("> GETATTR SERIALNO\nS SERIALNO {FIRST_CARD}"),
            format!("> GETATTR SERIALNO\nS SERIALNO {KEYLESS_CARD}"),
        ),
    ];
    let mut slotted = exchange(&grip, &fingerprint, "openpgp");
    for (from, to) in &edits {
        let edited = slotted.replacen(from, to, 1);
        assert_ne!(edited, slotted, "{from}");
        slotted = edited;
    }
    let empty = slotted.replacen(&format!("S KEY-FPR 1 {fingerprint}\n"), "", 1);
    assert_ne!(empty, slotted, "the keyless card's slots are empty");
    let log = workstation.with_card(&empty);
    let search = std::env::var_os("PATH").unwrap_or_default();
    let (agents, source) = (Agents::default(), workstation.source(Access::Restricted));
    let read = keys::read(&agents, &source, &search, &Known::default()).unwrap();
    let keyless = Serial::try_from(KEYLESS_CARD).unwrap();
    assert_eq!(
        keyless_in(&read),
        std::slice::from_ref(&keyless),
        "{read:?}"
    );
    let known = Known {
        cards: cards_in(&read).clone(),
        keyless: BTreeSet::from([keyless]),
    };
    let walks = |mark: usize| {
        only_reads(&log)
            .iter()
            .skip(mark)
            .any(|command| command == "KEYINFO --list")
    };
    let mark = only_reads(&log).len();
    let again = keys::read_cards(&agents, &source, &known, &read.keyring).unwrap();
    assert_eq!(again, Cards::default());
    assert!(!walks(mark), "its slots are still empty");
    // The stand-in reads its exchange once, at its start with the agent's.
    let mark = only_reads(&log).len();
    assert_eq!(workstation.with_card(&slotted), log);
    keys::read_cards(&agents, &source, &known, &read.keyring).unwrap();
    assert!(walks(mark), "a key was put on it");
}

/// The cards a whole read found; a test whose read could not read them fails.
fn cards_in(read: &keys::Read) -> Vec<Card> {
    read.cards.clone().unwrap().cards
}

/// The cards a whole read found holding no key.
fn keyless_in(read: &keys::Read) -> Vec<Serial> {
    read.cards.clone().unwrap().keyless
}

/// What the core knows having read `cards` and found no card holding no key.
fn knowing(cards: &[Card]) -> Known {
    Known {
        cards: cards.to_vec(),
        keyless: BTreeSet::new(),
    }
}

/// The channel the reads handed off here answer on.
const CHANNEL: ConnectionId = ConnectionId(Seq(3));

/// A home whose agent starts the recorded-exchange stand-in, its cards read
/// once as the core reads them at first sight; and the deciding thread's end
/// of the channel a read handed off answers on.
struct AtDesk {
    workstation: Scratch,
    log: PathBuf,
    agents: Arc<Agents>,
    search: OsString,
    whole: keys::Read,
    messages: mpsc::Sender<Message>,
    answers: Receiver<Message>,
}

impl AtDesk {
    fn new(purpose: &str) -> AtDesk {
        let workstation = Scratch::new(purpose);
        let (fingerprint, grip) = workstation.key();
        workstation.on_card(&grip, FIRST_CARD);
        let log = workstation.with_card(&exchange(&grip, &fingerprint, "openpgp"));
        let search = std::env::var_os("PATH").unwrap_or_default();
        let agents = Arc::new(Agents::default());
        let source = workstation.source(Access::Restricted);
        let whole = keys::read(&agents, &source, &search, &Known::default()).unwrap();
        let (messages, answers) = mpsc::channel();
        AtDesk {
            workstation,
            log,
            agents,
            search,
            whole,
            messages,
            answers,
        }
    }

    fn capability() -> Name {
        Name::try_from("gpg").unwrap()
    }

    fn source(&self) -> Gnupg {
        self.workstation.source(Access::Restricted)
    }

    /// What the core knows once it has recorded the first read of the cards.
    fn known(&self) -> Known {
        knowing(&cards_in(&self.whole))
    }

    fn cards(&self, id: u64, known: Known, keyring: Keyring) -> Effect {
        Effect::Cards {
            connection: CHANNEL,
            id: ReadId(id),
            sources: vec![(AtDesk::capability(), self.source(), keyring)],
            known,
        }
    }

    fn read(&self, id: u64, known: Known) -> Effect {
        Effect::Read {
            connection: CHANNEL,
            id: ReadId(id),
            sources: vec![(AtDesk::capability(), self.source())],
            known,
        }
    }

    /// Hands `effect` off as the deciding thread does, and gives back what it
    /// answers, on the channel the effect named.
    fn hand_off(&self, effect: Effect) -> Told {
        start_read(
            effect,
            Arc::clone(&self.agents),
            self.search.clone(),
            self.messages.clone(),
        );
        match self.answers.recv_timeout(WAIT).unwrap() {
            Message::Input(Input::Channel { connection, told }) => {
                assert_eq!(connection, CHANNEL);
                told
            }
            other => panic!("not a read's answer: {other:?}"),
        }
    }

    fn mark(&self) -> usize {
        only_reads(&self.log).len()
    }

    /// What the card was sent since `mark`, but for the agent's own sessions.
    fn sent_since(&self, mark: usize) -> Vec<String> {
        only_reads(&self.log)
            .into_iter()
            .skip(mark)
            .filter(|command| !agents_own(command))
            .collect()
    }

    fn walks_since(&self, mark: usize) -> usize {
        self.sent_since(mark)
            .iter()
            .filter(|command| *command == "KEYINFO --list")
            .count()
    }
}

/// A read of the cards handed off to the agent's thread carries what the core
/// knows - the cards it has read and the keyring that ties their slots - so a
/// card it knows is read from its attributes alone, and an effect naming none
/// has the cards walked; each answer names the read it answers.
#[test]
fn a_read_of_the_cards_handed_off_is_read_on_what_the_core_knows_and_answered_by_its_identity() {
    let desk = AtDesk::new("relay-desk-cards");
    let mark = desk.mark();
    let told = desk.hand_off(desk.cards(1, desk.known(), desk.whole.keyring.clone()));
    let first = cards_in(&desk.whole)[..1].to_vec();
    assert_eq!(
        told,
        Told::Cards {
            id: ReadId(1),
            read: vec![(
                AtDesk::capability(),
                Ok(Cards {
                    cards: first,
                    keyless: Vec::new(),
                }),
            )],
        }
    );
    assert_eq!(
        desk.sent_since(mark),
        [
            "GETINFO card_list",
            "GETATTR SERIALNO",
            "GETATTR APPTYPE",
            "GETATTR EXTCAP",
            "GETATTR UIF",
            "GETATTR CHV-STATUS",
            "GETATTR KEY-FPR"
        ]
    );
    let mark = desk.mark();
    let told = desk.hand_off(desk.cards(2, Known::default(), desk.whole.keyring.clone()));
    let Told::Cards { id, .. } = told else {
        panic!("the answer to a read of the cards: {told:?}");
    };
    assert_eq!(id, ReadId(2));
    assert!(
        desk.walks_since(mark) > 0,
        "an effect naming no card the core knows has the cards walked"
    );
}

/// A whole read handed off carries what the core knows too: read on it, the
/// read adds no walk of the cards to the agent's own for the listing, where
/// read on nothing it walks them after the listing; each answer names the read
/// it answers.
#[test]
fn a_whole_read_handed_off_on_what_the_core_knows_adds_no_walk_to_the_listings_own() {
    let desk = AtDesk::new("relay-desk-read");
    let mark = desk.mark();
    let listed = desk.workstation.run(
        "gpg.exe",
        &[
            "--no-autostart",
            "--batch",
            "--with-colons",
            "--with-keygrip",
            "--fixed-list-mode",
            "--list-secret-keys",
        ],
    );
    assert!(listed.status.success(), "{listed:?}");
    let alone = desk.walks_since(mark);

    let mark = desk.mark();
    let told = desk.hand_off(desk.read(1, desk.known()));
    let Told::Read { id, read } = told else {
        panic!("the answer to a whole read: {told:?}");
    };
    assert_eq!(id, ReadId(1));
    let [(capability, Ok(found))] = read.as_slice() else {
        panic!("one source, read: {read:?}");
    };
    assert_eq!(*capability, AtDesk::capability());
    assert_eq!(found.keyring, desk.whole.keyring);
    assert_eq!(cards_in(found), cards_in(&desk.whole)[..1]);
    let walks = desk.walks_since(mark);
    assert!(
        walks <= alone,
        "{walks} walks where the listing alone has {alone}"
    );

    let mark = desk.mark();
    let told = desk.hand_off(desk.read(2, Known::default()));
    let Told::Read { id, .. } = told else {
        panic!("the answer to a whole read: {told:?}");
    };
    assert_eq!(id, ReadId(2));
    let walks = desk.walks_since(mark);
    assert!(
        walks > alone,
        "read on nothing, the read walks the cards after the listing: {walks}, {alone}"
    );
}

/// The serial number of the stand-in card of two applications, a `YubiKey`'s
/// as scdaemon writes it.
const PIN_CARD: &str = "D2760001240103040006111111110000";

/// A card of the suite's own holding two applications: its RSA key held by a
/// home whose agent signs for the stand-in scdaemon, and the workstation home
/// that holds the key's stub, whose pinentry counts the PINs asked.
struct TwoApplications {
    /// Kept for its agent, which signs for the stand-in.
    _card: Scratch,
    workstation: Scratch,
    fingerprint: Fingerprint,
    grip: Grip,
    state: PathBuf,
    card_log: PathBuf,
    pin_log: PathBuf,
}

impl TwoApplications {
    fn new() -> TwoApplications {
        let card = Scratch::new("relay-pin-card");
        let made = card.run(
            "gpg.exe",
            &[
                "--batch",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Card PIN <card-pin@example.invalid>",
                "rsa2048",
                "sign",
                "never",
            ],
        );
        assert!(made.status.success(), "{made:?}");
        let listed = card.run("gpg.exe", &["--with-colons", "--with-keygrip", "-K"]);
        let text = String::from_utf8(listed.stdout).unwrap();
        let field = |kind: &str| {
            text.lines()
                .find(|line| line.starts_with(kind))
                .and_then(|line| line.split(':').nth(9))
                .unwrap()
                .to_owned()
        };
        let fingerprint = Fingerprint::try_from(field("fpr:").as_str()).unwrap();
        let grip = Grip::try_from(field("grp:").as_str()).unwrap();
        card.launch();
        let public = card.path().join("public.asc");
        let exported = card.run(
            "gpg.exe",
            &[
                "--armor",
                "--output",
                &public.to_string_lossy(),
                "--export",
                fingerprint.as_str(),
            ],
        );
        assert!(exported.status.success(), "{exported:?}");
        let workstation = Scratch::new("relay-pin");
        let imported = workstation.run(
            "gpg.exe",
            &["--batch", "--import", &public.to_string_lossy()],
        );
        assert!(imported.status.success(), "{imported:?}");
        std::fs::write(
            workstation.path().join("gpg-agent.conf"),
            format!(
                "scdaemon-program {}\npinentry-program {}\n",
                env!("CARGO_BIN_EXE_scdaemon-pin"),
                env!("CARGO_BIN_EXE_pinentry")
            ),
        )
        .unwrap();
        let state = workstation.path().join("inserted.txt");
        std::fs::write(
            &state,
            format!(
                "{PIN_CARD} {fingerprint} {} {}",
                card.path().display(),
                card.dir("agent-socket").display()
            ),
        )
        .unwrap();
        let card_log = workstation.path().join("card.log");
        let pin_log = workstation.path().join("pinentry.log");
        let two = TwoApplications {
            _card: card,
            workstation,
            fingerprint,
            grip,
            state,
            card_log,
            pin_log,
        };
        two.start("openpgp piv", "yubikey");
        let learned = two.workstation.run(
            "gpg-connect-agent.exe",
            &["--no-autostart", "LEARN --sendinfo", "/bye"],
        );
        assert!(learned.status.success(), "{learned:?}");
        two
    }

    /// A fresh agent, so neither the stand-in nor the agent's PIN cache
    /// carries anything over: the card holding `apps`, scdaemon keeping a PIN
    /// in the agent's cache unless `cache` is `none`.
    fn start(&self, apps: &str, cache: &str) {
        let stopped = self
            .workstation
            .run("gpgconf.exe", &["--kill", "gpg-agent"]);
        assert!(stopped.status.success(), "{stopped:?}");
        let launched = Command::new(tool("gpgconf.exe"))
            .arg("--homedir")
            .arg(self.workstation.path())
            .args(["--launch", "gpg-agent"])
            .env("HEDWIG_CARD_STATE", &self.state)
            .env("HEDWIG_CARD_APPS", apps)
            .env("HEDWIG_CARD_CACHE", cache)
            .env("HEDWIG_CARD_LOG", &self.card_log)
            .env("HEDWIG_PINENTRY_LOG", &self.pin_log)
            .output()
            .unwrap();
        assert!(launched.status.success(), "{launched:?}");
    }

    fn keyring(&self) -> Keyring {
        Keyring {
            keys: vec![hedwig_model::trail::Key {
                grip: self.grip.clone(),
                fingerprint: self.fingerprint.clone(),
                primary: self.fingerprint.clone(),
                uses: Uses::SIGN,
                user: None,
                card: Some(Serial::try_from(PIN_CARD).unwrap()),
                ssh: None,
            }],
            signing: None,
        }
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Three signatures in a row from a fresh agent, the cards read after each
    /// as the core reads them after a use where `read` says so: on the cards
    /// read before where it is `Some(true)`, as cards never read where it is
    /// `Some(false)`. The PINs the person was asked, and what each read
    /// selected.
    fn three(&self, apps: &str, cache: &str, read: Option<bool>) -> (usize, Vec<usize>) {
        self.start(apps, cache);
        let asked = Self::lines(&self.pin_log).len();
        let source = self.workstation.source(Access::Unrestricted);
        let agents = Agents::default();
        let mut known = Known::default();
        let mut selected = Vec::new();
        for n in 1..=3 {
            let text = self.workstation.path().join(format!("signed-{n}.txt"));
            std::fs::write(&text, format!("signature {n}")).unwrap();
            let signature = format!("{}.sig", text.display());
            let signed = self.workstation.run(
                "gpg.exe",
                &[
                    "--batch",
                    "--yes",
                    "-bsau",
                    self.fingerprint.as_str(),
                    "--output",
                    &signature,
                    &text.to_string_lossy(),
                ],
            );
            assert!(signed.status.success(), "{signed:?}");
            if let Some(on_known) = read {
                let mark = Self::lines(&self.card_log).len();
                let cards = keys::read_cards(&agents, &source, &known, &self.keyring()).unwrap();
                if on_known {
                    for card in cards.cards {
                        known.cards.retain(|was| was.serial != card.serial);
                        known.cards.push(card);
                    }
                    known.keyless.extend(cards.keyless);
                }
                let selections = Self::lines(&self.card_log)
                    .iter()
                    .skip(mark)
                    .filter(|line| line.starts_with("# selected"))
                    .count();
                selected.push(selections);
            }
        }
        let prompts = Self::lines(&self.pin_log)
            .iter()
            .skip(asked)
            .filter(|line| line.starts_with("GETPIN"))
            .count();
        (prompts, selected)
    }
}

/// A card of two applications forgets its verified PIN whenever an
/// application is selected, and the agent selects them itself before every
/// signature. So the PINs asked across consecutive signatures are what the
/// agent's own lookups cost - one where scdaemon keeps the PIN in the agent's
/// cache, one each where it keeps none - and the core's card read after each
/// changes neither: walked, it selects every application; on the cards it
/// knows, nothing.
#[test]
fn the_card_read_after_each_signature_asks_no_pin_and_selects_nothing_once_known() {
    let two = TwoApplications::new();
    for (cache, each) in [("yubikey", 1), ("none", 3)] {
        let (alone, _) = two.three("openpgp piv", cache, None);
        assert_eq!(alone, each, "{cache}: the agent's own signatures");
        let (walked, walks) = two.three("openpgp piv", cache, Some(false));
        assert_eq!(walked, alone, "{cache}: a walk after each");
        assert!(
            walks.iter().all(|selections| *selections > 0),
            "{cache}: {walks:?}"
        );
        let (known, reads) = two.three("openpgp piv", cache, Some(true));
        assert_eq!(
            known, alone,
            "{cache}: a read on the cards known after each"
        );
        assert_eq!(
            reads.get(1..),
            Some([0, 0].as_slice()),
            "{cache}: {reads:?}"
        );
    }
    let (single, walks) = two.three("openpgp", "none", Some(false));
    assert_eq!(single, 1, "a card of one application keeps its PIN");
    assert!(walks.iter().all(|selections| *selections == 0), "{walks:?}");
}
