//! The relay of an `ssh-agent` capability, run for real: `GnuPG` 2.5.24's own
//! agent on homes of the suite's, reached at its SSH socket and at a pipe of
//! its own, and the in-box OpenSSH client's `ssh-add` and `ssh-keygen` as the
//! remote's tools, reaching the relay through a pipe the suite serves as the
//! channel's forward would carry them. The suite plays the deciding thread.
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

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hedwig_core::agent::{self, Ask};
use hedwig_core::relay::{Relayed, Settle};
use hedwig_core::ssh::{SshAgent, carry, keys, request};
use hedwig_model::capability::{AgentAt, Home, Installation, Lends, LentKey, Operation, Toward};
use hedwig_model::holder::Whose;
use hedwig_model::refusal::{Refusal, Whereabouts, Withheld};
use hedwig_model::text::{AgentPipe, Folder as Place, SshKey, Words};
use hedwig_model::trail::{Failure, Payload};
use hedwig_support::{Folder, readerless};
use hedwig_win::Signal;
use hedwig_win::pipe::{Listener, Moved, Pipe};
use hedwig_win::token::Token;

const WAIT: Duration = Duration::from_secs(30);
const SSH_ADD: &str = r"C:\Windows\System32\OpenSSH\ssh-add.exe";
const SSH_KEYGEN: &str = r"C:\Windows\System32\OpenSSH\ssh-keygen.exe";

fn installation() -> PathBuf {
    let folder = std::env::var_os("HEDWIG_GNUPG")
        .map(PathBuf::from)
        .expect("HEDWIG_GNUPG names GnuPG's Windows build: run scripts\\fetch-test-tools.ps1");
    assert!(folder.join("bin").join("gpgconf.exe").is_file());
    folder
}

fn tool(name: &str) -> PathBuf {
    installation().join("bin").join(name)
}

static NEXT: AtomicU32 = AtomicU32::new(0);

fn unique(purpose: &str) -> String {
    format!(
        "hedwig-test-{purpose}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

/// A `GnuPG` home of the suite's own, whose scdaemon opens no reader, holding
/// two keys usable for SSH, each with no passphrase. Its agent logs what it
/// is asked; it is stopped when the home is dropped.
struct Scratch {
    folder: Folder,
}

impl Scratch {
    fn new(purpose: &str, pipe: Option<&str>) -> Scratch {
        let folder = Folder::new(purpose);
        readerless(folder.path()).unwrap();
        let mut conf = format!(
            "log-file {}\nverbose\n",
            folder.path().join("agent.log").display()
        );
        if let Some(pipe) = pipe {
            conf = format!("{conf}enable-win32-openssh-support \\\\.\\pipe\\{pipe}\n");
        }
        std::fs::write(folder.path().join("gpg-agent.conf"), conf).unwrap();
        let scratch = Scratch { folder };
        for who in ["One <one@example.invalid>", "Two <two@example.invalid>"] {
            let made = scratch.run(
                "gpg.exe",
                &[
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-generate-key",
                    who,
                    "ed25519",
                    "sign,auth",
                    "never",
                ],
            );
            assert!(made.status.success(), "{made:?}");
        }
        let listed = scratch.run(
            "gpg.exe",
            &[
                "--batch",
                "--with-colons",
                "--with-keygrip",
                "--list-secret-keys",
            ],
        );
        let grips: Vec<String> = String::from_utf8(listed.stdout)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("grp:"))
            .map(|line| line.split(':').nth(9).unwrap().to_owned())
            .collect();
        assert_eq!(grips.len(), 2);
        std::fs::write(scratch.path().join("sshcontrol"), grips.join("\n") + "\n").unwrap();
        scratch
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

    fn at(&self) -> AgentAt {
        AgentAt::Gnupg {
            installation: Installation::At(
                Place::try_from(installation().to_string_lossy().as_ref()).unwrap(),
            ),
            home: Home::At(Place::try_from(self.path().to_string_lossy().as_ref()).unwrap()),
        }
    }

    /// How many signatures the agent was asked for.
    fn signed(&self) -> usize {
        std::fs::read_to_string(self.path().join("agent.log"))
            .unwrap_or_default()
            .matches("ssh request handler for sign_request (13) started")
            .count()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Never through `installation`, which panics where GnuPG is not
        // named: a panic while a test unwinds aborts the whole suite.
        if let Some(folder) = std::env::var_os("HEDWIG_GNUPG") {
            let _ = Command::new(PathBuf::from(folder).join("bin").join("gpgconf.exe"))
                .arg("--homedir")
                .arg(self.path())
                .args(["--kill", "all"])
                .output();
        }
    }
}

/// The two keys the scratch agent holds, as it lists them.
fn held(scratch: &Scratch) -> (SshKey, SshKey) {
    let reached = keys(&scratch.at());
    let listed = reached.result.unwrap();
    let holder = reached
        .holder
        .expect("what listens at the socket's port is read");
    assert!(
        matches!(holder.whose, Whose::Person { .. })
            && holder.program.as_str().ends_with("gpg-agent.exe"),
        "{holder:?}"
    );
    assert_eq!(listed.len(), 2, "{listed:?}");
    (listed[0].key.clone(), listed[1].key.clone())
}

fn lending(keys: &[&SshKey]) -> Lends {
    Lends::of_keys(
        keys.iter()
            .map(|key| ((*key).clone(), Toward::Anywhere.into())),
    )
}

/// What the suite, as the deciding thread, answers a signature.
type Answer = Arc<Mutex<Result<(), Refusal>>>;

/// A relay on a loopback port carrying every connection to `at` with
/// `lends`, each signature answered with what `answer` holds then. Everything
/// a connection told the deciding thread is sent on.
fn relay(at: AgentAt, lends: Lends, answer: Answer) -> (u16, Receiver<Relayed>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen, told) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let (relayed, heard) = mpsc::channel();
            let settle: Arc<Settle> = carry(
                stream,
                SshAgent {
                    at: at.clone(),
                    lends: lends.clone(),
                },
                move |said| {
                    let _ = relayed.send(said);
                },
            );
            let (seen, answer) = (seen.clone(), Arc::clone(&answer));
            std::thread::spawn(move || {
                while let Ok(said) = heard.recv_timeout(WAIT) {
                    let verdict = match &said {
                        Relayed::Reached(Ok(())) => Some(Ok(())),
                        Relayed::Reached(Err(_)) => Some(Err(Refusal::Paused)),
                        Relayed::Signs(_) => Some(answer.lock().unwrap().clone()),
                        _ => None,
                    };
                    let ended = said == Relayed::Ended;
                    let _ = seen.send(said);
                    if let Some(verdict) = verdict {
                        settle.settle(verdict);
                    }
                    if ended {
                        break;
                    }
                }
            });
        }
    });
    (port, told)
}

fn served() -> Answer {
    Arc::new(Mutex::new(Ok(())))
}

/// A named pipe the in-box client opens as `SSH_AUTH_SOCK`, each client of it
/// spliced to the relay's port as the channel's forward carries a remote's
/// connection. Stops when dropped.
struct Bridge {
    name: String,
    stop: Arc<Signal>,
}

impl Bridge {
    fn new(port: u16) -> Bridge {
        let name = unique("bridge");
        let path = format!(r"\\.\pipe\{name}");
        let owner = Token::own().unwrap().user().unwrap();
        let (listener, first) = Listener::bind(&path, &owner).unwrap();
        let stop = Arc::new(Signal::new().unwrap());
        let stopping = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut instance = first;
            loop {
                match instance.accept(&stopping) {
                    Ok(Moved::Stopped) | Err(_) => return,
                    Ok(_) => {}
                }
                let Ok(next) = listener.another() else { return };
                splice(std::mem::replace(&mut instance, next), port);
            }
        });
        Bridge { name, stop }
    }

    fn path(&self) -> String {
        format!(r"\\.\pipe\{}", self.name)
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.stop.raise();
    }
}

fn splice(pipe: Pipe, port: u16) {
    let pipe = Arc::new(pipe);
    let Ok(tcp) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)) else {
        return;
    };
    let (mut to_relay, mut from_relay) = (tcp.try_clone().unwrap(), tcp);
    let reading = Arc::clone(&pipe);
    std::thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        while let Ok(Moved::Bytes(read)) = reading.read(&mut buffer, None) {
            if read == 0 || to_relay.write_all(&buffer[..read]).is_err() {
                break;
            }
        }
        let _ = to_relay.shutdown(std::net::Shutdown::Write);
    });
    std::thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        while let Ok(read) = from_relay.read(&mut buffer) {
            if read == 0 || !matches!(pipe.write(&buffer[..read], None), Ok(Moved::Bytes(_))) {
                break;
            }
        }
    });
}

fn in_box(program: &str, bridge: &Bridge, arguments: &[&str]) -> Output {
    Command::new(program)
        .env("SSH_AUTH_SOCK", bridge.path())
        .args(arguments)
        .output()
        .unwrap()
}

fn said(told: &Receiver<Relayed>) -> Vec<Relayed> {
    let mut all = Vec::new();
    while let Ok(next) = told.recv_timeout(Duration::from_millis(500)) {
        all.push(next);
    }
    all
}

fn public(key: &SshKey, at: &Path) -> PathBuf {
    std::fs::write(at, format!("{key}\n")).unwrap();
    at.to_path_buf()
}

/// A remote's `ssh-add` is told the keys its grant lends and no other; under
/// a grant of every key, every key the agent holds. The agent's own list is
/// read once for a grant surface, from its socket and from its pipe alike.
#[test]
fn a_remote_is_told_only_the_keys_its_grant_lends() {
    let pipe = unique("gpg-pipe");
    let scratch = Scratch::new("ssh-list", Some(&pipe));
    let (one, two) = held(&scratch);
    let reached = keys(&AgentAt::Pipe(AgentPipe::try_from(pipe.as_str()).unwrap()));
    let (by_pipe, by) = (reached.result.unwrap(), reached.holder);
    assert_eq!(
        by_pipe
            .iter()
            .map(|held| held.key.clone())
            .collect::<Vec<_>>(),
        vec![one.clone(), two.clone()]
    );
    let by = by.expect("the pipe's server is named");
    assert!(by.program.as_str().ends_with("gpg-agent.exe"), "{by:?}");
    assert!(matches!(by.whose, Whose::Person { .. }), "{by:?}");

    let (port, _told) = relay(scratch.at(), lending(&[&one]), served());
    let bridge = Bridge::new(port);
    let listed = in_box(SSH_ADD, &bridge, &["-L"]);
    assert!(listed.status.success(), "{listed:?}");
    assert_eq!(
        String::from_utf8(listed.stdout).unwrap().trim(),
        format!("{one}")
    );

    // Lent with the comment the agent's list gave it, the key is listed to
    // the remote by that comment, as the agent itself would list it.
    let comment = by_pipe[0]
        .comment
        .clone()
        .unwrap_or_else(|| Words::try_from("laptop").unwrap());
    let commented = Lends::of_keys([(
        one.clone(),
        LentKey {
            toward: Toward::Anywhere,
            comment: Some(comment.clone()),
        },
    )]);
    let (port, _told) = relay(scratch.at(), commented, served());
    let bridge = Bridge::new(port);
    let listed = in_box(SSH_ADD, &bridge, &["-L"]);
    assert_eq!(
        String::from_utf8(listed.stdout).unwrap().trim(),
        format!("{one} {comment}")
    );

    let (port, _told) = relay(scratch.at(), Lends::Every, served());
    let bridge = Bridge::new(port);
    let listed = String::from_utf8(in_box(SSH_ADD, &bridge, &["-L"]).stdout).unwrap();
    assert!(
        listed.contains(&one.to_string()) && listed.contains(&two.to_string()),
        "{listed}"
    );

    let (port, _told) = relay(scratch.at(), Lends::none(), served());
    let bridge = Bridge::new(port);
    let none = in_box(SSH_ADD, &bridge, &["-L"]);
    assert_eq!(
        String::from_utf8(none.stdout).unwrap().trim(),
        "The agent has no identities."
    );
}

/// The in-box `ssh-keygen -Y sign`, as `git` runs it for an SSH-signed
/// commit, signs through the relay: the request is held as a signature in
/// the `git` namespace, served, and the signature verifies. Refused, nothing
/// is signed and the agent is never asked.
#[test]
fn a_commit_signature_is_held_as_one_and_signed_once_served() {
    let scratch = Scratch::new("ssh-sign", None);
    let (one, _) = held(&scratch);
    let answer = served();
    let (port, told) = relay(scratch.at(), lending(&[&one]), Arc::clone(&answer));
    let bridge = Bridge::new(port);
    let key = public(&one, &scratch.path().join("one.pub"));
    let message = scratch.path().join("commit");
    std::fs::write(&message, "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n").unwrap();
    let signed = in_box(
        SSH_KEYGEN,
        &bridge,
        &[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            key.to_str().unwrap(),
            message.to_str().unwrap(),
        ],
    );
    assert!(signed.status.success(), "{signed:?}");
    let asked: Vec<Ask> = said(&told)
        .into_iter()
        .filter_map(|said| match said {
            Relayed::Signs(ask) => Some(ask),
            _ => None,
        })
        .collect();
    assert_eq!(
        asked,
        vec![Ask {
            operation: Operation::Sign,
            key: one.clone(),
            payload: Payload::Signature {
                namespace: Some(Words::try_from("git").unwrap()),
            },
        }]
    );
    let allowed = scratch.path().join("allowed");
    std::fs::write(&allowed, format!("one@example.invalid {one}\n")).unwrap();
    let verified = Command::new(SSH_KEYGEN)
        .args([
            "-Y",
            "verify",
            "-n",
            "git",
            "-I",
            "one@example.invalid",
            "-f",
        ])
        .arg(&allowed)
        .arg("-s")
        .arg(message.with_extension("sig"))
        .stdin(std::fs::File::open(&message).unwrap())
        .output()
        .unwrap();
    assert!(verified.status.success(), "{verified:?}");
    assert_eq!(scratch.signed(), 1);

    *answer.lock().unwrap() = Err(Refusal::NobodyReachable(Whereabouts::Away));
    std::fs::remove_file(message.with_extension("sig")).unwrap();
    let refused = in_box(
        SSH_KEYGEN,
        &bridge,
        &[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            key.to_str().unwrap(),
            message.to_str().unwrap(),
        ],
    );
    assert!(!refused.status.success(), "{refused:?}");
    assert!(!message.with_extension("sig").exists());
    assert_eq!(scratch.signed(), 1, "the agent was not asked");
}

/// A key the grant does not lend is refused at the relay, and the agent never
/// sees the request; nor does it see a remote's attempt to remove its keys or
/// lock it, after which it holds what it held.
#[test]
fn what_is_not_lent_and_what_would_change_the_agent_never_reach_it() {
    let scratch = Scratch::new("ssh-unlent", None);
    let (one, two) = held(&scratch);
    let (port, told) = relay(scratch.at(), lending(&[&one]), served());
    let bridge = Bridge::new(port);
    let key = public(&two, &scratch.path().join("two.pub"));
    let message = scratch.path().join("commit");
    std::fs::write(&message, "unlent\n").unwrap();
    let refused = in_box(
        SSH_KEYGEN,
        &bridge,
        &[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            key.to_str().unwrap(),
            message.to_str().unwrap(),
        ],
    );
    assert!(!refused.status.success(), "{refused:?}");
    let one_key = public(&one, &scratch.path().join("one.pub"));
    for managing in [&["-D"][..], &["-d", one_key.to_str().unwrap()][..]] {
        let tried = Command::new(SSH_ADD)
            .env("SSH_AUTH_SOCK", bridge.path())
            .args(managing)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(!tried.status.success(), "{managing:?}: {tried:?}");
    }
    // The in-box client asks to sign only with a key the agent listed, so a
    // remote's own tool never even asks for one not lent; asked for it all
    // the same, the relay refuses it.
    let mut asking = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    asking.set_read_timeout(Some(WAIT)).unwrap();
    let mut body = vec![13];
    for field in [two.blob().as_slice(), b"data"] {
        body.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        body.extend_from_slice(field);
    }
    body.extend_from_slice(&[0; 4]);
    let mut framed = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&body);
    asking.write_all(&framed).unwrap();
    let mut answer = [0u8; 5];
    asking.read_exact(&mut answer).unwrap();
    assert_eq!(answer, agent::FAILURE);
    drop(asking);
    let withheld: Vec<Withheld> = said(&told)
        .into_iter()
        .filter_map(|said| match said {
            Relayed::Withheld(withheld) => Some(withheld),
            Relayed::Signs(ask) => panic!("nothing unlent is held: {ask:?}"),
            _ => None,
        })
        .collect();
    assert!(withheld.contains(&Withheld::KeyUnlent(two)), "{withheld:?}");
    assert!(withheld.contains(&Withheld::Managing), "{withheld:?}");
    assert_eq!(scratch.signed(), 0);
    assert_eq!(
        keys(&scratch.at()).result.unwrap().len(),
        2,
        "the agent holds both keys still"
    );
}

/// A remote that keeps its connection open holds nothing of the agent's:
/// another connection signs meanwhile, and so does the first, afterwards.
#[test]
fn a_connection_held_open_holds_nothing_of_the_agent() {
    let pipe = unique("gpg-held");
    let scratch = Scratch::new("ssh-held", Some(&pipe));
    let (one, _) = held(&scratch);
    let data = {
        let mut data = b"SSHSIG".to_vec();
        for field in [&b"git"[..], b"", b"sha512", &[3; 64]] {
            data.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            data.extend_from_slice(field);
        }
        data
    };
    let sign = {
        let mut body = vec![13];
        for field in [one.blob().as_slice(), data.as_slice()] {
            body.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            body.extend_from_slice(field);
        }
        body.extend_from_slice(&[0; 4]);
        let mut framed = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        framed
    };
    let answered = |stream: &mut TcpStream| {
        stream.write_all(&sign).unwrap();
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).unwrap();
        let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(length)).unwrap()];
        stream.read_exact(&mut body).unwrap();
        body[0]
    };
    // gpg-agent's pipe serves one connection at a time; through Hedwig the
    // remote never holds it.
    let at = AgentAt::Pipe(AgentPipe::try_from(pipe.as_str()).unwrap());

    let (port, _told) = relay(at, lending(&[&one]), served());
    let mut first = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    first.set_read_timeout(Some(WAIT)).unwrap();
    first.write_all(&[0, 0, 0, 1, 11]).unwrap();
    let mut listed = [0u8; 4];
    first.read_exact(&mut listed).unwrap();
    let mut rest = vec![0u8; usize::try_from(u32::from_be_bytes(listed)).unwrap()];
    first.read_exact(&mut rest).unwrap();
    let mut second = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    second.set_read_timeout(Some(WAIT)).unwrap();
    assert_eq!(
        answered(&mut second),
        14,
        "signed while the first is held open"
    );
    assert_eq!(answered(&mut first), 14);
    assert_eq!(answered(&mut second), 14);
    drop((first, second));
    // The person's own client still reaches the agent's pipe afterwards.
    let theirs = Command::new(SSH_ADD)
        .env("SSH_AUTH_SOCK", format!(r"\\.\pipe\{pipe}"))
        .arg("-l")
        .output()
        .unwrap();
    assert!(theirs.status.success(), "{theirs:?}");
}

/// A stand-in agent behind a socket file of `form` in the place `gpgconf`
/// names for a home of the suite's: it ends its first `silent` connections
/// having read the file's bytes and nothing more, as gpg-agent's handler does
/// when no byte is waiting, and answers each later request with an empty
/// list. Returns the number of connections it took.
fn stand_in(form: &str, silent: usize) -> (Scratch, Arc<AtomicU32>) {
    let scratch = Scratch::new("ssh-stand-in", None);
    let _ = scratch.run("gpgconf.exe", &["--kill", "gpg-agent"]);
    let printed = scratch.run("gpgconf.exe", &["--list-dirs"]);
    let socket = PathBuf::from(
        String::from_utf8(hedwig_core::relay::listed(&printed.stdout, "agent-ssh-socket").unwrap())
            .unwrap(),
    );
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let nonce: [u8; 16] = *b"0123456789abcdef";
    let cygwin = form == "cygwin";
    let file = if cygwin {
        let groups: Vec<String> = nonce
            .chunks(4)
            .map(|group| format!("{:08x}", u32::from_le_bytes(group.try_into().unwrap())))
            .collect();
        format!("!<socket >{port} s {}\0", groups.join("-")).into_bytes()
    } else {
        let mut file = format!(
            "{port}
"
        )
        .into_bytes();
        file.extend_from_slice(&nonce);
        file
    };
    std::fs::write(&socket, file).unwrap();
    let taken = Arc::new(AtomicU32::new(0));
    let counting = Arc::clone(&taken);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let number = counting.fetch_add(1, Ordering::SeqCst);
            let mut presented = [0u8; 16];
            stream.read_exact(&mut presented).unwrap();
            assert_eq!(presented, nonce);
            if usize::try_from(number).unwrap() < silent {
                continue;
            }
            if cygwin {
                stream.write_all(&presented).unwrap();
                let mut credentials = [0u8; 8];
                stream.read_exact(&mut credentials).unwrap();
                stream.write_all(&[1, 2, 3, 4, 0, 0, 0, 0]).unwrap();
            }
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(length)).unwrap()];
            stream.read_exact(&mut body).unwrap();
            stream.write_all(&agent::identities([])).unwrap();
        }
    });
    (scratch, taken)
}

/// A request to gpg-agent's socket goes with the file's bytes in one write,
/// is asked again where the agent ended the connection having read nothing,
/// and goes after Cygwin's handshake where the file is in Cygwin's form.
#[test]
fn gpg_agent_s_socket_is_asked_again_when_it_read_nothing_and_in_either_form() {
    const LIST: [u8; 5] = [0, 0, 0, 1, 11];
    for form in ["native", "cygwin"] {
        let (scratch, taken) = stand_in(form, 2);
        let answer = request(&scratch.at(), &LIST).result.unwrap();
        assert_eq!(answer, agent::identities([]), "{form}");
        assert_eq!(taken.load(Ordering::SeqCst), 3, "{form}");
        let (scratch, taken) = stand_in(form, 3);
        assert_eq!(
            request(&scratch.at(), &LIST).result,
            Err(Failure::Mismatched),
            "{form}"
        );
        assert_eq!(taken.load(Ordering::SeqCst), 3, "{form}");
        drop(scratch);
    }
}

/// A server that closes each instance before it makes the next, as
/// gpg-agent's Win32-OpenSSH thread does, leaves a moment in which its pipe's
/// name does not exist; a client arriving then reaches the next instance and
/// is not told the agent is absent.
#[test]
fn a_client_arriving_between_a_servers_instances_reaches_the_next() {
    let name = unique("between");
    let path = format!(r"\\.\pipe\{name}");
    let person = Token::own().unwrap().user().unwrap();
    let (listener, first) = Listener::bind(&path, &person).unwrap();
    let (closed, gap) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let stop = Signal::new().unwrap();
        first.accept(&stop).unwrap();
        drop(first);
        closed.send(()).unwrap();
        // The next instance is made well after the client has tried.
        std::thread::sleep(Duration::from_millis(20));
        let next = listener.another().unwrap();
        next.accept(&stop).unwrap();
    });
    let held = hedwig_win::pipe::open_unwaited(&path, WAIT).unwrap();
    gap.recv().unwrap();
    drop(held);
    assert!(
        hedwig_win::pipe::open_unwaited(&path, WAIT).is_ok(),
        "the next instance is reached"
    );
    server.join().unwrap();
}

/// A pipe nobody serves is unreachable, and an opening to it is refused
/// saying so.
#[test]
fn an_agent_nobody_serves_is_unreachable() {
    let at = AgentAt::Pipe(AgentPipe::try_from(unique("nobody").as_str()).unwrap());
    assert_eq!(keys(&at).result, Err(Failure::Unreachable));
    let (port, told) = relay(at, Lends::Every, served());
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    let mut nothing = Vec::new();
    let _ = stream.read_to_end(&mut nothing);
    assert_eq!(nothing, Vec::<u8>::new());
    assert!(said(&told).contains(&Relayed::Reached(Err(Failure::Unreachable))));
}

/// A key of the run's own in the TPM, deleted when dropped.
struct MachineKey {
    name: hedwig_model::text::Name,
    key: SshKey,
}

impl MachineKey {
    fn make(what: &str, kind: hedwig_model::capability::KeyKind) -> MachineKey {
        let name = hedwig_model::text::Name::try_from(
            format!("hedwig-test-support-{}-{what}", std::process::id()).as_str(),
        )
        .unwrap();
        let made = match hedwig_core::machine::make(&name, kind) {
            Err(Refusal::NoTpm) => panic!("needs a TPM that makes ECDSA P-256 and RSA 2048 keys"),
            made => made.expect("made in this TPM"),
        };
        MachineKey {
            name,
            key: made.key,
        }
    }
}

impl Drop for MachineKey {
    fn drop(&mut self) {
        let _ = hedwig_core::machine::delete(&self.name, &self.key);
    }
}

/// A key the workstation's TPM holds, served by the core itself: the in-box
/// `ssh-add` is told the keys the grant lends, or under a grant of every key
/// each key Hedwig made with its name; the in-box `ssh-keygen -Y sign`, as
/// `git` runs it, is held as a signature in the `git` namespace, served, and
/// OpenSSH verifies what an ECDSA key and an RSA key signed. Refused, nothing
/// is signed.
#[test]
#[ignore = "needs a TPM that makes ECDSA P-256 and RSA 2048 keys"]
#[allow(
    clippy::too_many_lines,
    reason = "one scene, both kinds and both answers"
)]
fn a_key_the_tpm_holds_is_offered_and_signs_a_commit_through_the_relay() {
    use hedwig_model::capability::KeyKind;
    let folder = Folder::new("machine-sign");
    let p256 = MachineKey::make("p256", KeyKind::EcdsaP256);
    let rsa = MachineKey::make("rsa", KeyKind::Rsa2048);
    let answer = served();
    let (port, told) = relay(
        AgentAt::Machine,
        lending(&[&p256.key, &rsa.key]),
        Arc::clone(&answer),
    );
    let bridge = Bridge::new(port);
    let listed = in_box(SSH_ADD, &bridge, &["-L"]);
    assert!(listed.status.success(), "{listed:?}");
    let lines: Vec<String> = String::from_utf8(listed.stdout)
        .unwrap()
        .lines()
        .map(|line| line.trim().to_owned())
        .collect();
    assert_eq!(
        lines,
        [
            std::cmp::min(&p256.key, &rsa.key).to_string(),
            std::cmp::max(&p256.key, &rsa.key).to_string()
        ]
    );

    let message = folder.path().join("commit");
    for (made, signer) in [
        (&p256, "one@example.invalid"),
        (&rsa, "two@example.invalid"),
    ] {
        std::fs::write(&message, "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n").unwrap();
        let _ = std::fs::remove_file(message.with_extension("sig"));
        let key = public(&made.key, &folder.path().join(format!("{signer}.pub")));
        let signed = in_box(
            SSH_KEYGEN,
            &bridge,
            &[
                "-Y",
                "sign",
                "-n",
                "git",
                "-f",
                key.to_str().unwrap(),
                message.to_str().unwrap(),
            ],
        );
        assert!(signed.status.success(), "{signed:?}");
        let asked: Vec<Ask> = said(&told)
            .into_iter()
            .filter_map(|said| match said {
                Relayed::Signs(ask) => Some(ask),
                _ => None,
            })
            .collect();
        assert_eq!(
            asked,
            vec![Ask {
                operation: Operation::Sign,
                key: made.key.clone(),
                payload: Payload::Signature {
                    namespace: Some(Words::try_from("git").unwrap()),
                },
            }]
        );
        let allowed = folder.path().join("allowed");
        std::fs::write(&allowed, format!("{signer} {}\n", made.key)).unwrap();
        let verified = Command::new(SSH_KEYGEN)
            .args(["-Y", "verify", "-n", "git", "-I", signer, "-f"])
            .arg(&allowed)
            .arg("-s")
            .arg(message.with_extension("sig"))
            .stdin(std::fs::File::open(&message).unwrap())
            .output()
            .unwrap();
        assert!(verified.status.success(), "{verified:?}");
        assert!(
            String::from_utf8_lossy(&verified.stdout).contains("Good \"git\" signature"),
            "{verified:?}"
        );
    }

    *answer.lock().unwrap() = Err(Refusal::NobodyReachable(Whereabouts::Away));
    std::fs::remove_file(message.with_extension("sig")).unwrap();
    let key = public(&p256.key, &folder.path().join("refused.pub"));
    let refused = in_box(
        SSH_KEYGEN,
        &bridge,
        &[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            key.to_str().unwrap(),
            message.to_str().unwrap(),
        ],
    );
    assert!(!refused.status.success(), "{refused:?}");
    assert!(!message.with_extension("sig").exists());

    let (port, _told) = relay(AgentAt::Machine, Lends::Every, served());
    let bridge = Bridge::new(port);
    let every = String::from_utf8(in_box(SSH_ADD, &bridge, &["-L"]).stdout).unwrap();
    for made in [&p256, &rsa] {
        assert!(
            every.contains(&format!("{} {}", made.key, made.name)),
            "{every}"
        );
    }
}

/// Each key `gpg` offers from a home carries the public half
/// gpg-agent's own SSH socket lists it by - Ed25519, NIST P-256 and RSA
/// alike - read with `READKEY --format=ssh`; an encryption subkey, which SSH
/// has no form for, carries none. The agent's SSH list and the keyring name
/// the same keys.
#[test]
fn each_key_gpg_offers_carries_the_ssh_key_the_agent_lists_it_by() {
    use hedwig_core::relay::{Agents, Gnupg};
    use hedwig_model::capability::Access;
    let scratch = Scratch::new("ssh-named-once", None);
    for (who, algorithm) in [
        ("Three <three@example.invalid>", "nistp256"),
        ("Four <four@example.invalid>", "rsa2048"),
    ] {
        let made = scratch.run(
            "gpg.exe",
            &[
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                who,
                algorithm,
                "sign,auth",
                "never",
            ],
        );
        assert!(made.status.success(), "{made:?}");
    }
    let listed = scratch.run(
        "gpg.exe",
        &[
            "--batch",
            "--with-colons",
            "--list-secret-keys",
            "one@example.invalid",
        ],
    );
    let one = String::from_utf8(listed.stdout)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .map(|line| line.split(':').nth(9).unwrap().to_owned())
        .unwrap();
    let added = scratch.run(
        "gpg.exe",
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-add-key",
            &one,
            "cv25519",
            "encr",
            "never",
        ],
    );
    assert!(added.status.success(), "{added:?}");
    let grips = scratch.run(
        "gpg.exe",
        &[
            "--batch",
            "--with-colons",
            "--with-keygrip",
            "--list-secret-keys",
        ],
    );
    let grips: Vec<String> = String::from_utf8(grips.stdout)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("grp:"))
        .map(|line| line.split(':').nth(9).unwrap().to_owned())
        .collect();
    assert_eq!(grips.len(), 5, "four keys and one subkey");
    std::fs::write(scratch.path().join("sshcontrol"), grips.join("\n") + "\n").unwrap();

    let by_agent = keys(&scratch.at()).result.unwrap();
    let source = Gnupg {
        installation: Installation::At(
            Place::try_from(installation().to_string_lossy().as_ref()).unwrap(),
        ),
        home: Home::At(Place::try_from(scratch.path().to_string_lossy().as_ref()).unwrap()),
        access: Access::Restricted,
    };
    let search = std::env::var_os("PATH").unwrap_or_default();
    let read = hedwig_core::keys::read(&Agents::default(), &source, &search).unwrap();
    assert_eq!(read.keyring.keys.len(), 5, "{:?}", read.keyring);
    let forms: Vec<SshKey> = read
        .keyring
        .keys
        .iter()
        .filter_map(|key| key.ssh.clone())
        .collect();
    let kinds: Vec<&str> = forms.iter().map(SshKey::kind).collect();
    for kind in ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"] {
        assert!(kinds.contains(&kind), "{kinds:?}");
    }
    assert_eq!(forms.len(), 4, "the encryption subkey has none");
    let mut listed: Vec<SshKey> = by_agent.into_iter().map(|held| held.key).collect();
    let mut offered = forms;
    listed.sort();
    offered.sort();
    assert_eq!(offered, listed);
}
