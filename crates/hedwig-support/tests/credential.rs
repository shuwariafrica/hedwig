//! The credential relay with real processes on both sides: Git for Windows'
//! own `git` plays the remote's, its `cache` helper connecting to a
//! Unix-domain socket the suite carries to the relay as a remote's SSH server
//! carries its forward; and the same `git`'s `credential fill` answers on the
//! workstation's side from a credential system of the suite's own - `git`'s
//! `store` helper on a file of the suite's, every configuration but the
//! suite's own kept out, so no credential of the person's is ever read.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hedwig_core::credential::{Credential, Release, arguments};
use hedwig_core::relay::{Relayed, Settle};
use hedwig_model::credential::{Place, Unread};
use hedwig_model::gate::Interaction;
use hedwig_model::refusal::Refusal;
use hedwig_model::site::Site;
use hedwig_model::text::Program;
use hedwig_support::unix::Listener;
use hedwig_win::start::Environment;

/// The credential the suite's own store holds, and what it releases.
const STORED: &str = "https://octocat:gho_suiteToken0123456789@github.com\n";

/// A folder of the suite's own, its path with forward slashes, which both
/// `git`'s shell and Winsock read.
struct Scene {
    folder: PathBuf,
    socket: String,
}

impl Scene {
    fn new(name: &str) -> Scene {
        let folder = std::env::temp_dir().join(format!("hedwig-git-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("store"), STORED).unwrap();
        let store = slashed(&folder.join("store"));
        std::fs::write(
            folder.join("workstation.gitconfig"),
            format!("[credential]\n\thelper = store --file {store}\n"),
        )
        .unwrap();
        let socket = slashed(&folder.join("s"));
        std::fs::write(
            folder.join("remote.gitconfig"),
            format!("[credential]\n\thelper = cache --socket {socket}\n"),
        )
        .unwrap();
        Scene { folder, socket }
    }

    /// What the workstation's `git` runs with: the suite's configuration
    /// alone - none of the system's, where Git for Windows names Git
    /// Credential Manager, and none of the person's - and `askpass` as the
    /// person who answers `git`'s own prompt.
    fn workstation(&self) -> Environment {
        Environment::own()
            .with("GIT_CONFIG_NOSYSTEM", "1")
            .with_os(
                "GIT_CONFIG_GLOBAL",
                self.folder.join("workstation.gitconfig").as_os_str(),
            )
            .with_os(
                "GIT_ASKPASS",
                Path::new(env!("CARGO_BIN_EXE_child")).as_os_str(),
            )
            .without("SSH_ASKPASS")
            .without("GCM_INTERACTIVE")
    }

    /// The remote's `git` asking its own credential system, whose one helper
    /// is the cache at the forwarded socket.
    fn remote(&self, operation: &str, given: &str) -> (i32, String, String) {
        let mut child = Command::new("git")
            .args(["credential", operation])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.folder.join("remote.gitconfig"))
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_ASKPASS")
            .env_remove("SSH_ASKPASS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(given.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn store(&self) -> String {
        std::fs::read_to_string(self.folder.join("store")).unwrap()
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

fn slashed(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// The suite runs as the core does, in a job its children may leave: the
/// workstation's `git` is the person's, started outside every job of Hedwig's.
fn as_the_core_runs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| hedwig_support::leavable_here().unwrap());
}

fn search() -> OsString {
    std::env::var_os("PATH").unwrap()
}

/// The relay at a forward's end, the remote's socket carried to it, and what
/// each connection tells the deciding thread.
struct Relay {
    told: Receiver<(Relayed, Arc<Settle>)>,
    _socket: std::thread::JoinHandle<()>,
}

impl Relay {
    fn start(scene: &Scene) -> Relay {
        as_the_core_runs();
        let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let to = forward.local_addr().unwrap();
        let socket = Listener::bind(Path::new(&scene.socket))
            .unwrap()
            .forward(to);
        let (sender, told) = mpsc::channel();
        let base = scene.workstation();
        std::thread::spawn(move || {
            for stream in forward.incoming() {
                let Ok(stream) = stream else { break };
                let sender = Arc::new(Mutex::new(sender.clone()));
                let settled: Arc<Mutex<Option<Arc<Settle>>>> = Arc::new(Mutex::new(None));
                let telling = Arc::clone(&settled);
                let settle = hedwig_core::credential::carry(
                    stream,
                    Credential {
                        git: Program::try_from("git").unwrap(),
                    },
                    search(),
                    base.clone(),
                    move |relayed| {
                        let settle = loop {
                            if let Some(settle) = telling.lock().unwrap().clone() {
                                break settle;
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        };
                        let _ = sender.lock().unwrap().send((relayed, settle));
                    },
                );
                *settled.lock().unwrap() = Some(settle);
            }
        });
        Relay {
            told,
            _socket: socket,
        }
    }

    fn next(&self) -> (Relayed, Arc<Settle>) {
        self.told.recv_timeout(Duration::from_secs(30)).unwrap()
    }
}

/// Before anything: the workstation's `git` under the suite's variables
/// reads the suite's helper and no other, so no test reaches a credential of
/// the person's.
#[test]
fn the_suites_git_reads_no_configuration_of_the_persons() {
    let scene = Scene::new("guard");
    let mut command = Command::new("git");
    command
        .args(["config", "--show-origin", "--get-regexp", "credential"])
        .env_clear();
    for (name, value) in std::env::vars_os() {
        command.env(name, value);
    }
    let output = command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            scene.folder.join("workstation.gitconfig"),
        )
        .current_dir(&scene.folder)
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&output.stdout);
    assert_eq!(listed.lines().count(), 1, "{listed}");
    assert!(listed.contains("workstation.gitconfig"), "{listed}");
    assert!(listed.contains("store --file"), "{listed}");
}

/// Served, the remote's own `git` is given the workstation's credential for
/// the site, from the workstation's own credential system, and nothing else:
/// no refresh token, nothing written on the remote's side by hedwig.
#[test]
fn a_remotes_git_is_answered_from_the_workstations_own_credential_system() {
    let scene = Scene::new("served");
    let relay = Relay::start(&scene);
    let asking = std::thread::scope(|scope| {
        let asking = scope.spawn(|| scene.remote("fill", "protocol=https\nhost=github.com\n\n"));
        let (wants, settle) = relay.next();
        let Relayed::Wants(Place::Site(url)) = wants else {
            panic!("{wants:?}")
        };
        assert_eq!(Site::of(&url).to_string(), "https://github.com");
        settle.settle(Ok(()));
        assert_eq!(relay.next().0, Relayed::Gave(Release::Given));
        assert_eq!(relay.next().0, Relayed::Ended);
        asking.join().unwrap()
    });
    let (status, printed, said) = asking;
    assert_eq!(status, 0, "{said}");
    assert_eq!(
        printed,
        "protocol=https\nhost=github.com\nusername=octocat\npassword=gho_suiteToken0123456789\n"
    );
}

/// Refused, the remote's `git` is given nothing and goes on to its own
/// prompt, which is off: it fails, as it would with no helper.
#[test]
fn a_refused_request_gives_the_remote_nothing() {
    let scene = Scene::new("refused");
    let relay = Relay::start(&scene);
    let (status, _, said) = std::thread::scope(|scope| {
        let asking = scope.spawn(|| scene.remote("fill", "protocol=https\nhost=github.com\n\n"));
        let (wants, settle) = relay.next();
        assert!(matches!(wants, Relayed::Wants(_)), "{wants:?}");
        settle.settle(Err(Refusal::Declined));
        assert_eq!(relay.next().0, Relayed::Ended);
        asking.join().unwrap()
    });
    assert_eq!(status, 128);
    assert!(said.contains("terminal prompts disabled"), "{said}");
}

/// What the remote's `git` sends back - the secret that worked, and the one
/// a site refused - never reaches the workstation's store; the refusal is
/// told, for the site, as the forge's.
#[test]
fn a_store_and_an_erase_never_reach_the_workstations_store() {
    let scene = Scene::new("back");
    let relay = Relay::start(&scene);
    let before = scene.store();
    let stored = scene.remote(
        "approve",
        "protocol=https\nhost=gitlab.com\nusername=planted\npassword=planted-secret\n\n",
    );
    assert_eq!(stored.0, 0, "{}", stored.2);
    assert_eq!(relay.next().0, Relayed::Ended);
    let erased = scene.remote(
        "reject",
        "protocol=https\nhost=github.com\nusername=octocat\npassword=gho_suiteToken0123456789\n\n",
    );
    assert_eq!(erased.0, 0, "{}", erased.2);
    let (told, _) = relay.next();
    let Relayed::Erased(Place::Site(url)) = told else {
        panic!("{told:?}")
    };
    assert_eq!(Site::of(&url).to_string(), "https://github.com");
    assert_eq!(relay.next().0, Relayed::Ended);
    assert_eq!(scene.store(), before);
}

/// A site the workstation holds nothing for gives nothing, and with
/// interaction off `git`'s own prompt is never run; allowed where the person
/// is, the workstation's own prompt asks them - here the suite's askpass.
#[test]
fn the_workstations_helper_asks_the_person_only_where_they_allowed_it() {
    let scene = Scene::new("interaction");
    let relay = Relay::start(&scene);
    let (status, _, _) = std::thread::scope(|scope| {
        let asking = scope.spawn(|| scene.remote("fill", "protocol=https\nhost=gitlab.com\n\n"));
        let (_, settle) = relay.next();
        settle.settle(Ok(()));
        assert_eq!(relay.next().0, Relayed::Gave(Release::Nothing));
        assert_eq!(relay.next().0, Relayed::Ended);
        asking.join().unwrap()
    });
    assert_eq!(
        status, 128,
        "nothing was given, so the remote's own prompt failed"
    );

    let (status, printed, said) = std::thread::scope(|scope| {
        let asking = scope.spawn(|| scene.remote("fill", "protocol=https\nhost=gitlab.com\n\n"));
        let (_, settle) = relay.next();
        settle.interact(Interaction::Allowed);
        settle.settle(Ok(()));
        assert_eq!(relay.next().0, Relayed::Gave(Release::Given));
        assert_eq!(relay.next().0, Relayed::Ended);
        asking.join().unwrap()
    });
    assert_eq!(status, 0, "{said}");
    assert!(
        printed.contains("username=suite-user\npassword=suite-asked\n"),
        "{printed}"
    );
    assert_eq!(
        arguments(Interaction::Off),
        ["-c", "credential.interactive=false", "credential", "fill"].map(OsString::from)
    );
    assert_eq!(
        arguments(Interaction::Allowed),
        ["credential", "fill"].map(OsString::from)
    );
}

/// What is not `git`'s cache helper's request is turned away with nothing
/// said, whatever the remote sends.
#[test]
fn what_a_remote_sends_that_git_does_not_is_turned_away_unanswered() {
    let scene = Scene::new("noise");
    as_the_core_runs();
    let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    for (sent, why) in [
        (&b"GET / HTTP/1.1\r\n\r\n"[..], Unread::Action),
        (
            &b"action=get\ntimeout=900\nprotocol=https\nhost=a b\n"[..],
            Unread::Host,
        ),
        (&b"action=get\n"[..], Unread::Timeout),
    ] {
        let mut remote = TcpStream::connect(forward.local_addr().unwrap()).unwrap();
        let (stream, _) = forward.accept().unwrap();
        let (sender, told) = mpsc::channel();
        let sender = Mutex::new(sender);
        let _settle = hedwig_core::credential::carry(
            stream,
            Credential {
                git: Program::try_from("git").unwrap(),
            },
            search(),
            scene.workstation(),
            move |relayed| {
                let _ = sender.lock().unwrap().send(relayed);
            },
        );
        remote.write_all(sent).unwrap();
        remote.shutdown(Shutdown::Write).unwrap();
        let next = || told.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(next(), Relayed::Misasked(why));
        assert_eq!(next(), Relayed::Ended);
        let mut answer = Vec::new();
        let _ = remote.read_to_end(&mut answer);
        assert_eq!(answer, Vec::<u8>::new());
    }
}

/// A `git` the workstation does not have fails the source, and the remote is
/// given nothing.
#[test]
fn a_git_not_on_the_search_path_fails_the_source() {
    let scene = Scene::new("absent");
    as_the_core_runs();
    let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut remote = TcpStream::connect(forward.local_addr().unwrap()).unwrap();
    let (stream, _) = forward.accept().unwrap();
    let (sender, told) = mpsc::channel();
    let sender = Mutex::new(sender);
    let settle = hedwig_core::credential::carry(
        stream,
        Credential {
            git: Program::try_from("no-such-git").unwrap(),
        },
        search(),
        scene.workstation(),
        move |relayed| {
            let _ = sender.lock().unwrap().send(relayed);
        },
    );
    remote
        .write_all(b"action=get\ntimeout=900\nprotocol=https\nhost=github.com\n")
        .unwrap();
    remote.shutdown(Shutdown::Write).unwrap();
    let next = || told.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(
        next(),
        Relayed::Reached(Err(hedwig_model::trail::Failure::Unstartable))
    );
    settle.settle(Err(Refusal::Declined));
    assert_eq!(next(), Relayed::Ended);
    let mut answer = Vec::new();
    let _ = remote.read_to_end(&mut answer);
    assert_eq!(answer, Vec::<u8>::new());
}
