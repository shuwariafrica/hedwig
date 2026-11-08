//! A remote's `adb reverse` with real processes end to end, in the order the
//! answer depends on: the workspace's `hedwig.exe` holds a remote's channel
//! through the stand-in route (`child stand-in`, plan `carry`), whose
//! reverse carrier listens on the workstation and carries to the remote's
//! loopback, 127.0.0.2; platform-tools' own client on the remote asks
//! platform-tools' own server of the suite's, through the relay, for a
//! reverse on a stand-in device, which takes it as adbd does and connects
//! back through it as an app on the device does.
//!
//! The order is driven, never waited out: the route's carrier waits at a gate
//! the suite opens (`<route>/hold`), the device notes as it is asked whether
//! a carrier has listened and holds its answer until the suite lets it go,
//! and the suite ends a carrier or a remote's client and waits for its
//! process to end before the next step. One order the suite does not drive:
//! where the remote leaves while the device answers, its close and the
//! device's answer race to the relay. Correct code passes whichever wins; the
//! case's power to catch a relay that stops reading as the remote leaves
//! rests on the close crossing the stand-in route first.
//!
//! `HEDWIG_ADB` names the `adb.exe`, which `scripts\fetch-test-tools.ps1` lays
//! out; the route's shell is Git for Windows', installed where Git installs it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_client::{Session, Standing, look, released_within, stop};
use hedwig_model::capability::{
    Capability, Exposure, Lends, Offer, ServiceHost, ServicePort, Setup, Source, Stream,
};
use hedwig_model::config::{Activation, Change, Grant, Terms};
use hedwig_model::platform::{AgentForwarding, Platform, Sockets};
use hedwig_model::process::CoreState;
use hedwig_model::protocol::Request;
use hedwig_model::remote::{Argument, Client, Granted, Identity, Listing, RemoteId, Route};
use hedwig_model::text::{Address, Kernel, Name, Port, Program, Verbatim};
use hedwig_model::trail::{Carriage, ClientKind, Entry, Event, Target};
use hedwig_model::wire::read;
use hedwig_support::android::{Device, Server, client, executable, free_port, said, started};
use hedwig_support::{Folder, ended_within};

const WAIT: Duration = Duration::from_secs(60);
const SH: &str = r"C:\Program Files\Git\usr\bin\sh.exe";
/// Where the stand-in route's remote listens.
const REMOTE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
/// The device's side of every reverse the suite asks for.
const DEVICE_SIDE: &str = "tcp:8081";

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn port(number: u16) -> Port {
    Port::try_from(number).unwrap()
}

fn built(name: &str) -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_child")).with_file_name(name)
}

fn remote() -> RemoteId {
    RemoteId {
        route: name("standin"),
        address: Address::try_from("dev@standin.example").unwrap(),
    }
}

/// What Git for Windows' shell calls its system, as the survey will read it.
fn kernel() -> Kernel {
    assert!(
        Path::new(SH).exists(),
        "needs Git for Windows installed: {SH}"
    );
    let output = Command::new(SH)
        .args(["-c", "uname -s"])
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("SYSTEMROOT", r"C:\Windows")
        .output()
        .unwrap();
    Kernel::try_from(String::from_utf8(output.stdout).unwrap().trim()).unwrap()
}

/// Waits until `done` gives something, or panics with `what`.
fn until<T>(what: &str, mut done: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(found) = done() {
            return found;
        }
        assert!(Instant::now() < deadline, "gave up waiting: {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// The run's Hedwig on a folder of the suite's, its route's client the
/// stand-in, a terminal attending, one ADB capability for the suite's server
/// lending every device, and the remote's channel up.
struct Run {
    folder: Folder,
    route: Folder,
    attending: Child,
    adb: PathBuf,
    /// The port the capability's channel forward listens at on the remote.
    at: u16,
}

impl Run {
    fn start(server: &Server) -> Run {
        let kernel = kernel();
        let folder = Folder::new("reversed");
        let route = Folder::new("reversed-route");
        fs::write(route.path().join("plan"), "carry").unwrap();
        let search = format!(
            "{};{}",
            built("child.exe").parent().unwrap().display(),
            std::env::var("PATH").unwrap()
        );
        let started = Command::new(env!("CARGO_BIN_EXE_command"))
            .args(["start", "--folder"])
            .arg(folder.path())
            .env("PATH", search)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(started.status.success(), "{started:?}");
        let attending = Command::new(built("child.exe"))
            .arg("attend")
            .arg(folder.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let run = Run {
            folder,
            route,
            attending,
            adb: executable(),
            at: free_port(),
        };
        let literal = |text: &str| Argument::Literal(Verbatim::try_from(text).unwrap());
        run.ask(Request::Change(Change::DefinePlatform(Platform {
            family: name("git-bash"),
            kernel,
            sockets: Sockets::Emulated,
            agent_forwarding: AgentForwarding::Refused,
        })));
        run.ask(Request::Change(Change::DefineRoute(Route {
            id: name("standin"),
            client: Client {
                program: Program::try_from("child").unwrap(),
                before: vec![
                    literal("stand-in"),
                    literal(run.route.path().to_str().unwrap()),
                ],
                after: vec![Argument::Address],
            },
            listing: Listing::Blind,
            identity: Identity::HostKey,
        })));
        run.ask(Request::Change(Change::Define(Capability {
            id: name("adb-suite"),
            source: Source::Service {
                host: ServiceHost::Workstation,
                port: ServicePort::Fixed(port(server.port())),
                stream: Stream::Adb,
                remote: vec![Offer::Port(ServicePort::Fixed(port(run.at)))],
            },
        })));
        run.ask(Request::Change(Change::Grant {
            grant: Grant {
                capability: name("adb-suite"),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged: Exposure::SERVICE,
                lends: Lends::Every,
            },
        }));
        run.ask(Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        });
        until("the channel's forward on the remote", || {
            fs::read_to_string(run.route.path().join("carried"))
                .unwrap_or_default()
                .lines()
                .any(|line| line.starts_with(&format!("{} ", run.at)))
                .then_some(())
        });
        run
    }

    fn ask(&self, request: Request) {
        let Standing::Known(running) = look(self.folder.path()).unwrap() else {
            panic!("Hedwig runs");
        };
        let CoreState::Serving { pipe, .. } = &running.core else {
            panic!("the core serves");
        };
        let mut session = Session::open(pipe).unwrap();
        session.greet(ClientKind::Command).unwrap().unwrap();
        let asked = format!("{request:?}");
        let reply = session.ask(request).unwrap();
        assert!(reply.is_ok(), "{asked}: {reply:?}");
    }

    /// The remote's `adb reverse tcp:8081 tcp:<listener>`, left running.
    fn reverse(&self, listener: u16) -> Child {
        started(
            &self.adb,
            &REMOTE.to_string(),
            self.at,
            &["reverse", DEVICE_SIDE, &format!("tcp:{listener}")],
        )
    }

    fn gate(&self) -> PathBuf {
        self.route.path().join("hold")
    }

    /// Each carrier the route started that listens: its workstation port,
    /// and its process by number and creation.
    fn hauled(&self) -> Vec<(u16, u32, u64)> {
        fs::read_to_string(self.route.path().join("hauled"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let mut words = line.split(' ');
                Some((
                    words.next()?.parse().ok()?,
                    words.next()?.parse().ok()?,
                    words.next()?.parse().ok()?,
                ))
            })
            .collect()
    }

    /// Ends the carrier listening at `listen` and waits for its process.
    fn end_carrier(&self, listen: u16, process: u32, created: u64) {
        fs::write(self.route.path().join(format!("end-{listen}")), "").unwrap();
        assert!(ended_within(process, created, WAIT), "the carrier ended");
    }

    fn reverses_carried(&self) -> Vec<Target> {
        fs::read_to_string(self.folder.path().join("trail.jsonl"))
            .unwrap_or_default()
            .lines()
            .skip(2)
            .filter_map(|written| match read::<Entry>(written).unwrap().event {
                Event::Carried {
                    carriage: Carriage::Reverse(target),
                    ..
                } => Some(target),
                _ => None,
            })
            .collect()
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.gate());
        if let Ok(standing @ Standing::Known(_)) = look(self.folder.path()) {
            let _ = stop(&standing);
            released_within(self.folder.path(), Duration::from_secs(30));
        }
        let _ = self.attending.kill();
        let _ = self.attending.wait();
    }
}

/// The suite's server holding one stand-in device, attached as the person
/// attaches one.
fn server_with_device() -> (Server, Device) {
    let adb = executable();
    let server = Server::start(&adb);
    let device = Device::start("Pixel_Standin").unwrap();
    let connected = client(
        &adb,
        "127.0.0.1",
        server.port(),
        &["connect", &device.serial()],
    );
    assert!(connected.status.success(), "{}", said(&connected));
    until("the device online", || {
        let state = client(
            &adb,
            "127.0.0.1",
            server.port(),
            &["-s", &device.serial(), "get-state"],
        );
        (said(&state).trim() == "device").then_some(())
    });
    (server, device)
}

/// A dev server on the remote's loopback that echoes what it reads; its
/// port.
fn remote_listener() -> u16 {
    let listener = TcpListener::bind((REMOTE, 0)).unwrap();
    let at = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut buffer = [0u8; 1024];
                while let Ok(read) = stream.read(&mut buffer) {
                    if read == 0 || stream.write_all(&buffer[..read]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    at
}

fn asked_of_the_device(device: &Device) -> Vec<String> {
    device
        .opened()
        .into_iter()
        .filter(|name| name.starts_with("reverse:forward:"))
        .collect()
}

/// The remote's `adb reverse` is not answered while its carrier has not
/// said it listens - the device is not even asked, and when it is, the
/// carrier already listens - and once it is answered a connection the device
/// makes at that moment reaches the remote's dev server; the trail records
/// the reverse carried.
#[test]
fn a_reverse_is_answered_once_its_carrier_listens_and_reaches_the_remote_at_once() {
    let (server, device) = server_with_device();
    let run = Run::start(&server);
    let listener = remote_listener();

    fs::write(run.gate(), "").unwrap();
    device.witness(run.route.path().join("hauled"));
    let mut reverse = run.reverse(listener);
    until("the carrier at its gate", || {
        run.route.path().join("holding").exists().then_some(())
    });
    assert_eq!(
        asked_of_the_device(&device),
        Vec::<String>::new(),
        "the device is asked only once the carrier listens"
    );
    assert!(
        reverse.try_wait().unwrap().is_none(),
        "the remote is answered only once the carrier listens"
    );

    fs::remove_file(run.gate()).unwrap();
    let answered = reverse.wait_with_output().unwrap();
    assert!(answered.status.success(), "{}", said(&answered));
    let witnessed = device.witnessed();
    assert!(
        matches!(witnessed.as_slice(), [(name, true)]
            if name.starts_with(&format!("reverse:forward:{DEVICE_SIDE};tcp:"))),
        "the carrier listened when the device was asked: {witnessed:?}"
    );
    assert_eq!(
        device.reach(DEVICE_SIDE, b"to the dev server"),
        b"to the dev server"
    );
    assert_eq!(run.reverses_carried(), [Target::Loopback(port(listener))]);
}

/// A carrier that cannot listen is told to the remote in Hedwig's words, as
/// ADB's client prints a refusal, and the device is never asked: it holds no
/// reverse nothing carries.
#[test]
fn a_carrier_that_cannot_listen_is_told_to_the_remote_and_the_device_is_never_asked() {
    let (server, device) = server_with_device();
    let run = Run::start(&server);
    let listener = remote_listener();

    fs::write(run.route.path().join("unbindable"), "").unwrap();
    let refused = run.reverse(listener).wait_with_output().unwrap();
    assert!(!refused.status.success(), "{}", said(&refused));
    assert!(
        said(&refused)
            .contains("error: Hedwig cannot carry the reverse on to the remote: bind [127.0.0.1]:"),
        "{}",
        said(&refused)
    );
    assert_eq!(asked_of_the_device(&device), Vec::<String>::new());
    assert_eq!(run.reverses_carried(), Vec::<Target>::new());
}

/// A carrier that stood when the device was asked and is gone when the
/// device answers is stood again before the remote reads the answer, and a
/// device connection then reaches the remote; where it cannot stand again,
/// the remote reads that the device keeps the reverse and Hedwig carries it
/// once the remote's channel can.
#[test]
fn a_carrier_gone_before_the_answer_is_stood_again_or_the_remote_is_told() {
    let (server, device) = server_with_device();
    let run = Run::start(&server);
    let listener = remote_listener();

    for again in [true, false] {
        device.hold_reverses(true);
        let asked = asked_of_the_device(&device).len();
        let reverse = run.reverse(listener);
        until("the device asked", || {
            (asked_of_the_device(&device).len() > asked).then_some(())
        });
        let hauled = run.hauled();
        let &[(listen, process, created)] = hauled.as_slice() else {
            panic!("one carrier stood before the device was asked: {hauled:?}");
        };
        run.end_carrier(listen, process, created);
        if !again {
            fs::write(run.route.path().join("unbindable"), "").unwrap();
        }
        device.hold_reverses(false);
        let answered = reverse.wait_with_output().unwrap();
        if again {
            assert!(answered.status.success(), "{}", said(&answered));
            assert_eq!(run.hauled().len(), 2, "a carrier stood again");
            assert_eq!(device.reach(DEVICE_SIDE, b"again"), b"again");
            let (listen, process, created) = run.hauled()[1];
            run.end_carrier(listen, process, created);
            fs::remove_file(run.route.path().join("hauled")).unwrap();
        } else {
            assert!(!answered.status.success(), "{}", said(&answered));
            assert!(
                said(&answered).contains(
                    "the device keeps it, and Hedwig carries it once the remote's channel can"
                ),
                "{}",
                said(&answered)
            );
        }
    }
}

/// A remote that leaves while the device answers leaves the device's answer
/// still read: the reverse the device took is recorded, its carrier kept, and
/// a connection the device makes reaches the remote's listener.
#[test]
fn a_reverse_whose_remote_left_before_the_answer_is_recorded_as_the_device_took_it() {
    let (server, device) = server_with_device();
    let run = Run::start(&server);
    let listener = remote_listener();

    device.hold_reverses(true);
    let asked = asked_of_the_device(&device).len();
    let mut reverse = run.reverse(listener);
    until("the device asked", || {
        (asked_of_the_device(&device).len() > asked).then_some(())
    });
    reverse.kill().unwrap();
    let _ = reverse.wait();
    device.hold_reverses(false);
    until("the reverse recorded", || {
        run.reverses_carried()
            .contains(&Target::Loopback(port(listener)))
            .then_some(())
    });
    assert_eq!(device.reach(DEVICE_SIDE, b"left"), b"left");
}
