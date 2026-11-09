//! What the ADB relay carries for a remote, with real processes end to end:
//! the workspace's `hedwig.exe`, configured over its pipe as a person
//! configures it, holds a remote's channel through the stand-in route
//! (`child stand-in`, plan `carry`) - a whole route to this workstation as a
//! remote, which surveys it with Git for Windows' shell and listens for each
//! remote forward at 127.0.0.2, the remote's loopback - and relays
//! platform-tools' own client there to platform-tools' own server of the
//! suite's, which holds stand-in devices and an emulator's console.
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

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::num::NonZeroU16;
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
use hedwig_model::refusal::{Refusal, Withheld};
use hedwig_model::remote::{Argument, Client, Granted, Identity, Listing, RemoteId, Route};
use hedwig_model::text::{Address, DeviceSerial, Kernel, Name, Port, Program, Verbatim};
use hedwig_model::trail::{Carriage, ClientKind, Dropped, Entry, Event};
use hedwig_model::wire::read;
use hedwig_support::android::{
    CONSOLE_TOKEN, Console, Device, Server, client, executable, free_port, said, started,
};
use hedwig_support::{Folder, ended_within};

const WAIT: Duration = Duration::from_secs(60);
/// How long a channel may take to return to a port whose connections closed.
const RETURN: Duration = Duration::from_secs(120);
const SH: &str = r"C:\Program Files\Git\usr\bin\sh.exe";
/// Where the stand-in route's remote listens.
const REMOTE: &str = "127.0.0.2";

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
fn until<T>(what: &str, done: impl FnMut() -> Option<T>) -> T {
    until_within(WAIT, what, done)
}

/// As [`until`], for `bound`.
fn until_within<T>(bound: Duration, what: &str, mut done: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + bound;
    loop {
        if let Some(found) = done() {
            return found;
        }
        assert!(Instant::now() < deadline, "gave up waiting: {what}");
        thread::sleep(Duration::from_millis(200));
    }
}

/// The run's Hedwig on a folder of the suite's, its route's client the
/// stand-in, a terminal attending so the person is reachable, and one ADB
/// capability for the suite's server.
struct Run {
    folder: Folder,
    route: Folder,
    attending: Child,
    adb: PathBuf,
    /// The port the capability's channel forward listens at on the remote.
    at: u16,
}

impl Run {
    fn start(kernel: Kernel, server: &Server, lends: Lends) -> Run {
        Run::start_on(kernel, server, lends, Sockets::Emulated)
    }

    /// As [`Run::start`], the remote's platform carrying `sockets`.
    fn start_on(kernel: Kernel, server: &Server, lends: Lends, sockets: Sockets) -> Run {
        let folder = Folder::new("carried");
        let route = Folder::new("carried-route");
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
            sockets,
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
        run.lend(lends);
        run.ask(Request::Connect {
            remote: remote(),
            with: Vec::new(),
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        });
        until("the channel's forward on the remote", || {
            run.carried()
                .iter()
                .any(|(at, _)| *at == run.at)
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

    /// The capability granted to the remote, lending `lends`.
    fn lend(&self, lends: Lends) {
        self.ask(Request::Change(Change::Grant {
            grant: Grant {
                capability: name("adb-suite"),
                remotes: Granted::One(remote()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged: Exposure::SERVICE,
                lends,
            },
        }));
    }

    /// Each remote forward the route holds: where it listens on the remote,
    /// and the workstation's end it carries to.
    fn carried(&self) -> Vec<(u16, u16)> {
        fs::read_to_string(self.route.path().join("carried"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let (at, endpoint) = line.split_once(' ')?;
                Some((at.parse().ok()?, endpoint.parse().ok()?))
            })
            .collect()
    }

    /// The next carrier that listens on the remote waits before it asks,
    /// until [`Run::release_placers`].
    fn hold_placers(&self) {
        fs::write(self.route.path().join("hold-place"), "").unwrap();
    }

    fn release_placers(&self) {
        fs::remove_file(self.route.path().join("hold-place")).unwrap();
    }

    /// The process of the carrier waiting to ask, by number and creation.
    fn placer_held(&self) -> (u32, u64) {
        until("a carrier held before it asks", || {
            let text = fs::read_to_string(self.route.path().join("placing")).ok()?;
            let (process, created) = text.split_once(' ')?;
            Some((process.parse().ok()?, created.parse().ok()?))
        })
    }

    /// The workstation's endpoint of the placer asked to listen at `port`.
    fn placers_endpoint(&self, port: u16) -> u16 {
        until("the placer's endpoint", || {
            fs::read_to_string(self.route.path().join("placers"))
                .ok()?
                .lines()
                .find_map(|line| {
                    let (listen, endpoint) = line.split_once(' ')?;
                    (listen == port.to_string())
                        .then(|| endpoint.parse().ok())
                        .flatten()
                })
        })
    }

    /// The ports on the remote of the forwards the trail records as carried.
    fn forwards_carried(&self) -> Vec<u16> {
        self.trail()
            .iter()
            .filter_map(|event| match event {
                Event::Carried {
                    carriage: Carriage::Forward { port, .. },
                    ..
                } => Some(port.number()),
                _ => None,
            })
            .collect()
    }

    /// platform-tools' client on the remote.
    fn remote_adb(&self, arguments: &[&str]) -> std::process::Output {
        client(&self.adb, REMOTE, self.at, arguments)
    }

    /// The trail's events, after the lines naming its form and holding its
    /// head.
    fn trail(&self) -> Vec<Event> {
        fs::read_to_string(self.folder.path().join("trail.jsonl"))
            .unwrap_or_default()
            .lines()
            .skip(2)
            .map(|written| read::<Entry>(written).unwrap().event)
            .collect()
    }

    fn trail_text(&self) -> String {
        fs::read_to_string(self.folder.path().join("trail.jsonl")).unwrap_or_default()
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if let Ok(standing @ Standing::Known(_)) = look(self.folder.path()) {
            let _ = stop(&standing);
            released_within(self.folder.path(), Duration::from_secs(30));
        }
        let _ = self.attending.kill();
        let _ = self.attending.wait();
    }
}

/// A device attached to the suite's server by `adb connect`, as the person
/// attaches one.
fn attach(adb: &Path, server: &Server, address: &str, serial: &str) {
    let connected = client(adb, "127.0.0.1", server.port(), &["connect", address]);
    assert!(connected.status.success(), "{}", said(&connected));
    until(&format!("{serial} online"), || {
        let state = client(
            adb,
            "127.0.0.1",
            server.port(),
            &["-s", serial, "get-state"],
        );
        (said(&state).trim() == "device").then_some(())
    });
}

/// Writes `sent` at `at` on the remote's loopback and reads back as many
/// bytes, or what came before the end.
fn round_trip(at: u16, sent: &[u8]) -> Vec<u8> {
    let Ok(mut stream) = TcpStream::connect((REMOTE.parse::<Ipv4Addr>().unwrap(), at)) else {
        return Vec::new();
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let _ = stream.write_all(sent);
    let mut back = Vec::new();
    let mut buffer = [0u8; 64];
    while back.len() < sent.len() {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => back.extend_from_slice(&buffer[..read]),
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    back
}

/// Waits until nothing accepts at the workstation's endpoint.
fn endpoint_ended(endpoint: u16) {
    until("the placer's endpoint ended", || {
        TcpStream::connect((Ipv4Addr::LOCALHOST, endpoint))
            .is_err()
            .then_some(())
    });
}

/// Whether nothing listens at `at` on the remote.
fn unreachable_at(at: u16) -> bool {
    TcpStream::connect((REMOTE.parse::<Ipv4Addr>().unwrap(), at)).is_err()
}

/// The server's own listing of its forwards, as the person reads it.
fn servers_forwards(adb: &Path, server: &Server) -> String {
    said(&client(
        adb,
        "127.0.0.1",
        server.port(),
        &["forward", "--list"],
    ))
}

/// End to end, a remote's `adb forward` listens on the remote - at a port
/// its server chooses, answered with that port, or at the one it named - and
/// reaches the device through a listener the workstation's server chose; the
/// core's end carries only its carrier's connections; the remote lists and
/// removes its own forwards, by their ports on the remote, and never the
/// person's.
#[test]
#[allow(clippy::too_many_lines, reason = "one workflow, placed to removed")]
fn a_remotes_forward_listens_on_the_remote_and_reaches_the_device() {
    let kernel = kernel();
    let adb = executable();
    let server = Server::start(&adb);
    let device = Device::start("Pixel_Standin").unwrap();
    attach(&adb, &server, &device.serial(), &device.serial());
    let run = Run::start(kernel, &server, Lends::Every);

    let listed = run.remote_adb(&["devices"]);
    assert!(
        said(&listed).contains(&format!("{}\tdevice", device.serial())),
        "{}",
        said(&listed)
    );

    // tcp:0, as Flutter asks for its VM service: answered with the port on
    // the remote, not the server's.
    let chosen = run.remote_adb(&["forward", "tcp:0", "tcp:7000"]);
    assert!(chosen.status.success(), "{}", said(&chosen));
    let placed: u16 = String::from_utf8_lossy(&chosen.stdout)
        .trim()
        .parse()
        .unwrap();
    let endpoint = run
        .carried()
        .into_iter()
        .find(|(at, _)| *at == placed)
        .map(|(_, endpoint)| endpoint)
        .expect("a carrier listens at the port the remote was told");
    let own = servers_forwards(&adb, &server);
    let listener: u16 = own
        .lines()
        .find(|line| line.ends_with(" tcp:7000"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|local| local.strip_prefix("tcp:"))
        .and_then(|number| number.parse().ok())
        .expect("the server holds a listener for the forward");
    assert_ne!(listener, placed, "the server's listener is its own choice");
    assert_ne!(listener, endpoint);
    assert_eq!(round_trip(placed, b"to the device"), b"to the device");
    assert!(device.opened().contains(&"tcp:7000".to_owned()));

    // The core's end carries only what its carrier brings: the suite, a
    // process outside the channel's job, is closed unanswered.
    let mut stray = TcpStream::connect((Ipv4Addr::LOCALHOST, endpoint)).unwrap();
    stray
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let _ = stray.write_all(b"not the carrier");
    let mut rest = Vec::new();
    let _ = stray.read_to_end(&mut rest);
    assert!(rest.is_empty(), "{rest:?}");

    // A port the remote names, as Appium and Chrome do.
    let named = free_port();
    let fixed = run.remote_adb(&["forward", &format!("tcp:{named}"), "tcp:7001"]);
    assert!(fixed.status.success(), "{}", said(&fixed));
    assert_eq!(round_trip(named, b"fixed"), b"fixed");
    let refused = run.remote_adb(&[
        "forward",
        "--no-rebind",
        &format!("tcp:{named}"),
        "tcp:7002",
    ]);
    assert!(
        said(&refused).contains("cannot rebind existing socket"),
        "{}",
        said(&refused)
    );

    // The person's own forward on the server, beside the remote's.
    let persons = free_port();
    let made = client(
        &adb,
        "127.0.0.1",
        server.port(),
        &[
            "-s",
            &device.serial(),
            "forward",
            &format!("tcp:{persons}"),
            "tcp:7003",
        ],
    );
    assert!(made.status.success(), "{}", said(&made));

    let theirs = said(&run.remote_adb(&["forward", "--list"]));
    let serial = device.serial();
    assert_eq!(
        theirs
            .lines()
            .filter(|line| !line.is_empty())
            .collect::<BTreeSet<&str>>(),
        [
            format!("{serial} tcp:{placed} tcp:7000"),
            format!("{serial} tcp:{named} tcp:7001"),
        ]
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<&str>>(),
        "the remote's own, by their ports on the remote"
    );

    let removed = run.remote_adb(&["forward", "--remove", &format!("tcp:{placed}")]);
    assert!(removed.status.success(), "{}", said(&removed));
    assert!(!servers_forwards(&adb, &server).contains(" tcp:7000"));
    until("the removed forward's carrier ended", || {
        TcpStream::connect((REMOTE.parse::<Ipv4Addr>().unwrap(), placed))
            .is_err()
            .then_some(())
    });
    let missing = run.remote_adb(&["forward", "--remove", &format!("tcp:{persons}")]);
    assert!(
        said(&missing).contains(&format!("listener 'tcp:{persons}' not found")),
        "{}",
        said(&missing)
    );

    let all = run.remote_adb(&["forward", "--remove-all"]);
    assert!(all.status.success(), "{}", said(&all));
    let left = servers_forwards(&adb, &server);
    assert!(!left.contains(" tcp:7001"), "{left}");
    assert!(
        left.contains(&format!("tcp:{persons} tcp:7003")),
        "the person's own stays: {left}"
    );

    let trail = run.trail();
    let carried: Vec<u16> = trail
        .iter()
        .filter_map(|event| match event {
            Event::Carried {
                carriage: Carriage::Forward { port, .. },
                ..
            } => Some(port.number()),
            _ => None,
        })
        .collect();
    assert_eq!(carried, [placed, named], "{trail:#?}");
    let dropped: Vec<(u16, Dropped)> = trail
        .iter()
        .filter_map(|event| match event {
            Event::Dropped {
                carriage: Carriage::Forward { port, .. },
                why,
                ..
            } => Some((port.number(), *why)),
            _ => None,
        })
        .collect();
    assert_eq!(
        dropped,
        [(placed, Dropped::Removed), (named, Dropped::Removed)],
        "{trail:#?}"
    );
}

/// End to end, of two devices on the server, the remote sees, selects
/// and waits for only the one lent; lending the other reaches the remote.
#[test]
fn a_remote_sees_and_reaches_only_the_devices_lent() {
    let kernel = kernel();
    let adb = executable();
    let server = Server::start(&adb);
    let test = Device::start("Test_Device").unwrap();
    let phone = Device::start("Persons_Phone").unwrap();
    attach(&adb, &server, &test.serial(), &test.serial());
    attach(&adb, &server, &phone.serial(), &phone.serial());
    let lent = |serials: &[&str]| {
        Lends::devices(
            serials
                .iter()
                .map(|serial| DeviceSerial::try_from(*serial).unwrap()),
        )
    };
    let run = Run::start(kernel, &server, lent(&[&test.serial()]));

    let listed = said(&run.remote_adb(&["devices", "-l"]));
    assert!(listed.contains("model:Test_Device"), "{listed}");
    assert!(!listed.contains(&phone.serial()), "{listed}");
    assert!(!listed.contains("Persons_Phone"), "{listed}");

    // A Gradle-style run takes the one device there is; the phone named by
    // serial is not there.
    let one = run.remote_adb(&["get-serialno"]);
    assert_eq!(said(&one).trim(), test.serial());
    let named = run.remote_adb(&["-s", &phone.serial(), "get-state"]);
    assert!(
        said(&named).contains(&format!("device '{}' not found", phone.serial())),
        "{}",
        said(&named)
    );
    let modelled = run.remote_adb(&["-s", "model:Persons_Phone", "get-state"]);
    assert!(!modelled.status.success(), "{}", said(&modelled));
    let disconnect = run.remote_adb(&["disconnect"]);
    assert!(
        said(&disconnect).contains("never on every device"),
        "{}",
        said(&disconnect)
    );
    let still = client(&adb, "127.0.0.1", server.port(), &["devices"]);
    assert!(said(&still).contains(&phone.serial()), "{}", said(&still));
    assert!(
        run.trail_text().contains("unlent"),
        "the person reads which device the remote reached for"
    );

    run.lend(lent(&[&test.serial(), &phone.serial()]));
    until("the phone lent", || {
        said(&run.remote_adb(&["devices"]))
            .contains(&phone.serial())
            .then_some(())
    });
}

/// End to end, a lent emulator's console listens on the remote at the
/// port its serial names; the core authenticates with the token read on the
/// workstation, the remote's own `auth` never reaches the console, what acts
/// on the workstation is the console's own `KO`, and a console no longer
/// lent stops being carried.
#[test]
fn a_lent_emulators_console_is_reached_on_the_remote_authenticated_on_the_workstation() {
    let kernel = kernel();
    let adb = executable();
    let server = Server::start(&adb);
    let tokens = Folder::new("carried-console");
    let console = Console::start(tokens.path()).unwrap();
    let device = Device::start("sdk_gphone64_x86_64").unwrap();
    let serial = format!("emulator-{}", console.port());
    attach(
        &adb,
        &server,
        &format!("emu:{},{}", console.port(), device.port()),
        &serial,
    );
    let run = Run::start(kernel, &server, Lends::Every);
    until("the console carried on to the remote", || {
        run.carried()
            .iter()
            .any(|(at, _)| *at == console.port())
            .then_some(())
    });

    let mut remote =
        TcpStream::connect((REMOTE.parse::<Ipv4Addr>().unwrap(), console.port())).unwrap();
    remote
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut answer = |sent: &str| {
        if !sent.is_empty() {
            remote.write_all(sent.as_bytes()).unwrap();
        }
        let mut read = Vec::new();
        let mut byte = [0u8; 1];
        while !(read.ends_with(b"OK\r\n") || (read.ends_with(b"\r\n") && read.starts_with(b"KO"))) {
            if remote.read(&mut byte).unwrap() == 0 {
                break;
            }
            read.push(byte[0]);
        }
        String::from_utf8(read).unwrap()
    };
    // As a client holding the token is greeted, which `adb emu` reads past.
    assert_eq!(
        answer(""),
        "Android Console: Authentication required\r\n\
         Android Console: type 'auth <auth_token>' to authenticate\r\nOK\r\n"
    );
    assert_eq!(
        answer(""),
        "Android Console: type 'help' for a list of commands\r\nOK\r\n",
        "the console as it stands once authenticated"
    );
    assert_eq!(
        answer("auth a-token-of-the-remotes\r\n"),
        "I am alive!\r\nOK\r\n"
    );
    assert_eq!(answer("geo fix 39.2 -6.16\r\n"), "OK\r\n");
    for refused in ["qemu monitor\r\n", "redir add tcp:5000:6000\r\n"] {
        assert_eq!(answer(refused), "KO: unknown command, try 'help'\r\n");
    }
    assert_eq!(answer("ping\r\n"), "I am alive!\r\nOK\r\n");
    drop(remote);

    assert_eq!(
        console.lines(),
        [
            format!("auth {CONSOLE_TOKEN}"),
            "ping".to_owned(),
            "geo fix 39.2 -6.16".to_owned(),
            "hedwig-refused".to_owned(),
            "hedwig-refused".to_owned(),
            "ping".to_owned(),
        ]
    );
    let trail = run.trail();
    assert!(trail.iter().any(|event| matches!(
        event,
        Event::Carried { carriage: Carriage::Console { port: at, .. }, .. } if at.number() == console.port()
    )));
    assert!(run.trail_text().contains("hosted"), "{}", run.trail_text());
    assert!(
        !run.trail_text().contains("a-token-of-the-remotes"),
        "the remote's token is recorded nowhere"
    );

    run.lend(Lends::none());
    until("the console no longer carried", || {
        TcpStream::connect((REMOTE.parse::<Ipv4Addr>().unwrap(), console.port()))
            .is_err()
            .then_some(())
    });
    assert!(run.trail().iter().any(|event| matches!(
        event,
        Event::Dropped {
            carriage: Carriage::Console { .. },
            why: Dropped::Unlent,
            ..
        }
    )));
}

/// A forward placed again on a returning channel runs in that channel's job:
/// its device leaving ends it there, where its carrier runs. The platform has
/// Unix-domain sockets so the channel's return is surveyed with the POSIX
/// shell, the only one the stand-in route runs.
#[test]
fn a_forward_placed_again_ends_with_its_device_on_the_channel_that_carries_it() {
    let kernel = kernel();
    let adb = executable();
    let server = Server::start(&adb);
    let device = Device::start("Pixel_Standin").unwrap();
    attach(&adb, &server, &device.serial(), &device.serial());
    let sockets = Sockets::Unix {
        path_bytes: NonZeroU16::new(108).unwrap(),
    };
    let run = Run::start_on(kernel, &server, Lends::Every, sockets);

    let named = free_port();
    let fixed = run.remote_adb(&["forward", &format!("tcp:{named}"), "tcp:7001"]);
    assert!(fixed.status.success(), "{}", said(&fixed));

    run.ask(Request::Disconnect { remote: remote() });
    until("the channel's carriers ended", || {
        unreachable_at(named).then_some(())
    });
    run.ask(Request::Connect {
        remote: remote(),
        with: Vec::new(),
        acknowledged: Exposure::NONE,
        lends: Lends::none(),
    });
    // Windows keeps the closed connections' rows on the port, some of them
    // reading as listening, for about half a minute: the survey finds it held
    // and the channel tries again, on a backing-off pace.
    until_within(RETURN, "the forward placed again", || {
        (run.carried().iter().filter(|(at, _)| *at == named).count() == 2).then_some(())
    });
    assert_eq!(round_trip(named, b"carried again"), b"carried again");

    // Gone for good: dropping its connection alone has the server reconnect
    // it under the same transport id.
    let left = client(
        &adb,
        "127.0.0.1",
        server.port(),
        &["disconnect", &device.serial()],
    );
    assert!(left.status.success(), "{}", said(&left));
    until("the carrier placed again ended", || {
        unreachable_at(named).then_some(())
    });
    let trail = run.trail();
    assert!(
        trail.iter().any(|event| matches!(event, Event::Dropped {
            carriage: Carriage::Forward { port, .. },
            why: Dropped::Gone,
            ..
        } if port.number() == named)),
        "{trail:#?}"
    );
}

/// A remote that leaves before its forward is placed leaves it to be finished,
/// recorded and listed, as the workstation's server finishes one whose client
/// left. The gate holds the carrier until the remote's client has ended. One
/// order the suite does not drive: the client's close and the carrier's answer
/// race to the relay, and correct code passes whichever wins; the case's power
/// to catch a relay that stops as the remote leaves rests on the close
/// crossing the stand-in route first.
#[test]
fn a_forward_whose_remote_left_is_finished_recorded_and_listed() {
    let kernel = kernel();
    let adb = executable();
    let server = Server::start(&adb);
    let device = Device::start("Pixel_Standin").unwrap();
    attach(&adb, &server, &device.serial(), &device.serial());
    let run = Run::start(kernel, &server, Lends::Every);

    run.hold_placers();
    let named = free_port();
    let mut asking = started(
        &adb,
        REMOTE,
        run.at,
        &["forward", &format!("tcp:{named}"), "tcp:7006"],
    );
    run.placer_held();
    asking.kill().unwrap();
    asking.wait().unwrap();
    run.release_placers();

    until("the forward recorded", || {
        run.forwards_carried().contains(&named).then_some(())
    });
    let listed = said(&run.remote_adb(&["forward", "--list"]));
    assert!(
        listed.contains(&format!("tcp:{named} tcp:7006")),
        "{listed}"
    );
    assert_eq!(round_trip(named, b"finished"), b"finished");
}

/// A connection that ends before its forward is recorded ends the carrier
/// placing it: here it writes past its request, as `adb` never does, and the
/// relay turns it away while the gate holds the carrier.
#[test]
fn a_connection_ended_before_its_forward_is_recorded_ends_its_carrier() {
    let kernel = kernel();
    let adb = executable();
    let server = Server::start(&adb);
    let device = Device::start("Pixel_Standin").unwrap();
    attach(&adb, &server, &device.serial(), &device.serial());
    let run = Run::start(kernel, &server, Lends::Every);

    run.hold_placers();
    let named = free_port();
    let mut raw = TcpStream::connect((REMOTE.parse::<Ipv4Addr>().unwrap(), run.at)).unwrap();
    let request = format!("host:forward:tcp:{named};tcp:7007");
    raw.write_all(format!("{:04x}{request}", request.len()).as_bytes())
        .unwrap();
    let (process, created) = run.placer_held();
    let endpoint = run.placers_endpoint(named);
    raw.write_all(b"0004more").unwrap();
    assert!(ended_within(process, created, WAIT), "the carrier ended");
    endpoint_ended(endpoint);
    run.release_placers();
    assert!(!run.forwards_carried().contains(&named));
}

/// A forward the remote's server will not listen for is told to the remote in
/// ADB's words and recorded for the person in the same ones.
#[test]
fn a_forward_that_cannot_be_placed_is_told_to_the_remote_and_recorded_for_the_person() {
    let kernel = kernel();
    let adb = executable();
    let server = Server::start(&adb);
    let device = Device::start("Pixel_Standin").unwrap();
    attach(&adb, &server, &device.serial(), &device.serial());
    let run = Run::start(kernel, &server, Lends::Every);

    let taken = TcpListener::bind((REMOTE.parse::<Ipv4Addr>().unwrap(), 0)).unwrap();
    let named = taken.local_addr().unwrap().port();
    let refused = run.remote_adb(&["forward", &format!("tcp:{named}"), "tcp:7008"]);
    assert!(!refused.status.success(), "{}", said(&refused));
    let words = format!("the remote's ssh server would not listen at port {named}");
    assert!(
        said(&refused).contains(&format!("cannot bind listener: {words}")),
        "{}",
        said(&refused)
    );
    endpoint_ended(run.placers_endpoint(named));
    let trail = run.trail();
    assert!(
        trail.iter().any(|event| matches!(event, Event::TurnedAway {
            refusal: Refusal::Withheld {
                request: Withheld::Unhauled(why),
                ..
            },
            ..
        } if why.as_str() == words)),
        "{trail:#?}"
    );
}
