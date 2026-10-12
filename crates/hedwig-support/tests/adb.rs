//! The ADB relay with real processes: platform-tools' own server and client,
//! of the current release, carried through `hedwig_core::adb`; and the
//! endpoint a carried reverse is reached through, admitting only the
//! server's connections and carrying them only to a carrier in the remote's
//! channel's job.
//!
//! `HEDWIG_ADB` names the `adb.exe` of platform-tools 37.0.1, which
//! `scripts\fetch-test-tools.ps1` lays out. The suite's server listens on a
//! port of its own with USB, the emulator scan and mDNS off, so it reaches no
//! device and touches no server of the person's.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_core::adb::{Carriage, Carried, Lending, Reverse, Watch, query};
use hedwig_core::channel::Jobs;
use hedwig_core::devices::{Listing, View};
use hedwig_core::relay::{Relayed, Settle};
use hedwig_core::service::Service;
use hedwig_model::capability::ServiceHost;
use hedwig_model::holder::Whose;
use hedwig_model::refusal::Withheld;
use hedwig_model::remote::RemoteId;
use hedwig_model::text::{Address, Name, Port};
use hedwig_model::trail::{ConnectionId, Failure, Seq, Target};
use hedwig_support::android::{self, Server, executable, free_port, said};
use hedwig_win::process::Job;

fn adb() -> PathBuf {
    executable()
}

fn port(number: u16) -> Port {
    Port::try_from(number).unwrap()
}

fn every() -> Lending {
    Lending {
        lends: hedwig_model::capability::Lends::Every,
        network: false,
    }
}

/// The relay on a port of its own, each connection carried to `server` by
/// `hedwig_core::adb::carry`, its opening served at once, and everything it
/// tells the deciding thread kept.
struct Relay {
    port: u16,
    told: Arc<Mutex<Vec<Relayed>>>,
}

impl Relay {
    fn start(server: u16, lending: Lending) -> Relay {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listening = listener.local_addr().unwrap().port();
        let told: Arc<Mutex<Vec<Relayed>>> = Arc::default();
        let kept = Arc::clone(&told);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                let (tell, heard): (Sender<Relayed>, Receiver<Relayed>) = mpsc::channel();
                let service = Service {
                    host: ServiceHost::Workstation,
                    port: port(server),
                };
                let watch = Watch::new(service.clone(), |_| {});
                let settle = hedwig_core::adb::carry(
                    stream,
                    service,
                    Carried::default(),
                    lending.clone(),
                    watch,
                    move |relayed| {
                        let _ = tell.send(relayed);
                    },
                );
                let kept = Arc::clone(&kept);
                thread::spawn(move || decide(&heard, &settle, &kept));
            }
        });
        Relay {
            port: listening,
            told,
        }
    }

    fn told(&self) -> Vec<Relayed> {
        std::mem::take(&mut *self.told.lock().unwrap())
    }
}

/// The deciding thread's part: every opening served, every reverse refused
/// as the suite reaches no device to carry it to.
fn decide(heard: &Receiver<Relayed>, settle: &Settle, kept: &Mutex<Vec<Relayed>>) {
    for relayed in heard {
        match &relayed {
            Relayed::Reached(Ok(())) => settle.settle(Ok(())),
            Relayed::Reverse(_) => settle.carry(Err(Some(Withheld::Uncarriable))),
            _ => {}
        }
        let ended = matches!(relayed, Relayed::Ended);
        kept.lock().unwrap().push(relayed);
        if ended {
            return;
        }
    }
}

fn client(adb: &Path, port: u16, arguments: &[&str]) -> Output {
    android::client(adb, "127.0.0.1", port, arguments)
}

/// Waits for the relay's connections to end and gives what they told.
fn settled(relay: &Relay) -> Vec<Relayed> {
    thread::sleep(Duration::from_millis(300));
    relay.told()
}

/// platform-tools' own client lists the server's devices through the relay,
/// and cannot end the server: `kill-server` is refused in ADB's words, and
/// the server answers afterwards as before.
#[test]
fn a_real_client_uses_a_real_server_through_the_relay_and_cannot_end_it() {
    let adb = adb();
    let server = Server::start(&adb);
    let relay = Relay::start(server.port(), every());

    let listed = client(&adb, relay.port, &["devices"]);
    assert!(listed.status.success(), "{}", said(&listed));
    assert!(said(&listed).contains("List of devices attached"));
    let told = settled(&relay);
    assert!(told.contains(&Relayed::Reached(Ok(()))), "{told:?}");
    assert!(
        !told
            .iter()
            .any(|relayed| matches!(relayed, Relayed::Withheld(_)))
    );

    let killed = client(&adb, relay.port, &["kill-server"]);
    assert!(!killed.status.success());
    assert!(
        said(&killed).contains("error: kill-server rejected by remote server"),
        "{}",
        said(&killed)
    );
    assert!(settled(&relay).contains(&Relayed::Withheld(Withheld::Ending)));
    let after = client(&adb, server.port(), &["devices"]);
    assert!(after.status.success(), "the server ended: {}", said(&after));
}

/// Dropping every network device, and having the server reach
/// an address where the grant does not acknowledge `network`, are refused
/// with ADB's `FAIL`, which the client prints; the remote's own forwards are
/// listed, none here; a device the server does not hold is ADB's own miss.
#[test]
fn what_the_relay_withholds_the_client_hears_in_adbs_own_form() {
    let adb = adb();
    let server = Server::start(&adb);
    let relay = Relay::start(server.port(), every());
    let cases: [(&[&str], Withheld, &str); 3] = [
        (&["disconnect"], Withheld::Every, "never on every device"),
        (
            &["connect", "192.0.2.1:5555"],
            Withheld::Unacknowledged,
            "only where its grant acknowledges network",
        ),
        (
            &["pair", "192.0.2.1:37000", "123456"],
            Withheld::Unacknowledged,
            "only where its grant acknowledges network",
        ),
    ];
    for (arguments, withheld, words) in cases {
        let output = client(&adb, relay.port, arguments);
        assert!(
            said(&output).contains(words),
            "{arguments:?}: {}",
            said(&output)
        );
        let told = settled(&relay);
        assert!(
            told.contains(&Relayed::Withheld(withheld.clone())),
            "{arguments:?}: {told:?}"
        );
    }
    let listed = client(&adb, relay.port, &["forward", "--list"]);
    assert!(listed.status.success(), "{}", said(&listed));
    assert!(said(&listed).trim().is_empty(), "{}", said(&listed));
    // No device: the switch a forward or a reverse makes first finds none,
    // in the server's own words.
    for arguments in [
        &["forward", "tcp:8700", "tcp:8700"][..],
        &["reverse", "tcp:8081", "tcp:8081"],
    ] {
        let output = client(&adb, relay.port, arguments);
        assert!(!output.status.success());
        assert!(said(&output).contains("no devices"), "{}", said(&output));
        let told = settled(&relay);
        assert!(
            !told
                .iter()
                .any(|relayed| matches!(relayed, Relayed::Reverse(_) | Relayed::Withheld(_))),
            "{told:?}"
        );
    }
}

/// Platform-tools 34.0.5's own server names no device tracker in its
/// `host-features` and answers none, so it is read as outdated, the watch
/// tells the deciding thread so, and a remote's selection through the relay
/// is refused in words naming the release to update to, which the current
/// client prints. The current release's server is read as listing.
#[test]
fn a_server_older_than_platform_tools_35_is_named_as_the_cause() {
    let outdated = Server::start(&android::outdated_executable());
    let at = |listening: u16| Service {
        host: ServiceHost::Workstation,
        port: port(listening),
    };
    assert_eq!(
        query(&at(outdated.port())).listing,
        Listing::Failed(Failure::Outdated)
    );
    let views: Arc<Mutex<Vec<View>>> = Arc::default();
    let kept = Arc::clone(&views);
    let watch = Watch::new(at(outdated.port()), move |view| {
        kept.lock().unwrap().push(view.clone());
    });
    watch.ensure();
    let told = views.lock().unwrap().clone();
    let [view] = told.as_slice() else {
        panic!("{told:?}")
    };
    assert_eq!(view.listing, Listing::Failed(Failure::Outdated));
    assert_eq!(view.devices, Vec::new());
    assert!(
        matches!(&view.holder, Some(holder) if matches!(holder.whose, Whose::Person { .. })),
        "the suite's own server holds the port: {view:?}"
    );

    let relay = Relay::start(outdated.port(), every());
    let selected = client(&adb(), relay.port, &["-s", "emulator-5554", "get-state"]);
    assert!(!selected.status.success());
    assert!(
        said(&selected).contains("platform-tools 35.0.0 or later"),
        "{}",
        said(&selected)
    );
    assert!(settled(&relay).contains(&Relayed::Withheld(Withheld::Outdated)));

    let current = Server::start(&adb());
    assert_eq!(query(&at(current.port())).listing, Listing::Read);
}

/// Echoes what it reads until the other end closes.
fn echo() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
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
    port
}

/// `child tap <listen> <to>`, a process that listens and carries on, as the
/// carrier does; held in `job` where one is given.
fn carrier(listen: u16, to: u16, job: Option<&Job>, log: &Path) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_child"))
        .args(["tap", &listen.to_string(), &to.to_string()])
        .arg(log)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    if let Some(job) = job {
        job.hold(&child).unwrap();
    }
    let started = Instant::now();
    while TcpStream::connect((Ipv4Addr::LOCALHOST, listen)).is_err() {
        assert!(started.elapsed() < Duration::from_secs(10));
        thread::sleep(Duration::from_millis(50));
    }
    child
}

fn round_trip(endpoint: Port) -> Vec<u8> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, endpoint.number())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // The connection stays established while it is admitted, as the
    // server's does while a device uses it.
    let _ = stream.write_all(b"ping");
    let mut back = Vec::new();
    let mut buffer = [0u8; 16];
    while back.len() < 4 {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => back.extend_from_slice(&buffer[..read]),
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    back
}

/// The endpoint carries a connection on only where it comes from the process
/// listening at the server's port, and only to a carrier the remote's
/// channel's job holds: a carrier outside the job, or a connection from any
/// other process, is closed with nothing written.
#[test]
fn an_endpoint_carries_only_the_servers_connections_and_only_to_the_channels_carrier() {
    let folder = std::env::temp_dir().join(format!("hedwig-adb-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    // The suite stands for the server: it listens at the server's port and is
    // the process connecting to the endpoint.
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server_port = server.local_addr().unwrap().port();
    let service = Service {
        host: ServiceHost::Workstation,
        port: port(server_port),
    };
    let jobs: Jobs = Jobs::default();
    let connection = ConnectionId(Seq(7));
    let job = Arc::new(Job::new().unwrap());
    jobs.lock().unwrap().insert(connection, Arc::clone(&job));
    let remote = RemoteId {
        route: Name::try_from("ssh").unwrap(),
        address: Address::try_from("dev@build-7.example").unwrap(),
    };
    let reverse = |capability: &str, target: &Target| Reverse {
        remote: remote.clone(),
        capability: Name::try_from(capability).unwrap(),
        target: target.clone(),
    };
    let target = Target::Loopback(port(8081));
    let adb = reverse("adb", &target);
    let carriage = Carriage::default();
    let endpoint = carriage
        .endpoint(adb.clone(), service.clone(), &jobs)
        .unwrap();
    assert_eq!(
        carriage
            .endpoint(adb.clone(), service.clone(), &jobs)
            .unwrap(),
        endpoint,
        "the same target has the same endpoint"
    );
    let echoed = echo();

    // No carrier yet: nothing is carried.
    assert_eq!(round_trip(endpoint), b"");

    // A carrier in the channel's job carries the server's connection.
    let inside = free_port();
    let mut held = carrier(inside, echoed, Some(&job), &folder.join("inside.log"));
    carriage.haul(&adb, connection, port(inside));
    assert!(carriage.hauled(&adb, connection));
    assert_eq!(round_trip(endpoint), b"ping");

    // Another ADB capability's server - the suite again, at a second port -
    // reversing the same target has an endpoint of its own, which admits it.
    let emulator_server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let emulator = reverse("adb-emulator", &target);
    let own = carriage
        .endpoint(
            emulator.clone(),
            Service {
                host: ServiceHost::Workstation,
                port: port(emulator_server.local_addr().unwrap().port()),
            },
            &jobs,
        )
        .unwrap();
    assert_ne!(
        own, endpoint,
        "each capability's server has its own endpoint"
    );
    assert!(!carriage.hauled(&emulator, connection));
    carriage.haul(&emulator, connection, port(inside));
    assert_eq!(round_trip(own), b"ping");

    // A process outside the job at the carrier's port is not the carrier.
    let outside = free_port();
    let mut stray = carrier(outside, echoed, None, &folder.join("outside.log"));
    carriage.haul(&adb, connection, port(outside));
    assert_eq!(round_trip(endpoint), b"");

    // A connection from a process other than the server's is not carried:
    // the server's port is now another process's.
    let other = Target::Loopback(port(9000));
    let elsewhere = free_port();
    let mut foreign_server = carrier(elsewhere, echoed, None, &folder.join("server.log"));
    let foreign = Service {
        host: ServiceHost::Workstation,
        port: port(elsewhere),
    };
    let other = reverse("adb", &other);
    let second = carriage.endpoint(other.clone(), foreign, &jobs).unwrap();
    carriage.haul(&other, connection, port(inside));
    assert_eq!(round_trip(second), b"");

    for child in [&mut held, &mut stray, &mut foreign_server] {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = job.end();
    drop(server);
    drop(emulator_server);
    let _ = std::fs::remove_dir_all(&folder);
}

/// What the server says of itself reaches the remote without the
/// workstation's own paths: the person's client, at the server, reads the
/// executable, the log, the key store and the known hosts; the remote's,
/// through the relay, reads the same status less those four.
#[test]
fn the_servers_status_reaches_the_remote_without_the_workstations_paths() {
    let adb = adb();
    let server = Server::start(&adb);
    let relay = Relay::start(server.port(), every());
    let own = client(&adb, server.port(), &["server-status"]);
    assert!(own.status.success(), "{}", said(&own));
    let theirs = client(&adb, relay.port, &["server-status"]);
    assert!(theirs.status.success(), "{}", said(&theirs));
    let (own, theirs) = (said(&own), said(&theirs));
    let paths = [
        "executable_absolute_path",
        "log_absolute_path",
        "keystore_path",
        "known_hosts_path",
    ];
    for path in paths {
        assert!(own.contains(path), "{path} in {own}");
        assert!(!theirs.contains(path), "{path} in {theirs}");
    }
    let kept = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| !paths.iter().any(|path| line.contains(path)))
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(kept(&theirs), kept(&own));
    assert!(theirs.contains("version: \"37.0.1"), "{theirs}");
}

/// Accepts every connection and holds it without a word: a device whose
/// address platform-tools' own server connects to and lists offline.
fn silent() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    port
}

/// A listing that cannot be had says what failed - nothing listening at
/// the server's port, or something there that is no ADB server, which
/// answers the tracker with what it was sent.
#[test]
fn a_listing_that_cannot_be_had_says_what_failed() {
    let at = |listening: u16| Service {
        host: ServiceHost::Workstation,
        port: port(listening),
    };
    assert_eq!(
        query(&at(free_port())).listing,
        Listing::Failed(Failure::Unreachable)
    );
    assert_eq!(
        query(&at(echo())).listing,
        Listing::Failed(Failure::Mismatched)
    );
}

/// A watch of platform-tools' own server tells each listing as the
/// server changes it - a device connected by its address appears, then goes
/// - and tells the server's going away as nothing answering.
#[test]
fn a_watch_tells_each_change_of_the_servers_devices_and_its_end() {
    let adb = adb();
    let server = Server::start(&adb);
    let (tell, told) = mpsc::channel::<View>();
    let tell = Mutex::new(tell);
    let watch = Watch::new(
        Service {
            host: ServiceHost::Workstation,
            port: port(server.port()),
        },
        move |view| {
            let _ = tell.lock().unwrap().send(view.clone());
        },
    );
    watch.ensure();
    let next = || told.recv_timeout(Duration::from_secs(20)).unwrap();
    let first = next();
    assert_eq!(first.listing, Listing::Read);
    assert_eq!(first.devices, Vec::new());
    assert!(
        matches!(&first.holder, Some(holder) if matches!(holder.whose, Whose::Person { .. })),
        "the suite's own server holds the port: {first:?}"
    );
    let device = format!("127.0.0.1:{}", silent());
    let connected = client(&adb, server.port(), &["connect", &device]);
    assert!(said(&connected).contains(&device), "{}", said(&connected));
    let view = next();
    assert_eq!(view.listing, Listing::Read);
    assert_eq!(
        view.devices
            .iter()
            .map(|listed| listed.serial.as_str())
            .collect::<Vec<_>>(),
        [device.as_str()]
    );
    let gone = client(&adb, server.port(), &["disconnect", &device]);
    assert!(gone.status.success(), "{}", said(&gone));
    let view = loop {
        let view = next();
        if view.devices.is_empty() {
            break view;
        }
    };
    assert_eq!(view.listing, Listing::Read);
    drop(server);
    assert_eq!(next(), View::failed(Failure::Unreachable));
}
