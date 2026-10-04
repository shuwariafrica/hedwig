//! The relay for a workstation service, with real sockets: a service of this
//! account on the loopback in either family, one named by its host, one that
//! is not there, and a service an administrator installed.
//!
//! A connection is handed over as the forward's end hands one over: accepted
//! on a loopback port, its other end standing for the remote's tool. What is
//! decided is the suite's to say, as the deciding thread would.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use hedwig_core::relay::{Relayed, Settle};
use hedwig_core::service::{Service, admitted, carry, reach};
use hedwig_model::capability::ServiceHost;
use hedwig_model::holder::{Rights, SignedIn, Whose};
use hedwig_model::refusal::Refusal;
use hedwig_model::text::{Host, Port};
use hedwig_model::trail::Failure;
use hedwig_support::lower::{Level, Lowered, logon_sid};

const WAIT: Duration = Duration::from_secs(10);

/// A connection as the forward's end hands one over: the remote's tool's
/// end, and the end the relay is given.
fn forwarded() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    (remote, accepted)
}

/// A service of this account on `address` that echoes everything it reads
/// on one connection, closes its side when the other has, and gives back
/// what it read.
fn echo(address: &str) -> (Port, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind(address).unwrap();
    let port = Port::try_from(listener.local_addr().unwrap().port()).unwrap();
    let served = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut read = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    read.extend_from_slice(&buffer[..count]);
                    if stream.write_all(&buffer[..count]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = stream.shutdown(Shutdown::Write);
        read
    });
    (port, served)
}

fn on_workstation(port: Port) -> Service {
    Service {
        host: ServiceHost::Workstation,
        port,
    }
}

/// Carries `forward` to `service`, with what the relay tells the deciding
/// thread on a channel the suite reads.
fn carried(forward: TcpStream, service: Service) -> (std::sync::Arc<Settle>, Receiver<Relayed>) {
    let (told, hears) = mpsc::channel();
    let settle = carry(forward, service, move |relayed| {
        let _ = told.send(relayed);
    });
    (settle, hears)
}

/// The relay's first word: what held the service, here the suite's own.
fn held_by_the_person(hears: &Receiver<Relayed>) {
    match hears.recv_timeout(WAIT).unwrap() {
        Relayed::Held(Some(holder)) => {
            assert!(matches!(holder.whose, Whose::Person { .. }), "{holder:?}");
        }
        other => panic!("{other:?}"),
    }
}

fn read_all(mut remote: TcpStream) -> Vec<u8> {
    remote.set_read_timeout(Some(WAIT)).unwrap();
    let mut back = Vec::new();
    remote.read_to_end(&mut back).unwrap();
    back
}

/// What reaches the remote's end before it is closed or reset: Windows
/// resets a connection closed with bytes it never read, which is the remote
/// told nothing all the same.
fn received(mut remote: TcpStream) -> Vec<u8> {
    remote.set_read_timeout(Some(WAIT)).unwrap();
    let mut back = Vec::new();
    match remote.read_to_end(&mut back) {
        Ok(_) => {}
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
    back
}

/// Served, what the remote sent while it was decided reaches the service
/// first, then everything after it, both ways, and each end's close reaches
/// the other.
#[test]
fn a_served_connection_is_carried_both_ways_from_its_first_byte() {
    let (port, service) = echo("127.0.0.1:0");
    let (mut remote, forward) = forwarded();
    remote.write_all(b"early ").unwrap();
    let (settle, hears) = carried(forward, on_workstation(port));
    held_by_the_person(&hears);
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Reached(Ok(())));
    settle.settle(Ok(()));
    remote.write_all(b"and later").unwrap();
    remote.shutdown(Shutdown::Write).unwrap();
    assert_eq!(read_all(remote), b"early and later");
    assert_eq!(service.join().unwrap(), b"early and later");
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Ended);
}

/// What the remote sends while its connection is decided waits, held back
/// in the connection beyond a bounded amount the relay takes, and none of it
/// is lost once the connection is served.
#[test]
fn what_the_remote_sends_while_it_is_decided_waits_and_is_not_lost() {
    let (port, service) = echo("127.0.0.1:0");
    let (remote, forward) = forwarded();
    let sent: Vec<u8> = (0..(4u32 << 20))
        .map(|index| index.to_le_bytes()[0])
        .collect();
    let mut writer = remote.try_clone().unwrap();
    let to_send = sent.clone();
    let writing = thread::spawn(move || {
        writer.write_all(&to_send).unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
    });
    let (settle, hears) = carried(forward, on_workstation(port));
    held_by_the_person(&hears);
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Reached(Ok(())));
    thread::sleep(Duration::from_millis(300));
    settle.settle(Ok(()));
    assert_eq!(read_all(remote), sent);
    writing.join().unwrap();
    assert_eq!(service.join().unwrap(), sent);
}

/// Refused, nothing the remote sent reaches the service and nothing is
/// written back: the remote's tool reads the end of its connection.
#[test]
fn a_refused_connection_reaches_nothing_and_is_told_nothing() {
    let (port, service) = echo("127.0.0.1:0");
    let (mut remote, forward) = forwarded();
    remote.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let (settle, hears) = carried(forward, on_workstation(port));
    held_by_the_person(&hears);
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Reached(Ok(())));
    settle.settle(Err(Refusal::Declined));
    assert_eq!(received(remote), b"");
    assert_eq!(service.join().unwrap(), b"");
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Ended);
}

/// A service that is not there is the workstation's side failing; told so,
/// the deciding thread refuses the opening and the remote reads the end of
/// its connection.
#[test]
fn a_service_that_is_not_there_is_said_and_the_remote_told_nothing() {
    let free = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = Port::try_from(free.local_addr().unwrap().port()).unwrap();
    drop(free);
    let (remote, forward) = forwarded();
    let (settle, hears) = carried(forward, on_workstation(port));
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Held(None));
    assert_eq!(
        hears.recv_timeout(WAIT).unwrap(),
        Relayed::Reached(Err(Failure::Unreachable))
    );
    settle.settle(Err(Refusal::SourceUnavailable {
        capability: hedwig_model::text::Name::try_from("openocd").unwrap(),
        failure: Failure::Unreachable,
    }));
    assert_eq!(read_all(remote), b"");
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Ended);
}

/// A remote that gives up while its connection is decided ends it, so the
/// deciding thread can settle the request as abandoned; nothing reaches the
/// service.
#[test]
fn a_remote_that_gives_up_while_it_is_decided_ends_the_connection() {
    let (port, service) = echo("127.0.0.1:0");
    let (remote, forward) = forwarded();
    let (_settle, hears) = carried(forward, on_workstation(port));
    held_by_the_person(&hears);
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Reached(Ok(())));
    drop(remote);
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Ended);
    assert_eq!(service.join().unwrap(), b"");
}

/// A connection ends with the channel it came through: the route's client
/// ends with the channel's job, its end of the forward closes, and the relay
/// passes that on to the service.
#[test]
fn a_carried_connection_ends_with_its_channel() {
    let (port, service) = echo("127.0.0.1:0");
    let (mut remote, forward) = forwarded();
    let (settle, hears) = carried(forward, on_workstation(port));
    held_by_the_person(&hears);
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Reached(Ok(())));
    settle.settle(Ok(()));
    remote.write_all(b"ping").unwrap();
    let mut back = [0u8; 4];
    remote.set_read_timeout(Some(WAIT)).unwrap();
    remote.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"ping");
    drop(remote);
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Ended);
    assert_eq!(service.join().unwrap(), b"ping");
}

/// A service on the workstation's loopback is reached in either family: one
/// listening on `::1` alone is found there, and its listener is read and
/// admitted as this account's.
#[test]
fn a_service_listening_on_the_ipv6_loopback_alone_is_reached_and_admitted() {
    let (port, service) = echo("[::1]:0");
    let (mut remote, forward) = forwarded();
    let (settle, hears) = carried(forward, on_workstation(port));
    held_by_the_person(&hears);
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Reached(Ok(())));
    settle.settle(Ok(()));
    remote.write_all(b"six").unwrap();
    remote.shutdown(Shutdown::Write).unwrap();
    assert_eq!(read_all(remote), b"six");
    assert_eq!(service.join().unwrap(), b"six");
}

/// A service named by its host is reached at what the system's resolver
/// says of the name, and a listener that turns out to be on this
/// workstation is checked as one; a name the resolver has no address for is
/// said as that.
#[test]
fn a_service_named_by_its_host_is_resolved_and_a_name_with_no_address_said() {
    let (port, service) = echo("127.0.0.1:0");
    let named = Service {
        host: ServiceHost::Named(Host::try_from("localhost").unwrap()),
        port,
    };
    let (mut remote, forward) = forwarded();
    let (settle, hears) = carried(forward, named);
    held_by_the_person(&hears);
    assert_eq!(hears.recv_timeout(WAIT).unwrap(), Relayed::Reached(Ok(())));
    settle.settle(Ok(()));
    remote.write_all(b"by name").unwrap();
    remote.shutdown(Shutdown::Write).unwrap();
    assert_eq!(read_all(remote), b"by name");
    assert_eq!(service.join().unwrap(), b"by name");

    let nowhere = Service {
        host: ServiceHost::Named(Host::try_from("hedwig-no-such-host.invalid").unwrap()),
        port,
    };
    assert_eq!(reach(&nowhere).result.err(), Some(Failure::NoAddress));
}

/// The listener check: the person's own is admitted as theirs, and so is a
/// service an administrator installed, whose token is closed to this
/// account, named by the services the service control manager runs in it:
/// the RPC endpoint mapper, which Windows runs as Network Service on port 135.
#[test]
fn a_listener_is_admitted_as_the_persons_or_an_installed_services() {
    let own = TcpListener::bind("127.0.0.1:0").unwrap();
    let to_own = TcpStream::connect(own.local_addr().unwrap()).unwrap();
    let (admission, holder) = admitted(&to_own);
    assert_eq!(admission, Ok(()));
    let holder = holder.unwrap();
    // The suite's own rights: a full administrator's token, as the built-in
    // Administrator's is, carries them.
    let own_rights = if hedwig_win::token::Token::own().unwrap().elevated().unwrap() {
        Rights::Administrator
    } else {
        Rights::Standard
    };
    assert!(
        matches!(
            holder.whose,
            Whose::Person {
                signed_in: SignedIn::Locally,
                rights,
                ..
            } if rights == own_rights
        ),
        "{holder:?}"
    );
    assert!(
        std::path::Path::new(holder.program.as_str())
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe")),
        "{holder:?}"
    );

    let to_service = TcpStream::connect(("127.0.0.1", 135)).unwrap();
    let listener = hedwig_win::endpoint::owner(&to_service).unwrap().unwrap();
    assert!(
        hedwig_win::process::Process::open(listener)
            .and_then(|process| process.token())
            .is_err(),
        "its token is closed to this account"
    );
    let (admission, holder) = admitted(&to_service);
    assert_eq!(admission, Ok(()));
    let holder = holder.unwrap();
    assert_eq!(holder.session, 0);
    match &holder.whose {
        Whose::Service { services } => assert!(
            services.iter().any(|service| service.as_str() == "RpcSs"),
            "{services:?}"
        ),
        other => panic!("{other:?}"),
    }
}

/// A free loopback port, for a holder started apart to listen at.
fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

/// The suite's stand-in holder at `port`, started by `start`, once it
/// listens.
fn holding(port: u16, start: impl FnOnce(&str) -> Lowered) -> Lowered {
    let line = format!("\"{}\" {port}", env!("CARGO_BIN_EXE_holding"));
    let holder = start(&line);
    // A connection to a port nothing listens on takes Windows two seconds
    // to refuse, so the holder is waited for on the clock and by its end.
    let deadline = std::time::Instant::now() + WAIT;
    while std::time::Instant::now() < deadline {
        if let Some(ended) = holder.wait(Duration::from_millis(25)) {
            panic!("the holder ended {ended:#x} before it listened on {port}");
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return holder;
        }
    }
    panic!("the holder never listened on {port}");
}

/// How a stand-in holder is started, given its command line.
type Start = Box<dyn FnOnce(&str) -> Lowered>;

/// How many bytes reached the stand-in holder at `port` before this asked.
fn reached_it(port: u16) -> usize {
    let mut asking = TcpStream::connect(("127.0.0.1", port)).unwrap();
    asking
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut told = String::new();
    let mut byte = [0u8; 1];
    while asking.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
        told.push(char::from(byte[0]));
    }
    told.parse().unwrap()
}

/// The person's own account, which Windows confines below the person - at
/// low integrity, or restricted to a list that leaves the account out - is
/// refused as confined, and a remote's connection carried there reaches
/// nothing; restricted to a list that keeps the account, it is the person.
#[test]
fn a_listener_windows_confines_below_the_person_is_refused_and_reached_by_nothing() {
    let logon = logon_sid().unwrap();
    let person = hedwig_win::token::Token::own()
        .unwrap()
        .user()
        .unwrap()
        .to_text()
        .unwrap();
    let without: Vec<String> = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-12", &logon]
        .iter()
        .map(|sid| (*sid).to_owned())
        .collect();
    let mut with = without.clone();
    with.push(person);
    let cases: [(&str, Start, Option<Failure>); 3] = [
        (
            "low integrity",
            Box::new(|line: &str| Lowered::apart_at(Level::Low, line).unwrap()),
            Some(Failure::Confined),
        ),
        (
            "restricted to less than the account",
            Box::new(move |line: &str| {
                let list: Vec<&str> = without.iter().map(String::as_str).collect();
                Lowered::restricted_to(&list, line).unwrap()
            }),
            Some(Failure::Confined),
        ),
        (
            "restricted to a list that keeps the account",
            Box::new(move |line: &str| {
                let list: Vec<&str> = with.iter().map(String::as_str).collect();
                Lowered::restricted_to(&list, line).unwrap()
            }),
            None,
        ),
    ];
    for (case, start, refused) in cases {
        let port = free_port();
        let _holder = holding(port, start);
        let to_it = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (admission, holder) = admitted(&to_it);
        drop(to_it);
        let holder = holder.unwrap();
        if let Some(failure) = refused {
            assert_eq!(admission, Err(failure), "{case}");
            assert_eq!(holder.whose, Whose::Confined, "{case}");
            let (mut remote, forward) = forwarded();
            let (settle, told) = carried(forward, on_workstation(Port::try_from(port).unwrap()));
            remote.write_all(b"host:version").unwrap();
            assert_eq!(
                told.recv_timeout(Duration::from_secs(10)).unwrap(),
                Relayed::Held(Some(holder.clone())),
                "{case}"
            );
            assert_eq!(
                told.recv_timeout(Duration::from_secs(10)).unwrap(),
                Relayed::Reached(Err(failure)),
                "{case}"
            );
            settle.settle(Err(Refusal::SourceUnavailable {
                capability: hedwig_model::text::Name::try_from("held").unwrap(),
                failure,
            }));
            assert!(
                received(remote).is_empty(),
                "{case}: the remote is told nothing"
            );
            assert_eq!(reached_it(port), 0, "{case}: nothing reached the holder");
        } else {
            assert_eq!(admission, Ok(()), "{case}");
            assert!(
                matches!(holder.whose, Whose::Person { .. }),
                "{case}: {holder:?}"
            );
        }
    }
}

/// A listener whose token Windows keeps from this account, and in which no
/// service runs, is refused as unidentified, read as its session and name:
/// the System process, which holds the SMB port for the kernel.
#[test]
fn a_listener_windows_will_not_describe_is_unidentified() {
    let to_it = TcpStream::connect(("127.0.0.1", 445))
        .expect("needs Windows' own file sharing listening on port 445, as it does by default");
    assert_eq!(hedwig_win::endpoint::owner(&to_it).unwrap(), Some(4));
    let (admission, holder) = admitted(&to_it);
    assert_eq!(admission, Err(Failure::Unidentified));
    let holder = holder.unwrap();
    assert_eq!(holder.whose, Whose::Unread);
    assert_eq!(holder.session, 0);
    assert_eq!(holder.program.as_str(), "System");
}
