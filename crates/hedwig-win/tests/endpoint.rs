//! The workstation end of a forward: a port no other socket can take, a wait
//! that can be stopped, who connected, and the release a program states.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use hedwig_win::Signal;
use hedwig_win::endpoint::{Endpoint, owner};
use hedwig_win::search::program;
use hedwig_win::version::release;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, INVALID_SOCKET, IPPROTO_TCP, SO_REUSEADDR, SOCK_STREAM, SOCKADDR,
    SOCKADDR_IN, SOL_SOCKET, WSAGetLastError, WSASocketW, bind, listen, setsockopt,
};

/// What binding over a held address fails with: access is refused.
const ACCESS: i32 = 10013;

fn socket_of(listener: &TcpListener) -> usize {
    usize::try_from(listener.as_raw_socket()).unwrap()
}

/// Tries to take `port` on `address` the way a socket that means to share an
/// address does: by asking to reuse it.
fn take(address: Ipv4Addr, port: u16) -> io::Result<OwnedSocket> {
    // SAFETY: a plain TCP socket with no protocol information.
    let raw = unsafe {
        WSASocketW(
            i32::from(AF_INET),
            SOCK_STREAM,
            IPPROTO_TCP,
            std::ptr::null(),
            0,
            0,
        )
    };
    assert_ne!(raw, INVALID_SOCKET);
    // SAFETY: the socket was just created and nothing else owns it.
    let socket = unsafe { OwnedSocket::from_raw_socket(u64::try_from(raw).unwrap()) };
    let reuse = 1i32;
    // SAFETY: the option takes an `i32` of the length given.
    let set = unsafe { setsockopt(raw, SOL_SOCKET, SO_REUSEADDR, (&raw const reuse).cast(), 4) };
    assert_eq!(set, 0);
    let address = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from(address).to_be(),
            },
        },
        sin_zero: [0; 8],
    };
    let length = i32::try_from(size_of::<SOCKADDR_IN>()).unwrap();
    // SAFETY: `address` is an IPv4 socket address of the length given.
    if unsafe { bind(raw, (&raw const address).cast::<SOCKADDR>(), length) } != 0 {
        // SAFETY: reads this thread's last socket error.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(socket)
}

/// A socket that asks to reuse the endpoint's own address is refused it,
/// with nothing set on the endpoint to make it so. One that takes the same
/// port on every address at once is given it, and gets none of what is sent
/// to the endpoint: a connection to loopback reaches the socket bound to
/// loopback.
#[test]
fn no_other_socket_takes_what_is_sent_to_the_endpoint() {
    let endpoint = Endpoint::bind().unwrap();
    assert_ne!(endpoint.port(), 0);
    let refused = take(Ipv4Addr::LOCALHOST, endpoint.port()).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(ACCESS), "{refused}");

    let beside = take(Ipv4Addr::UNSPECIFIED, endpoint.port()).unwrap();
    let beside = TcpListener::from(beside);
    // SAFETY: the socket is bound.
    assert_eq!(unsafe { listen(socket_of(&beside), 16) }, 0);
    beside.set_nonblocking(true).unwrap();
    let stop = Signal::new().unwrap();
    for _ in 0..8 {
        let _client = connect(&endpoint);
        assert!(endpoint.accept(&stop).unwrap().is_some());
        assert!(beside.accept().is_err(), "it was sent to the endpoint");
    }
}

fn connect(endpoint: &Endpoint) -> TcpStream {
    TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, endpoint.port())).unwrap()
}

/// The wait for a connection gives each one as it comes, able to be read in
/// the ordinary way, and ends when it is told to stop.
#[test]
fn the_wait_gives_each_connection_and_can_be_stopped() {
    let endpoint = Arc::new(Endpoint::bind().unwrap());
    let stop = Arc::new(Signal::new().unwrap());
    let accepting = {
        let (endpoint, stop) = (Arc::clone(&endpoint), Arc::clone(&stop));
        thread::spawn(move || {
            let mut read = Vec::new();
            while let Some(mut stream) = endpoint.accept(&stop).unwrap() {
                let mut byte = [0u8; 1];
                io::Read::read_exact(&mut stream, &mut byte).unwrap();
                read.extend(byte);
            }
            read
        })
    };
    for byte in *b"abc" {
        let mut client = connect(&endpoint);
        // Sent a moment after connecting, so the read has to wait for it.
        thread::sleep(Duration::from_millis(20));
        client.write_all(&[byte]).unwrap();
    }
    thread::sleep(Duration::from_millis(100));
    stop.raise().unwrap();
    assert_eq!(accepting.join().unwrap(), b"abc");
}

/// The table of connections names the process that owns the other end, and
/// names nobody once that end has closed.
#[test]
fn who_connected_is_the_process_that_holds_the_other_end() {
    let endpoint = Endpoint::bind().unwrap();
    let stop = Signal::new().unwrap();
    let client = connect(&endpoint);
    let accepted = endpoint.accept(&stop).unwrap().unwrap();
    assert_eq!(owner(&accepted).unwrap(), Some(std::process::id()));

    drop(client);
    let deadline = Instant::now() + Duration::from_secs(5);
    while owner(&accepted).unwrap().is_some() {
        assert!(Instant::now() < deadline, "the closed end is still named");
        thread::sleep(Duration::from_millis(10));
    }
}

/// The release is the one the file states: the workstation's own OpenSSH
/// client states one, this suite's own program none, and a file that is not
/// there is an error.
#[test]
fn a_programs_release_is_what_its_file_states() {
    let ssh = program("ssh").unwrap();
    let [major, ..] = release(&ssh).unwrap().expect("ssh.exe states its release");
    assert!(major >= 8, "{major}");
    assert_eq!(release(&std::env::current_exe().unwrap()).unwrap(), None);
    assert!(release(&ssh.with_file_name("no-such-program.exe")).is_err());
}
