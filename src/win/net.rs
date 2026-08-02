use std::io;
use std::net::TcpListener;
use std::os::windows::io::{FromRawSocket, RawSocket};
use std::sync::Once;

use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, INVALID_SOCKET, IPPROTO_TCP, SO_EXCLUSIVEADDRUSE, SOCK_STREAM,
    SOCKADDR_IN, SOCKET, SOL_SOCKET, WSADATA, WSAGetLastError, WSAStartup, bind, listen,
    setsockopt, socket,
};

/// Win32 takes buffer lengths as `i32`; every argument here is a `size_of`,
/// so the width is fixed at compile time.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "size_of of a fixed-layout type"
)]
const fn len_of<T>() -> i32 {
    size_of::<T>() as i32
}

/// `SO_EXCLUSIVEADDRUSE` is what stops another process taking the port over with
/// `SO_REUSEADDR` while the relay holds it.
pub(crate) fn bind_loopback_exclusive(port: u16) -> io::Result<TcpListener> {
    winsock_init();
    let socket: SOCKET = unsafe { socket(i32::from(AF_INET), SOCK_STREAM, IPPROTO_TCP) };
    if socket == INVALID_SOCKET {
        return Err(wsa_error("socket"));
    }
    // Ownership passes to the listener before anything can fail, so every error
    // path below closes the socket by dropping it.
    let listener = unsafe { TcpListener::from_raw_socket(socket as RawSocket) };

    let exclusive: u32 = 1;
    let rc = unsafe {
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&raw const exclusive).cast(),
            len_of::<u32>(),
        )
    };
    if rc != 0 {
        return Err(wsa_error("setsockopt(SO_EXCLUSIVEADDRUSE)"));
    }

    let addr = SOCKADDR_IN {
        sin_family: AF_INET,
        // Network byte order, as htons would give; a swap needs no FFI call.
        sin_port: port.to_be(),
        // S_addr holds the four address bytes in network order; from_ne_bytes
        // stores [127,0,0,1] into the u32 so its memory layout is 127.0.0.1.
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
        },
        sin_zero: [0; 8],
    };
    let rc = unsafe { bind(socket, (&raw const addr).cast(), len_of::<SOCKADDR_IN>()) };
    if rc != 0 {
        return Err(wsa_error("bind"));
    }

    if unsafe { listen(socket, 128) } != 0 {
        return Err(wsa_error("listen"));
    }
    Ok(listener)
}

fn winsock_init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        unsafe { WSAStartup(0x0202, &raw mut data) };
    });
}

fn wsa_error(call: &str) -> io::Error {
    let code = unsafe { WSAGetLastError() };
    io::Error::other(format!("{call} failed with WSA error {code}"))
}
