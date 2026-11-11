//! The workstation end of a forward: a loopback port the core binds for one
//! run and tells only the channel it is for.
//!
//! The port is one Windows picks. A port carries no access list, so whoever
//! connects is looked up in the system's own table of connections, which
//! names the process that owns the other end.

use std::io;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::os::windows::io::AsRawSocket;

use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP_STATE_ESTAB, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, FD_ACCEPT, INVALID_SOCKET, SOCKET, WSAEnumNetworkEvents, WSAEventSelect,
    WSAGetLastError, WSANETWORKEVENTS,
};
use windows_sys::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};

use crate::raw::Signal;

fn last() -> io::Error {
    // SAFETY: reads this thread's last socket error.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

fn socket_of(socket: &impl AsRawSocket) -> SOCKET {
    SOCKET::try_from(socket.as_raw_socket()).unwrap_or(INVALID_SOCKET)
}

/// An event as the socket functions take one: the handle's own number.
fn event_of(signal: &Signal) -> isize {
    signal.raw().addr().cast_signed()
}

/// One loopback port, listening.
#[derive(Debug)]
pub struct Endpoint {
    listener: TcpListener,
    port: u16,
    /// Raised by the system when a connection waits to be accepted.
    arrived: Signal,
}

impl Endpoint {
    /// Binds a port of the system's choosing on `127.0.0.1`. While it is
    /// held no other socket can be bound to that address and port, whatever
    /// that socket asks for, and no process this one starts inherits it.
    ///
    /// # Errors
    ///
    /// What the system said.
    pub fn bind() -> io::Result<Endpoint> {
        Endpoint::listening(TcpListener::bind(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            0,
        ))?)
    }

    /// Binds `port` on `address`, held as [`Endpoint::bind`] holds its own.
    ///
    /// # Errors
    ///
    /// What the system said: [`io::ErrorKind::AddrInUse`] or
    /// [`io::ErrorKind::PermissionDenied`] where another socket holds the
    /// port there, [`io::ErrorKind::AddrNotAvailable`] where the workstation
    /// has no such address.
    pub fn bind_at(address: IpAddr, port: u16) -> io::Result<Endpoint> {
        Endpoint::listening(TcpListener::bind(SocketAddr::new(address, port))?)
    }

    fn listening(listener: TcpListener) -> io::Result<Endpoint> {
        let port = listener.local_addr()?.port();
        let arrived = Signal::new()?;
        // SAFETY: the socket and the event are open; from here the event is
        // raised when a connection waits, and the socket no longer blocks.
        let selected = unsafe {
            WSAEventSelect(
                socket_of(&listener),
                event_of(&arrived),
                FD_ACCEPT.cast_signed(),
            )
        };
        if selected != 0 {
            return Err(last());
        }
        Ok(Endpoint {
            listener,
            port,
            arrived,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Waits for the next connection, or for `stop`; `None` when stopped.
    ///
    /// # Errors
    ///
    /// What the system said.
    pub fn accept(&self, stop: &Signal) -> io::Result<Option<TcpStream>> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    // An accepted socket takes after its listener: it is
                    // given back to blocking calls with no event of its own.
                    // SAFETY: the socket is open; no event and no network
                    // events clears the selection.
                    if unsafe { WSAEventSelect(socket_of(&stream), 0, 0) } != 0 {
                        return Err(last());
                    }
                    stream.set_nonblocking(false)?;
                    return Ok(Some(stream));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            let waited = [self.arrived.raw(), stop.raw()];
            // SAFETY: `waited` holds two valid event handles.
            let which = unsafe { WaitForMultipleObjects(2, waited.as_ptr(), 0, INFINITE) };
            if which != WAIT_OBJECT_0 {
                return Ok(None);
            }
            // SAFETY: all-zero is a valid value for the structure the call
            // fills.
            let mut events: WSANETWORKEVENTS = unsafe { std::mem::zeroed() };
            // SAFETY: the socket and the event are open and `events` is a
            // valid out pointer; the call lowers the event again.
            let reset = unsafe {
                WSAEnumNetworkEvents(
                    socket_of(&self.listener),
                    event_of(&self.arrived),
                    &raw mut events,
                )
            };
            if reset != 0 {
                return Err(last());
            }
        }
    }
}

/// A port as the table writes it: in network order, in the low half.
fn port_of(raw: u32) -> u16 {
    let [high, low, _, _] = raw.to_ne_bytes();
    u16::from_be_bytes([high, low])
}

/// The number of the process on this workstation that owns the other end of
/// `stream`, a connection still established, from the system's table of
/// connections. `None` when the table holds no such connection: the other
/// end has closed, or is not on this workstation.
///
/// # Errors
///
/// What the system said, or that the two ends are of different families.
pub fn owner(stream: &TcpStream) -> io::Result<Option<u32>> {
    match (stream.peer_addr()?, stream.local_addr()?) {
        (SocketAddr::V4(theirs), SocketAddr::V4(ours)) => owner_v4(theirs, ours),
        (SocketAddr::V6(theirs), SocketAddr::V6(ours)) => owner_v6(theirs, ours),
        _ => Err(io::Error::from(io::ErrorKind::Unsupported)),
    }
}

/// The system's table of connections of `family`, read whole into a buffer
/// aligned for it.
fn table(family: u16) -> io::Result<Vec<u64>> {
    let mut size = 0u32;
    // The table can grow between the call that sizes it and the one that
    // reads it, so the read is tried again with the size it then asks for.
    for _ in 0..8 {
        let mut buffer = vec![0u64; (size as usize).div_ceil(8).max(1)];
        let given = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
        size = given;
        // SAFETY: `buffer` is `given` writable bytes, aligned for the table.
        let failed = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast(),
                &raw mut size,
                0,
                u32::from(family),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if failed == 0 {
            return Ok(buffer);
        }
    }
    Err(io::Error::from(io::ErrorKind::ResourceBusy))
}

fn owner_v6(theirs: SocketAddrV6, ours: SocketAddrV6) -> io::Result<Option<u32>> {
    let buffer = table(AF_INET6)?;
    let table = buffer.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
    // SAFETY: the call succeeded, so the buffer starts with the table's count
    // of rows.
    let count = unsafe { (*table).dwNumEntries } as usize;
    // SAFETY: the rows follow the count, inside `buffer`.
    let first = unsafe { &raw const (*table).table }.cast::<MIB_TCP6ROW_OWNER_PID>();
    // SAFETY: the call wrote `count` rows starting at `first`, all within
    // `buffer`, which outlives this slice.
    let rows = unsafe { std::slice::from_raw_parts(first, count) };
    Ok(rows
        .iter()
        .find(|row| {
            let local = SocketAddrV6::new(
                Ipv6Addr::from(row.ucLocalAddr),
                port_of(row.dwLocalPort),
                0,
                row.dwLocalScopeId,
            );
            let remote = SocketAddrV6::new(
                Ipv6Addr::from(row.ucRemoteAddr),
                port_of(row.dwRemotePort),
                0,
                row.dwRemoteScopeId,
            );
            row.dwState == MIB_TCP_STATE_ESTAB.cast_unsigned()
                && local.ip() == theirs.ip()
                && local.port() == theirs.port()
                && remote.ip() == ours.ip()
                && remote.port() == ours.port()
        })
        .map(|row| row.dwOwningPid))
}

fn owner_v4(theirs: SocketAddrV4, ours: SocketAddrV4) -> io::Result<Option<u32>> {
    let buffer = table(AF_INET)?;
    let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    // SAFETY: the call succeeded, so the buffer starts with the table's count
    // of rows.
    let count = unsafe { (*table).dwNumEntries } as usize;
    // SAFETY: the rows follow the count, inside `buffer`.
    let first = unsafe { &raw const (*table).table }.cast::<MIB_TCPROW_OWNER_PID>();
    // SAFETY: the call wrote `count` rows starting at `first`, all within
    // `buffer`, which outlives this slice.
    let rows = unsafe { std::slice::from_raw_parts(first, count) };
    Ok(rows
        .iter()
        .find(|row| {
            let local = SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(row.dwLocalAddr)),
                port_of(row.dwLocalPort),
            );
            let remote = SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)),
                port_of(row.dwRemotePort),
            );
            row.dwState == MIB_TCP_STATE_ESTAB.cast_unsigned() && local == theirs && remote == ours
        })
        .map(|row| row.dwOwningPid))
}
