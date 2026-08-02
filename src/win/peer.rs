use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP_STATE_ESTAB, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, IsTokenRestricted, TOKEN_QUERY, TOKEN_USER, TokenIsAppContainer,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PeerError {
    NotLoopback(std::net::SocketAddr),
    /// No established loopback TCP row matches the peer's endpoint. Either the
    /// peer vanished between accept and lookup, or the endpoint is not local.
    NoOwner(SocketAddrV4),
    ProcessQuery(u32, String),
    NotSameUser(u32),
    AppContainer(u32),
    RestrictedToken(u32),
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerError::NotLoopback(a) => write!(f, "peer {a} is not 127.0.0.1"),
            PeerError::NoOwner(a) => write!(f, "no owning process found for peer {a}"),
            PeerError::ProcessQuery(pid, e) => write!(f, "cannot query process {pid}: {e}"),
            PeerError::NotSameUser(pid) => {
                write!(f, "process {pid} does not run as the relay's user")
            }
            PeerError::AppContainer(pid) => write!(f, "process {pid} runs in an AppContainer"),
            PeerError::RestrictedToken(pid) => {
                write!(f, "process {pid} runs with a restricted token")
            }
        }
    }
}

impl std::error::Error for PeerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpRow {
    local: SocketAddrV4,
    remote: SocketAddrV4,
    established: bool,
    pid: u32,
}

/// Loopback TCP shows one row per side, so matching both addresses and the
/// established state is what pins the row to this exact connection.
fn find_owner(rows: &[TcpRow], endpoint: SocketAddrV4, to: SocketAddrV4) -> Option<u32> {
    rows.iter()
        .find(|r| r.established && r.local == endpoint && r.remote == to)
        .map(|r| r.pid)
}

/// `our_end` must be this process's own end of the connection: without it the
/// table lookup cannot tell the two loopback rows apart.
pub(crate) fn verify_same_user(
    stream: &TcpStream,
    our_end: SocketAddrV4,
) -> Result<u32, PeerError> {
    let peer = match stream
        .peer_addr()
        .map_err(|e| PeerError::ProcessQuery(0, format!("peer_addr: {e}")))?
    {
        std::net::SocketAddr::V4(a) if *a.ip() == Ipv4Addr::LOCALHOST => a,
        other => return Err(PeerError::NotLoopback(other)),
    };
    let rows = read_tcp_table().map_err(|e| PeerError::ProcessQuery(0, e))?;
    let pid = find_owner(&rows, peer, our_end).ok_or(PeerError::NoOwner(peer))?;
    admit(&ProcessToken::open(pid)?)?;
    Ok(pid)
}

/// Admission policy: exactly the processes the nonce file's ACL would let in.
/// `AppContainer` and restricted tokens carry the user's SID but are denied the
/// file, so they are denied here too.
fn admit(token: &ProcessToken) -> Result<(), PeerError> {
    if !token.same_user_as_current_process()? {
        return Err(PeerError::NotSameUser(token.pid));
    }
    if token.is_app_container()? {
        return Err(PeerError::AppContainer(token.pid));
    }
    if token.is_restricted() {
        return Err(PeerError::RestrictedToken(token.pid));
    }
    Ok(())
}

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// Win32 takes buffer lengths as `u32`; every argument here is a `size_of`,
/// so the width is fixed at compile time.
#[allow(
    clippy::cast_possible_truncation,
    reason = "size_of of a fixed-layout type"
)]
const fn len_of<T>() -> u32 {
    size_of::<T>() as u32
}

fn read_tcp_table() -> Result<Vec<TcpRow>, String> {
    let mut size: u32 = 0;
    // First call sizes the buffer; retry loop covers table growth in between.
    for _ in 0..8 {
        let buf_size = size;
        // u64 elements, not u8: the buffer is read back as MIB_TCPTABLE_OWNER_PID,
        // and a Vec<u8> is allocated for alignment 1. Dereferencing the struct out
        // of it is undefined behaviour whatever the allocator happens to return.
        let mut buf = vec![0u64; (buf_size.max(16) as usize).div_ceil(8)];
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &raw mut size,
                FALSE,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        match rc {
            0 if buf_size >= size => {
                let table = buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
                let count = unsafe { (*table).dwNumEntries } as usize;
                let first = unsafe { &raw const (*table).table }.cast::<MIB_TCPROW_OWNER_PID>();
                // SAFETY: the call reported success with a buffer of at least
                // `size` bytes, so the API's own count bounds the rows written
                // into it, and each lives as long as `buf`.
                let rows = (0..count)
                    .map(|i| {
                        let row = unsafe { first.add(i) };
                        convert_row(unsafe { &*row })
                    })
                    .collect();
                return Ok(rows);
            }
            0 | ERROR_INSUFFICIENT_BUFFER => {}
            e => return Err(format!("GetExtendedTcpTable failed with {e}")),
        }
    }
    Err("GetExtendedTcpTable kept growing".into())
}

/// The table widens each port to a DWORD but leaves it in network order in the
/// leading two bytes, so the value is read positionally rather than numerically.
fn port_of(raw: u32) -> u16 {
    let [high, low, _, _] = raw.to_ne_bytes();
    u16::from_be_bytes([high, low])
}

fn convert_row(row: &MIB_TCPROW_OWNER_PID) -> TcpRow {
    TcpRow {
        local: SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(row.dwLocalAddr)),
            port_of(row.dwLocalPort),
        ),
        remote: SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)),
            port_of(row.dwRemotePort),
        ),
        established: row.dwState == MIB_TCP_STATE_ESTAB as u32,
        pid: row.dwOwningPid,
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct ProcessToken {
    pid: u32,
    token: OwnedHandle,
}

impl ProcessToken {
    fn open(pid: u32) -> Result<Self, PeerError> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
        if process.is_null() {
            return Err(PeerError::ProcessQuery(pid, last_error("OpenProcess")));
        }
        let process = OwnedHandle(process);
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(PeerError::ProcessQuery(pid, last_error("OpenProcessToken")));
        }
        Ok(ProcessToken {
            pid,
            token: OwnedHandle(token),
        })
    }

    fn current_process() -> Result<Self, PeerError> {
        Self::open_current(TOKEN_QUERY)
    }

    #[cfg(test)]
    fn current_process_for_test() -> Result<Self, PeerError> {
        use windows_sys::Win32::Security::TOKEN_DUPLICATE;
        Self::open_current(TOKEN_QUERY | TOKEN_DUPLICATE)
    }

    fn open_current(access: u32) -> Result<Self, PeerError> {
        let mut token: HANDLE = std::ptr::null_mut();
        let process = unsafe { GetCurrentProcess() };
        if unsafe { OpenProcessToken(process, access, &raw mut token) } == 0 {
            return Err(PeerError::ProcessQuery(
                0,
                last_error("OpenProcessToken(self)"),
            ));
        }
        Ok(ProcessToken {
            pid: std::process::id(),
            token: OwnedHandle(token),
        })
    }

    /// u64 elements, not u8: the buffer is read back as a `TOKEN_USER`, whose
    /// `PSID` member needs pointer alignment that a `Vec<u8>` does not promise.
    fn user_sid_buffer(&self) -> Result<Vec<u64>, PeerError> {
        let mut size: u32 = 0;
        unsafe {
            GetTokenInformation(
                self.token.0,
                TokenUser,
                std::ptr::null_mut(),
                0,
                &raw mut size,
            )
        };
        let mut buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
        if unsafe {
            GetTokenInformation(
                self.token.0,
                TokenUser,
                buf.as_mut_ptr().cast(),
                size,
                &raw mut size,
            )
        } == 0
        {
            return Err(PeerError::ProcessQuery(
                self.pid,
                last_error("GetTokenInformation(TokenUser)"),
            ));
        }
        Ok(buf)
    }

    fn same_user_as_current_process(&self) -> Result<bool, PeerError> {
        let ours = ProcessToken::current_process()?.user_sid_buffer()?;
        let theirs = self.user_sid_buffer()?;
        let our_sid = unsafe { (*ours.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let their_sid = unsafe { (*theirs.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        Ok(unsafe { EqualSid(our_sid, their_sid) } != 0)
    }

    fn is_app_container(&self) -> Result<bool, PeerError> {
        let mut value: u32 = 0;
        let mut size: u32 = 0;
        if unsafe {
            GetTokenInformation(
                self.token.0,
                TokenIsAppContainer,
                (&raw mut value).cast(),
                len_of::<u32>(),
                &raw mut size,
            )
        } == 0
        {
            return Err(PeerError::ProcessQuery(
                self.pid,
                last_error("GetTokenInformation(TokenIsAppContainer)"),
            ));
        }
        Ok(value != 0)
    }

    fn is_restricted(&self) -> bool {
        unsafe { IsTokenRestricted(self.token.0) != 0 }
    }
}

fn last_error(call: &str) -> String {
    format!("{call}: {}", std::io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn addr(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
    }

    fn row(local: u16, remote: u16, established: bool, pid: u32) -> TcpRow {
        TcpRow {
            local: addr(local),
            remote: addr(remote),
            established,
            pid,
        }
    }

    #[test]
    fn finds_matching_established_row() {
        let rows = [row(50000, 47470, true, 42), row(47470, 50000, true, 7)];
        assert_eq!(find_owner(&rows, addr(50000), addr(47470)), Some(42));
    }

    #[test]
    fn the_mirror_row_does_not_match() {
        let rows = [row(47470, 50000, true, 7)];
        assert_eq!(find_owner(&rows, addr(50000), addr(47470)), None);
    }

    #[test]
    fn non_established_row_rejected() {
        let rows = [row(50000, 47470, false, 42)];
        assert_eq!(find_owner(&rows, addr(50000), addr(47470)), None);
    }

    #[test]
    fn wrong_remote_endpoint_rejected() {
        let rows = [row(50000, 9999, true, 42)];
        assert_eq!(find_owner(&rows, addr(50000), addr(47470)), None);
    }

    #[test]
    fn non_loopback_local_rejected() {
        let rows = [TcpRow {
            local: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 50000),
            remote: addr(47470),
            established: true,
            pid: 42,
        }];
        assert_eq!(find_owner(&rows, addr(50000), addr(47470)), None);
    }

    #[test]
    fn row_conversion_swaps_network_order() {
        let raw = MIB_TCPROW_OWNER_PID {
            dwState: MIB_TCP_STATE_ESTAB as u32,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: u32::from(8467u16.to_be()),
            dwRemoteAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwRemotePort: u32::from(50000u16.to_be()),
            dwOwningPid: 1234,
        };
        let converted = convert_row(&raw);
        assert_eq!(converted, row(8467, 50000, true, 1234));
    }

    /// A genuinely restricted token still carries the user's SID, so admission
    /// must fail on the restriction and not on the user check.
    #[test]
    fn restricted_token_is_rejected() {
        use windows_sys::Win32::Security::{CreateRestrictedToken, SID_AND_ATTRIBUTES};
        // S-1-5-32-545 (BUILTIN\Users): revision 1, 2 subauthorities,
        // authority 5, subauthorities [32, 545].
        let mut users_sid: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 0x02, 0, 0];
        let restricting = [SID_AND_ATTRIBUTES {
            Sid: users_sid.as_mut_ptr().cast(),
            Attributes: 0,
        }];
        let own = ProcessToken::current_process_for_test().unwrap();
        let mut new_token: HANDLE = std::ptr::null_mut();
        let ok = unsafe {
            CreateRestrictedToken(
                own.token.0,
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                u32::try_from(restricting.len()).unwrap(),
                restricting.as_ptr(),
                &raw mut new_token,
            )
        };
        assert_ne!(ok, 0, "CreateRestrictedToken failed");
        let restricted = ProcessToken {
            pid: 0,
            token: OwnedHandle(new_token),
        };
        assert!(restricted.same_user_as_current_process().unwrap());
        assert!(restricted.is_restricted());
        assert_eq!(admit(&restricted), Err(PeerError::RestrictedToken(0)));
    }

    #[test]
    fn ordinary_own_token_is_admitted() {
        let own = ProcessToken::current_process_for_test().unwrap();
        assert_eq!(admit(&own), Ok(()));
    }

    /// The only test that drives the whole FFI path: TCP table, `OpenProcess`,
    /// token query.
    #[test]
    fn own_connection_passes_verification() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(listen_addr) = listener.local_addr().unwrap() else {
            unreachable!("bound to 127.0.0.1")
        };
        let _client = TcpStream::connect(listen_addr).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        let pid = verify_same_user(&server_side, listen_addr).unwrap();
        assert_eq!(pid, std::process::id());
    }
}
