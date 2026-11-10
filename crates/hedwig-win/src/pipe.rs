//! The control pipe: a byte-mode named pipe that admits the person and nobody
//! else, from any of their sessions and from no other machine.
//!
//! Every end is opened for overlapped I/O, because a synchronous handle lets
//! a pending read block a write on the same end, and the core writes to a
//! client that is waiting to read. An operation never outlives the call that
//! started it: `finish` waits for the system to be done with the buffer
//! and the `OVERLAPPED` before either goes out of scope.

use std::fmt;
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_NO_DATA,
    ERROR_NO_MORE_FILES, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_NOT_CONNECTED, ERROR_SEM_TIMEOUT, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, TRUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FindClose, FindFirstFileW,
    FindNextFileW, GetFullPathNameW, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WIN32_FIND_DATAW, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, INFINITE, OpenThreadToken, WaitForMultipleObjects,
};

use crate::raw::{Local, Signal, code, owned, wide};
use crate::token::{Sid, Token, wide_length};

/// The most clients served at once: the largest count Windows accepts for a
/// pipe whose instances are counted at all.
pub const INSTANCES: u32 = 254;

/// What the person's own account may do with the pipe: read and write it as a
/// client, and create its further instances as the server. It is the file
/// rights for reading and writing, which on a pipe include creating an
/// instance.
pub(crate) const RIGHTS: u32 = 0x0012_019f;

/// How an overlapped operation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moved {
    /// This many bytes were read or written.
    Bytes(usize),
    /// The other end is gone.
    Closed,
    /// The stop signal was raised before the operation finished.
    Stopped,
}

/// One end of the pipe.
#[derive(Debug)]
pub struct Pipe(OwnedHandle);

/// Starts an overlapped operation and stays until the system has finished
/// with it, so nothing `start` lent it is still in use on return.
fn finish(
    handle: HANDLE,
    stop: Option<&Signal>,
    limit: Option<Duration>,
    start: impl FnOnce(*mut OVERLAPPED) -> i32,
) -> io::Result<Moved> {
    let done = Signal::new()?;
    // SAFETY: all-zero is a valid `OVERLAPPED`, with no offset and no event.
    let mut state: OVERLAPPED = unsafe { std::mem::zeroed() };
    state.hEvent = done.raw();
    let mut stopped = false;
    if start(&raw mut state) == 0 {
        match code(&io::Error::last_os_error()) {
            ERROR_IO_PENDING => {}
            ERROR_PIPE_CONNECTED => return Ok(Moved::Bytes(0)),
            ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA => {
                return Ok(Moved::Closed);
            }
            other => return Err(io::Error::from_raw_os_error(other.cast_signed())),
        }
        let waited = [done.raw(), stop.map_or(done.raw(), Signal::raw)];
        let count = if stop.is_some() { 2 } else { 1 };
        let limit = limit.map_or(INFINITE, |limit| {
            u32::try_from(limit.as_millis()).unwrap_or(INFINITE - 1)
        });
        // SAFETY: `waited` holds `count` valid event handles.
        let which = unsafe { WaitForMultipleObjects(count, waited.as_ptr(), 0, limit) };
        if which != WAIT_OBJECT_0 {
            stopped = true;
            // SAFETY: the handle is open and `state` is the operation pending
            // on it; cancelling one that has just finished is harmless.
            unsafe { CancelIoEx(handle, &raw const state) };
        }
    }
    let mut moved = 0u32;
    // SAFETY: `state` is the operation started above. Waiting here is what
    // keeps it and the caller's buffer alive until the system lets go.
    let finished = unsafe { GetOverlappedResult(handle, &raw const state, &raw mut moved, TRUE) };
    if finished != 0 {
        return Ok(Moved::Bytes(moved as usize));
    }
    match code(&io::Error::last_os_error()) {
        ERROR_OPERATION_ABORTED if stopped => Ok(Moved::Stopped),
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA => Ok(Moved::Closed),
        other => Err(io::Error::from_raw_os_error(other.cast_signed())),
    }
}

impl Pipe {
    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }

    /// Reads what has arrived, up to the size of `buffer`, waiting until
    /// something has or `stop` is raised.
    pub fn read(&self, buffer: &mut [u8], stop: Option<&Signal>) -> io::Result<Moved> {
        self.read_within(buffer, stop, None)
    }

    /// As [`Pipe::read`], giving up as stopped when `limit` passes first.
    pub fn read_within(
        &self,
        buffer: &mut [u8],
        stop: Option<&Signal>,
        limit: Option<Duration>,
    ) -> io::Result<Moved> {
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let into = buffer.as_mut_ptr();
        let moved = finish(self.raw(), stop, limit, |state| {
            // SAFETY: `into` is `length` writable bytes borrowed for the whole
            // of `finish`, which does not return while the read is pending.
            unsafe { ReadFile(self.raw(), into, length, std::ptr::null_mut(), state) }
        })?;
        Ok(match moved {
            Moved::Bytes(0) => Moved::Closed,
            other => other,
        })
    }

    /// Writes all of `bytes`, or stops part-way when the other end goes or
    /// `stop` is raised.
    pub fn write(&self, mut bytes: &[u8], stop: Option<&Signal>) -> io::Result<Moved> {
        let mut written = 0;
        while !bytes.is_empty() {
            let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            let from = bytes.as_ptr();
            let moved = finish(self.raw(), stop, None, |state| {
                // SAFETY: `from` is `length` readable bytes borrowed for the
                // whole of `finish`, which does not return while the write
                // is pending.
                unsafe { WriteFile(self.raw(), from, length, std::ptr::null_mut(), state) }
            })?;
            let Moved::Bytes(count) = moved else {
                return Ok(moved);
            };
            written += count;
            bytes = bytes.get(count..).unwrap_or_default();
        }
        Ok(Moved::Bytes(written))
    }

    /// Who owns the pipe. A client checks this before it sends anything: a
    /// pipe somebody else created under the name is not the person's core.
    pub fn owner(&self) -> io::Result<Sid> {
        let mut owner = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: the handle is open with the right to read its security;
        // `owner` and `descriptor` receive pointers into memory `Local` frees.
        let failed = unsafe {
            GetSecurityInfo(
                self.raw(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &raw mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        let held = Local(descriptor);
        if failed != 0 {
            return Err(io::Error::from_raw_os_error(failed.cast_signed()));
        }
        // SAFETY: `owner` points into the descriptor `held` keeps alive.
        let owner = unsafe { Sid::copy(owner) };
        drop(held);
        owner
    }

    /// The pipe's owner, access list and integrity label, as Windows writes
    /// them.
    pub fn security(&self) -> io::Result<String> {
        let wanted =
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: as in `owner`; only the descriptor itself is asked for.
        let failed = unsafe {
            GetSecurityInfo(
                self.raw(),
                SE_KERNEL_OBJECT,
                wanted,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        let held = Local(descriptor);
        if failed != 0 {
            return Err(io::Error::from_raw_os_error(failed.cast_signed()));
        }
        let mut text = std::ptr::null_mut();
        // SAFETY: `descriptor` is the valid descriptor just returned, and
        // `text` receives memory `Local` frees.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                held.0,
                SDDL_REVISION_1,
                wanted,
                &raw mut text,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error());
        }
        let text_held = Local(text.cast());
        // SAFETY: on success `text` is a NUL-terminated string.
        let length = unsafe { wide_length(text) };
        // SAFETY: the string is `length` units long, as just measured.
        let units = unsafe { std::slice::from_raw_parts(text, length) };
        let text = String::from_utf16_lossy(units);
        drop(text_held);
        Ok(text)
    }

    /// The process that connected to this server end, as it was numbered when
    /// it connected. It is shown, and never used to open anything.
    pub fn client_process(&self) -> io::Result<u32> {
        let mut process = 0u32;
        // SAFETY: the handle is a pipe's server end and `process` a valid out
        // pointer.
        if unsafe { GetNamedPipeClientProcessId(self.raw(), &raw mut process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(process)
    }

    /// The process serving this client end, read before anything is sent to
    /// it: who holds a name is learnt without asking it anything.
    pub fn server_process(&self) -> io::Result<u32> {
        let mut process = 0u32;
        // SAFETY: the handle is a pipe's client end and `process` a valid out
        // pointer.
        if unsafe { GetNamedPipeServerProcessId(self.raw(), &raw mut process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(process)
    }

    /// The token of the client whose bytes this server end last read. The
    /// thread wears the client's identity only long enough to open it.
    pub fn client_token(&self) -> io::Result<Token> {
        // SAFETY: the handle is a pipe's server end.
        if unsafe { ImpersonateNamedPipeClient(self.raw()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle for this thread is always valid.
        let thread = unsafe { GetCurrentThread() };
        // SAFETY: `handle` is a valid place for the token; it is opened with
        // this process's own rights, since the client may grant none.
        let opened = unsafe { OpenThreadToken(thread, TOKEN_QUERY, TRUE, &raw mut handle) };
        let opened = if opened == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        };
        // SAFETY: no arguments; it ends the impersonation begun above.
        if unsafe { RevertToSelf() } == 0 {
            // Carrying on as the client would let its identity decide what
            // this process does next. Microsoft's guidance is to end the
            // process, and nothing here can be left half-done by that.
            std::process::abort();
        }
        opened?;
        owned(handle).map(Token::from_handle)
    }
}

/// The descriptor that admits the person: owned by their account, whatever
/// group an elevated token would make the owner; a protected list with one
/// entry, for that account, granting what a client needs to read and write
/// and what the core needs to make further instances; labelled medium, so a
/// core started at high integrity is as reachable from the desktop as one
/// started there, and nothing below medium can write. The control pipe is
/// made with it, and a source's holder is the person's where Windows' own
/// check admits its token against it
/// ([`crate::token::Token::is_the_person`]).
pub(crate) fn the_persons(owner: &Sid) -> io::Result<Local> {
    let sid = owner.to_text()?;
    let text = wide(format!(
        "O:{sid}G:{sid}D:P(A;;{RIGHTS:#x};;;{sid})S:(ML;;NW;;;ME)"
    ));
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: `text` is NUL-terminated, and `descriptor` receives memory
    // `Local` frees.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Local(descriptor))
}

/// Creates the instances of one pipe.
pub struct Listener {
    path: Vec<u16>,
    security: Local,
}

// SAFETY: the security descriptor is memory this value alone owns and only
// reads; nothing about it is tied to the thread that allocated it.
unsafe impl Send for Listener {}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

impl Listener {
    /// Creates the pipe at `path`, owned by `owner` and open to that account
    /// alone, and its first instance.
    ///
    /// # Errors
    ///
    /// `PermissionDenied` when a pipe of that name already exists: the first
    /// instance is never an instance of somebody else's pipe.
    pub fn bind(path: &str, owner: &Sid) -> io::Result<(Listener, Pipe)> {
        let listener = Listener {
            path: wide(path),
            security: the_persons(owner)?,
        };
        let first = listener.instance(FILE_FLAG_FIRST_PIPE_INSTANCE)?;
        Ok((listener, first))
    }

    /// One more instance, for the next client.
    pub fn another(&self) -> io::Result<Pipe> {
        self.instance(0)
    }

    fn instance(&self, first: u32) -> io::Result<Pipe> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or_default(),
            lpSecurityDescriptor: self.security.0,
            bInheritHandle: 0,
        };
        // SAFETY: the path is NUL-terminated and the attributes point at a
        // descriptor this listener keeps alive.
        let handle = unsafe {
            CreateNamedPipeW(
                self.path.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                INSTANCES,
                65536,
                65536,
                0,
                &raw const attributes,
            )
        };
        owned(handle).map(Pipe)
    }
}

impl Pipe {
    /// Waits for a client to connect to this instance.
    pub fn accept(&self, stop: &Signal) -> io::Result<Moved> {
        finish(self.raw(), Some(stop), None, |state| {
            // SAFETY: the handle is a server instance, and `state` lives
            // until `finish` has seen the connection complete or cancelled.
            unsafe { ConnectNamedPipe(self.raw(), state) }
        })
    }
}

/// Why a pipe could not be opened as a client.
#[derive(Debug)]
pub enum OpenError {
    /// No pipe has that name.
    Absent,
    /// No instance came free for as long as the client was willing to wait.
    Busy,
    /// The pipe exists and does not admit this account.
    Denied,
    Other(io::Error),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Absent => f.write_str("no pipe has that name"),
            OpenError::Busy => f.write_str("every instance of the pipe is busy"),
            OpenError::Denied => f.write_str("the pipe does not admit this account"),
            OpenError::Other(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::Other(error) => Some(error),
            _ => None,
        }
    }
}

/// Opens the pipe at `path` as a client, letting the server identify this
/// process and never act as it.
///
/// A server has an instance free only between creating it and a client
/// taking it, and every client waiting for one wakes when one is created, so
/// a client that loses that race waits again for as long as `patience` has
/// left. [`OpenError::Busy`] therefore means no instance came free for the
/// whole of `patience`, never that others were quicker to one.
pub fn open(path: &str, patience: Duration) -> Result<Pipe, OpenError> {
    let path = wide(path);
    let until = Instant::now() + patience;
    loop {
        // SAFETY: the path is NUL-terminated; no security attributes and no
        // template are given.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        match owned(handle) {
            Ok(handle) => return Ok(Pipe(handle)),
            Err(error) => match code(&error) {
                ERROR_FILE_NOT_FOUND => return Err(OpenError::Absent),
                ERROR_ACCESS_DENIED => return Err(OpenError::Denied),
                ERROR_PIPE_BUSY => wait_for_instance(&path, until)?,
                _ => return Err(OpenError::Other(error)),
            },
        }
    }
}

/// How long a client of [`open_unwaited`] leaves between tries of a busy
/// pipe. Invariant: OpenSSH's in-box client tries again once a second
/// (`contrib/win32/win32compat/fileio.c:141-153` at v10.0.0.0); a twentieth of
/// that answers sooner and is still no load on the server.
pub const RETRY: Duration = Duration::from_millis(50);

/// Opens the pipe at `path` as a client, as [`open`] does, but never waits on
/// the server for an instance: while every instance is busy it tries again
/// every [`RETRY`]. A server that makes one instance after another and takes
/// a client arriving between making an instance and waiting on it for an
/// error stops serving the name altogether - gpg-agent 2.5.24's Win32-OpenSSH
/// thread does (`agent/gpg-agent.c:2804-2809`) - and that gap is exactly when
/// a waiting client wakes. The same server closes each instance before it
/// makes the next (`agent/gpg-agent.c:2856`, then `:2791`), so for a moment
/// the name does not exist: a pipe found absent is tried once more after
/// [`RETRY`], far longer than that gap, before it is said to be absent.
pub fn open_unwaited(path: &str, patience: Duration) -> Result<Pipe, OpenError> {
    let wide_path = wide(path);
    let until = Instant::now() + patience;
    let mut absent_once = false;
    loop {
        // SAFETY: as in `open`.
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        match owned(handle) {
            Ok(handle) => return Ok(Pipe(handle)),
            Err(error) => match code(&error) {
                ERROR_FILE_NOT_FOUND if !absent_once && Instant::now() + RETRY < until => {
                    absent_once = true;
                    std::thread::sleep(RETRY);
                }
                ERROR_FILE_NOT_FOUND => return Err(OpenError::Absent),
                ERROR_ACCESS_DENIED => return Err(OpenError::Denied),
                ERROR_PIPE_BUSY if Instant::now() + RETRY < until => std::thread::sleep(RETRY),
                ERROR_PIPE_BUSY => return Err(OpenError::Busy),
                _ => return Err(OpenError::Other(error)),
            },
        }
    }
}

/// Forms of a pipe's path the system opens as that pipe and
/// `GetFullPathNameW` does not read as one.
const NATIVE_PREFIXES: [&str; 3] = [
    r"\??\pipe\",
    r"\\.\GLOBALROOT\Device\NamedPipe\",
    r"\\?\GLOBALROOT\Device\NamedPipe\",
];

/// What follows `prefix` in `path`, the prefix's case ignored, where anything
/// does.
fn after_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.get(..prefix.len())
        .filter(|start| start.eq_ignore_ascii_case(prefix))?;
    path.get(prefix.len()..).filter(|name| !name.is_empty())
}

/// The name of the pipe `path` makes, as Windows itself reads `path`, or
/// nothing where `path` is no pipe's. No pipe is looked at.
///
/// # Errors
///
/// What the system said where it would not read `path`.
pub fn name_in(path: &str) -> io::Result<Option<String>> {
    if let Some(name) = NATIVE_PREFIXES
        .iter()
        .find_map(|prefix| after_prefix(path, prefix))
    {
        return Ok(Some(name.to_owned()));
    }
    // The call refuses an empty path, which names nothing.
    if path.is_empty() {
        return Ok(None);
    }
    let path = wide(path);
    // SAFETY: `path` is NUL-terminated; a length of zero writes nothing.
    let needed =
        unsafe { GetFullPathNameW(path.as_ptr(), 0, std::ptr::null_mut(), std::ptr::null_mut()) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut full = vec![0u16; needed as usize];
    // SAFETY: `path` is NUL-terminated and `full` holds `needed` units.
    let written = unsafe {
        GetFullPathNameW(
            path.as_ptr(),
            needed,
            full.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    let full = full
        .get(..written as usize)
        .filter(|full| !full.is_empty())
        .ok_or_else(io::Error::last_os_error)?;
    let full = String::from_utf16_lossy(full);
    Ok([r"\\.\pipe\", r"\\?\pipe\"]
        .iter()
        .find_map(|prefix| after_prefix(&full, prefix).map(str::to_owned)))
}

/// `name`, as it follows `\\.\pipe\`, as Windows reads it there.
#[must_use]
pub fn canonical(name: &str) -> String {
    name_in(&format!(r"\\.\pipe\{name}"))
        .ok()
        .flatten()
        .unwrap_or_else(|| name.to_owned())
}

/// Whether two names in the form [`canonical`] gives are one pipe's, by the
/// operating system's own table of case.
#[must_use]
pub fn same_name(one: &str, other: &str) -> bool {
    let units = |name: &str| name.encode_utf16().collect::<Vec<u16>>();
    let (one, other) = (units(one), units(other));
    let length = |name: &[u16]| i32::try_from(name.len()).unwrap_or(i32::MAX);
    // SAFETY: each pointer and length describe a live run of UTF-16 units.
    let compared = unsafe {
        CompareStringOrdinal(
            one.as_ptr(),
            length(&one),
            other.as_ptr(),
            length(&other),
            TRUE,
        )
    };
    compared == CSTR_EQUAL
}

/// Whether a pipe named `name` exists now, by the file system's list of
/// pipes. Nothing connects to it, so a server that treats a client it did not
/// wait for as an error is not disturbed by the asking.
///
/// # Errors
///
/// What the system said when the list could not be read.
pub fn exists(name: &str) -> io::Result<bool> {
    let name = canonical(name);
    let pattern = wide(r"\\.\pipe\*");
    // SAFETY: all-zero is a valid record, written by the calls below.
    let mut found: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    // SAFETY: `pattern` is NUL-terminated and `found` a valid out pointer.
    let handle = unsafe { FindFirstFileW(pattern.as_ptr(), &raw mut found) };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        return if code(&error) == ERROR_FILE_NOT_FOUND {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let listing = Listing(handle);
    loop {
        let units = &found.cFileName;
        let length = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        if same_name(
            &String::from_utf16_lossy(units.get(..length).unwrap_or_default()),
            &name,
        ) {
            return Ok(true);
        }
        // SAFETY: the listing is open and `found` a valid out pointer.
        if unsafe { FindNextFileW(listing.0, &raw mut found) } == 0 {
            let error = io::Error::last_os_error();
            return if code(&error) == ERROR_NO_MORE_FILES {
                Ok(false)
            } else {
                Err(error)
            };
        }
    }
}

/// An open listing of the pipes, closed when dropped.
struct Listing(HANDLE);

impl Drop for Listing {
    fn drop(&mut self) {
        // SAFETY: the handle came from `FindFirstFileW` and is closed once.
        unsafe { FindClose(self.0) };
    }
}

/// Waits until the server creates an instance, or `until` passes.
fn wait_for_instance(path: &[u16], until: Instant) -> Result<(), OpenError> {
    let left = until.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(OpenError::Busy);
    }
    // In whole milliseconds, rounded up: zero would ask for the server's
    // default wait and `u32::MAX` for no end to it.
    let left = u32::try_from(left.as_nanos().div_ceil(1_000_000))
        .map_or(u32::MAX - 1, |left| left.min(u32::MAX - 1));
    // SAFETY: the path is NUL-terminated.
    if unsafe { WaitNamedPipeW(path.as_ptr(), left) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match code(&error) {
        // The wait can end a little before the time it was given; whether the
        // patience is spent is this client's clock's to say, on the next try.
        ERROR_SEM_TIMEOUT => Ok(()),
        ERROR_FILE_NOT_FOUND => Err(OpenError::Absent),
        _ => Err(OpenError::Other(error)),
    }
}
