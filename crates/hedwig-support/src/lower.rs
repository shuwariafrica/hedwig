//! Starts a process with less than this one has: at a lower integrity level,
//! or with a restricted token.
//!
//! The owner reaches the workstation over SSH, where every process runs at
//! high integrity, and at its desktop, where they run at medium. A core in
//! one and a client in the other is the case the control channel must serve,
//! and a token lowered to medium from high is as near as one session gets to
//! it. Lowered to low, or restricted, the same account is a client the pipe's
//! access list must decide about by itself. A process under a restricted
//! token does not start in a desktop session without more than this suite
//! should give it, so that case runs on a thread under the token instead.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Duration;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree, WAIT_OBJECT_0};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DuplicateTokenEx, GetLengthSid, GetTokenInformation, PSID, RevertToSelf,
    SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenImpersonation, TokenIntegrityLevel, TokenLogonSid,
    TokenPrimary,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessAsUserW, DETACHED_PROCESS, GetCurrentProcess,
    GetExitCodeProcess, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW, SetThreadToken,
    TerminateProcess, WaitForSingleObject,
};

/// The flag that marks an identifier in a token as its integrity level.
const INTEGRITY: u32 = 0x20;

/// The integrity level a token is lowered to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Medium,
    Low,
}

impl Level {
    fn sid(self) -> &'static str {
        match self {
            Level::Medium => "S-1-16-8192",
            Level::Low => "S-1-16-4096",
        }
    }
}

fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle was just created for this process and nothing else
    // holds it.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// An identifier converted from its text, freed when dropped.
struct Identifier(PSID);

impl Identifier {
    fn from_text(text: &str) -> io::Result<Identifier> {
        let text: Vec<u16> = text.encode_utf16().chain([0]).collect();
        let mut sid = std::ptr::null_mut();
        // SAFETY: `text` is NUL-terminated and `sid` receives memory freed
        // when this value is dropped.
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &raw mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Identifier(sid))
    }
}

impl Drop for Identifier {
    fn drop(&mut self) {
        // SAFETY: allocated by the conversion and freed once.
        unsafe { LocalFree(self.0) };
    }
}

/// This process's own token, open for making others from.
fn own_token() -> io::Result<OwnedHandle> {
    let mut own: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle for this process is always valid.
    let process = unsafe { GetCurrentProcess() };
    let wanted = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY;
    // SAFETY: `own` is a valid place for the token.
    if unsafe { OpenProcessToken(process, wanted, &raw mut own) } == 0 {
        return Err(io::Error::last_os_error());
    }
    owned(own)
}

/// A copy of this process's token, labelled `level`.
fn labelled(level: Level) -> io::Result<OwnedHandle> {
    let own = own_token()?;
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: `own` is an open token; no attributes; `copy` receives the new
    // primary token. 0x0200_0000 asks for every right this process may have.
    let duplicated = unsafe {
        DuplicateTokenEx(
            own.as_raw_handle(),
            0x0200_0000,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            SecurityImpersonation,
            TokenPrimary,
            &raw mut copy,
        )
    };
    if duplicated == 0 {
        return Err(io::Error::last_os_error());
    }
    let copy = owned(copy)?;
    let level = Identifier::from_text(level.sid())?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: level.0,
            Attributes: INTEGRITY,
        },
    };
    // SAFETY: the identifier is the valid one just converted.
    let length = unsafe { GetLengthSid(level.0) };
    let size = u32::try_from(size_of::<TOKEN_MANDATORY_LABEL>()).unwrap_or_default() + length;
    // SAFETY: `label` is the structure the class names and points at a valid
    // identifier; lowering a token's own level needs no privilege.
    let set = unsafe {
        SetTokenInformation(
            copy.as_raw_handle(),
            TokenIntegrityLevel,
            (&raw const label).cast(),
            size,
        )
    };
    if set == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(copy)
}

/// A restricted copy of this process's token: every access it asks for is
/// checked a second time against `restricting` alone.
fn restricted(restricting: &[&str]) -> io::Result<OwnedHandle> {
    let own = own_token()?;
    let identifiers = restricting
        .iter()
        .map(|text| Identifier::from_text(text))
        .collect::<io::Result<Vec<Identifier>>>()?;
    let list: Vec<SID_AND_ATTRIBUTES> = identifiers
        .iter()
        .map(|identifier| SID_AND_ATTRIBUTES {
            Sid: identifier.0,
            Attributes: 0,
        })
        .collect();
    let mut made: HANDLE = std::ptr::null_mut();
    // SAFETY: `own` is an open token; nothing is disabled or deleted; `list`
    // holds as many valid identifiers as its length says, alive until the
    // call returns; `made` receives the new token.
    let created = unsafe {
        CreateRestrictedToken(
            own.as_raw_handle(),
            0,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            u32::try_from(list.len()).unwrap_or_default(),
            list.as_ptr(),
            &raw mut made,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    owned(made)
}

/// The ways a copy of this process's token can hold less than it, as a
/// token a check is asked of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Less {
    /// Every access checked again against Everyone alone.
    RestrictedToEveryone,
    /// The account's own identifier made deny-only: it can refuse access and
    /// never grant it.
    AccountDenyOnly,
    /// Labelled low integrity.
    Low,
    /// Nothing taken away.
    Same,
}

/// A copy of this process's token holding `less`.
///
/// # Errors
///
/// What the system said.
pub fn token(less: Less) -> io::Result<OwnedHandle> {
    match less {
        Less::RestrictedToEveryone => restricted(&["S-1-1-0"]),
        Less::Low => labelled(Level::Low),
        Less::Same => own_token(),
        Less::AccountDenyOnly => {
            let own = own_token()?;
            let user = hedwig_win::token::Token::own()?.user()?;
            let user = Identifier::from_text(&user.to_text()?)?;
            let disabled = [SID_AND_ATTRIBUTES {
                Sid: user.0,
                Attributes: 0,
            }];
            let mut made: HANDLE = std::ptr::null_mut();
            // SAFETY: `own` is an open token; `disabled` holds one valid
            // identifier, alive until the call returns; nothing is deleted
            // or restricted; `made` receives the new token.
            let created = unsafe {
                CreateRestrictedToken(
                    own.as_raw_handle(),
                    0,
                    1,
                    disabled.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &raw mut made,
                )
            };
            if created == 0 {
                return Err(io::Error::last_os_error());
            }
            owned(made)
        }
    }
}

/// This logon session's own identifier, as text: what a restricted token
/// needs among its restricting identifiers to start a process at a desktop.
///
/// # Errors
///
/// What the system said.
pub fn logon_sid() -> io::Result<String> {
    let own = own_token()?;
    let mut needed = 0u32;
    // SAFETY: a null buffer of length zero asks only for the size.
    unsafe {
        GetTokenInformation(
            own.as_raw_handle(),
            TokenLogonSid,
            std::ptr::null_mut(),
            0,
            &raw mut needed,
        )
    };
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buffer` is at least `needed` writable bytes.
    let read = unsafe {
        GetTokenInformation(
            own.as_raw_handle(),
            TokenLogonSid,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful query wrote a `TOKEN_GROUPS` with one entry at the
    // start of the aligned buffer.
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let mut text = std::ptr::null_mut();
    // SAFETY: the identifier lies inside `buffer`; `text` receives memory
    // freed below.
    if unsafe { ConvertSidToStringSidW(groups.Groups[0].Sid, &raw mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut length = 0;
    // SAFETY: the text is NUL-terminated, so every unit up to the terminator
    // is readable.
    while unsafe { *text.wrapping_add(length) } != 0 {
        length += 1;
    }
    // SAFETY: as above, `length` units are readable.
    let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    // SAFETY: allocated by the conversion.
    unsafe { LocalFree(text.cast()) };
    Ok(sid)
}

/// Runs `act` on this thread under a restricted copy of this process's
/// token, whose restricting identifiers are `restricting`, given as text.
/// Everything `act` opens is decided as it would be for a process running
/// under that token.
///
/// # Panics
///
/// When the thread cannot be given its own token back: nothing may run on
/// it as somebody it is not.
pub fn as_restricted<T>(restricting: &[&str], act: impl FnOnce() -> T) -> io::Result<T> {
    let token = restricted(restricting)?;
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` is an open token; no attributes; `copy` receives an
    // impersonation token a thread can take on.
    let duplicated = unsafe {
        DuplicateTokenEx(
            token.as_raw_handle(),
            0x0200_0000,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut copy,
        )
    };
    if duplicated == 0 {
        return Err(io::Error::last_os_error());
    }
    let copy = owned(copy)?;
    // SAFETY: a null thread means this one; the token is an impersonation
    // token made from this process's own.
    if unsafe { SetThreadToken(std::ptr::null(), copy.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = act();
    // SAFETY: gives this thread its process's token back.
    let reverted = unsafe { RevertToSelf() };
    assert!(reverted != 0, "the thread kept the restricted token");
    Ok(result)
}

/// A process started with less than this one has. It is ended when this is
/// dropped.
#[derive(Debug)]
pub struct Lowered(OwnedHandle);

impl Lowered {
    /// Starts `command_line` at medium integrity.
    pub fn start(command_line: &str) -> io::Result<Lowered> {
        Lowered::at(Level::Medium, command_line)
    }

    /// Starts `command_line` at `level`, which must not be above this
    /// process's own.
    pub fn at(level: Level, command_line: &str) -> io::Result<Lowered> {
        Lowered::with(&labelled(level)?, command_line, CREATE_NO_WINDOW)
    }

    /// Starts `command_line` at `level` with no console at all: a console
    /// program lowered to low integrity cannot start one (it ends
    /// `0xC0000142` before its first line, measured).
    pub fn apart_at(level: Level, command_line: &str) -> io::Result<Lowered> {
        Lowered::with(&labelled(level)?, command_line, DETACHED_PROCESS)
    }

    /// Starts `command_line` under a copy of this process's token restricted
    /// to `restricting`, given as text. A list that leaves out the logon
    /// session's own identifier cannot start a process in a desktop session.
    pub fn restricted_to(restricting: &[&str], command_line: &str) -> io::Result<Lowered> {
        Lowered::with(&restricted(restricting)?, command_line, DETACHED_PROCESS)
    }

    /// Starts `command_line` under `token` with no window and nothing
    /// inherited.
    fn with(token: &OwnedHandle, command_line: &str, flags: u32) -> io::Result<Lowered> {
        let mut line: Vec<u16> = command_line.encode_utf16().chain([0]).collect();
        // SAFETY: all-zero with its size set is the documented default.
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = u32::try_from(size_of::<STARTUPINFOW>()).unwrap_or_default();
        // SAFETY: all-zero is a valid value to be filled in.
        let mut started: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the token is a primary token this process made from its
        // own; the command line is a mutable NUL-terminated buffer; every
        // other pointer is null or a valid structure.
        let created = unsafe {
            CreateProcessAsUserW(
                token.as_raw_handle(),
                std::ptr::null(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                flags,
                std::ptr::null(),
                std::ptr::null(),
                &raw const startup,
                &raw mut started,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        drop(owned(started.hThread));
        owned(started.hProcess).map(Lowered)
    }

    /// Waits up to `limit` for the process to end, and gives its exit status
    /// if it has.
    pub fn wait(&self, limit: Duration) -> Option<u32> {
        let limit = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: the handle is the process this value owns.
        if unsafe { WaitForSingleObject(self.0.as_raw_handle(), limit) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut status = 0u32;
        // SAFETY: as above; `status` is writable.
        let asked = unsafe { GetExitCodeProcess(self.0.as_raw_handle(), &raw mut status) };
        (asked != 0).then_some(status)
    }
}

impl Drop for Lowered {
    fn drop(&mut self) {
        // SAFETY: the handle is the process this value owns; ending one that
        // has already ended does nothing.
        unsafe { TerminateProcess(self.0.as_raw_handle(), 1) };
    }
}
