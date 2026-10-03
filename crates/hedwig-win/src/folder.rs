//! Where the folders Windows names are, as Windows resolves them for this
//! process's own account.

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY};
use windows_sys::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_Programs, FOLDERID_System, FOLDERID_UserProgramFiles,
    SHGetKnownFolderPath,
};
use windows_sys::core::GUID;

use crate::raw::owned;
use crate::token::wide_length;

/// The known folder for application data that stays on this machine. The
/// folder can be redirected, and `LOCALAPPDATA` is whatever somebody set it
/// to.
pub fn local() -> io::Result<PathBuf> {
    known(FOLDERID_LocalAppData)
}

/// The known folder a program installed for this person alone goes in.
pub fn programs() -> io::Result<PathBuf> {
    known(FOLDERID_UserProgramFiles)
}

/// The person's own Start menu programs folder.
pub fn start_menu() -> io::Result<PathBuf> {
    known(FOLDERID_Programs)
}

/// Windows' own system folder.
pub fn system() -> io::Result<PathBuf> {
    known(FOLDERID_System)
}

/// The known folder `which`, asked of Windows every time as this process's
/// own account. The token is given because, given none, Windows expands the
/// person's registered location with this process's own `USERPROFILE`,
/// which a process can be started with another value of.
fn known(which: GUID) -> io::Result<PathBuf> {
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle for this process is always valid.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `handle` is a valid place for the opened token.
    let opened = unsafe {
        OpenProcessToken(
            process,
            TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
            &raw mut handle,
        )
    };
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owned(handle)?;
    // SAFETY: no reserved pointer; the call is balanced below when it
    // succeeds.
    let initialised =
        unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED.cast_unsigned()) };
    let mut path = std::ptr::null_mut();
    // SAFETY: the identifier and the token outlive the call, and `path`
    // receives memory freed below whatever the outcome.
    let found =
        unsafe { SHGetKnownFolderPath(&raw const which, 0, token.as_raw_handle(), &raw mut path) };
    let folder = if found >= 0 && !path.is_null() {
        // SAFETY: on success `path` is a NUL-terminated string.
        let length = unsafe { wide_length(path) };
        // SAFETY: the string is `length` units long, as just measured.
        let units = unsafe { std::slice::from_raw_parts(path, length) };
        Ok(PathBuf::from(OsString::from_wide(units)))
    } else {
        Err(io::Error::from_raw_os_error(found))
    };
    // SAFETY: the memory was allocated by the call above, or is null.
    unsafe { CoTaskMemFree(path.cast()) };
    if initialised >= 0 {
        // SAFETY: balances the successful initialisation above.
        unsafe { CoUninitialize() };
    }
    folder
}
