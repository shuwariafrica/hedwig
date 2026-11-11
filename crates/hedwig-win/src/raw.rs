//! What the modules share: owned handles, wide strings, memory the system
//! allocated, and a signal threads wait on.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{
    HANDLE, INVALID_HANDLE_VALUE, LocalFree, TRUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};

/// `text` as the NUL-terminated UTF-16 the wide functions take.
pub(crate) fn wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain([0]).collect()
}

/// Takes ownership of a handle a creating function just returned, or reports
/// why it returned none.
pub(crate) fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle is valid, was just created for this process, and is
    // held by nothing else, so the returned value is its only owner.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// The Windows error code an [`io::Error`] carries, or zero.
pub(crate) fn code(error: &io::Error) -> u32 {
    error
        .raw_os_error()
        .and_then(|raw| u32::try_from(raw).ok())
        .unwrap_or_default()
}

/// Memory the system allocated with `LocalAlloc` and this process must free.
pub(crate) struct Local(pub(crate) *mut core::ffi::c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a function documented to allocate
            // with `LocalAlloc`, and is freed exactly once, here.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// A signal one thread raises and any number of waits observe. Once raised it
/// stays raised.
#[derive(Debug)]
pub struct Signal(OwnedHandle);

impl Signal {
    pub fn new() -> io::Result<Signal> {
        // SAFETY: no name and default security; both pointers may be null.
        let handle = unsafe { CreateEventW(std::ptr::null(), TRUE, 0, std::ptr::null()) };
        owned(handle).map(Signal)
    }

    pub fn raise(&self) -> io::Result<()> {
        // SAFETY: the handle is an event this value owns.
        if unsafe { SetEvent(self.raw()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Whether it has been raised.
    pub fn raised(&self) -> bool {
        // SAFETY: the handle is an event this value owns; a wait of no
        // length only reads its state.
        unsafe { WaitForSingleObject(self.raw(), 0) == WAIT_OBJECT_0 }
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
}
