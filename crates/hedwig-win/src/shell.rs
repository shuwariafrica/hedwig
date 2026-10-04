//! What Windows opens an address with for the person: their default browser
//! for an `https` address, as the shell's own association names it.

use std::io;

use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::raw::wide;

/// Has the shell open `address` with what the person's associations name for
/// it, on this thread. COM is initialised on the thread for the call, since
/// the shell may hand the address to an extension; nothing waits on the
/// program it starts, and no dialog is shown where none answers.
///
/// # Errors
///
/// What the system said when nothing could be started for the address.
pub fn open(address: &str) -> io::Result<()> {
    // SAFETY: no reserved pointer; the flags are the ones the shell's
    // documentation asks of a thread that calls it.
    let initialised = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).cast_unsigned(),
        )
    };
    let (verb, file) = (wide("open"), wide(address));
    // SAFETY: all-zero is a valid value of the structure, filled in below.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = u32::try_from(size_of::<SHELLEXECUTEINFOW>()).unwrap_or_default();
    info.fMask = SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    // SAFETY: `info` is valid for the call and its strings are NUL-terminated
    // and outlive it.
    let opened = unsafe { ShellExecuteExW(&raw mut info) };
    let result = if opened == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    // Success, or already initialised on this thread: each is balanced.
    if initialised >= 0 {
        // SAFETY: balances the successful initialisation above.
        unsafe { CoUninitialize() };
    }
    result
}
