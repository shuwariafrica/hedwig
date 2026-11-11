//! What the modules share.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

/// `text` as the NUL-terminated UTF-16 the wide functions take.
pub(crate) fn wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain([0]).collect()
}

/// `text` copied into a fixed field of a structure, cut to leave its
/// terminator.
pub(crate) fn field<const N: usize>(text: &str) -> [u16; N] {
    let mut units = [0u16; N];
    for (unit, from) in units
        .iter_mut()
        .zip(text.encode_utf16().take(N.saturating_sub(1)))
    {
        *unit = from;
    }
    units
}

/// This executable's own module.
pub(crate) fn module() -> HINSTANCE {
    // SAFETY: a null name asks for the module of the calling process, which
    // is loaded for as long as the process runs.
    unsafe { GetModuleHandleW(std::ptr::null()) }
}

/// The size of a structure as the field Windows reads it from.
pub(crate) fn size<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or_default()
}

/// A failed call as the error Windows recorded for it.
pub(crate) fn last<T>() -> io::Result<T> {
    Err(io::Error::last_os_error())
}
