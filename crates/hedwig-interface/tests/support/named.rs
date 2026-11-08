//! What Windows reads of a built executable of Hedwig's: the strings of its
//! version information, and its icon at a size.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::FreeLibrary;
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE, LoadLibraryExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{HICON, IMAGE_ICON, LR_DEFAULTCOLOR, LoadImageW};

fn wide(text: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain([0]).collect()
}

/// The string `key` of the file's version information in UK English.
pub(crate) fn version(file: &Path, key: &str) -> Option<String> {
    let path = wide(file);
    // SAFETY: the path is NUL-terminated.
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), std::ptr::null_mut()) };
    let mut block = vec![0_u8; usize::try_from(size).ok()?];
    // SAFETY: the block is as large as Windows asked for.
    let read = unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, block.as_mut_ptr().cast()) };
    if read == 0 {
        return None;
    }
    let query = wide(format!("\\StringFileInfo\\080904b0\\{key}"));
    let mut value: *mut c_void = std::ptr::null_mut();
    let mut length = 0_u32;
    // SAFETY: the block is the one Windows filled; the places are valid.
    let found = unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            query.as_ptr(),
            &raw mut value,
            &raw mut length,
        )
    };
    if found == 0 || value.is_null() {
        return None;
    }
    // SAFETY: Windows points into the block at `length` UTF-16 units, the
    // last its terminator.
    let units =
        unsafe { std::slice::from_raw_parts(value.cast::<u16>(), usize::try_from(length).ok()?) };
    Some(
        String::from_utf16_lossy(units)
            .trim_end_matches('\0')
            .to_owned(),
    )
}

/// The file's icon, `side` pixels square, as Windows loads it from the
/// file's resources: Windows chooses which image of the group to take.
pub(crate) fn icon(file: &Path, side: i32) -> Option<HICON> {
    let path = wide(file);
    // SAFETY: the path is NUL-terminated; the file is mapped for its
    // resources alone and never run.
    let module = unsafe {
        LoadLibraryExW(
            path.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE,
        )
    };
    if module.is_null() {
        return None;
    }
    // SAFETY: the module is loaded; resource 1 is named by its ordinal.
    let icon = unsafe {
        LoadImageW(
            module,
            std::ptr::without_provenance(1),
            IMAGE_ICON,
            side,
            side,
            LR_DEFAULTCOLOR,
        )
    };
    // SAFETY: the icon is a copy of the resource's, which outlives the module.
    unsafe { FreeLibrary(module) };
    (!icon.is_null()).then_some(icon)
}
