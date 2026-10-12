//! The release a program's file states, read by Windows from the file's own
//! version resource. Nothing is started to ask it.

use std::io;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
};

use crate::raw::{code, wide};

/// What the size query fails with for a file that carries no resources, or
/// none of this kind.
const NO_RESOURCES: [u32; 3] = [1812, 1813, 1814];

/// What marks the fixed part of a version resource.
const SIGNATURE: u32 = 0xfeef_04bd;

/// The four numbers of the file version `program` states, or `None` where
/// its file states none.
///
/// # Errors
///
/// What the system said: the file is not there, or cannot be read.
pub fn release(program: &Path) -> io::Result<Option<[u16; 4]>> {
    let path = wide(program);
    // SAFETY: `path` is NUL-terminated; the handle out pointer may be null.
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), std::ptr::null_mut()) };
    if size == 0 {
        let error = io::Error::last_os_error();
        return if NO_RESOURCES.contains(&code(&error)) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let mut buffer = vec![0u32; (size as usize).div_ceil(4)];
    // SAFETY: `buffer` is at least `size` writable bytes.
    let read = unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, buffer.as_mut_ptr().cast()) };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    let root = wide("\\");
    let mut fixed = std::ptr::null_mut();
    let mut length = 0u32;
    // SAFETY: `buffer` holds the resource just read; `root` is
    // NUL-terminated; the two out pointers are valid.
    let found = unsafe {
        VerQueryValueW(
            buffer.as_ptr().cast(),
            root.as_ptr(),
            &raw mut fixed,
            &raw mut length,
        )
    };
    if found == 0 || (length as usize) < size_of::<VS_FIXEDFILEINFO>() {
        return Ok(None);
    }
    // SAFETY: on success `fixed` points at `length` bytes inside `buffer`,
    // enough for the structure, which is read wherever it lies.
    let fixed = unsafe { fixed.cast::<VS_FIXEDFILEINFO>().read_unaligned() };
    if fixed.dwSignature != SIGNATURE {
        return Ok(None);
    }
    let [major, minor] = halves(fixed.dwFileVersionMS);
    let [build, revision] = halves(fixed.dwFileVersionLS);
    Ok(Some([major, minor, build, revision]))
}

/// The high and the low half of a version word.
fn halves(word: u32) -> [u16; 2] {
    let [a, b, c, d] = word.to_be_bytes();
    [u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d])]
}
