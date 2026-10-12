//! The things about files the standard library does not reach: replacing
//! one by another so that the replacement is on disk before the call returns,
//! and a claim on a file that every reader can read beside.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    MoveFileExW, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::raw::wide;

/// Where a claim's lock sits: one byte far past anything a claimed file
/// holds, so no reader of its content ever meets it.
pub const CLAIM_AT: u64 = 0x7FFF_FFFF_FFFF_FF00;

/// [`CLAIM_AT`] as the two halves an `OVERLAPPED` carries it in.
const LOW: u32 = 0xFFFF_FF00;
const HIGH: u32 = 0x7FFF_FFFF;

/// The share mode a claim's holder and its writer open with: others may read
/// the file and write it, and nobody may remove it while the claim is held.
/// The holder itself only reads, so a reader that allows no writer beside it
/// is not refused.
pub const HOLDING: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;

/// Opens `path` as a claim's holder does: for reading, sharing [`HOLDING`].
///
/// # Errors
///
/// What the system said.
pub fn open_holding(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).share_mode(HOLDING).open(path)
}

/// Takes the claim on a file opened with [`open_holding`]: `Ok(false)` while
/// another handle holds it. The claim lasts until `file` closes, which
/// Windows does when its process ends however it ends.
///
/// # Errors
///
/// What the system said, other than that the claim is held.
pub fn claim(file: &File) -> io::Result<bool> {
    // SAFETY: an all-zero OVERLAPPED is valid; the offset is set below.
    let mut at: OVERLAPPED = unsafe { std::mem::zeroed() };
    at.Anonymous.Anonymous.Offset = LOW;
    at.Anonymous.Anonymous.OffsetHigh = HIGH;
    // SAFETY: the handle is open for the call, and `at` outlives it.
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &raw mut at,
        )
    };
    if locked != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION.cast_signed()) {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Whether something holds the claim on the file at `path`. It needs the
/// right to read that one file, nothing of the holder's process, and leaves
/// the file as it found it.
///
/// # Errors
///
/// What the system said, other than that the file is not there.
pub fn held(path: &Path) -> io::Result<bool> {
    let file = match OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if claim(&file)? {
        // SAFETY: an all-zero OVERLAPPED is valid; the offset is the one
        // just locked through this handle.
        let mut at: OVERLAPPED = unsafe { std::mem::zeroed() };
        at.Anonymous.Anonymous.Offset = LOW;
        at.Anonymous.Anonymous.OffsetHigh = HIGH;
        // SAFETY: the handle is open and holds the lock being let go.
        unsafe { UnlockFileEx(file.as_raw_handle() as HANDLE, 0, 1, 0, &raw mut at) };
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Puts `new` in the place of `old`. The name `old` refers to a whole file
/// before and after - the one it named, or `new` - and the change is on disk
/// when this returns.
pub fn replace(new: &Path, old: &Path) -> io::Result<()> {
    let from = wide(new);
    let to = wide(old);
    // SAFETY: both paths are NUL-terminated.
    let moved = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
