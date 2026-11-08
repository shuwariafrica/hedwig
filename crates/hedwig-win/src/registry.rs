//! A value an installer registered, read as the installed program's own
//! libraries read it; and the values of the person's own hive Hedwig keeps:
//! what Windows starts at their sign-in, and where it lists what is
//! installed for them. Nothing here writes outside the person's own hive.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_DWORD, REG_SZ, RRF_RT_REG_EXPAND_SZ,
    RRF_RT_REG_SZ, RRF_SUBKEY_WOW6432KEY, RRF_SUBKEY_WOW6464KEY, RegDeleteKeyValueW, RegDeleteKeyW,
    RegDeleteTreeW, RegSetKeyValueW,
};

/// The key under the person's own hive whose values Windows starts at their
/// desktop sign-in.
pub const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The key under the person's own hive where Windows lists the applications
/// installed for them alone.
pub const UNINSTALL: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";

/// `value` under `key` in the person's own hive, where it is a string.
///
/// # Errors
///
/// What the system said, other than that nothing is there.
pub fn own(key: &str, value: &str) -> io::Result<Option<OsString>> {
    read(HKEY_CURRENT_USER, &wide(key), &wide(value), 0)
}

/// Sets `value` under `key` in the person's own hive to a string, making the
/// key where it is not there.
///
/// # Errors
///
/// What the system said.
pub fn set_text(key: &str, value: &str, text: &OsStr) -> io::Result<()> {
    let data: Vec<u16> = text.encode_wide().chain(Some(0)).collect();
    let bytes = u32::try_from(data.len() * 2).map_err(|_| io::Error::from_raw_os_error(87))?;
    set(key, value, REG_SZ, data.as_ptr().cast(), bytes)
}

/// Sets `value` under `key` in the person's own hive to a number.
///
/// # Errors
///
/// What the system said.
pub fn set_number(key: &str, value: &str, number: u32) -> io::Result<()> {
    set(key, value, REG_DWORD, (&raw const number).cast(), 4)
}

fn set(
    key: &str,
    value: &str,
    kind: u32,
    data: *const core::ffi::c_void,
    bytes: u32,
) -> io::Result<()> {
    let (key, value) = (wide(key), wide(value));
    // SAFETY: both names are NUL-terminated; `data` points at `bytes`
    // readable bytes for the call.
    let failed = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            kind,
            data,
            bytes,
        )
    };
    if failed == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(failed.cast_signed()))
    }
}

/// Removes `value` under `key` in the person's own hive. Returns whether it
/// was there.
///
/// # Errors
///
/// What the system said, other than that it was not there.
pub fn remove_value(key: &str, value: &str) -> io::Result<bool> {
    let (key, value) = (wide(key), wide(value));
    // SAFETY: both names are NUL-terminated.
    let failed = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr()) };
    match failed {
        0 => Ok(true),
        ERROR_FILE_NOT_FOUND => Ok(false),
        other => Err(io::Error::from_raw_os_error(other.cast_signed())),
    }
}

/// Removes `key` and everything beneath it in the person's own hive.
/// Returns whether it was there.
///
/// # Errors
///
/// What the system said, other than that it was not there.
pub fn remove_key(key: &str) -> io::Result<bool> {
    let key = wide(key);
    // SAFETY: the name is NUL-terminated; this empties the key.
    let emptied = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, key.as_ptr()) };
    match emptied {
        0 => {}
        ERROR_FILE_NOT_FOUND => return Ok(false),
        other => return Err(io::Error::from_raw_os_error(other.cast_signed())),
    }
    // SAFETY: the name is NUL-terminated; the key is empty now.
    let removed = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, key.as_ptr()) };
    match removed {
        0 | ERROR_FILE_NOT_FOUND => Ok(true),
        other => Err(io::Error::from_raw_os_error(other.cast_signed())),
    }
}

use crate::raw::wide;

fn read(root: HKEY, key: &[u16], value: &[u16], view: u32) -> io::Result<Option<OsString>> {
    let mut units = vec![0u16; 260];
    loop {
        let mut size = u32::try_from(units.len() * 2).unwrap_or(u32::MAX);
        // SAFETY: both names are NUL-terminated; `units` is `size` writable
        // bytes; the call expands an expandable string itself.
        let failed = unsafe {
            windows_sys::Win32::System::Registry::RegGetValueW(
                root,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | view,
                std::ptr::null_mut(),
                units.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        match failed {
            0 => {
                let length = (size as usize / 2).saturating_sub(1);
                let text = units.get(..length).unwrap_or_default();
                return Ok(Some(OsString::from_wide(text)));
            }
            ERROR_MORE_DATA => units.resize((size as usize).div_ceil(2) + 1, 0),
            ERROR_FILE_NOT_FOUND => return Ok(None),
            other => return Err(io::Error::from_raw_os_error(other.cast_signed())),
        }
    }
}

/// `value` under `key`, as libgpg-error's registry reader finds it
/// (`w32-reg.c`): the person's own hive, then the machine's, in this
/// process's view of the registry; then the same in the other view, where a
/// 32-bit program's installer registers on a 64-bit Windows.
///
/// # Errors
///
/// What the system said, other than that nothing is there.
pub fn registered(key: &str, value: &str) -> io::Result<Option<OsString>> {
    let (key, value) = (wide(key), wide(value));
    let (own, other) = if cfg!(target_pointer_width = "64") {
        (RRF_SUBKEY_WOW6464KEY, RRF_SUBKEY_WOW6432KEY)
    } else {
        (RRF_SUBKEY_WOW6432KEY, RRF_SUBKEY_WOW6464KEY)
    };
    for view in [own, other] {
        for root in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
            if let Some(found) = read(root, &key, &value, view)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}
