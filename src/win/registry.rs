use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt as _;

use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_SZ, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW,
    RegSetKeyValueW,
};

const ERROR_FILE_NOT_FOUND: u32 = 2;

fn nul_terminated(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

/// `None` when the value is missing or is not a string. Redirection is not
/// applied: a caller wanting the 32-bit view passes the `WOW6432Node` path.
pub(crate) fn local_machine_string(subkey: &str, value: &str) -> Option<String> {
    let subkey = nul_terminated(subkey);
    let value = nul_terminated(value);
    let mut size: u32 = 0;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut size,
        )
    };
    if rc != 0 || size == 0 {
        return None;
    }
    let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &raw mut size,
        )
    };
    if rc != 0 {
        return None;
    }
    let len = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    #[allow(
        clippy::indexing_slicing,
        reason = "len comes from position within buffer"
    )]
    Some(String::from_utf16_lossy(&buffer[..len]))
}

/// Written as UTF-16 without transiting a `String`, so a path Windows accepts
/// but Rust cannot represent as UTF-8 still round-trips.
pub(crate) fn set_current_user_string(
    subkey: &str,
    value: &str,
    data: &OsStr,
) -> Result<(), String> {
    let subkey = nul_terminated(subkey);
    let value = nul_terminated(value);
    let data: Vec<u16> = data.encode_wide().chain([0]).collect();
    let Ok(byte_len) = u32::try_from(data.len() * 2) else {
        return Err("value is too long for the registry".into());
    };
    let rc = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            value.as_ptr(),
            REG_SZ,
            data.as_ptr().cast(),
            byte_len,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("registry write failed with code {rc}"))
    }
}

/// Already absent counts as removed, so a repeated uninstall is not an error.
pub(crate) fn delete_current_user_value(subkey: &str, value: &str) -> Result<(), String> {
    let subkey = nul_terminated(subkey);
    let value = nul_terminated(value);
    let rc = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, subkey.as_ptr(), value.as_ptr()) };
    if rc == 0 || rc == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(format!("registry delete failed with code {rc}"))
    }
}
