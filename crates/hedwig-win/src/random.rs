//! Bytes nobody can guess, from the system's own generator.

use std::io;

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};

/// Fills `bytes` from the system-preferred random number generator.
pub fn fill(bytes: &mut [u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: no algorithm handle is needed with the system-preferred flag,
    // and `bytes` is `length` writable bytes.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "the system random number generator failed with status {status:#x}"
        )));
    }
    Ok(())
}
