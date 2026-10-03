//! Whether a token would be let read a file: Windows' own access check, run
//! against the file's own security descriptor.
//!
//! The relay asks it of the process listening where gpg-agent's socket file
//! points, before that process is given the file's sixteen bytes. A process
//! the file would admit could read the bytes itself, so it learns nothing it
//! could not; one the file would refuse is never told them.

use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AccessCheck, DACL_SECURITY_INFORMATION, DuplicateTokenEx, GENERIC_MAPPING,
    GROUP_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PRIVILEGE_SET, PSECURITY_DESCRIPTOR, SecurityIdentification, TOKEN_QUERY, TokenImpersonation,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

use crate::raw::{owned, wide};
use crate::token::{Sid, Token};

/// A file's security descriptor, freed when dropped.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by `GetNamedSecurityInfoW` and freed once, here.
        unsafe { LocalFree(self.0) };
    }
}

fn descriptor(file: &Path) -> io::Result<Descriptor> {
    let name = wide(file);
    let mut held: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let wanted = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION;
    // SAFETY: `name` is NUL-terminated; the four parts are not asked for
    // separately, so their pointers may be null; `held` receives memory the
    // returned value frees.
    let failed = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            wanted,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut held,
        )
    };
    if failed != 0 {
        return Err(io::Error::from_raw_os_error(failed.cast_signed()));
    }
    Ok(Descriptor(held))
}

/// An identification-level copy of `token`: enough to be checked against a
/// descriptor, and never enough to act as its holder.
fn identification(token: &Token) -> io::Result<OwnedHandle> {
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: the token is open with the duplicate right; `copy` receives a
    // new handle that `owned` takes.
    let made = unsafe {
        DuplicateTokenEx(
            token.raw(),
            TOKEN_QUERY,
            std::ptr::null(),
            SecurityIdentification,
            TokenImpersonation,
            &raw mut copy,
        )
    };
    if made == 0 {
        return Err(io::Error::last_os_error());
    }
    owned(copy)
}

impl Token {
    /// Whether Windows' own access check admits this token as `person`: the
    /// check the control pipe's descriptor makes of a client
    /// ([`crate::pipe::Listener::bind`]), so a process is the person's at
    /// every door alike - the account, at medium integrity or above, not
    /// restricted to less, not in an application container - whatever logon,
    /// session or level it runs in.
    ///
    /// The token must be opened to be duplicated
    /// ([`crate::process::Process::token_to_check`]).
    ///
    /// # Errors
    ///
    /// What the system said: the descriptor could not be made, or the token
    /// copied.
    pub fn is_the_person(&self, person: &Sid) -> io::Result<bool> {
        let descriptor = crate::pipe::the_persons(person)?;
        let copy = identification(self)?;
        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        let mut privileges = PRIVILEGE_SET::default();
        let mut length = u32::try_from(size_of::<PRIVILEGE_SET>()).unwrap_or(u32::MAX);
        let mut granted = 0u32;
        let mut allowed = 0;
        // SAFETY: the descriptor and the copy are alive for the call; every
        // out pointer is to a writable value of its type, `length` the size
        // of `privileges`.
        let checked = unsafe {
            AccessCheck(
                descriptor.0,
                copy.as_raw_handle(),
                crate::pipe::RIGHTS,
                &raw const mapping,
                &raw mut privileges,
                &raw mut length,
                &raw mut granted,
                &raw mut allowed,
            )
        };
        if checked == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(allowed != 0 && granted & crate::pipe::RIGHTS == crate::pipe::RIGHTS)
    }

    /// Whether a process holding this token could open `file` to read it, as
    /// `GnuPG`'s own clients open a socket file. Every way a token can be
    /// lowered - a restricting list, an identifier made deny-only, an
    /// application container, an integrity level - and every grant the file
    /// makes is weighed by the system's own check, not by this crate.
    ///
    /// The token must be opened to be duplicated
    /// ([`crate::process::Process::token_to_check`]).
    ///
    /// # Errors
    ///
    /// What the system said: the file's descriptor could not be read, or the
    /// token copied.
    pub fn may_read(&self, file: &Path) -> io::Result<bool> {
        let descriptor = descriptor(file)?;
        let copy = identification(self)?;
        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        let mut privileges = PRIVILEGE_SET::default();
        let mut length = u32::try_from(size_of::<PRIVILEGE_SET>()).unwrap_or(u32::MAX);
        let mut granted = 0u32;
        let mut allowed = 0;
        // SAFETY: the descriptor and the copy are alive for the call; every
        // out pointer is to a writable value of its type, `length` the size
        // of `privileges`.
        let checked = unsafe {
            AccessCheck(
                descriptor.0,
                copy.as_raw_handle(),
                FILE_GENERIC_READ,
                &raw const mapping,
                &raw mut privileges,
                &raw mut length,
                &raw mut granted,
                &raw mut allowed,
            )
        };
        if checked == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(allowed != 0 && granted & FILE_GENERIC_READ == FILE_GENERIC_READ)
    }
}
