//! Whether a process runs a service an administrator installed, as the
//! service control manager says.
//!
//! A process of another account cannot be asked whose it is from medium
//! integrity: its token is closed to this one, and the system's own list of
//! processes leaves the account out (measured). The
//! service control manager lets any account list the services running and
//! the process each runs in, and only an administrator can install one.

use std::io;

use crate::raw::{code, wide};
use crate::token::wide_length;

use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    OpenServiceW, QueryServiceStatus, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_STATUS, SERVICE_WIN32,
};

/// The service control manager, opened to list services and closed when
/// dropped.
struct Manager(SC_HANDLE);

impl Drop for Manager {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `OpenSCManagerW` and is closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// Whether the service named `service` is running now; `false` for one not
/// installed. Asked with the rights any account holds.
///
/// # Errors
///
/// What the system said when it could not be asked.
pub fn is_running(service: &str) -> io::Result<bool> {
    // SAFETY: null names the local machine and its active database; the
    // right asked for is the one any account holds.
    let opened = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if opened.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = Manager(opened);
    let name = wide(service);
    // SAFETY: the manager is open and `name` NUL-terminated.
    let opened = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if opened.is_null() {
        let error = io::Error::last_os_error();
        return if code(&error) == ERROR_SERVICE_DOES_NOT_EXIST {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let service = Manager(opened);
    // SAFETY: all-zero is a valid status, overwritten below.
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: the service is open with the right to query it, and `status`
    // a valid place for the answer.
    if unsafe { QueryServiceStatus(service.0, &raw mut status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status.dwCurrentState == SERVICE_RUNNING)
}

/// The services the service control manager runs in `process` now, by
/// name; none for a process that runs none.
///
/// # Errors
///
/// What the system said when the services could not be listed.
pub fn services_in(process: u32) -> io::Result<Vec<String>> {
    // SAFETY: null names the local machine and its active database; the
    // right asked for is the one any account holds.
    let opened = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    if opened.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = Manager(opened);
    let (mut needed, mut returned) = (0u32, 0u32);
    // The list can grow between the call that sizes it and the one that
    // reads it, so the read is tried again with the size it then asks for.
    for _ in 0..8 {
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let size = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
        // Every read starts from the first service.
        let mut resume = 0u32;
        // SAFETY: `buffer` is `size` writable bytes aligned for the records;
        // each out pointer is valid; no group is named.
        let listed = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                buffer.as_mut_ptr().cast(),
                size,
                &raw mut needed,
                &raw mut returned,
                &raw mut resume,
                std::ptr::null(),
            )
        };
        if listed == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(234) {
                // ERROR_MORE_DATA: `needed` holds the size the list now has.
                continue;
            }
            return Err(error);
        }
        let first = buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>();
        // SAFETY: the call wrote `returned` records at the start of `buffer`,
        // which outlives this slice; the names they point at lie in it too.
        let services = unsafe { std::slice::from_raw_parts(first, returned as usize) };
        return Ok(services
            .iter()
            .filter(|service| service.ServiceStatusProcess.dwProcessId == process)
            .map(|service| {
                // SAFETY: each name is NUL-terminated inside `buffer`.
                let length = unsafe { wide_length(service.lpServiceName) };
                // SAFETY: as above, `length` units are readable there.
                let units = unsafe { std::slice::from_raw_parts(service.lpServiceName, length) };
                String::from_utf16_lossy(units)
            })
            .collect());
    }
    Err(io::Error::from(io::ErrorKind::ResourceBusy))
}
