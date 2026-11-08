//! Windows' own installers closing a program: Restart Manager's shutdown of
//! every process that holds a file, as an installer that replaces the file
//! asks for it.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::System::RestartManager::{
    CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources, RmShutdown,
    RmStartSession,
};

/// The processes Restart Manager lists as holding `file`, each with the name
/// it gives them; then what its shutdown of them answered.
pub(crate) fn shut_down(file: &Path) -> (Vec<(u32, String)>, u32) {
    let mut session = 0u32;
    let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
    // SAFETY: both outputs are valid for the call.
    let started = unsafe { RmStartSession(&raw mut session, 0, key.as_mut_ptr()) };
    assert_eq!(started, 0, "RmStartSession");
    let name: Vec<u16> = file.as_os_str().encode_wide().chain([0]).collect();
    let names = [name.as_ptr()];
    // SAFETY: one NUL-terminated path, alive for the call.
    let registered = unsafe {
        RmRegisterResources(
            session,
            1,
            names.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
        )
    };
    assert_eq!(registered, 0, "RmRegisterResources");
    let mut needed = 0u32;
    let mut room = 16u32;
    let mut reasons = 0u32;
    let mut found = vec![RM_PROCESS_INFO::default(); 16];
    // SAFETY: `found` holds `room` entries; the outputs are valid.
    let listed = unsafe {
        RmGetList(
            session,
            &raw mut needed,
            &raw mut room,
            found.as_mut_ptr(),
            &raw mut reasons,
        )
    };
    assert_eq!(listed, 0, "RmGetList");
    let holders = found
        .iter()
        .take(usize::try_from(room).unwrap_or_default())
        .map(|info| {
            let name = &info.strAppName;
            let end = name
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(name.len());
            (
                info.Process.dwProcessId,
                String::from_utf16_lossy(name.get(..end).unwrap_or_default()),
            )
        })
        .collect();
    // SAFETY: no progress callback; the session is this function's own.
    let shut = unsafe { RmShutdown(session, 0, None) };
    // SAFETY: as above.
    unsafe { RmEndSession(session) };
    (holders, shut)
}
