//! Which processes have a file in use, as Restart Manager says: what an installer
//! asks before it replaces or removes a folder, since Windows lets a folder
//! be renamed while a program runs from it.

use std::io;
use std::path::{Path, PathBuf};

use windows_sys::Win32::System::RestartManager::{
    CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
    RmStartSession,
};

use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
};
use windows_sys::core::BOOL;

use crate::raw::wide;

/// A process with one of the files asked about in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Using {
    pub process: u32,
    /// The name Windows gives it.
    pub name: String,
}

/// Every process with any of `files` in use.
///
/// # Errors
///
/// What Restart Manager said.
pub fn using(files: &[PathBuf]) -> io::Result<Vec<Using>> {
    let mut session = 0u32;
    let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
    // SAFETY: both out parameters are valid for the call.
    let started = unsafe { RmStartSession(&raw mut session, 0, key.as_mut_ptr()) };
    if started != 0 {
        return Err(io::Error::from_raw_os_error(started.cast_signed()));
    }
    let listed = list(session, files);
    // SAFETY: the session was started above and is ended once.
    unsafe { RmEndSession(session) };
    listed
}

/// Asks each process holding any of `files` whose own program is in
/// `folder` - Hedwig's icon and window - to close, by posting `WM_CLOSE` to
/// each of its top-level windows as its own close button would. Nothing else
/// is asked and nothing is ended: one that stays is named by
/// [`using`] afterwards. The calling process is never asked: removal's own
/// surface runs from the icon's program.
///
/// # Errors
///
/// What Restart Manager said.
pub fn close(files: &[PathBuf], folder: &Path) -> io::Result<()> {
    let caller = std::process::id();
    for held in using(files)? {
        if held.process == caller {
            continue;
        }
        let ours = crate::process::Process::open(held.process)
            .and_then(|process| process.program())
            .is_ok_and(|program| program.starts_with(folder));
        if ours {
            close_windows(held.process);
        }
    }
    Ok(())
}

/// Posts `WM_CLOSE` to every top-level window of `process`, shown or not.
fn close_windows(process: u32) {
    // SAFETY: the callback is a valid enumerator for the call's duration,
    // and reads the process number it is given as its parameter.
    unsafe { EnumWindows(Some(each), isize::try_from(process).unwrap_or(isize::MAX)) };
}

/// Posts `WM_CLOSE` to `window` where the process `wanted` owns it.
unsafe extern "system" fn each(window: HWND, wanted: LPARAM) -> BOOL {
    let mut owner = 0u32;
    // SAFETY: `window` is the window being enumerated; `owner` is valid.
    unsafe { GetWindowThreadProcessId(window, &raw mut owner) };
    if isize::try_from(owner).is_ok_and(|owner| owner == wanted) {
        // SAFETY: posting asks; the window's own procedure decides.
        unsafe { PostMessageW(window, WM_CLOSE, 0, 0) };
    }
    1
}

fn register(session: u32, files: &[PathBuf]) -> io::Result<()> {
    let names: Vec<Vec<u16>> = files.iter().map(wide).collect();
    let pointers: Vec<*const u16> = names.iter().map(Vec::as_ptr).collect();
    let count = u32::try_from(pointers.len()).map_err(|_| io::Error::from_raw_os_error(87))?;
    // SAFETY: `pointers` holds `count` NUL-terminated strings that outlive
    // the call; no processes or services are registered.
    let registered = unsafe {
        RmRegisterResources(
            session,
            count,
            pointers.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
        )
    };
    if registered == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(registered.cast_signed()))
    }
}

fn list(session: u32, files: &[PathBuf]) -> io::Result<Vec<Using>> {
    register(session, files)?;
    let mut room = 16u32;
    loop {
        let mut needed = 0u32;
        let mut count = room;
        let mut reasons = 0u32;
        let mut infos: Vec<RM_PROCESS_INFO> = Vec::with_capacity(room as usize);
        // SAFETY: `infos` has room for `count` entries, as `count` says.
        let got = unsafe {
            RmGetList(
                session,
                &raw mut needed,
                &raw mut count,
                infos.as_mut_ptr(),
                &raw mut reasons,
            )
        };
        match got {
            0 => {
                // SAFETY: the call wrote `count` entries, no more than room.
                unsafe { infos.set_len(count.min(room) as usize) };
                return Ok(infos
                    .iter()
                    .map(|info| Using {
                        process: info.Process.dwProcessId,
                        name: {
                            let name = &info.strAppName;
                            let end = name
                                .iter()
                                .position(|unit| *unit == 0)
                                .unwrap_or(name.len());
                            String::from_utf16_lossy(name.get(..end).unwrap_or_default())
                        },
                    })
                    .collect());
            }
            // ERROR_MORE_DATA: more hold the files than there was room for.
            234 => room = needed.max(room.saturating_mul(2)),
            other => return Err(io::Error::from_raw_os_error(other.cast_signed())),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use std::fs::File;

    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, MSG, PM_REMOVE, PeekMessageW, WS_OVERLAPPED,
    };

    use super::*;

    /// Whether a `WM_CLOSE` is waiting in this thread's queue for `window`,
    /// taking it out.
    fn asked_to_close(window: HWND) -> bool {
        let mut message = MSG::default();
        // SAFETY: `message` is valid for the call, and `window` is this
        // thread's.
        unsafe { PeekMessageW(&raw mut message, window, WM_CLOSE, WM_CLOSE, PM_REMOVE) != 0 }
    }

    /// Removal runs from the icon's program, whose own windows hold files of
    /// the folder it removes: it is never asked to close by its own act,
    /// while the same request reaches another process's windows.
    #[test]
    fn the_calling_process_is_not_asked_to_close_its_own_windows() {
        let folder = std::env::temp_dir().join(format!("hedwig-win-in-use-{}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("a folder");
        let file = folder.join("held.txt");
        std::fs::write(&file, b"held").expect("a file");
        let held = File::open(&file).expect("held by this process");
        let class = wide("STATIC");
        // SAFETY: a hidden top-level window of a system class, owned by this
        // thread and destroyed below.
        let window = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                std::ptr::null(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert!(!window.is_null());
        let ours = std::process::id();
        let program = std::env::current_exe().expect("this program");
        let holders = using(std::slice::from_ref(&file)).expect("Restart Manager answers");
        assert!(
            holders.iter().any(|holder| holder.process == ours),
            "{holders:?}"
        );

        close(
            std::slice::from_ref(&file),
            program.parent().expect("a folder"),
        )
        .expect("asked");
        let spared = !asked_to_close(window);

        // The control: the same request, made of this process directly,
        // reaches the window.
        close_windows(ours);
        let reached = asked_to_close(window);

        // SAFETY: the window was made above on this thread.
        unsafe { DestroyWindow(window) };
        drop(held);
        let _ = std::fs::remove_dir_all(&folder);
        assert!(spared, "the caller's own window was asked to close");
        assert!(reached, "a window of a process asked reaches its queue");
    }
}
