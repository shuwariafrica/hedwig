//! What this session and its desktop are, as Windows says.
//!
//! The interface exists only in a session with a desktop. Whether the person
//! can be shown anything there - unlocked, connected, not presenting, and
//! whether an application fills the screen - is asked of Windows here and
//! decided in `hedwig-view`.

use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSConnectState, WTSFreeMemory,
    WTSQuerySessionInformationW,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_READOBJECTS, GetProcessWindowStation, GetUserObjectInformationW,
    OpenInputDesktop, UOI_FLAGS, USEROBJECTFLAGS,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetDoubleClickTime;
use windows_sys::Win32::UI::Shell::SHQueryUserNotificationState;
use windows_sys::Win32::UI::WindowsAndMessaging::WSF_VISIBLE;

use hedwig_view::card::Desk;
use hedwig_view::presence::Desktop;

use crate::raw::size;

/// The state a session reports when its connection to a display is closed.
const DISCONNECTED: i32 = 4;

/// Whether this process is in a session that has a desktop at all. A process
/// started over SSH is on a window station nobody sees, where nothing the
/// interface draws would reach the person.
pub fn interactive() -> bool {
    // SAFETY: no arguments; the handle returned is this process's own and is
    // not closed.
    let station = unsafe { GetProcessWindowStation() };
    let mut flags = USEROBJECTFLAGS::default();
    let mut needed = 0u32;
    // SAFETY: `flags` is a writable structure of the size given, and `needed`
    // a valid place for the size the call wanted.
    let read = unsafe {
        GetUserObjectInformationW(
            station,
            UOI_FLAGS,
            (&raw mut flags).cast(),
            size::<USEROBJECTFLAGS>(),
            &raw mut needed,
        )
    };
    read != 0 && flags.dwFlags & WSF_VISIBLE.cast_unsigned() != 0
}

/// Whether the desktop is locked, whether the session is disconnected, and
/// what the desktop takes, asked at start; Windows' notifications keep them
/// in step afterwards.
pub fn desktop() -> Desktop {
    // While the desktop is locked the desktop that takes input is Winlogon's,
    // which an application cannot open.
    // SAFETY: no pointers; a handle that is returned is closed below.
    let input = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
    let locked = input.is_null();
    if !locked {
        // SAFETY: the handle was just opened by this process.
        unsafe { CloseDesktop(input) };
    }
    let mut state = std::ptr::null_mut();
    let mut length = 0u32;
    // SAFETY: both out pointers are valid; the buffer the call allocates is
    // freed below.
    let asked = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSConnectState,
            &raw mut state,
            &raw mut length,
        )
    };
    let mut disconnected = false;
    if asked != 0 && !state.is_null() {
        if length as usize >= size_of::<i32>() {
            // SAFETY: on success the buffer holds the connection state as one
            // 32-bit integer, which need not be aligned.
            let connection = unsafe { state.cast::<i32>().read_unaligned() };
            disconnected = connection == DISCONNECTED;
        }
        // SAFETY: the buffer was allocated by the query above.
        unsafe { WTSFreeMemory(state.cast()) };
    }
    Desktop {
        locked,
        disconnected,
        desk: desk(),
    }
}

/// What the desktop will take now, by the shell's own account.
pub fn desk() -> Desk {
    let mut state = 0i32;
    // SAFETY: `state` is a valid place for the answer.
    let answered = unsafe { SHQueryUserNotificationState(&raw mut state) };
    if answered < 0 {
        return Desk::Away;
    }
    match state {
        // A screen saver, a locked machine, or another person's session.
        1 => Desk::Away,
        2 => Desk::Filled,
        3 => Desk::Exclusive,
        4 => Desk::Presenting,
        _ => Desk::Open,
    }
}

/// The longest two presses can be apart and still be one act, in
/// milliseconds: the person's own setting.
pub fn settle() -> u32 {
    // SAFETY: no arguments and no failure.
    unsafe { GetDoubleClickTime() }
}
