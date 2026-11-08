//! The window's executable beside the presence: one window for each person,
//! desktop and Hedwig; the foreground the person's act gives, handed on to
//! the process that shows what they asked for; and the presence's card
//! brought forward from the window.
//!
//! A window is one Hedwig's - the folder it keeps its files in - so the key
//! of everything here is that folder. The objects are named in the session's
//! own namespace (`Local\`), which is the person's desktop.

use std::ffi::c_void;
use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND,
    INVALID_HANDLE_VALUE, LPARAM,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    PAGE_READWRITE, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, DestroyIcon, EnumWindows, FindWindowW, GW_OWNER, GetWindow,
    GetWindowThreadProcessId, HICON, ICON_BIG, ICON_SMALL, IMAGE_ICON, IsIconic, IsWindowVisible,
    LR_DEFAULTCOLOR, LoadImageW, PostMessageW, RegisterWindowMessageW, SM_CXICON, SM_CXSMICON,
    SW_RESTORE, SendMessageW, SetForegroundWindow, ShowWindow, WM_CLOSE, WM_SETICON,
};

use windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;

use crate::raw::{last, module, wide};

/// The class of the presence's unshown window (`host`).
pub(crate) const PRESENCE: &str = "hedwig.interface";
/// What the window posts the presence to have its card brought forward.
pub(crate) const BRING: &str = "hedwig.interface.bring";
/// What a second start of the presence posts the first to open the window.
pub(crate) const OPEN: &str = "hedwig.interface.open";

/// The key of one Hedwig's folder, the one an installation of that Hedwig is
/// named by, so the presence and the window of a Hedwig installed with
/// `--folder` claim what its Start entry and program folder are named for.
pub fn key(folder: &Path) -> String {
    hedwig_view::link::key(folder)
}

/// Names every window of this process to the taskbar as `id`, the identity
/// Hedwig's Start entry carries, so the window's button is that entry's: a pin
/// of either is one button, and starts Hedwig as the entry does. Windows reads
/// it only before the process shows anything.
///
/// # Errors
///
/// What Windows said.
pub fn identify(id: &str) -> io::Result<()> {
    let id = wide(id);
    // SAFETY: the identity is NUL-terminated and copied by the call.
    let said = unsafe { SetCurrentProcessExplicitAppUserModelID(id.as_ptr()) };
    if said < 0 {
        return Err(io::Error::from_raw_os_error(said));
    }
    Ok(())
}

/// The presence's unshown window's title, by which the window finds the
/// presence of its own hedwig.
pub(crate) fn presence_title(folder: &Path) -> String {
    format!("{PRESENCE} {}", key(folder))
}

/// What a start of the window found.
#[derive(Debug)]
pub enum Claim {
    /// This process is the window for this Hedwig at this desktop, for as
    /// long as the value is held.
    Held(Held),
    /// Another process is, and its window has been brought forward.
    Forwarded,
    /// Another process is and has no window yet: it is starting, and comes
    /// forward by itself.
    Starting,
}

/// The named section that says which process is the window, with this
/// process's number in it; nothing where another account holds the name.
#[derive(Debug)]
pub struct Held(Option<(HANDLE, *mut c_void)>);

impl Drop for Held {
    fn drop(&mut self) {
        if let Some((section, view)) = self.0 {
            // SAFETY: the view was mapped by `claim` and is not used after.
            unsafe { UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: view }) };
            // SAFETY: the handle is this value's own.
            unsafe { CloseHandle(section) };
        }
    }
}

/// How long a start that finds the window claimed and not shown waits for
/// the process holding it: one that is closing ends within a third of a
/// second here, one that is starting shows its window within half of one.
const ENDING: u32 = 2000;

/// Claims the window for the Hedwig that keeps its files in `folder`. Where
/// another account in this session holds the name, this process is a window
/// of its own: that account's window is not this person's.
///
/// # Errors
///
/// Windows could not make or map the section.
pub fn claim(folder: &Path) -> io::Result<Claim> {
    match claim_once(WINDOW, folder)? {
        Found::Claimed(claim) => Ok(claim),
        // A window that was just closed: its process is ending and still
        // holds the claim. Once it has ended the claim is free.
        Found::Unshown(holder) if ended(holder) => match claim_once(WINDOW, folder)? {
            Found::Claimed(claim) => Ok(claim),
            Found::Unshown(_) => Ok(Claim::Starting),
        },
        Found::Unshown(holder) => Ok(if bring(holder) {
            Claim::Forwarded
        } else {
            Claim::Starting
        }),
    }
}

/// Whether `process` ends within [`ENDING`].
fn ended(process: u32) -> bool {
    // SAFETY: the call takes a number and answers a handle or null.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, process) };
    if handle.is_null() {
        // Gone already, or not this person's to wait for.
        return true;
    }
    // SAFETY: the handle was just opened for waiting.
    let waited = unsafe { WaitForSingleObject(handle, ENDING) };
    // SAFETY: the handle is this function's own.
    unsafe { CloseHandle(handle) };
    waited == WAIT_OBJECT_0
}

/// What one look at the claim found.
enum Found {
    Claimed(Claim),
    /// Another process holds it and shows no window.
    Unshown(u32),
}

/// Claims the presence for the Hedwig in `folder`: the claim while this
/// process is its presence, `None` where another presence of this person's
/// holds it.
///
/// # Errors
///
/// Windows could not make or map the section.
pub fn claim_presence(folder: &Path) -> io::Result<Option<Held>> {
    Ok(match claim_once(PRESENCE, folder)? {
        Found::Claimed(Claim::Held(held)) => Some(held),
        _ => None,
    })
}

/// The names the window and the presence are claimed by.
const WINDOW: &str = "hedwig.window";

fn claim_once(what: &str, folder: &Path) -> io::Result<Found> {
    let name = wide(format!("Local\\{what}.{}", key(folder)));
    // SAFETY: the name is NUL-terminated; a section backed by the paging file
    // takes no file and the default security of this process's token.
    let section = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            PAGE_READWRITE,
            0,
            4,
            name.as_ptr(),
        )
    };
    // SAFETY: read at once after the call it reports on.
    let error = unsafe { GetLastError() };
    if section.is_null() {
        if error == ERROR_ACCESS_DENIED {
            return Ok(Found::Claimed(Claim::Held(Held(None))));
        }
        return last();
    }
    // SAFETY: the section was just made or opened with read and write.
    let view = unsafe { MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 4) };
    if view.Value.is_null() {
        // SAFETY: the handle is this function's own.
        unsafe { CloseHandle(section) };
        return last();
    }
    let held = Held(Some((section, view.Value)));
    let number = view.Value.cast::<u32>();
    if error == ERROR_ALREADY_EXISTS {
        // SAFETY: the view is four bytes, aligned, and mapped for reading.
        let first = unsafe { number.read_volatile() };
        drop(held);
        return Ok(match first {
            0 => Found::Claimed(Claim::Starting),
            first if bring(first) => Found::Claimed(Claim::Forwarded),
            first => Found::Unshown(first),
        });
    }
    // SAFETY: the call takes nothing.
    let me = unsafe { GetCurrentProcessId() };
    // SAFETY: as above, and mapped for writing.
    unsafe { number.write_volatile(me) };
    Ok(Found::Claimed(Claim::Held(held)))
}

/// Lets `process` take the foreground, which this process may give while
/// the person's act is its own: a click on its icon or its window.
pub fn allow(process: u32) -> bool {
    // SAFETY: the call takes a number and no pointer.
    unsafe { AllowSetForegroundWindow(process) != 0 }
}

struct Search {
    process: u32,
    found: HWND,
}

unsafe extern "system" fn visit(window: HWND, search: LPARAM) -> i32 {
    // SAFETY: `search` is the `Search` `window_of` passed, alive for the
    // enumeration.
    let search = unsafe { &mut *(search as *mut Search) };
    let mut process = 0;
    // SAFETY: the window is one Windows enumerates, and the place valid.
    unsafe { GetWindowThreadProcessId(window, &raw mut process) };
    // SAFETY: as above.
    let shown = unsafe { IsWindowVisible(window) } != 0;
    // SAFETY: as above.
    let owned = !unsafe { GetWindow(window, GW_OWNER) }.is_null();
    if process == search.process && shown && !owned {
        search.found = window;
        return 0;
    }
    1
}

/// The top-level window `process` shows the person, owned by no other.
pub fn window_of(process: u32) -> Option<isize> {
    let mut search = Search {
        process,
        found: std::ptr::null_mut(),
    };
    // SAFETY: the callback reads `search` only while the call runs.
    unsafe { EnumWindows(Some(visit), (&raw mut search) as LPARAM) };
    (!search.found.is_null()).then_some(search.found as isize)
}

/// The icons a window shows in its title bar, on its taskbar button and as
/// ALT+TAB lists it: the executable's own, at the sizes the window's monitor
/// asks for. Let go when dropped, which is when the window has gone.
#[derive(Debug)]
pub struct Named {
    small: HICON,
    big: HICON,
}

/// Gives `window` its executable's icon, the resource numbered `icon`. A
/// window WinUI makes sets none of its own, and Windows then shows the
/// generic application icon for it, not its executable's.
pub fn name(window: isize, icon: u16) -> Named {
    let window = window as HWND;
    // SAFETY: a window that has gone answers the system's own scale.
    let dpi = unsafe { GetDpiForWindow(window) };
    let load = |metric| {
        // SAFETY: no pointers; an unknown metric answers zero.
        let side = unsafe { GetSystemMetricsForDpi(metric, dpi) };
        // SAFETY: the module is this executable's own; the resource is named
        // by its number, as `MAKEINTRESOURCE` names it.
        unsafe {
            LoadImageW(
                module(),
                std::ptr::without_provenance(usize::from(icon)),
                IMAGE_ICON,
                side,
                side,
                LR_DEFAULTCOLOR,
            )
        }
    };
    let named = Named {
        small: load(SM_CXSMICON),
        big: load(SM_CXICON),
    };
    for (kind, icon) in [(ICON_SMALL, named.small), (ICON_BIG, named.big)] {
        if !icon.is_null() {
            // SAFETY: the window and the icon are alive; the window keeps the
            // handle, which this value holds until it is dropped.
            unsafe { SendMessageW(window, WM_SETICON, kind as usize, icon as isize) };
        }
    }
    named
}

impl Drop for Named {
    fn drop(&mut self) {
        for icon in [self.small, self.big] {
            if !icon.is_null() {
                // SAFETY: each icon is this value's own.
                unsafe { DestroyIcon(icon) };
            }
        }
    }
}

/// Brings `process`'s window forward, restored where it was minimised.
/// Returns whether it has one.
pub fn bring(process: u32) -> bool {
    let Some(window) = window_of(process) else {
        return false;
    };
    let window = window as HWND;
    // SAFETY: the window was just found; one that has gone answers false.
    if unsafe { IsIconic(window) } != 0 {
        // SAFETY: as above.
        unsafe { ShowWindow(window, SW_RESTORE) };
    }
    // SAFETY: as above. Windows gives it the foreground only where this
    // process may give it.
    unsafe { SetForegroundWindow(window) };
    true
}

/// Asks `process`'s window to close, as its close box would. Returns whether
/// it has one.
pub fn close(process: u32) -> bool {
    // SAFETY: posting to another process's window passes no pointer.
    window_of(process)
        .is_some_and(|window| unsafe { PostMessageW(window as HWND, WM_CLOSE, 0, 0) != 0 })
}

/// Asks the presence of the Hedwig in `folder` to bring its card forward,
/// handing it the foreground this process holds. Returns whether a presence
/// was found.
pub fn bring_card(folder: &Path) -> bool {
    tell_presence(folder, BRING)
}

/// Asks the presence of the Hedwig in `folder` to open the window, handing it
/// the foreground this process holds. Returns whether a presence was found.
pub fn open_window(folder: &Path) -> bool {
    tell_presence(folder, OPEN)
}

fn tell_presence(folder: &Path, what: &str) -> bool {
    let class = wide(PRESENCE);
    let title = wide(presence_title(folder));
    // SAFETY: both names are NUL-terminated.
    let presence = unsafe { FindWindowW(class.as_ptr(), title.as_ptr()) };
    if presence.is_null() {
        return false;
    }
    let mut process = 0;
    // SAFETY: the window was just found and the place is valid.
    unsafe { GetWindowThreadProcessId(presence, &raw mut process) };
    allow(process);
    let name = wide(what);
    // SAFETY: the name is NUL-terminated.
    let message = unsafe { RegisterWindowMessageW(name.as_ptr()) };
    // SAFETY: posting passes no pointer.
    message != 0 && unsafe { PostMessageW(presence, message, 0, 0) } != 0
}
