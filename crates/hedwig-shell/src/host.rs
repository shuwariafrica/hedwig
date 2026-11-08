//! The interface's one unshown window, and its message loop.
//!
//! The window is top-level and never shown. It is not a message-only window:
//! those receive no broadcasts, and the shell's announcement that the taskbar
//! was created again is a broadcast. Everything Windows tells the interface
//! arrives here and leaves as a [`Told`]; nothing is decided in this crate.

use std::cell::RefCell;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows_sys::Win32::UI::Controls::{
    ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx,
};
use windows_sys::Win32::UI::Shell::{
    ABM_NEW, ABM_REMOVE, ABN_FULLSCREENAPP, APPBARDATA, NIN_BALLOONUSERCLICK, NIN_SELECT,
    SHAppBarMessage,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DLGC_WANTCHARS, DefWindowProcW, DestroyWindow, DispatchMessageW, FindWindowW,
    GW_CHILD, GetWindow, IsDialogMessageW, MSG, MWMO_INPUTAVAILABLE, MsgWaitForMultipleObjectsEx,
    PM_REMOVE, PeekMessageW, PostMessageW, QS_ALLINPUT, RegisterClassExW, RegisterWindowMessageW,
    SendMessageW, SetWindowTextW, TranslateMessage, WM_APP, WM_CHAR, WM_CLOSE,
    WM_DWMCOLORIZATIONCOLORCHANGED, WM_ENDSESSION, WM_GETDLGCODE, WM_KEYDOWN, WM_SETTINGCHANGE,
    WM_SYSCHAR, WM_SYSCOLORCHANGE, WM_THEMECHANGED, WM_WTSSESSION_CHANGE, WNDCLASSEXW,
};

use hedwig_view::menu::Opened;
use hedwig_view::presence::Change;
use windows_sys::Win32::Foundation::POINT;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CURSOR_SUPPRESSED, CURSORINFO, GetCursorInfo, GetCursorPos,
};

use crate::raw::{last, module, size, wide};

/// The message the notification-area icon calls back with.
pub(crate) const CALLBACK: u32 = WM_APP + 1;
/// What another thread posts to have the loop look at what it left.
const WAKE: u32 = WM_APP + 2;
/// What the Windows Runtime's settings events post: a setting changed.
pub(crate) const CHANGED: u32 = WM_APP + 3;
/// What the shell sends the host as an application desktop toolbar.
const APPBAR: u32 = WM_APP + 4;
/// The class of the unshown window, by which a second start finds the first.
const CLASS: &str = crate::window::PRESENCE;
const WM_CONTEXTMENU: u32 = 0x007b;
/// `NIN_SELECT` made with the keyboard.
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;
const ALREADY_REGISTERED: i32 = 1410;

/// What Windows told the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Told {
    /// The icon was clicked, or chosen with the keyboard.
    Chosen,
    /// The icon's menu was asked for, at the point the shell gives: where
    /// the pointer was, or the icon when the keyboard asked.
    Menu { at: (i32, i32), opened: Opened },
    /// A notification raised through the icon was clicked.
    Nudged,
    /// The taskbar was created again: the icon is gone and is to be added.
    Taskbar,
    /// The desktop was locked or unlocked, its session left or rejoined.
    Session(Change),
    /// An answer on the card was pressed; the number is its place.
    Answered(u16),
    /// The card was put aside without an answer.
    Aside,
    /// The window asked for the card: what waits is to be brought forward,
    /// as the person asked for it.
    Bring,
    /// A second start of the presence asked for the window.
    Open,
    /// A confirmation was answered: the place of the answer that goes ahead,
    /// or `None` for "Cancel", which ESCAPE and its close box are.
    Confirmed(Option<u16>),
    /// A row of the icon's menu was chosen: the entry's place in the menu,
    /// within the group of that place where it is in a remote's own menu.
    Picked(Option<u16>, u16),
    /// The icon's menu closed with nothing chosen.
    Dismissed,
    /// The card was brought forward by the keyboard, or by Windows when
    /// another window closed, and not by a click on it. Its answers are off
    /// until it has settled again, as when it was first shown.
    Forward,
    /// The shell said an application began, or the last one stopped,
    /// filling the screen: what the desktop takes is to be asked again.
    Desk,
    /// Windows signalled that something the person sets may have changed -
    /// their mode, accent, contrast theme, text size or animations - or the
    /// card is now on a monitor of another scale. What is painted is read
    /// for and made again; the signal does not say which it was.
    Settings,
    /// Another thread has left something for this one.
    Woken,
    /// The interface is to end: its window was closed, or the session is
    /// ending.
    End,
}

/// What another thread wakes the message loop with.
#[derive(Debug, Clone, Copy)]
pub struct Waker(isize);

impl Waker {
    /// Has the loop tell its thread [`Told::Woken`]. A loop that has ended
    /// is not woken, and nothing is lost by that.
    pub fn wake(self) {
        // SAFETY: posting carries no pointer, and a window that no longer
        // exists refuses the message.
        unsafe { PostMessageW(self.0 as HWND, WAKE, 0, 0) };
    }
}

thread_local! {
    static TOLD: RefCell<Vec<Told>> = const { RefCell::new(Vec::new()) };
    /// The dialogs of this thread, whose keys the loop hands to the dialog
    /// manager.
    static DIALOGS: RefCell<Vec<isize>> = const { RefCell::new(Vec::new()) };
}

static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);
static BRING: AtomicU32 = AtomicU32::new(0);
static OPEN: AtomicU32 = AtomicU32::new(0);

pub(crate) fn tell(told: Told) {
    TOLD.with_borrow_mut(|queue| {
        // One change of a setting arrives as several signals; one is enough.
        if told != Told::Settings || !queue.contains(&told) {
            queue.push(told);
        }
    });
}

pub(crate) fn dialog(window: HWND, open: bool) {
    DIALOGS.with_borrow_mut(|dialogs| {
        dialogs.retain(|known| *known != window as isize);
        if open {
            dialogs.push(window as isize);
        }
    });
}

unsafe extern "system" fn procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        CALLBACK => {
            // With version 4 of the icon's contract the event is the low word,
            // and the point it is anchored at is in the other parameter.
            match u32::try_from(lparam & 0xffff).unwrap_or_default() {
                NIN_SELECT | NIN_KEYSELECT => tell(Told::Chosen),
                WM_CONTEXTMENU => {
                    let at = (
                        i32::from(low16(wparam).cast_signed()),
                        i32::from(high16(wparam).cast_signed()),
                    );
                    tell(Told::Menu {
                        at,
                        opened: opened_at(at),
                    });
                }
                NIN_BALLOONUSERCLICK => tell(Told::Nudged),
                _ => {}
            }
            0
        }
        WM_WTSSESSION_CHANGE => {
            match wparam {
                7 => tell(Told::Session(Change::Locked)),
                8 => tell(Told::Session(Change::Unlocked)),
                1 | 3 => tell(Told::Session(Change::Connected)),
                2 | 4 => tell(Told::Session(Change::Disconnected)),
                _ => {}
            }
            0
        }
        WAKE => {
            tell(Told::Woken);
            0
        }
        // Every signal Windows gives a top-level window that a setting of
        // the person's changed, and the two events `settings::Watch` adds.
        CHANGED => {
            tell(Told::Settings);
            0
        }
        // Nothing else signals that an application fills the screen.
        APPBAR => {
            if u32::try_from(wparam).ok() == Some(ABN_FULLSCREENAPP) {
                tell(Told::Desk);
            }
            0
        }
        WM_SETTINGCHANGE | WM_SYSCOLORCHANGE | WM_THEMECHANGED | WM_DWMCOLORIZATIONCOLORCHANGED => {
            tell(Told::Settings);
            // SAFETY: the arguments are the ones Windows called this
            // procedure with, passed on unchanged.
            unsafe { DefWindowProcW(window, message, wparam, lparam) }
        }
        WM_CLOSE => {
            tell(Told::End);
            0
        }
        WM_ENDSESSION => {
            if wparam != 0 {
                tell(Told::End);
            }
            0
        }
        other => {
            if other == TASKBAR_CREATED.load(Ordering::Relaxed) && other != 0 {
                tell(Told::Taskbar);
                return 0;
            }
            if other == BRING.load(Ordering::Relaxed) && other != 0 {
                tell(Told::Bring);
                return 0;
            }
            if other == OPEN.load(Ordering::Relaxed) && other != 0 {
                tell(Told::Open);
                return 0;
            }
            // SAFETY: the arguments are the ones Windows called this
            // procedure with, passed on unchanged.
            unsafe { DefWindowProcW(window, message, wparam, lparam) }
        }
    }
}

fn low16(value: usize) -> u16 {
    u16::try_from(value & 0xffff).unwrap_or_default()
}

fn high16(value: usize) -> u16 {
    u16::try_from((value >> 16) & 0xffff).unwrap_or_default()
}

/// How the menu was asked for, from what Windows says of the cursor
/// (`Opened::of`).
fn opened_at(at: (i32, i32)) -> Opened {
    let mut cursor = CURSORINFO {
        cbSize: size::<CURSORINFO>(),
        ..CURSORINFO::default()
    };
    // SAFETY: the structure's size is set; it is a valid place for the answer.
    let read = unsafe { GetCursorInfo(&raw mut cursor) } != 0;
    let suppressed = read && cursor.flags & CURSOR_SUPPRESSED != 0;
    let mut pointer = POINT::default();
    // SAFETY: the point is a valid place for the answer.
    let known = unsafe { GetCursorPos(&raw mut pointer) } != 0;
    Opened::of(suppressed, known.then_some((pointer.x, pointer.y)), at)
}

/// Whether a message is a character typed without ALT at a control that
/// takes no text. The dialog manager would treat it as an access key and
/// press the button it names; held back from it, the letter does nothing,
/// and an access key is ALT and its letter.
fn bare(message: &MSG) -> bool {
    if message.message != WM_CHAR {
        return false;
    }
    // SAFETY: the message carries no pointer; a window that is gone answers
    // zero.
    let wants = unsafe { SendMessageW(message.hwnd, WM_GETDLGCODE, 0, 0) };
    wants & isize::try_from(DLGC_WANTCHARS).unwrap_or_default() == 0
}

/// The unshown window. It belongs to the thread that made it, which is the
/// thread that must run [`Host::told`].
#[derive(Debug)]
pub struct Host {
    window: HWND,
    /// Whether this thread's COM apartment is this value's to leave.
    apartment: bool,
    /// Whether the shell took the window as an application desktop toolbar,
    /// to be told when an application fills the screen.
    appbar: bool,
}

impl Host {
    pub fn new() -> io::Result<Host> {
        // The thread that owns the windows is a single-threaded apartment:
        // what it asks of the Windows Runtime and of the shell's dialogs is
        // answered on it. A thread already in another kind keeps that kind.
        // SAFETY: the reserved pointer is null, as the call requires.
        let entered =
            unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED.cast_unsigned()) };
        let apartment = entered >= 0;
        let controls = INITCOMMONCONTROLSEX {
            dwSize: size::<INITCOMMONCONTROLSEX>(),
            dwICC: ICC_STANDARD_CLASSES,
        };
        // SAFETY: the structure is complete and outlives the call.
        unsafe { InitCommonControlsEx(&raw const controls) };
        let class = wide(CLASS);
        let description = WNDCLASSEXW {
            cbSize: size::<WNDCLASSEXW>(),
            lpfnWndProc: Some(procedure),
            hInstance: module(),
            lpszClassName: class.as_ptr(),
            ..WNDCLASSEXW::default()
        };
        // SAFETY: the structure is complete, and the class name and the
        // procedure live as long as the process.
        if unsafe { RegisterClassExW(&raw const description) } == 0
            && io::Error::last_os_error().raw_os_error() != Some(ALREADY_REGISTERED)
        {
            return last();
        }
        let broadcast = wide("TaskbarCreated");
        // SAFETY: the name is NUL-terminated.
        let created = unsafe { RegisterWindowMessageW(broadcast.as_ptr()) };
        TASKBAR_CREATED.store(created, Ordering::Relaxed);
        let bring = wide(crate::window::BRING);
        // SAFETY: as above.
        let bring = unsafe { RegisterWindowMessageW(bring.as_ptr()) };
        BRING.store(bring, Ordering::Relaxed);
        let open = wide(crate::window::OPEN);
        // SAFETY: as above.
        let open = unsafe { RegisterWindowMessageW(open.as_ptr()) };
        OPEN.store(open, Ordering::Relaxed);
        let title = wide("Hedwig");
        // SAFETY: the class was registered above and both names are
        // NUL-terminated; no parent makes the window top-level, and no style
        // shows it.
        let window = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                title.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                module(),
                std::ptr::null(),
            )
        };
        if window.is_null() {
            return last();
        }
        // SAFETY: the window is this thread's own. A session with no
        // notifications to give refuses, which leaves presence as it was
        // asked at start.
        unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) };
        // An application desktop toolbar with no place asked for: the shell
        // reserves no part of the screen for it, and tells it when an
        // application begins or stops filling the screen.
        let mut bar = APPBARDATA {
            cbSize: size::<APPBARDATA>(),
            hWnd: window,
            uCallbackMessage: APPBAR,
            ..APPBARDATA::default()
        };
        // SAFETY: the structure states its size and names this thread's own
        // window; the shell copies what it needs.
        let appbar = unsafe { SHAppBarMessage(ABM_NEW, &raw mut bar) } != 0;
        Ok(Host {
            window,
            apartment,
            appbar,
        })
    }

    /// Names the unshown window for the Hedwig in `folder`, so that Hedwig's
    /// window finds this presence and no other.
    pub fn serve(&self, folder: &std::path::Path) {
        let title = wide(crate::window::presence_title(folder));
        // SAFETY: the window is this thread's own and the title
        // NUL-terminated.
        unsafe { SetWindowTextW(self.window, title.as_ptr()) };
    }

    pub(crate) fn window(&self) -> HWND {
        self.window
    }

    /// A way for another thread to wake this window's loop.
    pub fn waker(&self) -> Waker {
        Waker(self.window as isize)
    }

    /// Runs the message loop until Windows has told the interface something
    /// or `wait` has passed, and returns what it was told.
    pub fn told(&self, wait: Duration) -> Vec<Told> {
        let until = Instant::now() + wait;
        loop {
            let mut message = MSG::default();
            // SAFETY: `message` is a valid place for one message; a null
            // window takes every message of this thread.
            while unsafe { PeekMessageW(&raw mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) }
                != 0
            {
                // A key typed in the icon's menu is the menu's.
                if matches!(message.message, WM_KEYDOWN | WM_CHAR)
                    && crate::menu::owns(message.hwnd)
                    && crate::menu::key(&message)
                {
                    continue;
                }
                let taken = !bare(&message)
                    && DIALOGS.with_borrow(|dialogs| {
                        // ALT and a letter with the keyboard on no control
                        // arrive at the dialog itself, where the dialog
                        // manager looks for no access key; it looks from the
                        // dialog's first control.
                        if message.message == WM_SYSCHAR
                            && dialogs.contains(&(message.hwnd as isize))
                        {
                            // SAFETY: the window is a dialog of this thread;
                            // one with no control answers null, which the
                            // dialog manager then ignores.
                            message.hwnd = unsafe { GetWindow(message.hwnd, GW_CHILD) };
                        }
                        dialogs.iter().any(|dialog| {
                            // SAFETY: the handle is a dialog of this thread
                            // and `message` the message just taken.
                            unsafe { IsDialogMessageW(*dialog as HWND, &raw const message) != 0 }
                        })
                    });
                if !taken {
                    // SAFETY: `message` was filled by `PeekMessageW`.
                    unsafe { TranslateMessage(&raw const message) };
                    // SAFETY: as above.
                    unsafe { DispatchMessageW(&raw const message) };
                }
            }
            let told = TOLD.with_borrow_mut(std::mem::take);
            let left = until.saturating_duration_since(Instant::now());
            if !told.is_empty() || left.is_zero() {
                return told;
            }
            let milliseconds = u32::try_from(left.as_millis()).unwrap_or(u32::MAX - 1);
            // SAFETY: no handles are waited on; the call returns when a
            // message is in the queue or the time has passed.
            unsafe {
                MsgWaitForMultipleObjectsEx(
                    0,
                    std::ptr::null(),
                    milliseconds,
                    QS_ALLINPUT,
                    MWMO_INPUTAVAILABLE,
                )
            };
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // SAFETY: the window is this thread's own and still exists.
        unsafe { WTSUnRegisterSessionNotification(self.window) };
        if self.appbar {
            let mut bar = APPBARDATA {
                cbSize: size::<APPBARDATA>(),
                hWnd: self.window,
                ..APPBARDATA::default()
            };
            // SAFETY: as when it was registered.
            unsafe { SHAppBarMessage(ABM_REMOVE, &raw mut bar) };
        }
        // SAFETY: as above; nothing uses the handle afterwards.
        unsafe { DestroyWindow(self.window) };
        if self.apartment {
            // SAFETY: balances the entry `new` made on this thread; every
            // object taken in the apartment borrows this host and is gone.
            unsafe { CoUninitialize() };
        }
    }
}

/// Asks the presence of the Hedwig in `folder` running in this session to
/// end, as closing its window would. Returns whether one was found.
pub fn end_running(folder: &std::path::Path) -> bool {
    let class = wide(CLASS);
    let title = wide(crate::window::presence_title(folder));
    // SAFETY: both names are NUL-terminated.
    let window = unsafe { FindWindowW(class.as_ptr(), title.as_ptr()) };
    if window.is_null() {
        return false;
    }
    // SAFETY: posting to a window of another process passes no pointer.
    unsafe { PostMessageW(window, WM_CLOSE, 0, 0) != 0 }
}
