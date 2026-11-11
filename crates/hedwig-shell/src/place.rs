//! Where the window opens, and where it was when it went.
//!
//! WinUI makes its window on the thread that runs it and shows it before
//! anything of the application's can reach it. A hook on that thread meets
//! the window as Windows makes it, where Windows lets the hook set its
//! first size and place ("By changing these parameters, a `CBTProc` hook
//! procedure can set the initial size and position of the window",
//! Microsoft's `CBTProc`, `HCBT_CREATEWND`), and again as it goes, when its place is
//! read. The hook sees only this thread's windows and is taken out with
//! [`Placing`].
//!
//! Windows takes no maximised state from a window's creation, so a window
//! kept maximised is cloaked once it is made - a second hook of the thread's,
//! on the calls it returns from, sees its creation return and is taken out -
//! maximised by a command posted as it is made, and uncloaked by a timer of
//! the thread's, which Windows runs only once no posted message waits: the
//! person's first sight of it is maximised, and it is uncloaked whatever
//! became of the command.

use std::cell::RefCell;
use std::io;

use hedwig_view::place::Placement;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_CLOAK, DwmSetWindowAttribute};
use windows_sys::Win32::Graphics::Gdi::{MONITOR_DEFAULTTONULL, MonitorFromRect};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::HiDpi::{GetDpiForMonitor, GetDpiForWindow, MDT_EFFECTIVE_DPI};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CBT_CREATEWNDW, CWPRETSTRUCT, CallNextHookEx, GetClassNameW, GetWindowPlacement, GetWindowRect,
    HCBT_CREATEWND, HCBT_DESTROYWND, HCBT_MINMAX, HHOOK, IsIconic, IsZoomed, KillTimer,
    PostMessageW, SC_MAXIMIZE, SetTimer, SetWindowsHookExW, USER_TIMER_MINIMUM,
    UnhookWindowsHookEx, WH_CALLWNDPROCRET, WH_CBT, WINDOWPLACEMENT, WM_CREATE, WM_SYSCOMMAND,
    WPF_RESTORETOMAXIMIZED,
};

use crate::raw::size;

/// What the hook knows, on the thread it is on.
struct State {
    class: Vec<u16>,
    at: Option<Placement>,
    window: Option<isize>,
    /// The window's restored rectangle, as last seen while it was restored.
    normal: Option<RECT>,
    kept: Option<Placement>,
    /// The hook that cloaks the window once it is made, while it waits.
    cloaking: Option<HHOOK>,
    /// The timer that uncloaks it, while it waits.
    revealing: Option<usize>,
}

thread_local! {
    static PLACING: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// The hook, on this thread, until dropped.
#[derive(Debug)]
pub struct Placing {
    hook: HHOOK,
}

/// `at` where some monitor connected now shows any of it, sized for that
/// monitor's scale; `None` where none does, so the window opens where
/// Windows puts a new one.
pub fn fitted(at: Placement) -> Option<Placement> {
    let rect = RECT {
        left: at.left,
        top: at.top,
        right: at.right,
        bottom: at.bottom,
    };
    // SAFETY: the rectangle is valid for the call.
    let monitor = unsafe { MonitorFromRect(&raw const rect, MONITOR_DEFAULTTONULL) };
    if monitor.is_null() {
        return None;
    }
    let (mut x, mut y) = (0u32, 0u32);
    // SAFETY: the monitor was just returned; both outputs are valid.
    let read = unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &raw mut x, &raw mut y) };
    Some(if read == 0 { at.scaled(x) } else { at })
}

fn rect(window: HWND) -> Option<RECT> {
    let mut rect = RECT::default();
    // SAFETY: the window is this thread's and still exists; the rectangle is
    // valid for the call.
    (unsafe { GetWindowRect(window, &raw mut rect) } != 0).then_some(rect)
}

/// Whether the window is neither maximised nor minimised.
fn restored(window: HWND) -> bool {
    // SAFETY: only reads the window's state.
    let zoomed = unsafe { IsZoomed(window) } != 0;
    // SAFETY: as above.
    !zoomed && unsafe { IsIconic(window) } == 0
}

fn class_of(window: HWND) -> Vec<u16> {
    let mut name = [0u16; 128];
    // SAFETY: the buffer's length is given.
    let length = unsafe { GetClassNameW(window, name.as_mut_ptr(), 128) };
    name.get(..usize::try_from(length).unwrap_or(0))
        .unwrap_or_default()
        .to_vec()
}

/// The window met as it is made: given its place where one is kept.
fn made(state: &mut State, window: HWND, lparam: LPARAM) {
    if state.window.is_some() || class_of(window) != state.class {
        return;
    }
    let create = lparam as *mut CBT_CREATEWNDW;
    // SAFETY: for `HCBT_CREATEWND` Windows passes a valid `CBT_CREATEWNDW`
    // whose `lpcs` points at the window's creation parameters, which the
    // hook may change until it returns.
    let Some(parameters) = (unsafe { create.as_ref() }).and_then(|create| {
        // SAFETY: as above.
        unsafe { create.lpcs.as_mut() }
    }) else {
        return;
    };
    if !parameters.hwndParent.is_null() {
        return;
    }
    state.window = Some(window as isize);
    if let Some(at) = state.at {
        parameters.x = at.left;
        parameters.y = at.top;
        parameters.cx = at.width();
        parameters.cy = at.height();
        // Windows takes no maximised state from the creation parameters, and
        // WinUI shows its window in the same turn it makes it, so the window
        // is maximised as the first thing its thread does once shown, cloaked
        // until then where it can be uncloaked after.
        if at.maximised {
            state.cloaking = cloaking();
            // SAFETY: posting to a window of this thread passes no pointer.
            unsafe { PostMessageW(window, WM_SYSCOMMAND, SC_MAXIMIZE as WPARAM, 0) };
        }
        state.normal = Some(RECT {
            left: at.left,
            top: at.top,
            right: at.right,
            bottom: at.bottom,
        });
    }
}

fn cloak(window: HWND, cloaked: bool) -> bool {
    let value = i32::from(cloaked);
    // SAFETY: the attribute takes one BOOL, which outlives the call; the
    // window is this thread's own.
    let set = unsafe {
        DwmSetWindowAttribute(
            window,
            DWMWA_CLOAK.cast_unsigned(),
            (&raw const value).cast(),
            size::<i32>(),
        )
    };
    set == 0
}

/// The hook that cloaks the window being made once it is.
fn cloaking() -> Option<HHOOK> {
    // SAFETY: no arguments; this thread's own number.
    let thread = unsafe { GetCurrentThreadId() };
    // SAFETY: a hook of this thread alone, whose procedure is in this module.
    let hook = unsafe {
        SetWindowsHookExW(
            WH_CALLWNDPROCRET,
            Some(returned),
            std::ptr::null_mut(),
            thread,
        )
    };
    (!hook.is_null()).then_some(hook)
}

/// A call to a window of this thread returned: once the window kept
/// maximised has returned from its creation - Windows refuses to cloak a
/// window still being made - it is cloaked, with the timer that uncloaks it,
/// and this hook is taken out.
extern "system" fn returned(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let call = if code >= 0 {
        // SAFETY: for this hook Windows passes a valid `CWPRETSTRUCT` for the
        // call, which lives until it returns.
        unsafe { (lparam as *const CWPRETSTRUCT).as_ref() }
    } else {
        None
    };
    if let Some(call) = call
        && call.message == WM_CREATE
    {
        let hook = PLACING.with_borrow_mut(|placing| {
            let state = placing.as_mut()?;
            if state.window != Some(call.hwnd as isize) {
                return None;
            }
            let hook = state.cloaking.take()?;
            // SAFETY: a timer of this thread's, with no window, whose
            // procedure is in this module.
            let timer =
                unsafe { SetTimer(std::ptr::null_mut(), 0, USER_TIMER_MINIMUM, Some(reveal)) };
            if timer != 0 {
                if cloak(call.hwnd, true) {
                    state.revealing = Some(timer);
                } else {
                    // SAFETY: the timer was just set on this thread.
                    unsafe { KillTimer(std::ptr::null_mut(), timer) };
                }
            }
            Some(hook)
        });
        if let Some(hook) = hook {
            // SAFETY: the hook is the one this module set on this thread;
            // Windows lets a hook take itself out.
            unsafe { UnhookWindowsHookEx(hook) };
        }
    }
    // SAFETY: passes the hook's own arguments on, as every hook must.
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
}

/// The thread has carried out every message posted before this timer came
/// due, the window's maximise among them: it is uncloaked.
extern "system" fn reveal(_: HWND, _: u32, timer: usize, _: u32) {
    // SAFETY: the timer is this thread's own, with no window.
    unsafe { KillTimer(std::ptr::null_mut(), timer) };
    let window = PLACING.with_borrow_mut(|placing| {
        let state = placing.as_mut()?;
        state.revealing.take()?;
        state.window
    });
    if let Some(window) = window {
        cloak(window as HWND, false);
    }
}

/// The window met as it goes: its place read and kept.
fn gone(state: &mut State, window: HWND) {
    if restored(window) {
        state.normal = rect(window).or(state.normal);
    }
    let mut placement = WINDOWPLACEMENT {
        length: size::<WINDOWPLACEMENT>(),
        ..WINDOWPLACEMENT::default()
    };
    // SAFETY: the window still exists while it is being destroyed; the
    // structure's length is set.
    let read = unsafe { GetWindowPlacement(window, &raw mut placement) } != 0;
    // SAFETY: as above.
    let maximised = unsafe { IsZoomed(window) } != 0
        || (read
            && unsafe { IsIconic(window) } != 0
            && placement.flags & WPF_RESTORETOMAXIMIZED != 0);
    // SAFETY: as above.
    let dpi = unsafe { GetDpiForWindow(window) };
    state.kept = state.normal.map(|normal| Placement {
        left: normal.left,
        top: normal.top,
        right: normal.right,
        bottom: normal.bottom,
        maximised,
        dpi,
    });
}

extern "system" fn hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let window = wparam as HWND;
    PLACING.with_borrow_mut(|placing| {
        let Some(state) = placing.as_mut() else {
            return;
        };
        let ours = state.window == Some(window as isize);
        match u32::try_from(code) {
            Ok(HCBT_CREATEWND) => made(state, window, lparam),
            // About to be maximised, minimised or restored: as it is now, its
            // restored rectangle where it is restored.
            Ok(HCBT_MINMAX) if ours && restored(window) => {
                state.normal = rect(window).or(state.normal);
            }
            Ok(HCBT_DESTROYWND) if ours => gone(state, window),
            _ => {}
        }
    });
    // SAFETY: passes the hook's own arguments on, as every hook must.
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
}

impl Placing {
    /// Hooks this thread: the first top-level window of the class named
    /// `class` made on it is made at `at`, maximised where `at` was, and
    /// where it was when it went is [`Placing::kept`].
    ///
    /// # Errors
    ///
    /// Windows refused the hook; the window then opens where Windows puts it.
    pub fn new(class: &str, at: Option<Placement>) -> io::Result<Placing> {
        // SAFETY: no arguments; this thread's own number.
        let thread = unsafe { GetCurrentThreadId() };
        // SAFETY: a hook of this thread alone, whose procedure is in this
        // module; no module handle is needed for a thread of the process's
        // own.
        let hook = unsafe { SetWindowsHookExW(WH_CBT, Some(hook), std::ptr::null_mut(), thread) };
        if hook.is_null() {
            return Err(io::Error::last_os_error());
        }
        PLACING.with_borrow_mut(|placing| {
            *placing = Some(State {
                class: class.encode_utf16().collect(),
                at,
                window: None,
                normal: None,
                kept: None,
                cloaking: None,
                revealing: None,
            });
        });
        Ok(Placing { hook })
    }

    /// Where the window was when it went: its restored rectangle, whether it
    /// was maximised, and its monitor's scale. None before it has gone, or
    /// where it was never restored and nothing was kept before.
    pub fn kept(&self) -> Option<Placement> {
        PLACING.with_borrow(|placing| placing.as_ref().and_then(|state| state.kept))
    }
}

impl Drop for Placing {
    fn drop(&mut self) {
        // SAFETY: the hook is this value's own, set on this thread.
        unsafe { UnhookWindowsHookEx(self.hook) };
        if let Some(state) = PLACING.with_borrow_mut(Option::take) {
            if let Some(hook) = state.cloaking {
                // SAFETY: a hook this module set on this thread and has not
                // taken out.
                unsafe { UnhookWindowsHookEx(hook) };
            }
            if let Some(timer) = state.revealing {
                // SAFETY: a timer this module set on this thread.
                unsafe { KillTimer(std::ptr::null_mut(), timer) };
            }
        }
    }
}
