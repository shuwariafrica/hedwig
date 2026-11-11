//! The icon's menu, exercised against the desktop this suite runs in.
//!
//! Each test opens the menu for a moment by where the notification area is,
//! titled "hedwig probe", and closes it. The foreground is locked where it
//! was while a menu is open, so the menu cannot take it; what the person's
//! keys and pointer would do is done by sending the menu's own windows the
//! messages Windows would. In a session with no desktop each does nothing.
//! A level is composed whole, so what it shows is read from the picture it
//! hands Windows, and where it stands from its menu's place in its window.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::time::{Duration, Instant};

use hedwig_model::protocol::Request;
use hedwig_model::remote::Remotes;
use hedwig_shell::host::{Host, Told};
use hedwig_shell::menu::{self, Menu, Taskbar};
use hedwig_shell::{desk, settings};
use hedwig_view::act::Act;
use hedwig_view::glance::Entry;
use hedwig_view::menu::{self as laid, Kind, Opened};
use hedwig_view::motion::{self, Closed, Grows};
use hedwig_view::style::{Appearance, Backdrop, Colours, Motion};
use windows_sys::Win32::Foundation::{HWND, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{
    DWMSBT_NONE, DWMWA_SYSTEMBACKDROP_TYPE, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_DONOTROUND,
    DwmGetWindowAttribute,
};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MapWindowPoints, MonitorFromPoint,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    VK_DOWN, VK_END, VK_ESCAPE, VK_LEFT, VK_RETURN,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GUITHREADINFO, GWL_EXSTYLE, GetClassNameW, GetForegroundWindow, GetGUIThreadInfo,
    GetWindowLongPtrW, GetWindowRect, GetWindowTextW, IsWindowVisible, LSFW_LOCK, LSFW_UNLOCK,
    LockSetForegroundWindow, PostMessageW, SendMessageW, WA_ACTIVE, WA_INACTIVE, WM_ACTIVATE,
    WM_CHAR, WM_KEYDOWN, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WS_EX_NOREDIRECTIONBITMAP,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
};

fn act(label: &str) -> Entry {
    Entry::Act {
        label: label.to_owned(),
        act: Act::Open(None),
        chief: false,
    }
}

/// The menu of a Hedwig with one remote connected and a request waiting.
fn entries() -> Vec<Entry> {
    vec![
        act("Answer what is waiting (1)"),
        act("Open Hedwig"),
        Entry::Rule,
        Entry::Act {
            label: "Pause all exposure".to_owned(),
            act: Act::Send(Request::Pause(Remotes::Every)),
            chief: false,
        },
        Entry::Rule,
        Entry::Group {
            label: "dev/build (coder)".to_owned(),
            entries: vec![
                Entry::Line("gpg: reachable there at ~/.gnupg/S.gpg-agent".to_owned()),
                Entry::Rule,
                act("Ask me first, until this connection ends"),
                act("Always ask me first for this remote"),
                act("Disconnect"),
            ],
        },
        Entry::Rule,
        act("Close this icon"),
    ]
}

fn text(window: HWND) -> String {
    let mut units = [0u16; 256];
    // SAFETY: the buffer is writable for the length given.
    let length = unsafe { GetWindowTextW(window, units.as_mut_ptr(), 256) };
    String::from_utf16_lossy(&units[..usize::try_from(length).unwrap()])
}

fn class(window: HWND) -> String {
    let mut units = [0u16; 64];
    // SAFETY: as in `text`.
    let length = unsafe { GetClassNameW(window, units.as_mut_ptr(), 64) };
    String::from_utf16_lossy(&units[..usize::try_from(length).unwrap()])
}

/// The control of this thread that has the keyboard.
fn focus() -> HWND {
    let mut info = GUITHREADINFO {
        cbSize: u32::try_from(size_of::<GUITHREADINFO>()).unwrap(),
        ..GUITHREADINFO::default()
    };
    // SAFETY: no arguments.
    let thread = unsafe { GetCurrentThreadId() };
    // SAFETY: the structure states its size; the thread is this one.
    unsafe { GetGUIThreadInfo(thread, &raw mut info) };
    info.hwndFocus
}

/// A key typed where the keyboard is, through the message loop.
fn key(host: &Host, message: u32, code: u16) -> Vec<Told> {
    // SAFETY: posting to a window of this thread carries no pointer.
    unsafe { PostMessageW(focus(), message, WPARAM::from(code), 0) };
    host.told(Duration::from_millis(30))
}

fn primary_work() -> RECT {
    let mut info = MONITORINFO {
        cbSize: u32::try_from(size_of::<MONITORINFO>()).unwrap(),
        ..MONITORINFO::default()
    };
    // SAFETY: the call always answers a monitor with this flag.
    let monitor = unsafe { MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY) };
    // SAFETY: the structure states its size.
    unsafe { GetMonitorInfoW(monitor, &raw mut info) };
    info.rcWork
}

fn rect(window: HWND) -> RECT {
    let mut place = RECT::default();
    // SAFETY: `place` is a valid place.
    unsafe { GetWindowRect(window, &raw mut place) };
    place
}

fn apart(one: &RECT, other: &RECT) -> bool {
    one.right <= other.left
        || other.right <= one.left
        || one.bottom <= other.top
        || other.bottom <= one.top
}

fn within(inner: &RECT, outer: &RECT) -> bool {
    inner.left >= outer.left
        && inner.right <= outer.right
        && inner.top >= outer.top
        && inner.bottom <= outer.bottom
}

fn shown(place: &RECT) -> String {
    format!(
        "({},{})-({},{})",
        place.left, place.top, place.right, place.bottom
    )
}

/// A press and release of the left button at a point of `window`'s client
/// area, as Windows sends them to the window that holds the pointer.
fn click(window: HWND, x: i32, y: i32) {
    let word = |value: i32| isize::from(i16::try_from(value).unwrap()) & 0xffff;
    let at = word(x) | (word(y) << 16);
    // SAFETY: the window is this thread's own; the messages carry no pointer.
    unsafe { SendMessageW(window, WM_LBUTTONDOWN, 1, at) };
    // SAFETY: as above.
    unsafe { SendMessageW(window, WM_LBUTTONUP, 0, at) };
}

/// The pointer moved to a point of `window`'s client area, as Windows tells
/// the window that holds it.
fn moved(window: HWND, x: i32, y: i32) {
    let word = |value: i32| isize::from(i16::try_from(value).unwrap()) & 0xffff;
    // SAFETY: the window is this thread's own; the message carries no pointer.
    unsafe { SendMessageW(window, WM_MOUSEMOVE, 0, word(x) | (word(y) << 16)) };
}

/// The point half way down row `row` of level `depth`, in its window.
fn on_row(menu: &Menu, depth: usize, row: usize) -> (i32, i32) {
    let (_, (left, top, _, _)) = menu.composed(depth).unwrap();
    let rect = menu.laid(depth).unwrap().rows[row].rect;
    (left + rect.left + 10, top + rect.top + rect.height / 2)
}

/// The icon's place in the primary monitor's bottom right corner, and the
/// point the shell gives with a request for its menu.
fn icon() -> ((i32, i32, i32, i32), (i32, i32)) {
    let work = primary_work();
    let icon = (
        work.right - 60,
        work.bottom,
        work.right - 20,
        work.bottom + 40,
    );
    (icon, (icon.0 + 20, icon.1 + 10))
}

/// Runs `check` with the foreground locked where the person has it, and
/// checks it is still there after. The person's appearance is read, with
/// motion off: what these tests check is where things stand once open, and
/// the opening is checked by itself.
fn quietly(check: impl FnOnce(&Host, &Appearance)) {
    assert!(desk::interactive(), "needs the desktop's foreground");
    // SAFETY: no arguments; the lock keeps the foreground where the person
    // has it.
    unsafe { LockSetForegroundWindow(LSFW_LOCK) };
    // SAFETY: no arguments.
    let before = unsafe { GetForegroundWindow() };
    let host = Host::new().expect("an unshown window");
    let still = Appearance {
        motion: Motion::Still,
        ..settings::read()
    };
    check(&host, &still);
    // SAFETY: no arguments.
    let after = unsafe { GetForegroundWindow() };
    // SAFETY: no arguments.
    unsafe { LockSetForegroundWindow(LSFW_UNLOCK) };
    assert_eq!(after, before, "the foreground is where the person had it");
}

/// Where a level's menu stands on the screen: its window, less the room for
/// the shadow round it.
fn menu_rect(menu: &Menu, depth: usize) -> RECT {
    let window = rect(menu.levels()[depth].cast());
    let (_, (left, top, width, height)) = menu.composed(depth).expect("the level");
    RECT {
        left: window.left + left,
        top: window.top + top,
        right: window.left + left + width,
        bottom: window.top + top + height,
    }
}

/// A DWM attribute of a window that is one 32-bit value.
fn attribute(window: HWND, which: i32) -> i32 {
    let mut value = 0i32;
    // SAFETY: the window is this thread's own; the attribute is one 32-bit
    // value written to `value`.
    unsafe {
        DwmGetWindowAttribute(
            window,
            u32::try_from(which).unwrap(),
            (&raw mut value).cast(),
            4,
        )
    };
    value
}

fn open(appearance: &Appearance, opened: Opened) -> Menu {
    let (icon, at) = icon();
    Menu::open(
        "hedwig probe",
        &entries(),
        appearance,
        at,
        Some(icon),
        opened,
    )
    .expect("the menu")
}

/// A person opens the icon's menu: a flyout above other windows with no taskbar
/// button, by the icon and never over it, whose every row that can be
/// chosen is one of Windows' buttons and every line of words a static
/// control, each where the view laid it out and saying what it says.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_menu_is_windows_own_controls_where_the_view_put_them() {
    quietly(|_, appearance| {
        let menu = open(appearance, Opened::Pointer);
        let root: HWND = menu.window().cast();
        assert_eq!(class(root), "hedwig.menu");
        // SAFETY: the window is this thread's own.
        assert!(unsafe { IsWindowVisible(root) } != 0);
        // SAFETY: as above.
        let extended = unsafe { GetWindowLongPtrW(root, GWL_EXSTYLE) };
        let wanted = isize::try_from(WS_EX_TOPMOST | WS_EX_TOOLWINDOW).unwrap();
        assert_eq!(extended & wanted, wanted);
        let (icon, _) = icon();
        let icon = RECT {
            left: icon.0,
            top: icon.1,
            right: icon.2,
            bottom: icon.3,
        };
        let placed = menu_rect(&menu, 0);
        assert!(apart(&placed, &icon), "never over the icon");
        assert!(within(&placed, &primary_work()));
        let (composed, (left, top, _, _)) = menu.composed(0).unwrap();
        assert!(composed, "composed as WinUI composes its flyout");
        for (at, row) in menu.laid(0).unwrap().rows.iter().enumerate() {
            let control: HWND = menu.control(0, at).cast();
            match row.kind {
                Kind::Rule => assert!(control.is_null()),
                Kind::Line => assert_eq!(class(control), "Static"),
                Kind::Item | Kind::Group => {
                    assert_eq!(class(control), "Button");
                    assert_eq!(text(control), row.label);
                    let mut corners = rect(control);
                    // SAFETY: both windows are this thread's; two points.
                    unsafe {
                        MapWindowPoints(
                            std::ptr::null_mut(),
                            root,
                            (&raw mut corners).cast::<POINT>(),
                            2,
                        )
                    };
                    assert_eq!(
                        (corners.left, corners.top),
                        (left + row.rect.left, top + row.rect.top)
                    );
                }
            }
        }
        println!(
            "the menu at {} beside the icon at {}, the taskbar at the {:?}",
            shown(&placed),
            shown(&icon),
            menu::taskbar()
        );
    });
}

/// Opened with the keyboard it is on the first row; down moves; the
/// remote's letter opens its menu beside it with the keyboard on its first
/// row that can be chosen; the arrow out comes back to the remote; a letter
/// in the remote's menu chooses there, and choosing closes the menu.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_keyboard_moves_through_the_menu_and_the_remotes_menu() {
    quietly(|host, appearance| {
        let menu = open(appearance, Opened::Keyboard);
        assert_eq!(focus(), menu.control(0, 0).cast());
        assert_eq!(key(host, WM_KEYDOWN, VK_DOWN), Vec::<Told>::new());
        assert_eq!(focus(), menu.control(0, 1).cast());
        assert_eq!(key(host, WM_CHAR, u16::from(b'd')), Vec::<Told>::new());
        assert_eq!(menu.levels().len(), 2);
        assert_eq!(
            focus(),
            menu.control(1, 2).cast(),
            "past the line and the rule"
        );
        let (root, sub) = (menu_rect(&menu, 0), menu_rect(&menu, 1));
        assert!(
            sub.left >= root.right - 30 || sub.right <= root.left + 30,
            "beside the menu: {} and {}",
            shown(&root),
            shown(&sub)
        );
        assert_eq!(key(host, WM_KEYDOWN, VK_LEFT), Vec::<Told>::new());
        assert_eq!(menu.levels().len(), 1);
        assert_eq!(focus(), menu.control(0, 5).cast());
        assert_eq!(key(host, WM_KEYDOWN, VK_RETURN), Vec::<Told>::new());
        assert_eq!(menu.levels().len(), 2, "ENTER opens it again");
        assert_eq!(
            key(host, WM_CHAR, u16::from(b'l')),
            [Told::Picked(Some(5), 3)]
        );
        assert!(!menu.is_open());
        let menu = open(appearance, Opened::Keyboard);
        assert_eq!(key(host, WM_KEYDOWN, VK_ESCAPE), [Told::Dismissed]);
        assert!(!menu.is_open());
    });
}

/// A control's Active Accessibility object, as a screen reader takes it.
struct Accessible(*mut std::ffi::c_void);

impl Accessible {
    fn of(window: HWND) -> Accessible {
        // IID_IAccessible.
        let iid = windows_sys::core::GUID::from_u128(0x6187_36e0_3c3d_11cf_810c_00aa_0038_9b71);
        let mut object = std::ptr::null_mut();
        // SAFETY: the window is this thread's own; the object is written to
        // `object`.
        let found = unsafe {
            windows_sys::Win32::UI::Accessibility::AccessibleObjectFromWindow(
                window,
                windows_sys::Win32::UI::WindowsAndMessaging::OBJID_CLIENT.cast_unsigned(),
                &raw const iid,
                &raw mut object,
            )
        };
        assert!(found >= 0 && !object.is_null(), "{found:#x}");
        Accessible(object)
    }

    /// Entry `at` of the object's table.
    fn slot<T: Copy>(&self, at: usize) -> T {
        // SAFETY: a COM object begins with a pointer to its table.
        let table = unsafe { *self.0.cast::<*const *const ()>() };
        // SAFETY: `at` is within IAccessible's table, whose entries the
        // callers declare.
        let place = unsafe { table.add(at) };
        // SAFETY: as above.
        let entry = unsafe { *place };
        // SAFETY: the entry is a function of the type the caller declares.
        unsafe { std::mem::transmute_copy::<*const (), T>(&entry) }
    }

    fn myself() -> windows_sys::Win32::System::Variant::VARIANT {
        let mut child = windows_sys::Win32::System::Variant::VARIANT::default();
        child.Anonymous.Anonymous.vt = windows_sys::Win32::System::Variant::VT_I4;
        child
    }

    /// `get_accState`, entry 14.
    fn state(&self) -> u32 {
        let get: unsafe extern "system" fn(
            *mut std::ffi::c_void,
            windows_sys::Win32::System::Variant::VARIANT,
            *mut windows_sys::Win32::System::Variant::VARIANT,
        ) -> i32 = self.slot(14);
        let mut state = windows_sys::Win32::System::Variant::VARIANT::default();
        // SAFETY: the object is live; the state is written to `state`.
        unsafe { get(self.0, Self::myself(), &raw mut state) };
        // SAFETY: a state is a VT_I4, read through its union.
        let inner = unsafe { state.Anonymous.Anonymous };
        // SAFETY: as above.
        let value = unsafe { inner.Anonymous.lVal };
        u32::try_from(value).unwrap_or_default()
    }

    /// `accDoDefaultAction`, entry 25.
    fn act(&self) -> i32 {
        let act: unsafe extern "system" fn(
            *mut std::ffi::c_void,
            windows_sys::Win32::System::Variant::VARIANT,
        ) -> i32 = self.slot(25);
        // SAFETY: the object is live.
        unsafe { act(self.0, Self::myself()) }
    }
}

impl Drop for Accessible {
    fn drop(&mut self) {
        let release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 = self.slot(2);
        // SAFETY: the reference this holds is released once.
        unsafe { release(self.0) };
    }
}

/// A person with a screen reader reads a remote's row as a menu item that has a
/// menu, closed, and does its default action: the remote's menu opens with
/// the keyboard on its first row that can be chosen, as ENTER opens it, and
/// the row reads as open. An item's default action chooses it.
#[test]
#[ignore = "needs the desktop's foreground"]
fn assistive_technology_opens_a_remotes_menu_and_chooses_an_item() {
    use windows_sys::Win32::UI::Accessibility::STATE_SYSTEM_HASPOPUP;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        STATE_SYSTEM_COLLAPSED, STATE_SYSTEM_EXPANDED,
    };
    quietly(|host, appearance| {
        let menu = open(appearance, Opened::Keyboard);
        let remote = Accessible::of(menu.control(0, 5).cast());
        let state = remote.state();
        assert_eq!(
            state & (STATE_SYSTEM_HASPOPUP | STATE_SYSTEM_COLLAPSED | STATE_SYSTEM_EXPANDED),
            STATE_SYSTEM_HASPOPUP | STATE_SYSTEM_COLLAPSED,
            "{state:#x}"
        );
        assert_eq!(remote.act(), 0);
        assert_eq!(host.told(Duration::from_millis(50)), Vec::<Told>::new());
        assert_eq!(menu.levels().len(), 2, "the remote's menu opened");
        assert_eq!(focus(), menu.control(1, 2).cast());
        let state = remote.state();
        assert_eq!(
            state & (STATE_SYSTEM_HASPOPUP | STATE_SYSTEM_COLLAPSED | STATE_SYSTEM_EXPANDED),
            STATE_SYSTEM_HASPOPUP | STATE_SYSTEM_EXPANDED,
            "{state:#x}"
        );
        drop(remote);
        let item = Accessible::of(menu.control(0, 1).cast());
        assert_eq!(
            item.state() & (STATE_SYSTEM_HASPOPUP | STATE_SYSTEM_COLLAPSED),
            0,
            "an item has no menu"
        );
        assert_eq!(item.act(), 0);
        drop(item);
        assert_eq!(
            host.told(Duration::from_millis(50)),
            [Told::Picked(None, 1)]
        );
        assert!(!menu.is_open());
    });
}

/// Opened by the keyboard, a remote's menu keeps the keyboard on its first
/// row whatever the pointer rests on: Windows tells a level that appears
/// under a resting pointer that the pointer moved, and a pointer that has
/// not moved is not the person pointing. A pointer that moves still takes
/// the keyboard to the row it is on.
#[test]
#[ignore = "needs the desktop's foreground"]
fn a_pointer_that_has_not_moved_takes_the_keyboard_from_no_row() {
    quietly(|host, appearance| {
        let menu = open(appearance, Opened::Keyboard);
        assert_eq!(key(host, WM_CHAR, u16::from(b'd')), Vec::<Told>::new());
        let sub: HWND = menu.levels()[1].cast();
        let (x, y) = on_row(&menu, 1, 3);
        moved(sub, x, y);
        assert_eq!(
            focus(),
            menu.control(1, 3).cast(),
            "the pointer moved there"
        );
        // Out of the remote's menu and into it again by the keyboard, with
        // the pointer where it was: the level appears under it.
        assert_eq!(key(host, WM_KEYDOWN, VK_LEFT), Vec::<Told>::new());
        assert_eq!(key(host, WM_KEYDOWN, VK_RETURN), Vec::<Told>::new());
        assert_eq!(menu.levels().len(), 2);
        let sub: HWND = menu.levels()[1].cast();
        moved(sub, x, y);
        assert_eq!(
            focus(),
            menu.control(1, 2).cast(),
            "the keyboard stays where it was put"
        );
        let (x, y) = on_row(&menu, 1, 4);
        moved(sub, x, y);
        assert_eq!(focus(), menu.control(1, 4).cast(), "a move still counts");
        assert_eq!(key(host, WM_KEYDOWN, VK_ESCAPE), Vec::<Told>::new());
        assert_eq!(key(host, WM_KEYDOWN, VK_ESCAPE), [Told::Dismissed]);
    });
}

/// The pixel of a level's row at `x` across it, half way down, as the
/// level's picture holds it.
fn pixel(menu: &Menu, depth: usize, row: usize, x: i32) -> u32 {
    let rect = menu.laid(depth).unwrap().rows[row].rect;
    menu.pixel(depth, rect.left + x, rect.top + rect.height / 2)
        .unwrap()
}

/// With a remote's menu opened by the keyboard, the keyboard is shown there
/// alone: the row it is on has the focus visual, and the remote's row it was
/// opened from is lit as WinUI lights an item whose submenu is open, with no
/// focus visual; back out of it, the remote's row has the focus visual again.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_keyboard_is_shown_only_in_the_level_it_is_in() {
    quietly(|host, appearance| {
        let menu = open(appearance, Opened::Keyboard);
        host.told(Duration::from_millis(30));
        let rest = || pixel(&menu, 0, 1, 1);
        // The focus visual is on a row's bounds and inward, where a row at
        // rest shows the menu's own ground.
        let ringed = |depth: usize, row: usize| pixel(&menu, depth, row, 1) != rest();
        assert!(ringed(0, 0), "opened by the keyboard, on the first row");
        assert_eq!(key(host, WM_CHAR, u16::from(b'd')), Vec::<Told>::new());
        assert_eq!(menu.levels().len(), 2);
        assert!(ringed(1, 2), "the row the keyboard is on");
        assert!(!ringed(0, 5), "the remote's row, its menu open");
        assert_eq!(key(host, WM_KEYDOWN, VK_LEFT), Vec::<Told>::new());
        assert!(ringed(0, 5), "back on the remote's row");
        assert_eq!(key(host, WM_KEYDOWN, VK_ESCAPE), [Told::Dismissed]);
    });
}

/// The menu is composed whole as WinUI composes its flyout: a window with no
/// surface of its own and none of DWM's corner, edge or backdrop, larger than
/// the menu by the room WinUI's popup window gives its shadow - 10 effective
/// pixels beside, 2 above and 18 below, rounded up. Over acrylic and over
/// the colour it falls back to alike - the acrylic's effect graph is one the
/// compositor accepts - a row at rest is clear in the picture, so what the
/// composition lays beneath the rows shows there.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_menu_is_composed_whole_on_acrylic_or_the_colour_it_falls_back_to() {
    quietly(|host, appearance| {
        let Colours::Theme { .. } = appearance.colours else {
            return;
        };
        println!("this session: {:?}", settings::backdrop());
        for backdrop in [Backdrop::Acrylic, Backdrop::Solid] {
            let menu = open(
                &Appearance {
                    backdrop,
                    ..*appearance
                },
                Opened::Pointer,
            );
            host.told(Duration::from_millis(30));
            let root: HWND = menu.window().cast();
            assert!(menu.composed(0).unwrap().0, "composed over {backdrop:?}");
            // SAFETY: the window is this thread's own.
            let extended = unsafe { GetWindowLongPtrW(root, GWL_EXSTYLE) };
            let none = isize::try_from(WS_EX_NOREDIRECTIONBITMAP).unwrap();
            assert_eq!(extended & none, none);
            assert_eq!(attribute(root, DWMWA_SYSTEMBACKDROP_TYPE), DWMSBT_NONE);
            assert_eq!(
                attribute(root, DWMWA_WINDOW_CORNER_PREFERENCE),
                DWMWCP_DONOTROUND
            );
            let (window, placed) = (rect(root), menu_rect(&menu, 0));
            // SAFETY: the window is this thread's own.
            let scale = f64::from(unsafe { GetDpiForWindow(root) }) / 96.0;
            #[allow(
                clippy::cast_possible_truncation,
                reason = "a window's room on a screen, rounded up, is within an i32"
            )]
            let pixels = |effective: f32| (f64::from(effective) * scale).ceil() as i32;
            let (side, above, below) = laid::ROOM;
            assert_eq!(
                [
                    placed.left - window.left,
                    placed.top - window.top,
                    window.right - placed.right,
                    window.bottom - placed.bottom,
                ],
                [pixels(side), pixels(above), pixels(side), pixels(below)],
                "room for the shadow: {} round {}",
                shown(&window),
                shown(&placed)
            );
            assert_eq!(pixel(&menu, 0, 1, 1) >> 24, 0, "a row at rest is clear");
        }
    });
}

/// Opened with the pointer no row has the keyboard; a click on a row
/// chooses it, a click on a rule does nothing, and a click anywhere else
/// closes the menu.
#[test]
#[ignore = "needs the desktop's foreground"]
fn a_click_chooses_a_row_and_a_click_elsewhere_closes_the_menu() {
    quietly(|host, appearance| {
        let menu = open(appearance, Opened::Pointer);
        let root: HWND = menu.window().cast();
        assert_eq!(focus(), root, "the menu itself, no row");
        let (_, (left, top, _, _)) = menu.composed(0).unwrap();
        let row = menu.laid(0).unwrap().rows[1].rect;
        click(root, left + row.left + 10, top + row.top + row.height / 2);
        assert_eq!(
            host.told(Duration::from_millis(30)),
            [Told::Picked(None, 1)]
        );
        assert!(!menu.is_open());
        let menu = open(appearance, Opened::Pointer);
        let root: HWND = menu.window().cast();
        let (_, (left, top, _, _)) = menu.composed(0).unwrap();
        let rule = menu.laid(0).unwrap().rows[2].rect;
        click(root, left + rule.left + 10, top + rule.top + 1);
        assert_eq!(host.told(Duration::from_millis(30)), Vec::<Told>::new());
        click(root, -40, -40);
        assert_eq!(host.told(Duration::from_millis(30)), [Told::Dismissed]);
        assert!(!menu.is_open());
    });
}

/// A menu that never had the foreground - here it is locked elsewhere - is
/// not closed by losing an activation it had only within its own thread.
/// That it closes when the person, having had it in the foreground, goes to
/// another window needs the foreground, which the suite leaves where the
/// person has it: that is checked by hand.
#[test]
#[ignore = "needs the desktop's foreground"]
fn a_menu_without_the_foreground_is_not_closed_by_its_threads_activation() {
    quietly(|host, appearance| {
        let menu = open(appearance, Opened::Pointer);
        let root: HWND = menu.window().cast();
        let send = |state: u32| {
            // SAFETY: the window is this thread's own; no pointer is passed.
            unsafe { SendMessageW(root, WM_ACTIVATE, WPARAM::try_from(state).unwrap(), 0) };
        };
        send(WA_ACTIVE);
        send(WA_INACTIVE);
        assert_eq!(host.told(Duration::from_millis(30)), Vec::<Told>::new());
        assert!(menu.is_open());
    });
}

/// Under a contrast theme the menu's edge is the two pixels Hedwig draws
/// itself, at least.
#[test]
#[ignore = "needs the desktop's foreground"]
fn under_a_contrast_theme_the_menu_draws_its_own_edge() {
    quietly(|_, appearance| {
        let contrast = Appearance {
            colours: Colours::System(settings::system()),
            ..*appearance
        };
        let menu = open(&contrast, Opened::Pointer);
        let laid = menu.laid(0).unwrap();
        assert!(laid.edge >= 2);
        assert_eq!(laid.rows[0].rect.left, laid.edge);
    });
}

/// Wherever the taskbar is, the menu opens on the side of the icon away
/// from it, within the work area, and never over the icon.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_menu_opens_away_from_the_taskbar_at_any_edge() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let work = primary_work();
    let size = (240, 300);
    let middle_x = work.left.midpoint(work.right);
    let middle_y = work.top.midpoint(work.bottom);
    let cases = [
        (
            Taskbar::Bottom,
            (middle_x, work.bottom, middle_x + 40, work.bottom + 40),
        ),
        (
            Taskbar::Top,
            (middle_x, work.top - 40, middle_x + 40, work.top),
        ),
        (
            Taskbar::Left,
            (work.left - 40, middle_y, work.left, middle_y + 40),
        ),
        (
            Taskbar::Right,
            (work.right, middle_y, work.right + 40, middle_y + 40),
        ),
        (
            Taskbar::Bottom,
            (work.right - 40, work.bottom, work.right, work.bottom + 40),
        ),
    ];
    for (edge, icon) in cases {
        let at = (icon.0 + 20, icon.1 + 20);
        let (left, top) = menu::placement(at, Some(icon), size, edge);
        let placed = RECT {
            left,
            top,
            right: left + size.0,
            bottom: top + size.1,
        };
        let icon_rect = RECT {
            left: icon.0,
            top: icon.1,
            right: icon.2,
            bottom: icon.3,
        };
        assert!(apart(&placed, &icon_rect), "{edge:?}: {}", shown(&placed));
        assert!(within(&placed, &work), "{edge:?}: {}", shown(&placed));
        match edge {
            Taskbar::Bottom => assert!(placed.bottom <= icon.1),
            Taskbar::Top => assert!(placed.top >= icon.3),
            Taskbar::Left => assert!(placed.left >= icon.2),
            Taskbar::Right => assert!(placed.right <= icon.0),
        }
    }
}

/// A menu taller than the work area shows what fits and scrolls: END puts
/// the keyboard on the last row and brings it into view.
#[test]
#[ignore = "needs the desktop's foreground"]
fn a_menu_taller_than_the_screen_scrolls_to_the_keyboards_row() {
    quietly(|host, appearance| {
        let many: Vec<Entry> = (0..80)
            .map(|at| act(&format!("Remote number {at}")))
            .collect();
        let (icon, at) = icon();
        let menu = Menu::open(
            "hedwig probe",
            &many,
            appearance,
            at,
            Some(icon),
            Opened::Keyboard,
        )
        .expect("the menu");
        let laid = menu.laid(0).unwrap();
        assert!(laid.scrolls(), "80 rows are taller than the work area");
        let window = menu_rect(&menu, 0);
        assert!(within(&window, &primary_work()));
        assert_eq!(key(host, WM_KEYDOWN, VK_END), Vec::<Told>::new());
        let last: HWND = menu.control(0, 79).cast();
        assert_eq!(focus(), last);
        let row = rect(last);
        assert!(
            row.top >= window.top && row.bottom <= window.bottom,
            "the last row {} within the menu {}",
            shown(&row),
            shown(&window)
        );
    });
}

/// Where the person has Windows animate, the menu opens as WinUI's menu
/// flyout opens: it grows from half its height away from the point it was
/// opened at, over 250 ms on `cubic-bezier(0,0,0,1)`, its bottom where it
/// stays since it stands above that point. With motion off it is whole at
/// once.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_menu_opens_as_winuis_menu_flyout_opens_where_windows_animates() {
    quietly(|host, appearance| {
        let whole = open(appearance, Opened::Pointer);
        let full = menu_rect(&whole, 0);
        drop(whole);
        host.told(Duration::from_millis(50));

        let animated = Appearance {
            motion: Motion::Animated,
            ..*appearance
        };
        let started = Instant::now();
        let menu = open(&animated, Opened::Pointer);
        // The opening begins once the level's composition is made, somewhere
        // within the call to open it: that much of the clock is uncertain.
        let span = u32::try_from(started.elapsed().as_millis()).unwrap();
        let mut seen = vec![(0u32, menu_rect(&menu, 0))];
        while started.elapsed() < Duration::from_millis(400) {
            host.told(Duration::from_millis(4));
            let at = u32::try_from(started.elapsed().as_millis()).unwrap();
            seen.push((at, menu_rect(&menu, 0)));
        }
        let whole = |place: &RECT| place.bottom - place.top == full.bottom - full.top;
        let (_, first) = seen[0];
        assert!(
            !whole(&first),
            "it begins short of its height: {}",
            shown(&first)
        );
        let height = |place: &RECT| place.bottom - place.top;
        let expected = |at: u32| {
            let full = hedwig_view::arrange::Rect {
                left: full.left,
                top: full.top,
                width: full.right - full.left,
                height: full.bottom - full.top,
            };
            motion::opening(full, Grows::Up, Closed::Menu, at)
                .map_or(full.height, |(place, _)| place.height)
        };
        let mut last = 0;
        for (at, place) in &seen {
            assert_eq!(place.bottom, full.bottom, "its bottom stays");
            assert_eq!((place.left, place.right), (full.left, full.right));
            let tall = height(place);
            assert!(tall >= last, "it only grows");
            last = tall;
            // What the window shows is the step last taken: at most two of
            // Windows' timer ticks behind the time it was looked at, counted
            // from when the opening began.
            let earliest = expected(at.saturating_sub(40 + span));
            assert!(
                tall >= earliest && tall <= expected(*at),
                "at {at} ms, {span} ms of it opening: {tall} against {earliest}..{}",
                expected(*at)
            );
        }
        assert!(whole(&seen.last().unwrap().1), "whole once it has opened");
        let steps = seen
            .windows(2)
            .filter(|pair| height(&pair[0].1) != height(&pair[1].1))
            .count();
        println!(
            "opened from {} to {} high in {steps} steps",
            height(&first),
            full.bottom - full.top
        );
    });
}
