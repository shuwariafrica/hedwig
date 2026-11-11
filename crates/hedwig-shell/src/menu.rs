//! The icon's menu: a flyout window composed as WinUI composes its menu
//! flyout.
//!
//! Each level of the menu is a top-level window of its own, as a WinUI menu
//! flyout is, larger than the menu by the room its shadow takes, and
//! `Windows.UI.Composition` draws all of it (`compose`): the shadow, the
//! rounded corner, the acrylic, and the rows `hedwig-view` lays out in
//! Windows 11's measurements, drawn here as a picture with an alpha channel.
//! Where no composition can be made, Windows draws the level's frame, corners
//! and acrylic through DWM's attributes instead and the rows lie over that.
//! Every row that can be chosen is one of Windows' own buttons and every row
//! of words one of its static controls, each announced to assistive
//! technology as what it is in a menu.
//!
//! The person opened it, so it takes the foreground and the keyboard; it
//! closes when they choose, press ESCAPE, click anywhere else - which that
//! click does nothing else - or go to another window. Under a contrast
//! theme it draws itself in the system's colours with no acrylic.

use std::cell::RefCell;
use std::ffi::c_void;
use std::io;
use std::time::Instant;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, SIZE, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{
    DWMSBT_NONE, DWMSBT_TRANSIENTWINDOW, DWMWA_BORDER_COLOR, DWMWA_COLOR_NONE,
    DWMWA_SYSTEMBACKDROP_TYPE, DWMWA_TRANSITIONS_FORCEDISABLED, DWMWA_USE_IMMERSIVE_DARK_MODE,
    DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_DONOTROUND, DWMWCP_ROUND, DwmExtendFrameIntoClientArea,
    DwmSetWindowAttribute,
};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, EndPaint, GetMonitorInfoW, HDC, InvalidateRect, MONITOR_DEFAULTTONEAREST,
    MONITORINFO, MonitorFromPoint, PAINTSTRUCT,
};
use windows_sys::Win32::UI::Accessibility::{
    NotifyWinEvent, ROLE_SYSTEM_MENUITEM, ROLE_SYSTEM_MENUPOPUP, ROLE_SYSTEM_STATICTEXT,
    STATE_SYSTEM_HASPOPUP,
};
use windows_sys::Win32::UI::Controls::{DRAWITEMSTRUCT, MARGINS};
use windows_sys::Win32::UI::Controls::{STATE_SYSTEM_FOCUSABLE, STATE_SYSTEM_INVISIBLE};
use windows_sys::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetCapture, GetFocus, ReleaseCapture, SetCapture, SetFocus, VK_DOWN, VK_END, VK_ESCAPE,
    VK_HOME, VK_LEFT, VK_RETURN, VK_RIGHT, VK_SPACE, VK_UP,
};
use windows_sys::Win32::UI::Shell::{ABM_GETTASKBARPOS, APPBARDATA, SHAppBarMessage};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, BS_OWNERDRAW, CHILDID_SELF, CalculatePopupWindowPosition, CreateWindowExW,
    DefWindowProcW, DestroyWindow, EVENT_SYSTEM_MENUPOPUPEND, EVENT_SYSTEM_MENUPOPUPSTART, GA_ROOT,
    GetAncestor, GetCursorPos, GetForegroundWindow, GetWindowRect, IDC_ARROW, KillTimer,
    LoadCursorW, MSG, OBJID_CLIENT, RegisterClassExW, SPI_GETMENUSHOWDELAY, SW_SHOWNA,
    SetForegroundWindow, SetTimer, SetWindowPos, ShowWindow, SystemParametersInfoW,
    TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RIGHTALIGN, TPM_TOPALIGN, TPM_VERTICAL, TPM_WORKAREA,
    WA_INACTIVE, WM_ACTIVATE, WM_CAPTURECHANGED, WM_CHAR, WM_COMMAND, WM_DRAWITEM, WM_ERASEBKGND,
    WM_KEYDOWN, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_PAINT,
    WM_RBUTTONDOWN, WM_RBUTTONUP, WM_TIMER, WNDCLASSEXW, WS_CHILD, WS_EX_NOREDIRECTIONBITMAP,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    IsWindowVisible, STATE_SYSTEM_COLLAPSED, STATE_SYSTEM_EXPANDED, STATE_SYSTEM_FOCUSED,
};

use hedwig_view::arrange::Rect;
use hedwig_view::glance::Entry;
use hedwig_view::menu::{self, Edge, Key, Kind, Laid, Opened, Space, Step};
use hedwig_view::motion::{self, Closed, Grows};
use hedwig_view::paint::Canvas;
use hedwig_view::style::{
    Appearance, Backdrop, Colours, MenuInk, Mode, Motion, Rgb, System, Tint, Type, line, pixels,
};

use crate::annotation::Annotations;
use crate::compose::{self, Composer, Frame, Place};
use crate::draw::{self, Setter};
use crate::host::{self, Told};
use crate::raw::{module, size, wide};
use crate::write::{Backing, Keys, Run, Setting};

const CLASS: &str = "hedwig.menu";
const ALREADY_REGISTERED: i32 = 1410;
/// A static control whose parent draws it.
const SS_OWNERDRAW: u32 = 0x0D;
/// The first row's control; the others follow it by the row's place.
const ROW: u16 = 100;
/// The timer that opens or closes a submenu once the pointer has rested.
const REST: usize = 1;
/// The timer that steps a level's opening; each step is due at once, and
/// Windows' timer resolution paces them.
const OPENS: usize = 2;
/// A row's highlight has WinUI's control corner (`ControlCornerRadius`).
const ROW_CORNER: f32 = 4.0;
/// The menu has WinUI's overlay corner (`OverlayCornerRadius`).
const OVERLAY_CORNER: f32 = 8.0;
/// The chevron glyph of Segoe Fluent Icons (`SubItemChevron`, U+E974).
const CHEVRON: &str = "\u{E974}";

/// One level of the menu on the screen.
struct Level {
    window: HWND,
    /// The level's composition; `None` where Windows draws its frame.
    frame: Option<Frame>,
    /// The room round the menu within the window, left and above: its
    /// shadow's where the level is composed, none where it is not.
    room: (i32, i32),
    /// Where the menu stands within the window now, moved and cut by its
    /// opening while that plays.
    body: Place,
    laid: Laid,
    /// Each group row's own menu, laid out when the menu was opened.
    groups: Vec<Option<Laid>>,
    /// The row of the level above that opened this one.
    from: Option<usize>,
    /// Each row's control, or null for a rule.
    controls: Vec<HWND>,
    scrolled: i32,
    /// How far the rows are lifted while the level opens from its top, so
    /// the edge that moves carries them.
    lifted: i32,
    /// The level's opening, while it plays.
    opening: Option<Opening>,
    /// The row under the pointer, the row the keyboard is on, the row being
    /// pressed.
    hover: Option<usize>,
    focus: Option<usize>,
    pressed: Option<usize>,
    /// The level's picture as it was last drawn, `0xAARRGGBB`.
    pixels: Vec<u32>,
}

/// A level opening as WinUI's menu flyout opens: where it will stand, which
/// way it grows, and since when.
struct Opening {
    full: Rect,
    grows: Grows,
    closed: Closed,
    since: Instant,
}

/// What the open menu is drawn with.
struct Open {
    dpi: u32,
    setter: Setter,
    ink: Ink,
    /// Whether Windows draws acrylic behind the menu; where it does not, Hedwig
    /// fills the menu with the colour WinUI's acrylic falls back to.
    backdrop: bool,
    /// Whether access keys and the focus visual are shown: once a key is
    /// used, or always where the person has Windows show them.
    cues: bool,
    work: RECT,
    /// Active Accessibility's annotation service, while the menu is open.
    annotations: Option<Annotations>,
    levels: Vec<Level>,
    /// Whether the menu has been the active window, so that losing it now
    /// means the person went elsewhere.
    active: bool,
    /// What each level's window is called.
    title: String,
    /// Whether the person has Windows animate.
    motion: Motion,
    /// What the levels are composed with, while the menu is open; `None`
    /// where no composition could be made. Let go after the levels.
    composer: Option<Composer>,
    /// Where the pointer was when the menu last saw it, from when it opened.
    /// Windows tells a window that appears under a resting pointer that the
    /// pointer moved; a move to where it already was is not the person
    /// pointing, and takes the keyboard from no row.
    pointer: POINT,
}

/// What a row shows of the person's pointer and keys.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lit {
    Rest,
    Over,
    Pressed,
    /// A group whose menu is open beside it.
    Opened,
}

/// The inks of the menu: Windows 11's, or a contrast theme's own colours.
#[derive(Clone, Copy)]
enum Ink {
    Theme { mode: Mode, ink: MenuInk },
    System(System),
}

thread_local! {
    static OPEN: RefCell<Option<Open>> = const { RefCell::new(None) };
}

fn low(value: usize) -> u16 {
    u16::try_from(value & 0xffff).unwrap_or_default()
}

fn high(value: usize) -> u16 {
    u16::try_from((value >> 16) & 0xffff).unwrap_or_default()
}

fn float(value: i32) -> f32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a length on a screen is far below the 24 bits a float holds exactly"
    )]
    let float = value as f32;
    float
}

fn scale(dpi: u32) -> f32 {
    float(i32::try_from(dpi).unwrap_or(96)) / 96.0
}

/// A window's room of `effective` pixels on a monitor of `dpi`, rounded up as
/// WinUI rounds its popup window's (`CPopup::GetInsetsForDropShadow`).
fn room(effective: f32, dpi: u32) -> i32 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a window's room on a screen, rounded up, is within an i32"
    )]
    let pixels = (effective * scale(dpi)).ceil() as i32;
    pixels
}

fn register() -> io::Result<()> {
    let class = wide(CLASS);
    let description = WNDCLASSEXW {
        cbSize: size::<WNDCLASSEXW>(),
        lpfnWndProc: Some(procedure),
        hInstance: module(),
        // SAFETY: a null module with a system identifier names the system's
        // own arrow, which is shared and never destroyed.
        hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
        lpszClassName: class.as_ptr(),
        ..WNDCLASSEXW::default()
    };
    // SAFETY: the structure is complete, and the class name and the
    // procedure live as long as the process.
    if unsafe { RegisterClassExW(&raw const description) } == 0
        && io::Error::last_os_error().raw_os_error() != Some(ALREADY_REGISTERED)
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The monitor a point is on: its scale and its work area.
fn monitor(at: POINT) -> (u32, RECT) {
    // SAFETY: the call always answers a monitor with this flag.
    let monitor = unsafe { MonitorFromPoint(at, MONITOR_DEFAULTTONEAREST) };
    let (mut across, mut down) = (96u32, 96u32);
    // SAFETY: both places are valid for the call.
    unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &raw mut across, &raw mut down) };
    let mut info = MONITORINFO {
        cbSize: size::<MONITORINFO>(),
        ..MONITORINFO::default()
    };
    // SAFETY: the structure states its size and is written through the
    // pointer given.
    unsafe { GetMonitorInfoW(monitor, &raw mut info) };
    (across, info.rcWork)
}

/// The edge of the screen the taskbar is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taskbar {
    Left,
    Top,
    Right,
    Bottom,
}

/// The edge the taskbar is on now, as the shell answers; the bottom where
/// it does not.
pub fn taskbar() -> Taskbar {
    let mut data = APPBARDATA {
        cbSize: size::<APPBARDATA>(),
        ..APPBARDATA::default()
    };
    // SAFETY: the structure states its size and is written through the
    // pointer given.
    let found = unsafe { SHAppBarMessage(ABM_GETTASKBARPOS, &raw mut data) };
    match (found, data.uEdge) {
        (0, _) => Taskbar::Bottom,
        (_, 0) => Taskbar::Left,
        (_, 1) => Taskbar::Top,
        (_, 2) => Taskbar::Right,
        _ => Taskbar::Bottom,
    }
}

/// Where a window of `size` goes when opened at `at`, kept off `avoid`, as
/// Windows places a menu (`CalculatePopupWindowPosition`).
fn placed(at: POINT, size: SIZE, flags: u32, avoid: &RECT) -> (i32, i32) {
    let mut place = RECT::default();
    // SAFETY: every argument is a valid place for the call.
    let found = unsafe {
        CalculatePopupWindowPosition(&raw const at, &raw const size, flags, avoid, &raw mut place)
    };
    if found == 0 {
        (at.x, at.y)
    } else {
        (place.left, place.top)
    }
}

/// Where a menu of `width` by `height` opens from the notification area: at
/// `at`, the point the shell gave, on the side of it away from `taskbar`,
/// within the work area, and never over `icon`.
pub fn placement(
    at: (i32, i32),
    icon: Option<(i32, i32, i32, i32)>,
    (width, height): (i32, i32),
    taskbar: Taskbar,
) -> (i32, i32) {
    let point = POINT { x: at.0, y: at.1 };
    let avoid = icon.map_or(
        RECT {
            left: at.0,
            top: at.1,
            right: at.0,
            bottom: at.1,
        },
        |(left, top, right, bottom)| RECT {
            left,
            top,
            right,
            bottom,
        },
    );
    let flags = TPM_WORKAREA
        | match taskbar {
            Taskbar::Left => TPM_LEFTALIGN | TPM_TOPALIGN,
            Taskbar::Top => TPM_LEFTALIGN | TPM_TOPALIGN | TPM_VERTICAL,
            Taskbar::Right => TPM_RIGHTALIGN | TPM_TOPALIGN,
            Taskbar::Bottom => TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_VERTICAL,
        };
    placed(
        point,
        SIZE {
            cx: width,
            cy: height,
        },
        flags,
        &avoid,
    )
}

impl Open {
    fn px(&self, effective: f32) -> i32 {
        pixels(effective, self.dpi)
    }

    fn space(&self) -> Space {
        Space {
            dpi: self.dpi,
            widest: self.work.right - self.work.left,
            tallest: self.work.bottom - self.work.top,
            edge: match self.ink {
                Ink::Theme { .. } => Edge::System,
                Ink::System(_) => Edge::Contrast,
            },
        }
    }

    /// Level `depth`'s picture, as it is to be shown now.
    fn compose(&self, depth: usize) -> Option<Canvas> {
        let level = self.levels.get(depth)?;
        let laid = &level.laid;
        let mut canvas = self.ground(level);
        let opened = self.levels.get(depth + 1).and_then(|child| child.from);
        // The keyboard is in the deepest level open, and only there does a
        // row show it.
        let keyboard = depth + 1 == self.levels.len();
        let row_corner = ROW_CORNER * scale(self.dpi);
        for (at, row) in laid.rows.iter().enumerate() {
            let shift = |rect: Rect| Rect {
                top: rect.top - level.scrolled - level.lifted,
                ..rect
            };
            let state = if level.pressed == Some(at) {
                Lit::Pressed
            } else if level.hover == Some(at) {
                Lit::Over
            } else if opened == Some(at) {
                Lit::Opened
            } else {
                Lit::Rest
            };
            let (text, fill) = self.inks(row.kind, state);
            if let Some(fill) = fill {
                let radius = if row.kind == Kind::Rule {
                    0.0
                } else {
                    row_corner
                };
                canvas.fill(shift(row.fill), radius, fill);
            }
            if self.cues && keyboard && level.focus == Some(at) && row.kind.takes() {
                self.ring(&mut canvas, shift(row.rect), row_corner);
            }
            if row.kind == Kind::Rule {
                continue;
            }
            let area = shift(row.text);
            let run = Run {
                style: Some(Type::Body),
                label: &row.label,
                setting: if row.wrapped {
                    Setting::Wrapped
                } else {
                    Setting::Row
                },
                keys: if self.cues { Keys::Shown } else { Keys::Hidden },
            };
            let cover = self.setter.coverage(&run, area.width, area.height);
            canvas.mask(area.left, area.top, index(area.width), &cover, text);
            if let Some(chevron) = row.chevron.map(shift) {
                let tint = match self.ink {
                    Ink::Theme { ink, .. } => ink.chevron,
                    Ink::System(_) => text,
                };
                let glyph = Run {
                    style: None,
                    label: CHEVRON,
                    setting: Setting::Glyph,
                    keys: Keys::Hidden,
                };
                let cover = self.setter.coverage(&glyph, chevron.width, chevron.height);
                canvas.mask(
                    chevron.left,
                    chevron.top,
                    index(chevron.width),
                    &cover,
                    tint,
                );
            }
        }
        if laid.scrolls() {
            self.indicator(&mut canvas, level);
        }
        Some(canvas)
    }

    /// What a level's rows are drawn over: nothing where the composition
    /// fills the menu, with WinUI's edge laid over that; the colour acrylic
    /// falls back to where Windows frames it and composes none; the system's
    /// colours, with their two-pixel edge, under a contrast theme.
    fn ground(&self, level: &Level) -> Canvas {
        let laid = &level.laid;
        let (width, height) = (index(laid.width), index(laid.shown));
        match self.ink {
            // The composition fills the menu with acrylic or the colour it
            // falls back to; the picture lays WinUI's edge over that.
            Ink::Theme { ink, .. } if level.frame.is_some() => {
                let mut canvas = Canvas::clear(width, height);
                canvas.outline(
                    Rect {
                        left: 0,
                        top: 0,
                        width: laid.width,
                        height: level.body.height,
                    },
                    OVERLAY_CORNER * scale(self.dpi),
                    line(1.0, self.dpi),
                    ink.edge,
                );
                canvas
            }
            Ink::Theme { ink, .. } if !self.backdrop => Canvas::solid(width, height, ink.solid),
            Ink::Theme { .. } => Canvas::clear(width, height),
            Ink::System(system) => {
                // The two pixels a contrast theme asks a flyout's edge for,
                // and the window's colour within them.
                let mut canvas = Canvas::solid(width, height, system.window_text);
                let edge = laid.edge;
                canvas.fill(
                    Rect {
                        left: edge,
                        top: edge,
                        width: laid.width - 2 * edge,
                        height: laid.shown - 2 * edge,
                    },
                    0.0,
                    opaque(system.window),
                );
                canvas
            }
        }
    }

    /// A row's text and fill, by its kind and state: WinUI's
    /// `MenuFlyoutItem` and `MenuFlyoutSubItem` states, a group whose menu is
    /// open being `SubMenuOpened`.
    fn inks(&self, kind: Kind, state: Lit) -> (Tint, Option<Tint>) {
        match (self.ink, kind, state) {
            (Ink::Theme { ink, .. }, Kind::Rule, _) => (ink.rule, Some(ink.rule)),
            (Ink::Theme { ink, .. }, Kind::Line, _) => (ink.words, None),
            (Ink::Theme { ink, .. }, Kind::Item | Kind::Group, state) => {
                let fill = match state {
                    Lit::Pressed => Some(ink.pressed),
                    Lit::Over | Lit::Opened => Some(ink.over),
                    Lit::Rest => None,
                };
                (ink.text, fill)
            }
            (Ink::System(system), Kind::Rule, _) => {
                (opaque(system.window_text), Some(opaque(system.window_text)))
            }
            (Ink::System(system), Kind::Item | Kind::Group, Lit::Over | Lit::Pressed) => (
                opaque(system.highlight_text),
                Some(opaque(system.highlight)),
            ),
            (Ink::System(system), Kind::Group, Lit::Opened) => (opaque(system.highlight), None),
            (Ink::System(system), Kind::Line | Kind::Item | Kind::Group, _) => {
                (opaque(system.window_text), None)
            }
        }
    }

    /// The focus visual on a row: as WinUI draws the system focus visual on
    /// a menu item, on the item's own bounds and inward - the outer ring two
    /// effective pixels, the inner one - with the item's corner.
    fn ring(&self, canvas: &mut Canvas, bounds: Rect, radius: f32) {
        let (outer, inner) = match self.ink {
            Ink::Theme { ink, .. } => ink.ring,
            Ink::System(system) => (opaque(system.window_text), opaque(system.window)),
        };
        let two = line(2.0, self.dpi);
        canvas.outline(bounds, radius, two, outer);
        canvas.outline(
            Rect {
                left: bounds.left + two,
                top: bounds.top + two,
                width: bounds.width - 2 * two,
                height: bounds.height - 2 * two,
            },
            (radius - float(two)).max(0.0),
            line(1.0, self.dpi),
            inner,
        );
    }

    /// Where in a taller menu this is: WinUI's panning indicator.
    fn indicator(&self, canvas: &mut Canvas, level: &Level) {
        let laid = &level.laid;
        let tint = match self.ink {
            Ink::Theme {
                mode: Mode::Dark, ..
            } => Tint::argb(0x8BFF_FFFF),
            Ink::Theme {
                mode: Mode::Light, ..
            } => Tint::argb(0x7200_0000),
            Ink::System(system) => opaque(system.window_text),
        };
        let (thin, inset) = (line(2.0, self.dpi), self.px(2.0));
        let track = laid.shown - 2 * laid.edge - 2 * inset;
        let long = (track * laid.shown / laid.extent.max(1)).max(self.px(32.0).min(track));
        let furthest = (laid.extent - laid.shown).max(1);
        let top = laid.edge + inset + (track - long) * level.scrolled / furthest;
        canvas.fill(
            Rect {
                left: laid.width - laid.edge - inset - thin,
                top,
                width: thin,
                height: long,
            },
            float(thin) / 2.0,
            tint,
        );
    }
}

fn opaque(colour: Rgb) -> Tint {
    Tint {
        colour,
        alpha: 0xff,
    }
}

fn index(value: i32) -> usize {
    usize::try_from(value).unwrap_or_default()
}

/// Draws a level again: its picture is made anew and put on its window.
fn repaint(window: HWND) {
    OPEN.with_borrow_mut(|open| {
        let Some(open) = open else {
            return;
        };
        let Some(at) = open.levels.iter().position(|level| level.window == window) else {
            return;
        };
        let pixels = open.compose(at).map(|canvas| canvas.premultiplied());
        let composer = open.composer.as_ref();
        if let (Some(level), Some(pixels)) = (open.levels.get_mut(at), pixels) {
            level.pixels = pixels;
            if let (Some(frame), Some(composer)) = (level.frame.as_mut(), composer) {
                let size = (index(level.laid.width), index(level.laid.shown));
                // A level whose composition refuses a picture keeps the one
                // it shows.
                let _ = frame.show(composer, level.body, &level.pixels, size);
            }
        }
    });
    // SAFETY: a null rectangle asks for the whole window, children too; a
    // window that is gone refuses.
    unsafe { InvalidateRect(window, std::ptr::null(), 0) };
    let controls = OPEN.with_borrow(|open| {
        open.as_ref()
            .and_then(|open| open.levels.iter().find(|level| level.window == window))
            .map(|level| level.controls.clone())
            .unwrap_or_default()
    });
    for control in controls.into_iter().filter(|control| !control.is_null()) {
        // SAFETY: as above.
        unsafe { InvalidateRect(control, std::ptr::null(), 0) };
    }
}

/// Puts a level's picture, or the part of it under one of its controls, on
/// a device context.
fn put(window: HWND, dc: HDC, area: Option<Rect>) {
    OPEN.with_borrow(|open| {
        let Some(level) = open
            .as_ref()
            .and_then(|open| open.levels.iter().find(|level| level.window == window))
        else {
            return;
        };
        let width = index(level.laid.width);
        match area {
            None => draw::blit_alpha(dc, 0, 0, width, &level.pixels),
            Some(area) => {
                let mut part = Vec::with_capacity(index(area.width) * index(area.height));
                for y in area.top..area.bottom() {
                    let from = index(y) * width + index(area.left);
                    let Some(row) = level.pixels.get(from..from + index(area.width)) else {
                        return;
                    };
                    part.extend_from_slice(row);
                }
                draw::blit_alpha(dc, 0, 0, index(area.width), &part);
            }
        }
    });
}

/// Validates a level's window, putting its picture there where Windows frames
/// it; a composed level's window has no surface for GDI.
fn paint(window: HWND) {
    let mut paint = PAINTSTRUCT::default();
    // SAFETY: the window is this thread's own and `paint` a valid place.
    let dc = unsafe { BeginPaint(window, &raw mut paint) };
    if !is_composed(window) {
        put(window, dc, None);
    }
    // SAFETY: balances BeginPaint.
    unsafe { EndPaint(window, &raw const paint) };
}

/// Whether `window` is a composed level's, which has no surface for GDI.
fn is_composed(window: HWND) -> bool {
    OPEN.with_borrow(|open| {
        open.as_ref().is_some_and(|open| {
            open.levels
                .iter()
                .any(|level| level.window == window && level.frame.is_some())
        })
    })
}

/// The level whose window is `window` or holds it, and the row of a
/// control.
fn level_of(window: HWND) -> Option<(usize, Option<usize>)> {
    OPEN.with_borrow(|open| {
        let open = open.as_ref()?;
        open.levels.iter().enumerate().find_map(|(depth, level)| {
            if level.window == window {
                return Some((depth, None));
            }
            level
                .controls
                .iter()
                .position(|control| *control == window && !control.is_null())
                .map(|row| (depth, Some(row)))
        })
    })
}

/// Closes every level from `depth` down, the whole menu at 0.
fn close_from(depth: usize) {
    if depth == 0 {
        if let Some(open) = OPEN.with_borrow_mut(Option::take) {
            retire(open);
        }
        return;
    }
    let closing: Vec<(HWND, Vec<HWND>)> = OPEN.with_borrow_mut(|open| {
        let Some(open) = open else {
            return Vec::new();
        };
        let closing: Vec<Level> = open.levels.drain(depth.min(open.levels.len())..).collect();
        for level in &closing {
            if let Some(annotations) = &open.annotations {
                for control in level.controls.iter().filter(|control| !control.is_null()) {
                    annotations.clear(*control);
                }
                annotations.clear(level.window);
            }
        }
        closing
            .into_iter()
            .map(|level| (level.window, level.controls))
            .collect()
    });
    for (window, _) in closing.iter().rev() {
        // SAFETY: the window is this thread's own; the event carries no
        // pointer.
        unsafe {
            NotifyWinEvent(
                EVENT_SYSTEM_MENUPOPUPEND,
                *window,
                OBJID_CLIENT,
                CHILDID_SELF.cast_signed(),
            );
        };
        // SAFETY: the window is this thread's own and nothing uses it after.
        unsafe { DestroyWindow(*window) };
    }
    if let Some(parent) = OPEN.with_borrow(|open| {
        open.as_ref()
            .and_then(|open| open.levels.last())
            .map(|level| level.window)
    }) {
        repaint(parent);
    }
}

/// Lets a menu that is no longer the open one go: its windows, the pointer
/// where one of them holds it, then its text, annotation service and
/// composition. Taken out of [`OPEN`] first, so that the activation its
/// windows lose as they go is never read as the person going elsewhere.
fn retire(open: Open) {
    // SAFETY: no arguments.
    let captured = unsafe { GetCapture() };
    for level in open.levels.iter().rev() {
        if let Some(annotations) = &open.annotations {
            for control in level.controls.iter().filter(|control| !control.is_null()) {
                annotations.clear(*control);
            }
            annotations.clear(level.window);
        }
        // SAFETY: the window is this thread's own; the event carries no
        // pointer.
        unsafe {
            NotifyWinEvent(
                EVENT_SYSTEM_MENUPOPUPEND,
                level.window,
                OBJID_CLIENT,
                CHILDID_SELF.cast_signed(),
            );
        };
        if captured == level.window {
            // SAFETY: the capture is this thread's.
            unsafe { ReleaseCapture() };
        }
        // SAFETY: the window is this thread's own and nothing uses it after.
        unsafe { DestroyWindow(level.window) };
    }
    drop(open);
}

/// Makes one level's window, unshown, with a control for each row.
fn make_level(
    title: &str,
    open: &Open,
    (laid, depth): (Laid, usize),
    groups: Vec<Option<Laid>>,
    from: Option<usize>,
) -> io::Result<Level> {
    let (window, frame, room) = match &open.composer {
        Some(composer) => match composed(title, open, composer, (&laid, depth)) {
            Ok(made) => made,
            Err(_) => (drawn(title, open, &laid)?, None, (0, 0)),
        },
        None => (drawn(title, open, &laid)?, None, (0, 0)),
    };
    let annotate = |window: HWND, role: u32, action: Option<&str>, key: Option<char>| {
        if let Some(annotations) = &open.annotations {
            annotations.mark(window, role, action, key);
        }
    };
    // A remote's row says it has a menu, and whether it is open, when asked.
    let opens = |window: HWND, key: Option<char>| {
        if let Some(annotations) = &open.annotations {
            annotations.stated(window, ROLE_SYSTEM_MENUITEM, Some("Open"), key, opening);
        }
    };
    annotate(window, ROLE_SYSTEM_MENUPOPUP, None, None);
    let controls = laid
        .rows
        .iter()
        .enumerate()
        .map(|(at, row)| {
            let (class, style) = match row.kind {
                Kind::Rule => return std::ptr::null_mut(),
                Kind::Line => ("STATIC", SS_OWNERDRAW),
                Kind::Item | Kind::Group => ("BUTTON", BS_OWNERDRAW.cast_unsigned()),
            };
            let (class, text) = (wide(class), wide(&row.label));
            let id = ROW.saturating_add(u16::try_from(at).unwrap_or(u16::MAX));
            // SAFETY: both strings are NUL-terminated and copied by the call;
            // the parent is alive; a control's menu handle is its identifier.
            let control = unsafe {
                CreateWindowExW(
                    0,
                    class.as_ptr(),
                    text.as_ptr(),
                    WS_CHILD | WS_VISIBLE | style,
                    room.0 + row.rect.left,
                    room.1 + row.rect.top,
                    row.rect.width,
                    row.rect.height,
                    window,
                    usize::from(id) as _,
                    module(),
                    std::ptr::null(),
                )
            };
            match row.kind {
                Kind::Item => annotate(control, ROLE_SYSTEM_MENUITEM, Some("Execute"), row.key),
                Kind::Group => opens(control, row.key),
                // An owner-drawn static control says it is a picture.
                Kind::Line => annotate(control, ROLE_SYSTEM_STATICTEXT, None, None),
                Kind::Rule => {}
            }
            control
        })
        .collect();
    let body = Place {
        left: room.0,
        top: room.1,
        width: laid.width,
        height: laid.shown,
    };
    Ok(Level {
        window,
        frame,
        room,
        body,
        laid,
        groups,
        from,
        controls,
        scrolled: 0,
        lifted: 0,
        opening: None,
        hover: None,
        focus: None,
        pressed: None,
        pixels: Vec::new(),
    })
}

/// A level's window whose frame Windows draws, as large as the menu.
fn drawn(title: &str, open: &Open, laid: &Laid) -> io::Result<HWND> {
    let window = popup(title, 0, (laid.width, laid.shown))?;
    frame(open, window);
    Ok(window)
}

/// Level `depth`'s window composed whole, with the room WinUI gives its
/// shadow: no surface of its own, and DWM's corner, edge and backdrop off.
fn composed(
    title: &str,
    open: &Open,
    composer: &Composer,
    (laid, depth): (&Laid, usize),
) -> io::Result<(HWND, Option<Frame>, (i32, i32))> {
    // WinUI rounds its popup window's room up at the monitor's scale, so
    // the window never cuts more of the shadow than at 100 per cent.
    let (side, above, below) = (
        room(menu::ROOM.0, open.dpi),
        room(menu::ROOM.1, open.dpi),
        room(menu::ROOM.2, open.dpi),
    );
    let whole = (laid.width + 2 * side, laid.shown + above + below);
    let window = popup(title, WS_EX_NOREDIRECTIONBITMAP, whole)?;
    for (attribute, value) in [
        (
            DWMWA_WINDOW_CORNER_PREFERENCE,
            DWMWCP_DONOTROUND.cast_unsigned(),
        ),
        (DWMWA_BORDER_COLOR, DWMWA_COLOR_NONE),
        (DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_NONE.cast_unsigned()),
    ] {
        // SAFETY: each attribute takes one 32-bit value, which outlives the
        // call.
        unsafe {
            DwmSetWindowAttribute(
                window,
                attribute.cast_unsigned(),
                (&raw const value).cast(),
                4,
            )
        };
    }
    // The fill begins within the edge the level's picture lays: WinUI's
    // one effective pixel, or the contrast theme's two, which are opaque.
    // Under a contrast theme WinUI casts no shadow.
    let (edge, shadow) = match open.ink {
        Ink::Theme { mode, .. } => (line(1.0, open.dpi), Some(menu::shadow(depth, mode))),
        Ink::System(_) => (line(2.0, open.dpi), None),
    };
    match Frame::new(
        composer,
        window,
        (OVERLAY_CORNER * scale(open.dpi), edge),
        (shadow, compose::within(scale(open.dpi))),
    ) {
        Ok(frame) => Ok((window, Some(frame), (side, above))),
        Err(error) => {
            // SAFETY: the window is this thread's own and nothing uses it.
            unsafe { DestroyWindow(window) };
            Err(error)
        }
    }
}

/// A level's popup window, unshown: no taskbar button, over other windows.
fn popup(title: &str, extended: u32, (width, height): (i32, i32)) -> io::Result<HWND> {
    let class = wide(CLASS);
    let title = wide(title);
    // SAFETY: the class is registered and both names NUL-terminated.
    let window = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | extended,
            class.as_ptr(),
            title.as_ptr(),
            WS_POPUP,
            0,
            0,
            width,
            height,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            module(),
            std::ptr::null(),
        )
    };
    if window.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(window)
}

/// The frame Windows draws: its corners, its edge, and the acrylic behind
/// the rows where it composes acrylic; under a contrast theme no acrylic and
/// no edge of its own.
fn frame(open: &Open, window: HWND) {
    let (dark, backdrop, border) = match open.ink {
        Ink::Theme { mode, .. } if open.backdrop => {
            (mode == Mode::Dark, DWMSBT_TRANSIENTWINDOW, None)
        }
        Ink::Theme { mode, .. } => (mode == Mode::Dark, DWMSBT_NONE, None),
        Ink::System(_) => (false, DWMSBT_NONE, Some(DWMWA_COLOR_NONE)),
    };
    let mut attributes = vec![
        (DWMWA_USE_IMMERSIVE_DARK_MODE, u32::from(dark)),
        (DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND.cast_unsigned()),
        (DWMWA_SYSTEMBACKDROP_TYPE, backdrop.cast_unsigned()),
    ];
    if let Some(border) = border {
        attributes.push((DWMWA_BORDER_COLOR, border));
    }
    for (attribute, value) in attributes {
        // SAFETY: each attribute takes one 32-bit value, which outlives the
        // call; a Windows that does not know one refuses it.
        unsafe {
            DwmSetWindowAttribute(
                window,
                attribute.cast_unsigned(),
                (&raw const value).cast(),
                4,
            )
        };
    }
    if open.backdrop {
        // The whole client area is the frame's, so what Hedwig leaves clear
        // shows the acrylic.
        let margins = MARGINS {
            cxLeftWidth: -1,
            cxRightWidth: -1,
            cyTopHeight: -1,
            cyBottomHeight: -1,
        };
        // SAFETY: the window is this thread's own; the margins outlive the
        // call.
        unsafe { DwmExtendFrameIntoClientArea(window, &raw const margins) };
    }
}

/// Shows a level at its place, without activating it; the menu itself is
/// activated once, by [`Menu::open`]. Where the person has Windows animate,
/// the level opens as WinUI's menu flyout opens, growing `grows` from
/// `closed` of its height, and Windows' own transition for the window is
/// turned off so that one motion plays.
fn show(window: HWND, (left, top): (i32, i32), laid: &Laid, grows: Grows, closed: Closed) {
    let full = Rect {
        left,
        top,
        width: laid.width,
        height: laid.shown,
    };
    let room = OPEN.with_borrow(|open| {
        open.as_ref()
            .and_then(|open| open.levels.iter().find(|level| level.window == window))
            .filter(|level| level.frame.is_some())
            .map(|level| level.room)
    });
    let first = OPEN.with_borrow_mut(|open| {
        let open = open.as_mut()?;
        if open.motion != Motion::Animated {
            return None;
        }
        let level = open
            .levels
            .iter_mut()
            .find(|level| level.window == window)?;
        let (rect, lifted) = motion::opening(full, grows, closed, 0)?;
        level.lifted = lifted;
        level.opening = Some(Opening {
            full,
            grows,
            closed,
            since: Instant::now(),
        });
        if level.frame.is_some() {
            level.body = within(level.room, full, rect);
        }
        place_rows(level);
        Some(rect)
    });
    if first.is_some() {
        let off = 1u32;
        // SAFETY: the attribute takes one BOOL, which outlives the call.
        unsafe {
            DwmSetWindowAttribute(
                window,
                DWMWA_TRANSITIONS_FORCEDISABLED.cast_unsigned(),
                (&raw const off).cast(),
                4,
            )
        };
    }
    // A composed level's window stands where the whole menu and its shadow
    // will; one Windows frames is moved and cut by the opening itself.
    let rect = match room {
        Some((side, above)) => {
            let mut whole = RECT::default();
            // SAFETY: the window is this thread's own and `whole` a valid
            // place.
            unsafe { GetWindowRect(window, &raw mut whole) };
            Rect {
                left: full.left - side,
                top: full.top - above,
                width: whole.right - whole.left,
                height: whole.bottom - whole.top,
            }
        }
        None => first.unwrap_or(full),
    };
    // SAFETY: the window is this thread's own; no pointer is passed.
    unsafe {
        SetWindowPos(
            window,
            std::ptr::null_mut(),
            rect.left,
            rect.top,
            rect.width,
            rect.height,
            windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOACTIVATE
                | windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOZORDER,
        )
    };
    repaint(window);
    if first.is_some() {
        // SAFETY: the window is this thread's own; its timers go with it.
        unsafe { SetTimer(window, OPENS, 1, None) };
    }
    // SAFETY: as above.
    unsafe { ShowWindow(window, SW_SHOWNA) };
    // SAFETY: the event carries no pointer.
    unsafe {
        NotifyWinEvent(
            EVENT_SYSTEM_MENUPOPUPSTART,
            window,
            OBJID_CLIENT,
            CHILDID_SELF.cast_signed(),
        );
    };
}

/// Opens row `row`'s submenu of level `depth`, with the keyboard on its
/// first row when `keyboard`.
fn open_group(depth: usize, row: usize, keyboard: bool) {
    close_from(depth + 1);
    let made = OPEN.with_borrow(|open| {
        let open = open.as_ref()?;
        let level = open.levels.get(depth)?;
        let laid = level.groups.get(row)?.clone()?;
        let at = level.laid.rows.get(row)?;
        let place = menu_rect(level);
        // The submenu's first row stands level with its row, and the
        // submenu against its row's highlight, on the side there is room.
        let top =
            place.top + at.rect.top - level.scrolled - level.lifted - laid.edge - open.px(2.0);
        let avoid = RECT {
            left: place.left + at.fill.left,
            top,
            right: place.left + at.fill.right(),
            bottom: top + 1,
        };
        let where_ = placed(
            POINT {
                x: avoid.right,
                y: top,
            },
            SIZE {
                cx: laid.width,
                cy: laid.shown,
            },
            TPM_LEFTALIGN | TPM_TOPALIGN | TPM_WORKAREA,
            &avoid,
        );
        let made = make_level(&open.title, open, (laid, depth + 1), Vec::new(), Some(row)).ok()?;
        Some((made, where_, top))
    });
    let Some((made, where_, row_top)) = made else {
        return;
    };
    let window = made.window;
    let laid = made.laid.clone();
    OPEN.with_borrow_mut(|open| {
        if let Some(open) = open {
            open.levels.push(made);
        }
    });
    // A remote's menu grows down from its row, or up where there was no
    // room for it below.
    let grows = if where_.1 < row_top {
        Grows::Up
    } else {
        Grows::Down
    };
    show(window, where_, &laid, grows, Closed::Sub);
    if keyboard {
        focus(depth + 1, first(&laid));
    }
    // The row it was opened from is now lit as open, and the keyboard is no
    // longer shown in its level.
    let parent = OPEN.with_borrow(|open| {
        open.as_ref()
            .and_then(|open| open.levels.get(depth))
            .map(|level| level.window)
    });
    if let Some(parent) = parent {
        repaint(parent);
    }
}

fn first(laid: &Laid) -> Option<usize> {
    laid.rows.iter().position(|row| row.kind.takes())
}

/// Puts the keyboard on a row of a level, or on the level itself.
fn focus(depth: usize, row: Option<usize>) {
    let target = OPEN.with_borrow_mut(|open| {
        let open = open.as_mut()?;
        let level = open.levels.get_mut(depth)?;
        level.focus = row;
        if let Some(row) = row {
            let scrolled = menu::reveal(&level.laid, row, level.scrolled);
            if scrolled != level.scrolled {
                level.scrolled = scrolled;
                place_rows(level);
            }
        }
        let control = row.and_then(|row| level.controls.get(row).copied());
        Some((level.window, control.unwrap_or(level.window)))
    });
    if let Some((window, control)) = target {
        // SAFETY: the window is this thread's own.
        unsafe { SetFocus(control) };
        repaint(window);
    }
}

/// Does what a step says at level `depth`.
fn apply(depth: usize, step: Step, keyboard: bool) {
    match step {
        Step::Focus(row) => focus(depth, Some(row)),
        Step::Open(row) => {
            focus(depth, Some(row));
            open_group(depth, row, keyboard);
        }
        Step::Choose(row) => {
            let picked = OPEN.with_borrow(|open| {
                let open = open.as_ref()?;
                let level = open.levels.get(depth)?;
                let entry = u16::try_from(level.laid.rows.get(row)?.entry).ok()?;
                let group = match level.from {
                    Some(from) => {
                        let parent = open.levels.get(depth.checked_sub(1)?)?;
                        Some(u16::try_from(parent.laid.rows.get(from)?.entry).ok()?)
                    }
                    None => None,
                };
                Some((group, entry))
            });
            close_from(0);
            if let Some((group, entry)) = picked {
                host::tell(Told::Picked(group, entry));
            }
        }
        Step::Close if depth == 0 => {
            close_from(0);
            host::tell(Told::Dismissed);
        }
        Step::Close => {
            let from = OPEN.with_borrow(|open| {
                open.as_ref()
                    .and_then(|open| open.levels.get(depth))
                    .and_then(|level| level.from)
            });
            close_from(depth);
            focus(depth - 1, from);
        }
        Step::Nothing => {}
    }
}

/// A key typed while the menu is open, from the message loop: what it does
/// in the level the keyboard is in. Returns whether the menu took it.
pub(crate) fn key(message: &MSG) -> bool {
    let Some((depth, _)) = level_of(message.hwnd) else {
        return false;
    };
    let pressed = match message.message {
        WM_KEYDOWN => match low(message.wParam) {
            VK_UP => Key::Up,
            VK_DOWN => Key::Down,
            VK_HOME => Key::Home,
            VK_END => Key::End,
            VK_RETURN | VK_SPACE => Key::Choose,
            VK_RIGHT => Key::Into,
            VK_LEFT => Key::Out,
            VK_ESCAPE => Key::Escape,
            // Any other key goes on to become a character.
            _ => return false,
        },
        WM_CHAR => match char::from_u32(u32::from(low(message.wParam))) {
            Some(letter) if letter.is_alphanumeric() => Key::Letter(letter),
            _ => return true,
        },
        _ => return false,
    };
    // The deepest level open is the one the keys are for.
    let depth = OPEN.with_borrow(|open| {
        open.as_ref()
            .map_or(depth, |open| open.levels.len().saturating_sub(1))
    });
    press_at(depth, pressed);
    true
}

fn press_at(depth: usize, pressed: Key) {
    // A key shows access keys and the focus visual from then on.
    let step = OPEN.with_borrow_mut(|open| {
        let open = open.as_mut()?;
        open.cues = true;
        let level = open.levels.get(depth)?;
        Some(menu::step(
            &level.laid.rows,
            level.focus,
            pressed,
            depth > 0,
        ))
    });
    if let Some(step) = step {
        apply(depth, step, true);
    }
}

/// Where the menu of `level` stands on the screen now, without the room
/// round it.
fn menu_rect(level: &Level) -> RECT {
    let mut place = RECT::default();
    // SAFETY: the window is this thread's own and `place` a valid place.
    unsafe { GetWindowRect(level.window, &raw mut place) };
    if level.frame.is_none() {
        return place;
    }
    RECT {
        left: place.left + level.body.left,
        top: place.top + level.body.top,
        right: place.left + level.body.left + level.body.width,
        bottom: place.top + level.body.top + level.body.height,
    }
}

/// Where the menu stands within a composed level's window while it opens:
/// `rect` of `full`, moved by the room round it.
fn within((side, above): (i32, i32), full: Rect, rect: Rect) -> Place {
    Place {
        left: side + rect.left - full.left,
        top: above + rect.top - full.top,
        width: rect.width,
        height: rect.height,
    }
}

/// Where the pointer is, on the screen, from a message to the menu's own
/// window, which holds the capture.
fn screen_point(window: HWND, lparam: LPARAM) -> POINT {
    let x = i32::from(low(lparam.cast_unsigned()).cast_signed());
    let y = i32::from(high(lparam.cast_unsigned()).cast_signed());
    let mut place = RECT::default();
    // SAFETY: the window is this thread's own and `place` a valid place.
    unsafe { GetWindowRect(window, &raw mut place) };
    POINT {
        x: place.left + x,
        y: place.top + y,
    }
}

/// The level and row at a point of the screen.
fn hit(at: POINT) -> Option<(usize, Option<usize>)> {
    let places: Vec<RECT> = OPEN.with_borrow(|open| {
        open.as_ref()
            .map(|open| open.levels.iter().map(menu_rect).collect())
            .unwrap_or_default()
    });
    for (depth, place) in places.iter().enumerate().rev() {
        if at.x >= place.left && at.x < place.right && at.y >= place.top && at.y < place.bottom {
            let row = OPEN.with_borrow(|open| {
                let level = open.as_ref()?.levels.get(depth)?;
                level.laid.at(
                    at.x - place.left,
                    at.y - place.top,
                    level.scrolled + level.lifted,
                )
            });
            return Some((depth, row));
        }
    }
    None
}

fn pointer(window: HWND, message: u32, lparam: LPARAM) {
    let at = screen_point(window, lparam);
    if message == WM_MOUSEMOVE {
        let rested = OPEN.with_borrow_mut(|open| {
            open.as_mut().is_some_and(|open| {
                let rested = open.pointer.x == at.x && open.pointer.y == at.y;
                open.pointer = at;
                rested
            })
        });
        if rested {
            return;
        }
    }
    let found = hit(at);
    match message {
        WM_MOUSEMOVE => {
            let changed = OPEN.with_borrow_mut(|open| {
                let open = open.as_mut()?;
                let mut changed = Vec::new();
                for (depth, level) in open.levels.iter_mut().enumerate() {
                    let hover = match found {
                        Some((at_depth, row)) if at_depth == depth => row,
                        _ => None,
                    };
                    if level.hover != hover {
                        level.hover = hover;
                        changed.push((depth, level.window, hover));
                    }
                }
                Some(changed)
            });
            for (depth, window, hover) in changed.unwrap_or_default() {
                if let Some(row) = hover {
                    focus(depth, Some(row));
                }
                repaint(window);
                // A submenu opens, or the one open closes, once the pointer
                // rests: the person's own menu delay.
                let mut delay = 400u32;
                // SAFETY: the action writes one u32 through the pointer.
                unsafe {
                    SystemParametersInfoW(SPI_GETMENUSHOWDELAY, 0, (&raw mut delay).cast(), 0)
                };
                // SAFETY: the window is this thread's own.
                unsafe { SetTimer(window, REST, delay, None) };
            }
        }
        WM_LBUTTONDOWN | WM_RBUTTONDOWN => match found {
            None => {
                // Anywhere else: the menu closes, and the click does nothing
                // more.
                close_from(0);
                host::tell(Told::Dismissed);
            }
            Some((depth, row)) => {
                OPEN.with_borrow_mut(|open| {
                    if let Some(level) = open.as_mut().and_then(|open| open.levels.get_mut(depth)) {
                        level.pressed = row;
                    }
                });
                if let Some(window) = level_window(depth) {
                    repaint(window);
                }
            }
        },
        WM_LBUTTONUP | WM_RBUTTONUP => {
            let pressed = OPEN.with_borrow_mut(|open| {
                open.as_mut()?
                    .levels
                    .iter_mut()
                    .enumerate()
                    .find_map(|(depth, level)| level.pressed.take().map(|row| (depth, row)))
            });
            // A row is chosen where the press on it ends on it.
            if let (Some((depth, row)), Some((at_depth, Some(at_row)))) = (pressed, found)
                && depth == at_depth
                && row == at_row
            {
                let step = OPEN.with_borrow(|open| {
                    let level = open.as_ref()?.levels.get(depth)?;
                    Some(menu::step(
                        &level.laid.rows,
                        Some(row),
                        Key::Choose,
                        depth > 0,
                    ))
                });
                if let Some(step) = step {
                    apply(depth, step, false);
                    return;
                }
            }
            if let Some(window) = pressed.and_then(|(depth, _)| level_window(depth)) {
                repaint(window);
            }
        }
        _ => {}
    }
}

fn level_window(depth: usize) -> Option<HWND> {
    OPEN.with_borrow(|open| open.as_ref()?.levels.get(depth).map(|level| level.window))
}

/// The pointer has rested: open the group it rests on, or close a submenu
/// whose row it has left.
fn rested(window: HWND) {
    // SAFETY: the window is this thread's own.
    unsafe { KillTimer(window, REST) };
    let Some((depth, None)) = level_of(window) else {
        return;
    };
    let (hover, kind, open_from) = OPEN.with_borrow(|open| {
        let Some(open) = open.as_ref() else {
            return (None, None, None);
        };
        let level = open.levels.get(depth);
        let hover = level.and_then(|level| level.hover);
        let kind = hover.and_then(|row| {
            level
                .and_then(|level| level.laid.rows.get(row))
                .map(|row| row.kind)
        });
        let open_from = open.levels.get(depth + 1).and_then(|child| child.from);
        (hover, kind, open_from)
    });
    match (hover, kind) {
        (Some(row), Some(Kind::Group)) if open_from != Some(row) => open_group(depth, row, false),
        (Some(row), Some(_)) if open_from.is_some() && open_from != Some(row) => {
            close_from(depth + 1);
        }
        _ => {}
    }
}

/// Puts each row's control where the level's scrolling and its opening put
/// it.
fn place_rows(level: &Level) {
    let lift = level.scrolled + level.lifted;
    let (across, down) = if level.frame.is_some() {
        (level.body.left, level.body.top)
    } else {
        (0, 0)
    };
    for (control, row) in level.controls.iter().zip(&level.laid.rows) {
        if !control.is_null() {
            // SAFETY: the control is this thread's own.
            unsafe {
                SetWindowPos(
                    *control,
                    std::ptr::null_mut(),
                    across + row.rect.left,
                    down + row.rect.top - lift,
                    0,
                    0,
                    windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOSIZE
                        | windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOZORDER
                        | windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOACTIVATE,
                )
            };
        }
    }
}

/// Puts a level where its opening has it now, and ends the opening once the
/// level is open.
fn open_further(window: HWND) {
    let Some((depth, None)) = level_of(window) else {
        return;
    };
    let at = OPEN.with_borrow_mut(|open| {
        let level = open.as_mut()?.levels.get_mut(depth)?;
        let opening = level.opening.as_ref()?;
        let elapsed = u32::try_from(opening.since.elapsed().as_millis()).unwrap_or(u32::MAX);
        let (rect, lifted, done) =
            match motion::opening(opening.full, opening.grows, opening.closed, elapsed) {
                Some((rect, lifted)) => (rect, lifted, false),
                None => (opening.full, 0, true),
            };
        level.lifted = lifted;
        let full = opening.full;
        if done {
            level.opening = None;
        }
        let composed = level.frame.is_some();
        if composed {
            level.body = within(level.room, full, rect);
        }
        place_rows(level);
        Some((rect, done, composed))
    });
    let Some((rect, done, composed)) = at else {
        return;
    };
    if composed {
        repaint(window);
        if done {
            // SAFETY: the timer is this window's own.
            unsafe { KillTimer(window, OPENS) };
        }
        return;
    }
    // SAFETY: the window is this thread's own; no pointer is passed.
    unsafe {
        SetWindowPos(
            window,
            std::ptr::null_mut(),
            rect.left,
            rect.top,
            rect.width,
            rect.height,
            windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOACTIVATE
                | windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOZORDER,
        )
    };
    repaint(window);
    if done {
        // SAFETY: the timer is this window's own.
        unsafe { KillTimer(window, OPENS) };
    }
}

fn scroll(window: HWND, by: i32) {
    let Some((depth, None)) = level_of(window) else {
        return;
    };
    let moved = OPEN.with_borrow_mut(|open| {
        let level = open.as_mut()?.levels.get_mut(depth)?;
        let furthest = (level.laid.extent - level.laid.shown).max(0);
        let to = (level.scrolled + by).clamp(0, furthest);
        (to != level.scrolled).then(|| {
            level.scrolled = to;
            place_rows(level);
        })
    });
    if moved.is_some() {
        repaint(window);
    }
}

/// A remote's row as assistive technology reads it now: a menu item with a
/// menu, open while its menu is, with the keyboard where Windows has it.
fn opening(control: HWND) -> u32 {
    let mut state = STATE_SYSTEM_FOCUSABLE | STATE_SYSTEM_HASPOPUP;
    // SAFETY: no arguments.
    if unsafe { GetFocus() } == control {
        state |= STATE_SYSTEM_FOCUSED;
    }
    // SAFETY: any window may be asked.
    if unsafe { IsWindowVisible(control) } == 0 {
        state |= STATE_SYSTEM_INVISIBLE;
    }
    // Asked from within a call that holds the menu, the row says only what
    // it is.
    let expanded = OPEN.with(|open| {
        let open = open.try_borrow().ok()?;
        let open = open.as_ref()?;
        open.levels.iter().enumerate().find_map(|(depth, level)| {
            let row = level.controls.iter().position(|known| *known == control)?;
            Some(
                open.levels
                    .get(depth + 1)
                    .is_some_and(|child| child.from == Some(row)),
            )
        })
    });
    state
        | if expanded == Some(true) {
            STATE_SYSTEM_EXPANDED
        } else {
            STATE_SYSTEM_COLLAPSED
        }
}

/// A row's button was pressed by something other than the pointer and keys
/// the menu takes itself - assistive technology doing its default action:
/// what ENTER on that row does. The button took the pointer to press itself,
/// so the menu takes it back.
fn clicked(window: HWND, id: u16) {
    let Some((depth, _)) = level_of(window) else {
        return;
    };
    let Some(row) = id.checked_sub(ROW).map(usize::from) else {
        return;
    };
    let step = OPEN.with_borrow(|open| {
        let level = open.as_ref()?.levels.get(depth)?;
        level.laid.rows.get(row)?;
        Some(menu::step(
            &level.laid.rows,
            Some(row),
            Key::Choose,
            depth > 0,
        ))
    });
    if let Some(step) = step {
        apply(depth, step, true);
    }
    if let Some(root) = level_window(0)
        // SAFETY: no arguments.
        && unsafe { GetCapture() } != root
    {
        // SAFETY: the window is this thread's own.
        unsafe { SetCapture(root) };
    }
}

unsafe extern "system" fn procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_PAINT => {
            paint(window);
            0
        }
        WM_ERASEBKGND => 1,
        WM_DRAWITEM => {
            // SAFETY: for this message the parameter points at the
            // structure, which lives for the call.
            let item = unsafe { &*(lparam as *const DRAWITEMSTRUCT) };
            let area = OPEN.with_borrow(|open| {
                let level = open
                    .as_ref()?
                    .levels
                    .iter()
                    .find(|level| level.window == window)?;
                let row = level.laid.rows.get(usize::from(
                    u16::try_from(item.CtlID).ok()?.checked_sub(ROW)?,
                ))?;
                Some(Rect {
                    top: row.rect.top - level.scrolled - level.lifted,
                    ..row.rect
                })
            });
            if let Some(area) = area.filter(|_| !is_composed(window)) {
                let shown = OPEN.with_borrow(|open| {
                    open.as_ref()
                        .and_then(|open| open.levels.iter().find(|level| level.window == window))
                        .map_or(0, |level| level.laid.shown)
                });
                let area = Rect {
                    top: area.top.max(0),
                    height: (area.bottom().min(shown) - area.top.max(0)).max(0),
                    ..area
                };
                put(window, item.hDC, Some(area));
            }
            1
        }
        WM_MOUSEMOVE | WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_LBUTTONUP | WM_RBUTTONUP => {
            pointer(window, message, lparam);
            0
        }
        WM_COMMAND if u32::from(high(wparam)) == BN_CLICKED => {
            clicked(window, low(wparam));
            0
        }
        WM_MOUSEWHEEL => {
            let notches = i32::from(high(wparam).cast_signed()) / 120;
            let lines = OPEN.with_borrow(|open| open.as_ref().map_or(0, |open| open.px(60.0)));
            let target = hit(screen_point(window, lparam))
                .and_then(|(depth, _)| level_window(depth))
                .unwrap_or(window);
            scroll(target, -notches * lines);
            0
        }
        WM_TIMER if wparam == REST => {
            rested(window);
            0
        }
        WM_TIMER if wparam == OPENS => {
            open_further(window);
            0
        }
        WM_ACTIVATE => {
            let (state, other) = (u32::from(low(wparam)), lparam as HWND);
            let ours = level_of(other).is_some();
            if state == WA_INACTIVE {
                let was_active =
                    OPEN.with_borrow(|open| open.as_ref().is_some_and(|open| open.active));
                if was_active && !ours {
                    close_from(0);
                    host::tell(Told::Dismissed);
                }
            } else {
                // Refused the foreground, a window is still made active for
                // its own thread; only the foreground counts, since only
                // from there does going elsewhere take activation away.
                // SAFETY: no arguments.
                let foreground = unsafe { GetForegroundWindow() } == window;
                OPEN.with_borrow_mut(|open| {
                    if let Some(open) = open {
                        open.active |= foreground;
                    }
                });
            }
            0
        }
        WM_CAPTURECHANGED => {
            capture_changed(window, lparam as HWND);
            0
        }
        // SAFETY: the arguments are the ones Windows called this procedure
        // with, passed on unchanged.
        _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
}

/// `taker` took the pointer from `window`: where another window took it, a
/// menu gives way.
fn capture_changed(window: HWND, taker: HWND) {
    let root = OPEN.with_borrow(|open| {
        open.as_ref()
            .and_then(|open| open.levels.first())
            .map(|level| level.window)
    });
    // A row's own button takes the pointer while it is pressed through
    // assistive technology: that is not going elsewhere.
    // SAFETY: any window may be asked.
    let taker_root = unsafe { GetAncestor(taker, GA_ROOT) };
    if Some(window) == root
        && level_of(taker).is_none()
        && level_of(taker_root).is_none()
        && OPEN.with_borrow(|open| open.as_ref().is_some_and(|open| open.active))
    {
        close_from(0);
        host::tell(Told::Dismissed);
    }
}

/// The icon's menu, open. Dropping it closes it.
#[derive(Debug)]
pub struct Menu {
    window: HWND,
}

impl Menu {
    /// Opens the menu of `entries` at `at`, the point the shell gave with the
    /// request for it, kept off `icon`, the icon's place. The menu takes the
    /// foreground and the keyboard; opened with the keyboard it begins with
    /// the keyboard on its first row. Opened while another is open - made
    /// again, a setting changed - it stands in that one's place, still, and
    /// takes the foreground and the pointer from it before it goes.
    ///
    /// # Errors
    ///
    /// Windows refused the window.
    pub fn open(
        title: &str,
        entries: &[Entry],
        appearance: &Appearance,
        at: (i32, i32),
        icon: Option<(i32, i32, i32, i32)>,
        opened: Opened,
    ) -> io::Result<Menu> {
        let replaced = OPEN.with_borrow_mut(Option::take);
        let menu = Self::make(
            title,
            entries,
            appearance,
            at,
            icon,
            opened,
            replaced.is_some(),
        );
        if let Some(replaced) = replaced {
            retire(replaced);
        }
        menu
    }

    fn make(
        title: &str,
        entries: &[Entry],
        appearance: &Appearance,
        at: (i32, i32),
        icon: Option<(i32, i32, i32, i32)>,
        opened: Opened,
        replacing: bool,
    ) -> io::Result<Menu> {
        register()?;
        let point = POINT { x: at.0, y: at.1 };
        let (dpi, work) = monitor(point);
        let ink = match appearance.colours {
            Colours::Theme { mode, accent } => Ink::Theme {
                mode,
                ink: hedwig_view::style::Palette::new(mode, accent).menu(),
            },
            Colours::System(system) => Ink::System(system),
        };
        let mut always = 0i32;
        // SAFETY: the action writes one BOOL through the pointer given.
        unsafe {
            SystemParametersInfoW(
                windows_sys::Win32::UI::WindowsAndMessaging::SPI_GETKEYBOARDCUES,
                0,
                (&raw mut always).cast(),
                0,
            )
        };
        let backdrop = matches!(ink, Ink::Theme { .. }) && appearance.backdrop == Backdrop::Acrylic;
        let composer = Composer::new(
            match ink {
                Ink::Theme { ink, .. } if backdrop => compose::Backdrop::Acrylic(ink.acrylic),
                Ink::Theme { ink, .. } => compose::Backdrop::Solid(ink.solid),
                Ink::System(system) => compose::Backdrop::Solid(system.window),
            },
            scale(dpi),
        )
        .ok();
        let mut pointer = POINT::default();
        // SAFETY: the place is valid; a desktop that cannot say leaves the
        // origin, which only lets the first move count.
        unsafe { GetCursorPos(&raw mut pointer) };
        let open = Open {
            pointer,
            dpi,
            // Hedwig draws every row itself, under a contrast theme too.
            setter: Setter::new(dpi, appearance.text, Backing::Clear, true),
            ink,
            backdrop,
            cues: always != 0 || opened == Opened::Keyboard,
            work,
            annotations: Annotations::new(),
            levels: Vec::new(),
            active: false,
            title: title.to_owned(),
            // Made again in place, the menu was already open: it does not
            // open a second time.
            motion: if replacing {
                Motion::Still
            } else {
                appearance.motion
            },
            composer,
        };
        let space = open.space();
        let laid = menu::arrange(entries, &open.setter, space, opened);
        let groups = entries
            .iter()
            .map(|entry| match entry {
                Entry::Group { entries, .. } => {
                    Some(menu::arrange(entries, &open.setter, space, opened))
                }
                _ => None,
            })
            .collect();
        let level = make_level(title, &open, (laid.clone(), 0), groups, None)?;
        let window = level.window;
        let place = placement(at, icon, (laid.width, laid.shown), taskbar());
        let mut open = open;
        open.levels.push(level);
        OPEN.set(Some(open));
        // The menu grows away from the point it was opened at.
        let grows = if place.1 + laid.shown <= at.1 {
            Grows::Up
        } else {
            Grows::Down
        };
        show(window, place, &laid, grows, Closed::Menu);
        // The person asked for the menu: it takes the foreground, which the
        // shell allows the icon's process on the person's click, and the
        // pointer, so that a click elsewhere closes it and does nothing else.
        // SAFETY: the window is this thread's own.
        unsafe { SetForegroundWindow(window) };
        // SAFETY: as above.
        unsafe { SetCapture(window) };
        if opened == Opened::Keyboard {
            focus(0, first(&laid));
        } else {
            focus(0, None);
        }
        Ok(Menu { window })
    }

    /// The menu's first level, for whatever must name it to Windows.
    pub fn window(&self) -> *mut c_void {
        self.window
    }

    /// Each open level's window, the menu's first.
    pub fn levels(&self) -> Vec<*mut c_void> {
        OPEN.with_borrow(|open| {
            open.as_ref()
                .map(|open| open.levels.iter().map(|level| level.window).collect())
                .unwrap_or_default()
        })
    }

    /// How a level is laid out, the menu's first at 0.
    pub fn laid(&self, depth: usize) -> Option<Laid> {
        OPEN.with_borrow(|open| {
            open.as_ref()?
                .levels
                .get(depth)
                .map(|level| level.laid.clone())
        })
    }

    /// A row's control at a level, or null.
    pub fn control(&self, depth: usize, row: usize) -> *mut c_void {
        OPEN.with_borrow(|open| {
            open.as_ref()
                .and_then(|open| open.levels.get(depth))
                .and_then(|level| level.controls.get(row).copied())
                .unwrap_or(std::ptr::null_mut())
        })
    }

    /// Does what `key` does in the deepest open level, as the key typed
    /// there would.
    pub fn press(&self, key: Key) {
        let depth = OPEN.with_borrow(|open| {
            open.as_ref()
                .map_or(0, |open| open.levels.len().saturating_sub(1))
        });
        press_at(depth, key);
    }

    /// Whether a level is composed whole, as WinUI composes its flyout, rather
    /// than framed by Windows; and where the menu stands within its window.
    pub fn composed(&self, depth: usize) -> Option<(bool, (i32, i32, i32, i32))> {
        OPEN.with_borrow(|open| {
            let level = open.as_ref()?.levels.get(depth)?;
            let body = level.body;
            Some((
                level.frame.is_some(),
                (body.left, body.top, body.width, body.height),
            ))
        })
    }

    /// What a level's picture holds at (`x`, `y`) of the menu, `0xAARRGGBB`
    /// premultiplied, as last handed to Windows to show.
    pub fn pixel(&self, depth: usize, x: i32, y: i32) -> Option<u32> {
        OPEN.with_borrow(|open| {
            let level = open.as_ref()?.levels.get(depth)?;
            let (x, y) = (usize::try_from(x).ok()?, usize::try_from(y).ok()?);
            let width = usize::try_from(level.laid.width).ok()?;
            (x < width)
                .then(|| level.pixels.get(y * width + x).copied())
                .flatten()
        })
    }

    /// Whether the menu is still open.
    pub fn is_open(&self) -> bool {
        OPEN.with_borrow(|open| {
            open.as_ref().is_some_and(|open| {
                open.levels
                    .first()
                    .is_some_and(|level| level.window == self.window)
            })
        })
    }
}

impl Drop for Menu {
    fn drop(&mut self) {
        if self.is_open() {
            close_from(0);
        }
    }
}

/// Whether a window is one of an open menu's, or a control of one.
pub(crate) fn owns(window: HWND) -> bool {
    // SAFETY: a window that is gone answers null.
    let root = unsafe { GetAncestor(window, GA_ROOT) };
    level_of(window).is_some() || level_of(root).is_some()
}
