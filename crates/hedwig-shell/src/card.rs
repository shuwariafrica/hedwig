//! The card: the window a held request is answered from.
//!
//! It is a dialog of Windows' own dialog manager holding Windows' own
//! controls - static text, push buttons, an edit box - so the keyboard and a
//! screen reader are served by Windows. What Hedwig does itself is what
//! Windows does not do for a Win32 surface: it places every control in
//! pixels, from `hedwig-view`'s arrangement in Windows 11's measurements, and
//! it draws the dialog's two layers and its buttons in the person's mode and
//! accent. Under a contrast theme it draws nothing: the buttons are Windows'
//! own and every colour is one of the system's.
//!
//! The card is shown above other windows and is never given the focus: the
//! person's keys go on reaching what they were typing in until they bring
//! the card forward themselves. No answer is the default, no answer has the
//! keyboard when the card comes forward, and a letter typed without ALT is
//! never an access key, so a key that does arrive decides nothing.

use std::cell::RefCell;
use std::io;
use std::time::Instant;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{
    DWMSBT_NONE, DWMWA_CAPTION_COLOR, DWMWA_SYSTEMBACKDROP_TYPE, DWMWA_USE_IMMERSIVE_DARK_MODE,
    DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute,
};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, HDC, InvalidateRect, MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromRect,
    SetBkColor, SetTextColor,
};
use windows_sys::Win32::UI::Accessibility::{
    NotifyWinEvent, ROLE_SYSTEM_ALERT, ROLE_SYSTEM_STATICTEXT,
};
use windows_sys::Win32::UI::Controls::{
    DRAWITEMSTRUCT, ODS_DISABLED, ODS_FOCUS, ODS_NOACCEL, ODS_NOFOCUSRECT, ODS_SELECTED,
    ODT_STATIC, WM_MOUSELEAVE,
};
use windows_sys::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, DDC_DISABLE_ALL, GetDpiForMonitor, MDT_EFFECTIVE_DPI,
    SetDialogDpiChangeBehavior,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, IsWindowEnabled, TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent, VK_END,
    VK_HOME, VK_NEXT, VK_PRIOR,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BS_MULTILINE, BS_OWNERDRAW, BS_PUSHBUTTON, CHILDID_SELF, CreateDialogIndirectParamW,
    CreateWindowExW, DLGTEMPLATE, DefWindowProcW, DestroyWindow, EN_KILLFOCUS, EN_SETFOCUS,
    ES_AUTOHSCROLL, ES_PASSWORD, EVENT_SYSTEM_ALERT, GA_ROOT, GetAncestor, GetClientRect,
    GetDlgCtrlID, GetDlgItem, GetParent, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
    HWND_TOPMOST, IDC_ARROW, IDCANCEL, IDOK, KillTimer, LoadCursorW, OBJID_CLIENT,
    RegisterClassExW, SPI_GETKEYBOARDCUES, SW_ERASE, SW_HIDE, SW_INVALIDATE, SW_SCROLLCHILDREN,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, ScrollWindowEx,
    SendMessageW, SetForegroundWindow, SetTimer, SetWindowPos, SetWindowTextW, ShowWindow,
    SystemParametersInfoW, UIS_SET, UISF_HIDEACCEL, UISF_HIDEFOCUS, WA_ACTIVE, WM_ACTIVATE,
    WM_CHANGEUISTATE, WM_CLOSE, WM_COMMAND, WM_CTLCOLORDLG, WM_CTLCOLOREDIT, WM_DPICHANGED,
    WM_DRAWITEM, WM_ERASEBKGND, WM_KEYDOWN, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_NCDESTROY,
    WM_NEXTDLGCTL, WM_SETFONT, WM_TIMER, WNDCLASSEXW, WS_BORDER, WS_CAPTION, WS_CHILD,
    WS_CLIPCHILDREN, WS_DISABLED, WS_EX_CONTROLPARENT, WS_EX_TOPMOST, WS_POPUP, WS_SYSMENU,
    WS_TABSTOP, WS_VISIBLE,
};

use hedwig_view::arrange::{
    self, Arranged, Layer, Measure as _, Part, Placed, Rect, Size, Space, arrange,
};
use hedwig_view::card::{Card, Does, Subject, Weight, keyed};
use hedwig_view::motion;
use hedwig_view::paint::{self, Shape};
use hedwig_view::style::{
    Appearance, Colours, Input, Kind, Mode, Motion, Palette, Rgb, State, Tint, Type, line, pixels,
};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};

use zeroize::Zeroizing;

use crate::annotation::Annotations;
use crate::draw::{self, Brush, Setter};
use crate::host::{self, Told};
use crate::raw::{module, size, wide};
use crate::window::Named;
use crate::write::{Backing, Keys, Run, Setting};

/// The first answer's control; the others follow it.
pub const ANSWER: u16 = 100;
/// The heading's control.
pub const HEADING: u16 = 200;
/// The line that says how many more are waiting.
pub const BEHIND: u16 = 201;
/// What an answer that allows for a time lets through.
pub const ALLOWS: u16 = 202;
/// What the heading's question means.
pub const SAYS: u16 = 203;
/// The first fact's name, and the first fact; the others follow each.
pub const NAME: u16 = 300;
pub const FACT: u16 = 400;
/// Where an answer is typed.
pub const TYPED: u16 = 500;
/// The layer that holds the heading and what the person needs to decide.
pub const CONTENT: u16 = 600;

/// Text Hedwig sets itself; the control keeps it, and a screen reader reads
/// it there.
const SS_OWNERDRAW: u32 = 0x0D;
/// Text read as it is: an `&` in a key's mark is not an access key.
const SS_NOPREFIX: u32 = 0x80;
/// How far from the edges of the work area the card stands.
const MARGIN: f32 = 12.0;
/// The radius of a control's outer edge, and the room its focus rings take
/// outside it. A WinUI button with `ControlCornerRadius` 4 and a border of 1
/// draws its outer edge on a radius of 5: at 120 dpi its corner's pixels are
/// those of a radius of 6.25 to within two levels, and not those of 5
/// (measured).
const CORNER: f32 = 5.0;
const RINGS: f32 = 3.0;
/// A box for typing keeps its text this far inside: left, above, right.
const BOX_LEFT: f32 = 10.0;
const BOX_RIGHT: f32 = 6.0;
const PANE: &str = "hedwig.card.content";
const ALREADY_REGISTERED: i32 = 1410;
const STYLE: u32 = WS_POPUP | WS_CAPTION | WS_SYSMENU;

/// What the card on this thread is drawn with. One card is shown at a time.
struct Look {
    dpi: u32,
    /// Whether Windows animates: where it does, an answer's fill changes over
    /// WinUI's time for it.
    motion: Motion,
    /// Each answer's fill as it last changed, by its window.
    fills: Vec<(isize, Fill)>,
    setter: Setter,
    /// `None` under a contrast theme: Windows draws the buttons itself.
    palette: Option<Palette>,
    content: Rgb,
    strip: Rgb,
    /// The brushes of text and of text that says what another is.
    inks: (Tint, Tint),
    quiet: Rgb,
    separator: Brush,
    content_brush: Brush,
    strip_brush: Brush,
    /// The fill of the box for typing, at rest and with the keyboard in it.
    boxes: Option<[Brush; 2]>,
    arranged: Arranged,
    /// Each choice as a button: its kind, and the layer it stands in.
    buttons: Vec<(Kind, Layer)>,
    /// The choice that sends what was typed.
    sends: Option<u16>,
    /// The control the pointer is over, and whether the keyboard is in the
    /// box for typing.
    hot: Option<u16>,
    typing: bool,
    /// How far the content is scrolled.
    scrolled: i32,
    /// A confirmation of the person's own act, which they asked for: it has
    /// the keyboard, and its answers are never off.
    confirming: bool,
    /// The safe answer, which has the keyboard when a confirmation is asked.
    cancels: Option<u16>,
}

thread_local! {
    /// What each dialog of this thread is drawn with, by its window: a card
    /// and a confirmation can be shown at once.
    static LOOKS: RefCell<Vec<(isize, Look)>> = const { RefCell::new(Vec::new()) };
}

/// The dialog `window` is, or is inside.
fn root(window: HWND) -> isize {
    // SAFETY: no pointers; a window that is gone answers null.
    unsafe { GetAncestor(window, GA_ROOT) as isize }
}

/// What the dialog `window` belongs to is drawn with.
fn looked<R>(window: HWND, read: impl FnOnce(&Look) -> R) -> Option<R> {
    let dialog = root(window);
    LOOKS.with_borrow(|looks| {
        looks
            .iter()
            .find(|(known, _)| *known == dialog)
            .map(|(_, look)| read(look))
    })
}

fn looked_mut<R>(window: HWND, change: impl FnOnce(&mut Look) -> R) -> Option<R> {
    let dialog = root(window);
    LOOKS.with_borrow_mut(|looks| {
        looks
            .iter_mut()
            .find(|(known, _)| *known == dialog)
            .map(|(_, look)| change(look))
    })
}

/// What choosing the answer at `place` of `dialog` tells the loop.
fn answered(dialog: HWND, place: u16) {
    match looked(dialog, |look| (look.confirming, look.cancels)) {
        Some((true, cancels)) => {
            host::tell(Told::Confirmed((cancels != Some(place)).then_some(place)));
        }
        _ => host::tell(Told::Answered(place)),
    }
}

fn low(value: usize) -> u16 {
    u16::try_from(value & 0xffff).unwrap_or_default()
}

fn high(value: usize) -> u16 {
    u16::try_from((value >> 16) & 0xffff).unwrap_or_default()
}

fn add(to: u16, place: usize) -> u16 {
    to.saturating_add(u16::try_from(place).unwrap_or(u16::MAX))
}

fn float(pixels: i32) -> f32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a length on a screen is far below the 24 bits a float holds exactly"
    )]
    let float = pixels as f32;
    float
}

fn scale(dpi: u32) -> f32 {
    float(i32::try_from(dpi).unwrap_or(96)) / 96.0
}

/// A control of the card by its identifier: in the row of answers, or in the
/// content.
fn control(dialog: HWND, id: u16) -> HWND {
    // SAFETY: the dialog is alive; an identifier with no control answers null.
    let direct = unsafe { GetDlgItem(dialog, i32::from(id)) };
    if !direct.is_null() || id == CONTENT {
        return direct;
    }
    // SAFETY: as above.
    let content = unsafe { GetDlgItem(dialog, i32::from(CONTENT)) };
    // SAFETY: as above; a null parent answers null.
    unsafe { GetDlgItem(content, i32::from(id)) }
}

fn identifier(window: HWND) -> u16 {
    // SAFETY: a window that is no control answers zero.
    u16::try_from(unsafe { GetDlgCtrlID(window) }).unwrap_or_default()
}

fn redraw(window: HWND) {
    // SAFETY: a null rectangle asks for the whole window; a window that is
    // gone refuses.
    unsafe { InvalidateRect(window, std::ptr::null(), 1) };
}

/// An answer's fill changing to `to`, from `from`, since `since`; `None` once
/// it has.
#[derive(Debug, Clone, Copy)]
struct Fill {
    from: Rgb,
    to: Rgb,
    since: Option<Instant>,
}

impl Fill {
    fn now(&self, now: Instant) -> Rgb {
        self.since.map_or(self.to, |since| {
            let elapsed = u32::try_from(now.duration_since(since).as_millis()).unwrap_or(u32::MAX);
            motion::filled(self.from, self.to, elapsed)
        })
    }
}

/// The timer that steps an answer's fill, and how often: the menu's opening
/// steps on the same.
const FADE: usize = 1;
const FADE_EVERY: u32 = 16;
/// The subclass by which an answer sees the pointer come and go.
const POINTED: usize = 1;

/// The fill `button` shows now, becoming `to`: at once where Windows does not
/// animate, else over WinUI's time from whatever it shows, its timer running
/// until it is done.
fn fill(look: &mut Look, button: HWND, to: Rgb) -> Rgb {
    let now = Instant::now();
    let animated = look.motion == Motion::Animated;
    let key = button as isize;
    let Some(fill) = look
        .fills
        .iter_mut()
        .find(|(known, _)| *known == key)
        .map(|(_, fill)| fill)
    else {
        look.fills.push((
            key,
            Fill {
                from: to,
                to,
                since: None,
            },
        ));
        return to;
    };
    if fill.to != to {
        let shown = fill.now(now);
        *fill = Fill {
            from: shown,
            to,
            since: animated.then_some(now),
        };
        if animated {
            // SAFETY: the button is this thread's own; no procedure, so the
            // timer comes as a message to the button's subclass.
            unsafe { SetTimer(button, FADE, FADE_EVERY, None) };
        }
    }
    let shown = fill.now(now);
    if fill
        .since
        .is_some_and(|since| now.duration_since(since).as_millis() >= u128::from(motion::FILL))
    {
        fill.since = None;
        // SAFETY: as above; a timer that is not running is refused.
        unsafe { KillTimer(button, FADE) };
    }
    shown
}

/// An answer's own messages, before the button's: the pointer coming over it
/// and leaving, which Windows tells no owner-drawn button's parent
/// (measured: `BCN_HOTITEMCHANGE` never arrives), and its fill's timer.
unsafe extern "system" fn pointed(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _: usize,
    _: usize,
) -> LRESULT {
    match message {
        WM_MOUSEMOVE => {
            let id = identifier(window);
            let entered = looked_mut(window, |look| {
                let entered = look.hot != Some(id);
                look.hot = Some(id);
                entered
            });
            if entered == Some(true) {
                let mut leaving = TRACKMOUSEEVENT {
                    cbSize: size::<TRACKMOUSEEVENT>(),
                    dwFlags: TME_LEAVE,
                    hwndTrack: window,
                    dwHoverTime: 0,
                };
                // SAFETY: the structure is valid for the call and the window
                // this thread's own.
                unsafe { TrackMouseEvent(&raw mut leaving) };
                redraw(window);
            }
        }
        WM_MOUSELEAVE => {
            let id = identifier(window);
            let left = looked_mut(window, |look| {
                let left = look.hot == Some(id);
                if left {
                    look.hot = None;
                }
                left
            });
            if left == Some(true) {
                redraw(window);
            }
        }
        WM_TIMER if wparam == FADE => {
            redraw(window);
            return 0;
        }
        WM_NCDESTROY => {
            // SAFETY: the subclass is this module's, set on this window.
            unsafe { RemoveWindowSubclass(window, Some(pointed), POINTED) };
        }
        _ => {}
    }
    // SAFETY: the arguments are the ones Windows called this procedure with,
    // passed on unchanged.
    unsafe { DefSubclassProc(window, message, wparam, lparam) }
}

/// The picture of the button `draw` asks for, and its label on it.
fn button(look: &mut Look, draw: &DRAWITEMSTRUCT) {
    let Some(palette) = look.palette else {
        return;
    };
    let id = u16::try_from(draw.CtlID).unwrap_or_default();
    let Some((kind, layer)) = look.buttons.get(usize::from(id.saturating_sub(ANSWER))) else {
        return;
    };
    let beneath = match layer {
        Layer::Content => look.content,
        Layer::Answers => look.strip,
    };
    let state = if draw.itemState & ODS_DISABLED != 0 {
        State::Disabled
    } else if draw.itemState & ODS_SELECTED != 0 {
        State::Pressed
    } else if look.hot == Some(id) {
        State::Over
    } else {
        State::Rest
    };
    let mut face = palette.button(*kind, state, beneath);
    face.fill = fill(look, draw.hwndItem, face.fill);
    let focused = draw.itemState & ODS_FOCUS != 0 && draw.itemState & ODS_NOFOCUSRECT == 0;
    let area = draw.rcItem;
    let rings = pixels(RINGS, look.dpi);
    let border = line(1.0, look.dpi);
    let shape = Shape {
        width: usize::try_from(area.right - area.left).unwrap_or_default(),
        height: usize::try_from(area.bottom - area.top).unwrap_or_default(),
        inset: float(rings),
        radius: CORNER * scale(look.dpi),
        border: float(border),
        bottom: float(border),
        scale: scale(look.dpi),
    };
    let picture = paint::control(
        &shape,
        beneath,
        &face,
        focused.then(|| palette.focus(beneath)),
    );
    draw::blit(draw.hDC, area.left, area.top, &picture);

    // The label stands where WinUI's padding puts it: 5 above and 6 below.
    let inside = RECT {
        left: area.left + rings + border,
        top: area.top + rings + border + pixels(5.0, look.dpi),
        right: area.right - rings - border,
        bottom: area.bottom - rings - border - pixels(6.0, look.dpi),
    };
    let label = words(draw.hwndItem);
    let run = Run {
        style: Some(Type::Body),
        label: &label,
        setting: Setting::Centred,
        keys: if draw.itemState & ODS_NOACCEL == 0 {
            Keys::Shown
        } else {
            Keys::Hidden
        },
    };
    look.setter
        .set(draw.hDC, &inside, &run, face.ink, face.fill);
}

/// A control's own text, which is what a screen reader reads of it.
fn words(control: HWND) -> String {
    // SAFETY: no pointers; a window that is gone answers zero.
    let length = unsafe { GetWindowTextLengthW(control) };
    let mut text = vec![0u16; usize::try_from(length).unwrap_or_default() + 1];
    // SAFETY: the buffer is writable for the length given.
    let copied = unsafe {
        GetWindowTextW(
            control,
            text.as_mut_ptr(),
            i32::try_from(text.len()).unwrap_or_default(),
        )
    };
    text.truncate(usize::try_from(copied).unwrap_or_default());
    String::from_utf16_lossy(&text)
}

/// A line of the content, set on the content's layer in the ink its kind of
/// line takes.
fn written(look: &Look, draw: &DRAWITEMSTRUCT) {
    let id = u16::try_from(draw.CtlID).unwrap_or_default();
    let quiet = (NAME..FACT).contains(&id) || id == ALLOWS || id == BEHIND;
    let ink = if quiet { look.inks.1 } else { look.inks.0 };
    let style = match id {
        HEADING => Type::Subtitle,
        BEHIND => Type::Caption,
        _ if (NAME..FACT).contains(&id) => Type::Caption,
        _ => Type::Body,
    };
    look.content_brush.fill(draw.hDC, &draw.rcItem);
    let text = words(draw.hwndItem);
    let run = Run {
        style: Some(style),
        label: &text,
        setting: Setting::Wrapped,
        keys: Keys::Hidden,
    };
    look.setter
        .set(draw.hDC, &draw.rcItem, &run, ink, look.content);
}

/// The colours of what is typed: the box's own fill beneath it.
fn typed(look: &Look, dc: HDC) -> Option<isize> {
    let palette = look.palette?;
    let state = if look.typing {
        Input::Typing
    } else {
        Input::Rest
    };
    let face = palette.input(state, look.content);
    // SAFETY: the context is the one Windows handed the message with.
    unsafe { SetTextColor(dc, draw::colour(face.text)) };
    // SAFETY: as above.
    unsafe { SetBkColor(dc, draw::colour(face.fill)) };
    let brushes = look.boxes.as_ref()?;
    let brush = if look.typing {
        brushes.get(1)
    } else {
        brushes.first()
    };
    brush.map(|brush| brush.handle() as isize)
}

/// What is common to the dialog and its content: the messages Windows sends
/// whichever of them a control's parent is. `None` leaves the message to the
/// caller.
fn shared(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> Option<isize> {
    match message {
        WM_DRAWITEM => {
            // SAFETY: for this message the parameter points at the structure,
            // which lives for the call.
            let draw = unsafe { &*(lparam as *const DRAWITEMSTRUCT) };
            looked_mut(window, |look| {
                if draw.CtlType == ODT_STATIC {
                    written(look, draw);
                } else {
                    button(look, draw);
                }
            });
            Some(1)
        }
        WM_CTLCOLOREDIT => looked(window, |look| typed(look, wparam as HDC)).flatten(),
        _ => None,
    }
}

/// Moves the content by `by` pixels, within what there is to show.
fn scroll(content: HWND, by: i32) {
    let moved = looked_mut(content, |look| {
        let furthest = (look.arranged.extent - look.arranged.shown).max(0);
        let to = (look.scrolled + by).clamp(0, furthest);
        let moved = look.scrolled - to;
        look.scrolled = to;
        (moved != 0).then_some(moved)
    })
    .flatten();
    if let Some(moved) = moved {
        // SAFETY: the window is the card's content; null rectangles scroll
        // all of it, with its controls.
        unsafe {
            ScrollWindowEx(
                content,
                0,
                moved,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                SW_SCROLLCHILDREN | SW_INVALIDATE | SW_ERASE,
            )
        };
        // The line that ends the content does not move with it.
        redraw(content);
    }
}

/// The content's own background: its layer, the box for typing, the line
/// that ends it and, when there is more than is shown, where in it this is.
fn backdrop(look: &Look, content: HWND, dc: HDC) {
    let mut area = RECT::default();
    // SAFETY: the rectangle is a valid place for the window's client area.
    unsafe { GetClientRect(content, &raw mut area) };
    look.content_brush.fill(dc, &area);
    let rule = line(1.0, look.dpi);
    look.separator.fill(
        dc,
        &RECT {
            top: area.bottom - rule,
            ..area
        },
    );
    if let (Some(palette), Some(placed)) = (look.palette, look.arranged.place(Part::Typed)) {
        let state = if look.typing {
            Input::Typing
        } else {
            Input::Rest
        };
        let face = palette.input(state, look.content);
        let shape = Shape {
            width: usize::try_from(placed.rect.width).unwrap_or_default(),
            height: usize::try_from(placed.rect.height).unwrap_or_default(),
            inset: 0.0,
            radius: CORNER * scale(look.dpi),
            border: float(rule),
            bottom: float(if look.typing {
                line(2.0, look.dpi)
            } else {
                rule
            }),
            scale: scale(look.dpi),
        };
        let picture = paint::control(&shape, look.content, &face, None);
        draw::blit(
            dc,
            placed.rect.left,
            placed.rect.top - look.scrolled,
            &picture,
        );
    }
    if look.arranged.scrolls() {
        // WinUI's panning indicator, its scroll bar at rest: 2 wide, 2 in
        // from the edge, never under 32 long (`ScrollBar_themeresources.xaml`
        // line 714), in `ControlStrongFillColorDefault`.
        let thin = line(2.0, look.dpi);
        let inset = pixels(2.0, look.dpi);
        let track = area.bottom - rule - 2 * inset;
        let shown = look.arranged.shown.max(1);
        let extent = look.arranged.extent.max(1);
        let long = (track * shown / extent).max(pixels(32.0, look.dpi).min(track));
        let furthest = (extent - shown).max(1);
        let top = inset + (track - long) * look.scrolled / furthest;
        let thumb = look
            .palette
            .map_or(look.quiet, |palette| palette.indicator(look.content));
        Brush::new(thumb).fill(
            dc,
            &RECT {
                left: area.right - inset - thin,
                top,
                right: area.right - inset,
                bottom: top + long,
            },
        );
    }
}

unsafe extern "system" fn content(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_ERASEBKGND => {
            looked(window, |look| backdrop(look, window, wparam as HDC));
            1
        }
        WM_COMMAND => {
            let code = u32::from(high(wparam));
            if low(wparam) == TYPED && matches!(code, EN_SETFOCUS | EN_KILLFOCUS) {
                looked_mut(window, |look| look.typing = code == EN_SETFOCUS);
                redraw(window);
            } else {
                // An answer in the content is the card's to hear of.
                // SAFETY: the content's parent is the card, alive for as long
                // as the content is.
                let card = unsafe { GetParent(window) };
                // SAFETY: the parameters are passed on unchanged.
                unsafe { SendMessageW(card, message, wparam, lparam) };
            }
            0
        }
        WM_MOUSEWHEEL => {
            // A notch of the wheel is 120; three lines of body text to each.
            let notches = i32::from(high(wparam).cast_signed()) / 120;
            let lines = looked(window, |look| pixels(60.0, look.dpi)).unwrap_or_default();
            scroll(window, -notches * lines);
            0
        }
        _ => match shared(window, message, wparam, lparam) {
            Some(answer) => answer,
            // SAFETY: the arguments are the ones Windows called this
            // procedure with, passed on unchanged.
            None => unsafe { DefWindowProcW(window, message, wparam, lparam) },
        },
    }
}

/// Turns every answer off. They are turned on again by [`Shown::arm`].
fn disarm(dialog: HWND) {
    let answers = looked(dialog, |look| look.buttons.len()).unwrap_or_default();
    for place in 0..answers {
        let answer = control(dialog, add(ANSWER, place));
        // SAFETY: the handle is a control of this dialog, or null.
        unsafe { EnableWindow(answer, 0) };
    }
}

/// ENTER: the answer that has the keyboard, or what was typed when the
/// keyboard is in the box and something is in it. Nothing otherwise.
fn entered(dialog: HWND) {
    // SAFETY: no arguments.
    let focus = unsafe { GetFocus() };
    let id = identifier(focus);
    let sends = looked(dialog, |look| look.sends).flatten();
    if id == TYPED {
        // SAFETY: the handle is the box for typing.
        let typed = unsafe { GetWindowTextLengthW(focus) };
        if let (Some(sends), true) = (sends, typed > 0) {
            // SAFETY: a control of this dialog, or null, which is not enabled.
            if unsafe { IsWindowEnabled(control(dialog, add(ANSWER, usize::from(sends)))) } != 0 {
                answered(dialog, sends);
            }
        }
    } else if (ANSWER..HEADING).contains(&id) {
        answered(dialog, id - ANSWER);
    }
}

unsafe extern "system" fn procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    let confirming = looked(window, |look| look.confirming).unwrap_or_default();
    // ESCAPE and the close box put a card aside, and cancel a confirmation.
    let aside = || {
        if confirming {
            host::tell(Told::Confirmed(None));
        } else {
            // SAFETY: the window is the dialog this procedure was called for.
            unsafe { ShowWindow(window, SW_HIDE) };
            host::tell(Told::Aside);
        }
    };
    match message {
        WM_COMMAND => {
            let id = low(wparam);
            if i32::from(id) == IDCANCEL {
                // What a card showed stays held.
                aside();
            } else if i32::from(id) == IDOK {
                entered(window);
            } else if (ANSWER..HEADING).contains(&id) {
                answered(window, id - ANSWER);
            }
            1
        }
        WM_CLOSE => {
            aside();
            1
        }
        WM_ACTIVATE => {
            // Brought forward by the keyboard, or by Windows when another
            // window closed: a key already on its way decides nothing. A
            // click on the card is the person's own act on it. A
            // confirmation was asked for, and is meant to have the keyboard.
            if u32::from(low(wparam)) == WA_ACTIVE && !confirming {
                disarm(window);
                host::tell(Told::Forward);
            }
            0
        }
        WM_CTLCOLORDLG => {
            looked(window, |look| look.strip_brush.handle() as isize).unwrap_or_default()
        }
        WM_DPICHANGED => {
            // On a monitor of another scale the card is made again.
            let known = looked(window, |look| look.dpi);
            if known != Some(u32::from(low(wparam))) {
                host::tell(Told::Settings);
            }
            1
        }
        WM_MOUSEWHEEL => {
            // SAFETY: the parameters are passed on unchanged.
            unsafe { SendMessageW(control(window, CONTENT), message, wparam, lparam) };
            1
        }
        WM_KEYDOWN => {
            let page = looked(window, |look| look.arranged.shown).unwrap_or_default();
            let by = match low(wparam) {
                VK_PRIOR => -page,
                VK_NEXT => page,
                VK_HOME => i32::MIN / 2,
                VK_END => i32::MAX / 2,
                _ => return 0,
            };
            scroll(control(window, CONTENT), by);
            1
        }
        // Everything else, the first message included, is left to the dialog
        // manager: answering it nothing keeps it from choosing a control to
        // focus or a default answer.
        _ => shared(window, message, wparam, lparam).unwrap_or(0),
    }
}

/// An empty dialog: its controls are made afterwards, in pixels.
fn template(title: &str) -> Vec<u32> {
    let mut units: Vec<u16> = Vec::new();
    for value in [STYLE, WS_EX_TOPMOST] {
        units.push(low(value as usize));
        units.push(high(value as usize));
    }
    // No controls, no place and no size; no menu, the dialog manager's class.
    units.extend([0, 0, 0, 0, 0, 0, 0]);
    units.extend(title.encode_utf16());
    units.push(0);
    units
        .chunks(2)
        .map(|pair| {
            let low = pair.first().copied().unwrap_or_default();
            let high = pair.get(1).copied().unwrap_or_default();
            u32::from(low) | (u32::from(high) << 16)
        })
        .collect()
}

fn register() -> io::Result<()> {
    let class = wide(PANE);
    let description = WNDCLASSEXW {
        cbSize: size::<WNDCLASSEXW>(),
        lpfnWndProc: Some(content),
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

/// A child of `parent`, of one of Windows' own classes or the content's.
fn child(parent: HWND, class: &str, text: &str, style: u32, id: u16, rect: Rect) -> HWND {
    let (class, text) = (wide(class), wide(text));
    let extended = if id == CONTENT {
        WS_EX_CONTROLPARENT
    } else {
        0
    };
    // SAFETY: both strings are NUL-terminated and copied by the call; the
    // parent is alive; a control's menu handle is its identifier.
    unsafe {
        CreateWindowExW(
            extended,
            class.as_ptr(),
            text.as_ptr(),
            WS_CHILD | WS_VISIBLE | style,
            rect.left,
            rect.top,
            rect.width,
            rect.height,
            parent,
            usize::from(id) as _,
            module(),
            std::ptr::null(),
        )
    }
}

/// Gives a control Windows draws itself the font of `style`.
fn fonted(window: HWND, look: &Look, style: Type) {
    // SAFETY: the font outlives every control of the card.
    unsafe { SendMessageW(window, WM_SETFONT, look.setter.font(style) as usize, 0) };
}

/// The monitor a rectangle is on, or the primary one: its scale and the area
/// its taskbar leaves.
fn monitor(near: Option<Rect>) -> (u32, Rect) {
    let near = near.unwrap_or_default();
    let at = RECT {
        left: near.left,
        top: near.top,
        right: near.right(),
        bottom: near.bottom(),
    };
    // SAFETY: the rectangle is valid for the call, which always answers a
    // monitor with this flag.
    let monitor = unsafe { MonitorFromRect(&raw const at, MONITOR_DEFAULTTOPRIMARY) };
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
    let work = info.rcWork;
    (
        across,
        Rect {
            left: work.left,
            top: work.top,
            width: work.right - work.left,
            height: work.bottom - work.top,
        },
    )
}

/// The size of the window whose client area is `width` by `height`.
fn framed(width: i32, height: i32, dpi: u32) -> Size {
    let mut frame = RECT {
        left: 0,
        top: 0,
        right: width,
        bottom: height,
    };
    // SAFETY: the rectangle is valid for the call; the card has no menu.
    unsafe { AdjustWindowRectExForDpi(&raw mut frame, STYLE, 0, WS_EX_TOPMOST, dpi) };
    Size {
        width: frame.right - frame.left,
        height: frame.bottom - frame.top,
    }
}

/// A button's window: the button and the room its focus rings take.
fn ringed(rect: Rect, dpi: u32) -> Rect {
    let rings = pixels(RINGS, dpi);
    Rect {
        left: rect.left - rings,
        top: rect.top - rings,
        width: rect.width + 2 * rings,
        height: rect.height + 2 * rings,
    }
}

impl Look {
    fn new(card: &Card, appearance: &Appearance, dpi: u32, tallest: i32) -> Look {
        // Under a contrast theme Windows draws the answers, so GDI, which
        // they draw with, measures and sets every line.
        let painted = matches!(appearance.colours, Colours::Theme { .. });
        let setter = Setter::new(dpi, appearance.text, Backing::Opaque, painted);
        let arranged = arrange(card, &setter, Space { dpi, tallest });
        let (palette, content, strip, inks, quiet, separator) = match appearance.colours {
            Colours::Theme { mode, accent } => {
                let palette = Palette::new(mode, accent);
                let content = palette.content();
                (
                    Some(palette),
                    content,
                    palette.strip(),
                    palette.inks(),
                    palette.quiet(content),
                    palette.separator(),
                )
            }
            // One pair of the system's colours for everything that is not a
            // control, and the text's colour for the line.
            Colours::System(system) => {
                let text = Tint {
                    colour: system.window_text,
                    alpha: u8::MAX,
                };
                (
                    None,
                    system.window,
                    system.window,
                    (text, text),
                    system.window_text,
                    system.window_text,
                )
            }
        };
        let layer = |place: usize| {
            arranged
                .place(Part::Choice(place))
                .map_or(Layer::Answers, |placed| placed.layer)
        };
        let buttons = card
            .choices
            .iter()
            .enumerate()
            .map(|(place, choice)| {
                let kind = if choice.weight == Weight::Usual {
                    Kind::Accent
                } else {
                    Kind::Standard
                };
                (kind, layer(place))
            })
            .collect();
        let place = |does: fn(&Does) -> bool| {
            card.choices
                .iter()
                .position(|choice| does(&choice.does))
                .and_then(|place| u16::try_from(place).ok())
        };
        let sends = place(|does| matches!(does, Does::Typed(_)));
        let cancels = place(|does| matches!(does, Does::Cancel));
        Look {
            dpi,
            motion: appearance.motion,
            fills: Vec::new(),
            setter,
            palette,
            content,
            strip,
            inks,
            quiet,
            separator: Brush::new(separator),
            content_brush: Brush::new(content),
            strip_brush: Brush::new(strip),
            boxes: palette.map(|palette| {
                [Input::Rest, Input::Typing]
                    .map(|state| Brush::new(palette.input(state, content).fill))
            }),
            arranged,
            buttons,
            sends,
            hot: None,
            typing: false,
            scrolled: 0,
            confirming: card.subject == Subject::Confirming,
            cancels,
        }
    }
}

/// The box an answer is typed in: inside the box Hedwig draws, or the one
/// Windows draws under a contrast theme.
fn typed_box(holder: HWND, look: &Look, placed: &Placed) {
    let rule = line(1.0, look.dpi);
    let painted = look.palette.is_some();
    // The box is Windows' own edit control, which sets its text with GDI.
    let tall = look.setter.gdi().text(Type::Body, "Ag", None).height;
    // Inside the box Hedwig draws, where WinUI's padding puts text;
    // under a contrast theme, the box Windows draws.
    let rect = if painted {
        Rect {
            left: placed.rect.left + rule + pixels(BOX_LEFT, look.dpi),
            top: placed.rect.top + (placed.rect.height - tall) / 2,
            width: placed.rect.width
                - 2 * rule
                - pixels(BOX_LEFT, look.dpi)
                - pixels(BOX_RIGHT, look.dpi),
            height: tall,
        }
    } else {
        placed.rect
    };
    let border = if painted { 0 } else { WS_BORDER };
    let style = WS_TABSTOP | border | (ES_PASSWORD | ES_AUTOHSCROLL).cast_unsigned();
    fonted(
        child(holder, "EDIT", "", style, TYPED, rect),
        look,
        Type::Body,
    );
}

/// A card on the screen, or ready to be.
#[derive(Debug)]
pub struct Shown {
    window: HWND,
    answers: usize,
    /// What says each line is text, and the lines it said it of.
    annotations: Option<Annotations>,
    lines: Vec<HWND>,
    /// The executable's icon in the card's title bar, held while the card is.
    named: Option<Named>,
}

impl Shown {
    /// Makes the card's window, unshown, with every answer disabled, where
    /// [`Shown::raise`] will show it: at the corner of the work area nearest
    /// `near` - the notification-area icon, or the card this one replaces -
    /// on the monitor that is on.
    ///
    /// # Errors
    ///
    /// Windows refused the window or one of its controls.
    pub fn new(
        title: &str,
        card: &Card,
        appearance: &Appearance,
        near: Option<(i32, i32, i32, i32)>,
    ) -> io::Result<Shown> {
        register()?;
        let near = near.map(|(left, top, right, bottom)| Rect {
            left,
            top,
            width: right - left,
            height: bottom - top,
        });
        let (dpi, work) = monitor(near);
        let margin = pixels(MARGIN, dpi);
        let chrome = framed(0, 0, dpi).height;
        let look = Look::new(card, appearance, dpi, work.height - 2 * margin - chrome);

        let template = template(title);
        // SAFETY: the template is complete, aligned for `DLGTEMPLATE` and
        // alive for the call, which copies what it needs; the procedure lives
        // as long as the process.
        let window = unsafe {
            CreateDialogIndirectParamW(
                module(),
                template.as_ptr().cast::<DLGTEMPLATE>(),
                std::ptr::null_mut(),
                Some(procedure),
                0,
            )
        };
        if window.is_null() {
            return Err(io::Error::last_os_error());
        }
        // The card is laid out here, in pixels: Windows' own scaling of a
        // dialog would undo it.
        // SAFETY: the dialog is this thread's own.
        unsafe { SetDialogDpiChangeBehavior(window, DDC_DISABLE_ALL, DDC_DISABLE_ALL) };
        let mut shown = Shown {
            window,
            answers: card.choices.len(),
            annotations: Annotations::new(),
            lines: Vec::new(),
            named: None,
        };
        shown.frame(&look);
        let outer = framed(look.arranged.width, look.arranged.height(), dpi);
        let (left, top) = if look.confirming {
            arrange::middle(work, outer)
        } else {
            arrange::corner(work, near, outer, margin)
        };
        // SAFETY: the window is this value's own; no pointer is passed.
        unsafe {
            SetWindowPos(
                window,
                std::ptr::null_mut(),
                left,
                top,
                outer.width,
                outer.height,
                SWP_NOACTIVATE | SWP_NOZORDER,
            )
        };
        // On its monitor, so the icon is drawn at that monitor's size; a
        // dialog has none of its own, and Windows would show its generic one.
        shown.named = Some(crate::window::name(
            window as isize,
            hedwig_view::resource::ICON,
        ));
        shown.fill(card, &look)?;
        shown.cues();
        LOOKS.with_borrow_mut(|looks| looks.push((window as isize, look)));
        host::dialog(window, true);
        Ok(shown)
    }

    /// The frame Windows draws: rounded, in the person's mode, its title bar
    /// one with the content beneath it, and no material behind the card.
    fn frame(&self, look: &Look) {
        let Some(palette) = look.palette else {
            return;
        };
        let attributes = [
            (
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                u32::from(palette.mode() == Mode::Dark),
            ),
            (DWMWA_CAPTION_COLOR, draw::colour(look.content)),
            (DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND.cast_unsigned()),
            (DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_NONE.cast_unsigned()),
        ];
        for (attribute, value) in attributes {
            // SAFETY: each attribute takes one 32-bit value, which outlives
            // the call; a Windows that does not know one refuses it.
            unsafe {
                DwmSetWindowAttribute(
                    self.window,
                    attribute.cast_unsigned(),
                    (&raw const value).cast(),
                    4,
                )
            };
        }
    }

    /// Nobody's key press brought the card up, so it begins with no access
    /// key underlined and no focus visual, unless the person has Windows
    /// underline access keys always. ALT, or a key that moves the keyboard,
    /// shows them from then on, as the dialog manager does for any dialog.
    fn cues(&self) {
        let mut always = 0i32;
        // SAFETY: the action writes one BOOL through the pointer given.
        unsafe { SystemParametersInfoW(SPI_GETKEYBOARDCUES, 0, (&raw mut always).cast(), 0) };
        if always == 0 {
            let hide = usize::try_from(UIS_SET | ((UISF_HIDEACCEL | UISF_HIDEFOCUS) << 16))
                .unwrap_or_default();
            // SAFETY: the window is this value's own; the message carries no
            // pointer.
            unsafe { SendMessageW(self.window, WM_CHANGEUISTATE, hide, 0) };
        }
    }

    /// Makes the card's controls where the arrangement puts them, in the
    /// order the keyboard reaches them.
    fn fill(&mut self, card: &Card, look: &Look) -> io::Result<()> {
        let arranged = &look.arranged;
        let pane = Rect {
            left: 0,
            top: 0,
            width: arranged.width,
            height: arranged.shown,
        };
        let content = |parent| child(parent, PANE, "", WS_CLIPCHILDREN, CONTENT, pane);
        // What is typed comes before the answers; otherwise the answers
        // come before what the content holds.
        let mut holder = if card.typed {
            content(self.window)
        } else {
            std::ptr::null_mut()
        };
        let labels = keyed(card.choices.iter().map(|choice| choice.label.as_str()));
        let answer = |parent: HWND, placed: &Placed, place: usize, top: i32| {
            let style = match look.palette {
                Some(_) => BS_OWNERDRAW.cast_unsigned(),
                None => (BS_PUSHBUTTON | BS_MULTILINE).cast_unsigned(),
            };
            let mut rect = ringed(placed.rect, look.dpi);
            rect.top += top;
            // A card's answers are off until it has settled.
            let off = if look.confirming { 0 } else { WS_DISABLED };
            let button = child(
                parent,
                "BUTTON",
                labels.get(place).map_or("", String::as_str),
                WS_TABSTOP | off | style,
                add(ANSWER, place),
                rect,
            );
            fonted(button, look, Type::Body);
            if look.palette.is_some() {
                // SAFETY: the button is this thread's own, the procedure this
                // module's; it is taken out as the button goes.
                unsafe { SetWindowSubclass(button, Some(pointed), POINTED, 0) };
            }
        };
        for place in &arranged.order {
            let Some(placed) = arranged.place(Part::Choice(*place)) else {
                continue;
            };
            if placed.layer == Layer::Answers {
                answer(self.window, placed, *place, arranged.shown);
            }
        }
        if holder.is_null() {
            holder = content(self.window);
        }
        if holder.is_null() {
            return Err(io::Error::last_os_error());
        }
        // A card is not given the keyboard, so nothing announces it; its
        // content says it is an alert, named by its question, which
        // `Shown::announce` raises. A confirmation has the keyboard.
        if let (Some(annotations), false) = (&self.annotations, look.confirming) {
            annotations.named(holder, ROLE_SYSTEM_ALERT, &card.heading);
            self.lines.push(holder);
        }
        for placed in &arranged.parts {
            let (id, text) = match placed.part {
                Part::Heading => (HEADING, card.heading.clone()),
                Part::Says => (SAYS, card.says.clone().unwrap_or_default()),
                Part::Name(at) => (
                    add(NAME, at),
                    card.facts.get(at).map_or("", |fact| fact.0).to_owned(),
                ),
                Part::Fact(at) => (
                    add(FACT, at),
                    card.facts.get(at).map_or("", |fact| &fact.1).to_owned(),
                ),
                Part::Allows => (ALLOWS, card.allows.clone().unwrap_or_default()),
                Part::Waiting => (BEHIND, card.waiting().unwrap_or_default()),
                Part::Typed | Part::Choice(_) => continue,
            };
            let line = child(
                holder,
                "STATIC",
                &text,
                SS_OWNERDRAW | SS_NOPREFIX,
                id,
                placed.rect,
            );
            // An owner-drawn static control says it is a picture.
            if let Some(annotations) = &self.annotations {
                annotations.mark(line, ROLE_SYSTEM_STATICTEXT, None, None);
                self.lines.push(line);
            }
        }
        if let Some(placed) = arranged.place(Part::Typed) {
            typed_box(holder, look, placed);
        }
        for place in &arranged.order {
            let Some(placed) = arranged.place(Part::Choice(*place)) else {
                continue;
            };
            if placed.layer == Layer::Content {
                answer(holder, placed, *place, 0);
            }
        }
        Ok(())
    }

    /// The window's handle, for whatever must name the window to Windows.
    pub fn window(&self) -> *mut core::ffi::c_void {
        self.window
    }

    /// One of the card's controls by its identifier, or null.
    pub fn control(&self, id: u16) -> *mut core::ffi::c_void {
        control(self.window, id)
    }

    /// Where each part of the card is, as it was arranged for the monitor
    /// it is on.
    pub fn arrangement(&self) -> Option<Arranged> {
        looked(self.window, |look| look.arranged.clone())
    }

    /// Where the card is on the screen, for the card that replaces it.
    pub fn place(&self) -> Option<(i32, i32, i32, i32)> {
        let mut place = RECT::default();
        // SAFETY: the window is this value's own, and `place` a valid place.
        let found = unsafe { GetWindowRect(self.window, &raw mut place) };
        (found != 0).then_some((place.left, place.top, place.right, place.bottom))
    }

    /// Shows the card where it was made, above other windows, without giving
    /// it the focus.
    pub fn raise(&self) -> io::Result<()> {
        let Some((left, top, right, bottom)) = self.place() else {
            return Err(io::Error::last_os_error());
        };
        let flags = SWP_NOACTIVATE | SWP_SHOWWINDOW;
        // SAFETY: the window is this value's own; no pointer is passed.
        let placed = unsafe {
            SetWindowPos(
                self.window,
                HWND_TOPMOST,
                left,
                top,
                right - left,
                bottom - top,
                flags,
            )
        };
        if placed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Tells assistive technology that the card has come up: an alert from
    /// its content, which says it is one and is named by the question. A
    /// screen reader that takes alerts from a topmost window speaks it
    /// without the card being given the keyboard, whatever notifications the
    /// person holds back.
    pub fn announce(&self) {
        let content = self.control(CONTENT);
        if !content.is_null() {
            // SAFETY: the window is this card's own content; no pointer.
            unsafe {
                NotifyWinEvent(
                    EVENT_SYSTEM_ALERT,
                    content,
                    OBJID_CLIENT,
                    CHILDID_SELF.cast_signed(),
                );
            };
        }
    }

    /// Brings the card forward with the keyboard, because the person asked
    /// for it from the icon: the one time it takes the foreground. Its
    /// answers go off until it has settled, as when Windows brings it
    /// forward.
    pub fn bring(&self) {
        // SAFETY: the window is this value's own; no pointer is passed.
        unsafe {
            SetWindowPos(
                self.window,
                HWND_TOPMOST,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
            )
        };
        // SAFETY: as above; the shell lets the icon's process take the
        // foreground on the person's act.
        unsafe { SetForegroundWindow(self.window) };
    }

    /// Puts a confirmation to the person: shown where it was made, above
    /// other windows, in the foreground, the keyboard on its safe answer. The
    /// person has just chosen the act it confirms, so the shell lets the
    /// icon's process take the foreground.
    pub fn ask(&self) {
        self.bring();
        let safe = looked(self.window, |look| look.cancels)
            .flatten()
            .map(|place| control(self.window, add(ANSWER, usize::from(place))))
            .filter(|answer| !answer.is_null());
        if let Some(safe) = safe {
            // The dialog manager's own way to give a control the keyboard,
            // so its idea of the default answer follows.
            // SAFETY: the dialog and the control are this thread's own.
            unsafe { SendMessageW(self.window, WM_NEXTDLGCTL, safe as usize, 1) };
        }
    }

    /// What the person typed, taken out of the box and erased there: the box
    /// is filled with as many characters and then emptied, so its buffer does
    /// not keep the answer. `None` where the card has no box.
    pub fn take_typed(&self) -> Option<String> {
        let typed = self.control(TYPED);
        if typed.is_null() {
            return None;
        }
        // SAFETY: no pointers; the box is alive for as long as the card is.
        let length = unsafe { GetWindowTextLengthW(typed) };
        let mut units = Zeroizing::new(vec![0u16; usize::try_from(length).unwrap_or_default() + 1]);
        // SAFETY: the buffer is writable for the length given.
        let copied = unsafe {
            GetWindowTextW(
                typed,
                units.as_mut_ptr(),
                i32::try_from(units.len()).unwrap_or_default(),
            )
        };
        let words = units.get(..usize::try_from(copied).unwrap_or_default())?;
        let text = String::from_utf16(words).ok();
        let filler = Zeroizing::new(
            vec![u16::from(b'x'); words.len()]
                .into_iter()
                .chain([0])
                .collect::<Vec<u16>>(),
        );
        // SAFETY: both texts are NUL-terminated and copied by the calls.
        unsafe { SetWindowTextW(typed, filler.as_ptr()) };
        let empty = [0u16];
        // SAFETY: as above.
        unsafe { SetWindowTextW(typed, empty.as_ptr()) };
        text
    }

    /// Lets the answers be taken, or stops them being.
    pub fn arm(&self, armed: bool) {
        for place in 0..self.answers {
            let answer = control(self.window, add(ANSWER, place));
            // SAFETY: the handle is a control of this dialog, or null.
            unsafe { EnableWindow(answer, i32::from(armed)) };
        }
    }
}

impl Drop for Shown {
    fn drop(&mut self) {
        if let Some(annotations) = &self.annotations {
            for line in &self.lines {
                annotations.clear(*line);
            }
        }
        host::dialog(self.window, false);
        // SAFETY: the window is this value's own and nothing uses it after.
        unsafe { DestroyWindow(self.window) };
        // Its fonts and brushes go once no control names them.
        let window = self.window as isize;
        LOOKS.with_borrow_mut(|looks| looks.retain(|(known, _)| *known != window));
    }
}
