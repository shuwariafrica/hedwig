//! What the person has set in Windows that a painted surface answers to.
//!
//! The mode, the accent's shades, the text size and transparency effects are
//! documented through one class, the Windows Runtime's `UISettings`, and
//! through nothing in Win32. `windows-sys` declares no Windows Runtime
//! activation, so the three calls and the three interfaces it takes are
//! declared here against Microsoft's own headers; nothing else of the Windows
//! Runtime is used. The contrast theme, its colours, the animation setting, a
//! Remote Desktop session and energy saver are Win32's own and are read there.
//!
//! [`read`] is asked each time a surface is about to be shown. While one is
//! on the screen a [`Watch`] has the host told of every signal Windows gives
//! that a setting may have changed, and the surface reads again.

use std::ffi::c_void;
use std::io;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Graphics::Gdi::{
    COLOR_3DFACE, COLOR_BTNTEXT, COLOR_GRAYTEXT, COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT,
    COLOR_HOTLIGHT, COLOR_WINDOW, COLOR_WINDOWTEXT, GetSysColor, SYS_COLOR_INDEX,
};
use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use windows_sys::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, PostMessageW, SM_REMOTESESSION, SPI_GETCLIENTAREAANIMATION,
    SPI_GETHIGHCONTRAST, SystemParametersInfoW,
};
use windows_sys::core::{GUID, HRESULT, HSTRING, IID_IUnknown, IInspectable_Vtbl, IUnknown_Vtbl};

use hedwig_view::emblem::Ink;
use hedwig_view::style::{
    Accent, Appearance, Backdrop, Colours, Mode, Motion, Rgb, Shade, System, TextScale,
};

use crate::host::{CHANGED, Host};
use crate::raw::{size, wide};

// The Windows Runtime's activation and its strings, in the library Windows
// itself resolves them from.
#[link(name = "combase.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    #[link_name = "RoActivateInstance"]
    fn activate_instance(class: HSTRING, instance: *mut *mut c_void) -> HRESULT;
    #[link_name = "WindowsCreateString"]
    fn create_string(source: *const u16, length: u32, string: *mut HSTRING) -> HRESULT;
    #[link_name = "WindowsDeleteString"]
    fn delete_string(string: HSTRING) -> HRESULT;
}

const CLASS: &str = "Windows.UI.ViewManagement.UISettings";
/// `IUISettings2`: the text size and the event that says it changed.
const SETTINGS_2: GUID = GUID::from_u128(0xbad8_2401_2721_44f9_bb91_2bb2_28be_442f);
/// `IUISettings3`: a colour by its `UIColorType`, and the event for those.
const SETTINGS_3: GUID = GUID::from_u128(0x0302_1be4_5254_4781_8194_5168_f7d0_6d7b);
/// `IUISettings4`: whether the person has transparency effects on.
const SETTINGS_4: GUID = GUID::from_u128(0x52bb_3002_919b_4d6b_9b78_8dd6_6ff4_b93b);
/// `TypedEventHandler<UISettings, Object>`, the handler both events take
/// (`windows.ui.viewmanagement.h`, Windows SDK 10.0.28000.0).
const HANDLER: GUID = GUID::from_u128(0x2dbd_ba9d_20da_519d_9078_09f8_35bc_5bc7);
/// `IAgileObject`: the handler may be called on whichever thread raises.
const AGILE: GUID = GUID::from_u128(0x94ea_2b94_e9cc_49e0_c0ff_ee64_ca8f_5b90);
const NO_INTERFACE: HRESULT = 0x8000_4002_u32.cast_signed();
/// `UIColorType.Foreground`.
const FOREGROUND: i32 = 1;

type Method<Arguments> = unsafe extern "system" fn(*mut c_void, Arguments) -> HRESULT;
type Subscribe = unsafe extern "system" fn(*mut c_void, *const Listener, *mut i64) -> HRESULT;

/// `Windows.UI.Color`.
#[repr(C)]
#[derive(Default)]
struct Color {
    alpha: u8,
    red: u8,
    green: u8,
    blue: u8,
}

#[repr(C)]
struct Settings2 {
    base: IInspectable_Vtbl,
    text_scale_factor: Method<*mut f64>,
    text_scale_changed: Subscribe,
    remove_text_scale_changed: Method<i64>,
}

#[repr(C)]
struct Settings3 {
    base: IInspectable_Vtbl,
    color_value: unsafe extern "system" fn(*mut c_void, i32, *mut Color) -> HRESULT,
    color_values_changed: Subscribe,
    remove_color_values_changed: Method<i64>,
}

#[repr(C)]
struct Settings4 {
    base: IInspectable_Vtbl,
    advanced_effects_enabled: Method<*mut u8>,
}

fn check(result: HRESULT) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::from_raw_os_error(result))
    } else {
        Ok(())
    }
}

/// One reference to a COM object, let go when this is dropped.
struct Object(NonNull<c_void>);

impl Object {
    fn taken(pointer: *mut c_void) -> io::Result<Object> {
        NonNull::new(pointer)
            .map(Object)
            .ok_or_else(|| io::Error::other("Windows answered success and gave no object"))
    }

    /// The object's table of methods, read as `T`.
    ///
    /// # Safety
    ///
    /// This reference is to the interface whose table `T` lays out, or to one
    /// that begins with it.
    unsafe fn table<T>(&self) -> &T {
        // SAFETY: a COM interface pointer points at a pointer to its table.
        let table = unsafe { *self.0.as_ptr().cast::<*const T>() };
        // SAFETY: the table lives as long as the object, which this reference
        // keeps alive; the caller vouches for its layout.
        unsafe { &*table }
    }

    fn query(&self, interface: &GUID) -> io::Result<Object> {
        let mut found = std::ptr::null_mut();
        // SAFETY: every COM interface begins with `IUnknown`'s three methods.
        let unknown = unsafe { self.table::<IUnknown_Vtbl>() };
        // SAFETY: the object is alive, and both pointers are valid for the
        // call.
        let answered =
            unsafe { (unknown.QueryInterface)(self.0.as_ptr(), interface, &raw mut found) };
        check(answered)?;
        Object::taken(found)
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: as in `query`.
        let unknown = unsafe { self.table::<IUnknown_Vtbl>() };
        // SAFETY: this reference is counted once and is not used afterwards.
        unsafe { (unknown.Release)(self.0.as_ptr()) };
    }
}

/// An instance of `UISettings`.
fn settings() -> io::Result<Object> {
    let name: Vec<u16> = CLASS.encode_utf16().collect();
    let length = u32::try_from(name.len()).unwrap_or_default();
    let mut class: HSTRING = std::ptr::null_mut();
    // SAFETY: `name` holds `length` units and outlives the call, which copies
    // them into a string of its own.
    check(unsafe { create_string(name.as_ptr(), length, &raw mut class) })?;
    let mut instance = std::ptr::null_mut();
    // SAFETY: the class name was just made, and `instance` is a valid place
    // for the object.
    let activated = unsafe { activate_instance(class, &raw mut instance) };
    // SAFETY: the string was made above and nothing uses it afterwards.
    unsafe { delete_string(class) };
    check(activated)?;
    Object::taken(instance)
}

/// What only the Windows Runtime answers: the person's mode, their accent as
/// that mode draws it, and their text size.
///
/// # Errors
///
/// The class could not be activated on this thread, or refused a value.
pub fn theme() -> io::Result<(Mode, Accent, TextScale)> {
    let settings = settings()?;
    let colours = settings.query(&SETTINGS_3)?;
    // SAFETY: the reference was asked for as `IUISettings3`.
    let table = unsafe { colours.table::<Settings3>() };
    let colour = |kind: i32| {
        let mut value = Color::default();
        // SAFETY: the object is alive and `value` a valid place for a colour.
        check(unsafe { (table.color_value)(colours.0.as_ptr(), kind, &raw mut value) })?;
        Ok::<Rgb, io::Error>(Rgb::new(value.red, value.green, value.blue))
    };
    let mode = Mode::of(colour(FOREGROUND)?);
    let shade = |shade: Shade| colour(shade as i32);
    let accent = Accent {
        fill: shade(mode.fill())?,
        text: shade(mode.text())?,
    };
    let sizes = settings.query(&SETTINGS_2)?;
    // SAFETY: the reference was asked for as `IUISettings2`.
    let table = unsafe { sizes.table::<Settings2>() };
    let mut factor = 1.0f64;
    // SAFETY: the object is alive and `factor` a valid place for the value.
    check(unsafe { (table.text_scale_factor)(sizes.0.as_ptr(), &raw mut factor) })?;
    Ok((mode, accent, TextScale::new(factor)))
}

fn system_colour(index: SYS_COLOR_INDEX) -> Rgb {
    // SAFETY: no pointers; an index Windows does not know answers zero.
    let [red, green, blue, _] = unsafe { GetSysColor(index) }.to_le_bytes();
    Rgb::new(red, green, blue)
}

/// The system's eight colours, which are the person's own under a contrast
/// theme.
pub fn system() -> System {
    System {
        window: system_colour(COLOR_WINDOW),
        window_text: system_colour(COLOR_WINDOWTEXT),
        button_face: system_colour(COLOR_3DFACE),
        button_text: system_colour(COLOR_BTNTEXT),
        highlight: system_colour(COLOR_HIGHLIGHT),
        highlight_text: system_colour(COLOR_HIGHLIGHTTEXT),
        gray_text: system_colour(COLOR_GRAYTEXT),
        hot_light: system_colour(COLOR_HOTLIGHT),
    }
}

/// Whether a contrast theme is on.
pub fn contrast() -> bool {
    let mut state = HIGHCONTRASTW {
        cbSize: size::<HIGHCONTRASTW>(),
        dwFlags: 0,
        lpszDefaultScheme: std::ptr::null_mut(),
    };
    // SAFETY: the structure states its size and is written through the
    // pointer given.
    let asked = unsafe {
        SystemParametersInfoW(
            SPI_GETHIGHCONTRAST,
            state.cbSize,
            (&raw mut state).cast(),
            0,
        )
    };
    asked != 0 && state.dwFlags & HCF_HIGHCONTRASTON != 0
}

/// The mode Windows draws its own surfaces in - the taskbar, and the
/// notification area on it - which the person sets apart from the mode for
/// applications: `SystemUsesLightTheme` (Microsoft's reference for Windows 11
/// settings, "Personalization - colors"). `None` where it cannot be read.
pub fn taskbar() -> Option<Mode> {
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
    let name = wide("SystemUsesLightTheme");
    let mut value = 0_u32;
    let mut length = size::<u32>();
    // SAFETY: both names are NUL-terminated and the value a place of the
    // length given; only a DWORD is accepted.
    let read = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    (read == 0).then_some(if value == 0 { Mode::Dark } else { Mode::Light })
}

/// What the notification-area icon is drawn in: a contrast theme's colours
/// where one is on, else the logo's for the taskbar's mode - the
/// applications' mode where that cannot be read.
pub fn ink() -> Ink {
    if contrast() {
        return Ink::System(system());
    }
    let mode = taskbar()
        .or_else(|| theme().ok().map(|(mode, _, _)| mode))
        .unwrap_or(Mode::Dark);
    Ink::Taskbar(mode)
}

/// Whether the person has Windows animate what it shows.
pub fn motion() -> Motion {
    let mut animated = 1i32;
    // SAFETY: the action writes one BOOL through the pointer given.
    let asked = unsafe {
        SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, (&raw mut animated).cast(), 0)
    };
    if asked != 0 && animated == 0 {
        Motion::Still
    } else {
        Motion::Animated
    }
}

fn transparency() -> io::Result<bool> {
    let settings = settings()?;
    let effects = settings.query(&SETTINGS_4)?;
    // SAFETY: the reference was asked for as `IUISettings4`.
    let table = unsafe { effects.table::<Settings4>() };
    let mut on = 0u8;
    // SAFETY: the object is alive and `on` a valid place for the boolean.
    check(unsafe { (table.advanced_effects_enabled)(effects.0.as_ptr(), &raw mut on) })?;
    Ok(on != 0)
}

/// Whether Windows composes acrylic behind a transient surface now: not in a
/// Remote Desktop session, not with the person's transparency effects off,
/// and not under energy saver - the conditions under which WinUI's own
/// materials fall back. Where the Windows Runtime does not answer, the
/// surface is filled as if they were off.
pub fn backdrop() -> Backdrop {
    // SAFETY: no pointers.
    let remote = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;
    let mut power = SYSTEM_POWER_STATUS::default();
    // SAFETY: the structure is written through the pointer given.
    let saving =
        unsafe { GetSystemPowerStatus(&raw mut power) } != 0 && power.SystemStatusFlag & 1 != 0;
    if remote || saving || !transparency().unwrap_or(false) {
        Backdrop::Solid
    } else {
        Backdrop::Acrylic
    }
}

/// What the person has set, as it is now.
///
/// Under a contrast theme the colours are the system's eight and nothing
/// else. They are also what a surface is painted in when the Windows Runtime
/// does not answer: those are colours Windows always has, each with its pair,
/// so the surface is legible whatever went wrong, and the text is then the
/// size Windows ships.
pub fn read() -> Appearance {
    let asked = theme();
    let text = asked
        .as_ref()
        .map_or(TextScale::DEFAULT, |(_, _, text)| *text);
    let colours = match asked {
        Ok((mode, accent, _)) if !contrast() => Colours::Theme { mode, accent },
        _ => Colours::System(system()),
    };
    Appearance {
        colours,
        text,
        motion: motion(),
        backdrop: backdrop(),
    }
}

/// The window a change is posted to, for the one handler below.
static TOLD: AtomicIsize = AtomicIsize::new(0);

#[repr(C)]
struct ListenerTable {
    base: IUnknown_Vtbl,
    invoke: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) -> HRESULT,
}

/// The object Windows calls when a setting changes. There is one, it lives as
/// long as the process and holds nothing, so a call that arrives after a
/// [`Watch`] has gone reaches an object that is still there.
#[repr(C)]
struct Listener {
    table: &'static ListenerTable,
}

static LISTENER: Listener = Listener {
    table: &ListenerTable {
        base: IUnknown_Vtbl {
            QueryInterface: listener_query,
            AddRef: listener_counted,
            Release: listener_counted,
        },
        invoke: listener_invoke,
    },
};

fn same(one: &GUID, other: &GUID) -> bool {
    (one.data1, one.data2, one.data3, one.data4)
        == (other.data1, other.data2, other.data3, other.data4)
}

unsafe extern "system" fn listener_query(
    this: *mut c_void,
    interface: *const GUID,
    found: *mut *mut c_void,
) -> HRESULT {
    // SAFETY: COM's contract gives a valid identifier for the call.
    let wanted = unsafe { &*interface };
    let known = [IID_IUnknown, AGILE, HANDLER]
        .iter()
        .any(|known| same(known, wanted));
    let (answer, result) = if known {
        (this, 0)
    } else {
        (std::ptr::null_mut(), NO_INTERFACE)
    };
    // SAFETY: COM's contract gives a valid place for the answer.
    unsafe { found.write(answer) };
    result
}

/// The listener is never freed, so its count is not kept.
unsafe extern "system" fn listener_counted(_: *mut c_void) -> u32 {
    1
}

unsafe extern "system" fn listener_invoke(
    _: *mut c_void,
    _: *mut c_void,
    _: *mut c_void,
) -> HRESULT {
    let window = TOLD.load(Ordering::Relaxed);
    if window != 0 {
        // SAFETY: posting carries no pointer, and a window that no longer
        // exists refuses the message.
        unsafe { PostMessageW(window as HWND, CHANGED, 0, 0) };
    }
    0
}

/// Has the host told, for as long as this lives, when the person changes
/// their mode, accent or text size. Windows' own broadcasts reach the host's
/// window without it; this adds the two events Microsoft documents for a
/// surface that is not WinUI.
pub struct Watch {
    sizes: Object,
    colours: Object,
    size_changed: i64,
    colours_changed: i64,
}

impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watch").finish_non_exhaustive()
    }
}

impl Watch {
    /// # Errors
    ///
    /// The class could not be activated on this thread, or refused a
    /// handler.
    pub fn new(host: &Host) -> io::Result<Watch> {
        TOLD.store(host.window() as isize, Ordering::Relaxed);
        let settings = settings()?;
        let sizes = settings.query(&SETTINGS_2)?;
        let colours = settings.query(&SETTINGS_3)?;
        let mut size_changed = 0i64;
        // SAFETY: the reference was asked for as `IUISettings2`.
        let table = unsafe { sizes.table::<Settings2>() };
        // SAFETY: the object is alive, the listener lives as long as the
        // process, and the token has a valid place.
        check(unsafe {
            (table.text_scale_changed)(sizes.0.as_ptr(), &raw const LISTENER, &raw mut size_changed)
        })?;
        let mut colours_changed = 0i64;
        // SAFETY: the reference was asked for as `IUISettings3`.
        let table = unsafe { colours.table::<Settings3>() };
        // SAFETY: as for the text size above.
        let subscribed = check(unsafe {
            (table.color_values_changed)(
                colours.0.as_ptr(),
                &raw const LISTENER,
                &raw mut colours_changed,
            )
        });
        let watch = Watch {
            sizes,
            colours,
            size_changed,
            // A token of zero is one Windows never gives; removing it is
            // refused and changes nothing.
            colours_changed,
        };
        subscribed.map(|()| watch)
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: the reference was asked for as `IUISettings2`.
        let table = unsafe { self.sizes.table::<Settings2>() };
        // SAFETY: the object is alive and the token is the one it gave.
        unsafe { (table.remove_text_scale_changed)(self.sizes.0.as_ptr(), self.size_changed) };
        // SAFETY: the reference was asked for as `IUISettings3`.
        let table = unsafe { self.colours.table::<Settings3>() };
        // SAFETY: as above.
        unsafe {
            (table.remove_color_values_changed)(self.colours.0.as_ptr(), self.colours_changed)
        };
    }
}
