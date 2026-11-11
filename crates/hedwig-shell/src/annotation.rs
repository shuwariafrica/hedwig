//! What a control is, said to assistive technology where Windows would say
//! otherwise: Active Accessibility's annotation service (`IAccPropServices`,
//! the Windows SDK's `um/oleacc.h`), called by the places of its table.
//!
//! A control Hedwig draws itself is one of Windows' own kinds - an
//! owner-drawn button or static - which Windows announces by its kind: a
//! push button, a graphic. The service lets its role, its default action and
//! its access key be what it is on the surface. A state that changes - a
//! remote's row with its menu open or closed - is answered when asked, by a
//! server of the service's own interface (`IAccPropServer`): a fixed state
//! would fix the focus with it.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows_sys::Win32::System::Variant::{VARIANT, VT_I4};
use windows_sys::Win32::UI::Accessibility::{
    ANNO_THIS, CLSID_AccPropServices, PROPID_ACC_DEFAULTACTION, PROPID_ACC_KEYBOARDSHORTCUT,
    PROPID_ACC_NAME, PROPID_ACC_ROLE, PROPID_ACC_STATE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{CHILDID_SELF, OBJID_CLIENT};
use windows_sys::core::BOOL;
use windows_sys::core::GUID;

use crate::com::{Com, Object};
use crate::raw::wide;

const IID_IACC_PROP_SERVICES: GUID = GUID::from_u128(0x6e26_e776_04f0_495d_80e4_3330_352e_3169);
const IID_IACC_PROP_SERVER: GUID = GUID::from_u128(0x76c0_dbbb_15e0_4e7b_b61b_20ee_ea20_01e0);
const IID_IUNKNOWN: GUID = GUID::from_u128(0x0000_0000_0000_0000_c000_0000_0000_0046);
const E_NOINTERFACE: i32 = 0x8000_4002_u32.cast_signed();

/// A window's state for assistive technology, worked out when asked.
pub(crate) type State = fn(HWND) -> u32;

/// `IAccPropServer`'s table: `IUnknown`'s three, then `GetPropValue`.
#[repr(C)]
struct Table {
    query: unsafe extern "system" fn(*mut Server, *const GUID, *mut *mut c_void) -> i32,
    add: unsafe extern "system" fn(*mut Server) -> u32,
    release: unsafe extern "system" fn(*mut Server) -> u32,
    value: unsafe extern "system" fn(
        *mut Server,
        *const u8,
        u32,
        GUID,
        *mut VARIANT,
        *mut BOOL,
    ) -> i32,
}

/// The server for one window's state: the service holds it while the window
/// is annotated, and lets it go when cleared.
#[repr(C)]
struct Server {
    table: &'static Table,
    count: AtomicU32,
    window: HWND,
    state: State,
}

static TABLE: Table = Table {
    query,
    add,
    release,
    value,
};

fn same(one: &GUID, other: &GUID) -> bool {
    (one.data1, one.data2, one.data3, one.data4)
        == (other.data1, other.data2, other.data3, other.data4)
}

unsafe extern "system" fn query(this: *mut Server, iid: *const GUID, out: *mut *mut c_void) -> i32 {
    // SAFETY: COM passes a live identifier.
    let iid = unsafe { &*iid };
    // SAFETY: COM passes a place to write the interface to.
    let out = unsafe { &mut *out };
    if same(iid, &IID_IUNKNOWN) || same(iid, &IID_IACC_PROP_SERVER) {
        // SAFETY: as above.
        unsafe { add(this) };
        *out = this.cast();
        0
    } else {
        *out = std::ptr::null_mut();
        E_NOINTERFACE
    }
}

unsafe extern "system" fn add(this: *mut Server) -> u32 {
    // SAFETY: COM passes a live object.
    unsafe { &*this }.count.fetch_add(1, Ordering::AcqRel) + 1
}

unsafe extern "system" fn release(this: *mut Server) -> u32 {
    // SAFETY: COM passes a live object.
    let left = unsafe { &*this }.count.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        // SAFETY: the last reference is gone; the object was made by
        // `Box::into_raw` in `Annotations::stated`.
        drop(unsafe { Box::from_raw(this) });
    }
    left
}

unsafe extern "system" fn value(
    this: *mut Server,
    _identity: *const u8,
    _length: u32,
    property: GUID,
    answer: *mut VARIANT,
    has: *mut BOOL,
) -> i32 {
    // SAFETY: COM passes a live object.
    let server = unsafe { &*this };
    // SAFETY: COM passes a place to write the value to.
    let answer = unsafe { &mut *answer };
    // SAFETY: COM passes a place to write whether there is one.
    let has = unsafe { &mut *has };
    if same(&property, &PROPID_ACC_STATE) {
        let mut state = VARIANT::default();
        state.Anonymous.Anonymous.vt = VT_I4;
        state.Anonymous.Anonymous.Anonymous.lVal =
            i32::try_from((server.state)(server.window)).unwrap_or_default();
        *answer = state;
        *has = 1;
    } else {
        *has = 0;
    }
    0
}

/// The annotation service, held while a surface that uses it is shown.
pub(crate) struct Annotations(Com);

impl std::fmt::Debug for Annotations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Annotations")
    }
}

impl Annotations {
    /// The service, or `None` where Windows does not give it: the controls
    /// then say what Windows says of them.
    pub(crate) fn new() -> Option<Annotations> {
        let mut props: Object = std::ptr::null_mut();
        // SAFETY: the identifiers are the service's own and the place valid;
        // the thread is in an apartment (`Host::new`).
        let made = unsafe {
            CoCreateInstance(
                &CLSID_AccPropServices,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_IACC_PROP_SERVICES,
                &raw mut props,
            )
        };
        if made < 0 {
            return None;
        }
        Com::new(props).map(Annotations)
    }

    /// Says what `window` is: its role, and where it has them, the default
    /// action and the access key. What cannot be set stays as Windows says.
    pub(crate) fn mark(&self, window: HWND, role: u32, action: Option<&str>, key: Option<char>) {
        self.said(window, role, None, action, key);
    }

    /// Says what `window` is, as `mark` does, and answers its state when
    /// asked with what `state` works out then.
    pub(crate) fn stated(
        &self,
        window: HWND,
        role: u32,
        action: Option<&str>,
        key: Option<char>,
        state: State,
    ) {
        self.said(window, role, None, action, key);
        let server = Box::into_raw(Box::new(Server {
            table: &TABLE,
            count: AtomicU32::new(1),
            window,
            state,
        }));
        // SAFETY: `SetHwndPropServer`, entry 8: the window, the object and
        // child identifiers, the properties, their count, the server and its
        // scope. The service takes its own reference to the server.
        let set: unsafe extern "system" fn(
            Object,
            HWND,
            u32,
            u32,
            *const GUID,
            i32,
            *mut c_void,
            i32,
        ) -> i32 = unsafe { self.0.slot(8) };
        let properties = [PROPID_ACC_STATE];
        // SAFETY: the window is this thread's own and alive; the server is
        // live and the property list lives for the call.
        unsafe {
            set(
                self.0.object(),
                window,
                OBJID_CLIENT.cast_unsigned(),
                CHILDID_SELF,
                properties.as_ptr(),
                1,
                server.cast(),
                ANNO_THIS,
            )
        };
        // SAFETY: this reference was the one `Box::into_raw` made.
        unsafe { release(server) };
    }

    /// Says what `window` is and what it is called: a window with no text of
    /// its own has no name to read otherwise.
    pub(crate) fn named(&self, window: HWND, role: u32, name: &str) {
        self.said(window, role, Some(name), None, None);
    }

    fn said(
        &self,
        window: HWND,
        role: u32,
        name: Option<&str>,
        action: Option<&str>,
        key: Option<char>,
    ) {
        let mut value = VARIANT::default();
        value.Anonymous.Anonymous.vt = VT_I4;
        value.Anonymous.Anonymous.Anonymous.lVal = i32::try_from(role).unwrap_or_default();
        // SAFETY: `SetHwndProp`, entry 6: the window, the object and child
        // identifiers, the property by value and the value by value.
        let set: unsafe extern "system" fn(Object, HWND, u32, u32, GUID, VARIANT) -> i32 =
            unsafe { self.0.slot(6) };
        let client = OBJID_CLIENT.cast_unsigned();
        // SAFETY: the window is this thread's own and alive.
        unsafe {
            set(
                self.0.object(),
                window,
                client,
                CHILDID_SELF,
                PROPID_ACC_ROLE,
                value,
            )
        };
        // SAFETY: `SetHwndPropStr`, entry 7, takes a NUL-terminated string,
        // copied by the call.
        let set_text: unsafe extern "system" fn(Object, HWND, u32, u32, GUID, *const u16) -> i32 =
            unsafe { self.0.slot(7) };
        let texts = [
            (PROPID_ACC_NAME, name.map(wide)),
            (PROPID_ACC_DEFAULTACTION, action.map(wide)),
            (
                PROPID_ACC_KEYBOARDSHORTCUT,
                key.map(|key| wide(key.to_string())),
            ),
        ];
        for (property, text) in texts {
            if let Some(text) = text {
                // SAFETY: as above.
                unsafe {
                    set_text(
                        self.0.object(),
                        window,
                        client,
                        CHILDID_SELF,
                        property,
                        text.as_ptr(),
                    )
                };
            }
        }
    }

    /// Takes back what was said of `window`, before it is destroyed.
    pub(crate) fn clear(&self, window: HWND) {
        let ids = [
            PROPID_ACC_ROLE,
            PROPID_ACC_NAME,
            PROPID_ACC_DEFAULTACTION,
            PROPID_ACC_KEYBOARDSHORTCUT,
            PROPID_ACC_STATE,
        ];
        // SAFETY: `ClearHwndProps`, entry 9: the window, the object and child
        // identifiers, and an array of property identifiers.
        let clear: unsafe extern "system" fn(Object, HWND, u32, u32, *const GUID, i32) -> i32 =
            unsafe { self.0.slot(9) };
        // SAFETY: the array lives for the call; a window that is gone is
        // refused.
        unsafe {
            clear(
                self.0.object(),
                window,
                OBJID_CLIENT.cast_unsigned(),
                CHILDID_SELF,
                ids.as_ptr(),
                5,
            )
        };
    }
}
