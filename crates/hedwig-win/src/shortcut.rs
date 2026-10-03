//! A shell link: what the Start menu lists and opens, written through the
//! shell's own `ShellLink` object so that Windows reads back exactly what it
//! would have written itself.
//!
//! `windows-sys` declares the class but not the interfaces, so the three
//! used are declared here in their slot order (`shobjidl_core.h`,
//! `objidl.h`, `propsys.h`).

use std::ffi::c_void;
use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::{PROPERTYKEY, TRUE};
use windows_sys::Win32::System::Com::StructuredStorage::PROPVARIANT;
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::Variant::VT_LPWSTR;
use windows_sys::Win32::UI::Shell::ShellLink;
use windows_sys::core::{BOOL, GUID, HRESULT};

use crate::raw::wide;

const IID_SHELL_LINK_W: GUID = GUID::from_u128(0x0002_14f9_0000_0000_c000_0000_0000_0046);
const IID_PERSIST_FILE: GUID = GUID::from_u128(0x0000_010b_0000_0000_c000_0000_0000_0046);
const IID_PROPERTY_STORE: GUID = GUID::from_u128(0x886d_8eeb_8cf2_4446_8d02_cdba_1dbd_cf99);

/// `System.AppUserModel.ID` (`propkey.h`, `PKEY_AppUserModel_ID`): the
/// identity the taskbar groups a window under and pins to.
const APP_USER_MODEL_ID: PROPERTYKEY = PROPERTYKEY {
    fmtid: GUID::from_u128(0x9f4c_2855_9f79_4b39_a8d0_e1d4_2de1_d5f3),
    pid: 5,
};

#[repr(C)]
struct Unknown {
    query: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    _add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

/// `IShellLinkW`, only the slots called typed.
#[repr(C)]
struct ShellLinkW {
    unknown: Unknown,
    _get_path: usize,
    _get_id_list: usize,
    _set_id_list: usize,
    _get_description: usize,
    _set_description: usize,
    _get_working_directory: usize,
    set_working_directory: unsafe extern "system" fn(*mut c_void, *const u16) -> HRESULT,
    _get_arguments: usize,
    set_arguments: unsafe extern "system" fn(*mut c_void, *const u16) -> HRESULT,
    _get_hotkey: usize,
    _set_hotkey: usize,
    _get_show_cmd: usize,
    _set_show_cmd: usize,
    _get_icon_location: usize,
    _set_icon_location: usize,
    _set_relative_path: usize,
    _resolve: usize,
    set_path: unsafe extern "system" fn(*mut c_void, *const u16) -> HRESULT,
}

/// `IPropertyStore`, only the slots called typed.
#[repr(C)]
struct PropertyStore {
    unknown: Unknown,
    _get_count: usize,
    _get_at: usize,
    _get_value: usize,
    set_value:
        unsafe extern "system" fn(*mut c_void, *const PROPERTYKEY, *const PROPVARIANT) -> HRESULT,
    commit: unsafe extern "system" fn(*mut c_void) -> HRESULT,
}

/// `IPersistFile`, only the slot called typed.
#[repr(C)]
struct PersistFile {
    unknown: Unknown,
    _get_class_id: usize,
    _is_dirty: usize,
    _load: usize,
    save: unsafe extern "system" fn(*mut c_void, *const u16, BOOL) -> HRESULT,
}

/// One reference to a COM object, released when dropped.
struct Object(*mut c_void);

impl Object {
    /// The object's table of `V`.
    ///
    /// # Safety
    ///
    /// The object implements the interface whose table `V` declares.
    unsafe fn table<V>(&self) -> &V {
        let pointer: *const *const V = self.0.cast();
        // SAFETY: a COM interface pointer points at its table's pointer.
        let table = unsafe { *pointer };
        // SAFETY: the table lives as long as the object, and the caller
        // vouches it is `V`'s.
        unsafe { &*table }
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: every interface begins with `IUnknown`'s slots.
        let release = unsafe { self.table::<Unknown>() }.release;
        // SAFETY: this reference is held once and released once.
        unsafe { release(self.0) };
    }
}

fn checked(result: HRESULT) -> io::Result<()> {
    if result >= 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

/// Writes the shell link `link` that starts `program` with `arguments`, from
/// `program`'s folder, under the application identity `identity`, replacing
/// one there. A window whose process names the same identity is grouped
/// with the link on the taskbar, and a pin of either is the link. COM is
/// initialised on this thread for the call.
///
/// # Errors
///
/// What the shell said: the object could not be made, the identity set, or
/// the file written.
pub fn make(link: &Path, program: &Path, arguments: &str, identity: &str) -> io::Result<()> {
    // SAFETY: no reserved pointer; the flags are the shell's own for a
    // thread that calls it.
    let initialised = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).cast_unsigned(),
        )
    };
    let made = write(link, program, arguments, identity);
    // Success, or already initialised on this thread: each is balanced.
    if initialised >= 0 {
        // SAFETY: balances the successful initialisation above, every object
        // having been released inside `write`.
        unsafe { CoUninitialize() };
    }
    made
}

fn write(link: &Path, program: &Path, arguments: &str, identity: &str) -> io::Result<()> {
    let mut made: *mut c_void = std::ptr::null_mut();
    // SAFETY: the class and interface identifiers are valid for the call and
    // `made` receives the one reference.
    checked(unsafe {
        CoCreateInstance(
            &ShellLink,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_SHELL_LINK_W,
            &raw mut made,
        )
    })?;
    let shell = Object(made);
    // SAFETY: `shell` was made as `IShellLinkW`.
    let table = unsafe { shell.table::<ShellLinkW>() };
    let (path, folder, arguments) = (
        wide(program),
        wide(program.parent().unwrap_or(program)),
        wide(arguments),
    );
    // SAFETY: each string is NUL-terminated and outlives its call.
    checked(unsafe { (table.set_path)(shell.0, path.as_ptr()) })?;
    // SAFETY: as above.
    checked(unsafe { (table.set_working_directory)(shell.0, folder.as_ptr()) })?;
    // SAFETY: as above.
    checked(unsafe { (table.set_arguments)(shell.0, arguments.as_ptr()) })?;
    identify(&shell, identity)?;
    let mut persisted: *mut c_void = std::ptr::null_mut();
    // SAFETY: the identifier is valid and `persisted` receives one reference.
    checked(unsafe { (table.unknown.query)(shell.0, &IID_PERSIST_FILE, &raw mut persisted) })?;
    let file = Object(persisted);
    let at = wide(link);
    // SAFETY: `file` was asked for as `IPersistFile`.
    let save = unsafe { file.table::<PersistFile>() }.save;
    // SAFETY: the path is NUL-terminated and outlives the call.
    checked(unsafe { save(file.0, at.as_ptr(), TRUE) })
}

/// Sets the link's `System.AppUserModel.ID` through its property store.
fn identify(shell: &Object, identity: &str) -> io::Result<()> {
    let mut asked: *mut c_void = std::ptr::null_mut();
    // SAFETY: `shell` is a live `IShellLinkW`, whose table begins with
    // `IUnknown`'s; the identifier is valid and `asked` receives one
    // reference.
    let query = unsafe { shell.table::<Unknown>() }.query;
    // SAFETY: as above.
    checked(unsafe { query(shell.0, &IID_PROPERTY_STORE, &raw mut asked) })?;
    let store = Object(asked);
    // SAFETY: `store` was asked for as `IPropertyStore`.
    let table = unsafe { store.table::<PropertyStore>() };
    let text = wide(identity);
    let mut value = PROPVARIANT::default();
    value.Anonymous.Anonymous.vt = VT_LPWSTR;
    // The store copies the string; the variant only lends it for the call,
    // so it is never cleared.
    value.Anonymous.Anonymous.Anonymous.pwszVal = text.as_ptr().cast_mut();
    // SAFETY: the key and the variant are valid for the call, and the string
    // the variant points at is NUL-terminated and outlives it.
    checked(unsafe { (table.set_value)(store.0, &APP_USER_MODEL_ID, &raw const value) })?;
    // SAFETY: `store` is live.
    checked(unsafe { (table.commit)(store.0) })
}
