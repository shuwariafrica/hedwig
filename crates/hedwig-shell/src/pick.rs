//! Choosing a file to write to or to read from: the shell's own dialog, its
//! Common Item Dialog, the one Windows gives every application.
//!
//! The dialog is modal to its owner and runs a message loop of its own on the
//! calling thread, which must be free to: the window calls it on a thread of
//! its own, never on the one WinUI runs on.

use std::ffi::{OsString, c_void};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows_sys::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows_sys::Win32::UI::Shell::{
    FILEOPENDIALOGOPTIONS, FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_OVERWRITEPROMPT,
    FOS_PATHMUSTEXIST, FileOpenDialog, FileSaveDialog, SIGDN, SIGDN_FILESYSPATH,
};
use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};

use crate::com::{Com, Object};
use crate::raw::wide;

const IID_FILE_OPEN_DIALOG: GUID = GUID::from_u128(0xd57c7288_d4ad_4768_be02_9d969532d960);
const IID_FILE_SAVE_DIALOG: GUID = GUID::from_u128(0x84bccd23_5fde_4cdb_aea4_af64b83d78ab);
/// `HRESULT_FROM_WIN32(ERROR_CANCELLED)`: the person closed the dialog.
const CANCELLED: HRESULT = 0x8007_04c7_u32.cast_signed();

// Places in the tables, after `IUnknown`'s three: `IModalWindow::Show`, then
// `IFileDialog`'s, then `IShellItem`'s (the `windows` crate 0.62.2's tables,
// in the order of `shobjidl_core.h`).
const SHOW: usize = 3;
const SET_FILE_TYPES: usize = 4;
const SET_OPTIONS: usize = 9;
const GET_OPTIONS: usize = 10;
const SET_FILE_NAME: usize = 15;
const SET_TITLE: usize = 17;
const GET_RESULT: usize = 20;
const SET_DEFAULT_EXTENSION: usize = 22;
const GET_DISPLAY_NAME: usize = 5;

type Show = unsafe extern "system" fn(Object, HWND) -> HRESULT;
type SetFileTypes = unsafe extern "system" fn(Object, u32, *const COMDLG_FILTERSPEC) -> HRESULT;
type SetOptions = unsafe extern "system" fn(Object, FILEOPENDIALOGOPTIONS) -> HRESULT;
type GetOptions = unsafe extern "system" fn(Object, *mut FILEOPENDIALOGOPTIONS) -> HRESULT;
type SetText = unsafe extern "system" fn(Object, PCWSTR) -> HRESULT;
type GetResult = unsafe extern "system" fn(Object, *mut Object) -> HRESULT;
type GetDisplayName = unsafe extern "system" fn(Object, SIGDN, *mut PWSTR) -> HRESULT;

/// What the dialog asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A file to read; it must exist.
    Read,
    /// A file to write, with a name suggested; replacing one is asked first.
    Write,
}

/// What the dialog shows and offers, in the words `hedwig-view` gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog<'a> {
    pub purpose: Purpose,
    pub title: &'a str,
    /// The name suggested for a file to write.
    pub name: &'a str,
    /// Each kind of file offered: its name and its pattern.
    pub kinds: &'a [(&'a str, &'a str)],
    /// What is added to a name typed with none.
    pub extension: &'a str,
}

fn checked(result: HRESULT) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::from_raw_os_error(result))
    } else {
        Ok(())
    }
}

/// The apartment this thread enters for the dialog and leaves after it.
struct Apartment;

impl Apartment {
    fn enter() -> io::Result<Apartment> {
        // SAFETY: the reserved pointer is null. A thread already in a
        // single-threaded apartment is entered again, which the drop
        // balances; one in the multithreaded apartment is refused.
        checked(unsafe {
            CoInitializeEx(
                std::ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).cast_unsigned(),
            )
        })?;
        Ok(Apartment)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: balances the entry `enter` made; every object it made is
        // released before this value is dropped.
        unsafe { CoUninitialize() };
    }
}

/// Shows the dialog over `owner`, or over nothing, and answers the file the
/// person chose, or `None` where they cancelled.
///
/// # Errors
///
/// The shell could not make or show the dialog, or the thread is in the
/// multithreaded apartment.
pub fn choose(dialog: &Dialog<'_>, owner: Option<isize>) -> io::Result<Option<PathBuf>> {
    let _apartment = Apartment::enter()?;
    let (class, interface, more) = match dialog.purpose {
        Purpose::Read => (
            FileOpenDialog,
            IID_FILE_OPEN_DIALOG,
            FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST,
        ),
        Purpose::Write => (FileSaveDialog, IID_FILE_SAVE_DIALOG, FOS_OVERWRITEPROMPT),
    };
    let mut made: Object = std::ptr::null_mut();
    // SAFETY: the identifiers are the shell's and the place is valid; the
    // thread is in a single-threaded apartment.
    checked(unsafe {
        CoCreateInstance(
            &raw const class,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &raw const interface,
            &raw mut made,
        )
    })?;
    let shown = Com::new(made).ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;

    let names: Vec<(Vec<u16>, Vec<u16>)> = dialog
        .kinds
        .iter()
        .map(|(name, pattern)| (wide(name), wide(pattern)))
        .collect();
    let specs: Vec<COMDLG_FILTERSPEC> = names
        .iter()
        .map(|(name, pattern)| COMDLG_FILTERSPEC {
            pszName: name.as_ptr(),
            pszSpec: pattern.as_ptr(),
        })
        .collect();
    let count = u32::try_from(specs.len()).unwrap_or_default();
    // SAFETY: entry 4 of `IFileDialog` is `SetFileTypes`.
    let set_file_types = unsafe { shown.slot::<SetFileTypes>(SET_FILE_TYPES) };
    // SAFETY: the specifications and the text they point at outlive the
    // dialog's use of them.
    checked(unsafe { set_file_types(shown.object(), count, specs.as_ptr()) })?;
    let mut options: FILEOPENDIALOGOPTIONS = 0;
    // SAFETY: entry 10 is `GetOptions`.
    let get_options = unsafe { shown.slot::<GetOptions>(GET_OPTIONS) };
    // SAFETY: the place is valid.
    checked(unsafe { get_options(shown.object(), &raw mut options) })?;
    // SAFETY: entry 9 is `SetOptions`.
    let set_options = unsafe { shown.slot::<SetOptions>(SET_OPTIONS) };
    // SAFETY: the call takes flags. Only a file on a disk is one the window
    // can read or write.
    checked(unsafe { set_options(shown.object(), options | FOS_FORCEFILESYSTEM | more) })?;
    for (place, text) in [
        (SET_TITLE, dialog.title),
        (SET_DEFAULT_EXTENSION, dialog.extension),
    ] {
        let text = wide(text);
        // SAFETY: entries 17 and 22 are `SetTitle` and `SetDefaultExtension`.
        let set = unsafe { shown.slot::<SetText>(place) };
        // SAFETY: the text is NUL-terminated, and the dialog copies it.
        checked(unsafe { set(shown.object(), text.as_ptr()) })?;
    }
    if dialog.purpose == Purpose::Write {
        let name = wide(dialog.name);
        // SAFETY: entry 15 is `SetFileName`.
        let set = unsafe { shown.slot::<SetText>(SET_FILE_NAME) };
        // SAFETY: as above.
        checked(unsafe { set(shown.object(), name.as_ptr()) })?;
    }

    let owner = owner.map_or(std::ptr::null_mut(), |owner| owner as HWND);
    // SAFETY: entry 3 is `IModalWindow::Show`.
    let show = unsafe { shown.slot::<Show>(SHOW) };
    // SAFETY: an owner that has gone is taken by the shell as none.
    let answered = unsafe { show(shown.object(), owner) };
    if answered == CANCELLED {
        return Ok(None);
    }
    checked(answered)?;
    let mut item: Object = std::ptr::null_mut();
    // SAFETY: entry 20 is `GetResult`.
    let get_result = unsafe { shown.slot::<GetResult>(GET_RESULT) };
    // SAFETY: the place is valid.
    checked(unsafe { get_result(shown.object(), &raw mut item) })?;
    let item = Com::new(item).ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let mut text: PWSTR = std::ptr::null_mut();
    // SAFETY: entry 5 of `IShellItem` is `GetDisplayName`.
    let get_display_name = unsafe { item.slot::<GetDisplayName>(GET_DISPLAY_NAME) };
    // SAFETY: the place is valid; the text answered is the caller's to free.
    checked(unsafe { get_display_name(item.object(), SIGDN_FILESYSPATH, &raw mut text) })?;
    if text.is_null() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    let mut length = 0;
    loop {
        // SAFETY: the shell answered a NUL-terminated text, and `length` has
        // not passed its terminator.
        let at = unsafe { text.add(length) };
        // SAFETY: as above.
        if unsafe { *at } == 0 {
            break;
        }
        length += 1;
    }
    // SAFETY: as above, `length` units long.
    let units = unsafe { std::slice::from_raw_parts(text, length) };
    let path = PathBuf::from(OsString::from_wide(units));
    // SAFETY: the text is the shell's allocation, freed once and not used
    // after.
    unsafe { CoTaskMemFree(text.cast::<c_void>().cast_const()) };
    Ok(Some(path))
}
