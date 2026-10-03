//! The workstation's serial ports: which there are, and one opened for a
//! connection.
//!
//! Every read, write and wait is overlapped and waited for before the call
//! returns, so no `OVERLAPPED` outlives the call that owns it, and every wait
//! wakes often enough to see [`ComPort::cancel`] and cancel its own I/O.

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Devices::Communication::{
    COMMTIMEOUTS, COMSTAT, ClearCommError, DCB, EscapeCommFunction, GetCommModemStatus,
    GetCommState, PurgeComm, SetCommMask, SetCommState, SetCommTimeouts, WaitCommEvent,
};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DICS_FLAG_GLOBAL, DIGCF_PRESENT, DIREG_DEV, GUID_DEVCLASS_PORTS, HDEVINFO, SP_DEVINFO_DATA,
    SPDRP_FRIENDLYNAME, SPDRP_HARDWAREID, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW, SetupDiOpenDevRegKey,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_NO_MORE_ITEMS,
    ERROR_PATH_NOT_FOUND, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, TRUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_READ, REG_NOTIFY_CHANGE_LAST_SET,
    REG_NOTIFY_CHANGE_NAME, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegEnumValueW, RegGetValueW,
    RegNotifyChangeKeyValue, RegOpenKeyExW,
};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

use crate::raw::{owned, wide};

pub use windows_sys::Win32::Devices::Communication::{
    CE_BREAK, CE_FRAME, CE_OVERRUN, CE_RXPARITY, EV_BREAK, EV_CTS, EV_DSR, EV_ERR, EV_RING,
    EV_RLSD, MS_CTS_ON, MS_DSR_ON, MS_RING_ON, MS_RLSD_ON, PURGE_RXABORT, PURGE_RXCLEAR,
    PURGE_TXABORT, PURGE_TXCLEAR,
};

/// Where Windows lists the serial ports present now: each serial driver
/// writes its port's name there while the device is there.
const SERIALCOMM: &str = r"HARDWARE\DEVICEMAP\SERIALCOMM";

/// How often a wait looks to see whether the port was cancelled.
const GLANCE: u32 = 250;

/// How long a read waits for a first byte before it returns none.
const READ_PATIENCE: u32 = 1000;

/// The names of the serial ports present now, as their drivers registered
/// them; none where the key is not there, as on a workstation with no port.
///
/// # Errors
///
/// What the registry said, other than that the key is not there.
pub fn present() -> io::Result<Vec<OsString>> {
    let key = wide(SERIALCOMM);
    let mut opened: HKEY = std::ptr::null_mut();
    // SAFETY: the subkey's name is NUL-terminated; `opened` receives a key
    // this function closes below.
    let failed = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            0,
            KEY_READ,
            &raw mut opened,
        )
    };
    match failed {
        0 => {}
        ERROR_FILE_NOT_FOUND => return Ok(Vec::new()),
        other => return Err(io::Error::from_raw_os_error(other.cast_signed())),
    }
    let names = values(opened);
    // SAFETY: the key was opened above and is closed once.
    unsafe { RegCloseKey(opened) };
    names
}

/// The text of every string value under an open key.
fn values(key: HKEY) -> io::Result<Vec<OsString>> {
    let mut found = Vec::new();
    for index in 0.. {
        let mut name = [0u16; 256];
        let mut name_length = u32::try_from(name.len()).unwrap_or(0);
        let mut data = [0u16; 256];
        let mut data_bytes = u32::try_from(data.len() * 2).unwrap_or(0);
        let mut kind = 0u32;
        // SAFETY: each buffer is as long as the length passed with it, which
        // the call reads and then sets to what it wrote.
        let failed = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &raw mut name_length,
                std::ptr::null(),
                &raw mut kind,
                data.as_mut_ptr().cast(),
                &raw mut data_bytes,
            )
        };
        match failed {
            0 if kind == REG_SZ => {
                let units = (data_bytes as usize / 2).min(data.len());
                let text = data.get(..units).unwrap_or_default();
                let text = text.split(|unit| *unit == 0).next().unwrap_or_default();
                found.push(OsString::from_wide(text));
            }
            0 => {}
            ERROR_NO_MORE_ITEMS => break,
            other => return Err(io::Error::from_raw_os_error(other.cast_signed())),
        }
    }
    Ok(found)
}

/// A device of the class Windows keeps serial and parallel ports in: the
/// port name its driver gave it, its name as Windows shows it, and its
/// hardware identifiers, most specific first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Described {
    pub port: Option<OsString>,
    pub friendly: Option<OsString>,
    pub hardware: Vec<OsString>,
}

/// Every device of the ports class, or only those present now.
///
/// # Errors
///
/// What the system said of the class.
pub fn described(present_only: bool) -> io::Result<Vec<Described>> {
    let flags = if present_only { DIGCF_PRESENT } else { 0 };
    let class = GUID_DEVCLASS_PORTS;
    // SAFETY: the class is a GUID the system defines; no enumerator and no
    // window; the set returned is destroyed below.
    let set: HDEVINFO = unsafe {
        SetupDiGetClassDevsW(
            &raw const class,
            std::ptr::null(),
            std::ptr::null_mut(),
            flags,
        )
    };
    if set == INVALID_HANDLE_VALUE as HDEVINFO {
        return Err(io::Error::last_os_error());
    }
    let mut found = Vec::new();
    for index in 0.. {
        let mut data = SP_DEVINFO_DATA {
            cbSize: u32::try_from(size_of::<SP_DEVINFO_DATA>()).unwrap_or(0),
            ..SP_DEVINFO_DATA::default()
        };
        // SAFETY: `set` is the list above; `data` states its own size.
        if unsafe { SetupDiEnumDeviceInfo(set, index, &raw mut data) } == FALSE {
            break;
        }
        found.push(Described {
            port: port_name(set, &data),
            friendly: property(set, &data, SPDRP_FRIENDLYNAME)
                .and_then(|units| strings(&units).into_iter().next()),
            hardware: property(set, &data, SPDRP_HARDWAREID)
                .map(|units| strings(&units))
                .unwrap_or_default(),
        });
    }
    // SAFETY: the list was created above and is destroyed once.
    unsafe { SetupDiDestroyDeviceInfoList(set) };
    Ok(found)
}

/// The `PortName` the device's driver keeps in the device's own key.
fn port_name(set: HDEVINFO, data: &SP_DEVINFO_DATA) -> Option<OsString> {
    // SAFETY: `set` and `data` name one device of the list; the key returned
    // is closed below.
    let key = unsafe { SetupDiOpenDevRegKey(set, data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ) };
    if key.is_null() || std::ptr::eq(key, INVALID_HANDLE_VALUE) {
        return None;
    }
    let value = wide("PortName");
    let mut units = [0u16; 64];
    let mut bytes = u32::try_from(units.len() * 2).unwrap_or(0);
    // SAFETY: the value's name is NUL-terminated; `units` is `bytes` bytes.
    let failed = unsafe {
        RegGetValueW(
            key,
            std::ptr::null(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            units.as_mut_ptr().cast(),
            &raw mut bytes,
        )
    };
    // SAFETY: the key was opened above and is closed once.
    unsafe { RegCloseKey(key) };
    (failed == 0).then(|| {
        let length = (bytes as usize / 2).saturating_sub(1).min(units.len());
        OsString::from_wide(units.get(..length).unwrap_or_default())
    })
}

/// A device's registry property as UTF-16 units, where it has one.
fn property(set: HDEVINFO, data: &SP_DEVINFO_DATA, which: u32) -> Option<Vec<u16>> {
    let mut units = vec![0u16; 512];
    let mut required = 0u32;
    // SAFETY: `set` and `data` name one device; `units` is the byte length
    // passed.
    let ok = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            set,
            data,
            which,
            std::ptr::null_mut(),
            units.as_mut_ptr().cast(),
            u32::try_from(units.len() * 2).unwrap_or(0),
            &raw mut required,
        )
    };
    (ok != FALSE).then(|| {
        units.truncate((required as usize / 2).min(units.len()));
        units
    })
}

/// The NUL-separated strings of a string or multi-string value.
fn strings(units: &[u16]) -> Vec<OsString> {
    units
        .split(|unit| *unit == 0)
        .filter(|text| !text.is_empty())
        .map(OsString::from_wide)
        .collect()
}

/// Why a port did not open.
#[derive(Debug)]
pub enum OpenError {
    /// No device answers to the name.
    Absent,
    /// Another program holds it: a communications resource is opened for
    /// one handle alone.
    Busy,
    /// What opened is no serial port.
    NotSerial,
    Other(io::Error),
}

/// The settings of the DCB a connection changes. Everything else in the
/// DCB is kept as the driver had it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the DCB's own flags, one to a field"
)]
pub struct State {
    pub baud: u32,
    pub size: u8,
    /// `NOPARITY` to `SPACEPARITY`.
    pub parity: u8,
    /// `ONESTOPBIT`, `ONE5STOPBITS`, `TWOSTOPBITS`.
    pub stop: u8,
    pub out_cts: bool,
    pub out_dsr: bool,
    /// `DTR_CONTROL_*`.
    pub dtr: u8,
    pub out_x: bool,
    pub in_x: bool,
    /// `RTS_CONTROL_*`.
    pub rts: u8,
}

const OUT_CTS: u32 = 1 << 2;
const OUT_DSR: u32 = 1 << 3;
const DTR_SHIFT: u32 = 4;
const OUT_X: u32 = 1 << 8;
const IN_X: u32 = 1 << 9;
const RTS_SHIFT: u32 = 12;

impl State {
    fn of(dcb: &DCB) -> State {
        let bits = dcb._bitfield;
        State {
            baud: dcb.BaudRate,
            size: dcb.ByteSize,
            parity: dcb.Parity,
            stop: dcb.StopBits,
            out_cts: bits & OUT_CTS != 0,
            out_dsr: bits & OUT_DSR != 0,
            dtr: u8::try_from((bits >> DTR_SHIFT) & 0b11).unwrap_or(0),
            out_x: bits & OUT_X != 0,
            in_x: bits & IN_X != 0,
            rts: u8::try_from((bits >> RTS_SHIFT) & 0b11).unwrap_or(0),
        }
    }

    fn onto(self, dcb: &mut DCB) {
        let mut bits = dcb._bitfield
            & !(OUT_CTS | OUT_DSR | (0b11 << DTR_SHIFT) | OUT_X | IN_X | (0b11 << RTS_SHIFT));
        bits |= (u32::from(self.out_cts) * OUT_CTS)
            | (u32::from(self.out_dsr) * OUT_DSR)
            | ((u32::from(self.dtr) & 0b11) << DTR_SHIFT)
            | (u32::from(self.out_x) * OUT_X)
            | (u32::from(self.in_x) * IN_X)
            | ((u32::from(self.rts) & 0b11) << RTS_SHIFT);
        // `fBinary`: "Windows does not support nonbinary mode transfers, so
        // this member must be TRUE" (`DCB`).
        bits |= 1;
        dcb._bitfield = bits;
        dcb.BaudRate = self.baud;
        dcb.ByteSize = self.size;
        dcb.Parity = self.parity;
        dcb.StopBits = self.stop;
    }
}

/// `EscapeCommFunction`'s functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    SetDtr,
    ClearDtr,
    SetRts,
    ClearRts,
    SetBreak,
    ClearBreak,
}

/// What `ClearCommError` reports and clears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Errors {
    /// `CE_*` bits.
    pub errors: u32,
    pub waiting: u32,
    pub unsent: u32,
}

/// A serial port opened for one connection. Closed when dropped.
#[derive(Debug)]
pub struct ComPort {
    handle: OwnedHandle,
    cancelled: AtomicBool,
}

impl ComPort {
    /// Opens `\\.\<name>` for overlapped reading and writing, set so a read
    /// returns as soon as a byte has arrived and the driver tells of every
    /// modem and line event.
    ///
    /// # Errors
    ///
    /// [`OpenError::Absent`] where no device answers to the name,
    /// [`OpenError::Busy`] where another handle holds it,
    /// [`OpenError::NotSerial`] where it takes no serial settings.
    pub fn open(name: &str) -> Result<ComPort, OpenError> {
        let path = wide(format!(r"\\.\{name}"));
        // SAFETY: the path is NUL-terminated; no security attributes and no
        // template, share mode zero as a communications resource requires.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        let handle = owned(handle).map_err(|error| match crate::raw::code(&error) {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => OpenError::Absent,
            ERROR_ACCESS_DENIED => OpenError::Busy,
            _ => OpenError::Other(error),
        })?;
        let port = ComPort {
            handle,
            cancelled: AtomicBool::new(false),
        };
        port.state().map_err(|_| OpenError::NotSerial)?;
        let timeouts = COMMTIMEOUTS {
            ReadIntervalTimeout: u32::MAX,
            ReadTotalTimeoutMultiplier: u32::MAX,
            ReadTotalTimeoutConstant: READ_PATIENCE,
            WriteTotalTimeoutMultiplier: 0,
            WriteTotalTimeoutConstant: 0,
        };
        // SAFETY: the handle is the port just opened; the structure is read.
        if unsafe { SetCommTimeouts(port.raw(), &raw const timeouts) } == FALSE {
            return Err(OpenError::NotSerial);
        }
        let mask = EV_CTS | EV_DSR | EV_RLSD | EV_RING | EV_ERR | EV_BREAK;
        // SAFETY: the handle is the port just opened.
        if unsafe { SetCommMask(port.raw(), mask) } == FALSE {
            return Err(OpenError::NotSerial);
        }
        Ok(port)
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }

    /// # Errors
    ///
    /// What the driver said.
    pub fn state(&self) -> io::Result<State> {
        Ok(State::of(&self.dcb()?))
    }

    fn dcb(&self) -> io::Result<DCB> {
        let mut dcb = DCB {
            DCBlength: u32::try_from(size_of::<DCB>()).unwrap_or(0),
            ..DCB::default()
        };
        // SAFETY: the handle is this port's; the DCB states its own length.
        if unsafe { GetCommState(self.raw(), &raw mut dcb) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(dcb)
    }

    /// Applies `state` over what the driver has now.
    ///
    /// # Errors
    ///
    /// The driver does not take it, and keeps what it had.
    pub fn set_state(&self, state: State) -> io::Result<()> {
        let mut dcb = self.dcb()?;
        state.onto(&mut dcb);
        // SAFETY: the handle is this port's; the DCB was read from it.
        if unsafe { SetCommState(self.raw(), &raw const dcb) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// # Errors
    ///
    /// The driver does not let the line be driven: handshaking holds it.
    pub fn escape(&self, function: Escape) -> io::Result<()> {
        use windows_sys::Win32::Devices::Communication::{
            CLRBREAK, CLRDTR, CLRRTS, SETBREAK, SETDTR, SETRTS,
        };
        let function = match function {
            Escape::SetDtr => SETDTR,
            Escape::ClearDtr => CLRDTR,
            Escape::SetRts => SETRTS,
            Escape::ClearRts => CLRRTS,
            Escape::SetBreak => SETBREAK,
            Escape::ClearBreak => CLRBREAK,
        };
        // SAFETY: the handle is this port's.
        if unsafe { EscapeCommFunction(self.raw(), function) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `MS_*_ON` bits.
    ///
    /// # Errors
    ///
    /// What the driver said.
    pub fn modem(&self) -> io::Result<u32> {
        let mut status = 0u32;
        // SAFETY: the handle is this port's; `status` is written.
        if unsafe { GetCommModemStatus(self.raw(), &raw mut status) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(status)
    }

    /// # Errors
    ///
    /// What the driver said.
    pub fn errors(&self) -> io::Result<Errors> {
        let mut errors = 0u32;
        let mut stat = COMSTAT::default();
        // SAFETY: the handle is this port's; both are written.
        if unsafe { ClearCommError(self.raw(), &raw mut errors, &raw mut stat) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(Errors {
            errors,
            waiting: stat.cbInQue,
            unsent: stat.cbOutQue,
        })
    }

    /// # Errors
    ///
    /// What the driver said.
    pub fn purge(&self, flags: u32) -> io::Result<()> {
        // SAFETY: the handle is this port's.
        if unsafe { PurgeComm(self.raw(), flags) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// What arrived, as soon as anything has; `Ok(0)` after a second with
    /// nothing.
    ///
    /// # Errors
    ///
    /// The port went away, or was cancelled.
    pub fn read(&self, into: &mut [u8]) -> io::Result<usize> {
        let length = u32::try_from(into.len()).unwrap_or(u32::MAX);
        let read = self.overlapped(|overlapped| {
            // SAFETY: `into` is `length` writable bytes that outlive the
            // operation, which `overlapped` waits for.
            unsafe {
                ReadFile(
                    self.raw(),
                    into.as_mut_ptr(),
                    length,
                    std::ptr::null_mut(),
                    overlapped,
                )
            }
        })?;
        Ok(read as usize)
    }

    /// Writes every byte.
    ///
    /// # Errors
    ///
    /// The port went away, or was cancelled.
    pub fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let mut rest = bytes;
        while !rest.is_empty() {
            let length = u32::try_from(rest.len()).unwrap_or(u32::MAX);
            let written = self.overlapped(|overlapped| {
                // SAFETY: `rest` is `length` readable bytes that outlive the
                // operation, which `overlapped` waits for.
                unsafe {
                    WriteFile(
                        self.raw(),
                        rest.as_ptr(),
                        length,
                        std::ptr::null_mut(),
                        overlapped,
                    )
                }
            })?;
            rest = rest.get(written as usize..).unwrap_or_default();
        }
        Ok(())
    }

    /// Waits for a modem or line event; the `EV_*` bits that happened, zero
    /// where the mask was changed under it.
    ///
    /// # Errors
    ///
    /// The port went away, or was cancelled.
    pub fn wait(&self) -> io::Result<u32> {
        let mut mask = 0u32;
        self.overlapped(|overlapped| {
            // SAFETY: `mask` outlives the operation, which `overlapped` waits
            // for.
            unsafe { WaitCommEvent(self.raw(), &raw mut mask, overlapped) }
        })?;
        Ok(mask)
    }

    /// Ends every read, write and wait on the port, now and later.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Starts one overlapped operation and waits for it, glancing at
    /// [`ComPort::cancel`] while it waits.
    fn overlapped(&self, start: impl FnOnce(*mut OVERLAPPED) -> i32) -> io::Result<u32> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        // SAFETY: a manual-reset event, unnamed, with default security.
        let event = unsafe { CreateEventW(std::ptr::null(), TRUE, FALSE, std::ptr::null()) };
        let event = owned(event)?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        if start(&raw mut overlapped) == FALSE {
            let error = io::Error::last_os_error();
            if crate::raw::code(&error) != ERROR_IO_PENDING {
                return Err(error);
            }
        }
        loop {
            // SAFETY: the event is the operation's own.
            let waited = unsafe { WaitForSingleObject(event.as_raw_handle(), GLANCE) };
            if waited == WAIT_OBJECT_0 {
                break;
            }
            if waited != WAIT_TIMEOUT {
                return Err(io::Error::last_os_error());
            }
            if self.cancelled.load(Ordering::SeqCst) {
                // SAFETY: cancels this operation alone; the wait below
                // returns once it has ended.
                unsafe { CancelIoEx(self.raw(), &raw const overlapped) };
                break;
            }
        }
        let mut transferred = 0u32;
        // SAFETY: waits for the operation to end, so nothing it wrote to is
        // released before then.
        if unsafe {
            GetOverlappedResult(
                self.raw(),
                &raw const overlapped,
                &raw mut transferred,
                TRUE,
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        Ok(transferred)
    }
}

/// Where Windows keeps its device maps. [`SERIALCOMM`] is beneath it and is
/// not there until a serial driver first writes it, so what is watched is
/// the maps.
const DEVICEMAP: &str = r"HARDWARE\DEVICEMAP";

/// Has `told` called, for the rest of this process's life, each time anything
/// beneath Windows' device maps changes - `SERIALCOMM` among them - so the
/// ports [`present`] reads may have changed. The watch is armed again before
/// `told` is called, so a change while it runs is told again. `told` runs on
/// a thread of its own; like [`crate::power`], the watch is made once and
/// never withdrawn.
///
/// # Errors
///
/// What the registry said when the device maps could not be watched.
pub fn watch(told: impl Fn() + Send + 'static) -> io::Result<()> {
    watch_key(HKEY_LOCAL_MACHINE, DEVICEMAP, told)
}

/// [`watch`] of the key `path` under `root`, its every subkey and value.
fn watch_key(root: HKEY, path: &str, told: impl Fn() + Send + 'static) -> io::Result<()> {
    let path = wide(path);
    // A predefined key is a number, not memory: it crosses to the thread as
    // one.
    let root = root.addr();
    let (armed, first) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let watching = match Watching::new(std::ptr::without_provenance_mut(root), &path) {
            Ok(watching) => {
                let _ = armed.send(Ok(()));
                watching
            }
            Err(error) => {
                let _ = armed.send(Err(error));
                return;
            }
        };
        while watching.next() {
            told();
        }
    });
    first
        .recv()
        .unwrap_or_else(|_| Err(io::Error::other("the watch ended before it was armed")))
}

/// An open key and the event its change notification signals. It lives on
/// the thread that armed it, which Windows requires of an asynchronous
/// notification that is not thread-agnostic.
struct Watching {
    key: HKEY,
    changed: OwnedHandle,
}

impl Watching {
    fn new(root: HKEY, path: &[u16]) -> io::Result<Watching> {
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: the subkey's name is NUL-terminated; `key` receives a key
        // the returned value closes when dropped.
        let failed = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_NOTIFY, &raw mut key) };
        if failed != 0 {
            return Err(io::Error::from_raw_os_error(failed.cast_signed()));
        }
        // SAFETY: an unnamed auto-reset event with default security; both
        // pointers may be null.
        let changed = unsafe { CreateEventW(std::ptr::null(), FALSE, FALSE, std::ptr::null()) };
        let changed = match owned(changed) {
            Ok(changed) => changed,
            Err(error) => {
                // SAFETY: the key was opened above and is closed once.
                unsafe { RegCloseKey(key) };
                return Err(error);
            }
        };
        let watching = Watching { key, changed };
        watching.arm()?;
        Ok(watching)
    }

    /// Asks for the event to be signalled at the next change of a subkey's
    /// name or a value, anywhere beneath the key.
    fn arm(&self) -> io::Result<()> {
        // SAFETY: the key and the event are this value's own and open.
        let failed = unsafe {
            RegNotifyChangeKeyValue(
                self.key,
                TRUE,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                self.changed.as_raw_handle(),
                TRUE,
            )
        };
        if failed != 0 {
            return Err(io::Error::from_raw_os_error(failed.cast_signed()));
        }
        Ok(())
    }

    /// Waits for the next change and arms the watch again; `false` where it
    /// can watch no more.
    fn next(&self) -> bool {
        // SAFETY: the event is this value's own and open.
        let waited = unsafe { WaitForSingleObject(self.changed.as_raw_handle(), INFINITE) };
        waited == WAIT_OBJECT_0 && self.arm().is_ok()
    }
}

impl Drop for Watching {
    fn drop(&mut self) {
        // SAFETY: the key was opened by `new` and is closed once, here.
        unsafe { RegCloseKey(self.key) };
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_VOLATILE, RegCreateKeyExW, RegDeleteTreeW,
        RegDeleteValueW, RegSetValueExW,
    };

    use super::*;

    /// A key of the test's own under the person's hive, volatile and removed
    /// when the test ends.
    struct Scratch(String);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let path = format!(r"Software\hedwig-design-{name}-{}", std::process::id());
            Scratch(path)
        }

        /// Creates `sub` beneath it and sets one value there.
        fn set(&self, sub: &str, value: &str, data: &str) {
            let path = wide(format!(r"{}\{sub}", self.0));
            let mut key: HKEY = std::ptr::null_mut();
            // SAFETY: the name is NUL-terminated and `key` receives a key
            // closed below.
            let failed = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    std::ptr::null(),
                    REG_OPTION_VOLATILE,
                    KEY_WRITE,
                    std::ptr::null(),
                    &raw mut key,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(failed, 0, "the scratch key was created");
            let name = wide(value);
            let data = wide(data);
            // SAFETY: the data is `data.len() * 2` bytes long.
            let failed = unsafe {
                RegSetValueExW(
                    key,
                    name.as_ptr(),
                    0,
                    REG_SZ,
                    data.as_ptr().cast(),
                    u32::try_from(data.len() * 2).unwrap_or(0),
                )
            };
            // SAFETY: opened above, closed once.
            unsafe { RegCloseKey(key) };
            assert_eq!(failed, 0, "the value was set");
        }

        fn remove_value(&self, sub: &str, value: &str) {
            let path = wide(format!(r"{}\{sub}", self.0));
            let mut key: HKEY = std::ptr::null_mut();
            // SAFETY: as in `set`.
            let failed = unsafe {
                RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_WRITE, &raw mut key)
            };
            assert_eq!(failed, 0, "the scratch key opened");
            let name = wide(value);
            // SAFETY: the key is open and the name NUL-terminated.
            let failed = unsafe { RegDeleteValueW(key, name.as_ptr()) };
            // SAFETY: opened above, closed once.
            unsafe { RegCloseKey(key) };
            assert_eq!(failed, 0, "the value was removed");
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let path = wide(&self.0);
            // SAFETY: the name is NUL-terminated.
            unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, path.as_ptr()) };
            // SAFETY: as above; the tree is empty, so this removes the key.
            unsafe {
                windows_sys::Win32::System::Registry::RegDeleteKeyW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                )
            };
        }
    }

    const TOLD: Duration = Duration::from_secs(5);

    #[test]
    fn a_port_written_beneath_a_watched_map_is_told_and_so_is_its_removal() {
        let scratch = Scratch::new("ports");
        scratch.set("other", "unrelated", "x");
        let (tell, told) = mpsc::channel();
        watch_key(HKEY_CURRENT_USER, &scratch.0, move || {
            let _ = tell.send(());
        })
        .expect("a key of the user's own can be watched");
        assert!(told.try_recv().is_err(), "nothing changed yet");
        // A map not there before, as SERIALCOMM is until a first serial
        // driver writes it.
        scratch.set("SERIALCOMM", r"\Device\Serial0", "COM5");
        assert!(told.recv_timeout(TOLD).is_ok(), "the first port is told");
        while told.recv_timeout(Duration::from_millis(200)).is_ok() {}
        scratch.remove_value("SERIALCOMM", r"\Device\Serial0");
        assert!(
            told.recv_timeout(TOLD).is_ok(),
            "the port's removal is told"
        );
    }

    #[test]
    fn the_workstations_device_maps_can_be_watched_by_its_user() {
        watch(|| {}).expect("HKLM\\HARDWARE\\DEVICEMAP opens for notification at medium integrity");
    }
}
