//! The supervisor's record, watched: a client learns that Hedwig started,
//! restarted its core or ended without asking anything of it.
//!
//! The folder the record is in also holds the trail, written on every
//! request, so the folder is watched with `ReadDirectoryChangesW`, which names
//! each file changed, and only a change to the record counts. A supervisor
//! that ends rewrites nothing, so the watch also waits on the supervisor the
//! record last named; a connection to its core, where there is one, ends
//! with it anyway.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, FALSE, FILETIME, HANDLE, INVALID_HANDLE_VALUE, TRUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadDirectoryChangesW,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetProcessTimes, INFINITE, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, ResetEvent, SetEvent, WaitForMultipleObjects,
};

use crate::raw::wide;

/// What one notification reads: room for some hundred names at once. A
/// notification that does not fit is a change of whatever was there.
const ROOM: usize = 4096;

/// What woke the watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// The record was made, written or replaced.
    Record,
    /// The supervisor the record named has ended.
    Ended,
}

/// Ends a watch's wait, from any thread.
#[derive(Debug, Clone)]
pub struct Stop(Arc<OwnedHandle>);

impl Stop {
    pub fn stop(&self) {
        // SAFETY: the handle is an event this value shares ownership of.
        unsafe { SetEvent(self.0.as_raw_handle()) };
    }
}

/// A watch of one folder's record.
pub struct Watch {
    directory: OwnedHandle,
    /// Raised by Windows when a read of the folder's changes completes.
    done: OwnedHandle,
    stop: Arc<OwnedHandle>,
    /// Where Windows writes the changes, aligned as it requires.
    changes: Box<[u32; ROOM / 4]>,
    overlapped: Box<OVERLAPPED>,
    /// Whether a read is outstanding, so it is cancelled before the buffer
    /// it writes into goes.
    reading: bool,
    record: Vec<u16>,
    supervisor: Option<OwnedHandle>,
}

// SAFETY: every handle is a kernel object of the process, usable from any
// thread; the read is overlapped and signals an event, with no completion
// routine queued to the thread that asked; the buffer and the overlapped
// structure are owned by the watch and move with it, boxed.
unsafe impl Send for Watch {}

fn event() -> io::Result<OwnedHandle> {
    // SAFETY: an unnamed manual-reset event with default security.
    let handle = unsafe { CreateEventW(std::ptr::null(), TRUE, FALSE, std::ptr::null()) };
    owned(handle)
}

fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just returned to this process, owned by nothing else.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

impl Watch {
    /// Watches `folder` for its file named `record`.
    ///
    /// # Errors
    ///
    /// The folder could not be opened for reading its changes.
    pub fn new(folder: &Path, record: &str) -> io::Result<(Watch, Stop)> {
        let path = wide(folder);
        // SAFETY: the path is NUL-terminated; a directory is opened with
        // backup semantics, every share, for overlapped reads of its changes.
        let directory = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        let stop = Arc::new(event()?);
        let watch = Watch {
            directory: owned(directory)?,
            done: event()?,
            stop: Arc::clone(&stop),
            changes: Box::new([0; ROOM / 4]),
            overlapped: Box::default(),
            reading: false,
            record: record.encode_utf16().collect(),
            supervisor: None,
        };
        Ok((watch, Stop(stop)))
    }

    /// Waits also for the supervisor numbered `process`, created at
    /// `created` as a file time, to end; for none where `None`. A process
    /// this one may not wait on, or one of that number created at another
    /// time, is not waited on.
    pub fn follow(&mut self, supervisor: Option<(u32, u64)>) {
        self.supervisor = supervisor.and_then(|(process, created)| {
            // SAFETY: opening by number, to wait on and to read its times.
            let opened = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    process,
                )
            };
            let handle = owned(opened).ok()?;
            let mut times = [FILETIME::default(); 4];
            let [creation, exit, kernel, user] = &mut times;
            // SAFETY: the handle carries the right to read times; each
            // structure is valid for the call.
            let read = unsafe {
                GetProcessTimes(
                    raw(&handle),
                    &raw mut *creation,
                    &raw mut *exit,
                    &raw mut *kernel,
                    &raw mut *user,
                )
            };
            let at = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
            (read != 0 && at == created).then_some(handle)
        });
    }

    /// Asks Windows for the folder's next changes, where no ask is out.
    fn read(&mut self) -> io::Result<()> {
        if self.reading {
            return Ok(());
        }
        *self.overlapped = OVERLAPPED {
            hEvent: raw(&self.done),
            ..OVERLAPPED::default()
        };
        // SAFETY: the event is this watch's own.
        unsafe { ResetEvent(raw(&self.done)) };
        // SAFETY: the buffer and the overlapped structure are boxed, so they
        // do not move, and live until the read completes or is cancelled and
        // waited for (`Drop`); the length is the buffer's.
        let asked = unsafe {
            ReadDirectoryChangesW(
                raw(&self.directory),
                self.changes.as_mut_ptr().cast::<c_void>(),
                u32::try_from(ROOM).unwrap_or(u32::MAX),
                FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
                std::ptr::null_mut(),
                &raw mut *self.overlapped,
                None,
            )
        };
        if asked == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != i32::try_from(ERROR_IO_PENDING).ok() {
                return Err(error);
            }
        }
        self.reading = true;
        Ok(())
    }

    /// Whether the completed read names the record, or overflowed.
    fn names_record(&mut self) -> bool {
        self.reading = false;
        let mut moved = 0u32;
        // SAFETY: the read has completed (its event is raised); this only
        // collects its count.
        let collected = unsafe {
            GetOverlappedResult(
                raw(&self.directory),
                &raw const *self.overlapped,
                &raw mut moved,
                FALSE,
            )
        };
        // More changes than the buffer holds (`ERROR_NOTIFY_ENUM_DIR`, or
        // nothing returned): any of them could be the record's.
        if collected == 0 || moved == 0 {
            return true;
        }
        let bytes: Vec<u8> = self
            .changes
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .collect();
        let word = |at: usize| {
            bytes
                .get(at..at + 4)
                .and_then(|four| <[u8; 4]>::try_from(four).ok())
                .map(u32::from_ne_bytes)
        };
        let mut at = 0usize;
        loop {
            let (Some(next), Some(length)) = (word(at), word(at + 8)) else {
                return false;
            };
            let start = at + 12;
            let end = start + usize::try_from(length).unwrap_or(usize::MAX - start);
            let name: Vec<u16> = bytes
                .get(start..end)
                .unwrap_or_default()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_ne_bytes(*pair))
                .collect();
            if name == self.record {
                return true;
            }
            if next == 0 {
                return false;
            }
            at += usize::try_from(next).unwrap_or(ROOM);
        }
    }

    /// Waits until the record changes or the supervisor followed ends, and
    /// says which; `None` once stopped, or where the folder cannot be read.
    pub fn wait(&mut self) -> Option<Seen> {
        loop {
            self.read().ok()?;
            let mut handles = vec![raw(&self.stop), raw(&self.done)];
            if let Some(supervisor) = &self.supervisor {
                handles.push(raw(supervisor));
            }
            // SAFETY: every handle is open and owned by this watch for the
            // wait; at most three.
            let woke = unsafe {
                WaitForMultipleObjects(
                    u32::try_from(handles.len()).unwrap_or(3),
                    handles.as_ptr(),
                    FALSE,
                    INFINITE,
                )
            };
            match woke.checked_sub(WAIT_OBJECT_0) {
                Some(1) => {
                    if self.names_record() {
                        return Some(Seen::Record);
                    }
                }
                Some(2) => {
                    self.supervisor = None;
                    return Some(Seen::Ended);
                }
                // Stopped, or the wait itself failed.
                _ => return None,
            }
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        if self.reading {
            // SAFETY: the read is this watch's own; cancelling it and
            // waiting for it to complete means Windows writes nothing into
            // the buffer once it goes.
            unsafe { CancelIoEx(raw(&self.directory), &raw const *self.overlapped) };
            let mut moved = 0u32;
            // SAFETY: as above; the wait returns once the cancelled read
            // has completed.
            unsafe {
                GetOverlappedResult(
                    raw(&self.directory),
                    &raw const *self.overlapped,
                    &raw mut moved,
                    TRUE,
                )
            };
        }
    }
}
