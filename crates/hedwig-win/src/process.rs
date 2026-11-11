//! Processes: the job a supervisor keeps its core in, how one process is told
//! from a later one with the same number, and how a start leaves the job of
//! the session that made it.

use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::process::Child;

use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_NO_MORE_FILES, FILETIME, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, RtlNtStatusToDosError, SetHandleInformation, UNICODE_STRING,
};
use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS,
    GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess,
};
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

use crate::raw::{Local, code, owned};
use crate::token::{Token, wide_length};

/// Creation flags for a process that must outlive the terminal that starts
/// it: no console of its parent's, no share in its parent's Ctrl+C.
pub const DETACHED: u32 = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;

/// [`DETACHED`], and out of the job its parent is in. An SSH session's job
/// ends every process in it when the session closes, and allows this.
pub const APART: u32 = DETACHED | CREATE_BREAKAWAY_FROM_JOB;

/// Creation flags for a tool asked something: no window, in this process's
/// jobs.
pub const UNSEEN: u32 = CREATE_NO_WINDOW;

/// [`UNSEEN`], and outside every job this process is in, where the job allows
/// it ([`Job::leavable`]): for what the person's own tools start that is the
/// person's, such as their `GnuPG`'s agent.
pub const LEAVING: u32 = CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB;

/// The status a process ends with when the job that holds it is ended for
/// not answering.
pub const ENDED: u32 = 0xc000_013a;

/// As [`Job::new`] makes one, a job ends every process in it when its last
/// handle closes, and nothing started inside can leave.
#[derive(Debug)]
pub struct Job(OwnedHandle, Leaving);

/// Whether a process in a job may start one outside it by asking to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leaving {
    Refused,
    Allowed,
}

impl Job {
    pub fn new() -> io::Result<Job> {
        Job::limited(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    }

    /// As [`Job::new`], and a process in it may start one outside it by
    /// asking to ([`LEAVING`]). Nothing leaves without asking.
    pub fn leavable() -> io::Result<Job> {
        Job::limited(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK)
    }

    /// A job to hold one process and what it starts inside this one, to be
    /// ended apart from it. It ends nothing when its last handle closes. It
    /// allows leaving as this job does, since the system reads that limit
    /// from the job a process is immediately in: allowed there, a process
    /// that asks is moved up only as far as the first job refusing it.
    pub(crate) fn within(&self) -> io::Result<Job> {
        Job::limited(match self.1 {
            Leaving::Allowed => JOB_OBJECT_LIMIT_BREAKAWAY_OK,
            Leaving::Refused => 0,
        })
    }

    fn limited(flags: u32) -> io::Result<Job> {
        // SAFETY: an unnamed job with default security; both may be null.
        let job = owned(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })?;
        // SAFETY: all-zero is a valid value of the structure: no limits.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = flags;
        let size =
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or_default();
        // SAFETY: `limits` is the structure the class names, `size` bytes long.
        let set = unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size,
            )
        };
        if set == 0 {
            return Err(io::Error::last_os_error());
        }
        let leaving = if flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK == 0 {
            Leaving::Refused
        } else {
            Leaving::Allowed
        };
        Ok(Job(job, leaving))
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }

    /// Whether `process` is in the job: a fact the kernel keeps, read now.
    pub fn includes(&self, process: &Process) -> io::Result<bool> {
        let mut inside = 0;
        // SAFETY: both are open handles, the process's carrying the limited
        // query right the call asks for; `inside` is a valid out pointer.
        let asked = unsafe {
            IsProcessInJob(
                process.0.as_raw_handle(),
                self.0.as_raw_handle(),
                &raw mut inside,
            )
        };
        if asked == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(inside != 0)
    }

    /// Puts `child`, and everything it starts from now on, in the job.
    pub fn hold(&self, child: &Child) -> io::Result<()> {
        // SAFETY: both are open handles; the child's carries every right.
        if unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), child.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn holds(&self, child: &Child) -> io::Result<bool> {
        let mut inside = 0;
        // SAFETY: both are open handles and `inside` a valid out pointer.
        let asked = unsafe {
            IsProcessInJob(
                child.as_raw_handle(),
                self.0.as_raw_handle(),
                &raw mut inside,
            )
        };
        if asked == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(inside != 0)
    }

    /// Ends every process in the job with [`ENDED`].
    pub fn end(&self) -> io::Result<()> {
        self.end_with(ENDED)
    }

    /// Ends every process in the job with `status`.
    pub(crate) fn end_with(&self, status: u32) -> io::Result<()> {
        // SAFETY: the handle is a job this value owns.
        if unsafe { TerminateJobObject(self.0.as_raw_handle(), status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// A process opened by its number, to be asked about and nothing more. The
/// right it is opened with is the one [`Job::includes`] and a token read
/// need, and no other.
#[derive(Debug)]
pub struct Process(OwnedHandle);

impl Process {
    /// # Errors
    ///
    /// What the system said: the process has ended, or Windows does not let
    /// this one ask about it.
    pub fn open(process: u32) -> io::Result<Process> {
        // SAFETY: opening by number, to query and nothing else.
        owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process) }).map(Process)
    }

    /// The file the process was started from.
    pub fn program(&self) -> io::Result<PathBuf> {
        let mut path = vec![0u16; 1 << 15];
        let mut length = u32::try_from(path.len()).unwrap_or(u32::MAX);
        // SAFETY: the process handle carries the limited query right the
        // call asks for; `path` is `length` writable units.
        let asked = unsafe {
            QueryFullProcessImageNameW(
                self.0.as_raw_handle(),
                PROCESS_NAME_WIN32,
                path.as_mut_ptr(),
                &raw mut length,
            )
        };
        if asked == 0 {
            return Err(io::Error::last_os_error());
        }
        let units = path.get(..length as usize).unwrap_or_default();
        Ok(PathBuf::from(OsString::from_wide(units)))
    }

    /// The moment the process was created, which with its number names it
    /// and no other.
    ///
    /// # Errors
    ///
    /// What the system said when the process's times could not be read.
    pub fn started(&self) -> io::Result<u64> {
        created(self.0.as_raw_handle())
    }

    /// Whether the process has ended, known only where the system says so.
    #[must_use]
    pub fn has_ended(&self) -> bool {
        status_of(&self.0).is_some_and(|status| status != STILL_ACTIVE)
    }

    /// The arguments it was started with, the program's name first, split as
    /// a Windows program splits its own.
    ///
    /// # Errors
    ///
    /// What the system said: the process has ended, or Windows does not let
    /// this one read them.
    pub fn arguments(&self) -> io::Result<Vec<String>> {
        // The size is asked first: a command line is at most 32,767 units,
        // but a process may have been given a longer block of its own.
        let mut needed = 0u32;
        // SAFETY: a null buffer of no length, with a valid place for the
        // length the system needs.
        unsafe {
            NtQueryInformationProcess(
                self.0.as_raw_handle(),
                ProcessCommandLineInformation,
                std::ptr::null_mut(),
                0,
                &raw mut needed,
            );
        }
        // In eight-byte units, so the structure at its start is aligned.
        let mut block = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let size = u32::try_from(block.len() * 8).unwrap_or(u32::MAX);
        // SAFETY: `block` is `size` writable bytes, aligned for the
        // `UNICODE_STRING` the system writes at its start.
        let status = unsafe {
            NtQueryInformationProcess(
                self.0.as_raw_handle(),
                ProcessCommandLineInformation,
                block.as_mut_ptr().cast(),
                size,
                &raw mut needed,
            )
        };
        if status < 0 {
            // SAFETY: a plain conversion of a status code.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(code.cast_signed()));
        }
        // SAFETY: on success the block starts with a `UNICODE_STRING`.
        let text = unsafe { &*block.as_ptr().cast::<UNICODE_STRING>() };
        if text.Buffer.is_null() {
            return Ok(Vec::new());
        }
        // SAFETY: the buffer, not null, holds `Length` bytes inside the block.
        let line = unsafe { std::slice::from_raw_parts(text.Buffer, usize::from(text.Length) / 2) };
        let line: Vec<u16> = line.iter().copied().chain([0]).collect();
        let mut count = 0;
        // SAFETY: `line` is NUL-terminated and `count` a valid out pointer;
        // the memory returned is freed by `Local`.
        let split = unsafe { CommandLineToArgvW(line.as_ptr(), &raw mut count) };
        if split.is_null() {
            return Err(io::Error::last_os_error());
        }
        let held = Local(split.cast());
        let count = usize::try_from(count).unwrap_or_default();
        // SAFETY: `split` points at `count` pointers, alive until `held` is
        // dropped.
        let pointers = unsafe { std::slice::from_raw_parts(split, count) };
        let arguments = pointers
            .iter()
            .map(|&argument| {
                // SAFETY: a NUL-terminated string, alive until `held` is
                // dropped.
                let length = unsafe { wide_length(argument) };
                // SAFETY: the `length` units before its NUL.
                let units = unsafe { std::slice::from_raw_parts(argument, length) };
                String::from_utf16_lossy(units)
            })
            .collect();
        drop(held);
        Ok(arguments)
    }

    /// The token the process runs with, to be read.
    pub fn token(&self) -> io::Result<Token> {
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: the process handle is open and `handle` a valid place for
        // the opened token.
        if unsafe { OpenProcessToken(self.0.as_raw_handle(), TOKEN_QUERY, &raw mut handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        owned(handle).map(Token::from_handle)
    }

    /// The token the process runs with, opened to be checked against a
    /// file's descriptor ([`Token::may_read`]).
    pub fn token_to_check(&self) -> io::Result<Token> {
        let mut handle: HANDLE = std::ptr::null_mut();
        let wanted = TOKEN_QUERY | TOKEN_DUPLICATE;
        // SAFETY: the process handle is open and `handle` a valid place for
        // the opened token.
        if unsafe { OpenProcessToken(self.0.as_raw_handle(), wanted, &raw mut handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        owned(handle).map(Token::from_handle)
    }
}

/// Whether this process is in any job.
pub fn in_a_job() -> io::Result<bool> {
    let mut inside = 0;
    // SAFETY: the pseudo-handle for this process is always valid.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: a null job asks about any job; `inside` is a valid out pointer.
    if unsafe { IsProcessInJob(process, std::ptr::null_mut(), &raw mut inside) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(inside != 0)
}

fn created(process: HANDLE) -> io::Result<u64> {
    let mut times = [FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }; 4];
    let [creation, exit, kernel, user] = &mut times;
    // SAFETY: the handle may query the process, and each pointer is to a
    // distinct, writable `FILETIME`.
    let asked = unsafe { GetProcessTimes(process, creation, exit, kernel, user) };
    if asked == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// The number of each process running from a file named `image`, its case
/// ignored as a file's name is, the system's own list read once.
///
/// # Errors
///
/// What the system said when the list could not be taken.
pub fn instances_of(image: &str) -> io::Result<Vec<u32>> {
    // SAFETY: a snapshot of every process, tied to no process of ours.
    let snapshot = owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
    // SAFETY: all-zero is a valid entry; its size is set before it is used.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap_or(u32::MAX);
    let mut found = Vec::new();
    // SAFETY: `snapshot` is open and `entry` valid, its size set.
    let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    if !more {
        at_its_end(io::Error::last_os_error())?;
    }
    while more {
        let name = entry.szExeFile;
        let length = name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(name.len());
        if String::from_utf16_lossy(name.get(..length).unwrap_or_default())
            .eq_ignore_ascii_case(image)
        {
            found.push(entry.th32ProcessID);
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
        if !more {
            at_its_end(io::Error::last_os_error())?;
        }
    }
    Ok(found)
}

/// `Ok` where the walk of a snapshot stopped because there is no more of it:
/// a list cut short by anything else would read as agents not running.
fn at_its_end(error: io::Error) -> io::Result<()> {
    if error.raw_os_error() == i32::try_from(ERROR_NO_MORE_FILES).ok() {
        Ok(())
    } else {
        Err(error)
    }
}

/// This process's number and the moment it was created, which together name
/// it and no other.
pub fn own() -> io::Result<(u32, u64)> {
    // SAFETY: the pseudo-handle for this process is always valid.
    let process = unsafe { GetCurrentProcess() };
    Ok((std::process::id(), created(process)?))
}

/// The number of a process this one started, and the moment it was created.
pub fn instance(child: &Child) -> io::Result<(u32, u64)> {
    Ok((child.id(), created(child.as_raw_handle())?))
}

/// What the system reports as the status of a process that has not ended.
const STILL_ACTIVE: u32 = 259;

/// The status of the process behind `handle`, where it can be asked.
fn status_of(handle: &OwnedHandle) -> Option<u32> {
    let mut status = 0u32;
    // SAFETY: the handle may query the process; `status` is writable.
    let asked = unsafe { GetExitCodeProcess(handle.as_raw_handle(), &raw mut status) };
    (asked != 0).then_some(status)
}

/// Whether the process behind `handle` has yet to end.
fn running(handle: &OwnedHandle) -> bool {
    status_of(handle) == Some(STILL_ACTIVE)
}

/// Why a process could not be ended.
#[derive(Debug)]
pub enum EndError {
    /// It has already ended, or its number now belongs to another process.
    Gone,
    /// Windows does not let this process open it: it was started elevated,
    /// or under another logon, and this process was not.
    Above,
    Other(io::Error),
}

impl fmt::Display for EndError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndError::Gone => f.write_str("the process has already ended"),
            EndError::Above => f.write_str("Windows does not let this process end that one"),
            EndError::Other(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for EndError {}

/// Ends the process numbered `process`, if it is still the one created at
/// `at`. Its exit status is `status`.
pub fn end(process: u32, at: u64, status: u32) -> Result<(), EndError> {
    // SAFETY: opening by number, to query and to end.
    let opened = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            0,
            process,
        )
    };
    let handle = owned(opened).map_err(|error| match code(&error) {
        ERROR_ACCESS_DENIED => EndError::Above,
        _ => EndError::Gone,
    })?;
    if created(handle.as_raw_handle()).map_err(EndError::Other)? != at || !running(&handle) {
        return Err(EndError::Gone);
    }
    // SAFETY: the handle carries the right to end the process, and is the
    // process the caller named.
    if unsafe { TerminateProcess(handle.as_raw_handle(), status) } == 0 {
        return Err(EndError::Other(io::Error::last_os_error()));
    }
    Ok(())
}

/// Has a fault end this process at once, with no dialog waiting for someone
/// to dismiss it: a core that faults is ended and started again, and in a
/// session with no desktop nobody could answer.
pub fn quieten() {
    // SAFETY: sets this process's own error mode; the previous mode is not
    // needed.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
}

/// Keeps this process's own standard handles out of every process it starts.
/// A handle a parent passed down stays inheritable, and whatever inherits a
/// pipe keeps it open: a core holding the pipe its supervisor was started
/// with would keep whoever reads that pipe waiting for as long as it runs.
pub fn seal() {
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: asks for one of the three standard handles.
        let handle = unsafe { GetStdHandle(which) };
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            // SAFETY: the handle is one this process was started with.
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
        }
    }
}

/// Takes this process's standard output as a file only the caller holds, so
/// that dropping it closes it. Anything printed afterwards goes nowhere.
pub fn take_output() -> Option<File> {
    // SAFETY: asks for the standard output handle.
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: clears the slot, so nothing else in this process uses the
    // handle after the returned file owns it.
    unsafe { SetStdHandle(STD_OUTPUT_HANDLE, std::ptr::null_mut()) };
    // SAFETY: the handle is open, and with the slot cleared the file is its
    // only owner.
    Some(unsafe { File::from_raw_handle(handle) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_walk_of_a_snapshot_cut_short_is_an_error_and_its_end_is_not() {
        assert!(at_its_end(io::Error::from_raw_os_error(18)).is_ok());
        assert!(at_its_end(io::Error::from_raw_os_error(5)).is_err());
    }
}
