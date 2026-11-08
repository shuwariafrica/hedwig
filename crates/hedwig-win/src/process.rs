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

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, FILETIME, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    SetHandleInformation,
};
use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
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

use crate::raw::{code, owned};
use crate::token::Token;

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

/// A job that ends every process in it when its last handle closes, and that
/// nothing started inside can leave.
#[derive(Debug)]
pub struct Job(OwnedHandle);

impl Job {
    pub fn new() -> io::Result<Job> {
        Job::limited(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    }

    /// As [`Job::new`], and a process in it may start one outside it by
    /// asking to ([`LEAVING`]). Nothing leaves without asking.
    pub fn leavable() -> io::Result<Job> {
        Job::limited(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK)
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
        Ok(Job(job))
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
        // SAFETY: the handle is a job this value owns.
        if unsafe { TerminateJobObject(self.0.as_raw_handle(), ENDED) } == 0 {
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

/// Whether the process behind `handle` has yet to end.
fn running(handle: &OwnedHandle) -> bool {
    /// What the system reports as the status of a process that has not ended.
    const STILL_ACTIVE: u32 = 259;
    let mut status = 0u32;
    // SAFETY: the handle may query the process; `status` is writable.
    let asked = unsafe { GetExitCodeProcess(handle.as_raw_handle(), &raw mut status) };
    asked != 0 && status == STILL_ACTIVE
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
