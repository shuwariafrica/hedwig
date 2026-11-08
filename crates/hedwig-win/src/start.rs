//! Starting a process that holds nothing of this one's: a supervisor apart
//! from the session that asked for it ([`apart`]), and a channel's client in
//! the job its remote is known by ([`held`]).
//!
//! A process started the ordinary way inherits every handle its parent holds
//! that may be inherited, not only the three it is given as its standard
//! ones. A supervisor started by a command would hold that command's own
//! output, and whoever reads that output - a shell, an SSH session, a script -
//! would wait for as long as Hedwig runs. Here the new process is given a
//! list: a pipe for what it says first, nothing to read, nowhere for errors,
//! and no other handle.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::io::{self, PipeReader, PipeWriter};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::process::Job;
use crate::raw::{owned, wide};

const SPACE: u16 = 0x20;
const TAB: u16 = 0x09;
const QUOTE: u16 = 0x22;
const BACKSLASH: u16 = 0x5c;

/// Appends `argument` so that the program's runtime reads it back as one
/// argument, whatever it contains.
fn quoted(argument: &OsStr, line: &mut Vec<u16>) {
    let units: Vec<u16> = argument.encode_wide().collect();
    let plain = !units.is_empty() && !units.iter().any(|unit| [SPACE, TAB, QUOTE].contains(unit));
    if plain {
        line.extend(units);
        return;
    }
    line.push(QUOTE);
    let mut backslashes = 0usize;
    for unit in units {
        if unit == BACKSLASH {
            backslashes += 1;
        } else {
            if unit == QUOTE {
                // Backslashes before a quote are read in pairs, and one more
                // makes the quote itself part of the argument.
                line.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(unit);
    }
    // Those before the closing quote are read in pairs too.
    line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
    line.push(QUOTE);
}

/// The command line that starts `program` with exactly `arguments`.
pub fn command_line(program: &Path, arguments: &[OsString]) -> Vec<u16> {
    let mut line = vec![QUOTE];
    line.extend(program.as_os_str().encode_wide());
    line.push(QUOTE);
    for argument in arguments {
        line.push(SPACE);
        quoted(argument, &mut line);
    }
    line.push(0);
    line
}

fn inheritable(handle: HANDLE) -> io::Result<()> {
    // SAFETY: the handle is open and owned by the caller.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The list that names the only handles a new process inherits and, for a
/// channel's client, the job it is created in. The memory is the system's to
/// lay out and this value's to keep until the process has been created.
struct Only {
    memory: Vec<usize>,
    /// The handles the list points at, which must outlive it.
    handles: Box<[HANDLE]>,
    /// The jobs the list points at, likewise.
    jobs: Box<[HANDLE]>,
}

impl Only {
    fn new(handles: Box<[HANDLE]>, jobs: Box<[HANDLE]>) -> io::Result<Only> {
        let count = if jobs.is_empty() { 1 } else { 2 };
        let mut size = 0usize;
        // SAFETY: a null list asks how much memory `count` attributes need;
        // the call reports it in `size` and fails, as documented.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &raw mut size) };
        let mut memory = vec![0usize; size.div_ceil(size_of::<usize>())];
        let list: LPPROC_THREAD_ATTRIBUTE_LIST = memory.as_mut_ptr().cast();
        // SAFETY: `memory` is at least `size` bytes, aligned for pointers.
        if unsafe { InitializeProcThreadAttributeList(list, count, 0, &raw mut size) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let only = Only {
            memory,
            handles,
            jobs,
        };
        only.attribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &only.handles)?;
        if !only.jobs.is_empty() {
            only.attribute(PROC_THREAD_ATTRIBUTE_JOB_LIST, &only.jobs)?;
        }
        Ok(only)
    }

    fn attribute(&self, which: u32, values: &[HANDLE]) -> io::Result<()> {
        // SAFETY: the list was initialised in `new` with room for this
        // attribute; the value is an array of handles this value owns and
        // keeps alive as long as the list.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                self.memory.as_ptr().cast_mut().cast(),
                0,
                which as usize,
                values.as_ptr().cast(),
                size_of_val::<[HANDLE]>(values),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if updated == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.memory.as_mut_ptr().cast()
    }
}

impl Drop for Only {
    fn drop(&mut self) {
        // SAFETY: the list was initialised in `new` and is deleted once.
        unsafe { DeleteProcThreadAttributeList(self.list()) };
    }
}

/// A process started by [`apart`].
#[derive(Debug)]
pub struct Started {
    process: OwnedHandle,
    /// What the process writes to its standard output.
    pub said: PipeReader,
}

impl Started {
    /// Waits for the process to end and gives its exit status.
    pub fn wait(&self) -> io::Result<u32> {
        // SAFETY: the handle is the process this value owns.
        unsafe { WaitForSingleObject(self.process.as_raw_handle(), INFINITE) };
        let mut status = 0u32;
        // SAFETY: as above; `status` is writable.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &raw mut status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(status)
    }
}

/// Starts `program` with `arguments` and the creation `flags`, holding no
/// handle of this process's but three made for it: nothing to read, a pipe
/// for its standard output, and nowhere for its errors.
///
/// # Errors
///
/// What the system said when the process could not be created; access
/// denied, among others, when `flags` ask to leave a job that does not allow
/// it.
pub fn apart(program: &Path, arguments: &[OsString], flags: u32) -> io::Result<Started> {
    let (said, says) = io::pipe()?;
    let nowhere = OpenOptions::new().read(true).write(true).open("NUL")?;
    inheritable(says.as_raw_handle())?;
    inheritable(nowhere.as_raw_handle())?;
    let mut only = Only::new(
        Box::new([nowhere.as_raw_handle(), says.as_raw_handle()]),
        Box::new([]),
    )?;

    // SAFETY: all-zero is a valid value of the structure, filled in below.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or_default();
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = nowhere.as_raw_handle();
    startup.StartupInfo.hStdOutput = says.as_raw_handle();
    startup.StartupInfo.hStdError = nowhere.as_raw_handle();
    startup.lpAttributeList = only.list();
    let application = wide(program);
    let mut line = command_line(program, arguments);
    // SAFETY: all-zero is a valid value to be filled in.
    let mut started: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: both strings are NUL-terminated and the command line is a
    // mutable buffer; handles are inherited, and only those in the list,
    // which outlives the call; the environment and directory are this
    // process's; the two structures are valid for the call.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            flags | EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            std::ptr::null(),
            (&raw const startup).cast(),
            &raw mut started,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(owned(started.hThread));
    // This process's own ends of what it gave away close here, so the pipe
    // ends when the new process closes its end.
    drop((says, nowhere, only));
    Ok(Started {
        process: owned(started.hProcess)?,
        said,
    })
}

/// The variables a process is started with: this process's own, less some
/// and with others set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment(BTreeMap<Vec<u16>, (OsString, OsString)>);

impl Environment {
    /// This process's own variables, as they are now.
    pub fn own() -> Environment {
        let mut environment = Environment(BTreeMap::new());
        for (name, value) in std::env::vars_os() {
            environment.set(name, value);
        }
        environment
    }

    /// The name as Windows compares names: without regard to case.
    fn folded(name: &OsStr) -> Vec<u16> {
        name.to_string_lossy()
            .to_uppercase()
            .encode_utf16()
            .collect()
    }

    fn set(&mut self, name: OsString, value: OsString) {
        self.0.insert(Environment::folded(&name), (name, value));
    }

    #[must_use]
    pub fn with(mut self, name: &str, value: &str) -> Environment {
        self.set(OsString::from(name), OsString::from(value));
        self
    }

    #[must_use]
    pub fn with_os(mut self, name: &str, value: &OsStr) -> Environment {
        self.set(OsString::from(name), value.to_owned());
        self
    }

    #[must_use]
    pub fn without(mut self, name: &str) -> Environment {
        self.0.remove(&Environment::folded(OsStr::new(name)));
        self
    }

    pub fn get(&self, name: &str) -> Option<&OsStr> {
        self.0
            .get(&Environment::folded(OsStr::new(name)))
            .map(|(_, value)| value.as_os_str())
    }

    /// The block `CreateProcessW` takes: `name=value`, each ended by a NUL,
    /// in the order Windows keeps them, and one NUL more.
    fn block(&self) -> Vec<u16> {
        let mut block = Vec::new();
        for (name, value) in self.0.values() {
            block.extend(name.encode_wide());
            block.push(u16::from(b'='));
            block.extend(value.encode_wide());
            block.push(0);
        }
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        block
    }
}

/// A process started by [`held`].
#[derive(Debug)]
pub struct Held {
    process: OwnedHandle,
    id: u32,
}

impl Held {
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Waits for the process to end and gives its exit status.
    pub fn wait(&self) -> io::Result<u32> {
        // SAFETY: the handle is the process this value owns.
        unsafe { WaitForSingleObject(self.process.as_raw_handle(), INFINITE) };
        let mut status = 0u32;
        // SAFETY: as above; `status` is writable.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &raw mut status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(status)
    }

    /// Ends the process with `status`, leaving the rest of its job running.
    /// A process that has already ended is left as it is.
    ///
    /// # Errors
    ///
    /// What the system said.
    pub fn end(&self, status: u32) -> io::Result<()> {
        // SAFETY: the handle is the process this value owns, opened with every
        // right its creator has, terminate among them.
        if unsafe { TerminateProcess(self.process.as_raw_handle(), status) } == 0 {
            let error = io::Error::last_os_error();
            // Access is denied to a process that has already ended.
            if self.finished() {
                return Ok(());
            }
            return Err(error);
        }
        Ok(())
    }

    fn finished(&self) -> bool {
        // SAFETY: the handle is the process this value owns; a zero wait
        // only asks whether it is signalled.
        unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) == WAIT_OBJECT_0 }
    }
}

/// Starts `program` with `arguments` inside `job`, with `environment` as its
/// variables, a console no window shows, and no handle of this process's but
/// three made for it: nothing to read, nowhere to print, and a pipe for its
/// errors, whose reading end is returned beside it.
///
/// The process is created in the job: it never exists outside it, so nothing
/// it starts can, and nothing is left behind if this process ends between
/// two calls.
///
/// # Errors
///
/// What the system said when the process could not be created.
pub fn held(
    program: &Path,
    arguments: &[OsString],
    environment: &Environment,
    job: &Job,
) -> io::Result<(Held, PipeReader)> {
    let (errors, errs) = io::pipe()?;
    let nowhere = OpenOptions::new().read(true).write(true).open("NUL")?;
    let held = within(program, arguments, environment, job, &nowhere, &errs)?;
    Ok((held, errors))
}

/// As [`held`], for a program asked something: what it prints and what it
/// says of its errors are each read from a pipe of their own, returned in
/// that order.
///
/// # Errors
///
/// What the system said when the process could not be created.
pub fn consulted(
    program: &Path,
    arguments: &[OsString],
    environment: &Environment,
    job: &Job,
) -> io::Result<(Held, PipeReader, PipeReader)> {
    let (said, says) = io::pipe()?;
    let (errors, errs) = io::pipe()?;
    let held = within(program, arguments, environment, job, &says, &errs)?;
    Ok((held, said, errors))
}

/// As [`consulted`], for a program given something to read: the writing
/// end of its input comes first, and it reads to the end once that is
/// dropped.
///
/// # Errors
///
/// What the system said when the process could not be created.
pub fn fed(
    program: &Path,
    arguments: &[OsString],
    environment: &Environment,
    job: &Job,
) -> io::Result<(Held, PipeWriter, PipeReader, PipeReader)> {
    let (reads, input) = io::pipe()?;
    let (said, says) = io::pipe()?;
    let (errors, errs) = io::pipe()?;
    let held = created(
        program,
        arguments,
        environment,
        Some(job),
        CREATE_NO_WINDOW,
        [&reads, &says, &errs],
    )?;
    Ok((held, input, said, errors))
}

/// As [`fed`], for a program of the person's own, started with `flags` -
/// [`crate::process::LEAVING`] to leave every job this process is in, as the
/// person's own tools are left - and nowhere for its errors: the writing end
/// of what it reads, and what it prints.
///
/// # Errors
///
/// What the system said when the process could not be created; access
/// denied when `flags` ask to leave a job that does not allow it.
pub fn given(
    program: &Path,
    arguments: &[OsString],
    environment: &Environment,
    flags: u32,
) -> io::Result<(Held, PipeWriter, PipeReader)> {
    let (reads, input) = io::pipe()?;
    let (said, says) = io::pipe()?;
    let nowhere = OpenOptions::new().read(true).write(true).open("NUL")?;
    let held = created(
        program,
        arguments,
        environment,
        None,
        flags,
        [&reads, &says, &nowhere],
    )?;
    Ok((held, input, said))
}

/// Creates `program` inside `job` with `output` and `errors` as its standard
/// handles, nothing to read, and no other handle of this process's.
fn within(
    program: &Path,
    arguments: &[OsString],
    environment: &Environment,
    job: &Job,
    output: &impl AsRawHandle,
    errors: &impl AsRawHandle,
) -> io::Result<Held> {
    let nowhere = OpenOptions::new().read(true).write(true).open("NUL")?;
    let input = nowhere.as_raw_handle();
    let handles = [input, output.as_raw_handle(), errors.as_raw_handle()];
    created_from(
        program,
        arguments,
        environment,
        Some(job),
        CREATE_NO_WINDOW,
        handles,
    )
}

/// Creates `program` with `standard` - its input, output and errors - and no
/// other handle of this process's, inside `job` where one is given, with
/// the creation `flags`.
fn created(
    program: &Path,
    arguments: &[OsString],
    environment: &Environment,
    job: Option<&Job>,
    flags: u32,
    standard: [&dyn AsRawHandle; 3],
) -> io::Result<Held> {
    let handles = standard.map(AsRawHandle::as_raw_handle);
    created_from(program, arguments, environment, job, flags, handles)
}

fn created_from(
    program: &Path,
    arguments: &[OsString],
    environment: &Environment,
    job: Option<&Job>,
    flags: u32,
    handles: [HANDLE; 3],
) -> io::Result<Held> {
    for handle in handles {
        inheritable(handle)?;
    }
    let [input, output, errors] = handles;
    let jobs: Box<[HANDLE]> = match job {
        Some(job) => Box::new([job.raw()]),
        None => Box::new([]),
    };
    let mut only = Only::new(Box::new(handles), jobs)?;

    // SAFETY: all-zero is a valid value of the structure, filled in below.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or_default();
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = output;
    startup.StartupInfo.hStdError = errors;
    startup.lpAttributeList = only.list();
    let application = wide(program);
    let mut line = command_line(program, arguments);
    let block = environment.block();
    // SAFETY: all-zero is a valid value to be filled in.
    let mut started: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: both strings are NUL-terminated and the command line is a
    // mutable buffer; handles are inherited, and only those in the list,
    // which outlives the call with any job it names; the environment is a
    // block of NUL-terminated UTF-16 strings ended by one more NUL, as the
    // flag says; the directory is this process's; the two structures are
    // valid for the call.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            flags | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            block.as_ptr().cast(),
            std::ptr::null(),
            (&raw const startup).cast(),
            &raw mut started,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(owned(started.hThread));
    // The caller's ends are dropped by the caller and the list closes here,
    // so each pipe ends when the new process closes its end.
    drop(only);
    Ok(Held {
        process: owned(started.hProcess)?,
        id: started.dwProcessId,
    })
}
