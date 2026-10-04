//! What the suites need that Hedwig never does: a folder of their own that
//! is gone afterwards, a process started with less than the suite has, a
//! remote's readiness report for a suite with no remote, and readiness as a
//! run against a real remote performs it.

pub mod android;
pub mod bench;
pub mod control;
pub mod experiment;
pub mod lower;
pub mod tap;
pub mod unix;

/// What `child probe` and `child halt` end with. A client that was lowered
/// cannot write where the suite reads, so it says what it met by how it ends.
pub mod met {
    /// The pipe was opened and the core greeted the client.
    pub const GREETED: u8 = 0;
    pub const ABSENT: u8 = 10;
    pub const BUSY: u8 = 11;
    /// The pipe does not admit the client.
    pub const DENIED: u8 = 12;
    pub const NOT_OURS: u8 = 13;
    pub const OTHER: u8 = 14;
    /// Hedwig was stopped.
    pub const STOPPED: u8 = 0;
    pub const NOTHING_TO_STOP: u8 = 20;
    /// No core answers and the supervisor runs above the client.
    pub const ABOVE: u8 = 23;
    pub const NOT_STOPPED: u8 = 24;
}

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    FILETIME, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

/// Waits up to `limit` for the process numbered `process` and created at
/// `created` to end. Returns whether it has, or was never that process.
pub fn ended_within(process: u32, created: u64, limit: Duration) -> bool {
    let rights = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    // SAFETY: opening by number, to query and to wait.
    let opened = unsafe { OpenProcess(rights, 0, process) };
    if opened.is_null() {
        return true;
    }
    // SAFETY: the handle was just opened and nothing else holds it.
    let handle = unsafe { OwnedHandle::from_raw_handle(opened) };
    let mut times = [FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }; 4];
    let [creation, exit, kernel, user] = &mut times;
    // SAFETY: the handle may query the process, and each pointer is to a
    // distinct, writable `FILETIME`.
    let asked = unsafe { GetProcessTimes(handle.as_raw_handle(), creation, exit, kernel, user) };
    let at = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if asked == 0 || at != created {
        return true;
    }
    let limit = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: the handle carries the right to wait on the process.
    unsafe { WaitForSingleObject(handle.as_raw_handle(), limit) == WAIT_OBJECT_0 }
}

/// Marks a handle as one every process this one starts the ordinary way
/// inherits: what a shell's or an SSH session's own handles are to the
/// commands it runs.
pub fn inheritable(handle: &impl AsRawHandle) -> io::Result<()> {
    let handle = handle.as_raw_handle();
    // SAFETY: the handle is open for as long as the borrow it came from.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Puts this process in a job of its own that its children may leave, as
/// the supervisor's job lets the core's: what Hedwig starts that is the
/// person's - their browser, their agent - then leaves every job it is in.
/// The job stays for the life of the process.
pub fn leavable_here() -> io::Result<()> {
    // SAFETY: an unnamed job with default security; both may be null.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the job was just created and nothing else holds it; owning it
    // closes it when this returns, which leaves the process in it.
    let job = unsafe { OwnedHandle::from_raw_handle(job) };
    // SAFETY: all-zero is a valid value of the structure: no limits.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or_default();
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
    // SAFETY: takes no argument and returns a pseudo-handle, never closed.
    let this = unsafe { GetCurrentProcess() };
    // SAFETY: the job is open, and the pseudo-handle names this process.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), this) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Makes `home` a `GnuPG` home whose scdaemon opens no reader: its PC/SC
/// library is a file that does not exist and its own CCID driver is off, so
/// whatever any agent of the home is asked, no reader of the person's is
/// listed and no card of theirs is reached (`scd/apdu.c`, `pcsc_init` and
/// `apdu_dev_list_start`). Every `SCD` command a card would answer is then
/// `No service`. The scdaemon logs to [`SCDAEMON_LOG`] in the home.
///
/// # Errors
///
/// When the home or its `scdaemon.conf` cannot be written.
pub fn readerless(home: &Path) -> io::Result<()> {
    std::fs::create_dir_all(home)?;
    std::fs::write(
        home.join("scdaemon.conf"),
        format!(
            "disable-ccid\npcsc-driver {}\nlog-file {}\n",
            home.join("no-pcsc-driver.dll").display(),
            home.join(SCDAEMON_LOG).display()
        ),
    )
}

/// Where the scdaemon of a [`readerless`] home logs.
pub const SCDAEMON_LOG: &str = "scdaemon.log";

/// The folder holding Git for Windows' own `git` and `curl`, as its shell
/// names it: `/clangarm64/bin` from the ARM64 installer, `/mingw64/bin` from
/// the x64 one.
#[must_use]
pub fn git_tools() -> &'static str {
    if Path::new(r"C:\Program Files\Git\clangarm64\bin").is_dir() {
        "/clangarm64/bin"
    } else {
        "/mingw64/bin"
    }
}

/// A folder under the temporary directory, removed when dropped.
#[derive(Debug)]
pub struct Folder(PathBuf);

static NEXT: AtomicU32 = AtomicU32::new(0);

impl Folder {
    /// # Panics
    ///
    /// When the folder cannot be made: a suite that cannot write has nothing
    /// to say.
    #[allow(clippy::panic, reason = "test scaffolding")]
    pub fn new(purpose: &str) -> Folder {
        let mut drawn = [0u8; 4];
        let _ = hedwig_win::random::fill(&mut drawn);
        let path = std::env::temp_dir().join(format!(
            "hedwig-design-{purpose}-{}-{}-{:08x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            u32::from_le_bytes(drawn)
        ));
        if let Err(error) = std::fs::create_dir_all(&path) {
            panic!("{}: {error}", path.display());
        }
        Folder(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        // A test that failed may have left its Hedwig running; nothing the
        // suite starts outlives it. A record a test wrote by hand can name
        // the suite's own process, which is not a Hedwig to stop.
        if let Ok(hedwig_client::Standing::Known(running)) = hedwig_client::look(&self.0)
            && running.supervisor.process != std::process::id()
        {
            let _ = hedwig_client::stop(&hedwig_client::Standing::Known(running));
            hedwig_client::released_within(&self.0, Duration::from_secs(30));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a Linux remote's readiness reports when every far end in `serving`
/// is free: a socket's path with nothing at it, a port nothing listens on.
pub fn placing(serving: &[hedwig_model::trail::Serving]) -> hedwig_core::dispatch::Told {
    use hedwig_core::survey::{Answer, At, Dialect, Place, Report};
    use hedwig_model::trail::Binding;
    let answers = serving
        .iter()
        .map(|serving| {
            let answer = match &serving.binding {
                Binding::Socket(path) | Binding::SocketFile { file: path, .. } => Answer {
                    place: Some(Place {
                        path: path.as_str().as_bytes().to_vec(),
                        at: Some(At::Free),
                        ..Place::default()
                    }),
                    ..Answer::default()
                },
                Binding::Port(port) => Answer {
                    listeners: [(*port, false)].into_iter().collect(),
                    ..Answer::default()
                },
            };
            (serving.capability.clone(), answer)
        })
        .collect();
    let kernel = hedwig_model::text::Kernel::try_from("Linux")
        .unwrap_or_else(|_| unreachable!("a fixed kernel name is valid"));
    hedwig_core::dispatch::Told::Surveyed {
        report: Ok(Report {
            dialect: Dialect::Posix,
            kernel,
            shell: b"/bin/bash".to_vec(),
            answers,
            issued: None,
        }),
        theirs: Vec::new(),
    }
}
