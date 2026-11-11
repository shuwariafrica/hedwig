//! What Windows lets this process read of another that holds a source - the
//! process listening at its port or serving its pipe - and nothing more.
//!
//! The process is opened for the limited query right and its token for query
//! and duplication; an identification copy is checked against the person's
//! own pipe descriptor. Where Windows will not open them, the system's list
//! of processes still gives the session and the program's name.

use std::io;

use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFO_EXW,
    WTSEnumerateProcessesExW, WTSFreeMemoryExW, WTSTypeProcessInfoLevel1,
};

use crate::process::Process;
use crate::token::{Sid, Token, wide_length};

/// What a holder's token is to the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Windows' own check admits it against the person's own pipe descriptor.
    Person,
    /// The person's account, which the check refuses.
    Confined,
    /// Another account.
    Another,
}

/// What was read of a holder's token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRead {
    pub standing: Standing,
    /// The logon session (`AuthenticationId`).
    pub logon: u64,
    pub over_the_network: bool,
    pub elevated: bool,
}

/// What Windows let this process read of a holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// The file it runs from where the process opened, else the name the
    /// system lists it under; `None` where it has gone.
    pub program: Option<String>,
    pub session: Option<u32>,
    /// `None` where Windows would not open the process or its token.
    pub token: Option<TokenRead>,
}

/// Reads `process`, which holds a source, for `person`, the account the core
/// runs as.
pub fn read(process: u32, person: &Sid) -> Read {
    let opened = Process::open(process).ok();
    let program = opened
        .as_ref()
        .and_then(|opened| opened.program().ok())
        .map(|path| path.to_string_lossy().into_owned());
    let token = opened
        .as_ref()
        .and_then(|opened| opened.token_to_check().ok())
        .and_then(|token| token_read(&token, person).ok());
    let mut session = 0u32;
    // SAFETY: `session` is a valid out pointer; the call opens the process
    // itself and fails where it may not.
    let session = (opened.is_some()
        && unsafe { ProcessIdToSessionId(process, &raw mut session) } != 0)
        .then_some(session);
    match (program, session) {
        (Some(program), Some(session)) => Read {
            program: Some(program),
            session: Some(session),
            token,
        },
        (program, session) => {
            let listed = listed(process).ok().flatten();
            Read {
                program: program.or_else(|| listed.as_ref().map(|(_, name)| name.clone())),
                session: session.or_else(|| listed.map(|(session, _)| session)),
                token,
            }
        }
    }
}

fn token_read(token: &Token, person: &Sid) -> io::Result<TokenRead> {
    let standing = if token.is_the_person(person)? {
        Standing::Person
    } else if token.user()? == *person {
        Standing::Confined
    } else {
        Standing::Another
    };
    let read = token.standing()?;
    Ok(TokenRead {
        standing,
        logon: read.logon,
        over_the_network: token.over_the_network()?,
        elevated: token.elevated()?,
    })
}

/// The session and image name the system lists `process` under, which it
/// gives for any process whether or not the caller may open it.
fn listed(process: u32) -> io::Result<Option<(u32, String)>> {
    let mut level = WTSTypeProcessInfoLevel1.cast_unsigned();
    let mut info = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: the out pointers are valid; the memory returned is freed
    // below with the level and count it was returned with.
    let listed = unsafe {
        WTSEnumerateProcessesExW(
            WTS_CURRENT_SERVER_HANDLE,
            &raw mut level,
            u32::MAX - 1,
            &raw mut info,
            &raw mut count,
        )
    };
    if listed == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call wrote `count` level-1 records at `info`.
    let records =
        unsafe { std::slice::from_raw_parts(info.cast::<WTS_PROCESS_INFO_EXW>(), count as usize) };
    let found = records
        .iter()
        .find(|record| record.ProcessId == process)
        .map(|record| {
            // SAFETY: the name is NUL-terminated and lies in the records'
            // memory, alive until it is freed below.
            let length = unsafe { wide_length(record.pProcessName) };
            // SAFETY: as above, `length` units are readable there.
            let units = unsafe { std::slice::from_raw_parts(record.pProcessName, length) };
            let name = String::from_utf16_lossy(units);
            (record.SessionId, name)
        });
    // SAFETY: the memory was returned by the enumeration above.
    unsafe { WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, info.cast(), count) };
    Ok(found)
}
