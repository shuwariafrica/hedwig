//! Finding the program a route's client is started by, from its name.
//!
//! The name is looked for in the absolute folders of the search path the
//! person's own programs are found on, by Windows' own search, and the whole
//! path found is what a process is started from. The current folder is never
//! searched: `SearchPathW` given no folders looks there first by default, and
//! the core's current folder is whatever started it.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::Storage::FileSystem::SearchPathW;

use crate::raw::{code, wide};

/// What the search fails with when no folder holds the program.
const ERROR_FILE_NOT_FOUND: u32 = 2;

#[derive(Debug)]
pub enum SearchError {
    /// No absolute folder of the search path holds a program of that name.
    Absent,
    /// The search path is unset, or holds no absolute folder.
    NoSearchPath,
    Other(io::Error),
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SearchError::Absent => f.write_str("no folder on the search path holds it"),
            SearchError::NoSearchPath => f.write_str("the search path names no folder"),
            SearchError::Other(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SearchError::Other(error) => Some(error),
            _ => None,
        }
    }
}

/// The program `name` names, on this process's search path.
///
/// # Errors
///
/// [`SearchError`] saying why none was found.
pub fn program(name: &str) -> Result<PathBuf, SearchError> {
    let path = std::env::var_os("PATH").ok_or(SearchError::NoSearchPath)?;
    program_on(name, &path)
}

/// The program `name` names, looked for in the absolute folders of
/// `search`, a list written as the search path is. A name with no extension
/// is looked for as an `.exe`.
///
/// # Errors
///
/// [`SearchError`] saying why none was found.
pub fn program_on(name: &str, search: &OsStr) -> Result<PathBuf, SearchError> {
    let folders: Vec<PathBuf> = std::env::split_paths(search)
        .filter(|folder| folder.is_absolute())
        .collect();
    if folders.is_empty() {
        return Err(SearchError::NoSearchPath);
    }
    let folders = std::env::join_paths(folders)
        .map_err(|error| SearchError::Other(io::Error::other(error)))?;
    let (folders, name, extension) = (wide(&folders), wide(name), wide(".exe"));
    let mut found = vec![0u16; 260];
    loop {
        let room = u32::try_from(found.len()).unwrap_or(u32::MAX);
        // SAFETY: the three strings are NUL-terminated, `found` is `room`
        // units long, and no pointer to the file part is asked for.
        let length = unsafe {
            SearchPathW(
                folders.as_ptr(),
                name.as_ptr(),
                extension.as_ptr(),
                room,
                found.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        };
        if length == 0 {
            let error = io::Error::last_os_error();
            return Err(match code(&error) {
                ERROR_FILE_NOT_FOUND => SearchError::Absent,
                _ => SearchError::Other(error),
            });
        }
        // Too small, the call answers the room it needs, terminator included.
        if length >= room {
            found.resize(length as usize, 0);
            continue;
        }
        let units = found.get(..length as usize).unwrap_or_default();
        return Ok(PathBuf::from(OsString::from_wide(units)));
    }
}
