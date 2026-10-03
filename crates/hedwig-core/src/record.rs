//! The record a supervisor holds for as long as it lives.
//!
//! The file is the claim to being the person's one supervisor and the place
//! a client looks for the core, at once. The supervisor holds it open for
//! reading and claims it with a lock far past its content
//! ([`hedwig_win::file::CLAIM_AT`]), which refuses a second supervisor and,
//! since the holder does not share deletion, keeps anything from removing it.
//! It writes through a handle it closes at once, so a reader that allows no
//! writer beside it - .NET's `File.ReadAllText` - reads it all the same. It
//! stays when its supervisor ends: what it says is what the supervisor it
//! names last wrote, and a reader believes it only while the claim is held.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use hedwig_model::process::{CoreState, Instance, Running};
use hedwig_model::wire::line;
use hedwig_win::file::{HOLDING, claim, open_holding};

use crate::store::Places;

/// How many times a claim that found the record held looks again, and how
/// long it waits between: long enough for a client's look to have passed.
const LOOKS: u32 = 3;
const LOOK: Duration = Duration::from_millis(20);

/// What an open that does not allow for another handle fails with.
const SHARING: i32 = 32;

#[derive(Debug)]
pub enum ClaimError {
    /// Another supervisor of this person's holds the record.
    Held,
    Other(io::Error),
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimError::Held => f.write_str("Hedwig is already running for this person"),
            ClaimError::Other(error) => write!(f, "the record cannot be made: {error}"),
        }
    }
}

impl std::error::Error for ClaimError {}

#[derive(Debug)]
pub struct Claim {
    /// Held for reading for as long as the supervisor lives: the lock is on
    /// it, and it does not share deletion.
    _holder: File,
    path: PathBuf,
    supervisor: Instance,
}

impl Claim {
    /// Claims the record for this process.
    ///
    /// # Errors
    ///
    /// [`ClaimError::Held`] while another process holds it. A record left by
    /// a supervisor that has ended is taken over.
    pub fn take(places: &Places) -> Result<Claim, ClaimError> {
        let (process, created) = hedwig_win::process::own().map_err(ClaimError::Other)?;
        let path = places.record();
        // Made where it is not there yet; the claim itself is the lock.
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(HOLDING)
            .open(&path)
            .map_err(ClaimError::Other)?;
        let file = open_holding(&path).map_err(ClaimError::Other)?;
        // A client finding out whether the record is held takes the lock for
        // an instant when nothing holds it.
        let mut tries = 0;
        loop {
            match claim(&file) {
                Ok(true) => break,
                Ok(false) if tries < LOOKS => {
                    tries += 1;
                    thread::sleep(LOOK);
                }
                Ok(false) => return Err(ClaimError::Held),
                Err(error) => return Err(ClaimError::Other(error)),
            }
        }
        Ok(Claim {
            _holder: file,
            path,
            supervisor: Instance { process, created },
        })
    }

    /// Writes where the core now stands, replacing what the record said,
    /// through a handle closed before this returns.
    pub fn write(&mut self, core: CoreState) -> io::Result<Running> {
        let running = Running {
            supervisor: self.supervisor,
            core,
        };
        let mut text = line(&running);
        text.push('\n');
        // A reader that allows no writer beside it holds the file for the
        // instant of its read.
        let mut tries = 0;
        let mut writer = loop {
            match OpenOptions::new()
                .write(true)
                .share_mode(HOLDING)
                .open(&self.path)
            {
                Ok(writer) => break writer,
                Err(error) if error.raw_os_error() == Some(SHARING) && tries < LOOKS => {
                    tries += 1;
                    thread::sleep(LOOK);
                }
                Err(error) => return Err(error),
            }
        };
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(text.as_bytes())?;
        writer.set_len(text.len() as u64)?;
        Ok(running)
    }
}
