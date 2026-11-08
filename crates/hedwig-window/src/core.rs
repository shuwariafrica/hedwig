//! The window's connection to the core, carried on WinUI's background work.
//!
//! `windows-reactor` 0.100.0 delivers to the window's thread only what a
//! background task returns when it ends, one message a task, so the pipe is
//! read by a chain of tasks: each waits for one frame, returns it with what
//! it read the pipe with, and the window starts the next. One waits at a
//! time, and raising the connection's stop ends the wait.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use hedwig_client::{Standing, connect, look};
use hedwig_model::frame::{Frames, Line};
use hedwig_model::protocol::{FromCore, ToCore};
use hedwig_model::text::PipeName;
use hedwig_model::wire::{line, read};
use hedwig_win::Signal;
use hedwig_win::pipe::{Moved, Pipe};

/// One connection to the core: which it is, so a message an earlier one
/// left is not taken for this one's.
#[derive(Debug)]
pub(crate) struct Connection {
    pub(crate) pipe: Arc<Pipe>,
    pub(crate) stop: Arc<Signal>,
    pub(crate) turn: u64,
}

impl Connection {
    /// Ends the connection: a read waiting on it returns, and the pipe
    /// closes when the last task lets go of it.
    pub(crate) fn hang(&self) {
        let _ = self.stop.raise();
    }

    /// What a read of this connection carries from one task to the next,
    /// boxed because every read hands it on in a message.
    #[allow(
        clippy::unnecessary_box_returns,
        reason = "every read hands it on in a message, where it is boxed"
    )]
    pub(crate) fn reading(&self) -> Box<Reading> {
        Box::new(Reading {
            pipe: Arc::clone(&self.pipe),
            stop: Arc::clone(&self.stop),
            frames: Frames::default(),
            turn: self.turn,
        })
    }
}

/// The state of reading one connection, handed from task to task.
pub(crate) struct Reading {
    pipe: Arc<Pipe>,
    stop: Arc<Signal>,
    frames: Frames,
    pub(crate) turn: u64,
}

/// Waits for the next frame, with when it was read: `None` where the
/// connection ended, or what arrived is not a frame, after which nothing can
/// be trusted.
pub(crate) fn next(mut reading: Box<Reading>) -> (Box<Reading>, Option<(FromCore, Instant)>) {
    loop {
        let parsed = match reading.frames.line() {
            Some(Line::Text(text)) => Some(read::<FromCore>(text).ok()),
            Some(Line::NotText) => Some(None),
            None => None,
        };
        match parsed {
            Some(Some(frame)) => {
                reading.frames.erase();
                return (reading, Some((frame, Instant::now())));
            }
            Some(None) => return (reading, None),
            None => {}
        }
        let Ok(room) = reading.frames.room() else {
            return (reading, None);
        };
        match reading.pipe.read(room, Some(&reading.stop)) {
            Ok(Moved::Bytes(count)) => reading.frames.filled(count),
            _ => return (reading, None),
        }
    }
}

/// Opens the pipe the record names and makes sure it is the person's own.
///
/// # Errors
///
/// The client's own sentence for why it could not be opened.
pub(crate) fn open(name: &PipeName, turn: u64) -> Result<Connection, String> {
    let pipe = connect(name).map_err(|refused| refused.to_string())?;
    let stop = Signal::new().map_err(|error| error.to_string())?;
    Ok(Connection {
        pipe: Arc::new(pipe),
        stop: Arc::new(stop),
        turn,
    })
}

/// Writes one frame, whole, or says the connection is gone.
pub(crate) fn write(pipe: &Pipe, frame: &ToCore) -> bool {
    let mut text = line(frame);
    text.push('\n');
    matches!(pipe.write(text.as_bytes(), None), Ok(Moved::Bytes(_)))
}

/// Reads the supervisor's record in `folder`; `None` where it cannot be
/// read at all, which the link treats as nothing new.
pub(crate) fn looked(folder: &Path) -> Option<Standing> {
    look(folder).ok()
}

/// The folder of the Hedwig this window attends: the one named, or the
/// person's own.
pub(crate) fn folder(named: Option<PathBuf>) -> Option<PathBuf> {
    named.or_else(|| hedwig_client::folder().ok())
}
