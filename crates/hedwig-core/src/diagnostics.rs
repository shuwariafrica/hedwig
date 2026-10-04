//! What the core writes beside the trail about what went wrong: a ring of two
//! files it bounds itself, written by a thread of its own from a queue that
//! never makes a sender wait.
//!
//! Nothing a frame carried is ever a line here: the senders are the threads
//! that read a channel's client and the store, never the pipe.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;

use hedwig_model::process::Diagnostic;
use hedwig_model::setting::Diagnostics as Level;
use hedwig_model::trail::Timestamp;
use hedwig_model::wire::line;

/// The newer of the two files, written to.
pub const NEWER: &str = "diagnostics.jsonl";

/// The older, which the newer becomes when it reaches [`BOUND`].
pub const OLDER: &str = "diagnostics.1.jsonl";

/// The most bytes either file holds before the newer becomes the older.
/// Invariant: the core's own bound on what it writes beside the trail.
pub const BOUND: u64 = 1 << 20;

/// The most lines waiting to be written. A line that finds the queue full is
/// counted, and the count is written next. Invariant: no sender waits.
pub const QUEUE: usize = 256;

/// The handle the core's threads write diagnostics through. Cloned freely;
/// the writer ends when the last clone is dropped.
#[derive(Debug, Clone)]
pub struct Diagnostics {
    queue: SyncSender<Diagnostic>,
    level: Arc<AtomicU8>,
    dropped: Arc<AtomicU64>,
}

impl Diagnostics {
    /// Starts the writer for the files in `folder`, writing nothing until a
    /// level is set.
    pub fn start(folder: &Path) -> Diagnostics {
        let (queue, waiting) = mpsc::sync_channel(QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let ring = Ring::new(folder);
        {
            let dropped = Arc::clone(&dropped);
            thread::spawn(move || write(ring, &waiting, &dropped));
        }
        Diagnostics {
            queue,
            level: Arc::new(AtomicU8::new(rank(Level::Off))),
            dropped,
        }
    }

    /// What is written from here.
    pub fn set(&self, level: Level) {
        self.level.store(rank(level), Ordering::Relaxed);
    }

    /// A fault: an error a waiting thread met, or a client's account of a
    /// channel that ended otherwise than as asked.
    pub fn fault(&self, at: Timestamp, from: &str, said: &str) {
        self.note(Level::Faults, at, from, said);
    }

    /// Detail: a line a channel's client wrote, as it wrote it.
    pub fn detail(&self, at: Timestamp, from: &str, said: &str) {
        self.note(Level::Detail, at, from, said);
    }

    fn note(&self, needs: Level, at: Timestamp, from: &str, said: &str) {
        if self.level.load(Ordering::Relaxed) < rank(needs) {
            return;
        }
        let diagnostic = Diagnostic {
            at,
            from: from.to_owned(),
            said: said.to_owned(),
        };
        if let Err(TrySendError::Full(_)) = self.queue.try_send(diagnostic) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

const fn rank(level: Level) -> u8 {
    match level {
        Level::Off => 0,
        Level::Faults => 1,
        Level::Detail => 2,
    }
}

fn write(mut ring: Ring, waiting: &Receiver<Diagnostic>, dropped: &AtomicU64) {
    for diagnostic in waiting {
        let lost = dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            let said = Diagnostic {
                at: diagnostic.at,
                from: "diagnostics".to_owned(),
                said: format!("{lost} lines were not written: the queue was full"),
            };
            let _ = ring.write(&said);
        }
        let _ = ring.write(&diagnostic);
    }
}

/// The two files, the newer open for appending.
#[derive(Debug)]
pub struct Ring {
    newer: PathBuf,
    older: PathBuf,
    file: Option<File>,
}

impl Ring {
    pub fn new(folder: &Path) -> Ring {
        Ring {
            newer: folder.join(NEWER),
            older: folder.join(OLDER),
            file: None,
        }
    }

    /// Appends one line, the newer file first becoming the older where the
    /// line would take it past [`BOUND`].
    ///
    /// # Errors
    ///
    /// What the system said.
    pub fn write(&mut self, diagnostic: &Diagnostic) -> io::Result<()> {
        let mut text = line(diagnostic);
        text.push('\n');
        let size = fs::metadata(&self.newer).map_or(0, |metadata| metadata.len());
        if size > 0 && size + text.len() as u64 > BOUND {
            self.file = None;
            hedwig_win::file::replace(&self.newer, &self.older)?;
        }
        let file = match self.file.take() {
            Some(file) => file,
            None => OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.newer)?,
        };
        let file = self.file.insert(file);
        file.write_all(text.as_bytes())
    }
}

/// The lines of both files, oldest first; what cannot be read is left out.
pub fn lines(folder: &Path) -> Vec<String> {
    [OLDER, NEWER]
        .into_iter()
        .filter_map(|name| fs::read_to_string(folder.join(name)).ok())
        .flat_map(|text| text.lines().map(str::to_owned).collect::<Vec<_>>())
        .collect()
}
