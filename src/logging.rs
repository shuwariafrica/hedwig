#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use crate::win::time::timestamp;

pub(crate) struct Logger {
    verbose: bool,
    file: Option<Mutex<File>>,
}

impl Logger {
    pub(crate) fn new(verbose: bool, log_file: Option<&Path>) -> std::io::Result<Logger> {
        let file = match log_file {
            None => None,
            Some(p) => Some(Mutex::new(
                OpenOptions::new().create(true).append(true).open(p)?,
            )),
        };
        Ok(Logger { verbose, file })
    }

    pub(crate) fn info(&self, msg: &str) {
        if self.verbose {
            eprintln!("{} {msg}", timestamp());
        }
        self.to_file(msg);
    }

    pub(crate) fn error(&self, msg: &str) {
        eprintln!("{} {msg}", timestamp());
        self.to_file(msg);
    }

    fn to_file(&self, msg: &str) {
        if let Some(file) = &self.file {
            // Recovered rather than propagated: a panic while the lock was held
            // would otherwise silently end file logging for the process.
            let mut f = file.lock().unwrap_or_else(PoisonError::into_inner);
            let _ = writeln!(f, "{} {msg}", timestamp());
        }
    }
}
