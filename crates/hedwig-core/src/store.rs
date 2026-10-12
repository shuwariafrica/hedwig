//! The two files the core keeps: the trail and the configuration.
//!
//! An entry is on disk before anything it records is allowed to happen, so a
//! crash or a power cut can lose only what nobody was yet told. A trail whose
//! last line was cut short loses that line and nothing else. A change to the
//! configuration is in the trail and in the stored document, or in neither.
//! A file that cannot be read is set aside, never overwritten, and the core
//! says so in the trail it starts afresh.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use hedwig_model::config::{Configuration, Document};
use hedwig_model::process::RECORD;
use hedwig_model::trail::{Entry, FORM, Form, Seq, State, Store, Timestamp};
use hedwig_model::wire::{line, page, read, read_stored};

#[derive(Debug)]
pub enum StoreError {
    /// The folder Hedwig keeps its files in could not be resolved or made.
    Folder(io::Error),
    Trail(io::Error),
    Configuration(io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Folder(error) => {
                write!(
                    f,
                    "the folder Hedwig keeps its files in cannot be used: {error}"
                )
            }
            StoreError::Trail(error) => {
                write!(f, "the record of activity cannot be written: {error}")
            }
            StoreError::Configuration(error) => {
                write!(f, "the configuration cannot be written: {error}")
            }
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Folder(error)
            | StoreError::Trail(error)
            | StoreError::Configuration(error) => Some(error),
        }
    }
}

/// Where Hedwig keeps its files.
#[derive(Debug, Clone)]
pub struct Places {
    folder: PathBuf,
    /// Whether this is the person's own folder, or one a Hedwig was started
    /// with in its place.
    own: bool,
}

impl Places {
    /// The person's own folder, under the local application data folder
    /// Windows resolves for them.
    pub fn resolve() -> Result<Places, StoreError> {
        let local = hedwig_win::folder::local().map_err(StoreError::Folder)?;
        let folder = local.join(hedwig_model::process::FOLDER);
        fs::create_dir_all(&folder).map_err(StoreError::Folder)?;
        Ok(Places { folder, own: true })
    }

    /// A given folder, made if it does not exist.
    pub fn at(folder: PathBuf) -> Result<Places, StoreError> {
        fs::create_dir_all(&folder).map_err(StoreError::Folder)?;
        Ok(Places { folder, own: false })
    }

    /// What this Hedwig's installation is named: the person's own, or one
    /// keyed by this folder.
    pub fn names(&self) -> hedwig_model::install::Names {
        if self.own {
            hedwig_model::install::Names::own()
        } else {
            hedwig_model::install::Names::keyed(&self.folder.to_string_lossy())
        }
    }

    pub fn folder(&self) -> &Path {
        &self.folder
    }

    pub fn trail(&self) -> PathBuf {
        self.folder.join("trail.jsonl")
    }

    pub fn configuration(&self) -> PathBuf {
        self.folder.join("configuration.json")
    }

    /// The record a supervisor keeps while it lives.
    pub fn record(&self) -> PathBuf {
        self.folder.join(RECORD)
    }

    fn aside(&self, stem: &str, at: Timestamp, extension: &str) -> PathBuf {
        self.folder
            .join(format!("{stem}.unreadable-{}.{extension}", at.0))
    }

    /// Where a compacted trail is written before it takes the trail's place.
    fn next_trail(&self) -> PathBuf {
        self.folder.join("trail.next.jsonl")
    }

    /// Every file set aside because it could not be read: its path, which
    /// store it was, when it was set aside, and its size.
    ///
    /// # Errors
    ///
    /// The folder could not be listed.
    pub fn set_aside(&self) -> io::Result<Vec<(PathBuf, Store, Timestamp, u64)>> {
        let mut found = Vec::new();
        for listed in fs::read_dir(&self.folder)? {
            let listed = listed?;
            let name = listed.file_name();
            let Some(name) = name.to_str() else { continue };
            let parsed = [
                ("trail", Store::Trail, "jsonl"),
                ("configuration", Store::Configuration, "json"),
            ]
            .into_iter()
            .find_map(|(stem, store, extension)| {
                name.strip_prefix(stem)
                    .and_then(|rest| rest.strip_prefix(".unreadable-"))
                    .and_then(|rest| rest.strip_suffix(extension))
                    .and_then(|rest| rest.strip_suffix('.'))
                    .and_then(|at| at.parse().ok())
                    .map(|at| (store, Timestamp(at)))
            });
            if let Some((store, at)) = parsed {
                found.push((listed.path(), store, at, listed.metadata()?.len()));
            }
        }
        found.sort_by_key(|(_, _, at, _)| *at);
        Ok(found)
    }

    /// Removes the files set aside before `before` whose store is not in
    /// `raised`: the person has put them away, and the horizon has passed
    /// them.
    ///
    /// # Errors
    ///
    /// The folder could not be listed, or a file removed.
    pub fn forget_aside(&self, before: Timestamp, raised: &[Store]) -> Result<(), StoreError> {
        for (path, store, at, _) in self.set_aside().map_err(StoreError::Folder)? {
            if at < before && !raised.contains(&store) {
                fs::remove_file(path).map_err(StoreError::Folder)?;
            }
        }
        Ok(())
    }
}

/// The trail's first two lines - its form, and what the entries before the
/// first were folded into - flushed.
fn head_lines(file: &mut File, head: &State) -> io::Result<()> {
    let mut text = line(&Form { trail: FORM });
    text.push('\n');
    text.push_str(&line(head));
    text.push('\n');
    file.write_all(text.as_bytes())?;
    file.sync_data()
}

/// The trail, open for appending.
#[derive(Debug)]
pub struct Trail {
    file: File,
}

/// What opening the trail found.
#[derive(Debug)]
pub struct Opened {
    pub trail: Trail,
    /// What the entries before the first were folded into.
    pub head: State,
    pub entries: Vec<Entry>,
    /// Why the trail that was there could not be read, when it could not. It
    /// has been set aside and `entries` is empty.
    pub unreadable: Option<String>,
}

/// The trail's head and entries; `None` for a head the file does not hold
/// yet, which is a trail with no entry.
fn entries(body: &[u8]) -> Result<(Option<State>, Vec<Entry>), String> {
    let text = std::str::from_utf8(body).map_err(|_| "it is not text".to_owned())?;
    let mut lines = text.lines().enumerate();
    if let Some((_, first)) = lines.next() {
        let form: Form =
            read(first).map_err(|error| format!("line 1 names no form of the trail: {error}"))?;
        if form.trail > FORM {
            return Err(format!(
                "it is in form {} of the trail, and this Hedwig reads forms up to {FORM}",
                form.trail
            ));
        }
    }
    let head: Option<State> = match lines.next() {
        Some((_, second)) => Some(
            read_stored(second)
                .map_err(|error| format!("line 2 is not the trail's head: {error}"))?,
        ),
        None => None,
    };
    let mut entries: Vec<Entry> = Vec::new();
    for (number, written) in lines {
        let entry: Entry =
            read(written).map_err(|error| format!("line {}: {error}", number + 1))?;
        let before = entries.last().map_or(Seq(0), |last| last.seq);
        if entry.seq <= before {
            return Err(format!(
                "line {}: entry {} does not follow entry {}",
                number + 1,
                entry.seq.0,
                before.0
            ));
        }
        entries.push(entry);
    }
    Ok((head, entries))
}

impl Trail {
    /// Opens the trail, reading what is there. `at` names the file an
    /// unreadable trail is set aside as.
    pub fn open(places: &Places, at: Timestamp) -> Result<Opened, StoreError> {
        let path = places.trail();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(StoreError::Trail(error)),
        };
        // Everything after the last line feed is a line that was being
        // written when the process or the power went: it was never on disk
        // whole, so nothing it records was allowed to happen.
        let whole = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |end| end + 1);
        let (body, torn) = bytes.split_at(whole);
        let (head, entries, unreadable) = match entries(body) {
            Ok((head, entries)) => {
                if !torn.is_empty() {
                    let file = OpenOptions::new().write(true).open(&path);
                    file.and_then(|file| {
                        file.set_len(whole as u64)?;
                        file.sync_all()
                    })
                    .map_err(StoreError::Trail)?;
                }
                (head, entries, None)
            }
            Err(account) => {
                fs::rename(&path, places.aside("trail", at, "jsonl")).map_err(StoreError::Trail)?;
                (None, Vec::new(), Some(account))
            }
        };
        // A trail without its head holds no entry: a new one, or one whose
        // first lines a power cut took. It begins again whole.
        let head = if let Some(head) = head {
            head
        } else {
            let head = State::default();
            File::create(&path)
                .and_then(|mut fresh| head_lines(&mut fresh, &head))
                .map_err(StoreError::Trail)?;
            head
        };
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(StoreError::Trail)?;
        Ok(Opened {
            trail: Trail { file },
            head,
            entries,
            unreadable,
        })
    }

    /// Puts `head` and `entries` in the trail's place, with its form line,
    /// in one step that is on disk when this returns, and appends to it from
    /// here.
    pub fn rewrite(
        &mut self,
        places: &Places,
        head: &State,
        entries: &[Entry],
    ) -> Result<(), StoreError> {
        let next = places.next_trail();
        let mut file = File::create(&next).map_err(StoreError::Trail)?;
        head_lines(&mut file, head).map_err(StoreError::Trail)?;
        let mut text = String::new();
        for entry in entries {
            text.push_str(&line(entry));
            text.push('\n');
        }
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(StoreError::Trail)?;
        // The trail's own handle is let go before the new file takes its
        // name, which Windows refuses while it is open; this handle, at the
        // new file's end, follows it there and is appended to from here.
        self.file = file;
        hedwig_win::file::replace(&next, &places.trail()).map_err(StoreError::Trail)?;
        Ok(())
    }

    /// Appends entries and returns once they are on disk.
    pub fn append(&mut self, entries: &[Entry]) -> Result<(), StoreError> {
        let mut text = String::new();
        for entry in entries {
            text.push_str(&line(entry));
            text.push('\n');
        }
        self.file
            .write_all(text.as_bytes())
            .and_then(|()| self.file.sync_data())
            .map_err(StoreError::Trail)
    }
}

/// What the stored configuration turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub enum Kept {
    /// None has been stored: nothing is configured.
    Absent,
    Read(Box<Configuration>),
    /// The stored document is not one this build accepts. It has been set
    /// aside; nothing is granted until the person imports a document.
    Unreadable(String),
}

/// Where a document waits between being written and taking the stored one's
/// place: beside it, named for the entry that records the change.
fn prepared(places: &Places, entry: Seq) -> PathBuf {
    places
        .folder()
        .join(format!("configuration.next-{}.json", entry.0))
}

/// The entries that documents are waiting on, in order.
fn waiting(places: &Places) -> io::Result<Vec<Seq>> {
    let mut waiting = Vec::new();
    for found in fs::read_dir(places.folder())? {
        let name = found?.file_name();
        let entry = name
            .to_str()
            .and_then(|name| name.strip_prefix("configuration.next-"))
            .and_then(|rest| rest.strip_suffix(".json"))
            .and_then(|number| number.parse().ok());
        if let Some(entry) = entry {
            waiting.push(Seq(entry));
        }
    }
    waiting.sort();
    Ok(waiting)
}

/// The first of three steps that change the stored configuration: the new
/// document is written beside the stored one and flushed. The second is the
/// trail's: the entry that records the change is appended and flushed. The
/// third is [`settle`]. Whenever the process or the power goes, the next run
/// finishes the change if its entry is in the trail and forgets it if not.
pub fn prepare(places: &Places, document: &Document, entry: Seq) -> Result<(), StoreError> {
    File::create(prepared(places, entry))
        .and_then(|mut file| {
            file.write_all(page(document).as_bytes())?;
            file.sync_all()
        })
        .map_err(StoreError::Configuration)
}

/// Puts the document prepared for `entry` in the stored one's place, in one
/// step that is on disk when this returns.
pub fn settle(places: &Places, entry: Seq) -> Result<(), StoreError> {
    hedwig_win::file::replace(&prepared(places, entry), &places.configuration())
        .map_err(StoreError::Configuration)
}

/// Finishes or forgets what the run before left between the steps.
fn recover(places: &Places, entries: &[Entry]) -> Result<(), StoreError> {
    for entry in waiting(places).map_err(StoreError::Configuration)? {
        let recorded = entries.binary_search_by_key(&entry, |recorded| recorded.seq);
        if recorded.is_ok() {
            settle(places, entry)?;
        } else {
            fs::remove_file(prepared(places, entry)).map_err(StoreError::Configuration)?;
        }
    }
    Ok(())
}

/// Reads the stored configuration through the gate every change goes through.
/// `entries` is the trail as just read: a change it records is a change the
/// stored document has when this returns.
pub fn load(places: &Places, at: Timestamp, entries: &[Entry]) -> Result<Kept, StoreError> {
    recover(places, entries)?;
    let path = places.configuration();
    let account = match fs::read_to_string(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Kept::Absent),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => "it is not text".to_owned(),
        Err(error) => return Err(StoreError::Configuration(error)),
        Ok(text) => {
            let imported = read::<Document>(&text)
                .map_err(|error| error.to_string())
                .and_then(|document| {
                    Configuration::restore(document).map_err(|refusal| refusal.to_string())
                });
            match imported {
                Ok(configuration) => return Ok(Kept::Read(Box::new(configuration))),
                Err(account) => account,
            }
        }
    };
    fs::rename(&path, places.aside("configuration", at, "json"))
        .map_err(StoreError::Configuration)?;
    Ok(Kept::Unreadable(account))
}
