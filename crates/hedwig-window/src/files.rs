//! What the window does with files and programs, each run off WinUI's
//! thread: the shell's dialog for choosing a file, the configuration written
//! out or read in, and Hedwig started.
//!
//! The dialog runs a modal loop of its own and needs a single-threaded
//! apartment, which WinUI's background work is not, so it is shown on a
//! thread made for it, owned by the window so the window waits for it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use hedwig_model::config::Document;
use hedwig_model::wire::FRAME;
use hedwig_shell::pick::{Dialog, Purpose, choose};
use hedwig_shell::window::window_of;
use hedwig_view::trial;

/// Hedwig's own program, beside the window where an install puts it.
const HEDWIG: &str = "hedwig.exe";

fn ask(purpose: Purpose, words: trial::Dialog) -> Result<Option<PathBuf>, String> {
    let owner = window_of(std::process::id());
    std::thread::spawn(move || {
        let dialog = Dialog {
            purpose,
            title: words.title,
            name: words.name,
            kinds: words.kinds,
            extension: words.extension,
        };
        choose(&dialog, owner).map_err(|error| error.to_string())
    })
    .join()
    .unwrap_or_else(|_| Err("the dialog for choosing a file ended unexpectedly".to_owned()))
}

/// Writes the person's configuration to a file they choose; `None` where
/// they cancelled.
pub(crate) fn export(document: &Document) -> Result<Option<PathBuf>, String> {
    save(&trial::written(document), trial::EXPORT)
}

/// Writes what a supporter needs to a file the person chooses; `None` where
/// they cancelled.
pub(crate) fn bundle(written: &str) -> Result<Option<PathBuf>, String> {
    save(written, hedwig_view::bundle::SAVE)
}

fn save(text: &str, words: trial::Dialog) -> Result<Option<PathBuf>, String> {
    let Some(path) = ask(Purpose::Write, words)? else {
        return Ok(None);
    };
    std::fs::write(&path, text).map_err(|error| error.to_string())?;
    Ok(Some(path))
}

/// Reads a configuration from a file the person chooses; `None` where they
/// cancelled.
pub(crate) fn import() -> Result<Option<Document>, String> {
    let Some(path) = ask(Purpose::Read, trial::IMPORT)? else {
        return Ok(None);
    };
    let length = std::fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len();
    if usize::try_from(length).map_or(true, |length| length > FRAME) {
        return Err(format!(
            "{} is larger than a Hedwig configuration can be, so it was not read.",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
    trial::document(&text)
        .map(Some)
        .map_err(|error| format!("{} is not a Hedwig configuration: {error}", path.display()))
}

/// Starts the Hedwig that keeps its files in `folder`, as the presence does;
/// what went wrong where it did not start.
pub(crate) fn start(folder: &Path) -> Option<String> {
    let program = std::env::current_exe().ok()?.with_file_name(HEDWIG);
    if !program.exists() {
        return Some("hedwig.exe is not beside this window to be started.".to_owned());
    }
    let mut arguments = vec![OsString::from("supervise")];
    if hedwig_client::folder().ok().as_deref() != Some(folder) {
        arguments.extend([OsString::from("--folder"), folder.into()]);
    }
    hedwig_client::launch(&program, &arguments)
        .err()
        .map(|error| error.to_string())
}
