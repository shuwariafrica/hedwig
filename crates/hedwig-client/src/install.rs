//! Installing Hedwig for the person, replacing one installed, and removing
//! it, each one function a setup program, Hedwig's own removal and a
//! deployer's script share.
//!
//! The program folder never moves between versions: a new version is placed
//! beside it and swapped in once nothing holds a file of it, and swapped
//! back where the version placed does not answer.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Write as _};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_model::install::{
    Index, Names, PackError, Placement, Starts, files, placement, unframe,
};
use hedwig_model::process::{CoreState, Exit, RECORD};
use hedwig_model::protocol::{PROTOCOL, Reply, Request, Withdrawal};
use hedwig_model::remote::Remotes;
use hedwig_model::setting::Autostart;
use hedwig_model::trail::{ClientKind, Withdrew};
use hedwig_win::in_use::{Using, using};
use hedwig_win::registry::{RUN, UNINSTALL, own, remove_key, remove_value, set_number, set_text};

use crate::{
    LaunchError, Session, SessionError, Standing, StopError, launch, look, released_within, stop,
};

/// How long anything holding a file of the folder is given to let go.
pub const LET_GO: Duration = Duration::from_secs(10);

/// What a removal waits at most for the remotes to be reached.
pub const REACH: Duration = Duration::from_secs(120);

/// The name an earlier release of this product started under, whose `Run`
/// value an installation takes away.
const PRIOR: &str = "wingpg-forward";

/// Where one installation of Hedwig is and what it is named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub names: Names,
    /// The program folder, under the person's own programs folder.
    pub program: PathBuf,
    /// The folder its Hedwig keeps its files in, where it is not the
    /// person's own.
    pub data: Option<PathBuf>,
}

impl Place {
    /// The person's own installation, or the one keyed by `data`.
    ///
    /// # Errors
    ///
    /// Windows could not say where the person's programs folder is.
    pub fn resolve(data: Option<PathBuf>) -> io::Result<Place> {
        let names = data
            .as_ref()
            .map_or_else(Names::own, |data| Names::keyed(&data.to_string_lossy()));
        let program = hedwig_win::folder::programs()?
            .join(hedwig_model::install::VENDOR)
            .join(names.program_folder());
        Ok(Place {
            names,
            program,
            data,
        })
    }

    fn data_folder(&self) -> io::Result<PathBuf> {
        match &self.data {
            Some(data) => Ok(data.clone()),
            None => crate::folder(),
        }
    }

    fn sibling(&self, suffix: &str) -> PathBuf {
        let mut name = self
            .program
            .file_name()
            .map(OsString::from)
            .unwrap_or_default();
        name.push(suffix);
        self.program.with_file_name(name)
    }

    fn entry(&self) -> String {
        format!("{UNINSTALL}\\{}", self.names.entry())
    }

    fn role(&self, role: &str) -> Vec<OsString> {
        let mut arguments = vec![OsString::from(role)];
        if let Some(data) = &self.data {
            arguments.push("--folder".into());
            arguments.push(data.clone().into_os_string());
        }
        arguments
    }
}

/// Why an installation, an update or a removal did not complete. Each names
/// the step it stopped at; nothing after it was done.
#[derive(Debug)]
pub enum SetupError {
    /// Run elevated: nothing Hedwig starts may run above the person.
    Elevated,
    /// The program folder cannot hold Hedwig.
    Placement(Placement),
    /// The payload cannot be placed.
    Pack(PackError),
    /// A file or folder could not be read, written, moved or removed.
    Files(io::Error),
    /// These still hold a file of Hedwig's folder.
    Held(Vec<Using>),
    /// The running Hedwig could not be stopped.
    Stop(StopError),
    /// The values Windows reads could not be written.
    Registry(io::Error),
    /// The Hedwig placed could not be started.
    Launch(LaunchError),
    /// The Hedwig placed did not answer.
    Unanswered(String),
    /// It answered as another version than the one placed.
    Version { placed: String, answered: String },
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetupError::Elevated => f.write_str(
                "Hedwig is installed for you alone and must not run as administrator: run setup again without elevation",
            ),
            SetupError::Placement(placement) => placement.fmt(f),
            SetupError::Pack(pack) => pack.fmt(f),
            SetupError::Files(error) => write!(f, "Hedwig's files could not be placed: {error}"),
            SetupError::Held(holders) => {
                f.write_str("these still use Hedwig's files; close them and run setup again:")?;
                for holder in holders {
                    write!(f, " {} ({})", holder.name, holder.process)?;
                }
                Ok(())
            }
            SetupError::Stop(error) => write!(f, "the Hedwig running could not be stopped: {error}"),
            SetupError::Registry(error) => {
                write!(f, "Windows' list of your applications could not be written: {error}")
            }
            SetupError::Launch(error) => write!(f, "{error}"),
            SetupError::Unanswered(account) => {
                write!(f, "the Hedwig placed did not answer: {account}")
            }
            SetupError::Version { placed, answered } => write!(
                f,
                "the Hedwig placed answered as version {answered}, not {placed}"
            ),
        }
    }
}

impl std::error::Error for SetupError {}

impl SetupError {
    /// The status setup exits with, which a deployer's script and winget's
    /// manifest name.
    pub const fn status(&self) -> u8 {
        match self {
            SetupError::Elevated => 10,
            SetupError::Placement(_) => 11,
            SetupError::Pack(_) => 12,
            SetupError::Files(_) => 13,
            SetupError::Held(_) => 14,
            SetupError::Stop(_) => 15,
            SetupError::Registry(_) => 16,
            SetupError::Launch(_) => 17,
            SetupError::Unanswered(_) => 18,
            SetupError::Version { .. } => 19,
        }
    }
}

/// What an installation said yes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choices {
    /// Hedwig and its icon start when the person signs in.
    pub at_logon: bool,
}

/// What an installation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub version: String,
    pub program: PathBuf,
    /// The version it replaced, where it replaced one.
    pub replaced: Option<String>,
    /// The removal it ended, where the Hedwig it replaced was being removed
    /// and the removal had not finished: Hedwig writes on the person's
    /// remotes again, as they consented.
    pub ended: Option<Withdrew>,
}

/// Places `framed` - a setup program's payload - as the installation at
/// `place`, replacing one there, starts the Hedwig placed, and returns only
/// once it has answered with the version placed.
///
/// # Errors
///
/// [`SetupError`], naming the step that failed.
pub fn install(framed: &[u8], place: &Place, choices: Choices) -> Result<Installed, SetupError> {
    elevated()?;
    let folder = place.program.to_str().ok_or_else(|| {
        SetupError::Files(io::Error::other("the programs folder's path is not text"))
    })?;
    placement(&place.names, folder).map_err(SetupError::Placement)?;
    let (index, stream) = unframe(framed).map_err(SetupError::Pack)?;
    let whole = hedwig_win::pack::decompress(
        stream,
        usize::try_from(index.length()).map_err(|_| SetupError::Pack(PackError::Lengths))?,
    )
    .map_err(SetupError::Files)?;
    let cut = files(&index, &whole).map_err(SetupError::Pack)?;

    let next = place.sibling(".next");
    let previous = place.sibling(".previous");
    for leftover in [&next, &previous] {
        remove_folder(leftover)?;
    }
    for (path, bytes) in cut {
        let to = next.join(path);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).map_err(SetupError::Files)?;
        }
        fs::write(&to, bytes).map_err(SetupError::Files)?;
    }

    let replaced = own(&place.entry(), "DisplayVersion")
        .map_err(SetupError::Registry)?
        .map(|version| version.to_string_lossy().into_owned());
    let installed = place.program.is_dir();
    if installed {
        if let Err(error) = let_go(place) {
            // Nothing was replaced: the version installed runs again.
            let _ = remove_folder(&next);
            let _ = start(place);
            return Err(error);
        }
        fs::rename(&place.program, &previous).map_err(SetupError::Files)?;
    }
    fs::rename(&next, &place.program).map_err(SetupError::Files)?;

    let started = start_and_verify(place, &index);
    if let Err(error) = started {
        // The version placed did not answer: the one it replaced goes back.
        let _ = let_go(place);
        let _ = fs::rename(&place.program, &next);
        if installed {
            let _ = fs::rename(&previous, &place.program);
            let _ = start(place);
        }
        let _ = remove_folder(&next);
        return Err(error);
    }
    remove_folder(&previous)?;
    register(place, &index)?;
    found_from_start(place)?;
    reap();
    let mut session = session(place)?;
    let ended = keep(&mut session)?;
    if choices.at_logon {
        choose_at_logon(&mut session)?;
    }
    Ok(Installed {
        version: index.version,
        program: place.program.clone(),
        replaced,
        ended,
    })
}

/// Refuses an elevated token.
fn elevated() -> Result<(), SetupError> {
    let standing = hedwig_win::token::Token::own()
        .and_then(|token| token.standing())
        .map_err(SetupError::Files)?;
    if standing.integrity >= HIGH {
        Err(SetupError::Elevated)
    } else {
        Ok(())
    }
}

/// The integrity level Windows gives an elevated token.
const HIGH: u32 = 0x3000;

/// Stops the Hedwig of this installation, waits for its record to be let go,
/// and waits for everything else holding a file of the program folder -
/// the icon and the window, which Restart Manager asks to close - to end.
fn let_go(place: &Place) -> Result<(), SetupError> {
    let data = place.data_folder().map_err(SetupError::Files)?;
    let standing = look(&data).map_err(SetupError::Files)?;
    if matches!(standing, Standing::Known(_)) {
        stop(&standing).map_err(SetupError::Stop)?;
        if !released_within(&data, LET_GO) {
            return Err(SetupError::Unanswered(
                "the Hedwig running did not stop".to_owned(),
            ));
        }
    }
    let files = every_file(&place.program).map_err(SetupError::Files)?;
    if files.is_empty() {
        return Ok(());
    }
    let _ = hedwig_win::in_use::close(&files, &place.program);
    let until = Instant::now() + LET_GO;
    loop {
        let holding = using(&files).map_err(SetupError::Files)?;
        if holding.is_empty() {
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(SetupError::Held(holding));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn every_file(folder: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    if !folder.is_dir() {
        return Ok(found);
    }
    for entry in fs::read_dir(folder)? {
        let path = entry?.path();
        if path.is_dir() {
            found.extend(every_file(&path)?);
        } else {
            found.push(path);
        }
    }
    Ok(found)
}

fn remove_folder(folder: &Path) -> Result<(), SetupError> {
    match fs::remove_dir_all(folder) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SetupError::Files(error)),
    }
}

fn start(place: &Place) -> Result<(), SetupError> {
    let program = place.program.join(Starts::Hedwig.program());
    launch(&program, &place.role("supervise"))
        .map(drop)
        .map_err(SetupError::Launch)
}

/// Starts the Hedwig placed and asks it who it is: success is its answer
/// with the version placed.
fn start_and_verify(place: &Place, index: &Index) -> Result<(), SetupError> {
    let program = place.program.join(Starts::Hedwig.program());
    let launched = launch(&program, &place.role("supervise")).map_err(SetupError::Launch)?;
    let CoreState::Serving { pipe, .. } = launched.running.core else {
        return Err(SetupError::Unanswered(format!(
            "{:?}",
            launched.running.core
        )));
    };
    let mut session =
        Session::open(&pipe).map_err(|error| SetupError::Unanswered(error.to_string()))?;
    let hello = Request::Hello {
        protocol: PROTOCOL,
        kind: ClientKind::Command,
        attends: Remotes::Every,
    };
    match session.ask(hello) {
        Ok(Ok(Reply::Welcome { version, .. })) if version == index.version => Ok(()),
        Ok(Ok(Reply::Welcome { version, .. })) => Err(SetupError::Version {
            placed: index.version.clone(),
            answered: version,
        }),
        Ok(Ok(other)) => Err(SetupError::Unanswered(format!("{other:?}"))),
        Ok(Err(refusal)) => Err(SetupError::Unanswered(refusal.to_string())),
        Err(error) => Err(SetupError::Unanswered(error.to_string())),
    }
}

/// Writes the entry Windows lists the installation under, which is also
/// what a deployer and winget read to know it is installed and at which
/// version.
fn register(place: &Place, index: &Index) -> Result<(), SetupError> {
    let key = place.entry();
    let program = place.program.as_os_str();
    let hedwig = place.program.join(Starts::Hedwig.program());
    let quoted = |arguments: &str| {
        let mut command = OsString::from("\"");
        command.push(&hedwig);
        command.push("\" ");
        command.push(arguments);
        command
    };
    let mut quiet = String::from("remove --quiet");
    if let Some(data) = &place.data {
        let _ = write!(quiet, " --folder \"{}\"", data.display());
    }
    let kilobytes = u32::try_from(index.length() / 1024).unwrap_or(u32::MAX);
    let texts: [(&str, OsString); 9] = [
        ("DisplayName", place.names.display().into()),
        ("DisplayVersion", index.version.clone().into()),
        ("Publisher", "Shuwari Africa".into()),
        ("InstallLocation", program.to_owned()),
        ("DisplayIcon", {
            let mut icon = hedwig.clone().into_os_string();
            icon.push(",0");
            icon
        }),
        ("UninstallString", removal(place, &quiet, &quoted)),
        ("QuietUninstallString", quoted(&quiet)),
        (
            "URLInfoAbout",
            "https://github.com/shuwariafrica/hedwig".into(),
        ),
        (
            "HelpLink",
            "https://github.com/shuwariafrica/hedwig/issues".into(),
        ),
    ];
    for (value, text) in &texts {
        set_text(&key, value, text).map_err(SetupError::Registry)?;
    }
    for (value, number) in [
        ("NoModify", 1),
        ("NoRepair", 1),
        ("EstimatedSize", kilobytes),
    ] {
        set_number(&key, value, number).map_err(SetupError::Registry)?;
    }
    Ok(())
}

/// What Settings runs to remove the installation: the icon's program, which
/// shows what is taken back and what is left, where it is in the folder;
/// else `hedwig.exe` itself, the same steps with no surface.
fn removal(place: &Place, quiet: &str, quoted: &dyn Fn(&str) -> OsString) -> OsString {
    let icon = place.program.join(Starts::Icon.program());
    let shown = quiet.replacen(" --quiet", "", 1);
    if !icon.is_file() {
        return quoted(&shown);
    }
    let mut command = OsString::from("\"");
    command.push(&icon);
    command.push("\" ");
    command.push(&shown);
    command
}

/// Writes the Start menu entry that opens the window, where the icon's
/// program is in the folder.
fn found_from_start(place: &Place) -> Result<(), SetupError> {
    let icon = place.program.join(Starts::Icon.program());
    if !icon.is_file() {
        return Ok(());
    }
    let start = hedwig_win::folder::start_menu().map_err(SetupError::Files)?;
    hedwig_win::shortcut::make(
        &start.join(place.names.shortcut()),
        &icon,
        &place.names.shortcut_arguments(),
        &place.names.entry(),
    )
    .map_err(SetupError::Files)
}

/// Takes away the `Run` value of the name this product started under,
/// where it starts a program of that name.
fn reap() {
    if let Ok(Some(command)) = own(RUN, PRIOR)
        && command
            .to_string_lossy()
            .to_lowercase()
            .contains("wingpg-forward.exe")
    {
        let _ = remove_value(RUN, PRIOR);
    }
}

/// A session with the Hedwig running at `place`, greeted as a command.
fn session(place: &Place) -> Result<Session, SetupError> {
    let data = place.data_folder().map_err(SetupError::Files)?;
    let Standing::Known(running) = look(&data).map_err(SetupError::Files)? else {
        return Err(SetupError::Unanswered("no record".to_owned()));
    };
    let CoreState::Serving { pipe, .. } = running.core else {
        return Err(SetupError::Unanswered("no core".to_owned()));
    };
    let mut session =
        Session::open(&pipe).map_err(|error| SetupError::Unanswered(error.to_string()))?;
    let greeted = session
        .greet(ClientKind::Command)
        .map_err(|error| SetupError::Unanswered(error.to_string()))?;
    greeted.map_err(|refusal| SetupError::Unanswered(refusal.to_string()))?;
    Ok(session)
}

/// Asks `request` of the core, as setup's own step.
fn asked(session: &mut Session, request: Request) -> Result<Reply, SetupError> {
    match session.ask(request) {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(refusal)) => Err(SetupError::Unanswered(refusal.to_string())),
        Err(error) => Err(SetupError::Unanswered(error.to_string())),
    }
}

/// Installing is the person's word that they want Hedwig: a removal begun
/// and not finished ends, and the one ended is returned.
fn keep(session: &mut Session) -> Result<Option<Withdrew>, SetupError> {
    let Reply::Status(status) = asked(session, Request::Status)? else {
        return Err(SetupError::Unanswered("no status".to_owned()));
    };
    if status.withdrawn.is_some() {
        asked(session, Request::Restore)?;
    }
    Ok(status.withdrawn)
}

/// Says, as the person's statement made at setup, that Hedwig and its icon
/// start when they sign in.
fn choose_at_logon(session: &mut Session) -> Result<(), SetupError> {
    for change in [
        hedwig_model::config::Change::Autostart(Some(Autostart::AtLogon)),
        hedwig_model::config::Change::Icon(Some(Autostart::AtLogon)),
    ] {
        asked(session, Request::Change(change))?;
    }
    Ok(())
}

/// What a removal could not take back, remote by remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    pub left: Vec<Withdrawal>,
}

/// The first part of a removal, run from the installed program: takes back
/// what Hedwig wrote on every remote it can reach, starting Hedwig where it
/// does not run, and returns what is left where it could not. `kind` is what
/// the caller is, so the trail says which surface removed Hedwig.
///
/// # Errors
///
/// [`SetupError`]: Hedwig could not be started or asked.
pub fn withdraw(place: &Place, kind: ClientKind) -> Result<Removed, SetupError> {
    let data = place.data_folder().map_err(SetupError::Files)?;
    if !matches!(look(&data).map_err(SetupError::Files)?, Standing::Known(_)) {
        start(place)?;
    }
    let Standing::Known(running) = look(&data).map_err(SetupError::Files)? else {
        return Err(SetupError::Unanswered("no record".to_owned()));
    };
    let CoreState::Serving { pipe, .. } = running.core else {
        return Err(SetupError::Unanswered("no core".to_owned()));
    };
    let mut session =
        Session::open(&pipe).map_err(|error| SetupError::Unanswered(error.to_string()))?;
    let unanswered = |error: SessionError| SetupError::Unanswered(error.to_string());
    session
        .greet(kind)
        .map_err(unanswered)?
        .map_err(|refusal| SetupError::Unanswered(refusal.to_string()))?;
    let mut asked = Request::Withdraw;
    let until = Instant::now() + REACH;
    loop {
        let left = match session.ask(asked).map_err(unanswered)? {
            Ok(Reply::Withdrawal(left)) => left,
            Ok(other) => return Err(SetupError::Unanswered(format!("{other:?}"))),
            Err(refusal) => return Err(SetupError::Unanswered(refusal.to_string())),
        };
        if left.iter().all(|remote| !remote.surveying) || Instant::now() >= until {
            return Ok(Removed { left });
        }
        thread::sleep(Duration::from_millis(250));
        asked = Request::Withdrawal;
    }
}

/// The last part of a removal, run by the installed `hedwig.exe` itself:
/// stops Hedwig, asks its icon and window to close, and removes the `Run`
/// values, the Start entry, the entry Windows lists it under, its folders
/// and its program folder. Its own file, which Windows does not let a
/// running program remove, is moved into the person's temporary folder,
/// where it stays as a temporary file.
///
/// # Errors
///
/// [`SetupError`]: what could not be stopped or removed.
pub fn finish(place: &Place) -> Result<PathBuf, SetupError> {
    let ours = std::process::id();
    let data = place.data_folder().map_err(SetupError::Files)?;
    let standing = look(&data).map_err(SetupError::Files)?;
    if matches!(standing, Standing::Known(_)) {
        stop(&standing).map_err(SetupError::Stop)?;
        if !released_within(&data, LET_GO) {
            return Err(SetupError::Unanswered(
                "the Hedwig running did not stop".to_owned(),
            ));
        }
    }
    let files = every_file(&place.program).map_err(SetupError::Files)?;
    if !files.is_empty() {
        let _ = hedwig_win::in_use::close(&files, &place.program);
        let until = Instant::now() + LET_GO;
        loop {
            let holding: Vec<Using> = using(&files)
                .map_err(SetupError::Files)?
                .into_iter()
                .filter(|holder| holder.process != ours)
                .collect();
            if holding.is_empty() {
                break;
            }
            if Instant::now() >= until {
                return Err(SetupError::Held(holding));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    for starts in Starts::ALL {
        remove_value(RUN, &place.names.run_value(starts)).map_err(SetupError::Registry)?;
    }
    remove_key(&place.entry()).map_err(SetupError::Registry)?;
    if let Ok(start) = hedwig_win::folder::start_menu() {
        let _ = fs::remove_file(start.join(place.names.shortcut()));
    }
    remove_record_last(&data)?;
    if let Some(vendor) = vendor(place, &data) {
        // Removed only where empty: another product of the vendor's keeps it.
        let _ = fs::remove_dir(vendor);
    }
    let running = std::env::current_exe().map_err(SetupError::Files)?;
    let aside = std::env::temp_dir().join(format!("hedwig-removed-{ours}.exe"));
    for file in files {
        if file == running {
            fs::rename(&file, &aside).map_err(SetupError::Files)?;
        } else {
            fs::remove_file(&file).map_err(SetupError::Files)?;
        }
    }
    remove_folder(&place.program)?;
    if let Some(vendor) = place.program.parent() {
        let _ = fs::remove_dir(vendor);
    }
    Ok(aside)
}

/// The vendor's folder above the core's `data`, which goes with its last
/// product: the person's own core folder sits under it, and a `--folder`
/// Hedwig's parent is the person's.
fn vendor<'a>(place: &Place, data: &'a Path) -> Option<&'a Path> {
    match place.data {
        Some(_) => None,
        None => data.parent(),
    }
}

/// Removes the core's folder, its record last: nothing removes the record
/// while a supervisor holds it.
fn remove_record_last(data: &Path) -> Result<(), SetupError> {
    if !data.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(data).map_err(SetupError::Files)? {
        let path = entry.map_err(SetupError::Files)?.path();
        if path.file_name() != Some(OsStr::new(RECORD)) {
            if path.is_dir() {
                remove_folder(&path)?;
            } else {
                fs::remove_file(&path).map_err(SetupError::Files)?;
            }
        }
    }
    remove_folder(data)
}

/// The status a removal exits with: 0 where everything was taken back.
pub fn removed_status(removed: &Removed) -> Exit {
    if removed.left.iter().all(|remote| remote.left.is_empty()) {
        Exit::Stopped
    } else {
        Exit::Unreached
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    /// A place whose program folder is `program` and whose Hedwig keeps its
    /// files in `data`, or in the person's own folder.
    fn place(program: &Path, data: Option<&Path>) -> Place {
        Place {
            names: data.map_or_else(Names::own, |data| Names::keyed(&data.to_string_lossy())),
            program: program.to_owned(),
            data: data.map(Path::to_owned),
        }
    }

    #[test]
    fn settings_removes_hedwig_through_the_icons_program_where_it_is_installed() {
        let program =
            std::env::temp_dir().join(format!("hedwig-client-removal-{}", std::process::id()));
        fs::create_dir_all(&program).expect("a folder");
        let data = program.join("data");
        let place = place(&program, Some(&data));
        let quiet = format!("remove --quiet --folder \"{}\"", data.display());
        let hedwig = program.join(Starts::Hedwig.program());
        let quoted = |arguments: &str| {
            let mut command = OsString::from("\"");
            command.push(&hedwig);
            command.push("\" ");
            command.push(arguments);
            command
        };
        let shown = format!("remove --folder \"{}\"", data.display());

        let without = removal(&place, &quiet, &quoted);
        let icon = program.join(Starts::Icon.program());
        fs::write(&icon, b"").expect("the icon's program");
        let with = removal(&place, &quiet, &quoted);
        let _ = fs::remove_dir_all(&program);

        assert_eq!(
            without,
            OsString::from(format!("\"{}\" {shown}", hedwig.display()))
        );
        assert_eq!(
            with,
            OsString::from(format!("\"{}\" {shown}", icon.display()))
        );
    }

    #[test]
    fn the_vendors_folder_is_offered_for_removal_only_above_the_persons_own_core() {
        let program = Path::new(r"C:\Programs\ShuwariAfrica\Hedwig");
        let own = Path::new(r"C:\Local\ShuwariAfrica\Hedwig");
        assert_eq!(
            vendor(&place(program, None), own),
            Some(Path::new(r"C:\Local\ShuwariAfrica"))
        );
        let theirs = Path::new(r"D:\work\hedwig-data");
        assert_eq!(vendor(&place(program, Some(theirs)), theirs), None);
    }
}
