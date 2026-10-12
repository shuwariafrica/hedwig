//! How a client of Hedwig's core finds it, talks to it and starts it.
//!
//! The command line and the interface are both built on this crate and on
//! nothing of the core's. [`folder`] is where Hedwig keeps its files, and
//! [`look`] reads the record the supervisor keeps there; [`connect`] opens
//! the control pipe once it is known to be the person's own, and [`Session`]
//! speaks the protocol over it; [`launch`] starts a supervisor that outlives
//! the terminal it was started from; [`stop`] ends Hedwig whether or not its
//! core is answering; [`ask`] puts a channel's prompt to the person.

#![forbid(unsafe_code)]

pub mod install;

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::time::{Duration, Instant};

use hedwig_model::frame::{Frames, Line};
use hedwig_model::process::{CoreState, Exit, FOLDER, RECORD, Running};
use hedwig_model::protocol::{Answer, FromCore, Hint, Notice, PROTOCOL, Reply, Request, ToCore};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::Remotes;
use hedwig_model::text::{PipeName, Words};
use hedwig_model::trail::{ClientKind, Origin};
use hedwig_model::wire::{WireError, line, read};
use hedwig_win::pipe::{self, Moved, Pipe};
use hedwig_win::process::{APART, DETACHED, EndError};
use hedwig_win::start::apart;
use hedwig_win::token::Token;
use zeroize::Zeroize;

/// How long a client waits for a place at the pipe. A place frees in the time
/// the core takes to make an instance unless every one is held, so this bounds
/// only the wait on a core already serving as many clients as a pipe can have.
const TURN: Duration = Duration::from_secs(5);

/// What starting a process outside its parent's job fails with when that job
/// does not allow it.
const NOT_ALLOWED: i32 = 5;

/// What the record says of the person's hedwig.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// No supervisor is running: there is no record, or nothing holds the
    /// one there.
    Absent,
    /// A supervisor holds the record and it cannot be read yet: it is being
    /// written.
    Unsettled,
    Known(Running),
}

/// Whether a supervisor holds the record at `path`: a test of its claim,
/// which needs only the right to read the record and asks nothing of the
/// supervisor's process, which a client in another session or under another
/// logon may not be allowed to open at all.
fn held(path: &Path) -> io::Result<bool> {
    hedwig_win::file::held(path)
}

/// The folder Hedwig keeps its files in: `hedwig` in the one Windows
/// resolves for the person's local application data, asked of Windows each
/// time and never read from a variable.
///
/// # Errors
///
/// Windows could not say where local application data is.
pub fn folder() -> io::Result<std::path::PathBuf> {
    hedwig_win::folder::local().map(|local| local.join(FOLDER))
}

/// Opens the control pipe `name` and makes sure it is the person's own
/// before anything is written to it: a pipe of that name that another
/// account made first is left with nothing said.
///
/// # Errors
///
/// [`OpenError::NotOurs`] for a pipe another account owns; otherwise why it
/// could not be opened.
pub fn connect(name: &PipeName) -> Result<Pipe, OpenError> {
    let pipe = pipe::open(&name.to_path(), TURN).map_err(|error| match error {
        pipe::OpenError::Absent => OpenError::Absent,
        pipe::OpenError::Busy => OpenError::Busy,
        pipe::OpenError::Denied => OpenError::Denied,
        pipe::OpenError::Other(error) => OpenError::Other(error),
    })?;
    let owner = pipe.owner().map_err(OpenError::Other)?;
    let me = Token::own()
        .and_then(|token| token.user())
        .map_err(OpenError::Other)?;
    if owner != me {
        return Err(OpenError::NotOurs {
            owner: format!("{owner:?}"),
        });
    }
    Ok(pipe)
}

/// Reads the record in `folder`.
///
/// # Errors
///
/// The folder or the record could not be read at all.
pub fn look(folder: &Path) -> io::Result<Standing> {
    let path = folder.join(RECORD);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Standing::Absent),
        Err(error) => return Err(error),
    };
    // A record stays when its supervisor ends, so what it says counts only
    // while something holds it.
    if !held(&path)? {
        return Ok(Standing::Absent);
    }
    match text.lines().next().map(read::<Running>) {
        Some(Ok(running)) => Ok(Standing::Known(running)),
        _ => Ok(Standing::Unsettled),
    }
}

/// Waits up to `limit` for the supervisor holding the record in `folder` to
/// let go of it, which it does by ending. Returns whether it has.
pub fn released_within(folder: &Path, limit: Duration) -> bool {
    let path = folder.join(RECORD);
    let until = Instant::now() + limit;
    loop {
        if matches!(held(&path), Ok(false)) {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Why a session could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// No pipe has the name the record gives: the core has just ended.
    Absent,
    /// Every place at the pipe stayed taken for as long as a client waits.
    Busy,
    /// The pipe does not admit this process: it runs as another account,
    /// below medium integrity, or under a token restricted to less than the
    /// person's own account.
    Denied,
    /// The pipe belongs to another account. Nothing was sent to it.
    NotOurs {
        owner: String,
    },
    Other(io::Error),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Absent => f.write_str("Hedwig's core is not listening"),
            OpenError::Busy => f.write_str("Hedwig's core is serving as many clients as it can"),
            OpenError::Denied => f.write_str("Hedwig's pipe does not admit this process"),
            OpenError::NotOurs { owner } => write!(
                f,
                "the pipe under Hedwig's name belongs to {owner}, not to you; nothing was sent to it"
            ),
            OpenError::Other(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// Why a request got no reply.
#[derive(Debug)]
pub enum SessionError {
    /// The core closed the connection, or ended.
    Closed,
    /// The core sent something that is not a frame of this protocol.
    Garbled(String),
    Other(io::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Closed => f.write_str("Hedwig's core closed the connection"),
            SessionError::Garbled(account) => {
                write!(f, "Hedwig's core sent a frame that is not valid: {account}")
            }
            SessionError::Other(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<WireError> for SessionError {
    fn from(error: WireError) -> SessionError {
        SessionError::Garbled(error.to_string())
    }
}

/// One connection to the control pipe.
pub struct Session {
    pipe: Pipe,
    frames: Frames,
    next: u32,
    /// Notices that arrived while a reply was awaited.
    notices: VecDeque<Notice>,
}

impl Session {
    /// Connects to the pipe and makes sure it is the person's own before
    /// anything is written to it.
    pub fn open(name: &PipeName) -> Result<Session, OpenError> {
        let pipe = connect(name)?;
        Ok(Session {
            pipe,
            frames: Frames::default(),
            next: 1,
            notices: VecDeque::new(),
        })
    }

    fn receive(&mut self) -> Result<FromCore, SessionError> {
        loop {
            if let Some(found) = self.frames.line() {
                let frame = match found {
                    Line::Text(text) => read::<FromCore>(text).map_err(SessionError::from),
                    Line::NotText => Err(SessionError::Garbled("it is not text".to_owned())),
                };
                self.frames.erase();
                return frame;
            }
            let room = self
                .frames
                .room()
                .map_err(|_| SessionError::Garbled("a frame is too long".to_owned()))?;
            match self.pipe.read(room, None) {
                Ok(Moved::Bytes(count)) => self.frames.filled(count),
                Ok(_) => return Err(SessionError::Closed),
                Err(error) => return Err(SessionError::Other(error)),
            }
        }
    }

    /// Sends one request and waits for its reply. Notices that arrive first
    /// are kept for [`Session::notice`].
    pub fn ask(&mut self, request: Request) -> Result<Result<Reply, Refusal>, SessionError> {
        let id = self.next;
        self.next = self.next.wrapping_add(1).max(1);
        let mut text = line(&ToCore { id, request });
        text.push('\n');
        let written = self.pipe.write(text.as_bytes(), None);
        // The request can be an answer to a prompt.
        text.zeroize();
        match written {
            Ok(Moved::Bytes(_)) => {}
            Ok(_) => return Err(SessionError::Closed),
            Err(error) => return Err(SessionError::Other(error)),
        }
        loop {
            match self.receive()? {
                FromCore::Notice(notice) => self.notices.push_back(notice),
                // A reply to 0 is the core saying it could not read a frame.
                FromCore::Reply { id: to, reply } if to == id || to == 0 => return Ok(reply),
                FromCore::Reply { id: to, .. } => {
                    return Err(SessionError::Garbled(format!(
                        "a reply to request {to} while request {id} was waiting"
                    )));
                }
            }
        }
    }

    /// The greeting, as a client that watches every remote. The reply says
    /// how the core sees this client.
    pub fn greet(&mut self, kind: ClientKind) -> Result<Result<Origin, Refusal>, SessionError> {
        let hello = Request::Hello {
            protocol: PROTOCOL,
            kind,
            attends: Remotes::Every,
        };
        Ok(match self.ask(hello)? {
            Ok(Reply::Welcome { you, .. }) => Ok(you),
            Ok(other) => return Err(SessionError::Garbled(format!("{other:?} to a greeting"))),
            Err(refusal) => Err(refusal),
        })
    }

    /// The next notice, waiting for one if none has arrived.
    pub fn notice(&mut self) -> Result<Notice, SessionError> {
        if let Some(notice) = self.notices.pop_front() {
            return Ok(notice);
        }
        match self.receive()? {
            FromCore::Notice(notice) => Ok(notice),
            FromCore::Reply { id, .. } => Err(SessionError::Garbled(format!(
                "a reply to request {id} that nobody made"
            ))),
        }
    }
}

/// Why a channel's prompt got no answer to hand its client.
#[derive(Debug)]
pub enum AskError {
    Open(OpenError),
    Session(SessionError),
    /// The core would not put it to the person: nobody could be asked, or
    /// the process that asked is in no live channel.
    Refused(Refusal),
}

impl fmt::Display for AskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AskError::Open(error) => write!(f, "{error}"),
            AskError::Session(error) => write!(f, "{error}"),
            AskError::Refused(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for AskError {}

/// Puts what a channel's client asks to the person, through the core, and
/// waits for their answer. The core attributes it to the remote whose
/// channel's job this process is in, and to nothing this process says.
///
/// # Errors
///
/// [`AskError`] when the pipe cannot be used or the core refuses to ask.
pub fn ask(pipe: &PipeName, words: Words, hint: Option<Hint>) -> Result<Answer, AskError> {
    let mut session = Session::open(pipe).map_err(AskError::Open)?;
    session
        .greet(ClientKind::Prompt)
        .map_err(AskError::Session)?
        .map_err(AskError::Refused)?;
    match session.ask(Request::Prompt { words, hint }) {
        Ok(Ok(Reply::Answer(answer))) => Ok(answer),
        Ok(Ok(other)) => Err(AskError::Session(SessionError::Garbled(format!(
            "{other:?} to a prompt"
        )))),
        Ok(Err(refusal)) => Err(AskError::Refused(refusal)),
        Err(error) => Err(AskError::Session(error)),
    }
}

/// Whether a started Hedwig is free of the session that started it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tether {
    /// It left the job of the session that started it, or that session had
    /// none: it runs until the person stops it or the machine shuts down.
    Free,
    /// The session's job did not let it leave. It ends when that session
    /// does.
    Tied,
}

#[derive(Debug)]
pub enum LaunchError {
    /// The supervisor could not be started.
    Spawn(io::Error),
    /// The supervisor ended before it said anything; with this status.
    Silent(Option<Exit>),
    /// The supervisor said something that is not a record.
    Garbled(String),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchError::Spawn(error) => write!(f, "Hedwig could not be started: {error}"),
            LaunchError::Silent(Some(Exit::AlreadyRunning)) => {
                f.write_str("Hedwig is already running for you")
            }
            LaunchError::Silent(Some(Exit::Storage)) => {
                f.write_str("Hedwig cannot use the folder it keeps its files in")
            }
            LaunchError::Silent(_) => f.write_str("Hedwig ended as soon as it was started"),
            LaunchError::Garbled(account) => {
                write!(f, "Hedwig said something unexpected: {account}")
            }
        }
    }
}

impl std::error::Error for LaunchError {}

/// A Hedwig just started: what its supervisor first reported, and whether it
/// will outlast the session that started it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launched {
    pub running: Running,
    pub tether: Tether,
}

/// Starts a supervisor and waits for the first thing it has to report: a
/// core serving, or the first core's breakdown.
///
/// It is started with no console, holding none of this process's handles,
/// and outside the job of the session that asks, where that job allows it,
/// so that it outlives an SSH session into the workstation and keeps nothing
/// of that session open. Where the job does not allow it, it is started
/// inside the job and the result says so.
pub fn launch(program: &Path, arguments: &[OsString]) -> Result<Launched, LaunchError> {
    let (started, tether) = match apart(program, arguments, APART) {
        Ok(started) => (started, Tether::Free),
        Err(error) if error.raw_os_error() == Some(NOT_ALLOWED) => (
            apart(program, arguments, DETACHED).map_err(LaunchError::Spawn)?,
            Tether::Tied,
        ),
        Err(error) => return Err(LaunchError::Spawn(error)),
    };
    let mut first = String::new();
    let said = BufReader::new(&started.said)
        .read_line(&mut first)
        .map_err(LaunchError::Spawn)?;
    if said == 0 {
        let exit = started.wait().ok().and_then(Exit::from_status);
        return Err(LaunchError::Silent(exit));
    }
    let running = read::<Running>(first.trim_end())
        .map_err(|error| LaunchError::Garbled(error.to_string()))?;
    Ok(Launched { running, tether })
}

/// Starts `program` as [`launch`] starts a supervisor - no console, none of
/// this process's handles, outside the session's job where it allows - and
/// waits for nothing it says: what setup starts the icon with.
///
/// # Errors
///
/// It could not be started.
pub fn detach(program: &Path, arguments: &[OsString]) -> io::Result<()> {
    match apart(program, arguments, APART) {
        Ok(_) => Ok(()),
        Err(error) if error.raw_os_error() == Some(NOT_ALLOWED) => {
            apart(program, arguments, DETACHED).map(drop)
        }
        Err(error) => Err(error),
    }
}

/// Why Hedwig could not be stopped.
#[derive(Debug)]
pub enum StopError {
    Session(SessionError),
    Refused(Refusal),
    /// No core answers, and the supervisor runs at a higher integrity level
    /// than this process, so Windows does not let it be ended from here.
    Above,
    Other(io::Error),
}

impl fmt::Display for StopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopError::Session(error) => write!(f, "{error}"),
            StopError::Refused(refusal) => write!(f, "{refusal}"),
            StopError::Above => f.write_str(
                "Hedwig is not answering and runs at a higher integrity level than this command; stop it from where it was started",
            ),
            StopError::Other(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StopError {}

/// Stops the Hedwig the record describes. A core that answers is asked, and
/// records who asked. Where no core answers - one is starting, or they keep
/// breaking down - the supervisor itself is ended, which ends whatever it is
/// running.
///
/// Returns whether there was anything to stop.
pub fn stop(standing: &Standing) -> Result<bool, StopError> {
    let Standing::Known(running) = standing else {
        return Ok(false);
    };
    if let CoreState::Serving { pipe, .. } = &running.core
        && let Ok(mut session) = Session::open(pipe)
    {
        session
            .greet(ClientKind::Command)
            .map_err(StopError::Session)?
            .map_err(StopError::Refused)?;
        return match session.ask(Request::Stop) {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(refusal)) => Err(StopError::Refused(refusal)),
            Err(error) => Err(StopError::Session(error)),
        };
    }
    let supervisor = running.supervisor;
    let status = u32::from(Exit::Stopped.status());
    match hedwig_win::process::end(supervisor.process, supervisor.created, status) {
        Ok(()) => Ok(true),
        Err(EndError::Gone) => Ok(false),
        Err(EndError::Above) => Err(StopError::Above),
        Err(EndError::Other(error)) => Err(StopError::Other(error)),
    }
}
