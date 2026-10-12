//! What serves a `gpg` capability: each connection admitted at the forward's
//! end, carried to the workstation's own gpg-agent and back.
//!
//! A connection reaches the agent first - the socket file read now, the
//! process listening where it points let read that file itself, the file's
//! sixteen bytes sent, the agent's greeting read - and only then asks to be
//! served. From there every line passes through the [`Conversation`], and a
//! request it holds waits for the deciding thread's word.
//!
//! Three threads carry a connection: one reads the remote, one reads the
//! agent, and one owns the conversation and writes both ways. Nothing the
//! deciding thread does waits on any of them.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hedwig_model::capability::{Access, Home, Installation};
use hedwig_model::holder::SourceHolder;
use hedwig_model::refusal::{Refusal, Withheld};
use hedwig_model::text::{DeviceSerial, DeviceSocket, Port};
use hedwig_model::trail::{ConnectionId, Failure, Target};
use hedwig_win::endpoint::owner;
use hedwig_win::process::Process;
use hedwig_win::process::{LEAVING, UNSEEN};
use hedwig_win::start::apart;
use zeroize::Zeroize;

use crate::assuan::{self, Ask, Breach, Conversation, LINE, NONCE, Nonce, Out, SocketFile};

/// How long the agent has to greet a connection once it is given the
/// file's bytes. Invariant: gpg-agent greets as soon as it has read them; a
/// listener that does not within the time Windows gives an unresponsive
/// program is not answering as an agent.
pub const GREETING: Duration = crate::PATIENCE;

/// The `GnuPG` a capability's source names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gnupg {
    pub installation: Installation,
    pub home: Home,
    pub access: Access,
}

/// What an admitted connection is carried to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relaying {
    /// The workstation's own gpg-agent, by the [`Conversation`].
    Gnupg(Gnupg),
    /// A service the workstation reaches, byte for byte
    /// ([`crate::service`]).
    Service(crate::service::Service),
    /// The workstation's ADB server, by its requests ([`crate::adb`]):
    /// what the connection's remote has carried on to it, what its grant
    /// lends, and the watch of the server's devices.
    Adb {
        service: crate::service::Service,
        carried: crate::adb::Carried,
        lending: crate::adb::Lending,
    },
    /// The workstation's browser, given what the remote's `curl` posts
    /// ([`crate::browse`]).
    Browse(crate::browse::Browse),
    /// A serial port of the workstation's, as RFC 2217 ([`crate::serial`]).
    Serial(crate::serial::Serial),
    /// The person's own SSH agent, by its requests ([`crate::ssh`]).
    Agent(crate::ssh::SshAgent),
    /// The workstation's own git credential system, asked for one site's
    /// credential at a time ([`crate::credential`]).
    Credential(crate::credential::Credential),
    /// The person's attention, told what the remote's jobs say
    /// ([`crate::notify`]).
    Notify,
}

/// What a relayed connection tells the deciding thread.
#[derive(Debug, PartialEq, Eq)]
pub enum Relayed {
    /// The remote did not present the bytes Hedwig issued for its socket
    /// file. Nothing was written to it.
    Unpresented,
    /// The workstation's side answered, or why it did not: the connection's
    /// own request to be served.
    Reached(Result<(), Failure>),
    /// A request the conversation holds for a decision.
    Asks(Ask),
    /// A signature an SSH agent's conversation holds for a decision.
    Signs(crate::agent::Ask),
    /// An end broke the SSH agent protocol, and the connection was closed.
    Strayed(crate::agent::Breach),
    /// What held the workstation's side when it was reached: the process
    /// listening at its port or serving its pipe, `None` where nothing
    /// answered. Told before [`Relayed::Reached`], and again for each request
    /// an agent's conversation reaches the agent for.
    Held(Option<SourceHolder>),
    /// An end broke the dialect's rules, and the connection was closed.
    Breached(Breach),
    /// An end broke ADB's rules, and the connection was closed.
    Misframed(crate::adb::Breach),
    /// A request refused at the relay; the remote was told so in ADB's form.
    Withheld(Withheld),
    /// A reverse waiting for the endpoint it lands on.
    Reverse(Target),
    /// The device took a reverse to `target`, which the workstation's server
    /// reaches at `endpoint`.
    Reversed { target: Target, endpoint: Port },
    /// The connection uses this lent device from here.
    Selected(DeviceSerial),
    /// A forward waiting for its port on the remote: `port` there, 0 for
    /// any.
    Forward {
        port: u16,
        device: DeviceSerial,
        socket: DeviceSocket,
    },
    /// The server took a forward, on the device with transport id `id`, in
    /// place of `replaced` where one held the same port on the remote.
    Forwarded {
        forward: crate::adb::Forward,
        replaced: Option<crate::adb::Forward>,
        id: u64,
    },
    /// A forward placed on the remote at this port that the server refused.
    Unplaced(Port),
    /// The remote removed its forward at this port.
    Unforwarded(Port),
    /// What the remote sent is not the post its `curl` makes; it was told so
    /// and the connection closed.
    Misread(crate::browse::Malformed),
    /// The remote's `curl` asks the browser to open `asked`. `held` is the
    /// workstation port its callback needs where another program holds it.
    /// The text is never recorded.
    Opens { asked: String, held: Option<Port> },
    /// The browser was started with the served URL, or why it was not.
    Browsed(Result<(), Failure>),
    /// The authorisation server's answer reached the remote through the
    /// callback.
    Called,
    /// The callback's time ran out unanswered.
    Expired,
    /// The served opening's serial port was opened for it, over the USB
    /// device given where it is one; or why it was not.
    Opened(Result<Option<hedwig_model::protocol::Usb>, Failure>),
    /// The serial port the connection held is closed.
    Released,
    /// What a remote's `git` sent is not what its cache helper sends; the
    /// connection was closed with nothing said.
    Misasked(hedwig_model::credential::Unread),
    /// A remote's `git` said this site refused a credential it was given.
    Erased(hedwig_model::credential::Place),
    /// A remote's `git` asks for a credential for this place.
    Wants(hedwig_model::credential::Place),
    /// What became of the credential a served request asked for.
    Gave(crate::credential::Release),
    /// A remote's job says this to the person.
    Says(hedwig_model::text::Remark),
    /// The remote broke RFC 2217 and its session was ended.
    Broke(crate::rfc2217::Breach),
    /// The serial port failed under the session, which ended; the port is
    /// not there now, or is.
    Lost(Failure),
    /// The connection is over.
    Ended,
}

/// Where a `GnuPG` keeps its agent's socket file, as its own `gpgconf` says.
#[derive(Debug, Clone)]
struct Located {
    gpgconf: PathBuf,
    socket: PathBuf,
}

/// The `gpgconf` of an installation.
///
/// # Errors
///
/// [`Failure::Unresolved`] where the installation registers no folder, or
/// the folder holds no `gpgconf`.
pub fn gpgconf(installation: &Installation) -> Result<PathBuf, Failure> {
    let folder = match installation {
        Installation::Registered => {
            hedwig_win::registry::registered("Software\\GnuPG", "Install Directory")
                .ok()
                .flatten()
                .map(PathBuf::from)
                .ok_or(Failure::Unresolved)?
        }
        Installation::At(folder) => folder.as_path().to_path_buf(),
    };
    let program = folder.join("bin").join("gpgconf.exe");
    if program.is_file() {
        Ok(program)
    } else {
        Err(Failure::Unresolved)
    }
}

pub(crate) fn home_arguments(home: &Home) -> Vec<OsString> {
    match home {
        Home::Default => Vec::new(),
        Home::At(folder) => vec!["--homedir".into(), folder.as_str().into()],
    }
}

/// What a program printed, at most a frame of it, and whether it ended well.
pub(crate) fn ran(
    program: &Path,
    arguments: &[OsString],
    flags: u32,
) -> io::Result<(Vec<u8>, bool)> {
    let mut started = apart(program, arguments, flags)?;
    let mut printed = Vec::new();
    (&mut started.said)
        .take(hedwig_model::wire::FRAME as u64)
        .read_to_end(&mut printed)?;
    let status = started.wait()?;
    Ok((printed, status == 0))
}

/// `%XX` as `GnuPG`'s tools escape a value they print.
pub fn unescape(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut rest = text;
    while let Some((&byte, tail)) = rest.split_first() {
        let hex = tail
            .get(..2)
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| u8::from_str_radix(digits, 16).ok());
        if let (b'%', Some(value)) = (byte, hex) {
            out.push(value);
            rest = tail.get(2..).unwrap_or_default();
        } else {
            out.push(byte);
            rest = tail;
        }
    }
    out
}

/// The value `gpgconf --list-dirs` prints for `name`, unescaped.
pub fn listed(printed: &[u8], name: &str) -> Option<Vec<u8>> {
    printed.split(|byte| *byte == b'\n').find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let (key, value) = line.split_at(line.iter().position(|byte| *byte == b':')?);
        (key == name.as_bytes()).then(|| unescape(value.get(1..).unwrap_or_default()))
    })
}

/// Where the source's agent keeps the socket file this capability is
/// carried to.
///
/// # Errors
///
/// [`Failure::Unresolved`] where `gpgconf` does not answer;
/// [`Failure::Unserved`] where it answers with a POSIX path, as a
/// POSIX-emulated `GnuPG` does, which Hedwig neither starts nor serves.
fn locate(source: &Gnupg) -> Result<Located, Failure> {
    let gpgconf = gpgconf(&source.installation)?;
    let mut arguments = home_arguments(&source.home);
    arguments.push("--list-dirs".into());
    let (printed, ended_well) =
        ran(&gpgconf, &arguments, UNSEEN).map_err(|_| Failure::Unresolved)?;
    let name = match source.access {
        Access::Restricted => "agent-extra-socket",
        Access::Unrestricted => "agent-socket",
    };
    let socket = listed(&printed, name)
        .filter(|_| ended_well)
        .ok_or(Failure::Unresolved)?;
    if socket.first() == Some(&b'/') {
        return Err(Failure::Unserved);
    }
    let socket = String::from_utf8(socket).map_err(|_| Failure::Unresolved)?;
    Ok(Located {
        gpgconf,
        socket: PathBuf::from(socket),
    })
}

/// Starts the source's agent, and `keyboxd` where its `gpg` uses one, with
/// its own `gpgconf`, outside every job Hedwig holds: the agent is the
/// person's, and outlives Hedwig as one started from their own terminal
/// would.
///
/// # Errors
///
/// What the system said; access denied where a job holding this process
/// does not let a process leave it.
pub fn launch(gpgconf: &Path, home: &Home, keyboxd: bool) -> io::Result<()> {
    let components: &[&str] = if keyboxd {
        &["gpg-agent", "keyboxd"]
    } else {
        &["gpg-agent"]
    };
    for component in components {
        let mut arguments = home_arguments(home);
        arguments.extend(["--launch".into(), (*component).into()]);
        let started = apart(gpgconf, &arguments, LEAVING)?;
        // What it prints is not read: the agent it starts can hold the pipe
        // open for as long as it runs.
        started.wait()?;
    }
    Ok(())
}

/// The resolved socket file of each source, kept between connections: only
/// its path, which changes when the person changes their `GnuPG`, never what
/// it holds, which is read for every connection. A connection that cannot
/// reach the agent forgets it, so the next is resolved again.
#[derive(Debug, Default)]
pub struct Agents {
    located: Mutex<BTreeMap<Gnupg, Located>>,
}

/// Why one attempt to reach the agent failed, and whether starting it can
/// mend that.
enum Missed {
    Mendable(Failure),
    Final(Failure),
}

impl Agents {
    fn located(&self, source: &Gnupg) -> Result<Located, Failure> {
        if let Some(found) = self
            .located
            .lock()
            .ok()
            .and_then(|located| located.get(source).cloned())
        {
            return Ok(found);
        }
        let found = locate(source)?;
        if let Ok(mut located) = self.located.lock() {
            located.insert(source.clone(), found.clone());
        }
        Ok(found)
    }

    fn forget(&self, source: &Gnupg) {
        if let Ok(mut located) = self.located.lock() {
            located.remove(source);
        }
    }

    /// A connection to the source's agent, given the file's bytes and
    /// greeted, and the greeting, or the failure that stands after the agent
    /// was started once; with what listened where the file points.
    pub fn reach(&self, source: &Gnupg) -> Reach<(TcpStream, Vec<u8>)> {
        let mut last = Reach::failed(Failure::Unreachable);
        for attempt in 0..2 {
            let found = match self.located(source) {
                Ok(found) => found,
                Err(failure) => return Reach::failed(failure),
            };
            let (attempted, holder) = attempt_on(&found);
            match attempted {
                Ok(reached) => {
                    return Reach {
                        result: Ok(reached),
                        holder,
                    };
                }
                Err(Missed::Final(failure)) => {
                    self.forget(source);
                    return Reach {
                        result: Err(failure),
                        holder,
                    };
                }
                Err(Missed::Mendable(failure)) => {
                    self.forget(source);
                    last = Reach {
                        result: Err(failure),
                        holder,
                    };
                    if attempt == 0 && launch(&found.gpgconf, &source.home, false).is_err() {
                        return last;
                    }
                }
            }
        }
        last
    }
}

/// The socket file read into a buffer of the stack, erased before return.
pub(crate) fn read_socket_file(path: &Path) -> io::Result<Result<SocketFile, assuan::Unparsed>> {
    let mut buffer = [0u8; 64];
    let mut file = std::fs::File::open(path)?;
    let mut filled = 0;
    while let Some(free) = buffer.get_mut(filled..).filter(|free| !free.is_empty()) {
        let read = file.read(free)?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    let read = assuan::socket_file(buffer.get(..filled).unwrap_or_default());
    buffer.zeroize();
    Ok(read)
}

type Attempt = (Result<(TcpStream, Vec<u8>), Missed>, Option<SourceHolder>);

fn attempt_on(found: &Located) -> Attempt {
    let file = match read_socket_file(&found.socket) {
        Err(_) | Ok(Err(_)) => return (Err(Missed::Mendable(Failure::Unreachable)), None),
        Ok(Ok(SocketFile::Cygwin { .. })) => return (Err(Missed::Final(Failure::Unserved)), None),
        Ok(Ok(file)) => file,
    };
    let SocketFile::Native { port, nonce } = file else {
        return (Err(Missed::Final(Failure::Unserved)), None);
    };
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let Ok(mut agent) = TcpStream::connect_timeout(&address.into(), crate::PATIENCE) else {
        return (Err(Missed::Mendable(Failure::Unreachable)), None);
    };
    let (admission, holder) = admitted(&agent, &found.socket);
    if let Err(failure) = admission {
        let _ = agent.shutdown(Shutdown::Both);
        return (Err(Missed::Mendable(failure)), holder);
    }
    if agent.write_all(nonce.as_bytes()).is_err() {
        return (Err(Missed::Mendable(Failure::Unreachable)), holder);
    }
    drop(nonce);
    match greeting(&mut agent) {
        Some(greeting) => (Ok((agent, greeting)), holder),
        None => (Err(Missed::Mendable(Failure::Mismatched)), holder),
    }
}

/// What reaching the workstation's side came to, and what held it there: the
/// process listening at its port or serving its pipe, where one was read.
#[derive(Debug, PartialEq, Eq)]
pub struct Reach<T> {
    pub result: Result<T, Failure>,
    pub holder: Option<SourceHolder>,
}

impl<T> Reach<T> {
    pub(crate) fn failed(failure: Failure) -> Reach<T> {
        Reach {
            result: Err(failure),
            holder: None,
        }
    }

    /// The reach as the deciding thread is told it: what held the side,
    /// then whether it answered.
    pub(crate) fn tell(&self, tell: &impl Fn(Relayed)) {
        tell(Relayed::Held(self.holder.clone()));
        tell(Relayed::Reached(
            self.result.as_ref().map(|_| ()).map_err(|failure| *failure),
        ));
    }
}

/// Whether the process listening at the other end of `agent` may be given
/// `socket_file`'s bytes, and what it is: the person's or a service, as every
/// source's holder must be, and one that could read the file itself, so the
/// file is never withheld from what it admits and nothing else learns what
/// it holds.
pub(crate) fn admitted(
    agent: &TcpStream,
    socket_file: &Path,
) -> (Result<(), Failure>, Option<SourceHolder>) {
    let Some(listener) = owner(agent).ok().flatten() else {
        return (Err(Failure::Unreachable), None);
    };
    let Some(holder) = crate::holder::of(listener) else {
        return (Err(Failure::Unreachable), None);
    };
    if let Err(failure) = holder.admitted() {
        return (Err(failure), Some(holder));
    }
    let reads = Process::open(listener)
        .ok()
        .and_then(|process| process.token_to_check().ok())
        .and_then(|token| token.may_read(socket_file).ok())
        .unwrap_or(false);
    let admission = if reads {
        Ok(())
    } else {
        Err(Failure::Mismatched)
    };
    (admission, Some(holder))
}

/// The agent's first line, where it is one an Assuan server greets with.
fn greeting(agent: &mut TcpStream) -> Option<Vec<u8>> {
    agent.set_read_timeout(Some(GREETING)).ok()?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < LINE {
        match agent.read(&mut byte) {
            Ok(1) => {
                line.extend_from_slice(&byte);
                if byte == *b"\n" {
                    break;
                }
            }
            _ => return None,
        }
    }
    agent.set_read_timeout(None).ok()?;
    assuan::greets(&line).then_some(line)
}

/// What one of a connection's threads tells the one that owns it.
#[derive(Debug)]
pub(crate) enum Event {
    Client(Vec<u8>),
    ClientClosed,
    Agent(Vec<u8>),
    AgentClosed,
    /// The deciding thread has settled the held request.
    Settled,
    /// The answer a callback waits for was carried to the remote.
    Called,
    /// The server's devices changed, or were read again.
    Viewed,
}

/// Where the deciding thread puts its word on a connection's held request,
/// and the run the endpoint a held reverse lands on.
#[derive(Debug)]
pub struct Settle {
    word: Mutex<Option<Result<(), Refusal>>>,
    endpoint: Mutex<Option<Result<Port, Option<Withheld>>>>,
    /// A held forward's port on the remote, or the words for why none was
    /// bound there.
    placed: Mutex<Option<Result<Port, String>>>,
    /// Whether the forward the server took was recorded and its endpoint
    /// given the server's listener, or the words for why it was not.
    listening: Mutex<Option<Result<(), String>>>,
    /// What the connection's grant lends now.
    lending: Mutex<Option<crate::adb::Lending>>,
    /// The carrier a served callback goes on through: the channel whose job
    /// holds it, and the port it listens on.
    carrier: Mutex<Option<(ConnectionId, Port)>>,
    /// Whether what serves a request may ask the person, as the deciding
    /// thread settled it.
    interaction: Mutex<Option<hedwig_model::gate::Interaction>>,
    stopped: AtomicBool,
    wake: SyncSender<Event>,
}

impl Settle {
    pub(crate) fn new(wake: SyncSender<Event>) -> Settle {
        Settle {
            word: Mutex::new(None),
            endpoint: Mutex::new(None),
            placed: Mutex::new(None),
            listening: Mutex::new(None),
            lending: Mutex::new(None),
            carrier: Mutex::new(None),
            interaction: Mutex::new(None),
            stopped: AtomicBool::new(false),
            wake,
        }
    }

    /// Lets what serves the request ask the person, or not; given before the
    /// word that serves it. Never waits.
    pub fn interact(&self, interaction: hedwig_model::gate::Interaction) {
        if let Ok(mut held) = self.interaction.lock() {
            *held = Some(interaction);
        }
    }

    /// Whether what serves the request may ask the person: not unless the
    /// deciding thread said so.
    pub(crate) fn interaction(&self) -> hedwig_model::gate::Interaction {
        self.interaction
            .lock()
            .ok()
            .and_then(|held| *held)
            .unwrap_or(hedwig_model::gate::Interaction::Off)
    }

    /// Gives a served callback its carrier. Never waits.
    pub fn call(&self, connection: ConnectionId, listen: Port) {
        if let Ok(mut carrier) = self.carrier.lock() {
            *carrier = Some((connection, listen));
        }
    }

    pub(crate) fn carrier(&self) -> Option<(ConnectionId, Port)> {
        self.carrier.lock().ok().and_then(|carrier| *carrier)
    }

    /// Stops what the connection still carries: a callback whose channel
    /// ended. Never waits.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        match self.wake.try_send(Event::Settled) {
            Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    pub(crate) fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Gives a held reverse the endpoint it lands on, or refuses it, with
    /// `None` where the workstation could bind none. Never waits, as
    /// [`Settle::settle`].
    pub fn carry(&self, verdict: Result<Port, Option<Withheld>>) {
        if let Ok(mut endpoint) = self.endpoint.lock() {
            *endpoint = Some(verdict);
        }
        match self.wake.try_send(Event::Settled) {
            Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    /// Gives a held forward its port on the remote, or the words for why
    /// none was bound there. Never waits.
    pub fn place(&self, placed: Result<Port, String>) {
        if let Ok(mut held) = self.placed.lock() {
            *held = Some(placed);
        }
        match self.wake.try_send(Event::Settled) {
            Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    pub(crate) fn take_placed(&self) -> Option<Result<Port, String>> {
        self.placed.lock().ok().and_then(|mut placed| placed.take())
    }

    /// Tells a forward the server took that the core recorded it and its
    /// endpoint goes on to the server's listener, or the words for why it
    /// does not. Never waits.
    pub fn listen(&self, listening: Result<(), String>) {
        if let Ok(mut held) = self.listening.lock() {
            *held = Some(listening);
        }
        match self.wake.try_send(Event::Settled) {
            Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    pub(crate) fn take_listening(&self) -> Option<Result<(), String>> {
        self.listening
            .lock()
            .ok()
            .and_then(|mut listening| listening.take())
    }

    /// What the connection's grant lends changed. Never waits.
    pub fn relend(&self, lending: crate::adb::Lending) {
        if let Ok(mut held) = self.lending.lock() {
            *held = Some(lending);
        }
        match self.wake.try_send(Event::Settled) {
            Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    pub(crate) fn take_lending(&self) -> Option<crate::adb::Lending> {
        self.lending
            .lock()
            .ok()
            .and_then(|mut lending| lending.take())
    }

    pub(crate) fn take_endpoint(&self) -> Option<Result<Port, Option<Withheld>>> {
        self.endpoint
            .lock()
            .ok()
            .and_then(|mut endpoint| endpoint.take())
    }

    /// Serves the held request, or refuses it. Never waits: where the
    /// connection's queue is full, its thread finds the word when it next
    /// takes from the queue.
    pub fn settle(&self, verdict: Result<(), Refusal>) {
        if let Ok(mut word) = self.word.lock() {
            *word = Some(verdict);
        }
        match self.wake.try_send(Event::Settled) {
            Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    pub(crate) fn take(&self) -> Option<Result<(), Refusal>> {
        self.word.lock().ok().and_then(|mut word| word.take())
    }
}

/// How many events a connection's readers may queue before they wait.
/// Invariant: a reader that waits stops reading, so the end it reads is
/// held back rather than the core growing for it.
pub(crate) const QUEUED: usize = 4;

pub(crate) fn read_into(mut from: TcpStream, events: &SyncSender<Event>, side: assuan::Side) {
    let mut buffer = [0u8; 8192];
    loop {
        let read = from.read(&mut buffer);
        let event = match (read, side) {
            (Ok(0) | Err(_), assuan::Side::Client) => Event::ClientClosed,
            (Ok(0) | Err(_), assuan::Side::Agent) => Event::AgentClosed,
            (Ok(read), side) => {
                let bytes = buffer.get(..read).unwrap_or_default().to_vec();
                match side {
                    assuan::Side::Client => Event::Client(bytes),
                    assuan::Side::Agent => Event::Agent(bytes),
                }
            }
        };
        let last = matches!(event, Event::ClientClosed | Event::AgentClosed);
        if events.send(event).is_err() || last {
            break;
        }
    }
    buffer.zeroize();
}

/// Carries one admitted connection. `presents` are the bytes a Windows
/// remote's socket file holds, which its client sends first; `tell` reaches
/// the deciding thread. Returns where the deciding thread settles what the
/// connection asks; the connection itself runs on threads of its own.
pub fn carry(
    client: TcpStream,
    presents: Option<Nonce>,
    source: Gnupg,
    agents: Arc<Agents>,
    tell: impl Fn(Relayed) + Send + 'static,
) -> Arc<Settle> {
    let (events, queue) = mpsc::sync_channel(QUEUED);
    let settle = Arc::new(Settle::new(events.clone()));
    let held = Arc::clone(&settle);
    thread::spawn(move || {
        run(
            client, presents, &source, &agents, &tell, &events, &queue, &held,
        );
        tell(Relayed::Ended);
    });
    settle
}

fn send(stream: &mut TcpStream, bytes: &[u8]) -> bool {
    stream.write_all(bytes).is_ok()
}

#[allow(
    clippy::too_many_arguments,
    reason = "the one function that owns a connection, given everything it holds"
)]
fn run(
    client: TcpStream,
    presents: Option<Nonce>,
    source: &Gnupg,
    agents: &Agents,
    tell: &impl Fn(Relayed),
    events: &SyncSender<Event>,
    queue: &Receiver<Event>,
    settle: &Settle,
) {
    let Ok(client_reader) = client.try_clone() else {
        return;
    };
    let mut client = client;
    {
        let events = events.clone();
        thread::spawn(move || read_into(client_reader, &events, assuan::Side::Client));
    }
    let mut early = Vec::new();
    if let Some(issued) = presents {
        while early.len() < NONCE {
            match queue.recv() {
                Ok(Event::Client(bytes)) => early.extend_from_slice(&bytes),
                _ => break,
            }
        }
        let presented = early.get(..NONCE).unwrap_or_default();
        if !issued.matches(presented) {
            early.zeroize();
            tell(Relayed::Unpresented);
            let _ = client.shutdown(Shutdown::Both);
            return;
        }
        early.drain(..NONCE);
    }
    let reached = agents.reach(source);
    reached.tell(tell);
    let Ok((agent, greeting)) = reached.result else {
        if let Some(Err(refusal)) = wait(queue, settle) {
            send(&mut client, &assuan::refused(&refusal));
        }
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    carry_on(client, agent, greeting, early, tell, events, queue, settle);
}

/// Carries a connection that reached the agent, from its greeting on.
#[allow(
    clippy::too_many_arguments,
    reason = "the second half of `run`, given everything it holds"
)]
fn carry_on(
    mut client: TcpStream,
    mut agent: TcpStream,
    greeting: Vec<u8>,
    mut early: Vec<u8>,
    tell: &impl Fn(Relayed),
    events: &SyncSender<Event>,
    queue: &Receiver<Event>,
    settle: &Settle,
) {
    let Ok(agent_reader) = agent.try_clone() else {
        return;
    };
    {
        let events = events.clone();
        thread::spawn(move || read_into(agent_reader, &events, assuan::Side::Agent));
    }
    let mut talk = Conversation::opened(greeting);
    let mut pending = vec![Event::Client(std::mem::take(&mut early))];
    'carry: loop {
        let event = match pending.pop() {
            Some(event) => event,
            None => match queue.recv() {
                Ok(event) => event,
                Err(_) => break,
            },
        };
        let outs = match event {
            Event::Client(bytes) if bytes.is_empty() => Ok(Vec::new()),
            Event::Client(bytes) => talk.from_client(&bytes),
            Event::Agent(bytes) => talk.from_agent(&bytes),
            Event::ClientClosed => {
                if let Err(breach) = talk.client_closed() {
                    tell(Relayed::Breached(breach));
                }
                break;
            }
            Event::AgentClosed => break,
            Event::Called | Event::Viewed => Ok(Vec::new()),
            Event::Settled => Ok(match settle.take() {
                Some(Ok(())) if talk.holds() => talk.serve(),
                Some(Err(refusal)) if talk.holds() => talk.refuse(&refusal),
                _ => Vec::new(),
            }),
        };
        let outs = match outs {
            Ok(outs) => outs,
            Err(breach) => {
                tell(Relayed::Breached(breach));
                break;
            }
        };
        for out in outs {
            let carried = match out {
                Out::ToAgent(bytes) => send(&mut agent, &bytes),
                Out::ToClient(bytes) => send(&mut client, &bytes),
                Out::Ask(ask) => {
                    tell(Relayed::Asks(ask));
                    true
                }
            };
            if !carried {
                break 'carry;
            }
        }
        if !talk.open() {
            break;
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = agent.shutdown(Shutdown::Both);
}

/// Waits for the deciding thread's word on the connection's request.
pub(crate) fn wait(queue: &Receiver<Event>, settle: &Settle) -> Option<Result<(), Refusal>> {
    loop {
        if let Some(word) = settle.take() {
            return Some(word);
        }
        if let Ok(Event::ClientClosed) | Err(_) = queue.recv() {
            return None;
        }
    }
}
