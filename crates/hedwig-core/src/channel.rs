//! A channel: a route's client, held in a job of its own for one remote, with
//! the forwards that remote's grants ask for.
//!
//! The deciding thread says when one starts and ends. What it is started
//! with - the options the core adds, the forwards, its variables - is decided
//! here as plain functions, and the waits are threads of their own: one holds
//! the client until it ends, one reads what it says, and one waits at the
//! workstation end of each forward.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, PipeReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hedwig_model::capability::Query;
use hedwig_model::protocol::Hint;
use hedwig_model::remote::Client;
use hedwig_model::setting::Keepalive;
use hedwig_model::text::{Address, Location, Mark, Name, PipeName, Port, Words};
use hedwig_model::trail::{
    Asking, Binding, ChannelEnd, ConnectionId, Finding, PromptKind, Release, Serving, Target,
};
use hedwig_model::wire::FRAME;
use hedwig_win::Signal;
use hedwig_win::endpoint::Endpoint;
use hedwig_win::process::Job;
use hedwig_win::search::{SearchError, program_on};
use hedwig_win::start::{Environment, Held, consulted, fed, held};
use hedwig_win::version::release;

use crate::diagnostics::Diagnostics;
use crate::dispatch::{Input, Told};
use crate::peer::knocker;
use crate::run::Message;
use crate::survey::{self, Dialect, Plan, Report, Unread};

/// What the core sets on every channel, over whatever the person's
/// configuration says for the host. Everything else - the host, the user,
/// the port, the keys, a jump host or a proxy - is the person's to say.
pub const SET: [&str; 10] = [
    // One forward the server refuses ends neither the others nor the channel.
    "ExitOnForwardFailure=no",
    // What the client says is read, so it is said at the level it says it at.
    "LogLevel=INFO",
    // The server's answer for each forward, which the client otherwise keeps
    // to itself. The function is named and its file is not: the in-box
    // client knows its files by the whole path they were built from.
    "LogVerbose=*:ssh_confirm_remote_forward():*",
    // A name the person's own configuration can tell this connection by.
    "Tag=hedwig",
    // Nothing of the person's rides a channel they did not open themselves.
    "ForwardAgent=no",
    "ForwardX11=no",
    "PermitLocalCommand=no",
    // The process that connects to the core is the one in the channel's job,
    // never another the person's sessions share.
    "ControlMaster=no",
    "ControlPath=none",
    // On Windows a client sent to the background points what it says at
    // nothing once it has authenticated, and the core reads what it says.
    "ForkAfterAuthentication=no",
];

/// The variable that tells Hedwig it was started as a channel's askpass, and
/// names the pipe it asks through. Its presence decides, never an argument:
/// the argument is the client's prompt, and part of it can be the server's
/// words.
pub const PIPE: &str = "HEDWIG_PIPE";

/// Where a channel's client sends what it asks: Hedwig's own executable,
/// asking the core through its pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Askpass {
    pub program: PathBuf,
    pub pipe: PipeName,
}

/// The channel's variables: the core's `own`, which are the person's, with
/// every prompt the client raises sent to Hedwig and none to a program of
/// theirs. The route is forced whether or not anyone can be asked: a prompt
/// batch mode does not stop would otherwise be read from a console no window
/// shows, and wait for ever.
///
/// ```
/// use hedwig_core::channel::{Askpass, PIPE, environment};
/// use hedwig_model::text::PipeName;
/// use hedwig_win::start::Environment;
///
/// let askpass = Askpass {
///     program: r"C:\Program Files\hedwig\hedwig.exe".into(),
///     pipe: PipeName::try_from("hedwig.9f86d081884c7d659a2feaa0c55ad015")?,
/// };
/// let set = environment(Environment::own().with("SSH_ASKPASS", "gnome-ssh-askpass"), &askpass);
/// assert_eq!(set.get("SSH_ASKPASS_REQUIRE"), Some("force".as_ref()));
/// assert_eq!(set.get(PIPE), Some("hedwig.9f86d081884c7d659a2feaa0c55ad015".as_ref()));
/// assert_eq!(set.get("SSH_ASKPASS"), Some(r"C:\Program Files\hedwig\hedwig.exe".as_ref()));
/// # Ok::<(), hedwig_model::text::TextError>(())
/// ```
pub fn environment(own: Environment, askpass: &Askpass) -> Environment {
    own.without("DISPLAY")
        .without("SSH_ASKPASS_PROMPT")
        .with_os("SSH_ASKPASS", askpass.program.as_os_str())
        .with("SSH_ASKPASS_REQUIRE", "force")
        .with(PIPE, askpass.pipe.as_str())
}

/// A forward as OpenSSH's `-R` takes it: the remote end, then the core's
/// endpoint on this workstation. A backslash keeps the character after it,
/// so one stands before each character of a path the client would otherwise
/// read as a separator.
///
/// ```
/// use hedwig_core::channel::forward;
/// use hedwig_model::text::Port;
/// use hedwig_model::trail::Binding;
///
/// let adb = Binding::Port(Port::try_from(5037)?);
/// assert_eq!(forward(&adb, Port::try_from(50123)?), "5037:127.0.0.1:50123");
/// # Ok::<(), hedwig_model::text::TextError>(())
/// ```
///
/// The workstation end is a port the core bound, never a bare number:
///
/// ```compile_fail
/// use hedwig_core::channel::forward;
/// use hedwig_model::text::Port;
/// use hedwig_model::trail::Binding;
///
/// let adb = Binding::Port(Port::try_from(5037)?);
/// assert_eq!(forward(&adb, 50123), "5037:127.0.0.1:50123");
/// # Ok::<(), hedwig_model::text::TextError>(())
/// ```
pub fn forward(binding: &Binding, endpoint: Port) -> String {
    let listen = match binding {
        Binding::Socket(path) => {
            let mut listen = String::new();
            // Only a field with a slash in it is read as a path.
            if !path.as_str().contains('/') {
                listen.push_str("./");
            }
            for character in path.as_str().chars() {
                if matches!(character, '\\' | ':' | '[') {
                    listen.push('\\');
                }
                listen.push(character);
            }
            listen
        }
        Binding::SocketFile { port, .. } | Binding::Port(port) => port.to_string(),
    };
    format!("{listen}:127.0.0.1:{endpoint}")
}

/// Everything the core passes between what a route's entry puts before and
/// after: no session, whether the client may ask, its own settings, how it
/// notices a dead link, and each forward.
pub fn options(forwards: &[(Serving, Port)], asking: Asking, keepalive: Keepalive) -> Vec<String> {
    let batch = match asking {
        Asking::Person => "BatchMode=no",
        Asking::Nobody => "BatchMode=yes",
    };
    let mut options = vec!["-N".to_owned(), "-o".to_owned(), batch.to_owned()];
    for set in SET {
        options.extend(["-o".to_owned(), set.to_owned()]);
    }
    options.extend([
        "-o".to_owned(),
        format!("ServerAliveInterval={}", keepalive.every),
        "-o".to_owned(),
        format!("ServerAliveCountMax={}", keepalive.missed),
    ]);
    for (serving, endpoint) in forwards {
        options.extend(["-R".to_owned(), forward(&serving.binding, *endpoint)]);
    }
    options
}

/// One line of what a channel's client wrote, as far as the core reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Heard {
    /// The remote's server answered for the forward to this endpoint.
    Forward {
        endpoint: u16,
        bound: bool,
    },
    /// The remote's server listens at `port` for the forward to this
    /// endpoint, which asked for a port of its choosing.
    Allocated {
        port: u16,
        endpoint: u16,
    },
    /// The host presented another key than the one known.
    Changed,
    /// The line that introduces the fingerprint of the key presented.
    Presents,
    /// The client would not go on without the person confirming the host's
    /// key.
    Unverified,
    Other,
}

/// What marks a line the client was made to say about a forward's answer.
const ANSWERS: &str = ":ssh_confirm_remote_forward():";

/// Reads one line. The words are OpenSSH's own and are not translated
/// (`ssh.c:1839`, `sshconnect.c:1675` and `:1680`, `sshconnect2.c:109` at
/// v9.5.0.0; the same at v10.0.0.0).
pub fn heard(line: &str) -> Heard {
    let answered = |word: &str| {
        let (said, port) = line.rsplit_once(", connect 127.0.0.1:")?;
        let endpoint = port.trim().parse().ok()?;
        (said.contains(ANSWERS) && said.contains(word)).then_some(endpoint)
    };
    if let Some(endpoint) = answered("remote forward success for: listen ") {
        Heard::Forward {
            endpoint,
            bound: true,
        }
    } else if let Some(endpoint) = answered("remote forward failure for: listen ") {
        Heard::Forward {
            endpoint,
            bound: false,
        }
    } else if let Some(allocated) = allocated(line) {
        allocated
    } else if line.contains("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!") {
        Heard::Changed
    } else if line.starts_with("The fingerprint for the ")
        && line.ends_with(" key sent by the remote host is")
    {
        Heard::Presents
    } else if line.starts_with("Host key verification failed.") {
        Heard::Unverified
    } else {
        Heard::Other
    }
}

/// `Allocated port <port> for remote forward to 127.0.0.1:<endpoint>`, which
/// the client says at `LogLevel=INFO` (`ssh.c:1860` at v9.5.0.0, `:1986` at
/// v10.0.0.0) - marked as the function's own, since the `LogVerbose` a carrier
/// is started with forces it (`log.c:477-490`), or bare from a client that
/// does not mark it.
fn allocated(line: &str) -> Option<Heard> {
    let (said, rest) = line.split_once("Allocated port ")?;
    if !(said.is_empty() || (said.contains(ANSWERS) && said.ends_with("): "))) {
        return None;
    }
    let (port, rest) = rest.split_once(' ')?;
    let endpoint = rest.strip_prefix("for remote forward to 127.0.0.1:")?;
    Some(Heard::Allocated {
        port: port.parse().ok()?,
        endpoint: endpoint.trim().parse().ok()?,
    })
}

/// `text` as words a surface can show: a line break or a tab is a space,
/// anything else that would drive a terminal is left out, and it is cut to
/// the length words may have.
pub fn words(text: &str) -> Option<Words> {
    let mut kept = String::new();
    let spaced = text.chars().map(|character| {
        if character.is_whitespace() {
            ' '
        } else {
            character
        }
    });
    for character in spaced.filter(|character| !character.is_control()) {
        if kept.len() + character.len_utf8() > 1024 {
            break;
        }
        kept.push(character);
    }
    Words::try_from(kept.trim()).ok()
}

/// What a client's ending says of the channel, where nothing it said while
/// it ran has already ended it. `user@host: Permission denied (methods).` is
/// OpenSSH's own account of a server that accepted nothing the client could
/// offer (`sshconnect2.c:551` at v9.5.0.0, `:549` at v10.0.0.0), and is never
/// tried again by itself: each try would count against the person at the
/// server.
///
/// ```
/// use hedwig_core::channel::{ended, words};
/// use hedwig_model::trail::ChannelEnd;
///
/// let last = words("dev@build-7.example: Permission denied (publickey,password).");
/// assert_eq!(
///     ended(255, false, last),
///     ChannelEnd::Unauthenticated(words("publickey,password").expect("words")),
/// );
/// ```
pub fn ended(status: i32, unverified: bool, last: Option<Words>) -> ChannelEnd {
    if unverified {
        return ChannelEnd::Needs(PromptKind::UnknownHostKey);
    }
    let accepts = last.as_ref().and_then(|last| {
        let (_, methods) = last.as_str().split_once(": Permission denied (")?;
        words(methods.strip_suffix(").")?)
    });
    match accepts {
        Some(accepts) => ChannelEnd::Unauthenticated(accepts),
        None => ChannelEnd::Exited { status, last },
    }
}

/// What a channel's client asks, from the words it gave its askpass and the
/// hint it set. The words are OpenSSH's own and are not translated: the host
/// key (`sshconnect.c:1183`), a passphrase (`sshconnect2.c:1580`), a
/// password and its change (`:1084`, `:1138-1157`), a key's PIN (`:1298`),
/// adding a key to an agent (`sshconnect.c:1747`), and a server's challenge,
/// which the client puts after `(user@host) ` (`sshconnect2.c:2009`), at
/// v9.5.0.0. Anything else is a question in words the core does not know,
/// answered with text like a challenge.
///
/// ```
/// use hedwig_core::channel::{asked, words};
/// use hedwig_model::protocol::Hint;
/// use hedwig_model::trail::PromptKind;
///
/// let host = words("The authenticity of host 'build-7 (203.0.113.7)' can't be established.")
///     .expect("words");
/// assert_eq!(asked(&host, Some(Hint::Confirm)), PromptKind::UnknownHostKey);
/// ```
pub fn asked(words: &Words, hint: Option<Hint>) -> PromptKind {
    let said = words.as_str();
    if hint == Some(Hint::Notice) {
        PromptKind::SecurityKeyTouch
    } else if said.starts_with("The authenticity of host '") {
        PromptKind::UnknownHostKey
    } else if said.starts_with("Enter passphrase for key '") {
        PromptKind::KeyPassphrase
    } else if said.starts_with("Enter PIN for ") {
        PromptKind::SecurityKeyPin
    } else if said.starts_with("Add key ") && said.ends_with(" to agent?") {
        PromptKind::AgentConfirmation
    } else if said.starts_with('(') {
        PromptKind::Challenge
    } else if said.ends_with("'s password:")
        || said.ends_with("'s old password:")
        || said.ends_with("'s new password:")
    {
        PromptKind::Password
    } else {
        PromptKind::Challenge
    }
}

/// Where a channel's client is looked for and what it is started with.
#[derive(Debug, Clone)]
pub struct Setting {
    /// The folders searched, written as the search path is.
    pub search: OsString,
    pub environment: Environment,
}

impl Setting {
    /// The core's own search path and the variables [`environment`] gives.
    pub fn own(askpass: &Askpass) -> Setting {
        Setting {
            search: std::env::var_os("PATH").unwrap_or_default(),
            environment: environment(Environment::own(), askpass),
        }
    }
}

/// What the deciding thread asked a channel to be started with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub connection: ConnectionId,
    pub client: Client,
    pub address: Address,
    pub serving: Vec<Serving>,
    pub asking: Asking,
    pub keepalive: Keepalive,
}

/// What the deciding thread asked a survey to be run with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surveying {
    pub connection: ConnectionId,
    pub client: Client,
    pub address: Address,
    pub dialect: Dialect,
    pub plan: Plan,
    pub asking: Asking,
    pub keepalive: Keepalive,
}

/// What the deciding thread asked an exercise to be run with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exercising {
    pub connection: ConnectionId,
    pub client: Client,
    pub address: Address,
    pub dialect: Dialect,
    pub query: Option<Query>,
    pub binding: Binding,
    pub asking: Asking,
    pub keepalive: Keepalive,
}

/// What the deciding thread asked a carrier to be started with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hauling {
    pub connection: ConnectionId,
    pub client: Client,
    pub address: Address,
    pub target: Target,
    /// The workstation port the carrier listens on.
    pub listen: Port,
    pub asking: Asking,
    pub keepalive: Keepalive,
}

/// Everything a carrier is started with between what the route's entry puts
/// before and after: what a channel is started with, with no forward of the
/// remote's and one local forward to the target, on the workstation's
/// loopback. The person's own forwards bind or fail on their own account, as
/// on the channel.
///
/// ```
/// use hedwig_core::channel::haul;
/// use hedwig_model::setting::Keepalive;
/// use hedwig_model::text::Port;
/// use hedwig_model::trail::{Asking, Target};
///
/// let metro = Target::Loopback(Port::try_from(8081)?);
/// let options = haul(&metro, Port::try_from(50140)?, Asking::Nobody, Keepalive::SHIPS);
/// assert_eq!(options.first().map(String::as_str), Some("-N"));
/// assert!(options.ends_with(&["-L".to_owned(), "127.0.0.1:50140:localhost:8081".to_owned()]));
/// # Ok::<(), hedwig_model::text::TextError>(())
/// ```
pub fn haul(target: &Target, listen: Port, asking: Asking, keepalive: Keepalive) -> Vec<String> {
    let mut options = options(&[], asking, keepalive);
    options.extend(["-L".to_owned(), crate::adb::local_forward(target, listen)]);
    options
}

/// What the deciding thread asked a carrier that listens on the remote to be
/// started with: a forward from `port` on the remote's loopback, 0 for one
/// its server chooses, to the core's endpoint at `listen`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placing {
    pub connection: ConnectionId,
    pub client: Client,
    pub address: Address,
    pub port: u16,
    pub listen: Port,
    pub asking: Asking,
    pub keepalive: Keepalive,
}

/// Everything a carrier that listens on the remote is started with: what a
/// channel is started with, and one remote forward to the core's endpoint.
///
/// ```
/// use hedwig_core::channel::place;
/// use hedwig_model::setting::Keepalive;
/// use hedwig_model::text::Port;
/// use hedwig_model::trail::Asking;
///
/// let options = place(0, Port::try_from(50170)?, Asking::Nobody, Keepalive::SHIPS);
/// assert!(options.ends_with(&["-R".to_owned(), "0:127.0.0.1:50170".to_owned()]));
/// # Ok::<(), hedwig_model::text::TextError>(())
/// ```
pub fn place(port: u16, listen: Port, asking: Asking, keepalive: Keepalive) -> Vec<String> {
    let mut options = options(&[], asking, keepalive);
    options.extend(["-R".to_owned(), crate::adb::remote_forward(port, listen)]);
    options
}

/// How long a remote's shell has to finish readiness once it has begun it.
/// Invariant: every probe the script makes is bounded at [`survey::PROBE`]
/// seconds, twice at most, and a survey asks about a handful of
/// capabilities; a shell that has not finished in a minute is stuck, and the
/// connection is then over rather than left opening.
pub const READINESS: Duration = Duration::from_secs(60);

/// The job each live channel runs in, by its connection. A reader that finds
/// who connected asks each job whether it holds that process.
pub type Jobs = Arc<Mutex<BTreeMap<ConnectionId, Arc<Job>>>>;

/// The input of each survey whose shell waits, after its report, for the
/// word to seal Hedwig's private folder.
type Sealers = Arc<Mutex<BTreeMap<ConnectionId, std::io::PipeWriter>>>;

struct Live {
    job: Arc<Job>,
    stop: Arc<Signal>,
}

/// Each carrier the core can end before its channel ends, by its channel and
/// the port it listens on.
type Carriers = Arc<Mutex<BTreeMap<(ConnectionId, Port), Arc<Held>>>>;

/// The channels the core holds.
pub struct Channels {
    setting: Arc<Setting>,
    messages: Sender<Message>,
    /// Where what a channel's client says is written, where anything is.
    diagnostics: Option<Diagnostics>,
    live: BTreeMap<ConnectionId, Live>,
    jobs: Jobs,
    sealers: Sealers,
    carriers: Carriers,
}

fn say(messages: &Sender<Message>, connection: ConnectionId, told: Told) {
    let _ = messages.send(Message::Input(Input::Channel { connection, told }));
}

fn unstarted(messages: &Sender<Message>, connection: ConnectionId, account: &str) {
    let account = words(account).or_else(|| words("the system gave no account"));
    if let Some(end) = account.map(ChannelEnd::Unstarted) {
        say(messages, connection, Told::Unstarted { end });
    }
}

impl Channels {
    pub fn new(setting: Setting, messages: Sender<Message>) -> Channels {
        Channels {
            setting: Arc::new(setting),
            messages,
            diagnostics: None,
            live: BTreeMap::new(),
            jobs: Jobs::default(),
            sealers: Sealers::default(),
            carriers: Carriers::default(),
        }
    }

    /// Writes what each channel's client says to `diagnostics`, at the level
    /// they are set to.
    #[must_use]
    pub fn diagnosed(mut self, diagnostics: Diagnostics) -> Channels {
        self.diagnostics = Some(diagnostics);
        self
    }

    /// The jobs of the live channels, for a reader to attribute by.
    pub fn jobs(&self) -> Jobs {
        Arc::clone(&self.jobs)
    }

    /// The connection's job and the signal that ends its waits: those its
    /// survey made, or new ones. Everything a connection runs - its survey,
    /// its channel, an exercise - runs in the one job, so a prompt any of
    /// them raises is that connection's and one end ends them all.
    fn live(&mut self, connection: ConnectionId) -> Option<(Arc<Job>, Arc<Signal>)> {
        if let Some(live) = self.live.get(&connection) {
            return Some((Arc::clone(&live.job), Arc::clone(&live.stop)));
        }
        let made = Job::new().and_then(|job| Ok((Arc::new(job), Arc::new(Signal::new()?))));
        let (job, stop) = match made {
            Ok(made) => made,
            Err(error) => {
                unstarted(&self.messages, connection, &error.to_string());
                return None;
            }
        };
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(connection, Arc::clone(&job));
        }
        self.live.insert(
            connection,
            Live {
                job: Arc::clone(&job),
                stop: Arc::clone(&stop),
            },
        );
        Some((job, stop))
    }

    /// Starts a channel. The job exists when this returns; everything that
    /// can wait - finding the client, binding, starting it - is the new
    /// thread's.
    pub fn start(&mut self, order: Order) {
        let Some((job, stop)) = self.live(order.connection) else {
            return;
        };
        let (setting, messages) = (Arc::clone(&self.setting), self.messages.clone());
        let jobs = Arc::clone(&self.jobs);
        let diagnostics = self.diagnostics.clone();
        thread::spawn(move || {
            hold(
                &order,
                &setting,
                &job,
                &jobs,
                &stop,
                &messages,
                diagnostics.as_ref(),
            );
        });
    }

    /// Runs readiness on a remote, in the connection's job.
    pub fn survey(&mut self, order: Surveying) {
        let Some((job, _)) = self.live(order.connection) else {
            return;
        };
        let (setting, messages) = (Arc::clone(&self.setting), self.messages.clone());
        let sealers = Arc::clone(&self.sealers);
        thread::spawn(move || surveyed(&order, &setting, &job, &messages, &sealers));
    }

    /// Has the connection's last survey seal Hedwig's private folder, where
    /// its shell waits for the word; its shell then ends.
    pub fn seal(&mut self, connection: ConnectionId) {
        let sealer = self
            .sealers
            .lock()
            .ok()
            .and_then(|mut sealers| sealers.remove(&connection));
        if let Some(mut sealer) = sealer {
            let _ = sealer.write_all(survey::SEALING);
        }
    }

    /// Has the remote's own tool use a capability once, in the connection's
    /// job.
    pub fn exercise(&mut self, order: Exercising) {
        let Some((job, _)) = self.live(order.connection) else {
            return;
        };
        let (setting, messages) = (Arc::clone(&self.setting), self.messages.clone());
        thread::spawn(move || exercised(&order, &setting, &job, &messages));
    }

    /// Starts a carrier in the connection's job, where its channel is live;
    /// it ends with the channel.
    pub fn haul(&mut self, order: Hauling) {
        if !self.live.contains_key(&order.connection) {
            return;
        }
        let Some((job, _)) = self.live(order.connection) else {
            return;
        };
        let (setting, messages) = (Arc::clone(&self.setting), self.messages.clone());
        let carriers = Arc::clone(&self.carriers);
        thread::spawn(move || carrier(&order, &setting, &job, &carriers, &messages));
    }

    /// Starts a carrier that listens on the remote in the connection's job,
    /// where its channel is live; `placed` is given the port the remote's
    /// server listens at, or OpenSSH's account of why it would not. A carrier
    /// whose forward was refused is ended. Either way it is known by the
    /// endpoint it forwards to, as [`Channels::unhaul`] ends it.
    pub fn place(
        &mut self,
        order: Placing,
        placed: impl FnOnce(Result<Port, String>) + Send + 'static,
    ) {
        let job = self
            .live
            .contains_key(&order.connection)
            .then(|| self.live(order.connection))
            .flatten();
        let Some((job, _)) = job else {
            placed(Err("the remote's channel is down".to_owned()));
            return;
        };
        let setting = Arc::clone(&self.setting);
        let carriers = Arc::clone(&self.carriers);
        thread::spawn(move || placer(&order, &setting, &job, &carriers, placed));
    }

    /// Ends the carrier of `connection`'s channel that listens at `listen`,
    /// and nothing else in its job.
    pub fn unhaul(&mut self, connection: ConnectionId, listen: Port) {
        let held = self
            .carriers
            .lock()
            .ok()
            .and_then(|mut carriers| carriers.remove(&(connection, listen)));
        if let Some(held) = held {
            let _ = held.end(1);
        }
    }

    /// Ends a channel: every process in its job, and with them its forwards.
    pub fn end(&mut self, connection: ConnectionId) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.remove(&connection);
        }
        if let Ok(mut sealers) = self.sealers.lock() {
            sealers.remove(&connection);
        }
        if let Some(live) = self.live.remove(&connection) {
            // The signal first: a client started after the job was emptied
            // is ended by the thread that started it.
            let _ = live.stop.raise();
            let _ = live.job.end();
        }
    }
}

/// Waits at one forward's end. Each connection is handed to the deciding
/// thread with what was read of the process that made it.
fn answer(
    connection: ConnectionId,
    capability: &Name,
    endpoint: &Endpoint,
    stop: &Signal,
    jobs: &Jobs,
    messages: &Sender<Message>,
) {
    while let Ok(Some(stream)) = endpoint.accept(stop) {
        let knocked = Message::Knocked {
            peer: knocker(&stream, jobs),
            stream,
            connection,
            capability: capability.clone(),
        };
        if messages.send(knocked).is_err() {
            return;
        }
    }
}

/// The route's client as found on the search path, and as recorded; or the
/// channel's ending when there is none to start.
fn found(client: &Client, setting: &Setting) -> Result<(PathBuf, Location), ChannelEnd> {
    let program = match program_on(client.program.as_str(), &setting.search) {
        Ok(program) => program,
        Err(SearchError::Absent | SearchError::NoSearchPath) => {
            return Err(ChannelEnd::ClientAbsent);
        }
        Err(SearchError::Other(error)) => return Err(unstarted_end(&error.to_string())),
    };
    match Location::try_from(program.to_string_lossy().as_ref()) {
        Ok(recorded) => Ok((program, recorded)),
        Err(error) => Err(unstarted_end(&error.to_string())),
    }
}

fn unstarted_end(account: &str) -> ChannelEnd {
    let account = words(account).or_else(|| words("the system gave no account"));
    account.map_or(ChannelEnd::ClientAbsent, ChannelEnd::Unstarted)
}

/// A number drawn for one survey, which begins every line of its report.
fn nonce() -> std::io::Result<String> {
    let mut drawn = [0u8; 16];
    hedwig_win::random::fill(&mut drawn)?;
    Ok(format!("{:032x}", u128::from_le_bytes(drawn)))
}

/// At most [`FRAME`] bytes of what a process printed, read until it closes
/// its output; what is past the bound is read and dropped.
fn bounded(output: PipeReader) -> String {
    let mut kept = Vec::new();
    let _ = output
        .take(u64::try_from(FRAME).unwrap_or(u64::MAX))
        .read_to_end(&mut kept);
    String::from_utf8_lossy(&kept).into_owned()
}

/// The forwards the person's own configuration declares for the host, as the
/// route's client states them: `-G` reads the configuration and connects to
/// nothing.
fn stated(program: &Path, order: &Surveying, setting: &Setting, job: &Job) -> Vec<Words> {
    let options = vec!["-G".to_owned(), "-o".to_owned(), "Tag=hedwig".to_owned()];
    let arguments: Vec<OsString> = order
        .client
        .arguments(&order.address, options)
        .into_iter()
        .map(OsString::from)
        .collect();
    let Ok((client, output, _)) = consulted(program, &arguments, &setting.environment, job) else {
        return Vec::new();
    };
    let stated = bounded(output);
    let _ = client.wait();
    survey::theirs(&stated)
}

/// Runs the route's client with `script` for the remote's shell, and gives
/// its exit status, what it printed, and whether it stopped for want of the
/// person's word on the host key with the last thing it said. Where `bound`
/// is given, the shell has that long from the report's first line to finish.
/// Where `waits` is given, the shell waits after its report for a word on its
/// input, which is kept there, and this returns once the report has ended,
/// with the status 0.
#[allow(clippy::too_many_arguments, reason = "each is one thing the run needs")]
fn run_script(
    connection: ConnectionId,
    program: &Path,
    arguments: &[OsString],
    script: String,
    bound: Option<Duration>,
    waits: Option<&Sealers>,
    setting: &Setting,
    job: &Arc<Job>,
    messages: &Sender<Message>,
) -> std::io::Result<(i32, String, bool, Option<Words>)> {
    let (client, mut input, output, errors) = fed(program, arguments, &setting.environment, job)?;
    let keep = waits.map(Arc::clone);
    thread::spawn(move || {
        if input.write_all(script.as_bytes()).is_ok()
            && let Some(sealers) = keep
            && let Ok(mut sealers) = sealers.lock()
        {
            sealers.insert(connection, input);
        }
    });
    let reading = {
        let messages = messages.clone();
        let names = BTreeMap::new();
        thread::spawn(move || listen(connection, errors, &names, &messages, None))
    };
    let (begun, begins) = mpsc::channel::<()>();
    let (ended, report) = mpsc::channel::<String>();
    let printed = thread::spawn(move || {
        let mut reader = BufReader::new(output);
        let mut kept = String::new();
        let mut line = String::new();
        while matches!(reader.read_line(&mut line), Ok(read) if read > 0) {
            if kept.len() + line.len() <= FRAME {
                kept.push_str(&line);
            }
            if line.contains(" begin ") {
                let _ = begun.send(());
            }
            // The report has ended; a shell that waits for a word goes on.
            if line.trim_end().ends_with(" end") {
                let _ = begun.send(());
                let _ = ended.send(kept.clone());
            }
            line.clear();
        }
        kept
    });
    let watching = Arc::clone(job);
    thread::spawn(move || {
        // A shell that has begun and not finished within the bound is ended
        // with everything else in the job; the survey then reads as
        // unfinished.
        if let Some(bound) = bound
            && begins.recv().is_ok()
            && matches!(
                begins.recv_timeout(bound),
                Err(mpsc::RecvTimeoutError::Timeout)
            )
        {
            let _ = watching.end();
        }
    });
    if waits.is_some() {
        // The shell waits for its word; what it printed up to the report's
        // end is the report, and the client is left to end with it.
        if let Ok(kept) = report.recv() {
            thread::spawn(move || {
                let _ = client.wait();
                let _ = printed.join();
                let _ = reading.join();
            });
            return Ok((0, kept, false, None));
        }
    }
    let status = client.wait().map_or(-1, u32::cast_signed);
    let printed = printed.join().unwrap_or_default();
    let (unverified, last, _) = reading.join().unwrap_or((false, None, VecDeque::new()));
    Ok((status, printed, unverified, last))
}

/// Surveys the remote and tells the deciding thread what it found. A client
/// that failed before the remote's shell ran ends the connection as a
/// channel's client would.
fn surveyed(
    order: &Surveying,
    setting: &Setting,
    job: &Arc<Job>,
    messages: &Sender<Message>,
    sealers: &Sealers,
) {
    let connection = order.connection;
    let (program, _) = match found(&order.client, setting) {
        Ok(found) => found,
        Err(end) => return say(messages, connection, Told::Unstarted { end }),
    };
    let theirs = stated(&program, order, setting, job);
    let nonce = match nonce() {
        Ok(nonce) => nonce,
        Err(error) => return unstarted(messages, connection, &error.to_string()),
    };
    let mut plan = order.plan.clone();
    let mut issued = [0u8; 16];
    if order.dialect == Dialect::PowerShell {
        if let Err(error) = hedwig_win::random::fill(&mut issued) {
            return unstarted(messages, connection, &error.to_string());
        }
        plan.issued = Some(issued);
    }
    let script = match order.dialect {
        Dialect::Posix => survey::posix(&plan, &nonce),
        Dialect::PowerShell => survey::powershell(&plan, &nonce),
    };
    let mut arguments = order.client.arguments(
        &order.address,
        survey::options(order.asking, order.keepalive),
    );
    arguments.extend(survey::command(order.dialect));
    let arguments: Vec<OsString> = arguments.into_iter().map(OsString::from).collect();
    let bound = Some(READINESS);
    let waits = (order.dialect == Dialect::Posix && survey::seals(&plan)).then_some(sealers);
    let ran = run_script(
        connection, &program, &arguments, script, bound, waits, setting, job, messages,
    );
    let (status, printed, unverified, last) = match ran {
        Ok(ran) => ran,
        Err(error) => return unstarted(messages, connection, &error.to_string()),
    };
    let told = match survey::read(&printed, &nonce) {
        Err(Unread::NotBegun) if status == FAILED => Told::Ended {
            status,
            unverified,
            last,
        },
        report => Told::Surveyed {
            report: report
                .map(|report| Report {
                    issued: plan.issued,
                    ..report
                })
                .map_err(|unread| (unread, last)),
            theirs,
        },
    };
    say(messages, connection, told);
}

/// The status OpenSSH's client ends with when it failed itself, rather than
/// passing on the remote command's.
const FAILED: i32 = 255;

/// Has the remote's tool use the capability, and tells the deciding thread
/// what it said.
fn exercised(order: &Exercising, setting: &Setting, job: &Arc<Job>, messages: &Sender<Message>) {
    let connection = order.connection;
    let absent = |tool: &str| {
        Name::try_from(tool).map_or(Finding::Unsurveyed(unaccounted()), Finding::ToolAbsent)
    };
    let Ok((program, _)) = found(&order.client, setting) else {
        let ran = Err(absent(order.client.program.as_str()));
        return say(messages, connection, Told::Exercised { ran });
    };
    let Ok(nonce) = nonce() else {
        let ran = Err(Finding::Unsurveyed(unaccounted()));
        return say(messages, connection, Told::Exercised { ran });
    };
    let script = survey::exercise(order.dialect, order.query, &order.binding, &nonce);
    let mut arguments = order.client.arguments(
        &order.address,
        survey::options(order.asking, order.keepalive),
    );
    arguments.extend(survey::command(order.dialect));
    let arguments: Vec<OsString> = arguments.into_iter().map(OsString::from).collect();
    // The request it makes can wait for the person, so nothing bounds it.
    let ran = match run_script(
        connection, &program, &arguments, script, None, None, setting, job, messages,
    ) {
        Ok((_, printed, _, last)) => match survey::exercised(&printed, &nonce) {
            Ok(ran) => ran,
            Err(_) => Err(Finding::Unsurveyed(last.unwrap_or_else(unaccounted))),
        },
        Err(error) => Err(Finding::Unsurveyed(
            words(&error.to_string()).unwrap_or_else(unaccounted),
        )),
    };
    say(messages, connection, Told::Exercised { ran });
}

/// Words for a failure the system gave no account of.
fn unaccounted() -> Words {
    words("the remote gave no account")
        .unwrap_or_else(|| unreachable!("fixed words are valid words"))
}

/// Holds one carrier until it ends. Its prompts are its connection's, and
/// what it says is read as a channel's client's is.
fn carrier(
    order: &Hauling,
    setting: &Setting,
    job: &Arc<Job>,
    carriers: &Carriers,
    messages: &Sender<Message>,
) {
    let Ok((program, _)) = found(&order.client, setting) else {
        return;
    };
    let arguments: Vec<OsString> = order
        .client
        .arguments(
            &order.address,
            haul(&order.target, order.listen, order.asking, order.keepalive),
        )
        .into_iter()
        .map(OsString::from)
        .collect();
    let Ok((client, errors)) = held(&program, &arguments, &setting.environment, job) else {
        return;
    };
    let client = Arc::new(client);
    let key = (order.connection, order.listen);
    if let Ok(mut carriers) = carriers.lock() {
        carriers.insert(key, Arc::clone(&client));
    }
    let reading = {
        let messages = messages.clone();
        let connection = order.connection;
        thread::spawn(move || listen(connection, errors, &BTreeMap::new(), &messages, None))
    };
    let _ = client.wait();
    if let Ok(mut carriers) = carriers.lock() {
        carriers.remove(&key);
    }
    let _ = reading.join();
}

/// Holds one carrier that listens on the remote until it ends, giving
/// `placed` what its server answered for the forward.
fn placer(
    order: &Placing,
    setting: &Setting,
    job: &Arc<Job>,
    carriers: &Carriers,
    placed: impl FnOnce(Result<Port, String>),
) {
    let refused = |port: u16| format!("the remote's ssh server would not listen at port {port}");
    let Ok((program, _)) = found(&order.client, setting) else {
        return placed(Err(
            "no folder on the search path holds the route's client".to_owned()
        ));
    };
    let arguments: Vec<OsString> = order
        .client
        .arguments(
            &order.address,
            place(order.port, order.listen, order.asking, order.keepalive),
        )
        .into_iter()
        .map(OsString::from)
        .collect();
    let Ok((client, errors)) = held(&program, &arguments, &setting.environment, job) else {
        return placed(Err("the route's client could not be started".to_owned()));
    };
    let client = Arc::new(client);
    let key = (order.connection, order.listen);
    if let Ok(mut carriers) = carriers.lock() {
        carriers.insert(key, Arc::clone(&client));
    }
    let endpoint = order.listen.number();
    let mut placed = Some(placed);
    let mut reader = BufReader::new(errors);
    let mut bytes = Vec::new();
    loop {
        bytes.clear();
        match reader.read_until(b'\n', &mut bytes) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let text = String::from_utf8_lossy(&bytes);
        let answered = match heard(text.trim_end_matches(['\r', '\n'])) {
            Heard::Forward {
                endpoint: at,
                bound: true,
            } if at == endpoint && order.port != 0 => {
                Port::try_from(order.port).map_err(|_| refused(order.port))
            }
            Heard::Allocated { port, endpoint: at } if at == endpoint => {
                Port::try_from(port).map_err(|_| refused(port))
            }
            Heard::Forward {
                endpoint: at,
                bound: false,
            } if at == endpoint => Err(refused(order.port)),
            _ => continue,
        };
        let failed = answered.is_err();
        if let Some(placed) = placed.take() {
            placed(answered);
        }
        if failed {
            let _ = client.end(1);
        }
    }
    if let Some(placed) = placed.take() {
        placed(Err(
            "the carrier ended before the remote's server answered".to_owned()
        ));
    }
    let _ = client.wait();
    if let Ok(mut carriers) = carriers.lock() {
        carriers.remove(&key);
    }
}

/// Holds one channel from its start to its client's end.
fn hold(
    order: &Order,
    setting: &Setting,
    job: &Arc<Job>,
    jobs: &Jobs,
    stop: &Arc<Signal>,
    messages: &Sender<Message>,
    diagnostics: Option<&Diagnostics>,
) {
    let connection = order.connection;
    let (program, recorded) = match found(&order.client, setting) {
        Ok(found) => found,
        Err(end) => return say(messages, connection, Told::Unstarted { end }),
    };
    let release = release(&program).ok().flatten().map(|numbers| {
        let [major, minor, build, revision] = numbers;
        Release {
            major,
            minor,
            build,
            revision,
        }
    });
    let mut forwards = Vec::new();
    let mut endpoints = BTreeMap::new();
    for serving in &order.serving {
        let bound = Endpoint::bind().and_then(|endpoint| {
            let port = Port::try_from(endpoint.port()).map_err(std::io::Error::other)?;
            Ok((endpoint, port))
        });
        match bound {
            Ok((endpoint, port)) => {
                forwards.push((serving.clone(), port));
                endpoints.insert(port.number(), (serving.capability.clone(), endpoint));
            }
            Err(error) => return unstarted(messages, connection, &error.to_string()),
        }
    }
    let arguments: Vec<OsString> = order
        .client
        .arguments(
            &order.address,
            options(&forwards, order.asking, order.keepalive),
        )
        .into_iter()
        .map(OsString::from)
        .collect();
    let (client, errors) = match held(&program, &arguments, &setting.environment, job) {
        Ok(started) => started,
        Err(error) => return unstarted(messages, connection, &error.to_string()),
    };
    if stop.raised() {
        let _ = job.end();
    }
    let program = recorded;
    let asking = order.asking;
    say(
        messages,
        connection,
        Told::Ran {
            program,
            release,
            asking,
        },
    );
    let names: BTreeMap<u16, Name> = endpoints
        .iter()
        .map(|(port, (capability, _))| (*port, capability.clone()))
        .collect();
    for (capability, endpoint) in endpoints.into_values() {
        let (stop, jobs, messages) = (Arc::clone(stop), Arc::clone(jobs), messages.clone());
        thread::spawn(move || answer(connection, &capability, &endpoint, &stop, &jobs, &messages));
    }
    let reading = {
        let (messages, diagnostics) = (messages.clone(), diagnostics.cloned());
        thread::spawn(move || listen(connection, errors, &names, &messages, diagnostics.as_ref()))
    };
    let status = client.wait().map_or(-1, u32::cast_signed);
    // Asked to end, the channel's words are not a fault's account.
    let asked = stop.raised();
    // Whatever the client started and left behind ends with it, which also
    // closes the pipe its words are read from.
    let _ = job.end();
    let _ = stop.raise();
    let (unverified, last, heard) = reading.join().unwrap_or((false, None, VecDeque::new()));
    if !asked && let Some(diagnostics) = diagnostics {
        let from = format!("channel {} ended with status {status}", connection.0.0);
        for said in &heard {
            diagnostics.fault(now(), &from, said);
        }
    }
    let ended = Told::Ended {
        status,
        unverified,
        last,
    };
    say(messages, connection, ended);
}

/// Reads what the client says until it and everything it started have ended.
/// Returns whether it stopped for want of the person's word on the host's
/// key, and the last thing it said that was its own to say.
fn listen(
    connection: ConnectionId,
    errors: PipeReader,
    names: &BTreeMap<u16, Name>,
    messages: &Sender<Message>,
    diagnostics: Option<&Diagnostics>,
) -> (bool, Option<Words>, VecDeque<String>) {
    let from = format!("channel {}", connection.0.0);
    let mut account: VecDeque<String> = VecDeque::new();
    let (mut changed, mut presents, mut unverified, mut last) = (false, false, false, None);
    let mut reader = BufReader::new(errors);
    let mut bytes = Vec::new();
    loop {
        bytes.clear();
        match reader.read_until(b'\n', &mut bytes) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let text = String::from_utf8_lossy(&bytes);
        let line = text.trim_end_matches(['\r', '\n']);
        if let Some(diagnostics) = diagnostics {
            diagnostics.detail(now(), &from, line);
        }
        if account.len() == HEARD {
            account.pop_front();
        }
        account.push_back(line.to_owned());
        let fingerprint = std::mem::take(&mut presents) && changed;
        match heard(line) {
            Heard::Forward { endpoint, bound } => {
                if let Some(capability) = names.get(&endpoint).cloned() {
                    say(messages, connection, Told::Forwarded { capability, bound });
                }
                continue;
            }
            // Only a carrier that listens on the remote asks for a port of
            // its server's choosing, and its placer reads what it says.
            Heard::Allocated { .. } => continue,
            Heard::Changed => changed = true,
            Heard::Presents => presents = true,
            Heard::Unverified => unverified = !changed,
            Heard::Other if fingerprint => {
                if let Ok(fingerprint) = Mark::try_from(line.trim_end_matches('.')) {
                    say(messages, connection, Told::HostKeyChanged { fingerprint });
                }
            }
            Heard::Other => {}
        }
        // What the client was made to say is not its own account of itself.
        if !line.contains(ANSWERS)
            && let Some(said) = words(line)
        {
            last = Some(said);
        }
    }
    (unverified, last, account)
}

/// The most of what a channel's client said that is kept for a fault's
/// account. Invariant: the end of a client's account is what explains it.
const HEARD: usize = 200;

/// The wall clock, as the trail keeps it.
fn now() -> hedwig_model::trail::Timestamp {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    hedwig_model::trail::Timestamp(u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}
