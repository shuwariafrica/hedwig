//! Which agent pipe a running gpg-agent of the person's is set to serve,
//! known without connecting to the pipe.
//!
//! gpg-agent's Win32-OpenSSH thread makes one instance of its pipe and then
//! waits on it; a client that connects in between, even one already gone,
//! makes the wait report an error the thread takes for fatal, and the pipe is
//! gone until gpg-agent is started again (2.5.24,
//! `agent/gpg-agent.c:2804-2809`). No client can tell that moment from an
//! instance standing free, so a pipe gpg-agent serves is never opened: the
//! request goes to the same agent's own SSH socket, and what the agent serves
//! is read from the options it read when it started.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use hedwig_model::capability::{Home, Installation};
use hedwig_model::holder::Whose;
use hedwig_model::text::{AgentPipe, Folder};
use hedwig_model::trail::Failure;
use hedwig_win::pipe::{canonical, name_in, same_name};
use hedwig_win::process::{Process, UNSEEN, instances_of};
use hedwig_win::services::is_running;

use crate::relay::{gpgconf, home_arguments, listed, ran};

/// The option `enable-win32-openssh-support`, which takes the pipe's full
/// path, or nothing for the well-known one.
const OPTION: &str = "enable-win32-openssh-support";

/// Windows' own agent service, which holds the well-known pipe while it runs
/// and lets no other program make an instance of it.
const WINDOWS_AGENT: &str = "ssh-agent";

/// What stands where what an agent serves could not be read: the pipe may be
/// that agent's, so it is not opened.
const UNREAD: Failure = Failure::Undetermined;

/// gpg-agent's long options that are always given a value (`agent/gpg-agent.c`,
/// its option table: each name's arity is the same from 2.4 to master, and the
/// lists are their union), so the next argument is not an option. `homedir` and
/// `options` are read apart.
const VALUED: &[&str] = &[
    "browser-socket",
    "change-std-env-name",
    "check-passphrase-pattern",
    "check-sym-passphrase-pattern",
    "debug",
    "debug-level",
    "debug-wait",
    "default-cache-ttl",
    "default-cache-ttl-ssh",
    "display",
    "extra-socket",
    "faked-system-time",
    "inactivity-timeout",
    "lc-ctype",
    "lc-messages",
    "listen-backlog",
    "log-file",
    "max-cache-ttl",
    "max-cache-ttl-ssh",
    "max-passphrase-days",
    "min-passphrase-len",
    "min-passphrase-nonalpha",
    "pinentry-invisible-char",
    "pinentry-program",
    "pinentry-timeout",
    "pinentry-touch-file",
    "s2k-calibration",
    "s2k-count",
    "scdaemon-program",
    "ssh-fingerprint-digest",
    "sys-trustlist-name",
    "tpm2daemon-program",
    "ttyname",
    "ttytype",
    "xauthority",
];

/// Those that may be given one: an argument not beginning with `-` is it.
const MAYBE_VALUED: &[&str] = &["auto-expand-secmem", "write-env-file"];

/// Whether an agent is set to serve a pipe, or the pipe only counts because
/// what it read is in doubt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Certainty {
    Set,
    Perhaps,
}

/// A running gpg-agent set to serve a pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Serving {
    /// Its SSH socket file, as its own `gpgconf` names it for its home.
    pub(crate) socket: PathBuf,
    pub(crate) home: Home,
    pub(crate) certainty: Certainty,
}

/// A running gpg-agent of the person's as it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Agent {
    /// The pipes it may serve: more than one only where a meta-command in its
    /// files, or a word that may have ended the command line, leaves which
    /// line applied unread.
    pipes: Vec<String>,
    /// Those of them it is set to serve for certain.
    set: Vec<String>,
    started: u64,
    serving: Serving,
}

impl Agent {
    fn serves(&self, name: &AgentPipe) -> bool {
        let wanted = canonical(name.as_str());
        self.pipes.iter().any(|pipe| same_name(pipe, &wanted))
    }

    /// Where it is reached for `name`, a pipe it [`serves`](Self::serves).
    fn for_pipe(self, name: &AgentPipe) -> Serving {
        let wanted = canonical(name.as_str());
        let certainty = if self.set.iter().any(|pipe| same_name(pipe, &wanted)) {
            Certainty::Set
        } else {
            Certainty::Perhaps
        };
        Serving {
            certainty,
            ..self.serving
        }
    }
}

/// What a process was read as, nothing where it serves no pipe of the
/// person's.
type Read = Option<Agent>;

/// What running agents were read as, by number and start.
type Known = Mutex<BTreeMap<(u32, u64), Read>>;

/// What each running agent was read as: an agent reads its options only when
/// it starts.
static READ: LazyLock<Known> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The running gpg-agent of the person's set to serve `name`, if any.
///
/// Read from the system's list of processes and each agent's own options, so
/// nothing connects to the pipe. Where Windows' own agent service runs the
/// well-known pipe is its, however a `gpg-agent.conf` is set.
///
/// # Errors
///
/// [`Failure::Undetermined`] where the list, or the options of a running
/// agent of the person's, could not be read and no agent read serves `name`.
pub(crate) fn serving(name: &AgentPipe) -> Result<Option<Serving>, Failure> {
    let running = instances_of("gpg-agent.exe");
    if let Ok(numbers) = &running {
        forget_ended(&READ, numbers);
    }
    among(name, running, || is_running(WINDOWS_AGENT), read_process)
}

/// Forgets what was read of every process no longer among `running`.
fn forget_ended(known: &Known, running: &[u32]) {
    locked(known).retain(|(process, _), _| running.contains(process));
}

/// [`serving`] over a list of processes, Windows' own agent and each
/// process's reading, as given.
fn among(
    name: &AgentPipe,
    running: io::Result<Vec<u32>>,
    windows_agent: impl FnOnce() -> io::Result<bool>,
    read: impl Fn(u32) -> Result<Read, Failure>,
) -> Result<Option<Serving>, Failure> {
    let running = running.map_err(|_| UNREAD)?;
    if running.is_empty() || windows_agent_holds(name, windows_agent) {
        return Ok(None);
    }
    let mut unread = false;
    let mut earliest: Option<Agent> = None;
    for number in running {
        match read(number) {
            Ok(Some(agent)) if agent.serves(name) => {
                earliest = Some(match earliest {
                    Some(other) if other.started <= agent.started => other,
                    _ => agent,
                });
            }
            Ok(_) => {}
            Err(_) => unread = true,
        }
    }
    match earliest {
        Some(agent) => Ok(Some(agent.for_pipe(name))),
        None if unread => Err(UNREAD),
        None => Ok(None),
    }
}

/// Whether `name` is the well-known pipe and Windows' own agent service is
/// running, by `runs`: a service that cannot be asked counts as not running,
/// since the holder the name then has is unknown, not Windows'.
fn windows_agent_holds(name: &AgentPipe, runs: impl FnOnce() -> io::Result<bool>) -> bool {
    same_name(&canonical(name.as_str()), AgentPipe::well_known().as_str())
        && runs().unwrap_or(false)
}

/// What the process numbered `number` was read as.
fn read_process(number: u32) -> Result<Read, Failure> {
    let process = match Process::open(number) {
        Ok(process) => process,
        Err(error) => return unopened(&error),
    };
    let started = process.started().map_err(|_| UNREAD)?;
    read_once(&READ, (number, started), || {
        unless_ended(read_agent(&process, number, started), || {
            process.has_ended()
        })
    })
}

/// What a process Windows would not open counts as: denied, it is another
/// account's, and gone, it has ended, and either way it serves nothing of the
/// person's. Anything else says nothing about it.
fn unopened(error: &io::Error) -> Result<Read, Failure> {
    if matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput
    ) {
        Ok(None)
    } else {
        Err(UNREAD)
    }
}

/// `read`, or nothing where it failed and the process has ended by now: a
/// process gone serves no pipe. One still running may be the pipe's server.
fn unless_ended(
    read: Result<Read, Failure>,
    ended: impl FnOnce() -> bool,
) -> Result<Read, Failure> {
    read.or_else(|failure| if ended() { Ok(None) } else { Err(failure) })
}

/// What the process `key` names was read as, by `reading` where it has not
/// been read: a read that failed is not remembered, so the next request
/// reads again and the process is never taken to serve nothing because of
/// it. Nothing is held while `reading` runs a program.
fn read_once(
    known: &Known,
    key: (u32, u64),
    reading: impl FnOnce() -> Result<Read, Failure>,
) -> Result<Read, Failure> {
    if let Some(found) = locked(known).get(&key) {
        return Ok(found.clone());
    }
    let found = reading()?;
    locked(known).insert(key, found.clone());
    Ok(found)
}

/// Whether a process is the person's to keep from being stopped. Another
/// account's token is closed to this one and reads as [`Whose::Unread`] (see
/// `hedwig_win::services`), so what cannot be read of it here says nothing of
/// the person's own agent; [`Whose::Confined`] is the person's account.
fn is_the_persons(whose: &Whose) -> bool {
    matches!(whose, Whose::Person { .. } | Whose::Confined)
}

/// A process's options as gpg-agent reads them. It serves no pipe where it is
/// not the person's, or where it keeps its socket in a POSIX emulation's form,
/// whose build has no Win32-OpenSSH thread.
fn read_agent(process: &Process, number: u32, started: u64) -> Result<Read, Failure> {
    let holder = crate::holder::of(number).ok_or(UNREAD)?;
    if !is_the_persons(&holder.whose) {
        return Ok(None);
    }
    let program = process.program().map_err(|_| UNREAD)?;
    let arguments = process.arguments().map_err(|_| UNREAD)?;
    let invocation = invoked(&arguments)?;
    let installation = installation_of(&program)
        .and_then(|folder| Folder::try_from(folder).ok())
        .map(Installation::At)
        .ok_or(UNREAD)?;
    let home = match &invocation.homedir {
        Some(folder) => Home::At(Folder::try_from(folder.as_str()).map_err(|_| UNREAD)?),
        None => Home::Default,
    };
    let gpgconf = gpgconf(&installation).map_err(|_| UNREAD)?;
    let mut asked: Vec<OsString> = home_arguments(&home);
    asked.push("--list-dirs".into());
    let (printed, ended_well) = ran(&gpgconf, &asked, UNSEEN).map_err(|_| UNREAD)?;
    if !ended_well {
        return Err(UNREAD);
    }
    read_listing(&printed, &invocation, home, started, configuration)
}

/// What an agent started with `invocation` was read as, from what `gpgconf
/// --list-dirs` printed for its home, its files read by `read_file`. A
/// `--options` file given relatively is read from a directory only the agent
/// knows.
fn read_listing(
    printed: &[u8],
    invocation: &Invocation,
    home: Home,
    started: u64,
    read_file: impl Fn(&Path) -> Result<Option<String>, Failure>,
) -> Result<Read, Failure> {
    let directory = |name: &str| {
        listed(printed, name)
            .and_then(|dir| String::from_utf8(dir).ok())
            .ok_or(UNREAD)
    };
    let socket = directory("agent-ssh-socket")?;
    if socket.starts_with('/') {
        return Ok(None);
    }
    let system = read_file(&Path::new(&directory("sysconfdir")?).join(FILE))?;
    let own = if invocation.no_options {
        None
    } else {
        let file = match &invocation.options {
            Some(file) if Path::new(file).is_absolute() => PathBuf::from(file),
            Some(_) => return Err(UNREAD),
            None => Path::new(&directory("homedir")?).join(FILE),
        };
        read_file(&file)?
    };
    let mut pipes = served(system.as_deref(), own.as_deref(), invocation.pipe.as_ref())?;
    let set = if conditional(system.as_deref(), own.as_deref()) {
        Vec::new()
    } else {
        pipes.clone()
    };
    let perhaps: Vec<String> = invocation
        .perhaps
        .iter()
        .filter_map(|setting| setting.pipe().transpose())
        .collect::<Result<_, _>>()?;
    pipes.extend(perhaps);
    Ok((!pipes.is_empty()).then(|| Agent {
        pipes,
        set,
        started,
        serving: Serving {
            socket: PathBuf::from(socket),
            home,
            certainty: Certainty::Perhaps,
        },
    }))
}

const FILE: &str = "gpg-agent.conf";

/// The file an agent image sits in, one level above `bin`.
fn installation_of(program: &Path) -> Option<&str> {
    program.parent()?.parent()?.to_str()
}

/// A configuration file's text; a file that is not there names nothing.
fn configuration(file: &Path) -> Result<Option<String>, Failure> {
    match std::fs::read(file) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(UNREAD),
    }
}

/// What gpg-agent's command line says, each only as gpg-agent itself takes
/// it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Invocation {
    pub(crate) homedir: Option<String>,
    pub(crate) options: Option<String>,
    pub(crate) no_options: bool,
    pub(crate) pipe: Option<Setting>,
    /// Each setting of the option past an argument that ended gpg-agent's
    /// parsing or was the value of an option not known here, which cannot be
    /// told: each counts as served beside what the rest says.
    pub(crate) perhaps: Vec<Setting>,
}

/// How [`OPTION`] was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Setting {
    /// With no value: the well-known pipe.
    WellKnown,
    /// With the value it was given, the pipe's full path where it is one.
    Named(String),
}

impl Setting {
    /// A line of a file gives no value by leaving it empty, and a quoted
    /// empty one is an empty value: such a value makes no pipe.
    fn in_a_file(value: &str) -> Setting {
        let value = value.trim();
        if value.is_empty() {
            return Setting::WellKnown;
        }
        let unquoted = value
            .strip_prefix('"')
            .map_or(value, |quoted| quoted.strip_suffix('"').unwrap_or(quoted));
        Setting::Named(unquoted.to_owned())
    }

    /// The name of the pipe this names, if it names one; what Windows would
    /// not read stays unknown, as a file that cannot be read does.
    fn pipe(&self) -> Result<Option<String>, Failure> {
        match self {
            Setting::WellKnown => Ok(Some(AgentPipe::well_known().as_str().to_owned())),
            Setting::Named(path) => name_in(path).map_err(|_| UNREAD),
        }
    }
}

/// `arguments` as gpg-agent's option parser reads them, the program's name
/// first: an option's value after `=` or as the next argument, and an
/// optional value only where the next argument is not itself an option and
/// an empty `=` gives none. A running agent's arguments passed that parser,
/// which refuses an abbreviation two options share, so a prefix of one of
/// these names is that option.
///
/// Parsing ends at `--`, and at the first argument that is no option, unless
/// that argument was the value of an option [`VALUED`] does not know, which
/// cannot be told from here. Past such an argument a setting of [`OPTION`]
/// goes to [`Invocation::perhaps`]; a home or an options file named there
/// leaves what the agent read unknown.
///
/// # Errors
///
/// [`Failure::Undetermined`] where a home or an options file is named past
/// such an argument.
pub(crate) fn invoked(arguments: &[String]) -> Result<Invocation, Failure> {
    let mut invocation = Invocation::default();
    let mut rest = arguments.iter().skip(1).peekable();
    let mut in_doubt = false;
    while let Some(argument) = rest.next() {
        if argument == "--" {
            break;
        }
        if argument == "-" || !argument.starts_with('-') {
            in_doubt = true;
            continue;
        }
        let Some(long) = argument.strip_prefix("--") else {
            continue;
        };
        let (name, attached) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (long, None),
        };
        let named = |full: &str| !name.is_empty() && full.starts_with(name);
        let mut value = || attached.clone().or_else(|| rest.next().cloned());
        if named(OPTION) {
            let given = match attached {
                Some(value) => Some(value).filter(|value| !value.is_empty()),
                None => rest.next_if(|next| !next.starts_with('-')).cloned(),
            };
            let setting = given.map_or(Setting::WellKnown, Setting::Named);
            if in_doubt {
                invocation.perhaps.push(setting);
            } else {
                invocation.pipe = Some(setting);
            }
        } else if in_doubt {
            if named("homedir") || named("options") || named("no-options") {
                return Err(UNREAD);
            }
        } else if named("homedir") {
            invocation.homedir = value();
        } else if named("options") {
            let file = value();
            if invocation.options.is_none() {
                invocation.options = file;
            }
        } else if named("no-options") {
            invocation.no_options = true;
        } else if VALUED.iter().copied().any(named) {
            value();
        } else if attached.is_none() && MAYBE_VALUED.iter().copied().any(named) {
            rest.next_if(|next| !next.starts_with('-'));
        }
    }
    Ok(invocation)
}

/// What one configuration file says of [`OPTION`], whose keyword a file may
/// not abbreviate.
#[derive(Debug, Default, PartialEq, Eq)]
struct Lines {
    /// Every setting of it, in the file's order.
    every: Vec<Setting>,
    /// Whether the file holds a meta-command (`[if]`, `[force]`, `[ignore]`
    /// and the like), after which the lines alone do not say which applied.
    conditional: bool,
}

fn lines_of(text: &str) -> Lines {
    let mut lines = Lines::default();
    for line in text.strip_prefix('\u{feff}').unwrap_or(text).lines() {
        let line = line.trim_start();
        if line.starts_with('[') {
            lines.conditional = true;
        } else if !line.starts_with('#') {
            let (keyword, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            if keyword == OPTION {
                lines.every.push(Setting::in_a_file(value));
            }
        }
    }
    lines
}

/// The pipes an agent with these options may serve: the last setting of the
/// option across its system file, its own file or the `--options` file in its
/// place, and its command line, which it reads in that order; or, where a
/// meta-command in either file leaves that unread, every pipe either file or
/// the command line names.
///
/// # Errors
///
/// [`Failure::Undetermined`] where Windows would not read a value as a path.
pub(crate) fn served(
    system: Option<&str>,
    own: Option<&str>,
    given: Option<&Setting>,
) -> Result<Vec<String>, Failure> {
    let system = system.map(lines_of).unwrap_or_default();
    let own = own.map(lines_of).unwrap_or_default();
    let settings: Vec<Setting> = if system.conditional || own.conditional {
        system
            .every
            .iter()
            .chain(&own.every)
            .chain(given)
            .cloned()
            .collect()
    } else {
        given
            .or(own.every.last())
            .or(system.every.last())
            .cloned()
            .into_iter()
            .collect()
    };
    settings
        .iter()
        .filter_map(|setting| setting.pipe().transpose())
        .collect()
}

/// Whether a meta-command in either file leaves which line applied unread.
fn conditional(system: Option<&str>, own: Option<&str>) -> bool {
    [system, own]
        .into_iter()
        .flatten()
        .any(|text| lines_of(text).conditional)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use hedwig_model::holder::{Rights, SignedIn};

    use super::*;

    const WELL_KNOWN: &str = "openssh-ssh-agent";

    fn named(value: &str) -> Setting {
        Setting::Named(value.to_owned())
    }

    fn args(words: &[&str]) -> Vec<String> {
        std::iter::once("gpg-agent.exe")
            .chain(words.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    fn pipes(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// What a command line of these words is read as, it being read at all.
    fn read(words: &[&str]) -> Invocation {
        invoked(&args(words)).unwrap()
    }

    /// What [`served`] finds, every value read.
    fn served_read(
        system: Option<&str>,
        own: Option<&str>,
        given: Option<&Setting>,
    ) -> Vec<String> {
        served(system, own, given).unwrap()
    }

    /// The setting a file's lines leave standing.
    fn set_in(text: &str) -> Option<Setting> {
        lines_of(text).every.last().cloned()
    }

    #[test]
    fn an_options_file_not_there_names_nothing_and_one_that_cannot_be_read_stays_unknown() {
        let folder = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            configuration(&folder.join("hedwig-no-such-file.conf")),
            Ok(None)
        );
        assert_eq!(configuration(folder), Err(Failure::Undetermined));
    }

    #[test]
    fn the_last_line_of_a_file_decides_and_a_comment_or_another_keyword_does_not() {
        assert_eq!(set_in(""), None);
        assert_eq!(
            set_in("# enable-win32-openssh-support \\\\.\\pipe\\a\n"),
            None
        );
        assert_eq!(
            set_in("enable-ssh-support\nenable-putty-support\n"),
            None,
            "the other switches name no pipe"
        );
        assert_eq!(
            set_in("enable-win32-openssh-support\n"),
            Some(Setting::WellKnown)
        );
        assert_eq!(
            set_in("enable-win32-openssh-support \\\\.\\pipe\\a\n"),
            Some(named(r"\\.\pipe\a"))
        );
        assert_eq!(
            set_in(
                "enable-win32-openssh-support \"\\\\.\\pipe\\a\"\r\n  \
                 enable-win32-openssh-support\t\\\\.\\pipe\\b  \n# trailing\n"
            ),
            Some(named(r"\\.\pipe\b")),
            "the last setting, quotes and surrounding space taken off"
        );
        assert_eq!(
            set_in("enable-win32-openssh-support b\"\n"),
            Some(named("b\"")),
            "a quote is taken off only where it opens the value"
        );
        assert_eq!(
            set_in("enable-win32-openssh-support \"a\n"),
            Some(named("a")),
            "and the closing one only with it"
        );
        assert_eq!(
            set_in("enable-win32-openssh-support \"\"\n"),
            Some(named("")),
            "a quoted empty value is a value"
        );
    }

    #[test]
    fn a_byte_order_mark_hides_no_first_line() {
        assert_eq!(
            set_in("\u{feff}enable-win32-openssh-support \\\\.\\pipe\\a\n"),
            Some(named(r"\\.\pipe\a"))
        );
    }

    #[test]
    fn a_keyword_in_a_file_is_never_abbreviated() {
        assert_eq!(set_in("enable-w \\\\.\\pipe\\c\n"), None);
        assert_eq!(set_in("enable-win32-openssh\tx\n"), None);
    }

    #[test]
    fn the_command_line_gives_the_home_the_options_file_and_the_option() {
        assert_eq!(read(&["--daemon"]), Invocation::default());
        let home = read(&["--homedir", r"C:\h", "--daemon"]);
        assert_eq!(home.homedir.as_deref(), Some(r"C:\h"));
        let attached = read(&["--homedir=C:/h", "--options=C:/o.conf", "--no-options"]);
        assert_eq!(attached.homedir.as_deref(), Some("C:/h"));
        assert_eq!(attached.options.as_deref(), Some("C:/o.conf"));
        assert!(attached.no_options);
        assert_eq!(
            read(&["--enable-win32-openssh-support"]).pipe,
            Some(Setting::WellKnown)
        );
        assert_eq!(
            read(&["--enable-win32-openssh-support="]).pipe,
            Some(Setting::WellKnown),
            "an empty `=` gives no value"
        );
        assert_eq!(
            read(&["--enable-win32-openssh-support", "--daemon"]).pipe,
            Some(Setting::WellKnown),
            "an optional value is never the next option"
        );
        assert_eq!(
            read(&["--enable-win32-openssh-support", r"\\.\pipe\x", "--daemon"]).pipe,
            Some(named(r"\\.\pipe\x"))
        );
        assert_eq!(
            read(&[r"--enable-win32-openssh-support=\\.\pipe\y"]).pipe,
            Some(named(r"\\.\pipe\y"))
        );
    }

    #[test]
    fn a_value_taking_option_before_the_pipe_or_the_home_does_not_hide_them() {
        let after = read(&["--log-file", r"C:\l", "--enable-win32-openssh-support"]);
        assert_eq!(after.pipe, Some(Setting::WellKnown));
        assert_eq!(after.perhaps, vec![]);
        assert_eq!(
            read(&["--log-file", r"C:\l", "--homedir", "C:/h"])
                .homedir
                .as_deref(),
            Some("C:/h")
        );
    }

    #[test]
    fn every_value_gpg_agent_is_given_is_taken_with_its_option() {
        for option in VALUED {
            let given = format!("--{option}");
            let spaced = read(&[&given, "v", "--homedir", "C:/h"]);
            assert_eq!(spaced.homedir.as_deref(), Some("C:/h"), "{option}");
            let attached = format!("--{option}=v");
            let joined = read(&[&attached, "--homedir", "C:/h"]);
            assert_eq!(joined.homedir.as_deref(), Some("C:/h"), "{option}");
        }
        for option in MAYBE_VALUED {
            let given = format!("--{option}");
            assert_eq!(
                read(&[&given, "v", "--homedir", "C:/h"]).homedir.as_deref(),
                Some("C:/h"),
                "{option} with its value"
            );
            assert_eq!(
                read(&[&given, "--homedir", "C:/h"]).homedir.as_deref(),
                Some("C:/h"),
                "{option} without one takes nothing"
            );
            let attached = format!("--{option}=v");
            assert_eq!(
                invoked(&args(&[&attached, "sh", "--homedir", "C:/h"])),
                Err(Failure::Undetermined),
                "{option}'s value attached leaves the next word a bare one"
            );
        }
    }

    /// Each entry of the lists is pinned by a case that writes it out, as a
    /// loop over the lists cannot pin the lists.
    #[test]
    fn a_value_taking_option_written_out_takes_its_value() {
        assert_eq!(
            read(&["--ttyname", "x", "--homedir", "C:/h"])
                .homedir
                .as_deref(),
            Some("C:/h")
        );
    }

    #[test]
    fn a_value_taking_option_may_be_abbreviated_too() {
        assert_eq!(
            read(&["--log", r"C:\l", "--homedir", "C:/h"])
                .homedir
                .as_deref(),
            Some("C:/h")
        );
    }

    #[test]
    fn a_command_line_abbreviates_as_the_parser_lets_it() {
        assert_eq!(
            read(&[r"--enable-w=\\.\pipe\p"]).pipe,
            Some(named(r"\\.\pipe\p"))
        );
        let short = read(&["--ho", r"C:\h", "--opt=C:/o", "--no-o"]);
        assert_eq!(short.homedir.as_deref(), Some(r"C:\h"));
        assert_eq!(short.options.as_deref(), Some("C:/o"));
        assert!(short.no_options);
        assert_eq!(
            read(&["--enable-ssh-support"]).pipe,
            None,
            "another option's name is not a prefix of this one's"
        );
    }

    #[test]
    fn the_first_options_file_is_the_one_read() {
        assert_eq!(
            read(&["--options=C:/a", "--options=C:/b"])
                .options
                .as_deref(),
            Some("C:/a")
        );
    }

    #[test]
    fn parsing_ends_at_the_double_dash_for_certain() {
        let after = read(&["--", "--homedir", "C:/h", "--enable-win32-openssh-support"]);
        assert_eq!(after, Invocation::default());
        assert_eq!(
            read(&["--daemon", "sh", "--", "--homedir", "C:/h"]).homedir,
            None,
            "past `--` nothing is an option, whatever came before it"
        );
        assert_eq!(
            read(&["-v", "--homedir", "C:/h"]).homedir.as_deref(),
            Some("C:/h"),
            "a short option is an option"
        );
    }

    #[test]
    fn past_a_word_no_option_took_the_pipe_counts_and_a_home_leaves_the_agent_unread() {
        let past = read(&[
            "--daemon",
            "sh",
            r"--enable-win32-openssh-support=\\.\pipe\p",
        ]);
        assert_eq!(past.pipe, None, "not taken as the agent's own setting");
        assert_eq!(past.perhaps, vec![named(r"\\.\pipe\p")]);
        let bare = read(&["-", "--enable-win32-openssh-support", "--daemon"]);
        assert_eq!(bare.perhaps, vec![Setting::WellKnown]);
        for home in [
            &["--daemon", "sh", "--homedir", "C:/h"][..],
            &["sh", "--options=C:/o"],
            &["sh", "--no-options"],
        ] {
            assert_eq!(invoked(&args(home)), Err(Failure::Undetermined), "{home:?}");
        }
    }

    #[test]
    fn what_serves_is_the_last_setting_across_the_system_file_the_own_file_and_the_command_line() {
        assert_eq!(served_read(None, None, None), pipes(&[]));
        assert_eq!(
            served_read(None, Some("enable-win32-openssh-support\n"), None),
            pipes(&[WELL_KNOWN])
        );
        let system = "enable-win32-openssh-support \\\\.\\pipe\\sys\n";
        let own = "enable-win32-openssh-support \\\\.\\pipe\\own\n";
        let twice = "enable-win32-openssh-support \\\\.\\pipe\\first\n\
                     enable-win32-openssh-support \\\\.\\pipe\\last\n";
        assert_eq!(
            served_read(None, Some(twice), None),
            pipes(&["last"]),
            "within the person's file, its last setting"
        );
        assert_eq!(
            served_read(Some(twice), None, None),
            pipes(&["last"]),
            "within the system's file, its last setting"
        );
        assert_eq!(
            served_read(Some(system), Some(own), None),
            pipes(&["own"]),
            "the person's file after the system's"
        );
        assert_eq!(
            served_read(Some(system), Some("verbose\n"), None),
            pipes(&["sys"]),
            "a file that does not set it leaves the earlier setting"
        );
        assert_eq!(
            served_read(Some(system), None, Some(&named(r"\\.\pipe\cmd"))),
            pipes(&["cmd"]),
            "the command line after the system's file"
        );
        assert_eq!(
            served_read(Some(system), Some(own), Some(&named(r"\\.\pipe\cmd"))),
            pipes(&["cmd"]),
            "the command line after the person's file"
        );
    }

    #[test]
    fn a_pipe_is_named_however_windows_would_make_it() {
        let of = |value: &str| {
            served_read(
                None,
                Some(&format!("enable-win32-openssh-support {value}\n")),
                None,
            )
        };
        assert_eq!(of(r"C:\not-a-pipe"), pipes(&[]), "no pipe path");
        assert_eq!(of("\"\""), pipes(&[]), "an empty value makes no pipe");
        assert_eq!(of(r"\\.\PIPE\Mixed"), pipes(&["Mixed"]));
        assert_eq!(of("//./pipe/x"), pipes(&["x"]));
        assert_eq!(of(r"\\?\pipe\y"), pipes(&["y"]));
        assert_eq!(of(r"\\.\pipe\\z"), pipes(&["z"]), "a doubled separator");
        assert_eq!(of(r"\\.\pipe\v."), pipes(&["v"]), "a trailing dot");
    }

    #[test]
    fn a_meta_command_makes_every_pipe_named_anywhere_count() {
        let forced = "[force]\nenable-win32-openssh-support \\\\.\\pipe\\forced\n";
        let own = "enable-win32-openssh-support \\\\.\\pipe\\own\n";
        assert_eq!(
            served_read(Some(forced), Some(own), None),
            pipes(&["forced", "own"])
        );
        let branched = "[if defined x]\nenable-win32-openssh-support \\\\.\\pipe\\a\n[else]\n\
                        enable-win32-openssh-support \\\\.\\pipe\\b\n[fi]\n";
        assert_eq!(served_read(None, Some(branched), None), pipes(&["a", "b"]));
        assert_eq!(
            served_read(
                Some("  [ignore]\n"),
                Some(own),
                Some(&named(r"\\.\pipe\cmd"))
            ),
            pipes(&["own", "cmd"]),
            "whichever file holds it, and with the command line's"
        );
    }

    fn agent(pipe: &str, started: u64, socket: &str) -> Agent {
        Agent {
            pipes: vec![pipe.to_owned()],
            started,
            set: vec![pipe.to_owned()],
            serving: Serving {
                socket: PathBuf::from(socket),
                home: Home::Default,
                certainty: Certainty::Perhaps,
            },
        }
    }

    fn serves(pipe: &str) -> Agent {
        agent(pipe, 1, r"C:\s")
    }

    #[test]
    fn a_pipe_is_opened_only_where_every_agent_was_read_and_none_serves_it() {
        let mine = AgentPipe::try_from("mine").unwrap();
        let unasked = || Ok(false);
        assert_eq!(
            among(
                &mine,
                Err(io::Error::other("no list")),
                unasked,
                |_| unreachable!()
            ),
            Err(Failure::Undetermined),
            "with no list, any agent may be running"
        );
        assert_eq!(
            among(&mine, Ok(vec![]), unasked, |_| unreachable!()),
            Ok(None)
        );
        assert_eq!(
            among(&mine, Ok(vec![1, 2]), unasked, |number| {
                Ok(if number == 1 {
                    None
                } else {
                    Some(serves("other"))
                })
            }),
            Ok(None),
            "each read, and none of them serves this one"
        );
        assert_eq!(
            among(&mine, Ok(vec![1]), unasked, |_| Err(Failure::Undetermined)),
            Err(Failure::Undetermined),
            "an agent not read may be the one that serves it"
        );
        let found = among(&mine, Ok(vec![1, 2]), unasked, |number| {
            if number == 1 {
                Err(Failure::Undetermined)
            } else {
                Ok(Some(serves("MINE")))
            }
        });
        assert_eq!(
            found.unwrap().unwrap().socket,
            PathBuf::from(r"C:\s"),
            "one that serves it is reached whatever another could not be read as"
        );
        assert_eq!(
            among(
                &AgentPipe::well_known(),
                Ok(vec![1]),
                || Ok(true),
                |_| { Ok(Some(serves(WELL_KNOWN))) }
            ),
            Ok(None),
            "Windows' own agent holds the name"
        );
    }

    #[test]
    fn of_two_agents_set_to_serve_one_pipe_the_earliest_started_is_reached() {
        let mine = AgentPipe::try_from("mine").unwrap();
        for order in [[1, 2], [2, 1]] {
            let found = among(
                &mine,
                Ok(order.to_vec()),
                || Ok(false),
                |number| {
                    Ok(Some(if number == 1 {
                        agent("mine", 5, r"C:\first")
                    } else {
                        agent("mine", 9, r"C:\second")
                    }))
                },
            );
            assert_eq!(found.unwrap().unwrap().socket, PathBuf::from(r"C:\first"));
        }
    }

    #[test]
    fn a_capability_spelt_as_windows_reads_it_names_the_pipe_an_agent_serves() {
        for spelt in ["MINE", "mine."] {
            let found = among(
                &AgentPipe::try_from(spelt).unwrap(),
                Ok(vec![1]),
                || Ok(false),
                |_| Ok(Some(serves("mine"))),
            );
            assert!(found.unwrap().is_some(), "{spelt}");
        }
    }

    #[test]
    fn an_agent_whose_files_name_several_pipes_may_serve_each() {
        let reader = Agent {
            pipes: pipes(&["a", "b"]),
            ..serves("x")
        };
        let found = among(
            &AgentPipe::try_from("b").unwrap(),
            Ok(vec![1]),
            || Ok(false),
            |_| Ok(Some(reader.clone())),
        );
        assert!(found.unwrap().is_some());
    }

    #[test]
    fn what_an_agent_is_read_as_is_remembered_and_a_read_that_failed_is_not() {
        let known = Mutex::new(BTreeMap::new());
        assert_eq!(
            read_once(&known, (1, 1), || Err(Failure::Undetermined)),
            Err(Failure::Undetermined)
        );
        assert_eq!(
            read_once(&known, (1, 1), || Ok(Some(serves("a")))).unwrap(),
            Some(serves("a")),
            "the failure was not kept"
        );
        assert_eq!(
            read_once(&known, (1, 1), || unreachable!()).unwrap(),
            Some(serves("a")),
            "read once"
        );
        assert_eq!(read_once(&known, (1, 2), || Ok(None)).unwrap(), None);
        assert_eq!(
            read_once(&known, (1, 2), || unreachable!()).unwrap(),
            None,
            "an agent that serves nothing is read once too"
        );
    }

    #[test]
    fn what_a_process_was_read_as_goes_when_it_has() {
        let known = Mutex::new(BTreeMap::from([((1, 1), None), ((2, 1), None)]));
        forget_ended(&known, &[2]);
        assert_eq!(
            known.into_inner().unwrap().into_keys().collect::<Vec<_>>(),
            vec![(2, 1)]
        );
    }

    #[test]
    fn a_process_windows_would_not_open_counts_for_nothing_only_where_denied_or_gone() {
        assert_eq!(unopened(&io::Error::from_raw_os_error(5)), Ok(None));
        assert_eq!(unopened(&io::Error::from_raw_os_error(87)), Ok(None));
        assert_eq!(
            unopened(&io::Error::from_raw_os_error(8)),
            Err(Failure::Undetermined),
            "too little memory says nothing of it"
        );
    }

    #[test]
    fn only_the_persons_account_is_read_for_what_it_serves() {
        let person = Whose::Person {
            logon: 7,
            signed_in: SignedIn::Locally,
            rights: Rights::Standard,
        };
        assert!(is_the_persons(&person));
        assert!(is_the_persons(&Whose::Confined));
        assert!(!is_the_persons(&Whose::Another));
        assert!(!is_the_persons(&Whose::Unread));
        assert!(!is_the_persons(&Whose::Service { services: vec![] }));
    }

    const LISTING: &[u8] = br"sysconfdir:C%3a\sys
homedir:C%3a\home
agent-ssh-socket:C%3a\home\S.gpg-agent.ssh
";

    const SET: &str = "enable-win32-openssh-support \\\\.\\pipe\\mine\n";

    /// What [`read_listing`] finds with the files `given` and no others.
    fn listing(
        printed: &[u8],
        invocation: &Invocation,
        given: &[(&str, &str)],
    ) -> Result<Read, Failure> {
        read_listing(printed, invocation, Home::Default, 1, |file: &Path| {
            Ok(given
                .iter()
                .find(|(path, _)| Path::new(path) == file)
                .map(|(_, text)| (*text).to_owned()))
        })
    }

    #[test]
    fn what_gpgconf_lists_and_the_files_it_names_say_what_an_agent_serves() {
        let plain = Invocation::default();
        let found = listing(LISTING, &plain, &[(r"C:\home\gpg-agent.conf", SET)])
            .unwrap()
            .unwrap();
        assert_eq!(found.pipes, pipes(&["mine"]));
        assert_eq!(
            found.serving.socket,
            PathBuf::from(r"C:\home\S.gpg-agent.ssh")
        );
        assert_eq!(found.serving.home, Home::Default);
        let pipes_of = |result: Result<Read, Failure>| result.unwrap().map(|found| found.pipes);
        assert_eq!(
            pipes_of(listing(LISTING, &plain, &[(r"C:\sys\gpg-agent.conf", SET)])),
            Some(pipes(&["mine"])),
            "the system's file counts as well"
        );
        let elsewhere = Invocation {
            options: Some(r"C:\o.conf".to_owned()),
            ..Invocation::default()
        };
        assert_eq!(
            pipes_of(listing(
                LISTING,
                &elsewhere,
                &[(r"C:\home\gpg-agent.conf", SET)]
            )),
            None,
            "--options is read in place of the home's own file"
        );
        assert_eq!(
            pipes_of(listing(LISTING, &elsewhere, &[(r"C:\o.conf", SET)])),
            Some(pipes(&["mine"]))
        );
    }

    #[test]
    fn no_options_leaves_the_systems_file_and_skips_the_persons_own() {
        let bare = Invocation {
            no_options: true,
            ..Invocation::default()
        };
        let pipes_of = |result: Result<Read, Failure>| result.unwrap().map(|found| found.pipes);
        assert_eq!(
            pipes_of(listing(LISTING, &bare, &[(r"C:\sys\gpg-agent.conf", SET)])),
            Some(pipes(&["mine"]))
        );
        assert_eq!(
            pipes_of(listing(LISTING, &bare, &[(r"C:\home\gpg-agent.conf", SET)])),
            None
        );
    }

    #[test]
    fn an_agent_keeping_its_socket_in_a_posix_emulations_form_serves_no_pipe() {
        assert_eq!(
            read_listing(
                b"homedir:/c/h\nagent-ssh-socket:/c/h/S.gpg-agent.ssh\n",
                &Invocation::default(),
                Home::Default,
                1,
                |_: &Path| unreachable!("none of its files is read")
            ),
            Ok(None)
        );
    }

    #[test]
    fn a_pipe_named_where_the_parse_is_in_doubt_counts_beside_what_the_files_say() {
        let doubted = Invocation {
            perhaps: vec![named(r"\\.\pipe\other")],
            ..Invocation::default()
        };
        let found = listing(LISTING, &doubted, &[(r"C:\home\gpg-agent.conf", SET)])
            .unwrap()
            .unwrap();
        assert_eq!(found.pipes, pipes(&["mine", "other"]));
    }

    #[test]
    fn a_pipe_counted_for_a_doubt_is_perhaps_set_and_one_its_files_name_is_set() {
        let doubted = Invocation {
            perhaps: vec![named(r"\\.\pipe\other")],
            ..Invocation::default()
        };
        let certainty = |found: Agent, pipe: &str| {
            found
                .for_pipe(&AgentPipe::try_from(pipe).unwrap())
                .certainty
        };
        let found = || {
            listing(LISTING, &doubted, &[(r"C:\home\gpg-agent.conf", SET)])
                .unwrap()
                .unwrap()
        };
        assert_eq!(certainty(found(), "mine"), Certainty::Set);
        assert_eq!(certainty(found(), "other"), Certainty::Perhaps);
        let forced = format!("[force]\n{SET}");
        let meta = listing(
            LISTING,
            &Invocation::default(),
            &[(r"C:\home\gpg-agent.conf", &forced)],
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            certainty(meta, "mine"),
            Certainty::Perhaps,
            "a meta-command leaves which line applied unread"
        );
    }

    #[test]
    fn a_pipe_path_windows_will_not_read_leaves_the_agent_unread() {
        let long = format!(r"\\.\pipe\{}", "x".repeat(40_000));
        assert_eq!(
            Setting::Named(long.clone()).pipe(),
            Err(Failure::Undetermined)
        );
        let set = format!("enable-win32-openssh-support {long}\n");
        assert_eq!(
            listing(
                LISTING,
                &Invocation::default(),
                &[(r"C:\home\gpg-agent.conf", &set)]
            ),
            Err(Failure::Undetermined)
        );
    }

    #[test]
    fn what_could_not_be_read_of_an_agent_leaves_it_unread() {
        let plain = Invocation::default();
        let refused = Err(Failure::Undetermined);
        assert_eq!(
            listing(b"homedir:C%3a\\h\n", &plain, &[]),
            refused,
            "no socket listed"
        );
        assert_eq!(
            listing(b"homedir:C%3a\\h\nagent-ssh-socket:C%3a\\s\n", &plain, &[]),
            refused,
            "no system directory listed"
        );
        assert_eq!(
            listing(
                b"sysconfdir:C%3a\\sys\nagent-ssh-socket:C%3a\\s\n",
                &plain,
                &[]
            ),
            refused,
            "no home listed"
        );
        let relative = Invocation {
            options: Some("o.conf".to_owned()),
            ..Invocation::default()
        };
        assert_eq!(
            listing(LISTING, &relative, &[]),
            refused,
            "an --options file only the agent can find"
        );
        let refusing = |unreadable: &'static str| {
            read_listing(LISTING, &plain, Home::Default, 1, move |file: &Path| {
                if file == Path::new(unreadable) {
                    Err(Failure::Undetermined)
                } else {
                    Ok(None)
                }
            })
        };
        assert_eq!(
            refusing(r"C:\sys\gpg-agent.conf"),
            refused,
            "the system's file"
        );
        assert_eq!(
            refusing(r"C:\home\gpg-agent.conf"),
            refused,
            "the person's own"
        );
    }

    #[test]
    fn a_read_that_failed_counts_for_nothing_only_where_the_process_has_ended() {
        let failed = || Err(Failure::Undetermined);
        assert_eq!(
            unless_ended(failed(), || true),
            Ok(None),
            "gone, it serves no pipe"
        );
        assert_eq!(
            unless_ended(failed(), || false),
            Err(Failure::Undetermined),
            "still running, it may be the pipe's server"
        );
        assert_eq!(
            unless_ended(Ok(Some(serves("a"))), || unreachable!()),
            Ok(Some(serves("a"))),
            "a process read is taken as read"
        );
    }

    #[test]
    fn the_well_known_pipe_is_left_to_windows_own_agent_only_while_it_runs() {
        let other = AgentPipe::try_from("mine").unwrap();
        let asked = std::cell::Cell::new(false);
        assert!(!windows_agent_holds(&other, || {
            asked.set(true);
            Ok(true)
        }));
        assert!(
            !asked.get(),
            "the service is asked of only for the well-known name"
        );
        let well_known = AgentPipe::well_known();
        assert!(windows_agent_holds(&well_known, || Ok(true)));
        assert!(
            windows_agent_holds(&AgentPipe::try_from("OpenSSH-SSH-Agent").unwrap(), || {
                Ok(true)
            }),
            "that name however a capability spells it"
        );
        assert!(
            windows_agent_holds(&AgentPipe::try_from("openssh-ssh-agent.").unwrap(), || {
                Ok(true)
            }),
            "that name however Windows reads it"
        );
        assert!(!windows_agent_holds(&well_known, || Ok(false)));
        assert!(
            !windows_agent_holds(&well_known, || Err(io::Error::other("no manager"))),
            "a service that cannot be asked holds nothing Hedwig can say"
        );
    }

    #[test]
    fn an_agent_image_s_installation_is_the_folder_above_its_bin() {
        assert_eq!(
            installation_of(Path::new(r"C:\Program Files (x86)\GnuPG\bin\gpg-agent.exe")),
            Some(r"C:\Program Files (x86)\GnuPG")
        );
        assert_eq!(installation_of(Path::new("gpg-agent.exe")), None);
    }
}
