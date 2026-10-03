//! A lent emulator's console, carried on to the remote at the port its
//! serial names, where the remote's `adb emu` and Appium's console client
//! look for it (`client/console.cpp`, `adb_get_emulator_console_port`).
//!
//! The console accepts only connections from the workstation's own loopback,
//! and authenticates with the token in the file its banner names. The core
//! reads that file on the workstation and authenticates; the remote is given
//! the console as it stands once authenticated, its own `auth` is answered
//! and never passed, and only the commands that act on the emulated device
//! reach the console: nothing the remote sends opens the hypervisor's
//! monitor, a port or a file on the workstation.
//!
//! [`Console`] is a function of the bytes given to it; [`carry`] does the
//! reading and writing.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::thread;

use hedwig_model::capability::ServiceHost;
use hedwig_model::text::{DeviceSerial, Port};

use crate::service::{Service, reach};

/// The longest line the console relay reads from either end: past the
/// longest command a test framework sends (an SMS of 160 characters, a
/// fingerprint's id) and the console's banner lines.
pub const LINE: usize = 4096;

/// The longest token file read: the emulator writes sixteen characters.
const TOKEN: u64 = 1024;

/// The file the console reads its token from, by name.
const TOKEN_FILE: &str = ".emulator_console_auth_token";

/// The console port an emulator's serial names: `emulator-<port>`, exactly as
/// the server names one.
pub fn port(serial: &DeviceSerial) -> Option<Port> {
    let digits = serial.as_str().strip_prefix("emulator-")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Port::try_from(digits.parse::<u16>().ok()?).ok()
}

/// What the console's banner asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Banner {
    /// Authentication with the token in this file.
    Token(String),
    /// Nothing: the person's token file is empty, and the console open.
    Open,
}

/// Reads the console's banner: whether it asks for a token, and the file it
/// names for it; `None` where it is not an emulator's console banner.
pub fn banner(text: &str) -> Option<Banner> {
    if !text.starts_with("Android Console:") {
        return None;
    }
    if !text.contains("Authentication required") {
        return Some(Banner::Open);
    }
    // `Android Console: you can find your <auth_token> in` and then the path,
    // quoted, on a line of its own.
    let mut lines = text.lines();
    lines.find(|line| line.contains("you can find your <auth_token> in"))?;
    let path = lines
        .next()?
        .trim()
        .strip_prefix('\'')?
        .strip_suffix('\'')?;
    let named = Path::new(path).file_name()?.to_str()?;
    (named == TOKEN_FILE && Path::new(path).is_absolute()).then(|| Banner::Token(path.to_owned()))
}

/// What the relay does with one line the remote sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// Passed to the console as it came.
    Pass,
    /// The remote's own `auth`, whatever its token: the console is
    /// authenticated already.
    Authenticated,
    /// Refused, by its first word.
    Refused(String),
}

/// The commands that act on the emulated device alone, by their first word,
/// and how each one's arguments are read (`android_emulator_console.txt`).
fn decided(command: &str, arguments: &[&str], network: bool) -> Line {
    // An argument a command writes to or reads from is a bare name: the
    // console puts it under the AVD's own folder.
    let bare = || {
        arguments
            .iter()
            .skip(1)
            .all(|argument| !argument.contains(['/', '\\', ':']) && !argument.contains(".."))
    };
    let first = arguments.first().copied();
    let passed = match command {
        "help" | "help-verbose" | "ping" | "quit" | "exit" | "event" | "geo" | "gsm" | "cdma"
        | "sms" | "sensor" | "finger" | "power" | "rotate" | "fold" | "unfold" | "kill"
        | "restart" | "crash" | "crash-on-exit" | "multidisplay" | "resize-display" | "nodraw"
        | "phonenumber" | "debug" | "icebox" => true,
        "avd" => matches!(
            first,
            None | Some("stop" | "start" | "status" | "name" | "snapshot")
        ),
        "redir" => matches!(first, None | Some("list")),
        "network" => first != Some("capture") || bare(),
        "screenrecord" | "automation" | "physics" => bare(),
        // Has the emulator reach a host the remote names.
        "proxy" => network,
        _ => false,
    };
    if passed {
        Line::Pass
    } else {
        Line::Refused(command.to_owned())
    }
}

/// One line the remote sent, without its line end, judged.
pub fn judge(line: &str, network: bool) -> Line {
    let mut words = line.split_ascii_whitespace();
    let Some(command) = words.next() else {
        return Line::Pass;
    };
    if command == "auth" {
        return Line::Authenticated;
    }
    let arguments: Vec<&str> = words.collect();
    decided(command, &arguments, network)
}

/// What goes to the console in place of the remote's `auth`: a command
/// the console answers `OK` to and that changes nothing, so the remote reads
/// one answer for its line, in its place among the others.
pub const AUTHENTICATED: &[u8] = b"ping\r\n";

/// What goes to the console in place of a refused command: a word the console
/// knows no command by, so the remote reads the console's own `KO` for it, in
/// its place among the others; the reason is the workstation's to show.
pub const REFUSED: &[u8] = b"hedwig-refused\r\n";

/// Why a console could not be carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unconsoled {
    /// Nothing answered at the port, or it is not the person's own.
    Unreached,
    /// What answered sent no emulator console's banner.
    NotConsole,
    /// The token file the banner names could not be read.
    Tokenless,
    /// The console refused the workstation's own token.
    Refused,
}

/// Reads up to and including the line `OK` or a line beginning `KO`, at most
/// `LINE` bytes.
fn answer(stream: &mut TcpStream) -> io::Result<String> {
    let mut read = Vec::new();
    let mut byte = [0u8; 1];
    while read.len() < LINE {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        read.push(byte[0]);
        if read.ends_with(b"OK\r\n") || read.ends_with(b"OK\n") {
            break;
        }
        let last = read
            .iter()
            .rposition(|byte| *byte == b'\n')
            .and_then(|end| read.get(..end))
            .map(|before| {
                before
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                    .map_or(before, |start| before.get(start + 1..).unwrap_or_default())
            });
        if read.ends_with(b"\n") && last.is_some_and(|line| line.starts_with(b"KO")) {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&read).into_owned())
}

/// What a remote is greeted with before the console's answer to the token:
/// the console's own request for one, less the line naming the token file,
/// which is a path of the workstation. A client reads past two `OK`s before
/// the answer to its command, whether or not it sent a token
/// (`client/console.cpp:166-185`), and the remote holds none.
pub const ASKED: &[u8] = b"Android Console: Authentication required\r\n\
Android Console: type 'auth <auth_token>' to authenticate\r\nOK\r\n";

/// Opens the console at `port` on the workstation's loopback and
/// authenticates with the workstation's own token: the console, and what the
/// remote is greeted with - [`ASKED`], then the console as it stands once
/// authenticated, as a client holding the token is greeted.
///
/// # Errors
///
/// [`Unconsoled`], where the console could not be reached or authenticated.
pub fn open(port: Port) -> Result<(TcpStream, Vec<u8>), Unconsoled> {
    let service = Service {
        host: ServiceHost::Workstation,
        port,
    };
    let mut console = reach(&service).result.map_err(|_| Unconsoled::Unreached)?;
    let _ = console.set_read_timeout(Some(crate::PATIENCE));
    let greeted = answer(&mut console).map_err(|_| Unconsoled::NotConsole)?;
    let greeting = match banner(&greeted).ok_or(Unconsoled::NotConsole)? {
        Banner::Open => greeted,
        Banner::Token(path) => {
            let mut token = String::new();
            std::fs::File::open(&path)
                .and_then(|file| file.take(TOKEN).read_to_string(&mut token))
                .map_err(|_| Unconsoled::Tokenless)?;
            let token = token.trim();
            if token.is_empty() || token.contains(['\r', '\n']) {
                return Err(Unconsoled::Tokenless);
            }
            console
                .write_all(format!("auth {token}\r\n").as_bytes())
                .map_err(|_| Unconsoled::Unreached)?;
            let authenticated = answer(&mut console).map_err(|_| Unconsoled::Unreached)?;
            if !authenticated.ends_with("OK\r\n") && !authenticated.ends_with("OK\n") {
                return Err(Unconsoled::Refused);
            }
            authenticated
        }
    };
    let _ = console.set_read_timeout(None);
    Ok((console, [ASKED, greeting.as_bytes()].concat()))
}

/// A line from the remote longer than [`LINE`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overlong;

impl std::fmt::Display for Overlong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the remote sent a console line longer than {LINE} bytes")
    }
}

impl std::error::Error for Overlong {}

/// The remote's side of one console connection, as the relay reads it.
#[derive(Debug, Default)]
pub struct Console {
    held: Vec<u8>,
}

/// What the relay does with what the remote sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    ToConsole(Vec<u8>),
    /// A command refused, by its first word.
    Refused(String),
}

impl Console {
    /// Takes what the remote sent: each whole line judged and its stand-in
    /// sent where it is not passed, a partial line held.
    ///
    /// # Errors
    ///
    /// [`Overlong`] where a line runs past [`LINE`] bytes.
    pub fn from_remote(&mut self, bytes: &[u8], network: bool) -> Result<Vec<Out>, Overlong> {
        self.held.extend_from_slice(bytes);
        let mut outs = Vec::new();
        while let Some(end) = self.held.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.held.drain(..=end).collect();
            let text = String::from_utf8_lossy(&line);
            let body = text.trim_end_matches(['\r', '\n']);
            match judge(body, network) {
                Line::Pass => outs.push(Out::ToConsole(line)),
                Line::Authenticated => outs.push(Out::ToConsole(AUTHENTICATED.to_vec())),
                Line::Refused(command) => {
                    outs.push(Out::ToConsole(REFUSED.to_vec()));
                    outs.push(Out::Refused(command));
                }
            }
        }
        if self.held.len() > LINE {
            return Err(Overlong);
        }
        Ok(outs)
    }
}

/// Carries one remote connection to the console at `port`: greets the
/// remote with the console as it stands once authenticated, then judges each
/// line it sends; everything the remote reads after its greeting is the
/// console's. `refused` is told each command refused.
pub fn carry(
    remote: TcpStream,
    port: Port,
    network: bool,
    refused: impl Fn(String) + Send + 'static,
) {
    thread::spawn(move || {
        let Ok((console, greeting)) = open(port) else {
            let _ = remote.shutdown(Shutdown::Both);
            return;
        };
        let (Ok(mut from_console), Ok(mut to_remote), Ok(mut from_remote), Ok(mut to_console)) = (
            console.try_clone(),
            remote.try_clone(),
            remote.try_clone(),
            console.try_clone(),
        ) else {
            return;
        };
        if to_remote.write_all(&greeting).is_err() {
            return;
        }
        let back = thread::spawn(move || {
            let _ = io::copy(&mut from_console, &mut to_remote);
            let _ = to_remote.shutdown(Shutdown::Write);
        });
        let mut side = Console::default();
        let mut buffer = [0u8; 4096];
        'read: loop {
            let read = match from_remote.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            let Ok(outs) = side.from_remote(buffer.get(..read).unwrap_or_default(), network) else {
                break;
            };
            for out in outs {
                match out {
                    Out::ToConsole(bytes) => {
                        if to_console.write_all(&bytes).is_err() {
                            break 'read;
                        }
                    }
                    Out::Refused(command) => refused(command),
                }
            }
        }
        let _ = to_console.shutdown(Shutdown::Write);
        let _ = back.join();
        let _ = remote.shutdown(Shutdown::Both);
        let _ = console.shutdown(Shutdown::Both);
    });
}
