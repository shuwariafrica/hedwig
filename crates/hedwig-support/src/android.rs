//! What an ADB suite stands on: platform-tools' own server and client of the
//! current release, on ports of the suite's own, and stand-ins for what the
//! server reaches - a device attached over TCP and an emulator's console.
//!
//! The server runs with USB, the emulator scan and mDNS off, so it reaches no
//! device of the person's and no server of theirs is touched. The stand-ins
//! listen on ports the system draws, outside the emulator range the person's
//! own server scans.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The `adb.exe` `HEDWIG_ADB` names, of the platform-tools release
/// `scripts\fetch-test-tools.ps1` lays out.
///
/// # Panics
///
/// Where `HEDWIG_ADB` is unset or names no file: a suite of real processes
/// has nothing to run.
#[allow(clippy::panic, reason = "test scaffolding")]
pub fn executable() -> PathBuf {
    let Some(path) = std::env::var_os("HEDWIG_ADB").map(PathBuf::from) else {
        panic!("HEDWIG_ADB names adb.exe: run scripts\\fetch-test-tools.ps1");
    };
    assert!(path.is_file(), "{} is not there", path.display());
    path
}

/// The `adb.exe` `HEDWIG_ADB_OUTDATED` names: platform-tools 34.0.5, whose
/// server lists no devices in protocol buffers, laid out by
/// `scripts\fetch-test-tools.ps1`.
///
/// # Panics
///
/// Where `HEDWIG_ADB_OUTDATED` is unset or names no file.
#[allow(clippy::panic, reason = "test scaffolding")]
pub fn outdated_executable() -> PathBuf {
    let Some(path) = std::env::var_os("HEDWIG_ADB_OUTDATED").map(PathBuf::from) else {
        panic!("HEDWIG_ADB_OUTDATED names adb.exe: run scripts\\fetch-test-tools.ps1");
    };
    assert!(path.is_file(), "{} is not there", path.display());
    path
}

/// A loopback port nothing listens on now.
///
/// # Panics
///
/// Where the system binds no port.
#[allow(clippy::expect_used, reason = "test scaffolding")]
pub fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|bound| bound.local_addr())
        .map(|address| address.port())
        .expect("a loopback port")
}

/// An ADB server of the suite's own on a port of its own, ended when dropped.
pub struct Server {
    child: Child,
    port: u16,
}

impl Server {
    /// # Panics
    ///
    /// Where the server does not start or listen within twenty seconds.
    #[allow(clippy::expect_used, reason = "test scaffolding")]
    pub fn start(adb: &Path) -> Server {
        let port = free_port();
        let child = Command::new(adb)
            .args(["-L", &format!("tcp:localhost:{port}"), "server", "nodaemon"])
            .env("ADB_USB", "0")
            .env("ADB_EMU", "0")
            .env("ADB_MDNS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the server starts");
        let started = Instant::now();
        while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the server did not listen"
            );
            thread::sleep(Duration::from_millis(100));
        }
        Server { child, port }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The server's own process number.
    pub fn process(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// platform-tools' client, given `arguments`, of the server at `host` and
/// `port`.
///
/// # Panics
///
/// Where the client cannot be started.
#[allow(clippy::expect_used, reason = "test scaffolding")]
pub fn client(adb: &Path, host: &str, port: u16, arguments: &[&str]) -> Output {
    Command::new(adb)
        .args(["-H", host, "-P", &port.to_string()])
        .args(arguments)
        .env("ADB_USB", "0")
        .env("ADB_EMU", "0")
        .env("ADB_MDNS", "0")
        .stdin(Stdio::null())
        .output()
        .expect("the client starts")
}

/// What a client printed, both streams.
pub fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

const CNXN: u32 = 0x4e58_4e43;
const OPEN: u32 = 0x4e45_504f;
const OKAY: u32 = 0x5941_4b4f;
const CLSE: u32 = 0x4553_4c43;
const WRTE: u32 = 0x4554_5257;
/// `A_VERSION_SKIP_CHECKSUM` (`adb.h`).
const VERSION: u32 = 0x0100_0001;
const MAX_PAYLOAD: u32 = 256 * 1024;

fn packet(command: u32, first: u32, second: u32, data: &[u8]) -> Vec<u8> {
    let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let check = data
        .iter()
        .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
    let mut bytes = Vec::with_capacity(24 + data.len());
    for word in [command, first, second, length, check, !command] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(data);
    bytes
}

/// One packet: its command, its two arguments and its payload.
fn received(stream: &mut TcpStream) -> io::Result<(u32, u32, u32, Vec<u8>)> {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header)?;
    let word = |at: usize| {
        let mut four = [0u8; 4];
        four.copy_from_slice(header.get(at..at + 4).unwrap_or(&[0; 4]));
        u32::from_le_bytes(four)
    };
    let length = usize::try_from(word(12)).unwrap_or(usize::MAX);
    if length > MAX_PAYLOAD as usize {
        return Err(io::Error::other("a payload past the limit"));
    }
    let mut data = vec![0u8; length];
    stream.read_exact(&mut data)?;
    Ok((word(0), word(4), word(8), data))
}

/// A stand-in Android device, reached by a server as a device attached by
/// `adb connect` is: it answers the server's `CNXN` with a banner naming its
/// model, and echoes back what it is sent on every `tcp:` stream it is
/// opened for. Every other service is closed at once.
pub struct Device {
    port: u16,
    opened: Arc<Mutex<Vec<String>>>,
    connections: Arc<Mutex<Vec<TcpStream>>>,
}

impl Device {
    /// # Errors
    ///
    /// What the system said when binding.
    pub fn start(model: &str) -> io::Result<Device> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let banner = format!(
            "device::ro.product.name=hedwig_standin;ro.product.model={model};ro.product.device=standin;"
        );
        let opened: Arc<Mutex<Vec<String>>> = Arc::default();
        let connections: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
        let (kept, held) = (Arc::clone(&opened), Arc::clone(&connections));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                if let (Ok(clone), Ok(mut held)) = (stream.try_clone(), held.lock()) {
                    held.push(clone);
                }
                let (banner, kept) = (banner.clone(), Arc::clone(&kept));
                thread::spawn(move || serve(stream, &banner, &kept));
            }
        });
        Ok(Device {
            port,
            opened,
            connections,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The serial a server gives the device once `adb connect` attached it.
    pub fn serial(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Every service a server opened on the device, as it named it.
    pub fn opened(&self) -> Vec<String> {
        self.opened
            .lock()
            .map(|opened| opened.clone())
            .unwrap_or_default()
    }

    /// Drops every server's connection to the device, as a device leaving
    /// the network does.
    pub fn leave(&self) {
        if let Ok(mut held) = self.connections.lock() {
            for stream in held.drain(..) {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }
}

/// One stream a server opened on the device: the server's id for it, whether
/// a write of ours waits for its `OKAY`, and what waits behind that.
struct Opened {
    theirs: u32,
    waiting: bool,
    queued: VecDeque<Vec<u8>>,
}

fn serve(mut stream: TcpStream, banner: &str, opened: &Mutex<Vec<String>>) {
    let Ok(mut out) = stream.try_clone() else {
        return;
    };
    let mut streams: BTreeMap<u32, Opened> = BTreeMap::new();
    let mut next = 1u32;
    let mut put = |command: u32, first: u32, second: u32, data: &[u8]| {
        out.write_all(&packet(command, first, second, data)).is_ok()
    };
    while let Ok((command, first, second, data)) = received(&mut stream) {
        let sent = match command {
            CNXN => put(CNXN, VERSION, MAX_PAYLOAD, banner.as_bytes()),
            OPEN => {
                let name = String::from_utf8_lossy(&data)
                    .trim_end_matches('\0')
                    .to_owned();
                let echoes = name.starts_with("tcp:");
                if let Ok(mut opened) = opened.lock() {
                    opened.push(name);
                }
                if echoes {
                    let ours = next;
                    next += 1;
                    streams.insert(
                        ours,
                        Opened {
                            theirs: first,
                            waiting: false,
                            queued: VecDeque::new(),
                        },
                    );
                    put(OKAY, ours, first, &[])
                } else {
                    put(CLSE, 0, first, &[])
                }
            }
            WRTE => match streams.get_mut(&second) {
                Some(echoing) => {
                    let theirs = echoing.theirs;
                    let acked = put(OKAY, second, theirs, &[]);
                    if echoing.waiting {
                        echoing.queued.push_back(data);
                        acked
                    } else {
                        echoing.waiting = true;
                        acked && put(WRTE, second, theirs, &data)
                    }
                }
                None => put(CLSE, 0, first, &[]),
            },
            OKAY => {
                if let Some(echoing) = streams.get_mut(&second) {
                    if let Some(data) = echoing.queued.pop_front() {
                        let theirs = echoing.theirs;
                        put(WRTE, second, theirs, &data)
                    } else {
                        echoing.waiting = false;
                        true
                    }
                } else {
                    true
                }
            }
            CLSE => {
                streams.remove(&second);
                true
            }
            _ => true,
        };
        if !sent {
            break;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

/// The token a [`Console`] stand-in asks for.
pub const CONSOLE_TOKEN: &str = "hedwigsuitetoken";

/// A stand-in emulator console on the workstation's IPv6 loopback, at a port
/// the system draws: it greets as an emulator's console does when its token
/// file holds a token, naming the file; answers `auth` with the token `OK`
/// and anything else `KO`; and once authenticated answers `ping` and the
/// commands that act on the emulated device `OK`, and every other word `KO`.
/// Every line it reads is kept.
pub struct Console {
    port: u16,
    token: PathBuf,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Console {
    /// Writes the token to `.emulator_console_auth_token` in `folder`, and
    /// listens.
    ///
    /// # Errors
    ///
    /// What the system said when writing the token or binding.
    pub fn start(folder: &Path) -> io::Result<Console> {
        let token = folder.join(".emulator_console_auth_token");
        std::fs::write(&token, CONSOLE_TOKEN)?;
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let (kept, named) = (Arc::clone(&lines), token.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let (kept, named) = (Arc::clone(&kept), named.clone());
                thread::spawn(move || console(stream, &named, &kept));
            }
        });
        Ok(Console { port, token, lines })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The token file its banner names.
    pub fn token(&self) -> &Path {
        &self.token
    }

    /// Every line the console was sent, without its line end.
    pub fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|lines| lines.clone())
            .unwrap_or_default()
    }
}

/// The console's own answers: what it says on a connection, to `auth`, to
/// `ping`, and to a word it knows no command by.
fn console(stream: TcpStream, token: &Path, lines: &Mutex<Vec<String>>) {
    let Ok(mut out) = stream.try_clone() else {
        return;
    };
    let greeting = format!(
        "Android Console: Authentication required\r\n\
         Android Console: type 'auth <auth_token>' to authenticate\r\n\
         Android Console: you can find your <auth_token> in \r\n\
         '{}'\r\nOK\r\n",
        token.display()
    );
    if out.write_all(greeting.as_bytes()).is_err() {
        return;
    }
    let mut authenticated = false;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    while reader.read_line(&mut line).is_ok_and(|read| read > 0) {
        let body = line.trim_end_matches(['\r', '\n']).to_owned();
        line.clear();
        if let Ok(mut lines) = lines.lock() {
            lines.push(body.clone());
        }
        let mut words = body.split_ascii_whitespace();
        let answer = match (words.next(), authenticated) {
            (Some("auth"), _) if words.next() == Some(CONSOLE_TOKEN) => {
                authenticated = true;
                "Android Console: type 'help' for a list of commands\r\nOK\r\n".to_owned()
            }
            (Some("auth"), _) => {
                "KO: authentication token does not match ~/.emulator_console_auth_token\r\n"
                    .to_owned()
            }
            (Some("quit" | "exit"), true) => break,
            (Some("ping"), true) => "I am alive!\r\nOK\r\n".to_owned(),
            (Some("geo" | "sms" | "power" | "rotate" | "help") | None, true) => "OK\r\n".to_owned(),
            (Some(_), true) => "KO: unknown command, try 'help'\r\n".to_owned(),
            (_, false) => "KO: authentication required\r\n".to_owned(),
        };
        if out.write_all(answer.as_bytes()).is_err() {
            break;
        }
    }
    let _ = out.shutdown(Shutdown::Both);
}
