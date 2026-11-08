//! What an ADB suite stands on: platform-tools' own server and client of the
//! current release, on ports of the suite's own, and stand-ins for what the
//! server reaches - a device attached over TCP and an emulator's console.
//!
//! The server runs with USB, the emulator scan and mDNS off, so it reaches no
//! device of the person's and no server of theirs is touched. The stand-ins
//! listen on ports the system draws, outside the emulator range the person's
//! own server scans.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Condvar, Mutex};
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
    started(adb, host, port, arguments)
        .wait_with_output()
        .expect("the client ends")
}

/// [`client`] left running, both its streams piped, for a suite that
/// watches what happens while it waits for its answer.
///
/// # Panics
///
/// Where the client cannot be started.
#[allow(clippy::expect_used, reason = "test scaffolding")]
pub fn started(adb: &Path, host: &str, port: u16, arguments: &[&str]) -> Child {
    Command::new(adb)
        .args(["-H", host, "-P", &port.to_string()])
        .args(arguments)
        .env("ADB_USB", "0")
        .env("ADB_EMU", "0")
        .env("ADB_MDNS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
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
/// model, echoes back what it is sent on every `tcp:` stream it is opened
/// for, and takes a `reverse:` request as adbd does - holding its answer
/// while [`Device::hold_reverses`] says so. [`Device::reach`] opens a
/// connection through a reverse as an app on the device does. Every other
/// service is closed at once.
pub struct Device {
    port: u16,
    opened: Arc<Mutex<Vec<String>>>,
    connections: Arc<Mutex<Vec<TcpStream>>>,
    links: Arc<Mutex<Vec<Arc<Link>>>>,
    reverses: Arc<Reverses>,
}

/// The device's reverses, each device side to the host side the server
/// reaches for it, and whether the device's answers wait.
#[derive(Default)]
struct Reverses {
    held: Mutex<BTreeMap<String, String>>,
    holding: Mutex<bool>,
    released: Condvar,
    /// A file whose presence each `reverse:` request is noted with, as it
    /// arrives.
    witness: Mutex<Option<PathBuf>>,
    witnessed: Mutex<Vec<(String, bool)>>,
}

impl Reverses {
    fn note(&self, name: &str) {
        let present = self
            .witness
            .lock()
            .ok()
            .and_then(|witness| witness.as_ref().map(|path| path.exists()));
        if let (Some(present), Ok(mut witnessed)) = (present, self.witnessed.lock()) {
            witnessed.push((name.to_owned(), present));
        }
    }

    fn wait_released(&self) {
        let Ok(mut holding) = self.holding.lock() else {
            return;
        };
        while *holding {
            let Ok(waited) = self.released.wait(holding) else {
                return;
            };
            holding = waited;
        }
    }

    /// adbd's answer to a reverse (`handle_forward_request`, on the device),
    /// the reverse taken where it is one.
    fn answer(&self, name: &str) -> Vec<u8> {
        let refused = |words: &str| {
            let mut answer = format!("FAIL{:04x}", words.len()).into_bytes();
            answer.extend_from_slice(words.as_bytes());
            answer
        };
        let Ok(mut held) = self.held.lock() else {
            return refused("the stand-in device failed");
        };
        let request = name.strip_prefix("reverse:").unwrap_or(name);
        if request == "killforward-all" {
            held.clear();
            return b"OKAY".to_vec();
        }
        if request == "list-forward" {
            let mut listing = String::new();
            for (local, host) in held.iter() {
                let _ = writeln!(listing, "host-1 {local} {host}");
            }
            let mut answer = format!("OKAY{:04x}", listing.len()).into_bytes();
            answer.extend_from_slice(listing.as_bytes());
            return answer;
        }
        if let Some(local) = request.strip_prefix("killforward:") {
            return if held.remove(local).is_some() {
                b"OKAY".to_vec()
            } else {
                refused(&format!("listener '{local}' not found"))
            };
        }
        let Some(forward) = request.strip_prefix("forward:") else {
            return refused("not a reverse forwarding command");
        };
        let (norebind, body) = forward
            .strip_prefix("norebind:")
            .map_or((false, forward), |body| (true, body));
        let Some((local, host)) = body.split_once(';') else {
            return refused(&format!("bad forward: {body}"));
        };
        if norebind && held.contains_key(local) {
            return refused("cannot rebind existing socket");
        }
        held.insert(local.to_owned(), host.to_owned());
        b"OKAY".to_vec()
    }
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
        let links: Arc<Mutex<Vec<Arc<Link>>>> = Arc::default();
        let reverses: Arc<Reverses> = Arc::default();
        let (kept, held, linked, taken) = (
            Arc::clone(&opened),
            Arc::clone(&connections),
            Arc::clone(&links),
            Arc::clone(&reverses),
        );
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let (Ok(clone), Ok(out)) = (stream.try_clone(), stream.try_clone()) else {
                    continue;
                };
                if let Ok(mut held) = held.lock() {
                    held.push(clone);
                }
                let link = Arc::new(Link {
                    out: Mutex::new(out),
                    streams: Mutex::default(),
                    changed: Condvar::new(),
                });
                if let Ok(mut linked) = linked.lock() {
                    linked.push(Arc::clone(&link));
                }
                let (banner, kept, taken) = (banner.clone(), Arc::clone(&kept), Arc::clone(&taken));
                thread::spawn(move || serve(stream, &link, &banner, &kept, &taken));
            }
        });
        Ok(Device {
            port,
            opened,
            connections,
            links,
            reverses,
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

    /// Each `reverse:` request from here is noted with whether `path` exists
    /// as it arrives, before the device takes it or answers.
    pub fn witness(&self, path: PathBuf) {
        if let Ok(mut witness) = self.reverses.witness.lock() {
            *witness = Some(path);
        }
    }

    /// Each `reverse:` request noted since [`Device::witness`], with whether
    /// the file was there as it arrived.
    pub fn witnessed(&self) -> Vec<(String, bool)> {
        self.reverses
            .witnessed
            .lock()
            .map(|witnessed| witnessed.clone())
            .unwrap_or_default()
    }

    /// While `holding`, the device takes no reverse and answers none until
    /// this is called again without it.
    pub fn hold_reverses(&self, holding: bool) {
        if let Ok(mut held) = self.reverses.holding.lock() {
            *held = holding;
        }
        self.reverses.released.notify_all();
    }

    /// Opens a connection at the device's side of the reverse at `local`, as
    /// an app on the device does: the device asks the server for the host
    /// side the reverse names, sends `sent`, and gives back as many bytes as
    /// came back, or what came before the server closed the connection -
    /// nothing where the device holds no such reverse.
    pub fn reach(&self, local: &str, sent: &[u8]) -> Vec<u8> {
        let host = self
            .reverses
            .held
            .lock()
            .ok()
            .and_then(|held| held.get(local).cloned());
        let link = self
            .links
            .lock()
            .ok()
            .and_then(|links| links.last().cloned());
        let (Some(host), Some(link)) = (host, link) else {
            return Vec::new();
        };
        let ours = link.open(
            0,
            Role::Reaching {
                got: Vec::new(),
                closed: false,
            },
        );
        let mut name = host.into_bytes();
        name.push(0);
        let theirs = link
            .put(OPEN, ours, 0, &name)
            .then(|| {
                link.until(ours, |opened| match &opened.role {
                    Role::Reaching { closed: true, .. } => Some(None),
                    _ if opened.theirs != 0 => Some(Some(opened.theirs)),
                    _ => None,
                })
            })
            .flatten()
            .flatten();
        let got = theirs
            .filter(|theirs| link.put(WRTE, ours, *theirs, sent))
            .and_then(|_| {
                link.until(ours, |opened| match &opened.role {
                    Role::Reaching { got, closed } if *closed || got.len() >= sent.len() => {
                        Some(got.clone())
                    }
                    _ => None,
                })
            })
            .unwrap_or_default();
        if let Some(theirs) = theirs {
            let _ = link.put(CLSE, ours, theirs, &[]);
        }
        link.forget(ours);
        got
    }
}

/// One server's connection to the device: where packets to it are written,
/// and each stream open on it, by the device's id for it.
struct Link {
    out: Mutex<TcpStream>,
    streams: Mutex<Streams>,
    changed: Condvar,
}

#[derive(Default)]
struct Streams {
    last: u32,
    open: BTreeMap<u32, Opened>,
}

/// One stream on a link: the server's id for it, 0 until the server took
/// one the device opened; whether a write of ours waits for its `OKAY`, and
/// what waits behind that; and what the stream is.
struct Opened {
    theirs: u32,
    waiting: bool,
    queued: VecDeque<Vec<u8>>,
    role: Role,
}

enum Role {
    /// Opened by the server for a `tcp:` socket: what it is sent comes back.
    Echo,
    /// Opened by the server for a `reverse:`: closed once its answer is
    /// taken.
    Answering,
    /// Opened by the device through a reverse: what came back, and whether
    /// the server closed it.
    Reaching { got: Vec<u8>, closed: bool },
}

impl Link {
    fn put(&self, command: u32, first: u32, second: u32, data: &[u8]) -> bool {
        self.out
            .lock()
            .is_ok_and(|mut out| out.write_all(&packet(command, first, second, data)).is_ok())
    }

    fn open(&self, theirs: u32, role: Role) -> u32 {
        let Ok(mut streams) = self.streams.lock() else {
            return 0;
        };
        streams.last += 1;
        let ours = streams.last;
        streams.open.insert(
            ours,
            Opened {
                theirs,
                waiting: false,
                queued: VecDeque::new(),
                role,
            },
        );
        ours
    }

    fn forget(&self, ours: u32) {
        if let Ok(mut streams) = self.streams.lock() {
            streams.open.remove(&ours);
        }
    }

    /// The server wrote on stream `second`.
    fn wrote(&self, first: u32, second: u32, data: &[u8]) -> bool {
        let Ok(mut streams) = self.streams.lock() else {
            return false;
        };
        let Some(opened) = streams.open.get_mut(&second) else {
            return self.put(CLSE, 0, first, &[]);
        };
        let theirs = opened.theirs;
        let acked = self.put(OKAY, second, theirs, &[]);
        match &mut opened.role {
            Role::Echo if opened.waiting => {
                opened.queued.push_back(data.to_vec());
                acked
            }
            Role::Echo => {
                opened.waiting = true;
                acked && self.put(WRTE, second, theirs, data)
            }
            Role::Reaching { got, .. } => {
                got.extend_from_slice(data);
                self.changed.notify_all();
                acked
            }
            Role::Answering => acked,
        }
    }

    /// The server's `OKAY` on stream `second`: its answer to a stream the
    /// device opened, or its taking of what the device wrote.
    fn okayed(&self, first: u32, second: u32) -> bool {
        let Ok(mut streams) = self.streams.lock() else {
            return false;
        };
        let Some(opened) = streams.open.get_mut(&second) else {
            return true;
        };
        if opened.theirs == 0 {
            opened.theirs = first;
            self.changed.notify_all();
            return true;
        }
        let theirs = opened.theirs;
        if matches!(opened.role, Role::Answering) {
            streams.open.remove(&second);
            return self.put(CLSE, second, theirs, &[]);
        }
        if let Some(data) = opened.queued.pop_front() {
            return self.put(WRTE, second, theirs, &data);
        }
        opened.waiting = false;
        true
    }

    fn closed(&self, second: u32) {
        if let Ok(mut streams) = self.streams.lock() {
            match streams.open.get_mut(&second) {
                Some(Opened {
                    role: Role::Reaching { closed, .. },
                    ..
                }) => *closed = true,
                _ => {
                    streams.open.remove(&second);
                }
            }
        }
        self.changed.notify_all();
    }

    /// The server's connection ended, and every stream with it.
    fn lost(&self) {
        if let Ok(mut streams) = self.streams.lock() {
            for opened in streams.open.values_mut() {
                if let Role::Reaching { closed, .. } = &mut opened.role {
                    *closed = true;
                }
            }
        }
        self.changed.notify_all();
    }

    /// What `found` makes of stream `ours` once it makes anything of it,
    /// waiting up to twenty seconds.
    fn until<T>(&self, ours: u32, found: impl Fn(&Opened) -> Option<T>) -> Option<T> {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut streams = self.streams.lock().ok()?;
        loop {
            if let Some(made) = streams.open.get(&ours).and_then(&found) {
                return Some(made);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            streams = self.changed.wait_timeout(streams, left).ok()?.0;
        }
    }
}

fn serve(
    mut stream: TcpStream,
    link: &Arc<Link>,
    banner: &str,
    opened: &Mutex<Vec<String>>,
    reverses: &Arc<Reverses>,
) {
    while let Ok((command, first, second, data)) = received(&mut stream) {
        let sent = match command {
            CNXN => link.put(CNXN, VERSION, MAX_PAYLOAD, banner.as_bytes()),
            OPEN => {
                let name = String::from_utf8_lossy(&data)
                    .trim_end_matches('\0')
                    .to_owned();
                if let Ok(mut opened) = opened.lock() {
                    opened.push(name.clone());
                }
                if name.starts_with("tcp:") {
                    let ours = link.open(first, Role::Echo);
                    link.put(OKAY, ours, first, &[])
                } else if name.starts_with("reverse:") {
                    reverses.note(&name);
                    let ours = link.open(first, Role::Answering);
                    let (link, reverses) = (Arc::clone(link), Arc::clone(reverses));
                    thread::spawn(move || {
                        reverses.wait_released();
                        let answer = reverses.answer(&name);
                        let _ = link.put(OKAY, ours, first, &[])
                            && link.put(WRTE, ours, first, &answer);
                    });
                    true
                } else {
                    link.put(CLSE, 0, first, &[])
                }
            }
            WRTE => link.wrote(first, second, &data),
            OKAY => link.okayed(first, second),
            CLSE => {
                link.closed(second);
                true
            }
            _ => true,
        };
        if !sent {
            break;
        }
    }
    link.lost();
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
