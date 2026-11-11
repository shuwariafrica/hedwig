//! A stand-in for scdaemon 2.5.24 holding one card of one or two
//! applications, whose handling of the signature PIN follows scdaemon's own,
//! which a scratch home's `gpg-agent.conf` names as its `scdaemon-program`:
//!
//! - the card is registered with its first application, `OpenPGP`, and
//!   `SERIALNO --all` adds the others it holds and, where it added one,
//!   selects the first again (`scd/app.c:102-112`, `:1198-1270`);
//! - `KEYINFO <keygrip>`, `KEYINFO --list` and `PKSIGN <keygrip>` on a card of
//!   more than one application select each application in turn, a full walk
//!   the first again after it (`app.c:1377-1430`, `command.c:1096`);
//! - selecting `OpenPGP` forgets its verified PIN (`app-openpgp.c:6551-6578`);
//! - `GETINFO card_list` and a `GETATTR` select nothing (`app.c:2791-2841`,
//!   `:1818-1915`), no other program sharing the card;
//! - a signature verifies the PIN where it is not verified: from the agent's
//!   cache by `INQUIRE PINCACHE_GET` where one was cached, else by
//!   `INQUIRE NEEDPIN`, put to the person through the agent's pinentry; a PIN
//!   verified is cached with `S PINCACHE_PUT` (`app-openpgp.c:2649-2895`).
//!   scdaemon caches a PIN only for a `YubiKey` without `pcsc-shared`
//!   (`app-openpgp.c:2654-2664`): `HEDWIG_CARD_CACHE=none` is every other
//!   case.
//!
//! `HEDWIG_CARD_STATE` names a file of one line
//! `<serial> <fingerprint> <home> <socket>`: a `GnuPG` home holding the card's
//! RSA key, whose agent signs for it, and that agent's socket file.
//! `HEDWIG_CARD_APPS` is `openpgp` or `openpgp piv`. Every command is appended
//! to `HEDWIG_CARD_LOG`, with `# ` lines saying what was selected and how the
//! PIN was verified.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;

/// `GnuPG`'s error source for scdaemon, shifted as libgpg-error shifts it.
const SCD: u32 = 6 << 24;
const NOT_FOUND: u32 = 27;
const BAD_PIN: u32 = 87;
const CANCELLED: u32 = 99;
const CARD_NOT_PRESENT: u32 = 112;
/// `GPG_ERR_ENODEV`: `GPG_ERR_SYSTEM_ERROR` with `ENODEV`'s index.
const NO_DEVICE: u32 = (1 << 15) | 0x50;
const UNKNOWN_COMMAND: u32 = 275;
/// The DER prefix of a SHA-256 `DigestInfo`, which the agent sends a card.
const SHA256_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const PIN: &str = "123456";
const PIV_GRIP: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

#[derive(Clone, Copy, PartialEq, Eq)]
enum App {
    Openpgp,
    Piv,
}

impl App {
    fn name(self) -> &'static str {
        match self {
            Self::Openpgp => "openpgp",
            Self::Piv => "piv",
        }
    }
}

struct Card {
    serial: String,
    fpr: String,
    home: String,
    socket: String,
}

struct Daemon<R, W> {
    input: R,
    out: W,
    card: Option<Card>,
    holds: Vec<App>,
    /// The applications registered, the first the card's current one.
    apps: Vec<App>,
    verified: bool,
    cached: bool,
    caches: bool,
    data: Vec<u8>,
    log: Option<std::fs::File>,
}

fn main() -> ExitCode {
    let log = std::env::var_os("HEDWIG_CARD_LOG")
        .and_then(|path| OpenOptions::new().create(true).append(true).open(path).ok());
    let holds = std::env::var("HEDWIG_CARD_APPS")
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|name| match name {
            "openpgp" => Some(App::Openpgp),
            "piv" => Some(App::Piv),
            _ => None,
        })
        .collect();
    let caches = std::env::var("HEDWIG_CARD_CACHE").as_deref() != Ok("none");
    let stdin = io::stdin();
    let mut daemon = Daemon {
        input: stdin.lock(),
        out: io::stdout().lock(),
        card: None,
        holds,
        apps: Vec::new(),
        verified: false,
        cached: false,
        caches,
        data: Vec::new(),
        log,
    };
    if daemon.say(&["OK stand-in scdaemon".to_owned()]).is_err() {
        return ExitCode::FAILURE;
    }
    loop {
        let mut line = String::new();
        match daemon.input.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let command = line.trim_end_matches(['\r', '\n']).to_owned();
        daemon.note(&command);
        let answer = daemon.answer(&command);
        if daemon.say(&answer).is_err() || command == "BYE" {
            break;
        }
    }
    ExitCode::SUCCESS
}

fn err(code: u32, words: &str) -> Vec<String> {
    vec![format!("ERR {} {words} <SCD>", SCD | code)]
}

fn inserted() -> Option<Card> {
    let path = std::env::var_os("HEDWIG_CARD_STATE")?;
    let text = std::fs::read_to_string(path).ok()?;
    let mut words = text.split_whitespace();
    Some(Card {
        serial: words.next()?.to_owned(),
        fpr: words.next()?.to_owned(),
        home: words.next()?.to_owned(),
        socket: words.next()?.to_owned(),
    })
}

impl<R: BufRead, W: Write> Daemon<R, W> {
    fn note(&mut self, text: &str) {
        if let Some(log) = self.log.as_mut() {
            let _ = writeln!(log, "{text}");
        }
    }

    fn say(&mut self, lines: &[String]) -> io::Result<()> {
        for line in lines {
            writeln!(self.out, "{line}")?;
        }
        self.out.flush()
    }

    /// Asks the agent `inquiry` and reads its data to `END`; `None` where it
    /// cancels.
    fn inquire(&mut self, inquiry: &str) -> Option<Vec<u8>> {
        self.say(&[format!("INQUIRE {inquiry}")]).ok()?;
        let mut data = Vec::new();
        loop {
            let mut line = String::new();
            if self.input.read_line(&mut line).ok()? == 0 {
                return None;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if let Some(chunk) = line.strip_prefix("D ") {
                data.extend(unescape(chunk.as_bytes()));
            } else if line == "END" {
                return Some(data);
            } else if line == "CAN" {
                return None;
            }
        }
    }

    fn select(&mut self, app: App) {
        self.note(&format!("# selected {}", app.name()));
        if app == App::Openpgp {
            self.verified = false;
        }
    }

    /// Registers the inserted card, as a scan does, where none is held.
    fn register(&mut self) -> bool {
        if self.card.is_none() {
            let Some(card) = inserted() else { return false };
            if !self.holds.contains(&App::Openpgp) {
                return false;
            }
            self.note(&format!("# registered {}", card.serial));
            self.card = Some(card);
            self.apps = vec![App::Openpgp];
            self.select(App::Openpgp);
        }
        true
    }

    fn add_all(&mut self) {
        let mut any_new = false;
        for app in self.holds.clone() {
            if !self.apps.contains(&app) {
                self.select(app);
                self.apps.push(app);
                any_new = true;
            }
        }
        if any_new && let Some(first) = self.apps.first().copied() {
            self.select(first);
        }
    }

    fn answer(&mut self, command: &str) -> Vec<String> {
        let (verb, rest) = command.split_once(' ').unwrap_or((command, ""));
        match verb {
            "OPTION" | "RESTART" | "BYE" | "NOP" => vec!["OK".to_owned()],
            "SERIALNO" => {
                if !self.register() {
                    return err(NO_DEVICE, "No such device");
                }
                if rest.split_whitespace().any(|word| word == "--all") {
                    self.add_all();
                }
                vec![format!("S SERIALNO {}", self.serial()), "OK".to_owned()]
            }
            "GETINFO" if rest == "card_list" => match &self.card {
                Some(card) => vec![format!("S SERIALNO {}", card.serial), "OK".to_owned()],
                None => err(CARD_NOT_PRESENT, "Card not present"),
            },
            "KEYINFO" => self.keyinfo(rest),
            "GETATTR" => self.getattr(rest),
            "LEARN" => self.learn(),
            "READKEY" => self.readkey(rest),
            "SETDATA" => {
                let (append, hex) = match rest.strip_prefix("--append ") {
                    Some(hex) => (true, hex),
                    None => (false, rest),
                };
                if !append {
                    self.data.clear();
                }
                self.data.extend(unhex(hex));
                vec!["OK".to_owned()]
            }
            "PKSIGN" => self.pksign(rest),
            _ => err(UNKNOWN_COMMAND, "Unknown IPC command"),
        }
    }

    fn serial(&self) -> String {
        self.card
            .as_ref()
            .map(|card| card.serial.clone())
            .unwrap_or_default()
    }

    fn grip(&self) -> Option<String> {
        self.card.as_ref().and_then(key_grip)
    }

    fn line_for(&self, app: App) -> Option<String> {
        let serial = self.serial();
        match app {
            App::Openpgp => self
                .grip()
                .map(|grip| format!("S KEYINFO {grip} T {serial} OPENPGP.1 sc")),
            App::Piv => Some(format!("S KEYINFO {PIV_GRIP} T {serial} PIV.9A a")),
        }
    }

    /// A lookup walks only the cards scdaemon holds, never scanning for one
    /// (`app.c:1386`).
    fn keyinfo(&mut self, rest: &str) -> Vec<String> {
        let wanted = (!rest.starts_with("--list")).then(|| rest.trim().to_ascii_uppercase());
        if self.card.is_none() {
            return match wanted {
                Some(_) => err(NOT_FOUND, "Not found"),
                None => vec!["OK".to_owned()],
            };
        }
        let several = self.apps.len() > 1;
        let mut said = Vec::new();
        for app in self.apps.clone() {
            if several {
                self.select(app);
            }
            let Some(line) = self.line_for(app) else {
                continue;
            };
            match &wanted {
                Some(grip) if line.split(' ').nth(2) == Some(grip.as_str()) => {
                    return vec![line, "OK".to_owned()];
                }
                Some(_) => {}
                None => said.push(line),
            }
        }
        if several && let Some(first) = self.apps.first().copied() {
            self.select(first);
        }
        if wanted.is_some() {
            return err(NOT_FOUND, "Not found");
        }
        said.push("OK".to_owned());
        said
    }

    fn getattr(&mut self, rest: &str) -> Vec<String> {
        if !self.register() {
            return err(NO_DEVICE, "No such device");
        }
        let Some(card) = self.card.as_ref() else {
            return err(NO_DEVICE, "No such device");
        };
        let mut said = match rest.split_whitespace().next().unwrap_or_default() {
            "SERIALNO" => vec![format!("S SERIALNO {}", card.serial)],
            "APPTYPE" => vec!["S APPTYPE openpgp".to_owned()],
            "KEY-FPR" => vec![format!("S KEY-FPR 1 {}", card.fpr)],
            "EXTCAP" => vec![
                "S EXTCAP gc=1+ki=1+fc=1+pd=1+mcl3=2048+aac=1+sm=0+si=5+dec=1+bt=1+kdf=1"
                    .to_owned(),
            ],
            "UIF" => vec![
                "S UIF-1 %00+".to_owned(),
                "S UIF-2 %00+".to_owned(),
                "S UIF-3 %00+".to_owned(),
            ],
            "CHV-STATUS" => vec!["S CHV-STATUS +1+127+127+127+3+0+3".to_owned()],
            _ => return err(NOT_FOUND, "Not found"),
        };
        said.push("OK".to_owned());
        said
    }

    fn learn(&mut self) -> Vec<String> {
        if !self.register() {
            return err(NO_DEVICE, "No such device");
        }
        let mut said = vec![
            format!("S SERIALNO {}", self.serial()),
            "S APPTYPE openpgp".to_owned(),
        ];
        if let Some(grip) = self.grip() {
            said.push(format!("S KEYPAIRINFO {grip} OPENPGP.1 sc 0 rsa2048"));
        }
        said.push("OK".to_owned());
        said
    }

    fn readkey(&mut self, rest: &str) -> Vec<String> {
        if !self.register() {
            return err(NO_DEVICE, "No such device");
        }
        let (Some(card), Some(grip)) = (self.card.as_ref(), self.grip()) else {
            return err(NOT_FOUND, "Not found");
        };
        match ask(&card.socket, &[format!("READKEY {grip}")]) {
            Ok(data) => {
                let mut said = Vec::new();
                if rest.contains("--info") {
                    said.push(format!("S KEYPAIRINFO {grip} OPENPGP.1 sc 0 rsa2048"));
                }
                said.extend(data_lines(&data));
                said.push("OK".to_owned());
                said
            }
            Err(error) => err(NOT_FOUND, &error),
        }
    }

    /// `verify_a_chv` for the signature PIN, and the status that caches it.
    fn verify(&mut self) -> Result<Vec<String>, Vec<String>> {
        let mut pin = None;
        if self.caches && self.cached {
            pin = self
                .inquire("PINCACHE_GET 0/openpgp/1")
                .filter(|data| !data.is_empty())
                .and_then(|data| String::from_utf8(unhex(&String::from_utf8_lossy(&data))).ok());
            if pin.is_some() {
                self.note("# PIN from the agent's cache");
            }
        }
        let pin = if let Some(pin) = pin {
            pin
        } else {
            self.note("# PIN asked");
            let Some(asked) = self.inquire("NEEDPIN ||Please unlock the card") else {
                return Err(err(CANCELLED, "Operation cancelled"));
            };
            String::from_utf8_lossy(&asked)
                .trim_end_matches('\0')
                .to_owned()
        };
        if pin != PIN {
            return Err(err(BAD_PIN, "Bad PIN"));
        }
        self.verified = true;
        let mut status = Vec::new();
        if self.caches {
            self.cached = true;
            status.push(format!(
                "S PINCACHE_PUT 0/openpgp/1 {}",
                hex(pin.as_bytes())
            ));
        }
        Ok(status)
    }

    fn pksign(&mut self, rest: &str) -> Vec<String> {
        if !self.register() {
            return err(NO_DEVICE, "No such device");
        }
        let grip = rest
            .rsplit(' ')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if self.grip().as_deref() != Some(grip.as_str()) {
            return err(NOT_FOUND, "Not found");
        }
        // scdaemon finds the card by the keygrip as a lookup does, selecting
        // each application up to the one holding the key (`command.c:1096`).
        if self.apps.len() > 1 {
            self.select(App::Openpgp);
        }
        let mut said = Vec::new();
        if !self.verified {
            match self.verify() {
                Ok(status) => said.extend(status),
                Err(refused) => return refused,
            }
        }
        let Some(card) = self.card.as_ref() else {
            return err(NO_DEVICE, "No such device");
        };
        let Some(hash) = self.data.strip_prefix(SHA256_INFO.as_slice()) else {
            return err(NOT_FOUND, "Not a SHA-256 DigestInfo");
        };
        let asked = [
            format!("SIGKEY {grip}"),
            format!("SETHASH --hash=sha256 {}", hex(hash)),
            "PKSIGN".to_owned(),
        ];
        match ask(&card.socket, &asked).map(|sexp| rsa_s(&sexp)) {
            Ok(Some(mut s)) => {
                while s.len() < 256 {
                    s.insert(0, 0);
                }
                said.extend(data_lines(&s));
                said.push("OK".to_owned());
                said
            }
            Ok(None) => err(NOT_FOUND, "No RSA signature"),
            Err(error) => err(NOT_FOUND, &error),
        }
    }
}

/// The keygrip of the key the card's home holds: the one file of its
/// `private-keys-v1.d`.
fn key_grip(card: &Card) -> Option<String> {
    let keys = std::path::Path::new(&card.home).join("private-keys-v1.d");
    std::fs::read_dir(keys).ok()?.find_map(|entry| {
        let name = entry.ok()?.file_name().into_string().ok()?;
        name.strip_suffix(".key").map(str::to_ascii_uppercase)
    })
}

/// Sends `commands` to the agent whose socket file is `socket` and returns
/// the data the last one answered with.
fn ask(socket: &str, commands: &[String]) -> Result<Vec<u8>, String> {
    let file = std::fs::read(socket).map_err(|error| format!("socket file: {error}"))?;
    let newline = file
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("socket file form")?;
    let port: u16 = std::str::from_utf8(file.get(..newline).ok_or("socket file form")?)
        .map_err(|_| "socket file port")?
        .trim()
        .parse()
        .map_err(|_| "socket file port")?;
    let nonce = file
        .get(newline + 1..newline + 17)
        .ok_or("socket file nonce")?;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
    stream.write_all(nonce).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);
    let mut greeting = String::new();
    reader
        .read_line(&mut greeting)
        .map_err(|error| error.to_string())?;
    let mut data = Vec::new();
    for command in commands {
        stream
            .write_all(format!("{command}\n").as_bytes())
            .map_err(|error| error.to_string())?;
        data.clear();
        loop {
            let mut line = Vec::new();
            reader
                .read_until(b'\n', &mut line)
                .map_err(|error| error.to_string())?;
            if line.is_empty() {
                return Err("agent closed".to_owned());
            }
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if let Some(chunk) = line.strip_prefix(b"D ") {
                data.extend(unescape(chunk));
            } else if line.starts_with(b"OK") {
                break;
            } else if line.starts_with(b"ERR") {
                return Err(String::from_utf8_lossy(&line).into_owned());
            }
        }
    }
    let _ = stream.write_all(b"BYE\n");
    let mut rest = Vec::new();
    let _ = reader.read_to_end(&mut rest);
    Ok(data)
}

/// The `s` of `(7:sig-val(3:rsa(1:s<n>:<bytes>)))`.
fn rsa_s(sexp: &[u8]) -> Option<Vec<u8>> {
    let at = sexp.windows(4).position(|window| window == b"(1:s")? + 4;
    let rest = sexp.get(at..)?;
    let colon = rest.iter().position(|byte| *byte == b':')?;
    let length: usize = std::str::from_utf8(rest.get(..colon)?).ok()?.parse().ok()?;
    rest.get(colon + 1..colon + 1 + length).map(<[u8]>::to_vec)
}

/// Data as Assuan `D` lines, each well within a line's 1,000 bytes, every byte
/// that is not printable ASCII escaped.
fn data_lines(data: &[u8]) -> Vec<String> {
    data.chunks(300)
        .map(|chunk| {
            let mut line = String::from("D ");
            for byte in chunk {
                match byte {
                    b' '..=b'~' if *byte != b'%' => line.push(char::from(*byte)),
                    _ => {
                        line.push('%');
                        line.push_str(&hex(&[*byte]));
                    }
                }
            }
            line
        })
        .collect()
}

fn unescape(chunk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunk.len());
    let mut at = 0;
    while let Some(byte) = chunk.get(at) {
        if *byte == b'%'
            && let Some(pair) = chunk.get(at + 1..at + 3)
            && let Ok(text) = std::str::from_utf8(pair)
            && let Ok(value) = u8::from_str_radix(text, 16)
        {
            out.push(value);
            at += 3;
        } else {
            out.push(*byte);
            at += 1;
        }
    }
    out
}

fn unhex(text: &str) -> Vec<u8> {
    text.trim()
        .as_bytes()
        .chunks(2)
        .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02X}");
        text
    })
}
