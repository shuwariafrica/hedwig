//! The keys a `GnuPG` source offers, read with its own tools, and the cards
//! its scdaemon holds, read through its agent.
//!
//! What its `gpg` lists as secret keys it can use, each with the keygrip the
//! agent knows it by and the card it is on; the public half of each,
//! armoured, for a remote's keyring; the key the person signs with, as their
//! own tools say; each key's public half as an SSH key, as the agent writes
//! it; and which key each card holds and what the card asks for before using
//! it. The readers of what the tools print are plain functions;
//! running the tools is the rest.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use hedwig_model::capability::{Access, Home};
use hedwig_model::text::{Fingerprint, Grip, Mark, Serial, SshKey, Words, base64, ssh_string};
use hedwig_model::trail::{Card, Failure, Held, Key, Keyring, SignaturePin, Touch, Uses};
use hedwig_win::process::UNSEEN;

use crate::assuan::LINE;
use crate::relay::{Agents, Gnupg, gpgconf, launch, listed, unescape};

/// What one read of a source found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Read {
    pub keyring: Keyring,
    /// Each key's public half, armoured, by its primary fingerprint.
    pub armoured: BTreeMap<Fingerprint, String>,
    /// The cards the source's scdaemon holds.
    pub cards: Vec<Card>,
}

/// The fields of one line of a colon listing.
fn fields(line: &[u8]) -> Vec<&[u8]> {
    line.split(|byte| *byte == b':').collect()
}

fn field<'a>(fields: &[&'a [u8]], number: usize) -> &'a [u8] {
    fields.get(number - 1).copied().unwrap_or_default()
}

fn text<'t, T: TryFrom<&'t str>>(bytes: &'t [u8]) -> Option<T> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| T::try_from(text).ok())
}

/// `\xNN` as a colon listing escapes a user ID (`DETAILS`, "Field 10").
fn unescape_user(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some((&byte, tail)) = rest.split_first() {
        let hex = tail
            .strip_prefix(b"x")
            .and_then(|tail| tail.get(..2))
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| u8::from_str_radix(digits, 16).ok());
        if let (b'\\', Some(value)) = (byte, hex) {
            out.push(value);
            rest = tail.get(3..).unwrap_or_default();
        } else {
            out.push(byte);
            rest = tail;
        }
    }
    out
}

/// A (sub)key being read: the line that opened it, waiting for its
/// fingerprint and keygrip.
struct Open {
    uses: Uses,
    usable: bool,
    primary: bool,
    fingerprint: Option<Fingerprint>,
    card: Option<Serial>,
}

/// The secret keys `gpg --list-secret-keys --with-colons --with-keygrip
/// --fixed-list-mode` lists that can be used: not revoked, expired, invalid
/// or disabled, and not a stub whose secret is elsewhere. A key on a card
/// carries the card's serial number in its fifteenth field (`DETAILS`).
pub fn listing(printed: &[u8]) -> Vec<Key> {
    let mut keys = Vec::new();
    let mut open: Option<Open> = None;
    let mut primary: Option<Fingerprint> = None;
    let mut user: Option<Words> = None;
    let mut first = keys.len();
    for line in printed.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let fields = fields(line);
        match field(&fields, 1) {
            kind @ (b"sec" | b"ssb") => {
                let validity = field(&fields, 2);
                let capabilities = field(&fields, 12);
                let serial = field(&fields, 15);
                let allows = capabilities
                    .iter()
                    .fold(Uses::NONE, |held, letter| match letter {
                        b's' => held.with(Uses::SIGN),
                        b'e' => held.with(Uses::ENCRYPT),
                        b'a' => held.with(Uses::AUTHENTICATE),
                        _ => held,
                    });
                let usable = !matches!(validity.first(), Some(b'r' | b'e' | b'i' | b'd'))
                    && !capabilities.contains(&b'D')
                    && serial != b"#";
                if kind == b"sec" {
                    primary = None;
                    user = None;
                    first = keys.len();
                }
                open = Some(Open {
                    uses: allows,
                    usable,
                    primary: kind == b"sec",
                    fingerprint: None,
                    card: text(serial),
                });
            }
            b"fpr" => {
                if let Some(open) = open.as_mut().filter(|open| open.fingerprint.is_none()) {
                    open.fingerprint = text(field(&fields, 10));
                    if open.primary {
                        primary.clone_from(&open.fingerprint);
                    }
                }
            }
            b"grp" => {
                let Some(taken) = open.take() else { continue };
                let (Some(grip), Some(fingerprint), Some(of)) =
                    (text(field(&fields, 10)), taken.fingerprint, primary.clone())
                else {
                    continue;
                };
                if taken.usable {
                    keys.push(Key {
                        grip,
                        fingerprint,
                        primary: of,
                        uses: taken.uses,
                        user: user.clone(),
                        card: taken.card,
                        ssh: None,
                    });
                }
            }
            b"uid" if user.is_none() && field(&fields, 2) != b"r" => {
                let named = unescape_user(field(&fields, 10));
                user = Words::try_from(String::from_utf8_lossy(&named).as_ref()).ok();
                // The primary key's line comes before its first user ID.
                for key in keys.iter_mut().skip(first) {
                    key.user.clone_from(&user);
                }
            }
            _ => {}
        }
    }
    keys
}

/// The key a tool's setting names, as `git` takes it back: a fingerprint,
/// a key ID or a user ID naming a key in `keys`, written as the fingerprint
/// it names, with `!` kept where the setting asked for that key exactly.
fn named(keys: &[&Key], setting: &str) -> Option<Mark> {
    let setting = setting.trim();
    let exact = setting.ends_with('!');
    let hex = setting
        .trim_end_matches('!')
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_uppercase();
    let is_hex =
        !hex.is_empty() && hex.len() >= 8 && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
    let found = keys.iter().find_map(|key| {
        if is_hex && key.fingerprint.as_str().ends_with(&hex) {
            let primary = key.fingerprint == key.primary;
            let text = if exact && !primary {
                format!("{}!", key.fingerprint)
            } else {
                key.primary.as_str().to_owned()
            };
            return Some(text);
        }
        let user = key.user.as_ref()?.as_str();
        let address = user
            .rsplit_once('<')
            .and_then(|(_, rest)| rest.strip_suffix('>'));
        (!is_hex && (user == setting || address == Some(setting.trim_matches(['<', '>']))))
            .then(|| key.primary.as_str().to_owned())
    })?;
    Mark::try_from(found.as_str()).ok()
}

/// The key the person signs with: what the workstation's `git` names, else
/// what `GnuPG`'s `default-key` names, where either names a key here; else
/// the one key here that signs, where all that sign belong to one. Never a
/// key picked from several.
pub fn signing(keys: &[Key], git: Option<&str>, default_key: Option<&str>) -> Option<Mark> {
    let signers: Vec<&Key> = keys.iter().filter(|key| key.uses.has(Uses::SIGN)).collect();
    let stated = [git, default_key]
        .into_iter()
        .flatten()
        .find_map(|setting| named(&signers, setting));
    if stated.is_some() {
        return stated;
    }
    let mut primaries = signers.iter().map(|key| &key.primary);
    let only = primaries.next()?;
    primaries
        .all(|other| other == only)
        .then(|| Mark::try_from(only.as_str()).ok())
        .flatten()
}

/// What `gpgconf --list-options gpg` says of `default-key` and of
/// `use-keyboxd`.
pub fn options(printed: &[u8]) -> (Option<String>, bool) {
    let mut default_key = None;
    let mut keyboxd = false;
    for line in printed.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let fields = fields(line);
        let value = field(&fields, 10);
        match field(&fields, 1) {
            b"default-key" if !value.is_empty() => {
                let value = unescape(value.strip_prefix(b"\"").unwrap_or(value));
                default_key = Some(String::from_utf8_lossy(&value).into_owned());
            }
            b"use_keyboxd" | b"use-keyboxd" => keyboxd = value == b"1",
            _ => {}
        }
    }
    (default_key, keyboxd)
}

fn home(home: &Home) -> Vec<OsString> {
    match home {
        Home::Default => Vec::new(),
        Home::At(folder) => vec!["--homedir".into(), folder.as_str().into()],
    }
}

fn printed(program: &Path, arguments: &[OsString]) -> Result<Vec<u8>, Failure> {
    let mut started =
        hedwig_win::start::apart(program, arguments, UNSEEN).map_err(|_| Failure::Unresolved)?;
    let mut said = Vec::new();
    (&mut started.said)
        .take(hedwig_model::wire::FRAME as u64)
        .read_to_end(&mut said)
        .map_err(|_| Failure::Unresolved)?;
    match started.wait() {
        Ok(0) => Ok(said),
        _ => Err(Failure::Unreachable),
    }
}

/// The workstation's `git`, found on `search` as a channel's client is.
fn git_signing(search: &std::ffi::OsStr) -> Option<String> {
    let git = hedwig_win::search::program_on("git", search).ok()?;
    let arguments: Vec<OsString> = ["config", "--global", "--get", "user.signingkey"]
        .into_iter()
        .map(OsString::from)
        .collect();
    let said = printed(&git, &arguments).ok()?;
    let text = String::from_utf8_lossy(&said).trim().to_owned();
    (!text.is_empty()).then_some(text)
}

/// What one of scdaemon's status lines carries, as `send_status_info`
/// escapes it: `%XX` for a byte, `+` for a blank.
fn status_value(value: &[u8]) -> Vec<u8> {
    let blanks: Vec<u8> = value
        .iter()
        .map(|byte| if *byte == b'+' { b' ' } else { *byte })
        .collect();
    unescape(&blanks)
}

/// Each key `SCD KEYINFO --list` names on a card scdaemon holds, with its
/// card and, for an `OpenPGP` application's key, the slot it is in:
/// `KEYINFO <keygrip> T <serial> <idstr> <usage>`, `idstr` `OPENPGP.<n>`.
pub fn on_cards(status: &[Vec<u8>]) -> Vec<(Grip, Serial, Option<usize>)> {
    status
        .iter()
        .filter_map(|line| {
            let mut words = line.split(|byte| *byte == b' ');
            if words.next()? != b"KEYINFO" {
                return None;
            }
            let grip = text(words.next()?)?;
            if words.next()? != b"T" {
                return None;
            }
            let serial = text(words.next()?)?;
            let slot = words
                .next()
                .and_then(|id| id.strip_prefix(b"OPENPGP."))
                .and_then(|n| std::str::from_utf8(n).ok())
                .and_then(|n| n.parse::<usize>().ok())
                .filter(|n| (1..=3).contains(n));
            Some((grip, serial, slot))
        })
        .collect()
}

/// The value of the status line `keyword` among `status`.
fn said<'s>(status: &'s [Vec<u8>], keyword: &[u8]) -> Option<&'s [u8]> {
    status.iter().find_map(|line| {
        line.strip_prefix(keyword)
            .and_then(|rest| rest.strip_prefix(b" "))
    })
}

/// Whether `EXTCAP` says the card has a button to touch (`bt=`).
pub fn button(status: &[Vec<u8>]) -> Option<bool> {
    let value = status_value(said(status, b"EXTCAP")?);
    value
        .split(|byte| *byte == b' ')
        .find_map(|pair| pair.strip_prefix(b"bt="))
        .and_then(|flag| match flag {
            b"1" => Some(true),
            b"0" => Some(false),
            _ => None,
        })
}

/// What `UIF-<slot>` says the card asks for before that slot's key is used:
/// the flag's first byte, as `GnuPG`'s `gpg-card` reads it, with the two values
/// a `YubiKey` adds for a touch that is then cached.
pub fn touch(status: &[Vec<u8>], slot: usize) -> Option<Touch> {
    let keyword = format!("UIF-{slot}");
    match status_value(said(status, keyword.as_bytes())?).first()? {
        0x00 | 0xff => Some(Touch::Off),
        0x01 | 0x02 => Some(Touch::On),
        0x03 | 0x04 => Some(Touch::Cached),
        _ => None,
    }
}

/// Whether `CHV-STATUS` says the signature PIN is asked for at every
/// signature: its first number is 1 where one entry serves several.
pub fn pin(status: &[Vec<u8>]) -> Option<SignaturePin> {
    let value = status_value(said(status, b"CHV-STATUS")?);
    let first = value
        .split(|byte| *byte == b' ')
        .find(|word| !word.is_empty())?;
    match first {
        b"1" => Some(SignaturePin::Once),
        b"0" => Some(SignaturePin::Forced),
        _ => None,
    }
}

/// What the card scdaemon reaches first said of itself: its serial number,
/// and, where its first application is `OpenPGP`'s, the touch of each slot
/// and the signature PIN.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct First {
    pub serial: Option<Serial>,
    pub touches: [Option<Touch>; 3],
    pub pin: Option<SignaturePin>,
}

/// The cards, each with the keys on it, from what `SCD KEYINFO --list` named
/// and what the first card said; a key on any other card is read as one whose
/// touch the card did not say.
pub fn cards(listed: &[(Grip, Serial, Option<usize>)], first: &First) -> Vec<Card> {
    let mut cards: Vec<Card> = Vec::new();
    for (grip, serial, slot) in listed {
        let is_first = first.serial.as_ref() == Some(serial);
        let touch = slot
            .filter(|_| is_first)
            .and_then(|slot| first.touches.get(slot - 1).copied().flatten());
        let held = Held {
            grip: grip.clone(),
            touch,
        };
        match cards.iter_mut().find(|card| card.serial == *serial) {
            Some(card) => card.keys.push(held),
            None => cards.push(Card {
                serial: serial.clone(),
                keys: vec![held],
                pin: first.pin.filter(|_| is_first),
            }),
        }
    }
    cards
}

/// How one command to the agent ended: its status lines, or its `ERR`.
type Answered = Result<Vec<Vec<u8>>, Vec<u8>>;

/// The most status lines one answer may carry: more keys than any card holds,
/// with every application's.
const STATUS: usize = 64;

/// Sends `command` and reads the agent's answer to it.
fn ask(agent: &mut TcpStream, command: &[u8]) -> Result<Answered, Failure> {
    let mut line = command.to_vec();
    line.push(b'\n');
    agent.write_all(&line).map_err(|_| Failure::Unreachable)?;
    let mut status = Vec::new();
    loop {
        let read = read_line(agent)?;
        let read = read.strip_suffix(b"\r").unwrap_or(&read);
        if read == b"OK" || read.starts_with(b"OK ") {
            return Ok(Ok(status));
        }
        if let Some(code) = read.strip_prefix(b"ERR ") {
            return Ok(Err(code.to_vec()));
        }
        if let Some(said) = read.strip_prefix(b"S ") {
            if status.len() == STATUS {
                return Err(Failure::Mismatched);
            }
            status.push(said.to_vec());
        } else if read.starts_with(b"INQUIRE") {
            // Nothing read here asks for anything; refuse what does.
            agent
                .write_all(b"CAN\n")
                .map_err(|_| Failure::Unreachable)?;
        }
    }
}

/// One line from the agent, without its line feed, cut where libassuan cuts
/// one.
fn read_line(agent: &mut TcpStream) -> Result<Vec<u8>, Failure> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match agent.read(&mut byte) {
            Ok(1) if byte == *b"\n" => return Ok(line),
            Ok(1) if line.len() < LINE => line.extend_from_slice(&byte),
            _ => return Err(Failure::Unreachable),
        }
    }
}

/// The most data one answer may carry: an RSA key of 16384 bits written as
/// OpenSSH writes it, with room.
const DATA: usize = 8 * 1024;

/// The public half `READKEY --format=ssh` answers with, as OpenSSH writes it:
/// a key type and its blob, then a comment, which is dropped.
pub fn ssh_form(data: &[u8]) -> Option<SshKey> {
    let text = std::str::from_utf8(data).ok()?;
    let mut words = text.split_ascii_whitespace();
    let (kind, encoded) = (words.next()?, words.next()?);
    let blob = base64(encoded)?;
    SshKey::from_blob(&ecdsa_curve_named(kind, &blob)?)
}

/// An ECDSA blob with its curve named as its key type names it, `nistp256`
/// for `ecdsa-sha2-nistp256` (RFC 5656 section 3.1), as OpenSSH and
/// gpg-agent's own SSH socket write it; any other blob as it is, its type
/// checked. `GnuPG` 2.5.24's `READKEY --format=ssh` writes libgcrypt's name,
/// `NIST P-256`, there instead (`common/ssh-utils.c:575-577,486-489`,
/// unchanged at master `82d5dc7`): this goes when a `GnuPG` that writes the
/// SSH name is the one in force.
fn ecdsa_curve_named(kind: &str, blob: &[u8]) -> Option<Vec<u8>> {
    let (named, rest) = ssh_string(blob)?;
    if named != kind.as_bytes() {
        return None;
    }
    let Some(curve) = kind.strip_prefix("ecdsa-sha2-") else {
        return Some(blob.to_vec());
    };
    let (_written, point) = ssh_string(rest)?;
    let mut fixed = Vec::with_capacity(blob.len());
    for field in [kind.as_bytes(), curve.as_bytes()] {
        fixed.extend_from_slice(&u32::try_from(field.len()).ok()?.to_be_bytes());
        fixed.extend_from_slice(field);
    }
    fixed.extend_from_slice(point);
    Some(fixed)
}

/// Sends `command` and reads the data the agent answers with, unescaped, or
/// the error it answers.
fn ask_data(agent: &mut TcpStream, command: &[u8]) -> Result<Result<Vec<u8>, Vec<u8>>, Failure> {
    let mut line = command.to_vec();
    line.push(b'\n');
    agent.write_all(&line).map_err(|_| Failure::Unreachable)?;
    let mut data = Vec::new();
    loop {
        let read = read_line(agent)?;
        let read = read.strip_suffix(b"\r").unwrap_or(&read);
        if read == b"OK" || read.starts_with(b"OK ") {
            return Ok(Ok(data));
        }
        if let Some(code) = read.strip_prefix(b"ERR ") {
            return Ok(Err(code.to_vec()));
        }
        if let Some(said) = read.strip_prefix(b"D ") {
            data.extend(unescape(said));
            if data.len() > DATA {
                return Err(Failure::Mismatched);
            }
        } else if read.starts_with(b"INQUIRE") {
            agent
                .write_all(b"CAN\n")
                .map_err(|_| Failure::Unreachable)?;
        }
    }
}

/// Each key's public half as an SSH key, asked of the agent on its own
/// socket, the one `READKEY` is not refused on: the agent reads it from the
/// key's own file, a card's stub included, and asks nothing of a card. A key
/// SSH has no form for is answered with an error and keeps none.
///
/// # Errors
///
/// The agent not answering.
pub fn read_ssh(agents: &Agents, source: &Gnupg, keys: &mut [Key]) -> Result<(), Failure> {
    let standard = Gnupg {
        access: Access::Unrestricted,
        ..source.clone()
    };
    let (mut agent, _) = agents.reach(&standard).result?;
    agent
        .set_read_timeout(Some(crate::PATIENCE))
        .map_err(|_| Failure::Unreachable)?;
    for key in keys.iter_mut() {
        let command = format!("READKEY --format=ssh {}", key.grip);
        if let Ok(data) = ask_data(&mut agent, command.as_bytes())? {
            key.ssh = ssh_form(&data);
        }
    }
    Ok(())
}

/// The commands a card read sends, each read-only and none naming a card, an
/// application or a key: `KEYINFO --list` walks only the cards scdaemon
/// already holds and selects each one's first application again after it; a
/// `GETATTR` without a keygrip reaches the card scdaemon reaches first, in the
/// application it has selected.
pub const KEYINFO: &[u8] = b"SCD KEYINFO --list";
pub const SERIALNO: &[u8] = b"SCD GETATTR SERIALNO";
pub const APPTYPE: &[u8] = b"SCD GETATTR APPTYPE";
pub const EXTCAP: &[u8] = b"SCD GETATTR EXTCAP";
pub const UIF: &[u8] = b"SCD GETATTR UIF";
pub const CHV_STATUS: &[u8] = b"SCD GETATTR CHV-STATUS";

/// Reads the cards `source`'s scdaemon holds through the agent's own socket,
/// which is the one `SCD GETATTR` is not refused on. Nothing is asked of a
/// card scdaemon does not hold already, so nothing is opened; nothing names
/// a card or an application, so nothing is switched.
///
/// # Errors
///
/// The agent not answering. A card that says nothing is not an error: it is
/// read as one whose safeguards are not known.
pub fn read_cards(agents: &Agents, source: &Gnupg) -> Result<Vec<Card>, Failure> {
    let standard = Gnupg {
        access: Access::Unrestricted,
        ..source.clone()
    };
    let (mut agent, _) = agents.reach(&standard).result?;
    agent
        .set_read_timeout(Some(crate::PATIENCE))
        .map_err(|_| Failure::Unreachable)?;
    let Ok(listed) = ask(&mut agent, KEYINFO)? else {
        return Ok(Vec::new());
    };
    let listed = on_cards(&listed);
    if listed.is_empty() {
        return Ok(Vec::new());
    }
    let mut first = First::default();
    if let Ok(serial) = ask(&mut agent, SERIALNO)? {
        first.serial = said(&serial, b"SERIALNO").and_then(text);
    }
    let openpgp = matches!(
        ask(&mut agent, APPTYPE)?,
        Ok(status) if said(&status, b"APPTYPE") == Some(b"openpgp".as_slice())
    );
    if openpgp {
        let touches = match ask(&mut agent, EXTCAP)? {
            Ok(extcap) if button(&extcap) == Some(false) => [Some(Touch::Off); 3],
            Ok(extcap) if button(&extcap) == Some(true) => match ask(&mut agent, UIF)? {
                Ok(uif) => [touch(&uif, 1), touch(&uif, 2), touch(&uif, 3)],
                Err(_) => [None; 3],
            },
            _ => [None; 3],
        };
        first.touches = touches;
        if let Ok(chv) = ask(&mut agent, CHV_STATUS)? {
            first.pin = pin(&chv);
        }
    } else {
        first.serial = None;
    }
    Ok(cards(&listed, &first))
}

/// Reads what `source` offers. `gpg` lists secret keys through the agent and
/// is told never to start one itself: where none answers, the agent, and
/// `keyboxd` where its `gpg` uses one, are started as [`launch`] starts them.
///
/// # Errors
///
/// The failure of the source's own tools.
pub fn read(agents: &Agents, source: &Gnupg, search: &std::ffi::OsStr) -> Result<Read, Failure> {
    let gpgconf = gpgconf(&source.installation)?;
    let mut dirs = home(&source.home);
    dirs.push("--list-dirs".into());
    let bin = listed(&printed(&gpgconf, &dirs)?, "bindir").ok_or(Failure::Unresolved)?;
    // A POSIX-emulated `GnuPG` answers with a POSIX path, and is never started.
    if bin.first() == Some(&b'/') {
        return Err(Failure::Unserved);
    }
    let gpg = PathBuf::from(String::from_utf8_lossy(&bin).as_ref()).join("gpg.exe");
    let mut asked = home(&source.home);
    asked.extend(["--list-options".into(), "gpg".into()]);
    let (default_key, keyboxd) = options(&printed(&gpgconf, &asked)?);
    let mut list = home(&source.home);
    list.extend(
        [
            "--no-autostart",
            "--batch",
            "--with-colons",
            "--with-keygrip",
            "--fixed-list-mode",
            "--list-secret-keys",
        ]
        .map(OsString::from),
    );
    // The agent is started only where it does not answer already.
    let listed = if let Ok(listed) = printed(&gpg, &list) {
        listed
    } else {
        launch(&gpgconf, &source.home, keyboxd).map_err(|_| Failure::Unreachable)?;
        printed(&gpg, &list)?
    };
    let mut keys = listing(&listed);
    // A key whose SSH form could not be read is offered all the same, named
    // by its keygrip and fingerprints alone.
    let _ = read_ssh(agents, source, &mut keys);
    let git = git_signing(search);
    let signing = signing(&keys, git.as_deref(), default_key.as_deref());
    let keyring = Keyring { keys, signing };
    let mut armoured = BTreeMap::new();
    for primary in keyring.primaries() {
        let mut export = home(&source.home);
        export.extend(["--no-autostart", "--batch", "--armor", "--export"].map(OsString::from));
        export.push(primary.as_str().into());
        let block = printed(&gpg, &export)?;
        armoured.insert(primary, String::from_utf8_lossy(&block).into_owned());
    }
    // The cards are read once the listing has started the agent; a card read
    // that fails leaves every card's safeguards unknown, never the keys unread.
    let cards = read_cards(agents, source).unwrap_or_default();
    Ok(Read {
        keyring,
        armoured,
        cards,
    })
}
