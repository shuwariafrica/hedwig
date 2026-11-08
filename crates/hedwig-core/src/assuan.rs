//! The Assuan conversation between a remote's client and gpg-agent, as the
//! relay carries it.
//!
//! The relay reads every line in both directions and keeps the two ends to
//! Assuan's turns: the client speaks only when nothing is outstanding or when
//! the agent has asked it for data, and the agent only when a command is with
//! it. A line is cut where libassuan cuts it and a command is named as its
//! dispatcher names it, so a line the agent would run as `PKSIGN` or
//! `PKDECRYPT` is the line the relay holds for a decision; no other line can
//! become one. Anything outside those turns ends the conversation.
//!
//! Everything here is a function of the bytes given to it: the relay's
//! threads feed it and carry out what it returns.

use std::fmt;

use hedwig_model::capability::Operation;
use hedwig_model::refusal::Refusal;
use hedwig_model::text::Grip;
use zeroize::Zeroize;

/// The longest line either end may send, its line feed and an optional
/// carriage return included: libassuan's `ASSUAN_LINELENGTH`. gpg-agent ends
/// a connection that sends a longer one (`assuan_process` stops at the read
/// error), and the relay ends it before carrying any of it.
pub const LINE: usize = 1002;

/// The bytes a client of an emulated socket presents before it speaks.
pub const NONCE: usize = 16;

/// Which end of the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    Client,
    Agent,
}

/// Why the relay stopped carrying a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Breach {
    /// A line past [`LINE`] bytes.
    TooLong(Side),
    /// The end spoke when it was not its turn: a client that writes while a
    /// command is with the agent, or an agent that writes when nothing was
    /// asked of it.
    OutOfTurn(Side),
    /// The agent sent a line no Assuan server sends.
    NotAnswer,
    /// The end closed in the middle of a line.
    Cut(Side),
}

impl fmt::Display for Breach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side = |side: &Side| match side {
            Side::Client => "the remote",
            Side::Agent => "gpg-agent",
        };
        match self {
            Breach::TooLong(at) => write!(f, "{} sent a line longer than Assuan allows", side(at)),
            Breach::OutOfTurn(at) => write!(f, "{} spoke out of turn", side(at)),
            Breach::NotAnswer => f.write_str("gpg-agent sent a line that is not an Assuan answer"),
            Breach::Cut(at) => write!(f, "{} closed in the middle of a line", side(at)),
        }
    }
}

/// A request read from the client that waits for a decision before the agent
/// sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub operation: Operation,
    /// The keygrip the agent would use: the one the last `SIGKEY` or `SETKEY`
    /// it accepted named, or the card key a `SCD` command names.
    pub key: Option<Grip>,
}

/// What the relay does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    ToAgent(Vec<u8>),
    ToClient(Vec<u8>),
    /// Hold the conversation until [`Conversation::serve`] or
    /// [`Conversation::refuse`] is called.
    Ask(Ask),
}

/// What an `OK` from the agent changes about the key it uses.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Effect {
    Nothing,
    Key(Grip),
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Turn {
    /// The agent's greeting, held until the connection is decided.
    Opening(Vec<u8>),
    /// Nothing is outstanding: the client's next line is a command.
    Idle,
    /// A command is with the agent; the client waits for its answer.
    Asked(Effect),
    /// The agent asked the client for data during a command.
    Inquired(Effect),
    /// A command waits for a decision and has not reached the agent.
    Held(Vec<u8>),
    /// The connection was refused at its opening.
    Over,
}

/// One relayed connection's conversation.
#[derive(Debug)]
pub struct Conversation {
    turn: Turn,
    key: Option<Grip>,
    client: Vec<u8>,
    agent: Vec<u8>,
}

/// The first complete line in `buffer`, taken out of it with its line feed,
/// or `None` while there is none.
fn line(buffer: &mut Vec<u8>, side: Side) -> Result<Option<Vec<u8>>, Breach> {
    match buffer.iter().position(|byte| *byte == b'\n') {
        Some(end) if end < LINE => {
            let rest = buffer.split_off(end + 1);
            Ok(Some(std::mem::replace(buffer, rest)))
        }
        Some(_) => Err(Breach::TooLong(side)),
        None if buffer.len() >= LINE => Err(Breach::TooLong(side)),
        None => Ok(None),
    }
}

/// The line as libassuan hands it on: without its line feed, and without a
/// carriage return before that.
fn content(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// The first word of `text` as libassuan's dispatcher takes it, ending at a
/// space, a tab or a NUL, and what follows the blanks after it.
fn word(text: &[u8]) -> (&[u8], &[u8]) {
    let end = text
        .iter()
        .position(|byte| matches!(byte, b' ' | b'\t' | 0))
        .unwrap_or(text.len());
    let (word, rest) = text.split_at(end);
    let rest = match rest.first() {
        Some(0) | None => &[][..],
        Some(_) => trim_blanks(rest),
    };
    (word, rest)
}

fn trim_blanks(text: &[u8]) -> &[u8] {
    let start = text
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(text.len());
    text.get(start..).unwrap_or_default()
}

/// Whether `word` names `command` as libassuan's dispatcher compares them:
/// exactly, or with ASCII lower-case letters taken as upper-case.
fn names(word: &[u8], command: &[u8]) -> bool {
    word.len() == command.len()
        && word
            .iter()
            .zip(command)
            .all(|(byte, wanted)| byte.to_ascii_uppercase() == *wanted)
}

/// The text up to the first NUL, as a C string ends.
fn until_nul(text: &[u8]) -> &[u8] {
    let end = text
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(text.len());
    text.get(..end).unwrap_or_default()
}

fn blank(byte: Option<&u8>) -> bool {
    matches!(byte, Some(b' ' | b'\t'))
}

/// `skip_options` of `GnuPG`'s `common/server-help.c`.
fn skip_options(text: &[u8]) -> &[u8] {
    let mut rest = trim_blanks(text);
    while rest.starts_with(b"--") {
        let end = rest
            .iter()
            .position(|byte| matches!(byte, b' ' | b'\t'))
            .unwrap_or(rest.len());
        rest = trim_blanks(rest.get(end..).unwrap_or_default());
    }
    rest
}

/// `has_option (line, "--another")` of the same file: the first occurrence,
/// among the leading options, as a whole word.
fn another(arguments: &[u8]) -> bool {
    const NAME: &[u8] = b"--another";
    let Some(at) = arguments
        .windows(NAME.len())
        .position(|window| window == NAME)
    else {
        return false;
    };
    let options = arguments.len() - skip_options(arguments).len();
    let before = at.checked_sub(1).and_then(|index| arguments.get(index));
    at < options
        && (at == 0 || blank(before))
        && matches!(arguments.get(at + NAME.len()), None | Some(b' ' | b'\t'))
}

/// The keygrip `SIGKEY` or `SETKEY` would set, parsed as gpg-agent's
/// `parse_keygrip` parses it: forty hexadecimal digits ended by a blank or
/// the end. `None` where the agent would refuse the line, or where it names
/// the second key.
fn keygrip(arguments: &[u8]) -> Option<Grip> {
    let arguments = until_nul(arguments);
    if another(arguments) {
        return None;
    }
    let grip = skip_options(arguments);
    let digits = grip
        .iter()
        .position(|byte| !byte.is_ascii_hexdigit())
        .unwrap_or(grip.len());
    if digits != 40 || !matches!(grip.get(digits), None | Some(b' ' | b'\t')) {
        return None;
    }
    let text = String::from_utf8_lossy(grip.get(..digits)?).to_ascii_uppercase();
    Grip::try_from(text.as_str()).ok()
}

/// A card key named by a `SCD` signing or decrypting command, where it is
/// named by keygrip.
fn card_key(arguments: &[u8]) -> Option<Grip> {
    let (grip, _) = word(skip_options(until_nul(arguments)));
    (grip.len() == 40 && grip.iter().all(u8::is_ascii_hexdigit))
        .then(|| String::from_utf8_lossy(grip).to_ascii_uppercase())
        .and_then(|text| Grip::try_from(text.as_str()).ok())
}

/// Which key a decided command uses.
enum Uses {
    /// The one the last accepted `SIGKEY` or `SETKEY` set.
    SetKey,
    /// The one the command names itself, where it names it by keygrip.
    Named(Option<Grip>),
}

/// What a client's command line is to the relay.
enum Command {
    /// A comment or an empty line: the agent answers nothing.
    Unanswered,
    Decided(Operation, Uses),
    Carried(Effect),
}

fn command(line: &[u8]) -> Command {
    let text = content(line);
    if text.is_empty() || text.first() == Some(&b'#') {
        return Command::Unanswered;
    }
    let (name, arguments) = word(text);
    if names(name, b"PKSIGN") {
        return Command::Decided(Operation::Sign, Uses::SetKey);
    }
    if names(name, b"PKDECRYPT") {
        return Command::Decided(Operation::Decrypt, Uses::SetKey);
    }
    if names(name, b"SCD") {
        let (inner, rest) = word(arguments);
        if names(inner, b"PKSIGN") {
            return Command::Decided(Operation::Sign, Uses::Named(card_key(rest)));
        }
        if names(inner, b"PKAUTH") {
            return Command::Decided(Operation::Authenticate, Uses::Named(card_key(rest)));
        }
        if names(inner, b"PKDECRYPT") {
            return Command::Decided(Operation::Decrypt, Uses::Named(card_key(rest)));
        }
    }
    if names(name, b"SIGKEY") || names(name, b"SETKEY") {
        return Command::Carried(keygrip(arguments).map_or(Effect::Nothing, Effect::Key));
    }
    if names(name, b"RESET") {
        return Command::Carried(Effect::Reset);
    }
    Command::Carried(Effect::Nothing)
}

/// What an agent's line is, as libassuan's client parses it
/// (`assuan_client_parse_response`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Data,
    Status,
    Comment,
    Ok,
    Error,
    Inquire,
}

fn answer(line: &[u8]) -> Option<Answer> {
    let text = content(line);
    let keyword = |word: &[u8]| {
        text.starts_with(word) && matches!(text.get(word.len()), None | Some(b' ' | 0))
    };
    if text.starts_with(b"D ") {
        Some(Answer::Data)
    } else if keyword(b"S") {
        Some(Answer::Status)
    } else if keyword(b"OK") {
        Some(Answer::Ok)
    } else if keyword(b"ERR") {
        Some(Answer::Error)
    } else if keyword(b"INQUIRE") {
        Some(Answer::Inquire)
    } else if text.first() == Some(&b'#') {
        Some(Answer::Comment)
    } else {
        None
    }
}

/// Whether a client's line answers an inquiry without ending it: data, a
/// comment or an empty line (`assuan_inquire`). Anything else ends it, as the
/// agent ends it on `END`, on `CAN` and on any other line.
fn continues_inquiry(line: &[u8]) -> bool {
    let text = content(line);
    text.is_empty()
        || text.first() == Some(&b'#')
        || (matches!(text.first(), Some(b'D' | b'd')) && text.get(1) == Some(&b' '))
}

/// Whether a line, sent while the agent inquires, can only be one the agent
/// reads as part of the inquiry: `END` and `CAN` end it. Any other line could
/// be read as a command were the agent to have ended the inquiry already.
fn ends_inquiry(line: &[u8]) -> bool {
    let text = content(line);
    let lower = |index: usize| text.get(index).map(u8::to_ascii_uppercase);
    let end = lower(0) == Some(b'E')
        && lower(1) == Some(b'N')
        && lower(2) == Some(b'D')
        && matches!(text.get(3), None | Some(b' '));
    let can = lower(0) == Some(b'C') && lower(1) == Some(b'A') && lower(2) == Some(b'N');
    end || can
}

impl Conversation {
    /// A conversation whose agent greeted with `greeting`, a line beginning
    /// `OK`, which the client receives once the connection is served.
    pub fn opened(greeting: Vec<u8>) -> Conversation {
        Conversation {
            turn: Turn::Opening(greeting),
            key: None,
            client: Vec::new(),
            agent: Vec::new(),
        }
    }

    /// Whether a request waits for a decision.
    pub fn holds(&self) -> bool {
        matches!(self.turn, Turn::Opening(_) | Turn::Held(_))
    }

    /// The key the agent would use for a signature or a decryption now.
    pub fn key(&self) -> Option<&Grip> {
        self.key.as_ref()
    }

    /// Bytes from the client.
    ///
    /// # Errors
    ///
    /// The breach that ends the conversation.
    pub fn from_client(&mut self, bytes: &[u8]) -> Result<Vec<Out>, Breach> {
        self.client.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            let open = matches!(self.turn, Turn::Idle | Turn::Inquired(_));
            if !open {
                return if self.client.is_empty() {
                    Ok(out)
                } else {
                    Err(Breach::OutOfTurn(Side::Client))
                };
            }
            let Some(line) = line(&mut self.client, Side::Client)? else {
                return Ok(out);
            };
            match std::mem::replace(&mut self.turn, Turn::Idle) {
                Turn::Idle => match command(&line) {
                    Command::Unanswered => out.push(Out::ToAgent(line)),
                    Command::Carried(effect) => {
                        self.turn = Turn::Asked(effect);
                        out.push(Out::ToAgent(line));
                    }
                    Command::Decided(operation, uses) => {
                        let key = match uses {
                            Uses::SetKey => self.key.clone(),
                            Uses::Named(key) => key,
                        };
                        self.turn = Turn::Held(line);
                        out.push(Out::Ask(Ask { operation, key }));
                    }
                },
                Turn::Inquired(effect) if continues_inquiry(&line) => {
                    self.turn = Turn::Inquired(effect);
                    out.push(Out::ToAgent(line));
                }
                Turn::Inquired(effect) if ends_inquiry(&line) => {
                    self.turn = Turn::Asked(effect);
                    out.push(Out::ToAgent(line));
                }
                Turn::Inquired(_) => return Err(Breach::OutOfTurn(Side::Client)),
                other => {
                    self.turn = other;
                    return Err(Breach::OutOfTurn(Side::Client));
                }
            }
        }
    }

    /// Bytes from the agent.
    ///
    /// # Errors
    ///
    /// The breach that ends the conversation.
    pub fn from_agent(&mut self, bytes: &[u8]) -> Result<Vec<Out>, Breach> {
        self.agent.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            let open = matches!(self.turn, Turn::Asked(_) | Turn::Inquired(_));
            if !open {
                return if self.agent.is_empty() {
                    Ok(out)
                } else {
                    Err(Breach::OutOfTurn(Side::Agent))
                };
            }
            let Some(line) = line(&mut self.agent, Side::Agent)? else {
                return Ok(out);
            };
            let said = answer(&line).ok_or(Breach::NotAnswer)?;
            let effect = match &self.turn {
                Turn::Asked(effect) | Turn::Inquired(effect) => effect.clone(),
                _ => Effect::Nothing,
            };
            match said {
                Answer::Data | Answer::Status | Answer::Comment => {}
                Answer::Inquire => self.turn = Turn::Inquired(effect),
                Answer::Error => self.turn = Turn::Idle,
                Answer::Ok => {
                    match effect {
                        Effect::Nothing => {}
                        Effect::Key(key) => self.key = Some(key),
                        Effect::Reset => self.key = None,
                    }
                    self.turn = Turn::Idle;
                }
            }
            out.push(Out::ToClient(line));
        }
    }

    /// The held request is served: the agent's greeting goes to the client,
    /// or the held command to the agent.
    pub fn serve(&mut self) -> Vec<Out> {
        match std::mem::replace(&mut self.turn, Turn::Idle) {
            Turn::Opening(greeting) => vec![Out::ToClient(greeting)],
            Turn::Held(line) => {
                self.turn = Turn::Asked(Effect::Nothing);
                vec![Out::ToAgent(line)]
            }
            other => {
                self.turn = other;
                Vec::new()
            }
        }
    }

    /// The held request is refused: the client is answered as the agent
    /// answers what it will not do, and the agent never sees the command. A
    /// connection refused at its opening is over.
    pub fn refuse(&mut self, refusal: &Refusal) -> Vec<Out> {
        match std::mem::replace(&mut self.turn, Turn::Idle) {
            Turn::Opening(_) => {
                self.turn = Turn::Over;
                vec![Out::ToClient(refused(refusal))]
            }
            Turn::Held(_) => vec![Out::ToClient(refused(refusal))],
            other => {
                self.turn = other;
                Vec::new()
            }
        }
    }

    /// Whether the conversation can go on: false once a connection was
    /// refused at its opening.
    pub fn open(&self) -> bool {
        self.turn != Turn::Over
    }

    /// The client closed.
    ///
    /// # Errors
    ///
    /// [`Breach::Cut`] where it closed in the middle of a line.
    pub fn client_closed(&self) -> Result<(), Breach> {
        if self.client.is_empty() {
            Ok(())
        } else {
            Err(Breach::Cut(Side::Client))
        }
    }
}

impl Drop for Conversation {
    // A decryption's result passes through the agent's buffer.
    fn drop(&mut self) {
        self.client.zeroize();
        self.agent.zeroize();
    }
}

/// libgpg-error's source number for gpg-agent (`err-sources.h.in`).
const SOURCE_GPGAGENT: u32 = 4;

/// The code gpg-agent itself gives for each refusal, with libgpg-error's
/// words for it (`err-codes.h.in`).
fn code(refusal: &Refusal) -> (u32, &'static str) {
    match refusal {
        // As gpg-agent answers when its owner denies a key's use
        // (`findkey.c`, `agent_get_confirmation`).
        Refusal::Declined => (99, "Operation cancelled"),
        Refusal::NobodyReachable(_) => (114, "Not confirmed"),
        Refusal::SourceUnavailable { .. } => (77, "No agent running"),
        // As gpg-agent answers what its restricted socket does not do.
        _ => (251, "Forbidden"),
    }
}

/// The line gpg-agent would write for `refusal`, in libassuan's form
/// (`assuan-handler.c`: `"ERR %d %.50s <%.30s>"`). The reason is the
/// workstation's to show: the remote is told the code alone.
pub fn refused(refusal: &Refusal) -> Vec<u8> {
    let (code, words) = code(refusal);
    format!(
        "ERR {} {words} <GPG Agent>\n",
        (SOURCE_GPGAGENT << 24) | code
    )
    .into_bytes()
}

/// The sixteen bytes gpg-agent issues with its port, which possession of is
/// possession of the agent. Boxed so a move carries the pointer and the one
/// copy is erased where it lies; never printed.
pub struct Nonce(Box<[u8; NONCE]>);

impl Nonce {
    pub fn new(bytes: [u8; NONCE]) -> Nonce {
        let mut held = Box::new([0u8; NONCE]);
        let mut bytes = bytes;
        held.copy_from_slice(&bytes);
        bytes.zeroize();
        Nonce(held)
    }

    pub fn as_bytes(&self) -> &[u8; NONCE] {
        &self.0
    }

    /// Whether `presented` are these bytes, compared in time that does not
    /// depend on where they differ.
    pub fn matches(&self, presented: &[u8]) -> bool {
        presented.len() == NONCE
            && self
                .0
                .iter()
                .zip(presented)
                .fold(0u8, |differ, (ours, theirs)| differ | (ours ^ theirs))
                == 0
    }
}

impl Drop for Nonce {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nonce(..)")
    }
}

/// What a socket file says.
#[derive(Debug)]
pub enum SocketFile {
    /// The native form libassuan writes on Windows: a decimal port, a line
    /// feed, sixteen bytes.
    Native { port: u16, nonce: Nonce },
    /// Cygwin's form, `!<socket >PORT s GUID`: the port, and the sixteen
    /// bytes the four groups of the GUID are, each a little-endian 32-bit
    /// number as libassuan copies them (`assuan-socket.c`
    /// `read_port_and_nonce`). A client of it reads them echoed and trades
    /// eight bytes of credentials before it speaks.
    Cygwin { port: u16, nonce: Nonce },
}

/// Why a socket file could not be read as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unparsed {
    Empty,
    NoLineFeed,
    Port,
    NonceLength(usize),
}

impl fmt::Display for Unparsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unparsed::Empty => f.write_str("the socket file is empty"),
            Unparsed::NoLineFeed => f.write_str("the socket file has no line feed after its port"),
            Unparsed::Port => f.write_str("the socket file's port is not a number from 1 to 65535"),
            Unparsed::NonceLength(length) => {
                write!(
                    f,
                    "the socket file holds {length} bytes after its port, not 16"
                )
            }
        }
    }
}

/// Reads a socket file's bytes (`assuan-socket.c` `read_port_and_nonce`).
///
/// # Errors
///
/// What makes the bytes no socket file.
pub fn socket_file(bytes: &[u8]) -> Result<SocketFile, Unparsed> {
    if bytes.is_empty() {
        return Err(Unparsed::Empty);
    }
    if let Some(rest) = bytes.strip_prefix(b"!<socket >") {
        return cygwin(rest);
    }
    let feed = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(Unparsed::NoLineFeed)?;
    let (digits, rest) = bytes.split_at(feed);
    let nonce = rest.get(1..).unwrap_or_default();
    if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Unparsed::Port);
    }
    // Folded rather than parsed: five checked digits stay well inside `u32`.
    let port = digits
        .iter()
        .fold(0u32, |port, digit| port * 10 + u32::from(digit - b'0'));
    let port = u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(Unparsed::Port)?;
    let mut held = [0u8; NONCE];
    if nonce.len() != NONCE {
        return Err(Unparsed::NonceLength(nonce.len()));
    }
    held.copy_from_slice(nonce);
    Ok(SocketFile::Native {
        port,
        nonce: Nonce::new(held),
    })
}

/// Cygwin's form after its prefix: `%u s %08x-%08x-%08x-%08x`, then a NUL
/// or nothing.
fn cygwin(rest: &[u8]) -> Result<SocketFile, Unparsed> {
    let rest = rest.strip_suffix(b"\0").unwrap_or(rest);
    let text = std::str::from_utf8(rest).map_err(|_| Unparsed::Port)?;
    let (port, guid) = text.split_once(" s ").ok_or(Unparsed::Port)?;
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Unparsed::Port);
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(Unparsed::Port)?;
    let groups: Vec<&str> = guid.split('-').collect();
    let mut held = [0u8; NONCE];
    if groups.len() != 4 {
        return Err(Unparsed::NonceLength(guid.len()));
    }
    for (slot, group) in held.as_chunks_mut::<4>().0.iter_mut().zip(&groups) {
        let value = (group.len() == 8)
            .then(|| u32::from_str_radix(group, 16).ok())
            .flatten()
            .ok_or(Unparsed::NonceLength(guid.len()))?;
        slot.copy_from_slice(&value.to_le_bytes());
    }
    Ok(SocketFile::Cygwin {
        port,
        nonce: Nonce::new(held),
    })
}

/// Whether `line`, the first an agent wrote, is the greeting of a server
/// that will take commands.
pub fn greets(line: &[u8]) -> bool {
    answer(line) == Some(Answer::Ok)
}
