//! Text that enters from a document, a control client or a remote, checked once
//! where it enters so nothing downstream re-validates it.

use std::fmt;
use std::num::NonZeroU16;
use std::path::Path;

use zeroize::Zeroize;

/// Why a piece of text was not accepted as the kind it was offered as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextError {
    Empty,
    /// Longer than the kind allows; carries the limit and the length offered.
    TooLong {
        limit: usize,
        length: usize,
    },
    /// A character the kind does not admit, with its byte offset.
    Character {
        found: char,
        at: usize,
    },
    /// A leading hyphen, which a program given this text as an argument would
    /// read as one of its own options.
    LeadingHyphen,
    /// A pattern with no `*`: it selects one remote, which a grant names
    /// directly.
    NoWildcard,
    /// A template that does not hold exactly one `{}`.
    Placeholder,
    /// Port zero.
    ZeroPort,
    /// Not `hedwig.` followed by thirty-two lower-case hexadecimal digits.
    PipeName,
    /// Hexadecimal digits of a length this kind never has; carries the length
    /// offered.
    Digits {
        length: usize,
    },
    /// Not a public key as OpenSSH writes one.
    Key,
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TextError::Empty => f.write_str("it is empty"),
            TextError::TooLong { limit, length } => {
                write!(f, "it is {length} bytes and the limit is {limit}")
            }
            TextError::Character { found, at } => {
                write!(f, "{found:?} at byte {at} is not allowed here")
            }
            TextError::LeadingHyphen => f.write_str("it begins with a hyphen"),
            TextError::NoWildcard => f.write_str("it has no `*`, so it names one remote"),
            TextError::Placeholder => f.write_str("it must contain `{}` exactly once"),
            TextError::ZeroPort => f.write_str("port 0 names no port"),
            TextError::PipeName => {
                f.write_str("it is not `hedwig.` and thirty-two hexadecimal digits")
            }
            TextError::Digits { length } => {
                write!(f, "no key is named by {length} hexadecimal digits")
            }
            TextError::Key => f.write_str(
                "it is not a public key as OpenSSH writes one: its type, a space and the key in base64",
            ),
        }
    }
}

impl std::error::Error for TextError {}

fn checked(text: &str, limit: usize, admits: impl Fn(char) -> bool) -> Result<(), TextError> {
    if text.is_empty() {
        return Err(TextError::Empty);
    }
    if text.len() > limit {
        return Err(TextError::TooLong {
            limit,
            length: text.len(),
        });
    }
    match text.char_indices().find(|(_, c)| !admits(*c)) {
        Some((at, found)) => Err(TextError::Character { found, at }),
        None => Ok(()),
    }
}

/// The characters OpenSSH refuses in a host name it is given
/// (`.ext/openssh-portable/readconf.c:3428-3440`). The in-box client, 9.5,
/// does not check; a route that puts an address into a proxy command would
/// then pass them to a program, so the address carries the check itself.
const REFUSED_IN_HOSTS: &str = "'`\"$\\;&<>|(){},";

fn argument_safe(text: &str, limit: usize) -> Result<(), TextError> {
    checked(text, limit, |c| {
        c.is_ascii_graphic() && !REFUSED_IN_HOSTS.contains(c)
    })?;
    if text.starts_with('-') {
        return Err(TextError::LeadingHyphen);
    }
    Ok(())
}

macro_rules! text_type {
    ($(#[$meta:meta])* $name:ident, $check:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = TextError;

            fn try_from(text: &str) -> Result<Self, TextError> {
                let check: fn(&str) -> Result<(), TextError> = $check;
                check(text)?;
                Ok($name(text.to_owned()))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

text_type!(
    /// The stable identifier of a capability, a route or a platform family:
    /// lower-case letters, digits and hyphens, at most 63 bytes. A reference by
    /// name survives export and import, which a storage-assigned number would
    /// not.
    Name,
    |text| {
        checked(text, 63, |c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
        })?;
        if text.starts_with('-') {
            return Err(TextError::LeadingHyphen);
        }
        Ok(())
    }
);

text_type!(
    /// Where a route finds one remote: an SSH destination, a workspace name.
    /// It becomes an argument of the route's client program, so it is printable
    /// ASCII with no leading hyphen.
    Address,
    |text| argument_safe(text, 255)
);

text_type!(
    /// The name a route's client is started by: `ssh`, `gh`. Windows finds the
    /// program, so the name holds nothing a location is written with - no
    /// separator and no drive - and a path cannot be one.
    Program,
    |text| {
        checked(text, 64, |c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
        })?;
        match text.chars().next() {
            Some('-') => Err(TextError::LeadingHyphen),
            Some(found @ '.') => Err(TextError::Character { found, at: 0 }),
            _ => Ok(()),
        }
    }
);

text_type!(
    /// One argument a route's entry gives its client, passed exactly as it is
    /// written: it is never joined to another and never read by a shell.
    Verbatim,
    |text| checked(text, 1024, |c| !c.is_control())
);

text_type!(
    /// A host the workstation can reach, for a service that is not on the
    /// workstation itself.
    Host,
    |text| {
        checked(text, 253, |c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':')
        })?;
        if text.starts_with('-') {
            return Err(TextError::LeadingHyphen);
        }
        Ok(())
    }
);

text_type!(
    /// The name of an environment variable a remote tool reads.
    Variable,
    |text| {
        checked(text, 64, |c| {
            c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'
        })?;
        match text.chars().next() {
            Some(found) if found.is_ascii_digit() => Err(TextError::Character { found, at: 0 }),
            _ => Ok(()),
        }
    }
);

text_type!(
    /// The value a remote tool's variable takes, with `{}` standing for the
    /// socket path: `localfilesystem:{}`. Its alphabet excludes everything a
    /// shell would interpret, because the value is written into a remote's
    /// configuration.
    Template,
    |text| {
        checked(text, 128, |c| {
            c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '_' | '-' | '{' | '}')
        })?;
        if text.matches("{}").count() != 1 || text.matches(['{', '}']).count() != 2 {
            return Err(TextError::Placeholder);
        }
        Ok(())
    }
);

text_type!(
    /// What a remote's own system calls itself, as readiness reads it there:
    /// `uname -s` on a Unix remote, `Windows_NT` on a Windows one. A platform
    /// profile names the one it answers to.
    Kernel,
    |text| checked(text, 64, |c| c.is_ascii_graphic())
);

text_type!(
    /// A path on a remote, as that remote's own tool reported it.
    RemotePath,
    |text| checked(text, 4096, |c| !c.is_control())
);

text_type!(
    /// A directory on the workstation. Held as text because it only ever
    /// arrives as text, in a document or a control message; [`Folder::as_path`]
    /// is the form the OS boundary takes.
    Folder,
    |text| checked(text, 4096, |c| !c.is_control())
);

impl Folder {
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

text_type!(
    /// A file on the workstation, as Windows' own search returned it: the
    /// program a channel ran. Recorded and shown; a process is started from
    /// the path found, never from this text.
    Location,
    |text| checked(text, 4096, |c| !c.is_control())
);

text_type!(
    /// A service's name as the service control manager lists it: at most 256
    /// characters, never a slash of either kind.
    ServiceName,
    |text| checked(text, 256, |c| !c.is_control() && c != '/' && c != '\\')
);

text_type!(
    /// What identifies a host key to the person, or names a key as `git`
    /// takes it: a fingerprint in the form its tool prints it, kept as
    /// written.
    Mark,
    |text| checked(text, 128, |c| c.is_ascii_graphic())
);

/// Upper-case hexadecimal digits, `lengths` of them.
fn digits(text: &str, lengths: &[usize]) -> Result<(), TextError> {
    checked(text, 64, |c| c.is_ascii_digit() || ('A'..='F').contains(&c))?;
    if lengths.contains(&text.len()) {
        Ok(())
    } else {
        Err(TextError::Digits { length: text.len() })
    }
}

text_type!(
    /// The keygrip gpg-agent knows a key by: forty upper-case hexadecimal
    /// digits, as its own commands write it. A relayed request names its key
    /// by this, and so does a card.
    Grip,
    |text| digits(text, &[40])
);

text_type!(
    /// An `OpenPGP` key's fingerprint as `gpg --with-colons` prints it: forty
    /// upper-case hexadecimal digits for a version 4 key, sixty-four for
    /// versions 5 and 6. How a person, a remote's keyring and `git` name a key.
    Fingerprint,
    |text| digits(text, &[40, 64])
);

text_type!(
    /// A card's serial number as scdaemon writes it, which is how gpg-agent's
    /// stub of a card key names its card.
    Serial,
    |text| checked(text, 128, |c| c.is_ascii_alphanumeric())
);

text_type!(
    /// A device as the workstation's ADB server names it, and how a grant
    /// names what it lends: a USB device's own serial, `emulator-<port>`, a
    /// connected device's address as `ParseNetAddress` writes it, a wireless
    /// device's mDNS name. At most 512 bytes, the longest of those - a USB
    /// string descriptor's 126 UTF-16 units - with room; no control
    /// character, since a listing is lines of tab- and space-separated text.
    /// A device the server lists without one cannot be named.
    DeviceSerial,
    |text| checked(text, 512, |c| !c.is_control())
);

text_type!(
    /// A serial port as Windows lists it among the workstation's serial ports,
    /// `COM5`, and how a capability names the port it lends. The core opens
    /// `\\.\` and this name, so it is letters and digits alone: never a path,
    /// and never a name of another device's form such as `C:`.
    PortName,
    |text| checked(text, 32, |c| c.is_ascii_alphanumeric())
);

impl PortName {
    /// Whether the two name one port: Windows' names for devices do not
    /// distinguish case.
    pub fn same(&self, other: &PortName) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

text_type!(
    /// The device side of an ADB forward, as the remote's tool asked for it
    /// and the device resolves it: `tcp:6790`, `localabstract:<name>`,
    /// `jdwp:<pid>`. The server splits a forward at `;`, so none is in it.
    DeviceSocket,
    |text| checked(text, 1024, |c| !c.is_control() && c != ';')
);

text_type!(
    /// Words a channel's client or a remote server addressed to the person: a
    /// host key fingerprint, a challenge. Line feeds are the only control
    /// characters kept, so nothing in them can drive the terminal they are
    /// shown in.
    Words,
    |text| checked(text, 1024, |c| c == '\n' || !c.is_control())
);

/// Characters that change which way text runs or what it sits beside without
/// showing themselves: with them a remote's words can be made to read as
/// other words, or as the workstation's own (Unicode's bidirectional
/// algorithm, UAX 9, its explicit marks, embeddings, overrides and isolates;
/// and the line and paragraph separators).
const UNSHOWN: [char; 14] = [
    '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{2028}', '\u{2029}',
];

fn shown(c: char) -> bool {
    !c.is_control() && !UNSHOWN.contains(&c)
}

/// The most a remark may be, in bytes. Invariant: a sentence or two, more
/// than any notification Windows shows whole (`NOTIFYICONDATAW::szInfo`, 256
/// UTF-16 units); it bounds what one remote's notice makes the core keep.
pub const REMARK: usize = 1024;

text_type!(
    /// What a remote's job said to the person, as that remote's words: one
    /// line, with no control character and nothing that turns text around or
    /// breaks it, so it is shown as written and never as anything else.
    Remark,
    |text| checked(text, REMARK, shown)
);

impl Remark {
    /// `text` as a remark: each control character, and each character that
    /// turns text around, removed - a line break, a tab and a separator
    /// becoming a blank - and the blanks at either end trimmed.
    ///
    /// # Errors
    ///
    /// [`TextError::Empty`] where nothing is left, and
    /// [`TextError::TooLong`] past [`REMARK`].
    pub fn cleaned(text: &str) -> Result<Remark, TextError> {
        let kept: String = text
            .chars()
            .filter_map(|c| {
                if shown(c) {
                    Some(c)
                } else if c.is_whitespace() {
                    Some(' ')
                } else {
                    None
                }
            })
            .collect();
        Remark::try_from(kept.trim())
    }
}

text_type!(
    /// An address pattern in which `*` stands for any run of characters,
    /// including none.
    Pattern,
    |text| {
        argument_safe(text, 255)?;
        if !text.contains('*') {
            return Err(TextError::NoWildcard);
        }
        Ok(())
    }
);

text_type!(
    /// The name of the core's control pipe for one run: `hedwig.` and
    /// thirty-two lower-case hexadecimal digits the core drew at random. A
    /// client takes it from the record the supervisor keeps, so its form is
    /// checked before it becomes a path.
    PipeName,
    |text| {
        let digits = text.strip_prefix("hedwig.").ok_or(TextError::PipeName)?;
        let hexadecimal = digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if digits.len() == 32 && hexadecimal {
            Ok(())
        } else {
            Err(TextError::PipeName)
        }
    }
);

impl PipeName {
    /// The name as the path a client opens and the core creates.
    pub fn to_path(&self) -> String {
        format!(r"\\.\pipe\{}", self.0)
    }
}

text_type!(
    /// The name of a pipe an SSH agent on the workstation serves, as it
    /// follows `\\.\pipe\`: `openssh-ssh-agent`, which several products
    /// claim, or one of an agent's own. Windows takes any character but a
    /// backslash in a pipe's name, up to 256 with its prefix; Pageant's
    /// carries the account's name.
    AgentPipe,
    |text| checked(text, 247, |c| !c.is_control() && c != '\\')
);

impl AgentPipe {
    /// The pipe every Windows OpenSSH client reaches where `SSH_AUTH_SOCK`
    /// names none, whichever product holds it (`wmain_common.c`).
    pub fn well_known() -> AgentPipe {
        AgentPipe("openssh-ssh-agent".to_owned())
    }

    /// The name as the path a client opens.
    pub fn to_path(&self) -> String {
        format!(r"\\.\pipe\{}", self.0)
    }
}

/// The standard alphabet of RFC 4648 with its padding, as OpenSSH writes a
/// key: the decoded bytes, or `None` for anything else.
pub fn base64(text: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut accumulated = 0u32;
    let body = bytes.get(..bytes.len() - padding)?;
    for (at, byte) in body.iter().enumerate() {
        accumulated = (accumulated << 6) | u32::from(value(*byte)?);
        if at % 4 == 3 {
            out.extend_from_slice(accumulated.to_be_bytes().get(1..)?);
            accumulated = 0;
        }
    }
    let [_, high, middle, _] = match body.len() % 4 {
        0 => return Some(out),
        3 => (accumulated << 6).to_be_bytes(),
        2 => (accumulated << 12).to_be_bytes(),
        _ => return None,
    };
    // Bits a canonical encoder leaves at zero: anything else is a second
    // spelling of the same key, which would name it twice.
    let spare = if body.len() % 4 == 3 {
        accumulated & 0b11
    } else {
        accumulated & 0b1111
    };
    if spare != 0 {
        return None;
    }
    out.push(high);
    if body.len() % 4 == 3 {
        out.push(middle);
    }
    Some(out)
}

/// RFC 4648's encoding with padding, the inverse of [`base64`].
pub fn to_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let symbol = |index: u32| {
        ALPHABET
            .get(usize::try_from(index & 63).unwrap_or_default())
            .map_or('=', |byte| char::from(*byte))
    };
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        for (slot, byte) in group.iter_mut().zip(chunk) {
            *slot = *byte;
        }
        let [a, b, c] = group;
        let joined = u32::from(a) << 16 | u32::from(b) << 8 | u32::from(c);
        out.push(symbol(joined >> 18));
        out.push(symbol(joined >> 12));
        out.push(if chunk.len() > 1 {
            symbol(joined >> 6)
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { symbol(joined) } else { '=' });
    }
    out
}

/// The SSH string at the start of `bytes` and what follows it: a 32-bit
/// big-endian length and that many bytes (RFC 4251 section 5).
pub fn ssh_string(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = bytes.split_first_chunk::<4>()?;
    let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
    (rest.len() >= length).then(|| rest.split_at(length))
}

text_type!(
    /// A public key as OpenSSH writes one in `authorized_keys` and
    /// `ssh-add -L` prints it, without the comment: its type, a space, and
    /// the key's blob in base64, whose first field names the same type. The
    /// blob is what the agent protocol carries, so two keys are one exactly
    /// when their blobs are. How a grant lends a key, a statement names one,
    /// and a key a remote may authenticate toward is named.
    SshKey,
    |text| {
        checked(text, 16384, |c| c.is_ascii_graphic() || c == ' ')?;
        let (kind, encoded) = text.split_once(' ').ok_or(TextError::Key)?;
        let kind_admitted = !kind.is_empty()
            && kind.len() <= 64
            && kind
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'@' | b'.'));
        let blob = base64(encoded).ok_or(TextError::Key)?;
        match ssh_string(&blob) {
            Some((named, rest)) if kind_admitted && named == kind.as_bytes() && !rest.is_empty() => {
                Ok(())
            }
            _ => Err(TextError::Key),
        }
    }
);

/// The key a request uses, as its dialect reads it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyId {
    /// The keygrip gpg-agent would use, as an Assuan request names it.
    Grip(Grip),
    /// The public key an SSH agent's request names.
    Ssh(SshKey),
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyId::Grip(grip) => grip.fmt(f),
            KeyId::Ssh(key) => key.fmt(f),
        }
    }
}

impl SshKey {
    /// The blob the agent protocol carries.
    pub fn blob(&self) -> Vec<u8> {
        self.0
            .split_once(' ')
            .and_then(|(_, encoded)| base64(encoded))
            .unwrap_or_default()
    }

    /// The key whose blob this is, where it is one: what a relayed request
    /// names, written as the person names it.
    pub fn from_blob(blob: &[u8]) -> Option<SshKey> {
        let (kind, _) = ssh_string(blob)?;
        let kind = std::str::from_utf8(kind).ok()?;
        SshKey::try_from(format!("{kind} {}", to_base64(blob)).as_str()).ok()
    }

    /// The key's type: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`.
    pub fn kind(&self) -> &str {
        self.0.split_once(' ').map_or("", |(kind, _)| kind)
    }
}

impl Pattern {
    /// Whether `address` is selected. Linear in the two lengths: each literal
    /// run is searched for once, left to right, so no input makes it backtrack.
    pub fn matches(&self, address: &Address) -> bool {
        let text = address.as_str();
        let mut runs = self.0.split('*');
        let first = runs.next().unwrap_or_default();
        let Some(mut rest) = text.strip_prefix(first) else {
            return false;
        };
        let mut runs: Vec<&str> = runs.collect();
        let Some(last) = runs.pop() else {
            return rest.is_empty();
        };
        for run in runs {
            match rest.find(run) {
                Some(at) => rest = rest.get(at + run.len()..).unwrap_or_default(),
                None => return false,
            }
        }
        rest.ends_with(last)
    }
}

/// A TCP port other than zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port(NonZeroU16);

impl Port {
    pub fn number(self) -> u16 {
        self.0.get()
    }
}

impl TryFrom<u16> for Port {
    type Error = TextError;

    fn try_from(number: u16) -> Result<Self, TextError> {
        NonZeroU16::new(number).map(Port).ok_or(TextError::ZeroPort)
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Text a person typed in answer to a channel's prompt: a passphrase, a
/// password, a one-time code. It is never printed, never recorded, never
/// copied, and erased where it lies when it is dropped.
#[derive(PartialEq, Eq)]
pub struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    /// The answer, for the one place that hands it to the channel's client.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(text: String) -> Self {
        Secret(text)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}
