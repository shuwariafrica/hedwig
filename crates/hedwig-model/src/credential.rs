//! What a remote's `git` asks through its own `cache` helper, and what the
//! workstation's own `git credential fill` answers: each read once here,
//! bounded and checked, so the relay passes on nothing it has not read.
//!
//! The cache helper sends its daemon an `action=` line, a `timeout=` line, and
//! then the credential as `git` wrote it to the helper, one `key=value` to a
//! line (`git-2.56.0/builtin/credential-cache.c:94-104`), and reads whatever
//! comes back as the helper's answer. Only a `get` is ever answered: a
//! `store` carries back the secret released, and an `erase` the one a forge
//! refused, and neither reaches the workstation's own store.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::site::{self, Url};
use crate::text::Words;

/// The most a remote's request, or the workstation's answer, may be. Invariant:
/// a request names one URL and the headers its server sent with a `401`, and an
/// answer one credential; `git` writes neither beyond a few kilobytes, and a
/// remote is never read past this.
pub const LONGEST: usize = 65_536;

/// The most `wwwauth[]` lines a request may carry. Invariant: a server sends
/// one `WWW-Authenticate` header per scheme it accepts.
pub const CHALLENGES: usize = 16;

/// What the cache helper asks of its daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// A credential for the site, which only the workstation's own credential
    /// system can give.
    Get,
    /// The credential that just succeeded, sent back to every helper.
    Store,
    /// The credential the site just refused.
    Erase,
    /// `exit`, or an action this version of `git` does not know.
    Other,
}

/// What a request names, as the remote's `git` wrote it. A secret the request
/// carries - the password of a `store` or an `erase` - is never kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    protocol: Option<String>,
    host: Option<String>,
    path: Option<String>,
    username: Option<String>,
    challenges: Vec<String>,
    /// The remote's `git` reads a credential given as `authtype` and
    /// `credential` (`git` 2.46 and later).
    bearer: bool,
}

/// Where a request leads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// An `https` or `http` site.
    Site(Url),
    /// Any other protocol - a client certificate's passphrase (`cert`), a
    /// mail server (`smtp`) - in the remote's words, or `None` where it named
    /// none.
    Other(Option<Words>),
}

/// A request read whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub action: Action,
    pub wanted: Wanted,
}

/// Why what a remote sent is not what `git`'s cache helper sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unread {
    /// Longer than [`LONGEST`].
    TooLong,
    /// The first line is not `action=`.
    Action,
    /// The second line is not `timeout=` and digits.
    Timeout,
    /// A line with no `=`, or more `wwwauth[]` lines than [`CHALLENGES`].
    Line,
    /// A value holding a control character, or not UTF-8.
    Value,
    /// A host that is not one of an `https` or `http` site.
    Host,
}

impl fmt::Display for Unread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Unread::TooLong => "the remote sent a credential request longer than git sends",
            Unread::Action => "the remote's credential request did not begin with its action",
            Unread::Timeout => "the remote's credential request did not give its timeout second",
            Unread::Line => "the remote sent a credential request line git does not write",
            Unread::Value => "the remote sent a credential request value git does not write",
            Unread::Host => "the remote's git asked for a credential for a host no site has",
        })
    }
}

impl std::error::Error for Unread {}

/// A value as `git` writes one: text with no control character but a tab,
/// which a server's challenge may hold.
fn value(bytes: &[u8]) -> Result<String, Unread> {
    let text = std::str::from_utf8(bytes).map_err(|_| Unread::Value)?;
    if text.chars().any(|c| c.is_control() && c != '\t') {
        return Err(Unread::Value);
    }
    Ok(text.to_owned())
}

/// Reads a remote's request: `action=`, `timeout=`, then the credential's
/// lines to the first empty one or the end. Lines this version does not know
/// are passed over, as `git` passes them over (`credential.c:330-412`).
///
/// # Errors
///
/// [`Unread`], saying why it is not what `git` sends.
pub fn read(bytes: &[u8]) -> Result<Asked, Unread> {
    if bytes.len() > LONGEST {
        return Err(Unread::TooLong);
    }
    let mut lines = bytes.split(|byte| *byte == b'\n');
    let action = lines
        .next()
        .and_then(|line| line.strip_prefix(b"action="))
        .ok_or(Unread::Action)?;
    let action = match action {
        b"get" => Action::Get,
        b"store" => Action::Store,
        b"erase" => Action::Erase,
        _ => Action::Other,
    };
    let timeout = lines
        .next()
        .and_then(|line| line.strip_prefix(b"timeout="))
        .ok_or(Unread::Timeout)?;
    if timeout.is_empty() || !timeout.iter().all(u8::is_ascii_digit) {
        return Err(Unread::Timeout);
    }
    let mut wanted = Wanted {
        protocol: None,
        host: None,
        path: None,
        username: None,
        challenges: Vec::new(),
        bearer: false,
    };
    for line in lines {
        if line.is_empty() {
            break;
        }
        let at = line
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(Unread::Line)?;
        let (key, rest) = line.split_at(at);
        let raw = rest.get(1..).unwrap_or_default();
        match key {
            b"protocol" => wanted.protocol = Some(value(raw)?),
            b"host" => wanted.host = Some(value(raw)?),
            b"path" => wanted.path = Some(value(raw)?),
            b"username" => wanted.username = Some(value(raw)?),
            b"wwwauth[]" => {
                if wanted.challenges.len() == CHALLENGES {
                    return Err(Unread::Line);
                }
                wanted.challenges.push(value(raw)?);
            }
            b"capability[]" if raw == b"authtype" => wanted.bearer = true,
            // The secret of a `store` or an `erase`, and whatever else this
            // version does not read, is never kept.
            _ => {}
        }
    }
    if wanted.protocol.as_deref().is_some_and(web) && wanted.place().is_err() {
        return Err(Unread::Host);
    }
    Ok(Asked { action, wanted })
}

fn web(protocol: &str) -> bool {
    matches!(protocol, "https" | "http")
}

impl Wanted {
    /// Where the request leads.
    ///
    /// # Errors
    ///
    /// [`Unread::Host`] for an `https` or `http` request whose host is not a
    /// site's.
    pub fn place(&self) -> Result<Place, Unread> {
        match (self.protocol.as_deref(), self.host.as_deref()) {
            (Some(protocol), Some(host)) if web(protocol) => {
                let url = site::url(&format!("{protocol}://{host}/")).map_err(|_| Unread::Host)?;
                Ok(Place::Site(url))
            }
            (Some(protocol), None) if web(protocol) => Err(Unread::Host),
            (protocol, _) => Ok(Place::Other(
                protocol.and_then(|protocol| Words::try_from(protocol).ok()),
            )),
        }
    }

    /// Whether the remote's `git` reads a credential given as `authtype` and
    /// `credential`.
    pub fn bearer(&self) -> bool {
        self.bearer
    }

    /// What the workstation's `git credential fill` is given: what the remote
    /// named of the site, its server's challenges, and that it reads a bearer
    /// credential where it does; never anything the remote said of a secret.
    pub fn to_fill(&self) -> Vec<u8> {
        let mut fill = String::new();
        if self.bearer {
            fill.push_str("capability[]=authtype\n");
        }
        let mut line = |key: &str, value: &str| {
            fill.push_str(key);
            fill.push('=');
            fill.push_str(value);
            fill.push('\n');
        };
        for (key, value) in [
            ("protocol", &self.protocol),
            ("host", &self.host),
            ("path", &self.path),
            ("username", &self.username),
        ] {
            if let Some(value) = value {
                line(key, value);
            }
        }
        for challenge in &self.challenges {
            line("wwwauth[]", challenge);
        }
        fill.push('\n');
        fill.into_bytes()
    }
}

/// Why the workstation's `git credential fill` gave no credential to release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unfilled {
    /// Longer than [`LONGEST`].
    TooLong,
    /// A line with no `=`, or a value with a control character or not UTF-8.
    Malformed,
    /// No user name and password, nor a bearer credential the remote reads.
    Incomplete,
}

impl fmt::Display for Unfilled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Unfilled::TooLong => {
                "the workstation's git gave a credential longer than any it writes"
            }
            Unfilled::Malformed => "the workstation's git gave lines it does not write",
            Unfilled::Incomplete => "the workstation's git gave no credential the remote can use",
        })
    }
}

impl std::error::Error for Unfilled {}

/// A credential released for one request: held only until it is written to
/// the remote, and erased when dropped.
#[derive(PartialEq, Eq)]
pub struct Released {
    username: Option<String>,
    password: Option<String>,
    /// When the workstation's helper says the password stops working, in
    /// seconds since 1970, as `git` writes it.
    expiry: Option<String>,
    authtype: Option<String>,
    credential: Option<String>,
    ephemeral: bool,
}

impl Drop for Released {
    fn drop(&mut self) {
        for held in [
            &mut self.username,
            &mut self.password,
            &mut self.authtype,
            &mut self.credential,
        ]
        .into_iter()
        .flatten()
        {
            held.zeroize();
        }
    }
}

impl fmt::Debug for Released {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Released(redacted)")
    }
}

/// Reads what the workstation's `git credential fill` printed, for a remote
/// whose `git` reads a bearer credential where `bearer` is true. A refresh
/// token, and every line `git` writes that the remote's `git` does not need,
/// is passed over and never reaches the remote.
///
/// # Errors
///
/// [`Unfilled`], saying why there is nothing to release.
pub fn released(filled: &[u8], bearer: bool) -> Result<Released, Unfilled> {
    if filled.len() > LONGEST {
        return Err(Unfilled::TooLong);
    }
    let mut released = Released {
        username: None,
        password: None,
        expiry: None,
        authtype: None,
        credential: None,
        ephemeral: false,
    };
    for line in filled.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let at = line
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(Unfilled::Malformed)?;
        let (key, rest) = line.split_at(at);
        let held = rest.get(1..).unwrap_or_default();
        let text = || {
            let text = std::str::from_utf8(held).map_err(|_| Unfilled::Malformed)?;
            if text.chars().any(char::is_control) {
                return Err(Unfilled::Malformed);
            }
            Ok(text.to_owned())
        };
        match key {
            b"username" => released.username = Some(text()?),
            b"password" => released.password = Some(text()?),
            b"password_expiry_utc" if !held.is_empty() && held.iter().all(u8::is_ascii_digit) => {
                released.expiry = Some(text()?);
            }
            b"authtype" if bearer => released.authtype = Some(text()?),
            b"credential" if bearer => released.credential = Some(text()?),
            b"ephemeral" if bearer => released.ephemeral = held == b"1" || held == b"true",
            _ => {}
        }
    }
    let pair = released.username.is_some() && released.password.is_some();
    let token = released.authtype.is_some() && released.credential.is_some();
    if pair || token {
        Ok(released)
    } else {
        Err(Unfilled::Incomplete)
    }
}

impl Released {
    /// The answer the remote's `git` is given, as `git`'s own daemon writes
    /// one (`credential-cache--daemon.c:134-156`).
    pub fn answer(&self) -> Zeroizing<Vec<u8>> {
        let mut answer = Zeroizing::new(Vec::new());
        let mut line = |key: &str, value: &str| {
            answer.extend_from_slice(key.as_bytes());
            answer.push(b'=');
            answer.extend_from_slice(value.as_bytes());
            answer.push(b'\n');
        };
        if let (Some(authtype), Some(credential)) = (&self.authtype, &self.credential) {
            line("capability[]", "authtype");
            line("authtype", authtype);
            line("credential", credential);
            if self.ephemeral {
                line("ephemeral", "1");
            }
        }
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            line("username", username);
            line("password", password);
        }
        if let Some(expiry) = &self.expiry {
            line("password_expiry_utc", expiry);
        }
        answer
    }
}
