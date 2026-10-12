//! Who holds a capability's source on this workstation, and whether a
//! remote's connection may be carried to it.
//!
//! The holder is the process listening at a source's port or serving its
//! pipe, read by the core after its own connection is made and before any of
//! the remote's bytes are sent. One rule decides every source: the person -
//! a token Windows itself would admit to the person's own pipe - or a
//! service an administrator installed; every other holder is refused, saying
//! what was read of it.

use std::fmt;

use crate::text::{Location, ServiceName};
use crate::trail::Failure;

/// What a holder's token is to the person, as Windows' own access check
/// against the person's own pipe descriptor and the token's account say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Standing {
    /// The check admits it: the account, at medium integrity or above, not
    /// restricted to less, not in an application container.
    Person,
    /// The person's account, which the check refuses: Windows confines it.
    Confined,
    /// Another account.
    Another,
}

/// How the holder's logon was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignedIn {
    /// At the workstation or over Remote Desktop: a desktop's logon.
    Locally,
    /// Over the network, with no desktop: an SSH logon among others.
    OverTheNetwork,
}

/// Whether the holder's token carries the administrator's rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rights {
    Standard,
    Administrator,
}

/// What the core read of a holder's token, where Windows let it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub standing: Standing,
    /// The logon session (`AuthenticationId`).
    pub logon: u64,
    pub signed_in: SignedIn,
    pub rights: Rights,
}

/// Whose a holder is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Whose {
    /// The person, in any of their logons, sessions and levels.
    Person {
        logon: u64,
        signed_in: SignedIn,
        rights: Rights,
    },
    /// The service control manager runs these services in it.
    Service { services: Vec<ServiceName> },
    /// The person's account, which Windows confines below the person: low or
    /// untrusted integrity, a token restricted to less than the account, an
    /// application container.
    Confined,
    /// Another account's.
    Another,
    /// Windows would not let the core read its token, and it runs no service.
    Unread,
}

/// Whose a process is, from what was read of its token - `None` where
/// Windows would not open it - and the services the service control manager
/// runs in it, which are asked only where the token does not settle it.
pub fn whose(token: Option<Reading>, services: impl FnOnce() -> Vec<ServiceName>) -> Whose {
    match token {
        Some(Reading {
            standing: Standing::Person,
            logon,
            signed_in,
            rights,
        }) => Whose::Person {
            logon,
            signed_in,
            rights,
        },
        token => {
            let services = services();
            if !services.is_empty() {
                return Whose::Service { services };
            }
            match token {
                Some(Reading {
                    standing: Standing::Another,
                    ..
                }) => Whose::Another,
                Some(_) => Whose::Confined,
                None => Whose::Unread,
            }
        }
    }
}

/// The process holding a capability's source, as the core read it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceHolder {
    /// The program: the file it runs from where Windows let the core open
    /// the process, else the name the system lists it under.
    pub program: Location,
    /// The Windows session it runs in: 0 for a service, and for a sign-in
    /// over the network, which has no desktop.
    pub session: u32,
    pub whose: Whose,
}

impl SourceHolder {
    /// Whether a remote's connection may be carried to it.
    ///
    /// # Errors
    ///
    /// The source failing for what was read: [`Failure::Confined`],
    /// [`Failure::Foreign`] or [`Failure::Unidentified`].
    pub fn admitted(&self) -> Result<(), Failure> {
        match self.whose {
            Whose::Person { .. } | Whose::Service { .. } => Ok(()),
            Whose::Confined => Err(Failure::Confined),
            Whose::Another => Err(Failure::Foreign),
            Whose::Unread => Err(Failure::Unidentified),
        }
    }
}

/// The holder as the person reads it: its program, then whose it is and
/// where it runs, each only as read.
impl fmt::Display for SourceHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let session = self.session;
        match &self.whose {
            Whose::Person {
                signed_in, rights, ..
            } => {
                write!(f, "{}, yours, in session {session}", self.program)?;
                if *signed_in == SignedIn::OverTheNetwork {
                    f.write_str(", signed in over the network")?;
                }
                if *rights == Rights::Administrator {
                    f.write_str(", as administrator")?;
                }
                Ok(())
            }
            Whose::Service { services } => {
                write!(f, "{}, which runs the service", self.program)?;
                if services.len() > 1 {
                    f.write_str("s")?;
                }
                for (at, service) in services.iter().enumerate() {
                    f.write_str(if at == 0 { " " } else { ", " })?;
                    write!(f, "{service}")?;
                }
                f.write_str(" an administrator installed")
            }
            Whose::Confined => write!(
                f,
                "{}, yours but confined by Windows to less than you, in session {session}",
                self.program
            ),
            Whose::Another => write!(
                f,
                "{}, another account's, in session {session}",
                self.program
            ),
            Whose::Unread => write!(
                f,
                "{} in session {session}, which Windows does not let Hedwig read",
                self.program
            ),
        }
    }
}
