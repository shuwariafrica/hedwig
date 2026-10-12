//! What a remote platform's own SSH server and tools can carry.
//!
//! Nothing branches on a platform's name. A platform is the profile below, and
//! every decision reads a member of it, so a platform nobody has met is a new
//! profile - in the shipped catalogue or in a person's configuration - and no
//! code changes.

use std::num::NonZeroU16;

use crate::refusal::Refusal;
use crate::text::{Kernel, Name, RemotePath};

/// How a program on the platform reaches a local service, which decides what
/// the far end of a forward has to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sockets {
    /// The SSH server binds Unix-domain sockets and tools connect to them.
    /// `path_bytes` is the platform's `sun_path` size, terminator included.
    Unix { path_bytes: NonZeroU16 },
    /// The SSH server binds no Unix-domain socket. `GnuPG` there reads a file
    /// naming a loopback port and sixteen bytes to present on it.
    Emulated,
}

/// Whether the platform's SSH server creates an agent socket for a session
/// opened with agent forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentForwarding {
    Served,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Platform {
    pub family: Name,
    /// What a remote of this platform calls its own system, by which
    /// readiness knows the platform of a remote it reaches.
    pub kernel: Kernel,
    pub sockets: Sockets,
    pub agent_forwarding: AgentForwarding,
}

impl Platform {
    /// Checks a socket path against the platform's limit, before a forward to
    /// it is asked for.
    ///
    /// # Errors
    ///
    /// [`Refusal::SocketPathTooLong`] when the path and its terminator exceed
    /// `sun_path`; [`Refusal::NoUnixSockets`] where the platform binds none.
    pub fn admits(&self, path: &RemotePath) -> Result<(), Refusal> {
        match self.sockets {
            Sockets::Emulated => Err(Refusal::NoUnixSockets {
                platform: self.family.clone(),
            }),
            Sockets::Unix { path_bytes } => {
                let usable = path_bytes.get() - 1;
                // A remote path is at most 4096 bytes, so its length fits.
                let length = u16::try_from(path.as_str().len()).unwrap_or(u16::MAX);
                if length > usable {
                    Err(Refusal::SocketPathTooLong { usable, length })
                } else {
                    Ok(())
                }
            }
        }
    }
}
