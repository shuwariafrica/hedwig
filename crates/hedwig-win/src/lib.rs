//! The one crate of Hedwig that calls Windows directly.
//!
//! Every other crate forbids `unsafe`; what they need of the platform is here,
//! behind safe functions that own their handles and buffers for as long as the
//! system can touch them. Start with [`pipe`] for the control channel,
//! [`token`] for what is read of a client, [`process`] for the supervisor's
//! job and a channel's, [`start`] for a start that hands nothing on,
//! [`search`] for the program a start is made from, [`version`] for the
//! release that program states, [`endpoint`] for the workstation end of a
//! forward and who connects to it, [`access`] for whether a process could read
//! a file itself, [`registry`] for where an installer says it put a program,
//! [`clock`] for the clock deadlines are kept on, [`power`] for being told of
//! sleep and waking, [`services`] for whether a process runs a service an
//! administrator installed, [`shell`] for what Windows opens an address
//! with, [`serial`] for the workstation's serial ports, and [`tpm`] for keys
//! the workstation's TPM holds.

pub mod access;
pub mod clock;
pub mod endpoint;
pub mod file;
pub mod folder;
pub mod holder;
pub mod in_use;
pub mod network;
pub mod pack;
pub mod pipe;
pub mod power;
pub mod process;
pub mod random;
mod raw;
pub mod registry;
pub mod search;
pub mod serial;
pub mod services;
pub mod shell;
pub mod shortcut;
pub mod start;
pub mod token;
pub mod tpm;
pub mod version;

pub use raw::Signal;
