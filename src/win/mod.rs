//! All `unsafe` in the crate lives here; every sibling module forbids it.

pub(crate) mod net;
pub(crate) mod peer;
pub(crate) mod registry;
pub(crate) mod time;

/// Keeps a console window from flashing when the relay is spawned at logon.
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;
