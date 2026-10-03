//! Hedwig's core, and the supervisor that runs it.
//!
//! One supervisor per person holds a record where clients look
//! ([`record`]) and runs one core as its child, starting another when that
//! one breaks down ([`supervise`]). The core keeps a trail and a
//! configuration on disk ([`store`]), serves the control pipe ([`serve`]),
//! and decides everything on one thread, as a function from what arrived to
//! what follows ([`dispatch`]). [`run`] is that thread. A channel to a remote
//! is the route's client held in a job of its own ([`channel`]), and what
//! connects to the core is read the same way at every door ([`peer`]). A
//! connection admitted at a forward's end is carried to the person's
//! gpg-agent by [`relay`], to a workstation service by [`service`], to the
//! workstation's ADB server by [`adb`], to the workstation's browser by
//! [`browse`], to a serial port of the workstation's by [`serial`], or to the
//! person's own SSH agent by [`ssh`], whose protocol [`agent`] reads; a key
//! the workstation's TPM holds is answered for by the core in [`machine`].
//!
//! Nothing here contains `unsafe`: what is needed of Windows is in
//! `hedwig-win`.

#![forbid(unsafe_code)]

use std::time::Duration;

pub mod adb;
pub mod agent;
pub mod assuan;
pub mod browse;
pub mod channel;
pub mod console;
pub mod credential;
pub mod devices;
pub mod diagnostics;
pub mod dispatch;
pub mod holder;
pub mod keys;
pub mod listing;
pub mod machine;
pub mod notify;
pub mod peer;
pub mod record;
pub mod relay;
pub mod rfc2217;
pub mod run;
pub mod serial;
pub mod serve;
pub mod service;
pub mod ssh;
pub mod startup;
pub mod store;
pub mod supervise;
pub mod survey;
pub mod timer;

/// How long something may go unanswered before it is taken to be stuck: the
/// figure Windows itself uses for a program that is not responding. A
/// supervisor allows its core this long to answer, and a connection the core
/// is ending is given this long to be read.
pub const PATIENCE: Duration = Duration::from_secs(5);
