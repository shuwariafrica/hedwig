//! The one crate of Hedwig's interface that calls Windows directly.
//!
//! What the interface shows is decided in `hedwig-view`; this crate puts it
//! on the screen with what Windows itself provides and decides nothing:
//!
//! - [`host`] - the one unshown window and its message loop;
//! - [`icon`] - the notification-area icon, its tooltip and its notifications;
//! - [`card`] - the window a held request is answered from, never given the
//!   focus, and of the same construction the confirmation of an act the
//!   person chose, which has it;
//! - [`menu`] - the icon's menu, a flyout window of its own;
//! - [`settings`] - what the person has set in Windows that a painted surface
//!   answers to;
//! - [`desk`] - what this session and its desktop are;
//! - [`window`] - Hedwig's window beside the presence: one for each person,
//!   desktop and Hedwig, and the foreground handed on to it;
//! - [`pick`] - the shell's dialog for choosing a file to read or write;
//! - [`place`] - where Hedwig's window opens, and where it was when it went;
//! - [`question`] - a card put by a program of Hedwig's with no icon: setup,
//!   and removal;
//! - [`clock`] - a moment as the person's Windows writes one;
//! - [`record`] - the supervisor's record, watched.
//!
//! The card, the confirmation and the menu are made of Windows' own controls, so the keyboard
//! and a screen reader are served by Windows; what the controls cannot look
//! like by themselves - Windows 11's layers, buttons and rows - is drawn here
//! from the pictures `hedwig-view` computes, and their text is set by
//! DirectWrite, as WinUI sets it. The bindings are `windows-sys`, the crate
//! the core already carries, and declarations of this crate's own where it
//! has none: DirectWrite, Direct2D and Active Accessibility's annotation
//! service, called by the places of their tables.
//!
//! An executable that links this crate needs the interface's manifest:
//! Windows' controls are fully exposed to UI Automation only in version 6 of
//! the common controls, which the manifest selects.

mod annotation;
pub mod card;
pub mod clock;
mod com;
mod compose;
pub mod desk;
mod draw;
mod effect;
pub mod host;
pub mod icon;
pub mod menu;
pub mod pick;
pub mod place;
pub mod question;
mod raw;
pub mod record;
pub mod settings;
pub mod window;
mod write;
