//! Everything Hedwig's interface shows and offers, as a function of what the
//! core said.
//!
//! The interface owns no state of Hedwig's. [`link::Link`] turns the record,
//! the pipe and the core's frames into [`link::Seen`]; each surface is a
//! function of that and of nothing else:
//!
//! - [`glance`] - the notification-area icon: what it says at a glance, its
//!   tooltip and its menu, and [`menu`] - where each row of that menu goes and
//!   what each key does in it;
//! - [`card`] - the one request or prompt that is asking the person now, and
//!   [`arrange`] - where each part of it goes on the monitor it is shown on;
//! - [`exposure`] - the window: what is reachable from where, and the first
//!   grant when nothing is;
//! - [`grant`] - a grant being made;
//! - [`setting`] - every other setting, where it comes from and what holds
//!   it, as the window shows it;
//! - [`trial`] - a configuration to export, and one to import tried before
//!   it is made, and [`bundle`] - what a supporter is given, shown before it
//!   is saved;
//! - [`place`] - where the person left the window, kept for its next opening;
//! - [`emblem`] - Hedwig's logo as the icon and the executables show it;
//! - [`presence`] - whether this desktop can show the person anything;
//! - [`removal`] - what removal from Settings shows, from what Hedwig wrote
//!   on each remote to what it could not take back;
//! - [`resource`] - what Windows reads of an executable to name it and show
//!   its icon;
//! - [`setup`] - setup's one question, and what it says while it installs
//!   and where it could not;
//! - [`style`] - what the surfaces Hedwig paints are drawn in, from what the
//!   person has set in Windows, and [`paint`] - the pixels of their controls;
//! - [`words`] - the sentences all of them share, and [`fingerprint`] - an
//!   SSH key's type and fingerprint as OpenSSH prints them.
//!
//! Nothing here draws, opens a pipe or reads a clock, so every state of every
//! surface is checked without a desktop. What draws is `hedwig-shell`.
//!
//! # Examples
//!
//! With no Hedwig running, the icon says so and its menu offers to start it:
//!
//! ```
//! use hedwig_client::Standing;
//! use hedwig_view::act::Act;
//! use hedwig_view::glance::{self, Glance, Reach};
//! use hedwig_view::link::{Event, Link};
//!
//! let mut link = Link::default();
//! link.handle(Event::Looked(Standing::Absent));
//!
//! let glance = Glance::of(link.seen());
//! assert_eq!(glance.reach, Reach::Off);
//! assert_eq!(glance.tip(), "Hedwig is not running");
//! assert_eq!(glance::chosen(link.seen()), Act::Start);
//! ```
//!
//! # What the types rule out
//!
//! Each of these fails to compile, and each is a thing that must never
//! happen.
//!
//! The interface never drives the core by running its command line: no act a
//! surface can offer carries a command.
//!
//! ```compile_fail,E0599
//! let act = hedwig_view::act::Act::Run("hedwig pause --all".to_owned());
//! ```
//!
//! What the interface knows of the core comes from the core: a link's state
//! is never assembled by a surface.
//!
//! ```compile_fail,E0451
//! use hedwig_view::link::Link;
//! let link = Link { open: true, ..Link::default() };
//! ```
//!
//! A tooltip is never longer than the shell keeps, because one is only ever
//! made by the function that fits it.
//!
//! ```compile_fail,E0451
//! use hedwig_view::glance::{Glance, Reach, Waiting};
//! let glance = Glance { reach: Reach::Quiet, waiting: Waiting::Nothing, tip: "x".repeat(500) };
//! ```
//!
//! Which request the card shows, and since when, is settled from what the
//! core says needs an answer and cannot be set.
//!
//! ```compile_fail,E0451
//! use hedwig_view::card::Deck;
//! let deck = Deck { since: 0, ..Deck::default() };
//! ```
//!
//! An answer the person types never passes through this crate: a card names
//! the prompt it answers, not the text.
//!
//! ```compile_fail,E0308
//! use hedwig_view::card::Does;
//! let does = Does::Typed("the passphrase".to_owned());
//! ```

#![forbid(unsafe_code)]

pub mod act;
pub mod arrange;
pub mod bundle;
pub mod card;
pub mod define;
pub mod emblem;
pub mod exposure;
pub mod fingerprint;
pub mod glance;
pub mod grant;
pub mod link;
pub mod menu;
pub mod motion;
pub mod paint;
pub mod place;
pub mod presence;
pub mod removal;
pub mod resource;
pub mod setting;
pub mod setup;
pub mod style;
pub mod trial;
pub mod words;
