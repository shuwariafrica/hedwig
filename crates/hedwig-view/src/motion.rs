//! How a menu flyout opens, as WinUI opens one.
//!
//! WinUI's `MenuPopupThemeTransition` (release 2.5.1,
//! `dxaml/xcp/dxaml/lib/LayoutTransition_partial.cpp`): over 250 ms on
//! `cubic-bezier(0,0,0,1)` the menu's border grows from a fraction of its
//! height to all of it, away from where it was opened, and its rows move
//! with the edge that moves, so the rows nearest that edge are the first
//! seen. The fraction is 0.5 for the menu and 0.67 closed, a third open, for
//! a menu opened from one of its rows. None of it plays unless the person
//! has Windows animate.

use crate::arrange::Rect;
use crate::style::Rgb;

/// How long the menu takes to open, in milliseconds
/// (`MenuPopupThemeTransition::s_OpenDuration`).
pub const OPENING: u32 = 250;

/// Which way the menu grows as it opens: away from the point it was opened
/// at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grows {
    /// It stands above that point: its bottom stays, its top rises.
    Up,
    /// It stands below it, or beside a row: its top stays.
    Down,
}

/// How much of it is not yet shown when it begins to open.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Closed {
    /// The icon's menu: half (`MenuFlyout`, `closedRatioConstant` 0.5).
    Menu,
    /// A remote's menu, opened from its row (`MenuFlyoutSubItem`, 0.67).
    Sub,
}

impl Closed {
    fn ratio(self) -> f32 {
        match self {
            Closed::Menu => 0.5,
            Closed::Sub => 0.67,
        }
    }
}

/// `cubic-bezier(0,0,0,1)` at `t` in 0 to 1. Its first control point and its
/// second's time are 0, so time is the cube of the curve's parameter and the
/// value `3s^2 - 2s^3` of it.
pub fn ease(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    let s = t.cbrt();
    3.0 * s * s - 2.0 * s * s * s
}

/// Where a level of the menu stands `elapsed` milliseconds after it began to
/// open, and how far its rows are moved up within it so the edge that moves
/// carries them: `None` once it is open.
pub fn opening(full: Rect, grows: Grows, closed: Closed, elapsed: u32) -> Option<(Rect, i32)> {
    if elapsed >= OPENING {
        return None;
    }
    #[allow(
        clippy::cast_precision_loss,
        reason = "milliseconds below 250 are exact in a float"
    )]
    let progress = ease(elapsed as f32 / OPENING as f32);
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "a menu's height is far below the 24 bits a float holds exactly"
    )]
    let hidden = ((full.height as f32) * closed.ratio() * (1.0 - progress)).round() as i32;
    let height = full.height - hidden;
    Some(match grows {
        Grows::Up => (
            Rect {
                top: full.top + hidden,
                height,
                ..full
            },
            0,
        ),
        Grows::Down => (Rect { height, ..full }, hidden),
    })
}

/// How long a button's fill takes to become another, in milliseconds: WinUI's
/// `BrushTransition` on a button (`Button_themeresources.xaml:174` at
/// release 2.5.1). Its edge and text change at once.
pub const FILL: u32 = 83;

/// A button's fill `elapsed` milliseconds into becoming `to` from `from`:
/// each component stepped linearly, as XAML interpolates a colour; `to` once
/// [`FILL`] has passed. A change during a change starts from the fill then
/// shown, as WinUI's does.
pub fn filled(from: Rgb, to: Rgb, elapsed: u32) -> Rgb {
    if elapsed >= FILL {
        return to;
    }
    let step = |from: u8, to: u8| {
        let (from, to) = (i64::from(from), i64::from(to));
        u8::try_from(from + (to - from) * i64::from(elapsed) / i64::from(FILL)).unwrap_or(u8::MAX)
    };
    Rgb {
        red: step(from.red, to.red),
        green: step(from.green, to.green),
        blue: step(from.blue, to.blue),
    }
}
