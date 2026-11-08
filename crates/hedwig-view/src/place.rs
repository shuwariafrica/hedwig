//! Where the person left the window: its restored rectangle on the screen,
//! whether it was maximised, and the scale of the monitor it was on, kept
//! between one opening of the window and the next.
//!
//! A minimised window is kept as what it would be restored to, so the next
//! opening never starts minimised.

use std::fmt;

/// The window's place, in the screen's physical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub maximised: bool,
    /// The dots per inch of the monitor the rectangle was on.
    pub dpi: u32,
}

/// A kept placement this build cannot read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable;

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a window's placement")
    }
}

impl std::error::Error for Unreadable {}

/// The fewest pixels a side may have and still be a window the person can
/// take hold of; anything smaller is not kept.
const LEAST: i32 = 64;

impl Placement {
    /// One line: the rectangle, `maximised` or `restored`, and the scale.
    pub fn written(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.left,
            self.top,
            self.right,
            self.bottom,
            if self.maximised {
                "maximised"
            } else {
                "restored"
            },
            self.dpi
        )
    }

    /// Reads what [`Placement::written`] wrote.
    ///
    /// # Errors
    ///
    /// [`Unreadable`] for anything else, or for a rectangle too small to be
    /// a window or a scale of none.
    pub fn read(text: &str) -> Result<Placement, Unreadable> {
        let mut words = text.split_whitespace();
        let mut number = || words.next().and_then(|word| word.parse::<i32>().ok());
        let (Some(left), Some(top), Some(right), Some(bottom)) =
            (number(), number(), number(), number())
        else {
            return Err(Unreadable);
        };
        let maximised = match words.next() {
            Some("maximised") => true,
            Some("restored") => false,
            _ => return Err(Unreadable),
        };
        let dpi = words
            .next()
            .and_then(|word| word.parse::<u32>().ok())
            .filter(|dpi| *dpi > 0)
            .ok_or(Unreadable)?;
        let placement = Placement {
            left,
            top,
            right,
            bottom,
            maximised,
            dpi,
        };
        if words.next().is_some() || placement.width() < LEAST || placement.height() < LEAST {
            return Err(Unreadable);
        }
        Ok(placement)
    }

    pub fn width(&self) -> i32 {
        self.right.saturating_sub(self.left)
    }

    pub fn height(&self) -> i32 {
        self.bottom.saturating_sub(self.top)
    }

    /// The same window on a monitor of `dpi`: as large to the eye, from the
    /// same corner, to the nearest pixel.
    #[must_use]
    pub fn scaled(&self, dpi: u32) -> Placement {
        if dpi == self.dpi || dpi == 0 {
            return *self;
        }
        let side = |pixels: i32| {
            let from = i64::from(self.dpi);
            let scaled = (i64::from(pixels) * i64::from(dpi) + from / 2) / from;
            i32::try_from(scaled).unwrap_or(i32::MAX)
        };
        Placement {
            right: self.left.saturating_add(side(self.width())),
            bottom: self.top.saturating_add(side(self.height())),
            dpi,
            ..*self
        }
    }
}
