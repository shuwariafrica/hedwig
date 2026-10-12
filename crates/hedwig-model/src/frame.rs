//! Bytes from a client, cut into frames.
//!
//! A frame is one line. The buffer that holds it is erased as soon as the
//! frame has been read, and erased before it is given up when it has to grow,
//! because a frame can be the person's answer to a prompt: a passphrase.

use crate::wire::FRAME;
use zeroize::Zeroize;

/// The size the buffer starts at: more than any frame but a document or a
/// page of activity.
const START: usize = 4096;

/// A frame longer than [`FRAME`] bytes. Nothing after it can be trusted to
/// start at a frame's beginning, so the connection ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overlong;

/// What arrived as a frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Line<'a> {
    Text(&'a str),
    /// A line that is not UTF-8.
    NotText,
}

pub struct Frames {
    bytes: Vec<u8>,
    /// How much of `bytes` holds what was read and not yet taken.
    filled: usize,
    /// Where the line returned by [`Frames::line`] ends, until it is erased.
    taken: usize,
}

impl Default for Frames {
    fn default() -> Frames {
        Frames {
            bytes: vec![0; START],
            filled: 0,
            taken: 0,
        }
    }
}

impl Frames {
    /// Where to read the next bytes into. The slice is never empty.
    ///
    /// # Errors
    ///
    /// [`Overlong`] when more than [`FRAME`] bytes have arrived with no end
    /// of line among them.
    pub fn room(&mut self) -> Result<&mut [u8], Overlong> {
        self.erase();
        if self.filled == self.bytes.len() {
            if self.filled > FRAME {
                return Err(Overlong);
            }
            // One byte past the limit, so an overlong frame is seen as one.
            let larger = (self.bytes.len() * 2).min(FRAME + 1);
            let mut grown = vec![0; larger];
            if let Some(start) = grown.get_mut(..self.filled) {
                start.copy_from_slice(&self.bytes);
            }
            // The old buffer is given back to the allocator empty.
            self.bytes.zeroize();
            self.bytes = grown;
        }
        Ok(self.bytes.get_mut(self.filled..).unwrap_or_default())
    }

    /// Records that `count` bytes were read into the slice [`Frames::room`]
    /// gave.
    pub fn filled(&mut self, count: usize) {
        self.filled = (self.filled + count).min(self.bytes.len());
    }

    /// The next whole frame, if one has arrived. It stays in the buffer until
    /// [`Frames::erase`], which the reader calls as soon as it has parsed it.
    pub fn line(&mut self) -> Option<Line<'_>> {
        self.erase();
        let end = self
            .bytes
            .get(..self.filled)?
            .iter()
            .position(|byte| *byte == b'\n')?;
        self.taken = end + 1;
        let line = self.bytes.get(..end)?;
        Some(std::str::from_utf8(line).map_or(Line::NotText, Line::Text))
    }

    /// Erases the frame last returned and moves what follows it to the front.
    pub fn erase(&mut self) {
        if self.taken == 0 {
            return;
        }
        let rest = self.filled - self.taken;
        self.bytes.copy_within(self.taken..self.filled, 0);
        if let Some(vacated) = self.bytes.get_mut(rest..self.filled) {
            vacated.zeroize();
        }
        self.filled = rest;
        self.taken = 0;
    }
}

impl Drop for Frames {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
