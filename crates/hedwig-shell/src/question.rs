//! A card put to the person by a program of Hedwig's that has no icon of
//! its own: setup's question, and removal's account of what it took back.
//!
//! It is the confirmation's construction, shown in the middle of the work
//! area in the foreground with the keyboard on its safe answer, since the
//! person started the program that asks; it runs a message loop of its own
//! until the person answers, or while work the card waits on runs on another
//! thread, and makes the card again where the person's appearance changed.

use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use hedwig_view::card::Card;
use hedwig_view::style::Appearance;
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;

use crate::card::Shown;
use crate::host::{Host, Told};
use crate::pick::{self, Dialog};
use crate::settings;

/// The longest the loop waits for Windows when nothing is due sooner.
const IDLE: Duration = Duration::from_secs(3600);

/// The loop a program's cards are shown from, and the card shown now.
#[derive(Debug)]
pub struct Question {
    host: Host,
    title: String,
    shown: Option<(Shown, Appearance)>,
}

impl Question {
    /// A loop for cards titled `title`, with none shown yet.
    ///
    /// # Errors
    ///
    /// Windows refused the unshown window the loop runs on.
    pub fn new(title: &str) -> io::Result<Question> {
        Ok(Question {
            host: Host::new()?,
            title: title.to_owned(),
            shown: None,
        })
    }

    /// Shows `card` in place of the one shown, put to the person.
    fn show(&mut self, card: &Card) -> io::Result<()> {
        let appearance = settings::read();
        self.shown = None;
        let shown = Shown::new(&self.title, card, &appearance, None)?;
        shown.ask();
        self.shown = Some((shown, appearance));
        Ok(())
    }

    /// Makes the card again where what the person set reads otherwise than
    /// it was made with.
    fn changed(&mut self, card: &Card) -> io::Result<()> {
        if self
            .shown
            .as_ref()
            .is_none_or(|(_, made)| *made != settings::read())
        {
            self.show(card)?;
        }
        Ok(())
    }

    /// Puts `card` to the person and waits for their answer: the place of
    /// the answer that goes ahead, or `None` for the safe one, ESCAPE, the
    /// close box, and the program being asked to close.
    ///
    /// # Errors
    ///
    /// Windows refused the card's window.
    pub fn ask(&mut self, card: &Card) -> io::Result<Option<usize>> {
        self.show(card)?;
        loop {
            for told in self.host.told(IDLE) {
                match told {
                    Told::Confirmed(answer) => return Ok(answer.map(usize::from)),
                    Told::End => return Ok(None),
                    Told::Settings => self.changed(card)?,
                    _ => {}
                }
            }
        }
    }

    /// Shows `card` while `work` runs on a thread of its own, and returns
    /// what it returned. The card offers no answer: what it waits on cannot
    /// be stopped half-way, and closing it closes nothing but the card.
    ///
    /// # Errors
    ///
    /// Windows refused the card's window; the work runs to its end whatever
    /// was shown.
    pub fn during<T: Send + 'static>(
        &mut self,
        card: &Card,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> io::Result<T> {
        let shown = self.show(card);
        let (sender, receiver) = mpsc::channel();
        let waker = self.host.waker();
        let worker = thread::spawn(move || {
            let _ = sender.send(work());
            waker.wake();
        });
        loop {
            if let Ok(done) = receiver.try_recv() {
                let _ = worker.join();
                shown?;
                return Ok(done);
            }
            for told in self.host.told(IDLE) {
                if matches!(told, Told::Settings) && shown.is_ok() {
                    self.changed(card)?;
                }
            }
        }
    }

    /// The shell's dialog for choosing a file, owned by the card shown so it
    /// stands over it; `None` where the person cancelled.
    ///
    /// # Errors
    ///
    /// What the shell said.
    pub fn choose(&self, dialog: &Dialog<'_>) -> io::Result<Option<PathBuf>> {
        let owner = self
            .shown
            .as_ref()
            .map(|(shown, _)| shown.window() as isize);
        pick::choose(dialog, owner)
    }

    /// Takes the card shown off the screen.
    pub fn close(&mut self) {
        self.shown = None;
    }

    /// Puts `text` on the clipboard, in place of what was there, for the
    /// person to paste where they keep a note.
    ///
    /// # Errors
    ///
    /// Windows refused the clipboard or the memory it is handed in; the
    /// clipboard is then as it was.
    pub fn copy(&self, text: &str) -> io::Result<()> {
        let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
        let bytes = units.len() * size_of::<u16>();
        // SAFETY: the loop's own window owns the clipboard while it is open.
        if unsafe { OpenClipboard(self.host.window()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let handed = (|| {
            // SAFETY: no pointer; the memory is the clipboard's once handed.
            if unsafe { EmptyClipboard() } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a size and flags; the result is checked.
            let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
            if memory.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the memory was just allocated with `bytes` bytes.
            let at = unsafe { GlobalLock(memory) }.cast::<u16>();
            if at.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `at` is writable for `units.len()` units, which do not
            // overlap the vector they are copied from.
            unsafe { std::ptr::copy_nonoverlapping(units.as_ptr(), at, units.len()) };
            // SAFETY: the memory is unlocked once, as it was locked.
            unsafe { GlobalUnlock(memory) };
            // SAFETY: the clipboard is open and takes the memory over.
            if unsafe { SetClipboardData(u32::from(CF_UNICODETEXT), memory) }.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        // SAFETY: opened above by this thread.
        unsafe { CloseClipboard() };
        handed
    }
}

/// The name of the account this program runs as, as Windows logs it on.
///
/// # Errors
///
/// What Windows said.
pub fn account() -> io::Result<String> {
    let mut units = vec![0u16; 257];
    let mut length = u32::try_from(units.len()).unwrap_or_default();
    // SAFETY: the buffer is writable for `length` characters, which the call
    // reads and then sets to what it wrote, the terminator included.
    if unsafe { GetUserNameW(units.as_mut_ptr(), &raw mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let written = usize::try_from(length)
        .unwrap_or_default()
        .saturating_sub(1);
    String::from_utf16(units.get(..written).unwrap_or_default())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}
