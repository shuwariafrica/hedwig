//! What a token says about the process that holds it.
//!
//! The core reads these of itself and of each control client. They are
//! recorded and shown; nothing here decides anything.

use std::fmt;
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
    PSID, SID_AND_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER, TokenElevation, TokenGroups,
    TokenIntegrityLevel, TokenSessionId, TokenStatistics, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::raw::{Local, owned};

/// A security identifier, held as its own bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// Copies the identifier `raw` points at.
    ///
    /// # Safety
    ///
    /// `raw` must point at memory readable for as long as a security
    /// identifier can be, 68 bytes, or be null.
    pub(crate) unsafe fn copy(raw: PSID) -> io::Result<Sid> {
        // SAFETY: the caller guarantees the memory is readable; the function
        // itself rejects what is not an identifier.
        if raw.is_null() || unsafe { IsValidSid(raw) } == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        // SAFETY: `raw` was just found to be a valid identifier.
        let length = unsafe { GetLengthSid(raw) } as usize;
        // SAFETY: a valid identifier is `length` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), length) };
        Ok(Sid(bytes.to_vec()))
    }

    /// The identifier `text` writes, such as `S-1-5-32-544`.
    pub fn from_text(text: &str) -> io::Result<Sid> {
        let text = crate::raw::wide(text);
        let mut raw = std::ptr::null_mut();
        // SAFETY: `text` is NUL-terminated and `raw` receives memory `Local`
        // frees.
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &raw mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let held = Local(raw);
        // SAFETY: on success `raw` points at a valid identifier, alive until
        // `held` drops.
        let sid = unsafe { Sid::copy(held.0) };
        drop(held);
        sid
    }

    pub(crate) fn as_raw(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }

    /// The identifier as Windows writes it: `S-1-5-21-...`.
    pub fn to_text(&self) -> io::Result<String> {
        let mut text = std::ptr::null_mut();
        // SAFETY: `self` holds a valid identifier, and `text` receives memory
        // that `Local` frees.
        if unsafe { ConvertSidToStringSidW(self.as_raw(), &raw mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let held = Local(text.cast());
        // SAFETY: on success `text` is a NUL-terminated string, freed only
        // when `held` drops after this read.
        let length = unsafe { wide_length(text) };
        // SAFETY: the string is `length` units long, as just measured.
        let units = unsafe { std::slice::from_raw_parts(text, length) };
        let text = String::from_utf16_lossy(units);
        drop(held);
        Ok(text)
    }

    /// The last number of the identifier: for an integrity label, its level.
    fn last(&self) -> u32 {
        // SAFETY: `self` holds a valid identifier.
        let count = unsafe { GetSidSubAuthorityCount(self.as_raw()) };
        // SAFETY: for a valid identifier the pointer is to its count.
        let count = unsafe { *count };
        if count == 0 {
            return 0;
        }
        // SAFETY: the identifier has `count` sub-authorities and this is the
        // last of them.
        let last = unsafe { GetSidSubAuthority(self.as_raw(), u32::from(count) - 1) };
        // SAFETY: the pointer is to that sub-authority, inside `self`.
        unsafe { *last }
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_text() {
            Ok(text) => f.write_str(&text),
            Err(_) => f.write_str("Sid(unprintable)"),
        }
    }
}

/// The number of UTF-16 units before the terminator.
///
/// # Safety
///
/// `text` must point at a NUL-terminated wide string.
pub(crate) unsafe fn wide_length(text: *const u16) -> usize {
    let mut length = 0;
    loop {
        // SAFETY: every unit up to and including the terminator is in the
        // string, so this stays inside it.
        let unit = unsafe { text.add(length) };
        // SAFETY: as above, the unit is readable.
        if unsafe { *unit } == 0 {
            return length;
        }
        length += 1;
    }
}

/// Where a process stands, as its token records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    /// The logon session: two logons of one account differ here and nowhere
    /// in their user identifier.
    pub logon: u64,
    pub session: u32,
    /// The integrity level as Windows numbers it: 0x2000 medium, 0x3000 high.
    pub integrity: u32,
}

/// A token opened for reading.
#[derive(Debug)]
pub struct Token(OwnedHandle);

impl From<OwnedHandle> for Token {
    /// A token handle this process already holds, such as one it made with
    /// less than its own.
    fn from(handle: OwnedHandle) -> Token {
        Token(handle)
    }
}

impl Token {
    /// This process's own token.
    pub fn own() -> io::Result<Token> {
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle for this process is always valid.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: `handle` is a valid place for the opened token.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        owned(handle).map(Token)
    }

    pub(crate) fn from_handle(handle: OwnedHandle) -> Token {
        Token(handle)
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }

    /// One class of information, in a buffer aligned for any of them.
    fn information(&self, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
        let mut needed = 0u32;
        // SAFETY: a null buffer of length zero asks only for the size.
        unsafe {
            GetTokenInformation(
                self.0.as_raw_handle(),
                class,
                std::ptr::null_mut(),
                0,
                &raw mut needed,
            )
        };
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        // A fixed-size class is refused with `ERROR_BAD_LENGTH` given more
        // than its size (`TokenElevation`, measured), so the size asked for is
        // the size given.
        let size = if needed == 0 {
            u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX)
        } else {
            needed
        };
        // SAFETY: `buffer` is at least `size` writable bytes.
        let read = unsafe {
            GetTokenInformation(
                self.0.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                size,
                &raw mut needed,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }

    /// The account the token is for.
    pub fn user(&self) -> io::Result<Sid> {
        let buffer = self.information(TokenUser)?;
        // SAFETY: a successful `TokenUser` query wrote a `TOKEN_USER` at the
        // start of the buffer, which is aligned for it.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        // SAFETY: the identifier the structure points at lies inside `buffer`,
        // which is alive.
        unsafe { Sid::copy(user.User.Sid) }
    }

    /// Whether the token carries the administrator's rights: an elevated
    /// window, or an administrator's sign-in over the network.
    pub fn elevated(&self) -> io::Result<bool> {
        let buffer = self.information(TokenElevation)?;
        // SAFETY: a successful `TokenElevation` query wrote the structure at
        // the start of the aligned buffer.
        let elevation = unsafe { &*buffer.as_ptr().cast::<TOKEN_ELEVATION>() };
        Ok(elevation.TokenIsElevated != 0)
    }

    /// Whether the logon signed in over the network: Windows puts `NETWORK`
    /// (`S-1-5-2`) among the groups of such a logon's token, an SSH logon's
    /// among them, and of no desktop's.
    pub fn over_the_network(&self) -> io::Result<bool> {
        let network = Sid::from_text("S-1-5-2")?;
        let buffer = self.information(TokenGroups)?;
        // SAFETY: a successful `TokenGroups` query wrote the structure at the
        // start of the aligned buffer, its groups following it there.
        let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
        // SAFETY: the structure is followed by `GroupCount` entries inside
        // `buffer`, which is alive.
        let entries = unsafe {
            std::slice::from_raw_parts(
                groups.Groups.as_ptr().cast::<SID_AND_ATTRIBUTES>(),
                groups.GroupCount as usize,
            )
        };
        Ok(entries.iter().any(|entry| {
            // SAFETY: each identifier lies inside `buffer`.
            unsafe { Sid::copy(entry.Sid) }.is_ok_and(|sid| sid == network)
        }))
    }

    pub fn standing(&self) -> io::Result<Standing> {
        let statistics = self.information(TokenStatistics)?;
        // SAFETY: a successful `TokenStatistics` query wrote the structure at
        // the start of the aligned buffer.
        let statistics = unsafe { &*statistics.as_ptr().cast::<TOKEN_STATISTICS>() };
        let logon = statistics.AuthenticationId;
        let session = self.information(TokenSessionId)?;
        // SAFETY: a successful `TokenSessionId` query wrote a `u32`.
        let session = unsafe { *session.as_ptr().cast::<u32>() };
        let label = self.information(TokenIntegrityLevel)?;
        // SAFETY: a successful `TokenIntegrityLevel` query wrote the structure
        // at the start of the aligned buffer.
        let level = unsafe { &*label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
        // SAFETY: the identifier the structure points at lies inside `label`,
        // which is alive.
        let level = unsafe { Sid::copy(level.Label.Sid) }?;
        Ok(Standing {
            logon: (u64::from(logon.HighPart.cast_unsigned()) << 32) | u64::from(logon.LowPart),
            session,
            integrity: level.last(),
        })
    }
}
