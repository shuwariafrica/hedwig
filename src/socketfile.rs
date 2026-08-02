#![forbid(unsafe_code)]

use std::fmt;
use std::io::Read;
use std::path::Path;

use zeroize::Zeroize;

/// The file is five port digits, an LF and 16 nonce bytes. The slack lets a
/// longer file be rejected rather than silently truncated into something that
/// parses.
const MAX_SOCKET_FILE: usize = 64;

/// The 16 random bytes gpg-agent requires as the first bytes of every
/// connection to its emulated socket. Possession of the nonce is possession of
/// the agent, so the value is zeroised on drop and never printed.
///
/// Boxed because a move is a bitwise copy and `Drop` does not run on what was
/// moved out of: held inline, every move could strand an unzeroised copy in a
/// dead stack slot. Behind a box the moves carry the pointer, so one copy
/// exists and it is erased where it lies.
pub(crate) struct Nonce(Box<[u8; 16]>);

impl Nonce {
    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Drop for Nonce {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nonce(redacted)")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    Empty,
    /// `!<socket >` prefix: Cygwin's emulation, which needs a different
    /// handshake. Gpg4win writes the native format; refusing beats guessing.
    CygwinFormat,
    NoNewline,
    BadPort,
    BadNonceLength(usize),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "socket file is empty"),
            ParseError::CygwinFormat => {
                write!(f, "socket file is in Cygwin format, which is not supported")
            }
            ParseError::NoNewline => write!(f, "socket file has no port/nonce separator"),
            ParseError::BadPort => write!(f, "socket file port is not a number in 1..=65535"),
            ParseError::BadNonceLength(n) => {
                write!(f, "socket file nonce is {n} bytes, expected 16")
            }
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug)]
pub(crate) enum ReadError {
    Io(std::io::Error),
    Parse(ParseError),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "{e}"),
            ReadError::Parse(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Reads and parses on the stack, so no allocator copy of the nonce can
/// outlive the call however the file is sized.
pub(crate) fn read_from(path: &Path) -> Result<(u16, Nonce), ReadError> {
    let mut buf = [0u8; MAX_SOCKET_FILE];
    let filled = fill(path, &mut buf).map_err(ReadError::Io)?;
    #[allow(clippy::indexing_slicing, reason = "fill returns at most buf.len()")]
    let result = parse(&buf[..filled]).map_err(ReadError::Parse);
    buf.zeroize();
    result
}

fn fill(path: &Path, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut file = std::fs::File::open(path)?;
    let mut filled = 0;
    while filled < buf.len() {
        #[allow(clippy::indexing_slicing, reason = "filled < buf.len() above")]
        let n = file.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// The file gpg-agent writes in place of a Unix socket on Windows: ASCII
/// decimal port, LF, 16 nonce bytes.
pub(crate) fn parse(bytes: &[u8]) -> Result<(u16, Nonce), ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }
    if bytes.starts_with(b"!<socket >") {
        return Err(ParseError::CygwinFormat);
    }
    let lf = bytes
        .iter()
        .position(|b| *b == b'\n')
        .ok_or(ParseError::NoNewline)?;
    #[allow(clippy::indexing_slicing, reason = "lf is an index into bytes")]
    let digits = &bytes[..lf];
    if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(ParseError::BadPort);
    }
    // Folded rather than parsed so the untrusted path holds no panic site: the
    // length and digit checks above bound the result well inside u32.
    let port = digits
        .iter()
        .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'));
    let Ok(port) = u16::try_from(port) else {
        return Err(ParseError::BadPort);
    };
    if port == 0 {
        return Err(ParseError::BadPort);
    }
    #[allow(
        clippy::indexing_slicing,
        reason = "lf indexes the LF, so lf + 1 is in bounds"
    )]
    let nonce = &bytes[lf + 1..];
    if nonce.len() != 16 {
        return Err(ParseError::BadNonceLength(nonce.len()));
    }
    let mut boxed = Box::new([0u8; 16]);
    boxed.copy_from_slice(nonce);
    Ok((port, Nonce(boxed)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn file(port: &str, nonce_len: usize) -> Vec<u8> {
        let mut v = Vec::from(port.as_bytes());
        v.push(b'\n');
        v.extend(std::iter::repeat_n(0xA5, nonce_len));
        v
    }

    #[test]
    fn valid_four_digit_port() {
        let (port, nonce) = parse(&file("8467", 16)).unwrap();
        assert_eq!(port, 8467);
        assert_eq!(nonce.as_bytes(), &[0xA5; 16]);
    }

    #[test]
    fn valid_five_digit_port() {
        let (port, _) = parse(&file("65535", 16)).unwrap();
        assert_eq!(port, 65535);
    }

    #[test]
    fn valid_one_digit_port() {
        let (port, _) = parse(&file("7", 16)).unwrap();
        assert_eq!(port, 7);
    }

    #[test]
    fn empty_file() {
        assert_eq!(parse(&Vec::new()).unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn cygwin_format_refused() {
        let err = parse(b"!<socket >54321 s ABCD-EF01-2345-6789").unwrap_err();
        assert_eq!(err, ParseError::CygwinFormat);
    }

    #[test]
    fn missing_newline() {
        assert_eq!(parse(b"8467").unwrap_err(), ParseError::NoNewline);
    }

    #[test]
    fn port_zero_rejected() {
        assert_eq!(parse(&file("0", 16)).unwrap_err(), ParseError::BadPort);
    }

    #[test]
    fn port_too_large_rejected() {
        assert_eq!(parse(&file("65536", 16)).unwrap_err(), ParseError::BadPort);
    }

    #[test]
    fn port_too_many_digits_rejected() {
        assert_eq!(parse(&file("123456", 16)).unwrap_err(), ParseError::BadPort);
    }

    #[test]
    fn port_non_digit_rejected() {
        assert_eq!(parse(&file("84a7", 16)).unwrap_err(), ParseError::BadPort);
    }

    #[test]
    fn empty_port_rejected() {
        assert_eq!(parse(&file("", 16)).unwrap_err(), ParseError::BadPort);
    }

    #[test]
    fn nonce_too_short_rejected() {
        assert_eq!(
            parse(&file("8467", 15)).unwrap_err(),
            ParseError::BadNonceLength(15)
        );
    }

    #[test]
    fn nonce_too_long_rejected() {
        assert_eq!(
            parse(&file("8467", 17)).unwrap_err(),
            ParseError::BadNonceLength(17)
        );
    }

    /// Covers the read path itself: a file past the buffer must fail closed
    /// rather than truncate into something that parses.
    #[test]
    fn read_from_handles_absent_valid_and_oversized_files() {
        let dir = std::env::temp_dir().join(format!("hedwig-socketfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("S.gpg-agent.extra");

        assert!(matches!(read_from(&path), Err(ReadError::Io(_))));

        std::fs::write(&path, file("8467", 16)).unwrap();
        let (port, nonce) = read_from(&path).unwrap();
        assert_eq!(port, 8467);
        assert_eq!(nonce.as_bytes(), &[0xA5; 16]);

        std::fs::write(&path, file("8467", MAX_SOCKET_FILE * 2)).unwrap();
        assert!(matches!(
            read_from(&path),
            Err(ReadError::Parse(ParseError::BadNonceLength(_)))
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn debug_never_shows_bytes() {
        let (_, nonce) = parse(&file("8467", 16)).unwrap();
        assert_eq!(format!("{nonce:?}"), "Nonce(redacted)");
    }
}
