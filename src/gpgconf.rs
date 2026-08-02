#![forbid(unsafe_code)]

use std::io;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::win::CREATE_NO_WINDOW;
use crate::win::registry;

/// Gpg4win ships a 32-bit build, so on every 64-bit host - x64 and ARM64 alike -
/// its registry key is redirected under `WOW6432Node` and it installs to
/// `Program Files (x86)`. The 64-bit locations are the fallback, not the norm.
pub(crate) fn locate_gpgconf() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        if let Some(hit) = search_path(&path, Path::new("gpgconf.exe"), Path::is_file) {
            return Some(hit);
        }
    }
    for key in [r"SOFTWARE\WOW6432Node\GnuPG", r"SOFTWARE\GnuPG"] {
        if let Some(dir) = registry::local_machine_string(key, "Install Directory") {
            let candidate = PathBuf::from(dir).join("bin").join("gpgconf.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for dir in [
        r"C:\Program Files (x86)\GnuPG\bin",
        r"C:\Program Files\GnuPG\bin",
    ] {
        let candidate = Path::new(dir).join("gpgconf.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn search_path(
    path_var: &std::ffi::OsStr,
    file: &Path,
    exists: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    std::env::split_paths(path_var)
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.join(file))
        .find(|c| exists(c))
}

/// The directory holding `S.gpg-agent*`. The `%LOCALAPPDATA%\gnupg` fallback is
/// where Gpg4win puts it when gpgconf cannot be asked; it is not `GnuPG`'s
/// documented default and must not be relied on when gpgconf answers.
pub(crate) fn socket_dir(explicit: Option<&Path>, gpgconf: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(dir) = explicit {
        return Ok(dir.to_path_buf());
    }
    if let Some(gpgconf) = gpgconf {
        let out = Command::new(gpgconf)
            .args(["--list-dirs", "socketdir"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()?;
        if out.status.success() {
            let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !dir.is_empty() {
                return Ok(PathBuf::from(dir));
            }
        }
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return Ok(PathBuf::from(local).join("gnupg"));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "cannot determine the GnuPG socket directory; pass --socketdir",
    ))
}

/// `gpgconf --launch gpg-agent` starts the agent if it is not running and
/// returns once its sockets exist; when the agent already runs it is a no-op.
pub(crate) fn launch_agent(gpgconf: &Path) -> io::Result<()> {
    let status = Command::new(gpgconf)
        .args(["--launch", "gpg-agent"])
        .creation_flags(CREATE_NO_WINDOW)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "gpgconf --launch gpg-agent exited with {status}"
        )))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::ffi::OsString;

    #[test]
    fn search_path_finds_first_match() {
        let path = OsString::from(r"C:\a;C:\b;C:\c");
        let hit = search_path(&path, Path::new("x.exe"), |p| {
            p == Path::new(r"C:\b\x.exe") || p == Path::new(r"C:\c\x.exe")
        });
        assert_eq!(hit, Some(PathBuf::from(r"C:\b\x.exe")));
    }

    #[test]
    fn search_path_no_match() {
        let path = OsString::from(r"C:\a;C:\b");
        assert_eq!(search_path(&path, Path::new("x.exe"), |_| false), None);
    }

    #[test]
    fn search_path_skips_empty_entries() {
        let path = OsString::from(r";;C:\a");
        let hit = search_path(&path, Path::new("x.exe"), |p| p == Path::new(r"C:\a\x.exe"));
        assert_eq!(hit, Some(PathBuf::from(r"C:\a\x.exe")));
    }

    #[test]
    fn explicit_socketdir_wins() {
        let dir = socket_dir(Some(Path::new(r"C:\override")), None).unwrap();
        assert_eq!(dir, PathBuf::from(r"C:\override"));
    }

    #[test]
    fn fallback_socketdir_is_localappdata_gnupg() {
        let dir = socket_dir(None, None).unwrap();
        assert!(dir.ends_with("gnupg"));
    }
}
