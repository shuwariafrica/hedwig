//! A route's client is found by name on the search path, in its absolute
//! folders only, never in the current folder. The one test changes this
//! process's current folder, so it is alone in this file.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::ffi::OsString;
use std::fs;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use hedwig_win::search::{SearchError, program, program_on};
use windows_sys::Win32::Storage::FileSystem::SearchPathW;

/// What the platform's search answers when it is given no folders.
fn searched_by_default(name: &str) -> Option<PathBuf> {
    let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (name, extension) = (wide(name), wide(".exe"));
    let mut found = vec![0u16; 1024];
    // SAFETY: both strings are NUL-terminated and `found` is 1024 units.
    let length = unsafe {
        SearchPathW(
            std::ptr::null(),
            name.as_ptr(),
            extension.as_ptr(),
            1024,
            found.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    let units = found.get(..length as usize)?;
    (length != 0).then(|| PathBuf::from(OsString::from_wide(units)))
}

#[test]
fn a_client_is_found_on_the_search_path_and_never_in_the_current_folder() {
    let ssh = program("ssh").unwrap();
    println!("ssh is {}", ssh.display());
    assert!(ssh.is_absolute() && ssh.is_file());
    assert!(
        ssh.file_name()
            .is_some_and(|file| file.eq_ignore_ascii_case("ssh.exe"))
    );
    assert!(matches!(
        program("hedwig-no-such-client"),
        Err(SearchError::Absent)
    ));
    assert!(matches!(
        program_on("ssh", &OsString::from(r".;relative\bin")),
        Err(SearchError::NoSearchPath)
    ));

    // A program of a name found nowhere else, put in the current folder.
    let folder = std::env::temp_dir().join(format!("hedwig-search-{}", std::process::id()));
    fs::create_dir_all(&folder).unwrap();
    let planted = folder.join("hedwig-planted.exe");
    fs::copy(&ssh, &planted).unwrap();
    let before = std::env::current_dir().unwrap();
    std::env::set_current_dir(&folder).unwrap();

    // Windows' own search, given no folders, finds it there.
    let default = searched_by_default("hedwig-planted");
    // Given the search path, the search does not - even one that names the
    // current folder as `.`.
    let path = std::env::var_os("PATH").unwrap();
    let mut with_dot = OsString::from(".;");
    with_dot.push(&path);
    let ours = program_on("hedwig-planted", &with_dot);
    // And the real client is still found, from anywhere.
    let still = program("ssh").unwrap();

    std::env::set_current_dir(before).unwrap();
    let _ = fs::remove_dir_all(&folder);
    let default = default.expect("the default search looks in the current folder");
    assert!(
        default.ends_with("hedwig-planted.exe"),
        "{}",
        default.display()
    );
    assert!(matches!(ours, Err(SearchError::Absent)), "{ours:?}");
    assert_eq!(still, ssh);
}
