//! Where a client finds Hedwig's files: the folder Windows gives for the
//! person's local application data, whatever the environment it was started
//! with says.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::path::{Path, PathBuf};
use std::process::Command;

use hedwig_model::process::FOLDER;

#[test]
fn a_client_finds_hedwigs_folder_where_windows_says_and_not_where_a_variable_does() {
    let own = hedwig_client::folder().expect("Windows says where local data is");
    assert!(own.is_absolute());
    assert_eq!(own, hedwig_win::folder::local().unwrap().join(FOLDER));

    // A profile somewhere else that has the folder Windows would expand to,
    // and one that does not: neither is where the person's files are.
    let elsewhere =
        std::env::temp_dir().join(format!("hedwig-design-profile-{}", std::process::id()));
    std::fs::create_dir_all(elsewhere.join("AppData").join("Local")).unwrap();
    let missing = elsewhere.join("missing");
    for profile in [&elsewhere, &missing] {
        let printed = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_child")))
            .arg("folder")
            .env("LOCALAPPDATA", profile)
            .env("USERPROFILE", profile)
            .output()
            .expect("the child runs");
        assert!(printed.status.success(), "{printed:?}");
        let found = PathBuf::from(String::from_utf8(printed.stdout).unwrap().trim_end());
        assert_eq!(found, own);
        assert!(!found.starts_with(Path::new(&elsewhere)));
    }
    std::fs::remove_dir_all(&elsewhere).unwrap();
}
