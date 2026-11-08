//! The commit a build names, read from a repository as each executable's
//! build script reads it.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use hedwig_model::text::Commit;
use hedwig_view::resource;

/// A folder of the test's own, holding a repository's folder and a git
/// configuration of its own; removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let root =
            std::env::temp_dir().join(format!("hedwig-commit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("repository")).unwrap();
        fs::write(root.join("gitconfig"), "").unwrap();
        Scratch(root)
    }

    fn repository(&self) -> PathBuf {
        self.0.join("repository")
    }

    /// Runs git in the repository, reading none of the person's own
    /// configuration, so no signing key or hook of theirs takes part.
    fn git(&self, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(self.repository())
            .args([
                "-c",
                "user.name=Hedwig test",
                "-c",
                "user.email=test@hedwig.example",
            ])
            .args(arguments)
            .env("GIT_CONFIG_GLOBAL", self.0.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {arguments:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// A repository with one commit of one tracked file.
    fn committed(name: &str) -> Scratch {
        let scratch = Scratch::new(name);
        scratch.git(&["init", "--quiet"]);
        fs::write(scratch.repository().join("tracked.txt"), "first\n").unwrap();
        scratch.git(&["add", "tracked.txt"]);
        scratch.git(&["commit", "--quiet", "--message", "first"]);
        scratch
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn twelve(head: &str) -> String {
    head.get(..12).unwrap().to_owned()
}

#[test]
fn a_checkout_as_committed_is_named_by_its_commits_first_twelve_digits() {
    let scratch = Scratch::committed("clean");
    let head = scratch.git(&["rev-parse", "HEAD"]);

    assert_eq!(
        resource::commit(&scratch.repository()).as_str(),
        twelve(&head)
    );
}

#[test]
fn a_tracked_file_changed_marks_the_commit_modified_and_an_untracked_file_does_not() {
    let scratch = Scratch::committed("modified");
    let head = scratch.git(&["rev-parse", "HEAD"]);
    fs::write(scratch.repository().join("untracked.txt"), "notes").unwrap();
    assert_eq!(
        resource::commit(&scratch.repository()).as_str(),
        twelve(&head)
    );

    fs::write(scratch.repository().join("tracked.txt"), "second\n").unwrap();
    assert_eq!(
        resource::commit(&scratch.repository()).as_str(),
        format!("{}, modified", twelve(&head))
    );
}

#[test]
fn a_folder_with_no_repository_names_no_commit() {
    let scratch = Scratch::new("none");

    assert_eq!(resource::commit(&scratch.repository()), Commit::unknown());
}

#[test]
fn a_repository_with_no_commit_names_none() {
    let scratch = Scratch::new("unborn");
    scratch.git(&["init", "--quiet"]);

    assert_eq!(resource::commit(&scratch.repository()), Commit::unknown());
}
