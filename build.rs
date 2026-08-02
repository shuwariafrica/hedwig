use std::process::Command;

// Cargo parses the manifest before any code runs and build scripts cannot alter
// package metadata, so the version cannot be derived from git. What git can
// supply is provenance: which commit a binary came from, and whether its tree
// was dirty. Absent when building from a packaged crate rather than a checkout,
// hence optional at the use site.
fn main() {
    if let Some(describe) = git_describe() {
        println!("cargo::rustc-env=HEDWIG_GIT_DESCRIBE={describe}");
    }
}

fn git_describe() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty", "--match", "v*"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let describe = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!describe.is_empty()).then_some(describe)
}
