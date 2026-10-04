//! Embeds `hedwig.exe`'s manifest by a path built from this crate's own
//! folder: a relative path resolves against wherever the link runs, which
//! fails with `LNK1327` outside the crate root.

use std::path::Path;

fn main() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("hedwig.manifest");
    println!("cargo::rerun-if-changed={}", manifest.display());
    println!("cargo::rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo::rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
}
