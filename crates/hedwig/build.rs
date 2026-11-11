//! Embeds `hedwig.exe`'s manifest by a path built from this crate's own
//! folder - a relative path resolves against wherever the link runs, which
//! fails with `LNK1327` outside the crate root - and links the resource every
//! executable of Hedwig's carries. `hedwig-view` is a build dependency alone:
//! the binary holds no interface code.

use std::error::Error;
use std::path::Path;

use hedwig_view::resource::{self, Program};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = here.join("hedwig.manifest");
    println!("cargo::rerun-if-changed={}", manifest.display());
    println!("cargo::rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo::rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
    resource::link(Program::Hedwig, here)
}
