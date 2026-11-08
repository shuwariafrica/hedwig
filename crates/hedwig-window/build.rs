//! Stages the Windows App Runtime the window carries beside its executable,
//! adds the window's own manifest to the one that staging embeds, and links
//! the resource every executable of Hedwig's carries.
//!
//! The runtime is what makes the window start on a machine with nothing of
//! Microsoft's installed; `windows-reactor-setup` stages it into the profile's
//! output folder and marks the executable to load it from there.

use std::error::Error;
use std::path::Path;

use hedwig_view::resource::{self, Program};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    windows_reactor_setup::as_self_contained();
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = here.join("window.manifest");
    println!("cargo::rerun-if-changed={}", manifest.display());
    println!(
        "cargo::rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
    resource::link(Program::Window, here)
}
