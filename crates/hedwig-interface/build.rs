//! Embeds the interface's own manifest in its executable and in its suites,
//! and links the resource every executable of Hedwig's carries.
//!
//! The manifest selects version 6 of the common controls, the only version
//! whose controls Windows fully exposes to UI Automation, and declares
//! per-monitor DPI awareness, which Windows asks to be declared there.

use std::error::Error;
use std::path::Path;

use hedwig_view::resource::{self, Program};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = here.join("interface.manifest");
    println!("cargo::rerun-if-changed={}", manifest.display());
    for kind in ["bins", "tests"] {
        println!("cargo::rustc-link-arg-{kind}=/MANIFEST:EMBED");
        println!(
            "cargo::rustc-link-arg-{kind}=/MANIFESTINPUT:{}",
            manifest.display()
        );
    }
    resource::link(Program::Icon, here)
}
