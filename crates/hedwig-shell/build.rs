//! Gives this crate's test executables the manifest the interface carries.
//!
//! What the suites show at the desktop - Windows' controls as version 6 of
//! the common controls draws and exposes them, at the monitor's own scale -
//! is what the manifest selects, and the suites check that it does.

fn main() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("hedwig-interface")
        .join("interface.manifest");
    println!("cargo::rerun-if-changed={}", manifest.display());
    println!("cargo::rustc-link-arg-tests=/MANIFEST:EMBED");
    println!(
        "cargo::rustc-link-arg-tests=/MANIFESTINPUT:{}",
        manifest.display()
    );
}
