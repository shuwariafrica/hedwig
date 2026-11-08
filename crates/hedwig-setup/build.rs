//! Packs the folder `HEDWIG_PAYLOAD` names - the three executables and the
//! window's runtime, as a release stages them - into the payload setup
//! carries: an index of every file with its path and length, then every
//! file's bytes in one LZMS stream, compressed with Windows' own
//! Compression API. With no folder named, setup carries nothing and says so.
//!
//! Embeds setup's manifest by this crate's own path, and links the resource
//! every executable of Hedwig's carries.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use hedwig_model::install::{Index, Packed, frame};
use hedwig_view::resource::{self, Program};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("no OUT_DIR")?);
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = here.join("setup.manifest");
    println!("cargo::rerun-if-changed={}", manifest.display());
    println!("cargo::rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo::rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
    resource::link(Program::Setup, here)?;
    println!("cargo::rerun-if-env-changed=HEDWIG_PAYLOAD");
    let out = out_dir.join("payload.bin");
    let Some(folder) = std::env::var_os("HEDWIG_PAYLOAD").map(PathBuf::from) else {
        fs::write(&out, [])?;
        return Ok(());
    };
    println!("cargo::rerun-if-changed={}", folder.display());
    let mut found = Vec::new();
    collect(&folder, &folder, &mut found)?;
    found.sort();
    let mut files = Vec::with_capacity(found.len());
    let mut whole = Vec::new();
    for relative in found {
        let bytes = fs::read(folder.join(&relative))?;
        files.push(Packed {
            path: relative,
            bytes: u64::try_from(bytes.len())?,
        });
        whole.extend(bytes);
    }
    let index = Index {
        version: std::env::var("CARGO_PKG_VERSION")?,
        files,
    }
    .checked()?;
    let stream = hedwig_win::pack::compress(&whole)?;
    fs::write(&out, frame(&index, &stream))?;
    Ok(())
}

fn collect(
    root: &Path,
    folder: &Path,
    found: &mut Vec<String>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for entry in fs::read_dir(folder)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(root, &path, found)?;
        } else {
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .ok_or("a path that is not text")?;
            found.push(relative.to_owned());
        }
    }
    Ok(())
}
