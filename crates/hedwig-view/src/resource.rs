//! What Windows reads of an executable to name it and show its face: an icon
//! in every size Windows asks for, and the version information that names
//! the product and the build, as the resource file the linker takes.
//!
//! Nothing here calls Windows. Each executable's build script calls [`link`],
//! which writes this file and links it; Windows reading it back is the
//! suites'.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

use hedwig_model::install::Starts;
use hedwig_model::text::Commit;

use crate::emblem::{Emblem, Ink};
use crate::paint::Canvas;
use crate::style::Mode;

/// Each size Windows draws an executable's icon at, from the notification
/// area at 100 per cent to the largest view: an exact match for every scale
/// Windows 11 offers up to 400 per cent, and 256 so it only ever scales down.
pub const SIDES: [usize; 14] = [16, 20, 24, 30, 32, 36, 40, 48, 60, 64, 72, 80, 96, 256];

/// The resource number of the executable's icon: the lowest, which Windows
/// shows as the file's own.
pub const ICON: u16 = 1;

/// Each executable of Hedwig's, which links this resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    /// `hedwig.exe`: the supervisor, the core and the command line.
    Hedwig,
    /// `hedwig-interface.exe`: the icon, its menu, the card.
    Icon,
    /// `hedwig-window.exe`.
    Window,
    /// `hedwig-setup.exe`.
    Setup,
}

impl Program {
    pub const fn file(self) -> &'static str {
        match self {
            Program::Hedwig => Starts::Hedwig.program(),
            Program::Icon => Starts::Icon.program(),
            Program::Window => "hedwig-window.exe",
            Program::Setup => "hedwig-setup.exe",
        }
    }

    /// What Windows calls the program where it lists programs rather than
    /// windows - Settings' start-up apps, Task Manager's processes - so the
    /// two things that start at sign-in, each turned off on its own, are told
    /// apart there.
    pub const fn description(self) -> &'static str {
        match self {
            Program::Hedwig | Program::Window => "Hedwig",
            Program::Icon => "Hedwig icon",
            Program::Setup => "Hedwig setup",
        }
    }
}

/// What the version information says, every string in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    /// `major.minor.patch`, each at most 65535: the version Windows compares.
    pub version: [u16; 3],
    /// The whole version, pre-release included (`FileVersion`).
    pub release: String,
    /// The commit the build was made from, said after the release in
    /// `ProductVersion`.
    pub commit: Commit,
    /// The program, as Windows lists it (`FileDescription`).
    pub description: String,
    /// The product the program is part of (`ProductName`).
    pub product: String,
    pub publisher: String,
    pub copyright: String,
    /// The executable's own file name.
    pub file: String,
}

impl Named {
    /// What `program` says of itself: what it is, the product Hedwig, its
    /// publisher as the package manifests name it, the build it is, and the
    /// copyright line of `licence`, the repository's licence.
    pub fn hedwig(
        program: Program,
        version: [u16; 3],
        release: &str,
        commit: Commit,
        licence: &str,
    ) -> Named {
        Named {
            version,
            release: release.to_owned(),
            commit,
            description: program.description().to_owned(),
            product: "Hedwig".to_owned(),
            publisher: "Shuwari Africa".to_owned(),
            copyright: licence
                .lines()
                .find(|line| line.starts_with("Copyright"))
                .unwrap_or_default()
                .trim()
                .to_owned(),
            file: program.file().to_owned(),
        }
    }
}

/// Writes `program`'s resource and links it into the executable of the crate
/// at `crate_dir`, a folder of the repository's `crates`, and gives that
/// crate's code the build's commit as `HEDWIG_COMMIT`; cargo is asked to run
/// the build script again whenever the commit, or whether the tree differs
/// from it, could have changed.
///
/// # Errors
///
/// A variable cargo gives a build script is missing or not a version, the
/// repository's licence cannot be read, or the resource cannot be written.
pub fn link(program: Program, crate_dir: &Path) -> Result<(), Box<dyn Error + Send + Sync>> {
    let root = crate_dir
        .parent()
        .and_then(Path::parent)
        .ok_or("the crate is not in the repository's crates folder")?;
    let licence = root.join("LICENSE");
    println!("cargo::rerun-if-changed={}", licence.display());
    let part = |name: &str| -> Result<u16, Box<dyn Error + Send + Sync>> {
        Ok(std::env::var(name)?.parse()?)
    };
    let commit = commit(root);
    let named = Named::hedwig(
        program,
        [
            part("CARGO_PKG_VERSION_MAJOR")?,
            part("CARGO_PKG_VERSION_MINOR")?,
            part("CARGO_PKG_VERSION_PATCH")?,
        ],
        &std::env::var("CARGO_PKG_VERSION")?,
        commit.clone(),
        &std::fs::read_to_string(licence)?,
    );
    let out = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("no OUT_DIR")?).join("hedwig.res");
    std::fs::write(&out, file(&named))?;
    println!("cargo::rustc-link-arg-bins={}", out.display());
    println!("cargo::rustc-env=HEDWIG_COMMIT={commit}");
    Ok(())
}

/// The commit the repository at `root` holds checked out: unknown where
/// there is no repository there or git cannot be run, and modified where a
/// tracked file differs from it or git cannot say whether one does. Asks
/// cargo to run the calling build script again when the checkout, the index
/// or any tracked path but `target` changes.
pub fn commit(root: &Path) -> Commit {
    let git = |arguments: &[&str]| -> Option<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let (Some(head), Some(own), Some(common)) = (
        git(&["rev-parse", "--verify", "HEAD"]),
        git(&["rev-parse", "--absolute-git-dir"]),
        git(&["rev-parse", "--path-format=absolute", "--git-common-dir"]),
    ) else {
        return Commit::unknown();
    };
    // A path cargo is told to watch that does not exist makes it run the
    // script again on every build.
    let watch = |path: PathBuf| {
        if path.exists() {
            println!("cargo::rerun-if-changed={}", path.display());
        }
    };
    let (own, common) = (Path::new(&own), Path::new(&common));
    watch(own.join("HEAD"));
    watch(own.join("index"));
    watch(common.join("packed-refs"));
    if let Some(branch) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        watch(common.join(branch));
    }
    let tracked = git(&["ls-tree", "--name-only", "HEAD"]).unwrap_or_default();
    for name in tracked.lines().filter(|name| *name != "target") {
        watch(root.join(name));
    }
    let changed = git(&["status", "--porcelain", "--untracked-files=no"]);
    let marked = match changed.as_deref() {
        Some("") => "",
        _ => ", modified",
    };
    head.get(..12)
        .and_then(|id| Commit::try_from(format!("{id}{marked}").as_str()).ok())
        .unwrap_or_else(Commit::unknown)
}

/// A resource file holding the emblem as the executable's icon and the
/// version information `named` gives, in UK English.
pub fn file(named: &Named) -> Vec<u8> {
    let images: Vec<Vec<u8>> = SIDES
        .iter()
        .map(|side| png(&Emblem::PLAIN.draw(*side, Ink::Taskbar(Mode::Dark))))
        .collect();
    let mut out = Vec::new();
    // A resource file opens with an empty entry.
    entry(&mut out, 0, 0, &[]);
    for (number, image) in (1_u16..).zip(&images) {
        entry(&mut out, RT_ICON, number, image);
    }
    entry(&mut out, RT_GROUP_ICON, ICON, &group(&images));
    entry(&mut out, RT_VERSION, 1, &version(named));
    out
}

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const RT_VERSION: u16 = 16;
/// English (United Kingdom), and its code page for Unicode text.
const LANGUAGE: u16 = 0x0809;
const UNICODE: u16 = 1200;

fn push16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn length32(bytes: usize) -> u32 {
    u32::try_from(bytes).unwrap_or(u32::MAX)
}

fn length16(bytes: usize) -> u16 {
    u16::try_from(bytes).unwrap_or(u16::MAX)
}

fn align(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// One entry of a resource file: its header, naming its type and number by
/// ordinal, then its data, each aligned to four bytes.
fn entry(out: &mut Vec<u8>, kind: u16, number: u16, data: &[u8]) {
    push32(out, length32(data.len()));
    push32(out, 32);
    for ordinal in [kind, number] {
        push16(out, 0xffff);
        push16(out, ordinal);
    }
    push32(out, 0);
    // Moveable, pure and discardable, as the resource compiler marks these.
    push16(out, if kind == 0 { 0 } else { 0x1030 });
    push16(out, if kind == 0 { 0 } else { LANGUAGE });
    push32(out, 0);
    push32(out, 0);
    out.extend_from_slice(data);
    align(out);
}

/// The icon group: a directory of the images, each by its resource number.
fn group(images: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    push16(&mut out, 0);
    push16(&mut out, 1);
    push16(&mut out, length16(images.len()));
    for ((number, image), side) in (1_u16..).zip(images).zip(SIDES) {
        directory_entry(&mut out, side, image.len());
        push16(&mut out, number);
    }
    out
}

fn directory_entry(out: &mut Vec<u8>, side: usize, bytes: usize) {
    // 256 is written as 0.
    let side = u8::try_from(side).unwrap_or(0);
    out.extend_from_slice(&[side, side, 0, 0]);
    push16(out, 1);
    push16(out, 32);
    push32(out, length32(bytes));
}

/// The emblem as an icon file of its own (`.ico`), every size in [`SIDES`].
pub fn icon_file() -> Vec<u8> {
    let images: Vec<Vec<u8>> = SIDES
        .iter()
        .map(|side| png(&Emblem::PLAIN.draw(*side, Ink::Taskbar(Mode::Dark))))
        .collect();
    let mut out = Vec::new();
    push16(&mut out, 0);
    push16(&mut out, 1);
    push16(&mut out, length16(images.len()));
    let mut offset = 6 + 16 * images.len();
    for (image, side) in images.iter().zip(SIDES) {
        directory_entry(&mut out, side, image.len());
        push32(&mut out, length32(offset));
        offset += image.len();
    }
    for image in &images {
        out.extend_from_slice(image);
    }
    out
}

fn wide(out: &mut Vec<u8>, text: &str) {
    for unit in text.encode_utf16().chain([0]) {
        push16(out, unit);
    }
}

/// One block of version information: its length, its value's length, its
/// type, its key, its value and its children, each aligned to four bytes.
fn block(key: &str, value: Value<'_>, children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0, 0];
    let (value_length, kind) = match value {
        Value::None => (0, 1),
        Value::Text(text) => (length16(text.encode_utf16().count() + 1), 1),
        Value::Binary(bytes) => (length16(bytes.len()), 0),
    };
    push16(&mut out, value_length);
    push16(&mut out, kind);
    wide(&mut out, key);
    align(&mut out);
    match value {
        Value::None => {}
        Value::Text(text) => wide(&mut out, text),
        Value::Binary(bytes) => out.extend_from_slice(bytes),
    }
    for child in children {
        align(&mut out);
        out.extend_from_slice(child);
    }
    let length = length16(out.len()).to_le_bytes();
    if let Some(first) = out.get_mut(..2) {
        first.copy_from_slice(&length);
    }
    out
}

#[derive(Clone, Copy)]
enum Value<'a> {
    None,
    Text(&'a str),
    Binary(&'a [u8]),
}

fn version(named: &Named) -> Vec<u8> {
    let [major, minor, patch] = named.version;
    let high = u32::from(major) << 16 | u32::from(minor);
    let low = u32::from(patch) << 16;
    let mut fixed = Vec::new();
    for value in [
        0xfeef_04bd, // the signature
        0x0001_0000,
        high,
        low,
        high,
        low,
        0x3f, // the flags a version may state
        0,
        0x0004_0004, // for 32-bit and 64-bit Windows
        1,           // an application
        0,
        0,
        0,
    ] {
        push32(&mut fixed, value);
    }
    let product = format!("{} ({})", named.release, named.commit);
    let strings = [
        ("CompanyName", named.publisher.as_str()),
        ("FileDescription", named.description.as_str()),
        ("FileVersion", named.release.as_str()),
        ("InternalName", named.file.trim_end_matches(".exe")),
        ("LegalCopyright", named.copyright.as_str()),
        ("OriginalFilename", named.file.as_str()),
        ("ProductName", named.product.as_str()),
        ("ProductVersion", product.as_str()),
    ]
    .map(|(key, text)| block(key, Value::Text(text), &[]));
    let table = block(
        &format!("{LANGUAGE:04x}{UNICODE:04x}"),
        Value::None,
        &strings,
    );
    let mut translation = Vec::new();
    push16(&mut translation, LANGUAGE);
    push16(&mut translation, UNICODE);
    let var = block("Translation", Value::Binary(&translation), &[]);
    block(
        "VS_VERSION_INFO",
        Value::Binary(&fixed),
        &[
            block("StringFileInfo", Value::None, &[table]),
            block("VarFileInfo", Value::None, &[var]),
        ],
    )
}

/// The picture as a PNG: eight bits a channel with alpha, unmultiplied, each
/// row filtered as whichever of none, the pixel to the left or the row above
/// leaves the smallest differences.
pub fn png(canvas: &Canvas) -> Vec<u8> {
    let (width, height) = (canvas.width, canvas.height);
    let stride = width * 4;
    let mut raw = Vec::with_capacity(height * (stride + 1));
    let mut above = vec![0_u8; stride];
    for y in 0..height {
        let row: Vec<u8> = (0..width)
            .flat_map(|x| {
                canvas.at(x, y).map_or([0; 4], |(colour, alpha)| {
                    if alpha == 0 {
                        [0; 4]
                    } else {
                        [colour.red, colour.green, colour.blue, alpha]
                    }
                })
            })
            .collect();
        let candidates = [
            (0_u8, row.clone()),
            (
                1,
                row.iter()
                    .enumerate()
                    .map(|(at, value)| {
                        let left = at.checked_sub(4).and_then(|left| row.get(left));
                        value.wrapping_sub(left.copied().unwrap_or(0))
                    })
                    .collect(),
            ),
            (
                2,
                row.iter()
                    .zip(&above)
                    .map(|(value, up)| value.wrapping_sub(*up))
                    .collect(),
            ),
        ];
        let cost = |filtered: &Vec<u8>| -> u32 {
            filtered
                .iter()
                .map(|value| u32::from((*value).min(value.wrapping_neg())))
                .sum()
        };
        if let Some((filter, filtered)) = candidates
            .into_iter()
            .min_by_key(|(_, filtered)| cost(filtered))
        {
            raw.push(filter);
            raw.extend_from_slice(&filtered);
        }
        above = row;
    }
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut header = Vec::new();
    header.extend_from_slice(&length32(width).to_be_bytes());
    header.extend_from_slice(&length32(height).to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut out, *b"IHDR", &header);
    chunk(&mut out, *b"IDAT", &zlib(&raw));
    chunk(&mut out, *b"IEND", &[]);
    out
}

fn chunk(out: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
    out.extend_from_slice(&length32(data.len()).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(&kind);
    out.extend_from_slice(data);
    let sum = crc(out.get(start..).unwrap_or_default());
    out.extend_from_slice(&sum.to_be_bytes());
}

/// CRC-32 as PNG's chunks carry it (ISO 3309).
pub fn crc(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                0xedb8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// `data` as a zlib stream: one block of deflate's fixed codes, each run of
/// a repeated byte written as a copy of the byte before it.
fn zlib(data: &[u8]) -> Vec<u8> {
    let mut bits = Bits::default();
    // The last block, fixed codes.
    bits.push(1, 1);
    bits.push(1, 2);
    let mut at = 0;
    while let Some(&value) = data.get(at) {
        let run = if at == 0 {
            0
        } else {
            data.get(at..)
                .unwrap_or_default()
                .iter()
                .take(258)
                .take_while(|next| **next == data.get(at - 1).copied().unwrap_or(!value))
                .count()
        };
        if run >= 3 {
            length(&mut bits, run);
            // Distance code 0, a distance of one: five zero bits.
            bits.code(0, 5);
            at += run;
        } else {
            literal(&mut bits, u16::from(value));
            at += 1;
        }
    }
    literal(&mut bits, 256);
    let mut out = vec![0x78, 0x01];
    out.extend(bits.finish());
    out.extend_from_slice(&adler(data).to_be_bytes());
    out
}

/// A fixed code for a literal byte or the block's end (256).
fn literal(bits: &mut Bits, value: u16) {
    match value {
        0..=143 => bits.code(0x30 + u32::from(value), 8),
        144..=255 => bits.code(0x190 + u32::from(value - 144), 9),
        _ => bits.code(u32::from(value - 256), 7),
    }
}

/// A fixed code for a copy of `run` bytes, 3 to 258, with its extra bits.
fn length(bits: &mut Bits, run: usize) {
    const BASES: [(u16, u16, u8); 29] = [
        (257, 3, 0),
        (258, 4, 0),
        (259, 5, 0),
        (260, 6, 0),
        (261, 7, 0),
        (262, 8, 0),
        (263, 9, 0),
        (264, 10, 0),
        (265, 11, 1),
        (266, 13, 1),
        (267, 15, 1),
        (268, 17, 1),
        (269, 19, 2),
        (270, 23, 2),
        (271, 27, 2),
        (272, 31, 2),
        (273, 35, 3),
        (274, 43, 3),
        (275, 51, 3),
        (276, 59, 3),
        (277, 67, 4),
        (278, 83, 4),
        (279, 99, 4),
        (280, 115, 4),
        (281, 131, 5),
        (282, 163, 5),
        (283, 195, 5),
        (284, 227, 5),
        (285, 258, 0),
    ];
    let run = u16::try_from(run).unwrap_or(258);
    let Some(&(code, base, extra)) = BASES.iter().rev().find(|(_, base, _)| *base <= run) else {
        return;
    };
    match code {
        257..=279 => bits.code(u32::from(code - 256), 7),
        _ => bits.code(0xc0 + u32::from(code - 280), 8),
    }
    bits.push(u32::from(run - base), extra);
}

fn adler(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in data {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    b << 16 | a
}

/// Bits as deflate packs them, least significant first.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    current: u32,
    count: u8,
}

impl Bits {
    /// `count` bits of `value`, its least significant first.
    fn push(&mut self, value: u32, count: u8) {
        for at in 0..count {
            self.current |= ((value >> at) & 1) << self.count;
            self.count += 1;
            if self.count == 8 {
                self.out
                    .push(self.current.to_le_bytes().first().copied().unwrap_or(0));
                self.current = 0;
                self.count = 0;
            }
        }
    }

    /// A Huffman code of `count` bits, its most significant first.
    fn code(&mut self, code: u32, count: u8) {
        for at in (0..count).rev() {
            self.push((code >> at) & 1, 1);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.count > 0 {
            self.out
                .push(self.current.to_le_bytes().first().copied().unwrap_or(0));
        }
        self.out
    }
}
