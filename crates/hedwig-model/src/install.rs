//! What an installation of Hedwig is named, and whether a folder can hold
//! one. No Windows call: the setup program and the core resolve the folders
//! and write the values; this module says what they are.

use std::fmt;

use crate::text::Words;

/// The segment every folder and key of Hedwig's sits under, as the policy
/// key spells it.
pub const VENDOR: &str = "ShuwariAfrica";

/// The product's own segment, under [`VENDOR`].
pub const PRODUCT: &str = "Hedwig";

/// The longest command Windows starts from a `Run` value.
pub const RUN_LONGEST: usize = 260;

/// What Windows starts at sign-in for one start-up choice, as the core found
/// its `Run` value when it last kept it. Windows' own Startup switch can
/// still turn an entry off; its state is undocumented and not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtSignIn {
    /// What the choice says: this installation's program, or nothing.
    AsChosen,
    /// Another program's value of the same name, which the choice leaves as
    /// it is, and the command it starts; `None` where that command is not
    /// words that can be shown.
    Another(Option<Words>),
    /// The choice starts a program this installation does not have, so
    /// nothing is started for it.
    Absent,
    /// The value could not be kept, and why.
    Unkept(Words),
}

/// What a `Run` value of Hedwig's starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Starts {
    /// The supervisor, `hedwig.exe supervise`.
    Hedwig,
    /// The icon, `hedwig-interface.exe tray`.
    Icon,
}

impl Starts {
    pub const ALL: [Starts; 2] = [Starts::Hedwig, Starts::Icon];

    /// The executable it starts, beside the others in the program folder.
    pub const fn program(self) -> &'static str {
        match self {
            Starts::Hedwig => "hedwig.exe",
            Starts::Icon => "hedwig-interface.exe",
        }
    }

    const fn role(self) -> &'static str {
        match self {
            Starts::Hedwig => "supervise",
            Starts::Icon => "tray",
        }
    }

    const fn value(self) -> &'static str {
        match self {
            Starts::Hedwig => "hedwig",
            Starts::Icon => "hedwig-interface",
        }
    }
}

/// The names of one installation: the person's own, or one keyed by the
/// folder a Hedwig keeps its files in when that is not the person's own
/// (`--folder`), so two never share a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    /// The data folder this installation's Hedwig is started with, and its
    /// key, where it is not the person's own.
    keyed: Option<(String, String)>,
}

impl Names {
    /// The person's own installation.
    pub const fn own() -> Names {
        Names { keyed: None }
    }

    /// The installation whose Hedwig keeps its files in `folder`.
    pub fn keyed(folder: &str) -> Names {
        Names {
            keyed: Some((folder.to_owned(), key(folder))),
        }
    }

    /// The folder's name under `<UserProgramFiles>\ShuwariAfrica`.
    pub fn program_folder(&self) -> String {
        match &self.keyed {
            None => PRODUCT.to_owned(),
            Some((_, key)) => format!("{PRODUCT} {key}"),
        }
    }

    /// The key under the person's `Uninstall` key, which is also the product
    /// code winget correlates a manifest with.
    pub fn entry(&self) -> String {
        match &self.keyed {
            None => format!("{VENDOR}.{PRODUCT}"),
            Some((_, key)) => format!("{VENDOR}.{PRODUCT}.{key}"),
        }
    }

    /// What the entry shows as the application's name.
    pub fn display(&self) -> String {
        match &self.keyed {
            None => PRODUCT.to_owned(),
            Some((folder, _)) => format!("{PRODUCT} ({folder})"),
        }
    }

    /// The name of the `Run` value that starts `starts`.
    pub fn run_value(&self, starts: Starts) -> String {
        match &self.keyed {
            None => starts.value().to_owned(),
            Some((_, key)) => format!("{}.{key}", starts.value()),
        }
    }

    /// The command a `Run` value starts `starts` with, from the program
    /// folder `program`.
    pub fn run_command(&self, program: &str, starts: Starts) -> String {
        let mut command = format!("\"{program}\\{}\" {}", starts.program(), starts.role());
        if let Some((folder, _)) = &self.keyed {
            command.push_str(" --folder \"");
            command.push_str(folder);
            command.push('"');
        }
        command
    }

    /// The Start menu shortcut's file name, which Start shows without its
    /// extension: the program folder's, since the entry's name holds the
    /// data folder's path, which no file name can.
    pub fn shortcut(&self) -> String {
        format!("{}.lnk", self.program_folder())
    }

    /// What the Start menu shortcut starts the icon's program with, which
    /// then opens the window: nothing for the person's own Hedwig, the folder
    /// for a keyed one.
    pub fn shortcut_arguments(&self) -> String {
        self.keyed
            .as_ref()
            .map_or_else(String::new, |(folder, _)| format!("--folder \"{folder}\""))
    }
}

/// FNV-1a over the folder in lower case, as the interface keys its claims,
/// in sixteen hexadecimal digits.
pub fn key(folder: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in folder.to_lowercase().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Why a program folder cannot hold Hedwig.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// The in-box OpenSSH client would split the path of `hedwig.exe` when it
    /// starts it as `SSH_ASKPASS`: a `.exe` stands before the file's own,
    /// with a space after it.
    Splits { askpass: String },
    /// A `Run` command from this folder is longer than Windows starts.
    Long { command: String },
}

impl fmt::Display for Placement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Placement::Splits { askpass } => write!(
                f,
                "Hedwig cannot be installed at {askpass}: the OpenSSH client in Windows would \
                 split that path where \".exe\" is followed by a space, and could not ask you \
                 anything for a remote"
            ),
            Placement::Long { command } => write!(
                f,
                "Hedwig cannot be installed there: the command Windows would start it with at \
                 sign-in is {} characters, and Windows starts none longer than {RUN_LONGEST}: \
                 {command}",
                command.chars().count()
            ),
        }
    }
}

impl std::error::Error for Placement {}

/// Whether `program`, the program folder, can hold this installation.
///
/// # Errors
///
/// The first reason it cannot.
pub fn placement(names: &Names, program: &str) -> Result<(), Placement> {
    let askpass = format!("{program}\\{}", Starts::Hedwig.program());
    if splits(&askpass) {
        return Err(Placement::Splits { askpass });
    }
    for starts in Starts::ALL {
        let command = names.run_command(program, starts);
        if command.chars().count() > RUN_LONGEST {
            return Err(Placement::Long { command });
        }
    }
    Ok(())
}

/// Whether the in-box client splits `path` when it starts it: it puts the
/// closing quote at the first space after the first `.exe`, case as written
/// (`contrib/win32/win32compat/misc.c:1930-1946`, Win32-OpenSSH v10.0.0.0).
pub fn splits(path: &str) -> bool {
    path.find(".exe")
        .and_then(|at| path.get(at..))
        .is_some_and(|rest| rest.contains(' '))
}

/// What a setup program carries: the release, and each file with the path it
/// takes in the program folder and its length, in the order the files'
/// bytes follow one another in the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub version: String,
    pub files: Vec<Packed>,
}

/// One file a setup program carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packed {
    /// Relative to the program folder, its parts separated by `\`.
    pub path: String,
    pub bytes: u64,
}

/// Why a setup program's payload cannot be placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    /// It ends before what it says it holds.
    Short,
    /// Its index is not one.
    Index(String),
    /// A path that is not relative to the program folder, or leaves it.
    Escapes(String),
    /// A path listed twice.
    Repeated(String),
    /// The files' lengths do not add up to what the stream holds.
    Lengths,
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackError::Short => f.write_str("the setup program is cut short"),
            PackError::Index(account) => {
                write!(f, "the setup program's index cannot be read: {account}")
            }
            PackError::Escapes(path) => {
                write!(
                    f,
                    "the setup program would place {path} outside Hedwig's folder"
                )
            }
            PackError::Repeated(path) => write!(f, "the setup program lists {path} twice"),
            PackError::Lengths => f.write_str("the setup program's files do not add up"),
        }
    }
}

impl std::error::Error for PackError {}

impl Index {
    /// Refuses an index whose files could land outside the program folder,
    /// or one listing a file twice.
    ///
    /// # Errors
    ///
    /// [`PackError::Escapes`], [`PackError::Repeated`].
    pub fn checked(self) -> Result<Index, PackError> {
        let mut seen = std::collections::BTreeSet::new();
        for packed in &self.files {
            let parts: Vec<&str> = packed.path.split('\\').collect();
            let escapes = packed.path.is_empty()
                || packed.path.contains(['/', ':'])
                || parts
                    .iter()
                    .any(|part| part.is_empty() || *part == "." || *part == "..");
            if escapes {
                return Err(PackError::Escapes(packed.path.clone()));
            }
            if !seen.insert(packed.path.to_lowercase()) {
                return Err(PackError::Repeated(packed.path.clone()));
            }
        }
        Ok(self)
    }

    /// The files' total length.
    pub fn length(&self) -> u64 {
        self.files.iter().map(|packed| packed.bytes).sum()
    }
}

/// The payload's frame: the index's length, the index in the written form,
/// then the compressed stream of every file's bytes in the index's order.
pub fn frame(index: &Index, stream: &[u8]) -> Vec<u8> {
    let written = crate::wire::line(index);
    let mut framed = Vec::with_capacity(4 + written.len() + stream.len());
    framed.extend_from_slice(
        &u32::try_from(written.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    framed.extend_from_slice(written.as_bytes());
    framed.extend_from_slice(stream);
    framed
}

/// The index a frame begins with, checked, and the stream after it.
///
/// # Errors
///
/// [`PackError`]: the frame is cut short, its index cannot be read, or the
/// index could place a file outside the program folder.
pub fn unframe(framed: &[u8]) -> Result<(Index, &[u8]), PackError> {
    let (length, rest) = framed.split_first_chunk::<4>().ok_or(PackError::Short)?;
    let length = usize::try_from(u32::from_le_bytes(*length)).map_err(|_| PackError::Short)?;
    let written = rest.get(..length).ok_or(PackError::Short)?;
    let stream = rest.get(length..).ok_or(PackError::Short)?;
    let text = std::str::from_utf8(written).map_err(|error| PackError::Index(error.to_string()))?;
    let index: Index =
        crate::wire::read(text).map_err(|error| PackError::Index(error.to_string()))?;
    Ok((index.checked()?, stream))
}

/// Each file's path and bytes, cut from the stream's contents in the
/// index's order.
///
/// # Errors
///
/// [`PackError::Lengths`] where they do not add up.
pub fn files<'a>(index: &'a Index, whole: &'a [u8]) -> Result<Vec<(&'a str, &'a [u8])>, PackError> {
    let mut rest = whole;
    let mut cut = Vec::with_capacity(index.files.len());
    for packed in &index.files {
        let bytes = usize::try_from(packed.bytes).map_err(|_| PackError::Lengths)?;
        if rest.len() < bytes {
            return Err(PackError::Lengths);
        }
        let (file, after) = rest.split_at(bytes);
        cut.push((packed.path.as_str(), file));
        rest = after;
    }
    if rest.is_empty() {
        Ok(cut)
    } else {
        Err(PackError::Lengths)
    }
}
