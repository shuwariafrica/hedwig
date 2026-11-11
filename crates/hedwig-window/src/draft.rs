//! Where a grant or a definition being made is kept between the person's
//! edits, and where the person left the window.
//!
//! A draft is the person's partial input, not Hedwig's state: the core holds
//! no draft and reads nothing of the interface's. So a draft is a file of the
//! interface's own, in a folder of its own inside the folder of the Hedwig it
//! is for, named for what is being made: it goes wherever that Hedwig's
//! files go, and with them when Hedwig is removed. It is written whole on
//! every edit, so it outlives the window's process, a crash, the presence, a
//! sign-out and a restart, and it is removed when what it makes is made or
//! the person discards it.

use std::io;
use std::path::{Path, PathBuf};

use hedwig_win::file::replace;

/// The interface's own folder, inside the core's. The core lists its folder
/// only for names of its own files, and removal takes the whole of it.
const FOLDER: &str = "interface";

/// What a draft makes, which names the file it is kept in; or the
/// window's place, kept beside them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Making {
    Grant,
    Definition,
    Place,
}

/// What was found where a draft is kept.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Kept<T> {
    Nothing,
    Draft(T),
    /// A file is there and is not a draft this build reads.
    Unreadable,
}

/// The file the draft of `making` for the Hedwig in `folder` is kept in.
pub(crate) fn place(folder: &Path, making: Making) -> PathBuf {
    folder.join(FOLDER).join(match making {
        Making::Grant => "grant",
        Making::Definition => "define",
        Making::Place => "place",
    })
}

/// Writes a draft's written form in the place of whatever was kept.
pub(crate) fn keep(place: &Path, written: &str) -> io::Result<()> {
    if let Some(parent) = place.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut writing = place.as_os_str().to_owned();
    writing.push(".new");
    let writing = PathBuf::from(writing);
    std::fs::write(&writing, written)?;
    replace(&writing, place)
}

/// What is kept at `place`, read by `read`.
pub(crate) fn kept<T, E>(place: &Path, read: impl FnOnce(&str) -> Result<T, E>) -> Kept<T> {
    match std::fs::read_to_string(place) {
        Ok(text) => read(&text).map_or(Kept::Unreadable, Kept::Draft),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Kept::Nothing,
        Err(_) => Kept::Unreadable,
    }
}

/// Removes what is kept: the grant was made, or the person discarded it.
pub(crate) fn forget(place: &Path) -> io::Result<()> {
    match std::fs::remove_file(place) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use hedwig_model::config::{Configuration, Reference};
    use hedwig_model::text::Name;
    use hedwig_view::define::{self, Kind};
    use hedwig_view::grant::Draft;

    use super::{Kept, forget, keep, kept};

    #[test]
    fn a_draft_is_kept_whole_read_back_and_forgotten() {
        let folder = std::env::temp_dir().join(format!("hedwig draft {}", std::process::id()));
        let place = folder.join("nested").join("key.grant");
        assert_eq!(kept(&place, Draft::read), Kept::Nothing);

        let mut draft = Draft::default();
        keep(&place, &draft.written()).unwrap();
        assert_eq!(kept(&place, Draft::read), Kept::Draft(draft.clone()));
        // Written again in place of what was kept, and nothing left beside it.
        draft.capability = Some(Name::try_from("gpg").unwrap());
        keep(&place, &draft.written()).unwrap();
        assert_eq!(kept(&place, Draft::read), Kept::Draft(draft));
        let beside: Vec<_> = std::fs::read_dir(place.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(beside, ["key.grant"]);

        std::fs::write(&place, "{\"capability\":").unwrap();
        assert_eq!(kept(&place, Draft::read), Kept::Unreadable);
        forget(&place).unwrap();
        assert_eq!(kept(&place, Draft::read), Kept::Nothing);
        forget(&place).unwrap();
        std::fs::remove_dir_all(&folder).unwrap();
    }

    /// A definition being made is kept by its own written form and read back
    /// as it was, the name it changes included.
    #[test]
    fn a_definition_being_made_is_kept_and_read_back() {
        let folder = std::env::temp_dir().join(format!("hedwig define {}", std::process::id()));
        let place = folder.join("key.define");
        let mut kept_one = define::Draft::new(Kind::Route);
        let (reference, document) = (Reference::default(), Configuration::default().export());
        let (reference, document) = (&reference, &document);
        for (key, text) in [
            ("name", "lab"),
            ("program", "lab-ssh"),
            ("after", "{address}\n-v"),
        ] {
            kept_one.edit(
                define::Edit::Typed {
                    key: key.to_owned(),
                    text: text.to_owned(),
                },
                reference,
                document,
            );
        }
        kept_one.edit(
            define::Edit::Chose {
                key: "listing".to_owned(),
                at: 1,
            },
            reference,
            document,
        );
        keep(&place, &kept_one.written()).unwrap();
        assert_eq!(kept(&place, define::Draft::read), Kept::Draft(kept_one));
        // A grant's draft is not a definition's.
        keep(&place, &Draft::default().written()).unwrap();
        assert_eq!(kept(&place, define::Draft::read), Kept::Unreadable);
        std::fs::remove_dir_all(&folder).unwrap();
    }
}
