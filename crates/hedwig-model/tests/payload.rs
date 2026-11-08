//! A setup program's payload: the frame that carries it, and every index and
//! stream refused before a file is written.

#![allow(clippy::expect_used, reason = "tests")]

use hedwig_model::install::{Index, PackError, Packed, files, frame, unframe};

fn index(paths: &[(&str, u64)]) -> Index {
    Index {
        version: "0.2.0".to_owned(),
        files: paths
            .iter()
            .map(|&(path, bytes)| Packed {
                path: path.to_owned(),
                bytes,
            })
            .collect(),
    }
}

/// `path` after a file the folder can hold, so a refusal is the path's own
/// and not the first file's.
fn after_one(path: &str) -> Result<Index, PackError> {
    index(&[("hedwig.exe", 1), (path, 1)]).checked()
}

fn escapes(path: &str) -> Result<Index, PackError> {
    Err(PackError::Escapes(path.to_owned()))
}

#[test]
fn a_frame_gives_back_the_index_and_the_stream_it_was_made_from() {
    let paths = [
        ("hedwig.exe", 4_382_208),
        (r"runtime\Microsoft.WindowsAppRuntime.Bootstrap.dll", 0),
        (r"a b\c d.txt", 1),
        ("..config", 7),
        ("caf\u{e9}\\\u{fc}.txt", u64::MAX),
    ];
    let every_byte: Vec<u8> = (0..=u8::MAX).collect();
    let streams: [&[u8]; 3] = [&[], &[0x42, 0, 0, 0], &every_byte];
    let mut checked = 0;
    for version in ["0.2.0", "0.2.0-alpha.1"] {
        for subset in 0..1_u32 << paths.len() {
            let made = Index {
                version: version.to_owned(),
                files: paths
                    .iter()
                    .enumerate()
                    .filter(|&(at, _)| subset & (1 << at) != 0)
                    .map(|(_, &(path, bytes))| Packed {
                        path: path.to_owned(),
                        bytes,
                    })
                    .collect(),
            };
            for stream in streams {
                let framed = frame(&made, stream);
                let (read, rest) = unframe(&framed).expect("a frame of an index it can hold");
                assert_eq!((&read, rest), (&made, stream));
                assert_eq!(frame(&read, rest), framed);
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 192);
}

#[test]
fn a_frame_is_its_written_index_after_that_index_length_then_the_stream() {
    let written = br#"{"version":"0.2.0","files":[{"path":"bin\\hedwig.exe","bytes":3}]}"#;
    let mut expected = vec![0x42, 0, 0, 0];
    expected.extend_from_slice(written);
    expected.extend_from_slice(b"\x00\xff\x07");
    assert_eq!(
        frame(&index(&[(r"bin\hedwig.exe", 3)]), b"\x00\xff\x07"),
        expected
    );
}

#[test]
fn a_frame_cut_before_its_index_ends_is_refused() {
    let whole = frame(&index(&[("hedwig.exe", 3)]), b"abc");
    let index_ends = whole.len() - b"abc".len();
    for cut in 0..index_ends {
        assert_eq!(
            unframe(whole.get(..cut).expect("within the frame")),
            Err(PackError::Short),
            "cut at {cut}"
        );
    }
}

#[test]
fn a_frame_whose_index_cannot_be_read_is_refused() {
    for written in [&b"\xff\xfe"[..], b"not an index", br#"{"version":"0.2.0"}"#] {
        let mut framed = u32::try_from(written.len())
            .expect("a short index")
            .to_le_bytes()
            .to_vec();
        framed.extend_from_slice(written);
        assert!(
            matches!(unframe(&framed), Err(PackError::Index(_))),
            "{written:?}"
        );
    }
}

#[test]
fn a_frame_whose_index_could_misplace_a_file_is_refused() {
    let outside = frame(&index(&[(r"..\hedwig.exe", 1)]), b"x");
    assert_eq!(
        unframe(&outside),
        Err(PackError::Escapes(r"..\hedwig.exe".to_owned()))
    );
    let twice = frame(&index(&[("hedwig.exe", 1), ("HEDWIG.EXE", 1)]), b"xy");
    assert_eq!(
        unframe(&twice),
        Err(PackError::Repeated("HEDWIG.EXE".to_owned()))
    );
}

#[test]
fn a_path_with_a_forward_slash_is_refused() {
    for path in ["bin/hedwig.exe", "../hedwig.exe"] {
        assert_eq!(after_one(path), escapes(path));
    }
}

#[test]
fn a_path_naming_a_drive_or_a_stream_is_refused() {
    for path in [
        r"C:\Windows\hedwig.exe",
        "C:hedwig.exe",
        "hedwig.exe:hidden",
    ] {
        assert_eq!(after_one(path), escapes(path));
    }
}

#[test]
fn a_path_with_an_empty_part_is_refused() {
    for path in [
        "",
        r"\Windows\hedwig.exe",
        r"\\server\share\hedwig.exe",
        r"bin\\hedwig.exe",
        "bin\\",
    ] {
        assert_eq!(after_one(path), escapes(path));
    }
}

#[test]
fn a_path_through_a_current_folder_part_is_refused() {
    for path in [r"bin\.\hedwig.exe", r".\hedwig.exe", "."] {
        assert_eq!(after_one(path), escapes(path));
    }
}

#[test]
fn a_path_through_a_parent_folder_part_is_refused() {
    for path in [r"..\hedwig.exe", r"bin\..\..\hedwig.exe", ".."] {
        assert_eq!(after_one(path), escapes(path));
    }
}

#[test]
fn a_path_listed_twice_is_refused_in_any_case() {
    let twice = index(&[("hedwig.exe", 1), (r"runtime\a.dll", 1), ("hedwig.exe", 2)]);
    assert_eq!(
        twice.checked(),
        Err(PackError::Repeated("hedwig.exe".to_owned()))
    );
    let cased = index(&[(r"Runtime\A.dll", 1), (r"runtime\a.DLL", 1)]);
    assert_eq!(
        cased.checked(),
        Err(PackError::Repeated(r"runtime\a.DLL".to_owned()))
    );
}

#[test]
fn an_index_of_paths_inside_the_folder_is_kept_as_it_is() {
    for inside in [
        index(&[
            ("hedwig.exe", 1),
            (r"runtime\Microsoft.WindowsAppRuntime.Bootstrap.dll", 2),
            (r"a b\..config", 3),
            ("a..b.txt", 4),
            (r"x\y\z", 0),
        ]),
        index(&[]),
    ] {
        assert_eq!(inside.clone().checked(), Ok(inside));
    }
}

#[test]
fn the_stream_is_cut_into_each_files_bytes_in_the_index_order() {
    let made = index(&[("hedwig.exe", 3), ("empty.txt", 0), (r"runtime\a.dll", 2)]);
    assert_eq!(made.length(), 5);
    assert_eq!(
        files(&made, b"abcde"),
        Ok(vec![
            ("hedwig.exe", &b"abc"[..]),
            ("empty.txt", &b""[..]),
            (r"runtime\a.dll", &b"de"[..]),
        ])
    );
}

#[test]
fn a_stream_shorter_than_its_index_says_is_refused() {
    let made = index(&[("hedwig.exe", 3), (r"runtime\a.dll", 2)]);
    for whole in [&b""[..], b"ab", b"abcd"] {
        assert_eq!(files(&made, whole), Err(PackError::Lengths), "{whole:?}");
    }
}

#[test]
fn a_stream_longer_than_its_index_says_is_refused() {
    let made = index(&[("hedwig.exe", 3), (r"runtime\a.dll", 2)]);
    assert_eq!(files(&made, b"abcdef"), Err(PackError::Lengths));
}
