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

fn misnamed(path: &str) -> Result<Index, PackError> {
    Err(PackError::Misnamed(path.to_owned()))
}

/// Every device name Windows reserves: the four named, then COM and LPT each
/// with one to nine and the superscript one, two and three.
fn devices() -> Vec<String> {
    let numbered = ["COM", "LPT"].into_iter().flat_map(|prefix| {
        [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u{b9}", "\u{b2}", "\u{b3}",
        ]
        .into_iter()
        .map(move |digit| format!("{prefix}{digit}"))
    });
    ["CON", "PRN", "AUX", "NUL"]
        .into_iter()
        .map(str::to_owned)
        .chain(numbered)
        .collect()
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
fn a_part_ending_in_a_period_is_refused() {
    for path in [
        r"a.\hedwig.exe",
        "hedwig.exe.",
        r"bin\...\hedwig.exe",
        "...",
    ] {
        assert_eq!(after_one(path), misnamed(path));
    }
}

#[test]
fn a_part_ending_in_a_space_is_refused() {
    for path in [
        r"a \hedwig.exe",
        "hedwig.exe ",
        r"bin\ \hedwig.exe",
        r". \x",
    ] {
        assert_eq!(after_one(path), misnamed(path));
    }
}

#[test]
fn a_part_naming_a_device_is_refused_alone_or_before_an_extension() {
    let mut named = 0;
    for device in devices() {
        for path in [
            device.clone(),
            device.to_lowercase(),
            format!("{device}.txt"),
            format!("{device}.tar.gz"),
            format!(r"{device}\hedwig.exe"),
            format!(r"bin\{}.dll", device.to_lowercase()),
        ] {
            assert_eq!(after_one(&path), misnamed(&path));
            named += 1;
        }
    }
    assert_eq!(named, 28 * 6);
}

#[test]
fn a_part_only_resembling_a_device_is_kept() {
    let resembling = index(&[
        ("NULx", 1),
        ("xNUL", 1),
        ("CONSOLE.txt", 1),
        ("AUXILIARY", 1),
        ("NUL x.txt", 1),
        (r"PRN-notes\a.txt", 1),
        ("COM10", 1),
        ("LPT10.log", 1),
        ("COM0", 1),
        ("LPT0", 1),
        ("COM\u{2074}", 1),
    ]);
    assert_eq!(resembling.clone().checked(), Ok(resembling));
}

#[test]
fn a_part_holding_a_character_windows_refuses_is_refused() {
    for character in ['<', '>', '"', '|', '?', '*', '\0', '\u{1}', '\t', '\u{1f}'] {
        let path = format!(r"bin\a{character}b.txt");
        assert_eq!(after_one(&path), misnamed(&path), "{character:?}");
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
            (".temp", 5),
            ("a!b~1 \u{7f}c.txt", 6),
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
