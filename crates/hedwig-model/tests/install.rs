//! What an installation is named, and which folders cannot hold one.

use hedwig_model::install::{Names, Placement, RUN_LONGEST, Starts, key, placement, splits};

/// The client's own rule, written as `misc.c:1930-1946` does it: the first
/// `.exe`, then the first space after it. Kept here as the oracle the
/// model's predicate is checked against.
fn client_splits(path: &str) -> bool {
    match path.find(".exe") {
        None => false,
        Some(at) => path.get(at..).is_some_and(|rest| rest.contains(' ')),
    }
}

#[test]
fn a_path_the_client_splits_is_told_apart_from_one_it_does_not() {
    let measured = [
        (
            r"C:\Users\a\AppData\Local\Programs\ShuwariAfrica\Hedwig\hedwig.exe",
            false,
        ),
        (r"C:\work\a.exempt folder\Hedwig\hedwig.exe", true),
        (
            r"C:\Users\Jo Smith\AppData\Local\Programs\ShuwariAfrica\Hedwig\hedwig.exe",
            false,
        ),
        (
            r"C:\Users\x.exe y\AppData\Local\Programs\ShuwariAfrica\Hedwig\hedwig.exe",
            true,
        ),
        (
            r"C:\Users\X.EXE Y\AppData\Local\Programs\ShuwariAfrica\Hedwig\hedwig.exe",
            false,
        ),
        (r"C:\a.exe\b\hedwig.exe", false),
    ];
    for (path, expected) in measured {
        assert_eq!(splits(path), expected, "{path}");
    }
}

#[test]
fn the_rule_is_the_clients_over_generated_paths() {
    let parts = [
        "a", ".exe", " ", "b.exempt", "Hedwig", "X.EXE", "dir name", ".ex", "e ",
    ];
    let mut checked = 0;
    for first in parts {
        for second in parts {
            for third in parts {
                let path = format!(r"C:\{first}\{second}{third}\hedwig.exe");
                assert_eq!(splits(&path), client_splits(&path), "{path}");
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 729);
}

#[test]
fn the_persons_own_installation_and_a_keyed_one_share_no_name() {
    let own = Names::own();
    let other = Names::keyed(r"C:\scratch\run\data");
    assert_eq!(own.program_folder(), "Hedwig");
    assert_eq!(own.entry(), "ShuwariAfrica.Hedwig");
    assert_eq!(own.run_value(Starts::Hedwig), "hedwig");
    assert_eq!(own.run_value(Starts::Icon), "hedwig-interface");
    assert_eq!(own.shortcut(), "Hedwig.lnk");
    let at = key(r"C:\scratch\run\data");
    assert_eq!(at, key(r"c:\SCRATCH\run\DATA"), "the key ignores case");
    assert_eq!(other.program_folder(), format!("Hedwig {at}"));
    assert_eq!(other.entry(), format!("ShuwariAfrica.Hedwig.{at}"));
    assert_eq!(other.run_value(Starts::Hedwig), format!("hedwig.{at}"));
    assert_eq!(
        other.run_value(Starts::Icon),
        format!("hedwig-interface.{at}")
    );
    for starts in Starts::ALL {
        assert_ne!(own.run_value(starts), other.run_value(starts));
    }
    assert_ne!(own.entry(), other.entry());
}

#[test]
fn a_run_command_names_the_program_quoted_and_its_role() {
    let program = r"C:\Users\Jo Smith\AppData\Local\Programs\ShuwariAfrica\Hedwig";
    assert_eq!(
        Names::own().run_command(program, Starts::Hedwig),
        format!("\"{program}\\hedwig.exe\" supervise")
    );
    assert_eq!(
        Names::own().run_command(program, Starts::Icon),
        format!("\"{program}\\hedwig-interface.exe\" tray")
    );
    assert_eq!(
        Names::keyed(r"C:\a b\data").run_command(program, Starts::Hedwig),
        format!("\"{program}\\hedwig.exe\" supervise --folder \"C:\\a b\\data\"")
    );
}

#[test]
fn the_start_entry_opens_the_window_of_its_own_hedwig() {
    assert_eq!(Names::own().shortcut_arguments(), "");
    let keyed = Names::keyed(r"C:\a b\data");
    assert_eq!(keyed.shortcut_arguments(), r#"--folder "C:\a b\data""#);
    assert_ne!(keyed.shortcut(), Names::own().shortcut());
    for names in [Names::own(), keyed] {
        let refused = |c: char| r#"\/:*?"<>|"#.contains(c);
        assert!(!names.shortcut().contains(refused), "{}", names.shortcut());
    }
}

#[test]
fn a_folder_that_cannot_hold_hedwig_is_refused_with_its_reason() {
    let fits = r"C:\Users\a\AppData\Local\Programs\ShuwariAfrica\Hedwig";
    assert_eq!(placement(&Names::own(), fits), Ok(()));

    let split = r"C:\Users\x.exe y\AppData\Local\Programs\ShuwariAfrica\Hedwig";
    assert_eq!(
        placement(&Names::own(), split),
        Err(Placement::Splits {
            askpass: format!("{split}\\hedwig.exe")
        })
    );

    let deep = format!(
        r"C:\{}\Programs\ShuwariAfrica\Hedwig",
        "d".repeat(RUN_LONGEST)
    );
    let refused = placement(&Names::own(), &deep);
    assert!(
        matches!(&refused, Err(Placement::Long { command }) if command.chars().count() > RUN_LONGEST),
        "{refused:?}"
    );
    // The longest program folder whose icon command still fits.
    let room = RUN_LONGEST - "\"\\hedwig-interface.exe\" tray".len();
    let edge = format!(r"C:\{}", "e".repeat(room - 3));
    assert_eq!(placement(&Names::own(), &edge), Ok(()));
    let over = format!(r"C:\{}", "e".repeat(room - 2));
    assert!(matches!(
        placement(&Names::own(), &over),
        Err(Placement::Long { .. })
    ));
    for refusal in [refused.err(), placement(&Names::own(), split).err()] {
        let words = refusal
            .map(|refusal| refusal.to_string())
            .unwrap_or_default();
        assert!(words.starts_with("Hedwig cannot be installed"), "{words}");
    }
}
