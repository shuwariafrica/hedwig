//! Text is checked where it enters. Each refusal here is one a document
//! author, a control client or a remote can provoke.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::text::{
    Address, Fingerprint, Folder, Grip, Host, Mark, Name, Pattern, PipeName, Port, Program,
    RemotePath, Secret, Serial, Template, TextError, Variable, Verbatim, Words,
};

mod support;
use support::{Seeded, address, pattern};

#[test]
fn a_name_is_lower_case_letters_digits_and_hyphens() {
    assert_eq!(Name::try_from("probe-rs").unwrap().as_str(), "probe-rs");
    assert_eq!(Name::try_from(""), Err(TextError::Empty));
    assert_eq!(
        Name::try_from("Gpg"),
        Err(TextError::Character { found: 'G', at: 0 })
    );
    assert_eq!(Name::try_from("-x"), Err(TextError::LeadingHyphen));
    assert_eq!(
        Name::try_from("a".repeat(64).as_str()),
        Err(TextError::TooLong {
            limit: 63,
            length: 64
        })
    );
}

/// An address becomes an argument of the route's client, so one that the
/// client would read as an option is refused here rather than quoted there.
#[test]
fn an_address_cannot_be_read_as_an_option_or_split_into_two_arguments() {
    assert!(Address::try_from("dev@build-7.example").is_ok());
    assert_eq!(
        Address::try_from("-oProxyCommand=calc"),
        Err(TextError::LeadingHyphen)
    );
    assert_eq!(
        Address::try_from("host -oProxyCommand=calc"),
        Err(TextError::Character { found: ' ', at: 4 })
    );
    assert_eq!(
        Address::try_from("host\n"),
        Err(TextError::Character { found: '\n', at: 4 })
    );
    // What OpenSSH refuses in a host name is refused here, where the in-box
    // client, which does not check, would pass it on to a proxy command.
    for found in "'`\"$\\;&<>|(){},".chars() {
        assert_eq!(
            Address::try_from(format!("dev{found}x").as_str()),
            Err(TextError::Character { found, at: 3 })
        );
        assert_eq!(
            Pattern::try_from(format!("dev{found}*").as_str()),
            Err(TextError::Character { found, at: 3 })
        );
    }
    assert!(Address::try_from("owner/workspace.agent").is_ok());
}

/// A route's client is named, never located: the name holds nothing a path
/// is written with, so the program can only be one Windows finds.
#[test]
fn a_program_is_a_name_and_never_a_location() {
    assert_eq!(Program::try_from("gh").unwrap().as_str(), "gh");
    assert!(Program::try_from("ssh.exe").is_ok());
    for (text, found, at) in [
        (r"C:\OpenSSH\ssh", ':', 1),
        ("tools/ssh", '/', 5),
        (r"..\ssh", '\\', 2),
        (".ssh", '.', 0),
        ("ssh probe", ' ', 3),
    ] {
        assert_eq!(
            Program::try_from(text),
            Err(TextError::Character { found, at }),
            "{text}"
        );
    }
    assert_eq!(Program::try_from("-ssh"), Err(TextError::LeadingHyphen));
    // An argument is passed as it is; only what would split a line is kept out.
    assert!(Verbatim::try_from(".[] | select(.state == \"Available\") | .name").is_ok());
    assert_eq!(
        Verbatim::try_from("a\nb"),
        Err(TextError::Character { found: '\n', at: 1 })
    );
}

#[test]
fn a_pattern_needs_a_wildcard_and_matches_runs_in_order() {
    assert_eq!(Pattern::try_from("dev-1"), Err(TextError::NoWildcard));
    let cases = [
        ("*", "anything", true),
        ("dev-*", "dev-", true),
        ("dev-*", "dev-build-7", true),
        ("dev-*", "prod-dev-1", false),
        ("*-prod", "eu-prod", true),
        ("*-prod", "eu-prod-2", false),
        ("a*b*c", "a-b-c", true),
        ("a*b*c", "a-c-b", false),
        ("ab*ba", "aba", false),
        ("a**b", "ab", true),
    ];
    for (glob, text, selected) in cases {
        assert_eq!(
            pattern(glob).matches(&address(text)),
            selected,
            "{glob} against {text}"
        );
    }
}

/// The property behind the cases: a pattern built by replacing a run of an
/// address with `*` always selects that address.
#[test]
fn a_pattern_cut_from_an_address_selects_it() {
    let alphabet: Vec<char> = "abc-.@7".chars().collect();
    let mut seeded = Seeded(7);
    for _ in 0..2000 {
        let length = 1 + seeded.below(12);
        let text: String = (0..length).map(|_| *seeded.pick(&alphabet)).collect();
        if text.starts_with('-') {
            continue;
        }
        let from = seeded.below(length);
        let to = from + seeded.below(length - from + 1);
        let glob = format!("{}*{}", text.get(..from).unwrap(), text.get(to..).unwrap());
        if glob.starts_with('-') {
            continue;
        }
        assert!(
            pattern(&glob).matches(&address(&text)),
            "{glob} must select {text}"
        );
    }
}

#[test]
fn a_template_holds_the_socket_path_exactly_once_and_nothing_a_shell_reads() {
    assert!(Template::try_from("localfilesystem:{}").is_ok());
    assert_eq!(
        Template::try_from("localfilesystem:"),
        Err(TextError::Placeholder)
    );
    assert_eq!(Template::try_from("{}{}"), Err(TextError::Placeholder));
    assert_eq!(Template::try_from("{x}"), Err(TextError::Placeholder));
    assert_eq!(
        Template::try_from("{};rm"),
        Err(TextError::Character { found: ';', at: 2 })
    );
}

#[test]
fn a_variable_is_an_environment_name() {
    assert!(Variable::try_from("ADB_SERVER_SOCKET").is_ok());
    assert_eq!(
        Variable::try_from("9X"),
        Err(TextError::Character { found: '9', at: 0 })
    );
    assert_eq!(
        Variable::try_from("a"),
        Err(TextError::Character { found: 'a', at: 0 })
    );
}

#[test]
fn a_host_is_a_name_or_an_address_literal() {
    assert!(Host::try_from("licence.lab.example").is_ok());
    assert!(Host::try_from("fd00::7").is_ok());
    assert_eq!(Host::try_from("-h"), Err(TextError::LeadingHyphen));
    assert_eq!(
        Host::try_from("a b"),
        Err(TextError::Character { found: ' ', at: 1 })
    );
}

/// Words come from a remote server and are shown in a terminal; an escape
/// sequence in them would drive that terminal.
#[test]
fn words_shown_to_the_person_keep_line_feeds_and_no_other_control_character() {
    assert!(Words::try_from("Verification code:\n").is_ok());
    assert_eq!(
        Words::try_from("\u{1b}[2J"),
        Err(TextError::Character {
            found: '\u{1b}',
            at: 0
        })
    );
}

#[test]
fn paths_and_marks_refuse_control_characters() {
    assert!(RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").is_ok());
    assert!(RemotePath::try_from("/tmp/a\0b").is_err());
    let folder = Folder::try_from(r"C:\Users\dev\AppData\Roaming\gnupg").unwrap();
    assert_eq!(
        folder.as_path(),
        std::path::Path::new(r"C:\Users\dev\AppData\Roaming\gnupg")
    );
    assert!(Mark::try_from("SHA256:abc/def+0").is_ok());
    assert_eq!(
        Mark::try_from("a b"),
        Err(TextError::Character { found: ' ', at: 1 })
    );
}

#[test]
fn port_zero_names_no_port() {
    assert_eq!(Port::try_from(0), Err(TextError::ZeroPort));
    assert_eq!(Port::try_from(5037).unwrap().number(), 5037);
}

#[test]
fn a_secret_is_never_printed() {
    let secret = Secret::from("correct horse".to_owned());
    assert_eq!(format!("{secret:?}"), "Secret(redacted)");
    assert_eq!(secret.expose(), "correct horse");
}

#[test]
fn every_text_refusal_says_what_was_wrong() {
    let said: Vec<String> = [
        TextError::Empty,
        TextError::TooLong {
            limit: 63,
            length: 64,
        },
        TextError::Character { found: ' ', at: 4 },
        TextError::LeadingHyphen,
        TextError::NoWildcard,
        TextError::Placeholder,
        TextError::ZeroPort,
        TextError::PipeName,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert!(said.iter().all(|sentence| !sentence.is_empty()));
    assert_eq!(said.get(2).unwrap(), "' ' at byte 4 is not allowed here");
}

/// A client reads the pipe's name from a file, so only the one form the core
/// writes is accepted: nothing that could name another pipe or a path.
#[test]
fn a_pipe_name_is_the_one_form_the_core_writes() {
    let name = PipeName::try_from("hedwig.9f86d081884c7d659a2feaa0c55ad015").unwrap();
    assert_eq!(
        name.to_path(),
        r"\\.\pipe\hedwig.9f86d081884c7d659a2feaa0c55ad015"
    );
    for refused in [
        "",
        "hedwig.",
        "hedwig.9f86d081884c7d659a2feaa0c55ad01",
        "hedwig.9f86d081884c7d659a2feaa0c55ad0150",
        "hedwig.9F86D081884C7D659A2FEAA0C55AD015",
        "hedwig.9f86d081884c7d659a2feaa0c55ad01g",
        r"hedwig.9f86d081884c7d659a2feaa0c55a\015",
        "openssh-ssh-agent",
        r"..\hedwig.9f86d081884c7d659a2feaa0c55ad015",
    ] {
        assert_eq!(
            PipeName::try_from(refused),
            Err(TextError::PipeName),
            "{refused}"
        );
    }
    assert_eq!(
        TextError::PipeName.to_string(),
        "it is not `hedwig.` and thirty-two hexadecimal digits"
    );
}

/// A keygrip is forty upper-case hexadecimal digits, a fingerprint forty or
/// sixty-four, as `GnuPG`'s own tools write them; a card's serial number is
/// what scdaemon writes. Each is told apart by its own form.
#[test]
fn a_keygrip_a_fingerprint_and_a_serial_number_are_each_their_own_form() {
    let forty = "64EFB4597F2EB1968F187B7235A461FC48342EC5";
    let sixty_four = "07B56DFBBA12BB80FA84939C76F8274EF16510880E5D4B6E1A2C3F405162738E";
    assert!(Grip::try_from(forty).is_ok());
    assert_eq!(
        Grip::try_from(sixty_four),
        Err(TextError::Digits { length: 64 })
    );
    assert_eq!(
        Grip::try_from(&forty[..39]),
        Err(TextError::Digits { length: 39 })
    );
    assert_eq!(
        Grip::try_from(forty.to_ascii_lowercase().as_str()),
        Err(TextError::Character { found: 'e', at: 2 })
    );
    assert!(Fingerprint::try_from(forty).is_ok());
    assert!(Fingerprint::try_from(sixty_four).is_ok());
    assert_eq!(
        Fingerprint::try_from("7F3A9C02D1E4B6A8"),
        Err(TextError::Digits { length: 16 })
    );
    assert!(Serial::try_from("D2760001240103040006123456780000").is_ok());
    assert_eq!(
        Serial::try_from("D276+0001"),
        Err(TextError::Character { found: '+', at: 4 })
    );
}
