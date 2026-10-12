//! Readiness as plain functions: the report a remote's shell prints read back
//! as it was said, refused whole when it did not run as written, and each
//! answer made into the far end a forward binds or the findings that keep it
//! from binding.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::num::NonZeroU16;

use hedwig_core::survey::{
    Answer, Asked, At, Dialect, Place, Plan, Question, Report, Unread, command, exercised, options,
    place, read, theirs,
};
use hedwig_model::capability::{Form, Query, ServicePort};
use hedwig_model::platform::{AgentForwarding, Platform, Sockets};
use hedwig_model::setting::Keepalive;
use hedwig_model::text::{Fingerprint, Kernel, Name, Port, RemotePath, Template, Variable, Words};
use hedwig_model::trail::{Asking, Binding, Finding, Prepared, Readiness, Serving};

const NONCE: &str = "5f1c0e2a9b8d7c6e5f4a3b2c1d0e9f8a";

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn hex(text: &str) -> String {
    if text.is_empty() {
        return "-".to_owned();
    }
    text.bytes().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

fn said(words: &str) -> String {
    format!("hedwig {NONCE} {words}")
}

fn linux() -> Platform {
    Platform {
        family: name("linux"),
        kernel: Kernel::try_from("Linux").unwrap(),
        sockets: Sockets::Unix {
            path_bytes: NonZeroU16::new(108).unwrap(),
        },
        agent_forwarding: AgentForwarding::Served,
    }
}

fn macos() -> Platform {
    Platform {
        family: name("macos"),
        kernel: Kernel::try_from("Darwin").unwrap(),
        sockets: Sockets::Unix {
            path_bytes: NonZeroU16::new(104).unwrap(),
        },
        agent_forwarding: AgentForwarding::Served,
    }
}

const SOCKET: &str = "/run/user/1000/gnupg/S.gpg-agent";

fn socket() -> RemotePath {
    RemotePath::try_from(SOCKET).unwrap()
}

fn gpg() -> Form {
    Form::SocketAt(Query::AgentSocket)
}

fn at(state: At) -> Answer {
    Answer {
        place: Some(Place {
            path: SOCKET.as_bytes().to_vec(),
            at: Some(state),
            ..Place::default()
        }),
        ..Answer::default()
    }
}

fn placed(form: &Form, platform: &Platform, answer: &Answer) -> (Readiness, Option<Serving>) {
    let placed = place(&name("gpg"), form, platform, answer, &[], &[]);
    (placed.readiness, placed.serving)
}

fn blocked(finding: Finding) -> (Readiness, Option<Serving>) {
    (Readiness::Unready(vec![finding]), None)
}

fn serving() -> Serving {
    Serving {
        capability: name("gpg"),
        binding: Binding::Socket(socket()),
    }
}

/// Every line a survey reports reads back as what was said, around what the
/// remote's login scripts printed and lines of another survey's.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one report, every kind of line in it"
)]
fn a_report_reads_back_as_the_remote_said_it() {
    let output = [
        "Welcome to build-7".to_owned(),
        said("begin posix"),
        said(&format!("kernel {}", hex("Linux"))),
        said(&format!("shell {}", hex("/usr/bin/fish"))),
        format!(
            "hedwig 00000000000000000000000000000000 kernel {}",
            hex("Darwin")
        ),
        said(&format!("path gpg {}", hex(SOCKET))),
        said(&format!("created gpg {}", hex("/run/user/1000/gnupg"))),
        said(&format!("filesystem gpg {}", hex("tmpfs"))),
        said("at gpg removed"),
        said("autostart gpg on"),
        said("keyboxd gpg off"),
        said("key gpg 0E5D4B6E1A2C3F40516273847F3A9C02D1E4B6A8 absent"),
        said(&format!("signing gpg {}", hex("7F3A9C02D1E4B6A8!"))),
        said(&format!("format gpg {}", hex(""))),
        said("absent ssh-agent gpgconf"),
        said("listener adb 5037 present"),
        said(&format!(
            "at openocd uncleared {}",
            hex("rm: Permission denied")
        )),
        said(&format!(
            "uncreatable pyocd {}",
            hex("mkdir: Read-only file system")
        )),
        said("signing other unset"),
        said("end\r"),
    ]
    .join("\n");
    let report = read(&output, NONCE).unwrap();
    let mut answers = BTreeMap::new();
    answers.insert(
        name("gpg"),
        Answer {
            place: Some(Place {
                path: SOCKET.as_bytes().to_vec(),
                created: Some(b"/run/user/1000/gnupg".to_vec()),
                uncreatable: None,
                filesystem: Some(b"tmpfs".to_vec()),
                at: Some(At::Removed),
            }),
            autostart: Some(true),
            keyboxd: Some(false),
            keys: [(
                Fingerprint::try_from("0E5D4B6E1A2C3F40516273847F3A9C02D1E4B6A8").unwrap(),
                false,
            )]
            .into_iter()
            .collect(),
            signing: Some(Some(b"7F3A9C02D1E4B6A8!".to_vec())),
            format: Some(Vec::new()),
            ..Answer::default()
        },
    );
    answers.insert(
        name("ssh-agent"),
        Answer {
            absent: Some(name("gpgconf")),
            ..Answer::default()
        },
    );
    answers.insert(
        name("adb"),
        Answer {
            listeners: [(Port::try_from(5037).unwrap(), true)]
                .into_iter()
                .collect(),
            ..Answer::default()
        },
    );
    answers.insert(
        name("openocd"),
        Answer {
            place: Some(Place {
                at: Some(At::Uncleared(b"rm: Permission denied".to_vec())),
                ..Place::default()
            }),
            ..Answer::default()
        },
    );
    answers.insert(
        name("pyocd"),
        Answer {
            place: Some(Place {
                uncreatable: Some(b"mkdir: Read-only file system".to_vec()),
                ..Place::default()
            }),
            ..Answer::default()
        },
    );
    answers.insert(
        name("other"),
        Answer {
            signing: Some(None),
            ..Answer::default()
        },
    );
    assert_eq!(
        report,
        Report {
            dialect: Dialect::Posix,
            kernel: Kernel::try_from("Linux").unwrap(),
            shell: b"/usr/bin/fish".to_vec(),
            answers,
            issued: None,
        }
    );
}

/// A report is read whole or not at all: one that never began, one cut off
/// before its end, and one that says something it was not asked are each
/// told apart.
#[test]
fn a_report_that_did_not_run_as_written_is_refused_for_what_went_wrong() {
    let noise = "sh: 1: /bin/sh: not found";
    assert_eq!(read(noise, NONCE), Err(Unread::NotBegun));
    let cut = [
        said("begin posix"),
        said(&format!("kernel {}", hex("Linux"))),
    ]
    .join("\n");
    assert_eq!(read(&cut, NONCE), Err(Unread::Unfinished));
    for line in [
        "at gpg taken",
        "kernel zz",
        "listener adb 70000 present",
        "path GPG 2f",
        "autostart gpg maybe",
        "reboot",
    ] {
        let output = [said("begin posix"), said(line), said("end")].join("\n");
        assert_eq!(
            read(&output, NONCE),
            Err(Unread::Malformed(line.to_owned())),
            "{line}"
        );
    }
    let nameless = [said("begin posix"), said("end")].join("\n");
    assert!(matches!(read(&nameless, NONCE), Err(Unread::Malformed(_))));
}

/// What the remote reports at a socket's path decides whether the forward
/// goes there: nothing there, or a socket nothing answered at and readiness
/// removed, is carried; anything that answers or cannot be judged is named
/// and left.
#[test]
fn what_is_at_the_path_decides_whether_the_forward_goes_there() {
    let linux = linux();
    assert_eq!(
        placed(&gpg(), &linux, &at(At::Free)),
        (Readiness::Ready, Some(serving()))
    );
    assert_eq!(
        placed(&gpg(), &linux, &at(At::Ours)),
        (Readiness::Ready, Some(serving()))
    );
    let removed = place(&name("gpg"), &gpg(), &linux, &at(At::Removed), &[], &[]);
    assert_eq!(removed.prepared, [Prepared::Removed(socket())]);
    assert_eq!(
        (removed.readiness, removed.serving),
        (Readiness::Ready, Some(serving()))
    );
    for (state, finding) in [
        (At::Occupied, Finding::Occupied(socket())),
        (At::Agent, Finding::AgentLive(socket())),
        (At::Answers, Finding::Answers(socket())),
        (At::Silent, Finding::Silent(socket())),
        (At::Unprobed, Finding::Unprobed(socket())),
        (
            At::Uncleared(b"rm: Permission denied".to_vec()),
            Finding::Uncleared(Words::try_from("rm: Permission denied").unwrap()),
        ),
    ] {
        assert_eq!(placed(&gpg(), &linux, &at(state)), blocked(finding));
    }
}

/// The folder a socket needs is made and recorded; one that cannot be made,
/// a path longer than the platform's `sun_path` takes, a path that is not
/// absolute, and a folder other hosts share each keep the forward away.
#[test]
fn the_socket_needs_a_folder_a_fitting_path_and_a_home_of_its_own() {
    let linux = linux();
    let mut made = at(At::Free);
    made.place.as_mut().unwrap().created = Some(b"/run/user/1000/gnupg".to_vec());
    let made = place(&name("gpg"), &gpg(), &linux, &made, &[], &[]);
    assert_eq!(
        made.prepared,
        [Prepared::Created(
            RemotePath::try_from("/run/user/1000/gnupg").unwrap()
        )]
    );
    assert_eq!(made.serving, Some(serving()));

    let mut unmade = at(At::Free);
    unmade.place.as_mut().unwrap().at = None;
    unmade.place.as_mut().unwrap().uncreatable = Some(b"mkdir: Read-only file system".to_vec());
    assert_eq!(
        placed(&gpg(), &linux, &unmade),
        blocked(Finding::ParentUncreatable(
            Words::try_from("mkdir: Read-only file system").unwrap()
        ))
    );

    // 103 bytes fit macOS's sun_path with its terminator; 104 do not.
    let long = format!("/Users/{}/.gnupg/S.gpg-agent", "d".repeat(78));
    assert_eq!(long.len(), 104);
    let mut answer = at(At::Free);
    answer.place.as_mut().unwrap().path = long.as_bytes().to_vec();
    assert_eq!(
        placed(&gpg(), &macos(), &answer).0,
        Readiness::Unready(vec![Finding::PathTooLong {
            usable: 103,
            length: 104
        }])
    );
    assert!(placed(&gpg(), &linux, &answer).1.is_some());

    let mut relative = at(At::Free);
    relative.place.as_mut().unwrap().path = b"S.gpg-agent".to_vec();
    assert_eq!(
        placed(&gpg(), &linux, &relative),
        blocked(Finding::PathUnusable)
    );

    let mut shared = at(At::Free);
    shared.place.as_mut().unwrap().filesystem = Some(b"nfs4".to_vec());
    assert_eq!(
        placed(&gpg(), &linux, &shared),
        blocked(Finding::SharedHome(Words::try_from("nfs4").unwrap()))
    );
    shared.place.as_mut().unwrap().filesystem = Some(b"ext2/ext3".to_vec());
    assert_eq!(
        placed(&gpg(), &linux, &shared),
        (Readiness::Ready, Some(serving()))
    );
}

/// What stands between the remote's gpg and the key is named beside a
/// forward that is carried: an agent that starts on its own, a keyring it
/// cannot then read, a public key it lacks, and a signing key git does not
/// name or names otherwise. Git set to sign another way says nothing here.
#[test]
fn what_stands_between_gpg_and_the_key_is_named_and_carried() {
    let linux = linux();
    let key = Fingerprint::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap();
    let mut answer = at(At::Free);
    answer.autostart = Some(true);
    answer.keyboxd = Some(true);
    answer.keys = [(key.clone(), false)].into_iter().collect();
    answer.signing = Some(None);
    let named = place(
        &name("gpg"),
        &gpg(),
        &linux,
        &answer,
        std::slice::from_ref(&key),
        &[],
    );
    assert_eq!(
        named.readiness,
        Readiness::Unready(vec![
            Finding::AgentAutostarts,
            Finding::PublicKeyAbsent(key.clone()),
            Finding::SigningKeyUnset,
        ])
    );
    assert_eq!(named.serving, Some(serving()));

    answer.autostart = Some(false);
    answer.keys.insert(key.clone(), true);
    answer.signing = Some(Some(b"0x95A6B7C8D9E0F1A2!".to_vec()));
    assert_eq!(
        place(
            &name("gpg"),
            &gpg(),
            &linux,
            &answer,
            std::slice::from_ref(&key),
            &[]
        )
        .readiness,
        Readiness::Unready(vec![Finding::KeyboxdStopped])
    );

    answer.keyboxd = Some(false);
    answer.signing = Some(Some(b"DEADBEEF".to_vec()));
    assert_eq!(
        place(
            &name("gpg"),
            &gpg(),
            &linux,
            &answer,
            std::slice::from_ref(&key),
            &[]
        )
        .readiness,
        Readiness::Unready(vec![Finding::SigningKeyOther(
            Words::try_from("DEADBEEF").unwrap()
        )])
    );
    answer.format = Some(b"ssh".to_vec());
    assert_eq!(
        place(&name("gpg"), &gpg(), &linux, &answer, &[key], &[]).readiness,
        Readiness::Ready
    );
}

/// A port is carried where nothing on the remote listens on it; a tool the
/// remote lacks and a socket the report says nothing of keep a capability
/// away; the person's own forwards are named on every capability and keep
/// none away.
#[test]
fn a_port_a_missing_tool_and_the_persons_forwards() {
    let linux = linux();
    let port = Port::try_from(5037).unwrap();
    let adb = Form::Port(ServicePort::Fixed(port));
    let mut answer = Answer::default();
    assert_eq!(
        place(&name("adb"), &adb, &linux, &answer, &[], &[]).serving,
        Some(Serving {
            capability: name("adb"),
            binding: Binding::Port(port),
        })
    );
    answer.listeners.insert(port, true);
    let listened = place(&name("adb"), &adb, &linux, &answer, &[], &[]);
    assert_eq!(
        (listened.readiness, listened.serving),
        (
            Readiness::Unready(vec![Finding::ListenerPresent(port)]),
            None
        )
    );

    let absent = Answer {
        absent: Some(name("gpgconf")),
        ..Answer::default()
    };
    assert_eq!(
        placed(&gpg(), &linux, &absent),
        blocked(Finding::ToolAbsent(name("gpgconf")))
    );
    assert!(matches!(
        placed(&gpg(), &linux, &Answer::default()),
        (Readiness::Unready(findings), None)
            if matches!(findings.as_slice(), [Finding::Unsurveyed(_)])
    ));

    let forward = Words::try_from("localforward 8080 [localhost]:80").unwrap();
    let theirs = place(
        &name("gpg"),
        &gpg(),
        &linux,
        &at(At::Free),
        &[],
        std::slice::from_ref(&forward),
    );
    assert_eq!(
        (theirs.readiness, theirs.serving),
        (
            Readiness::Unready(vec![Finding::TheirForward(forward)]),
            Some(serving())
        )
    );
}

/// The forwards `ssh -G` states for a host are the person's own; nothing
/// else it states is.
#[test]
fn the_persons_forwards_are_read_from_what_the_client_states() {
    let stated = "host build-7\nuser dev\nlocalforward 8080 [localhost]:80\n\
                  remoteforward /run/user/1000/gnupg/S.gpg-agent [127.0.0.1]:47470\n\
                  dynamicforward 1080\nforwardagent yes\n";
    let forwards: Vec<String> = theirs(stated)
        .into_iter()
        .map(|forward| forward.as_str().to_owned())
        .collect();
    assert_eq!(
        forwards,
        [
            "localforward 8080 [localhost]:80",
            "remoteforward /run/user/1000/gnupg/S.gpg-agent [127.0.0.1]:47470",
            "dynamicforward 1080",
        ]
    );
}

/// Each capability's forms raise one question each, whichever platform the
/// remote turns out to be.
#[test]
fn each_form_raises_its_question() {
    let adb = [
        Form::PrivateSocket {
            variable: Variable::try_from("ADB_SERVER_SOCKET").unwrap(),
            value: Template::try_from("localfilesystem:{}").unwrap(),
        },
        Form::Port(ServicePort::Fixed(Port::try_from(5037).unwrap())),
        Form::Port(ServicePort::Unstated),
    ];
    assert_eq!(
        Question::of(&adb),
        [
            Question::Private {
                variable: Variable::try_from("ADB_SERVER_SOCKET").unwrap(),
                value: Template::try_from("localfilesystem:{}").unwrap(),
            },
            Question::Port(Port::try_from(5037).unwrap()),
        ]
    );
    let gpg = [
        Form::SocketAt(Query::AgentSocket),
        Form::SocketFileAt(Query::AgentSocket),
    ];
    assert_eq!(Question::of(&gpg), [Question::Socket(Query::AgentSocket)]);
}

/// An opener's form asks for the remote's `curl` and a socket in Hedwig's
/// private folder, which the survey seals once bound; placed, it is carried
/// there, and with no `curl` it is not carried at all.
#[test]
fn an_opener_is_placed_as_a_private_socket_and_needs_the_remotes_curl() {
    use hedwig_core::survey::{OPENERS, posix, seals};
    use hedwig_model::trail::Write;

    assert_eq!(Question::of(&[Form::Opener]), [Question::Opener]);
    let plan = Plan {
        asks: vec![Asked {
            capability: name("sign-in"),
            server: None,
            questions: vec![Question::Opener],
        }],
        writes: OPENERS
            .iter()
            .map(|(variable, _)| {
                (
                    name("sign-in"),
                    Write::Variable(Variable::try_from(*variable).unwrap()),
                )
            })
            .collect(),
        ..Plan::default()
    };
    assert!(seals(&plan));
    let script = posix(&plan, "n");
    assert!(script.contains("command -v curl >/dev/null 2>&1 || say absent sign-in curl"));
    assert!(script.contains(r#"setvar sign-in BROWSER "curl -q -fsS --noproxy hedwig --unix-socket $hedwig_socket --data-raw %s hedwig/""#));
    assert!(script.contains(r#"setvar sign-in GH_BROWSER "curl -q -fsS --noproxy hedwig --unix-socket $hedwig_socket hedwig/ --data-raw""#));
    // No value an opener splits on `:` can hold a scheme.
    for (_, command) in OPENERS {
        assert!(!command.contains(':'), "{command}");
    }

    let linux = linux();
    let path = "/run/user/1000/hedwig/sign-in";
    let free = Answer {
        place: Some(Place {
            path: path.as_bytes().to_vec(),
            at: Some(At::Free),
            ..Place::default()
        }),
        ..Answer::default()
    };
    assert_eq!(
        place(&name("sign-in"), &Form::Opener, &linux, &free, &[], &[]).serving,
        Some(Serving {
            capability: name("sign-in"),
            binding: Binding::Socket(RemotePath::try_from(path).unwrap()),
        })
    );
    let without = Answer {
        absent: Some(name("curl")),
        ..free
    };
    let placed = place(&name("sign-in"), &Form::Opener, &linux, &without, &[], &[]);
    assert_eq!(
        placed.readiness,
        Readiness::Unready(vec![Finding::ToolAbsent(name("curl"))])
    );
}

/// The survey's connection runs its own command with no terminal and asks
/// for none of the person's forwards; PowerShell is handed the script on its
/// input, and its command line holds only what reads it.
#[test]
fn the_survey_runs_its_own_command_and_no_forward() {
    let asked = options(Asking::Nobody, Keepalive::SHIPS);
    assert_eq!(asked.first().map(String::as_str), Some("-T"));
    for option in [
        "BatchMode=yes",
        "ClearAllForwardings=yes",
        "RemoteCommand=none",
        "SessionType=default",
        "StdinNull=no",
        "ForkAfterAuthentication=no",
        "ControlMaster=no",
        "Tag=hedwig",
        "ServerAliveInterval=15",
        "ServerAliveCountMax=3",
    ] {
        assert!(asked.iter().any(|given| given == option), "{option}");
    }
    assert_eq!(command(Dialect::Posix), ["/bin/sh", "-s"]);
    let powershell = command(Dialect::PowerShell);
    let encoded = powershell.last().unwrap();
    let bytes = decode(encoded);
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| u16::from_le_bytes(pair.try_into().unwrap()))
        .collect();
    assert_eq!(
        String::from_utf16(&units).unwrap(),
        "$s = [Console]::In.ReadToEnd(); Invoke-Expression $s"
    );
}

fn decode(text: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut held = 0;
    let mut out = Vec::new();
    for byte in text.bytes().filter(|byte| *byte != b'=') {
        let value = alphabet.iter().position(|known| *known == byte).unwrap();
        bits = (bits << 6) | u32::try_from(value).unwrap();
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push(u8::try_from((bits >> held) & 0xff).unwrap());
        }
    }
    out
}

/// What an exercise reports is the tool's last words, the tool the remote
/// lacks, or the keyring it lacks; one that did not run as written is
/// refused like a survey's.
#[test]
fn an_exercise_reports_what_the_tool_said() {
    let ran = [
        said("begin posix"),
        said(&format!(
            "ran 2 {}",
            hex("gpg: signing failed: No secret key")
        )),
        said("end"),
    ]
    .join("\n");
    assert_eq!(
        exercised(&ran, NONCE),
        Ok(Ok(Some(
            Words::try_from("gpg: signing failed: No secret key").unwrap()
        )))
    );
    let quiet = [said("begin posix"), said("ran 0 -"), said("end")].join("\n");
    assert_eq!(exercised(&quiet, NONCE), Ok(Ok(None)));
    let absent = [said("begin posix"), said("absent gpg"), said("end")].join("\n");
    assert_eq!(
        exercised(&absent, NONCE),
        Ok(Err(Finding::ToolAbsent(name("gpg"))))
    );
    let unkeyed = [said("begin posix"), said("unkeyed"), said("end")].join(
        "
",
    );
    assert_eq!(exercised(&unkeyed, NONCE), Ok(Err(Finding::KeyringAbsent)));
    assert_eq!(exercised("", NONCE), Err(Unread::NotBegun));
    assert_eq!(
        exercised(&said("begin posix"), NONCE),
        Err(Unread::Unfinished)
    );
}

/// A plan the deciding thread makes is what the script is written from.
#[test]
fn a_plan_is_written_into_both_dialects() {
    let plan = Plan {
        asks: vec![Asked {
            capability: name("gpg"),
            server: None,
            questions: vec![Question::Socket(Query::AgentSocket)],
        }],
        ours: vec![socket()],
        keys: vec![Fingerprint::try_from("0E5D4B6E1A2C3F40516273847F3A9C02D1E4B6A8").unwrap()],
        ..Plan::default()
    };
    let posix = hedwig_core::survey::posix(&plan, NONCE);
    assert!(posix.contains(&format!("n={NONCE}")));
    assert!(posix.contains("ours() { case $1 in '/run/user/1000/gnupg/S.gpg-agent') return 0"));
    assert!(posix.contains("'0E5D4B6E1A2C3F40516273847F3A9C02D1E4B6A8'"));
    let powershell = hedwig_core::survey::powershell(&plan, NONCE);
    assert!(powershell.contains("$ours = @('/run/user/1000/gnupg/S.gpg-agent')"));
}

/// A unit of the remote's service manager at the path is named, never taken
/// for an agent nobody started, and keeps the forward away: connecting to it
/// would start the remote's own agent.
#[test]
fn a_unit_the_service_manager_holds_the_path_for_is_named_and_blocks() {
    let output = [
        said("begin posix"),
        said(&format!("kernel {}", hex("Linux"))),
        said(&format!("path gpg {}", hex(SOCKET))),
        said(&format!("at gpg held {}", hex("gpg-agent.socket"))),
        said("end"),
    ]
    .join("\n");
    let report = read(&output, NONCE).unwrap();
    let answer = report.answers.get(&name("gpg")).unwrap();
    assert_eq!(
        answer.place.as_ref().unwrap().at,
        Some(At::Held(b"gpg-agent.socket".to_vec()))
    );
    let finding = Finding::UnitListens {
        unit: Words::try_from("gpg-agent.socket").unwrap(),
        path: socket(),
    };
    assert!(finding.blocks());
    assert_eq!(placed(&gpg(), &linux(), answer), blocked(finding));
}

/// The mask is written where the unit is surveyed, only under consent, with
/// the outermost folder it made; and taken back by unmasking, listening
/// again and removing that folder while it is empty.
#[test]
fn a_consented_mask_is_planned_reported_and_taken_back() {
    use hedwig_core::survey::{Asked, Undo, posix};
    use hedwig_model::trail::Write;

    let asked = |writes: Vec<(Name, Write)>| Plan {
        asks: vec![Asked {
            capability: name("gpg"),
            server: None,
            questions: vec![Question::Socket(Query::AgentSocket)],
        }],
        writes,
        ..Plan::default()
    };
    let consented = posix(&asked(vec![(name("gpg"), Write::Masked)]), NONCE);
    assert!(consented.contains(r#"place gpg "$(gpgconf --list-dirs agent-socket)" assuan mask"#));
    let inspected = posix(&asked(Vec::new()), NONCE);
    assert!(inspected.contains(r#"place gpg "$(gpgconf --list-dirs agent-socket)" assuan keep"#));

    let unit = "/home/dev/.config/systemd/user/gpg-agent.socket";
    let output = [
        said("begin posix"),
        said(&format!("kernel {}", hex("Linux"))),
        said(&format!(
            "wrote gpg masked {} {}",
            hex(unit),
            hex("/home/dev/.config")
        )),
        said(&format!(
            "wrote gpg no-autostart {}",
            hex("/home/dev/.gnupg/common.conf")
        )),
        said("end"),
    ]
    .join("\n");
    let report = read(&output, NONCE).unwrap();
    assert_eq!(
        report.answers.get(&name("gpg")).unwrap().wrote,
        [
            (
                Write::Masked,
                unit.as_bytes().to_vec(),
                Some(b"/home/dev/.config".to_vec())
            ),
            (
                Write::NoAutostart,
                b"/home/dev/.gnupg/common.conf".to_vec(),
                None
            ),
        ]
    );

    let undo = posix(
        &Plan {
            undo: vec![Undo {
                capability: name("gpg"),
                write: Write::Masked,
                place: RemotePath::try_from(unit).unwrap(),
                made: Some(RemotePath::try_from("/home/dev/.config").unwrap()),
            }],
            ..Plan::default()
        },
        NONCE,
    );
    assert!(undo.contains(r#"systemctl --user unmask -- "$(basename -- '/home/dev/.config/systemd/user/gpg-agent.socket')""#));
    assert!(undo.contains(r#"systemctl --user start -- "$(basename -- '/home/dev/.config/systemd/user/gpg-agent.socket')""#));
    assert!(
        undo.contains(
            "unmade '/home/dev/.config/systemd/user/gpg-agent.socket' '/home/dev/.config'"
        )
    );
}

/// What a command the remote's SSH server runs has in a tool's variable is
/// read from the survey's own command; one that misses the forward is named,
/// unless this survey has just written the variable or could not.
#[test]
fn a_command_that_misses_the_forward_through_its_variable_is_named() {
    use hedwig_model::trail::Write;

    let agent = Form::SocketAt(Query::AgentSshSocket);
    let ssh = "/run/user/1000/gnupg/S.gpg-agent.ssh";
    let report = |lines: &[&str]| {
        let mut output = vec![
            said("begin posix"),
            said(&format!("kernel {}", hex("Linux"))),
            said(&format!("path ssh-agent {}", hex(ssh))),
            said("at ssh-agent free"),
        ];
        output.extend(lines.iter().map(|line| said(line)));
        output.push(said("end"));
        read(&output.join("\n"), NONCE).unwrap()
    };
    let readiness = |report: &Report| {
        place(
            &name("ssh-agent"),
            &agent,
            &linux(),
            report.answers.get(&name("ssh-agent")).unwrap(),
            &[],
            &[],
        )
        .readiness
    };
    let variable = Variable::try_from("SSH_AUTH_SOCK").unwrap();
    let missed = report(&["command ssh-agent SSH_AUTH_SOCK absent"]);
    assert_eq!(
        missed.answers.get(&name("ssh-agent")).unwrap().commands,
        BTreeMap::from([(variable.clone(), false)])
    );
    assert_eq!(
        readiness(&missed),
        Readiness::Unready(vec![Finding::VariableUnset(variable.clone())])
    );
    assert!(!Finding::VariableUnset(variable.clone()).blocks());
    assert_eq!(
        readiness(&report(&["command ssh-agent SSH_AUTH_SOCK present"])),
        Readiness::Ready
    );
    let written = format!(
        "wrote ssh-agent variable:SSH_AUTH_SOCK {}",
        hex("/home/dev/.bashrc")
    );
    assert_eq!(
        readiness(&report(&[
            "command ssh-agent SSH_AUTH_SOCK absent",
            &written
        ])),
        Readiness::Ready
    );
    let unwritten = format!(
        "unwritten ssh-agent variable:SSH_AUTH_SOCK {}",
        hex("the login shell reads its startup from files Hedwig does not know")
    );
    let readiness = readiness(&report(&[
        "command ssh-agent SSH_AUTH_SOCK absent",
        &unwritten,
    ]));
    assert!(matches!(&readiness, Readiness::Unready(findings)
            if matches!(findings.as_slice(), [Finding::Unwritten { write: Write::Variable(_), .. }])));
    let script = hedwig_core::survey::posix(
        &Plan {
            asks: vec![Asked {
                capability: name("ssh-agent"),
                server: None,
                questions: vec![Question::Socket(Query::AgentSshSocket)],
            }],
            ..Plan::default()
        },
        NONCE,
    );
    let seen = script.find("seen_SSH_AUTH_SOCK=${SSH_AUTH_SOCK-}").unwrap();
    assert!(seen < script.find("place ssh-agent").unwrap());
    assert!(script.contains(
        r#"if [ "$seen_SSH_AUTH_SOCK" = "$p" ]; then say command ssh-agent SSH_AUTH_SOCK present"#
    ));
}

/// A server the remote's own `adb` started where the forward would bind - at
/// the private socket behind `ADB_SERVER_SOCKET`, or on port 5037 - is named
/// as that, and keeps the capability off the channel; the report says which
/// program listens, as the remote's own `ss` names it.
#[test]
fn a_remote_adb_server_where_the_forward_would_bind_is_named_and_keeps_it_off() {
    const PRIVATE: &str = "/run/user/1000/hedwig/adb";
    let output = [
        said("begin posix"),
        said(&format!("kernel {}", hex("Linux"))),
        said(&format!("path adb {}", hex(PRIVATE))),
        said("at adb server adb"),
        said("listener adb-tcp 5037 server adb"),
        said("end"),
    ]
    .join("\n");
    let report = read(&output, NONCE).unwrap();
    let private = report.answers.get(&name("adb")).unwrap();
    assert_eq!(
        private.place.as_ref().and_then(|place| place.at.clone()),
        Some(At::Server(name("adb")))
    );
    let form = Form::PrivateSocket {
        variable: Variable::try_from("ADB_SERVER_SOCKET").unwrap(),
        value: Template::try_from("localfilesystem:{}").unwrap(),
    };
    let placed = place(&name("adb"), &form, &linux(), private, &[], &[]);
    assert_eq!(
        (placed.readiness, placed.serving),
        (
            Readiness::Unready(vec![Finding::ServerLive {
                program: name("adb"),
                at: Binding::Socket(RemotePath::try_from(PRIVATE).unwrap()),
            }]),
            None
        )
    );
    let port = Port::try_from(5037).unwrap();
    let tcp = report.answers.get(&name("adb-tcp")).unwrap();
    let placed = place(
        &name("adb-tcp"),
        &Form::Port(ServicePort::Fixed(port)),
        &linux(),
        tcp,
        &[],
        &[],
    );
    assert_eq!(
        (placed.readiness, placed.serving),
        (
            Readiness::Unready(vec![Finding::ServerLive {
                program: name("adb"),
                at: Binding::Port(port),
            }]),
            None
        )
    );
}

/// A survey with a private socket opens Hedwig's private folder before it
/// places the socket, and after its report waits for the word that seals the
/// folder; one without leaves no shell waiting.
#[test]
fn a_survey_with_a_private_socket_opens_the_folder_and_waits_to_seal_it() {
    let private = Plan {
        asks: vec![Asked {
            capability: name("adb"),
            questions: vec![Question::Private {
                variable: Variable::try_from("ADB_SERVER_SOCKET").unwrap(),
                value: Template::try_from("localfilesystem:{}").unwrap(),
            }],
            server: Some(name("adb")),
        }],
        ..Plan::default()
    };
    assert!(hedwig_core::survey::seals(&private));
    let script = hedwig_core::survey::posix(&private, NONCE);
    let opened = script.find(r#"[ -d "$r" ] && chmod u+w "$r""#).unwrap();
    let placed = script.find(r#"place adb "$r/adb" adb"#).unwrap();
    assert!(opened < placed);
    assert!(script.ends_with(
        "say end\nIFS= read -r w || exit 0\n[ \"$w\" = seal ] && [ -n \"${hedwig:-}\" ] && chmod a-w \"$hedwig\"\n"
    ));
    assert_eq!(hedwig_core::survey::SEALING, b"seal\n");
    let port = Plan {
        asks: vec![Asked {
            capability: name("openocd"),
            questions: vec![Question::Port(Port::try_from(3333).unwrap())],
            server: None,
        }],
        ..Plan::default()
    };
    assert!(!hedwig_core::survey::seals(&port));
    assert!(hedwig_core::survey::posix(&port, NONCE).ends_with("say end\n"));
}

/// The survey asks the remote's own `ss` which program holds an ADB binding,
/// and only for a capability whose tool runs a server of its own.
#[test]
fn the_survey_asks_which_program_holds_a_binding_only_of_a_tool_that_runs_a_server() {
    let adb = Asked {
        capability: name("adb"),
        questions: vec![
            Question::Private {
                variable: Variable::try_from("ADB_SERVER_SOCKET").unwrap(),
                value: Template::try_from("localfilesystem:{}").unwrap(),
            },
            Question::Port(Port::try_from(5037).unwrap()),
        ],
        server: Some(name("adb")),
    };
    let openocd = Asked {
        capability: name("openocd"),
        questions: vec![Question::Port(Port::try_from(3333).unwrap())],
        server: None,
    };
    let plan = Plan {
        asks: vec![adb, openocd],
        ..Plan::default()
    };
    let script = hedwig_core::survey::posix(&plan, NONCE);
    assert!(script.contains(r#"place adb "$r/adb" adb"#), "{script}");
    assert!(script.contains("if served 5037 adb; then say listener adb 5037 server adb;"));
    assert!(script.contains("case $? in 0) say listener openocd 3333 present ;;"));
    assert!(script.contains(r#"ss -Hxlp src "$1""#));
    let windows = hedwig_core::survey::powershell(&plan, NONCE);
    assert!(windows.contains("-eq 'adb') { Say listener, adb, 5037, server, adb }"));
}

/// An SSH client needs no `GnuPG`: an agent's socket goes where the remote's
/// `gpgconf` names it, and where the remote has none and the grant consents
/// to `SSH_AUTH_SOCK`, in Hedwig's own folder, sealed as every socket there
/// is. Without that consent a remote with no `gpgconf` is told it lacks it.
#[test]
fn an_agent_s_socket_needs_no_gpgconf_where_the_grant_consents_to_its_variable() {
    use hedwig_core::survey::{Asked, posix, seals};
    use hedwig_model::trail::Write;

    let plan = |writes: Vec<(Name, Write)>| Plan {
        asks: vec![Asked {
            capability: name("ssh-agent"),
            server: None,
            questions: vec![Question::Socket(Query::AgentSshSocket)],
        }],
        writes,
        ..Plan::default()
    };
    let variable = Write::Variable(Variable::try_from("SSH_AUTH_SOCK").unwrap());
    let consented = plan(vec![
        (name("ssh-agent"), Write::Masked),
        (name("ssh-agent"), variable),
    ]);
    assert!(seals(&consented));
    let script = posix(&consented, NONCE);
    assert!(
        script.contains(r#"place ssh-agent "$(gpgconf --list-dirs agent-ssh-socket)" other mask"#)
    );
    assert!(script.contains(r#"setvar ssh-agent SSH_AUTH_SOCK "$p""#));
    assert!(script.contains(r#"place ssh-agent "$r/ssh-agent" other"#));
    assert!(script.contains(r#"setvar ssh-agent SSH_AUTH_SOCK "$r/ssh-agent""#));
    assert!(!script.contains("say absent ssh-agent gpgconf"));
    assert!(script.ends_with(
        "IFS= read -r w || exit 0\n[ \"$w\" = seal ] && [ -n \"${hedwig:-}\" ] && chmod a-w \"$hedwig\"\n"
    ));

    let inspected = plan(Vec::new());
    assert!(!seals(&inspected));
    let script = posix(&inspected, NONCE);
    assert!(script.contains("say absent ssh-agent gpgconf"));
    assert!(!script.contains(r#""$r/ssh-agent""#));
}

/// A credential's form asks for the remote's `git` and a socket in Hedwig's
/// private folder, which the survey seals once bound; it names every helper
/// of the person's that `git` would give what Hedwig releases, writes `git`'s
/// own `cache` helper at the socket after them under consent, and names
/// `git`'s own cache where it holds the path.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one form, from the script through the report to what is placed"
)]
fn a_credential_is_placed_as_git_s_own_helper_at_a_private_socket() {
    use hedwig_core::survey::{posix, seals};
    use hedwig_model::trail::Write;

    assert_eq!(Question::of(&[Form::Helper]), [Question::Helper]);
    let plan = Plan {
        asks: vec![Asked {
            capability: name("git-https"),
            server: None,
            questions: vec![Question::Helper],
        }],
        writes: vec![(name("git-https"), Write::Helper)],
        ..Plan::default()
    };
    assert!(seals(&plan));
    let script = posix(&plan, NONCE);
    assert!(script.contains(r#"place git-https "$hedwig_socket" git"#));
    assert!(script.contains("git config --get-regexp '^credential\\..*helper$'"));
    assert!(script.contains(
        r#"put git-https credential-helper "$(gitconfig)" 'git-https credential-helper' "$(printf '[credential]\n\thelper = cache --socket %s' "$hedwig_socket")""#
    ));
    assert!(script.contains("say absent git-https git"));
    let inspected = Plan {
        writes: Vec::new(),
        ..plan
    };
    assert!(!posix(&inspected, NONCE).contains("credential-helper"));

    let path = "/run/user/1000/hedwig/git-https";
    let report = [
        said("begin posix"),
        said(&format!("kernel {}", hex("Linux"))),
        said(&format!("path git-https {}", hex(path))),
        said("at git-https free"),
        said(&format!(
            "helper git-https {}",
            hex("credential.helper store")
        )),
        said(&format!(
            "wrote git-https credential-helper {}",
            hex("/home/dev/.gitconfig")
        )),
        said("end"),
    ]
    .join("\n");
    let report = read(&report, NONCE).unwrap();
    let answer = report.answers.get(&name("git-https")).unwrap();
    let placed = place(
        &name("git-https"),
        &Form::Helper,
        &linux(),
        answer,
        &[],
        &[],
    );
    assert_eq!(
        placed.serving,
        Some(Serving {
            capability: name("git-https"),
            binding: Binding::Socket(RemotePath::try_from(path).unwrap()),
        })
    );
    assert_eq!(
        placed.readiness,
        Readiness::Unready(vec![Finding::HelperBeside(
            Words::try_from("credential.helper store").unwrap()
        )]),
        "named, and carried"
    );

    let cached = Answer {
        place: Some(Place {
            path: path.as_bytes().to_vec(),
            at: Some(At::Server(name("git"))),
            ..Place::default()
        }),
        ..Answer::default()
    };
    let placed = place(
        &name("git-https"),
        &Form::Helper,
        &linux(),
        &cached,
        &[],
        &[],
    );
    assert_eq!(placed.serving, None);
    assert_eq!(
        placed.readiness,
        Readiness::Unready(vec![Finding::CacheLive(
            RemotePath::try_from(path).unwrap()
        )])
    );
    let unwritten = Answer {
        place: cached.place.clone().map(|place| Place {
            at: Some(At::Free),
            ..place
        }),
        unwritten: vec![(Write::Helper, b"the path holds a blank".to_vec())],
        ..Answer::default()
    };
    let placed = place(
        &name("git-https"),
        &Form::Helper,
        &linux(),
        &unwritten,
        &[],
        &[],
    );
    assert_eq!(
        placed.serving, None,
        "without git's line nothing asks Hedwig"
    );
}

/// A notices capability's form is an opener's in all but its variable:
/// `HEDWIG_NOTIFY`, the remote's own `curl` posting what it is given last.
#[test]
fn a_notifier_is_placed_as_a_private_socket_its_variable_naming_the_remotes_curl() {
    use hedwig_core::survey::{NOTIFIER, posix, seals};
    use hedwig_model::trail::Write;

    assert_eq!(Question::of(&[Form::Notifier]), [Question::Notifier]);
    let plan = Plan {
        asks: vec![Asked {
            capability: name("notices"),
            server: None,
            questions: vec![Question::Notifier],
        }],
        writes: vec![(
            name("notices"),
            Write::Variable(Variable::try_from("HEDWIG_NOTIFY").unwrap()),
        )],
        ..Plan::default()
    };
    assert!(seals(&plan));
    let script = posix(&plan, NONCE);
    assert!(script.contains("command -v curl >/dev/null 2>&1 || say absent notices curl"));
    assert!(script.contains(r#"setvar notices HEDWIG_NOTIFY "curl -q -fsS --noproxy hedwig --unix-socket $hedwig_socket hedwig/ --data-raw""#));
    assert!(script.contains("seen_HEDWIG_NOTIFY=${HEDWIG_NOTIFY-}"));
    assert_eq!(NOTIFIER.len(), 1);
}
