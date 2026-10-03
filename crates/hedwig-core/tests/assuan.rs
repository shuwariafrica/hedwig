//! The Assuan conversation as the relay carries it: known-answer vectors from
//! a signing and a decrypting exchange as `GnuPG` 2.5.24's own `gpg` makes them,
//! every spelling the agent's dispatcher runs as a decision, every way a line
//! could reach the agent past one, and the socket file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use hedwig_core::assuan::{
    Ask, Breach, Conversation, LINE, Out, Side, SocketFile, Unparsed, refused, socket_file,
};
use hedwig_model::capability::Operation;
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::text::{Grip, Name};
use hedwig_model::trail::Failure;

const GREETING: &[u8] = b"OK Pleased to meet you, process 53492\n";
const GRIP: &str = "64EFB4597F2EB1968F187B7235A461FC48342EC5";

fn mark(text: &str) -> Grip {
    Grip::try_from(text).unwrap()
}

fn served() -> Conversation {
    let mut talk = Conversation::opened(GREETING.to_vec());
    assert_eq!(talk.serve(), vec![Out::ToClient(GREETING.to_vec())]);
    talk
}

/// The client sends `line` and the agent answers `answer`: both pass
/// unchanged, in both directions.
fn exchange(talk: &mut Conversation, line: &[u8], answer: &[u8]) {
    assert_eq!(
        talk.from_client(line).unwrap(),
        vec![Out::ToAgent(line.to_vec())],
        "{}",
        String::from_utf8_lossy(line)
    );
    let back: Vec<u8> = talk
        .from_agent(answer)
        .unwrap()
        .into_iter()
        .flat_map(|out| match out {
            Out::ToClient(bytes) => bytes,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(back, answer);
}

/// The signing exchange `gpg --detach-sign` made with `GnuPG` 2.5.24 on
/// 2026-10-01, line for line: everything passes, `PKSIGN` alone waits, and
/// it names the key the `SIGKEY` before it set.
#[test]
fn a_signature_waits_for_its_decision_and_names_the_key_it_uses() {
    let mut talk = served();
    exchange(&mut talk, b"RESET\n", b"OK\n");
    exchange(&mut talk, b"OPTION ttytype=xterm-256color\n", b"OK\n");
    exchange(&mut talk, b"GETINFO version\n", b"D 2.5.24\nOK\n");
    exchange(&mut talk, b"OPTION allow-pinentry-notify\n", b"OK\n");
    exchange(&mut talk, b"OPTION agent-awareness=2.1.0\n", b"OK\n");
    exchange(
        &mut talk,
        b"SCD SERIALNO\n",
        b"ERR 100696144 No such device <SCD>\n",
    );
    exchange(&mut talk, b"RESET\n", b"OK\n");
    let sigkey = format!("SIGKEY {GRIP}\n");
    exchange(&mut talk, sigkey.as_bytes(), b"OK\n");
    exchange(
        &mut talk,
        b"SETKEYDESC Please+enter+the+passphrase+to+unlock+the+OpenPGP+secret+key:%0A%22Relay+Test+<relay@example.invalid>%22%0A\n",
        b"OK\n",
    );
    exchange(
        &mut talk,
        b"SETHASH 10 9FF3973FEA743195C97D82EB0689663A0823DEA11866A8BF8A79CC5A25A9B0844C86099A13CFD01E40FAB8ADFB8C62B244C7992D0916C74D21A629E672210446\n",
        b"OK\n",
    );
    assert_eq!(
        talk.from_client(b"PKSIGN\n").unwrap(),
        vec![Out::Ask(Ask {
            operation: Operation::Sign,
            key: Some(mark(GRIP)),
        })]
    );
    assert!(talk.holds());
    assert_eq!(talk.serve(), vec![Out::ToAgent(b"PKSIGN\n".to_vec())]);
    let signature = b"D (7:sig-val(5:eddsa(1:r32:%00%01%02)(1:s32:%03%04%05)))\nOK\n";
    let back = talk.from_agent(signature).unwrap();
    assert_eq!(
        back,
        vec![
            Out::ToClient(b"D (7:sig-val(5:eddsa(1:r32:%00%01%02)(1:s32:%03%04%05)))\n".to_vec()),
            Out::ToClient(b"OK\n".to_vec()),
        ]
    );
}

/// Refused, the client hears what gpg-agent says when its owner denies a
/// key's use, the agent never sees the command, and the conversation goes on.
#[test]
fn a_refused_signature_never_reaches_the_agent_and_the_client_hears_the_agents_words() {
    let mut talk = served();
    exchange(&mut talk, format!("SIGKEY {GRIP}\n").as_bytes(), b"OK\n");
    talk.from_client(b"PKSIGN\n").unwrap();
    assert_eq!(
        talk.refuse(&Refusal::Declined),
        vec![Out::ToClient(
            b"ERR 67108963 Operation cancelled <GPG Agent>\n".to_vec()
        )]
    );
    assert!(talk.open());
    exchange(&mut talk, b"BYE\n", b"OK closing connection\n");
}

#[test]
fn each_refusal_is_said_with_the_code_whose_words_are_true_of_it() {
    let capability = Name::try_from("gpg").unwrap();
    let cases = [
        (
            Refusal::Declined,
            "ERR 67108963 Operation cancelled <GPG Agent>\n",
        ),
        (
            Refusal::NobodyReachable(Whereabouts::Away),
            "ERR 67108978 Not confirmed <GPG Agent>\n",
        ),
        (
            Refusal::SourceUnavailable {
                capability: capability.clone(),
                failure: Failure::Unreachable,
            },
            "ERR 67108941 No agent running <GPG Agent>\n",
        ),
        (Refusal::Paused, "ERR 67109115 Forbidden <GPG Agent>\n"),
        (
            Refusal::OperationNotInDialect {
                capability,
                operation: Operation::Sign,
            },
            "ERR 67109115 Forbidden <GPG Agent>\n",
        ),
    ];
    for (refusal, line) in cases {
        assert_eq!(String::from_utf8(refused(&refusal)).unwrap(), line);
    }
}

/// A connection refused at its opening is answered in place of the greeting,
/// which is how a client learns its connection failed, and is over.
#[test]
fn a_connection_refused_at_its_opening_hears_the_refusal_as_its_greeting() {
    let mut talk = Conversation::opened(GREETING.to_vec());
    assert!(talk.holds());
    assert_eq!(
        talk.refuse(&Refusal::NobodyReachable(Whereabouts::Away)),
        vec![Out::ToClient(
            b"ERR 67108978 Not confirmed <GPG Agent>\n".to_vec()
        )]
    );
    assert!(!talk.open());
}

/// Every line the agent's dispatcher would run as a signature or a
/// decryption - in any case, after any blank, ended by a NUL or a carriage
/// return, through `SCD` - is held.
#[test]
fn every_spelling_the_agent_runs_as_a_decision_is_held() {
    let card = "SCD PKSIGN --hash=sha256 1234567890ABCDEF1234567890ABCDEF12345678\n";
    let cases: [(&[u8], Operation, Option<&str>); 12] = [
        (b"PKSIGN\n", Operation::Sign, Some(GRIP)),
        (b"pksign\n", Operation::Sign, Some(GRIP)),
        (b"PkSiGn --hash=sha256\n", Operation::Sign, Some(GRIP)),
        (b"PKSIGN\t\tnonce\n", Operation::Sign, Some(GRIP)),
        (b"PKSIGN\r\n", Operation::Sign, Some(GRIP)),
        (b"PKSIGN\0anything\n", Operation::Sign, Some(GRIP)),
        (b"PKDECRYPT --kem\n", Operation::Decrypt, Some(GRIP)),
        (b"pkdecrypt\n", Operation::Decrypt, Some(GRIP)),
        (
            card.as_bytes(),
            Operation::Sign,
            Some("1234567890ABCDEF1234567890ABCDEF12345678"),
        ),
        (b"scd  pkauth OPENPGP.3\n", Operation::Authenticate, None),
        (b"SCD PKDECRYPT OPENPGP.2\n", Operation::Decrypt, None),
        (b"SCD\tPKSIGN\n", Operation::Sign, None),
    ];
    for (line, operation, key) in cases {
        let mut talk = served();
        exchange(&mut talk, format!("SIGKEY {GRIP}\n").as_bytes(), b"OK\n");
        assert_eq!(
            talk.from_client(line).unwrap(),
            vec![Out::Ask(Ask {
                operation,
                key: key.map(mark),
            })],
            "{}",
            String::from_utf8_lossy(line)
        );
    }
}

/// What the dispatcher would not run as a decision passes on, and the agent
/// answers it.
#[test]
fn a_line_the_agent_runs_as_something_else_passes() {
    let cases: [&[u8]; 9] = [
        b" PKSIGN\n",
        b"\tPKSIGN\n",
        b"D PKSIGN\n",
        b"PKSIGNX\n",
        b"XPKSIGN\n",
        b"\0PKSIGN\n",
        b"SCD PKSIGNX\n",
        b"SCD --x PKSIGN\n",
        b"HAVEKEY --list=1000\n",
    ];
    for line in cases {
        let mut talk = served();
        exchange(
            &mut talk,
            line,
            b"ERR 67109139 Unknown IPC command <GPG Agent>\n",
        );
    }
}

/// A comment or an empty line is answered by nothing, so the client may go
/// on at once.
#[test]
fn a_comment_or_an_empty_line_passes_and_leaves_the_client_its_turn() {
    let mut talk = served();
    let out = talk.from_client(b"# PKSIGN\n\r\nRESET\n").unwrap();
    assert_eq!(
        out,
        vec![
            Out::ToAgent(b"# PKSIGN\n".to_vec()),
            Out::ToAgent(b"\r\n".to_vec()),
            Out::ToAgent(b"RESET\n".to_vec()),
        ]
    );
}

/// gpg-agent ends a connection that sends a line past 1002 bytes; the relay
/// ends it before any of the line is carried.
#[test]
fn a_line_past_the_limit_ends_the_conversation_before_any_of_it_is_carried() {
    let mut longest = vec![b'A'; LINE - 1];
    longest.push(b'\n');
    let mut talk = served();
    exchange(
        &mut talk,
        &longest,
        b"ERR 67109139 Unknown IPC command <GPG Agent>\n",
    );

    let mut smuggled = vec![b'A'; LINE];
    smuggled.extend_from_slice(b"PKSIGN\n");
    let mut talk = served();
    assert_eq!(
        talk.from_client(&smuggled),
        Err(Breach::TooLong(Side::Client))
    );
    let mut talk = served();
    assert_eq!(
        talk.from_client(&vec![b'A'; LINE]),
        Err(Breach::TooLong(Side::Client))
    );
    let mut talk = served();
    talk.from_client(b"GETINFO version\n").unwrap();
    assert_eq!(
        talk.from_agent(&vec![b'D'; LINE + 1]),
        Err(Breach::TooLong(Side::Agent))
    );
}

/// A client writes only when nothing is outstanding or the agent asked it
/// for data; an agent only when asked.
#[test]
fn either_end_out_of_turn_ends_the_conversation() {
    let mut talk = served();
    assert_eq!(
        talk.from_client(b"RESET\nPKSIGN\n"),
        Err(Breach::OutOfTurn(Side::Client))
    );

    let mut talk = served();
    talk.from_client(b"PKSIGN\n").unwrap();
    assert_eq!(
        talk.from_client(b"RESET\n"),
        Err(Breach::OutOfTurn(Side::Client))
    );

    let mut talk = Conversation::opened(GREETING.to_vec());
    assert_eq!(
        talk.from_client(b"RESET\n"),
        Err(Breach::OutOfTurn(Side::Client))
    );

    let mut talk = served();
    assert_eq!(
        talk.from_agent(b"OK\n"),
        Err(Breach::OutOfTurn(Side::Agent))
    );

    let mut talk = served();
    talk.from_client(b"RESET\n").unwrap();
    assert_eq!(talk.from_agent(b"hello\n"), Err(Breach::NotAnswer));
}

/// The decrypting exchange: the agent inquires for the ciphertext once the
/// command is served, data passes while it inquires, and `END` returns the
/// turn to the agent.
#[test]
fn a_decryption_passes_its_inquiry_once_served() {
    let mut talk = served();
    exchange(&mut talk, format!("SETKEY {GRIP}\n").as_bytes(), b"OK\n");
    assert_eq!(
        talk.from_client(b"PKDECRYPT\n").unwrap(),
        vec![Out::Ask(Ask {
            operation: Operation::Decrypt,
            key: Some(mark(GRIP)),
        })]
    );
    assert_eq!(talk.serve(), vec![Out::ToAgent(b"PKDECRYPT\n".to_vec())]);
    assert_eq!(
        talk.from_agent(b"S INQUIRE_MAXLEN 4096\nINQUIRE CIPHERTEXT\n")
            .unwrap(),
        vec![
            Out::ToClient(b"S INQUIRE_MAXLEN 4096\n".to_vec()),
            Out::ToClient(b"INQUIRE CIPHERTEXT\n".to_vec()),
        ]
    );
    assert_eq!(
        talk.from_client(b"D (7:enc-val(4:ecdh\nD (1:s10:%00%01)))\nEND\n")
            .unwrap(),
        vec![
            Out::ToAgent(b"D (7:enc-val(4:ecdh\n".to_vec()),
            Out::ToAgent(b"D (1:s10:%00%01)))\n".to_vec()),
            Out::ToAgent(b"END\n".to_vec()),
        ]
    );
    assert_eq!(
        talk.from_agent(b"D (5:value16:%01%02)\nOK\n").unwrap(),
        vec![
            Out::ToClient(b"D (5:value16:%01%02)\n".to_vec()),
            Out::ToClient(b"OK\n".to_vec()),
        ]
    );
}

/// While the agent inquires, only data, a comment, `END` or `CAN` pass: any
/// other line could be run as a command were the agent to have ended the
/// inquiry already.
#[test]
fn while_the_agent_inquires_only_its_answers_pass() {
    for (line, passes) in [
        (&b"d lower\n"[..], true),
        (b"#\n", true),
        (b"end\n", true),
        (b"CANCEL\n", true),
        (b"PKSIGN\n", false),
        (b"ENDX\n", false),
        (b"Dx\n", false),
    ] {
        let mut talk = served();
        talk.from_client(b"PKDECRYPT\n").unwrap();
        talk.serve();
        talk.from_agent(b"INQUIRE CIPHERTEXT\n").unwrap();
        let out = talk.from_client(line);
        assert_eq!(out.is_ok(), passes, "{}", String::from_utf8_lossy(line));
    }
}

/// The key a decision names is the one the agent took: set by an accepted
/// `SIGKEY` or `SETKEY`, kept when the agent refuses one, cleared by `RESET`,
/// and never the second key.
#[test]
fn the_key_named_is_the_one_the_agent_accepted() {
    let other = "00112233445566778899AABBCCDDEEFF00112233";
    let mut talk = served();
    exchange(
        &mut talk,
        format!("SIGKEY {}\n", GRIP.to_lowercase()).as_bytes(),
        b"OK\n",
    );
    assert_eq!(talk.key(), Some(&mark(GRIP)));
    exchange(
        &mut talk,
        format!("SIGKEY {other}\n").as_bytes(),
        b"ERR 67108881 No secret key <GPG Agent>\n",
    );
    assert_eq!(talk.key(), Some(&mark(GRIP)));
    exchange(
        &mut talk,
        format!("SIGKEY --another {other}\n").as_bytes(),
        b"OK\n",
    );
    assert_eq!(talk.key(), Some(&mark(GRIP)));
    exchange(
        &mut talk,
        b"SETKEY ABCD\n",
        b"ERR 67109000 Parameter error <GPG Agent>\n",
    );
    exchange(
        &mut talk,
        format!("setkey --x {other} trailing\n").as_bytes(),
        b"OK\n",
    );
    assert_eq!(talk.key(), Some(&mark(other)));
    exchange(&mut talk, b"RESET\n", b"OK\n");
    assert_eq!(talk.key(), None);
}

#[test]
fn a_client_that_closes_mid_line_is_told_apart() {
    let mut talk = served();
    talk.from_client(b"PKSI").unwrap();
    assert_eq!(talk.client_closed(), Err(Breach::Cut(Side::Client)));
    let talk = served();
    assert_eq!(talk.client_closed(), Ok(()));
}

/// The native socket file, round-tripped from the bytes gpg-agent writes; the
/// Cygwin form told apart; each malformed file named.
#[test]
fn a_socket_file_reads_back_as_gpg_agent_wrote_it() {
    let nonce: [u8; 16] = *b"\x00\x0a\x0d\xff0123456789ab";
    let mut written = b"49152\n".to_vec();
    written.extend_from_slice(&nonce);
    let SocketFile::Native { port, nonce: read } = socket_file(&written).unwrap() else {
        panic!("native")
    };
    assert_eq!(port, 49152);
    assert_eq!(read.as_bytes(), &nonce);
    assert!(read.matches(&nonce));
    assert!(!read.matches(&[0u8; 16]));
    assert!(!read.matches(&nonce[..15]));
    assert_eq!(format!("{read:?}"), "Nonce(..)");

    // Each group of the GUID is a 32-bit number libassuan copies as it lies
    // in memory: little-endian.
    let Ok(SocketFile::Cygwin {
        port,
        nonce: cygwin,
    }) = socket_file(b"!<socket >49152 s 01234567-89abcdef-00000001-ffffffff\0")
    else {
        panic!("Cygwin's form is read");
    };
    assert_eq!(port, 49152);
    assert_eq!(
        cygwin.as_bytes(),
        &[
            0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff
        ]
    );
    for unread in [
        &b"!<socket >0 s 01234567-89abcdef-00000001-ffffffff\0"[..],
        b"!<socket >65536 s 01234567-89abcdef-00000001-ffffffff",
        b"!<socket >49152 d 01234567-89abcdef-00000001-ffffffff",
        b"!<socket >49152 s 01234567-89abcdef-00000001",
        b"!<socket >49152 s 0123456-89abcdef-00000001-ffffffff",
        b"!<socket >49152 s 0123456g-89abcdef-00000001-ffffffff",
        b"!<socket >49152 s 01234567-89abcdef-00000001-ffffffff-00000000",
        b"!<socket >",
    ] {
        assert!(socket_file(unread).is_err(), "{unread:?}");
    }
    assert_eq!(socket_file(b"").unwrap_err(), Unparsed::Empty);
    assert_eq!(socket_file(b"49152").unwrap_err(), Unparsed::NoLineFeed);
    for port in [&b"\n"[..], b"0\n", b"65536\n", b"123456\n", b"+1\n"] {
        let mut file = port.to_vec();
        file.extend_from_slice(&nonce);
        assert_eq!(socket_file(&file).unwrap_err(), Unparsed::Port);
    }
    assert_eq!(
        socket_file(b"49152\n0123456789abcde").unwrap_err(),
        Unparsed::NonceLength(15)
    );
    let mut long = b"49152\n".to_vec();
    long.extend_from_slice(&[7u8; 17]);
    assert_eq!(socket_file(&long).unwrap_err(), Unparsed::NonceLength(17));
}
