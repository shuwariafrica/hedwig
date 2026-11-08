//! A lent emulator's console as the relay reads it: the port a serial names,
//! the banner, each line the remote sends judged, and the workstation's own
//! authentication against consoles of the suite's on loopback, each way it
//! can fail.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::thread;

use hedwig_core::console::{
    ASKED, AUTHENTICATED, Banner, Console, LINE, Line, Out, Overlong, REFUSED, Unconsoled, banner,
    judge, open, port,
};
use hedwig_model::text::{DeviceSerial, Port};

fn serial(text: &str) -> DeviceSerial {
    DeviceSerial::try_from(text).unwrap()
}

#[test]
fn an_emulators_serial_names_its_console_port_and_nothing_else_does() {
    assert_eq!(
        port(&serial("emulator-5554")),
        Some(Port::try_from(5554).unwrap())
    );
    for other in [
        "emulator-",
        "emulator-55a4",
        "emulator-5554 ",
        "emulator-70000",
        "emulator-0",
        "127.0.0.1:5555",
        "R58M1234ABC",
        "Emulator-5554",
    ] {
        assert_eq!(port(&serial(other)), None, "{other}");
    }
}

fn asking(path: &str) -> String {
    format!(
        "Android Console: Authentication required\r\n\
         Android Console: type 'auth <auth_token>' to authenticate\r\n\
         Android Console: you can find your <auth_token> in \r\n\
         '{path}'\r\nOK\r\n"
    )
}

#[test]
fn the_banner_names_the_token_file_or_an_open_console() {
    let file = r"C:\Users\dev\.emulator_console_auth_token";
    assert_eq!(banner(&asking(file)), Some(Banner::Token(file.to_owned())));
    assert_eq!(
        banner("Android Console: type 'help' for a list of commands\r\nOK\r\n"),
        Some(Banner::Open)
    );
    for refused in [
        // Not an emulator's console.
        "SSH-2.0-OpenSSH_9.6\r\n".to_owned(),
        // A path that is not the token file, or not absolute here.
        asking(r"C:\Users\dev\.ssh\id_ed25519"),
        asking(".emulator_console_auth_token"),
        asking("/home/dev/.emulator_console_auth_token"),
        // Asking, and naming nothing.
        "Android Console: Authentication required\r\nOK\r\n".to_owned(),
    ] {
        assert_eq!(banner(&refused), None, "{refused}");
    }
}

#[test]
fn each_line_is_passed_answered_in_place_or_refused_by_its_first_word() {
    for passed in [
        "",
        "ping",
        "help",
        "geo fix 39.2 -6.16",
        "sms send 5551234 hello",
        "power capacity 40",
        "avd snapshot save before",
        "avd stop",
        "redir list",
        "network speed full",
        "network capture start trace.pcap",
        "screenrecord start clip.webm",
        "kill",
        "quit",
    ] {
        assert_eq!(judge(passed, false), Line::Pass, "{passed}");
    }
    assert_eq!(judge("auth 0123456789abcdef", false), Line::Authenticated);
    assert_eq!(judge("auth", true), Line::Authenticated);
    for (refused, word) in [
        ("qemu monitor", "qemu"),
        ("redir add tcp:5000:6000", "redir"),
        ("redir del tcp:5000", "redir"),
        ("grpc start 8554", "grpc"),
        (
            "virtualscene-image wall C:\\poster.png",
            "virtualscene-image",
        ),
        ("avd hostmicon", "avd"),
        ("network capture start C:\\Users\\dev\\out.pcap", "network"),
        ("network capture start ../out.pcap", "network"),
        ("screenrecord start /tmp/clip.webm", "screenrecord"),
        ("automation record C:/macro", "automation"),
        ("proxy start http://example.invalid:3128", "proxy"),
        (
            "a-command-of-a-later-emulator",
            "a-command-of-a-later-emulator",
        ),
    ] {
        assert_eq!(
            judge(refused, false),
            Line::Refused(word.to_owned()),
            "{refused}"
        );
    }
    assert_eq!(
        judge("proxy start http://example.invalid:3128", true),
        Line::Pass
    );
}

#[test]
fn what_the_remote_sends_goes_on_line_by_line_in_order() {
    let mut console = Console::default();
    assert_eq!(console.from_remote(b"geo fix 1", false), Ok(Vec::new()));
    assert_eq!(
        console.from_remote(b" 2\r\nauth theirs\r\nqemu monitor\r\nping\n", false),
        Ok(vec![
            Out::ToConsole(b"geo fix 1 2\r\n".to_vec()),
            Out::ToConsole(AUTHENTICATED.to_vec()),
            Out::ToConsole(REFUSED.to_vec()),
            Out::Refused("qemu".to_owned()),
            Out::ToConsole(b"ping\n".to_vec()),
        ])
    );
    let mut long = Console::default();
    assert_eq!(long.from_remote(&vec![b'a'; LINE], false), Ok(Vec::new()));
    assert_eq!(long.from_remote(b"a", false), Err(Overlong));
}

/// A console of the suite's on loopback that greets with `greeting` and
/// answers `auth` with `answer`; gives its port and the lines it read.
fn console(greeting: String, answer: &'static str) -> (Port, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = Port::try_from(listener.local_addr().unwrap().port()).unwrap();
    let served = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut out = stream.try_clone().unwrap();
        out.write_all(greeting.as_bytes()).unwrap();
        let mut read = Vec::new();
        let mut lines = BufReader::new(stream);
        let mut line = String::new();
        if lines.read_line(&mut line).unwrap_or(0) > 0 {
            read.push(line.trim_end().to_owned());
            let _ = out.write_all(answer.as_bytes());
        }
        read
    });
    (port, served)
}

fn token_file(folder: &Path, token: &str) -> PathBuf {
    std::fs::create_dir_all(folder).unwrap();
    let file = folder.join(".emulator_console_auth_token");
    std::fs::write(&file, token).unwrap();
    file
}

fn folder(purpose: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hedwig-console-{purpose}-{}", std::process::id()))
}

#[test]
fn the_workstation_authenticates_with_its_own_token_and_greets_with_what_follows() {
    let home = folder("own");
    let file = token_file(&home, "0123456789abcdef\n");
    let (at, served) = console(
        asking(file.to_str().unwrap()),
        "Android Console: type 'help' for a list of commands\r\nOK\r\n",
    );
    let authenticated = b"Android Console: type 'help' for a list of commands\r\nOK\r\n";
    let (_, greeting) = open(at).unwrap();
    assert_eq!(greeting, [ASKED, authenticated].concat());
    assert!(
        !String::from_utf8_lossy(&greeting).contains(".emulator_console_auth_token"),
        "the token file's path stays on the workstation"
    );
    assert_eq!(served.join().unwrap(), ["auth 0123456789abcdef"]);

    let (at, served) = console(
        "Android Console: type 'help' for a list of commands\r\nOK\r\n".to_owned(),
        "",
    );
    let (console, greeting) = open(at).unwrap();
    assert_eq!(greeting, [ASKED, authenticated].concat());
    drop(console);
    assert!(
        served.join().unwrap().is_empty(),
        "an open console is sent nothing"
    );
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn a_console_that_cannot_be_authenticated_says_why() {
    let nothing = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let unheard = Port::try_from(nothing.local_addr().unwrap().port()).unwrap();
    drop(nothing);
    assert_eq!(open(unheard).err(), Some(Unconsoled::Unreached));

    let (at, _) = console("SSH-2.0-OpenSSH_9.6\r\nOK\r\n".to_owned(), "");
    assert_eq!(open(at).err(), Some(Unconsoled::NotConsole));

    let home = folder("refusals");
    let absent = home.join("absent").join(".emulator_console_auth_token");
    let (at, _) = console(asking(absent.to_str().unwrap()), "");
    assert_eq!(open(at).err(), Some(Unconsoled::Tokenless));

    let empty = token_file(&home.join("empty"), "  \n");
    let (at, _) = console(asking(empty.to_str().unwrap()), "");
    assert_eq!(open(at).err(), Some(Unconsoled::Tokenless));

    let stale = token_file(&home.join("stale"), "fedcba9876543210");
    let (at, served) = console(
        asking(stale.to_str().unwrap()),
        "KO: authentication token does not match ~/.emulator_console_auth_token\r\n",
    );
    assert_eq!(open(at).err(), Some(Unconsoled::Refused));
    assert_eq!(served.join().unwrap(), ["auth fedcba9876543210"]);
    let _ = std::fs::remove_dir_all(home);
}
