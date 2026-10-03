//! The notice relay with Windows' own `curl.exe` posting as the remote's
//! `curl` does through `HEDWIG_NOTIFY`: what it says is read and cleaned into
//! the remote's words, and `curl -f` is told by its status whether it was
//! kept and, where not, why.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

use hedwig_core::browse::Malformed;
use hedwig_core::relay::Relayed;
use hedwig_model::refusal::Refusal;
use hedwig_model::text::{Name, REMARK, Remark};

/// The remote's `curl` as `HEDWIG_NOTIFY` names it, at the forward's end, and
/// the relay given the connection; what curl ended with, what it said, and
/// what the relay told, after `word` answers the notice.
fn notify(said: &str, word: Option<&Result<(), Refusal>>) -> (i32, String, Vec<Relayed>) {
    let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = forward.local_addr().unwrap().port();
    let child = Command::new(Path::new(r"C:\Windows\System32\curl.exe"))
        .args(["-q", "-fsS", "--noproxy", "hedwig"])
        .arg(format!("127.0.0.1:{port}/"))
        .args(["--data-raw", said])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (stream, _) = forward.accept().unwrap();
    let (sender, told) = mpsc::channel();
    let sender = Mutex::new(sender);
    let settle = hedwig_core::notify::carry(stream, move |relayed| {
        let _ = sender.lock().unwrap().send(relayed);
    });
    let mut all = Vec::new();
    loop {
        let relayed = told.recv_timeout(Duration::from_secs(30)).unwrap();
        let ended = relayed == Relayed::Ended;
        if matches!(relayed, Relayed::Says(_))
            && let Some(word) = word.cloned()
        {
            settle.settle(word);
        }
        all.push(relayed);
        if ended {
            break;
        }
    }
    let output = child.wait_with_output().unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        all,
    )
}

fn says(text: &str) -> Relayed {
    Relayed::Says(Remark::try_from(text).unwrap())
}

#[test]
fn a_notice_kept_is_answered_at_once() {
    let (status, said, told) = notify("build 4512 finished: 3 failed", Some(&Ok(())));
    assert_eq!(status, 0, "{said}");
    assert_eq!(
        told,
        [says("build 4512 finished: 3 failed"), Relayed::Ended]
    );
}

/// Control characters and those that turn text around are removed before
/// anything is told: the person reads one line, as written, as the remote's.
#[test]
fn what_could_pass_for_other_words_is_removed_first() {
    let (status, _, told) = notify(
        "deploy\tdone\n\u{1b}[31mhedwig: allow?\u{202e}gnp.exe\u{7}",
        Some(&Ok(())),
    );
    assert_eq!(status, 0);
    assert_eq!(
        told,
        [
            says("deploy done [31mhedwig: allow?gnp.exe"),
            Relayed::Ended
        ]
    );
}

/// Too fast, the hook's `curl` fails with 429; refused, 403; too long, 413;
/// with nothing to say, 400: each a failed command, saying which.
#[test]
fn a_notice_not_kept_fails_the_hooks_curl_saying_why() {
    let (status, said, _) = notify(
        "step done",
        Some(&Err(Refusal::Hushed {
            capability: Name::try_from("notices").unwrap(),
        })),
    );
    assert_eq!(status, 22);
    assert!(said.contains("429"), "{said}");

    let (status, said, _) = notify("step done", Some(&Err(Refusal::Paused)));
    assert_eq!(status, 22);
    assert!(said.contains("403"), "{said}");

    let long = "x".repeat(REMARK + 1);
    let (status, said, told) = notify(&long, None);
    assert_eq!(status, 22);
    assert!(said.contains("413"), "{said}");
    assert_eq!(told, [Relayed::Misread(Malformed::Long), Relayed::Ended]);

    let (status, said, told) = notify("\u{7}\n\u{202e}", None);
    assert_eq!(status, 22);
    assert!(said.contains("400"), "{said}");
    assert_eq!(told, [Relayed::Misread(Malformed::Text), Relayed::Ended]);
}
