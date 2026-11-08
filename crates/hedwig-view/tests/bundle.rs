//! What a supporter is given, as the window shows it before it is saved,
//! and the file it is saved as, read back.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::Exposure;
use hedwig_model::config::{Activation, Change};
use hedwig_model::protocol::{Bundle, Request, SetAside};
use hedwig_model::remote::Granted;
use hedwig_model::text::Commit;
use hedwig_model::trail::Timestamp;
use hedwig_model::wire::read;
use hedwig_view::bundle;
use hedwig_view::link::{Event, Place};

mod common;
use common::Bench;
use common::support::{grant, remote, terms};

/// A bundle of what a core with one grant says, as the real core assembles
/// it from the same replies.
fn assembled() -> Bundle {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(remote("ssh", "build.example"))),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        }),
    ));
    let attached = bench.seen();
    Bundle {
        version: "0.0.0".to_owned(),
        commit: Commit::try_from("0123456789ab").unwrap(),
        program: r"C:\Users\x\AppData\Local\Programs\ShuwariAfrica\Hedwig".to_owned(),
        windows: "10.0.26200".to_owned(),
        status: attached.status.clone().expect("status"),
        attention: attached.attention.clone().expect("attention"),
        exposure: attached.rows.clone().expect("rows"),
        settings: *attached.settings.clone().expect("settings"),
        activity: Vec::new(),
        diagnostics: vec![
            r#"{"at":1,"from":"startup","said":"refused"}"#.to_owned(),
            r#"{"at":2,"from":"power","said":"refused"}"#.to_owned(),
        ],
        set_aside: vec![SetAside {
            name: "trail.unreadable-1700000000000.jsonl".to_owned(),
            bytes: 2048,
            at: Timestamp(1_700_000_000_000),
        }],
    }
}

/// Every part is said with how much of it there is, then what in it names
/// the person and what it never holds.
#[test]
fn the_person_sees_each_part_and_what_names_them_before_it_is_saved() {
    let lines = bundle::contents(&assembled());
    assert_eq!(
        lines,
        vec![
            r"Hedwig 0.0.0 (0123456789ab), running from C:\Users\x\AppData\Local\Programs\ShuwariAfrica\Hedwig, on Windows 10.0.26200.".to_owned(),
            "What is reachable, line by line, from 1 remote: build.example (ssh).".to_owned(),
            "What needs you: 0 items.".to_owned(),
            "Every setting, with the statement it comes from and what your organisation states."
                .to_owned(),
            "What happened: the newest 0 entries.".to_owned(),
            "What Hedwig wrote down about what went wrong: 2 lines.".to_owned(),
            "Files set aside because they could not be read: \
             trail.unreadable-1700000000000.jsonl (2048 bytes)."
                .to_owned(),
            "It names your remotes, your keys by fingerprint, your account and the folders \
             Hedwig runs from. It holds no passphrase, answer, PIN or key."
                .to_owned(),
        ]
    );
}

/// The file is the core's written form of the bundle, which reads back as
/// the bundle it was written from.
#[test]
fn the_saved_file_reads_back_as_the_bundle() {
    let made = assembled();
    let written = bundle::written(&made);
    assert!(written.ends_with('\n'));
    assert_eq!(read::<Bundle>(written.trim_end()).unwrap(), made);
}
