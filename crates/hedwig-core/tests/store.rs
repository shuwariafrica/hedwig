//! The trail and the configuration on disk: what is read back is what was
//! written, a line cut short by a crash is dropped and nothing else is, and a
//! file that cannot be read is set aside whole.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::fs;
use std::os::windows::fs::OpenOptionsExt;

use hedwig_core::record::{Claim, ClaimError};
use hedwig_core::store::{Kept, Places, StoreError, Trail, load, prepare, settle};
use hedwig_model::config::{Catalogue, Change, Configuration, Reach};
use hedwig_model::process::{CoreState, Running};
use hedwig_model::setting::Autostart;
use hedwig_model::trail::{
    Breakdown, ClientId, Entry, Event, Integrity, Origin, Seq, State, Store, Tick, Timestamp,
};
use hedwig_model::wire::{line, page, read};

/// The line every trail begins with.
/// A new trail's first two lines: its form, and the head of a trail nothing
/// was folded into.
fn fresh() -> String {
    format!("{{\"trail\":1}}\n{}\n", line(&State::default()))
}

/// What an open that does not allow for another handle fails with.
const SHARING: i32 = 32;

mod common;
use common::Folder;

const AT: Timestamp = Timestamp(1_790_000_000_000);

fn entry(seq: u64, after: Option<Breakdown>) -> Entry {
    Entry {
        seq: Seq(seq),
        at: Timestamp(AT.0 + seq),
        tick: Tick(seq * 10),
        event: Event::Started {
            version: "0.2.0".to_owned(),
            origin: Origin {
                process: 4200,
                logon: 999,
                session: 2,
                integrity: Integrity::Medium,
            },
            after,
        },
    }
}

fn set_aside(folder: &Folder, stem: &str) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(folder.path())
        .unwrap()
        .map(|found| found.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(&format!("{stem}.unreadable-")))
        .collect();
    names.sort();
    names
}

#[test]
fn a_trail_is_read_back_as_it_was_written() {
    let folder = Folder::new("trail");
    let places = folder.places();
    let opened = Trail::open(&places, AT).unwrap();
    assert!(opened.entries.is_empty() && opened.unreadable.is_none());
    let mut trail = opened.trail;
    let written = [entry(1, None), entry(2, Some(Breakdown::Hung))];
    trail.append(&written).unwrap();
    trail.append(&[entry(3, None)]).unwrap();
    drop(trail);

    let text = fs::read_to_string(places.trail()).unwrap();
    assert_eq!(text.lines().count(), 5);
    assert_eq!(
        text,
        fresh()
            + &[1, 2, 3]
                .map(|seq| line(&entry(seq, (seq == 2).then_some(Breakdown::Hung))) + "\n")
                .concat()
    );
    let again = Trail::open(&places, AT).unwrap();
    assert_eq!(again.entries.len(), 3);
    assert_eq!(again.entries.get(..2).unwrap(), written);
    assert!(again.unreadable.is_none());
}

/// The process or the power went while a line was being written. That line
/// was never on disk whole, so nothing it records was allowed to happen: it
/// is dropped, the file ends at the last whole line, and the trail goes on.
#[test]
fn a_line_cut_short_is_dropped_and_nothing_else_is() {
    let folder = Folder::new("torn");
    let places = folder.places();
    let whole = fresh() + &line(&entry(1, None)) + "\n" + &line(&entry(2, None)) + "\n";
    let third = line(&entry(3, None));
    for cut in [1, third.len() / 2, third.len()] {
        fs::write(
            places.trail(),
            format!("{whole}{}", third.get(..cut).unwrap()),
        )
        .unwrap();
        let mut opened = Trail::open(&places, AT).unwrap();
        assert_eq!(
            opened.entries,
            [entry(1, None), entry(2, None)],
            "cut at {cut}"
        );
        assert!(opened.unreadable.is_none());
        assert_eq!(fs::read_to_string(places.trail()).unwrap(), whole);
        opened.trail.append(&[entry(3, None)]).unwrap();
        assert_eq!(Trail::open(&places, AT).unwrap().entries.len(), 3);
    }
    assert_eq!(set_aside(&folder, "trail"), Vec::<String>::new());
}

/// A trail with a whole line that cannot be read is not repaired and not
/// appended to. It is set aside as it is, a new one is begun, and the account
/// says which line and why.
#[test]
fn a_trail_that_cannot_be_read_is_set_aside_whole() {
    let entry_one = line(&entry(1, None));
    let one = format!("{}{entry_one}", fresh());
    let cases = [
        (
            format!("{one}\n{{\"seq\":2}}\n"),
            "line 4: the value has no at",
        ),
        (
            "{\"trail\":1}\n{\"seq\":2}\n".to_owned(),
            "line 2 is not the trail's head: the value has no started",
        ),
        (
            format!("{one}\n{entry_one}\n"),
            "line 4: entry 1 does not follow entry 1",
        ),
        (
            format!("{one}\n\n"),
            "line 4: the text ends inside a value at byte 0",
        ),
        (
            format!("{one}\nnot json\n"),
            "line 4: an unexpected character at byte 0",
        ),
    ];
    for (number, (text, account)) in cases.into_iter().enumerate() {
        let folder = Folder::new("unreadable");
        let places = folder.places();
        fs::write(places.trail(), &text).unwrap();
        let at = Timestamp(AT.0 + number as u64);
        let opened = Trail::open(&places, at).unwrap();
        assert_eq!(opened.unreadable.as_deref(), Some(account));
        assert_eq!(opened.entries, Vec::<Entry>::new());
        let aside = set_aside(&folder, "trail");
        assert_eq!(aside, [format!("trail.unreadable-{}.jsonl", at.0)]);
        let kept = fs::read_to_string(folder.path().join(aside.first().unwrap())).unwrap();
        assert_eq!(kept, text, "set aside byte for byte");
        assert_eq!(fs::read_to_string(places.trail()).unwrap(), fresh());
    }

    let folder = Folder::new("not-text");
    let places = folder.places();
    fs::write(places.trail(), [0xff, 0xfe, b'\n']).unwrap();
    let opened = Trail::open(&places, AT).unwrap();
    assert_eq!(opened.unreadable.as_deref(), Some("it is not text"));
}

fn configured() -> (Catalogue, Configuration) {
    let catalogue = Catalogue::shipped().unwrap();
    let mut configuration = Configuration::default();
    configuration
        .apply(&catalogue, Change::Autostart(Some(Autostart::AtLogon)))
        .unwrap();
    (catalogue, configuration)
}

/// An entry that records a change to the configuration.
fn changed(seq: u64) -> Entry {
    Entry {
        event: Event::Changed {
            change: Change::Autostart(Some(Autostart::AtLogon)),
            by: ClientId(Seq(1)),
            reach: Reach::NoWider,
        },
        ..entry(seq, None)
    }
}

fn waiting(folder: &Folder) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(folder.path())
        .unwrap()
        .map(|found| found.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("configuration.next-"))
        .collect();
    names.sort();
    names
}

#[test]
fn a_configuration_kept_is_the_configuration_loaded() {
    let folder = Folder::new("configuration");
    let places = folder.places();
    let (_, configuration) = configured();
    assert_eq!(load(&places, AT, &[]).unwrap(), Kept::Absent);

    prepare(&places, &configuration.export(), Seq(2)).unwrap();
    assert!(!places.configuration().exists(), "prepared is not stored");
    settle(&places, Seq(2)).unwrap();
    // What is on disk is the page a person would export, byte for byte.
    assert_eq!(
        fs::read_to_string(places.configuration()).unwrap(),
        page(&configuration.export())
    );
    assert_eq!(
        load(&places, AT, &[]).unwrap(),
        Kept::Read(Box::new(configuration.clone()))
    );
    // Kept again, it replaces what was there.
    prepare(&places, &Configuration::default().export(), Seq(3)).unwrap();
    settle(&places, Seq(3)).unwrap();
    assert_eq!(load(&places, AT, &[]).unwrap(), Kept::Read(Box::default()));
    assert_eq!(waiting(&folder), Vec::<String>::new());
}

/// A change is three steps: the new document is written beside the stored
/// one, the entry that records it is appended to the trail, and the document
/// is put in place. The process or the power can go between any two. The
/// next run reads the trail, and the stored document is what the trail says:
/// a change that was recorded is finished, and one that was not is forgotten.
#[test]
fn a_change_is_in_the_trail_and_the_document_or_in_neither() {
    let (_, configuration) = configured();
    let (before, after) = (Configuration::default(), configuration);
    let stored = |folder: &Folder| {
        let places = folder.places();
        prepare(&places, &before.export(), Seq(1)).unwrap();
        settle(&places, Seq(1)).unwrap();
        places
    };
    let recorded = [entry(1, None), changed(2)];
    let not_recorded = [entry(1, None)];

    // It went while the new document was being written: a piece of it is
    // there, and the entry is not.
    let folder = Folder::new("torn-document");
    let places = stored(&folder);
    let whole = page(&after.export());
    fs::write(
        folder.path().join("configuration.next-2.json"),
        whole.get(..whole.len() / 2).unwrap(),
    )
    .unwrap();
    assert_eq!(
        load(&places, AT, &not_recorded).unwrap(),
        Kept::Read(Box::new(before.clone()))
    );
    assert!(waiting(&folder).is_empty(), "forgotten");

    // It went after the document was written and before the entry was.
    let folder = Folder::new("prepared-only");
    let places = stored(&folder);
    prepare(&places, &after.export(), Seq(2)).unwrap();
    assert_eq!(waiting(&folder), ["configuration.next-2.json"]);
    assert_eq!(
        load(&places, AT, &not_recorded).unwrap(),
        Kept::Read(Box::new(before.clone()))
    );
    assert!(waiting(&folder).is_empty(), "forgotten");

    // It went after the entry was written and before the document was put
    // in place: the trail says the change was made, and so it is.
    let folder = Folder::new("recorded-not-settled");
    let places = stored(&folder);
    prepare(&places, &after.export(), Seq(2)).unwrap();
    assert_eq!(
        load(&places, AT, &recorded).unwrap(),
        Kept::Read(Box::new(after.clone()))
    );
    assert!(waiting(&folder).is_empty(), "finished");
    assert_eq!(
        fs::read_to_string(places.configuration()).unwrap(),
        page(&after.export())
    );

    // The very first change, with no document stored yet.
    let folder = Folder::new("first-change");
    let places = folder.places();
    prepare(&places, &after.export(), Seq(2)).unwrap();
    assert_eq!(load(&places, AT, &not_recorded).unwrap(), Kept::Absent);
    prepare(&places, &after.export(), Seq(2)).unwrap();
    assert_eq!(
        load(&places, AT, &recorded).unwrap(),
        Kept::Read(Box::new(after))
    );
}

/// A stored document this build does not accept is set aside, never
/// overwritten: the person can mend it and import it. Until then nothing is
/// granted.
#[test]
fn a_configuration_that_cannot_be_read_is_set_aside_whole() {
    let (catalogue, configuration) = configured();
    let good = page(&configuration.export());
    let cases = [
        (
            good.replace("\"version\": 2", "\"version\": 1"),
            "the document is version 1 and this Hedwig reads version 2",
        ),
        (
            good.replace("\"autostart\"", "\"auto-start\""),
            "the value has no autostart",
        ),
        (
            good.replace("\"at-logon\"", "\"at-login\""),
            "autostart has \"at-login\", which is not known here",
        ),
        ("{".to_owned(), "the text ends inside a value at byte 1"),
    ];
    for (text, account) in cases {
        let folder = Folder::new("unreadable-configuration");
        let places = folder.places();
        fs::write(places.configuration(), &text).unwrap();
        assert_eq!(
            load(&places, AT, &[]).unwrap(),
            Kept::Unreadable(account.to_owned())
        );
        let aside = set_aside(&folder, "configuration");
        assert_eq!(aside, [format!("configuration.unreadable-{}.json", AT.0)]);
        let kept = fs::read_to_string(folder.path().join(aside.first().unwrap())).unwrap();
        assert_eq!(kept, text);
        assert!(!places.configuration().exists());
    }
    // What the person stored is read back whatever has changed around it: a
    // grant of a capability nothing defines now is kept, and serves nothing.
    let folder = Folder::new("dangling-configuration");
    let dangling = good.replace(
        "\"grants\": []",
        "\"grants\": [{\"grant\": {\"capability\": \"gone\", \"remotes\": {\"route\": \"ssh\"}}, \"terms\": {\"activation\": \"on-request\", \"setup\": \"inspect\", \"acknowledged\": [], \"lends\": []}}]",
    );
    fs::write(folder.places().configuration(), &dangling).unwrap();
    assert!(matches!(
        load(&folder.places(), AT, &[]).unwrap(),
        Kept::Read(kept) if kept.grants().count() == 1
    ));
    assert!(
        Configuration::import(&catalogue, read(&dangling).unwrap()).is_err(),
        "made now, the same statement is refused"
    );
    let folder = Folder::new("not-text-configuration");
    fs::write(folder.places().configuration(), [0xff, 0xfe]).unwrap();
    assert_eq!(
        load(&folder.places(), AT, &[]).unwrap(),
        Kept::Unreadable("it is not text".to_owned())
    );
}

/// Each way the files can fail to be used says which file, and why.
#[test]
fn every_failure_names_what_could_not_be_used() {
    let folder = Folder::new("failures");
    let file = folder.path().join("a-file");
    fs::write(&file, "").unwrap();
    let under_a_file = Places::at(file.join("hedwig")).unwrap_err();
    assert!(matches!(under_a_file, StoreError::Folder(_)));
    assert!(
        under_a_file
            .to_string()
            .starts_with("the folder Hedwig keeps its files in cannot be used: ")
    );

    // A folder stands where each file should be.
    let places = folder.places();
    fs::create_dir(places.trail()).unwrap();
    let trail = Trail::open(&places, AT).unwrap_err();
    assert!(matches!(trail, StoreError::Trail(_)));
    assert!(
        trail
            .to_string()
            .starts_with("the record of activity cannot be written: ")
    );

    fs::create_dir(places.configuration()).unwrap();
    let (_, configuration) = configured();
    prepare(&places, &configuration.export(), Seq(2)).unwrap();
    let kept = settle(&places, Seq(2)).unwrap_err();
    assert!(matches!(kept, StoreError::Configuration(_)));
    assert!(
        kept.to_string()
            .starts_with("the configuration cannot be written: ")
    );
    fs::remove_file(folder.path().join("configuration.next-2.json")).unwrap();
    let loaded = load(&places, AT, &[]).unwrap_err();
    assert!(matches!(loaded, StoreError::Configuration(_)));
    assert!(std::error::Error::source(&loaded).is_some());
}

/// The record is the claim to being the person's one supervisor. A second
/// claim is refused while the first is held, the record says what its holder
/// last wrote, and it is gone the moment its holder lets go.
#[test]
fn a_second_supervisor_is_refused_while_the_first_holds_the_record() {
    let folder = Folder::new("record");
    let places = folder.places();
    let mut claim = Claim::take(&places).unwrap();
    let second = Claim::take(&places).unwrap_err();
    assert!(matches!(second, ClaimError::Held));
    assert_eq!(
        second.to_string(),
        "Hedwig is already running for this person"
    );

    let running = claim.write(CoreState::Starting).unwrap();
    let on_disk = fs::read_to_string(places.record()).unwrap();
    assert_eq!(on_disk, line(&running) + "\n");
    // Nothing removes the record from under its holder: a folder cleared
    // while Hedwig runs would otherwise leave it running and unfindable.
    let removed = fs::remove_file(places.record()).unwrap_err();
    assert_eq!(removed.raw_os_error(), Some(SHARING));
    assert!(hedwig_win::file::held(&places.record()).unwrap());
    assert_eq!(fs::read_to_string(places.record()).unwrap(), on_disk);
    let (process, created) = hedwig_win::process::own().unwrap();
    assert_eq!(
        (running.supervisor.process, running.supervisor.created),
        (process, created)
    );

    // A shorter record replaces a longer one whole.
    let long = CoreState::Restarting {
        cause: Breakdown::Exited { status: 101 },
        said: "x".repeat(300),
    };
    claim.write(long).unwrap();
    claim.write(CoreState::Starting).unwrap();
    let read: Running = read(fs::read_to_string(places.record()).unwrap().trim_end()).unwrap();
    assert_eq!(read, running);

    // The ordinary ways of reading a file do not allow for its deletion, and
    // read the record all the same: a script needs nothing special. One that
    // allows no writer beside it - .NET's `File.ReadAllText` - reads it too,
    // since its holder only reads.
    for share in [3, 1] {
        let plain = fs::OpenOptions::new()
            .read(true)
            .share_mode(share)
            .open(places.record());
        assert!(plain.is_ok(), "sharing {share}: {plain:?}");
    }

    drop(claim);
    assert!(!hedwig_win::file::held(&places.record()).unwrap());
    // The record stays, saying what its supervisor last said; nobody holds
    // it, and the next supervisor takes it over.
    assert_eq!(fs::read_to_string(places.record()).unwrap(), on_disk);
    fs::write(places.record(), "left behind\n").unwrap();
    let mut after = Claim::take(&places).unwrap();
    after.write(CoreState::Starting).unwrap();
    assert!(
        fs::read_to_string(places.record())
            .unwrap()
            .starts_with('{')
    );

    fs::create_dir(folder.path().join("sub")).unwrap();
    let blocked = Places::at(folder.path().join("sub")).unwrap();
    fs::create_dir(blocked.record()).unwrap();
    let other = Claim::take(&blocked).unwrap_err();
    assert!(matches!(other, ClaimError::Other(_)));
    assert!(other.to_string().starts_with("the record cannot be made: "));
}

/// The trail's first line names its form and its second is its head; a trail
/// rewritten whole reads back as written, head and entries, and is appended
/// to from there.
#[test]
fn the_trail_names_its_form_and_its_head_and_reads_back_after_a_rewrite() {
    let folder = Folder::new("form");
    let places = folder.places();
    let opened = Trail::open(&places, AT).unwrap();
    assert_eq!(opened.head, State::default());
    let written = fs::read_to_string(places.trail()).unwrap();
    assert_eq!(
        written,
        format!("{{\"trail\":1}}\n{}\n", line(&State::default()))
    );
    let mut trail = opened.trail;
    let entries: Vec<Entry> = (1..=3)
        .map(|number| Entry {
            seq: Seq(number),
            at: Timestamp(number),
            tick: Tick(number),
            event: Event::Offline,
        })
        .collect();
    trail.append(&entries).unwrap();
    let head = State::fold(entries.get(..1).unwrap());
    assert_ne!(head, State::default(), "the head says what was dropped");
    let kept: Vec<Entry> = entries.get(1..).unwrap().to_vec();
    trail.rewrite(&places, &head, &kept).unwrap();
    let next = Entry {
        seq: Seq(4),
        at: Timestamp(4),
        tick: Tick(4),
        event: Event::Online,
    };
    trail.append(&[next]).unwrap();
    drop(trail);
    let reopened = Trail::open(&places, AT).unwrap();
    assert!(reopened.unreadable.is_none());
    assert_eq!(reopened.head, head);
    let numbers: Vec<u64> = reopened.entries.iter().map(|entry| entry.seq.0).collect();
    assert_eq!(numbers, [2, 3, 4]);
    assert!(
        fs::read_to_string(places.trail())
            .unwrap()
            .starts_with(&format!("{{\"trail\":1}}\n{}\n", line(&head)))
    );
    assert!(!folder.path().join("trail.next.jsonl").exists());
}

/// A trail whose head a power cut took before it was whole holds no entry:
/// it begins again whole, with nothing set aside.
#[test]
fn a_trail_without_its_head_begins_again_whole() {
    let folder = Folder::new("headless");
    let places = folder.places();
    fs::write(places.trail(), "{\"trail\":1}\n{\"started\":nu").unwrap();
    let opened = Trail::open(&places, AT).unwrap();
    assert!(opened.unreadable.is_none());
    assert_eq!(opened.head, State::default());
    assert_eq!(opened.entries, Vec::new());
    assert_eq!(
        fs::read_to_string(places.trail()).unwrap(),
        format!("{{\"trail\":1}}\n{}\n", line(&State::default()))
    );
}

/// A trail of a form this build does not read, a later one, is set aside
/// whole and said with both numbers; so is one that names no form.
#[test]
fn a_trail_of_a_later_form_is_set_aside_and_said_with_both_numbers() {
    for (first, account) in [
        (
            "{\"trail\":2}",
            "it is in form 2 of the trail, and this Hedwig reads forms up to 1",
        ),
        ("{\"seq\":1}", "line 1 names no form of the trail"),
    ] {
        let folder = Folder::new("later");
        let places = folder.places();
        fs::write(
            places.trail(),
            format!(
                "{first}
"
            ),
        )
        .unwrap();
        let opened = Trail::open(&places, AT).unwrap();
        let said = opened.unreadable.unwrap();
        assert!(said.starts_with(account), "{said}");
        assert_eq!(opened.entries, Vec::<Entry>::new());
        let aside = folder
            .path()
            .join(format!("trail.unreadable-{}.jsonl", AT.0));
        assert_eq!(
            fs::read_to_string(aside).unwrap(),
            format!(
                "{first}
"
            )
        );
    }
}

/// Files set aside are listed with their store, time and size, and go once
/// the horizon has passed them and their store is not still before the
/// person.
#[test]
fn set_aside_files_go_once_put_away_and_past_the_horizon() {
    let folder = Folder::new("aside");
    let places = folder.places();
    for name in [
        "trail.unreadable-100.jsonl",
        "configuration.unreadable-200.json",
        "trail.unreadable-900.jsonl",
    ] {
        fs::write(folder.path().join(name), "x").unwrap();
    }
    let listed: Vec<(Store, u64)> = places
        .set_aside()
        .unwrap()
        .into_iter()
        .map(|(_, store, at, _)| (store, at.0))
        .collect();
    assert_eq!(
        listed,
        [
            (Store::Trail, 100),
            (Store::Configuration, 200),
            (Store::Trail, 900)
        ]
    );
    places
        .forget_aside(Timestamp(500), &[Store::Configuration])
        .unwrap();
    let left: Vec<u64> = places
        .set_aside()
        .unwrap()
        .iter()
        .map(|(_, _, at, _)| at.0)
        .collect();
    assert_eq!(
        left,
        [200, 900],
        "the one put away and past the horizon goes"
    );
}
