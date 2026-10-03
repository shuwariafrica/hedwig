//! What the trail keeps: a horizon inside a ceiling, the rest folded into
//! the trail's head, with one entry saying how much went and why.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU8;

use hedwig_model::policy::Selector;
use hedwig_model::protocol::Topic;
use hedwig_model::remote::{RemoteId, Sets};
use hedwig_model::text::{Address, Name};
use hedwig_model::trail::{
    CEILING, Cut, Entry, Event, FORM, Form, Seq, State, Tick, Timestamp, about, compact, page,
};
use hedwig_model::wire::{line, read, read_stored};

mod support;
use support::corpus;

/// The trail as the core keeps it on disk - its head on a line of its own,
/// then an entry a line - read back line by line.
fn through_disk(head: &State, entries: &[Entry]) -> (State, Vec<Entry>) {
    let mut file = line(head) + "\n";
    file.extend(entries.iter().map(|entry| line(entry) + "\n"));
    let mut lines = file.lines();
    let head = read_stored(lines.next().expect("the head")).expect("the head reads back");
    let entries = lines.map(|text| read(text).expect("an entry")).collect();
    (head, entries)
}

#[test]
fn the_whole_fold_reads_back_from_its_written_form_after_every_entry() {
    let entries = corpus::entries();
    for cut in 0..=entries.len() {
        let state = State::fold(entries.get(..cut).unwrap());
        let back: State = read(&line(&state)).expect("the state reads back");
        assert_eq!(back, state, "after {cut} entries");
    }
}

#[test]
fn a_compacted_trail_folds_from_its_head_to_what_the_whole_trail_folded_to_at_every_cut() {
    let entries = corpus::entries();
    let whole = State::fold(&entries);
    let mut cuts = 0;
    for at in entries
        .iter()
        .map(|entry| entry.at)
        .chain([Timestamp(u64::MAX)])
    {
        let (head, compacted) = compact(State::default(), entries.clone(), at, CEILING);
        assert_eq!(
            State::after(head.clone(), &compacted),
            whole,
            "cut before {at:?}"
        );
        let (head, compacted) = through_disk(&head, &compacted);
        assert_eq!(
            State::after(head, &compacted),
            whole,
            "cut before {at:?}, read back from disk"
        );
        let numbers: Vec<Seq> = compacted.iter().map(|entry| entry.seq).collect();
        assert!(
            numbers.windows(2).all(|pair| pair.first() < pair.get(1)),
            "entries stay in order"
        );
        cuts += 1;
    }
    assert_eq!(cuts, entries.len() + 1);
}

#[test]
fn kept_entries_keep_their_numbers_and_the_cut_says_why() {
    let entries = corpus::entries();
    let half = entries.len() / 2;
    let before = entries.get(half).unwrap().at;
    let (_, compacted) = compact(State::default(), entries.clone(), before, CEILING);
    assert_eq!(compacted.len(), entries.len() - half + 1);
    assert_eq!(compacted.get(1..), entries.get(half..));
    let earlier = entries
        .get(..half)
        .unwrap()
        .iter()
        .filter(|entry| !matches!(entry.event, Event::Kept { .. }))
        .count() as u64;
    assert_eq!(
        compacted.first().unwrap().event,
        Event::Kept {
            dropped: earlier,
            cut: Cut::Horizon
        },
        "the cut is the horizon's, and an earlier compaction's entry is not counted"
    );
    assert_eq!(
        compacted.first().unwrap().seq,
        entries.get(half - 1).unwrap().seq
    );
}

#[test]
fn compacting_again_with_nothing_older_changes_nothing() {
    let entries = corpus::entries();
    let before = entries.get(entries.len() / 3).unwrap().at;
    let once = compact(State::default(), entries, before, CEILING);
    let twice = compact(once.0.clone(), once.1.clone(), before, CEILING);
    assert_eq!(twice, once);
    let nothing_older = corpus::entries();
    assert_eq!(
        compact(
            State::default(),
            nothing_older.clone(),
            Timestamp(0),
            CEILING
        ),
        (State::default(), nothing_older)
    );
}

#[test]
fn compacting_a_compacted_trail_folds_its_head_on() {
    let entries = corpus::entries();
    let whole = State::fold(&entries);
    let third = entries.len() / 3;
    let (head, once) = compact(
        State::default(),
        entries.clone(),
        entries.get(third).unwrap().at,
        CEILING,
    );
    let (head, twice) = compact(head, once, entries.get(2 * third).unwrap().at, CEILING);
    assert_eq!(State::after(head, &twice), whole);
    assert!(matches!(
        twice.first().unwrap().event,
        Event::Kept {
            cut: Cut::Horizon,
            ..
        }
    ));
    assert_eq!(
        twice
            .iter()
            .filter(|entry| matches!(entry.event, Event::Kept { .. }))
            .count(),
        1,
        "one cut says where the trail now begins"
    );
}

#[test]
fn past_the_ceiling_the_oldest_go_whatever_the_horizon_and_it_says_so() {
    let entries = corpus::entries();
    let ceiling = entries.len() / 4;
    let (head, compacted) = compact(State::default(), entries.clone(), Timestamp(0), ceiling);
    assert_eq!(compacted.len(), ceiling + 1);
    assert!(matches!(
        compacted.first().unwrap().event,
        Event::Kept {
            cut: Cut::Ceiling,
            ..
        }
    ));
    assert_eq!(State::after(head, &compacted), State::fold(&entries));
}

#[test]
fn a_flood_past_the_ceiling_is_held_at_the_ceiling() {
    let mut entries = corpus::entries();
    let last = entries.last().unwrap().clone();
    let flood = CEILING + 5_000;
    for number in 1..=flood as u64 {
        entries.push(Entry {
            seq: Seq(last.seq.0 + number),
            at: Timestamp(last.at.0 + number),
            tick: Tick(last.tick.0 + number),
            event: Event::Offline,
        });
    }
    let whole = State::fold(&entries);
    let (head, compacted) = compact(State::default(), entries, Timestamp(0), CEILING);
    assert_eq!(compacted.len(), CEILING + 1);
    assert_eq!(State::after(head, &compacted), whole);
}

/// Every remote's activity reaches back to where the trail was cut and
/// says why, whether or not anything of that remote's was dropped.
#[test]
fn every_remotes_activity_ends_at_the_cut_with_how_much_went_and_why() {
    let entries = corpus::entries();
    let half = entries.len() / 2;
    let (head, compacted) = compact(
        State::default(),
        entries.clone(),
        entries.get(half).unwrap().at,
        CEILING,
    );
    let kept = compacted.first().unwrap();
    let mut remotes: Vec<RemoteId> = entries
        .iter()
        .filter_map(|entry| match &entry.event {
            Event::Opening { remote, .. } => Some(remote.clone()),
            _ => None,
        })
        .collect();
    remotes.push(RemoteId {
        route: Name::try_from("ssh").unwrap(),
        address: Address::try_from("never@seen.example").unwrap(),
    });
    for remote in &remotes {
        let reached = about(&head, &compacted, remote, &Sets::NONE).next();
        assert_eq!(reached, Some(kept), "{remote:?}");
        let oldest = page(
            &head,
            &compacted,
            &Selector::Only(remote.clone()),
            &Sets::NONE,
            None,
            NonZeroU8::MAX,
        );
        if oldest.len() < usize::from(NonZeroU8::MAX.get()) {
            assert_eq!(oldest.first(), Some(kept), "{remote:?}");
        }
    }
    assert!(
        kept.event.touches().contains(&Topic::Exposure),
        "a remote's activity is read under exposure"
    );
}

#[test]
fn the_trail_names_its_form_on_its_first_line() {
    assert_eq!(line(&Form { trail: FORM }), "{\"trail\":1}");
    assert_eq!(read::<Form>("{\"trail\":1}").unwrap(), Form { trail: 1 });
}
