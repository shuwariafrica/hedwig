//! What an ADB grant lends, at the surfaces: the server's devices listed at
//! grant time with none lent until the person names one,
//! what each grant lends on its line with lending and taking back there, a
//! device a remote reached for and was refused lent from where the refusal
//! shows, and what an ADB capability carries on - forwards and consoles
//! beside reverses - on the line, in the menu and in the activity.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::time::Instant;

use hedwig_model::capability::{Exposure, Lends};
use hedwig_model::config::{Activation, Change, Terms};
use hedwig_model::holder::{SourceHolder, Whose};
use hedwig_model::protocol::{Attachment, DeviceState, Lendable, Notice, Request, Topic};
use hedwig_model::refusal::{Refusal, Withheld};
use hedwig_model::remote::{Granted, RemoteId};
use hedwig_model::text::{DeviceSerial, DeviceSocket, Location, Port, Words};
use hedwig_model::trail::{Carriage, Dropped, Event as Happened, Failure, Health};
use hedwig_view::act::Act;
use hedwig_view::exposure::{self, Board, Line, Shown, Window};
use hedwig_view::glance::{self, Entry as Row};
use hedwig_view::grant::{self, Draft, Field, Form};
use hedwig_view::link::{Event, Place};
use hedwig_view::words::Keyrings;

mod common;
use common::support::{grant, name, remote, terms};
use common::{Bench, clock};

fn workspace() -> RemoteId {
    remote("coder", "dev/build")
}

fn serial(text: &str) -> DeviceSerial {
    DeviceSerial::try_from(text).unwrap()
}

/// The server's devices: an emulator, the person's phone by USB, and a
/// device the server lists with no serial, which no grant can name.
fn devices() -> Vec<Lendable> {
    vec![
        Lendable {
            serial: Some(serial("emulator-5554")),
            model: Some(Words::try_from("sdk_gphone64_x86_64").unwrap()),
            state: DeviceState::Device,
            attached: Attachment::Socket,
        },
        Lendable {
            serial: Some(serial("R5CR10ABC")),
            model: Some(Words::try_from("Pixel_7").unwrap()),
            state: DeviceState::Device,
            attached: Attachment::Usb,
        },
        Lendable {
            serial: None,
            model: None,
            state: DeviceState::NoPermission,
            attached: Attachment::Usb,
        },
    ]
}

fn refresh(bench: &mut Bench) {
    for topic in [
        Topic::Status,
        Topic::Exposure,
        Topic::Attention,
        Topic::Configuration,
        Topic::Workstation,
    ] {
        bench.notice(Notice::Stale(topic));
    }
}

/// The window's link attached, the server's devices `devices()`, and `adb`
/// granted to the workspace lending `lends`.
fn lending(lends: Lends) -> Bench {
    let mut bench = Bench::attached();
    bench.desk.hold_devices(&name("adb"), Ok(devices()));
    bench.feed(Event::Window(true));
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("adb", Granted::One(workspace())),
            terms: Terms {
                lends,
                ..terms(Activation::OnRequest, Exposure::SERVICE)
            },
        }),
    ));
    assert_eq!(bench.seen().refused, None);
    bench
}

fn window(bench: &Bench) -> Window {
    Window::of(bench.link.seen(), &clock, Instant::now())
}

fn adb(window: &Window) -> &Line {
    match &window.board {
        Board::Exposure { groups, .. } => groups
            .iter()
            .flat_map(|group| &group.lines)
            .find(|line| line.remote == Some(workspace()) && line.capability.as_str() == "adb")
            .expect("adb's line on the workspace"),
        other => unreachable!("{other:?}"),
    }
}

fn form(bench: &Bench, draft: &Draft) -> Form {
    let attached = bench.seen();
    Form::of(
        draft,
        attached.catalogue.as_ref().unwrap().reference(),
        attached.document.as_ref().unwrap(),
        attached.workstation.as_ref(),
        (
            draft
                .capability
                .as_ref()
                .and_then(|capability| attached.devices.get(capability)),
            None,
        ),
        None,
    )
}

fn label(shown: &Shown) -> &str {
    match shown {
        Shown::Offered { label, .. } | Shown::Withheld { label, .. } => label,
    }
}

fn act(shown: &Shown) -> &Act {
    match shown {
        Shown::Offered { act, .. } => act,
        Shown::Withheld { label, why } => unreachable!("{label}: {why}"),
    }
}

/// A person granting adb names which of the server's devices a remote gets:
/// the form lists each with its model, serial and how it is attached, lends
/// none until the person picks, and lends every device only where they
/// choose that; a device with no serial is lent only so. The grant asked is
/// one the core accepts, and the draft keeps what was picked across a
/// restart of the window.
#[test]
fn an_adb_grant_lends_no_device_until_the_person_picks_one_from_the_servers_list() {
    let mut bench = Bench::attached();
    bench.desk.hold_devices(&name("adb"), Ok(devices()));
    bench.feed(Event::Window(true));
    let (reference, document) = {
        let attached = bench.seen();
        (
            attached.catalogue.as_ref().unwrap().reference().clone(),
            attached.document.clone().unwrap(),
        )
    };
    let mut draft = Draft::default();
    draft.choose_capability(name("gpg"), &reference, &document);
    assert_eq!(
        form(&bench, &draft).lending,
        None,
        "gpg's source holds no device"
    );

    draft.choose_capability(name("adb"), &reference, &document);
    assert_eq!(draft.lends, Lends::none());
    let reading = form(&bench, &draft).lending.unwrap();
    assert_eq!(
        reading.listing.as_deref(),
        Some("Reading which devices the workstation's ADB server holds.")
    );
    bench.feed(Event::Devices(name("adb")));
    let lending = form(&bench, &draft).lending.unwrap();
    assert_eq!(lending.listing, None);
    assert_eq!(
        lending.lends,
        "lends no device: the remote sees none until you lend one"
    );
    assert_eq!(
        lending
            .devices
            .iter()
            .map(|choice| (choice.label.as_str(), choice.chosen))
            .collect::<Vec<_>>(),
        [
            ("sdk_gphone64_x86_64 (emulator-5554), an emulator", false),
            ("Pixel_7 (R5CR10ABC), by USB", false),
            (
                "a device the server lists with no serial, by USB, which the ADB server has no \
                 permission to open on this workstation",
                false
            ),
        ]
    );
    assert!(!lending.every);

    draft.lend(serial("emulator-5554"), true);
    let lending = form(&bench, &draft).lending.unwrap();
    assert_eq!(lending.lends, "lends sdk_gphone64_x86_64 (emulator-5554)");
    assert_eq!(
        lending
            .devices
            .iter()
            .map(|choice| choice.chosen)
            .collect::<Vec<_>>(),
        [true, false, false]
    );
    draft.choose_route(name("coder"), &reference);
    draft.choose_activation(Activation::OnRequest);
    draft.acknowledge("service", true);
    let change = draft.change(&reference, &document).unwrap();
    let Change::Grant { terms, .. } = &change else {
        unreachable!()
    };
    assert_eq!(terms.lends, Lends::devices([serial("emulator-5554")]));
    assert_eq!(bench.permits(&Request::Change(change)), Ok(()));
    // Kept on disk as written, and read back the same, both ways.
    assert_eq!(Draft::read(&draft.written()), Ok(draft.clone()));

    draft.lend_every(true);
    let lending = form(&bench, &draft).lending.unwrap();
    assert!(lending.every);
    assert_eq!(
        lending.lends,
        "lends every device the workstation's ADB server holds, now and later"
    );
    assert!(lending.devices.iter().all(|choice| choice.chosen));
    // Under every device none is named: one is not taken back on its own.
    draft.lend(serial("R5CR10ABC"), false);
    assert_eq!(draft.lends, Lends::Every);
    assert_eq!(Draft::read(&draft.written()), Ok(draft.clone()));
    draft.lend_every(false);
    assert_eq!(draft.lends, Lends::none());

    // Another capability's devices are another source's.
    draft.lend(serial("R5CR10ABC"), true);
    draft.choose_capability(name("gpg"), &reference, &document);
    assert_eq!(draft.lends, Lends::none());
}

/// The list reads as being read until the core answers, and where the
/// server's devices cannot be read, the core's refusal in the model's words
/// stands in its place - for a server older than platform-tools 35.0.0, that
/// cause and its remedy; a grant refused for lending
/// what its source does not hold is shown at the devices. It is read once for
/// what shows it, and again when the person asks.
#[test]
fn the_list_says_while_it_is_read_and_why_it_could_not_be() {
    let mut bench = Bench::attached();
    let refusal = Refusal::SourceUnavailable {
        capability: name("adb"),
        failure: Failure::Outdated,
    };
    bench
        .desk
        .hold_devices(&name("adb"), Err(Failure::Outdated));
    bench.feed(Event::Window(true));
    let asked = |bench: &Bench| {
        bench
            .sent
            .iter()
            .filter(|frame| matches!(frame.request, Request::Devices(_)))
            .count()
    };
    bench.feed(Event::Devices(name("adb")));
    bench.feed(Event::Devices(name("adb")));
    assert_eq!(asked(&bench), 1, "read once for what shows it");
    let lending = grant::Lending::of(&Lends::none(), bench.seen().devices.get(&name("adb")));
    assert_eq!(
        lending.listing,
        Some(format!("The devices could not be read: {refusal}."))
    );
    assert_eq!(
        lending.devices,
        Vec::<grant::Choice<Option<DeviceSerial>>>::new()
    );
    assert!(
        lending
            .listing
            .as_deref()
            .is_some_and(|said| said.contains("updating platform-tools on this workstation")),
        "{:?}",
        lending.listing
    );
    bench.feed(Event::Wish(Place::Window, Request::Devices(name("adb"))));
    assert_eq!(asked(&bench), 2, "again when the person asks");

    let unlendable = Refusal::Unlendable {
        capability: name("gpg"),
        lent: hedwig_model::capability::Holds::Devices,
    };
    assert_eq!(grant::blames(&unlendable), Field::Lends);
    assert_eq!(
        unlendable.to_string(),
        "gpg holds no devices to lend; a grant of it lends none"
    );
}

/// A person reads on adb's line what its grant lends and changes it there: a
/// device not lent is lent once the person has read what that lets the
/// remote do with it; a device lent is taken back in one act; every device is
/// asked first, and taken back in one act. Each act is one the core carries
/// out, and the line then says what is lent.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one person's flow over every way a grant lends"
)]
fn a_grants_line_lends_and_takes_back_its_devices() {
    let mut bench = lending(Lends::devices([serial("emulator-5554")]));
    // Until the list is read, the line says so and holds what is lent.
    let shown = window(&bench);
    let lent = adb(&shown).lending.as_ref().unwrap();
    assert_eq!(lent.lends, "lends emulator-5554");
    assert_eq!(
        lent.listing.as_deref(),
        Some("Reading which devices the workstation's ADB server holds.")
    );
    assert_eq!(
        lent.devices
            .iter()
            .map(|device| (device.label.as_str(), device.lent))
            .collect::<Vec<_>>(),
        [(
            "emulator-5554, which the workstation's ADB server does not hold now",
            true
        )]
    );
    bench.feed(Event::Devices(name("adb")));
    let shown = window(&bench);
    let line = adb(&shown);
    let lent = line.lending.as_ref().unwrap();
    assert_eq!(lent.lends, "lends sdk_gphone64_x86_64 (emulator-5554)");
    assert_eq!(
        lent.devices
            .iter()
            .map(|device| (
                device.label.as_str(),
                device.lent,
                device.act.as_ref().map(label)
            ))
            .collect::<Vec<_>>(),
        [
            (
                "sdk_gphone64_x86_64 (emulator-5554), an emulator",
                true,
                Some("Stop lending sdk_gphone64_x86_64 (emulator-5554)")
            ),
            (
                "Pixel_7 (R5CR10ABC), by USB",
                false,
                Some("Lend Pixel_7 (R5CR10ABC)...")
            ),
            (
                "a device the server lists with no serial, by USB, which the ADB server has no \
                 permission to open on this workstation",
                false,
                None
            ),
        ]
    );
    assert_eq!(
        lent.acts.iter().map(label).collect::<Vec<_>>(),
        ["Lend every device...", "Look again for devices"]
    );
    let Act::Confirm {
        request,
        consequence,
        answer,
    } = act(lent.devices[1].act.as_ref().unwrap())
    else {
        unreachable!("lending another device is asked first")
    };
    assert_eq!(answer, "Lend it");
    assert_eq!(
        consequence,
        "dev/build (coder) can then see Pixel_7 (R5CR10ABC) and use it as a device attached \
         there: install and run apps, open a shell, read and write its files and its logs."
    );
    assert_eq!(bench.permits(request), Ok(()));
    let Act::Confirm {
        consequence: every, ..
    } = act(&lent.acts[0])
    else {
        unreachable!("every device is asked first")
    };
    assert!(every.contains("your own phone among them"), "{every}");

    let request = common::clone(request);
    bench.feed(Event::Wish(
        Place::Line {
            remote: Some(workspace()),
            capability: name("adb"),
        },
        request,
    ));
    let shown = window(&bench);
    let lent = adb(&shown).lending.as_ref().unwrap();
    assert_eq!(
        lent.lends,
        "lends sdk_gphone64_x86_64 (emulator-5554), Pixel_7 (R5CR10ABC)"
    );
    let Act::Send(request) = act(lent.devices[0].act.as_ref().unwrap()) else {
        unreachable!("taking a device back is one act")
    };
    assert_eq!(bench.permits(request), Ok(()));

    // Under every device, each is lent and none is taken back on its own.
    let mut bench = lending(Lends::Every);
    bench.feed(Event::Devices(name("adb")));
    let shown = window(&bench);
    let lent = adb(&shown).lending.as_ref().unwrap();
    assert!(
        lent.devices
            .iter()
            .all(|device| device.lent && device.act.is_none())
    );
    let Act::Send(request) = act(&lent.acts[0]) else {
        unreachable!("taking every device back is one act")
    };
    assert_eq!(label(&lent.acts[0]), "Stop lending every device");
    assert_eq!(bench.permits(request), Ok(()));

    // Reading the list again from the line asks the core once more.
    let Act::Send(again) = act(&lent.acts[1]) else {
        unreachable!()
    };
    assert_eq!(*again, Request::Devices(name("adb")));
}

/// A remote that reached for a device its
/// grant does not lend reads only that nothing is there; the person reads on adb's
/// line and in what needs them which device it reached for and how often,
/// and lends it from there - from the refusal where the list does not
/// already offer it.
#[test]
fn a_device_a_remote_reached_for_is_lent_from_where_its_refusal_shows() {
    let mut bench = lending(Lends::none());
    bench.desk.channel_up(&workspace(), "linux");
    bench.desk.trail.push(Happened::TurnedAway {
        remote: Some(workspace()),
        refusal: Refusal::Withheld {
            capability: name("adb"),
            request: Withheld::Unlent(Some(serial("R5CR10ABC"))),
        },
    });
    bench.desk.trail.push(Happened::TurnedAway {
        remote: Some(workspace()),
        refusal: Refusal::Withheld {
            capability: name("adb"),
            request: Withheld::Unlent(None),
        },
    });
    refresh(&mut bench);
    let shown = window(&bench);
    let line = adb(&shown);
    let mut turned = line.turned.clone();
    turned.sort();
    assert_eq!(
        turned,
        [
            "a request to adb was refused because it asked for R5CR10ABC, which the grant does \
             not lend, once",
            "a request to adb was refused because it asked for a device without naming one, and \
             the grant lends none of those the workstation's ADB server holds, once",
        ]
    );
    // The list is not read yet: the refusal offers the device.
    assert_eq!(
        line.lending
            .as_ref()
            .unwrap()
            .acts
            .iter()
            .map(label)
            .collect::<Vec<_>>(),
        [
            "Lend R5CR10ABC...",
            "Lend every device...",
            "Look again for devices"
        ]
    );
    let Board::Exposure { needs, .. } = &shown.board else {
        unreachable!()
    };
    let need = needs
        .iter()
        .find(|need| need.sentence.contains("R5CR10ABC"))
        .unwrap();
    let Act::Confirm { request, .. } = act(&need.acts[0]) else {
        unreachable!("lending is asked first")
    };
    assert_eq!(label(&need.acts[0]), "Lend R5CR10ABC...");
    assert_eq!(bench.permits(request), Ok(()));

    // Once the list holds it, its own box offers it, once.
    bench.feed(Event::Devices(name("adb")));
    let shown = window(&bench);
    let lent = adb(&shown).lending.as_ref().unwrap();
    assert_eq!(
        lent.acts.iter().map(label).collect::<Vec<_>>(),
        ["Lend every device...", "Look again for devices"]
    );
    let Board::Exposure { needs, .. } = &shown.board else {
        unreachable!()
    };
    let need = needs
        .iter()
        .find(|need| need.sentence.contains("R5CR10ABC"))
        .unwrap();
    assert_eq!(label(&need.acts[0]), "Lend Pixel_7 (R5CR10ABC)...");
}

/// A remote's forward and a lent emulator's console read on adb's
/// line with what the workstation's own listing shows, under the remote in
/// the menu as where each lands, and in the activity from when it was carried
/// to why it stopped.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one carriage of every kind on every surface"
)]
fn a_forward_and_a_console_read_on_the_line_in_the_menu_and_in_the_activity() {
    let mut bench = lending(Lends::devices([serial("emulator-5554")]));
    let connection = bench.desk.channel_up(&workspace(), "linux");
    let forward = Carriage::Forward {
        port: Port::try_from(7100).unwrap(),
        device: serial("emulator-5554"),
        socket: DeviceSocket::try_from("tcp:7000").unwrap(),
    };
    let console = Carriage::Console {
        port: Port::try_from(5554).unwrap(),
        device: serial("emulator-5554"),
    };
    let reverse = Carriage::Reverse(hedwig_model::trail::Target::Loopback(
        Port::try_from(8081).unwrap(),
    ));
    for (carriage, endpoint) in [(&reverse, 50131), (&forward, 50140), (&console, 50150)] {
        bench.desk.trail.push(Happened::Carried {
            connection,
            capability: name("adb"),
            carriage: carriage.clone(),
            endpoint: Port::try_from(endpoint).unwrap(),
        });
    }
    refresh(&mut bench);
    let shown = window(&bench);
    assert_eq!(
        adb(&shown).carried,
        [
            "A device's connections reach port 8081 on the remote, which adb reverse --list on \
             this workstation shows as tcp:50131",
            "Port 7100 on the remote reaches tcp:7000 on emulator-5554, which adb forward --list \
             on this workstation shows as tcp:50140",
            "The console of emulator-5554 answers at port 5554 on the remote",
        ]
    );
    let said: Vec<String> = glance::menu(bench.link.seen(), Instant::now())
        .into_iter()
        .find_map(|entry| match entry {
            Row::Group { label, entries } if label == workspace().to_string() => Some(entries),
            _ => None,
        })
        .expect("the workspace is in the menu")
        .into_iter()
        .filter_map(|entry| match entry {
            Row::Line(line) => Some(line),
            _ => None,
        })
        .collect();
    assert!(
        said.contains(
            &"adb: a device's connections reach port 8081 on the remote; port 7100 reaches \
              tcp:7000 on emulator-5554; the console of emulator-5554 at port 5554"
                .to_owned()
        ),
        "{said:?}"
    );

    bench.desk.trail.push(Happened::Dropped {
        connection,
        capability: name("adb"),
        carriage: forward.clone(),
        why: Dropped::Removed,
    });
    bench.desk.trail.push(Happened::Dropped {
        connection,
        capability: name("adb"),
        carriage: console.clone(),
        why: Dropped::Unlent,
    });
    refresh(&mut bench);
    let shown = window(&bench);
    assert_eq!(
        adb(&shown).carried.len(),
        1,
        "only the reverse is carried now"
    );
    let activity = exposure::activity(&bench.desk.trail.entries, &clock, Keyrings::default());
    let said: Vec<&str> = activity
        .iter()
        .map(|(_, said)| said.split_once(": ").unwrap().1)
        .collect();
    // A capability added to one connection says what it lends.
    let opening = Happened::Opening {
        remote: workspace(),
        with: vec![name("adb")],
        acknowledged: Exposure::SERVICE,
        lends: Lends::devices([serial("emulator-5554")]),
        opener: hedwig_model::trail::Opener::Grant,
    };
    let entry = hedwig_model::trail::Entry {
        seq: hedwig_model::trail::Seq(1),
        at: hedwig_model::trail::Timestamp(7),
        tick: hedwig_model::trail::Tick(7),
        event: opening,
    };
    assert_eq!(
        exposure::activity(&[entry], &clock, Keyrings::default()),
        [(
            hedwig_model::trail::Seq(1),
            "t7: connecting for adb, which lends emulator-5554, as its grant says".to_owned()
        )]
    );
    for expected in [
        "adb stopped carrying the console of emulator-5554: emulator-5554 is no longer lent to \
         the remote",
        "adb stopped carrying the forward from port 7100 on the remote: the remote removed it",
        "adb carries the console of emulator-5554 on, at port 5554 on the remote",
        "adb carries a forward on: port 7100 on the remote reaches tcp:7000 on emulator-5554",
    ] {
        assert!(said.contains(&expected), "{said:?}");
    }
}

/// A person reading what a remote's Android build did: every connection its ADB
/// client opens is an entry, served, and a run of them reads as one line with
/// how often and from when to when, so the signature asked between them is
/// not paged away behind them; entries that differ stay apart.
#[test]
fn a_run_of_the_same_entry_reads_as_one_line_with_how_often() {
    use hedwig_model::capability::Operation;
    use hedwig_model::policy::Basis;
    use hedwig_model::trail::{ConnectionId, Entry, Outcome, RequestId, Seq, Tick, Timestamp};
    let connection = ConnectionId(Seq(1));
    let mut entries = Vec::new();
    let mut push = |event: Happened| {
        let seq = Seq(u64::try_from(entries.len()).unwrap() + 2);
        entries.push(Entry {
            seq,
            at: Timestamp(seq.0),
            tick: Tick(seq.0),
            event,
        });
        seq
    };
    let ask = |push: &mut dyn FnMut(Happened) -> Seq, capability: &str, operation| {
        let asked = push(Happened::Asked {
            connection,
            capability: name(capability),
            operation,
            key: None,
        });
        push(Happened::Settled {
            request: RequestId(asked),
            outcome: Outcome::Served(Basis::Default),
        });
    };
    for _ in 0..3 {
        ask(&mut push, "adb", Operation::Connect);
    }
    ask(&mut push, "gpg", Operation::Sign);
    for _ in 0..2 {
        ask(&mut push, "adb", Operation::Connect);
    }
    // A clock that tells one minute: a run within it reads one time.
    let minute = |at: Timestamp| format!("m{}", at.0 / 100);
    assert_eq!(
        exposure::activity(&entries, &minute, Keyrings::default())
            .into_iter()
            .map(|(_, said)| said)
            .collect::<Vec<_>>(),
        [
            "m0: asked to use adb - served, 2 times",
            "m0: asked to sign with gpg - served",
            "m0: asked to use adb - served, 3 times",
        ]
    );
    let said: Vec<String> = exposure::activity(&entries, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, said)| said)
        .collect();
    assert_eq!(
        said,
        [
            "t10 to t12: asked to use adb - served, 2 times",
            "t8: asked to sign with gpg - served",
            "t2 to t6: asked to use adb - served, 3 times",
        ]
    );
}

/// A person plugs the phone in while the grant form lists the server's devices: it
/// appears with nothing pressed, read again because the core said the list
/// changed; the same list again tells nothing; the server gone is said
/// where the list stood, in the model's words.
#[test]
fn a_device_list_shown_follows_the_server_without_the_person_asking() {
    let mut bench = Bench::attached();
    let adb = name("adb");
    bench
        .desk
        .hold_devices(&adb, Ok(devices().into_iter().take(1).collect()));
    bench.feed(Event::Window(true));
    bench.feed(Event::Devices(adb.clone()));
    let asked = |bench: &Bench| {
        bench
            .sent
            .iter()
            .filter(|frame| matches!(frame.request, Request::Devices(_)))
            .count()
    };
    let listed = |bench: &Bench| match bench.seen().devices.get(&name("adb")) {
        Some(Some(Ok(listed))) => listed.len(),
        other => unreachable!("{other:?}"),
    };
    assert_eq!((asked(&bench), listed(&bench)), (1, 1));

    let told = bench.desk.hold_devices(&adb, Ok(devices()));
    assert_eq!(bench.hear(told), 1, "the window is told");
    assert_eq!(
        (asked(&bench), listed(&bench)),
        (2, 3),
        "and reads them again"
    );

    let told = bench.desk.hold_devices(&adb, Ok(devices()));
    assert_eq!(bench.hear(told), 0);
    assert_eq!(asked(&bench), 2, "an unchanged list is not read again");

    let told = bench.desk.hold_devices(&adb, Err(Failure::Unreachable));
    assert_eq!(bench.hear(told), 1);
    let gone = Refusal::SourceUnavailable {
        capability: adb.clone(),
        failure: Failure::Unreachable,
    };
    let lending = grant::Lending::of(&Lends::none(), bench.seen().devices.get(&adb));
    assert_eq!(
        lending.listing,
        Some(format!("The devices could not be read: {gone}."))
    );
    assert!(
        gone.to_string()
            .contains("nothing answers for adb on this workstation"),
        "{gone}"
    );
}

/// A person's remote's adb is refused because Windows will not let Hedwig read
/// whose ADB server answers - the person's own, started over SSH in session 0.
/// Wherever the refusal is said, what answers is said with it and the
/// server's own `adb kill-server`, behind "if it is yours": on adb's line
/// beside its state, under the remote in the icon's menu where the refusal is
/// counted, and on the grant form when its list of devices fails so. The
/// presence reads what adb is defined as only once such a refusal is counted.
#[test]
fn an_adb_server_hedwig_cannot_read_is_said_with_what_stops_it_wherever_it_fails() {
    let refusal = Refusal::SourceUnavailable {
        capability: name("adb"),
        failure: Failure::Unidentified,
    };
    let mend = "adb is answered by adb.exe in session 0, which Windows does not let Hedwig read. \
                If it is yours, adb kill-server stops it, and your next adb command starts one in \
                the sign-in you run it from";
    let refuse = |bench: &mut Bench| {
        bench.desk.channel_up(&workspace(), "linux");
        bench.desk.trail.push(Happened::HeldBy {
            capability: name("adb"),
            holder: Some(SourceHolder {
                program: Location::try_from("adb.exe").unwrap(),
                session: 0,
                whose: Whose::Unread,
            }),
        });
        bench.desk.trail.push(Happened::Source {
            capability: name("adb"),
            health: Health::Failing(Failure::Unidentified),
        });
        bench.desk.trail.push(Happened::TurnedAway {
            remote: Some(workspace()),
            refusal: refusal.clone(),
        });
    };
    let definitions = |bench: &Bench| {
        bench
            .sent
            .iter()
            .filter(|frame| matches!(frame.request, Request::Catalogue))
            .count()
    };

    // The presence: no definition is read until a refusal they mend counts.
    let mut presence = Bench::attached();
    presence.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("adb", Granted::One(workspace())),
            terms: terms(Activation::OnRequest, Exposure::SERVICE),
        }),
    ));
    assert_eq!(definitions(&presence), 0);
    refuse(&mut presence);
    for topic in [
        Topic::Status,
        Topic::Exposure,
        Topic::Attention,
        Topic::Workstation,
    ] {
        presence.notice(Notice::Stale(topic));
    }
    assert_eq!(definitions(&presence), 1);
    let said: Vec<String> = glance::menu(presence.link.seen(), Instant::now())
        .into_iter()
        .find_map(|entry| match entry {
            Row::Group { label, entries } if label == workspace().to_string() => Some(entries),
            _ => None,
        })
        .expect("the workspace is in the menu")
        .into_iter()
        .filter_map(|entry| match entry {
            Row::Line(line) => Some(line),
            _ => None,
        })
        .collect();
    assert!(said.contains(&format!("{refusal}, once")), "{said:#?}");
    assert!(said.contains(&mend.to_owned()), "{said:#?}");

    // The window: the line, beside its state, and the refusal counted alone.
    let mut bench = lending(Lends::none());
    refuse(&mut bench);
    refresh(&mut bench);
    let shown = window(&bench);
    let line = adb(&shown);
    let mut capitalised = refusal.to_string();
    capitalised.replace_range(..1, "W");
    assert_eq!(
        line.answers,
        [format!("{capitalised}."), format!("{mend}.")]
    );
    assert_eq!(line.turned, [format!("{refusal}, once")]);

    // The grant form, whose list of devices fails so.
    bench
        .desk
        .hold_devices(&name("adb"), Err(Failure::Unidentified));
    bench.feed(Event::Devices(name("adb")));
    let draft = Draft {
        capability: Some(name("adb")),
        ..Draft::default()
    };
    assert_eq!(
        form(&bench, &draft).lending.unwrap().listing,
        Some(format!("The devices could not be read: {refusal}. {mend}."))
    );
}
