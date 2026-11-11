//! A serial port lent to a remote, at the surfaces: the port picked from the
//! workstation's own listing where the capability is defined, with what a
//! remote's tool cannot do through it; the address the remote's tools open it
//! at, where it is defined, granted and on its line, with how long they wait
//! where the person is asked first; the port a connection holds, since when;
//! a second connection refused for it; two capabilities at one spot on the
//! remote; and the port taken and given back in the remote's activity.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::time::Instant;

use hedwig_model::capability::{Capability, Exposure, Operation, Source};
use hedwig_model::config::{Activation, Change, Document, Reference};
use hedwig_model::gate::Verdict;
use hedwig_model::policy::{Mode, RuleScope, Selector};
use hedwig_model::protocol::{Notice, Request, SerialPort, Topic, Usb};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::text::{Port, PortName, Words};
use hedwig_model::trail::{
    ConnectionId, Entry, Event as Happened, Failure, Health, RequestId, Seq, Tick, Timestamp,
};
use hedwig_view::define::{Definitions, Draft, Edit, Field, Form, Input, Kind};
use hedwig_view::exposure::{self, Board, Line, Shown, Window};
use hedwig_view::glance::{self, Entry as Row};
use hedwig_view::grant;
use hedwig_view::link::{Event, Place};
use hedwig_view::words::Keyrings;

mod common;
use common::support::{grant, name, remote, terms};
use common::{Bench, clock};

fn workspace() -> RemoteId {
    remote("coder", "dev/build")
}

fn lab() -> RemoteId {
    remote("coder", "lab/bench")
}

fn port_name(text: &str) -> PortName {
    PortName::try_from(text).unwrap()
}

fn port(number: u16) -> Port {
    Port::try_from(number).unwrap()
}

/// The workstation's ports: a board on a `CP210x` bridge, and an `ESP32-S3`
/// on its chip's own USB-Serial/JTAG, as Windows names each.
fn ports() -> Vec<SerialPort> {
    vec![
        SerialPort {
            port: port_name("COM5"),
            name: Some(Words::try_from("Silicon Labs CP210x USB to UART Bridge (COM5)").unwrap()),
            usb: Some(Usb {
                vendor: 0x10C4,
                product: 0xEA60,
            }),
        },
        SerialPort {
            port: port_name("COM7"),
            name: Some(Words::try_from("USB JTAG/serial debug unit").unwrap()),
            usb: Some(Usb {
                vendor: 0x303A,
                product: 0x1001,
            }),
        },
    ]
}

fn bench() -> Bench {
    let mut bench = Bench::attached();
    bench.desk.hold_ports(ports());
    bench.feed(Event::Window(true));
    bench
}

fn known(bench: &Bench) -> (Reference, Document) {
    let attached = bench.seen();
    (
        attached
            .catalogue
            .as_ref()
            .expect("the catalogue")
            .reference()
            .clone(),
        attached.document.clone().expect("the document"),
    )
}

fn edit(draft: &mut Draft, bench: &Bench, edit: Edit) {
    let (reference, document) = known(bench);
    draft.edit(edit, &reference, &document);
}

fn typed(key: &str, text: &str) -> Edit {
    Edit::Typed {
        key: key.to_owned(),
        text: text.to_owned(),
    }
}

fn form(draft: &Draft, bench: &Bench) -> Form {
    let document = known(bench).1;
    let attached = bench.seen();
    Form::of(
        draft,
        attached.catalogue.as_ref().expect("the catalogue"),
        &document,
        attached.ports.as_ref(),
        None,
    )
}

fn field<'f>(form: &'f Form, key: &str) -> &'f Field {
    form.fields
        .iter()
        .find(|field| field.key == key)
        .unwrap_or_else(|| unreachable!("no {key} among {:?}", form.fields))
}

fn wish(bench: &mut Bench, request: &Request) {
    assert_eq!(bench.permits(request), Ok(()));
    bench.feed(Event::Wish(Place::Window, common::clone(request)));
    assert_eq!(bench.seen().refused, None);
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

fn window(bench: &Bench) -> Window {
    Window::of(bench.link.seen(), &clock, Instant::now())
}

fn line<'w>(window: &'w Window, remote: &RemoteId, capability: &str) -> &'w Line {
    match &window.board {
        Board::Exposure { groups, .. } => groups
            .iter()
            .flat_map(|group| &group.lines)
            .find(|line| {
                line.remote.as_ref() == Some(remote) && line.capability.as_str() == capability
            })
            .unwrap_or_else(|| unreachable!("{capability}'s line on {remote}")),
        other => unreachable!("{other:?}"),
    }
}

fn serial(capability: &str, at: &str, remote: u16) -> Capability {
    Capability {
        id: name(capability),
        source: Source::Serial {
            port: port_name(at),
            remote: port(remote),
        },
    }
}

/// `capability`, the person's own, granted to `to` on request, its service
/// exposure named.
fn granted(bench: &mut Bench, capability: &Capability, to: &RemoteId) {
    wish(bench, &Request::Change(Change::Define(capability.clone())));
    wish(
        bench,
        &Request::Change(Change::Grant {
            grant: grant(capability.id.as_str(), Granted::One(to.clone())),
            terms: terms(Activation::OnRequest, Exposure::SERVICE),
        }),
    );
}

/// A person defines a capability that lends their board's port: the port is picked
/// from what the workstation lists - by the name Windows shows and the USB
/// device behind it - never typed; a board on its chip's own USB says what a
/// remote's esptool cannot do through it; the remote port typed shows the
/// address the remote's tools open. The core takes it, the window lists it
/// with that address, and changing it keeps its port even once the board is
/// unplugged.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one person's flow from defining to changing it unplugged"
)]
fn a_serial_port_is_picked_from_the_workstations_ports_and_its_address_shown() {
    let mut bench = bench();
    let mut draft = Draft::new(Kind::Capability);
    edit(
        &mut draft,
        &bench,
        Edit::Chose {
            key: "source".to_owned(),
            at: 4,
        },
    );
    assert!(draft.lists_ports());
    let reading = form(&draft, &bench);
    assert_eq!(
        reading
            .fields
            .iter()
            .map(|field| field.key)
            .collect::<Vec<_>>(),
        ["name", "source", "serial-port", "remote-port"]
    );
    assert_eq!(
        field(&reading, "serial-port").notes,
        ["Reading this workstation's serial ports."],
        "nothing is read until a surface shows the ports"
    );
    assert_eq!(bench.seen().ports, None);

    let asked = |bench: &Bench| {
        bench
            .sent
            .iter()
            .filter(|frame| matches!(frame.request, Request::Ports))
            .count()
    };
    bench.feed(Event::Ports);
    bench.feed(Event::Ports);
    assert_eq!(asked(&bench), 1, "read once for what shows it");
    let shown = form(&draft, &bench);
    let picked = field(&shown, "serial-port");
    let Input::Pick { options, chosen } = &picked.input else {
        unreachable!("{:?}", picked.input)
    };
    assert_eq!(
        options
            .iter()
            .map(|option| (option.label.as_str(), option.value.as_str()))
            .collect::<Vec<_>>(),
        [
            (
                "Silicon Labs CP210x USB to UART Bridge (COM5), the USB device 10C4:EA60",
                "COM5"
            ),
            (
                "USB JTAG/serial debug unit (COM7), the USB device 303A:1001",
                "COM7"
            ),
        ]
    );
    assert_eq!(*chosen, None);
    assert_eq!(picked.invalid.as_deref(), Some("Choose the serial port."));
    assert_eq!(picked.again, Some("Look again for serial ports"));

    // The window sends the value picked, as typed.
    edit(&mut draft, &bench, typed("serial-port", "COM7"));
    edit(&mut draft, &bench, typed("remote-port", "4217"));
    edit(&mut draft, &bench, typed("name", "board"));
    let shown = form(&draft, &bench);
    let picked = field(&shown, "serial-port");
    assert!(matches!(
        picked.input,
        Input::Pick {
            chosen: Some(1),
            ..
        }
    ));
    assert_eq!(picked.invalid, None);
    assert_eq!(picked.notes.len(), 1);
    assert!(
        picked.notes[0].starts_with(
            "This board's port is its chip's own USB, which esptool tells from a UART bridge"
        ),
        "{:?}",
        picked.notes
    );
    assert!(
        picked.notes[0].ends_with(
            "What would change it: esptool learning a remote port's USB mode from something \
             other than the identifiers of a port on its own machine."
        ),
        "{:?}",
        picked.notes
    );
    let address = "The remote's esptool, PlatformIO and pyserial tools open it at \
                   rfc2217://127.0.0.1:4217; where Hedwig asks you first, at \
                   rfc2217://127.0.0.1:4217?timeout=<seconds>, the seconds a tool there waits \
                   for your answer, since pyserial gives up after three";
    assert_eq!(field(&shown, "remote-port").notes, [address]);
    let made = serial("board", "COM7", 4217);
    let request = match shown.ready {
        Ok(Shown::Offered {
            act:
                hedwig_view::act::Act::Send(request) | hedwig_view::act::Act::Confirm { request, .. },
            ..
        }) => request,
        other => unreachable!("{other:?}"),
    };
    assert_eq!(request, Request::Change(Change::Define(made.clone())));
    wish(&mut bench, &request);

    let (reference, document) = known(&bench);
    let outside = &bench.seen().catalogue.as_ref().unwrap().definitions;
    let listed = Definitions::of(outside, &reference, &document, None);
    let own = listed
        .own
        .iter()
        .find(|own| own.name == name("board"))
        .unwrap();
    assert_eq!(
        own.says,
        format!("the serial port COM7 on this workstation. {address}")
    );

    // The board unplugged and the ports read again: the port the definition
    // names stays its choice, said to be absent.
    bench.desk.hold_ports(ports().into_iter().take(1).collect());
    bench.feed(Event::Wish(Place::Defining, Request::Ports));
    assert_eq!(asked(&bench), 2, "again when the person asks");
    let changing = Draft::changing(Kind::Capability, &name("board"), &document).unwrap();
    let shown = form(&changing, &bench);
    let Input::Pick { options, chosen } = &field(&shown, "serial-port").input else {
        unreachable!()
    };
    assert_eq!(
        options.last().map(|option| option.label.as_str()),
        Some("COM7, which is not among this workstation's serial ports now")
    );
    assert_eq!(*chosen, Some(1));
    assert_eq!(field(&shown, "serial-port").notes, Vec::<String>::new());
    assert!(matches!(
        shown.ready,
        Ok(Shown::Offered { act: hedwig_view::act::Act::Send(Request::Change(Change::Define(ref again))) | hedwig_view::act::Act::Confirm { request: Request::Change(Change::Define(ref again)), .. }, .. }) if *again == made
    ));

    // No port at all, or none readable: said beneath the field.
    bench.desk.hold_ports(Vec::new());
    bench.feed(Event::Wish(Place::Defining, Request::Ports));
    let fresh = {
        let mut draft = Draft::new(Kind::Capability);
        edit(
            &mut draft,
            &bench,
            Edit::Chose {
                key: "source".to_owned(),
                at: 4,
            },
        );
        draft
    };
    assert_eq!(
        field(&form(&fresh, &bench), "serial-port").notes,
        ["This workstation has no serial port now: plug the board in, then look again."]
    );
    bench.refuse = Some((
        |request| matches!(request, Request::Ports),
        Refusal::NotAttending,
    ));
    bench.feed(Event::Wish(Place::Defining, Request::Ports));
    assert_eq!(
        field(&form(&fresh, &bench), "serial-port").notes,
        [format!(
            "This workstation's serial ports could not be read: {}.",
            Refusal::NotAttending
        )]
    );
    let shown = form(&fresh, &bench);
    assert_eq!(
        field(&shown, "remote-port").invalid.as_deref(),
        Some("\"\" is not a port: a number from 1 to 65535."),
        "a serial capability's remote port is not optional"
    );
}

/// The grant form, where the person looks for what to grant, offers a serial
/// port of their own to define while none is; with one chosen, it says the
/// address the remote's tools open.
#[test]
fn the_grant_form_offers_a_serial_port_and_says_where_the_remote_opens_it() {
    let mut bench = bench();
    let (reference, document) = known(&bench);
    let empty = grant::Form::of(
        &grant::Draft::default(),
        &reference,
        &document,
        None,
        (None, None),
        None,
    );
    assert!(
        empty.defines.iter().any(|(label, draft)| {
            label == "Define a serial port on this workstation, for a board..."
                && draft.lists_ports()
        }),
        "{:?}",
        empty.defines
    );

    wish(
        &mut bench,
        &Request::Change(Change::Define(serial("board", "COM5", 4217))),
    );
    let (reference, document) = known(&bench);
    let mut draft = grant::Draft::default();
    draft.choose_capability(name("board"), &reference, &document);
    let shown = grant::Form::of(&draft, &reference, &document, None, (None, None), None);
    assert!(
        shown
            .opened_at
            .as_deref()
            .is_some_and(|said| said.contains("rfc2217://127.0.0.1:4217;")),
        "{:?}",
        shown.opened_at
    );
    assert!(
        !shown
            .defines
            .iter()
            .any(|(label, _)| label.contains("serial"))
    );
    assert_eq!(shown.lending, None, "a serial port lends no device");
}

/// A person's esptool on the workspace holds the board: the line says which port is
/// held and since when, and the icon's menu that it is held; served without
/// asking, the line gives the remote's address as it ships, and once they
/// have Hedwig ask first, the address with how long a tool waits for them.
#[test]
fn a_held_port_is_on_its_line_and_in_the_menu_and_its_address_follows_the_mode() {
    let mut bench = bench();
    granted(&mut bench, &serial("board", "COM5", 4217), &workspace());
    let connection = bench.desk.channel_up(&workspace(), "linux");
    let (request, verdict) = bench.desk.asks(connection, "board", Operation::Connect);
    assert!(matches!(verdict, Verdict::Serve(_)), "{verdict:?}");
    bench.desk.trail.push(Happened::Taken {
        request,
        connection,
        capability: name("board"),
        port: port_name("COM5"),
        usb: Some(Usb {
            vendor: 0x10C4,
            product: 0xEA60,
        }),
    });
    refresh(&mut bench);
    let shown = window(&bench);
    let board = line(&shown, &workspace(), "board");
    let since = clock(
        bench.rows()[0]
            .hold
            .as_ref()
            .map_or(Timestamp(0), |hold| hold.since),
    );
    assert_eq!(
        board.hold.as_deref(),
        Some(
            format!(
                "COM5 is held for a connection from {} since {since}: no other program on this \
                 workstation, and no other connection, can open it until that one ends",
                workspace()
            )
            .as_str()
        )
    );
    assert_eq!(
        board.beyond,
        Vec::<String>::new(),
        "a bridge resets as locally"
    );
    assert_eq!(
        board.opened_at.as_deref(),
        Some(
            "The remote's esptool, PlatformIO and pyserial tools open it at \
             rfc2217://127.0.0.1:4217"
        )
    );
    let menu = glance::menu(bench.link.seen(), Instant::now());
    let said: Vec<&str> = menu
        .iter()
        .flat_map(|entry| match entry {
            Row::Group { entries, .. } => entries.iter().collect(),
            other => vec![other],
        })
        .filter_map(|entry| match entry {
            Row::Line(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        said.contains(&"board: COM5 is held for this remote's connection"),
        "{said:?}"
    );

    wish(
        &mut bench,
        &Request::Change(Change::Rule {
            scope: RuleScope {
                remotes: Remotes::One(workspace()),
                capability: Selector::Only(name("board")),
                operation: Selector::Only(Operation::Connect),
                key: hedwig_model::policy::Keys::Every,
            },
            mode: Mode::Confirm,
        }),
    );
    refresh(&mut bench);
    assert_eq!(
        line(&window(&bench), &workspace(), "board")
            .opened_at
            .as_deref(),
        Some(
            "Hedwig asks you first here, so the remote's tools open it at \
             rfc2217://127.0.0.1:4217?timeout=<seconds>, the seconds they wait for your answer: \
             pyserial gives up after three as it ships"
        )
    );

    // Given back, the line holds nothing.
    bench.desk.trail.push(Happened::Released { request });
    refresh(&mut bench);
    assert_eq!(line(&window(&bench), &workspace(), "board").hold, None);
}

/// A second remote's connection to the port another holds is refused naming
/// the holder, which its line says as how its last request ended; a port
/// last opened over a chip's own USB carries that limit on each line naming
/// it, in the model's words with what would change it.
#[test]
fn a_port_held_elsewhere_refuses_and_a_chips_own_usb_is_said_on_the_line() {
    let mut bench = bench();
    granted(&mut bench, &serial("board", "COM7", 4217), &workspace());
    wish(
        &mut bench,
        &Request::Change(Change::Grant {
            grant: grant("board", Granted::One(lab())),
            terms: terms(Activation::OnRequest, Exposure::SERVICE),
        }),
    );
    let first = bench.desk.channel_up(&workspace(), "linux");
    let (request, _) = bench.desk.asks(first, "board", Operation::Connect);
    bench.desk.trail.push(Happened::Taken {
        request,
        connection: first,
        capability: name("board"),
        port: port_name("COM7"),
        usb: Some(Usb {
            vendor: 0x303A,
            product: 0x1001,
        }),
    });
    let second = bench.desk.channel_up(&lab(), "linux");
    let (_, verdict) = bench.desk.asks(second, "board", Operation::Connect);
    assert_eq!(
        verdict,
        Verdict::Refuse(Refusal::PortHeld {
            capability: name("board"),
            by: workspace(),
        })
    );
    refresh(&mut bench);
    let shown = window(&bench);
    let held = line(&shown, &lab(), "board");
    assert!(
        held.last
            .as_deref()
            .is_some_and(|last| last.ends_with(&format!(
                "refused: {}",
                Refusal::PortHeld {
                    capability: name("board"),
                    by: workspace(),
                }
            ))),
        "{:?}",
        held.last
    );
    assert_eq!(held.hold, None, "the lab's connection holds nothing");
    for remote in [workspace(), lab()] {
        let beyond = &line(&shown, &remote, "board").beyond;
        assert_eq!(beyond.len(), 1, "{remote}: {beyond:?}");
        assert!(beyond[0].starts_with("This board's port is its chip's own USB"));
    }
}

/// Two serial capabilities granted to one remote at one remote port: neither
/// is carried, and each line says so naming the other, in the model's words.
/// A port that is unplugged or that another program holds stands on its line.
#[test]
fn two_capabilities_at_one_remote_port_and_a_failing_port_are_said_on_the_line() {
    let mut bench = bench();
    granted(&mut bench, &serial("board", "COM5", 4217), &workspace());
    granted(&mut bench, &serial("probe", "COM7", 4217), &workspace());
    bench.desk.channel_up(&workspace(), "linux");
    refresh(&mut bench);
    let shown = window(&bench);
    assert_eq!(
        line(&shown, &workspace(), "board").state,
        "cannot be served: board and probe both take port 4217 on the remote, so neither is \
         carried; give one of them another remote port"
    );
    assert_eq!(
        line(&shown, &workspace(), "probe").state,
        "cannot be served: probe and board both take port 4217 on the remote, so neither is \
         carried; give one of them another remote port"
    );

    for (failure, said) in [
        (
            Failure::Absent,
            "board names a serial port that is not among this workstation's serial ports now; \
             the board may be unplugged",
        ),
        (
            Failure::Busy,
            "board names a serial port that another program on this workstation has open",
        ),
    ] {
        let mut bench = self::bench();
        granted(&mut bench, &serial("board", "COM5", 4217), &workspace());
        bench.desk.channel_up(&workspace(), "linux");
        bench.desk.trail.push(Happened::Source {
            capability: name("board"),
            health: Health::Failing(failure),
        });
        refresh(&mut bench);
        assert_eq!(
            line(&window(&bench), &workspace(), "board").state,
            format!("cannot be served: {said}")
        );
    }
}

/// A person reads which board a remote held and when: the port opened for a
/// connection, over which USB device, and closed when it ended, each in the
/// remote's activity; a closing whose opening is on an earlier page still
/// says what it was.
#[test]
fn a_port_taken_and_given_back_reads_in_the_remotes_activity() {
    let request = RequestId(Seq(1));
    let at = |seq: u64, event| Entry {
        seq: Seq(seq),
        at: Timestamp(seq),
        tick: Tick(seq),
        event,
    };
    let taken = |usb| Happened::Taken {
        request,
        connection: ConnectionId(Seq(1)),
        capability: name("board"),
        port: port_name("COM7"),
        usb,
    };
    let said = |entries: &[Entry]| -> Vec<String> {
        exposure::activity(entries, &clock, Keyrings::default())
            .into_iter()
            .map(|(_, said)| said)
            .collect()
    };
    let both = said(&[
        at(
            2,
            taken(Some(Usb {
                vendor: 0x303A,
                product: 0x1001,
            })),
        ),
        at(3, Happened::Released { request }),
    ]);
    assert_eq!(
        both,
        [
            format!(
                "{}: board closed COM7: its connection ended, and the port is free again",
                clock(Timestamp(3))
            ),
            format!(
                "{}: board opened COM7, over the USB device 303A:1001, for that connection alone",
                clock(Timestamp(2))
            ),
        ]
    );
    assert_eq!(
        said(&[at(2, taken(None))]),
        [format!(
            "{}: board opened COM7 for that connection alone",
            clock(Timestamp(2))
        )]
    );
    assert_eq!(
        said(&[at(3, Happened::Released { request })]),
        [format!(
            "{}: a serial port held for a request asked earlier was closed: its connection \
             ended, and the port is free again",
            clock(Timestamp(3))
        )]
    );
}

/// What no definition can give a remote's tool is listed where the person
/// defines, each with why and what would change it; a shipped preset whose
/// port only a program chooses says so beside its name, and again where it is
/// chosen to grant.
#[test]
fn what_no_definition_can_give_is_listed_where_the_person_defines() {
    let bench = bench();
    let (reference, document) = known(&bench);
    let outside = &bench.seen().catalogue.as_ref().unwrap().definitions;
    let listed = Definitions::of(outside, &reference, &document, None);
    assert_eq!(listed.beyond.len(), 3);
    assert!(listed.beyond[0].starts_with("An iPhone or iPad at this workstation cannot be lent"));
    assert!(
        listed.beyond[0].ends_with(
            "What would change it: Xcode on a macOS remote reading a device through anything \
             but its own /var/run/usbmuxd; or Apple's usbmuxd giving a client a device without \
             the workstation's pairing record; or a documented, unprivileged way to point a \
             macOS remote's device services at another host."
        ),
        "{}",
        listed.beyond[0]
    );
    let capabilities = &listed
        .outside
        .iter()
        .find(|(kind, _)| *kind == Kind::Capability)
        .unwrap()
        .1;
    let playwright = capabilities
        .iter()
        .find(|known| known.name.as_str() == "playwright")
        .unwrap();
    let per_run = playwright.beyond.as_deref().unwrap();
    assert!(
        per_run.starts_with("A program that chooses its debug port each run cannot be carried")
    );
    assert!(
        capabilities
            .iter()
            .filter(|known| known.name.as_str() != "playwright")
            .all(|known| known.beyond.is_none() || known.beyond.as_deref() == Some(per_run)),
        "only a preset whose port is unstated carries it"
    );
    let mut draft = grant::Draft::default();
    draft.choose_capability(name("playwright"), &reference, &document);
    let shown = grant::Form::of(&draft, &reference, &document, None, (None, None), None);
    assert_eq!(shown.beyond.as_deref(), Some(per_run));
    draft.choose_capability(name("gpg"), &reference, &document);
    let shown = grant::Form::of(&draft, &reference, &document, None, (None, None), None);
    assert_eq!(shown.beyond, None);
}

/// A person plugs a board in while the define form lists the workstation's ports:
/// it appears with nothing pressed, read again because the core said the
/// ports changed; unplugged, it goes the same way; the same ports again
/// tell nothing.
#[test]
fn the_ports_shown_follow_the_workstation_without_the_person_asking() {
    let mut bench = Bench::attached();
    bench.desk.hold_ports(ports().into_iter().take(1).collect());
    bench.feed(Event::Ports);
    let asked = |bench: &Bench| {
        bench
            .sent
            .iter()
            .filter(|frame| matches!(frame.request, Request::Ports))
            .count()
    };
    let listed = |bench: &Bench| match &bench.seen().ports {
        Some(Some(Ok(listed))) => listed.len(),
        other => unreachable!("{other:?}"),
    };
    assert_eq!((asked(&bench), listed(&bench)), (1, 1));

    let told = bench.desk.hold_ports(ports());
    assert_eq!(bench.hear(told), 1);
    assert_eq!((asked(&bench), listed(&bench)), (2, 2));

    let told = bench.desk.hold_ports(ports());
    assert_eq!(bench.hear(told), 0);
    assert_eq!(asked(&bench), 2);

    let told = bench.desk.hold_ports(Vec::new());
    assert_eq!(bench.hear(told), 1);
    assert_eq!((asked(&bench), listed(&bench)), (3, 0));
}
