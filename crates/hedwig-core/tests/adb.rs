//! The ADB conversation against a recorded exchange and against what the
//! server's own reader does with every request a remote can send.
//!
//! `data/adb-36.0.0-exchange.txt` is what passed between platform-tools
//! 36.0.0's `adb` and its own server, with an Android 16 emulator as the
//! device, recorded by `child tap`: `devices`, `shell
//! echo hedwig`, `reverse tcp:8081 tcp:8081`, `reverse --list`, `reverse
//! --remove-all`, `forward --list` and a device that is not there. The
//! recorded device is `127.0.0.1:15555`, transport id 1.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests over a fixed recording"
)]

use std::collections::BTreeMap;

use hedwig_core::adb::{
    Breach, Carried, Conversation, Forward, HELD, Kind, Lending, Out, Side, fail, framed,
    host_service, kind, local_forward, reason, remote_forward, target,
};
use hedwig_core::devices::{Device, Listing, State, View};
use hedwig_model::capability::Lends;
use hedwig_model::refusal::Withheld;
use hedwig_model::text::{DeviceSerial, DeviceSocket, Host, Port, RemotePath};
use hedwig_model::trail::Target;

/// One read of the recording.
#[derive(Debug, Clone)]
enum Read {
    Client(Vec<u8>),
    Server(Vec<u8>),
    ServerEnd,
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// The recording, connection by connection, each read in order.
fn recorded() -> BTreeMap<usize, Vec<Read>> {
    let text = include_str!("data/adb-36.0.0-exchange.txt");
    let mut connections: BTreeMap<usize, Vec<Read>> = BTreeMap::new();
    for line in text.lines() {
        let mut words = line.split(' ');
        let number: usize = words.next().unwrap().parse().unwrap();
        let way = words.next().unwrap();
        let bytes = words.next().unwrap();
        let read = match (way, bytes) {
            (">", "end") => continue,
            ("<", "end") => Read::ServerEnd,
            (">", bytes) => Read::Client(unhex(bytes)),
            ("<", bytes) => Read::Server(unhex(bytes)),
            _ => panic!("{line}"),
        };
        connections.entry(number).or_default().push(read);
    }
    connections
}

fn port(number: u16) -> Port {
    Port::try_from(number).unwrap()
}

fn serial(text: &str) -> DeviceSerial {
    DeviceSerial::try_from(text).unwrap()
}

fn device(name: &str, usb: bool, id: u64) -> Device {
    Device {
        serial: name.to_owned(),
        state: State::DEVICE,
        usb,
        devpath: String::new(),
        product: String::new(),
        model: String::new(),
        device: String::new(),
        id,
    }
}

const RECORDED: &str = "127.0.0.1:15555";

/// The recorded device, as the server's listing gives it.
fn recorded_view() -> View {
    View {
        devices: vec![device(RECORDED, false, 1)],
        listing: Listing::Read,
        holder: None,
    }
}

fn view(devices: Vec<Device>) -> View {
    View {
        devices,
        listing: Listing::Read,
        holder: None,
    }
}

fn lent(serials: &[&str]) -> Lending {
    Lending {
        lends: Lends::devices(serials.iter().map(|text| serial(text))),
        network: false,
    }
}

fn every() -> Lending {
    Lending {
        lends: Lends::Every,
        network: false,
    }
}

fn networked(mut lending: Lending) -> Lending {
    lending.network = true;
    lending
}

fn opened(lending: Lending) -> Conversation {
    Conversation::opened(Carried::default(), lending)
}

/// What each end received from the relay.
#[derive(Debug, Default, PartialEq, Eq)]
struct Got {
    server: Vec<u8>,
    client: Vec<u8>,
    asked: Vec<Out>,
}

/// Feeds a connection's reads to a conversation as the relay does: the
/// server's bytes go straight to the client once the stream is spliced, and
/// a request held for a fresh view is given the same view again.
fn relay(reads: &[Read], carried: Carried, lending: Lending, seen: &View) -> (Got, Conversation) {
    let mut talk = Conversation::opened(carried, lending);
    let mut got = Got::default();
    let mut spliced = false;
    for read in reads {
        let outs = match read {
            Read::Client(bytes) if spliced => vec![Out::ToServer(bytes.clone())],
            Read::Client(bytes) => talk.from_client(bytes, seen).unwrap(),
            Read::Server(bytes) if spliced => {
                got.client.extend_from_slice(bytes);
                Vec::new()
            }
            Read::Server(bytes) => talk.from_server(bytes, seen).unwrap(),
            Read::ServerEnd if spliced => Vec::new(),
            Read::ServerEnd => talk.server_closed(seen).unwrap(),
        };
        take(&mut got, &mut spliced, &mut talk, seen, outs);
    }
    (got, talk)
}

fn take(got: &mut Got, spliced: &mut bool, talk: &mut Conversation, seen: &View, outs: Vec<Out>) {
    for out in outs {
        match out {
            Out::ToServer(bytes) => got.server.extend(bytes),
            Out::ToClient(bytes) => got.client.extend(bytes),
            Out::Splice => *spliced = true,
            Out::Stale => {
                let again = talk.viewed(seen);
                take(got, spliced, talk, seen, again);
            }
            other => got.asked.push(other),
        }
    }
}

fn sent(reads: &[Read]) -> (Vec<u8>, Vec<u8>) {
    let mut client = Vec::new();
    let mut server = Vec::new();
    for read in reads {
        match read {
            Read::Client(bytes) => client.extend_from_slice(bytes),
            Read::Server(bytes) => server.extend_from_slice(bytes),
            Read::ServerEnd => {}
        }
    }
    (client, server)
}

fn okay(text: &[u8]) -> Vec<u8> {
    let mut answer = b"OKAY".to_vec();
    answer.extend(framed(text));
    answer
}

/// Every connection of the recording that selects no device reaches each end
/// byte for byte, whatever is lent: what the client sent is what the server
/// got, and what the server sent is what the client got.
#[test]
fn a_recorded_session_that_selects_nothing_is_carried_byte_for_byte_both_ways() {
    let connections = recorded();
    for lending in [every(), lent(&[RECORDED]), lent(&[])] {
        for number in [0, 2, 5, 8, 10, 12, 14] {
            let reads = &connections[&number];
            let (got, _) = relay(reads, Carried::default(), lending.clone(), &recorded_view());
            let (client, server) = sent(reads);
            assert_eq!(got.server, client, "connection {number}, to the server");
            assert_eq!(got.client, server, "connection {number}, to the client");
            assert!(got.asked.is_empty(), "connection {number}: {:?}", got.asked);
        }
    }
    // The recorded listing, of the one device lent, reaches the client as it
    // was sent.
    let reads = &connections[&1];
    let (got, _) = relay(
        reads,
        Carried::default(),
        lent(&[RECORDED]),
        &recorded_view(),
    );
    assert_eq!(got.client, sent(reads).1);
}

/// What selects a device is sent naming the device it resolved to among
/// those lent by its transport id, which the server cannot take for another;
/// the answer reaches the client as the server gave it.
#[test]
fn a_selection_is_sent_naming_the_lent_device_by_its_transport_id() {
    let connections = recorded();
    let reads = &connections[&3];
    let (got, _) = relay(
        reads,
        Carried::default(),
        lent(&[RECORDED]),
        &recorded_view(),
    );
    assert_eq!(got.server, framed(b"host-transport-id:1:features"));
    assert_eq!(got.client, sent(reads).1);

    let reads = &connections[&4];
    let (got, talk) = relay(
        reads,
        Carried::default(),
        lent(&[RECORDED]),
        &recorded_view(),
    );
    let mut server = framed(b"host-transport-id:1:tport:any");
    let Read::Client(shell) = &reads[3] else {
        panic!()
    };
    server.extend(shell);
    assert_eq!(got.server, server);
    assert_eq!(got.client, sent(reads).1);
    assert_eq!(got.asked, vec![Out::Selected(serial(RECORDED))]);
    assert!(talk.spliced());

    // A legacy switch names the id in its own form.
    let mut talk = opened(lent(&[RECORDED]));
    assert_eq!(
        talk.from_client(&framed(b"host:transport:127.0.0.1:15555"), &recorded_view())
            .unwrap(),
        vec![Out::ToServer(framed(b"host:transport-id:1"))]
    );
}

/// Of two devices the server holds, the one device a remote names
/// nothing for is the one lent; one not lent is not there, in ADB's own
/// words, with the device it reached for recorded; nothing reaches the
/// server for it.
#[test]
fn the_one_device_is_the_one_lent_and_a_device_not_lent_is_not_there() {
    let held = view(vec![
        device("R5CT1234ABC", true, 1),
        device("TESTDEVICE01", true, 2),
    ]);
    let lending = lent(&["TESTDEVICE01"]);
    let mut talk = opened(lending.clone());
    assert_eq!(
        talk.from_client(&framed(b"host:tport:any"), &held).unwrap(),
        vec![Out::ToServer(framed(b"host-transport-id:2:tport:any"))]
    );
    let reads = [Read::Client(framed(b"host:tport:serial:R5CT1234ABC"))];
    let (got, talk) = relay(&reads, Carried::default(), lending.clone(), &held);
    assert_eq!(got.server, Vec::<u8>::new());
    assert_eq!(got.client, fail("device 'R5CT1234ABC' not found"));
    assert_eq!(
        got.asked,
        vec![Out::Withheld(Withheld::Unlent(Some(serial("R5CT1234ABC"))))]
    );
    assert!(!talk.open());
    // By transport id, by `-s` of any prefix, and the device's model.
    for request in [
        &b"host-transport-id:1:get-state"[..],
        b"host-serial:R5CT1234ABC:features",
        b"host:transport-id:1",
    ] {
        let (got, _) = relay(
            &[Read::Client(framed(request))],
            Carried::default(),
            lending.clone(),
            &held,
        );
        assert!(
            got.server.is_empty(),
            "{}",
            String::from_utf8_lossy(request)
        );
        assert_eq!(
            got.asked,
            vec![Out::Withheld(Withheld::Unlent(Some(serial("R5CT1234ABC"))))]
        );
    }
    // Nothing lent: the one device is none, and that the remote reached for
    // one is recorded.
    let (got, _) = relay(
        &[Read::Client(framed(b"host:tport:any"))],
        Carried::default(),
        lent(&[]),
        &held,
    );
    assert_eq!(got.client, fail("no devices/emulators found"));
    assert_eq!(got.asked, vec![Out::Withheld(Withheld::Unlent(None))]);
    // A device nobody holds is the server's own miss, and no refusal.
    let connections = recorded();
    let (got, _) = relay(
        &connections[&15],
        Carried::default(),
        every(),
        &recorded_view(),
    );
    assert_eq!(got.server, Vec::<u8>::new());
    assert_eq!(got.client, fail("device 'nosuch' not found"));
    assert_eq!(got.asked, Vec::<Out>::new());
}

/// A miss is decided once more against the server's devices read afresh,
/// so a device the server has just attached is found.
#[test]
fn a_miss_is_decided_again_against_a_fresh_view() {
    let mut talk = opened(every());
    assert_eq!(
        talk.from_client(
            &framed(b"host:tport:serial:emulator-5554"),
            &view(Vec::new())
        )
        .unwrap(),
        vec![Out::Stale]
    );
    let fresh = view(vec![device("emulator-5554", false, 7)]);
    assert_eq!(
        talk.viewed(&fresh),
        vec![Out::ToServer(framed(b"host-transport-id:7:tport:any"))]
    );
}

/// A device that leaves between the view and the server's answer is told in
/// the words the server would have used for what the remote asked.
#[test]
fn a_device_gone_meanwhile_is_told_in_the_words_for_what_was_asked() {
    let mut talk = opened(every());
    talk.from_client(
        &framed(b"host:tport:serial:127.0.0.1:15555"),
        &recorded_view(),
    )
    .unwrap();
    let gone = fail("no device with transport id '1'");
    assert_eq!(
        talk.from_server(&gone, &recorded_view()).unwrap(),
        vec![Out::ToClient(fail("device '127.0.0.1:15555' not found"))]
    );
    let mut talk = opened(every());
    talk.from_client(&framed(b"host:get-state"), &recorded_view())
        .unwrap();
    talk.from_server(&gone, &recorded_view()).unwrap();
    assert_eq!(
        talk.server_closed(&recorded_view()).unwrap(),
        vec![Out::ToClient(fail("no devices/emulators found"))]
    );
    // `reconnect` answers a device not there with `OKAY`, as the server does.
    let (got, _) = relay(
        &[Read::Client(framed(b"host:reconnect"))],
        Carried::default(),
        lent(&[]),
        &View {
            devices: Vec::new(),
            listing: Listing::Read,
            holder: None,
        },
    );
    assert_eq!(got.client, okay(b"no devices/emulators found"));
}

/// A listing, once and as a tracker sends it on every change, holds the
/// devices lent and no other; a change to what the grant lends writes the
/// tracker's last listing again as the grant now has it.
#[test]
fn a_listing_and_a_tracker_hold_the_devices_lent() {
    let held = view(vec![
        device("R5CT1234ABC", true, 1),
        device("TESTDEVICE01", true, 2),
    ]);
    let both = b"R5CT1234ABC\tdevice\nTESTDEVICE01\tdevice\n";
    let reads = [
        Read::Client(framed(b"host:devices")),
        Read::Server(b"OKAY".to_vec()),
        Read::Server(framed(both)),
        Read::ServerEnd,
    ];
    let (got, _) = relay(&reads, Carried::default(), lent(&["TESTDEVICE01"]), &held);
    assert_eq!(got.server, framed(b"host:devices"));
    assert_eq!(got.client, okay(b"TESTDEVICE01\tdevice\n"));

    let mut talk = opened(lent(&["TESTDEVICE01"]));
    talk.from_client(&framed(b"host:track-devices"), &held)
        .unwrap();
    let mut first = b"OKAY".to_vec();
    first.extend(framed(both));
    assert_eq!(
        talk.from_server(&first, &held).unwrap(),
        vec![
            Out::ToClient(b"OKAY".to_vec()),
            Out::ToClient(framed(b"TESTDEVICE01\tdevice\n"))
        ]
    );
    let second = framed(b"R5CT1234ABC\tdevice\nTESTDEVICE01\toffline\n");
    assert_eq!(
        talk.from_server(&second[..5], &held).unwrap(),
        Vec::<Out>::new()
    );
    assert_eq!(
        talk.from_server(&second[5..], &held).unwrap(),
        vec![Out::ToClient(framed(b"TESTDEVICE01\toffline\n"))]
    );
    assert_eq!(
        talk.relent(lent(&["R5CT1234ABC", "TESTDEVICE01"]), &held),
        vec![Out::ToClient(framed(
            b"R5CT1234ABC\tdevice\nTESTDEVICE01\toffline\n"
        ))]
    );
    assert!(!talk.lists_by_id());
}

/// A connection using a device the grant no longer lends ends.
#[test]
fn a_connection_on_a_device_no_longer_lent_ends() {
    let connections = recorded();
    let reads = &connections[&4];
    let (_, mut talk) = relay(
        reads,
        Carried::default(),
        lent(&[RECORDED]),
        &recorded_view(),
    );
    assert!(talk.open());
    assert_eq!(talk.relent(lent(&[]), &recorded_view()), Vec::<Out>::new());
    assert!(!talk.open());
}

fn refused(request: &[u8], withheld: Withheld, lending: Lending) {
    let mut talk = opened(lending);
    let outs = talk
        .from_client(&framed(request), &recorded_view())
        .unwrap();
    assert_eq!(
        outs,
        vec![
            Out::ToClient(fail(reason(&withheld))),
            Out::Withheld(withheld)
        ],
        "{}",
        String::from_utf8_lossy(request)
    );
    assert!(!talk.open());
}

/// `kill` under every prefix the server reads ends the server, so each is
/// refused, and refused in ADB's own words for a server that rejects it.
#[test]
fn kill_is_refused_under_every_prefix_in_adbs_own_words() {
    for request in [
        &b"host:kill"[..],
        b"host-usb:kill",
        b"host-local:kill",
        b"host-serial:emulator-5554:kill",
        b"host-serial:tcp:127.0.0.1:5555:kill",
        b"host-serial:[::1]:5555:kill",
        b"host-transport-id:1:kill",
        b"host-transport-id:+1:kill",
    ] {
        refused(request, Withheld::Ending, every());
    }
    assert_eq!(
        fail(reason(&Withheld::Ending)),
        b"FAIL0025kill-server rejected by remote server".to_vec()
    );
    // Not the service `kill`, which the server does not end on; a request
    // Hedwig does not know is refused rather than passed.
    assert_eq!(kind(b"host:kill\0x", 11), Kind::Withheld(Withheld::Unknown));
}

/// After a switch the server reads the next request with every prefix
/// again, so `kill` after `host:transport` is still refused.
#[test]
fn kill_after_a_switch_is_still_refused() {
    let mut talk = opened(every());
    talk.from_client(&framed(b"host:transport-any"), &recorded_view())
        .unwrap();
    assert_eq!(
        talk.from_server(b"OKAY", &recorded_view()).unwrap(),
        vec![
            Out::ToClient(b"OKAY".to_vec()),
            Out::Selected(serial(RECORDED))
        ]
    );
    let outs = talk
        .from_client(&framed(b"host:kill"), &recorded_view())
        .unwrap();
    assert_eq!(outs.last(), Some(&Out::Withheld(Withheld::Ending)));
}

/// What acts on every device is refused whatever the grant;
/// what has the server reach the workstation's network is refused unless the
/// grant acknowledges `network`; an emulator's own request always.
#[test]
fn what_acts_on_every_device_or_reaches_the_network_unacknowledged_is_refused() {
    for lending in [every(), networked(every())] {
        for request in [&b"host:disconnect:"[..], b"host:reconnect-offline"] {
            refused(request, Withheld::Every, lending.clone());
        }
        refused(b"host:emulator:5600", Withheld::Reaching, lending);
    }
    for request in [
        &b"host:connect:192.168.1.20:5555"[..],
        b"host:pair:123456:192.168.1.20:37000",
        b"host:disconnect:192.168.1.20:5555",
        b"host:mdns:check",
        b"host:mdns:services",
        b"host:track-mdns-services",
        b"host:list-mdns-known-hosts",
    ] {
        refused(request, Withheld::Unacknowledged, every());
    }
}

/// Under `network`, a remote attaches a device by its address only
/// where the device it attaches is lent, pairs, and lists what the network
/// offers; it removes a device by its address only where that device is
/// lent, by its serial; a device not lent is not there to it.
#[test]
fn under_network_a_remote_attaches_and_removes_only_lent_devices() {
    let phone = "192.168.1.20:5555";
    let lending = networked(lent(&[phone, "emulator-5700"]));
    let passes = |request: &[u8], seen: &View| {
        let mut talk = opened(lending.clone());
        let outs = talk.from_client(&framed(request), seen).unwrap();
        assert_eq!(
            outs,
            vec![Out::Splice, Out::ToServer(framed(request))],
            "{}",
            String::from_utf8_lossy(request)
        );
    };
    passes(b"host:connect:192.168.1.20:5555", &recorded_view());
    passes(b"host:connect:192.168.1.20", &recorded_view());
    passes(b"host:connect:emu:5700,5701", &recorded_view());
    passes(b"host:pair:123456:192.168.1.20:37000", &recorded_view());
    passes(b"host:mdns:services", &recorded_view());
    // What the server would refuse to parse it is left to refuse.
    passes(b"host:connect::123", &recorded_view());
    let mut talk = opened(lending.clone());
    assert_eq!(
        talk.from_client(&framed(b"host:connect:10.0.0.9:5555"), &recorded_view())
            .unwrap(),
        vec![
            Out::ToClient(fail(
                "Hedwig attaches only a device lent to this remote, not 10.0.0.9:5555"
            )),
            Out::Withheld(Withheld::Unlent(Some(serial("10.0.0.9:5555"))))
        ]
    );
    let held = view(vec![
        device(phone, false, 4),
        device("10.0.0.9:5555", false, 5),
    ]);
    let mut talk = opened(lending.clone());
    assert_eq!(
        talk.from_client(&framed(b"host:disconnect:192.168.1.20"), &held)
            .unwrap(),
        vec![
            Out::Splice,
            Out::ToServer(framed(b"host:disconnect:192.168.1.20:5555"))
        ]
    );
    passes(b"host:disconnect:192.168.1.20:5555", &held);
    let mut talk = opened(lending.clone());
    assert_eq!(
        talk.from_client(&framed(b"host:disconnect:10.0.0.9"), &held)
            .unwrap(),
        vec![
            Out::ToClient(fail("no such device '10.0.0.9:5555'")),
            Out::Withheld(Withheld::Unlent(Some(serial("10.0.0.9:5555"))))
        ]
    );
    let (got, _) = relay(
        &[Read::Client(framed(b"host:disconnect:192.168.9.9"))],
        Carried::default(),
        lending.clone(),
        &held,
    );
    assert_eq!(got.client, fail("no such device '192.168.9.9:5555'"));
    let (got, _) = relay(
        &[Read::Client(framed(b"host:disconnect:[::1"))],
        Carried::default(),
        lending,
        &held,
    );
    assert_eq!(
        got.client,
        fail("couldn't parse '[::1': bad IPv6 address '[::1'")
    );
}

/// What cannot be judged is refused: a request for the server Hedwig does
/// not know, and any selection where the server's devices could not be
/// read; what touches no device passes, the server's status without the
/// workstation's own paths.
#[test]
fn what_cannot_be_judged_is_refused_and_what_touches_no_device_passes() {
    refused(b"host:wipe-everything", Withheld::Unknown, every());
    let mut talk = opened(every());
    let unlisted = View::default();
    assert_eq!(
        talk.from_client(&framed(b"host:tport:any"), &unlisted)
            .unwrap(),
        vec![
            Out::ToClient(fail(reason(&Withheld::Unlisted))),
            Out::Withheld(Withheld::Unlisted)
        ]
    );
    // A server older than platform-tools 35.0.0 is named as the cause.
    let mut talk = opened(every());
    let outdated = View {
        devices: Vec::new(),
        listing: Listing::Failed(hedwig_model::trail::Failure::Outdated),
        holder: None,
    };
    assert_eq!(
        talk.from_client(&framed(b"host:tport:any"), &outdated)
            .unwrap(),
        vec![
            Out::ToClient(fail(reason(&Withheld::Outdated))),
            Out::Withheld(Withheld::Outdated)
        ]
    );
    assert!(reason(&Withheld::Outdated).contains("platform-tools 35.0.0 or later"));
    for request in [&b"host:version"[..], b"host:host-features"] {
        let mut talk = opened(lent(&[]));
        assert_eq!(
            talk.from_client(&framed(request), &unlisted).unwrap(),
            vec![Out::Splice, Out::ToServer(framed(request))]
        );
    }

    // `AdbServerStatus` as platform-tools 37.0.1 fills it: 5 version, 7 the
    // executable, 8 the log, 9 the system, 13 the key store, 14 the known
    // hosts.
    let field = |number: u8, text: &[u8]| -> Vec<u8> {
        [
            &[number << 3 | 2, u8::try_from(text.len()).unwrap()][..],
            text,
        ]
        .concat()
    };
    let status = [
        field(5, b"37.0.1-14725123"),
        field(7, br"C:\Users\person\platform-tools\adb.exe"),
        field(8, br"C:\Users\person\AppData\Local\Temp\adb.log"),
        field(9, b"Windows 11 (26200)"),
        field(13, br"C:\Users\person\.android\adbkey"),
        field(14, br"C:\Users\person\.android\adb_known_hosts.pb"),
    ]
    .concat();
    let kept = [
        field(5, b"37.0.1-14725123"),
        field(9, b"Windows 11 (26200)"),
    ]
    .concat();
    for request in [
        &b"host:server-status"[..],
        b"host-serial:R58M1234:server-status",
    ] {
        let mut talk = opened(lent(&[]));
        assert_eq!(
            talk.from_client(&framed(request), &unlisted).unwrap(),
            vec![Out::ToServer(framed(b"host:server-status"))]
        );
        let answer = [&b"OKAY"[..], &framed(&status)].concat();
        assert_eq!(talk.from_server(&answer, &unlisted).unwrap(), Vec::new());
        assert_eq!(
            talk.server_closed(&unlisted).unwrap(),
            vec![Out::ToClient([&b"OKAY"[..], &framed(&kept)].concat())]
        );
    }
    let mut talk = opened(lent(&[]));
    talk.from_client(&framed(b"host:server-status"), &unlisted)
        .unwrap();
    talk.from_server(&fail("closed"), &unlisted).unwrap();
    assert_eq!(
        talk.server_closed(&unlisted).unwrap(),
        vec![Out::ToClient(fail("closed"))]
    );
}

/// A wait for a device waits among those lent: answered by the server for
/// the one lent device once there is one, here at once where it waits for one
/// to go and none is there, refused where several answer.
#[test]
fn a_wait_for_a_device_waits_among_those_lent() {
    let nothing = view(Vec::new());
    let mut talk = opened(lent(&["emulator-5554"]));
    assert_eq!(
        talk.from_client(&framed(b"host:wait-for-any-device"), &nothing)
            .unwrap(),
        vec![Out::Await]
    );
    assert_eq!(
        talk.viewed(&view(vec![device("R5CT1234ABC", true, 1)])),
        vec![Out::Await]
    );
    assert_eq!(
        talk.viewed(&view(vec![device("emulator-5554", false, 3)])),
        vec![
            Out::Splice,
            Out::ToServer(framed(b"host-transport-id:3:wait-for-any-device"))
        ]
    );
    let mut talk = opened(lent(&["emulator-5554"]));
    assert_eq!(
        talk.from_client(&framed(b"host:wait-for-any-disconnect"), &nothing)
            .unwrap(),
        vec![Out::ToClient(b"OKAYOKAY".to_vec())]
    );
    let two = view(vec![
        device("emulator-5554", false, 3),
        device("emulator-5556", false, 4),
    ]);
    let mut talk = opened(every());
    assert_eq!(
        talk.from_client(&framed(b"host:wait-for-local-device"), &two)
            .unwrap(),
        vec![Out::ToClient(fail("more than one emulator"))]
    );
    let mut talk = opened(every());
    assert_eq!(
        talk.from_client(
            &framed(b"host-serial:emulator-5556:wait-for-any-device"),
            &two
        )
        .unwrap(),
        vec![
            Out::Splice,
            Out::ToServer(framed(b"host-transport-id:4:wait-for-any-device"))
        ]
    );
}

fn chrome() -> DeviceSocket {
    DeviceSocket::try_from("localabstract:chrome_devtools_remote").unwrap()
}

fn chrome_forward() -> Forward {
    Forward {
        port: port(9222),
        server: port(58765),
        device: serial(RECORDED),
        socket: chrome(),
    }
}

/// A forward on a lent device is placed on the remote at the port it
/// named; then the server is asked for a listener of its own choosing to the
/// device. The remote is answered only once the core has recorded the forward
/// and given its endpoint the server's listener, as the server answers only
/// once its listener is installed.
#[test]
fn a_forward_is_placed_on_the_remote_and_answered_once_the_server_and_the_core_listen() {
    let mut talk = opened(lent(&[RECORDED]));
    let request = framed(
        b"host-serial:127.0.0.1:15555:forward:tcp:9222;localabstract:chrome_devtools_remote",
    );
    assert_eq!(
        talk.from_client(&request, &recorded_view()).unwrap(),
        vec![Out::Forward {
            port: 9222,
            device: serial(RECORDED),
            socket: chrome(),
        }]
    );
    assert!(talk.places());
    assert_eq!(
        talk.placed(Ok(port(9222))),
        vec![Out::ToServer(framed(
            b"host-transport-id:1:forward:tcp:0;localabstract:chrome_devtools_remote"
        ))]
    );
    talk.from_server(b"OKAYOKAY000558765", &recorded_view())
        .unwrap();
    assert_eq!(
        talk.server_closed(&recorded_view()).unwrap(),
        vec![Out::Forwarded {
            forward: chrome_forward(),
            replaced: None,
            id: 1,
        }]
    );
    assert!(talk.open(), "the remote waits for its answer");
    assert_eq!(
        talk.listened(Ok(())),
        vec![Out::ToClient(b"OKAYOKAY".to_vec())]
    );
    assert!(!talk.open());
    assert_eq!(talk.listened(Ok(())), Vec::new(), "answered once");
}

/// `tcp:0` is answered with the port bound on the remote, never the
/// server's on the workstation.
#[test]
fn a_forward_from_any_port_is_answered_with_the_port_bound_on_the_remote() {
    let mut talk = opened(every());
    talk.from_client(&framed(b"host:forward:tcp:0;tcp:7000"), &recorded_view())
        .unwrap();
    talk.placed(Ok(port(44863)));
    talk.from_server(b"OKAYOKAY000558766", &recorded_view())
        .unwrap();
    let outs = talk.server_closed(&recorded_view()).unwrap();
    assert!(matches!(
        &outs[..],
        [Out::Forwarded { forward, .. }] if forward.port == port(44863) && forward.server == port(58766)
    ));
    let mut answered = b"OKAYOKAY".to_vec();
    answered.extend(framed(b"44863"));
    assert_eq!(talk.listened(Ok(())), vec![Out::ToClient(answered)]);
}

/// Where the remote's side cannot be bound the remote reads ADB's own words
/// for it; where the server refuses after the remote's side was placed, the
/// remote reads the server's refusal and the carrier is ended; and where the
/// core cannot give the endpoint the server's listener, the remote reads
/// ADB's words for a listener not installed and the carrier is ended.
#[test]
fn a_forward_that_cannot_be_placed_or_is_refused_is_told_in_adbs_words() {
    let mut talk = opened(every());
    talk.from_client(&framed(b"host:forward:tcp:9222;tcp:9222"), &recorded_view())
        .unwrap();
    assert_eq!(
        talk.placed(Err(
            "the remote's ssh server would not listen at port 9222".to_owned()
        )),
        vec![Out::ToClient(fail(
            "cannot bind listener: the remote's ssh server would not listen at port 9222"
        ))]
    );
    let mut talk = opened(every());
    talk.from_client(&framed(b"host:forward:tcp:9222;tcp:9222"), &recorded_view())
        .unwrap();
    talk.placed(Ok(port(9222)));
    talk.from_server(&fail("device offline (no transport)"), &recorded_view())
        .unwrap();
    assert_eq!(
        talk.server_closed(&recorded_view()).unwrap(),
        vec![
            Out::ToClient(fail("device offline (no transport)")),
            Out::Unplaced(port(9222))
        ]
    );
    let mut talk = opened(every());
    talk.from_client(&framed(b"host:forward:tcp:9222;tcp:9222"), &recorded_view())
        .unwrap();
    talk.placed(Ok(port(9222)));
    talk.from_server(b"OKAYOKAY000558765", &recorded_view())
        .unwrap();
    talk.server_closed(&recorded_view()).unwrap();
    assert_eq!(
        talk.listened(Err("the workstation's endpoint for it has ended".to_owned())),
        vec![
            Out::ToClient(fail(
                "cannot bind listener: the workstation's endpoint for it has ended"
            )),
            Out::Unplaced(port(9222))
        ]
    );
    assert!(!talk.open());
}

/// A forward at a port the remote holds one at gives the server's own
/// listener the new target, unless the remote asked not to rebind; a
/// malformed forward is the server's own refusal; a remote side that is not
/// a TCP port is refused.
#[test]
fn a_forward_at_a_port_held_rebinds_and_a_malformed_one_is_refused() {
    let carried = Carried {
        reverses: Vec::new(),
        forwards: vec![chrome_forward()],
    };
    let mut talk = Conversation::opened(carried.clone(), every());
    assert_eq!(
        talk.from_client(&framed(b"host:forward:tcp:9222;tcp:9000"), &recorded_view())
            .unwrap(),
        vec![Out::ToServer(framed(
            b"host-transport-id:1:forward:tcp:58765;tcp:9000"
        ))]
    );
    talk.from_server(b"OKAYOKAY", &recorded_view()).unwrap();
    let outs = talk.server_closed(&recorded_view()).unwrap();
    assert_eq!(
        outs,
        vec![Out::Forwarded {
            forward: Forward {
                socket: DeviceSocket::try_from("tcp:9000").unwrap(),
                ..chrome_forward()
            },
            replaced: Some(chrome_forward()),
            id: 1,
        }]
    );
    assert_eq!(
        talk.listened(Ok(())),
        vec![Out::ToClient(b"OKAYOKAY".to_vec())]
    );
    let mut talk = Conversation::opened(carried, every());
    assert_eq!(
        talk.from_client(
            &framed(b"host:forward:norebind:tcp:9222;tcp:9000"),
            &recorded_view()
        )
        .unwrap(),
        vec![Out::ToClient(fail("cannot rebind existing socket"))]
    );
    for (request, words) in [
        (&b"host:forward:tcp:1;"[..], "bad forward: tcp:1;"),
        (b"host:forward:tcp:1", "bad forward: tcp:1;"),
        (
            b"host:forward:tcp:1;*smartsocket*",
            "bad forward: tcp:1;*smartsocket*",
        ),
    ] {
        let mut talk = opened(every());
        assert_eq!(
            talk.from_client(&framed(request), &recorded_view())
                .unwrap(),
            vec![Out::ToClient(fail(words))]
        );
    }
    for request in [
        &b"host:forward:localabstract:mine;tcp:1"[..],
        b"host:forward:tcp:example.com:1;tcp:1",
        b"host:forward:localfilesystem:/tmp/x;tcp:1",
    ] {
        refused(request, Withheld::Unforwardable, every());
    }
    // A forward on a device not lent is the device not there.
    let (got, _) = relay(
        &[Read::Client(framed(
            b"host-serial:127.0.0.1:15555:forward:tcp:1;tcp:1",
        ))],
        Carried::default(),
        lent(&[]),
        &recorded_view(),
    );
    assert_eq!(got.client, fail("device '127.0.0.1:15555' not found"));
}

/// A removal removes only the remote's own forward, from the server and
/// from the remote; a listing shows the remote its own forwards by their ports
/// there, and no other.
#[test]
fn a_removal_and_a_listing_are_the_remotes_own() {
    let carried = Carried {
        reverses: Vec::new(),
        forwards: vec![chrome_forward()],
    };
    let mut talk = Conversation::opened(carried.clone(), every());
    assert_eq!(
        talk.from_client(&framed(b"host:killforward:tcp:9222"), &recorded_view())
            .unwrap(),
        vec![Out::ToServer(framed(
            b"host-transport-id:1:killforward:tcp:58765"
        ))]
    );
    talk.from_server(b"OKAYOKAY", &recorded_view()).unwrap();
    assert_eq!(
        talk.server_closed(&recorded_view()).unwrap(),
        vec![
            Out::ToClient(b"OKAYOKAY".to_vec()),
            Out::Unforwarded(port(9222))
        ]
    );
    // With its device gone, the server's listener went with it.
    let mut talk = Conversation::opened(carried.clone(), every());
    assert_eq!(
        talk.from_client(&framed(b"host:killforward:tcp:9222"), &View::default())
            .unwrap(),
        vec![
            Out::ToClient(b"OKAYOKAY".to_vec()),
            Out::Unforwarded(port(9222))
        ]
    );
    let mut talk = Conversation::opened(carried.clone(), every());
    assert_eq!(
        talk.from_client(&framed(b"host:killforward:tcp:5037"), &recorded_view())
            .unwrap(),
        vec![Out::ToClient(fail("listener 'tcp:5037' not found"))]
    );
    let mut talk = Conversation::opened(carried.clone(), every());
    assert_eq!(
        talk.from_client(&framed(b"host:killforward-all"), &recorded_view())
            .unwrap(),
        vec![Out::RemoveAll(vec![(1, chrome_forward())])]
    );
    assert_eq!(
        talk.removed(),
        vec![
            Out::ToClient(b"OKAYOKAY".to_vec()),
            Out::Unforwarded(port(9222))
        ]
    );
    let mut talk = Conversation::opened(carried, every());
    assert_eq!(
        talk.from_client(&framed(b"host:list-forward"), &recorded_view())
            .unwrap(),
        vec![Out::ToServer(framed(b"host:list-forward"))]
    );
    let server = okay(
        b"127.0.0.1:15555 tcp:58765 localabstract:chrome_devtools_remote\nR5CT tcp:5000 tcp:6000\n",
    );
    talk.from_server(&server, &recorded_view()).unwrap();
    assert_eq!(
        talk.server_closed(&recorded_view()).unwrap(),
        vec![Out::ToClient(okay(
            b"127.0.0.1:15555 tcp:9222 localabstract:chrome_devtools_remote\n"
        ))]
    );
    // The recorded listing of no forwards reaches the client as it was sent.
    let connections = recorded();
    let reads = &connections[&13];
    let (got, _) = relay(reads, Carried::default(), every(), &recorded_view());
    assert_eq!(got.client, sent(reads).1);
}

/// The `-R` a forward is carried with: the port on the remote, 0 for its
/// server's choosing, to the core's endpoint.
#[test]
fn a_forward_is_carried_from_the_remotes_port_to_the_cores_endpoint() {
    assert_eq!(remote_forward(9222, port(50170)), "9222:127.0.0.1:50170");
    assert_eq!(remote_forward(0, port(50171)), "0:127.0.0.1:50171");
}

/// The recorded reverse is held for its endpoint, sent on naming that
/// endpoint as its host side, and the device's answer reaches the client
/// whole, with the reverse it took told to the core.
#[test]
fn a_reverse_is_held_rewritten_to_its_endpoint_and_its_answer_carried() {
    let reads = &recorded()[&7];
    let (mut got, mut talk) = relay(&reads[0..3], Carried::default(), every(), &recorded_view());
    let Read::Client(reverse) = &reads[3] else {
        panic!()
    };
    assert_eq!(reverse, &framed(b"reverse:forward:tcp:8081;tcp:8081"));
    let mut spliced = false;
    let outs = talk.from_client(reverse, &recorded_view()).unwrap();
    take(&mut got, &mut spliced, &mut talk, &recorded_view(), outs);
    let metro = Target::Loopback(port(8081));
    assert_eq!(
        got.asked,
        vec![Out::Selected(serial(RECORDED)), Out::Reverse(metro.clone())]
    );
    assert!(talk.holds());
    // A client that speaks while its reverse is held is out of turn.
    let mut eager = opened(every());
    eager.from_client(reverse, &recorded_view()).unwrap();
    assert_eq!(
        eager.from_client(b"x", &recorded_view()),
        Err(Breach::OutOfTurn(Side::Client))
    );
    let before = got.server.len();
    let outs = talk.carry(port(50131));
    take(&mut got, &mut spliced, &mut talk, &recorded_view(), outs);
    assert_eq!(
        got.server[before..],
        framed(b"reverse:forward:tcp:8081;tcp:50131")
    );
    for read in &reads[4..] {
        let outs = match read {
            Read::Server(bytes) => talk.from_server(bytes, &recorded_view()).unwrap(),
            Read::ServerEnd => talk.server_closed(&recorded_view()).unwrap(),
            Read::Client(_) => panic!(),
        };
        take(&mut got, &mut spliced, &mut talk, &recorded_view(), outs);
    }
    let (_, server) = sent(reads);
    assert_eq!(got.client, server);
    assert!(!spliced);
    assert_eq!(
        got.asked[2],
        Out::Reversed {
            target: metro,
            endpoint: port(50131),
        }
    );
}

/// A reverse listing names each of this remote's endpoints as the target it
/// carries to, so `adb reverse --list` on the remote says what the remote
/// asked for; a host side no endpoint of its own is left as the device says
/// it.
#[test]
fn a_reverse_listing_names_each_endpoint_as_the_target_the_remote_asked_for() {
    let reads = &recorded()[&9];
    let device = okay(b"host-17 tcp:8081 tcp:50131\nhost-17 tcp:9000 tcp:7000\n");
    let mut with_device = reads[..4].to_vec();
    with_device.push(Read::Server(device));
    with_device.push(Read::ServerEnd);
    let carried = Carried {
        reverses: vec![(port(50131), Target::Loopback(port(8081)))],
        forwards: Vec::new(),
    };
    let (got, _) = relay(&with_device, carried, every(), &recorded_view());
    let mut expected = b"OKAY".to_vec();
    expected.extend(&b"\x01\x00\x00\x00\x00\x00\x00\x00"[..]);
    expected.extend(okay(
        b"host-17 tcp:8081 tcp:8081\nhost-17 tcp:9000 tcp:7000\n",
    ));
    assert_eq!(got.client, expected);
    let (got, _) = relay(reads, Carried::default(), every(), &recorded_view());
    assert_eq!(got.client, sent(reads).1);
}

/// What the server stops on: a reverse it does not know
/// (`UpdateReverseConfig`'s `LOG(FATAL)`), however near a known one it is.
#[test]
fn a_reverse_the_server_stops_on_is_refused() {
    for request in [
        &b"reverse:anything"[..],
        b"reverse:list-forwardx",
        b"reverse:killforward-allx",
        b"reverse:",
        b"reverse:list-forward ",
    ] {
        refused(request, Withheld::Stopping, every());
    }
    // The longest request four hexadecimal digits can give is passed to a
    // device as it comes.
    assert_eq!(kind(b"shell:", 0xFFFF), Kind::Passed);
}

/// A request for the server itself, or a reverse, longer than [`HELD`] is
/// refused on its first bytes, before the rest is read; a device request of
/// any length the server takes is passed as it comes.
#[test]
fn a_long_request_for_the_server_is_refused_and_a_long_device_one_is_passed_as_it_comes() {
    let mut talk = opened(every());
    let header = format!("{:04x}", HELD + 1);
    let mut start = header.into_bytes();
    start.extend(b"host-serial:");
    start.extend(std::iter::repeat_n(b'a', 10));
    assert_eq!(
        talk.from_client(&start, &recorded_view()).unwrap().last(),
        Some(&Out::Withheld(Withheld::Long))
    );
    let mut talk = opened(every());
    let mut start = format!("{:04x}", 8000).into_bytes();
    start.extend(b"shell:echo ");
    start.extend(std::iter::repeat_n(b'b', 20));
    let outs = talk.from_client(&start, &recorded_view()).unwrap();
    assert_eq!(outs, vec![Out::Splice, Out::ToServer(start.clone())]);
    let rest = vec![b'c'; 8000 - 31];
    assert_eq!(
        talk.from_client(&rest, &recorded_view()).unwrap(),
        vec![Out::ToServer(rest.clone())]
    );
    assert!(talk.spliced());
    assert_eq!(
        talk.from_server(b"OKAY", &recorded_view()).unwrap(),
        vec![Out::ToClient(b"OKAY".to_vec())]
    );
}

#[test]
fn a_reverse_to_what_the_channel_cannot_carry_is_refused() {
    for request in [
        &b"reverse:forward:tcp:8081;localabstract:metro"[..],
        b"reverse:forward:tcp:8081;localfilesystem:relative.sock",
        b"reverse:forward:tcp:8081;localfilesystem:/tmp/a:b.sock",
        b"reverse:forward:tcp:8081;tcp:0",
        b"reverse:forward:tcp:8081;tcp:65536",
        b"reverse:forward:tcp:8081;jdwp:1",
    ] {
        refused(request, Withheld::Uncarriable, every());
    }
    let mut talk = opened(every());
    talk.from_client(
        &framed(b"reverse:forward:tcp:8081;tcp:8081"),
        &recorded_view(),
    )
    .unwrap();
    let outs = talk.withhold(Withheld::Crowded);
    assert_eq!(outs.last(), Some(&Out::Withheld(Withheld::Crowded)));
    assert!(!talk.open());
    // A forward is refused for crowding the same way.
    let mut talk = opened(every());
    talk.from_client(&framed(b"host:forward:tcp:9222;tcp:9222"), &recorded_view())
        .unwrap();
    assert_eq!(
        talk.withhold(Withheld::Crowded).last(),
        Some(&Out::Withheld(Withheld::Crowded))
    );
}

/// The forms a reverse's host side lands in, and the local forward each is
/// carried with.
#[test]
fn each_target_is_read_as_the_remote_meant_it_and_carried_with_its_own_forward() {
    let cases = [
        (
            "tcp:8081",
            Target::Loopback(port(8081)),
            "127.0.0.1:50140:localhost:8081",
        ),
        (
            "tcp:db.internal:5432",
            Target::Host {
                host: Host::try_from("db.internal").unwrap(),
                port: port(5432),
            },
            "127.0.0.1:50140:db.internal:5432",
        ),
        (
            "tcp:[::1]:9000",
            Target::Host {
                host: Host::try_from("::1").unwrap(),
                port: port(9000),
            },
            "127.0.0.1:50140:[::1]:9000",
        ),
        (
            "localfilesystem:/run/user/1000/metro.sock",
            Target::Path(RemotePath::try_from("/run/user/1000/metro.sock").unwrap()),
            "127.0.0.1:50140:/run/user/1000/metro.sock",
        ),
        (
            "local:/tmp/dev.sock",
            Target::Path(RemotePath::try_from("/tmp/dev.sock").unwrap()),
            "127.0.0.1:50140:/tmp/dev.sock",
        ),
    ];
    for (spec, expected, forward) in cases {
        let read = target(spec.as_bytes()).unwrap();
        assert_eq!(read, expected, "{spec}");
        assert_eq!(local_forward(&read, port(50140)), forward, "{spec}");
    }
    // The rewritten request keeps what stood before the target, `norebind`
    // included.
    let mut talk = opened(every());
    talk.from_client(
        &framed(b"reverse:forward:norebind:tcp:0;tcp:8081"),
        &recorded_view(),
    )
    .unwrap();
    assert_eq!(
        talk.carry(port(50141)),
        vec![Out::ToServer(framed(
            b"reverse:forward:norebind:tcp:0;tcp:50141"
        ))]
    );
}

/// A reverse the device refuses as malformed is passed for the device to
/// refuse, since nothing will listen; a removal and a listing are read whole.
#[test]
fn a_malformed_reverse_a_removal_and_a_listing_are_passed_and_answered_whole() {
    for request in [
        &b"reverse:forward:tcp:1;tcp:2;tcp:3"[..],
        b"reverse:forward:;tcp:2",
        b"reverse:forward:tcp:1;*x",
        b"reverse:forward:nosemicolon",
        b"reverse:killforward:tcp:8081",
        b"reverse:killforward-all",
        b"reverse:list-forward",
    ] {
        let mut talk = opened(every());
        assert_eq!(
            talk.from_client(&framed(request), &recorded_view())
                .unwrap(),
            vec![Out::ToServer(framed(request))]
        );
        assert_eq!(
            talk.from_server(b"OKAYFAIL0003bad", &recorded_view())
                .unwrap(),
            vec![]
        );
        assert_eq!(
            talk.server_closed(&recorded_view()).unwrap(),
            vec![Out::ToClient(b"OKAYFAIL0003bad".to_vec())]
        );
    }
}

/// Every breach, each ending the conversation before anything of it is
/// carried.
#[test]
fn every_breach_is_told_apart() {
    let seen = recorded_view();
    let fresh = || opened(every());
    assert_eq!(
        fresh().from_client(b"00g1host:kill", &seen),
        Err(Breach::Length)
    );
    assert_eq!(fresh().from_client(b"0000", &seen), Err(Breach::Length));
    assert_eq!(fresh().from_client(b"ffff", &seen), Ok(vec![]));
    assert_eq!(fresh().from_client(b"000 ", &seen), Err(Breach::Length));
    assert_eq!(fresh().from_client(b"+00c", &seen), Err(Breach::Length));
    let mut past = fresh();
    let mut both = framed(b"host:version");
    both.extend(framed(b"host:devices"));
    assert_eq!(
        past.from_client(&both, &seen),
        Err(Breach::OutOfTurn(Side::Client))
    );
    let mut switching = fresh();
    switching
        .from_client(&framed(b"host:transport-any"), &seen)
        .unwrap();
    assert_eq!(
        switching.from_client(&framed(b"host:kill"), &seen),
        Err(Breach::OutOfTurn(Side::Client))
    );
    let mut idle = fresh();
    assert_eq!(
        idle.from_server(b"OKAY", &seen),
        Err(Breach::OutOfTurn(Side::Server))
    );
    let mut garbled = fresh();
    garbled
        .from_client(&framed(b"host:transport-any"), &seen)
        .unwrap();
    assert_eq!(garbled.from_server(b"WHAT", &seen), Err(Breach::NotAnswer));
    let mut extra = fresh();
    extra
        .from_client(&framed(b"host:transport-any"), &seen)
        .unwrap();
    assert_eq!(
        extra.from_server(b"OKAYOKAY", &seen),
        Err(Breach::OutOfTurn(Side::Server))
    );
    let mut long = fresh();
    long.from_client(&framed(b"reverse:list-forward"), &seen)
        .unwrap();
    assert_eq!(
        long.from_server(&vec![b'x'; 8 + 0xFFFF + 1], &seen),
        Err(Breach::LongAnswer)
    );
    let mut tracker = fresh();
    tracker
        .from_client(&framed(b"host:track-devices"), &seen)
        .unwrap();
    assert_eq!(
        tracker.from_server(b"OKAYzzzz", &seen),
        Err(Breach::NotAnswer)
    );
    let mut cut = fresh();
    cut.from_client(b"000chost:ver", &seen).unwrap();
    assert_eq!(cut.client_closed(), Err(Breach::Cut(Side::Client)));
    let mut passing = fresh();
    let mut start = format!("{:04x}", 8000).into_bytes();
    start.extend(std::iter::repeat_n(b'a', 30));
    passing.from_client(&start, &seen).unwrap();
    assert_eq!(passing.client_closed(), Err(Breach::Cut(Side::Client)));
    let mut server_cut = fresh();
    server_cut
        .from_client(&framed(b"host:tport:any"), &seen)
        .unwrap();
    server_cut.from_server(b"OKAY", &seen).unwrap();
    assert_eq!(
        server_cut.server_closed(&seen),
        Err(Breach::Cut(Side::Server))
    );
    for breach in [
        Breach::Length,
        Breach::OutOfTurn(Side::Client),
        Breach::OutOfTurn(Side::Server),
        Breach::NotAnswer,
        Breach::LongAnswer,
        Breach::Cut(Side::Client),
        Breach::Cut(Side::Server),
    ] {
        assert_ne!(breach.to_string(), "");
    }
}

/// Every refusal's words are ADB's own form, and none is empty.
#[test]
fn every_refusal_has_words_for_the_remotes_tool() {
    for withheld in [
        Withheld::Ending,
        Withheld::Unlent(None),
        Withheld::Every,
        Withheld::Unacknowledged,
        Withheld::Reaching,
        Withheld::Stopping,
        Withheld::Long,
        Withheld::Uncarriable,
        Withheld::Unforwardable,
        Withheld::Crowded,
        Withheld::Unlisted,
        Withheld::Unknown,
        Withheld::Hosted,
    ] {
        let words = reason(&withheld);
        assert!(!words.is_empty() && words.is_ascii(), "{withheld:?}");
    }
}

/// `socket_test.cpp`'s own vectors for `parse_host_service`.
#[test]
fn a_serial_and_its_command_are_split_as_the_server_splits_them() {
    let split = |service: &str| {
        host_service(service.as_bytes()).map(|(serial, command)| {
            (
                String::from_utf8(serial.to_vec()).unwrap(),
                String::from_utf8(command.to_vec()).unwrap(),
            )
        })
    };
    let expect = |service: &str, serial: &str, command: &str| {
        assert_eq!(
            split(service),
            Some((serial.to_owned(), command.to_owned())),
            "{service}"
        );
    };
    for protocol in ["", "tcp:", "udp:"] {
        assert_eq!(split(protocol), None, "{protocol}");
        assert_eq!(split(&format!("{protocol}foo")), None, "{protocol}foo");
        let serial = format!("{protocol}foo");
        expect(&format!("{serial}:bar"), &serial, "bar");
        expect(&format!("{serial}:bar:baz"), &serial, "bar:baz");
        let serial = format!("{protocol}foo:123");
        expect(&format!("{serial}:bar"), &serial, "bar");
        expect(&format!("{serial}:456"), &serial, "456");
        expect(&format!("{serial}:bar:baz"), &serial, "bar:baz");
        expect(
            &format!("{protocol}foo:123"),
            &format!("{protocol}foo"),
            "123",
        );
        expect(
            &format!("{protocol}foo:123bar:baz"),
            &format!("{protocol}foo"),
            "123bar:baz",
        );
        for address in ["100.100.100.100", "[0123:4567:89ab:CDEF:0:9:a:f]", "[::1]"] {
            let serial = format!("{protocol}{address}");
            let with_port = format!("{protocol}{address}:5555");
            expect(&format!("{serial}:foo"), &serial, "foo");
            expect(&format!("{with_port}:foo"), &with_port, "foo");
        }
        expect(
            &format!("{protocol}[0123:foo"),
            &format!("{protocol}[0123"),
            "foo",
        );
        expect(
            &format!("{protocol}foo:ping [0123:4567:89ab:CDEF:0:9:a:f]:5555"),
            &format!("{protocol}foo"),
            "ping [0123:4567:89ab:CDEF:0:9:a:f]:5555",
        );
        let embedded = format!("{protocol}foo:echo foo\0bar");
        assert_eq!(
            host_service(embedded.as_bytes()),
            Some((format!("{protocol}foo").as_bytes(), &b"echo foo\0bar"[..]))
        );
    }
    for prefix in ["usb:", "product:", "model:", "device:"] {
        assert_eq!(split(prefix), None);
        assert_eq!(split(&format!("{prefix}foo")), None);
        expect(&format!("{prefix}foo:bar"), &format!("{prefix}foo"), "bar");
        expect(
            &format!("{prefix}foo:bar:baz"),
            &format!("{prefix}foo"),
            "bar:baz",
        );
        expect(
            &format!("{prefix}foo:123:bar"),
            &format!("{prefix}foo"),
            "123:bar",
        );
    }
}
