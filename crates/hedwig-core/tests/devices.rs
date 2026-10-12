//! What the server holds and what a grant lends of it, read as the server
//! reads it: `ParseNetAddress` and `MatchesTarget` against their own suites'
//! vectors (`.ext/libbase/parsenetaddress_test.cpp`,
//! `.ext/adb/transport_test.cpp`), a selection resolved among the devices
//! lent with the server's own words for a miss, and each form of listing
//! kept to the devices lent.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests over fixed vectors"
)]

use hedwig_core::devices::{
    Device, Form, Listing, Resolved, Selection, State, View, kept, net_address, resolve, strtol,
};
use hedwig_model::capability::Lends;
use hedwig_model::text::DeviceSerial;

fn device(serial: &str, usb: bool, id: u64) -> Device {
    Device {
        serial: serial.to_owned(),
        state: State::DEVICE,
        usb,
        devpath: String::new(),
        product: String::new(),
        model: String::new(),
        device: String::new(),
        id,
    }
}

fn lends(serials: &[&str]) -> Lends {
    Lends::devices(
        serials
            .iter()
            .map(|serial| DeviceSerial::try_from(*serial).unwrap()),
    )
}

fn view(devices: Vec<Device>) -> View {
    View {
        devices,
        listing: Listing::Read,
        holder: None,
    }
}

#[test]
fn an_address_is_read_as_libbase_reads_it() {
    let canonical =
        |address: &str, port: u16| net_address(address, Some(port)).map(|a| a.canonical(port));
    assert_eq!(
        canonical("www.google.com", 123).unwrap(),
        "www.google.com:123"
    );
    assert_eq!(
        canonical("www.google.com:666", 123).unwrap(),
        "www.google.com:666"
    );
    assert_eq!(canonical("1.2.3.4", 123).unwrap(), "1.2.3.4:123");
    assert_eq!(canonical("1.2.3.4:666", 123).unwrap(), "1.2.3.4:666");
    assert_eq!(canonical("::1", 123).unwrap(), "[::1]:123");
    assert_eq!(
        canonical("fe80::200:5aee:feaa:20a2", 123).unwrap(),
        "[fe80::200:5aee:feaa:20a2]:123"
    );
    assert_eq!(canonical("[::1]:666", 123).unwrap(), "[::1]:666");
    assert_eq!(
        canonical("[fe80::200:5aee:feaa:20a2]:666", 123).unwrap(),
        "[fe80::200:5aee:feaa:20a2]:666"
    );
    for refused in [
        "1.2.3.4:",
        "1.2.3.4::",
        ":123",
        ":1",
        "::::::::1",
        "[::1",
        "[::1]",
        "[::1]:",
        "[::1]::",
        "1.2.3.4:-1",
        "1.2.3.4:0",
        "1.2.3.4:65536",
        "1.2.3.4:hello",
        "[::1]:-1",
        "[::1]:0",
        "[::1]:65536",
        "[::1]:hello",
        "",
    ] {
        let error = net_address(refused, Some(5555)).unwrap_err();
        assert!(!error.is_empty(), "{refused}");
    }
    // `sscanf`'s reading of a port: what follows the digits is not read.
    assert_eq!(canonical("1.2.3.4:5555abc", 1).unwrap(), "1.2.3.4:5555");
    // libbase's own words, which the server puts in its refusal.
    assert_eq!(
        net_address("[::1", None).unwrap_err(),
        "bad IPv6 address '[::1'"
    );
    assert_eq!(net_address(":123", None).unwrap_err(), "no host in ':123'");
    assert_eq!(
        net_address("1.2.3.4:0", None).unwrap_err(),
        "bad port number '0' in '1.2.3.4:0'"
    );
}

#[test]
fn strtol_reads_an_emulators_ports_as_c_does() {
    assert_eq!(strtol("5554"), 5554);
    assert_eq!(strtol("  5554x"), 5554);
    assert_eq!(strtol("0x15b2"), 5554);
    assert_eq!(strtol("012662"), 5554);
    assert_eq!(strtol("-5"), -5);
    assert_eq!(strtol("abc"), 0);
    assert_eq!(strtol(""), 0);
}

#[test]
fn a_target_matches_a_device_as_the_server_matches_it() {
    let mut usb = device("foo", true, 1);
    usb.devpath = "/path/to/bar".to_owned();
    usb.product = "test_product".to_owned();
    usb.model = "test_model".to_owned();
    usb.device = "test_device".to_owned();
    for usb_or_socket in [true, false] {
        usb.usb = usb_or_socket;
        for target in [
            "foo",
            "/path/to/bar",
            "product:test_product",
            "model:test_model",
            "device:test_device",
        ] {
            assert!(usb.matches(target.as_bytes()), "{target}");
        }
        for target in ["test_product", "test_model", "test_device"] {
            assert!(!usb.matches(target.as_bytes()), "{target}");
        }
    }
    let mut local = device("100.100.100.100:5555", false, 2);
    for socket in [true, false] {
        local.usb = !socket;
        for target in [
            "100.100.100.100",
            "tcp:100.100.100.100",
            "tcp:100.100.100.100:5555",
            "udp:100.100.100.100",
            "udp:100.100.100.100:5555",
        ] {
            assert_eq!(local.matches(target.as_bytes()), socket, "{target}");
        }
        for target in [
            "100.100.100",
            "100.100.100.100:",
            "100.100.100.100:-1",
            "100.100.100.100:5554",
            "abc:100.100.100.100",
        ] {
            assert!(!local.matches(target.as_bytes()), "{target}");
        }
    }
    // A model is compared as the server writes it, every other character `_`.
    let mut pixel = device("R5CT", true, 3);
    pixel.model = "Pixel 7".to_owned();
    assert!(pixel.matches(b"model:Pixel_7"));
}

/// The one device is the one lent; a device not lent is not there; the
/// server's own words for each miss, and which device not lent the remote
/// reached for.
#[test]
fn a_selection_resolves_among_the_devices_lent_alone() {
    let phone = device("R5CT1234ABC", true, 1);
    let mut test = device("TESTDEVICE01", true, 2);
    test.model = "Pixel_8".to_owned();
    let emulator = device("emulator-5554", false, 3);
    let held = view(vec![phone.clone(), test.clone(), emulator.clone()]);
    let lent = lends(&["TESTDEVICE01"]);
    let one = |selection: Selection| match resolve(&held, &lent, &selection) {
        Resolved::One(device) => device.serial,
        missing @ Resolved::Missing { .. } => panic!("{selection:?}: {missing:?}"),
    };
    let missing = |selection: Selection| match resolve(&held, &lent, &selection) {
        Resolved::Missing { words, unlent } => (words, unlent),
        Resolved::One(device) => panic!("{selection:?}: {device:?}"),
    };
    assert_eq!(one(Selection::Any), "TESTDEVICE01");
    assert_eq!(one(Selection::Usb), "TESTDEVICE01");
    assert_eq!(
        one(Selection::Target(b"TESTDEVICE01".to_vec())),
        "TESTDEVICE01"
    );
    assert_eq!(
        one(Selection::Target(b"model:Pixel_8".to_vec())),
        "TESTDEVICE01"
    );
    assert_eq!(one(Selection::Id(2)), "TESTDEVICE01");
    let serial = |text: &str| Some(DeviceSerial::try_from(text).ok());
    assert_eq!(
        missing(Selection::Target(b"R5CT1234ABC".to_vec())),
        (
            "device 'R5CT1234ABC' not found".to_owned(),
            serial("R5CT1234ABC")
        )
    );
    assert_eq!(
        missing(Selection::Id(1)),
        (
            "no device with transport id '1'".to_owned(),
            serial("R5CT1234ABC")
        )
    );
    assert_eq!(
        missing(Selection::Local),
        ("no emulators found".to_owned(), Some(None))
    );
    assert_eq!(
        missing(Selection::Target(b"nosuch".to_vec())),
        ("device 'nosuch' not found".to_owned(), None)
    );
    // Nothing lent: the one device is none, and what the remote reached for
    // is said.
    assert!(matches!(
        resolve(&held, &Lends::none(), &Selection::Any),
        Resolved::Missing { words, unlent: Some(None) } if words == "no devices/emulators found"
    ));
    // Every device lent: the server's own ambiguity, in its words.
    for (selection, words) in [
        (Selection::Any, "more than one device/emulator"),
        (Selection::Usb, "more than one USB device"),
    ] {
        assert!(matches!(
            resolve(&held, &Lends::Every, &selection),
            Resolved::Missing { words: said, unlent: None } if said == words
        ));
    }
    assert_eq!(
        match resolve(&held, &Lends::Every, &Selection::Local) {
            Resolved::One(device) => device.serial,
            other @ Resolved::Missing { .. } => panic!("{other:?}"),
        },
        "emulator-5554"
    );
    // A device without permission is passed over where another answers, and
    // is the answer where none does, so the server says why itself.
    let mut unpermitted = device("NOPERM", true, 4);
    unpermitted.state = State::NO_PERMISSION;
    let both = view(vec![unpermitted.clone(), test.clone()]);
    let both_lent = lends(&["NOPERM", "TESTDEVICE01"]);
    assert!(matches!(
        resolve(&both, &both_lent, &Selection::Usb),
        Resolved::One(device) if device.serial == "TESTDEVICE01"
    ));
    assert!(matches!(
        resolve(&view(vec![unpermitted]), &lends(&["NOPERM"]), &Selection::Usb),
        Resolved::One(device) if device.serial == "NOPERM"
    ));
}

/// Each form of the server's own listing with the lines or
/// entries of devices not lent left out, and every device's under every
/// device lent.
#[test]
fn every_form_of_listing_is_kept_to_the_devices_lent() {
    let held = view(vec![
        device("R5CT1234ABC", true, 1),
        device("TESTDEVICE01", true, 2),
        device("emulator-5554", false, 3),
    ]);
    let lent = lends(&["TESTDEVICE01", "emulator-5554"]);
    let short = b"R5CT1234ABC\tdevice\nTESTDEVICE01\tdevice\nemulator-5554\toffline\n";
    assert_eq!(
        kept(short, Form::Short, &lent, &held),
        b"TESTDEVICE01\tdevice\nemulator-5554\toffline\n"
    );
    let long = concat!(
        "R5CT1234ABC            device usb:1-1 product:panther model:Pixel_7 device:panther transport_id:1\n",
        "TESTDEVICE01           device usb:1-2 product:shiba model:Pixel_8 device:shiba transport_id:2\n",
        "emulator-5554          device product:sdk_gphone64_x86_64 model:sdk transport_id:3\n",
        "a line of no device's\n",
    );
    assert_eq!(
        String::from_utf8(kept(long.as_bytes(), Form::Long, &lent, &held)).unwrap(),
        concat!(
            "TESTDEVICE01           device usb:1-2 product:shiba model:Pixel_8 device:shiba transport_id:2\n",
            "emulator-5554          device product:sdk_gphone64_x86_64 model:sdk transport_id:3\n",
        )
    );
    // A transport id the view does not hold is left out.
    let stray = "STRAY                  device transport_id:9\n";
    assert_eq!(
        kept(stray.as_bytes(), Form::Long, &Lends::none(), &held),
        Vec::<u8>::new()
    );
    let text = concat!(
        "device {\n  serial: \"R5CT1234ABC\"\n  state: DEVICE\n  transport_id: 1\n}\n",
        "device {\n  serial: \"emulator-5554\"\n  state: DEVICE\n  transport_id: 3\n}\n",
    );
    assert_eq!(
        String::from_utf8(kept(text.as_bytes(), Form::Text, &lent, &held)).unwrap(),
        "device {\n  serial: \"emulator-5554\"\n  state: DEVICE\n  transport_id: 3\n}\n"
    );
    let binary = devices_message(&[("R5CT1234ABC", 1), ("TESTDEVICE01", 2)]);
    let only = devices_message(&[("TESTDEVICE01", 2)]);
    assert_eq!(kept(&binary, Form::Binary, &lent, &held), only);
    assert_eq!(
        View::decode(&only).unwrap().devices[0].serial,
        "TESTDEVICE01"
    );
    for form in [Form::Short, Form::Long, Form::Binary, Form::Text] {
        assert_eq!(kept(short, form, &Lends::Every, &held), short);
    }
}

/// A protocol-buffer `Devices` message, as the server writes one: each
/// device's serial, its state `DEVICE`, and its transport id.
fn devices_message(devices: &[(&str, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (serial, id) in devices {
        let mut body = vec![0x0A, u8::try_from(serial.len()).unwrap()];
        body.extend_from_slice(serial.as_bytes());
        body.extend([0x10, 8, 0x50, u8::try_from(*id).unwrap()]);
        out.push(0x0A);
        out.push(u8::try_from(body.len()).unwrap());
        out.extend(body);
    }
    out
}

#[test]
fn a_listing_that_is_not_a_devices_message_is_unreadable() {
    assert!(View::decode(&[0x0A, 0x05, 0x0A]).is_err());
    assert!(View::decode(&[0x08]).is_err());
    assert!(View::decode(&[0x0F]).is_err());
    // A field this version does not know is passed over.
    let mut known = vec![0x7A, 0x01, 0x00];
    known.extend(devices_message(&[("emulator-5554", 3)]));
    assert_eq!(View::decode(&known).unwrap().devices.len(), 1);
}

/// A message's fields are left out by number and the rest kept byte for
/// byte; a cut message is unreadable.
#[test]
fn fields_are_left_out_by_number_and_the_rest_kept_as_they_came() {
    use hedwig_core::devices::without;

    // 1: varint 3; 5: "37.0.1"; 7: "C:/a"; 12: true; 13: "k".
    let message: Vec<u8> = [
        &[0x08, 0x03][..],
        &[0x2a, 0x06],
        b"37.0.1",
        &[0x3a, 0x04],
        b"C:/a",
        &[0x60, 0x01],
        &[0x6a, 0x01],
        b"k",
    ]
    .concat();
    let kept: Vec<u8> = [&[0x08, 0x03][..], &[0x2a, 0x06], b"37.0.1", &[0x60, 0x01]].concat();
    assert_eq!(without(&message, &[7, 8, 13, 14]), Ok(kept));
    assert_eq!(without(&message, &[]), Ok(message.clone()));
    assert_eq!(without(&[], &[7]), Ok(Vec::new()));
    assert!(without(&message[..message.len() - 1], &[7]).is_err());
}
