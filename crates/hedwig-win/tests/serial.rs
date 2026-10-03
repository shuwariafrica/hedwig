//! The workstation's serial ports through Windows' own calls: the ports
//! present, the devices of the ports class and their names, a port that is
//! not there, and Windows' names for devices read without regard to case.
//!
//! The tests marked ignored need a COM port, which neither a hosted runner nor
//! most workstations have: `HEDWIG_COM` names a port the test may open, and
//! `HEDWIG_COM_LOOP` that its TX is wired to its RX, RTS to CTS and DTR to DSR.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::fs::OpenOptions;
use std::time::Duration;

use hedwig_win::serial::{ComPort, Escape, MS_CTS_ON, MS_DSR_ON, OpenError, described, present};

#[test]
fn the_ports_present_are_what_serial_drivers_registered_and_a_name_none_has_is_absent() {
    let names = present().unwrap();
    // Every one present is a device of the ports class that is present.
    let devices = described(true).unwrap();
    for name in &names {
        assert!(
            devices
                .iter()
                .any(|device| device.port.as_ref() == Some(name)),
            "{name:?} in {devices:?}"
        );
    }
    let unused = (1..=255)
        .map(|number| format!("COM{number}"))
        .rfind(|candidate| {
            !names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(candidate))
        })
        .unwrap();
    assert!(matches!(ComPort::open(&unused), Err(OpenError::Absent)));
}

#[test]
fn the_ports_class_names_each_device_s_port_and_how_windows_shows_it() {
    // Without the presence filter the class lists the devices Windows has
    // known, unplugged ones among them; each with a port carries the name its
    // driver gave it in the name Windows shows for it.
    let known = described(false).unwrap();
    let present = described(true).unwrap();
    assert!(present.len() <= known.len());
    for device in &known {
        if let (Some(port), Some(friendly)) = (&device.port, &device.friendly) {
            let port = port.to_string_lossy();
            assert!(
                friendly.to_string_lossy().contains(port.as_ref()),
                "{device:?}"
            );
        }
    }
    eprintln!(
        "ports class: {} known, {} present: {known:?}",
        known.len(),
        present.len()
    );
}

#[test]
fn windows_names_a_device_without_regard_to_case() {
    for name in [r"\\.\NUL", r"\\.\nul", r"\\.\Nul"] {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

fn named() -> String {
    std::env::var("HEDWIG_COM").expect("HEDWIG_COM names a port the test may open")
}

#[test]
#[ignore = "needs a COM port, named by HEDWIG_COM"]
fn a_port_opens_once_and_takes_and_reports_its_settings() {
    let name = named();
    let port = ComPort::open(&name).unwrap();
    assert!(matches!(ComPort::open(&name), Err(OpenError::Busy)));
    let mut state = port.state().unwrap();
    for baud in [115_200, 921_600, 9600] {
        state.baud = baud;
        state.size = 8;
        port.set_state(state).unwrap();
        assert_eq!(port.state().unwrap().baud, baud);
    }
    for escape in [
        Escape::SetDtr,
        Escape::SetRts,
        Escape::ClearRts,
        Escape::ClearDtr,
        Escape::SetBreak,
        Escape::ClearBreak,
    ] {
        port.escape(escape).unwrap();
    }
    port.modem().unwrap();
    port.errors().unwrap();
    // A read with nothing to read returns after its patience, and a wait
    // returns once cancelled.
    let mut buffer = [0u8; 16];
    let before = std::time::Instant::now();
    port.read(&mut buffer).unwrap();
    assert!(before.elapsed() < Duration::from_secs(3));
    drop(port);
    ComPort::open(&name).unwrap();
}

#[test]
#[ignore = "needs a COM port wired back to itself, named by HEDWIG_COM, with HEDWIG_COM_LOOP set"]
fn a_port_wired_back_to_itself_reads_what_it_wrote_and_its_own_lines() {
    assert!(std::env::var_os("HEDWIG_COM_LOOP").is_some());
    let port = ComPort::open(&named()).unwrap();
    let sent: Vec<u8> = (0..=255).collect();
    port.write(&sent).unwrap();
    let mut read = Vec::new();
    let mut buffer = [0u8; 512];
    while read.len() < sent.len() {
        let count = port.read(&mut buffer).unwrap();
        assert!(count > 0, "only {} of {} came back", read.len(), sent.len());
        read.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(read, sent);
    for (escape, bit, on) in [
        (Escape::SetRts, MS_CTS_ON, true),
        (Escape::ClearRts, MS_CTS_ON, false),
        (Escape::SetDtr, MS_DSR_ON, true),
        (Escape::ClearDtr, MS_DSR_ON, false),
    ] {
        port.escape(escape).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(port.modem().unwrap() & bit != 0, on, "{escape:?}");
    }
}

/// Windows' device maps tell a port unplugged and the same port plugged
/// back, each time with the port already gone from, then back among, the
/// ports present. The person unplugs `HEDWIG_COM` once the test has started,
/// then plugs it back, within a minute each.
#[test]
#[ignore = "needs a COM port to unplug and plug back, named by HEDWIG_COM"]
fn the_device_maps_tell_a_port_unplugged_and_plugged_back() {
    let name = named();
    let (tell, told) = std::sync::mpsc::channel();
    hedwig_win::serial::watch(move || {
        let _ = tell.send(());
    })
    .unwrap();
    let there = || {
        present()
            .unwrap()
            .iter()
            .any(|port| port.to_string_lossy().eq_ignore_ascii_case(&name))
    };
    assert!(there(), "{name} is plugged in at the start");
    for wanted in [false, true] {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            told.recv_timeout(left)
                .expect("the device maps told a change in time");
            if there() == wanted {
                break;
            }
        }
    }
}
