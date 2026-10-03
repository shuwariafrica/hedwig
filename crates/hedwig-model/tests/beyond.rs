//! What a remote's tool cannot be given, said where the person meets it: every
//! limit in the catalogue's answer with what would change it, a serial port
//! over its chip's own USB on the row of the capability that names it, and a
//! preset whose port no definition can state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unnecessary_wraps,
    reason = "tests"
)]

use hedwig_model::beyond::{Beyond, ESPRESSIF, USB_OTG, USB_SERIAL_JTAG};
use hedwig_model::capability::{Capability, Exposure, Lends, Operation, Setup, Source};
use hedwig_model::config::{Activation, Change, Terms};
use hedwig_model::protocol::{Reply, Request, SerialPort, Usb};
use hedwig_model::remote::{Granted, RemoteId};
use hedwig_model::text::PortName;
use hedwig_model::trail::{ClientKind, Event};

mod support;
use support::desk::Desk;
use support::{DESKTOP, capability, catalogue, grant, name, port, remote};

fn host() -> RemoteId {
    remote("ssh", "dev@build.example")
}

fn usb(vendor: u16, product: u16) -> Option<Usb> {
    Some(Usb { vendor, product })
}

#[test]
fn a_port_over_its_chip_s_own_usb_is_one_esptool_on_a_remote_cannot_reset() {
    assert_eq!(
        Beyond::of_port(usb(ESPRESSIF, USB_SERIAL_JTAG)),
        Some(Beyond::ChipUsb)
    );
    for product in USB_OTG {
        assert_eq!(
            Beyond::of_port(usb(ESPRESSIF, product)),
            Some(Beyond::ChipUsb)
        );
    }
    // Espressif's own USB-to-UART bridge firmware, a CP210x bridge, a port
    // with no USB device: what esptool resets as any bridge.
    for other in [usb(ESPRESSIF, 0x1002), usb(0x10C4, 0xEA60), None] {
        assert_eq!(Beyond::of_port(other), None, "{other:?}");
    }
    let listed = SerialPort {
        port: PortName::try_from("COM7").unwrap(),
        name: None,
        usb: usb(ESPRESSIF, USB_SERIAL_JTAG),
    };
    assert_eq!(listed.beyond(), Some(Beyond::ChipUsb));
}

#[test]
fn the_catalogue_says_every_limit_with_what_would_change_it() {
    let mut desk = Desk::new(catalogue());
    let viewer = desk.attend(ClientKind::Viewer, DESKTOP);
    let Ok(Reply::Catalogue(definitions)) = desk.send(viewer, Request::Catalogue) else {
        panic!("the catalogue")
    };
    assert_eq!(definitions.beyond, Beyond::ALL);
    for beyond in Beyond::ALL {
        let words = beyond.to_string();
        assert!(words.is_ascii() && !words.ends_with('.'), "{words}");
        assert_ne!(beyond.reopens(), Vec::<&str>::new(), "{words}");
    }
    // Three things would let an Apple device be given.
    assert_eq!(Beyond::AppleDevice.reopens().len(), 3);
    // A preset that leaves its port unstated is one whose program chooses it
    // each run; what ships stated is not.
    let catalogue = catalogue();
    assert_eq!(
        Beyond::of_capability(&capability(&catalogue, "playwright")),
        Some(Beyond::PortPerRun)
    );
    assert_eq!(
        Beyond::of_capability(&capability(&catalogue, "openocd")),
        None
    );
}

#[test]
fn the_row_says_a_serial_port_s_limit_once_a_connection_opened_it_over_its_chip_s_usb() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(
        interface,
        Request::Change(Change::Define(Capability {
            id: name("esp32c3"),
            source: Source::Serial {
                port: PortName::try_from("COM7").unwrap(),
                remote: port(4000),
            },
        })),
    )
    .unwrap();
    desk.send(
        interface,
        Request::Change(Change::Grant {
            grant: grant("esp32c3", Granted::One(host())),
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged: Exposure::SERVICE,
                lends: Lends::none(),
            },
        }),
    )
    .unwrap();
    let connection = desk.channel_up(&host(), "linux");
    assert_eq!(
        desk.row(interface, &host(), &name("esp32c3")).beyond,
        Vec::<Beyond>::new()
    );
    let take = |desk: &mut Desk, over: Option<Usb>| {
        let (request, _) = desk.asks(connection, "esp32c3", Operation::Connect);
        desk.trail.push(Event::Taken {
            request,
            connection,
            capability: name("esp32c3"),
            port: PortName::try_from("com7").unwrap(),
            usb: over,
        });
        desk.trail.push(Event::Released { request });
    };
    take(&mut desk, usb(ESPRESSIF, USB_SERIAL_JTAG));
    assert_eq!(
        desk.row(interface, &host(), &name("esp32c3")).beyond,
        [Beyond::ChipUsb]
    );
    // What a port was last opened over outlives the run.
    desk.trail.push(Event::Started {
        version: "0.2.0".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    let connection = desk.channel_up(&host(), "linux");
    assert_eq!(
        desk.row(interface, &host(), &name("esp32c3")).beyond,
        [Beyond::ChipUsb]
    );
    // The same name over a bridge, as another board plugged in where it was.
    let (request, _) = desk.asks(connection, "esp32c3", Operation::Connect);
    desk.trail.push(Event::Taken {
        request,
        connection,
        capability: name("esp32c3"),
        port: PortName::try_from("COM7").unwrap(),
        usb: usb(0x10C4, 0xEA60),
    });
    assert_eq!(
        desk.row(interface, &host(), &name("esp32c3")).beyond,
        Vec::<Beyond>::new()
    );
}
